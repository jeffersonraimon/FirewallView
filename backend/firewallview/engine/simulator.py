import copy
import ipaddress
from typing import Dict, List, Optional, Set
from firewallview.models.rules import FirewallRule
from firewallview.models.packet import SimulationPacket, SimulationResult, StageEvaluation, RuleEvaluation
from firewallview.models.address_list import AddressList
from firewallview.engine.matcher import evaluate_rule_match

# Documented placeholders: the simulator does not know the router's real addresses.
MASQUERADE_PLACEHOLDER_V4 = "203.0.113.1"   # RFC 5737 TEST-NET-3
MASQUERADE_PLACEHOLDER_V6 = "2001:db8::1"   # RFC 3849
ROUTER_PLACEHOLDER_V4 = "192.0.2.1"         # RFC 5737 TEST-NET-1
ROUTER_PLACEHOLDER_V6 = "2001:db8::ffff"    # RFC 3849

# Verdicts returned by _evaluate_chain (with done=False) that stop evaluation of the whole
# table/chain stage, including parent chains of a jump.
STAGE_STOP_VERDICTS = ("ACCEPT", "STOP")


def _addr_version(ip_str: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip_str.strip()).version
    except ValueError:
        return None


def _resolve_nat_address(current_ip: str, spec: Optional[str]):
    """Picks the translated address from a to-addresses spec.

    Returns (new_ip_or_None, note). A range 'a-b' (or a comma list) uses the first address.
    Never returns an invalid IP string or one of a different IP version.
    """
    if not spec or not spec.strip():
        return None, ""
    spec = spec.strip()
    note = ""
    first = spec
    if "," in first:
        first = first.split(",", 1)[0].strip()
        note = f"list '{spec}' -> using first address {first}"
    if "-" in first:
        first = first.split("-", 1)[0].strip()
        note = f"range '{spec}' -> using first address {first}"
    try:
        new_ip = ipaddress.ip_address(first)
    except ValueError:
        return None, f"to-addresses '{spec}' is not a valid IP address; address left unchanged"
    cur_v = _addr_version(current_ip)
    if cur_v is not None and new_ip.version != cur_v:
        return None, f"to-addresses '{spec}' has a different IP version than the packet; address left unchanged"
    return str(new_ip), note


def _resolve_nat_port(spec: Optional[str]):
    """First port of a to-ports spec ('a' or 'a-b'). Returns (port_or_None, note)."""
    if not spec or not spec.strip():
        return None, ""
    spec = spec.strip()
    first = spec.split(",", 1)[0].split("-", 1)[0].strip()
    try:
        port = int(first)
    except ValueError:
        return None, f"to-ports '{spec}' is not numeric; port left unchanged"
    if not 0 <= port <= 65535:
        return None, f"to-ports '{spec}' out of range; port left unchanged"
    note = f"range '{spec}' -> using first port {port}" if ("-" in spec or "," in spec) else ""
    return port, note


def _netmap(current_ip: str, spec: Optional[str]):
    """1:1 prefix mapping keeping host bits. Returns (new_ip_or_None, note)."""
    if not spec or not spec.strip():
        return None, "netmap without to-addresses; nothing translated"
    try:
        net = ipaddress.ip_network(spec.strip(), strict=False)
        cur = ipaddress.ip_address(current_ip.strip())
    except ValueError:
        return None, f"netmap to-addresses '{spec}' is not a valid network; address left unchanged"
    if net.version != cur.version:
        return None, f"netmap network '{spec}' has a different IP version than the packet; address left unchanged"
    host_mask = (1 << (net.max_prefixlen - net.prefixlen)) - 1
    new_int = int(net.network_address) | (int(cur) & host_mask)
    return str(ipaddress.ip_address(new_int)), f"host bits of {current_ip} kept under {net}"


class FirewallSimulator:
    def __init__(self, rules: List[FirewallRule], address_lists: Dict[str, AddressList]):
        # Keep rules sorted by order
        self.rules = sorted([r for r in rules if not r.disabled], key=lambda x: x.order)
        self.address_lists = address_lists
        self._chain_note: Optional[str] = None
        self._terminal_rule: Optional[FirewallRule] = None
        self._accepted_rule: Optional[FirewallRule] = None

    @staticmethod
    def _policy_last(rules: List[FirewallRule]) -> List[FirewallRule]:
        """Stable partition: policy rules go after every normal rule, whatever their order."""
        return [r for r in rules if not r.is_policy] + [r for r in rules if r.is_policy]

    @staticmethod
    def _group_by_chain(rules: List[FirewallRule]) -> List[FirewallRule]:
        """Keeps rules of each named chain together, chains in order of first appearance."""
        groups: Dict[str, List[FirewallRule]] = {}
        for r in rules:
            groups.setdefault(r.chain.lower(), []).append(r)
        return [r for g in groups.values() for r in g]

    def get_rules_for_chain(self, table: str, chain: str) -> List[FirewallRule]:
        self._chain_note = None
        # Exact table + chain match
        matched = [
            r for r in self.rules
            if (r.table.lower() == table.lower() and r.chain.lower() == chain.lower())
        ]
        if matched:
            return self._policy_last(matched)

        # If evaluating main filter forward/input/output and there are no rules explicitly named,
        # but there are rules in filter table with named ACL or Junos filter names (e.g. protect-re, local_acl, WAN_IN)
        if table.lower() == "filter" and chain.lower() in ["forward", "input", "output"]:
            all_filter_rules = [r for r in self.rules if r.table.lower() == "filter"]
            has_standard = any(r.chain.lower() in ["forward", "input", "output"] for r in all_filter_rules)
            if not has_standard and all_filter_rules:
                # Sub-chains (targets of jump) should not run as root chains
                jump_targets = {r.target_chain.lower() for r in self.rules if r.action == "jump" and r.target_chain}
                root_rules = [r for r in all_filter_rules if r.chain.lower() not in jump_targets]

                selected = root_rules if root_rules else all_filter_rules
                if chain.lower() == "input":
                    input_root_rules = [
                        r for r in root_rules
                        if any(k in r.chain.lower() for k in ["protect-re", "re-protect", "-lo", "lo0", "input", "local_acl"])
                    ]
                    if input_root_rules:
                        selected = input_root_rules

                selected = self._group_by_chain(selected)
                names = list(dict.fromkeys(r.chain for r in selected))
                if len(names) > 1:
                    self._chain_note = (
                        f"No standard '{chain}' chain: applying named ACLs/filters {names} in sequence "
                        f"(heuristic - independent ACLs are normally bound to different interfaces/directions)"
                    )
                else:
                    self._chain_note = f"No standard '{chain}' chain: using named ACL/filter '{names[0]}'"
                return self._policy_last(selected)

        return []

    def simulate(self, packet: SimulationPacket) -> SimulationResult:
        # Create a deep copy of packet to track mutations (NAT, marks)
        current_packet = copy.deepcopy(packet)
        self._terminal_rule = None
        self._accepted_rule = None
        stages: List[StageEvaluation] = []
        flow_path: List[str] = ["start"]

        # Determine packet flow type:
        # 1. 'input': traffic directed to router (prerouting -> input)
        # 2. 'output': traffic generated locally by router (output -> postrouting)
        # 3. 'forward': traffic traversing the router (prerouting -> forward -> postrouting)
        flow_type = (packet.flow_type or "forward").lower()
        if packet.is_router_traffic and flow_type == "forward":
            flow_type = "input"

        # In local input flow, if in_interface was not set but out_interface was provided, fallback to out_interface
        if flow_type == "input" and not current_packet.in_interface and current_packet.out_interface:
            current_packet.in_interface = current_packet.out_interface
        # In local output flow, if out_interface was not set but in_interface was provided, fallback to in_interface
        if flow_type == "output" and not current_packet.out_interface and current_packet.in_interface:
            current_packet.out_interface = current_packet.in_interface

        # Pipeline stages in canonical order:
        # Stage definition: (stage_id, title, table, chain)
        if flow_type == "input":
            pipeline = [
                ("raw_prerouting", "Raw - PREROUTING", "raw", "prerouting"),
                ("mangle_prerouting", "Mangle - PREROUTING", "mangle", "prerouting"),
                ("nat_dstnat", "NAT - DSTNAT", "nat", "dstnat"),
                ("routing_decision_in", "Routing Decision (Local Input)", "", ""),
                ("mangle_input", "Mangle - INPUT", "mangle", "input"),
                ("filter_input", "Filter - INPUT", "filter", "input"),
            ]
        elif flow_type == "output":
            pipeline = [
                ("routing_decision_out", "Routing Decision (Local Output)", "", ""),
                ("raw_output", "Raw - OUTPUT", "raw", "output"),
                ("mangle_output", "Mangle - OUTPUT", "mangle", "output"),
                ("nat_output", "NAT - OUTPUT", "nat", "output"),
                ("filter_output", "Filter - OUTPUT", "filter", "output"),
                ("mangle_postrouting", "Mangle - POSTROUTING", "mangle", "postrouting"),
                ("nat_srcnat", "NAT - SRCNAT", "nat", "srcnat"),
            ]
        else:
            pipeline = [
                ("raw_prerouting", "Raw - PREROUTING", "raw", "prerouting"),
                ("mangle_prerouting", "Mangle - PREROUTING", "mangle", "prerouting"),
                ("nat_dstnat", "NAT - DSTNAT", "nat", "dstnat"),
                ("routing_decision_fwd", "Routing Decision (Forward)", "", ""),
                ("mangle_forward", "Mangle - FORWARD", "mangle", "forward"),
                ("filter_forward", "Filter - FORWARD", "filter", "forward"),
                ("mangle_postrouting", "Mangle - POSTROUTING", "mangle", "postrouting"),
                ("nat_srcnat", "NAT - SRCNAT", "nat", "srcnat"),
            ]

        final_verdict = "ACCEPT"
        final_action = "ACCEPT (Default Policy)"
        terminal_rule_id: Optional[str] = None
        accepted_filter_rule_id: Optional[str] = None
        is_terminated = False
        accepted_is_policy = False
        accepted_where = ""

        for stage_id, stage_title, table, chain in pipeline:
            flow_path.append(stage_id)

            # Virtual routing decision step
            if not table or not chain:
                stages.append(StageEvaluation(
                    stage_id=stage_id,
                    stage_title=stage_title,
                    table="system",
                    chain="system",
                    stage_verdict="CONTINUE",
                    notes="Packet routed based on destination IP and routing table"
                ))
                continue

            stage_eval = StageEvaluation(
                stage_id=stage_id,
                stage_title=stage_title,
                table=table,
                chain=chain,
                stage_verdict="CONTINUE"
            )

            chain_rules = self.get_rules_for_chain(table, chain)
            if self._chain_note:
                stage_eval.notes = self._chain_note
                self._chain_note = None

            # Evaluate chain with jump support
            stage_done, verdict_from_chain, term_id = self._evaluate_chain(
                table, chain, chain_rules, current_packet, stage_eval, flow_path
            )

            stages.append(stage_eval)

            if stage_done:
                is_terminated = True
                final_verdict = verdict_from_chain
                final_action = verdict_from_chain
                if self._terminal_rule is not None and self._terminal_rule.is_policy:
                    final_action = f"{verdict_from_chain} (Default Policy of {table}/{chain})"
                terminal_rule_id = term_id
                break
            elif verdict_from_chain == "ACCEPT" and table.lower() == "filter":
                accepted_filter_rule_id = term_id
                accepted_is_policy = self._accepted_rule is not None and self._accepted_rule.is_policy
                accepted_where = f"{table}/{chain}"

        # If not terminated by explicit rule, check default behavior
        if not is_terminated:
            if accepted_filter_rule_id:
                final_verdict = "ACCEPT"
                if accepted_is_policy:
                    final_action = f"ACCEPT (Default Policy of {accepted_where})"
                else:
                    final_action = f"ACCEPT (Rule #{accepted_filter_rule_id})"
                terminal_rule_id = accepted_filter_rule_id
            else:
                final_verdict = "ACCEPT"
                final_action = "ACCEPT (Default Policy)"
            flow_path.append("delivered")
        elif final_verdict in ["DROP", "REJECT"]:
            flow_path.append("dropped")
        else:
            flow_path.append("delivered")

        summary = self._generate_summary(final_verdict, final_action, terminal_rule_id, packet, current_packet)

        return SimulationResult(
            verdict=final_verdict,
            final_action=final_action,
            packet_in=packet,
            packet_out=current_packet,
            stages=stages,
            flow_path=flow_path,
            summary=summary,
            matched_rule_id=terminal_rule_id
        )

    def _evaluate_chain(
        self,
        table: str,
        chain: str,
        rules: List[FirewallRule],
        packet: SimulationPacket,
        stage_eval: StageEvaluation,
        flow_path: List[str],
        call_stack: Optional[Set[str]] = None
    ) -> (bool, str, Optional[str]):
        """
        Evaluates rules in chain.
        Returns (terminated: bool, verdict: str, terminal_rule_id: Optional[str]).
        """
        if call_stack is None:
            call_stack = set()

        chain_key = f"{table}:{chain}"
        if chain_key in call_stack:
            # Prevent infinite recursion in jumps (real loops only: the key is popped on exit)
            note = f"Warning: Loop detected in chain {chain_key}"
            stage_eval.notes = f"{stage_eval.notes}; {note}" if stage_eval.notes else note
            return False, "CONTINUE", None

        call_stack.add(chain_key)
        try:
            return self._run_rules(table, chain, rules, packet, stage_eval, flow_path, call_stack)
        finally:
            call_stack.discard(chain_key)

    def _run_rules(
        self,
        table: str,
        chain: str,
        rules: List[FirewallRule],
        packet: SimulationPacket,
        stage_eval: StageEvaluation,
        flow_path: List[str],
        call_stack: Set[str]
    ) -> (bool, str, Optional[str]):
        for rule in rules:
            matched, reasons = evaluate_rule_match(rule, packet, self.address_lists)
            action_lower = rule.action.strip().lower()

            eval_item = RuleEvaluation(
                rule_id=rule.id,
                rule_order=rule.order,
                table=rule.table,
                chain=rule.chain,
                action=rule.action,
                matched=matched,
                reasons=reasons,
                comment=rule.comment,
                raw_syntax=rule.raw_syntax
            )

            if not matched:
                stage_eval.evaluated_rules.append(eval_item)
                continue

            # It matched! Now apply action logic
            if action_lower == "drop":
                eval_item.applied_effect = "Packet dropped immediately"
                eval_item.terminated = True
                stage_eval.evaluated_rules.append(eval_item)
                stage_eval.stage_verdict = "DROPPED"
                self._terminal_rule = rule
                return True, "DROP", rule.id

            elif action_lower == "reject":
                eval_item.applied_effect = "Packet rejected (ICMP unreachable generated)"
                eval_item.terminated = True
                stage_eval.evaluated_rules.append(eval_item)
                stage_eval.stage_verdict = "REJECTED"
                self._terminal_rule = rule
                return True, "REJECT", rule.id

            elif action_lower in ["accept", "fasttrack-connection"]:
                eval_item.applied_effect = f"Accepted by rule ({action_lower})"
                eval_item.terminated = True
                stage_eval.evaluated_rules.append(eval_item)
                stage_eval.stage_verdict = "ACCEPTED"
                # Accept ends evaluation of the whole table/chain stage (also when reached via jump),
                # but not the packet: it continues to the next pipeline stage.
                self._accepted_rule = rule
                return False, "ACCEPT", rule.id

            elif action_lower == "return":
                eval_item.applied_effect = "Returned to parent chain"
                stage_eval.evaluated_rules.append(eval_item)
                return False, "RETURN", None

            elif action_lower == "jump":
                target_chain = rule.target_chain
                eval_item.applied_effect = f"Jumped to chain '{target_chain}'"
                stage_eval.evaluated_rules.append(eval_item)
                flow_path.append(f"jump_{target_chain}")

                jump_rules = self.get_rules_for_chain(table, target_chain or "")
                jump_done, jump_verdict, term_id = self._evaluate_chain(
                    table, target_chain or "", jump_rules, packet, stage_eval, flow_path, call_stack
                )
                if jump_done:
                    return True, jump_verdict, term_id
                if jump_verdict in STAGE_STOP_VERDICTS:
                    return False, jump_verdict, term_id
                # RETURN / CONTINUE: resume with the next rule of the current chain

            elif action_lower in ["dst-nat", "src-nat", "masquerade", "redirect", "netmap"]:
                self._apply_nat(action_lower, rule, packet, eval_item)
                stage_eval.evaluated_rules.append(eval_item)
                return False, "STOP", rule.id

            elif action_lower in ["mark-packet", "mark-connection", "mark-routing"]:
                mark = rule.mark_value or "marked"
                # A new mark REPLACES the previous one (nft `meta mark set`, iptables
                # MARK --set-mark, RouterOS new-packet-mark). The model has a single
                # mark slot shared by packet/connection/routing marks, kept as a list
                # for compatibility; it always holds at most one value.
                packet.packet_marks[:] = [mark]
                eval_item.applied_effect = f"Applied {action_lower}: '{mark}'"
                stage_eval.evaluated_rules.append(eval_item)

            elif action_lower in ["change-mss", "clamp-mss-to-pmtu"]:
                mss = rule.mark_value or "1452"
                eval_item.applied_effect = f"TCP MSS adjusted to {mss}"
                stage_eval.evaluated_rules.append(eval_item)

            elif action_lower in ["snpt", "dnpt"]:
                import ipaddress
                is_snpt = (action_lower == "snpt")
                src_prefix = rule.npt_src_prefix
                dst_prefix = rule.npt_dst_prefix
                target_ip_str = packet.src_ip if is_snpt else packet.dst_ip

                translated = False
                orig_ip = target_ip_str

                if src_prefix and dst_prefix:
                    try:
                        from_net = ipaddress.IPv6Network(src_prefix.strip(), strict=False)
                        to_net = ipaddress.IPv6Network(dst_prefix.strip(), strict=False)
                        curr_ip = ipaddress.IPv6Address(target_ip_str.strip())

                        if curr_ip in from_net:
                            host_mask = (1 << (128 - from_net.prefixlen)) - 1
                            host_bits = int(curr_ip) & host_mask
                            new_ip_int = int(to_net.network_address) | host_bits
                            new_ip_str = str(ipaddress.IPv6Address(new_ip_int))

                            if is_snpt:
                                packet.src_ip = new_ip_str
                            else:
                                packet.dst_ip = new_ip_str
                            translated = True
                            target_ip_str = new_ip_str
                    except Exception:
                        pass

                trans_type = "SNPTv6 (Stateless Source NAT)" if is_snpt else "DNPTv6 (Stateless Destination NAT)"
                if translated:
                    eval_item.applied_effect = f"{trans_type} applied: {orig_ip} -> {target_ip_str}. (Stateless: conntrack does not track this session)"
                else:
                    eval_item.applied_effect = f"{trans_type} evaluated ({src_prefix} -> {dst_prefix})"
                stage_eval.evaluated_rules.append(eval_item)
                return False, "STOP", rule.id

            elif action_lower in ["add-src-to-address-list", "add-dst-to-address-list"]:
                target_list = rule.address_list_target or "DYNAMIC_LIST"
                target_ip = packet.src_ip if "src" in action_lower else packet.dst_ip
                timeout = rule.address_list_timeout or ""
                if target_list not in self.address_lists:
                    from firewallview.models.address_list import AddressList
                    self.address_lists[target_list] = AddressList(name=target_list, entries=[])
                already = any(e.address == target_ip for e in self.address_lists[target_list].entries)
                if not already:
                    import uuid
                    from firewallview.models.address_list import AddressListEntry
                    self.address_lists[target_list].entries.append(
                        AddressListEntry(id=str(uuid.uuid4())[:8], address=target_ip, comment=f"Dynamic (timeout={timeout})" if timeout else "Dynamic", disabled=False)
                    )
                eval_item.applied_effect = f"Added {target_ip} dynamically to address-list '{target_list}'" + (f" (timeout: {timeout})" if timeout else "")
                stage_eval.evaluated_rules.append(eval_item)

            elif action_lower in ["log", "passthrough"]:
                eval_item.applied_effect = f"Action {action_lower} executed; packet continues"
                stage_eval.evaluated_rules.append(eval_item)

            else:
                eval_item.applied_effect = f"Action {action_lower} executed"
                stage_eval.evaluated_rules.append(eval_item)

        return False, "CONTINUE", None

    def _apply_nat(self, action: str, rule: FirewallRule, packet: SimulationPacket, eval_item: RuleEvaluation) -> None:
        """Applies a NAT action to the packet and fills eval_item.applied_effect."""
        notes: List[str] = []
        v6 = _addr_version(packet.src_ip) == 6
        has_ports = packet.protocol.strip().lower() in ("tcp", "udp")

        if action == "dst-nat":
            orig = f"{packet.dst_ip}:{packet.dst_port}"
            new_ip, note = _resolve_nat_address(packet.dst_ip, rule.nat_to_addresses)
            if note:
                notes.append(note)
            old_ip, old_port = packet.dst_ip, packet.dst_port
            if new_ip:
                packet.dst_ip = new_ip
            port, note = _resolve_nat_port(rule.nat_to_ports)
            if note:
                notes.append(note)
            if port is not None and has_ports:
                packet.dst_port = port
            # RouterOS (verified on CHR 7.25.1): connection-nat-state=dstnat only when address or port really changed
            if packet.dst_ip != old_ip or packet.dst_port != old_port:
                packet.connection_nat_state = "dstnat"
            effect = f"Destination NAT applied: {orig} -> {packet.dst_ip}:{packet.dst_port}"

        elif action in ("src-nat", "masquerade"):
            orig = f"{packet.src_ip}:{packet.src_port}"
            if action == "masquerade":
                placeholder = MASQUERADE_PLACEHOLDER_V6 if v6 else MASQUERADE_PLACEHOLDER_V4
                packet.src_ip = placeholder
                notes.append(
                    f"masquerade uses the address of the out-interface ('{packet.out_interface}'), unknown to the "
                    f"simulator: documentation placeholder {placeholder} shown"
                )
            else:
                new_ip, note = _resolve_nat_address(packet.src_ip, rule.nat_to_addresses)
                if note:
                    notes.append(note)
                if new_ip:
                    packet.src_ip = new_ip
            port, note = _resolve_nat_port(rule.nat_to_ports)
            if note:
                notes.append(note)
            if port is not None and has_ports:
                packet.src_port = port
            packet.connection_nat_state = "srcnat"
            effect = f"Source NAT applied: {orig} -> {packet.src_ip}:{packet.src_port}"

        elif action == "redirect":
            orig = f"{packet.dst_ip}:{packet.dst_port}"
            placeholder = ROUTER_PLACEHOLDER_V6 if _addr_version(packet.dst_ip) == 6 else ROUTER_PLACEHOLDER_V4
            packet.dst_ip = placeholder
            notes.append(
                f"redirect targets the router's own address, unknown to the simulator: placeholder {placeholder} shown"
            )
            port, note = _resolve_nat_port(rule.nat_to_ports)
            if note:
                notes.append(note)
            if port is not None and has_ports:
                packet.dst_port = port
            packet.connection_nat_state = "dstnat"
            effect = f"Redirect applied: {orig} -> {packet.dst_ip}:{packet.dst_port}"

        else:  # netmap
            is_dst = rule.chain.strip().lower() in ("dstnat", "prerouting", "output")
            attr = "dst_ip" if is_dst else "src_ip"
            orig = getattr(packet, attr)
            new_ip, note = _netmap(orig, rule.nat_to_addresses)
            if note:
                notes.append(note)
            if new_ip:
                setattr(packet, attr, new_ip)
            port, note = _resolve_nat_port(rule.nat_to_ports)
            if note:
                notes.append(note)
            if port is not None and has_ports:
                if is_dst:
                    packet.dst_port = port
                else:
                    packet.src_port = port
            packet.connection_nat_state = "dstnat" if is_dst else "srcnat"
            effect = f"Netmap applied ({'destination' if is_dst else 'source'}): {orig} -> {getattr(packet, attr)}"

        if notes:
            effect += " (" + "; ".join(notes) + ")"
        eval_item.applied_effect = effect

    def _generate_summary(
        self,
        verdict: str,
        final_action: str,
        rule_id: Optional[str],
        orig_packet: SimulationPacket,
        final_packet: SimulationPacket
    ) -> str:
        nat_info = ""
        if orig_packet.dst_ip != final_packet.dst_ip or orig_packet.dst_port != final_packet.dst_port:
            nat_info += f" DNAT: {orig_packet.dst_ip}:{orig_packet.dst_port} -> {final_packet.dst_ip}:{final_packet.dst_port}."
        if orig_packet.src_ip != final_packet.src_ip:
            nat_info += f" SNAT: {orig_packet.src_ip} -> {final_packet.src_ip}."

        if verdict in ["DROP", "REJECT"]:
            return f"Packet was {verdict}PED by Rule #{rule_id}.{nat_info}"
        else:
            return f"Packet was PERMITTED ({final_action}).{nat_info}"
