import copy
from typing import Dict, List, Optional, Set
from firewallview.models.rules import FirewallRule
from firewallview.models.packet import SimulationPacket, SimulationResult, StageEvaluation, RuleEvaluation
from firewallview.models.address_list import AddressList
from firewallview.engine.matcher import evaluate_rule_match

class FirewallSimulator:
    def __init__(self, rules: List[FirewallRule], address_lists: Dict[str, AddressList]):
        # Keep rules sorted by order
        self.rules = sorted([r for r in rules if not r.disabled], key=lambda x: x.order)
        self.address_lists = address_lists

    def get_rules_for_chain(self, table: str, chain: str) -> List[FirewallRule]:
        # Exact table + chain match
        matched = [
            r for r in self.rules
            if (r.table.lower() == table.lower() and r.chain.lower() == chain.lower())
        ]
        if matched:
            return matched

        # If evaluating main filter forward/input/output and there are no rules explicitly named,
        # but there are rules in filter table with named ACL or Junos filter names (e.g. protect-re, local_acl, WAN_IN)
        if table.lower() == "filter" and chain.lower() in ["forward", "input", "output"]:
            all_filter_rules = [r for r in self.rules if r.table.lower() == "filter"]
            has_standard = any(r.chain.lower() in ["forward", "input", "output"] for r in all_filter_rules)
            if not has_standard and all_filter_rules:
                # Sub-chains (targets of jump) should not run as root chains
                jump_targets = {r.target_chain.lower() for r in self.rules if r.action == "jump" and r.target_chain}
                root_rules = [r for r in all_filter_rules if r.chain.lower() not in jump_targets]

                if chain.lower() == "input":
                    input_root_rules = [
                        r for r in root_rules
                        if any(k in r.chain.lower() for k in ["protect-re", "re-protect", "-lo", "lo0", "input", "local_acl"])
                    ]
                    if input_root_rules:
                        return input_root_rules

                return root_rules if root_rules else all_filter_rules

        return []

    def simulate(self, packet: SimulationPacket) -> SimulationResult:
        # Create a deep copy of packet to track mutations (NAT, marks)
        current_packet = copy.deepcopy(packet)
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

            # Evaluate chain with jump support
            stage_done, verdict_from_chain, term_id = self._evaluate_chain(
                table, chain, chain_rules, current_packet, stage_eval, flow_path
            )

            stages.append(stage_eval)

            if stage_done:
                is_terminated = True
                final_verdict = verdict_from_chain
                final_action = verdict_from_chain
                terminal_rule_id = term_id
                break
            elif verdict_from_chain == "ACCEPT" and table.lower() == "filter":
                accepted_filter_rule_id = term_id

        # If not terminated by explicit rule, check default behavior
        if not is_terminated:
            if accepted_filter_rule_id:
                final_verdict = "ACCEPT"
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
            # Prevent infinite recursion in jumps
            stage_eval.notes = f"Warning: Loop detected in chain {chain_key}"
            return False, "CONTINUE", None

        call_stack.add(chain_key)

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
                return True, "DROP", rule.id

            elif action_lower == "reject":
                eval_item.applied_effect = "Packet rejected (ICMP unreachable generated)"
                eval_item.terminated = True
                stage_eval.evaluated_rules.append(eval_item)
                stage_eval.stage_verdict = "REJECTED"
                return True, "REJECT", rule.id

            elif action_lower in ["accept", "fasttrack-connection"]:
                eval_item.applied_effect = f"Accepted by rule ({action_lower})"
                eval_item.terminated = True
                stage_eval.evaluated_rules.append(eval_item)
                stage_eval.stage_verdict = "ACCEPTED"
                # For filter table, accept is terminating for the filter stage!
                if table.lower() == "filter":
                    return False, "ACCEPT", rule.id # Finishes filter chain, proceeds to postrouting/delivery
                return False, "CONTINUE", rule.id

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
                if jump_done or jump_verdict in ["DROP", "REJECT", "ACCEPT"]:
                    return jump_done or (table.lower() == "filter" and jump_verdict == "ACCEPT"), jump_verdict, term_id
                # If jump returned or ended without drop/accept, continue next rule in current chain

            elif action_lower == "dst-nat":
                orig_dst = f"{packet.dst_ip}:{packet.dst_port}"
                if rule.nat_to_addresses:
                    packet.dst_ip = rule.nat_to_addresses
                if rule.nat_to_ports:
                    try:
                        packet.dst_port = int(rule.nat_to_ports.split("-")[0].strip())
                    except ValueError:
                        pass
                packet.connection_nat_state = "dstnat"
                new_dst = f"{packet.dst_ip}:{packet.dst_port}"
                eval_item.applied_effect = f"Destination NAT applied: {orig_dst} -> {new_dst}"
                stage_eval.evaluated_rules.append(eval_item)
                return False, "CONTINUE", rule.id

            elif action_lower in ["src-nat", "masquerade"]:
                orig_src = f"{packet.src_ip}:{packet.src_port}"
                if action_lower == "masquerade":
                    # Masquerade to out-interface gateway IP (example simulation: 203.0.113.1)
                    packet.src_ip = "203.0.113.1"
                elif rule.nat_to_addresses:
                    packet.src_ip = rule.nat_to_addresses
                packet.connection_nat_state = "srcnat"
                new_src = f"{packet.src_ip}:{packet.src_port}"
                eval_item.applied_effect = f"Source NAT applied: {orig_src} -> {new_src}"
                stage_eval.evaluated_rules.append(eval_item)
                return False, "CONTINUE", rule.id

            elif action_lower in ["mark-packet", "mark-connection", "mark-routing"]:
                mark = rule.mark_value or "marked"
                if mark not in packet.packet_marks:
                    packet.packet_marks.append(mark)
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
                return False, "CONTINUE", rule.id

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
