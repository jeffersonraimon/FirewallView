import re
import uuid
from typing import Dict, List, Optional, Set, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

JUNOS_SERVICES = {
    "bgp": "179",
    "ldp": "646",
    "ospf": "89",
    "rip": "520",
    "bfd": "3784",
    "bfd-control": "3784",
    "bfd-echo": "3785",
    "multihop-bfd": "4784",
    "ssh": "22",
    "telnet": "23",
    "ftp": "21",
    "ftp-data": "20",
    "tftp": "69",
    "http": "80",
    "https": "443",
    "snmp": "161",
    "snmp-trap": "162",
    "syslog": "514",
    "ntp": "123",
    "domain": "53",
    "dns": "53",
    "netbios": "137",
    "netbios-ns": "137",
    "netbios-dgm": "138",
    "netbios-ssn": "139",
    "bootps": "67",
    "bootpc": "68",
    "dhcp": "67",
    "dhcpv6-client": "546",
    "dhcpv6-server": "547",
    "radius": "1812",
    "radius-acct": "1813",
    "tacacs": "49",
    "sip": "5060",
    "traceroute": "33434-33523",
}

def resolve_junos_port(token: str) -> str:
    cleaned = token.replace(";", "").replace("[", "").replace("]", "").strip().lower()
    return JUNOS_SERVICES.get(cleaned, cleaned)

def _accumulate_csv(existing: Optional[str], new_val: str) -> str:
    if not new_val:
        return existing or ""
    if not existing:
        return new_val
    existing_items = [x.strip() for x in existing.split(",") if x.strip()]
    if new_val not in existing_items:
        existing_items.append(new_val)
    return ",".join(existing_items)

def parse_junos_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Juniper Junos OS firewall configurations:
    Supports both hierarchical block syntax (filter { term { ... } }) and 'set' format.
    """
    lines = content.splitlines()
    set_lines = [l.strip() for l in lines if l.strip().startswith("set ") or l.strip().startswith("deactivate ")]

    if len(set_lines) > 0 and len(set_lines) >= len([l for l in lines if "{" in l]):
        return _parse_junos_set(lines)
    else:
        return _parse_junos_hierarchical(content)

def _parse_junos_set(lines: List[str]) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    address_lists: Dict[str, AddressList] = {}
    term_rules: Dict[Tuple[str, str], Dict] = {}
    term_order_list: List[Tuple[str, str]] = []
    deactivated_terms: Set[Tuple[str, str]] = set()

    for line in lines:
        stripped = line.strip()

        # Handle deactivated terms (deactivate firewall family inet filter <filter> term <term>)
        if stripped.startswith("deactivate "):
            tokens = stripped.split()
            if "filter" in tokens and "term" in tokens:
                f_idx = tokens.index("filter")
                t_idx = tokens.index("term")
                if f_idx + 1 < len(tokens) and t_idx + 1 < len(tokens):
                    d_filter = tokens[f_idx + 1]
                    d_term = tokens[t_idx + 1]
                    deactivated_terms.add((d_filter, d_term))
            continue

        if not stripped.startswith("set "):
            continue

        tokens = stripped.split()
        if "prefix-list" in tokens:
            idx = tokens.index("prefix-list")
            if idx + 2 < len(tokens):
                plist_name = tokens[idx + 1]
                ip_val = tokens[idx + 2].replace(";", "")
                if plist_name not in address_lists:
                    address_lists[plist_name] = AddressList(name=plist_name, entries=[])
                # Skip dynamic apply-path placeholder from being parsed as invalid IP
                if ip_val != "apply-path":
                    address_lists[plist_name].entries.append(
                        AddressListEntry(id=str(uuid.uuid4())[:8], address=ip_val)
                    )
            continue

        if "filter" in tokens and "term" in tokens:
            f_idx = tokens.index("filter")
            t_idx = tokens.index("term")
            if f_idx + 1 < len(tokens) and t_idx + 1 < len(tokens):
                filter_name = tokens[f_idx + 1]
                term_name = tokens[t_idx + 1]
                key = (filter_name, term_name)

                if key not in term_rules:
                    term_rules[key] = {
                        "filter": filter_name,
                        "term": term_name,
                        "conditions": RuleCondition(),
                        "action": "accept",
                        "target_chain": None,
                        "comment": None,
                        "raw_lines": []
                    }
                    term_order_list.append(key)

                term_data = term_rules[key]
                term_data["raw_lines"].append(stripped)
                cond = term_data["conditions"]

                rem_tokens = tokens[t_idx + 2:]
                line_str = " ".join(rem_tokens)

                # 1. Sub-filter invocation (jump to another filter: term <name> filter <target>)
                if len(rem_tokens) >= 2 and rem_tokens[0] == "filter":
                    target_filter = rem_tokens[1].replace(";", "")
                    term_data["action"] = "jump"
                    term_data["target_chain"] = target_filter
                    continue

                # 2. Actions: then accept / discard / reject / policer / count
                if "then" in rem_tokens:
                    then_idx = rem_tokens.index("then")
                    if then_idx + 1 < len(rem_tokens):
                        then_act = rem_tokens[then_idx + 1].replace(";", "").lower()
                        if then_act == "accept":
                            term_data["action"] = "accept"
                        elif then_act in ["discard", "drop"]:
                            term_data["action"] = "drop"
                        elif then_act == "reject":
                            term_data["action"] = "reject"
                        elif then_act in ["policer", "count"]:
                            if term_data["action"] not in ["accept", "drop", "reject", "jump"]:
                                term_data["action"] = "passthrough"

                # 3. Protocol / Next-Header (IPv4 protocol or IPv6 next-header)
                if "protocol" in rem_tokens:
                    p_idx = rem_tokens.index("protocol")
                    if p_idx + 1 < len(rem_tokens):
                        proto_val = rem_tokens[p_idx + 1].replace(";", "").lower()
                        cond.protocol = _accumulate_csv(cond.protocol, proto_val)
                elif "next-header" in rem_tokens:
                    nh_idx = rem_tokens.index("next-header")
                    if nh_idx + 1 < len(rem_tokens):
                        proto_val = rem_tokens[nh_idx + 1].replace(";", "").lower()
                        cond.protocol = _accumulate_csv(cond.protocol, proto_val)

                # 4. Source Address
                if "source-address" in rem_tokens:
                    s_idx = rem_tokens.index("source-address")
                    if s_idx + 1 < len(rem_tokens):
                        s_val = rem_tokens[s_idx + 1].replace(";", "")
                        cond.src_address = _accumulate_csv(cond.src_address, s_val)

                # 5. Destination Address
                if "destination-address" in rem_tokens:
                    d_idx = rem_tokens.index("destination-address")
                    if d_idx + 1 < len(rem_tokens):
                        d_val = rem_tokens[d_idx + 1].replace(";", "")
                        cond.dst_address = _accumulate_csv(cond.dst_address, d_val)

                # 6. Destination Port
                if "destination-port" in rem_tokens:
                    dp_idx = rem_tokens.index("destination-port")
                    if dp_idx + 1 < len(rem_tokens):
                        dp_raw = rem_tokens[dp_idx + 1]
                        dp_val = resolve_junos_port(dp_raw)
                        cond.dst_port = _accumulate_csv(cond.dst_port, dp_val)

                # 7. Source Port
                if "source-port" in rem_tokens:
                    sp_idx = rem_tokens.index("source-port")
                    if sp_idx + 1 < len(rem_tokens):
                        sp_raw = rem_tokens[sp_idx + 1]
                        sp_val = resolve_junos_port(sp_raw)
                        cond.src_port = _accumulate_csv(cond.src_port, sp_val)

                # 8. Generic Port (from port ...) matches either source or destination
                if "port" in rem_tokens and "source-port" not in rem_tokens and "destination-port" not in rem_tokens:
                    p_idx = rem_tokens.index("port")
                    if p_idx + 1 < len(rem_tokens):
                        p_raw = rem_tokens[p_idx + 1]
                        p_val = resolve_junos_port(p_raw)
                        cond.port = _accumulate_csv(cond.port, p_val)

                # 9. Source & Destination Prefix Lists
                if "source-prefix-list" in rem_tokens:
                    pl_idx = rem_tokens.index("source-prefix-list")
                    if pl_idx + 1 < len(rem_tokens):
                        pl_val = rem_tokens[pl_idx + 1].replace(";", "")
                        cond.src_address_list = _accumulate_csv(cond.src_address_list, pl_val)
                elif "destination-prefix-list" in rem_tokens:
                    dpl_idx = rem_tokens.index("destination-prefix-list")
                    if dpl_idx + 1 < len(rem_tokens):
                        dpl_val = rem_tokens[dpl_idx + 1].replace(";", "")
                        cond.dst_address_list = _accumulate_csv(cond.dst_address_list, dpl_val)
                elif "prefix-list" in rem_tokens and "from" in rem_tokens:
                    pl_idx = rem_tokens.index("prefix-list")
                    if pl_idx + 1 < len(rem_tokens):
                        pl_val = rem_tokens[pl_idx + 1].replace(";", "")
                        cond.src_address_list = _accumulate_csv(cond.src_address_list, pl_val)

                # 10. TCP States
                if "tcp-established" in line_str:
                    for st in ["established", "related"]:
                        if st not in cond.connection_state:
                            cond.connection_state.append(st)
                if "tcp-initial" in line_str:
                    if "new" not in cond.connection_state:
                        cond.connection_state.append("new")
                    if "syn" not in cond.tcp_flags:
                        cond.tcp_flags.extend(["syn", "!ack"])

    rules: List[FirewallRule] = []
    rule_order = 1
    for key in term_order_list:
        data = term_rules[key]
        is_disabled = (key in deactivated_terms)
        rule = FirewallRule(
            id=str(rule_order),
            order=rule_order,
            table="filter",
            chain=data["filter"],
            action=data["action"],
            target_chain=data["target_chain"],
            conditions=data["conditions"],
            comment=f"term: {data['term']}",
            disabled=is_disabled,
            raw_syntax="; ".join(data["raw_lines"])
        )
        rules.append(rule)
        rule_order += 1

    return rules, address_lists

def _parse_junos_hierarchical(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Junos nested blocks using a clean brace-depth parser.
    """
    address_lists: Dict[str, AddressList] = {}
    rules: List[FirewallRule] = []
    rule_order = 1

    # Extract prefix-lists first
    plist_matches = re.finditer(r"prefix-list\s+([\w\-]+)\s*\{([^}]+)\}", content)
    for m in plist_matches:
        pl_name = m.group(1).strip()
        body = m.group(2).strip()
        if pl_name not in address_lists:
            address_lists[pl_name] = AddressList(name=pl_name, entries=[])
        for entry_line in body.split(";"):
            entry_line = entry_line.strip()
            if entry_line and not entry_line.startswith("/*") and not entry_line.startswith("#"):
                if "apply-path" not in entry_line:
                    address_lists[pl_name].entries.append(
                        AddressListEntry(id=str(uuid.uuid4())[:8], address=entry_line)
                    )

    # Clean comments
    cleaned = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    cleaned = re.sub(r"#.*", "", cleaned)

    # Find each filter block
    filter_starts = [m.start() for m in re.finditer(r"\bfilter\s+([\w\-]+)\s*\{", cleaned)]

    for f_start in filter_starts:
        m_fname = re.match(r"\bfilter\s+([\w\-]+)\s*\{", cleaned[f_start:])
        if not m_fname:
            continue
        filter_name = m_fname.group(1)

        open_brace = f_start + m_fname.end() - 1
        depth = 1
        pos = open_brace + 1
        filter_content = ""

        while pos < len(cleaned) and depth > 0:
            if cleaned[pos] == "{":
                depth += 1
            elif cleaned[pos] == "}":
                depth -= 1
            pos += 1

        if depth == 0:
            filter_content = cleaned[open_brace + 1:pos - 1]

        # Extract terms from filter_content
        term_starts = [m.start() for m in re.finditer(r"\bterm\s+([\w\-]+)\s*\{", filter_content)]

        for t_start in term_starts:
            m_tname = re.match(r"\bterm\s+([\w\-]+)\s*\{", filter_content[t_start:])
            if not m_tname:
                continue
            term_name = m_tname.group(1)

            t_open = t_start + m_tname.end() - 1
            t_depth = 1
            t_pos = t_open + 1
            term_content = ""

            while t_pos < len(filter_content) and t_depth > 0:
                if filter_content[t_pos] == "{":
                    t_depth += 1
                elif filter_content[t_pos] == "}":
                    t_depth -= 1
                t_pos += 1

            if t_depth == 0:
                term_content = filter_content[t_open + 1:t_pos - 1]

            cond = RuleCondition()
            action = "accept"
            target_chain = None

            # Sub-filter jump: filter <other_filter>;
            subfilter_m = re.search(r"\bfilter\s+([\w\-]+);", term_content)
            if subfilter_m:
                action = "jump"
                target_chain = subfilter_m.group(1).strip()

            # Parse 'from'
            from_m = re.search(r"\bfrom\s*\{([\s\S]*?)\}", term_content)
            if from_m:
                from_body = from_m.group(1)

                proto_m = re.search(r"(?:protocol|next-header)\s+([\w\-]+);?", from_body)
                if proto_m:
                    cond.protocol = proto_m.group(1).strip().lower()

                src_m = re.findall(r"source-address\s+([\d\.\/\w:]+);?", from_body)
                if src_m:
                    cond.src_address = ",".join(src_m)

                dst_m = re.findall(r"destination-address\s+([\d\.\/\w:]+);?", from_body)
                if dst_m:
                    cond.dst_address = ",".join(dst_m)

                dport_m = re.search(r"destination-port\s+(?:\[\s*([^\]]+)\s*\]|([\w\d\-]+));?", from_body)
                if dport_m:
                    raw_ports = dport_m.group(1) or dport_m.group(2)
                    ports = [resolve_junos_port(p.strip()) for p in raw_ports.replace(";", "").split() if p.strip()]
                    cond.dst_port = ",".join(ports)

                sport_m = re.search(r"source-port\s+(?:\[\s*([^\]]+)\s*\]|([\w\d\-]+));?", from_body)
                if sport_m:
                    raw_ports = sport_m.group(1) or sport_m.group(2)
                    ports = [resolve_junos_port(p.strip()) for p in raw_ports.replace(";", "").split() if p.strip()]
                    cond.src_port = ",".join(ports)

                port_m = re.search(r"\bport\s+(?:\[\s*([^\]]+)\s*\]|([\w\d\-]+));?", from_body)
                if port_m and not sport_m and not dport_m:
                    raw_ports = port_m.group(1) or port_m.group(2)
                    ports = [resolve_junos_port(p.strip()) for p in raw_ports.replace(";", "").split() if p.strip()]
                    cond.port = ",".join(ports)

                pl_m = re.findall(r"(?:source-prefix-list|prefix-list)\s*\{?\s*([\w\-]+);?\s*\}?", from_body)
                if pl_m:
                    cond.src_address_list = ",".join(pl_m)

                dpl_m = re.findall(r"destination-prefix-list\s*\{?\s*([\w\-]+);?\s*\}?", from_body)
                if dpl_m:
                    cond.dst_address_list = ",".join(dpl_m)

                if "tcp-established" in from_body:
                    cond.connection_state = ["established", "related"]
                if "tcp-initial" in from_body:
                    cond.connection_state = ["new"]
                    cond.tcp_flags = ["syn", "!ack"]

            # Parse 'then'
            then_m = re.search(r"\bthen\s*\{([\s\S]*?)\}", term_content)
            if then_m:
                then_body = then_m.group(1).lower()
                if "discard" in then_body:
                    action = "drop"
                elif "reject" in then_body:
                    action = "reject"
                elif "accept" in then_body:
                    action = "accept"
                elif ("policer" in then_body or "count" in then_body) and action not in ["drop", "reject", "accept", "jump"]:
                    action = "passthrough"

            rule = FirewallRule(
                id=str(rule_order),
                order=rule_order,
                table="filter",
                chain=filter_name,
                action=action,
                target_chain=target_chain,
                conditions=cond,
                comment=f"term {term_name}",
                raw_syntax=f"filter {filter_name} term {term_name}"
            )
            rules.append(rule)
            rule_order += 1

    return rules, address_lists
