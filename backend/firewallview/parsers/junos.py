import re
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def parse_junos_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Juniper Junos OS firewall configurations:
    Supports both hierarchical block syntax (filter { term { ... } }) and 'set' format.
    """
    lines = content.splitlines()
    set_lines = [l.strip() for l in lines if l.strip().startswith("set ")]

    if len(set_lines) > 0 and len(set_lines) >= len([l for l in lines if "{" in l]):
        return _parse_junos_set(lines)
    else:
        return _parse_junos_hierarchical(content)

def _parse_junos_set(lines: List[str]) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    address_lists: Dict[str, AddressList] = {}
    term_rules: Dict[str, Dict] = {}
    term_order_list: List[Tuple[str, str]] = []

    for line in lines:
        stripped = line.strip()
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
                        "comment": None,
                        "raw_lines": []
                    }
                    term_order_list.append(key)

                term_data = term_rules[key]
                term_data["raw_lines"].append(stripped)
                cond = term_data["conditions"]

                line_str = " ".join(tokens[t_idx + 2:])

                if "then accept" in line_str:
                    term_data["action"] = "accept"
                elif "then discard" in line_str:
                    term_data["action"] = "drop"
                elif "then reject" in line_str:
                    term_data["action"] = "reject"

                if "from protocol" in line_str:
                    p_idx = tokens.index("protocol")
                    if p_idx + 1 < len(tokens):
                        cond.protocol = tokens[p_idx + 1].replace(";", "")

                if "from source-address" in line_str:
                    s_idx = tokens.index("source-address")
                    if s_idx + 1 < len(tokens):
                        cond.src_address = tokens[s_idx + 1].replace(";", "")

                if "from destination-address" in line_str:
                    d_idx = tokens.index("destination-address")
                    if d_idx + 1 < len(tokens):
                        cond.dst_address = tokens[d_idx + 1].replace(";", "")

                if "from destination-port" in line_str:
                    dp_idx = tokens.index("destination-port")
                    if dp_idx + 1 < len(tokens):
                        cond.dst_port = tokens[dp_idx + 1].replace(";", "").replace("[", "").replace("]", "")

                if "from source-port" in line_str:
                    sp_idx = tokens.index("source-port")
                    if sp_idx + 1 < len(tokens):
                        cond.src_port = tokens[sp_idx + 1].replace(";", "").replace("[", "").replace("]", "")

                if "source-prefix-list" in tokens:
                    pl_idx = tokens.index("source-prefix-list")
                    if pl_idx + 1 < len(tokens):
                        cond.src_address_list = tokens[pl_idx + 1].replace(";", "")
                elif "destination-prefix-list" in tokens:
                    pl_idx = tokens.index("destination-prefix-list")
                    if pl_idx + 1 < len(tokens):
                        cond.dst_address_list = tokens[pl_idx + 1].replace(";", "")
                elif "prefix-list" in tokens and "from" in tokens:
                    pl_idx = tokens.index("prefix-list")
                    if pl_idx + 1 < len(tokens):
                        cond.src_address_list = tokens[pl_idx + 1].replace(";", "")

                if "tcp-established" in line_str:
                    cond.connection_state = ["established", "related"]

    rules: List[FirewallRule] = []
    rule_order = 1
    for key in term_order_list:
        data = term_rules[key]
        rule = FirewallRule(
            id=str(rule_order),
            order=rule_order,
            table="filter",
            chain=data["filter"],
            action=data["action"],
            conditions=data["conditions"],
            comment=f"term: {data['term']}",
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

            # Parse 'from'
            from_m = re.search(r"\bfrom\s*\{([\s\S]*?)\}", term_content)
            if from_m:
                from_body = from_m.group(1)

                proto_m = re.search(r"protocol\s+([\w\-]+);?", from_body)
                if proto_m:
                    cond.protocol = proto_m.group(1).strip().lower()

                src_m = re.search(r"source-address\s+([\d\.\/]+);?", from_body)
                if src_m:
                    cond.src_address = src_m.group(1).strip()

                dst_m = re.search(r"destination-address\s+([\d\.\/]+);?", from_body)
                if dst_m:
                    cond.dst_address = dst_m.group(1).strip()

                dport_m = re.search(r"destination-port\s+(?:\[\s*([^\]]+)\s*\]|([\w\d\-]+));?", from_body)
                if dport_m:
                    raw_ports = dport_m.group(1) or dport_m.group(2)
                    ports = [p.strip() for p in raw_ports.replace(";", "").split() if p.strip()]
                    cond.dst_port = ",".join(ports)

                sport_m = re.search(r"source-port\s+(?:\[\s*([^\]]+)\s*\]|([\w\d\-]+));?", from_body)
                if sport_m:
                    raw_ports = sport_m.group(1) or sport_m.group(2)
                    ports = [p.strip() for p in raw_ports.replace(";", "").split() if p.strip()]
                    cond.src_port = ",".join(ports)

                pl_m = re.search(r"(?:source-prefix-list|prefix-list)\s*\{?\s*([\w\-]+);?\s*\}?", from_body)
                if pl_m:
                    cond.src_address_list = pl_m.group(1).strip()

                dpl_m = re.search(r"destination-prefix-list\s*\{?\s*([\w\-]+);?\s*\}?", from_body)
                if dpl_m:
                    cond.dst_address_list = dpl_m.group(1).strip()

                if "tcp-established" in from_body:
                    cond.connection_state = ["established", "related"]

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

            rule = FirewallRule(
                id=str(rule_order),
                order=rule_order,
                table="filter",
                chain=filter_name,
                action=action,
                conditions=cond,
                comment=f"term {term_name}",
                raw_syntax=f"filter {filter_name} term {term_name}"
            )
            rules.append(rule)
            rule_order += 1

    return rules, address_lists
