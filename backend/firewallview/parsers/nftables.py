import re
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def parse_nftables_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses nftables configuration syntax (blocks and one-line rules).
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    rule_order = 1

    current_table = "filter"
    current_chain = "forward"
    inside_set = False
    current_set_name = ""

    lines = content.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Handle sets
        # e.g.: set blocked_hosts {
        if stripped.startswith("set ") and "{" in stripped:
            inside_set = True
            current_set_name = stripped.split()[1]
            if current_set_name not in address_lists:
                address_lists[current_set_name] = AddressList(name=current_set_name, entries=[])
            continue

        if inside_set:
            if "elements" in stripped:
                # elements = { 10.0.0.1, 192.168.1.0/24 }
                elems_part = stripped.split("=", 1)[1].replace("{", "").replace("}", "").strip()
                for el in elems_part.split(","):
                    el = el.strip()
                    if el:
                        address_lists[current_set_name].entries.append(
                            AddressListEntry(id=str(uuid.uuid4())[:8], address=el)
                        )
            if "}" in stripped:
                inside_set = False
            continue

        # Handle table declaration
        if stripped.startswith("table "):
            parts = stripped.split()
            if len(parts) >= 3:
                current_table = parts[2].replace("{", "").strip().lower()
            continue

        # Handle chain declaration
        if stripped.startswith("chain "):
            parts = stripped.split()
            if len(parts) >= 2:
                current_chain = parts[1].replace("{", "").strip().lower()
            continue

        if stripped == "}":
            continue

        # One-line commands or rule lines within a chain
        rule_line = stripped
        if rule_line.startswith("add rule ") or rule_line.startswith("nft add rule "):
            # nft add rule inet filter input ...
            toks = rule_line.replace("nft ", "").replace("add rule ", "").split()
            if len(toks) >= 3:
                # toks[0]=family, toks[1]=table, toks[2]=chain
                current_table = toks[1].lower()
                current_chain = toks[2].lower()
                rule_line = " ".join(toks[3:])

        # Skip chain type/hook declarations
        if "type filter hook" in rule_line or "type nat hook" in rule_line:
            continue

        tokens = rule_line.split()
        if not tokens:
            continue

        # Parse conditions and action
        cond = RuleCondition()
        action = "accept"
        target_chain = None
        nat_to_addresses = None
        nat_to_ports = None

        # Check last token as common action: accept, drop, reject, return
        last_tok = tokens[-1].lower()
        if last_tok in ["accept", "drop", "reject", "return", "masquerade"]:
            action = last_tok
            tokens = tokens[:-1]
        elif "dnat to" in rule_line:
            action = "dst-nat"
            m = re.search(r"dnat\s+to\s+([0-9\.]+)(?::([0-9]+))?", rule_line)
            if m:
                nat_to_addresses = m.group(1)
                nat_to_ports = m.group(2)
        elif "snat to" in rule_line:
            action = "src-nat"
            m = re.search(r"snat\s+to\s+([0-9\.]+)(?::([0-9]+))?", rule_line)
            if m:
                nat_to_addresses = m.group(1)
                nat_to_ports = m.group(2)
        elif "jump" in tokens:
            action = "jump"
            j_idx = tokens.index("jump")
            if j_idx + 1 < len(tokens):
                target_chain = tokens[j_idx + 1]

        # Scan for matchers
        rule_str = " ".join(tokens)

        # ip saddr
        m_saddr = re.search(r"ip\s+saddr\s+(@?[\w\.\/]+)", rule_str)
        if m_saddr:
            val = m_saddr.group(1)
            if val.startswith("@"):
                cond.src_address_list = val[1:]
            else:
                cond.src_address = val

        # ip daddr
        m_daddr = re.search(r"ip\s+daddr\s+(@?[\w\.\/]+)", rule_str)
        if m_daddr:
            val = m_daddr.group(1)
            if val.startswith("@"):
                cond.dst_address_list = val[1:]
            else:
                cond.dst_address = val

        # tcp/udp dport
        m_dport = re.search(r"(?:tcp|udp)\s+dport\s+(?:\{([^}]+)\}|(\d+))", rule_str)
        if m_dport:
            ports = m_dport.group(1) or m_dport.group(2)
            cond.dst_port = ports.replace(" ", "")
            if "tcp" in rule_str:
                cond.protocol = "tcp"
            elif "udp" in rule_str:
                cond.protocol = "udp"

        # tcp/udp sport
        m_sport = re.search(r"(?:tcp|udp)\s+sport\s+(?:\{([^}]+)\}|(\d+))", rule_str)
        if m_sport:
            ports = m_sport.group(1) or m_sport.group(2)
            cond.src_port = ports.replace(" ", "")

        # protocol icmp
        if "ip protocol icmp" in rule_str:
            cond.protocol = "icmp"

        # ct state
        m_ct = re.search(r"ct\s+state\s+([\w,]+)", rule_str)
        if m_ct:
            cond.connection_state = [s.strip() for s in m_ct.group(1).split(",")]

        # iif / oif
        m_iif = re.search(r'iif(?:name)?\s+"?([\w\.\-]+)"?', rule_str)
        if m_iif:
            cond.in_interface = m_iif.group(1)

        m_oif = re.search(r'oif(?:name)?\s+"?([\w\.\-]+)"?', rule_str)
        if m_oif:
            cond.out_interface = m_oif.group(1)

        rule = FirewallRule(
            id=str(rule_order),
            order=rule_order,
            table=current_table,
            chain=current_chain,
            action=action,
            target_chain=target_chain,
            nat_to_addresses=nat_to_addresses,
            nat_to_ports=nat_to_ports,
            conditions=cond,
            raw_syntax=stripped
        )
        rules.append(rule)
        rule_order += 1

    return rules, address_lists
