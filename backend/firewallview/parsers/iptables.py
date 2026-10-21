import shlex
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def parse_iptables_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses standard iptables commands or iptables-save dump, as well as ipset commands.
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    current_table = "filter"
    rule_order = 1

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for ipset creation: e.g. "ipset create BLACKLIST hash:net", "ipset add BLACKLIST 10.0.0.0/8"
        if line.startswith("ipset "):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "create":
                set_name = parts[2]
                if set_name not in address_lists:
                    address_lists[set_name] = AddressList(name=set_name, entries=[])
            elif len(parts) >= 4 and parts[1] == "add":
                set_name = parts[2]
                ip_entry = parts[3]
                if set_name not in address_lists:
                    address_lists[set_name] = AddressList(name=set_name, entries=[])
                address_lists[set_name].entries.append(
                    AddressListEntry(id=str(uuid.uuid4())[:8], address=ip_entry)
                )
            continue

        # iptables-save table declaration
        if line.startswith("*"):
            current_table = line[1:].strip().lower()
            continue
        if line == "COMMIT":
            continue

        # Ignore policy definitions like ":INPUT ACCEPT [0:0]"
        if line.startswith(":"):
            continue

        # Remove "iptables " prefix if present
        clean_line = line
        if clean_line.startswith("iptables "):
            clean_line = clean_line[len("iptables "):].strip()

        try:
            tokens = shlex.split(clean_line)
        except ValueError:
            tokens = clean_line.split()

        if not tokens:
            continue

        table = current_table
        chain = "FORWARD"
        action = "ACCEPT"
        target_chain = None
        nat_to_addresses = None
        nat_to_ports = None
        comment = None
        cond = RuleCondition()

        i = 0
        negate_next = False

        while i < len(tokens):
            tok = tokens[i]

            if tok == "!":
                negate_next = True
                i += 1
                continue

            if tok == "-t" and i + 1 < len(tokens):
                table = tokens[i + 1].lower()
                i += 2
                continue

            elif tok in ["-A", "--append", "-I", "--insert"] and i + 1 < len(tokens):
                chain = tokens[i + 1].lower()
                i += 2
                continue

            elif tok in ["-j", "--jump"] and i + 1 < len(tokens):
                target = tokens[i + 1]
                t_upper = target.upper()
                if t_upper in ["ACCEPT", "DROP", "REJECT", "MASQUERADE", "RETURN"]:
                    action = t_upper.lower()
                elif t_upper == "DNAT":
                    action = "dst-nat"
                elif t_upper == "SNAT":
                    action = "src-nat"
                elif t_upper == "REDIRECT":
                    action = "redirect"
                else:
                    action = "jump"
                    target_chain = target
                i += 2
                continue

            elif tok in ["-p", "--protocol"] and i + 1 < len(tokens):
                cond.protocol = tokens[i + 1].lower()
                cond.negate_protocol = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["-s", "--source"] and i + 1 < len(tokens):
                cond.src_address = tokens[i + 1]
                cond.negate_src_address = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["-d", "--destination"] and i + 1 < len(tokens):
                cond.dst_address = tokens[i + 1]
                cond.negate_dst_address = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["-i", "--in-interface"] and i + 1 < len(tokens):
                cond.in_interface = tokens[i + 1]
                cond.negate_in_interface = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["-o", "--out-interface"] and i + 1 < len(tokens):
                cond.out_interface = tokens[i + 1]
                cond.negate_out_interface = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["--dport", "--destination-port"] and i + 1 < len(tokens):
                cond.dst_port = tokens[i + 1].replace(":", "-")
                cond.negate_dst_port = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["--sport", "--source-port"] and i + 1 < len(tokens):
                cond.src_port = tokens[i + 1].replace(":", "-")
                cond.negate_src_port = negate_next
                negate_next = False
                i += 2
                continue

            elif tok in ["--state", "--ctstate"] and i + 1 < len(tokens):
                states = tokens[i + 1].lower().split(",")
                cond.connection_state = [s.strip() for s in states]
                i += 2
                continue

            elif tok == "--match-set" and i + 2 < len(tokens):
                set_name = tokens[i + 1]
                direction = tokens[i + 2].lower()
                if "src" in direction:
                    cond.src_address_list = set_name
                    cond.negate_src_address_list = negate_next
                elif "dst" in direction:
                    cond.dst_address_list = set_name
                    cond.negate_dst_address_list = negate_next
                negate_next = False
                i += 3
                continue

            elif tok == "--comment" and i + 1 < len(tokens):
                comment = tokens[i + 1]
                i += 2
                continue

            elif tok == "--to-destination" and i + 1 < len(tokens):
                target_val = tokens[i + 1]
                if ":" in target_val:
                    ip, port = target_val.split(":", 1)
                    nat_to_addresses = ip
                    nat_to_ports = port
                else:
                    nat_to_addresses = target_val
                i += 2
                continue

            elif tok == "--to-ports" and i + 1 < len(tokens):
                nat_to_ports = tokens[i + 1]
                i += 2
                continue

            elif tok == "--to-source" and i + 1 < len(tokens):
                nat_to_addresses = tokens[i + 1]
                i += 2
                continue

            i += 1
            negate_next = False

        rule = FirewallRule(
            id=str(rule_order),
            order=rule_order,
            table=table,
            chain=chain,
            action=action,
            target_chain=target_chain,
            nat_to_addresses=nat_to_addresses,
            nat_to_ports=nat_to_ports,
            conditions=cond,
            comment=comment,
            raw_syntax=line
        )
        rules.append(rule)
        rule_order += 1

    return rules, address_lists
