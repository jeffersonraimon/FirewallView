import re
import ipaddress
import uuid
from typing import Dict, List, Tuple, Optional
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def wildcard_to_cidr(ip_str: str, wildcard_str: str) -> str:
    """Converts Cisco wildcard mask (e.g. 0.0.0.255) to CIDR notation."""
    try:
        # Wildcard inverse is netmask
        wc_parts = [int(p) for p in wildcard_str.split(".")]
        mask_parts = [255 - p for p in wc_parts]
        mask_str = ".".join(str(p) for p in mask_parts)
        net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return str(net)
    except Exception:
        return f"{ip_str}/{wildcard_str}"

def parse_cisco_acl(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Cisco Standard, Extended and Named Access Control Lists & Object-Groups.
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    rule_order = 1
    current_named_acl = None
    current_obj_group = None

    lines = content.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue

        # Handle object-group network <name>
        if stripped.startswith("object-group network "):
            parts = stripped.split()
            if len(parts) >= 3:
                current_obj_group = parts[2]
                if current_obj_group not in address_lists:
                    address_lists[current_obj_group] = AddressList(name=current_obj_group, entries=[])
            continue

        if current_obj_group:
            if stripped.startswith("network-object host "):
                host_ip = stripped.split()[2]
                address_lists[current_obj_group].entries.append(
                    AddressListEntry(id=str(uuid.uuid4())[:8], address=host_ip)
                )
                continue
            elif stripped.startswith("network-object "):
                # e.g. network-object 192.168.1.0 255.255.255.0
                parts = stripped.split()
                if len(parts) >= 3:
                    try:
                        net = ipaddress.IPv4Network(f"{parts[1]}/{parts[2]}", strict=False)
                        address_lists[current_obj_group].entries.append(
                            AddressListEntry(id=str(uuid.uuid4())[:8], address=str(net))
                        )
                    except Exception:
                        address_lists[current_obj_group].entries.append(
                            AddressListEntry(id=str(uuid.uuid4())[:8], address=parts[1])
                        )
                continue
            elif not stripped.startswith("network-object") and not stripped.startswith("description"):
                current_obj_group = None

        # Handle ip access-list [standard|extended] <name>
        if stripped.startswith("ip access-list "):
            parts = stripped.split()
            if len(parts) >= 4:
                current_named_acl = parts[3]
            elif len(parts) >= 3:
                current_named_acl = parts[2]
            continue

        # Rule lines: either named subline, or "access-list 101 ..."
        tokens = stripped.split()
        if not tokens:
            continue

        acl_name = current_named_acl or "cisco-acl"
        idx = 0

        if tokens[0] == "access-list":
            if len(tokens) < 3:
                continue
            acl_name = f"acl_{tokens[1]}"
            idx = 2

        if idx >= len(tokens):
            continue

        action_token = tokens[idx].lower()
        if action_token not in ["permit", "deny"]:
            continue

        action = "accept" if action_token == "permit" else "drop"
        idx += 1

        protocol = "ip"
        if idx < len(tokens):
            protocol = tokens[idx].lower()
            idx += 1

        cond = RuleCondition()
        if protocol not in ["ip", "any"]:
            cond.protocol = protocol

        # Helper to parse source or dest IP/group
        def parse_ip_spec(curr_idx: int) -> Tuple[Optional[str], Optional[str], int]:
            # Returns (ip_or_cidr, group_name, new_idx)
            if curr_idx >= len(tokens):
                return None, None, curr_idx

            t = tokens[curr_idx].lower()
            if t == "any":
                return None, None, curr_idx + 1
            elif t == "host" and curr_idx + 1 < len(tokens):
                return tokens[curr_idx + 1], None, curr_idx + 2
            elif t == "object-group" and curr_idx + 1 < len(tokens):
                return None, tokens[curr_idx + 1], curr_idx + 2
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
                # Check if next token is wildcard mask
                if curr_idx + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[curr_idx + 1]):
                    cidr = wildcard_to_cidr(tokens[curr_idx], tokens[curr_idx + 1])
                    return cidr, None, curr_idx + 2
                return tokens[curr_idx], None, curr_idx + 1
            return None, None, curr_idx + 1

        # Source
        src_ip, src_grp, idx = parse_ip_spec(idx)
        if src_ip:
            cond.src_address = src_ip
        if src_grp:
            cond.src_address_list = src_grp

        # Optional source port (e.g. eq 80)
        if idx < len(tokens) and tokens[idx].lower() in ["eq", "gt", "lt", "range"]:
            op = tokens[idx].lower()
            if op == "eq" and idx + 1 < len(tokens):
                cond.src_port = tokens[idx + 1]
                idx += 2
            elif op == "range" and idx + 2 < len(tokens):
                cond.src_port = f"{tokens[idx + 1]}-{tokens[idx + 2]}"
                idx += 3
            else:
                idx += 2

        # Destination
        dst_ip, dst_grp, idx = parse_ip_spec(idx)
        if dst_ip:
            cond.dst_address = dst_ip
        if dst_grp:
            cond.dst_address_list = dst_grp

        # Destination port
        if idx < len(tokens) and tokens[idx].lower() in ["eq", "gt", "lt", "range"]:
            op = tokens[idx].lower()
            if op == "eq" and idx + 1 < len(tokens):
                cond.dst_port = tokens[idx + 1]
                idx += 2
            elif op == "range" and idx + 2 < len(tokens):
                cond.dst_port = f"{tokens[idx + 1]}-{tokens[idx + 2]}"
                idx += 3
            else:
                idx += 2

        # Check for established
        if idx < len(tokens) and tokens[idx].lower() == "established":
            cond.connection_state = ["established", "related"]

        rule = FirewallRule(
            id=str(rule_order),
            order=rule_order,
            table="filter",
            chain=acl_name,
            action=action,
            conditions=cond,
            raw_syntax=stripped
        )
        rules.append(rule)
        rule_order += 1

    return rules, address_lists
