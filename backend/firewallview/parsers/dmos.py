import re
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList

DMOS_SERVICES = {
    "bgp": "179",
    "ldp": "646",
    "ospf": "89",
    "rip": "520",
    "bfd": "3784",
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
    "dns": "53",
    "domain": "53",
    "tacacs": "49",
    "radius": "1812",
}

DMOS_PROTOCOLS = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "46": "rsvp",
    "47": "gre",
    "50": "esp",
    "51": "ah",
    "89": "ospf",
    "112": "vrrp",
    "ipv6-icmp": "icmp6",
    "icmpv6": "icmp6",
}

def resolve_dmos_port(val: str) -> str:
    cleaned = val.strip().lower()
    return DMOS_SERVICES.get(cleaned, cleaned)

def resolve_dmos_protocol(val: str) -> str:
    cleaned = val.strip().lower()
    return DMOS_PROTOCOLS.get(cleaned, cleaned)

def parse_dmos_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Datacom DmOS access-list and acl-profile configurations:
    - Detects CPU protection profiles (chain: input, table: filter).
    - Extracts access-list-entry with sequence numbers, match conditions, and actions (permit -> accept, deny -> drop).
    """
    address_lists: Dict[str, AddressList] = {}
    rules: List[FirewallRule] = []

    lines = content.splitlines()

    # Heuristic: Check if this profile or protection targets CPU
    is_cpu_protection = (
        "protection" in content.lower() and "cpu" in content.lower()
    ) or "acl-profile cpu" in content.lower()

    default_chain = "input" if is_cpu_protection else "forward"

    current_entry_id: Optional[str] = None
    current_comment: Optional[str] = None
    current_cond = RuleCondition()
    current_action = "accept"
    current_raw_lines: List[str] = []
    rule_order = 1

    def save_current_rule():
        nonlocal current_entry_id, current_comment, current_cond, current_action, current_raw_lines, rule_order
        if current_entry_id is not None:
            rules.append(
                FirewallRule(
                    id=str(current_entry_id),
                    order=rule_order,
                    table="filter",
                    chain=default_chain,
                    action=current_action,
                    conditions=current_cond,
                    comment=current_comment or f"entry {current_entry_id}",
                    raw_syntax="; ".join(current_raw_lines)
                )
            )
            rule_order += 1
            current_entry_id = None
            current_comment = None
            current_cond = RuleCondition()
            current_action = "accept"
            current_raw_lines = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Start of a new access-list-entry
        m_entry = re.match(r"^access-list-entry\s+(\d+)", stripped)
        if m_entry:
            save_current_rule()
            current_entry_id = m_entry.group(1)
            current_raw_lines.append(stripped)
            continue

        # End delimiter
        if stripped == "!":
            save_current_rule()
            continue

        if current_entry_id is not None:
            current_raw_lines.append(stripped)

            # description <comment>
            if stripped.startswith("description "):
                current_comment = stripped[len("description "):].strip()
                continue

            # action <permit|deny>
            if stripped.startswith("action "):
                act = stripped[len("action "):].strip().lower()
                if act in ["permit", "accept"]:
                    current_action = "accept"
                elif act in ["deny", "drop"]:
                    current_action = "drop"
                elif act == "reject":
                    current_action = "reject"
                continue

            # match <criterion> <value>
            if stripped.startswith("match "):
                parts = stripped.split()
                if len(parts) >= 3:
                    criterion = parts[1].lower()
                    val = parts[2]

                    if criterion in ["ip-protocol", "protocol"]:
                        current_cond.protocol = resolve_dmos_protocol(val)

                    elif criterion in ["source-ipv4-address", "source-ipv6-address", "source-ip", "src-ip"]:
                        current_cond.src_address = val

                    elif criterion in ["destination-ipv4-address", "destination-ipv6-address", "destination-ip", "dst-ip"]:
                        current_cond.dst_address = val

                    elif criterion in ["source-port", "src-port"]:
                        current_cond.src_port = resolve_dmos_port(val)

                    elif criterion in ["destination-port", "dst-port"]:
                        current_cond.dst_port = resolve_dmos_port(val)

                    elif criterion == "port":
                        current_cond.port = resolve_dmos_port(val)

                    elif criterion == "ethertype":
                        if val.lower() == "arp":
                            current_cond.protocol = "arp"

    # Save last entry if buffer remains
    save_current_rule()

    return rules, address_lists
