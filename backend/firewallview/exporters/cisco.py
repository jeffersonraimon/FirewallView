import ipaddress
from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def cidr_to_wildcard(cidr_str: str) -> str:
    """Converts IP/CIDR (e.g. 192.168.1.0/24) to Cisco network + wildcard string."""
    try:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
        net_addr = str(net.network_address)
        netmask = int(net.netmask)
        hostmask = ~netmask & 0xFFFFFFFF
        wc_str = f"{(hostmask >> 24) & 0xFF}.{(hostmask >> 16) & 0xFF}.{(hostmask >> 8) & 0xFF}.{hostmask & 0xFF}"
        if net.prefixlen == 32:
            return f"host {net_addr}"
        return f"{net_addr} {wc_str}"
    except Exception:
        return f"host {cidr_str}"

def export_to_cisco(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = [
        "! Exported by FirewallView (Cisco IOS / ASA ACL format)",
        "!"
    ]

    # Export Object-Groups
    if address_lists:
        for name, alist in address_lists.items():
            lines.append(f"object-group network {name}")
            for entry in alist.entries:
                if entry.disabled:
                    continue
                addr = entry.address.strip()
                if "/" in addr:
                    try:
                        net = ipaddress.IPv4Network(addr, strict=False)
                        lines.append(f" network-object {net.network_address} {net.netmask}")
                    except Exception:
                        lines.append(f" network-object {addr}")
                else:
                    lines.append(f" network-object host {addr}")
            lines.append("!")

    # Group rules by chain (representing ACL name)
    by_chain: Dict[str, List[FirewallRule]] = {}
    for r in sorted(rules, key=lambda x: x.order):
        acl_name = r.chain if r.chain and r.chain not in ["forward", "input", "prerouting"] else "FW_FILTER"
        by_chain.setdefault(acl_name, []).append(r)

    for acl_name, r_list in by_chain.items():
        lines.append(f"ip access-list extended {acl_name}")
        for r in r_list:
            if r.disabled:
                continue

            c = r.conditions
            action_str = "permit" if r.action.lower() in ["accept", "fasttrack-connection"] else "deny"
            proto = c.protocol if c.protocol and c.protocol not in ["any"] else "ip"

            parts = [f" {action_str}", proto]

            # Source
            if c.src_address_list:
                parts.append(f"object-group {c.src_address_list}")
            elif c.src_address:
                parts.append(cidr_to_wildcard(c.src_address))
            else:
                parts.append("any")

            if c.src_port:
                if "-" in c.src_port:
                    p1, p2 = c.src_port.split("-", 1)
                    parts.append(f"range {p1} {p2}")
                else:
                    parts.append(f"eq {c.src_port}")

            # Destination
            if c.dst_address_list:
                parts.append(f"object-group {c.dst_address_list}")
            elif c.dst_address:
                parts.append(cidr_to_wildcard(c.dst_address))
            else:
                parts.append("any")

            if c.dst_port:
                if "-" in c.dst_port:
                    p1, p2 = c.dst_port.split("-", 1)
                    parts.append(f"range {p1} {p2}")
                else:
                    parts.append(f"eq {c.dst_port}")

            # Established
            if c.connection_state and "established" in c.connection_state:
                parts.append("established")

            lines.append(" ".join(parts))
        lines.append("!")

    return "\n".join(lines)
