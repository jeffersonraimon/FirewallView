from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def export_to_nftables(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = [
        "#!/usr/sbin/nft -f",
        "# Exported by FirewallView (nftables syntax)",
        "flush ruleset",
        "",
        "table inet filter {"
    ]

    # Export sets
    if address_lists:
        for name, alist in address_lists.items():
            elements = [e.address for e in alist.entries if not e.disabled]
            if elements:
                lines.append(f"    set {name} {{")
                lines.append("        type ipv4_addr")
                lines.append(f"        elements = {{ {', '.join(elements)} }}")
                lines.append("    }")
        lines.append("")

    # Group by chain
    by_chain: Dict[str, List[FirewallRule]] = {}
    for r in sorted(rules, key=lambda x: x.order):
        by_chain.setdefault(r.chain.lower(), []).append(r)

    for chain, r_list in by_chain.items():
        lines.append(f"    chain {chain} {{")
        for r in r_list:
            if r.disabled:
                continue

            c = r.conditions
            parts = ["       "]

            # Connection state
            if c.connection_state:
                parts.append(f"ct state {{ {', '.join(c.connection_state)} }}")

            # Interfaces
            if c.in_interface:
                parts.append(f'iifname "{c.in_interface}"')
            if c.out_interface:
                parts.append(f'oifname "{c.out_interface}"')

            # Protocol
            if c.protocol and c.protocol not in ["any", "ip"]:
                if c.protocol == "icmp":
                    parts.append("ip protocol icmp")
                else:
                    parts.append(c.protocol)

            # Addresses
            if c.src_address:
                parts.append(f"ip saddr {c.src_address}")
            if c.dst_address:
                parts.append(f"ip daddr {c.dst_address}")

            # Sets
            if c.src_address_list:
                parts.append(f"ip saddr @{c.src_address_list}")
            if c.dst_address_list:
                parts.append(f"ip daddr @{c.dst_address_list}")

            # Ports
            if c.dst_port:
                p_proto = c.protocol if c.protocol in ["tcp", "udp"] else "tcp"
                parts.append(f"{p_proto} dport {c.dst_port}")
            if c.src_port:
                p_proto = c.protocol if c.protocol in ["tcp", "udp"] else "tcp"
                parts.append(f"{p_proto} sport {c.src_port}")

            # Action
            act = r.action.lower()
            if act == "dst-nat":
                target = f"{r.nat_to_addresses}"
                if r.nat_to_ports:
                    target += f":{r.nat_to_ports}"
                parts.append(f"dnat to {target}")
            elif act == "src-nat":
                parts.append(f"snat to {r.nat_to_addresses}")
            elif act == "jump" and r.target_chain:
                parts.append(f"jump {r.target_chain}")
            else:
                parts.append(act)

            if r.comment:
                parts.append(f'comment "{r.comment}"')

            lines.append(" ".join(parts))
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)
