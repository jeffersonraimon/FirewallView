from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def export_to_junos(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = [
        "/* Exported by FirewallView (Juniper Junos OS syntax) */",
        "firewall {",
        "    family inet {"
    ]

    # Export prefix-lists (Address lists)
    if address_lists:
        for name, alist in address_lists.items():
            lines.append(f"        prefix-list {name} {{")
            for entry in alist.entries:
                if entry.disabled:
                    continue
                addr = entry.address.strip()
                if "/" not in addr and "-" not in addr:
                    addr += "/32"
                lines.append(f"            {addr};")
            lines.append("        }")
        lines.append("")

    # Group rules by chain (filter name)
    by_filter: Dict[str, List[FirewallRule]] = {}
    for r in sorted(rules, key=lambda x: x.order):
        filter_name = r.chain if r.chain and r.chain not in ["forward", "input", "prerouting"] else "PROTECT_INBOUND"
        by_filter.setdefault(filter_name, []).append(r)

    for filter_name, r_list in by_filter.items():
        lines.append(f"        filter {filter_name} {{")
        for r in r_list:
            if r.disabled:
                continue

            term_name = r.comment.replace(" ", "-").replace(":", "-").lower() if r.comment else f"rule-{r.id}"
            # Clean term name to valid Junos identifier
            term_name = "".join(ch for ch in term_name if ch.isalnum() or ch in ["-", "_"])[:32]
            if not term_name:
                term_name = f"rule-{r.id}"

            lines.append(f"            term {term_name} {{")

            c = r.conditions
            has_from = (
                c.protocol or c.src_address or c.dst_address or
                c.src_address_list or c.dst_address_list or
                c.src_port or c.dst_port or c.in_interface or
                (c.connection_state and "established" in c.connection_state)
            )

            if has_from:
                lines.append("                from {")
                if c.src_address_list:
                    lines.append(f"                    source-prefix-list {c.src_address_list};")
                elif c.src_address:
                    lines.append(f"                    source-address {c.src_address};")

                if c.dst_address_list:
                    lines.append(f"                    destination-prefix-list {c.dst_address_list};")
                elif c.dst_address:
                    lines.append(f"                    destination-address {c.dst_address};")

                if c.protocol and c.protocol not in ["any", "ip"]:
                    lines.append(f"                    protocol {c.protocol};")

                if c.dst_port:
                    if "," in c.dst_port:
                        ports_str = " ".join(c.dst_port.split(","))
                        lines.append(f"                    destination-port [ {ports_str} ];")
                    else:
                        lines.append(f"                    destination-port {c.dst_port};")

                if c.src_port:
                    if "," in c.src_port:
                        ports_str = " ".join(c.src_port.split(","))
                        lines.append(f"                    source-port [ {ports_str} ];")
                    else:
                        lines.append(f"                    source-port {c.src_port};")

                if c.in_interface:
                    lines.append(f"                    interface {c.in_interface};")

                if c.connection_state and "established" in c.connection_state:
                    lines.append("                    tcp-established;")

                lines.append("                }")

            # Then block
            action = r.action.lower()
            lines.append("                then {")
            if action in ["drop", "discard"]:
                lines.append("                    discard;")
            elif action == "reject":
                lines.append("                    reject;")
            else:
                lines.append("                    accept;")
            lines.append("                }")

            lines.append("            }")
        lines.append("        }")

    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)
