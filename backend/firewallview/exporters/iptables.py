from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def export_to_iptables(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# Exported by FirewallView (iptables & ipset syntax)",
        "set -e",
        ""
    ]

    # Export ipset
    if address_lists:
        lines.append("# === IPSET Definitions ===")
        for name, alist in address_lists.items():
            lines.append(f"ipset create {name} hash:net -exist")
            for entry in alist.entries:
                if not entry.disabled:
                    lines.append(f"ipset add {name} {entry.address} -exist")
        lines.append("")

    lines.append("# === IPTABLES Rules ===")
    for r in sorted(rules, key=lambda x: x.order):
        if r.disabled:
            lines.append(f"# [DISABLED] Rule {r.id}: {r.comment or ''}")
            continue

        c = r.conditions
        cmd = ["iptables"]

        if r.table and r.table.lower() != "filter":
            cmd.extend(["-t", r.table.lower()])

        cmd.extend(["-A", r.chain.upper()])

        # Protocol
        if c.protocol:
            if c.negate_protocol:
                cmd.append("!")
            cmd.extend(["-p", c.protocol])

        # Interfaces
        if c.in_interface:
            if c.negate_in_interface:
                cmd.append("!")
            cmd.extend(["-i", c.in_interface])

        if c.out_interface:
            if c.negate_out_interface:
                cmd.append("!")
            cmd.extend(["-o", c.out_interface])

        # Addresses
        if c.src_address:
            if c.negate_src_address:
                cmd.append("!")
            cmd.extend(["-s", c.src_address])

        if c.dst_address:
            if c.negate_dst_address:
                cmd.append("!")
            cmd.extend(["-d", c.dst_address])

        # Address lists (ipset)
        if c.src_address_list:
            if c.negate_src_address_list:
                cmd.append("!")
            cmd.extend(["-m", "set", "--match-set", c.src_address_list, "src"])

        if c.dst_address_list:
            if c.negate_dst_address_list:
                cmd.append("!")
            cmd.extend(["-m", "set", "--match-set", c.dst_address_list, "dst"])

        # Ports
        if c.src_port:
            if c.negate_src_port:
                cmd.append("!")
            cmd.extend(["--sport", c.src_port.replace("-", ":")])

        if c.dst_port:
            if c.negate_dst_port:
                cmd.append("!")
            cmd.extend(["--dport", c.dst_port.replace("-", ":")])

        # Conntrack state
        if c.connection_state:
            states_upper = [s.upper() for s in c.connection_state]
            cmd.extend(["-m", "conntrack", "--ctstate", ",".join(states_upper)])

        # Comment
        if r.comment:
            cmd.extend(["-m", "comment", "--comment", f'"{r.comment}"'])

        # Action / Target
        act = r.action.lower()
        if act == "accept":
            cmd.extend(["-j", "ACCEPT"])
        elif act == "drop":
            cmd.extend(["-j", "DROP"])
        elif act == "reject":
            cmd.extend(["-j", "REJECT"])
        elif act == "masquerade":
            cmd.extend(["-j", "MASQUERADE"])
        elif act == "dst-nat":
            target = f"{r.nat_to_addresses}"
            if r.nat_to_ports:
                target += f":{r.nat_to_ports}"
            cmd.extend(["-j", "DNAT", "--to-destination", target])
        elif act == "src-nat":
            cmd.extend(["-j", "SNAT", "--to-source", r.nat_to_addresses or ""])
        elif act == "redirect":
            cmd.extend(["-j", "REDIRECT"])
            if r.nat_to_ports:
                cmd.extend(["--to-ports", r.nat_to_ports])
        elif act == "jump" and r.target_chain:
            cmd.extend(["-j", r.target_chain])
        else:
            cmd.extend(["-j", act.upper()])

        lines.append(" ".join(cmd))

    return "\n".join(lines)
