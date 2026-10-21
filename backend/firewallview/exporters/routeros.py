from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def export_to_routeros(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = ["# Exported by FirewallView (MikroTik RouterOS v6/v7 syntax)", ""]

    # Export Address Lists
    if address_lists:
        lines.append("/ip firewall address-list")
        for name, alist in address_lists.items():
            for entry in alist.entries:
                cmd = f"add list={name} address={entry.address}"
                if entry.comment:
                    cmd += f' comment="{entry.comment}"'
                if entry.disabled:
                    cmd += " disabled=yes"
                lines.append(cmd)
        lines.append("")

    # Group rules by table
    by_table: Dict[str, List[FirewallRule]] = {}
    for r in sorted(rules, key=lambda x: x.order):
        by_table.setdefault(r.table.lower(), []).append(r)

    table_menus = {
        "filter": "/ip firewall filter",
        "nat": "/ip firewall nat",
        "mangle": "/ip firewall mangle",
        "raw": "/ip firewall raw"
    }

    for tbl, r_list in by_table.items():
        menu = table_menus.get(tbl, f"/ip firewall {tbl}")
        lines.append(menu)
        for r in r_list:
            c = r.conditions
            parts = [f"add chain={r.chain} action={r.action}"]

            if r.comment:
                parts.append(f'comment="{r.comment}"')

            # Protocol
            if c.protocol:
                p = f"!{c.protocol}" if c.negate_protocol else c.protocol
                parts.append(f"protocol={p}")

            # Src/Dst IP
            if c.src_address:
                s = f"!{c.src_address}" if c.negate_src_address else c.src_address
                parts.append(f"src-address={s}")
            if c.dst_address:
                d = f"!{c.dst_address}" if c.negate_dst_address else c.dst_address
                parts.append(f"dst-address={d}")

            # Address lists
            if c.src_address_list:
                sl = f"!{c.src_address_list}" if c.negate_src_address_list else c.src_address_list
                parts.append(f"src-address-list={sl}")
            if c.dst_address_list:
                dl = f"!{c.dst_address_list}" if c.negate_dst_address_list else c.dst_address_list
                parts.append(f"dst-address-list={dl}")

            # Ports
            if c.src_port:
                sp = f"!{c.src_port}" if c.negate_src_port else c.src_port
                parts.append(f"src-port={sp}")
            if c.dst_port:
                dp = f"!{c.dst_port}" if c.negate_dst_port else c.dst_port
                parts.append(f"dst-port={dp}")

            # Interfaces
            if c.in_interface:
                ii = f"!{c.in_interface}" if c.negate_in_interface else c.in_interface
                parts.append(f"in-interface={ii}")
            if c.out_interface:
                oi = f"!{c.out_interface}" if c.negate_out_interface else c.out_interface
                parts.append(f"out-interface={oi}")

            # Connection states
            if c.connection_state:
                parts.append(f"connection-state={','.join(c.connection_state)}")

            # TCP flags
            if c.tcp_flags:
                parts.append(f"tcp-flags={','.join(c.tcp_flags)}")

            # Targets & NAT
            if r.target_chain:
                parts.append(f"jump-target={r.target_chain}")
            if r.nat_to_addresses:
                parts.append(f"to-addresses={r.nat_to_addresses}")
            if r.nat_to_ports:
                parts.append(f"to-ports={r.nat_to_ports}")
            if r.mark_value:
                parts.append(f"new-packet-mark={r.mark_value}")

            if r.disabled:
                parts.append("disabled=yes")

            lines.append(" ".join(parts))
        lines.append("")

    return "\n".join(lines)
