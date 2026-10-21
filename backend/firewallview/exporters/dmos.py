from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

def export_to_dmos(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    """
    Exports FirewallRule list to Datacom DmOS access-list profile syntax.
    """
    lines = [
        "! Exported by FirewallView (Datacom DmOS syntax)",
        "access-list",
        " protection",
        "  cpu ACL-PADRAO-CPU",
        " !",
        " acl-profile cpu l3 ACL-PADRAO-CPU",
        "  priority 0"
    ]

    seq = 10
    for r in sorted(rules, key=lambda x: x.order):
        if r.disabled:
            continue

        lines.append(f"  access-list-entry {seq}")
        if r.comment:
            clean_comment = "".join(ch for ch in r.comment if ch.isalnum() or ch in ["-", "_", " "])
            clean_comment = "-".join(clean_comment.split())
            if clean_comment:
                lines.append(f"   description {clean_comment}")

        c = r.conditions
        if c.protocol and c.protocol not in ["any", "all", "ip"]:
            lines.append(f"   match ip-protocol {c.protocol}")

        if c.src_address:
            lines.append(f"   match source-ipv4-address {c.src_address}")

        if c.dst_address:
            lines.append(f"   match destination-ipv4-address {c.dst_address}")

        if c.src_port:
            lines.append(f"   match source-port {c.src_port}")

        if c.dst_port:
            lines.append(f"   match destination-port {c.dst_port}")

        action = "permit" if r.action.lower() in ["accept", "fasttrack-connection"] else "deny"
        lines.append(f"   action {action}")
        lines.append("  !")
        seq += 10

    lines.append(" !")
    lines.append("!")
    return "\n".join(lines)
