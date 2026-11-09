import re
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

DEFAULT_CPU_PROFILE = "ACL-PADRAO-CPU"


def _is_v6(addr: str) -> bool:
    return ":" in addr


def _seq_from_id(rid: str) -> Optional[int]:
    """Entry sequence from an id: '10' or '<profile>-10'."""
    m = re.fullmatch(r"(?:.*-)?(\d+)", rid or "")
    return int(m.group(1)) if m else None


def _unsupported_reason(r: FirewallRule) -> Optional[str]:
    """Reason why the rule cannot be exported without changing its meaning (None = ok)."""
    c = r.conditions
    if r.table != "filter":
        return f"table '{r.table}' has no DmOS ACL equivalent"
    if r.is_policy:
        return "chain default policy has no confirmed DmOS equivalent"
    if r.action.lower() not in ("accept", "drop"):
        return f"action '{r.action}' not exportable (only permit/deny)"
    for flag in ("negate_src_address", "negate_dst_address", "negate_protocol",
                 "negate_src_port", "negate_dst_port"):
        if getattr(c, flag):
            return f"negation ({flag}) not expressible in DmOS ACL"
    if c.negate_port or c.port:
        return "'port' (src or dst) match not expressible"
    for attr in ("src_address_list", "dst_address_list", "in_interface", "out_interface",
                 "connection_nat_state", "limit", "ipsec_policy", "packet_mark"):
        if getattr(c, attr):
            return f"condition '{attr}' not expressible in DmOS ACL"
    if c.connection_state:
        return "condition 'connection_state' not expressible in DmOS ACL"
    if c.tcp_flags:
        return "condition 'tcp_flags' not expressible in DmOS ACL"
    for attr in ("src_port", "dst_port"):
        v = getattr(c, attr)
        if v and not re.fullmatch(r"\d+|[A-Za-z][A-Za-z0-9_-]*", v):
            return f"{attr} '{v}' is a list/range, not exportable"
    v6 = [a for a in (c.src_address, c.dst_address) if a and _is_v6(a)]
    v4 = [a for a in (c.src_address, c.dst_address) if a and not _is_v6(a)]
    if v6 and v4:
        return "mixes IPv4 and IPv6 addresses"
    if r.family == "ipv6" and not v6 and (c.protocol or "").lower() not in ("icmp6",):
        return "IPv6-only rule without IPv6 address would become broader (IPv4 too)"
    if r.family == "ipv4" and v6:
        return "family ipv4 with IPv6 address"
    return None


def export_to_dmos(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    """
    Exports FirewallRule list to Datacom DmOS access-list profile syntax.

    One acl-profile per chain: chain 'input' -> CPU protection profile
    (``acl-profile cpu l3 ACL-PADRAO-CPU``); other chains -> ``acl-profile l3 <chain>``
    (assumed form, flagged with a comment). Rules that cannot be expressed without
    broadening them are emitted as ``! UNSUPPORTED:`` comments.
    """
    lines = ["! Exported by FirewallView (Datacom DmOS syntax)", "access-list"]

    ordered = [r for r in sorted(rules, key=lambda x: x.order) if not r.disabled]
    groups: Dict[str, List[FirewallRule]] = {}
    for r in ordered:
        groups.setdefault(r.chain, []).append(r)

    def profile_name(chain: str) -> str:
        if chain == "input":
            return DEFAULT_CPU_PROFILE
        return re.sub(r"[^A-Za-z0-9_.-]", "-", chain) or "PROFILE"

    if "input" in groups:
        lines += [" protection", f"  cpu {DEFAULT_CPU_PROFILE}", " !"]

    for chain, grp in groups.items():
        name = profile_name(chain)
        if chain == "input":
            lines.append(f" acl-profile cpu l3 {name}")
        else:
            lines.append(f" ! ASSUMED syntax for non-CPU chain '{chain}'")
            lines.append(f" acl-profile l3 {name}")
        lines.append("  priority 0")

        # Sequence numbers: keep original ones when usable and unique in this profile.
        seqs: List[Optional[int]] = []
        seen = set()
        for r in grp:
            s = _seq_from_id(r.id)
            if s is not None and s not in seen:
                seen.add(s)
            else:
                s = None
            seqs.append(s)
        next_seq = (max(seen) if seen else 0)
        final: List[int] = []
        for s in seqs:
            if s is None:
                next_seq = (next_seq // 10 + 1) * 10
                while next_seq in seen:
                    next_seq += 10
                seen.add(next_seq)
                s = next_seq
            final.append(s)

        for r, seq in zip(grp, final):
            reason = _unsupported_reason(r)
            if reason:
                lines.append(f"  ! UNSUPPORTED: rule '{r.id}' skipped: {reason}")
                continue

            lines.append(f"  access-list-entry {seq}")
            if r.comment:
                clean = "".join(ch for ch in r.comment if ch.isalnum() or ch in ["-", "_", " "])
                clean = "-".join(clean.split())
                if clean:
                    lines.append(f"   description {clean}")

            c = r.conditions
            proto = (c.protocol or "").lower()
            if proto == "arp":
                lines.append("   match ethertype arp")
            elif proto and proto not in ["any", "all", "ip"]:
                lines.append(f"   match ip-protocol {c.protocol}")

            for addr, kind in ((c.src_address, "source"), (c.dst_address, "destination")):
                if addr:
                    ver = "ipv6" if _is_v6(addr) else "ipv4"
                    lines.append(f"   match {kind}-{ver}-address {addr}")

            if c.src_port:
                lines.append(f"   match source-port {c.src_port}")
            if c.dst_port:
                lines.append(f"   match destination-port {c.dst_port}")

            lines.append(f"   action {'permit' if r.action.lower() == 'accept' else 'deny'}")
            lines.append("  !")
        lines.append(" !")

    lines.append("!")
    return "\n".join(lines)
