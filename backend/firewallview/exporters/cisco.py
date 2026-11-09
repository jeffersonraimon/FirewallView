import ipaddress
import itertools
import re
from typing import Dict, List, Optional
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList


class _Unsupported(Exception):
    """Raised when a rule cannot be expressed as a Cisco ACL entry."""


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


def _addr_variants(addr: Optional[str], v6: bool) -> List[str]:
    """Address condition -> list of Cisco address specs (comma lists expand to several)."""
    if not addr:
        return ["any"]
    out: List[str] = []
    for part in [p.strip() for p in addr.split(",") if p.strip()]:
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise _Unsupported(f"address '{part}' is not an IP/CIDR")
        if (net.version == 6) != v6:
            raise _Unsupported(f"address '{part}' does not match the ACL address family")
        if net.prefixlen == 0:
            out.append("any")
        elif net.prefixlen == net.max_prefixlen:
            out.append(f"host {net.network_address}")
        elif v6:
            out.append(str(net))
        else:
            out.append(cidr_to_wildcard(str(net)))
    return out or ["any"]


def _port_variants(spec: Optional[str], negate: bool) -> List[Optional[str]]:
    """Port condition -> list of operator clauses ('eq 80 443', 'range 1 2', 'neq 22')."""
    if not spec:
        return [None]
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    plain = [p for p in parts if "-" not in p]
    ranges = [p for p in parts if "-" in p]
    if negate:
        if len(plain) == 1 and not ranges:
            return [f"neq {plain[0]}"]
        raise _Unsupported("negated port list/range cannot be expressed")
    variants: List[Optional[str]] = []
    for i in range(0, len(plain), 10):  # IOS accepts at most 10 values per eq
        variants.append("eq " + " ".join(plain[i:i + 10]))
    for rg in ranges:
        a, b = rg.split("-", 1)
        variants.append(f"range {a.strip()} {b.strip()}")
    return variants or [None]


def _summary(r: FirewallRule) -> str:
    c = r.conditions
    bits = [r.table, r.chain, r.action]
    if c.protocol:
        bits.append(c.protocol)
    if c.src_address or c.src_address_list:
        bits.append("src=" + (c.src_address or c.src_address_list))
    if c.dst_address or c.dst_address_list:
        bits.append("dst=" + (c.dst_address or c.dst_address_list))
    if c.dst_port:
        bits.append("dport=" + c.dst_port)
    return " ".join(bits)


def _remark(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return " remark " + text[:100]


def _rule_family(r: FirewallRule) -> str:
    if r.family in ("ipv4", "ipv6"):
        return r.family
    c = r.conditions
    for a in (c.src_address, c.dst_address):
        if a and ":" in a:
            return "ipv6"
    return "ipv4"


def _rule_lines(r: FirewallRule, v6: bool) -> List[str]:
    """Returns ACL entry lines (with leading space) for one rule, or raises _Unsupported."""
    act = r.action.lower()
    if act == "accept":
        verb = "permit"
    elif act in ("drop", "reject"):
        verb = "deny"
    else:
        raise _Unsupported(f"action '{r.action}' has no ACL equivalent")

    c = r.conditions
    neg_flags = [
        ("negate_src_address", c.negate_src_address and (c.src_address or c.src_address_list) is not None),
        ("negate_dst_address", c.negate_dst_address and (c.dst_address or c.dst_address_list) is not None),
        ("negate_src_address_list", c.negate_src_address_list and bool(c.src_address_list)),
        ("negate_dst_address_list", c.negate_dst_address_list and bool(c.dst_address_list)),
        ("negate_protocol", c.negate_protocol and bool(c.protocol)),
        ("negate_port", c.negate_port and bool(c.port)),
        ("negate_in_interface", c.negate_in_interface and bool(c.in_interface)),
        ("negate_out_interface", c.negate_out_interface and bool(c.out_interface)),
        ("negate_connection_state", c.negate_connection_state and bool(c.connection_state)),
    ]
    for name, active in neg_flags:
        if active:
            raise _Unsupported(f"negation ({name}) cannot be expressed in a Cisco ACL")

    for field, val in (("in_interface", c.in_interface), ("out_interface", c.out_interface),
                       ("connection_nat_state", c.connection_nat_state), ("limit", c.limit),
                       ("ipsec_policy", c.ipsec_policy), ("packet_mark", c.packet_mark),
                       ("tcp_flags", c.tcp_flags)):
        if val:
            raise _Unsupported(f"matcher {field} has no ACL equivalent")

    proto = (c.protocol or "").lower().strip()
    if proto in ("", "any", "ip", "ipv4", "ipv6"):
        proto = ""
    if proto == "icmpv6":
        proto = "icmp" if v6 else "icmpv6"
    if proto and not re.match(r"^[a-z0-9-]+$", proto):
        raise _Unsupported(f"protocol '{c.protocol}' cannot be expressed")
    if proto == "icmpv6":
        raise _Unsupported("icmpv6 in an IPv4 ACL")

    established = False
    if c.connection_state:
        states = {s.lower() for s in c.connection_state}
        if "established" not in states or not states <= {"established", "related"}:
            raise _Unsupported(f"connection_state {sorted(states)} cannot be expressed")
        if proto and proto != "tcp":
            raise _Unsupported("'established' only applies to tcp")
        proto = "tcp"
        established = True

    # (src_port, dst_port) clause pairs
    if c.port:
        if c.src_port or c.dst_port:
            raise _Unsupported("port combined with src/dst port cannot be expressed")
        if c.negate_src_port or c.negate_dst_port:
            raise _Unsupported("negated port cannot be expressed")
        pv = _port_variants(c.port, False)
        port_pairs = [(None, p) for p in pv] + [(p, None) for p in pv]
    else:
        port_pairs = list(itertools.product(_port_variants(c.src_port, c.negate_src_port),
                                            _port_variants(c.dst_port, c.negate_dst_port)))
    if any(sp or dp for sp, dp in port_pairs) and proto not in ("tcp", "udp", "sctp"):
        raise _Unsupported("port match requires protocol tcp/udp")

    if c.src_address_list:
        src_vars = [f"object-group {c.src_address_list}"]
    else:
        src_vars = _addr_variants(c.src_address, v6)
    if c.dst_address_list:
        dst_vars = [f"object-group {c.dst_address_list}"]
    else:
        dst_vars = _addr_variants(c.dst_address, v6)

    proto_out = proto or ("ipv6" if v6 else "ip")
    lines: List[str] = []
    for src, dst, (sp, dp) in itertools.product(src_vars, dst_vars, port_pairs):
        parts = [f" {verb}", proto_out, src]
        if sp:
            parts.append(sp)
        parts.append(dst)
        if dp:
            parts.append(dp)
        if established:
            parts.append("established")
        lines.append(" ".join(parts))
    return lines


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
                try:
                    if "-" in addr and "/" not in addr and ":" not in addr:
                        a, b = addr.split("-", 1)
                        ipaddress.ip_address(a.strip())
                        lines.append(f" range {a.strip()} {b.strip()}")
                    else:
                        net = ipaddress.ip_network(addr, strict=False)
                        if net.prefixlen == net.max_prefixlen:
                            lines.append(f" network-object host {net.network_address}")
                        elif net.version == 4:
                            lines.append(f" network-object {net.network_address} {net.netmask}")
                        else:
                            lines.append(f" network-object {net}")
                except ValueError:
                    lines.append(f"! UNSUPPORTED object-group entry: {addr}")
            lines.append("!")

    # Group by (chain, family): one ACL per filter chain. Non-filter tables are skipped.
    groups: Dict[tuple, dict] = {}
    skipped: List[str] = []
    for r in sorted(rules, key=lambda x: x.order):
        if r.disabled:
            continue
        if (r.table or "filter").lower() != "filter":
            skipped.append(f"! SKIPPED (table {r.table}, no ACL equivalent): {_summary(r)}")
            continue
        fam = _rule_family(r)
        g = groups.setdefault((r.chain or "filter", fam), {"rules": [], "policy": None})
        if r.is_policy:
            g["policy"] = r
        else:
            g["rules"].append(r)

    used_names: Dict[str, str] = {}
    for (chain, fam), g in groups.items():
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", chain)
        if name in used_names and used_names[name] != fam:
            name = f"{name}_{'v6' if fam == 'ipv6' else 'v4'}"
        used_names[name] = fam
        v6 = fam == "ipv6"

        body: List[str] = []
        for r in g["rules"]:
            try:
                entry = _rule_lines(r, v6)
            except _Unsupported as e:
                body.append(_remark(f"UNSUPPORTED: {_summary(r)} ({e})"))
                continue
            if r.comment:
                body.append(_remark(r.comment))
            body.extend(entry)
        pol = g["policy"]
        if pol is not None and pol.action.lower() == "accept":
            body.append(" permit ipv6 any any" if v6 else " permit ip any any")
        # policy drop == implicit deny: nothing to emit

        lines.append(f"ipv6 access-list {name}" if v6 else f"ip access-list extended {name}")
        lines.extend(body if body else [" remark (empty ACL: implicit deny)"])
        lines.append("!")

    lines.extend(skipped)
    return "\n".join(lines)
