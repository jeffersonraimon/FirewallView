import re
import shlex
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

BUILTIN = {"prerouting", "input", "forward", "output", "postrouting"}
PORT_PROTOS = {"tcp", "udp", "sctp", "dccp", "udplite"}
ALL_FLAGS = ["syn", "ack", "fin", "rst", "psh", "urg"]


def _builtin_name(chain: str) -> Optional[str]:
    low = chain.lower()
    if low == "dstnat":
        return "PREROUTING"
    if low == "srcnat":
        return "POSTROUTING"
    if low in BUILTIN:
        return low.upper()
    return None


def _rule_families(r: FirewallRule) -> List[str]:
    if r.family == "ipv4":
        return ["ipv4"]
    if r.family == "ipv6":
        return ["ipv6"]
    c = r.conditions
    addrs = [c.src_address, c.dst_address, r.nat_to_addresses, r.npt_src_prefix]
    addrs = [a for a in addrs if a]
    if any(":" in a for a in addrs):
        return ["ipv6"]
    if any("." in a for a in addrs):
        return ["ipv4"]
    return ["ipv4", "ipv6"]


def _timeout_seconds(t: Optional[str]) -> Optional[int]:
    if not t:
        return None
    t = t.strip()
    if t.isdigit():
        return int(t)
    parts = re.findall(r"(\d+)([wdhms])", t)
    if not parts or "".join(a + b for a, b in parts) != t:
        return None
    mult = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(int(a) * mult[b] for a, b in parts)


def _nat_target(addr: Optional[str], ports: Optional[str], v6: bool) -> str:
    addr = addr or ""
    if ports:
        if v6 and addr:
            return f"[{addr}]:{ports}"
        return f"{addr}:{ports}"
    return addr


def _tcp_flag_args(flags: List[str], negate: bool) -> List[str]:
    setf = [f.lower() for f in flags if not f.startswith("!")]
    unset = [f[1:].lower() for f in flags if f.startswith("!")]
    mask = list(dict.fromkeys(setf + unset))
    if not mask:
        return []
    args = ["!"] if negate else []
    args += ["--tcp-flags", ",".join(m.upper() for m in mask), ",".join(s.upper() for s in setf) or "NONE"]
    return args


def _port_args(value: str, flag: str, negate: bool) -> List[str]:
    v = value.replace("-", ":")
    neg = ["!"] if negate else []
    if "," in v:
        multi = {"--sport": "--sports", "--dport": "--dports", "--port": "--ports"}[flag]
        return ["-m", "multiport"] + neg + [multi, v]
    if flag == "--port":
        return ["-m", "multiport"] + neg + ["--ports", v]
    return neg + [flag, v]


def _build_rule(r: FirewallRule, tool: str, chain_names: Dict[Tuple[str, str], str]) -> List[str]:
    """Return the output lines (commands and/or comments) for one rule."""
    v6 = tool == "ip6tables"
    c = r.conditions
    table = (r.table or "filter").lower()
    notes: List[str] = []

    def unsupported(why: str) -> List[str]:
        return [f"# unsupported: rule {r.id} ({why})"]

    def canon(name: str) -> str:
        return chain_names.get((table, name.lower()), name)

    chain = _builtin_name(r.chain) or canon(r.chain)
    base = [tool]
    if table != "filter":
        base += ["-t", table]
    base += ["-A", chain]

    act = r.action.lower()

    # Target
    tgt: List[str]
    if act in ("accept", "drop", "reject", "return", "log"):
        tgt = ["-j", act.upper()]
        if act == "log":
            tgt += ["--log-prefix", (r.comment or "fwv: ")[:28]]
    elif act == "passthrough":
        tgt = []
    elif act == "masquerade":
        tgt = ["-j", "MASQUERADE"]
        if r.nat_to_ports:
            tgt += ["--to-ports", r.nat_to_ports]
    elif act == "dst-nat":
        if not r.nat_to_addresses and not r.nat_to_ports:
            return unsupported("dst-nat without a target address")
        tgt = ["-j", "DNAT", "--to-destination", _nat_target(r.nat_to_addresses, r.nat_to_ports, v6)]
    elif act == "src-nat":
        if not r.nat_to_addresses and not r.nat_to_ports:
            return unsupported("src-nat without a target address")
        tgt = ["-j", "SNAT", "--to-source", _nat_target(r.nat_to_addresses, r.nat_to_ports, v6)]
    elif act == "redirect":
        tgt = ["-j", "REDIRECT"]
        if r.nat_to_ports:
            tgt += ["--to-ports", r.nat_to_ports]
    elif act == "netmap":
        if not r.nat_to_addresses:
            return unsupported("netmap without target prefix")
        tgt = ["-j", "NETMAP", "--to", r.nat_to_addresses]
    elif act in ("mark-packet", "mark-routing"):
        if not r.mark_value:
            return unsupported(f"{act} without mark value")
        tgt = ["-j", "MARK", "--set-mark", r.mark_value]
    elif act == "mark-connection":
        if not r.mark_value:
            return unsupported("mark-connection without mark value")
        tgt = ["-j", "CONNMARK", "--set-mark", r.mark_value]
    elif act == "change-mss":
        if r.mark_value == "clamp-to-pmtu":
            tgt = ["-j", "TCPMSS", "--clamp-mss-to-pmtu"]
        elif r.mark_value:
            tgt = ["-j", "TCPMSS", "--set-mss", r.mark_value]
        else:
            return unsupported("change-mss without value")
    elif act in ("add-src-to-address-list", "add-dst-to-address-list"):
        if not r.address_list_target:
            return unsupported(f"{act} without list name")
        side = "src" if "src" in act else "dst"
        tgt = ["-j", "SET", "--add-set", r.address_list_target, side]
        secs = _timeout_seconds(r.address_list_timeout)
        if secs is not None:
            tgt += ["--timeout", str(secs), "--exist"]
        elif r.address_list_timeout:
            notes.append(f"# note: rule {r.id} timeout '{r.address_list_timeout}' could not be converted")
    elif act in ("snpt", "dnpt"):
        if not (r.npt_src_prefix and r.npt_dst_prefix):
            return unsupported(f"{act} without prefixes")
        tgt = ["-j", act.upper(), "--src-pfx", r.npt_src_prefix, "--dst-pfx", r.npt_dst_prefix]
    elif act == "jump":
        if not r.target_chain:
            return unsupported("jump without target chain")
        tgt = ["-j", canon(r.target_chain)]
    else:
        return unsupported(f"action '{act}' has no iptables equivalent")

    # Protocol(s)
    has_ports = bool(c.src_port or c.dst_port or c.port)
    proto = c.protocol
    protos: List[Optional[str]] = [proto]
    if has_ports or c.tcp_flags:
        if not proto:
            protos = ["tcp"] if c.tcp_flags else ["tcp", "udp"]
            notes.append(f"# warning: rule {r.id} has a port/flag match without protocol; expanded to {' and '.join(protos)}")
        elif proto not in PORT_PROTOS or c.negate_protocol:
            return unsupported(f"port match requires a positive tcp/udp/sctp/dccp protocol, got {'!' if c.negate_protocol else ''}{proto}")
        if c.tcp_flags and protos != ["tcp"] and proto != "tcp":
            return unsupported("tcp flags need protocol tcp")

    out: List[str] = list(notes)
    for p in protos:
        cmd = list(base)
        if p:
            if c.negate_protocol:
                cmd.append("!")
            cmd += ["-p", p]
        if c.src_address:
            cmd += (["!"] if c.negate_src_address else []) + ["-s", c.src_address]
        if c.dst_address:
            cmd += (["!"] if c.negate_dst_address else []) + ["-d", c.dst_address]
        if c.in_interface:
            cmd += (["!"] if c.negate_in_interface else []) + ["-i", c.in_interface]
        if c.out_interface:
            cmd += (["!"] if c.negate_out_interface else []) + ["-o", c.out_interface]
        if c.src_address_list:
            cmd += ["-m", "set"] + (["!"] if c.negate_src_address_list else []) + ["--match-set", c.src_address_list, "src"]
        if c.dst_address_list:
            cmd += ["-m", "set"] + (["!"] if c.negate_dst_address_list else []) + ["--match-set", c.dst_address_list, "dst"]
        if c.src_port:
            cmd += _port_args(c.src_port, "--sport", c.negate_src_port)
        if c.dst_port:
            cmd += _port_args(c.dst_port, "--dport", c.negate_dst_port)
        if c.port:
            cmd += _port_args(c.port, "--port", c.negate_port)
        if c.tcp_flags:
            cmd += _tcp_flag_args(c.tcp_flags, c.negate_tcp_flags)
        if c.connection_state:
            cmd += ["-m", "conntrack"] + (["!"] if c.negate_connection_state else []) + \
                   ["--ctstate", ",".join(s.upper() for s in c.connection_state)]
        if c.connection_nat_state:
            st = {"dstnat": "DNAT", "srcnat": "SNAT"}.get(c.connection_nat_state.lower())
            if st:
                cmd += ["-m", "conntrack"] + (["!"] if c.negate_connection_nat_state else []) + ["--ctstatus", st]
            else:
                return unsupported(f"connection-nat-state '{c.connection_nat_state}'")
        if c.packet_mark:
            cmd += ["-m", "mark"] + (["!"] if c.negate_packet_mark else []) + ["--mark", c.packet_mark]
        if c.limit:
            m = re.match(r"^([^,:]+)(?:,(\d+))?(?::\w+)?$", c.limit.strip())
            if not m:
                return unsupported(f"limit '{c.limit}'")
            rate = m.group(1) if "/" in m.group(1) else f"{m.group(1)}/second"
            cmd += ["-m", "limit", "--limit", rate]
            if m.group(2):
                cmd += ["--limit-burst", m.group(2)]
        if c.ipsec_policy:
            bits = [b.strip() for b in c.ipsec_policy.split(",")]
            if len(bits) == 2 and bits[0] in ("in", "out") and bits[1] in ("ipsec", "none"):
                cmd += ["-m", "policy", "--dir", bits[0], "--pol", bits[1]]
            else:
                return unsupported(f"ipsec-policy '{c.ipsec_policy}'")
        if r.comment:
            cmd += ["-m", "comment", "--comment", " ".join(r.comment.split())[:255]]
        cmd += tgt
        out.append(" ".join(shlex.quote(t) if t not in ("!",) else t for t in cmd))
    return out


def export_to_iptables(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# Exported by FirewallView (iptables & ipset syntax)",
        "set -e",
        ""
    ]

    ordered = sorted(rules, key=lambda x: x.order)

    # ipset definitions (also for sets only referenced by rules)
    timeout_sets = {r.address_list_target for r in ordered
                    if r.address_list_target and _timeout_seconds(r.address_list_timeout) is not None}
    referenced = set()
    for r in ordered:
        for n in (r.conditions.src_address_list, r.conditions.dst_address_list, r.address_list_target):
            if n:
                referenced.add(n)
    all_sets = dict(address_lists or {})
    if all_sets or referenced:
        lines.append("# === IPSET Definitions ===")
        for name in list(all_sets) + sorted(referenced - set(all_sets)):
            alist = all_sets.get(name)
            entries = [e for e in (alist.entries if alist else []) if not e.disabled]
            v6 = [e for e in entries if ":" in e.address]
            fam = ""
            if entries and len(v6) == len(entries):
                fam = " family inet6"
            elif v6:
                lines.append(f"# warning: ipset {name} mixes IPv4 and IPv6 entries; IPv6 entries skipped")
            tmo = " timeout 0" if name in timeout_sets else ""
            lines.append(f"ipset create {name} hash:net{fam}{tmo} -exist")
            for e in entries:
                if fam == "" and ":" in e.address:
                    continue
                lines.append(f"ipset add {name} {e.address} -exist")
        lines.append("")

    # Canonical spelling of custom chains per table (rule chains win over jump targets)
    chain_names: Dict[Tuple[str, str], str] = {}
    for r in ordered:
        if r.disabled:
            continue
        t = (r.table or "filter").lower()
        if _builtin_name(r.chain) is None:
            chain_names.setdefault((t, r.chain.lower()), r.chain)
    for r in ordered:
        if r.disabled:
            continue
        t = (r.table or "filter").lower()
        if r.action.lower() == "jump" and r.target_chain and _builtin_name(r.target_chain) is None:
            chain_names.setdefault((t, r.target_chain.lower()), r.target_chain)

    for tool, fam, title in (("iptables", "ipv4", "IPTABLES (IPv4)"), ("ip6tables", "ipv6", "IP6TABLES (IPv6)")):
        sect: List[str] = []
        for (t, _), name in chain_names.items():
            used = any((x.table or "filter").lower() == t and fam in _rule_families(x) and not x.disabled
                       and (x.chain.lower() == name.lower()
                            or (x.target_chain or "").lower() == name.lower())
                       for x in ordered)
            if used:
                tt = [] if t == "filter" else ["-t", t]
                sect.append(" ".join([tool] + tt + ["-N", shlex.quote(name)]))
        policies: List[str] = []
        for r in ordered:
            if fam not in _rule_families(r):
                continue
            if r.is_policy:
                bn = _builtin_name(r.chain)
                if bn is None or r.action.lower() not in ("accept", "drop"):
                    policies.append(f"# unsupported: rule {r.id} (policy on chain '{r.chain}')")
                    continue
                t = (r.table or "filter").lower()
                tt = [] if t == "filter" else ["-t", t]
                policies.append(" ".join([tool] + tt + ["-P", bn, r.action.upper()]))
                continue
            built = _build_rule(r, tool, chain_names)
            if r.disabled:
                sect.extend("# [DISABLED] " + b.lstrip("# ") if not b.startswith("#") else b for b in built)
            else:
                sect.extend(built)
        sect.extend(policies)
        if sect:
            lines.append(f"# === {title} Rules ===")
            lines.extend(sect)
            lines.append("")

    return "\n".join(lines)
