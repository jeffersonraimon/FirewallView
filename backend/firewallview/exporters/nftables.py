"""nftables exporter.

Emits one ``table inet firewallview`` with base chains declared from the
canonical (table, chain) pair, sets typed per contents and every matcher
(including negations) preserved. Rules that cannot be expressed are written as
``# ...`` comment lines instead of being silently broadened.
"""
import ipaddress
import itertools
import re
from typing import Dict, List, Optional, Tuple

from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList

TABLE_NAME = "firewallview"
L4_PORT_PROTOS = ("tcp", "udp", "sctp", "dccp", "udplite")
CT_STATES = ("new", "established", "related", "invalid", "untracked")
TCP_FLAGS = ("fin", "syn", "rst", "psh", "ack", "urg", "ecn", "cwr")
HOOKS = ("prerouting", "input", "forward", "output", "postrouting")

Alt = Tuple[Optional[str], List[str]]  # (family, match expressions)


def _ident(name: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if not out or not re.match(r"[A-Za-z_]", out):
        out = "_" + out
    return out


def _classify(entry: str) -> Optional[str]:
    """ipv4 / ipv6 for an address, CIDR or a-b range; None when invalid."""
    entry = entry.strip()
    try:
        if "/" in entry:
            return "ipv6" if ipaddress.ip_network(entry, strict=False).version == 6 else "ipv4"
        if "-" in entry:
            a, b = (ipaddress.ip_address(x.strip()) for x in entry.split("-", 1))
            return "ipv6" if a.version == 6 and b.version == 6 else (
                "ipv4" if a.version == 4 and b.version == 4 else None)
        return "ipv6" if ipaddress.ip_address(entry).version == 6 else "ipv4"
    except ValueError:
        return None


def _needs_interval(entries: List[str]) -> bool:
    return any("/" in e or "-" in e for e in entries)


def _set_expr(values: List[str]) -> str:
    return values[0] if len(values) == 1 else "{ " + ", ".join(values) + " }"


def _split(value: Optional[str]) -> List[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _timeout(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    if re.fullmatch(r"(\d+[wdhms])+", v):
        return v
    m = re.fullmatch(r"(?:(\d+)d )?(\d+):(\d+):(\d+)", v) or re.fullmatch(r"(?:(\d+)d)?(\d+):(\d+):(\d+)", v)
    if m:
        d, h, mi, s = (int(x or 0) for x in m.groups())
        parts = [f"{d}d" if d else "", f"{h}h" if h else "", f"{mi}m" if mi else "", f"{s}s" if s else ""]
        return "".join(parts) or "0s"
    return None


class _Ctx:
    def __init__(self, rules: List[FirewallRule], address_lists: Dict[str, AddressList]):
        self.notes: List[str] = []
        self.marks: Dict[str, int] = {}
        self.set_defs: List[Tuple[str, str, List[str], bool]] = []  # name, type, elements, dynamic
        self.set_names: Dict[str, Dict[str, str]] = {}  # list name -> {family: nft set name}
        self.chain_names: Dict[Tuple[str, str], str] = {}
        self.rules = rules
        self.build_sets(address_lists)

    # sets -------------------------------------------------------------
    def build_sets(self, address_lists: Dict[str, AddressList]):
        dyn: Dict[str, str] = {}
        for r in self.rules:
            if r.action.lower() in ("add-src-to-address-list", "add-dst-to-address-list") \
                    and r.address_list_target and not r.disabled:
                dyn.setdefault(r.address_list_target, "ipv6" if r.family == "ipv6" else "ipv4")
        used = set()
        for name, alist in address_lists.items():
            groups: Dict[str, List[str]] = {"ipv4": [], "ipv6": []}
            for e in alist.entries:
                if e.disabled:
                    continue
                fam = _classify(e.address)
                if fam is None:
                    self.notes.append(f"set {name}: entry '{e.address}' is not an IP/CIDR/range and was skipped")
                    continue
                if e.address.strip() not in groups[fam]:
                    groups[fam].append(e.address.strip())
            fams = [f for f in ("ipv4", "ipv6") if groups[f]] or [dyn.get(name, "ipv4")]
            mapping: Dict[str, str] = {}
            for idx, fam in enumerate(fams):
                base = _ident(name)
                nm = base if idx == 0 else base + "_v6"
                while nm in used:
                    nm += "_"
                used.add(nm)
                mapping[fam] = nm
                self.set_defs.append((nm, fam, groups[fam], name in dyn))
            self.set_names[name] = mapping
        for name, fam in dyn.items():
            if name not in self.set_names:
                nm = _ident(name)
                while nm in used:
                    nm += "_"
                used.add(nm)
                self.set_names[name] = {fam: nm}
                self.set_defs.append((nm, fam, [], True))

    def set_for(self, name: str, fam: Optional[str]) -> Optional[str]:
        m = self.set_names.get(name)
        if m is None:
            return None
        return m.get(fam) if fam else next(iter(m.values()))

    # marks ------------------------------------------------------------
    def mark(self, value: str) -> str:
        v = value.strip()
        if v.lower() == "no-mark":
            return "0"
        if re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", v):
            return v
        if v not in self.marks:
            self.marks[v] = len(self.marks) + 1
        return str(self.marks[v])


def _chain_spec(role: str, chain: str) -> Optional[Tuple[str, str, str, str]]:
    """(nft chain name, type, hook, priority) for a base chain, else None."""
    if role == "nat":
        if chain in ("dstnat", "prerouting"):
            return ("dstnat", "nat", "prerouting", "dstnat")
        if chain in ("srcnat", "postrouting"):
            return ("srcnat", "nat", "postrouting", "srcnat")
        if chain == "output":
            return ("nat_output", "nat", "output", "dstnat")
        if chain == "input":
            return ("nat_input", "nat", "input", "srcnat")
        return None
    if chain not in HOOKS:
        return None
    if role == "filter":
        return (chain, "filter", chain, "filter")
    if role == "mangle":
        return (f"mangle_{chain}", "route" if chain == "output" else "filter", chain, "mangle")
    if role == "raw":
        return (f"raw_{chain}", "filter", chain, "raw")
    return None


def _norm(role: str, chain: str) -> Tuple[str, str]:
    role, chain = (role or "filter").lower(), chain.strip()
    if role == "nat":
        chain = {"prerouting": "dstnat", "postrouting": "srcnat"}.get(chain.lower(), chain)
        if chain.lower() in ("dstnat", "srcnat", "output", "input"):
            chain = chain.lower()
    elif chain.lower() in HOOKS:
        chain = chain.lower()
    return role, chain


# ---------------------------------------------------------------------------
# Matchers
# ---------------------------------------------------------------------------

def _combine(a: List[Alt], b: List[Alt]) -> List[Alt]:
    out: List[Alt] = []
    for (fa, ea), (fb, eb) in itertools.product(a, b):
        if fa and fb and fa != fb:
            continue
        out.append((fa or fb, ea + eb))
    return out


def _addr_alts(ctx: _Ctx, c: RuleCondition, side: str, rule_family: Optional[str]) -> Tuple[List[Alt], List[str]]:
    """Alternatives for the source or destination address (+ named sets)."""
    pre = "src" if side == "s" else "dst"
    kw = "saddr" if side == "s" else "daddr"
    neg_addr = getattr(c, f"negate_{pre}_address")
    neg_list = getattr(c, f"negate_{pre}_address_list")
    problems: List[str] = []
    alts: List[Alt] = [(None, [])]

    addrs = _split(getattr(c, f"{pre}_address"))
    if addrs:
        groups: Dict[str, List[str]] = {"ipv4": [], "ipv6": []}
        for a in addrs:
            fam = _classify(a)
            if fam is None:
                problems.append(f"{pre} address '{a}' cannot be expressed in nftables")
            else:
                groups[fam].append(a)
        a_alts: List[Alt] = []
        for fam in ("ipv4", "ipv6"):
            if groups[fam]:
                key = "ip" if fam == "ipv4" else "ip6"
                op = "!= " if neg_addr else ""
                a_alts.append((fam, [f"{key} {kw} {op}{_set_expr(groups[fam])}"]))
        alts = _combine(alts, a_alts) if a_alts else []

    names = _split(getattr(c, f"{pre}_address_list"))
    if names:
        l_alts: List[Alt] = []
        default_fam = "ipv6" if rule_family == "ipv6" else "ipv4"
        if neg_list:
            for fam in ("ipv4", "ipv6"):
                exprs = []
                for nm in names:
                    sn = ctx.set_for(nm, fam) if nm in ctx.set_names else (
                        _ident(nm) if fam == default_fam else None)
                    if sn:
                        exprs.append(f"{'ip' if fam == 'ipv4' else 'ip6'} {kw} != @{sn}")
                if exprs:
                    l_alts.append((fam, exprs))
        else:
            for nm in names:
                fams = ctx.set_names.get(nm) or {default_fam: _ident(nm)}
                for fam, sn in fams.items():
                    l_alts.append((fam, [f"{'ip' if fam == 'ipv4' else 'ip6'} {kw} @{sn}"]))
        alts = _combine(alts, l_alts) if l_alts else []
    return alts, problems


def _port_expr(value: str, neg: bool) -> Optional[str]:
    items = _split(value)
    if not items or not all(re.fullmatch(r"\d+(-\d+)?", i) for i in items):
        return None
    return ("!= " if neg else "") + _set_expr(items)


def _iface_expr(kw: str, value: str, neg: bool) -> str:
    items = ['"' + i.replace('"', "") + '"' for i in _split(value)]
    return f'{kw} {"!= " if neg else ""}{_set_expr(items)}'


def _limit_expr(limit: str) -> Optional[str]:
    lim = limit.strip()
    if lim.startswith("rate"):
        return f"limit {lim}"
    m = re.fullmatch(r"(\d+)(?:,(\d+))?(?::(packet|byte)s?)?", lim)
    if m:
        out = f"limit rate {m.group(1)}/second"
        if m.group(2):
            out += f" burst {m.group(2)} {'bytes' if m.group(3) == 'byte' else 'packets'}"
        return out
    return None


def _tcp_flags_expr(flags: List[str], neg: bool) -> Optional[str]:
    pos, unset = [], []
    for f in flags:
        f = f.strip().lower()
        if f.startswith("!"):
            unset.append(f[1:])
        elif f:
            pos.append(f)
    if any(f not in TCP_FLAGS for f in pos + unset):
        return None
    mask = pos + [f for f in unset if f not in pos]
    if not mask:
        return None
    wrap = lambda xs: xs[0] if len(xs) == 1 else "(" + "|".join(xs) + ")"
    val = wrap(pos) if pos else "0"
    return f"tcp flags & {wrap(mask)} {'!=' if neg else '=='} {val}"


def _build_matches(ctx: _Ctx, r: FirewallRule) -> Tuple[List[Alt], List[str]]:
    """All alternatives (one nft rule each) plus problems that make the rule inexpressible."""
    c = r.conditions
    problems: List[str] = []
    base: List[str] = []

    if c.in_interface:
        base.append(_iface_expr("iifname", c.in_interface, c.negate_in_interface))
    if c.out_interface:
        base.append(_iface_expr("oifname", c.out_interface, c.negate_out_interface))

    # protocol / ports -----------------------------------------------------
    protos = [p.strip().lower() for p in _split(c.protocol) if p.strip().lower() not in ("any", "all", "ip")]
    protos = ["icmpv6" if p in ("icmp6", "icmpv6", "ipv6-icmp") else p for p in protos]
    for p in protos:
        if not re.fullmatch(r"[a-z0-9-]+", p):
            problems.append(f"protocol '{p}' cannot be expressed")
    nft_proto = lambda p: "ipv6-icmp" if p == "icmpv6" else p
    has_ports = bool(c.dst_port or c.src_port or c.port)
    single_l4 = len(protos) == 1 and protos[0] in L4_PORT_PROTOS and not c.negate_protocol
    pfx = protos[0] if single_l4 else "th"
    flags_expr = None
    if c.tcp_flags:
        flags_expr = _tcp_flags_expr(c.tcp_flags, c.negate_tcp_flags)
        if flags_expr is None:
            problems.append(f"tcp flags {c.tcp_flags} cannot be expressed")
    skip_proto = single_l4 and protos[0] == "tcp" and flags_expr and not has_ports
    if protos and not (single_l4 and has_ports) and not skip_proto:
        vals = [nft_proto(p) for p in protos]
        base.append(f"meta l4proto {'!= ' if c.negate_protocol else ''}{_set_expr(vals)}")
    elif has_ports and not protos:
        pass  # 'th dport' matches any transport protocol
    if flags_expr:
        base.append(flags_expr)

    port_alts: List[List[str]] = [[]]
    for field, kw in (("dst_port", "dport"), ("src_port", "sport")):
        val = getattr(c, field)
        if val:
            e = _port_expr(val, getattr(c, f"negate_{field}"))
            if e is None:
                problems.append(f"{field} '{val}' cannot be expressed")
            else:
                port_alts = [pa + [f"{pfx} {kw} {e}"] for pa in port_alts]
    if c.port:
        e = _port_expr(c.port, c.negate_port)
        if e is None:
            problems.append(f"port '{c.port}' cannot be expressed")
        elif c.negate_port:
            port_alts = [pa + [f"{pfx} dport {e}", f"{pfx} sport {e}"] for pa in port_alts]
        else:
            port_alts = [pa + [f"{pfx} {kw} {e}"] for pa in port_alts for kw in ("dport", "sport")]

    # state / mark / misc ---------------------------------------------------
    if c.connection_state:
        states = [s.strip().lower() for s in c.connection_state if s.strip()]
        valid = [s for s in states if s in CT_STATES]
        if len(valid) != len(states) or not valid:
            problems.append(f"connection state {c.connection_state} cannot be expressed")
        else:
            base.append(f"ct state {'!= ' if c.negate_connection_state else ''}{_set_expr(valid)}")
    if c.connection_nat_state:
        m = {"dstnat": "dnat", "srcnat": "snat"}.get(c.connection_nat_state.strip().lower())
        if m:
            base.append(f"ct status {'!= ' if c.negate_connection_nat_state else ''}{m}")
        else:
            problems.append(f"connection-nat-state '{c.connection_nat_state}' cannot be expressed")
    if c.packet_mark:
        marks = [ctx.mark(m) for m in _split(c.packet_mark)]
        base.append(f"meta mark {'!= ' if c.negate_packet_mark else ''}{_set_expr(marks)}")
    if c.ipsec_policy:
        problems.append(f"ipsec-policy '{c.ipsec_policy}' has no nftables equivalent")
    if c.limit:
        le = _limit_expr(c.limit)
        if le:
            base.append(le)
        else:
            problems.append(f"limit '{c.limit}' cannot be expressed")

    # addresses ---------------------------------------------------------------
    s_alts, p1 = _addr_alts(ctx, c, "s", r.family)
    d_alts, p2 = _addr_alts(ctx, c, "d", r.family)
    problems += p1 + p2
    alts = _combine(s_alts, d_alts)
    out: List[Alt] = []
    for fam, exprs in alts:
        if r.family and fam and fam != r.family:
            continue
        fam = fam or r.family
        pre = [] if (fam and exprs) else ([f"meta nfproto {'ipv4' if fam == 'ipv4' else 'ipv6'}"] if fam else [])
        for pa in port_alts:
            out.append((fam, pre + base + pa + exprs))
    return out, problems


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def _nat_family(r: FirewallRule) -> str:
    if r.family == "ipv6" or (r.nat_to_addresses and ":" in r.nat_to_addresses):
        return "ip6"
    return "ip"


def _action(ctx: _Ctx, r: FirewallRule) -> Tuple[Optional[str], Optional[str]]:
    """(statement, problem)."""
    a = r.action.lower()
    if a in ("accept", "drop", "return", "reject", "masquerade"):
        if a == "masquerade" and r.nat_to_ports:
            return f"masquerade to :{r.nat_to_ports}", None
        return a, None
    if a == "passthrough":
        return "counter", None
    if a == "log":
        return "log", None
    if a == "jump":
        if not r.target_chain:
            return None, "jump without target chain"
        return f"jump {_ident(r.target_chain)}", None  # replaced by caller for naming
    if a == "redirect":
        return (f"redirect to :{r.nat_to_ports}" if r.nat_to_ports else "redirect"), None
    if a in ("dst-nat", "src-nat"):
        fam = _nat_family(r)
        verb = "dnat" if a == "dst-nat" else "snat"
        addr = r.nat_to_addresses
        port = r.nat_to_ports
        if not addr and not port:
            return None, f"{a} without target address/port"
        if addr and fam == "ip6" and port:
            addr = f"[{addr}]"
        tgt = (addr or "") + (f":{port}" if port else "")
        return f"{verb} {fam} to {tgt}", None
    if a in ("mark-packet", "mark-routing"):
        return (f"meta mark set {ctx.mark(r.mark_value)}", None) if r.mark_value else (None, "mark without value")
    if a == "mark-connection":
        return (f"ct mark set {ctx.mark(r.mark_value)}", None) if r.mark_value else (None, "mark without value")
    if a == "change-mss":
        v = (r.mark_value or "").strip()
        if v in ("", "clamp-to-pmtu"):
            return "tcp option maxseg size set rt mtu", None
        if v.isdigit():
            return f"tcp option maxseg size set {v}", None
        return None, f"change-mss value '{v}'"
    if a in ("add-src-to-address-list", "add-dst-to-address-list"):
        if not r.address_list_target:
            return None, "address-list target missing"
        fam = "ipv6" if r.family == "ipv6" else "ipv4"
        sn = ctx.set_for(r.address_list_target, fam) or ctx.set_for(r.address_list_target, None)
        key = ("ip6" if sn and ctx.set_names[r.address_list_target].get("ipv6") == sn
               and "ipv4" not in ctx.set_names[r.address_list_target] else "ip")
        kw = "saddr" if a == "add-src-to-address-list" else "daddr"
        to = _timeout(r.address_list_timeout)
        return f"add @{sn} {{ {key} {kw}{' timeout ' + to if to else ''} }}", None
    return None, f"action '{r.action}' has no nftables equivalent"


def _comment(text: Optional[str]) -> str:
    if not text:
        return ""
    t = re.sub(r"[\r\n]+", " ", text).replace('"', "'").replace("\\", "/")
    return f' comment "{t}"'


def _sanitize_comment_line(text: str) -> str:
    return re.sub(r"[\r\n]+", " ", text)


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def export_to_nftables(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    rules = sorted(rules, key=lambda x: x.order)
    ctx = _Ctx(rules, address_lists or {})

    policies: Dict[Tuple[str, str], str] = {}
    by_chain: Dict[Tuple[str, str], List[FirewallRule]] = {}
    for r in rules:
        if r.disabled:
            continue
        key = _norm(r.table, r.chain)
        if r.is_policy:
            if r.action.lower() in ("accept", "drop"):
                policies[key] = r.action.lower()
            continue
        by_chain.setdefault(key, [])
        by_chain[key].append(r)
    for key in policies:
        by_chain.setdefault(key, [])

    # chain naming (roles share one nft table)
    custom_roles: Dict[str, List[str]] = {}
    for (role, chain) in by_chain:
        if _chain_spec(role, chain) is None:
            custom_roles.setdefault(chain, []).append(role)
    # referenced but empty custom chains must exist
    for r in rules:
        if not r.disabled and r.action.lower() == "jump" and r.target_chain:
            tgt = r.target_chain
            if not any(tgt == c for (_, c) in by_chain) and _chain_spec(*_norm(r.table, tgt)) is None:
                by_chain.setdefault(_norm(r.table, tgt), [])
                custom_roles.setdefault(tgt, []).append(_norm(r.table, tgt)[0])
    used_names = set()
    for key in by_chain:
        spec = _chain_spec(*key)
        if spec:
            nm = spec[0]
        else:
            role, chain = key
            nm = _ident(chain)
            if nm in used_names or (len(custom_roles.get(chain, [])) > 1 and role != custom_roles[chain][0]):
                nm = f"{role}_{nm}"
            while nm in used_names or any(_chain_spec(*k) and _chain_spec(*k)[0] == nm for k in by_chain):
                nm += "_"
        used_names.add(nm)
        ctx.chain_names[key] = nm

    def jump_name(r: FirewallRule) -> str:
        tgt = r.target_chain or ""
        for key in ((_norm(r.table, tgt)), ("filter", tgt)):
            if key in ctx.chain_names:
                return ctx.chain_names[key]
        for (role, chain), nm in ctx.chain_names.items():
            if chain == tgt:
                return nm
        return _ident(tgt)

    lines = [
        "#!/usr/sbin/nft -f",
        "# Exported by FirewallView (nftables syntax)",
        f"add table inet {TABLE_NAME}",
        f"delete table inet {TABLE_NAME}",
        "",
        f"table inet {TABLE_NAME} {{",
    ]

    # sets
    for nm, fam, elements, dynamic in ctx.set_defs:
        lines.append(f"    set {nm} {{")
        lines.append(f"        type {'ipv6_addr' if fam == 'ipv6' else 'ipv4_addr'}")
        interval = _needs_interval(elements)
        flags = []
        if interval:
            flags.append("interval")
        if dynamic and not interval:
            flags += ["dynamic", "timeout"]
        if flags:
            lines.append(f"        flags {', '.join(flags)}")
        if interval:
            lines.append("        auto-merge")
        if elements:
            lines.append(f"        elements = {{ {', '.join(elements)} }}")
        lines.append("    }")
        lines.append("")

    rule_notes: List[str] = []
    for key, r_list in by_chain.items():
        role, chain = key
        spec = _chain_spec(role, chain)
        name = ctx.chain_names[key]
        lines.append(f"    chain {name} {{")
        if spec:
            _, ctype, hook, prio = spec
            pol = policies.get(key)
            decl = f"type {ctype} hook {hook} priority {prio};"
            if pol:
                decl += f" policy {pol};"
            lines.append(f"        {decl}")
        for r in r_list:
            alts, problems = _build_matches(ctx, r)
            stmt, aprob = _action(ctx, r)
            if aprob:
                problems.append(aprob)
            if stmt and r.action.lower() == "jump":
                stmt = f"jump {jump_name(r)}"
            if problems or stmt is None:
                reason = "; ".join(problems)
                lines.append(_sanitize_comment_line(
                    f"        # NOT EXPORTED (rule {r.id}, {r.action}): {reason}"))
                continue
            if not alts:
                lines.append(f"        # NOT EXPORTED (rule {r.id}): address family constraints are contradictory")
                continue
            for fam, exprs in alts:
                lines.append("        " + " ".join(exprs + [stmt]) + _comment(r.comment))
        lines.append("    }")
        lines.append("")

    lines.append("}")
    if ctx.marks:
        lines.append("")
        for k, v in ctx.marks.items():
            lines.append(_sanitize_comment_line(f"# mark '{k}' => {v}"))
    for note in ctx.notes:
        lines.append(_sanitize_comment_line(f"# NOTE: {note}"))
    return "\n".join(lines) + "\n"
