import ipaddress
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList

BUILTIN_FILTER_NAMES = {
    "input": "PROTECT_INBOUND",
    "forward": "FORWARD_FILTER",
    "output": "OUTPUT_FILTER",
}

_ANY_PROTOCOLS = {"any", "all", "ip", "ip4", "ipv4", "ipv6"}


class _Unsupported(Exception):
    pass


def _comment(text: str) -> str:
    return "/* UNSUPPORTED: " + text.replace("*/", "* /").replace("\n", " ") + " */"


def _normalize_address(addr: str) -> List[str]:
    """Junos prefixes: hosts get /32 (v4) or /128 (v6); ranges are summarized into CIDRs."""
    addr = addr.strip()
    if not addr:
        return []
    if "/" in addr:
        return [addr]
    if "-" in addr:
        lo, _, hi = addr.partition("-")
        try:
            a, b = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
            return [str(n) for n in ipaddress.summarize_address_range(a, b)]
        except ValueError:
            return [addr]
    try:
        ip = ipaddress.ip_address(addr)
        return [f"{addr}/{32 if ip.version == 4 else 128}"]
    except ValueError:
        return [addr]


def _split_csv(value: Optional[str]) -> List[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _is_v6(text: str) -> bool:
    return ":" in text


def _filter_name(chain: str, family: str) -> str:
    name = BUILTIN_FILTER_NAMES.get(chain.lower(), chain)
    if family == "inet6" and name.endswith("-inet6"):
        name = name[: -len("-inet6")]
    return name


def _rule_family(r: FirewallRule, address_lists: Dict[str, AddressList]) -> str:
    if r.family == "ipv6":
        return "inet6"
    if r.family == "ipv4":
        return "inet"
    c = r.conditions
    texts = _split_csv(c.src_address) + _split_csv(c.dst_address)
    for ln in _split_csv(c.src_address_list) + _split_csv(c.dst_address_list):
        al = address_lists.get(ln)
        if al:
            texts += [e.address for e in al.entries]
    return "inet6" if texts and all(_is_v6(t) for t in texts) else "inet"


def _clean_term_name(r: FirewallRule) -> str:
    raw = r.comment or ""
    for prefix in ("term: ", "term "):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    name = raw.replace(" ", "-").replace(":", "-").lower() if raw else f"rule-{r.id}"
    name = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:32]
    return name or f"rule-{r.id}"


def _addr_stmt(indent: str, keyword: str, values: List[str], negate: bool) -> List[str]:
    if len(values) == 1:
        return [f"{indent}{keyword} {values[0]}{' except' if negate else ''};"]
    out = [f"{indent}{keyword} {{"]
    for v in values:
        out.append(f"{indent}    {v}{' except' if negate else ''};")
    out.append(f"{indent}}}")
    return out


def _list_stmt(indent: str, keyword: str, values: List[str], negate: bool) -> List[str]:
    if len(values) == 1:
        return [f"{indent}{keyword} {values[0]}{' except' if negate else ''};"]
    return _addr_stmt(indent, keyword, values, negate)


def _values_stmt(indent: str, keyword: str, values: List[str]) -> str:
    if len(values) == 1:
        return f"{indent}{keyword} {values[0]};"
    return f"{indent}{keyword} [ {' '.join(values)} ];"


def _from_lines(r: FirewallRule, family: str, ind: str) -> List[str]:
    """Builds the body of the 'from' block. Raises _Unsupported if the rule cannot be expressed."""
    c = r.conditions
    out: List[str] = []

    unsupported = []
    if c.packet_mark:
        unsupported.append("packet-mark")
    if c.limit:
        unsupported.append("limit")
    if c.ipsec_policy:
        unsupported.append("ipsec-policy")
    if c.connection_nat_state:
        unsupported.append("connection-nat-state")
    if c.negate_in_interface and c.in_interface:
        unsupported.append("negated in-interface")
    if c.negate_out_interface and c.out_interface:
        unsupported.append("negated out-interface")
    if unsupported:
        raise _Unsupported("condition(s) not expressible in Junos: " + ", ".join(unsupported))

    for side, kw in (("src", "source"), ("dst", "destination")):
        addrs = getattr(c, f"{side}_address")
        lists = getattr(c, f"{side}_address_list")
        if addrs:
            values: List[str] = []
            for a in _split_csv(addrs):
                values.extend(_normalize_address(a))
            if values:
                out += _addr_stmt(ind, f"{kw}-address", values, getattr(c, f"negate_{side}_address"))
        if lists:
            out += _list_stmt(ind, f"{kw}-prefix-list", _split_csv(lists), getattr(c, f"negate_{side}_address_list"))

    if c.protocol and c.protocol.strip().lower() not in _ANY_PROTOCOLS:
        protos = [p.lower() for p in _split_csv(c.protocol)]
        if family == "inet6":
            protos = ["icmp6" if p in ("icmp", "icmpv6", "ipv6-icmp") else p for p in protos]
            kw = "next-header"
        else:
            kw = "protocol"
        if c.negate_protocol:
            kw += "-except"
        out.append(_values_stmt(ind, kw, protos))

    for attr, kw in (("dst_port", "destination-port"), ("src_port", "source-port"), ("port", "port")):
        val = getattr(c, attr)
        if val:
            ports = _split_csv(val)
            if ports:
                out.append(_values_stmt(ind, kw + ("-except" if getattr(c, f"negate_{attr}") else ""), ports))

    if c.in_interface:
        out.append(_values_stmt(ind, "interface", _split_csv(c.in_interface)))
    if c.out_interface:
        out.append(f"{ind}/* out-interface is not a standard Junos filter match; verify on the target platform */")
        out.append(_values_stmt(ind, "out-interface", _split_csv(c.out_interface)))

    # Connection state / TCP flags
    states = [s.lower() for s in (c.connection_state or [])]
    flags = [f.lower() for f in (c.tcp_flags or [])]
    if states:
        if c.negate_connection_state:
            raise _Unsupported("negated connection-state has no stateless Junos equivalent")
        unknown = [s for s in states if s not in ("new", "established", "related")]
        if unknown:
            raise _Unsupported(f"connection-state {','.join(unknown)} has no stateless Junos equivalent")
        has_est = "established" in states or "related" in states
        if "new" in states and has_est:
            pass  # any TCP packet: no restriction expressible
        elif has_est:
            out.append(f"{ind}tcp-established;")
        elif "new" in states:
            out.append(f"{ind}tcp-initial;")
            if not c.negate_tcp_flags:
                for f in ("syn", "!ack"):
                    if f in flags:
                        flags.remove(f)
    if flags:
        expr = " & ".join(flags)
        if c.negate_tcp_flags:
            expr = f"!({expr})"
        out.append(f'{ind}tcp-flags "{expr}";')
    return out


def _then_lines(r: FirewallRule, ind: str) -> List[str]:
    action = (r.action or "accept").lower()
    if action == "accept":
        return [f"{ind}accept;"]
    if action in ("drop", "discard"):
        return [f"{ind}discard;"]
    if action == "reject":
        return [f"{ind}reject;"]
    if action == "passthrough":
        return [f"{ind}next term;"]
    if action == "log":
        return [f"{ind}log;", f"{ind}next term;"]
    raise _Unsupported(f"action '{r.action}' has no Junos firewall-filter equivalent")


def export_to_junos(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines: List[str] = ["/* Exported by FirewallView (Juniper Junos OS syntax) */"]

    # Non-filter tables cannot be expressed as firewall filters.
    skipped_tables: List[str] = []
    filter_rules: List[FirewallRule] = []
    for r in sorted(rules, key=lambda x: x.order):
        if (r.table or "filter").lower() != "filter":
            skipped_tables.append(
                _comment(f"rule {r.id} in table {r.table} chain {r.chain} (action {r.action}) skipped; "
                         f"Junos filters have no {r.table} table")
            )
        else:
            filter_rules.append(r)
    lines.extend(skipped_tables)

    # Prefix lists (policy-options)
    if address_lists:
        lines.append("policy-options {")
        for name, alist in address_lists.items():
            lines.append(f"    prefix-list {name} {{")
            for entry in alist.entries:
                if entry.disabled:
                    continue
                for a in _normalize_address(entry.address):
                    lines.append(f"        {a};")
            lines.append("    }")
        lines.append("}")

    # Group by (family, filter), keeping first-seen order; policy rules go last in each filter.
    groups: Dict[Tuple[str, str], List[FirewallRule]] = {}
    for r in filter_rules:
        fam = _rule_family(r, address_lists)
        groups.setdefault((fam, _filter_name(r.chain or "forward", fam)), []).append(r)

    by_family: Dict[str, List[str]] = {"inet": [], "inet6": []}
    for (fam, fname), r_list in groups.items():
        normal = [r for r in r_list if not r.is_policy]
        policies = [r for r in r_list if r.is_policy]
        body: List[str] = []
        used_names = set()

        def unique(name: str) -> str:
            base, n = name, 2
            while name in used_names:
                name = f"{base[:28]}-{n}"
                n += 1
            used_names.add(name)
            return name

        n_terms = 0
        for r in normal:
            try:
                from_body = _from_lines(r, fam, " " * 20)
                then_body = _then_lines(r, " " * 20)
            except _Unsupported as e:
                body.append(" " * 12 + _comment(f"rule {r.id} ({r.action}) skipped: {e}"))
                continue
            name = unique(_clean_term_name(r))
            head = "inactive: " if r.disabled else ""
            body.append(f"            {head}term {name} {{")
            if from_body:
                body.append("                from {")
                body.extend(from_body)
                body.append("                }")
            body.append("                then {")
            body.extend(then_body)
            body.append("                }")
            body.append("            }")
            n_terms += 1

        for r in policies:
            act = (r.action or "drop").lower()
            if act in ("drop", "discard"):
                continue  # Junos filters end with an implicit discard
            if act == "reject":
                tname, then = "default-reject", ["reject;"]
            elif act == "accept":
                tname, then = "default-accept", ["accept;"]
            else:
                body.append(" " * 12 + _comment(f"policy rule {r.id} action {r.action} skipped"))
                continue
            body.append(f"            term {unique(tname)} {{")
            body.append("                then {")
            body.extend(" " * 20 + t for t in then)
            body.append("                }")
            body.append("            }")
            n_terms += 1

        if n_terms == 0 and not any(b.strip().startswith("/*") for b in body):
            continue
        by_family[fam].append(f"        filter {fname} {{")
        by_family[fam].extend(body)
        by_family[fam].append("        }")

    lines.append("firewall {")
    for fam in ("inet", "inet6"):
        if by_family[fam]:
            lines.append(f"    family {fam} {{")
            lines.extend(by_family[fam])
            lines.append("    }")
    lines.append("}")
    return "\n".join(lines)
