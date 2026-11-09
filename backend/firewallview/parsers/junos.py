import re
import uuid
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

JUNOS_SERVICES = {
    "bgp": "179",
    "ldp": "646",
    "ospf": "89",
    "rip": "520",
    "bfd": "3784",
    "bfd-control": "3784",
    "bfd-echo": "3785",
    "multihop-bfd": "4784",
    "ssh": "22",
    "telnet": "23",
    "ftp": "21",
    "ftp-data": "20",
    "tftp": "69",
    "http": "80",
    "https": "443",
    "snmp": "161",
    "snmp-trap": "162",
    "snmptrap": "162",
    "syslog": "514",
    "ntp": "123",
    "domain": "53",
    "dns": "53",
    "netbios": "137",
    "netbios-ns": "137",
    "netbios-dgm": "138",
    "netbios-ssn": "139",
    "bootps": "67",
    "bootpc": "68",
    "dhcp": "67",
    "dhcpv6-client": "546",
    "dhcpv6-server": "547",
    "radius": "1812",
    "radacct": "1813",
    "radius-acct": "1813",
    "tacacs": "49",
    "tacacs-ds": "65",
    "sip": "5060",
    "smtp": "25",
    "pop3": "110",
    "imap": "143",
    "imaps": "993",
    "ldap": "389",
    "ldaps": "636",
    "ike": "500",
    "l2tp": "1701",
    "pptp": "1723",
    "rtsp": "554",
    "nfsd": "2049",
    "sunrpc": "111",
    "xdmcp": "177",
    "who": "513",
    "traceroute": "33434-33523",
}

# Then-actions that never change the verdict of a term.
_NONTERMINAL_THEN = {
    "count", "log", "syslog", "sample", "policer", "three-color-policer",
    "hierarchical-policer", "forwarding-class", "loss-priority", "port-mirror",
    "traffic-class", "dscp", "packet-mark", "service-accounting", "load-balance",
    "ipsec-sa", "next-hop-group", "prefix-action", "decapsulate", "encapsulate",
    "topology", "virtual-channel", "parallel", "flood", "ttl",
}

_PORT_FIELDS = {
    "destination-port": ("dst_port", False),
    "destination-port-except": ("dst_port", True),
    "source-port": ("src_port", False),
    "source-port-except": ("src_port", True),
    "port": ("port", False),
    "port-except": ("port", True),
}

_TCP_FLAG_NAMES = {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}


def resolve_junos_port(token: str) -> str:
    cleaned = token.replace(";", "").replace("[", "").replace("]", "").strip().lower()
    return JUNOS_SERVICES.get(cleaned, cleaned)


def _accumulate_csv(existing: Optional[str], new_val: str) -> str:
    if not new_val:
        return existing or ""
    if not existing:
        return new_val
    existing_items = [x.strip() for x in existing.split(",") if x.strip()]
    if new_val not in existing_items:
        existing_items.append(new_val)
    return ",".join(existing_items)


# ---------------------------------------------------------------------------
# Tokenizer / tree parser for the curly (hierarchical) format
# ---------------------------------------------------------------------------

_PUNCT = "{};[]"


def _tokenize(text: str) -> List[Tuple[str, str]]:
    """Returns (kind, value) tokens; kind is 'punct' or 'word'.

    Handles /* */ and # comments and "quoted strings" (kept as one word, quotes removed).
    """
    tokens: List[Tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "/" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif ch == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif ch in _PUNCT:
            tokens.append(("punct", ch))
            i += 1
        elif ch == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            tokens.append(("word", "".join(buf)))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in _PUNCT and text[j] != '"':
                j += 1
            tokens.append(("word", text[i:j]))
            i = j
    return tokens


class _Node:
    __slots__ = ("words", "children", "inactive")

    def __init__(self, words: List[str], children: Optional[List["_Node"]], inactive: bool):
        self.words = words
        self.children = children
        self.inactive = inactive


def _parse_tree(tokens: List[Tuple[str, str]]) -> List[_Node]:
    """Brace-aware parser: statements end with ';' (leaf) or '{ ... }' (block)."""
    pos = 0
    n = len(tokens)

    def parse_block() -> List[_Node]:
        nonlocal pos
        nodes: List[_Node] = []
        while pos < n:
            kind, val = tokens[pos]
            if kind == "punct" and val == "}":
                pos += 1
                return nodes
            if kind == "punct" and val in ";]":
                pos += 1
                continue
            words: List[str] = []
            children: Optional[List[_Node]] = None
            while pos < n:
                kind, val = tokens[pos]
                if kind == "word":
                    words.append(val)
                    pos += 1
                elif val == "[" or val == "]":
                    pos += 1
                elif val == ";":
                    pos += 1
                    break
                elif val == "{":
                    pos += 1
                    children = parse_block()
                    break
                else:  # '}' closes the parent; statement lacked its ';'
                    break
            inactive = False
            while words and words[0] in ("inactive:", "replace:", "protect:", "delete:"):
                if words[0] == "inactive:":
                    inactive = True
                words = words[1:]
            if words or children is not None:
                nodes.append(_Node(words, children, inactive))
        return nodes

    return parse_block()


# ---------------------------------------------------------------------------
# Normalised intermediate representation (shared by curly and set formats)
# ---------------------------------------------------------------------------

Item = Tuple[str, bool]  # (value, except)


def _items_from_words(words: List[str]) -> List[Item]:
    items: List[Item] = []
    for w in words:
        if w == "except" and items:
            items[-1] = (items[-1][0], True)
        elif w in ("[", "]"):
            continue
        else:
            items.append((w, False))
    return items


class _Term:
    def __init__(self, name: str):
        self.name = name
        self.inactive = False
        self.from_stmts: List[Tuple[str, List[Item]]] = []
        self.then_stmts: List[Tuple[str, List[str]]] = []
        self.nested_filter: Optional[str] = None
        self.warnings: List[str] = []
        self.raw: List[str] = []


class _Filter:
    def __init__(self, family: str, name: str):
        self.family = family
        self.name = name
        self.inactive = False
        self.terms: Dict[str, _Term] = {}
        self.warnings: List[str] = []

    def term(self, name: str) -> _Term:
        if name not in self.terms:
            self.terms[name] = _Term(name)
        return self.terms[name]


class _Model:
    def __init__(self):
        self.filters: Dict[Tuple[str, str], _Filter] = {}
        self.address_lists: Dict[str, AddressList] = {}

    def filter(self, family: str, name: str) -> _Filter:
        key = (family, name)
        if key not in self.filters:
            self.filters[key] = _Filter(family, name)
        return self.filters[key]

    def add_prefix(self, name: str, address: Optional[str]):
        if name not in self.address_lists:
            self.address_lists[name] = AddressList(name=name, entries=[])
        if address and address != "apply-path":
            self.address_lists[name].entries.append(
                AddressListEntry(id=str(uuid.uuid4())[:8], address=address)
            )


def _fill_term_from_node(term: _Term, node: _Node):
    """Folds one child node of a curly 'term' block into the term IR."""
    if node.inactive:
        return  # an inactive statement inside a term is ignored entirely
    kw = node.words[0] if node.words else ""
    if kw == "from":
        if node.children is None and len(node.words) > 1:
            term.from_stmts.append((node.words[1], _items_from_words(node.words[2:])))
        for st in node.children or []:
            if st.inactive or not st.words:
                continue
            items = _items_from_words(st.words[1:])
            for c in st.children or []:
                if c.inactive or not c.words:
                    continue
                items.extend(_items_from_words(c.words))
            term.from_stmts.append((st.words[0], items))
    elif kw == "then":
        if len(node.words) > 1:
            term.then_stmts.append((node.words[1], node.words[2:]))
        for st in node.children or []:
            if st.inactive or not st.words:
                continue
            args = list(st.words[1:])
            for c in st.children or []:
                args.extend(c.words)
            term.then_stmts.append((st.words[0], args))
    elif kw == "filter" and len(node.words) >= 2:
        term.nested_filter = node.words[1]
    elif kw in ("apply-groups", "apply-groups-except"):
        term.warnings.append(f"{kw} {' '.join(node.words[1:])} not resolved (group contents are unknown)")
    elif kw:
        term.warnings.append(f"Unsupported term statement '{kw}' ignored")


def _walk_curly(nodes: List[_Node], family: str, model: _Model):
    for node in nodes:
        w = node.words
        if not w or w[0] == "groups":
            continue
        if w[0] == "family" and len(w) == 2 and node.children is not None:
            _walk_curly(node.children, w[1], model)
        elif w[0] == "filter" and len(w) == 2 and node.children is not None:
            flt = model.filter(family, w[1])
            if node.inactive:
                flt.inactive = True
            for child in node.children:
                cw = child.words
                if cw and cw[0] == "term" and len(cw) == 2 and child.children is not None:
                    term = flt.term(cw[1])
                    term.inactive = term.inactive or child.inactive
                    term.raw.append(f"filter {w[1]} term {cw[1]}")
                    for sub in child.children:
                        _fill_term_from_node(term, sub)
                elif cw and cw[0] in ("apply-groups", "apply-groups-except"):
                    flt.warnings.append(f"{cw[0]} {' '.join(cw[1:])} not resolved")
        elif w[0] == "prefix-list" and len(w) == 2 and node.children is not None:
            model.add_prefix(w[1], None)
            for c in node.children:
                if c.inactive or not c.words or c.words[0] in ("apply-path", "apply-groups"):
                    continue
                model.add_prefix(w[1], c.words[0])
        elif node.children is not None:
            _walk_curly(node.children, family, model)


def _build_model_curly(content: str) -> _Model:
    model = _Model()
    _walk_curly(_parse_tree(_tokenize(content)), "inet", model)
    return model


def _split_firewall_path(tokens: List[str]):
    """Tokens after set/deactivate: firewall [family X] filter F [term T ...].

    Returns (family, filter_name, term_name, tail); missing parts are None.
    """
    if not tokens or tokens[0] != "firewall":
        return "inet", None, None, []
    i = 1
    family = "inet"
    if i + 1 < len(tokens) and tokens[i] == "family":
        family = tokens[i + 1]
        i += 2
    if i + 1 < len(tokens) and tokens[i] == "filter":
        fname = tokens[i + 1]
        i += 2
        if i + 1 < len(tokens) and tokens[i] == "term":
            return family, fname, tokens[i + 1], tokens[i + 2:]
        return family, fname, None, tokens[i:]
    return family, None, None, []


def _build_model_set(content: str) -> _Model:
    model = _Model()
    deactivated_terms = set()
    deactivated_filters = set()
    partial_deactivate: List[Tuple[str, str, str, str]] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("set ") or stripped.startswith("deactivate ")):
            continue
        tokens = [v for k, v in _tokenize(stripped) if not (k == "punct" and v in "[];")]
        verb, rest = tokens[0], tokens[1:]

        if verb == "deactivate":
            fam, fname, tname, tail = _split_firewall_path(rest)
            if fname is not None and tname is not None:
                if tail:
                    partial_deactivate.append((fam, fname, tname, " ".join(tail)))
                else:
                    deactivated_terms.add((fam, fname, tname))
            elif fname is not None:
                deactivated_filters.add((fam, fname))
            continue

        if "prefix-list" in rest and "term" not in rest:
            idx = rest.index("prefix-list")
            if idx + 1 < len(rest):
                model.add_prefix(rest[idx + 1], rest[idx + 2] if idx + 2 < len(rest) else None)
            continue

        if not rest or rest[0] != "firewall":
            continue
        fam, fname, tname, tail = _split_firewall_path(rest)
        if fname is None or tname is None:
            continue
        term = model.filter(fam, fname).term(tname)
        term.raw.append(stripped)
        if not tail:
            continue
        head = tail[0]
        if head == "from" and len(tail) >= 2:
            term.from_stmts.append((tail[1], _items_from_words(tail[2:])))
        elif head == "then" and len(tail) >= 2:
            term.then_stmts.append((tail[1], tail[2:]))
        elif head == "filter" and len(tail) >= 2:
            term.nested_filter = tail[1]
        elif head in ("apply-groups", "apply-groups-except"):
            term.warnings.append(f"{head} {' '.join(tail[1:])} not resolved (group contents are unknown)")
        else:
            term.warnings.append(f"Unsupported term statement '{head}' ignored")

    for key, flt in model.filters.items():
        if key in deactivated_filters:
            flt.inactive = True
        for tname, term in flt.terms.items():
            if (flt.family, flt.name, tname) in deactivated_terms:
                term.inactive = True
    for fam, fname, tname, tail in partial_deactivate:
        flt = model.filters.get((fam, fname))
        if flt and tname in flt.terms:
            flt.terms[tname].warnings.append(
                f"deactivate of '{tail}' inside the term is not modeled (statement kept active)"
            )
    return model


# ---------------------------------------------------------------------------
# IR -> FirewallRule
# ---------------------------------------------------------------------------

def _family_info(family: str) -> Tuple[str, Optional[str], List[str]]:
    """Returns (chain suffix, rule family, warnings).

    inet -> chain '<name>', ipv4. inet6 -> chain '<name>-inet6', ipv6, so inet and inet6
    filters sharing a name never merge. 'any' -> chain '<name>', both families.
    """
    if family == "inet":
        return "", "ipv4", []
    if family == "inet6":
        return "-inet6", "ipv6", []
    if family == "any":
        return "", None, []
    return f"-{family}", None, [f"Filter family '{family}' is not modeled; treated as applying to all IP traffic"]


def _chain_name(name: str, family: str) -> str:
    return name + _family_info(family)[0]


def _csv(vals: List[str]) -> str:
    out: List[str] = []
    for v in vals:
        if v and v not in out:
            out.append(v)
    return ",".join(out)


def _apply_addresses(cond: RuleCondition, side: str, pa, na, pl, nl, warns: List[str],
                     model: _Model, list_name: str):
    """Maps positive/except addresses and prefix-lists onto the (address, address_list) slots.

    Each slot carries a single polarity; the matcher ANDs the two slots. Mixed allow/except
    addresses use a synthetic negated address list holding the except entries.
    """
    if not (pa or na or pl or nl):
        return
    a_attr, l_attr = f"{side}_address", f"{side}_address_list"
    na_attr, nl_attr = f"negate_{side}_address", f"negate_{side}_address_list"
    if not (na or nl):
        if pa:
            setattr(cond, a_attr, _csv(pa))
        if pl:
            setattr(cond, l_attr, _csv(pl))
        return
    if not (pa or pl):
        if na:
            setattr(cond, a_attr, _csv(na))
            setattr(cond, na_attr, True)
        if nl:
            setattr(cond, l_attr, _csv(nl))
            setattr(cond, nl_attr, True)
        return
    # Mixed positive and 'except' entries.
    if pa:
        setattr(cond, a_attr, _csv(pa))
    if pl:
        setattr(cond, l_attr, _csv(pl))
    list_free = not pl
    if na:
        if not pa:
            setattr(cond, a_attr, _csv(na))
            setattr(cond, na_attr, True)
        elif list_free:
            model.add_prefix(list_name, None)
            for a in na:
                model.add_prefix(list_name, a)
            setattr(cond, l_attr, list_name)
            setattr(cond, nl_attr, True)
            list_free = False
        else:
            warns.append(f"Mixed {side} allow/except addresses could not be represented; except entries "
                         f"{','.join(na)} ignored")
    if nl:
        if list_free:
            setattr(cond, l_attr, _csv(nl))
            setattr(cond, nl_attr, True)
        else:
            warns.append(f"Mixed {side} allow/except prefix-lists could not be represented; except lists "
                         f"{','.join(nl)} ignored")


def _parse_tcp_flags(value: str, cond: RuleCondition, warns: List[str]):
    s = value.strip()
    neg = False
    if s.startswith("!") and s[1:].lstrip().startswith("("):
        neg = True
        s = s[1:].strip()
    s = s.strip("() ")
    if "|" in s:
        warns.append(f"tcp-flags '{value}' uses OR; modeled as AND of all flags")
    for tok in re.split(r"[&|]", s):
        tok = tok.strip().strip("()").strip().lower()
        if not tok:
            continue
        bare = tok.lstrip("!")
        if bare not in _TCP_FLAG_NAMES and re.fullmatch(r"(0x)?[0-9a-f]+(/(0x)?[0-9a-f]+)?", bare):
            warns.append(f"tcp-flags numeric value '{tok}' not modeled")
            continue
        if tok not in cond.tcp_flags:
            cond.tcp_flags.append(tok)
    if neg:
        cond.negate_tcp_flags = True


def _build_rule(flt: _Filter, term: _Term, model: _Model, rule_id: int, set_format: bool) -> FirewallRule:
    suffix, rfamily, fam_warns = _family_info(flt.family)
    chain = flt.name + suffix
    cond = RuleCondition()
    warns: List[str] = list(fam_warns) + list(flt.warnings) + list(term.warnings)

    acc = {"src": ([], [], [], []), "dst": ([], [], [], [])}  # pa, na, pl, nl

    def add_addr(side, items, is_list):
        pa, na, pl, nl = acc[side]
        for val, exc in items:
            if is_list:
                (nl if exc else pl).append(val)
            else:
                (na if exc else pa).append(val)

    port_neg: Dict[str, bool] = {}

    for kw, items in term.from_stmts:
        vals = [v for v, _ in items]
        if kw == "source-address":
            add_addr("src", items, False)
        elif kw == "destination-address":
            add_addr("dst", items, False)
        elif kw == "source-prefix-list":
            add_addr("src", items, True)
        elif kw == "destination-prefix-list":
            add_addr("dst", items, True)
        elif kw == "prefix-list":
            add_addr("src", items, True)
            warns.append("'from prefix-list' matches source OR destination in Junos; modeled as source only")
        elif kw in ("protocol", "next-header", "payload-protocol", "protocol-except", "next-header-except"):
            cond.protocol = _csv(([cond.protocol] if cond.protocol else []) + [v.lower() for v in vals])
            if kw.endswith("-except"):
                cond.negate_protocol = True
        elif kw in _PORT_FIELDS:
            attr, neg = _PORT_FIELDS[kw]
            resolved = [resolve_junos_port(v) for v in vals]
            cur = getattr(cond, attr)
            setattr(cond, attr, _csv(([cur] if cur else []) + resolved))
            if attr in port_neg and port_neg[attr] != neg:
                warns.append(f"{attr} mixes plain and '-except' matches; last one wins")
            port_neg[attr] = neg
            setattr(cond, f"negate_{attr}", neg)
        elif kw in ("interface", "input-interface", "ingress-interface"):
            cond.in_interface = _csv(([cond.in_interface] if cond.in_interface else []) + vals)
        elif kw in ("out-interface", "output-interface", "egress-interface"):
            cond.out_interface = _csv(([cond.out_interface] if cond.out_interface else []) + vals)
        elif kw == "tcp-established":
            for st in ("established", "related"):
                if st not in cond.connection_state:
                    cond.connection_state.append(st)
        elif kw == "tcp-initial":
            if "new" not in cond.connection_state:
                cond.connection_state.append("new")
            for f in ("syn", "!ack"):
                if f not in cond.tcp_flags:
                    cond.tcp_flags.append(f)
        elif kw == "tcp-flags":
            for v in vals:
                _parse_tcp_flags(v, cond, warns)
        elif kw in ("icmp-type", "icmp-type-except", "icmp-code", "icmp-code-except"):
            warns.append(f"{kw} {' '.join(vals)} not modeled (no ICMP type field); rule is broader than the original")
        elif kw in ("apply-groups", "apply-groups-except"):
            warns.append(f"{kw} {' '.join(vals)} not resolved (group contents are unknown)")
        else:
            warns.append((f"Unsupported match condition '{kw}' {' '.join(vals)}").rstrip() + " ignored")

    base = f"{chain}-{term.name}"
    _apply_addresses(cond, "src", *acc["src"], warns, model, f"{base}-src-except")
    _apply_addresses(cond, "dst", *acc["dst"], warns, model, f"{base}-dst-except")

    # Action: first terminal verdict by precedence discard > reject > accept > routing-instance > next term.
    action = "accept"
    target_chain = None
    verdicts = []
    for kw, args in term.then_stmts:
        if kw in ("discard", "drop"):
            verdicts.append((0, "drop"))
        elif kw == "reject":
            verdicts.append((1, "reject"))
        elif kw == "accept":
            verdicts.append((2, "accept"))
        elif kw == "next":
            if args and args[0] == "term":
                verdicts.append((4, "passthrough"))
                warns.append("'next term': no verdict, evaluation continues with the next term")
            else:
                warns.append(f"Unsupported 'then next {' '.join(args)}' ignored")
        elif kw == "routing-instance":
            verdicts.append((3, "accept"))
            warns.append(f"then routing-instance {' '.join(args)}: traffic is forwarded in another routing "
                         f"instance; modeled as accept")
        elif kw in _NONTERMINAL_THEN:
            continue
        else:
            warns.append(f"Unsupported 'then {kw}' action ignored")
    if verdicts:
        action = min(verdicts)[1]

    if term.nested_filter:
        action = "jump"
        target_chain = _chain_name(term.nested_filter, flt.family)

    if set_format:
        comment = f"term: {term.name}"
        raw = "; ".join(term.raw)
    else:
        comment = f"term {term.name}"
        raw = f"filter {flt.name} term {term.name}"

    return FirewallRule(
        id=str(rule_id),
        order=rule_id,
        table="filter",
        chain=chain,
        family=rfamily,
        action=action,
        target_chain=target_chain,
        conditions=cond,
        comment=comment,
        disabled=bool(term.inactive or flt.inactive),
        raw_syntax=raw,
        parse_warnings=warns,
    )


def _model_to_rules(model: _Model, set_format: bool) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    rules: List[FirewallRule] = []
    jump_targets = set()
    for flt in model.filters.values():
        for term in flt.terms.values():
            if term.nested_filter:
                jump_targets.add(_chain_name(term.nested_filter, flt.family))

    rule_id = 1
    for flt in model.filters.values():
        for term in flt.terms.values():
            rules.append(_build_rule(flt, term, model, rule_id, set_format))
            rule_id += 1
        suffix, rfamily, _ = _family_info(flt.family)
        chain = flt.name + suffix
        if chain in jump_targets:
            # A nested filter without a match falls back to the calling filter, so only
            # top-level filters get Junos' implicit final discard.
            continue
        rules.append(FirewallRule(
            id=str(rule_id),
            order=rule_id,
            table="filter",
            chain=chain,
            family=rfamily,
            action="drop",
            is_policy=True,
            comment="implicit discard",
            raw_syntax="implicit discard",
        ))
        rule_id += 1
    return rules, model.address_lists


def parse_junos_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Juniper Junos OS firewall configurations:
    Supports both hierarchical block syntax (filter { term { ... } }) and 'set' format.

    Conventions: a family inet6 filter F becomes chain 'F-inet6' (rule.family ipv6);
    inet filters keep their name (rule.family ipv4). Every top-level (non-nested) filter gets a
    trailing is_policy drop rule ("implicit discard"). 'inactive:' / deactivated terms are disabled.
    """
    lines = content.splitlines()
    set_lines = [l for l in lines if l.strip().startswith(("set ", "deactivate "))]
    brace_lines = [l for l in lines if "{" in l and not l.strip().startswith(("#", "/*", "*"))]

    if set_lines and len(set_lines) >= len(brace_lines):
        return _model_to_rules(_build_model_set(content), True)
    return _model_to_rules(_build_model_curly(content), False)
