"""nftables parser.

The input is tokenised (quoted strings, ``{ }`` sets, ``;`` and newlines are
tokens), split into tables / chains / sets / rules, and every rule statement is
then interpreted token by token.

Mapping to the canonical model (see ``FirewallRule``):
- ``table`` is the family-agnostic role (raw | mangle | nat | filter) derived
  from the base chain ``type`` / ``hook`` / ``priority``; it is NOT the nft
  table name.
- nat prerouting/postrouting become ``dstnat``/``srcnat``.
- regular (non-base) chains live in the role of the base chains that jump to
  them (default ``filter``) and keep their name.
- ``policy`` of a base chain becomes an ``is_policy`` rule.
- one nft rule with several actions produces several rules
  (``log drop`` -> ``log`` + ``drop``), each with the same conditions.
- anything that cannot be represented becomes a ``parse_warnings`` entry.
"""
import re
import uuid
from typing import Dict, List, Optional, Tuple

from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

HOOKS = ("prerouting", "input", "forward", "output", "postrouting")
PRIORITY_NAMES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0,
                  "security": 50, "srcnat": 100}
PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53,
    "bootps": 67, "bootpc": 68, "tftp": 69, "http": 80, "pop3": 110, "ntp": 123,
    "imap": 143, "snmp": 161, "snmp-trap": 162, "bgp": 179, "ldap": 389,
    "https": 443, "smtps": 465, "syslog": 514, "submission": 587, "ldaps": 636,
    "imaps": 993, "pop3s": 995, "mysql": 3306, "postgresql": 5432,
}
PROTO_ALIASES = {"icmpv6": "icmpv6", "ipv6-icmp": "icmpv6", "icmp6": "icmpv6",
                 "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6",
                 "47": "gre", "50": "esp", "51": "ah", "132": "sctp"}
L4_NAMES = ("tcp", "udp", "sctp", "dccp", "udplite")
COMPARE_OPS = {"==": "", "eq": "", "!=": "!=", "ne": "!=", "<": "<", "lt": "<",
               ">": ">", "gt": ">", "<=": "<=", "le": "<=", ">=": ">=", "ge": ">="}
LOG_FLAGS = ("tcp", "sequence", "options", "ip", "ether", "skuid", "all")
NAT_FLAGS = ("persistent", "random", "fully-random")
# words that start a new statement / matcher (delimit free-form values)
STOP_WORDS = {
    "ip", "ip6", "meta", "tcp", "udp", "sctp", "dccp", "udplite", "icmp", "icmpv6",
    "th", "ct", "iif", "iifname", "oif", "oifname", "limit", "counter", "log",
    "comment", "accept", "drop", "reject", "return", "jump", "goto", "dnat",
    "snat", "masquerade", "redirect", "queue", "continue", "notrack",
    "add", "update", "delete", "tproxy", "ether", "vlan", "fib", "socket",
}


class Tok:
    __slots__ = ("kind", "text", "start", "end")

    def __init__(self, kind: str, text: str, start: int, end: int):
        self.kind, self.text, self.start, self.end = kind, text, start, end

    def __repr__(self):
        return f"Tok({self.kind},{self.text!r})"


def _lex(content: str) -> List[Tok]:
    toks: List[Tok] = []
    i, n = 0, len(content)
    while i < n:
        c = content[i]
        if c == "\n":
            toks.append(Tok("nl", "\n", i, i + 1)); i += 1
        elif c in " \t\r":
            i += 1
        elif c == "\\" and content[i + 1:i + 2] == "\n":
            i += 2
        elif c == "#":
            while i < n and content[i] != "\n":
                i += 1
        elif c in "{};,":
            toks.append(Tok(c, c, i, i + 1)); i += 1
        elif c in "\"'":
            j = i + 1
            buf = []
            while j < n and content[j] != c:
                if content[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(content[j]); j += 1
            toks.append(Tok("s", "".join(buf), i, min(j + 1, n))); i = j + 1
        else:
            j = i
            while j < n and content[j] not in " \t\r\n{};,#\"'":
                j += 1
            toks.append(Tok("w", content[i:j], i, j)); i = j
    return toks


def _expand_defines(toks: List[Tok]) -> List[Tok]:
    """Substitute ``define NAME = value`` variables (``$NAME``) and drop the defines."""
    defs: Dict[str, List[Tok]] = {}
    out: List[Tok] = []
    i, n = 0, len(toks)
    at_start = True
    while i < n:
        t = toks[i]
        if at_start and t.kind == "w" and t.text.lower() in ("define", "redefine"):
            j = i + 1
            name = toks[j].text if j < n else ""
            j += 1
            if j < n and toks[j].text == "=":
                j += 1
            depth, val = 0, []
            while j < n:
                tj = toks[j]
                if tj.kind == "{":
                    depth += 1
                elif tj.kind == "}":
                    depth -= 1
                elif tj.kind in ("nl", ";") and depth <= 0:
                    break
                if not (tj.kind == "nl" and depth > 0):
                    val.append(tj)
                j += 1
            defs[name.lstrip("$")] = val
            i = j
            continue
        if t.kind == "w" and t.text.startswith("$") and t.text[1:] in defs:
            out.extend(defs[t.text[1:]])
        else:
            out.append(t)
        at_start = t.kind in ("nl", ";", "{", "}")
        i += 1
    return out


class _Chain:
    def __init__(self, table: "_Table", name: str, idx: int):
        self.table, self.name, self.idx = table, name, idx
        self.ctype: Optional[str] = None
        self.hook: Optional[str] = None
        self.prio = 0
        self.policy: Optional[str] = None
        self.rules: List[Tuple[List[Tok], str]] = []
        self.target: Optional[Tuple[str, str]] = None  # (role table, chain)


class _Table:
    def __init__(self, family: str, name: str):
        self.family, self.name = family, name
        self.chains: Dict[str, _Chain] = {}


class _SetInfo:
    def __init__(self, name: str):
        self.name = name
        self.type = ""
        self.elements: List[Tuple[str, Optional[str]]] = []


class _Structure:
    """Token stream -> tables, chains, sets."""

    def __init__(self, content: str):
        self.content = content
        self.toks = _expand_defines(_lex(content))
        self.pos = 0
        self.tables: Dict[Tuple[str, str], _Table] = {}
        self.chain_counter = 0
        self.sets: Dict[str, _SetInfo] = {}
        self.warnings: List[str] = []

    # --- cursor helpers -------------------------------------------------
    def peek(self) -> Optional[Tok]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def skip_seps(self):
        while self.pos < len(self.toks) and self.toks[self.pos].kind in ("nl", ";"):
            self.pos += 1

    def read_header(self) -> Tuple[List[Tok], bool]:
        """Words up to '{' (consumed -> True) or end of statement (False)."""
        out: List[Tok] = []
        while self.pos < len(self.toks):
            t = self.toks[self.pos]
            if t.kind == "{":
                self.pos += 1
                return out, True
            if t.kind in ("nl", ";", "}"):
                if t.kind != "}":
                    self.pos += 1
                return out, False
            out.append(t)
            self.pos += 1
        return out, False

    def read_statement(self) -> List[Tok]:
        """Tokens up to NL/';' at brace depth 0 (consumed) or an unmatched '}' (not consumed)."""
        out: List[Tok] = []
        depth = 0
        while self.pos < len(self.toks):
            t = self.toks[self.pos]
            if t.kind == "{":
                depth += 1
            elif t.kind == "}":
                if depth == 0:
                    return out
                depth -= 1
            elif t.kind in ("nl", ";") and depth == 0:
                self.pos += 1
                return out
            self.pos += 1
            if t.kind != "nl":
                out.append(t)
        return out

    def skip_block(self):
        depth = 1
        while self.pos < len(self.toks) and depth:
            k = self.toks[self.pos].kind
            depth += (k == "{") - (k == "}")
            self.pos += 1

    def collect_block(self) -> List[Tok]:
        """After an opening '{' (consumed): tokens of the block, closing '}' consumed."""
        out: List[Tok] = []
        depth = 1
        while self.pos < len(self.toks) and depth:
            t = self.toks[self.pos]
            depth += (t.kind == "{") - (t.kind == "}")
            if depth and t.kind != "nl":
                out.append(t)
            self.pos += 1
        return out

    # --- model helpers --------------------------------------------------
    def get_table(self, fam: str, name: str) -> _Table:
        key = (fam, name)
        if key not in self.tables:
            self.tables[key] = _Table(fam, name)
        return self.tables[key]

    def get_chain(self, table: _Table, name: str) -> _Chain:
        if name not in table.chains:
            table.chains[name] = _Chain(table, name, self.chain_counter)
            self.chain_counter += 1
        return table.chains[name]

    def get_set(self, name: str) -> _SetInfo:
        if name not in self.sets:
            self.sets[name] = _SetInfo(name)
        return self.sets[name]

    def src(self, toks: List[Tok]) -> str:
        return self.content[toks[0].start:toks[-1].end].strip() if toks else ""

    # --- parse ----------------------------------------------------------
    def parse(self):
        while True:
            self.skip_seps()
            t = self.peek()
            if t is None:
                return
            if t.kind != "w":
                self.pos += 1
                continue
            w = t.text.lower()
            if w == "nft":
                self.pos += 1
            elif w in ("flush", "delete", "destroy", "rename", "list", "reset"):
                st = self.read_statement()
                if w != "flush":
                    self.warnings.append(f"Ignored command: {self.src(st)}")
            elif w == "table":
                self.pos += 1
                hdr, block = self.read_header()
                self.table_decl(hdr, block)
            elif w in ("add", "create", "insert"):
                self.pos += 1
                self.add_command(w)
            elif w in ("chain", "set"):
                self.pos += 1
                _, block = self.read_header()
                if block:
                    self.skip_block()
                self.warnings.append(f"Ignored top-level '{w}' outside of a table")
            else:
                st = self.read_statement()
                self.warnings.append(f"Unrecognised statement: {self.src(st)}")

    def table_decl(self, hdr: List[Tok], block: bool):
        words = [h.text for h in hdr]
        if len(words) >= 2:
            fam, name = words[0].lower(), words[1]
        elif len(words) == 1:
            fam, name = "ip", words[0]
        else:
            if block:
                self.skip_block()
            return
        if fam not in ("ip", "ip6", "inet"):
            self.warnings.append(f"Table '{fam} {name}' ignored: family '{fam}' is not supported")
            if block:
                self.skip_block()
            return
        table = self.get_table(fam, name)
        if block:
            self.table_body(table)

    def table_body(self, table: _Table):
        while True:
            self.skip_seps()
            t = self.peek()
            if t is None:
                return
            if t.kind == "}":
                self.pos += 1
                return
            if t.kind != "w":
                self.pos += 1
                continue
            w = t.text.lower()
            self.pos += 1
            if w == "chain":
                hdr, block = self.read_header()
                if hdr:
                    ch = self.get_chain(table, hdr[0].text)
                    if block:
                        self.chain_body(ch)
                elif block:
                    self.skip_block()
            elif w == "set":
                hdr, block = self.read_header()
                if hdr:
                    si = self.get_set(hdr[0].text)
                    if block:
                        self.set_body(si)
                elif block:
                    self.skip_block()
            elif w in ("map", "vmap", "flowtable", "counter", "quota", "limit",
                       "synproxy", "secmark", "ct", "element"):
                hdr, block = self.read_header()
                if w in ("map", "vmap", "flowtable"):
                    nm = hdr[0].text if hdr else ""
                    self.warnings.append(f"'{w} {nm}' is not supported and was ignored")
                if block:
                    self.skip_block()
            else:
                self.pos -= 1
                st = self.read_statement()
                self.warnings.append(f"Unrecognised statement in table: {self.src(st)}")

    def chain_body(self, ch: _Chain):
        while True:
            self.skip_seps()
            t = self.peek()
            if t is None:
                return
            if t.kind == "}":
                self.pos += 1
                return
            st = self.read_statement()
            if not st:
                continue
            w = st[0].text.lower() if st[0].kind == "w" else ""
            if w == "type":
                self.chain_spec(ch, st)
            elif w == "policy":
                if len(st) >= 2:
                    ch.policy = st[1].text.lower()
            elif w in ("flags", "devices", "device") or (w == "comment" and len(st) == 2):
                continue  # chain metadata, not a rule
            else:
                ch.rules.append((st, self.src(st)))

    def chain_spec(self, ch: _Chain, st: List[Tok]):
        words = [t.text for t in st]
        low = [w.lower() for w in words]
        if len(words) >= 2:
            ch.ctype = low[1]
        if "hook" in low and low.index("hook") + 1 < len(low):
            ch.hook = low[low.index("hook") + 1]
        if "priority" in low:
            expr = "".join(words[low.index("priority") + 1:]).replace(" ", "")
            ch.prio = self.eval_priority(expr)

    @staticmethod
    def eval_priority(expr: str) -> int:
        m = re.fullmatch(r"([A-Za-z]+)?([+-]\d+)?", expr)
        if m:
            name = (m.group(1) or "").lower()
            if not name or name in PRIORITY_NAMES:
                return PRIORITY_NAMES.get(name, 0) + (int(m.group(2)) if m.group(2) else 0)
        try:
            return int(expr)
        except ValueError:
            return 0

    def set_body(self, si: _SetInfo):
        while True:
            self.skip_seps()
            t = self.peek()
            if t is None:
                return
            if t.kind == "}":
                self.pos += 1
                return
            st = self.read_statement()
            if not st:
                continue
            w = st[0].text.lower()
            if w == "type":
                si.type = " ".join(t.text for t in st[1:]).lower()
            elif w == "elements":
                self.add_elements(si, st)

    def add_elements(self, si: _SetInfo, st: List[Tok]):
        """st contains ``[elements =] { a, b, ... }``."""
        try:
            lb = next(i for i, t in enumerate(st) if t.kind == "{")
        except StopIteration:
            return
        inner = st[lb + 1:]
        if inner and inner[-1].kind == "}":
            inner = inner[:-1]
        groups: List[List[Tok]] = [[]]
        depth = 0
        for t in inner:
            if t.kind == "{":
                depth += 1
            elif t.kind == "}":
                depth -= 1
            if t.kind == "," and depth == 0:
                groups.append([])
            else:
                groups[-1].append(t)
        for g in groups:
            if not g:
                continue
            val, comment = [], None
            k = 0
            while k < len(g):
                tx = g[k].text.lower() if g[k].kind == "w" else ""
                if tx in ("timeout", "expires"):
                    k += 2
                elif tx == "comment" and k + 1 < len(g):
                    comment = g[k + 1].text
                    k += 2
                else:
                    val.append(g[k].text)
                    k += 1
            if any(v in (".", ":") or v.startswith("{") for v in val):
                self.warnings.append(
                    f"Set '{si.name}': element '{' '.join(val)}' is not supported (concatenation/map)")
                continue
            joined = "".join(val)
            if joined:
                si.elements.append((joined, comment))

    def add_command(self, verb: str):
        t = self.peek()
        if t is None or t.kind != "w":
            return
        what = t.text.lower()
        self.pos += 1
        if what == "table":
            hdr, block = self.read_header()
            self.table_decl(hdr, block)
            return
        if what == "rule":
            self.add_rule(self.read_statement(), insert=(verb == "insert"))
            return
        if what in ("chain", "set", "map", "element"):
            hdr, block = self.read_header()
            words = [h.text for h in hdr]
            fam = "ip"
            if words and words[0].lower() in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
                fam = words[0].lower()
                words = words[1:]
            if fam not in ("ip", "ip6", "inet"):
                if block:
                    self.skip_block()
                self.warnings.append(f"Ignored '{what}' in unsupported family '{fam}'")
                return
            if len(words) < 2:
                if block:
                    self.skip_block()
                return
            table = self.get_table(fam, words[0])
            name = words[1]
            if what == "chain":
                ch = self.get_chain(table, name)
                if block:
                    self.chain_body(ch)
            elif what == "set":
                si = self.get_set(name)
                if block:
                    self.set_body(si)
            elif what == "element":
                si = self.get_set(name)
                if block:
                    self.add_elements(si, [Tok("{", "{", 0, 0)] + self.collect_block())
            else:
                if block:
                    self.skip_block()
                self.warnings.append(f"'{what} {name}' is not supported and was ignored")
            return
        st = self.read_statement()
        self.warnings.append(f"Unrecognised command: {verb} {what} {self.src(st)}")

    def add_rule(self, st: List[Tok], insert: bool):
        words = list(st)
        fam = "ip"
        if words and words[0].text.lower() in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
            fam = words[0].text.lower()
            words = words[1:]
        if len(words) < 2:
            return
        if fam not in ("ip", "ip6", "inet"):
            self.warnings.append(f"Rule in unsupported family '{fam}' ignored")
            return
        table = self.get_table(fam, words[0].text)
        ch = self.get_chain(table, words[1].text)
        body = words[2:]
        while len(body) >= 2 and body[0].text.lower() in ("position", "handle", "index"):
            body = body[2:]
        if not body:
            return
        item = (body, self.src(body))
        if insert:
            ch.rules.insert(0, item)
        else:
            ch.rules.append(item)


# ---------------------------------------------------------------------------
# Rule statement interpretation
# ---------------------------------------------------------------------------

class _Val:
    """Operand of a matcher."""

    def __init__(self):
        self.op = ""                    # "", "!=", "<", ...
        self.items: List[str] = []      # words / set elements
        self.ref: Optional[str] = None  # @name
        self.is_set = False
        self.bad: Optional[str] = None  # reason it cannot be modelled


class _RuleParser:
    def __init__(self, st: _Structure):
        self.st = st

    def operand(self, toks: List[Tok], i: int) -> Tuple[_Val, int]:
        v = _Val()
        n = len(toks)
        if i < n and toks[i].kind == "w":
            tx = toks[i].text.lower()
            if tx in COMPARE_OPS:
                v.op = COMPARE_OPS[tx]
                i += 1
            elif tx == "!":
                v.op = "!="
                i += 1
        if i >= n:
            v.bad = "missing value"
            return v, i
        t = toks[i]
        if t.kind == "{":
            v.is_set = True
            depth, i = 1, i + 1
            elems: List[List[Tok]] = [[]]
            while i < n and depth:
                tk = toks[i]
                if tk.kind == "{":
                    depth += 1
                elif tk.kind == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                if tk.kind == "," and depth == 1:
                    elems.append([])
                else:
                    elems[-1].append(tk)
                i += 1
            for e in elems:
                if not e:
                    continue
                texts = [x.text for x in e]
                if "." in texts or ":" in texts or any(x.kind in ("{", "}") for x in e):
                    v.bad = "concatenation/map elements are not supported"
                    continue
                v.items.append("".join(texts))
            return v, i
        if t.kind == "w" and t.text in ("vmap", "map"):
            v.bad = f"{t.text} is not supported"
            return v, n
        if t.kind == "w" and t.text.startswith("@"):
            v.ref = t.text[1:]
            return v, i + 1
        if t.kind in ("w", "s"):
            text = t.text
            i += 1
            if i + 1 < n and toks[i].kind == "w" and toks[i].text == "-" and toks[i + 1].kind == "w":
                text += "-" + toks[i + 1].text
                i += 2
            v.items.append(text)
            while i + 1 < n and toks[i].kind == "," and toks[i + 1].kind in ("w", "s"):
                v.items.append(toks[i + 1].text)  # 'new,established' written without braces
                i += 2
            return v, i
        v.bad = "unexpected token"
        return v, i + 1

    def typed_set_items(self, v: _Val, kind: str, warn) -> List[str]:
        """Expand a named set of non-address type (ports, interfaces, protocols)."""
        si = self.st.sets.get(v.ref or "")
        if si is None:
            warn(f"Named set @{v.ref} is not defined")
            return []
        if kind not in si.type:
            warn(f"Named set @{v.ref} has type '{si.type}', expected {kind}")
        return [e for e, _ in si.elements]

    def run(self, toks: List[Tok], tfamily: Optional[str]) -> List[dict]:
        cond = RuleCondition()
        warns: List[str] = []
        actions: List[dict] = []
        state = {"family": tfamily, "comment": None}
        unknown: List[str] = []
        n = len(toks)

        def warn(msg):
            if msg not in warns:
                warns.append(msg)

        def flush_unknown():
            if unknown:
                warn("Unsupported matcher/statement ignored: " + " ".join(unknown))
                unknown.clear()

        def set_family(f):
            if state["family"] and state["family"] != f:
                warn(f"Conflicting address family: table is {state['family']}, rule uses {f}")
            elif not state["family"]:
                state["family"] = f

        def put(field, value, neg_field=None, neg=False):
            if getattr(cond, field):
                warn(f"Duplicate matcher for {field}: '{value}' ignored (cannot be represented)")
                return
            setattr(cond, field, value)
            if neg_field and neg:
                setattr(cond, neg_field, True)

        def bad(v: _Val, what: str) -> bool:
            if v.bad:
                warn(f"Unsupported {what} operand ({v.bad})")
                return True
            return False

        def generic_skip(j: int) -> int:
            """Skip an unmodelled 'prefix field [op] value' (j at the prefix)."""
            flush_unknown()
            label = [toks[j].text] + ([toks[j + 1].text] if j + 1 < n else [])
            k = j + 2
            if k < n and toks[k].text.lower() == "set":
                label.append("set")
                k += 1
            v, k = self.operand(toks, k)
            warn("Unsupported matcher ignored: " + " ".join(label) +
                 (" " + v.op if v.op else "") + (" " + " ".join(v.items) if v.items else ""))
            return k

        def addr_matcher(i, side, fam):
            v, i = self.operand(toks, i)
            set_family(fam)
            if bad(v, "address"):
                return i
            if v.op not in ("", "!="):
                warn(f"Comparison '{v.op}' on address is not supported")
                return i
            pre = "src" if side == "s" else "dst"
            if v.ref:
                put(f"{pre}_address_list", v.ref, f"negate_{pre}_address_list", v.op == "!=")
            else:
                put(f"{pre}_address", ",".join(v.items), f"negate_{pre}_address", v.op == "!=")
            return i

        def proto_names(v: _Val) -> List[str]:
            items = self.typed_set_items(v, "proto", warn) if v.ref else v.items
            return [PROTO_ALIASES.get(x.lower(), x.lower()) for x in items]

        def set_proto(names: List[str], neg=False):
            if not names:
                return
            new = ",".join(names)
            cur = cond.protocol
            if cur and cur != new:
                if not neg and not cond.negate_protocol and all(x in cur.split(",") for x in names):
                    cond.protocol = new  # narrowing of an earlier l4proto set
                else:
                    warn(f"Conflicting protocol matchers '{cur}' / '{new}'; '{new}' ignored")
                return
            cond.protocol = new
            if neg:
                cond.negate_protocol = True

        def ports(i, proto, which):
            v, i = self.operand(toks, i)
            if proto:
                set_proto([proto])
            if bad(v, "port"):
                return i
            items = self.typed_set_items(v, "inet_service", warn) if v.ref else v.items
            out = []
            for it in items:
                pr = [str(PORT_NAMES.get(x.lower(), x)) for x in it.strip().split("-")]
                if not all(re.fullmatch(r"\d+", x) for x in pr):
                    warn(f"Unknown port '{it}' ignored")
                    continue
                out.append("-".join(pr))
            if not out:
                return i
            if v.op in ("<", ">", "<=", ">="):
                num = int(out[0].split("-")[0])
                out = [{">": f"{num + 1}-65535", ">=": f"{num}-65535",
                        "<": f"1-{max(num - 1, 1)}", "<=": f"1-{max(num, 1)}"}[v.op]]
            field = "dst_port" if which == "d" else "src_port"
            put(field, ",".join(out), f"negate_{field}", v.op == "!=")
            return i

        def flag_names(s: str) -> List[str]:
            return [x for x in re.split(r"[|,()\s]+", s.lower()) if x]

        def tcp_flags(i):
            mask = None
            if i + 1 < n and toks[i].text == "&":
                mask = flag_names(toks[i + 1].text)
                i += 2
            v, i = self.operand(toks, i)
            if v.bad or not v.items:
                warn("Unsupported tcp flags expression ignored")
                return i
            vals = [x for it in v.items for x in flag_names(it)]
            while i + 1 < n and toks[i].kind == ",":
                vals += flag_names(toks[i + 1].text)
                i += 2
            vals = [x for x in vals if x != "0"]
            flags = list(vals)
            if mask is not None:
                flags += [f"!{m}" for m in mask if m not in vals]
            if cond.tcp_flags:
                warn("Duplicate tcp flags matcher ignored")
            else:
                cond.tcp_flags = flags
                cond.negate_tcp_flags = v.op == "!="
            return i

        def read_free(i) -> Tuple[str, int]:
            """Free-form value up to the next statement keyword."""
            parts = []
            if i < n and toks[i].kind == "w" and toks[i].text.lower() in ("ct", "meta"):
                parts += [toks[i].text] + ([toks[i + 1].text] if i + 1 < n else [])
                i += 2
            while i < n and toks[i].kind in ("w", "s") and \
                    not (toks[i].kind == "w" and toks[i].text.lower() in STOP_WORDS):
                parts.append(toks[i].text)
                i += 1
            return " ".join(parts), i

        def nat_target(s: str) -> Tuple[Optional[str], Optional[str]]:
            s = s.strip()
            m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::([\d-]+))?", s)
            if m:
                return m.group(1), m.group(2)
            if s.startswith(":"):
                return None, s[1:] or None
            if s.count(":") == 1:
                a, p = s.split(":")
                return a or None, p or None
            return s or None, None

        i = 0
        while i < n:
            t = toks[i]
            if t.kind != "w":
                unknown.append(t.text)
                i += 1
                continue
            w = t.text.lower()
            nxt = toks[i + 1].text.lower() if i + 1 < n and toks[i + 1].kind == "w" else ""

            if w in ("ip", "ip6"):
                fam = "ipv4" if w == "ip" else "ipv6"
                if nxt in ("saddr", "daddr"):
                    flush_unknown()
                    i = addr_matcher(i + 2, nxt[0], fam)
                elif nxt in ("protocol", "nexthdr"):
                    flush_unknown()
                    v, i = self.operand(toks, i + 2)
                    set_family(fam)
                    if not bad(v, "protocol"):
                        set_proto(proto_names(v), v.op == "!=")
                else:
                    set_family(fam)
                    i = generic_skip(i)
                continue

            if w == "meta":
                flush_unknown()
                if nxt in ("iifname", "iif", "oifname", "oif"):
                    w = nxt
                    i += 1  # handled by the interface branch below
                elif nxt == "mark":
                    if i + 2 < n and toks[i + 2].text.lower() == "set":
                        val, i = read_free(i + 3)
                        actions.append({"action": "mark-packet", "mark_value": val or None})
                    else:
                        v, i = self.operand(toks, i + 2)
                        if not bad(v, "mark"):
                            put("packet_mark", ",".join(v.items) or (v.ref or ""),
                                "negate_packet_mark", v.op == "!=")
                    continue
                elif nxt == "l4proto":
                    v, i = self.operand(toks, i + 2)
                    if not bad(v, "l4proto"):
                        set_proto(proto_names(v), v.op == "!=")
                    continue
                elif nxt == "nfproto":
                    v, i = self.operand(toks, i + 2)
                    item = v.items[0].lower() if v.items else ""
                    if not v.bad and v.op == "" and item in ("ipv4", "ip"):
                        set_family("ipv4")
                    elif not v.bad and v.op == "" and item in ("ipv6", "ip6"):
                        set_family("ipv6")
                    else:
                        warn(f"Unsupported nfproto matcher ignored: {v.op} {' '.join(v.items)}")
                    continue
                else:
                    i = generic_skip(i)
                    continue

            if w in ("iifname", "iif", "oifname", "oif"):
                flush_unknown()
                v, i = self.operand(toks, i + 1)
                if not bad(v, "interface"):
                    items = self.typed_set_items(v, "ifname", warn) if v.ref else v.items
                    if v.op not in ("", "!="):
                        warn("Comparison on interface is not supported")
                    elif items:
                        fld = "in_interface" if w.startswith("i") else "out_interface"
                        put(fld, ",".join(items), f"negate_{fld}", v.op == "!=")
                continue

            if w in L4_NAMES or w == "th":
                proto = w if w in L4_NAMES else None
                flush_unknown()
                if nxt in ("dport", "sport"):
                    i = ports(i + 2, proto, nxt[0])
                elif w == "tcp" and nxt == "flags":
                    set_proto(["tcp"])
                    i = tcp_flags(i + 2)
                elif w == "tcp" and nxt == "option" and \
                        [x.text.lower() for x in toks[i + 2:i + 5]] == ["maxseg", "size", "set"]:
                    val, i = read_free(i + 5)
                    actions.append({"action": "change-mss",
                                    "mark_value": "clamp-to-pmtu" if val.replace(" ", "") == "rtmtu"
                                    else (val or None)})
                else:
                    if proto:
                        set_proto([proto])
                    i = generic_skip(i)
                continue

            if w in ("icmp", "icmpv6"):
                flush_unknown()
                set_family("ipv4" if w == "icmp" else "ipv6")
                set_proto([w])
                i = generic_skip(i)
                continue

            if w == "ct":
                flush_unknown()
                if nxt == "state":
                    v, i = self.operand(toks, i + 2)
                    if not bad(v, "ct state"):
                        cond.connection_state = [x.lower() for x in v.items]
                        cond.negate_connection_state = v.op == "!="
                elif nxt == "status":
                    v, i = self.operand(toks, i + 2)
                    m = {"dnat": "dstnat", "snat": "srcnat"}
                    if not v.bad and len(v.items) == 1 and v.items[0].lower() in m \
                            and v.op in ("", "!="):
                        put("connection_nat_state", m[v.items[0].lower()],
                            "negate_connection_nat_state", v.op == "!=")
                    else:
                        warn("Unsupported ct status matcher ignored: " + " ".join(v.items))
                elif nxt == "mark" and i + 2 < n and toks[i + 2].text.lower() == "set":
                    val, i = read_free(i + 3)
                    actions.append({"action": "mark-connection", "mark_value": val or None})
                else:
                    i = generic_skip(i)
                continue

            if w == "mark" and nxt == "set":
                flush_unknown()
                val, i = read_free(i + 2)
                actions.append({"action": "mark-packet", "mark_value": val or None})
                continue

            if w == "limit":
                flush_unknown()
                val, i = read_free(i + 1)
                cond.limit = val or None
                continue

            if w == "counter":
                flush_unknown()
                i += 1
                while i + 1 < n and toks[i].kind == "w" and toks[i].text.lower() in ("packets", "bytes"):
                    i += 2
                continue

            if w == "comment":
                flush_unknown()
                if i + 1 < n:
                    state["comment"] = toks[i + 1].text
                i += 2
                continue

            if w == "log":
                flush_unknown()
                i += 1
                while i < n and toks[i].kind == "w":
                    k = toks[i].text.lower()
                    if k in ("prefix", "level", "group", "snaplen", "queue-threshold"):
                        i += 2
                    elif k == "flags":
                        i += 1
                        while i < n and (toks[i].kind == "," or
                                         (toks[i].kind == "w" and toks[i].text.lower() in LOG_FLAGS)):
                            i += 1
                    else:
                        break
                actions.append({"action": "log"})
                continue

            if w in ("accept", "drop", "return"):
                flush_unknown()
                actions.append({"action": w})
                i += 1
                continue

            if w == "continue":
                flush_unknown()
                i += 1
                continue

            if w == "reject":
                flush_unknown()
                i += 1
                if i < n and toks[i].text.lower() == "with":
                    i += 1
                    while i < n and toks[i].kind == "w" and toks[i].text.lower() not in STOP_WORDS:
                        i += 1
                actions.append({"action": "reject"})
                continue

            if w in ("jump", "goto"):
                flush_unknown()
                if i + 1 < n:
                    if w == "goto":
                        warn("goto treated as jump (control does not return to the caller in nftables)")
                    actions.append({"action": "jump", "target_chain": toks[i + 1].text})
                    i += 2
                else:
                    warn(f"{w} without target")
                    i += 1
                continue

            if w in ("dnat", "snat"):
                flush_unknown()
                i += 1
                if i < n and toks[i].text.lower() in ("ip", "ip6"):
                    set_family("ipv4" if toks[i].text.lower() == "ip" else "ipv6")
                    i += 1
                if i < n and toks[i].text.lower() == "to":
                    i += 1
                a = {"action": "dst-nat" if w == "dnat" else "src-nat"}
                if i < n and toks[i].kind == "w" and toks[i].text.lower() not in ("map", "numgen", "jhash"):
                    a["nat_to_addresses"], a["nat_to_ports"] = nat_target(toks[i].text)
                    i += 1
                else:
                    warn(f"{w} with unsupported target (map/numgen) - address not modelled")
                    i = n
                while i < n and toks[i].kind == "w" and toks[i].text.lower() in NAT_FLAGS:
                    i += 1
                actions.append(a)
                continue

            if w in ("masquerade", "redirect"):
                flush_unknown()
                i += 1
                a = {"action": w}
                if i < n and toks[i].text.lower() == "to":
                    i += 1
                    if i < n:
                        a["nat_to_ports"] = nat_target(toks[i].text)[1]
                        i += 1
                while i < n and toks[i].kind == "w" and toks[i].text.lower() in NAT_FLAGS:
                    i += 1
                actions.append(a)
                continue

            if w in ("add", "update", "delete") and nxt.startswith("@"):
                flush_unknown()
                name = toks[i + 1].text[1:]
                i += 2
                if i < n and toks[i].kind == "{":
                    j, depth, body = i + 1, 1, []
                    while j < n and depth:
                        depth += (toks[j].kind == "{") - (toks[j].kind == "}")
                        if depth:
                            body.append(toks[j])
                        j += 1
                    i = j
                    words = [b.text.lower() for b in body]
                    timeout = None
                    if "timeout" in words and words.index("timeout") + 1 < len(words):
                        timeout = body[words.index("timeout") + 1].text
                    if w != "delete" and words[:2] in (["ip", "saddr"], ["ip", "daddr"],
                                                       ["ip6", "saddr"], ["ip6", "daddr"]) \
                            and "." not in words:
                        set_family("ipv4" if words[0] == "ip" else "ipv6")
                        actions.append({
                            "action": "add-src-to-address-list" if words[1] == "saddr"
                            else "add-dst-to-address-list",
                            "address_list_target": name, "address_list_timeout": timeout})
                    else:
                        warn(f"Unsupported dynamic set statement ({w} @{name}) ignored")
                else:
                    warn(f"Unsupported set statement ({w} @{name}) ignored")
                continue

            if w in ("queue", "notrack", "tproxy", "fwd", "dup", "synproxy"):
                flush_unknown()
                warn(f"Statement '{w}' is not supported and was ignored")
                i += 1
                while i < n and toks[i].kind in ("w", "s") and \
                        not (toks[i].kind == "w" and toks[i].text.lower() in STOP_WORDS):
                    i += 1
                continue

            unknown.append(t.text)
            i += 1

        flush_unknown()
        if not actions:
            warn("No terminal verdict in this rule (modelled as passthrough)")
            actions.append({"action": "passthrough"})
        out = []
        for a in actions:
            out.append(dict(a, _family=state["family"], _cond=cond,
                            _warnings=list(warns), _comment=state["comment"]))
        return out


# ---------------------------------------------------------------------------
# Resolution of nft tables/chains into canonical (table, chain)
# ---------------------------------------------------------------------------

def _role_from_prio(prio: int) -> str:
    if prio >= 0:
        return "filter"
    if prio >= -150:
        return "mangle"
    return "raw"


def _nat_chain(hook: str) -> str:
    return {"prerouting": "dstnat", "postrouting": "srcnat"}.get(hook, hook)


def _base_target(ch: _Chain) -> Optional[Tuple[str, str]]:
    """(role, chain) for base chains, None for regular chains."""
    if ch.hook:
        if ch.hook not in HOOKS:
            return None
        if ch.ctype == "nat":
            return ("nat", _nat_chain(ch.hook))
        if ch.ctype == "route":
            return ("mangle", ch.hook)
        return (_role_from_prio(ch.prio), ch.hook)
    if ch.ctype is None and ch.name in HOOKS:
        # chain only known through 'add rule': infer the role from the nft table name
        tn = ch.table.name.lower()
        if tn == "nat":
            return ("nat", _nat_chain(ch.name))
        if tn in ("mangle", "raw"):
            return (tn, ch.name)
        return ("filter", ch.name)
    return None


def _jump_targets(ch: _Chain) -> List[str]:
    out = []
    for toks, _ in ch.rules:
        for k, t in enumerate(toks):
            if t.kind == "w" and t.text.lower() in ("jump", "goto") and k + 1 < len(toks):
                out.append(toks[k + 1].text)
    return out


def _copy_cond(c: RuleCondition) -> RuleCondition:
    return c.model_copy(deep=True) if hasattr(c, "model_copy") else c.copy(deep=True)


def parse_nftables(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList], List[str]]:
    """Full parse. Returns (rules, address_lists, global_warnings)."""
    st = _Structure(content)
    st.parse()
    rp = _RuleParser(st)

    chains: List[_Chain] = [c for tbl in st.tables.values() for c in tbl.chains.values()]
    chains.sort(key=lambda c: c.idx)

    for ch in chains:
        ch.target = _base_target(ch)
        if ch.hook and ch.target is None:
            st.warnings.append(f"Chain '{ch.name}' uses unsupported hook '{ch.hook}' and was ignored")
    # regular chains inherit the role of the chains that jump to them
    changed = True
    while changed:
        changed = False
        for ch in chains:
            if ch.target is None:
                continue
            for tgt in _jump_targets(ch):
                other = ch.table.chains.get(tgt)
                if other is not None and other.target is None and not other.hook:
                    other.target = (ch.target[0], other.name)
                    changed = True
    for ch in chains:
        if ch.target is None and not ch.hook:
            ch.target = ("filter", ch.name)

    # sets: address-typed (or untyped) become address lists; others are expanded on use
    address_lists: Dict[str, AddressList] = {}
    for si in st.sets.values():
        if " . " in si.type or "." in si.type.split():
            st.warnings.append(f"Set '{si.name}' has concatenated type '{si.type}'; not modelled")
            continue
        if si.type and si.type not in ("ipv4_addr", "ipv6_addr"):
            continue
        al = address_lists.setdefault(si.name, AddressList(name=si.name, entries=[]))
        for el, cm in si.elements:
            al.entries.append(AddressListEntry(id=str(uuid.uuid4())[:8], address=el, comment=cm))

    # keep chains of the same target together, ordered by hook priority
    first_idx: Dict[Tuple[str, str], int] = {}
    for ch in chains:
        if ch.target and ch.target not in first_idx:
            first_idx[ch.target] = ch.idx
    units = [c for c in chains if c.target]
    units.sort(key=lambda c: (first_idx[c.target], c.prio if c.hook else 0, c.idx))

    roles_of: Dict[str, set] = {}
    for c in units:
        if not c.hook and c.name not in HOOKS:
            roles_of.setdefault(c.name, set()).add(c.target[0])

    rules: List[FirewallRule] = []
    order = 1
    for ch in units:
        role, cname = ch.target
        tfam = {"ip": "ipv4", "ip6": "ipv6"}.get(ch.table.family)
        for toks, raw in ch.rules:
            for a in rp.run(toks, tfam):
                warns = a.pop("_warnings")
                cond = a.pop("_cond")
                comment = a.pop("_comment")
                fam = a.pop("_family")
                if len(roles_of.get(ch.name, ())) > 1:
                    warns.append(f"Chain '{ch.name}' is reachable from several tables; placed in '{role}'")
                rules.append(FirewallRule(
                    id=str(order), order=order, table=role, chain=cname, family=fam,
                    parse_warnings=warns, conditions=_copy_cond(cond), comment=comment,
                    raw_syntax=raw, **a))
                order += 1
        if ch.hook and ch.policy in ("accept", "drop"):
            rules.append(FirewallRule(
                id=str(order), order=order, table=role, chain=cname, family=tfam,
                is_policy=True, action=ch.policy, raw_syntax=f"policy {ch.policy};"))
            order += 1
    return rules, address_lists, st.warnings


def parse_nftables_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """Parses nftables configuration syntax (blocks and one-line commands)."""
    rules, lists, _warnings = parse_nftables(content)
    return rules, lists
