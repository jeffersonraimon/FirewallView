import re
import ipaddress
import uuid
from typing import Dict, List, Tuple, Optional
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

# Well-known IOS port names -> numbers (IOS prints/accepts these in "eq www").
CISCO_PORT_NAMES: Dict[str, int] = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "tacacs": 49,
    "domain": 53, "bootps": 67, "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79,
    "www": 80, "http": 80, "kerberos": 88, "pop2": 109, "pop3": 110, "sunrpc": 111,
    "ident": 113, "nntp": 119, "ntp": 123, "msrpc": 135, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ss": 139, "imap4": 143, "imap": 143, "snmp": 161,
    "snmptrap": 162, "bgp": 179, "irc": 194, "ldap": 389, "https": 443, "isakmp": 500,
    "exec": 512, "login": 513, "cmd": 514, "syslog": 514, "lpd": 515, "talk": 517,
    "rip": 520, "ldaps": 636, "nfs": 2049, "h323": 1720, "pptp": 1723,
    "radius": 1812, "radius-acct": 1813, "sip": 5060, "non500-isakmp": 4500,
    "pim-auto-rp": 496, "ftps": 990, "imaps": 993, "pop3s": 995,
}

# Numeric IP protocol -> name
CISCO_PROTO_NUMBERS: Dict[str, str] = {
    "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah",
    "58": "icmpv6", "89": "ospf", "103": "pim", "132": "sctp",
}

_QUAD = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_QUAD_CIDR = re.compile(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$")


def _is_addr_token(t: str) -> bool:
    return bool(_QUAD_CIDR.match(t)) or (":" in t and re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", t) is not None)


def _mask_net(ip_str: str, mask_str: str) -> Optional[str]:
    """IPv4 ip + Cisco wildcard (or ASA-style netmask) -> CIDR string.

    Returns None for /0 (any). Single host -> bare IP. Raises ValueError when the
    mask is not contiguous (e.g. 0.0.255.0)."""
    m = int(ipaddress.IPv4Address(mask_str))
    full = 0xFFFFFFFF
    if (m + 1) & m == 0:  # contiguous wildcard 0..01..1
        prefix = 32 - m.bit_length()
    else:
        inv = full ^ m
        if (inv + 1) & inv == 0:  # contiguous netmask 1..10..0 (ASA style)
            prefix = 32 - inv.bit_length()
        else:
            raise ValueError("non-contiguous mask")
    if prefix == 0:
        return None
    net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
    return str(net.network_address) if prefix == 32 else str(net)


def wildcard_to_cidr(ip_str: str, wildcard_str: str) -> str:
    """Converts Cisco wildcard mask (e.g. 0.0.0.255) to CIDR notation."""
    try:
        r = _mask_net(ip_str, wildcard_str)
        return r if r is not None else "0.0.0.0/0"
    except Exception:
        return f"{ip_str}/{wildcard_str}"


def _cidr_token(t: str) -> Optional[str]:
    """NX-OS style prefix / bare address -> normalised address (None = any)."""
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            if net.prefixlen == 0:
                return None
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
            return str(net)
        return str(ipaddress.ip_address(t))
    except ValueError:
        return t


def _resolve_port(tok: str, warnings: List[str]) -> str:
    t = tok.lower()
    if t.isdigit():
        return t
    if t in CISCO_PORT_NAMES:
        return str(CISCO_PORT_NAMES[t])
    warnings.append(f"Unknown port name '{tok}' kept as-is")
    return tok


def _is_port_tok(tok: str) -> bool:
    t = tok.lower()
    return t.isdigit() or t in CISCO_PORT_NAMES


def _parse_ports(tokens: List[str], i: int, warnings: List[str]) -> Tuple[Optional[str], bool, int]:
    """Parses an optional port operator at tokens[i]. Returns (spec, negate, new_i)."""
    if i >= len(tokens):
        return None, False, i
    op = tokens[i].lower()
    if op in ("eq", "neq"):
        if i + 1 >= len(tokens):
            warnings.append(f"Port operator '{op}' without value")
            return None, False, i + 1
        vals = [_resolve_port(tokens[i + 1], warnings)]
        j = i + 2
        while j < len(tokens) and _is_port_tok(tokens[j]):
            vals.append(_resolve_port(tokens[j], warnings))
            j += 1
        return ",".join(vals), op == "neq", j
    if op in ("gt", "lt"):
        if i + 1 >= len(tokens):
            warnings.append(f"Port operator '{op}' without value")
            return None, False, i + 1
        v = _resolve_port(tokens[i + 1], warnings)
        if not v.isdigit():
            return None, False, i + 2
        n = int(v)
        if op == "gt":
            return f"{n + 1}-65535", False, i + 2
        return f"0-{max(n - 1, 0)}", False, i + 2
    if op == "range":
        if i + 2 >= len(tokens):
            warnings.append("Port operator 'range' needs two values")
            return None, False, len(tokens)
        a = _resolve_port(tokens[i + 1], warnings)
        b = _resolve_port(tokens[i + 2], warnings)
        return f"{a}-{b}", False, i + 3
    if op == "port-group":
        warnings.append("port-group (object-group service) is not supported; port match ignored")
        return None, False, i + 2
    return None, False, i


def _parse_addr(tokens: List[str], i: int, warnings: List[str]):
    """Returns (address, address_list, ok, new_i). address None + list None = any."""
    if i >= len(tokens):
        return None, None, False, i
    t = tokens[i].lower()
    if t in ("any", "any4", "any6"):
        return None, None, True, i + 1
    if t == "host" and i + 1 < len(tokens):
        return _cidr_token(tokens[i + 1]), None, True, i + 2
    if t in ("object-group", "addrgroup") and i + 1 < len(tokens):
        return None, tokens[i + 1], True, i + 2
    if _is_addr_token(tokens[i]):
        if _QUAD.match(tokens[i]) and i + 1 < len(tokens) and _QUAD.match(tokens[i + 1]):
            try:
                return _mask_net(tokens[i], tokens[i + 1]), None, True, i + 2
            except ValueError:
                warnings.append(
                    f"Non-contiguous wildcard mask '{tokens[i]} {tokens[i + 1]}' cannot be "
                    "represented; address match dropped (rule is broader than the original)")
                return None, None, True, i + 2
        return _cidr_token(tokens[i]), None, True, i + 1
    return None, None, False, i


def _parse_entry(tokens: List[str], standard: bool):
    """tokens start at permit/deny. Returns (action, cond, warnings)."""
    warnings: List[str] = []
    action = "accept" if tokens[0].lower() == "permit" else "drop"
    idx = 1
    cond = RuleCondition()

    if standard:
        addr, grp, ok, idx = _parse_addr(tokens, idx, warnings)
        if not ok:
            warnings.append(f"Could not parse standard ACL source at '{' '.join(tokens[idx:])}'")
            return action, cond, warnings
        cond.src_address = addr
        cond.src_address_list = grp
    else:
        if idx >= len(tokens):
            return action, cond, warnings
        proto = tokens[idx].lower()
        idx += 1
        proto = CISCO_PROTO_NUMBERS.get(proto, proto)
        if proto == "object-group":
            warnings.append("Protocol/service object-group is not supported; treated as any protocol")
            idx += 1
            proto = "ip"
        if proto not in ("ip", "ipv6", "any"):
            cond.protocol = "icmp" if proto == "icmpv6" else proto
        has_ports = proto in ("tcp", "udp", "sctp")

        addr, grp, ok, idx = _parse_addr(tokens, idx, warnings)
        if not ok:
            warnings.append(f"Could not parse source address at '{' '.join(tokens[idx:])}'")
            return action, cond, warnings
        cond.src_address, cond.src_address_list = addr, grp
        spec, neg, idx = _parse_ports(tokens, idx, warnings)
        if spec:
            cond.src_port, cond.negate_src_port = spec, neg
            if not has_ports:
                warnings.append("Port match on a non tcp/udp protocol")

        addr, grp, ok, idx = _parse_addr(tokens, idx, warnings)
        if not ok:
            warnings.append(f"Could not parse destination address at '{' '.join(tokens[idx:])}'")
            return action, cond, warnings
        cond.dst_address, cond.dst_address_list = addr, grp
        spec, neg, idx = _parse_ports(tokens, idx, warnings)
        if spec:
            cond.dst_port, cond.negate_dst_port = spec, neg
            if not has_ports:
                warnings.append("Port match on a non tcp/udp protocol")

    leftovers: List[str] = []
    while idx < len(tokens):
        t = tokens[idx].lower()
        if t in ("log", "log-input"):
            pass
        elif t == "established":
            cond.connection_state = ["established"]
            warnings.append("'established' approximated as connection_state=established "
                            "(Cisco matches TCP segments with ACK or RST set)")
        else:
            leftovers.append(tokens[idx])
        idx += 1
    if leftovers:
        warnings.append("Unsupported options ignored: " + " ".join(leftovers))
    return action, cond, warnings


def _is_standard_number(n: int) -> bool:
    return 1 <= n <= 99 or 1300 <= n <= 1999


def _obj_entry(tokens: List[str], lst: AddressList, groups_ref: List[str]) -> bool:
    """Handles one member line of an object-group network. Returns True if recognised."""
    t = list(tokens)
    if t and t[0].isdigit():  # NX-OS sequence number
        t = t[1:]
    if t and t[0] == "network-object":
        t = t[1:]
    if not t:
        return False
    head = t[0].lower()
    addr: Optional[str] = None
    if head == "group-object" and len(t) >= 2:
        groups_ref.append(t[1])
        return True
    if head == "host" and len(t) >= 2:
        addr = t[1]
    elif head == "range" and len(t) >= 3:
        addr = f"{t[1]}-{t[2]}"
    elif _QUAD.match(t[0]) and len(t) >= 2 and _QUAD.match(t[1]):
        try:
            addr = str(ipaddress.IPv4Network(f"{t[0]}/{t[1]}", strict=False))
        except ValueError:
            try:
                addr = _mask_net(t[0], t[1]) or "0.0.0.0/0"
            except ValueError:
                addr = t[0]
    elif _is_addr_token(t[0]):
        addr = _cidr_token(t[0])
    if addr is None:
        return False
    lst.entries.append(AddressListEntry(id=str(uuid.uuid4())[:8], address=addr))
    return True


def parse_cisco_acl(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """Parses Cisco IOS/NX-OS/ASA-ish ACLs & object-groups.

    Supported: named (`ip access-list [standard|extended] N`, `ipv6 access-list N`, with or
    without sequence numbers), numbered (`access-list 101 ...`; 1-99/1300-1999 standard),
    remarks (become the comment of the next entry), host/any/wildcard/CIDR/IPv6 addresses,
    object-group/addrgroup, port operators eq/neq/gt/lt/range with named ports, established.

    Conventions:
    - chain = ACL name (numbered ACLs: `acl_<n>`), table filter, family ipv4/ipv6.
    - Every ACL gets a trailing is_policy drop rule (comment "implicit deny").
    - `ip access-group NAME in|out` / `ipv6 traffic-filter` under an interface is recorded as
      a parse_warning on that ACL's implicit-deny rule (interface binding is not modelled).
    - Entries are ordered by sequence number when given.
    """
    address_lists: Dict[str, AddressList] = {}
    group_refs: Dict[str, List[str]] = {}
    acls: Dict[str, dict] = {}
    bindings: Dict[str, List[str]] = {}

    cur: Optional[dict] = None
    cur_group: Optional[AddressList] = None
    cur_iface: Optional[str] = None
    pending_remark: Optional[str] = None

    def get_acl(name: str, family: str, standard: bool) -> dict:
        a = acls.get(name)
        if a is None:
            a = {"name": name, "family": family, "standard": standard, "entries": [], "last_seq": 0}
            acls[name] = a
        return a

    def add_entry(acl: dict, seq: Optional[int], toks: List[str], raw: str):
        nonlocal pending_remark
        if toks[0].lower() == "remark":
            pending_remark = " ".join(toks[1:]) or None
            return
        action, cond, warns = _parse_entry(toks, acl["standard"])
        if seq is None:
            seq = acl["last_seq"] + 10
        acl["last_seq"] = max(acl["last_seq"], seq)
        acl["entries"].append((seq, len(acl["entries"]), action, cond, warns, pending_remark, raw))
        pending_remark = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        tokens = stripped.split()
        low0 = tokens[0].lower()
        indented = line[:1] in (" ", "\t")

        # --- object groups -------------------------------------------------
        m = re.match(r"^object-group\s+(?:network|ip\s+address|ipv6\s+address)\s+(\S+)", stripped, re.I)
        if m:
            name = m.group(1)
            cur_group = address_lists.setdefault(name, AddressList(name=name, entries=[]))
            group_refs.setdefault(name, [])
            cur, cur_iface = None, None
            continue
        if cur_group is not None:
            if low0 == "description":
                continue
            if (indented or low0 in ("network-object", "group-object")) and \
                    _obj_entry(tokens, cur_group, group_refs[cur_group.name]):
                continue
            if indented:
                continue
            cur_group = None

        # --- interface bindings ---------------------------------------------
        if low0 == "interface" and len(tokens) >= 2:
            cur_iface = tokens[1]
            cur = None
            continue
        if cur_iface and len(tokens) >= 4 and (
            (low0 == "ip" and tokens[1].lower() == "access-group") or
            (low0 == "ipv6" and tokens[1].lower() == "traffic-filter")
        ):
            bindings.setdefault(tokens[2], []).append(f"{cur_iface} {tokens[3].lower()}")
            continue

        # --- ACL headers -----------------------------------------------------
        if low0 in ("ip", "ipv6") and len(tokens) >= 3 and tokens[1].lower() == "access-list":
            family = "ipv6" if low0 == "ipv6" else "ipv4"
            rest = tokens[2:]
            standard = False
            if rest[0].lower() in ("standard", "extended") and len(rest) >= 2:
                standard = rest[0].lower() == "standard"
                rest = rest[1:]
            elif rest[0].lower() in ("resequence", "log-update", "logging"):
                continue
            cur = get_acl(rest[0], family, standard)
            cur_iface = None
            pending_remark = None
            continue

        # --- numbered / ASA "access-list" ----------------------------------------
        if low0 == "access-list" and len(tokens) >= 3:
            name = tokens[1]
            idx = 2
            standard = False
            if name.isdigit():
                standard = _is_standard_number(int(name))
                name = f"acl_{name}"
            else:
                if tokens[idx].lower() == "line" and idx + 2 < len(tokens):
                    idx += 2
                if tokens[idx].lower() in ("extended", "standard") and idx + 1 < len(tokens):
                    standard = tokens[idx].lower() == "standard"
                    idx += 1
            body = tokens[idx:]
            if body and body[0].lower() in ("permit", "deny", "remark"):
                add_entry(get_acl(name, "ipv4", standard), None, body, stripped)
            continue

        # --- entries inside a named ACL ------------------------------------------
        if cur is not None:
            seq = None
            body = tokens
            if tokens[0].isdigit() and len(tokens) >= 2:
                seq = int(tokens[0])
                body = tokens[1:]
            if body[0].lower() in ("permit", "deny", "remark"):
                add_entry(cur, seq, body, stripped)
                continue

        if not indented:
            cur = None

    # flatten group-object references (no cycles)
    def expand(name: str, seen: set):
        for ref in group_refs.get(name, []):
            if ref in seen or ref not in address_lists:
                continue
            seen.add(ref)
            expand(ref, seen)
            have = {e.address for e in address_lists[name].entries}
            for e in address_lists[ref].entries:
                if e.address not in have:
                    address_lists[name].entries.append(AddressListEntry(id=str(uuid.uuid4())[:8], address=e.address))
    for gname in list(group_refs):
        expand(gname, {gname})

    rules: List[FirewallRule] = []
    order = 1
    for name, acl in acls.items():
        fam = acl["family"]
        for seq, _i, action, cond, warns, remark, raw in sorted(acl["entries"], key=lambda e: (e[0], e[1])):
            rules.append(FirewallRule(
                id=str(order), order=order, table="filter", chain=name, family=fam,
                action=action, conditions=cond, comment=remark, parse_warnings=warns,
                raw_syntax=raw,
            ))
            order += 1
        pol_warn = [f"ACL applied via access-group on interface {b}" for b in bindings.get(name, [])]
        rules.append(FirewallRule(
            id=str(order), order=order, table="filter", chain=name, family=fam,
            is_policy=True, action="drop", comment="implicit deny", parse_warnings=pol_warn,
        ))
        order += 1

    return rules, address_lists
