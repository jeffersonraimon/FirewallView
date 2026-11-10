import re
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def merge_multiline_routeros(content: str) -> List[str]:
    """
    Handles RouterOS multiline export lines with trailing backslash (\\).
    Concatenates continuations properly, respecting '=' bindings.
    """
    merged: List[str] = []
    buffer = ""
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line:
            if buffer.strip():
                merged.append(buffer.strip())
                buffer = ""
            continue

        is_continuation = line.endswith("\\")
        clean_content = line[:-1].rstrip() if is_continuation else line.strip()

        if buffer.endswith("="):
            buffer += clean_content.lstrip()
        else:
            buffer = (buffer + " " + clean_content).strip() if buffer else clean_content

        if not is_continuation:
            if buffer.strip():
                merged.append(buffer.strip())
            buffer = ""

    if buffer.strip():
        merged.append(buffer.strip())
    return merged


_UNESCAPES = {"n": "\n", "r": "\r", "t": "\t", "_": " ", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}


def _unescape(raw: str) -> str:
    """Resolves RouterOS backslash escapes inside a quoted string (\\" \\\\ \\$ \\? \\n ...)."""
    out: List[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append(_UNESCAPES.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_routeros_line(line: str) -> Dict[str, str]:
    """
    Parses a single RouterOS command line into a dictionary of key-value pairs.
    Handles quoted values (including escaped quotes) and bare flags.
    """
    props: Dict[str, str] = {}
    n = len(line)
    i = 0
    while i < n:
        if line[i].isspace():
            i += 1
            continue
        j = i
        while j < n and not line[j].isspace() and line[j] != "=":
            j += 1
        key = line[i:j]
        if j < n and line[j] == "=":
            j += 1
            if j < n and line[j] == '"':
                k = j + 1
                while k < n and line[k] != '"':
                    k += 2 if line[k] == "\\" else 1
                value = _unescape(line[j + 1:k])
                j = min(k + 1, n)
            elif j < n and line[j] == "'":
                k = line.find("'", j + 1)
                k = n if k == -1 else k
                value = line[j + 1:k]
                j = min(k + 1, n)
            else:
                k = j
                while k < n and not line[k].isspace():
                    k += 1
                value = line[j:k]
                j = k
            if key:
                props[key.lower()] = value
        else:
            if key:
                props[key.lower()] = "true"
        i = max(j, i + 1)
    return props


_PRINT_START = re.compile(r"^(\d+)\s+((?:[A-Z]\s+)*)(.*)$")
_PRINT_MARK = "print-entry\t"


def _join_print_entries(content: str) -> str:
    """
    Terminal `print` output wraps long entries on indented continuation lines
    (and puts `;;; comment` on its own line). Folds each numbered entry into a
    single marker line: print-entry<TAB>flags<TAB>comment<TAB>body.
    """
    out: List[str] = []
    entry = None  # [flags, comment, parts]
    prev_cont = False

    def flush():
        nonlocal entry
        if entry is not None:
            out.append(f"{_PRINT_MARK}{entry[0]}\t{entry[1]}\t{' '.join(entry[2])}")
            entry = None

    for raw in content.splitlines():
        s = raw.strip()
        if prev_cont:
            out.append(raw)
            prev_cont = raw.rstrip().endswith("\\")
            continue
        m = _PRINT_START.match(s)
        if m:
            flush()
            rest = m.group(3).strip()
            comment = ""
            parts: List[str] = []
            if rest.startswith(";;;"):
                comment = rest[3:].strip()
            elif rest:
                parts.append(rest)
            entry = [re.sub(r"\s+", "", m.group(2)), comment, parts]
            continue
        if (entry is not None and s and raw[:1].isspace()
                and not s.startswith(("/", "#", "Flags:", "Columns:"))
                and not re.match(r"^add(\s|$)", s)):
            if s.startswith(";;;"):
                entry[1] = s[3:].strip()
            else:
                entry[2].append(s)
            continue
        flush()
        out.append(raw)
        prev_cont = raw.rstrip().endswith("\\")
    flush()
    return "\n".join(out)


_VERBS = {"add", "set", "remove", "print", "disable", "enable", "move", "comment", "find",
          "export", "get", "edit", "reset-counters", "reset-counters-all", "unset", "monitor"}
_MENU_KINDS = {"filter", "nat", "mangle", "raw", "address-list"}
_IGNORE = "ignore"
_BUILTIN_CHAINS = {"input", "forward", "output", "prerouting", "postrouting", "srcnat", "dstnat"}

# Properties consumed by the rule builder or harmless (not matchers).
_HANDLED = {
    "add", "chain", "action", "comment", "disabled", "jump-target", "to-addresses", "to-ports",
    "address-list", "address-list-timeout", "src-prefix", "dst-prefix",
    "new-packet-mark", "new-routing-mark", "new-connection-mark", "new-mss",
    "protocol", "src-address", "dst-address", "src-address-list", "dst-address-list",
    "src-port", "dst-port", "port", "in-interface", "in-interface-list", "out-interface",
    "out-interface-list", "connection-state", "connection-nat-state", "limit", "ipsec-policy",
    "tcp-flags", "packet-mark",
    # not matchers / runtime noise
    "log", "log-prefix", "passthrough", "place-before", "bytes", "packets", ".id", "dynamic",
    "invalid",
}
_ACTION_PARAMS = {"new-dscp", "new-ttl", "new-priority", "new-tcp-mss", "routing-table", "gateway",
                  "reject-with", "tarpit", "dscp-mark"}


def _neg(value: str):
    if value.startswith("!"):
        return True, value[1:]
    return False, value


def _neg_list(value: str, field: str, warnings: List[str]):
    """Parses flag-set values like connection-state / tcp-flags with `!` negation."""
    items = [s.strip() for s in value.split(",") if s.strip()]
    if not items:
        return False, []
    flagged = [s.startswith("!") for s in items]
    items = [s[1:] if s.startswith("!") else s for s in items]
    negate = all(flagged) or (flagged[0] and not any(flagged[1:]))
    if any(flagged) and not negate:
        warnings.append(f"mixed negation in {field}={value} approximated as non-negated")
    return negate, items


def _split_path(line: str):
    """Splits `/ip firewall filter add x=y` into (path_tokens, rest_tokens)."""
    tokens = line.split()
    path: List[str] = []
    idx = len(tokens)
    for i, tok in enumerate(tokens):
        if tok.lower() in _VERBS or "=" in tok or tok.startswith("["):
            idx = i
            break
        path.extend(t for t in tok.split("/") if t)
    return [p.lower() for p in path], tokens[idx:]


def _menu_from_path(path: List[str]):
    if len(path) == 3 and path[0] in ("ip", "ipv6") and path[1] == "firewall" and path[2] in _MENU_KINDS:
        return ("ipv6" if path[0] == "ipv6" else "ipv4", path[2])
    return _IGNORE


def _build_rule(props: Dict[str, str], menu, line: str, order: int, comment, disabled: bool) -> FirewallRule:
    warnings: List[str] = []
    family, table = menu if menu else (None, "filter")
    chain = props.get("chain", "")
    if menu is None:
        if chain.lower() in ("srcnat", "dstnat"):
            table = "nat"
        elif any(k.startswith("new-") for k in props) or props.get("action", "").lower() in ("snpt", "dnpt"):
            table = "mangle"
    if not chain:
        chain = "forward" if table == "filter" else ("srcnat" if table == "nat" else "prerouting")
    if chain.lower() in _BUILTIN_CHAINS:
        chain = chain.lower()
    action = props.get("action", "accept").lower()

    cond = RuleCondition()

    proto = props.get("protocol")
    if proto:
        cond.negate_protocol, proto = _neg(proto)
        proto_clean = re.sub(r"^\d+\s*\((.*?)\)$", r"\1", proto).strip().lower()
        proto_map = {"6": "tcp", "17": "udp", "1": "icmp", "47": "gre", "50": "esp"}
        cond.protocol = proto_map.get(proto_clean, proto_clean)

    for key, attr in (("src-address", "src_address"), ("dst-address", "dst_address"),
                      ("src-address-list", "src_address_list"), ("dst-address-list", "dst_address_list"),
                      ("src-port", "src_port"), ("dst-port", "dst_port"), ("port", "port")):
        val = props.get(key)
        if val:
            neg, val = _neg(val)
            setattr(cond, "negate_" + attr, neg)
            setattr(cond, attr, val)

    if (cond.port or cond.src_port or cond.dst_port) and (
            not cond.protocol or cond.negate_protocol
            or cond.protocol not in ("tcp", "udp", "udp-lite", "sctp", "dccp")):
        warnings.append("RouterOS rejects ports without protocol tcp/udp/udp-lite/sctp/dccp "
                        "(rule as written cannot be loaded)")

    for direction in ("in", "out"):
        iface = props.get(f"{direction}-interface")
        iface_list = props.get(f"{direction}-interface-list")
        if iface:
            neg, iface = _neg(iface)
            setattr(cond, f"negate_{direction}_interface", neg)
            setattr(cond, f"{direction}_interface", iface)
        if iface_list:
            neg, iface_list = _neg(iface_list)
            setattr(cond, f"negate_{direction}_interface_list", neg)
            setattr(cond, f"{direction}_interface_list", iface_list)

    if props.get("connection-state"):
        cond.negate_connection_state, cond.connection_state = _neg_list(
            props["connection-state"], "connection-state", warnings)

    if props.get("connection-nat-state"):
        cond.negate_connection_nat_state, cond.connection_nat_state = _neg(props["connection-nat-state"])

    for key, attr in (("limit", "limit"), ("ipsec-policy", "ipsec_policy")):
        val = props.get(key)
        if val:
            if val.startswith("!"):
                val = val[1:]
                warnings.append(f"negation of {key} ignored (rule matches more broadly)")
            setattr(cond, attr, val)

    if props.get("tcp-flags"):
        cond.negate_tcp_flags, cond.tcp_flags = _neg_list(props["tcp-flags"], "tcp-flags", warnings)

    if props.get("packet-mark"):
        cond.negate_packet_mark, cond.packet_mark = _neg(props["packet-mark"])

    npt_src_prefix = props.get("src-prefix")
    npt_dst_prefix = props.get("dst-prefix")
    if action == "snpt" and npt_src_prefix and not cond.src_address:
        cond.src_address = npt_src_prefix
    elif action == "dnpt" and npt_src_prefix and not cond.dst_address:
        cond.dst_address = npt_src_prefix

    mark_keys = {
        "mark-packet": "new-packet-mark", "mark-routing": "new-routing-mark",
        "mark-connection": "new-connection-mark", "change-mss": "new-mss",
    }
    mark_value = props.get(mark_keys.get(action, ""))
    if mark_value is None:
        mark_value = (props.get("new-packet-mark") or props.get("new-routing-mark")
                      or props.get("new-connection-mark") or props.get("new-mss"))

    for key, val in props.items():
        if key in _HANDLED:
            continue
        if key in _ACTION_PARAMS or key.startswith("new-"):
            warnings.append(f"unsupported action parameter {key}={val} ignored")
        else:
            warnings.append(f"unsupported matcher {key}={val} ignored (rule matches more broadly)")

    return FirewallRule(
        id=str(order), order=order, table=table, chain=chain, family=family,
        action=action,
        target_chain=props.get("jump-target"),
        nat_to_addresses=props.get("to-addresses"),
        nat_to_ports=props.get("to-ports"),
        mark_value=mark_value,
        address_list_target=props.get("address-list"),
        address_list_timeout=props.get("address-list-timeout"),
        npt_src_prefix=npt_src_prefix,
        npt_dst_prefix=npt_dst_prefix,
        conditions=cond, comment=comment, disabled=disabled,
        parse_warnings=warnings, raw_syntax=line,
    )


def parse_routeros_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses RouterOS (v6 and v7) export, script, or terminal print content.
    Only /ip|/ipv6 firewall filter|nat|mangle|raw|address-list menus are read;
    `add` lines under any other menu are ignored. IPv4 and IPv6 address-lists
    with the same name are merged (AddressList has no family field).
    Returns (rules, address_lists).
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    menu = None  # None = no menu seen yet; _IGNORE = unrelated menu; else (family, kind)
    rule_order = 1
    pending_comment = None

    lines = merge_multiline_routeros(_join_print_entries(content))

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        flag_disabled = False
        if line_clean.startswith(_PRINT_MARK):
            parts = (line_clean.split("\t", 3) + ["", "", ""])[:4]
            flag_disabled = "X" in parts[1]
            if parts[2]:
                pending_comment = parts[2]
            line_clean = "add " + parts[3].strip()
        elif line_clean.startswith(";;;"):
            pending_comment = line_clean[3:].strip()
            continue
        elif line_clean.startswith("#"):
            c_text = line_clean[1:].strip()
            # Ignore standard RouterOS export date headers like "# mar/21/2026 12:00:00 by RouterOS"
            if c_text and not re.match(r"^[a-zA-Z]{3}/\d{2}/\d{4}", c_text):
                pending_comment = c_text
            continue
        elif line_clean.startswith("Flags:") or line_clean.startswith("Columns:"):
            continue

        # Menu path (header or full-path one-liner)
        if line_clean.startswith("/"):
            path, rest = _split_path(line_clean)
            menu = _menu_from_path(path)
            pending_comment = None
            if not rest:
                continue
            line_clean = " ".join(rest)

        if not re.match(r"^add(\s|$)", line_clean, re.IGNORECASE):
            continue

        props = parse_routeros_line(line_clean)
        comment = props.get("comment") or pending_comment
        pending_comment = None
        disabled = flag_disabled or props.get("disabled", "").lower() in ("yes", "true")

        if menu == _IGNORE:
            continue

        is_list_menu = menu is not None and menu[1] == "address-list"
        if is_list_menu or (menu is None and "list" in props and "address" in props):
            list_name = props.get("list")
            address = props.get("address")
            if list_name and address:
                if list_name not in address_lists:
                    address_lists[list_name] = AddressList(name=list_name, entries=[])
                address_lists[list_name].entries.append(
                    AddressListEntry(id=str(uuid.uuid4())[:8], address=address,
                                     comment=comment, disabled=disabled))
            continue

        if menu is None and "chain" not in props:
            continue

        rules.append(_build_rule(props, menu, line_clean, rule_order, comment, disabled))
        rule_order += 1

    return rules, address_lists
