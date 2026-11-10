import re
import shlex
import uuid
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

BUILTIN_CHAINS = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

# Targets understood natively (iptables targets are case sensitive).
SIMPLE_TARGETS = {
    "ACCEPT": "accept", "DROP": "drop", "REJECT": "reject", "RETURN": "return",
    "MASQUERADE": "masquerade", "DNAT": "dst-nat", "SNAT": "src-nat",
    "REDIRECT": "redirect", "NETMAP": "netmap", "LOG": "log", "NFLOG": "log",
    "MARK": "mark-packet", "CONNMARK": "mark-connection", "TCPMSS": "change-mss",
    "SET": "set", "SNPT": "snpt", "DNPT": "dnpt",
}
# Known extension targets we cannot model (everything else is a user chain).
UNSUPPORTED_TARGETS = {
    "TOS", "DSCP", "TTL", "HL", "NFQUEUE", "ULOG", "CT", "TPROXY", "CLASSIFY",
    "AUDIT", "TRACE", "NOTRACK", "SECMARK", "CONNSECMARK", "CHECKSUM", "TEE",
    "SYNPROXY", "RATEEST", "IDLETIMER", "LED", "QUEUE", "DELUDE", "TARPIT",
}
KNOWN_MODULES = {
    "tcp", "udp", "icmp", "icmp6", "sctp", "multiport", "conntrack", "state",
    "mark", "set", "comment", "limit", "policy", "iprange",
}
# Options that carry an argument we deliberately ignore (target cosmetics).
IGNORED_ARG1 = {
    "--log-prefix", "--log-level", "--reject-with", "--nflog-group",
    "--nflog-prefix", "--nflog-range", "--nflog-threshold", "--nfmask", "--ctmask",
}
IGNORED_FLAGS = {
    "--random", "--random-fully", "--fully-random", "--persistent", "--exist",
    "--log-tcp-sequence", "--log-tcp-options", "--log-ip-options", "--log-uid",
    "--line-numbers", "-v", "-n", "-x", "--verbose", "--numeric", "--wait", "-w",
}
MGMT_OPTS = {
    "-N", "--new-chain", "-X", "--delete-chain", "-F", "--flush", "-Z", "--zero",
    "-E", "--rename-chain", "-D", "--delete", "-R", "--replace", "-L", "--list",
    "-S", "--list-rules", "-C", "--check",
}
PROTO_NUMBERS = {
    "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
    "51": "ah", "58": "icmpv6", "132": "sctp",
}
ALL_FLAGS = ["syn", "ack", "fin", "rst", "psh", "urg"]

ADDR_OPTS = {
    "-s": ("src_address", "negate_src_address"), "--source": ("src_address", "negate_src_address"),
    "--src": ("src_address", "negate_src_address"),
    "-d": ("dst_address", "negate_dst_address"), "--destination": ("dst_address", "negate_dst_address"),
    "--dst": ("dst_address", "negate_dst_address"),
    "-i": ("in_interface", "negate_in_interface"), "--in-interface": ("in_interface", "negate_in_interface"),
    "-o": ("out_interface", "negate_out_interface"), "--out-interface": ("out_interface", "negate_out_interface"),
}
PORT_OPTS = {
    "--dport": ("dst_port", "negate_dst_port"), "--destination-port": ("dst_port", "negate_dst_port"),
    "--dports": ("dst_port", "negate_dst_port"), "--destination-ports": ("dst_port", "negate_dst_port"),
    "--sport": ("src_port", "negate_src_port"), "--source-port": ("src_port", "negate_src_port"),
    "--sports": ("src_port", "negate_src_port"), "--source-ports": ("src_port", "negate_src_port"),
    "--ports": ("port", "negate_port"),
}


def normalize_chain(table: str, chain: str) -> str:
    if chain in BUILTIN_CHAINS:
        low = chain.lower()
        if table == "nat":
            if low == "prerouting":
                return "dstnat"
            if low == "postrouting":
                return "srcnat"
        return low
    return chain


def split_nat_target(val: str) -> Tuple[Optional[str], Optional[str]]:
    """Split `[addr[-addr]][:port[-port]]`, handling IPv6 brackets."""
    port = None
    if "]" in val:
        idx = val.rfind("]")
        addr = val[:idx + 1]
        rest = val[idx + 1:]
        if rest.startswith(":"):
            port = rest[1:]
        addr = addr.replace("[", "").replace("]", "")
    elif val.count(":") == 1:
        addr, port = val.split(":", 1)
    else:
        addr = val
    return (addr or None), (port.replace(":", "-") if port else None)


def _flags_from(s: str) -> List[str]:
    out: List[str] = []
    for f in s.lower().split(","):
        f = f.strip()
        if f == "all":
            out.extend(ALL_FLAGS)
        elif f == "none" or not f:
            continue
        else:
            out.append(f)
    return out


def _tcp_flags(mask: str, comp: str) -> List[str]:
    m = _flags_from(mask)
    c = _flags_from(comp)
    res = list(c)
    res.extend("!" + f for f in m if f not in c)
    return res


def parse_iptables_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses standard iptables/ip6tables commands, iptables-save dumps and ipset commands.
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    current_table = "filter"
    default_family = "ipv4"

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if "ip6tables-save" in line:
                default_family = "ipv6"
            elif "iptables-save" in line:
                default_family = "ipv4"
            continue

        if line.startswith("ipset "):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "create":
                set_name = parts[2]
                if set_name not in address_lists:
                    address_lists[set_name] = AddressList(name=set_name, entries=[])
            elif len(parts) >= 4 and parts[1] == "add":
                set_name = parts[2]
                if set_name not in address_lists:
                    address_lists[set_name] = AddressList(name=set_name, entries=[])
                address_lists[set_name].entries.append(
                    AddressListEntry(id=str(uuid.uuid4())[:8], address=parts[3])
                )
            continue

        if line.startswith("*"):
            current_table = line[1:].strip().lower()
            continue
        if line == "COMMIT":
            continue

        # ":INPUT DROP [0:0]" policy / ":MYCHAIN - [0:0]" chain declaration
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2 and parts[1].upper() in ("ACCEPT", "DROP"):
                rules.append(FirewallRule(
                    id="0", table=current_table,
                    chain=normalize_chain(current_table, parts[0]),
                    family=default_family, is_policy=True,
                    action=parts[1].lower(), raw_syntax=line,
                ))
            continue

        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            tokens = line.split()
        if not tokens:
            continue

        family = default_family
        if tokens[0] == "sudo":
            tokens = tokens[1:]
        if tokens and re.match(r"^ip6tables(-legacy|-nft)?$", tokens[0]):
            family = "ipv6"
            tokens = tokens[1:]
        elif tokens and re.match(r"^iptables(-legacy|-nft)?$", tokens[0]):
            family = "ipv4"
            tokens = tokens[1:]
        elif not tokens[0].startswith("-"):
            continue  # shell glue (set -e, shebang, echo, ...)
        if not tokens or not tokens[0].startswith("-"):
            continue

        parsed = _parse_command(tokens, line, current_table, family)
        if parsed is not None:
            new_rule, insert_pos = parsed
            _place(rules, new_rule, insert_pos)

    for idx, r in enumerate(rules, start=1):
        r.order = idx
        r.id = str(idx)
    return rules, address_lists


def _place(rules: List[FirewallRule], new_rule: FirewallRule, pos: Optional[int]) -> None:
    if pos is None:
        rules.append(new_rule)
        return
    idxs = [i for i, r in enumerate(rules)
            if not r.is_policy and r.table == new_rule.table
            and r.chain == new_rule.chain and r.family == new_rule.family]
    if not idxs:
        rules.append(new_rule)
    elif pos - 1 < len(idxs):
        rules.insert(idxs[max(pos - 1, 0)], new_rule)
    else:
        rules.insert(idxs[-1] + 1, new_rule)


def _parse_command(tokens: List[str], line: str, table: str, family: str):
    chain: Optional[str] = None
    insert_pos: Optional[int] = None
    policy: Optional[str] = None
    is_policy = False
    appended = False
    target: Optional[str] = None
    goto = False
    warns: List[str] = []

    def warn(msg: str):
        if msg not in warns:
            warns.append(msg)

    nat_addr = nat_ports = None
    mark_val: Optional[str] = None
    mss: Optional[str] = None
    netmap_to: Optional[str] = None
    add_set: Optional[Tuple[str, str]] = None
    set_timeout: Optional[str] = None
    src_pfx = dst_pfx = None
    comment = None
    limit_rate = limit_burst = None
    pol_dir = pol_pol = None
    cond = RuleCondition()
    range_set: set = set()

    n = len(tokens)
    i = 0
    negate = False

    def arg(j: int, neg: bool) -> Tuple[Optional[str], bool, int]:
        """Read option argument at j, honouring the legacy `opt ! value` form."""
        if j < n and tokens[j] == "!":
            neg = True
            j += 1
        if j >= n:
            return None, neg, j
        return tokens[j], neg, j + 1

    # table must be known before chain normalisation: pre-scan for -t
    for k, t in enumerate(tokens):
        if t in ("-t", "--table") and k + 1 < n:
            table = tokens[k + 1].lower()

    while i < n:
        tok = tokens[i]
        if tok == "!":
            negate = True
            i += 1
            continue
        if tok in ("-t", "--table"):
            i += 2
            continue
        if tok in MGMT_OPTS:
            return None
        if tok in ("-A", "--append", "-I", "--insert", "-P", "--policy"):
            if i + 1 >= n:
                return None
            chain = tokens[i + 1]
            i += 2
            if tok in ("-P", "--policy"):
                is_policy = True
                if i < n:
                    policy = tokens[i]
                    i += 1
            else:
                appended = True
                if tok in ("-I", "--insert"):
                    if i < n and tokens[i].isdigit():
                        insert_pos = int(tokens[i])
                        i += 1
                    else:
                        insert_pos = 1
            continue
        if tok in ("-j", "--jump", "-g", "--goto"):
            if i + 1 < n:
                target = tokens[i + 1]
                if tok in ("-g", "--goto"):
                    goto = True
                i += 2
            else:
                i += 1
            negate = False
            continue
        if tok in ("-m", "--match"):
            if i + 1 < n:
                mod = tokens[i + 1]
                if mod not in KNOWN_MODULES:
                    warn(f"unsupported match module '{mod}' (rule may match more traffic than the original)")
                i += 2
            else:
                i += 1
            continue
        if tok in ("-p", "--protocol"):
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                v = v.lower()
                v = PROTO_NUMBERS.get(v, v)
                if v != "all":
                    cond.protocol = v
                    cond.negate_protocol = neg
            negate = False
            continue
        if tok in ADDR_OPTS:
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                fld = ADDR_OPTS[tok][0]
                if fld in ("in_interface", "out_interface") and v.endswith("+"):
                    v = v[:-1] + "*"   # iptables wildcard -> matcher wildcard
                if fld in range_set:
                    warn(f"{tok} combined with iprange on the same side; kept the range only")
                else:
                    setattr(cond, fld, v)
                    setattr(cond, ADDR_OPTS[tok][1], neg)
            negate = False
            continue
        if tok in ("--src-range", "--dst-range"):
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                fld = "src_address" if tok == "--src-range" else "dst_address"
                if getattr(cond, fld):
                    warn(f"{tok} combined with -{fld[0]} on the same side; kept the earlier address match only")
                else:
                    setattr(cond, fld, v)
                    setattr(cond, "negate_" + fld, neg)
                    range_set.add(fld)
            negate = False
            continue
        if tok in PORT_OPTS:
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                setattr(cond, PORT_OPTS[tok][0], v.replace(":", "-"))
                setattr(cond, PORT_OPTS[tok][1], neg)
            negate = False
            continue
        if tok in ("--state", "--ctstate"):
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                states = [s.strip().lower() for s in v.split(",") if s.strip()]
                nat = [s for s in states if s in ("dnat", "snat")]
                rest = [s for s in states if s not in ("dnat", "snat")]
                if nat:
                    if len(nat) > 1:
                        warn("--ctstate DNAT,SNAT cannot be represented; NAT state ignored")
                    else:
                        cond.connection_nat_state = "dstnat" if nat[0] == "dnat" else "srcnat"
                        cond.negate_connection_nat_state = neg
                        if rest and not neg:
                            warn("--ctstate mixing DNAT/SNAT with other states is an OR; "
                                 "only the NAT state and the other states are ANDed (narrower)")
                if rest or not nat:
                    cond.connection_state = rest
                    cond.negate_connection_state = neg
            negate = False
            continue
        if tok == "--ctstatus":
            v, neg, i = arg(i + 1, negate)
            if v is not None and v.upper() in ("DNAT", "SNAT"):
                cond.connection_nat_state = "dstnat" if v.upper() == "DNAT" else "srcnat"
                cond.negate_connection_nat_state = neg
            else:
                warn(f"unsupported --ctstatus {v}")
            negate = False
            continue
        if tok == "--mark":
            v, neg, i = arg(i + 1, negate)
            if v is not None:
                cond.packet_mark = v
                cond.negate_packet_mark = neg
            negate = False
            continue
        if tok == "--tcp-flags":
            neg = negate
            if i + 1 < n and tokens[i + 1] == "!":
                neg = True
                i += 1
            if i + 2 < n:
                cond.tcp_flags = _tcp_flags(tokens[i + 1], tokens[i + 2])
                cond.negate_tcp_flags = neg
                i += 3
            else:
                i = n
            negate = False
            continue
        if tok == "--syn":
            cond.tcp_flags = _tcp_flags("SYN,RST,ACK,FIN", "SYN")
            cond.negate_tcp_flags = negate
            negate = False
            i += 1
            continue
        if tok == "--match-set":
            neg = negate
            j = i + 1
            if j < n and tokens[j] == "!":
                neg = True
                j += 1
            if j + 1 < n:
                set_name, direction = tokens[j], tokens[j + 1].lower()
                dirs = direction.split(",")
                if len(dirs) > 1 or dirs[0] not in ("src", "dst"):
                    warn(f"ipset match direction '{direction}' not representable; only the first part was used")
                if dirs[0].startswith("src"):
                    cond.src_address_list = set_name
                    cond.negate_src_address_list = neg
                elif dirs[0].startswith("dst"):
                    cond.dst_address_list = set_name
                    cond.negate_dst_address_list = neg
                i = j + 2
            else:
                i = n
            negate = False
            continue
        if tok == "--limit":
            limit_rate, _, i = arg(i + 1, False)
            continue
        if tok == "--limit-burst":
            limit_burst, _, i = arg(i + 1, False)
            continue
        if tok == "--dir":
            pol_dir, _, i = arg(i + 1, False)
            continue
        if tok == "--pol":
            pol_pol, _, i = arg(i + 1, False)
            continue
        if tok == "--comment":
            comment, _, i = arg(i + 1, False)
            continue
        if tok in ("--icmp-type", "--icmpv6-type"):
            v, _, i = arg(i + 1, negate)
            warn(f"{tok} {v} cannot be represented (no ICMP type field); rule matches all ICMP")
            negate = False
            continue
        if tok in ("--to-destination", "--to-source"):
            v, _, i = arg(i + 1, False)
            if v is not None:
                nat_addr, nat_ports = split_nat_target(v)
            continue
        if tok == "--to-ports":
            v, _, i = arg(i + 1, False)
            nat_ports = v.replace(":", "-") if v else None
            continue
        if tok in ("--set-mark", "--set-xmark"):
            mark_val, _, i = arg(i + 1, False)
            continue
        if tok in ("--or-mark", "--and-mark", "--xor-mark"):
            warn(f"{tok} not representable; mark value unset")
            i += 2
            continue
        if tok in ("--save-mark", "--restore-mark"):
            warn(f"{tok} not representable; mark value unset")
            i += 1
            continue
        if tok == "--set-mss":
            mss, _, i = arg(i + 1, False)
            continue
        if tok == "--clamp-mss-to-pmtu":
            mss = "clamp-to-pmtu"
            i += 1
            continue
        if tok == "--to":
            netmap_to, _, i = arg(i + 1, False)
            continue
        if tok in ("--add-set", "--del-set"):
            if i + 2 < n:
                if tok == "--add-set":
                    add_set = (tokens[i + 1], tokens[i + 2].lower())
                else:
                    warn("ipset --del-set not representable")
                i += 3
            else:
                i = n
            continue
        if tok == "--timeout":
            set_timeout, _, i = arg(i + 1, False)
            continue
        if tok == "--src-pfx":
            src_pfx, _, i = arg(i + 1, False)
            continue
        if tok == "--dst-pfx":
            dst_pfx, _, i = arg(i + 1, False)
            continue
        if tok in IGNORED_ARG1:
            i += 2
            continue
        if tok in IGNORED_FLAGS:
            i += 1
            continue
        if tok == "-c":
            i += 3
            continue
        if tok in ("-f", "--fragment"):
            warn("fragment match (-f) not representable")
            negate = False
            i += 1
            continue
        if tok.startswith("-"):
            warn(f"unsupported option '{tok}' (rule may match more traffic than the original)")
            negate = False
        i += 1

    if chain is None or (not appended and not is_policy):
        return None

    chain_n = normalize_chain(table, chain)

    if is_policy:
        if policy is None or policy.upper() not in ("ACCEPT", "DROP"):
            return None
        return FirewallRule(
            id="0", table=table, chain=chain_n, family=family, is_policy=True,
            action=policy.lower(), raw_syntax=line,
        ), None

    if limit_rate:
        m = re.match(r"^(\d+)(?:/(\w+))?$", limit_rate)
        rate = limit_rate
        if m and (m.group(2) is None or m.group(2).startswith("sec")):
            rate = m.group(1)
        cond.limit = f"{rate},{limit_burst or 5}:packet"
    if pol_dir or pol_pol:
        cond.ipsec_policy = f"{pol_dir or ''},{pol_pol or ''}".strip(",")

    action = "passthrough"
    target_chain = None
    nat: Dict[str, Optional[str]] = {}
    extra: Dict[str, Optional[str]] = {}
    if target is not None:
        if target in SIMPLE_TARGETS:
            action = SIMPLE_TARGETS[target]
            if target == "NFLOG":
                warn("NFLOG treated as LOG")
            if target in ("DNAT", "SNAT", "REDIRECT", "MASQUERADE"):
                nat = dict(nat_to_addresses=nat_addr, nat_to_ports=nat_ports)
            elif target == "NETMAP":
                nat = dict(nat_to_addresses=netmap_to or nat_addr)
            elif target == "MARK" or target == "CONNMARK":
                extra["mark_value"] = mark_val
            elif target == "TCPMSS":
                extra["mark_value"] = mss
            elif target == "SET":
                if add_set:
                    action = "add-src-to-address-list" if add_set[1].startswith("src") else "add-dst-to-address-list"
                    extra["address_list_target"] = add_set[0]
                    extra["address_list_timeout"] = set_timeout
                else:
                    action = "passthrough"
                    warn("SET target without --add-set not representable")
            elif target in ("SNPT", "DNPT"):
                extra["npt_src_prefix"] = src_pfx
                extra["npt_dst_prefix"] = dst_pfx
        elif target in UNSUPPORTED_TARGETS:
            action = target.lower()
            warn(f"target '{target}' not supported by the simulator")
        else:
            action = "jump"
            target_chain = target
            if goto:
                warn("--goto treated as a normal jump (no RETURN to the calling chain)")

    rule = FirewallRule(
        id="0", table=table, chain=chain_n, family=family, action=action,
        target_chain=target_chain, conditions=cond, comment=comment,
        parse_warnings=warns, raw_syntax=line, **nat, **extra,
    )
    return rule, insert_pos
