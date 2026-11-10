import hashlib
import re
from typing import Dict, List
from firewallview.models.rules import FirewallRule
from firewallview.models.address_list import AddressList


def _escape(text: str) -> str:
    return (text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
            .replace("\r", "\\r").replace("\n", "\\n"))


def _quote(text: str) -> str:
    return f'"{_escape(text)}"'


def _val(text: str) -> str:
    """Quotes a value only when RouterOS needs it (spaces, quotes, ';', empty)."""
    if text == "" or re.search(r'[\s";\\$]', text):
        return _quote(text)
    return text


def _neg(value: str, negate: bool) -> str:
    return f"!{value}" if negate else value


def _neg_items(items: List[str], negate: bool) -> str:
    return ",".join(_neg(i, negate) for i in items)


_MARK_KEYS = {
    "mark-packet": "new-packet-mark",
    "mark-routing": "new-routing-mark",
    "mark-connection": "new-connection-mark",
    "change-mss": "new-mss",
}


def _rule_line(r: FirewallRule) -> str:
    c = r.conditions
    parts = [f"add chain={_val(r.chain)} action={_val(r.action)}"]

    if r.comment:
        parts.append(f"comment={_quote(r.comment)}")

    if c.protocol:
        parts.append(f"protocol={_neg(c.protocol, c.negate_protocol)}")

    # NPTv6 parsers copy the prefix into src/dst-address; do not export that twice.
    skip_src = r.action == "snpt" and c.src_address == r.npt_src_prefix and not c.negate_src_address
    skip_dst = r.action == "dnpt" and c.dst_address == r.npt_src_prefix and not c.negate_dst_address

    if c.src_address and not skip_src:
        parts.append(f"src-address={_val(_neg(c.src_address, c.negate_src_address))}")
    if c.dst_address and not skip_dst:
        parts.append(f"dst-address={_val(_neg(c.dst_address, c.negate_dst_address))}")
    if c.src_address_list:
        parts.append(f"src-address-list={_val(_neg(c.src_address_list, c.negate_src_address_list))}")
    if c.dst_address_list:
        parts.append(f"dst-address-list={_val(_neg(c.dst_address_list, c.negate_dst_address_list))}")

    if c.port:
        parts.append(f"port={_neg(c.port, c.negate_port)}")
    if c.src_port:
        parts.append(f"src-port={_neg(c.src_port, c.negate_src_port)}")
    if c.dst_port:
        parts.append(f"dst-port={_neg(c.dst_port, c.negate_dst_port)}")

    if c.in_interface:
        parts.append(f"in-interface={_val(_neg(c.in_interface, c.negate_in_interface))}")
    if c.out_interface:
        parts.append(f"out-interface={_val(_neg(c.out_interface, c.negate_out_interface))}")
    if c.in_interface_list:
        parts.append(f"in-interface-list={_val(_neg(c.in_interface_list, c.negate_in_interface_list))}")
    if c.out_interface_list:
        parts.append(f"out-interface-list={_val(_neg(c.out_interface_list, c.negate_out_interface_list))}")

    if c.connection_state:
        parts.append(f"connection-state={_neg_items(c.connection_state, c.negate_connection_state)}")
    if c.connection_nat_state:
        parts.append(f"connection-nat-state={_neg(c.connection_nat_state, c.negate_connection_nat_state)}")
    if c.limit:
        parts.append(f"limit={_val(c.limit)}")
    if c.ipsec_policy:
        parts.append(f"ipsec-policy={c.ipsec_policy}")
    if c.tcp_flags:
        parts.append(f"tcp-flags={_neg_items(c.tcp_flags, c.negate_tcp_flags)}")
    if c.packet_mark:
        parts.append(f"packet-mark={_val(_neg(c.packet_mark, c.negate_packet_mark))}")

    # Targets, NAT and action parameters
    if r.target_chain:
        parts.append(f"jump-target={_val(r.target_chain)}")
    if r.nat_to_addresses:
        parts.append(f"to-addresses={r.nat_to_addresses}")
    if r.nat_to_ports:
        parts.append(f"to-ports={r.nat_to_ports}")
    if r.mark_value:
        parts.append(f"{_MARK_KEYS.get(r.action, 'new-packet-mark')}={_val(r.mark_value)}")
    if r.address_list_target:
        parts.append(f"address-list={_val(r.address_list_target)}")
    if r.address_list_timeout and r.action in ("add-src-to-address-list", "add-dst-to-address-list"):
        parts.append(f"address-list-timeout={r.address_list_timeout}")
    if r.npt_src_prefix:
        parts.append(f"src-prefix={r.npt_src_prefix}")
    if r.npt_dst_prefix:
        parts.append(f"dst-prefix={r.npt_dst_prefix}")

    if r.disabled:
        parts.append("disabled=yes")

    return " ".join(parts)


def _list_line(name: str, entry) -> str:
    cmd = f"add list={_val(name)} address={entry.address}"
    if entry.comment:
        cmd += f" comment={_quote(entry.comment)}"
    if entry.disabled:
        cmd += " disabled=yes"
    return cmd


def _split_addrs(value) -> List[str]:
    return [a.strip() for a in value.split(",") if a.strip()] if value and "," in value else []


def _lower_comma_lists(r: FirewallRule, generated: Dict[str, tuple]) -> List[FirewallRule]:
    """RouterOS 7.25 rejects comma lists in src-address/dst-address (also negated). A list becomes a generated
    address-list `fwv-<hash>` referenced by src/dst-address-list (works for negation); `generated` collects
    name -> (family, [addresses]). When the rule already uses an address-list on that side, positive lists are
    expanded into one rule per address instead."""
    c = r.conditions
    out = r.model_copy(deep=True)
    todo = []
    for side in ("src", "dst"):
        addrs = _split_addrs(getattr(c, f"{side}_address"))
        if not addrs:
            continue
        if getattr(c, f"{side}_address_list"):
            todo.append((side, addrs))
            continue
        digest = hashlib.sha1(f"{r.family}|{','.join(addrs)}".encode()).hexdigest()[:10]
        name = f"fwv-{digest}"
        generated.setdefault(name, (r.family, addrs))
        setattr(out.conditions, f"{side}_address", None)
        setattr(out.conditions, f"{side}_address_list", name)
        setattr(out.conditions, f"negate_{side}_address_list", getattr(c, f"negate_{side}_address"))
        setattr(out.conditions, f"negate_{side}_address", False)
    result = [out]
    for side, addrs in todo:
        if getattr(c, f"negate_{side}_address"):
            continue  # cannot be expressed; left as-is
        expanded = []
        for base in result:
            for a in addrs:
                copy = base.model_copy(deep=True)
                setattr(copy.conditions, f"{side}_address", a)
                expanded.append(copy)
        result = expanded
    return result


def export_to_routeros(rules: List[FirewallRule], address_lists: Dict[str, AddressList]) -> str:
    lines = ["# Exported by FirewallView (MikroTik RouterOS v6/v7 syntax)", ""]

    generated: Dict[str, tuple] = {}
    rules = [x for r in rules for x in _lower_comma_lists(r, generated)]

    # Address lists: entries holding IPv6 addresses go under /ipv6 firewall.
    v4_lines: List[str] = []
    v6_lines: List[str] = []
    for name, alist in (address_lists or {}).items():
        for entry in alist.entries:
            (v6_lines if ":" in entry.address else v4_lines).append(_list_line(name, entry))
    for name, (family, addrs) in generated.items():
        for addr in addrs:
            (v6_lines if family == "ipv6" else v4_lines).append(f"add list={name} address={addr}")
    for menu, entries in (("/ip firewall address-list", v4_lines), ("/ipv6 firewall address-list", v6_lines)):
        if entries:
            lines.append(menu)
            lines.extend(entries)
            lines.append("")

    # Group rules by (family, table), keeping first-appearance order of the menus.
    # RouterOS has no chain policy: policy rules go last in their menu as a final rule.
    groups: Dict[str, List[FirewallRule]] = {}
    for r in sorted(rules, key=lambda x: x.order):
        root = "/ipv6 firewall" if r.family == "ipv6" else "/ip firewall"
        groups.setdefault(f"{root} {r.table.lower()}", []).append(r)

    for menu, r_list in groups.items():
        lines.append(menu)
        normal = [r for r in r_list if not r.is_policy]
        policies = [r for r in r_list if r.is_policy]
        for r in normal:
            lines.append(_rule_line(r))
        for r in policies:
            lines.append(
                f"add chain={_val(r.chain)} action={_val(r.action)} "
                f"comment={_quote('default policy')}"
                + (" disabled=yes" if r.disabled else ""))
        lines.append("")

    return "\n".join(lines)
