import os
import shutil
import subprocess
import tempfile

import pytest

from firewallview.exporters.nftables import export_to_nftables
from firewallview.models.address_list import AddressList, AddressListEntry
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.parsers.nftables import parse_nftables, parse_nftables_script


def one(text, table="inet", chain="input", ctype="filter", prio="filter"):
    src = f"""
    table {table} t {{
        chain {chain} {{
            type {ctype} hook {chain} priority {prio};
            {text}
        }}
    }}"""
    rules, lists = parse_nftables_script(src)
    return rules, lists


def first(text, **kw):
    rules, _ = one(text, **kw)
    assert rules, text
    return rules[0]


# --------------------------------------------------------------------- actions
def test_verdict_not_last_token():
    r = first('tcp dport 22 drop comment "block ssh"')
    assert r.action == "drop" and r.comment == "block ssh"
    assert r.conditions.dst_port == "22" and r.conditions.protocol == "tcp"


def test_counter_after_verdict_and_reject_with():
    assert first("tcp dport 22 counter drop").action == "drop"
    r = first("tcp dport 22 reject with tcp reset")
    assert r.action == "reject" and r.conditions.dst_port == "22"
    assert first("counter packets 1 bytes 2 accept").action == "accept"


def test_nat_actions():
    rules, _ = one("tcp dport 80 dnat ip to 10.0.0.5:8080", ctype="nat", prio="dstnat", chain="prerouting")
    r = rules[0]
    assert (r.table, r.chain, r.action) == ("nat", "dstnat", "dst-nat")
    assert r.nat_to_addresses == "10.0.0.5" and r.nat_to_ports == "8080"
    assert r.family == "ipv4"
    rules, _ = one("oifname eth0 snat to 192.0.2.1", ctype="nat", prio="srcnat", chain="postrouting")
    assert (rules[0].table, rules[0].chain, rules[0].action) == ("nat", "srcnat", "src-nat")
    assert rules[0].nat_to_addresses == "192.0.2.1"
    rules, _ = one("oifname eth0 masquerade", ctype="nat", prio="srcnat", chain="postrouting")
    assert rules[0].action == "masquerade"
    rules, _ = one("tcp dport 80 redirect to :8080", ctype="nat", prio="dstnat", chain="prerouting")
    assert rules[0].action == "redirect" and rules[0].nat_to_ports == "8080"
    rules, _ = one("dnat to :8080", ctype="nat", prio="dstnat", chain="prerouting")
    assert rules[0].nat_to_addresses is None and rules[0].nat_to_ports == "8080"


def test_jump_goto_return():
    src = """
    table inet t {
        chain input { type filter hook input priority 0;
            tcp dport 22 jump ssh_chain
            goto other
        }
        chain ssh_chain { ip saddr 192.0.2.0/24 return
            drop }
        chain other { accept }
    }"""
    rules, _ = parse_nftables_script(src)
    j = [r for r in rules if r.action == "jump"]
    assert [x.target_chain for x in j] == ["ssh_chain", "other"]
    assert any("goto" in w for w in j[1].parse_warnings)
    ssh = [r for r in rules if r.chain == "ssh_chain"]
    assert ssh[0].action == "return" and ssh[0].table == "filter"


def test_no_verdict_is_passthrough_with_warning():
    r = first("counter")
    assert r.action == "passthrough" and r.parse_warnings
    r = first('tcp dport 22 log prefix "ssh "')
    assert r.action == "log"


def test_log_plus_verdict_splits():
    rules, _ = one('tcp dport 23 log prefix "telnet " drop')
    assert [r.action for r in rules] == ["log", "drop"]
    assert all(r.conditions.dst_port == "23" for r in rules)


def test_marks():
    r = first("tcp dport 80 meta mark set 0x1", chain="prerouting", ctype="filter", prio="mangle")
    assert r.action == "mark-packet" and r.mark_value == "0x1" and r.table == "mangle"
    r = first("tcp dport 80 ct mark set 0x2", chain="prerouting", ctype="filter", prio="mangle")
    assert r.action == "mark-connection" and r.mark_value == "0x2"
    r = first("meta mark 0x5 accept")
    assert r.conditions.packet_mark == "0x5" and not r.conditions.negate_packet_mark
    r = first("meta mark != 0x5 drop")
    assert r.conditions.packet_mark == "0x5" and r.conditions.negate_packet_mark


def test_dynamic_set_add():
    r = first("tcp dport 22 add @bad { ip saddr timeout 10m }")
    assert r.action == "add-src-to-address-list" and r.address_list_target == "bad"
    assert r.address_list_timeout == "10m"


# ------------------------------------------------------------------- matchers
def test_negations():
    r = first("ip saddr != 10.0.0.0/8 drop")
    assert r.conditions.src_address == "10.0.0.0/8" and r.conditions.negate_src_address
    r = first("ip daddr != @bl drop")
    assert r.conditions.dst_address_list == "bl" and r.conditions.negate_dst_address_list
    r = first("tcp dport != 22 drop")
    assert r.conditions.dst_port == "22" and r.conditions.negate_dst_port
    r = first("tcp sport != { 1, 2 } drop")
    assert r.conditions.src_port == "1,2" and r.conditions.negate_src_port
    r = first('iifname != "lan0" drop')
    assert r.conditions.in_interface == "lan0" and r.conditions.negate_in_interface
    r = first('oifname != "wan0" drop')
    assert r.conditions.out_interface == "wan0" and r.conditions.negate_out_interface
    r = first("ct state != new drop")
    assert r.conditions.connection_state == ["new"] and r.conditions.negate_connection_state


def test_ranges_and_sets():
    r = first("ip saddr 10.0.0.1-10.0.0.9 accept")
    assert r.conditions.src_address == "10.0.0.1-10.0.0.9"
    r = first("ip saddr 10.0.0.1 - 10.0.0.9 accept")
    assert r.conditions.src_address == "10.0.0.1-10.0.0.9"
    r = first("ip daddr { 192.0.2.1, 192.0.2.0/24 } accept")
    assert r.conditions.dst_address == "192.0.2.1,192.0.2.0/24"
    r = first("tcp dport { 22, 80, 1000-2000 } accept")
    assert r.conditions.dst_port == "22,80,1000-2000"
    r = first("udp dport 5000-6000 accept")
    assert r.conditions.dst_port == "5000-6000" and r.conditions.protocol == "udp"
    r = first("tcp dport > 1023 accept")
    assert r.conditions.dst_port == "1024-65535"
    r = first("tcp dport ssh accept")
    assert r.conditions.dst_port == "22"
    r = first("ct state { established, related } accept")
    assert r.conditions.connection_state == ["established", "related"]
    r = first("ct state established,related accept")
    assert r.conditions.connection_state == ["established", "related"]
    r = first('iifname { "eth0", "eth1" } accept')
    assert r.conditions.in_interface == "eth0,eth1"


def test_protocol_matchers():
    assert first("ip protocol tcp accept").conditions.protocol == "tcp"
    assert first("meta l4proto udp accept").conditions.protocol == "udp"
    assert first("meta l4proto { tcp, udp } accept").conditions.protocol == "tcp,udp"
    r = first("ip6 nexthdr icmpv6 accept")
    assert r.conditions.protocol == "icmpv6" and r.family == "ipv6"
    r = first("meta l4proto != tcp drop")
    assert r.conditions.protocol == "tcp" and r.conditions.negate_protocol
    r = first("meta l4proto { tcp, udp } th dport 53 accept")
    assert r.conditions.protocol == "tcp,udp" and r.conditions.dst_port == "53"


def test_families():
    assert first("ip saddr 192.0.2.1 accept").family == "ipv4"
    assert first("ip6 saddr 2001:db8::/32 accept").family == "ipv6"
    assert first("ip6 daddr 2001:db8::1 accept").conditions.dst_address == "2001:db8::1"
    assert first("tcp dport 22 accept").family is None
    assert first("tcp dport 22 accept", table="ip").family == "ipv4"
    assert first("tcp dport 22 accept", table="ip6").family == "ipv6"
    assert first("meta nfproto ipv6 accept").family == "ipv6"


def test_tcp_flags():
    r = first("tcp flags syn accept")
    assert r.conditions.tcp_flags == ["syn"] and r.conditions.protocol == "tcp"
    r = first("tcp flags & (fin|syn|rst|ack) == syn accept")
    assert r.conditions.tcp_flags == ["syn", "!fin", "!rst", "!ack"]
    r = first("tcp flags != syn drop")
    assert r.conditions.tcp_flags == ["syn"] and r.conditions.negate_tcp_flags


def test_unknown_matcher_warns():
    r = first("meta length 100-200 drop")
    assert r.action == "drop" and any("meta length" in w for w in r.parse_warnings)
    r = first("tcp dport vmap { 22 : accept, 80 : drop }")
    assert r.parse_warnings
    r = first("ip saddr . tcp dport { 192.0.2.1 . 22 } accept")
    assert r.parse_warnings


def test_dup_matcher_warns():
    r = first("tcp dport 22 tcp dport 80 accept")
    assert r.conditions.dst_port == "22" and r.parse_warnings


# ----------------------------------------------------------------- structure
FULL = """
#!/usr/sbin/nft -f
flush ruleset
define LAN = 192.168.0.0/16
define PORTS = { 22, 443 }

table inet filter {
    set blocked {
        type ipv4_addr
        flags interval
        elements = {
            192.0.2.1,
            198.51.100.0/24,
            203.0.113.10-203.0.113.20
        }
    }
    set blocked6 { type ipv6_addr; flags interval; elements = { 2001:db8::/32, 2001:db8:1::1 } }
    set web { type inet_service; elements = { 80, 443 } }
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ip saddr @blocked drop
        ip6 saddr @blocked6 drop
        tcp dport @web accept
        ip saddr $LAN tcp dport $PORTS accept
        jump custom
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain custom {
        udp dport 53 accept
        return
    }
}
table ip nat {
    chain pre { type nat hook prerouting priority dstnat; tcp dport 80 dnat to 10.0.0.5:8080 }
    chain post { type nat hook postrouting priority srcnat; oifname "wan0" masquerade }
}
table ip raw {
    chain pre { type filter hook prerouting priority -300; notrack }
}
table ip mangle {
    chain out { type route hook output priority mangle; meta mark set 0x1 }
    chain fwd { type filter hook forward priority -150; tcp option maxseg size set rt mtu }
}
"""


def test_full_structure():
    rules, lists, warns = parse_nftables(FULL)
    keys = {(r.table, r.chain) for r in rules}
    assert ("filter", "input") in keys and ("filter", "forward") in keys
    assert ("nat", "dstnat") in keys and ("nat", "srcnat") in keys
    assert ("raw", "prerouting") in keys
    assert ("mangle", "output") in keys and ("mangle", "forward") in keys
    assert ("filter", "custom") in keys
    for r in rules:  # structural lines never become rules
        assert not r.raw_syntax.startswith(("table", "chain", "flush", "define", "type", "}"))
    pol = {(r.table, r.chain): r.action for r in rules if r.is_policy}
    assert pol == {("filter", "input"): "drop", ("filter", "forward"): "accept"}
    # policy is a condition-less rule
    assert all(not r.conditions.src_address for r in rules if r.is_policy)
    d = [r for r in rules if r.action == "drop" and not r.is_policy]
    assert len(d) == 2
    rule_lan = [r for r in rules if r.conditions.src_address == "192.168.0.0/16"][0]
    assert rule_lan.conditions.dst_port == "22,443"
    web = [r for r in rules if r.conditions.dst_port == "80,443"]
    assert len(web) == 1
    # sets
    assert set(lists) == {"blocked", "blocked6"}
    assert [e.address for e in lists["blocked"].entries] == [
        "192.0.2.1", "198.51.100.0/24", "203.0.113.10-203.0.113.20"]
    assert [e.address for e in lists["blocked6"].entries] == ["2001:db8::/32", "2001:db8:1::1"]
    assert any(r.action == "passthrough" and r.table == "raw" for r in rules)
    mss = [r for r in rules if r.action == "change-mss"]
    assert mss and mss[0].mark_value == "clamp-to-pmtu"


def test_set_one_liner_does_not_swallow_following_lines():
    src = """
    table inet t {
        set s { type ipv4_addr; elements = { 192.0.2.1, 192.0.2.2 } }
        chain input { type filter hook input priority 0;
            ip saddr @s drop
            accept
        }
    }"""
    rules, lists = parse_nftables_script(src)
    assert len(lists["s"].entries) == 2
    assert [r.action for r in rules] == ["drop", "accept"]


def test_add_rule_one_liners():
    src = """
    nft add rule inet filter input tcp dport 22 accept
    add rule ip nat prerouting tcp dport 80 dnat to 10.0.0.9:80
    add rule inet filter forward ip saddr 192.0.2.1 drop
    """
    rules, _ = parse_nftables_script(src)
    assert [(r.table, r.chain, r.action) for r in rules] == [
        ("filter", "input", "accept"), ("nat", "dstnat", "dst-nat"), ("filter", "forward", "drop")]


def test_priority_roles():
    for prio, role in ((-300, "raw"), ("raw", "raw"), (-150, "mangle"), ("mangle", "mangle"),
                       (0, "filter"), ("filter", "filter"), ("filter + 10", "filter")):
        r = first("accept", chain="input", prio=prio)
        assert r.table == role, prio


def test_unsupported_family_table_skipped():
    src = """
    table bridge b { chain c { type filter hook prerouting priority 0; drop } }
    table inet t { chain input { type filter hook input priority 0; accept } }
    """
    rules, _, warns = parse_nftables(src)
    assert len(rules) == 1 and warns


def test_legacy_example_still_works():
    rules, sets = parse_nftables_script("""
    table inet filter {
        set blacklist {
            type ipv4_addr
            elements = { 10.10.10.10 }
        }
        chain input {
            ip saddr @blacklist drop
            tcp dport 22 accept
        }
    }""")
    assert len(rules) == 2 and "blacklist" in sets
    assert (rules[0].table, rules[0].chain) == ("filter", "input")


# ------------------------------------------------------------------- exporter
def mk(order, action="accept", table="filter", chain="input", **cond):
    extra = {k: cond.pop(k) for k in list(cond) if k in (
        "target_chain", "nat_to_addresses", "nat_to_ports", "mark_value", "family",
        "comment", "is_policy", "address_list_target", "address_list_timeout")}
    return FirewallRule(id=str(order), order=order, table=table, chain=chain, action=action,
                        conditions=RuleCondition(**cond), **extra)


def test_exporter_valid_layout():
    rules = [
        mk(1, "drop", chain="input", protocol="tcp", dst_port="22", src_address="10.0.0.0/8",
           negate_src_address=True),
        mk(2, "accept", chain="input", connection_state=["new"], negate_connection_state=True),
        mk(3, "drop", chain="input", is_policy=True),
        mk(4, "dst-nat", table="nat", chain="dstnat", protocol="tcp", dst_port="80",
           nat_to_addresses="10.0.0.5", nat_to_ports="8080"),
        mk(5, "masquerade", table="nat", chain="srcnat", out_interface="wan0"),
        mk(6, "accept", table="mangle", chain="prerouting", protocol="tcp"),
        mk(7, "accept", table="raw", chain="prerouting"),
        mk(8, "jump", chain="forward", protocol="tcp", target_chain="mychain"),
        mk(9, "drop", chain="mychain"),
    ]
    text = export_to_nftables(rules, {})
    assert "table inet firewallview {" in text
    assert "type filter hook input priority filter; policy drop;" in text
    assert "type nat hook prerouting priority dstnat;" in text
    assert "type nat hook postrouting priority srcnat;" in text
    assert "priority mangle;" in text and "priority raw;" in text
    assert "ip saddr != 10.0.0.0/8" in text
    assert "tcp dport 22" in text and "tcp tcp" not in text
    assert "ct state != new" in text
    assert "meta l4proto tcp jump mychain" in text
    assert "dnat ip to 10.0.0.5:8080" in text
    assert "chain mychain {" in text
    assert "{ !" not in text
    nft_check(text)


def test_exporter_sets_typed_and_family():
    lists = {
        "v4": AddressList(name="v4", entries=[AddressListEntry(address="192.0.2.1"),
                                              AddressListEntry(address="198.51.100.0/24")]),
        "v6": AddressList(name="v6", entries=[AddressListEntry(address="2001:db8::/32")]),
        "plain": AddressList(name="plain", entries=[AddressListEntry(address="192.0.2.5")]),
    }
    rules = [
        mk(1, "drop", src_address_list="v4"),
        mk(2, "drop", src_address_list="v6"),
        mk(3, "drop", dst_address_list="plain", negate_dst_address_list=True),
        mk(4, "drop", dst_address="2001:db8::1"),
        mk(5, "accept", family="ipv6", protocol="udp"),
    ]
    text = export_to_nftables(rules, lists)
    assert "type ipv4_addr" in text and "type ipv6_addr" in text
    assert "flags interval" in text
    assert "ip saddr @v4" in text and "ip6 saddr @v6" in text
    assert "ip daddr != @plain" in text
    assert "ip6 daddr 2001:db8::1" in text
    assert "meta nfproto ipv6 meta l4proto udp" in text
    nft_check(text)


def test_exporter_mixed_family_list_and_comment_escape():
    lists = {"mix": AddressList(name="mix", entries=[AddressListEntry(address="192.0.2.1"),
                                                     AddressListEntry(address="2001:db8::1")])}
    rules = [mk(1, "drop", src_address_list="mix", comment='he said "hi"')]
    text = export_to_nftables(rules, lists)
    assert "set mix {" in text and "set mix_v6 {" in text
    assert text.count("drop comment") == 2
    nft_check(text)


def test_exporter_misc_actions_valid():
    rules = [
        mk(1, "accept", chain="input", tcp_flags=["syn", "!ack"], protocol="tcp"),
        mk(2, "drop", chain="input", tcp_flags=["syn"], negate_tcp_flags=True),
        mk(3, "accept", chain="input", port="53", protocol="udp"),
        mk(4, "drop", chain="input", in_interface="eth0", negate_in_interface=True),
        mk(5, "accept", chain="input", limit="50,5:packet"),
        mk(6, "mark-packet", table="mangle", chain="prerouting", mark_value="7"),
        mk(7, "mark-connection", table="mangle", chain="prerouting", mark_value="8"),
        mk(8, "add-src-to-address-list", chain="input", protocol="tcp", dst_port="22",
           address_list_target="scanners", address_list_timeout="1d"),
        mk(9, "drop", chain="input", src_address_list="scanners"),
        mk(10, "change-mss", table="mangle", chain="forward", mark_value="clamp-to-pmtu"),
        mk(11, "log", chain="input"),
        mk(12, "passthrough", chain="input"),
        mk(13, "redirect", table="nat", chain="dstnat", nat_to_ports="8080", protocol="tcp", dst_port="80"),
        mk(14, "src-nat", table="nat", chain="srcnat", nat_to_addresses="192.0.2.1"),
        mk(15, "fasttrack-connection", chain="forward"),
        mk(16, "accept", chain="input", ipsec_policy="in,ipsec"),
    ]
    text = export_to_nftables(rules, {})
    assert "tcp flags & (syn|ack) == syn" in text
    assert "tcp flags & syn != syn" in text
    assert "udp dport 53" in text and "udp sport 53" in text
    assert 'iifname != "eth0"' in text
    assert "limit rate 50/second burst 5 packets" in text
    assert "NOT EXPORTED" in text  # fasttrack / ipsec
    nft_check(text)


# ----------------------------------------------------------------- round trip
def sig(r):
    return (r.table, r.chain, r.action, r.is_policy, r.target_chain, r.nat_to_addresses,
            r.nat_to_ports, r.mark_value, r.address_list_target,
            r.conditions.model_dump() if hasattr(r.conditions, "model_dump") else r.conditions.dict())


def test_round_trip_full():
    rules, lists, _ = parse_nftables(FULL)
    text = export_to_nftables(rules, lists)
    rules2, lists2, _ = parse_nftables(text)
    assert len(rules2) == len(rules)
    # the exporter normalises (e.g. numeric mark spelling stays); compare field by field
    for a, b in zip(sorted(rules, key=lambda r: (r.table, r.chain, r.order)),
                    sorted(rules2, key=lambda r: (r.table, r.chain, r.order))):
        sa, sb = sig(a), sig(b)
        assert sa[:9] == sb[:9], (a.raw_syntax, b.raw_syntax)
        ca, cb = dict(sa[9]), dict(sb[9])
        # a port-set reference is expanded by the parser, protocol l4 is preserved
        assert ca == cb, (a.raw_syntax, ca, cb)
    assert set(lists2) == set(lists)
    nft_check(text)


ROUND_TRIP_RULES = """
table inet t {
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr != 10.0.0.0/8 tcp dport != { 22, 23 } drop
        iifname != "lo" ct state != established,related counter drop
        ip saddr { 192.0.2.1, 198.51.100.0/24 } udp sport 1000-2000 accept comment "x"
        meta l4proto != tcp meta mark != 0x3 accept
        ip6 saddr 2001:db8::/32 ip6 daddr != 2001:db8:1::/48 accept
        tcp flags & (fin|syn) == syn drop
        oifname "wan0" accept
    }
}
"""


def test_round_trip_negations():
    rules, lists, _ = parse_nftables(ROUND_TRIP_RULES)
    text = export_to_nftables(rules, lists)
    rules2, _, _ = parse_nftables(text)
    assert [sig(r)[2:] for r in rules] == [sig(r)[2:] for r in rules2]
    assert [r.comment for r in rules] == [r.comment for r in rules2]
    nft_check(text)


# ------------------------------------------------------------ nft -c validation
def nft_check(text):
    """Validate with `nft -c` (inside a user+net namespace) when available."""
    nft = shutil.which("nft")
    unshare = shutil.which("unshare")
    if not nft or not unshare:
        pytest.skip("nft/unshare not installed; syntax check skipped")
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        p = subprocess.run([unshare, "-rn", nft, "-c", "-f", path], capture_output=True, text=True)
    finally:
        os.unlink(path)
    if p.returncode != 0 and ("Operation not permitted" in p.stderr or "unshare" in p.stderr):
        pytest.skip("cannot run nft -c here: " + p.stderr.strip()[:80])
    assert p.returncode == 0, p.stderr + "\n" + text
