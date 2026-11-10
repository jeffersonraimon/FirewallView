"""Regression tests for defects found by the kernel differential harness."""
import re

from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.packet import SimulationPacket
from firewallview.parsers.iptables import parse_iptables_script
from firewallview.parsers.nftables import parse_nftables_script
from firewallview.exporters.iptables import export_to_iptables
from firewallview.engine.simulator import FirewallSimulator


def ipt(text):
    rules, _ = parse_iptables_script(text)
    assert len(rules) == 1, rules
    return rules[0]


def nft(text):
    rules, _ = parse_nftables_script(
        "table inet t { chain input { type filter hook input priority filter; %s } }" % text)
    assert len(rules) == 1, rules
    return rules[0]


# 1. conntrack --ctstate DNAT/SNAT
def test_ctstate_dnat_snat():
    c = ipt("iptables -t nat -A PREROUTING -m conntrack --ctstate DNAT -j ACCEPT").conditions
    assert c.connection_nat_state == "dstnat" and not c.connection_state
    c = ipt("iptables -A FORWARD -m conntrack --ctstate SNAT -j ACCEPT").conditions
    assert c.connection_nat_state == "srcnat"
    c = ipt("iptables -A FORWARD -m conntrack ! --ctstate DNAT -j ACCEPT").conditions
    assert c.connection_nat_state == "dstnat" and c.negate_connection_nat_state
    c = ipt("iptables -A FORWARD -m conntrack --ctstate NEW,DNAT -j ACCEPT").conditions
    assert c.connection_state == ["new"] and c.connection_nat_state == "dstnat"


# 2. interface wildcard
def test_interface_plus_wildcard():
    c = ipt("iptables -A FORWARD -i ether+ -o eth+ -j ACCEPT").conditions
    assert c.in_interface == "ether*" and c.out_interface == "eth*"
    c = ipt("iptables -A FORWARD ! -i br+ -j ACCEPT").conditions
    assert c.in_interface == "br*" and c.negate_in_interface


# 3. iprange
def test_iprange():
    r = ipt("iptables -A INPUT -m iprange ! --src-range 192.0.2.1-192.0.2.9 --dst-range 198.51.100.1-198.51.100.5 -j DROP")
    c = r.conditions
    assert c.src_address == "192.0.2.1-192.0.2.9" and c.negate_src_address
    assert c.dst_address == "198.51.100.1-198.51.100.5" and not c.negate_dst_address
    assert not any("iprange" in w or "src-range" in w for w in r.parse_warnings)


def test_iprange_with_dash_s_warns_and_keeps_one():
    r = ipt("iptables -A INPUT -s 192.0.2.0/24 -m iprange --src-range 192.0.2.1-192.0.2.9 -j DROP")
    assert r.conditions.src_address == "192.0.2.0/24"
    assert r.parse_warnings


# 4. nft reject with
def test_nft_reject_with():
    for txt in ("reject with icmp type admin-prohibited", "reject with icmpx type port-unreachable",
                "reject with icmpv6 type no-route", "reject with tcp reset"):
        r = nft("ip saddr 192.0.2.1 " + txt)
        assert r.action == "reject"
        assert r.conditions.protocol is None, txt
        assert not r.parse_warnings, (txt, r.parse_warnings)
    r = nft("reject with tcp reset")
    assert not r.parse_warnings


# 5. marks replace
def _mark_sim(first, second):
    rules = [
        FirewallRule(id="m1", order=1, table="mangle", chain="prerouting", action="mark-packet",
                     mark_value=first, conditions=RuleCondition()),
        FirewallRule(id="m2", order=2, table="mangle", chain="prerouting", action="mark-packet",
                     mark_value=second, conditions=RuleCondition()),
        FirewallRule(id="f", order=1, table="filter", chain="forward", action="drop",
                     conditions=RuleCondition(packet_mark=first)),
    ]
    p = SimulationPacket(src_ip="192.168.1.50", dst_ip="198.51.100.10", src_port=40000, dst_port=443,
                         protocol="tcp", in_interface="lan", out_interface="wan")
    return FirewallSimulator(rules, {}).simulate(p)


def test_new_mark_replaces_previous():
    r = _mark_sim("a", "b")
    assert r.packet_out.packet_marks == ["b"]
    assert r.verdict != "DROP"  # rule matching the overwritten mark "a" must not match


# 6. negated multi-address export
def _export(c):
    r = FirewallRule(id="x", order=1, table="filter", chain="input", action="drop", conditions=c)
    return export_to_iptables([r], {})


def test_negated_address_list_export_has_no_forbidden_combo():
    out = _export(RuleCondition(src_address="192.0.2.1,192.0.2.2", negate_src_address=True))
    assert not re.search(r"! -s \S*,", out)
    assert "-N FWV_" in out and "-s 192.0.2.1 -j RETURN" in out and "-s 192.0.2.2 -j RETURN" in out
    out = _export(RuleCondition(src_address="192.0.2.1", negate_src_address=True,
                                dst_address="198.51.100.1,198.51.100.2"))
    assert "! -s 192.0.2.1 -d 198.51.100.1" in out and "! -s 192.0.2.1 -d 198.51.100.2" in out
    assert not re.search(r"-d \S*,", out)
