"""Regression tests for the simulation engine, matcher and API (review fixes)."""
import pytest
from fastapi.testclient import TestClient

from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.packet import SimulationPacket
from firewallview.models.address_list import AddressList
from firewallview.engine.matcher import evaluate_rule_match, is_ip_matching
from firewallview.engine.simulator import FirewallSimulator
from firewallview.main import app, detect_syntax, MAX_IMPORT_BYTES


def R(id, order=1, table="filter", chain="forward", action="accept", cond=None, **kw):
    return FirewallRule(id=id, order=order, table=table, chain=chain, action=action,
                        conditions=RuleCondition(**(cond or {})), **kw)


def P(**kw):
    base = dict(src_ip="192.168.1.50", dst_ip="198.51.100.10", src_port=40000, dst_port=443,
                protocol="tcp", in_interface="lan", out_interface="wan")
    base.update(kw)
    return SimulationPacket(**base)


def sim(rules, packet, lists=None):
    return FirewallSimulator(rules, lists or {}).simulate(packet)


def stage(result, stage_id):
    return next(s for s in result.stages if s.stage_id == stage_id)


# 1. accept via jump in filter must not skip postrouting / srcnat
def test_accept_via_jump_continues_to_srcnat():
    rules = [
        R("j", 1, chain="forward", action="jump", target_chain="sub"),
        R("a", 2, chain="sub", action="accept"),
        R("m", 1, table="nat", chain="srcnat", action="masquerade"),
    ]
    r = sim(rules, P())
    assert r.verdict == "ACCEPT"
    assert "nat_srcnat" in r.flow_path
    assert r.packet_out.src_ip != "192.168.1.50"
    assert r.matched_rule_id == "a"


# 2. call stack popped: two sequential jumps to the same chain are not a loop
def test_sequential_jumps_same_chain_no_loop():
    rules = [
        R("j1", 1, action="jump", target_chain="sub", cond={"protocol": "udp"}),
        R("j2", 2, action="jump", target_chain="sub"),
        R("s", 1, chain="sub", action="drop", cond={"dst_port": "443"}),
    ]
    r = sim(rules, P())
    assert r.verdict == "DROP"
    st = stage(r, "filter_forward")
    assert not (st.notes and "Loop" in st.notes)


def test_real_recursion_still_detected():
    rules = [
        R("j", 1, action="jump", target_chain="a"),
        R("ja", 1, chain="a", action="jump", target_chain="b"),
        R("jb", 1, chain="b", action="jump", target_chain="a"),
    ]
    r = sim(rules, P())
    assert "Loop detected" in (stage(r, "filter_forward").notes or "")


# 3. accept inside jumped mangle chain stops the whole stage
def test_accept_in_jumped_mangle_chain_stops_stage():
    rules = [
        R("j", 1, table="mangle", chain="forward", action="jump", target_chain="msub"),
        R("acc", 1, table="mangle", chain="msub", action="accept"),
        R("mk", 2, table="mangle", chain="forward", action="mark-packet", mark_value="late"),
    ]
    r = sim(rules, P())
    assert "late" not in r.packet_out.packet_marks
    assert r.verdict == "ACCEPT"


# 4. mixed IP versions never raise and never match
def test_mixed_family_ranges_do_not_raise():
    assert is_ip_matching("192.0.2.5", "2001:db8::1-2001:db8::ff") is False
    assert is_ip_matching("2001:db8::5", "192.0.2.1-192.0.2.9") is False
    assert is_ip_matching("2001:db8::5", "192.0.2.0/24") is False
    assert is_ip_matching("192.0.2.5", "2001:db8::5") is False
    assert is_ip_matching("192.0.2.5", "192.0.2.1-192.0.2.9") is True


def test_mixed_family_address_list():
    lists = {"L": AddressList(name="L", entries=[{"address": "2001:db8::/32"}, {"address": "192.0.2.1-192.0.2.9"}])}
    rule = R("x", cond={"src_address_list": "L"})
    m, _ = evaluate_rule_match(rule, P(src_ip="192.0.2.5"), lists)
    assert m is True
    m, _ = evaluate_rule_match(rule, P(src_ip="10.0.0.1"), lists)
    assert m is False


# 5. icmp vs icmp6
def test_icmp_does_not_match_icmp6():
    m, _ = evaluate_rule_match(R("a", cond={"protocol": "icmp"}), P(protocol="icmp6", src_ip="2001:db8::1", dst_ip="2001:db8::2"), {})
    assert m is False
    m, _ = evaluate_rule_match(R("b", cond={"protocol": "icmpv6"}), P(protocol="icmp"), {})
    assert m is False


@pytest.mark.parametrize("alias", ["icmpv6", "ipv6-icmp", "icmp6"])
def test_icmp6_aliases(alias):
    m, _ = evaluate_rule_match(R("a", cond={"protocol": alias}), P(protocol="icmp6", src_ip="2001:db8::1", dst_ip="2001:db8::2"), {})
    assert m is True


# 6. packet-mark, connection-state negation, tcp flags negation, limit
def test_packet_mark():
    rule = R("pm", cond={"packet_mark": "voip"})
    assert evaluate_rule_match(rule, P(packet_marks=["voip"]), {})[0] is True
    assert evaluate_rule_match(rule, P(packet_marks=[]), {})[0] is False
    neg = R("pn", cond={"packet_mark": "voip", "negate_packet_mark": True})
    assert evaluate_rule_match(neg, P(packet_marks=["voip"]), {})[0] is False
    assert evaluate_rule_match(neg, P(packet_marks=[]), {})[0] is True


def test_connection_state_negation():
    flag = R("f", cond={"connection_state": ["new"], "negate_connection_state": True})
    assert evaluate_rule_match(flag, P(connection_state="new"), {})[0] is False
    assert evaluate_rule_match(flag, P(connection_state="established"), {})[0] is True
    legacy = R("l", cond={"connection_state": ["!new"]})
    assert evaluate_rule_match(legacy, P(connection_state="new"), {})[0] is False
    assert evaluate_rule_match(legacy, P(connection_state="established"), {})[0] is True


def test_negate_tcp_flags():
    rule = R("t", cond={"tcp_flags": ["syn"], "negate_tcp_flags": True})
    assert evaluate_rule_match(rule, P(tcp_flags=["syn"]), {})[0] is False
    assert evaluate_rule_match(rule, P(tcp_flags=["ack"]), {})[0] is True


def test_limit_and_ipsec_assumed_match_with_reason():
    m, reasons = evaluate_rule_match(R("l", cond={"limit": "50,5:packet", "ipsec_policy": "in,ipsec"}), P(), {})
    assert m is True
    assert "limit not simulated (assumed match)" in reasons


# 7. NAT
def test_dstnat_range_uses_first_address_and_notes():
    rules = [R("d", table="nat", chain="dstnat", action="dst-nat", nat_to_addresses="10.0.0.10-10.0.0.20", nat_to_ports="8080")]
    r = sim(rules, P())
    assert r.packet_out.dst_ip == "10.0.0.10"
    assert r.packet_out.dst_port == 8080
    ev = stage(r, "nat_dstnat").evaluated_rules[0]
    assert "first address" in ev.applied_effect


def test_srcnat_honors_ports_and_masquerade_documented():
    rules = [R("s", table="nat", chain="srcnat", action="src-nat", nat_to_addresses="203.0.113.5", nat_to_ports="1024-2000")]
    r = sim(rules, P())
    assert r.packet_out.src_ip == "203.0.113.5" and r.packet_out.src_port == 1024
    r = sim([R("m", table="nat", chain="srcnat", action="masquerade")], P())
    assert "placeholder" in stage(r, "nat_srcnat").evaluated_rules[0].applied_effect


def test_nat_invalid_address_never_corrupts_packet():
    rules = [R("d", table="nat", chain="dstnat", action="dst-nat", nat_to_addresses="not-an-ip")]
    r = sim(rules, P())
    assert r.packet_out.dst_ip == "198.51.100.10"


def test_redirect():
    rules = [R("r", table="nat", chain="dstnat", action="redirect", nat_to_ports="3128", cond={"dst_port": "80"})]
    r = sim(rules, P(dst_port=80))
    assert r.packet_out.dst_port == 3128
    assert r.packet_out.dst_ip != "198.51.100.10"


def test_netmap_maps_host_bits():
    rules = [R("n", table="nat", chain="dstnat", action="netmap", nat_to_addresses="10.20.0.0/24")]
    r = sim(rules, P(dst_ip="198.51.100.77"))
    assert r.packet_out.dst_ip == "10.20.0.77"
    rules = [R("n", table="nat", chain="srcnat", action="netmap", nat_to_addresses="203.0.113.0/24")]
    r = sim(rules, P(src_ip="192.168.1.50"))
    assert r.packet_out.src_ip == "203.0.113.50"


# 8. family and is_policy
def test_family_restriction():
    rule = R("f4", action="drop", family="ipv4")
    assert evaluate_rule_match(rule, P(), {})[0] is True
    assert evaluate_rule_match(rule, P(src_ip="2001:db8::1", dst_ip="2001:db8::2"), {})[0] is False
    rule6 = R("f6", action="drop", family="ipv6")
    assert evaluate_rule_match(rule6, P(), {})[0] is False


def test_policy_rule_evaluated_last_regardless_of_order():
    rules = [
        R("pol", order=1, chain="input", action="drop", is_policy=True),
        R("ssh", order=50, chain="input", action="accept", cond={"dst_port": "22"}),
    ]
    r = sim(rules, P(flow_type="input", dst_port=22))
    assert r.verdict == "ACCEPT" and r.matched_rule_id == "ssh"
    r = sim(rules, P(flow_type="input", dst_port=23))
    assert r.verdict == "DROP"
    assert r.final_action == "DROP (Default Policy of filter/input)"


def test_no_policy_defaults_to_accept():
    r = sim([R("x", chain="forward", action="drop", cond={"dst_port": "1"})], P())
    assert r.verdict == "ACCEPT" and r.final_action == "ACCEPT (Default Policy)"


# 9. named ACL grouping
def test_multiple_named_acls_grouped_with_note():
    rules = [
        R("a1", 1, chain="ACL_A", action="accept", cond={"dst_port": "1"}),
        R("b1", 2, chain="ACL_B", action="accept", cond={"dst_port": "2"}),
        R("a2", 3, chain="ACL_A", action="drop", cond={"dst_port": "3"}),
    ]
    s = FirewallSimulator(rules, {})
    got = [r.id for r in s.get_rules_for_chain("filter", "forward")]
    assert got == ["a1", "a2", "b1"]
    assert "ACL_A" in s._chain_note and "ACL_B" in s._chain_note


# 10. detect_syntax
def test_detect_routeros_with_long_term_comment():
    script = '/ip firewall filter\nadd chain=input action=accept comment="long term rule"'
    assert detect_syntax(script) == "routeros"


def test_detect_cisco_with_prefix_list():
    cfg = "ip prefix-list PL seq 5 permit 192.0.2.0/24\nip access-list extended X\n permit ip any any\n"
    assert detect_syntax(cfg) == "cisco"


@pytest.mark.parametrize("text,expected", [
    ("iptables -A INPUT -p tcp --dport 22 -j ACCEPT", "iptables"),
    ("*filter\n:INPUT DROP [0:0]\nCOMMIT", "iptables"),
    ("table inet filter {\n chain input { }\n}", "nftables"),
    ("access-list 100 permit ip any any", "cisco"),
    ("firewall {\n family inet {\n filter F {\n term t1 {\n then accept;\n}}}}", "junos"),
    ("set firewall family inet filter F term t1 then accept", "junos"),
    ("acl-profile X\n access-list-entry 1", "dmos"),
])
def test_detect_syntax_table(text, expected):
    assert detect_syntax(text) == expected


# 11. API
@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_unknown_preset_404(client):
    assert client.get("/api/presets/does-not-exist").status_code == 404
    assert client.get("/api/presets/routeros").status_code == 200


def test_import_warnings_and_size_limit(client):
    r = client.post("/api/import", json={"syntax": "iptables", "content": "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"})
    assert r.status_code == 200
    assert "warnings" in r.json()
    big = "x" * (MAX_IMPORT_BYTES + 10)
    assert client.post("/api/import", json={"syntax": "auto", "content": big}).status_code == 413


def test_unknown_api_path_404_and_no_traversal(client):
    assert client.get("/api/nope").status_code == 404
    r = client.get("/..%2f..%2fetc/passwd")
    assert r.status_code in (200, 404)
    assert "root:" not in r.text


def test_cors_no_credentials(client):
    r = client.get("/api/health", headers={"Origin": "http://example.test"})
    assert "access-control-allow-credentials" not in r.headers
