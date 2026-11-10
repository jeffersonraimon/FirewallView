"""Regression tests for defects found by the RouterOS CHR differential lab (tests/routeros_lab)."""
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.packet import SimulationPacket
from firewallview.exporters.routeros import export_to_routeros
from firewallview.parsers.routeros import parse_routeros_script
from firewallview.engine.simulator import FirewallSimulator


def _rule(order=1, family="ipv4", **cond):
    return FirewallRule(id=str(order), order=order, chain="forward", table="filter", action="accept",
                        family=family, conditions=RuleCondition(**cond), comment="c")


def _lines(text):
    return [l for l in text.splitlines() if l and not l.startswith("#")]


def test_comma_src_address_becomes_address_list():
    out = export_to_routeros([_rule(src_address="192.0.2.1,198.51.100.0/24")], {})
    ls = _lines(out)
    assert "/ip firewall address-list" in ls
    entries = [l for l in ls if l.startswith("add list=fwv-")]
    assert len(entries) == 2 and entries[0].endswith("address=192.0.2.1") and entries[1].endswith("address=198.51.100.0/24")
    name = entries[0].split()[1].split("=")[1]
    rule = next(l for l in ls if l.startswith("add chain=forward"))
    assert f"src-address-list={name}" in rule and "src-address=" not in rule and 'comment="c"' in rule


def test_negated_comma_list_and_both_sides():
    out = export_to_routeros([_rule(src_address="10.0.0.1,10.0.0.2", negate_src_address=True,
                                    dst_address="10.1.0.0/24,10.2.0.0/24")], {})
    rule = next(l for l in _lines(out) if l.startswith("add chain=forward"))
    assert "src-address-list=!fwv-" in rule and "dst-address-list=fwv-" in rule
    assert "," not in rule.replace('comment="c"', "")


def test_ipv6_comma_list_goes_under_ipv6_menu():
    out = export_to_routeros([_rule(family="ipv6", dst_address="2001:db8::1,2001:db8::2")], {})
    ls = _lines(out)
    i = ls.index("/ipv6 firewall address-list")
    assert ls[i + 1].startswith("add list=fwv-") and "2001:db8::1" in ls[i + 1]


def test_comma_list_with_existing_address_list_expands_rules():
    out = export_to_routeros([_rule(src_address="10.0.0.1,10.0.0.2", src_address_list="x")], {})
    rules = [l for l in _lines(out) if l.startswith("add chain=forward")]
    assert len(rules) == 2 and "src-address=10.0.0.1 " in rules[0] and "src-address=10.0.0.2 " in rules[1]


def test_dstnat_noop_does_not_set_nat_state():
    nat = FirewallRule(id="1", order=1, chain="dstnat", table="nat", action="dst-nat", family="ipv4",
                       nat_to_addresses="192.0.2.10", nat_to_ports="80",
                       conditions=RuleCondition(protocol="tcp", dst_port="80"))
    pk = SimulationPacket(src_ip="198.51.100.5", dst_ip="192.0.2.10", protocol="tcp", src_port=1234, dst_port=80,
                          in_interface="eth0")
    FirewallSimulator([nat], {}).simulate(pk) if hasattr(FirewallSimulator, "simulate") else None
    sim_pk = pk.model_copy(deep=True)
    FirewallSimulator([nat], {})._apply_nat("dst-nat", nat, sim_pk, __import__("types").SimpleNamespace(applied_effect=""))
    assert not sim_pk.connection_nat_state
    nat.nat_to_ports = "8080"
    sim_pk = pk.model_copy(deep=True)
    FirewallSimulator([nat], {})._apply_nat("dst-nat", nat, sim_pk, __import__("types").SimpleNamespace(applied_effect=""))
    assert sim_pk.connection_nat_state == "dstnat"


def test_ports_without_protocol_warn():
    for line in ("add chain=forward action=accept dst-port=80",
                 "add chain=forward action=accept protocol=icmp dst-port=80"):
        _, _ = (None, None)
        rules = parse_routeros_script("/ip firewall filter\n" + line + "\n")
        r = rules[0][0] if isinstance(rules, tuple) else rules[0]
        assert any("ports without protocol" in w for w in r.parse_warnings), line
    rules = parse_routeros_script("/ip firewall filter\nadd chain=forward action=accept protocol=tcp dst-port=80\n")
    r = rules[0][0] if isinstance(rules, tuple) else rules[0]
    assert not any("ports without protocol" in w for w in r.parse_warnings)
