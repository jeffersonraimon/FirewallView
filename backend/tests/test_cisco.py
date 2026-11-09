from firewallview.parsers.cisco import parse_cisco_acl
from firewallview.exporters.cisco import export_to_cisco
from firewallview.models.rules import FirewallRule, RuleCondition


def chain_rules(rules, chain, policy=False):
    return [r for r in rules if r.chain == chain and r.is_policy == policy]


# ---------------------------------------------------------------- parser

def test_named_acl_with_sequence_numbers_and_remark():
    cfg = """
ip access-list extended EDGE
 remark allow ssh
 20 permit tcp any any eq 22
 10 deny ip host 203.0.113.9 any log
 30 permit udp any any eq domain
"""
    rules, _ = parse_cisco_acl(cfg)
    rs = chain_rules(rules, "EDGE")
    assert [r.action for r in rs] == ["drop", "accept", "accept"]  # sorted by sequence
    assert rs[0].conditions.src_address == "203.0.113.9"
    assert rs[0].parse_warnings == []  # log ignored silently
    assert rs[1].comment == "allow ssh"
    assert rs[1].conditions.dst_port == "22"
    assert rs[2].conditions.dst_port == "53"
    assert all(r.family == "ipv4" for r in rs)
    pol = chain_rules(rules, "EDGE", policy=True)
    assert len(pol) == 1 and pol[0].action == "drop" and pol[0].comment == "implicit deny"
    assert pol[0].order > rs[-1].order


def test_numbered_standard_and_extended():
    cfg = """
access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 permit host 192.0.2.1
access-list 10 deny any
access-list 101 permit tcp 10.1.0.0 0.0.255.255 any eq 80 443
access-list 1300 deny 10.9.9.9
"""
    rules, _ = parse_cisco_acl(cfg)
    s = chain_rules(rules, "acl_10")
    assert s[0].conditions.src_address == "10.0.0.0/24" and s[0].conditions.protocol is None
    assert s[1].conditions.src_address == "192.0.2.1"
    assert s[2].action == "drop" and s[2].conditions.src_address is None
    e = chain_rules(rules, "acl_101")[0]
    assert e.conditions.src_address == "10.1.0.0/16"
    assert e.conditions.dst_port == "80,443"
    assert chain_rules(rules, "acl_1300")[0].conditions.src_address == "10.9.9.9"


def test_ipv6_acl_own_chain():
    cfg = """
ip access-list extended V4
 permit ip any any
ipv6 access-list V6
 permit tcp 2001:db8::/32 host 2001:db8:1::1 eq 443
 deny ipv6 any any
"""
    rules, _ = parse_cisco_acl(cfg)
    assert len(chain_rules(rules, "V4")) == 1
    v6 = chain_rules(rules, "V6")
    assert len(v6) == 2 and all(r.family == "ipv6" for r in v6)
    assert v6[0].conditions.src_address == "2001:db8::/32"
    assert v6[0].conditions.dst_address == "2001:db8:1::1"
    assert v6[1].conditions.protocol is None


def test_port_operators():
    cfg = """
ip access-list extended P
 permit tcp any any neq 25
 permit tcp any any gt 1023
 permit tcp any any lt 1024
 permit tcp any any range 8000 9000
 permit tcp any eq www any eq https
 permit tcp any any established
"""
    rs = chain_rules(parse_cisco_acl(cfg)[0], "P")
    assert rs[0].conditions.dst_port == "25" and rs[0].conditions.negate_dst_port
    assert rs[1].conditions.dst_port == "1024-65535"
    assert rs[2].conditions.dst_port == "0-1023"
    assert rs[3].conditions.dst_port == "8000-9000"
    assert rs[4].conditions.src_port == "80" and rs[4].conditions.dst_port == "443"
    assert rs[5].conditions.connection_state == ["established"]


def test_addresses_nxos_wildcards_and_groups():
    cfg = """
object-group network NETS
 network-object host 198.51.100.7
 network-object 203.0.113.0 255.255.255.0
ip access-list NX
 10 permit ip 10.0.0.0/24 any
 20 permit ip addrgroup NETS any
 30 permit ip 10.0.0.0 0.0.255.0 any
 40 permit ip any6 any
"""
    rules, lists = parse_cisco_acl(cfg)
    assert [e.address for e in lists["NETS"].entries] == ["198.51.100.7", "203.0.113.0/24"]
    rs = chain_rules(rules, "NX")
    assert rs[0].conditions.src_address == "10.0.0.0/24"
    assert rs[1].conditions.src_address_list == "NETS"
    assert rs[2].conditions.src_address is None
    assert any("Non-contiguous" in w for w in rs[2].parse_warnings)


def test_unknown_tokens_warn_and_log_input_silent():
    rules, _ = parse_cisco_acl("ip access-list extended U\n permit tcp any any eq 22 log-input\n permit tcp any any eq 22 time-range WORK\n")
    rs = chain_rules(rules, "U")
    assert rs[0].parse_warnings == []
    assert any("time-range" in w for w in rs[1].parse_warnings)


def test_access_group_recorded():
    cfg = "ip access-list extended IN\n permit ip any any\ninterface Gi0/1\n ip access-group IN in\n"
    rules, _ = parse_cisco_acl(cfg)
    pol = chain_rules(rules, "IN", policy=True)[0]
    assert any("Gi0/1 in" in w for w in pol.parse_warnings)


# ---------------------------------------------------------------- exporter

def _rule(order, action="accept", chain="forward", table="filter", **cond):
    return FirewallRule(id=str(order), order=order, table=table, chain=chain, action=action,
                        conditions=RuleCondition(**cond))


def test_exporter_never_turns_other_actions_into_deny():
    rules = [
        _rule(1, action="jump", target_chain="x"),
        _rule(2, action="masquerade", table="nat", chain="srcnat"),
        _rule(3, action="log"),
        _rule(4, action="return"),
        _rule(5, action="drop", protocol="tcp", dst_port="22"),
    ]
    out = export_to_cisco(rules, {})
    assert out.count(" deny ") == 1
    assert "remark UNSUPPORTED" in out
    assert "deny ip any any" not in out
    assert "SKIPPED (table nat" in out


def test_exporter_ports_negation_and_chains():
    rules = [
        _rule(1, chain="input", protocol="tcp", dst_port="80,443"),
        _rule(2, chain="forward", protocol="tcp", dst_port="1000-2000"),
        _rule(3, chain="forward", protocol="tcp", dst_port="22", negate_dst_port=True),
        _rule(4, chain="forward", src_address="10.0.0.0/8", negate_src_address=True),
        _rule(5, chain="forward", protocol="udp", dst_port="53,8000-9000"),
    ]
    out = export_to_cisco(rules, {})
    assert "ip access-list extended input" in out
    assert "ip access-list extended forward" in out
    assert " permit tcp any any eq 80 443" in out
    assert " permit tcp any any range 1000 2000" in out
    assert " permit tcp any any neq 22" in out
    assert " permit udp any any eq 53" in out and " permit udp any any range 8000 9000" in out
    assert "remark UNSUPPORTED" in out


def test_exporter_policy_and_ipv6():
    rules = [
        _rule(1, chain="input", protocol="tcp", dst_port="22"),
        FirewallRule(id="p", order=2, chain="input", is_policy=True, action="drop"),
        FirewallRule(id="6", order=3, chain="in6", family="ipv6", action="accept",
                     conditions=RuleCondition(src_address="2001:db8::/32", protocol="tcp", dst_port="443")),
        FirewallRule(id="p6", order=4, chain="in6", family="ipv6", is_policy=True, action="accept"),
    ]
    out = export_to_cisco(rules, {})
    assert "ipv6 access-list in6" in out
    assert " permit tcp 2001:db8::/32 any eq 443" in out
    assert " permit ipv6 any any" in out
    assert out.split("ip access-list extended input")[1].split("!")[0].count("any any") == 1  # only the explicit rule


def test_roundtrip_parse_export_parse():
    cfg = """
object-group network BAD
 network-object 198.51.100.0 255.255.255.0
 network-object host 203.0.113.99
ip access-list extended EDGE
 10 deny ip object-group BAD any
 20 permit tcp any 172.16.10.0 0.0.0.255 eq 80 443
 30 permit tcp any any range 8000 9000
 40 permit tcp any any neq 25
 50 permit tcp any host 172.16.20.15 established
 60 permit icmp any any
 70 deny ip any any
ipv6 access-list EDGE6
 10 permit tcp 2001:db8::/32 any eq 22
"""
    rules1, lists1 = parse_cisco_acl(cfg)
    text = export_to_cisco(rules1, lists1)
    rules2, lists2 = parse_cisco_acl(text)

    def sig(rules):
        return [(r.chain, r.family, r.action, r.is_policy, r.conditions.model_dump()) for r in rules]
    assert sig(rules1) == sig(rules2)
    assert {k: [e.address for e in v.entries] for k, v in lists1.items()} == \
           {k: [e.address for e in v.entries] for k, v in lists2.items()}
