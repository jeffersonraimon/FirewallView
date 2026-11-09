from firewallview.parsers.junos import parse_junos_script
from firewallview.exporters.junos import export_to_junos
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry


def _terms(rules):
    return [r for r in rules if not r.is_policy]


def _by_name(rules, name):
    return next(r for r in rules if r.comment and r.comment.endswith(name))


CURLY = """
/* comment with { braces } */
policy-options {
    prefix-list MGMT {
        192.0.2.0/24;
        # a comment
        198.51.100.0/24;
    }
}
firewall {
    family inet {
        filter EDGE {
            term bare-discard {
                then discard;
            }
            term bare-accept {
                from protocol icmp;
                then accept;
            }
            term bare-reject {
                from protocol udp;
                then reject;
            }
            term counted-discard {
                from {
                    source-address {
                        10.0.0.0/8;
                        192.0.2.0/24 except;
                    }
                    protocol [ tcp udp ];
                    destination-port [ ssh 80 ];
                }
                then {
                    count dropped;
                    log;
                    discard;
                }
            }
            term mgmt {
                from {
                    source-prefix-list {
                        MGMT;
                    }
                    destination-address {
                        203.0.113.1/32;
                    }
                    protocol tcp;
                    port https;
                }
                then accept;
            }
            term skip {
                from protocol gre;
                then {
                    count gre;
                    next term;
                }
            }
            inactive: term old {
                from protocol tcp;
                then discard;
            }
            term weird {
                from {
                    ttl 1;
                    icmp-type echo-request;
                }
                then accept;
            }
        }
    }
    family inet6 {
        filter EDGE {
            term v6 {
                from {
                    next-header tcp;
                    destination-port 22;
                }
                then accept;
            }
        }
    }
}
"""


def test_curly_nested_blocks_and_verdicts():
    rules, lists = parse_junos_script(CURLY)
    assert set(lists) == {"MGMT"} | {n for n in lists if n != "MGMT"}
    assert [e.address for e in lists["MGMT"].entries] == ["192.0.2.0/24", "198.51.100.0/24"]

    assert _by_name(rules, "bare-discard").action == "drop"
    assert _by_name(rules, "bare-accept").action == "accept"
    assert _by_name(rules, "bare-reject").action == "reject"

    cd = _by_name(rules, "counted-discard")
    assert cd.action == "drop"
    assert cd.conditions.protocol == "tcp,udp"
    assert cd.conditions.dst_port == "22,80"
    # mixed allow/except -> positive address + negated synthetic list
    assert cd.conditions.src_address == "10.0.0.0/8"
    assert cd.conditions.negate_src_address_list is True
    ex = lists[cd.conditions.src_address_list]
    assert [e.address for e in ex.entries] == ["192.0.2.0/24"]

    mg = _by_name(rules, "mgmt")
    assert mg.conditions.src_address_list == "MGMT"
    assert mg.conditions.dst_address == "203.0.113.1/32"
    assert mg.conditions.port == "443"

    skip = _by_name(rules, "skip")
    assert skip.action == "passthrough"
    assert any("next term" in w for w in skip.parse_warnings)

    assert _by_name(rules, "old").disabled is True

    weird = _by_name(rules, "weird")
    joined = " ".join(weird.parse_warnings)
    assert "ttl" in joined and "icmp-type" in joined


def test_family_separation_and_implicit_discard():
    rules, _ = parse_junos_script(CURLY)
    v4 = [r for r in rules if r.chain == "EDGE"]
    v6 = [r for r in rules if r.chain == "EDGE-inet6"]
    assert v4 and v6
    assert all(r.family == "ipv4" for r in v4)
    assert all(r.family == "ipv6" for r in v6)
    pol4 = [r for r in v4 if r.is_policy]
    pol6 = [r for r in v6 if r.is_policy]
    assert len(pol4) == 1 and pol4[0].action == "drop" and pol4[0].comment == "implicit discard"
    assert len(pol6) == 1
    assert pol4[0].order > max(r.order for r in v4 if not r.is_policy)
    assert v6[0].conditions.protocol == "tcp"


def test_negation_except_whole_list():
    rules, _ = parse_junos_script("""
    firewall { filter F { term t {
        from {
            source-address { 192.0.2.0/24 except; }
            destination-prefix-list { BLK except; }
            protocol-except icmp;
        }
        then discard;
    } } }
    """)
    c = rules[0].conditions
    assert c.src_address == "192.0.2.0/24" and c.negate_src_address
    assert c.dst_address_list == "BLK" and c.negate_dst_address_list
    assert c.protocol == "icmp" and c.negate_protocol


def test_set_format_lists_and_except():
    rules, lists = parse_junos_script("""
    set policy-options prefix-list NOC 192.0.2.0/24
    set firewall family inet filter F term a from protocol [ tcp udp ]
    set firewall family inet filter F term a from destination-port [ 22 80 ]
    set firewall family inet filter F term a from source-address 10.0.0.0/8 except
    set firewall family inet filter F term a from source-prefix-list NOC
    set firewall family inet filter F term a from tcp-flags "syn & !ack"
    set firewall family inet filter F term a then discard
    set firewall family inet6 filter F term b from next-header icmp6
    set firewall family inet6 filter F term b then accept
    set firewall family inet filter F term c from icmp-type echo-request
    set firewall family inet filter F term c then reject
    deactivate firewall family inet filter F term c
    """)
    a = _by_name(rules, "a")
    assert a.conditions.protocol == "tcp,udp"
    assert a.conditions.dst_port == "22,80"
    assert a.action == "drop"
    assert a.conditions.tcp_flags == ["syn", "!ack"]
    assert a.conditions.src_address_list == "NOC"
    assert a.conditions.src_address == "10.0.0.0/8" and a.conditions.negate_src_address
    b = _by_name(rules, "b")
    assert b.chain == "F-inet6" and b.family == "ipv6"
    c = _by_name(rules, "c")
    assert c.disabled and c.action == "reject"
    assert any("icmp-type" in w for w in c.parse_warnings)
    assert "NOC" in lists


def test_then_routing_instance_warns_and_no_then_accepts():
    rules, _ = parse_junos_script("""
    set firewall filter F term r from protocol tcp
    set firewall filter F term r then routing-instance GUEST
    set firewall filter F term n from protocol udp
    """)
    r = _by_name(rules, "r")
    assert any("routing-instance" in w for w in r.parse_warnings)
    assert _by_name(rules, "n").action == "accept"


def test_nested_filter_is_jump_without_policy():
    rules, _ = parse_junos_script("""
    firewall { family inet {
        filter SUB { term t { from protocol icmp; then accept; } }
        filter MAIN { term j { filter SUB; } }
    } }
    """)
    j = _by_name(rules, "j")
    assert j.action == "jump" and j.target_chain == "SUB"
    assert [r.chain for r in rules if r.is_policy] == ["MAIN"]


def test_exporter_unsupported_actions_not_accept():
    rules = [
        FirewallRule(id="1", order=1, table="filter", chain="fw", action="drop",
                     conditions=RuleCondition(protocol="tcp", dst_port="22,80")),
        FirewallRule(id="2", order=2, table="filter", chain="fw", action="return"),
        FirewallRule(id="3", order=3, table="filter", chain="fw", action="jump", target_chain="x"),
        FirewallRule(id="4", order=4, table="nat", chain="srcnat", action="masquerade"),
        FirewallRule(id="5", order=5, table="mangle", chain="prerouting", action="mark-packet"),
        FirewallRule(id="6", order=6, table="filter", chain="fw", action="dst-nat"),
    ]
    out = export_to_junos(rules, {})
    assert out.count("UNSUPPORTED") == 5
    assert out.count("accept;") == 0
    assert "destination-port [ 22 80 ];" in out
    assert "discard;" in out


def test_exporter_ipv6_negation_flags_policy():
    rules = [
        FirewallRule(id="1", order=1, table="filter", chain="in6", family="ipv6", action="accept",
                     conditions=RuleCondition(src_address="2001:db8::1", dst_address="2001:db8:1::/48",
                                              negate_dst_address=True, protocol="icmp")),
        FirewallRule(id="2", order=2, table="filter", chain="in6", family="ipv6", action="drop",
                     conditions=RuleCondition(protocol="tcp", out_interface="ge-0/0/1.0",
                                              connection_state=["established"])),
        FirewallRule(id="3", order=3, table="filter", chain="in6", family="ipv6", action="accept",
                     is_policy=True),
        FirewallRule(id="4", order=4, table="filter", chain="in4", family="ipv4", action="drop",
                     is_policy=True),
        FirewallRule(id="5", order=5, table="filter", chain="in4", family="ipv4", action="drop",
                     conditions=RuleCondition(src_address="10.1.1.1", tcp_flags=["syn", "!ack"],
                                              protocol="tcp", connection_state=["new"])),
    ]
    out = export_to_junos(rules, {})
    assert "2001:db8::1/128" in out
    assert "/32" in out and "2001:db8::1/32" not in out
    assert "10.1.1.1/32" in out
    assert "destination-address 2001:db8:1::/48 except;" in out
    assert "family inet6 {" in out
    assert "next-header icmp6;" in out
    assert "tcp-established;" in out
    assert "out-interface ge-0/0/1.0;" in out
    assert "tcp-initial;" in out
    assert "term default-accept" in out
    assert out.count("default-") == 1  # drop policy emits nothing


def test_exporter_range_and_address_list():
    lists = {"L": AddressList(name="L", entries=[AddressListEntry(address="192.0.2.1"),
                                                  AddressListEntry(address="192.0.2.8-192.0.2.15")])}
    rules = [FirewallRule(id="1", order=1, table="filter", chain="f", action="accept",
                          conditions=RuleCondition(src_address_list="L", negate_src_address_list=True))]
    out = export_to_junos(rules, lists)
    assert "192.0.2.1/32;" in out and "192.0.2.8/29;" in out
    assert "source-prefix-list L except;" in out


def _signature(rules):
    sig = []
    for r in rules:
        c = r.conditions
        sig.append((r.chain, r.family, r.action, r.is_policy, r.disabled,
                    c.protocol, c.negate_protocol, c.src_address, c.negate_src_address,
                    c.dst_address, c.negate_dst_address, c.src_address_list, c.negate_src_address_list,
                    c.dst_address_list, c.dst_port, c.src_port, c.port, c.negate_dst_port,
                    tuple(c.connection_state), tuple(c.tcp_flags), c.in_interface))
    return sig


ROUNDTRIP_SRC = """
firewall {
    family inet {
        filter PROTECT {
            term est {
                from { protocol tcp; tcp-established; }
                then accept;
            }
            term ssh {
                from {
                    source-address { 192.0.2.0/24; 198.51.100.7/32; }
                    protocol tcp;
                    destination-port [ 22 443 ];
                }
                then accept;
            }
            term nobogon {
                from { source-address { 10.0.0.0/8 except; } interface ge-0/0/0.0; }
                then discard;
            }
            inactive: term off {
                from { protocol udp; destination-port 53; }
                then reject;
            }
            term syn {
                from { protocol tcp; tcp-initial; }
                then discard;
            }
        }
    }
    family inet6 {
        filter PROTECT {
            term ra {
                from { source-address 2001:db8::/32; next-header icmp6; }
                then accept;
            }
        }
    }
}
"""


def test_roundtrip_curly_and_set():
    rules1, lists1 = parse_junos_script(ROUNDTRIP_SRC)
    out = export_to_junos(rules1, lists1)
    rules2, _ = parse_junos_script(out)
    assert _signature(rules1) == _signature(rules2)
    assert [r.comment for r in rules1 if not r.is_policy] and \
        [r.comment.split()[-1] for r in rules1] == [r.comment.split()[-1] for r in rules2]

    set_src = """
    set firewall family inet filter PROTECT term ssh from source-address 192.0.2.0/24
    set firewall family inet filter PROTECT term ssh from protocol tcp
    set firewall family inet filter PROTECT term ssh from destination-port [ 22 443 ]
    set firewall family inet filter PROTECT term ssh then accept
    set firewall family inet filter PROTECT term nobogon from source-address 10.0.0.0/8 except
    set firewall family inet filter PROTECT term nobogon then discard
    """
    s1, l1 = parse_junos_script(set_src)
    s2, _ = parse_junos_script(export_to_junos(s1, l1))
    assert _signature(s1) == _signature(s2)
    assert [r.action for r in s2 if not r.is_policy] == ["accept", "drop"]
