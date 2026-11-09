from firewallview.parsers.routeros import parse_routeros_script
from firewallview.exporters.routeros import export_to_routeros
from firewallview.models.rules import FirewallRule, RuleCondition


def _cmp(rule):
    d = rule.model_dump(exclude={"id", "order", "raw_syntax", "parse_warnings"})
    return d


RICH = r"""
/ip firewall address-list
add address=192.0.2.0/24 list=ADMINS comment="Admin net"
/ip firewall filter
add chain=input action=accept connection-state=established,related comment="est"
add chain=input action=drop connection-state=!new in-interface=ether1 comment="not new"
add chain=input action=accept protocol=tcp port=22,443 src-address=!198.51.100.0/24 limit=50,5:packet
add chain=forward action=drop protocol=tcp tcp-flags=!syn,!ack packet-mark=!flagged ipsec-policy=in,ipsec
add chain=forward action=drop connection-nat-state=!dstnat out-interface=!ether2 src-port=1024-65535 dst-port=!80
add chain=forward action=add-src-to-address-list address-list=SCAN address-list-timeout=3d protocol=tcp dst-port=23
add chain=forward action=jump jump-target=custom-chain disabled=yes
add chain=forward action=drop comment="say \"hi\" to \$me"
/ip firewall mangle
add chain=prerouting action=mark-packet new-packet-mark=voip passthrough=yes protocol=udp
add chain=prerouting action=mark-routing new-routing-mark=to-wan src-address-list=ADMINS
add chain=prerouting action=mark-connection new-connection-mark=conn1 protocol=tcp
add chain=forward action=change-mss new-mss=1360 protocol=tcp
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1
add chain=dstnat action=dst-nat to-addresses=192.168.1.10 to-ports=80 dst-port=8080 protocol=tcp
/ipv6 firewall filter
add chain=forward action=accept connection-state=established,related
add chain=input action=drop in-interface=ether1
"""


def test_roundtrip_rich_ruleset():
    rules, lists = parse_routeros_script(RICH)
    text = export_to_routeros(rules, lists)
    rules2, lists2 = parse_routeros_script(text)
    assert len(rules) == len(rules2) == 16
    for a, b in zip(rules, rules2):
        assert _cmp(a) == _cmp(b), (a.raw_syntax, text)
    assert lists2["ADMINS"].entries[0].address == "192.0.2.0/24"
    # every rule kept its family
    assert [r.family for r in rules2][-2:] == ["ipv6", "ipv6"]
    assert rules2[0].family == "ipv4"


def test_negations_and_new_fields_parsed():
    rules, _ = parse_routeros_script(RICH)
    r = rules[1]
    assert r.conditions.connection_state == ["new"] and r.conditions.negate_connection_state
    r = rules[3]
    assert r.conditions.tcp_flags == ["syn", "ack"] and r.conditions.negate_tcp_flags
    assert r.conditions.packet_mark == "flagged" and r.conditions.negate_packet_mark
    assert r.conditions.ipsec_policy == "in,ipsec"
    assert rules[2].conditions.limit == "50,5:packet"
    assert rules[2].conditions.negate_src_address
    assert rules[5].address_list_timeout == "3d"
    assert rules[6].disabled and rules[6].target_chain == "custom-chain"


def test_export_action_specific_mark_keys():
    text = export_to_routeros(parse_routeros_script(RICH)[0], {})
    assert "new-routing-mark=to-wan" in text
    assert "new-connection-mark=conn1" in text
    assert "new-mss=1360" in text
    assert "new-packet-mark=voip" in text
    assert "address-list-timeout=3d" in text
    assert "/ipv6 firewall filter" in text


def test_full_export_ignores_non_firewall_menus():
    script = r"""
# nov/09/2026 10:00:00 by RouterOS 7.16
/interface bridge
add name=bridge1
/ip address
add address=192.0.2.1/24 interface=bridge1 network=192.0.2.0
/ip route
add dst-address=0.0.0.0/0 gateway=192.0.2.254
/ip firewall filter
add chain=input action=accept protocol=icmp
/ip firewall service-port
set ftp disabled=yes
/ip firewall layer7-protocol
add name=l7 regexp=abc
/ipv6 address
add address=2001:db8::1/64 interface=bridge1
/ip firewall filter add chain=forward action=drop
/ip dhcp-server
add name=d1 interface=bridge1
"""
    rules, lists = parse_routeros_script(script)
    assert [(r.chain, r.action) for r in rules] == [("input", "accept"), ("forward", "drop")]
    assert not lists


def test_ipv6_family_and_ipv4_family_and_addresslists():
    script = """
/ipv6 firewall address-list
add address=2001:db8::/32 list=V6
/ip firewall address-list
add address=192.0.2.0/24 list=V4
/ipv6 firewall nat
add chain=srcnat action=masquerade
/ipv6 firewall filter add chain=input action=drop
/ip firewall raw
add chain=prerouting action=drop src-address=198.51.100.1
"""
    rules, lists = parse_routeros_script(script)
    assert [(r.table, r.family) for r in rules] == [("nat", "ipv6"), ("filter", "ipv6"), ("raw", "ipv4")]
    assert set(lists) == {"V6", "V4"}
    text = export_to_routeros(rules, lists)
    assert "/ipv6 firewall nat" in text and "/ipv6 firewall filter" in text
    assert "/ip firewall raw" in text
    assert "/ipv6 firewall address-list" in text


def test_print_with_wrapped_continuation_lines():
    script = """Flags: X - disabled, I - invalid, D - dynamic
 0    chain=input action=accept protocol=tcp
      dst-port=22 src-address=192.0.2.5 connection-state=new
 1 X  ;;; blocked scan
      chain=forward action=drop protocol=tcp
      tcp-flags=syn,!ack in-interface=ether1
 2    chain=forward action=accept
"""
    rules, _ = parse_routeros_script("/ip firewall filter\n" + script)
    assert len(rules) == 3
    assert rules[0].conditions.dst_port == "22"
    assert rules[0].conditions.src_address == "192.0.2.5"
    assert rules[0].conditions.connection_state == ["new"]
    assert not rules[0].disabled
    assert rules[1].disabled
    assert rules[1].comment == "blocked scan"
    assert rules[1].conditions.in_interface == "ether1"
    assert rules[1].conditions.protocol == "tcp"
    assert rules[1].conditions.tcp_flags == ["syn", "ack"]  # mixed negation approximated
    assert any("mixed negation" in w for w in rules[1].parse_warnings)
    assert rules[2].action == "accept" and not rules[2].disabled


def test_escaped_quotes_in_comment():
    script = r'''/ip firewall filter
add chain=input action=accept comment="allow \"admin\" access; ok" protocol=tcp dst-port=22
'''
    rules, _ = parse_routeros_script(script)
    assert rules[0].comment == 'allow "admin" access; ok'
    assert rules[0].conditions.dst_port == "22"
    assert rules[0].conditions.protocol == "tcp"


def test_exporter_escapes_quotes_in_comment():
    rule = FirewallRule(id="1", chain="input", action="accept", comment='say "hi" \\ now')
    text = export_to_routeros([rule], {})
    assert 'comment="say \\"hi\\" \\\\ now"' in text
    back, _ = parse_routeros_script(text)
    assert back[0].comment == 'say "hi" \\ now'


def test_unsupported_matchers_warn():
    script = """/ip firewall filter
add chain=input action=accept protocol=icmp icmp-options=8:0 dst-address-type=local layer7-protocol=l7 connection-mark=c1 routing-mark=r1 content=abc psd=21,3s,3,1
add chain=input action=accept protocol=tcp
"""
    rules, _ = parse_routeros_script(script)
    joined = " | ".join(rules[0].parse_warnings)
    for key in ("icmp-options=8:0", "dst-address-type=local", "layer7-protocol=l7",
                "connection-mark=c1", "routing-mark=r1", "content=abc", "psd="):
        assert f"unsupported matcher {key}" in joined
    assert "rule matches more broadly" in joined
    assert rules[1].parse_warnings == []


def test_in_interface_and_list_kept_separately_and_round_trip():
    script = """/ip firewall filter
add chain=input action=drop in-interface=ether1 in-interface-list=WAN out-interface-list=!LAN
"""
    rules, lists = parse_routeros_script(script)
    c = rules[0].conditions
    assert c.in_interface == "ether1"
    assert c.in_interface_list == "WAN"
    assert c.out_interface_list == "LAN" and c.negate_out_interface_list
    assert not rules[0].parse_warnings
    exported = export_to_routeros(rules, lists)
    assert "in-interface-list=WAN" in exported
    assert "out-interface-list=!LAN" in exported
    assert "in-interface=WAN" not in exported


def test_policy_rule_exported_last_as_drop():
    rules = [
        FirewallRule(id="p", order=1, chain="forward", action="drop", is_policy=True),
        FirewallRule(id="a", order=2, chain="forward", action="accept", comment="allow"),
        FirewallRule(id="v6", order=3, chain="input", action="accept", family="ipv6"),
    ]
    text = export_to_routeros(rules, {})
    lines = [l for l in text.splitlines() if l.startswith("add")]
    assert lines[0].startswith("add chain=forward action=accept")
    assert lines[1] == 'add chain=forward action=drop comment="default policy"'
    assert "/ipv6 firewall filter" in text
    back, _ = parse_routeros_script(text)
    assert back[1].comment == "default policy" and back[1].action == "drop"


def test_exporter_emits_all_condition_fields():
    cond = RuleCondition(
        port="53", connection_nat_state="dstnat", negate_connection_nat_state=True,
        limit="10,5:packet", ipsec_policy="out,none", packet_mark="m1",
        connection_state=["new"], negate_connection_state=True,
        tcp_flags=["syn"], negate_tcp_flags=True, protocol="tcp",
    )
    rule = FirewallRule(id="1", chain="forward", action="add-dst-to-address-list",
                        address_list_target="L", address_list_timeout="1h", conditions=cond)
    text = export_to_routeros([rule], {})
    for frag in ("port=53", "connection-nat-state=!dstnat", "limit=10,5:packet",
                 "ipsec-policy=out,none", "packet-mark=m1", "connection-state=!new",
                 "tcp-flags=!syn", "address-list=L", "address-list-timeout=1h"):
        assert frag in text, frag
