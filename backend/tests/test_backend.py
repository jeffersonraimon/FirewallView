import pytest
from firewallview.parsers.routeros import parse_routeros_script
from firewallview.parsers.iptables import parse_iptables_script
from firewallview.parsers.cisco import parse_cisco_acl
from firewallview.parsers.nftables import parse_nftables_script
from firewallview.models.packet import SimulationPacket
from firewallview.engine.simulator import FirewallSimulator
from firewallview.samples.presets import PRESET_ROUTEROS, PRESET_IPTABLES, PRESET_CISCO

def test_routeros_parser_and_simulation():
    rules, addr_lists = parse_routeros_script(PRESET_ROUTEROS)
    assert len(rules) > 5
    assert "BOGONS" in addr_lists
    assert "TRUSTED_ADMINS" in addr_lists

    # Test 1: Bogon IP from WAN should be DROPPED
    pkt_bogon = SimulationPacket(
        src_ip="10.5.5.5", # in BOGONS
        dst_ip="192.168.88.50",
        src_port=44444,
        dst_port=80,
        protocol="tcp",
        in_interface="ether1-wan",
        out_interface="ether2-lan"
    )
    sim = FirewallSimulator(rules, addr_lists)
    res = sim.simulate(pkt_bogon)
    assert res.verdict == "DROP"

    # Test 2: Admin accessing SSH to router input should be ACCEPTED
    pkt_admin = SimulationPacket(
        src_ip="192.168.88.5", # in TRUSTED_ADMINS
        dst_ip="192.168.88.1",
        src_port=55555,
        dst_port=22,
        protocol="tcp",
        in_interface="ether2-lan",
        is_router_traffic=True
    )
    res2 = sim.simulate(pkt_admin)
    assert res2.verdict == "ACCEPT"

def test_iptables_parser():
    rules, addr_lists = parse_iptables_script(PRESET_IPTABLES)
    assert len(rules) > 5
    assert "BAD_ACTORS" in addr_lists

    # Bad actor input dropped
    pkt_bad = SimulationPacket(
        src_ip="198.51.100.10",
        dst_ip="1.2.3.4",
        src_port=1234,
        dst_port=80,
        protocol="tcp",
        in_interface="eth0",
        is_router_traffic=True
    )
    sim = FirewallSimulator(rules, addr_lists)
    res = sim.simulate(pkt_bad)
    assert res.verdict == "DROP"

def test_cisco_parser():
    rules, addr_lists = parse_cisco_acl(PRESET_CISCO)
    assert len(rules) > 3
    assert "BLOCKED_SUBNETS" in addr_lists

def test_nftables_parser():
    nft_text = """
    table inet filter {
        set blacklist {
            type ipv4_addr
            elements = { 10.10.10.10 }
        }
        chain input {
            ip saddr @blacklist drop
            tcp dport 22 accept
        }
    }
    """
    rules, sets = parse_nftables_script(nft_text)
    assert len(rules) == 2
    assert "blacklist" in sets

    pkt = SimulationPacket(
        src_ip="10.10.10.10",
        dst_ip="192.168.1.1",
        src_port=55000,
        dst_port=22,
        protocol="tcp",
        is_router_traffic=True
    )
    sim = FirewallSimulator(rules, sets)
    res = sim.simulate(pkt)
    assert res.verdict == "DROP"

def test_junos_parser_and_simulation():
    from firewallview.parsers.junos import parse_junos_script
    from firewallview.samples.presets import PRESET_JUNOS

    rules, addr_lists = parse_junos_script(PRESET_JUNOS)
    assert len(rules) >= 4
    assert "BLOCKED_PREFIXES" in addr_lists
    assert "NOC_ADMINS" in addr_lists

    # Test 1: Bogon IP dropped by drop-bogons term
    pkt_bogon = SimulationPacket(
        src_ip="10.20.30.40",
        dst_ip="1.1.1.1",
        src_port=50000,
        dst_port=80,
        protocol="tcp"
    )
    sim = FirewallSimulator(rules, addr_lists)
    res = sim.simulate(pkt_bogon)
    assert res.verdict == "DROP"

    # Test 2: SSH from NOC Admin allowed
    pkt_admin = SimulationPacket(
        src_ip="192.168.88.10",
        dst_ip="192.168.88.1",
        src_port=52345,
        dst_port=22,
        protocol="tcp"
    )
    res_admin = sim.simulate(pkt_admin)
    assert res_admin.verdict == "ACCEPT"

def test_output_flow_simulation():
    from firewallview.models.rules import FirewallRule, RuleCondition
    rules = [
        FirewallRule(
            id="1",
            order=1,
            table="filter",
            chain="output",
            action="drop",
            conditions=RuleCondition(protocol="tcp", dst_port="23"),
            comment="Block telnet output from router"
        ),
        FirewallRule(
            id="2",
            order=2,
            table="filter",
            chain="output",
            action="accept",
            conditions=RuleCondition(protocol="udp", dst_port="53"),
            comment="Allow DNS output from router"
        )
    ]
    sim = FirewallSimulator(rules, {})

    # Telnet from router dropped in OUTPUT filter
    pkt_telnet = SimulationPacket(
        src_ip="192.168.88.1",
        dst_ip="8.8.8.8",
        src_port=45000,
        dst_port=23,
        protocol="tcp",
        flow_type="output"
    )
    res1 = sim.simulate(pkt_telnet)
    assert res1.verdict == "DROP"

    # DNS from router accepted in OUTPUT filter
    pkt_dns = SimulationPacket(
        src_ip="192.168.88.1",
        dst_ip="1.1.1.1",
        src_port=45001,
        dst_port=53,
        protocol="udp",
        flow_type="output"
    )
    res2 = sim.simulate(pkt_dns)
    assert res2.verdict == "ACCEPT"

def test_routeros_oneliners_and_multiline():
    raw_script = r"""
    /ip firewall address-list add list=TEST_LIST address=192.168.10.0/24 comment="Office"
    /ip firewall filter add chain=input action=accept protocol=tcp dst-port=22 comment="SSH Admin"
    /ip firewall filter add chain=forward action=drop in-interface=ether1-wan comment=\
        "Drop WAN invalid" connection-state=\
        invalid
    /ip firewall nat add chain=srcnat action=masquerade out-interface=ether1-wan
    """
    rules, addr_lists = parse_routeros_script(raw_script)
    assert len(rules) == 3
    assert "TEST_LIST" in addr_lists
    assert rules[0].chain == "input"
    assert rules[0].action == "accept"
    assert rules[0].comment == "SSH Admin"
    assert rules[1].chain == "forward"
    assert rules[1].action == "drop"
    assert rules[1].conditions.connection_state == ["invalid"]
    assert rules[2].table == "nat"
    assert rules[2].chain == "srcnat"
    assert rules[2].action == "masquerade"

def test_routeros_port_parameter_and_protocol_filtering():
    raw_script = """
    /ip firewall filter add action=accept chain=input comment=ACCEPT-WIREGUARD port=13231 protocol=udp
    /ip firewall filter add action=drop chain=input
    """
    rules, addr_lists = parse_routeros_script(raw_script)
    assert len(rules) == 2
    assert rules[0].conditions.port == "13231"

    sim = FirewallSimulator(rules, addr_lists)

    # 1. Packet to port 53 (DNS) must NOT match WireGuard port 13231 -> should be dropped
    pkt_dns = SimulationPacket(
        src_ip="203.0.113.50",
        dst_ip="198.51.100.1",
        src_port=54321,
        dst_port=53,
        protocol="udp",
        flow_type="input",
        is_router_traffic=True
    )
    res_dns = sim.simulate(pkt_dns)
    assert res_dns.verdict == "DROP"

    # 2. Packet to port 13231 (WireGuard) matches and is ACCEPTED
    pkt_wg = SimulationPacket(
        src_ip="203.0.113.50",
        dst_ip="198.51.100.1",
        src_port=54321,
        dst_port=13231,
        protocol="udp",
        flow_type="input",
        is_router_traffic=True
    )
    res_wg = sim.simulate(pkt_wg)
    assert res_wg.verdict == "ACCEPT"

    # 3. ICMP packet must NOT match port-specific rule
    pkt_icmp = SimulationPacket(
        src_ip="203.0.113.50",
        dst_ip="198.51.100.1",
        src_port=0,
        dst_port=0,
        protocol="icmp",
        flow_type="input",
        is_router_traffic=True
    )
    res_icmp = sim.simulate(pkt_icmp)
    assert res_icmp.verdict == "DROP"

def test_connection_nat_state_and_dynamic_address_list():
    raw_script = """
    /ip firewall nat add action=dst-nat chain=dstnat dst-port=8080 protocol=tcp to-addresses=192.168.1.100 to-ports=80
    /ip firewall filter add action=add-src-to-address-list address-list=PORTSCAN address-list-timeout=3d chain=forward dst-port=23 protocol=tcp
    /ip firewall filter add action=drop chain=forward comment="DROP ALL NOT DSTNATED" connection-nat-state=!dstnat in-interface-list=WAN
    /ip firewall filter add action=accept chain=forward
    """
    rules, addr_lists = parse_routeros_script(raw_script)
    assert len(rules) == 4
    assert rules[1].action == "add-src-to-address-list"
    assert rules[1].address_list_target == "PORTSCAN"
    assert rules[2].conditions.connection_nat_state == "dstnat"
    assert rules[2].conditions.negate_connection_nat_state is True

    sim = FirewallSimulator(rules, addr_lists)

    # Packet without DSTNAT from WAN -> should be dropped by DROP ALL NOT DSTNATED
    pkt_non_dstnat = SimulationPacket(
        src_ip="203.0.113.5",
        dst_ip="198.51.100.1",
        src_port=50000,
        dst_port=9999,
        protocol="tcp",
        in_interface="WAN",
        out_interface="LAN",
        flow_type="forward"
    )
    res1 = sim.simulate(pkt_non_dstnat)
    assert res1.verdict == "DROP"
    assert res1.matched_rule_id == rules[2].id

    # Packet with port 8080 gets DSTNAT -> bypasses connection-nat-state=!dstnat and gets ACCEPTED
    pkt_dstnat = SimulationPacket(
        src_ip="203.0.113.5",
        dst_ip="198.51.100.1",
        src_port=50000,
        dst_port=8080,
        protocol="tcp",
        in_interface="WAN",
        out_interface="LAN",
        flow_type="forward"
    )
    res2 = sim.simulate(pkt_dstnat)
    assert res2.verdict == "ACCEPT"
    assert res2.packet_out.dst_port == 80
    assert res2.packet_out.dst_ip == "192.168.1.100"

    # Packet hitting port 23 adds source to PORTSCAN list dynamically
    pkt_scan = SimulationPacket(
        src_ip="198.51.100.99",
        dst_ip="198.51.100.1",
        src_port=51111,
        dst_port=23,
        protocol="tcp",
        in_interface="LAN",
        out_interface="LAN",
        flow_type="forward"
    )
    sim.simulate(pkt_scan)
    assert "PORTSCAN" in sim.address_lists
    assert any(e.address == "198.51.100.99" for e in sim.address_lists["PORTSCAN"].entries)

def test_ipv6_firewall_parser():
    raw_script = """
    /ipv6 firewall address-list add address=2001:db8:1000::/48 list=V6-DOCS-NET
    /ipv6 firewall filter add action=accept chain=input comment="ACCEPT DHCPV6 CLIENT" in-interface-list=WAN port=546,547 protocol=udp
    /ipv6 firewall filter add action=drop chain=forward comment="DROP NEW" connection-state=new in-interface-list=WAN
    """
    rules, addr_lists = parse_routeros_script(raw_script)
    assert len(rules) == 2
    assert "V6-DOCS-NET" in addr_lists
    assert rules[0].chain == "input"
    assert rules[0].conditions.port == "546,547"
    assert rules[1].chain == "forward"
    assert rules[1].action == "drop"

def test_junos_advanced_features_and_simulation():
    from firewallview.parsers.junos import parse_junos_script
    raw_script = """
    set policy-options prefix-list bgp-peers 198.51.100.10/32
    set policy-options prefix-list bgp-peers 198.51.100.11/32
    set policy-options prefix-list dynamic-peers apply-path "protocols bgp group <*> neighbor <*>"
    
    set firewall family inet filter accept-icmp term allow-ping from protocol icmp
    set firewall family inet filter accept-icmp term allow-ping then accept

    set firewall family inet filter protect-re term accept-bgp from source-prefix-list bgp-peers
    set firewall family inet filter protect-re term accept-bgp from protocol tcp
    set firewall family inet filter protect-re term accept-bgp from destination-port bgp
    set firewall family inet filter protect-re term accept-bgp then accept

    set firewall family inet filter protect-re term accept-icmp filter accept-icmp

    set firewall family inet filter protect-re term bfd from protocol udp
    set firewall family inet filter protect-re term bfd from destination-port 3784
    set firewall family inet filter protect-re term bfd from destination-port 3785
    set firewall family inet filter protect-re term bfd then accept

    set firewall family inet filter protect-re term tcp-mgmt from protocol tcp
    set firewall family inet filter protect-re term tcp-mgmt from port ssh
    set firewall family inet filter protect-re term tcp-mgmt from tcp-established
    set firewall family inet filter protect-re term tcp-mgmt then accept

    set firewall family inet filter protect-re term blocked-bad from protocol udp
    set firewall family inet filter protect-re term blocked-bad from destination-port 0
    set firewall family inet filter protect-re term blocked-bad then reject
    deactivate firewall family inet filter protect-re term blocked-bad

    set firewall family inet filter protect-re term discard-all then discard
    """
    rules, addr_lists = parse_junos_script(raw_script)

    assert "bgp-peers" in addr_lists
    assert len(addr_lists["bgp-peers"].entries) == 2
    assert "dynamic-peers" in addr_lists
    assert len(addr_lists["dynamic-peers"].entries) == 0 # apply-path safely handled

    # Check rule actions and conditions
    bgp_rule = next(r for r in rules if "accept-bgp" in r.comment)
    assert bgp_rule.conditions.dst_port == "179" # bgp resolved to 179

    jump_rule = next(r for r in rules if "accept-icmp" in r.comment and r.chain == "protect-re")
    assert jump_rule.action == "jump"
    assert jump_rule.target_chain == "accept-icmp"

    bfd_rule = next(r for r in rules if "bfd" in r.comment)
    assert "3784" in bfd_rule.conditions.dst_port
    assert "3785" in bfd_rule.conditions.dst_port

    mgmt_rule = next(r for r in rules if "tcp-mgmt" in r.comment)
    assert mgmt_rule.conditions.port == "22" # ssh resolved to 22 in port=
    assert "established" in mgmt_rule.conditions.connection_state

    deactivated_rule = next(r for r in rules if "blocked-bad" in r.comment)
    assert deactivated_rule.disabled is True

    sim = FirewallSimulator(rules, addr_lists)

    # 1. BGP from valid peer accepted by protect-re
    pkt_bgp = SimulationPacket(
        src_ip="198.51.100.10",
        dst_ip="192.0.2.1",
        src_port=51234,
        dst_port=179,
        protocol="tcp",
        flow_type="input",
        is_router_traffic=True
    )
    res_bgp = sim.simulate(pkt_bgp)
    assert res_bgp.verdict == "ACCEPT"

    # 2. ICMP jumps to accept-icmp subfilter and gets ACCEPTED
    pkt_icmp = SimulationPacket(
        src_ip="203.0.113.88",
        dst_ip="192.0.2.1",
        src_port=0,
        dst_port=0,
        protocol="icmp",
        flow_type="input",
        is_router_traffic=True
    )
    res_icmp = sim.simulate(pkt_icmp)
    assert res_icmp.verdict == "ACCEPT"

    # 3. Port 0 packet would be rejected by blocked-bad, but because it is DEACTIVATED, it falls through to discard-all
    pkt_zero = SimulationPacket(
        src_ip="203.0.113.88",
        dst_ip="192.0.2.1",
        src_port=12345,
        dst_port=0,
        protocol="udp",
        flow_type="input",
        is_router_traffic=True
    )
    res_zero = sim.simulate(pkt_zero)
    assert res_zero.verdict == "DROP" # dropped by discard-all, not rejected by blocked-bad

    # 4. Unknown random traffic dropped by discard-all
    pkt_telnet = SimulationPacket(
        src_ip="203.0.113.99",
        dst_ip="192.0.2.1",
        src_port=40000,
        dst_port=23,
        protocol="tcp",
        flow_type="input",
        is_router_traffic=True
    )
    res_telnet = sim.simulate(pkt_telnet)
    assert res_telnet.verdict == "DROP"




