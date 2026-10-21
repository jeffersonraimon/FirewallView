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

