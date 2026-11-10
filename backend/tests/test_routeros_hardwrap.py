"""Terminal copies hard-wrap long RouterOS lines at a fixed column, even mid-token."""
from firewallview.parsers.routeros import parse_routeros_script

WRAPPED = (
    "/ip firewall address-list add address=198.51.100.7 list=ALLOWED\n"
    "/ip firewall filter add action=add-src-to-address-list address-list=k2 address-list-timeout=15s "
    "chain=input comment=\"KNOCK 2\" dst-port=18967 in-interface-list=WAN protocol=udp src-address-list=k-on\n"
    "e\n"
    "/ip firewall filter add action=add-src-to-address-list address-list=ALLOWED chain=input dst-port=17840 "
    "in-interface-list=WAN protocol=tcp src-address-\n"
    "list=k2\n"
    "/ip firewall filter add action=add-src-to-address-list address-list=SCAN chain=input "
    "dst-port=20-25,80,443 in-interface-list=WAN\n"
    " protocol=tcp src-address-list=!ALLOWED\n"
    "/ip firewall filter add action=drop chain=input dst-port=500,1701 protocol=udp src-addre\n"
    "ss-list=!ALLOWED\n"
)


def test_hard_wrapped_terminal_copy_is_rejoined():
    rules, lists = parse_routeros_script(WRAPPED)
    assert list(lists) == ["ALLOWED"]
    assert len(rules) == 4
    assert all(not r.parse_warnings for r in rules), [r.parse_warnings for r in rules]
    c0, c1, c2, c3 = (r.conditions for r in rules)
    assert c0.src_address_list == "k-one"
    assert c1.src_address_list == "k2"
    assert c2.protocol == "tcp" and c2.src_address_list == "ALLOWED" and c2.negate_src_address_list
    assert c3.src_address_list == "ALLOWED" and c3.negate_src_address_list


def test_backslash_continuation_and_menu_blocks_unchanged():
    script = (
        "/ip firewall filter\n"
        "add action=accept chain=input comment=\"a\" \\\n"
        "    protocol=tcp dst-port=22\n"
        "add action=drop chain=input\n"
    )
    rules, _ = parse_routeros_script(script)
    assert len(rules) == 2
    assert rules[0].conditions.protocol == "tcp" and rules[0].conditions.dst_port == "22"
    assert rules[1].action == "drop"


def test_stray_bare_token_is_warned():
    rules, _ = parse_routeros_script("/ip firewall filter add chain=input action=drop protocol=tcp stray\n")
    assert any("stray" in w for w in rules[0].parse_warnings)
