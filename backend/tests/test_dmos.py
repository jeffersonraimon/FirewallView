from firewallview.parsers.dmos import parse_dmos_script
from firewallview.exporters.dmos import export_to_dmos
from firewallview.models.rules import FirewallRule, RuleCondition

MULTI = """
access-list
 protection
  cpu CPU-A
 !
 acl-profile cpu l3 CPU-A
  priority 0
  access-list-entry 10
   description CPU-SSH
   match destination-port ssh
   action permit
  !
  access-list-entry 20
   description CPU-DENY
   action deny
  !
 !
 acl-profile l3 TRANSIT-B
  priority 1
  access-list-entry 10
   description B-V4
   match source-ipv4-address 198.51.100.0/24
   match ip-protocol tcp
   action deny
  !
  access-list-entry 20
   description B-V6
   match source-ipv6-address 2001:db8::/32
   action permit
  !
 !
"""


def test_multiple_profiles_get_own_chain_and_unique_ids():
    rules, _ = parse_dmos_script(MULTI)
    assert len(rules) == 4
    assert len({r.id for r in rules}) == 4
    assert [r.order for r in rules] == [1, 2, 3, 4]
    chains = [r.chain for r in rules]
    assert chains == ["input", "input", "TRANSIT-B", "TRANSIT-B"]

    assert rules[2].id == "TRANSIT-B-10"
    assert rules[0].id == "CPU-A-10"


def test_ipv6_family_and_ipv4_family():
    rules, _ = parse_dmos_script(MULTI)
    by = {r.comment: r for r in rules}
    assert by["B-V4"].family == "ipv4"
    assert by["B-V6"].family == "ipv6"
    assert by["B-V6"].conditions.src_address == "2001:db8::/32"
    assert by["CPU-SSH"].family is None


def test_unknown_match_warns():
    rules, _ = parse_dmos_script("""
 acl-profile l3 P
  access-list-entry 10
   match vlan-id 100
   match destination-port range 1 10
   frobnicate yes
   action permit
  !
""")
    w = " ".join(rules[0].parse_warnings)
    assert "vlan-id" in w
    assert "Extra tokens" in w
    assert "frobnicate" in w
    assert rules[0].chain == "P"


def test_unique_seq_across_profiles_keeps_plain_id():
    rules, _ = parse_dmos_script("""
 acl-profile l3 A
  access-list-entry 10
   action permit
  !
 acl-profile l3 B
  access-list-entry 20
   action deny
  !
""")
    assert [r.id for r in rules] == ["10", "20"]


def test_exporter_one_profile_per_chain_and_unsupported():
    rules = [
        FirewallRule(id="1", order=1, chain="input", action="accept",
                     conditions=RuleCondition(protocol="tcp", dst_port="22")),
        FirewallRule(id="2", order=2, chain="forward", action="drop",
                     conditions=RuleCondition(src_address="198.51.100.0/24", negate_src_address=True)),
        FirewallRule(id="3", order=3, chain="forward", action="drop",
                     conditions=RuleCondition(dst_port="80,443", protocol="tcp")),
        FirewallRule(id="4", order=4, chain="forward", action="accept", family="ipv6",
                     conditions=RuleCondition(dst_address="2001:db8::1/128")),
        FirewallRule(id="5", order=5, chain="forward", action="accept", family="ipv6"),
    ]
    out = export_to_dmos(rules, {})
    assert out.count("acl-profile") == 2
    assert "match destination-ipv6-address 2001:db8::1/128" in out
    assert out.count("! UNSUPPORTED:") == 3
    assert "negat" in out
    # nothing broader exported for rule 2/3/5
    assert out.count("access-list-entry") == 2


def test_roundtrip_preserves_entries_and_order():
    rules, _ = parse_dmos_script(MULTI)
    out = export_to_dmos(rules, {})
    rules2, _ = parse_dmos_script(out)
    # CPU profiles merge into 'input'; ids may re-prefix, but entries/order stay
    assert [r.comment for r in rules2] == [r.comment for r in rules]
    assert [r.action for r in rules2] == [r.action for r in rules]
    assert [r.family for r in rules2] == [r.family for r in rules]
    assert [r.chain for r in rules2] == [r.chain for r in rules]
    # CPU profile name is normalised on export; sequence numbers are kept
    assert [r.id.rsplit('-', 1)[-1] for r in rules2] == [r.id.rsplit('-', 1)[-1] for r in rules]
    rules3, _ = parse_dmos_script(export_to_dmos(rules2, {}))
    assert [r.id for r in rules3] == [r.id for r in rules2]
    assert [r.conditions.dst_port for r in rules2] == [r.conditions.dst_port for r in rules]
    assert [r.conditions.src_address for r in rules2] == [r.conditions.src_address for r in rules]
    assert len({r.id for r in rules2}) == len(rules2)
