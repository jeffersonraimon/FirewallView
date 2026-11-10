"""Mode B for RouterOS: seeded random FirewallRule sets -> export_to_routeros -> CHR; the simulator runs on the ORIGINAL rules.

Reuses the generator of tests/kernel/fuzz_gen (IPv4 rules only, since the lab is IPv4) and adds RouterOS-only
features: interface lists, mangle packet marks + filter on packet-mark, address-lists (always on, RouterOS has
native ranges / lists).  Subset: filter input/forward (+ policy as final rule), one custom chain with jump/return,
dstnat (dst-nat, redirect) / srcnat (src-nat, masquerade), mangle mark-packet; accept/drop/reject.
"""
import random
from typing import List

from firewallview.exporters.routeros import export_to_routeros
from firewallview.models.rules import FirewallRule, RuleCondition

import fuzz_gen
from kernel_harness import Case, gen_packets


def _extras(rng: random.Random, rules: List[FirewallRule]) -> List[FirewallRule]:
    out = list(rules)
    # interface-list variants
    for r in out:
        c = r.conditions
        for d in ("in", "out"):
            ifc = getattr(c, f"{d}_interface")
            if ifc and rng.random() < 0.4:
                setattr(c, f"{d}_interface", None)
                setattr(c, f"{d}_interface_list", "WAN" if ifc == fuzz_gen.WAN else "LAN")
    # mangle mark + a filter rule on the mark (placed before the policy rule of forward / input)
    if rng.random() < 0.5:
        mc = RuleCondition(protocol=rng.choice(["tcp", "udp"]), dst_port=rng.choice(["80", "443", "1000-2000", "22"]))
        if rng.random() < 0.5:
            mc.src_address = rng.choice(fuzz_gen.NETS4[:4])
        out.append(FirewallRule(id="m1", order=0, table="mangle", chain="prerouting", family="ipv4",
                                action="mark-packet", mark_value="fzmark", conditions=mc))
        fc = RuleCondition(packet_mark="fzmark", negate_packet_mark=rng.random() < 0.3)
        out.append(FirewallRule(id="m2", order=0, table="filter", chain=rng.choice(["forward", "input"]),
                                family="ipv4", action=rng.choice(["drop", "accept"]), conditions=fc))
    return out


def _renumber(rules: List[FirewallRule]) -> List[FirewallRule]:
    pol = [r for r in rules if r.is_policy]
    rest = [r for r in rules if not r.is_policy]
    out = rest + pol
    for i, r in enumerate(out, start=1):
        r.id, r.order = str(i), i
    return out


def _comma(r: FirewallRule) -> bool:
    c = r.conditions
    return any(a and "," in a for a in (c.src_address, c.dst_address))


def build_cases(n_rulesets: int, n_packets: int, seed: int) -> List[Case]:
    cases: List[Case] = []
    probe_done = False
    for i in range(n_rulesets):
        rng = random.Random(f"rosfuzz:{seed}:{i}")
        rules, _, lists = fuzz_gen.make_rules(rng, ranges=True)
        # the lab is IPv4-only: IPv6-only rules are dropped (they could not match any packet anyway)
        rules = [r for r in rules if r.family != "ipv6"]
        rules = _renumber(_extras(rng, rules))
        lists = {k: v for k, v in lists.items()}
        pk = gen_packets(rules, lists, rng, k_random=max(4, n_packets // 3), k_cap=n_packets, only_families=[4])
        text = export_to_routeros(rules, lists)
        suffix = ""
        if not probe_done and any(_comma(r) for r in rules):   # comma address lists are exported as address-lists
            probe_done = True
            suffix = "_comma_address_list"
        cases.append(Case(name=f"rosfuzz{seed}_{i:03d}{suffix}", source="fuzz", backend="routeros", rules=rules,
                          address_lists=lists, kernel={"rsc": text}, packets=[dict(p) for p in pk],
                          meta=dict(file="fuzz")))
    return cases
