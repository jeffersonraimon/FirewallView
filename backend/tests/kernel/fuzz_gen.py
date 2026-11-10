"""Mode B: seeded random FirewallRule sets -> exporters -> kernel, simulator runs on the ORIGINAL rules.

Feature subset (what both exporters, the simulator and the Linux kernel can express):
  tables/chains : filter input / forward (+ policy accept|drop), one custom filter chain (jump / return),
                  nat dstnat (dst-nat, redirect) and srcnat (src-nat, masquerade); IPv4 NAT only
  conditions    : src/dst address (host, CIDR, 2-item list, optionally negated; IPv4 or IPv6, family set
                  accordingly), protocol tcp / udp / icmp, dst/src port (single, range, list, negated),
                  in/out interface (ether2-lan / ether1-wan, optionally negated, only where the hook has it),
                  connection_state ["new"], and (nftables only, every 4th ruleset) address ranges a-b and address lists (nft sets),
                  connection_state new / established,related / negated new
  actions       : accept, drop, reject, jump, return
Not generated (covered by the hand-written corpus or out of scope): marks, address lists / sets, tcp flags,
limit, IPv6 NAT, netmap, output chain, established/related.
"""
import random
from typing import List

from firewallview.exporters.iptables import export_to_iptables
from firewallview.exporters.nftables import export_to_nftables
from firewallview.models.address_list import AddressList, AddressListEntry
from firewallview.models.rules import FirewallRule, RuleCondition

from kernel_harness import Case, gen_packets

LAN, WAN = "ether2-lan", "ether1-wan"
HOSTS4 = ["192.168.1.50", "192.168.1.100", "203.0.113.10", "203.0.113.20", "198.51.100.7", "192.0.2.77"]
NETS4 = ["192.168.1.0/24", "192.168.1.64/26", "203.0.113.0/25", "198.51.100.0/24", "192.0.2.0/24", "203.0.113.16/28"]
HOSTS6 = ["fd00:1::50", "fd00:1::64", "2001:db8:1::10", "2001:db8:2::5"]
NETS6 = ["fd00:1::/64", "2001:db8:1::/64", "2001:db8:2::/48", "fd00:1::40/122"]
RANGES4 = ["192.168.1.64-192.168.1.127", "203.0.113.10-203.0.113.30", "198.51.100.5-198.51.100.9"]
PORTS = ["22", "53", "80", "123", "443", "8080", "1000-2000", "8000-8100", "5000-5010", "80,443", "22,8080"]


class _Gen:
    def __init__(self, rng: random.Random, ranges: bool):
        self.rng, self.ranges = rng, ranges
        self.rules: List[FirewallRule] = []
        self.used_range = False
        self.lists = {}          # address lists (nftables sets); only generated together with `ranges`
        self.used_list = False

    def addr(self, v6: bool, allow_range: bool = True) -> str:
        r = self.rng
        k = r.random()
        if not v6 and allow_range and self.ranges and k < 0.12:
            self.used_range = True
            return r.choice(RANGES4)
        hosts, nets = (HOSTS6, NETS6) if v6 else (HOSTS4, NETS4)
        if k < 0.45:
            return r.choice(hosts)
        if k < 0.85:
            return r.choice(nets)
        return ",".join(r.sample(hosts + nets, 2))

    def cond(self, chain: str, custom: bool = False) -> (RuleCondition, str):
        r = self.rng
        c = RuleCondition()
        fam = r.choices([None, "ipv4", "ipv6"], [3, 5, 2])[0]
        v6 = fam == "ipv6"
        if fam and r.random() < 0.55:
            c.src_address = self.addr(v6)
            c.negate_src_address = r.random() < 0.2
        if fam and r.random() < 0.5:
            c.dst_address = self.addr(v6)
            c.negate_dst_address = r.random() < 0.2
        if self.ranges and fam == "ipv4" and r.random() < 0.3:
            nm = r.choice(["fz_a", "fz_b"])
            if nm not in self.lists:
                ents = r.sample(HOSTS4 + NETS4, 3)
                self.lists[nm] = AddressList(name=nm, entries=[AddressListEntry(address=e) for e in ents])
            self.used_list = True
            if r.random() < 0.5:
                c.src_address, c.src_address_list = None, nm
                c.negate_src_address_list = r.random() < 0.3
            else:
                c.dst_address, c.dst_address_list = None, nm
                c.negate_dst_address_list = r.random() < 0.3
        proto = r.choices([None, "tcp", "udp", "icmp"], [2, 5, 3, 1])[0]
        if proto in ("tcp", "udp") and r.random() < 0.75:
            if r.random() < 0.8:
                c.dst_port = r.choice(PORTS)
                c.negate_dst_port = r.random() < 0.15
            if r.random() < 0.2:
                c.src_port = r.choice(PORTS[:5] + ["1000-2000"])
                c.negate_src_port = r.random() < 0.2
            if c.dst_port is None and c.src_port is None and r.random() < 0.3:
                c.port = r.choice(PORTS[:6])      # either direction
        if proto == "icmp" and fam == "ipv6":
            proto = "icmpv6"
        c.protocol = proto
        if proto and not (c.dst_port or c.src_port or c.port) and r.random() < 0.15:
            c.negate_protocol = True
        if not custom:
            ifs = {"input": ["in"], "dstnat": ["in"], "srcnat": ["out"], "forward": ["in", "out"]}[chain]
            for d in ifs:
                if r.random() < 0.3:
                    setattr(c, f"{d}_interface", r.choice([LAN, WAN]))
                    setattr(c, f"negate_{d}_interface", r.random() < 0.2)
        k = r.random()
        if k < 0.08:
            c.connection_state = ["new"]
        elif k < 0.12:
            c.connection_state = ["established", "related"]
        elif k < 0.14:
            c.connection_state = ["new"]
            c.negate_connection_state = True
        return c, fam

    def add(self, **kw):
        n = len(self.rules) + 1
        self.rules.append(FirewallRule(id=str(n), order=n, **kw))

    def filter_rule(self, chain: str, table="filter", custom=False, jump_to=None, allow_return=False):
        r = self.rng
        c, fam = self.cond(chain, custom=custom)
        acts = ["accept", "drop", "reject"]
        w = [5, 5, 1]
        if jump_to:
            acts.append("jump"); w.append(3)
        if allow_return:
            acts.append("return"); w.append(3)
        act = r.choices(acts, w)[0]
        kw = dict(table="filter", chain=chain, family=fam, action=act, conditions=c)
        if act == "jump":
            kw["target_chain"] = jump_to
        self.add(**kw)

    def nat_rule(self, chain: str):
        r = self.rng
        c = RuleCondition()
        c.protocol = r.choice([None, "tcp", "udp"])
        if c.protocol and r.random() < 0.7:
            c.dst_port = r.choice(["22", "53", "80", "443", "8080", "1000-2000", "80,443"])
        if r.random() < 0.5:
            c.dst_address = r.choice(HOSTS4 + ["203.0.113.1"] + NETS4[:3])
        if r.random() < 0.4:
            c.src_address = r.choice(NETS4[:4])
        if chain == "dstnat":
            if r.random() < 0.5:
                c.in_interface = r.choice([LAN, WAN])
            if r.random() < 0.8 or not c.protocol:
                tgt = r.choice(["192.168.1.50", "192.168.1.100", "203.0.113.20"])
                ports = r.choice([None, "80", "8080", "22"]) if c.protocol else None
                self.add(table="nat", chain="dstnat", family="ipv4", action="dst-nat",
                         nat_to_addresses=tgt, nat_to_ports=ports, conditions=c)
            elif c.protocol:
                c.dst_port = c.dst_port or "80"
                self.add(table="nat", chain="dstnat", family="ipv4", action="redirect",
                         nat_to_ports=r.choice(["8080", "3128"]), conditions=c)
        else:
            if r.random() < 0.6:
                c.out_interface = WAN
            if r.random() < 0.5:
                self.add(table="nat", chain="srcnat", family="ipv4", action="masquerade", conditions=c)
            else:
                self.add(table="nat", chain="srcnat", family="ipv4", action="src-nat",
                         nat_to_addresses=r.choice(["203.0.113.1", "203.0.113.50"]), conditions=c)


def make_rules(rng: random.Random, ranges: bool):
    g = _Gen(rng, ranges)
    custom = "fz_chain" if rng.random() < 0.6 else None
    for chain, lo, hi in (("dstnat", 0, 2), ("srcnat", 0, 2)):
        for _ in range(rng.randint(lo, hi)):
            g.nat_rule(chain)
    for chain, lo, hi in (("input", 1, 4), ("forward", 3, 7)):
        for _ in range(rng.randint(lo, hi)):
            g.filter_rule(chain, jump_to=custom)
    if custom:
        for _ in range(rng.randint(1, 3)):
            g.filter_rule(custom, custom=True, allow_return=True)
    for chain in ("input", "forward"):
        g.add(table="filter", chain=chain, is_policy=True, action=rng.choice(["accept", "drop"]),
              conditions=RuleCondition())
    return g.rules, g.used_range or g.used_list, g.lists


def build_cases(n_rulesets: int, n_packets: int, seed: int) -> List[Case]:
    cases: List[Case] = []
    for i in range(n_rulesets):
        rng = random.Random(f"fuzz:{seed}:{i}")
        rules, used_range, lists = make_rules(rng, ranges=(i % 4 == 0))
        pk = gen_packets(rules, lists, rng, k_random=max(4, n_packets // 3), k_cap=n_packets)
        nft_text = export_to_nftables(rules, lists)
        cases.append(Case(name=f"fuzz{seed}_{i:03d}_nft", backend="nft", kernel={"nft": nft_text},
                          packets=[dict(p) for p in pk], rules=rules, address_lists=lists, source="fuzz",
                          meta=dict(export_notes=[ln for ln in nft_text.splitlines() if "NOT EXPORTED" in ln])))
        if used_range:
            continue  # no address ranges (-m iprange) / no ipset in the kernel: this ruleset is nft-only
        # ip6tables-legacy is unavailable in the WSL2 kernel, so the exported script always runs on iptables-nft
        ipt_text = export_to_iptables(rules, {})
        cases.append(Case(name=f"fuzz{seed}_{i:03d}_ipt", backend="iptables-nft", kernel={"script": ipt_text},
                          packets=[dict(p) for p in pk], rules=rules, address_lists={}, source="fuzz",
                          meta=dict(export_notes=[ln for ln in ipt_text.splitlines() if "unsupported" in ln])))
    return cases
