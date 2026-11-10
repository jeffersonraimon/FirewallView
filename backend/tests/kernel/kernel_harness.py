"""Pytest-side half of the kernel differential harness.

Builds cases (ruleset + packets), runs them through the real kernel (``kernel_lab.py`` inside
``unshare -Urnm``) and through the FirewallView simulator, and compares both.
See README.md for the design and the list of known limits.
"""
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from firewallview.engine.simulator import (MASQUERADE_PLACEHOLDER_V4, MASQUERADE_PLACEHOLDER_V6,
                                           ROUTER_PLACEHOLDER_V4, ROUTER_PLACEHOLDER_V6, FirewallSimulator)
from firewallview.models.packet import SimulationPacket

HERE = Path(__file__).resolve().parent
LAB = HERE / "kernel_lab.py"
LAN_IF, WAN_IF = "ether2-lan", "ether1-wan"
ROUTER_ADDRS = {"192.168.1.1", "203.0.113.1", "fd00:1::1", "2001:db8:1::1"}
PLACEHOLDERS = {MASQUERADE_PLACEHOLDER_V4, MASQUERADE_PLACEHOLDER_V6, ROUTER_PLACEHOLDER_V4, ROUTER_PLACEHOLDER_V6}
LAN_NETS = [ipaddress.ip_network("192.168.1.0/24"), ipaddress.ip_network("fd00:1::/64")]
WAN_NETS = [ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8:1::/64")]
FLOWS = ("fwd_lan_wan", "fwd_wan_lan", "input_lan", "input_wan")


# ----------------------------------------------------------------------------- environment
def skip_reason() -> Optional[str]:
    """Why the kernel suite cannot run here (None when it can)."""
    if not sys.platform.startswith("linux"):
        return "needs Linux"
    for tool in ("unshare", "nft", "ip", "iptables-nft-restore"):
        if shutil.which(tool) is None and shutil.which(tool, path="/usr/sbin:/sbin") is None:
            return f"{tool} not found"
    try:
        p = subprocess.run(["unshare", "-Urn", "true"], capture_output=True, timeout=20)
    except Exception as exc:  # pragma: no cover
        return f"unshare failed: {exc}"
    if p.returncode != 0:
        return "rootless namespaces unavailable (unshare -Urn true failed)"
    p = subprocess.run(["unshare", "-Urn", "nft", "list", "ruleset"], capture_output=True, timeout=20)
    if p.returncode != 0:
        return "nft does not work inside an unprivileged user namespace"
    return None


# ----------------------------------------------------------------------------- data classes
@dataclass
class Case:
    name: str
    source: str                      # corpus | fuzz
    backend: str                     # nft | iptables-nft | iptables-legacy
    rules: list                      # FirewallRule models seen by the simulator
    address_lists: dict
    kernel: dict                     # nft / ipt4 / ipt6 / script
    packets: List[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)   # directives, parser warnings, exporter notes


# ----------------------------------------------------------------------------- packet generation
def _ip(s):
    return ipaddress.ip_address(s)


def _usable(a) -> bool:
    if a.version == 4:
        return not (a.is_multicast or a.is_loopback or a.is_unspecified or a.is_link_local
                    or int(a) & 0xFF in (0, 255) or a.is_reserved)
    return not (a.is_multicast or a.is_loopback or a.is_unspecified or a.is_link_local)


def addr_samples(spec: Optional[str], lists: dict) -> List[str]:
    """Addresses inside and just outside of an address condition (ip / cidr / range / comma list)."""
    out: List[str] = []
    if not spec:
        return out
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (_ip(x.strip()) for x in part.split("-", 1))
                cands = [lo, hi, lo - 1, hi + 1, lo + (int(hi) - int(lo)) // 2]
            elif "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                cands = [net.network_address + 1, net.broadcast_address - 1 if net.version == 4 else net[-1],
                         net.network_address - 1, net.broadcast_address + 1 if net.version == 4 else net[-1] + 1]
                if net.num_addresses > 8:
                    cands.append(net.network_address + net.num_addresses // 2)
            else:
                a = _ip(part)
                cands = [a, a + 1, a - 1]
        except (ValueError, TypeError, ipaddress.AddressValueError):
            continue
        for a in cands:
            try:
                if _usable(a):
                    out.append(str(a))
            except Exception:
                pass
    return out


def port_samples(spec: Optional[str]) -> List[int]:
    out: List[int] = []
    if not spec:
        return out
    for part in str(spec).replace(":", "-").split(","):
        part = part.strip()
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                cands = [lo - 1, lo, (lo + hi) // 2, hi, hi + 1]
            else:
                p = int(part)
                cands = [p - 1, p, p + 1]
        except ValueError:
            continue
        out += [c for c in cands if 1 <= c <= 65535]
    return out


def _in_nets(addr: str, nets) -> bool:
    a = _ip(addr)
    return any(a in n for n in nets if n.version == a.version)


BASE = {
    # (family) -> pools
    4: dict(lan_src=["192.168.1.50", "192.168.1.100", "192.168.1.200"],
            wan_src=["203.0.113.10", "198.51.100.7", "192.0.2.77", "203.0.113.99"],
            odd_src=["10.9.9.9", "172.16.5.5"],
            to_wan=["203.0.113.10", "203.0.113.20", "198.51.100.7", "192.0.2.77"],
            to_lan=["192.168.1.50", "192.168.1.100", "192.168.1.200"],
            router_lan="192.168.1.1", router_wan="203.0.113.1"),
    6: dict(lan_src=["fd00:1::50", "fd00:1::64", "fd00:1::c8"],
            wan_src=["2001:db8:1::10", "2001:db8:ffff::7", "2001:db8:2::5"],
            odd_src=["fd00:2::9"],
            to_wan=["2001:db8:1::10", "2001:db8:1::20", "2001:db8:ffff::7", "2001:db8:2::5"],
            to_lan=["fd00:1::50", "fd00:1::64", "fd00:1::c8"],
            router_lan="fd00:1::1", router_wan="2001:db8:1::1"),
}


def _flow_ok(flow: str, src: str, dst: str) -> bool:
    """Address constraints that keep the packet on the intended path through the topology."""
    if src == dst or src in ROUTER_ADDRS:
        return False
    if flow == "fwd_lan_wan":
        return not _in_nets(dst, LAN_NETS) and dst not in ROUTER_ADDRS
    if flow == "fwd_wan_lan":
        return _in_nets(dst, LAN_NETS) and dst not in ROUTER_ADDRS
    return dst in ROUTER_ADDRS


def _flow_dsts(flow: str, fam: int, extra: List[str]) -> List[str]:
    b = BASE[fam]
    if flow == "fwd_lan_wan":
        base = b["to_wan"]
    elif flow == "fwd_wan_lan":
        base = b["to_lan"]
    else:
        base = [b["router_lan"], b["router_wan"]]
    return list(dict.fromkeys(base + [a for a in extra if _ip(a).version == fam]))


def _flow_srcs(flow: str, fam: int, extra: List[str]) -> List[str]:
    b = BASE[fam]
    lan = flow in ("fwd_lan_wan", "input_lan")
    base = (b["lan_src"] if lan else b["wan_src"]) + b["odd_src"]
    return list(dict.fromkeys(base + [a for a in extra if _ip(a).version == fam]))


def _cond_values(rules, lists):
    srcs, dsts, sports, dports = [], [], [], []
    for r in rules:
        c = r.conditions
        for spec, store in ((c.src_address, srcs), (c.dst_address, dsts)):
            store += addr_samples(spec, lists)
        for nm, store in ((c.src_address_list, srcs), (c.dst_address_list, dsts)):
            if nm and nm in lists:
                for e in lists[nm].entries:
                    store += addr_samples(e.address, lists)
        sports += port_samples(c.src_port) + port_samples(c.port)
        dports += port_samples(c.dst_port) + port_samples(c.port)
        if r.action in ("dst-nat", "redirect", "src-nat", "masquerade"):
            pass
    return srcs, dsts, sports, dports


def _flows_for_rule(r) -> List[str]:
    c = r.conditions
    chain = r.chain.lower()
    wan_in = (c.in_interface == WAN_IF and not c.negate_in_interface) or \
             (c.out_interface == LAN_IF and not c.negate_out_interface)
    dst_router = False
    if c.dst_address and not c.negate_dst_address:
        dst_router = any(a.strip() in ROUTER_ADDRS for a in c.dst_address.split(","))
    if chain == "input":
        return ["input_wan"] if wan_in else ["input_lan"]
    if chain == "output":
        return []
    if dst_router and chain in ("dstnat", "prerouting"):
        a = c.dst_address.split(",")[0].strip()
        return ["input_wan"] if a.endswith(("203.0.113.1", "2001:db8:1::1")) else ["input_lan"]
    if chain in ("forward", "dstnat", "prerouting", "srcnat", "postrouting"):
        return ["fwd_wan_lan"] if wan_in else ["fwd_lan_wan"]
    return ["fwd_lan_wan", "input_lan"]  # custom chains: both


def gen_packets(rules, lists, rng: random.Random, k_random: int, k_cap: int,
                flows=FLOWS, only_families=None) -> List[dict]:
    """Targeted packets (one 'hit' per rule + boundary variants) followed by random ones."""
    srcs, dsts, sports, dports = _cond_values(rules, lists)
    fams_rules = {r.family for r in rules if not r.is_policy}
    fams = [4, 6] if (None in fams_rules or not fams_rules or ("ipv4" in fams_rules and "ipv6" in fams_rules)) \
        else ([6] if fams_rules == {"ipv6"} else [4])
    if only_families:
        fams = [f for f in fams if f in only_families]
    seen = set()
    out: List[dict] = []

    used_sports = set()

    def add(flow, fam, proto, src, dst, sport, dport, sport_free=False):
        if proto in ("tcp", "udp"):
            sport = sport or 40000
            dport = dport or 80
            if sport_free:
                # SNAT/masquerade makes distinct sources collide on the same 5-tuple and the kernel then
                # picks another source port; keep every free source port unique within the ruleset.
                while (proto, sport) in used_sports and sport < 65535:
                    sport += 1
        else:
            sport = dport = None
        if not _flow_ok(flow, src, dst) or not (_usable(_ip(dst)) or dst in ROUTER_ADDRS):
            return
        key2 = (flow, proto, src, dst, sport, dport)
        if key2 in seen or len(out) >= k_cap:
            return
        seen.add(key2)
        used_sports.add((proto, sport))
        out.append(dict(n=len(out) + 1, flow=flow, family=fam, proto=proto, src=src, dst=dst,
                        sport=sport, dport=dport))

    # --- targeted: build matching / boundary packets from each rule; every rule gets its fair share of the
    #     budget (cap - random), rules visited in random order so that the cap never starves late rules
    live = [r for r in rules if not r.is_policy and not r.disabled]
    rng.shuffle(live)
    budget = max(0, k_cap - k_random)
    per_rule = max(6, budget // max(1, len(live)))
    for r in live:
        c = r.conditions
        cands = []
        for flow in _flows_for_rule(r):
            if flow not in flows:
                continue
            for fam in fams:
                if r.family == "ipv4" and fam == 6 or r.family == "ipv6" and fam == 4:
                    continue
                protos = [c.protocol.lower()] if c.protocol and c.protocol.lower() in ("tcp", "udp") else                     (["icmp"] if c.protocol and c.protocol.lower() in ("icmp", "icmpv6", "icmp6", "ipv6-icmp") else
                     ["tcp", "udp", "icmp"])
                if (c.src_port or c.dst_port or c.port) and not c.protocol:
                    protos = ["tcp", "udp"]
                s_in = [a for a in addr_samples(c.src_address, lists) if _ip(a).version == fam]
                d_in = [a for a in addr_samples(c.dst_address, lists) if _ip(a).version == fam]
                for nm, st in ((c.src_address_list, s_in), (c.dst_address_list, d_in)):
                    if nm and nm in lists:
                        for e in lists[nm].entries:
                            st += [a for a in addr_samples(e.address, lists) if _ip(a).version == fam]
                sp = port_samples(c.src_port) or port_samples(c.port)
                dp = port_samples(c.dst_port) or port_samples(c.port)
                for proto in protos:
                    srcl = (s_in[:4] or _flow_srcs(flow, fam, [])[:2])
                    dstl = (d_in[:4] or _flow_dsts(flow, fam, [])[:2])
                    for si, s in enumerate(srcl):
                        for di, d in enumerate(dstl):
                            if si and di and si != di:
                                continue
                            for pi in range(max(1, min(5, max(len(sp), len(dp))))):
                                cands.append((flow, fam, proto, s, d,
                                              sp[pi % len(sp)] if sp else 40000 + pi,
                                              dp[pi % len(dp)] if dp else (80, 443, 22, 53, 8080)[pi],
                                              not sp))
        if len(cands) > per_rule:
            cands = rng.sample(cands, per_rule)
        for cd in cands:
            if len(out) < max(budget, 0) or budget == 0:
                add(*cd[:7], sport_free=cd[7])
    # --- random fill
    flows = list(flows)
    protos_all = ["tcp", "tcp", "udp", "icmp"]
    tries = 0
    target = len(out) + k_random
    while len(out) < min(target, k_cap) and tries < k_random * 40:
        tries += 1
        flow = rng.choice(flows)
        fam = rng.choice(fams)
        proto = rng.choice(protos_all)
        src_v = [a for a in srcs if _ip(a).version == fam]
        dst_v = [a for a in dsts if _ip(a).version == fam]
        src = rng.choice(src_v) if src_v and rng.random() < 0.6 else rng.choice(_flow_srcs(flow, fam, []))
        dst = rng.choice(dst_v) if dst_v and rng.random() < 0.6 else rng.choice(_flow_dsts(flow, fam, []))
        from_rule = bool(sports) and rng.random() < 0.5
        sport = rng.choice(sports) if from_rule else rng.choice([40000, 51234, 1024, 33333])
        dport = rng.choice(dports + [22, 80, 443, 53]) if dports else rng.choice([22, 80, 443, 53, 8080])
        add(flow, fam, proto, src, dst, sport, dport, sport_free=not from_rule)
    for i, p in enumerate(out, start=1):
        p["n"] = i
    return out


# ----------------------------------------------------------------------------- kernel run
def run_kernel(cases: List[Case], timeout: int = 900) -> Dict[str, dict]:
    import tempfile
    job = {"cases": [dict(name=c.name, backend=c.backend, packets=c.packets,
                          observe_fwd=any(r.action in ("dst-nat", "redirect", "netmap") for r in c.rules),
                          **c.kernel) for c in cases]}
    with tempfile.TemporaryDirectory(prefix="kd_") as td:
        jp, op = os.path.join(td, "job.json"), os.path.join(td, "out.json")
        with open(jp, "w") as fh:
            json.dump(job, fh)
        p = subprocess.run(["unshare", "-Urnm", "--fork", sys.executable, str(LAB), jp, op],
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0 or not os.path.exists(op):
            raise RuntimeError(f"kernel lab failed (rc={p.returncode}):\n{p.stdout}\n{p.stderr}")
        with open(op) as fh:
            res = json.load(fh)
    return {r["name"]: r for r in res["results"]}


# ----------------------------------------------------------------------------- simulator side
def _route_target(dst: str, original_dst: str) -> str:
    """Where the kernel routes a destination: 'local' | LAN_IF | WAN_IF.  The simulator's REDIRECT
    placeholder (192.0.2.1) only means "the router" when the simulator itself rewrote the destination."""
    if dst in ROUTER_ADDRS or (dst in PLACEHOLDERS and dst != original_dst):
        return "local"
    return LAN_IF if _in_nets(dst, LAN_NETS) else WAN_IF


def _sim_packet(spec: dict, flow: str, out_if: Optional[str]) -> SimulationPacket:
    side_lan = spec["flow"] in ("fwd_lan_wan", "input_lan")
    proto = spec["proto"]
    if proto == "icmp" and spec["family"] == 6:
        proto = "icmpv6"
    return SimulationPacket(
        src_ip=spec["src"], dst_ip=spec["dst"], src_port=spec["sport"], dst_port=spec["dport"],
        protocol=proto, in_interface=LAN_IF if side_lan else WAN_IF,
        out_interface=out_if if flow == "forward" else None,
        connection_state="new", tcp_flags=["syn"] if proto == "tcp" else [],
        flow_type=flow)


def simulate(sim: FirewallSimulator, spec: dict) -> Tuple[object, dict]:
    """Runs the simulator the way a user would, but picks flow_type / out_interface from the routing
    decision the kernel takes *after* DNAT (the simulator does not re-route by itself).  Returns
    (result, info) where info lists the corrections made."""
    flow = "input" if spec["flow"].startswith("input") else "forward"
    out_if = WAN_IF if spec["flow"] == "fwd_lan_wan" else LAN_IF
    info = {"flow_initial": flow, "reruns": []}
    res = sim.simulate(_sim_packet(spec, flow, out_if))
    for _ in range(3):
        tgt = _route_target(res.packet_out.dst_ip, spec["dst"])
        want_flow = "input" if tgt == "local" else "forward"
        want_out = out_if if tgt == "local" else tgt
        if want_flow == flow and (flow == "input" or want_out == out_if):
            break
        info["reruns"].append(f"post-DNAT dst {res.packet_out.dst_ip} routes to {tgt}: flow={want_flow} out={want_out}")
        flow, out_if = want_flow, want_out
        res = sim.simulate(_sim_packet(spec, flow, out_if))
    info["flow_used"], info["out_if_used"] = flow, out_if
    return res, info


def _fresh_sim(case: Case) -> FirewallSimulator:
    return FirewallSimulator([r.model_copy(deep=True) for r in case.rules],
                             {k: v.model_copy(deep=True) for k, v in case.address_lists.items()})


# ----------------------------------------------------------------------------- comparison
def _collides(sim_res_nat_seen, res, spec) -> bool:
    """True when the simulator's post-NAT tuple was already produced by an earlier packet."""
    po = res.packet_out
    post = (spec["proto"], po.src_ip, po.src_port, po.dst_ip, po.dst_port)
    return post in sim_res_nat_seen and sim_res_nat_seen[post] != spec["n"] and po != res.packet_in



def _norm_ip(a):
    return str(_ip(a)) if a else a


def compare_case(case: Case, kres: dict) -> Tuple[List[dict], List[dict], dict]:
    """-> (mismatches, infos, stats)."""
    mism: List[dict] = []
    infos: List[dict] = []
    stats = {"packets": 0, "accept": 0, "block": 0}
    if kres.get("skip"):
        stats["skipped"] = kres["skip"]
        return [], [dict(case=case.name, kind="skipped", detail=kres["skip"])], stats
    if kres.get("load_error"):
        return ([dict(case=case.name, backend=case.backend, kind="kernel-load-error", packet=None,
                      kernel={"error": kres["load_error"][:600]}, sim=None,
                      detail="the kernel rejected the ruleset text")], infos, stats)
    sim = _fresh_sim(case)
    nat_seen: Dict[tuple, int] = {}
    for spec in case.packets:
        stats["packets"] += 1
        k = kres["packets"][str(spec["n"])]
        obs, back = k["observed"], k["back"]
        kverdict = "ACCEPT" if obs else ("REJECT" if back else "DROP")
        res, info = simulate(sim, spec)
        sverdict = res.verdict
        stats["accept" if kverdict == "ACCEPT" else "block"] += 1
        matched = None
        for st in res.stages:
            for ev in st.evaluated_rules:
                if ev.terminated or (ev.matched and ev.action in ("dst-nat", "src-nat", "masquerade", "redirect", "netmap")):
                    matched = f"{ev.table}/{ev.chain}#{ev.rule_id} {ev.action}: {ev.raw_syntax or ''}".strip()
        simd = dict(verdict=sverdict, final_action=res.final_action, matched=matched,
                    out=dict(src=res.packet_out.src_ip, dst=res.packet_out.dst_ip,
                             sport=res.packet_out.src_port, dport=res.packet_out.dst_port),
                    flow=info)
        base = dict(case=case.name, backend=case.backend, packet={k2: spec[k2] for k2 in
                    ("flow", "family", "proto", "src", "dst", "sport", "dport")},
                    kernel=dict(verdict=kverdict, observed=obs, back=back), sim=simd)
        blocked_sim = sverdict in ("DROP", "REJECT")
        if kverdict == "ACCEPT" and blocked_sim:
            mism.append(dict(base, kind="verdict", detail="kernel ACCEPT, simulator " + sverdict))
        elif kverdict != "ACCEPT" and not blocked_sim and _collides(sim_res_nat_seen=nat_seen, res=res, spec=spec):
            infos.append(dict(base, kind="nat-tuple-collision",
                              detail="kernel dropped a flow that collides with an earlier translated flow"))
        elif kverdict != "ACCEPT" and not blocked_sim:
            mism.append(dict(base, kind="verdict", detail=f"kernel {kverdict}, simulator " + sverdict))
        elif kverdict != "ACCEPT":
            if kverdict != sverdict:
                mism.append(dict(base, kind="reject-vs-drop", detail=f"kernel {kverdict}, simulator {sverdict}"))
        else:
            po = res.packet_out
            diffs = []
            post = (spec["proto"], po.src_ip, po.src_port, po.dst_ip, po.dst_port)
            if post in nat_seen and nat_seen[post] != spec["n"]:
                # two different flows translated onto the same tuple: the kernel must pick another port
                # (or drop when the port is fixed); the simulator cannot know the flow table.
                infos.append(dict(base, kind="nat-tuple-collision",
                                  detail=f"same post-NAT tuple as packet #{nat_seen[post]}; not compared"))
                continue
            nat_seen[post] = spec["n"]
            if _norm_ip(obs["src"]) != _norm_ip(po.src_ip):
                if po.src_ip in PLACEHOLDERS and obs["src"] in ROUTER_ADDRS:
                    # masquerade placeholder (the simulator does not know the out-interface address)
                    infos.append(dict(base, kind="placeholder",
                                      detail=f"src: kernel {obs['src']} vs placeholder {po.src_ip}"))
                else:
                    diffs.append(f"src {obs['src']} != {po.src_ip}")
            if _norm_ip(obs["dst"]) != _norm_ip(po.dst_ip):
                if po.dst_ip in PLACEHOLDERS and obs["where"] == "local":
                    infos.append(dict(base, kind="placeholder",
                                      detail=f"dst: kernel {obs['dst']} vs placeholder {po.dst_ip}"))
                else:
                    diffs.append(f"dst {obs['dst']} != {po.dst_ip}")
            if spec["proto"] in ("tcp", "udp"):
                if obs.get("dport") != po.dst_port:
                    diffs.append(f"dport {obs.get('dport')} != {po.dst_port}")
                if obs["where"] != "local" and obs.get("sport") != po.src_port:
                    diffs.append(f"sport {obs.get('sport')} != {po.src_port}")
            if diffs:
                mism.append(dict(base, kind="nat", detail="; ".join(diffs)))
    return mism, infos, stats


# ----------------------------------------------------------------------------- reporting
def format_mismatch(m: dict) -> str:
    p = m.get("packet")
    if not p:
        return f"[{m['case']}] {m['kind']}: {m['kernel']}"
    port = f":{p['sport']}->{p['dport']}" if p["sport"] else ""
    k, s = m["kernel"], m["sim"]
    return (f"[{m['case']}] {m['kind']}: {p['flow']} {p['proto']}/v{p['family']} {p['src']} -> {p['dst']}{port}\n"
            f"    kernel: {k['verdict']} observed={k['observed']}\n"
            f"    sim   : {s['verdict']} out={s['out']} via {s['matched']}"
            + (f" reruns={s['flow']['reruns']}" if s["flow"]["reruns"] else "") + f"\n    {m['detail']}")


def write_report(outdir: Path, mismatches: List[dict], infos: List[dict], summary: dict) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.json").write_text(json.dumps(dict(summary=summary, mismatches=mismatches, infos=infos),
                                                   indent=1, default=str))
    lines = [f"kernel differential report: {summary}", ""]
    by: Dict[str, List[dict]] = {}
    for m in mismatches:
        by.setdefault(m["case"], []).append(m)
    for case, ms in by.items():
        lines.append(f"=== {case}: {len(ms)} mismatch(es)")
        lines += [format_mismatch(m) for m in ms]
        lines.append("")
    (outdir / "report.txt").write_text("\n".join(lines))
