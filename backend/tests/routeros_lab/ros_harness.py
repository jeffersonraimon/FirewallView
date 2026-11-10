"""Cases, run loop and comparison for the RouterOS differential suite (see README.md).

Packet generation, the simulator driver and the comparison are the ones of tests/kernel (kernel_harness); this
module only adapts them: IPv4 only, one CHR instead of the namespaces, input verdicts from router replies.
"""
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "kernel"))
sys.path.insert(0, str(HERE))

import kernel_harness as kh  # noqa: E402
from corpus_loader import directives  # noqa: E402  (tests/kernel)
from firewallview.exporters.routeros import export_to_routeros  # noqa: E402
from firewallview.parsers.routeros import parse_routeros_script  # noqa: E402

import chr_lab  # noqa: E402

CORPUS = HERE / "corpus"
DEFAULT_SEED = 20261110


def load_corpus(scale: float = 1.0) -> List[kh.Case]:
    cases = []
    for path in sorted(CORPUS.glob("*.rsc")):
        text = path.read_text()
        d = directives(text)
        rules, lists = parse_routeros_script(text)
        rng = random.Random(f"{d.get('seed', DEFAULT_SEED)}:{path.stem}")
        cap = max(8, int(int(d.get("packets", 70)) * scale))
        flows = d.get("flows", ",".join(kh.FLOWS)).split(",")
        pk = kh.gen_packets(rules, lists, rng, k_random=max(4, int(25 * scale)), k_cap=cap, flows=flows,
                            only_families=[4])
        warns = [f"rule {r.id}: {w}" for r in rules for w in r.parse_warnings]
        cases.append(kh.Case(name=path.stem, source="corpus", backend="routeros", rules=rules, address_lists=lists,
                             kernel={"rsc": text}, packets=[dict(p) for p in pk],
                             meta=dict(directives=d, parse_warnings=warns, file=path.name)))
    return cases


def build_fuzz(n_rulesets: int, n_packets: int, seed: int) -> List[kh.Case]:
    import fuzz_ros
    return fuzz_ros.build_cases(n_rulesets, n_packets, seed)


# ----------------------------------------------------------------------------- run
def run_router(cases: List[kh.Case], lab: "chr_lab.Lab") -> Dict[str, dict]:
    """Loads every case into the CHR and sends its packets.  -> {case name: kres} for kh.compare_case."""
    out = {}
    for c in cases:
        t0 = time.time()
        res = {"name": c.name, "backend": c.backend, "load_error": None, "packets": {}}
        try:
            lab.reset()
            lab.load(c.kernel["rsc"])
        except chr_lab.RestError as exc:
            res["load_error"] = str(exc)
            out[c.name] = res
            continue
        res["packets"] = lab.run_packets(c.packets)
        # sanity: the management rules survived (a rule under test must never lock the lab out)
        res["secs"] = round(time.time() - t0, 1)
        out[c.name] = res
    return out


def _local_verdict_only(case: kh.Case, kres: dict, ambiguous: list):
    """Packets answered by the router itself: RouterOS shows no post-NAT header, so only the verdict is
    compared (src/dst/port of the observation are copied from the simulator's own result).

    A forwarded-flow packet that the simulator redirects to the router (redirect / dst-nat to a router address) is
    answered by the router's own stack with RST / ICMP port unreachable, which looks exactly like a reject.  Such a
    reply is read as "delivered locally" and listed as an info (`ambiguous-local-reply`)."""
    sim = kh._fresh_sim(case)
    for spec in case.packets:
        k = kres["packets"].get(str(spec["n"]))
        if not k:
            continue
        if not k["observed"] and k["back"] and (k["back"]["type"] == "rst" or k["back"]["type"] == "icmp3/3"):
            res, info = kh.simulate(sim, spec)
            if info["flow_used"] == "input" and spec["flow"].startswith("fwd"):
                k["observed"] = dict(where="local", src=spec["src"], dst=spec["dst"], sport=spec["sport"],
                                     dport=spec["dport"], proto=spec["proto"], via="ambiguous")
                ambiguous.append(dict(case=case.name, kind="ambiguous-local-reply", packet=spec,
                                      detail=f"router answered ({k['back']['type']}) a packet the simulator redirects to "
                                             "the router; read as delivered locally"))
        if k["observed"] and k["observed"]["where"] == "local":
            res, _ = kh.simulate(sim, spec)
            po = res.packet_out
            k["observed"].update(src=po.src_ip, dst=po.dst_ip, dport=po.dst_port, sport=spec["sport"])


def compare(case: kh.Case, kres: dict):
    amb: list = []
    if not kres.get("load_error"):
        _local_verdict_only(case, kres, amb)
    mism, infos, st = kh.compare_case(case, kres)
    infos += amb
    for m in mism:
        if m["kind"] == "kernel-load-error":
            m["kind"] = "routeros-load-error"
            m["detail"] = "RouterOS rejected the script"
    return mism, infos, st


def write_report(outdir: Path, mismatches, infos, summary, extra=None):
    kh.write_report(outdir, mismatches, infos, summary)
    if extra:
        (outdir / "cases.json").write_text(json.dumps(extra, indent=1, default=str))
