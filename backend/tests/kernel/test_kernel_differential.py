"""Differential test: FirewallView simulator vs. the real Linux kernel (nftables / iptables).

Run:   cd backend && PYTHONPATH=. python3 -m pytest tests/kernel -m kernel -q
Scale: KD_FUZZ_RULESETS / KD_FUZZ_PACKETS / KD_FUZZ_SEED / KD_SCALE (see README.md)
Report: backend/tests/kernel/_out/report.{txt,json}

Skipped cleanly when rootless user namespaces or nft are unavailable.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kernel_harness as kh  # noqa: E402

pytestmark = pytest.mark.kernel

_REASON = kh.skip_reason()
if _REASON:
    pytest.skip(f"kernel differential suite unavailable: {_REASON}", allow_module_level=True)

import corpus_loader  # noqa: E402
import fuzz_gen  # noqa: E402

OUT_DIR = Path(os.environ.get("KD_OUT", Path(__file__).resolve().parent / "_out"))
SCALE = float(os.environ.get("KD_SCALE", "1"))

# Corpus rulesets (or fuzz seeds) whose mismatches come from a documented, inherent limitation of the
# model and not from a bug.  name-prefix -> reason.  Everything else must match the kernel exactly.
KNOWN_LIMITATIONS = {
    "17_two_filter_tables": "model limitation: an accept in one base chain does not end evaluation of other base "
                            "chains hooked at the same point (other tables / priorities); the canonical model "
                            "flattens every table into one filter/forward chain",
    "i11_icmp_types": "model limitation: RuleCondition/SimulationPacket have no ICMP type field (the parser warns "
                      "'rule matches all ICMP'); only echo-request is sent so every typed ICMP rule over-matches",
}

CASES = corpus_loader.load_corpus(SCALE) + fuzz_gen.build_cases(
    n_rulesets=int(os.environ.get("KD_FUZZ_RULESETS", "30")),
    n_packets=int(os.environ.get("KD_FUZZ_PACKETS", "20")),
    seed=int(os.environ.get("KD_FUZZ_SEED", "1")))
BY_NAME = {c.name: c for c in CASES}


@pytest.fixture(scope="session")
def outcome():
    """Runs every case through the kernel ONCE (one namespace setup) and compares with the simulator."""
    kernel = kh.run_kernel(CASES)
    results, all_m, all_i = {}, [], []
    totals = dict(rulesets=len(CASES), packets=0, accept=0, block=0, mismatches=0)
    for c in CASES:
        m, i, st = kh.compare_case(c, kernel[c.name])
        results[c.name] = (m, i, st)
        all_m += m
        all_i += i
        totals["packets"] += st["packets"]
        totals["accept"] += st["accept"]
        totals["block"] += st["block"]
    totals["mismatches"] = len(all_m)
    kinds = {}
    for m in all_m:
        kinds[m["kind"]] = kinds.get(m["kind"], 0) + 1
    totals["by_kind"] = kinds
    kh.write_report(OUT_DIR, all_m, all_i, totals)
    results["__totals__"] = totals
    return results


def _check(name, outcome):
    c = BY_NAME[name]
    mism, infos, st = outcome[name]
    if st.get("skipped"):
        pytest.skip(st["skipped"])
    if not mism:
        return
    text = "\n".join(kh.format_mismatch(m) for m in mism[:12])
    more = f"\n... and {len(mism) - 12} more (see {OUT_DIR}/report.txt)" if len(mism) > 12 else ""
    msg = f"{len(mism)} mismatch(es) in {name} [{c.meta.get('file', 'fuzz')}]\n{text}{more}"
    reason = c.meta.get("directives", {}).get("xfail") or next(
        (r for p, r in KNOWN_LIMITATIONS.items() if name.startswith(p)), None)
    if reason:
        pytest.xfail(f"known limitation: {reason}\n{msg}")
    pytest.fail(msg, pytrace=False)


@pytest.mark.parametrize("name", [c.name for c in CASES if c.source == "corpus"])
def test_corpus(name, outcome):
    _check(name, outcome)


@pytest.mark.parametrize("name", [c.name for c in CASES if c.source == "fuzz"])
def test_fuzz(name, outcome):
    _check(name, outcome)


def test_zz_summary(outcome, capsys):
    with capsys.disabled():
        print(f"\nkernel differential totals: {outcome['__totals__']}  report: {OUT_DIR}/report.txt")
