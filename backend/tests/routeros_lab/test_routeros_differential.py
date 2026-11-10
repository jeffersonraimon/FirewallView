"""Differential test: FirewallView parser / simulator / exporter vs. a REAL RouterOS (mikrotik/chr in docker + KVM).

Run:   cd backend && PYTHONPATH=. python3 -m pytest tests/routeros_lab -m routeros -q
Scale: RL_FUZZ_RULESETS (default 12) / RL_FUZZ_PACKETS (24) / RL_FUZZ_SEED (1) / RL_SCALE (corpus packet multiplier, 1)
       RL_OUT (report dir, default tests/routeros_lab/_out) / RL_SETTLE (seconds to wait for packets, 1.2),
       RL_ONLY (regex: run only the matching case names)
Skipped cleanly when docker, /dev/kvm or the mikrotik/chr image is missing.  See README.md.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chr_lab  # noqa: E402

pytestmark = pytest.mark.routeros

_REASON = chr_lab.skip_reason()
if _REASON:
    pytest.skip(f"RouterOS differential suite unavailable: {_REASON}", allow_module_level=True)

import ros_harness as rh  # noqa: E402

OUT_DIR = Path(os.environ.get("RL_OUT", Path(__file__).resolve().parent / "_out"))
SCALE = float(os.environ.get("RL_SCALE", "1"))

# name-prefix -> reason: inherent limitations of the model (not bugs).  Everything else must match RouterOS exactly.
KNOWN_LIMITATIONS = {}

CASES = rh.load_corpus(SCALE) + rh.build_fuzz(
    n_rulesets=int(os.environ.get("RL_FUZZ_RULESETS", "12")),
    n_packets=int(os.environ.get("RL_FUZZ_PACKETS", "24")),
    seed=int(os.environ.get("RL_FUZZ_SEED", "1")))
if os.environ.get("RL_ONLY"):       # regex on case names, e.g. RL_ONLY='rosfuzz2_0(23|33)|05_'
    import re
    CASES = [c for c in CASES if re.search(os.environ["RL_ONLY"], c.name)]
BY_NAME = {c.name: c for c in CASES}


@pytest.fixture(scope="session")
def outcome():
    """One CHR for the whole session: boots it, runs every case, compares with the simulator, tears everything down."""
    lab = chr_lab.Lab(settle=float(os.environ.get("RL_SETTLE", "1.2")))
    lab.settle = float(os.environ.get("RL_SETTLE", "1.2"))
    try:
        lab.start()
        router = rh.run_router(CASES, lab)
        version = lab.version
    finally:
        lab.stop()
    assert not chr_lab.leftovers(), f"fv-lab-* resources left behind: {chr_lab.leftovers()}"
    results, all_m, all_i = {}, [], []
    totals = dict(routeros=version, rulesets=len(CASES), packets=0, accept=0, block=0, mismatches=0)
    for c in CASES:
        m, i, st = rh.compare(c, router[c.name])
        results[c.name] = (m, i, st)
        all_m += m
        all_i += i
        for k in ("packets", "accept", "block"):
            totals[k] += st[k]
    totals["mismatches"] = len(all_m)
    kinds = {}
    for m in all_m:
        kinds[m["kind"]] = kinds.get(m["kind"], 0) + 1
    totals["by_kind"] = kinds
    rh.write_report(OUT_DIR, all_m, all_i, totals,
                    extra={c.name: dict(rsc=c.kernel["rsc"], parse_warnings=c.meta.get("parse_warnings"),
                                        secs=router[c.name].get("secs")) for c in CASES})
    results["__totals__"] = totals
    return results


def _check(name, outcome):
    c = BY_NAME[name]
    mism, infos, st = outcome[name]
    if not mism:
        return
    from kernel_harness import format_mismatch
    text = "\n".join(format_mismatch(m) for m in mism[:12])
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
        print(f"\nRouterOS differential totals: {outcome['__totals__']}  report: {OUT_DIR}/report.txt")
