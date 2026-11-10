"""Loads the hand-written corpus (nft files and iptables-save files) into harness Cases."""
import random
import re
from pathlib import Path
from typing import List

from firewallview.parsers.iptables import parse_iptables_script
from firewallview.parsers.nftables import parse_nftables_script

from kernel_harness import Case, FLOWS, gen_packets

CORPUS = Path(__file__).resolve().parent / "corpus"
DEFAULT_SEED = 20261109


def directives(text: str) -> dict:
    """``# kd: key=value; key=value`` header (first lines of a corpus file)."""
    out = {}
    for line in text.splitlines()[:5]:
        m = re.match(r"#\s*kd:\s*(.*)", line)
        if m:
            for item in m.group(1).split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    out[k.strip()] = v.strip()
    return out


def split_ipt(text: str):
    """Splits an iptables-save dump with ip6tables-save sections into (v4_text, v6_text)."""
    v4, v6, cur = [], [], None
    cur = v4
    for line in text.splitlines():
        if line.startswith("#") and "ip6tables-save" in line:
            cur = v6
        elif line.startswith("#") and "iptables-save" in line:
            cur = v4
        if not line.startswith("#"):
            cur.append(line)
    return "\n".join(v4) + "\n", "\n".join(v6) + "\n"


def load_corpus(scale: float = 1.0) -> List[Case]:
    cases: List[Case] = []
    for path in sorted(CORPUS.iterdir()):
        text = path.read_text()
        d = directives(text)
        stem = path.stem
        if path.suffix == ".nft":
            rules, lists = parse_nftables_script(text)
            variants = [("nft", {"nft": text}, stem)]
        elif path.suffix == ".ipt":
            rules, lists = parse_iptables_script(text)
            v4, v6 = split_ipt(text)
            kern = {"ipt4": v4, "ipt6": v6}
            variants = [("iptables-nft", kern, f"{stem}@nft"), ("iptables-legacy", kern, f"{stem}@legacy")]
            if d.get("backends"):
                variants = [v for v in variants if v[0].split("-")[1] in d["backends"].split(",")]
        else:
            continue
        rng = random.Random(f"{d.get('seed', DEFAULT_SEED)}:{stem}")
        cap = max(8, int(int(d.get("packets", 60)) * 1.6 * scale))
        flows = d.get("flows", ",".join(FLOWS)).split(",")
        pk = gen_packets(rules, lists, rng, k_random=max(4, int(30 * scale)), k_cap=cap, flows=flows)
        warns = [f"rule {r.id}: {w}" for r in rules for w in r.parse_warnings]
        for backend, kern, name in variants:
            cases.append(Case(name=name, source="corpus", backend=backend, rules=rules, address_lists=lists,
                              kernel=kern, packets=[dict(p) for p in pk],
                              meta=dict(directives=d, parse_warnings=warns, file=path.name)))
    return cases
