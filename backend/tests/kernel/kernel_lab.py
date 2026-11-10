#!/usr/bin/env python3
"""Kernel side of the differential harness.  Pure standard library.

Run it INSIDE a rootless user+net+mount namespace:

    unshare -Urnm --fork python3 kernel_lab.py JOB.json OUT.json

It builds three network namespaces (client / router / server), loads each
ruleset of the job into the router with the real nft / iptables binaries,
injects crafted packets with AF_PACKET sockets and reports what the kernel did.

Topology (names inside the router match SimulationPacket defaults):

    cl (c0) 192.168.1.50/24 fd00:1::50/64 ---- ether2-lan  192.168.1.1/24 fd00:1::1/64
                                          rt
    sv (s0) 203.0.113.10/24 2001:db8:1::10/64 -- ether1-wan 203.0.113.1/24 2001:db8:1::1/64

Observation of one packet (identified by IPv4 ``id`` / IPv6 flow label == packet number):
  * forwarded packets are sniffed (AF_PACKET) on the client / server side, hop limit 63 -> post-NAT header
  * packets delivered to the router itself are seen by the ``zz_observer`` nft table (base chain at
    priority 1000 in input, so only packets accepted by every earlier chain reach it).  It records
    the *conntrack original* tuple (to identify the packet) and the post-NAT daddr/dport.
  * REJECT shows up as an ICMP error / TCP RST sniffed on the sender side.
"""
import ctypes
import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

LAN_IF, WAN_IF = "ether2-lan", "ether1-wan"
MAC = {"c0": "02:00:00:00:01:01", LAN_IF: "02:00:00:00:01:02",
       WAN_IF: "02:00:00:00:02:02", "s0": "02:00:00:00:02:01"}
ROUTER_V4 = {"lan": "192.168.1.1", "wan": "203.0.113.1"}
ROUTER_V6 = {"lan": "fd00:1::1", "wan": "2001:db8:1::1"}
SETTLE = float(os.environ.get("KD_SETTLE", "0.30"))

_libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNET = 0x40000000


def sh(cmd, inp=None, check=True):
    p = subprocess.run(cmd, input=inp, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def ip(*args, ns=None, inp=None, check=True):
    cmd = ["ip"] + (["-n", ns] if ns else []) + list(args)
    return sh(cmd, inp=inp, check=check)


class Ns:
    fds = {}

    @classmethod
    def open(cls, name):
        cls.fds[name] = os.open(f"/run/netns/{name}", os.O_RDONLY)

    @classmethod
    def enter(cls, name):
        if _libc.setns(cls.fds[name], CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), "setns " + name)


# ----------------------------------------------------------------------------- topology
def setup():
    sh(["mount", "-t", "tmpfs", "none", "/run"])
    os.makedirs("/run/netns", exist_ok=True)
    for n in ("cl", "rt", "sv"):
        ip("netns", "add", n)
    ip("link", "add", "c0", "type", "veth", "peer", "name", LAN_IF, "address", MAC[LAN_IF])
    ip("link", "set", "c0", "address", MAC["c0"], "netns", "cl")
    ip("link", "set", LAN_IF, "netns", "rt")
    ip("link", "add", "s0", "type", "veth", "peer", "name", WAN_IF, "address", MAC[WAN_IF])
    ip("link", "set", "s0", "address", MAC["s0"], "netns", "sv")
    ip("link", "set", WAN_IF, "netns", "rt")
    for n in ("cl", "rt", "sv"):
        ip("link", "set", "lo", "up", ns=n)
    ip("link", "set", "c0", "up", ns="cl")
    ip("link", "set", "s0", "up", ns="sv")
    ip("link", "set", LAN_IF, "up", ns="rt")
    ip("link", "set", WAN_IF, "up", ns="rt")
    ip("addr", "add", "192.168.1.50/24", "dev", "c0", ns="cl")
    ip("addr", "add", "fd00:1::50/64", "dev", "c0", "nodad", ns="cl")
    ip("addr", "add", "203.0.113.10/24", "dev", "s0", ns="sv")
    ip("addr", "add", "2001:db8:1::10/64", "dev", "s0", "nodad", ns="sv")
    ip("addr", "add", "192.168.1.1/24", "dev", LAN_IF, ns="rt")
    ip("addr", "add", "fd00:1::1/64", "dev", LAN_IF, "nodad", ns="rt")
    ip("addr", "add", "203.0.113.1/24", "dev", WAN_IF, ns="rt")
    ip("addr", "add", "2001:db8:1::1/64", "dev", WAN_IF, "nodad", ns="rt")
    ip("route", "add", "default", "via", "203.0.113.10", ns="rt")
    ip("-6", "route", "add", "default", "via", "2001:db8:1::10", ns="rt")
    ip("-6", "route", "add", "default", "via", "fd00:1::1", ns="cl", check=False)
    # permanent neighbours so that anything the router forwards is really put on the wire
    batch = []
    for i in range(2, 255):
        batch.append(f"neigh replace 192.168.1.{i} lladdr {MAC['c0']} dev {LAN_IF} nud permanent")
        batch.append(f"neigh replace 203.0.113.{i} lladdr {MAC['s0']} dev {WAN_IF} nud permanent")
    # IPv6: the connected /64 routes are replaced by "via <the only neighbour>" so that any host id of the
    # prefix is put on the wire (no neighbour discovery for the 2^64 possible hosts).
    batch.append(f"neigh replace fd00:1::50 lladdr {MAC['c0']} dev {LAN_IF} nud permanent")
    batch.append(f"neigh replace 2001:db8:1::10 lladdr {MAC['s0']} dev {WAN_IF} nud permanent")
    batch.append(f"neigh replace 203.0.113.10 lladdr {MAC['s0']} dev {WAN_IF} nud permanent")
    ip("-batch", "-", ns="rt", inp="\n".join(batch) + "\n")
    for pfx, gw, dev in (("fd00:1::/64", "fd00:1::50", LAN_IF), ("2001:db8:1::/64", "2001:db8:1::10", WAN_IF)):
        ip("-6", "route", "del", pfx, "dev", dev, ns="rt")
        ip("-6", "route", "add", gw + "/128", "dev", dev, ns="rt")
        ip("-6", "route", "add", pfx, "via", gw, "dev", dev, ns="rt")
    for key in ("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1",
                "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{LAN_IF}.rp_filter=0", f"net.ipv4.conf.{WAN_IF}.rp_filter=0",
                # REJECT must always produce its ICMP error (default rate limit would swallow most of them)
                "net.ipv4.icmp_ratelimit=0", "net.ipv4.icmp_msgs_per_sec=1000000",
                "net.ipv4.icmp_msgs_burst=1000000", "net.ipv6.icmp.ratelimit=0"):
        q = sh(["ip", "netns", "exec", "rt", "sysctl", "-qw", key], check=False)
        if q.returncode != 0 and os.environ.get("KD_DEBUG"):
            sys.stderr.write(f"sysctl {key} failed: {q.stderr}\n")
    # client and server never answer anything (no stray RST / ICMP noise coming back)
    mute = "table inet kd_mute { chain input { type filter hook input priority 0; policy drop; } }\n"
    for n in ("cl", "sv"):
        sh(["ip", "netns", "exec", n, "nft", "-f", "-"], inp=mute, check=False)
    for suffix in ("nft", "legacy"):
        d = f"/run/kdbin/{suffix}"
        os.makedirs(d, exist_ok=True)
        for tool in ("iptables", "ip6tables", "iptables-restore", "ip6tables-restore"):
            target = os.path.realpath(f"/usr/sbin/{tool.replace('tables', 'tables-' + suffix, 1)}")
            if os.path.exists(target):
                os.symlink(target, f"{d}/{tool}")
    for n in ("cl", "rt", "sv"):
        Ns.open(n)


def rawsock(ns, ifname):
    Ns.enter(ns)
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind((ifname, 0))
        s.setblocking(False)
        return s
    finally:
        Ns.enter("rt")


# ----------------------------------------------------------------------------- packets
def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac_b(m):
    return bytes(int(x, 16) for x in m.split(":"))


PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}


def build_frame(p, dmac, smac):
    n, fam, proto = p["n"], p["family"], p["proto"]
    src, dst = ipaddress.ip_address(p["src"]).packed, ipaddress.ip_address(p["dst"]).packed
    if proto == "tcp":
        flags = 0x02
        l4 = struct.pack("!HHIIBBHHH", p["sport"], p["dport"], n * 1000, 0, 5 << 4, flags, 8192, 0, 0)
        nh = 6
    elif proto == "udp":
        l4 = struct.pack("!HHHH", p["sport"], p["dport"], 10, 0) + b"kd"
        nh = 17
    elif proto == "icmp":
        if fam == 4:
            l4, nh = struct.pack("!BBHHH", 8, 0, 0, n, 1) + b"kd", 1
        else:
            l4, nh = struct.pack("!BBHHH", 128, 0, 0, n, 1) + b"kd", 58
    else:
        raise ValueError(proto)
    if fam == 4:
        pseudo = src + dst + struct.pack("!BBH", 0, nh, len(l4))
        if nh in (6, 17):
            off = 16 if nh == 6 else 6
            c = csum(pseudo + l4)
            if nh == 17 and c == 0:
                c = 0xFFFF
            l4 = l4[:off] + struct.pack("!H", c) + l4[off + 2:]
        else:
            l4 = l4[:2] + struct.pack("!H", csum(l4)) + l4[4:]
        hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), n, 0, 64, nh, 0) + src + dst
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        return mac_b(dmac) + mac_b(smac) + b"\x08\x00" + hdr + l4
    pseudo = src + dst + struct.pack("!IxxxB", len(l4), nh)
    if nh == 6:
        off = 16
    elif nh == 17:
        off = 6
    else:
        off = 2
    c = csum(pseudo + l4)
    if nh == 17 and c == 0:
        c = 0xFFFF
    l4 = l4[:off] + struct.pack("!H", c) + l4[off + 2:]
    hdr = struct.pack("!IHBB", (6 << 28) | (n & 0xFFFFF), len(l4), nh, 64) + src + dst
    return mac_b(dmac) + mac_b(smac) + b"\x86\xdd" + hdr + l4


def _l4(proto_num, b, out):
    out["proto"] = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto_num, str(proto_num))
    if proto_num in (6, 17) and len(b) >= 4:
        out["sport"], out["dport"] = struct.unpack("!HH", b[:4])
        if proto_num == 6 and len(b) >= 14:
            out["tcpflags"] = b[13]
    elif proto_num in (1, 58) and len(b) >= 2:
        out["icmp_type"] = b[0]


def parse_ip(b, inner=False):
    """Parses an IP packet (no L2).  Returns dict or None."""
    if not b:
        return None
    ver = b[0] >> 4
    out = {}
    try:
        if ver == 4:
            ihl = (b[0] & 0xF) * 4
            out.update(family=4, ttl=b[8], id=struct.unpack("!H", b[4:6])[0],
                       src=str(ipaddress.IPv4Address(b[12:16])), dst=str(ipaddress.IPv4Address(b[16:20])))
            _l4(b[9], b[ihl:], out)
            nxt = b[ihl + 8:] if out.get("proto") == "icmp" else None
        elif ver == 6:
            first = struct.unpack("!I", b[:4])[0]
            out.update(family=6, ttl=b[7], id=first & 0xFFFFF,
                       src=str(ipaddress.IPv6Address(b[8:24])), dst=str(ipaddress.IPv6Address(b[24:40])))
            _l4(b[6], b[40:], out)
            nxt = b[48:] if out.get("proto") == "icmpv6" else None
        else:
            return None
    except Exception:
        return None
    if not inner and nxt is not None and out.get("icmp_type") in (3, 11, 1, 2, 4):
        out["inner"] = parse_ip(nxt, inner=True)
    return out


def parse_frame(buf):
    if len(buf) < 34:
        return None
    et = buf[12:14]
    if et not in (b"\x08\x00", b"\x86\xdd"):
        return None
    return parse_ip(buf[14:])


# ----------------------------------------------------------------------------- kernel state
def flush_conntrack():
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        msg = struct.pack("=IHHII", 20, (1 << 8) | 2, 0x1 | 0x4, 1, 0) + struct.pack("=BBH", 0, 0, 0)
        s.send(msg)
        s.settimeout(0.5)
        s.recv(4096)
        s.close()
    except Exception:
        pass


CLEAN_IPT = "".join(f"*{t}\n" + "".join(f":{c} ACCEPT [0:0]\n" for c in cs) + "COMMIT\n"
                    for t, cs in (("raw", ("PREROUTING", "OUTPUT")),
                                  ("mangle", ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING")),
                                  ("nat", ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")),
                                  ("filter", ("INPUT", "FORWARD", "OUTPUT"))))


def clean():
    sh(["nft", "flush", "ruleset"], check=False)
    for tool in ("iptables-legacy-restore", "ip6tables-legacy-restore"):
        sh([tool], inp=CLEAN_IPT, check=False)
    if os.environ.get("KD_DEBUG"):
        sys.stderr.write("ct before flush: " + ct_count() + "\n")
    flush_conntrack()
    if os.environ.get("KD_DEBUG"):
        sys.stderr.write("ct after flush: " + ct_count() + "\n")


def ct_count():
    try:
        return open("/proc/sys/net/netfilter/nf_conntrack_count").read().strip()
    except OSError:
        return "?"


def observer_ruleset(packets, observe_fwd=True):
    """One set pair per packet: ``d_N`` gets the post-NAT daddr, ``p_N`` the post-NAT dport.

    (``ct original`` / concatenated dynamic sets are broken in the installed nft, and ``ip id`` cannot be
    used as a set key, hence per-packet sets keyed by rules ``ip id N`` / ``ip6 flowlabel N``.)
    """
    lines = ["table inet zz_observer {"]
    rules = []
    for p in packets:
        if not observe_fwd and not p["flow"].startswith("input"):
            continue  # forwarded packets are sniffed; only DNAT/REDIRECT can divert them to the router itself
        n, fam = p["n"], p["family"]
        a = "ipv4_addr" if fam == 4 else "ipv6_addr"
        lines.append(f"  set d_{n} {{ type {a}; flags dynamic; size 4; }}")
        sel = f"ip id {n}" if fam == 4 else f"ip6 flowlabel {n}"
        ipx = "ip" if fam == 4 else "ip6"
        rules.append(f"    {sel} add @d_{n} {{ {ipx} daddr }}")
        if p["proto"] in ("tcp", "udp"):
            lines.append(f"  set p_{n} {{ type inet_service; flags dynamic; size 4; }}")
            rules.append(f"    {sel} meta l4proto {p['proto']} add @p_{n} {{ th dport }}")
    lines.append("  chain input { type filter hook input priority 1000; policy accept;")
    lines += rules
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def load_ruleset(case):
    """Returns an error string or None."""
    backend = case["backend"]
    if backend == "nft":
        p = sh(["nft", "-f", "-"], inp=case["nft"], check=False)
        return None if p.returncode == 0 else (p.stderr.strip() or "nft failed")
    suffix = "nft" if backend == "iptables-nft" else "legacy"
    if case.get("script"):
        # exported bash script calling plain `iptables` / `ip6tables`: pick the backend through PATH
        env = dict(os.environ, PATH=f"/run/kdbin/{suffix}:" + os.environ.get("PATH", ""))
        p = subprocess.run(["bash", "-c", case["script"]], capture_output=True, text=True, env=env)
        return None if p.returncode == 0 else (p.stderr.strip() or "script failed")
    errs = []
    for key, tool in (("ipt4", f"iptables-{suffix}-restore"), ("ipt6", f"ip6tables-{suffix}-restore")):
        text = case.get(key)
        if text and text.strip():
            p = sh([tool], inp=text, check=False)
            if p.returncode != 0:
                errs.append(f"{tool}: {p.stderr.strip()}")
    return "; ".join(errs) or None


def read_observer():
    """-> {set_name: [values]} for the observer table."""
    p = sh(["nft", "-j", "list", "table", "inet", "zz_observer"], check=False)
    seen = {}
    if p.returncode != 0:
        return seen
    for item in json.loads(p.stdout).get("nftables", []):
        s = item.get("set")
        if s and s.get("elem"):
            seen[s["name"]] = list(s["elem"])
    return seen


# ----------------------------------------------------------------------------- one case
def run_case(case, socks):
    clean()
    res = {"name": case["name"], "backend": case["backend"], "load_error": None, "packets": {}}
    err = load_ruleset(case)
    if err:
        res["load_error"] = err
        if "could not insert" in err and "ip6_tables" in err:
            res["skip"] = "kernel has no ip6_tables (legacy) module"
        return res
    ob = sh(["nft", "-f", "-"], inp=observer_ruleset(case["packets"], case.get("observe_fwd", True)), check=False)
    if ob.returncode != 0:
        res["load_error"] = "observer: " + ob.stderr.strip()
        return res
    pk = case["packets"]
    sent = {}
    for p in pk:
        lan_origin = p["flow"].endswith("lan") if p["flow"].startswith("input") else p["flow"] == "fwd_lan_wan"
        if p["flow"] == "input_wan":
            lan_origin = False
        side = "lan" if lan_origin else "wan"
        fam = p["family"]
        if p["flow"].startswith("input"):
            dst = p["dst"]
        else:
            dst = p["dst"]
        frame = build_frame(p, MAC[LAN_IF] if side == "lan" else MAC[WAN_IF],
                            MAC["c0"] if side == "lan" else MAC["s0"])
        socks[side + "_tx"].send(frame)
        sent[p["n"]] = (p, side)
    # collect
    deadline = time.time() + SETTLE
    obs = {n: [] for n in sent}
    back = {n: None for n in sent}
    rx = {"lan": socks["lan_rx"], "wan": socks["wan_rx"]}
    while True:
        left = deadline - time.time()
        if left <= 0:
            break
        r, _, _ = select.select(list(rx.values()), [], [], left)
        for s in r:
            where = "lan" if s is rx["lan"] else "wan"
            while True:
                try:
                    buf, addr = s.recvfrom(65535)
                except BlockingIOError:
                    break
                if addr[2] == 4:  # PACKET_OUTGOING
                    continue
                f = parse_frame(buf)
                if not f:
                    continue
                n = f["id"]
                if f["ttl"] == 63 and n in sent and f["proto"] in (sent[n][0]["proto"], "icmpv6" if sent[n][0]["proto"] == "icmp" else ""):
                    obs[n].append(dict(f, where=where))
                    continue
                # reply side: ICMP error quoting our packet, or TCP RST
                inn = f.get("inner")
                if inn and inn["id"] in sent:
                    back[inn["id"]] = {"type": f.get("icmp_type"), "proto": f["proto"], "from": f["src"], "to": f["dst"],
                                       "where": where}
                elif f.get("proto") == "tcp" and f.get("tcpflags", 0) & 0x04:
                    for n2, (p2, side2) in sent.items():
                        if p2["proto"] == "tcp" and f["dst"] == p2["src"] and f.get("dport") == p2["sport"] \
                                and f["src"] == p2["dst"] and f.get("sport") == p2["dport"]:
                            back[n2] = {"type": "rst", "proto": "tcp", "from": f["src"], "to": f["dst"], "where": where}
    seen = read_observer()
    if os.environ.get("KD_DEBUG"):
        sys.stderr.write(sh(["nft", "list", "table", "inet", "zz_observer"], check=False).stdout + "\n")
    for n, (p, side) in sent.items():
        entry = {"observed": None, "back": back[n]}
        if obs[n]:
            o = obs[n][0]
            entry["observed"] = {"where": o["where"], "src": o["src"], "dst": o["dst"],
                                 "sport": o.get("sport"), "dport": o.get("dport"), "proto": o["proto"]}
        else:
            dd, pp = seen.get(f"d_{n}"), seen.get(f"p_{n}")
            if dd:
                entry["observed"] = {"where": "local", "src": p["src"], "dst": str(ipaddress.ip_address(dd[0])),
                                     "sport": p["sport"], "dport": int(pp[0]) if pp else None, "proto": p["proto"]}
        res["packets"][str(n)] = entry
    return res


def main():
    job = json.load(open(sys.argv[1]))
    setup()
    socks = {
        "lan_tx": rawsock("cl", "c0"), "wan_tx": rawsock("sv", "s0"),
        "lan_rx": rawsock("cl", "c0"), "wan_rx": rawsock("sv", "s0"),
    }
    Ns.enter("rt")
    out = {"results": []}
    for case in job["cases"]:
        out["results"].append(run_case(case, socks))
    clean()
    json.dump(out, open(sys.argv[2], "w"))


if __name__ == "__main__":
    main()
