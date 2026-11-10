#!/usr/bin/env python3
"""Runs INSIDE a peer container (client on the LAN network, server on the WAN network).  Stdlib only.

    python3 agent.py JOB.json   ->  JSON on stdout

job = {"iface": "eth0", "dmac": "<CHR mac on this segment>", "smac": "<own mac>",
       "send": [packet dicts as produced by kernel_harness.gen_packets], "delay": 0.8, "settle": 1.2}

The agent sniffs every incoming IPv4 frame on the interface (AF_PACKET), sends the crafted frames (kernel_lab.build_frame:
IPv4 ``id`` = packet number, TCP seq = n*1000, ICMP echo id = n) and prints all frames it received, so the orchestrator can
correlate forwarded packets (post-NAT header), replies of the router (input flows) and ICMP errors (reject).
"""
import json
import select
import socket
import struct
import sys
import time

sys.path.insert(0, "/kernel")
import kernel_lab as kl  # noqa: E402  (bind-mounted tests/kernel; only build_frame / parse_ip are used)


def extra(buf):
    """parse_frame + fields kernel_lab does not extract (ICMP id, TCP seq/ack)."""
    f = kl.parse_frame(buf)
    if not f or f.get("family") != 4:
        return None
    ihl = (buf[14] & 0xF) * 4
    l4 = buf[14 + ihl:]
    if f.get("proto") == "icmp" and len(l4) >= 8:
        f["icmp_id"] = struct.unpack("!H", l4[4:6])[0]
        f["icmp_code"] = l4[1]
    if f.get("proto") == "tcp" and len(l4) >= 12:
        f["seq"], f["ack"] = struct.unpack("!II", l4[4:12])
    if f.get("proto") == "udp" and len(l4) >= 8:
        f["udp_len"] = struct.unpack("!H", l4[4:6])[0]
    if f.get("inner") and f["proto"] == "icmp":
        f["icmp_code"] = l4[1]
    return f


def main():
    job = json.load(open(sys.argv[1]))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((job["iface"], 0))
    s.setblocking(False)
    frames = []
    t0 = time.time()
    sent = False
    end = t0 + job["delay"] + job["settle"]
    while True:
        now = time.time()
        if not sent and now - t0 >= job["delay"]:
            for p in job["send"]:
                s.send(kl.build_frame(p, job["dmac"], job["smac"]))
            sent = True
            end = time.time() + job["settle"]
        if now >= end:
            break
        r, _, _ = select.select([s], [], [], 0.05)
        if r:
            while True:
                try:
                    buf, addr = s.recvfrom(65535)
                except BlockingIOError:
                    break
                if addr[2] == 4:          # PACKET_OUTGOING
                    continue
                f = extra(buf)
                if f:
                    frames.append(f)
    json.dump(frames, sys.stdout)


if __name__ == "__main__":
    main()
