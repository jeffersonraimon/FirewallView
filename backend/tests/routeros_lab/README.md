# RouterOS differential tests

Sends the same packets through (a) a **real RouterOS** (official `mikrotik/chr` image, RouterOS 7.25.1, booted with KVM in
docker) and (b) the FirewallView simulator, and compares verdicts and NAT results.  Mirror of `tests/kernel/` (Linux
netfilter); it reuses that harness' packet generator, simulator driver and comparison (`kernel_harness.gen_packets`,
`simulate`, `compare_case`, `kernel_lab.build_frame`).  The goal is to MEASURE parser / simulator / exporter against ground
truth, not to fix them.

## Running

```
cd backend
PYTHONPATH=. python3 -m pytest tests/routeros_lab -m routeros -q        # ~2.5 min (CHR boot ~45 s + one batch per ruleset)
```

Registering the marker (not done here, `pytest.ini` belongs to someone else) and keeping it out of the quick suite:

```
addopts = -m "not kernel and not routeros"
markers =
    routeros: differential tests against a real RouterOS CHR (docker + KVM); see tests/routeros_lab/README.md
```

Knobs: `RL_FUZZ_RULESETS` (default 12), `RL_FUZZ_PACKETS` (24 per ruleset), `RL_FUZZ_SEED` (1), `RL_SCALE` (corpus packet
multiplier, 1), `RL_OUT` (report dir, default `tests/routeros_lab/_out/`, gitignored), `RL_SETTLE` (seconds to wait for
packets, 1.2), `RL_BOOT_TIMEOUT` (150), `RL_PEER_IMAGE` (image for client / server containers; any image with python3, default
`firewallview:latest`).  Reports: `_out/report.txt`, `_out/report.json` (mismatches + infos), `_out/cases.json` (the
exact .rsc loaded per case, parser warnings, seconds).

The module skips cleanly when `docker`, `/dev/kvm`, the daemon, the `mikrotik/chr` image or the peer image are missing.
Needs no pip dependency (stdlib `urllib` for the REST API, `docker` CLI for everything else).  Safe to re-run: every
resource is named `fv-lab-*`, removed at the start of a run, at exit (`atexit`) and in the fixture teardown (the test
fails if anything is left).  The user's real routers are never contacted: only the local containers.

## How it works

```
 fv-lab-lan  192.168.1.0/24  client 192.168.1.50 ----- ether2-lan 192.168.1.1  [CHR]  ether1-wan 203.0.113.1 ----- server 203.0.113.10
 fv-lab-mgmt 10.99.0.0/24    host (REST, http) ------- ether3-mgmt 10.99.0.10          default route -> 203.0.113.10
```

* `chr_lab.py` creates the three docker networks (no docker MASQUERADE, explicit gateways `.254`), the client / server peer
  containers (raw sockets, `/lab` = this dir and `/kernel` = tests/kernel bind-mounted read-only) and the CHR.  Docker
  connects networks in lexical order (lan, mgmt, wan), so CHR interfaces are matched by MAC (docker veth MAC + 1, see
  `/start.sh`) and renamed to `ether2-lan` / `ether1-wan` / `ether3-mgmt` (the names of the `SimulationPacket` defaults).
* Bootstrap through the serial console (the container's stdio, `docker start -ai`): login `admin`, answer the cursor query
  RouterOS sends, set a password, add the management IP.  The console client MUST stay attached for the whole run:
  terminating `docker start -ai` forwards SIGTERM and powers the CHR off.  Everything else goes through the REST API.
* Configuration is applied as RouterOS script text: `PUT /rest/system/script` + `POST /rest/system/script/run` (same
  parser as `/import`).  A rejected line raises an error and the case is reported as `routeros-load-error` (for exporter
  output this is itself a finding).  After loading, the harness waits until no rule is `invalid=true` (new rules are inactive
  for a moment; without the wait the first packets saw a half-loaded ruleset) and flushes conntrack.
* Static ARP entries for 192.168.1.2-254 / 203.0.113.2-254 point to the client / server MAC, so any destination (including
  post-DNAT / netmap ones) is delivered to the sniffing container.  Interface lists `WAN` / `LAN` exist permanently.
* Management safety: first rules in filter input, raw prerouting, mangle prerouting, nat dstnat / srcnat accept everything
  on `ether3-mgmt` (comment `fv-safety`); `reset()` removes every other rule, address-list entry and connection.  Rules under
  test cannot lock the lab out (REST uses mgmt, never an interface under test).
* Packets: `agent.py` (inside the peers) sniffs with AF_PACKET and sends crafted frames (IPv4 `id` = packet number, TCP seq
  = n*1000, ICMP id = n).  Observation (`chr_lab.classify`): forwarded = frame with the packet's id and TTL 63 on either side
  (post-NAT header read from it); input accepted = router answers (TCP RST / SYN-ACK, ICMP echo reply, ICMP port
  unreachable); REJECT = other ICMP unreachable / RST quoting the packet; nothing = DROP.
* Mode A (corpus): `corpus/*.rsc` are parsed with `parse_routeros_script`, loaded into the CHR, packets generated from the
  parsed rules (hit + boundary variants per rule + seeded random).  `# kd: packets=N; flows=...; xfail=reason` headers work.
* Mode B (`fuzz_ros.py`): seeded random `FirewallRule` sets (generator of `tests/kernel/fuzz_gen` restricted to IPv4, plus
  interface lists and mangle `mark-packet` + filter on `packet-mark`), exported with `export_to_routeros`, loaded, simulated
  on the ORIGINAL model.  The first ruleset with comma
  address lists is named `*_comma_address_list` (exported as generated `fwv-<hash>` address-lists; must load and agree).

## Comparison rules / known limits (not simulator bugs)

* IPv4 only (the IPv6 half of the lab is not built); `reject-vs-drop` is reported separately; output chain, established /
  related, tcp flags other than SYN, ICMP types other than echo are out of scope.  Free CHR is limited to 1 Mbps (irrelevant).
* Packets answered by the router itself (input flows) can only be compared on the verdict: RouterOS shows no post-NAT
  header, so src/dst/port of such observations are copied from the simulator.
* A forwarded packet that the simulator redirects to the router (redirect, dst-nat to a router address) is answered by the
  router's own stack with RST / ICMP port-unreachable, indistinguishable from a reject; read as "delivered locally" and
  listed as info `ambiguous-local-reply`.
* Masquerade: the simulator uses the placeholder 203.0.113.1, equal to the CHR WAN address.
* UDP / TCP rules without `protocol=` plus ports are rejected by RouterOS ("ports can be specified if proto is
  tcp,udp,..."): hand-written corpus must always name the protocol.
* Docker's own NAT would rewrite spoofed sources belonging to the other subnet; the networks are created with
  `enable_ip_masquerade=false` for that reason.
