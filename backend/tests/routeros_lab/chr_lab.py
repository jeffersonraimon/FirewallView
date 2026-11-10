"""RouterOS CHR lab: docker topology, serial-console bootstrap, REST client and per-case packet runs.

Topology (all names prefixed ``fv-lab-``):

    fv-lab-lan  192.168.1.0/24 (docker gw .254)   client 192.168.1.50 --- ether2-lan 192.168.1.1  [CHR]
    fv-lab-wan  203.0.113.0/24 (docker gw .254)   server 203.0.113.10 --- ether1-wan 203.0.113.1  [CHR]
    fv-lab-mgmt 10.99.0.0/24   (docker gw .254)   host (this process) --- ether3-mgmt 10.99.0.10  [CHR]

Docker connects networks in lexical order (lan, mgmt, wan), so the CHR interfaces are identified by MAC, not by
position, and renamed.  See README.md.
"""
import atexit
import base64
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
KERNEL_DIR = HERE.parent / "kernel"
PREFIX = "fv-lab-"
NETS = {  # name -> (subnet, docker gateway)
    "mgmt": ("10.99.0.0/24", "10.99.0.254"),
    "lan": ("192.168.1.0/24", "192.168.1.254"),
    "wan": ("203.0.113.0/24", "203.0.113.254"),
}
CHR_IMAGE = "mikrotik/chr"
PEER_IMAGE = os.environ.get("RL_PEER_IMAGE", "firewallview:latest")   # anything with python3
CHR = PREFIX + "chr"
CLIENT, SERVER = PREFIX + "client", PREFIX + "server"
MGMT_IP = "10.99.0.10"
REST_PORT = 18080     # www service moved off tcp/80: the harness probes port 80 of the router like any other port
PASSWORD = "fvlab-Pass1"
LAN_IF, WAN_IF, MGMT_IF = "ether2-lan", "ether1-wan", "ether3-mgmt"
SAFETY = "fv-safety"
BOOT_TIMEOUT = int(os.environ.get("RL_BOOT_TIMEOUT", "150"))


def _run(cmd, check=False, timeout=120, inp=None):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout, input=inp)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {cmd}\n{p.stdout}\n{p.stderr}")
    return p


def skip_reason() -> Optional[str]:
    """Why the RouterOS suite cannot run here (None when it can)."""
    if shutil.which("docker") is None:
        return "docker not found"
    if not os.path.exists("/dev/kvm"):
        return "/dev/kvm not available"
    p = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if p.returncode != 0:
        return "docker daemon unreachable"
    if _run(["docker", "image", "inspect", CHR_IMAGE]).returncode != 0:
        return f"docker image {CHR_IMAGE} not present (docker pull {CHR_IMAGE})"
    if _run(["docker", "image", "inspect", PEER_IMAGE]).returncode != 0:
        return f"peer image {PEER_IMAGE} not present (set RL_PEER_IMAGE to any image with python3)"
    if not (KERNEL_DIR / "kernel_lab.py").exists():
        return "tests/kernel/kernel_lab.py missing"
    return None


def cleanup():
    """Removes every fv-lab-* container and network (idempotent)."""
    ps = _run(["docker", "ps", "-aq", "--filter", f"name={PREFIX}"]).stdout.split()
    if ps:
        _run(["docker", "rm", "-f", *ps])
    for n in NETS:
        _run(["docker", "network", "rm", PREFIX + n])


def leftovers() -> List[str]:
    out = _run(["docker", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={PREFIX}"]).stdout.split()
    nets = _run(["docker", "network", "ls", "--format", "{{.Name}}", "--filter", f"name={PREFIX}"]).stdout.split()
    return out + nets


def _inc_mac(mac: str) -> str:
    v = int(mac.replace(":", ""), 16) + 1
    return ":".join(f"{v:012X}"[i:i + 2] for i in range(0, 12, 2))


class RestError(RuntimeError):
    pass


class Console:
    """Serial console of the CHR (container stdio).  Only used to bootstrap the management IP."""

    def __init__(self):
        self.p = subprocess.Popen(["docker", "start", "-ai", CHR], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        self.buf = bytearray()
        self.lock = threading.Lock()
        threading.Thread(target=self._rd, daemon=True).start()

    def _rd(self):
        while True:
            b = self.p.stdout.read1(4096)
            if not b:
                break
            with self.lock:
                self.buf.extend(b)
            if b"\x1b[6n" in b:          # cursor position query: RouterOS blocks until it is answered
                try:
                    self.p.stdin.write(b"\x1b[1;200R")
                    self.p.stdin.flush()
                except Exception:
                    pass

    def text(self) -> str:
        with self.lock:
            return self.buf.decode(errors="replace")

    def send(self, s: str):
        self.p.stdin.write(s.encode())
        self.p.stdin.flush()

    def wait(self, pattern: str, timeout: float) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pattern, self.text()):
                return True
            time.sleep(0.2)
        return False

    def clear(self):
        with self.lock:
            self.buf.clear()

    def login(self):
        if not self.wait(r"Login:", BOOT_TIMEOUT):
            raise RuntimeError("CHR did not reach the login prompt:\n" + self.text()[-800:])
        time.sleep(0.5)
        self.clear()
        self.send("admin\r")
        self.wait(r"Password:", 10)
        time.sleep(0.3)
        self.send("\r")
        # first login: licence / new password prompts, then the normal prompt
        end = time.time() + 40
        while time.time() < end:
            t = self.text()
            if re.search(r"\] > ", t):
                return
            if re.search(r"software license", t, re.I) and not getattr(self, "_lic", False):
                self._lic = True
                self.send("n\r")
            elif re.search(r"new password>", t) and not getattr(self, "_pw1", False):
                self._pw1 = True
                self.send(PASSWORD + "\r")
            elif re.search(r"repeat new password>", t) and not getattr(self, "_pw2", False):
                self._pw2 = True
                self.send(PASSWORD + "\r")
            time.sleep(0.3)
        raise RuntimeError("CHR login failed:\n" + self.text()[-800:])

    def command(self, cmd: str, wait: float = 1.5) -> str:
        self.clear()
        self.send(cmd + "\r")
        time.sleep(wait)
        return self.text()

    def close(self):
        try:
            self.p.terminate()
        except Exception:
            pass


class Lab:
    """Creates / destroys the topology and runs packet batches through the CHR."""

    def __init__(self, settle: float = 1.2):
        self.settle = settle
        self.mac: Dict[str, str] = {}
        self.auth = None
        self.started = False
        self._pw = None
        self.script_n = 0

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        cleanup()
        atexit.register(cleanup)
        try:
            self._start()
        except BaseException:
            self.stop()
            raise
        self.started = True

    def stop(self):
        if getattr(self, "con", None):
            self.con.close()
        cleanup()
        self.started = False

    def _start(self):
        for n, (subnet, gw) in NETS.items():
            _run(["docker", "network", "create", "--subnet", subnet, "--gateway", gw,
              # no docker MASQUERADE: it would rewrite spoofed sources that belong to the other subnet
              "-o", "com.docker.network.bridge.enable_ip_masquerade=false", PREFIX + n], check=True)
        common = ["--user", "0", "-v", f"{HERE}:/lab:ro", "-v", f"{KERNEL_DIR}:/kernel:ro", "--entrypoint", "sleep"]
        _run(["docker", "create", "--name", CLIENT, "--network", PREFIX + "lan", "--ip", "192.168.1.50",
              *common, PEER_IMAGE, "infinity"], check=True)
        _run(["docker", "create", "--name", SERVER, "--network", PREFIX + "wan", "--ip", "203.0.113.10",
              *common, PEER_IMAGE, "infinity"], check=True)
        # the CHR container: every network must be connected BEFORE qemu starts (start.sh bridges what it finds)
        _run(["docker", "create", "--name", CHR, "-i", "--device", "/dev/kvm", "--device", "/dev/net/tun",
              "--cap-add", "NET_ADMIN", "--network", PREFIX + "mgmt", "--ip", "10.99.0.2", CHR_IMAGE], check=True)
        _run(["docker", "network", "connect", "--ip", "192.168.1.2", PREFIX + "lan", CHR], check=True)
        _run(["docker", "network", "connect", "--ip", "203.0.113.2", PREFIX + "wan", CHR], check=True)
        _run(["docker", "start", CLIENT, SERVER], check=True)
        con = self.con = Console()   # starts the CHR container (qemu) and attaches to its serial console
        time.sleep(2)
        ins = json.loads(_run(["docker", "inspect", CHR, CLIENT, SERVER], check=True).stdout)
        eps = {}
        for c in ins:
            for net, d in c["NetworkSettings"]["Networks"].items():
                eps[(c["Name"].lstrip("/"), net)] = d["MacAddress"].upper()
        # the CHR tap device of each docker veth gets (veth mac + 1) (start.sh increment_mac)
        chr_mac = {n: _inc_mac(eps[(CHR, PREFIX + n)]) for n in NETS}
        self.mac = dict(chr_lan=chr_mac["lan"], chr_wan=chr_mac["wan"], chr_mgmt=chr_mac["mgmt"],
                        client=eps[(CLIENT, PREFIX + "lan")], server=eps[(SERVER, PREFIX + "wan")])
        try:
            con.login()
            time.sleep(1)
            con.command(f"/ip address add address={MGMT_IP}/24 "
                        f"interface=[/interface ethernet find mac-address={self.mac['chr_mgmt']}]", 2)
            con.command("/user set admin password=%s" % PASSWORD, 1)
            con.command("/ip service set www port=%d" % REST_PORT, 1)
            self._wait_rest()
        except BaseException:
            con.close()
            raise
        # the console stays attached for the whole run: terminating the attached `docker start -ai` client would
        # forward SIGTERM to the container and shut the CHR down
        self._configure_base()

    def _wait_rest(self):
        end = time.time() + 40
        last = None
        for pw in (PASSWORD, ""):
            self.auth = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()
            while time.time() < end:
                try:
                    self.rest("GET", "system/identity")
                    return
                except Exception as exc:   # noqa: BLE001
                    last = exc
                    if "401" in str(exc):
                        break
                    time.sleep(1)
        raise RuntimeError(f"CHR REST API unreachable at {MGMT_IP}: {last}")

    # ------------------------------------------------------------------ REST
    def rest(self, method: str, path: str, body=None, timeout=60):
        req = urllib.request.Request(f"http://{MGMT_IP}:{REST_PORT}/rest/{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise RestError(f"{e.code}: {e.read().decode(errors='replace')}") from None

    def script(self, text: str, timeout=120) -> str:
        """Runs RouterOS script text through /system/script (same parser as /import).  Raises RestError on failure."""
        self.script_n += 1
        name = f"fvlab{self.script_n}"
        r = self.rest("PUT", "system/script", {"name": name, "source": text, "policy": "read,write,policy,test,reboot"})
        try:
            out = self.rest("POST", "system/script/run", {".id": r[".id"]}, timeout=timeout)
        finally:
            try:
                self.rest("DELETE", f"system/script/{r['.id']}")
            except RestError:
                pass
        return json.dumps(out)

    # ------------------------------------------------------------------ base configuration
    def _configure_base(self):
        m = self.mac
        # interfaces by MAC -> stable names
        for key, name in (("chr_lan", LAN_IF), ("chr_wan", WAN_IF), ("chr_mgmt", MGMT_IF)):
            ids = self.rest("GET", f"interface/ethernet?mac-address={m[key]}")
            if len(ids) != 1:
                raise RuntimeError(f"cannot find CHR interface with mac {m[key]}: {ids}")
            self.rest("PATCH", f"interface/ethernet/{ids[0]['.id']}", {"name": name})
        arps = []
        for i in range(2, 255):
            arps.append(f":do {{/ip arp add address=192.168.1.{i} mac-address={m['client']} interface={LAN_IF}}} on-error={{}}")
            arps.append(f":do {{/ip arp add address=203.0.113.{i} mac-address={m['server']} interface={WAN_IF}}} on-error={{}}")
        self.script("\n".join([
            f"/ip address add address=192.168.1.1/24 interface={LAN_IF}",
            f"/ip address add address=203.0.113.1/24 interface={WAN_IF}",
            "/ip route add dst-address=0.0.0.0/0 gateway=203.0.113.10",
            "/interface list add name=WAN", "/interface list add name=LAN",
            f"/interface list member add list=WAN interface={WAN_IF}",
            f"/interface list member add list=LAN interface={LAN_IF}",
            "/ip firewall connection tracking set enabled=yes",
            *arps]), timeout=180)
        self.safety()
        ident = self.rest("GET", "system/resource")
        self.version = ident.get("version")

    def safety(self):
        """Management safety rules: always first in their chains, never removed by reset()."""
        self.script("\n".join([
            f'/ip firewall filter add chain=input in-interface={MGMT_IF} action=accept comment={SAFETY}',
            f'/ip firewall raw add chain=prerouting in-interface={MGMT_IF} action=accept comment={SAFETY}',
            f'/ip firewall nat add chain=dstnat in-interface={MGMT_IF} action=accept comment={SAFETY}',
            f'/ip firewall nat add chain=srcnat out-interface={MGMT_IF} action=accept comment={SAFETY}',
            f'/ip firewall mangle add chain=prerouting in-interface={MGMT_IF} action=accept comment={SAFETY}',
        ]))

    def reset(self):
        self.script("\n".join(
            [f'/ip firewall {t} remove [find where comment!="{SAFETY}"]' for t in ("filter", "nat", "mangle", "raw")]
            + [f'/ip firewall {t} remove [find where !comment]' for t in ("filter", "nat", "mangle", "raw")]
            + ["/ip firewall address-list remove [find]", "/ip firewall connection remove [find]"]))

    def load(self, text: str):
        """Loads a RouterOS script; RestError if RouterOS rejects any line."""
        self.script(text)
        self.wait_valid()
        self.script("/ip firewall connection remove [find]")

    def wait_valid(self, timeout: float = 15.0):
        """Freshly added rules are reported `invalid=true` (inactive) until RouterOS has resolved them (interface names,
        lists); packets sent earlier would see a half-loaded ruleset.  Waits until no rule is invalid."""
        end = time.time() + timeout
        while True:
            bad = [r for t in ("filter", "nat", "mangle", "raw") for r in self.rest("GET", f"ip/firewall/{t}")
                   if r.get("invalid") == "true"]
            if not bad:
                return
            if time.time() > end:
                raise RestError(f"{len(bad)} rule(s) still invalid={bad[0].get('invalid')} after {timeout}s: "
                                f"{[{k: v for k, v in b.items() if not k.startswith('.')} for b in bad[:3]]}")
            time.sleep(0.2)

    def dump_rules(self) -> dict:
        out = {}
        for t in ("filter", "nat", "mangle", "raw"):
            out[t] = [{k: v for k, v in r.items() if not k.startswith(".") and k not in ("bytes", "packets")}
                      for r in self.rest("GET", f"ip/firewall/{t}")]
        return out

    # ------------------------------------------------------------------ packets
    def _exec(self, ctr: str, job: dict) -> list:
        path = HERE / "_out" / f"job_{ctr}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(job))
        p = _run(["docker", "exec", ctr, "python3", "/lab/agent.py", f"/lab/_out/job_{ctr}.json"], timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"agent failed in {ctr}: {p.stderr}")
        return json.loads(p.stdout)

    def run_packets(self, packets: List[dict]) -> Dict[str, dict]:
        """Sends the packets (IPv4 only) and returns {str(n): {"observed": dict|None, "back": dict|None}} in the
        format of kernel_harness.compare_case."""
        side = {}
        for p in packets:
            lan = p["flow"] in ("fwd_lan_wan", "input_lan")
            side[p["n"]] = "lan" if lan else "wan"
        jobs = {}
        for s, ctr, dmac, smac in (("lan", CLIENT, self.mac["chr_lan"], self.mac["client"]),
                                   ("wan", SERVER, self.mac["chr_wan"], self.mac["server"])):
            jobs[s] = dict(iface="eth0", dmac=dmac, smac=smac, send=[p for p in packets if side[p["n"]] == s],
                           delay=0.8, settle=self.settle)
        res = {}

        def go(s, ctr):
            res[s] = self._exec(ctr, jobs[s])
        ths = [threading.Thread(target=go, args=("lan", CLIENT)), threading.Thread(target=go, args=("wan", SERVER))]
        [t.start() for t in ths]
        [t.join() for t in ths]
        frames = [dict(f, where=w) for w in ("lan", "wan") for f in res[w]]
        return classify(packets, side, frames)


def classify(packets, side, frames) -> Dict[str, dict]:
    """Turns captured frames into kernel_harness observations.

    forwarded      : frame with ip id == n, ttl 63, same protocol, seen on the far side  -> observed (post-NAT header)
    input accepted : TCP RST / SYN-ACK, ICMP echo reply, ICMP port unreachable (code 3) for our packet
                     -> observed {where: local}  (RouterOS answered => the filter accepted the packet)
    reject / drop  : ICMP error with another code quoting the packet => back; nothing => DROP
    """
    by_id = {p["n"]: p for p in packets}
    out = {}
    for p in packets:
        n = p["n"]
        entry = {"observed": None, "back": None}
        fwd_side = "wan" if side[n] == "lan" else "lan"
        for f in frames:
            inner = f.get("inner")
            # any flow can end up forwarded (an input-flow packet may be DNAT-ed / netmapped to another host)
            # (either side: DNAT may send the packet back out of the interface it came in from; sent frames have ttl 64)
            if f["id"] == n and f.get("ttl") == 63 and f["proto"] == p["proto"] \
                    and not inner and not entry["observed"]:
                entry["observed"] = dict(where="fwd", src=f["src"], dst=f["dst"], sport=f.get("sport"),
                                         dport=f.get("dport"), proto=f["proto"])
                continue
            # replies / errors
            if inner and inner["id"] == n and f["proto"] == "icmp":
                if p["flow"].startswith("input") and f.get("icmp_code") == 3 and f["icmp_type"] == 3:
                    entry["observed"] = dict(where="local", src=p["src"], dst=p["dst"], sport=p["sport"],
                                             dport=p["dport"], proto=p["proto"], via="icmp-port-unreachable")
                elif f["icmp_type"] == 3 and f["dst"] == p["src"]:
                    entry["back"] = {"type": f"icmp3/{f.get('icmp_code')}", "from": f["src"], "where": f["where"]}
            elif p["flow"].startswith("input"):
                if p["proto"] == "icmp" and f["proto"] == "icmp" and f.get("icmp_type") == 0 and f.get("icmp_id") == n \
                        and f["dst"] == p["src"]:
                    entry["observed"] = dict(where="local", src=p["src"], dst=p["dst"], sport=None, dport=None,
                                             proto="icmp", via="echo-reply")
                elif p["proto"] == "tcp" and f["proto"] == "tcp" and f.get("ack") == n * 1000 + 1 and f["dst"] == p["src"]:
                    entry["observed"] = dict(where="local", src=p["src"], dst=p["dst"], sport=p["sport"],
                                             dport=p["dport"], proto="tcp", via="tcp-%02x" % f.get("tcpflags", 0))
            elif p["flow"].startswith("fwd") and p["proto"] == "tcp" and f["proto"] == "tcp" \
                    and (f.get("tcpflags", 0) & 0x04) and f["dst"] == p["src"] and f.get("ack") == n * 1000 + 1:
                entry["back"] = {"type": "rst", "from": f["src"], "where": f["where"]}
        if entry["observed"] and entry["observed"]["where"] == "fwd":
            entry["observed"]["where"] = "far"
        out[str(n)] = entry
    return out
