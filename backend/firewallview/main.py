import os
import re
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from firewallview.models.rules import FirewallRule
from firewallview.models.packet import SimulationPacket, SimulationResult
from firewallview.models.address_list import AddressList
from firewallview.engine.simulator import FirewallSimulator
from firewallview.parsers.routeros import parse_routeros_script
from firewallview.parsers.iptables import parse_iptables_script
from firewallview.parsers.nftables import parse_nftables_script
from firewallview.parsers.cisco import parse_cisco_acl
from firewallview.parsers.junos import parse_junos_script
from firewallview.parsers.dmos import parse_dmos_script
from firewallview.exporters.routeros import export_to_routeros
from firewallview.exporters.iptables import export_to_iptables
from firewallview.exporters.nftables import export_to_nftables
from firewallview.exporters.cisco import export_to_cisco
from firewallview.exporters.junos import export_to_junos
from firewallview.exporters.dmos import export_to_dmos
from firewallview.samples.presets import get_preset

app = FastAPI(title="FirewallView API", version="1.0.0")

# CORS: origins configurable via FIREWALLVIEW_CORS_ORIGINS (comma separated, default "*").
# No credentials are used by the API, so allow_credentials stays off.
CORS_ORIGINS = [
    o.strip() for o in os.environ.get("FIREWALLVIEW_CORS_ORIGINS", "*").split(",") if o.strip()
] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Maximum accepted size for /api/import request bodies.
MAX_IMPORT_BYTES = 2 * 1024 * 1024

@app.middleware("http")
async def limit_import_size(request: Request, call_next):
    if request.url.path == "/api/import" and request.method == "POST":
        too_big = JSONResponse(
            status_code=413,
            content={"detail": f"Import payload too large (max {MAX_IMPORT_BYTES // (1024 * 1024)} MB)"},
        )
        length = request.headers.get("content-length")
        if length and length.isdigit():
            if int(length) > MAX_IMPORT_BYTES:
                return too_big
        else:
            body = await request.body()
            if len(body) > MAX_IMPORT_BYTES:
                return too_big
    return await call_next(request)

class SimulationRequest(BaseModel):
    packet: SimulationPacket
    rules: List[FirewallRule]
    address_lists: Dict[str, AddressList] = {}

class ImportRequest(BaseModel):
    syntax: str = "auto" # auto, routeros, iptables, nftables, cisco
    content: str

class ExportRequest(BaseModel):
    syntax: str # routeros, iptables, nftables, cisco
    rules: List[FirewallRule]
    address_lists: Dict[str, AddressList] = {}

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "FirewallView", "version": "1.0.0"}

# No nftables preset exists yet (get_preset would silently fall back to RouterOS).
KNOWN_PRESETS = {"routeros", "iptables", "cisco", "junos", "juniper", "dmos", "datacom"}

@app.get("/api/presets/{preset_name}")
def load_preset(preset_name: str):
    if preset_name.strip().lower() not in KNOWN_PRESETS:
        raise HTTPException(status_code=404, detail=f"Unknown preset: {preset_name}")
    rules, address_lists = get_preset(preset_name)
    return {
        "preset": preset_name,
        "rules": rules,
        "address_lists": address_lists
    }

@app.post("/api/simulate", response_model=SimulationResult)
def simulate_packet(req: SimulationRequest):
    simulator = FirewallSimulator(rules=req.rules, address_lists=req.address_lists)
    result = simulator.simulate(req.packet)
    return result

def detect_syntax(content: str) -> str:
    """Heuristic syntax detection: strong, anchored signals first, word-boundary regexes."""
    def has(pattern: str) -> bool:
        return re.search(pattern, content, re.IGNORECASE | re.MULTILINE) is not None

    # RouterOS
    if has(r"^\s*/ip(?:v6)?\s+firewall\b") or has(r"/ip(?:v6)?\s+firewall\b"):
        return "routeros"
    # iptables / ipset
    if (has(r"^\s*(?:sudo\s+)?(?:ip6?tables(?:-restore)?|ipset)\b")
            or has(r"^\*(?:filter|nat|mangle|raw)\s*$")
            or has(r"^\s*-A\s+\S+")
            or has(r"^:(?:INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)\s+(?:ACCEPT|DROP)\b")):
        return "iptables"
    # nftables
    if has(r"\btable\s+(?:inet|ip6?|arp|bridge|netdev)\s+\S+\s*\{") or has(r"^\s*(?:sudo\s+)?nft\s+"):
        return "nftables"
    # DmOS
    if has(r"\bacl-profile\b") or has(r"\baccess-list-entry\b") or (has(r"\bprotection\b") and has(r"\bcpu\b")):
        return "dmos"
    # Cisco
    if has(r"^\s*(?:ip|ipv6)?\s*access-list\b") or has(r"^\s*object-group\s+network\b"):
        return "cisco"
    # Junos
    if (has(r"\bfirewall\s*\{\s*family\b") or has(r"^\s*set\s+firewall\s+family\b")
            or has(r"^\s*family\s+inet6?\s*\{") or has(r"^\s*term\s+\S+\s*\{")
            or has(r"^\s*set\s+firewall\s+filter\b")):
        return "junos"
    # Weaker hints
    if has(r"\bchain=") or has(r"\baction="):
        return "routeros"
    return "routeros"

@app.post("/api/import")
def import_rules(req: ImportRequest):
    if len(req.content.encode("utf-8", errors="ignore")) > MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="Import payload too large (max 2 MB)")
    syntax = req.syntax.lower()
    if syntax == "auto":
        syntax = detect_syntax(req.content)

    if syntax in ["dmos", "datacom"]:
        rules, addr_lists = parse_dmos_script(req.content)
    elif syntax in ["junos", "juniper"]:
        rules, addr_lists = parse_junos_script(req.content)
    elif syntax == "routeros":
        rules, addr_lists = parse_routeros_script(req.content)
    elif syntax == "iptables":
        rules, addr_lists = parse_iptables_script(req.content)
    elif syntax == "nftables":
        rules, addr_lists = parse_nftables_script(req.content)
    elif syntax == "cisco":
        rules, addr_lists = parse_cisco_acl(req.content)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported syntax: {syntax}")

    warnings = [f"{r.id}: {w}" for r in rules for w in (r.parse_warnings or [])]

    return {
        "detected_syntax": syntax,
        "warnings": warnings,
        "rules": rules,
        "address_lists": addr_lists,
        "rules_count": len(rules),
        "address_lists_count": len(addr_lists)
    }

@app.post("/api/export")
def export_rules(req: ExportRequest):
    syntax = req.syntax.lower()
    if syntax in ["dmos", "datacom"]:
        text = export_to_dmos(req.rules, req.address_lists)
    elif syntax in ["junos", "juniper"]:
        text = export_to_junos(req.rules, req.address_lists)
    elif syntax == "routeros":
        text = export_to_routeros(req.rules, req.address_lists)
    elif syntax == "iptables":
        text = export_to_iptables(req.rules, req.address_lists)
    elif syntax == "nftables":
        text = export_to_nftables(req.rules, req.address_lists)
    elif syntax == "cisco":
        text = export_to_cisco(req.rules, req.address_lists)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported export syntax: {syntax}")

    return {
        "syntax": syntax,
        "content": text
    }

# Serve static files in production if frontend build exists
candidate_paths = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")),
    "/app/frontend/dist"
]
FRONTEND_DIST = None
for p in candidate_paths:
    if os.path.exists(os.path.join(p, "index.html")):
        FRONTEND_DIST = p
        break

if FRONTEND_DIST:
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    _FRONTEND_ROOT = os.path.realpath(FRONTEND_DIST)

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="Not found")
        if full_path:
            file_path = os.path.realpath(os.path.join(_FRONTEND_ROOT, full_path))
            inside = file_path.startswith(_FRONTEND_ROOT + os.sep)
            if inside and os.path.isfile(file_path):
                return FileResponse(file_path)
        return FileResponse(os.path.join(_FRONTEND_ROOT, "index.html"))
