import os
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
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

# Enable CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.get("/api/presets/{preset_name}")
def load_preset(preset_name: str):
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
    content_lower = content.lower()
    if "acl-profile" in content_lower or "access-list-entry" in content_lower or ("protection" in content_lower and "cpu" in content_lower):
        return "dmos"
    if "prefix-list" in content_lower or "term " in content_lower or "then accept" in content_lower or "then discard" in content_lower or "family inet" in content_lower:
        return "junos"
    if "/ip firewall" in content_lower or "/ipv6 firewall" in content_lower:
        return "routeros"
    if "access-list" in content_lower or "object-group network" in content_lower:
        return "cisco"
    if "table inet" in content_lower or "table ip" in content_lower or "nft " in content_lower:
        return "nftables"
    if "iptables" in content_lower or "ipset" in content_lower or "*filter" in content_lower:
        return "iptables"
    # Fallback default heuristic
    if "chain=" in content_lower or "action=" in content_lower:
        return "routeros"
    return "routeros"

@app.post("/api/import")
def import_rules(req: ImportRequest):
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

    return {
        "detected_syntax": syntax,
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

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
