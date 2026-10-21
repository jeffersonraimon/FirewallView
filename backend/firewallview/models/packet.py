from typing import List, Optional
from pydantic import BaseModel, Field

class SimulationPacket(BaseModel):
    src_ip: str = "192.168.1.50"
    dst_ip: str = "1.1.1.1"
    src_port: Optional[int] = 51234
    dst_port: Optional[int] = 443
    protocol: str = "tcp" # tcp, udp, icmp, gre, etc.
    in_interface: Optional[str] = "ether2-lan"
    out_interface: Optional[str] = "ether1-wan"
    connection_state: str = "new" # new, established, related, invalid, untracked
    tcp_flags: List[str] = Field(default_factory=lambda: ["syn"]) # syn, ack, fin, rst, etc.
    packet_marks: List[str] = Field(default_factory=list)
    connection_nat_state: Optional[str] = None # dstnat, srcnat, or None
    flow_type: str = "forward" # "forward" (transit), "input" (to router), "output" (from router)
    is_router_traffic: bool = False # kept for backward compatibility

class RuleEvaluation(BaseModel):
    rule_id: str
    rule_order: int
    table: str
    chain: str
    action: str
    matched: bool
    reasons: List[str] = Field(default_factory=list)
    applied_effect: Optional[str] = None
    terminated: bool = False
    comment: Optional[str] = None
    raw_syntax: Optional[str] = None

class StageEvaluation(BaseModel):
    stage_id: str
    stage_title: str
    table: str
    chain: str
    evaluated_rules: List[RuleEvaluation] = Field(default_factory=list)
    stage_verdict: str = "CONTINUE" # CONTINUE, ACCEPTED, DROPPED, REJECTED
    notes: Optional[str] = None

class SimulationResult(BaseModel):
    verdict: str # ACCEPT, DROP, REJECT, DEFAULT_ACCEPT, DEFAULT_DROP
    final_action: str
    packet_in: SimulationPacket
    packet_out: SimulationPacket
    stages: List[StageEvaluation] = Field(default_factory=list)
    flow_path: List[str] = Field(default_factory=list)
    summary: str
    matched_rule_id: Optional[str] = None
