from typing import List, Optional
from pydantic import BaseModel, Field

class RuleCondition(BaseModel):
    src_address: Optional[str] = None
    dst_address: Optional[str] = None
    src_address_list: Optional[str] = None
    dst_address_list: Optional[str] = None
    protocol: Optional[str] = None # tcp, udp, icmp, gre, any, etc.
    src_port: Optional[str] = None # 1024-65535, 80, 80,443
    dst_port: Optional[str] = None # 22, 80,443, 8000-9000
    port: Optional[str] = None # Matches either src_port or dst_port (MikroTik port=...)
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None
    connection_state: Optional[List[str]] = Field(default_factory=list) # new, established, related, invalid, untracked
    connection_nat_state: Optional[str] = None # dstnat, srcnat
    limit: Optional[str] = None # 50,5:packet
    ipsec_policy: Optional[str] = None # out,none
    tcp_flags: Optional[List[str]] = Field(default_factory=list) # syn, ack, fin, rst, etc.
    packet_mark: Optional[str] = None

    # Negations
    negate_src_address: bool = False
    negate_dst_address: bool = False
    negate_src_address_list: bool = False
    negate_dst_address_list: bool = False
    negate_protocol: bool = False
    negate_src_port: bool = False
    negate_dst_port: bool = False
    negate_port: bool = False
    negate_in_interface: bool = False
    negate_out_interface: bool = False
    negate_connection_nat_state: bool = False

class FirewallRule(BaseModel):
    id: str
    order: int = 1
    table: str = "filter" # raw, mangle, nat, filter
    chain: str = "forward" # prerouting, input, forward, output, postrouting, dstnat, srcnat, or custom
    action: str = "accept" # accept, drop, reject, fasttrack-connection, add-src-to-address-list, etc.
    target_chain: Optional[str] = None
    nat_to_addresses: Optional[str] = None
    nat_to_ports: Optional[str] = None
    mark_value: Optional[str] = None
    address_list_target: Optional[str] = None # target list for add-src-to-address-list
    address_list_timeout: Optional[str] = None # e.g. 3d, 10s
    npt_src_prefix: Optional[str] = None # NPTv6 matching prefix (RFC 6296)
    npt_dst_prefix: Optional[str] = None # NPTv6 target prefix (RFC 6296)
    conditions: RuleCondition = Field(default_factory=RuleCondition)
    comment: Optional[str] = None
    disabled: bool = False
    raw_syntax: Optional[str] = None
