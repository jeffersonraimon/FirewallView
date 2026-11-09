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
    in_interface_list: Optional[str] = None # RouterOS interface-list / nft iifname set, e.g. WAN
    out_interface_list: Optional[str] = None
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
    negate_in_interface_list: bool = False
    negate_out_interface_list: bool = False
    negate_connection_nat_state: bool = False
    negate_connection_state: bool = False
    negate_packet_mark: bool = False
    negate_tcp_flags: bool = False

class FirewallRule(BaseModel):
    """Canonical rule model shared by every parser, exporter and the simulator.

    Contract (all parsers MUST normalise to it):
    - table: lowercase, one of raw | mangle | nat | filter.
    - chain: built-in chains lowercase. In the nat table PREROUTING => "dstnat"
      and POSTROUTING => "srcnat" (output stays "output"). Custom chains keep
      their name; target_chain must reference it with the same spelling.
    - action: lowercase (accept, drop, reject, jump, return, dst-nat, src-nat,
      masquerade, redirect, netmap, mark-packet, mark-connection, mark-routing,
      change-mss, log, passthrough, add-src-to-address-list,
      add-dst-to-address-list, fasttrack-connection, snpt, dnpt, ...).
    - family: None = applies to IPv4 and IPv6; "ipv4" or "ipv6" restricts it.
    - is_policy: True marks the chain's default policy (iptables -P / :CHAIN
      DROP, nft "policy drop;", Cisco/Junos implicit deny). The simulator
      always evaluates policy rules after every normal rule of that chain,
      whatever their order; they carry no conditions and action accept|drop.
    - parse_warnings: human-readable notes for anything the parser could not
      represent (unknown matcher, unsupported option). Never silently drop a
      matcher: either model it or add a warning.
    """
    id: str
    order: int = 1
    table: str = "filter" # raw, mangle, nat, filter
    chain: str = "forward" # prerouting, input, forward, output, postrouting, dstnat, srcnat, or custom
    family: Optional[str] = None # None (both), ipv4, ipv6
    is_policy: bool = False
    parse_warnings: List[str] = Field(default_factory=list)
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
