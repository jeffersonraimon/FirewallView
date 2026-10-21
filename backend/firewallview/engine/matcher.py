import ipaddress
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.packet import SimulationPacket
from firewallview.models.address_list import AddressList

def parse_ip_or_network(value: str):
    """Parses single IP, CIDR, or returns range tuple."""
    value = value.strip()
    if "-" in value:
        parts = value.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(parts[0].strip())
            end_ip = ipaddress.ip_address(parts[1].strip())
            return ("range", start_ip, end_ip)
        except ValueError:
            pass
    try:
        if "/" in value:
            return ("network", ipaddress.ip_network(value, strict=False))
        return ("ip", ipaddress.ip_address(value))
    except ValueError:
        return ("invalid", value)

def is_ip_matching(packet_ip_str: str, condition_str: str) -> bool:
    """Checks if packet_ip matches single IP, CIDR, or range."""
    try:
        pkt_ip = ipaddress.ip_address(packet_ip_str.strip())
    except ValueError:
        return False

    parsed = parse_ip_or_network(condition_str)
    kind = parsed[0]
    if kind == "range":
        _, start_ip, end_ip = parsed
        return start_ip <= pkt_ip <= end_ip
    elif kind == "network":
        _, net = parsed
        return pkt_ip in net
    elif kind == "ip":
        _, ip = parsed
        return pkt_ip == ip
    return False

def is_ip_in_address_list(packet_ip_str: str, address_list: AddressList) -> bool:
    """Checks if packet_ip matches any active entry in AddressList."""
    for entry in address_list.entries:
        if entry.disabled:
            continue
        if is_ip_matching(packet_ip_str, entry.address):
            return True
    return False

def parse_port_specs(port_str: str) -> List[Tuple[int, int]]:
    """Parses port specs like '80', '80,443', '1000-2000' into list of (min, max) ranges."""
    ranges = []
    for item in port_str.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            p_parts = item.split("-", 1)
            try:
                p1, p2 = int(p_parts[0].strip()), int(p_parts[1].strip())
                ranges.append((min(p1, p2), max(p1, p2)))
            except ValueError:
                pass
        else:
            try:
                p = int(item)
                ranges.append((p, p))
            except ValueError:
                pass
    return ranges

def is_port_matching(packet_port: int, condition_str: str) -> bool:
    """Checks if packet_port is in port specifications."""
    specs = parse_port_specs(condition_str)
    for p_min, p_max in specs:
        if p_min <= packet_port <= p_max:
            return True
    return False

def is_interface_matching(packet_iface: str, condition_iface: str) -> bool:
    """
    Supports exact match, wildcard * (e.g. ether*), interface lists (e.g. WAN, LAN),
    and composite entries like 'ether1, WAN' or 'ether1-wan'.
    """
    if not packet_iface or not condition_iface:
        return False
    pkt = packet_iface.strip().lower()
    cond = condition_iface.strip().lower()

    if cond.endswith("*"):
        prefix = cond[:-1]
        return pkt.startswith(prefix)

    # 1. Exact match
    if pkt == cond:
        return True

    # 2. Tokenized match (e.g. packet is "ether1, WAN", "ether1 (WAN)", or "ether1-wan")
    tokens = [t for t in re.split(r"[\s,;()/\-]+", pkt) if t]
    if cond in tokens:
        return True

    cond_tokens = [t for t in re.split(r"[\s,;()/\-]+", cond) if t]
    if pkt in cond_tokens:
        return True

    return False

def evaluate_rule_match(
    rule: FirewallRule,
    packet: SimulationPacket,
    address_lists: Dict[str, AddressList]
) -> Tuple[bool, List[str]]:
    """
    Evaluates whether the packet matches all conditions in the rule.
    Returns (matched: bool, reasons: list of explanation strings).
    """
    if rule.disabled:
        return False, ["Rule is disabled"]

    reasons: List[str] = []
    c = rule.conditions

    # 1. Protocol match
    if c.protocol and c.protocol.strip():
        cond_proto = c.protocol.strip().lower()
        pkt_proto = packet.protocol.strip().lower()
        if cond_proto not in ["any", "all", "ip"]:
            proto_match = (cond_proto == pkt_proto)
            if c.negate_protocol:
                proto_match = not proto_match

            if proto_match:
                reasons.append(f"Protocol: {pkt_proto} matches {cond_proto}")
            else:
                reasons.append(f"Protocol mismatch: packet is {pkt_proto}, rule requires {cond_proto}")
                return False, reasons

    # 2. Source Address
    if c.src_address and c.src_address.strip():
        matched = is_ip_matching(packet.src_ip, c.src_address.strip())
        if c.negate_src_address:
            matched = not matched

        if matched:
            reasons.append(f"Src IP: {packet.src_ip} matches condition {c.src_address}")
        else:
            reasons.append(f"Src IP mismatch: {packet.src_ip} does not match {c.src_address}")
            return False, reasons

    # 3. Destination Address
    if c.dst_address and c.dst_address.strip():
        matched = is_ip_matching(packet.dst_ip, c.dst_address.strip())
        if c.negate_dst_address:
            matched = not matched

        if matched:
            reasons.append(f"Dst IP: {packet.dst_ip} matches condition {c.dst_address}")
        else:
            reasons.append(f"Dst IP mismatch: {packet.dst_ip} does not match {c.dst_address}")
            return False, reasons

    # 4. Source Address List
    if c.src_address_list and c.src_address_list.strip():
        list_name = c.src_address_list.strip()
        addr_list = address_lists.get(list_name)
        matched = False
        if addr_list:
            matched = is_ip_in_address_list(packet.src_ip, addr_list)
        if c.negate_src_address_list:
            matched = not matched

        if matched:
            reasons.append(f"Src IP {packet.src_ip} is in address list '{list_name}'")
        else:
            reasons.append(f"Src IP {packet.src_ip} is NOT in address list '{list_name}'")
            return False, reasons

    # 5. Destination Address List
    if c.dst_address_list and c.dst_address_list.strip():
        list_name = c.dst_address_list.strip()
        addr_list = address_lists.get(list_name)
        matched = False
        if addr_list:
            matched = is_ip_in_address_list(packet.dst_ip, addr_list)
        if c.negate_dst_address_list:
            matched = not matched

        if matched:
            reasons.append(f"Dst IP {packet.dst_ip} is in address list '{list_name}'")
        else:
            reasons.append(f"Dst IP {packet.dst_ip} is NOT in address list '{list_name}'")
            return False, reasons

    # 6. Any Port (port= in MikroTik, matches either src or dst port)
    if c.port and c.port.strip():
        if packet.protocol.lower() in ["tcp", "udp"]:
            src_m = is_port_matching(packet.src_port or 0, c.port.strip())
            dst_m = is_port_matching(packet.dst_port or 0, c.port.strip())
            matched = src_m or dst_m
            if c.negate_port:
                matched = not matched

            if matched:
                reasons.append(f"Port (src or dst) matches {c.port}")
            else:
                reasons.append(f"Port mismatch: neither src ({packet.src_port}) nor dst ({packet.dst_port}) matches {c.port}")
                return False, reasons
        else:
            reasons.append(f"Port mismatch: protocol {packet.protocol} has no ports, rule requires port {c.port}")
            return False, reasons

    # 7. Source Port (only applies if protocol is tcp or udp)
    if c.src_port and c.src_port.strip():
        if packet.protocol.lower() in ["tcp", "udp"]:
            pkt_port = packet.src_port if packet.src_port is not None else 0
            matched = is_port_matching(pkt_port, c.src_port.strip())
            if c.negate_src_port:
                matched = not matched

            if matched:
                reasons.append(f"Src Port {pkt_port} matches condition {c.src_port}")
            else:
                reasons.append(f"Src Port mismatch: {pkt_port} does not match {c.src_port}")
                return False, reasons
        else:
            reasons.append(f"Src Port mismatch: protocol {packet.protocol} has no ports, rule requires port {c.src_port}")
            return False, reasons

    # 8. Destination Port
    if c.dst_port and c.dst_port.strip():
        if packet.protocol.lower() in ["tcp", "udp"]:
            pkt_port = packet.dst_port if packet.dst_port is not None else 0
            matched = is_port_matching(pkt_port, c.dst_port.strip())
            if c.negate_dst_port:
                matched = not matched

            if matched:
                reasons.append(f"Dst Port {pkt_port} matches condition {c.dst_port}")
            else:
                reasons.append(f"Dst Port mismatch: {pkt_port} does not match {c.dst_port}")
                return False, reasons
        else:
            reasons.append(f"Dst Port mismatch: protocol {packet.protocol} has no ports, rule requires port {c.dst_port}")
            return False, reasons

    # 8. In-Interface
    if c.in_interface and c.in_interface.strip():
        matched = is_interface_matching(packet.in_interface or "", c.in_interface.strip())
        if c.negate_in_interface:
            matched = not matched

        if matched:
            reasons.append(f"In-Interface '{packet.in_interface}' matches '{c.in_interface}'")
        else:
            reasons.append(f"In-Interface mismatch: '{packet.in_interface}' != '{c.in_interface}'")
            return False, reasons

    # 9. Out-Interface
    if c.out_interface and c.out_interface.strip():
        matched = is_interface_matching(packet.out_interface or "", c.out_interface.strip())
        if c.negate_out_interface:
            matched = not matched

        if matched:
            reasons.append(f"Out-Interface '{packet.out_interface}' matches '{c.out_interface}'")
        else:
            reasons.append(f"Out-Interface mismatch: '{packet.out_interface}' != '{c.out_interface}'")
            return False, reasons

    # 10. Connection State
    if c.connection_state and len(c.connection_state) > 0:
        # Check if packet's connection state is in any of the rule's allowed states
        rule_states = [s.strip().lower() for s in c.connection_state if s.strip()]
        pkt_state = (packet.connection_state or "new").strip().lower()
        if pkt_state in rule_states:
            reasons.append(f"Connection state '{pkt_state}' matches allowed {rule_states}")
        else:
            reasons.append(f"Connection state mismatch: '{pkt_state}' not in {rule_states}")
            return False, reasons

    # 11. TCP Flags
    if c.tcp_flags and len(c.tcp_flags) > 0:
        if packet.protocol.lower() != "tcp":
            reasons.append(f"TCP Flags mismatch: packet protocol is {packet.protocol}, rule requires TCP flags {c.tcp_flags}")
            return False, reasons
        pkt_flags = set(f.strip().lower() for f in packet.tcp_flags)
        flag_mismatch = False
        for flag_req in c.tcp_flags:
            flag_req = flag_req.strip().lower()
            if flag_req.startswith("!"):
                actual_flag = flag_req[1:]
                if actual_flag in pkt_flags:
                    reasons.append(f"TCP Flag mismatch: '{actual_flag}' must NOT be set")
                    flag_mismatch = True
                    break
            else:
                if flag_req not in pkt_flags:
                    reasons.append(f"TCP Flag mismatch: '{flag_req}' is not set in packet")
                    flag_mismatch = True
                    break
        if flag_mismatch:
            return False, reasons
        else:
            reasons.append(f"TCP Flags {list(pkt_flags)} matched requirements {c.tcp_flags}")

    if not reasons:
        reasons.append("Match all (unconditional rule)")

    return True, reasons
