import re
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def merge_multiline_routeros(content: str) -> List[str]:
    """
    Handles RouterOS multiline export lines with trailing backslash (\\).
    Concatenates continuations properly, respecting '=' bindings.
    """
    merged: List[str] = []
    buffer = ""
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line:
            if buffer.strip():
                merged.append(buffer.strip())
                buffer = ""
            continue

        is_continuation = line.endswith("\\")
        clean_content = line[:-1].rstrip() if is_continuation else line.strip()

        if buffer.endswith("="):
            buffer += clean_content.lstrip()
        else:
            buffer = (buffer + " " + clean_content).strip() if buffer else clean_content

        if not is_continuation:
            if buffer.strip():
                merged.append(buffer.strip())
            buffer = ""

    if buffer.strip():
        merged.append(buffer.strip())
    return merged

def parse_routeros_line(line: str) -> Dict[str, str]:
    """
    Parses a single RouterOS command line into a dictionary of key-value pairs.
    Handles quotes and flags properly using regex.
    """
    pattern = r"""([a-zA-Z0-9_\-\./]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\s]+)))?"""
    matches = re.findall(pattern, line)
    props: Dict[str, str] = {}
    for m in matches:
        k = m[0].lower()
        v = m[1] or m[2] or m[3]
        if v == "":
            if f"{m[0]}=" in line:
                props[k] = ""
            else:
                props[k] = "true"
        else:
            props[k] = v
    return props

def parse_routeros_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses RouterOS (v6 and v7) export, script, or terminal print content.
    Returns (rules, address_lists).
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    current_context = ""
    rule_order = 1
    pending_comment = None

    lines = merge_multiline_routeros(content)

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Check comment-only lines
        if line_clean.startswith(";;;"):
            pending_comment = line_clean[3:].strip()
            continue
        if line_clean.startswith("#"):
            c_text = line_clean[1:].strip()
            # Ignore standard RouterOS export date headers like "# mar/21/2026 12:00:00 by RouterOS"
            if c_text and not re.match(r"^[a-zA-Z]{3}/\d{2}/\d{4}", c_text):
                pending_comment = c_text
            continue

        # Check if line is terminal print header or banner
        if line_clean.startswith("Flags:") or line_clean.startswith("Columns:"):
            continue

        # Check section header without add (e.g. "/ip firewall filter" or "/ip firewall nat")
        if line_clean.startswith("/") and " add" not in line_clean.lower() and not line_clean.lower().endswith("add"):
            current_context = line_clean.lower()
            continue

        # Detect table and type from inline command or current context
        cmd_lower = line_clean.lower()
        is_address_list = False
        table = "filter"

        # Explicit command path takes precedence over ongoing context
        if "/ip firewall filter" in cmd_lower:
            table = "filter"
            current_context = "/ip firewall filter"
        elif "/ip firewall nat" in cmd_lower:
            table = "nat"
            current_context = "/ip firewall nat"
        elif "/ip firewall mangle" in cmd_lower:
            table = "mangle"
            current_context = "/ip firewall mangle"
        elif "/ip firewall raw" in cmd_lower:
            table = "raw"
            current_context = "/ip firewall raw"
        elif "/ip firewall address-list" in cmd_lower:
            is_address_list = True
            current_context = "/ip firewall address-list"
        elif "/ip firewall nat" in current_context or current_context.endswith("nat"):
            table = "nat"
        elif "/ip firewall mangle" in current_context or current_context.endswith("mangle"):
            table = "mangle"
        elif "/ip firewall raw" in current_context or current_context.endswith("raw"):
            table = "raw"
        elif "/ip firewall address-list" in current_context or "address-list" in current_context:
            is_address_list = True
        else:
            table = "filter"

        # Check print format flags (e.g. " 0 X  chain=forward...")
        disabled_from_flag = False
        print_match = re.match(r"^\s*\d+\s+([XID\s]+)(?:;;;.*)?\s*(chain=.*|add.*)", line_clean, re.IGNORECASE)
        if print_match:
            flags = print_match.group(1)
            if "X" in flags:
                disabled_from_flag = True
            line_clean = print_match.group(2)

        props = parse_routeros_line(line_clean)

        # Infer table if not already explicitly set
        chain_val = props.get("chain", "").lower()
        if not is_address_list:
            if chain_val in ["srcnat", "dstnat"]:
                table = "nat"
            elif table == "filter" and any(k.startswith("new-") for k in props):
                table = "mangle"

        # Check if address list command
        if is_address_list or ("list" in props and "address" in props):
            list_name = props.get("list")
            address = props.get("address")
            comment = props.get("comment") or pending_comment
            pending_comment = None
            disabled = disabled_from_flag or (props.get("disabled", "").lower() in ["yes", "true"])

            if list_name and address:
                if list_name not in address_lists:
                    address_lists[list_name] = AddressList(name=list_name, entries=[])
                address_lists[list_name].entries.append(
                    AddressListEntry(
                        id=str(uuid.uuid4())[:8],
                        address=address,
                        comment=comment,
                        disabled=disabled
                    )
                )
            continue

        # Check if rule command (add or contains chain=)
        is_add_rule = "add" in props or line_clean.lower().startswith("add") or "chain" in props
        if is_add_rule:
            chain = props.get("chain", "forward" if table == "filter" else ("srcnat" if table == "nat" else "prerouting"))
            action = props.get("action", "accept")
            comment = props.get("comment") or pending_comment
            pending_comment = None
            disabled = disabled_from_flag or (props.get("disabled", "").lower() in ["yes", "true"])

            cond = RuleCondition()

            # Protocol
            proto = props.get("protocol")
            if proto:
                if proto.startswith("!"):
                    cond.negate_protocol = True
                    proto = proto[1:]
                proto_clean = re.sub(r"^\d+\s*\((.*?)\)$", r"\1", proto).strip().lower()
                proto_map = {"6": "tcp", "17": "udp", "1": "icmp", "47": "gre", "50": "esp"}
                cond.protocol = proto_map.get(proto_clean, proto_clean)

            # Addresses
            src_addr = props.get("src-address")
            if src_addr:
                if src_addr.startswith("!"):
                    cond.negate_src_address = True
                    src_addr = src_addr[1:]
                cond.src_address = src_addr

            dst_addr = props.get("dst-address")
            if dst_addr:
                if dst_addr.startswith("!"):
                    cond.negate_dst_address = True
                    dst_addr = dst_addr[1:]
                cond.dst_address = dst_addr

            # Address lists
            src_list = props.get("src-address-list")
            if src_list:
                if src_list.startswith("!"):
                    cond.negate_src_address_list = True
                    src_list = src_list[1:]
                cond.src_address_list = src_list

            dst_list = props.get("dst-address-list")
            if dst_list:
                if dst_list.startswith("!"):
                    cond.negate_dst_address_list = True
                    dst_list = dst_list[1:]
                cond.dst_address_list = dst_list

            # Ports
            src_port = props.get("src-port")
            if src_port:
                if src_port.startswith("!"):
                    cond.negate_src_port = True
                    src_port = src_port[1:]
                cond.src_port = src_port

            dst_port = props.get("dst-port")
            if dst_port:
                if dst_port.startswith("!"):
                    cond.negate_dst_port = True
                    dst_port = dst_port[1:]
                cond.dst_port = dst_port

            # Interfaces
            in_iface = props.get("in-interface") or props.get("in-interface-list")
            if in_iface:
                if in_iface.startswith("!"):
                    cond.negate_in_interface = True
                    in_iface = in_iface[1:]
                cond.in_interface = in_iface

            out_iface = props.get("out-interface") or props.get("out-interface-list")
            if out_iface:
                if out_iface.startswith("!"):
                    cond.negate_out_interface = True
                    out_iface = out_iface[1:]
                cond.out_interface = out_iface

            # Connection states
            conn_state = props.get("connection-state")
            if conn_state:
                cond.connection_state = [s.strip() for s in conn_state.split(",") if s.strip()]

            # TCP flags
            tcp_flags = props.get("tcp-flags")
            if tcp_flags:
                cond.tcp_flags = [f.strip() for f in tcp_flags.split(",") if f.strip()]

            # Packet marks
            pkt_mark = props.get("packet-mark")
            if pkt_mark:
                cond.packet_mark = pkt_mark

            target_chain = props.get("jump-target")
            nat_to_addresses = props.get("to-addresses")
            nat_to_ports = props.get("to-ports")
            mark_value = props.get("new-packet-mark") or props.get("new-routing-mark") or props.get("new-connection-mark")

            rule = FirewallRule(
                id=str(rule_order),
                order=rule_order,
                table=table,
                chain=chain,
                action=action,
                target_chain=target_chain,
                nat_to_addresses=nat_to_addresses,
                nat_to_ports=nat_to_ports,
                mark_value=mark_value,
                conditions=cond,
                comment=comment,
                disabled=disabled,
                raw_syntax=line
            )
            rules.append(rule)
            rule_order += 1

    return rules, address_lists
