import re
import shlex
import uuid
from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry

def parse_routeros_line(line: str) -> Dict[str, str]:
    """
    Parses a single RouterOS command line into a dictionary of key-value pairs.
    Handles quotes and equals signs properly.
    """
    props = {}
    tokens = []
    # Tokenize preserving quoted strings
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()

    for token in tokens:
        if "=" in token:
            k, v = token.split("=", 1)
            props[k.strip().lower()] = v.strip().strip('"\'')
        else:
            props[token.strip().lower()] = "true"
    return props

def parse_routeros_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses RouterOS (v6 and v7) export or script content.
    Returns (rules, address_lists).
    """
    rules: List[FirewallRule] = []
    address_lists: Dict[str, AddressList] = {}
    current_context = "" # e.g. /ip firewall filter, /ip firewall nat
    rule_order = 1

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check section header
        if line.startswith("/"):
            current_context = line.lower()
            continue

        # Determine table based on context or inline command
        cmd_line = line
        table = "filter"
        is_add_rule = False
        is_address_list = False

        if "/ip firewall filter" in cmd_line.lower() or "/ip firewall filter" in current_context:
            table = "filter"
            is_add_rule = "add" in cmd_line
        elif "/ip firewall nat" in cmd_line.lower() or "/ip firewall nat" in current_context:
            table = "nat"
            is_add_rule = "add" in cmd_line
        elif "/ip firewall mangle" in cmd_line.lower() or "/ip firewall mangle" in current_context:
            table = "mangle"
            is_add_rule = "add" in cmd_line
        elif "/ip firewall raw" in cmd_line.lower() or "/ip firewall raw" in current_context:
            table = "raw"
            is_add_rule = "add" in cmd_line
        elif "/ip firewall address-list" in cmd_line.lower() or "/ip firewall address-list" in current_context:
            is_address_list = "add" in cmd_line

        props = parse_routeros_line(cmd_line)

        if is_address_list:
            list_name = props.get("list")
            address = props.get("address")
            comment = props.get("comment")
            disabled = props.get("disabled", "").lower() in ["yes", "true"]

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

        if is_add_rule or "chain" in props:
            chain = props.get("chain", "forward" if table == "filter" else ("srcnat" if table == "nat" else "prerouting"))
            action = props.get("action", "accept")
            comment = props.get("comment")
            disabled = props.get("disabled", "").lower() in ["yes", "true"]

            cond = RuleCondition()

            # Protocol
            proto = props.get("protocol")
            if proto:
                if proto.startswith("!"):
                    cond.negate_protocol = True
                    cond.protocol = proto[1:]
                else:
                    cond.protocol = proto

            # Src address
            src_addr = props.get("src-address")
            if src_addr:
                if src_addr.startswith("!"):
                    cond.negate_src_address = True
                    cond.src_address = src_addr[1:]
                else:
                    cond.src_address = src_addr

            # Dst address
            dst_addr = props.get("dst-address")
            if dst_addr:
                if dst_addr.startswith("!"):
                    cond.negate_dst_address = True
                    cond.dst_address = dst_addr[1:]
                else:
                    cond.dst_address = dst_addr

            # Address lists
            src_list = props.get("src-address-list")
            if src_list:
                if src_list.startswith("!"):
                    cond.negate_src_address_list = True
                    cond.src_address_list = src_list[1:]
                else:
                    cond.src_address_list = src_list

            dst_list = props.get("dst-address-list")
            if dst_list:
                if dst_list.startswith("!"):
                    cond.negate_dst_address_list = True
                    cond.dst_address_list = dst_list[1:]
                else:
                    cond.dst_address_list = dst_list

            # Ports
            src_port = props.get("src-port")
            if src_port:
                if src_port.startswith("!"):
                    cond.negate_src_port = True
                    cond.src_port = src_port[1:]
                else:
                    cond.src_port = src_port

            dst_port = props.get("dst-port")
            if dst_port:
                if dst_port.startswith("!"):
                    cond.negate_dst_port = True
                    cond.dst_port = dst_port[1:]
                else:
                    cond.dst_port = dst_port

            # Interfaces (support in-interface and in-interface-list)
            in_iface = props.get("in-interface") or props.get("in-interface-list")
            if in_iface:
                if in_iface.startswith("!"):
                    cond.negate_in_interface = True
                    cond.in_interface = in_iface[1:]
                else:
                    cond.in_interface = in_iface

            out_iface = props.get("out-interface") or props.get("out-interface-list")
            if out_iface:
                if out_iface.startswith("!"):
                    cond.negate_out_interface = True
                    cond.out_interface = out_iface[1:]
                else:
                    cond.out_interface = out_iface

            # Connection states
            conn_state = props.get("connection-state")
            if conn_state:
                cond.connection_state = [s.strip() for s in conn_state.split(",")]

            # TCP flags
            tcp_flags = props.get("tcp-flags")
            if tcp_flags:
                cond.tcp_flags = [f.strip() for f in tcp_flags.split(",")]

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
