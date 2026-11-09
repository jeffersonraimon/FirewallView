import re
from typing import Dict, List, Optional, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList

DMOS_SERVICES = {
    "bgp": "179",
    "ldp": "646",
    "ospf": "89",
    "rip": "520",
    "bfd": "3784",
    "ssh": "22",
    "telnet": "23",
    "ftp": "21",
    "ftp-data": "20",
    "tftp": "69",
    "http": "80",
    "https": "443",
    "snmp": "161",
    "snmp-trap": "162",
    "syslog": "514",
    "ntp": "123",
    "dns": "53",
    "domain": "53",
    "tacacs": "49",
    "radius": "1812",
}

DMOS_PROTOCOLS = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "46": "rsvp",
    "47": "gre",
    "50": "esp",
    "51": "ah",
    "89": "ospf",
    "112": "vrrp",
    "ipv6-icmp": "icmp6",
    "icmpv6": "icmp6",
}

def resolve_dmos_port(val: str) -> str:
    cleaned = val.strip().lower()
    return DMOS_SERVICES.get(cleaned, cleaned)

def resolve_dmos_protocol(val: str) -> str:
    cleaned = val.strip().lower()
    return DMOS_PROTOCOLS.get(cleaned, cleaned)

def parse_dmos_script(content: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    """
    Parses Datacom DmOS access-list and acl-profile configurations.

    - Each ``acl-profile [<kind>...] <NAME>`` gets its own chain. Profiles that
      target the CPU (``cpu`` token in the profile line, or NAME listed in a
      ``protection / cpu NAME`` line) use chain ``input``; other profiles use
      the profile name as chain (custom chain; the simulator fallback groups
      custom chains). Entries outside any profile keep the legacy behaviour
      (``input`` if the file mentions CPU protection, else ``forward``).
    - Rule ids are the entry sequence number when unique across the import,
      otherwise ``<profile>-<seq>`` (and a ``-N`` suffix if still duplicated).
    - ``order`` follows file order across all profiles.
    - Anything not modelled (unknown match criterion, extra tokens, unknown
      action, unknown line inside an entry) goes to ``parse_warnings``.
    - A DmOS implicit deny at the end of a profile is NOT modelled (not confirmed).
    """
    address_lists: Dict[str, AddressList] = {}
    rules: List[FirewallRule] = []

    lines = content.splitlines()
    lowered = content.lower()

    # Names referenced by "protection / cpu <NAME>"
    cpu_names = set()
    for ln in lines:
        mc = re.match(r"^\s*cpu\s+(\S+)\s*$", ln)
        if mc:
            cpu_names.add(mc.group(1))

    legacy_cpu = ("protection" in lowered and "cpu" in lowered)
    legacy_chain = "input" if legacy_cpu else "forward"

    current_profile: Optional[str] = None
    current_chain = legacy_chain

    current_entry_id: Optional[str] = None
    current_comment: Optional[str] = None
    current_cond = RuleCondition()
    current_action = "accept"
    current_family: Optional[str] = None
    current_warnings: List[str] = []
    current_seen: Dict[str, str] = {}
    current_raw_lines: List[str] = []
    rule_order = 1
    pending: List[Tuple[FirewallRule, Optional[str], str]] = []

    def reset_entry():
        nonlocal current_entry_id, current_comment, current_cond, current_action
        nonlocal current_raw_lines, current_family, current_warnings, current_seen
        current_entry_id = None
        current_comment = None
        current_cond = RuleCondition()
        current_action = "accept"
        current_family = None
        current_warnings = []
        current_seen = {}
        current_raw_lines = []

    def save_current_rule():
        nonlocal rule_order
        if current_entry_id is not None:
            r = FirewallRule(
                id=str(current_entry_id),
                order=rule_order,
                table="filter",
                chain=current_chain,
                family=current_family,
                action=current_action,
                conditions=current_cond,
                comment=current_comment or f"entry {current_entry_id}",
                parse_warnings=list(current_warnings),
                raw_syntax="; ".join(current_raw_lines)
            )
            pending.append((r, current_profile, str(current_entry_id)))
            rule_order += 1
        reset_entry()

    def set_family(fam: str):
        nonlocal current_family
        if current_family and current_family != fam:
            current_warnings.append("Entry mixes IPv4 and IPv6 matches; family set to the last one seen")
        current_family = fam

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # End delimiter
        if stripped == "!":
            save_current_rule()
            continue
        # Comment lines (e.g. the exporter's "! UNSUPPORTED: ...")
        if stripped.startswith("!"):
            continue

        m_prof = re.match(r"^acl-profile\s+(.+)$", stripped)
        if m_prof:
            save_current_rule()
            toks = m_prof.group(1).split()
            current_profile = toks[-1]
            is_cpu = ("cpu" in [t.lower() for t in toks[:-1]]) or current_profile in cpu_names
            current_chain = "input" if is_cpu else current_profile
            continue

        # Start of a new access-list-entry
        m_entry = re.match(r"^access-list-entry\s+(\d+)", stripped)
        if m_entry:
            save_current_rule()
            current_entry_id = m_entry.group(1)
            current_raw_lines.append(stripped)
            continue

        if current_entry_id is None:
            continue

        current_raw_lines.append(stripped)

        # description <comment>
        if stripped.startswith("description "):
            current_comment = stripped[len("description "):].strip()
            continue

        # action <permit|deny>
        if stripped.startswith("action "):
            act = stripped[len("action "):].strip().lower()
            if act in ["permit", "accept"]:
                current_action = "accept"
            elif act in ["deny", "drop"]:
                current_action = "drop"
            elif act == "reject":
                current_action = "reject"
            else:
                current_warnings.append(f"Unknown action '{act}' ignored (defaulting to accept): {stripped}")
            continue

        # match <criterion> <value>
        if stripped.startswith("match "):
            parts = stripped.split()
            if len(parts) < 3:
                current_warnings.append(f"Incomplete match ignored: {stripped}")
                continue
            criterion = parts[1].lower()
            val = parts[2]
            if len(parts) > 3:
                current_warnings.append(
                    f"Extra tokens ignored after value (ranges/lists/operators not modelled): {stripped}"
                )

            if criterion in current_seen and current_seen[criterion] != val:
                current_warnings.append(
                    f"Criterion '{criterion}' repeated with a different value; last one kept: {stripped}"
                )
            current_seen[criterion] = val

            if criterion in ["ip-protocol", "protocol"]:
                current_cond.protocol = resolve_dmos_protocol(val)

            elif criterion in ["source-ipv4-address", "source-ipv6-address", "source-ip", "src-ip"]:
                current_cond.src_address = val
                if "ipv6" in criterion:
                    set_family("ipv6")
                elif "ipv4" in criterion:
                    set_family("ipv4")

            elif criterion in ["destination-ipv4-address", "destination-ipv6-address", "destination-ip", "dst-ip"]:
                current_cond.dst_address = val
                if "ipv6" in criterion:
                    set_family("ipv6")
                elif "ipv4" in criterion:
                    set_family("ipv4")

            elif criterion in ["source-port", "src-port"]:
                current_cond.src_port = resolve_dmos_port(val)

            elif criterion in ["destination-port", "dst-port"]:
                current_cond.dst_port = resolve_dmos_port(val)

            elif criterion == "port":
                current_cond.port = resolve_dmos_port(val)

            elif criterion == "ethertype":
                if val.lower() == "arp":
                    current_cond.protocol = "arp"
                else:
                    current_warnings.append(f"Unsupported ethertype '{val}' ignored: {stripped}")

            else:
                current_warnings.append(f"Unsupported match criterion '{criterion}' ignored: {stripped}")
            continue

        current_warnings.append(f"Unrecognized line inside access-list-entry ignored: {stripped}")

    # Save last entry if buffer remains
    save_current_rule()

    # Make ids unique across the whole import.
    seq_count: Dict[str, int] = {}
    for _, _, seq in pending:
        seq_count[seq] = seq_count.get(seq, 0) + 1
    used = set()
    for r, prof, seq in pending:
        rid = seq if (seq_count[seq] == 1 or not prof) else f"{prof}-{seq}"
        base, n = rid, 2
        while rid in used:
            rid = f"{base}-{n}"
            n += 1
        used.add(rid)
        r.id = rid
        rules.append(r)

    return rules, address_lists
