from typing import Dict, List, Tuple
from firewallview.models.rules import FirewallRule, RuleCondition
from firewallview.models.address_list import AddressList, AddressListEntry
from firewallview.parsers.routeros import parse_routeros_script
from firewallview.parsers.iptables import parse_iptables_script
from firewallview.parsers.cisco import parse_cisco_acl

PRESET_ROUTEROS = """
/ip firewall address-list
add address=10.0.0.0/8 list=BOGONS comment="RFC 1918 Private"
add address=172.16.0.0/12 list=BOGONS comment="RFC 1918 Private"
add address=192.168.0.0/16 list=BOGONS comment="RFC 1918 Private"
add address=192.168.88.2-192.168.88.20 list=TRUSTED_ADMINS comment="IT Staff"
add address=203.0.113.250 list=MALICIOUS_BOTNET comment="Known C2 IP"

/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=input action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=input action=accept protocol=icmp comment="defconf: accept ICMP"
add chain=input action=accept src-address-list=TRUSTED_ADMINS dst-port=22,80,443,8291 protocol=tcp comment="Allow Winbox and SSH from Admins"
add chain=input action=drop in-interface=ether1-wan comment="defconf: drop all not coming from LAN"

add chain=forward action=fasttrack-connection connection-state=established,related comment="defconf: fasttrack"
add chain=forward action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=forward action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=forward action=drop in-interface=ether1-wan src-address-list=BOGONS comment="Drop Bogon IPs from Internet"
add chain=forward action=drop src-address-list=MALICIOUS_BOTNET comment="Drop Botnet traffic"
add chain=forward action=accept in-interface=ether2-lan out-interface=ether1-wan comment="Allow LAN internet access"
add chain=forward action=accept dst-address=192.168.88.50 dst-port=80 protocol=tcp comment="Allow port forward to internal webserver"
add chain=forward action=drop comment="defconf: drop all else"

/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1-wan comment="defconf: masquerade"
add chain=dstnat action=dst-nat dst-port=8080 in-interface=ether1-wan protocol=tcp to-addresses=192.168.88.50 to-ports=80 comment="Port forward 8080->80"
"""

PRESET_IPTABLES = """
ipset create BAD_ACTORS hash:net
ipset add BAD_ACTORS 198.51.100.0/24
ipset add BAD_ACTORS 203.0.113.44

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.10:8080
iptables -A INPUT -m set --match-set BAD_ACTORS src -j DROP -m comment --comment "Block known malicious CIDR"
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT -m comment --comment "SSH only for internal subnet"
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -j DROP

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT -m comment --comment "LAN to WAN"
iptables -A FORWARD -p tcp -d 10.0.0.10 --dport 8080 -j ACCEPT
iptables -A FORWARD -j DROP

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
"""

PRESET_CISCO = """
object-group network BLOCKED_SUBNETS
 network-object 198.51.100.0 255.255.255.0
 network-object host 203.0.113.99

object-group network INTERNAL_SERVERS
 network-object 172.16.10.0 255.255.255.0
 network-object host 172.16.20.15

ip access-list extended EDGE_INBOUND
 deny ip object-group BLOCKED_SUBNETS any
 permit tcp any object-group INTERNAL_SERVERS eq 443
 permit tcp any object-group INTERNAL_SERVERS eq 80
 permit tcp any 172.16.10.0 0.0.0.255 eq 22 established
 permit icmp any any
 deny ip any any
"""

def get_preset(name: str) -> Tuple[List[FirewallRule], Dict[str, AddressList]]:
    name_clean = name.lower()
    if "cisco" in name_clean:
        return parse_cisco_acl(PRESET_CISCO)
    elif "iptables" in name_clean:
        return parse_iptables_script(PRESET_IPTABLES)
    else: # default routeros
        return parse_routeros_script(PRESET_ROUTEROS)
