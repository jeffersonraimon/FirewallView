/ip firewall filter
add chain=forward action=reject reject-with=icmp-network-unreachable protocol=udp dst-port=53 in-interface=ether2-lan
add chain=forward action=reject reject-with=tcp-reset protocol=tcp dst-port=25
add chain=forward action=reject reject-with=icmp-admin-prohibited src-address=198.51.100.0/24
add chain=input action=reject reject-with=icmp-host-unreachable protocol=tcp dst-port=22 in-interface=ether1-wan
add chain=input action=accept protocol=icmp
add chain=input action=drop
