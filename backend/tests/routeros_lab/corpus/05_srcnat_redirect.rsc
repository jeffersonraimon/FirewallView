/ip firewall nat
add chain=srcnat action=src-nat to-addresses=203.0.113.1 src-address=192.168.1.0/25 out-interface=ether1-wan
add chain=srcnat action=masquerade src-address=192.168.1.128/25 protocol=tcp
add chain=dstnat action=redirect to-ports=3128 protocol=tcp dst-port=80 in-interface=ether2-lan
add chain=dstnat action=redirect to-ports=5300 protocol=udp dst-port=53
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=3128
add chain=input action=accept protocol=udp dst-port=5300
add chain=input action=drop
