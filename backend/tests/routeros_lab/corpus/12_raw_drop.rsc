/ip firewall raw
add chain=prerouting action=drop src-address=198.51.100.0/24
add chain=prerouting action=drop protocol=udp dst-port=1900 in-interface=ether1-wan
add chain=prerouting action=accept src-address=192.168.1.100
add chain=prerouting action=drop protocol=tcp dst-port=23
/ip firewall filter
add chain=forward action=accept
add chain=input action=drop protocol=tcp dst-port=80
