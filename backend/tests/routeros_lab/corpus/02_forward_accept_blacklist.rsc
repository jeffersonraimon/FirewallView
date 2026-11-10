# Default accept, explicit drops (single host, CIDR, range, port).
/ip firewall filter
add chain=forward action=drop src-address=198.51.100.7
add chain=forward action=drop dst-address=203.0.113.0/28 protocol=tcp dst-port=443
add chain=forward action=drop src-address=192.168.1.100-192.168.1.150 protocol=udp
add chain=forward action=drop protocol=tcp src-port=1000-2000
add chain=input action=drop src-address=203.0.113.0/25 protocol=tcp dst-port=8080
