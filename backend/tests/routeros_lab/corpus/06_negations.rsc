/ip firewall filter
add chain=forward action=drop src-address=!192.168.1.0/24 in-interface=ether2-lan
add chain=forward action=drop dst-port=!80 protocol=tcp in-interface=ether1-wan
add chain=forward action=drop protocol=!tcp dst-address=192.168.1.100
add chain=forward action=accept in-interface=!ether1-wan
add chain=forward action=drop out-interface=!ether1-wan src-address=!203.0.113.10
add chain=input action=drop in-interface=!ether2-lan protocol=!icmp
add chain=input action=accept src-address=!198.51.100.0/24 protocol=icmp
add chain=input action=drop src-port=!1000-2000 protocol=udp
