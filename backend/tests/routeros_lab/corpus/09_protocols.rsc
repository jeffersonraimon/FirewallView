/ip firewall filter
add chain=forward action=accept protocol=icmp in-interface=ether2-lan
add chain=forward action=drop protocol=icmp
add chain=forward action=accept protocol=udp dst-port=53,123
add chain=forward action=drop protocol=udp
add chain=forward action=accept protocol=tcp dst-port=443
add chain=forward action=drop protocol=!tcp
add chain=input action=accept protocol=icmp
add chain=input action=drop protocol=udp
add chain=input action=accept protocol=tcp dst-port=22
add chain=input action=drop
