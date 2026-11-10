/ip firewall filter
add chain=forward action=drop protocol=tcp dst-port=1000-2000 in-interface=ether2-lan
add chain=forward action=accept protocol=tcp dst-port=80,443,8000-8100
add chain=forward action=drop src-address=203.0.113.10-203.0.113.30 protocol=udp
add chain=forward action=drop dst-address=192.168.1.64/26 protocol=tcp src-port=5000-5010
add chain=forward action=accept protocol=udp port=53
add chain=forward action=drop
add chain=input action=accept protocol=tcp dst-port=22,8291 src-address=192.168.1.0/24
add chain=input action=accept protocol=udp port=123,5000-5010
add chain=input action=drop
