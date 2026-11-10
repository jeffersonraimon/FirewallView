/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 in-interface=ether1-wan to-addresses=192.168.1.50 to-ports=80
add chain=dstnat action=dst-nat protocol=udp dst-port=5353 in-interface=ether1-wan to-addresses=192.168.1.100
add chain=srcnat action=masquerade out-interface=ether1-wan
/ip firewall filter
add chain=forward action=accept connection-nat-state=dstnat
add chain=forward action=accept in-interface=ether2-lan
add chain=forward action=drop
add chain=input action=drop in-interface=ether1-wan
