# Port forward on the WAN address plus hairpin from the LAN.
/ip firewall nat
add chain=dstnat action=dst-nat dst-address=203.0.113.1 protocol=tcp dst-port=2222 to-addresses=192.168.1.50 to-ports=22
add chain=dstnat action=dst-nat dst-address=203.0.113.1 protocol=tcp dst-port=8000-8100 to-addresses=192.168.1.100
add chain=srcnat action=masquerade out-interface=ether1-wan
add chain=srcnat action=masquerade src-address=192.168.1.0/24 dst-address=192.168.1.0/24
/ip firewall filter
add chain=forward action=accept connection-nat-state=dstnat
add chain=forward action=accept in-interface=ether2-lan
add chain=forward action=drop
add chain=input action=accept in-interface=ether2-lan
add chain=input action=drop
