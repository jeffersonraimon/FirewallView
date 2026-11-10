/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp dst-port=2222 in-interface=ether1-wan to-addresses=192.168.1.50 to-ports=22
add chain=srcnat action=masquerade out-interface=ether1-wan
/ip firewall filter
add chain=forward action=accept connection-nat-state=dstnat protocol=tcp
add chain=forward action=drop connection-nat-state=!dstnat in-interface=ether1-wan
add chain=forward action=accept in-interface=ether2-lan
add chain=forward action=drop
