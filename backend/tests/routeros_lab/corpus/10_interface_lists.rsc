/ip firewall filter
add chain=input action=accept in-interface-list=LAN
add chain=input action=accept in-interface-list=WAN protocol=icmp
add chain=input action=drop in-interface-list=!LAN
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN
add chain=forward action=accept in-interface-list=WAN out-interface-list=LAN dst-port=443 protocol=tcp
add chain=forward action=drop out-interface-list=!WAN
add chain=forward action=drop in-interface-list=WAN
/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=2222 to-addresses=192.168.1.100 to-ports=22
