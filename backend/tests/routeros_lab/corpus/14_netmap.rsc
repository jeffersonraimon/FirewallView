/ip firewall nat
add chain=srcnat action=netmap to-addresses=198.51.100.0/24 src-address=192.168.1.0/24 out-interface=ether1-wan
add chain=dstnat action=netmap to-addresses=198.51.100.0/24 dst-address=203.0.113.0/28 in-interface=ether2-lan
/ip firewall filter
add chain=forward action=accept
