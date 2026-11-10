# Disabled rules never match; first match wins.
/ip firewall filter
add chain=forward action=drop src-address=192.168.1.50 disabled=yes
add chain=forward action=accept src-address=192.168.1.0/24 protocol=tcp dst-port=443
add chain=forward action=drop src-address=192.168.1.0/24
add chain=forward action=drop dst-address=192.168.1.200 disabled=yes
add chain=input action=drop protocol=icmp disabled=yes
add chain=input action=drop protocol=udp
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1-wan disabled=yes
add chain=dstnat action=dst-nat protocol=tcp dst-port=9999 to-addresses=192.168.1.100 disabled=yes
