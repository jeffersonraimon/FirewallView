# Final-drop policy emulation: established/related are irrelevant for new-only packets.
/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=accept protocol=icmp
add chain=input action=accept protocol=tcp dst-port=22 src-address=192.168.1.0/24
add chain=input action=drop
add chain=forward action=accept connection-state=established,related
add chain=forward action=accept in-interface=ether2-lan
add chain=forward action=accept protocol=tcp dst-port=80,443 in-interface=ether1-wan dst-address=192.168.1.50
add chain=forward action=drop
