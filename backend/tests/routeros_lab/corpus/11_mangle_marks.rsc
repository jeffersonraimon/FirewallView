/ip firewall mangle
add chain=prerouting action=mark-packet new-packet-mark=web passthrough=yes protocol=tcp dst-port=80,443
add chain=prerouting action=mark-packet new-packet-mark=lanmark passthrough=no src-address=192.168.1.100 in-interface=ether2-lan
add chain=prerouting action=mark-packet new-packet-mark=wanmark passthrough=yes in-interface=ether1-wan protocol=udp
/ip firewall filter
add chain=forward action=drop packet-mark=web in-interface=ether1-wan
add chain=forward action=accept packet-mark=lanmark
add chain=forward action=drop packet-mark=!web protocol=tcp
add chain=input action=drop packet-mark=wanmark
add chain=input action=accept packet-mark=!web
