/ip firewall filter
add chain=forward action=jump jump-target=inspect protocol=tcp
add chain=forward action=accept in-interface=ether2-lan
add chain=forward action=drop
add chain=inspect action=return protocol=tcp dst-port=80
add chain=inspect action=drop protocol=tcp dst-port=443,8443
add chain=inspect action=accept src-address=192.168.1.100
add chain=input action=jump jump-target=in_chk
add chain=input action=accept protocol=icmp
add chain=input action=drop
add chain=in_chk action=return src-address=192.168.1.0/24
add chain=in_chk action=drop protocol=tcp dst-port=22
