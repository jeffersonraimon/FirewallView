/ip firewall address-list
add list=bad address=198.51.100.0/24
add list=bad address=203.0.113.20
add list=bad address=192.0.2.70-192.0.2.80
add list=trusted address=192.168.1.100
add list=trusted address=203.0.113.10
add list=srvs address=192.168.1.50
add list=srvs address=192.168.1.200
/ip firewall filter
add chain=forward action=drop src-address-list=bad
add chain=forward action=drop dst-address-list=bad protocol=tcp
add chain=forward action=accept src-address-list=trusted
add chain=forward action=accept dst-address-list=srvs protocol=tcp dst-port=80,443
add chain=forward action=drop src-address-list=!trusted in-interface=ether1-wan
add chain=input action=accept src-address-list=trusted
add chain=input action=drop dst-address-list=!srvs protocol=tcp
