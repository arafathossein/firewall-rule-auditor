# 2026-11-12 06:00:01 by RouterOS 7.16.1
# software id = 7QXW-2LMA
#
# model = RB5009UG+S+
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1 list=WAN
add interface=bridge-lan list=LAN
/ip firewall address-list
add address=10.40.99.0/24 list=mgmt
/ip firewall filter
add action=accept chain=input comment="established, related" connection-state=established,related
add action=drop chain=input comment="drop invalid" connection-state=invalid
add action=accept chain=input comment="ICMP" protocol=icmp
add action=accept chain=input comment="Winbox from management network" dst-port=8291 protocol=tcp \
    src-address-list=mgmt
add action=accept chain=input dst-port=8291,22 protocol=tcp
add action=accept chain=input comment="LAN to router" in-interface-list=LAN
add action=accept chain=input comment="old webfig access" disabled=yes dst-port=80 protocol=tcp
add action=accept chain=forward comment="established, related" connection-state=established,related
add action=drop chain=forward comment="drop invalid" connection-state=invalid
add action=accept chain=forward comment="RDP to accounting PC (port forward)" connection-nat-state=dstnat \
    dst-address=10.40.0.25 dst-port=3389 in-interface-list=WAN protocol=tcp
add action=accept chain=forward comment="LAN to internet" in-interface-list=LAN
add action=drop chain=forward comment="drop all from WAN not port forwarded" connection-nat-state=!dstnat \
    in-interface-list=WAN
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
add action=dst-nat chain=dstnat dst-port=3389 in-interface-list=WAN protocol=tcp to-addresses=10.40.0.25
