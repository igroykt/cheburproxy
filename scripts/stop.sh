#!/bin/bash

LAN_ADDR="192.168.1.10"
LAN_IFACE="eno1"

ip rule del fwmark 0x1 >/dev/null 2>&1
ip rule del fwmark 0x2 >/dev/null 2>&1
ip rule del from $LAN_ADDR table default >/dev/null 2>&1
ip rule del to $LAN_ADDR table default >/dev/null 2>&1

iptables -t mangle -D PREROUTING -i $LAN_IFACE -j TPROXY_CHAIN >/dev/null 2>&1
iptables -t mangle -D OUTPUT -j TPROXY_MARK >/dev/null 2>&1

iptables -t nat -F >/dev/null 2>&1

iptables -t mangle -F TPROXY_CHAIN >/dev/null 2>&1
iptables -t mangle -F TPROXY_MARK >/dev/null 2>&1
iptables -t mangle -X TPROXY_CHAIN >/dev/null 2>&1
iptables -t mangle -X TPROXY_MARK >/dev/null 2>&1
iptables -t mangle -N TPROXY_CHAIN >/dev/null 2>&1
iptables -t mangle -N TPROXY_MARK >/dev/null 2>&1
