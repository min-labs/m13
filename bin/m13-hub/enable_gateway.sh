#!/bin/bash
set -e

echo "[*] Enabling IP Forwarding..."
sysctl -w net.ipv4.ip_forward=1

# Detect WAN Interface (usually eth0 on Azure)
WAN_IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
echo "[*] WAN Interface detected: $WAN_IFACE"

echo "[*] Configuring NAT (Masquerade)..."
# Flush old NAT rules to prevent conflicts
iptables -t nat -F
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $WAN_IFACE -j MASQUERADE

echo "[*] Allowing Forwarding..."
iptables -A FORWARD -i m13hub0 -j ACCEPT
iptables -A FORWARD -o m13hub0 -j ACCEPT

# Clamp MTU to match M13 internal limit (Safe Harbor)
ip link set dev m13hub0 mtu 1280 2>/dev/null || echo "[!] Note: m13hub0 not up yet, MTU will be set by app"

echo "[SUCCESS] Gateway Mode Active."
