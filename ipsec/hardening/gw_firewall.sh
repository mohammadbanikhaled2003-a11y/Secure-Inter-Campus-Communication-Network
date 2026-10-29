#!/usr/bin/env bash
set -euo pipefail

# Gateway Hardening & Fail-Closed Firewall Script
# Enforces SR08:
# 1. On WAN interface (eth0): Accept ONLY UDP 500/4500 (IKE) and protocol 50 (ESP).
# 2. LAN-to-LAN Traffic: Dropped if not encapsulated in IPsec (Fail-Closed).
# 3. Drops any cleartext cross-campus transit packet.

SITE="${1:-hq}"

echo "=========================================================="
echo " Applying Gateway Hardening Firewall for: ${SITE}"
echo "=========================================================="

WAN_IF="eth0"
LAN_IF="eth1"

# 1. Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# 2. Set Default Policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Allow Loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4. Allow Established & Related Connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 5. WAN Interface Rules (eth0): Only IKE and ESP allowed!
# Allow IKEv2 (UDP 500)
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 500 -j ACCEPT
# Allow IKE NAT-Traversal (UDP 4500)
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 4500 -j ACCEPT
# Allow IPsec Encapsulating Security Payload (ESP / Protocol 50)
iptables -A INPUT -i "${WAN_IF}" -p esp -j ACCEPT

# 6. LAN Interface Rules (eth1): Allow local management and gateway services
iptables -A INPUT -i "${LAN_IF}" -j ACCEPT

# 7. Fail-Closed Inter-LAN Forwarding Rule:
# CRITICAL: LAN-to-LAN packets are permitted ONLY if matched by IPsec policy (encrypted)
# Any cleartext LAN-to-LAN packet attempting to traverse WAN is unconditionally DROPPED!
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -m policy --dir out --pol ipsec -j ACCEPT
iptables -A FORWARD -i "${WAN_IF}" -o "${LAN_IF}" -m policy --dir in --pol ipsec -j ACCEPT

# Log & Drop any attempt to route LAN-to-LAN traffic in clear
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j LOG --log-prefix "[FAIL-CLOSED DROP] "
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j DROP

echo "[✓] Firewall successfully hardened in FAIL-CLOSED mode."
iptables -L -n -v --line-numbers
