#!/bin/bash
set -e

# Extract GROUP_NUM or default to 1
G="${GROUP_NUM:-1}"
ROLE="${NODE_ROLE:-node}"

echo "[+] Initializing $ROLE for Group $G..."

case "$ROLE" in
  gw-hq)
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    # Route branch LAN through gw-branch over WAN (baseline cleartext routing)
    ip route add 10.${G}.2.0/24 via 172.16.${G}.20 dev eth0 2>/dev/null || true
    # Start strongSwan if configs exist
    if [ -f /work/ipsec/gw-hq/swanctl.conf ]; then
      echo "[+] Starting strongswan on gw-hq..."
      swanctl --load-all 2>/dev/null || true
    fi
    ;;
  gw-branch)
    sysctl -w net.ipv4.ip_forward=1
    # Route HQ LAN through gw-hq over WAN (baseline cleartext routing)
    ip route add 10.${G}.1.0/24 via 172.16.${G}.10 dev eth0 2>/dev/null || true
    if [ -f /work/ipsec/gw-branch/swanctl.conf ]; then
      echo "[+] Starting strongswan on gw-branch..."
      swanctl --load-all 2>/dev/null || true
    fi
    ;;
  web-hq)
    # Default route via gw-hq
    ip route del default 2>/dev/null || true
    ip route add default via 10.${G}.1.1
    # Add domain mapping to /etc/hosts
    echo "10.${G}.1.10 portal.g$(printf "%02d" $G).scp.lab pki.g$(printf "%02d" $G).scp.lab" >> /etc/hosts
    # Start nginx if config is ready
    if [ -f /work/tls/nginx/portal.conf ]; then
      mkdir -p /var/log/nginx /var/www/crl /var/www/html
      cp /work/tls/nginx/portal.conf /etc/nginx/conf.d/portal.conf 2>/dev/null || true
      nginx -g "daemon on;" 2>/dev/null || true
    fi
    ;;
  kdc)
    ip route del default 2>/dev/null || true
    ip route add default via 10.${G}.1.1
    echo "10.${G}.1.20 kdc.g$(printf "%02d" $G).scp.lab" >> /etc/hosts
    ;;
  client-br)
    ip route del default 2>/dev/null || true
    ip route add default via 10.${G}.2.1
    # DNS mapping for portal, pki, and kdc
    echo "10.${G}.1.10 portal.g$(printf "%02d" $G).scp.lab pki.g$(printf "%02d" $G).scp.lab" >> /etc/hosts
    echo "10.${G}.1.20 kdc.g$(printf "%02d" $G).scp.lab" >> /etc/hosts
    ;;
  attacker)
    # Attacker is on WAN only. It can route to Branch LAN via gw-branch, but has NO route into HQ LAN
    ip route add 10.${G}.2.0/24 via 172.16.${G}.20 dev eth0 2>/dev/null || true
    ;;
esac

echo "[+] Node $ROLE setup complete."
exec tail -f /dev/null
