#!/usr/bin/env bash
set -euo pipefail

# Attack T5: Rogue CA Man-in-the-Middle Verification
# Demonstrates SR06:
# 1. Attacker node impersonates portal and presents a certificate signed by Rogue CA.
# 2. Hardened client refuses connection with certificate verification failure.
# 3. When certificate verification is switched off (curl -k), connection succeeds (proving the vulnerability).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f ../../lab/.env ]; then
  set -a
  source ../../lab/.env
  set +a
fi

GROUP_ID="${GROUP_ID:-06}"
PORTAL_DOMAIN="portal.g${GROUP_ID}.scp.lab"
TARGET_PORT="${1:-8443}"

echo "=========================================================="
echo " Running Attack T5: Rogue CA MITM Resistance Test"
echo "=========================================================="

# Ensure Rogue CA and Rogue Server Certificate exist
if [ ! -f rogue_ca.key ]; then
  echo "[+] Generating Rogue CA..."
  openssl ecparam -name prime256v1 -genkey -noout -out rogue_ca.key
  chmod 600 rogue_ca.key
  openssl req -new -x509 -days 30 -key rogue_ca.key -out rogue_ca.crt \
    -subj "/C=JO/O=Al al-Bayt University/CN=AABU SCP Root CA g${GROUP_ID} (imitation)"
fi

if [ ! -f rogue_server.key ]; then
  echo "[+] Generating Rogue Portal Server Certificate..."
  openssl ecparam -name prime256v1 -genkey -noout -out rogue_server.key
  chmod 600 rogue_server.key
  openssl req -new -key rogue_server.key -out rogue_server.csr \
    -subj "/C=JO/O=Al al-Bayt University/CN=${PORTAL_DOMAIN}"
  
  openssl x509 -req -days 30 -in rogue_server.csr \
    -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
    -out rogue_server.crt \
    -extfile <(printf "subjectAltName=DNS:%s" "${PORTAL_DOMAIN}")
  rm -f rogue_server.csr
fi

echo "[+] Starting Rogue HTTPS listener on port ${TARGET_PORT} in background..."
# Start minimal rogue SSL listener using openssl s_server
openssl s_server -quiet -key rogue_server.key -cert rogue_server.crt -accept "${TARGET_PORT}" -www &
ROGUE_PID=$!
trap "kill -9 $ROGUE_PID 2>/dev/null || true" EXIT
sleep 1

echo "[+] 1. Client attempts connection WITH strict certificate verification against legitimate Root CA..."
set +e
curl --cacert ../../pki/root/certs/ca.cert.pem "https://localhost:${TARGET_PORT}/" >/dev/null 2>&1
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
  echo "[✓] [T5 PASS] Client correctly REFUSED the connection (Exit code: $EXIT_CODE)."
  echo "    The Rogue CA certificate was rejected because it does not chain to the legitimate Root CA!"
else
  echo "[✗] [T5 FAIL] Client accepted the Rogue CA certificate!"
  exit 1
fi

echo -e "\n[+] 2. Demonstration: Client repeats connection with verification DISABLED (curl -k)..."
set +e
curl -k -s "https://localhost:${TARGET_PORT}/" | head -n 3
set -e
echo "[i] When certificate validation is bypassed (curl -k), the client is vulnerable to MITM."
echo "[✓] Attack T5 simulation finished successfully."
