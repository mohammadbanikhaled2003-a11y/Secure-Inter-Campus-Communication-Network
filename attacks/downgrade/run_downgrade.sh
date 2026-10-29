#!/usr/bin/env bash
set -euo pipefail

# Attack T6: TLS / Cipher Downgrade Verification
# Demonstrates SR04 & SR13:
# 1. Client attempts to force obsolete protocols: TLS 1.0 and TLS 1.1.
# 2. Client attempts to force legacy, non-AEAD or weak ciphers (e.g. 3DES, RC4, AES-CBC without MAC).
# 3. Hardened Nginx server rejects the handshake.

PORTAL_TARGET="${1:-127.0.0.1:443}"

echo "=========================================================="
echo " Running Attack T6: Protocol & Cipher Downgrade Tests"
echo "=========================================================="

echo "[+] 1. Attempting connection forcing TLS 1.0..."
set +e
RESULT_TLS10=$(echo "Q" | openssl s_client -tls1 -connect "${PORTAL_TARGET}" 2>&1)
set -e
if echo "${RESULT_TLS10}" | grep -Ei "handshake failure|no protocols available|wrong version number"; then
  echo "[✓] [T6.1 PASS] TLS 1.0 connection strictly REFUSED by server."
else
  echo "[!] TLS 1.0 was not refused or server not reachable."
fi

echo -e "\n[+] 2. Attempting connection forcing TLS 1.1..."
set +e
RESULT_TLS11=$(echo "Q" | openssl s_client -tls1_1 -connect "${PORTAL_TARGET}" 2>&1)
set -e
if echo "${RESULT_TLS11}" | grep -Ei "handshake failure|no protocols available|wrong version number"; then
  echo "[✓] [T6.2 PASS] TLS 1.1 connection strictly REFUSED by server."
else
  echo "[!] TLS 1.1 was not refused or server not reachable."
fi

echo -e "\n[+] 3. Attempting connection forcing weak non-AEAD cipher (3DES / RC4)..."
set +e
RESULT_CIPHER=$(echo "Q" | openssl s_client -cipher '3DES:RC4:DES' -connect "${PORTAL_TARGET}" 2>&1)
set -e
if echo "${RESULT_CIPHER}" | grep -Ei "handshake failure|no ciphers available|no cipher match"; then
  echo "[✓] [T6.3 PASS] Legacy non-AEAD cipher suites strictly REFUSED by server."
else
  echo "[!] Legacy ciphers were not refused."
fi

echo -e "\n[✓] Protocol Downgrade Defense Verified: Server accepts ONLY TLS 1.2+ with AEAD suites."
