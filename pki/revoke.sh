#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <certificate_name_or_file> [revocation_reason]"
  echo "Example: $0 staff02 keyCompromise"
  exit 1
fi

TARGET="$1"
REASON="${2:-unspecified}"

# Find certificate file
CERT_FILE=""
if [ -f "certs_out/${TARGET}.crt" ]; then
  CERT_FILE="certs_out/${TARGET}.crt"
elif [ -f "${TARGET}" ]; then
  CERT_FILE="${TARGET}"
else
  echo "Error: Certificate file for '$TARGET' not found in certs_out/."
  exit 1
fi

echo "[+] Revoking certificate: ${CERT_FILE} (Reason: ${REASON})..."
openssl ca -config openssl_issuing.cnf -revoke "${CERT_FILE}" -crl_reason "${REASON}"

echo "[+] Regenerating updated Certificate Revocation List (CRL)..."
openssl ca -config openssl_issuing.cnf -gencrl -out crl/issuing.crl
cp crl/issuing.crl issuing/crl/issuing.crl
chmod 644 crl/issuing.crl

# If web-hq is running and CRL directory exists, update it immediately
if [ -d "/var/www/crl" ]; then
  cp crl/issuing.crl /var/www/crl/issuing.crl
  # Reload nginx if present
  if command -v nginx >/dev/null 2>&1; then
    nginx -s reload 2>/dev/null || true
  fi
fi

echo "[✓] Certificate ${TARGET} revoked and CRL successfully updated."
