#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <profile: server_cert|gateway_cert|client_cert> <name> [SAN_override]"
  echo "Example: $0 client_cert staff04"
  exit 1
fi

PROFILE="$1"
NAME="$2"

if [ -f ../lab/.env ]; then
  set -a
  source ../lab/.env
  set +a
fi

GROUP_ID="${GROUP_ID:-06}"
GROUP_NUM="${GROUP_NUM:-6}"

mkdir -p certs_out

# Determine Subject & SAN default based on profile
case "$PROFILE" in
  server_cert)
    SUBJ="/C=JO/O=Al al-Bayt University/CN=${NAME}.g${GROUP_ID}.scp.lab"
    SAN_VAL="${3:-DNS:${NAME}.g${GROUP_ID}.scp.lab}"
    ;;
  gateway_cert)
    SUBJ="/C=JO/O=Al al-Bayt University/CN=${NAME}.g${GROUP_ID}.scp.lab"
    SAN_VAL="${3:-DNS:${NAME}.g${GROUP_ID}.scp.lab}"
    ;;
  client_cert)
    SUBJ="/C=JO/O=Al al-Bayt University/CN=${NAME}"
    SAN_VAL="${3:-email:${NAME}@g${GROUP_ID}.scp.lab}"
    ;;
  *)
    echo "Unknown profile: $PROFILE"
    exit 1
    ;;
esac

echo "[+] Generating private key for ${NAME}..."
openssl ecparam -name prime256v1 -genkey -noout -out "certs_out/${NAME}.key"
chmod 600 "certs_out/${NAME}.key"

echo "[+] Generating CSR for ${NAME}..."
openssl req -new -sha256 \
  -key "certs_out/${NAME}.key" \
  -out "certs_out/${NAME}.csr" \
  -subj "${SUBJ}"

export SAN="${SAN_VAL}"
echo "[+] Signing ${NAME} certificate using Issuing CA..."
openssl ca -config openssl_issuing.cnf \
  -batch \
  -extensions "${PROFILE}" \
  -days 398 -notext -md sha256 \
  -in "certs_out/${NAME}.csr" \
  -out "certs_out/${NAME}.crt"

chmod 644 "certs_out/${NAME}.crt"
rm -f "certs_out/${NAME}.csr"

echo "[✓] Certificate ${NAME} issued successfully in certs_out/${NAME}.crt"
