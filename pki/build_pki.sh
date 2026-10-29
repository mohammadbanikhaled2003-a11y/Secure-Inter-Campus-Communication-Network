#!/usr/bin/env bash
set -euo pipefail

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source environment variables if present
if [ -f ../lab/.env ]; then
  # shellcheck source=/dev/null
  set -a
  source ../lab/.env
  set +a
fi

GROUP_ID="${GROUP_ID:-01}"
GROUP_NUM="${GROUP_NUM:-1}"
ROOT_PASS="RootSecretPassphrase_${GROUP_ID}!"

echo "=========================================================="
echo " Building Two-Tier PKI Hierarchy for Group ${GROUP_ID}..."
echo "=========================================================="

# Create Directory Structures
mkdir -p root/{certs,crl,newcerts,private}
mkdir -p issuing/{certs,crl,newcerts,private}
mkdir -p crl certs_out
chmod 700 root/private issuing/private

# Initialize serials and databases
touch root/index.txt
echo 1000 > root/serial
echo 1000 > root/crlnumber

touch issuing/index.txt
echo 2000 > issuing/serial
echo 2000 > issuing/crlnumber

# ---------------------------------------------------------
# Step 1: Generate Root CA (ECDSA P-384, Offline, Passphrase protected)
# ---------------------------------------------------------
echo "[+] 1. Generating Root CA private key & self-signed certificate..."
openssl ecparam -name secp384r1 -genkey -noout -out root/private/ca.key.pem
# Encrypt key with passphrase
openssl ec -in root/private/ca.key.pem -out root/private/ca.key.pem -aes256 -passout "pass:${ROOT_PASS}"
chmod 600 root/private/ca.key.pem

openssl req -config openssl_root.cnf \
  -key root/private/ca.key.pem \
  -passin "pass:${ROOT_PASS}" \
  -new -x509 -days 1825 -sha384 \
  -extensions v3_ca \
  -out root/certs/ca.cert.pem \
  -subj "/C=JO/O=Al al-Bayt University/CN=AABU SCP Root CA g${GROUP_ID}"

chmod 644 root/certs/ca.cert.pem

# ---------------------------------------------------------
# Step 2: Generate Issuing CA (ECDSA P-384) & Sign with Root CA
# ---------------------------------------------------------
echo "[+] 2. Generating Issuing CA key & CSR..."
openssl ecparam -name secp384r1 -genkey -noout -out issuing/private/issuing.key.pem
chmod 600 issuing/private/issuing.key.pem

openssl req -new -sha384 \
  -key issuing/private/issuing.key.pem \
  -out issuing/issuing.csr.pem \
  -subj "/C=JO/O=Al al-Bayt University/CN=AABU SCP Issuing CA g${GROUP_ID}"

echo "[+] 3. Signing Issuing CA with Root CA (pathlen:0)..."
openssl ca -config openssl_root.cnf \
  -batch \
  -passin "pass:${ROOT_PASS}" \
  -extensions v3_intermediate_ca \
  -days 730 -notext -md sha384 \
  -in issuing/issuing.csr.pem \
  -out issuing/certs/issuing.cert.pem

chmod 644 issuing/certs/issuing.cert.pem

# Create Certificate Chain Bundle (Issuing + Root)
cat issuing/certs/issuing.cert.pem root/certs/ca.cert.pem > issuing/certs/ca-chain.cert.pem
chmod 644 issuing/certs/ca-chain.cert.pem

# ---------------------------------------------------------
# Step 3: Issue Initial CRL
# ---------------------------------------------------------
echo "[+] 4. Generating initial Certificate Revocation List (CRL)..."
openssl ca -config openssl_issuing.cnf -gencrl -out crl/issuing.crl
chmod 644 crl/issuing.crl
cp crl/issuing.crl issuing/crl/issuing.crl

# ---------------------------------------------------------
# Step 4: Issue End-Entity Certificates
# ---------------------------------------------------------
# Helper function to issue certificates
issue_cert() {
  local PROFILE="$1"
  local NAME="$2"
  local SUBJ="$3"
  local SAN_VAL="$4"

  echo "[+] Issuing certificate: ${NAME} (${PROFILE})..."
  openssl ecparam -name prime256v1 -genkey -noout -out "certs_out/${NAME}.key"
  chmod 600 "certs_out/${NAME}.key"

  openssl req -new -sha256 \
    -key "certs_out/${NAME}.key" \
    -out "certs_out/${NAME}.csr" \
    -subj "${SUBJ}"

  export SAN="${SAN_VAL}"
  openssl ca -config openssl_issuing.cnf \
    -batch \
    -extensions "${PROFILE}" \
    -days 398 -notext -md sha256 \
    -in "certs_out/${NAME}.csr" \
    -out "certs_out/${NAME}.crt"
  chmod 644 "certs_out/${NAME}.crt"
  rm -f "certs_out/${NAME}.csr"
}

# 4.1 Portal Server Certificate
issue_cert "server_cert" "portal" \
  "/C=JO/O=Al al-Bayt University/CN=portal.g${GROUP_ID}.scp.lab" \
  "DNS:portal.g${GROUP_ID}.scp.lab,DNS:pki.g${GROUP_ID}.scp.lab"

# 4.2 Gateway HQ Certificate
issue_cert "gateway_cert" "gw-hq" \
  "/C=JO/O=Al al-Bayt University/CN=gw-hq.g${GROUP_ID}.scp.lab" \
  "DNS:gw-hq.g${GROUP_ID}.scp.lab,IP:172.16.${GROUP_NUM}.10"

# 4.3 Gateway Branch Certificate
issue_cert "gateway_cert" "gw-branch" \
  "/C=JO/O=Al al-Bayt University/CN=gw-branch.g${GROUP_ID}.scp.lab" \
  "DNS:gw-branch.g${GROUP_ID}.scp.lab,IP:172.16.${GROUP_NUM}.20"

# 4.4 Staff Clients (staff01, staff02, staff03)
issue_cert "client_cert" "staff01" \
  "/C=JO/O=Al al-Bayt University/CN=staff01" \
  "email:staff01@g${GROUP_ID}.scp.lab"

issue_cert "client_cert" "staff02" \
  "/C=JO/O=Al al-Bayt University/CN=staff02" \
  "email:staff02@g${GROUP_ID}.scp.lab"

issue_cert "client_cert" "staff03" \
  "/C=JO/O=Al al-Bayt University/CN=staff03" \
  "email:staff03@g${GROUP_ID}.scp.lab"

# ---------------------------------------------------------
# Step 5: Revoke staff03 as required by specification
# (At least three staff certificates of which one is revoked)
# ---------------------------------------------------------
echo "[+] 5. Revoking staff03 for testing and regenerating CRL..."
openssl ca -config openssl_issuing.cnf -revoke certs_out/staff03.crt -crl_reason cessationOfOperation
openssl ca -config openssl_issuing.cnf -gencrl -out crl/issuing.crl
cp crl/issuing.crl issuing/crl/issuing.crl

# ---------------------------------------------------------
# Step 6: Generate Rogue CA for Attack Verification (M3 / T5)
# ---------------------------------------------------------
echo "[+] 6. Generating Rogue CA (self-signed unauthorized imitation)..."
mkdir -p ../attacks/mitm
openssl ecparam -name prime256v1 -genkey -noout -out ../attacks/mitm/rogue_ca.key
chmod 600 ../attacks/mitm/rogue_ca.key
openssl req -new -x509 -days 30 -key ../attacks/mitm/rogue_ca.key \
  -out ../attacks/mitm/rogue_ca.crt \
  -subj "/C=JO/O=Al al-Bayt University/CN=AABU SCP Root CA g${GROUP_ID} (imitation)"
chmod 644 ../attacks/mitm/rogue_ca.crt

# ---------------------------------------------------------
# Step 7: Update Certificate Inventory (certs_inventory.md)
# ---------------------------------------------------------
echo "[+] 7. Generating certs_inventory.md..."
cat << 'EOF' > certs_inventory.md
# PKI Certificate Inventory
**Project:** Secure Inter-Campus Communication Network  
**Authority:** AABU SCP Two-Tier PKI  

| Certificate Name | Serial Number | Subject DN | Subject Alternative Name (SAN) | Issuer DN | Status | Expiry (Days) |
|---|---|---|---|---|---|---|
EOF

for crt in root/certs/ca.cert.pem issuing/certs/issuing.cert.pem certs_out/*.crt; do
  if [ -f "$crt" ]; then
    BASE=$(basename "$crt" .pem)
    BASE=$(basename "$BASE" .crt)
    SERIAL=$(openssl x509 -in "$crt" -noout -serial 2>/dev/null | cut -d= -f2 || echo "N/A")
    SUBJ=$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    SAN_EXT=$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -v "Subject Alternative Name" | tr -d '\n ' || echo "N/A")
    STATUS="VALID"
    if [ "$BASE" == "staff03" ]; then STATUS="REVOKED"; fi
    echo "| **${BASE}** | \`${SERIAL}\` | \`${SUBJ}\` | \`${SAN_EXT}\` | \`${ISSUER}\` | **${STATUS}** | Standard |" >> certs_inventory.md
  fi
done

echo "[+] PKI Generation Completed Successfully!"
