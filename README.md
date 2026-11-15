# Secure Inter-Campus Communication Network
**Course:** Secure Communication Protocols (1305301) — First Semester 2026/2027  
**Faculty:** Prince Al Hussein bin Abdullah II Faculty of Information Technology  
**Institution:** Al al-Bayt University (AABU)  
**Assigned Group:** Group 06 (`g06` / `GROUP_ID=06`, `GROUP_NUM=6`)  

> 🎯 **Phase 1 (Milestone 1) Quick Links:**  
> - ⚡ **[Phase 1 Interactive Simulation Dashboard (Live Demo)](docs/M1/Phase1_Interactive_Dashboard.html)**  
> - 🖥️ **[Phase 1 Visual Architecture Slides (English)](docs/M1/Phase1_Visual_Slides.html)**  
> - 📄 **[Phase 1 Comprehensive Engineering Documentation (English)](docs/M1/Phase1_Documentation_Report.md)**  

---

## 1. Project Overview & Architecture
This project implements, hardens, and verifies an end-to-end secure communication infrastructure connecting the Headquarters Campus (**HQ**) and Branch Campus (**Branch**) over an untrusted Wide Area Network (**WAN**).

```
[Branch LAN: 10.6.2.0/24]                  [Untrusted WAN: 172.16.6.0/24]                  [HQ LAN: 10.6.1.0/24]
       client-br                                      attacker                                     web-hq (Portal/mTLS)
      (10.6.2.10)                                   (172.16.6.66)                                       (10.6.1.10)
           |                                              |                                                  |
       gw-branch <================== IKEv2 / ESP IPsec Tunnel (PFS) ==================>                    gw-hq
  (WAN: 172.16.6.20)                           (Mutual X.509)                                       (WAN: 172.16.6.10)
  (LAN: 10.6.2.1)                                                                                   (LAN: 10.6.1.1)
                                                                                                             |
                                                                                                            kdc
                                                                                                        (10.6.1.20)
```

The system is delivered through 4 cumulative Milestones:
- **M1 (Analysis, Design & Baseline):** Requirements, Trust boundaries, PKI design, Protocol sequence diagrams, STRIDE threat model, and baseline unencrypted capture.
- **M2 (PKI, Crypto Tool & TLS Portal):** Two-tier PKI from scratch, `crypto/scpcrypt.py` with RFC 4231 & 8032 test vectors, and hardened Nginx TLS with mTLS on `/staff/`.
- **M3 (VPN, Authentication Protocol & Attacks):** strongSwan IKEv2 site-to-site IPsec tunnel with fail-closed firewall, Kerberos-style KDC/Service/Client protocol, and red-team attacks (MITM, Replay, Downgrade).
- **M4 (Final Assessment & Delivery):** Acceptance test runner `tests/run_all.sh` (Tests T1–T13), secret scan, and final project documentation.

---

## 2. Directory Structure

```
project-root/
├── README.md                           # Main documentation & reproduction steps
├── .gitignore                          # Strict secret exclusions (SR11)
├── lab/
│   ├── docker-compose.yml              # Six-node isolated lab topology
│   ├── .env.example                    # Template for GROUP_ID & GROUP_NUM
│   ├── docker/Dockerfile               # Ubuntu 24.04 image definition
│   └── roles/entrypoint.sh             # Per-node initialization & routing
├── pki/
│   ├── openssl_root.cnf                # Offline Root CA configuration
│   ├── openssl_issuing.cnf             # Issuing CA & profile configurations
│   ├── build_pki.sh                    # Automated two-tier PKI generation
│   ├── issue.sh                        # Profile-based dynamic cert issuer
│   ├── revoke.sh                       # Cert revoker & CRL publisher
│   ├── certs_inventory.md              # Certificate inventory & metadata
│   └── crl/                            # Published CRL directory
├── crypto/
│   ├── scpcrypt.py                     # Command-line cryptographic tool
│   └── tests/test_scpcrypt.py          # RFC vectors & tamper detection tests
├── tls/
│   ├── nginx/portal.conf               # Hardened TLS, HSTS, CRL & mTLS config
│   └── html/                           # Web portal and staff pages
├── ipsec/
│   ├── gw-hq/swanctl.conf              # HQ Gateway strongSwan IKEv2 config
│   ├── gw-branch/swanctl.conf          # Branch Gateway strongSwan IKEv2 config
│   └── hardening/gw_firewall.sh        # Fail-closed gateway firewall
├── auth_protocols/
│   ├── PROTOCOL.md                     # Formal mathematical protocol spec
│   ├── kdc.py                          # Kerberos Key Distribution Center (TCP 8800)
│   ├── service.py                      # Protected Application Service (TCP 8801)
│   └── client.py                       # Staff client authentication utility
├── attacks/
│   ├── README_SAFETY.md                # Ethical lab boundaries & rules
│   ├── mitm/run_mitm.sh                # Rogue CA MITM attack verification (T5)
│   ├── downgrade/run_downgrade.sh      # Protocol downgrade resistance test (T6)
│   └── replay/                         # Replay attack against weak vs fixed (T12a/b)
├── tests/
│   └── run_all.sh                      # Unified acceptance runner (T1–T13)
├── docs/
│   ├── M1/                             # M1 deliverables (Requirements, STRIDE, etc.)
│   ├── M2/                             # M2 deliverables (Cert profiles, tests)
│   ├── M3/                             # M3 deliverables (Security tests, pcaps)
│   └── M4/                             # Final Report
└── evidence/
    ├── pcaps/                          # Baseline and encrypted traffic captures
    ├── sanitized_logs/                 # Test execution logs
    └── test_log.xlsx                   # Acceptance test matrix results
```

---

## 3. Quick Start & Clean Rebuild (FR11)

### Step 1: Configure Environment Variables
Copy `.env.example` to `lab/.env` and update your assigned Group numbers:
```bash
cp lab/.env.example lab/.env
# Edit GROUP_ID (e.g. 07) and GROUP_NUM (e.g. 7)
```

### Step 2: Build the PKI from Scratch (FR01)
Generate the complete two-tier hierarchy (Root CA, Issuing CA, server/gateway/staff certificates, and CRL):
```bash
bash pki/build_pki.sh
```

### Step 3: Launch the Six-Node Docker Lab
```bash
cd lab
docker compose up -d --build
docker compose ps
```
All six containers (`gw-hq`, `gw-branch`, `web-hq`, `kdc`, `client-br`, `attacker`) will be running and attached to their isolated subnets.

### Step 4: Run the Cryptographic Tool & Tests (FR08)
```bash
# Run unit tests (RFC 4231 HMAC-SHA256, RFC 8032 Ed25519, Tamper detection)
python3 -m unittest crypto/tests/test_scpcrypt.py

# Using scpcrypt.py CLI directly:
python3 crypto/scpcrypt.py mac --key-hex 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -i /path/to/file
python3 crypto/scpcrypt.py encrypt --cipher aes-gcm -i /path/to/plaintext -o /path/to/ciphertext
```

### Step 5: Run the Complete Acceptance Test Suite (T1 – T13)
Execute the master automated verification script:
```bash
bash tests/run_all.sh
```

---

## 4. Acceptance Test Matrix (T1 – T13)

| Test ID | Scenario | Expected Result | Status |
|---|---|---|---|
| **T1** | `openssl verify` of all certificates against Root CA; Rogue CA check | All lab certs verify OK; Rogue CA strictly fails | **PASS** |
| **T2** | `scpcrypt.py` sign, MAC, encrypt, and 1-byte tamper detection | Valid inputs verify; any modified byte rejected | **PASS** |
| **T3** | Staff client with valid certificate opens `/staff/` | Allowed; staff identity logged in `$ssl_client_s_dn` | **PASS** |
| **T4** | `/staff/` without certificate or with revoked certificate | Refused with generic 403 error; attempt logged | **PASS** |
| **T5** | Rogue CA MITM attack with simulated DNS spoof | Strict client verification refuses connection | **PASS** |
| **T6** | Protocol downgrade (TLS 1.0/1.1 or legacy non-AEAD suites) | Handshake refused by server; no HIGH/CRITICAL | **PASS** |
| **T7** | WAN capture with tunnel up | Only IKE (UDP 500/4500) and ESP; zero cleartext | **PASS** |
| **T8** | Unauthorized peer presents staff cert as gateway peer | IKE negotiation fails; logged by strongSwan | **PASS** |
| **T9** | IKE daemon stopped on `gw-branch` | Fail-Closed: inter-LAN packets dropped immediately | **PASS** |
| **T10** | Attacker port scan of gateways and HQ LAN | Only IKE ports answer; HQ LAN unreachable | **PASS** |
| **T11** | Kerberos login with correct vs wrong password | Valid login issues ticket; wrong fails generically | **PASS** |
| **T12a**| Replay of captured authenticator against weak service | Attack succeeds and is documented | **PASS** |
| **T12b**| Same replay attack against fixed protocol | Replay rejected by sliding cache / freshness check | **PASS** |
| **T13** | Secret scan of repository history (SR11) | Zero private keys, passphrases, or secrets in Git | **PASS** |

---

## 5. Security & Academic Integrity Compliance
- **SR11 Hygiene:** No private keys, CA passphrases, or `.env` files are tracked in Git.
- **Safety Boundaries:** All attacks are executed strictly within the isolated lab networks (`172.16.G.0/24`, `10.G.1.0/24`, `10.G.2.0/24`) from the `attacker` node. See `attacks/README_SAFETY.md`.
