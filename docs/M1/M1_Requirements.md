# Milestone 1: System Requirements Specification
**Project:** Secure Inter-Campus Communication Network  
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  
**Academic Year:** 2026/2027 First Semester  

---

## 1. Executive Summary & Purpose
This document establishes the functional requirements (FR01–FR12), mandatory security requirements (SR01–SR14), and detailed use-case interactions for the secure communication infrastructure connecting the Headquarters (HQ Campus) and Branch Campus across an untrusted Wide Area Network (WAN).

---

## 2. Primary Actors and Use Cases

### UC-01: Public Visitor Access (Prospective Student / General Public)
- **Actor:** Public Internet/Campus Visitor.
- **Goal:** Access public academic information, schedules, and general announcements.
- **Flow:**
  1. Visitor opens a web browser and navigates to `http://portal.g${GROUP_ID}.scp.lab`.
  2. The web server immediately responds with an HTTP 301/308 redirect to `https://portal.g${GROUP_ID}.scp.lab/`.
  3. A hardened TLS handshake (TLS 1.2 / TLS 1.3 only, AEAD ciphers with PFS) is negotiated.
  4. Nginx sends the Strict-Transport-Security (`HSTS`) header with a minimum 6-month max-age.
  5. The visitor views the public portal. No client certificate is demanded or checked.

### UC-02: Staff Member Access to Secured Services (Mutual TLS)
- **Actor:** Branch Campus Staff Member (`client-br`).
- **Goal:** Access restricted staff operational portal (`/staff/`) and retrieve administrative services.
- **Flow:**
  1. Staff member points their browser or `curl` to `https://portal.g${GROUP_ID}.scp.lab/staff/`.
  2. Nginx initiates TLS client certificate authentication (Mutual TLS, `ssl_verify_client on`).
  3. The client presents their issued X.509 staff certificate (e.g., `CN=staff01, email=staff01@g${GROUP_ID}.scp.lab`).
  4. Nginx validates:
     - The certificate is signed by the trusted Issuing CA.
     - The certificate validity dates are current.
     - The certificate serial number is **not** present in the latest published Certificate Revocation List (CRL).
  5. Upon success, Nginx logs the authenticated Distinguished Name (`$ssl_client_s_dn`) and renders the secured staff dashboard.
  6. If authentication fails (missing certificate or revoked serial), Nginx returns a generic 403 Forbidden error without leaking internal error details.

### UC-03: Staff Authentication to Network Services via Kerberos-Style Protocol
- **Actor:** Branch Campus Staff Member (`client`).
- **Goal:** Authenticate securely to an internal HQ campus network service (`service.py` on `web-hq`) through the Key Distribution Center (`kdc.py`).
- **Flow:**
  1. **Authentication Service (AS) Exchange:** Client sends an `AS_REQ` containing client identity and a fresh nonce. KDC replies with `AS_REP` containing Ticket-Granting Ticket (TGT) encrypted with KDC secret, and session key encrypted with client's long-term derived key.
  2. **Ticket Granting Service (TGS) Exchange:** Client submits `TGS_REQ` with TGT, an authenticator (with timestamp), and requested service ID. KDC validates freshness, checks replay cache, and returns `TGS_REP` containing Service Ticket and Service Session Key.
  3. **Application (AP) Exchange:** Client presents Service Ticket and a fresh Authenticator to `service.py`. The service verifies ticket integrity, enforces replay protection, verifies mutual authentication (`AP_REP`), and establishes the session.

### UC-04: Network Administrator (PKI & Gateway Management)
- **Actor:** System / Security Administrator.
- **Goal:** Maintain PKI lifecycle, enforce access control, deploy tunnels, and inspect security telemetry.
- **Flow:**
  1. Generate offline Root CA and online Issuing CA with strictly defined cryptographic profiles.
  2. Issue, sign, and distribute X.509 end-entity certificates for server, gateways, and staff.
  3. In case of key compromise, execute `revoke.sh`, issue an updated CRL, and trigger real-time CRL updates on `web-hq` and strongSwan gateways.
  4. Configure and monitor the IKEv2 IPsec tunnel between `gw-hq` and `gw-branch` and verify fail-closed firewall state.

---

## 3. Functional Requirements (FR01 – FR12)

| Requirement ID | Name | Description | Verification Criterion |
|---|---|---|---|
| **FR01** | Two-Tier PKI Automation | Reproducible script `pki/build_pki.sh` that builds Root CA, Issuing CA, and all lab certificates from scratch. | Clean directory execution produces complete, verified PKI hierarchy. |
| **FR02** | Profile-Based Issuance | `pki/issue.sh <profile> <name>` issues certificates from CSRs adhering to predefined extension profiles. | Every chain validates via `openssl verify -CAfile ...`. |
| **FR03** | Dynamic Certificate Revocation | `pki/revoke.sh <name>` revokes a certificate, updates CRL with valid `nextUpdate`, and enforces immediate rejection on Nginx and strongSwan. | Revoked certificate is immediately blocked from `/staff/` and IKE tunnel. |
| **FR04** | Hardened HTTPS Portal | Nginx serves the portal over HTTPS only with HTTP→HTTPS redirect (301/308) and HSTS. | HTTP access is redirected; HSTS header present; only TLS 1.2+ allowed. |
| **FR05** | Mutual TLS Staff Area | `/staff/` demands a valid, unrevoked client certificate. Staff identity is logged. | Valid cert allowed; missing/revoked cert receives generic error. |
| **FR06** | Automated IKEv2 Tunnel | `gw-hq` and `gw-branch` establish an IKEv2 IPsec tunnel automatically upon startup with certificate authentication. | `swanctl --list-sas` shows active ESTABLISHED state with ECDH PFS. |
| **FR07** | Strict Traffic Selectors | Only HQ-LAN (`10.G.1.0/24`) $\leftrightarrow$ Branch-LAN (`10.G.2.0/24`) traffic enters the IPsec tunnel. | Packets matching LAN subnets are encapsulated in ESP; external traffic is not misrouted. |
| **FR08** | Cryptographic Message Tool | Python CLI `crypto/scpcrypt.py` provides sign/verify, MAC, AEAD encrypt/decrypt, and ECDH with 1-byte tamper detection. | Test suite passes all RFC vectors (RFC 4231, RFC 8032) and detects single-byte bit flips. |
| **FR09** | KDC Ticket Issuance | KDC authenticates client principals and issues TGT and Service Tickets with bounded lifetimes. | Tickets decrypt successfully only with intended symmetric keys. |
| **FR10** | Mutual Auth & Freshness | Client and service mutually authenticate, confirm fresh session keys, and reject replayed messages. | Fresh authenticators succeed; replayed or expired authenticators fail. |
| **FR11** | Full Clean Rebuildability | System can be reconstructed from zero by executing documented scripts in order. | Clean Docker environment runs `tests/run_all.sh` to completion. |
| **FR12** | Isolated Attack Variants | Weak protocol/crypto variants are isolated in `attacks/` and never included in default production configurations. | Production configurations maintain full hardening; attacks run against isolated test targets. |

---

## 4. Mandatory Security Requirements Traceability (SR01 – SR14)
- **SR01 (Crypto Hygiene):** AES-GCM, ChaCha20-Poly1305, SHA-256+, ECDSA P-256/P-384, Ed25519, X25519. No MD5, SHA-1, RC4, or DES.
- **SR02 (PKI Hierarchy):** Root CA offline, pathlen constraints (`pathlen:1` for Root, `pathlen:0` for Issuing), SAN on all end-entity certs.
- **SR03 (Revocation):** CRL enforcement on Nginx and strongSwan.
- **SR04 (TLS Hardening):** TLS 1.2 min, TLS 1.3 preferred, forward secrecy only, full chain served, testssl.sh grade A / zero HIGH/CRITICAL findings.
- **SR05 (mTLS):** Client cert validation against Issuing CA and CRL.
- **SR06 (MITM Resistance):** Rogue CA rejected by client verification.
- **SR07 (IKEv2 VPN):** Mutual certificate auth, pinned remote IDs (`gw-hq.gG.scp.lab`, `gw-branch.gG.scp.lab`), PFS enabled.
- **SR08 (Fail-Closed Firewall):** WAN accepts only UDP 500/4500 and ESP. Dropped when tunnel is down.
- **SR09 (Auth Protocol Design):** Nonces, timestamps, replay cache, AEAD tickets, HKDF key derivation.
- **SR10 (Replay Attack & Fix):** Attack demonstrated on weak variant and defeated on fixed variant.
- **SR11 (Secrets Management):** No keys, passphrases, or real `.env` in Git repository.
- **SR12 (Traffic Evidence):** WAN pcap captures before/after tunnel activation.
- **SR13 (Downgrade Resistance):** Incompatible/weak TLS and IKE proposals rejected.
- **SR14 (Unified Test Logging):** Standardized test matrix T1–T13 documented in `evidence/test_log.xlsx`.
