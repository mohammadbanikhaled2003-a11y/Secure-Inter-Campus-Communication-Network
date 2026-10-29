# Milestone 1: Public Key Infrastructure (PKI) Design Specification
**Project:** Secure Inter-Campus Communication Network  
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  

---

## 1. Two-Tier PKI Hierarchy Architecture

```
                    +--------------------------------------------+
                    |                Root CA                     |
                    |     CN = AABU SCP Root CA g${GROUP_ID}     |
                    |           Key: ECDSA P-384 / RSA 4096      |
                    |        Validity: 5 Years (1825 days)       |
                    |        basicConstraints = CA:TRUE,         |
                    |                 pathlen:1                  |
                    |   keyUsage = keyCertSign, cRLSign (crit)   |
                    +---------------------+----------------------+
                                          |
                                (Signs offline only)
                                          |
                                          v
                    +--------------------------------------------+
                    |               Issuing CA                   |
                    |    CN = AABU SCP Issuing CA g${GROUP_ID}   |
                    |           Key: ECDSA P-384 / RSA 3072      |
                    |        Validity: 2 Years (730 days)        |
                    |        basicConstraints = CA:TRUE,         |
                    |                 pathlen:0                  |
                    |   keyUsage = keyCertSign, cRLSign (crit)   |
                    | CRL DP: http://pki.gG.scp.lab/crl/issuing.crl |
                    +---------------------+----------------------+
                                          |
                  +-----------------------+-----------------------+
                  |                       |                       |
                  v                       v                       v
      +-----------------------+ +-------------------+ +-----------------------+
      |     Portal Server     | |  Campus Gateways  | |     Staff Clients     |
      |   (web-hq / pki)      | | (gw-hq / gw-branch)| |   (staff01..staff03)  |
      |  Key: ECDSA P-256     | | Key: ECDSA P-256  | |  Key: ECDSA P-256     |
      |  Validity: 398 Days   | | Validity: 398 Days| |  Validity: 365 Days   |
      |  EKU: serverAuth      | | EKU: serverAuth,  | |  EKU: clientAuth      |
      |                       | |      clientAuth   | |                       |
      +-----------------------+ +-------------------+ +-----------------------+
```

---

## 2. Certificate Profiles Specification

| Certificate Entity | Subject (DN) | Key Type & Curve | Validity | basicConstraints | keyUsage (Critical) | extendedKeyUsage (EKU) | Subject Alternative Name (SAN) | CRL Distribution Point |
|---|---|---|---|---|---|---|---|---|
| **Root CA** | `CN=AABU SCP Root CA g${GROUP_ID}, O=Al al-Bayt University, C=JO` | ECDSA P-384 | 5 years (1825d) | `critical, CA:TRUE, pathlen:1` | `keyCertSign, cRLSign` | None | None | None |
| **Issuing CA** | `CN=AABU SCP Issuing CA g${GROUP_ID}, O=Al al-Bayt University, C=JO` | ECDSA P-384 | 2 years (730d) | `critical, CA:TRUE, pathlen:0` | `keyCertSign, cRLSign` | None | None | `URI:http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl` |
| **Portal Server** | `CN=portal.g${GROUP_ID}.scp.lab, O=Al al-Bayt University, C=JO` | ECDSA P-256 | 398 days | `critical, CA:FALSE` | `digitalSignature, keyEncipherment` | `serverAuth` | `DNS:portal.g${GROUP_ID}.scp.lab, DNS:pki.g${GROUP_ID}.scp.lab` | `URI:http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl` |
| **Gateway HQ** | `CN=gw-hq.g${GROUP_ID}.scp.lab, O=Al al-Bayt University, C=JO` | ECDSA P-256 | 398 days | `critical, CA:FALSE` | `digitalSignature` | `serverAuth, clientAuth, 1.3.6.1.5.5.7.3.17` (ipsecIKE) | `DNS:gw-hq.g${GROUP_ID}.scp.lab, IP:172.16.${GROUP_NUM}.10` | `URI:http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl` |
| **Gateway Branch** | `CN=gw-branch.g${GROUP_ID}.scp.lab, O=Al al-Bayt University, C=JO` | ECDSA P-256 | 398 days | `critical, CA:FALSE` | `digitalSignature` | `serverAuth, clientAuth, 1.3.6.1.5.5.7.3.17` (ipsecIKE) | `DNS:gw-branch.g${GROUP_ID}.scp.lab, IP:172.16.${GROUP_NUM}.20` | `URI:http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl` |
| **Staff Clients** (`staff01`..`03`) | `CN=staff01, O=Al al-Bayt University, C=JO` | ECDSA P-256 | 1 year (365d) | `critical, CA:FALSE` | `digitalSignature` | `clientAuth` | `email:staff01@g${GROUP_ID}.scp.lab` | `URI:http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl` |
| **Rogue CA** (Attacks Only) | `CN=AABU SCP Root CA g${GROUP_ID}, O=Al al-Bayt University, C=JO` | ECDSA P-256 | 30 days | `critical, CA:TRUE` | `keyCertSign, cRLSign` | None | None | None (Untrusted self-signed) |

---

## 3. Revocation Architecture & Policy

### 3.1 Revocation Procedure
1. An administrator flags a certificate serial for revocation (e.g., employee termination or key compromise) using:
   ```bash
   pki/revoke.sh <cert_name>
   ```
2. The OpenSSL CA database (`index.txt`) updates the certificate entry to `R` (Revoked) with a UTC timestamp and revocation reason code (`keyCompromise`, `cessationOfOperation`, etc.).
3. A newly signed Certificate Revocation List (CRL) is generated with:
   - `lastUpdate`: Current time.
   - `nextUpdate`: `lastUpdate + 7 days`.
4. The CRL is copied to the web root (`/var/www/crl/issuing.crl`) accessible via HTTP at `http://pki.g${GROUP_ID}.scp.lab/crl/issuing.crl`.
5. Nginx and strongSwan daemon are triggered to reload the updated CRL.

### 3.2 CRL vs. OCSP & The Danger of Soft-Fail
- **CRL (Certificate Revocation List):**
  - *Mechanism:* A digitally signed file listing all revoked certificate serials. Downloaded periodically and cached locally by clients and validators.
  - *Advantages:* Simple, does not require real-time high-throughput server lookup infrastructure; offline verifiable.
  - *Disadvantages:* Latency between actual revocation and next scheduled CRL download; file grows linearly with revocations.
- **OCSP (Online Certificate Status Protocol):**
  - *Mechanism:* Real-time request/response query protocol where client asks an OCSP responder for the status of a specific certificate.
  - *Advantages:* Up-to-the-second status checks; bandwidth efficient.
  - *Disadvantages:* Privacy leak (CA learns which sites/identities the client accesses); adds TLS handshake latency unless OCSP Stapling is used.
- **The "Soft-Fail" Security Vulnerability:**
  - When a client or server is configured for *soft-fail*, if the CRL cannot be reached or the OCSP responder is unavailable (due to network timeout or active attacker blocking), the client **proceeds anyway and accepts the certificate**.
  - An active attacker who stole a compromised private key can simply block traffic to the CRL distribution point; under soft-fail, the victim will accept the compromised certificate.
  - **Lab Enforcement Policy:** We configure our systems with **Hard-Fail**: if a certificate contains a CRL DP or our server has a configured CRL, failure to validate against an active, unexpired CRL causes immediate rejection.

---

## 4. Cryptographic Artefact Classification Matrix

| Classification Level | Definition & Handling Rules | Specific Artefacts |
|---|---|---|
| **Public** | May be distributed freely over untrusted networks. | Root CA cert (`ca.crt`), Issuing CA cert (`issuing.crt`), Server cert (`portal.crt`), Gateway certs, Staff certs, Published CRL (`issuing.crl`). |
| **Internal** | Available to internal nodes and operators; contains system configs. | OpenSSL configuration files (`openssl_root.cnf`, `openssl_issuing.cnf`), `certs_inventory.md`, `swanctl.conf`, Nginx `portal.conf`. |
| **Secret** | Must NEVER be committed to Git, shared across nodes, or transmitted in plaintext. File mode strictly `600`. | Root CA private key (`ca.key`), Issuing CA private key (`issuing.key`), Root CA passphrase, Gateway private keys, Staff private keys, Kerberos master keys (`K_kdc`, `K_service`, `K_user`). |
