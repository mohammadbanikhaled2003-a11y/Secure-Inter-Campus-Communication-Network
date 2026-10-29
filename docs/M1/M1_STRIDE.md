# Milestone 1: STRIDE Threat Model
**Project:** Secure Inter-Campus Communication Network  
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  

---

## 1. System Assets Under Threat
1. **Asset 1: Cleartext Inter-Campus Transit Traffic** (HTTP, employee records, academic data on WAN).
2. **Asset 2: Private Cryptographic Keys** (Root CA, Issuing CA, Gateways, Portal, Staff client private keys).
3. **Asset 3: Certificate Trust Chain & Revocation Status** (Integrity of CA signatures and CRL).
4. **Asset 4: Restricted Campus Portal (`/staff/`)** (Administrative functions, employee profiles).
5. **Asset 5: VPN Security Associations & Gateways** (`gw-hq` and `gw-branch` routing, IKE state).
6. **Asset 6: Kerberos Authentication Tickets & Sessions** (TGT, Service Tickets, authenticators).
7. **Asset 7: DNS Resolution Integrity** (`portal.gG.scp.lab` and `pki.gG.scp.lab`).
8. **Asset 8: Cryptographic Messages & Hashes** (Files processed by `scpcrypt.py`).

---

## 2. Comprehensive STRIDE Threat Analysis Matrix

| Threat ID | STRIDE Category | Target Asset | Threat Description & Attack Vector | Likelihood | Impact | Overall Risk | Countermeasure / Security Control |
|---|---|---|---|---|---|---|---|
| **TH-01** | **Information Disclosure** | Inter-Campus WAN Traffic | **Eavesdropping on WAN**: In baseline (M1), WAN traffic traverses in cleartext. Attacker sniffs credentials, session cookies, and HTTP payloads. | High | High | **CRITICAL** | **SR07 / SR08**: Encapsulate all LAN-to-LAN traffic inside IKEv2/IPsec ESP tunnel with AES-GCM-256 and PFS. |
| **TH-02** | **Spoofing** | Portal Web Server | **Rogue CA Man-in-the-Middle (MITM)**: Attacker spoofs DNS or ARP on WAN, redirects client to rogue portal presenting certificate issued by unauthorized Rogue CA. | High | High | **CRITICAL** | **SR02 / SR06**: Client strictly validates certificate chain up to offline Root CA; untrusted CAs fail TLS handshake immediately. |
| **TH-03** | **Elevation of Privilege** | Portal Staff Area (`/staff/`) | **Access with Revoked / Compromised Certificate**: A terminated staff member or attacker with leaked certificate accesses `/staff/`. | Medium | High | **HIGH** | **SR03 / SR05**: Nginx enforces strict mTLS with live CRL checking (`ssl_crl`). Serial is rejected with generic error. |
| **TH-04** | **Spoofing** | Gateway Identity | **Gateway Impersonation**: Attacker attempts IKE negotiation using a stolen staff certificate or unauthorized CA cert to establish tunnel with `gw-hq`. | Medium | High | **HIGH** | **SR07**: Identity Pinning in `swanctl.conf` (`connections.<conn>.remote.id = gw-branch.gG.scp.lab`) and dedicated `ipsecIKE` EKU. |
| **TH-05** | **Information Disclosure** | Inter-Campus WAN Traffic | **Cleartext Traffic Leak on Tunnel Down (Fail-Open)**: If strongSwan crashes or tunnel drops, gateways fall back to standard cleartext IP routing. | High | High | **CRITICAL** | **SR08**: Gateway firewall script (`gw_firewall.sh`) drops any inter-LAN packet on WAN unless encrypted in ESP (Fail-Closed). |
| **TH-06** | **Tampering** | Cryptographic Messages | **Bit-Flipping / Ciphertext Tampering**: Attacker intercepts ciphertext or MAC and modifies single byte in transit. | High | Medium | **HIGH** | **SR01 / SR08**: Use Authenticated Encryption (AES-GCM / ChaCha20-Poly1305) and HMAC-SHA256; single bit flip triggers tag verification error. |
| **TH-07** | **Elevation of Privilege** | Service (`web-hq`) | **Replay Attack on Authentication**: Attacker sniffs legitimate `AP_REQ` authenticator packet on the network and replays it to service to gain access. | High | High | **CRITICAL** | **SR09 / SR10**: Protocol enforces 300s freshness window ($TS$) and an in-memory **Replay Cache** that logs used $(C, TS)$ tuples and rejects duplicates. |
| **TH-08** | **Tampering / Downgrade** | TLS & IKE Negotiations | **Cipher / Protocol Downgrade**: Attacker strips TLS 1.3 or modern IKE proposals in transit to force legacy TLS 1.0 or non-AEAD suites (e.g. 3DES). | Medium | Medium | **MEDIUM** | **SR04 / SR13**: Explicit minimal TLS version 1.2, AEAD-only cipher suites in Nginx, and strict proposals in `swanctl.conf`. Legacy suites rejected. |
| **TH-09** | **Information Disclosure** | Root CA Authority | **Root CA Key Compromise**: Exposure of Root CA private key invalidates the entire university security infrastructure. | Low | Catastrophic | **HIGH** | **SR02 / SR11**: Root CA key is passphrase-protected, kept completely offline, never copied into any container, and omitted from Git. |
| **TH-10** | **Repudiation** | Staff Operations | **Denial of Action**: Staff member performs privileged change on `/staff/` and denies doing so. | Medium | Low | **LOW** | **SR05 / SR14**: Nginx logs the authenticated client certificate subject DN in audit log (`$ssl_client_s_dn`) with timestamps. |

---

## 3. Threat Mitigation Verification Roadmap

Each threat directly corresponds to our Acceptance Test Matrix (T1–T13):
- **TH-01** $\rightarrow$ Test **T7** (Verify only ESP packets on WAN).
- **TH-02** $\rightarrow$ Test **T5** (Rogue CA rejection verification).
- **TH-03** $\rightarrow$ Test **T4** (Revoked certificate rejection on `/staff/`).
- **TH-04** $\rightarrow$ Test **T8** (Rogue / Staff cert rejection as gateway peer).
- **TH-05** $\rightarrow$ Test **T9** (Fail-closed drop when IKE daemon is killed).
- **TH-06** $\rightarrow$ Test **T2** (Crypto tool 1-byte tamper detection).
- **TH-07** $\rightarrow$ Tests **T12a** (Replay succeeds on weak variant) and **T12b** (Replay rejected on fixed variant).
- **TH-08** $\rightarrow$ Test **T6** (Downgrade handshake refusal).
- **TH-09** $\rightarrow$ Test **T13** (Full Git history secret scan).
