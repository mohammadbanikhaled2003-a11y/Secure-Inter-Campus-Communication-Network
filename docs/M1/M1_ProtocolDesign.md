# Milestone 1: Cryptographic Protocol Design Specification
**Project:** Secure Inter-Campus Communication Network  
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  

---

## 1. TLS 1.3 Handshake Protocol (with Mutual TLS)

The secure campus portal enforces TLS 1.3 as primary standard, requiring client authentication on the `/staff/` URI endpoint.

```
       Client (client-br)                                   Server (web-hq)
               |                                                   |
               | -------- ClientHello (KeyShare, CipherSuites) --> |
               |                                                   |
               | <-- ServerHello (KeyShare selected) ------------- |
               | <-- {EncryptedExtensions} ----------------------- |
               | <-- {CertificateRequest (Issuing CA DN)} -------- |
               | <-- {Certificate (portal.crt + issuing.crt)} ---- |
               | <-- {CertificateVerify (ECDSA Signature)} ------- |
               | <-- {Finished} ---------------------------------- |
               |                                                   |
[Verify Server Cert & Sig]                                         |
               |                                                   |
               | --- {Certificate (staff01.crt)} ----------------> |
               | --- {CertificateVerify (ECDSA Signature)} ------> |
               | --- {Finished} ---------------------------------> |
               |                                                   |
               |                                         [Verify Client Cert,
               |                                          Check CRL revocation,
               |                                          Extract Staff ID]
               |                                                   |
               | <========== Bidirectional AEAD Encrypted =======> |
               |             Application Data (HTTP/2)             |
```

### Protocol Steps:
1. **ClientHello**: Includes supported versions (TLS 1.3), cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`), and ephemeral ECDH public key share (`X25519` / `secp256r1`).
2. **ServerHello**: Chooses cipher suite and responds with ephemeral key share. Immediately derives handshake secret.
3. **CertificateRequest**: Demands client certificate matching the accepted CA DN (`CN=AABU SCP Issuing CA g${GROUP_ID}`).
4. **Certificate & CertificateVerify**: Server sends full certificate chain and proves possession of private key via digital signature over handshake context transcript.
5. **Client Authentication**: Client transmits its issued staff certificate and signs handshake transcript with its private key.
6. **Finished**: Both parties verify MAC over handshake hash, ensuring transcript integrity.

---

## 2. IKEv2 / IPsec Protocol (RFC 7296 & RFC 4303)

The site-to-site VPN negotiates security associations through two phases: `IKE_SA_INIT` and `IKE_AUTH`. Authentication is performed strictly via mutual X.509 digital certificates (no PSK allowed).

```
   Branch Gateway (gw-branch)                            HQ Gateway (gw-hq)
        [172.16.G.20]                                       [172.16.G.10]
               |                                                   |
               | ===== 1. IKE_SA_INIT Request ===================> |
               |   HDR, SAi1, KEi (Curve25519), Ni (Nonce)         |
               |                                                   |
               | <==== 2. IKE_SA_INIT Response =================== |
               |   HDR, SAr1, KEr (Curve25519), Nr (Nonce)         |
               |                                                   |
    [Derive SKEYSEED &                                  [Derive SKEYSEED &
     SK_e, SK_a, SK_d]                                   SK_e, SK_a, SK_d]
               |                                                   |
               | ===== 3. IKE_AUTH Request (Encrypted) ===========> |
               |   HDR, SK { IDi (gw-branch.gG.scp.lab),           |
               |             CERT (gw-branch cert),                |
               |             AUTH (Digital Signature),             |
               |             SAi2 (ESP Proposal: AES-GCM-256),     |
               |             TSi (10.G.2.0/24), TSr (10.G.1.0/24) }|
               |                                                   |
               |                                         [Validate gw-branch cert,
               |                                          Check pinned Identity,
               |                                          Verify AUTH signature,
               |                                          Validate Traffic Selectors]
               |                                                   |
               | <==== 4. IKE_AUTH Response (Encrypted) ========== |
               |   HDR, SK { IDr (gw-hq.gG.scp.lab),               |
               |             CERT (gw-hq cert),                    |
               |             AUTH (Digital Signature),             |
               |             SAr2 (ESP Proposal Accepted),         |
               |             TSi (10.G.2.0/24), TSr (10.G.1.0/24) }|
               |                                                   |
 [Validate gw-hq cert,                                             |
  Check pinned Identity,                                           |
  Verify AUTH signature]                                           |
               |                                                   |
               +===================================================+
               |     ESTABLISHED CHILD SA (IPsec ESP Tunnel)       |
               |     Header: ESP SPI, Sequence #, AEAD Tag         |
               |     Encapsulated Subnets: 10.G.2.0/24 <-> 10.G.1.0/24 |
               +===================================================+
```

### Security Properties:
- **Proposal Hardening:** `aes256gcm16-prfsha384-curve25519` for IKE; `aes256gcm16-curve25519` for ESP.
- **Perfect Forward Secrecy (PFS):** Curve25519 ECDH exchanged in both IKE SA and Child SA rekeying.
- **Identity Pinning:** `gw-hq` accepts peer identity ONLY if it matches `gw-branch.g${GROUP_ID}.scp.lab`; any staff certificate from the same CA is rejected with an identity mismatch error.

---

## 3. Kerberos-Style Authentication Protocol

The protocol authenticates a principal ($C$, Client) to an Application Service ($S$, `service.py`) via a Key Distribution Center ($KDC$, `kdc.py`) which acts as both Authentication Server (AS) and Ticket-Granting Server (TGS).

### 3.1 Notation & Cryptographic Primitives
- $K_C$: Client's long-term key derived from password using `PBKDF2-HMAC-SHA256(password, salt=client_id, iterations=600000)`.
- $K_{KDC}$: Master symmetric key known only to KDC.
- $K_S$: Service master key shared only between KDC and `service.py`.
- $K_{C,TGS}$: Session key for Client $\leftrightarrow$ TGS communication.
- $K_{C,S}$: Session key for Client $\leftrightarrow$ Service communication.
- $N_1, N_2$: Fresh 128-bit random nonces generated via `os.urandom(16)`.
- $T_{exp}$: Expiration timestamp (Freshness lifetime, typically 300 seconds).
- $TS$: Current timestamp of authenticator generation.
- $E_K(P)$: Authenticated Encryption with Associated Data (AES-256-GCM) with IV, ciphertext, and 128-bit authentication tag.

### 3.2 Message Sequence Overview

```
Client (C)                         KDC (AS / TGS)                         Service (S)
    |                                    |                                     |
    | ----- 1. AS_REQ (C, TGS, N1) ----> |                                     |
    |                                    |                                     |
    | <-- 2. AS_REP (E_Kc, TGT) -------- |                                     |
    |                                    |                                     |
    | ----- 3. TGS_REQ (Auth_c, TGT) --> |                                     |
    |                                    |                                     |
    | <-- 4. TGS_REP (E_Kc,tgs, ST) ---- |                                     |
    |                                                                          |
    | ------------------------- 5. AP_REQ (Auth_cs, ST) ---------------------> |
    |                                                                          |
    | <------------------------ 6. AP_REP (Mutual Auth Confirmation) --------- |
```

### 3.3 Detailed Mathematical Message Definitions

#### Step 1: AS_REQ (Authentication Service Request)
Client contacts KDC to request access to the Ticket-Granting Service:
$$C \rightarrow KDC: \{ C,\ TGS,\ N_1 \}$$

#### Step 2: AS_REP (Authentication Service Response)
KDC verifies $C$ exists in database, generates session key $K_{C,TGS}$, constructs Ticket-Granting Ticket $TGT$, and encrypts:
$$TGT = E_{K_{KDC}}\Big( C,\ TGS,\ K_{C,TGS},\ T_{exp} \Big)$$
$$C \leftarrow KDC: \Big\{ E_{K_C}\Big( K_{C,TGS},\ N_1,\ TGS,\ T_{exp} \Big),\ TGT \Big\}$$
Client decrypts the first block using $K_C$ and verifies nonce $N_1$ matches.

#### Step 3: TGS_REQ (Ticket-Granting Service Request)
Client constructs an Authenticator to prove possession of $K_{C,TGS}$:
$$Auth_C = E_{K_{C,TGS}}\Big( C,\ TS_1 \Big)$$
$$C \rightarrow KDC: \{ S,\ N_2,\ TGT,\ Auth_C \}$$

#### Step 4: TGS_REP (Ticket-Granting Service Response)
KDC decrypts $TGT$ using $K_{KDC}$, extracts $K_{C,TGS}$, decrypts $Auth_C$, checks $|CurrentTime - TS_1| \le \Delta t$ (Freshness Window: 300s), and checks its **Replay Cache**. KDC creates Service Ticket $ST$:
$$ST = E_{K_S}\Big( C,\ S,\ K_{C,S},\ T_{exp} \Big)$$
$$C \leftarrow KDC: \Big\{ E_{K_{C,TGS}}\Big( K_{C,S},\ N_2,\ S,\ T_{exp} \Big),\ ST \Big\}$$
Client decrypts with $K_{C,TGS}$ and verifies nonce $N_2$.

#### Step 5: AP_REQ (Application Request to Service)
Client constructs a fresh Authenticator for Service $S$:
$$Auth_{CS} = E_{K_{C,S}}\Big( C,\ TS_2 \Big)$$
$$C \rightarrow S: \{ ST,\ Auth_{CS},\ Payload \}$$

#### Step 6: AP_REP (Mutual Authentication Confirmation)
Service decrypts $ST$ using $K_S$, extracts $K_{C,S}$, decrypts $Auth_{CS}$, validates timestamp $|CurrentTime - TS_2| \le \Delta t$, verifies against Service Replay Cache, and proves its identity by responding:
$$S \rightarrow C: E_{K_{C,S}}\Big( TS_2 + 1,\ Status \Big)$$
Client decrypts and verifies timestamp equals $TS_2 + 1$. Mutual authentication is now established.
