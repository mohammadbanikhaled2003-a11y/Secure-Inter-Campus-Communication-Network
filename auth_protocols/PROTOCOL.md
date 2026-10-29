# Kerberos-Style Inter-Campus Authentication Protocol Specification
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  
**Implementation:** `auth_protocols/kdc.py`, `auth_protocols/service.py`, `auth_protocols/client.py`  

---

## 1. Principals & Cryptographic Material

- **Client ($C$):** Staff member workstation (`client-br`).
- **Key Distribution Center ($KDC$):** Combines Authentication Service (AS) and Ticket Granting Service (TGS).
- **Service ($S$):** Internal Campus Application Service running on `web-hq`.
- **$K_C$:** Client long-term master key derived from password via `PBKDF2-HMAC-SHA256(password, salt=client_id, iterations=600000)`. Never transmitted.
- **$K_S$:** Service long-term master key shared symmetrically between KDC and $S$.
- **$K_{KDC}$:** Master key known exclusively to KDC.
- **$K_{C,TGS}$:** Ephemeral session key for Client $\leftrightarrow$ TGS.
- **$K_{C,S}$:** Ephemeral session key for Client $\leftrightarrow$ Service.
- **$N_1, N_2$:** Cryptographically secure 128-bit random nonces (`secrets.token_bytes(16)`).
- **$TS$:** Unix timestamp in seconds.
- **$\Delta t$:** Freshness window (configured to 300 seconds).
- **$E_K(P)$:** Authenticated Encryption with Associated Data (AES-256-GCM) with random 12-byte IV and 16-byte authentication tag.

---

## 2. Formal Message Sequence in Standard Notation

### Phase 1: Authentication Service (AS) Exchange
The client requests a Ticket-Granting Ticket without sending credentials over the network:

$$1.\quad C \longrightarrow KDC:\quad \{\text{"type": "AS\_REQ"},\ C,\ TGS,\ N_1\}$$

KDC generates fresh session key $K_{C,TGS}$, constructs $TGT$, and replies:
$$TGT = E_{K_{KDC}}\Big( C,\ TGS,\ K_{C,TGS},\ T_{\text{exp}} \Big)$$
$$2.\quad KDC \longrightarrow C:\quad \Big\{ E_{K_C}\Big( K_{C,TGS},\ N_1,\ TGS,\ T_{\text{exp}} \Big),\ TGT \Big\}$$

The client decrypts the encrypted block using $K_C$ and verifies that the nonce in the decrypted plaintext equals $N_1$.

---

### Phase 2: Ticket-Granting Service (TGS) Exchange
The client presents the opaque $TGT$ and proves possession of $K_{C,TGS}$ using a fresh Authenticator $Auth_C$:

$$Auth_C = E_{K_{C,TGS}}\Big( C,\ TS_1 \Big)$$
$$3.\quad C \longrightarrow KDC:\quad \{\text{"type": "TGS\_REQ"},\ S,\ N_2,\ TGT,\ Auth_C\}$$

KDC validates:
1. $TGT$ decrypts with $K_{KDC}$ and $T_{\text{exp}} > \text{CurrentTime}$.
2. $Auth_C$ decrypts with $K_{C,TGS}$ and identity equals $C$.
3. $|CurrentTime - TS_1| \le \Delta t$.
4. Tuple $(C, TS_1)$ is **not** present in KDC Replay Cache. Tuple is added to cache.

KDC generates service session key $K_{C,S}$, encrypts Service Ticket $ST$, and replies:
$$ST = E_{K_S}\Big( C,\ S,\ K_{C,S},\ T_{\text{exp}} \Big)$$
$$4.\quad KDC \longrightarrow C:\quad \Big\{ E_{K_{C,TGS}}\Big( K_{C,S},\ N_2,\ S,\ T_{\text{exp}} \Big),\ ST \Big\}$$

The client decrypts and verifies $N_2$.

---

### Phase 3: Application (AP) Mutual Authentication Exchange
The client sends the Service Ticket and a fresh Service Authenticator $Auth_{CS}$:

$$Auth_{CS} = E_{K_{C,S}}\Big( C,\ TS_2 \Big)$$
$$5.\quad C \longrightarrow S:\quad \{\text{"type": "AP\_REQ"},\ ST,\ Auth_{CS},\ \text{payload}\}$$

Service $S$ validates:
1. $ST$ decrypts with $K_S$ and expiration is valid.
2. $Auth_{CS}$ decrypts with $K_{C,S}$.
3. Freshness check: $|CurrentTime - TS_2| \le \Delta t$.
4. Replay Cache check: $(C, TS_2)$ has never been seen before.

To prove mutual authentication, Service responds with:
$$6.\quad S \longrightarrow C:\quad E_{K_{C,S}}\Big( TS_2 + 1,\ \text{"STATUS": "AUTHORIZED"},\ \text{response\_data} \Big)$$

Client decrypts response and verifies that the returned timestamp is exactly $TS_2 + 1$.

---

## 3. Defense Against Known Protocol Vulnerabilities
- **Offline Password Guessing:** Passwords are salted with client ID and stretched using 600,000 PBKDF2 iterations.
- **Eavesdropping on Session Keys:** Keys are always transmitted inside AES-GCM encrypted envelopes.
- **Replay Attacks (SR10):** Prevented by the combination of the 300-second freshness window and the persistent in-memory sliding Replay Cache. Any replayed $(C, TS)$ within the window is rejected with `REPLAY_DETECTED`. Beyond the window, it is rejected with `TIMESTAMP_EXPIRED`.
