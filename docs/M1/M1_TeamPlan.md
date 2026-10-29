# Milestone 1: Team Work Plan & Release Management
**Project:** Secure Inter-Campus Communication Network  
**Course:** Secure Communication Protocols (1305301) — Al al-Bayt University  

---

## 1. Team Structure & Role Allocation

As mandated by course policy (3 members per group), responsibilities are assigned across primary security functional domains:

### Member 1: Cryptography & PKI Lead
- **Domain:** Public Key Infrastructure & Message Cryptography.
- **Responsibilities:**
  - Design OpenSSL configuration profiles (`openssl_root.cnf`, `openssl_issuing.cnf`).
  - Implement and automate PKI generation scripts (`build_pki.sh`, `issue.sh`, `revoke.sh`).
  - Maintain the Certificate Inventory (`certs_inventory.md`) and CRL distribution mechanism.
  - Implement the Python cryptographic message tool (`crypto/scpcrypt.py`) and write comprehensive test suites adhering to RFC 4231 (HMAC-SHA256) and RFC 8032 (Ed25519).
  - Conduct secret scans before milestone commits (SR11).

### Member 2: Network Infrastructure & VPN Lead
- **Domain:** Containerized Lab, Network Routing & IPsec Architecture.
- **Responsibilities:**
  - Configure and maintain the 6-node Docker Compose virtual lab topology.
  - Deploy and tune strongSwan IKEv2 site-to-site VPN (`swanctl.conf` on `gw-hq` and `gw-branch`).
  - Author and verify the gateway hardening firewall script (`gw_firewall.sh`) enforcing **Fail-Closed** packet dropping.
  - Execute traffic captures on the untrusted WAN (`tcpdump` / `tshark`), generating baseline (`M1_baseline_wan.pcap`) and encrypted (`M3_tunnel_wan.pcap`) evidence.
  - Verify Dead Peer Detection (DPD) and Perfect Forward Secrecy (PFS).

### Member 3: Application Security & Protocol Lead
- **Domain:** Hardened Web Services, Authentication Protocols & Red-Team Attacks.
- **Responsibilities:**
  - Build hardened Nginx TLS configuration (`portal.conf`) with HSTS, HTTP redirects, and mutual TLS (mTLS) client verification for `/staff/`.
  - Design and implement the Kerberos-style authentication protocol (`kdc.py`, `service.py`, `client.py`, `PROTOCOL.md`).
  - ConstructRED red-team attack scripts: Rogue CA MITM (`attacks/mitm/`), TLS/IKE downgrade (`attacks/downgrade/`), and Authenticator replay (`attacks/replay/`).
  - Assemble the master test runner (`tests/run_all.sh`) and consolidate test results in `evidence/test_log.xlsx`.

---

## 2. Project Milestone Roadmap & Deadlines

```mermaid
gantt
    title Secure Inter-Campus Network Project Timeline (First Semester 2026/2027)
    dateFormat  YYYY-MM-DD
    section Milestones
    M1: Analysis, Design & Baseline (4 pts)       :done,    m1, 2026-10-29, 2026-11-06
    M2: PKI, Crypto Tool & TLS Portal (6 pts)     :active,  m2, 2026-11-07, 2026-11-20
    Midterm Exams Week (No Submissions)           :crit,    mid, 2026-11-29, 2026-12-05
    M3: VPN, Auth Protocol & Attacks (11 pts)     :         m3, 2026-12-06, 2026-12-11
    M4: Final Delivery & Assessment (9 pts)       :         m4, 2026-12-12, 2026-12-25
    Final Discussion & Oral Defense               :crit,    def, 2027-01-10, 2027-01-14
```

| Milestone | Deadline | Marks | Core Deliverables | Git Tag |
|---|---|---|---|---|
| **M1: Analysis, Design & Baseline** | 06/11/2026 | 4 | Requirements document, Topology/Trust diagram, PKI design, Protocol design, STRIDE threat model, Team work plan, Baseline cleartext WAN capture (`M1_baseline_wan.pcap`). | `M1` |
| **M2: PKI, Crypto Tool & TLS** | 20/11/2026 | 6 | `build_pki.sh`, `issue.sh`, `revoke.sh`, CRL, `scpcrypt.py` with RFC test vectors, Nginx TLS + mTLS on `/staff/`, functional tests report. | `M2` |
| *Midterms Week* | *29/11 – 05/12/2026* | — | *No submissions due.* | — |
| **M3: VPN, Auth Protocol & Attacks** | 11/12/2026 | 11 | strongSwan IKEv2 VPN, fail-closed firewall, Kerberos Python protocol (`kdc.py`, `service.py`, `client.py`), MITM, replay and downgrade attack scripts with before/after pcaps. | `M3` |
| **M4: Final Assessment & Delivery** | 25/12/2026 | 9 | Integrated `run_all.sh` (Tests T1–T13), `testssl.sh` report, cert revocation & key rotation demonstration, Final Report (12–20 pages), clean rebuild verification. | `FINAL` |
| **Oral Discussion** | 10/01 – 14/01/2027 | (2) | Live practical evaluation & individual defense questions. | — |

---

## 3. Git Release & Branching Strategy
- **Repository Visibility:** Private repository on GitHub / Git host.
- **Main Branch (`main`):** Production-ready, verified code. Direct commits of untested code are prohibited.
- **Feature Branches:**
  - `feature/pki-core`: PKI scripts and profiles.
  - `feature/crypto-tool`: `scpcrypt.py` and unit tests.
  - `feature/tls-portal`: Nginx configurations and mTLS.
  - `feature/ipsec-vpn`: strongSwan configurations and firewall.
  - `feature/kerberos-auth`: KDC, service, and client implementation.
  - `feature/attacks`: Red-team attack scripts and tests.
- **Milestone Release Tags:**
  Each milestone is tagged with an annotated, timestamped Git tag:
  ```bash
  git tag -a M1 -m "Milestone 1: Design, Specifications, and Baseline Capture"
  git tag -a M2 -m "Milestone 2: Two-Tier PKI, Crypto Tool, and TLS/mTLS Portal"
  git tag -a M3 -m "Milestone 3: IPsec Tunnel, Kerberos Protocol, and Attack Suite"
  git tag -a FINAL -m "Milestone 4: Final Assessment, Unified Tests, and Documentation"
  ```
- **Pre-Tag Verification (SR11):**
  Prior to pushing any tag, run:
  ```bash
  git log -p | grep -Ei "BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|passphrase|password|secret"
  ```
