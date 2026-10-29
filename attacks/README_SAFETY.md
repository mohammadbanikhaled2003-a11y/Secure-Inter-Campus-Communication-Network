# Safety and Ethical Rules for Laboratory Attacks

## 1. Scope & Authorised Boundaries
- **Strictly Local to Lab Network**: All attacks, scans, packet captures, and penetration tests are strictly permitted **ONLY** within the isolated Docker virtual lab environment (`172.16.G.0/24`, `10.G.1.0/24`, `10.G.2.0/24`).
- **No External Targets**: Conducting any attack, port scanning, ARP spoofing, or packet flooding against university infrastructure, external internet hosts, or peer physical machines is strictly forbidden.
- **Isolated Node Role**: All offensive actions originate from the designated `attacker` container (`172.16.G.66`).

## 2. Containment Controls
- **IP Masquerading Disabled**: All Docker bridge networks are explicitly configured with `com.docker.network.bridge.enable_ip_masquerade: "false"`. No simulated malicious traffic or internal packet can leak outside the host workstation.
- **Rogue CA Protection**: The generated Rogue CA (`CN=AABU SCP Root CA gG (imitation)`) MUST NEVER be installed in any real operating system trust store or host web browser. It is mounted exclusively inside lab test directories.
- **Secret Protection**: Real private keys and passphrases are never committed to version control. Keys used in attack demonstrations are synthetic test artifacts only.

## 3. Responsible Conduct & Forensics
- All attacks are performed for **Verification and Defense**: proving that unhardened components fail and verifying that hardened components reject attacks.
- Packet captures (`.pcap`) and sanitized logs are collected solely to establish forensic evidence for milestones M1, M3, and M4.
