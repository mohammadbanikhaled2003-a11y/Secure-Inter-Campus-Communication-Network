#!/usr/bin/env python3
"""
service.py - Kerberos Protected Campus Application Service
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Listens on TCP port 8801.
Implements AP_REQ validation, freshness checks, replay cache, and AP_REP mutual authentication.
"""

import socket
import json
import time
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 8801
FRESHNESS_WINDOW = 300  # 300 seconds

# Service long-term key (matches KDC SERVICES_DB["service_portal"])
K_SERVICE = hashlib.sha256(b"PORTAL_SERVICE_SECRET_2026").digest()

# Service Replay Cache: stores (client_id, timestamp)
SERVICE_REPLAY_CACHE = set()


def encrypt_aead(key: bytes, plaintext: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return (nonce + ct).hex()


def decrypt_aead(key: bytes, hex_payload: str) -> bytes:
    payload = bytes.fromhex(hex_payload)
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def handle_ap_req(req: dict) -> dict:
    ticket_enc = req.get("ticket")
    auth_enc = req.get("authenticator")
    command = req.get("command", "READ_RECORDS")

    # 1. Decrypt Service Ticket
    try:
        st_data = json.loads(decrypt_aead(K_SERVICE, ticket_enc).decode("utf-8"))
    except Exception as e:
        print("[!] Service Ticket decryption failed:", e)
        return {"status": "ERROR", "message": "Ticket decryption failed"}

    client_id = st_data["client_id"]
    k_c_s = bytes.fromhex(st_data["session_key"])
    t_exp = st_data["t_exp"]

    if time.time() > t_exp:
        return {"status": "ERROR", "message": "Ticket expired"}

    # 2. Decrypt Authenticator
    try:
        auth_data = json.loads(decrypt_aead(k_c_s, auth_enc).decode("utf-8"))
    except Exception as e:
        print("[!] Authenticator decryption failed:", e)
        return {"status": "ERROR", "message": "Authenticator decryption failed"}

    if auth_data["client_id"] != client_id:
        return {"status": "ERROR", "message": "Identity mismatch in ticket and authenticator"}

    ts = auth_data["timestamp"]
    now = time.time()

    # 3. Freshness Check
    if abs(now - ts) > FRESHNESS_WINDOW:
        print(f"[!] Authenticator expired: delta {abs(now - ts):.1f}s")
        return {"status": "ERROR", "message": "Freshness check failed: timestamp outside window"}

    # 4. Replay Cache Check
    cache_entry = (client_id, ts)
    if cache_entry in SERVICE_REPLAY_CACHE:
        print(f"[!] REPLAY ATTACK DETECTED for {client_id} (timestamp: {ts})!")
        return {"status": "ERROR", "message": "Replay attack detected: cached timestamp rejected"}

    SERVICE_REPLAY_CACHE.add(cache_entry)

    print(f"[✓] Mutual auth verified for staff member '{client_id}'. Processing command '{command}'...")

    # 5. Build Mutual Authentication Response (AP_REP)
    # Echo back timestamp + 1 encrypted with session key K_C,S
    reply_payload = json.dumps({
        "timestamp_confirm": ts + 1,
        "service_status": "SUCCESS",
        "result": f"Restricted administrative records released to authenticated user {client_id}."
    }).encode("utf-8")

    enc_reply = encrypt_aead(k_c_s, reply_payload)

    return {
        "status": "OK",
        "type": "AP_REP",
        "enc_part": enc_reply
    }


def run_service():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(10)
    print(f"[*] Application Service running on port {PORT}...")

    while True:
        conn, addr = server.accept()
        try:
            raw = conn.recv(16384)
            if not raw:
                conn.close()
                continue
            req = json.loads(raw.decode("utf-8"))
            if req.get("type") == "AP_REQ":
                resp = handle_ap_req(req)
            else:
                resp = {"status": "ERROR", "message": "Unknown service request"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
        except Exception as e:
            print("[!] Exception handling service request:", e)
        finally:
            conn.close()


if __name__ == "__main__":
    run_service()
