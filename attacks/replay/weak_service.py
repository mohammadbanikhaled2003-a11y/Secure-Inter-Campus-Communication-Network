#!/usr/bin/env python3
"""
weak_service.py - Vulnerable Application Service (NO FRESHNESS / NO REPLAY CACHE)
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Used for Acceptance Test T12a to demonstrate successful replay attack.
Listens on TCP port 8802.
"""

import socket
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 8802
K_SERVICE = hashlib.sha256(b"PORTAL_SERVICE_SECRET_2026").digest()


def decrypt_aead(key: bytes, hex_payload: str) -> bytes:
    payload = bytes.fromhex(hex_payload)
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def encrypt_aead(key: bytes, plaintext: bytes) -> str:
    import secrets
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return (nonce + ct).hex()


def handle_weak_ap_req(req: dict) -> dict:
    ticket_enc = req.get("ticket")
    auth_enc = req.get("authenticator")

    # Decrypt Ticket
    try:
        st_data = json.loads(decrypt_aead(K_SERVICE, ticket_enc).decode("utf-8"))
    except Exception as e:
        return {"status": "ERROR", "message": "Ticket decryption failed"}

    client_id = st_data["client_id"]
    k_c_s = bytes.fromhex(st_data["session_key"])

    # Decrypt Authenticator
    try:
        auth_data = json.loads(decrypt_aead(k_c_s, auth_enc).decode("utf-8"))
    except Exception as e:
        return {"status": "ERROR", "message": "Authenticator decryption failed"}

    # VULNERABILITY: Neither timestamp freshness nor replay cache is checked!
    print(f"[!] VULNERABLE SERVICE: Accepted packet for '{client_id}' (Timestamp: {auth_data.get('timestamp')}) WITHOUT Freshness or Replay Check!")

    reply_payload = json.dumps({
        "timestamp_confirm": auth_data.get("timestamp", 0) + 1,
        "service_status": "VULNERABLE_SUCCESS",
        "result": f"Confidential payload leaked to attacker via replayed ticket for {client_id}!"
    }).encode("utf-8")

    return {
        "status": "OK",
        "type": "AP_REP",
        "enc_part": encrypt_aead(k_c_s, reply_payload)
    }


def run_weak_service():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    print(f"[*] Deliberately WEAK Service running on port {PORT} for T12a...")

    while True:
        conn, _ = server.accept()
        try:
            raw = conn.recv(16384)
            if not raw:
                conn.close()
                continue
            req = json.loads(raw.decode("utf-8"))
            resp = handle_weak_ap_req(req)
            conn.sendall(json.dumps(resp).encode("utf-8"))
        finally:
            conn.close()


if __name__ == "__main__":
    run_weak_service()
