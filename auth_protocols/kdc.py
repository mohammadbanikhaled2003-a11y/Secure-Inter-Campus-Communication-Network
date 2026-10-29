#!/usr/bin/env python3
"""
kdc.py - Key Distribution Center (AS + TGS)
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Listens on TCP port 8800.
Implements AS_REQ/AS_REP and TGS_REQ/TGS_REP exchanges with AEAD, nonces, timestamps, and replay protection.
"""

import socket
import json
import time
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

PORT = 8800
FRESHNESS_WINDOW = 300  # 300 seconds (5 minutes)

# Fixed server master key for reproducible testing
K_KDC = hashlib.sha256(b"AABU_KDC_MASTER_SECRET_2026").digest()

# Pre-shared secrets database
USERS_DB = {
    "staff01": "Staff01Password2026!",
    "staff02": "Staff02Password2026!",
    "staff03": "Staff03Password2026!"
}

SERVICES_DB = {
    "service_portal": hashlib.sha256(b"PORTAL_SERVICE_SECRET_2026").digest()
}

# In-memory Replay Cache: stores (client_id, timestamp)
REPLAY_CACHE = set()


def derive_client_key(client_id: str, password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_id.encode("utf-8"),
        iterations=600000,
    )
    return kdf.derive(password.encode("utf-8"))


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


def handle_as_req(data: dict) -> dict:
    client_id = data.get("client_id")
    server_id = data.get("server_id", "TGS")
    nonce_c = data.get("nonce")

    print(f"[+] Processing AS_REQ from client '{client_id}' for '{server_id}'...")

    if client_id not in USERS_DB:
        print(f"[!] Unknown client '{client_id}'")
        return {"status": "ERROR", "message": "Authentication failed"}

    client_password = USERS_DB[client_id]
    k_c = derive_client_key(client_id, client_password)

    # Generate fresh session key K_C,TGS
    k_c_tgs = secrets.token_bytes(32)
    t_exp = int(time.time()) + 28800  # 8 hours

    # Construct TGT (encrypted under K_KDC)
    tgt_payload = json.dumps({
        "client_id": client_id,
        "server_id": "TGS",
        "session_key": k_c_tgs.hex(),
        "t_exp": t_exp
    }).encode("utf-8")
    tgt_enc = encrypt_aead(K_KDC, tgt_payload)

    # Construct Client response block (encrypted under K_C)
    resp_payload = json.dumps({
        "session_key": k_c_tgs.hex(),
        "nonce": nonce_c,
        "server_id": "TGS",
        "t_exp": t_exp
    }).encode("utf-8")
    resp_enc = encrypt_aead(k_c, resp_payload)

    return {
        "status": "OK",
        "type": "AS_REP",
        "enc_part": resp_enc,
        "tgt": tgt_enc
    }


def handle_tgs_req(data: dict) -> dict:
    service_id = data.get("service_id")
    nonce_c = data.get("nonce")
    tgt_enc = data.get("tgt")
    auth_enc = data.get("authenticator")

    print(f"[+] Processing TGS_REQ for service '{service_id}'...")

    if service_id not in SERVICES_DB:
        return {"status": "ERROR", "message": "Unknown service"}

    # 1. Decrypt TGT using K_KDC
    try:
        tgt_data = json.loads(decrypt_aead(K_KDC, tgt_enc).decode("utf-8"))
    except Exception as e:
        print("[!] TGT decryption failed:", e)
        return {"status": "ERROR", "message": "Invalid TGT"}

    client_id = tgt_data["client_id"]
    k_c_tgs = bytes.fromhex(tgt_data["session_key"])
    t_exp = tgt_data["t_exp"]

    if time.time() > t_exp:
        return {"status": "ERROR", "message": "TGT expired"}

    # 2. Decrypt Authenticator using K_C,TGS
    try:
        auth_data = json.loads(decrypt_aead(k_c_tgs, auth_enc).decode("utf-8"))
    except Exception as e:
        print("[!] Authenticator decryption failed:", e)
        return {"status": "ERROR", "message": "Invalid Authenticator"}

    if auth_data["client_id"] != client_id:
        return {"status": "ERROR", "message": "Authenticator client mismatch"}

    ts = auth_data["timestamp"]
    now = time.time()

    # 3. Freshness Check
    if abs(now - ts) > FRESHNESS_WINDOW:
        print(f"[!] Timestamp expired: delta {abs(now - ts):.1f}s > {FRESHNESS_WINDOW}s")
        return {"status": "ERROR", "message": "Timestamp expired"}

    # 4. Replay Cache Check
    cache_key = (client_id, ts)
    if cache_key in REPLAY_CACHE:
        print(f"[!] REPLAY ATTACK DETECTED for client '{client_id}' at timestamp {ts}!")
        return {"status": "ERROR", "message": "Replay detected"}

    REPLAY_CACHE.add(cache_key)

    # 5. Issue Service Ticket (ST)
    k_service = SERVICES_DB[service_id]
    k_c_s = secrets.token_bytes(32)
    st_exp = int(now) + 3600  # 1 hour

    st_payload = json.dumps({
        "client_id": client_id,
        "service_id": service_id,
        "session_key": k_c_s.hex(),
        "t_exp": st_exp
    }).encode("utf-8")
    st_enc = encrypt_aead(k_service, st_payload)

    # 6. Response to client encrypted with K_C,TGS
    tgs_resp_payload = json.dumps({
        "session_key": k_c_s.hex(),
        "nonce": nonce_c,
        "service_id": service_id,
        "t_exp": st_exp
    }).encode("utf-8")
    tgs_resp_enc = encrypt_aead(k_c_tgs, tgs_resp_payload)

    return {
        "status": "OK",
        "type": "TGS_REP",
        "enc_part": tgs_resp_enc,
        "ticket": st_enc
    }


def run_kdc():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(10)
    print(f"[*] KDC daemon running on port {PORT}...")

    while True:
        conn, addr = server.accept()
        try:
            raw = conn.recv(16384)
            if not raw:
                conn.close()
                continue
            req = json.loads(raw.decode("utf-8"))
            req_type = req.get("type")

            if req_type == "AS_REQ":
                resp = handle_as_req(req)
            elif req_type == "TGS_REQ":
                resp = handle_tgs_req(req)
            else:
                resp = {"status": "ERROR", "message": "Unknown request type"}

            conn.sendall(json.dumps(resp).encode("utf-8"))
        except Exception as ex:
            print("[!] Exception handling request:", ex)
        finally:
            conn.close()


if __name__ == "__main__":
    run_kdc()
