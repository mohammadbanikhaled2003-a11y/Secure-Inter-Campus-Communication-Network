#!/usr/bin/env python3
"""
client.py - Staff Client for Kerberos Authentication
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Usage:
  python3 client.py --client staff01 --password Staff01Password2026!
"""

import socket
import json
import time
import secrets
import argparse
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


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


def send_json(host: str, port: int, msg: dict) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    s.sendall(json.dumps(msg).encode("utf-8"))
    raw = s.recv(16384)
    s.close()
    return json.loads(raw.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="AABU Kerberos Client")
    parser.add_argument("--client", default="staff01", help="Client Principal ID")
    parser.add_argument("--password", default="Staff01Password2026!", help="Client password")
    parser.add_argument("--kdc-host", default="127.0.0.1", help="KDC hostname or IP")
    parser.add_argument("--kdc-port", type=int, default=8800, help="KDC port")
    parser.add_argument("--service-host", default="127.0.0.1", help="Service hostname or IP")
    parser.add_argument("--service-port", type=int, default=8801, help="Service port")
    parser.add_argument("--service-id", default="service_portal", help="Target service ID")
    parser.add_argument("--save-auth", help="Save AP_REQ packet to file for replay tests")

    args = parser.parse_args()

    print(f"[+] 1. Starting AS exchange with KDC ({args.kdc_host}:{args.kdc_port})...")
    k_c = derive_client_key(args.client, args.password)
    nonce1 = secrets.token_hex(16)

    as_req = {
        "type": "AS_REQ",
        "client_id": args.client,
        "server_id": "TGS",
        "nonce": nonce1
    }

    try:
        as_rep = send_json(args.kdc_host, args.kdc_port, as_req)
    except Exception as e:
        print("[!] Connection to KDC failed:", e)
        sys.exit(1)

    if as_rep.get("status") != "OK":
        print(f"[✗] AS Exchange FAILED: {as_rep.get('message', 'Refused')}")
        sys.exit(1)

    try:
        dec_part = json.loads(decrypt_aead(k_c, as_rep["enc_part"]).decode("utf-8"))
    except InvalidTag:
        # Security test T11: Wrong password fails without leaking internals
        print("[✗] AS Exchange FAILED: Authentication credentials rejected (Invalid key/password)!")
        sys.exit(1)

    if dec_part["nonce"] != nonce1:
        print("[!] Nonce mismatch in AS_REP!")
        sys.exit(1)

    k_c_tgs = bytes.fromhex(dec_part["session_key"])
    tgt = as_rep["tgt"]
    print("[✓] AS Exchange SUCCESS: Received valid TGT and K_C,TGS.")

    # -------------------------------------------------------------
    # 2. TGS Exchange
    # -------------------------------------------------------------
    print(f"[+] 2. Starting TGS exchange for service '{args.service_id}'...")
    nonce2 = secrets.token_hex(16)
    ts1 = int(time.time())

    # Build Authenticator for TGS
    auth_c = encrypt_aead(k_c_tgs, json.dumps({
        "client_id": args.client,
        "timestamp": ts1
    }).encode("utf-8"))

    tgs_req = {
        "type": "TGS_REQ",
        "service_id": args.service_id,
        "nonce": nonce2,
        "tgt": tgt,
        "authenticator": auth_c
    }

    tgs_rep = send_json(args.kdc_host, args.kdc_port, tgs_req)
    if tgs_rep.get("status") != "OK":
        print(f"[✗] TGS Exchange FAILED: {tgs_rep.get('message', 'Refused')}")
        sys.exit(1)

    dec_tgs = json.loads(decrypt_aead(k_c_tgs, tgs_rep["enc_part"]).decode("utf-8"))
    if dec_tgs["nonce"] != nonce2:
        print("[!] Nonce mismatch in TGS_REP!")
        sys.exit(1)

    k_c_s = bytes.fromhex(dec_tgs["session_key"])
    service_ticket = tgs_rep["ticket"]
    print(f"[✓] TGS Exchange SUCCESS: Received Service Ticket for '{args.service_id}'.")

    # -------------------------------------------------------------
    # 3. Application (AP) Mutual Authentication Exchange
    # -------------------------------------------------------------
    print(f"[+] 3. Connecting to Application Service ({args.service_host}:{args.service_port})...")
    ts2 = int(time.time())

    # Build Service Authenticator
    auth_cs = encrypt_aead(k_c_s, json.dumps({
        "client_id": args.client,
        "timestamp": ts2
    }).encode("utf-8"))

    ap_req = {
        "type": "AP_REQ",
        "ticket": service_ticket,
        "authenticator": auth_cs,
        "command": "FETCH_FINANCIAL_RECORDS"
    }

    if args.save_auth:
        with open(args.save_auth, "w") as f:
            json.dump(ap_req, f, indent=2)
        print(f"[i] Saved AP_REQ packet to {args.save_auth} for replay testing.")

    ap_rep = send_json(args.service_host, args.service_port, ap_req)
    if ap_rep.get("status") != "OK":
        print(f"[✗] Service AP Authentication FAILED: {ap_rep.get('message')}")
        sys.exit(1)

    # Verify Mutual Authentication from Service
    dec_service_reply = json.loads(decrypt_aead(k_c_s, ap_rep["enc_part"]).decode("utf-8"))
    if dec_service_reply.get("timestamp_confirm") != ts2 + 1:
        print("[✗] MUTUAL AUTHENTICATION FAILED: Timestamp confirmation incorrect!")
        sys.exit(1)

    print("[✓] MUTUAL AUTHENTICATION CONFIRMED by Service!")
    print(f"[✓] Service Response: {dec_service_reply.get('result')}")
    print("[✓] Full Kerberos Exchange Completed Successfully.")


if __name__ == "__main__":
    main()
