#!/usr/bin/env python3
"""
test_auth.py - Verification of Kerberos protocol components and Replay Attack
"""

import unittest
import time
import secrets
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from auth_protocols.kdc import handle_as_req, handle_tgs_req, derive_client_key, decrypt_aead
from auth_protocols.service import handle_ap_req
from attacks.replay.weak_service import handle_weak_ap_req


class TestKerberosProtocol(unittest.TestCase):

    def test_as_and_tgs_exchange(self):
        # 1. AS Exchange
        nonce1 = secrets.token_hex(16)
        as_req = {"type": "AS_REQ", "client_id": "staff01", "nonce": nonce1}
        as_rep = handle_as_req(as_req)
        self.assertEqual(as_rep["status"], "OK")

        k_c = derive_client_key("staff01", "Staff01Password2026!")
        dec_part = json.loads(decrypt_aead(k_c, as_rep["enc_part"]).decode())
        self.assertEqual(dec_part["nonce"], nonce1)
        k_c_tgs = bytes.fromhex(dec_part["session_key"])
        tgt = as_rep["tgt"]

        # 2. TGS Exchange
        nonce2 = secrets.token_hex(16)
        ts1 = int(time.time())
        nonce_iv = secrets.token_bytes(12)
        auth_c_enc = (nonce_iv + AESGCM(k_c_tgs).encrypt(nonce_iv, json.dumps({"client_id": "staff01", "timestamp": ts1}).encode(), None)).hex()

        tgs_req = {
            "type": "TGS_REQ",
            "service_id": "service_portal",
            "nonce": nonce2,
            "tgt": tgt,
            "authenticator": auth_c_enc
        }
        tgs_rep = handle_tgs_req(tgs_req)
        self.assertEqual(tgs_rep["status"], "OK")

        dec_tgs = json.loads(decrypt_aead(k_c_tgs, tgs_rep["enc_part"]).decode())
        self.assertEqual(dec_tgs["nonce"], nonce2)
        k_c_s = bytes.fromhex(dec_tgs["session_key"])
        service_ticket = tgs_rep["ticket"]

        # 3. AP Exchange
        ts2 = int(time.time())
        nonce_iv2 = secrets.token_bytes(12)
        auth_cs_enc = (nonce_iv2 + AESGCM(k_c_s).encrypt(nonce_iv2, json.dumps({"client_id": "staff01", "timestamp": ts2}).encode(), None)).hex()

        ap_req = {
            "type": "AP_REQ",
            "ticket": service_ticket,
            "authenticator": auth_cs_enc,
            "command": "GET_PORTAL_DATA"
        }

        ap_rep = handle_ap_req(ap_req)
        self.assertEqual(ap_rep["status"], "OK")
        dec_service_reply = json.loads(decrypt_aead(k_c_s, ap_rep["enc_part"]).decode())
        self.assertEqual(dec_service_reply["timestamp_confirm"], ts2 + 1)

    def test_replay_attacks_t12a_and_t12b(self):
        from auth_protocols.service import SERVICE_REPLAY_CACHE
        SERVICE_REPLAY_CACHE.clear()
        k_service = hashlib.sha256(b"PORTAL_SERVICE_SECRET_2026").digest()
        k_cs = secrets.token_bytes(32)
        ts = int(time.time())

        tgt_data = json.dumps({"client_id": "staff01", "service_id": "service_portal", "session_key": k_cs.hex(), "t_exp": ts + 3600}).encode()
        nonce = secrets.token_bytes(12)
        st_enc = (nonce + AESGCM(k_service).encrypt(nonce, tgt_data, None)).hex()

        auth_data = json.dumps({"client_id": "staff01", "timestamp": ts}).encode()
        nonce2 = secrets.token_bytes(12)
        auth_enc = (nonce2 + AESGCM(k_cs).encrypt(nonce2, auth_data, None)).hex()

        ap_packet = {"type": "AP_REQ", "ticket": st_enc, "authenticator": auth_enc, "command": "TEST"}

        # Weak service: Both requests succeed (T12a)
        r1_weak = handle_weak_ap_req(ap_packet)
        r2_weak = handle_weak_ap_req(ap_packet)
        self.assertEqual(r1_weak["status"], "OK")
        self.assertEqual(r2_weak["status"], "OK")

        # Fixed service: First succeeds, second rejected by replay cache (T12b)
        r1_fixed = handle_ap_req(ap_packet)
        r2_fixed = handle_ap_req(ap_packet)
        self.assertEqual(r1_fixed["status"], "OK")
        self.assertEqual(r2_fixed["status"], "ERROR")
        self.assertIn("Replay attack detected", r2_fixed["message"])


if __name__ == "__main__":
    unittest.main()
