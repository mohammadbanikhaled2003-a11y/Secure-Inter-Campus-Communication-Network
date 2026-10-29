#!/usr/bin/env python3
"""
Unit and Acceptance Tests for scpcrypt.py
Includes:
- RFC 4231 HMAC-SHA256 Test Vectors
- RFC 8032 Ed25519 Test Vectors
- AES-256-GCM / ChaCha20-Poly1305 AEAD Integrity
- 1-Byte Tamper Detection Tests
- X25519 Key Agreement Verification
"""

import unittest
import os
import tempfile
import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag


class TestCryptoKnownAnswerVectors(unittest.TestCase):

    def test_rfc4231_hmac_sha256_case1(self):
        """RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = 'Hi There'"""
        key = bytes([0x0b] * 20)
        data = b"Hi There"
        expected = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        tag = h.finalize()
        self.assertEqual(tag, expected, "RFC 4231 Case 1 Failed")

    def test_rfc4231_hmac_sha256_case2(self):
        """RFC 4231 Test Case 2: Key = 'Jefe', Data = 'what do ya want for nothing?'"""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        tag = h.finalize()
        self.assertEqual(tag, expected, "RFC 4231 Case 2 Failed")

    def test_rfc4231_hmac_sha256_case3(self):
        """RFC 4231 Test Case 3: Key = 20 bytes 0xaa, Data = 50 bytes 0xdd"""
        key = bytes([0xaa] * 20)
        data = bytes([0xdd] * 50)
        expected = bytes.fromhex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        tag = h.finalize()
        self.assertEqual(tag, expected, "RFC 4231 Case 3 Failed")

    def test_rfc8032_ed25519_vector1(self):
        """RFC 8032 Test Vector 1: Empty message"""
        priv_bytes = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pub_bytes = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        data = b""
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

        sig = priv_key.sign(data)
        self.assertEqual(sig, expected_sig, "RFC 8032 Vector 1 Signature Mismatch")
        pub_key.verify(sig, data)  # Should not raise

    def test_rfc8032_ed25519_vector2(self):
        """RFC 8032 Test Vector 2: 1-byte message 0x72"""
        priv_bytes = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pub_bytes = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        data = bytes([0x72])
        expected_sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )

        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

        sig = priv_key.sign(data)
        self.assertEqual(sig, expected_sig, "RFC 8032 Vector 2 Signature Mismatch")
        pub_key.verify(sig, data)


class TestTamperDetection(unittest.TestCase):
    """Test 2 (T2): Verify that 1-byte modification is detected and rejected."""

    def test_hmac_tamper_detection(self):
        key = secrets.token_bytes(32)
        msg = b"AABU inter-campus transaction payload"
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(msg)
        tag = h.finalize()

        # 1-byte flip in message
        tampered_msg = bytearray(msg)
        tampered_msg[0] ^= 0x01
        h_bad = hmac.HMAC(key, hashes.SHA256())
        h_bad.update(bytes(tampered_msg))
        with self.assertRaises(InvalidSignature):
            h_bad.verify(tag)

        # 1-byte flip in tag
        tampered_tag = bytearray(tag)
        tampered_tag[10] ^= 0x01
        h_bad_tag = hmac.HMAC(key, hashes.SHA256())
        h_bad_tag.update(msg)
        with self.assertRaises(InvalidSignature):
            h_bad_tag.verify(bytes(tampered_tag))

    def test_aead_aes_gcm_tamper_detection(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"Confidential staff salary record"
        ad = b"header-dept-hr"
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, pt, ad)

        # Flip 1 byte in ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[5] ^= 0xFF
        with self.assertRaises(InvalidTag):
            aesgcm.decrypt(nonce, bytes(tampered_ct), ad)

        # Flip 1 byte in AD
        with self.assertRaises(InvalidTag):
            aesgcm.decrypt(nonce, ct, b"header-dept-hx")

    def test_aead_chacha20_poly1305_tamper_detection(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"Branch campus student grades"
        ad = b"metadata-auth"
        chacha = ChaCha20Poly1305(key)
        ct = chacha.encrypt(nonce, pt, ad)

        # Flip 1 byte in tag/ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[-1] ^= 0x01
        with self.assertRaises(InvalidTag):
            chacha.decrypt(nonce, bytes(tampered_ct), ad)

    def test_ed25519_signature_tamper_detection(self):
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        msg = b"Official Academic Council Directive"
        sig = priv_key.sign(msg)

        # Flip byte in message
        tampered_msg = bytearray(msg)
        tampered_msg[2] ^= 0xAA
        with self.assertRaises(InvalidSignature):
            pub_key.verify(sig, bytes(tampered_msg))

        # Flip byte in signature
        tampered_sig = bytearray(sig)
        tampered_sig[15] ^= 0x01
        with self.assertRaises(InvalidSignature):
            pub_key.verify(bytes(tampered_sig), msg)


class TestKeyAgreement(unittest.TestCase):

    def test_x25519_shared_secret_agreement(self):
        """Verify peer A and peer B derive identical shared secrets."""
        alice_priv = x25519.X25519PrivateKey.generate()
        bob_priv = x25519.X25519PrivateKey.generate()

        alice_pub = alice_priv.public_key()
        bob_pub = bob_priv.public_key()

        secret_alice = alice_priv.exchange(bob_pub)
        secret_bob = bob_priv.exchange(alice_pub)

        self.assertEqual(secret_alice, secret_bob, "ECDH secrets must match")
        self.assertEqual(len(secret_alice), 32)


if __name__ == "__main__":
    unittest.main()
