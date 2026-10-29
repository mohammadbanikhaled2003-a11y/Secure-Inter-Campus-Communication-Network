#!/usr/bin/env python3
"""
scpcrypt.py - Unified Cryptographic Message Tool
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Implements:
  - Digital Signatures (Ed25519 / ECDSA)
  - Message Authentication Codes (HMAC-SHA256)
  - Authenticated Encryption with Associated Data (AES-256-GCM / ChaCha20-Poly1305)
  - Key Agreement (ECDH / X25519 with HKDF-SHA256)
  - Strict 1-byte tamper detection
"""

import sys
import os
import argparse
import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, InvalidTag


def cmd_mac(args):
    """Compute HMAC-SHA256 over message with given hex key or file."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
            if len(key) == 64 and all(c in b'0123456789abcdefABCDEF' for c in key):
                key = bytes.fromhex(key.decode('ascii'))
    else:
        raise ValueError("Must provide --key-hex or --key-file")

    with open(args.in_file, "rb") as f:
        data = f.read()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    tag = h.finalize()

    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(tag)
    else:
        print(tag.hex())


def cmd_verify_mac(args):
    """Verify HMAC-SHA256 tag over message. Returns exit code 0 on success, 1 on tamper."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
            if len(key) == 64 and all(c in b'0123456789abcdefABCDEF' for c in key):
                key = bytes.fromhex(key.decode('ascii'))
    else:
        raise ValueError("Must provide --key-hex or --key-file")

    with open(args.in_file, "rb") as f:
        data = f.read()

    if args.tag_hex:
        expected_tag = bytes.fromhex(args.tag_hex)
    elif args.tag_file:
        with open(args.tag_file, "rb") as f:
            expected_tag = f.read().strip()
            if len(expected_tag) == 64:
                try:
                    expected_tag = bytes.fromhex(expected_tag.decode('ascii'))
                except ValueError:
                    pass
    else:
        raise ValueError("Must provide --tag-hex or --tag-file")

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(expected_tag)
        print("[✓] HMAC-SHA256 Verification: SUCCESS (Integrity Verified)")
        return 0
    except InvalidSignature:
        print("[✗] HMAC-SHA256 Verification: FAILED (Tampering Detected!)", file=sys.stderr)
        sys.exit(1)


def cmd_sign(args):
    """Generate Ed25519 digital signature."""
    with open(args.key_file, "rb") as f:
        key_data = f.read()
    
    # Support raw 32-byte seed or PEM
    if key_data.startswith(b"-----BEGIN"):
        priv_key = serialization.load_pem_private_key(key_data, password=None)
    elif len(key_data) == 32:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data)
    elif len(key_data) == 64:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_data.decode('ascii')))
    else:
        raise ValueError("Unsupported private key format for signing")

    with open(args.in_file, "rb") as f:
        data = f.read()

    sig = priv_key.sign(data)
    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(sig)
    else:
        print(sig.hex())


def cmd_verify_sig(args):
    """Verify Ed25519 digital signature."""
    with open(args.pub_file, "rb") as f:
        pub_data = f.read()

    if pub_data.startswith(b"-----BEGIN"):
        pub_key = serialization.load_pem_public_key(pub_data)
    elif len(pub_data) == 32:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_data)
    elif len(pub_data) == 64:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_data.decode('ascii')))
    else:
        raise ValueError("Unsupported public key format for verification")

    with open(args.in_file, "rb") as f:
        data = f.read()

    if args.sig_hex:
        sig = bytes.fromhex(args.sig_hex)
    elif args.sig_file:
        with open(args.sig_file, "rb") as f:
            sig = f.read()
            if len(sig) == 128:
                try:
                    sig = bytes.fromhex(sig.decode('ascii'))
                except ValueError:
                    pass
    else:
        raise ValueError("Must provide --sig-hex or --sig-file")

    try:
        pub_key.verify(sig, data)
        print("[✓] Digital Signature Verification: SUCCESS")
        return 0
    except InvalidSignature:
        print("[✗] Digital Signature Verification: FAILED (Forged or Modified!)", file=sys.stderr)
        sys.exit(1)


def cmd_encrypt(args):
    """AEAD Authenticated Encryption (AES-GCM or ChaCha20-Poly1305)."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
            if len(key) == 64:
                key = bytes.fromhex(key.decode('ascii'))
    else:
        key = secrets.token_bytes(32)
        print(f"[i] Generated random 256-bit key: {key.hex()}")

    with open(args.in_file, "rb") as f:
        data = f.read()

    ad = args.ad.encode("utf-8") if args.ad else b""

    if args.cipher.lower() == "chacha20":
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, data, ad)
    else:
        # Default: AES-256-GCM
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key)
        ct = cipher.encrypt(nonce, data, ad)

    # Format: [12 bytes nonce] + [ciphertext + 16 bytes tag]
    output_payload = nonce + ct

    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(output_payload)
        print(f"[✓] Encrypted successfully to {args.out_file}")
    else:
        print(output_payload.hex())


def cmd_decrypt(args):
    """AEAD Decryption with tamper rejection."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
            if len(key) == 64:
                key = bytes.fromhex(key.decode('ascii'))
    else:
        raise ValueError("Must provide --key-hex or --key-file")

    with open(args.in_file, "rb") as f:
        raw_payload = f.read()

    if len(raw_payload) < 28:
        print("[✗] Error: Ciphertext is too short to contain nonce and tag.", file=sys.stderr)
        sys.exit(1)

    nonce = raw_payload[:12]
    ct = raw_payload[12:]
    ad = args.ad.encode("utf-8") if args.ad else b""

    try:
        if args.cipher.lower() == "chacha20":
            cipher = ChaCha20Poly1305(key)
            pt = cipher.decrypt(nonce, ct, ad)
        else:
            cipher = AESGCM(key)
            pt = cipher.decrypt(nonce, ct, ad)

        if args.out_file:
            with open(args.out_file, "wb") as f:
                f.write(pt)
            print(f"[✓] Decrypted successfully to {args.out_file}")
        else:
            sys.stdout.buffer.write(pt)
        return 0
    except InvalidTag:
        print("[✗] AEAD Decryption FAILED: Integrity tag mismatch! (Tampering Detected)", file=sys.stderr)
        sys.exit(1)


def cmd_ecdh(args):
    """Key Agreement using X25519 with HKDF-SHA256 key derivation."""
    if args.generate:
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if args.priv_out:
            with open(args.priv_out, "wb") as f:
                f.write(priv_bytes)
        if args.pub_out:
            with open(args.pub_out, "wb") as f:
                f.write(pub_bytes)
        print("[✓] X25519 Key pair generated successfully.")
        return

    if not args.my_priv or not args.peer_pub:
        raise ValueError("Must specify --my-priv and --peer-pub to compute shared secret")

    with open(args.my_priv, "rb") as f:
        my_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(args.peer_pub, "rb") as f:
        peer_pub = serialization.load_pem_public_key(f.read())

    raw_shared = my_priv.exchange(peer_pub)

    # Derive hardened 256-bit symmetric session key using HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=args.info.encode("utf-8") if args.info else b"AABU-SCP-ECDH-V1",
        info=b"inter-campus-session-key",
    ).derive(raw_shared)

    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(derived_key)
        print(f"[✓] Derived session key written to {args.out_file}")
    else:
        print(derived_key.hex())


def main():
    parser = argparse.ArgumentParser(description="AABU Cryptographic Message Tool (scpcrypt.py)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # MAC
    p_mac = subparsers.add_parser("mac", help="Compute HMAC-SHA256")
    p_mac.add_argument("--key-hex", help="Hex encoded key")
    p_mac.add_argument("--key-file", help="File containing key")
    p_mac.add_argument("-i", "--in-file", required=True, help="Input message file")
    p_mac.add_argument("-o", "--out-file", help="Output tag file")

    p_vmac = subparsers.add_parser("verify-mac", help="Verify HMAC-SHA256")
    p_vmac.add_argument("--key-hex", help="Hex encoded key")
    p_vmac.add_argument("--key-file", help="File containing key")
    p_vmac.add_argument("-i", "--in-file", required=True, help="Input message file")
    p_vmac.add_argument("--tag-hex", help="Hex encoded tag")
    p_vmac.add_argument("--tag-file", help="File containing tag")

    # SIGN
    p_sign = subparsers.add_parser("sign", help="Digital signature (Ed25519)")
    p_sign.add_argument("--key-file", required=True, help="Ed25519 private key file")
    p_sign.add_argument("-i", "--in-file", required=True, help="Input file to sign")
    p_sign.add_argument("-o", "--out-file", help="Output signature file")

    p_vsig = subparsers.add_parser("verify", help="Verify digital signature")
    p_vsig.add_argument("--pub-file", required=True, help="Ed25519 public key file")
    p_vsig.add_argument("-i", "--in-file", required=True, help="Original message file")
    p_vsig.add_argument("--sig-hex", help="Hex encoded signature")
    p_vsig.add_argument("--sig-file", help="Signature file")

    # ENCRYPT / DECRYPT
    p_enc = subparsers.add_parser("encrypt", help="AEAD encryption (AES-GCM / ChaCha20)")
    p_enc.add_argument("--cipher", default="aes-gcm", choices=["aes-gcm", "chacha20"])
    p_enc.add_argument("--key-hex", help="Hex encoded key (256-bit)")
    p_enc.add_argument("--key-file", help="File containing key")
    p_enc.add_argument("--ad", help="Associated authenticated data (plaintext)")
    p_enc.add_argument("-i", "--in-file", required=True, help="Plaintext input file")
    p_enc.add_argument("-o", "--out-file", help="Ciphertext output file")

    p_dec = subparsers.add_parser("decrypt", help="AEAD decryption with integrity check")
    p_dec.add_argument("--cipher", default="aes-gcm", choices=["aes-gcm", "chacha20"])
    p_dec.add_argument("--key-hex", help="Hex encoded key")
    p_dec.add_argument("--key-file", help="File containing key")
    p_dec.add_argument("--ad", help="Associated authenticated data (plaintext)")
    p_dec.add_argument("-i", "--in-file", required=True, help="Ciphertext input file")
    p_dec.add_argument("-o", "--out-file", help="Plaintext output file")

    # ECDH
    p_ecdh = subparsers.add_parser("ecdh", help="ECDH key agreement (X25519 + HKDF)")
    p_ecdh.add_argument("--generate", action="store_true", help="Generate key pair")
    p_ecdh.add_argument("--priv-out", help="Private key output file")
    p_ecdh.add_argument("--pub-out", help="Public key output file")
    p_ecdh.add_argument("--my-priv", help="Local private key file")
    p_ecdh.add_argument("--peer-pub", help="Remote public key file")
    p_ecdh.add_argument("--info", help="HKDF context info string")
    p_ecdh.add_argument("-o", "--out-file", help="Output derived session key file")

    args = parser.parse_args()

    if args.command == "mac":
        cmd_mac(args)
    elif args.command == "verify-mac":
        cmd_verify_mac(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify_sig(args)
    elif args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    elif args.command == "ecdh":
        cmd_ecdh(args)


if __name__ == "__main__":
    main()
