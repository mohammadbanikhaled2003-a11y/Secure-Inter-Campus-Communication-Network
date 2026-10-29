#!/usr/bin/env python3
"""
run_replay_attack.py - Replay Attack Demonstration (T12a & T12b)
Course: Secure Communication Protocols (1305301) - Al al-Bayt University
Demonstrates:
  - T12a: Replay succeeds against vulnerable weak service.
  - T12b: Replay is rejected and logged against fixed protocol.
"""

import socket
import json
import sys
import os

WEAK_PORT = 8802
FIXED_PORT = 8801


def send_packet(host: str, port: int, packet: dict) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    s.sendall(json.dumps(packet).encode("utf-8"))
    raw = s.recv(16384)
    s.close()
    return json.loads(raw.decode("utf-8"))


def main():
    packet_path = sys.argv[1] if len(sys.argv) > 1 else "replayed_packet.json"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

    if not os.path.exists(packet_path):
        print(f"[!] Error: Replay packet file '{packet_path}' does not exist.")
        sys.exit(1)

    with open(packet_path, "r") as f:
        packet = json.load(f)

    print("==========================================================")
    print(" Running Attack Verification: T12a & T12b")
    print("==========================================================")

    # 1. Test T12a: Attack against WEAK service
    print(f"[+] 1. Launching Replay Attack against Weak Service (Port {WEAK_PORT})...")
    try:
        resp_weak = send_packet(host, WEAK_PORT, packet)
        print("[*] Weak Service Response:", resp_weak)
        if resp_weak.get("status") == "OK":
            print("[✓] [T12a PASS] Replay attack succeeded against vulnerable variant as expected!")
        else:
            print("[!] [T12a Unexpected] Weak service did not accept replay.")
    except Exception as e:
        print(f"[!] Could not connect to weak service on port {WEAK_PORT}: {e}")

    # 2. Test T12b: Attack against FIXED service
    print(f"\n[+] 2. Launching Identical Replay Attack against Fixed Service (Port {FIXED_PORT})...")
    try:
        resp_fixed = send_packet(host, FIXED_PORT, packet)
        print("[*] Fixed Service Response:", resp_fixed)
        if resp_fixed.get("status") == "ERROR" and "Replay attack detected" in resp_fixed.get("message", ""):
            print("[✓] [T12b PASS] Fixed service successfully DETECTED and REJECTED the replayed packet!")
        elif resp_fixed.get("status") == "ERROR" and "expired" in resp_fixed.get("message", ""):
            print("[✓] [T12b PASS] Fixed service successfully REJECTED packet via freshness window expiration!")
        else:
            print("[✗] [T12b FAIL] Fixed service failed to reject replayed packet!")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Could not connect to fixed service on port {FIXED_PORT}: {e}")


if __name__ == "__main__":
    main()
