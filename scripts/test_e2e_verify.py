#!/usr/bin/env python3
"""
HashGuard-ID End-to-End Verification Telemetry & Verification Harness
Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B
"""

import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.request

GATEWAY_URL = "http://127.0.0.1:8080"
HKDF_CONTEXT_INFO = b"HashGuard-v1-Context-Enclosure-Key"

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hkdf_extract_and_expand(ikm: bytes, info: bytes, length: int = 32, salt: bytes = None) -> bytes:
    """
    RFC 5869 compliant HKDF using HMAC-SHA256.
    Extracts PRK from IKM, then expands to derived key material.
    """
    if salt is None:
        salt = b"\x00" * 32  # HashLen zeros for SHA-256
    
    # Step 1: HKDF-Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    
    # Step 2: HKDF-Expand (Single block iteration for length <= 32)
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:length]

def solve_hashcash(ticket_hmac_bytes: bytes, difficulty: int) -> int:
    """Solves Adaptive Hashcash with bounded leading zero prefix."""
    mask = 0 if difficulty == 0 else ((1 << 32) - 1) ^ ((1 << (32 - difficulty)) - 1)
    nonce = 0
    while True:
        candidate = sha256(ticket_hmac_bytes + struct.pack(">Q", nonce))
        prefix = struct.unpack(">I", candidate[:4])[0]
        if (prefix & mask) == 0:
            return nonce
        nonce += 1

def main():
    print("[*] 1. Initializing Lamport Chain (RFC 2289) with 256-bit CSPRNG seed...")
    seed = os.urandom(32)
    chain = [seed]
    N = 100
    for i in range(N):
        chain.append(sha256(chain[-1]))
    
    terminal_anchor = chain[-1]
    print(f"    Terminal Anchor H^100(S): {terminal_anchor.hex()}")

    # 1. Ghi danh Terminal Anchor vào Gateway
    print("[*] 2. Enrolling Terminal Anchor to Edge Gateway...")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/v1/enroll",
        data=json.dumps({"terminal_anchor": terminal_anchor.hex(), "total_steps": N}).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        enroll_res = json.loads(resp.read().decode())
        print(f"    Enroll Response: {enroll_res}")

    # 2. Yêu cầu Challenge Ticket phi trạng thái
    print("[*] 3. Requesting Stateless Challenge Ticket...")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/v1/challenge",
        data=json.dumps({"client_ip": "127.0.0.1", "velocity_rpm": 1}).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        chal_res = json.loads(resp.read().decode())
        print(f"    Challenge Response: {chal_res}")

    ticket_hmac = bytes.fromhex(chal_res["ticket_hmac"])
    difficulty = chal_res["difficulty_bits"]

    # 3. Giải Proof-of-Work (Adaptive Hashcash)
    print(f"[*] 4. Solving Adaptive Hashcash (D = {difficulty} bits)...")
    t0 = time.perf_counter()
    pow_nonce = solve_hashcash(ticket_hmac, difficulty)
    solve_duration = (time.perf_counter() - t0) * 1000
    print(f"    Nonce found: {pow_nonce} in {solve_duration:.3f} ms (SLA Budget: < 20 ms)")

    # 4. Ký ngữ cảnh giao dịch (RFC 5869 HKDF + RFC 8785 JCS + RFC 2104 HMAC)
    step_index = N - 1  # Bước 99
    token = chain[step_index] # H^99(S)

    tx_payload = {
        "amount": 500000,
        "currency": "VND",
        "nonce": "tx-deterministic-nonce-001",
        "recipient": "merchant_safe_store",
        "sender": "alice_vault",
        "timestamp": chal_res["timestamp"],
        "tx_id": "tx-880291"
    }
    canonical_bytes = json.dumps(tx_payload, separators=(',', ':'), sort_keys=True).encode()
    payload_digest = sha256(canonical_bytes)

    # Dẫn xuất khóa ngữ cảnh chuẩn RFC 5869 (HKDF-Extract + HKDF-Expand)
    signing_key = hkdf_extract_and_expand(ikm=token, info=HKDF_CONTEXT_INFO, length=32)
    signature = hmac.new(signing_key, payload_digest, hashlib.sha256).digest()

    # 5. Đóng gói phong bì và gửi xác thực tới /v1/verify
    print("[*] 5. Submitting Sealed Envelope to /v1/verify...")
    verify_envelope = {
        "client_ip": chal_res["client_ip"],
        "timestamp": chal_res["timestamp"],
        "difficulty_bits": chal_res["difficulty_bits"],
        "ticket_hmac": chal_res["ticket_hmac"],
        "pow_nonce": pow_nonce,
        "step_index": step_index,
        "token": token.hex(),
        "signature": signature.hex(),
        "canonical_payload": tx_payload
    }

    req = urllib.request.Request(
        f"{GATEWAY_URL}/v1/verify",
        data=json.dumps(verify_envelope).encode(),
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req) as resp:
            verify_res = json.loads(resp.read().decode())
            print("\n=======================================================")
            print("PROTOCOL VERIFICATION & ATOMIC CAS EXECUTION SUCCESS")
            print("=======================================================")
            print(json.dumps(verify_res, indent=2))
            print("=======================================================")
            print(f"[+] Server Core Verification Latency: {verify_res['server_execution_micros']:.2f} µs")
            print("[+] Zero-Telecom Guarantee: 0 SMS dispatched, Carrier Fee = $0.00")
    except urllib.error.HTTPError as err:
        error_msg = err.read().decode("utf-8", errors="replace")
        print(f"\n[-] Gateway Rejected Request [HTTP {err.code}]: {error_msg}")

if __name__ == "__main__":
    main()