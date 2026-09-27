#!/usr/bin/env python3
import concurrent.futures
import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.request

GATEWAY_URL = "http://127.0.0.1:8080"
HKDF_INFO = b"HashGuard-v1-Context-Enclosure-Key"
USER_ID = "usr_concurrent_test"

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hkdf_expand(ikm: bytes, info: bytes = HKDF_INFO, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]

def solve_hashcash(ticket_hmac_bytes: bytes, difficulty: int) -> int:
    mask = 0 if difficulty == 0 else ((1 << 32) - 1) ^ ((1 << (32 - difficulty)) - 1)
    nonce = 0
    while True:
        candidate = sha256(ticket_hmac_bytes + struct.pack(">Q", nonce))
        prefix = struct.unpack(">I", candidate[:4])[0]
        if (prefix & mask) == 0:
            return nonce
        nonce += 1

def send_request(endpoint: str, payload: dict) -> tuple[int, dict | str]:
    req = urllib.request.Request(
        f"{GATEWAY_URL}{endpoint}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", errors="replace")

def execute_worker(payload: dict) -> int:
    status, _ = send_request("/v1/verify", payload)
    return status

def main():
    print("[*] 1. Initializing Lamport Chain (N = 100) for user:", USER_ID)
    seed = os.urandom(32)
    chain = [seed]
    for _ in range(100):
        chain.append(sha256(chain[-1]))
    terminal_anchor = chain[-1]

    # 1. Enroll user to Redis State via Gateway
    status, res = send_request("/v1/enroll", {
        "user_id": USER_ID,
        "terminal_anchor": terminal_anchor.hex(),
        "total_steps": 100
    })
    assert status == 200, f"Enroll failed: {res}"
    print(f"[+] User enrolled successfully. Step: 100, Terminal Anchor: {terminal_anchor.hex()[:16]}...")

    # 2. Get Challenge Ticket
    status, chal = send_request("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    assert status == 200

    # 3. Solve PoW
    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])

    # 4. Prepare Step 99 Token and Context
    step_99 = 99
    token_99 = chain[step_99]
    tx_payload = {"tx_id": "tx_race_001", "amount": 1000000, "user": USER_ID}
    canonical_bytes = json.dumps(tx_payload, separators=(',', ':'), sort_keys=True).encode()
    payload_digest = sha256(canonical_bytes)
    derived_key = hkdf_expand(token_99)
    signature = hmac.new(derived_key, payload_digest, hashlib.sha256).digest()

    base_envelope = {
        "user_id": USER_ID,
        "client_ip": chal["client_ip"],
        "timestamp": chal["timestamp"],
        "difficulty_bits": chal["difficulty_bits"],
        "ticket_hmac": chal["ticket_hmac"],
        "pow_nonce": pow_nonce,
        "step_index": step_99,
        "token": token_99.hex(),
        "signature": signature.hex(),
        "nonce": "unique_race_nonce_001",
        "canonical_payload": tx_payload
    }

    # 5. Launch 50 concurrent racing threads
    num_threads = 50
    print(f"[*] 2. Firing {num_threads} concurrent racing requests to /v1/verify...")

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(execute_worker, base_envelope) for _ in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    total_time = (time.perf_counter() - t_start) * 1000

    success_count = results.count(200)
    conflict_count = results.count(409)

    print("\n=======================================================")
    print("CONCURRENCY & TOCTOU VERIFICATION TELEMETRY")
    print("=======================================================")
    print(f"[+] Total Racing Requests : {num_threads}")
    print(f"[+] Execution Wall Time   : {total_time:.2f} ms")
    print(f"[+] HTTP 200 (COMMITTED)  : {success_count}")
    print(f"[+] HTTP 409 (REJECTED)   : {conflict_count}")
    print("=======================================================")

    assert success_count == 1, f"CRITICAL: TOCTOU exploit detected! Expected 1 commit, got {success_count}"
    assert conflict_count == num_threads - 1, f"Unexpected rejection count: {conflict_count}"
    print("[+] INVARIANT VERIFIED: 100% TOCTOU Immunity via Redis Lua CAS.")

if __name__ == "__main__":
    main()