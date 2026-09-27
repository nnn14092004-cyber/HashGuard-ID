#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import struct
import urllib.error
import urllib.request

GATEWAY_URL = "http://127.0.0.1:8080"
HKDF_INFO = b"HashGuard-v1-Context-Enclosure-Key"

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

def get_challenge() -> dict:
    _, data = send_request("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    return data

def build_envelope(chal: dict, step: int, token: bytes, payload: dict) -> dict:
    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])
    canonical_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    payload_digest = sha256(canonical_bytes)
    derived_key = hkdf_expand(token)
    signature = hmac.new(derived_key, payload_digest, hashlib.sha256).digest()

    return {
        "client_ip": chal["client_ip"],
        "timestamp": chal["timestamp"],
        "difficulty_bits": chal["difficulty_bits"],
        "ticket_hmac": chal["ticket_hmac"],
        "pow_nonce": nonce,
        "step_index": step,
        "token": token.hex(),
        "signature": signature.hex(),
        "canonical_payload": payload
    }

def main():
    print("[*] Provisioning isolated test chain (N = 10)...")
    seed = os.urandom(32)
    chain = [seed]
    for _ in range(10):
        chain.append(sha256(chain[-1]))
    terminal_anchor = chain[-1]

    status, _ = send_request("/v1/enroll", {"terminal_anchor": terminal_anchor.hex(), "total_steps": 10})
    if status != 200:
        print(f"[-] Failed to enroll anchor: {status}")
        return

    # Commit hop 9 hop le
    chal = get_challenge()
    tx_base = {"tx_id": "tx_init_9", "amount": 100000}
    env_9 = build_envelope(chal, 9, chain[9], tx_base)
    status, _ = send_request("/v1/verify", env_9)
    if status != 200:
        print(f"[-] Failed to commit base step 9: {status}")
        return
    print("[+] State initialized: current_step = 9")

    # Vector 1: Monotonic sequence replay (ky hop le nhung step_index = 9)
    chal_v1 = get_challenge()
    env_v1 = build_envelope(chal_v1, 9, chain[9], {"tx_id": "tx_replay", "amount": 100000})
    status_v1, _ = send_request("/v1/verify", env_v1)
    if status_v1 == 409:
        print("[+] PASSED: Vector 1 (Sequence Replay) rejected with HTTP 409 Conflict")
    else:
        print(f"[-] FAILED: Vector 1 rejected with HTTP {status_v1}, expected HTTP 409")

    # Vector 2: Context tampering (sua doi payload sau khi ky HMAC)
    chal_v2 = get_challenge()
    env_v2 = build_envelope(chal_v2, 8, chain[8], {"tx_id": "tx_legit", "amount": 500000})
    env_v2["canonical_payload"]["amount"] = 50000000
    status_v2, _ = send_request("/v1/verify", env_v2)
    if status_v2 == 401:
        print("[+] PASSED: Vector 2 (Payload Tampering) rejected with HTTP 401 Unauthorized")
    else:
        print(f"[-] FAILED: Vector 2 rejected with HTTP {status_v2}, expected HTTP 401")

    # Vector 3: Preimage forgery (token sinh ngau nhien nhung ky khop payload)
    chal_v3 = get_challenge()
    fake_token = os.urandom(32)
    env_v3 = build_envelope(chal_v3, 8, fake_token, {"tx_id": "tx_forgery", "amount": 200000})
    status_v3, _ = send_request("/v1/verify", env_v3)
    if status_v3 == 401:
        print("[+] PASSED: Vector 3 (Preimage Forgery) rejected with HTTP 401 Unauthorized")
    else:
        print(f"[-] FAILED: Vector 3 rejected with HTTP {status_v3}, expected HTTP 401")

if __name__ == "__main__":
    main()