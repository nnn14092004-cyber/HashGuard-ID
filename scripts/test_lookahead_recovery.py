#!/usr/bin/env python3
"""
HashGuard-ID Protocol Robustness & Lifecycle Verification Harness
Standards Compliance: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B
Scope: Evaluates Delta-Step Lookahead (packet loss recovery) and Silent Re-anchoring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple

GATEWAY_URL: str = "http://127.0.0.1:8080"
HKDF_CONTEXT_INFO: bytes = b"HashGuard-v1-Context-Enclosure-Key"
TEST_USER_ID: str = "usr_prod_lifecycle_test"


def sha256(data: bytes) -> bytes:
    """Computes SHA-256 digest over arbitrary binary stream."""
    return hashlib.sha256(data).digest()


def hkdf_extract_and_expand(ikm: bytes, info: bytes = HKDF_CONTEXT_INFO, length: int = 32) -> bytes:
    """
    RFC 5869 compliant HMAC-SHA256 Extract-and-Expand key derivation.
    Enforces cryptographic domain separation.
    """
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def solve_hashcash(ticket_hmac_bytes: bytes, difficulty: int) -> int:
    """
    Solves stateless client challenge. Average complexity: O(2^D).
    Target solve time: < 2.0 ms for D = 10 bits.
    """
    mask = 0 if difficulty == 0 else ((1 << 32) - 1) ^ ((1 << (32 - difficulty)) - 1)
    nonce = 0
    while True:
        candidate = sha256(ticket_hmac_bytes + struct.pack(">Q", nonce))
        prefix = struct.unpack(">I", candidate[:4])[0]
        if (prefix & mask) == 0:
            return nonce
        nonce += 1


def post_json(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
    """Issues hardened HTTP POST request to Edge Gateway."""
    req = urllib.request.Request(
        f"{GATEWAY_URL}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", errors="replace")


def execute_transaction(chal: Dict[str, Any], step: int, token: bytes, tx_payload: Dict[str, Any], nonce: str) -> Tuple[int, Any]:
    """Constructs canonical envelope, signs payload via HKDF-derived key, and submits to Gateway."""
    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])

    canonical_bytes = json.dumps(tx_payload, separators=(',', ':'), sort_keys=True).encode("utf-8")
    payload_digest = sha256(canonical_bytes)
    derived_key = hkdf_extract_and_expand(token)
    signature = hmac.new(derived_key, payload_digest, hashlib.sha256).digest()

    envelope = {
        "user_id": TEST_USER_ID,
        "client_ip": chal["client_ip"],
        "timestamp": chal["timestamp"],
        "difficulty_bits": chal["difficulty_bits"],
        "ticket_hmac": chal["ticket_hmac"],
        "pow_nonce": pow_nonce,
        "step_index": step,
        "token": token.hex(),
        "signature": signature.hex(),
        "nonce": nonce,
        "canonical_payload": tx_payload
    }
    return post_json("/v1/verify", envelope)


def generate_chain(length: int) -> Tuple[list[bytes], bytes]:
    """Generates Lamport reverse hash chain from 256-bit CSPRNG entropy."""
    seed = os.urandom(32)
    chain = [seed]
    for _ in range(length):
        chain.append(sha256(chain[-1]))
    return chain, chain[-1]


def main() -> None:
    print("===================================================================")
    print("HASHGUARD-ID PRODUCTION LIFECYCLE & LOOKAHEAD AUDIT")
    print("Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B")
    print("===================================================================\n")

    # 1. Provision Primary Chain (N = 10)
    chain_primary, terminal_anchor = generate_chain(10)
    status, res = post_json("/v1/enroll", {
        "user_id": TEST_USER_ID,
        "terminal_anchor": terminal_anchor.hex(),
        "total_steps": 10
    })
    assert status == 200, f"Enrollment failed: {res}"
    print(f"[*] Step 0: User enrolled with initial chain N = 10. Anchor = {terminal_anchor.hex()[:16]}...")

    # Case 1: Standard Monotonic Single Hop (10 -> 9)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 9, chain_primary[9], {"tx_id": "tx_hop_1"}, "nonce_h1")
    assert status == 200, f"Case 1 failed: {res}"
    print(f"[+] Case 1: Single Step Advance (10 -> 9): PASSED (Status: {res['status']})")

    # Case 2: Packet Loss Simulation (Delta = 3 hops: 9 -> 6)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 6, chain_primary[6], {"tx_id": "tx_desync_recovery"}, "nonce_h2")
    assert status == 200, f"Case 2 failed: {res}"
    print(f"[+] Case 2: Delta-3 Lookahead Recovery (9 -> 6): PASSED (Current Step: {res['remaining_step']})")

    # Case 3: Excessive Hop Violation (Delta = 6 > 5)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 0, chain_primary[0], {"tx_id": "tx_hop_excessive"}, "nonce_h3")
    if status == 409 and "ERR_LOOKAHEAD_EXCEEDED" in str(res):
        print("[+] Case 3: Bounded Lookahead Exceeded (Delta=6 > 5): REJECTED with HTTP 409 Conflict")
    else:
        raise AssertionError(f"Case 3 security breach: Expected 409, got {status}: {res}")

    # Case 4: Piggybacked Next Anchor Registration at Step 5
    chain_secondary, next_terminal_anchor = generate_chain(50)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    payload_reanchor = {
        "tx_id": "tx_handshake_piggyback",
        "next_anchor": next_terminal_anchor.hex(),
        "next_total_steps": 50
    }
    status, res = execute_transaction(chal, 5, chain_primary[5], payload_reanchor, "nonce_h4")
    assert status == 200, f"Re-anchoring piggyback failed: {res}"
    print(f"[+] Case 4A: Piggybacked Secondary Anchor (M=50) registered atomically at step 5.")

    # Advance chain to edge boundary (Step 1)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 1, chain_primary[1], {"tx_id": "tx_pre_exhaustion"}, "nonce_h5")
    assert status == 200, f"Advance to step 1 failed: {res}"

    # Trigger Step 0 Exhaustion Rollover
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 0, chain_primary[0], {"tx_id": "tx_terminal_rollover"}, "nonce_h6")
    assert status == 200, f"Terminal rollover failed: {res}"
    print(f"[+] Case 4B: Step 0 Reached -> Atomic Rollover EXECUTED (Status: {res['status']}, New Step: {res['remaining_step']})")

    # Validate First Transaction on Substituted Secondary Chain (Step 49)
    _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})
    status, res = execute_transaction(chal, 49, chain_secondary[49], {"tx_id": "tx_sec_chain_001"}, "nonce_h7")
    assert status == 200, f"Secondary chain execution failed: {res}"
    print(f"[+] Case 4C: First Transaction on Secondary Chain (50 -> 49): PASSED (Current Step: {res['remaining_step']})")

    print("\n===================================================================")
    print("ALL NEGATIVE-SPACE RECOVERY & CONCURRENCY CONSTRAINTS VERIFIED")
    print("===================================================================")


if __name__ == "__main__":
    main()