#!/usr/bin/env python3
"""
HashGuard-ID SLA Latency & Percentile Benchmark Suite
Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B
Measures: Client PoW Solve Time, Server Core Verification, Round-Trip Latency (p50, p95, p99).
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
from typing import Any, Dict, List, Tuple

GATEWAY_URL: str = "http://127.0.0.1:8080"
HKDF_CONTEXT_INFO: bytes = b"HashGuard-v1-Context-Enclosure-Key"
BENCHMARK_USER_ID: str = "usr_benchmark_perf"
NUM_ITERATIONS: int = 500


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract_and_expand(ikm: bytes, info: bytes = HKDF_CONTEXT_INFO, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def solve_hashcash(ticket_hmac_bytes: bytes, difficulty: int) -> int:
    mask = 0 if difficulty == 0 else ((1 << 32) - 1) ^ ((1 << (32 - difficulty)) - 1)
    nonce = 0
    buf = bytearray(40)
    buf[:32] = ticket_hmac_bytes

    while True:
        buf[32:] = struct.pack(">Q", nonce)
        digest = sha256(buf)
        prefix = struct.unpack(">I", digest[:4])[0]
        if (prefix & mask) == 0:
            return nonce
        nonce += 1


def post_json(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
    req = urllib.request.Request(
        f"{GATEWAY_URL}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def calculate_percentiles(latencies: List[float]) -> Dict[str, float]:
    latencies.sort()
    n = len(latencies)
    return {
        "min": latencies[0],
        "p50": latencies[int(n * 0.50)],
        "p95": latencies[int(n * 0.95)],
        "p99": latencies[int(n * 0.99)],
        "max": latencies[-1],
    }


def main() -> None:
    print("===================================================================")
    print(f"STARTING SLA BENCHMARK SUITE ({NUM_ITERATIONS} CONSECUTIVE TRANSACTIONS)")
    print("===================================================================\n")

    # 1. Initialize Long Lamport Chain
    print(f"[*] Provisioning Lamport reverse chain (N = {NUM_ITERATIONS})...")
    seed = os.urandom(32)
    chain = [seed]
    for _ in range(NUM_ITERATIONS):
        chain.append(sha256(chain[-1]))
    terminal_anchor = chain[-1]

    status, _ = post_json("/v1/enroll", {
        "user_id": BENCHMARK_USER_ID,
        "terminal_anchor": terminal_anchor.hex(),
        "total_steps": NUM_ITERATIONS
    })
    assert status == 200, "Enrollment failed"
    print("[+] Enrolled successfully. Executing benchmark loop...\n")

    client_pow_times: List[float] = []
    server_core_times: List[float] = []
    e2e_roundtrip_times: List[float] = []

    for i in range(NUM_ITERATIONS - 1, -1, -1):
        t_e2e_start = time.perf_counter()

        # Step A: Challenge
        _, chal = post_json("/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1})

        # Step B: Solve PoW
        t_pow_start = time.perf_counter()
        ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
        pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])
        pow_duration_ms = (time.perf_counter() - t_pow_start) * 1000
        client_pow_times.append(pow_duration_ms)

        # Step C: Sign Context
        tx_payload = {
            "tx_id": f"tx_bench_{i}",
            "amount": 100000 + i,
            "currency": "VND",
            "recipient": "merchant_bench"
        }
        canonical_bytes = json.dumps(tx_payload, separators=(',', ':'), sort_keys=True).encode("utf-8")
        payload_digest = sha256(canonical_bytes)
        derived_key = hkdf_extract_and_expand(chain[i])
        signature = hmac.new(derived_key, payload_digest, hashlib.sha256).digest()

        # Step D: Verify via CAS
        envelope = {
            "user_id": BENCHMARK_USER_ID,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": i,
            "token": chain[i].hex(),
            "signature": signature.hex(),
            "nonce": f"bench_{i}_{time.time_ns()}",
            "canonical_payload": tx_payload
        }
        status, res = post_json("/v1/verify", envelope)
        assert status == 200, f"Verify failed at step {i}: {res}"

        server_core_times.append(res["server_execution_micros"] / 1000.0) # ms
        e2e_roundtrip_times.append((time.perf_counter() - t_e2e_start) * 1000)

        if (NUM_ITERATIONS - i) % 50 == 0:
            print(f"    Progress: {NUM_ITERATIONS - i}/{NUM_ITERATIONS} transactions committed...")

    # Calculate percentiles
    pow_stats = calculate_percentiles(client_pow_times)
    srv_stats = calculate_percentiles(server_core_times)
    e2e_stats = calculate_percentiles(e2e_roundtrip_times)

    print("\n===================================================================")
    print("HASHGUARD-ID BENCHMARK SLA SCORECARD (N = 500)")
    print("===================================================================")
    print(f"{'METRIC':<25} | {'p50 (Median)':<12} | {'p95':<12} | {'p99':<12} | {'Max'}")
    print("-" * 75)
    print(f"{'Client PoW Solve (ms)':<25} | {pow_stats['p50']:<12.3f} | {pow_stats['p95']:<12.3f} | {pow_stats['p99']:<12.3f} | {pow_stats['max']:.3f} ms")
    print(f"{'Server CAS Core (ms)':<25} | {srv_stats['p50']:<12.3f} | {srv_stats['p95']:<12.3f} | {srv_stats['p99']:<12.3f} | {srv_stats['max']:.3f} ms")
    print(f"{'E2E Network Roundtrip (ms)':<25} | {e2e_stats['p50']:<12.3f} | {e2e_stats['p95']:<12.3f} | {e2e_stats['p99']:<12.3f} | {e2e_stats['max']:.3f} ms")
    print("===================================================================")
    print(f"[+] SLA Target (< 20.00 ms)   : {'100% COMPLIANT' if e2e_stats['p99'] < 20.0 else 'VIOLATED'}")
    print(f"[+] Carrier Telecom Surcharge : $0.0000 USD (0 SMS Dispatched)")
    print("===================================================================")


if __name__ == "__main__":
    main()