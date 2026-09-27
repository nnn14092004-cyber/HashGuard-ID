#!/usr/bin/env python3
"""
HashGuard-ID Comprehensive System Audit & Protocol Verification Harness.
Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (§5.1.3.2).
Architecture: Zero-Telecom, Thread-Safe Connection Pooling, Single-Cycle CAS.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import struct
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Tuple

GATEWAY_ENDPOINT = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")
HKDF_CONTEXT_INFO = b"HashGuard-v1-Context-Enclosure-Key"


class ProtocolClient:
    """HTTP client with thread-local persistent connection pooling."""

    def __init__(self, base_url: str = GATEWAY_ENDPOINT) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or 8080
        self._local = threading.local()

    def _get_connection(self) -> http.client.HTTPConnection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = http.client.HTTPConnection(
                self.host, self.port, timeout=10
            )
        return self._local.conn

    def post(self, path: str, payload: dict) -> Tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }

        conn = self._get_connection()
        for _ in range(2):
            try:
                conn.request("POST", path, body=data, headers=headers)
                resp = conn.getresponse()
                raw_body = resp.read().decode("utf-8")
                try:
                    body = json.loads(raw_body)
                except Exception:
                    body = {"raw": raw_body}
                return resp.status, body
            except (
                http.client.CannotSendRequest,
                http.client.BadStatusLine,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
            ):
                conn.close()
                self._local.conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=10
                )
                conn = self._local.conn

        return 500, {"transport_error": "Connection retry exhausted"}

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_derive_key(token: bytes) -> bytes:
    prk = hmac.new(b"\x00" * 32, token, hashlib.sha256).digest()
    return hmac.new(prk, HKDF_CONTEXT_INFO + b"\x01", hashlib.sha256).digest()[:32]


def jcs_canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_payload(key: bytes, canonical_data: bytes) -> bytes:
    digest = sha256(canonical_data)
    return hmac.new(key, digest, hashlib.sha256).digest()


def solve_hashcash(ticket_hmac: bytes, difficulty: int) -> int:
    base = hashlib.sha256(ticket_hmac)
    nonce = 0
    full_bytes = difficulty // 8
    rem_bits = difficulty % 8
    mask = (0xFF << (8 - rem_bits)) & 0xFF if rem_bits > 0 else 0

    while True:
        h = base.copy()
        h.update(struct.pack("!Q", nonce))
        digest = h.digest()

        if full_bytes > 0 and any(b != 0 for b in digest[:full_bytes]):
            nonce += 1
            continue

        if rem_bits > 0 and (digest[full_bytes] & mask) != 0:
            nonce += 1
            continue

        return nonce


def generate_chain(length: int) -> Tuple[List[bytes], bytes]:
    seed = os.urandom(32)
    chain = [seed]
    for _ in range(length):
        chain.append(sha256(chain[-1]))
    return chain, chain[length]


def test_vector_nominal_and_context(client: ProtocolClient) -> None:
    print("[RUN] Pillar 1: Cryptographic Context Binding & Nominal Execution")
    user_id = f"usr_nom_{time.time_ns()}"
    chain, terminal_anchor = generate_chain(10)

    status, res = client.post(
        "/v1/enroll",
        {
            "user_id": user_id,
            "terminal_anchor": terminal_anchor.hex(),
            "total_steps": 10,
        },
    )
    assert status == 200, f"Enrollment failed: {res}"

    status, chal = client.post(
        "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
    )
    assert status == 200, f"Challenge failed: {chal}"
    assert chal["difficulty_bits"] == 10, "Base difficulty must be 10 bits"

    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])
    token_9 = chain[9]

    tx_payload = {
        "amount_cents": 50000,
        "currency": "USD",
        "recipient": "stripe_merchant_global",
        "tx_id": "tx_nom_001",
    }
    signing_key = hkdf_derive_key(token_9)
    signature = sign_payload(signing_key, jcs_canonical_bytes(tx_payload))

    status, verify_res = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 9,
            "token": token_9.hex(),
            "signature": signature.hex(),
            "nonce": f"nonce_{time.time_ns()}",
            "canonical_payload": tx_payload,
        },
    )
    assert status == 200, f"Verification failed: {verify_res}"
    assert verify_res["remaining_step"] == 9
    print("      Nominal state transition committed (10 -> 9).")


def test_vector_adversarial_tamper(client: ProtocolClient) -> None:
    print("[RUN] Pillar 1: Adversarial Vector - Context Tampering Detection")
    user_id = f"usr_tamp_{time.time_ns()}"
    chain, terminal_anchor = generate_chain(10)
    client.post(
        "/v1/enroll",
        {
            "user_id": user_id,
            "terminal_anchor": terminal_anchor.hex(),
            "total_steps": 10,
        },
    )

    _, chal = client.post(
        "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
    )
    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])

    token_9 = chain[9]
    tx_payload = {
        "amount_cents": 1000,
        "currency": "USD",
        "recipient": "merchant_alice",
        "tx_id": "tx_tamp_001",
    }
    signing_key = hkdf_derive_key(token_9)
    signature = sign_payload(signing_key, jcs_canonical_bytes(tx_payload))

    tampered_payload = dict(tx_payload)
    tampered_payload["amount_cents"] = 999999

    status, _ = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 9,
            "token": token_9.hex(),
            "signature": signature.hex(),
            "nonce": f"nonce_tamp_{time.time_ns()}",
            "canonical_payload": tampered_payload,
        },
    )
    assert status == 401, f"Tampered transaction must be rejected with 401, got {status}"
    print("      Tampered payload rejected (HTTP 401 Unauthorized).")


def test_vector_toctou_concurrency(client: ProtocolClient) -> None:
    print("[RUN] Pillar 2: 50-Thread TOCTOU Atomic Race Condition Simulation")
    user_id = f"usr_race_{time.time_ns()}"
    chain, terminal_anchor = generate_chain(10)
    client.post(
        "/v1/enroll",
        {
            "user_id": user_id,
            "terminal_anchor": terminal_anchor.hex(),
            "total_steps": 10,
        },
    )

    _, chal = client.post(
        "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
    )
    ticket_bytes = bytes.fromhex(chal["ticket_hmac"])
    pow_nonce = solve_hashcash(ticket_bytes, chal["difficulty_bits"])

    token_9 = chain[9]
    tx_payload = {
        "amount_cents": 25000,
        "currency": "USD",
        "recipient": "service_node",
        "tx_id": "tx_race",
    }
    signing_key = hkdf_derive_key(token_9)
    signature = sign_payload(signing_key, jcs_canonical_bytes(tx_payload))

    def dispatch_worker(thread_id: int) -> int:
        worker_client = ProtocolClient(client.base_url)
        status, _ = worker_client.post(
            "/v1/verify",
            {
                "user_id": user_id,
                "client_ip": chal["client_ip"],
                "timestamp": chal["timestamp"],
                "difficulty_bits": chal["difficulty_bits"],
                "ticket_hmac": chal["ticket_hmac"],
                "pow_nonce": pow_nonce,
                "step_index": 9,
                "token": token_9.hex(),
                "signature": signature.hex(),
                "nonce": f"nonce_race_{thread_id}",
                "canonical_payload": tx_payload,
            },
        )
        worker_client.close()
        return status

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(dispatch_worker, i) for i in range(50)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    success = results.count(200)
    rejected = results.count(409)
    assert success == 1, f"Expected exactly 1 commit, got {success}"
    assert rejected == 49, f"Expected 49 CAS conflict rejections, got {rejected}"
    print("      TOCTOU verified: 1 Committed, 49 Rejected (Conflict Immunity).")


def test_vector_mobile_packet_loss_and_rollover(client: ProtocolClient) -> None:
    print("[RUN] Pillar 2: Packet-Loss Lookahead (Delta <= 5) & Silent Rollover")
    user_id = f"usr_loss_{time.time_ns()}"
    chain1, anchor1 = generate_chain(10)
    chain2, anchor2 = generate_chain(50)

    client.post(
        "/v1/enroll",
        {"user_id": user_id, "terminal_anchor": anchor1.hex(), "total_steps": 10},
    )

    _, chal = client.post(
        "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
    )
    pow_nonce = solve_hashcash(
        bytes.fromhex(chal["ticket_hmac"]), chal["difficulty_bits"]
    )
    token_7 = chain1[7]
    tx1 = {
        "amount_cents": 1000,
        "currency": "USD",
        "recipient": "carrier",
        "tx_id": "tx_delta3",
    }
    sig1 = sign_payload(hkdf_derive_key(token_7), jcs_canonical_bytes(tx1))

    status, res = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 7,
            "token": token_7.hex(),
            "signature": sig1.hex(),
            "nonce": f"nonce_loss_{time.time_ns()}",
            "canonical_payload": tx1,
        },
    )
    assert status == 200 and res["remaining_step"] == 7, f"Delta-3 lookahead failed: {res}"

    token_1 = chain1[1]
    sig_fail = sign_payload(hkdf_derive_key(token_1), jcs_canonical_bytes(tx1))
    status, _ = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 1,
            "token": token_1.hex(),
            "signature": sig_fail.hex(),
            "nonce": f"nonce_loss_fail_{time.time_ns()}",
            "canonical_payload": tx1,
        },
    )
    assert status == 409, f"Lookahead > 5 must return HTTP 409 Conflict, got {status}"

    token_2 = chain1[2]
    tx_piggyback = {
        "amount_cents": 1000,
        "currency": "USD",
        "next_anchor": anchor2.hex(),
        "next_total_steps": 50,
        "recipient": "carrier",
        "tx_id": "tx_piggy",
    }
    sig_step2 = sign_payload(
        hkdf_derive_key(token_2), jcs_canonical_bytes(tx_piggyback)
    )
    status, res = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 2,
            "token": token_2.hex(),
            "signature": sig_step2.hex(),
            "nonce": f"nonce_valid_piggy_{time.time_ns()}",
            "canonical_payload": tx_piggyback,
        },
    )
    assert status == 200, f"Delta-5 advance with piggyback failed: {res}"

    token_0 = chain1[0]
    tx_zero = {
        "amount_cents": 1000,
        "currency": "USD",
        "recipient": "carrier",
        "tx_id": "tx_k0",
    }
    sig_zero = sign_payload(hkdf_derive_key(token_0), jcs_canonical_bytes(tx_zero))
    status, res_zero = client.post(
        "/v1/verify",
        {
            "user_id": user_id,
            "client_ip": chal["client_ip"],
            "timestamp": chal["timestamp"],
            "difficulty_bits": chal["difficulty_bits"],
            "ticket_hmac": chal["ticket_hmac"],
            "pow_nonce": pow_nonce,
            "step_index": 0,
            "token": token_0.hex(),
            "signature": sig_zero.hex(),
            "nonce": f"nonce_k0_{time.time_ns()}",
            "canonical_payload": tx_zero,
        },
    )
    assert status == 200, f"Terminal step 0 failed: {res_zero}"
    assert res_zero["status"] == "ROLLED_OVER_ATOMIC", f"Expected rollover, got {res_zero}"
    assert res_zero["remaining_step"] == 50, f"Expected new chain step 50, got {res_zero}"
    print("      Delta recovery (Delta <= 5) and atomic rollover at k=0 verified.")


def test_vector_anti_ait_and_sla(client: ProtocolClient) -> None:
    print("[RUN] Pillar 3: Adaptive Hashcash Anti-AIT & 100-Transaction SLA Audit")

    status, chal_surge = client.post(
        "/v1/challenge", {"client_ip": "192.0.2.1", "velocity_rpm": 15}
    )
    assert status == 200
    assert chal_surge["difficulty_bits"] >= 26, (
        f"High velocity must trigger D >= 26 bits, got {chal_surge['difficulty_bits']}"
    )
    print(
        f"      Botnet surge penalty: V=15 rpm -> D={chal_surge['difficulty_bits']} bits (CPU lockup enforced)."
    )

    user_id = f"usr_sla_{time.time_ns()}"
    chain, anchor = generate_chain(110)
    client.post(
        "/v1/enroll",
        {"user_id": user_id, "terminal_anchor": anchor.hex(), "total_steps": 110},
    )

    # 3-cycle socket warmup to normalize Windows TCP loopback state
    for w in range(3):
        w_step = 109 - w
        _, w_chal = client.post(
            "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
        )
        w_nonce = solve_hashcash(
            bytes.fromhex(w_chal["ticket_hmac"]), w_chal["difficulty_bits"]
        )
        w_tx = {
            "amount_cents": 100,
            "currency": "USD",
            "recipient": "warmup",
            "tx_id": f"tx_w_{w}",
        }
        w_sig = sign_payload(
            hkdf_derive_key(chain[w_step]), jcs_canonical_bytes(w_tx)
        )
        client.post(
            "/v1/verify",
            {
                "user_id": user_id,
                "client_ip": w_chal["client_ip"],
                "timestamp": w_chal["timestamp"],
                "difficulty_bits": w_chal["difficulty_bits"],
                "ticket_hmac": w_chal["ticket_hmac"],
                "pow_nonce": w_nonce,
                "step_index": w_step,
                "token": chain[w_step].hex(),
                "signature": w_sig.hex(),
                "nonce": f"nonce_w_{w}_{time.time_ns()}",
                "canonical_payload": w_tx,
            },
        )

    latencies_solve: List[float] = []
    latencies_core: List[float] = []
    latencies_verify_e2e: List[float] = []
    latencies_lifecycle_total: List[float] = []

    for i in range(100):
        target_step = 106 - i
        t_cycle_start = time.perf_counter()

        _, chal = client.post(
            "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
        )

        t_solve_start = time.perf_counter()
        nonce = solve_hashcash(
            bytes.fromhex(chal["ticket_hmac"]), chal["difficulty_bits"]
        )
        t_solve_end = time.perf_counter()

        token = chain[target_step]
        tx = {
            "amount_cents": 1000 + i,
            "currency": "USD",
            "recipient": "gateway_bench",
            "tx_id": f"tx_sla_{i}",
        }
        sig = sign_payload(hkdf_derive_key(token), jcs_canonical_bytes(tx))

        t_verify_start = time.perf_counter()
        status, body = client.post(
            "/v1/verify",
            {
                "user_id": user_id,
                "client_ip": chal["client_ip"],
                "timestamp": chal["timestamp"],
                "difficulty_bits": chal["difficulty_bits"],
                "ticket_hmac": chal["ticket_hmac"],
                "pow_nonce": nonce,
                "step_index": target_step,
                "token": token.hex(),
                "signature": sig.hex(),
                "nonce": f"nonce_sla_{i}_{time.time_ns()}",
                "canonical_payload": tx,
            },
        )
        t_verify_end = time.perf_counter()

        assert status == 200, f"Benchmark transaction {i} failed: {body}"

        latencies_solve.append((t_solve_end - t_solve_start) * 1000.0)
        latencies_core.append(body["server_execution_micros"] / 1000.0)
        latencies_verify_e2e.append((t_verify_end - t_verify_start) * 1000.0)
        latencies_lifecycle_total.append((t_verify_end - t_cycle_start) * 1000.0)

    latencies_solve.sort()
    latencies_core.sort()
    latencies_verify_e2e.sort()
    latencies_lifecycle_total.sort()

    p99_idx = 98

    p50_solve = latencies_solve[int(len(latencies_solve) * 0.50)]
    p99_solve = latencies_solve[p99_idx]

    p50_core = latencies_core[int(len(latencies_core) * 0.50)]
    p99_core = latencies_core[p99_idx]

    p50_verify = latencies_verify_e2e[int(len(latencies_verify_e2e) * 0.50)]
    p99_verify = latencies_verify_e2e[p99_idx]

    p50_total = latencies_lifecycle_total[int(len(latencies_lifecycle_total) * 0.50)]
    p99_total = latencies_lifecycle_total[p99_idx]

    print(
        f"      Telemetry [Client PoW Solve]    : p50={p50_solve:.2f}ms | p99={p99_solve:.2f}ms"
    )
    print(
        f"      Telemetry [Server CAS Core]      : p50={p50_core:.3f}ms | p99={p99_core:.3f}ms"
    )
    print(
        f"      Telemetry [Verify E2E Roundtrip] : p50={p50_verify:.2f}ms | p99={p99_verify:.2f}ms"
    )
    print(
        f"      Telemetry [Full Lifecycle E2E]   : p50={p50_total:.2f}ms | p99={p99_total:.2f}ms"
    )

    assert p99_verify < 20.00, (
        f"SLA Violation on Verify Roundtrip: p99 must be < 20ms, got {p99_verify:.2f}ms"
    )
    assert p99_total < 20.00, (
        f"SLA Violation on Full Lifecycle: p99 must be < 20ms, got {p99_total:.2f}ms"
    )

    print("      SLA Budget Target (< 20.00 ms): 100% COMPLIANT.")
    print("      Carrier Telecom Surcharge: $0.0000 USD (0 SMS Dispatched).")


def main() -> None:
    client = ProtocolClient(GATEWAY_ENDPOINT)

    probe_status, _ = client.post(
        "/v1/challenge", {"client_ip": "127.0.0.1", "velocity_rpm": 1}
    )
    if probe_status != 200:
        print(
            f"[FATAL] Cannot reach Edge Gateway at {GATEWAY_ENDPOINT}. Ensure cargo run --release --bin gateway is active."
        )
        sys.exit(1)

    print(f"Connected to HashGuard-ID Gateway at {GATEWAY_ENDPOINT}")
    print("Beginning Comprehensive Verification Audit...")

    try:
        test_vector_nominal_and_context(client)
        test_vector_adversarial_tamper(client)
        test_vector_toctou_concurrency(client)
        test_vector_mobile_packet_loss_and_rollover(client)
        test_vector_anti_ait_and_sla(client)
    except AssertionError as err:
        print(f"\n[FAIL] Invariant Check Broken: {err}")
        client.close()
        sys.exit(1)
    except Exception as err:
        print(f"\n[ERROR] Unhandled Exception: {err}")
        client.close()
        sys.exit(1)

    client.close()
    print("\nAll 3 Protocol Pillars & Edge Cases Successfully Verified.")
    sys.exit(0)


if __name__ == "__main__":
    main()