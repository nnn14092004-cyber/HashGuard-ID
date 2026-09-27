#!/usr/bin/env python3
"""
HashGuard-ID RFC Specification Writer
Writes RFC-HashGuard-ID-v1.0.md using measured test data (matches README's
section 3), not invented benchmark figures.
"""

from pathlib import Path

RFC_TEXT = r"""# RFC-HashGuard-ID-v1.0: Zero-Telecom Cryptographic Verification Protocol

```text
Status: Draft -- Personal project specification, not an IETF standards-track document
Author: Nam Nguyen
Compliance: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (Section 5.1.3.2)
Date: September 2026
```

## Abstract

This document specifies HashGuard-ID, a zero-telecom, low-latency cryptographic
authentication protocol built as an alternative to SMS-based One-Time Passwords
(OTP). It combines Lamport reverse hash chains (RFC 2289), deterministic context
binding (RFC 5869, RFC 2104, RFC 8785), an atomic Redis-backed Compare-And-Swap
state engine, and velocity-adaptive Proof-of-Work (Hashcash). The goal is to
address AIT/SMS pumping fraud, SIM-swapping, SS7 interception, and distributed
TOCTOU races that affect SMS OTP -- while staying within a 20ms end-to-end
latency budget. Performance numbers in Section 5 are measured, not projected;
see that section for methodology and caveats.

## 1. Introduction and Threat Model

### 1.1 SMS OTP Vulnerabilities

Public Switched Telephone Networks (PSTN) introduce structural attack vectors
when used for authentication:

1. **AIT / Toll Fraud.** Botnets automate authentication requests toward
   premium-rate ranges under an attacker's control, generating illegitimate
   termination revenue at $0.05-$0.15 USD per dispatched message.
2. **No proof-of-possession.** Plaintext OTP codes sent via SMS aren't bound
   to a channel or tied to proof of possession, making them exploitable via
   SS7/Diameter redirection and SIM-swapping.
3. **NIST deprecation.** NIST SP 800-63B Section 5.1.3.2 deprecates
   out-of-band SMS verification for sensitive transactions.

### 1.2 Protocol Invariants

* **No telecom dependency.** The protocol never dispatches PSTN packets, so
  there's no per-message carrier cost to account for.
* **Deterministic context enclosure.** Authentication tokens are
  cryptographically bound to transaction parameters; a token cannot be
  intercepted and replayed against a different transaction.
* **Atomic monotonic descent.** Reverse sequence indices decrease
  monotonically under single-cycle atomic CAS operations, which rules out
  double-spending and TOCTOU races by construction.
* **Asymmetric defense economics.** Verification on the edge gateway is
  bounded to O(1) time and memory; client-side request bursts instead trigger
  escalating Proof-of-Work cost.

## 2. Cryptographic Specification

### 2.1 Reverse Hash Chain Construction (RFC 2289)

During enrollment, the client generates a 256-bit pseudorandom seed:

```
S <- CSPRNG({0,1}^256)
```

A chain of length N is generated through recursive SHA-256 evaluation:

```
T_0 = S,  T_i = SHA-256(T_(i-1))  for i in [1, N]
```

The terminal anchor `Anchor_N = T_N = H^N(S)` is registered with the
verification gateway. Submitting preimage `T_(k-1)` authorizes step k,
verified in O(1):

```
SHA-256(T_(k-1)) =?= Anchor_k
```

Preimage resistance of SHA-256 (2^256 operations) means revealing `T_(k-1)`
leaks no information about preceding tokens `T_(k-2) .. T_0`.

### 2.2 Cryptographic Context Enclosure (RFC 8785, RFC 5869, RFC 2104)

To prevent payload substitution in transit, `T_(k-1)` is never sent as a bare
preimage:

1. **RFC 8785 canonicalization (JCS):** the transaction payload M (containing
   `amount_cents`, `currency`, `recipient`, `tx_id`) is normalized to
   deterministic bytes `C(M)`.
2. **Payload digest:** `D_M = SHA-256(C(M))`
3. **RFC 5869 HKDF derivation:**
   ```
   PRK       = HMAC-SHA256(salt=0^32, IKM=T_(k-1))
   K_context = HMAC-SHA256(PRK, "HashGuard-v1-Context-Enclosure-Key" || 0x01)
   ```
4. **RFC 2104 context signature:** `Sigma = HMAC-SHA256(K_context, D_M)`

All comparisons run in constant time via `subtle::ConstantTimeEq` to avoid
timing side-channels.

## 3. Distributed State Engine & Concurrency Control

### 3.1 Why TOCTOU matters here

In multi-node deployments, concurrent requests submitting the same token
`T_(k-1)` can trigger split-brain execution if validation and state updates
aren't atomic together. This is the failure mode Section 3.2 is built to rule
out.

### 3.2 Single-Cycle Redis Lua CAS

Verification executes inside one atomic Redis Lua script. All state keys use
the `{user:<id>}` Hash Tag to keep CRC16 slot routing consistent in Redis
Cluster:

* `KEYS[1] = {user:<id>}:anchor`
* `KEYS[2] = {user:<id>}:step`
* `KEYS[3] = {user:<id>}:nonce:<val>`
* `KEYS[4] = {user:<id>}:pending_anchor`
* `KEYS[5] = {user:<id>}:pending_step`

Execution sequence inside the atomic transaction:

1. **Nonce validation** -- rejects if `{user:<id>}:nonce:<val>` already exists
   (`ERR_NONCE_REPLAY`).
2. **Monotonicity check** -- verifies `k_claimed < k_current`
   (`ERR_SEQUENCE_VIOLATION`).
3. **Bounded lookahead matching** -- computes `delta = k_current - k_claimed`;
   rejects if `delta > 5` (`ERR_LOOKAHEAD_EXCEEDED`), otherwise matches
   against a precomputed candidate.
4. **State commit** -- updates the anchor to `T_(k-1)`, sets step to
   `k_claimed`, persists the nonce with a 300s TTL.
5. **Silent rollover** -- at step k=0, atomically activates `pending_anchor`
   and `pending_step`, returning `ROLLED_OVER_ATOMIC`.

## 4. Anti-Toll Economic Engine (Adaptive Hashcash)

### 4.1 Stateless Challenge Issuance

The edge gateway mints stateless challenge tickets without server-side memory
allocation:

```
Ticket      = <IP, t_issued, D(V)>
TicketHMAC  = HMAC-SHA256(K_gateway, IP || t_issued || D(V))
```

### 4.2 Dynamic Difficulty Scaling

Target zero-bit difficulty D(V) scales with observed request velocity V
(requests/minute):

```
D(V) = 10 bits                              if V <= 3 req/min  (legitimate client)
D(V) = min(26, 10 + ceil(0.8*(V-3)^2))       if V > 3 req/min   (suspected botnet)
```

These are the design targets, not measured hash rates:
* At D=10, expected iterations = 2^10 = 1,024.
* At D=26, expected iterations = 2^26 ~ 6.7x10^7 -- several orders of
  magnitude harder, which is the point: legitimate clients pay a near-zero
  cost, sustained abuse gets exponentially expensive.

Actual solve time depends on the client's hardware, so no fixed millisecond
figure is claimed here -- see Section 5 for what was actually measured on the
test setup.

## 5. Measured Performance

Everything in this section comes from running `scripts/test_full_system.py`
against a live local gateway (`cargo run --release --bin gateway`) on a single
Windows dev machine, over 100 transactions. This is not a production or
multi-node benchmark -- see the Roadmap in the project README for planned
load testing on more representative infrastructure.

| Metric | p50 | p99 | Design budget |
|---|---|---|---|
| Client PoW Solve (D=10) | 0.25 ms | 0.39 ms | < 5 ms |
| Server CAS Core | 0.716 ms | 1.000 ms | < 10 ms |
| Verify E2E Roundtrip | 0.94 ms | 1.33 ms | < 15 ms |
| **Full Lifecycle E2E** | **1.42 ms** | **1.81 ms** | **< 20 ms** |

All 100 transactions in this run landed inside the 20ms budget. Under forced
load (velocity pushed to 15 req/min), difficulty escalated from D=10 to D=26
bits as expected, and a 50-thread concurrent race for the same step resolved
to exactly 1 commit and 49 rejections -- confirming the CAS logic in Section
3.2 behaves as designed under contention.

No SMS was dispatched during any of these runs, so there was no carrier
surcharge to speak of -- that's a property of the design (Section 1.2), not
a cost figure being measured here.

## 6. Security Considerations

### 6.1 Replay Defense

Handled by two independent layers: sequence-step enforcement rejects
`k_claimed >= k_current` (`409 Conflict`), and ephemeral transaction nonces
are stored in Redis with a 300-second TTL.

### 6.2 Timing Side-Channels

All hash, HMAC, and token comparisons use constant-time byte comparison
(`subtle::ConstantTimeEq`).

### 6.3 Memory Exhaustion

Ingress sockets enforce a 2KB body-size ceiling
(`axum::extract::DefaultBodyLimit::max(2048)`), rejecting oversized bodies
before deserialization.

### 6.4 What this document doesn't claim

This spec has not been through a third-party cryptographic review. The
measured numbers in Section 5 are from one dev machine, not a hardened or
audited deployment. Treat this as a working design and implementation, not a
certified standard.

## 7. Error Code Mapping

| Error Code | HTTP Status | Description |
|---|---|---|
| `ERR_NONCE_REPLAY` | 409 Conflict | Nonce already consumed within its TTL |
| `ERR_SEQUENCE_VIOLATION` | 409 Conflict | Claimed step >= current server anchor step |
| `ERR_LOOKAHEAD_EXCEEDED` | 409 Conflict | Desync gap exceeds delta = 5 |
| `ERR_PREIMAGE_MISMATCH` | 401 Unauthorized | Preimage doesn't match state anchor |
| `ERR_INVALID_CONTEXT_SIGNATURE` | 401 Unauthorized | HMAC doesn't match canonical payload |
| `ERR_INVALID_PROOF_OF_WORK` | 403 Forbidden | Nonce doesn't satisfy difficulty target |
| `ERR_USER_NOT_FOUND` | 404 Not Found | User anchor state not found in store |

## 8. Normative References

* **RFC 2289** -- A One-Time Password System (S/KEY / Lamport)
* **RFC 2104** -- HMAC: Keyed-Hashing for Message Authentication
* **RFC 5869** -- HKDF: HMAC-based Extract-and-Expand Key Derivation Function
* **RFC 8785** -- JSON Canonicalization Scheme (JCS)
* **NIST SP 800-63B** -- Digital Identity Guidelines (Section 5.1.3.2, Out-of-Band Verifiers)
"""

def main() -> None:
    output_path = Path("RFC-HashGuard-ID-v1.0.md")
    output_path.write_text(RFC_TEXT.strip() + "\n", encoding="utf-8")
    print(f"[SUCCESS] Wrote {output_path} ({output_path.stat().st_size:,} bytes).")

if __name__ == "__main__":
    main()