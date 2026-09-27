# HashGuard-ID Engineering Directive: Repository Agent Specifications

## 1. System Mission & Scope
HashGuard-ID is a deterministic, zero-telecom verification protocol designed to eliminate Artificially Inflated Traffic (AIT / SMS Pumping Toll Fraud), SIM-swapping, and SS7 routing interception by replacing Public Switched Telephone Network (PSTN) OTPs with cryptographic one-way state transitions.

All code, tests, and architectural additions within this repository must conform to the normative specifications, cryptographic invariants, and concurrency rules defined below.

---

## 2. Normative Standards & Cryptographic Primitives
Implementations MUST strictly adhere to the following standards:
- **RFC 2289 (A One-Time Password System):** Reverse Lamport hash chains $H^0(S) \dots H^N(S)$. The client holds the secret chain; the server holds the state anchor $Anchor_k = H^k(S)$ and verifies forward transitions in $\mathcal{O}(1)$ via $H(T_{k-1}) \stackrel{?}{=} Anchor_k$.
- **RFC 5869 (HKDF) & RFC 2104 (HMAC):** Preimage tokens $T_k$ MUST NOT be exposed directly as symmetric signing keys. Symmetric context keys MUST be derived using HKDF-Expand with domain separation:
  `K_context = HKDF-Expand(T_k, info="HashGuard-v1-Context-Enclosure-Key", L=32)`
- **RFC 8785 (JSON Canonicalization Scheme - JCS):** Deterministic payload serialization prior to cryptographic hashing to neutralize key-ordering, whitespace, and numerical representation malleability.
- **NIST SP 800-63B (Digital Identity Guidelines):** Complete deprecation of out-of-band telecom (SMS/PSTN) transport. The protocol operates out-of-band via data plane only, reducing marginal telecom carrier cost to $0.00.

---

## 3. Cryptographic Invariants & Side-Channel Immunity
- **No Proprietary Cryptography:** Only standardized primitives are permitted: SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), and HKDF-SHA256 (RFC 5869).
- **Constant-Time Verification:** All digest, preimage, token, and signature comparisons MUST execute via constant-time primitives (e.g., `subtle::ConstantTimeEq`). Direct equality operators (`==`) are strictly forbidden on sensitive memory buffers.
- **Entropy Bounds:** Seed generation requires 256 bits of OS-level CSPRNG entropy ($H(S) = 256$). Cryptographic security bounds are defined at $2^{256}$ for preimage resistance and $2^{128}$ for collision resistance.

---

## 4. Concurrency Control & State Anchor Mutations
- **Atomic Compare-And-Swap (CAS):** State verification, monotonic counter validation, replay cache assertion, and state anchor progression MUST execute within a single atomic transaction boundary (single-threaded Redis Lua script or relational table row lock).
- **Invariant Verification Sequence:**
  1. Nonce Replay Check: If `EXISTS nonce:<val>` == 1, reject with `ERR_REPLAY_ATTACK_DETECTED`.
  2. Monotonic Step Check: Assert claimed step $k_{\text{claimed}} < k_{\text{current}}$. If false, reject with `ERR_SEQUENCE_VIOLATION`.
  3. Preimage Check: Assert $\text{SHA-256}(T_k) == Anchor_k$. If false, reject with `ERR_PREIMAGE_MISMATCH`.
  4. State Mutation: Atomically store $Anchor \leftarrow T_k$, $k_{\text{current}} \leftarrow k_{\text{claimed}}$, and persist the nonce with a 300-second TTL.
- Split read-then-write logic (e.g., separate `SELECT` followed by `UPDATE`) is strictly prohibited to prevent Time-of-Check to Time-of-Use (TOCTOU) exploitation.

---

## 5. Anti-Toll Economic Engine (Stateless Adaptive Hashcash)
- **Stateless Challenge Ticket:** The API gateway must maintain 0 bytes of RAM state per challenge. Tickets are verified via keyed HMAC-SHA256 containing `(Client_IP, Timestamp, Difficulty_Bits)` with a strict 10-second Time-To-Live (TTL).
- **Adaptive Difficulty Scaling:**
  - Base difficulty: $D_0 = 10\text{ bits}$ for velocity $V \le 3\text{ req/min}$ (target client solve time $\approx 0.126\text{ ms}$, latency budget $< 20\text{ ms}$).
  - Exponential penalty: For $V > 3\text{ req/min}$, calculate difficulty as:
    $$D(V) = \min\left(26, \, 10 + \lceil 0.8 \times (V - 3)^2 \rceil\right)$$
  - At $V \ge 10$, difficulty reaches 26 bits ($\approx 6.7 \times 10^7$ hashes), locking adversary hardware for $> 40\text{ seconds}$ per request while server verification remains $\mathcal{O}(1) \approx 1.9\ \mu\text{s}$.

---

## 6. Codebase Architecture & Implementation Guardrails
- **Language & Safety:** Rust (2021 edition), `#![deny(unsafe_code)]`, zero-allocation hot paths.
- **Memory Hardening:** Ingress socket streams at the edge gateway must enforce a hard buffer ceiling of 2,048 octets (2 KB) via transport-level limits (Axum `DefaultBodyLimit`), terminating oversized payloads with HTTP 413 prior to deserialization.
- **Performance Budget:**
  - Server-side core verification latency: $\le 5\ \mu\text{s}$.
  - End-to-end cryptographic processing overhead: $\le 1\text{ ms}$.

---

## 7. Negative-Space & Adversarial Testing Matrix
All functional modules must maintain automated regression tests covering:
- **Preimage Forgery:** Attempting to advance the chain with invalid or unhashed tokens.
- **Context Tampering:** Modifying canonical transaction payload fields without signature invalidation.
- **Monotonic Sequence Violations:** Attempting chain rewind ($k_{\text{claimed}} \ge k_{\text{current}}$) or replay of historical preimages.
- **Concurrency Collisions:** Executing concurrent racing requests with identical tokens to verify that exactly 1 request commits and all racing duplicates fail.
- **Challenge Expiration:** Submitting solutions against expired or tampered HMAC challenge tickets.