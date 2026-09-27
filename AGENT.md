# HashGuard-ID Engineering Directive: Repository Agent Specifications

## 1. System Mission & Scope
HashGuard-ID is a deterministic, zero-telecom verification protocol designed to eliminate Artificially Inflated Traffic (AIT / SMS Pumping Toll Fraud), SIM-swapping, and SS7 routing interception by replacing Public Switched Telephone Network (PSTN) OTPs with cryptographic one-way state transitions.

All code, tests, and architectural additions within this repository must conform to the normative specifications, cryptographic invariants, and concurrency rules defined below.

## 2. Normative Standards & Cryptographic Primitives
Implementations MUST strictly adhere to the following standards:
- **RFC 2289 (Lamport OTP):** Reverse hash chains $H^0(S) \dots H^N(S)$. The client holds the secret chain; the server holds the state anchor $Anchor_k = H^k(S)$ and verifies forward transitions in $\mathcal{O}(1)$ via $H(T_{k-1}) \stackrel{?}{=} Anchor_k$.
- **RFC 5869 (HKDF) & RFC 2104 (HMAC):** Preimage tokens $T_k$ MUST NOT be exposed directly as symmetric signing keys. Symmetric context keys MUST be derived using HKDF-Expand with domain separation:
  `K_context = HKDF-Expand(T_k, info="HashGuard-v1-Context-Enclosure-Key", L=32)`
- **RFC 8785 (JSON Canonicalization Scheme - JCS):** Deterministic payload serialization prior to cryptographic hashing to eliminate key-ordering, whitespace, and numerical formatting ambiguity.
- **NIST SP 800-63B (§5.1.3.2):** Deprecation of out-of-band telecom (SMS/PSTN) transport. The protocol operates strictly over the data plane, reducing marginal telecom carrier cost to $0.0000 USD.

## 3. Cryptographic Invariants & Side-Channel Immunity
- **Standardized Cryptography Only:** Proprietary ciphers or unvetted primitives are prohibited. Use only SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), and HKDF-SHA256 (RFC 5869).
- **Constant-Time Verification:** All digest, preimage, token, and signature comparisons MUST execute via constant-time primitives (`subtle::ConstantTimeEq`). Direct equality operators (`==`) on secret buffers are strictly forbidden.
- **Entropy Bounds:** Seed generation requires 256 bits of OS-level CSPRNG entropy ($H(S) = 256$). Cryptographic security bounds are defined at $2^{256}$ for preimage resistance and $2^{128}$ for collision resistance.

## 4. Concurrency Control & State Mutations
- **Atomic Compare-And-Swap (CAS):** State verification, monotonic counter validation, replay cache assertions, and anchor progression MUST execute within a single atomic boundary via a Redis Lua script.
- **Redis Cluster Slot Routing:** All state keys for an account MUST use the `{user:<id>}` Hash Tag to ensure CRC16 slot alignment and prevent `CROSSSLOT` errors across cluster nodes:
  - `{user:<id>}:anchor`
  - `{user:<id>}:step`
  - `{user:<id>}:nonce:<val>`
  - `{user:<id>}:pending_anchor`
  - `{user:<id>}:pending_step`
- **Execution Invariants Inside CAS:**
  1. Nonce Replay Check: If `EXISTS {user:<id>}:nonce:<val>` == 1, reject with `ERR_NONCE_REPLAY`.
  2. Monotonic Step Check: Assert claimed step $k_{\text{claimed}} < k_{\text{current}}$. If false, reject with `ERR_SEQUENCE_VIOLATION`.
  3. Bounded Desync Window: Assert $\Delta = k_{\text{current}} - k_{\text{claimed}} \le 5$. If $\Delta > 5$, reject with `ERR_LOOKAHEAD_EXCEEDED`.
  4. Preimage Matching: Match anchor against precomputed candidate $\text{ARGV}[7 + \Delta]$. If mismatched, reject with `ERR_PREIMAGE_MISMATCH`.
  5. State Mutation: Atomically store $Anchor \leftarrow T_k$, $Step \leftarrow k_{\text{claimed}}$, and persist the nonce with a 300-second TTL.
  6. Terminal Boundary Transition: If $k_{\text{claimed}} = 0$, atomically promote `pending_anchor` to active state, returning `ROLLED_OVER_ATOMIC`.
- Split read-then-write logic (e.g., separate `GET` followed by `SET`) is strictly prohibited to eliminate Time-of-Check to Time-of-Use (TOCTOU) exploitation.

## 5. Anti-Toll Economic Engine (Stateless Adaptive Hashcash)
- **Stateless Challenge Ticket:** The API gateway maintains 0 bytes of RAM state per challenge. Tickets are verified via keyed HMAC-SHA256 containing `(Client_IP, Timestamp, Difficulty_Bits)` with a strict 10-second Time-To-Live (TTL).
- **Adaptive Difficulty Scaling:**
  - Base difficulty: $D_0 = 10\text{ bits}$ for velocity $V \le 3\text{ req/min}$ (target client solve time $\approx 1.60\text{ ms}$, latency budget $< 20.00\text{ ms}$).
  - Exponential penalty: For $V > 3\text{ req/min}$, calculate difficulty as:
    $$D(V) = \min\left(26, \, 10 + \lceil 0.8 \times (V - 3)^2 \rceil\right)$$
  - At $V \ge 10$, difficulty reaches 26 bits ($\approx 6.7 \times 10^7$ hashes), locking adversary hardware for $> 40\text{ seconds}$ per request while server verification remains $\mathcal{O}(1) \approx 1.9\ \mu\text{s}$.

## 6. Codebase Architecture & Implementation Guardrails
- **Language & Safety:** Rust (2021 edition), `#![deny(unsafe_code)]`, zero-allocation hot paths.
- **Memory Hardening:** Ingress socket streams at the edge gateway must enforce a hard buffer ceiling of 2,048 octets (2 KB) via transport-level limits (`axum::extract::DefaultBodyLimit::max(2048)`), terminating oversized payloads with HTTP 413 prior to deserialization.
- **Client Transport:** Test suites and production clients MUST maintain persistent connection pooling (HTTP Keep-Alive) to prevent local TCP ephemeral port exhaustion and loopback `TIME_WAIT` latency on Windows/Linux network stacks.
- **Performance Budget:**
  - Client-side solve latency: $\le 5\text{ ms}$ (p99).
  - Server-side core CAS latency: $\le 3\text{ ms}$ (p99).
  - Full end-to-end verification lifecycle: $\le 20\text{ ms}$ (p99 SLA).

## 7. Negative-Space & Adversarial Testing Matrix
All functional modules must maintain automated regression tests covering:
- **Preimage Forgery:** Submitting invalid or unhashed tokens must return `HTTP 401 Unauthorized`.
- **Context Tampering:** Modifying canonical transaction payload fields without signature updating must return `HTTP 401 Unauthorized`.
- **Monotonic Sequence Violations:** Submitting $k_{\text{claimed}} \ge k_{\text{current}}$ or replaying historical preimages must return `HTTP 409 Conflict`.
- **Concurrency Collisions:** Executing 50 concurrent racing requests with identical tokens must yield exactly 1 commit and 49 conflict rejections (`HTTP 409`).
- **Packet-Loss Recovery:** Steps jumping across $1 \le \Delta \le 5$ must succeed; $\Delta > 5$ must be rejected with `HTTP 409 Conflict`.
- **Challenge Expiration:** Submitting solutions against expired (> 10s) or modified HMAC challenge tickets must return `HTTP 401 Unauthorized` or `HTTP 403 Forbidden`.