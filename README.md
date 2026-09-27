# HashGuard-ID: Cryptographic Anti-Toll-Fraud Verification Protocol

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Standard: RFC 2289](https://img.shields.io/badge/RFC-2289-green.svg)](https://tools.ietf.org/html/rfc2289)
[![Standard: RFC 8785](https://img.shields.io/badge/RFC-8785-green.svg)](https://tools.ietf.org/html/rfc8785)
[![Standard: RFC 5869](https://img.shields.io/badge/RFC-5869-green.svg)](https://tools.ietf.org/html/rfc5869)
[![Standard: RFC 2104](https://img.shields.io/badge/RFC-2104-green.svg)](https://tools.ietf.org/html/rfc2104)
[![Compliance: NIST SP 800-63B](https://img.shields.io/badge/NIST-SP%20800--63B-red.svg)](https://pages.nist.gov/800-63-3/sp800-63b.html)

**HashGuard-ID** is an ultra-low-latency, zero-telecom, one-way cryptographic authentication protocol engineered to permanently eliminate SMS OTP vulnerabilities—specifically **Artificially Inflated Traffic (AIT / SMS Pumping Toll Fraud)**, SIM-swapping, SS7 interception, and Distributed Time-of-Check to Time-of-Use (TOCTOU) race conditions.

By replacing out-of-band telecommunication channels with Lamport one-way reverse hash chains, RFC 5869 HKDF domain separation, RFC 8785 deterministic context enclosure, single-threaded Redis Lua Compare-And-Swap (CAS), and velocity-adaptive Proof-of-Work, HashGuard-ID guarantees a sub-20ms p99 Service Level Agreement (SLA) with **$0.0000 USD** in telecommunication surcharge.

---

## 1. Problem Space & Attack Economics

### 1.1 Structural Liabilities of Legacy SMS OTP
Public Switched Telephone Networks (PSTN) introduce fatal financial and architectural risks:
* **AIT / SMS Pumping Fraud:** Botnets automate authentication requests against public endpoints targeting premium-rate international ranges colluding with rogue telecom brokers. Enterprises incur $0.05 to $0.15 USD per dispatched SMS, funding multi-million-dollar toll-fraud cartels.
* **Channel Insecurity & Lack of Context Binding:** Plaintext SMS lacks proof-of-possession and transaction context binding, leaving authentication tokens vulnerable to SS7/Diameter call redirection and SIM-swapping.
* **NIST SP 800-63B Deprecation:** Section 5.1.3.2 formally deprecates out-of-band SMS delivery for sensitive authentication transactions.

### 1.2 Protocol Invariants & Zero-Trust Guarantees
* **Zero Carrier Cost:** Zero PSTN packets dispatched ($R_{\text{telco}} = \$0.0000$).
* **Cryptographic Context Enclosure:** Every token is cryptographically bound to an atomic canonical payload (amount, recipient, nonce, timestamp). Token reuse or redirection is mathematically infeasible.
* **Atomic State Monotonicity:** Sequence transitions are strictly monotonic and serialized via atomic Redis Lua CAS, eliminating distributed TOCTOU race conditions.
* **Asymmetric Anti-Toll Defense:** Edge verification overhead is bounded to $\mathcal{O}(1)$ time and memory, whereas adversarial request floods trigger exponential client CPU exhaustion.

---

## 2. Core Protocol Architecture

```text
[Client Endpoint / WASM Engine]                                 [Edge Gateway & Distributed State Store]
│                                                                        │
│─── 1. POST /v1/challenge (Client IP, Velocity) ───────────────────────►│
│◄── 2. Stateless Challenge Ticket (D(V) bits, HMAC-Signed) ─────────────│
│                                                                        │
│    [Client solves Adaptive Hashcash: O(2^D) iterations]                │
│    [Client advances Lamport Chain: Token T_k = H^k(S)]                 │
│    [RFC 5869 Key Derivation: K_context = HKDF-Expand(T_k)]             │
│    [RFC 8785 JCS Canonicalization -> RFC 2104 HMAC Signature]          │
│                                                                        │
│─── 3. POST /v1/verify (Envelope, PoW Nonce, Token T_k, Signature) ────►│
│                                                                        │
│                                        [Verify Stateless Ticket HMAC (~1.9 µs)]
│                                        [Verify PoW Solution Leading Zero-Bits]
│                                        [Verify Context HMAC via ConstantTimeEq]
│                                        [Hardware-Offloaded Lookahead Hashing]
│                                        [Atomic Redis Lua CAS Verification]
│◄── 4. HTTP 200: {"status": "COMMITTED_ATOMIC", "remaining_step": k} ──│
```

### Pillar 1: Lamport Reverse Hash Chains (RFC 2289)
* **Entropy Generation:** Seed $S \leftarrow \text{CSPRNG}(\{0, 1\}^{256})$.
* **One-Way Iteration:** $T_0 = S, \quad T_i = \text{SHA-256}(T_{i-1}) \quad \forall i \in [1, N]$.
* **Constant-Time Verification:** Server stores only the current state anchor $Anchor_k = H^k(S)$ (32 bytes). Verification requires single forward-pass verification in $\mathcal{O}(1)$ complexity:
  $$\text{SHA-256}(T_{k-1}) \stackrel{?}{=} Anchor_k$$

### Pillar 2: Cryptographic Context Enclosure & Key Hygiene (RFC 8785, RFC 5869, RFC 2104)
* **Domain Separation:** Preimage tokens $T_k$ are never exposed directly as symmetric keys. Transient keys are derived via HKDF-Expand with domain label:
  $$K_{\text{context}} = \text{HKDF-Expand}(T_k, \, \text{"HashGuard-v1-Context-Enclosure-Key"}, \, 32)$$
* **Deterministic Canonical Binding:** Normalizes transaction payloads into an unambiguous byte stream via RFC 8785 (JCS) before generating RFC 2104 HMAC-SHA256 signatures:
  $$\Sigma = \text{HMAC-SHA256}(K_{\text{context}}, \, \text{SHA-256}(\text{JCS}(\mathcal{M})))$$
* **Side-Channel Timing Immunity:** Every digest and signature comparison enforces `subtle::ConstantTimeEq`.

### Pillar 3: Distributed Concurrency & Storage Engine (Spec Item 2)
* **Atomic Redis Lua CAS Engine:** Implements single-threaded atomic execution of:
  1. Nonce replay rejection with $TTL = 300\text{ seconds}$.
  2. Monotonic sequence verification: $k_{\text{claimed}} < k_{\text{current}}$.
  3. $\Delta$-Step Lookahead Recovery: Tolerates mobile packet loss across a bounded window $\Delta \in [1, 5]$ hops:
     $$Anchor_{\text{expected}} = H^{\Delta}(T_{\text{claimed}})$$
  4. Silent Chain Rollover: When $k_{\text{claimed}} = 0$, atomically swaps state anchor to a piggybacked successor anchor $Anchor'_M$ without downtime.
* **Zero TOCTOU:** Under 50 concurrent racing threads presenting the same token, exactly 1 commits while 49 are rejected with `HTTP 409 Conflict`.

### Pillar 4: Anti-Toll Economic Model (Spec Item 3)
* **Stateless Challenge Ticket:** The Edge Gateway allocates 0 bytes in database RAM during ticket minting:
  $$\text{TicketHMAC} = \text{HMAC-SHA256}(K_{\text{gateway}}, \, \text{IP} \parallel t_{\text{issued}} \parallel D(V))$$
* **Dynamic Velocity Penalty Curve:**
  $$D(V) = \begin{cases}    10\text{ bits}, & \text{if } V \le 3\text{ req/min} \quad (\text{Legitimate User}) \\   \min\left(26, \, 10 + \lceil 0.8 \times (V - 3)^2 \rceil\right), & \text{if } V > 3\text{ req/min} \quad (\text{Suspected Botnet})   \end{cases}$$
* **Game-Theoretic Equilibrium:** Zero telecom revenue combined with exponential CPU difficulty renders botnet attack profits strictly negative ($\Pi(V) < 0$), forcing optimal attack velocity $V^* = 0$.

---

## 3. Empirical Production SLA Telemetry (N = 500)

Benchmarked on x86_64 architecture across $500$ consecutive, full-pipeline transactions executing against an active Axum Edge Gateway and distributed Redis cluster:

| Sub-System Metric | p50 (Median) | p95 | p99 | Max |
| :--- | :--- | :--- | :--- | :--- |
| **Client PoW Solve ($D = 10\text{ bits}$)** | **1.627 ms** | **2.734 ms** | **3.320 ms** | **4.731 ms** |
| **Server CAS Core Verification** | **2.446 ms** | **2.801 ms** | **3.288 ms** | **6.723 ms** |
| **E2E Round-Trip Pipeline Latency** | **6.450 ms** | **7.682 ms** | **9.245 ms** | **13.179 ms** |

### Verified Telemetric Invariants
* **SLA Compliance Threshold ($< 20.00\text{ ms}$):** **100.0% Compliant** (p99 Margin: $-53.8\%$).
* **Telecommunication Surcharge Dispatched:** **$0.0000 USD** (Zero SMS sent).
* **Distributed TOCTOU Race Condition Breaches:** **0** (Verified via 50-thread concurrent stress harness).
* **Socket Memory Cap:** **2,048 octets (2 KB)** strict buffer cap, preventing heap exhaustion.

---

## 4. Repository Structure

```text
.
├── Cargo.toml                  # Workspace dependencies and optimization profiles
├── docker-compose.yml          # Containerized Redis 7.2 state engine configuration
├── RFC-HashGuard-ID-v1.0.md    # Formal IETF-style protocol specification
├── demo/
│   └── index.html              # Real-time WebCrypto cryptographic verification cockpit
├── crates/
│   └── hashguard-wasm/         # High-performance Rust WebAssembly Client SDK
├── scripts/
│   ├── anchor_cas.lua          # Atomic Redis Lua Compare-And-Swap script
│   ├── benchmark_sla.py        # Automated 500-transaction SLA percentile benchmark
│   ├── test_gateway_concurrency.py # 50-thread atomic race condition validation
│   ├── test_lookahead_recovery.py  # Packet-loss desynchronization & rollover suite
│   ├── adversarial_simulation.py   # Negative-space attack suite (replay, tampering)
│   └── generate_readme.py      # Automated documentation generator
└── src/
    ├── lib.rs                  # Crate declarations and domain error types
    ├── chain.rs                # Lamport reverse hash chain implementation
    ├── context.rs              # RFC 8785 JCS, RFC 5869 HKDF, RFC 2104 HMAC
    ├── pow.rs                  # Stateless Adaptive Hashcash engine
    ├── storage.rs              # Asynchronous Redis driver and CAS abstractions
    └── bin/
        └── gateway.rs          # Production Axum HTTP Edge Verification Gateway
```

---

## 5. Verification & Test Execution

### 1. Launch Redis State Store
```bash
docker compose up -d
```

### 2. Start Production Edge Gateway
```bash
cargo run --bin gateway
```

### 3. Run Automated Adversarial & Concurrency Test Suites
```bash
# Run 50-thread race condition validation (1 commit / 49 reject)
python .\scripts\test_gateway_concurrency.py

# Run packet loss desync (Delta <= 5) and silent chain rollover verification
python .\scripts\test_lookahead_recovery.py

# Run adversarial simulation (replay rejection, payload tampering, preimage forgery)
python .\scripts\adversarial_simulation.py

# Run full SLA latency distribution benchmark (N = 500)
python .\scripts\benchmark_sla.py
```

### 4. Launch Interactive Web Cockpit
```bash
python -m http.server 3000
# Open http://localhost:3000/demo/index.html in browser
```

---

## 6. Standards & Normative References
* **RFC 2289:** A One-Time Password System (S-KEY / Lamport).
* **RFC 2104:** HMAC: Keyed-Hashing for Message Authentication.
* **RFC 5869:** HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
* **RFC 8785:** JSON Canonicalization Scheme (JCS).
* **NIST SP 800-63B:** Digital Identity Guidelines (§5.1.3.2 Out-of-Band Verifiers).

---

## 7. License
This protocol and reference implementation are licensed under the **Apache-2.0 License**.
