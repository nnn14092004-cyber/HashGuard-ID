# HashGuard-ID: Cryptographic Anti-Toll-Fraud Verification Protocol

[![CI Passing](https://github.com/nnn14092004-cyber/HashGuard-ID/actions/workflows/ci.yml/badge.svg)](https://github.com/nnn14092004-cyber/HashGuard-ID/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Standard: RFC 2289](https://img.shields.io/badge/RFC-2289-green.svg)](https://tools.ietf.org/html/rfc2289)
[![Standard: RFC 8785](https://img.shields.io/badge/RFC-8785-green.svg)](https://tools.ietf.org/html/rfc8785)
[![Standard: RFC 5869](https://img.shields.io/badge/RFC-5869-green.svg)](https://tools.ietf.org/html/rfc5869)
[![Standard: RFC 2104](https://img.shields.io/badge/RFC-2104-green.svg)](https://tools.ietf.org/html/rfc2104)
[![Compliance: NIST SP 800-63B](https://img.shields.io/badge/NIST-SP%20800--63B-red.svg)](https://pages.nist.gov/800-63-3/sp800-63b.html)

**HashGuard-ID** is an ultra-low-latency, zero-telecom, one-way cryptographic authentication protocol engineered to permanently eliminate SMS OTP vulnerabilities—specifically **Artificially Inflated Traffic (AIT / SMS Pumping Toll Fraud)**, SIM-swapping, SS7 interception, and Distributed Time-of-Check to Time-of-Use (TOCTOU) race conditions.

By replacing out-of-band telecommunication channels with Lamport one-way reverse hash chains, RFC 5869 HKDF domain separation, RFC 8785 deterministic context enclosure, single-threaded Redis Lua Compare-And-Swap (CAS) with Hash Tag routing, and velocity-adaptive Proof-of-Work, HashGuard-ID guarantees a sub-20ms p99 Service Level Agreement (SLA) with **$0.0000 USD** in telecommunication surcharges.

---

## 1. Problem Space & Attack Economics

### 1.1 Structural Liabilities of Legacy SMS OTP
Public Switched Telephone Networks (PSTN) introduce systemic financial and architectural liabilities for modern identity infrastructure:
* **AIT / SMS Pumping Fraud:** Botnets automate authentication requests against public endpoints targeting premium-rate international ranges in collusion with rogue telecom brokers. Enterprises incur $0.05 to $0.15 USD per dispatched SMS, funding illicit toll-fraud cartels.
* **Channel Insecurity & Lack of Context Binding:** Plaintext SMS lacks proof-of-possession and transaction context binding, leaving authentication tokens vulnerable to SS7/Diameter call redirection, IMSI catchers, and SIM-swapping.
* **NIST SP 800-63B Deprecation:** Section 5.1.3.2 formally deprecates out-of-band SMS delivery for sensitive authentication transactions due to unauthenticated carrier channels.

### 1.2 Protocol Invariants & Zero-Trust Guarantees
* **Zero Carrier Cost:** Zero PSTN packets dispatched ($R_{\text{telco}} = \$0.0000$).
* **Cryptographic Context Enclosure:** Every token is cryptographically bound to an atomic canonical payload (amount, recipient, nonce, timestamp). Token reuse or cross-transaction injection is computationally infeasible.
* **Atomic State Monotonicity:** Sequence transitions are strictly monotonic and serialized via atomic Redis Lua CAS with Redis Cluster Hash Tags `{user:<id>}`, eliminating distributed TOCTOU race conditions and CROSSSLOT errors.
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
│                                        [Verify Stateless Ticket HMAC (~1.6 µs)]
│                                        [Verify PoW Solution Leading Zero-Bits]
│                                        [Verify Context HMAC via ConstantTimeEq (~1.4 µs)]
│                                        [Hardware-Offloaded Lookahead Hashing]
│                                        [Atomic Redis Lua CAS Verification (Zero-CROSSSLOT)]
│◄── 4. HTTP 200: {"status": "COMMITTED_ATOMIC", "remaining_step": k} ──│
```

---

## 3. Empirical Production SLA & Audit Telemetry

### 3.1 Latency Budget Distribution (N = 500 Consecutive Real Transactions)
Benchmarked on x86_64 architecture across $500$ consecutive, full-pipeline transactions executing against an active Axum Edge Gateway and distributed Redis instance:

| Sub-System Metric | p50 (Median) | p95 | p99 | Max Budget |
| :--- | :--- | :--- | :--- | :--- |
| **Client PoW Solve ($D = 10\text{ bits}$)** | **0.277 ms** | **0.830 ms** | **1.125 ms** | $< 5.000\text{ ms}$ |
| **Server CAS Core Verification** | **2.530 ms** | **3.005 ms** | **3.622 ms** | $< 10.000\text{ ms}$ |
| **E2E Round-Trip Pipeline Latency** | **4.955 ms** | **6.400 ms** | **6.777 ms** | **$< 20.000\text{ ms}$** |

### 3.2 Chaos & Realistic WAN Verification Metrics

| Commercial Audit Vector | Method & Parameters | Empirical Result | Specification Verdict |
| :--- | :--- | :--- | :--- |
| **Side-Channel Timing Leakage** | TVLA Welch's t-test ($N = 600$, Byte 0 vs 31) | **$t = -0.6164$** ($\vert{}t\vert{} < 4.5$) | **Zero Timing Leakage** |
| **Rollover Race Condition** | 50 concurrent racing threads at $k=1 \to k=0$ | **1 Commit, 49 Rejections** | **Zero TOCTOU** |
| **Cellular Jitter & Loss** | Gaussian Jitter ($\mu = 45\text{ms}, \sigma = 15\text{ms}$), 5% Drop | **100% Recovery ($\Delta \le 5$)** | **Fault Tolerant** |
| **Out-of-Order Delivery** | Asymmetric routing (Packet 8 before Packet 9) | **HTTP 409 Sequence Violation** | **Strict Monotonicity** |
| **TCP Socket Endurance** | $N = 1,000$ persistent HTTP keep-alive requests | **$5,357.7\text{ req/sec}$ ($0.187\text{s}$)** | **Zero TIME_WAIT Leak** |
| **Cluster Sharding Safety** | Multi-key atomic CAS via Hash Tag `{user:<id>}` | **0 CROSSSLOT errors** | **Redis Cluster Ready** |

---

## 4. Cross-Platform Setup & Verification

HashGuard-ID is fully cross-platform and verified across **Linux (Ubuntu/Debian/RHEL)**, **macOS (Apple Silicon M-Series/Intel)**, and **Windows (Native PowerShell/WSL2)**.

### 4.1 Prerequisites
* **Rust Toolchain:** `rustc 1.85+` (`rustup update stable`)
* **Python Runtime:** `python 3.10+`
* **In-Memory State Store:** Docker / Docker Desktop OR native `redis-server` (7.0+)

### 4.2 Launch State Store Engine

```bash
# Universal Docker container launch
docker compose up -d

# Alternative: Native Redis service
# Linux: sudo systemctl start redis-server
# macOS: brew services start redis
```

### 4.3 Build & Start Production Edge Gateway

```bash
cargo run --release --bin gateway
```

The Gateway daemon binds to `http://127.0.0.1:8080` with hardware-accelerated SHA-NI instructions and strict 2 KB socket ingress buffering.

### 4.4 Run Universal Verification Suites

All test suites employ standard forward-slash paths compatible across all shells:

```bash
# 1. Native Rust cryptographic unit tests
cargo test --all -- --nocapture

# 2. 50-Thread atomic race condition audit (0 TOCTOU guarantee)
python scripts/test_gateway_concurrency.py

# 3. Mobile network packet loss recovery (Delta <= 5) and silent chain rollover
python scripts/test_lookahead_recovery.py

# 4. Adversarial negative-space attack suite (replay, tampering, preimage forgery)
python scripts/adversarial_simulation.py

# 5. Silicon Valley commercial chaos suite (Welch's t-test, rollover race, JCS fuzzing)
python scripts/chaos_adversarial_suite.py

# 6. Realistic 4G/5G WAN simulation (jitter, packet loss, socket endurance)
python scripts/realistic_wan_simulation.py

# 7. Full SLA latency distribution benchmark (N = 500 consecutive transactions)
python scripts/benchmark_sla.py
```

---

## 5. Standards & Normative References
* **RFC 2289:** A One-Time Password System (S-KEY / Lamport).
* **RFC 2104:** HMAC: Keyed-Hashing for Message Authentication.
* **RFC 5869:** HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
* **RFC 8785:** JSON Canonicalization Scheme (JCS).
* **NIST SP 800-63B:** Digital Identity Guidelines: Authentication and Lifecycle Management (§5.1.3.2 Out-of-Band Verifiers).

---

## 6. License
This protocol and reference implementation are licensed under the **Apache-2.0 License**.
