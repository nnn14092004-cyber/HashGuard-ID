# HashGuard-ID: Cryptographic Anti-Toll-Fraud Verification Protocol

[![CI Passing](https://github.com/nnn14092004-cyber/HashGuard-ID/actions/workflows/ci.yml/badge.svg)](https://github.com/nnn14092004-cyber/HashGuard-ID/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Standard: RFC 2289](https://img.shields.io/badge/RFC-2289-green.svg)](https://tools.ietf.org/html/rfc2289)
[![Standard: RFC 8785](https://img.shields.io/badge/RFC-8785-green.svg)](https://tools.ietf.org/html/rfc8785)
[![Standard: RFC 5869](https://img.shields.io/badge/RFC-5869-green.svg)](https://tools.ietf.org/html/rfc5869)
[![Standard: RFC 2104](https://img.shields.io/badge/RFC-2104-green.svg)](https://tools.ietf.org/html/rfc2104)

I started this because SMS OTP is a mess from a security standpoint, and honestly
also an economic one -- carriers charge per message, botnets exploit that for
toll fraud, and SS7 has been broken for over a decade. HashGuard-ID is my take
on replacing it: a low-latency, cryptographic verification protocol that never
touches the telecom layer at all.

It combines a few well-established primitives rather than inventing new crypto:
Lamport reverse hash chains (RFC 2289) for the one-time-password mechanics,
HKDF (RFC 5869) for key derivation, JSON Canonicalization (RFC 8785) so signed
payloads are unambiguous, and an atomic Redis Lua CAS layer to keep state
consistent under concurrent load. Rate-limiting is handled by an adaptive
Hashcash proof-of-work that scales difficulty with request velocity.

## 1. Why not just keep using SMS?

A few structural problems with PSTN-based auth that pushed me toward this:

* **AIT / SMS pumping fraud.** Botnets hammer public auth endpoints targeting
  premium-rate number ranges, working with rogue telecom brokers on the other
  end. Providers eat $0.05-$0.15 per message sent this way.
* **No context binding.** Plaintext SMS isn't cryptographically tied to the
  transaction it's authenticating, so tokens are exposed to SS7/Diameter
  redirection, SIM-swapping, and baseband interception.
* **NIST already flagged this.** SP 800-63B Section 5.1.3.2 deprecates
  out-of-band SMS for sensitive auth flows.

What the protocol actually guarantees:

* **No PSTN packets, ever.** The whole flow stays off the telecom layer, so
  there's no per-message carrier surcharge to begin with.
* **Tokens are bound to context.** Every token is cryptographically tied to an
  immutable payload (amount, recipient, nonce, timestamp) -- redirecting a
  token to a different transaction is computationally infeasible.
* **Monotonic, atomic state.** Sequence transitions go through Redis Lua CAS
  with `{user:<id>}` Hash Tags, which rules out TOCTOU races and Redis Cluster
  `CROSSSLOT` errors in one move.
* **Asymmetric cost for attackers.** Gateway-side verification stays O(1); an
  attacker flooding requests eats exponentially growing PoW cost instead.

## 2. Protocol Architecture

```text
[Client / WebAssembly Native]                                   [Axum Edge Gateway & Redis Cluster]
|                                                                        |
|--- 1. POST /v1/challenge (Client IP, Velocity RPM) ------------------->|
|<-- 2. Stateless Challenge Ticket (Difficulty D(V), Server HMAC) -------|
|                                                                        |
|    [Client solves Hashcash: O(2^D) SHA-256 iterations]                 |
|    [Client advances Lamport Chain: Token T_k = H^k(S)]                 |
|    [RFC 5869 HKDF Expansion: K_context = HKDF-Expand(T_k)]             |
|    [RFC 8785 Canonical JCS -> RFC 2104 HMAC-SHA256 Signature]          |
|                                                                        |
|--- 3. POST /v1/verify (Envelope, PoW Nonce, Token T_k, Signature) ---->|
|                                                                        |
|                                        [Verify Ticket HMAC & 10s TTL]
|                                        [Verify PoW Solution Zero-Bits]
|                                        [Verify Context HMAC via ConstantTimeEq]
|                                        [Atomic Redis Lua CAS Verification]
|<-- 4. HTTP 200: {"status": "COMMITTED_ATOMIC", "remaining_step": k} ---|
```

### 2.1 Binding a token to its transaction

Tokens never travel as bare preimages. The transaction payload M gets
canonicalized via RFC 8785 into deterministic bytes C(M), then:

```
PRK          = HMAC-SHA256(0^32, T_k)
K_context    = HMAC-SHA256(PRK, "HashGuard-v1-Context-Enclosure-Key" || 0x01)
Sigma        = HMAC-SHA256(K_context, SHA-256(C(M)))
```

Digest comparisons all go through `subtle::ConstantTimeEq` -- no timing
side-channels from a naive `==`.

### 2.2 The atomic state store

One Redis Lua CAS script handles verification, single-threaded, with every key
using the `{user:<id>}` Hash Tag so cluster slots stay deterministic:

1. **Replay defense** -- checks `{user:<id>}:nonce:<val>` in O(1); consumed
   nonces get a 300s TTL.
2. **Monotonic descent** -- `k_claimed < k_current`, enforced strictly.
3. **Packet-loss tolerance** -- allows a desync of `delta = k_current -
   k_claimed <= 5`, computing lookahead hashes client-side.
4. **Silent re-anchoring** -- at the terminal state (`k = 0`), it rolls over
   to a pre-registered successor anchor with zero downtime.

### 2.3 Adaptive Hashcash

Challenge tickets carry the client IP, issuance time, and target difficulty,
signed under an ephemeral gateway secret. Difficulty scales with observed
request velocity -- a legit client solves a cheap puzzle, a suspected botnet
gets pushed into an exponentially harder one.

## 3. What I've actually measured

Everything below is straight from a real test run -- `cargo test --all` and
`scripts/test_full_system.py` against a live local gateway. All of it was run
on a single Windows dev machine, so treat it as "works and is fast on my
setup," not a production SLA guarantee -- more on that under Status.

### 3.1 Test suite -- 11/11 passing

| Suite | Tests | Result |
|---|---|---|
| `adversarial_tests.rs` | 6 | all passing |
| `concurrency_tests.rs` | 1 | passing |
| `e2e_pipeline_tests.rs` | 2 | all passing |
| `gateway_tests.rs` | 2 | all passing |

Covers replay attacks, preimage forgery, context tampering, PoW rate penalty +
TTL expiration, and the nominal Lamport/PoW happy paths.

### 3.2 TOCTOU under concurrency

50 threads racing for the same authentication step:

```
Concurrent In-Flight Requests : 50
Committed State Transitions   : 1
Rejected Racing Preimages     : 49
```

One commit, 49 rejections -- exactly what the CAS design is supposed to do.

### 3.3 Single-run timing (Rust test)

```
Client PoW Solve Time (D=10) : 0.140 ms
Server PoW Verification      : 1.5 us
Server Context Verification  : 1.1 us
Server Total Core Execution  : 3.0 us
Total Protocol Processing    : 0.143 ms
```

Just one run of `e2e_pipeline_tests.rs` -- the percentile numbers below are
the ones that actually mean something statistically.

### 3.4 100-transaction sweep

This is from `scripts/test_full_system.py` hitting a live gateway
(`cargo run --release --bin gateway`), running all three pillars -- context
binding, TOCTOU/lookahead recovery, adaptive Hashcash -- plus 100 transactions
timed end-to-end:

| Metric | p50 | p99 |
|---|---|---|
| Client PoW Solve | 0.25 ms | 0.39 ms |
| Server CAS Core | 0.716 ms | 1.000 ms |
| Verify E2E Roundtrip | 0.94 ms | 1.33 ms |
| **Full Lifecycle E2E** | **1.42 ms** | **1.81 ms** |

All 100 landed inside the 20ms budget. When I forced request velocity up to 15
req/min, difficulty escalated from D=10 to D=26 bits, and the 50-thread TOCTOU
race resolved the same way as above -- 1 commit, 49 rejections.

## 4. Setup

### 4.1 Linux (Ubuntu / Debian / RHEL / Fedora)

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y curl build-essential pkg-config libssl-dev redis-server python3 python3-pip python3-venv

# Fedora / RHEL
sudo dnf install -y gcc gcc-c++ openssl-devel redis python3 python3-pip

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

For concurrency benchmarks, raise the socket ceilings:
```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo systemctl enable --now redis-server || sudo systemctl enable --now redis
redis-cli ping   # expect: PONG
```

### 4.2 macOS

```bash
brew install rustup-init redis python@3.11
rustup-init -y
source "$HOME/.cargo/env"
brew services start redis
redis-cli ping   # expect: PONG
```

Bump the file descriptor limit before running the concurrency tests:
```bash
ulimit -n 65536
```

### 4.3 Windows (PowerShell)

```powershell
winget install Rustlang.Rustup
winget install Redis.Redis
```
If a native Windows Redis build gives you trouble, just run it in Docker (4.4).

### 4.4 Docker (any platform)

```bash
docker run -d \
  --name hashguard-redis \
  -p 6379:6379 \
  --restart unless-stopped \
  redis:7-alpine redis-server --appendonly no --save ""

docker exec -it hashguard-redis redis-cli ping
```

### 4.5 Build & run

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin gateway
```

Gateway binds to `http://127.0.0.1:8080`.

### 4.6 Run the tests

```bash
cargo test --all -- --nocapture
python3 scripts/test_full_system.py
```
(Run the gateway in its own terminal first -- `test_full_system.py` needs it
up and listening before it can hit the endpoints.)

## 5. Status

This is a working prototype, not an audited security product -- I'd want a
third-party crypto review before anyone relies on it for real auth. All the
numbers in section 3 are from my own dev machine (Windows), a single set of
runs, not a production or multi-node deployment. Take them as "the design
works and is fast enough," not as a guaranteed SLA.

## Roadmap
- [ ] Load testing on something closer to production infrastructure
- [ ] Third-party cryptographic review
- [ ] Confirm the same test results hold on Linux/macOS, not just Windows
- [ ] Redis Cluster multi-node failure testing

## 6. Normative References
* **RFC 2289** -- A One-Time Password System (S/KEY / Lamport OTP)
* **RFC 2104** -- HMAC: Keyed-Hashing for Message Authentication
* **RFC 5869** -- HKDF: HMAC-based Extract-and-Expand Key Derivation Function
* **RFC 8785** -- JSON Canonicalization Scheme (JCS)
* **NIST SP 800-63B** -- Digital Identity Guidelines (Section 5.1.3.2, Out-of-Band Verifiers)

## License
Apache License, Version 2.0
