//! # Concurrency & TOCTOU Stress Test (Spec.docx Item 2)
//! Standards: NIST SP 800-63B, RFC 2289.
//! Verifies atomic state transitions and race condition immunity under concurrent bursts.

use hashguard_core::{ClientChain, HashGuardError};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{Barrier, Mutex};

/// In-memory single-threaded atomic engine simulating Redis Lua script execution.
struct MockRedisLuaEngine {
    anchor: [u8; 32],
    step: usize,
    spent_nonces: HashSet<String>,
}

impl MockRedisLuaEngine {
    fn new(initial_anchor: [u8; 32], total_steps: usize) -> Self {
        Self {
            anchor: initial_anchor,
            step: total_steps,
            spent_nonces: HashSet::new(),
        }
    }

    /// Simulates scripts/anchor_cas.lua atomically inside a critical section.
    fn atomic_cas(
        &mut self,
        expected_anchor: &[u8; 32],
        new_token: &[u8; 32],
        claimed_step: usize,
        nonce: &str,
    ) -> Result<usize, HashGuardError> {
        // 1. Anti-Replay check: O(1)
        if self.spent_nonces.contains(nonce) {
            return Err(HashGuardError::SequenceViolation);
        }

        // 2. Monotonic sequence check
        if claimed_step >= self.step {
            return Err(HashGuardError::SequenceViolation);
        }

        // 3. Constant-time anchor invariant check: H(T_k) == current_anchor
        if self.anchor.ct_eq(expected_anchor).unwrap_u8() != 1 {
            return Err(HashGuardError::InvalidPreimage);
        }

        // 4. Atomic state transition
        self.anchor = *new_token;
        self.step = claimed_step;
        self.spent_nonces.insert(nonce.to_string());

        Ok(self.step)
    }
}

#[tokio::test]
async fn test_toctou_atomic_race_condition_simulation() {
    let chain_len = 100;
    let (mut client_chain, initial_anchor) = ClientChain::generate(chain_len)
        .expect("CSPRNG seed generation failed");

    // Shared state protected by an asynchronous mutex (representing Redis single-threaded execution)
    let engine = Arc::new(Mutex::new(MockRedisLuaEngine::new(initial_anchor, chain_len)));

    // Client extracts token at step k = 99
    let (step, token) = client_chain.advance().expect("Premature chain depletion");

    // Pre-calculate expected current anchor: H(T_k)
    let mut hasher = Sha256::new();
    hasher.update(&token);
    let expected_anchor: [u8; 32] = hasher.finalize().into();

    let concurrency_count = 50;
    let barrier = Arc::new(Barrier::new(concurrency_count));
    let mut handles = Vec::with_capacity(concurrency_count);

    for i in 0..concurrency_count {
        let engine_clone = Arc::clone(&engine);
        let barrier_clone = Arc::clone(&barrier);
        let nonce = format!("race_nonce_step_{}_worker_{}", step, i);

        handles.push(tokio::spawn(async move {
            barrier_clone.wait().await; // Synchronize release time across all 50 tasks

            let mut state = engine_clone.lock().await;
            state.atomic_cas(&expected_anchor, &token, step, &nonce)
        }));
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    for handle in handles {
        match handle.await.expect("Tokio worker task panicked") {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    println!("\n=======================================================");
    println!("HASHGUARD-ID TOCTOU CONCURRENCY BENCHMARK REPORT");
    println!("=======================================================");
    println!("Concurrent In-Flight Requests : {}", concurrency_count);
    println!("Committed State Transitions   : {}", success_count);
    println!("Rejected Racing Preimages (CAS): {}", failure_count);
    println!("=======================================================");

    // Invariant: Exactly one transaction must commit; all remaining 49 must be rejected
    assert_eq!(
        success_count, 1,
        "CRITICAL TOCTOU FAILURE: State anchor mutated more than once!"
    );
    assert_eq!(
        failure_count,
        concurrency_count - 1,
        "ATOMICITY BREACH: Inconsistent rejection tally."
    );
}