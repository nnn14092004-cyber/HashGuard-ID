//! # Reverse Hash Chain Primitives (RFC 2289 Engine)
//! Standards: RFC 2289 (S-KEY / Lamport OTP), NIST SP 800-63B (§5.1.3.2)
//! Complexity: O(1) Preimage Verification, Bounded Delta-Lookahead Synchronization

use crate::HashGuardError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SEED_BYTE_LENGTH: usize = 32; // 256-bit high-entropy CSPRNG seed
pub const HASH_OUTPUT_LENGTH: usize = 32;
pub const MAX_LOOKAHEAD_HOPS: usize = 5; // Tolerates up to 5 consecutive packet drops

/// In-memory client cryptographic state maintaining reverse hash chain.
pub struct ClientChain {
    chain: Vec<[u8; HASH_OUTPUT_LENGTH]>,
    current_step: usize,
}

impl ClientChain {
    /// Initializes a Lamport Reverse Hash Chain from OS CSPRNG entropy.
    ///
    /// # Complexity
    /// Time: O(N) | Space: O(N) where N = chain length
    pub fn generate(length: usize) -> Result<(Self, [u8; HASH_OUTPUT_LENGTH]), HashGuardError> {
        if length == 0 {
            return Err(HashGuardError::EntropyFailure);
        }

        let mut seed = [0u8; SEED_BYTE_LENGTH];
        getrandom::getrandom(&mut seed).map_err(|_| HashGuardError::EntropyFailure)?;

        let mut chain = Vec::with_capacity(length + 1);
        chain.push(seed);

        for i in 0..length {
            let mut hasher = Sha256::new();
            hasher.update(chain[i]);
            let output: [u8; HASH_OUTPUT_LENGTH] = hasher.finalize().into();
            chain.push(output);
        }

        let terminal_anchor = chain[length];

        Ok((
            Self {
                chain,
                current_step: length,
            },
            terminal_anchor,
        ))
    }

    /// Emits the next preimage token: T_k = H^{k-1}(S).
    ///
    /// # Complexity
    /// Time: O(1) | Space: O(1)
    pub fn advance(&mut self) -> Result<(usize, [u8; HASH_OUTPUT_LENGTH]), HashGuardError> {
        if self.current_step == 0 {
            return Err(HashGuardError::ChainExhausted);
        }
        self.current_step -= 1;
        Ok((self.current_step, self.chain[self.current_step]))
    }

    /// Returns current remaining chain depth.
    #[inline(always)]
    pub fn remaining_steps(&self) -> usize {
        self.current_step
    }
}

/// Server-side state anchor enforcing strict monotonic sequence descent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerAnchor {
    pub anchor: [u8; HASH_OUTPUT_LENGTH],
    pub step: usize,
}

impl ServerAnchor {
    /// Initializes server anchor from public enrollment registration.
    #[inline(always)]
    pub fn new(initial_anchor: [u8; HASH_OUTPUT_LENGTH], total_length: usize) -> Self {
        Self {
            anchor: initial_anchor,
            step: total_length,
        }
    }

    /// Verifies preimage token under bounded lookahead window (1 <= Delta <= MAX_LOOKAHEAD_HOPS).
    /// Constant-time comparison ensures zero side-channel timing leakage.
    ///
    /// # Complexity
    /// Time: O(Delta) where Delta <= 5 (Bounded Constant Time) | Space: O(1)
    pub fn verify_and_transition(
        &mut self,
        submitted_token: &[u8; HASH_OUTPUT_LENGTH],
        claimed_step: usize,
    ) -> Result<(), HashGuardError> {
        // Enforce strictly monotonic decreasing progression
        if claimed_step >= self.step {
            return Err(HashGuardError::SequenceViolation);
        }

        let delta = self.step - claimed_step;
        if delta > MAX_LOOKAHEAD_HOPS {
            return Err(HashGuardError::LookaheadExceeded);
        }

        // Compute H^delta(submitted_token)
        let mut cursor = *submitted_token;
        for _ in 0..delta {
            let mut hasher = Sha256::new();
            hasher.update(cursor);
            cursor = hasher.finalize().into();
        }

        // Constant-time execution to prevent timing side-channel exploitation (TVLA compliant)
        if cursor.ct_eq(&self.anchor).unwrap_u8() != 1 {
            return Err(HashGuardError::InvalidPreimage);
        }

        // Atomic anchor transition
        self.anchor = *submitted_token;
        self.step = claimed_step;

        Ok(())
    }
}
