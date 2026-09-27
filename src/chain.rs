//! # Reverse Hash Chain Primitives (RFC 2289 Engine)
//! Provides discrete one-way sequence generation and single-step anchor verification.

use crate::HashGuardError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SEED_BYTE_LENGTH: usize = 32; // 256-bit entropy
pub const HASH_OUTPUT_LENGTH: usize = 32;

/// In-memory client cryptographic state.
pub struct ClientChain {
    chain: Vec<[u8; HASH_OUTPUT_LENGTH]>,
    current_step: usize,
}

impl ClientChain {
    /// Initializes a Lamport Reverse Hash Chain from OS CSPRNG entropy.
    /// Time Complexity: O(N)
    /// Space Complexity: O(N)
    pub fn generate(length: usize) -> Result<(Self, [u8; HASH_OUTPUT_LENGTH]), HashGuardError> {
        let mut seed = [0u8; SEED_BYTE_LENGTH];
        getrandom::getrandom(&mut seed).map_err(|_| HashGuardError::EntropyFailure)?;

        let mut chain = Vec::with_capacity(length + 1);
        chain.push(seed);

        for i in 0..length {
            let mut hasher = Sha256::new();
            hasher.update(&chain[i]);
            let output: [u8; HASH_OUTPUT_LENGTH] = hasher.finalize().into();
            chain.push(output);
        }

        let initial_anchor = chain[length];

        Ok((
            Self {
                chain,
                current_step: length,
            },
            initial_anchor,
        ))
    }

    /// Emits the next preimage token: T_k = H^{k-1}(S).
    /// Time Complexity: O(1)
    pub fn advance(&mut self) -> Result<(usize, [u8; HASH_OUTPUT_LENGTH]), HashGuardError> {
        if self.current_step == 0 {
            return Err(HashGuardError::ChainExhausted);
        }
        self.current_step -= 1;
        Ok((self.current_step, self.chain[self.current_step]))
    }
}

/// Server-side immutable state anchor.
#[derive(Debug, Clone, Copy)]
pub struct ServerAnchor {
    pub anchor: [u8; HASH_OUTPUT_LENGTH],
    pub step: usize,
}

impl ServerAnchor {
    pub fn new(initial_anchor: [u8; HASH_OUTPUT_LENGTH], total_length: usize) -> Self {
        Self {
            anchor: initial_anchor,
            step: total_length,
        }
    }

    /// Verifies token preimage and executes atomic state transition.
    /// Time Complexity: O(1)
    /// Space Complexity: O(1)
    pub fn verify_and_transition(
        &mut self,
        submitted_token: &[u8; HASH_OUTPUT_LENGTH],
        claimed_step: usize,
    ) -> Result<(), HashGuardError> {
        // Enforce strictly monotonic decreasing progression
        if claimed_step >= self.step {
            return Err(HashGuardError::SequenceViolation);
        }

        // H(submitted_token) == self.anchor
        let mut hasher = Sha256::new();
        hasher.update(submitted_token);
        let computed: [u8; HASH_OUTPUT_LENGTH] = hasher.finalize().into();

        // Constant-time execution to prevent timing side-channel exploitation
        if computed.ct_eq(&self.anchor).unwrap_u8() != 1 {
            return Err(HashGuardError::InvalidPreimage);
        }

        // Atomic anchor transition
        self.anchor = *submitted_token;
        self.step = claimed_step;

        Ok(())
    }
}