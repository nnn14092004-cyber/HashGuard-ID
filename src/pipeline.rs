//! # End-to-End Protocol Verification Pipeline
//! Standards: RFC 2289, RFC 2104, RFC 8785, NIST SP 800-63B, Spec.docx Items 1-3.
//! Guarantees: O(1) time verification, bounded memory footprint, zero-telecom dependency.

use crate::chain::HASH_OUTPUT_LENGTH;
use crate::context::TransactionEnvelope;
use crate::pow::{ChallengeTicket, HashcashEngine};
use crate::HashGuardError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Performance execution metrics for SLA validation.
#[derive(Debug, Clone, Copy)]
pub struct PipelineTelemetry {
    pub pow_verification_nanos: u128,
    pub context_verification_nanos: u128,
    pub total_pipeline_nanos: u128,
    pub remaining_chain_depth: usize,
}

/// Request envelope submitted to the verification gateway.
pub struct VerificationRequest {
    pub account_id: String,
    pub ticket: ChallengeTicket,
    pub pow_nonce: u64,
    pub envelope: TransactionEnvelope,
    pub current_time_epoch: u64,
}

/// Core protocol pipeline runner.
pub struct ProtocolPipeline {
    gateway_secret: [u8; 32],
}

impl ProtocolPipeline {
    /// Initializes protocol pipeline with gateway ephemeral secret.
    pub fn new(gateway_secret: [u8; 32]) -> Self {
        Self { gateway_secret }
    }

    /// Executes full end-to-end zero-trust verification.
    /// Time Complexity: O(1) hashing + O(L) payload scan
    /// Space Complexity: O(1) heap allocation
    pub fn verify_and_advance(
        &self,
        request: &VerificationRequest,
        current_anchor: &mut [u8; HASH_OUTPUT_LENGTH],
        current_step: &mut usize,
    ) -> Result<PipelineTelemetry, HashGuardError> {
        let pipeline_start = std::time::Instant::now();

        // -------------------------------------------------------------
        // STEP 1: Verify Stateless PoW Challenge Ticket & Proof (Spec Item 3)
        // -------------------------------------------------------------
        let pow_start = std::time::Instant::now();

        // 1.1 Verify ticket integrity and freshness in O(1)
        request
            .ticket
            .verify_ticket(request.current_time_epoch, &self.gateway_secret)?;

        // 1.2 Verify Hashcash single-pass condition: SHA256(HMAC || Nonce)
        let pow_valid = HashcashEngine::verify_solution(
            &request.ticket.server_hmac,
            request.pow_nonce,
            request.ticket.difficulty_bits,
        );

        if !pow_valid {
            return Err(HashGuardError::InvalidProofOfWork);
        }
        let pow_verification_nanos = pow_start.elapsed().as_nanos();

        // -------------------------------------------------------------
        // STEP 2: Verify Cryptographic Context Binding (Spec Item 1)
        // -------------------------------------------------------------
        let context_start = std::time::Instant::now();

        // 2.1 Constant-time HMAC transaction envelope verification
        request.envelope.verify_binding()?;
        let context_verification_nanos = context_start.elapsed().as_nanos();

        // -------------------------------------------------------------
        // STEP 3: Verify Reverse Hash Chain Preimage & Monotonicity (Spec Items 1 & 2)
        // -------------------------------------------------------------
        // 3.1 Strict sequence monotonicity check
        if request.envelope.step_index >= *current_step {
            return Err(HashGuardError::SequenceViolation);
        }

        // 3.2 Verify Lamport step: H(T_k) == CurrentAnchor
        let mut hasher = Sha256::new();
        hasher.update(request.envelope.token);
        let computed_anchor: [u8; HASH_OUTPUT_LENGTH] = hasher.finalize().into();

        if computed_anchor.ct_eq(current_anchor).unwrap_u8() != 1 {
            return Err(HashGuardError::InvalidPreimage);
        }

        // 3.3 Atomic Anchor Mutation
        *current_anchor = request.envelope.token;
        *current_step = request.envelope.step_index;

        let total_pipeline_nanos = pipeline_start.elapsed().as_nanos();

        Ok(PipelineTelemetry {
            pow_verification_nanos,
            context_verification_nanos,
            total_pipeline_nanos,
            remaining_chain_depth: *current_step,
        })
    }
}
