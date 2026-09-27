//! # HashGuard-ID Core Verification Protocol
//! Specifications: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B.
//! Guarantees: Constant-time execution, strictly O(1) state verification, zero-telecom dependency.

#![deny(unsafe_code)]
#![allow(missing_docs)]

pub mod chain;
pub mod context;
pub mod pipeline;
pub mod pow;
pub mod storage;

pub use chain::{ClientChain, ServerAnchor};
pub use context::{CanonicalTransaction, TransactionEnvelope};
pub use pipeline::{PipelineTelemetry, ProtocolPipeline, VerificationRequest};
pub use pow::{ChallengeTicket, HashcashEngine};
pub use storage::RedisAnchorStore;

use thiserror::Error;

/// Protocol failure states.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum HashGuardError {
    #[error("Cryptographic preimage mismatch: H(T_k) != CurrentAnchor")]
    InvalidPreimage,

    #[error("Context signature mismatch: Constant-time HMAC comparison failed")]
    InvalidContextSignature,

    #[error("RFC 8785 canonical serialization failure")]
    SerializationError,

    #[error("Lamport chain exhausted: Current index reached zero")]
    ChainExhausted,

    #[error("Monotonic sequence violation or replay attempt")]
    SequenceViolation,

    #[error("Internal operational failure or entropy depletion")]
    EntropyFailure,

    #[error("Challenge ticket expired: TTL window exceeded")]
    ChallengeExpired,

    #[error("Invalid challenge ticket signature")]
    InvalidChallenge,

    #[error("Proof-of-work difficulty requirement not satisfied")]
    InvalidProofOfWork,
}