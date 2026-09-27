//! # HashGuard-ID Core Cryptographic Protocol Library
//! Standards   : RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (§5.1.3.2)
//! Guarantees  : Zero-Telecom Surcharge ($0.0000 USD), Anti-AIT Toll Fraud Mitigation,
//!               Hardware-Accelerated Lamport CAS Engine, Constant-Time Side-Channel Immunity.

pub mod chain;
pub mod context;
pub mod pipeline;
pub mod pow;
pub mod storage;

use std::fmt;

/// Unified cryptographic, protocol, and state-machine error enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashGuardError {
    EntropyFailure,
    ChainExhausted,
    SequenceViolation,
    InvalidPreimage,
    LookaheadExceeded,
    ReplayAttack,
    StateNotFound,
    DistributedLockError(String),
    SerializationError,
    InvalidContextSignature,
    ChallengeExpired,
    InvalidChallenge,
    InvalidProofOfWork,
}

impl fmt::Display for HashGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyFailure => write!(f, "CRYPTOGRAPHIC_ENTROPY_FAILURE"),
            Self::ChainExhausted => write!(f, "ERR_CHAIN_EXHAUSTED"),
            Self::SequenceViolation => write!(f, "ERR_SEQUENCE_VIOLATION"),
            Self::InvalidPreimage => write!(f, "ERR_PREIMAGE_MISMATCH"),
            Self::LookaheadExceeded => write!(f, "ERR_LOOKAHEAD_EXCEEDED"),
            Self::ReplayAttack => write!(f, "ERR_NONCE_REPLAY"),
            Self::StateNotFound => write!(f, "ERR_USER_NOT_FOUND"),
            Self::DistributedLockError(msg) => write!(f, "ERR_DISTRIBUTED_STATE_FAILURE: {}", msg),
            Self::SerializationError => write!(f, "ERR_CANONICALIZATION_FAILED"),
            Self::InvalidContextSignature => write!(f, "ERR_INVALID_CONTEXT_SIGNATURE"),
            Self::ChallengeExpired => write!(f, "ERR_CHALLENGE_EXPIRED"),
            Self::InvalidChallenge => write!(f, "ERR_INVALID_CHALLENGE"),
            Self::InvalidProofOfWork => write!(f, "ERR_INVALID_PROOF_OF_WORK"),
        }
    }
}

impl std::error::Error for HashGuardError {}

// Re-export core primitives for downstream integration tests
pub use chain::{ClientChain, ServerAnchor};
pub use context::{CanonicalTransaction, TransactionEnvelope};
pub use pipeline::{ProtocolPipeline, VerificationRequest};
pub use pow::{ChallengeTicket, HashcashEngine};
pub use storage::RedisAnchorStore;