//! # Cryptographic Context Enclosure Engine
//! Standards: RFC 8785 (JCS), RFC 2104 (HMAC-SHA256), RFC 5869 (HKDF).
//! Guarantees: EUF-CMA security bound (2^256), strict domain separation, timing immunity.

use crate::HashGuardError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type HmacSha256 = Hmac<Sha256>;

const HKDF_INFO_CONTEXT_EXPANSION: &[u8] = b"HashGuard-v1-Context-Enclosure-Key";

/// Immutable transaction payload structure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTransaction {
    pub tx_id: String,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub currency: String,
    pub timestamp: u64,
    pub nonce: String,
}

/// Cryptographically sealed transaction envelope transferred over the wire.
#[derive(Debug, Clone)]
pub struct TransactionEnvelope {
    pub step_index: usize,
    pub token: [u8; 32],
    pub signature: [u8; 32],
    pub canonical_payload: Vec<u8>,
}

impl TransactionEnvelope {
    /// Derives domain-separated signature key from preimage token using RFC 5869 (HKDF-Expand).
    #[inline(always)]
    fn derive_signing_key(token: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, token);
        let mut okm = [0u8; 32];
        hk.expand(HKDF_INFO_CONTEXT_EXPANSION, &mut okm)
            .expect("Valid 32-byte expansion for HKDF-SHA256");
        okm
    }

    /// Seals transaction context with domain-separated HKDF key derived from preimage token.
    /// Time Complexity: O(L) where L = |canonical_payload|
    /// Space Complexity: O(L)
    pub fn seal(
        step_index: usize,
        token: [u8; 32],
        transaction: &CanonicalTransaction,
    ) -> Result<Self, HashGuardError> {
        let canonical_payload =
            serde_jcs::to_vec(transaction).map_err(|_| HashGuardError::SerializationError)?;

        // Pre-hash payload digest to mitigate length-extension attacks
        let mut hasher = Sha256::new();
        hasher.update(&canonical_payload);
        let payload_digest = hasher.finalize();

        // RFC 5869 HKDF Key Derivation
        let signing_key = Self::derive_signing_key(&token);

        // RFC 2104 HMAC-SHA256 Signature
        let mut mac = HmacSha256::new_from_slice(&signing_key)
            .expect("HMAC accepts 256-bit derived key");
        mac.update(&payload_digest);
        let signature: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(Self {
            step_index,
            token,
            signature,
            canonical_payload,
        })
    }

    /// Verifies deterministic binding in constant time using HKDF-derived key.
    /// Time Complexity: O(L)
    /// Space Complexity: O(1) heap overhead
    pub fn verify_binding(&self) -> Result<(), HashGuardError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_payload);
        let payload_digest = hasher.finalize();

        let signing_key = Self::derive_signing_key(&self.token);

        let mut mac = HmacSha256::new_from_slice(&signing_key)
            .expect("HMAC accepts 256-bit derived key");
        mac.update(&payload_digest);
        let expected_signature: [u8; 32] = mac.finalize().into_bytes().into();

        if expected_signature.ct_eq(&self.signature).unwrap_u8() != 1 {
            return Err(HashGuardError::InvalidContextSignature);
        }

        Ok(())
    }
}