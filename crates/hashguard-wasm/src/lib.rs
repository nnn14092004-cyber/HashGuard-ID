//! # HashGuard-ID WebAssembly Client Engine
//! Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (§5.1.3.2).
//! Invariants: In-memory CSPRNG entropy isolation, sub-millisecond Hashcash solver.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

const HKDF_CONTEXT_INFO: &[u8] = b"HashGuard-v1-Context-Enclosure-Key";
const HASH_LEN: usize = 32;

#[wasm_bindgen]
pub struct LamportKeychain {
    tokens: Vec<[u8; HASH_LEN]>,
    total_steps: usize,
    current_index: usize,
}

#[wasm_bindgen]
impl LamportKeychain {
    /// Generates a new Lamport reverse hash chain from 256-bit browser CSPRNG entropy.
    /// Complexity: O(N) where N = total_steps.
    #[wasm_bindgen(constructor)]
    pub fn new(total_steps: usize) -> Result<LamportKeychain, JsValue> {
        if total_steps == 0 || total_steps > 100_000 {
            return Err(JsValue::from_str("Invalid chain length: 1 <= N <= 100,000"));
        }

        let mut seed = [0u8; HASH_LEN];
        getrandom::getrandom(&mut seed)
            .map_err(|e| JsValue::from_str(&format!("CSPRNG hardware entropy failure: {}", e)))?;

        let mut tokens = Vec::with_capacity(total_steps + 1);
        tokens.push(seed);

        for i in 0..total_steps {
            let mut hasher = Sha256::new();
            hasher.update(&tokens[i]);
            let digest: [u8; HASH_LEN] = hasher.finalize().into();
            tokens.push(digest);
        }

        Ok(LamportKeychain {
            tokens,
            total_steps,
            current_index: total_steps,
        })
    }

    /// Exports the root Terminal Anchor H^N(S) for Gateway registration.
    #[wasm_bindgen]
    pub fn get_terminal_anchor_hex(&self) -> String {
        hex::encode(self.tokens[self.total_steps])
    }

    #[wasm_bindgen]
    pub fn get_remaining_steps(&self) -> usize {
        self.current_index
    }

    /// Advances the chain by one step and reveals token T_{k-1}.
    #[wasm_bindgen]
    pub fn advance_step(&mut self) -> Result<String, JsValue> {
        if self.current_index == 0 {
            return Err(JsValue::from_str("ERR_CHAIN_EXHAUSTED: k is already 0"));
        }
        self.current_index -= 1;
        Ok(hex::encode(self.tokens[self.current_index]))
    }

    /// Peeks at token T_{k-1} without decrementing the cursor.
    #[wasm_bindgen]
    pub fn peek_current_token_hex(&self) -> Result<String, JsValue> {
        if self.current_index == 0 {
            return Err(JsValue::from_str("ERR_CHAIN_EXHAUSTED"));
        }
        Ok(hex::encode(self.tokens[self.current_index - 1]))
    }
}

/// Solves Adaptive Hashcash Proof-of-Work against Gateway ticket HMAC.
/// Complexity: Average O(2^D) evaluations.
#[wasm_bindgen]
pub fn solve_adaptive_hashcash(ticket_hmac_hex: &str, difficulty_bits: u32) -> Result<u64, JsValue> {
    let ticket_hmac = hex::decode(ticket_hmac_hex)
        .map_err(|_| JsValue::from_str("Malformed ticket HMAC hex"))?;

    if ticket_hmac.len() != HASH_LEN {
        return Err(JsValue::from_str("Invalid ticket HMAC length"));
    }

    let mask: u32 = if difficulty_bits == 0 {
        0
    } else {
        ((1u64 << 32) - 1) as u32 ^ ((1u64 << (32 - difficulty_bits)) - 1) as u32
    };

    let mut nonce: u64 = 0;
    let mut buffer = [0u8; 40]; // 32 bytes ticket + 8 bytes nonce
    buffer[..32].copy_from_slice(&ticket_hmac);

    loop {
        buffer[32..].copy_from_slice(&nonce.to_be_bytes());
        let digest = Sha256::digest(&buffer);
        let prefix = u32::from_be_bytes(digest[..4].try_into().unwrap());

        if (prefix & mask) == 0 {
            return Ok(nonce);
        }
        nonce += 1;
    }
}

/// Derives context key via RFC 5869 (HKDF) and produces RFC 2104 HMAC-SHA256 signature.
/// Enforces canonical deterministic serialization (RFC 8785 JCS).
#[wasm_bindgen]
pub fn sign_transaction_envelope(
    token_hex: &str,
    canonical_json: &str,
) -> Result<String, JsValue> {
    let token_bytes: [u8; HASH_LEN] = hex::decode(token_hex)
        .map_err(|_| JsValue::from_str("Malformed token hex"))?
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid token length"))?;

    let parsed_val: serde_json::Value = serde_json::from_str(canonical_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;

    let canonical_bytes = serde_jcs::to_vec(&parsed_val)
        .map_err(|e| JsValue::from_str(&format!("RFC 8785 canonicalization failed: {}", e)))?;

    let mut prehasher = Sha256::new();
    prehasher.update(&canonical_bytes);
    let payload_digest = prehasher.finalize();

    // RFC 5869 HKDF-Extract & Expand
    let hk = Hkdf::<Sha256>::new(None, &token_bytes);
    let mut context_key = [0u8; HASH_LEN];
    hk.expand(HKDF_CONTEXT_INFO, &mut context_key)
        .map_err(|_| JsValue::from_str("HKDF expansion failure"))?;

    let mut mac = HmacSha256::new_from_slice(&context_key)
        .map_err(|_| JsValue::from_str("HMAC key initialization failure"))?;
    mac.update(&payload_digest);
    let signature = mac.finalize().into_bytes();

    Ok(hex::encode(signature))
}