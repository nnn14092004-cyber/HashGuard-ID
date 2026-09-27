//! # Distributed Atomic State Store (Redis CAS Engine)
//! Standards: RFC 2289, RFC 2104, NIST SP 800-63B (§5.1.3.2), Redis Cluster Specification.
//! Guarantees: Zero-TOCTOU, O(1) complexity, Cluster Hash Slot Alignment via Hash Tags.

use crate::HashGuardError;
use redis::aio::ConnectionLike;
use redis::{AsyncCommands, Script};
use sha2::{Digest, Sha256};

pub const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;

pub struct RedisAnchorStore {
    cas_script: Script,
}

impl RedisAnchorStore {
    pub fn new() -> Self {
        let script_source = include_str!("../scripts/anchor_cas.lua");
        Self {
            cas_script: Script::new(script_source),
        }
    }

    pub async fn initialize_user<C>(
        &self,
        con: &mut C,
        account_id: &str,
        anchor: &[u8; 32],
        total_steps: usize,
    ) -> Result<(), HashGuardError>
    where
        C: AsyncCommands,
    {
        // Enforce Redis Cluster Hash Tag
        let state_key = format!("{{hashguard:user:{}}}:state", account_id);
        let anchor_hex = hex::encode(anchor);

        let () = con
            .hset_multiple(
                &state_key,
                &[("anchor", &anchor_hex), ("step", &total_steps.to_string())],
            )
            .await
            .map_err(|_| HashGuardError::EntropyFailure)?;

        Ok(())
    }

    pub async fn atomic_verify_and_advance<C>(
        &self,
        con: &mut C,
        account_id: &str,
        token: &[u8; 32],
        step_index: usize,
        nonce: &str,
    ) -> Result<usize, HashGuardError>
    where
        C: ConnectionLike + Send,
    {
        let mut hasher = Sha256::new();
        hasher.update(token);
        let expected_anchor: [u8; 32] = hasher.finalize().into();

        let expected_anchor_hex = hex::encode(expected_anchor);
        let token_hex = hex::encode(token);

        // Both keys share the exact same hash tag {hashguard:user:<id>}, eliminating CROSSSLOT errors
        let state_key = format!("{{hashguard:user:{}}}:state", account_id);
        let nonce_key = format!("{{hashguard:user:{}}}:nonce:{}", account_id, nonce);

        let result: Result<(i32, usize), redis::RedisError> = self
            .cas_script
            .key(state_key)
            .key(nonce_key)
            .arg(expected_anchor_hex)
            .arg(token_hex)
            .arg(step_index)
            .arg(nonce)
            .arg(DEFAULT_NONCE_TTL_SECONDS)
            .invoke_async(con)
            .await;

        match result {
            Ok((_, remaining_step)) => Ok(remaining_step),
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("ERR_REPLAY_ATTACK_DETECTED")
                    || err_msg.contains("ERR_SEQUENCE_VIOLATION")
                {
                    Err(HashGuardError::SequenceViolation)
                } else if err_msg.contains("ERR_PREIMAGE_MISMATCH") {
                    Err(HashGuardError::InvalidPreimage)
                } else {
                    Err(HashGuardError::EntropyFailure)
                }
            }
        }
    }
}

impl Default for RedisAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}
