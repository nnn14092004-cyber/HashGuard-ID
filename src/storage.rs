//! # Distributed Atomic State Store (Redis CAS Engine)
//! Guarantees: Zero-TOCTOU, O(1) time complexity, strictly monotonic sequence progression.

use crate::HashGuardError;
use redis::aio::ConnectionLike;
use redis::{AsyncCommands, Script};
use sha2::{Digest, Sha256};

pub const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;

/// Atomic storage adapter for state anchors.
pub struct RedisAnchorStore {
    cas_script: Script,
}

impl RedisAnchorStore {
    /// Compiles and caches the atomic CAS Lua script.
    pub fn new() -> Self {
        let script_source = include_str!("../scripts/anchor_cas.lua");
        Self {
            cas_script: Script::new(script_source),
        }
    }

    /// Initializes a user anchor state in Redis.
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
        let key = format!("hashguard:anchor:{}", account_id);
        let anchor_hex = hex::encode(anchor);

        let () = con
            .hset_multiple(&key, &[("anchor", &anchor_hex), ("step", &total_steps.to_string())])
            .await
            .map_err(|_| HashGuardError::EntropyFailure)?;

        Ok(())
    }

    /// Executes atomic CAS verification and advance.
    /// Time Complexity: O(1)
    /// Space Complexity: O(1)
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

        let state_key = format!("hashguard:anchor:{}", account_id);
        let nonce_key = format!("hashguard:nonce:{}", nonce);

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