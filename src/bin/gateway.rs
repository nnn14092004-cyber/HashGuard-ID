//! # HashGuard-ID Production Edge Verification Gateway
//! Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (§5.1.3.2).
//! Architecture: Zero-Telecom, Stateless Challenge Minting, Hardware-Offloaded Delta-Lookahead CAS.

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use hashguard_core::{chain::HASH_OUTPUT_LENGTH, ChallengeTicket, HashGuardError, HashcashEngine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_PAYLOAD_BYTES: usize = 2048; // Hard socket buffer limit (anti-exhaustion)
pub const MAX_LOOKAHEAD_STEPS: usize = 5; // Bounded packet loss desync tolerance: Delta <= 5
pub const NONCE_TTL_SECONDS: usize = 300; // 5-minute replay prevention lock

const HKDF_CONTEXT_INFO: &[u8] = b"HashGuard-v1-Context-Enclosure-Key";

fn default_user_id() -> String {
    "default_user".to_string()
}

/// Atomic Redis Lua CAS Script with Hardware-Offloaded Lookahead & Silent Re-anchoring.
/// Complexity: O(1) time, O(1) space on Redis single-threaded engine.
const LUA_HARDENED_CAS_SCRIPT: &str = r#"
local user_id = KEYS[1]
local claimed_step = tonumber(ARGV[1])
local claimed_token = ARGV[2]
local nonce = ARGV[3]
local nonce_ttl = tonumber(ARGV[4])
local max_lookahead = tonumber(ARGV[5])
local next_anchor = ARGV[6]
local next_steps = tonumber(ARGV[7])

local anchor_key = "user:" .. user_id .. ":anchor"
local step_key = "user:" .. user_id .. ":step"
local nonce_key = "nonce:" .. nonce
local pending_anchor_key = "user:" .. user_id .. ":pending_anchor"
local pending_step_key = "user:" .. user_id .. ":pending_step"

-- 1. Enforce Nonce Replay Immunity
if redis.call("EXISTS", nonce_key) == 1 then
    return redis.error_reply("ERR_NONCE_REPLAY")
end

-- 2. Verify Identity Existence & Monotonic Sequence Descent
local current_step = tonumber(redis.call("GET", step_key))
if not current_step then
    return redis.error_reply("ERR_USER_NOT_FOUND")
end

if claimed_step >= current_step then
    return redis.error_reply("ERR_SEQUENCE_VIOLATION")
end

-- 3. Assert Bounded Lookahead Window
local delta = current_step - claimed_step
if delta > max_lookahead then
    return redis.error_reply("ERR_LOOKAHEAD_EXCEEDED")
end

-- 4. O(1) Anchor Matching via Offloaded Precomputed Candidates: ARGV[7 + delta]
local expected_anchor = ARGV[7 + delta]
local current_anchor = redis.call("GET", anchor_key)

if expected_anchor ~= current_anchor then
    return redis.error_reply("ERR_PREIMAGE_MISMATCH")
end

-- 5. Atomic State Transition
redis.call("SET", anchor_key, claimed_token)
redis.call("SET", step_key, claimed_step)
redis.call("SET", nonce_key, "1", "EX", nonce_ttl)

-- 6. Register Piggybacked Successor Anchor (Silent Re-anchoring)
if next_anchor and #next_anchor == 64 and next_steps and next_steps > 0 then
    redis.call("SET", pending_anchor_key, next_anchor)
    redis.call("SET", pending_step_key, next_steps)
end

-- 7. Atomic Chain Rollover when Claimed Step reaches Terminal Boundary (k = 0)
if claimed_step == 0 then
    local p_anchor = redis.call("GET", pending_anchor_key)
    local p_steps = tonumber(redis.call("GET", pending_step_key))
    if p_anchor and p_steps and p_steps > 0 then
        redis.call("SET", anchor_key, p_anchor)
        redis.call("SET", step_key, p_steps)
        redis.call("DEL", pending_anchor_key)
        redis.call("DEL", pending_step_key)
        return {p_steps, p_anchor, "ROLLED_OVER_ATOMIC"}
    end
end

return {claimed_step, claimed_token, "COMMITTED_ATOMIC"}
"#;

pub struct GatewayState {
    pub ephemeral_secret: [u8; 32],
    pub redis_client: redis::Client,
}

#[derive(Deserialize)]
pub struct EnrollRequestPayload {
    #[serde(default = "default_user_id")]
    pub user_id: String,
    pub terminal_anchor: String,
    pub total_steps: usize,
}

#[derive(Serialize)]
pub struct EnrollResponsePayload {
    pub status: &'static str,
    pub user_id: String,
    pub enrolled_step: usize,
}

#[derive(Deserialize)]
pub struct ChallengeRequestPayload {
    pub client_ip: String,
    pub velocity_rpm: u32,
}

#[derive(Serialize)]
pub struct ChallengeResponsePayload {
    pub client_ip: String,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub ticket_hmac: String,
}

#[derive(Deserialize)]
pub struct VerifyRequestPayload {
    #[serde(default = "default_user_id")]
    pub user_id: String,
    pub client_ip: String,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub ticket_hmac: String,
    pub pow_nonce: u64,
    pub step_index: usize,
    pub token: String,
    pub signature: String,
    #[serde(default)]
    pub nonce: String,
    pub canonical_payload: serde_json::Value,
}

#[derive(Serialize)]
pub struct VerifyResponsePayload {
    pub status: String,
    pub remaining_step: usize,
    pub server_execution_micros: f64,
}

pub async fn enroll_handler(
    State(state): State<Arc<GatewayState>>,
    Json(payload): Json<EnrollRequestPayload>,
) -> Result<Json<EnrollResponsePayload>, (StatusCode, String)> {
    if payload.terminal_anchor.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Terminal anchor must be 32 bytes hex".into(),
        ));
    }

    let mut conn = state
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis connection error: {}", e),
            )
        })?;

    let anchor_key = format!("user:{}:anchor", payload.user_id);
    let step_key = format!("user:{}:step", payload.user_id);
    let anchor_hex = payload.terminal_anchor.to_lowercase();

    redis::pipe()
        .atomic()
        .set(&anchor_key, &anchor_hex)
        .set(&step_key, payload.total_steps)
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis pipeline write failure: {}", e),
            )
        })?;

    Ok(Json(EnrollResponsePayload {
        status: "ENROLLED_ATOMIC",
        user_id: payload.user_id,
        enrolled_step: payload.total_steps,
    }))
}

pub async fn mint_challenge_handler(
    State(state): State<Arc<GatewayState>>,
    Json(payload): Json<ChallengeRequestPayload>,
) -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ticket = ChallengeTicket::mint(
        &payload.client_ip,
        now,
        payload.velocity_rpm,
        &state.ephemeral_secret,
    );

    (
        StatusCode::OK,
        Json(ChallengeResponsePayload {
            client_ip: ticket.client_ip,
            timestamp: ticket.timestamp,
            difficulty_bits: ticket.difficulty_bits,
            ticket_hmac: hex::encode(ticket.server_hmac),
        }),
    )
}

pub async fn verify_transaction_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<VerifyRequestPayload>,
) -> Result<Json<VerifyResponsePayload>, (StatusCode, String)> {
    let start_instant = std::time::Instant::now();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Decode byte representations
    let ticket_hmac_bytes: [u8; 32] = hex::decode(&req.ticket_hmac)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Malformed ticket HMAC".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid ticket HMAC length".into()))?;

    let token_bytes: [u8; 32] = hex::decode(&req.token)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Malformed token hex".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid token length".into()))?;

    let signature_bytes: [u8; 32] = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Malformed signature hex".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length".into()))?;

    // 2. Stateless Proof-of-Work Verification (Spec Item 3)
    let ticket = ChallengeTicket {
        client_ip: req.client_ip,
        timestamp: req.timestamp,
        difficulty_bits: req.difficulty_bits,
        server_hmac: ticket_hmac_bytes,
    };

    ticket
        .verify_ticket(current_time, &state.ephemeral_secret)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    if !HashcashEngine::verify_solution(&ticket.server_hmac, req.pow_nonce, ticket.difficulty_bits)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid Proof-of-Work solution".into(),
        ));
    }

    // 3. Cryptographic Context Verification: RFC 8785 JCS + RFC 5869 HKDF + RFC 2104 HMAC (Spec Item 1)
    let canonical_bytes = serde_jcs::to_vec(&req.canonical_payload).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "RFC 8785 Canonicalization failed".into(),
        )
    })?;

    let mut prehasher = Sha256::new();
    prehasher.update(&canonical_bytes);
    let payload_digest = prehasher.finalize();

    let hk = Hkdf::<Sha256>::new(None, &token_bytes);
    let mut signing_key = [0u8; 32];
    hk.expand(HKDF_CONTEXT_INFO, &mut signing_key)
        .expect("Valid 32-byte expansion");

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(&payload_digest);
    let expected_signature: [u8; 32] = mac.finalize().into_bytes().into();

    if expected_signature.ct_eq(&signature_bytes).unwrap_u8() != 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            HashGuardError::InvalidContextSignature.to_string(),
        ));
    }

    // 4. Precompute Lookahead Hashes on Gateway CPU (Hardware SHA-NI Accelerated)
    // Candidate[d] = H^d(token_bytes), d in [1, MAX_LOOKAHEAD_STEPS]
    let mut lookahead_hashes = Vec::with_capacity(MAX_LOOKAHEAD_STEPS);
    let mut cursor = token_bytes;
    for _ in 0..MAX_LOOKAHEAD_STEPS {
        let mut hasher = Sha256::new();
        hasher.update(cursor);
        let digest: [u8; HASH_OUTPUT_LENGTH] = hasher.finalize().into();
        lookahead_hashes.push(hex::encode(digest));
        cursor = digest;
    }

    // Derive deterministic fallback nonce if empty
    let effective_nonce = if req.nonce.is_empty() {
        hex::encode(&signature_bytes[..16])
    } else {
        req.nonce
    };

    let next_anchor = req
        .canonical_payload
        .get("next_anchor")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let next_steps = req
        .canonical_payload
        .get("next_total_steps")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // 5. Atomic Redis Lua CAS Execution (Spec Item 2)
    let mut conn = state
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis disconnected: {}", e),
            )
        })?;

    let script = redis::Script::new(LUA_HARDENED_CAS_SCRIPT);
    let mut invocation = script.key(&req.user_id);
    invocation
        .arg(req.step_index)
        .arg(req.token.to_lowercase())
        .arg(&effective_nonce)
        .arg(NONCE_TTL_SECONDS)
        .arg(MAX_LOOKAHEAD_STEPS)
        .arg(next_anchor)
        .arg(next_steps);

    for candidate in &lookahead_hashes {
        invocation.arg(candidate);
    }

    let result: Result<(usize, String, String), redis::RedisError> =
        invocation.invoke_async(&mut conn).await;

    match result {
        Ok((committed_step, _, status_msg)) => {
            let execution_micros = start_instant.elapsed().as_nanos() as f64 / 1000.0;
            Ok(Json(VerifyResponsePayload {
                status: status_msg,
                remaining_step: committed_step,
                server_execution_micros: execution_micros,
            }))
        }
        Err(err) => {
            let err_str = err.to_string();
            if err_str.contains("ERR_SEQUENCE_VIOLATION") {
                Err((StatusCode::CONFLICT, "ERR_SEQUENCE_VIOLATION".into()))
            } else if err_str.contains("ERR_NONCE_REPLAY") {
                Err((StatusCode::CONFLICT, "ERR_NONCE_REPLAY".into()))
            } else if err_str.contains("ERR_LOOKAHEAD_EXCEEDED") {
                Err((StatusCode::CONFLICT, "ERR_LOOKAHEAD_EXCEEDED".into()))
            } else if err_str.contains("ERR_PREIMAGE_MISMATCH") {
                Err((StatusCode::UNAUTHORIZED, "ERR_PREIMAGE_MISMATCH".into()))
            } else if err_str.contains("ERR_USER_NOT_FOUND") {
                Err((StatusCode::NOT_FOUND, "ERR_USER_NOT_FOUND".into()))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Redis CAS failure: {}", err),
                ))
            }
        }
    }
}

pub fn create_gateway_app(state: Arc<GatewayState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/v1/enroll", post(enroll_handler))
        .route("/v1/challenge", post(mint_challenge_handler))
        .route("/v1/verify", post(verify_transaction_handler))
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_BYTES))
        .layer(cors)
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let mut ephemeral_secret = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_secret).expect("CSPRNG failure");

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis_client =
        redis::Client::open(redis_url.clone()).expect("Failed to initialize Redis client");

    match redis_client.get_async_connection().await {
        Ok(_) => println!(
            "[+] Connected to Distributed Redis State Engine at: {}",
            redis_url
        ),
        Err(e) => {
            eprintln!("[-] Fatal: Cannot connect to Redis at {}: {}", redis_url, e);
            std::process::exit(1);
        }
    }

    let state = Arc::new(GatewayState {
        ephemeral_secret,
        redis_client,
    });

    let app = create_gateway_app(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    println!("=======================================================");
    println!("HASHGUARD-ID GATEWAY (LOOKAHEAD & RE-ANCHORING ACTIVE)");
    println!("=======================================================");
    println!("Listening on             : http://{}", addr);
    println!("Max Lookahead Steps (Δ)  : {} hops", MAX_LOOKAHEAD_STEPS);
    println!("Silent Rollover Support  : Enabled (k = 0 Atomic Transition)");
    println!("Distributed State Engine : Redis Lua (0 TOCTOU)");
    println!("Standards Compliance     : RFC 2289, RFC 2104, RFC 5869, RFC 8785");
    println!("=======================================================");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
