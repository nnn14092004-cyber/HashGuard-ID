//! # Integration Tests for HashGuard-ID Edge Verification Gateway
//! Standards: RFC 2289, RFC 2104, RFC 5869, RFC 8785, NIST SP 800-63B (§5.1.3.2).
//! Scope: Socket buffer limits, HTTP envelope validation, stateless PoW verification.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hashguard_core::{ChallengeTicket, HashcashEngine};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[tokio::test]
async fn test_gateway_enforce_payload_size_limit() {
    let app = axum::Router::new()
        .route("/v1/challenge", axum::routing::post(|_: axum::Json<serde_json::Value>| async {
            StatusCode::OK
        }))
        .layer(axum::extract::DefaultBodyLimit::max(2048));

    // Construct oversized payload (> 2048 bytes) to verify socket buffer protection
    let large_garbage = "A".repeat(4096);
    let oversized_payload = json!({
        "client_ip": "127.0.0.1",
        "velocity_rpm": 1,
        "padding": large_garbage
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/challenge")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&oversized_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Gateway must strictly reject payloads exceeding 2048 bytes"
    );
}

#[test]
fn test_stateless_pow_evaluation_cycle() {
    let ephemeral_secret = [0x5Au8; 32];
    let client_ip = "192.168.1.100";
    let now = 1774431000u64;
    let difficulty = 10u32;

    // 1. Mint stateless ticket: O(1) time and memory
    let ticket = ChallengeTicket::mint(client_ip, now, 1, &ephemeral_secret);
    assert_eq!(ticket.difficulty_bits, difficulty);

    // 2. Solve PoW: O(2^D) search space
    let mask: u32 = ((1u64 << 32) - 1) as u32 ^ ((1u64 << (32 - difficulty)) - 1) as u32;
    let mut nonce = 0u64;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(&ticket.server_hmac);
        hasher.update(&nonce.to_be_bytes());
        let digest = hasher.finalize();
        let prefix = u32::from_be_bytes(digest[..4].try_into().unwrap());

        if (prefix & mask) == 0 {
            break;
        }
        nonce += 1;
    }

    // 3. Verify solution on server side in O(1)
    let is_valid = HashcashEngine::verify_solution(&ticket.server_hmac, nonce, difficulty);
    assert!(is_valid, "Server must accept valid Hashcash solution");
}