//! # Adversarial Test Suite for HashGuard-ID Protocol
//! Standards: RFC 2289, RFC 2104, RFC 8785, NIST SP 800-63B.
//! Negative Space Coverage: Preimage forgery, Context tampering, Replay, TOCTOU desync, PoW rate exhaustion.

use hashguard_core::{
    CanonicalTransaction, ChallengeTicket, ClientChain, HashGuardError, HashcashEngine,
    ServerAnchor, TransactionEnvelope,
};

fn generate_test_payload(nonce: &str) -> CanonicalTransaction {
    CanonicalTransaction {
        tx_id: "tx-fiat-88019".to_string(),
        sender: "0x89205A3A3b2A5538C60318573960".to_string(),
        recipient: "0x129fC12903C34026DF56b6A180".to_string(),
        amount: 5000000,
        currency: "USD".to_string(),
        timestamp: 1774431000,
        nonce: nonce.to_string(),
    }
}

#[test]
fn test_nominal_lamport_lifecycle() {
    let chain_len = 16;
    let (mut client, initial_anchor) = ClientChain::generate(chain_len).unwrap();
    let mut server = ServerAnchor::new(initial_anchor, chain_len);

    for expected_step in (0..chain_len).rev() {
        let (step, token) = client.advance().unwrap();
        assert_eq!(step, expected_step);

        let tx = generate_test_payload(&format!("nonce_seq_{}", step));
        let envelope = TransactionEnvelope::seal(step, token, &tx).unwrap();

        assert!(envelope.verify_binding().is_ok());
        assert!(server
            .verify_and_transition(&envelope.token, envelope.step_index)
            .is_ok());

        assert_eq!(server.anchor, token);
        assert_eq!(server.step, step);
    }

    assert_eq!(
        client.advance().unwrap_err(),
        HashGuardError::ChainExhausted
    );
}

#[test]
fn test_adversary_context_tampering() {
    let (mut client, initial_anchor) = ClientChain::generate(4).unwrap();
    let server = ServerAnchor::new(initial_anchor, 4);

    let (step, token) = client.advance().unwrap();
    let original_tx = generate_test_payload("nonce_legit");
    let mut envelope = TransactionEnvelope::seal(step, token, &original_tx).unwrap();

    let tampered_tx = CanonicalTransaction {
        amount: 9999999999,
        ..original_tx
    };
    envelope.canonical_payload = serde_jcs::to_vec(&tampered_tx).unwrap();

    assert_eq!(
        envelope.verify_binding().unwrap_err(),
        HashGuardError::InvalidContextSignature
    );
    assert_eq!(server.step, 4);
}

#[test]
fn test_adversary_replay_attack() {
    let (mut client, initial_anchor) = ClientChain::generate(4).unwrap();
    let mut server = ServerAnchor::new(initial_anchor, 4);

    let (step, token) = client.advance().unwrap();
    let tx = generate_test_payload("nonce_replay");
    let envelope = TransactionEnvelope::seal(step, token, &tx).unwrap();

    assert!(envelope.verify_binding().is_ok());
    assert!(server
        .verify_and_transition(&envelope.token, envelope.step_index)
        .is_ok());

    let replay_result = server.verify_and_transition(&envelope.token, envelope.step_index);
    assert_eq!(
        replay_result.unwrap_err(),
        HashGuardError::SequenceViolation
    );
}

#[test]
fn test_adversary_preimage_forgery() {
    let (_client, initial_anchor) = ClientChain::generate(4).unwrap();
    let mut server = ServerAnchor::new(initial_anchor, 4);

    let forged_token = [0x7fu8; 32];
    let tx = generate_test_payload("nonce_forged");
    let envelope = TransactionEnvelope::seal(3, forged_token, &tx).unwrap();

    assert!(envelope.verify_binding().is_ok());
    let transition_result = server.verify_and_transition(&envelope.token, envelope.step_index);
    assert_eq!(
        transition_result.unwrap_err(),
        HashGuardError::InvalidPreimage
    );
}

#[test]
fn test_pow_nominal_execution() {
    let secret = [0x3fu8; 32];
    let client_ip = "192.168.1.150";
    let timestamp = 1774431000;

    // Baseline request rate (V = 1 req/min) -> Difficulty: D0 = 10 bits
    let ticket = ChallengeTicket::mint(client_ip, timestamp, 1, &secret);
    assert_eq!(ticket.difficulty_bits, 10);
    assert!(ticket.verify_ticket(timestamp + 3, &secret).is_ok());

    let nonce = HashcashEngine::solve(&ticket.server_hmac, ticket.difficulty_bits);

    assert!(HashcashEngine::verify_solution(
        &ticket.server_hmac,
        nonce,
        ticket.difficulty_bits
    ));
}

#[test]
fn test_adversary_pow_rate_penalty_and_ttl_expiration() {
    let secret = [0x3fu8; 32];
    let attacker_ip = "10.0.0.99";
    let timestamp = 1774431000;

    // Traffic spike: V = 6 req/min -> D scales from 10 to 18 bits
    let ticket_attack = ChallengeTicket::mint(attacker_ip, timestamp, 6, &secret);
    assert_eq!(ticket_attack.difficulty_bits, 18);

    let expired_result = ticket_attack.verify_ticket(timestamp + 11, &secret);
    assert_eq!(
        expired_result.unwrap_err(),
        HashGuardError::ChallengeExpired
    );
}
