//! # End-to-End Pipeline & SLA Benchmark Tests
//! Validates sub-millisecond core verification and anti-abuse escalation under complete protocol execution.

use hashguard_core::{
    CanonicalTransaction, ChallengeTicket, ClientChain, HashGuardError, HashcashEngine,
    ProtocolPipeline, TransactionEnvelope, VerificationRequest,
};

#[test]
fn test_end_to_end_nominal_lifecycle_and_sla() {
    let gateway_secret = [0x42u8; 32];
    let pipeline = ProtocolPipeline::new(gateway_secret);

    let client_ip = "192.168.1.50";
    let current_epoch = 1774431000;
    let chain_length = 100;

    // 1. Client initialization
    let (mut client_chain, mut server_anchor) = ClientChain::generate(chain_length).unwrap();
    let mut server_step = chain_length;

    // 2. Gateway issues challenge ticket (V = 1 req/min -> D = 10 bits)
    let ticket = ChallengeTicket::mint(client_ip, current_epoch, 1, &gateway_secret);

    // 3. Client solves PoW
    let client_solve_start = std::time::Instant::now();
    let pow_nonce = HashcashEngine::solve(&ticket.server_hmac, ticket.difficulty_bits);
    let client_solve_duration = client_solve_start.elapsed();

    // 4. Client advances Lamport chain and seals transaction
    let (step, token) = client_chain.advance().unwrap();
    let tx = CanonicalTransaction {
        tx_id: "tx-instant-transfer-007".to_string(),
        sender: "alice_wallet".to_string(),
        recipient: "bob_wallet".to_string(),
        amount: 15000000,
        currency: "USD".to_string(),
        timestamp: current_epoch,
        nonce: "unique_nonce_e2e_001".to_string(),
    };
    let envelope = TransactionEnvelope::seal(step, token, &tx).unwrap();

    let request = VerificationRequest {
        account_id: "alice_wallet".to_string(),
        ticket,
        pow_nonce,
        envelope,
        current_time_epoch: current_epoch + 1,
    };

    // 5. Server executes zero-trust verification pipeline
    let telemetry = pipeline
        .verify_and_advance(&request, &mut server_anchor, &mut server_step)
        .expect("End-to-End verification must succeed");

    println!("\n=======================================================");
    println!("HASHGUARD-ID PROTOCOL TELEMETRY REPORT (E2E SLA)");
    println!("=======================================================");
    println!("Client PoW Solve Time (D=10) : {:.3} ms", client_solve_duration.as_secs_f64() * 1000.0);
    println!("Server PoW Verification       : {:.3} µs", telemetry.pow_verification_nanos as f64 / 1000.0);
    println!("Server Context Verification   : {:.3} µs", telemetry.context_verification_nanos as f64 / 1000.0);
    println!("Server Total Core Execution   : {:.3} µs", telemetry.total_pipeline_nanos as f64 / 1000.0);
    println!("Total Protocol Processing     : {:.3} ms", (client_solve_duration.as_secs_f64() * 1000.0) + (telemetry.total_pipeline_nanos as f64 / 1_000_000.0));
    println!("Remaining Lamport Depth       : {}", telemetry.remaining_chain_depth);
    println!("=======================================================");

    // SLA Assertions: Spec.docx Item 3 requires latency < 20ms for legitimate traffic
    assert!(
        client_solve_duration.as_millis() < 20,
        "SLA Violation: Client PoW computation exceeded 20ms budget (Actual: {} ms)",
        client_solve_duration.as_millis()
    );
    assert!(
        telemetry.total_pipeline_nanos < 500_000, // < 0.5ms on server
        "Performance Regression: Server-side execution took longer than 500µs"
    );
    assert_eq!(server_step, 99);
}

#[test]
fn test_end_to_end_tampered_payload_rejection() {
    let gateway_secret = [0x42u8; 32];
    let pipeline = ProtocolPipeline::new(gateway_secret);

    let client_ip = "192.168.1.51";
    let current_epoch = 1774431000;
    let chain_length = 10;

    let (mut client_chain, mut server_anchor) = ClientChain::generate(chain_length).unwrap();
    let mut server_step = chain_length;

    let ticket = ChallengeTicket::mint(client_ip, current_epoch, 1, &gateway_secret);
    let pow_nonce = HashcashEngine::solve(&ticket.server_hmac, ticket.difficulty_bits);

    let (step, token) = client_chain.advance().unwrap();
    let original_tx = CanonicalTransaction {
        tx_id: "tx-tamper-target".to_string(),
        sender: "alice".to_string(),
        recipient: "bob".to_string(),
        amount: 100,
        currency: "USD".to_string(),
        timestamp: current_epoch,
        nonce: "nonce_tamper_001".to_string(),
    };
    let mut envelope = TransactionEnvelope::seal(step, token, &original_tx).unwrap();

    let forged_tx = CanonicalTransaction {
        amount: 999999,
        ..original_tx
    };
    envelope.canonical_payload = serde_jcs::to_vec(&forged_tx).unwrap();

    let request = VerificationRequest {
        account_id: "alice".to_string(),
        ticket,
        pow_nonce,
        envelope,
        current_time_epoch: current_epoch + 1,
    };

    let result = pipeline.verify_and_advance(&request, &mut server_anchor, &mut server_step);
    assert_eq!(result.unwrap_err(), HashGuardError::InvalidContextSignature);
    assert_eq!(server_step, 10);
}