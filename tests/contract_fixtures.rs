use asf::{
    contracts::RunmillSignedWorkOrderV1,
    crypto::{decode_verifying_key, sha256_digest},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureMetadata {
    public_key_base64url_no_pad: String,
    payload_digest: String,
    envelope_digest: String,
    signature: String,
}

#[test]
fn work_order_golden_fixture_is_stable_and_verifiable() {
    let bytes = include_bytes!("../contracts/fixtures/work-order-envelope-v1.json");
    let envelope: RunmillSignedWorkOrderV1 = serde_json::from_slice(bytes).unwrap();
    let metadata: FixtureMetadata = serde_json::from_slice(include_bytes!(
        "../contracts/fixtures/work-order-envelope-v1.meta.json"
    ))
    .unwrap();
    let key = decode_verifying_key(&metadata.public_key_base64url_no_pad).unwrap();
    let admission_time = DateTime::parse_from_rfc3339("2026-08-21T10:01:00Z")
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(envelope.payload_digest().unwrap(), metadata.payload_digest);
    assert_eq!(
        envelope.envelope_digest().unwrap(),
        metadata.envelope_digest
    );
    assert_eq!(envelope.signature, metadata.signature);
    assert_eq!(
        envelope.payload_digest().unwrap(),
        sha256_digest(&envelope.payload.canonical_bytes().unwrap())
    );
    envelope.verify(&key, admission_time).unwrap();
}

#[test]
fn unknown_authority_field_and_tampering_fail_closed() {
    let bytes = include_bytes!("../contracts/fixtures/work-order-envelope-v1.json");
    let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    value["payload"]["runtime"]["credential"] = serde_json::json!("forbidden");
    assert!(serde_json::from_value::<RunmillSignedWorkOrderV1>(value).is_err());

    let mut envelope: RunmillSignedWorkOrderV1 = serde_json::from_slice(bytes).unwrap();
    envelope.payload.budgets.max_cost_usd += 1.0;
    let metadata: FixtureMetadata = serde_json::from_slice(include_bytes!(
        "../contracts/fixtures/work-order-envelope-v1.meta.json"
    ))
    .unwrap();
    let key = decode_verifying_key(&metadata.public_key_base64url_no_pad).unwrap();
    assert!(envelope.verify_integrity(&key).is_err());
}
