use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    Error, Result,
    crypto::{canonical_json, decode_verifying_key, sha256_digest, verify_signature},
    security::reject_sensitive_fields,
};

pub const ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA: &str = "asf.terminal-evidence/v1";
pub const ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA: &str = "asf.signed-terminal-evidence/v1";
pub const ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE: &str =
    "https://runmill.dev/attestations/asf-terminal-evidence/v1";
pub const ASF_TERMINAL_IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceRun {
    pub run_id: String,
    pub work_order_id: String,
    pub attempt_id: String,
    pub terminal_phase: String,
    pub terminal_event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceSignatureVerification {
    pub verified: bool,
    pub key_id: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceAdmission {
    pub work_order_envelope_digest: String,
    pub work_order_payload_digest: String,
    pub effective_policy_digest: String,
    pub work_order_envelope: JsonValue,
    pub signature_verification: AsfTerminalEvidenceSignatureVerification,
    pub effective_policy: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceSource {
    pub repository: String,
    pub base_sha: String,
    pub candidate_sha: Option<String>,
    pub subject_kind: String,
    pub subject_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalStopEvidence {
    pub code: String,
    pub summary: String,
    pub interrupted_phase: String,
    pub retry_disposition: String,
    pub required_actor: String,
    pub required_action: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceBudget {
    pub wall_seconds_limit: u64,
    pub max_cost_usd: f64,
    pub max_agent_invocations: u64,
    pub max_fix_iterations: u64,
    pub observed_fix_iterations: u64,
    pub evidence_refs: Vec<String>,
    pub provider_usage: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceTiming {
    pub admitted_at: String,
    pub terminal_evidence_at: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceCleanup {
    pub intent_id: String,
    pub intent_digest: String,
    pub observation_digest: String,
    pub identity_leases: String,
    pub repository_lease: String,
    pub workspace: String,
    pub unresolved_effects: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceEvidence {
    pub preceding_event_count: u64,
    pub preceding_event_chain_digest: String,
    pub observations: Vec<JsonValue>,
    pub events: Vec<JsonValue>,
    pub delivery_bundle_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceCancellation {
    pub request_id: String,
    pub event_type: String,
    pub requester_subject: String,
    pub reason_digest: String,
    pub mode: String,
    pub grace_seconds: u64,
    pub requested_at: String,
    pub event_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidencePredicate {
    pub schema: String,
    pub run: AsfTerminalEvidenceRun,
    pub admission: AsfTerminalEvidenceAdmission,
    pub source: AsfTerminalEvidenceSource,
    pub stop: AsfTerminalStopEvidence,
    pub cancellation: Option<AsfTerminalEvidenceCancellation>,
    pub budget: AsfTerminalEvidenceBudget,
    pub side_effects: JsonValue,
    pub timing: AsfTerminalEvidenceTiming,
    pub cleanup: AsfTerminalEvidenceCleanup,
    pub evidence: AsfTerminalEvidenceEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceSubject {
    pub name: String,
    pub digest: serde_json::Map<String, JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceStatement {
    #[serde(rename = "_type")]
    pub type_field: String,
    pub subject: Vec<AsfTerminalEvidenceSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: AsfTerminalEvidencePredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAsfTerminalEvidenceBundle {
    pub schema: String,
    pub key_id: String,
    pub algorithm: String,
    pub issued_at: String,
    pub bundle_digest: String,
    pub statement: AsfTerminalEvidenceStatement,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedAsfTerminalEvidenceView {
    schema: String,
    key_id: String,
    algorithm: String,
    issued_at: String,
    bundle_digest: String,
    statement: AsfTerminalEvidenceStatement,
}

/// Expected bindings for semantic verification of terminal evidence.
/// Used by `verify_expected_bindings` to enforce exact matching of external Runmill IDs,
/// admission details, source artifacts, and cleanup state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsfTerminalEvidenceExpectation {
    /// External Runmill run identifier
    pub run_id: String,
    /// External Runmill work order identifier
    pub work_order_id: String,
    /// External Runmill attempt identifier
    pub attempt_id: String,
    /// Expected terminal phase (e.g., "COMPLETED", "FAILED", "CANCELLED")
    pub terminal_phase: String,
    /// Expected terminal event sequence number
    pub terminal_event_seq: u64,
    /// Expected admission work order envelope digest
    pub work_order_envelope_digest: String,
    /// Expected admission work order payload digest
    pub work_order_payload_digest: String,
    /// Expected admission effective policy digest
    pub effective_policy_digest: String,
    /// Expected admission signature verification key id
    pub admission_key_id: String,
    /// Expected source repository identifier
    pub source_repository: String,
    /// Expected source base SHA
    pub source_base_sha: String,
    /// Expected source candidate SHA (optional)
    pub source_candidate_sha: Option<String>,
    /// Expected cleanup observation digest
    pub cleanup_observation_digest: String,
    /// Expected delivery bundle digest (optional, required for COMPLETED phase)
    pub delivery_bundle_digest: Option<String>,
}

impl SignedAsfTerminalEvidenceBundle {
    /// Parse a JSON object into a `SignedAsfTerminalEvidenceBundle` with wire integrity checks.
    /// This is a WIRE PARSER ONLY: it validates shape and cryptographic integrity,
    /// not semantic authorization or closure state.
    pub fn from_json(value: &JsonValue) -> Result<Self> {
        reject_sensitive_fields(value)?;

        let bundle: SignedAsfTerminalEvidenceBundle = serde_json::from_value(value.clone())
            .map_err(|e| {
                Error::Validation(format!("failed to parse terminal evidence bundle: {e}"))
            })?;

        DateTime::parse_from_rfc3339(&bundle.issued_at)
            .map_err(|e| Error::Validation(format!("invalid issued_at RFC3339 timestamp: {e}")))?;

        // Validate outer schema
        if bundle.schema != ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA {
            return Err(Error::Validation(format!(
                "invalid bundle schema: expected '{}', got '{}'",
                ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA, bundle.schema
            )));
        }

        // Validate statement type and predicate type
        if bundle.statement.type_field != ASF_TERMINAL_IN_TOTO_STATEMENT_V1 {
            return Err(Error::Validation(format!(
                "invalid statement type: expected '{}', got '{}'",
                ASF_TERMINAL_IN_TOTO_STATEMENT_V1, bundle.statement.type_field
            )));
        }

        if bundle.statement.predicate_type != ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE {
            return Err(Error::Validation(format!(
                "invalid predicate type: expected '{}', got '{}'",
                ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE, bundle.statement.predicate_type
            )));
        }

        if bundle.statement.predicate.schema != ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA {
            return Err(Error::Validation(format!(
                "invalid predicate schema: expected '{}', got '{}'",
                ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA, bundle.statement.predicate.schema
            )));
        }

        // Exactly one subject required
        if bundle.statement.subject.len() != 1 {
            return Err(Error::Validation(format!(
                "statement must have exactly one subject, got {}",
                bundle.statement.subject.len()
            )));
        }

        // Validate subject name format
        let subject = &bundle.statement.subject[0];
        if !subject.name.starts_with("asf-run:") {
            return Err(Error::Validation(
                "subject name must start with 'asf-run:'".to_string(),
            ));
        }

        // Validate subject digest has sha1 field
        if !subject.digest.contains_key("sha1") {
            return Err(Error::Validation(
                "subject digest must contain sha1 field".to_string(),
            ));
        }

        let predicate = &bundle.statement.predicate;

        // Validate event count binding: count+1 = terminal_event_seq
        if predicate.evidence.preceding_event_count + 1 != predicate.run.terminal_event_seq {
            return Err(Error::Validation(format!(
                "event count mismatch: preceding_event_count + 1 ({}) must equal terminal_event_seq ({})",
                predicate.evidence.preceding_event_count + 1,
                predicate.run.terminal_event_seq
            )));
        }

        // Validate subject binding: subject_kind and subject_sha must truthfully name candidate or base
        let expected_subject_kind = if predicate.source.candidate_sha.is_none() {
            "base"
        } else {
            "candidate"
        };
        let expected_subject_sha = predicate
            .source
            .candidate_sha
            .clone()
            .unwrap_or_else(|| predicate.source.base_sha.clone());

        if predicate.source.subject_kind != expected_subject_kind {
            return Err(Error::Validation(format!(
                "subject kind mismatch: expected '{}', got '{}'",
                expected_subject_kind, predicate.source.subject_kind
            )));
        }

        if predicate.source.subject_sha != expected_subject_sha {
            return Err(Error::Validation(format!(
                "subject sha mismatch: expected '{}', got '{}'",
                expected_subject_sha, predicate.source.subject_sha
            )));
        }

        // Validate cancellation requirement for CANCELLED phase
        if predicate.run.terminal_phase == "CANCELLED" && predicate.cancellation.is_none() {
            return Err(Error::Validation(
                "cancellation evidence is required for CANCELLED phase".to_string(),
            ));
        }

        // Validate delivery digest requirement for COMPLETED phase
        if predicate.run.terminal_phase == "COMPLETED"
            && predicate.evidence.delivery_bundle_digest.is_none()
        {
            return Err(Error::Validation(
                "delivery_bundle_digest is required for COMPLETED phase".to_string(),
            ));
        }

        // Validate cleanup state: all fields must have specific values
        if predicate.cleanup.identity_leases != "released" {
            return Err(Error::Validation(
                "cleanup identity_leases must be 'released'".to_string(),
            ));
        }
        if predicate.cleanup.repository_lease != "released" {
            return Err(Error::Validation(
                "cleanup repository_lease must be 'released'".to_string(),
            ));
        }
        if predicate.cleanup.workspace != "removed" {
            return Err(Error::Validation(
                "cleanup workspace must be 'removed'".to_string(),
            ));
        }
        if predicate.cleanup.unresolved_effects != 0 {
            return Err(Error::Validation(
                "cleanup unresolved_effects must be 0".to_string(),
            ));
        }

        // Validate timing: issued_at must equal timing.terminal_evidence_at
        if bundle.issued_at != predicate.timing.terminal_evidence_at {
            return Err(Error::Validation(format!(
                "issued_at must equal timing.terminal_evidence_at: '{}' vs '{}'",
                bundle.issued_at, predicate.timing.terminal_evidence_at
            )));
        }

        // Validate timing: elapsed_ms must match the difference between timestamps
        let admitted_at = DateTime::parse_from_rfc3339(&predicate.timing.admitted_at)
            .map_err(|e| Error::Validation(format!("invalid admitted_at timestamp: {e}")))?
            .with_timezone(&Utc);
        let terminal_at = DateTime::parse_from_rfc3339(&predicate.timing.terminal_evidence_at)
            .map_err(|e| Error::Validation(format!("invalid terminal_evidence_at timestamp: {e}")))?
            .with_timezone(&Utc);

        let elapsed_millis = (terminal_at - admitted_at).num_milliseconds();
        if elapsed_millis < 0 || elapsed_millis.cast_unsigned() != predicate.timing.elapsed_ms {
            return Err(Error::Validation(format!(
                "elapsed_ms mismatch: expected {}, calculated {}",
                predicate.timing.elapsed_ms, elapsed_millis
            )));
        }

        Ok(bundle)
    }

    /// Verify wire integrity: canonical JCS digest and Ed25519 signature.
    /// Does NOT perform semantic verification or authorization checks.
    pub fn verify_wire_integrity_only(&self, verifying_key_b64: &str) -> Result<()> {
        let key = decode_verifying_key(verifying_key_b64)?;

        // Verify statement digest: bundle_digest is the canonical JCS of the statement
        let statement_json = serde_json::to_value(&self.statement)
            .map_err(|e| Error::Serialization(format!("failed to serialize statement: {e}")))?;

        let canonical_statement = canonical_json(&statement_json)?;
        let calculated_statement_digest = sha256_digest(&canonical_statement);

        if calculated_statement_digest != self.bundle_digest {
            return Err(Error::Crypto(format!(
                "statement digest mismatch: expected '{}', calculated '{}'",
                self.bundle_digest, calculated_statement_digest
            )));
        }

        // Verify signature over canonical JSON of unsigned outer bundle
        let unsigned = UnsignedAsfTerminalEvidenceView {
            schema: self.schema.clone(),
            key_id: self.key_id.clone(),
            algorithm: self.algorithm.clone(),
            issued_at: self.issued_at.clone(),
            bundle_digest: self.bundle_digest.clone(),
            statement: self.statement.clone(),
        };

        let unsigned_json = serde_json::to_value(&unsigned).map_err(|e| {
            Error::Serialization(format!("failed to serialize unsigned bundle: {e}"))
        })?;

        let canonical_unsigned = canonical_json(&unsigned_json)?;

        let signature_str = self
            .signature
            .strip_prefix("base64url:")
            .ok_or_else(|| Error::Crypto("signature must start with 'base64url:'".to_string()))?;

        verify_signature(&key, &canonical_unsigned, signature_str)?;

        Ok(())
    }

    /// Verify semantic bindings against expected values. This is explicitly separate from
    /// `wire_integrity` verification and performs deep validation of external IDs, digests,
    /// and cryptographic authorization.
    ///
    /// Checks:
    /// - Admission signature verification is true
    /// - Algorithm is `EdDSA`
    /// - Key ID is non-empty and matches expected admission key ID
    /// - All Runmill IDs match (run, `work_order`, attempt)
    /// - Terminal phase and event sequence match
    /// - Admission digests match (envelope, payload, policy)
    /// - Source repository and SHAs match
    /// - Cleanup observation digest matches
    /// - Delivery bundle digest matches (or is appropriately null)
    pub fn verify_expected_bindings(
        &self,
        expectation: &AsfTerminalEvidenceExpectation,
    ) -> Result<()> {
        let predicate = &self.statement.predicate;

        // Require explicit signature verification
        if !predicate.admission.signature_verification.verified {
            return Err(Error::Crypto(
                "admission signature_verification.verified must be true".to_string(),
            ));
        }

        // Require EdDSA algorithm
        if predicate.admission.signature_verification.algorithm != "EdDSA" {
            return Err(Error::Crypto(format!(
                "admission algorithm must be EdDSA, got '{}'",
                predicate.admission.signature_verification.algorithm
            )));
        }

        // Require algorithm field in bundle also be EdDSA
        if self.algorithm != "EdDSA" {
            return Err(Error::Crypto(format!(
                "bundle algorithm must be EdDSA, got '{}'",
                self.algorithm
            )));
        }

        // Require non-empty key ID and exact match
        let admission_key_id = &predicate.admission.signature_verification.key_id;
        if admission_key_id.is_empty() {
            return Err(Error::Crypto(
                "admission key_id must be non-empty".to_string(),
            ));
        }
        if admission_key_id != &expectation.admission_key_id {
            return Err(Error::Validation(format!(
                "admission key_id mismatch: expected '{}', got '{}'",
                expectation.admission_key_id, admission_key_id
            )));
        }

        // Verify Runmill IDs match exactly
        if predicate.run.run_id != expectation.run_id {
            return Err(Error::Validation(format!(
                "run_id mismatch: expected '{}', got '{}'",
                expectation.run_id, predicate.run.run_id
            )));
        }

        if predicate.run.work_order_id != expectation.work_order_id {
            return Err(Error::Validation(format!(
                "work_order_id mismatch: expected '{}', got '{}'",
                expectation.work_order_id, predicate.run.work_order_id
            )));
        }

        if predicate.run.attempt_id != expectation.attempt_id {
            return Err(Error::Validation(format!(
                "attempt_id mismatch: expected '{}', got '{}'",
                expectation.attempt_id, predicate.run.attempt_id
            )));
        }

        // Verify terminal phase matches
        if predicate.run.terminal_phase != expectation.terminal_phase {
            return Err(Error::Validation(format!(
                "terminal_phase mismatch: expected '{}', got '{}'",
                expectation.terminal_phase, predicate.run.terminal_phase
            )));
        }

        // Verify terminal event sequence matches
        if predicate.run.terminal_event_seq != expectation.terminal_event_seq {
            return Err(Error::Validation(format!(
                "terminal_event_seq mismatch: expected {}, got {}",
                expectation.terminal_event_seq, predicate.run.terminal_event_seq
            )));
        }

        // Verify admission digests with fail-closed string comparison
        if predicate.admission.work_order_envelope_digest != expectation.work_order_envelope_digest
        {
            return Err(Error::Validation(format!(
                "work_order_envelope_digest mismatch: expected '{}', got '{}'",
                expectation.work_order_envelope_digest,
                predicate.admission.work_order_envelope_digest
            )));
        }

        if predicate.admission.work_order_payload_digest != expectation.work_order_payload_digest {
            return Err(Error::Validation(format!(
                "work_order_payload_digest mismatch: expected '{}', got '{}'",
                expectation.work_order_payload_digest,
                predicate.admission.work_order_payload_digest
            )));
        }

        if predicate.admission.effective_policy_digest != expectation.effective_policy_digest {
            return Err(Error::Validation(format!(
                "effective_policy_digest mismatch: expected '{}', got '{}'",
                expectation.effective_policy_digest, predicate.admission.effective_policy_digest
            )));
        }

        // Verify source bindings with fail-closed comparison
        if predicate.source.repository != expectation.source_repository {
            return Err(Error::Validation(format!(
                "source repository mismatch: expected '{}', got '{}'",
                expectation.source_repository, predicate.source.repository
            )));
        }

        if predicate.source.base_sha != expectation.source_base_sha {
            return Err(Error::Validation(format!(
                "source base_sha mismatch: expected '{}', got '{}'",
                expectation.source_base_sha, predicate.source.base_sha
            )));
        }

        if predicate.source.candidate_sha != expectation.source_candidate_sha {
            return Err(Error::Validation(format!(
                "source candidate_sha mismatch: expected {:?}, got {:?}",
                expectation.source_candidate_sha, predicate.source.candidate_sha
            )));
        }

        // Verify cleanup observation digest
        if predicate.cleanup.observation_digest != expectation.cleanup_observation_digest {
            return Err(Error::Validation(format!(
                "cleanup observation_digest mismatch: expected '{}', got '{}'",
                expectation.cleanup_observation_digest, predicate.cleanup.observation_digest
            )));
        }

        // Verify delivery bundle digest (optional, but must match if present)
        if predicate.evidence.delivery_bundle_digest != expectation.delivery_bundle_digest {
            return Err(Error::Validation(format!(
                "delivery_bundle_digest mismatch: expected {:?}, got {:?}",
                expectation.delivery_bundle_digest, predicate.evidence.delivery_bundle_digest
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519Signer;
    use serde_json::json;

    fn create_test_bundle() -> SignedAsfTerminalEvidenceBundle {
        SignedAsfTerminalEvidenceBundle {
            schema: ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA.to_string(),
            key_id: "test-key-1".to_string(),
            algorithm: "EdDSA".to_string(),
            issued_at: "2026-08-24T17:00:00Z".to_string(),
            bundle_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            statement: AsfTerminalEvidenceStatement {
                type_field: ASF_TERMINAL_IN_TOTO_STATEMENT_V1.to_string(),
                subject: vec![AsfTerminalEvidenceSubject {
                    name: "asf-run:test-run-1".to_string(),
                    digest: {
                        let mut map = serde_json::Map::new();
                        map.insert(
                            "sha1".to_string(),
                            JsonValue::String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
                        );
                        map
                    },
                }],
                predicate_type: ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE.to_string(),
                predicate: AsfTerminalEvidencePredicate {
                    schema: ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA.to_string(),
                    run: AsfTerminalEvidenceRun {
                        run_id: "run-123".to_string(),
                        work_order_id: "wo-456".to_string(),
                        attempt_id: "attempt-789".to_string(),
                        terminal_phase: "COMPLETED".to_string(),
                        terminal_event_seq: 10,
                    },
                    admission: AsfTerminalEvidenceAdmission {
                        work_order_envelope_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                        work_order_payload_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                        effective_policy_digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                            .to_string(),
                        work_order_envelope: json!({}),
                        signature_verification: AsfTerminalEvidenceSignatureVerification {
                            verified: true,
                            key_id: "test-key-1".to_string(),
                            algorithm: "EdDSA".to_string(),
                        },
                        effective_policy: json!({"digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"}),
                    },
                    source: AsfTerminalEvidenceSource {
                        repository: "owner/repo".to_string(),
                        base_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                        candidate_sha: Some("cccccccccccccccccccccccccccccccccccccccc".to_string()),
                        subject_kind: "candidate".to_string(),
                        subject_sha: "cccccccccccccccccccccccccccccccccccccccc".to_string(),
                    },
                    stop: AsfTerminalStopEvidence {
                        code: "SUCCESS".to_string(),
                        summary: "Run completed successfully".to_string(),
                        interrupted_phase: "delivery".to_string(),
                        retry_disposition: "safe".to_string(),
                        required_actor: "asf".to_string(),
                        required_action: "none".to_string(),
                        evidence_refs: vec![],
                    },
                    cancellation: None,
                    budget: AsfTerminalEvidenceBudget {
                        wall_seconds_limit: 3600,
                        max_cost_usd: 10.0,
                        max_agent_invocations: 100,
                        max_fix_iterations: 5,
                        observed_fix_iterations: 2,
                        evidence_refs: vec![],
                        provider_usage: json!({
                            "schema": "asf.provider-budget-evidence-summary/v1",
                            "run_id": "run-123",
                            "work_order_id": "wo-456",
                            "attempt_id": "attempt-789",
                            "policy_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                            "candidate_sha": "cccccccccccccccccccccccccccccccccccccccc",
                            "usage": {
                                "max_cost_micros": 10_000_000,
                                "reported_actual_cost_micros": 5_000_000,
                                "settled_unknown_cost_micros": 0,
                                "outstanding_reserved_cost_micros": 0,
                                "conservative_cost_micros": 5_000_000,
                                "invocation_count": 10,
                                "completed_invocation_count": 10,
                                "settled_unknown_invocation_count": 0,
                                "outstanding_invocation_count": 0,
                                "denied_count": 0
                            },
                            "invocations": [],
                            "settlement_digests": [],
                            "ledger_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                        }),
                    },
                    side_effects: json!({
                        "run_id": "run-123",
                        "work_order_id": "wo-456",
                        "attempt_id": "attempt-789",
                        "policy_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                        "effects": []
                    }),
                    timing: AsfTerminalEvidenceTiming {
                        admitted_at: "2026-08-24T16:59:00Z".to_string(),
                        terminal_evidence_at: "2026-08-24T17:00:00Z".to_string(),
                        elapsed_ms: 60000,
                    },
                    cleanup: AsfTerminalEvidenceCleanup {
                        intent_id: "intent-100".to_string(),
                        intent_digest: "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                            .to_string(),
                        observation_digest: "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                            .to_string(),
                        identity_leases: "released".to_string(),
                        repository_lease: "released".to_string(),
                        workspace: "removed".to_string(),
                        unresolved_effects: 0,
                    },
                    evidence: AsfTerminalEvidenceEvidence {
                        preceding_event_count: 9,
                        preceding_event_chain_digest: "sha256:7777777777777777777777777777777777777777777777777777777777777777"
                            .to_string(),
                        observations: vec![],
                        events: vec![],
                        delivery_bundle_digest: Some(
                            "sha256:8888888888888888888888888888888888888888888888888888888888888888".to_string(),
                        ),
                    },
                },
            },
            signature: "base64url:test_signature_placeholder".to_string(),
        }
    }

    #[test]
    fn test_parse_valid_bundle_structure() {
        let bundle = create_test_bundle();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_valid_fixture_uses_in_toto_predicate_type_key() {
        // The in-toto Statement spells the field 'predicateType'. The valid
        // fixture must serialize to that wire key, parse back from it, and a
        // document carrying the snake_case spelling must be rejected.
        let json = serde_json::to_value(create_test_bundle()).unwrap();
        let statement = json.get("statement").unwrap();
        assert_eq!(
            statement.get("predicateType").and_then(JsonValue::as_str),
            Some(ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE)
        );
        assert!(statement.get("predicate_type").is_none());

        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json).unwrap();
        assert_eq!(
            parsed.statement.predicate_type,
            ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE
        );

        let mut legacy = json.clone();
        let legacy_statement = legacy
            .get_mut("statement")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let predicate_type = legacy_statement.remove("predicateType").unwrap();
        legacy_statement.insert("predicate_type".to_string(), predicate_type);
        assert!(SignedAsfTerminalEvidenceBundle::from_json(&legacy).is_err());
    }

    #[test]
    fn test_reject_invalid_bundle_schema() {
        let mut bundle = create_test_bundle();
        bundle.schema = "invalid.schema/v1".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_invalid_statement_type() {
        let mut bundle = create_test_bundle();
        bundle.statement.type_field = "https://invalid.io/Statement/v1".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_invalid_predicate_type() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate_type =
            "https://invalid.dev/attestations/asf-terminal-evidence/v1".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_multiple_subjects() {
        let mut bundle = create_test_bundle();
        bundle.statement.subject.push(AsfTerminalEvidenceSubject {
            name: "asf-run:test-run-2".to_string(),
            digest: {
                let mut map = serde_json::Map::new();
                map.insert(
                    "sha1".to_string(),
                    JsonValue::String("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
                );
                map
            },
        });
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_bad_event_count() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.terminal_event_seq = 9; // Should be 10
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_subject_sha_mismatch_with_candidate() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.subject_sha =
            "dddddddddddddddddddddddddddddddddddddddd".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_subject_kind_mismatch() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.subject_kind = "base".to_string(); // Should be candidate
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_missing_cancellation_for_cancelled_phase() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.terminal_phase = "CANCELLED".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_missing_delivery_digest_for_completed() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.evidence.delivery_bundle_digest = None;
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_bad_cleanup_state() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.cleanup.identity_leases = "not_released".to_string();
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_timing_mismatch() {
        let mut bundle = create_test_bundle();
        bundle.issued_at = "2026-08-24T17:00:01Z".to_string(); // Different from terminal_evidence_at
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_reject_elapsed_ms_mismatch() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.timing.elapsed_ms = 30000; // Should be 60000
        let json = serde_json::to_value(&bundle).unwrap();
        let parsed = SignedAsfTerminalEvidenceBundle::from_json(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_verify_wire_integrity_with_valid_signature() {
        let signer = Ed25519Signer::generate("test-key");
        let mut bundle = create_test_bundle();
        bundle.key_id = signer.key_id().to_string();

        // Calculate statement digest
        let statement_json = serde_json::to_value(&bundle.statement).unwrap();
        let canonical_statement = canonical_json(&statement_json).unwrap();
        bundle.bundle_digest = sha256_digest(&canonical_statement);

        // Sign the canonical JSON of the unsigned outer bundle
        let unsigned = UnsignedAsfTerminalEvidenceView {
            schema: bundle.schema.clone(),
            key_id: bundle.key_id.clone(),
            algorithm: bundle.algorithm.clone(),
            issued_at: bundle.issued_at.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            statement: bundle.statement.clone(),
        };

        let unsigned_json = serde_json::to_value(&unsigned).unwrap();
        let canonical_unsigned = canonical_json(&unsigned_json).unwrap();
        let signature = signer.sign(&canonical_unsigned);
        bundle.signature = format!("base64url:{signature}");

        let encoded_key = crate::crypto::encode_verifying_key(&signer.verifying_key());

        let result = bundle.verify_wire_integrity_only(&encoded_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_bad_signature() {
        let mut bundle = create_test_bundle();
        bundle.signature = "base64url:invalid_signature_data".to_string();
        let encoded_key = "AA_placeholder_base64_key_that_will_fail";

        let result = bundle.verify_wire_integrity_only(encoded_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_digest_mismatch() {
        let signer = Ed25519Signer::generate("test-key");
        let mut bundle = create_test_bundle();
        bundle.key_id = signer.key_id().to_string();

        // Create correct signature for the statement
        let statement_json = serde_json::to_value(&bundle.statement).unwrap();
        let canonical_statement = canonical_json(&statement_json).unwrap();
        let correct_digest = sha256_digest(&canonical_statement);
        let signature = signer.sign(correct_digest.as_bytes());
        bundle.signature = format!("base64url:{signature}");

        // But then change bundle_digest to something else
        bundle.bundle_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        let encoded_key = crate::crypto::encode_verifying_key(&signer.verifying_key());

        let result = bundle.verify_wire_integrity_only(&encoded_key);
        assert!(result.is_err());
    }

    fn create_valid_expectation() -> AsfTerminalEvidenceExpectation {
        AsfTerminalEvidenceExpectation {
            run_id: "run-123".to_string(),
            work_order_id: "wo-456".to_string(),
            attempt_id: "attempt-789".to_string(),
            terminal_phase: "COMPLETED".to_string(),
            terminal_event_seq: 10,
            work_order_envelope_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            work_order_payload_digest:
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            effective_policy_digest:
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            admission_key_id: "test-key-1".to_string(),
            source_repository: "owner/repo".to_string(),
            source_base_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            source_candidate_sha: Some("cccccccccccccccccccccccccccccccccccccccc".to_string()),
            cleanup_observation_digest:
                "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                    .to_string(),
            delivery_bundle_digest: Some(
                "sha256:8888888888888888888888888888888888888888888888888888888888888888"
                    .to_string(),
            ),
        }
    }

    #[test]
    fn test_verify_expected_bindings_valid() {
        let bundle = create_test_bundle();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_signature_verification_false() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .signature_verification
            .verified = false;
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signature_verification.verified must be true")
        );
    }

    #[test]
    fn test_reject_wrong_admission_algorithm() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .signature_verification
            .algorithm = "ECDSA".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EdDSA"));
    }

    #[test]
    fn test_reject_wrong_bundle_algorithm() {
        let mut bundle = create_test_bundle();
        bundle.algorithm = "ECDSA".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EdDSA"));
    }

    #[test]
    fn test_reject_empty_admission_key_id() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .signature_verification
            .key_id = String::new();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("admission key_id must be non-empty")
        );
    }

    #[test]
    fn test_reject_mismatched_admission_key_id() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .signature_verification
            .key_id = "different-key-id".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("admission key_id mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_run_id() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.run_id = "run-999".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("run_id mismatch"));
    }

    #[test]
    fn test_reject_mismatched_work_order_id() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.work_order_id = "wo-999".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("work_order_id mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_attempt_id() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.attempt_id = "attempt-999".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("attempt_id mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_terminal_phase() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.terminal_phase = "FAILED".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("terminal_phase mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_terminal_event_seq() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.run.terminal_event_seq = 20;
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("terminal_event_seq mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_work_order_envelope_digest() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .work_order_envelope_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("work_order_envelope_digest mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_work_order_payload_digest() {
        let mut bundle = create_test_bundle();
        bundle
            .statement
            .predicate
            .admission
            .work_order_payload_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("work_order_payload_digest mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_effective_policy_digest() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.admission.effective_policy_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("effective_policy_digest mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_source_repository() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.repository = "different/repo".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("source repository mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_source_base_sha() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.base_sha =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("source base_sha mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_source_candidate_sha() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.candidate_sha =
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("source candidate_sha mismatch")
        );
    }

    #[test]
    fn test_reject_candidate_sha_absent_when_expected() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.source.candidate_sha = None;
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("source candidate_sha mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_cleanup_observation_digest() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.cleanup.observation_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cleanup observation_digest mismatch")
        );
    }

    #[test]
    fn test_reject_mismatched_delivery_bundle_digest() {
        let mut bundle = create_test_bundle();
        bundle.statement.predicate.evidence.delivery_bundle_digest = Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        let expectation = create_valid_expectation();
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("delivery_bundle_digest mismatch")
        );
    }

    #[test]
    fn test_reject_delivery_digest_present_when_none_expected() {
        let bundle = create_test_bundle();
        let mut expectation = create_valid_expectation();
        expectation.delivery_bundle_digest = None;
        let result = bundle.verify_expected_bindings(&expectation);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("delivery_bundle_digest mismatch")
        );
    }
}
