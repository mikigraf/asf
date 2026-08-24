/// Recovery-candidate validator for runmill submission lookups.
///
/// This module validates external lookup outcomes against persisted recovery cases.
/// It performs NO I/O, database writes, run adoption, or adapter negotiation.
///
/// Validation determines whether an exact match exists, suitable ONLY for a separate
/// atomic adoption transaction. An `ExactCandidate` is NOT a permission to resend, retry,
/// dispatch, register handlers, insert runs, or perform any I/O.
/// All `NotExact` cases must document observe/escalate; they are read-only.
use uuid::Uuid;

use crate::adapters::runmill_control::RunmillRunSnapshot;
use crate::crypto::{canonical_json, sha256_digest};
use crate::domain::{AttemptId, TenantId, WorkItemId, WorkOrderId, WorkerId};
use crate::ledger::RunmillSubmissionRecoveryCase;
use crate::ports::runmill::{
    LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionReceipt,
    LookupQualifiedSubmissionRequest, QualifiedSubmissionIdentityV1,
};

/// Named precondition that failed during external lookup validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMismatch {
    /// Case state is not `PENDING_EXTERNAL_LOOKUP`.
    CaseStateNotPendingExternalLookup,
    /// Case has a nil UUID field.
    CaseHasNilUuid,
    /// Case `worker_generation` is not positive.
    CaseGenerationNotPositive,
    /// Case `payload_digest` is not a lowercase tagged SHA-256 digest (sha256:...).
    CasePayloadDigestInvalid,
    /// Case `request_digest` is not a lowercase tagged SHA-256 digest (sha256:...).
    CaseRequestDigestInvalid,
    /// Case `remote_idempotency_key` is blank or whitespace-only.
    CaseIdempotencyKeyBlank,
    /// Run ID is blank or whitespace-only.
    RunIdBlank,
    /// Run `state_version` is zero or negative.
    RunStateVersionNotPositive,
    /// Run `latest_sequence` is zero or negative.
    RunLatestSequenceNotPositive,
    /// Run `latest_sequence` does not equal run `state_version`.
    RunSequenceDoesNotMatchStateVersion,
    /// Admission `idempotency_key` does not match case `remote_idempotency_key`.
    AdmissionIdempotencyKeyMismatch,
    /// Admission `tenant_id` does not match case `tenant_id`.
    AdmissionTenantIdMismatch,
    /// Admission `work_order_id` does not match case `work_order_id`.
    AdmissionWorkOrderIdMismatch,
    /// Admission `attempt_id` does not match case `attempt_id`.
    AdmissionAttemptIdMismatch,
    /// Admission `payload_digest` does not match case `payload_digest`.
    AdmissionPayloadDigestMismatch,
    /// Admission `envelope_digest` does not match case `request_digest`.
    AdmissionEnvelopeDigestMismatch,
    /// Run `work_order_id` does not match case `work_order_id`.
    RunWorkOrderIdMismatch,
    /// Run `attempt_id` does not match case `attempt_id`.
    RunAttemptIdMismatch,
    /// Outcome is `NotFound`; external system has no record.
    LookupNotFound,
    /// Outcome is `Ambiguous`; multiple or unclear candidates.
    LookupAmbiguous,
    /// The lookup request could not be built or the receipt failed to validate against it.
    ReceiptRequestInvalid,
    /// Receipt validation outcome is `NotFound`; no receipt found.
    ReceiptNotFound,
    /// Receipt external run ID is blank or whitespace-only.
    ReceiptExternalRunIdBlank,
    /// Receipt admission worker ID does not match case worker ID.
    ReceiptWorkerIdMismatch,
    /// Receipt admission worker generation does not match case worker generation.
    ReceiptWorkerGenerationMismatch,
    /// Receipt run aggregate version is not positive.
    ReceiptAggregateVersionNotPositive,
    /// Receipt run aggregate version cannot be safely converted to i64.
    ReceiptAggregateVersionOverflow,
}

impl ValidationMismatch {
    pub fn description(&self) -> &'static str {
        match self {
            Self::CaseStateNotPendingExternalLookup => {
                "case state must be PENDING_EXTERNAL_LOOKUP for validation"
            }
            Self::CaseHasNilUuid => "all case UUID fields must be non-nil",
            Self::CaseGenerationNotPositive => "case worker_generation must be positive",
            Self::CasePayloadDigestInvalid => {
                "case payload_digest must be lowercase tagged SHA-256 (sha256:...)"
            }
            Self::CaseRequestDigestInvalid => {
                "case request_digest must be lowercase tagged SHA-256 (sha256:...)"
            }
            Self::CaseIdempotencyKeyBlank => "case remote_idempotency_key must be non-blank",
            Self::RunIdBlank => "run ID must be non-blank",
            Self::RunStateVersionNotPositive => "run state_version must be positive",
            Self::RunLatestSequenceNotPositive => "run latest_sequence must be positive",
            Self::RunSequenceDoesNotMatchStateVersion => {
                "run latest_sequence must equal run state_version"
            }
            Self::AdmissionIdempotencyKeyMismatch => {
                "admission idempotency_key must match case remote_idempotency_key"
            }
            Self::AdmissionTenantIdMismatch => "admission tenant_id must match case tenant_id",
            Self::AdmissionWorkOrderIdMismatch => {
                "admission work_order_id must match case work_order_id"
            }
            Self::AdmissionAttemptIdMismatch => "admission attempt_id must match case attempt_id",
            Self::AdmissionPayloadDigestMismatch => {
                "admission payload_digest must match case payload_digest"
            }
            Self::AdmissionEnvelopeDigestMismatch => {
                "admission envelope_digest must match case request_digest"
            }
            Self::RunWorkOrderIdMismatch => "run work_order_id must match case work_order_id",
            Self::RunAttemptIdMismatch => "run attempt_id must match case attempt_id",
            Self::LookupNotFound => "external lookup found no candidate",
            Self::LookupAmbiguous => "external lookup result is ambiguous",
            Self::ReceiptRequestInvalid => {
                "lookup request could not be built or receipt failed validation against it"
            }
            Self::ReceiptNotFound => "receipt validation found no receipt candidate",
            Self::ReceiptExternalRunIdBlank => "receipt external run ID must be non-blank",
            Self::ReceiptWorkerIdMismatch => {
                "receipt admission worker ID must match case worker ID"
            }
            Self::ReceiptWorkerGenerationMismatch => {
                "receipt admission worker generation must match case worker generation"
            }
            Self::ReceiptAggregateVersionNotPositive => {
                "receipt run aggregate version must be positive"
            }
            Self::ReceiptAggregateVersionOverflow => "receipt run aggregate version overflows i64",
        }
    }
}

/// An opaque exact match: eligible only for a separate atomic adoption transaction.
/// NEVER grants permission for resend, retry, dispatch, handler registration, run insertion, or I/O.
/// All fields are private; use read-only accessors.
#[derive(Debug, Clone)]
pub struct ExactSubmissionLookupCandidate {
    run_id: String,
    snapshot: RunmillRunSnapshot,
    worker_id: Uuid,
    worker_generation: i64,
    worker_session_id: Uuid,
}

impl ExactSubmissionLookupCandidate {
    /// Read-only accessor for the Runmill run ID.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Read-only accessor for the complete `RunmillRunSnapshot`.
    pub fn snapshot(&self) -> &RunmillRunSnapshot {
        &self.snapshot
    }

    /// Read-only accessor for the preserved worker ID.
    pub fn worker_id(&self) -> Uuid {
        self.worker_id
    }

    /// Read-only accessor for the preserved worker generation.
    pub fn worker_generation(&self) -> i64 {
        self.worker_generation
    }

    /// Read-only accessor for the preserved worker session ID.
    pub fn worker_session_id(&self) -> Uuid {
        self.worker_session_id
    }
}

/// An opaque exact qualified submission receipt proof; eligible only for a separate atomic adoption transaction.
/// NEVER grants permission for resend, retry, dispatch, handler registration, run insertion, or I/O.
/// All fields are private; use read-only accessors.
#[derive(Debug, Clone)]
pub struct ExactQualifiedSubmissionReceiptProof {
    receipt: LookupQualifiedSubmissionReceipt,
    canonical_receipt_bytes: Vec<u8>,
    receipt_digest: String,
    external_run_id: String,
    worker_id: Uuid,
    worker_generation: i64,
    worker_session_id: Uuid,
    remote_state_version: i64,
}

impl ExactQualifiedSubmissionReceiptProof {
    /// Read-only accessor for the typed receipt.
    pub fn receipt(&self) -> &LookupQualifiedSubmissionReceipt {
        &self.receipt
    }

    /// Read-only accessor for the canonical receipt bytes.
    pub fn canonical_receipt_bytes(&self) -> &[u8] {
        &self.canonical_receipt_bytes
    }

    /// Read-only accessor for the receipt digest (SHA-256).
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    /// Read-only accessor for the external run ID.
    pub fn external_run_id(&self) -> &str {
        &self.external_run_id
    }

    /// Read-only accessor for the preserved worker ID.
    pub fn worker_id(&self) -> Uuid {
        self.worker_id
    }

    /// Read-only accessor for the preserved worker generation.
    pub fn worker_generation(&self) -> i64 {
        self.worker_generation
    }

    /// Read-only accessor for the preserved worker session ID.
    pub fn worker_session_id(&self) -> Uuid {
        self.worker_session_id
    }

    /// Read-only accessor for the remote state version.
    pub fn remote_state_version(&self) -> i64 {
        self.remote_state_version
    }

    #[cfg(test)]
    pub fn new_for_test(
        receipt: LookupQualifiedSubmissionReceipt,
        canonical_receipt_bytes: Vec<u8>,
        receipt_digest: String,
        external_run_id: String,
        worker_id: Uuid,
        worker_generation: i64,
        worker_session_id: Uuid,
        remote_state_version: i64,
    ) -> Self {
        Self {
            receipt,
            canonical_receipt_bytes,
            receipt_digest,
            external_run_id,
            worker_id,
            worker_generation,
            worker_session_id,
            remote_state_version,
        }
    }
}

/// Outcome of a lookup attempt in external systems or local cache.
/// `Found` outcome contains a `RunmillRunSnapshot` for validation.
#[derive(Debug, Clone)]
pub enum SubmissionLookupOutcome {
    /// Lookup found a run snapshot.
    Found(Box<RunmillRunSnapshot>),
    /// Lookup found no candidate.
    NotFound,
    /// Lookup result is ambiguous; multiple or unclear results.
    Ambiguous { reason: String },
}

/// External lookup validation result.
/// `Exact` means the found run exactly matches all critical case preconditions,
/// eligible ONLY for a separate atomic adoption transaction.
/// `NotExact` means a mismatch or unresolved outcome; observe/escalate only, no I/O permitted.
#[derive(Debug, Clone)]
pub enum ExternalLookupCandidate {
    /// Found candidate exactly matches all critical case preconditions.
    /// This is a read-only match token; it NEVER permits resend, retry, dispatch, I/O, or handler registration.
    /// It is eligible only for a separate atomic adoption transaction.
    Exact(Box<ExactSubmissionLookupCandidate>),
    /// Found candidate mismatches one or more critical preconditions, or lookup was not found / ambiguous.
    /// This is observe/escalate only; NO I/O or actions are permitted.
    NotExact(ValidationMismatch),
}

/// Validate a qualified submission receipt against a persisted recovery case.
///
/// Pure no-I/O V2 receipt proof path. Defensively requires:
/// - Case state is `PENDING_EXTERNAL_LOOKUP`
/// - All critical case UUIDs are non-nil
/// - Case `worker_generation` is positive
/// - Receipt validation succeeds (Found outcome)
/// - Receipt external run ID is non-blank
/// - Receipt admission worker ID equals case worker ID
/// - Receipt admission worker generation equals case worker generation (safe i64 conversion)
/// - Receipt run aggregate version is positive
/// - Receipt run aggregate version safely converts to i64
///
/// Canonicalizes the entire receipt using `canonical_json` then `sha256_digest`.
/// All validation is in-process, pure function with no I/O, database writes, or external calls.
///
/// Returns `ExactQualifiedSubmissionReceiptProof` only if all preconditions pass.
/// Returns first failing precondition as a `ValidationMismatch` otherwise.
/// Never reconstructs receipt from Runmill control snapshots.
///
/// # Examples
///
/// ```ignore
/// let case = /* RunmillSubmissionRecoveryCase from database */;
/// let receipt = /* LookupQualifiedSubmissionReceipt from lookup */;
/// match validate_qualified_submission_receipt_for_recovery(&case, receipt) {
///     Ok(proof) => {
///         // Eligible for atomic adoption transaction ONLY.
///         // Safe to read proof.external_run_id() and proof.receipt().
///         // NEVER permit resend, retry, dispatch, or I/O.
///     }
///     Err(mismatch) => {
///         // Validation failed. Observe/escalate only. No I/O permitted.
///         eprintln!("Receipt validation failed: {}", mismatch.description());
///     }
/// }
/// ```
pub fn validate_qualified_submission_receipt_for_recovery(
    case_: &RunmillSubmissionRecoveryCase,
    receipt: LookupQualifiedSubmissionReceipt,
) -> Result<ExactQualifiedSubmissionReceiptProof, ValidationMismatch> {
    if let Some(mismatch) = validate_case_preconditions(case_) {
        return Err(mismatch);
    }

    let identity = QualifiedSubmissionIdentityV1 {
        tenant_id: TenantId::from_uuid(case_.tenant_id),
        work_order_id: WorkOrderId::from_uuid(case_.work_order_id),
        work_item_id: WorkItemId::from_uuid(case_.work_item_id),
        attempt_id: AttemptId::from_uuid(case_.attempt_id),
        idempotency_key: case_.remote_idempotency_key.clone(),
        work_order_digest: case_.payload_digest.clone(),
        request_digest: case_.request_digest.clone(),
    };

    let request = LookupQualifiedSubmissionRequest::new(identity)
        .map_err(|_| ValidationMismatch::ReceiptRequestInvalid)?;

    receipt
        .validate_against(&request)
        .map_err(|_| ValidationMismatch::ReceiptRequestInvalid)?;

    let (external_run_id, admission_worker_id, admission_worker_generation, aggregate_version) =
        match &receipt.outcome {
            LookupQualifiedSubmissionOutcome::Found(found) => (
                found.run.run_id.to_string(),
                found.admission_worker.worker_id,
                found.admission_worker.worker_generation,
                found.run.aggregate_version,
            ),
            LookupQualifiedSubmissionOutcome::NotFound => {
                return Err(ValidationMismatch::ReceiptNotFound);
            }
        };

    if external_run_id.trim().is_empty() {
        return Err(ValidationMismatch::ReceiptExternalRunIdBlank);
    }

    if admission_worker_id != WorkerId::from_uuid(case_.worker_id) {
        return Err(ValidationMismatch::ReceiptWorkerIdMismatch);
    }

    let case_worker_generation = u64::try_from(case_.worker_generation)
        .map_err(|_| ValidationMismatch::ReceiptWorkerGenerationMismatch)?;
    if admission_worker_generation != case_worker_generation {
        return Err(ValidationMismatch::ReceiptWorkerGenerationMismatch);
    }

    if aggregate_version == 0 {
        return Err(ValidationMismatch::ReceiptAggregateVersionNotPositive);
    }

    let remote_state_version = i64::try_from(aggregate_version)
        .map_err(|_| ValidationMismatch::ReceiptAggregateVersionOverflow)?;

    let canonical_receipt_bytes =
        canonical_json(&receipt).map_err(|_| ValidationMismatch::ReceiptRequestInvalid)?;
    let receipt_digest = sha256_digest(&canonical_receipt_bytes);

    Ok(ExactQualifiedSubmissionReceiptProof {
        receipt,
        canonical_receipt_bytes,
        receipt_digest,
        external_run_id,
        worker_id: case_.worker_id,
        worker_generation: case_.worker_generation,
        worker_session_id: case_.worker_session_id,
        remote_state_version,
    })
}

/// Validate an external lookup outcome against a persisted recovery case.
///
/// For `Found` outcomes, defensively requires:
/// - Case state is `PENDING_EXTERNAL_LOOKUP`
/// - All critical case UUIDs are non-nil
/// - Case `worker_generation` is positive
/// - Case digests are lowercase tagged SHA-256
/// - Case `remote_idempotency_key` is non-blank (format verified by database trigger)
/// - Run ID is non-blank
/// - Run `state_version` is positive
/// - Run `latest_sequence` is positive and equals `state_version`
/// - Admission fields match case fields exactly
/// - Run `work_order_id` and `attempt_id` match case and admission
///
/// Worker id/generation/session are preserved in `ExactCandidate` but NOT compared to
/// Runmill run generation (which is Runmill's own internal generation).
///
/// Returns `ExactCandidate` only if all preconditions pass.
/// Returns `NotExact` with the first failing precondition otherwise.
/// `NotFound` and `Ambiguous` outcomes are not eligible for exact match.
///
/// # Examples
///
/// ```ignore
/// let case = /* RunmillSubmissionRecoveryCase from database */;
/// let outcome = SubmissionLookupOutcome::Found(snapshot);
/// match validate_external_lookup_candidate(&case, outcome) {
///     ExternalLookupCandidate::Exact(candidate) => {
///         // Eligible for atomic adoption transaction ONLY.
///         // Safe to read candidate.run_id() and candidate.snapshot().
///         // NEVER permit resend, retry, dispatch, or I/O.
///     }
///     ExternalLookupCandidate::NotExact(mismatch) => {
///         // Observe/escalate only. No I/O permitted.
///         eprintln!("Validation failed: {}", mismatch.description());
///     }
/// }
/// ```
pub fn validate_external_lookup_candidate(
    case_: &RunmillSubmissionRecoveryCase,
    outcome: SubmissionLookupOutcome,
) -> ExternalLookupCandidate {
    match outcome {
        SubmissionLookupOutcome::Found(snapshot) => {
            if let Some(mismatch) = validate_case_preconditions(case_) {
                return ExternalLookupCandidate::NotExact(mismatch);
            }
            if let Some(mismatch) = validate_run_preconditions(&snapshot.run) {
                return ExternalLookupCandidate::NotExact(mismatch);
            }
            if let Some(mismatch) = validate_sequence_consistency(&snapshot) {
                return ExternalLookupCandidate::NotExact(mismatch);
            }
            if let Some(mismatch) = validate_admission_matches(case_, &snapshot.admission) {
                return ExternalLookupCandidate::NotExact(mismatch);
            }
            if let Some(mismatch) = validate_run_matches(case_, &snapshot.run) {
                return ExternalLookupCandidate::NotExact(mismatch);
            }

            let run_id = snapshot.run.run_id.to_string();
            ExternalLookupCandidate::Exact(Box::new(ExactSubmissionLookupCandidate {
                run_id,
                snapshot: *snapshot,
                worker_id: case_.worker_id,
                worker_generation: case_.worker_generation,
                worker_session_id: case_.worker_session_id,
            }))
        }
        SubmissionLookupOutcome::NotFound => {
            ExternalLookupCandidate::NotExact(ValidationMismatch::LookupNotFound)
        }
        SubmissionLookupOutcome::Ambiguous { .. } => {
            ExternalLookupCandidate::NotExact(ValidationMismatch::LookupAmbiguous)
        }
    }
}

/// Validate case preconditions (state, UUIDs, generation, digests, idempotency).
fn validate_case_preconditions(
    case_: &RunmillSubmissionRecoveryCase,
) -> Option<ValidationMismatch> {
    if case_.state != "PENDING_EXTERNAL_LOOKUP" {
        return Some(ValidationMismatch::CaseStateNotPendingExternalLookup);
    }

    if case_.tenant_id.is_nil()
        || case_.effect_intent_id.is_nil()
        || case_.work_item_id.is_nil()
        || case_.attempt_id.is_nil()
        || case_.work_order_id.is_nil()
        || case_.worker_id.is_nil()
        || case_.worker_session_id.is_nil()
    {
        return Some(ValidationMismatch::CaseHasNilUuid);
    }

    if case_.worker_generation <= 0 {
        return Some(ValidationMismatch::CaseGenerationNotPositive);
    }

    if !is_lowercase_sha256_digest(&case_.payload_digest) {
        return Some(ValidationMismatch::CasePayloadDigestInvalid);
    }

    if !is_lowercase_sha256_digest(&case_.request_digest) {
        return Some(ValidationMismatch::CaseRequestDigestInvalid);
    }

    if case_.remote_idempotency_key.trim().is_empty() {
        return Some(ValidationMismatch::CaseIdempotencyKeyBlank);
    }

    None
}

/// Validate run preconditions (ID, `state_version`, `latest_sequence`).
fn validate_run_preconditions(
    run: &crate::adapters::runmill_control::RunmillRunRow,
) -> Option<ValidationMismatch> {
    let run_id_str = run.run_id.to_string();
    if run_id_str.trim().is_empty() {
        return Some(ValidationMismatch::RunIdBlank);
    }

    if run.state_version == 0 {
        return Some(ValidationMismatch::RunStateVersionNotPositive);
    }

    None
}

/// Validate sequence consistency (`latest_sequence` > 0 and == `state_version`).
fn validate_sequence_consistency(snapshot: &RunmillRunSnapshot) -> Option<ValidationMismatch> {
    if snapshot.latest_sequence == 0 {
        return Some(ValidationMismatch::RunLatestSequenceNotPositive);
    }

    if snapshot.latest_sequence != snapshot.run.state_version {
        return Some(ValidationMismatch::RunSequenceDoesNotMatchStateVersion);
    }

    None
}

/// Validate admission fields match case fields.
fn validate_admission_matches(
    case_: &RunmillSubmissionRecoveryCase,
    admission: &crate::adapters::runmill_control::RunmillAdmissionSnapshot,
) -> Option<ValidationMismatch> {
    if admission.idempotency_key != case_.remote_idempotency_key {
        return Some(ValidationMismatch::AdmissionIdempotencyKeyMismatch);
    }

    if admission.tenant_id != case_.tenant_id.to_string() {
        return Some(ValidationMismatch::AdmissionTenantIdMismatch);
    }

    if admission.work_order_id != case_.work_order_id.to_string() {
        return Some(ValidationMismatch::AdmissionWorkOrderIdMismatch);
    }

    if admission.attempt_id != case_.attempt_id.to_string() {
        return Some(ValidationMismatch::AdmissionAttemptIdMismatch);
    }

    if admission.payload_digest != case_.payload_digest {
        return Some(ValidationMismatch::AdmissionPayloadDigestMismatch);
    }

    if admission.envelope_digest != case_.request_digest {
        return Some(ValidationMismatch::AdmissionEnvelopeDigestMismatch);
    }

    None
}

/// Validate run fields match case and admission fields.
fn validate_run_matches(
    case_: &RunmillSubmissionRecoveryCase,
    run: &crate::adapters::runmill_control::RunmillRunRow,
) -> Option<ValidationMismatch> {
    if run.work_order_id != case_.work_order_id.to_string() {
        return Some(ValidationMismatch::RunWorkOrderIdMismatch);
    }

    if run.attempt_id != case_.attempt_id.to_string() {
        return Some(ValidationMismatch::RunAttemptIdMismatch);
    }

    None
}

/// Check if a string is a lowercase tagged SHA-256 digest (sha256:...).
fn is_lowercase_sha256_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest[7..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RunId;
    use crate::ports::runmill::{
        LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1, QualifiedSubmissionAdmissionWorkerV1,
        QualifiedSubmissionFound, RUN_SNAPSHOT_SCHEMA_V1, RunSnapshot, RunmillRunState,
    };
    use chrono::Utc;

    fn make_recovery_case() -> RunmillSubmissionRecoveryCase {
        RunmillSubmissionRecoveryCase {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            effect_intent_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            payload_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            request_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            remote_idempotency_key: String::new(), // Will be set per test
            worker_id: Uuid::now_v7(),
            worker_generation: 1,
            worker_session_id: Uuid::now_v7(),
            state: "PENDING_EXTERNAL_LOOKUP".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_runmill_run_row(
        case: &RunmillSubmissionRecoveryCase,
    ) -> crate::adapters::runmill_control::RunmillRunRow {
        crate::adapters::runmill_control::RunmillRunRow {
            run_id: crate::adapters::runmill_control::RunmillRunId::parse("run-abc123")
                .expect("valid run_id"),
            issue_id: "123".into(),
            repo: "owner/repo".into(),
            provider: "github".into(),
            state: crate::adapters::runmill_control::RunmillRunPhase::Admitted,
            state_version: 1,
            attempt: 1,
            base_commit: Some("abc".into()),
            candidate_sha: None,
            branch: None,
            mode: "check".into(),
            work_order_id: case.work_order_id.to_string(),
            attempt_id: case.attempt_id.to_string(),
            generation: 1,
            owner_id: None,
            heartbeat_at: None,
        }
    }

    fn make_runmill_admission_snapshot(
        case: &RunmillSubmissionRecoveryCase,
    ) -> crate::adapters::runmill_control::RunmillAdmissionSnapshot {
        crate::adapters::runmill_control::RunmillAdmissionSnapshot {
            idempotency_key: case.remote_idempotency_key.clone(),
            work_order_id: case.work_order_id.to_string(),
            attempt_id: case.attempt_id.to_string(),
            tenant_id: case.tenant_id.to_string(),
            payload_digest: case.payload_digest.clone(),
            envelope_digest: case.request_digest.clone(),
            effective_policy_digest: String::new(),
            signature_key_id: String::new(),
            signature_algorithm: String::new(),
            accepted_at: Utc::now(),
        }
    }

    fn make_runmill_run_snapshot(case: &RunmillSubmissionRecoveryCase) -> RunmillRunSnapshot {
        RunmillRunSnapshot {
            run: make_runmill_run_row(case),
            admission: make_runmill_admission_snapshot(case),
            latest_sequence: 1,
        }
    }

    #[test]
    fn exact_match_validates_successfully() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot.clone()));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::Exact(candidate) => {
                assert_eq!(candidate.run_id(), "run-abc123");
                assert_eq!(candidate.worker_id(), case.worker_id);
                assert_eq!(candidate.worker_generation(), case.worker_generation);
                assert_eq!(candidate.worker_session_id(), case.worker_session_id);
                assert_eq!(candidate.snapshot().latest_sequence, 1);
            }
            ExternalLookupCandidate::NotExact(mismatch) => {
                panic!("expected Exact, got mismatch: {mismatch:?}");
            }
        }
    }

    #[test]
    fn case_state_not_pending_external_lookup() {
        let mut case = make_recovery_case();
        case.state = "SOME_OTHER_STATE".into();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(
                    mismatch,
                    ValidationMismatch::CaseStateNotPendingExternalLookup
                );
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_has_nil_tenant_id() {
        let mut case = make_recovery_case();
        case.tenant_id = Uuid::nil();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CaseHasNilUuid);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_generation_not_positive() {
        let mut case = make_recovery_case();
        case.worker_generation = 0;
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CaseGenerationNotPositive);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_payload_digest_invalid() {
        let mut case = make_recovery_case();
        case.payload_digest = "invalid".into();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CasePayloadDigestInvalid);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_payload_digest_uppercase() {
        let mut case = make_recovery_case();
        case.payload_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000A".into();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CasePayloadDigestInvalid);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_request_digest_invalid() {
        let mut case = make_recovery_case();
        case.request_digest = "not-a-digest".into();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CaseRequestDigestInvalid);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn case_idempotency_key_blank() {
        let case = make_recovery_case();
        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::CaseIdempotencyKeyBlank);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn run_latest_sequence_not_positive() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.latest_sequence = 0;
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::RunLatestSequenceNotPositive);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn run_sequence_does_not_match_state_version() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.latest_sequence = 5;
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(
                    mismatch,
                    ValidationMismatch::RunSequenceDoesNotMatchStateVersion
                );
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_idempotency_key_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.idempotency_key = "different-key".into();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(
                    mismatch,
                    ValidationMismatch::AdmissionIdempotencyKeyMismatch
                );
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_tenant_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.tenant_id = Uuid::now_v7().to_string();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::AdmissionTenantIdMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_payload_digest_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.payload_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::AdmissionPayloadDigestMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_envelope_digest_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.envelope_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(
                    mismatch,
                    ValidationMismatch::AdmissionEnvelopeDigestMismatch
                );
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn run_work_order_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.run.work_order_id = Uuid::now_v7().to_string();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::RunWorkOrderIdMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn run_attempt_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.run.attempt_id = Uuid::now_v7().to_string();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::RunAttemptIdMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn lookup_not_found() {
        let case = make_recovery_case();
        let outcome = SubmissionLookupOutcome::NotFound;

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::LookupNotFound);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn lookup_ambiguous() {
        let case = make_recovery_case();
        let outcome = SubmissionLookupOutcome::Ambiguous {
            reason: "Multiple candidates found".into(),
        };

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::LookupAmbiguous);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_work_order_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.work_order_id = Uuid::now_v7().to_string();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::AdmissionWorkOrderIdMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn admission_attempt_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.admission.attempt_id = Uuid::now_v7().to_string();
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::AdmissionAttemptIdMismatch);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn run_state_version_zero() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );

        let mut snapshot = make_runmill_run_snapshot(&case);
        snapshot.run.state_version = 0;
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::NotExact(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::RunStateVersionNotPositive);
            }
            ExternalLookupCandidate::Exact(_) => panic!("expected NotExact, got Exact"),
        }
    }

    #[test]
    fn exact_candidate_preserves_worker_metadata() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        let expected_worker_id = Uuid::now_v7();
        let expected_generation = 42;
        let expected_session_id = Uuid::now_v7();
        case.worker_id = expected_worker_id;
        case.worker_generation = expected_generation;
        case.worker_session_id = expected_session_id;

        let snapshot = make_runmill_run_snapshot(&case);
        let outcome = SubmissionLookupOutcome::Found(Box::new(snapshot.clone()));

        match validate_external_lookup_candidate(&case, outcome) {
            ExternalLookupCandidate::Exact(candidate) => {
                assert_eq!(candidate.worker_id(), expected_worker_id);
                assert_eq!(candidate.worker_generation(), expected_generation);
                assert_eq!(candidate.worker_session_id(), expected_session_id);
            }
            ExternalLookupCandidate::NotExact(mismatch) => {
                panic!("expected Exact, got mismatch: {mismatch:?}");
            }
        }
    }

    #[test]
    fn run_id_blank_cannot_be_tested_with_runmillrunid_parse() {
        // RunmillRunId is a strict type that requires valid parsing via RunmillRunId::parse().
        // The type system prevents constructing a RunmillRunId from a blank string,
        // so this validation (RunIdBlank) serves as a defensive check against hypothetical
        // corrupted database state or unexpected future changes to the RunmillRunId type.
        // If we could construct invalid IDs, the test would look like:
        //   snapshot.run.run_id = <blank>;
        //   assert_eq!(mismatch, ValidationMismatch::RunIdBlank);
        // Since we cannot, this comment documents the validation intent.
    }

    #[test]
    fn validation_mismatch_descriptions() {
        assert!(
            !ValidationMismatch::CaseStateNotPendingExternalLookup
                .description()
                .is_empty()
        );
        assert!(!ValidationMismatch::CaseHasNilUuid.description().is_empty());
        assert!(!ValidationMismatch::RunIdBlank.description().is_empty());
        assert!(!ValidationMismatch::LookupNotFound.description().is_empty());
    }

    #[test]
    fn exact_qualified_receipt_proof_validates_successfully() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        let receipt = make_mock_lookup_qualified_submission_receipt(&case);

        match validate_qualified_submission_receipt_for_recovery(&case, receipt) {
            Ok(proof) => {
                assert!(!proof.external_run_id().is_empty());
                assert_eq!(proof.worker_id(), case.worker_id);
                assert_eq!(proof.worker_generation(), case.worker_generation);
                assert_eq!(proof.worker_session_id(), case.worker_session_id);
                assert!(proof.remote_state_version() > 0);
                assert!(!proof.receipt_digest().is_empty());
                assert!(!proof.canonical_receipt_bytes().is_empty());
            }
            Err(mismatch) => {
                panic!(
                    "expected Ok receipt proof, got error: {}",
                    mismatch.description()
                );
            }
        }
    }

    #[test]
    fn receipt_not_found() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        let receipt = make_mock_lookup_qualified_submission_receipt_not_found(&case);

        match validate_qualified_submission_receipt_for_recovery(&case, receipt) {
            Ok(_) => panic!("expected ReceiptNotFound error"),
            Err(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::ReceiptNotFound);
            }
        }
    }

    #[test]
    fn receipt_worker_id_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        let wrong_worker_id = Uuid::now_v7();
        case.worker_id = Uuid::now_v7();

        let receipt =
            make_mock_lookup_qualified_submission_receipt_with_worker_id(&case, wrong_worker_id);

        match validate_qualified_submission_receipt_for_recovery(&case, receipt) {
            Ok(_) => panic!("expected ReceiptWorkerIdMismatch error"),
            Err(mismatch) => {
                assert_eq!(mismatch, ValidationMismatch::ReceiptWorkerIdMismatch);
            }
        }
    }

    #[test]
    fn receipt_worker_generation_mismatch() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        case.worker_generation = 5;

        let receipt = make_mock_lookup_qualified_submission_receipt_with_generation(&case, 7);

        match validate_qualified_submission_receipt_for_recovery(&case, receipt) {
            Ok(_) => panic!("expected ReceiptWorkerGenerationMismatch error"),
            Err(mismatch) => {
                assert_eq!(
                    mismatch,
                    ValidationMismatch::ReceiptWorkerGenerationMismatch
                );
            }
        }
    }

    #[test]
    fn receipt_canonical_digest_stability() {
        let mut case = make_recovery_case();
        case.remote_idempotency_key = format!(
            "{}/{}/{}",
            case.tenant_id, case.work_item_id, case.attempt_id
        );
        let receipt = make_mock_lookup_qualified_submission_receipt(&case);

        let result1 = validate_qualified_submission_receipt_for_recovery(&case, receipt.clone());
        let result2 = validate_qualified_submission_receipt_for_recovery(&case, receipt);

        match (result1, result2) {
            (Ok(proof1), Ok(proof2)) => {
                assert_eq!(proof1.receipt_digest(), proof2.receipt_digest());
                assert_eq!(
                    proof1.canonical_receipt_bytes(),
                    proof2.canonical_receipt_bytes()
                );
            }
            _ => panic!("both validations should succeed"),
        }
    }

    fn make_identity_for_case(
        case: &RunmillSubmissionRecoveryCase,
    ) -> QualifiedSubmissionIdentityV1 {
        QualifiedSubmissionIdentityV1 {
            tenant_id: TenantId::from_uuid(case.tenant_id),
            work_order_id: WorkOrderId::from_uuid(case.work_order_id),
            work_item_id: WorkItemId::from_uuid(case.work_item_id),
            attempt_id: AttemptId::from_uuid(case.attempt_id),
            idempotency_key: case.remote_idempotency_key.clone(),
            work_order_digest: case.payload_digest.clone(),
            request_digest: case.request_digest.clone(),
        }
    }

    fn make_run_snapshot_for_case(
        case: &RunmillSubmissionRecoveryCase,
        worker_id: Uuid,
        worker_generation: u64,
    ) -> RunSnapshot {
        let now = Utc::now();
        RunSnapshot {
            schema: RUN_SNAPSHOT_SCHEMA_V1.into(),
            run_id: RunId::new(),
            attempt_id: AttemptId::from_uuid(case.attempt_id),
            idempotency_key: case.remote_idempotency_key.clone(),
            work_order_digest: case.payload_digest.clone(),
            worker_id: WorkerId::from_uuid(worker_id),
            worker_generation,
            state: RunmillRunState::Running,
            aggregate_version: 1,
            last_event_cursor: None,
            evidence_digest: None,
            outcome_acknowledged: false,
            accepted_at: now,
            updated_at: now,
        }
    }

    fn make_mock_lookup_qualified_submission_receipt(
        case: &RunmillSubmissionRecoveryCase,
    ) -> LookupQualifiedSubmissionReceipt {
        make_mock_lookup_qualified_submission_receipt_with_worker(
            case,
            case.worker_id,
            case.worker_generation.cast_unsigned(),
        )
    }

    fn make_mock_lookup_qualified_submission_receipt_not_found(
        _case: &RunmillSubmissionRecoveryCase,
    ) -> LookupQualifiedSubmissionReceipt {
        LookupQualifiedSubmissionReceipt {
            schema: LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
            outcome: LookupQualifiedSubmissionOutcome::NotFound,
        }
    }

    fn make_mock_lookup_qualified_submission_receipt_with_worker_id(
        case: &RunmillSubmissionRecoveryCase,
        worker_id: Uuid,
    ) -> LookupQualifiedSubmissionReceipt {
        make_mock_lookup_qualified_submission_receipt_with_worker(
            case,
            worker_id,
            case.worker_generation.cast_unsigned(),
        )
    }

    fn make_mock_lookup_qualified_submission_receipt_with_generation(
        case: &RunmillSubmissionRecoveryCase,
        generation: i64,
    ) -> LookupQualifiedSubmissionReceipt {
        make_mock_lookup_qualified_submission_receipt_with_worker(
            case,
            case.worker_id,
            generation.cast_unsigned(),
        )
    }

    fn make_mock_lookup_qualified_submission_receipt_with_worker(
        case: &RunmillSubmissionRecoveryCase,
        worker_id: Uuid,
        worker_generation: u64,
    ) -> LookupQualifiedSubmissionReceipt {
        LookupQualifiedSubmissionReceipt {
            schema: LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
            outcome: LookupQualifiedSubmissionOutcome::Found(Box::new(QualifiedSubmissionFound {
                qualification: make_identity_for_case(case),
                run: make_run_snapshot_for_case(case, worker_id, worker_generation),
                admission_worker: QualifiedSubmissionAdmissionWorkerV1 {
                    worker_id: WorkerId::from_uuid(worker_id),
                    worker_generation,
                },
            })),
        }
    }
}
