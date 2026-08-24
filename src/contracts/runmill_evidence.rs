use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Error, Result,
    crypto::{Ed25519Signer, canonical_json, is_sha256_digest, sha256_digest, verify_signature},
    domain::{AttemptId, WorkOrderId},
    security::reject_sensitive_fields,
};

use super::PullRequestEvidence;

pub const RUNMILL_SIGNED_EVIDENCE_SCHEMA_V1: &str = "asf.signed-evidence/v1";
pub const RUNMILL_EVIDENCE_PREDICATE_SCHEMA_V1: &str = "asf.evidence-bundle/v1";
pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const RUNMILL_EVIDENCE_PREDICATE_TYPE_V1: &str =
    "https://runmill.dev/attestations/asf-evidence/v1";

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_REFERENCE_BYTES: usize = 512;
const MAX_REPOSITORY_BYTES: usize = 512;
const MAX_BRANCH_REF_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_SORTED_STRINGS: usize = 2_048;
const MAX_PROVIDERS: usize = 3;
const MAX_ROLE_OUTCOMES: usize = 3;
const MAX_LOCAL_CHECKS: usize = 256;
const MAX_CI_CONTEXTS: usize = 256;
const MAX_REVIEWS: usize = 16;
const MAX_SIDE_EFFECTS: usize = 1_024;
const MAX_APPROVALS: usize = 256;
const MAX_ARTIFACTS: usize = 2_048;
const MAX_ARTIFACT_BYTES: u64 = 1_073_741_824;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Runmill owns this identifier. It is intentionally not ASF's UUID `RunId`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunmillExternalRunId(String);

impl RunmillExternalRunId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_identifier(&value, "Runmill run id")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.0, "Runmill run id")
    }
}

/// RFC 3339 wire text is retained exactly because the original spelling is
/// covered by Runmill's signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunmillEvidenceTimestamp(String);

impl RunmillEvidenceTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = Self(value.into());
        value.to_utc()?;
        Ok(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_utc(&self) -> Result<DateTime<Utc>> {
        if self.0.len() > 64 || !self.0.contains('T') {
            return Err(Error::Validation(
                "Runmill evidence timestamp is not bounded RFC 3339".into(),
            ));
        }
        DateTime::parse_from_rfc3339(&self.0)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| Error::Validation("Runmill evidence timestamp is not RFC 3339".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidenceRun {
    pub run_id: RunmillExternalRunId,
    pub attempt_id: AttemptId,
    pub work_order_id: WorkOrderId,
    pub completed_at: RunmillEvidenceTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillVerifiedWorkOrderSignature {
    pub key_id: String,
    pub algorithm: RunmillEvidenceAlgorithm,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidenceWorkOrder {
    pub envelope_digest: String,
    pub payload_digest: String,
    pub envelope_artifact_digest: String,
    pub signature: RunmillVerifiedWorkOrderSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillPolicyInputs {
    pub operator_policy_digest: String,
    pub work_order_policy_digest: String,
    pub repository_policy_digest: String,
    pub forge_policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEffectivePolicyEvidence {
    pub effective_policy_digest: String,
    pub effective_policy_artifact_digest: String,
    pub inputs: RunmillPolicyInputs,
    pub required_local_checks: Vec<String>,
    pub required_ci_contexts: Vec<String>,
    pub require_local_review: bool,
    pub require_pull_request_review: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillSourceEvidence {
    pub forge: String,
    pub repository: String,
    pub base_ref: String,
    pub base_sha: String,
    pub candidate_sha: String,
    pub remote_head_sha: String,
    pub merge_sha: Option<String>,
    pub tree_digest: String,
    pub normalized_diff_digest: String,
    pub normalized_diff_artifact_digest: String,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RunmillProviderRole {
    #[serde(rename = "implementer")]
    Implementer,
    #[serde(rename = "local-reviewer")]
    LocalReviewer,
    #[serde(rename = "pull-request-reviewer")]
    PullRequestReviewer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillProviderAttribution {
    pub role: RunmillProviderRole,
    pub provider: String,
    pub model: String,
    pub principal_id: String,
    pub lease_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillRuntimeEvidence {
    pub harness_digest: String,
    pub tool_policy_digest: String,
    pub sandbox_profile_digest: String,
    pub dependency_digest: String,
    pub runtime_digest: String,
    pub runtime_manifest_digest: String,
    pub providers: Vec<RunmillProviderAttribution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillRoleOutcomeConclusion {
    Completed,
    Passed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillRoleOutcome {
    pub role: RunmillProviderRole,
    pub outcome: RunmillRoleOutcomeConclusion,
    pub candidate_sha: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillLocalCheckConclusion {
    Success,
    Failure,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillCheckCoverage {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillLocalCheckEvidence {
    pub check_id: String,
    pub candidate_sha: String,
    pub tree_digest: String,
    pub command_digest: String,
    pub executor_id: String,
    pub toolchain_digest: String,
    pub sandbox_profile_digest: String,
    pub started_at: RunmillEvidenceTimestamp,
    pub completed_at: RunmillEvidenceTimestamp,
    pub conclusion: RunmillLocalCheckConclusion,
    pub coverage: RunmillCheckCoverage,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillCiConclusion {
    Success,
    Failure,
    Pending,
    Cancelled,
    Skipped,
    Neutral,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCiContextEvidence {
    pub context: String,
    pub candidate_sha: String,
    pub conclusion: RunmillCiConclusion,
    pub observed_at: RunmillEvidenceTimestamp,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillVerificationEvidence {
    pub local_checks: Vec<RunmillLocalCheckEvidence>,
    pub ci_contexts: Vec<RunmillCiContextEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RunmillReviewStage {
    #[serde(rename = "local")]
    Local,
    #[serde(rename = "pull-request")]
    PullRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillReviewVerdict {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillReviewEvidence {
    pub review_id: String,
    pub stage: RunmillReviewStage,
    pub reviewer_principal: String,
    pub reviewer_profile: String,
    pub independent: bool,
    pub candidate_sha: String,
    pub policy_digest: String,
    pub verdict: RunmillReviewVerdict,
    pub findings_digest: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunmillSideEffectKind {
    #[serde(rename = "branch.push")]
    BranchPush,
    #[serde(rename = "pull-request.create")]
    PullRequestCreate,
    #[serde(rename = "pull-request.update")]
    PullRequestUpdate,
    #[serde(rename = "pull-request.observe")]
    PullRequestObserve,
    #[serde(rename = "ci.observe")]
    CiObserve,
    #[serde(rename = "review.observe")]
    ReviewObserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillConfirmedStatus {
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillSideEffectEvidence {
    pub effect_key: String,
    pub kind: RunmillSideEffectKind,
    pub candidate_sha: String,
    pub intent_digest: String,
    pub observation_digest: String,
    pub reconciliation_digest: Option<String>,
    pub confirmation_digest: String,
    pub status: RunmillConfirmedStatus,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillApprovalEvidence {
    pub approval_id: String,
    pub decision_type: String,
    pub requested_effect: String,
    pub approver_subject: String,
    pub authority_digest: String,
    pub work_order_digest: String,
    pub candidate_sha: String,
    pub policy_digest: String,
    pub issued_at: RunmillEvidenceTimestamp,
    pub expires_at: RunmillEvidenceTimestamp,
    pub signature_digest: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCancellationEvidence {
    pub requester_subject: String,
    pub reason_code: String,
    pub requested_at: RunmillEvidenceTimestamp,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillBudgetEvidence {
    pub cost_usd: f64,
    pub agent_invocations: u64,
    pub fix_iterations: u64,
    pub elapsed_ms: u64,
    pub stop_reason: RunmillStopReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunmillStopReason {
    #[serde(rename = "pr-delivered")]
    PullRequestDelivered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillPullRequestDeliveryEvidence {
    pub forge: String,
    pub repository: String,
    pub number: u64,
    pub url: String,
    pub head_ref: String,
    pub base_ref: String,
    pub head_sha: String,
    pub observed_at: RunmillEvidenceTimestamp,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillClosureTarget {
    Pr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillDeliveryEvidence {
    pub closure_target: RunmillClosureTarget,
    pub satisfied: bool,
    pub pull_request: RunmillPullRequestDeliveryEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunmillArtifactKind {
    #[serde(rename = "work-order-envelope")]
    WorkOrderEnvelope,
    #[serde(rename = "effective-policy")]
    EffectivePolicy,
    #[serde(rename = "normalized-diff")]
    NormalizedDiff,
    #[serde(rename = "agent-outcome")]
    AgentOutcome,
    #[serde(rename = "verification")]
    Verification,
    #[serde(rename = "ci-observation")]
    CiObservation,
    #[serde(rename = "review")]
    Review,
    #[serde(rename = "side-effect")]
    SideEffect,
    #[serde(rename = "approval")]
    Approval,
    #[serde(rename = "runtime-manifest")]
    RuntimeManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillRetentionClass {
    Portable,
    Protected,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidenceArtifact {
    pub artifact_id: String,
    pub kind: RunmillArtifactKind,
    pub size_bytes: u64,
    pub media_type: String,
    pub digest: String,
    pub retention_class: RunmillRetentionClass,
    pub location_ref: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidencePredicate {
    pub schema: String,
    pub run: RunmillEvidenceRun,
    pub work_order: RunmillEvidenceWorkOrder,
    pub policy: RunmillEffectivePolicyEvidence,
    pub source: RunmillSourceEvidence,
    pub runtime: RunmillRuntimeEvidence,
    pub role_outcomes: Vec<RunmillRoleOutcome>,
    pub verification: RunmillVerificationEvidence,
    pub reviews: Vec<RunmillReviewEvidence>,
    pub side_effects: Vec<RunmillSideEffectEvidence>,
    pub approvals: Vec<RunmillApprovalEvidence>,
    pub cancellation: Option<RunmillCancellationEvidence>,
    pub budget: RunmillBudgetEvidence,
    pub delivery: RunmillDeliveryEvidence,
    pub artifacts: Vec<RunmillEvidenceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillSubjectDigest {
    pub sha1: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidenceSubject {
    pub name: String,
    pub digest: RunmillSubjectDigest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillEvidenceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<RunmillEvidenceSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: RunmillEvidencePredicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunmillEvidenceAlgorithm {
    EdDSA,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRunmillEvidenceBundle {
    pub schema: String,
    pub key_id: String,
    pub algorithm: RunmillEvidenceAlgorithm,
    pub issued_at: RunmillEvidenceTimestamp,
    pub bundle_digest: String,
    pub statement: RunmillEvidenceStatement,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct UnsignedRunmillEvidenceBundle<'a> {
    schema: &'a str,
    key_id: &'a str,
    algorithm: RunmillEvidenceAlgorithm,
    issued_at: &'a RunmillEvidenceTimestamp,
    bundle_digest: &'a str,
    statement: &'a RunmillEvidenceStatement,
}

impl SignedRunmillEvidenceBundle {
    pub fn sign(
        statement: RunmillEvidenceStatement,
        issued_at: RunmillEvidenceTimestamp,
        signer: &Ed25519Signer,
    ) -> Result<Self> {
        validate_statement_shape(&statement)?;
        validate_identifier(signer.key_id(), "evidence signer key id")?;
        issued_at.to_utc()?;
        let bundle_digest = sha256_digest(&canonical_json(&statement)?);
        let mut bundle = Self {
            schema: RUNMILL_SIGNED_EVIDENCE_SCHEMA_V1.into(),
            key_id: signer.key_id().into(),
            algorithm: RunmillEvidenceAlgorithm::EdDSA,
            issued_at,
            bundle_digest,
            statement,
            signature: String::new(),
        };
        reject_sensitive_fields(
            &serde_json::to_value(&bundle)
                .map_err(|error| Error::Serialization(error.to_string()))?,
        )?;
        bundle.signature = format!(
            "base64url:{}",
            signer.sign(&bundle.unsigned_canonical_bytes()?)
        );
        Ok(bundle)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::Serialization(format!("decode Runmill evidence: {error}")))?;
        bundle.validate_shape()?;
        Ok(bundle)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != RUNMILL_SIGNED_EVIDENCE_SCHEMA_V1 {
            return Err(Error::Validation(
                "unsupported Runmill signed-evidence schema".into(),
            ));
        }
        validate_identifier(&self.key_id, "evidence signer key id")?;
        self.issued_at.to_utc()?;
        validate_digest(&self.bundle_digest, "bundle digest")?;
        validate_statement_shape(&self.statement)?;
        validate_signature_encoding(&self.signature)?;
        reject_sensitive_fields(
            &serde_json::to_value(self).map_err(|error| Error::Serialization(error.to_string()))?,
        )
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(&UnsignedRunmillEvidenceBundle {
            schema: &self.schema,
            key_id: &self.key_id,
            algorithm: self.algorithm,
            issued_at: &self.issued_at,
            bundle_digest: &self.bundle_digest,
            statement: &self.statement,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TrustedRunmillEvidenceSigner<'a> {
    pub key_id: &'a str,
    pub verifying_key: &'a VerifyingKey,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthorizedRunmillReviewer<'a> {
    pub principal_id: &'a str,
    pub profile_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct RunmillEvidenceExpectation<'a> {
    pub trusted_signer: TrustedRunmillEvidenceSigner<'a>,
    pub observed_at: DateTime<Utc>,
    pub run_id: &'a RunmillExternalRunId,
    pub attempt_id: AttemptId,
    pub work_order_id: WorkOrderId,
    pub work_order_key_id: &'a str,
    pub work_order_envelope_digest: &'a str,
    pub work_order_payload_digest: &'a str,
    pub effective_policy_digest: &'a str,
    pub forge: &'a str,
    pub repository: &'a str,
    pub base_ref: &'a str,
    pub base_sha: &'a str,
    pub candidate_sha: &'a str,
    pub tree_digest: &'a str,
    pub normalized_diff_digest: &'a str,
    pub changed_paths: &'a BTreeSet<String>,
    pub required_local_checks: &'a BTreeSet<String>,
    pub required_ci_contexts: &'a BTreeSet<String>,
    pub local_reviewer: Option<AuthorizedRunmillReviewer<'a>>,
    pub pull_request_reviewer: Option<AuthorizedRunmillReviewer<'a>>,
    pub pull_request_head_ref: &'a str,
    pub independently_observed_pull_request: &'a PullRequestEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRunmillEvidence {
    pub bundle_digest: String,
    pub run_id: RunmillExternalRunId,
    pub candidate_sha: String,
    pub worker_key_id: String,
}

impl SignedRunmillEvidenceBundle {
    /// Verify the signed bundle's intrinsic integrity before using any of its
    /// claims to make an external provider request.
    pub fn verify_signed_integrity(
        &self,
        trusted_signer: &TrustedRunmillEvidenceSigner<'_>,
        observed_at: DateTime<Utc>,
    ) -> Result<()> {
        self.validate_shape()?;
        validate_identifier(trusted_signer.key_id, "trusted worker key id")?;
        let statement_digest = sha256_digest(&canonical_json(&self.statement)?);
        if statement_digest != self.bundle_digest {
            return Err(Error::Crypto(
                "Runmill evidence bundle digest does not match its JCS statement".into(),
            ));
        }
        verify_trusted_signature(self, trusted_signer, observed_at)?;
        verify_artifact_references(&self.statement.predicate)
    }

    pub fn verify(
        &self,
        expectation: &RunmillEvidenceExpectation<'_>,
    ) -> Result<ValidatedRunmillEvidence> {
        validate_expectation(expectation)?;
        self.verify_signed_integrity(&expectation.trusted_signer, expectation.observed_at)?;
        verify_bindings(self, expectation)?;
        Ok(ValidatedRunmillEvidence {
            bundle_digest: self.bundle_digest.clone(),
            run_id: self.statement.predicate.run.run_id.clone(),
            candidate_sha: self.statement.predicate.source.candidate_sha.clone(),
            worker_key_id: self.key_id.clone(),
        })
    }
}

fn validate_statement_shape(statement: &RunmillEvidenceStatement) -> Result<()> {
    if statement.statement_type != IN_TOTO_STATEMENT_V1
        || statement.predicate_type != RUNMILL_EVIDENCE_PREDICATE_TYPE_V1
        || statement.subject.len() != 1
    {
        return Err(Error::Validation(
            "Runmill evidence is not an in-toto Statement v1 with one subject".into(),
        ));
    }
    let subject = &statement.subject[0];
    validate_subject_name(&subject.name)?;
    validate_git_sha(&subject.digest.sha1, "statement subject SHA")?;
    validate_predicate_shape(&statement.predicate)
}

fn validate_predicate_shape(predicate: &RunmillEvidencePredicate) -> Result<()> {
    if predicate.schema != RUNMILL_EVIDENCE_PREDICATE_SCHEMA_V1 {
        return Err(Error::Validation(
            "unsupported Runmill evidence predicate schema".into(),
        ));
    }
    predicate.run.run_id.validate()?;
    predicate.run.completed_at.to_utc()?;
    for (label, digest) in [
        ("Work Order envelope", &predicate.work_order.envelope_digest),
        ("Work Order payload", &predicate.work_order.payload_digest),
        (
            "Work Order envelope artifact",
            &predicate.work_order.envelope_artifact_digest,
        ),
        (
            "effective policy",
            &predicate.policy.effective_policy_digest,
        ),
        (
            "effective policy artifact",
            &predicate.policy.effective_policy_artifact_digest,
        ),
        (
            "operator policy",
            &predicate.policy.inputs.operator_policy_digest,
        ),
        (
            "Work Order policy",
            &predicate.policy.inputs.work_order_policy_digest,
        ),
        (
            "repository policy",
            &predicate.policy.inputs.repository_policy_digest,
        ),
        ("forge policy", &predicate.policy.inputs.forge_policy_digest),
        ("candidate tree", &predicate.source.tree_digest),
        ("normalized diff", &predicate.source.normalized_diff_digest),
        (
            "normalized diff artifact",
            &predicate.source.normalized_diff_artifact_digest,
        ),
        ("harness", &predicate.runtime.harness_digest),
        ("tool policy", &predicate.runtime.tool_policy_digest),
        ("sandbox profile", &predicate.runtime.sandbox_profile_digest),
        ("dependencies", &predicate.runtime.dependency_digest),
        ("runtime", &predicate.runtime.runtime_digest),
        (
            "runtime manifest",
            &predicate.runtime.runtime_manifest_digest,
        ),
    ] {
        validate_digest(digest, label)?;
    }
    validate_identifier(
        &predicate.work_order.signature.key_id,
        "Work Order signature key id",
    )?;
    if !predicate.work_order.signature.verified {
        return Err(Error::Validation(
            "Runmill did not verify the Work Order signature".into(),
        ));
    }
    validate_sorted_references(
        &predicate.policy.required_local_checks,
        "required local checks",
    )?;
    validate_sorted_references(
        &predicate.policy.required_ci_contexts,
        "required CI contexts",
    )?;
    validate_identifier(&predicate.source.forge, "source forge")?;
    validate_repository(&predicate.source.repository)?;
    validate_branch_ref(&predicate.source.base_ref, "source base ref")?;
    validate_git_sha(&predicate.source.base_sha, "source base SHA")?;
    validate_git_sha(&predicate.source.candidate_sha, "source candidate SHA")?;
    validate_git_sha(&predicate.source.remote_head_sha, "source remote head SHA")?;
    if let Some(merge_sha) = &predicate.source.merge_sha {
        validate_git_sha(merge_sha, "source merge SHA")?;
    }
    validate_sorted_paths(&predicate.source.changed_paths)?;
    validate_runtime_shape(&predicate.runtime)?;
    validate_role_outcomes_shape(&predicate.role_outcomes)?;
    validate_verification_shape(&predicate.verification)?;
    validate_reviews_shape(&predicate.reviews)?;
    validate_side_effects_shape(&predicate.side_effects)?;
    validate_approvals_shape(&predicate.approvals)?;
    if let Some(cancellation) = &predicate.cancellation {
        validate_identifier(&cancellation.requester_subject, "cancellation requester")?;
        validate_identifier(&cancellation.reason_code, "cancellation reason code")?;
        cancellation.requested_at.to_utc()?;
        validate_digest(&cancellation.evidence_digest, "cancellation evidence")?;
    }
    validate_budget_shape(&predicate.budget)?;
    validate_delivery_shape(&predicate.delivery)?;
    validate_artifacts_shape(&predicate.artifacts)
}

fn validate_runtime_shape(runtime: &RunmillRuntimeEvidence) -> Result<()> {
    if runtime.providers.len() > MAX_PROVIDERS {
        return Err(Error::Validation(
            "too many Runmill provider attributions".into(),
        ));
    }
    for provider in &runtime.providers {
        validate_identifier(&provider.provider, "provider")?;
        validate_reference(&provider.model, "provider model")?;
        validate_identifier(&provider.principal_id, "provider principal")?;
        validate_identifier(&provider.lease_id, "provider lease")?;
    }
    Ok(())
}

fn validate_role_outcomes_shape(outcomes: &[RunmillRoleOutcome]) -> Result<()> {
    if outcomes.len() > MAX_ROLE_OUTCOMES {
        return Err(Error::Validation("too many Runmill role outcomes".into()));
    }
    for outcome in outcomes {
        validate_git_sha(&outcome.candidate_sha, "role outcome candidate")?;
        validate_digest(&outcome.evidence_digest, "role outcome evidence")?;
    }
    Ok(())
}

fn validate_verification_shape(verification: &RunmillVerificationEvidence) -> Result<()> {
    if verification.local_checks.len() > MAX_LOCAL_CHECKS
        || verification.ci_contexts.len() > MAX_CI_CONTEXTS
    {
        return Err(Error::Validation(
            "too many Runmill verification records".into(),
        ));
    }
    for check in &verification.local_checks {
        validate_reference(&check.check_id, "local check id")?;
        validate_git_sha(&check.candidate_sha, "local check candidate")?;
        for (label, digest) in [
            ("local check tree", &check.tree_digest),
            ("local check command", &check.command_digest),
            ("local check toolchain", &check.toolchain_digest),
            ("local check sandbox", &check.sandbox_profile_digest),
            ("local check evidence", &check.evidence_digest),
        ] {
            validate_digest(digest, label)?;
        }
        validate_identifier(&check.executor_id, "local check executor")?;
        check.started_at.to_utc()?;
        check.completed_at.to_utc()?;
    }
    for context in &verification.ci_contexts {
        validate_reference(&context.context, "CI context")?;
        validate_git_sha(&context.candidate_sha, "CI candidate")?;
        context.observed_at.to_utc()?;
        validate_digest(&context.evidence_digest, "CI evidence")?;
    }
    Ok(())
}

fn validate_reviews_shape(reviews: &[RunmillReviewEvidence]) -> Result<()> {
    if reviews.len() > MAX_REVIEWS {
        return Err(Error::Validation("too many Runmill review records".into()));
    }
    for review in reviews {
        validate_identifier(&review.review_id, "review id")?;
        validate_identifier(&review.reviewer_principal, "reviewer principal")?;
        validate_identifier(&review.reviewer_profile, "reviewer profile")?;
        if !review.independent {
            return Err(Error::Validation(
                "Runmill review evidence must assert independence".into(),
            ));
        }
        validate_git_sha(&review.candidate_sha, "review candidate")?;
        validate_digest(&review.policy_digest, "review policy")?;
        validate_digest(&review.findings_digest, "review findings")?;
        validate_digest(&review.evidence_digest, "review evidence")?;
    }
    Ok(())
}

fn validate_side_effects_shape(effects: &[RunmillSideEffectEvidence]) -> Result<()> {
    if effects.len() > MAX_SIDE_EFFECTS {
        return Err(Error::Validation("too many Runmill side effects".into()));
    }
    for effect in effects {
        validate_digest(&effect.effect_key, "side-effect key")?;
        validate_git_sha(&effect.candidate_sha, "side-effect candidate")?;
        for (label, digest) in [
            ("side-effect intent", &effect.intent_digest),
            ("side-effect observation", &effect.observation_digest),
            ("side-effect confirmation", &effect.confirmation_digest),
            ("side-effect evidence", &effect.evidence_digest),
        ] {
            validate_digest(digest, label)?;
        }
        if let Some(digest) = &effect.reconciliation_digest {
            validate_digest(digest, "side-effect reconciliation")?;
        }
    }
    Ok(())
}

fn validate_approvals_shape(approvals: &[RunmillApprovalEvidence]) -> Result<()> {
    if approvals.len() > MAX_APPROVALS {
        return Err(Error::Validation("too many Runmill approvals".into()));
    }
    for approval in approvals {
        for (label, value) in [
            ("approval id", &approval.approval_id),
            ("approval decision", &approval.decision_type),
            ("approval requested effect", &approval.requested_effect),
            ("approval subject", &approval.approver_subject),
        ] {
            validate_identifier(value, label)?;
        }
        for (label, digest) in [
            ("approval authority", &approval.authority_digest),
            ("approval Work Order", &approval.work_order_digest),
            ("approval policy", &approval.policy_digest),
            ("approval signature", &approval.signature_digest),
            ("approval evidence", &approval.evidence_digest),
        ] {
            validate_digest(digest, label)?;
        }
        validate_git_sha(&approval.candidate_sha, "approval candidate")?;
        approval.issued_at.to_utc()?;
        approval.expires_at.to_utc()?;
    }
    Ok(())
}

fn validate_budget_shape(budget: &RunmillBudgetEvidence) -> Result<()> {
    if !budget.cost_usd.is_finite()
        || budget.cost_usd < 0.0
        || [
            budget.agent_invocations,
            budget.fix_iterations,
            budget.elapsed_ms,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_JSON_INTEGER)
    {
        return Err(Error::Validation(
            "Runmill budget evidence is out of bounds".into(),
        ));
    }
    Ok(())
}

fn validate_delivery_shape(delivery: &RunmillDeliveryEvidence) -> Result<()> {
    if !delivery.satisfied {
        return Err(Error::Validation(
            "Runmill PR delivery evidence is not satisfied".into(),
        ));
    }
    let pull_request = &delivery.pull_request;
    validate_identifier(&pull_request.forge, "pull-request forge")?;
    validate_repository(&pull_request.repository)?;
    if pull_request.number == 0 || pull_request.number > MAX_SAFE_JSON_INTEGER {
        return Err(Error::Validation(
            "pull-request number is out of bounds".into(),
        ));
    }
    validate_public_https_url(&pull_request.url)?;
    validate_branch_ref(&pull_request.head_ref, "pull-request head ref")?;
    validate_branch_ref(&pull_request.base_ref, "pull-request base ref")?;
    validate_git_sha(&pull_request.head_sha, "pull-request head SHA")?;
    pull_request.observed_at.to_utc()?;
    validate_digest(&pull_request.evidence_digest, "pull-request evidence")
}

fn validate_artifacts_shape(artifacts: &[RunmillEvidenceArtifact]) -> Result<()> {
    if artifacts.len() > MAX_ARTIFACTS {
        return Err(Error::Validation(
            "too many Runmill evidence artifacts".into(),
        ));
    }
    for artifact in artifacts {
        validate_identifier(&artifact.artifact_id, "artifact id")?;
        if artifact.size_bytes > MAX_ARTIFACT_BYTES {
            return Err(Error::Validation("Runmill artifact is too large".into()));
        }
        validate_media_type(&artifact.media_type)?;
        validate_digest(&artifact.digest, "artifact digest")?;
        validate_cas_location(&artifact.location_ref)?;
    }
    Ok(())
}

fn verify_trusted_signature(
    bundle: &SignedRunmillEvidenceBundle,
    trusted: &TrustedRunmillEvidenceSigner<'_>,
    observed_at: DateTime<Utc>,
) -> Result<()> {
    if trusted.revoked
        || trusted.key_id != bundle.key_id
        || trusted.valid_from >= trusted.valid_until
    {
        return Err(Error::Crypto(
            "Runmill evidence signer is unknown, revoked, or contradictory".into(),
        ));
    }
    let issued_at = bundle.issued_at.to_utc()?;
    if issued_at < trusted.valid_from || issued_at >= trusted.valid_until || issued_at > observed_at
    {
        return Err(Error::Crypto(
            "Runmill evidence signer was not trusted at bundle issuance".into(),
        ));
    }
    let encoded = bundle
        .signature
        .strip_prefix("base64url:")
        .ok_or_else(|| Error::Crypto("Runmill evidence signature prefix is invalid".into()))?;
    verify_signature(
        trusted.verifying_key,
        &bundle.unsigned_canonical_bytes()?,
        encoded,
    )
}

fn verify_bindings(
    bundle: &SignedRunmillEvidenceBundle,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let statement = &bundle.statement;
    let predicate = &statement.predicate;
    let source = &predicate.source;
    if &predicate.run.run_id != expectation.run_id
        || predicate.run.attempt_id != expectation.attempt_id
        || predicate.run.work_order_id != expectation.work_order_id
        || predicate.work_order.signature.key_id != expectation.work_order_key_id
        || predicate.work_order.envelope_digest != expectation.work_order_envelope_digest
        || predicate.work_order.payload_digest != expectation.work_order_payload_digest
        || predicate.policy.effective_policy_digest != expectation.effective_policy_digest
        || source.forge != expectation.forge
        || source.repository != expectation.repository
        || source.base_ref != expectation.base_ref
        || source.base_sha != expectation.base_sha
        || source.candidate_sha != expectation.candidate_sha
        || source.remote_head_sha != expectation.candidate_sha
        || source.tree_digest != expectation.tree_digest
        || source.normalized_diff_digest != expectation.normalized_diff_digest
        || source.merge_sha.is_some()
    {
        return Err(Error::Validation(
            "Runmill evidence is not bound to the expected run, Work Order, policy, and candidate"
                .into(),
        ));
    }
    let subject = &statement.subject[0];
    if subject.name != format!("{}:{}", expectation.forge, expectation.repository)
        || subject.digest.sha1 != expectation.candidate_sha
    {
        return Err(Error::Validation(
            "in-toto subject is not the exact expected candidate".into(),
        ));
    }
    if !same_values(&source.changed_paths, expectation.changed_paths)
        || !same_values(
            &predicate.policy.required_local_checks,
            expectation.required_local_checks,
        )
        || !same_values(
            &predicate.policy.required_ci_contexts,
            expectation.required_ci_contexts,
        )
        || predicate.policy.require_local_review != expectation.local_reviewer.is_some()
        || predicate.policy.require_pull_request_review
            != expectation.pull_request_reviewer.is_some()
    {
        return Err(Error::Validation(
            "Runmill evidence requirements do not match authoritative policy".into(),
        ));
    }
    if predicate.cancellation.is_some() {
        return Err(Error::Validation(
            "cancelled Runmill evidence cannot satisfy PR delivery".into(),
        ));
    }
    verify_providers_and_outcomes(predicate, expectation)?;
    verify_local_checks(predicate, expectation)?;
    verify_ci_contexts(predicate, expectation)?;
    verify_reviews(predicate, expectation)?;
    verify_side_effects(predicate, expectation)?;
    verify_approvals(predicate, expectation)?;
    verify_pull_request(predicate, expectation)?;
    if bundle.issued_at.to_utc()? < predicate.run.completed_at.to_utc()? {
        return Err(Error::Validation(
            "Runmill evidence bundle predates run completion".into(),
        ));
    }
    Ok(())
}

fn verify_providers_and_outcomes(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let providers = unique_provider_roles(&predicate.runtime.providers)?;
    for role in [
        RunmillProviderRole::Implementer,
        RunmillProviderRole::LocalReviewer,
        RunmillProviderRole::PullRequestReviewer,
    ] {
        if !providers.contains_key(&role) {
            return Err(Error::Validation(format!(
                "Runmill evidence is missing {role:?} provider attribution"
            )));
        }
    }
    let implementer = providers
        .get(&RunmillProviderRole::Implementer)
        .expect("implementer presence checked");
    for (role, reviewer) in [
        (
            RunmillProviderRole::LocalReviewer,
            expectation.local_reviewer,
        ),
        (
            RunmillProviderRole::PullRequestReviewer,
            expectation.pull_request_reviewer,
        ),
    ] {
        if let Some(reviewer) = reviewer {
            let provider = providers.get(&role).expect("reviewer presence checked");
            if provider.principal_id != reviewer.principal_id
                || provider.principal_id == implementer.principal_id
            {
                return Err(Error::Validation(
                    "Runmill reviewer provider is not the independent authorized principal".into(),
                ));
            }
        }
    }
    let mut outcomes = BTreeMap::new();
    for outcome in &predicate.role_outcomes {
        if outcomes.insert(outcome.role, outcome).is_some() {
            return Err(Error::Validation(
                "Runmill role outcomes contain a duplicate role".into(),
            ));
        }
        if outcome.candidate_sha != expectation.candidate_sha {
            return Err(Error::Validation(
                "Runmill role outcome names a different candidate".into(),
            ));
        }
    }
    if outcomes
        .get(&RunmillProviderRole::Implementer)
        .is_none_or(|outcome| outcome.outcome != RunmillRoleOutcomeConclusion::Completed)
        || expectation.local_reviewer.is_some()
            && outcomes
                .get(&RunmillProviderRole::LocalReviewer)
                .is_none_or(|outcome| outcome.outcome != RunmillRoleOutcomeConclusion::Passed)
        || expectation.pull_request_reviewer.is_some()
            && outcomes
                .get(&RunmillProviderRole::PullRequestReviewer)
                .is_none_or(|outcome| outcome.outcome != RunmillRoleOutcomeConclusion::Passed)
    {
        return Err(Error::Validation(
            "Runmill role outcomes do not prove completed implementation and required reviews"
                .into(),
        ));
    }
    Ok(())
}

fn verify_local_checks(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let mut checks = BTreeMap::new();
    for check in &predicate.verification.local_checks {
        if checks.insert(check.check_id.as_str(), check).is_some() {
            return Err(Error::Validation(
                "Runmill local checks contain a duplicate id".into(),
            ));
        }
        if check.candidate_sha != expectation.candidate_sha
            || check.tree_digest != expectation.tree_digest
            || check.conclusion != RunmillLocalCheckConclusion::Success
            || check.coverage != RunmillCheckCoverage::Complete
            || check.started_at.to_utc()? > check.completed_at.to_utc()?
        {
            return Err(Error::Validation(
                "Runmill local check is not a complete success on the exact candidate tree".into(),
            ));
        }
    }
    if !expectation
        .required_local_checks
        .iter()
        .all(|required| checks.contains_key(required.as_str()))
    {
        return Err(Error::Validation(
            "Runmill evidence is missing a required local check".into(),
        ));
    }
    Ok(())
}

fn verify_ci_contexts(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let mut contexts = BTreeMap::new();
    for context in &predicate.verification.ci_contexts {
        if contexts.insert(context.context.as_str(), context).is_some() {
            return Err(Error::Validation(
                "Runmill CI evidence contains a duplicate context".into(),
            ));
        }
        if context.candidate_sha != expectation.candidate_sha
            || context.conclusion != RunmillCiConclusion::Success
        {
            return Err(Error::Validation(
                "Runmill CI context is not a non-skipped success on the exact candidate".into(),
            ));
        }
    }
    if !expectation
        .required_ci_contexts
        .iter()
        .all(|required| contexts.contains_key(required.as_str()))
    {
        return Err(Error::Validation(
            "Runmill evidence is missing a required CI context".into(),
        ));
    }
    Ok(())
}

fn verify_reviews(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let providers = unique_provider_roles(&predicate.runtime.providers)?;
    for review in &predicate.reviews {
        if !ids.insert(review.review_id.as_str()) {
            return Err(Error::Validation(
                "Runmill reviews contain a duplicate id".into(),
            ));
        }
        let authorized = match review.stage {
            RunmillReviewStage::Local => expectation.local_reviewer,
            RunmillReviewStage::PullRequest => expectation.pull_request_reviewer,
        }
        .ok_or_else(|| {
            Error::Validation("Runmill evidence contains an unauthorized review".into())
        })?;
        let provider_role = match review.stage {
            RunmillReviewStage::Local => RunmillProviderRole::LocalReviewer,
            RunmillReviewStage::PullRequest => RunmillProviderRole::PullRequestReviewer,
        };
        let provider = providers
            .get(&provider_role)
            .expect("all provider roles checked before review validation");
        if !review.independent
            || review.reviewer_principal != authorized.principal_id
            || review.reviewer_profile != authorized.profile_id
            || provider.principal_id != review.reviewer_principal
            || review.candidate_sha != expectation.candidate_sha
            || review.policy_digest != expectation.effective_policy_digest
            || review.verdict != RunmillReviewVerdict::Pass
        {
            return Err(Error::Validation(
                "Runmill review is not an independent authorized pass on exact policy and candidate"
                    .into(),
            ));
        }
    }
    for (stage, required) in [
        (
            RunmillReviewStage::Local,
            expectation.local_reviewer.is_some(),
        ),
        (
            RunmillReviewStage::PullRequest,
            expectation.pull_request_reviewer.is_some(),
        ),
    ] {
        if required && !predicate.reviews.iter().any(|review| review.stage == stage) {
            return Err(Error::Validation(
                "Runmill evidence is missing an authorized required review".into(),
            ));
        }
    }
    Ok(())
}

fn verify_side_effects(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let mut keys = BTreeSet::new();
    for effect in &predicate.side_effects {
        if !keys.insert(effect.effect_key.as_str())
            || effect.candidate_sha != expectation.candidate_sha
        {
            return Err(Error::Validation(
                "Runmill side effect is duplicate or names a different candidate".into(),
            ));
        }
    }
    for required in [
        RunmillSideEffectKind::BranchPush,
        RunmillSideEffectKind::PullRequestCreate,
    ] {
        if !predicate
            .side_effects
            .iter()
            .any(|effect| effect.kind == required)
        {
            return Err(Error::Validation(
                "Runmill evidence is missing a required confirmed delivery effect".into(),
            ));
        }
    }
    Ok(())
}

fn verify_approvals(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    for approval in &predicate.approvals {
        if !ids.insert(approval.approval_id.as_str())
            || approval.work_order_digest != expectation.work_order_payload_digest
            || approval.candidate_sha != expectation.candidate_sha
            || approval.policy_digest != expectation.effective_policy_digest
            || approval.issued_at.to_utc()? >= approval.expires_at.to_utc()?
            || expectation.observed_at >= approval.expires_at.to_utc()?
        {
            return Err(Error::Validation(
                "Runmill approval is duplicate, stale, expired, or incorrectly bound".into(),
            ));
        }
    }
    Ok(())
}

fn verify_pull_request(
    predicate: &RunmillEvidencePredicate,
    expectation: &RunmillEvidenceExpectation<'_>,
) -> Result<()> {
    let delivery = &predicate.delivery.pull_request;
    let observed = expectation.independently_observed_pull_request;
    if delivery.forge != expectation.forge
        || delivery.repository != expectation.repository
        || delivery.repository != observed.repository
        || delivery.number != observed.number
        || delivery.url != observed.url
        || delivery.head_ref != expectation.pull_request_head_ref
        || delivery.base_ref != expectation.base_ref
        || delivery.head_sha != expectation.candidate_sha
        || observed.base_sha != expectation.base_sha
        || observed.head_sha != expectation.candidate_sha
        || observed.required_ci_contexts != *expectation.required_ci_contexts
        || !expectation
            .required_ci_contexts
            .is_subset(&observed.successful_ci_contexts)
    {
        return Err(Error::Validation(
            "Runmill PR delivery does not match ASF's independent exact-candidate observation"
                .into(),
        ));
    }
    Ok(())
}

fn verify_artifact_references(predicate: &RunmillEvidencePredicate) -> Result<()> {
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    for artifact in &predicate.artifacts {
        if !artifact_ids.insert(artifact.artifact_id.as_str()) {
            return Err(Error::Validation(
                "Runmill artifact manifest contains a duplicate id".into(),
            ));
        }
        let expected_location = format!(
            "cas://sha256/{}",
            artifact
                .digest
                .strip_prefix("sha256:")
                .expect("validated digest prefix")
        );
        if artifact.location_ref != expected_location {
            return Err(Error::Validation(
                "Runmill artifact location is not bound to its digest".into(),
            ));
        }
        if !artifact_digests.insert(artifact.digest.as_str()) {
            return Err(Error::Validation(
                "Runmill artifact manifest contains a duplicate digest".into(),
            ));
        }
    }
    let mut references = vec![
        predicate.work_order.envelope_artifact_digest.as_str(),
        predicate.policy.effective_policy_artifact_digest.as_str(),
        predicate.source.normalized_diff_artifact_digest.as_str(),
        predicate.runtime.runtime_manifest_digest.as_str(),
        predicate.delivery.pull_request.evidence_digest.as_str(),
    ];
    references.extend(
        predicate
            .role_outcomes
            .iter()
            .map(|outcome| outcome.evidence_digest.as_str()),
    );
    references.extend(
        predicate
            .verification
            .local_checks
            .iter()
            .map(|check| check.evidence_digest.as_str()),
    );
    references.extend(
        predicate
            .verification
            .ci_contexts
            .iter()
            .map(|context| context.evidence_digest.as_str()),
    );
    for review in &predicate.reviews {
        references.push(review.findings_digest.as_str());
        references.push(review.evidence_digest.as_str());
    }
    references.extend(
        predicate
            .side_effects
            .iter()
            .map(|effect| effect.evidence_digest.as_str()),
    );
    references.extend(
        predicate
            .approvals
            .iter()
            .map(|approval| approval.evidence_digest.as_str()),
    );
    if let Some(cancellation) = &predicate.cancellation {
        references.push(cancellation.evidence_digest.as_str());
    }
    if references
        .into_iter()
        .any(|reference| !artifact_digests.contains(reference))
    {
        return Err(Error::Validation(
            "Runmill evidence references an artifact absent from its manifest".into(),
        ));
    }

    let has_kind = |digest: &str, kind: RunmillArtifactKind| {
        predicate
            .artifacts
            .iter()
            .any(|artifact| artifact.digest == digest && artifact.kind == kind)
    };
    if !has_kind(
        &predicate.work_order.envelope_artifact_digest,
        RunmillArtifactKind::WorkOrderEnvelope,
    ) || !has_kind(
        &predicate.policy.effective_policy_artifact_digest,
        RunmillArtifactKind::EffectivePolicy,
    ) || !has_kind(
        &predicate.source.normalized_diff_artifact_digest,
        RunmillArtifactKind::NormalizedDiff,
    ) || !has_kind(
        &predicate.runtime.runtime_manifest_digest,
        RunmillArtifactKind::RuntimeManifest,
    ) || !has_kind(
        &predicate.delivery.pull_request.evidence_digest,
        RunmillArtifactKind::SideEffect,
    ) || predicate
        .role_outcomes
        .iter()
        .any(|outcome| !has_kind(&outcome.evidence_digest, RunmillArtifactKind::AgentOutcome))
        || predicate
            .verification
            .local_checks
            .iter()
            .any(|check| !has_kind(&check.evidence_digest, RunmillArtifactKind::Verification))
        || predicate
            .verification
            .ci_contexts
            .iter()
            .any(|context| !has_kind(&context.evidence_digest, RunmillArtifactKind::CiObservation))
        || predicate.reviews.iter().any(|review| {
            !has_kind(&review.findings_digest, RunmillArtifactKind::Review)
                || !has_kind(&review.evidence_digest, RunmillArtifactKind::Review)
        })
        || predicate
            .side_effects
            .iter()
            .any(|effect| !has_kind(&effect.evidence_digest, RunmillArtifactKind::SideEffect))
        || predicate
            .approvals
            .iter()
            .any(|approval| !has_kind(&approval.evidence_digest, RunmillArtifactKind::Approval))
    {
        return Err(Error::Validation(
            "Runmill evidence artifact kinds do not match their signed semantic references".into(),
        ));
    }
    Ok(())
}

fn validate_expectation(expectation: &RunmillEvidenceExpectation<'_>) -> Result<()> {
    expectation.run_id.validate()?;
    validate_identifier(expectation.trusted_signer.key_id, "trusted worker key id")?;
    validate_identifier(expectation.work_order_key_id, "trusted Work Order key id")?;
    for (label, digest) in [
        (
            "expected Work Order envelope",
            expectation.work_order_envelope_digest,
        ),
        (
            "expected Work Order payload",
            expectation.work_order_payload_digest,
        ),
        (
            "expected effective policy",
            expectation.effective_policy_digest,
        ),
        ("expected tree", expectation.tree_digest),
        (
            "expected normalized diff",
            expectation.normalized_diff_digest,
        ),
    ] {
        validate_digest(digest, label)?;
    }
    validate_identifier(expectation.forge, "expected forge")?;
    validate_repository(expectation.repository)?;
    validate_branch_ref(expectation.base_ref, "expected base ref")?;
    validate_branch_ref(expectation.pull_request_head_ref, "expected PR head ref")?;
    validate_git_sha(expectation.base_sha, "expected base SHA")?;
    validate_git_sha(expectation.candidate_sha, "expected candidate SHA")?;
    for value in expectation.changed_paths {
        validate_path(value)?;
    }
    for value in expectation
        .required_local_checks
        .iter()
        .chain(expectation.required_ci_contexts)
    {
        validate_reference(value, "expected check requirement")?;
    }
    for reviewer in [
        expectation.local_reviewer,
        expectation.pull_request_reviewer,
    ]
    .into_iter()
    .flatten()
    {
        validate_identifier(reviewer.principal_id, "authorized reviewer principal")?;
        validate_identifier(reviewer.profile_id, "authorized reviewer profile")?;
    }
    Ok(())
}

fn unique_provider_roles(
    providers: &[RunmillProviderAttribution],
) -> Result<BTreeMap<RunmillProviderRole, &RunmillProviderAttribution>> {
    let mut values = BTreeMap::new();
    for provider in providers {
        if values.insert(provider.role, provider).is_some() {
            return Err(Error::Validation(
                "Runmill providers contain a duplicate role".into(),
            ));
        }
    }
    Ok(values)
}

fn same_values(actual: &[String], expected: &BTreeSet<String>) -> bool {
    actual.len() == expected.len() && actual.iter().all(|value| expected.contains(value))
}

fn validate_signature_encoding(value: &str) -> Result<()> {
    let Some(encoded) = value.strip_prefix("base64url:") else {
        return Err(Error::Validation(
            "Runmill signature must have the base64url prefix".into(),
        ));
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Validation("Runmill signature is not base64url".into()))?;
    if decoded.len() != 64 || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(Error::Validation(
            "Runmill signature is not canonical 64-byte Ed25519 base64url".into(),
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(Error::Validation(format!(
            "{label} is not a Runmill identifier"
        )));
    }
    Ok(())
}

fn validate_reference(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
    {
        return Err(Error::Validation(format!(
            "{label} is not a Runmill reference"
        )));
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<()> {
    if value.len() < 3 || value.len() > MAX_REPOSITORY_BYTES {
        return Err(Error::Validation(
            "Runmill repository slug is out of bounds".into(),
        ));
    }
    let mut parts = value.split('/');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    };
    if !parts.next().is_some_and(valid_part)
        || !parts.next().is_some_and(valid_part)
        || parts.next().is_some()
    {
        return Err(Error::Validation(
            "Runmill repository must be an owner/name slug".into(),
        ));
    }
    Ok(())
}

fn validate_branch_ref(value: &str, label: &str) -> Result<()> {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return Err(Error::Validation(format!("{label} is not a branch ref")));
    };
    if value.len() < 12
        || value.len() > MAX_BRANCH_REF_BYTES
        || branch.is_empty()
        || !branch.as_bytes()[0].is_ascii_alphanumeric()
        || !branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    {
        return Err(Error::Validation(format!(
            "{label} is not a safe branch ref"
        )));
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|part| part == "..")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(Error::Validation(
            "Runmill changed path is not normalized and repository-relative".into(),
        ));
    }
    Ok(())
}

fn validate_sorted_references(values: &[String], label: &str) -> Result<()> {
    if values.len() > MAX_SORTED_STRINGS {
        return Err(Error::Validation(format!(
            "{label} exceeds the Runmill bound"
        )));
    }
    for value in values {
        validate_reference(value, label)?;
    }
    validate_lexically_sorted_unique(values, label)
}

fn validate_sorted_paths(values: &[String]) -> Result<()> {
    if values.len() > MAX_SORTED_STRINGS {
        return Err(Error::Validation(
            "Runmill changed paths exceed the manifest bound".into(),
        ));
    }
    for value in values {
        validate_path(value)?;
    }
    validate_lexically_sorted_unique(values, "changed paths")
}

fn validate_lexically_sorted_unique(values: &[String], label: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Validation(format!(
            "Runmill {label} must be unique and lexically sorted"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "Runmill {label} must be a lowercase sha256 digest"
        )))
    }
}

fn validate_git_sha(value: &str, label: &str) -> Result<()> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "Runmill {label} must be a lowercase 40-hex Git SHA"
        )))
    }
}

fn validate_subject_name(value: &str) -> Result<()> {
    let Some((forge, repository)) = value.split_once(':') else {
        return Err(Error::Validation(
            "Runmill statement subject is malformed".into(),
        ));
    };
    if forge.is_empty()
        || !forge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::Validation(
            "Runmill statement forge is malformed".into(),
        ));
    }
    validate_repository(repository)
}

fn validate_media_type(value: &str) -> Result<()> {
    let Some((kind, subtype)) = value.split_once('/') else {
        return Err(Error::Validation(
            "Runmill artifact media type is malformed".into(),
        ));
    };
    let valid = |part: &str| {
        !part.is_empty()
            && part.as_bytes()[0].is_ascii_lowercase()
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    };
    if value.len() < 3 || value.len() > MAX_IDENTIFIER_BYTES || !valid(kind) || !valid(subtype) {
        return Err(Error::Validation(
            "Runmill artifact media type is malformed".into(),
        ));
    }
    Ok(())
}

fn validate_public_https_url(value: &str) -> Result<()> {
    let url = Url::parse(value)
        .map_err(|_| Error::Validation("Runmill pull-request URL is malformed".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Validation(
            "Runmill pull-request URL must be public HTTPS without credentials, query, or fragment"
                .into(),
        ));
    }
    Ok(())
}

fn validate_cas_location(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("cas://sha256/") else {
        return Err(Error::Validation(
            "Runmill artifact location is not CAS".into(),
        ));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::Validation(
            "Runmill artifact CAS location is malformed".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use uuid::Uuid;

    use crate::crypto::{encode_verifying_key, verify_domain_signature};

    use super::*;

    const FIXTURE_SEED: [u8; 32] = [7; 32];
    const WORKER_KEY_ID: &str = "runmill-worker-fixture";
    const WORK_ORDER_KEY_ID: &str = "asf-work-order-fixture";
    const FORGE: &str = "github";
    const REPOSITORY: &str = "acme/widgets";
    const BASE_REF: &str = "refs/heads/main";
    const HEAD_REF: &str = "refs/heads/runmill/run_01JTEST";
    const BASE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CANDIDATE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PR_URL: &str = "https://github.com/acme/widgets/pull/42";

    struct TestAuthority {
        verifying_key: VerifyingKey,
        run_id: RunmillExternalRunId,
        attempt_id: AttemptId,
        work_order_id: WorkOrderId,
        work_order_envelope_digest: String,
        work_order_payload_digest: String,
        effective_policy_digest: String,
        tree_digest: String,
        normalized_diff_digest: String,
        changed_paths: BTreeSet<String>,
        required_local_checks: BTreeSet<String>,
        required_ci_contexts: BTreeSet<String>,
        observed_pull_request: PullRequestEvidence,
    }

    impl TestAuthority {
        fn expectation(&self) -> RunmillEvidenceExpectation<'_> {
            RunmillEvidenceExpectation {
                trusted_signer: TrustedRunmillEvidenceSigner {
                    key_id: WORKER_KEY_ID,
                    verifying_key: &self.verifying_key,
                    valid_from: instant("2026-08-21T09:00:00Z"),
                    valid_until: instant("2026-08-22T09:00:00Z"),
                    revoked: false,
                },
                observed_at: instant("2026-08-21T10:30:00Z"),
                run_id: &self.run_id,
                attempt_id: self.attempt_id,
                work_order_id: self.work_order_id,
                work_order_key_id: WORK_ORDER_KEY_ID,
                work_order_envelope_digest: &self.work_order_envelope_digest,
                work_order_payload_digest: &self.work_order_payload_digest,
                effective_policy_digest: &self.effective_policy_digest,
                forge: FORGE,
                repository: REPOSITORY,
                base_ref: BASE_REF,
                base_sha: BASE_SHA,
                candidate_sha: CANDIDATE_SHA,
                tree_digest: &self.tree_digest,
                normalized_diff_digest: &self.normalized_diff_digest,
                changed_paths: &self.changed_paths,
                required_local_checks: &self.required_local_checks,
                required_ci_contexts: &self.required_ci_contexts,
                local_reviewer: Some(AuthorizedRunmillReviewer {
                    principal_id: "reviewer-local",
                    profile_id: "profile-local",
                }),
                pull_request_reviewer: Some(AuthorizedRunmillReviewer {
                    principal_id: "reviewer-pr",
                    profile_id: "profile-pr",
                }),
                pull_request_head_ref: HEAD_REF,
                independently_observed_pull_request: &self.observed_pull_request,
            }
        }
    }

    struct TestFixture {
        bundle: SignedRunmillEvidenceBundle,
        authority: TestAuthority,
    }

    fn fixed_signer() -> Ed25519Signer {
        Ed25519Signer::from_base64_seed(WORKER_KEY_ID, &STANDARD.encode(FIXTURE_SEED)).unwrap()
    }

    fn timestamp(value: &str) -> RunmillEvidenceTimestamp {
        RunmillEvidenceTimestamp::new(value).unwrap()
    }

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc))
            .unwrap()
    }

    fn digest(label: &str) -> String {
        sha256_digest(label.as_bytes())
    }

    fn artifact(
        artifact_id: &str,
        kind: RunmillArtifactKind,
        digest: &str,
    ) -> RunmillEvidenceArtifact {
        RunmillEvidenceArtifact {
            artifact_id: artifact_id.into(),
            kind,
            size_bytes: 10,
            media_type: "application/json".into(),
            digest: digest.into(),
            retention_class: RunmillRetentionClass::Portable,
            location_ref: format!("cas://sha256/{}", digest.strip_prefix("sha256:").unwrap()),
        }
    }

    fn fixture() -> TestFixture {
        let signer = fixed_signer();
        let verifying_key = signer.verifying_key();
        let run_id = RunmillExternalRunId::new("run_01JTEST").unwrap();
        let attempt_id =
            AttemptId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000004").unwrap());
        let work_order_id = WorkOrderId::from_uuid(
            Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
        );

        let work_order_envelope_digest = digest("work-order-envelope");
        let work_order_payload_digest = digest("work-order-payload");
        let effective_policy_digest = digest("effective-policy");
        let normalized_diff_digest = digest("normalized-diff");
        let tree_digest = digest("candidate-tree");
        let runtime_manifest_digest = digest("runtime-manifest");
        let implementer_outcome_digest = digest("implementer-outcome");
        let local_reviewer_outcome_digest = digest("local-reviewer-outcome");
        let pull_request_reviewer_outcome_digest = digest("pull-request-reviewer-outcome");
        let local_check_digest = digest("local-check-lint");
        let ci_digest = digest("ci-test");
        let local_review_digest = digest("local-review");
        let pull_request_review_digest = digest("pull-request-review");
        let branch_push_digest = digest("branch-push");
        let pull_request_create_digest = digest("pull-request-create");

        let changed_paths = BTreeSet::from(["src/lib.rs".to_owned()]);
        let required_local_checks = BTreeSet::from(["lint".to_owned()]);
        let required_ci_contexts = BTreeSet::from(["ci/test".to_owned()]);
        let observed_pull_request = PullRequestEvidence {
            repository: REPOSITORY.into(),
            number: 42,
            url: PR_URL.into(),
            base_sha: BASE_SHA.into(),
            head_sha: CANDIDATE_SHA.into(),
            required_ci_contexts: required_ci_contexts.clone(),
            successful_ci_contexts: required_ci_contexts.clone(),
        };

        let predicate = RunmillEvidencePredicate {
            schema: RUNMILL_EVIDENCE_PREDICATE_SCHEMA_V1.into(),
            run: RunmillEvidenceRun {
                run_id: run_id.clone(),
                attempt_id,
                work_order_id,
                completed_at: timestamp("2026-08-21T10:19:00Z"),
            },
            work_order: RunmillEvidenceWorkOrder {
                envelope_digest: work_order_envelope_digest.clone(),
                payload_digest: work_order_payload_digest.clone(),
                envelope_artifact_digest: work_order_envelope_digest.clone(),
                signature: RunmillVerifiedWorkOrderSignature {
                    key_id: WORK_ORDER_KEY_ID.into(),
                    algorithm: RunmillEvidenceAlgorithm::EdDSA,
                    verified: true,
                },
            },
            policy: RunmillEffectivePolicyEvidence {
                effective_policy_digest: effective_policy_digest.clone(),
                effective_policy_artifact_digest: effective_policy_digest.clone(),
                inputs: RunmillPolicyInputs {
                    operator_policy_digest: digest("operator-policy"),
                    work_order_policy_digest: digest("work-order-policy"),
                    repository_policy_digest: digest("repository-policy"),
                    forge_policy_digest: digest("forge-policy"),
                },
                required_local_checks: required_local_checks.iter().cloned().collect(),
                required_ci_contexts: required_ci_contexts.iter().cloned().collect(),
                require_local_review: true,
                require_pull_request_review: true,
            },
            source: RunmillSourceEvidence {
                forge: FORGE.into(),
                repository: REPOSITORY.into(),
                base_ref: BASE_REF.into(),
                base_sha: BASE_SHA.into(),
                candidate_sha: CANDIDATE_SHA.into(),
                remote_head_sha: CANDIDATE_SHA.into(),
                merge_sha: None,
                tree_digest: tree_digest.clone(),
                normalized_diff_digest: normalized_diff_digest.clone(),
                normalized_diff_artifact_digest: normalized_diff_digest.clone(),
                changed_paths: changed_paths.iter().cloned().collect(),
            },
            runtime: RunmillRuntimeEvidence {
                harness_digest: digest("harness"),
                tool_policy_digest: digest("tool-policy"),
                sandbox_profile_digest: digest("sandbox-profile"),
                dependency_digest: digest("dependencies"),
                runtime_digest: digest("runtime"),
                runtime_manifest_digest: runtime_manifest_digest.clone(),
                providers: vec![
                    RunmillProviderAttribution {
                        role: RunmillProviderRole::Implementer,
                        provider: "openai".into(),
                        model: "gpt-5.4".into(),
                        principal_id: "implementer".into(),
                        lease_id: "lease-implementer".into(),
                    },
                    RunmillProviderAttribution {
                        role: RunmillProviderRole::LocalReviewer,
                        provider: "anthropic".into(),
                        model: "claude-opus-4.1".into(),
                        principal_id: "reviewer-local".into(),
                        lease_id: "lease-local".into(),
                    },
                    RunmillProviderAttribution {
                        role: RunmillProviderRole::PullRequestReviewer,
                        provider: "anthropic".into(),
                        model: "claude-opus-4.1".into(),
                        principal_id: "reviewer-pr".into(),
                        lease_id: "lease-pr".into(),
                    },
                ],
            },
            role_outcomes: vec![
                RunmillRoleOutcome {
                    role: RunmillProviderRole::Implementer,
                    outcome: RunmillRoleOutcomeConclusion::Completed,
                    candidate_sha: CANDIDATE_SHA.into(),
                    evidence_digest: implementer_outcome_digest.clone(),
                },
                RunmillRoleOutcome {
                    role: RunmillProviderRole::LocalReviewer,
                    outcome: RunmillRoleOutcomeConclusion::Passed,
                    candidate_sha: CANDIDATE_SHA.into(),
                    evidence_digest: local_reviewer_outcome_digest.clone(),
                },
                RunmillRoleOutcome {
                    role: RunmillProviderRole::PullRequestReviewer,
                    outcome: RunmillRoleOutcomeConclusion::Passed,
                    candidate_sha: CANDIDATE_SHA.into(),
                    evidence_digest: pull_request_reviewer_outcome_digest.clone(),
                },
            ],
            verification: RunmillVerificationEvidence {
                local_checks: vec![RunmillLocalCheckEvidence {
                    check_id: "lint".into(),
                    candidate_sha: CANDIDATE_SHA.into(),
                    tree_digest: tree_digest.clone(),
                    command_digest: digest("cargo-clippy-command"),
                    executor_id: "executor-linux".into(),
                    toolchain_digest: digest("rust-toolchain"),
                    sandbox_profile_digest: digest("sandbox-profile"),
                    started_at: timestamp("2026-08-21T10:05:00Z"),
                    completed_at: timestamp("2026-08-21T10:10:00Z"),
                    conclusion: RunmillLocalCheckConclusion::Success,
                    coverage: RunmillCheckCoverage::Complete,
                    evidence_digest: local_check_digest.clone(),
                }],
                ci_contexts: vec![RunmillCiContextEvidence {
                    context: "ci/test".into(),
                    candidate_sha: CANDIDATE_SHA.into(),
                    conclusion: RunmillCiConclusion::Success,
                    observed_at: timestamp("2026-08-21T10:15:00Z"),
                    evidence_digest: ci_digest.clone(),
                }],
            },
            reviews: vec![
                RunmillReviewEvidence {
                    review_id: "review-local-1".into(),
                    stage: RunmillReviewStage::Local,
                    reviewer_principal: "reviewer-local".into(),
                    reviewer_profile: "profile-local".into(),
                    independent: true,
                    candidate_sha: CANDIDATE_SHA.into(),
                    policy_digest: effective_policy_digest.clone(),
                    verdict: RunmillReviewVerdict::Pass,
                    findings_digest: local_review_digest.clone(),
                    evidence_digest: local_review_digest.clone(),
                },
                RunmillReviewEvidence {
                    review_id: "review-pr-1".into(),
                    stage: RunmillReviewStage::PullRequest,
                    reviewer_principal: "reviewer-pr".into(),
                    reviewer_profile: "profile-pr".into(),
                    independent: true,
                    candidate_sha: CANDIDATE_SHA.into(),
                    policy_digest: effective_policy_digest.clone(),
                    verdict: RunmillReviewVerdict::Pass,
                    findings_digest: pull_request_review_digest.clone(),
                    evidence_digest: pull_request_review_digest.clone(),
                },
            ],
            side_effects: vec![
                RunmillSideEffectEvidence {
                    effect_key: digest("effect-key-branch-push"),
                    kind: RunmillSideEffectKind::BranchPush,
                    candidate_sha: CANDIDATE_SHA.into(),
                    intent_digest: digest("branch-push-intent"),
                    observation_digest: digest("branch-push-observation"),
                    reconciliation_digest: None,
                    confirmation_digest: digest("branch-push-confirmation"),
                    status: RunmillConfirmedStatus::Confirmed,
                    evidence_digest: branch_push_digest.clone(),
                },
                RunmillSideEffectEvidence {
                    effect_key: digest("effect-key-pr-create"),
                    kind: RunmillSideEffectKind::PullRequestCreate,
                    candidate_sha: CANDIDATE_SHA.into(),
                    intent_digest: digest("pr-create-intent"),
                    observation_digest: digest("pr-create-observation"),
                    reconciliation_digest: Some(digest("pr-create-reconciliation")),
                    confirmation_digest: digest("pr-create-confirmation"),
                    status: RunmillConfirmedStatus::Confirmed,
                    evidence_digest: pull_request_create_digest.clone(),
                },
            ],
            approvals: Vec::new(),
            cancellation: None,
            budget: RunmillBudgetEvidence {
                cost_usd: 2.5,
                agent_invocations: 3,
                fix_iterations: 1,
                elapsed_ms: 1_140_000,
                stop_reason: RunmillStopReason::PullRequestDelivered,
            },
            delivery: RunmillDeliveryEvidence {
                closure_target: RunmillClosureTarget::Pr,
                satisfied: true,
                pull_request: RunmillPullRequestDeliveryEvidence {
                    forge: FORGE.into(),
                    repository: REPOSITORY.into(),
                    number: 42,
                    url: PR_URL.into(),
                    head_ref: HEAD_REF.into(),
                    base_ref: BASE_REF.into(),
                    head_sha: CANDIDATE_SHA.into(),
                    observed_at: timestamp("2026-08-21T10:18:00Z"),
                    evidence_digest: pull_request_create_digest.clone(),
                },
            },
            artifacts: vec![
                artifact(
                    "artifact-work-order",
                    RunmillArtifactKind::WorkOrderEnvelope,
                    &work_order_envelope_digest,
                ),
                artifact(
                    "artifact-policy",
                    RunmillArtifactKind::EffectivePolicy,
                    &effective_policy_digest,
                ),
                artifact(
                    "artifact-diff",
                    RunmillArtifactKind::NormalizedDiff,
                    &normalized_diff_digest,
                ),
                artifact(
                    "artifact-runtime",
                    RunmillArtifactKind::RuntimeManifest,
                    &runtime_manifest_digest,
                ),
                artifact(
                    "artifact-outcome-implementer",
                    RunmillArtifactKind::AgentOutcome,
                    &implementer_outcome_digest,
                ),
                artifact(
                    "artifact-outcome-local-review",
                    RunmillArtifactKind::AgentOutcome,
                    &local_reviewer_outcome_digest,
                ),
                artifact(
                    "artifact-outcome-pr-review",
                    RunmillArtifactKind::AgentOutcome,
                    &pull_request_reviewer_outcome_digest,
                ),
                artifact(
                    "artifact-local-check",
                    RunmillArtifactKind::Verification,
                    &local_check_digest,
                ),
                artifact(
                    "artifact-ci",
                    RunmillArtifactKind::CiObservation,
                    &ci_digest,
                ),
                artifact(
                    "artifact-review-local",
                    RunmillArtifactKind::Review,
                    &local_review_digest,
                ),
                artifact(
                    "artifact-review-pr",
                    RunmillArtifactKind::Review,
                    &pull_request_review_digest,
                ),
                artifact(
                    "artifact-branch-push",
                    RunmillArtifactKind::SideEffect,
                    &branch_push_digest,
                ),
                artifact(
                    "artifact-pr-create",
                    RunmillArtifactKind::SideEffect,
                    &pull_request_create_digest,
                ),
            ],
        };
        let statement = RunmillEvidenceStatement {
            statement_type: IN_TOTO_STATEMENT_V1.into(),
            subject: vec![RunmillEvidenceSubject {
                name: format!("{FORGE}:{REPOSITORY}"),
                digest: RunmillSubjectDigest {
                    sha1: CANDIDATE_SHA.into(),
                },
            }],
            predicate_type: RUNMILL_EVIDENCE_PREDICATE_TYPE_V1.into(),
            predicate,
        };
        let bundle = SignedRunmillEvidenceBundle::sign(
            statement,
            timestamp("2026-08-21T10:20:00Z"),
            &signer,
        )
        .unwrap();

        TestFixture {
            bundle,
            authority: TestAuthority {
                verifying_key,
                run_id,
                attempt_id,
                work_order_id,
                work_order_envelope_digest,
                work_order_payload_digest,
                effective_policy_digest,
                tree_digest,
                normalized_diff_digest,
                changed_paths,
                required_local_checks,
                required_ci_contexts,
                observed_pull_request,
            },
        }
    }

    fn resign(bundle: &mut SignedRunmillEvidenceBundle) {
        bundle.bundle_digest = sha256_digest(&canonical_json(&bundle.statement).unwrap());
        bundle.signature = format!(
            "base64url:{}",
            fixed_signer().sign(&bundle.unsigned_canonical_bytes().unwrap())
        );
    }

    fn mutation_fails(mutate: impl FnOnce(&mut SignedRunmillEvidenceBundle)) {
        let mut fixture = fixture();
        mutate(&mut fixture.bundle);
        resign(&mut fixture.bundle);
        assert!(
            fixture
                .bundle
                .verify(&fixture.authority.expectation())
                .is_err()
        );
    }

    #[test]
    fn golden_fixture_is_stable_and_fully_verifies() {
        let fixture = fixture();
        let generated = format!(
            "{}\n",
            serde_json::to_string_pretty(&fixture.bundle).unwrap()
        );
        if std::env::var_os("ASF_PRINT_RUNMILL_EVIDENCE_FIXTURE").is_some() {
            print!("{generated}");
            return;
        }
        assert_eq!(
            generated,
            include_str!("../../contracts/fixtures/runmill-signed-evidence-v1.json")
        );
        let decoded = SignedRunmillEvidenceBundle::from_json(generated.as_bytes()).unwrap();
        let validated = decoded.verify(&fixture.authority.expectation()).unwrap();
        assert_eq!(validated.run_id.as_str(), "run_01JTEST");
        assert_eq!(validated.candidate_sha, CANDIDATE_SHA);
    }

    #[test]
    fn run_id_is_an_external_string_and_signature_has_no_invented_domain() {
        let fixture = fixture();
        assert!(Uuid::parse_str(fixture.authority.run_id.as_str()).is_err());
        let signature = fixture.bundle.signature.strip_prefix("base64url:").unwrap();
        let payload = fixture.bundle.unsigned_canonical_bytes().unwrap();
        verify_signature(&fixture.authority.verifying_key, &payload, signature).unwrap();
        assert!(
            verify_domain_signature(
                &fixture.authority.verifying_key,
                RUNMILL_SIGNED_EVIDENCE_SCHEMA_V1,
                &payload,
                signature,
            )
            .is_err()
        );
        assert_eq!(
            encode_verifying_key(&fixture.authority.verifying_key),
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
    }

    #[test]
    fn strict_decode_rejects_unknown_fields_and_enums() {
        let fixture = fixture();
        let mut value = serde_json::to_value(&fixture.bundle).unwrap();
        value["statement"]["predicate"]["source"]["future_field"] = true.into();
        assert!(
            SignedRunmillEvidenceBundle::from_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );

        let mut value = serde_json::to_value(&fixture.bundle).unwrap();
        value["statement"]["predicate"]["verification"]["ci_contexts"][0]["conclusion"] =
            "passed".into();
        assert!(
            SignedRunmillEvidenceBundle::from_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );
    }

    #[test]
    fn digest_signature_and_trust_each_fail_closed() {
        let mut fixture = fixture();
        fixture.bundle.statement.predicate.source.candidate_sha = BASE_SHA.into();
        assert!(
            fixture
                .bundle
                .verify(&fixture.authority.expectation())
                .is_err()
        );

        fixture.bundle.bundle_digest =
            sha256_digest(&canonical_json(&fixture.bundle.statement).unwrap());
        assert!(
            fixture
                .bundle
                .verify(&fixture.authority.expectation())
                .is_err()
        );

        let mut expectation = fixture.authority.expectation();
        expectation.trusted_signer.revoked = true;
        assert!(fixture.bundle.verify(&expectation).is_err());
    }

    #[test]
    fn required_checks_ci_reviews_and_effects_cannot_be_omitted() {
        mutation_fails(|bundle| bundle.statement.predicate.verification.local_checks.clear());
        mutation_fails(|bundle| bundle.statement.predicate.verification.ci_contexts.clear());
        mutation_fails(|bundle| {
            bundle
                .statement
                .predicate
                .reviews
                .retain(|review| review.stage != RunmillReviewStage::PullRequest);
        });
        mutation_fails(|bundle| {
            bundle
                .statement
                .predicate
                .side_effects
                .retain(|effect| effect.kind != RunmillSideEffectKind::BranchPush);
        });
    }

    #[test]
    fn reviewer_authorization_and_independence_are_enforced() {
        mutation_fails(|bundle| {
            let predicate = &mut bundle.statement.predicate;
            predicate.reviews[0].reviewer_principal = "untrusted-reviewer".into();
            predicate.runtime.providers[1].principal_id = "untrusted-reviewer".into();
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.reviews[0].independent = false;
        });
        mutation_fails(|bundle| {
            let predicate = &mut bundle.statement.predicate;
            predicate.reviews[0].reviewer_principal = "implementer".into();
            predicate.runtime.providers[1].principal_id = "implementer".into();
        });
    }

    #[test]
    fn exact_remote_head_and_independent_pr_observation_are_required() {
        mutation_fails(|bundle| {
            bundle.statement.predicate.source.remote_head_sha = BASE_SHA.into();
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.delivery.pull_request.head_sha = BASE_SHA.into();
        });

        let mut fixture = fixture();
        fixture.authority.observed_pull_request.head_sha = BASE_SHA.into();
        assert!(
            fixture
                .bundle
                .verify(&fixture.authority.expectation())
                .is_err()
        );
    }

    #[test]
    fn malformed_order_bounds_and_credentials_are_rejected() {
        mutation_fails(|bundle| {
            bundle.statement.predicate.source.changed_paths = vec!["z.rs".into(), "a.rs".into()];
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.artifacts[0].size_bytes = MAX_ARTIFACT_BYTES + 1;
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.delivery.pull_request.url =
                "https://github.com/github_pat_not-portable".into();
        });
    }

    #[test]
    fn artifact_manifest_is_bijective_and_semantically_typed() {
        mutation_fails(|bundle| {
            let mut duplicate = bundle.statement.predicate.artifacts[0].clone();
            duplicate.artifact_id = "artifact-duplicate-content".into();
            bundle.statement.predicate.artifacts.push(duplicate);
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.artifacts[0].kind = RunmillArtifactKind::Review;
        });
    }

    #[test]
    fn work_order_key_and_exact_policy_bindings_are_enforced() {
        mutation_fails(|bundle| {
            bundle.statement.predicate.work_order.signature.key_id = "wrong-key".into();
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.policy.effective_policy_digest = digest("different-policy");
        });
        mutation_fails(|bundle| {
            bundle.statement.predicate.delivery.closure_target = RunmillClosureTarget::Pr;
            bundle.statement.predicate.source.merge_sha = Some(CANDIDATE_SHA.into());
        });
    }
}
