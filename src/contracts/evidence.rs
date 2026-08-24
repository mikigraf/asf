use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    crypto::{
        Ed25519Signer, canonical_json, is_sha256_digest, sha256_digest, verify_domain_signature,
    },
    domain::{
        AttemptId, ClosureTarget, CtxlaneProfileRef, DeliveryPermission, EvidenceId, IdentityRole,
        RunId, WorkItemId, WorkerId,
    },
    security::reject_sensitive_fields,
};

use super::SignedWorkOrder;

pub const EVIDENCE_SCHEMA_V1: &str = "runmill.evidence/v1";
pub const EVIDENCE_ENVELOPE_SCHEMA_V1: &str = "runmill.evidence-envelope/v1";
const EVIDENCE_SIGNATURE_DOMAIN: &str = "runmill.evidence-envelope/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckEvidence {
    pub check_id: String,
    pub candidate_sha: String,
    pub conclusion: CheckConclusion,
    pub artifact_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub reviewer_profile: String,
    pub reviewer_principal: String,
    pub candidate_sha: String,
    pub independent: bool,
    pub approved: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestEvidence {
    pub repository: String,
    pub number: u64,
    pub url: String,
    pub base_sha: String,
    pub head_sha: String,
    pub required_ci_contexts: BTreeSet<String>,
    pub successful_ci_contexts: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageEvidence {
    pub cost_microunits: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub implementer_invocations: u32,
    pub reviewer_invocations: u32,
    pub fix_iterations: u32,
    pub wall_time_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleIdentityEvidence {
    pub role: IdentityRole,
    pub provider: String,
    pub profile_ref: CtxlaneProfileRef,
    pub principal_ref: String,
    pub lease_id: String,
    pub model: String,
    pub isolation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDigestEvidence {
    pub harness: String,
    pub tool_policy: String,
    pub sandbox: String,
    pub dependencies: String,
    pub runtime: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleOutcomeConclusion {
    Completed,
    Refused,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOutcomeEvidence {
    pub role: IdentityRole,
    pub candidate_sha: Option<String>,
    pub conclusion: RoleOutcomeConclusion,
    pub summary_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingEvidence {
    pub stable_code: String,
    pub severity: String,
    pub candidate_sha: String,
    pub disposition: String,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectStatus {
    Confirmed,
    Reconciled,
    Ambiguous,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideEffectEvidence {
    pub effect_type: String,
    pub idempotency_key: String,
    pub intent_digest: String,
    pub status: SideEffectStatus,
    pub observation_digest: Option<String>,
    pub candidate_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEvidenceRecord {
    pub approval_type: String,
    pub decision: String,
    pub binding_digest: String,
    pub candidate_sha: Option<String>,
    pub approver_subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestEntry {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub retention_class: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleV1 {
    pub schema: String,
    pub evidence_id: EvidenceId,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub run_id: RunId,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub work_order_digest: String,
    pub work_order: SignedWorkOrder,
    pub work_order_signature_verified_by_worker: bool,
    pub source_snapshot_digest: String,
    pub policy_input_digests: BTreeMap<String, String>,
    pub repository: String,
    pub base_ref: String,
    pub base_sha: String,
    pub candidate_sha: String,
    pub remote_head_sha: String,
    pub merge_sha: Option<String>,
    pub changed_paths: BTreeSet<String>,
    pub diff_digest: String,
    pub identity_attribution: Vec<RoleIdentityEvidence>,
    pub runtime_digests: RuntimeDigestEvidence,
    pub role_outcomes: Vec<RoleOutcomeEvidence>,
    pub findings: Vec<FindingEvidence>,
    pub requested_target: ClosureTarget,
    pub target_satisfied: bool,
    pub checks: Vec<CheckEvidence>,
    pub review: ReviewEvidence,
    pub pull_request: Option<PullRequestEvidence>,
    pub side_effects: Vec<SideEffectEvidence>,
    pub approvals: Vec<ApprovalEvidenceRecord>,
    pub cancellation: Option<String>,
    pub artifacts: Vec<ArtifactManifestEntry>,
    pub usage: UsageEvidence,
    pub stop_reason: String,
    pub produced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceBundle {
    #[serde(rename = "schema")]
    pub envelope_schema: String,
    pub algorithm: String,
    pub key_id: String,
    pub payload_digest: String,
    pub payload: EvidenceBundleV1,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceExpectation<'a> {
    pub asf_work_order_key: &'a VerifyingKey,
    pub asf_work_order_key_id: &'a str,
    pub worker_key_id: &'a str,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub run_id: RunId,
    pub worker_id: WorkerId,
    pub work_order_digest: &'a str,
    pub repository: &'a str,
    pub base_sha: &'a str,
    pub candidate_sha: &'a str,
    pub target: ClosureTarget,
    pub required_local_checks: &'a BTreeSet<String>,
    pub required_ci_contexts: &'a BTreeSet<String>,
    pub current_worker_generation: u64,
    /// Observation produced by ASF's deterministic forge adapter, not by the worker.
    pub independently_observed_pull_request: Option<&'a PullRequestEvidence>,
}

impl SignedEvidenceBundle {
    pub fn sign(payload: EvidenceBundleV1, signer: &Ed25519Signer) -> Result<Self> {
        validate_payload_shape(&payload)?;
        let bytes = canonical_json(&payload)?;
        let mut envelope = Self {
            envelope_schema: EVIDENCE_ENVELOPE_SCHEMA_V1.into(),
            algorithm: "EdDSA".into(),
            key_id: signer.key_id().into(),
            payload_digest: sha256_digest(&bytes),
            payload,
            signature: String::new(),
        };
        envelope.signature = signer.sign_domain(
            EVIDENCE_SIGNATURE_DOMAIN,
            &envelope.protected_canonical_bytes()?,
        );
        Ok(envelope)
    }

    pub fn verify(&self, key: &VerifyingKey, expectation: &EvidenceExpectation<'_>) -> Result<()> {
        if self.envelope_schema != EVIDENCE_ENVELOPE_SCHEMA_V1
            || self.algorithm != "EdDSA"
            || self.payload.schema != EVIDENCE_SCHEMA_V1
        {
            return Err(Error::Crypto("unsupported evidence envelope".into()));
        }
        let bytes = canonical_json(&self.payload)?;
        if sha256_digest(&bytes) != self.payload_digest {
            return Err(Error::Crypto("evidence payload digest mismatch".into()));
        }
        verify_domain_signature(
            key,
            EVIDENCE_SIGNATURE_DOMAIN,
            &self.protected_canonical_bytes()?,
            &self.signature,
        )?;
        if self.key_id != expectation.worker_key_id {
            return Err(Error::Validation(
                "evidence signing key is not the authoritative worker key".into(),
            ));
        }
        validate_payload_shape(&self.payload)?;
        reject_sensitive_fields(
            &serde_json::to_value(&self.payload)
                .map_err(|error| Error::Serialization(error.to_string()))?,
        )?;

        let evidence = &self.payload;
        if evidence.work_item_id != expectation.work_item_id
            || evidence.attempt_id != expectation.attempt_id
            || evidence.run_id != expectation.run_id
            || evidence.worker_id != expectation.worker_id
            || evidence.work_order_digest != expectation.work_order_digest
            || evidence.repository != expectation.repository
            || evidence.base_sha != expectation.base_sha
            || evidence.candidate_sha != expectation.candidate_sha
            || evidence.requested_target != expectation.target
        {
            return Err(Error::Validation(
                "evidence is not bound to the expected Work Order target".into(),
            ));
        }
        evidence
            .work_order
            .verify_integrity(expectation.asf_work_order_key)?;
        if evidence.work_order.key_id != expectation.asf_work_order_key_id
            || evidence.work_order.payload_digest != evidence.work_order_digest
            || evidence.work_order.payload.work_item_id != evidence.work_item_id
            || evidence.work_order.payload.attempt_id != evidence.attempt_id
            || evidence.work_order.payload.source_snapshot_digest != evidence.source_snapshot_digest
            || evidence.work_order.payload.repository.base_sha != evidence.base_sha
            || evidence.work_order.payload.repository.base_ref != evidence.base_ref
            || evidence.work_order.payload.closure_target != evidence.requested_target
            || !evidence.work_order_signature_verified_by_worker
        {
            return Err(Error::Validation(
                "evidence does not faithfully embed the authorized Work Order".into(),
            ));
        }
        if evidence.worker_generation != expectation.current_worker_generation {
            return Err(Error::Validation("stale worker generation".into()));
        }
        validate_frozen_authority(evidence)?;
        if !evidence.target_satisfied
            || !is_git_sha(&evidence.candidate_sha)
            || evidence.remote_head_sha != evidence.candidate_sha
        {
            return Err(Error::Validation(
                "evidence does not assert a concrete satisfied candidate".into(),
            ));
        }
        if evidence.side_effects.iter().any(|effect| {
            matches!(
                effect.status,
                SideEffectStatus::Ambiguous | SideEffectStatus::Failed
            )
        }) {
            return Err(Error::Validation(
                "evidence contains an unresolved blocking external effect".into(),
            ));
        }
        let passed_checks: BTreeSet<&str> = evidence
            .checks
            .iter()
            .filter(|check| {
                check.conclusion == CheckConclusion::Passed
                    && check.candidate_sha == evidence.candidate_sha
            })
            .map(|check| check.check_id.as_str())
            .collect();
        if !expectation
            .required_local_checks
            .iter()
            .all(|required| passed_checks.contains(required.as_str()))
        {
            return Err(Error::Validation(
                "not every required local check passed on the exact candidate".into(),
            ));
        }
        if !evidence.review.independent
            || !evidence.review.approved
            || evidence.review.candidate_sha != evidence.candidate_sha
        {
            return Err(Error::Validation(
                "independent review did not approve the exact candidate".into(),
            ));
        }
        let pr_reviewer = identity_for(evidence, IdentityRole::PrReviewer)?;
        if evidence.review.reviewer_profile != pr_reviewer.profile_ref.as_str()
            || evidence.review.reviewer_principal != pr_reviewer.principal_ref
        {
            return Err(Error::Validation(
                "independent review is not bound to the authorized PR reviewer identity".into(),
            ));
        }
        if expectation.target == ClosureTarget::PullRequest {
            let pull_request = evidence.pull_request.as_ref().ok_or_else(|| {
                Error::Validation("pull-request target requires pull-request evidence".into())
            })?;
            if pull_request.head_sha != evidence.candidate_sha
                || pull_request.base_sha != evidence.base_sha
                || !expectation
                    .required_ci_contexts
                    .is_subset(&pull_request.successful_ci_contexts)
            {
                return Err(Error::Validation(
                    "pull request does not prove the exact candidate and required CI".into(),
                ));
            }
            if expectation.independently_observed_pull_request != Some(pull_request) {
                return Err(Error::Validation(
                    "worker pull-request evidence does not match ASF's independent forge observation"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn protected_canonical_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct ProtectedEvidence<'a> {
            schema: &'a str,
            algorithm: &'a str,
            key_id: &'a str,
            payload_digest: &'a str,
            payload: &'a EvidenceBundleV1,
        }
        canonical_json(&ProtectedEvidence {
            schema: &self.envelope_schema,
            algorithm: &self.algorithm,
            key_id: &self.key_id,
            payload_digest: &self.payload_digest,
            payload: &self.payload,
        })
    }
}

fn validate_payload_shape(evidence: &EvidenceBundleV1) -> Result<()> {
    if evidence.schema != EVIDENCE_SCHEMA_V1
        || evidence.worker_generation == 0
        || evidence.repository.trim().is_empty()
        || evidence.base_ref.trim().is_empty()
        || evidence.stop_reason.trim().is_empty()
        || !is_git_sha(&evidence.base_sha)
        || !is_git_sha(&evidence.candidate_sha)
        || !is_sha256_digest(&evidence.work_order_digest)
        || !is_sha256_digest(&evidence.source_snapshot_digest)
        || !is_sha256_digest(&evidence.diff_digest)
    {
        return Err(Error::Validation(
            "evidence is missing required versioned provenance fields".into(),
        ));
    }
    for digest in evidence
        .policy_input_digests
        .values()
        .chain([
            &evidence.runtime_digests.harness,
            &evidence.runtime_digests.tool_policy,
            &evidence.runtime_digests.sandbox,
            &evidence.runtime_digests.dependencies,
            &evidence.runtime_digests.runtime,
            &evidence.review.report_digest,
        ])
        .chain(evidence.artifacts.iter().map(|artifact| &artifact.digest))
        .chain(
            evidence
                .role_outcomes
                .iter()
                .map(|outcome| &outcome.summary_digest),
        )
        .chain(
            evidence
                .findings
                .iter()
                .map(|finding| &finding.report_digest),
        )
        .chain(
            evidence
                .checks
                .iter()
                .filter_map(|check| check.artifact_digest.as_ref()),
        )
        .chain(evidence.side_effects.iter().flat_map(|effect| {
            std::iter::once(&effect.intent_digest).chain(effect.observation_digest.iter())
        }))
        .chain(
            evidence
                .approvals
                .iter()
                .map(|approval| &approval.binding_digest),
        )
    {
        if !is_sha256_digest(digest) {
            return Err(Error::Validation(
                "evidence provenance digests must use lowercase sha256".into(),
            ));
        }
    }
    if evidence.changed_paths.iter().any(|path| {
        path.is_empty() || path.starts_with('/') || path.contains("..") || path.contains('\0')
    }) {
        return Err(Error::Validation(
            "evidence contains an unsafe changed path".into(),
        ));
    }
    let roles: BTreeSet<IdentityRole> = evidence
        .identity_attribution
        .iter()
        .map(|identity| identity.role)
        .collect();
    if evidence.identity_attribution.len() != 3
        || roles
            != BTreeSet::from([
                IdentityRole::Implementer,
                IdentityRole::LocalReviewer,
                IdentityRole::PrReviewer,
            ])
    {
        return Err(Error::Validation(
            "evidence must attribute all three identity roles".into(),
        ));
    }
    for identity in &evidence.identity_attribution {
        if identity.provider != identity.profile_ref.provider().to_string()
            || identity.principal_ref.trim().is_empty()
            || identity.lease_id.trim().is_empty()
            || identity.model.trim().is_empty()
            || identity.isolation != "credential-isolated"
        {
            return Err(Error::Validation(
                "identity attribution is incomplete, mismatched, or not credential-isolated".into(),
            ));
        }
    }
    let implementer = evidence
        .identity_attribution
        .iter()
        .find(|identity| identity.role == IdentityRole::Implementer)
        .map(|identity| identity.principal_ref.as_str());
    if implementer.is_none()
        || evidence.identity_attribution.iter().any(|identity| {
            identity.role != IdentityRole::Implementer
                && Some(identity.principal_ref.as_str()) == implementer
        })
    {
        return Err(Error::Validation(
            "evidence does not prove reviewer principal independence".into(),
        ));
    }
    let outcome_roles: BTreeSet<IdentityRole> = evidence
        .role_outcomes
        .iter()
        .map(|outcome| outcome.role)
        .collect();
    if evidence.role_outcomes.len() != 3
        || outcome_roles != roles
        || evidence.role_outcomes.iter().any(|outcome| {
            outcome.conclusion != RoleOutcomeConclusion::Completed
                || outcome.candidate_sha.as_deref() != Some(evidence.candidate_sha.as_str())
        })
    {
        return Err(Error::Validation(
            "successful evidence requires exact-candidate outcomes for all three roles".into(),
        ));
    }
    if evidence
        .findings
        .iter()
        .any(|finding| finding.candidate_sha != evidence.candidate_sha)
    {
        return Err(Error::Validation(
            "evidence findings are not bound to the exact candidate".into(),
        ));
    }
    Ok(())
}

fn identity_for(evidence: &EvidenceBundleV1, role: IdentityRole) -> Result<&RoleIdentityEvidence> {
    evidence
        .identity_attribution
        .iter()
        .find(|identity| identity.role == role)
        .ok_or_else(|| Error::Validation(format!("evidence is missing {role} attribution")))
}

fn validate_frozen_authority(evidence: &EvidenceBundleV1) -> Result<()> {
    let order = &evidence.work_order.payload;
    for role in [
        IdentityRole::Implementer,
        IdentityRole::LocalReviewer,
        IdentityRole::PrReviewer,
    ] {
        if &identity_for(evidence, role)?.profile_ref != order.identities.profile_for(role) {
            return Err(Error::Validation(format!(
                "{role} evidence used a profile outside the signed Work Order"
            )));
        }
    }
    if evidence
        .changed_paths
        .iter()
        .any(|path| !order.authority.paths.allows_path(path))
    {
        return Err(Error::Validation(
            "evidence contains a changed path outside signed authority".into(),
        ));
    }
    if evidence.runtime_digests.harness != order.digests.harness
        || !evidence
            .policy_input_digests
            .values()
            .any(|digest| digest == &order.digests.policy)
        || !evidence
            .policy_input_digests
            .values()
            .any(|digest| digest == &order.digests.repository_policy)
    {
        return Err(Error::Validation(
            "evidence runtime and policy inputs do not match the signed Work Order".into(),
        ));
    }
    let budget = order.authority.budgets;
    let usage = &evidence.usage;
    let external_effects = u32::try_from(evidence.side_effects.len()).unwrap_or(u32::MAX);
    if usage.cost_microunits > budget.max_cost_microunits
        || usage.input_tokens > budget.max_input_tokens
        || usage.output_tokens > budget.max_output_tokens
        || usage.implementer_invocations > budget.max_implementer_invocations
        || usage.reviewer_invocations > budget.max_reviewer_invocations
        || usage.fix_iterations > budget.max_fix_iterations
        || usage.wall_time_seconds > budget.max_wall_time_seconds
        || external_effects > budget.max_external_api_calls
    {
        return Err(Error::Validation(
            "evidence usage exceeds the signed Work Order budget".into(),
        ));
    }
    for effect in &evidence.side_effects {
        let authorized = match effect.effect_type.as_str() {
            "pull_request.create" | "pull_request.update" => {
                order.authority.effects.delivery != DeliveryPermission::None
                    && effect.candidate_sha.as_deref() == Some(evidence.candidate_sha.as_str())
            }
            "comment.create" | "comment.update" => order.authority.effects.may_comment,
            "check.create" | "check.update" => order.authority.effects.may_update_checks,
            _ => false,
        };
        if !authorized
            || effect.idempotency_key.trim().is_empty()
            || matches!(
                effect.status,
                SideEffectStatus::Confirmed | SideEffectStatus::Reconciled
            ) && effect.observation_digest.is_none()
        {
            return Err(Error::Validation(
                "evidence contains an unrecognized, unbound, or unauthorized side effect".into(),
            ));
        }
    }
    Ok(())
}

fn is_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
