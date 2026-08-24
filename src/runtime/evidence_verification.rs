//! Independent, exact-candidate verification of one signed Runmill evidence bundle.
//!
//! The activity performs only read-side external I/O. It first snapshots the
//! exact ledger authority, verifies every content-addressed artifact, and asks
//! the forge for the current pull-request/CI state. A second transaction then
//! re-locks the same authority before it atomically persists the VALID receipt,
//! advances the work through `TARGET_REACHED` to `CLOSING_SOURCE`, installs the
//! closure accountability anchor, enqueues `CLOSE_SOURCE`, and completes the
//! owned verification job.

use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, CLOSE_SOURCE, CLOSE_SOURCE_ACTIVITY_CONTRACT_ID, JobHandler,
    VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID,
};
use crate::{
    Error, Result,
    artifacts::ArtifactStore,
    contracts::{
        AuthorizedRunmillReviewer, EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1,
        EvidenceVerificationReceiptV1, PullRequestEvidence, RunmillArtifactKind,
        RunmillEvidenceExpectation, RunmillExternalRunId, RunmillProviderRole,
        RunmillRetentionClass, RunmillSignedWorkOrderV1, SignedRunmillEvidenceBundle,
        TrustedRunmillEvidenceSigner,
    },
    crypto::{canonical_json, decode_verifying_key, is_sha256_digest, sha256_digest},
    domain::{AttemptId, EvidenceId, PathAuthority, RunId, TenantId, WorkItemId, WorkOrderId},
    ledger::{
        AccountabilityReplacement, ClaimedWorkflowJob, LedgerAccountabilityKind, PgLedger,
        StepAuditEvent, StepOutboxMessage, StepWorkflowJob, WorkflowStepCommit,
        WorkflowStepCommitOutcome, WorkflowStepFence, commit_workflow_step_with_prelocked_claim,
    },
    ports::{ForgeGateway, ForgeGatewayError, ObservePullRequestRequest, PullRequestRef},
    security::reject_sensitive_fields,
};

const VERIFIER_ID: &str = "asf:github-evidence-verifier/v1";
const RESULT_SCHEMA_V1: &str = "asf.evidence-verification-workflow-result.v1";
const AUDIT_SCHEMA_V1: &str = "asf.evidence-verification-audit.v1";
const PROVIDER_CLOCK_SKEW_SECONDS: i64 = 300;

/// Tenant-fenced production evidence verifier.
pub struct EvidenceVerificationHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    forge: Arc<dyn ForgeGateway>,
    artifacts: Arc<dyn ArtifactStore>,
    work_order_key_id: String,
    work_order_verifying_key: VerifyingKey,
}

impl fmt::Debug for EvidenceVerificationHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceVerificationHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("forge", &"ForgeGateway([REDACTED])")
            .field("artifacts", &"ArtifactStore([REDACTED])")
            .field("work_order_key_id", &self.work_order_key_id)
            .field("work_order_verifying_key", &"[PUBLIC KEY]")
            .finish()
    }
}

impl EvidenceVerificationHandler {
    /// Construct a verifier from read-only forge/artifact boundaries and the
    /// ASF Work Order signing authority trusted by this deployment.
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        forge: Arc<dyn ForgeGateway>,
        artifacts: Arc<dyn ArtifactStore>,
        work_order_key_id: impl Into<String>,
        work_order_verifying_key: VerifyingKey,
    ) -> Result<Self> {
        let work_order_key_id = work_order_key_id.into();
        if tenant_id.as_uuid().is_nil() || work_order_key_id.trim().is_empty() {
            return Err(Error::Validation(
                "evidence verifier requires a non-nil tenant and Work Order key ID".into(),
            ));
        }
        Ok(Self {
            ledger,
            tenant_id,
            forge,
            artifacts,
            work_order_key_id,
            work_order_verifying_key,
        })
    }

    async fn execute_inner(&self, job: &ClaimedWorkflowJob) -> Result<ActivityOutcome> {
        let payload = VerificationJobPayload::parse(job, self.tenant_id)?;
        let prepared = self.prepare(job, &payload).await?;
        prepared.binding.verify_artifact_metadata()?;
        verify_artifact_contents(self.artifacts.as_ref(), &prepared.binding).await?;

        let request = prepared.binding.forge_request()?;
        let observation_requested_at = Utc::now();
        let observation = self
            .forge
            .observe_pull_request(&request)
            .await
            .map_err(|error| map_forge_error(&error))?;
        let independent_pull_request = observation
            .exact_candidate_evidence(&request)
            .map_err(|error| map_forge_error(&error))?;
        prepared.binding.verify_complete_evidence(
            &self.work_order_key_id,
            &self.work_order_verifying_key,
            &independent_pull_request,
            observation_requested_at,
            observation.observed_at,
        )?;

        self.finalize(
            job,
            &payload,
            &prepared,
            independent_pull_request,
            observation.provider_revision,
            observation_requested_at,
            observation.observed_at,
        )
        .await?;
        Ok(ActivityOutcome::TransactionCommitted)
    }

    async fn prepare(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &VerificationJobPayload,
    ) -> Result<PreparedVerification> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin evidence-verification preflight: {error}"))
        })?;
        let binding = lock_claim_and_binding(&mut transaction, job, payload).await?;
        binding.verify_static_authority(&self.work_order_key_id, &self.work_order_verifying_key)?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit evidence-verification preflight: {error}"))
        })?;
        Ok(PreparedVerification { binding })
    }

    async fn finalize(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &VerificationJobPayload,
        prepared: &PreparedVerification,
        pull_request: PullRequestEvidence,
        provider_revision: String,
        observation_requested_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin evidence-verification commit: {error}"))
        })?;
        let binding = lock_claim_and_binding(&mut transaction, job, payload).await?;
        if binding != prepared.binding {
            return Err(Error::Conflict(format!(
                "evidence-verification job {} authority changed during forge observation",
                job.id
            )));
        }
        binding.verify_artifact_metadata()?;
        binding.verify_complete_evidence(
            &self.work_order_key_id,
            &self.work_order_verifying_key,
            &pull_request,
            observation_requested_at,
            observed_at,
        )?;
        commit_valid_verification(
            &mut transaction,
            job,
            &binding,
            pull_request,
            provider_revision,
            observed_at,
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit evidence-verification transaction: {error}"))
        })
    }
}

#[async_trait]
impl JobHandler for EvidenceVerificationHandler {
    fn job_type(&self) -> &str {
        VERIFY_EVIDENCE
    }

    fn activity_contract_id(&self) -> &str {
        VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        // Observation and closure of already-finished work remain permitted in
        // maintenance mode; this activity creates no attempt or Runmill run.
        self.execute_inner(job).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationJobPayload {
    evidence_id: Uuid,
    run_id: Uuid,
    payload_digest: String,
    work_order_digest: String,
    expectation_digest: String,
}

impl VerificationJobPayload {
    fn parse(job: &ClaimedWorkflowJob, tenant_id: TenantId) -> Result<Self> {
        if job.job_type != VERIFY_EVIDENCE
            || job.activity_contract_id != VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID
            || job.tenant_id != tenant_id.as_uuid()
            || job.workflow_instance_id.is_none()
            || job.work_item_id.is_none()
            || job.attempt_id.is_none()
            || job.idempotency_key.trim().is_empty()
        {
            return Err(Error::Validation(format!(
                "evidence-verification job {} lacks an exact tenant/workflow/work/attempt binding or activity contract",
                job.id
            )));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!(
                "evidence-verification job {} has an incompatible payload: {error}",
                job.id
            ))
        })?;
        if payload.evidence_id.is_nil()
            || payload.run_id.is_nil()
            || !is_sha256_digest(&payload.payload_digest)
            || !is_sha256_digest(&payload.work_order_digest)
            || !is_sha256_digest(&payload.expectation_digest)
        {
            return Err(Error::Validation(format!(
                "evidence-verification job {} has invalid immutable evidence coordinates",
                job.id
            )));
        }
        reject_sensitive_fields(&job.payload)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct PreparedVerification {
    binding: VerificationBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactBinding {
    id: Uuid,
    manifest_artifact_id: String,
    manifest_kind: String,
    relationship: String,
    digest: String,
    media_type: String,
    byte_size: i64,
    object_key: String,
    retention_class: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalBinding {
    id: Uuid,
    approval_type: String,
    status: String,
    work_order_digest: Option<String>,
    candidate_sha: Option<String>,
    decision_effect_type: String,
    policy_digest: String,
    decision_subject: Option<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
struct VerificationBinding {
    tenant_id: Uuid,
    work_item_id: Uuid,
    work_item_version: i64,
    source_external_id: String,
    source_snapshot_digest: String,
    repository: String,
    policy_digest: String,
    attempt_id: Uuid,
    attempt_base_ref: String,
    attempt_base_sha: String,
    attempt_source_snapshot_digest: String,
    attempt_policy_digest: String,
    attempt_terminal_at: DateTime<Utc>,
    work_order_id: Uuid,
    work_order_payload_digest: String,
    work_order_canonical_payload: Vec<u8>,
    work_order_payload: Value,
    work_order_exact_envelope: Vec<u8>,
    work_order_schema: String,
    work_order_envelope_schema: String,
    work_order_algorithm: String,
    work_order_key_id: String,
    work_order_signature: String,
    work_order_issued_at: DateTime<Utc>,
    work_order_not_before: DateTime<Utc>,
    work_order_expires_at: DateTime<Utc>,
    work_order: RunmillSignedWorkOrderV1,
    workflow_id: Uuid,
    workflow_version: i64,
    workflow_fence_token: i64,
    workflow_event_cursor: i64,
    anchor_generation: i64,
    run_id: Uuid,
    external_run_id: String,
    run_terminal_at: DateTime<Utc>,
    expectation_digest: String,
    worker_id: Uuid,
    worker_generation: i64,
    worker_status: String,
    worker_session_id: Uuid,
    worker_session_status: String,
    worker_session_signing_key_id: String,
    worker_session_signing_public_key: String,
    worker_session_started_at: DateTime<Utc>,
    worker_session_expires_at: DateTime<Utc>,
    worker_session_closed_at: Option<DateTime<Utc>>,
    evidence_id: Uuid,
    evidence_worker_session_id: Uuid,
    evidence_payload_digest: String,
    evidence_work_order_digest: String,
    evidence_base_sha: String,
    evidence_candidate_sha: String,
    evidence_schema: String,
    evidence_envelope_schema: String,
    evidence_algorithm: String,
    evidence_key_id: String,
    evidence_signature: String,
    evidence_canonical_payload: Vec<u8>,
    evidence_payload: Value,
    evidence_exact_envelope: Vec<u8>,
    evidence_produced_at: DateTime<Utc>,
    evidence: SignedRunmillEvidenceBundle,
    artifacts: Vec<ArtifactBinding>,
    approvals: Vec<ApprovalBinding>,
}

impl VerificationBinding {
    fn from_row(
        row: &PgRow,
        artifacts: Vec<ArtifactBinding>,
        approvals: Vec<ApprovalBinding>,
        job_id: Uuid,
    ) -> Result<Self> {
        let work_order_exact_envelope: Vec<u8> = required(
            row,
            "work_order_exact_envelope",
            "signed Work Order envelope",
        )?;
        let work_order: RunmillSignedWorkOrderV1 =
            serde_json::from_slice(&work_order_exact_envelope).map_err(|error| {
                Error::Persistence(format!(
                    "evidence-verification job {job_id} has an invalid signed Work Order: {error}"
                ))
            })?;
        let evidence_exact_envelope: Vec<u8> =
            required(row, "evidence_exact_envelope", "signed evidence envelope")?;
        let evidence =
            SignedRunmillEvidenceBundle::from_json(&evidence_exact_envelope).map_err(|error| {
                Error::Persistence(format!(
                    "evidence-verification job {job_id} has invalid Runmill evidence: {error}"
                ))
            })?;
        Ok(Self {
            tenant_id: required(row, "tenant_id", "tenant")?,
            work_item_id: required(row, "work_item_id", "work item")?,
            work_item_version: required(row, "work_item_version", "work-item version")?,
            source_external_id: required(row, "source_external_id", "source external ID")?,
            source_snapshot_digest: required(
                row,
                "source_snapshot_digest",
                "source snapshot digest",
            )?,
            repository: required(row, "repository", "repository")?,
            policy_digest: required(row, "policy_digest", "effective policy")?,
            attempt_id: required(row, "attempt_id", "attempt")?,
            attempt_base_ref: required(row, "attempt_base_ref", "attempt base ref")?,
            attempt_base_sha: required(row, "attempt_base_sha", "attempt base SHA")?,
            attempt_source_snapshot_digest: required(
                row,
                "attempt_source_snapshot_digest",
                "attempt source-snapshot digest",
            )?,
            attempt_policy_digest: required(row, "attempt_policy_digest", "attempt policy digest")?,
            attempt_terminal_at: required(row, "attempt_terminal_at", "attempt terminal time")?,
            work_order_id: required(row, "work_order_id", "Work Order")?,
            work_order_payload_digest: required(
                row,
                "work_order_payload_digest",
                "Work Order payload digest",
            )?,
            work_order_canonical_payload: required(
                row,
                "work_order_canonical_payload",
                "canonical Work Order payload",
            )?,
            work_order_payload: required(row, "work_order_payload", "Work Order payload")?,
            work_order_exact_envelope,
            work_order_schema: required(row, "work_order_schema", "Work Order schema")?,
            work_order_envelope_schema: required(
                row,
                "work_order_envelope_schema",
                "Work Order envelope schema",
            )?,
            work_order_algorithm: required(row, "work_order_algorithm", "Work Order algorithm")?,
            work_order_key_id: required(row, "work_order_key_id", "Work Order key")?,
            work_order_signature: required(row, "work_order_signature", "Work Order signature")?,
            work_order_issued_at: required(row, "work_order_issued_at", "Work Order issuance")?,
            work_order_not_before: required(row, "work_order_not_before", "Work Order activation")?,
            work_order_expires_at: required(row, "work_order_expires_at", "Work Order expiry")?,
            work_order,
            workflow_id: required(row, "workflow_id", "workflow")?,
            workflow_version: required(row, "workflow_version", "workflow version")?,
            workflow_fence_token: required(row, "workflow_fence_token", "workflow fence")?,
            workflow_event_cursor: required(row, "workflow_event_cursor", "workflow cursor")?,
            anchor_generation: required(row, "anchor_generation", "anchor generation")?,
            run_id: required(row, "run_id", "run")?,
            external_run_id: required(row, "external_run_id", "external run")?,
            run_terminal_at: required(row, "run_terminal_at", "run terminal time")?,
            expectation_digest: required(row, "expectation_digest", "evidence expectation")?,
            worker_id: required(row, "worker_id", "worker")?,
            worker_generation: required(row, "worker_generation", "worker generation")?,
            worker_status: required(row, "worker_status", "worker status")?,
            worker_session_id: required(row, "worker_session_id", "worker session")?,
            worker_session_status: required(row, "worker_session_status", "worker-session status")?,
            worker_session_signing_key_id: required(
                row,
                "worker_session_signing_key_id",
                "worker-session key",
            )?,
            worker_session_signing_public_key: required(
                row,
                "worker_session_signing_public_key",
                "worker-session public key",
            )?,
            worker_session_started_at: required(
                row,
                "worker_session_started_at",
                "worker-session start",
            )?,
            worker_session_expires_at: required(
                row,
                "worker_session_expires_at",
                "worker-session expiry",
            )?,
            worker_session_closed_at: optional(
                row,
                "worker_session_closed_at",
                "worker-session close",
            )?,
            evidence_id: required(row, "evidence_id", "evidence")?,
            evidence_worker_session_id: required(
                row,
                "evidence_worker_session_id",
                "evidence worker session",
            )?,
            evidence_payload_digest: required(
                row,
                "evidence_payload_digest",
                "evidence payload digest",
            )?,
            evidence_work_order_digest: required(
                row,
                "evidence_work_order_digest",
                "evidence Work Order digest",
            )?,
            evidence_base_sha: required(row, "evidence_base_sha", "evidence base SHA")?,
            evidence_candidate_sha: required(
                row,
                "evidence_candidate_sha",
                "evidence candidate SHA",
            )?,
            evidence_schema: required(row, "evidence_schema", "evidence schema")?,
            evidence_envelope_schema: required(
                row,
                "evidence_envelope_schema",
                "evidence envelope schema",
            )?,
            evidence_algorithm: required(row, "evidence_algorithm", "evidence algorithm")?,
            evidence_key_id: required(row, "evidence_key_id", "evidence key")?,
            evidence_signature: required(row, "evidence_signature", "evidence signature")?,
            evidence_canonical_payload: required(
                row,
                "evidence_canonical_payload",
                "canonical evidence payload",
            )?,
            evidence_payload: required(row, "evidence_payload", "evidence payload")?,
            evidence_exact_envelope,
            evidence_produced_at: required(row, "evidence_produced_at", "evidence production")?,
            evidence,
            artifacts,
            approvals,
        })
    }

    fn verify_static_authority(
        &self,
        configured_work_order_key_id: &str,
        configured_work_order_key: &VerifyingKey,
    ) -> Result<()> {
        let work_order_payload_bytes = canonical_json(&self.work_order.payload)?;
        let work_order_payload_value = serde_json::to_value(&self.work_order.payload)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        let evidence_statement_bytes = canonical_json(&self.evidence.statement)?;
        let evidence_statement_value = serde_json::to_value(&self.evidence.statement)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        let work_order = &self.work_order.payload;
        let predicate = &self.evidence.statement.predicate;
        let produced_at = self.evidence.issued_at.to_utc()?;
        let completed_at = predicate.run.completed_at.to_utc()?;

        if canonical_json(&self.work_order)? != self.work_order_exact_envelope
            || work_order_payload_bytes != self.work_order_canonical_payload
            || work_order_payload_value != self.work_order_payload
            || self.work_order.payload.digest()? != self.work_order_payload_digest
            || self.work_order.schema != self.work_order_envelope_schema
            || self.work_order.payload.schema != self.work_order_schema
            || self.work_order.algorithm != self.work_order_algorithm
            || self.work_order.key_id != self.work_order_key_id
            || self.work_order.signature != self.work_order_signature
            || self.work_order.issued_at != self.work_order_issued_at
            || self.work_order.not_before != self.work_order_not_before
            || self.work_order.expires_at != self.work_order_expires_at
        {
            return Err(Error::Persistence(
                "stored Work Order envelope contradicts its immutable ledger projection".into(),
            ));
        }
        if self.work_order_key_id != configured_work_order_key_id {
            return Err(Error::Crypto(format!(
                "Work Order key {} is not the configured ASF signing authority",
                self.work_order_key_id
            )));
        }
        self.work_order
            .verify_integrity(configured_work_order_key)?;

        if canonical_json(&self.evidence)? != self.evidence_exact_envelope
            || evidence_statement_bytes != self.evidence_canonical_payload
            || evidence_statement_value != self.evidence_payload
            || sha256_digest(&self.evidence_canonical_payload) != self.evidence_payload_digest
            || self.evidence.bundle_digest != self.evidence_payload_digest
            || self.evidence.schema != self.evidence_envelope_schema
            || predicate.schema != self.evidence_schema
            || self.evidence_algorithm != "EdDSA"
            || self.evidence.key_id != self.evidence_key_id
            || self.evidence.signature != self.evidence_signature
            || produced_at != self.evidence_produced_at
        {
            return Err(Error::Persistence(
                "stored Runmill evidence contradicts its immutable ledger projection".into(),
            ));
        }

        let exact = self.worker_generation > 0
            && self.worker_status != "QUARANTINED"
            && self.worker_session_status != "REVOKED"
            && self.evidence_worker_session_id == self.worker_session_id
            && self.evidence_key_id == self.worker_session_signing_key_id
            && self.worker_session_started_at <= produced_at
            && produced_at < self.worker_session_expires_at
            && self
                .worker_session_closed_at
                .is_none_or(|closed_at| produced_at <= closed_at)
            && completed_at <= produced_at
            && completed_at == self.run_terminal_at
            && self.run_terminal_at <= self.attempt_terminal_at
            && completed_at >= self.work_order_not_before
            && produced_at < self.work_order_expires_at
            && work_order.work_order_id == self.work_order_id.to_string()
            && work_order.tenant_id == self.tenant_id.to_string()
            && work_order.work_item_id == self.work_item_id.to_string()
            && work_order.attempt_id == self.attempt_id.to_string()
            && work_order.source.system == "linear"
            && work_order.source.external_id == self.source_external_id
            && work_order.source.snapshot_digest == self.source_snapshot_digest
            && self.attempt_source_snapshot_digest == self.source_snapshot_digest
            && work_order.repository.forge == "github"
            && work_order.repository.repository == self.repository
            && work_order.repository.base_ref == self.attempt_base_ref
            && work_order.repository.base_sha == self.attempt_base_sha
            && work_order.policy_digest == self.policy_digest
            && self.attempt_policy_digest == self.policy_digest
            && work_order.verification.policy_snapshot_digest == self.policy_digest
            && matches!(
                work_order.delivery.closure_target,
                crate::contracts::RunmillWorkOrderClosureTarget::Pr
            )
            && predicate.work_order.envelope_digest == self.work_order.envelope_digest()?
            && predicate.run.run_id.as_str() == self.external_run_id
            && predicate.run.attempt_id.as_uuid() == self.attempt_id
            && predicate.run.work_order_id.as_uuid() == self.work_order_id
            && predicate.work_order.payload_digest == self.work_order_payload_digest
            && predicate.policy.effective_policy_digest == self.policy_digest
            && predicate.source.forge == "github"
            && predicate.source.repository == self.repository
            && predicate.source.base_ref == self.attempt_base_ref
            && predicate.source.base_sha == self.attempt_base_sha
            && predicate.source.candidate_sha == self.evidence_candidate_sha
            && predicate.source.remote_head_sha == self.evidence_candidate_sha
            && self.evidence_base_sha == self.attempt_base_sha
            && self.evidence_work_order_digest == self.work_order_payload_digest;
        if !exact {
            return Err(Error::Validation(
                "Runmill evidence contradicts its authoritative run, Work Order, worker session, or repository binding"
                    .into(),
            ));
        }

        let signer_key = decode_verifying_key(&self.worker_session_signing_public_key)?;
        let signer_valid_until = self
            .worker_session_closed_at
            .map_or(self.worker_session_expires_at, |closed_at| {
                closed_at.min(self.worker_session_expires_at)
            });
        let preflight_observed_at = Utc::now()
            .checked_add_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| Error::Validation("evidence preflight clock bound overflowed".into()))?;
        self.evidence.verify_signed_integrity(
            &TrustedRunmillEvidenceSigner {
                key_id: &self.worker_session_signing_key_id,
                verifying_key: &signer_key,
                valid_from: self.worker_session_started_at,
                valid_until: signer_valid_until,
                revoked: self.worker_session_status == "REVOKED",
            },
            preflight_observed_at,
        )?;

        let authority = PathAuthority {
            allowed: work_order.scope.allowed_paths.iter().cloned().collect(),
            forbidden: work_order.scope.forbidden_paths.iter().cloned().collect(),
        };
        authority.validate()?;
        if predicate
            .source
            .changed_paths
            .iter()
            .any(|path| !authority.allows_path(path))
        {
            return Err(Error::Validation(
                "Runmill evidence contains a changed path outside the immutable Work Order scope"
                    .into(),
            ));
        }
        self.verify_approval_bindings()?;
        reject_sensitive_fields(&self.evidence_payload)
    }

    fn verify_artifact_metadata(&self) -> Result<()> {
        let manifest = &self.evidence.statement.predicate.artifacts;
        if manifest.len() != self.artifacts.len() {
            return Err(Error::Validation(
                "not every signed Runmill artifact has one durable ledger binding".into(),
            ));
        }
        for expected in manifest {
            let expected_kind = match expected.kind {
                RunmillArtifactKind::WorkOrderEnvelope => "work-order-envelope",
                RunmillArtifactKind::EffectivePolicy => "effective-policy",
                RunmillArtifactKind::NormalizedDiff => "normalized-diff",
                RunmillArtifactKind::AgentOutcome => "agent-outcome",
                RunmillArtifactKind::Verification => "verification",
                RunmillArtifactKind::CiObservation => "ci-observation",
                RunmillArtifactKind::Review => "review",
                RunmillArtifactKind::SideEffect => "side-effect",
                RunmillArtifactKind::Approval => "approval",
                RunmillArtifactKind::RuntimeManifest => "runtime-manifest",
            };
            let expected_retention = match expected.retention_class {
                RunmillRetentionClass::Portable => "portable",
                RunmillRetentionClass::Protected => "protected",
                RunmillRetentionClass::Restricted => "restricted",
            };
            let Some(stored) = self
                .artifacts
                .iter()
                .find(|stored| stored.manifest_artifact_id == expected.artifact_id)
            else {
                return Err(Error::Validation(format!(
                    "signed Runmill artifact {} is absent from durable storage metadata",
                    expected.digest
                )));
            };
            if stored.byte_size < 0
                || stored.manifest_kind != expected_kind
                || stored.digest != expected.digest
                || u64::try_from(stored.byte_size).ok() != Some(expected.size_bytes)
                || stored.media_type != expected.media_type
                || stored.retention_class.to_ascii_lowercase() != expected_retention
                || stored.object_key != expected.location_ref
                || stored.created_at > Utc::now() + Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS)
                || stored
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= Utc::now())
                || stored.object_key.trim().is_empty()
                || stored.relationship.trim().is_empty()
                || stored.id.is_nil()
            {
                return Err(Error::Validation(format!(
                    "durable artifact metadata contradicts signed artifact {}",
                    expected.digest
                )));
            }
        }
        let predicate = &self.evidence.statement.predicate;
        if predicate.work_order.envelope_artifact_digest != predicate.work_order.envelope_digest
            || predicate.policy.effective_policy_artifact_digest
                != predicate.policy.effective_policy_digest
            || predicate.source.normalized_diff_artifact_digest
                != predicate.source.normalized_diff_digest
            || [
                &predicate.work_order.envelope_artifact_digest,
                &predicate.policy.effective_policy_artifact_digest,
                &predicate.source.normalized_diff_artifact_digest,
            ]
            .iter()
            .any(|required| {
                !manifest
                    .iter()
                    .any(|artifact| artifact.digest.as_str() == required.as_str())
            })
        {
            return Err(Error::Validation(
                "primary evidence artifacts are not digest-identical to their signed subjects"
                    .into(),
            ));
        }
        Ok(())
    }

    fn forge_request(&self) -> Result<ObservePullRequestRequest> {
        let predicate = &self.evidence.statement.predicate;
        let delivery = &predicate.delivery.pull_request;
        let request = ObservePullRequestRequest::new(
            PullRequestRef {
                repository: self.repository.clone(),
                number: delivery.number,
            },
            self.attempt_base_sha.clone(),
            self.evidence_candidate_sha.clone(),
            self.work_order
                .payload
                .verification
                .required_remote_checks
                .iter()
                .cloned()
                .collect(),
        );
        request
            .validate()
            .map_err(|error| map_forge_error(&error))?;
        Ok(request)
    }

    fn verify_complete_evidence(
        &self,
        configured_work_order_key_id: &str,
        configured_work_order_key: &VerifyingKey,
        independently_observed_pull_request: &PullRequestEvidence,
        observation_requested_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    ) -> Result<()> {
        self.verify_static_authority(configured_work_order_key_id, configured_work_order_key)?;
        let latest_permitted = Utc::now()
            .checked_add_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| Error::Validation("forge clock bound overflowed".into()))?;
        let earliest_permitted = observation_requested_at
            .checked_sub_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| Error::Validation("forge freshness bound overflowed".into()))?;
        if observed_at < self.evidence_produced_at
            || observed_at < earliest_permitted
            || observed_at > latest_permitted
        {
            return Err(Error::Validation(
                "forge observation time is outside the evidence verification window".into(),
            ));
        }
        let signer_key = decode_verifying_key(&self.worker_session_signing_public_key)?;
        let signer_valid_until = self
            .worker_session_closed_at
            .map_or(self.worker_session_expires_at, |closed_at| {
                closed_at.min(self.worker_session_expires_at)
            });
        let predicate = &self.evidence.statement.predicate;
        let changed_paths: BTreeSet<String> =
            predicate.source.changed_paths.iter().cloned().collect();
        let required_local_checks = self
            .work_order
            .payload
            .verification
            .required_local_check_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let required_ci_contexts = self
            .work_order
            .payload
            .verification
            .required_remote_checks
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let local_reviewer_principal =
            self.reviewer_principal(RunmillProviderRole::LocalReviewer)?;
        let pull_request_reviewer_principal =
            self.reviewer_principal(RunmillProviderRole::PullRequestReviewer)?;
        let external_run_id = RunmillExternalRunId::new(self.external_run_id.clone())?;
        let work_order_envelope_digest = self.work_order.envelope_digest()?;
        let expectation = RunmillEvidenceExpectation {
            trusted_signer: TrustedRunmillEvidenceSigner {
                key_id: &self.worker_session_signing_key_id,
                verifying_key: &signer_key,
                valid_from: self.worker_session_started_at,
                valid_until: signer_valid_until,
                revoked: self.worker_session_status == "REVOKED",
            },
            observed_at,
            run_id: &external_run_id,
            attempt_id: AttemptId::from_uuid(self.attempt_id),
            work_order_id: WorkOrderId::from_uuid(self.work_order_id),
            work_order_key_id: &self.work_order_key_id,
            work_order_envelope_digest: &work_order_envelope_digest,
            work_order_payload_digest: &self.work_order_payload_digest,
            effective_policy_digest: &self.policy_digest,
            forge: "github",
            repository: &self.repository,
            base_ref: &self.attempt_base_ref,
            base_sha: &self.attempt_base_sha,
            candidate_sha: &self.evidence_candidate_sha,
            tree_digest: &predicate.source.tree_digest,
            normalized_diff_digest: &predicate.source.normalized_diff_digest,
            changed_paths: &changed_paths,
            required_local_checks: &required_local_checks,
            required_ci_contexts: &required_ci_contexts,
            local_reviewer: Some(AuthorizedRunmillReviewer {
                principal_id: local_reviewer_principal,
                profile_id: &self.work_order.payload.identities.local_reviewer,
            }),
            pull_request_reviewer: Some(AuthorizedRunmillReviewer {
                principal_id: pull_request_reviewer_principal,
                profile_id: &self.work_order.payload.identities.pr_reviewer,
            }),
            pull_request_head_ref: &predicate.delivery.pull_request.head_ref,
            independently_observed_pull_request,
        };
        self.evidence.verify(&expectation)?;
        Ok(())
    }

    fn reviewer_principal(&self, role: RunmillProviderRole) -> Result<&str> {
        let mut matches = self
            .evidence
            .statement
            .predicate
            .runtime
            .providers
            .iter()
            .filter(|provider| provider.role == role);
        let provider = matches.next().ok_or_else(|| {
            Error::Validation(format!("Runmill evidence is missing the {role:?} identity"))
        })?;
        if matches.next().is_some() {
            return Err(Error::Validation(format!(
                "Runmill evidence repeats the {role:?} identity"
            )));
        }
        Ok(&provider.principal_id)
    }

    fn verify_approval_bindings(&self) -> Result<()> {
        let evidence_approvals = &self.evidence.statement.predicate.approvals;
        if self.approvals.len() != evidence_approvals.len()
            || self.approvals.iter().any(|approval| {
                approval.status != "APPROVED"
                    || approval.work_order_digest.as_deref()
                        != Some(self.work_order_payload_digest.as_str())
                    || approval.candidate_sha.as_deref()
                        != Some(self.evidence_candidate_sha.as_str())
                    || approval.policy_digest != self.policy_digest
                    || approval.expires_at <= Utc::now()
            })
        {
            return Err(Error::Validation(
                "ledger approvals are unresolved, expired, or absent from signed evidence".into(),
            ));
        }
        for approval in &self.approvals {
            let Some(evidence) = evidence_approvals
                .iter()
                .find(|evidence| evidence.approval_id == approval.id.to_string())
            else {
                return Err(Error::Validation(format!(
                    "approved ledger decision {} is absent from signed evidence",
                    approval.id
                )));
            };
            if evidence.requested_effect != approval.decision_effect_type
                || evidence.decision_type != approval.approval_type
                || approval.decision_subject.as_deref() != Some(&evidence.approver_subject)
                || evidence.work_order_digest != self.work_order_payload_digest
                || evidence.candidate_sha != self.evidence_candidate_sha
                || evidence.policy_digest != self.policy_digest
                || evidence.issued_at.to_utc()? != approval.issued_at
                || evidence.expires_at.to_utc()? != approval.expires_at
            {
                return Err(Error::Validation(format!(
                    "signed approval evidence contradicts ledger decision {}",
                    approval.id
                )));
            }
        }
        Ok(())
    }
}

async fn lock_claim_and_binding(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &VerificationJobPayload,
) -> Result<VerificationBinding> {
    let row = sqlx::query(
        r"
        SELECT
            work.tenant_id,
            work.id AS work_item_id,
            work.aggregate_version AS work_item_version,
            work.source_external_id,
            snapshot.content_digest AS source_snapshot_digest,
            repository.owner || '/' || repository.name AS repository,
            work.policy_digest,
            attempt.id AS attempt_id,
            attempt.base_ref AS attempt_base_ref,
            attempt.base_sha AS attempt_base_sha,
            attempt.source_snapshot_digest AS attempt_source_snapshot_digest,
            attempt.policy_digest AS attempt_policy_digest,
            attempt.terminal_at AS attempt_terminal_at,
            work_order.id AS work_order_id,
            work_order.payload_digest AS work_order_payload_digest,
            work_order.canonical_payload AS work_order_canonical_payload,
            work_order.payload AS work_order_payload,
            work_order.exact_signed_envelope AS work_order_exact_envelope,
            work_order.schema_version AS work_order_schema,
            work_order.envelope_schema AS work_order_envelope_schema,
            work_order.algorithm AS work_order_algorithm,
            work_order.key_id AS work_order_key_id,
            work_order.signature AS work_order_signature,
            work_order.issued_at AS work_order_issued_at,
            work_order.not_before AS work_order_not_before,
            work_order.expires_at AS work_order_expires_at,
            workflow.id AS workflow_id,
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence_token,
            workflow.event_cursor AS workflow_event_cursor,
            COALESCE(anchor.generation, 0) AS anchor_generation,
            run.id AS run_id,
            run.external_run_id,
            run.terminal_at AS run_terminal_at,
            run.evidence_expectation_digest AS expectation_digest,
            run.worker_id,
            run.worker_generation,
            worker.status AS worker_status,
            run.worker_session_id,
            worker_session.status AS worker_session_status,
            worker_session.signing_key_id AS worker_session_signing_key_id,
            worker_session.signing_public_key AS worker_session_signing_public_key,
            worker_session.started_at AS worker_session_started_at,
            worker_session.expires_at AS worker_session_expires_at,
            worker_session.closed_at AS worker_session_closed_at,
            evidence.id AS evidence_id,
            evidence.worker_session_id AS evidence_worker_session_id,
            evidence.payload_digest AS evidence_payload_digest,
            evidence.work_order_digest AS evidence_work_order_digest,
            evidence.base_sha AS evidence_base_sha,
            evidence.candidate_sha AS evidence_candidate_sha,
            evidence.schema_version AS evidence_schema,
            evidence.envelope_schema AS evidence_envelope_schema,
            evidence.algorithm AS evidence_algorithm,
            evidence.key_id AS evidence_key_id,
            evidence.signature AS evidence_signature,
            evidence.canonical_payload AS evidence_canonical_payload,
            evidence.payload AS evidence_payload,
            evidence.exact_signed_envelope AS evidence_exact_envelope,
            evidence.produced_at AS evidence_produced_at
        FROM workflow_jobs AS job
        JOIN work_items AS work
          ON work.tenant_id = job.tenant_id
         AND work.id = job.work_item_id
         AND work.current_attempt_id = job.attempt_id
         AND work.state = 'VERIFYING_OUTCOME'
         AND work.source_system = 'LINEAR'
         AND work.closure_target = 'pull_request'
        JOIN source_snapshots AS snapshot
          ON snapshot.tenant_id = work.tenant_id
         AND snapshot.id = work.source_snapshot_id
         AND snapshot.repository_id = work.repository_id
         AND snapshot.source_system = work.source_system
         AND snapshot.external_id = work.source_external_id
        JOIN repositories AS repository
          ON repository.tenant_id = work.tenant_id
         AND repository.id = work.repository_id
        JOIN attempts AS attempt
          ON attempt.tenant_id = work.tenant_id
         AND attempt.id = work.current_attempt_id
         AND attempt.work_item_id = work.id
         AND attempt.state = 'SUCCEEDED'
         AND attempt.terminal_at IS NOT NULL
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = job.tenant_id
         AND workflow.id = job.workflow_instance_id
         AND workflow.work_item_id = work.id
         AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
         AND workflow.state = 'ACTIVE'
        JOIN runs AS run
          ON run.tenant_id = work.tenant_id
         AND run.id = $7
         AND run.work_item_id = work.id
         AND run.attempt_id = attempt.id
         AND run.authoritative
         AND run.state = 'SUCCEEDED'
         AND run.terminal_at IS NOT NULL
         AND run.evidence_expectation_digest = $11
        JOIN workers AS worker
          ON worker.tenant_id = run.tenant_id
         AND worker.id = run.worker_id
         AND worker.status <> 'QUARANTINED'
        JOIN worker_sessions AS worker_session
          ON worker_session.tenant_id = run.tenant_id
         AND worker_session.id = run.worker_session_id
         AND worker_session.worker_id = run.worker_id
         AND worker_session.worker_generation = run.worker_generation
        JOIN work_orders AS work_order
          ON work_order.tenant_id = run.tenant_id
         AND work_order.id = run.work_order_id
         AND work_order.work_item_id = work.id
         AND work_order.attempt_id = attempt.id
         AND work_order.payload_digest = attempt.work_order_digest
         AND work_order.payload_digest = $10
        JOIN evidence_bundles AS evidence
          ON evidence.tenant_id = work.tenant_id
         AND evidence.id = $6
         AND evidence.work_item_id = work.id
         AND evidence.attempt_id = attempt.id
         AND evidence.run_id = run.id
         AND evidence.worker_id = run.worker_id
         AND evidence.worker_generation = run.worker_generation
         AND evidence.worker_session_id = run.worker_session_id
         AND evidence.key_id = worker_session.signing_key_id
         AND evidence.payload_digest = $9
         AND evidence.work_order_digest = work_order.payload_digest
         AND evidence.base_sha = attempt.base_sha
         AND evidence.requested_target = work.closure_target
         AND evidence.target_satisfied
        LEFT JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
        WHERE job.tenant_id = $1
          AND job.id = $2
          AND job.workflow_instance_id = $3
          AND job.work_item_id = $4
          AND job.attempt_id = $5
          AND job.job_type = 'VERIFY_EVIDENCE'
          AND job.activity_contract_id = $13
          AND job.status = 'RUNNING'
          AND job.lease_owner = $8
          AND job.fence_token = $12
          AND job.lease_expires_at > clock_timestamp()
          AND NOT EXISTS (
              SELECT 1
              FROM evidence_verifications AS verification
              WHERE verification.tenant_id = evidence.tenant_id
                AND verification.evidence_id = evidence.id
                AND verification.expectation_digest = run.evidence_expectation_digest
          )
          AND NOT EXISTS (
              SELECT 1
              FROM escalations AS escalation
              WHERE escalation.tenant_id = work.tenant_id
                AND escalation.work_item_id = work.id
                AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
                AND escalation.authority_or_effect_active
          )
          AND NOT EXISTS (
              SELECT 1
              FROM effect_intents AS effect
              WHERE effect.tenant_id = work.tenant_id
                AND effect.work_item_id = work.id
                AND effect.status NOT IN ('OBSERVED', 'CANCELLED')
          )
        FOR UPDATE OF job, work, attempt, workflow, run, worker
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(job.workflow_instance_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(payload.evidence_id)
    .bind(payload.run_id)
    .bind(&job.lease_owner)
    .bind(&payload.payload_digest)
    .bind(&payload.work_order_digest)
    .bind(&payload.expectation_digest)
    .bind(job.fence_token)
    .bind(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "lock authoritative evidence-verification binding: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "evidence-verification job {} has no exact current unblocked delivery authority",
            job.id
        ))
    })?;
    let evidence_id: Uuid = required(&row, "evidence_id", "evidence")?;
    let artifacts = lock_artifact_bindings(transaction, job.tenant_id, evidence_id).await?;
    let work_item_id: Uuid = required(&row, "work_item_id", "work item")?;
    let attempt_id: Uuid = required(&row, "attempt_id", "attempt")?;
    let approvals =
        lock_approval_bindings(transaction, job.tenant_id, work_item_id, attempt_id).await?;
    VerificationBinding::from_row(&row, artifacts, approvals, job.id)
}

async fn lock_artifact_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    evidence_id: Uuid,
) -> Result<Vec<ArtifactBinding>> {
    let rows = sqlx::query(
        r"
        SELECT
            artifact.id,
            link.manifest_artifact_id,
            link.manifest_kind,
            link.relationship,
            artifact.digest,
            artifact.media_type,
            artifact.byte_size,
            artifact.object_key,
            artifact.retention_class,
            artifact.created_at,
            artifact.expires_at
        FROM evidence_artifacts AS link
        JOIN artifacts AS artifact
          ON artifact.tenant_id = link.tenant_id
         AND artifact.id = link.artifact_id
         AND artifact.digest_algorithm = 'sha256'
        WHERE link.tenant_id = $1
          AND link.evidence_id = $2
        ORDER BY artifact.digest, artifact.id
        FOR SHARE OF link, artifact
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("lock evidence artifact bindings: {error}")))?;
    rows.iter()
        .map(|row| {
            Ok(ArtifactBinding {
                id: required(row, "id", "artifact ID")?,
                manifest_artifact_id: required(
                    row,
                    "manifest_artifact_id",
                    "signed manifest artifact ID",
                )?,
                manifest_kind: required(row, "manifest_kind", "signed manifest artifact kind")?,
                relationship: required(row, "relationship", "artifact relationship")?,
                digest: required(row, "digest", "artifact digest")?,
                media_type: required(row, "media_type", "artifact media type")?,
                byte_size: required(row, "byte_size", "artifact byte size")?,
                object_key: required(row, "object_key", "artifact object key")?,
                retention_class: required(row, "retention_class", "artifact retention class")?,
                created_at: required(row, "created_at", "artifact creation time")?,
                expires_at: optional(row, "expires_at", "artifact expiry")?,
            })
        })
        .collect()
}

async fn lock_approval_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
) -> Result<Vec<ApprovalBinding>> {
    let rows = sqlx::query(
        r"
        SELECT
            id, approval_type, status, work_order_digest, candidate_sha,
            decision_effect_type, policy_digest, decision_subject,
            issued_at, expires_at
        FROM approvals
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND attempt_id = $3
        ORDER BY id
        FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(attempt_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("lock evidence approval bindings: {error}")))?;
    rows.iter()
        .map(|row| {
            Ok(ApprovalBinding {
                id: required(row, "id", "approval ID")?,
                approval_type: required(row, "approval_type", "approval type")?,
                status: required(row, "status", "approval status")?,
                work_order_digest: optional(row, "work_order_digest", "approval Work Order")?,
                candidate_sha: optional(row, "candidate_sha", "approval candidate")?,
                decision_effect_type: required(row, "decision_effect_type", "approval effect")?,
                policy_digest: required(row, "policy_digest", "approval policy")?,
                decision_subject: optional(row, "decision_subject", "approval subject")?,
                issued_at: required(row, "issued_at", "approval issuance")?,
                expires_at: required(row, "expires_at", "approval expiry")?,
            })
        })
        .collect()
}

async fn verify_artifact_contents(
    store: &dyn ArtifactStore,
    binding: &VerificationBinding,
) -> Result<()> {
    for artifact in &binding.evidence.statement.predicate.artifacts {
        let bytes = store.get(&artifact.digest).await.map_err(|error| {
            Error::ExternalUnavailable(format!(
                "load content-addressed evidence artifact {}: {error}",
                artifact.digest
            ))
        })?;
        if sha256_digest(&bytes) != artifact.digest
            || u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes)
        {
            return Err(Error::Crypto(format!(
                "content-addressed artifact {} does not match its signed digest and size",
                artifact.digest
            )));
        }
    }
    Ok(())
}

async fn commit_valid_verification(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &VerificationBinding,
    pull_request: PullRequestEvidence,
    provider_revision: String,
    observed_at: DateTime<Utc>,
) -> Result<()> {
    let verified_at = Utc::now();
    let receipt = EvidenceVerificationReceiptV1 {
        schema: EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1.into(),
        evidence_id: EvidenceId::from_uuid(binding.evidence_id),
        work_item_id: WorkItemId::from_uuid(binding.work_item_id),
        attempt_id: AttemptId::from_uuid(binding.attempt_id),
        run_id: RunId::from_uuid(binding.run_id),
        evidence_digest: binding.evidence_payload_digest.clone(),
        work_order_digest: binding.work_order_payload_digest.clone(),
        expectation_digest: binding.expectation_digest.clone(),
        verification_job_id: job.id,
        verification_job_fence_token: job.fence_token,
        verification_job_completed_by: job.lease_owner.clone(),
        verifier: VERIFIER_ID.into(),
        pull_request,
        provider_revision,
        observed_at,
    };
    receipt.validate()?;
    let receipt_details =
        serde_json::to_value(&receipt).map_err(|error| Error::Serialization(error.to_string()))?;
    let receipt_digest = receipt.digest()?;
    let verification_id = derived_uuid(binding.evidence_id, 40);

    sqlx::query(
        r"
        INSERT INTO evidence_verifications (
            id, tenant_id, evidence_id, work_item_id, attempt_id, run_id,
            evidence_digest, work_order_digest, verifier, status,
            expectation_digest, workflow_job_id, workflow_job_fence_token,
            workflow_job_completed_by, details, verified_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 'VALID', $10,
            $11, $12, $13, $14, $15
        )
        ",
    )
    .bind(verification_id)
    .bind(binding.tenant_id)
    .bind(binding.evidence_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(binding.run_id)
    .bind(&binding.evidence_payload_digest)
    .bind(&binding.work_order_payload_digest)
    .bind(VERIFIER_ID)
    .bind(&binding.expectation_digest)
    .bind(job.id)
    .bind(job.fence_token)
    .bind(&job.lease_owner)
    .bind(&receipt_details)
    .bind(verified_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("insert VALID evidence receipt: {error}")))?;

    let intermediate_version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE work_items
        SET state = 'TARGET_REACHED',
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND state = 'VERIFYING_OUTCOME'
          AND aggregate_version = $3
        RETURNING aggregate_version
        ",
    )
    .bind(binding.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.work_item_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("advance independently verified target: {error}")))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {} changed before evidence verification committed",
            binding.work_item_id
        ))
    })?;
    let final_work_item_version = intermediate_version.checked_add(1).ok_or_else(|| {
        Error::Persistence("work-item version overflow during evidence verification".into())
    })?;
    let next_cursor = binding
        .workflow_event_cursor
        .checked_add(1)
        .ok_or_else(|| Error::Persistence("workflow cursor overflow".into()))?;
    let close_job_id = derived_uuid(binding.evidence_id, 41);
    let close_payload = json!({
        "work_item_id": binding.work_item_id,
        "expected_work_item_version": final_work_item_version,
        "evidence_id": binding.evidence_id,
        "run_id": binding.run_id,
        "payload_digest": binding.evidence_payload_digest,
        "work_order_digest": binding.work_order_payload_digest,
        "expectation_digest": binding.expectation_digest,
    });
    let result = json!({
        "schema": RESULT_SCHEMA_V1,
        "work_item_id": binding.work_item_id,
        "attempt_id": binding.attempt_id,
        "run_id": binding.run_id,
        "evidence_id": binding.evidence_id,
        "evidence_digest": binding.evidence_payload_digest,
        "work_order_digest": binding.work_order_payload_digest,
        "expectation_digest": binding.expectation_digest,
        "verification_id": verification_id,
        "verification_receipt_digest": receipt_digest,
        "close_source_job_id": close_job_id,
    });
    let commit_digest = sha256_digest(&canonical_json(&json!({
        "job_id": job.id,
        "job_fence_token": job.fence_token,
        "work_item_version": intermediate_version,
        "workflow_version": binding.workflow_version,
        "workflow_fence_token": binding.workflow_fence_token,
        "workflow_event_cursor": next_cursor,
        "result": result,
        "work_item_state": "CLOSING_SOURCE",
        "workflow_state": "ACTIVE",
        "closure_evidence_id": binding.evidence_id,
        "close_source_job": close_payload,
    }))?);
    let commit = WorkflowStepCommit {
        fence: WorkflowStepFence {
            tenant_id: binding.tenant_id,
            job_id: job.id,
            workflow_instance_id: binding.workflow_id,
            work_item_id: binding.work_item_id,
            lease_owner: job.lease_owner.clone(),
            job_fence_token: job.fence_token,
            expected_work_item_version: intermediate_version,
            expected_workflow_version: binding.workflow_version,
            expected_workflow_fence_token: binding.workflow_fence_token,
            expected_anchor_generation: binding.anchor_generation,
        },
        commit_digest,
        job_result: Some(result),
        work_item_state: "CLOSING_SOURCE".into(),
        workflow_state: "ACTIVE".into(),
        workflow_event_cursor: next_cursor,
        accountability: AccountabilityReplacement {
            kind: LedgerAccountabilityKind::Closure,
            reference_id: binding.evidence_id,
            wake_or_deadline_at: None,
            authority_or_effect_active: false,
        },
        jobs: vec![StepWorkflowJob {
            id: close_job_id,
            attempt_id: Some(binding.attempt_id),
            job_type: CLOSE_SOURCE.into(),
            activity_contract_id: CLOSE_SOURCE_ACTIVITY_CONTRACT_ID.into(),
            payload: close_payload,
            idempotency_key: format!("close-source:{}", binding.evidence_id),
            priority: 80,
            available_at: verified_at,
            max_attempts: 25,
        }],
        timers: Vec::new(),
        effects: Vec::new(),
        outbox: vec![StepOutboxMessage {
            id: derived_uuid(binding.evidence_id, 43),
            topic: "work-items".into(),
            message_key: binding.work_item_id.to_string(),
            event_type: "evidence.verified".into(),
            payload: json!({
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "run_id": binding.run_id,
                "evidence_id": binding.evidence_id,
                "evidence_digest": binding.evidence_payload_digest,
                "verification_id": verification_id,
                "verification_receipt_digest": receipt_digest,
                "close_source_job_id": close_job_id,
            }),
            headers: json!({"schema": "asf.work-item-event/v1"}),
            idempotency_key: format!("evidence-verified:{}:outbox", binding.evidence_id),
            available_at: verified_at,
        }],
        audit_events: vec![StepAuditEvent {
            id: derived_uuid(binding.evidence_id, 42),
            attempt_id: Some(binding.attempt_id),
            actor_type: "SERVICE".into(),
            actor_id: job.lease_owner.clone(),
            action: "EVIDENCE_VERIFIED".into(),
            subject_type: "EVIDENCE".into(),
            subject_id: binding.evidence_id.to_string(),
            correlation_id: format!("evidence-verification:{}", binding.evidence_id),
            trace_id: None,
            policy_digest: Some(binding.policy_digest.clone()),
            before_digest: Some(binding.evidence_payload_digest.clone()),
            after_digest: Some(receipt_digest),
            details: json!({
                "schema": AUDIT_SCHEMA_V1,
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "run_id": binding.run_id,
                "evidence_id": binding.evidence_id,
                "verification_id": verification_id,
                "receipt": receipt,
                "close_source_job_id": close_job_id,
            }),
            occurred_at: verified_at,
        }],
    };
    match commit_workflow_step_with_prelocked_claim(transaction, &commit).await? {
        WorkflowStepCommitOutcome::Applied {
            work_item_version, ..
        } if work_item_version == final_work_item_version => Ok(()),
        WorkflowStepCommitOutcome::Applied {
            work_item_version, ..
        } => Err(Error::Persistence(format!(
            "evidence verification advanced work to unexpected version {work_item_version}"
        ))),
        WorkflowStepCommitOutcome::AlreadyApplied => Ok(()),
    }
}

fn map_forge_error(error: &ForgeGatewayError) -> Error {
    match error {
        ForgeGatewayError::AmbiguousEffect { .. } => Error::AmbiguousEffect(error.to_string()),
        _ => Error::ExternalUnavailable(error.to_string()),
    }
}

fn derived_uuid(base: Uuid, discriminator: u8) -> Uuid {
    let mut bytes = *base.as_bytes();
    bytes[15] ^= discriminator;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn required<T>(row: &PgRow, name: &str, label: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|error| Error::Persistence(format!("decode {label}: {error}")))
}

fn optional<T>(row: &PgRow, name: &str, label: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|error| Error::Persistence(format!("decode optional {label}: {error}")))
}
