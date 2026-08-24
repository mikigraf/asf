//! Durable, evidence-authorized Linear source closure.
//!
//! A source close is split across two transactions. The first locks the exact
//! workflow-job claim and authoritative delivery evidence, then persists one
//! immutable Linear request before any network I/O. The second re-locks every
//! authoritative coordinate and atomically records the provider receipt,
//! closes the work and workflow, installs the closure accountability anchor,
//! completes the job, and emits audit/outbox facts.
//!
//! An ambiguous mutation is never made sendable again. Every later execution
//! uses only Linear's exact signed-marker reconciliation operation.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, CLOSE_SOURCE, CLOSE_SOURCE_ACTIVITY_CONTRACT_ID, JobHandler,
};
use crate::{
    Error, Result,
    contracts::{
        EvidenceVerificationReceiptV1, RunmillClosureTarget, RunmillSignedWorkOrderV1,
        RunmillStopReason, SignedRunmillEvidenceBundle,
    },
    crypto::{
        canonical_json, decode_verifying_key, is_sha256_digest, sha256_digest, verify_signature,
    },
    domain::{ClosureTarget, EvidenceId, SourceSystem, TenantId, WorkItemId},
    ledger::{
        AccountabilityReplacement, AttemptReservationReleaseNamespace, ClaimedWorkflowJob,
        LedgerAccountabilityKind, PgLedger, StepAuditEvent, StepOutboxMessage, WorkflowStepCommit,
        WorkflowStepCommitOutcome, WorkflowStepFence, commit_workflow_step_with_prelocked_claim,
        lock_attempt_reservation_release_authority, release_active_attempt_reservations,
    },
    ports::{
        CloseSourceRequest, ReconcileSourceCloseRequest, SOURCE_CLOSE_RECEIPT_SCHEMA_V1,
        SourceCloseDisposition, SourceCloseEffect, SourceCloseReceipt, SourceCloseReconciliation,
        SourceClosure, SourceGateway, SourceGatewayError, SourceItemRef,
    },
    security::reject_sensitive_fields,
};

const SOURCE_CLOSE_RESULT_SCHEMA_V1: &str = "asf.source-close-workflow-result.v1";
const SOURCE_CLOSE_AUDIT_SCHEMA_V1: &str = "asf.source-close-audit.v1";
const PROVIDER_CLOCK_SKEW_SECONDS: i64 = 300;

/// Production activity that closes one Linear item from independently valid
/// evidence. One instance is fenced to exactly one tenant and source gateway.
pub struct LinearSourceClosureHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    source: Arc<dyn SourceGateway>,
}

impl fmt::Debug for LinearSourceClosureHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearSourceClosureHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("source", &"SourceGateway([REDACTED])")
            .finish()
    }
}

impl LinearSourceClosureHandler {
    /// Construct a tenant-fenced source-closure activity.
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        source: Arc<dyn SourceGateway>,
    ) -> Result<Self> {
        if tenant_id.as_uuid().is_nil() {
            return Err(Error::Validation(
                "source-closure handler tenant cannot be nil".into(),
            ));
        }
        Ok(Self {
            ledger,
            tenant_id,
            source,
        })
    }

    async fn execute_inner(&self, job: &ClaimedWorkflowJob) -> Result<ActivityOutcome> {
        let payload = SourceClosureJobPayload::parse(job, self.tenant_id)?;
        let prepared = self.prepare(job, &payload).await?;

        let receipt = match &prepared.action {
            ExternalAction::Close => match self.source.close_source(&prepared.request).await {
                Ok(receipt) => {
                    if let Err(error) = validate_receipt(&prepared.request, &receipt, false) {
                        self.release_remote_outcome_to_ambiguity(
                            job,
                            &prepared,
                            "Linear returned a contradictory source-close receipt",
                        )
                        .await?;
                        return Err(error);
                    }
                    receipt
                }
                Err(error) => {
                    let ambiguous = mutation_error_is_ambiguous(&error);
                    self.record_mutation_failure(job, &prepared, &error, ambiguous)
                        .await?;
                    return Err(map_source_error(&error));
                }
            },
            ExternalAction::Reconcile => {
                let request = ReconcileSourceCloseRequest::from_close(&prepared.request);
                let reconciliation = match self.source.reconcile_source_close(&request).await {
                    Ok(reconciliation) => reconciliation,
                    Err(error) => {
                        self.record_reconciliation_pending(&prepared, &error.to_string())
                            .await?;
                        return Err(map_source_error(&error));
                    }
                };
                match reconciliation {
                    SourceCloseReconciliation::Applied(receipt) => {
                        if let Err(error) = validate_receipt(&prepared.request, &receipt, true) {
                            self.record_reconciliation_pending(
                                &prepared,
                                "Linear reconciliation returned a contradictory receipt",
                            )
                            .await?;
                            return Err(error);
                        }
                        receipt
                    }
                    SourceCloseReconciliation::NotObserved => {
                        self.record_reconciliation_pending(
                            &prepared,
                            "Linear has not observed the exact ambiguous close request",
                        )
                        .await?;
                        return Err(Error::ExternalUnavailable(format!(
                            "ambiguous Linear source closure {} is not yet observed",
                            prepared.effect_id
                        )));
                    }
                }
            }
            ExternalAction::FinalizeObserved(receipt) => {
                validate_receipt(&prepared.request, receipt, false)?;
                receipt.clone()
            }
        };

        if let Err(error) = self.finalize(job, &payload, &prepared, &receipt).await {
            if prepared.action.remote_outcome_may_need_reconciliation() {
                self.release_remote_outcome_to_ambiguity(
                    job,
                    &prepared,
                    "the Linear receipt could not be atomically committed to the ledger",
                )
                .await?;
            }
            return Err(error);
        }
        Ok(ActivityOutcome::TransactionCommitted)
    }

    async fn prepare(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &SourceClosureJobPayload,
    ) -> Result<PreparedClosure> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin Linear source-close preflight: {error}"))
        })?;
        let binding = lock_claim_and_binding(&mut transaction, job, payload).await?;
        let request = binding.build_request(Utc::now())?;
        let effect_id = stable_source_close_effect_id(binding.evidence_id);
        let (request, request_digest, action) =
            persist_or_adopt_effect(&mut transaction, job, &binding, request, effect_id).await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit Linear source-close preflight: {error}"))
        })?;
        Ok(PreparedClosure {
            binding,
            request,
            request_digest,
            effect_id,
            action,
        })
    }

    async fn finalize(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &SourceClosureJobPayload,
        prepared: &PreparedClosure,
        receipt: &SourceCloseReceipt,
    ) -> Result<()> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin Linear source-close commit: {error}"))
        })?;
        let final_binding = lock_claim_and_binding(&mut transaction, job, payload).await?;
        if prepared.binding != final_binding {
            return Err(Error::Conflict(format!(
                "source-closure job {} authoritative binding changed after Linear activity",
                job.id
            )));
        }
        final_binding.validate_request(&prepared.request)?;
        validate_receipt(
            &prepared.request,
            receipt,
            matches!(prepared.action, ExternalAction::Reconcile),
        )?;
        observe_exact_effect(&mut transaction, job, &final_binding, prepared, receipt).await?;
        commit_closed_workflow(&mut transaction, job, &final_binding, prepared, receipt).await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit Linear source-close transaction: {error}"))
        })
    }

    async fn record_mutation_failure(
        &self,
        job: &ClaimedWorkflowJob,
        prepared: &PreparedClosure,
        error: &SourceGatewayError,
        ambiguous: bool,
    ) -> Result<()> {
        update_owned_effect_failure(
            self.ledger.pool(),
            job,
            prepared,
            &error.to_string(),
            ambiguous,
        )
        .await
    }

    async fn release_remote_outcome_to_ambiguity(
        &self,
        job: &ClaimedWorkflowJob,
        prepared: &PreparedClosure,
        reason: &str,
    ) -> Result<()> {
        if matches!(prepared.action, ExternalAction::Close) {
            update_owned_effect_failure(self.ledger.pool(), job, prepared, reason, true).await
        } else {
            self.record_reconciliation_pending(prepared, reason).await
        }
    }

    async fn record_reconciliation_pending(
        &self,
        prepared: &PreparedClosure,
        error: &str,
    ) -> Result<()> {
        if matches!(prepared.action, ExternalAction::FinalizeObserved(_)) {
            return Ok(());
        }
        let error = summarize_error(error);
        let changed = sqlx::query(
            r"
            UPDATE effect_intents
            SET last_error = $7,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND id = $2
              AND work_item_id = $3
              AND attempt_id = $4
              AND provider = 'linear'
              AND effect_type = 'close_source'
              AND status = 'AMBIGUOUS'
              AND request_digest = $5
              AND request_payload = $6
              AND owning_workflow_job_id IS NULL
              AND lease_owner IS NULL
              AND lease_expires_at IS NULL
            ",
        )
        .bind(prepared.binding.tenant_id)
        .bind(prepared.effect_id)
        .bind(prepared.binding.work_item_id)
        .bind(prepared.binding.attempt_id)
        .bind(&prepared.request_digest)
        .bind(serde_json::to_value(&prepared.request).map_err(|error| {
            Error::Serialization(format!("encode persisted source-close request: {error}"))
        })?)
        .bind(error)
        .execute(self.ledger.pool())
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "record Linear source-close reconciliation state: {error}"
            ))
        })?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(Error::Conflict(format!(
                "ambiguous Linear source-close effect {} changed during reconciliation",
                prepared.effect_id
            )))
        }
    }
}

#[async_trait]
impl JobHandler for LinearSourceClosureHandler {
    fn job_type(&self) -> &str {
        CLOSE_SOURCE
    }

    fn activity_contract_id(&self) -> &str {
        CLOSE_SOURCE_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        // Closure drains already-authorized work and is safe during dispatch
        // maintenance. It cannot create an attempt or a Runmill execution.
        self.execute_inner(job).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceClosureJobPayload {
    work_item_id: Uuid,
    expected_work_item_version: i64,
    evidence_id: Uuid,
    run_id: Uuid,
    payload_digest: String,
    work_order_digest: String,
    expectation_digest: String,
}

impl SourceClosureJobPayload {
    fn parse(job: &ClaimedWorkflowJob, tenant_id: TenantId) -> Result<Self> {
        if job.job_type != CLOSE_SOURCE
            || job.activity_contract_id != CLOSE_SOURCE_ACTIVITY_CONTRACT_ID
            || job.tenant_id != tenant_id.as_uuid()
            || job.workflow_instance_id.is_none()
            || job.work_item_id.is_none()
            || job.attempt_id.is_none()
            || job.idempotency_key.trim().is_empty()
        {
            return Err(Error::Validation(format!(
                "source-closure job {} lacks an exact tenant/workflow/work/attempt binding or activity contract",
                job.id
            )));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!(
                "source-closure job {} has an incompatible payload: {error}",
                job.id
            ))
        })?;
        if payload.work_item_id.is_nil()
            || payload.evidence_id.is_nil()
            || payload.run_id.is_nil()
            || payload.expected_work_item_version <= 0
            || job.work_item_id != Some(payload.work_item_id)
            || !is_sha256_digest(&payload.payload_digest)
            || !is_sha256_digest(&payload.work_order_digest)
            || !is_sha256_digest(&payload.expectation_digest)
        {
            return Err(Error::Validation(format!(
                "source-closure job {} has invalid immutable evidence coordinates",
                job.id
            )));
        }
        reject_sensitive_fields(&job.payload)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SourceClosureBinding {
    tenant_id: Uuid,
    work_item_id: Uuid,
    work_item_version: i64,
    source_external_id: String,
    source_snapshot_id: Uuid,
    source_revision: String,
    source_snapshot_digest: String,
    repository: String,
    policy_digest: String,
    attempt_id: Uuid,
    attempt_version: i64,
    attempt_fence_token: i64,
    attempt_base_ref: String,
    attempt_base_sha: String,
    attempt_source_snapshot_digest: String,
    attempt_policy_digest: String,
    work_order_id: Uuid,
    work_order_digest: String,
    work_order_envelope_digest: String,
    work_order: RunmillSignedWorkOrderV1,
    workflow_id: Uuid,
    workflow_version: i64,
    workflow_fence_token: i64,
    workflow_event_cursor: i64,
    anchor_generation: i64,
    run_id: Uuid,
    external_run_id: String,
    run_version: i64,
    run_terminal_at: chrono::DateTime<Utc>,
    expectation_digest: String,
    worker_id: Uuid,
    worker_generation: i64,
    worker_status: String,
    worker_session_id: Uuid,
    worker_session_signing_key_id: String,
    worker_session_signing_public_key: String,
    worker_session_started_at: chrono::DateTime<Utc>,
    worker_session_expires_at: chrono::DateTime<Utc>,
    worker_session_closed_at: Option<chrono::DateTime<Utc>>,
    evidence_worker_session_id: Uuid,
    evidence_id: Uuid,
    evidence_digest: String,
    evidence_produced_at: chrono::DateTime<Utc>,
    evidence: SignedRunmillEvidenceBundle,
    verification_verifier: String,
    verification_verified_at: chrono::DateTime<Utc>,
    verification: EvidenceVerificationReceiptV1,
}

impl SourceClosureBinding {
    fn from_row(row: &PgRow, job_id: Uuid) -> Result<Self> {
        let work_order_exact: Vec<u8> = required(
            row,
            "work_order_exact_envelope",
            "signed Work Order envelope",
        )?;
        let work_order: RunmillSignedWorkOrderV1 = serde_json::from_slice(&work_order_exact)
            .map_err(|_| {
                Error::Persistence(format!(
                    "source-closure job {job_id} has an invalid signed Work Order envelope"
                ))
            })?;
        if work_order.canonical_bytes()? != work_order_exact {
            return Err(Error::Persistence(format!(
                "source-closure job {job_id} Work Order is not the canonical stored envelope"
            )));
        }
        let work_order_envelope_digest = work_order.envelope_digest()?;

        let canonical_payload: Vec<u8> = required(row, "canonical_payload", "evidence payload")?;
        let payload_value: Value = required(row, "evidence_payload", "evidence JSON payload")?;
        let exact_envelope: Vec<u8> =
            required(row, "exact_signed_envelope", "signed evidence envelope")?;
        let evidence = SignedRunmillEvidenceBundle::from_json(&exact_envelope).map_err(|error| {
            Error::Persistence(format!(
                "source-closure job {job_id} has an invalid production Runmill evidence envelope: {error}"
            ))
        })?;
        let payload_digest: String = required(row, "evidence_digest", "evidence bundle digest")?;
        let envelope_schema: String = required(row, "envelope_schema", "evidence envelope schema")?;
        let schema_version: String = required(row, "schema_version", "evidence predicate schema")?;
        let algorithm: String = required(row, "algorithm", "evidence signature algorithm")?;
        let key_id: String = required(row, "key_id", "evidence signing key")?;
        let signature: String = required(row, "signature", "evidence signature")?;
        let issued_at = evidence.issued_at.to_utc()?;
        let evidence_produced_at: chrono::DateTime<Utc> =
            required(row, "evidence_produced_at", "evidence production")?;
        if canonical_json(&evidence)? != exact_envelope
            || canonical_json(&evidence.statement)? != canonical_payload
            || sha256_digest(&canonical_payload) != payload_digest
            || serde_json::to_value(&evidence.statement)
                .map_err(|error| Error::Serialization(error.to_string()))?
                != payload_value
            || evidence.bundle_digest != payload_digest
            || evidence.schema != envelope_schema
            || evidence.statement.predicate.schema != schema_version
            || algorithm != "EdDSA"
            || evidence.key_id != key_id
            || evidence.signature != signature
            || issued_at != evidence_produced_at
        {
            return Err(Error::Persistence(format!(
                "source-closure job {job_id} production Runmill evidence contradicts its ledger projection"
            )));
        }
        reject_sensitive_fields(&payload_value)?;

        let verification_details: Value =
            required(row, "verification_details", "evidence verification receipt")?;
        let verification: EvidenceVerificationReceiptV1 =
            serde_json::from_value(verification_details.clone()).map_err(|_| {
                Error::Persistence(format!(
                    "source-closure job {job_id} has no exact evidence-verification receipt"
                ))
            })?;
        verification.validate()?;
        if serde_json::to_value(&verification)
            .map_err(|error| Error::Serialization(error.to_string()))?
            != verification_details
        {
            return Err(Error::Persistence(format!(
                "source-closure job {job_id} verification receipt is not its exact stored JSON"
            )));
        }
        let verification_job_id: Uuid =
            required(row, "verification_job_id", "verification workflow job")?;
        let verification_job_fence_token: i64 = required(
            row,
            "verification_job_fence_token",
            "verification workflow-job fence",
        )?;
        let verification_job_completed_by: String = required(
            row,
            "verification_job_completed_by",
            "verification workflow-job completer",
        )?;
        if verification.verification_job_id != verification_job_id
            || verification.verification_job_fence_token != verification_job_fence_token
            || verification.verification_job_completed_by != verification_job_completed_by
        {
            return Err(Error::Persistence(format!(
                "source-closure job {job_id} verification receipt contradicts its completed workflow-job claim"
            )));
        }

        let binding = Self {
            tenant_id: required(row, "tenant_id", "tenant")?,
            work_item_id: required(row, "work_item_id", "work item")?,
            work_item_version: required(row, "work_item_version", "work-item version")?,
            source_external_id: required(row, "source_external_id", "source external ID")?,
            source_snapshot_id: required(row, "source_snapshot_id", "source snapshot")?,
            source_revision: required(row, "source_revision", "source revision")?,
            source_snapshot_digest: required(
                row,
                "source_snapshot_digest",
                "source snapshot digest",
            )?,
            repository: required(row, "repository", "repository")?,
            policy_digest: required(row, "policy_digest", "policy digest")?,
            attempt_id: required(row, "attempt_id", "attempt")?,
            attempt_version: required(row, "attempt_version", "attempt version")?,
            attempt_fence_token: required(row, "attempt_fence_token", "attempt fence")?,
            attempt_base_ref: required(row, "attempt_base_ref", "attempt base ref")?,
            attempt_base_sha: required(row, "attempt_base_sha", "attempt base SHA")?,
            attempt_source_snapshot_digest: required(
                row,
                "attempt_source_snapshot_digest",
                "attempt source-snapshot digest",
            )?,
            attempt_policy_digest: required(row, "attempt_policy_digest", "attempt policy digest")?,
            work_order_id: required(row, "work_order_id", "work order")?,
            work_order_digest: required(row, "work_order_digest", "work-order digest")?,
            work_order_envelope_digest,
            work_order,
            workflow_id: required(row, "workflow_id", "workflow")?,
            workflow_version: required(row, "workflow_version", "workflow version")?,
            workflow_fence_token: required(row, "workflow_fence_token", "workflow fence")?,
            workflow_event_cursor: required(row, "workflow_event_cursor", "workflow cursor")?,
            anchor_generation: required(row, "anchor_generation", "anchor generation")?,
            run_id: required(row, "run_id", "run")?,
            external_run_id: required(row, "external_run_id", "external run")?,
            run_version: required(row, "run_version", "run version")?,
            run_terminal_at: required(row, "run_terminal_at", "run terminal time")?,
            expectation_digest: required(row, "expectation_digest", "evidence expectation")?,
            worker_id: required(row, "worker_id", "worker")?,
            worker_generation: required(row, "worker_generation", "worker generation")?,
            worker_status: required(row, "worker_status", "worker status")?,
            worker_session_id: required(row, "worker_session_id", "worker session")?,
            worker_session_signing_key_id: required(
                row,
                "worker_session_signing_key_id",
                "worker-session signing key",
            )?,
            worker_session_signing_public_key: required(
                row,
                "worker_session_signing_public_key",
                "worker-session signing public key",
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
                "worker-session close time",
            )?,
            evidence_worker_session_id: required(
                row,
                "evidence_worker_session_id",
                "evidence worker session",
            )?,
            evidence_id: required(row, "evidence_id", "evidence")?,
            evidence_digest: payload_digest,
            evidence_produced_at,
            evidence,
            verification_verifier: required(row, "verification_verifier", "evidence verifier")?,
            verification_verified_at: required(
                row,
                "verification_verified_at",
                "evidence verification time",
            )?,
            verification,
        };
        binding.validate_evidence(job_id)?;
        Ok(binding)
    }

    fn validate_evidence(&self, job_id: Uuid) -> Result<()> {
        u64::try_from(self.worker_generation).map_err(|_| {
            Error::Persistence(format!(
                "source-closure job {job_id} is bound to an invalid worker generation"
            ))
        })?;
        let predicate = &self.evidence.statement.predicate;
        let source = &predicate.source;
        let delivery = &predicate.delivery.pull_request;
        let work_order = &self.work_order.payload;
        let observation = &self.verification.pull_request;
        let required_ci = predicate
            .policy
            .required_ci_contexts
            .iter()
            .cloned()
            .collect();
        let completed_at = predicate.run.completed_at.to_utc()?;
        let delivery_observed_at = delivery.observed_at.to_utc()?;
        let latest_permitted = Utc::now()
            .checked_add_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| Error::Validation("evidence clock bound overflowed".into()))?;
        let verifying_key = decode_verifying_key(&self.worker_session_signing_public_key)?;
        let encoded_signature = self
            .evidence
            .signature
            .strip_prefix("base64url:")
            .ok_or_else(|| Error::Crypto("Runmill evidence signature prefix is invalid".into()))?;
        verify_signature(
            &verifying_key,
            &self.evidence.unsigned_canonical_bytes()?,
            encoded_signature,
        )?;
        let exact = predicate.run.run_id.as_str() == self.external_run_id
            && predicate.run.attempt_id.as_uuid() == self.attempt_id
            && predicate.run.work_order_id.as_uuid() == self.work_order_id
            && completed_at == self.run_terminal_at
            && predicate.work_order.envelope_digest == self.work_order_envelope_digest
            && predicate.work_order.payload_digest == self.work_order_digest
            && predicate.work_order.signature.key_id == self.work_order.key_id
            && self.evidence_worker_session_id == self.worker_session_id
            && self.evidence.key_id == self.worker_session_signing_key_id
            && self.worker_session_started_at <= self.evidence_produced_at
            && self.evidence_produced_at < self.worker_session_expires_at
            && self
                .worker_session_closed_at
                .is_none_or(|closed_at| self.evidence_produced_at <= closed_at)
            && predicate.work_order.signature.verified
            && predicate.policy.effective_policy_digest == self.policy_digest
            && self.attempt_source_snapshot_digest == self.source_snapshot_digest
            && self.attempt_policy_digest == self.policy_digest
            && self.worker_status != "QUARANTINED"
            && work_order.work_order_id == self.work_order_id.to_string()
            && work_order.tenant_id == self.tenant_id.to_string()
            && work_order.work_item_id == self.work_item_id.to_string()
            && work_order.attempt_id == self.attempt_id.to_string()
            && work_order.source.system == "linear"
            && work_order.source.external_id == self.source_external_id
            && work_order.source.snapshot_digest == self.source_snapshot_digest
            && work_order.policy_digest == predicate.policy.effective_policy_digest
            && work_order.verification.policy_snapshot_digest
                == predicate.policy.effective_policy_digest
            && work_order.verification.required_local_check_ids
                == predicate.policy.required_local_checks
            && work_order.verification.required_remote_checks
                == predicate.policy.required_ci_contexts
            && work_order.repository.forge == "github"
            && work_order.repository.repository == self.repository
            && work_order.repository.base_ref == self.attempt_base_ref
            && work_order.repository.base_sha == self.attempt_base_sha
            && matches!(
                work_order.delivery.closure_target,
                crate::contracts::RunmillWorkOrderClosureTarget::Pr
            )
            && source.forge == "github"
            && source.repository == self.repository
            && source.base_ref == self.attempt_base_ref
            && source.base_sha == self.attempt_base_sha
            && source.remote_head_sha == source.candidate_sha
            && source.merge_sha.is_none()
            && predicate.delivery.closure_target == RunmillClosureTarget::Pr
            && predicate.delivery.satisfied
            && predicate.cancellation.is_none()
            && predicate.budget.stop_reason == RunmillStopReason::PullRequestDelivered
            && delivery.forge == "github"
            && delivery.repository == self.repository
            && delivery.base_ref == self.attempt_base_ref
            && delivery.head_sha == source.candidate_sha
            && self.verification.evidence_id == EvidenceId::from_uuid(self.evidence_id)
            && self.verification.work_item_id == WorkItemId::from_uuid(self.work_item_id)
            && self.verification.attempt_id.as_uuid() == self.attempt_id
            && self.verification.run_id.as_uuid() == self.run_id
            && self.verification.evidence_digest == self.evidence_digest
            && self.verification.work_order_digest == self.work_order_digest
            && self.verification.expectation_digest == self.expectation_digest
            && self.verification.verifier == self.verification_verifier
            && observation.repository == self.repository
            && observation.number == delivery.number
            && observation.url == delivery.url
            && observation.base_sha == self.attempt_base_sha
            && observation.head_sha == source.candidate_sha
            && observation.required_ci_contexts == required_ci
            && observation
                .required_ci_contexts
                .is_subset(&observation.successful_ci_contexts)
            && completed_at <= self.evidence_produced_at
            && self.evidence_produced_at <= self.verification.observed_at
            && delivery_observed_at <= self.verification.observed_at
            && self.verification.observed_at
                <= self.verification_verified_at + Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS)
            && self.verification_verified_at <= latest_permitted;
        if exact {
            Ok(())
        } else {
            Err(Error::Validation(format!(
                "source-closure job {job_id} evidence contradicts its authoritative run, Work Order, or source binding"
            )))
        }
    }

    fn build_request(&self, requested_at: chrono::DateTime<Utc>) -> Result<CloseSourceRequest> {
        let pull_request = self.verification.pull_request.clone();
        let closure = SourceClosure {
            work_item_id: WorkItemId::from_uuid(self.work_item_id),
            target: ClosureTarget::PullRequest,
            pull_request: Some(pull_request.clone()),
            evidence_id: EvidenceId::from_uuid(self.evidence_id),
            evidence_digest: self.evidence_digest.clone(),
            final_outcome_summary: format!(
                "Verified pull request {}#{} at {}",
                pull_request.repository, pull_request.number, pull_request.head_sha
            ),
            cost_microunits: Some(usd_to_microunits(
                self.evidence.statement.predicate.budget.cost_usd,
            )?),
            wall_time_seconds: Some(
                self.evidence
                    .statement
                    .predicate
                    .budget
                    .elapsed_ms
                    .div_ceil(1_000),
            ),
        };
        let effect = SourceCloseEffect::new(
            SourceItemRef {
                tenant_id: TenantId::from_uuid(self.tenant_id),
                source: SourceSystem::Linear,
                external_id: self.source_external_id.clone(),
            },
            self.source_revision.clone(),
            self.source_snapshot_digest.clone(),
            stable_source_close_correlation(self.work_item_id, self.evidence_id),
            closure,
        )
        .map_err(|error| source_contract_error(&error))?;
        CloseSourceRequest::new(
            stable_source_close_idempotency(self.work_item_id, self.evidence_id),
            effect,
            requested_at,
        )
        .map_err(|error| source_contract_error(&error))
    }

    fn validate_request(&self, request: &CloseSourceRequest) -> Result<()> {
        request
            .validate()
            .map_err(|error| source_contract_error(&error))?;
        let expected = self.build_request(request.requested_at)?;
        let latest_permitted = Utc::now()
            .checked_add_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| Error::Validation("source-close clock bound overflowed".into()))?;
        if request != &expected
            || request.requested_at < self.evidence_produced_at
            || request.requested_at < self.verification_verified_at
            || request.requested_at > latest_permitted
        {
            return Err(Error::Conflict(format!(
                "persisted Linear source-close request for work item {} contradicts its immutable source/evidence binding",
                self.work_item_id
            )));
        }
        reject_sensitive_fields(
            &serde_json::to_value(request)
                .map_err(|error| Error::Serialization(error.to_string()))?,
        )
    }
}

#[derive(Debug)]
struct PreparedClosure {
    binding: SourceClosureBinding,
    request: CloseSourceRequest,
    request_digest: String,
    effect_id: Uuid,
    action: ExternalAction,
}

#[derive(Debug)]
enum ExternalAction {
    Close,
    Reconcile,
    FinalizeObserved(SourceCloseReceipt),
}

impl ExternalAction {
    const fn remote_outcome_may_need_reconciliation(&self) -> bool {
        matches!(self, Self::Close | Self::Reconcile)
    }
}

async fn lock_exact_job_claim(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
) -> Result<()> {
    let locked = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM workflow_jobs
        WHERE tenant_id = $1
          AND id = $2
          AND workflow_instance_id = $3
          AND work_item_id = $4
          AND attempt_id = $5
          AND job_type = 'CLOSE_SOURCE'
          AND activity_contract_id = $8
          AND status = 'RUNNING'
          AND lease_owner = $6
          AND fence_token = $7
          AND lease_expires_at > clock_timestamp()
        FOR UPDATE
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(job.workflow_instance_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .bind(CLOSE_SOURCE_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!("lock exact Linear source-close job claim: {error}"))
    })?;
    if locked == Some(job.id) {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "source-closure job {} no longer owns its live workflow-job claim",
            job.id
        )))
    }
}

async fn lock_claim_and_binding(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &SourceClosureJobPayload,
) -> Result<SourceClosureBinding> {
    // Global recovery order: job first, then workflow/work/attempt/run and
    // immutable source/evidence records, then the effect intent.
    lock_exact_job_claim(transaction, job).await?;
    let worker_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT evidence.worker_id
        FROM evidence_bundles AS evidence
        WHERE evidence.tenant_id = $1
          AND evidence.id = $2
          AND evidence.work_item_id = $3
          AND evidence.attempt_id = $4
          AND evidence.run_id = $5
          AND evidence.payload_digest = $6
          AND evidence.work_order_digest = $7
        ",
    )
    .bind(job.tenant_id)
    .bind(payload.evidence_id)
    .bind(payload.work_item_id)
    .bind(job.attempt_id)
    .bind(payload.run_id)
    .bind(&payload.payload_digest)
    .bind(&payload.work_order_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "locate immutable source-close worker authority: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "source-closure job {} has no exact immutable evidence worker",
            job.id
        ))
    })?;
    lock_attempt_reservation_release_authority(
        transaction,
        job.tenant_id,
        payload.work_item_id,
        worker_id,
    )
    .await?;
    let row = sqlx::query(
        r"
        SELECT
            work.tenant_id,
            work.id AS work_item_id,
            work.aggregate_version AS work_item_version,
            work.source_external_id,
            work.policy_digest,
            snapshot.id AS source_snapshot_id,
            snapshot.source_revision,
            snapshot.content_digest AS source_snapshot_digest,
            repository.owner || '/' || repository.name AS repository,
            attempt.id AS attempt_id,
            attempt.aggregate_version AS attempt_version,
            attempt.fence_token AS attempt_fence_token,
            attempt.base_ref AS attempt_base_ref,
            attempt.base_sha AS attempt_base_sha,
            attempt.source_snapshot_digest AS attempt_source_snapshot_digest,
            attempt.policy_digest AS attempt_policy_digest,
            attempt.work_order_digest,
            work_order.id AS work_order_id,
            work_order.exact_signed_envelope AS work_order_exact_envelope,
            workflow.id AS workflow_id,
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence_token,
            workflow.event_cursor AS workflow_event_cursor,
            COALESCE(anchor.generation, 0) AS anchor_generation,
            run.id AS run_id,
            run.external_run_id,
            run.aggregate_version AS run_version,
            run.terminal_at AS run_terminal_at,
            run.evidence_expectation_digest AS expectation_digest,
            run.worker_id,
            run.worker_generation,
            run.worker_session_id,
            worker.status AS worker_status,
            worker_session.signing_key_id AS worker_session_signing_key_id,
            worker_session.signing_public_key AS worker_session_signing_public_key,
            worker_session.started_at AS worker_session_started_at,
            worker_session.expires_at AS worker_session_expires_at,
            worker_session.closed_at AS worker_session_closed_at,
            evidence.id AS evidence_id,
            evidence.worker_session_id AS evidence_worker_session_id,
            evidence.payload_digest AS evidence_digest,
            evidence.schema_version,
            evidence.canonical_payload,
            evidence.payload AS evidence_payload,
            evidence.envelope_schema,
            evidence.algorithm,
            evidence.key_id,
            evidence.signature,
            evidence.exact_signed_envelope,
            evidence.produced_at AS evidence_produced_at,
            verification.verifier AS verification_verifier,
            verification.details AS verification_details,
            verification.verified_at AS verification_verified_at,
            verification.workflow_job_id AS verification_job_id,
            verification.workflow_job_fence_token AS verification_job_fence_token,
            verification.workflow_job_completed_by AS verification_job_completed_by
        FROM workflow_jobs AS job
        JOIN work_items AS work
          ON work.tenant_id = job.tenant_id
         AND work.id = job.work_item_id
         AND work.id = $7
         AND work.aggregate_version = $8
         AND work.current_attempt_id = job.attempt_id
         AND work.source_system = 'LINEAR'
         AND work.closure_target = 'pull_request'
         AND work.state = 'CLOSING_SOURCE'
        JOIN source_snapshots AS snapshot
          ON snapshot.tenant_id = work.tenant_id
         AND snapshot.id = work.source_snapshot_id
         AND snapshot.repository_id = work.repository_id
         AND snapshot.source_system = 'LINEAR'
         AND snapshot.external_id = work.source_external_id
        JOIN repositories AS repository
          ON repository.tenant_id = work.tenant_id
         AND repository.id = work.repository_id
        JOIN attempts AS attempt
          ON attempt.tenant_id = work.tenant_id
         AND attempt.id = work.current_attempt_id
         AND attempt.work_item_id = work.id
         AND attempt.state = 'SUCCEEDED'
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = job.tenant_id
         AND workflow.id = job.workflow_instance_id
         AND workflow.work_item_id = work.id
         AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
         AND workflow.state = 'ACTIVE'
        JOIN runs AS run
          ON run.tenant_id = work.tenant_id
         AND run.id = $10
         AND run.work_item_id = work.id
         AND run.attempt_id = attempt.id
         AND run.authoritative
         AND run.state = 'SUCCEEDED'
         AND run.terminal_at IS NOT NULL
         AND run.evidence_expectation_digest = $13
        JOIN workers AS worker
          ON worker.tenant_id = run.tenant_id
         AND worker.id = run.worker_id
         AND worker.status <> 'QUARANTINED'
        JOIN work_orders AS work_order
          ON work_order.tenant_id = run.tenant_id
         AND work_order.id = run.work_order_id
         AND work_order.work_item_id = work.id
         AND work_order.attempt_id = attempt.id
         AND work_order.payload_digest = attempt.work_order_digest
         AND work_order.payload_digest = $12
        JOIN worker_sessions AS worker_session
          ON worker_session.tenant_id = run.tenant_id
         AND worker_session.id = run.worker_session_id
         AND worker_session.worker_id = run.worker_id
         AND worker_session.worker_generation = run.worker_generation
        JOIN evidence_bundles AS evidence
          ON evidence.tenant_id = work.tenant_id
         AND evidence.id = $9
         AND evidence.work_item_id = work.id
         AND evidence.attempt_id = attempt.id
         AND evidence.run_id = run.id
         AND evidence.worker_id = run.worker_id
         AND evidence.worker_generation = run.worker_generation
         AND evidence.worker_session_id = run.worker_session_id
         AND evidence.key_id = worker_session.signing_key_id
         AND evidence.payload_digest = $11
         AND evidence.work_order_digest = work_order.payload_digest
         AND evidence.base_sha = attempt.base_sha
         AND evidence.requested_target = work.closure_target
         AND evidence.target_satisfied
        JOIN evidence_verifications AS verification
         ON verification.tenant_id = evidence.tenant_id
         AND verification.evidence_id = evidence.id
         AND verification.work_item_id = work.id
         AND verification.attempt_id = attempt.id
         AND verification.run_id = run.id
         AND verification.evidence_digest = evidence.payload_digest
         AND verification.work_order_digest = work_order.payload_digest
         AND verification.expectation_digest = run.evidence_expectation_digest
         AND verification.status = 'VALID'
        LEFT JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
        WHERE job.tenant_id = $1
          AND job.id = $2
          AND job.workflow_instance_id = $3
          AND job.work_item_id = $4
          AND job.attempt_id = $5
          AND job.job_type = 'CLOSE_SOURCE'
          AND job.activity_contract_id = $15
          AND job.status = 'RUNNING'
          AND job.lease_owner = $6
          AND job.fence_token = $14
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
              FROM effect_intents AS cancellation_effect
              WHERE cancellation_effect.tenant_id = work.tenant_id
                AND cancellation_effect.work_item_id = work.id
                AND cancellation_effect.attempt_id = attempt.id
                AND cancellation_effect.provider = 'runmill'
                AND cancellation_effect.effect_type = 'request_cancellation'
                AND cancellation_effect.status <> 'CANCELLED'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_jobs AS cancellation_job
              WHERE cancellation_job.tenant_id = work.tenant_id
                AND cancellation_job.work_item_id = work.id
                AND cancellation_job.attempt_id = attempt.id
                AND cancellation_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                AND cancellation_job.status IN ('PENDING', 'RUNNING', 'RETRY')
          )
          AND NOT EXISTS (
              SELECT 1
              FROM approvals AS approval
              WHERE approval.tenant_id = work.tenant_id
                AND approval.work_item_id = work.id
                AND approval.attempt_id = attempt.id
                AND approval.status <> 'APPROVED'
          )
        FOR UPDATE OF work, attempt, workflow, run, worker
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(job.workflow_instance_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(&job.lease_owner)
    .bind(payload.work_item_id)
    .bind(payload.expected_work_item_version)
    .bind(payload.evidence_id)
    .bind(payload.run_id)
    .bind(&payload.payload_digest)
    .bind(&payload.work_order_digest)
    .bind(&payload.expectation_digest)
    .bind(job.fence_token)
    .bind(CLOSE_SOURCE_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "lock authoritative Linear source-close binding: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "source-closure job {} has no exact current independently-valid delivery evidence",
            job.id
        ))
    })?;
    SourceClosureBinding::from_row(&row, job.id)
}

async fn persist_or_adopt_effect(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &SourceClosureBinding,
    proposed_request: CloseSourceRequest,
    effect_id: Uuid,
) -> Result<(CloseSourceRequest, String, ExternalAction)> {
    binding.validate_request(&proposed_request)?;
    let proposed_payload = serde_json::to_value(&proposed_request)
        .map_err(|error| Error::Serialization(error.to_string()))?;
    let proposed_digest = sha256_digest(&canonical_json(&proposed_request)?);
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            status, idempotency_key, correlation_marker, request_digest,
            request_payload, attempt_count, next_attempt_at, fence_token,
            lease_owner, lease_expires_at, owning_workflow_job_id,
            source_snapshot_id, source_revision, source_snapshot_digest,
            evidence_id, evidence_digest
        ) VALUES (
            $1, $2, $3, $4, 'linear', 'close_source', 'IN_FLIGHT',
            $5, $6, $7, $8, 1, clock_timestamp(), $9, $10, $11, $12,
            $13, $14, $15, $16, $17
        )
        ON CONFLICT DO NOTHING
        RETURNING id
        ",
    )
    .bind(effect_id)
    .bind(binding.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(&proposed_request.idempotency_key)
    .bind(&proposed_request.effect.correlation_marker)
    .bind(&proposed_digest)
    .bind(&proposed_payload)
    .bind(job.fence_token)
    .bind(&job.lease_owner)
    .bind(job.lease_expires_at)
    .bind(job.id)
    .bind(binding.source_snapshot_id)
    .bind(&binding.source_revision)
    .bind(&binding.source_snapshot_digest)
    .bind(binding.evidence_id)
    .bind(&binding.evidence_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("persist Linear source-close effect: {error}")))?;
    if inserted == Some(effect_id) {
        return Ok((proposed_request, proposed_digest, ExternalAction::Close));
    }

    let row = lock_effect(transaction, binding).await?.ok_or_else(|| {
        Error::Conflict(format!(
            "Linear source-close effect {} conflicts with another durable identity",
            binding.work_item_id
        ))
    })?;
    let stored = decode_and_validate_effect(&row, binding, effect_id)?;
    match stored.status.as_str() {
        "AMBIGUOUS" => Ok((
            stored.request,
            stored.request_digest,
            ExternalAction::Reconcile,
        )),
        "OBSERVED" => {
            let receipt = stored.receipt.ok_or_else(|| {
                Error::Persistence(format!(
                    "observed Linear source-close effect {effect_id} has no receipt"
                ))
            })?;
            validate_receipt(&stored.request, &receipt, false)?;
            Ok((
                stored.request,
                stored.request_digest,
                ExternalAction::FinalizeObserved(receipt),
            ))
        }
        "PENDING" | "FAILED" => {
            let adopted = sqlx::query_scalar::<_, Uuid>(
                r"
                UPDATE effect_intents
                SET status = 'IN_FLIGHT',
                    observed_outcome = NULL,
                    observed_at = NULL,
                    attempt_count = attempt_count + 1,
                    next_attempt_at = clock_timestamp(),
                    fence_token = $7,
                    lease_owner = $8,
                    lease_expires_at = $9,
                    owning_workflow_job_id = $10,
                    last_error = NULL,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1
                  AND id = $2
                  AND work_item_id = $3
                  AND attempt_id = $4
                  AND provider = 'linear'
                  AND effect_type = 'close_source'
                  AND status IN ('PENDING', 'FAILED')
                  AND request_digest = $5
                  AND request_payload = $6
                  AND owning_workflow_job_id IS NULL
                RETURNING id
                ",
            )
            .bind(binding.tenant_id)
            .bind(effect_id)
            .bind(binding.work_item_id)
            .bind(binding.attempt_id)
            .bind(&stored.request_digest)
            .bind(
                serde_json::to_value(&stored.request)
                    .map_err(|error| Error::Serialization(error.to_string()))?,
            )
            .bind(job.fence_token)
            .bind(&job.lease_owner)
            .bind(job.lease_expires_at)
            .bind(job.id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| {
                Error::Persistence(format!("adopt failed Linear source-close effect: {error}"))
            })?;
            if adopted == Some(effect_id) {
                Ok((stored.request, stored.request_digest, ExternalAction::Close))
            } else {
                Err(Error::Conflict(format!(
                    "Linear source-close effect {effect_id} changed while it was adopted"
                )))
            }
        }
        "IN_FLIGHT" => {
            let owner_job: Option<Uuid> = optional(&row, "owning_workflow_job_id", "effect owner")?;
            let owner: Option<String> = optional(&row, "lease_owner", "effect lease owner")?;
            let fence: i64 = required(&row, "fence_token", "effect fence")?;
            if owner_job == Some(job.id)
                && owner.as_deref() == Some(job.lease_owner.as_str())
                && fence == job.fence_token
            {
                Ok((stored.request, stored.request_digest, ExternalAction::Close))
            } else {
                Err(Error::Conflict(format!(
                    "Linear source-close effect {effect_id} has another live owner"
                )))
            }
        }
        status => Err(Error::Conflict(format!(
            "Linear source-close effect {effect_id} is {status} and cannot be executed"
        ))),
    }
}

async fn lock_effect(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &SourceClosureBinding,
) -> Result<Option<PgRow>> {
    sqlx::query(
        r"
        SELECT
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            status, idempotency_key, correlation_marker, request_digest,
            request_payload, observed_outcome, fence_token, lease_owner,
            lease_expires_at, owning_workflow_job_id, source_snapshot_id,
            source_revision, source_snapshot_digest, evidence_id, evidence_digest
        FROM effect_intents
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND provider = 'linear'
          AND effect_type = 'close_source'
        FOR UPDATE
        ",
    )
    .bind(binding.tenant_id)
    .bind(binding.work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("lock Linear source-close effect: {error}")))
}

#[derive(Debug)]
struct StoredEffect {
    status: String,
    request: CloseSourceRequest,
    request_digest: String,
    receipt: Option<SourceCloseReceipt>,
}

fn decode_and_validate_effect(
    row: &PgRow,
    binding: &SourceClosureBinding,
    effect_id: Uuid,
) -> Result<StoredEffect> {
    let row_id: Uuid = required(row, "id", "source-close effect ID")?;
    let tenant_id: Uuid = required(row, "tenant_id", "source-close effect tenant")?;
    let work_item_id: Option<Uuid> =
        optional(row, "work_item_id", "source-close effect work item")?;
    let attempt_id: Option<Uuid> = optional(row, "attempt_id", "source-close effect attempt")?;
    let provider: String = required(row, "provider", "source-close provider")?;
    let effect_type: String = required(row, "effect_type", "source-close effect type")?;
    let idempotency_key: String = required(row, "idempotency_key", "source-close idempotency")?;
    let correlation_marker: Option<String> =
        optional(row, "correlation_marker", "source-close correlation")?;
    let request_digest: String = required(row, "request_digest", "source-close request digest")?;
    let request_payload: Value = required(row, "request_payload", "source-close request payload")?;
    let request: CloseSourceRequest =
        serde_json::from_value(request_payload.clone()).map_err(|_| {
            Error::Persistence(format!(
                "Linear source-close effect {effect_id} has an incompatible request"
            ))
        })?;
    binding.validate_request(&request)?;
    let reproduced_digest = sha256_digest(&canonical_json(&request)?);
    let source_snapshot_id: Option<Uuid> = optional(
        row,
        "source_snapshot_id",
        "source-close effect source snapshot",
    )?;
    let source_revision: Option<String> = optional(
        row,
        "source_revision",
        "source-close effect source revision",
    )?;
    let snapshot_digest: Option<String> = optional(
        row,
        "source_snapshot_digest",
        "source-close effect source digest",
    )?;
    let evidence_id: Option<Uuid> = optional(row, "evidence_id", "source-close effect evidence")?;
    let evidence_digest: Option<String> = optional(
        row,
        "evidence_digest",
        "source-close effect evidence digest",
    )?;
    let exact = row_id == effect_id
        && tenant_id == binding.tenant_id
        && work_item_id == Some(binding.work_item_id)
        && attempt_id == Some(binding.attempt_id)
        && provider == "linear"
        && effect_type == "close_source"
        && idempotency_key == request.idempotency_key
        && correlation_marker.as_deref() == Some(request.effect.correlation_marker.as_str())
        && request_digest == reproduced_digest
        && serde_json::to_value(&request)
            .map_err(|error| Error::Serialization(error.to_string()))?
            == request_payload
        && source_snapshot_id == Some(binding.source_snapshot_id)
        && source_revision.as_deref() == Some(binding.source_revision.as_str())
        && snapshot_digest.as_deref() == Some(binding.source_snapshot_digest.as_str())
        && evidence_id == Some(binding.evidence_id)
        && evidence_digest.as_deref() == Some(binding.evidence_digest.as_str());
    if !exact {
        return Err(Error::Conflict(format!(
            "Linear source-close effect {effect_id} contradicts its immutable source/evidence binding"
        )));
    }
    reject_sensitive_fields(&request_payload)?;
    let status: String = required(row, "status", "source-close effect status")?;
    let observed: Option<Value> =
        optional(row, "observed_outcome", "source-close observed outcome")?;
    if let Some(value) = &observed {
        reject_sensitive_fields(value)?;
    }
    // AMBIGUOUS and FAILED outcomes are durable diagnostic facts, not provider
    // receipts. Only an OBSERVED intent is allowed to supply a receipt for
    // idempotent local finalization.
    let receipt = if status == "OBSERVED" {
        observed
            .map(|value| {
                serde_json::from_value(value).map_err(|_| {
                    Error::Persistence(format!(
                        "Linear source-close effect {effect_id} has an incompatible observed receipt"
                    ))
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok(StoredEffect {
        status,
        request,
        request_digest,
        receipt,
    })
}

async fn update_owned_effect_failure(
    pool: &sqlx::PgPool,
    job: &ClaimedWorkflowJob,
    prepared: &PreparedClosure,
    error: &str,
    ambiguous: bool,
) -> Result<()> {
    let status = if ambiguous { "AMBIGUOUS" } else { "FAILED" };
    let request_payload = serde_json::to_value(&prepared.request)
        .map_err(|error| Error::Serialization(error.to_string()))?;
    let outcome = json!({
        "schema": "asf.source-close-effect-outcome.v1",
        "status": status.to_ascii_lowercase(),
        "request_digest": prepared.request_digest,
        "effect_digest": prepared.request.effect_digest,
    });
    let changed = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = $7,
            observed_outcome = $8,
            observed_at = NULL,
            owning_workflow_job_id = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL,
            last_error = $9,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND provider = 'linear'
          AND effect_type = 'close_source'
          AND request_digest = $5
          AND request_payload = $6
          AND status = 'IN_FLIGHT'
          AND owning_workflow_job_id = $10
          AND lease_owner = $11
          AND fence_token = $12
        ",
    )
    .bind(job.tenant_id)
    .bind(prepared.effect_id)
    .bind(prepared.binding.work_item_id)
    .bind(prepared.binding.attempt_id)
    .bind(&prepared.request_digest)
    .bind(request_payload)
    .bind(status)
    .bind(outcome)
    .bind(summarize_error(error))
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .execute(pool)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "record Linear source-close effect failure: {error}"
        ))
    })?
    .rows_affected();
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "Linear source-close effect {} lost its exact job fence",
            prepared.effect_id
        )))
    }
}

async fn observe_exact_effect(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &SourceClosureBinding,
    prepared: &PreparedClosure,
    receipt: &SourceCloseReceipt,
) -> Result<()> {
    let row = lock_effect(transaction, binding).await?.ok_or_else(|| {
        Error::Conflict(format!(
            "Linear source-close effect {} disappeared",
            prepared.effect_id
        ))
    })?;
    let stored = decode_and_validate_effect(&row, binding, prepared.effect_id)?;
    if stored.request != prepared.request || stored.request_digest != prepared.request_digest {
        return Err(Error::Conflict(format!(
            "Linear source-close effect {} changed before receipt persistence",
            prepared.effect_id
        )));
    }
    let receipt_value =
        serde_json::to_value(receipt).map_err(|error| Error::Serialization(error.to_string()))?;
    match (&prepared.action, stored.status.as_str()) {
        (ExternalAction::Close, "IN_FLIGHT") => {
            let owner_job: Option<Uuid> = optional(&row, "owning_workflow_job_id", "effect owner")?;
            let owner: Option<String> = optional(&row, "lease_owner", "effect owner text")?;
            let fence: i64 = required(&row, "fence_token", "effect fence")?;
            if owner_job != Some(job.id)
                || owner.as_deref() != Some(job.lease_owner.as_str())
                || fence != job.fence_token
            {
                return Err(Error::Conflict(format!(
                    "Linear source-close effect {} lost its exact owner",
                    prepared.effect_id
                )));
            }
        }
        (ExternalAction::Reconcile, "AMBIGUOUS") => {}
        (ExternalAction::FinalizeObserved(_), "OBSERVED") => {
            if stored.receipt.as_ref() == Some(receipt) {
                return Ok(());
            }
            return Err(Error::Conflict(format!(
                "observed Linear source-close effect {} has a contradictory receipt",
                prepared.effect_id
            )));
        }
        (_, status) => {
            return Err(Error::Conflict(format!(
                "Linear source-close effect {} is unexpectedly {status}",
                prepared.effect_id
            )));
        }
    }

    let changed = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'OBSERVED',
            observed_outcome = $7,
            observed_at = clock_timestamp(),
            observing_workflow_job_id = $9,
            observing_workflow_job_fence_token = $11,
            observing_workflow_job_completed_by = $10,
            owning_workflow_job_id = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL,
            last_error = NULL,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND provider = 'linear'
          AND effect_type = 'close_source'
          AND request_digest = $5
          AND request_payload = $6
          AND status = $8
          AND (
              ($8 = 'AMBIGUOUS' AND owning_workflow_job_id IS NULL AND lease_owner IS NULL)
              OR (
                  $8 = 'IN_FLIGHT'
                  AND owning_workflow_job_id = $9
                  AND lease_owner = $10
                  AND fence_token = $11
              )
          )
        ",
    )
    .bind(binding.tenant_id)
    .bind(prepared.effect_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(&prepared.request_digest)
    .bind(
        serde_json::to_value(&prepared.request)
            .map_err(|error| Error::Serialization(error.to_string()))?,
    )
    .bind(receipt_value)
    .bind(stored.status)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("observe Linear source-close effect: {error}")))?
    .rows_affected();
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "Linear source-close effect {} lost its finalization fence",
            prepared.effect_id
        )))
    }
}

async fn commit_closed_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &SourceClosureBinding,
    prepared: &PreparedClosure,
    receipt: &SourceCloseReceipt,
) -> Result<()> {
    let now = Utc::now();
    let receipt_digest = sha256_digest(&canonical_json(receipt)?);
    let released_reservations = release_active_attempt_reservations(
        transaction,
        binding.tenant_id,
        binding.work_item_id,
        binding.attempt_id,
        binding.worker_id,
        AttemptReservationReleaseNamespace::WorkClosure,
        &job.lease_owner,
        "verified source closure completed the authoritative attempt",
    )
    .await?;
    let next_cursor = binding
        .workflow_event_cursor
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("source-closure workflow cursor overflowed".into()))?;
    let result = json!({
        "schema": SOURCE_CLOSE_RESULT_SCHEMA_V1,
        "work_item_id": binding.work_item_id,
        "attempt_id": binding.attempt_id,
        "run_id": binding.run_id,
        "evidence_id": binding.evidence_id,
        "evidence_digest": binding.evidence_digest,
        "source_snapshot_id": binding.source_snapshot_id,
        "source_revision": binding.source_revision,
        "source_snapshot_digest": binding.source_snapshot_digest,
        "request_digest": prepared.request_digest,
        "effect_digest": prepared.request.effect_digest,
        "receipt_digest": receipt_digest,
        "provider_revision": receipt.provider_revision,
        "disposition": receipt.disposition,
        "released_reservations": released_reservations,
    });
    let commit_digest = sha256_digest(&canonical_json(&json!({
        "job_id": job.id,
        "job_fence_token": job.fence_token,
        "work_item_version": binding.work_item_version,
        "workflow_version": binding.workflow_version,
        "workflow_fence_token": binding.workflow_fence_token,
        "workflow_event_cursor": next_cursor,
        "result": result,
        "work_item_state": "CLOSED",
        "workflow_state": "COMPLETED",
        "closure_evidence_id": binding.evidence_id,
    }))?);
    let commit = WorkflowStepCommit {
        fence: WorkflowStepFence {
            tenant_id: binding.tenant_id,
            job_id: job.id,
            workflow_instance_id: binding.workflow_id,
            work_item_id: binding.work_item_id,
            lease_owner: job.lease_owner.clone(),
            job_fence_token: job.fence_token,
            expected_work_item_version: binding.work_item_version,
            expected_workflow_version: binding.workflow_version,
            expected_workflow_fence_token: binding.workflow_fence_token,
            expected_anchor_generation: binding.anchor_generation,
        },
        commit_digest,
        job_result: Some(result),
        work_item_state: "CLOSED".into(),
        workflow_state: "COMPLETED".into(),
        workflow_event_cursor: next_cursor,
        accountability: AccountabilityReplacement {
            kind: LedgerAccountabilityKind::Closure,
            reference_id: binding.evidence_id,
            wake_or_deadline_at: None,
            authority_or_effect_active: false,
        },
        jobs: Vec::new(),
        timers: Vec::new(),
        effects: Vec::new(),
        outbox: vec![StepOutboxMessage {
            id: derived_uuid(prepared.effect_id, 2),
            topic: "work-items".into(),
            message_key: binding.work_item_id.to_string(),
            event_type: "work_item.closed".into(),
            payload: json!({
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "run_id": binding.run_id,
                "evidence_id": binding.evidence_id,
                "evidence_digest": binding.evidence_digest,
                "source_system": "LINEAR",
                "source_external_id": binding.source_external_id,
                "source_revision": binding.source_revision,
                "effect_id": prepared.effect_id,
                "effect_digest": prepared.request.effect_digest,
                "receipt_digest": receipt_digest,
                "provider_revision": receipt.provider_revision,
                "released_reservations": released_reservations,
            }),
            headers: json!({"schema": "asf.work-item-event/v1"}),
            idempotency_key: format!("source-close:{}:outbox", prepared.effect_id),
            available_at: now,
        }],
        audit_events: vec![StepAuditEvent {
            id: derived_uuid(prepared.effect_id, 1),
            attempt_id: Some(binding.attempt_id),
            actor_type: "SERVICE".into(),
            actor_id: job.lease_owner.clone(),
            action: "SOURCE_CLOSED".into(),
            subject_type: "SOURCE_ITEM".into(),
            subject_id: binding.source_external_id.clone(),
            correlation_id: prepared.request.effect.correlation_marker.clone(),
            trace_id: None,
            policy_digest: Some(binding.policy_digest.clone()),
            before_digest: Some(prepared.request_digest.clone()),
            after_digest: Some(receipt_digest),
            details: json!({
                "schema": SOURCE_CLOSE_AUDIT_SCHEMA_V1,
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "run_id": binding.run_id,
                "evidence_id": binding.evidence_id,
                "evidence_digest": binding.evidence_digest,
                "source_snapshot_id": binding.source_snapshot_id,
                "source_revision": binding.source_revision,
                "source_snapshot_digest": binding.source_snapshot_digest,
                "effect_id": prepared.effect_id,
                "idempotency_key": prepared.request.idempotency_key,
                "request_digest": prepared.request_digest,
                "effect_digest": prepared.request.effect_digest,
                "receipt": receipt,
                "released_reservations": released_reservations,
            }),
            occurred_at: now,
        }],
    };
    match commit_workflow_step_with_prelocked_claim(transaction, &commit).await? {
        WorkflowStepCommitOutcome::Applied { .. } | WorkflowStepCommitOutcome::AlreadyApplied => {
            Ok(())
        }
    }
}

fn validate_receipt(
    request: &CloseSourceRequest,
    receipt: &SourceCloseReceipt,
    reconciliation: bool,
) -> Result<()> {
    let disposition_valid = if reconciliation {
        receipt.disposition == SourceCloseDisposition::Reconciled
    } else {
        matches!(
            receipt.disposition,
            SourceCloseDisposition::Applied
                | SourceCloseDisposition::Adopted
                | SourceCloseDisposition::Reconciled
        )
    };
    let latest_permitted = Utc::now()
        .checked_add_signed(Duration::seconds(PROVIDER_CLOCK_SKEW_SECONDS))
        .ok_or_else(|| Error::Validation("source-close receipt clock bound overflowed".into()))?;
    let exact = receipt.schema == SOURCE_CLOSE_RECEIPT_SCHEMA_V1
        && receipt.item == request.effect.item
        && receipt.idempotency_key == request.idempotency_key
        && receipt.effect_digest == request.effect_digest
        && receipt.correlation_marker == request.effect.correlation_marker
        && disposition_valid
        && !receipt.provider_revision.trim().is_empty()
        && receipt.provider_revision.trim() == receipt.provider_revision
        && receipt.recorded_at >= request.requested_at
        && receipt.recorded_at <= latest_permitted;
    if !exact {
        return Err(Error::ExternalUnavailable(
            "Linear source-close receipt contradicts the immutable request".into(),
        ));
    }
    reject_sensitive_fields(
        &serde_json::to_value(receipt).map_err(|error| Error::Serialization(error.to_string()))?,
    )
}

fn mutation_error_is_ambiguous(error: &SourceGatewayError) -> bool {
    // The port uses AmbiguousEffect only after a mutation may have crossed the
    // provider boundary. Ordinary transport/response errors can occur during
    // the adapter's pre-mutation read and remain safely retryable.
    matches!(error, SourceGatewayError::AmbiguousEffect { .. })
}

fn map_source_error(error: &SourceGatewayError) -> Error {
    Error::ExternalUnavailable(format!("Linear source closure failed: {error}"))
}

fn source_contract_error(error: &SourceGatewayError) -> Error {
    Error::Validation(format!("invalid Linear source-close contract: {error}"))
}

fn usd_to_microunits(cost_usd: f64) -> Result<u64> {
    if !cost_usd.is_finite() || cost_usd.is_sign_negative() {
        return Err(Error::Validation(
            "Runmill source-close cost is not a finite nonnegative amount".into(),
        ));
    }
    let scaled = cost_usd * 1_000_000.0;
    let rounded = scaled.round();
    if !scaled.is_finite()
        || rounded > 9_007_199_254_740_991.0
        || (scaled - rounded).abs() > 0.000_001
    {
        return Err(Error::Validation(
            "Runmill source-close cost cannot be represented exactly in integer microunits".into(),
        ));
    }
    format!("{rounded:.0}").parse::<u64>().map_err(|_| {
        Error::Validation("Runmill source-close cost exceeds the microunit range".into())
    })
}

fn stable_source_close_idempotency(work_item_id: Uuid, evidence_id: Uuid) -> String {
    format!("source-close:{work_item_id}:{evidence_id}")
}

fn stable_source_close_correlation(work_item_id: Uuid, evidence_id: Uuid) -> String {
    format!("asf-close:{work_item_id}:{evidence_id}")
}

fn stable_source_close_effect_id(evidence_id: Uuid) -> Uuid {
    derived_uuid(evidence_id, 19)
}

fn derived_uuid(base: Uuid, discriminator: u8) -> Uuid {
    let mut bytes = *base.as_bytes();
    bytes[15] ^= discriminator;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn summarize_error(error: &str) -> String {
    error.chars().take(8_192).collect()
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
        .map_err(|error| Error::Persistence(format!("decode {label}: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use chrono::{Duration, Utc};
    use tokio::sync::Mutex;
    use url::Url;

    use super::*;
    use crate::{
        contracts::{
            EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1, RunmillArtifactKind, RunmillEvidenceAlgorithm,
            RunmillEvidenceTimestamp, RunmillExternalRunId, RunmillRetentionClass,
        },
        crypto::{Ed25519Signer, encode_verifying_key},
        domain::{AttemptId, RunId, WorkOrderId},
        ports::{
            ObserveSourceRequest, SourceIntakePage, SourceIntakeRequest, SourceObservation,
            SourceResult,
        },
        runtime::VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID,
    };

    struct ScopedDatabase {
        ledger: PgLedger,
        admin: sqlx::PgPool,
        schema: String,
    }

    impl ScopedDatabase {
        async fn create(database_url: &str) -> Self {
            let admin = sqlx::PgPool::connect(database_url)
                .await
                .expect("connect source-close test administrator");
            let schema = format!("asf_source_close_{}", Uuid::now_v7().simple());
            assert!(
                schema
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            );
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated source-close schema");
            let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated source-close ledger");
            ledger
                .migrate()
                .await
                .expect("migrate isolated source-close schema");
            Self {
                ledger,
                admin,
                schema,
            }
        }

        async fn cleanup(self) {
            self.ledger.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .expect("drop isolated source-close schema");
            self.admin.close().await;
        }

        async fn create_through_0010(database_url: &str) -> Self {
            let admin = sqlx::PgPool::connect(database_url)
                .await
                .expect("connect source-close upgrade-test administrator");
            let schema = format!("asf_source_upgrade_{}", Uuid::now_v7().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated source-close upgrade schema");
            let mut scoped_url = Url::parse(database_url).expect("parse upgrade-test database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated source-close upgrade ledger");
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin legacy migrations");
            for migration in [
                include_str!("../../migrations/0001_initial.sql"),
                include_str!("../../migrations/0002_operational_incident_lifecycle.sql"),
                include_str!(
                    "../../migrations/0003_work_attempt_bindings_and_shared_escalations.sql"
                ),
                include_str!("../../migrations/0004_reservation_internal_event_guard.sql"),
                include_str!("../../migrations/0005_effect_intent_exact_job_ownership.sql"),
                include_str!("../../migrations/0006_cross_binding_and_terminal_guards.sql"),
                include_str!("../../migrations/0007_operational_incident_reciprocal_proofs.sql"),
                include_str!("../../migrations/0008_runmill_submission_effect_ownership.sql"),
                include_str!("../../migrations/0009_linear_source_closure_ownership.sql"),
                include_str!("../../migrations/0010_reservation_worker_session_fencing.sql"),
            ] {
                sqlx::raw_sql(migration)
                    .execute(&mut *transaction)
                    .await
                    .expect("apply legacy source-close migration");
            }
            transaction
                .commit()
                .await
                .expect("commit legacy migrations");
            Self::shim_pre_0023_activity_contract_column(&ledger).await;
            Self {
                ledger,
                admin,
                schema,
            }
        }

        /// Test-only forward-compatibility shim -- NOT a production migration
        /// and not one of the historical migrations under test. `Fixture`
        /// and `LinearSourceClosureHandler` are written against the current
        /// (post-0023) `ClaimedWorkflowJob`/schema shape and unconditionally
        /// read and write `workflow_jobs.activity_contract_id`, but these two
        /// scoped databases deliberately stop several migrations short of
        /// 0023 so a specific historical upgrade (0011's signing-authority
        /// backfill, or 0019's shared-finality gate) can be exercised against
        /// a schema that genuinely predates it. This shim adds only the
        /// minimum column shape needed to let that current code run at all: a
        /// bare nullable `text` column on `workflow_jobs` (the only table
        /// these historical fixtures write through this column -- they never
        /// insert into `workflow_timers`), with none of migration 0023's
        /// backfill, `NOT NULL`, shape `CHECK`, or trigger changes. It runs
        /// after the real historical migrations above are committed, so it
        /// is never part of what those migrations apply. Every fixture
        /// INSERT still supplies its own canonical, exact contract id --
        /// this shim never invents or defaults one -- and neither migration
        /// 0011 nor 0019 reads, writes, or locks this column, so its
        /// presence changes nothing about either migration's own behavior.
        async fn shim_pre_0023_activity_contract_column(ledger: &PgLedger) {
            sqlx::query("ALTER TABLE workflow_jobs ADD COLUMN activity_contract_id text")
                .execute(ledger.pool())
                .await
                .expect("apply test-only pre-0023 activity-contract column shim");
        }

        async fn create_through_0018(database_url: &str) -> Self {
            let admin = sqlx::PgPool::connect(database_url)
                .await
                .expect("connect source-close finality upgrade-test administrator");
            let schema = format!("asf_source_finality_upgrade_{}", Uuid::now_v7().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated source-close finality upgrade schema");
            let mut scoped_url = Url::parse(database_url).expect("parse finality upgrade-test URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated source-close finality upgrade ledger");
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin migrations through 0018");
            for migration in [
                include_str!("../../migrations/0001_initial.sql"),
                include_str!("../../migrations/0002_operational_incident_lifecycle.sql"),
                include_str!(
                    "../../migrations/0003_work_attempt_bindings_and_shared_escalations.sql"
                ),
                include_str!("../../migrations/0004_reservation_internal_event_guard.sql"),
                include_str!("../../migrations/0005_effect_intent_exact_job_ownership.sql"),
                include_str!("../../migrations/0006_cross_binding_and_terminal_guards.sql"),
                include_str!("../../migrations/0007_operational_incident_reciprocal_proofs.sql"),
                include_str!("../../migrations/0008_runmill_submission_effect_ownership.sql"),
                include_str!("../../migrations/0009_linear_source_closure_ownership.sql"),
                include_str!("../../migrations/0010_reservation_worker_session_fencing.sql"),
                include_str!("../../migrations/0011_worker_session_signing_authority.sql"),
                include_str!(
                    "../../migrations/0012_worker_authority_lifetime_and_closure_preservation.sql"
                ),
                include_str!("../../migrations/0013_source_closure_terminal_invariants.sql"),
                include_str!("../../migrations/0014_evidence_verification_job_ownership.sql"),
                include_str!("../../migrations/0015_verified_evidence_artifact_integrity.sql"),
                include_str!("../../migrations/0016_evidence_verification_receipt_integrity.sql"),
                include_str!("../../migrations/0017_cancellation_receipt_integrity.sql"),
                include_str!("../../migrations/0018_cancellation_escalation_supersession.sql"),
            ] {
                sqlx::raw_sql(migration)
                    .execute(&mut *transaction)
                    .await
                    .expect("apply source-close migration through 0018");
            }
            transaction
                .commit()
                .await
                .expect("commit migrations through 0018");
            Self::shim_pre_0023_activity_contract_column(&ledger).await;
            Self {
                ledger,
                admin,
                schema,
            }
        }
    }

    #[derive(Debug)]
    struct Fixture {
        tenant_id: Uuid,
        work_item_id: Uuid,
        attempt_id: Uuid,
        run_id: Uuid,
        workflow_id: Uuid,
        evidence_id: Uuid,
        expectation_digest: String,
        work_order_digest: String,
        job: ClaimedWorkflowJob,
        bundle: SignedRunmillEvidenceBundle,
        verification: EvidenceVerificationReceiptV1,
        worker_id: Uuid,
        worker_session_id: Uuid,
    }

    type SourceClosureFinalityGuard = (i64, Option<Uuid>, Option<Uuid>, chrono::DateTime<Utc>);

    impl Fixture {
        async fn insert(ledger: &PgLedger, wrong_observed_head: bool) -> Self {
            Self::try_insert_with_signature_tamper(
                ledger,
                wrong_observed_head,
                false,
                CLOSE_SOURCE_ACTIVITY_CONTRACT_ID,
            )
            .await
            .expect("commit source-close fixture")
        }

        async fn insert_with_signature_tamper(
            ledger: &PgLedger,
            wrong_observed_head: bool,
            tamper_signature: bool,
        ) -> Self {
            Self::try_insert_with_signature_tamper(
                ledger,
                wrong_observed_head,
                tamper_signature,
                CLOSE_SOURCE_ACTIVITY_CONTRACT_ID,
            )
            .await
            .expect("commit source-close signature fixture")
        }

        /// Persists the owning `workflow_jobs` row with `persisted_activity_contract_id`
        /// from its initial INSERT (never via a later UPDATE, which migration 0023's
        /// immutability trigger rejects). The in-memory `ClaimedWorkflowJob` always
        /// carries the canonical contract, so tests that use this to exercise a
        /// mismatch drive failure through the SQL `activity_contract_id` predicate
        /// rather than any in-memory/parser check.
        async fn insert_with_wrong_persisted_contract(
            ledger: &PgLedger,
            persisted_activity_contract_id: &str,
        ) -> Self {
            Self::try_insert_with_signature_tamper(
                ledger,
                false,
                false,
                persisted_activity_contract_id,
            )
            .await
            .expect("commit source-close wrong-contract fixture")
        }

        async fn try_insert_with_signature_tamper(
            ledger: &PgLedger,
            wrong_observed_head: bool,
            tamper_signature: bool,
            persisted_activity_contract_id: &str,
        ) -> std::result::Result<Self, sqlx::Error> {
            let tenant_id = Uuid::now_v7();
            let repository_id = Uuid::now_v7();
            let snapshot_id = Uuid::now_v7();
            let policy_id = Uuid::now_v7();
            let work_item_id = Uuid::now_v7();
            let attempt_id = Uuid::now_v7();
            let work_order_id = Uuid::now_v7();
            let worker_id = Uuid::now_v7();
            let worker_session_id = Uuid::now_v7();
            let run_id = Uuid::now_v7();
            let workflow_id = Uuid::now_v7();
            let evidence_id = Uuid::now_v7();
            let verification_id = Uuid::now_v7();
            let verification_job_id = derived_uuid(evidence_id, 30);
            let job_id = Uuid::now_v7();
            let source_digest = digest("source-snapshot");
            let policy_digest = digest("effective-policy-runtime");
            let expectation_digest = digest("evidence-expectation");
            let external_run_id = "run_01JTEST";
            let lease_owner = "reactor:source-close-test".to_owned();
            let lease_expires_at = Utc::now() + Duration::minutes(20);

            let mut work_order: RunmillSignedWorkOrderV1 = serde_json::from_slice(include_bytes!(
                "../../contracts/fixtures/work-order-envelope-v1.json"
            ))
            .expect("decode production Work Order fixture");
            work_order.payload.work_order_id = work_order_id.to_string();
            work_order.payload.tenant_id = tenant_id.to_string();
            work_order.payload.work_item_id = work_item_id.to_string();
            work_order.payload.attempt_id = attempt_id.to_string();
            work_order.payload.idempotency_key = format!("{tenant_id}/{work_item_id}/{attempt_id}");
            work_order.payload.source.system = "linear".into();
            work_order.payload.source.external_id = "ASF-42".into();
            work_order.payload.source.snapshot_digest = source_digest.clone();
            work_order.payload.repository.forge = "github".into();
            work_order.payload.repository.repository = "acme/widgets".into();
            work_order.payload.repository.base_ref = "refs/heads/main".into();
            work_order.payload.repository.base_sha = "b".repeat(40);
            work_order.payload.policy_digest = policy_digest.clone();
            work_order.payload.verification.policy_snapshot_digest = policy_digest.clone();
            work_order.payload.verification.required_local_check_ids = vec!["lint".into()];
            work_order.payload.verification.required_remote_checks = vec!["ci/test".into()];
            work_order.payload.delivery.closure_target =
                crate::contracts::RunmillWorkOrderClosureTarget::Pr;
            let work_order_payload =
                serde_json::to_value(&work_order.payload).expect("encode Work Order payload");
            let work_order_canonical_payload =
                canonical_json(&work_order.payload).expect("canonicalize Work Order payload");
            let work_order_digest = work_order
                .payload_digest()
                .expect("digest Work Order payload");
            let work_order_exact = work_order
                .canonical_bytes()
                .expect("canonicalize Work Order envelope");
            let work_order_envelope_digest = sha256_digest(&work_order_exact);

            let evidence_issued_at = Utc::now() - Duration::minutes(3);
            let mut bundle = SignedRunmillEvidenceBundle::from_json(include_bytes!(
                "../../contracts/fixtures/runmill-signed-evidence-v1.json"
            ))
            .expect("decode production Runmill evidence fixture");
            let predicate = &mut bundle.statement.predicate;
            predicate.run.run_id =
                RunmillExternalRunId::new(external_run_id).expect("valid external run ID");
            predicate.run.attempt_id = AttemptId::from_uuid(attempt_id);
            predicate.run.work_order_id = WorkOrderId::from_uuid(work_order_id);
            predicate.run.completed_at = RunmillEvidenceTimestamp::new(
                (evidence_issued_at - Duration::seconds(1)).to_rfc3339(),
            )
            .expect("valid authoritative run terminal timestamp");
            predicate.work_order.envelope_digest = work_order_envelope_digest;
            predicate.work_order.envelope_artifact_digest =
                predicate.work_order.envelope_digest.clone();
            predicate.work_order.payload_digest = work_order_digest.clone();
            predicate.work_order.signature.key_id = work_order.key_id.clone();
            predicate.work_order.signature.algorithm = RunmillEvidenceAlgorithm::EdDSA;
            predicate.policy.effective_policy_digest = policy_digest.clone();
            predicate.policy.effective_policy_artifact_digest = policy_digest.clone();
            predicate.policy.required_local_checks = vec!["lint".into()];
            predicate.policy.required_ci_contexts = vec!["ci/test".into()];
            predicate.source.forge = "github".into();
            predicate.source.repository = "acme/widgets".into();
            predicate.source.base_ref = "refs/heads/main".into();
            predicate.source.base_sha = "b".repeat(40);
            predicate.source.candidate_sha = "a".repeat(40);
            predicate.source.remote_head_sha = "a".repeat(40);
            predicate.source.normalized_diff_artifact_digest =
                predicate.source.normalized_diff_digest.clone();
            predicate.delivery.closure_target = RunmillClosureTarget::Pr;
            predicate.delivery.satisfied = true;
            predicate.delivery.pull_request.forge = "github".into();
            predicate.delivery.pull_request.repository = "acme/widgets".into();
            predicate.delivery.pull_request.base_ref = "refs/heads/main".into();
            predicate.delivery.pull_request.head_sha = "a".repeat(40);
            for artifact in &mut predicate.artifacts {
                match artifact.kind {
                    RunmillArtifactKind::WorkOrderEnvelope => {
                        artifact.digest = predicate.work_order.envelope_digest.clone();
                        artifact.size_bytes = u64::try_from(work_order_exact.len())
                            .expect("Work Order envelope size fits u64");
                    }
                    RunmillArtifactKind::EffectivePolicy => {
                        artifact.digest = policy_digest.clone();
                        artifact.size_bytes = u64::try_from("effective-policy-runtime".len())
                            .expect("policy artifact size fits u64");
                    }
                    RunmillArtifactKind::NormalizedDiff => {
                        artifact.digest = predicate.source.normalized_diff_digest.clone();
                    }
                    RunmillArtifactKind::AgentOutcome
                    | RunmillArtifactKind::Verification
                    | RunmillArtifactKind::CiObservation
                    | RunmillArtifactKind::Review
                    | RunmillArtifactKind::SideEffect
                    | RunmillArtifactKind::Approval
                    | RunmillArtifactKind::RuntimeManifest => {}
                }
                artifact.location_ref = format!(
                    "cas://sha256/{}",
                    artifact
                        .digest
                        .strip_prefix("sha256:")
                        .expect("fixture artifact uses sha256")
                );
            }
            let evidence_signer = Ed25519Signer::generate("runmill-worker:source-close-test");
            bundle = SignedRunmillEvidenceBundle::sign(
                bundle.statement,
                RunmillEvidenceTimestamp::new(evidence_issued_at.to_rfc3339())
                    .expect("valid evidence issuance timestamp"),
                &evidence_signer,
            )
            .expect("re-sign exact production evidence fixture");
            if tamper_signature {
                let final_character = bundle.signature.pop().expect("nonempty signature");
                bundle
                    .signature
                    .push(if final_character == 'A' { 'B' } else { 'A' });
            }
            let worker_signing_public_key = encode_verifying_key(&evidence_signer.verifying_key());
            let evidence_digest = bundle.bundle_digest.clone();
            let evidence_payload =
                serde_json::to_value(&bundle.statement).expect("encode evidence statement");
            let evidence_canonical =
                canonical_json(&bundle.statement).expect("canonical evidence statement");
            let evidence_exact = canonical_json(&bundle).expect("canonical evidence envelope");
            let evidence_produced_at = bundle
                .issued_at
                .to_utc()
                .expect("evidence issuance timestamp");

            let observed_at = Utc::now() - Duration::minutes(2);
            let verified_at = Utc::now() - Duration::minutes(1);
            let verification = EvidenceVerificationReceiptV1 {
                schema: EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1.into(),
                evidence_id: EvidenceId::from_uuid(evidence_id),
                work_item_id: WorkItemId::from_uuid(work_item_id),
                attempt_id: AttemptId::from_uuid(attempt_id),
                run_id: RunId::from_uuid(run_id),
                evidence_digest: evidence_digest.clone(),
                work_order_digest: work_order_digest.clone(),
                expectation_digest: expectation_digest.clone(),
                verification_job_id,
                verification_job_fence_token: 1,
                verification_job_completed_by: "reactor:evidence-verification-test".into(),
                verifier: "asf:github-evidence-verifier/v1".into(),
                pull_request: crate::contracts::PullRequestEvidence {
                    repository: "acme/widgets".into(),
                    number: 42,
                    url: "https://github.com/acme/widgets/pull/42".into(),
                    base_sha: "b".repeat(40),
                    head_sha: if wrong_observed_head {
                        "c".repeat(40)
                    } else {
                        "a".repeat(40)
                    },
                    required_ci_contexts: BTreeSet::from(["ci/test".into()]),
                    successful_ci_contexts: BTreeSet::from(["ci/test".into()]),
                },
                provider_revision: "github:pull-request:42:rev-1".into(),
                observed_at,
            };
            verification
                .validate()
                .expect("valid independent verification receipt shape");

            let job_payload = json!({
                "work_item_id": work_item_id,
                "expected_work_item_version": 1,
                "evidence_id": evidence_id,
                "run_id": run_id,
                "payload_digest": evidence_digest,
                "work_order_digest": work_order_digest,
                "expectation_digest": expectation_digest,
            });
            let mut transaction = ledger.pool().begin().await.expect("begin fixture");
            sqlx::query(
                "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Source close test')",
            )
            .bind(tenant_id)
            .bind(format!("source-close-{tenant_id}"))
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
            sqlx::query(
                r"
                INSERT INTO policy_versions (
                    id, tenant_id, scope, schema_version, digest, canonical_bytes,
                    policy, created_by
                ) VALUES ($1, $2, 'TENANT', 'v1', $3, '{}'::bytea, '{}'::jsonb, 'test')
                ",
            )
            .bind(policy_id)
            .bind(tenant_id)
            .bind(&policy_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert policy");
            sqlx::query(
                r"
                INSERT INTO repositories (
                    id, tenant_id, owner, name, repository_url, default_branch
                ) VALUES ($1, $2, 'acme', 'widgets', 'https://github.com/acme/widgets', 'main')
                ",
            )
            .bind(repository_id)
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .expect("insert repository");
            sqlx::query(
                r"
                INSERT INTO source_snapshots (
                    id, tenant_id, repository_id, source_system, external_id,
                    source_revision, normalized_content, content_digest,
                    connector_identity, source_updated_at
                ) VALUES (
                    $1, $2, $3, 'LINEAR', 'ASF-42', 'linear-rev-1',
                    '{}'::jsonb, $4, 'linear:test', clock_timestamp()
                )
                ",
            )
            .bind(snapshot_id)
            .bind(tenant_id)
            .bind(repository_id)
            .bind(&source_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert source snapshot");
            sqlx::query(
                r"
                INSERT INTO work_items (
                    id, tenant_id, source_snapshot_id, source_system,
                    source_external_id, repository_id, state, closure_target,
                    risk_class, policy_digest, budget_limits,
                    identity_requirements, owner_fallback, normalized_priority,
                    current_attempt_id, accepted_at
                ) VALUES (
                    $1, $2, $3, 'LINEAR', 'ASF-42', $4, 'CLOSING_SOURCE',
                    'pull_request', 'low', $5, $6, $7, 'team:platform', 50,
                    $8, clock_timestamp()
                )
                ",
            )
            .bind(work_item_id)
            .bind(tenant_id)
            .bind(snapshot_id)
            .bind(repository_id)
            .bind(&policy_digest)
            .bind(valid_budget_limits())
            .bind(valid_identity_requirements())
            .bind(attempt_id)
            .execute(&mut *transaction)
            .await
            .expect("insert work item");
            sqlx::query(
                r"
                INSERT INTO attempts (
                    id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                    base_ref, base_sha, source_snapshot_digest, policy_digest,
                    work_order_digest, fence_token, created_at, terminal_at
                ) VALUES (
                    $1, $2, $3, 1, 'SUCCEEDED', $4, 'refs/heads/main', $5,
                    $6, $7, $8, 7, $9 - interval '1 minute', $9
                )
                ",
            )
            .bind(attempt_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(format!("{tenant_id}/{work_item_id}/{attempt_id}"))
            .bind("b".repeat(40))
            .bind(&source_digest)
            .bind(&policy_digest)
            .bind(&work_order_digest)
            .bind(
                bundle
                    .statement
                    .predicate
                    .run
                    .completed_at
                    .to_utc()
                    .expect("attempt terminal timestamp"),
            )
            .execute(&mut *transaction)
            .await
            .expect("insert attempt");
            sqlx::query(
                r"
                INSERT INTO work_orders (
                    id, tenant_id, work_item_id, attempt_id, schema_version,
                    envelope_schema, algorithm, key_id, idempotency_key,
                    payload_digest, canonical_payload, payload, signature,
                    exact_signed_envelope, issued_at, not_before, expires_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17
                )
                ",
            )
            .bind(work_order_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(&work_order.payload.schema)
            .bind(&work_order.schema)
            .bind(&work_order.algorithm)
            .bind(&work_order.key_id)
            .bind(&work_order.payload.idempotency_key)
            .bind(&work_order_digest)
            .bind(work_order_canonical_payload)
            .bind(work_order_payload)
            .bind(&work_order.signature)
            .bind(work_order_exact)
            .bind(work_order.issued_at)
            .bind(work_order.not_before)
            .bind(work_order.expires_at)
            .execute(&mut *transaction)
            .await
            .expect("insert Work Order");
            sqlx::query(
                r"
                INSERT INTO workers (
                    id, tenant_id, name, endpoint, status, capabilities,
                    generation, max_concurrency, signing_key_id, signing_public_key
                ) VALUES (
                    $1, $2, $3, $4, 'READY', '{}'::jsonb, 1, 1, $5, $6
                )
                ",
            )
            .bind(worker_id)
            .bind(tenant_id)
            .bind(format!("worker-{}", worker_id.simple()))
            .bind(format!("https://worker.invalid/{worker_id}"))
            .bind(&bundle.key_id)
            .bind(&worker_signing_public_key)
            .execute(&mut *transaction)
            .await
            .expect("insert worker");
            sqlx::query(
                r"
                INSERT INTO worker_sessions (
                    id, tenant_id, worker_id, worker_generation, status,
                    started_at, expires_at
                ) VALUES ($1, $2, $3, 1, 'ACTIVE', $4, $5)
                ",
            )
            .bind(worker_session_id)
            .bind(tenant_id)
            .bind(worker_id)
            .bind(evidence_produced_at - Duration::minutes(2))
            .bind(evidence_produced_at + Duration::hours(1))
            .execute(&mut *transaction)
            .await
            .expect("insert worker session");
            sqlx::query(
                r"
                INSERT INTO runs (
                    id, tenant_id, work_item_id, attempt_id, work_order_id,
                    worker_id, worker_generation, worker_session_id,
                    evidence_expectation_digest, external_run_id, authoritative,
                    state, adopted_at, last_observed_at, terminal_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, 1, $7, $8, $9, true,
                    'SUCCEEDED', $10 - interval '1 minute', $10, $10
                )
                ",
            )
            .bind(run_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(work_order_id)
            .bind(worker_id)
            .bind(worker_session_id)
            .bind(&expectation_digest)
            .bind(external_run_id)
            .bind(
                bundle
                    .statement
                    .predicate
                    .run
                    .completed_at
                    .to_utc()
                    .expect("run terminal timestamp"),
            )
            .execute(&mut *transaction)
            .await
            .expect("insert run");
            sqlx::query(
                r"
                INSERT INTO evidence_bundles (
                    id, tenant_id, work_item_id, attempt_id, run_id, worker_id,
                    worker_generation, schema_version, envelope_schema, algorithm,
                    key_id, payload_digest, work_order_digest, base_sha, candidate_sha,
                    requested_target, target_satisfied, canonical_payload, payload,
                    signature, exact_signed_envelope, produced_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, 1, $7, $8, 'EdDSA', $9, $10,
                    $11, $12, $13, 'pull_request', true, $14, $15, $16, $17, $18
                )
                ",
            )
            .bind(evidence_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(run_id)
            .bind(worker_id)
            .bind(&bundle.statement.predicate.schema)
            .bind(&bundle.schema)
            .bind(&bundle.key_id)
            .bind(&evidence_digest)
            .bind(&work_order_digest)
            .bind("b".repeat(40))
            .bind("a".repeat(40))
            .bind(evidence_canonical)
            .bind(evidence_payload)
            .bind(&bundle.signature)
            .bind(evidence_exact)
            .bind(evidence_produced_at)
            .execute(&mut *transaction)
            .await
            .expect("insert evidence");
            for artifact in &bundle.statement.predicate.artifacts {
                let artifact_id = Uuid::now_v7();
                let retention = match artifact.retention_class {
                    RunmillRetentionClass::Portable => "portable",
                    RunmillRetentionClass::Protected => "protected",
                    RunmillRetentionClass::Restricted => "restricted",
                };
                sqlx::query(
                    r"
                    INSERT INTO artifacts (
                        id, tenant_id, digest_algorithm, digest, media_type,
                        byte_size, object_key, encryption_class, retention_class,
                        access_policy, producer, created_at
                    ) VALUES (
                        $1, $2, 'sha256', $3, $4, $5, $6, 'none', $7,
                        'tenant', 'runmill:source-close-test', $8
                    )
                    ",
                )
                .bind(artifact_id)
                .bind(tenant_id)
                .bind(&artifact.digest)
                .bind(&artifact.media_type)
                .bind(i64::try_from(artifact.size_bytes).expect("artifact size fits bigint"))
                .bind(&artifact.location_ref)
                .bind(retention)
                .bind(verified_at - Duration::seconds(1))
                .execute(&mut *transaction)
                .await
                .expect("insert source-close artifact metadata");
                sqlx::query(
                    r"
                    INSERT INTO evidence_artifacts (
                        tenant_id, evidence_id, artifact_id, relationship
                    ) VALUES ($1, $2, $3, 'OTHER')
                    ",
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(artifact_id)
                .execute(&mut *transaction)
                .await
                .expect("link source-close evidence artifact");
            }
            let has_exact_verification_provenance: bool = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = 'evidence_verifications'
                      AND column_name = 'workflow_job_id'
                )
                ",
            )
            .fetch_one(&mut *transaction)
            .await
            .expect("detect evidence-verification schema generation");
            let verification_details =
                serde_json::to_value(&verification).expect("encode verification receipt");
            if has_exact_verification_provenance {
                sqlx::query(
                    r"
                    INSERT INTO evidence_verifications (
                        id, tenant_id, evidence_id, work_item_id, attempt_id, run_id,
                        evidence_digest, work_order_digest, verifier, status,
                        expectation_digest, workflow_job_id, workflow_job_fence_token,
                        workflow_job_completed_by, details, verified_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, 'VALID', $10,
                        $11, 1, $12, $13, $14
                    )
                    ",
                )
                .bind(verification_id)
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(work_item_id)
                .bind(attempt_id)
                .bind(run_id)
                .bind(&evidence_digest)
                .bind(&work_order_digest)
                .bind(&verification.verifier)
                .bind(&expectation_digest)
                .bind(verification_job_id)
                .bind(&verification.verification_job_completed_by)
                .bind(verification_details)
                .bind(verified_at)
                .execute(&mut *transaction)
                .await
                .expect("insert exact evidence verification");
            } else {
                sqlx::query(
                    r"
                    INSERT INTO evidence_verifications (
                        id, tenant_id, evidence_id, verifier, status,
                        expectation_digest, details, verified_at
                    ) VALUES ($1, $2, $3, $4, 'VALID', $5, $6, $7)
                    ",
                )
                .bind(verification_id)
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(&verification.verifier)
                .bind(&expectation_digest)
                .bind(verification_details)
                .bind(verified_at)
                .execute(&mut *transaction)
                .await
                .expect("insert legacy evidence verification");
            }
            sqlx::query(
                r"
                INSERT INTO workflow_instances (
                    id, tenant_id, work_item_id, workflow_type, state,
                    reducer_version, event_cursor, fence_token
                ) VALUES (
                    $1, $2, $3, 'WORK_ITEM_DELIVERY', 'ACTIVE',
                    'asf.workflow/v1', 9, 3
                )
                ",
            )
            .bind(workflow_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .execute(&mut *transaction)
            .await
            .expect("insert workflow");
            let verification_job_payload = json!({
                "evidence_id": evidence_id,
                "run_id": run_id,
                "payload_digest": &evidence_digest,
                "work_order_digest": &work_order_digest,
                "expectation_digest": &expectation_digest,
            });
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                    job_type, activity_contract_id, status, payload, idempotency_key,
                    attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
                ) VALUES (
                    $1, $2, $3, $4, $5, 'VERIFY_EVIDENCE', $6, 'RUNNING', $7,
                    $8, 1, 25, 1, $9, clock_timestamp() + interval '5 minutes'
                )
                ",
            )
            .bind(verification_job_id)
            .bind(tenant_id)
            .bind(workflow_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
            .bind(verification_job_payload)
            .bind(format!("verify-evidence-job:{work_item_id}:{evidence_id}"))
            .bind(&verification.verification_job_completed_by)
            .execute(&mut *transaction)
            .await
            .expect("insert running evidence-verification claim");
            sqlx::query(
                r"
                UPDATE workflow_jobs
                SET status = 'COMPLETED',
                    result = '{}'::jsonb,
                    completed_by = lease_owner,
                    completion_fence_token = fence_token,
                    completed_at = clock_timestamp(),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1 AND id = $2
                ",
            )
            .bind(tenant_id)
            .bind(verification_job_id)
            .execute(&mut *transaction)
            .await
            .expect("complete evidence-verification claim");
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                    job_type, activity_contract_id, status, payload, idempotency_key,
                    attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
                ) VALUES (
                    $1, $2, $3, $4, $5, 'CLOSE_SOURCE', $6, 'RUNNING', $7, $8,
                    1, 25, 1, $9, $10
                )
                ",
            )
            .bind(job_id)
            .bind(tenant_id)
            .bind(workflow_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(persisted_activity_contract_id)
            .bind(&job_payload)
            .bind(format!("source-close-job:{work_item_id}:{evidence_id}"))
            .bind(&lease_owner)
            .bind(lease_expires_at)
            .execute(&mut *transaction)
            .await
            .expect("insert source-close job");
            sqlx::query(
                r"
                INSERT INTO accountability_anchors (
                    tenant_id, work_item_id, anchor_type, reference_id,
                    authority_or_effect_active, generation
                ) VALUES ($1, $2, 'WORKFLOW', $3, true, 1)
                ",
            )
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(workflow_id)
            .execute(&mut *transaction)
            .await
            .expect("insert workflow accountability");
            transaction.commit().await?;

            let job = ClaimedWorkflowJob {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                job_type: CLOSE_SOURCE.into(),
                activity_contract_id: CLOSE_SOURCE_ACTIVITY_CONTRACT_ID.into(),
                payload: job_payload,
                idempotency_key: format!("source-close-job:{work_item_id}:{evidence_id}"),
                priority: 75,
                attempt_count: 1,
                max_attempts: 25,
                fence_token: 1,
                lease_owner,
                lease_expires_at,
                created_at: Utc::now(),
            };
            Ok(Self {
                tenant_id,
                work_item_id,
                attempt_id,
                run_id,
                workflow_id,
                evidence_id,
                expectation_digest,
                work_order_digest,
                job,
                bundle,
                verification,
                worker_id,
                worker_session_id,
            })
        }

        async fn insert_alternate_valid_evidence(&self, ledger: &PgLedger) -> Uuid {
            let alternate_id = Uuid::now_v7();
            let verification_job_id = derived_uuid(alternate_id, 30);
            let mut bundle = self.bundle.clone();
            bundle.statement.predicate.budget.agent_invocations += 1;
            bundle.bundle_digest =
                sha256_digest(&canonical_json(&bundle.statement).expect("alternate statement"));
            let digest = bundle.bundle_digest.clone();
            let canonical = canonical_json(&bundle.statement).expect("alternate canonical payload");
            let payload =
                serde_json::to_value(&bundle.statement).expect("alternate evidence payload");
            let envelope = canonical_json(&bundle).expect("alternate evidence envelope");
            let mut verification = self.verification.clone();
            verification.evidence_id = EvidenceId::from_uuid(alternate_id);
            verification.evidence_digest = digest.clone();
            verification.verification_job_id = verification_job_id;
            let verification_details =
                serde_json::to_value(&verification).expect("alternate verification receipt");
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin alternate evidence");
            sqlx::query(
                r"
                INSERT INTO evidence_bundles (
                    id, tenant_id, work_item_id, attempt_id, run_id, worker_id,
                    worker_generation, schema_version, envelope_schema, algorithm,
                    key_id, payload_digest, work_order_digest, base_sha, candidate_sha,
                    requested_target, target_satisfied, canonical_payload, payload,
                    signature, exact_signed_envelope, produced_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, 1, $7, $8, 'EdDSA', $9, $10,
                    $11, $12, $13, 'pull_request', true, $14, $15, $16, $17, $18
                )
                ",
            )
            .bind(alternate_id)
            .bind(self.tenant_id)
            .bind(self.work_item_id)
            .bind(self.attempt_id)
            .bind(self.run_id)
            .bind(self.worker_id)
            .bind(&bundle.statement.predicate.schema)
            .bind(&bundle.schema)
            .bind(&bundle.key_id)
            .bind(&digest)
            .bind(&self.work_order_digest)
            .bind("b".repeat(40))
            .bind("a".repeat(40))
            .bind(canonical)
            .bind(payload)
            .bind(&bundle.signature)
            .bind(envelope)
            .bind(bundle.issued_at.to_utc().expect("alternate issued at"))
            .execute(&mut *transaction)
            .await
            .expect("insert alternate valid evidence");
            sqlx::query(
                r"
                INSERT INTO evidence_artifacts (
                    tenant_id, evidence_id, artifact_id, relationship
                )
                SELECT tenant_id, $3, artifact_id, relationship
                FROM evidence_artifacts
                WHERE tenant_id = $1 AND evidence_id = $2
                ",
            )
            .bind(self.tenant_id)
            .bind(self.evidence_id)
            .bind(alternate_id)
            .execute(&mut *transaction)
            .await
            .expect("bind alternate evidence to its signed artifact manifest");
            let verification_job_payload = json!({
                "evidence_id": alternate_id,
                "run_id": self.run_id,
                "payload_digest": &digest,
                "work_order_digest": &self.work_order_digest,
                "expectation_digest": &self.expectation_digest,
            });
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                    job_type, activity_contract_id, status, payload, idempotency_key,
                    attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
                ) VALUES (
                    $1, $2, $3, $4, $5, 'VERIFY_EVIDENCE', $6, 'RUNNING', $7,
                    $8, 1, 25, 1, $9, clock_timestamp() + interval '5 minutes'
                )
                ",
            )
            .bind(verification_job_id)
            .bind(self.tenant_id)
            .bind(self.workflow_id)
            .bind(self.work_item_id)
            .bind(self.attempt_id)
            .bind(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
            .bind(verification_job_payload)
            .bind(format!(
                "verify-evidence-job:{}:{alternate_id}",
                self.work_item_id
            ))
            .bind(&verification.verification_job_completed_by)
            .execute(&mut *transaction)
            .await
            .expect("insert alternate running verification claim");
            sqlx::query(
                r"
                UPDATE workflow_jobs
                SET status = 'COMPLETED',
                    result = '{}'::jsonb,
                    completed_by = lease_owner,
                    completion_fence_token = fence_token,
                    completed_at = clock_timestamp(),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1 AND id = $2
                ",
            )
            .bind(self.tenant_id)
            .bind(verification_job_id)
            .execute(&mut *transaction)
            .await
            .expect("complete alternate evidence-verification claim");
            sqlx::query(
                r"
                INSERT INTO evidence_verifications (
                    id, tenant_id, evidence_id, work_item_id, attempt_id, run_id,
                    evidence_digest, work_order_digest, verifier, status,
                    expectation_digest, workflow_job_id, workflow_job_fence_token,
                    workflow_job_completed_by, details, verified_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, 'VALID', $10,
                    $11, 1, $12, $13, clock_timestamp()
                )
                ",
            )
            .bind(Uuid::now_v7())
            .bind(self.tenant_id)
            .bind(alternate_id)
            .bind(self.work_item_id)
            .bind(self.attempt_id)
            .bind(self.run_id)
            .bind(&digest)
            .bind(&self.work_order_digest)
            .bind(&verification.verifier)
            .bind(&self.expectation_digest)
            .bind(verification_job_id)
            .bind(&verification.verification_job_completed_by)
            .bind(verification_details)
            .execute(&mut *transaction)
            .await
            .expect("insert alternate valid verification");
            transaction
                .commit()
                .await
                .expect("commit alternate valid evidence");
            alternate_id
        }

        async fn insert_active_reservation(&self, ledger: &PgLedger) -> Uuid {
            let reservation_set_id = Uuid::now_v7();
            let acquired_at = Utc::now();
            let idempotency_key = format!("source-close-reservation:{reservation_set_id}");
            let actor_id = "scheduler:source-close-test";
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin source-close reservation");
            sqlx::query(
                r"
                INSERT INTO reservation_sets (
                    id, tenant_id, work_item_id, attempt_id, repository_id,
                    worker_id, worker_session_id, worker_generation,
                    request_digest, idempotency_key, state, fence_token,
                    acquired_by, acquired_at, expires_at
                )
                SELECT
                    $1, work.tenant_id, work.id, $3, work.repository_id,
                    $4, $5, 1, $6, $7, 'ACTIVE', 1, $8, $9,
                    $9 + interval '15 minutes'
                FROM work_items AS work
                WHERE work.tenant_id = $2 AND work.id = $10
                ",
            )
            .bind(reservation_set_id)
            .bind(self.tenant_id)
            .bind(self.attempt_id)
            .bind(self.worker_id)
            .bind(self.worker_session_id)
            .bind(digest("source-close-reservation-request"))
            .bind(&idempotency_key)
            .bind(actor_id)
            .bind(acquired_at)
            .bind(self.work_item_id)
            .execute(&mut *transaction)
            .await
            .expect("insert active source-close reservation");
            sqlx::query(
                r"
                INSERT INTO reservation_set_events (
                    id, tenant_id, reservation_set_id, event_type,
                    previous_fence_token, fence_token, actor_id, reason,
                    idempotency_key, occurred_at
                ) VALUES (
                    $1, $2, $3, 'ACQUIRED', 0, 1, $4,
                    'atomic admission acquired', $5, $6
                )
                ",
            )
            .bind(Uuid::now_v7())
            .bind(self.tenant_id)
            .bind(reservation_set_id)
            .bind(actor_id)
            .bind(&idempotency_key)
            .bind(acquired_at)
            .execute(&mut *transaction)
            .await
            .expect("insert source-close reservation acquisition event");
            transaction
                .commit()
                .await
                .expect("commit active source-close reservation");
            reservation_set_id
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum GatewayMode {
        Applied,
        LoseFirstResponse,
        ContradictReceipt,
    }

    #[derive(Debug, Default)]
    struct GatewayState {
        close_calls: usize,
        reconcile_calls: usize,
        applied: Option<SourceCloseReceipt>,
    }

    #[derive(Debug)]
    struct FakeGateway {
        mode: GatewayMode,
        state: Mutex<GatewayState>,
    }

    impl FakeGateway {
        fn new(mode: GatewayMode) -> Self {
            Self {
                mode,
                state: Mutex::new(GatewayState::default()),
            }
        }

        async fn counts(&self) -> (usize, usize) {
            let state = self.state.lock().await;
            (state.close_calls, state.reconcile_calls)
        }
    }

    #[async_trait]
    impl SourceGateway for FakeGateway {
        async fn intake(&self, _request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage> {
            Err(SourceGatewayError::UnsupportedContract {
                detail: "not used by source-close fixture".into(),
            })
        }

        async fn observe_source(
            &self,
            _request: &ObserveSourceRequest,
        ) -> SourceResult<SourceObservation> {
            Err(SourceGatewayError::UnsupportedContract {
                detail: "not used by source-close fixture".into(),
            })
        }

        async fn close_source(
            &self,
            request: &CloseSourceRequest,
        ) -> SourceResult<SourceCloseReceipt> {
            request.validate()?;
            let mut state = self.state.lock().await;
            state.close_calls += 1;
            let receipt = SourceCloseReceipt {
                schema: SOURCE_CLOSE_RECEIPT_SCHEMA_V1.into(),
                item: request.effect.item.clone(),
                idempotency_key: request.idempotency_key.clone(),
                effect_digest: request.effect_digest.clone(),
                correlation_marker: request.effect.correlation_marker.clone(),
                disposition: SourceCloseDisposition::Applied,
                provider_revision: "linear:ASF-42:closed:1".into(),
                recorded_at: Utc::now(),
            };
            state.applied = Some(receipt.clone());
            match self.mode {
                GatewayMode::Applied => Ok(receipt),
                GatewayMode::LoseFirstResponse => Err(SourceGatewayError::AmbiguousEffect {
                    idempotency_key: request.idempotency_key.clone(),
                    effect_digest: request.effect_digest.clone(),
                }),
                GatewayMode::ContradictReceipt => {
                    let mut wrong = receipt;
                    wrong.item.external_id = "ASF-WRONG".into();
                    Ok(wrong)
                }
            }
        }

        async fn reconcile_source_close(
            &self,
            _request: &ReconcileSourceCloseRequest,
        ) -> SourceResult<SourceCloseReconciliation> {
            let mut state = self.state.lock().await;
            state.reconcile_calls += 1;
            Ok(state.applied.clone().map_or(
                SourceCloseReconciliation::NotObserved,
                |mut receipt| {
                    receipt.disposition = SourceCloseDisposition::Reconciled;
                    SourceCloseReconciliation::Applied(receipt)
                },
            ))
        }
    }

    #[tokio::test]
    async fn happy_path_is_one_atomic_observed_closure_and_anchor_is_reciprocal() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        // Create the otherwise-valid alternate proof before terminal source
        // closure.  Once CLOSED, the shared finality gate correctly rejects
        // every newly inserted work-scoped row, including terminal history.
        let alternate = fixture
            .insert_alternate_valid_evidence(&database.ledger)
            .await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        let outcome = handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect("close Linear source");
        assert_eq!(outcome, ActivityOutcome::TransactionCommitted);
        assert_eq!(gateway.counts().await, (1, 0));
        let state: (String, String, String, String, Uuid, bool, i64, i64) = sqlx::query_as(
            r"
            SELECT
                work.state, workflow.state, job.status, effect.status,
                anchor.reference_id, anchor.authority_or_effect_active,
                (SELECT count(*) FROM audit_events WHERE tenant_id = work.tenant_id),
                (SELECT count(*) FROM outbox WHERE tenant_id = work.tenant_id)
            FROM work_items AS work
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = work.tenant_id AND workflow.id = $3
            JOIN workflow_jobs AS job
              ON job.tenant_id = work.tenant_id AND job.id = $4
            JOIN effect_intents AS effect
              ON effect.tenant_id = work.tenant_id
             AND effect.work_item_id = work.id
             AND effect.provider = 'linear'
             AND effect.effect_type = 'close_source'
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = work.tenant_id AND anchor.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.workflow_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load atomic closure");
        assert_eq!(state.0, "CLOSED");
        assert_eq!(state.1, "COMPLETED");
        assert_eq!(state.2, "COMPLETED");
        assert_eq!(state.3, "OBSERVED");
        assert_eq!(state.4, fixture.evidence_id);
        assert!(!state.5);
        assert_eq!(state.6, 1);
        assert_eq!(state.7, 1);
        let reservation: (String, i64, String, String, String, i64) = sqlx::query_as(
            r"
            SELECT reservation_set.state,
                   reservation_set.fence_token,
                   reservation_set.transition_idempotency_key,
                   reservation_set.released_by,
                   reservation_set.release_reason,
                   count(event.id) FILTER (WHERE event.event_type = 'RELEASED')
            FROM reservation_sets AS reservation_set
            LEFT JOIN reservation_set_events AS event
              ON event.tenant_id = reservation_set.tenant_id
             AND event.reservation_set_id = reservation_set.id
            WHERE reservation_set.tenant_id = $1
              AND reservation_set.id = $2
            GROUP BY reservation_set.state, reservation_set.fence_token,
                     reservation_set.transition_idempotency_key,
                     reservation_set.released_by, reservation_set.release_reason
            ",
        )
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load atomically released source-close reservation");
        assert_eq!(reservation.0, "RELEASED");
        assert_eq!(reservation.1, 2);
        assert_eq!(
            reservation.2,
            format!(
                "work-closure:v1:{}:{}:{reservation_set_id}:fence:1",
                fixture.work_item_id, fixture.attempt_id
            )
        );
        assert_eq!(reservation.3, fixture.job.lease_owner);
        assert_eq!(
            reservation.4,
            "verified source closure completed the authoritative attempt"
        );
        assert_eq!(reservation.5, 1);

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin anchor swap");
        sqlx::query(
            "UPDATE accountability_anchors SET reference_id = $3 WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(alternate)
        .execute(&mut *transaction)
        .await
        .expect("stage otherwise-valid closure anchor swap");
        assert!(
            sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                .execute(&mut *transaction)
                .await
                .is_err(),
            "a CLOSED item cannot sever its receipt/evidence anchor chain"
        );
        transaction
            .rollback()
            .await
            .expect("rollback anchor attack");
        let anchor: Uuid = sqlx::query_scalar(
            "SELECT reference_id FROM accountability_anchors WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load protected anchor");
        assert_eq!(anchor, fixture.evidence_id);

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin closed-run mutation");
        sqlx::query("UPDATE runs SET state = 'FAILED' WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .execute(&mut *transaction)
            .await
            .expect("stage otherwise-legal terminal run rewrite");
        assert!(
            sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                .execute(&mut *transaction)
                .await
                .is_err(),
            "a CLOSED item cannot lose its authoritative SUCCEEDED run"
        );
        transaction
            .rollback()
            .await
            .expect("rollback closed-run mutation");
        let run_state: String =
            sqlx::query_scalar("SELECT state FROM runs WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(fixture.run_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load protected run state");
        assert_eq!(run_state, "SUCCEEDED");
        database.cleanup().await;
    }

    #[tokio::test]
    async fn closed_source_finality_rejects_unrelated_live_children_immediately() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close finality handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("establish a valid observed source closure"),
            ActivityOutcome::TransactionCommitted
        );
        assert_eq!(gateway.counts().await, (1, 0));

        let source_closure_effect_id: Uuid = sqlx::query_scalar(
            r"
            SELECT id
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'linear'
              AND effect_type = 'close_source'
              AND status = 'OBSERVED'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load the observed source-close effect frozen into the guard");
        let guard_before: SourceClosureFinalityGuard = sqlx::query_as(
            r"
            SELECT
                generation,
                terminal_receipt_id,
                source_closure_effect_intent_id,
                updated_at
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load the frozen source-closure guard");
        assert!(guard_before.1.is_none());
        assert_eq!(guard_before.2, Some(source_closure_effect_id));
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT asf_observed_source_closure_is_valid($1, $2)",)
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("validate source closure before child insert attacks")
        );

        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let timer_id = Uuid::now_v7();
        let effect_id = Uuid::now_v7();
        let rejected_ids = [workflow_id, job_id, timer_id, effect_id];
        let assert_shared_guard_rejection = |label: &str, error: &sqlx::Error| {
            let database_error = error
                .as_database_error()
                .unwrap_or_else(|| panic!("{label} rejection must be a PostgreSQL error"));
            assert_eq!(
                database_error.code().as_deref(),
                Some("23514"),
                "{label} must fail with an immediate integrity violation"
            );
            assert_eq!(
                database_error.constraint(),
                Some("cancellation_authority_facts_preserve_terminal_receipt"),
                "{label} must fail at the shared finality gate"
            );
        };

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin post-closure child insert attacks");

        sqlx::query("SAVEPOINT active_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint ACTIVE workflow attack");
        let workflow_error = sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state,
                reducer_version
            ) VALUES (
                $1, $2, $3, $4, 'ACTIVE', 'asf.workflow/v1'
            )
            ",
        )
        .bind(workflow_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!("SOURCE_CLOSURE_FINALITY_{}", workflow_id.simple()))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh ACTIVE workflow must be rejected after source closure");
        assert_shared_guard_rejection("fresh ACTIVE workflow", &workflow_error);
        sqlx::query("ROLLBACK TO SAVEPOINT active_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back ACTIVE workflow attack");
        sqlx::query("RELEASE SAVEPOINT active_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("release ACTIVE workflow attack savepoint");
        assert_source_closure_finality_preserved(
            &mut transaction,
            &fixture,
            &guard_before,
            rejected_ids,
        )
        .await;

        sqlx::query("SAVEPOINT pending_job_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint PENDING job attack");
        let job_error = sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5,
                'SOURCE_CLOSURE_FINALITY_REGRESSION',
                'test.activity/source-closure-finality-regression/v1', 'PENDING',
                '{}'::jsonb, $6
            )
            ",
        )
        .bind(job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.workflow_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("post-closure-pending-job:{job_id}"))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh PENDING job must be rejected after source closure");
        assert_shared_guard_rejection("fresh PENDING job", &job_error);
        sqlx::query("ROLLBACK TO SAVEPOINT pending_job_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back PENDING job attack");
        sqlx::query("RELEASE SAVEPOINT pending_job_attack")
            .execute(&mut *transaction)
            .await
            .expect("release PENDING job attack savepoint");
        assert_source_closure_finality_preserved(
            &mut transaction,
            &fixture,
            &guard_before,
            rejected_ids,
        )
        .await;

        sqlx::query("SAVEPOINT scheduled_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint SCHEDULED timer attack");
        let timer_error = sqlx::query(
            r"
            INSERT INTO workflow_timers (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                workflow_key, timer_key, timer_type, activity_contract_id, status,
                due_at, payload
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                'SOURCE_CLOSURE_FINALITY_REGRESSION',
                'test.activity/source-closure-finality-regression/v1', 'SCHEDULED',
                clock_timestamp() + interval '1 hour', '{}'::jsonb
            )
            ",
        )
        .bind(timer_id)
        .bind(fixture.tenant_id)
        .bind(fixture.workflow_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("source-closure-finality:{timer_id}"))
        .bind(format!("post-closure-scheduled-timer:{timer_id}"))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh SCHEDULED timer must be rejected after source closure");
        assert_shared_guard_rejection("fresh SCHEDULED timer", &timer_error);
        sqlx::query("ROLLBACK TO SAVEPOINT scheduled_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back SCHEDULED timer attack");
        sqlx::query("RELEASE SAVEPOINT scheduled_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("release SCHEDULED timer attack savepoint");
        assert_source_closure_finality_preserved(
            &mut transaction,
            &fixture,
            &guard_before,
            rejected_ids,
        )
        .await;

        sqlx::query("SAVEPOINT pending_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint PENDING effect attack");
        let effect_error = sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, request_digest, request_payload
            ) VALUES (
                $1, $2, $3, $4, 'test-provider',
                'source-closure-finality-regression', 'PENDING',
                $5, $6, '{}'::jsonb
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("post-closure-pending-effect:{effect_id}"))
        .bind(digest("post-closure-pending-effect"))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh generic PENDING effect must be rejected after source closure");
        assert_shared_guard_rejection("fresh generic PENDING effect", &effect_error);
        sqlx::query("ROLLBACK TO SAVEPOINT pending_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back PENDING effect attack");
        sqlx::query("RELEASE SAVEPOINT pending_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("release PENDING effect attack savepoint");
        assert_source_closure_finality_preserved(
            &mut transaction,
            &fixture,
            &guard_before,
            rejected_ids,
        )
        .await;

        transaction
            .commit()
            .await
            .expect("commit transaction containing only rejected child attacks");

        let final_guard: SourceClosureFinalityGuard = sqlx::query_as(
            r"
            SELECT
                generation,
                terminal_receipt_id,
                source_closure_effect_intent_id,
                updated_at
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("reload frozen source-closure guard after child attacks");
        assert_eq!(final_guard, guard_before);
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT asf_observed_source_closure_is_valid($1, $2)",)
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("revalidate source closure after child insert attacks")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn committed_live_child_wins_before_source_closure() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let winning_workflow_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state,
                reducer_version
            ) VALUES (
                $1, $2, $3, $4, 'ACTIVE', 'asf.workflow/v1'
            )
            ",
        )
        .bind(winning_workflow_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!(
            "SOURCE_CLOSURE_WINNER_{}",
            winning_workflow_id.simple()
        ))
        .execute(database.ledger.pool())
        .await
        .expect("commit unrelated live workflow before source closure");

        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close winner handler");
        let error = handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect_err("committed live workflow must defeat source-closure finalization");
        let message = match error {
            Error::Persistence(message) => message,
            other => panic!("source-closure finalization must fail at database commit: {other}"),
        };
        assert!(
            message.contains("closed work item has no exact terminal source-closure proof"),
            "source closure must fail its deferred no-live-authority proof: {message}"
        );
        assert_eq!(gateway.counts().await, (1, 0));

        let state: (
            String,
            String,
            String,
            String,
            String,
            Option<Uuid>,
            Option<Uuid>,
            bool,
        ) = sqlx::query_as(
            r"
            SELECT
                work.state,
                workflow.state,
                job.status,
                effect.status,
                winning_workflow.state,
                authority_guard.terminal_receipt_id,
                authority_guard.source_closure_effect_intent_id,
                asf_observed_source_closure_is_valid(work.tenant_id, work.id)
            FROM work_items AS work
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = work.tenant_id
             AND workflow.id = $3
            JOIN workflow_jobs AS job
              ON job.tenant_id = work.tenant_id
             AND job.id = $4
            JOIN effect_intents AS effect
              ON effect.tenant_id = work.tenant_id
             AND effect.work_item_id = work.id
             AND effect.attempt_id = work.current_attempt_id
             AND effect.provider = 'linear'
             AND effect.effect_type = 'close_source'
            JOIN workflow_instances AS winning_workflow
              ON winning_workflow.tenant_id = work.tenant_id
             AND winning_workflow.id = $5
            JOIN work_cancellation_authority_guards AS authority_guard
              ON authority_guard.tenant_id = work.tenant_id
             AND authority_guard.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.workflow_id)
        .bind(fixture.job.id)
        .bind(winning_workflow_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load state preserved after the winning live child");
        assert_eq!(state.0, "CLOSING_SOURCE");
        assert_eq!(state.1, "ACTIVE");
        assert_eq!(state.2, "RUNNING");
        assert_eq!(state.3, "AMBIGUOUS");
        assert_eq!(state.4, "ACTIVE");
        assert!(state.5.is_none());
        assert!(state.6.is_none());
        assert!(!state.7);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_later_work_closure_release_requires_its_own_job_provenance() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        fixture.insert_active_reservation(&database.ledger).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway,
        )
        .expect("construct source-close handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("complete the real source closure before the provenance attack"),
            ActivityOutcome::TransactionCommitted
        );

        let (effect_observed_at, job_completed_at, forged_released_at): (
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        ) = sqlx::query_as(
            r"
            SELECT effect.observed_at,
                   job.completed_at,
                   effect.observed_at +
                       (job.completed_at - effect.observed_at) / 2
            FROM effect_intents AS effect
            JOIN workflow_jobs AS job
              ON job.tenant_id = effect.tenant_id
             AND job.id = effect.observing_workflow_job_id
            WHERE effect.tenant_id = $1
              AND effect.work_item_id = $2
              AND effect.provider = 'linear'
              AND effect.effect_type = 'close_source'
              AND effect.status = 'OBSERVED'
              AND job.id = $3
              AND job.status = 'COMPLETED'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load the real effect-observed/job-completed interval");
        assert!(effect_observed_at <= forged_released_at);
        assert!(forged_released_at <= job_completed_at);

        let forged_set_id = Uuid::now_v7();
        let forged_event_id = Uuid::now_v7();
        let forged_released_by = "reactor:forged-source-closure";
        assert_ne!(forged_released_by, fixture.job.lease_owner.as_str());
        let release_reason = "verified source closure completed the authoritative attempt";
        let transition_idempotency_key = format!(
            "work-closure:v1:{}:{}:{forged_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin late work-closure release attack");
        let insert_error = sqlx::query(
            r"
            INSERT INTO reservation_sets (
                id, tenant_id, work_item_id, attempt_id, repository_id,
                worker_id, worker_session_id, worker_generation,
                request_digest, idempotency_key, state, fence_token,
                acquired_by, acquired_at, expires_at,
                released_at, released_by, release_reason,
                transition_idempotency_key
            )
            SELECT
                $1, work.tenant_id, work.id, $3, work.repository_id,
                $4, $5, 1,
                $6, $7, 'RELEASED', 2,
                'scheduler:late-source-closure-attack', $8,
                $8 + interval '15 minutes',
                $9, $10, $11, $12
            FROM work_items AS work
            WHERE work.tenant_id = $2 AND work.id = $13
            ",
        )
        .bind(forged_set_id)
        .bind(fixture.tenant_id)
        .bind(fixture.attempt_id)
        .bind(fixture.worker_id)
        .bind(fixture.worker_session_id)
        .bind(digest("late-source-closure-reservation"))
        .bind(format!("late-source-closure-reservation:{forged_set_id}"))
        .bind(effect_observed_at)
        .bind(forged_released_at)
        .bind(forged_released_by)
        .bind(release_reason)
        .bind(&transition_idempotency_key)
        .bind(fixture.work_item_id)
        .execute(&mut *transaction)
        .await
        .expect_err("terminal finality must reject a late release-shaped reservation");
        let database_error = insert_error
            .as_database_error()
            .expect("forged work-closure release rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("cancellation_authority_facts_preserve_terminal_receipt")
        );
        transaction
            .rollback()
            .await
            .expect("roll back rejected late work-closure release attack");

        let forged_rows: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*)
                 FROM reservation_sets
                 WHERE tenant_id = $1
                   AND (id = $2 OR transition_idempotency_key = $4)),
                (SELECT count(*)
                 FROM reservation_set_events
                 WHERE tenant_id = $1
                   AND (id = $3 OR idempotency_key = $4))
            ",
        )
        .bind(fixture.tenant_id)
        .bind(forged_set_id)
        .bind(forged_event_id)
        .bind(&transition_idempotency_key)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rolled-back forged work-closure rows");
        assert_eq!(forged_rows, (0, 0));
        let closed_work_proof_valid: bool =
            sqlx::query_scalar("SELECT asf_observed_source_closure_is_valid($1, $2)")
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("revalidate the closed-work proof after the rejected release");
        assert!(closed_work_proof_valid);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn attempt_release_rejects_a_different_authoritative_worker() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let different_worker_id = Uuid::now_v7();
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin mismatched terminal reservation release");
        lock_attempt_reservation_release_authority(
            &mut transaction,
            fixture.tenant_id,
            fixture.work_item_id,
            different_worker_id,
        )
        .await
        .expect("lock proposed terminal reservation authority");
        let error = release_active_attempt_reservations(
            &mut transaction,
            fixture.tenant_id,
            fixture.work_item_id,
            fixture.attempt_id,
            different_worker_id,
            AttemptReservationReleaseNamespace::WorkClosure,
            &fixture.job.lease_owner,
            "verified source closure completed the authoritative attempt",
        )
        .await
        .expect_err("a different worker authority must not release the attempt reservation");
        assert!(matches!(error, Error::Conflict(_)));
        transaction
            .rollback()
            .await
            .expect("rollback mismatched terminal reservation release");

        let reservation: (String, i64, i64) = sqlx::query_as(
            r"
            SELECT reservation_set.state, reservation_set.fence_token,
                   count(event.id) FILTER (WHERE event.event_type = 'RELEASED')
            FROM reservation_sets AS reservation_set
            LEFT JOIN reservation_set_events AS event
              ON event.tenant_id = reservation_set.tenant_id
             AND event.reservation_set_id = reservation_set.id
            WHERE reservation_set.tenant_id = $1
              AND reservation_set.id = $2
            GROUP BY reservation_set.state, reservation_set.fence_token
            ",
        )
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load rejected terminal reservation release");
        assert_eq!(reservation, ("ACTIVE".into(), 1, 0));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn observation_uses_the_prelocked_claims_transaction_start_lease_boundary() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;

        // Exercise the production finalize path.  Its first operation locks
        // the exact live CLOSE_SOURCE claim; this test-only trigger then makes
        // wall time cross the lease deadline before the production observation
        // trigger runs.
        let fixture = Fixture::insert(&database.ledger, false).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct delayed source-close handler");
        let payload =
            SourceClosureJobPayload::parse(&fixture.job, TenantId::from_uuid(fixture.tenant_id))
                .expect("parse delayed source-close payload");
        let prepared = handler
            .prepare(&fixture.job, &payload)
            .await
            .expect("persist delayed source-close intent");
        let receipt = gateway
            .close_source(&prepared.request)
            .await
            .expect("obtain delayed source-close receipt");

        sqlx::raw_sql(
            r"
            CREATE TABLE asf_test_source_close_lease_timing (
                transaction_started_at timestamptz NOT NULL,
                wall_after_delay timestamptz NOT NULL,
                claim_deadline timestamptz NOT NULL
            );
            CREATE FUNCTION asf_test_delay_source_close_observation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            DECLARE
                deadline timestamptz;
            BEGIN
                IF NEW.provider = 'linear'
                   AND NEW.effect_type = 'close_source'
                   AND OLD.status <> 'OBSERVED'
                   AND NEW.status = 'OBSERVED' THEN
                    SELECT job.lease_expires_at
                    INTO STRICT deadline
                    FROM workflow_jobs AS job
                    WHERE job.tenant_id = NEW.tenant_id
                      AND job.id = OLD.owning_workflow_job_id;
                    PERFORM pg_sleep(3);
                    INSERT INTO asf_test_source_close_lease_timing (
                        transaction_started_at,
                        wall_after_delay,
                        claim_deadline
                    ) VALUES (
                        transaction_timestamp(),
                        clock_timestamp(),
                        deadline
                    );
                END IF;
                RETURN NEW;
            END;
            $$;
            CREATE TRIGGER aaa_test_delay_source_close_observation
                BEFORE UPDATE ON effect_intents
                FOR EACH ROW EXECUTE FUNCTION asf_test_delay_source_close_observation();
            ",
        )
        .execute(database.ledger.pool())
        .await
        .expect("install source-close lease-boundary delay");
        sqlx::query(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() + interval '2 seconds'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .execute(database.ledger.pool())
        .await
        .expect("shorten delayed source-close claim");

        handler
            .finalize(&fixture.job, &payload, &prepared, &receipt)
            .await
            .expect("commit the prelocked claim after its wall-clock deadline");
        let timing: (
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        ) = sqlx::query_as(
            r"
            SELECT transaction_started_at, wall_after_delay, claim_deadline
            FROM asf_test_source_close_lease_timing
            ",
        )
        .fetch_one(database.ledger.pool())
        .await
        .expect("load committed lease-boundary timing");
        assert!(
            timing.0 < timing.2,
            "the final transaction must begin while the exact claim is live"
        );
        assert!(
            timing.1 > timing.2,
            "the observation must reach its guard after wall-clock lease expiry"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM work_items WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load delayed source-close state"),
            "CLOSED"
        );
        sqlx::raw_sql(
            r"
            DROP TRIGGER aaa_test_delay_source_close_observation ON effect_intents;
            DROP FUNCTION asf_test_delay_source_close_observation();
            DROP TABLE asf_test_source_close_lease_timing;
            ",
        )
        .execute(database.ledger.pool())
        .await
        .expect("remove source-close lease-boundary delay");

        // Conversely, beginning after expiry grants no authority, even when a
        // direct writer supplies the otherwise exact owner and fence values.
        let expired_fixture = Fixture::insert(&database.ledger, false).await;
        let expired_gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let expired_handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(expired_fixture.tenant_id),
            expired_gateway.clone(),
        )
        .expect("construct expired source-close handler");
        let expired_payload = SourceClosureJobPayload::parse(
            &expired_fixture.job,
            TenantId::from_uuid(expired_fixture.tenant_id),
        )
        .expect("parse expired source-close payload");
        let expired_prepared = expired_handler
            .prepare(&expired_fixture.job, &expired_payload)
            .await
            .expect("persist expired source-close intent");
        let expired_receipt = expired_gateway
            .close_source(&expired_prepared.request)
            .await
            .expect("obtain exact expired source-close receipt");
        let expired_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() + interval '2 seconds'
            WHERE tenant_id = $1 AND id = $2
            RETURNING lease_expires_at
            ",
        )
        .bind(expired_fixture.tenant_id)
        .bind(expired_fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("shorten source-close claim before hostile transaction");
        sqlx::query("SELECT pg_sleep(3)")
            .execute(database.ledger.pool())
            .await
            .expect("let the source-close claim expire without mutating its anchored workflow");
        let mut hostile = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin post-expiry observation attack");
        let hostile_started_at: chrono::DateTime<Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *hostile)
                .await
                .expect("load hostile transaction start");
        assert!(hostile_started_at > expired_at);
        let error = sqlx::query(
            r"
            UPDATE effect_intents
            SET status = 'OBSERVED',
                observed_outcome = $3,
                observed_at = clock_timestamp(),
                observing_workflow_job_id = $4,
                observing_workflow_job_fence_token = $5,
                observing_workflow_job_completed_by = $6,
                owning_workflow_job_id = NULL,
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(expired_fixture.tenant_id)
        .bind(expired_prepared.effect_id)
        .bind(serde_json::to_value(&expired_receipt).expect("encode expired receipt"))
        .bind(expired_fixture.job.id)
        .bind(expired_fixture.job.fence_token)
        .bind(&expired_fixture.job.lease_owner)
        .execute(&mut *hostile)
        .await
        .expect_err("a transaction begun after expiry cannot fabricate observation");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("effect_intents_live_source_close_observer")
        );
        hostile
            .rollback()
            .await
            .expect("rollback post-expiry observation attack");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM effect_intents WHERE tenant_id = $1 AND id = $2",
            )
            .bind(expired_fixture.tenant_id)
            .bind(expired_prepared.effect_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load protected expired source-close intent"),
            "IN_FLIGHT"
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn signing_authority_upgrade_refuses_unverifiable_legacy_run_history() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create_through_0010(&database_url).await;
        let _fixture = Fixture::insert(&database.ledger, false).await;
        let mut upgrade = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin signing-authority upgrade");
        let error = sqlx::raw_sql(include_str!(
            "../../migrations/0011_worker_session_signing_authority.sql"
        ))
        .execute(&mut *upgrade)
        .await
        .expect_err("legacy run history has no reconstructable historical public key");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("worker_session_signing_authority_requires_verified_history")
        );
        upgrade
            .rollback()
            .await
            .expect("rollback refused signing-authority upgrade");
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS (\
                    SELECT 1 FROM information_schema.columns \
                    WHERE table_schema = current_schema() \
                      AND table_name = 'worker_sessions' \
                      AND column_name = 'signing_public_key'\
                )"
            )
            .fetch_one(database.ledger.pool())
            .await
            .expect("verify upgrade rollback")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn shared_finality_upgrade_backfills_closed_source_closure() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create_through_0018(&database_url).await;
        let fixture = Fixture::insert(&database.ledger, false).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway,
        )
        .expect("construct pre-0019 source-close handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("close source under 0018"),
            ActivityOutcome::TransactionCommitted
        );

        let guard_generation: i64 = sqlx::query_scalar(
            "SELECT generation FROM work_cancellation_authority_guards \
             WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load pre-0019 authority generation");
        let observed_effect_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM effect_intents \
             WHERE tenant_id = $1 AND work_item_id = $2 AND attempt_id = $3 \
               AND provider = 'linear' AND effect_type = 'close_source' AND status = 'OBSERVED'",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load exact pre-0019 observed source-close effect");

        let mut upgrade = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin shared-finality upgrade");
        sqlx::raw_sql(include_str!(
            "../../migrations/0019_shared_work_finality_gate.sql"
        ))
        .execute(&mut *upgrade)
        .await
        .expect("apply shared-finality upgrade");
        upgrade
            .commit()
            .await
            .expect("commit shared-finality upgrade");

        let guard: (i64, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT generation, terminal_receipt_id, source_closure_effect_intent_id \
             FROM work_cancellation_authority_guards \
             WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load backfilled shared-finality guard");
        assert_eq!(
            guard,
            (guard_generation + 1, None, Some(observed_effect_id))
        );
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT asf_observed_source_closure_is_valid($1, $2)")
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("validate backfilled source closure")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn shared_finality_upgrade_rejects_historical_closed_work_with_live_workflow() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create_through_0018(&database_url).await;
        let fixture = Fixture::insert(&database.ledger, false).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway,
        )
        .expect("construct pre-0019 source-close handler");
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect("close source under 0018");

        let historical_workflow_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state, reducer_version
            ) VALUES ($1, $2, $3, $4, 'ACTIVE', 'asf.workflow/v1')
            ",
        )
        .bind(historical_workflow_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!(
            "HISTORICAL_LIVE_WORKFLOW_{}",
            historical_workflow_id.simple()
        ))
        .execute(database.ledger.pool())
        .await
        .expect("commit pre-0019 unrelated active workflow");

        let mut upgrade = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin invalid shared-finality upgrade");
        let error = sqlx::raw_sql(include_str!(
            "../../migrations/0019_shared_work_finality_gate.sql"
        ))
        .execute(&mut *upgrade)
        .await
        .expect_err("historical live workflow must reject shared-finality upgrade");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("shared_work_finality_upgrade_requires_exact_closure")
        );
        upgrade
            .rollback()
            .await
            .expect("roll back rejected shared-finality upgrade");
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS (\
                    SELECT 1 FROM information_schema.columns \
                    WHERE table_schema = current_schema() \
                      AND table_name = 'work_cancellation_authority_guards' \
                      AND column_name = 'source_closure_effect_intent_id'\
                )"
            )
            .fetch_one(database.ledger.pool())
            .await
            .expect("verify rejected shared-finality upgrade rolled back")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn invalid_worker_signature_never_reaches_linear_authority() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = Fixture::insert_with_signature_tamper(&database.ledger, false, true).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err(),
            "a key-ID match cannot substitute for signature verification"
        );
        assert_eq!(gateway.counts().await, (0, 0));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM effect_intents WHERE tenant_id = $1 AND work_item_id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count rejected signature effects"),
            0
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn wrong_contract_claimed_job_never_reaches_linear_authority() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = Fixture::insert(&database.ledger, false).await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        let mut wrong_contract = fixture.job.clone();
        wrong_contract.activity_contract_id = "asf.activity/close-source/v2".into();
        let error = handler
            .execute(&wrong_contract, ActivityControls::new(false))
            .await
            .expect_err("a wrong-contract claimed job must fail closed");
        assert!(matches!(error, Error::Validation(_)));
        assert_eq!(gateway.counts().await, (0, 0));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn forged_wrong_contract_owning_row_cannot_satisfy_source_closure_authority_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        // Persist the owning row with a wrong contract from its initial INSERT:
        // migration 0023's immutability trigger rejects any later UPDATE of
        // activity_contract_id, so the mismatch must be born with the row.
        // The in-memory claim (and its job_type) stays canonical, so the SQL
        // predicate, not the caller-supplied struct, is what decides authority.
        let fixture = Fixture::insert_with_wrong_persisted_contract(
            &database.ledger,
            "asf.activity/close-source/v2",
        )
        .await;
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err(),
            "a persisted row with a non-canonical activity contract must never satisfy \
             source-closure authority, regardless of the caller's claimed contract"
        );
        assert_eq!(gateway.counts().await, (0, 0));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn wrong_contract_owning_row_cannot_satisfy_effect_intent_owner_trigger_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        // Unlike `forged_wrong_contract_owning_row_cannot_satisfy_source_closure_authority_sql`,
        // which proves the SQL job-claim lock (`lock_exact_job_claim`) rejects
        // a wrong-contract RUNNING job before any binding is even read, this
        // test proves the separate `effect_intents_exact_external_mutation_owner`
        // database trigger (migration 0024's activity-contract predicate)
        // independently rejects the same wrong-contract row as an effect
        // *owner*. It never calls handler validation or the job-claim lock;
        // it issues the exact raw INSERT that `persist_or_adopt_effect` uses,
        // directly against `effect_intents`.
        let fixture = Fixture::insert_with_wrong_persisted_contract(
            &database.ledger,
            "asf.activity/close-source/v2",
        )
        .await;

        let source_snapshot_id: Uuid =
            sqlx::query_scalar("SELECT id FROM source_snapshots WHERE tenant_id = $1")
                .bind(fixture.tenant_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load fixture source snapshot");

        let closure = SourceClosure {
            work_item_id: WorkItemId::from_uuid(fixture.work_item_id),
            target: ClosureTarget::PullRequest,
            pull_request: Some(fixture.verification.pull_request.clone()),
            evidence_id: EvidenceId::from_uuid(fixture.evidence_id),
            evidence_digest: fixture.bundle.bundle_digest.clone(),
            final_outcome_summary: format!(
                "Verified pull request {}#{} at {}",
                fixture.verification.pull_request.repository,
                fixture.verification.pull_request.number,
                fixture.verification.pull_request.head_sha
            ),
            cost_microunits: Some(
                usd_to_microunits(fixture.bundle.statement.predicate.budget.cost_usd)
                    .expect("encode fixture cost as microunits"),
            ),
            wall_time_seconds: Some(
                fixture
                    .bundle
                    .statement
                    .predicate
                    .budget
                    .elapsed_ms
                    .div_ceil(1_000),
            ),
        };
        let effect = SourceCloseEffect::new(
            SourceItemRef {
                tenant_id: TenantId::from_uuid(fixture.tenant_id),
                source: SourceSystem::Linear,
                external_id: "ASF-42".into(),
            },
            "linear-rev-1",
            digest("source-snapshot"),
            stable_source_close_correlation(fixture.work_item_id, fixture.evidence_id),
            closure,
        )
        .expect("build canonical source-close effect");
        let request = CloseSourceRequest::new(
            stable_source_close_idempotency(fixture.work_item_id, fixture.evidence_id),
            effect,
            Utc::now(),
        )
        .expect("build canonical source-close request");
        let request_digest = sha256_digest(
            &canonical_json(&request).expect("canonicalize canonical source-close request"),
        );
        let request_payload =
            serde_json::to_value(&request).expect("encode canonical source-close request");
        let effect_id = stable_source_close_effect_id(fixture.evidence_id);

        let insert_error = sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, correlation_marker, request_digest,
                request_payload, attempt_count, next_attempt_at, fence_token,
                lease_owner, lease_expires_at, owning_workflow_job_id,
                source_snapshot_id, source_revision, source_snapshot_digest,
                evidence_id, evidence_digest
            ) VALUES (
                $1, $2, $3, $4, 'linear', 'close_source', 'IN_FLIGHT',
                $5, $6, $7, $8, 1, clock_timestamp(), $9, $10, $11, $12,
                $13, $14, $15, $16, $17
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&request.idempotency_key)
        .bind(&request.effect.correlation_marker)
        .bind(&request_digest)
        .bind(&request_payload)
        .bind(fixture.job.fence_token)
        .bind(&fixture.job.lease_owner)
        .bind(fixture.job.lease_expires_at)
        .bind(fixture.job.id)
        .bind(source_snapshot_id)
        .bind("linear-rev-1")
        .bind(digest("source-snapshot"))
        .bind(fixture.evidence_id)
        .bind(&fixture.bundle.bundle_digest)
        .execute(database.ledger.pool())
        .await
        .expect_err(
            "a wrong-contract RUNNING job must never satisfy the exact \
             external-mutation owner trigger",
        );
        let database_error = insert_error
            .as_database_error()
            .expect("owner-trigger rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("effect_intents_exact_external_mutation_owner")
        );

        let persisted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM effect_intents WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(effect_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rejected source-close effect rows");
        assert_eq!(persisted, 0);

        database.cleanup().await;
    }

    #[tokio::test]
    async fn historical_worker_session_key_remains_authoritative_after_worker_rotation() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        sqlx::query(
            r"
            UPDATE worker_sessions
            SET status = 'CLOSED',
                closed_at = clock_timestamp(),
                close_reason = 'test signing-authority rotation'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.worker_session_id)
        .execute(database.ledger.pool())
        .await
        .expect("close historical worker session");
        sqlx::query(
            r"
            UPDATE workers
            SET status = 'REGISTERED',
                generation = generation + 1,
                signing_key_id = 'runmill-worker:test-rotated',
                signing_public_key = 'test-rotated-public-key',
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id)
        .execute(database.ledger.pool())
        .await
        .expect("rotate current worker authority");

        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect("close from immutable historical session authority");
        assert_eq!(gateway.counts().await, (1, 0));
        let state: String =
            sqlx::query_scalar("SELECT state FROM work_items WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load session-authorized closure");
        assert_eq!(state, "CLOSED");
        database.cleanup().await;
    }

    #[tokio::test]
    async fn lost_response_becomes_reconciliation_only_and_never_resends() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let gateway = Arc::new(FakeGateway::new(GatewayMode::LoseFirstResponse));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err()
        );
        let status: String = sqlx::query_scalar(
            "SELECT status FROM effect_intents WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load ambiguous effect");
        assert_eq!(status, "AMBIGUOUS");

        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect("reconcile lost Linear response");
        assert_eq!(gateway.counts().await, (1, 1));
        let state: (String, String) = sqlx::query_as(
            r"
            SELECT work.state, effect.status
            FROM work_items AS work
            JOIN effect_intents AS effect
              ON effect.tenant_id = work.tenant_id AND effect.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load reconciled closure");
        assert_eq!(state, ("CLOSED".into(), "OBSERVED".into()));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn stale_job_fence_and_contradictory_receipt_never_close_work() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        let mut stale = fixture.job.clone();
        stale.fence_token += 1;
        assert!(
            handler
                .execute(&stale, ActivityControls::new(false))
                .await
                .is_err()
        );
        assert_eq!(gateway.counts().await, (0, 0));
        let effects: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM effect_intents WHERE tenant_id = $1 AND work_item_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count stale-fence effects");
        assert_eq!(effects, 0);
        database.cleanup().await;

        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        let gateway = Arc::new(FakeGateway::new(GatewayMode::ContradictReceipt));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err()
        );
        let state: (String, String) = sqlx::query_as(
            r"
            SELECT work.state, effect.status
            FROM work_items AS work
            JOIN effect_intents AS effect
              ON effect.tenant_id = work.tenant_id AND effect.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load contradictory receipt state");
        assert_eq!(state, ("CLOSING_SOURCE".into(), "AMBIGUOUS".into()));
        assert_eq!(gateway.counts().await, (1, 0));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn evidence_and_source_cross_bindings_fail_before_linear_authority() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let cross_bound = Fixture::try_insert_with_signature_tamper(
            &database.ledger,
            true,
            false,
            CLOSE_SOURCE_ACTIVITY_CONTRACT_ID,
        );
        let rejection = cross_bound
            .await
            .expect_err("a cross-bound VALID receipt must fail at ledger insertion");
        assert_eq!(
            rejection
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("evidence_verifications_require_exact_completed_job"),
            "the independently observed head must be relationally bound before source authority exists"
        );
        database.cleanup().await;

        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        sqlx::query(
            "UPDATE work_items SET source_external_id = 'ASF-CROSS-BOUND', aggregate_version = aggregate_version + 1 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .execute(database.ledger.pool())
        .await
        .expect("install source cross-binding fixture");
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err()
        );
        assert_eq!(gateway.counts().await, (0, 0));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn final_transaction_failure_rolls_back_and_recovers_only_by_reconciliation() {
        let Some((database, fixture)) = setup(false).await else {
            return;
        };
        sqlx::raw_sql(
            r"
            CREATE FUNCTION asf_test_reject_source_close_audit() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.action = 'SOURCE_CLOSED' THEN
                    RAISE EXCEPTION 'injected source-close audit failure';
                END IF;
                RETURN NEW;
            END;
            $$;
            CREATE TRIGGER asf_test_reject_source_close_audit
                BEFORE INSERT ON audit_events
                FOR EACH ROW EXECUTE FUNCTION asf_test_reject_source_close_audit();
            ",
        )
        .execute(database.ledger.pool())
        .await
        .expect("install atomic rollback trigger");
        let gateway = Arc::new(FakeGateway::new(GatewayMode::Applied));
        let handler = LinearSourceClosureHandler::new(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            gateway.clone(),
        )
        .expect("construct source-close handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err()
        );
        let rolled_back: (String, String, String, i64, i64) = sqlx::query_as(
            r"
            SELECT
                work.state, workflow.state, effect.status,
                (SELECT count(*) FROM audit_events WHERE tenant_id = work.tenant_id),
                (SELECT count(*) FROM outbox WHERE tenant_id = work.tenant_id)
            FROM work_items AS work
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = work.tenant_id AND workflow.id = $3
            JOIN effect_intents AS effect
              ON effect.tenant_id = work.tenant_id AND effect.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.workflow_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load rolled-back closure");
        assert_eq!(
            rolled_back,
            (
                "CLOSING_SOURCE".into(),
                "ACTIVE".into(),
                "AMBIGUOUS".into(),
                0,
                0,
            )
        );
        assert_eq!(gateway.counts().await, (1, 0));

        sqlx::raw_sql(
            r"
            DROP TRIGGER asf_test_reject_source_close_audit ON audit_events;
            DROP FUNCTION asf_test_reject_source_close_audit();
            ",
        )
        .execute(database.ledger.pool())
        .await
        .expect("remove atomic rollback trigger");
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect("reconcile after local atomic rollback");
        assert_eq!(gateway.counts().await, (1, 1));
        let state: String =
            sqlx::query_scalar("SELECT state FROM work_items WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load recovered work state");
        assert_eq!(state, "CLOSED");
        database.cleanup().await;
    }

    async fn assert_source_closure_finality_preserved(
        transaction: &mut Transaction<'_, Postgres>,
        fixture: &Fixture,
        expected_guard: &SourceClosureFinalityGuard,
        rejected_ids: [Uuid; 4],
    ) {
        let rejected_rows: (bool, bool, bool, bool) = sqlx::query_as(
            r"
            SELECT
                EXISTS (
                    SELECT 1
                    FROM workflow_instances
                    WHERE tenant_id = $1 AND id = $3
                ),
                EXISTS (
                    SELECT 1
                    FROM workflow_jobs
                    WHERE tenant_id = $1 AND id = $4
                ),
                EXISTS (
                    SELECT 1
                    FROM workflow_timers
                    WHERE tenant_id = $1 AND id = $5
                ),
                EXISTS (
                    SELECT 1
                    FROM effect_intents
                    WHERE tenant_id = $1 AND id = $6
                )
            FROM work_items
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(rejected_ids[0])
        .bind(rejected_ids[1])
        .bind(rejected_ids[2])
        .bind(rejected_ids[3])
        .fetch_one(&mut **transaction)
        .await
        .expect("prove rejected post-closure children are absent");
        assert_eq!(rejected_rows, (false, false, false, false));

        let actual_guard: SourceClosureFinalityGuard = sqlx::query_as(
            r"
            SELECT
                generation,
                terminal_receipt_id,
                source_closure_effect_intent_id,
                updated_at
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(&mut **transaction)
        .await
        .expect("reload frozen source-closure guard after rejected child");
        assert_eq!(&actual_guard, expected_guard);
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT asf_observed_source_closure_is_valid($1, $2)",)
                .bind(fixture.tenant_id)
                .bind(fixture.work_item_id)
                .fetch_one(&mut **transaction)
                .await
                .expect("revalidate source closure after rejected child")
        );
    }

    async fn setup(wrong_observed_head: bool) -> Option<(ScopedDatabase, Fixture)> {
        let database_url = std::env::var("ASF_TEST_DATABASE_URL").ok()?;
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = Fixture::insert(&database.ledger, wrong_observed_head).await;
        Some((database, fixture))
    }

    fn digest(label: &str) -> String {
        sha256_digest(label.as_bytes())
    }

    fn valid_budget_limits() -> Value {
        json!({
            "max_cost_microunits": 10_000_000,
            "max_input_tokens": 100_000,
            "max_output_tokens": 100_000,
            "max_implementer_invocations": 2,
            "max_reviewer_invocations": 2,
            "max_fix_iterations": 2,
            "max_wall_time_seconds": 7_200,
            "max_external_api_calls": 20
        })
    }

    fn valid_identity_requirements() -> Value {
        json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "claude:pr-reviewer"
        })
    }
}
