//! Production Runmill cancellation activity.
//!
//! Cancellation is an incident-control operation, so maintenance mode never
//! suppresses it. The handler durably records one stable Runmill request, drops
//! all database locks before socket I/O, then re-locks and verifies the complete
//! authoritative run/workflow coordinates. It commits the run observation,
//! workflow-job completion, audit, outbox, and accountability replacement as
//! one fenced `PostgreSQL` transaction.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, JobClaimScope, JobHandler, REQUEST_WORK_ITEM_CANCELLATION,
    REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
};
use crate::{
    Error, Result,
    adapters::{
        RUNMILL_CANCELLATION_SCHEMA, RunmillCancellationDisposition, RunmillCancellationMode,
        RunmillCancellationRequest, RunmillCancellationRequester, RunmillCancellationResult,
        RunmillControlClient, RunmillControlError, RunmillRunId, RunmillRunPhase,
        RunmillRunSnapshot,
    },
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
    domain::{TenantId, WorkerId},
    ledger::{
        AccountabilityReplacement, AttemptReservationReleaseNamespace, ClaimedWorkflowJob,
        LedgerAccountabilityKind, PgLedger, StepAuditEvent, StepOutboxMessage, StepWorkflowJob,
        WorkflowStepCommit, WorkflowStepCommitOutcome, WorkflowStepFence,
        commit_workflow_step_with_prelocked_claim, lock_attempt_reservation_release_authority,
        release_active_attempt_reservations,
    },
    security::reject_sensitive_fields,
};

const TERMINAL_CONFLICT_DEADLINE_HOURS: i64 = 4;
const TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON: &str =
    "terminal Runmill cancellation observation completed the authoritative attempt";

#[async_trait]
trait CancellationControl: Send + Sync + fmt::Debug {
    async fn get_run(
        &self,
        run_id: &RunmillRunId,
    ) -> std::result::Result<RunmillRunSnapshot, RunmillControlError>;

    async fn request_cancel(
        &self,
        request: &RunmillCancellationRequest,
    ) -> std::result::Result<RunmillCancellationResult, RunmillControlError>;
}

#[async_trait]
impl CancellationControl for RunmillControlClient {
    async fn get_run(
        &self,
        run_id: &RunmillRunId,
    ) -> std::result::Result<RunmillRunSnapshot, RunmillControlError> {
        RunmillControlClient::get_run(self, run_id).await
    }

    async fn request_cancel(
        &self,
        request: &RunmillCancellationRequest,
    ) -> std::result::Result<RunmillCancellationResult, RunmillControlError> {
        RunmillControlClient::request_cancel(self, request).await
    }
}

/// Exact Runmill cancellation handler used by `asf-server all`.
#[derive(Clone)]
pub struct RunmillCancellationHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    worker_id: WorkerId,
    control: Arc<dyn CancellationControl>,
    controller_subject: String,
    grace_seconds: u16,
}

impl fmt::Debug for RunmillCancellationHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillCancellationHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("worker_id", &self.worker_id)
            .field("control", &"RunmillControlClient([REDACTED])")
            .field("controller_subject", &self.controller_subject)
            .field("grace_seconds", &self.grace_seconds)
            .finish()
    }
}

impl RunmillCancellationHandler {
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: RunmillControlClient,
        controller_subject: impl Into<String>,
        grace_seconds: u16,
    ) -> Result<Self> {
        Self::with_control(
            ledger,
            tenant_id,
            worker_id,
            Arc::new(control),
            controller_subject,
            grace_seconds,
        )
    }

    fn with_control(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: Arc<dyn CancellationControl>,
        controller_subject: impl Into<String>,
        grace_seconds: u16,
    ) -> Result<Self> {
        let controller_subject = controller_subject.into();
        let validation_request = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: "asf-cancel:configuration-check".into(),
            run_id: RunmillRunId::parse("run_00000000000000000000000000000000").map_err(
                |error| Error::Validation(format!("invalid cancellation handler: {error}")),
            )?,
            requester: RunmillCancellationRequester {
                subject: controller_subject.clone(),
                authority: "asf:cancel".into(),
            },
            reason: "configuration check".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds,
        };
        validation_request
            .validate()
            .map_err(|error| Error::Validation(format!("invalid cancellation handler: {error}")))?;
        if worker_id.as_uuid().is_nil() {
            return Err(Error::Validation(
                "invalid cancellation handler: worker ID must be non-nil".into(),
            ));
        }
        Ok(Self {
            ledger,
            tenant_id,
            worker_id,
            control,
            controller_subject,
            grace_seconds,
        })
    }

    async fn execute_inner(&self, job: &ClaimedWorkflowJob) -> Result<ActivityOutcome> {
        if job.tenant_id != self.tenant_id.as_uuid() {
            return Err(Error::Validation(format!(
                "cancellation job {} crosses the configured tenant boundary",
                job.id
            )));
        }
        let payload = CancellationJobPayload::parse(job)?;
        if payload.worker_id != self.worker_id {
            return Err(Error::Validation(format!(
                "cancellation job {} is routed to worker {}, not configured worker {}",
                job.id, payload.worker_id, self.worker_id
            )));
        }
        if payload.observe_only {
            return self.observe_cancellation(job, &payload).await;
        }
        if self.observed_cancellation_effect_exists(job).await? {
            return self.observe_cancellation(job, &payload).await;
        }
        let (binding, request, request_digest, effect_id) =
            self.prepare_cancellation_effect(job, &payload).await?;
        let external_run_id = RunmillRunId::parse(binding.external_run_id.clone())
            .map_err(|error| incompatible_binding(job.id, &error))?;

        // Read before mutating so a stale external run ID can never receive
        // cancellation authority merely because it is syntactically valid.
        let initial = match self.control.get_run(&external_run_id).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.record_effect_failure(job, effect_id, &request_digest, &error, false)
                    .await?;
                return Err(control_failure(&error));
            }
        };
        if let Err(error) = binding.validate_external(&initial, job.id) {
            self.record_effect_validation_failure(
                job,
                effect_id,
                &request_digest,
                &error.to_string(),
                false,
            )
            .await?;
            return Err(error);
        }

        let result = match self.control.request_cancel(&request).await {
            Ok(result) => result,
            Err(error @ RunmillControlError::AmbiguousOutcome { .. }) => {
                // A mutation response may be lost after Runmill durably fenced
                // the run. Re-read the same run, then retry the *unchanged*
                // request ID/body so Runmill can return its existing record.
                let reconciled = match self.control.get_run(&external_run_id).await {
                    Ok(snapshot) => snapshot,
                    Err(read_error) => {
                        self.record_effect_failure(job, effect_id, &request_digest, &error, true)
                            .await?;
                        return Err(control_failure(&read_error));
                    }
                };
                if let Err(binding_error) = binding.validate_external(&reconciled, job.id) {
                    self.record_effect_validation_failure(
                        job,
                        effect_id,
                        &request_digest,
                        &binding_error.to_string(),
                        true,
                    )
                    .await?;
                    return Err(binding_error);
                }
                match self.control.request_cancel(&request).await {
                    Ok(result) => result,
                    Err(retry_error) => {
                        self.record_effect_failure(
                            job,
                            effect_id,
                            &request_digest,
                            &retry_error,
                            true,
                        )
                        .await?;
                        return Err(control_failure(&retry_error));
                    }
                }
            }
            Err(error) => {
                self.record_effect_failure(job, effect_id, &request_digest, &error, false)
                    .await?;
                return Err(control_failure(&error));
            }
        };
        if result.request_digest != request_digest {
            self.record_effect_validation_failure(
                job,
                effect_id,
                &request_digest,
                "Runmill returned a contradictory request digest",
                true,
            )
            .await?;
            return Err(Error::ExternalUnavailable(
                "Runmill cancellation returned a contradictory request digest".into(),
            ));
        }

        // Observe once more after the mutation. Cancellation can finish before
        // its acknowledgement reaches ASF; routing from the follow-up snapshot
        // avoids installing a live-run anchor for an already-terminal run.
        let observed = match self.control.get_run(&external_run_id).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.record_effect_failure(job, effect_id, &request_digest, &error, true)
                    .await?;
                return Err(control_failure(&error));
            }
        };
        if let Err(error) = binding.validate_external(&observed, job.id) {
            self.record_effect_validation_failure(
                job,
                effect_id,
                &request_digest,
                &error.to_string(),
                true,
            )
            .await?;
            return Err(error);
        }
        if let Err(error) = validate_result_and_observation(&request, &result, &observed) {
            self.record_effect_validation_failure(
                job,
                effect_id,
                &request_digest,
                &error.to_string(),
                true,
            )
            .await?;
            return Err(error);
        }

        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin Runmill cancellation commit: {error}"))
        })?;
        let final_binding =
            match lock_cancellation_claim_and_binding(&mut transaction, job, &payload).await {
                Ok(binding) => binding,
                Err(error) => {
                    drop(transaction);
                    self.record_effect_validation_failure(
                        job,
                        effect_id,
                        &request_digest,
                        "authoritative cancellation binding changed after Runmill mutation",
                        true,
                    )
                    .await?;
                    return Err(error);
                }
            };
        if !binding.same_authoritative_coordinates(&final_binding) {
            drop(transaction);
            self.record_effect_validation_failure(
                job,
                effect_id,
                &request_digest,
                "authoritative run coordinates changed after Runmill cancellation",
                true,
            )
            .await?;
            return Err(Error::Conflict(format!(
                "cancellation job {} authoritative run changed after remote cancellation",
                job.id
            )));
        }

        persist_cancellation(
            &mut transaction,
            job,
            &payload,
            &final_binding,
            &request,
            &result,
            &observed,
            &request_digest,
            effect_id,
            CancellationEffectCommit::ObserveInFlight,
            None,
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit Runmill cancellation transaction: {error}"))
        })?;
        Ok(ActivityOutcome::TransactionCommitted)
    }

    async fn observed_cancellation_effect_exists(&self, job: &ClaimedWorkflowJob) -> Result<bool> {
        let work_item_id = job.work_item_id.ok_or_else(|| {
            Error::Validation(format!(
                "cancellation job {} has no work-item binding",
                job.id
            ))
        })?;
        let attempt_id = job.attempt_id.ok_or_else(|| {
            Error::Validation(format!(
                "cancellation job {} has no attempt binding",
                job.id
            ))
        })?;
        sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM effect_intents
                WHERE tenant_id = $1
                  AND work_item_id = $2
                  AND attempt_id = $3
                  AND provider = 'runmill'
                  AND effect_type = 'request_cancellation'
                  AND status = 'OBSERVED'
            )
            ",
        )
        .bind(job.tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .fetch_one(self.ledger.pool())
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "check for an observed Runmill cancellation effect: {error}"
            ))
        })
    }

    async fn observe_cancellation(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &CancellationJobPayload,
    ) -> Result<ActivityOutcome> {
        let (binding, intent) = self.prepare_cancellation_observation(job, payload).await?;
        let observed = self
            .control
            .get_run(&intent.request.run_id)
            .await
            .map_err(|error| control_failure(&error))?;
        binding.validate_external(&observed, job.id)?;
        validate_cancellation_observation_progress(&intent.latest_observation, &observed)?;

        if !observed.run.state.terminal() {
            self.record_cancellation_observer_progress(job, payload, &binding, &intent, &observed)
                .await?;
            let retry_at = Utc::now()
                .checked_add_signed(Duration::seconds(i64::from(intent.request.grace_seconds)))
                .ok_or_else(|| {
                    Error::Validation("Runmill cancellation observation retry overflowed".into())
                })?;
            return Ok(ActivityOutcome::Retry {
                error: format!(
                    "Runmill cancellation {} remains {}; terminal observation is still required",
                    intent.request.request_id,
                    phase_name(observed.run.state)
                ),
                retry_at,
            });
        }

        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!(
                "begin Runmill terminal cancellation observation: {error}"
            ))
        })?;
        let final_binding =
            lock_cancellation_claim_and_binding(&mut transaction, job, payload).await?;
        if !binding.same_authoritative_coordinates(&final_binding) {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} authoritative run changed after Runmill read",
                job.id
            )));
        }
        let final_intent =
            load_observed_cancellation_intent(&mut transaction, job, &final_binding).await?;
        if final_intent != intent {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} durable effect receipt changed after Runmill read",
                job.id
            )));
        }
        let result = intent.result();

        persist_cancellation(
            &mut transaction,
            job,
            payload,
            &final_binding,
            &intent.request,
            &result,
            &observed,
            &intent.request_digest,
            intent.effect_id,
            CancellationEffectCommit::AlreadyObserved,
            Some(&intent.latest_observation),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!(
                "commit Runmill terminal cancellation observation: {error}"
            ))
        })?;
        Ok(ActivityOutcome::TransactionCommitted)
    }

    async fn record_cancellation_observer_progress(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &CancellationJobPayload,
        binding: &CancellationBinding,
        intent: &ObservedCancellationIntent,
        observed: &RunmillRunSnapshot,
    ) -> Result<()> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!(
                "begin Runmill cancellation observer progress: {error}"
            ))
        })?;
        let final_binding =
            lock_cancellation_claim_and_binding(&mut transaction, job, payload).await?;
        if !binding.same_authoritative_coordinates(&final_binding) {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} authoritative run changed after Runmill read",
                job.id
            )));
        }
        let final_intent =
            load_observed_cancellation_intent(&mut transaction, job, &final_binding).await?;
        if &final_intent != intent {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} observation chain changed after Runmill read",
                job.id
            )));
        }
        validate_cancellation_observation_progress(&final_intent.latest_observation, observed)?;
        let result = final_intent.result();
        insert_cancellation_observation(
            &mut transaction,
            job,
            &final_binding,
            final_intent.effect_id,
            &final_intent.request,
            &result,
            observed,
            &final_intent.request_digest,
            CancellationObservationRoute::Observer,
            Some(final_intent.latest_observation.id),
            Utc::now(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!(
                "commit Runmill cancellation observer progress: {error}"
            ))
        })?;
        Ok(())
    }

    async fn prepare_cancellation_observation(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &CancellationJobPayload,
    ) -> Result<(CancellationBinding, ObservedCancellationIntent)> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!(
                "begin Runmill cancellation observation preflight: {error}"
            ))
        })?;
        let binding = lock_cancellation_claim_and_binding(&mut transaction, job, payload).await?;
        let intent = load_observed_cancellation_intent(&mut transaction, job, &binding).await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!(
                "commit Runmill cancellation observation preflight: {error}"
            ))
        })?;
        Ok((binding, intent))
    }

    async fn prepare_cancellation_effect(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &CancellationJobPayload,
    ) -> Result<(
        CancellationBinding,
        RunmillCancellationRequest,
        String,
        Uuid,
    )> {
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin Runmill cancellation preflight: {error}"))
        })?;
        // Keep the global recovery order job -> worker/budget authority ->
        // aggregates -> effect. Besides the explicit binding locks below, the
        // effect's exact-owner foreign key takes a key-share lock on the job row
        // when the intent is inserted or adopted.
        let binding = lock_cancellation_claim_and_binding(&mut transaction, job, payload).await?;
        let proposed_request = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: stable_cancellation_request_id(
                binding.tenant_id,
                binding.work_item_id,
                binding.attempt_id,
                binding.internal_run_id,
            ),
            run_id: RunmillRunId::parse(binding.external_run_id.clone())
                .map_err(|error| incompatible_binding(job.id, &error))?,
            requester: RunmillCancellationRequester {
                subject: self.controller_subject.clone(),
                authority: "asf:cancel".into(),
            },
            reason: payload.reason.clone(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: self.grace_seconds,
        };
        let effect_id = stable_cancellation_effect_id(binding.internal_run_id);
        let (request, request_digest) = persist_or_adopt_effect_intent(
            &mut transaction,
            job,
            &binding,
            proposed_request,
            effect_id,
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit Runmill cancellation preflight: {error}"))
        })?;
        Ok((binding, request, request_digest, effect_id))
    }

    async fn record_effect_failure(
        &self,
        job: &ClaimedWorkflowJob,
        effect_id: Uuid,
        request_digest: &str,
        error: &RunmillControlError,
        ambiguous: bool,
    ) -> Result<()> {
        update_effect_failure(
            self.ledger.pool(),
            job,
            effect_id,
            request_digest,
            &error.to_string(),
            ambiguous,
        )
        .await
    }

    async fn record_effect_validation_failure(
        &self,
        job: &ClaimedWorkflowJob,
        effect_id: Uuid,
        request_digest: &str,
        error: &str,
        ambiguous: bool,
    ) -> Result<()> {
        update_effect_failure(
            self.ledger.pool(),
            job,
            effect_id,
            request_digest,
            error,
            ambiguous,
        )
        .await
    }
}

#[async_trait]
impl JobHandler for RunmillCancellationHandler {
    fn job_type(&self) -> &str {
        REQUEST_WORK_ITEM_CANCELLATION
    }

    fn activity_contract_id(&self) -> &str {
        REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
    }

    fn claim_scope(&self) -> JobClaimScope {
        JobClaimScope::CancellationWorker(self.worker_id)
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        // Deliberately ignore maintenance mode: cancellation is a recovery and
        // containment operation, never a new dispatch effect.
        self.execute_inner(job).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancellationJobPayload {
    work_item_id: Uuid,
    worker_id: WorkerId,
    expected_version: i64,
    reason: String,
    requested_by: String,
    #[serde(default)]
    observe_only: bool,
}

impl CancellationJobPayload {
    fn parse(job: &ClaimedWorkflowJob) -> Result<Self> {
        if job.job_type != REQUEST_WORK_ITEM_CANCELLATION
            || job.activity_contract_id != REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
        {
            return Err(Error::Validation(format!(
                "cancellation handler cannot execute job type {:?} with activity contract {:?}",
                job.job_type, job.activity_contract_id
            )));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|_| {
            Error::Validation(format!(
                "cancellation job {} has an incompatible payload",
                job.id
            ))
        })?;
        if job.work_item_id != Some(payload.work_item_id)
            || job.workflow_instance_id.is_none()
            || job.attempt_id.is_none()
            || payload.work_item_id.is_nil()
            || payload.worker_id.as_uuid().is_nil()
            || payload.expected_version <= 0
            || payload.reason.trim().is_empty()
            || payload.reason.trim() != payload.reason
            || payload.reason.len() > 2_048
            || payload.requested_by.trim().is_empty()
            || payload.requested_by.len() > 1_024
        {
            return Err(Error::Validation(format!(
                "cancellation job {} is missing an exact workflow/work-item/attempt binding",
                job.id
            )));
        }
        reject_sensitive_fields(&json!({
            "reason": payload.reason,
            "requested_by": payload.requested_by,
        }))?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancellationEffectObservation {
    schema: String,
    status: String,
    request_id: String,
    request_digest: String,
    disposition: RunmillCancellationDisposition,
    external_phase: RunmillRunPhase,
    external_generation: u64,
    external_state_version: u64,
    external_latest_sequence: u64,
    reconciliation_required: bool,
    cancellation_observation_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedCancellationIntent {
    effect_id: Uuid,
    request: RunmillCancellationRequest,
    request_digest: String,
    outcome: CancellationEffectObservation,
    observed_at: chrono::DateTime<Utc>,
    latest_observation: CancellationObservationReceipt,
}

impl ObservedCancellationIntent {
    fn result(&self) -> RunmillCancellationResult {
        RunmillCancellationResult {
            request_id: self.outcome.request_id.clone(),
            run_id: self.request.run_id.clone(),
            disposition: self.outcome.disposition,
            state: self.outcome.external_phase,
            generation: self.outcome.external_generation,
            request_digest: self.request_digest.clone(),
            reconciliation_required: self.outcome.reconciliation_required,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationEffectCommit {
    ObserveInFlight,
    AlreadyObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationObservationRoute {
    Initial,
    Observer,
}

impl CancellationObservationRoute {
    const fn as_sql(self) -> &'static str {
        match self {
            Self::Initial => "INITIAL",
            Self::Observer => "OBSERVER",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CancellationObservationReceipt {
    id: Uuid,
    workflow_job_id: Uuid,
    workflow_job_fence_token: i64,
    workflow_job_attempt_count: i32,
    workflow_job_owner: String,
    route: String,
    prior_observation_id: Option<Uuid>,
    request_id: String,
    request_digest: String,
    disposition: String,
    external_phase: RunmillRunPhase,
    external_generation: u64,
    external_state_version: u64,
    external_latest_sequence: u64,
    reconciliation_required: bool,
    observed_at: chrono::DateTime<Utc>,
    receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CancellationObservationFact {
    id: Uuid,
    prior_id: Option<Uuid>,
}

#[derive(Debug)]
struct CancellationBinding {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    internal_run_id: Uuid,
    worker_id: WorkerId,
    external_run_id: String,
    attempt_aggregate_version: i64,
    attempt_fence_token: i64,
    attempt_state: String,
    work_item_version: i64,
    workflow_id: Uuid,
    workflow_version: i64,
    workflow_fence_token: i64,
    workflow_event_cursor: i64,
    anchor_generation: i64,
    run_aggregate_version: i64,
    run_state: String,
    attempt_ordinal: i32,
    repository: String,
    work_order_digest: String,
    policy_digest: Option<String>,
    work_order_key_id: String,
    work_order_algorithm: String,
}

impl CancellationBinding {
    fn from_row(row: &PgRow) -> Result<Self> {
        Ok(Self {
            tenant_id: required(row, "tenant_id", "tenant")?,
            work_item_id: required(row, "work_item_id", "work item")?,
            attempt_id: required(row, "attempt_id", "attempt")?,
            work_order_id: required(row, "work_order_id", "work order")?,
            internal_run_id: required(row, "internal_run_id", "run")?,
            worker_id: WorkerId::from_uuid(required(row, "worker_id", "worker")?),
            external_run_id: required(row, "external_run_id", "external run")?,
            attempt_aggregate_version: required(
                row,
                "attempt_aggregate_version",
                "attempt aggregate version",
            )?,
            attempt_fence_token: required(row, "attempt_fence_token", "attempt fence token")?,
            attempt_state: required(row, "attempt_state", "attempt state")?,
            work_item_version: required(row, "work_item_version", "work-item version")?,
            workflow_id: required(row, "workflow_id", "workflow")?,
            workflow_version: required(row, "workflow_version", "workflow version")?,
            workflow_fence_token: required(row, "workflow_fence_token", "workflow fence token")?,
            workflow_event_cursor: required(row, "workflow_event_cursor", "workflow event cursor")?,
            anchor_generation: required(row, "anchor_generation", "anchor generation")?,
            run_aggregate_version: required(row, "run_aggregate_version", "run aggregate version")?,
            run_state: required(row, "run_state", "run state")?,
            attempt_ordinal: required(row, "attempt_ordinal", "attempt ordinal")?,
            repository: required(row, "repository", "repository")?,
            work_order_digest: required(row, "work_order_digest", "work-order digest")?,
            policy_digest: optional(row, "policy_digest", "policy digest")?,
            work_order_key_id: required(row, "work_order_key_id", "work-order key ID")?,
            work_order_algorithm: required(row, "work_order_algorithm", "work-order algorithm")?,
        })
    }

    fn validate_external(&self, snapshot: &RunmillRunSnapshot, job_id: Uuid) -> Result<()> {
        let expected_idempotency = format!(
            "{}/{}/{}",
            self.tenant_id, self.work_item_id, self.attempt_id
        );
        let attempt_ordinal = u64::try_from(self.attempt_ordinal).map_err(|_| {
            Error::Validation(format!(
                "cancellation job {job_id} is bound to an invalid attempt ordinal"
            ))
        })?;
        let compatible = snapshot.admission.tenant_id == self.tenant_id.to_string()
            && snapshot.run.run_id.as_str() == self.external_run_id
            && snapshot.admission.idempotency_key == expected_idempotency
            && snapshot.run.attempt_id == self.attempt_id.to_string()
            && snapshot.admission.attempt_id == self.attempt_id.to_string()
            && snapshot.run.work_order_id == self.work_order_id.to_string()
            && snapshot.admission.work_order_id == self.work_order_id.to_string()
            && snapshot.run.attempt == attempt_ordinal
            && snapshot.run.repo == self.repository
            && snapshot.admission.payload_digest == self.work_order_digest
            && snapshot.admission.signature_key_id == self.work_order_key_id
            && snapshot.admission.signature_algorithm == self.work_order_algorithm
            && self.policy_digest.as_deref()
                == Some(snapshot.admission.effective_policy_digest.as_str());
        if compatible {
            Ok(())
        } else {
            Err(Error::Validation(format!(
                "cancellation job {job_id} does not match Runmill's immutable admission binding"
            )))
        }
    }

    fn same_authoritative_coordinates(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.work_item_id == other.work_item_id
            && self.attempt_id == other.attempt_id
            && self.attempt_ordinal == other.attempt_ordinal
            && self.work_order_id == other.work_order_id
            && self.internal_run_id == other.internal_run_id
            && self.worker_id == other.worker_id
            && self.external_run_id == other.external_run_id
            && self.attempt_aggregate_version == other.attempt_aggregate_version
            && self.attempt_fence_token == other.attempt_fence_token
            && self.attempt_state == other.attempt_state
            // A concurrent observer changing even the same authoritative run
            // must win. Retrying the stable external request is safer than
            // overwriting its freshly persisted state/version.
            && self.run_aggregate_version == other.run_aggregate_version
            && self.run_state == other.run_state
            && self.work_item_version == other.work_item_version
            && self.workflow_id == other.workflow_id
            && self.workflow_version == other.workflow_version
            && self.workflow_fence_token == other.workflow_fence_token
            && self.workflow_event_cursor == other.workflow_event_cursor
            && self.anchor_generation == other.anchor_generation
            && self.repository == other.repository
            && self.work_order_digest == other.work_order_digest
            && self.policy_digest == other.policy_digest
            && self.work_order_key_id == other.work_order_key_id
            && self.work_order_algorithm == other.work_order_algorithm
    }
}

async fn lock_cancellation_job_claim(
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
          AND job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
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
    .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "lock exact Runmill cancellation workflow-job claim: {error}"
        ))
    })?;
    if locked == Some(job.id) {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "cancellation job {} no longer owns its live workflow-job claim",
            job.id
        )))
    }
}

async fn lock_cancellation_claim_and_binding(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &CancellationJobPayload,
) -> Result<CancellationBinding> {
    lock_cancellation_job_claim(transaction, job).await?;
    lock_attempt_reservation_release_authority(
        transaction,
        job.tenant_id,
        payload.work_item_id,
        payload.worker_id.as_uuid(),
    )
    .await?;
    lock_cancellation_binding(transaction, job, payload).await
}

async fn lock_cancellation_binding(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &CancellationJobPayload,
) -> Result<CancellationBinding> {
    let row = sqlx::query(
        r"
        SELECT
            work.tenant_id,
            work.id AS work_item_id,
            work.aggregate_version AS work_item_version,
            work.policy_digest,
            attempt.id AS attempt_id,
            attempt.ordinal AS attempt_ordinal,
            attempt.aggregate_version AS attempt_aggregate_version,
            attempt.fence_token AS attempt_fence_token,
            attempt.state AS attempt_state,
            workflow.id AS workflow_id,
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence_token,
            workflow.event_cursor AS workflow_event_cursor,
            COALESCE(anchor.generation, 0) AS anchor_generation,
            run.id AS internal_run_id,
            run.worker_id,
            run.external_run_id,
            run.work_order_id,
            run.aggregate_version AS run_aggregate_version,
            run.state AS run_state,
            work_order.payload_digest AS work_order_digest,
            work_order.key_id AS work_order_key_id,
            work_order.algorithm AS work_order_algorithm,
            repository.owner || '/' || repository.name AS repository
        FROM workflow_jobs AS job
        JOIN work_items AS work
          ON work.tenant_id = job.tenant_id
         AND work.id = job.work_item_id
         AND work.id = $7
         AND work.current_attempt_id = job.attempt_id
         AND work.state = 'CANCEL_REQUESTED'
         AND work.aggregate_version = $8
        JOIN attempts AS attempt
          ON attempt.tenant_id = work.tenant_id
         AND attempt.id = work.current_attempt_id
         AND attempt.work_item_id = work.id
         AND attempt.state IN (
             'AUTHORIZED', 'DISPATCHING', 'RUNNING', 'VERIFYING',
             'WAITING_APPROVAL', 'CANCEL_REQUESTED'
         )
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = job.tenant_id
         AND workflow.id = job.workflow_instance_id
         AND workflow.work_item_id = work.id
         AND workflow.workflow_type = 'WORK_ITEM_CANCELLATION'
         AND workflow.state IN ('ACTIVE', 'WAITING')
        JOIN runs AS run
          ON run.tenant_id = job.tenant_id
         AND run.work_item_id = work.id
         AND run.attempt_id = attempt.id
         AND run.authoritative
         AND run.worker_id = $10
         AND run.state IN (
             'ADOPTED', 'RUNNING', 'WAITING_APPROVAL', 'VERIFYING',
             'CANCEL_REQUESTED'
         )
        JOIN work_orders AS work_order
          ON work_order.tenant_id = run.tenant_id
         AND work_order.id = run.work_order_id
         AND work_order.work_item_id = work.id
         AND work_order.attempt_id = attempt.id
        JOIN repositories AS repository
          ON repository.tenant_id = work.tenant_id
         AND repository.id = work.repository_id
        LEFT JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
        WHERE job.tenant_id = $1
          AND job.id = $2
          AND job.workflow_instance_id = $3
          AND job.work_item_id = $4
          AND job.attempt_id = $5
          AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND job.activity_contract_id = $11
          AND job.status = 'RUNNING'
          AND job.lease_owner = $6
          AND job.fence_token = $9
        FOR UPDATE OF work, attempt, workflow, run
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(job.workflow_instance_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(&job.lease_owner)
    .bind(payload.work_item_id)
    .bind(payload.expected_version)
    .bind(job.fence_token)
    .bind(payload.worker_id.as_uuid())
    .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "lock authoritative Runmill cancellation binding: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "cancellation job {} has no live, authoritative, exactly-bound run",
            job.id
        ))
    })?;
    CancellationBinding::from_row(&row)
}

async fn persist_or_adopt_effect_intent(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    proposed_request: RunmillCancellationRequest,
    effect_id: Uuid,
) -> Result<(RunmillCancellationRequest, String)> {
    let stable_request_id = stable_cancellation_request_id(
        binding.tenant_id,
        binding.work_item_id,
        binding.attempt_id,
        binding.internal_run_id,
    );
    let idempotency_key = format!("runmill-cancellation:{stable_request_id}");
    let proposed_digest = proposed_request
        .digest()
        .map_err(|error| incompatible_binding(job.id, &error))?;
    let proposed_payload = serde_json::to_value(&proposed_request).map_err(|error| {
        Error::Validation(format!("encode Runmill cancellation request: {error}"))
    })?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            status, idempotency_key, correlation_marker, request_digest,
            request_payload, attempt_count, next_attempt_at, fence_token,
            lease_owner, lease_expires_at, owning_workflow_job_id
        ) VALUES (
            $1, $2, $3, $4, 'runmill', 'request_cancellation', 'IN_FLIGHT',
            $5, $6, $7, $8, 1, clock_timestamp(), $9, $10, $11, $12
        )
        ON CONFLICT DO NOTHING
        RETURNING id
        ",
    )
    .bind(effect_id)
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(&idempotency_key)
    .bind(&stable_request_id)
    .bind(&proposed_digest)
    .bind(&proposed_payload)
    .bind(job.fence_token)
    .bind(&job.lease_owner)
    .bind(job.lease_expires_at)
    .bind(job.id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "persist Runmill cancellation effect intent: {error}"
        ))
    })?;
    if inserted == Some(effect_id) {
        return Ok((proposed_request, proposed_digest));
    }

    // A replacement workflow job must adopt the exact request already bound
    // to this authoritative attempt/run. Its caller-provided reason, job UUID,
    // current controller settings, and fence must never create a second
    // logical mutation after an ambiguous outcome.
    let existing = sqlx::query(
        r"
        SELECT
            id, idempotency_key, correlation_marker, request_digest,
            request_payload, status
        FROM effect_intents
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND attempt_id = $3
          AND provider = 'runmill'
          AND effect_type = 'request_cancellation'
        FOR UPDATE
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "load persisted Runmill cancellation effect intent: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill cancellation effect {stable_request_id} conflicts with another durable identity"
        ))
    })?;
    let existing_id: Uuid = required(&existing, "id", "cancellation effect ID")?;
    let existing_idempotency_key: String = required(
        &existing,
        "idempotency_key",
        "cancellation effect idempotency key",
    )?;
    let existing_correlation: Option<String> = optional(
        &existing,
        "correlation_marker",
        "cancellation effect correlation marker",
    )?;
    let stored_digest: String = required(
        &existing,
        "request_digest",
        "cancellation effect request digest",
    )?;
    let stored_payload: Value = required(
        &existing,
        "request_payload",
        "cancellation effect request payload",
    )?;
    let stored_status: String = required(&existing, "status", "cancellation effect status")?;
    let stored_request: RunmillCancellationRequest =
        serde_json::from_value(stored_payload.clone()).map_err(|_| {
            Error::Conflict(format!(
                "Runmill cancellation effect {stable_request_id} has an incompatible persisted request"
            ))
        })?;
    stored_request.validate().map_err(|_| {
        Error::Conflict(format!(
            "Runmill cancellation effect {stable_request_id} has an invalid persisted request"
        ))
    })?;
    reject_sensitive_fields(&stored_payload)?;
    let canonical_stored_digest = stored_request.digest().map_err(|_| {
        Error::Conflict(format!(
            "Runmill cancellation effect {stable_request_id} cannot reproduce its persisted digest"
        ))
    })?;
    let exact_binding = existing_id == effect_id
        && existing_idempotency_key == idempotency_key
        && existing_correlation.as_deref() == Some(stable_request_id.as_str())
        && stored_request.request_id == stable_request_id
        && stored_request.run_id.as_str() == binding.external_run_id
        && stored_digest == canonical_stored_digest;
    if !exact_binding {
        return Err(Error::Conflict(format!(
            "Runmill cancellation effect {stable_request_id} contradicts its authoritative run binding"
        )));
    }

    // The exact owning job was locked before any aggregate.  Owner text and a
    // per-row fence are not globally unique: another job claimed by the same
    // reactor can carry the same pair.  Only the persisted job UUID decides
    // whether an in-flight request is still owned.  The effect lease remains a
    // diagnostic snapshot because reactor heartbeats renew the job itself.
    let adopted = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT',
            attempt_count = attempt_count + 1,
            next_attempt_at = clock_timestamp(),
            owning_workflow_job_id = $7,
            fence_token = $8,
            lease_owner = $9,
            lease_expires_at = $10,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND provider = 'runmill'
          AND effect_type = 'request_cancellation'
          AND request_digest = $5
          AND request_payload = $6
          AND (
              status IN ('PENDING', 'AMBIGUOUS', 'FAILED')
              OR (
                  status = 'IN_FLIGHT'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM workflow_jobs AS owning_job
                      WHERE owning_job.tenant_id = effect_intents.tenant_id
                        AND owning_job.id = effect_intents.owning_workflow_job_id
                        AND owning_job.work_item_id = effect_intents.work_item_id
                        AND owning_job.attempt_id = effect_intents.attempt_id
                        AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                        AND owning_job.activity_contract_id = $11
                        AND owning_job.status = 'RUNNING'
                        AND owning_job.lease_owner = effect_intents.lease_owner
                        AND owning_job.fence_token = effect_intents.fence_token
                        AND owning_job.lease_expires_at > clock_timestamp()
                  )
              )
          )
        RETURNING id
        ",
    )
    .bind(job.tenant_id)
    .bind(effect_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(&stored_digest)
    .bind(&stored_payload)
    .bind(job.id)
    .bind(job.fence_token)
    .bind(&job.lease_owner)
    .bind(job.lease_expires_at)
    .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "adopt persisted Runmill cancellation effect intent: {error}"
        ))
    })?;
    if adopted == Some(effect_id) {
        Ok((stored_request, stored_digest))
    } else {
        Err(Error::Conflict(format!(
            "Runmill cancellation effect {stable_request_id} is {stored_status} and cannot be replaced"
        )))
    }
}

async fn load_observed_cancellation_intent(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
) -> Result<ObservedCancellationIntent> {
    let row = sqlx::query(
        r"
        SELECT
            id, status, idempotency_key, correlation_marker, request_digest,
            request_payload, observed_outcome, observed_at,
            initial_cancellation_observation_id,
            owning_workflow_job_id, lease_owner, lease_expires_at, last_error
        FROM effect_intents
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND attempt_id = $3
          AND provider = 'runmill'
          AND effect_type = 'request_cancellation'
        FOR UPDATE
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "load observed Runmill cancellation effect: {error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "cancellation observation job {} has no durable Runmill cancellation effect",
            job.id
        ))
    })?;

    let effect_id: Uuid = required(&row, "id", "observed cancellation effect ID")?;
    let status: String = required(&row, "status", "observed cancellation effect status")?;
    let idempotency_key: String = required(
        &row,
        "idempotency_key",
        "observed cancellation idempotency key",
    )?;
    let correlation_marker: Option<String> = optional(
        &row,
        "correlation_marker",
        "observed cancellation correlation marker",
    )?;
    let request_digest: String = required(
        &row,
        "request_digest",
        "observed cancellation request digest",
    )?;
    let request_payload: Value = required(
        &row,
        "request_payload",
        "observed cancellation request payload",
    )?;
    let outcome_payload: Option<Value> = optional(
        &row,
        "observed_outcome",
        "observed cancellation effect outcome",
    )?;
    let observed_at: Option<chrono::DateTime<Utc>> =
        optional(&row, "observed_at", "observed cancellation effect time")?;
    let initial_observation_id: Option<Uuid> = optional(
        &row,
        "initial_cancellation_observation_id",
        "initial cancellation observation",
    )?;
    let owning_job_id: Option<Uuid> = optional(
        &row,
        "owning_workflow_job_id",
        "observed cancellation owning job",
    )?;
    let lease_owner: Option<String> =
        optional(&row, "lease_owner", "observed cancellation lease owner")?;
    let lease_expires_at: Option<chrono::DateTime<Utc>> = optional(
        &row,
        "lease_expires_at",
        "observed cancellation lease expiry",
    )?;
    let last_error: Option<String> =
        optional(&row, "last_error", "observed cancellation last error")?;

    let request: RunmillCancellationRequest = serde_json::from_value(request_payload.clone())
        .map_err(|_| {
            Error::Conflict(format!(
                "cancellation observation job {} has an incompatible persisted request",
                job.id
            ))
        })?;
    request.validate().map_err(|_| {
        Error::Conflict(format!(
            "cancellation observation job {} has an invalid persisted request",
            job.id
        ))
    })?;
    reject_sensitive_fields(&request_payload)?;
    let canonical_request_digest = request.digest().map_err(|_| {
        Error::Conflict(format!(
            "cancellation observation job {} cannot reproduce its persisted request digest",
            job.id
        ))
    })?;
    let outcome_payload = outcome_payload.ok_or_else(|| {
        Error::Conflict(format!(
            "cancellation observation job {} has no observed effect receipt",
            job.id
        ))
    })?;
    let outcome: CancellationEffectObservation =
        serde_json::from_value(outcome_payload).map_err(|_| {
            Error::Conflict(format!(
                "cancellation observation job {} has an incompatible observed effect receipt",
                job.id
            ))
        })?;

    let stable_request_id = stable_cancellation_request_id(
        binding.tenant_id,
        binding.work_item_id,
        binding.attempt_id,
        binding.internal_run_id,
    );
    let expected_effect_id = stable_cancellation_effect_id(binding.internal_run_id);
    let exact_observed_effect = effect_id == expected_effect_id
        && status == "OBSERVED"
        && idempotency_key == format!("runmill-cancellation:{stable_request_id}")
        && correlation_marker.as_deref() == Some(stable_request_id.as_str())
        && request.request_id == stable_request_id
        && request.run_id.as_str() == binding.external_run_id
        && request_digest == canonical_request_digest
        && outcome.schema == "asf.runmill-cancellation-effect/v1"
        && outcome.status == "observed"
        && outcome.request_id == request.request_id
        && outcome.request_digest == request_digest
        && matches!(
            outcome.disposition,
            RunmillCancellationDisposition::Requested | RunmillCancellationDisposition::Existing
        )
        && matches!(
            outcome.external_phase,
            RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
        )
        && outcome.external_generation > 0
        && !outcome.cancellation_observation_id.is_nil()
        && initial_observation_id == Some(outcome.cancellation_observation_id)
        && owning_job_id.is_none()
        && lease_owner.is_none()
        && lease_expires_at.is_none()
        && last_error.is_none();
    if !exact_observed_effect {
        return Err(Error::Conflict(format!(
            "cancellation observation job {} does not match its immutable observed effect receipt",
            job.id
        )));
    }

    let initial_observation_id = initial_observation_id.ok_or_else(|| {
        Error::Conflict(format!(
            "cancellation observation job {} has no initial cancellation observation binding",
            job.id
        ))
    })?;
    let observed_at = observed_at.ok_or_else(|| {
        Error::Conflict(format!(
            "cancellation observation job {} has no durable observation time",
            job.id
        ))
    })?;
    let latest_observation = load_latest_cancellation_observation(
        transaction,
        job,
        binding,
        effect_id,
        initial_observation_id,
        &request,
        &request_digest,
        &outcome,
        observed_at,
    )
    .await?;

    Ok(ObservedCancellationIntent {
        effect_id,
        request,
        request_digest,
        outcome,
        observed_at,
        latest_observation,
    })
}

async fn load_latest_cancellation_observation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    effect_id: Uuid,
    initial_observation_id: Uuid,
    request: &RunmillCancellationRequest,
    request_digest: &str,
    effect_outcome: &CancellationEffectObservation,
    effect_observed_at: chrono::DateTime<Utc>,
) -> Result<CancellationObservationReceipt> {
    let rows = sqlx::query(
        r"
        SELECT
            observation.id,
            observation.workflow_job_id,
            observation.workflow_job_fence_token,
            observation.workflow_job_attempt_count,
            observation.workflow_job_owner,
            observation.route,
            observation.prior_observation_id,
            observation.request_id,
            observation.request_digest,
            observation.disposition,
            observation.external_phase,
            observation.external_generation,
            observation.external_state_version,
            observation.external_latest_sequence,
            observation.reconciliation_required,
            observation.observed_at,
            observation.receipt_digest
        FROM runmill_cancellation_observations AS observation
        WHERE observation.tenant_id = $1
          AND observation.work_item_id = $2
          AND observation.attempt_id = $3
          AND observation.run_id = $4
          AND observation.effect_intent_id = $5
          AND observation.workflow_instance_id = $6
        ORDER BY observation.recorded_at, observation.id
        FOR UPDATE OF observation
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(binding.internal_run_id)
    .bind(effect_id)
    .bind(binding.workflow_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "load Runmill cancellation observation chain: {error}"
        ))
    })?;
    if rows.is_empty() {
        return Err(Error::Conflict(format!(
            "cancellation observation job {} has no durable observation chain",
            job.id
        )));
    }

    let mut observations = rows
        .iter()
        .map(decode_cancellation_observation)
        .collect::<Result<Vec<_>>>()?;
    let initial_position = observations
        .iter()
        .position(|observation| observation.id == initial_observation_id)
        .ok_or_else(|| {
            Error::Conflict(format!(
                "cancellation observation job {} cannot find the effect's initial observation",
                job.id
            ))
        })?;
    let mut tail = observations.swap_remove(initial_position);
    let exact_initial = tail.route == CancellationObservationRoute::Initial.as_sql()
        && tail.prior_observation_id.is_none()
        && tail.request_id == request.request_id
        && tail.request_digest == request_digest
        && tail.disposition == cancellation_receipt_disposition(effect_outcome.disposition)
        && tail.external_phase == effect_outcome.external_phase
        && tail.external_generation == effect_outcome.external_generation
        && tail.external_state_version == effect_outcome.external_state_version
        && tail.external_latest_sequence == effect_outcome.external_latest_sequence
        && tail.reconciliation_required == effect_outcome.reconciliation_required
        && tail.observed_at == effect_observed_at;
    if !exact_initial {
        return Err(Error::Conflict(format!(
            "cancellation observation job {} has a contradictory initial observation",
            job.id
        )));
    }

    while !observations.is_empty() {
        let successors = observations
            .iter()
            .enumerate()
            .filter_map(|(index, observation)| {
                (observation.prior_observation_id == Some(tail.id)).then_some(index)
            })
            .collect::<Vec<_>>();
        if successors.len() != 1 {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} has a forked or disconnected observation chain",
                job.id
            )));
        }
        let successor = observations.swap_remove(successors[0]);
        let exact_successor = successor.route == CancellationObservationRoute::Observer.as_sql()
            && successor.request_id == request.request_id
            && successor.request_digest == request_digest
            && successor.disposition
                == cancellation_receipt_disposition(effect_outcome.disposition)
            && successor.external_generation == effect_outcome.external_generation
            && successor.reconciliation_required == effect_outcome.reconciliation_required
            && successor.external_latest_sequence >= tail.external_latest_sequence
            && successor.observed_at >= tail.observed_at
            && cancellation_state_progressed(
                tail.external_phase,
                tail.external_state_version,
                successor.external_phase,
                successor.external_state_version,
            );
        if !exact_successor {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} has a regressed or contradictory observation chain",
                job.id
            )));
        }
        tail = successor;
    }
    Ok(tail)
}

fn decode_cancellation_observation(row: &PgRow) -> Result<CancellationObservationReceipt> {
    let external_generation: i64 = required(
        row,
        "external_generation",
        "cancellation observation generation",
    )?;
    let external_state_version: i64 = required(
        row,
        "external_state_version",
        "cancellation observation state version",
    )?;
    let external_latest_sequence: i64 = required(
        row,
        "external_latest_sequence",
        "cancellation observation latest sequence",
    )?;
    let external_phase: String = required(
        row,
        "external_phase",
        "cancellation observation external phase",
    )?;
    let receipt = CancellationObservationReceipt {
        id: required(row, "id", "cancellation observation ID")?,
        workflow_job_id: required(
            row,
            "workflow_job_id",
            "cancellation observation workflow job",
        )?,
        workflow_job_fence_token: required(
            row,
            "workflow_job_fence_token",
            "cancellation observation job fence",
        )?,
        workflow_job_attempt_count: required(
            row,
            "workflow_job_attempt_count",
            "cancellation observation job attempt count",
        )?,
        workflow_job_owner: required(
            row,
            "workflow_job_owner",
            "cancellation observation job owner",
        )?,
        route: required(row, "route", "cancellation observation route")?,
        prior_observation_id: optional(
            row,
            "prior_observation_id",
            "prior cancellation observation",
        )?,
        request_id: required(row, "request_id", "cancellation observation request ID")?,
        request_digest: required(
            row,
            "request_digest",
            "cancellation observation request digest",
        )?,
        disposition: required(row, "disposition", "cancellation observation disposition")?,
        external_phase: parse_cancellation_receipt_phase(&external_phase)?,
        external_generation: u64::try_from(external_generation).map_err(|_| {
            Error::Persistence("cancellation observation has a negative generation".into())
        })?,
        external_state_version: u64::try_from(external_state_version).map_err(|_| {
            Error::Persistence("cancellation observation has a negative state version".into())
        })?,
        external_latest_sequence: u64::try_from(external_latest_sequence).map_err(|_| {
            Error::Persistence("cancellation observation has a negative latest sequence".into())
        })?,
        reconciliation_required: required(
            row,
            "reconciliation_required",
            "cancellation observation reconciliation flag",
        )?,
        observed_at: required(row, "observed_at", "cancellation observation timestamp")?,
        receipt_digest: required(
            row,
            "receipt_digest",
            "cancellation observation receipt digest",
        )?,
    };
    if receipt.workflow_job_id.is_nil()
        || receipt.workflow_job_fence_token <= 0
        || receipt.workflow_job_attempt_count <= 0
        || receipt.workflow_job_owner.trim().is_empty()
        || !is_sha256_digest(&receipt.request_digest)
        || !is_sha256_digest(&receipt.receipt_digest)
    {
        return Err(Error::Persistence(
            "cancellation observation has invalid immutable provenance".into(),
        ));
    }
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
async fn insert_cancellation_observation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    effect_id: Uuid,
    request: &RunmillCancellationRequest,
    result: &RunmillCancellationResult,
    observed: &RunmillRunSnapshot,
    request_digest: &str,
    route: CancellationObservationRoute,
    prior_observation_id: Option<Uuid>,
    observed_at: chrono::DateTime<Utc>,
) -> Result<CancellationObservationFact> {
    if (route == CancellationObservationRoute::Initial) != prior_observation_id.is_none() {
        return Err(Error::Conflict(format!(
            "cancellation job {} has an invalid observation-chain route",
            job.id
        )));
    }
    if job.fence_token <= 0 || job.attempt_count <= 0 || job.lease_owner.trim().is_empty() {
        return Err(Error::Conflict(format!(
            "cancellation job {} has invalid observation claim provenance",
            job.id
        )));
    }
    let external_generation =
        cancellation_external_counter(observed.run.generation, "Runmill cancellation generation")?;
    if external_generation == 0 {
        return Err(Error::ExternalUnavailable(
            "Runmill cancellation generation must be positive".into(),
        ));
    }
    let external_state_version = cancellation_external_counter(
        observed.run.state_version,
        "Runmill cancellation state version",
    )?;
    let external_latest_sequence = cancellation_external_counter(
        observed.latest_sequence,
        "Runmill cancellation latest sequence",
    )?;
    if external_state_version == 0
        || external_latest_sequence == 0
        || external_latest_sequence != external_state_version
    {
        return Err(Error::ExternalUnavailable(
            "Runmill cancellation observation has incompatible version/sequence provenance".into(),
        ));
    }
    let observation_id = stable_cancellation_observation_id(job.id, job.fence_token);
    let receipt_digest: String = sqlx::query_scalar(
        r"
        INSERT INTO runmill_cancellation_observations (
            id, tenant_id, work_item_id, attempt_id, run_id,
            effect_intent_id, workflow_instance_id, workflow_job_id,
            workflow_job_fence_token, workflow_job_attempt_count,
            workflow_job_owner, route, prior_observation_id, request_id,
            request_digest, disposition, external_phase,
            external_generation, external_state_version,
            external_latest_sequence, reconciliation_required, observed_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8,
            $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17,
            $18, $19,
            $20, $21, $22
        )
        RETURNING receipt_digest
        ",
    )
    .bind(observation_id)
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(binding.internal_run_id)
    .bind(effect_id)
    .bind(binding.workflow_id)
    .bind(job.id)
    .bind(job.fence_token)
    .bind(job.attempt_count)
    .bind(&job.lease_owner)
    .bind(route.as_sql())
    .bind(prior_observation_id)
    .bind(&result.request_id)
    .bind(request_digest)
    .bind(cancellation_receipt_disposition(result.disposition))
    .bind(cancellation_receipt_phase(observed.run.state)?)
    .bind(external_generation)
    .bind(external_state_version)
    .bind(external_latest_sequence)
    .bind(result.reconciliation_required)
    .bind(observed_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "insert Runmill cancellation observation receipt: {error}"
        ))
    })?;
    if result.request_id != request.request_id
        || result.generation != observed.run.generation
        || !is_sha256_digest(&receipt_digest)
    {
        return Err(Error::Conflict(format!(
            "cancellation job {} produced contradictory observation provenance",
            job.id
        )));
    }
    Ok(CancellationObservationFact {
        id: observation_id,
        prior_id: prior_observation_id,
    })
}

fn cancellation_external_counter(value: u64, label: &str) -> Result<i64> {
    const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
    if value > MAX_EXACT_JSON_INTEGER {
        return Err(Error::ExternalUnavailable(format!(
            "{label} exceeds the exact receipt range"
        )));
    }
    i64::try_from(value)
        .map_err(|_| Error::ExternalUnavailable(format!("{label} cannot be persisted")))
}

async fn update_effect_failure(
    pool: &sqlx::PgPool,
    job: &ClaimedWorkflowJob,
    effect_id: Uuid,
    request_digest: &str,
    error: &str,
    ambiguous: bool,
) -> Result<()> {
    let error_summary = error.chars().take(8_192).collect::<String>();
    let status = if ambiguous { "AMBIGUOUS" } else { "FAILED" };
    let outcome = json!({
        "schema": "asf.runmill-cancellation-effect/v1",
        "status": status.to_ascii_lowercase(),
        "request_digest": request_digest,
    });
    let changed = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = $5,
            observed_outcome = $6,
            owning_workflow_job_id = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL,
            last_error = $7,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND provider = 'runmill'
          AND effect_type = 'request_cancellation'
          AND request_digest = $8
          AND fence_token = $9
          AND owning_workflow_job_id = $10
          AND lease_owner = $11
          AND status = 'IN_FLIGHT'
          AND EXISTS (
              SELECT 1
              FROM workflow_jobs AS job
              WHERE job.tenant_id = effect_intents.tenant_id
                AND job.id = $10
                AND job.work_item_id = effect_intents.work_item_id
                AND job.attempt_id = effect_intents.attempt_id
                AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                AND job.activity_contract_id = $12
                AND job.status = 'RUNNING'
                AND job.lease_owner = $11
                AND job.fence_token = effect_intents.fence_token
                AND job.lease_expires_at > clock_timestamp()
          )
        ",
    )
    .bind(job.tenant_id)
    .bind(effect_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(status)
    .bind(outcome)
    .bind(error_summary)
    .bind(request_digest)
    .bind(job.fence_token)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
    .execute(pool)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "record Runmill cancellation effect failure: {database_error}"
        ))
    })?
    .rows_affected();
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "Runmill cancellation effect {effect_id} lost its fence"
        )))
    }
}

fn validate_result_and_observation(
    request: &RunmillCancellationRequest,
    result: &RunmillCancellationResult,
    observed: &RunmillRunSnapshot,
) -> Result<()> {
    let result_shape_valid = match result.disposition {
        RunmillCancellationDisposition::Requested | RunmillCancellationDisposition::Existing => {
            matches!(
                result.state,
                RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
            )
        }
        RunmillCancellationDisposition::AlreadyTerminal => result.state.terminal(),
    };
    let progressed_from_cancellation = matches!(
        result.state,
        RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
    ) && (matches!(
        observed.run.state,
        RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
    ) || observed.run.state.terminal());
    let observed_compatible = result.state == observed.run.state || progressed_from_cancellation;
    let exact_identity = result.request_id == request.request_id
        && result.run_id == request.run_id
        && result.request_digest
            == request.digest().map_err(|_| {
                Error::ExternalUnavailable(
                    "Runmill cancellation request digest could not be reproduced".into(),
                )
            })?
        && result.run_id == observed.run.run_id
        && result.generation == observed.run.generation;
    if result_shape_valid && observed_compatible && exact_identity {
        Ok(())
    } else {
        Err(Error::ExternalUnavailable(
            "Runmill cancellation result contradicted its follow-up run snapshot".into(),
        ))
    }
}

fn validate_cancellation_observation_progress(
    prior: &CancellationObservationReceipt,
    observed: &RunmillRunSnapshot,
) -> Result<()> {
    if observed.run.generation == prior.external_generation
        && observed.latest_sequence >= prior.external_latest_sequence
        && cancellation_state_progressed(
            prior.external_phase,
            prior.external_state_version,
            observed.run.state,
            observed.run.state_version,
        )
    {
        Ok(())
    } else {
        Err(Error::ExternalUnavailable(
            "Runmill cancellation observation regressed or contradicted its durable observation chain"
                .into(),
        ))
    }
}

fn cancellation_state_progressed(
    prior_phase: RunmillRunPhase,
    prior_version: u64,
    observed_phase: RunmillRunPhase,
    observed_version: u64,
) -> bool {
    cancellation_phase_progressed(prior_phase, observed_phase)
        && if observed_phase == prior_phase {
            observed_version >= prior_version
        } else {
            observed_version > prior_version
        }
}

fn cancellation_phase_progressed(prior: RunmillRunPhase, observed: RunmillRunPhase) -> bool {
    match prior {
        RunmillRunPhase::CancelRequested => {
            matches!(
                observed,
                RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
            ) || observed.terminal()
        }
        RunmillRunPhase::Cancelling => {
            observed == RunmillRunPhase::Cancelling || observed.terminal()
        }
        _ => false,
    }
}

async fn persist_cancellation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &CancellationJobPayload,
    binding: &CancellationBinding,
    request: &RunmillCancellationRequest,
    result: &RunmillCancellationResult,
    observed: &RunmillRunSnapshot,
    request_digest: &str,
    effect_id: Uuid,
    effect_commit: CancellationEffectCommit,
    prior_observation: Option<&CancellationObservationReceipt>,
) -> Result<()> {
    // Use the database representation before hashing any audit/commit facts.
    // PostgreSQL timestamptz is microsecond-precision; a local nanosecond value
    // would be rounded on insert and could never reproduce its original hash.
    let observed_at = sqlx::query_scalar::<_, chrono::DateTime<Utc>>("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "load Runmill cancellation observation timestamp: {error}"
            ))
        })?;
    let request_reason_digest = sha256_digest(
        &canonical_json(&json!({"reason": request.reason})).map_err(|error| {
            Error::Validation(format!("canonicalize cancellation reason: {error}"))
        })?,
    );
    let reconciliation_job_reason_digest = sha256_digest(
        &canonical_json(&json!({"reason": payload.reason})).map_err(|error| {
            Error::Validation(format!("canonicalize cancellation job reason: {error}"))
        })?,
    );
    let external_phase = phase_name(observed.run.state);
    let disposition = disposition_name(result.disposition);
    let run_state = local_run_state(observed.run.state);
    let terminal = observed.run.state.terminal();
    let (observation_route, prior_observation_id) = match effect_commit {
        CancellationEffectCommit::ObserveInFlight if prior_observation.is_none() => {
            (CancellationObservationRoute::Initial, None)
        }
        CancellationEffectCommit::AlreadyObserved => (
            CancellationObservationRoute::Observer,
            Some(
                prior_observation
                    .ok_or_else(|| {
                        Error::Conflict(format!(
                            "cancellation observation job {} has no locked chain tail",
                            job.id
                        ))
                    })?
                    .id,
            ),
        ),
        CancellationEffectCommit::ObserveInFlight => {
            return Err(Error::Conflict(format!(
                "initial cancellation job {} unexpectedly has a prior observation",
                job.id
            )));
        }
    };
    let cancellation_observation = insert_cancellation_observation(
        transaction,
        job,
        binding,
        effect_id,
        request,
        result,
        observed,
        request_digest,
        observation_route,
        prior_observation_id,
        observed_at,
    )
    .await?;
    let terminal_receipt_id = terminal.then(|| stable_cancellation_terminal_receipt_id(job.id));
    let run_snapshot = json!({
        "schema": "asf.runmill-cancellation-observation/v1",
        "request_id": result.request_id,
        "request_digest": request_digest,
        "disposition": disposition,
        "external_phase": external_phase,
        "external_generation": result.generation,
        "external_state_version": observed.run.state_version,
        "external_latest_sequence": observed.latest_sequence,
        "reconciliation_required": result.reconciliation_required,
        "cancellation_observation_id": cancellation_observation.id,
        "prior_cancellation_observation_id": cancellation_observation.prior_id,
        "observed_at": observed_at,
    });
    if effect_commit == CancellationEffectCommit::ObserveInFlight {
        let effect_outcome = json!({
            "schema": "asf.runmill-cancellation-effect/v1",
            "status": "observed",
            "request_id": result.request_id,
            "request_digest": request_digest,
            "disposition": disposition,
            "external_phase": external_phase,
            "external_generation": result.generation,
            "external_state_version": observed.run.state_version,
            "external_latest_sequence": observed.latest_sequence,
            "reconciliation_required": result.reconciliation_required,
            "cancellation_observation_id": cancellation_observation.id,
        });
        let effect_changed = sqlx::query(
            r"
            UPDATE effect_intents
            SET status = 'OBSERVED',
                observed_outcome = $5,
                observed_at = $6,
                initial_cancellation_observation_id = $11,
                owning_workflow_job_id = NULL,
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND id = $2
              AND work_item_id = $3
              AND attempt_id = $4
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
              AND request_digest = $7
              AND fence_token = $8
              AND owning_workflow_job_id = $9
              AND lease_owner = $10
              AND status = 'IN_FLIGHT'
            ",
        )
        .bind(job.tenant_id)
        .bind(effect_id)
        .bind(binding.work_item_id)
        .bind(binding.attempt_id)
        .bind(effect_outcome)
        .bind(observed_at)
        .bind(request_digest)
        .bind(job.fence_token)
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(cancellation_observation.id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            Error::Persistence(format!("observe Runmill cancellation effect: {error}"))
        })?
        .rows_affected();
        if effect_changed != 1 {
            return Err(Error::Conflict(format!(
                "Runmill cancellation effect {effect_id} lost its fence"
            )));
        }
    }
    let updated = sqlx::query(
        r"
        UPDATE runs
        SET state = $5,
            snapshot = jsonb_set(
                COALESCE(snapshot, '{}'::jsonb),
                '{runmill_cancellation}',
                $6,
                true
            ),
            aggregate_version = aggregate_version + 1,
            last_observed_at = $7,
            terminal_at = CASE WHEN $8 THEN COALESCE(terminal_at, $7) ELSE NULL END
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND aggregate_version = $9
          AND state = $10
          AND authoritative
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.internal_run_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(run_state)
    .bind(run_snapshot)
    .bind(observed_at)
    .bind(terminal)
    .bind(binding.run_aggregate_version)
    .bind(&binding.run_state)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("record Runmill cancellation: {error}")))?
    .rows_affected();
    if updated != 1 {
        return Err(Error::Conflict(format!(
            "authoritative run {} changed while cancellation was committed",
            binding.internal_run_id
        )));
    }
    let attempt_state = local_attempt_state(observed.run.state);
    let attempt_updated = sqlx::query(
        r"
        UPDATE attempts
        SET state = $4,
            aggregate_version = aggregate_version + 1,
            terminal_at = CASE WHEN $5 THEN COALESCE(terminal_at, $6) ELSE NULL END,
            updated_at = $6
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND aggregate_version = $7
          AND fence_token = $8
          AND state = $9
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.attempt_id)
    .bind(binding.work_item_id)
    .bind(attempt_state)
    .bind(terminal)
    .bind(observed_at)
    .bind(binding.attempt_aggregate_version)
    .bind(binding.attempt_fence_token)
    .bind(&binding.attempt_state)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("record cancellation attempt state: {error}")))?
    .rows_affected();
    if attempt_updated != 1 {
        return Err(Error::Conflict(format!(
            "attempt {} changed while cancellation was committed",
            binding.attempt_id
        )));
    }
    let released_reservations = if terminal {
        release_active_attempt_reservations(
            transaction,
            binding.tenant_id,
            binding.work_item_id,
            binding.attempt_id,
            binding.worker_id.as_uuid(),
            AttemptReservationReleaseNamespace::RunmillCancellation {
                terminal_receipt_id: terminal_receipt_id.ok_or_else(|| {
                    Error::Conflict(format!(
                        "terminal cancellation job {} has no reservation-release receipt identity",
                        job.id
                    ))
                })?,
            },
            &job.lease_owner,
            TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON,
        )
        .await?
    } else {
        0
    };

    let observation_job = if terminal {
        None
    } else {
        if effect_commit != CancellationEffectCommit::ObserveInFlight {
            return Err(Error::Conflict(format!(
                "cancellation observation job {} cannot create another nonterminal observer",
                job.id
            )));
        }
        let expected_version = binding.work_item_version.checked_add(1).ok_or_else(|| {
            Error::Conflict("cancellation observer work-item version overflowed".into())
        })?;
        let available_at = observed_at
            .checked_add_signed(Duration::seconds(i64::from(request.grace_seconds)))
            .ok_or_else(|| Error::Validation("cancellation observer schedule overflowed".into()))?;
        Some(StepWorkflowJob {
            id: derived_uuid(effect_id, 5),
            attempt_id: Some(binding.attempt_id),
            job_type: REQUEST_WORK_ITEM_CANCELLATION.into(),
            activity_contract_id: REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({
                "work_item_id": binding.work_item_id,
                "worker_id": binding.worker_id,
                "expected_version": expected_version,
                "reason": payload.reason,
                "requested_by": payload.requested_by,
                "observe_only": true,
            }),
            idempotency_key: format!(
                "runmill-cancellation:{}:observe-terminal",
                request.request_id
            ),
            priority: job.priority,
            available_at,
            max_attempts: job.max_attempts,
        })
    };
    let observation_job_fact = observation_job.as_ref().map(|observer| {
        json!({
            "id": observer.id,
            "attempt_id": observer.attempt_id,
            "job_type": observer.job_type,
            "payload": observer.payload,
            "idempotency_key": observer.idempotency_key,
            "priority": observer.priority,
            "available_at": observer.available_at,
            "max_attempts": observer.max_attempts,
        })
    });

    let (
        work_item_state,
        workflow_state,
        accountability,
        audit_action,
        local_route,
        terminal_conflict,
    ) = match observed.run.state {
        RunmillRunPhase::Cancelled => {
            let terminal_receipt_id = terminal_receipt_id.ok_or_else(|| {
                Error::Conflict(format!(
                    "cancelled Runmill job {} has no terminal receipt identity",
                    job.id
                ))
            })?;
            (
                "CANCELLED",
                "CANCELLED",
                AccountabilityReplacement {
                    kind: LedgerAccountabilityKind::Cancellation,
                    reference_id: terminal_receipt_id,
                    wake_or_deadline_at: None,
                    authority_or_effect_active: false,
                },
                "WORK_ITEM_CANCELLED",
                "cancelled",
                None,
            )
        }
        phase if phase.terminal() => {
            let escalation =
                ensure_terminal_conflict_escalation(transaction, job, binding, phase, observed_at)
                    .await?;
            (
                "ESCALATED",
                "WAITING",
                AccountabilityReplacement {
                    kind: LedgerAccountabilityKind::Escalation,
                    reference_id: escalation.id,
                    wake_or_deadline_at: Some(escalation.deadline),
                    authority_or_effect_active: true,
                },
                "RUNMILL_CANCELLATION_ALREADY_TERMINAL",
                "terminal_conflict_escalated",
                Some(escalation),
            )
        }
        _ => (
            "CANCEL_REQUESTED",
            "WAITING",
            AccountabilityReplacement {
                kind: LedgerAccountabilityKind::Workflow,
                reference_id: binding.workflow_id,
                wake_or_deadline_at: None,
                authority_or_effect_active: false,
            },
            "RUNMILL_CANCELLATION_ACCEPTED",
            "cancellation_in_progress",
            None,
        ),
    };

    let audit_id = derived_uuid(job.id, 1);
    let outbox_id = derived_uuid(job.id, 2);
    let job_result = json!({
        "schema": "asf.runmill-cancellation-result/v1",
        "request_id": result.request_id,
        "request_digest": request_digest,
        "external_run_id": binding.external_run_id,
        "disposition": disposition,
        "external_phase": external_phase,
        "reconciliation_required": result.reconciliation_required,
        "route": local_route,
        "released_reservations": released_reservations,
        "cancellation_observation_id": cancellation_observation.id,
        "terminal_receipt_id": terminal_receipt_id,
        "observation_job": observation_job_fact,
        "escalation_id": terminal_conflict.as_ref().map(|escalation| escalation.id),
        "escalation_deadline": terminal_conflict.as_ref().map(|escalation| escalation.deadline),
        "escalation_disposition": terminal_conflict.as_ref().map(|escalation| escalation.disposition),
        "escalation_before_digest": terminal_conflict
            .as_ref()
            .and_then(|escalation| escalation.before_digest.as_deref()),
        "escalation_after_digest": terminal_conflict
            .as_ref()
            .map(|escalation| escalation.after_digest.as_str()),
    });
    let commit_digest = sha256_digest(&canonical_json(&json!({
        "job_id": job.id,
        "run_id": binding.internal_run_id,
        "request_digest": request_digest,
        "job_result": job_result,
        "work_item_state": work_item_state,
        "workflow_state": workflow_state,
        "accountability_kind": accountability_kind_name(accountability.kind),
        "accountability_reference": accountability.reference_id,
        "released_reservations": released_reservations,
        "cancellation_observation_id": cancellation_observation.id,
        "prior_cancellation_observation_id": cancellation_observation.prior_id,
        "terminal_receipt_id": terminal_receipt_id,
        "observation_job": observation_job_fact,
        "escalation_id": terminal_conflict.as_ref().map(|escalation| escalation.id),
        "escalation_deadline": terminal_conflict.as_ref().map(|escalation| escalation.deadline),
        "escalation_disposition": terminal_conflict.as_ref().map(|escalation| escalation.disposition),
        "escalation_before_digest": terminal_conflict
            .as_ref()
            .and_then(|escalation| escalation.before_digest.as_deref()),
        "escalation_after_digest": terminal_conflict
            .as_ref()
            .map(|escalation| escalation.after_digest.as_str()),
    }))?);
    let next_cursor = binding
        .workflow_event_cursor
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("cancellation workflow cursor overflowed".into()))?;
    let commit = WorkflowStepCommit {
        fence: WorkflowStepFence {
            tenant_id: job.tenant_id,
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
        job_result: Some(job_result),
        work_item_state: work_item_state.into(),
        workflow_state: workflow_state.into(),
        workflow_event_cursor: next_cursor,
        accountability,
        jobs: observation_job.clone().into_iter().collect(),
        timers: Vec::new(),
        effects: Vec::new(),
        outbox: vec![StepOutboxMessage {
            id: outbox_id,
            topic: "work-items".into(),
            message_key: binding.work_item_id.to_string(),
            event_type: match local_route {
                "cancelled" => "work_item.cancelled",
                "terminal_conflict_escalated" => "work_item.cancellation_terminal_conflict",
                _ => "work_item.cancellation_in_progress",
            }
            .into(),
            payload: json!({
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "run_id": binding.internal_run_id,
                "external_run_id": binding.external_run_id,
                "request_id": result.request_id,
                "request_digest": request_digest,
                "external_phase": external_phase,
                "route": local_route,
                "released_reservations": released_reservations,
                "cancellation_observation_id": cancellation_observation.id,
                "terminal_receipt_id": terminal_receipt_id,
                "observation_job_id": observation_job.as_ref().map(|observer| observer.id),
                "observation_available_at": observation_job
                    .as_ref()
                    .map(|observer| observer.available_at),
                "escalation_id": terminal_conflict.as_ref().map(|escalation| escalation.id),
                "escalation_deadline": terminal_conflict.as_ref().map(|escalation| escalation.deadline),
                "escalation_disposition": terminal_conflict.as_ref().map(|escalation| escalation.disposition),
                "escalation_before_digest": terminal_conflict
                    .as_ref()
                    .and_then(|escalation| escalation.before_digest.as_deref()),
                "escalation_after_digest": terminal_conflict
                    .as_ref()
                    .map(|escalation| escalation.after_digest.as_str()),
            }),
            headers: json!({"schema": "asf.work-item-event/v1"}),
            idempotency_key: format!("runmill-cancellation:{}:outbox", job.id),
            available_at: observed_at,
        }],
        audit_events: vec![StepAuditEvent {
            id: audit_id,
            attempt_id: Some(binding.attempt_id),
            actor_type: "SERVICE".into(),
            actor_id: job.lease_owner.clone(),
            action: audit_action.into(),
            subject_type: "RUN".into(),
            subject_id: binding.internal_run_id.to_string(),
            correlation_id: result.request_id.clone(),
            trace_id: None,
            policy_digest: binding.policy_digest.clone(),
            before_digest: terminal_conflict
                .as_ref()
                .and_then(|escalation| escalation.before_digest.clone()),
            after_digest: terminal_conflict
                .as_ref()
                .map(|escalation| escalation.after_digest.clone())
                .or_else(|| Some(request_digest.into())),
            details: json!({
                "work_item_id": binding.work_item_id,
                "attempt_id": binding.attempt_id,
                "external_run_id": binding.external_run_id,
                "request_id": result.request_id,
                "request_digest": request_digest,
                "request_reason_digest": request_reason_digest,
                "runmill_requester_subject": request.requester.subject,
                "reconciliation_job_reason_digest": reconciliation_job_reason_digest,
                "reconciliation_requested_by": payload.requested_by,
                "persisted_request_adopted": request.reason != payload.reason,
                "disposition": disposition,
                "external_phase": external_phase,
                "reconciliation_required": result.reconciliation_required,
                "route": local_route,
                "released_reservations": released_reservations,
                "cancellation_observation_id": cancellation_observation.id,
                "terminal_receipt_id": terminal_receipt_id,
                "observation_job_id": observation_job.as_ref().map(|observer| observer.id),
                "observation_available_at": observation_job
                    .as_ref()
                    .map(|observer| observer.available_at),
                "escalation_id": terminal_conflict.as_ref().map(|escalation| escalation.id),
                "escalation_deadline": terminal_conflict.as_ref().map(|escalation| escalation.deadline),
                "escalation_disposition": terminal_conflict.as_ref().map(|escalation| escalation.disposition),
                "escalation_before_digest": terminal_conflict
                    .as_ref()
                    .and_then(|escalation| escalation.before_digest.as_deref()),
                "escalation_after_digest": terminal_conflict
                    .as_ref()
                    .map(|escalation| escalation.after_digest.as_str()),
            }),
            occurred_at: observed_at,
        }],
    };
    let commit_outcome = commit_workflow_step_with_prelocked_claim(transaction, &commit).await?;
    if terminal {
        let (work_item_version, workflow_version, workflow_fence_token, anchor_generation) =
            match commit_outcome {
                WorkflowStepCommitOutcome::Applied {
                    work_item_version,
                    workflow_version,
                    workflow_fence_token,
                    anchor_generation,
                } => (
                    work_item_version,
                    workflow_version,
                    workflow_fence_token,
                    anchor_generation,
                ),
                WorkflowStepCommitOutcome::AlreadyApplied => {
                    return Err(Error::Conflict(format!(
                        "terminal cancellation job {} was already completed without its receipt",
                        job.id
                    )));
                }
            };
        insert_runmill_cancellation_terminal_receipt(
            transaction,
            job,
            binding,
            terminal_receipt_id.ok_or_else(|| {
                Error::Conflict(format!(
                    "terminal cancellation job {} has no receipt identity",
                    job.id
                ))
            })?,
            cancellation_observation.id,
            audit_id,
            outbox_id,
            terminal_conflict.as_ref().map(|escalation| escalation.id),
            released_reservations,
            work_item_version,
            workflow_version,
            workflow_fence_token,
            anchor_generation,
            observed.run.state,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_runmill_cancellation_terminal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    terminal_receipt_id: Uuid,
    terminal_observation_id: Uuid,
    audit_event_id: Uuid,
    outbox_event_id: Uuid,
    escalation_id: Option<Uuid>,
    released_reservations: usize,
    work_item_version_after: i64,
    workflow_version_after: i64,
    workflow_fence_after: i64,
    anchor_generation_after: i64,
    terminal_phase: RunmillRunPhase,
) -> Result<()> {
    if !terminal_phase.terminal() {
        return Err(Error::Conflict(format!(
            "cancellation job {} cannot create a nonterminal receipt",
            job.id
        )));
    }
    let outcome = if terminal_phase == RunmillRunPhase::Cancelled {
        if escalation_id.is_some() {
            return Err(Error::Conflict(format!(
                "cancelled Runmill job {} unexpectedly retained an escalation",
                job.id
            )));
        }
        "CANCELLED"
    } else {
        if escalation_id.is_none() {
            return Err(Error::Conflict(format!(
                "terminal-conflict Runmill job {} has no owned escalation",
                job.id
            )));
        }
        "TERMINAL_CONFLICT"
    };
    let expected_work_item_version_after = checked_increment(
        binding.work_item_version,
        "terminal cancellation work-item version",
    )?;
    let attempt_version_after = checked_increment(
        binding.attempt_aggregate_version,
        "terminal cancellation attempt version",
    )?;
    let run_version_after = checked_increment(
        binding.run_aggregate_version,
        "terminal cancellation run version",
    )?;
    let expected_workflow_version_after = checked_increment(
        binding.workflow_version,
        "terminal cancellation workflow version",
    )?;
    let expected_workflow_fence_after = checked_increment(
        binding.workflow_fence_token,
        "terminal cancellation workflow fence",
    )?;
    let expected_anchor_generation_after = checked_increment(
        binding.anchor_generation,
        "terminal cancellation anchor generation",
    )?;
    if work_item_version_after != expected_work_item_version_after
        || workflow_version_after != expected_workflow_version_after
        || workflow_fence_after != expected_workflow_fence_after
        || anchor_generation_after != expected_anchor_generation_after
    {
        return Err(Error::Conflict(format!(
            "terminal cancellation job {} committed contradictory ledger versions",
            job.id
        )));
    }
    let released_reservations = i64::try_from(released_reservations).map_err(|_| {
        Error::Conflict("terminal cancellation reservation count overflowed".into())
    })?;
    let inserted_id: Uuid = sqlx::query_scalar(
        r"
        INSERT INTO cancellation_terminal_receipts (
            id, tenant_id, work_item_id, route, outcome,
            attempt_id, run_id, effect_intent_id, terminal_observation_id,
            workflow_instance_id, workflow_job_id, workflow_job_fence_token,
            workflow_job_attempt_count, workflow_job_completed_by,
            audit_event_id, outbox_event_id, idempotency_record_id,
            escalation_id, work_item_version_before, work_item_version_after,
            attempt_version_before, attempt_version_after, attempt_fence_token,
            run_version_before, run_version_after, workflow_version_before,
            workflow_version_after, workflow_fence_before, workflow_fence_after,
            anchor_generation_before, anchor_generation_after,
            dispatch_guard_generation, released_reservations
        ) VALUES (
            $1, $2, $3, 'RUNMILL', $4,
            $5, $6, $7, $8,
            $9, $10, $11,
            $12, $13,
            $14, $15, $16,
            $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25,
            $26, $27, $28,
            $29, $30,
            $31, $32
        )
        RETURNING id
        ",
    )
    .bind(terminal_receipt_id)
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(outcome)
    .bind(binding.attempt_id)
    .bind(binding.internal_run_id)
    .bind(stable_cancellation_effect_id(binding.internal_run_id))
    .bind(terminal_observation_id)
    .bind(binding.workflow_id)
    .bind(job.id)
    .bind(job.fence_token)
    .bind(job.attempt_count)
    .bind(&job.lease_owner)
    .bind(audit_event_id)
    .bind(outbox_event_id)
    .bind(Option::<Uuid>::None)
    .bind(escalation_id)
    .bind(binding.work_item_version)
    .bind(work_item_version_after)
    .bind(binding.attempt_aggregate_version)
    .bind(attempt_version_after)
    .bind(binding.attempt_fence_token)
    .bind(binding.run_aggregate_version)
    .bind(run_version_after)
    .bind(binding.workflow_version)
    .bind(workflow_version_after)
    .bind(binding.workflow_fence_token)
    .bind(workflow_fence_after)
    .bind(binding.anchor_generation)
    .bind(anchor_generation_after)
    .bind(Option::<i64>::None)
    .bind(released_reservations)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "insert Runmill cancellation terminal receipt: {error}"
        ))
    })?;
    if inserted_id != terminal_receipt_id {
        return Err(Error::Persistence(format!(
            "terminal cancellation job {} inserted a contradictory receipt identity",
            job.id
        )));
    }
    Ok(())
}

fn checked_increment(value: i64, label: &str) -> Result<i64> {
    value
        .checked_add(1)
        .ok_or_else(|| Error::Conflict(format!("{label} overflowed")))
}

#[derive(Debug)]
struct TerminalConflictEscalation {
    id: Uuid,
    deadline: chrono::DateTime<Utc>,
    disposition: &'static str,
    before_digest: Option<String>,
    after_digest: String,
}

async fn ensure_terminal_conflict_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    phase: RunmillRunPhase,
    observed_at: chrono::DateTime<Utc>,
) -> Result<TerminalConflictEscalation> {
    let spec = terminal_conflict_spec(binding, phase, observed_at)?;
    if let Some(existing) = load_open_remote_effect_escalation(transaction, job, binding).await? {
        return merge_terminal_conflict_escalation(transaction, job, binding, existing, &spec)
            .await;
    }

    let escalation_id = derived_uuid(binding.internal_run_id, 3);
    let inserted = sqlx::query(
        r"
        INSERT INTO escalations (
            id, tenant_id, work_item_id, attempt_id, run_id, category, status,
            severity, reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key, opened_at
        ) VALUES (
            $1, $2, $3, $4, $5, 'REMOTE_EFFECT_AMBIGUOUS', 'OPEN', 'HIGH',
            $6, 'ON_CALL', 'platform-operations', $7, $8, $9, $10, $11,
            $12, true, $13, $14
        )
        ON CONFLICT DO NOTHING
        RETURNING
            id, tenant_id, work_item_id, attempt_id, run_id, category, status,
            severity, reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key,
            aggregate_version, opened_at, acknowledged_at, closed_at
        ",
    )
    .bind(escalation_id)
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(binding.internal_run_id)
    .bind(&spec.reason)
    .bind(&spec.required_action)
    .bind(&spec.evidence_references)
    .bind(spec.deadline)
    .bind(&spec.escalation_path)
    .bind(&spec.retry_policy)
    .bind(&spec.prerequisites)
    .bind(&spec.idempotency_key)
    .bind(spec.opened_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("open cancellation escalation: {error}")))?;
    if let Some(inserted) = inserted {
        return terminal_conflict_transition(transaction, &inserted, "created", None).await;
    }

    // A provider may have won the generic open-category uniqueness race
    // without taking ASF's run/workflow locks. At `READ COMMITTED`, this next
    // statement sees the committed row and merges the cancellation evidence.
    let existing = load_open_remote_effect_escalation(transaction, job, binding)
        .await?
        .ok_or_else(|| Error::Conflict("cancellation escalation identity conflict".into()))?;
    merge_terminal_conflict_escalation(transaction, job, binding, existing, &spec).await
}

#[derive(Debug)]
struct TerminalConflictSpec {
    opened_at: chrono::DateTime<Utc>,
    deadline: chrono::DateTime<Utc>,
    reason: String,
    required_action: String,
    evidence_references: Value,
    escalation_path: Value,
    retry_policy: Value,
    prerequisites: Value,
    idempotency_key: String,
}

fn terminal_conflict_spec(
    binding: &CancellationBinding,
    phase: RunmillRunPhase,
    observed_at: chrono::DateTime<Utc>,
) -> Result<TerminalConflictSpec> {
    let request_id = stable_cancellation_request_id(
        binding.tenant_id,
        binding.work_item_id,
        binding.attempt_id,
        binding.internal_run_id,
    );
    // Use the durable observation timestamp as the escalation clock.  Besides
    // avoiding a second precision boundary, this makes both creation and the
    // conservative merge deadline reproducible by the database receipt.
    let opened_at = observed_at;
    let deadline = opened_at
        .checked_add_signed(Duration::hours(TERMINAL_CONFLICT_DEADLINE_HOURS))
        .ok_or_else(|| Error::Validation("cancellation escalation deadline overflowed".into()))?;
    let prerequisites = json!([
        "verify terminal Runmill evidence",
        "reconcile remote delivery effects",
        "record an explicit operator disposition",
    ]);
    Ok(TerminalConflictSpec {
        opened_at,
        deadline,
        reason: format!(
            "Runmill was already terminal in {} when cancellation was reconciled",
            phase_name(phase)
        ),
        required_action:
            "inspect the terminal Runmill evidence and explicitly close, retry, or cancel the work item"
                .into(),
        evidence_references: json!([
            format!("run:{}", binding.internal_run_id),
            format!("external-run:{}", binding.external_run_id),
            format!("cancellation-request:{request_id}"),
            format!(
                "effect-intent:{}",
                stable_cancellation_effect_id(binding.internal_run_id)
            ),
        ]),
        escalation_path: json!([
            {"owner_type": "ON_CALL", "owner_id": "platform-operations"},
            {"owner_type": "TEAM", "owner_id": "platform-engineering"},
        ]),
        retry_policy: json!({
            "automatic": false,
            "max_additional_attempts": 0,
            "backoff_seconds": 0,
            "prerequisites": prerequisites,
        }),
        prerequisites,
        idempotency_key: format!("runmill-cancellation:{request_id}:terminal-conflict"),
    })
}

async fn load_open_remote_effect_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
) -> Result<Option<PgRow>> {
    sqlx::query(
        r"
        SELECT
            id, tenant_id, work_item_id, attempt_id, run_id, category, status,
            severity, reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key,
            aggregate_version, opened_at, acknowledged_at, closed_at
        FROM escalations
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND attempt_id = $3
          AND category = 'REMOTE_EFFECT_AMBIGUOUS'
          AND status IN ('OPEN', 'ACKNOWLEDGED')
        FOR UPDATE
        ",
    )
    .bind(job.tenant_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("load cancellation escalation: {error}")))
}

async fn merge_terminal_conflict_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    binding: &CancellationBinding,
    existing: PgRow,
    spec: &TerminalConflictSpec,
) -> Result<TerminalConflictEscalation> {
    let escalation_id: Uuid = required(&existing, "id", "cancellation escalation ID")?;
    let before_digest =
        load_terminal_conflict_state_digest(transaction, job.tenant_id, escalation_id).await?;
    let existing_run_id: Option<Uuid> =
        optional(&existing, "run_id", "cancellation escalation run")?;
    let severity: String = required(&existing, "severity", "cancellation escalation severity")?;
    let reason: String = required(&existing, "reason", "cancellation escalation reason")?;
    let required_action: String = required(
        &existing,
        "required_action",
        "cancellation escalation required action",
    )?;
    let mut evidence_references = merge_json_arrays(
        required(
            &existing,
            "evidence_references",
            "cancellation escalation evidence",
        )?,
        &spec.evidence_references,
        "cancellation escalation evidence",
    )?;
    if let Some(prior_run_id) = existing_run_id.filter(|run_id| *run_id != binding.internal_run_id)
    {
        push_unique_json(
            &mut evidence_references,
            json!(format!("prior-escalation-run:{prior_run_id}")),
            "cancellation escalation evidence",
        )?;
    }
    require_nonempty_string_array(&evidence_references, "cancellation escalation evidence")?;
    let existing_deadline: chrono::DateTime<Utc> =
        required(&existing, "deadline", "cancellation escalation deadline")?;
    let escalation_path = merge_json_arrays(
        required(&existing, "escalation_path", "cancellation escalation path")?,
        &spec.escalation_path,
        "cancellation escalation path",
    )?;
    let mut prerequisites = merge_json_arrays(
        required(
            &existing,
            "prerequisites",
            "cancellation escalation prerequisites",
        )?,
        &spec.prerequisites,
        "cancellation escalation prerequisites",
    )?;
    let existing_retry_policy: Value = required(
        &existing,
        "retry_policy",
        "cancellation escalation retry policy",
    )?;
    if let Some(policy_prerequisites) = existing_retry_policy.get("prerequisites") {
        prerequisites = merge_json_arrays(
            prerequisites,
            policy_prerequisites,
            "cancellation escalation retry prerequisites",
        )?;
    }
    if !existing_retry_policy.is_object() {
        return Err(Error::Persistence(
            "cancellation escalation retry policy is not an object".into(),
        ));
    }
    require_nonempty_string_array(&prerequisites, "cancellation escalation prerequisites")?;
    // Attention projection requires this exact four-field shape. Cancellation
    // is the conservative policy: no automatic or additional retries.
    let retry_policy = json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 0,
        "prerequisites": prerequisites,
    });
    let aggregate_version: i64 = required(
        &existing,
        "aggregate_version",
        "cancellation escalation aggregate version",
    )?;
    let merged_reason = append_semantic_clause(reason, &spec.reason);
    let merged_action = append_semantic_clause(required_action, &spec.required_action);
    let merged_severity = if severity == "CRITICAL" {
        "CRITICAL"
    } else {
        "HIGH"
    };
    let merged_deadline = std::cmp::min(existing_deadline, spec.deadline);
    let changed = sqlx::query(
        r"
        UPDATE escalations
        SET run_id = $5,
            severity = $6,
            reason = $7,
            required_action = $8,
            evidence_references = $9,
            deadline = $10,
            escalation_path = $11,
            retry_policy = $12,
            prerequisites = $13,
            authority_or_effect_active = true,
            aggregate_version = aggregate_version + 1
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND category = 'REMOTE_EFFECT_AMBIGUOUS'
          AND status IN ('OPEN', 'ACKNOWLEDGED')
          AND aggregate_version = $14
        RETURNING
            id, tenant_id, work_item_id, attempt_id, run_id, category, status,
            severity, reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key,
            aggregate_version, opened_at, acknowledged_at, closed_at
        ",
    )
    .bind(job.tenant_id)
    .bind(escalation_id)
    .bind(binding.work_item_id)
    .bind(binding.attempt_id)
    .bind(binding.internal_run_id)
    .bind(merged_severity)
    .bind(merged_reason)
    .bind(merged_action)
    .bind(evidence_references)
    .bind(merged_deadline)
    .bind(escalation_path)
    .bind(retry_policy)
    .bind(prerequisites)
    .bind(aggregate_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("merge cancellation escalation: {error}")))?;
    let changed = changed
        .ok_or_else(|| Error::Conflict("cancellation escalation changed while merging".into()))?;
    terminal_conflict_transition(transaction, &changed, "merged", Some(before_digest)).await
}

async fn terminal_conflict_transition(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    disposition: &'static str,
    before_digest: Option<String>,
) -> Result<TerminalConflictEscalation> {
    let id = required(row, "id", "cancellation escalation ID")?;
    Ok(TerminalConflictEscalation {
        id,
        deadline: required(row, "deadline", "cancellation escalation deadline")?,
        disposition,
        before_digest,
        after_digest: load_terminal_conflict_state_digest(
            transaction,
            required(row, "tenant_id", "cancellation escalation tenant")?,
            id,
        )
        .await?,
    })
}

async fn load_terminal_conflict_state_digest(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    escalation_id: Uuid,
) -> Result<String> {
    sqlx::query_scalar("SELECT asf_terminal_conflict_escalation_digest($1, $2)")
        .bind(tenant_id)
        .bind(escalation_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "digest persisted terminal-conflict escalation: {error}"
            ))
        })
}

#[cfg(test)]
fn terminal_conflict_state_digest(row: &PgRow) -> Result<String> {
    let state = json!({
        "schema": "asf.terminal-conflict-escalation-state/v1",
        "id": required::<Uuid>(row, "id", "cancellation escalation ID")?,
        "tenant_id": required::<Uuid>(row, "tenant_id", "cancellation escalation tenant")?,
        "work_item_id": required::<Uuid>(
            row,
            "work_item_id",
            "cancellation escalation work item",
        )?,
        "attempt_id": optional::<Uuid>(row, "attempt_id", "cancellation escalation attempt")?,
        "run_id": optional::<Uuid>(row, "run_id", "cancellation escalation run")?,
        "category": required::<String>(row, "category", "cancellation escalation category")?,
        "status": required::<String>(row, "status", "cancellation escalation status")?,
        "severity": required::<String>(row, "severity", "cancellation escalation severity")?,
        "reason": required::<String>(row, "reason", "cancellation escalation reason")?,
        "owner_type": required::<String>(row, "owner_type", "cancellation escalation owner type")?,
        "owner_id": required::<String>(row, "owner_id", "cancellation escalation owner")?,
        "required_action": required::<String>(
            row,
            "required_action",
            "cancellation escalation required action",
        )?,
        "evidence_references": required::<Value>(
            row,
            "evidence_references",
            "cancellation escalation evidence",
        )?,
        "deadline": required::<chrono::DateTime<Utc>>(
            row,
            "deadline",
            "cancellation escalation deadline",
        )?,
        "escalation_path": required::<Value>(
            row,
            "escalation_path",
            "cancellation escalation path",
        )?,
        "retry_policy": required::<Value>(
            row,
            "retry_policy",
            "cancellation escalation retry policy",
        )?,
        "prerequisites": required::<Value>(
            row,
            "prerequisites",
            "cancellation escalation prerequisites",
        )?,
        "authority_or_effect_active": required::<bool>(
            row,
            "authority_or_effect_active",
            "cancellation escalation authority",
        )?,
        "idempotency_key": required::<String>(
            row,
            "idempotency_key",
            "cancellation escalation idempotency key",
        )?,
        "aggregate_version": required::<i64>(
            row,
            "aggregate_version",
            "cancellation escalation aggregate version",
        )?,
        "opened_at": required::<chrono::DateTime<Utc>>(
            row,
            "opened_at",
            "cancellation escalation opened at",
        )?,
        "acknowledged_at": optional::<chrono::DateTime<Utc>>(
            row,
            "acknowledged_at",
            "cancellation escalation acknowledged at",
        )?,
        "closed_at": optional::<chrono::DateTime<Utc>>(
            row,
            "closed_at",
            "cancellation escalation closed at",
        )?,
    });
    Ok(sha256_digest(&canonical_json(&state)?))
}

fn merge_json_arrays(existing: Value, additions: &Value, label: &str) -> Result<Value> {
    let mut merged = existing;
    let additions = additions
        .as_array()
        .ok_or_else(|| Error::Persistence(format!("{label} additions are not an array")))?;
    for addition in additions {
        push_unique_json(&mut merged, addition.clone(), label)?;
    }
    Ok(merged)
}

fn push_unique_json(target: &mut Value, addition: Value, label: &str) -> Result<()> {
    let target = target
        .as_array_mut()
        .ok_or_else(|| Error::Persistence(format!("{label} is not an array")))?;
    if !target.contains(&addition) {
        target.push(addition);
    }
    Ok(())
}

fn require_nonempty_string_array(value: &Value, label: &str) -> Result<()> {
    let values = value
        .as_array()
        .ok_or_else(|| Error::Persistence(format!("{label} is not an array")))?;
    if values.is_empty()
        || values
            .iter()
            .any(|value| value.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(Error::Persistence(format!(
            "{label} must contain only non-empty strings"
        )));
    }
    Ok(())
}

fn append_semantic_clause(existing: String, addition: &str) -> String {
    if existing.contains(addition) {
        existing
    } else {
        format!("{existing}; {addition}")
    }
}

fn local_run_state(phase: RunmillRunPhase) -> &'static str {
    match phase {
        RunmillRunPhase::Cancelled => "CANCELLED",
        RunmillRunPhase::Completed => "SUCCEEDED",
        RunmillRunPhase::Refused => "REFUSED",
        RunmillRunPhase::Quarantined => "QUARANTINED",
        RunmillRunPhase::Failed | RunmillRunPhase::BudgetExhausted => "FAILED",
        _ => "CANCEL_REQUESTED",
    }
}

fn local_attempt_state(phase: RunmillRunPhase) -> &'static str {
    match phase {
        RunmillRunPhase::Cancelled => "CANCELLED",
        RunmillRunPhase::Completed => "SUCCEEDED",
        RunmillRunPhase::Refused => "REFUSED",
        RunmillRunPhase::Quarantined => "QUARANTINED",
        RunmillRunPhase::Failed | RunmillRunPhase::BudgetExhausted => "FAILED",
        _ => "CANCEL_REQUESTED",
    }
}

fn disposition_name(disposition: RunmillCancellationDisposition) -> &'static str {
    match disposition {
        RunmillCancellationDisposition::Requested => "requested",
        RunmillCancellationDisposition::Existing => "existing",
        RunmillCancellationDisposition::AlreadyTerminal => "already-terminal",
    }
}

fn cancellation_receipt_disposition(disposition: RunmillCancellationDisposition) -> &'static str {
    match disposition {
        RunmillCancellationDisposition::Requested => "REQUESTED",
        RunmillCancellationDisposition::Existing => "EXISTING",
        RunmillCancellationDisposition::AlreadyTerminal => "ALREADY_TERMINAL",
    }
}

fn cancellation_receipt_phase(phase: RunmillRunPhase) -> Result<&'static str> {
    match phase {
        RunmillRunPhase::CancelRequested => Ok("CANCEL_REQUESTED"),
        RunmillRunPhase::Cancelling => Ok("CANCELLING"),
        RunmillRunPhase::Completed => Ok("SUCCEEDED"),
        RunmillRunPhase::Failed | RunmillRunPhase::BudgetExhausted => Ok("FAILED"),
        RunmillRunPhase::Refused => Ok("REFUSED"),
        RunmillRunPhase::Cancelled => Ok("CANCELLED"),
        RunmillRunPhase::Quarantined => Ok("QUARANTINED"),
        _ => Err(Error::ExternalUnavailable(format!(
            "Runmill cancellation observation has incompatible phase {}",
            phase_name(phase)
        ))),
    }
}

fn parse_cancellation_receipt_phase(value: &str) -> Result<RunmillRunPhase> {
    match value {
        "CANCEL_REQUESTED" => Ok(RunmillRunPhase::CancelRequested),
        "CANCELLING" => Ok(RunmillRunPhase::Cancelling),
        "SUCCEEDED" => Ok(RunmillRunPhase::Completed),
        "FAILED" => Ok(RunmillRunPhase::Failed),
        "REFUSED" => Ok(RunmillRunPhase::Refused),
        "CANCELLED" => Ok(RunmillRunPhase::Cancelled),
        "QUARANTINED" => Ok(RunmillRunPhase::Quarantined),
        _ => Err(Error::Persistence(format!(
            "cancellation observation has incompatible phase {value}"
        ))),
    }
}

fn phase_name(phase: RunmillRunPhase) -> &'static str {
    match phase {
        RunmillRunPhase::Received => "RECEIVED",
        RunmillRunPhase::Admitted => "ADMITTED",
        RunmillRunPhase::RepositoryLeased => "REPOSITORY_LEASED",
        RunmillRunPhase::IdentityReady => "IDENTITY_READY",
        RunmillRunPhase::WorkspaceReady => "WORKSPACE_READY",
        RunmillRunPhase::TaskPacketReady => "TASK_PACKET_READY",
        RunmillRunPhase::Implementing => "IMPLEMENTING",
        RunmillRunPhase::CandidateReady => "CANDIDATE_READY",
        RunmillRunPhase::LocalVerify => "LOCAL_VERIFY",
        RunmillRunPhase::LocalReview => "LOCAL_REVIEW",
        RunmillRunPhase::Fixing => "FIXING",
        RunmillRunPhase::DeliveryReady => "DELIVERY_READY",
        RunmillRunPhase::Pushed => "PUSHED",
        RunmillRunPhase::PrOpen => "PR_OPEN",
        RunmillRunPhase::CiWait => "CI_WAIT",
        RunmillRunPhase::PrReview => "PR_REVIEW",
        RunmillRunPhase::PrDelivered => "PR_DELIVERED",
        RunmillRunPhase::MergeQueueWait => "MERGE_QUEUE_WAIT",
        RunmillRunPhase::MergeReady => "MERGE_READY",
        RunmillRunPhase::Merged => "MERGED",
        RunmillRunPhase::EvidenceFinalized => "EVIDENCE_FINALIZED",
        RunmillRunPhase::Completed => "COMPLETED",
        RunmillRunPhase::CancelRequested => "CANCEL_REQUESTED",
        RunmillRunPhase::Cancelling => "CANCELLING",
        RunmillRunPhase::WaitingApproval => "WAITING_APPROVAL",
        RunmillRunPhase::NeedsSpec => "NEEDS_SPEC",
        RunmillRunPhase::BlockedExternal => "BLOCKED_EXTERNAL",
        RunmillRunPhase::BudgetExhausted => "BUDGET_EXHAUSTED",
        RunmillRunPhase::Refused => "REFUSED",
        RunmillRunPhase::Quarantined => "QUARANTINED",
        RunmillRunPhase::Cancelled => "CANCELLED",
        RunmillRunPhase::Failed => "FAILED",
    }
}

fn accountability_kind_name(kind: LedgerAccountabilityKind) -> &'static str {
    match kind {
        LedgerAccountabilityKind::Workflow => "WORKFLOW",
        LedgerAccountabilityKind::Run => "RUN",
        LedgerAccountabilityKind::Timer => "TIMER",
        LedgerAccountabilityKind::Retry => "RETRY",
        LedgerAccountabilityKind::Approval => "APPROVAL",
        LedgerAccountabilityKind::Escalation => "ESCALATION",
        LedgerAccountabilityKind::Closure => "CLOSURE",
        LedgerAccountabilityKind::Cancellation => "CANCELLATION",
    }
}

fn control_failure(error: &RunmillControlError) -> Error {
    Error::ExternalUnavailable(format!("Runmill cancellation control failed: {error}"))
}

fn incompatible_binding(job_id: Uuid, error: &RunmillControlError) -> Error {
    Error::Validation(format!(
        "cancellation job {job_id} has an incompatible Runmill binding: {error}"
    ))
}

fn stable_cancellation_request_id(
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    internal_run_id: Uuid,
) -> String {
    format!(
        "asf-cancel:{}:{}:{}:{}",
        tenant_id.simple(),
        work_item_id.simple(),
        attempt_id.simple(),
        internal_run_id.simple(),
    )
}

fn stable_cancellation_effect_id(internal_run_id: Uuid) -> Uuid {
    // An authoritative run is unique per attempt. Deriving from that stable
    // identity makes the effect independent of replaceable workflow-job IDs.
    derived_uuid(internal_run_id, 4)
}

fn stable_cancellation_observation_id(workflow_job_id: Uuid, fence_token: i64) -> Uuid {
    stable_receipt_uuid(
        b"asf.runmill-cancellation-observation/v1",
        workflow_job_id,
        Some(fence_token),
    )
}

fn stable_cancellation_terminal_receipt_id(workflow_job_id: Uuid) -> Uuid {
    stable_receipt_uuid(
        b"asf.runmill-cancellation-terminal-receipt/v1",
        workflow_job_id,
        None,
    )
}

fn stable_receipt_uuid(namespace: &[u8], workflow_job_id: Uuid, fence_token: Option<i64>) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(namespace);
    hasher.update(workflow_job_id.as_bytes());
    if let Some(fence_token) = fence_token {
        hasher.update(fence_token.to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
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
        .map_err(|error| Error::Persistence(format!("decode {label}: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration as StdDuration,
    };

    use serde_json::Value;
    use sqlx::PgPool;
    use tokio::sync::oneshot;
    use url::Url;

    use super::*;
    use crate::{
        api::{ApiBackend, CancellationRequest, PageQuery, PostgresApiBackend},
        application::AttentionItemKind,
        domain::WorkItemId,
        ledger::{
            DeadLetterEscalation, WorkflowStepFailure, WorkflowStepFailureDisposition,
            fail_workflow_step,
        },
        runtime::{HandlerRegistry, ReactorOptions, ReactorPollReport, ReactorRuntime},
        security::{Caller, Role},
    };

    #[derive(Debug)]
    struct RetryingScopedCancellationHandler {
        worker_id: WorkerId,
        invocations: AtomicUsize,
    }

    #[async_trait]
    impl JobHandler for RetryingScopedCancellationHandler {
        fn job_type(&self) -> &str {
            REQUEST_WORK_ITEM_CANCELLATION
        }

        fn activity_contract_id(&self) -> &str {
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::CancellationWorker(self.worker_id)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(ActivityOutcome::Retry {
                error: "route-scope probe intentionally retried".into(),
                retry_at: Utc::now() + Duration::seconds(1),
            })
        }
    }

    #[derive(Debug)]
    struct ScriptedCancellationControl {
        tenant_id: Uuid,
        work_item_id: Uuid,
        attempt_id: Uuid,
        work_order_id: Uuid,
        run_id: RunmillRunId,
        repository: String,
        work_order_digest: String,
        policy_digest: String,
        phases: Mutex<VecDeque<RunmillRunPhase>>,
        result_phase: RunmillRunPhase,
        ambiguous_calls: usize,
        cancellation_calls: AtomicUsize,
        cancellation_requests: Mutex<Vec<RunmillCancellationRequest>>,
    }

    impl ScriptedCancellationControl {
        fn snapshot(&self, phase: RunmillRunPhase) -> RunmillRunSnapshot {
            let state_version = match phase {
                RunmillRunPhase::CancelRequested => 2,
                RunmillRunPhase::Cancelling => 3,
                phase if phase.terminal() => 4,
                _ => 1,
            };
            RunmillRunSnapshot {
                run: crate::adapters::RunmillRunRow {
                    run_id: self.run_id.clone(),
                    issue_id: "issue-1".into(),
                    repo: self.repository.clone(),
                    provider: "codex".into(),
                    state: phase,
                    state_version,
                    attempt: 1,
                    base_commit: Some("a".repeat(40)),
                    candidate_sha: None,
                    branch: Some("refs/heads/main".into()),
                    mode: "asf-worker".into(),
                    work_order_id: self.work_order_id.to_string(),
                    attempt_id: self.attempt_id.to_string(),
                    generation: 2,
                    owner_id: None,
                    heartbeat_at: None,
                },
                admission: crate::adapters::RunmillAdmissionSnapshot {
                    idempotency_key: format!(
                        "{}/{}/{}",
                        self.tenant_id, self.work_item_id, self.attempt_id
                    ),
                    work_order_id: self.work_order_id.to_string(),
                    attempt_id: self.attempt_id.to_string(),
                    tenant_id: self.tenant_id.to_string(),
                    payload_digest: self.work_order_digest.clone(),
                    envelope_digest: digest('e'),
                    effective_policy_digest: self.policy_digest.clone(),
                    signature_key_id: "key-1".into(),
                    signature_algorithm: "EdDSA".into(),
                    accepted_at: Utc::now(),
                },
                latest_sequence: state_version,
            }
        }

        fn cancellation_calls(&self) -> usize {
            self.cancellation_calls.load(Ordering::SeqCst)
        }

        fn cancellation_requests(&self) -> Vec<RunmillCancellationRequest> {
            self.cancellation_requests
                .lock()
                .expect("cancellation request script poisoned")
                .clone()
        }
    }

    #[async_trait]
    impl CancellationControl for ScriptedCancellationControl {
        async fn get_run(
            &self,
            run_id: &RunmillRunId,
        ) -> std::result::Result<RunmillRunSnapshot, RunmillControlError> {
            assert_eq!(run_id, &self.run_id);
            let mut phases = self.phases.lock().expect("phase script poisoned");
            let phase = phases
                .pop_front()
                .or_else(|| phases.back().copied())
                .unwrap_or(self.result_phase);
            Ok(self.snapshot(phase))
        }

        async fn request_cancel(
            &self,
            request: &RunmillCancellationRequest,
        ) -> std::result::Result<RunmillCancellationResult, RunmillControlError> {
            assert_eq!(request.run_id, self.run_id);
            self.cancellation_requests
                .lock()
                .expect("cancellation request script poisoned")
                .push(request.clone());
            let call = self.cancellation_calls.fetch_add(1, Ordering::SeqCst);
            if call < self.ambiguous_calls {
                return Err(RunmillControlError::AmbiguousOutcome {
                    operation: crate::adapters::RunmillControlOperation::RequestCancel,
                    reason: crate::adapters::AmbiguousControlFailure::ResponseLost,
                });
            }
            Ok(RunmillCancellationResult {
                request_id: request.request_id.clone(),
                run_id: request.run_id.clone(),
                disposition: if self.result_phase.terminal() {
                    RunmillCancellationDisposition::AlreadyTerminal
                } else if call == 0 {
                    RunmillCancellationDisposition::Requested
                } else {
                    RunmillCancellationDisposition::Existing
                },
                state: self.result_phase,
                generation: 2,
                request_digest: request.digest().expect("digest scripted request"),
                reconciliation_required: self.ambiguous_calls > 0,
            })
        }
    }

    struct ScopedDatabase {
        ledger: PgLedger,
        admin: PgPool,
        schema: String,
    }

    impl ScopedDatabase {
        async fn create(database_url: &str) -> Self {
            let database = Self::connect_unmigrated(database_url).await;
            database
                .ledger
                .migrate()
                .await
                .expect("migrate cancellation-test schema");
            database
        }

        async fn create_through_0004(database_url: &str) -> Self {
            let database = Self::connect_unmigrated(database_url).await;
            let mut transaction = database
                .ledger
                .pool()
                .begin()
                .await
                .expect("begin legacy cancellation migrations");
            for migration in [
                include_str!("../../migrations/0001_initial.sql"),
                include_str!("../../migrations/0002_operational_incident_lifecycle.sql"),
                include_str!(
                    "../../migrations/0003_work_attempt_bindings_and_shared_escalations.sql"
                ),
                include_str!("../../migrations/0004_reservation_internal_event_guard.sql"),
            ] {
                sqlx::raw_sql(migration)
                    .execute(&mut *transaction)
                    .await
                    .expect("apply legacy cancellation migration");
            }
            transaction
                .commit()
                .await
                .expect("commit legacy cancellation migrations");
            database
        }

        async fn connect_unmigrated(database_url: &str) -> Self {
            let admin = PgPool::connect(database_url)
                .await
                .expect("connect cancellation-test administrator");
            let schema = format!("asf_cancellation_test_{}", Uuid::now_v7().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create cancellation-test schema");
            let mut scoped_url = Url::parse(database_url).expect("parse cancellation database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect cancellation-test ledger");
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
                .expect("drop cancellation-test schema");
            self.admin.close().await;
        }
    }

    struct LiveFixture {
        tenant_id: Uuid,
        repository_id: Uuid,
        worker_id: WorkerId,
        worker_session_id: Uuid,
        work_item_id: Uuid,
        attempt_id: Uuid,
        work_order_id: Uuid,
        run_id: Uuid,
        external_run_id: RunmillRunId,
        job: ClaimedWorkflowJob,
        policy_digest: String,
        work_order_digest: String,
    }

    impl LiveFixture {
        async fn insert(ledger: &PgLedger) -> Self {
            Self::insert_with_max_attempts(ledger, 5).await
        }

        async fn insert_with_max_attempts(ledger: &PgLedger, max_attempts: i32) -> Self {
            Self::insert_with_max_attempts_and_persisted_contract(
                ledger,
                max_attempts,
                REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
            )
            .await
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
            Self::insert_with_max_attempts_and_persisted_contract(
                ledger,
                5,
                persisted_activity_contract_id,
            )
            .await
        }

        /// Builds the fixture against a schema that predates migration 0023's
        /// `workflow_jobs.activity_contract_id` column -- i.e. a schema created
        /// through `ScopedDatabase::create_through_0004`, which stops before
        /// migration 0005 even exists yet. The `workflow_jobs` INSERT omits the
        /// column entirely rather than supplying it, because on this schema the
        /// column does not exist. The in-memory `ClaimedWorkflowJob` still
        /// carries the canonical contract id, matching every other fixture
        /// variant: the struct field is a caller-side claim, never read back
        /// from the database, so historical-migration tests exercising
        /// pre-0023 schemas can use it unchanged.
        async fn insert_legacy_pre_activity_contract(ledger: &PgLedger) -> Self {
            Self::insert_with_max_attempts_and_optional_persisted_contract(ledger, 5, None).await
        }

        async fn insert_with_max_attempts_and_persisted_contract(
            ledger: &PgLedger,
            max_attempts: i32,
            persisted_activity_contract_id: &str,
        ) -> Self {
            Self::insert_with_max_attempts_and_optional_persisted_contract(
                ledger,
                max_attempts,
                Some(persisted_activity_contract_id),
            )
            .await
        }

        async fn insert_with_max_attempts_and_optional_persisted_contract(
            ledger: &PgLedger,
            max_attempts: i32,
            persisted_activity_contract_id: Option<&str>,
        ) -> Self {
            assert!(max_attempts > 0);
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
            let job_id = Uuid::now_v7();
            let policy_digest = digest('a');
            let source_digest = digest('b');
            let work_order_digest = digest('c');
            let external_run_id = RunmillRunId::parse(format!("run_{}", run_id.simple()))
                .expect("valid external run ID");
            let lease_expires_at = Utc::now() + Duration::minutes(5);
            let mut transaction = ledger.pool().begin().await.expect("begin fixture");

            sqlx::query(
                "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Cancellation test')",
            )
            .bind(tenant_id)
            .bind(format!("cancel-{tenant_id}"))
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
            sqlx::query(
                r"INSERT INTO policy_versions
                  (id, tenant_id, scope, schema_version, digest, canonical_bytes, policy, created_by)
                  VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')",
            )
            .bind(policy_id)
            .bind(tenant_id)
            .bind(&policy_digest)
            .bind(b"{}".as_slice())
            .execute(&mut *transaction)
            .await
            .expect("insert policy");
            sqlx::query(
                r"INSERT INTO repositories
                  (id, tenant_id, owner, name, repository_url, default_branch, default_policy_digest)
                  VALUES ($1, $2, 'acme', 'widget', 'https://example.invalid/acme/widget', 'main', $3)",
            )
            .bind(repository_id)
            .bind(tenant_id)
            .bind(&policy_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert repository");
            sqlx::query(
                r"INSERT INTO source_snapshots
                  (id, tenant_id, repository_id, source_system, external_id, source_revision,
                   normalized_content, content_digest, connector_identity, source_updated_at)
                  VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', clock_timestamp())",
            )
            .bind(snapshot_id)
            .bind(tenant_id)
            .bind(repository_id)
            .bind(format!("issue-{work_item_id}"))
            .bind(&source_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert source snapshot");
            sqlx::query(
                r"INSERT INTO work_items
                  (id, tenant_id, source_snapshot_id, source_system, source_external_id,
                   repository_id, state, closure_target, risk_class, policy_digest,
                   budget_limits, identity_requirements, owner_fallback, normalized_priority,
                   current_attempt_id, accepted_at)
                  VALUES ($1, $2, $3, 'API', $4, $5, 'CANCEL_REQUESTED', 'pull_request',
                          'low', $6, $7, $8, 'platform-operations', 50, $9, clock_timestamp())",
            )
            .bind(work_item_id)
            .bind(tenant_id)
            .bind(snapshot_id)
            .bind(format!("issue-{work_item_id}"))
            .bind(repository_id)
            .bind(&policy_digest)
            .bind(json!({
                "max_cost_microunits": 1_000_000,
                "max_input_tokens": 100_000,
                "max_output_tokens": 100_000,
                "max_implementer_invocations": 2,
                "max_reviewer_invocations": 2,
                "max_fix_iterations": 1,
                "max_wall_time_seconds": 3600,
                "max_external_api_calls": 10,
            }))
            .bind(json!({
                "implementer": "codex:implementer",
                "local_reviewer": "claude:local-reviewer",
                "pr_reviewer": "codex:pr-reviewer",
            }))
            .bind(attempt_id)
            .execute(&mut *transaction)
            .await
            .expect("insert work item");
            sqlx::query(
                r"INSERT INTO attempts
                  (id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                   base_ref, base_sha, source_snapshot_digest, policy_digest, work_order_digest,
                   started_at)
                  VALUES ($1, $2, $3, 1, 'RUNNING', $4, 'refs/heads/main', $5, $6, $7, $8,
                          clock_timestamp())",
            )
            .bind(attempt_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(format!("attempt:{attempt_id}"))
            .bind("a".repeat(40))
            .bind(&source_digest)
            .bind(&policy_digest)
            .bind(&work_order_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert attempt");
            sqlx::query(
                r"INSERT INTO work_orders
                  (id, tenant_id, work_item_id, attempt_id, schema_version, envelope_schema,
                   algorithm, key_id, idempotency_key, payload_digest, canonical_payload,
                   payload, signature, exact_signed_envelope, issued_at, not_before, expires_at)
                  VALUES ($1, $2, $3, $4, 'asf.work-order/v1', 'asf.work-order-envelope/v1',
                          'EdDSA', 'key-1', $5, $6, $7, '{}'::jsonb, 'signature', $8,
                          clock_timestamp(), clock_timestamp(), clock_timestamp() + interval '1 hour')",
            )
            .bind(work_order_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(format!("{tenant_id}/{work_item_id}/{attempt_id}"))
            .bind(&work_order_digest)
            .bind(b"{}".as_slice())
            .bind(b"signed".as_slice())
            .execute(&mut *transaction)
            .await
            .expect("insert work order");
            sqlx::query(
                r"INSERT INTO workers
                  (id, tenant_id, name, endpoint, status, generation, signing_key_id, signing_public_key)
                  VALUES ($1, $2, 'worker', 'unix:///run/runmill.sock', 'READY', 1, 'key-1', 'public-key')",
            )
            .bind(worker_id)
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .expect("insert worker");
            sqlx::query(
                r"INSERT INTO worker_sessions
                  (id, tenant_id, worker_id, worker_generation, expires_at)
                  VALUES ($1, $2, $3, 1, clock_timestamp() + interval '1 hour')",
            )
            .bind(worker_session_id)
            .bind(tenant_id)
            .bind(worker_id)
            .execute(&mut *transaction)
            .await
            .expect("insert worker session");
            sqlx::query(
                r"INSERT INTO runs
                  (id, tenant_id, work_item_id, attempt_id, work_order_id, worker_id,
                   worker_generation, worker_session_id, evidence_expectation_digest,
                   external_run_id, state)
                  VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, 'RUNNING')",
            )
            .bind(run_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(work_order_id)
            .bind(worker_id)
            .bind(worker_session_id)
            .bind(digest('d'))
            .bind(external_run_id.as_str())
            .execute(&mut *transaction)
            .await
            .expect("insert run");
            sqlx::query(
                r"INSERT INTO workflow_instances
                  (id, tenant_id, work_item_id, workflow_type, reducer_version)
                  VALUES ($1, $2, $3, 'WORK_ITEM_CANCELLATION', 'asf.workflow/v1')",
            )
            .bind(workflow_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .execute(&mut *transaction)
            .await
            .expect("insert workflow");
            let payload = json!({
                "work_item_id": work_item_id,
                "worker_id": worker_id,
                "expected_version": 1,
                "reason": "Operator requested cancellation",
                "requested_by": "operator:alice",
            });
            match persisted_activity_contract_id {
                Some(contract) => {
                    sqlx::query(
                        r"INSERT INTO workflow_jobs
                          (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type,
                           activity_contract_id, status, payload, idempotency_key, attempt_count,
                           max_attempts, fence_token, lease_owner, lease_expires_at)
                          VALUES ($1, $2, $3, $4, $5, 'REQUEST_WORK_ITEM_CANCELLATION', $6, 'RUNNING',
                                  $7, $8, 1, $9, 1, 'reactor:cancellation-test', $10)",
                    )
                    .bind(job_id)
                    .bind(tenant_id)
                    .bind(workflow_id)
                    .bind(work_item_id)
                    .bind(attempt_id)
                    .bind(contract)
                    .bind(&payload)
                    .bind(format!("cancel:{job_id}"))
                    .bind(max_attempts)
                    .bind(lease_expires_at)
                    .execute(&mut *transaction)
                    .await
                }
                // Pre-0023 schema (through migration 0004): the
                // `activity_contract_id` column does not exist yet, so it is
                // omitted from the column list entirely rather than bound as
                // NULL, matching what a contemporaneous 0004-era writer would
                // have executed.
                None => {
                    sqlx::query(
                        r"INSERT INTO workflow_jobs
                          (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type,
                           status, payload, idempotency_key, attempt_count,
                           max_attempts, fence_token, lease_owner, lease_expires_at)
                          VALUES ($1, $2, $3, $4, $5, 'REQUEST_WORK_ITEM_CANCELLATION', 'RUNNING',
                                  $6, $7, 1, $8, 1, 'reactor:cancellation-test', $9)",
                    )
                    .bind(job_id)
                    .bind(tenant_id)
                    .bind(workflow_id)
                    .bind(work_item_id)
                    .bind(attempt_id)
                    .bind(&payload)
                    .bind(format!("cancel:{job_id}"))
                    .bind(max_attempts)
                    .bind(lease_expires_at)
                    .execute(&mut *transaction)
                    .await
                }
            }
            .expect("insert cancellation job");
            sqlx::query(
                r"INSERT INTO accountability_anchors
                  (tenant_id, work_item_id, anchor_type, reference_id, generation)
                  VALUES ($1, $2, 'WORKFLOW', $3, 1)",
            )
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(workflow_id)
            .execute(&mut *transaction)
            .await
            .expect("insert workflow anchor");
            transaction.commit().await.expect("commit fixture");

            let job = ClaimedWorkflowJob {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                job_type: REQUEST_WORK_ITEM_CANCELLATION.into(),
                activity_contract_id: REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID.into(),
                payload,
                idempotency_key: format!("cancel:{job_id}"),
                priority: 0,
                attempt_count: 1,
                max_attempts,
                fence_token: 1,
                lease_owner: "reactor:cancellation-test".into(),
                lease_expires_at,
                created_at: Utc::now(),
            };
            Self {
                tenant_id,
                repository_id,
                worker_id: WorkerId::from_uuid(worker_id),
                worker_session_id,
                work_item_id,
                attempt_id,
                work_order_id,
                run_id,
                external_run_id,
                job,
                policy_digest,
                work_order_digest,
            }
        }

        async fn insert_active_reservation(&self, ledger: &PgLedger) -> Uuid {
            let reservation_set_id = Uuid::now_v7();
            let acquired_at = Utc::now();
            let idempotency_key = format!("cancellation-reservation:{reservation_set_id}");
            let actor_id = "scheduler:cancellation-test";
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin cancellation reservation fixture");
            sqlx::query(
                r"
                INSERT INTO reservation_sets (
                    id, tenant_id, work_item_id, attempt_id, repository_id,
                    worker_id, worker_session_id, worker_generation,
                    request_digest, idempotency_key, state, fence_token,
                    acquired_by, acquired_at, expires_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, 1, $8, $9, 'ACTIVE', 1,
                    $10, $11, $11 + interval '15 minutes'
                )
                ",
            )
            .bind(reservation_set_id)
            .bind(self.tenant_id)
            .bind(self.work_item_id)
            .bind(self.attempt_id)
            .bind(self.repository_id)
            .bind(self.worker_id.as_uuid())
            .bind(self.worker_session_id)
            .bind(digest('e'))
            .bind(&idempotency_key)
            .bind(actor_id)
            .bind(acquired_at)
            .execute(&mut *transaction)
            .await
            .expect("insert active cancellation reservation");
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
            .expect("insert cancellation reservation acquisition event");
            transaction
                .commit()
                .await
                .expect("commit active cancellation reservation");
            reservation_set_id
        }

        fn control(
            &self,
            phases: Vec<RunmillRunPhase>,
            result_phase: RunmillRunPhase,
            ambiguous_first: bool,
        ) -> Arc<ScriptedCancellationControl> {
            self.control_with_ambiguous_calls(phases, result_phase, usize::from(ambiguous_first))
        }

        fn control_with_ambiguous_calls(
            &self,
            phases: Vec<RunmillRunPhase>,
            result_phase: RunmillRunPhase,
            ambiguous_calls: usize,
        ) -> Arc<ScriptedCancellationControl> {
            Arc::new(ScriptedCancellationControl {
                tenant_id: self.tenant_id,
                work_item_id: self.work_item_id,
                attempt_id: self.attempt_id,
                work_order_id: self.work_order_id,
                run_id: self.external_run_id.clone(),
                repository: "acme/widget".into(),
                work_order_digest: self.work_order_digest.clone(),
                policy_digest: self.policy_digest.clone(),
                phases: Mutex::new(phases.into()),
                result_phase,
                ambiguous_calls,
                cancellation_calls: AtomicUsize::new(0),
                cancellation_requests: Mutex::new(Vec::new()),
            })
        }
    }

    #[derive(Debug)]
    struct ReservationReleaseState {
        state: String,
        fence_token: i64,
        transition_idempotency_key: Option<String>,
        cancellation_terminal_receipt_id: Option<Uuid>,
        released_by: Option<String>,
        release_reason: Option<String>,
        release_event_count: i64,
    }

    async fn load_reservation_release_state(
        ledger: &PgLedger,
        tenant_id: Uuid,
        reservation_set_id: Uuid,
    ) -> ReservationReleaseState {
        let row = sqlx::query(
            r"
            SELECT reservation_set.state, reservation_set.fence_token,
                   reservation_set.transition_idempotency_key,
                   reservation_set.cancellation_terminal_receipt_id,
                   reservation_set.released_by, reservation_set.release_reason,
                   count(event.id) FILTER (WHERE event.event_type = 'RELEASED')
                       AS release_event_count
            FROM reservation_sets AS reservation_set
            LEFT JOIN reservation_set_events AS event
              ON event.tenant_id = reservation_set.tenant_id
             AND event.reservation_set_id = reservation_set.id
            WHERE reservation_set.tenant_id = $1
              AND reservation_set.id = $2
            GROUP BY reservation_set.state, reservation_set.fence_token,
                     reservation_set.transition_idempotency_key,
                     reservation_set.cancellation_terminal_receipt_id,
                     reservation_set.released_by, reservation_set.release_reason
            ",
        )
        .bind(tenant_id)
        .bind(reservation_set_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load cancellation reservation release state");
        ReservationReleaseState {
            state: row.try_get("state").unwrap(),
            fence_token: row.try_get("fence_token").unwrap(),
            transition_idempotency_key: row.try_get("transition_idempotency_key").unwrap(),
            cancellation_terminal_receipt_id: row
                .try_get("cancellation_terminal_receipt_id")
                .unwrap(),
            released_by: row.try_get("released_by").unwrap(),
            release_reason: row.try_get("release_reason").unwrap(),
            release_event_count: row.try_get("release_event_count").unwrap(),
        }
    }

    fn assert_cancellation_reservation_released(
        fixture: &LiveFixture,
        reservation_set_id: Uuid,
        actor_id: &str,
        expected_terminal_receipt_id: Uuid,
        reservation: &ReservationReleaseState,
    ) {
        let expected_transition_key = format!(
            "runmill-cancellation:v1:{}:{}:{reservation_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );
        assert_eq!(reservation.state, "RELEASED");
        assert_eq!(reservation.fence_token, 2);
        assert_eq!(
            reservation.transition_idempotency_key.as_deref(),
            Some(expected_transition_key.as_str())
        );
        assert_eq!(reservation.released_by.as_deref(), Some(actor_id));
        assert_eq!(
            reservation.cancellation_terminal_receipt_id,
            Some(expected_terminal_receipt_id)
        );
        assert_eq!(
            reservation.release_reason.as_deref(),
            Some(TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON)
        );
        assert_eq!(reservation.release_event_count, 1);
    }

    fn assert_cancellation_reservation_retained(reservation: &ReservationReleaseState) {
        assert_eq!(reservation.state, "ACTIVE");
        assert_eq!(reservation.fence_token, 1);
        assert!(reservation.transition_idempotency_key.is_none());
        assert!(reservation.cancellation_terminal_receipt_id.is_none());
        assert!(reservation.released_by.is_none());
        assert!(reservation.release_reason.is_none());
        assert_eq!(reservation.release_event_count, 0);
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn job() -> ClaimedWorkflowJob {
        let work_item_id = Uuid::now_v7();
        let worker_id = WorkerId::new();
        ClaimedWorkflowJob {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            workflow_instance_id: Some(Uuid::now_v7()),
            work_item_id: Some(work_item_id),
            attempt_id: Some(Uuid::now_v7()),
            job_type: REQUEST_WORK_ITEM_CANCELLATION.into(),
            activity_contract_id: REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({
                "work_item_id": work_item_id,
                "worker_id": worker_id,
                "expected_version": 7,
                "reason": "Operator requested cancellation",
                "requested_by": "operator:alice",
            }),
            idempotency_key: "cancel-job:test".into(),
            priority: 0,
            attempt_count: 1,
            max_attempts: 5,
            fence_token: 1,
            lease_owner: "reactor:test".into(),
            lease_expires_at: Utc::now() + Duration::minutes(1),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn payload_is_strict_and_exactly_bound_to_the_claim() {
        let valid = job();
        assert!(!CancellationJobPayload::parse(&valid).unwrap().observe_only);

        let mut observer = valid.clone();
        observer.payload["observe_only"] = json!(true);
        assert!(
            CancellationJobPayload::parse(&observer)
                .unwrap()
                .observe_only
        );

        let mut wrong_item = valid.clone();
        wrong_item.payload["work_item_id"] = json!(Uuid::now_v7());
        assert!(CancellationJobPayload::parse(&wrong_item).is_err());

        let mut missing_worker = valid.clone();
        missing_worker
            .payload
            .as_object_mut()
            .expect("object payload")
            .remove("worker_id");
        assert!(CancellationJobPayload::parse(&missing_worker).is_err());

        let mut unknown = valid.clone();
        unknown.payload["unexpected"] = json!(true);
        assert!(CancellationJobPayload::parse(&unknown).is_err());

        let mut secret = valid.clone();
        secret.payload["reason"] = json!("Bearer secret-value");
        assert!(CancellationJobPayload::parse(&secret).is_err());

        let mut wrong_job_type = valid.clone();
        wrong_job_type.job_type = "SOME_OTHER_JOB".into();
        assert!(CancellationJobPayload::parse(&wrong_job_type).is_err());

        let mut wrong_contract = valid;
        wrong_contract.activity_contract_id =
            "asf.activity/request-work-item-cancellation/v2".into();
        assert!(matches!(
            CancellationJobPayload::parse(&wrong_contract),
            Err(Error::Validation(detail)) if detail.contains("activity contract")
        ));
    }

    #[test]
    fn stable_request_identity_and_digest_do_not_depend_on_replaceable_jobs_or_maintenance_mode() {
        let tenant_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let internal_run_id = Uuid::now_v7();
        let run_id = RunmillRunId::parse("run_0123456789abcdef").unwrap();
        let make = |_replaceable_job_id: Uuid| RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: stable_cancellation_request_id(
                tenant_id,
                work_item_id,
                attempt_id,
                internal_run_id,
            ),
            run_id: run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "asf:production-controller".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        let first = make(Uuid::now_v7());
        let replacement = make(Uuid::now_v7());
        assert_eq!(first, replacement);
        assert_eq!(first.digest().unwrap(), replacement.digest().unwrap());
        assert_eq!(
            stable_cancellation_effect_id(internal_run_id),
            derived_uuid(internal_run_id, 4)
        );
        let workflow_job_id = Uuid::now_v7();
        assert_eq!(
            stable_cancellation_observation_id(workflow_job_id, 7),
            stable_cancellation_observation_id(workflow_job_id, 7)
        );
        assert_ne!(
            stable_cancellation_observation_id(workflow_job_id, 7),
            stable_cancellation_observation_id(workflow_job_id, 8)
        );
        assert_ne!(
            stable_cancellation_observation_id(workflow_job_id, 7),
            stable_cancellation_terminal_receipt_id(workflow_job_id)
        );
        assert!(ActivityControls::new(true).maintenance_mode());
    }

    #[test]
    fn terminal_runmill_phases_never_leave_a_live_run_route() {
        for phase in [
            RunmillRunPhase::Completed,
            RunmillRunPhase::Failed,
            RunmillRunPhase::Refused,
            RunmillRunPhase::Quarantined,
            RunmillRunPhase::BudgetExhausted,
        ] {
            assert_ne!(local_run_state(phase), "CANCEL_REQUESTED");
            assert_ne!(local_attempt_state(phase), "CANCEL_REQUESTED");
            assert!(phase.terminal());
        }
        assert_eq!(local_run_state(RunmillRunPhase::Cancelled), "CANCELLED");
        assert_eq!(local_attempt_state(RunmillRunPhase::Cancelled), "CANCELLED");
        assert_eq!(
            local_run_state(RunmillRunPhase::Cancelling),
            "CANCEL_REQUESTED"
        );
        assert_eq!(
            local_attempt_state(RunmillRunPhase::Cancelling),
            "CANCEL_REQUESTED"
        );
    }

    #[test]
    fn terminal_observation_phase_order_never_regresses() {
        assert!(cancellation_state_progressed(
            RunmillRunPhase::CancelRequested,
            7,
            RunmillRunPhase::CancelRequested,
            7,
        ));
        assert!(!cancellation_state_progressed(
            RunmillRunPhase::CancelRequested,
            7,
            RunmillRunPhase::Cancelling,
            7,
        ));
        assert!(cancellation_state_progressed(
            RunmillRunPhase::CancelRequested,
            7,
            RunmillRunPhase::Cancelling,
            8,
        ));
        assert!(cancellation_phase_progressed(
            RunmillRunPhase::CancelRequested,
            RunmillRunPhase::CancelRequested
        ));
        assert!(cancellation_phase_progressed(
            RunmillRunPhase::CancelRequested,
            RunmillRunPhase::Cancelling
        ));
        assert!(cancellation_phase_progressed(
            RunmillRunPhase::CancelRequested,
            RunmillRunPhase::Cancelled
        ));
        assert!(cancellation_phase_progressed(
            RunmillRunPhase::Cancelling,
            RunmillRunPhase::Cancelling
        ));
        assert!(cancellation_phase_progressed(
            RunmillRunPhase::Cancelling,
            RunmillRunPhase::Failed
        ));
        assert!(!cancellation_phase_progressed(
            RunmillRunPhase::Cancelling,
            RunmillRunPhase::CancelRequested
        ));
        assert!(!cancellation_phase_progressed(
            RunmillRunPhase::CancelRequested,
            RunmillRunPhase::Implementing
        ));
    }

    #[tokio::test]
    async fn live_contradictory_cancellation_route_is_dead_lettered_and_releases_effect_ambiguous()
    {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let invalid_job_id = Uuid::now_v7();
        let foreign_worker_id = WorkerId::new();
        let lease_owner = "reactor:crashed-invalid-cancellation-route";
        let live_lease = Utc::now() + Duration::minutes(5);
        let invalid_payload = json!({
            "work_item_id": fixture.work_item_id,
            "worker_id": foreign_worker_id,
            "expected_version": 1,
            "reason": "Operator requested cancellation",
            "requested_by": "operator:alice",
        });
        let request_id = stable_cancellation_request_id(
            fixture.tenant_id,
            fixture.work_item_id,
            fixture.attempt_id,
            fixture.run_id,
        );
        let request = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: request_id.clone(),
            run_id: fixture.external_run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "asf:test-controller".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        let request_digest = request.digest().expect("digest invalid-route request");
        let request_payload = serde_json::to_value(&request).expect("encode invalid-route request");
        let effect_id = stable_cancellation_effect_id(fixture.run_id);

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin invalid cancellation route fixture");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'REQUEST_WORK_ITEM_CANCELLATION',
                $10, 'RUNNING', $6, $7, 1, 5, 1, $8, $9
            )
            ",
        )
        .bind(invalid_job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&invalid_payload)
        .bind(format!("invalid-cancellation-route:{invalid_job_id}"))
        .bind(lease_owner)
        .bind(live_lease)
        .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
        .execute(&mut *transaction)
        .await
        .expect("insert invalid cancellation route");
        sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, correlation_marker, request_digest,
                request_payload, attempt_count, next_attempt_at, fence_token,
                lease_owner, lease_expires_at, owning_workflow_job_id
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'request_cancellation',
                'IN_FLIGHT', $5, $6, $7, $8, 1, clock_timestamp(), 1,
                $9, $10, $11
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("runmill-cancellation:{request_id}"))
        .bind(&request_id)
        .bind(&request_digest)
        .bind(&request_payload)
        .bind(lease_owner)
        .bind(live_lease)
        .bind(invalid_job_id)
        .execute(&mut *transaction)
        .await
        .expect("insert invalid-route owned cancellation effect");
        sqlx::query(
            "UPDATE effect_intents SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(effect_id)
        .execute(&mut *transaction)
        .await
        .expect("expire invalid-route effect snapshot");
        sqlx::query(
            "UPDATE workflow_jobs SET lease_expires_at = clock_timestamp() - interval '1 second', updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(invalid_job_id)
        .execute(&mut *transaction)
        .await
        .expect("expire invalid cancellation route owner");
        transaction
            .commit()
            .await
            .expect("commit invalid cancellation route fixture");

        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            HandlerRegistry::fail_closed_production().expect("build production registry"),
            ReactorOptions {
                lease_owner: "reactor:route-rejection".into(),
                poll_interval: StdDuration::from_millis(10),
                lease_duration: StdDuration::from_secs(5),
                max_error_backoff: StdDuration::from_secs(1),
                claim_batch_size: 4,
            },
            false,
        )
        .expect("construct route rejection reactor");
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("reject contradictory cancellation route"),
            ReactorPollReport {
                route_invalid_jobs_rejected: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        let state: (String, i32, String, Option<Uuid>, Option<String>) = sqlx::query_as(
            r"
            SELECT job.status, job.attempt_count, effect.status,
                   effect.owning_workflow_job_id, effect.lease_owner
            FROM workflow_jobs AS job
            JOIN effect_intents AS effect
              ON effect.tenant_id = job.tenant_id
             AND effect.id = $3
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(invalid_job_id)
        .bind(effect_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load rejected cancellation route");
        assert_eq!(state.0, "DEAD");
        assert_eq!(state.1, 5);
        assert_eq!(state.2, "AMBIGUOUS");
        assert!(state.3.is_none());
        assert!(state.4.is_none());
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_reactor_leases_cancellation_only_to_the_authoritative_run_worker() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let mut expiration = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation route expiration");
        sqlx::query(
            r"
            UPDATE accountability_anchors
            SET anchor_type = 'RUN', reference_id = $3, generation = generation + 1
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.run_id)
        .execute(&mut *expiration)
        .await
        .expect("move cancellation route fixture to its live run anchor");
        sqlx::query(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() - interval '1 second',
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .execute(&mut *expiration)
        .await
        .expect("expire cancellation route fixture");
        expiration
            .commit()
            .await
            .expect("commit cancellation route expiration");

        let options = |owner: &str| ReactorOptions {
            lease_owner: owner.into(),
            poll_interval: StdDuration::from_millis(10),
            lease_duration: StdDuration::from_secs(5),
            max_error_backoff: StdDuration::from_secs(1),
            claim_batch_size: 4,
        };
        let foreign_handler = Arc::new(RetryingScopedCancellationHandler {
            worker_id: WorkerId::new(),
            invocations: AtomicUsize::new(0),
        });
        let mut foreign_registry = HandlerRegistry::new();
        foreign_registry
            .register(foreign_handler.clone())
            .expect("register foreign cancellation route");
        let foreign_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            foreign_registry,
            options("reactor:foreign-cancellation-worker"),
            false,
        )
        .expect("construct foreign cancellation reactor");
        assert_eq!(
            foreign_reactor
                .poll_once()
                .await
                .expect("foreign worker poll remains isolated"),
            ReactorPollReport::default()
        );
        assert_eq!(foreign_handler.invocations.load(Ordering::SeqCst), 0);

        let authoritative_handler = Arc::new(RetryingScopedCancellationHandler {
            worker_id: fixture.worker_id,
            invocations: AtomicUsize::new(0),
        });
        let mut authoritative_registry = HandlerRegistry::new();
        authoritative_registry
            .register(authoritative_handler.clone())
            .expect("register authoritative cancellation route");
        let authoritative_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            authoritative_registry,
            options("reactor:authoritative-cancellation-worker"),
            false,
        )
        .expect("construct authoritative cancellation reactor");
        assert_eq!(
            authoritative_reactor
                .poll_once()
                .await
                .expect("authoritative worker reclaims cancellation"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_retried: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(authoritative_handler.invocations.load(Ordering::SeqCst), 1);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_foreign_worker_route_is_rejected_before_any_daemon_call() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Implementing],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let foreign_worker_id = WorkerId::new();
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            foreign_worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct foreign-worker cancellation handler");
        assert_eq!(
            handler.claim_scope(),
            JobClaimScope::CancellationWorker(foreign_worker_id)
        );

        let error = handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect_err("foreign worker cancellation route must fail closed");
        assert!(matches!(error, Error::Validation(_)));
        assert_eq!(control.cancellation_calls(), 0);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_wrong_contract_claimed_job_is_rejected_before_any_daemon_call() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Implementing],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        let mut wrong_contract = fixture.job.clone();
        wrong_contract.activity_contract_id =
            "asf.activity/request-work-item-cancellation/v2".into();

        let error = handler
            .execute(&wrong_contract, ActivityControls::new(false))
            .await
            .expect_err("a wrong-contract claimed job must fail closed");
        assert!(matches!(error, Error::Validation(detail) if detail.contains("activity contract")));
        assert_eq!(control.cancellation_calls(), 0);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_forged_wrong_contract_owning_row_cannot_satisfy_cancellation_authority_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        // Persist the owning row with a wrong contract from its initial INSERT:
        // migration 0023's immutability trigger rejects any later UPDATE of
        // activity_contract_id, so the mismatch must be born with the row.
        // The in-memory claim (and its job_type) stays canonical, so the SQL
        // predicate, not the caller-supplied struct, is what decides authority.
        let fixture = LiveFixture::insert_with_wrong_persisted_contract(
            &database.ledger,
            "asf.activity/request-work-item-cancellation/v2",
        )
        .await;

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin forged-contract authority check");
        assert!(
            lock_cancellation_job_claim(&mut transaction, &fixture.job)
                .await
                .is_err(),
            "a persisted row with a non-canonical activity contract must never satisfy \
             cancellation authority, regardless of the caller's claimed contract"
        );
        transaction
            .rollback()
            .await
            .expect("rollback forged-contract authority check");

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_wrong_contract_owning_row_cannot_satisfy_effect_intent_owner_trigger_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        // Unlike `live_forged_wrong_contract_owning_row_cannot_satisfy_cancellation_authority_sql`,
        // which proves the SQL job-claim lock (`lock_cancellation_job_claim`)
        // rejects a wrong-contract RUNNING job, this test proves the separate
        // `effect_intents_exact_external_mutation_owner` database trigger
        // (migration 0024's activity-contract predicate) independently
        // rejects the same wrong-contract row as an effect *owner*. It never
        // calls handler validation or `lock_cancellation_job_claim`; it issues
        // the exact raw INSERT that `persist_or_adopt_effect_intent` uses,
        // directly against `effect_intents`.
        let fixture = LiveFixture::insert_with_wrong_persisted_contract(
            &database.ledger,
            "asf.activity/request-work-item-cancellation/v2",
        )
        .await;

        let request_id = stable_cancellation_request_id(
            fixture.tenant_id,
            fixture.work_item_id,
            fixture.attempt_id,
            fixture.run_id,
        );
        let request = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: request_id.clone(),
            run_id: fixture.external_run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "asf:test-controller".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        let request_digest = request
            .digest()
            .expect("canonical cancellation request digest");
        let request_payload =
            serde_json::to_value(&request).expect("encode canonical cancellation request");
        let effect_id = stable_cancellation_effect_id(fixture.run_id);
        let idempotency_key = format!("runmill-cancellation:{request_id}");

        let insert_error = sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, correlation_marker, request_digest,
                request_payload, attempt_count, next_attempt_at, fence_token,
                lease_owner, lease_expires_at, owning_workflow_job_id
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'request_cancellation', 'IN_FLIGHT',
                $5, $6, $7, $8, 1, clock_timestamp(), $9, $10, $11, $12
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&idempotency_key)
        .bind(&request_id)
        .bind(&request_digest)
        .bind(&request_payload)
        .bind(fixture.job.fence_token)
        .bind(&fixture.job.lease_owner)
        .bind(fixture.job.lease_expires_at)
        .bind(fixture.job.id)
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
        .expect("count rejected cancellation effect rows");
        assert_eq!(persisted, 0);

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_ambiguous_response_is_reconciled_once_and_commits_one_observed_effect() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let control = fixture.control(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
                RunmillRunPhase::CancelRequested,
            ],
            RunmillRunPhase::CancelRequested,
            true,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        let outcome = handler
            .execute(&fixture.job, ActivityControls::new(true))
            .await
            .expect("maintenance-mode cancellation must reconcile and commit");
        assert_eq!(outcome, ActivityOutcome::TransactionCommitted);
        assert_eq!(control.cancellation_calls(), 2);

        let row = sqlx::query(
            r"
            SELECT
                job.status AS job_status,
                job.result AS job_result,
                work.state AS work_state,
                work.aggregate_version AS work_version,
                workflow.state AS workflow_state,
                workflow.aggregate_version AS workflow_version,
                workflow.fence_token AS workflow_fence,
                attempt.state AS attempt_state,
                attempt.aggregate_version AS attempt_version,
                attempt.terminal_at AS attempt_terminal_at,
                run.state AS run_state,
                run.aggregate_version AS run_version,
                anchor.anchor_type,
                anchor.reference_id,
                effect.status AS effect_status,
                effect.attempt_count AS effect_attempt_count,
                effect.observed_outcome,
                effect.lease_owner AS effect_lease_owner
            FROM workflow_jobs AS job
            JOIN work_items AS work
              ON work.tenant_id = job.tenant_id AND work.id = job.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = job.tenant_id AND workflow.id = job.workflow_instance_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = job.tenant_id AND attempt.id = job.attempt_id
            JOIN runs AS run
              ON run.tenant_id = job.tenant_id AND run.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = job.tenant_id AND anchor.work_item_id = job.work_item_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = job.tenant_id
             AND effect.work_item_id = job.work_item_id
             AND effect.attempt_id = job.attempt_id
             AND effect.effect_type = 'request_cancellation'
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load committed cancellation");
        assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "COMPLETED");
        assert_eq!(
            row.try_get::<Value, _>("job_result").unwrap()["result"]["route"],
            "cancellation_in_progress"
        );
        assert_eq!(
            row.try_get::<Value, _>("job_result").unwrap()["result"]["released_reservations"],
            0
        );
        assert_eq!(
            row.try_get::<String, _>("work_state").unwrap(),
            "CANCEL_REQUESTED"
        );
        assert_eq!(row.try_get::<i64, _>("work_version").unwrap(), 2);
        assert_eq!(
            row.try_get::<String, _>("workflow_state").unwrap(),
            "WAITING"
        );
        assert_eq!(row.try_get::<i64, _>("workflow_version").unwrap(), 2);
        assert_eq!(row.try_get::<i64, _>("workflow_fence").unwrap(), 1);
        assert_eq!(
            row.try_get::<String, _>("attempt_state").unwrap(),
            "CANCEL_REQUESTED"
        );
        assert_eq!(row.try_get::<i64, _>("attempt_version").unwrap(), 2);
        assert!(
            row.try_get::<Option<chrono::DateTime<Utc>>, _>("attempt_terminal_at")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            row.try_get::<String, _>("run_state").unwrap(),
            "CANCEL_REQUESTED"
        );
        assert_eq!(row.try_get::<i64, _>("run_version").unwrap(), 2);
        assert_eq!(row.try_get::<String, _>("anchor_type").unwrap(), "WORKFLOW");
        assert_eq!(
            row.try_get::<Uuid, _>("reference_id").unwrap(),
            fixture.job.workflow_instance_id.unwrap()
        );
        assert_eq!(
            row.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        assert_eq!(row.try_get::<i32, _>("effect_attempt_count").unwrap(), 1);
        assert!(
            row.try_get::<Value, _>("observed_outcome").unwrap()["reconciliation_required"]
                .as_bool()
                .unwrap()
        );
        assert!(
            row.try_get::<Option<String>, _>("effect_lease_owner")
                .unwrap()
                .is_none()
        );

        let provenance = sqlx::query(
            r"
            SELECT
                observation.id AS observation_id,
                observation.route AS observation_route,
                observation.prior_observation_id,
                observation.workflow_job_id AS observation_job_id,
                observation.workflow_job_fence_token AS observation_job_fence,
                observation.workflow_job_attempt_count AS observation_job_attempt,
                observation.receipt_digest,
                effect.initial_cancellation_observation_id,
                effect.observed_outcome AS effect_outcome,
                run.snapshot -> 'runmill_cancellation' AS run_cancellation,
                job.result AS job_result,
                audit.details AS audit_details,
                outbox.payload AS outbox_payload
            FROM runmill_cancellation_observations AS observation
            JOIN effect_intents AS effect
              ON effect.tenant_id = observation.tenant_id
             AND effect.id = observation.effect_intent_id
            JOIN runs AS run
              ON run.tenant_id = observation.tenant_id
             AND run.id = observation.run_id
            JOIN workflow_jobs AS job
              ON job.tenant_id = observation.tenant_id
             AND job.id = observation.workflow_job_id
            JOIN audit_events AS audit
              ON audit.tenant_id = observation.tenant_id
             AND audit.work_item_id = observation.work_item_id
             AND audit.action = 'RUNMILL_CANCELLATION_ACCEPTED'
            JOIN outbox
              ON outbox.tenant_id = observation.tenant_id
             AND outbox.event_type = 'work_item.cancellation_in_progress'
             AND outbox.message_key = observation.work_item_id::text
            WHERE observation.tenant_id = $1
              AND observation.effect_intent_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(stable_cancellation_effect_id(fixture.run_id))
        .fetch_one(database.ledger.pool())
        .await
        .expect("load initial cancellation observation provenance");
        let initial_observation_id =
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token);
        assert_eq!(
            provenance.try_get::<Uuid, _>("observation_id").unwrap(),
            initial_observation_id
        );
        assert_eq!(
            provenance
                .try_get::<String, _>("observation_route")
                .unwrap(),
            "INITIAL"
        );
        assert!(
            provenance
                .try_get::<Option<Uuid>, _>("prior_observation_id")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provenance.try_get::<Uuid, _>("observation_job_id").unwrap(),
            fixture.job.id
        );
        assert_eq!(
            provenance
                .try_get::<i64, _>("observation_job_fence")
                .unwrap(),
            fixture.job.fence_token
        );
        assert_eq!(
            provenance
                .try_get::<i32, _>("observation_job_attempt")
                .unwrap(),
            fixture.job.attempt_count
        );
        assert!(is_sha256_digest(
            &provenance.try_get::<String, _>("receipt_digest").unwrap()
        ));
        assert_eq!(
            provenance
                .try_get::<Option<Uuid>, _>("initial_cancellation_observation_id")
                .unwrap(),
            Some(initial_observation_id)
        );
        for payload in [
            provenance.try_get::<Value, _>("effect_outcome").unwrap(),
            provenance.try_get::<Value, _>("run_cancellation").unwrap(),
            provenance.try_get::<Value, _>("job_result").unwrap()["result"].clone(),
            provenance.try_get::<Value, _>("audit_details").unwrap(),
            provenance.try_get::<Value, _>("outbox_payload").unwrap(),
        ] {
            assert_eq!(
                payload["cancellation_observation_id"],
                json!(initial_observation_id)
            );
        }

        let observation_job_id = derived_uuid(stable_cancellation_effect_id(fixture.run_id), 5);
        assert_eq!(
            row.try_get::<Value, _>("job_result").unwrap()["result"]["observation_job"]["id"],
            json!(observation_job_id)
        );
        let observer = sqlx::query(
            r"
            SELECT
                status, workflow_instance_id, work_item_id, attempt_id, job_type,
                payload, idempotency_key, priority, available_at, attempt_count,
                max_attempts
            FROM workflow_jobs
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(observation_job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load durable terminal cancellation observer");
        assert_eq!(observer.try_get::<String, _>("status").unwrap(), "PENDING");
        assert_eq!(
            observer
                .try_get::<Option<Uuid>, _>("workflow_instance_id")
                .unwrap(),
            fixture.job.workflow_instance_id
        );
        assert_eq!(
            observer.try_get::<Option<Uuid>, _>("work_item_id").unwrap(),
            Some(fixture.work_item_id)
        );
        assert_eq!(
            observer.try_get::<Option<Uuid>, _>("attempt_id").unwrap(),
            Some(fixture.attempt_id)
        );
        assert_eq!(
            observer.try_get::<String, _>("job_type").unwrap(),
            REQUEST_WORK_ITEM_CANCELLATION
        );
        let observer_payload = observer.try_get::<Value, _>("payload").unwrap();
        assert_eq!(observer_payload["worker_id"], json!(fixture.worker_id));
        assert_eq!(
            observer_payload["work_item_id"],
            json!(fixture.work_item_id)
        );
        assert_eq!(observer_payload["expected_version"], json!(2));
        assert_eq!(observer_payload["observe_only"], json!(true));
        assert_eq!(observer.try_get::<i16, _>("priority").unwrap(), 0);
        assert_eq!(observer.try_get::<i32, _>("attempt_count").unwrap(), 0);
        assert_eq!(observer.try_get::<i32, _>("max_attempts").unwrap(), 5);
        assert!(
            observer
                .try_get::<chrono::DateTime<Utc>, _>("available_at")
                .unwrap()
                > Utc::now()
        );

        // Keep the workflow accountability anchor live with an unrelated job
        // so this attack reaches the dedicated observer-obligation guard
        // rather than failing only because it would strand the workflow.
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, payload, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5, 'TEST_KEEP_WORKFLOW_LIVE',
                'test.activity/test-keep-workflow-live/v1', '{}'::jsonb, $6
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id.unwrap())
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("test-keep-workflow-live:{}", fixture.work_item_id))
        .execute(database.ledger.pool())
        .await
        .expect("insert decoy live job for observer-obligation attack");

        let cancellation_error = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'CANCELLED', updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2 AND status = 'PENDING'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(observation_job_id)
        .execute(database.ledger.pool())
        .await
        .expect_err("a nonterminal cancellation observer cannot be silently cancelled");
        let cancellation_database_error = cancellation_error
            .as_database_error()
            .expect("observer-obligation rejection must be a PostgreSQL error");
        assert_eq!(cancellation_database_error.code().as_deref(), Some("23514"));
        assert!(
            cancellation_database_error
                .message()
                .contains("cannot be cancelled before terminal proof")
        );
        let observer_status: String =
            sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(observation_job_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("reload observer after rejected silent cancellation");
        assert_eq!(observer_status, "PENDING");

        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND work_item_id = $2 AND action = 'RUNMILL_CANCELLATION_ACCEPTED'",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count cancellation audit");
        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox WHERE tenant_id = $1 AND event_type = 'work_item.cancellation_in_progress'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count cancellation outbox");
        assert_eq!(audit_count, 1);
        assert_eq!(outbox_count, 1);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn cancellation_commit_rejects_an_outbox_poisoned_before_commit() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };

        for (phase, expected_message) in [
            (
                RunmillRunPhase::CancelRequested,
                "completed cancellation job has no exact observation receipt",
            ),
            (
                RunmillRunPhase::Cancelled,
                "cancellation terminal receipt outbox was not freshly publishable",
            ),
        ] {
            let database = ScopedDatabase::create(&database_url).await;
            let fixture = LiveFixture::insert(&database.ledger).await;
            sqlx::query(
                r"
                CREATE FUNCTION asf_test_poison_cancellation_outbox()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    UPDATE outbox
                    SET status = 'DEAD'
                    WHERE tenant_id = NEW.tenant_id AND id = NEW.id;
                    RETURN NULL;
                END;
                $function$
                ",
            )
            .execute(database.ledger.pool())
            .await
            .expect("install adversarial outbox poison function");
            sqlx::query(
                r"
                CREATE TRIGGER zzz_test_poison_cancellation_outbox
                    AFTER INSERT ON outbox
                    FOR EACH ROW
                    EXECUTE FUNCTION asf_test_poison_cancellation_outbox()
                ",
            )
            .execute(database.ledger.pool())
            .await
            .expect("install adversarial outbox poison trigger");

            let control = fixture.control(vec![phase, phase], phase, false);
            let handler = RunmillCancellationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control,
                "asf:test-controller",
                30,
            )
            .expect("construct cancellation handler");
            let error = handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect_err("a poisoned cancellation outbox must abort the commit");
            assert!(
                error.to_string().contains(expected_message),
                "unexpected poisoned-outbox error for {phase:?}: {error}"
            );
            let emitted: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM outbox WHERE tenant_id = $1 AND event_type LIKE 'work_item.cancellation%'",
            )
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count rolled-back cancellation outbox rows");
            assert_eq!(emitted, 0);
            database.cleanup().await;
        }
    }

    #[tokio::test]
    async fn terminal_observer_completes_without_reissuing_the_cancellation_effect() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let control = fixture.control(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
                RunmillRunPhase::Cancelled,
            ],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = Arc::new(
            RunmillCancellationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
                "asf:test-controller",
                1,
            )
            .expect("construct cancellation handler"),
        );
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("commit initial nonterminal cancellation"),
            ActivityOutcome::TransactionCommitted
        );
        assert_eq!(control.cancellation_calls(), 1);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);

        let observation_job_id = derived_uuid(stable_cancellation_effect_id(fixture.run_id), 5);
        let effect_before: Value = sqlx::query_scalar(
            r"
            SELECT observed_outcome
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load initial observed cancellation effect");
        sqlx::query(
            r"
            UPDATE workflow_jobs
            SET available_at = clock_timestamp() - interval '1 second'
            WHERE tenant_id = $1 AND id = $2 AND status = 'PENDING'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(observation_job_id)
        .execute(database.ledger.pool())
        .await
        .expect("make terminal cancellation observer due");

        let mut registry = HandlerRegistry::new();
        registry
            .register(handler.clone())
            .expect("register cancellation observer");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            ReactorOptions {
                lease_owner: "reactor:terminal-cancellation-observer".into(),
                poll_interval: StdDuration::from_millis(10),
                lease_duration: StdDuration::from_secs(5),
                max_error_backoff: StdDuration::from_secs(1),
                claim_batch_size: 4,
            },
            false,
        )
        .expect("construct terminal cancellation observer reactor");
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("observe terminal Runmill cancellation"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(
            control.cancellation_calls(),
            1,
            "observation mode must never call request_cancel"
        );

        let terminal = sqlx::query(
            r"
            SELECT
                observer.status AS observer_status,
                observer.result AS observer_result,
                work.state AS work_state,
                workflow.state AS workflow_state,
                attempt.state AS attempt_state,
                run.state AS run_state,
                anchor.anchor_type,
                anchor.reference_id,
                effect.status AS effect_status,
                effect.observed_outcome
            FROM workflow_jobs AS observer
            JOIN work_items AS work
              ON work.tenant_id = observer.tenant_id AND work.id = observer.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = observer.tenant_id
             AND workflow.id = observer.workflow_instance_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = observer.tenant_id AND attempt.id = observer.attempt_id
            JOIN runs AS run
              ON run.tenant_id = observer.tenant_id AND run.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = observer.tenant_id
             AND anchor.work_item_id = observer.work_item_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = observer.tenant_id
             AND effect.work_item_id = observer.work_item_id
             AND effect.attempt_id = observer.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
            WHERE observer.tenant_id = $1 AND observer.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(observation_job_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal cancellation observation");
        assert_eq!(
            terminal.try_get::<String, _>("observer_status").unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            terminal.try_get::<Value, _>("observer_result").unwrap()["result"]["released_reservations"],
            1
        );
        assert_eq!(
            terminal.try_get::<String, _>("work_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            terminal.try_get::<String, _>("workflow_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            terminal.try_get::<String, _>("attempt_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            terminal.try_get::<String, _>("run_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            terminal.try_get::<String, _>("anchor_type").unwrap(),
            "CANCELLATION"
        );
        assert_eq!(
            terminal.try_get::<Uuid, _>("reference_id").unwrap(),
            stable_cancellation_terminal_receipt_id(observation_job_id)
        );
        assert_eq!(
            terminal.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        assert_eq!(
            terminal.try_get::<Value, _>("observed_outcome").unwrap(),
            effect_before,
            "terminal observation must not rewrite the immutable effect receipt"
        );
        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(observation_job_id);
        let initial_observation_id =
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token);
        let terminal_observation_id = stable_cancellation_observation_id(observation_job_id, 1);
        let receipt = sqlx::query(
            r"
            SELECT
                receipt.id AS receipt_id,
                receipt.route,
                receipt.outcome,
                receipt.terminal_observation_id,
                receipt.workflow_job_id,
                receipt.workflow_job_fence_token,
                receipt.workflow_job_attempt_count,
                receipt.workflow_job_completed_by,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                receipt.work_item_version_before,
                receipt.work_item_version_after,
                receipt.attempt_version_before,
                receipt.attempt_version_after,
                receipt.run_version_before,
                receipt.run_version_after,
                receipt.workflow_version_before,
                receipt.workflow_version_after,
                receipt.workflow_fence_before,
                receipt.workflow_fence_after,
                receipt.anchor_generation_before,
                receipt.anchor_generation_after,
                receipt.released_reservations,
                observation.route AS observation_route,
                observation.prior_observation_id,
                effect.initial_cancellation_observation_id,
                observer.result AS observer_result,
                audit.details AS audit_details,
                outbox.payload AS outbox_payload,
                run.snapshot -> 'runmill_cancellation' AS run_cancellation
            FROM cancellation_terminal_receipts AS receipt
            JOIN runmill_cancellation_observations AS observation
              ON observation.tenant_id = receipt.tenant_id
             AND observation.id = receipt.terminal_observation_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = receipt.tenant_id
             AND effect.id = receipt.effect_intent_id
            JOIN workflow_jobs AS observer
              ON observer.tenant_id = receipt.tenant_id
             AND observer.id = receipt.workflow_job_id
            JOIN audit_events AS audit
              ON audit.tenant_id = receipt.tenant_id
             AND audit.id = receipt.audit_event_id
            JOIN outbox
              ON outbox.tenant_id = receipt.tenant_id
             AND outbox.id = receipt.outbox_event_id
            JOIN runs AS run
              ON run.tenant_id = receipt.tenant_id
             AND run.id = receipt.run_id
            WHERE receipt.tenant_id = $1 AND receipt.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal cancellation receipt provenance");
        assert_eq!(
            receipt.try_get::<Uuid, _>("receipt_id").unwrap(),
            terminal_receipt_id
        );
        assert_eq!(receipt.try_get::<String, _>("route").unwrap(), "RUNMILL");
        assert_eq!(
            receipt.try_get::<String, _>("outcome").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            receipt
                .try_get::<Uuid, _>("terminal_observation_id")
                .unwrap(),
            terminal_observation_id
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("workflow_job_id").unwrap(),
            observation_job_id
        );
        assert_eq!(
            receipt
                .try_get::<i64, _>("workflow_job_fence_token")
                .unwrap(),
            1
        );
        assert_eq!(
            receipt
                .try_get::<i32, _>("workflow_job_attempt_count")
                .unwrap(),
            1
        );
        assert_eq!(
            receipt
                .try_get::<String, _>("workflow_job_completed_by")
                .unwrap(),
            "reactor:terminal-cancellation-observer"
        );
        assert_eq!(
            receipt.try_get::<String, _>("observation_route").unwrap(),
            "OBSERVER"
        );
        assert_eq!(
            receipt
                .try_get::<Option<Uuid>, _>("prior_observation_id")
                .unwrap(),
            Some(initial_observation_id)
        );
        assert_eq!(
            receipt
                .try_get::<Option<Uuid>, _>("initial_cancellation_observation_id")
                .unwrap(),
            Some(initial_observation_id)
        );
        for (column, expected) in [
            ("work_item_version_before", 2_i64),
            ("work_item_version_after", 3),
            ("attempt_version_before", 2),
            ("attempt_version_after", 3),
            ("run_version_before", 2),
            ("run_version_after", 3),
            ("workflow_version_before", 2),
            ("workflow_version_after", 3),
            ("workflow_fence_before", 1),
            ("workflow_fence_after", 2),
            ("anchor_generation_before", 2),
            ("anchor_generation_after", 3),
            ("released_reservations", 1),
        ] {
            assert_eq!(receipt.try_get::<i64, _>(column).unwrap(), expected);
        }
        assert_eq!(
            receipt.try_get::<Uuid, _>("audit_event_id").unwrap(),
            derived_uuid(observation_job_id, 1)
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("outbox_event_id").unwrap(),
            derived_uuid(observation_job_id, 2)
        );
        for payload in [
            receipt.try_get::<Value, _>("observer_result").unwrap()["result"].clone(),
            receipt.try_get::<Value, _>("audit_details").unwrap(),
            receipt.try_get::<Value, _>("outbox_payload").unwrap(),
        ] {
            assert_eq!(
                payload["cancellation_observation_id"],
                json!(terminal_observation_id)
            );
            assert_eq!(payload["terminal_receipt_id"], json!(terminal_receipt_id));
        }
        let run_cancellation = receipt.try_get::<Value, _>("run_cancellation").unwrap();
        assert_eq!(
            run_cancellation["cancellation_observation_id"],
            json!(terminal_observation_id)
        );
        assert_eq!(
            run_cancellation["prior_cancellation_observation_id"],
            json!(initial_observation_id)
        );
        let cancellation_job_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM workflow_jobs
            WHERE tenant_id = $1
              AND workflow_instance_id = $2
              AND job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count cancellation workflow jobs");
        assert_eq!(cancellation_job_count, 2);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_released(
            &fixture,
            reservation_set_id,
            "reactor:terminal-cancellation-observer",
            terminal_receipt_id,
            &reservation,
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn nonterminal_observer_retries_then_escalates_without_reissuing_cancellation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert_with_max_attempts(&database.ledger, 2).await;
        let control = fixture.control(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
                RunmillRunPhase::CancelRequested,
            ],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = Arc::new(
            RunmillCancellationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
                "asf:test-controller",
                1,
            )
            .expect("construct cancellation handler"),
        );
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("commit initial nonterminal cancellation"),
            ActivityOutcome::TransactionCommitted
        );
        assert_eq!(control.cancellation_calls(), 1);

        let observation_job_id = derived_uuid(stable_cancellation_effect_id(fixture.run_id), 5);
        let effect_before: Value = sqlx::query_scalar(
            r"
            SELECT observed_outcome
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load initial observed cancellation effect");

        let mut registry = HandlerRegistry::new();
        registry
            .register(handler.clone())
            .expect("register cancellation observer");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            ReactorOptions {
                lease_owner: "reactor:retrying-cancellation-observer".into(),
                poll_interval: StdDuration::from_millis(10),
                lease_duration: StdDuration::from_secs(5),
                max_error_backoff: StdDuration::from_secs(1),
                claim_batch_size: 4,
            },
            false,
        )
        .expect("construct retrying cancellation observer reactor");

        for expected_attempt in 1..=2 {
            sqlx::query(
                r"
                UPDATE workflow_jobs
                SET available_at = clock_timestamp() - interval '1 second'
                WHERE tenant_id = $1
                  AND id = $2
                  AND status IN ('PENDING', 'RETRY')
                ",
            )
            .bind(fixture.tenant_id)
            .bind(observation_job_id)
            .execute(database.ledger.pool())
            .await
            .expect("make nonterminal cancellation observer due");
            let report = reactor
                .poll_once()
                .await
                .expect("observe still-nonterminal Runmill cancellation");
            if expected_attempt == 1 {
                assert_eq!(
                    report,
                    ReactorPollReport {
                        jobs_claimed: 1,
                        jobs_retried: 1,
                        ..ReactorPollReport::default()
                    }
                );
                let retry: (String, i32) = sqlx::query_as(
                    "SELECT status, attempt_count FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
                )
                .bind(fixture.tenant_id)
                .bind(observation_job_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load retried cancellation observer");
                assert_eq!(retry, ("RETRY".into(), 1));
            } else {
                assert_eq!(
                    report,
                    ReactorPollReport {
                        jobs_claimed: 1,
                        jobs_transactionally_finalized: 1,
                        ..ReactorPollReport::default()
                    }
                );
            }
            assert_eq!(
                control.cancellation_calls(),
                1,
                "observation attempts must never call request_cancel"
            );
        }

        let chain = sqlx::query(
            r"
            WITH RECURSIVE chain AS (
                SELECT
                    observation.id,
                    observation.route,
                    observation.prior_observation_id,
                    observation.workflow_job_id,
                    observation.workflow_job_fence_token,
                    observation.workflow_job_attempt_count,
                    observation.workflow_job_owner,
                    observation.external_phase,
                    observation.receipt_digest,
                    0::bigint AS depth
                FROM runmill_cancellation_observations AS observation
                WHERE observation.tenant_id = $1
                  AND observation.effect_intent_id = $2
                  AND observation.route = 'INITIAL'
                UNION ALL
                SELECT
                    observation.id,
                    observation.route,
                    observation.prior_observation_id,
                    observation.workflow_job_id,
                    observation.workflow_job_fence_token,
                    observation.workflow_job_attempt_count,
                    observation.workflow_job_owner,
                    observation.external_phase,
                    observation.receipt_digest,
                    chain.depth + 1
                FROM runmill_cancellation_observations AS observation
                JOIN chain
                  ON observation.tenant_id = $1
                 AND observation.prior_observation_id = chain.id
            )
            SELECT * FROM chain ORDER BY depth
            ",
        )
        .bind(fixture.tenant_id)
        .bind(stable_cancellation_effect_id(fixture.run_id))
        .fetch_all(database.ledger.pool())
        .await
        .expect("load chained nonterminal cancellation observations");
        assert_eq!(chain.len(), 3);
        let initial_observation_id =
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token);
        assert_eq!(
            chain[0].try_get::<Uuid, _>("id").unwrap(),
            initial_observation_id
        );
        assert_eq!(chain[0].try_get::<String, _>("route").unwrap(), "INITIAL");
        assert!(
            chain[0]
                .try_get::<Option<Uuid>, _>("prior_observation_id")
                .unwrap()
                .is_none()
        );
        for (index, fence_token) in [1_i64, 2_i64].into_iter().enumerate() {
            let observation = &chain[index + 1];
            let expected_id = stable_cancellation_observation_id(observation_job_id, fence_token);
            let expected_prior = if index == 0 {
                initial_observation_id
            } else {
                stable_cancellation_observation_id(observation_job_id, fence_token - 1)
            };
            assert_eq!(observation.try_get::<Uuid, _>("id").unwrap(), expected_id);
            assert_eq!(
                observation.try_get::<String, _>("route").unwrap(),
                "OBSERVER"
            );
            assert_eq!(
                observation
                    .try_get::<Option<Uuid>, _>("prior_observation_id")
                    .unwrap(),
                Some(expected_prior)
            );
            assert_eq!(
                observation.try_get::<Uuid, _>("workflow_job_id").unwrap(),
                observation_job_id
            );
            assert_eq!(
                observation
                    .try_get::<i64, _>("workflow_job_fence_token")
                    .unwrap(),
                fence_token
            );
            assert_eq!(
                observation
                    .try_get::<i32, _>("workflow_job_attempt_count")
                    .unwrap(),
                i32::try_from(fence_token).unwrap()
            );
            assert_eq!(
                observation
                    .try_get::<String, _>("workflow_job_owner")
                    .unwrap(),
                "reactor:retrying-cancellation-observer"
            );
            assert_eq!(
                observation.try_get::<String, _>("external_phase").unwrap(),
                "CANCEL_REQUESTED"
            );
            assert!(is_sha256_digest(
                &observation.try_get::<String, _>("receipt_digest").unwrap()
            ));
        }

        let escalated = sqlx::query(
            r"
            SELECT
                observer.status AS observer_status,
                observer.attempt_count,
                work.state AS work_state,
                work.aggregate_version AS work_version,
                workflow.state AS workflow_state,
                anchor.anchor_type,
                anchor.reference_id,
                anchor.generation AS anchor_generation,
                escalation.category,
                escalation.status AS escalation_status,
                escalation.aggregate_version AS escalation_version,
                escalation.evidence_references AS escalation_evidence,
                asf_terminal_conflict_escalation_digest(
                    escalation.tenant_id, escalation.id
                ) AS escalation_digest,
                observer.dead_letter_escalation_id,
                observer.result AS dead_job_result,
                effect.status AS effect_status,
                effect.observed_outcome
            FROM workflow_jobs AS observer
            JOIN work_items AS work
              ON work.tenant_id = observer.tenant_id AND work.id = observer.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = observer.tenant_id
             AND workflow.id = observer.workflow_instance_id
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = observer.tenant_id
             AND anchor.work_item_id = observer.work_item_id
            JOIN escalations AS escalation
              ON escalation.tenant_id = observer.tenant_id
             AND escalation.id = anchor.reference_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = observer.tenant_id
             AND effect.work_item_id = observer.work_item_id
             AND effect.attempt_id = observer.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
            WHERE observer.tenant_id = $1 AND observer.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(observation_job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load exhausted cancellation observer escalation");
        assert_eq!(
            escalated.try_get::<String, _>("observer_status").unwrap(),
            "DEAD"
        );
        assert_eq!(escalated.try_get::<i32, _>("attempt_count").unwrap(), 2);
        assert_eq!(
            escalated.try_get::<String, _>("work_state").unwrap(),
            "ESCALATED"
        );
        assert_eq!(
            escalated.try_get::<String, _>("workflow_state").unwrap(),
            "WAITING"
        );
        assert_eq!(
            escalated.try_get::<String, _>("anchor_type").unwrap(),
            "ESCALATION"
        );
        assert_eq!(
            escalated.try_get::<String, _>("category").unwrap(),
            "WORKFLOW_JOB_EXHAUSTED"
        );
        assert_eq!(
            escalated.try_get::<String, _>("escalation_status").unwrap(),
            "OPEN"
        );
        assert_eq!(
            escalated.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        assert_eq!(
            escalated.try_get::<Value, _>("observed_outcome").unwrap(),
            effect_before
        );
        let exhausted_escalation_id = escalated.try_get::<Uuid, _>("reference_id").unwrap();
        assert_eq!(
            escalated
                .try_get::<Option<Uuid>, _>("dead_letter_escalation_id")
                .unwrap(),
            Some(exhausted_escalation_id)
        );
        let exhausted_escalation_version =
            escalated.try_get::<i64, _>("escalation_version").unwrap();
        let exhausted_anchor_generation = escalated.try_get::<i64, _>("anchor_generation").unwrap();
        let exhausted_escalation_digest =
            escalated.try_get::<String, _>("escalation_digest").unwrap();
        let exhausted_escalation_evidence = escalated
            .try_get::<Value, _>("escalation_evidence")
            .unwrap();
        let exhausted_dead_job_result = escalated.try_get::<Value, _>("dead_job_result").unwrap();

        control
            .phases
            .lock()
            .expect("phase script poisoned")
            .push_back(RunmillRunPhase::Cancelled);
        let mut recovery_registry = HandlerRegistry::new();
        recovery_registry
            .register(handler.clone())
            .expect("register cancellation recovery observer");
        let backend = PostgresApiBackend::from_ledger(
            &database.ledger,
            TenantId::from_uuid(fixture.tenant_id),
        )
        .with_activity_capabilities(recovery_registry.api_activity_capabilities());
        let caller = Caller {
            subject: "operator:recovery".into(),
            roles: BTreeSet::from([Role::Operator]),
        };
        let escalated_version = u64::try_from(escalated.try_get::<i64, _>("work_version").unwrap())
            .expect("positive escalated work-item version");
        let escalated_version_i64 =
            i64::try_from(escalated_version).expect("escalated work-item version fits PostgreSQL");
        let receipt = backend
            .cancel_work_item(
                TenantId::from_uuid(fixture.tenant_id),
                WorkItemId::from_uuid(fixture.work_item_id),
                &CancellationRequest {
                    expected_version: escalated_version,
                    reason: "Re-observe the durable cancellation request".into(),
                },
                &caller,
                "replacement-observed-cancellation",
            )
            .await
            .expect("enqueue API-style replacement cancellation observation");
        assert_eq!(receipt.status, "cancellation_requested");
        assert_eq!(receipt.version, Some(escalated_version + 1));

        let supersession = sqlx::query(
            r"
            SELECT
                supersession.id AS supersession_receipt_id,
                supersession.idempotency_record_id,
                supersession.actor_id,
                supersession.request_digest,
                supersession.replacement_workflow_id,
                supersession.replacement_job_id,
                supersession.work_item_version_before,
                supersession.work_item_version_after,
                supersession.anchor_generation_before,
                supersession.anchor_generation_after,
                supersession.cancellation_authority_generation,
                supersession.escalation_status_before,
                supersession.escalation_version_before,
                supersession.escalation_version_after,
                supersession.escalation_before_digest,
                supersession.escalation_after_digest,
                supersession.dead_workflow_job_ids,
                supersession.audit_event_id,
                supersession.outbox_event_id,
                supersession.superseded_at,
                supersession.recorded_at,
                supersession.receipt_digest,
                escalation.status AS superseded_status,
                escalation.authority_or_effect_active AS superseded_authority,
                escalation.closed_at AS escalation_closed_at,
                escalation.evidence_references AS retained_escalation_evidence,
                dead_job.status AS dead_job_status,
                dead_job.dead_letter_escalation_id AS retained_dead_letter_escalation_id,
                dead_job.result AS retained_dead_job_result,
                anchor.anchor_type AS replacement_anchor_type,
                anchor.reference_id AS replacement_anchor_reference,
                anchor.generation AS replacement_anchor_generation,
                idempotency.state AS idempotency_state,
                idempotency.response_status,
                idempotency.response_body,
                audit.action AS supersession_audit_action,
                audit.before_digest AS supersession_audit_before_digest,
                audit.after_digest AS supersession_audit_after_digest,
                audit.details AS supersession_audit_details,
                audit.occurred_at AS supersession_audit_occurred_at,
                outbox.event_type AS supersession_event_type,
                outbox.payload AS supersession_outbox_payload,
                outbox.created_at AS supersession_outbox_created_at,
                authority_guard.generation AS current_authority_generation,
                escalation_fact.fact_digest AS escalation_transition_fact_digest,
                anchor_fact.fact_digest AS anchor_transition_fact_digest,
                work_fact.fact_digest AS work_transition_fact_digest,
                asf_valid_cancellation_escalation_supersession_receipt(
                    supersession.tenant_id, supersession.id, true
                ) AS exact_fresh_receipt
            FROM cancellation_escalation_supersession_receipts AS supersession
            JOIN escalations AS escalation
              ON escalation.tenant_id = supersession.tenant_id
             AND escalation.id = supersession.escalation_id
            JOIN workflow_jobs AS dead_job
              ON dead_job.tenant_id = supersession.tenant_id
             AND dead_job.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = supersession.tenant_id
             AND anchor.work_item_id = supersession.work_item_id
            JOIN idempotency_records AS idempotency
              ON idempotency.tenant_id = supersession.tenant_id
             AND idempotency.id = supersession.idempotency_record_id
            JOIN audit_events AS audit
              ON audit.tenant_id = supersession.tenant_id
             AND audit.id = supersession.audit_event_id
            JOIN outbox
              ON outbox.tenant_id = supersession.tenant_id
             AND outbox.id = supersession.outbox_event_id
            JOIN work_cancellation_authority_guards AS authority_guard
              ON authority_guard.tenant_id = supersession.tenant_id
             AND authority_guard.work_item_id = supersession.work_item_id
            JOIN cancellation_supersession_escalation_facts AS escalation_fact
              ON escalation_fact.tenant_id = supersession.tenant_id
             AND escalation_fact.escalation_id = supersession.escalation_id
            JOIN cancellation_supersession_anchor_facts AS anchor_fact
              ON anchor_fact.tenant_id = supersession.tenant_id
             AND anchor_fact.escalation_id = supersession.escalation_id
            JOIN cancellation_supersession_work_facts AS work_fact
              ON work_fact.tenant_id = supersession.tenant_id
             AND work_fact.escalation_id = supersession.escalation_id
            WHERE supersession.tenant_id = $1
              AND supersession.escalation_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(exhausted_escalation_id)
        .bind(observation_job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load exact cancellation escalation supersession proof");
        let idempotency_record_id = supersession
            .try_get::<Uuid, _>("idempotency_record_id")
            .unwrap();
        let supersession_receipt_id = derived_uuid(idempotency_record_id, 3);
        let supersession_outbox_id = derived_uuid(idempotency_record_id, 4);
        let replacement_job_id = supersession
            .try_get::<Uuid, _>("replacement_job_id")
            .unwrap();
        let superseded_at = supersession
            .try_get::<chrono::DateTime<Utc>, _>("superseded_at")
            .unwrap();
        let recorded_at = supersession
            .try_get::<chrono::DateTime<Utc>, _>("recorded_at")
            .unwrap();
        let escalation_after_digest = supersession
            .try_get::<String, _>("escalation_after_digest")
            .unwrap();
        let expected_api_request_digest = sha256_digest(
            &canonical_json(&json!({
                "work_item_id": fixture.work_item_id,
                "expected_version": escalated_version,
                "reason": "Re-observe the durable cancellation request",
            }))
            .expect("canonicalize API cancellation request"),
        );
        assert_eq!(
            supersession
                .try_get::<Uuid, _>("supersession_receipt_id")
                .unwrap(),
            supersession_receipt_id
        );
        assert_eq!(
            supersession.try_get::<String, _>("actor_id").unwrap(),
            "operator:recovery"
        );
        assert_eq!(
            supersession.try_get::<String, _>("request_digest").unwrap(),
            expected_api_request_digest
        );
        assert_eq!(
            supersession
                .try_get::<Uuid, _>("replacement_workflow_id")
                .unwrap(),
            fixture.job.workflow_instance_id.unwrap()
        );
        for (column, expected) in [
            ("work_item_version_before", escalated_version_i64),
            ("work_item_version_after", escalated_version_i64 + 1),
            ("anchor_generation_before", exhausted_anchor_generation),
            ("anchor_generation_after", exhausted_anchor_generation + 1),
            ("escalation_version_before", exhausted_escalation_version),
            ("escalation_version_after", exhausted_escalation_version + 1),
        ] {
            assert_eq!(supersession.try_get::<i64, _>(column).unwrap(), expected);
        }
        assert_eq!(
            supersession
                .try_get::<String, _>("escalation_status_before")
                .unwrap(),
            "OPEN"
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("escalation_before_digest")
                .unwrap(),
            exhausted_escalation_digest
        );
        assert!(is_sha256_digest(&escalation_after_digest));
        assert_ne!(escalation_after_digest, exhausted_escalation_digest);
        assert_eq!(
            supersession
                .try_get::<Vec<Uuid>, _>("dead_workflow_job_ids")
                .unwrap(),
            vec![observation_job_id]
        );
        assert_eq!(
            supersession.try_get::<Uuid, _>("outbox_event_id").unwrap(),
            supersession_outbox_id
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("superseded_status")
                .unwrap(),
            "CANCELLED"
        );
        assert!(
            !supersession
                .try_get::<bool, _>("superseded_authority")
                .unwrap()
        );
        assert_eq!(
            supersession
                .try_get::<chrono::DateTime<Utc>, _>("escalation_closed_at")
                .unwrap(),
            superseded_at
        );
        assert_eq!(
            supersession
                .try_get::<Value, _>("retained_escalation_evidence")
                .unwrap(),
            exhausted_escalation_evidence
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("dead_job_status")
                .unwrap(),
            "DEAD"
        );
        assert_eq!(
            supersession
                .try_get::<Option<Uuid>, _>("retained_dead_letter_escalation_id")
                .unwrap(),
            Some(exhausted_escalation_id)
        );
        assert_eq!(
            supersession
                .try_get::<Value, _>("retained_dead_job_result")
                .unwrap(),
            exhausted_dead_job_result
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("replacement_anchor_type")
                .unwrap(),
            "WORKFLOW"
        );
        assert_eq!(
            supersession
                .try_get::<Uuid, _>("replacement_anchor_reference")
                .unwrap(),
            fixture.job.workflow_instance_id.unwrap()
        );
        assert_eq!(
            supersession
                .try_get::<i64, _>("replacement_anchor_generation")
                .unwrap(),
            exhausted_anchor_generation + 1
        );
        assert_eq!(
            supersession
                .try_get::<i64, _>("cancellation_authority_generation")
                .unwrap(),
            supersession
                .try_get::<i64, _>("current_authority_generation")
                .unwrap()
        );
        for column in [
            "escalation_transition_fact_digest",
            "anchor_transition_fact_digest",
            "work_transition_fact_digest",
        ] {
            assert!(is_sha256_digest(
                &supersession.try_get::<String, _>(column).unwrap()
            ));
        }
        assert_eq!(
            supersession
                .try_get::<String, _>("idempotency_state")
                .unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            supersession.try_get::<i32, _>("response_status").unwrap(),
            202
        );
        assert_eq!(
            supersession.try_get::<Value, _>("response_body").unwrap(),
            serde_json::to_value(&receipt).expect("serialize cancellation receipt")
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("supersession_audit_action")
                .unwrap(),
            "WORKFLOW_JOB_EXHAUSTION_SUPERSEDED_BY_CANCELLATION"
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("supersession_audit_before_digest")
                .unwrap(),
            exhausted_escalation_digest
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("supersession_audit_after_digest")
                .unwrap(),
            escalation_after_digest
        );
        let supersession_audit_details = supersession
            .try_get::<Value, _>("supersession_audit_details")
            .unwrap();
        assert_eq!(
            supersession_audit_details["receipt_id"],
            json!(supersession_receipt_id)
        );
        assert_eq!(
            supersession_audit_details["dead_workflow_job_ids"],
            json!([observation_job_id])
        );
        assert_eq!(
            supersession
                .try_get::<String, _>("supersession_event_type")
                .unwrap(),
            "workflow_job_exhaustion.superseded_by_cancellation"
        );
        let supersession_outbox_payload = supersession
            .try_get::<Value, _>("supersession_outbox_payload")
            .unwrap();
        assert_eq!(
            supersession_outbox_payload["receipt_id"],
            json!(supersession_receipt_id)
        );
        assert_eq!(
            supersession_outbox_payload["replacement_job_id"],
            json!(replacement_job_id)
        );
        let audit_occurred_at = supersession
            .try_get::<chrono::DateTime<Utc>, _>("supersession_audit_occurred_at")
            .unwrap();
        let outbox_created_at = supersession
            .try_get::<chrono::DateTime<Utc>, _>("supersession_outbox_created_at")
            .unwrap();
        assert!(superseded_at <= audit_occurred_at);
        assert!(audit_occurred_at <= outbox_created_at);
        assert!(outbox_created_at <= recorded_at);
        assert!(is_sha256_digest(
            &supersession.try_get::<String, _>("receipt_digest").unwrap()
        ));
        assert!(
            supersession
                .try_get::<bool, _>("exact_fresh_receipt")
                .unwrap()
        );

        let replacement = sqlx::query(
            r"
            SELECT id, status, payload
            FROM workflow_jobs
            WHERE tenant_id = $1
              AND workflow_instance_id = $2
              AND job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND status = 'PENDING'
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load API-style replacement cancellation job");
        let replacement_job_id = replacement.try_get::<Uuid, _>("id").unwrap();
        let replacement_payload = replacement.try_get::<Value, _>("payload").unwrap();
        assert_eq!(
            replacement.try_get::<String, _>("status").unwrap(),
            "PENDING"
        );
        assert_eq!(replacement_payload["worker_id"], json!(fixture.worker_id));
        assert_eq!(
            replacement_payload["expected_version"],
            json!(escalated_version + 1)
        );
        assert!(replacement_payload.get("observe_only").is_none());

        let recovery_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            recovery_registry,
            ReactorOptions {
                lease_owner: "reactor:replacement-cancellation-observer".into(),
                poll_interval: StdDuration::from_millis(10),
                lease_duration: StdDuration::from_secs(5),
                max_error_backoff: StdDuration::from_secs(1),
                claim_batch_size: 4,
            },
            false,
        )
        .expect("construct replacement cancellation observer reactor");
        assert_eq!(
            recovery_reactor
                .poll_once()
                .await
                .expect("recover terminal cancellation from ordinary replacement job"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(
            control.cancellation_calls(),
            1,
            "ordinary replacement must adopt observation mode for an immutable OBSERVED effect"
        );
        let recovered = sqlx::query(
            r"
            SELECT
                replacement.status AS replacement_status,
                work.state AS work_state,
                workflow.state AS workflow_state,
                run.state AS run_state,
                anchor.anchor_type,
                anchor.reference_id,
                effect.status AS effect_status,
                effect.observed_outcome
            FROM workflow_jobs AS replacement
            JOIN work_items AS work
              ON work.tenant_id = replacement.tenant_id
             AND work.id = replacement.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = replacement.tenant_id
             AND workflow.id = replacement.workflow_instance_id
            JOIN runs AS run
              ON run.tenant_id = replacement.tenant_id AND run.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = replacement.tenant_id
             AND anchor.work_item_id = replacement.work_item_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = replacement.tenant_id
             AND effect.work_item_id = replacement.work_item_id
             AND effect.attempt_id = replacement.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
            WHERE replacement.tenant_id = $1 AND replacement.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(replacement_job_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load recovered cancellation terminal state");
        assert_eq!(
            recovered
                .try_get::<String, _>("replacement_status")
                .unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            recovered.try_get::<String, _>("work_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            recovered.try_get::<String, _>("workflow_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            recovered.try_get::<String, _>("run_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            recovered.try_get::<String, _>("anchor_type").unwrap(),
            "CANCELLATION"
        );
        let replacement_terminal_receipt_id =
            stable_cancellation_terminal_receipt_id(replacement_job_id);
        assert_eq!(
            recovered.try_get::<Uuid, _>("reference_id").unwrap(),
            replacement_terminal_receipt_id
        );
        assert_eq!(
            recovered.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        assert_eq!(
            recovered.try_get::<Value, _>("observed_outcome").unwrap(),
            effect_before
        );
        let recovered_provenance = sqlx::query(
            r"
            SELECT
                terminal.id AS terminal_receipt_id,
                terminal.terminal_observation_id,
                observation.prior_observation_id,
                observation.workflow_job_fence_token,
                observation.workflow_job_attempt_count,
                observation.workflow_job_owner,
                observation.route AS observation_route,
                terminal.outcome
            FROM cancellation_terminal_receipts AS terminal
            JOIN runmill_cancellation_observations AS observation
              ON observation.tenant_id = terminal.tenant_id
             AND observation.id = terminal.terminal_observation_id
            WHERE terminal.tenant_id = $1 AND terminal.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(replacement_terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load replacement cancellation terminal provenance");
        let total_observations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_cancellation_observations WHERE tenant_id = $1 AND effect_intent_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(stable_cancellation_effect_id(fixture.run_id))
        .fetch_one(database.ledger.pool())
        .await
        .expect("count recovered cancellation observation chain");
        assert_eq!(total_observations, 4);
        let replacement_terminal_observation_id =
            stable_cancellation_observation_id(replacement_job_id, 1);
        assert_eq!(
            recovered_provenance
                .try_get::<Uuid, _>("terminal_receipt_id")
                .unwrap(),
            replacement_terminal_receipt_id
        );
        assert_eq!(
            recovered_provenance
                .try_get::<Uuid, _>("terminal_observation_id")
                .unwrap(),
            replacement_terminal_observation_id
        );
        assert_eq!(
            recovered_provenance
                .try_get::<Option<Uuid>, _>("prior_observation_id")
                .unwrap(),
            Some(stable_cancellation_observation_id(observation_job_id, 2))
        );
        assert_eq!(
            recovered_provenance
                .try_get::<String, _>("observation_route")
                .unwrap(),
            "OBSERVER"
        );
        assert_eq!(
            recovered_provenance
                .try_get::<i64, _>("workflow_job_fence_token")
                .unwrap(),
            1
        );
        assert_eq!(
            recovered_provenance
                .try_get::<i32, _>("workflow_job_attempt_count")
                .unwrap(),
            1
        );
        assert_eq!(
            recovered_provenance
                .try_get::<String, _>("workflow_job_owner")
                .unwrap(),
            "reactor:replacement-cancellation-observer"
        );
        assert_eq!(
            recovered_provenance
                .try_get::<String, _>("outcome")
                .unwrap(),
            "CANCELLED"
        );
        let historical_supersession_is_exact: bool = sqlx::query_scalar(
            "SELECT asf_valid_cancellation_escalation_supersession_receipt($1, $2, false)",
        )
        .bind(fixture.tenant_id)
        .bind(supersession_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("revalidate historical escalation supersession receipt");
        assert!(historical_supersession_is_exact);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn exact_effect_job_owner_blocks_same_reactor_same_fence_replacement() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
            ],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        let payload = CancellationJobPayload::parse(&fixture.job).unwrap();
        handler
            .prepare_cancellation_effect(&fixture.job, &payload)
            .await
            .expect("commit cancellation preflight as if its response were lost");

        // The effect lease is only the preflight snapshot.  Let it expire,
        // then model the reactor heartbeat renewing the owning workflow job.
        // A separately claimed replacement must honor that live owner/fence
        // instead of treating the stale effect timestamp as authority.
        sqlx::query(
            r"
            UPDATE effect_intents
            SET lease_expires_at = clock_timestamp() - interval '1 second'
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .execute(database.ledger.pool())
        .await
        .expect("expire only the effect lifecycle snapshot");
        let renewed_until = database
            .ledger
            .renew_job_lease(
                fixture.tenant_id,
                fixture.job.id,
                &fixture.job.lease_owner,
                fixture.job.fence_token,
                StdDuration::from_mins(30),
            )
            .await
            .expect("heartbeat-renew original cancellation job");
        assert!(renewed_until > Utc::now() + Duration::minutes(20));

        let replacement_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, payload, idempotency_key, max_attempts
            ) VALUES (
                $1, $2, $3, $4, $5, 'REQUEST_WORK_ITEM_CANCELLATION',
                $8, $6, $7, 5
            )
            ",
        )
        .bind(replacement_id)
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&fixture.job.payload)
        .bind(format!("cancel-overlap-replacement:{replacement_id}"))
        .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
        .execute(database.ledger.pool())
        .await
        .expect("enqueue overlapping cancellation replacement");
        let mut replacements = database
            .ledger
            .claim_jobs(
                fixture.tenant_id,
                &fixture.job.lease_owner,
                1,
                StdDuration::from_mins(5),
            )
            .await
            .expect("claim overlapping cancellation replacement");
        assert_eq!(replacements.len(), 1);
        let replacement_job = replacements.remove(0);
        assert_eq!(replacement_job.id, replacement_id);
        assert_eq!(replacement_job.lease_owner, fixture.job.lease_owner);
        assert_eq!(replacement_job.fence_token, fixture.job.fence_token);

        assert!(
            handler
                .execute(&replacement_job, ActivityControls::new(false))
                .await
                .is_err(),
            "the heartbeat-renewed original owner must protect its in-flight effect"
        );
        assert_eq!(control.cancellation_calls(), 0);
        let protected: (String, i32, chrono::DateTime<Utc>, Uuid) = sqlx::query_as(
            r"
            SELECT status, attempt_count, lease_expires_at, owning_workflow_job_id
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load live-owner-protected effect");
        assert_eq!(protected.0, "IN_FLIGHT");
        assert_eq!(protected.1, 1);
        assert!(protected.2 <= Utc::now());
        assert_eq!(protected.3, fixture.job.id);

        // The timestamp is not the ownership oracle in the other direction,
        // either.  Make the snapshot long-lived while the exact owner is still
        // valid, then retire that owner below.
        sqlx::query(
            r"
            UPDATE effect_intents
            SET lease_expires_at = clock_timestamp() + interval '1 hour'
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .execute(database.ledger.pool())
        .await
        .expect("extend the live owner's effect lifecycle snapshot");

        // Retirement is now reciprocally fenced by the effect's exact claim.
        // Recovery must first make the uncertain provider outcome explicit and
        // release the old claim; a job transition can never silently orphan an
        // IN_FLIGHT mutation.
        sqlx::query(
            r"
            UPDATE effect_intents
            SET status = 'AMBIGUOUS', owning_workflow_job_id = NULL,
                lease_owner = NULL, lease_expires_at = NULL,
                last_error = 'preflight commit acknowledgement was lost',
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
              AND status = 'IN_FLIGHT'
              AND owning_workflow_job_id = $4
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.job.id)
        .execute(database.ledger.pool())
        .await
        .expect("release the old claim into explicit ambiguity");

        let failed = database
            .ledger
            .fail_job(
                fixture.tenant_id,
                fixture.job.id,
                &fixture.job.lease_owner,
                fixture.job.fence_token,
                "preflight commit acknowledgement was lost",
                Utc::now(),
            )
            .await
            .expect("move the old owner out of RUNNING");
        assert_eq!(
            failed.disposition,
            crate::ledger::FailureDisposition::RetryScheduled
        );

        // Once the exact old claim was explicitly released and its job is no
        // longer live, the already-claimed replacement can adopt the request.
        assert_eq!(
            handler
                .execute(&replacement_job, ActivityControls::new(true))
                .await
                .expect("replacement adopts after original owner loses its fence"),
            ActivityOutcome::TransactionCommitted
        );
        assert_eq!(control.cancellation_calls(), 1);
        let adopted: (String, i32, String, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT effect.status, effect.attempt_count, job.status,
                   effect.owning_workflow_job_id
            FROM effect_intents AS effect
            JOIN workflow_jobs AS job
              ON job.tenant_id = effect.tenant_id
             AND job.work_item_id = effect.work_item_id
             AND job.attempt_id = effect.attempt_id
             AND job.id = $4
            WHERE effect.tenant_id = $1
              AND effect.work_item_id = $2
              AND effect.attempt_id = $3
              AND effect.provider = 'runmill'
              AND effect.effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(replacement_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immediately adopted cancellation");
        assert_eq!(adopted, ("OBSERVED".into(), 2, "COMPLETED".into(), None));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn owner_migration_never_guesses_between_same_owner_same_fence_jobs() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        // This test exercises the genuine 0004 -> 0005 historical migration,
        // so the fixture and its sibling job are built against a schema that
        // stops at migration 0004 -- before migration 0023 ever introduces
        // `workflow_jobs.activity_contract_id`. Both INSERTs below therefore
        // omit that column entirely rather than supply it.
        let database = ScopedDatabase::create_through_0004(&database_url).await;
        let fixture = LiveFixture::insert_legacy_pre_activity_contract(&database.ledger).await;
        let sibling_job_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, status, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'REQUEST_WORK_ITEM_CANCELLATION',
                'RUNNING', $6, $7, 1, 5, $8, $9, $10
            )
            ",
        )
        .bind(sibling_job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&fixture.job.payload)
        .bind(format!("legacy-cancellation-sibling:{sibling_job_id}"))
        .bind(fixture.job.fence_token)
        .bind(&fixture.job.lease_owner)
        .bind(fixture.job.lease_expires_at)
        .execute(database.ledger.pool())
        .await
        .expect("insert colliding legacy cancellation job");

        let request = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: stable_cancellation_request_id(
                fixture.tenant_id,
                fixture.work_item_id,
                fixture.attempt_id,
                fixture.run_id,
            ),
            run_id: fixture.external_run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "asf:test-controller".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        request.validate().unwrap();
        let request_digest = request.digest().unwrap();
        let request_payload = serde_json::to_value(&request).unwrap();
        let effect_id = stable_cancellation_effect_id(fixture.run_id);
        sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, correlation_marker, request_digest,
                request_payload, attempt_count, fence_token, lease_owner,
                lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'request_cancellation',
                'IN_FLIGHT', $5, $6, $7, $8, 1, $9, $10, $11
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("runmill-cancellation:{}", request.request_id))
        .bind(&request.request_id)
        .bind(&request_digest)
        .bind(&request_payload)
        .bind(fixture.job.fence_token)
        .bind(&fixture.job.lease_owner)
        .bind(fixture.job.lease_expires_at)
        .execute(database.ledger.pool())
        .await
        .expect("insert legacy owner-ambiguous cancellation effect");

        let mut migration = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin exact effect-owner migration");
        sqlx::raw_sql(include_str!(
            "../../migrations/0005_effect_intent_exact_job_ownership.sql"
        ))
        .execute(&mut *migration)
        .await
        .expect("apply exact effect-owner migration");
        migration
            .commit()
            .await
            .expect("commit exact effect-owner migration");

        let migrated = sqlx::query(
            r"
            SELECT status, owning_workflow_job_id, lease_owner,
                   lease_expires_at, request_digest, request_payload
            FROM effect_intents
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(effect_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load conservatively migrated cancellation effect");
        assert_eq!(
            migrated.try_get::<String, _>("status").unwrap(),
            "AMBIGUOUS"
        );
        assert!(
            migrated
                .try_get::<Option<Uuid>, _>("owning_workflow_job_id")
                .unwrap()
                .is_none(),
            "migration must not guess an owner ID"
        );
        assert!(
            migrated
                .try_get::<Option<String>, _>("lease_owner")
                .unwrap()
                .is_none()
        );
        assert!(
            migrated
                .try_get::<Option<chrono::DateTime<Utc>>, _>("lease_expires_at")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            migrated.try_get::<String, _>("request_digest").unwrap(),
            request_digest
        );
        assert_eq!(
            migrated.try_get::<Value, _>("request_payload").unwrap(),
            request_payload
        );

        let live_jobs: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM workflow_jobs
            WHERE tenant_id = $1
              AND id IN ($2, $3)
              AND status = 'RUNNING'
              AND lease_expires_at > clock_timestamp()
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(sibling_job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count conservatively retained legacy jobs");
        assert_eq!(live_jobs, 2);

        sqlx::query(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() - interval '1 second'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .execute(database.ledger.pool())
        .await
        .expect("expire only the original job while its live sibling preserves accountability");
        let poison = sqlx::query(
            r"
            UPDATE effect_intents
            SET status = 'IN_FLIGHT',
                owning_workflow_job_id = $3,
                fence_token = $4,
                lease_owner = $5,
                lease_expires_at = clock_timestamp() + interval '5 minutes'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(effect_id)
        .bind(fixture.job.id)
        .bind(fixture.job.fence_token)
        .bind(&fixture.job.lease_owner)
        .execute(database.ledger.pool())
        .await
        .expect_err("live sibling with equal owner/fence must not validate the wrong exact job");
        assert_eq!(
            poison
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("effect_intents_exact_cancellation_owner")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn cancellation_binding_waits_on_job_before_locking_any_aggregate() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let payload = CancellationJobPayload::parse(&fixture.job).unwrap();

        let mut job_owner = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin workflow-job lock owner");
        sqlx::query("SELECT 1 FROM workflow_jobs WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
            .bind(fixture.tenant_id)
            .bind(fixture.job.id)
            .execute(&mut *job_owner)
            .await
            .expect("hold exact cancellation workflow-job lock");

        let (pid_sender, pid_receiver) = oneshot::channel();
        let waiter_ledger = database.ledger.clone();
        let waiter_job = fixture.job.clone();
        let waiter = tokio::spawn(async move {
            let mut transaction = waiter_ledger
                .pool()
                .begin()
                .await
                .expect("begin cancellation lock waiter");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await
                .expect("load cancellation waiter backend PID");
            let _ = pid_sender.send(backend_pid);
            let result =
                lock_cancellation_claim_and_binding(&mut transaction, &waiter_job, &payload)
                    .await
                    .map(|_| ());
            transaction
                .rollback()
                .await
                .expect("roll back cancellation lock waiter");
            result
        });
        let waiter_pid = pid_receiver
            .await
            .expect("receive cancellation waiter backend PID");
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let wait_event_type: Option<String> = sqlx::query_scalar(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1",
                )
                .bind(waiter_pid)
                .fetch_one(database.ledger.pool())
                .await
                .expect("inspect cancellation waiter state");
                if wait_event_type.as_deref() == Some("Lock") {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancellation binding must wait on its workflow job first");

        let mut aggregate_probe = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation aggregate probe");
        sqlx::query("SELECT 1 FROM work_items WHERE tenant_id = $1 AND id = $2 FOR UPDATE NOWAIT")
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .execute(&mut *aggregate_probe)
            .await
            .expect("job-blocked cancellation waiter must not already own the work-item lock");
        aggregate_probe
            .rollback()
            .await
            .expect("release cancellation aggregate probe");
        job_owner
            .rollback()
            .await
            .expect("release cancellation workflow-job lock");

        tokio::time::timeout(StdDuration::from_secs(5), waiter)
            .await
            .expect("cancellation waiter must finish without a deadlock")
            .expect("join cancellation lock waiter")
            .expect("cancellation waiter must lock the exact binding");
        database.cleanup().await;
    }

    #[tokio::test]
    async fn prelocked_finalization_wins_if_lease_expires_while_waiting_on_aggregate() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::CancelRequested],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        let payload = CancellationJobPayload::parse(&fixture.job).unwrap();
        let (initial_binding, request, request_digest, effect_id) = handler
            .prepare_cancellation_effect(&fixture.job, &payload)
            .await
            .expect("prepare exact cancellation effect");
        let result = control
            .request_cancel(&request)
            .await
            .expect("perform one idempotent cancellation mutation");
        let observed = control.snapshot(RunmillRunPhase::CancelRequested);
        assert_eq!(control.cancellation_calls(), 1);

        let lease_deadline: chrono::DateTime<Utc> = sqlx::query_scalar(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() + interval '3 seconds'
            WHERE tenant_id = $1
              AND id = $2
              AND status = 'RUNNING'
              AND lease_owner = $3
              AND fence_token = $4
            RETURNING lease_expires_at
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(&fixture.job.lease_owner)
        .bind(fixture.job.fence_token)
        .fetch_one(database.ledger.pool())
        .await
        .expect("shorten cancellation lease for deterministic expiry");

        let mut aggregate_owner = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin finalization aggregate blocker");
        sqlx::query("SELECT 1 FROM work_items WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .execute(&mut *aggregate_owner)
            .await
            .expect("hold work item ahead of cancellation finalization");

        let (final_pid_sender, final_pid_receiver) = oneshot::channel();
        let final_ledger = database.ledger.clone();
        let final_job = fixture.job.clone();
        let finalizer = tokio::spawn(async move {
            let mut transaction = final_ledger
                .pool()
                .begin()
                .await
                .expect("begin blocked cancellation finalization");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await
                .expect("load finalizer backend PID");
            let _ = final_pid_sender.send(backend_pid);
            let final_binding =
                lock_cancellation_claim_and_binding(&mut transaction, &final_job, &payload).await?;
            if !initial_binding.same_authoritative_coordinates(&final_binding) {
                return Err(Error::Conflict(
                    "authoritative coordinates changed in expiry regression".into(),
                ));
            }
            persist_cancellation(
                &mut transaction,
                &final_job,
                &payload,
                &final_binding,
                &request,
                &result,
                &observed,
                &request_digest,
                effect_id,
                CancellationEffectCommit::ObserveInFlight,
                None,
            )
            .await?;
            transaction.commit().await.map_err(|error| {
                Error::Persistence(format!("commit blocked cancellation finalization: {error}"))
            })
        });
        let finalizer_pid = final_pid_receiver
            .await
            .expect("receive cancellation finalizer backend PID");
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let wait_event_type: Option<String> = sqlx::query_scalar(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1",
                )
                .bind(finalizer_pid)
                .fetch_one(database.ledger.pool())
                .await
                .expect("inspect blocked cancellation finalizer");
                if wait_event_type.as_deref() == Some("Lock") {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("finalizer must own the job before waiting on the work item");

        tokio::time::timeout(StdDuration::from_secs(6), async {
            loop {
                let expired: bool = sqlx::query_scalar("SELECT clock_timestamp() >= $1")
                    .bind(lease_deadline)
                    .fetch_one(database.ledger.pool())
                    .await
                    .expect("compare cancellation lease with database clock");
                if expired {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(20)).await;
            }
        })
        .await
        .expect("cancellation job lease must expire while its row lock is owned");

        let (reaper_pid_sender, reaper_pid_receiver) = oneshot::channel();
        let reaper_ledger = database.ledger.clone();
        let reaper_job = fixture.job.clone();
        let reaper = tokio::spawn(async move {
            let mut transaction = reaper_ledger
                .pool()
                .begin()
                .await
                .expect("begin competing cancellation recovery");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await
                .expect("load recovery backend PID");
            let _ = reaper_pid_sender.send(backend_pid);
            let affected = sqlx::query(
                r"
                UPDATE workflow_jobs
                SET status = 'RETRY',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1
                  AND id = $2
                  AND status = 'RUNNING'
                  AND lease_owner = $3
                  AND fence_token = $4
                  AND lease_expires_at <= clock_timestamp()
                ",
            )
            .bind(reaper_job.tenant_id)
            .bind(reaper_job.id)
            .bind(&reaper_job.lease_owner)
            .bind(reaper_job.fence_token)
            .execute(&mut *transaction)
            .await
            .expect("run competing cancellation recovery")
            .rows_affected();
            transaction
                .commit()
                .await
                .expect("commit competing cancellation recovery");
            affected
        });
        let reaper_pid = reaper_pid_receiver
            .await
            .expect("receive cancellation recovery backend PID");
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let wait_event_type: Option<String> = sqlx::query_scalar(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1",
                )
                .bind(reaper_pid)
                .fetch_one(database.ledger.pool())
                .await
                .expect("inspect blocked cancellation recovery");
                if wait_event_type.as_deref() == Some("Lock") {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("expired-lease recovery must wait behind finalizer's job lock");

        aggregate_owner
            .rollback()
            .await
            .expect("release cancellation finalization aggregate");
        tokio::time::timeout(StdDuration::from_secs(5), finalizer)
            .await
            .expect("prelocked finalizer must finish")
            .expect("join prelocked finalizer")
            .expect("prelocked finalizer must commit after lease expiry");
        let recovered = tokio::time::timeout(StdDuration::from_secs(5), reaper)
            .await
            .expect("competing recovery must finish")
            .expect("join competing recovery");
        assert_eq!(
            recovered, 0,
            "recovery must lose after finalization commits"
        );

        let durable: (String, String, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT job.status, effect.status, effect.owning_workflow_job_id
            FROM workflow_jobs AS job
            JOIN effect_intents AS effect
              ON effect.tenant_id = job.tenant_id
             AND effect.work_item_id = job.work_item_id
             AND effect.attempt_id = job.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load post-expiry cancellation receipt");
        assert_eq!(durable, ("COMPLETED".into(), "OBSERVED".into(), None));
        assert_eq!(control.cancellation_calls(), 1);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_dead_letter_replacement_adopts_the_one_ambiguous_run_request() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert_with_max_attempts(&database.ledger, 1).await;
        let final_attempt_job = fixture.job.clone();

        let control = fixture.control_with_ambiguous_calls(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
                RunmillRunPhase::CancelRequested,
                RunmillRunPhase::CancelRequested,
            ],
            RunmillRunPhase::CancelRequested,
            2,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        assert!(
            handler
                .execute(&final_attempt_job, ActivityControls::new(false))
                .await
                .is_err(),
            "two ambiguous mutation responses must remain unresolved"
        );
        assert_eq!(control.cancellation_calls(), 2);
        let first_effect_status: String = sqlx::query_scalar(
            r"
            SELECT status
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load ambiguous cancellation effect");
        assert_eq!(first_effect_status, "AMBIGUOUS");

        let initial_requests = control.cancellation_requests();
        assert_eq!(initial_requests.len(), 2);
        assert_eq!(initial_requests[0], initial_requests[1]);
        let original_request = initial_requests[0].clone();
        let original_payload = serde_json::to_value(&original_request).unwrap();
        let original_digest = original_request.digest().unwrap();
        let mut coherent_tamper = original_request.clone();
        coherent_tamper.requester.subject = "asf:replacement-controller".into();
        coherent_tamper.reason = "Rewrite the logically ambiguous cancellation".into();
        coherent_tamper.mode = RunmillCancellationMode::Forced;
        coherent_tamper.grace_seconds = 0;
        let coherent_tamper_payload = serde_json::to_value(&coherent_tamper).unwrap();
        let coherent_tamper_digest = coherent_tamper.digest().unwrap();
        assert_ne!(coherent_tamper_digest, original_digest);
        let tamper_error = sqlx::query(
            r"
            UPDATE effect_intents
            SET request_payload = $4,
                request_digest = $5
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&coherent_tamper_payload)
        .bind(&coherent_tamper_digest)
        .execute(database.ledger.pool())
        .await
        .expect_err("database must freeze the exact effect request and digest");
        assert_eq!(
            tamper_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("effect_intents_identity_request_immutable")
        );
        let frozen_request: (Value, String) = sqlx::query_as(
            r"
            SELECT request_payload, request_digest
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load frozen cancellation request");
        assert_eq!(frozen_request, (original_payload, original_digest));
        let delete_error = sqlx::query(
            r"
            DELETE FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .execute(database.ledger.pool())
        .await
        .expect_err("database must reject delete-and-recreate of an effect request");
        assert_eq!(
            delete_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("effect_intents_identity_request_immutable")
        );

        let opened_at = Utc::now();
        let escalation_id = Uuid::now_v7();
        let dead_letter_correlation = format!("workflow-job-exhausted:{}", fixture.job.id);
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation dead letter");
        let failure = WorkflowStepFailure {
            fence: WorkflowStepFence {
                tenant_id: fixture.tenant_id,
                job_id: fixture.job.id,
                workflow_instance_id: fixture
                    .job
                    .workflow_instance_id
                    .expect("fixture workflow ID"),
                work_item_id: fixture.work_item_id,
                lease_owner: fixture.job.lease_owner.clone(),
                job_fence_token: fixture.job.fence_token,
                expected_work_item_version: 1,
                expected_workflow_version: 1,
                expected_workflow_fence_token: 0,
                expected_anchor_generation: 1,
            },
            error_summary: "Runmill cancellation response remained ambiguous".into(),
            retry_at: opened_at + Duration::minutes(1),
            dead_letter: DeadLetterEscalation {
                id: escalation_id,
                run_id: Some(fixture.run_id),
                category: "WORKFLOW_JOB_EXHAUSTED".into(),
                severity: "HIGH".into(),
                reason: "Runmill cancellation exhausted its final workflow-job attempt".into(),
                owner_type: "ON_CALL".into(),
                owner_id: "platform-operations".into(),
                required_action:
                    "reconcile the exact Runmill cancellation effect, then explicitly retry".into(),
                evidence_references: json!([
                    format!("workflow-job:{}", fixture.job.id),
                    format!("run:{}", fixture.run_id),
                ]),
                deadline: opened_at + Duration::hours(4),
                escalation_path: json!([
                    {"owner_type": "ON_CALL", "owner_id": "platform-operations"},
                    {"owner_type": "TEAM", "owner_id": "platform-engineering"},
                ]),
                retry_policy: json!({
                    "automatic": false,
                    "max_additional_attempts": 0,
                    "backoff_seconds": 0,
                    "prerequisites": ["remote effect reconciled", "operator decision recorded"],
                }),
                prerequisites: json!([
                    "inspect failure evidence",
                    "reconcile ambiguous remote effect",
                ]),
                authority_or_effect_active: true,
                idempotency_key: dead_letter_correlation.clone(),
                opened_at,
                audit_event: StepAuditEvent {
                    id: Uuid::now_v7(),
                    attempt_id: Some(fixture.attempt_id),
                    actor_type: "SERVICE".into(),
                    actor_id: fixture.job.lease_owner.clone(),
                    action: "WORKFLOW_JOB_EXHAUSTED".into(),
                    subject_type: "WORKFLOW_JOB".into(),
                    subject_id: fixture.job.id.to_string(),
                    correlation_id: dead_letter_correlation.clone(),
                    trace_id: None,
                    policy_digest: Some(fixture.policy_digest.clone()),
                    before_digest: None,
                    after_digest: None,
                    details: json!({
                        "job_type": REQUEST_WORK_ITEM_CANCELLATION,
                        "ambiguous_effect": true,
                    }),
                    occurred_at: opened_at,
                },
                outbox_message: StepOutboxMessage {
                    id: Uuid::now_v7(),
                    topic: "attention".into(),
                    message_key: fixture.work_item_id.to_string(),
                    event_type: "workflow_job.exhausted".into(),
                    payload: json!({
                        "work_item_id": fixture.work_item_id,
                        "workflow_job_id": fixture.job.id,
                        "escalation_id": escalation_id,
                    }),
                    headers: json!({"schema": "asf.attention-event/v1"}),
                    idempotency_key: format!("{dead_letter_correlation}:outbox"),
                    available_at: opened_at,
                },
            },
        };
        let dead_letter = fail_workflow_step(&mut transaction, &failure)
            .await
            .expect("dead-letter unresolved cancellation with owned escalation");
        assert_eq!(
            dead_letter.disposition,
            WorkflowStepFailureDisposition::Escalated
        );
        transaction
            .commit()
            .await
            .expect("commit cancellation dead letter");

        let mut api_registry = HandlerRegistry::new();
        api_registry
            .register(Arc::new(handler.clone()))
            .expect("register exact cancellation activity for API route");
        let backend = PostgresApiBackend::from_ledger(
            &database.ledger,
            TenantId::from_uuid(fixture.tenant_id),
        )
        .with_activity_capabilities(api_registry.api_activity_capabilities());
        let caller = Caller {
            subject: "operator:bob".into(),
            roles: BTreeSet::from([Role::Operator]),
        };
        let receipt = backend
            .cancel_work_item(
                TenantId::from_uuid(fixture.tenant_id),
                WorkItemId::from_uuid(fixture.work_item_id),
                &CancellationRequest {
                    expected_version: 2,
                    reason: "Replacement request after dead-letter review".into(),
                },
                &caller,
                "replacement-cancellation-request",
            )
            .await
            .expect("API-style replacement cancellation");
        assert_eq!(receipt.status, "cancellation_requested");
        assert_eq!(receipt.version, Some(3));

        let mut replacements = database
            .ledger
            .claim_jobs(
                fixture.tenant_id,
                "reactor:cancellation-replacement",
                10,
                StdDuration::from_mins(5),
            )
            .await
            .expect("claim replacement cancellation job");
        assert_eq!(replacements.len(), 1);
        let replacement_job = replacements.remove(0);
        assert_ne!(replacement_job.id, fixture.job.id);
        assert_eq!(replacement_job.job_type, REQUEST_WORK_ITEM_CANCELLATION);
        assert_eq!(
            replacement_job
                .payload
                .get("worker_id")
                .and_then(Value::as_str),
            Some(fixture.worker_id.to_string().as_str())
        );
        assert_eq!(
            handler
                .execute(&replacement_job, ActivityControls::new(true))
                .await
                .expect("replacement must adopt and reconcile the exact original request"),
            ActivityOutcome::TransactionCommitted
        );

        let requests = control.cancellation_requests();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| request == &requests[0]));
        assert_eq!(requests[0].reason, "Operator requested cancellation");
        assert_eq!(
            requests[0].request_id,
            stable_cancellation_request_id(
                fixture.tenant_id,
                fixture.work_item_id,
                fixture.attempt_id,
                fixture.run_id,
            )
        );

        let effect_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count logical cancellation effects");
        assert_eq!(effect_count, 1);
        let row = sqlx::query(
            r"
            SELECT
                effect.id AS effect_id,
                effect.status AS effect_status,
                effect.attempt_count AS effect_attempt_count,
                effect.request_digest,
                effect.request_payload,
                original_job.status AS original_job_status,
                replacement_job.status AS replacement_job_status,
                work.state AS work_state,
                attempt.state AS attempt_state,
                audit.details AS audit_details
            FROM effect_intents AS effect
            JOIN workflow_jobs AS original_job
              ON original_job.tenant_id = effect.tenant_id AND original_job.id = $4
            JOIN workflow_jobs AS replacement_job
              ON replacement_job.tenant_id = effect.tenant_id AND replacement_job.id = $5
            JOIN work_items AS work
              ON work.tenant_id = effect.tenant_id AND work.id = effect.work_item_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = effect.tenant_id AND attempt.id = effect.attempt_id
            JOIN audit_events AS audit
              ON audit.tenant_id = effect.tenant_id
             AND audit.work_item_id = effect.work_item_id
             AND audit.action = 'RUNMILL_CANCELLATION_ACCEPTED'
            WHERE effect.tenant_id = $1
              AND effect.work_item_id = $2
              AND effect.attempt_id = $3
              AND effect.provider = 'runmill'
              AND effect.effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.job.id)
        .bind(replacement_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load adopted cancellation result");
        assert_eq!(
            row.try_get::<Uuid, _>("effect_id").unwrap(),
            stable_cancellation_effect_id(fixture.run_id)
        );
        assert_eq!(
            row.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        assert_eq!(row.try_get::<i32, _>("effect_attempt_count").unwrap(), 2);
        assert_eq!(
            row.try_get::<Value, _>("request_payload").unwrap()["reason"],
            "Operator requested cancellation"
        );
        assert_eq!(
            row.try_get::<String, _>("request_digest").unwrap(),
            requests[0].digest().unwrap()
        );
        assert_eq!(
            row.try_get::<String, _>("original_job_status").unwrap(),
            "DEAD"
        );
        assert_eq!(
            row.try_get::<String, _>("replacement_job_status").unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            row.try_get::<String, _>("work_state").unwrap(),
            "CANCEL_REQUESTED"
        );
        assert_eq!(
            row.try_get::<String, _>("attempt_state").unwrap(),
            "CANCEL_REQUESTED"
        );
        let audit_details = row.try_get::<Value, _>("audit_details").unwrap();
        let original_reason_digest = sha256_digest(
            &canonical_json(&json!({"reason": "Operator requested cancellation"})).unwrap(),
        );
        let replacement_reason_digest = sha256_digest(
            &canonical_json(&json!({"reason": "Replacement request after dead-letter review"}))
                .unwrap(),
        );
        assert_eq!(
            audit_details["request_reason_digest"],
            original_reason_digest
        );
        assert_ne!(
            audit_details["request_reason_digest"],
            replacement_reason_digest
        );
        assert_eq!(
            audit_details["reconciliation_job_reason_digest"],
            replacement_reason_digest
        );
        assert_eq!(audit_details["reconciliation_requested_by"], "operator:bob");
        assert!(
            audit_details["persisted_request_adopted"]
                .as_bool()
                .unwrap()
        );
        let contradictory_insert = sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, correlation_marker, request_digest,
                request_payload
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'request_cancellation', 'FAILED',
                $5, $6, $7, '{}'::jsonb
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("contradictory-effect:{}", Uuid::now_v7()))
        .bind(format!("contradictory-request:{}", Uuid::now_v7()))
        .bind(digest('f'))
        .execute(database.ledger.pool())
        .await
        .expect_err("database must reject a second cancellation intent for one attempt");
        assert_eq!(
            contradictory_insert
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("effect_intents_one_runmill_cancellation_per_attempt_idx")
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_semantic_mismatch_never_reopens_ambiguous_or_observed_effect() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control_with_ambiguous_calls(
            vec![
                RunmillRunPhase::Implementing,
                RunmillRunPhase::CancelRequested,
            ],
            RunmillRunPhase::CancelRequested,
            2,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err()
        );
        assert_eq!(control.cancellation_calls(), 2);

        // Simulate a legacy/out-of-band row that predates the database guard,
        // then restore the trigger before asking the handler to inspect it.
        sqlx::query(
            "ALTER TABLE effect_intents DISABLE TRIGGER effect_intents_identity_request_immutable",
        )
        .execute(database.ledger.pool())
        .await
        .expect("temporarily disable effect request guard in isolated test schema");
        sqlx::query(
            r"
            UPDATE effect_intents
            SET request_payload = jsonb_set(
                    request_payload,
                    '{reason}',
                    to_jsonb($4::text),
                    false
                )
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind("Contradictory replacement request")
        .execute(database.ledger.pool())
        .await
        .expect("inject persisted semantic mismatch");
        sqlx::query(
            "ALTER TABLE effect_intents ENABLE TRIGGER effect_intents_identity_request_immutable",
        )
        .execute(database.ledger.pool())
        .await
        .expect("restore effect request guard in isolated test schema");

        assert!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .is_err(),
            "an ambiguous effect with a changed exact body must fail closed"
        );
        assert_eq!(control.cancellation_calls(), 2);
        let ambiguous = sqlx::query(
            r"
            SELECT status, attempt_count, request_payload
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load unchanged ambiguous mismatch");
        assert_eq!(
            ambiguous.try_get::<String, _>("status").unwrap(),
            "AMBIGUOUS"
        );
        assert_eq!(ambiguous.try_get::<i32, _>("attempt_count").unwrap(), 1);
        assert_eq!(
            ambiguous.try_get::<Value, _>("request_payload").unwrap()["reason"],
            "Contradictory replacement request"
        );

        sqlx::query(
            r"
            UPDATE effect_intents
            SET status = 'OBSERVED'
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .execute(database.ledger.pool())
        .await
        .expect_err("an effect cannot become OBSERVED without its exact INITIAL observation");
        assert_eq!(control.cancellation_calls(), 2);
        let observed: (String, i32) = sqlx::query_as(
            r"
            SELECT status, attempt_count
            FROM effect_intents
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND provider = 'runmill'
              AND effect_type = 'request_cancellation'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load unchanged ambiguous mismatch after rejected observation forgery");
        assert_eq!(observed, ("AMBIGUOUS".into(), 1));
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_already_cancelled_run_gets_terminal_audit_accountability_not_a_live_run_anchor() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Cancelled, RunmillRunPhase::Cancelled],
            RunmillRunPhase::Cancelled,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        let outcome = handler
            .execute(&fixture.job, ActivityControls::new(true))
            .await
            .expect("already-cancelled Runmill run must finalize locally");
        assert_eq!(outcome, ActivityOutcome::TransactionCommitted);
        assert_eq!(control.cancellation_calls(), 1);

        let row = sqlx::query(
            r"
            SELECT
                job.status AS job_status,
                job.result AS job_result,
                work.state AS work_state,
                workflow.state AS workflow_state,
                attempt.state AS attempt_state,
                attempt.aggregate_version AS attempt_version,
                attempt.terminal_at AS attempt_terminal_at,
                run.state AS run_state,
                run.terminal_at,
                anchor.anchor_type,
                anchor.reference_id,
                receipt.outcome AS receipt_outcome,
                receipt.terminal_observation_id,
                audit.action AS anchor_action,
                audit.details AS audit_details,
                outbox.id AS cancellation_outbox_id,
                outbox.payload AS outbox_payload,
                effect.status AS effect_status
            FROM workflow_jobs AS job
            JOIN work_items AS work
              ON work.tenant_id = job.tenant_id AND work.id = job.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = job.tenant_id AND workflow.id = job.workflow_instance_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = job.tenant_id AND attempt.id = job.attempt_id
            JOIN runs AS run
              ON run.tenant_id = job.tenant_id AND run.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = job.tenant_id AND anchor.work_item_id = job.work_item_id
            JOIN cancellation_terminal_receipts AS receipt
              ON receipt.tenant_id = anchor.tenant_id
             AND receipt.id = anchor.reference_id
            JOIN audit_events AS audit
              ON audit.tenant_id = receipt.tenant_id
             AND audit.id = receipt.audit_event_id
            JOIN outbox
              ON outbox.tenant_id = receipt.tenant_id
             AND outbox.id = receipt.outbox_event_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = job.tenant_id
             AND effect.work_item_id = job.work_item_id
             AND effect.effect_type = 'request_cancellation'
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal cancellation");
        assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "COMPLETED");
        assert_eq!(row.try_get::<String, _>("work_state").unwrap(), "CANCELLED");
        assert_eq!(
            row.try_get::<String, _>("workflow_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            row.try_get::<String, _>("attempt_state").unwrap(),
            "CANCELLED"
        );
        assert_eq!(row.try_get::<i64, _>("attempt_version").unwrap(), 2);
        assert!(
            row.try_get::<Option<chrono::DateTime<Utc>>, _>("attempt_terminal_at")
                .unwrap()
                .is_some()
        );
        assert_eq!(row.try_get::<String, _>("run_state").unwrap(), "CANCELLED");
        assert!(
            row.try_get::<Option<chrono::DateTime<Utc>>, _>("terminal_at")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            row.try_get::<String, _>("anchor_type").unwrap(),
            "CANCELLATION"
        );
        assert_eq!(
            row.try_get::<String, _>("anchor_action").unwrap(),
            "WORK_ITEM_CANCELLED"
        );
        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        let cancellation_observation_id =
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token);
        assert_eq!(
            row.try_get::<Uuid, _>("reference_id").unwrap(),
            terminal_receipt_id
        );
        assert_eq!(
            row.try_get::<String, _>("receipt_outcome").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            row.try_get::<Uuid, _>("terminal_observation_id").unwrap(),
            cancellation_observation_id
        );
        assert_eq!(
            row.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        let result = row.try_get::<Value, _>("job_result").unwrap();
        let audit_details = row.try_get::<Value, _>("audit_details").unwrap();
        let outbox_payload = row.try_get::<Value, _>("outbox_payload").unwrap();
        for payload in [&result["result"], &audit_details, &outbox_payload] {
            assert_eq!(payload["released_reservations"], 1);
            assert_eq!(
                payload["cancellation_observation_id"],
                json!(cancellation_observation_id)
            );
            assert_eq!(payload["terminal_receipt_id"], json!(terminal_receipt_id));
        }
        let cancellation_outbox_id = row.try_get::<Uuid, _>("cancellation_outbox_id").unwrap();
        sqlx::query(
            r"
            UPDATE outbox
            SET available_at = GREATEST(available_at, clock_timestamp()) + interval '1 minute'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(cancellation_outbox_id)
        .execute(database.ledger.pool())
        .await
        .expect("publisher retry may move cancellation outbox availability forward");
        let receipt_remains_valid: bool =
            sqlx::query_scalar("SELECT asf_valid_cancellation_terminal_receipt($1, $2)")
                .bind(fixture.tenant_id)
                .bind(terminal_receipt_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("revalidate terminal receipt after publisher retry scheduling");
        assert!(receipt_remains_valid);
        sqlx::query(
            r"
            UPDATE attempts
            SET updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.attempt_id)
        .execute(database.ledger.pool())
        .await
        .expect("unrelated legal attempt lifecycle touch must preserve terminal receipt");
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_released(
            &fixture,
            reservation_set_id,
            fixture.job.lease_owner.as_str(),
            terminal_receipt_id,
            &reservation,
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_requested_cancellation_may_finish_before_followup_observation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Implementing, RunmillRunPhase::Cancelled],
            RunmillRunPhase::CancelRequested,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct immediate-terminal cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("REQUESTED acknowledgement may be followed by a terminal snapshot"),
            ActivityOutcome::TransactionCommitted
        );
        assert_eq!(control.cancellation_calls(), 1);

        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        let row = sqlx::query(
            r"
            SELECT
                observation.route,
                observation.disposition,
                observation.external_phase,
                effect.status AS effect_status,
                effect.observed_outcome AS effect_outcome,
                job.status AS job_status,
                work.state AS work_state,
                receipt.outcome AS receipt_outcome,
                asf_valid_cancellation_terminal_receipt(
                    receipt.tenant_id, receipt.id
                ) AS receipt_valid
            FROM runmill_cancellation_observations AS observation
            JOIN effect_intents AS effect
              ON effect.tenant_id = observation.tenant_id
             AND effect.id = observation.effect_intent_id
            JOIN workflow_jobs AS job
              ON job.tenant_id = observation.tenant_id
             AND job.id = observation.workflow_job_id
            JOIN work_items AS work
              ON work.tenant_id = observation.tenant_id
             AND work.id = observation.work_item_id
            JOIN cancellation_terminal_receipts AS receipt
              ON receipt.tenant_id = observation.tenant_id
             AND receipt.workflow_job_id = observation.workflow_job_id
             AND receipt.terminal_observation_id = observation.id
            WHERE observation.tenant_id = $1
              AND observation.workflow_job_id = $2
              AND receipt.id = $3
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immediate-terminal cancellation provenance");
        assert_eq!(row.try_get::<String, _>("route").unwrap(), "INITIAL");
        assert_eq!(
            row.try_get::<String, _>("disposition").unwrap(),
            "REQUESTED"
        );
        assert_eq!(
            row.try_get::<String, _>("external_phase").unwrap(),
            "CANCELLED"
        );
        assert_eq!(
            row.try_get::<String, _>("effect_status").unwrap(),
            "OBSERVED"
        );
        let effect_outcome = row.try_get::<Value, _>("effect_outcome").unwrap();
        assert_eq!(effect_outcome["disposition"], "requested");
        assert_eq!(effect_outcome["external_phase"], "CANCELLED");
        assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "COMPLETED");
        assert_eq!(row.try_get::<String, _>("work_state").unwrap(), "CANCELLED");
        assert_eq!(
            row.try_get::<String, _>("receipt_outcome").unwrap(),
            "CANCELLED"
        );
        assert!(row.try_get::<bool, _>("receipt_valid").unwrap());
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_cancelled_receipt_freezes_late_work_authority() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Cancelled, RunmillRunPhase::Cancelled],
            RunmillRunPhase::Cancelled,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct terminal cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("terminal cancellation must commit before the authority attack"),
            ActivityOutcome::TransactionCommitted
        );

        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        let guard_before: (i64, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT generation, terminal_receipt_id
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load frozen cancellation authority guard");
        assert_eq!(guard_before.1, Some(terminal_receipt_id));

        let late_job_id = Uuid::now_v7();
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin late-authority attack");
        let late_authority_result = sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5, 'TEST_LATE_WORK_AUTHORITY',
                'test.activity/test-late-work-authority/v1', 'PENDING',
                '{}'::jsonb, $6
            )
            ",
        )
        .bind(late_job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("test-late-work-authority:{late_job_id}"))
        .execute(&mut *transaction)
        .await;
        let late_authority_error = match late_authority_result {
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .expect("roll back rejected late-authority attack");
                error
            }
            Ok(_) => transaction
                .commit()
                .await
                .expect_err("late work authority must fail no later than commit"),
        };
        let database_error = late_authority_error
            .as_database_error()
            .expect("late-authority rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("cancellation_authority_facts_preserve_terminal_receipt")
        );

        let guard_after: (i64, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT generation, terminal_receipt_id
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("reload cancellation authority guard after rejected attack");
        assert_eq!(guard_after, guard_before);
        let late_job_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM workflow_jobs WHERE id = $1")
                .bind(late_job_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("count rejected late work-authority jobs");
        assert_eq!(late_job_count, 0);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_cancelled_receipt_rejects_fresh_terminal_children_immediately() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Cancelled, RunmillRunPhase::Cancelled],
            RunmillRunPhase::Cancelled,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct terminal-child finality handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("establish valid terminal cancellation before child insert attacks"),
            ActivityOutcome::TransactionCommitted
        );

        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        let guard_before: (i64, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT
                generation,
                terminal_receipt_id,
                source_closure_effect_intent_id
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal authority guard before terminal-child attacks");
        assert_eq!(guard_before.1, Some(terminal_receipt_id));
        assert!(guard_before.2.is_none());
        let receipt_before: (String, bool) = sqlx::query_as(
            r"
            SELECT
                receipt_digest,
                asf_valid_cancellation_terminal_receipt(tenant_id, id)
            FROM cancellation_terminal_receipts
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load exact terminal receipt before terminal-child attacks");
        assert!(receipt_before.1);

        let failed_attempt_id = Uuid::now_v7();
        let completed_workflow_id = Uuid::now_v7();
        let fired_timer_id = Uuid::now_v7();
        let failed_effect_id = Uuid::now_v7();
        let cancellation_workflow_id = fixture
            .job
            .workflow_instance_id
            .expect("fixture cancellation job has a workflow");
        let assert_shared_guard_rejection = |label: &str, error: &sqlx::Error| {
            let database_error = error
                .as_database_error()
                .unwrap_or_else(|| panic!("{label} rejection must be a PostgreSQL error"));
            assert_eq!(
                database_error.code().as_deref(),
                Some("23514"),
                "{label} must fail with an integrity violation"
            );
            assert_eq!(
                database_error.constraint(),
                Some("cancellation_authority_facts_preserve_terminal_receipt"),
                "{label} must fail at the shared cancellation-authority guard"
            );
        };

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin terminal-child finality attacks");

        sqlx::query("SAVEPOINT failed_attempt_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint failed-attempt attack");
        let failed_attempt_error = sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest,
                work_order_digest, fence_token, aggregate_version,
                created_at, started_at, terminal_at, updated_at
            )
            SELECT
                $1, existing.tenant_id, existing.work_item_id,
                existing.ordinal + 1, 'FAILED', $4,
                existing.base_ref, existing.base_sha,
                existing.source_snapshot_digest, existing.policy_digest,
                NULL, 0, 1,
                clock_timestamp() - interval '1 second',
                clock_timestamp() - interval '1 second',
                clock_timestamp(), clock_timestamp()
            FROM attempts AS existing
            WHERE existing.tenant_id = $2 AND existing.id = $3
            ",
        )
        .bind(failed_attempt_id)
        .bind(fixture.tenant_id)
        .bind(fixture.attempt_id)
        .bind(format!("late-terminal-attempt:{failed_attempt_id}"))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh FAILED attempt must be rejected by terminal cancellation");
        assert_shared_guard_rejection("fresh FAILED attempt", &failed_attempt_error);
        sqlx::query("ROLLBACK TO SAVEPOINT failed_attempt_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back failed-attempt attack");
        sqlx::query("RELEASE SAVEPOINT failed_attempt_attack")
            .execute(&mut *transaction)
            .await
            .expect("release failed-attempt attack savepoint");

        sqlx::query("SAVEPOINT completed_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint completed-workflow attack");
        let completed_workflow_error = sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state,
                reducer_version, created_at, updated_at, terminal_at
            ) VALUES (
                $1, $2, $3, $4, 'COMPLETED', 'asf.workflow/v1',
                clock_timestamp() - interval '1 second',
                clock_timestamp(), clock_timestamp()
            )
            ",
        )
        .bind(completed_workflow_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!(
            "TEST_TERMINAL_CHILD_{}",
            completed_workflow_id.simple()
        ))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh COMPLETED workflow must be rejected by terminal cancellation");
        assert_shared_guard_rejection("fresh COMPLETED workflow", &completed_workflow_error);
        sqlx::query("ROLLBACK TO SAVEPOINT completed_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back completed-workflow attack");
        sqlx::query("RELEASE SAVEPOINT completed_workflow_attack")
            .execute(&mut *transaction)
            .await
            .expect("release completed-workflow attack savepoint");

        sqlx::query("SAVEPOINT fired_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint fired-timer attack");
        let fired_timer_error = sqlx::query(
            r"
            INSERT INTO workflow_timers (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                workflow_key, timer_key, timer_type, activity_contract_id, status,
                due_at, payload, created_at, fired_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 'TEST_TERMINAL_CHILD',
                'test.activity/test-terminal-child/v1',
                'FIRED', clock_timestamp() - interval '1 second',
                '{}'::jsonb, clock_timestamp() - interval '1 second',
                clock_timestamp()
            )
            ",
        )
        .bind(fired_timer_id)
        .bind(fixture.tenant_id)
        .bind(cancellation_workflow_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("terminal-child-workflow:{fired_timer_id}"))
        .bind(format!("terminal-child-timer:{fired_timer_id}"))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh FIRED timer must be rejected by terminal cancellation");
        assert_shared_guard_rejection("fresh FIRED timer", &fired_timer_error);
        sqlx::query("ROLLBACK TO SAVEPOINT fired_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back fired-timer attack");
        sqlx::query("RELEASE SAVEPOINT fired_timer_attack")
            .execute(&mut *transaction)
            .await
            .expect("release fired-timer attack savepoint");

        sqlx::query("SAVEPOINT failed_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("savepoint failed-effect attack");
        let failed_effect_error = sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, request_digest, request_payload
            ) VALUES (
                $1, $2, $3, $4, 'test-provider', 'test-terminal-child',
                'FAILED', $5, $6, '{}'::jsonb
            )
            ",
        )
        .bind(failed_effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("late-terminal-effect:{failed_effect_id}"))
        .bind(digest('f'))
        .execute(&mut *transaction)
        .await
        .expect_err("fresh FAILED generic effect must be rejected by terminal cancellation");
        assert_shared_guard_rejection("fresh FAILED generic effect", &failed_effect_error);
        sqlx::query("ROLLBACK TO SAVEPOINT failed_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("roll back failed-effect attack");
        sqlx::query("RELEASE SAVEPOINT failed_effect_attack")
            .execute(&mut *transaction)
            .await
            .expect("release failed-effect attack savepoint");

        transaction
            .commit()
            .await
            .expect("commit transaction containing only rejected terminal-child attacks");

        let rejected_child_counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM attempts
                 WHERE tenant_id = $1 AND id = $3),
                (SELECT count(*) FROM workflow_instances
                 WHERE tenant_id = $1 AND id = $4),
                (SELECT count(*) FROM workflow_timers
                 WHERE tenant_id = $1 AND id = $5),
                (SELECT count(*) FROM effect_intents
                 WHERE tenant_id = $1 AND id = $6)
            FROM work_items
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(failed_attempt_id)
        .bind(completed_workflow_id)
        .bind(fired_timer_id)
        .bind(failed_effect_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("prove rejected terminal children did not persist");
        assert_eq!(rejected_child_counts, (0, 0, 0, 0));

        let guard_after: (i64, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT
                generation,
                terminal_receipt_id,
                source_closure_effect_intent_id
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("reload terminal authority guard after terminal-child attacks");
        assert_eq!(guard_after, guard_before);
        let receipt_after: (String, bool) = sqlx::query_as(
            r"
            SELECT
                receipt_digest,
                asf_valid_cancellation_terminal_receipt(tenant_id, id)
            FROM cancellation_terminal_receipts
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("revalidate terminal receipt after rejected terminal-child attacks");
        assert_eq!(receipt_after.0, receipt_before.0);
        assert!(receipt_after.1);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_committed_work_authority_wins_race_against_terminal_cancellation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let late_job_id = Uuid::now_v7();

        let mut authority_owner = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin winning work-authority transaction");
        let authority_owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *authority_owner)
            .await
            .expect("load winning work-authority backend PID");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5, 'TEST_CONCURRENT_WORK_AUTHORITY',
                'test.activity/test-concurrent-work-authority/v1', 'PENDING',
                '{}'::jsonb, $6
            )
            ",
        )
        .bind(late_job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("test-concurrent-work-authority:{late_job_id}"))
        .execute(&mut *authority_owner)
        .await
        .expect("insert winning live child while holding its authority guard");

        let control = fixture.control(
            vec![RunmillRunPhase::Cancelled, RunmillRunPhase::Cancelled],
            RunmillRunPhase::Cancelled,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
            "asf:test-controller",
            30,
        )
        .expect("construct racing terminal cancellation handler");
        let cancellation_job = fixture.job.clone();
        let cancellation = tokio::spawn(async move {
            handler
                .execute(&cancellation_job, ActivityControls::new(false))
                .await
        });

        let blocked_query = tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let blocked: Option<(i32, String)> = sqlx::query_as(
                    r"
                    SELECT pid, query
                    FROM pg_stat_activity
                    WHERE wait_event_type = 'Lock'
                      AND $1 = ANY(pg_blocking_pids(pid))
                    ORDER BY pid
                    LIMIT 1
                    ",
                )
                .bind(authority_owner_pid)
                .fetch_optional(database.ledger.pool())
                .await
                .expect("inspect terminal cancellation guard waiter");
                if let Some(blocked) = blocked {
                    break blocked;
                }
                assert!(
                    !cancellation.is_finished(),
                    "terminal cancellation finished before reaching the held authority guard"
                );
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("terminal cancellation must block behind the live child authority guard");
        assert_ne!(blocked_query.0, authority_owner_pid);
        assert!(!blocked_query.1.trim().is_empty());
        assert!(!cancellation.is_finished());

        authority_owner
            .commit()
            .await
            .expect("commit the winning live child authority");
        let cancellation_error = tokio::time::timeout(StdDuration::from_secs(10), cancellation)
            .await
            .expect("terminal cancellation must finish after the guard winner commits")
            .expect("join racing terminal cancellation")
            .expect_err("terminal cancellation must lose to committed live authority");
        assert!(matches!(cancellation_error, Error::Persistence(_)));

        let child_status: String =
            sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(late_job_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("reload winning live child");
        assert_eq!(child_status, "PENDING");
        let terminal_receipt_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM cancellation_terminal_receipts
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count receipts after the losing terminal cancellation");
        assert_eq!(terminal_receipt_count, 0);

        let preterminal: (String, String, bool, String, bool, String, String) = sqlx::query_as(
            r"
            SELECT work.state,
                   attempt.state,
                   attempt.terminal_at IS NULL,
                   run.state,
                   run.terminal_at IS NULL,
                   workflow.state,
                   cancellation_job.status
            FROM work_items AS work
            JOIN attempts AS attempt
              ON attempt.tenant_id = work.tenant_id
             AND attempt.id = work.current_attempt_id
            JOIN runs AS run
              ON run.tenant_id = work.tenant_id
             AND run.work_item_id = work.id
             AND run.attempt_id = attempt.id
             AND run.authoritative
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = work.tenant_id
             AND workflow.id = $3
            JOIN workflow_jobs AS cancellation_job
              ON cancellation_job.tenant_id = work.tenant_id
             AND cancellation_job.id = $4
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.job.workflow_instance_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load preterminal state after losing terminal cancellation");
        assert_eq!(preterminal.0, "CANCEL_REQUESTED");
        assert_eq!(preterminal.1, "RUNNING");
        assert!(preterminal.2);
        assert_eq!(preterminal.3, "RUNNING");
        assert!(preterminal.4);
        assert_eq!(preterminal.5, "ACTIVE");
        assert_eq!(preterminal.6, "RUNNING");
        let frozen_receipt_id: Option<Uuid> = sqlx::query_scalar(
            r"
            SELECT terminal_receipt_id
            FROM work_cancellation_authority_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load unfrozen authority guard after the child wins");
        assert!(frozen_receipt_id.is_none());
        assert_eq!(control.cancellation_calls(), 1);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_predictable_cancellation_reservation_release_requires_terminal_receipt_binding() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let transition_idempotency_key = format!(
            "runmill-cancellation:v1:{}:{}:{reservation_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin forged reservation-release attack");
        let release_result = sqlx::query(
            r"
            UPDATE reservation_sets
            SET state = 'RELEASED',
                fence_token = 2,
                released_at = clock_timestamp(),
                released_by = $3,
                release_reason = $4,
                transition_idempotency_key = $5
            WHERE tenant_id = $1
              AND id = $2
              AND state = 'ACTIVE'
              AND fence_token = 1
            ",
        )
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .bind(fixture.job.lease_owner.as_str())
        .bind(TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON)
        .bind(&transition_idempotency_key)
        .execute(&mut *transaction)
        .await;
        let release_error = match release_result {
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .expect("roll back rejected reservation-release attack");
                error
            }
            Ok(_) => transaction
                .commit()
                .await
                .expect_err("unbound cancellation release must fail no later than commit"),
        };
        let database_error = release_error
            .as_database_error()
            .expect("reservation-release rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("reservation_sets_cancellation_release_provenance")
        );

        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_runmill_cancellation_release_namespace_rejects_direct_poisoning() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let transition_idempotency_key = format!(
            "runmill-cancellation:v1:{}:{}:{reservation_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );

        let poison_event_id = Uuid::now_v7();
        let mut event_transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation event namespace poisoning");
        let event_error = sqlx::query(
            r"
            INSERT INTO reservation_set_events (
                id, tenant_id, reservation_set_id, event_type,
                previous_fence_token, fence_token, actor_id, reason,
                idempotency_key, occurred_at
            ) VALUES (
                $1, $2, $3, 'RELEASED', 1, 2, $4, $5, $6,
                clock_timestamp()
            )
            ",
        )
        .bind(poison_event_id)
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .bind(fixture.job.lease_owner.as_str())
        .bind(TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON)
        .bind(&transition_idempotency_key)
        .execute(&mut *event_transaction)
        .await
        .expect_err("direct writer must not occupy the cancellation event namespace");
        let event_database_error = event_error
            .as_database_error()
            .expect("event namespace rejection must be a PostgreSQL error");
        assert_eq!(event_database_error.code().as_deref(), Some("23514"));
        event_transaction
            .rollback()
            .await
            .expect("roll back cancellation event namespace poisoning");
        let poison_event_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM reservation_set_events
            WHERE tenant_id = $1
              AND (id = $2 OR idempotency_key = $3)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(poison_event_id)
        .bind(&transition_idempotency_key)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rejected cancellation event namespace rows");
        assert_eq!(poison_event_count, 0);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);

        let poison_budget_id = Uuid::now_v7();
        let budget_idempotency_key =
            format!("{transition_idempotency_key}:budget-release:COST_MICROUNITS");
        let mut budget_transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation budget namespace poisoning");
        let budget_error = sqlx::query(
            r"
            INSERT INTO budget_ledger (
                id, tenant_id, work_item_id, attempt_id, reservation_id,
                scope_type, scope_id, dimension, entry_type, amount, unit,
                idempotency_key, occurred_at
            ) VALUES (
                $1, $2, $3, $4, NULL,
                'ATTEMPT', $5, 'COST_MICROUNITS', 'ADJUST', 0, 'microunits',
                $6, clock_timestamp()
            )
            ",
        )
        .bind(poison_budget_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.attempt_id.to_string())
        .bind(&budget_idempotency_key)
        .execute(&mut *budget_transaction)
        .await
        .expect_err("direct writer must not occupy the cancellation budget-release namespace");
        let budget_database_error = budget_error
            .as_database_error()
            .expect("budget namespace rejection must be a PostgreSQL error");
        assert_eq!(budget_database_error.code().as_deref(), Some("23514"));
        budget_transaction
            .rollback()
            .await
            .expect("roll back cancellation budget namespace poisoning");
        let poison_budget_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM budget_ledger
            WHERE tenant_id = $1
              AND (id = $2 OR idempotency_key = $3)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(poison_budget_id)
        .bind(&budget_idempotency_key)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rejected cancellation budget namespace rows");
        assert_eq!(poison_budget_count, 0);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);

        let poison_set_id = Uuid::now_v7();
        let poison_admission_key = format!(
            "runmill-cancellation:v1:{}:{}:{poison_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );
        let mut admission_transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation admission namespace poisoning");
        let admission_error = sqlx::query(
            r"
            INSERT INTO reservation_sets (
                id, tenant_id, work_item_id, attempt_id, repository_id,
                worker_id, worker_session_id, worker_generation,
                request_digest, idempotency_key, state, fence_token,
                acquired_by, acquired_at, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, 1,
                $8, $9, 'ACTIVE', 1,
                'scheduler:namespace-poison', clock_timestamp(),
                clock_timestamp() + interval '15 minutes'
            )
            ",
        )
        .bind(poison_set_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.repository_id)
        .bind(fixture.worker_id.as_uuid())
        .bind(fixture.worker_session_id)
        .bind(digest('f'))
        .bind(&poison_admission_key)
        .execute(&mut *admission_transaction)
        .await
        .expect_err("reservation admission must reject the cancellation release prefix");
        let admission_database_error = admission_error
            .as_database_error()
            .expect("admission namespace rejection must be a PostgreSQL error");
        assert_eq!(admission_database_error.code().as_deref(), Some("23514"));
        admission_transaction
            .rollback()
            .await
            .expect("roll back cancellation admission namespace poisoning");
        let poison_set_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM reservation_sets
            WHERE tenant_id = $1
              AND (id = $2 OR idempotency_key = $3)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(poison_set_id)
        .bind(&poison_admission_key)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rejected cancellation admission namespace rows");
        assert_eq!(poison_set_count, 0);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_retained(&reservation);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_terminal_conflict_receipt_rejects_late_reservation_membership_growth() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Completed, RunmillRunPhase::Completed],
            RunmillRunPhase::Completed,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct terminal-conflict cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(true))
                .await
                .expect("create valid zero-release terminal-conflict receipt"),
            ActivityOutcome::TransactionCommitted
        );

        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        let (
            receipt_outcome,
            released_reservations,
            receipt_worker_id,
            observation_observed_at,
            receipt_recorded_at,
            receipt_completed_by,
        ): (
            String,
            i64,
            Uuid,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            String,
        ) = sqlx::query_as(
            r"
            SELECT receipt.outcome,
                   receipt.released_reservations,
                   run.worker_id,
                   observation.observed_at,
                   receipt.recorded_at,
                   receipt.workflow_job_completed_by
            FROM cancellation_terminal_receipts AS receipt
            JOIN runmill_cancellation_observations AS observation
              ON observation.tenant_id = receipt.tenant_id
             AND observation.id = receipt.terminal_observation_id
            JOIN runs AS run
              ON run.tenant_id = receipt.tenant_id
             AND run.id = receipt.run_id
            WHERE receipt.tenant_id = $1 AND receipt.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable terminal-conflict receipt provenance");
        assert_eq!(receipt_outcome, "TERMINAL_CONFLICT");
        assert_eq!(released_reservations, 0);
        assert_eq!(receipt_worker_id, fixture.worker_id.as_uuid());
        assert!(observation_observed_at <= receipt_recorded_at);
        let receipt_before: Value = sqlx::query_scalar(
            r"
            SELECT to_jsonb(receipt)
            FROM cancellation_terminal_receipts AS receipt
            WHERE receipt.tenant_id = $1 AND receipt.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("snapshot terminal-conflict receipt before membership attack");

        let poison_set_id = Uuid::now_v7();
        let poison_event_id = Uuid::now_v7();
        let transition_idempotency_key = format!(
            "runmill-cancellation:v1:{}:{}:{poison_set_id}:fence:1",
            fixture.work_item_id, fixture.attempt_id
        );
        let acquired_at = observation_observed_at - Duration::seconds(1);
        let released_at = observation_observed_at;
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin terminal-receipt membership attack");
        sqlx::query(
            r"
            INSERT INTO reservation_sets (
                id, tenant_id, work_item_id, attempt_id, repository_id,
                worker_id, worker_session_id, worker_generation,
                request_digest, idempotency_key, state, fence_token,
                acquired_by, acquired_at, expires_at,
                released_at, released_by, release_reason,
                transition_idempotency_key, cancellation_terminal_receipt_id
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, 1,
                $8, $9, 'RELEASED', 2,
                'scheduler:receipt-membership-attack', $10,
                $10 + interval '15 minutes',
                $11, $12, $13,
                $14, $15
            )
            ",
        )
        .bind(poison_set_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.repository_id)
        .bind(receipt_worker_id)
        .bind(fixture.worker_session_id)
        .bind(digest('f'))
        .bind(format!("receipt-membership-attack:{poison_set_id}"))
        .bind(acquired_at)
        .bind(released_at)
        .bind(&receipt_completed_by)
        .bind(TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON)
        .bind(&transition_idempotency_key)
        .bind(terminal_receipt_id)
        .execute(&mut *transaction)
        .await
        .expect("insert release-shaped late receipt member");
        sqlx::query(
            r"
            INSERT INTO reservation_set_events (
                id, tenant_id, reservation_set_id, event_type,
                previous_fence_token, fence_token, actor_id, reason,
                idempotency_key, occurred_at
            ) VALUES (
                $1, $2, $3, 'RELEASED', 1, 2, $4, $5, $6, $7
            )
            ",
        )
        .bind(poison_event_id)
        .bind(fixture.tenant_id)
        .bind(poison_set_id)
        .bind(&receipt_completed_by)
        .bind(TERMINAL_CANCELLATION_RESERVATION_RELEASE_REASON)
        .bind(&transition_idempotency_key)
        .bind(released_at)
        .execute(&mut *transaction)
        .await
        .expect("insert matching event for late receipt member");
        let commit_error = transaction
            .commit()
            .await
            .expect_err("immutable receipt cardinality must reject a late released member");
        let database_error = commit_error
            .as_database_error()
            .expect("late receipt membership rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("reservation_sets_cancellation_release_provenance")
        );

        let poison_set_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM reservation_sets
            WHERE tenant_id = $1
              AND (id = $2 OR cancellation_terminal_receipt_id = $3)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(poison_set_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rolled-back late receipt members");
        assert_eq!(poison_set_count, 0);
        let poison_event_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM reservation_set_events
            WHERE tenant_id = $1
              AND (id = $2 OR idempotency_key = $3)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(poison_event_id)
        .bind(&transition_idempotency_key)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rolled-back late receipt-member events");
        assert_eq!(poison_event_count, 0);
        let receipt_after: Value = sqlx::query_scalar(
            r"
            SELECT to_jsonb(receipt)
            FROM cancellation_terminal_receipts AS receipt
            WHERE receipt.tenant_id = $1 AND receipt.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("reload terminal-conflict receipt after rejected membership attack");
        assert_eq!(receipt_after, receipt_before);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_terminal_conflict_merge_receipt_rejects_direct_insert() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let direct_insert = sqlx::query(
            r"
            INSERT INTO terminal_conflict_escalation_merge_receipts (
                tenant_id,
                escalation_id,
                work_item_id,
                attempt_id,
                run_id_after,
                aggregate_version_before,
                aggregate_version_after,
                before_digest,
                after_digest
            ) VALUES ($1, $2, $3, $4, $5, 1, 2, $6, $7)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(Uuid::now_v7())
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.run_id)
        .bind(digest('a'))
        .bind(digest('b'))
        .execute(database.ledger.pool())
        .await
        .expect_err("direct writers must not manufacture escalation merge receipts");
        let database_error = direct_insert
            .as_database_error()
            .expect("direct receipt insert must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("55000"));
        assert_eq!(
            database_error.constraint(),
            Some("terminal_conflict_escalation_merge_receipts_generated_only")
        );
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM terminal_conflict_escalation_merge_receipts")
                .fetch_one(database.ledger.pool())
                .await
                .expect("count escalation merge receipts after rejected direct insert");
        assert_eq!(receipt_count, 0);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_terminal_conflict_merge_receipt_binds_actual_transition_and_is_append_only() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let escalation_id = Uuid::now_v7();
        let opened_at = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, attempt_id, category, status,
                severity, reason, owner_type, owner_id, required_action,
                evidence_references, deadline, escalation_path, retry_policy,
                prerequisites, authority_or_effect_active, idempotency_key, opened_at
            ) VALUES (
                $1, $2, $3, $4, 'REMOTE_EFFECT_AMBIGUOUS', 'OPEN', 'LOW',
                'provider acknowledgement is ambiguous',
                'TEAM', 'source-integrations',
                'inspect the provider receipt',
                '["provider-receipt:ambiguous"]'::jsonb,
                $5 + interval '12 hours',
                '[{"owner_type":"TEAM","owner_id":"source-integrations"}]'::jsonb,
                '{"automatic":true,"max_additional_attempts":1.0,"backoff_seconds":30,"prerequisites":["inspect provider receipt"]}'::jsonb,
                '["preserve provider evidence"]'::jsonb,
                false, $6, $5
            )
            "#,
        )
        .bind(escalation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(opened_at)
        .bind(format!("provider-ambiguous:{escalation_id}"))
        .execute(database.ledger.pool())
        .await
        .expect("seed escalation before merge-shaped transition");
        let expected_before_digest: String =
            sqlx::query_scalar("SELECT asf_terminal_conflict_escalation_digest($1, $2)")
                .bind(fixture.tenant_id)
                .bind(escalation_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("digest persisted escalation before merge-shaped transition");

        let control = fixture.control(
            vec![RunmillRunPhase::Completed, RunmillRunPhase::Completed],
            RunmillRunPhase::Completed,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("terminal cancellation must perform the certified merge"),
            ActivityOutcome::TransactionCommitted
        );
        let expected_after_digest: String =
            sqlx::query_scalar("SELECT asf_terminal_conflict_escalation_digest($1, $2)")
                .bind(fixture.tenant_id)
                .bind(escalation_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("digest persisted escalation after merge-shaped transition");
        assert_ne!(expected_before_digest, expected_after_digest);

        let receipt = sqlx::query(
            r"
            SELECT
                receipt.*,
                asf_source_closure_digest(jsonb_build_object(
                    'schema', 'asf.terminal-conflict-escalation-merge-receipt/v1',
                    'id', receipt.id,
                    'tenant_id', receipt.tenant_id,
                    'escalation_id', receipt.escalation_id,
                    'work_item_id', receipt.work_item_id,
                    'attempt_id', receipt.attempt_id,
                    'run_id_after', receipt.run_id_after,
                    'effect_intent_id', receipt.effect_intent_id,
                    'terminal_observation_id', receipt.terminal_observation_id,
                    'workflow_job_id', receipt.workflow_job_id,
                    'aggregate_version_before', receipt.aggregate_version_before,
                    'aggregate_version_after', receipt.aggregate_version_after,
                    'before_digest', receipt.before_digest,
                    'after_digest', receipt.after_digest
                )) AS expected_receipt_digest
            FROM terminal_conflict_escalation_merge_receipts AS receipt
            WHERE receipt.tenant_id = $1
              AND receipt.escalation_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(escalation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load trigger-generated escalation merge receipt");
        let receipt_id = receipt.try_get::<Uuid, _>("id").unwrap();
        assert_eq!(
            receipt_id,
            stable_receipt_uuid(
                b"asf.terminal-conflict-escalation-merge-receipt/v1",
                escalation_id,
                Some(2),
            )
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("tenant_id").unwrap(),
            fixture.tenant_id
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("work_item_id").unwrap(),
            fixture.work_item_id
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("attempt_id").unwrap(),
            fixture.attempt_id
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("run_id_after").unwrap(),
            fixture.run_id
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("effect_intent_id").unwrap(),
            stable_cancellation_effect_id(fixture.run_id)
        );
        assert_eq!(
            receipt
                .try_get::<Uuid, _>("terminal_observation_id")
                .unwrap(),
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token)
        );
        assert_eq!(
            receipt.try_get::<Uuid, _>("workflow_job_id").unwrap(),
            fixture.job.id
        );
        assert_eq!(
            receipt
                .try_get::<i64, _>("aggregate_version_before")
                .unwrap(),
            1
        );
        assert_eq!(
            receipt
                .try_get::<i64, _>("aggregate_version_after")
                .unwrap(),
            2
        );
        assert_eq!(
            receipt.try_get::<String, _>("before_digest").unwrap(),
            expected_before_digest
        );
        assert_eq!(
            receipt.try_get::<String, _>("after_digest").unwrap(),
            expected_after_digest
        );
        assert_eq!(
            receipt.try_get::<String, _>("receipt_digest").unwrap(),
            receipt
                .try_get::<String, _>("expected_receipt_digest")
                .unwrap()
        );
        let receipt_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM terminal_conflict_escalation_merge_receipts
            WHERE tenant_id = $1 AND escalation_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(escalation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count receipts for one merge-shaped transition");
        assert_eq!(receipt_count, 1);

        let update_error = sqlx::query(
            r"
            UPDATE terminal_conflict_escalation_merge_receipts
            SET before_digest = $2
            WHERE id = $1
            ",
        )
        .bind(receipt_id)
        .bind(digest('f'))
        .execute(database.ledger.pool())
        .await
        .expect_err("escalation merge receipts must reject tampering");
        let update_database_error = update_error
            .as_database_error()
            .expect("receipt update rejection must be a PostgreSQL error");
        assert_eq!(update_database_error.code().as_deref(), Some("55000"));
        assert!(update_database_error.message().contains("append-only"));

        let delete_error =
            sqlx::query("DELETE FROM terminal_conflict_escalation_merge_receipts WHERE id = $1")
                .bind(receipt_id)
                .execute(database.ledger.pool())
                .await
                .expect_err("escalation merge receipts must reject deletion");
        let delete_database_error = delete_error
            .as_database_error()
            .expect("receipt delete rejection must be a PostgreSQL error");
        assert_eq!(delete_database_error.code().as_deref(), Some("55000"));
        assert!(delete_database_error.message().contains("append-only"));

        let preserved: (String, String, i64) = sqlx::query_as(
            r"
            SELECT before_digest, after_digest, count(*) OVER ()
            FROM terminal_conflict_escalation_merge_receipts
            WHERE tenant_id = $1 AND escalation_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(escalation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable escalation merge receipt after rejected mutations");
        assert_eq!(
            preserved,
            (expected_before_digest, expected_after_digest, 1)
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_terminal_conflict_merge_rejects_evidence_destruction_atomically() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let escalation_id = Uuid::now_v7();
        let opened_at = Utc::now();
        let original_evidence = json!(["provider-evidence:must-survive"]);
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, attempt_id, category, status,
                severity, reason, owner_type, owner_id, required_action,
                evidence_references, deadline, escalation_path, retry_policy,
                prerequisites, authority_or_effect_active, idempotency_key, opened_at
            ) VALUES (
                $1, $2, $3, $4, 'REMOTE_EFFECT_AMBIGUOUS', 'OPEN', 'LOW',
                'provider acknowledgement is ambiguous',
                'TEAM', 'source-integrations',
                'inspect the provider receipt',
                $5, $6 + interval '12 hours', $7, $8, $9, false, $10, $6
            )
            ",
        )
        .bind(escalation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(&original_evidence)
        .bind(opened_at)
        .bind(json!([
            {"owner_type": "TEAM", "owner_id": "source-integrations"},
        ]))
        .bind(json!({
            "automatic": true,
            "max_additional_attempts": 1,
            "backoff_seconds": 30,
            "prerequisites": ["inspect provider receipt"],
        }))
        .bind(json!(["preserve provider evidence"]))
        .bind(format!("provider-ambiguous:{escalation_id}"))
        .execute(database.ledger.pool())
        .await
        .expect("seed unrelated escalation before destructive merge probe");
        let before_row = sqlx::query("SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(escalation_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load escalation before destructive merge probe");
        let expected_before_digest = terminal_conflict_state_digest(&before_row)
            .expect("digest escalation before destructive merge probe");

        sqlx::raw_sql(
            r"
            CREATE FUNCTION asf_test_discard_old_escalation_evidence()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $test_trigger$
            BEGIN
                IF OLD.category = 'REMOTE_EFFECT_AMBIGUOUS'
                   AND NEW.category = OLD.category
                   AND NEW.aggregate_version = OLD.aggregate_version + 1
                   AND NEW.run_id IS NOT NULL THEN
                    NEW.evidence_references :=
                        jsonb_build_array('forged-replacement:evidence-destroyed');
                END IF;
                RETURN NEW;
            END;
            $test_trigger$;

            CREATE TRIGGER zz_test_discard_old_escalation_evidence
                BEFORE UPDATE ON escalations
                FOR EACH ROW
                EXECUTE FUNCTION asf_test_discard_old_escalation_evidence();
            ",
        )
        .execute(database.ledger.pool())
        .await
        .expect("install scoped destructive escalation trigger");

        let control = fixture.control(
            vec![RunmillRunPhase::Completed, RunmillRunPhase::Completed],
            RunmillRunPhase::Completed,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler for destructive merge probe");
        let merge_error = handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .expect_err("destruction of prior escalation evidence must abort cancellation");
        let merge_error = merge_error.to_string();
        assert!(merge_error.contains("merge cancellation escalation"));
        assert!(merge_error.contains(
            "terminal-conflict escalation update is not the conservative cancellation merge"
        ));

        let preserved_row =
            sqlx::query("SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(escalation_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load escalation after rejected destructive merge");
        assert_eq!(
            terminal_conflict_state_digest(&preserved_row)
                .expect("digest escalation after rejected destructive merge"),
            expected_before_digest
        );
        assert_eq!(
            preserved_row
                .try_get::<i64, _>("aggregate_version")
                .unwrap(),
            1
        );
        assert!(
            preserved_row
                .try_get::<Option<Uuid>, _>("run_id")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            preserved_row
                .try_get::<Value, _>("evidence_references")
                .unwrap(),
            original_evidence
        );
        assert!(
            !preserved_row
                .try_get::<bool, _>("authority_or_effect_active")
                .unwrap()
        );

        let receipts: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*)
                 FROM terminal_conflict_escalation_merge_receipts
                 WHERE tenant_id = $1 AND escalation_id = $2),
                (SELECT count(*)
                 FROM runmill_cancellation_observations
                 WHERE tenant_id = $1 AND workflow_job_id = $3),
                (SELECT count(*)
                 FROM cancellation_terminal_receipts
                 WHERE tenant_id = $1 AND workflow_job_id = $3),
                (SELECT count(*)
                 FROM audit_events
                 WHERE tenant_id = $1
                   AND work_item_id = $4
                   AND action = 'RUNMILL_CANCELLATION_ALREADY_TERMINAL'),
                (SELECT count(*)
                 FROM outbox
                 WHERE tenant_id = $1
                   AND message_key = $4::text
                   AND event_type = 'work_item.cancellation_terminal_conflict')
            ",
        )
        .bind(fixture.tenant_id)
        .bind(escalation_id)
        .bind(fixture.job.id)
        .bind(fixture.work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count cancellation artifacts after rejected destructive merge");
        assert_eq!(receipts, (0, 0, 0, 0, 0));

        let aggregate_state: (String, String, String, String, String, String, Uuid) =
            sqlx::query_as(
                r"
                SELECT
                    job.status,
                    work.state,
                    workflow.state,
                    attempt.state,
                    run.state,
                    anchor.anchor_type,
                    anchor.reference_id
                FROM workflow_jobs AS job
                JOIN work_items AS work
                  ON work.tenant_id = job.tenant_id
                 AND work.id = job.work_item_id
                JOIN workflow_instances AS workflow
                  ON workflow.tenant_id = job.tenant_id
                 AND workflow.id = job.workflow_instance_id
                JOIN attempts AS attempt
                  ON attempt.tenant_id = job.tenant_id
                 AND attempt.id = job.attempt_id
                JOIN runs AS run
                  ON run.tenant_id = job.tenant_id
                 AND run.id = $3
                JOIN accountability_anchors AS anchor
                  ON anchor.tenant_id = job.tenant_id
                 AND anchor.work_item_id = job.work_item_id
                WHERE job.tenant_id = $1 AND job.id = $2
                ",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.job.id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load aggregate state after rejected destructive merge");
        assert_eq!(
            aggregate_state,
            (
                "RUNNING".into(),
                "CANCEL_REQUESTED".into(),
                "ACTIVE".into(),
                "RUNNING".into(),
                "RUNNING".into(),
                "WORKFLOW".into(),
                fixture.job.workflow_instance_id.unwrap(),
            )
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_terminal_conflict_merges_unrelated_remote_effect_escalation_conservatively() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let existing_escalation_id = Uuid::now_v7();
        let existing_opened_at = Utc::now();
        let existing_deadline = existing_opened_at + Duration::hours(12);
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, attempt_id, category, status,
                severity, reason, owner_type, owner_id, required_action,
                evidence_references, deadline, escalation_path, retry_policy,
                prerequisites, authority_or_effect_active, idempotency_key, opened_at
            ) VALUES (
                $1, $2, $3, $4, 'REMOTE_EFFECT_AMBIGUOUS', 'OPEN', 'LOW',
                'GitHub delivery acknowledgement is ambiguous',
                'TEAM', 'source-integrations',
                'inspect the GitHub delivery receipt',
                $5, $6, $7, $8, $9, false, $10, $11
            )
            ",
        )
        .bind(existing_escalation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(json!(["github-delivery:delivery-123"]))
        .bind(existing_deadline)
        .bind(json!([
            {"owner_type": "TEAM", "owner_id": "source-integrations"},
        ]))
        .bind(json!({
            "automatic": true,
            "max_additional_attempts": 3,
            "backoff_seconds": 60,
            "prerequisites": ["inspect GitHub delivery"],
        }))
        .bind(json!(["preserve GitHub delivery evidence"]))
        .bind(format!("github-delivery-ambiguous:{}", fixture.attempt_id))
        .bind(existing_opened_at)
        .execute(database.ledger.pool())
        .await
        .expect("seed unrelated remote-effect escalation");
        let before_row = sqlx::query("SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(existing_escalation_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load unrelated escalation before cancellation merge");
        let expected_before_digest = terminal_conflict_state_digest(&before_row)
            .expect("digest escalation state before cancellation merge");

        let control = fixture.control(
            vec![RunmillRunPhase::Completed, RunmillRunPhase::Completed],
            RunmillRunPhase::Completed,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(false))
                .await
                .expect("terminal cancellation must merge generic escalation collision"),
            ActivityOutcome::TransactionCommitted
        );

        let row = sqlx::query(
            r"
            SELECT
                escalation.id,
                escalation.status,
                escalation.run_id,
                escalation.severity,
                escalation.reason,
                escalation.owner_type,
                escalation.owner_id,
                escalation.required_action,
                escalation.evidence_references,
                escalation.deadline,
                escalation.escalation_path,
                escalation.retry_policy,
                escalation.prerequisites,
                escalation.authority_or_effect_active,
                escalation.aggregate_version,
                anchor.reference_id AS anchor_reference_id,
                work.state AS work_state,
                attempt.state AS attempt_state
            FROM escalations AS escalation
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = escalation.tenant_id
             AND anchor.work_item_id = escalation.work_item_id
            JOIN work_items AS work
              ON work.tenant_id = escalation.tenant_id
             AND work.id = escalation.work_item_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = escalation.tenant_id
             AND attempt.id = escalation.attempt_id
            WHERE escalation.tenant_id = $1
              AND escalation.work_item_id = $2
              AND escalation.attempt_id = $3
              AND escalation.category = 'REMOTE_EFFECT_AMBIGUOUS'
              AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load merged Runmill cancellation escalation");
        assert_eq!(
            row.try_get::<Uuid, _>("id").unwrap(),
            existing_escalation_id
        );
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "OPEN");
        assert_eq!(row.try_get::<Uuid, _>("run_id").unwrap(), fixture.run_id);
        assert_eq!(row.try_get::<String, _>("severity").unwrap(), "HIGH");
        assert!(
            row.try_get::<String, _>("reason")
                .unwrap()
                .contains("GitHub delivery")
        );
        assert!(
            row.try_get::<String, _>("reason")
                .unwrap()
                .contains("Runmill was already terminal")
        );
        assert_eq!(row.try_get::<String, _>("owner_type").unwrap(), "TEAM");
        assert_eq!(
            row.try_get::<String, _>("owner_id").unwrap(),
            "source-integrations"
        );
        let action = row.try_get::<String, _>("required_action").unwrap();
        assert!(action.contains("GitHub delivery receipt"));
        assert!(action.contains("terminal Runmill evidence"));
        let evidence = row.try_get::<Value, _>("evidence_references").unwrap();
        for expected in [
            "github-delivery:delivery-123".into(),
            format!("run:{}", fixture.run_id),
            format!("external-run:{}", fixture.external_run_id),
            format!(
                "cancellation-request:{}",
                stable_cancellation_request_id(
                    fixture.tenant_id,
                    fixture.work_item_id,
                    fixture.attempt_id,
                    fixture.run_id,
                )
            ),
            format!(
                "effect-intent:{}",
                stable_cancellation_effect_id(fixture.run_id)
            ),
        ] {
            assert!(evidence.as_array().unwrap().contains(&json!(expected)));
        }
        let merged_deadline = row.try_get::<chrono::DateTime<Utc>, _>("deadline").unwrap();
        assert!(merged_deadline < existing_deadline);
        assert!(merged_deadline > Utc::now());
        let path = row.try_get::<Value, _>("escalation_path").unwrap();
        assert!(path.as_array().unwrap().contains(&json!({
            "owner_type": "TEAM",
            "owner_id": "source-integrations",
        })));
        assert!(path.as_array().unwrap().contains(&json!({
            "owner_type": "ON_CALL",
            "owner_id": "platform-operations",
        })));
        let retry_policy = row.try_get::<Value, _>("retry_policy").unwrap();
        assert_eq!(retry_policy["automatic"], false);
        assert_eq!(retry_policy["max_additional_attempts"], 0);
        assert_eq!(retry_policy["backoff_seconds"], 0);
        assert!(
            retry_policy["prerequisites"]
                .as_array()
                .unwrap()
                .contains(&json!("inspect GitHub delivery"))
        );
        assert!(
            retry_policy["prerequisites"]
                .as_array()
                .unwrap()
                .contains(&json!("verify terminal Runmill evidence"))
        );
        let prerequisites = row.try_get::<Value, _>("prerequisites").unwrap();
        assert!(
            prerequisites
                .as_array()
                .unwrap()
                .contains(&json!("preserve GitHub delivery evidence"))
        );
        assert!(
            prerequisites
                .as_array()
                .unwrap()
                .contains(&json!("record an explicit operator disposition"))
        );
        assert!(
            row.try_get::<bool, _>("authority_or_effect_active")
                .unwrap()
        );
        assert_eq!(row.try_get::<i64, _>("aggregate_version").unwrap(), 2);
        assert_eq!(
            row.try_get::<Uuid, _>("anchor_reference_id").unwrap(),
            existing_escalation_id
        );
        assert_eq!(row.try_get::<String, _>("work_state").unwrap(), "ESCALATED");
        assert_eq!(
            row.try_get::<String, _>("attempt_state").unwrap(),
            "SUCCEEDED"
        );
        let after_row = sqlx::query("SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(existing_escalation_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load escalation after cancellation merge");
        let expected_after_digest = terminal_conflict_state_digest(&after_row)
            .expect("digest escalation state after cancellation merge");
        assert_ne!(expected_before_digest, expected_after_digest);
        let emitted = sqlx::query(
            r"
            SELECT
                job.result AS job_result,
                audit.before_digest AS audit_before_digest,
                audit.after_digest AS audit_after_digest,
                audit.details AS audit_details,
                outbox.payload AS outbox_payload
            FROM workflow_jobs AS job
            JOIN audit_events AS audit
              ON audit.tenant_id = job.tenant_id
             AND audit.work_item_id = job.work_item_id
             AND audit.attempt_id = job.attempt_id
             AND audit.action = 'RUNMILL_CANCELLATION_ALREADY_TERMINAL'
            JOIN outbox
              ON outbox.tenant_id = job.tenant_id
             AND outbox.event_type = 'work_item.cancellation_terminal_conflict'
             AND outbox.message_key = job.work_item_id::text
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load merged escalation cancellation emissions");
        let job_result = emitted.try_get::<Value, _>("job_result").unwrap();
        let result = &job_result["result"];
        let audit_details = emitted.try_get::<Value, _>("audit_details").unwrap();
        let outbox_payload = emitted.try_get::<Value, _>("outbox_payload").unwrap();
        let cancellation_observation_id =
            stable_cancellation_observation_id(fixture.job.id, fixture.job.fence_token);
        let terminal_receipt_id = stable_cancellation_terminal_receipt_id(fixture.job.id);
        for payload in [result, &audit_details, &outbox_payload] {
            assert_eq!(payload["released_reservations"], 1);
            assert_eq!(
                payload["cancellation_observation_id"],
                json!(cancellation_observation_id)
            );
            assert_eq!(payload["terminal_receipt_id"], json!(terminal_receipt_id));
            assert_eq!(payload["escalation_id"], json!(existing_escalation_id));
            assert_eq!(payload["escalation_disposition"], "merged");
            assert_eq!(payload["escalation_before_digest"], expected_before_digest);
            assert_eq!(payload["escalation_after_digest"], expected_after_digest);
            assert_eq!(payload["escalation_deadline"], json!(merged_deadline));
        }
        assert_eq!(
            emitted
                .try_get::<Option<String>, _>("audit_before_digest")
                .unwrap()
                .as_deref(),
            Some(expected_before_digest.as_str())
        );
        assert_eq!(
            emitted
                .try_get::<Option<String>, _>("audit_after_digest")
                .unwrap()
                .as_deref(),
            Some(expected_after_digest.as_str())
        );
        assert_eq!(audit_details["request_digest"], result["request_digest"]);
        assert_ne!(audit_details["request_digest"], expected_after_digest);
        let terminal_receipt = sqlx::query(
            r"
            SELECT outcome, terminal_observation_id, escalation_id,
                   released_reservations
            FROM cancellation_terminal_receipts
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal-conflict cancellation receipt");
        assert_eq!(
            terminal_receipt.try_get::<String, _>("outcome").unwrap(),
            "TERMINAL_CONFLICT"
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Uuid, _>("terminal_observation_id")
                .unwrap(),
            cancellation_observation_id
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Option<Uuid>, _>("escalation_id")
                .unwrap(),
            Some(existing_escalation_id)
        );
        assert_eq!(
            terminal_receipt
                .try_get::<i64, _>("released_reservations")
                .unwrap(),
            1
        );
        let open_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM escalations
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND attempt_id = $3
              AND category = 'REMOTE_EFFECT_AMBIGUOUS'
              AND status IN ('OPEN', 'ACKNOWLEDGED')
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count merged remote-effect escalation");
        assert_eq!(open_count, 1);
        let projected = PostgresApiBackend::from_ledger(
            &database.ledger,
            TenantId::from_uuid(fixture.tenant_id),
        )
        .attention(
            TenantId::from_uuid(fixture.tenant_id),
            &PageQuery {
                cursor: None,
                limit: 50,
            },
        )
        .await
        .expect("project the merged cancellation escalation into attention");
        let projected = projected
            .items
            .iter()
            .find(|item| item.id == existing_escalation_id)
            .expect("merged cancellation escalation in attention projection");
        assert!(projected.evidence_references.contains(&format!(
            "effect-intent:{}",
            stable_cancellation_effect_id(fixture.run_id)
        )));
        assert!(
            projected
                .required_action
                .contains("terminal Runmill evidence")
        );
        assert_eq!(projected.retry_policy["automatic"], false);
        assert!(projected.authority_or_effect_active);
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_released(
            &fixture,
            reservation_set_id,
            fixture.job.lease_owner.as_str(),
            terminal_receipt_id,
            &reservation,
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_non_cancelled_terminal_run_is_completed_only_with_an_owned_escalation_anchor() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveFixture::insert(&database.ledger).await;
        let reservation_set_id = fixture.insert_active_reservation(&database.ledger).await;
        let control = fixture.control(
            vec![RunmillRunPhase::Completed, RunmillRunPhase::Completed],
            RunmillRunPhase::Completed,
            false,
        );
        let handler = RunmillCancellationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control,
            "asf:test-controller",
            30,
        )
        .expect("construct cancellation handler");
        assert_eq!(
            handler
                .execute(&fixture.job, ActivityControls::new(true))
                .await
                .expect("terminal conflict must be durably routed"),
            ActivityOutcome::TransactionCommitted
        );

        let row = sqlx::query(
            r"
            SELECT
                job.status AS job_status,
                work.state AS work_state,
                workflow.state AS workflow_state,
                attempt.state AS attempt_state,
                attempt.aggregate_version AS attempt_version,
                attempt.terminal_at AS attempt_terminal_at,
                run.state AS run_state,
                anchor.anchor_type,
                anchor.reference_id,
                escalation.category,
                escalation.owner_type,
                escalation.owner_id,
                escalation.required_action,
                escalation.evidence_references,
                escalation.deadline,
                escalation.authority_or_effect_active
            FROM workflow_jobs AS job
            JOIN work_items AS work
              ON work.tenant_id = job.tenant_id AND work.id = job.work_item_id
            JOIN workflow_instances AS workflow
              ON workflow.tenant_id = job.tenant_id AND workflow.id = job.workflow_instance_id
            JOIN attempts AS attempt
              ON attempt.tenant_id = job.tenant_id AND attempt.id = job.attempt_id
            JOIN runs AS run
              ON run.tenant_id = job.tenant_id AND run.id = $3
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = job.tenant_id AND anchor.work_item_id = job.work_item_id
            JOIN escalations AS escalation
              ON escalation.tenant_id = anchor.tenant_id AND escalation.id = anchor.reference_id
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal-conflict escalation");
        assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "COMPLETED");
        assert_eq!(row.try_get::<String, _>("work_state").unwrap(), "ESCALATED");
        assert_eq!(
            row.try_get::<String, _>("workflow_state").unwrap(),
            "WAITING"
        );
        assert_eq!(
            row.try_get::<String, _>("attempt_state").unwrap(),
            "SUCCEEDED"
        );
        assert_eq!(row.try_get::<i64, _>("attempt_version").unwrap(), 2);
        assert!(
            row.try_get::<Option<chrono::DateTime<Utc>>, _>("attempt_terminal_at")
                .unwrap()
                .is_some()
        );
        assert_eq!(row.try_get::<String, _>("run_state").unwrap(), "SUCCEEDED");
        assert_eq!(
            row.try_get::<String, _>("anchor_type").unwrap(),
            "ESCALATION"
        );
        assert_eq!(
            row.try_get::<String, _>("category").unwrap(),
            "REMOTE_EFFECT_AMBIGUOUS"
        );
        assert_eq!(row.try_get::<String, _>("owner_type").unwrap(), "ON_CALL");
        assert_eq!(
            row.try_get::<String, _>("owner_id").unwrap(),
            "platform-operations"
        );
        assert!(
            row.try_get::<String, _>("required_action")
                .unwrap()
                .contains("explicitly")
        );
        assert!(
            row.try_get::<Value, _>("evidence_references")
                .unwrap()
                .as_array()
                .unwrap()
                .contains(&json!(format!(
                    "cancellation-request:{}",
                    stable_cancellation_request_id(
                        fixture.tenant_id,
                        fixture.work_item_id,
                        fixture.attempt_id,
                        fixture.run_id,
                    )
                )))
        );
        assert!(row.try_get::<chrono::DateTime<Utc>, _>("deadline").unwrap() > Utc::now());
        assert!(
            row.try_get::<bool, _>("authority_or_effect_active")
                .unwrap()
        );
        assert_ne!(
            row.try_get::<Uuid, _>("reference_id").unwrap(),
            fixture.run_id
        );
        let escalation_id = row.try_get::<Uuid, _>("reference_id").unwrap();
        let escalation_deadline = row.try_get::<chrono::DateTime<Utc>, _>("deadline").unwrap();
        let escalation_row =
            sqlx::query("SELECT * FROM escalations WHERE tenant_id = $1 AND id = $2")
                .bind(fixture.tenant_id)
                .bind(escalation_id)
                .fetch_one(database.ledger.pool())
                .await
                .expect("load newly created cancellation escalation state");
        let expected_after_digest = terminal_conflict_state_digest(&escalation_row)
            .expect("digest newly created cancellation escalation state");
        let emitted = sqlx::query(
            r"
            SELECT
                job.result AS job_result,
                audit.before_digest AS audit_before_digest,
                audit.after_digest AS audit_after_digest,
                audit.details AS audit_details,
                outbox.payload AS outbox_payload
            FROM workflow_jobs AS job
            JOIN audit_events AS audit
              ON audit.tenant_id = job.tenant_id
             AND audit.work_item_id = job.work_item_id
             AND audit.attempt_id = job.attempt_id
             AND audit.action = 'RUNMILL_CANCELLATION_ALREADY_TERMINAL'
            JOIN outbox
              ON outbox.tenant_id = job.tenant_id
             AND outbox.event_type = 'work_item.cancellation_terminal_conflict'
             AND outbox.message_key = job.work_item_id::text
            WHERE job.tenant_id = $1 AND job.id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load new escalation cancellation emissions");
        let job_result = emitted.try_get::<Value, _>("job_result").unwrap();
        let result = &job_result["result"];
        let audit_details = emitted.try_get::<Value, _>("audit_details").unwrap();
        let outbox_payload = emitted.try_get::<Value, _>("outbox_payload").unwrap();
        for payload in [result, &audit_details, &outbox_payload] {
            assert_eq!(payload["released_reservations"], 1);
            assert_eq!(payload["escalation_id"], json!(escalation_id));
            assert_eq!(payload["escalation_disposition"], "created");
            assert!(payload["escalation_before_digest"].is_null());
            assert_eq!(payload["escalation_after_digest"], expected_after_digest);
            assert_eq!(payload["escalation_deadline"], json!(escalation_deadline));
        }
        assert!(
            emitted
                .try_get::<Option<String>, _>("audit_before_digest")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            emitted
                .try_get::<Option<String>, _>("audit_after_digest")
                .unwrap()
                .as_deref(),
            Some(expected_after_digest.as_str())
        );
        assert_eq!(audit_details["request_digest"], result["request_digest"]);
        assert_ne!(audit_details["request_digest"], expected_after_digest);
        let attention = PostgresApiBackend::from_ledger(
            &database.ledger,
            TenantId::from_uuid(fixture.tenant_id),
        )
        .attention(
            TenantId::from_uuid(fixture.tenant_id),
            &PageQuery {
                cursor: None,
                limit: 10,
            },
        )
        .await
        .expect("terminal-conflict escalation must project as complete attention");
        assert_eq!(attention.items.len(), 1);
        assert_eq!(attention.items[0].kind, AttentionItemKind::Escalation);
        assert_eq!(
            attention.items[0].work_item_id,
            Some(WorkItemId::from_uuid(fixture.work_item_id))
        );
        let reservation =
            load_reservation_release_state(&database.ledger, fixture.tenant_id, reservation_set_id)
                .await;
        assert_cancellation_reservation_released(
            &fixture,
            reservation_set_id,
            fixture.job.lease_owner.as_str(),
            stable_cancellation_terminal_receipt_id(fixture.job.id),
            &reservation,
        );
        database.cleanup().await;
    }
}
