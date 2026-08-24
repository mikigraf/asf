//! Durable, cursor-addressed Runmill control-plane observation.
//!
//! Every job performs two bounded reads, retains their exact validated wires,
//! records them as immutable snapshots with their exact provenance intact,
//! and advances the observation stream cursor under fenced state guards.
//! No event projection or `VERIFY_EVIDENCE` workflow is produced from Runmill events.
//!
//! FUTURE: Authoritative run projection requires a versioned Runmill-to-ASF contract
//! plus pre-signed evidence bundles with `evidence_id`, `payload_digest`, `work_order_digest`,
//! and `expectation_digest` supplied by Runmill control. Once available, a separate
//! projection boundary can safely ingest events via `ledger::ingest_run_event` and
//! enqueue evidence verification workflows.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, JobClaimScope, JobHandler, OBSERVE_RUNMILL_RUN,
    OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
};
use crate::{
    Error, Result,
    adapters::{
        RunmillControlClient, RunmillControlError, RunmillEventPage, RunmillRunId,
        RunmillRunSnapshot,
    },
    crypto::{is_sha256_digest, sha256_digest},
    domain::{TenantId, WorkerId},
    ledger::{
        ClaimedWorkflowJob, DeadLetterEscalation, IncomingRunmillControlSnapshot, PgLedger,
        RunmillControlObservationOutcome, RunmillObservationFence, StepAuditEvent,
        StepOutboxMessage, WorkflowStepFailure, WorkflowStepFailureDisposition, WorkflowStepFence,
        fail_workflow_step_with_prelocked_claim_force_terminal, record_runmill_control_observation,
    },
    security::reject_sensitive_fields,
};

/// The observer intentionally retains only one bounded page per claimed job.
pub const RUNMILL_OBSERVATION_EVENT_LIMIT: u16 = 100;
const RUNMILL_OBSERVATION_PAYLOAD_SCHEMA_V2: &str = "asf.runmill-observation/v2";
const RUNMILL_LIVE_POLL_DELAY_SECONDS: i64 = 5;

/// The two exact control responses retained by one bounded observation.
///
/// This stays private so production code alone crosses from a
/// `RunmillValidatedRead` into a durable snapshot. Tests may supply an
/// already-validated batch through the private control seam without gaining a
/// public way to forge control provenance.
#[derive(Debug, Clone)]
struct RunmillObservationBatch {
    get_run: IncomingRunmillControlSnapshot,
    event_page: IncomingRunmillControlSnapshot,
}

#[async_trait]
trait RunmillObservationControl: Send + Sync + fmt::Debug {
    async fn observe_run(
        &self,
        run_id: &RunmillRunId,
        after_sequence: u64,
    ) -> Result<RunmillObservationBatch>;
}

#[async_trait]
impl RunmillObservationControl for RunmillControlClient {
    async fn observe_run(
        &self,
        run_id: &RunmillRunId,
        after_sequence: u64,
    ) -> Result<RunmillObservationBatch> {
        let get_run_read = RunmillControlClient::get_run_with_provenance(self, run_id)
            .await
            .map_err(|error| control_failure(&error))?;
        let get_run = IncomingRunmillControlSnapshot::from_validated_get_run(
            Uuid::now_v7(),
            1,
            Utc::now(),
            get_run_read,
        )?;

        let event_page_read = RunmillControlClient::list_run_events_with_provenance(
            self,
            run_id,
            after_sequence,
            RUNMILL_OBSERVATION_EVENT_LIMIT,
        )
        .await
        .map_err(|error| control_failure(&error))?;
        let event_ids = (0..event_page_read.value().events.len())
            .map(|_| Uuid::now_v7())
            .collect();
        let event_page = IncomingRunmillControlSnapshot::from_validated_event_page(
            Uuid::now_v7(),
            event_ids,
            2,
            Utc::now(),
            event_page_read,
        )?;

        Ok(RunmillObservationBatch {
            get_run,
            event_page,
        })
    }
}

/// Retains one exact `get-run` response and one bounded cursor page for a
/// single configured tenant and private Runmill worker.
#[derive(Clone)]
pub struct RunmillObservationHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    worker_id: WorkerId,
    control: Arc<dyn RunmillObservationControl>,
}

impl fmt::Debug for RunmillObservationHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillObservationHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("worker_id", &self.worker_id)
            .field("control", &"RunmillControlClient([REDACTED])")
            .finish()
    }
}

impl RunmillObservationHandler {
    /// Construct an observer explicitly scoped to one tenant and worker.
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: RunmillControlClient,
    ) -> Result<Self> {
        if tenant_id.as_uuid().is_nil() || worker_id.as_uuid().is_nil() {
            return Err(Error::Validation(
                "Runmill observation handler requires non-nil tenant and worker IDs".into(),
            ));
        }
        Ok(Self::with_control(
            ledger,
            tenant_id,
            worker_id,
            Arc::new(control),
        ))
    }

    fn with_control(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: Arc<dyn RunmillObservationControl>,
    ) -> Self {
        Self {
            ledger,
            tenant_id,
            worker_id,
            control,
        }
    }

    async fn execute_inner(&self, job: &ClaimedWorkflowJob) -> Result<ActivityOutcome> {
        let payload = RunmillObservationPayload::parse(job, self.tenant_id, self.worker_id)?;
        let external_run_id =
            RunmillRunId::parse(payload.external_run_id.clone()).map_err(|err| {
                Error::Validation(format!(
                    "Runmill observation job {} has an invalid external run ID: {err}",
                    job.id
                ))
            })?;
        self.preflight_authority(job, &payload).await?;
        let attempt_id = job.attempt_id.ok_or_else(|| {
            Error::Validation(format!(
                "Runmill observation job {} lacks its attempt binding",
                job.id
            ))
        })?;

        // Complete and validate both remote reads before opening the ledger
        // transaction. A remote timeout or malformed response never creates a
        // partial local observation.
        let observations = self
            .control
            .observe_run(&external_run_id, payload.after_sequence)
            .await?;
        let event_page = validate_remote_binding(
            &payload,
            self.tenant_id,
            &external_run_id,
            attempt_id,
            &observations.get_run,
            &observations.event_page,
        )?;

        self.persist_observations(
            job,
            &payload,
            &observations.get_run,
            &observations.event_page,
            &event_page,
        )
        .await
    }

    /// Checks the immutable authority binding before opening a private Runmill
    /// socket. This read intentionally takes no locks; persistence repeats the
    /// proof under locks after remote I/O.
    async fn preflight_authority(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &RunmillObservationPayload,
    ) -> Result<()> {
        assert_exact_observation_authority(self.ledger.pool(), job, payload, false)
            .await
            .map(|_| ())
    }

    async fn persist_observations(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &RunmillObservationPayload,
        get_run: &IncomingRunmillControlSnapshot,
        event_page: &IncomingRunmillControlSnapshot,
        validated_page: &RunmillEventPage,
    ) -> Result<ActivityOutcome> {
        let fence = payload.fence(job)?;
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!("begin Runmill observation transaction: {error}"))
        })?;
        let authority =
            assert_exact_observation_authority(&mut *transaction, job, payload, true).await?;
        let get_run_outcome =
            record_runmill_control_observation(&mut transaction, &fence, get_run).await?;
        let event_page_outcome =
            record_runmill_control_observation(&mut transaction, &fence, event_page).await?;
        if validated_page.gap {
            persist_gap_escalation(
                &mut transaction,
                job,
                payload,
                &authority,
                &get_run_outcome,
                &event_page_outcome,
                validated_page,
            )
            .await?;
        } else {
            persist_cursor_advance(
                &mut transaction,
                job,
                payload,
                &authority,
                &get_run_outcome,
                &event_page_outcome,
                validated_page,
            )
            .await?;
        }
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!("commit Runmill observation transaction: {error}"))
        })?;
        Ok(if validated_page.gap {
            ActivityOutcome::DeadLetterCommitted
        } else {
            ActivityOutcome::TransactionCommitted
        })
    }
}

#[async_trait]
impl JobHandler for RunmillObservationHandler {
    fn job_type(&self) -> &str {
        OBSERVE_RUNMILL_RUN
    }

    fn activity_contract_id(&self) -> &str {
        OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
    }

    fn claim_scope(&self) -> JobClaimScope {
        JobClaimScope::ObserveRunmillRunWorker(self.worker_id)
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        self.execute_inner(job).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunmillObservationPayload {
    schema: String,
    observation_id: Uuid,
    run_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    worker_id: WorkerId,
    worker_session_id: Uuid,
    observer_session_id: Uuid,
    worker_generation: u64,
    external_run_id: String,
    after_sequence: u64,
    observation_epoch: u64,
}

impl RunmillObservationPayload {
    fn parse(job: &ClaimedWorkflowJob, tenant_id: TenantId, worker_id: WorkerId) -> Result<Self> {
        if job.job_type != OBSERVE_RUNMILL_RUN
            || job.activity_contract_id != OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
            || job.tenant_id != tenant_id.as_uuid()
            || job.workflow_instance_id.is_none()
            || job.work_item_id.is_none()
            || job.attempt_id.is_none()
            || job.idempotency_key.trim().is_empty()
            || job.attempt_count <= 0
            || job.fence_token <= 0
            || job.lease_owner.trim().is_empty()
        {
            return Err(Error::Validation(
                "Runmill observation job has invalid type, activity contract, claim, tenant, or workflow binding"
                    .into(),
            ));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!("invalid Runmill observation payload: {error}"))
        })?;
        if payload.schema != RUNMILL_OBSERVATION_PAYLOAD_SCHEMA_V2
            || payload.observation_id.is_nil()
            || payload.run_id.is_nil()
            || payload.work_order_id.is_nil()
            || payload.worker_id != worker_id
            || payload.worker_id.as_uuid().is_nil()
            || payload.worker_session_id.is_nil()
            || payload.observer_session_id.is_nil()
            || payload.worker_generation == 0
            || payload.after_sequence > 9_007_199_254_740_991
            || payload.observation_epoch == 0
            || payload.observation_epoch > 9_007_199_254_740_991
            || payload.external_run_id.trim().is_empty()
            || !is_sha256_digest(&payload.work_order_digest)
        {
            return Err(Error::Validation(
                "Runmill observation payload is not bound to the configured worker and exact run authority"
                    .into(),
            ));
        }
        reject_sensitive_fields(&job.payload)?;
        Ok(payload)
    }

    fn fence(&self, job: &ClaimedWorkflowJob) -> Result<RunmillObservationFence> {
        let work_item_id = job.work_item_id.ok_or_else(|| {
            Error::Validation(format!(
                "Runmill observation job {} lacks its work-item binding",
                job.id
            ))
        })?;
        let attempt_id = job.attempt_id.ok_or_else(|| {
            Error::Validation(format!(
                "Runmill observation job {} lacks its attempt binding",
                job.id
            ))
        })?;
        Ok(RunmillObservationFence {
            tenant_id: job.tenant_id,
            run_id: self.run_id,
            work_item_id,
            attempt_id,
            work_order_id: self.work_order_id,
            work_order_digest: self.work_order_digest.clone(),
            workflow_job_id: job.id,
            workflow_job_fence_token: job.fence_token,
            workflow_job_attempt_count: job.attempt_count,
            workflow_job_owner: job.lease_owner.clone(),
            worker_session_id: self.worker_session_id,
            observer_session_id: self.observer_session_id,
            observation_id: self.observation_id,
            requested_after_sequence: i64::try_from(self.after_sequence).map_err(|_| {
                Error::Validation("Runmill observation cursor overflows bigint".into())
            })?,
            observation_epoch: i64::try_from(self.observation_epoch).map_err(|_| {
                Error::Validation("Runmill observation epoch overflows bigint".into())
            })?,
            worker_id: self.worker_id.as_uuid(),
            worker_generation: i64::try_from(self.worker_generation).map_err(|_| {
                Error::Validation("Runmill observation worker generation overflows bigint".into())
            })?,
            external_run_id: self.external_run_id.clone(),
        })
    }
}

fn validate_remote_binding(
    payload: &RunmillObservationPayload,
    tenant_id: TenantId,
    external_run_id: &RunmillRunId,
    attempt_id: Uuid,
    get_run: &IncomingRunmillControlSnapshot,
    event_page: &IncomingRunmillControlSnapshot,
) -> Result<RunmillEventPage> {
    let get_run =
        RunmillRunSnapshot::validate_provenance_data(&get_run.raw_snapshot).map_err(|_| {
            Error::Validation(
            "Runmill observation get-run response no longer satisfies the exact response contract"
                .into(),
        )
        })?;
    let event_page =
        RunmillEventPage::validate_provenance_data(&event_page.raw_snapshot).map_err(|_| {
            Error::Validation(
                "Runmill observation event page no longer satisfies the exact response contract"
                    .into(),
            )
        })?;
    event_page
        .validate_provenance_request(
            external_run_id,
            payload.after_sequence,
            RUNMILL_OBSERVATION_EVENT_LIMIT,
        )
        .map_err(|_| {
            Error::Validation(
                "Runmill observation event page contradicts its requested cursor or page limit"
                    .into(),
            )
        })?;
    let get_run_row = &get_run.run;
    let event_page_row = &event_page.snapshot.run;
    let expected_work_order_id = payload.work_order_id.to_string();
    let expected_attempt_id = attempt_id.to_string();
    if get_run_row.run_id.as_str() != external_run_id.as_str()
        || event_page_row.run_id.as_str() != external_run_id.as_str()
        || get_run_row.work_order_id != expected_work_order_id
        || event_page_row.work_order_id != expected_work_order_id
        || get_run_row.attempt_id != expected_attempt_id
        || event_page_row.attempt_id != expected_attempt_id
        || !event_page_snapshot_does_not_regress(
            get_run_row.generation,
            get_run_row.state_version,
            get_run.latest_sequence,
            event_page_row.generation,
            event_page_row.state_version,
            event_page.snapshot.latest_sequence,
        )
        || get_run.admission.work_order_id != expected_work_order_id
        || get_run.admission.attempt_id != expected_attempt_id
        || get_run.admission.tenant_id != tenant_id.to_string()
        || get_run.admission.payload_digest != payload.work_order_digest
    {
        return Err(Error::Validation(
            "validated Runmill control reads contradict the observation job authority".into(),
        ));
    }
    Ok(event_page)
}

/// The later event-page snapshot must never regress any authority-bearing
/// counter from the preceding get-run read.
fn event_page_snapshot_does_not_regress(
    get_run_generation: u64,
    get_run_state_version: u64,
    get_run_latest_sequence: u64,
    event_page_generation: u64,
    event_page_state_version: u64,
    event_page_latest_sequence: u64,
) -> bool {
    event_page_generation >= get_run_generation
        && event_page_state_version >= get_run_state_version
        && event_page_latest_sequence >= get_run_latest_sequence
}

fn completion_result(
    payload: &RunmillObservationPayload,
    get_run: &RunmillControlObservationOutcome,
    event_page: &RunmillControlObservationOutcome,
    page: &RunmillEventPage,
    disposition: &str,
) -> Result<Value> {
    let result = json!({
        "schema": "asf.runmill-observation-result/v2",
        "observation_id": payload.observation_id,
        "observation_epoch": payload.observation_epoch,
        "run_id": payload.run_id,
        "work_order_id": payload.work_order_id,
        "external_run_id": payload.external_run_id,
        "after_sequence": payload.after_sequence,
        "next_sequence": page.next_cursor,
        "has_more": page.has_more,
        "gap": page.gap,
        "compacted_through": page.compacted_through,
        "disposition": disposition,
        "get_run_snapshot_id": get_run.snapshot_id,
        "get_run_snapshot_semantic_digest": get_run.snapshot_semantic_digest,
        "event_page_snapshot_id": event_page.snapshot_id,
        "event_page_snapshot_semantic_digest": event_page.snapshot_semantic_digest,
        "event_count": page.events.len(),
    });
    reject_sensitive_fields(&result)?;
    Ok(result)
}

async fn persist_cursor_advance(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &RunmillObservationPayload,
    authority: &ObservationAuthority,
    get_run: &RunmillControlObservationOutcome,
    event_page: &RunmillControlObservationOutcome,
    page: &RunmillEventPage,
) -> Result<()> {
    let terminal_ready = !page.has_more
        && page.next_cursor == page.snapshot.latest_sequence
        && page.snapshot.run.state.terminal();
    let disposition = if terminal_ready {
        "TERMINAL_READY"
    } else {
        "ADVANCED"
    };
    insert_observation_result(
        transaction,
        job.tenant_id,
        payload,
        get_run.snapshot_id,
        event_page.snapshot_id,
        page,
        disposition,
    )
    .await?;
    let after_sequence = cursor_i64(payload.after_sequence, "requested cursor")?;
    let next_sequence = cursor_i64(page.next_cursor, "next cursor")?;
    let observation_epoch = cursor_i64(payload.observation_epoch, "observation epoch")?;
    let next_poll_delay = if page.has_more {
        0
    } else {
        RUNMILL_LIVE_POLL_DELAY_SECONDS
    };
    let state = if terminal_ready {
        "TERMINAL_READY"
    } else {
        "ACTIVE"
    };
    let changed = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE runmill_run_observation_streams AS stream
        SET next_after_sequence = $7,
            active_job_id = NULL,
            active_observation_id = NULL,
            state = $8,
            next_poll_at = clock_timestamp() + ($9::bigint * interval '1 second'),
            last_snapshot_id = $10,
            last_error_digest = NULL,
            aggregate_version = stream.aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE stream.tenant_id = $1
          AND stream.run_id = $2
          AND stream.active_job_id = $3
          AND stream.active_observation_id = $4
          AND stream.next_after_sequence = $5
          AND stream.observation_epoch = $6
          AND stream.state = 'ACTIVE'
          AND stream.aggregate_version = $11
        RETURNING stream.run_id
        ",
    )
    .bind(job.tenant_id)
    .bind(payload.run_id)
    .bind(job.id)
    .bind(payload.observation_id)
    .bind(after_sequence)
    .bind(observation_epoch)
    .bind(next_sequence)
    .bind(state)
    .bind(next_poll_delay)
    .bind(event_page.snapshot_id)
    .bind(authority.stream_aggregate_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("advance Runmill observation stream: {error}")))?;
    if changed != Some(payload.run_id) {
        return Err(Error::Conflict(format!(
            "Runmill observation stream {} changed before cursor advancement",
            payload.run_id
        )));
    }

    let result = completion_result(payload, get_run, event_page, page, disposition)?;
    complete_observation_job(transaction, job, &result).await
}

/// Preserve a valid compacted page, then terminally hand the exact stream to
/// owned operator attention. A compacted range is structural: later polling
/// cannot recover the missing events, so this branch never consumes retry
/// budget or silently advances the cursor.
async fn persist_gap_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &RunmillObservationPayload,
    authority: &ObservationAuthority,
    get_run: &RunmillControlObservationOutcome,
    event_page: &RunmillControlObservationOutcome,
    page: &RunmillEventPage,
) -> Result<()> {
    if !page.gap {
        return Err(Error::Validation(
            "Runmill gap escalation requires a gap=true event page".into(),
        ));
    }
    let compacted_through = page
        .compacted_through
        .ok_or_else(|| Error::Validation("Runmill gap event page lacks compactedThrough".into()))?;
    insert_observation_result(
        transaction,
        job.tenant_id,
        payload,
        get_run.snapshot_id,
        event_page.snapshot_id,
        page,
        "BLOCKED_GAP",
    )
    .await?;

    let workflow_instance_id = job.workflow_instance_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its workflow binding",
            job.id
        ))
    })?;
    let work_item_id = job.work_item_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its work-item binding",
            job.id
        ))
    })?;
    let attempt_id = job.attempt_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its attempt binding",
            job.id
        ))
    })?;
    let opened_at = Utc::now();
    let deadline = opened_at
        .checked_add_signed(TimeDelta::hours(4))
        .ok_or_else(|| Error::Validation("Runmill gap escalation deadline overflowed".into()))?;
    let error_summary = "Runmill event page reports an unrecoverable compacted cursor gap";
    let error_digest = sha256_digest(error_summary.as_bytes());
    let correlation_id = format!(
        "runmill-observation-gap:{}:{}",
        job.id, payload.observation_id
    );
    let failure = WorkflowStepFailure {
        fence: WorkflowStepFence {
            tenant_id: job.tenant_id,
            job_id: job.id,
            workflow_instance_id,
            work_item_id,
            lease_owner: job.lease_owner.clone(),
            job_fence_token: job.fence_token,
            expected_work_item_version: authority.work_item_version,
            expected_workflow_version: authority.workflow_version,
            expected_workflow_fence_token: authority.workflow_fence_token,
            expected_anchor_generation: authority.anchor_generation,
        },
        error_summary: error_summary.into(),
        // A forced terminal failure is never requeued. The wall-clock value is
        // still retained by the generic failure receipt for audit completeness.
        retry_at: opened_at,
        dead_letter: DeadLetterEscalation {
            id: Uuid::now_v7(),
            run_id: Some(payload.run_id),
            category: "WORKFLOW_JOB_EXHAUSTED".into(),
            severity: "HIGH".into(),
            reason: format!(
                "Runmill compacted required event history after cursor {} through {}.",
                payload.after_sequence, compacted_through
            ),
            owner_type: "ON_CALL".into(),
            owner_id: "platform-operations".into(),
            required_action: "reconcile the exact Runmill event gap from retained control provenance, then explicitly replace, cancel, or otherwise resolve the work item".into(),
            evidence_references: json!([
                format!("workflow-job:{}", job.id),
                format!("run:{}", payload.run_id),
                format!("runmill-observation:{}", payload.observation_id),
                format!("runmill-control-snapshot:{}", event_page.snapshot_id),
                event_page.snapshot_semantic_digest,
                format!("runmill-compacted-through:{compacted_through}"),
            ]),
            deadline,
            escalation_path: json!([
                {"owner_type": "ON_CALL", "owner_id": "platform-operations"},
                {"owner_type": "TEAM", "owner_id": "platform-engineering"},
            ]),
            retry_policy: json!({
                "automatic": false,
                "max_additional_attempts": 0,
                "backoff_seconds": 0,
                "prerequisites": [
                    "retained Runmill gap provenance inspected",
                    "operator reconciliation decision recorded",
                ],
            }),
            prerequisites: json!([
                "inspect compacted Runmill event range",
                "reconcile retained control snapshots",
            ]),
            authority_or_effect_active: true,
            idempotency_key: correlation_id.clone(),
            opened_at,
            audit_event: StepAuditEvent {
                id: Uuid::now_v7(),
                attempt_id: Some(attempt_id),
                actor_type: "SERVICE".into(),
                actor_id: job.lease_owner.clone(),
                action: "WORKFLOW_JOB_EXHAUSTED".into(),
                subject_type: "WORKFLOW_JOB".into(),
                subject_id: job.id.to_string(),
                correlation_id: correlation_id.clone(),
                trace_id: None,
                policy_digest: authority.policy_digest.clone(),
                before_digest: None,
                after_digest: None,
                details: json!({
                    "observation_id": payload.observation_id,
                    "observation_epoch": payload.observation_epoch,
                    "run_id": payload.run_id,
                    "after_sequence": payload.after_sequence,
                    "next_sequence": page.next_cursor,
                    "compacted_through": compacted_through,
                    "event_page_snapshot_id": event_page.snapshot_id,
                    "event_page_snapshot_semantic_digest": event_page.snapshot_semantic_digest,
                    "error_digest": error_digest,
                    "failure_kind": "RUNMILL_OBSERVATION_GAP",
                }),
                occurred_at: opened_at,
            },
            outbox_message: StepOutboxMessage {
                id: Uuid::now_v7(),
                topic: "attention".into(),
                message_key: work_item_id.to_string(),
                event_type: "workflow_job.exhausted".into(),
                payload: json!({
                    "run_id": payload.run_id,
                    "observation_id": payload.observation_id,
                    "after_sequence": payload.after_sequence,
                    "next_sequence": page.next_cursor,
                    "compacted_through": compacted_through,
                    "event_page_snapshot_id": event_page.snapshot_id,
                    "event_page_snapshot_semantic_digest": event_page.snapshot_semantic_digest,
                    "failure_kind": "RUNMILL_OBSERVATION_GAP",
                }),
                headers: json!({"schema": "asf.attention-event/v1"}),
                idempotency_key: format!("{correlation_id}:outbox"),
                available_at: opened_at,
            },
        },
    };
    let outcome =
        fail_workflow_step_with_prelocked_claim_force_terminal(transaction, &failure).await?;
    if outcome.disposition != WorkflowStepFailureDisposition::Escalated {
        return Err(Error::Persistence(format!(
            "Runmill observation gap job {} was not atomically escalated",
            job.id
        )));
    }
    let escalation_id = outcome.dead_letter_escalation_id.ok_or_else(|| {
        Error::Persistence(format!(
            "Runmill observation gap job {} has no effective escalation ID",
            job.id
        ))
    })?;
    bind_gap_to_effective_escalation(
        transaction,
        job.tenant_id,
        payload.run_id,
        payload.observation_id,
        job.id,
        escalation_id,
        event_page.snapshot_id,
    )
    .await?;
    let after_sequence = cursor_i64(payload.after_sequence, "requested cursor")?;
    let observation_epoch = cursor_i64(payload.observation_epoch, "observation epoch")?;
    let changed = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE runmill_run_observation_streams AS stream
        SET active_job_id = NULL,
            active_observation_id = NULL,
            state = 'ESCALATED',
            last_snapshot_id = $8,
            escalation_id = $9,
            last_error_digest = $10,
            aggregate_version = stream.aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE stream.tenant_id = $1
          AND stream.run_id = $2
          AND stream.active_job_id = $3
          AND stream.active_observation_id = $4
          AND stream.next_after_sequence = $5
          AND stream.observation_epoch = $6
          AND stream.state = 'ACTIVE'
          AND stream.aggregate_version = $7
        RETURNING stream.run_id
        ",
    )
    .bind(job.tenant_id)
    .bind(payload.run_id)
    .bind(job.id)
    .bind(payload.observation_id)
    .bind(after_sequence)
    .bind(observation_epoch)
    .bind(authority.stream_aggregate_version)
    .bind(event_page.snapshot_id)
    .bind(escalation_id)
    .bind(error_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("escalate Runmill observation stream: {error}")))?;
    if changed != Some(payload.run_id) {
        return Err(Error::Conflict(format!(
            "Runmill observation stream {} changed before gap escalation",
            payload.run_id
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn bind_gap_to_effective_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    run_id: Uuid,
    observation_id: Uuid,
    workflow_job_id: Uuid,
    escalation_id: Uuid,
    event_page_snapshot_id: Uuid,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO runmill_observation_gap_escalation_bindings (
            tenant_id, run_id, observation_id, workflow_job_id,
            escalation_id, event_page_snapshot_id
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (tenant_id, observation_id) DO NOTHING
        ",
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(observation_id)
    .bind(workflow_job_id)
    .bind(escalation_id)
    .bind(event_page_snapshot_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "bind Runmill observation gap to its effective escalation: {error}"
        ))
    })?;

    let retained = sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, Uuid)>(
        r"
        SELECT run_id, observation_id, workflow_job_id, escalation_id,
               event_page_snapshot_id
        FROM runmill_observation_gap_escalation_bindings
        WHERE tenant_id = $1
          AND observation_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(observation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!(
            "load Runmill observation gap escalation binding: {error}"
        ))
    })?;
    if retained
        != Some((
            run_id,
            observation_id,
            workflow_job_id,
            escalation_id,
            event_page_snapshot_id,
        ))
    {
        return Err(Error::Conflict(format!(
            "Runmill observation gap {observation_id} has a conflicting effective escalation binding"
        )));
    }
    Ok(())
}

async fn insert_observation_result(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    payload: &RunmillObservationPayload,
    get_run_snapshot_id: Uuid,
    event_page_snapshot_id: Uuid,
    page: &RunmillEventPage,
    disposition: &str,
) -> Result<Uuid> {
    let result_id = Uuid::now_v7();
    let after_sequence = cursor_i64(payload.after_sequence, "requested cursor")?;
    let next_sequence = cursor_i64(page.next_cursor, "next cursor")?;
    let compacted_through = page
        .compacted_through
        .map(|value| cursor_i64(value, "compacted-through cursor"))
        .transpose()?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO runmill_run_observation_results (
            id, tenant_id, run_id, observation_id, after_sequence,
            next_sequence, has_more, gap, compacted_through,
            get_run_snapshot_id, event_page_snapshot_id, disposition
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (tenant_id, observation_id) DO NOTHING
        RETURNING id
        ",
    )
    .bind(result_id)
    .bind(tenant_id)
    .bind(payload.run_id)
    .bind(payload.observation_id)
    .bind(after_sequence)
    .bind(next_sequence)
    .bind(page.has_more)
    .bind(page.gap)
    .bind(compacted_through)
    .bind(get_run_snapshot_id)
    .bind(event_page_snapshot_id)
    .bind(disposition)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("record Runmill observation result: {error}")))?;
    inserted.ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill observation {} already has a completion result",
            payload.observation_id
        ))
    })
}

fn cursor_i64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Validation(format!("Runmill {label} overflows bigint")))
}

async fn complete_observation_job(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    result: &Value,
) -> Result<()> {
    let changed = sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'COMPLETED',
            result = $5,
            completed_by = $3,
            completion_fence_token = $4,
            completed_at = clock_timestamp(),
            lease_owner = NULL,
            lease_expires_at = NULL,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'RUNNING'
          AND lease_owner = $3
          AND fence_token = $4
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .bind(result)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("complete Runmill observation job: {error}")))?
    .rows_affected();
    if changed != 1 {
        return Err(Error::Conflict(format!(
            "Runmill observation job {} lost its completion fence",
            job.id
        )));
    }
    Ok(())
}

fn control_failure(error: &RunmillControlError) -> Error {
    Error::ExternalUnavailable(format!("Runmill observation control failed: {error}"))
}

const EXACT_OBSERVATION_AUTHORITY_SQL: &str = r"
SELECT
    job.id,
    stream.aggregate_version AS stream_aggregate_version,
    work.aggregate_version AS work_item_version,
    workflow.aggregate_version AS workflow_version,
    workflow.fence_token AS workflow_fence_token,
    COALESCE(anchor.generation, 0) AS anchor_generation,
    work.policy_digest
FROM workflow_jobs AS job
JOIN runmill_run_observation_streams AS stream
  ON stream.tenant_id = job.tenant_id
 AND stream.run_id = $9::uuid
 AND stream.workflow_instance_id = job.workflow_instance_id
 AND stream.work_item_id = job.work_item_id
 AND stream.attempt_id = job.attempt_id
 AND stream.work_order_id = $10::uuid
 AND stream.work_order_digest = $11
 AND stream.worker_id = $12::uuid
 AND stream.run_admission_worker_session_id = $13::uuid
 AND stream.worker_generation = $14::bigint
 AND stream.external_run_id = $15
 AND stream.active_observation_id = $16::uuid
 AND stream.next_after_sequence = $17::bigint
 AND stream.observation_epoch = $18::bigint
 AND stream.active_job_id = job.id
 AND stream.state = 'ACTIVE'
JOIN runmill_run_observation_checkpoints AS checkpoint
  ON checkpoint.tenant_id = stream.tenant_id
 AND checkpoint.id = stream.active_observation_id
 AND checkpoint.run_id = stream.run_id
 AND checkpoint.workflow_job_id = job.id
 AND checkpoint.after_sequence = stream.next_after_sequence
 AND checkpoint.observation_epoch = stream.observation_epoch
 AND checkpoint.observer_session_id = $19::uuid
 AND checkpoint.worker_id = stream.worker_id
 AND checkpoint.worker_generation = stream.worker_generation
JOIN workflow_instances AS workflow
  ON workflow.tenant_id = job.tenant_id
 AND workflow.id = job.workflow_instance_id
 AND workflow.work_item_id = job.work_item_id
 AND workflow.state IN ('ACTIVE', 'WAITING')
JOIN work_items AS work
  ON work.tenant_id = job.tenant_id
 AND work.id = job.work_item_id
 AND work.current_attempt_id = job.attempt_id
 AND work.accepted_at IS NOT NULL
 AND work.state NOT IN ('CLOSED', 'CANCELLED')
LEFT JOIN accountability_anchors AS anchor
  ON anchor.tenant_id = work.tenant_id
 AND anchor.work_item_id = work.id
JOIN attempts AS attempt
  ON attempt.tenant_id = job.tenant_id
 AND attempt.id = job.attempt_id
 AND attempt.work_item_id = job.work_item_id
JOIN runs AS run
  ON run.tenant_id = job.tenant_id
 AND run.id = $9::uuid
 AND run.work_item_id = job.work_item_id
 AND run.attempt_id = job.attempt_id
 AND run.work_order_id = $10::uuid
 AND run.worker_id = $12::uuid
 AND run.worker_session_id = $13::uuid
 AND run.worker_generation = $14::bigint
 AND run.external_run_id = $15
 AND run.authoritative
JOIN work_orders AS work_order
  ON work_order.tenant_id = run.tenant_id
 AND work_order.id = run.work_order_id
 AND work_order.work_item_id = job.work_item_id
 AND work_order.attempt_id = job.attempt_id
 AND work_order.payload_digest = $11
 AND attempt.work_order_digest = work_order.payload_digest
JOIN workers AS worker
  ON worker.tenant_id = run.tenant_id
 AND worker.id = run.worker_id
 AND worker.id = $12::uuid
 AND worker.generation = $14::bigint
 AND worker.status <> 'QUARANTINED'
JOIN worker_sessions AS observer_session
  ON observer_session.tenant_id = run.tenant_id
 AND observer_session.id = $19::uuid
 AND observer_session.worker_id = run.worker_id
 AND observer_session.worker_generation = run.worker_generation
 AND observer_session.status = 'ACTIVE'
 AND observer_session.expires_at > clock_timestamp()
WHERE job.tenant_id = $1
  AND job.id = $2
  AND job.workflow_instance_id = $3
  AND job.work_item_id = $4
  AND job.attempt_id = $5
  AND job.job_type = 'OBSERVE_RUNMILL_RUN'
  AND job.activity_contract_id = $21
  AND job.status = 'RUNNING'
  AND job.lease_owner = $6
  AND job.fence_token = $7
  AND job.attempt_count = $8
  AND job.lease_expires_at > clock_timestamp()
  AND job.payload = $20::jsonb
";

#[derive(Debug, Clone)]
struct ObservationAuthority {
    stream_aggregate_version: i64,
    work_item_version: i64,
    workflow_version: i64,
    workflow_fence_token: i64,
    anchor_generation: i64,
    policy_digest: Option<String>,
}

async fn assert_exact_observation_authority<'executor, Executor>(
    executor: Executor,
    job: &ClaimedWorkflowJob,
    payload: &RunmillObservationPayload,
    lock: bool,
) -> Result<ObservationAuthority>
where
    Executor: sqlx::Executor<'executor, Database = Postgres>,
{
    let workflow_instance_id = job.workflow_instance_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its workflow binding",
            job.id
        ))
    })?;
    let work_item_id = job.work_item_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its work-item binding",
            job.id
        ))
    })?;
    let attempt_id = job.attempt_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill observation job {} lacks its attempt binding",
            job.id
        ))
    })?;
    let worker_generation = i64::try_from(payload.worker_generation).map_err(|_| {
        Error::Validation("Runmill observation worker generation overflows bigint".into())
    })?;
    let after_sequence = cursor_i64(payload.after_sequence, "requested cursor")?;
    let observation_epoch = cursor_i64(payload.observation_epoch, "observation epoch")?;
    let sql = if lock {
        format!("{EXACT_OBSERVATION_AUTHORITY_SQL} FOR UPDATE OF job, stream")
    } else {
        EXACT_OBSERVATION_AUTHORITY_SQL.into()
    };
    let found = sqlx::query(&sql)
        .bind(job.tenant_id)
        .bind(job.id)
        .bind(workflow_instance_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(&job.lease_owner)
        .bind(job.fence_token)
        .bind(job.attempt_count)
        .bind(payload.run_id)
        .bind(payload.work_order_id)
        .bind(&payload.work_order_digest)
        .bind(payload.worker_id.as_uuid())
        .bind(payload.worker_session_id)
        .bind(worker_generation)
        .bind(&payload.external_run_id)
        .bind(payload.observation_id)
        .bind(after_sequence)
        .bind(observation_epoch)
        .bind(payload.observer_session_id)
        .bind(&job.payload)
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .fetch_optional(executor)
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "prove exact Runmill observation authority: {error}"
            ))
        })?;
    let row = found.ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill observation job {} lacks its exact live authoritative run binding",
            job.id
        ))
    })?;
    let found_job_id: Uuid = authority_column(&row, "id", "job ID")?;
    if found_job_id != job.id {
        return Err(Error::Conflict(format!(
            "Runmill observation authority returned a foreign job for {}",
            job.id
        )));
    }
    Ok(ObservationAuthority {
        stream_aggregate_version: authority_column(
            &row,
            "stream_aggregate_version",
            "stream version",
        )?,
        work_item_version: authority_column(&row, "work_item_version", "work-item version")?,
        workflow_version: authority_column(&row, "workflow_version", "workflow version")?,
        workflow_fence_token: authority_column(&row, "workflow_fence_token", "workflow fence")?,
        anchor_generation: authority_column(&row, "anchor_generation", "anchor generation")?,
        policy_digest: row.try_get("policy_digest").map_err(|error| {
            Error::Persistence(format!("decode observation policy digest: {error}"))
        })?,
    })
}

fn authority_column<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!("decode Runmill observation {description}: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration as StdDuration,
    };

    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use url::Url;

    use super::*;
    use crate::{
        crypto::sha256_digest,
        ledger::{
            IncomingRunmillControlEvent, RunmillAdmissionProvenance, RunmillControlOperation,
            RunmillObservationProductionReport, produce_due_runmill_observation_jobs,
        },
        runtime::{HandlerRegistry, ReactorOptions, ReactorPollReport, ReactorRuntime},
    };

    type StoredSnapshotRow = (Uuid, i64, String, Vec<u8>, Value, Uuid, i64, i32, String);
    type EscalatedStreamRow = (
        String,
        i64,
        i64,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
    );
    type RetriedJobRow = (
        String,
        i32,
        i64,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<String>,
    );

    struct ScopedDatabase {
        ledger: PgLedger,
        admin: PgPool,
        schema: String,
    }

    impl ScopedDatabase {
        async fn create(database_url: &str) -> Self {
            let admin = PgPool::connect(database_url)
                .await
                .expect("connect Runmill observation reactor test administrator");
            let schema = format!("asf_runmill_observer_reactor_{}", Uuid::now_v7().simple());
            assert!(
                schema
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            );
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated Runmill observation reactor schema");
            let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated Runmill observation reactor ledger");
            ledger
                .migrate()
                .await
                .expect("migrate isolated Runmill observation reactor schema");
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
                .expect("drop isolated Runmill observation reactor schema");
            self.admin.close().await;
        }
    }

    #[derive(Debug)]
    struct FakeObservationControl {
        expected_run_id: String,
        expected_after_sequence: u64,
        response: std::result::Result<RunmillObservationBatch, String>,
        invocations: AtomicUsize,
    }

    impl FakeObservationControl {
        fn success(
            expected_run_id: String,
            expected_after_sequence: u64,
            response: RunmillObservationBatch,
        ) -> Self {
            Self {
                expected_run_id,
                expected_after_sequence,
                response: Ok(response),
                invocations: AtomicUsize::new(0),
            }
        }

        fn failure(
            expected_run_id: String,
            expected_after_sequence: u64,
            error: impl Into<String>,
        ) -> Self {
            Self {
                expected_run_id,
                expected_after_sequence,
                response: Err(error.into()),
                invocations: AtomicUsize::new(0),
            }
        }

        fn invocations(&self) -> usize {
            self.invocations.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl RunmillObservationControl for FakeObservationControl {
        async fn observe_run(
            &self,
            run_id: &RunmillRunId,
            after_sequence: u64,
        ) -> Result<RunmillObservationBatch> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            if run_id.as_str() != self.expected_run_id {
                return Err(Error::Validation(format!(
                    "observer requested unexpected Runmill run ID {run_id}"
                )));
            }
            if after_sequence != self.expected_after_sequence {
                return Err(Error::Validation(format!(
                    "observer requested cursor {after_sequence}, expected {}",
                    self.expected_after_sequence
                )));
            }
            self.response.clone().map_err(Error::ExternalUnavailable)
        }
    }

    /// A control seam that commits exactly one database-valid control
    /// snapshot against the exact claim coordinates a job holds on its first
    /// live, fenced attempt, then fails every call — including that first one
    /// — the same deterministic way. This proves that a stream which already
    /// retained control evidence for its dead observation must never be
    /// auto-escalated by the terminal-failure reconciler, unlike a genuinely
    /// clean exhaustion.
    #[derive(Debug)]
    struct PoisonedObservationControl {
        ledger: PgLedger,
        fixture: Arc<LiveObservationFixture>,
        failure_message: String,
        poisoned: AtomicBool,
        invocations: AtomicUsize,
    }

    impl PoisonedObservationControl {
        fn new(
            ledger: PgLedger,
            fixture: Arc<LiveObservationFixture>,
            failure_message: impl Into<String>,
        ) -> Self {
            Self {
                ledger,
                fixture,
                failure_message: failure_message.into(),
                poisoned: AtomicBool::new(false),
                invocations: AtomicUsize::new(0),
            }
        }

        fn invocations(&self) -> usize {
            self.invocations.load(Ordering::SeqCst)
        }

        /// Reuse the exact production ledger entrypoint and fence type to
        /// retain one legitimate get-run snapshot while the job is still
        /// legitimately RUNNING and fenced under its current claim. The claim
        /// coordinates are read fresh from `workflow_jobs` rather than
        /// assumed, since a retried job's fence token and attempt count are
        /// only known once it has actually been claimed.
        async fn record_one_poison_snapshot(&self) -> Result<()> {
            let (fence_token, attempt_count, lease_owner): (i64, i32, String) = sqlx::query_as(
                "SELECT fence_token, attempt_count, lease_owner FROM workflow_jobs WHERE tenant_id = $1 AND id = $2 AND status = 'RUNNING'",
            )
            .bind(self.fixture.tenant_id)
            .bind(self.fixture.job_id)
            .fetch_one(self.ledger.pool())
            .await
            .map_err(|error| {
                Error::Persistence(format!(
                    "load the current live Runmill observation claim coordinates: {error}"
                ))
            })?;
            let fence = RunmillObservationFence {
                tenant_id: self.fixture.tenant_id,
                run_id: self.fixture.run_id,
                work_item_id: self.fixture.work_item_id,
                attempt_id: self.fixture.attempt_id,
                work_order_id: self.fixture.work_order_id,
                work_order_digest: self.fixture.work_order_digest.clone(),
                workflow_job_id: self.fixture.job_id,
                workflow_job_fence_token: fence_token,
                workflow_job_attempt_count: attempt_count,
                workflow_job_owner: lease_owner,
                worker_session_id: self.fixture.worker_session_id,
                observer_session_id: self.fixture.worker_session_id,
                observation_id: self.fixture.observation_id,
                requested_after_sequence: 0,
                observation_epoch: 1,
                worker_id: self.fixture.worker_id.as_uuid(),
                worker_generation: 3,
                external_run_id: self.fixture.external_run_id.clone(),
            };
            let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
                Error::Persistence(format!(
                    "begin the poisoned Runmill observation snapshot transaction: {error}"
                ))
            })?;
            record_runmill_control_observation(
                &mut transaction,
                &fence,
                &self.fixture.get_run_snapshot(),
            )
            .await?;
            transaction.commit().await.map_err(|error| {
                Error::Persistence(format!(
                    "commit the poisoned Runmill observation snapshot: {error}"
                ))
            })
        }
    }

    #[async_trait]
    impl RunmillObservationControl for PoisonedObservationControl {
        async fn observe_run(
            &self,
            run_id: &RunmillRunId,
            after_sequence: u64,
        ) -> Result<RunmillObservationBatch> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            if run_id.as_str() != self.fixture.external_run_id || after_sequence != 0 {
                return Err(Error::Validation(format!(
                    "poisoned observer requested unexpected Runmill run coordinates for {run_id}"
                )));
            }
            if !self.poisoned.swap(true, Ordering::SeqCst) {
                self.record_one_poison_snapshot().await?;
            }
            Err(Error::ExternalUnavailable(self.failure_message.clone()))
        }
    }

    /// Whether `LiveObservationFixture::insert_stream` also inserts the
    /// immutable observation checkpoint and activates the stream's
    /// `active_job_id`/`active_observation_id` pointers, or leaves the freshly
    /// inserted stream idle and the job PENDING for a caller-driven claim or
    /// checkpoint step.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StreamActivation {
        ActivateWithCheckpoint,
        LeaveIdle,
    }

    #[derive(Debug)]
    struct LiveObservationFixture {
        tenant_id: Uuid,
        work_item_id: Uuid,
        workflow_instance_id: Uuid,
        attempt_id: Uuid,
        work_order_id: Uuid,
        work_order_digest: String,
        policy_digest: String,
        envelope_digest: String,
        worker_id: WorkerId,
        worker_session_id: Uuid,
        run_id: Uuid,
        external_run_id: String,
        observation_id: Uuid,
        job_id: Uuid,
        occurred_at: DateTime<Utc>,
    }

    impl LiveObservationFixture {
        async fn insert(ledger: &PgLedger) -> Self {
            Self::insert_stream(
                ledger,
                None,
                OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
                StreamActivation::ActivateWithCheckpoint,
            )
            .await
        }

        /// Insert a second, fully independent run and observation stream inside
        /// an existing fixture's tenant. Only the tenant row and its policy
        /// version are shared, so each stream keeps its own work item, attempt,
        /// Work Order, worker, live observer session, job, and checkpoint. That
        /// is what makes tenant-wide producer isolation provable.
        async fn insert_sibling(ledger: &PgLedger, shared: &Self) -> Self {
            Self::insert_stream(
                ledger,
                Some(shared),
                OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
                StreamActivation::ActivateWithCheckpoint,
            )
            .await
        }

        /// Insert the complete idle stream and PENDING `OBSERVE_RUNMILL_RUN`
        /// job with caller-supplied `persisted_activity_contract_id`, without
        /// inserting the observation checkpoint or activating the stream's
        /// `active_job_id`/`active_observation_id` pointers. Callers that need
        /// to drive their own claim or checkpoint step against a still-idle
        /// stream -- including ones that must remain idle so migration 0024's
        /// checkpoint trigger can be exercised directly -- start from here
        /// instead of the fully activated `insert_stream` path.
        async fn insert_idle(ledger: &PgLedger, persisted_activity_contract_id: &str) -> Self {
            Self::insert_stream(
                ledger,
                None,
                persisted_activity_contract_id,
                StreamActivation::LeaveIdle,
            )
            .await
        }

        /// Insert a fully bound observation job that is persisted as RUNNING
        /// and already claimed by `lease_owner`, but whose `activity_contract_id`
        /// is `persisted_activity_contract_id` from its initial INSERT --
        /// migration 0023's immutability trigger rejects any later UPDATE of
        /// that column, so a wrong-contract owning row can only ever be born
        /// wrong, never corrupted after the fact. The claim UPDATE below only
        /// touches `status`/`lease_owner`/`fence_token`/`attempt_count`/`lease_expires_at`,
        /// none of which are part of the guarded identity tuple, so it is a
        /// legitimate ordinary claim transition, not a mutation of the forged
        /// contract. The underlying stream starts and stays idle: since
        /// migration 0024, its checkpoint trigger requires the exact canonical
        /// activity contract, so a born-wrong-contract job can never legitimately
        /// acquire a checkpoint or an activated stream in the first place.
        async fn insert_claimed_with_wrong_persisted_contract(
            ledger: &PgLedger,
            persisted_activity_contract_id: &str,
            lease_owner: &str,
        ) -> Self {
            let fixture = Self::insert_idle(ledger, persisted_activity_contract_id).await;
            sqlx::query(
                r"
                UPDATE workflow_jobs
                SET status = 'RUNNING', lease_owner = $3, fence_token = 1, attempt_count = 1,
                    lease_expires_at = clock_timestamp() + interval '5 minutes'
                WHERE tenant_id = $1 AND id = $2
                ",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.job_id)
            .bind(lease_owner)
            .execute(ledger.pool())
            .await
            .expect("claim the born-wrong-contract observation job");
            fixture
        }

        async fn insert_stream(
            ledger: &PgLedger,
            shared: Option<&Self>,
            persisted_activity_contract_id: &str,
            activation: StreamActivation,
        ) -> Self {
            let fixture = Self {
                tenant_id: shared.map_or_else(Uuid::now_v7, |shared| shared.tenant_id),
                work_item_id: Uuid::now_v7(),
                workflow_instance_id: Uuid::now_v7(),
                attempt_id: Uuid::now_v7(),
                work_order_id: Uuid::now_v7(),
                // `work_orders` is unique on (tenant_id, payload_digest), so a
                // sibling inside the same tenant needs its own Work Order.
                work_order_digest: if shared.is_some() {
                    digest('f')
                } else {
                    digest('b')
                },
                policy_digest: shared
                    .map_or_else(|| digest('a'), |shared| shared.policy_digest.clone()),
                envelope_digest: sha256_digest(b"exact observer signed envelope"),
                worker_id: WorkerId::new(),
                worker_session_id: Uuid::now_v7(),
                run_id: Uuid::now_v7(),
                external_run_id: format!("run_{}", Uuid::now_v7().simple()),
                observation_id: Uuid::now_v7(),
                job_id: Uuid::now_v7(),
                occurred_at: Utc::now(),
            };
            let repository_id = Uuid::now_v7();
            let source_snapshot_id = Uuid::now_v7();
            let policy_id = Uuid::now_v7();
            let mut transaction = ledger
                .pool()
                .begin()
                .await
                .expect("begin Runmill observation reactor fixture");

            if shared.is_none() {
                sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
                    .bind(fixture.tenant_id)
                    .bind(format!("runmill-observer-reactor-{}", fixture.tenant_id))
                    .bind("Runmill observation reactor test")
                    .execute(&mut *transaction)
                    .await
                    .expect("insert observation reactor tenant");
                sqlx::query(
                    "INSERT INTO policy_versions (id, tenant_id, scope, schema_version, digest, canonical_bytes, policy, created_by) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')",
                )
                .bind(policy_id)
                .bind(fixture.tenant_id)
                .bind(&fixture.policy_digest)
                .bind(b"{}".as_slice())
                .execute(&mut *transaction)
                .await
                .expect("insert observation reactor policy");
            }
            sqlx::query(
                "INSERT INTO repositories (id, tenant_id, owner, name, repository_url, default_branch) VALUES ($1, $2, 'acme', $3, $4, 'main')",
            )
            .bind(repository_id)
            .bind(fixture.tenant_id)
            .bind(format!("repo-{}", repository_id.simple()))
            .bind(format!("https://example.invalid/{repository_id}"))
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor repository");
            sqlx::query(
                "INSERT INTO source_snapshots (id, tenant_id, repository_id, source_system, external_id, source_revision, normalized_content, content_digest, connector_identity, source_updated_at) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', $6)",
            )
            .bind(source_snapshot_id)
            .bind(fixture.tenant_id)
            .bind(repository_id)
            .bind(format!("item-{}", fixture.work_item_id))
            .bind(digest('c'))
            .bind(fixture.occurred_at)
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor source snapshot");
            sqlx::query(
                "INSERT INTO work_items (id, tenant_id, source_snapshot_id, source_system, source_external_id, repository_id, state, closure_target, risk_class, policy_digest, budget_limits, identity_requirements, owner_fallback, normalized_priority, discovered_at, accepted_at) VALUES ($1, $2, $3, 'API', $4, $5, 'RUNNING', 'pull_request', 'low', $6, $7, $8, 'team:platform', 50, $9, $9)",
            )
            .bind(fixture.work_item_id)
            .bind(fixture.tenant_id)
            .bind(source_snapshot_id)
            .bind(format!("item-{}", fixture.work_item_id))
            .bind(repository_id)
            .bind(&fixture.policy_digest)
            .bind(budget_limits())
            .bind(identity_requirements())
            .bind(fixture.occurred_at)
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor work item");
            sqlx::query(
                "INSERT INTO workflow_instances (id, tenant_id, work_item_id, workflow_type, reducer_version) VALUES ($1, $2, $3, 'RUNMILL_OBSERVATION_REACTOR_TEST', 'v1')",
            )
            .bind(fixture.workflow_instance_id)
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor workflow");
            sqlx::query(
                "INSERT INTO attempts (id, tenant_id, work_item_id, ordinal, state, idempotency_key, base_ref, base_sha, source_snapshot_digest, policy_digest) VALUES ($1, $2, $3, 1, 'AUTHORIZED', $4, 'main', $5, $6, $7)",
            )
            .bind(fixture.attempt_id)
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .bind(format!("attempt-{}", fixture.attempt_id))
            .bind("a".repeat(40))
            .bind(digest('d'))
            .bind(&fixture.policy_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor attempt");
            sqlx::query(
                "UPDATE work_items SET current_attempt_id = $3, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .bind(fixture.attempt_id)
            .execute(&mut *transaction)
            .await
            .expect("bind observation fixture work item to its active attempt");
            sqlx::query(
                "INSERT INTO work_orders (id, tenant_id, work_item_id, attempt_id, schema_version, envelope_schema, algorithm, key_id, idempotency_key, payload_digest, canonical_payload, payload, signature, exact_signed_envelope, issued_at, not_before, expires_at) VALUES ($1, $2, $3, $4, 'v1', 'envelope-v1', 'EdDSA', 'key-1', $5, $6, $7, '{}'::jsonb, 'signature', $8, $9, $9, $10)",
            )
            .bind(fixture.work_order_id)
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .bind(fixture.attempt_id)
            .bind(format!(
                "{}/{}/{}",
                fixture.tenant_id, fixture.work_item_id, fixture.attempt_id
            ))
            .bind(&fixture.work_order_digest)
            .bind(b"{}".as_slice())
            .bind(b"exact observer signed envelope".as_slice())
            .bind(fixture.occurred_at)
            .bind(fixture.occurred_at + Duration::hours(1))
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor Work Order");
            sqlx::query(
                "UPDATE attempts SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.attempt_id)
            .bind(&fixture.work_order_digest)
            .execute(&mut *transaction)
            .await
            .expect("bind observation reactor Work Order to attempt");
            sqlx::query(
                "INSERT INTO workers (id, tenant_id, name, endpoint, generation, signing_key_id, signing_public_key) VALUES ($1, $2, $3, $4, 3, 'key-1', 'public-key')",
            )
            .bind(fixture.worker_id.as_uuid())
            .bind(fixture.tenant_id)
            .bind(format!("worker-{}", fixture.worker_id))
            .bind(format!("local://{}", fixture.worker_id))
            .execute(&mut *transaction)
            .await
            .expect("insert observation reactor worker");
            sqlx::query(
                "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, expires_at) VALUES ($1, $2, $3, 3, $4)",
            )
            .bind(fixture.worker_session_id)
            .bind(fixture.tenant_id)
            .bind(fixture.worker_id.as_uuid())
            .bind(fixture.occurred_at + Duration::hours(1))
            .execute(&mut *transaction)
            .await
            .expect("insert active observation reactor worker session");
            sqlx::query(
                "INSERT INTO runs (id, tenant_id, work_item_id, attempt_id, work_order_id, worker_id, worker_generation, worker_session_id, evidence_expectation_digest, external_run_id, state) VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8, $9, 'ADOPTED')",
            )
            .bind(fixture.run_id)
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .bind(fixture.attempt_id)
            .bind(fixture.work_order_id)
            .bind(fixture.worker_id.as_uuid())
            .bind(fixture.worker_session_id)
            .bind(digest('e'))
            .bind(&fixture.external_run_id)
            .execute(&mut *transaction)
            .await
            .expect("insert authoritative observation reactor run");
            sqlx::query(
                "INSERT INTO accountability_anchors (tenant_id, work_item_id, anchor_type, reference_id, authority_or_effect_active) VALUES ($1, $2, 'RUN', $3, true)",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .bind(fixture.run_id)
            .execute(&mut *transaction)
            .await
            .expect("anchor observation reactor work to its authoritative run");
            sqlx::query(
                "INSERT INTO runmill_run_observation_streams (tenant_id, run_id, workflow_instance_id, work_item_id, attempt_id, work_order_id, work_order_digest, worker_id, worker_generation, run_admission_worker_session_id, external_run_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 3, $9, $10)",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .bind(fixture.workflow_instance_id)
            .bind(fixture.work_item_id)
            .bind(fixture.attempt_id)
            .bind(fixture.work_order_id)
            .bind(&fixture.work_order_digest)
            .bind(fixture.worker_id.as_uuid())
            .bind(fixture.worker_session_id)
            .bind(&fixture.external_run_id)
            .execute(&mut *transaction)
            .await
            .expect("insert idle durable Runmill observation stream");
            sqlx::query(
                "INSERT INTO workflow_jobs (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type, activity_contract_id, status, payload, idempotency_key, max_attempts) VALUES ($1, $2, $3, $4, $5, 'OBSERVE_RUNMILL_RUN', $6, 'PENDING', $7, $8, 3)",
            )
            .bind(fixture.job_id)
            .bind(fixture.tenant_id)
            .bind(fixture.workflow_instance_id)
            .bind(fixture.work_item_id)
            .bind(fixture.attempt_id)
            .bind(persisted_activity_contract_id)
            .bind(fixture.payload())
            .bind(format!("observe-reactor-{}", fixture.job_id))
            .execute(&mut *transaction)
            .await
            .expect("insert pending fully bound observation job");
            if activation == StreamActivation::ActivateWithCheckpoint {
                sqlx::query(
                    "INSERT INTO runmill_run_observation_checkpoints (id, tenant_id, run_id, workflow_job_id, after_sequence, observation_epoch, observer_session_id, worker_id, worker_generation) VALUES ($1, $2, $3, $4, 0, 1, $5, $6, 3)",
                )
                .bind(fixture.observation_id)
                .bind(fixture.tenant_id)
                .bind(fixture.run_id)
                .bind(fixture.job_id)
                .bind(fixture.worker_session_id)
                .bind(fixture.worker_id.as_uuid())
                .execute(&mut *transaction)
                .await
                .expect("insert immutable Runmill observation checkpoint");
                sqlx::query(
                    "UPDATE runmill_run_observation_streams SET observation_epoch = 1, active_job_id = $3, active_observation_id = $4, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND run_id = $2 AND aggregate_version = 1",
                )
                .bind(fixture.tenant_id)
                .bind(fixture.run_id)
                .bind(fixture.job_id)
                .bind(fixture.observation_id)
                .execute(&mut *transaction)
                .await
                .expect("activate durable Runmill observation checkpoint");
            }
            transaction
                .commit()
                .await
                .expect("commit Runmill observation reactor fixture");
            fixture
        }

        fn payload(&self) -> Value {
            json!({
                "schema": RUNMILL_OBSERVATION_PAYLOAD_SCHEMA_V2,
                "observation_id": self.observation_id.to_string(),
                "run_id": self.run_id.to_string(),
                "work_order_id": self.work_order_id.to_string(),
                "work_order_digest": self.work_order_digest,
                "worker_id": self.worker_id.to_string(),
                "worker_session_id": self.worker_session_id.to_string(),
                "observer_session_id": self.worker_session_id.to_string(),
                "worker_generation": 3,
                "external_run_id": self.external_run_id,
                "after_sequence": 0,
                "observation_epoch": 1,
            })
        }

        fn run_row(&self) -> Value {
            json!({
                "runId": self.external_run_id,
                "issueId": format!("item-{}", self.work_item_id),
                "repo": "acme/repository",
                "provider": "github",
                "state": "REPOSITORY_LEASED",
                "workOrderId": self.work_order_id.to_string(),
                "attemptId": self.attempt_id.to_string(),
                "generation": 3,
                "stateVersion": 2,
                "attempt": 1,
                "baseCommit": "a".repeat(40),
                "candidateSha": null,
                "branch": null,
                "mode": "asf-worker",
                "ownerId": null,
                "heartbeatAt": self.occurred_at.to_rfc3339(),
            })
        }

        fn get_run_snapshot(&self) -> IncomingRunmillControlSnapshot {
            let raw_snapshot = json!({
                "run": self.run_row(),
                "latestSequence": 2,
                "admission": {
                    "idempotencyKey": format!(
                        "{}/{}/{}",
                        self.tenant_id, self.work_item_id, self.attempt_id
                    ),
                    "workOrderId": self.work_order_id.to_string(),
                    "attemptId": self.attempt_id.to_string(),
                    "tenantId": self.tenant_id.to_string(),
                    "payloadDigest": self.work_order_digest,
                    "envelopeDigest": self.envelope_digest,
                    "effectivePolicyDigest": self.policy_digest,
                    "signatureKeyId": "key-1",
                    "signatureAlgorithm": "EdDSA",
                    "acceptedAt": self.occurred_at.to_rfc3339(),
                },
            });
            IncomingRunmillControlSnapshot {
                id: Uuid::now_v7(),
                control_sequence: 1,
                operation: RunmillControlOperation::GetRun,
                external_generation: 3,
                external_state_version: 2,
                external_latest_sequence: 2,
                observed_at: self.occurred_at,
                admission: Some(RunmillAdmissionProvenance {
                    idempotency_key: format!(
                        "{}/{}/{}",
                        self.tenant_id, self.work_item_id, self.attempt_id
                    ),
                    envelope_digest: self.envelope_digest.clone(),
                    effective_policy_digest: self.policy_digest.clone(),
                }),
                raw_response_bytes: successful_response_bytes(&raw_snapshot),
                raw_snapshot,
                events: Vec::new(),
            }
        }

        fn event(&self, suffix: &str, sequence: u64) -> IncomingRunmillControlEvent {
            let occurred_at = self.occurred_at
                + Duration::seconds(i64::try_from(sequence).expect("test event sequence fits i64"));
            let external_event_id = format!("{}-{suffix}", self.external_run_id);
            let raw_event = json!({
                "schema": "asf.run-event/v1",
                "event_id": external_event_id,
                "run_id": self.external_run_id,
                "work_order_id": self.work_order_id.to_string(),
                "attempt_id": self.attempt_id.to_string(),
                "seq": sequence,
                "type": "repository.lease_acquired",
                "phase": "REPOSITORY_LEASED",
                "occurred_at": occurred_at.to_rfc3339(),
                "policy_digest": self.policy_digest,
                "payload": {
                    "repository": "acme/repository",
                    "generation": 3,
                },
            });
            IncomingRunmillControlEvent {
                id: Uuid::now_v7(),
                external_event_id,
                sequence,
                event_type: "repository.lease_acquired".into(),
                occurred_at,
                raw_event,
            }
        }

        fn event_page_snapshot(
            &self,
            events: Vec<IncomingRunmillControlEvent>,
        ) -> IncomingRunmillControlSnapshot {
            let raw_events = events
                .iter()
                .map(|event| event.raw_event.clone())
                .collect::<Vec<_>>();
            let raw_snapshot = json!({
                "snapshot": {
                    "run": self.run_row(),
                    "latestSequence": 2,
                },
                "events": raw_events,
                "nextCursor": 2,
                "hasMore": false,
                "gap": false,
                "compactedThrough": null,
            });
            IncomingRunmillControlSnapshot {
                id: Uuid::now_v7(),
                control_sequence: 2,
                operation: RunmillControlOperation::ListRunEvents,
                external_generation: 3,
                external_state_version: 2,
                external_latest_sequence: 2,
                observed_at: self.occurred_at + Duration::seconds(1),
                admission: None,
                raw_response_bytes: successful_response_bytes(&raw_snapshot),
                raw_snapshot,
                events,
            }
        }

        fn observation_batch(&self) -> RunmillObservationBatch {
            RunmillObservationBatch {
                get_run: self.get_run_snapshot(),
                event_page: self
                    .event_page_snapshot(vec![self.event("one", 1), self.event("two", 2)]),
            }
        }

        fn terminal_observation_batch(&self) -> RunmillObservationBatch {
            let mut get_run = self.get_run_snapshot();
            get_run.raw_snapshot["run"]["state"] = json!("COMPLETED");
            get_run.raw_response_bytes = successful_response_bytes(&get_run.raw_snapshot);

            // At cursor two, the page is intentionally empty and reaches the
            // exact latest sequence. This is the smallest valid terminal page
            // for proving that a rotated observer session can finish a stream.
            let mut event_page = self.event_page_snapshot(Vec::new());
            event_page.raw_snapshot["snapshot"]["run"]["state"] = json!("COMPLETED");
            event_page.raw_response_bytes = successful_response_bytes(&event_page.raw_snapshot);

            RunmillObservationBatch {
                get_run,
                event_page,
            }
        }

        fn gap_observation_batch(&self) -> RunmillObservationBatch {
            let event = self.event("after-compaction", 2);
            let raw_snapshot = json!({
                "snapshot": {
                    "run": self.run_row(),
                    "latestSequence": 2,
                },
                "events": [event.raw_event.clone()],
                "nextCursor": 2,
                "hasMore": false,
                "gap": true,
                "compactedThrough": 1,
            });
            RunmillObservationBatch {
                get_run: self.get_run_snapshot(),
                event_page: IncomingRunmillControlSnapshot {
                    id: Uuid::now_v7(),
                    control_sequence: 2,
                    operation: RunmillControlOperation::ListRunEvents,
                    external_generation: 3,
                    external_state_version: 2,
                    external_latest_sequence: 2,
                    observed_at: self.occurred_at + Duration::seconds(1),
                    admission: None,
                    raw_response_bytes: successful_response_bytes(&raw_snapshot),
                    raw_snapshot,
                    events: vec![event],
                },
            }
        }
    }

    fn reactor_options(lease_owner: &str) -> ReactorOptions {
        ReactorOptions {
            lease_owner: lease_owner.into(),
            poll_interval: StdDuration::from_millis(10),
            lease_duration: StdDuration::from_secs(5),
            max_error_backoff: StdDuration::from_secs(1),
            claim_batch_size: 4,
        }
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn budget_limits() -> Value {
        json!({
            "max_cost_microunits": 1_000_000,
            "max_input_tokens": 100_000,
            "max_output_tokens": 100_000,
            "max_implementer_invocations": 2,
            "max_reviewer_invocations": 2,
            "max_fix_iterations": 1,
            "max_wall_time_seconds": 3_600,
            "max_external_api_calls": 10,
        })
    }

    fn identity_requirements() -> Value {
        json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "claude:pr-reviewer",
        })
    }

    fn successful_response_bytes(raw_snapshot: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"ok": true, "data": raw_snapshot}))
            .expect("serialize complete Runmill success envelope");
        bytes.push(b'\n');
        bytes
    }

    fn claimed_job(tenant_id: TenantId, worker_id: WorkerId) -> ClaimedWorkflowJob {
        let work_item_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        ClaimedWorkflowJob {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.as_uuid(),
            workflow_instance_id: Some(Uuid::now_v7()),
            work_item_id: Some(work_item_id),
            attempt_id: Some(attempt_id),
            job_type: OBSERVE_RUNMILL_RUN.into(),
            activity_contract_id: OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({
                "schema": RUNMILL_OBSERVATION_PAYLOAD_SCHEMA_V2,
                "observation_id": Uuid::now_v7(),
                "run_id": Uuid::now_v7(),
                "work_order_id": Uuid::now_v7(),
                "work_order_digest": format!("sha256:{}", "a".repeat(64)),
                "worker_id": worker_id,
                "worker_session_id": Uuid::now_v7(),
                "observer_session_id": Uuid::now_v7(),
                "worker_generation": 3,
                "external_run_id": "run_observation_test",
                "after_sequence": 0,
                "observation_epoch": 1,
            }),
            idempotency_key: "observe-test".into(),
            priority: 0,
            attempt_count: 1,
            max_attempts: 3,
            fence_token: 1,
            lease_owner: "test-observer".into(),
            lease_expires_at: Utc::now() + Duration::minutes(1),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn observation_payload_rejects_unknown_fields() {
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let mut job = claimed_job(tenant_id, worker_id);
        RunmillObservationPayload::parse(&job, tenant_id, worker_id)
            .expect("exact observation payload is accepted");

        job.payload["unexpected"] = json!(true);
        let error = RunmillObservationPayload::parse(&job, tenant_id, worker_id)
            .expect_err("unknown observation payload field is rejected");
        assert!(
            error
                .to_string()
                .contains("invalid Runmill observation payload")
        );
    }

    #[test]
    fn observation_payload_cannot_cross_configured_worker() {
        let tenant_id = TenantId::new();
        let mut job = claimed_job(tenant_id, WorkerId::new());
        let configured_worker = WorkerId::new();
        job.payload["worker_id"] = json!(configured_worker);

        let error = RunmillObservationPayload::parse(&job, tenant_id, WorkerId::new())
            .expect_err("worker-scoped observer rejects a foreign payload route");
        assert!(
            error
                .to_string()
                .contains("not bound to the configured worker")
        );
    }

    #[test]
    fn observation_payload_requires_a_positive_stream_epoch() {
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let mut job = claimed_job(tenant_id, worker_id);
        job.payload["observation_epoch"] = json!(0);
        assert!(RunmillObservationPayload::parse(&job, tenant_id, worker_id).is_err());
    }

    #[test]
    fn observation_payload_rejects_a_wrong_job_type_or_activity_contract() {
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();

        let mut wrong_job_type = claimed_job(tenant_id, worker_id);
        wrong_job_type.job_type = "SOME_OTHER_JOB".into();
        assert!(RunmillObservationPayload::parse(&wrong_job_type, tenant_id, worker_id).is_err());

        let mut wrong_contract = claimed_job(tenant_id, worker_id);
        wrong_contract.activity_contract_id = "asf.activity/observe-runmill-run/v3".into();
        let error = RunmillObservationPayload::parse(&wrong_contract, tenant_id, worker_id)
            .expect_err("a non-canonical activity contract must be rejected");
        assert!(matches!(error, Error::Validation(detail) if detail.contains("activity contract")));
    }

    #[tokio::test]
    async fn live_wrong_contract_claimed_job_is_rejected_before_any_control_call() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "control must never be called for a wrong-contract claimed job",
        ));
        let handler = RunmillObservationHandler::with_control(
            database.ledger.clone(),
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
            control.clone(),
        );
        let job = ClaimedWorkflowJob {
            id: fixture.job_id,
            tenant_id: fixture.tenant_id,
            workflow_instance_id: Some(fixture.workflow_instance_id),
            work_item_id: Some(fixture.work_item_id),
            attempt_id: Some(fixture.attempt_id),
            job_type: OBSERVE_RUNMILL_RUN.into(),
            activity_contract_id: "asf.activity/observe-runmill-run/v3".into(),
            payload: fixture.payload(),
            idempotency_key: format!("observe-reactor-{}", fixture.job_id),
            priority: 0,
            attempt_count: 1,
            max_attempts: 3,
            fence_token: 1,
            lease_owner: "test-observer".into(),
            lease_expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };
        let error = handler
            .execute(&job, ActivityControls::new(false))
            .await
            .expect_err("a wrong-contract claimed job must fail closed");
        assert!(matches!(error, Error::Validation(_)));
        assert_eq!(control.invocations(), 0);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_forged_wrong_contract_owning_row_cannot_satisfy_observation_authority_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let lease_owner = "test-observer-authority";
        // Persist the owning row as RUNNING and already claimed by
        // `lease_owner`, but with a wrong contract from its initial INSERT:
        // migration 0023's immutability trigger rejects any later UPDATE of
        // activity_contract_id, so the mismatch must be born with the row.
        // The in-memory claim stays canonical, so the SQL predicate, not the
        // caller-supplied struct, must decide authority. The underlying
        // stream itself is left idle -- no checkpoint, no active pointers --
        // since migration 0024's checkpoint trigger would itself reject a
        // checkpoint for this non-canonical contract; that boundary is
        // exercised separately by
        // `live_forged_wrong_contract_checkpoint_insert_is_rejected_by_the_exact_schedule_trigger`.
        let fixture = LiveObservationFixture::insert_claimed_with_wrong_persisted_contract(
            &database.ledger,
            "asf.activity/observe-runmill-run/v3",
            lease_owner,
        )
        .await;

        let job = ClaimedWorkflowJob {
            id: fixture.job_id,
            tenant_id: fixture.tenant_id,
            workflow_instance_id: Some(fixture.workflow_instance_id),
            work_item_id: Some(fixture.work_item_id),
            attempt_id: Some(fixture.attempt_id),
            job_type: OBSERVE_RUNMILL_RUN.into(),
            activity_contract_id: OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID.into(),
            payload: fixture.payload(),
            idempotency_key: format!("observe-reactor-{}", fixture.job_id),
            priority: 0,
            attempt_count: 1,
            max_attempts: 3,
            fence_token: 1,
            lease_owner: lease_owner.into(),
            lease_expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };
        let payload = RunmillObservationPayload::parse(
            &job,
            TenantId::from_uuid(fixture.tenant_id),
            fixture.worker_id,
        )
        .expect("the in-memory claim itself still carries the canonical contract");

        let result =
            assert_exact_observation_authority(database.ledger.pool(), &job, &payload, false).await;
        assert!(
            result.is_err(),
            "a persisted row with a non-canonical activity contract must never satisfy \
             Runmill observation authority, regardless of the caller's claimed contract"
        );
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_forged_wrong_contract_checkpoint_insert_is_rejected_by_the_exact_schedule_trigger()
     {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        // The fixture's PENDING job is born with a non-canonical
        // activity_contract_id and its stream is left idle: no checkpoint,
        // no active pointers. Neither the handler nor the Rust-side
        // authority query is invoked here -- only migration 0024's
        // asf_assert_runmill_observation_checkpoint_insert trigger stands
        // between this raw checkpoint INSERT and the exact idle-schedule
        // proof it demands, so a rejection proves the database trigger
        // itself.
        let fixture = LiveObservationFixture::insert_idle(
            &database.ledger,
            "asf.activity/observe-runmill-run/v3",
        )
        .await;

        let error = sqlx::query(
            r"
            INSERT INTO runmill_run_observation_checkpoints (id, tenant_id, run_id, workflow_job_id, after_sequence, observation_epoch, observer_session_id, worker_id, worker_generation) VALUES ($1, $2, $3, $4, 0, 1, $5, $6, 3)
            ",
        )
        .bind(fixture.observation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.job_id)
        .bind(fixture.worker_session_id)
        .bind(fixture.worker_id.as_uuid())
        .execute(database.ledger.pool())
        .await
        .expect_err(
            "a born-wrong-contract PENDING job must never satisfy the checkpoint's exact \
             idle-schedule trigger",
        );
        let database_error = error
            .as_database_error()
            .expect("checkpoint trigger rejection must be a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("runmill_observation_checkpoints_exact_schedule")
        );

        let checkpoint_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_run_observation_checkpoints WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count checkpoints after the rejected forged insert");
        assert_eq!(checkpoint_count, 0);

        let stream: (String, Option<Uuid>, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT state, active_job_id, active_observation_id, observation_epoch FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load stream after the rejected forged checkpoint insert");
        assert_eq!(stream, ("ACTIVE".into(), None, None, 0));

        database.cleanup().await;
    }

    #[test]
    fn observation_event_page_snapshot_cannot_regress_get_run_counters() {
        assert!(event_page_snapshot_does_not_regress(3, 2, 2, 3, 2, 2));
        assert!(!event_page_snapshot_does_not_regress(3, 2, 2, 2, 2, 2));
        assert!(!event_page_snapshot_does_not_regress(3, 2, 2, 3, 1, 2));
        assert!(!event_page_snapshot_does_not_regress(3, 2, 2, 3, 2, 1));
    }

    #[tokio::test]
    async fn live_reactor_observes_bound_runmill_snapshots_in_maintenance_mode() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let before_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run before observer reactor poll");
        let raw_run_events_before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count projected run events before observer reactor poll");

        let foreign_control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "foreign observer route must never issue a control read",
        ));
        let mut foreign_registry = HandlerRegistry::new();
        foreign_registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                WorkerId::new(),
                foreign_control.clone(),
            )))
            .expect("register foreign observation handler");
        let foreign_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            foreign_registry,
            reactor_options("reactor:foreign-runmill-observer"),
            true,
        )
        .expect("construct foreign observation reactor");
        assert_eq!(
            foreign_reactor
                .poll_once()
                .await
                .expect("foreign observation route remains unclaimed"),
            ReactorPollReport::default()
        );
        assert_eq!(
            foreign_control.invocations(),
            0,
            "a foreign configured worker must not invoke the private control"
        );
        let pending_after_foreign: (String, i32, i64) = sqlx::query_as(
            "SELECT status, attempt_count, fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load unclaimed observer job after foreign poll");
        assert_eq!(pending_after_foreign, ("PENDING".into(), 0, 0));

        let expected_observations = fixture.observation_batch();
        let primary_control = Arc::new(FakeObservationControl::success(
            fixture.external_run_id.clone(),
            0,
            expected_observations.clone(),
        ));
        let primary_owner = "reactor:authoritative-runmill-observer";
        let mut primary_registry = HandlerRegistry::new();
        primary_registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                primary_control.clone(),
            )))
            .expect("register authoritative observation handler");
        let primary_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            primary_registry,
            reactor_options(primary_owner),
            true,
        )
        .expect("construct maintenance-mode observation reactor");
        assert_eq!(
            primary_reactor
                .poll_once()
                .await
                .expect("claim and retain authoritative observation"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(
            primary_control.invocations(),
            1,
            "maintenance mode must not suppress read-only observation"
        );

        let completed: (String, i32, i64, Option<String>, Option<i64>, Option<Value>) =
            sqlx::query_as(
                "SELECT status, attempt_count, fence_token, completed_by, completion_fence_token, result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.job_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load completed observer job");
        assert_eq!(completed.0, "COMPLETED");
        assert_eq!(completed.1, 1);
        assert_eq!(completed.2, 1);
        assert_eq!(completed.3.as_deref(), Some(primary_owner));
        assert_eq!(completed.4, Some(1));
        let completion_result = completed.5.expect("observer completion result");
        assert_eq!(completion_result["event_count"], json!(2));
        assert_eq!(
            completion_result["get_run_snapshot_id"],
            json!(expected_observations.get_run.id)
        );
        assert_eq!(
            completion_result["event_page_snapshot_id"],
            json!(expected_observations.event_page.id)
        );

        let stream: (String, i64, Option<Uuid>, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT state, next_after_sequence, active_job_id, active_observation_id, aggregate_version FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load advanced durable observation stream");
        assert_eq!(stream, ("ACTIVE".into(), 2, None, None, 3));
        let observation_result: (String, i64, i64, bool) = sqlx::query_as(
            "SELECT disposition, after_sequence, next_sequence, gap FROM runmill_run_observation_results WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable normal observation result");
        assert_eq!(observation_result, ("ADVANCED".into(), 0, 2, false));

        let snapshots: Vec<StoredSnapshotRow> = sqlx::query_as(
                "SELECT id, control_sequence, control_operation, raw_response_bytes, raw_snapshot, workflow_job_id, workflow_job_fence_token, workflow_job_attempt_count, workflow_job_owner FROM runmill_control_snapshots WHERE tenant_id = $1 AND run_id = $2 ORDER BY control_sequence",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_all(database.ledger.pool())
            .await
            .expect("load exact retained control snapshots");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].0, expected_observations.get_run.id);
        assert_eq!(snapshots[0].1, 1);
        assert_eq!(snapshots[0].2, "GET_RUN");
        assert_eq!(
            snapshots[0].3,
            expected_observations.get_run.raw_response_bytes
        );
        assert_eq!(snapshots[0].4, expected_observations.get_run.raw_snapshot);
        assert_eq!(snapshots[1].0, expected_observations.event_page.id);
        assert_eq!(snapshots[1].1, 2);
        assert_eq!(snapshots[1].2, "LIST_RUN_EVENTS");
        assert_eq!(
            snapshots[1].3,
            expected_observations.event_page.raw_response_bytes
        );
        assert_eq!(
            snapshots[1].4,
            expected_observations.event_page.raw_snapshot
        );
        for snapshot in &snapshots {
            assert_eq!(snapshot.5, fixture.job_id);
            assert_eq!(snapshot.6, 1);
            assert_eq!(snapshot.7, 1);
            assert_eq!(snapshot.8, primary_owner);
        }

        let retained_events: Vec<(Uuid, String, i64, Value)> = sqlx::query_as(
            "SELECT id, external_event_id, event_sequence, raw_event FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2 ORDER BY event_sequence",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_all(database.ledger.pool())
        .await
        .expect("load exact retained control events");
        assert_eq!(retained_events.len(), 2);
        for (stored, expected) in retained_events
            .iter()
            .zip(expected_observations.event_page.events.iter())
        {
            assert_eq!(stored.0, expected.id);
            assert_eq!(stored.1, expected.external_event_id);
            assert_eq!(stored.2, i64::try_from(expected.sequence).unwrap());
            assert_eq!(stored.3, expected.raw_event);
        }
        let links: Vec<(Uuid, Uuid, i32)> = sqlx::query_as(
            "SELECT snapshot_id, event_id, page_ordinal FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND snapshot_id = $2 ORDER BY page_ordinal",
        )
        .bind(fixture.tenant_id)
        .bind(expected_observations.event_page.id)
        .fetch_all(database.ledger.pool())
        .await
        .expect("load exact retained snapshot-event links");
        assert_eq!(links.len(), 2);
        for (ordinal, (snapshot_id, event_id, page_ordinal)) in links.iter().enumerate() {
            assert_eq!(*snapshot_id, expected_observations.event_page.id);
            assert_eq!(
                *event_id,
                expected_observations.event_page.events[ordinal].id
            );
            assert_eq!(*page_ordinal, i32::try_from(ordinal).unwrap());
        }

        let raw_run_events_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count projected run events after observer reactor poll");
        assert_eq!(raw_run_events_after, raw_run_events_before);
        let after_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run after observer reactor poll");
        assert_eq!(after_run, before_run, "observer must not mutate runs");

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_reactor_produces_rotated_session_cursor_continuation_to_terminal_ready() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;

        let first_control = Arc::new(FakeObservationControl::success(
            fixture.external_run_id.clone(),
            0,
            fixture.observation_batch(),
        ));
        let mut first_registry = HandlerRegistry::new();
        first_registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                first_control.clone(),
            )))
            .expect("register initial observation handler");
        let first_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            first_registry,
            reactor_options("reactor:initial-session-observer"),
            true,
        )
        .expect("construct initial observation reactor");
        assert_eq!(
            first_reactor
                .poll_once()
                .await
                .expect("advance the initial observer page"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(first_control.invocations(), 1);

        let advanced: (String, i64, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT state, next_after_sequence, active_job_id, active_observation_id FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load cursor advanced by the initial observation");
        assert_eq!(advanced, ("ACTIVE".into(), 2, None, None));

        // Make the completed stream eligible immediately, then rotate only
        // the current control session. The run admission session must remain
        // the historical session that originally admitted the run.
        let made_due = sqlx::query(
            "UPDATE runmill_run_observation_streams SET next_poll_at = clock_timestamp(), aggregate_version = aggregate_version + 1 WHERE tenant_id = $1 AND run_id = $2 AND state = 'ACTIVE' AND active_job_id IS NULL AND active_observation_id IS NULL",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .execute(database.ledger.pool())
        .await
        .expect("make advanced observation stream due");
        assert_eq!(made_due.rows_affected(), 1);
        let closed = sqlx::query(
            "UPDATE worker_sessions SET status = 'CLOSED', closed_at = clock_timestamp(), close_reason = 'controller session rotation' WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.worker_session_id)
        .execute(database.ledger.pool())
        .await
        .expect("close the historic active controller session");
        assert_eq!(closed.rows_affected(), 1);
        let rotated_observer_session_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, expires_at) VALUES ($1, $2, $3, 3, $4)",
        )
        .bind(rotated_observer_session_id)
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id.as_uuid())
        .bind(Utc::now() + Duration::hours(1))
        .execute(database.ledger.pool())
        .await
        .expect("insert the rotated live same-generation observer session");

        let continuation_batch = fixture.terminal_observation_batch();
        let continuation_control = Arc::new(FakeObservationControl::success(
            fixture.external_run_id.clone(),
            2,
            continuation_batch.clone(),
        ));
        let mut continuation_registry = HandlerRegistry::new();
        continuation_registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                continuation_control.clone(),
            )))
            .expect("register rotated-session observation handler");
        let continuation_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            continuation_registry,
            reactor_options("reactor:rotated-session-observer"),
            true,
        )
        .expect("construct rotated-session observation reactor");
        assert_eq!(
            continuation_reactor
                .poll_once()
                .await
                .expect("produce, claim, and finish the rotated-session continuation"),
            ReactorPollReport {
                runmill_observation_jobs_produced: 1,
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(
            continuation_control.invocations(),
            1,
            "the continuation control must receive the retained cursor"
        );

        let continuation_job: (Uuid, String, i32, Value) = sqlx::query_as(
            "SELECT id, status, attempt_count, payload FROM workflow_jobs WHERE tenant_id = $1 AND job_type = 'OBSERVE_RUNMILL_RUN' AND id <> $2 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load producer-created continuation job");
        assert_eq!(continuation_job.1, "COMPLETED");
        assert_eq!(continuation_job.2, 1);
        let continuation_payload = &continuation_job.3;
        assert_eq!(
            continuation_payload.as_object().map(serde_json::Map::len),
            Some(12),
            "producer payload must remain exact V2 without extension fields"
        );
        assert_eq!(
            continuation_payload["schema"],
            json!(RUNMILL_OBSERVATION_PAYLOAD_SCHEMA_V2)
        );
        assert_eq!(continuation_payload["run_id"], json!(fixture.run_id));
        assert_eq!(
            continuation_payload["work_order_id"],
            json!(fixture.work_order_id)
        );
        assert_eq!(
            continuation_payload["worker_id"],
            json!(fixture.worker_id.as_uuid())
        );
        assert_eq!(
            continuation_payload["worker_session_id"],
            json!(fixture.worker_session_id),
            "run-admission provenance must not rotate"
        );
        assert_eq!(
            continuation_payload["observer_session_id"],
            json!(rotated_observer_session_id),
            "the new job must carry the new live observer session"
        );
        assert_eq!(continuation_payload["worker_generation"], json!(3));
        assert_eq!(continuation_payload["after_sequence"], json!(2));
        assert_eq!(continuation_payload["observation_epoch"], json!(2));
        let continuation_observation_id = Uuid::parse_str(
            continuation_payload["observation_id"]
                .as_str()
                .expect("continuation observation ID is a string"),
        )
        .expect("continuation observation ID is a UUID");

        let checkpoint: (Uuid, i64, i64, Uuid, Uuid, i64) = sqlx::query_as(
            "SELECT id, after_sequence, observation_epoch, observer_session_id, worker_id, worker_generation FROM runmill_run_observation_checkpoints WHERE tenant_id = $1 AND workflow_job_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(continuation_job.0)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable continuation checkpoint");
        assert_eq!(checkpoint.0, continuation_observation_id);
        assert_eq!(checkpoint.1, 2);
        assert_eq!(checkpoint.2, 2);
        assert_eq!(checkpoint.3, rotated_observer_session_id);
        assert_eq!(checkpoint.4, fixture.worker_id.as_uuid());
        assert_eq!(checkpoint.5, 3);

        let stamped_snapshots: Vec<(Uuid, Uuid, Uuid, i64, i64, String)> = sqlx::query_as(
            "SELECT run_admission_worker_session_id, observer_session_id, observation_id, requested_after_sequence, observation_epoch, control_operation FROM runmill_control_snapshots WHERE tenant_id = $1 AND workflow_job_id = $2 ORDER BY control_sequence",
        )
        .bind(fixture.tenant_id)
        .bind(continuation_job.0)
        .fetch_all(database.ledger.pool())
        .await
        .expect("load rotated-session control provenance");
        assert_eq!(stamped_snapshots.len(), 2);
        for (expected_operation, snapshot) in ["GET_RUN", "LIST_RUN_EVENTS"]
            .into_iter()
            .zip(stamped_snapshots)
        {
            assert_eq!(snapshot.0, fixture.worker_session_id);
            assert_eq!(snapshot.1, rotated_observer_session_id);
            assert_eq!(snapshot.2, continuation_observation_id);
            assert_eq!(snapshot.3, 2);
            assert_eq!(snapshot.4, 2);
            assert_eq!(snapshot.5, expected_operation);
        }

        let terminal_stream: (String, i64, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT state, next_after_sequence, active_job_id, active_observation_id FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal-ready stream after rotated continuation");
        assert_eq!(terminal_stream, ("TERMINAL_READY".into(), 2, None, None));
        let terminal_result: (String, i64, i64, bool) = sqlx::query_as(
            "SELECT disposition, after_sequence, next_sequence, has_more FROM runmill_run_observation_results WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(continuation_observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load terminal-ready immutable continuation result");
        assert_eq!(terminal_result, ("TERMINAL_READY".into(), 2, 2, false));
        assert_eq!(
            continuation_batch.get_run.id,
            sqlx::query_scalar::<_, Uuid>(
                "SELECT get_run_snapshot_id FROM runmill_run_observation_results WHERE tenant_id = $1 AND observation_id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(continuation_observation_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("retain terminal get-run provenance"),
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_database_rejects_terminal_ready_result_for_nonterminal_page() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let lease_owner = "test:forged-terminal-ready";
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin forged terminal-ready proof transaction");
        let claimed = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'RUNNING',
                attempt_count = 1,
                fence_token = 1,
                lease_owner = $3,
                lease_expires_at = clock_timestamp() + interval '5 minutes',
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND id = $2
              AND status = 'PENDING'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .bind(lease_owner)
        .execute(&mut *transaction)
        .await
        .expect("claim observation job for terminal-ready database guard test");
        assert_eq!(claimed.rows_affected(), 1);

        let fence = RunmillObservationFence {
            tenant_id: fixture.tenant_id,
            run_id: fixture.run_id,
            work_item_id: fixture.work_item_id,
            attempt_id: fixture.attempt_id,
            work_order_id: fixture.work_order_id,
            work_order_digest: fixture.work_order_digest.clone(),
            workflow_job_id: fixture.job_id,
            workflow_job_fence_token: 1,
            workflow_job_attempt_count: 1,
            workflow_job_owner: lease_owner.into(),
            worker_session_id: fixture.worker_session_id,
            observer_session_id: fixture.worker_session_id,
            observation_id: fixture.observation_id,
            requested_after_sequence: 0,
            observation_epoch: 1,
            worker_id: fixture.worker_id.as_uuid(),
            worker_generation: 3,
            external_run_id: fixture.external_run_id.clone(),
        };
        let observations = fixture.observation_batch();
        let get_run =
            record_runmill_control_observation(&mut transaction, &fence, &observations.get_run)
                .await
                .expect("retain exact get-run proof before forged terminal result");
        let event_page =
            record_runmill_control_observation(&mut transaction, &fence, &observations.event_page)
                .await
                .expect("retain exact nonterminal page before forged terminal result");

        sqlx::query("SAVEPOINT forged_terminal_ready")
            .execute(&mut *transaction)
            .await
            .expect("open forged terminal-ready savepoint");
        let error = sqlx::query(
            r"
            INSERT INTO runmill_run_observation_results (
                id, tenant_id, run_id, observation_id, after_sequence,
                next_sequence, has_more, gap, compacted_through,
                get_run_snapshot_id, event_page_snapshot_id, disposition
            ) VALUES ($1, $2, $3, $4, 0, 2, false, false, NULL, $5, $6, 'TERMINAL_READY')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.observation_id)
        .bind(get_run.snapshot_id)
        .bind(event_page.snapshot_id)
        .execute(&mut *transaction)
        .await
        .expect_err("database must reject a terminal-ready result for a nonterminal page");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runmill_observation_results_terminal_phase")
        );
        sqlx::query("ROLLBACK TO SAVEPOINT forged_terminal_ready")
            .execute(&mut *transaction)
            .await
            .expect("recover from rejected forged terminal-ready result");
        sqlx::query("RELEASE SAVEPOINT forged_terminal_ready")
            .execute(&mut *transaction)
            .await
            .expect("release forged terminal-ready savepoint");

        let retained_snapshot_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("count retained exact snapshots after forged result rejection");
        assert_eq!(retained_snapshot_count, 2);
        let result_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_run_observation_results WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("count rejected forged terminal-ready results");
        assert_eq!(result_count, 0);
        let stream: (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT state, active_job_id, active_observation_id FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("load stream after forged terminal-ready rejection");
        assert_eq!(
            stream,
            (
                "ACTIVE".into(),
                Some(fixture.job_id),
                Some(fixture.observation_id)
            )
        );

        transaction
            .rollback()
            .await
            .expect("rollback forged terminal-ready proof transaction");
        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_reactor_retains_gap_and_forces_owned_stream_escalation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let preexisting_escalation_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, attempt_id, category, severity,
                reason, owner_type, owner_id, required_action,
                evidence_references, deadline, retry_policy,
                authority_or_effect_active, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, 'WORKFLOW_JOB_EXHAUSTED', 'HIGH',
                'pre-existing shared exhaustion without a run binding',
                'ON_CALL', 'platform-operations',
                'reconcile the pre-existing exhausted workflow activity',
                '[]'::jsonb, $5,
                '{"automatic":false,"max_additional_attempts":0,"backoff_seconds":0,"prerequisites":[]}'::jsonb,
                true, $6
            )
            "#,
        )
        .bind(preexisting_escalation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(Utc::now() + Duration::hours(4))
        .bind(format!(
            "preexisting-runmill-gap-escalation-{preexisting_escalation_id}"
        ))
        .execute(database.ledger.pool())
        .await
        .expect("insert shared exhaustion escalation without a run binding");
        let expected_observations = fixture.gap_observation_batch();
        let control = Arc::new(FakeObservationControl::success(
            fixture.external_run_id.clone(),
            0,
            expected_observations.clone(),
        ));
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
            )))
            .expect("register gap observation handler");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            reactor_options("reactor:gap-runmill-observer"),
            true,
        )
        .expect("construct gap observation reactor");
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("retain and terminally escalate valid Runmill gap"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(control.invocations(), 1);

        let dead_job: (String, i32, Option<Uuid>) = sqlx::query_as(
            "SELECT status, attempt_count, dead_letter_escalation_id FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load force-dead-lettered gap observation job");
        assert_eq!(dead_job.0, "DEAD");
        assert_eq!(dead_job.1, 1, "gap handling must not consume retry budget");
        let escalation_id = dead_job
            .2
            .expect("forced gap dead-letter must retain its escalation identity");
        assert_eq!(
            escalation_id, preexisting_escalation_id,
            "gap handling must adopt the already-owned shared exhaustion"
        );

        let stream: (String, i64, Option<Uuid>, Option<Uuid>, Option<Uuid>, Uuid) =
            sqlx::query_as(
                "SELECT state, next_after_sequence, active_job_id, active_observation_id, escalation_id, last_snapshot_id FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load terminally escalated Runmill observation stream");
        assert_eq!(stream.0, "ESCALATED");
        assert_eq!(stream.1, 0, "gap must not advance the missing cursor");
        assert_eq!(stream.2, None);
        assert_eq!(stream.3, None);
        assert_eq!(stream.4, Some(escalation_id));
        assert_eq!(stream.5, expected_observations.event_page.id);

        let result: (String, bool, Option<i64>, Uuid, Uuid) = sqlx::query_as(
            "SELECT disposition, gap, compacted_through, get_run_snapshot_id, event_page_snapshot_id FROM runmill_run_observation_results WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable retained gap result");
        assert_eq!(result.0, "BLOCKED_GAP");
        assert!(result.1);
        assert_eq!(result.2, Some(1));
        assert_eq!(result.3, expected_observations.get_run.id);
        assert_eq!(result.4, expected_observations.event_page.id);

        let escalation: (Uuid, String, Option<Uuid>, String, String, Value) = sqlx::query_as(
            "SELECT id, category, run_id, status, severity, evidence_references FROM escalations WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(escalation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load owned gap escalation");
        assert_eq!(escalation.0, escalation_id);
        assert_eq!(escalation.1, "WORKFLOW_JOB_EXHAUSTED");
        assert_eq!(
            escalation.2, None,
            "a shared escalation must not be rebound to the later gap run"
        );
        assert_eq!(escalation.3, "OPEN");
        assert_eq!(escalation.4, "HIGH");
        let evidence = escalation
            .5
            .as_array()
            .expect("shared gap escalation evidence is an array");
        for expected_reference in [
            format!("workflow-job:{}", fixture.job_id),
            format!("run:{}", fixture.run_id),
            format!("runmill-observation:{}", fixture.observation_id),
            format!(
                "runmill-control-snapshot:{}",
                expected_observations.event_page.id
            ),
        ] {
            assert!(
                evidence
                    .iter()
                    .any(|reference| reference.as_str() == Some(&expected_reference)),
                "shared escalation lacks exact gap evidence {expected_reference}"
            );
        }

        let binding: (Uuid, Uuid, Uuid, Uuid, Uuid) = sqlx::query_as(
            "SELECT run_id, observation_id, workflow_job_id, escalation_id, event_page_snapshot_id FROM runmill_observation_gap_escalation_bindings WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable gap-to-shared-escalation binding");
        assert_eq!(
            binding,
            (
                fixture.run_id,
                fixture.observation_id,
                fixture.job_id,
                escalation_id,
                expected_observations.event_page.id,
            )
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_reactor_retries_control_failure_without_partial_observation_persistence() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let before_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run before failed observer poll");
        let raw_run_events_before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count projected events before failed observer poll");

        let control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "temporary exact control transport failure",
        ));
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
            )))
            .expect("register retrying observation handler");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            reactor_options("reactor:retrying-runmill-observer"),
            true,
        )
        .expect("construct retrying observation reactor");
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("retry failed observation control read"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_retried: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(control.invocations(), 1);

        let failed_job: RetriedJobRow = sqlx::query_as(
                "SELECT status, attempt_count, fence_token, lease_owner, lease_expires_at, last_error FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.job_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load retried observer job");
        assert_eq!(failed_job.0, "RETRY");
        assert_eq!(failed_job.1, 1);
        assert_eq!(failed_job.2, 1);
        assert!(failed_job.3.is_none());
        assert!(failed_job.4.is_none());
        assert!(
            failed_job
                .5
                .as_deref()
                .is_some_and(|error| error.contains("temporary exact control transport failure"))
        );
        let snapshot_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count snapshots after failed observation control read");
        let control_event_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count control events after failed observation control read");
        let link_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_control_snapshot_events WHERE tenant_id = $1",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count snapshot links after failed observation control read");
        assert_eq!(snapshot_count, 0);
        assert_eq!(control_event_count, 0);
        assert_eq!(link_count, 0);
        let raw_run_events_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count projected events after failed observer poll");
        assert_eq!(raw_run_events_after, raw_run_events_before);
        let after_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run after failed observer poll");
        assert_eq!(
            after_run, before_run,
            "failed observer must not mutate runs"
        );

        database.cleanup().await;
    }

    /// Drive the fixture's observer job through its whole retry budget with a
    /// permanently failing control, returning the effective escalation and the
    /// durable failure digest retained by its dead-letter receipt.
    async fn exhaust_observation_job(
        database: &ScopedDatabase,
        fixture: &LiveObservationFixture,
        lease_owner: &str,
    ) -> (Uuid, String) {
        let control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "permanent exact control transport failure",
        ));
        let exhausted =
            exhaust_observation_job_with_control(database, fixture, lease_owner, control.clone())
                .await;
        assert_eq!(control.invocations(), 3);
        exhausted
    }

    /// Same drive-to-exhaustion loop, but under a caller-supplied control seam
    /// so a test can commit its own evidence while the job is legitimately
    /// claimed and RUNNING.
    async fn exhaust_observation_job_with_control(
        database: &ScopedDatabase,
        fixture: &LiveObservationFixture,
        lease_owner: &str,
        control: Arc<dyn RunmillObservationControl>,
    ) -> (Uuid, String) {
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
            )))
            .expect("register exhausting observation handler");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            reactor_options(lease_owner),
            true,
        )
        .expect("construct exhausting observation reactor");

        for _ in 0..2 {
            assert_eq!(
                reactor
                    .poll_once()
                    .await
                    .expect("retry a nonfinal observation control failure"),
                ReactorPollReport {
                    jobs_claimed: 1,
                    jobs_retried: 1,
                    ..ReactorPollReport::default()
                },
                "an unexhausted observer must retry without releasing its stream"
            );
            sqlx::query(
                "UPDATE workflow_jobs SET available_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'RETRY'",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.job_id)
            .execute(database.ledger.pool())
            .await
            .expect("release deterministic observation retry backoff");
        }
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("dead-letter the final observation attempt"),
            ReactorPollReport {
                jobs_claimed: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            },
            "the exhausting poll must not also recover the stream it just killed"
        );

        let dead_job: (String, i32, Option<Uuid>, Option<Value>) = sqlx::query_as(
            "SELECT status, attempt_count, dead_letter_escalation_id, result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load exhausted observation job");
        assert_eq!(dead_job.0, "DEAD");
        assert_eq!(dead_job.1, 3);
        let escalation_id = dead_job
            .2
            .expect("an exhausted observer must retain its owned escalation");
        let failure_digest = dead_job
            .3
            .as_ref()
            .and_then(|result| result.get("error_digest"))
            .and_then(Value::as_str)
            .expect("an exhausted observer must retain its durable failure digest")
            .to_owned();

        let pinned: (String, i64, Option<Uuid>, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT state, next_after_sequence, active_job_id, active_observation_id, escalation_id FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load still-pinned stream immediately after dead-lettering");
        assert_eq!(
            pinned,
            (
                "ACTIVE".into(),
                0,
                Some(fixture.job_id),
                Some(fixture.observation_id),
                None,
            ),
            "the dead-letter commit alone must leave the stream pinned"
        );

        (escalation_id, failure_digest)
    }

    async fn assert_no_observation_evidence_was_invented(
        database: &ScopedDatabase,
        fixture: &LiveObservationFixture,
    ) {
        for (table, description) in [
            ("runmill_run_observation_results", "observation results"),
            ("runmill_control_snapshots", "control snapshots"),
        ] {
            let statement =
                format!("SELECT count(*) FROM {table} WHERE tenant_id = $1 AND run_id = $2");
            let count: i64 = sqlx::query_scalar(&statement)
                .bind(fixture.tenant_id)
                .bind(fixture.run_id)
                .fetch_one(database.ledger.pool())
                .await
                .unwrap_or_else(|error| panic!("count retained {description}: {error}"));
            assert_eq!(count, 0, "terminal-failure recovery invented {description}");
        }
        let projected: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count projected run events after terminal-failure recovery");
        assert_eq!(projected, 0);
    }

    async fn escalated_stream_row(
        database: &ScopedDatabase,
        fixture: &LiveObservationFixture,
    ) -> EscalatedStreamRow {
        sqlx::query_as(
            "SELECT state, next_after_sequence, observation_epoch, active_job_id, active_observation_id, escalation_id, last_snapshot_id, last_error_digest FROM runmill_run_observation_streams WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load recovered Runmill observation stream")
    }

    #[tokio::test]
    async fn live_exhausted_observer_is_reconciled_into_an_escalated_stream_after_restart() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let before_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run before exhausting observer polls");

        let (escalation_id, failure_digest) =
            exhaust_observation_job(&database, &fixture, "reactor:exhausting-runmill-observer")
                .await;

        // A restarted process must recover the pinned stream without ever
        // touching the private control socket.
        let recovery_control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "terminal-failure recovery must never issue a control read",
        ));
        let mut recovery_registry = HandlerRegistry::new();
        recovery_registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                recovery_control.clone(),
            )))
            .expect("register restarted observation handler");
        let recovery_reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            recovery_registry,
            reactor_options("reactor:restarted-runmill-observer"),
            true,
        )
        .expect("construct restarted observation reactor");
        assert_eq!(
            recovery_reactor
                .poll_once()
                .await
                .expect("recover the pinned dead observation stream"),
            ReactorPollReport {
                runmill_observation_streams_escalated: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(recovery_control.invocations(), 0);

        assert_eq!(
            escalated_stream_row(&database, &fixture).await,
            (
                "ESCALATED".into(),
                0,
                1,
                None,
                None,
                Some(escalation_id),
                None,
                Some(failure_digest.clone()),
            ),
            "recovery must release the pointers at the unchanged cursor without a snapshot"
        );

        let fact: (Uuid, Uuid, Uuid, Uuid, i64, i64, String) = sqlx::query_as(
            "SELECT run_id, observation_id, workflow_job_id, escalation_id, after_sequence, observation_epoch, failure_digest FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable terminal-failure fact");
        assert_eq!(
            fact,
            (
                fixture.run_id,
                fixture.observation_id,
                fixture.job_id,
                escalation_id,
                0,
                1,
                failure_digest.clone(),
            )
        );

        assert_no_observation_evidence_was_invented(&database, &fixture).await;
        let after_run: (String, Option<String>, Option<Value>, i64, i64, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT state, last_event_cursor, snapshot, last_event_sequence, aggregate_version, last_observed_at FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(fixture.run_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load run after terminal-failure recovery");
        assert_eq!(
            after_run, before_run,
            "terminal-failure recovery must not mutate runs"
        );

        // The recovery is bounded and idempotent: the stream is no longer a
        // candidate and no second fact or job appears.
        assert_eq!(
            recovery_reactor
                .poll_once()
                .await
                .expect("re-poll a recovered observation stream"),
            ReactorPollReport::default()
        );
        let fact_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count retained terminal-failure facts");
        assert_eq!(fact_count, 1);
        let job_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_jobs WHERE tenant_id = $1 AND job_type = 'OBSERVE_RUNMILL_RUN'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count observation jobs after recovery");
        assert_eq!(
            job_count, 1,
            "recovery must not schedule a replacement observer"
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_producer_recovers_a_preexisting_dead_pinned_stream_without_a_ready_route() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let (escalation_id, failure_digest) =
            exhaust_observation_job(&database, &fixture, "reactor:crashing-runmill-observer").await;

        // This is the crash window between the dead-letter commit and stream
        // recovery: the restarted process has no ready worker route yet, and
        // recovery must still complete because it needs no observer session.
        assert_eq!(
            produce_due_runmill_observation_jobs(
                database.ledger.pool(),
                fixture.tenant_id,
                &[],
                4,
            )
            .await
            .expect("reconcile a pinned dead stream without any ready worker route"),
            RunmillObservationProductionReport {
                dead_jobs_escalated: 1,
                jobs_enqueued: 0,
            }
        );
        assert_eq!(
            escalated_stream_row(&database, &fixture).await,
            (
                "ESCALATED".into(),
                0,
                1,
                None,
                None,
                Some(escalation_id),
                None,
                Some(failure_digest),
            )
        );
        assert_eq!(
            produce_due_runmill_observation_jobs(
                database.ledger.pool(),
                fixture.tenant_id,
                &[],
                4,
            )
            .await
            .expect("replay a completed stream recovery"),
            RunmillObservationProductionReport::default()
        );
        assert_no_observation_evidence_was_invented(&database, &fixture).await;

        database.cleanup().await;
    }

    /// A route-invalid observer *can* still name an admitted exact stream: the
    /// route predicate additionally requires a live current observer session,
    /// so a closed session rejects the job while the stream stays pinned.
    /// That is exactly the case the terminal-failure reconciler must cover.
    #[tokio::test]
    async fn live_route_invalid_observer_with_a_closed_session_still_recovers_its_stream() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        sqlx::query(
            "UPDATE worker_sessions SET status = 'CLOSED', closed_at = clock_timestamp(), close_reason = 'controller session rotation' WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.worker_session_id)
        .execute(database.ledger.pool())
        .await
        .expect("close the observer control session");

        let control = Arc::new(FakeObservationControl::failure(
            fixture.external_run_id.clone(),
            0,
            "route-invalid rejection must never issue a control read",
        ));
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(RunmillObservationHandler::with_control(
                database.ledger.clone(),
                TenantId::from_uuid(fixture.tenant_id),
                fixture.worker_id,
                control.clone(),
            )))
            .expect("register route-invalid observation handler");
        let reactor = ReactorRuntime::new(
            database.ledger.clone(),
            fixture.tenant_id,
            registry,
            reactor_options("reactor:route-invalid-runmill-observer"),
            true,
        )
        .expect("construct route-invalid observation reactor");
        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("reject the route-invalid observer without a daemon call"),
            ReactorPollReport {
                route_invalid_jobs_rejected: 1,
                jobs_transactionally_finalized: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(control.invocations(), 0);

        let dead_job: (String, Option<Uuid>, Option<Value>) = sqlx::query_as(
            "SELECT status, dead_letter_escalation_id, result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load route-invalid dead observation job");
        assert_eq!(dead_job.0, "DEAD");
        let escalation_id = dead_job.1.expect("route-invalid rejection stays owned");
        let failure_digest = dead_job
            .2
            .as_ref()
            .and_then(|result| result.get("error_digest"))
            .and_then(Value::as_str)
            .expect("route-invalid rejection retains a durable failure digest")
            .to_owned();

        assert_eq!(
            reactor
                .poll_once()
                .await
                .expect("recover the route-invalid observer stream"),
            ReactorPollReport {
                runmill_observation_streams_escalated: 1,
                ..ReactorPollReport::default()
            }
        );
        assert_eq!(
            escalated_stream_row(&database, &fixture).await,
            (
                "ESCALATED".into(),
                0,
                1,
                None,
                None,
                Some(escalation_id),
                None,
                Some(failure_digest),
            )
        );
        assert_no_observation_evidence_was_invented(&database, &fixture).await;

        database.cleanup().await;
    }

    /// The tenant-wide producer must isolate a stream whose dead observation
    /// retained legitimate control evidence from a clean sibling stream that
    /// retained none, escalating only the sibling in the very same pass.
    #[tokio::test]
    async fn live_database_isolates_poisoned_control_evidence_from_a_clean_sibling_escalation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let poisoned_fixture = Arc::new(LiveObservationFixture::insert(&database.ledger).await);
        let sibling_fixture =
            LiveObservationFixture::insert_sibling(&database.ledger, &poisoned_fixture).await;

        let poison_control = Arc::new(PoisonedObservationControl::new(
            database.ledger.clone(),
            poisoned_fixture.clone(),
            "deterministic poisoned Runmill observer failure",
        ));
        let (_poisoned_escalation_id, _poisoned_failure_digest) =
            exhaust_observation_job_with_control(
                &database,
                &poisoned_fixture,
                "reactor:database-poisoned-runmill-observer",
                poison_control.clone(),
            )
            .await;
        assert_eq!(
            poison_control.invocations(),
            3,
            "the poisoned control must still be consulted on every retried attempt"
        );

        let (sibling_escalation_id, sibling_failure_digest) = exhaust_observation_job(
            &database,
            &sibling_fixture,
            "reactor:database-clean-runmill-observer",
        )
        .await;

        assert_eq!(
            produce_due_runmill_observation_jobs(
                database.ledger.pool(),
                poisoned_fixture.tenant_id,
                &[],
                4,
            )
            .await
            .expect("recover only the clean sibling stream, isolating the poisoned one"),
            RunmillObservationProductionReport {
                dead_jobs_escalated: 1,
                jobs_enqueued: 0,
            }
        );

        // The poisoned stream retains control evidence for its dead
        // observation, so it must stay exactly where the dead-letter commit
        // left it: pinned ACTIVE at its original cursor, epoch, job, and
        // observation, with no stream escalation, last-snapshot pointer, or
        // error digest.
        assert_eq!(
            escalated_stream_row(&database, &poisoned_fixture).await,
            (
                "ACTIVE".into(),
                0,
                1,
                Some(poisoned_fixture.job_id),
                Some(poisoned_fixture.observation_id),
                None,
                None,
                None,
            ),
            "a stream with retained control evidence for its dead observation must stay pinned"
        );
        let poisoned_snapshot_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1 AND run_id = $2 AND observation_id = $3",
        )
        .bind(poisoned_fixture.tenant_id)
        .bind(poisoned_fixture.run_id)
        .bind(poisoned_fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count retained control snapshots for the poisoned observation");
        assert_eq!(
            poisoned_snapshot_count, 1,
            "the poison control must have committed exactly one control snapshot"
        );
        let poisoned_fact_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1 AND run_id = $2 AND observation_id = $3",
        )
        .bind(poisoned_fixture.tenant_id)
        .bind(poisoned_fixture.run_id)
        .bind(poisoned_fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count terminal-failure facts for the poisoned observation");
        assert_eq!(
            poisoned_fact_count, 0,
            "a poisoned dead observation must never gain a terminal-failure fact"
        );

        // The clean sibling, sharing only the tenant, must still escalate
        // normally with its own exact escalation and failure digest.
        assert_eq!(
            escalated_stream_row(&database, &sibling_fixture).await,
            (
                "ESCALATED".into(),
                0,
                1,
                None,
                None,
                Some(sibling_escalation_id),
                None,
                Some(sibling_failure_digest.clone()),
            ),
            "the clean sibling must still escalate in the same tenant-wide producer pass"
        );
        let sibling_fact: (Uuid, Uuid, Uuid, Uuid, i64, i64, String) = sqlx::query_as(
            "SELECT run_id, observation_id, workflow_job_id, escalation_id, after_sequence, observation_epoch, failure_digest FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1 AND run_id = $2 AND observation_id = $3",
        )
        .bind(sibling_fixture.tenant_id)
        .bind(sibling_fixture.run_id)
        .bind(sibling_fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load the sibling's immutable terminal-failure fact");
        assert_eq!(
            sibling_fact,
            (
                sibling_fixture.run_id,
                sibling_fixture.observation_id,
                sibling_fixture.job_id,
                sibling_escalation_id,
                0,
                1,
                sibling_failure_digest,
            )
        );
        let tenant_fact_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1",
        )
        .bind(poisoned_fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count terminal-failure facts across the tenant");
        assert_eq!(
            tenant_fact_count, 1,
            "only the clean sibling must gain a terminal-failure fact in this tenant"
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn live_database_rejects_forged_or_mutated_terminal_failure_facts() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let fixture = LiveObservationFixture::insert(&database.ledger).await;
        let forged_digest = sha256_digest(b"forged Runmill observer failure");

        // The active job is still PENDING, so no terminal-failure fact exists.
        let error = sqlx::query(
            r"
            INSERT INTO runmill_observation_terminal_failure_facts (
                tenant_id, run_id, observation_id, workflow_job_id,
                escalation_id, after_sequence, observation_epoch, failure_digest
            ) VALUES ($1, $2, $3, $4, $5, 0, 1, $6)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.observation_id)
        .bind(fixture.job_id)
        .bind(Uuid::now_v7())
        .bind(&forged_digest)
        .execute(database.ledger.pool())
        .await
        .expect_err("a live observer job must not be releasable as a terminal failure");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runmill_observation_terminal_failure_facts_exact_proof")
        );

        let (escalation_id, failure_digest) =
            exhaust_observation_job(&database, &fixture, "reactor:forgery-runmill-observer").await;

        // Even a genuinely dead job cannot be released under a digest that its
        // own durable dead-letter receipt does not carry.
        let error = sqlx::query(
            r"
            INSERT INTO runmill_observation_terminal_failure_facts (
                tenant_id, run_id, observation_id, workflow_job_id,
                escalation_id, after_sequence, observation_epoch, failure_digest
            ) VALUES ($1, $2, $3, $4, $5, 0, 1, $6)
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.observation_id)
        .bind(fixture.job_id)
        .bind(escalation_id)
        .bind(&forged_digest)
        .execute(database.ledger.pool())
        .await
        .expect_err("a forged failure digest must be rejected");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runmill_observation_terminal_failure_facts_exact_proof")
        );

        // Releasing the pointers without any fact is rejected as well.
        let error = sqlx::query(
            r"
            UPDATE runmill_run_observation_streams
            SET active_job_id = NULL,
                active_observation_id = NULL,
                state = 'ESCALATED',
                escalation_id = $3,
                last_error_digest = $4,
                aggregate_version = aggregate_version + 1
            WHERE tenant_id = $1 AND run_id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(escalation_id)
        .bind(&failure_digest)
        .execute(database.ledger.pool())
        .await
        .expect_err("an unproved release must be rejected");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runmill_observation_streams_exact_escalation")
        );

        assert_eq!(
            produce_due_runmill_observation_jobs(
                database.ledger.pool(),
                fixture.tenant_id,
                &[],
                4,
            )
            .await
            .expect("record the one legitimate terminal-failure fact"),
            RunmillObservationProductionReport {
                dead_jobs_escalated: 1,
                jobs_enqueued: 0,
            }
        );

        for statement in [
            "UPDATE runmill_observation_terminal_failure_facts SET failure_digest = $3 WHERE tenant_id = $1 AND observation_id = $2",
            "DELETE FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1 AND observation_id = $2 AND $3::text IS NOT NULL",
        ] {
            let error = sqlx::query(statement)
                .bind(fixture.tenant_id)
                .bind(fixture.observation_id)
                .bind(&forged_digest)
                .execute(database.ledger.pool())
                .await
                .expect_err("a retained terminal-failure fact is append-only");
            let code = error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .map(std::borrow::Cow::into_owned);
            assert_eq!(
                code.as_deref(),
                Some("55000"),
                "append-only rejection must fail closed"
            );
        }
        let retained_digest: String = sqlx::query_scalar(
            "SELECT failure_digest FROM runmill_observation_terminal_failure_facts WHERE tenant_id = $1 AND observation_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.observation_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load the surviving terminal-failure fact");
        assert_eq!(retained_digest, failure_digest);

        database.cleanup().await;
    }
}
