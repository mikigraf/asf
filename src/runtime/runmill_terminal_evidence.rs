//! Production retention of one Runmill terminal evidence bundle.
//!
//! An observation stream that reached `TERMINAL_READY` proved, through two
//! exact control snapshots, that its run reached a terminal phase at a known
//! external sequence. It did not read the evidence itself: the signed terminal
//! bundle comes from a separate `asf.get_evidence` call, and that call's exact
//! response wire is a third provenance which is never conflated with the two
//! snapshots.
//!
//! This activity performs that one read and retains its result. It never
//! projects Runmill events, never updates `runs`, and never advances an
//! observation stream: the append-only bundle is the whole effect. The remote
//! read completes and validates before the ledger transaction opens, so a
//! timeout or a malformed response can never leave a partial local proof.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, JobClaimScope, JobHandler, RETAIN_RUNMILL_TERMINAL_EVIDENCE,
    RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID,
};
use crate::{
    Error, Result,
    adapters::{
        RunmillControlClient, RunmillControlError, RunmillEvidenceView, RunmillRunId,
        RunmillRunPhase, RunmillValidatedRead,
    },
    crypto::is_sha256_digest,
    domain::{TenantId, WorkerId},
    ledger::{
        ClaimedWorkflowJob, PgLedger, RunmillTerminalEvidenceFence, RunmillTerminalEvidenceOutcome,
        record_runmill_terminal_evidence,
    },
    security::reject_sensitive_fields,
};

const TERMINAL_EVIDENCE_PAYLOAD_SCHEMA_V1: &str = "asf.runmill-terminal-evidence/v1";
const TERMINAL_EVIDENCE_RESULT_SCHEMA_V1: &str = "asf.runmill-terminal-evidence-result/v1";
const MAX_RUNMILL_SEQUENCE: u64 = 9_007_199_254_740_991;

/// The single control read this activity is allowed to make.
///
/// Kept private and narrow so production code alone crosses from a live
/// `asf.get_evidence` response into a [`RunmillValidatedRead`]; there is no
/// public way to forge terminal evidence provenance.
#[async_trait]
trait RunmillTerminalEvidenceControl: Send + Sync + fmt::Debug {
    async fn read_terminal_evidence(
        &self,
        run_id: &RunmillRunId,
    ) -> Result<RunmillValidatedRead<RunmillEvidenceView>>;
}

#[async_trait]
impl RunmillTerminalEvidenceControl for RunmillControlClient {
    async fn read_terminal_evidence(
        &self,
        run_id: &RunmillRunId,
    ) -> Result<RunmillValidatedRead<RunmillEvidenceView>> {
        Self::get_evidence_with_provenance(self, run_id)
            .await
            .map_err(|error| control_failure(&error))
    }
}

/// Retains one signed terminal evidence bundle for a single configured tenant
/// and private Runmill worker.
#[derive(Clone)]
pub struct RunmillTerminalEvidenceHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    worker_id: WorkerId,
    control: Arc<dyn RunmillTerminalEvidenceControl>,
}

impl fmt::Debug for RunmillTerminalEvidenceHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillTerminalEvidenceHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("worker_id", &self.worker_id)
            .field("control", &"RunmillControlClient([REDACTED])")
            .finish()
    }
}

impl RunmillTerminalEvidenceHandler {
    /// Construct a retention activity explicitly scoped to one tenant and
    /// worker.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] when the tenant or worker identity is nil.
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: RunmillControlClient,
    ) -> Result<Self> {
        if tenant_id.as_uuid().is_nil() || worker_id.as_uuid().is_nil() {
            return Err(Error::Validation(
                "Runmill terminal evidence handler requires non-nil tenant and worker IDs".into(),
            ));
        }
        Ok(Self {
            ledger,
            tenant_id,
            worker_id,
            control: Arc::new(control),
        })
    }

    async fn execute_inner(&self, job: &ClaimedWorkflowJob) -> Result<ActivityOutcome> {
        let payload = TerminalEvidencePayload::parse(job, self.tenant_id, self.worker_id)?;
        let external_run_id =
            RunmillRunId::parse(payload.external_run_id.clone()).map_err(|error| {
                Error::Validation(format!(
                    "Runmill terminal evidence job {} has an invalid external run ID: {error}",
                    job.id
                ))
            })?;
        // The authority binding is checked before a private Runmill socket is
        // opened. This read takes no locks; retention repeats the proof under
        // locks after the remote read completes.
        assert_exact_retention_authority(self.ledger.pool(), job, &payload, false).await?;

        let read = self
            .control
            .read_terminal_evidence(&external_run_id)
            .await?;
        self.retain(job, &payload, read).await
    }

    async fn retain(
        &self,
        job: &ClaimedWorkflowJob,
        payload: &TerminalEvidencePayload,
        read: RunmillValidatedRead<RunmillEvidenceView>,
    ) -> Result<ActivityOutcome> {
        let fence = payload.fence(job)?;
        let mut transaction = self.ledger.pool().begin().await.map_err(|error| {
            Error::Persistence(format!(
                "begin Runmill terminal evidence transaction: {error}"
            ))
        })?;
        assert_exact_retention_authority(&mut *transaction, job, payload, true).await?;
        let outcome = record_runmill_terminal_evidence(&mut transaction, &fence, read).await?;
        complete_retention_job(&mut transaction, job, payload, &outcome).await?;
        transaction.commit().await.map_err(|error| {
            Error::Persistence(format!(
                "commit Runmill terminal evidence transaction: {error}"
            ))
        })?;
        Ok(ActivityOutcome::TransactionCommitted)
    }
}

#[async_trait]
impl JobHandler for RunmillTerminalEvidenceHandler {
    fn job_type(&self) -> &str {
        RETAIN_RUNMILL_TERMINAL_EVIDENCE
    }

    fn activity_contract_id(&self) -> &str {
        RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID
    }

    fn claim_scope(&self) -> JobClaimScope {
        JobClaimScope::RetainRunmillTerminalEvidenceWorker(self.worker_id)
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        self.execute_inner(job).await
    }
}

/// The immutable retention claim minted by the producer.
///
/// Every field is a coordinate the producer already proved against a
/// `TERMINAL_READY` stream and its exact observation result. The handler
/// invents none of them: it re-proves them under lock and then requires the
/// retained evidence bytes to state exactly the same thing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalEvidencePayload {
    schema: String,
    bundle_id: Uuid,
    run_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    worker_id: WorkerId,
    worker_session_id: Uuid,
    worker_generation: u64,
    observer_session_id: Uuid,
    external_run_id: String,
    observation_id: Uuid,
    get_run_snapshot_id: Uuid,
    event_page_snapshot_id: Uuid,
    terminal_phase: RunmillRunPhase,
    terminal_event_seq: u64,
}

impl TerminalEvidencePayload {
    fn parse(job: &ClaimedWorkflowJob, tenant_id: TenantId, worker_id: WorkerId) -> Result<Self> {
        if job.job_type != RETAIN_RUNMILL_TERMINAL_EVIDENCE
            || job.activity_contract_id != RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID
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
                "Runmill terminal evidence job has invalid type, activity contract, claim, tenant, or workflow binding"
                    .into(),
            ));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!(
                "invalid Runmill terminal evidence payload: {error}"
            ))
        })?;
        if payload.schema != TERMINAL_EVIDENCE_PAYLOAD_SCHEMA_V1
            || payload.bundle_id.is_nil()
            || payload.run_id.is_nil()
            || payload.work_order_id.is_nil()
            || payload.worker_id != worker_id
            || payload.worker_id.as_uuid().is_nil()
            || payload.worker_session_id.is_nil()
            || payload.observer_session_id.is_nil()
            || payload.observation_id.is_nil()
            || payload.get_run_snapshot_id.is_nil()
            || payload.event_page_snapshot_id.is_nil()
            || payload.get_run_snapshot_id == payload.event_page_snapshot_id
            || payload.worker_generation == 0
            || !(1..=MAX_RUNMILL_SEQUENCE).contains(&payload.terminal_event_seq)
            || payload.external_run_id.trim().is_empty()
            || !is_sha256_digest(&payload.work_order_digest)
        {
            return Err(Error::Validation(
                "Runmill terminal evidence payload is not bound to the configured worker and exact terminal observation"
                    .into(),
            ));
        }
        if !payload.terminal_phase.terminal() {
            return Err(Error::Validation(
                "Runmill terminal evidence payload names a non-terminal run phase".into(),
            ));
        }
        reject_sensitive_fields(&job.payload)?;
        Ok(payload)
    }

    fn fence(&self, job: &ClaimedWorkflowJob) -> Result<RunmillTerminalEvidenceFence> {
        let work_item_id = job.work_item_id.ok_or_else(|| {
            Error::Validation(format!(
                "Runmill terminal evidence job {} lacks its work-item binding",
                job.id
            ))
        })?;
        let attempt_id = job.attempt_id.ok_or_else(|| {
            Error::Validation(format!(
                "Runmill terminal evidence job {} lacks its attempt binding",
                job.id
            ))
        })?;
        Ok(RunmillTerminalEvidenceFence {
            id: self.bundle_id,
            tenant_id: job.tenant_id,
            run_id: self.run_id,
            work_item_id,
            attempt_id,
            work_order_id: self.work_order_id,
            work_order_digest: self.work_order_digest.clone(),
            worker_session_id: self.worker_session_id,
            worker_id: self.worker_id.as_uuid(),
            worker_generation: self.worker_generation_i64()?,
            external_run_id: self.external_run_id.clone(),
            get_run_snapshot_id: self.get_run_snapshot_id,
            event_page_snapshot_id: self.event_page_snapshot_id,
            terminal_phase: self.terminal_phase,
            terminal_event_seq: self.terminal_event_seq_i64()?,
        })
    }

    fn worker_generation_i64(&self) -> Result<i64> {
        i64::try_from(self.worker_generation).map_err(|_| {
            Error::Validation("Runmill terminal evidence worker generation overflows bigint".into())
        })
    }

    fn terminal_event_seq_i64(&self) -> Result<i64> {
        i64::try_from(self.terminal_event_seq).map_err(|_| {
            Error::Validation("Runmill terminal event sequence overflows bigint".into())
        })
    }
}

/// The exact live authority one retention may run under.
///
/// The stream must still be `TERMINAL_READY` through the very observation
/// result whose two snapshots this job names, the run must still be the
/// authoritative one, and a live observer session for the exact worker
/// generation must still exist. Migration 0035 re-proves the snapshot and
/// stream bindings under lock; proving them here turns a lost race into a named
/// ASF conflict rather than an opaque trigger abort.
const EXACT_RETENTION_AUTHORITY_SQL: &str = r"
SELECT
    job.id,
    stream.aggregate_version AS stream_aggregate_version
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
 AND stream.state = 'TERMINAL_READY'
JOIN runmill_run_observation_results AS result
  ON result.tenant_id = stream.tenant_id
 AND result.run_id = stream.run_id
 AND result.observation_id = $16::uuid
 AND result.disposition = 'TERMINAL_READY'
 AND result.get_run_snapshot_id = $17::uuid
 AND result.event_page_snapshot_id = $18::uuid
 AND result.next_sequence = $19::bigint - 1
JOIN runs AS run
  ON run.tenant_id = job.tenant_id
 AND run.id = stream.run_id
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
JOIN attempts AS attempt
  ON attempt.tenant_id = job.tenant_id
 AND attempt.id = job.attempt_id
 AND attempt.work_item_id = job.work_item_id
 AND attempt.work_order_digest = work_order.payload_digest
JOIN work_items AS work
  ON work.tenant_id = job.tenant_id
 AND work.id = job.work_item_id
 AND work.current_attempt_id = job.attempt_id
 AND work.accepted_at IS NOT NULL
 AND work.state NOT IN ('CLOSED', 'CANCELLED')
JOIN workflow_instances AS workflow
  ON workflow.tenant_id = job.tenant_id
 AND workflow.id = job.workflow_instance_id
 AND workflow.work_item_id = job.work_item_id
 AND workflow.state IN ('ACTIVE', 'WAITING')
JOIN workers AS worker
  ON worker.tenant_id = run.tenant_id
 AND worker.id = run.worker_id
 AND worker.generation = $14::bigint
 AND worker.status <> 'QUARANTINED'
JOIN worker_sessions AS observer_session
  ON observer_session.tenant_id = run.tenant_id
 AND observer_session.id = $20::uuid
 AND observer_session.worker_id = run.worker_id
 AND observer_session.worker_generation = run.worker_generation
 AND observer_session.status = 'ACTIVE'
 AND observer_session.expires_at > clock_timestamp()
WHERE job.tenant_id = $1
  AND job.id = $2
  AND job.workflow_instance_id = $3
  AND job.work_item_id = $4
  AND job.attempt_id = $5
  AND job.job_type = 'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
  AND job.activity_contract_id = $22
  AND job.status = 'RUNNING'
  AND job.lease_owner = $6
  AND job.fence_token = $7
  AND job.attempt_count = $8
  AND job.lease_expires_at > clock_timestamp()
  AND job.payload = $21::jsonb
";

async fn assert_exact_retention_authority<'executor, Executor>(
    executor: Executor,
    job: &ClaimedWorkflowJob,
    payload: &TerminalEvidencePayload,
    lock: bool,
) -> Result<()>
where
    Executor: sqlx::Executor<'executor, Database = Postgres>,
{
    let workflow_instance_id = job.workflow_instance_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill terminal evidence job {} lacks its workflow binding",
            job.id
        ))
    })?;
    let work_item_id = job.work_item_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill terminal evidence job {} lacks its work-item binding",
            job.id
        ))
    })?;
    let attempt_id = job.attempt_id.ok_or_else(|| {
        Error::Validation(format!(
            "Runmill terminal evidence job {} lacks its attempt binding",
            job.id
        ))
    })?;
    let sql = if lock {
        format!("{EXACT_RETENTION_AUTHORITY_SQL} FOR UPDATE OF job, stream")
    } else {
        EXACT_RETENTION_AUTHORITY_SQL.into()
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
        .bind(payload.worker_generation_i64()?)
        .bind(&payload.external_run_id)
        .bind(payload.observation_id)
        .bind(payload.get_run_snapshot_id)
        .bind(payload.event_page_snapshot_id)
        .bind(payload.terminal_event_seq_i64()?)
        .bind(payload.observer_session_id)
        .bind(&job.payload)
        .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID)
        .fetch_optional(executor)
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "prove exact Runmill terminal evidence authority: {error}"
            ))
        })?;
    let row = found.ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill terminal evidence job {} lacks its exact terminal-ready observation binding",
            job.id
        ))
    })?;
    let found_job_id: Uuid = authority_column(&row, "id", "job ID")?;
    if found_job_id != job.id {
        return Err(Error::Conflict(format!(
            "Runmill terminal evidence authority returned a foreign job for {}",
            job.id
        )));
    }
    Ok(())
}

async fn complete_retention_job(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    payload: &TerminalEvidencePayload,
    outcome: &RunmillTerminalEvidenceOutcome,
) -> Result<()> {
    let result = retention_result(payload, outcome)?;
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
    .bind(&result)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        Error::Persistence(format!("complete Runmill terminal evidence job: {error}"))
    })?
    .rows_affected();
    if changed != 1 {
        return Err(Error::Conflict(format!(
            "Runmill terminal evidence job {} lost its completion fence",
            job.id
        )));
    }
    Ok(())
}

/// The immutable completion result. It names the retained proof by digest and
/// records whether this attempt was the one that wrote it, so a replay is
/// distinguishable from a first retention without reopening the bundle.
fn retention_result(
    payload: &TerminalEvidencePayload,
    outcome: &RunmillTerminalEvidenceOutcome,
) -> Result<Value> {
    let result = json!({
        "schema": TERMINAL_EVIDENCE_RESULT_SCHEMA_V1,
        "bundle_id": outcome.bundle_id,
        "inserted": outcome.inserted,
        "idempotency_key": outcome.idempotency_key,
        "terminal_bundle_digest": outcome.terminal_bundle_digest,
        "statement_digest": outcome.statement_digest,
        "run_id": payload.run_id,
        "external_run_id": payload.external_run_id,
        "observation_id": payload.observation_id,
        "get_run_snapshot_id": payload.get_run_snapshot_id,
        "event_page_snapshot_id": payload.event_page_snapshot_id,
        "terminal_event_seq": payload.terminal_event_seq,
    });
    reject_sensitive_fields(&result)?;
    Ok(result)
}

fn control_failure(error: &RunmillControlError) -> Error {
    Error::ExternalUnavailable(format!("Runmill terminal evidence read failed: {error}"))
}

fn authority_column<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!(
            "decode Runmill terminal evidence {description}: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use serde_json::json;

    use super::*;

    fn claimed_job(payload: Value) -> ClaimedWorkflowJob {
        ClaimedWorkflowJob {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            workflow_instance_id: Some(Uuid::now_v7()),
            work_item_id: Some(Uuid::now_v7()),
            attempt_id: Some(Uuid::now_v7()),
            job_type: RETAIN_RUNMILL_TERMINAL_EVIDENCE.into(),
            activity_contract_id: RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID.into(),
            payload,
            idempotency_key: "runmill-terminal-evidence:test".into(),
            priority: 70,
            attempt_count: 1,
            max_attempts: 25,
            fence_token: 1,
            lease_owner: "reactor:terminal-evidence-test".into(),
            lease_expires_at: Utc::now() + TimeDelta::minutes(5),
            created_at: Utc::now(),
        }
    }

    fn valid_payload(tenant_worker: WorkerId) -> Value {
        json!({
            "schema": TERMINAL_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "bundle_id": Uuid::now_v7(),
            "run_id": Uuid::now_v7(),
            "work_order_id": Uuid::now_v7(),
            "work_order_digest": format!("sha256:{}", "a".repeat(64)),
            "worker_id": tenant_worker,
            "worker_session_id": Uuid::now_v7(),
            "worker_generation": 3,
            "observer_session_id": Uuid::now_v7(),
            "external_run_id": "run-123",
            "observation_id": Uuid::now_v7(),
            "get_run_snapshot_id": Uuid::now_v7(),
            "event_page_snapshot_id": Uuid::now_v7(),
            "terminal_phase": "COMPLETED",
            "terminal_event_seq": 10,
        })
    }

    #[test]
    fn payload_accepts_the_exact_producer_claim() {
        let worker_id = WorkerId::new();
        let job = claimed_job(valid_payload(worker_id));
        let tenant_id = TenantId::from_uuid(job.tenant_id);

        let payload = TerminalEvidencePayload::parse(&job, tenant_id, worker_id)
            .expect("the producer's own claim parses");
        assert_eq!(payload.terminal_phase, RunmillRunPhase::Completed);
        assert_eq!(payload.terminal_event_seq, 10);

        let fence = payload.fence(&job).expect("claim yields a storable fence");
        assert_eq!(fence.tenant_id, job.tenant_id);
        assert_eq!(fence.work_item_id, job.work_item_id.unwrap());
        assert_eq!(fence.attempt_id, job.attempt_id.unwrap());
        assert_eq!(fence.terminal_event_seq, 10);
    }

    #[test]
    fn payload_rejects_a_foreign_worker_or_tenant() {
        let worker_id = WorkerId::new();
        let job = claimed_job(valid_payload(worker_id));
        let tenant_id = TenantId::from_uuid(job.tenant_id);

        let other_worker = WorkerId::new();
        assert!(TerminalEvidencePayload::parse(&job, tenant_id, other_worker).is_err());

        let other_tenant = TenantId::new();
        assert!(TerminalEvidencePayload::parse(&job, other_tenant, worker_id).is_err());
    }

    /// One deliberate perturbation of an otherwise storable retention claim.
    type PayloadMutation = Box<dyn Fn(&mut Value)>;

    #[test]
    fn payload_rejects_an_unprovable_terminal_claim() {
        let worker_id = WorkerId::new();
        let tenant_of = |job: &ClaimedWorkflowJob| TenantId::from_uuid(job.tenant_id);

        let shared_snapshot = Uuid::now_v7();
        let mutations: Vec<PayloadMutation> = vec![
            Box::new(|payload| payload["schema"] = json!("asf.runmill-terminal-evidence/v2")),
            Box::new(|payload| payload["bundle_id"] = json!(Uuid::nil())),
            Box::new(|payload| payload["run_id"] = json!(Uuid::nil())),
            Box::new(|payload| payload["worker_generation"] = json!(0)),
            Box::new(|payload| payload["terminal_event_seq"] = json!(0)),
            Box::new(|payload| payload["terminal_event_seq"] = json!(MAX_RUNMILL_SEQUENCE + 1)),
            Box::new(|payload| payload["work_order_digest"] = json!("not-a-digest")),
            Box::new(|payload| payload["external_run_id"] = json!("   ")),
            // A run that has not stopped has no terminal evidence to retain.
            Box::new(|payload| payload["terminal_phase"] = json!("IMPLEMENTING")),
            // One snapshot can never satisfy both provenance roles.
            Box::new(move |payload| {
                payload["get_run_snapshot_id"] = json!(shared_snapshot);
                payload["event_page_snapshot_id"] = json!(shared_snapshot);
            }),
        ];

        for mutate in mutations {
            let mut payload = valid_payload(worker_id);
            mutate(&mut payload);
            let job = claimed_job(payload);
            assert!(
                TerminalEvidencePayload::parse(&job, tenant_of(&job), worker_id).is_err(),
                "an unprovable terminal claim must never reach a control read"
            );
        }
    }

    #[test]
    fn payload_rejects_a_job_that_is_not_this_activity() {
        let worker_id = WorkerId::new();
        for mutate in [
            |job: &mut ClaimedWorkflowJob| job.job_type = "OBSERVE_RUNMILL_RUN".into(),
            |job: &mut ClaimedWorkflowJob| {
                job.activity_contract_id = "asf.activity/observe-runmill-run/v2".into();
            },
            |job: &mut ClaimedWorkflowJob| job.attempt_id = None,
            |job: &mut ClaimedWorkflowJob| job.fence_token = 0,
            |job: &mut ClaimedWorkflowJob| job.lease_owner = String::new(),
        ] {
            let mut job = claimed_job(valid_payload(worker_id));
            let tenant_id = TenantId::from_uuid(job.tenant_id);
            mutate(&mut job);
            assert!(TerminalEvidencePayload::parse(&job, tenant_id, worker_id).is_err());
        }
    }

    #[test]
    fn authority_requires_the_terminal_ready_stream_and_its_exact_result() {
        for required in [
            "stream.state = 'TERMINAL_READY'",
            "result.disposition = 'TERMINAL_READY'",
            "result.get_run_snapshot_id = $17::uuid",
            "result.event_page_snapshot_id = $18::uuid",
            "result.next_sequence = $19::bigint - 1",
            "run.authoritative",
            "observer_session.status = 'ACTIVE'",
            "job.job_type = 'RETAIN_RUNMILL_TERMINAL_EVIDENCE'",
        ] {
            assert!(
                EXACT_RETENTION_AUTHORITY_SQL.contains(required),
                "missing {required}"
            );
        }
        // Retention proves authority; it never mutates run state or the stream.
        for forbidden in [
            "UPDATE runs",
            "UPDATE runmill_run_observation_streams",
            "INSERT INTO raw_run_events",
        ] {
            assert!(
                !EXACT_RETENTION_AUTHORITY_SQL.contains(forbidden),
                "unexpected {forbidden}"
            );
        }
    }

    #[test]
    fn retention_result_names_the_retained_proof() {
        let worker_id = WorkerId::new();
        let job = claimed_job(valid_payload(worker_id));
        let payload =
            TerminalEvidencePayload::parse(&job, TenantId::from_uuid(job.tenant_id), worker_id)
                .unwrap();
        let outcome = RunmillTerminalEvidenceOutcome {
            bundle_id: payload.bundle_id,
            inserted: true,
            idempotency_key: "runmill-terminal-evidence:t:r:d".into(),
            terminal_bundle_digest: format!("sha256:{}", "b".repeat(64)),
            statement_digest: format!("sha256:{}", "b".repeat(64)),
        };

        let result = retention_result(&payload, &outcome).expect("result carries no secrets");
        assert_eq!(result["schema"], json!(TERMINAL_EVIDENCE_RESULT_SCHEMA_V1));
        assert_eq!(result["bundle_id"], json!(payload.bundle_id));
        assert_eq!(result["inserted"], json!(true));
        assert_eq!(
            result["terminal_bundle_digest"],
            json!(outcome.terminal_bundle_digest)
        );
        assert_eq!(result["terminal_event_seq"], json!(10));
    }
}
