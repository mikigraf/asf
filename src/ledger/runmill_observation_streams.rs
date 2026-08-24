//! Durable Runmill observation-stream creation and job production.
//!
//! A stream is the mutable cursor aggregate for one already-authoritative run.
//! It is intentionally separate from the append-only control snapshots: the
//! stream decides which cursor may be requested next, while snapshots prove
//! exactly what the worker returned for an owned request.

use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::persistence_error;
use crate::{Error, Result, crypto::is_sha256_digest};

const OBSERVE_RUNMILL_RUN: &str = "OBSERVE_RUNMILL_RUN";
const OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID: &str = "asf.activity/observe-runmill-run/v2";
const OBSERVATION_PAYLOAD_SCHEMA_V2: &str = "asf.runmill-observation/v2";
const OBSERVATION_JOB_PRIORITY: i16 = 75;
const OBSERVATION_JOB_MAX_ATTEMPTS: i32 = 25;
const MAX_PRODUCTION_BATCH: u32 = 1_000;
const MAX_RUNMILL_SEQUENCE: i64 = 9_007_199_254_740_991;

const SELECT_DUE_STREAMS_SQL: &str = r"
SELECT
    stream.run_id,
    stream.workflow_instance_id,
    stream.work_item_id,
    stream.attempt_id,
    stream.work_order_id,
    stream.work_order_digest,
    stream.worker_id,
    stream.worker_generation,
    stream.run_admission_worker_session_id,
    stream.external_run_id,
    stream.next_after_sequence,
    stream.observation_epoch,
    stream.aggregate_version,
    observer_session.id AS observer_session_id
FROM runmill_run_observation_streams AS stream
JOIN runs AS run
  ON run.tenant_id = stream.tenant_id
 AND run.id = stream.run_id
 AND run.work_item_id = stream.work_item_id
 AND run.attempt_id = stream.attempt_id
 AND run.work_order_id = stream.work_order_id
 AND run.worker_id = stream.worker_id
 AND run.worker_generation = stream.worker_generation
 AND run.worker_session_id = stream.run_admission_worker_session_id
 AND run.external_run_id = stream.external_run_id
 AND run.authoritative
JOIN work_orders AS work_order
  ON work_order.tenant_id = stream.tenant_id
 AND work_order.id = stream.work_order_id
 AND work_order.work_item_id = stream.work_item_id
 AND work_order.attempt_id = stream.attempt_id
 AND work_order.payload_digest = stream.work_order_digest
JOIN attempts AS attempt
  ON attempt.tenant_id = stream.tenant_id
 AND attempt.id = stream.attempt_id
 AND attempt.work_item_id = stream.work_item_id
 AND attempt.work_order_digest = stream.work_order_digest
JOIN work_items AS work
  ON work.tenant_id = stream.tenant_id
 AND work.id = stream.work_item_id
 AND work.current_attempt_id = stream.attempt_id
 AND work.accepted_at IS NOT NULL
 AND work.state NOT IN ('CLOSED', 'CANCELLED')
JOIN workflow_instances AS workflow
  ON workflow.tenant_id = stream.tenant_id
 AND workflow.id = stream.workflow_instance_id
 AND workflow.work_item_id = stream.work_item_id
 AND workflow.state IN ('ACTIVE', 'WAITING')
JOIN workers AS worker
  ON worker.tenant_id = stream.tenant_id
 AND worker.id = stream.worker_id
 AND worker.generation = stream.worker_generation
 AND worker.status <> 'QUARANTINED'
JOIN LATERAL (
    SELECT session.id
    FROM worker_sessions AS session
    WHERE session.tenant_id = stream.tenant_id
      AND session.worker_id = stream.worker_id
      AND session.worker_generation = stream.worker_generation
      AND session.status = 'ACTIVE'
      AND session.expires_at > clock_timestamp()
    ORDER BY session.started_at DESC, session.id DESC
    LIMIT 1
) AS observer_session ON true
WHERE stream.tenant_id = $1
  AND stream.worker_id::text = ANY($2::text[])
  AND stream.state = 'ACTIVE'
  AND stream.active_job_id IS NULL
  AND stream.active_observation_id IS NULL
  AND stream.next_poll_at <= clock_timestamp()
ORDER BY stream.next_poll_at, stream.run_id
FOR UPDATE OF stream SKIP LOCKED
LIMIT $3
";

/// Streams whose exact active observer job already became owned `DEAD` work
/// without ever retaining a remote page.
///
/// Every coordinate needed for the immutable terminal-failure fact is proved
/// here before the row is locked, so an unprovable stream is simply skipped
/// instead of aborting the whole producer transaction. The database trigger
/// re-proves all of it under lock; this scan only decides what is worth trying.
///
/// That includes the trigger's absence preconditions. A checkpoint that already
/// retained an observation result, a gap-escalation binding, or any control
/// snapshot has its own result-backed release and can never satisfy the
/// terminal-failure guard, so one such poisoned stream must not be selected: it
/// would abort the whole tenant's producer transaction and block recovery and
/// scheduling for every other stream in that tenant.
const SELECT_DEAD_PINNED_STREAMS_SQL: &str = r"
SELECT
    stream.run_id,
    stream.active_job_id,
    stream.active_observation_id,
    stream.next_after_sequence,
    stream.observation_epoch,
    stream.aggregate_version,
    job.dead_letter_escalation_id AS escalation_id,
    job.result ->> 'error_digest' AS failure_digest
FROM runmill_run_observation_streams AS stream
JOIN runmill_run_observation_checkpoints AS checkpoint
  ON checkpoint.tenant_id = stream.tenant_id
 AND checkpoint.id = stream.active_observation_id
 AND checkpoint.run_id = stream.run_id
 AND checkpoint.workflow_job_id = stream.active_job_id
 AND checkpoint.after_sequence = stream.next_after_sequence
 AND checkpoint.observation_epoch = stream.observation_epoch
 AND checkpoint.worker_id = stream.worker_id
 AND checkpoint.worker_generation = stream.worker_generation
JOIN workflow_jobs AS job
  ON job.tenant_id = stream.tenant_id
 AND job.id = stream.active_job_id
 AND job.workflow_instance_id = stream.workflow_instance_id
 AND job.work_item_id = stream.work_item_id
 AND job.attempt_id = stream.attempt_id
 AND job.job_type = 'OBSERVE_RUNMILL_RUN'
 AND job.activity_contract_id = $3
 AND job.status = 'DEAD'
 AND job.dead_letter_escalation_id IS NOT NULL
 AND job.dead_letter_operational_incident_id IS NULL
JOIN escalations AS escalation
  ON escalation.tenant_id = job.tenant_id
 AND escalation.id = job.dead_letter_escalation_id
 AND escalation.work_item_id = stream.work_item_id
 AND escalation.attempt_id = stream.attempt_id
 AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
 AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
 AND escalation.authority_or_effect_active
WHERE stream.tenant_id = $1
  AND stream.state = 'ACTIVE'
  AND stream.active_job_id IS NOT NULL
  AND stream.active_observation_id IS NOT NULL
  AND stream.next_after_sequence BETWEEN 0 AND 9007199254740991
  AND stream.observation_epoch BETWEEN 1 AND 9007199254740991
  AND jsonb_typeof(job.payload) = 'object'
  AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
  AND job.payload ->> 'observation_id' = checkpoint.id::text
  AND job.payload ->> 'run_id' = stream.run_id::text
  AND job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)
  AND job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)
  AND jsonb_typeof(job.result) = 'object'
  AND job.result ->> 'schema' = 'asf.workflow-job-dead-letter-result/v1'
  AND job.result ->> 'workflow_job_id' = job.id::text
  AND job.result ->> 'job_type' = 'OBSERVE_RUNMILL_RUN'
  AND jsonb_typeof(job.result -> 'error_digest') = 'string'
  AND job.result ->> 'error_digest' ~ '^sha256:[0-9a-f]{64}$'
  AND job.result #>> '{escalation,id}' = escalation.id::text
  AND escalation.evidence_references @> jsonb_build_array(
      'workflow-job:' || job.id::text
  )
  AND escalation.evidence_references @> jsonb_build_array(
      'workflow-job-type:' || job.id::text || ':OBSERVE_RUNMILL_RUN'
  )
  AND escalation.evidence_references @> jsonb_build_array(
      'workflow-job-error:' || job.id::text || ':' || (job.result ->> 'error_digest')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM runmill_run_observation_results AS result
      WHERE result.tenant_id = stream.tenant_id
        AND result.observation_id = stream.active_observation_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM runmill_observation_gap_escalation_bindings AS binding
      WHERE binding.tenant_id = stream.tenant_id
        AND binding.observation_id = stream.active_observation_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM runmill_control_snapshots AS snapshot
      WHERE snapshot.tenant_id = stream.tenant_id
        AND snapshot.observation_id = stream.active_observation_id
  )
ORDER BY stream.run_id
FOR UPDATE OF stream SKIP LOCKED
LIMIT $2
";

const RELEASE_DEAD_PINNED_STREAM_SQL: &str = r"
UPDATE runmill_run_observation_streams AS stream
SET active_job_id = NULL,
    active_observation_id = NULL,
    state = 'ESCALATED',
    escalation_id = $6,
    last_error_digest = $7,
    aggregate_version = stream.aggregate_version + 1,
    updated_at = clock_timestamp()
WHERE stream.tenant_id = $1
  AND stream.run_id = $2
  AND stream.state = 'ACTIVE'
  AND stream.active_job_id = $3
  AND stream.active_observation_id = $4
  AND stream.aggregate_version = $5
RETURNING stream.run_id
";

/// One stream that is pinned behind an owned terminal observer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeadPinnedStream {
    run_id: Uuid,
    workflow_job_id: Uuid,
    observation_id: Uuid,
    after_sequence: i64,
    observation_epoch: i64,
    aggregate_version: i64,
    escalation_id: Uuid,
    failure_digest: String,
}

/// Immutable authority required when an adopted run first acquires an
/// observation cursor. The caller should insert this in the same transaction
/// that makes the run authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRunmillObservationStream {
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub workflow_instance_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub work_order_id: Uuid,
    pub work_order_digest: String,
    pub worker_id: Uuid,
    pub worker_generation: i64,
    pub run_admission_worker_session_id: Uuid,
    pub external_run_id: String,
}

impl NewRunmillObservationStream {
    fn validate(&self) -> Result<()> {
        if [
            self.tenant_id,
            self.run_id,
            self.workflow_instance_id,
            self.work_item_id,
            self.attempt_id,
            self.work_order_id,
            self.worker_id,
            self.run_admission_worker_session_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.worker_generation <= 0
            || !is_sha256_digest(&self.work_order_digest)
            || self.external_run_id.trim().is_empty()
        {
            return Err(Error::Validation(
                "Runmill observation stream requires exact non-nil authority, a SHA-256 Work Order digest, a positive worker generation, and an external run ID"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Result of idempotently installing the cursor root for an adopted run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRunmillObservationStreamOutcome {
    pub run_id: Uuid,
    pub inserted: bool,
}

/// Work performed by one bounded producer scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunmillObservationProductionReport {
    /// Streams released from an owned `DEAD` observer job that retained no
    /// remote page, each through one append-only terminal-failure fact.
    pub dead_jobs_escalated: u32,
    pub jobs_enqueued: u32,
}

/// Idempotently create one stream beneath an already-inserted authoritative
/// run. Reusing the run identity with different immutable authority is a
/// conflict, even if the existing stream has subsequently advanced.
pub async fn create_runmill_observation_stream(
    transaction: &mut Transaction<'_, Postgres>,
    stream: &NewRunmillObservationStream,
) -> Result<CreateRunmillObservationStreamOutcome> {
    stream.validate()?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO runmill_run_observation_streams (
            tenant_id, run_id, workflow_instance_id, work_item_id, attempt_id,
            work_order_id, work_order_digest, worker_id, worker_generation,
            run_admission_worker_session_id, external_run_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (tenant_id, run_id) DO NOTHING
        RETURNING run_id
        ",
    )
    .bind(stream.tenant_id)
    .bind(stream.run_id)
    .bind(stream.workflow_instance_id)
    .bind(stream.work_item_id)
    .bind(stream.attempt_id)
    .bind(stream.work_order_id)
    .bind(&stream.work_order_digest)
    .bind(stream.worker_id)
    .bind(stream.worker_generation)
    .bind(stream.run_admission_worker_session_id)
    .bind(&stream.external_run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("create Runmill observation stream", error))?;
    if inserted == Some(stream.run_id) {
        return Ok(CreateRunmillObservationStreamOutcome {
            run_id: stream.run_id,
            inserted: true,
        });
    }

    let row = sqlx::query(
        r"
        SELECT
            workflow_instance_id, work_item_id, attempt_id, work_order_id,
            work_order_digest, worker_id, worker_generation,
            run_admission_worker_session_id, external_run_id
        FROM runmill_run_observation_streams
        WHERE tenant_id = $1 AND run_id = $2
        FOR SHARE
        ",
    )
    .bind(stream.tenant_id)
    .bind(stream.run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load idempotent Runmill observation stream", error))?
    .ok_or_else(|| {
        Error::Persistence(
            "Runmill observation stream conflict was observed without a visible row".into(),
        )
    })?;
    if stream_binding_matches(&row, stream)? {
        Ok(CreateRunmillObservationStreamOutcome {
            run_id: stream.run_id,
            inserted: false,
        })
    } else {
        Err(Error::Conflict(format!(
            "Runmill observation stream for run {} has different immutable authority",
            stream.run_id
        )))
    }
}

/// Reconcile pinned dead observers, then produce at most `limit` due V2
/// observation jobs for workers with ready, worker-scoped handlers.
///
/// Recovery deliberately runs first and is not scoped to a ready worker route:
/// releasing a stream that an owned dead job left pinned is pure ledger
/// reconciliation and needs no live observer session. Scheduling still requires
/// a ready worker. The stream row, pending job, immutable scheduling
/// checkpoint, and active pointers are committed together.
pub async fn produce_due_runmill_observation_jobs(
    pool: &PgPool,
    tenant_id: Uuid,
    ready_worker_ids: &[String],
    limit: u32,
) -> Result<RunmillObservationProductionReport> {
    if tenant_id.is_nil() || limit == 0 || limit > MAX_PRODUCTION_BATCH {
        return Err(Error::Validation(
            "Runmill observation production requires a non-nil tenant and a limit in 1..=1000"
                .into(),
        ));
    }

    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| persistence_error("begin Runmill observation production", error))?;
    let dead_jobs_escalated =
        escalate_dead_pinned_streams(&mut transaction, tenant_id, limit).await?;

    let mut jobs_enqueued = 0_u32;
    if !ready_worker_ids.is_empty() {
        let rows = sqlx::query(SELECT_DUE_STREAMS_SQL)
            .bind(tenant_id)
            .bind(ready_worker_ids)
            .bind(i64::from(limit))
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| persistence_error("lock due Runmill observation streams", error))?;
        for row in rows {
            schedule_stream_job(&mut transaction, tenant_id, &row).await?;
            jobs_enqueued = jobs_enqueued.checked_add(1).ok_or_else(|| {
                Error::Persistence("observation production count overflowed".into())
            })?;
        }
    }
    transaction
        .commit()
        .await
        .map_err(|error| persistence_error("commit Runmill observation production", error))?;
    Ok(RunmillObservationProductionReport {
        dead_jobs_escalated,
        jobs_enqueued,
    })
}

/// Release every stream whose exact active observer job is owned `DEAD` work
/// without a retained remote page.
///
/// Each stream records one append-only terminal-failure fact and then moves to
/// `ESCALATED` at its unchanged cursor and epoch. Nothing here fabricates a
/// snapshot, an observation result, or a next cursor. The scan is bounded and
/// uses `SKIP LOCKED`, so a concurrent producer or handler never blocks it, and
/// a crash between the job's dead-letter commit and this release simply leaves
/// the same provable candidate for the next poll.
async fn escalate_dead_pinned_streams(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    limit: u32,
) -> Result<u32> {
    let rows = sqlx::query(SELECT_DEAD_PINNED_STREAMS_SQL)
        .bind(tenant_id)
        .bind(i64::from(limit))
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| {
            persistence_error("lock dead pinned Runmill observation streams", error)
        })?;

    let mut escalated = 0_u32;
    for row in rows {
        let candidate = dead_pinned_stream(&row)?;
        record_terminal_failure_fact(transaction, tenant_id, &candidate).await?;
        release_dead_pinned_stream(transaction, tenant_id, &candidate).await?;
        escalated = escalated.checked_add(1).ok_or_else(|| {
            Error::Persistence("observation stream recovery count overflowed".into())
        })?;
    }
    Ok(escalated)
}

fn dead_pinned_stream(row: &PgRow) -> Result<DeadPinnedStream> {
    let candidate = DeadPinnedStream {
        run_id: required(row, "run_id", "observation stream run")?,
        workflow_job_id: required(row, "active_job_id", "active observer job")?,
        observation_id: required(row, "active_observation_id", "active checkpoint")?,
        after_sequence: required(row, "next_after_sequence", "next cursor")?,
        observation_epoch: required(row, "observation_epoch", "observation epoch")?,
        aggregate_version: required(row, "aggregate_version", "stream version")?,
        escalation_id: required(row, "escalation_id", "effective escalation")?,
        failure_digest: required(row, "failure_digest", "durable failure digest")?,
    };
    validate_dead_pinned_stream(&candidate)?;
    Ok(candidate)
}

fn validate_dead_pinned_stream(candidate: &DeadPinnedStream) -> Result<()> {
    if [
        candidate.run_id,
        candidate.workflow_job_id,
        candidate.observation_id,
        candidate.escalation_id,
    ]
    .into_iter()
    .any(|id| id.is_nil())
        || !(0..=MAX_RUNMILL_SEQUENCE).contains(&candidate.after_sequence)
        || !(1..=MAX_RUNMILL_SEQUENCE).contains(&candidate.observation_epoch)
        || candidate.aggregate_version <= 0
        || !is_sha256_digest(&candidate.failure_digest)
    {
        return Err(Error::Conflict(format!(
            "Runmill observation stream {} has an out-of-range or unproved terminal-failure identity",
            candidate.run_id
        )));
    }
    Ok(())
}

/// Insert the immutable fact, or adopt an identical existing one, then compare
/// the retained row exactly. A conflicting retained fact is never overwritten.
async fn record_terminal_failure_fact(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    candidate: &DeadPinnedStream,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO runmill_observation_terminal_failure_facts (
            tenant_id, run_id, observation_id, workflow_job_id, escalation_id,
            after_sequence, observation_epoch, failure_digest
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (tenant_id, observation_id) DO NOTHING
        ",
    )
    .bind(tenant_id)
    .bind(candidate.run_id)
    .bind(candidate.observation_id)
    .bind(candidate.workflow_job_id)
    .bind(candidate.escalation_id)
    .bind(candidate.after_sequence)
    .bind(candidate.observation_epoch)
    .bind(&candidate.failure_digest)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        persistence_error("record Runmill observation terminal-failure fact", error)
    })?;

    let retained = sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, i64, i64, String)>(
        r"
        SELECT run_id, observation_id, workflow_job_id, escalation_id,
               after_sequence, observation_epoch, failure_digest
        FROM runmill_observation_terminal_failure_facts
        WHERE tenant_id = $1
          AND observation_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(candidate.observation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load Runmill observation terminal-failure fact", error))?;
    if retained
        != Some((
            candidate.run_id,
            candidate.observation_id,
            candidate.workflow_job_id,
            candidate.escalation_id,
            candidate.after_sequence,
            candidate.observation_epoch,
            candidate.failure_digest.clone(),
        ))
    {
        return Err(Error::Conflict(format!(
            "Runmill observation {} has a conflicting retained terminal-failure fact",
            candidate.observation_id
        )));
    }
    Ok(())
}

async fn release_dead_pinned_stream(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    candidate: &DeadPinnedStream,
) -> Result<()> {
    let released = sqlx::query_scalar::<_, Uuid>(RELEASE_DEAD_PINNED_STREAM_SQL)
        .bind(tenant_id)
        .bind(candidate.run_id)
        .bind(candidate.workflow_job_id)
        .bind(candidate.observation_id)
        .bind(candidate.aggregate_version)
        .bind(candidate.escalation_id)
        .bind(&candidate.failure_digest)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| {
            persistence_error("release dead pinned Runmill observation stream", error)
        })?;
    if released == Some(candidate.run_id) {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "Runmill observation stream {} changed before its terminal-failure release",
            candidate.run_id
        )))
    }
}

async fn schedule_stream_job(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    row: &PgRow,
) -> Result<()> {
    let run_id: Uuid = required(row, "run_id", "observation stream run")?;
    let workflow_instance_id: Uuid = required(row, "workflow_instance_id", "workflow")?;
    let work_item_id: Uuid = required(row, "work_item_id", "work item")?;
    let attempt_id: Uuid = required(row, "attempt_id", "attempt")?;
    let work_order_id: Uuid = required(row, "work_order_id", "Work Order")?;
    let work_order_digest: String = required(row, "work_order_digest", "Work Order digest")?;
    let worker_id: Uuid = required(row, "worker_id", "worker")?;
    let worker_generation: i64 = required(row, "worker_generation", "worker generation")?;
    let run_session_id: Uuid = required(
        row,
        "run_admission_worker_session_id",
        "run admission session",
    )?;
    let observer_session_id: Uuid = required(row, "observer_session_id", "observer session")?;
    let external_run_id: String = required(row, "external_run_id", "external run")?;
    let after_sequence: i64 = required(row, "next_after_sequence", "next cursor")?;
    let current_epoch: i64 = required(row, "observation_epoch", "observation epoch")?;
    let aggregate_version: i64 = required(row, "aggregate_version", "stream version")?;
    let observation_epoch = next_observation_epoch(current_epoch)?;
    let job_id = Uuid::now_v7();
    let observation_id = Uuid::now_v7();
    let payload = json!({
        "schema": OBSERVATION_PAYLOAD_SCHEMA_V2,
        "observation_id": observation_id,
        "run_id": run_id,
        "work_order_id": work_order_id,
        "work_order_digest": work_order_digest,
        "worker_id": worker_id,
        "worker_session_id": run_session_id,
        "worker_generation": worker_generation,
        "external_run_id": external_run_id,
        "after_sequence": after_sequence,
        "observation_epoch": observation_epoch,
        "observer_session_id": observer_session_id,
    });
    let idempotency_key =
        format!("runmill-observation:{run_id}:{observation_epoch}:{after_sequence}");

    let inserted_job = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, status, payload, idempotency_key,
            priority, available_at, max_attempts
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, 'PENDING', $8, $9, $10,
            clock_timestamp(), $11
        )
        ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        RETURNING id
        ",
    )
    .bind(job_id)
    .bind(tenant_id)
    .bind(workflow_instance_id)
    .bind(work_item_id)
    .bind(attempt_id)
    .bind(OBSERVE_RUNMILL_RUN)
    .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
    .bind(&payload)
    .bind(&idempotency_key)
    .bind(OBSERVATION_JOB_PRIORITY)
    .bind(OBSERVATION_JOB_MAX_ATTEMPTS)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert Runmill observation job", error))?;
    if inserted_job != Some(job_id) {
        return Err(Error::Conflict(format!(
            "Runmill observation idempotency key {idempotency_key} already exists"
        )));
    }

    sqlx::query(
        r"
        INSERT INTO runmill_run_observation_checkpoints (
            id, tenant_id, run_id, workflow_job_id, after_sequence,
            observation_epoch, observer_session_id, worker_id, worker_generation
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(observation_id)
    .bind(tenant_id)
    .bind(run_id)
    .bind(job_id)
    .bind(after_sequence)
    .bind(observation_epoch)
    .bind(observer_session_id)
    .bind(worker_id)
    .bind(worker_generation)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert Runmill observation checkpoint", error))?;

    let installed = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE runmill_run_observation_streams
        SET observation_epoch = $4,
            active_job_id = $5,
            active_observation_id = $6,
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND run_id = $2
          AND aggregate_version = $3
          AND state = 'ACTIVE'
          AND active_job_id IS NULL
          AND active_observation_id IS NULL
          AND next_after_sequence = $7
          AND observation_epoch = $8
        RETURNING run_id
        ",
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(aggregate_version)
    .bind(observation_epoch)
    .bind(job_id)
    .bind(observation_id)
    .bind(after_sequence)
    .bind(current_epoch)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("install active Runmill observation job", error))?;
    if installed != Some(run_id) {
        return Err(Error::Conflict(format!(
            "Runmill observation stream {run_id} changed before its job was installed"
        )));
    }
    Ok(())
}

fn next_observation_epoch(current_epoch: i64) -> Result<i64> {
    current_epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= MAX_RUNMILL_SEQUENCE)
        .ok_or_else(|| {
            Error::Conflict("Runmill observation epoch exceeded the protocol range".into())
        })
}

fn stream_binding_matches(row: &PgRow, stream: &NewRunmillObservationStream) -> Result<bool> {
    Ok(
        required::<Uuid>(row, "workflow_instance_id", "workflow")? == stream.workflow_instance_id
            && required::<Uuid>(row, "work_item_id", "work item")? == stream.work_item_id
            && required::<Uuid>(row, "attempt_id", "attempt")? == stream.attempt_id
            && required::<Uuid>(row, "work_order_id", "Work Order")? == stream.work_order_id
            && required::<String>(row, "work_order_digest", "Work Order digest")?
                == stream.work_order_digest
            && required::<Uuid>(row, "worker_id", "worker")? == stream.worker_id
            && required::<i64>(row, "worker_generation", "worker generation")?
                == stream.worker_generation
            && required::<Uuid>(
                row,
                "run_admission_worker_session_id",
                "run admission session",
            )? == stream.run_admission_worker_session_id
            && required::<String>(row, "external_run_id", "external run")?
                == stream.external_run_id,
    )
}

fn required<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        persistence_error(
            &format!("decode {description} from Runmill observation stream"),
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_input_rejects_missing_authority() {
        let stream = NewRunmillObservationStream {
            tenant_id: Uuid::nil(),
            run_id: Uuid::now_v7(),
            workflow_instance_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            work_order_digest: "not-a-digest".into(),
            worker_id: Uuid::now_v7(),
            worker_generation: 0,
            run_admission_worker_session_id: Uuid::now_v7(),
            external_run_id: String::new(),
        };
        assert!(stream.validate().is_err());
    }

    #[test]
    fn producer_sql_requires_exact_authority_and_skip_locked() {
        for required in [
            "run.authoritative",
            "work.current_attempt_id = stream.attempt_id",
            "attempt.work_order_digest = stream.work_order_digest",
            "session.expires_at > clock_timestamp()",
            "worker.generation = stream.worker_generation",
            "FOR UPDATE OF stream SKIP LOCKED",
        ] {
            assert!(
                SELECT_DUE_STREAMS_SQL.contains(required),
                "missing {required}"
            );
        }
    }

    #[test]
    fn observation_epoch_never_exceeds_the_runmill_safe_integer_range() {
        assert_eq!(next_observation_epoch(0).unwrap(), 1);
        assert_eq!(
            next_observation_epoch(MAX_RUNMILL_SEQUENCE - 1).unwrap(),
            MAX_RUNMILL_SEQUENCE
        );
        assert!(next_observation_epoch(MAX_RUNMILL_SEQUENCE).is_err());
    }

    #[test]
    fn dead_pinned_stream_scan_requires_exact_owned_terminal_failure_proof() {
        for required in [
            "job.job_type = 'OBSERVE_RUNMILL_RUN'",
            "job.activity_contract_id = $3",
            "job.status = 'DEAD'",
            "job.dead_letter_escalation_id IS NOT NULL",
            "job.dead_letter_operational_incident_id IS NULL",
            "escalation.category = 'WORKFLOW_JOB_EXHAUSTED'",
            "escalation.status IN ('OPEN', 'ACKNOWLEDGED')",
            "escalation.authority_or_effect_active",
            "checkpoint.after_sequence = stream.next_after_sequence",
            "checkpoint.observation_epoch = stream.observation_epoch",
            "job.payload ->> 'schema' = 'asf.runmill-observation/v2'",
            "job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)",
            "job.result ->> 'schema' = 'asf.workflow-job-dead-letter-result/v1'",
            "job.result ->> 'error_digest' ~ '^sha256:[0-9a-f]{64}$'",
            "job.result #>> '{escalation,id}' = escalation.id::text",
            "'workflow-job-error:' || job.id::text || ':' || (job.result ->> 'error_digest')",
            "FROM runmill_run_observation_results AS result",
            // The pre-scan must exclude every independently existing piece of
            // evidence whose absence the insert trigger re-proves under lock,
            // or one poisoned candidate aborts the whole tenant transaction.
            "FROM runmill_observation_gap_escalation_bindings AS binding",
            "FROM runmill_control_snapshots AS snapshot",
            "FOR UPDATE OF stream SKIP LOCKED",
        ] {
            assert!(
                SELECT_DEAD_PINNED_STREAMS_SQL.contains(required),
                "missing {required}"
            );
        }
        for forbidden in ["next_after_sequence =", "last_snapshot_id"] {
            assert!(
                !RELEASE_DEAD_PINNED_STREAM_SQL.contains(forbidden),
                "terminal-failure release must not touch {forbidden}"
            );
        }
        assert!(RELEASE_DEAD_PINNED_STREAM_SQL.contains("state = 'ESCALATED'"));
        assert!(RELEASE_DEAD_PINNED_STREAM_SQL.contains("stream.aggregate_version = $5"));
    }

    #[test]
    fn dead_pinned_stream_identity_uses_safe_integer_and_digest_bounds() {
        let valid = DeadPinnedStream {
            run_id: Uuid::now_v7(),
            workflow_job_id: Uuid::now_v7(),
            observation_id: Uuid::now_v7(),
            after_sequence: MAX_RUNMILL_SEQUENCE,
            observation_epoch: 1,
            aggregate_version: 2,
            escalation_id: Uuid::now_v7(),
            failure_digest: format!("sha256:{}", "a".repeat(64)),
        };
        assert!(validate_dead_pinned_stream(&valid).is_ok());

        for invalid in [
            DeadPinnedStream {
                after_sequence: MAX_RUNMILL_SEQUENCE + 1,
                ..valid.clone()
            },
            DeadPinnedStream {
                observation_epoch: 0,
                ..valid.clone()
            },
            DeadPinnedStream {
                aggregate_version: 0,
                ..valid.clone()
            },
            DeadPinnedStream {
                escalation_id: Uuid::nil(),
                ..valid.clone()
            },
            DeadPinnedStream {
                failure_digest: "sha256:not-a-digest".into(),
                ..valid.clone()
            },
        ] {
            assert!(validate_dead_pinned_stream(&invalid).is_err());
        }
    }

    #[test]
    fn terminal_failure_fact_trigger_reproves_every_release_coordinate() {
        let migration = include_str!("../../migrations/0022_runmill_observation_streams.sql");
        for required in [
            "CREATE TABLE runmill_observation_terminal_failure_facts",
            "failure_digest text NOT NULL",
            "CREATE FUNCTION asf_assert_runmill_observation_terminal_failure_fact_insert()",
            "runmill_observation_terminal_failure_facts_exact_proof",
            "AND job.status = 'DEAD'",
            "AND job.dead_letter_escalation_id = NEW.escalation_id",
            "AND job.result ->> 'error_digest' = NEW.failure_digest",
            "AND job.result #>> '{escalation,id}' = NEW.escalation_id::text",
            "'workflow-job-type:' || NEW.workflow_job_id::text || ':OBSERVE_RUNMILL_RUN'",
            "AND stream.active_observation_id = NEW.observation_id",
            "AND stream.next_after_sequence = NEW.after_sequence",
            "AND stream.observation_epoch = NEW.observation_epoch",
            "FROM runmill_observation_gap_escalation_bindings AS binding",
            "FROM runmill_control_snapshots AS snapshot",
            "FOR SHARE OF checkpoint, stream, job, escalation",
            "runmill_observation_terminal_failure_fact_append_only",
            "runmill_observation_terminal_failure_fact_truncate_forbidden",
            "FROM runmill_observation_terminal_failure_facts AS fact",
            "AND NEW.last_snapshot_id IS NOT DISTINCT FROM OLD.last_snapshot_id",
            "AND NEW.last_error_digest = fact.failure_digest",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn checkpoint_trigger_rechecks_the_producer_authority_under_lock() {
        let migration = include_str!("../../migrations/0022_runmill_observation_streams.sql");
        for required in [
            "CREATE FUNCTION asf_assert_runmill_observation_checkpoint_insert()",
            "jsonb_typeof(job.payload -> 'external_run_id') = 'string'",
            "jsonb_typeof(job.payload -> 'observation_epoch') = 'number'",
            "JOIN runs AS run",
            "run.authoritative",
            "JOIN work_orders AS work_order",
            "JOIN attempts AS attempt",
            "JOIN work_items AS work",
            "JOIN workflow_instances AS workflow",
            "work.state NOT IN ('CLOSED', 'CANCELLED')",
            "workflow.state IN ('ACTIVE', 'WAITING')",
            "FOR UPDATE OF stream, job, run, work_order, attempt, work, workflow, observer_session, worker",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }
}
