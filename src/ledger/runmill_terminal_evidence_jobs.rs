//! Durable production of Runmill terminal evidence retention jobs.
//!
//! An observation stream that reaches `TERMINAL_READY` has proved, through one
//! exact observation result, that its run reached a terminal phase at a known
//! external sequence. The bundle itself is a separate read: Runmill's signed
//! terminal evidence is fetched with `asf.get_evidence`, not with the two
//! snapshots that proved the phase. This producer is the bridge between those
//! two facts, and nothing more.
//!
//! It mints at most one retention job per terminal observation. The job's
//! idempotency key is the observation itself, so a completed retention never
//! re-enqueues, and a run that already carries a retained bundle is never
//! selected again. Nothing here reads Runmill, signs anything, or advances the
//! stream: it only decides that one exact retention is worth attempting.

use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::persistence_error;
use crate::{Error, Result, crypto::is_sha256_digest};

const RETAIN_RUNMILL_TERMINAL_EVIDENCE: &str = "RETAIN_RUNMILL_TERMINAL_EVIDENCE";
const RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID: &str =
    "asf.activity/retain-runmill-terminal-evidence/v1";
const TERMINAL_EVIDENCE_PAYLOAD_SCHEMA_V1: &str = "asf.runmill-terminal-evidence/v1";
const TERMINAL_EVIDENCE_JOB_PRIORITY: i16 = 70;
const TERMINAL_EVIDENCE_JOB_MAX_ATTEMPTS: i32 = 25;
const MAX_PRODUCTION_BATCH: u32 = 1_000;
const MAX_RUNMILL_SEQUENCE: i64 = 9_007_199_254_740_991;

/// Streams that reached `TERMINAL_READY` and still owe a terminal evidence
/// bundle.
///
/// Every coordinate migration 0035's insert guard re-proves under lock is
/// proved here first, so an unprovable stream is skipped instead of minting a
/// job that could never commit. That includes both snapshots' exact roles and
/// terminal phases, the event page's sequence boundary, and the live observer
/// session that will own the control read.
const SELECT_TERMINAL_READY_STREAMS_SQL: &str = r"
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
    result.observation_id,
    result.get_run_snapshot_id,
    result.event_page_snapshot_id,
    result.next_sequence,
    get_run.raw_snapshot #>> '{run,state}' AS terminal_phase,
    observer_session.id AS observer_session_id
FROM runmill_run_observation_streams AS stream
JOIN runmill_run_observation_results AS result
  ON result.tenant_id = stream.tenant_id
 AND result.run_id = stream.run_id
 AND result.disposition = 'TERMINAL_READY'
 AND NOT result.gap
 AND NOT result.has_more
JOIN runmill_control_snapshots AS get_run
  ON get_run.tenant_id = stream.tenant_id
 AND get_run.id = result.get_run_snapshot_id
 AND get_run.control_operation = 'GET_RUN'
 AND get_run.run_id = stream.run_id
 AND get_run.work_item_id = stream.work_item_id
 AND get_run.attempt_id = stream.attempt_id
 AND get_run.work_order_id = stream.work_order_id
 AND get_run.work_order_digest = stream.work_order_digest
 AND get_run.worker_session_id = stream.run_admission_worker_session_id
 AND get_run.worker_id = stream.worker_id
 AND get_run.worker_generation = stream.worker_generation
 AND get_run.external_run_id = stream.external_run_id
 AND get_run.observation_id = result.observation_id
JOIN runmill_control_snapshots AS event_page
  ON event_page.tenant_id = stream.tenant_id
 AND event_page.id = result.event_page_snapshot_id
 AND event_page.control_operation = 'LIST_RUN_EVENTS'
 AND event_page.run_id = stream.run_id
 AND event_page.work_item_id = stream.work_item_id
 AND event_page.attempt_id = stream.attempt_id
 AND event_page.work_order_id = stream.work_order_id
 AND event_page.work_order_digest = stream.work_order_digest
 AND event_page.worker_session_id = stream.run_admission_worker_session_id
 AND event_page.worker_id = stream.worker_id
 AND event_page.worker_generation = stream.worker_generation
 AND event_page.external_run_id = stream.external_run_id
 AND event_page.observation_id = result.observation_id
 AND event_page.external_latest_sequence = result.next_sequence
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
  AND stream.state = 'TERMINAL_READY'
  AND get_run.raw_snapshot #>> '{run,state}' IN (
      'COMPLETED', 'CANCELLED', 'FAILED', 'REFUSED', 'QUARANTINED', 'BUDGET_EXHAUSTED'
  )
  AND event_page.raw_snapshot #>> '{snapshot,run,state}'
      = get_run.raw_snapshot #>> '{run,state}'
  AND NOT EXISTS (
      SELECT 1
      FROM runmill_terminal_evidence_bundles AS bundle
      WHERE bundle.tenant_id = stream.tenant_id
        AND bundle.run_id = stream.run_id
  )
ORDER BY stream.run_id
FOR UPDATE OF stream SKIP LOCKED
LIMIT $3
";

/// How many retention jobs one bounded producer pass enqueued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunmillTerminalEvidenceProductionReport {
    pub jobs_enqueued: u32,
}

/// One terminal observation that still owes a retained bundle.
#[derive(Debug, Clone)]
struct TerminalReadyStream {
    run_id: Uuid,
    workflow_instance_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    worker_id: Uuid,
    worker_generation: i64,
    run_admission_worker_session_id: Uuid,
    observer_session_id: Uuid,
    external_run_id: String,
    observation_id: Uuid,
    get_run_snapshot_id: Uuid,
    event_page_snapshot_id: Uuid,
    terminal_phase: String,
    /// The terminal event's own sequence: one past the last sequence the event
    /// page observed, exactly as migration 0035 requires.
    terminal_event_seq: i64,
}

/// Enqueue one retention job for every terminal observation that still owes a
/// bundle, bounded by `limit`.
///
/// The scan is `SKIP LOCKED`, so a concurrent producer never blocks it, and the
/// job's idempotency key is the observation, so a crash between insert and
/// commit simply leaves the same provable candidate for the next pass. A job
/// whose key already exists — pending, running, or long completed — is counted
/// as nothing and silently skipped: retention already happened or is in flight.
///
/// # Errors
///
/// Returns [`Error::Validation`] for a nil tenant or an out-of-range limit,
/// [`Error::Conflict`] when a locked candidate is missing a coordinate the
/// insert guard requires, and [`Error::Persistence`] on database failure.
pub async fn produce_due_runmill_terminal_evidence_jobs(
    pool: &PgPool,
    tenant_id: Uuid,
    ready_worker_ids: &[String],
    limit: u32,
) -> Result<RunmillTerminalEvidenceProductionReport> {
    if tenant_id.is_nil() || limit == 0 || limit > MAX_PRODUCTION_BATCH {
        return Err(Error::Validation(
            "Runmill terminal evidence production requires a non-nil tenant and a limit in 1..=1000"
                .into(),
        ));
    }
    if ready_worker_ids.is_empty() {
        return Ok(RunmillTerminalEvidenceProductionReport::default());
    }

    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| persistence_error("begin Runmill terminal evidence production", error))?;
    let rows = sqlx::query(SELECT_TERMINAL_READY_STREAMS_SQL)
        .bind(tenant_id)
        .bind(ready_worker_ids)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| {
            persistence_error("lock terminal-ready Runmill observation streams", error)
        })?;

    let mut jobs_enqueued = 0_u32;
    for row in rows {
        let candidate = terminal_ready_stream(&row)?;
        if schedule_terminal_evidence_job(&mut transaction, tenant_id, &candidate).await? {
            jobs_enqueued = jobs_enqueued.checked_add(1).ok_or_else(|| {
                Error::Persistence("terminal evidence production count overflowed".into())
            })?;
        }
    }
    transaction
        .commit()
        .await
        .map_err(|error| persistence_error("commit Runmill terminal evidence production", error))?;
    Ok(RunmillTerminalEvidenceProductionReport { jobs_enqueued })
}

/// The logical identity of one retention. Two passes that select the same
/// terminal observation mint the same key, so the second inserts nothing.
#[must_use]
fn terminal_evidence_idempotency_key(run_id: Uuid, observation_id: Uuid) -> String {
    format!("runmill-terminal-evidence:{run_id}:{observation_id}")
}

/// Insert one retention job, or report that its exact key already exists.
async fn schedule_terminal_evidence_job(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    candidate: &TerminalReadyStream,
) -> Result<bool> {
    let job_id = Uuid::now_v7();
    // The bundle row identity is minted here rather than in the handler so a
    // retried retention reuses one identity instead of leaving an abandoned
    // uuid behind on every attempt.
    let bundle_id = Uuid::now_v7();
    let payload = json!({
        "schema": TERMINAL_EVIDENCE_PAYLOAD_SCHEMA_V1,
        "bundle_id": bundle_id,
        "run_id": candidate.run_id,
        "work_order_id": candidate.work_order_id,
        "work_order_digest": candidate.work_order_digest,
        "worker_id": candidate.worker_id,
        "worker_session_id": candidate.run_admission_worker_session_id,
        "worker_generation": candidate.worker_generation,
        "observer_session_id": candidate.observer_session_id,
        "external_run_id": candidate.external_run_id,
        "observation_id": candidate.observation_id,
        "get_run_snapshot_id": candidate.get_run_snapshot_id,
        "event_page_snapshot_id": candidate.event_page_snapshot_id,
        "terminal_phase": candidate.terminal_phase,
        "terminal_event_seq": candidate.terminal_event_seq,
    });
    let idempotency_key =
        terminal_evidence_idempotency_key(candidate.run_id, candidate.observation_id);

    let inserted = sqlx::query_scalar::<_, Uuid>(
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
    .bind(candidate.workflow_instance_id)
    .bind(candidate.work_item_id)
    .bind(candidate.attempt_id)
    .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE)
    .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID)
    .bind(&payload)
    .bind(&idempotency_key)
    .bind(TERMINAL_EVIDENCE_JOB_PRIORITY)
    .bind(TERMINAL_EVIDENCE_JOB_MAX_ATTEMPTS)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert Runmill terminal evidence job", error))?;
    Ok(inserted == Some(job_id))
}

fn terminal_ready_stream(row: &PgRow) -> Result<TerminalReadyStream> {
    let next_sequence: i64 = required(row, "next_sequence", "observed sequence boundary")?;
    let candidate = TerminalReadyStream {
        run_id: required(row, "run_id", "observation stream run")?,
        workflow_instance_id: required(row, "workflow_instance_id", "workflow")?,
        work_item_id: required(row, "work_item_id", "work item")?,
        attempt_id: required(row, "attempt_id", "attempt")?,
        work_order_id: required(row, "work_order_id", "Work Order")?,
        work_order_digest: required(row, "work_order_digest", "Work Order digest")?,
        worker_id: required(row, "worker_id", "worker")?,
        worker_generation: required(row, "worker_generation", "worker generation")?,
        run_admission_worker_session_id: required(
            row,
            "run_admission_worker_session_id",
            "run admission session",
        )?,
        observer_session_id: required(row, "observer_session_id", "observer session")?,
        external_run_id: required(row, "external_run_id", "external run")?,
        observation_id: required(row, "observation_id", "terminal observation")?,
        get_run_snapshot_id: required(row, "get_run_snapshot_id", "GET_RUN snapshot")?,
        event_page_snapshot_id: required(
            row,
            "event_page_snapshot_id",
            "LIST_RUN_EVENTS snapshot",
        )?,
        terminal_phase: required(row, "terminal_phase", "terminal phase")?,
        terminal_event_seq: terminal_event_sequence(next_sequence)?,
    };
    validate_terminal_ready_stream(&candidate)?;
    Ok(candidate)
}

/// The terminal event is the one appended after every sequence the event page
/// observed, which is exactly what migration 0035 requires the bundle to state.
fn terminal_event_sequence(observed_sequence: i64) -> Result<i64> {
    observed_sequence
        .checked_add(1)
        .filter(|sequence| (1..=MAX_RUNMILL_SEQUENCE).contains(sequence))
        .ok_or_else(|| {
            Error::Conflict(
                "Runmill terminal event sequence exceeded the supported protocol range".into(),
            )
        })
}

fn validate_terminal_ready_stream(candidate: &TerminalReadyStream) -> Result<()> {
    if [
        candidate.run_id,
        candidate.workflow_instance_id,
        candidate.work_item_id,
        candidate.attempt_id,
        candidate.work_order_id,
        candidate.worker_id,
        candidate.run_admission_worker_session_id,
        candidate.observer_session_id,
        candidate.observation_id,
        candidate.get_run_snapshot_id,
        candidate.event_page_snapshot_id,
    ]
    .into_iter()
    .any(|id| id.is_nil())
        || candidate.get_run_snapshot_id == candidate.event_page_snapshot_id
        || candidate.worker_generation <= 0
        || candidate.external_run_id.trim().is_empty()
        || candidate.terminal_phase.trim().is_empty()
        || !is_sha256_digest(&candidate.work_order_digest)
    {
        return Err(Error::Conflict(format!(
            "Runmill observation stream {} lacks a provable terminal evidence identity",
            candidate.run_id
        )));
    }
    Ok(())
}

fn required<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        persistence_error(
            &format!("decode {description} from terminal-ready Runmill stream"),
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> TerminalReadyStream {
        TerminalReadyStream {
            run_id: Uuid::now_v7(),
            workflow_instance_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            work_order_digest: format!("sha256:{}", "a".repeat(64)),
            worker_id: Uuid::now_v7(),
            worker_generation: 3,
            run_admission_worker_session_id: Uuid::now_v7(),
            observer_session_id: Uuid::now_v7(),
            external_run_id: "run-123".into(),
            observation_id: Uuid::now_v7(),
            get_run_snapshot_id: Uuid::now_v7(),
            event_page_snapshot_id: Uuid::now_v7(),
            terminal_phase: "COMPLETED".into(),
            terminal_event_seq: 10,
        }
    }

    #[test]
    fn terminal_event_sequence_is_one_past_the_observed_boundary() {
        assert_eq!(terminal_event_sequence(0).unwrap(), 1);
        assert_eq!(terminal_event_sequence(9).unwrap(), 10);
        assert!(terminal_event_sequence(MAX_RUNMILL_SEQUENCE).is_err());
        assert!(terminal_event_sequence(i64::MAX).is_err());
    }

    #[test]
    fn candidate_accepts_a_complete_terminal_identity() {
        assert!(validate_terminal_ready_stream(&candidate()).is_ok());
    }

    #[test]
    fn candidate_rejects_missing_or_conflated_authority() {
        let shared = Uuid::now_v7();
        for invalid in [
            TerminalReadyStream {
                run_id: Uuid::nil(),
                ..candidate()
            },
            TerminalReadyStream {
                observation_id: Uuid::nil(),
                ..candidate()
            },
            TerminalReadyStream {
                observer_session_id: Uuid::nil(),
                ..candidate()
            },
            // One snapshot can never satisfy both provenance roles.
            TerminalReadyStream {
                get_run_snapshot_id: shared,
                event_page_snapshot_id: shared,
                ..candidate()
            },
            TerminalReadyStream {
                worker_generation: 0,
                ..candidate()
            },
            TerminalReadyStream {
                external_run_id: "  ".into(),
                ..candidate()
            },
            TerminalReadyStream {
                terminal_phase: String::new(),
                ..candidate()
            },
            TerminalReadyStream {
                work_order_digest: "not-a-digest".into(),
                ..candidate()
            },
        ] {
            assert!(validate_terminal_ready_stream(&invalid).is_err());
        }
    }

    #[test]
    fn idempotency_key_binds_the_run_and_its_terminal_observation() {
        let candidate = candidate();
        let key = terminal_evidence_idempotency_key(candidate.run_id, candidate.observation_id);
        assert_eq!(
            key,
            format!(
                "runmill-terminal-evidence:{}:{}",
                candidate.run_id, candidate.observation_id
            )
        );
        assert_eq!(
            key,
            terminal_evidence_idempotency_key(candidate.run_id, candidate.observation_id)
        );
        assert_ne!(
            key,
            terminal_evidence_idempotency_key(candidate.run_id, Uuid::now_v7())
        );
        assert_ne!(
            key,
            terminal_evidence_idempotency_key(Uuid::now_v7(), candidate.observation_id)
        );
    }

    #[test]
    fn producer_selects_only_terminal_ready_streams_that_still_owe_a_bundle() {
        for required in [
            "stream.state = 'TERMINAL_READY'",
            "result.disposition = 'TERMINAL_READY'",
            "get_run.control_operation = 'GET_RUN'",
            "event_page.control_operation = 'LIST_RUN_EVENTS'",
            "event_page.external_latest_sequence = result.next_sequence",
            "FROM runmill_terminal_evidence_bundles AS bundle",
            "FOR UPDATE OF stream SKIP LOCKED",
        ] {
            assert!(
                SELECT_TERMINAL_READY_STREAMS_SQL.contains(required),
                "missing {required}"
            );
        }
        // Production decides what to attempt; it never mutates the stream, the
        // run, or any evidence.
        for forbidden in ["UPDATE runmill_run_observation_streams", "UPDATE runs"] {
            assert!(
                !SELECT_TERMINAL_READY_STREAMS_SQL.contains(forbidden),
                "unexpected {forbidden}"
            );
        }
    }
}
