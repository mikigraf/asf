//! Worker-session-and-generation-fenced Runmill event ingestion.
//!
//! This module locks the durable session, its worker generation, and the
//! adopted run before retaining a raw event. Raw storage and projection are
//! performed through a caller-owned transaction so terminal run projection can
//! be composed with the workflow/accountability transition it triggers.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::persistence_error;
use crate::{Error, Result, contracts::ProductEvent, ports::runmill::PRODUCT_EVENT_SCHEMA_V1};

const LOCK_WORKER_SESSION_SQL: &str = r"
SELECT
    session.worker_generation,
    session.status,
    session.expires_at > clock_timestamp() AS session_is_live,
    worker.generation AS current_worker_generation
FROM worker_sessions AS session
JOIN workers AS worker
  ON worker.tenant_id = session.tenant_id
 AND worker.id = session.worker_id
WHERE session.tenant_id = $1
  AND session.id = $2
  AND session.worker_id = $3
FOR UPDATE OF session, worker
";

const LOCK_RUN_PROJECTION_SQL: &str = r"
SELECT
    run.worker_id,
    run.worker_generation,
    run.worker_session_id,
    run.work_item_id,
    run.attempt_id,
    work_order.payload_digest AS work_order_digest,
    run.authoritative,
    run.state,
    run.last_event_cursor,
    run.last_event_sequence,
    run.aggregate_version
FROM runs AS run
JOIN work_orders AS work_order
  ON work_order.tenant_id = run.tenant_id
 AND work_order.id = run.work_order_id
WHERE run.tenant_id = $1
  AND run.id = $2
FOR UPDATE OF run
";

const INSERT_RAW_EVENT_SQL: &str = r"
INSERT INTO raw_run_events (
    id,
    tenant_id,
    run_id,
    worker_session_id,
    worker_id,
    worker_generation,
    external_event_id,
    cursor,
    sequence,
    run_aggregate_version,
    schema_version,
    event_type,
    occurred_at,
    payload
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT DO NOTHING
RETURNING id
";

const NEXT_RAW_EVENT_SQL: &str = r"
SELECT
    event.id,
    event.worker_session_id,
    event.worker_id,
    event.worker_generation,
    event.external_event_id,
    event.cursor,
    event.sequence,
    event.run_aggregate_version,
    event.schema_version,
    event.event_type,
    event.occurred_at,
    event.payload,
    application.run_id AS applied_run_id,
    application.run_aggregate_version AS applied_aggregate_version
FROM raw_run_events AS event
LEFT JOIN run_event_applications AS application
  ON application.tenant_id = event.tenant_id
 AND application.run_event_id = event.id
WHERE event.tenant_id = $1
  AND event.run_id = $2
  AND event.sequence = $3
FOR UPDATE OF event
";

const UPDATE_RUN_PROJECTION_SQL: &str = r"
UPDATE runs AS run
SET state = $10,
    last_event_cursor = $9,
    last_event_sequence = $8,
    snapshot = $11,
    aggregate_version = $12,
    last_observed_at = clock_timestamp(),
    terminal_at = CASE
        WHEN $10 IN ('SUCCEEDED', 'FAILED', 'REFUSED', 'CANCELLED', 'QUARANTINED')
            THEN COALESCE(run.terminal_at, $13)
        ELSE run.terminal_at
    END
WHERE run.tenant_id = $1
  AND run.id = $2
  AND run.worker_session_id = $3
  AND run.worker_id = $4
  AND run.worker_generation = $5
  AND run.authoritative
  AND run.last_event_sequence = $6
  AND run.aggregate_version = $7
RETURNING run.state, run.last_event_cursor, run.last_event_sequence, run.aggregate_version
";

const INSERT_EVENT_APPLICATION_SQL: &str = r"
INSERT INTO run_event_applications (
    tenant_id,
    run_event_id,
    run_id,
    run_aggregate_version
)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, run_event_id) DO NOTHING
RETURNING run_event_id
";

/// The durable worker session and generation authorized to report for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerSessionFence {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub worker_id: Uuid,
    pub generation: i64,
}

impl WorkerSessionFence {
    fn validate(self) -> Result<()> {
        if self.tenant_id.is_nil()
            || self.session_id.is_nil()
            || self.worker_id.is_nil()
            || self.generation <= 0
        {
            return Err(Error::Validation(
                "worker session requires non-nil tenant/session/worker IDs and a positive generation".into(),
            ));
        }
        Ok(())
    }
}

/// One cursor-addressed raw worker event.
///
/// `raw_event` is retained exactly at the JSON value level. For the supported
/// schema it must deserialize as [`ProductEvent`]. Unknown schema values are
/// intentionally accepted and retained, but are never applied to the run
/// projection.
#[derive(Debug, Clone, PartialEq)]
pub struct IncomingRunEvent {
    pub id: Uuid,
    pub run_id: Uuid,
    pub external_event_id: String,
    pub cursor: String,
    /// Run-scoped delivery sequence.  Sequence one is the first event.
    pub sequence: i64,
    pub aggregate_version: i64,
    pub schema_version: String,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub raw_event: Value,
}

impl IncomingRunEvent {
    fn validate(&self) -> Result<()> {
        if self.id.is_nil()
            || self.run_id.is_nil()
            || self.external_event_id.trim().is_empty()
            || self.cursor.trim().is_empty()
            || self.schema_version.trim().is_empty()
            || self.event_type.trim().is_empty()
            || !self.raw_event.is_object()
        {
            return Err(Error::Validation(
                "raw run event has missing identity, cursor, schema, type, or object payload"
                    .into(),
            ));
        }
        if self.sequence <= 0 || self.aggregate_version <= 0 {
            return Err(Error::Validation(
                "run event sequence and aggregate version must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEventProjectionBlock {
    SequenceGap { expected: i64 },
    AggregateVersionGap { expected: i64, received: i64 },
    UnsupportedSchema { schema_version: String },
    UnsupportedEventType { event_type: String },
    InvalidKnownEnvelope { reason: String },
    InvalidStateTransition { from: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEventIngestionDisposition {
    Applied,
    DuplicateApplied,
    RetainedUnapplied(RunEventProjectionBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEventIngestionOutcome {
    pub event_id: Uuid,
    pub inserted: bool,
    pub applied_event_count: u32,
    pub disposition: RunEventIngestionDisposition,
    pub last_event_cursor: Option<String>,
    pub last_event_sequence: i64,
    pub run_aggregate_version: i64,
}

#[derive(Debug, Clone)]
struct LockedRun {
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_digest: String,
    state: String,
    last_event_cursor: Option<String>,
    last_event_sequence: i64,
    aggregate_version: i64,
}

#[derive(Debug)]
struct DrainOutcome {
    applied_count: u32,
    block: Option<RunEventProjectionBlock>,
}

#[derive(Debug)]
struct DecodedProjection {
    state: String,
    snapshot: Value,
    aggregate_version: i64,
}

/// Retain and, when safe, project a Runmill event in one transaction.
///
/// The function first locks both the current worker generation and the adopted
/// run.  It stores duplicate-delivered raw events idempotently, then drains only
/// the contiguous `(sequence, aggregate_version)` prefix.  An unknown schema,
/// unknown event type, invalid binding, or version gap remains in
/// `raw_run_events` and blocks later projection; in particular it cannot move a
/// run to `SUCCEEDED` or advance the durable cursor.
///
/// # Errors
///
/// Returns a conflict for a stale worker generation, non-authoritative run, or
/// reused raw-event identity with different semantics.  Database errors are
/// returned without committing the caller-owned transaction.
pub async fn ingest_run_event(
    transaction: &mut Transaction<'_, Postgres>,
    session: WorkerSessionFence,
    incoming: &IncomingRunEvent,
) -> Result<RunEventIngestionOutcome> {
    session.validate()?;
    incoming.validate()?;
    let mut run = lock_worker_and_run(transaction, session, incoming.run_id).await?;
    let (stored_event_id, inserted) = store_raw_event(transaction, session, incoming).await?;

    let drain = drain_contiguous_events(transaction, session, incoming.run_id, &mut run).await?;
    let target_applied = event_is_applied(
        transaction,
        session.tenant_id,
        incoming.run_id,
        stored_event_id,
    )
    .await?;

    let disposition = if target_applied {
        if inserted {
            RunEventIngestionDisposition::Applied
        } else {
            RunEventIngestionDisposition::DuplicateApplied
        }
    } else {
        let block = drain.block.unwrap_or(RunEventProjectionBlock::SequenceGap {
            expected: run
                .last_event_sequence
                .checked_add(1)
                .ok_or_else(|| Error::Conflict("run event sequence overflowed".into()))?,
        });
        RunEventIngestionDisposition::RetainedUnapplied(block)
    };

    Ok(RunEventIngestionOutcome {
        event_id: stored_event_id,
        inserted,
        applied_event_count: drain.applied_count,
        disposition,
        last_event_cursor: run.last_event_cursor,
        last_event_sequence: run.last_event_sequence,
        run_aggregate_version: run.aggregate_version,
    })
}

async fn lock_worker_and_run(
    transaction: &mut Transaction<'_, Postgres>,
    session: WorkerSessionFence,
    run_id: Uuid,
) -> Result<LockedRun> {
    let session_row = sqlx::query(LOCK_WORKER_SESSION_SQL)
        .bind(session.tenant_id)
        .bind(session.session_id)
        .bind(session.worker_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock run-event worker session", error))?
        .ok_or_else(|| Error::NotFound(format!("worker session {}", session.session_id)))?;
    let session_generation: i64 = required_column(
        &session_row,
        "worker_generation",
        "worker session generation",
    )?;
    let current_generation: i64 = required_column(
        &session_row,
        "current_worker_generation",
        "current worker generation",
    )?;
    let session_status: String = required_column(&session_row, "status", "worker session status")?;
    let session_is_live: bool =
        required_column(&session_row, "session_is_live", "worker session liveness")?;
    if session_generation != session.generation || current_generation != session.generation {
        return Err(stale_generation_error(
            session.worker_id,
            session.generation,
            current_generation,
        ));
    }
    if session_status != "ACTIVE" || !session_is_live {
        return Err(Error::Conflict(format!(
            "worker session {} is closed, revoked, or expired",
            session.session_id
        )));
    }

    let row = sqlx::query(LOCK_RUN_PROJECTION_SQL)
        .bind(session.tenant_id)
        .bind(run_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock run-event projection", error))?
        .ok_or_else(|| Error::NotFound(format!("run {run_id}")))?;
    let worker_id: Uuid = required_column(&row, "worker_id", "run worker")?;
    let worker_generation: i64 =
        required_column(&row, "worker_generation", "run worker generation")?;
    let worker_session_id: Uuid = required_column(&row, "worker_session_id", "run worker session")?;
    let authoritative: bool = required_column(&row, "authoritative", "authoritative run flag")?;
    if worker_id != session.worker_id
        || worker_generation != session.generation
        || worker_session_id != session.session_id
    {
        return Err(Error::Conflict(format!(
            "run {run_id} is not bound to worker session {} generation {}",
            session.session_id, session.generation
        )));
    }
    if !authoritative {
        return Err(Error::Conflict(format!(
            "run {run_id} is not the authoritative run for its attempt"
        )));
    }

    Ok(LockedRun {
        work_item_id: required_column(&row, "work_item_id", "run work item")?,
        attempt_id: required_column(&row, "attempt_id", "run attempt")?,
        work_order_digest: required_column(&row, "work_order_digest", "run Work Order digest")?,
        state: required_column(&row, "state", "run state")?,
        last_event_cursor: optional_column(&row, "last_event_cursor", "run event cursor")?,
        last_event_sequence: required_column(&row, "last_event_sequence", "run event sequence")?,
        aggregate_version: required_column(&row, "aggregate_version", "run version")?,
    })
}

async fn store_raw_event(
    transaction: &mut Transaction<'_, Postgres>,
    session: WorkerSessionFence,
    incoming: &IncomingRunEvent,
) -> Result<(Uuid, bool)> {
    let inserted = sqlx::query(INSERT_RAW_EVENT_SQL)
        .bind(incoming.id)
        .bind(session.tenant_id)
        .bind(incoming.run_id)
        .bind(session.session_id)
        .bind(session.worker_id)
        .bind(session.generation)
        .bind(&incoming.external_event_id)
        .bind(&incoming.cursor)
        .bind(incoming.sequence)
        .bind(incoming.aggregate_version)
        .bind(&incoming.schema_version)
        .bind(&incoming.event_type)
        .bind(incoming.occurred_at)
        .bind(&incoming.raw_event)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("store raw run event", error))?;
    if inserted.is_some() {
        return Ok((incoming.id, true));
    }

    let rows = sqlx::query(
        r"
        SELECT
            id,
            worker_session_id,
            worker_id,
            worker_generation,
            external_event_id,
            cursor,
            sequence,
            run_aggregate_version,
            schema_version,
            event_type,
            occurred_at,
            payload
        FROM raw_run_events
        WHERE tenant_id = $1
          AND run_id = $2
          AND (
              external_event_id = $3
              OR cursor = $4
              OR sequence = $5
          )
        FOR UPDATE
        ",
    )
    .bind(session.tenant_id)
    .bind(incoming.run_id)
    .bind(&incoming.external_event_id)
    .bind(&incoming.cursor)
    .bind(incoming.sequence)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load deduplicated raw run event", error))?;
    if rows.len() != 1 {
        return Err(Error::Conflict(format!(
            "run event {} collides with multiple event identities",
            incoming.external_event_id
        )));
    }
    let row = &rows[0];
    let matches = required_column::<Uuid>(row, "worker_session_id", "raw worker session")?
        == session.session_id
        && required_column::<Uuid>(row, "worker_id", "raw worker")? == session.worker_id
        && required_column::<i64>(row, "worker_generation", "raw worker generation")?
            == session.generation
        && required_column::<String>(row, "external_event_id", "raw external event ID")?
            == incoming.external_event_id
        && required_column::<String>(row, "cursor", "raw event cursor")? == incoming.cursor
        && required_column::<i64>(row, "sequence", "raw event sequence")? == incoming.sequence
        && required_column::<i64>(row, "run_aggregate_version", "raw run version")?
            == incoming.aggregate_version
        && required_column::<String>(row, "schema_version", "raw event schema")?
            == incoming.schema_version
        && required_column::<String>(row, "event_type", "raw event type")? == incoming.event_type
        && required_column::<DateTime<Utc>>(row, "occurred_at", "raw occurrence time")?
            == incoming.occurred_at
        && required_column::<Value>(row, "payload", "raw event payload")? == incoming.raw_event;
    if !matches {
        return Err(Error::Conflict(format!(
            "run event identity {} was reused for different semantics",
            incoming.external_event_id
        )));
    }
    Ok((
        required_column(row, "id", "deduplicated raw event ID")?,
        false,
    ))
}

async fn drain_contiguous_events(
    transaction: &mut Transaction<'_, Postgres>,
    session: WorkerSessionFence,
    run_id: Uuid,
    run: &mut LockedRun,
) -> Result<DrainOutcome> {
    let mut applied_count = 0_u32;
    loop {
        let expected_sequence = run
            .last_event_sequence
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("run event sequence overflowed".into()))?;
        let Some(row) = sqlx::query(NEXT_RAW_EVENT_SQL)
            .bind(session.tenant_id)
            .bind(run_id)
            .bind(expected_sequence)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("load next contiguous raw run event", error))?
        else {
            return Ok(DrainOutcome {
                applied_count,
                block: Some(RunEventProjectionBlock::SequenceGap {
                    expected: expected_sequence,
                }),
            });
        };

        let applied_run_id: Option<Uuid> =
            optional_column(&row, "applied_run_id", "event application run")?;
        if let Some(applied_run_id) = applied_run_id {
            let applied_version: Option<i64> = optional_column(
                &row,
                "applied_aggregate_version",
                "event application version",
            )?;
            return Err(Error::Persistence(format!(
                "event sequence {expected_sequence} is already applied to run {applied_run_id} at version {applied_version:?}, but the run cursor did not advance"
            )));
        }

        let decoded = match decode_projection(&row, session, run_id, run) {
            Ok(decoded) => decoded,
            Err(block) => {
                return Ok(DrainOutcome {
                    applied_count,
                    block: Some(block),
                });
            }
        };
        let expected_aggregate = run
            .aggregate_version
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("run aggregate version overflowed".into()))?;
        if decoded.aggregate_version != expected_aggregate {
            return Ok(DrainOutcome {
                applied_count,
                block: Some(RunEventProjectionBlock::AggregateVersionGap {
                    expected: expected_aggregate,
                    received: decoded.aggregate_version,
                }),
            });
        }

        let event_id: Uuid = required_column(&row, "id", "raw event ID")?;
        let cursor: String = required_column(&row, "cursor", "raw event cursor")?;
        let occurred_at: DateTime<Utc> =
            required_column(&row, "occurred_at", "raw event occurrence time")?;
        let updated = sqlx::query(UPDATE_RUN_PROJECTION_SQL)
            .bind(session.tenant_id)
            .bind(run_id)
            .bind(session.session_id)
            .bind(session.worker_id)
            .bind(session.generation)
            .bind(run.last_event_sequence)
            .bind(run.aggregate_version)
            .bind(expected_sequence)
            .bind(&cursor)
            .bind(&decoded.state)
            .bind(&decoded.snapshot)
            .bind(decoded.aggregate_version)
            .bind(occurred_at)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("apply run event projection", error))?
            .ok_or_else(|| {
                Error::Conflict(format!(
                    "run {run_id} cursor, version, authority, or worker generation changed"
                ))
            })?;

        let application = sqlx::query(INSERT_EVENT_APPLICATION_SQL)
            .bind(session.tenant_id)
            .bind(event_id)
            .bind(run_id)
            .bind(decoded.aggregate_version)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("record run event application", error))?;
        if application.is_none() {
            return Err(Error::Conflict(format!(
                "raw run event {event_id} was concurrently applied"
            )));
        }

        run.state = required_column(&updated, "state", "projected run state")?;
        run.last_event_cursor =
            optional_column(&updated, "last_event_cursor", "projected event cursor")?;
        run.last_event_sequence =
            required_column(&updated, "last_event_sequence", "projected event sequence")?;
        run.aggregate_version =
            required_column(&updated, "aggregate_version", "projected run version")?;
        applied_count = applied_count
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("applied run event count overflowed".into()))?;
    }
}

fn decode_projection(
    row: &PgRow,
    session: WorkerSessionFence,
    run_id: Uuid,
    run: &LockedRun,
) -> std::result::Result<DecodedProjection, RunEventProjectionBlock> {
    let schema_version = raw_column::<String>(row, "schema_version")?;
    if schema_version != PRODUCT_EVENT_SCHEMA_V1 {
        return Err(RunEventProjectionBlock::UnsupportedSchema { schema_version });
    }
    let event_type = raw_column::<String>(row, "event_type")?;
    let occurred_at = raw_column::<DateTime<Utc>>(row, "occurred_at")?;
    let external_event_id = raw_column::<String>(row, "external_event_id")?;
    let stored_session_id = raw_column::<Uuid>(row, "worker_session_id")?;
    let stored_worker_id = raw_column::<Uuid>(row, "worker_id")?;
    let stored_generation = raw_column::<i64>(row, "worker_generation")?;
    let aggregate_version = raw_column::<i64>(row, "run_aggregate_version")?;
    if stored_session_id != session.session_id
        || stored_worker_id != session.worker_id
        || stored_generation != session.generation
    {
        return Err(invalid_envelope(
            "stored event belongs to a different worker session generation",
        ));
    }

    let raw_event = raw_column::<Value>(row, "payload")?;
    let event: ProductEvent = serde_json::from_value(raw_event.clone())
        .map_err(|error| invalid_envelope(&format!("invalid product event: {error}")))?;
    let aggregate_matches = i64::try_from(event.aggregate_version)
        .ok()
        .is_some_and(|version| version == aggregate_version);
    let bindings_match = event.schema == schema_version
        && event.event_id.to_string() == external_event_id
        && event.tenant_id.as_uuid() == session.tenant_id
        && event.work_item_id.map(crate::domain::WorkItemId::as_uuid) == Some(run.work_item_id)
        && event.attempt_id.map(crate::domain::AttemptId::as_uuid) == Some(run.attempt_id)
        && event.work_order_digest.as_deref() == Some(run.work_order_digest.as_str())
        && event.run_id.map(crate::domain::RunId::as_uuid) == Some(run_id)
        && event.event_type == event_type
        && event.occurred_at == occurred_at
        && aggregate_matches;
    if !bindings_match {
        return Err(invalid_envelope(
            "product event does not match its tenant, run, attempt, Work Order, metadata, or aggregate binding",
        ));
    }

    let projected_state = project_state(&run.state, &event_type)?;
    Ok(DecodedProjection {
        state: projected_state,
        snapshot: raw_event,
        aggregate_version,
    })
}

fn project_state(
    current: &str,
    event_type: &str,
) -> std::result::Result<String, RunEventProjectionBlock> {
    let target = match event_type {
        "run.accepted" | "run.adopted" => "ADOPTED",
        "run.started" | "run.running" => "RUNNING",
        "run.progressed" => current,
        "run.waiting_approval" => "WAITING_APPROVAL",
        "run.verifying" => "VERIFYING",
        "run.succeeded" | "run.target_reached" => "SUCCEEDED",
        "run.failed" => "FAILED",
        "run.refused" => "REFUSED",
        "run.cancel_requested" => "CANCEL_REQUESTED",
        "run.cancelled" => "CANCELLED",
        "run.quarantined" => "QUARANTINED",
        _ => {
            return Err(RunEventProjectionBlock::UnsupportedEventType {
                event_type: event_type.into(),
            });
        }
    };
    if valid_run_transition(current, target) {
        Ok(target.into())
    } else {
        Err(RunEventProjectionBlock::InvalidStateTransition {
            from: current.into(),
            to: target.into(),
        })
    }
}

fn valid_run_transition(current: &str, target: &str) -> bool {
    if current == target {
        return true;
    }
    match current {
        "ADOPTED" => matches!(
            target,
            "RUNNING"
                | "WAITING_APPROVAL"
                | "VERIFYING"
                | "SUCCEEDED"
                | "FAILED"
                | "REFUSED"
                | "CANCEL_REQUESTED"
                | "CANCELLED"
                | "QUARANTINED"
        ),
        "RUNNING" => matches!(
            target,
            "WAITING_APPROVAL"
                | "VERIFYING"
                | "SUCCEEDED"
                | "FAILED"
                | "REFUSED"
                | "CANCEL_REQUESTED"
                | "CANCELLED"
                | "QUARANTINED"
        ),
        "WAITING_APPROVAL" => matches!(
            target,
            "RUNNING"
                | "VERIFYING"
                | "SUCCEEDED"
                | "FAILED"
                | "REFUSED"
                | "CANCEL_REQUESTED"
                | "CANCELLED"
                | "QUARANTINED"
        ),
        "VERIFYING" => matches!(
            target,
            "WAITING_APPROVAL"
                | "SUCCEEDED"
                | "FAILED"
                | "REFUSED"
                | "CANCEL_REQUESTED"
                | "CANCELLED"
                | "QUARANTINED"
        ),
        "CANCEL_REQUESTED" => matches!(target, "CANCELLED" | "FAILED" | "QUARANTINED"),
        _ => false,
    }
}

async fn event_is_applied(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    run_id: Uuid,
    event_id: Uuid,
) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM run_event_applications
            WHERE tenant_id = $1
              AND run_id = $2
              AND run_event_id = $3
        )
        ",
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(event_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("check run event application", error))
}

fn raw_column<T>(row: &PgRow, column: &str) -> std::result::Result<T, RunEventProjectionBlock>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|error| invalid_envelope(&format!("cannot decode {column}: {error}")))
}

fn required_column<T>(row: &PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|error| persistence_error(&format!("decode {context}"), error))
}

fn optional_column<T>(row: &PgRow, column: &str, context: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|error| persistence_error(&format!("decode {context}"), error))
}

fn invalid_envelope(reason: &str) -> RunEventProjectionBlock {
    RunEventProjectionBlock::InvalidKnownEnvelope {
        reason: reason.into(),
    }
}

fn stale_generation_error(worker_id: Uuid, supplied: i64, current: i64) -> Error {
    Error::Conflict(format!(
        "worker {worker_id} generation {supplied} is stale; current generation is {current}"
    ))
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::Duration;
    use serde_json::json;

    use super::*;
    use crate::domain::{AttemptId, EventId, RunId, TenantId, WorkItemId};

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    #[test]
    fn ingestion_sql_is_tenant_generation_and_cursor_fenced() {
        assert!(LOCK_WORKER_SESSION_SQL.contains("session.tenant_id = $1"));
        assert!(LOCK_WORKER_SESSION_SQL.contains("session.id = $2"));
        assert!(LOCK_WORKER_SESSION_SQL.contains("session.expires_at > clock_timestamp()"));
        assert!(LOCK_WORKER_SESSION_SQL.contains("FOR UPDATE OF session, worker"));
        assert!(LOCK_RUN_PROJECTION_SQL.contains("run.tenant_id = $1"));
        assert!(LOCK_RUN_PROJECTION_SQL.contains("FOR UPDATE OF run"));
        assert!(UPDATE_RUN_PROJECTION_SQL.contains("run.worker_session_id = $3"));
        assert!(UPDATE_RUN_PROJECTION_SQL.contains("run.worker_generation = $5"));
        assert!(UPDATE_RUN_PROJECTION_SQL.contains("run.authoritative"));
        assert!(UPDATE_RUN_PROJECTION_SQL.contains("run.last_event_sequence = $6"));
        assert!(UPDATE_RUN_PROJECTION_SQL.contains("run.aggregate_version = $7"));
        assert!(INSERT_RAW_EVENT_SQL.contains("worker_session_id"));
        assert!(INSERT_RAW_EVENT_SQL.contains("run_aggregate_version"));
        assert!(INSERT_RAW_EVENT_SQL.contains("ON CONFLICT DO NOTHING"));
    }

    #[test]
    fn only_supported_schema_and_known_types_can_project() {
        assert_eq!(PRODUCT_EVENT_SCHEMA_V1, "asf.product-event.v1");
        assert!(matches!(
            project_state("RUNNING", "future.event"),
            Err(RunEventProjectionBlock::UnsupportedEventType { .. })
        ));
        assert_eq!(
            project_state("RUNNING", "run.target_reached").expect("known event"),
            "SUCCEEDED"
        );
        assert!(project_state("SUCCEEDED", "run.running").is_err());
    }

    #[test]
    fn worker_generation_pair_is_the_session_fence() {
        assert!(
            WorkerSessionFence {
                tenant_id: Uuid::now_v7(),
                session_id: Uuid::now_v7(),
                worker_id: Uuid::now_v7(),
                generation: 1,
            }
            .validate()
            .is_ok()
        );
        assert!(
            WorkerSessionFence {
                tenant_id: Uuid::now_v7(),
                session_id: Uuid::now_v7(),
                worker_id: Uuid::now_v7(),
                generation: 0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn incoming_event_requires_positive_contiguous_coordinates() {
        let event = IncomingRunEvent {
            id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            external_event_id: "event-1".into(),
            cursor: "cursor-1".into(),
            sequence: 0,
            aggregate_version: 2,
            schema_version: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_type: "run.progressed".into(),
            occurred_at: Utc::now().trunc_subsecs(6),
            raw_event: json!({}),
        };
        assert!(event.validate().is_err());
    }

    #[tokio::test]
    async fn live_ingestion_applies_one_fenced_event_when_database_is_configured() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = super::super::PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let mut transaction = ledger.pool().begin().await.expect("begin transaction");

        let tenant_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let work_order_id = Uuid::now_v7();
        let worker_id = Uuid::now_v7();
        let worker_session_id = Uuid::now_v7();
        let run_id = Uuid::now_v7();
        let now = Utc::now().trunc_subsecs(6);
        let policy_digest = digest('a');
        let work_order_digest = digest('b');

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("tenant-{tenant_id}"))
            .bind("Run event test")
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
            r"INSERT INTO source_snapshots
              (id, tenant_id, source_system, external_id, source_revision,
               normalized_content, content_digest, connector_identity, source_updated_at)
              VALUES ($1, $2, 'API', $3, '1', '{}'::jsonb, $4, 'test', $5)",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(format!("item-{work_item_id}"))
        .bind(digest('c'))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .expect("insert snapshot");
        sqlx::query(
            r"INSERT INTO work_items
              (id, tenant_id, source_snapshot_id, source_system, source_external_id,
               state, normalized_priority)
              VALUES ($1, $2, $3, 'API', $4, 'DISCOVERED', 50)",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(format!("item-{work_item_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert work item");
        sqlx::query(
            r"INSERT INTO attempts
              (id, tenant_id, work_item_id, ordinal, state, idempotency_key,
               base_ref, base_sha, source_snapshot_digest, policy_digest)
              VALUES ($1, $2, $3, 1, 'CREATED', $4, 'main', $5, $6, $7)",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(format!("attempt-{attempt_id}"))
        .bind("a".repeat(40))
        .bind(digest('d'))
        .bind(&policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert attempt");
        sqlx::query(
            r"INSERT INTO work_orders
              (id, tenant_id, work_item_id, attempt_id, schema_version,
               envelope_schema, algorithm, key_id, idempotency_key, payload_digest,
               canonical_payload, payload, signature, exact_signed_envelope,
               issued_at, not_before, expires_at)
              VALUES ($1, $2, $3, $4, 'v1', 'envelope-v1', 'EdDSA', 'key-1', $5,
                      $6, $7, '{}'::jsonb, 'signature', $8, $9, $9, $10)",
        )
        .bind(work_order_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(format!("work-order-{work_order_id}"))
        .bind(&work_order_digest)
        .bind(b"{}".as_slice())
        .bind(b"signed".as_slice())
        .bind(now)
        .bind(now + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert Work Order");
        sqlx::query(
            r"INSERT INTO workers
              (id, tenant_id, name, endpoint, generation, signing_key_id, signing_public_key)
              VALUES ($1, $2, $3, $4, 3, 'key-1', 'public-key')",
        )
        .bind(worker_id)
        .bind(tenant_id)
        .bind(format!("worker-{worker_id}"))
        .bind(format!("local://{worker_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert worker");
        sqlx::query(
            r"INSERT INTO worker_sessions
              (id, tenant_id, worker_id, worker_generation, expires_at)
              VALUES ($1, $2, $3, 3, $4)",
        )
        .bind(worker_session_id)
        .bind(tenant_id)
        .bind(worker_id)
        .bind(now + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert worker session");
        sqlx::query(
            r"INSERT INTO runs
              (id, tenant_id, work_item_id, attempt_id, work_order_id, worker_id,
               worker_generation, worker_session_id, evidence_expectation_digest,
               external_run_id, state)
              VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8, $9, 'ADOPTED')",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(work_order_id)
        .bind(worker_id)
        .bind(worker_session_id)
        .bind(digest('e'))
        .bind(format!("external-{run_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert run");

        let event_id = EventId::new();
        let product_event = ProductEvent {
            schema: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_id,
            tenant_id: TenantId::from_uuid(tenant_id),
            work_item_id: Some(WorkItemId::from_uuid(work_item_id)),
            attempt_id: Some(AttemptId::from_uuid(attempt_id)),
            work_order_digest: Some(work_order_digest),
            run_id: Some(RunId::from_uuid(run_id)),
            aggregate_version: 2,
            occurred_at: now,
            ingested_at: now,
            actor: "runmill".into(),
            event_type: "run.running".into(),
            payload: json!({"phase": "implementation"}),
            policy_digest: Some(policy_digest),
            trace_id: format!("trace-{event_id}"),
            correlation_id: format!("correlation-{event_id}"),
        };
        let incoming = IncomingRunEvent {
            id: Uuid::now_v7(),
            run_id,
            external_event_id: event_id.to_string(),
            cursor: "cursor-1".into(),
            sequence: 1,
            aggregate_version: 2,
            schema_version: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_type: "run.running".into(),
            occurred_at: now,
            raw_event: serde_json::to_value(product_event).expect("serialize product event"),
        };
        let outcome = ingest_run_event(
            &mut transaction,
            WorkerSessionFence {
                tenant_id,
                session_id: worker_session_id,
                worker_id,
                generation: 3,
            },
            &incoming,
        )
        .await
        .expect("ingest run event");
        assert_eq!(outcome.disposition, RunEventIngestionDisposition::Applied);
        assert_eq!(outcome.last_event_sequence, 1);
        assert_eq!(outcome.run_aggregate_version, 2);

        let state: String =
            sqlx::query_scalar("SELECT state FROM runs WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(run_id)
                .fetch_one(&mut *transaction)
                .await
                .expect("load projected run");
        assert_eq!(state, "RUNNING");
        transaction.rollback().await.expect("rollback test data");
    }
}
