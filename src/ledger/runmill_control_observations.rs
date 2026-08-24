//! Append-only provenance for read-only Runmill control observations.
//!
//! This module stores an exact Runmill control response wire and its events beneath
//! one exact, live `OBSERVE_RUNMILL_RUN` workflow-job claim.  It intentionally
//! does not update `runs` and never writes `raw_run_events`: retaining control
//! evidence is not authority to project it into ASF state.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::persistence_error;
use crate::{
    Error, Result,
    adapters::runmill_control::{
        RunmillEventPage, RunmillRunId, RunmillRunSnapshot, RunmillValidatedRead,
    },
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const OBSERVATION_EVENT_PAGE_LIMIT: u16 = 100;

const INSERT_SNAPSHOT_SQL: &str = r"
INSERT INTO runmill_control_snapshots (
    id, tenant_id, run_id, work_item_id, attempt_id, work_order_id,
    work_order_digest, workflow_job_id, workflow_job_fence_token,
    workflow_job_attempt_count, workflow_job_owner, worker_session_id,
    worker_id, worker_generation, external_run_id,
    run_admission_worker_session_id, observer_session_id, observation_id,
    requested_after_sequence, observation_epoch, control_sequence,
    admission_idempotency_key, admission_envelope_digest, admission_policy_digest,
    control_operation, external_generation, external_state_version,
    external_latest_sequence, observed_at, raw_response_bytes, response_wire_digest,
    raw_snapshot, canonical_snapshot, snapshot_semantic_digest
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29,
    $30, $31, $32, $33, $34
)
ON CONFLICT DO NOTHING
RETURNING id, snapshot_semantic_digest
";

const LOAD_SNAPSHOT_SQL: &str = r"
SELECT
    id, run_id, work_item_id, attempt_id, work_order_id, work_order_digest,
    workflow_job_id, workflow_job_fence_token, workflow_job_attempt_count,
    workflow_job_owner, worker_session_id, worker_id, worker_generation,
    external_run_id, run_admission_worker_session_id, observer_session_id,
    observation_id, requested_after_sequence, observation_epoch,
    control_sequence, admission_idempotency_key,
    admission_envelope_digest, admission_policy_digest, control_operation,
    external_generation, external_state_version, external_latest_sequence,
    observed_at, raw_response_bytes, response_wire_digest, raw_snapshot,
    canonical_snapshot, snapshot_semantic_digest
FROM runmill_control_snapshots
WHERE tenant_id = $1
  AND (
      id = $2
      OR (
          workflow_job_id = $3
          AND workflow_job_fence_token = $4
          AND control_sequence = $5
      )
  )
FOR SHARE
";

const INSERT_EVENT_SQL: &str = r"
INSERT INTO raw_runmill_control_events (
    id, tenant_id, first_snapshot_id, run_id, external_event_id,
    event_sequence, event_type, occurred_at, raw_event, canonical_event,
    event_semantic_digest
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT DO NOTHING
RETURNING id, event_semantic_digest
";

const LOAD_EVENT_SQL: &str = r"
SELECT
    id, first_snapshot_id, run_id, external_event_id, event_sequence,
    event_type, occurred_at, raw_event, canonical_event, event_semantic_digest
FROM raw_runmill_control_events
WHERE tenant_id = $1
  AND run_id = $2
  AND (
      id = $3
      OR external_event_id = $4
      OR event_sequence = $5
  )
FOR SHARE
";

const INSERT_SNAPSHOT_EVENT_SQL: &str = r"
INSERT INTO runmill_control_snapshot_events (
    tenant_id, snapshot_id, event_id, page_ordinal
)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
RETURNING event_id
";

const LOAD_SNAPSHOT_EVENT_SQL: &str = r"
SELECT event_id, page_ordinal
FROM runmill_control_snapshot_events
WHERE tenant_id = $1
  AND snapshot_id = $2
  AND (event_id = $3 OR page_ordinal = $4)
FOR SHARE
";

/// The exact run, worker session, and live observation-job claim that fences
/// a control-plane read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillObservationFence {
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub work_order_id: Uuid,
    pub work_order_digest: String,
    pub workflow_job_id: Uuid,
    pub workflow_job_fence_token: i64,
    pub workflow_job_attempt_count: i32,
    pub workflow_job_owner: String,
    /// Immutable worker session that admitted the run.
    pub worker_session_id: Uuid,
    /// Current live control session that performed this cursor read.
    pub observer_session_id: Uuid,
    /// Immutable scheduling checkpoint for this observation job.
    pub observation_id: Uuid,
    /// Exclusive numeric cursor sent to `list-run-events`.
    pub requested_after_sequence: i64,
    /// Monotonic stream scheduling epoch.
    pub observation_epoch: i64,
    pub worker_id: Uuid,
    pub worker_generation: i64,
    pub external_run_id: String,
}

impl RunmillObservationFence {
    fn validate(&self) -> Result<()> {
        if [
            self.tenant_id,
            self.run_id,
            self.work_item_id,
            self.attempt_id,
            self.work_order_id,
            self.workflow_job_id,
            self.worker_session_id,
            self.observer_session_id,
            self.observation_id,
            self.worker_id,
        ]
        .into_iter()
        .any(|value| value.is_nil())
        {
            return Err(Error::Validation(
                "Runmill observation provenance requires non-nil IDs".into(),
            ));
        }
        if !is_sha256_digest(&self.work_order_digest)
            || self.workflow_job_fence_token <= 0
            || self.workflow_job_attempt_count <= 0
            || self.worker_generation <= 0
            || self.requested_after_sequence < 0
            || self.requested_after_sequence > i64::try_from(MAX_SAFE_INTEGER).unwrap_or(i64::MAX)
            || self.observation_epoch <= 0
            || self.observation_epoch > i64::try_from(MAX_SAFE_INTEGER).unwrap_or(i64::MAX)
            || self.workflow_job_owner.trim().is_empty()
            || self.external_run_id.trim().is_empty()
        {
            return Err(Error::Validation(
                "Runmill observation provenance has an invalid digest, claim, cursor epoch, worker generation, or external run ID".into(),
            ));
        }
        Ok(())
    }
}

/// The Runmill control operation that yielded a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunmillControlOperation {
    GetRun,
    ListRunEvents,
}

/// The exact admission coordinates exposed by Runmill's `get-run` response.
/// Event-page snapshots do not contain this admission block and therefore
/// intentionally carry `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillAdmissionProvenance {
    pub idempotency_key: String,
    pub envelope_digest: String,
    pub effective_policy_digest: String,
}

impl RunmillAdmissionProvenance {
    fn validate(&self) -> Result<()> {
        if self.idempotency_key.trim().is_empty()
            || !is_sha256_digest(&self.envelope_digest)
            || !is_sha256_digest(&self.effective_policy_digest)
        {
            return Err(Error::Validation(
                "Runmill admission provenance requires an idempotency key and SHA-256 digests"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl RunmillControlOperation {
    const fn as_database_value(self) -> &'static str {
        match self {
            Self::GetRun => "GET_RUN",
            Self::ListRunEvents => "LIST_RUN_EVENTS",
        }
    }
}

/// One raw Runmill event returned by a `list-run-events` control response.
#[derive(Debug, Clone, PartialEq)]
pub struct IncomingRunmillControlEvent {
    pub id: Uuid,
    pub external_event_id: String,
    pub sequence: u64,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    /// The parsed event value from the retained response page, never projected.
    pub raw_event: Value,
}

impl IncomingRunmillControlEvent {
    fn validate(&self, latest_sequence: u64) -> Result<()> {
        if self.id.is_nil()
            || self.external_event_id.trim().is_empty()
            || self.event_type.trim().is_empty()
            || !self.raw_event.is_object()
        {
            return Err(Error::Validation(
                "Runmill control event requires identity, type, and object JSON".into(),
            ));
        }
        if self.sequence == 0 || self.sequence > MAX_SAFE_INTEGER || self.sequence > latest_sequence
        {
            return Err(Error::Validation(
                "Runmill control event sequence is outside its snapshot boundary".into(),
            ));
        }
        Ok(())
    }

    fn canonical(&self) -> Result<(Vec<u8>, String)> {
        let bytes = canonical_json(&self.raw_event)?;
        Ok((bytes.clone(), sha256_digest(&bytes)))
    }
}

/// A raw response snapshot and any raw events returned alongside it.
#[derive(Debug, Clone, PartialEq)]
pub struct IncomingRunmillControlSnapshot {
    pub id: Uuid,
    /// Monotonic within one exact workflow-job claim; it makes retried reads
    /// idempotent without collapsing distinct observations.
    pub control_sequence: u64,
    pub operation: RunmillControlOperation,
    pub external_generation: u64,
    pub external_state_version: u64,
    pub external_latest_sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub admission: Option<RunmillAdmissionProvenance>,
    /// Complete exact successful Runmill control response wire: its only
    /// envelope keys are `ok` and `data`, `ok` is `true`, `data` is
    /// `raw_snapshot`, and the wire ends in one newline byte.
    pub raw_response_bytes: Vec<u8>,
    /// The semantic `data` value in `raw_response_bytes`.
    pub raw_snapshot: Value,
    pub events: Vec<IncomingRunmillControlEvent>,
}

impl IncomingRunmillControlSnapshot {
    /// Builds a durable get-run observation from a read that the control
    /// adapter already proved to be an exact successful Runmill response.
    ///
    /// Prefer this over struct literals for production control reads: it keeps
    /// the exact response wire and data while deriving every indexed Runmill
    /// field from the typed, revalidated response.
    pub fn from_validated_get_run(
        id: Uuid,
        control_sequence: u64,
        observed_at: DateTime<Utc>,
        read: RunmillValidatedRead<RunmillRunSnapshot>,
    ) -> Result<Self> {
        let (typed_snapshot, raw_response_bytes, raw_snapshot) = read.into_parts();
        let snapshot =
            RunmillRunSnapshot::validate_provenance_data(&raw_snapshot).map_err(|_| {
                Error::Validation(
                "validated get-run proof no longer satisfies the exact Runmill response contract"
                    .into(),
            )
            })?;
        if typed_snapshot != snapshot {
            return Err(Error::Validation(
                "validated get-run proof typed value contradicts its exact response data".into(),
            ));
        }

        let incoming = Self {
            id,
            control_sequence,
            operation: RunmillControlOperation::GetRun,
            external_generation: snapshot.run.generation,
            external_state_version: snapshot.run.state_version,
            external_latest_sequence: snapshot.latest_sequence,
            observed_at,
            admission: Some(RunmillAdmissionProvenance {
                idempotency_key: snapshot.admission.idempotency_key,
                envelope_digest: snapshot.admission.envelope_digest,
                effective_policy_digest: snapshot.admission.effective_policy_digest,
            }),
            raw_response_bytes,
            raw_snapshot,
            events: Vec::new(),
        };
        incoming.validate()?;
        Ok(incoming)
    }

    /// Builds a durable list-run-events observation from a validated response
    /// page. `event_ids` must provide one non-nil internal event ID for every
    /// event in the retained page, in page order.
    ///
    /// The immutable event identities and their indexed fields are derived
    /// from the typed page; each retained raw event remains the page member
    /// later checked by the ledger and database.
    pub fn from_validated_event_page(
        id: Uuid,
        event_ids: Vec<Uuid>,
        control_sequence: u64,
        observed_at: DateTime<Utc>,
        read: RunmillValidatedRead<RunmillEventPage>,
    ) -> Result<Self> {
        let (typed_page, raw_response_bytes, raw_snapshot) = read.into_parts();
        let page = RunmillEventPage::validate_provenance_data(&raw_snapshot).map_err(|_| {
            Error::Validation(
                "validated event-page proof no longer satisfies the exact Runmill response contract"
                    .into(),
            )
        })?;
        if typed_page != page {
            return Err(Error::Validation(
                "validated event-page proof typed value contradicts its exact response data".into(),
            ));
        }
        let raw_events = raw_snapshot
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::Validation(
                    "validated event-page proof lacks its exact retained event array".into(),
                )
            })?;
        if event_ids.len() != page.events.len() || raw_events.len() != page.events.len() {
            return Err(Error::Validation(
                "Runmill event-page observation requires one internal event ID per retained event"
                    .into(),
            ));
        }
        let events = event_ids
            .into_iter()
            .zip(page.events.iter().zip(raw_events))
            .map(|(id, (event, raw_event))| IncomingRunmillControlEvent {
                id,
                external_event_id: event.event_id.clone(),
                sequence: event.seq,
                event_type: event.event_type.clone(),
                occurred_at: event.occurred_at,
                raw_event: raw_event.clone(),
            })
            .collect();

        let incoming = Self {
            id,
            control_sequence,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: page.snapshot.run.generation,
            external_state_version: page.snapshot.run.state_version,
            external_latest_sequence: page.snapshot.latest_sequence,
            observed_at,
            admission: None,
            raw_response_bytes,
            raw_snapshot,
            events,
        };
        incoming.validate()?;
        Ok(incoming)
    }

    fn validate(&self) -> Result<()> {
        if self.id.is_nil() || !self.raw_snapshot.is_object() {
            return Err(Error::Validation(
                "Runmill control snapshot requires a non-nil ID and object JSON".into(),
            ));
        }
        if self.raw_response_bytes.len() > 2 * 1024 * 1024
            || self.raw_response_bytes.len() < 2
            || self.raw_response_bytes.last() != Some(&b'\n')
            || self.raw_response_bytes[..self.raw_response_bytes.len() - 1].contains(&b'\n')
        {
            return Err(Error::Validation(
                "Runmill control response wire must be newline-terminated and at most 2 MiB".into(),
            ));
        }
        let response = serde_json::from_slice::<Value>(&self.raw_response_bytes).map_err(|_| {
            Error::Validation("Runmill control response wire must be UTF-8 JSON".into())
        })?;
        let Some(envelope) = response.as_object() else {
            return Err(Error::Validation(
                "Runmill control response wire must be a success envelope object".into(),
            ));
        };
        if envelope.len() != 2
            || envelope.get("ok") != Some(&Value::Bool(true))
            || envelope.get("data") != Some(&self.raw_snapshot)
        {
            return Err(Error::Validation(
                "Runmill control response wire must be exactly {ok:true,data:raw_snapshot}".into(),
            ));
        }
        match (self.operation, &self.admission) {
            (RunmillControlOperation::GetRun, Some(admission)) => {
                admission.validate()?;
                if !self.events.is_empty() {
                    return Err(Error::Validation(
                        "a get-run snapshot cannot carry list-run-events rows".into(),
                    ));
                }
                let validated = RunmillRunSnapshot::validate_provenance_data(&self.raw_snapshot)
                    .map_err(|_| {
                        Error::Validation(
                            "get-run provenance must satisfy the exact Runmill response contract"
                                .into(),
                        )
                    })?;
                if validated.run.generation != self.external_generation
                    || validated.run.state_version != self.external_state_version
                    || validated.latest_sequence != self.external_latest_sequence
                    || validated.admission.idempotency_key != admission.idempotency_key
                    || validated.admission.envelope_digest != admission.envelope_digest
                    || validated.admission.effective_policy_digest
                        != admission.effective_policy_digest
                {
                    return Err(Error::Validation(
                        "get-run indexed provenance contradicts its validated response".into(),
                    ));
                }
            }
            (RunmillControlOperation::ListRunEvents, None) => {
                let Some(raw_events) = self.raw_snapshot.get("events").and_then(Value::as_array)
                else {
                    return Err(Error::Validation(
                        "a list-run-events snapshot must retain its exact events array".into(),
                    ));
                };
                if raw_events.len() > 1_000
                    || raw_events.len() != self.events.len()
                    || raw_events
                        .iter()
                        .zip(&self.events)
                        .any(|(raw, incoming)| raw != &incoming.raw_event)
                {
                    return Err(Error::Validation(
                        "list-run-events rows must exactly match the retained response page".into(),
                    ));
                }
                let validated = RunmillEventPage::validate_provenance_data(&self.raw_snapshot)
                    .map_err(|_| {
                        Error::Validation(
                            "event-page provenance must satisfy the exact Runmill response contract"
                                .into(),
                        )
                    })?;
                if validated.snapshot.run.generation != self.external_generation
                    || validated.snapshot.run.state_version != self.external_state_version
                    || validated.snapshot.latest_sequence != self.external_latest_sequence
                    || validated
                        .events
                        .iter()
                        .zip(&self.events)
                        .any(|(typed, incoming)| {
                            typed.event_id != incoming.external_event_id
                                || typed.seq != incoming.sequence
                                || typed.event_type != incoming.event_type
                                || typed.occurred_at != incoming.occurred_at
                        })
                {
                    return Err(Error::Validation(
                        "event-page indexed provenance contradicts its validated response".into(),
                    ));
                }
            }
            _ => {
                return Err(Error::Validation(
                    "only get-run observations may carry Runmill admission provenance".into(),
                ));
            }
        }
        for value in [
            self.control_sequence,
            self.external_state_version,
            self.external_latest_sequence,
        ] {
            if value == 0 || value > MAX_SAFE_INTEGER {
                return Err(Error::Validation(
                    "Runmill control snapshot counter is outside the supported safe-integer range"
                        .into(),
                ));
            }
        }
        if self.external_state_version != self.external_latest_sequence {
            return Err(Error::Validation(
                "Runmill control snapshot state version must equal its latest sequence".into(),
            ));
        }
        for event in &self.events {
            event.validate(self.external_latest_sequence)?;
        }
        for (index, event) in self.events.iter().enumerate() {
            if self.events[..index].iter().any(|prior| {
                prior.id == event.id
                    || prior.external_event_id == event.external_event_id
                    || prior.sequence == event.sequence
            }) {
                return Err(Error::Validation(
                    "Runmill control snapshot contains duplicate event identities".into(),
                ));
            }
        }
        Ok(())
    }

    fn canonical(&self) -> Result<(Vec<u8>, String)> {
        let bytes = canonical_json(&self.raw_snapshot)?;
        Ok((bytes.clone(), sha256_digest(&bytes)))
    }
}

/// Result of idempotently retaining one control response and its raw events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillControlObservationOutcome {
    pub snapshot_id: Uuid,
    pub snapshot_inserted: bool,
    pub snapshot_semantic_digest: String,
    /// Newly discovered remote event identities, excluding page re-observations.
    pub inserted_event_count: u32,
    /// New immutable links from this retained page to remote event identities.
    pub linked_event_count: u32,
}

/// Retain one read-only Runmill control observation in a caller-owned
/// transaction.
///
/// The database rechecks the exact live `OBSERVE_RUNMILL_RUN` claim, the
/// authoritative run's Work Order, and the active worker session/generation.
/// This function never updates `runs` and never inserts into `raw_run_events`.
/// A future reducer must explicitly decide whether this provenance is usable.
pub async fn record_runmill_control_observation(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
) -> Result<RunmillControlObservationOutcome> {
    sqlx::query("SAVEPOINT asf_runmill_control_observation")
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("start Runmill observation savepoint", error))?;

    let result = record_runmill_control_observation_inner(transaction, fence, incoming).await;
    if let Err(error) = result {
        sqlx::query("ROLLBACK TO SAVEPOINT asf_runmill_control_observation")
            .execute(&mut **transaction)
            .await
            .map_err(|rollback_error| {
                persistence_error(
                    "roll back failed Runmill observation savepoint",
                    rollback_error,
                )
            })?;
        sqlx::query("RELEASE SAVEPOINT asf_runmill_control_observation")
            .execute(&mut **transaction)
            .await
            .map_err(|release_error| {
                persistence_error(
                    "release failed Runmill observation savepoint",
                    release_error,
                )
            })?;
        return Err(error);
    }

    sqlx::query("RELEASE SAVEPOINT asf_runmill_control_observation")
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("release Runmill observation savepoint", error))?;
    result
}

async fn record_runmill_control_observation_inner(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
) -> Result<RunmillControlObservationOutcome> {
    fence.validate()?;
    incoming.validate()?;
    if incoming.operation == RunmillControlOperation::ListRunEvents {
        let run_id = RunmillRunId::parse(fence.external_run_id.clone()).map_err(|_| {
            Error::Validation("Runmill observation fence has an invalid external run ID".into())
        })?;
        let after = u64::try_from(fence.requested_after_sequence).map_err(|_| {
            Error::Validation("Runmill observation fence cursor cannot be represented".into())
        })?;
        let page =
            RunmillEventPage::validate_provenance_data(&incoming.raw_snapshot).map_err(|_| {
                Error::Validation(
                    "Runmill event-page provenance no longer satisfies its exact response contract"
                        .into(),
                )
            })?;
        page.validate_provenance_request(&run_id, after, OBSERVATION_EVENT_PAGE_LIMIT)
            .map_err(|_| {
                Error::Validation(
                    "Runmill event-page provenance contradicts its scheduled cursor or page limit"
                        .into(),
                )
            })?;
    }
    let control_sequence = i64::try_from(incoming.control_sequence).map_err(|_| {
        Error::Validation("Runmill control sequence overflows PostgreSQL bigint".into())
    })?;
    let external_generation = i64::try_from(incoming.external_generation).map_err(|_| {
        Error::Validation("Runmill external generation overflows PostgreSQL bigint".into())
    })?;
    let external_state_version = i64::try_from(incoming.external_state_version).map_err(|_| {
        Error::Validation("Runmill external state version overflows PostgreSQL bigint".into())
    })?;
    let external_latest_sequence =
        i64::try_from(incoming.external_latest_sequence).map_err(|_| {
            Error::Validation("Runmill external latest sequence overflows PostgreSQL bigint".into())
        })?;
    let (canonical_snapshot, snapshot_digest) = incoming.canonical()?;
    if let Some(replay) = load_complete_runmill_control_replay(
        transaction,
        fence,
        incoming,
        control_sequence,
        &canonical_snapshot,
        &snapshot_digest,
    )
    .await?
    {
        return Ok(replay);
    }
    let response_wire_digest = sha256_digest(&incoming.raw_response_bytes);
    let admission = incoming.admission.as_ref();

    let inserted_snapshot = sqlx::query_as::<_, (Uuid, String)>(INSERT_SNAPSHOT_SQL)
        .bind(incoming.id)
        .bind(fence.tenant_id)
        .bind(fence.run_id)
        .bind(fence.work_item_id)
        .bind(fence.attempt_id)
        .bind(fence.work_order_id)
        .bind(&fence.work_order_digest)
        .bind(fence.workflow_job_id)
        .bind(fence.workflow_job_fence_token)
        .bind(fence.workflow_job_attempt_count)
        .bind(&fence.workflow_job_owner)
        .bind(fence.worker_session_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .bind(&fence.external_run_id)
        .bind(fence.worker_session_id)
        .bind(fence.observer_session_id)
        .bind(fence.observation_id)
        .bind(fence.requested_after_sequence)
        .bind(fence.observation_epoch)
        .bind(control_sequence)
        .bind(admission.map(|value| &value.idempotency_key))
        .bind(admission.map(|value| &value.envelope_digest))
        .bind(admission.map(|value| &value.effective_policy_digest))
        .bind(incoming.operation.as_database_value())
        .bind(external_generation)
        .bind(external_state_version)
        .bind(external_latest_sequence)
        .bind(incoming.observed_at)
        .bind(&incoming.raw_response_bytes)
        .bind(&response_wire_digest)
        .bind(&incoming.raw_snapshot)
        .bind(&canonical_snapshot)
        .bind(&snapshot_digest)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("store Runmill control snapshot", error))?;

    let snapshot_inserted = inserted_snapshot.is_some();
    let (stored_snapshot_id, stored_snapshot_digest) = if let Some(stored) = inserted_snapshot {
        stored
    } else {
        let rows = sqlx::query(LOAD_SNAPSHOT_SQL)
            .bind(fence.tenant_id)
            .bind(incoming.id)
            .bind(fence.workflow_job_id)
            .bind(fence.workflow_job_fence_token)
            .bind(control_sequence)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|error| persistence_error("load duplicate Runmill control snapshot", error))?;
        if rows.len() != 1 || !snapshot_matches(&rows[0], fence, incoming, &canonical_snapshot)? {
            return Err(Error::Conflict(
                "Runmill control snapshot identity was reused for different semantics".into(),
            ));
        }
        (
            required_column(&rows[0], "id", "snapshot ID")?,
            required_column(
                &rows[0],
                "snapshot_semantic_digest",
                "snapshot semantic digest",
            )?,
        )
    };
    if stored_snapshot_digest != snapshot_digest {
        return Err(Error::Persistence(
            "Runmill control snapshot canonical digest disagrees with ledger semantics".into(),
        ));
    }

    let mut inserted_event_count = 0_u32;
    let mut linked_event_count = 0_u32;
    for (page_ordinal, event) in incoming.events.iter().enumerate() {
        let (canonical_event, event_digest) = event.canonical()?;
        let sequence = i64::try_from(event.sequence).map_err(|_| {
            Error::Validation("Runmill event sequence overflows PostgreSQL bigint".into())
        })?;
        let inserted = sqlx::query_as::<_, (Uuid, String)>(INSERT_EVENT_SQL)
            .bind(event.id)
            .bind(fence.tenant_id)
            .bind(stored_snapshot_id)
            .bind(fence.run_id)
            .bind(&event.external_event_id)
            .bind(sequence)
            .bind(&event.event_type)
            .bind(event.occurred_at)
            .bind(&event.raw_event)
            .bind(&canonical_event)
            .bind(&event_digest)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("store raw Runmill control event", error))?;
        let stored_event_id = if let Some((stored_id, stored_digest)) = inserted {
            if stored_digest != event_digest {
                return Err(Error::Persistence(
                    "Runmill control event canonical digest disagrees with ledger semantics".into(),
                ));
            }
            inserted_event_count = inserted_event_count.checked_add(1).ok_or_else(|| {
                Error::Conflict("Runmill control event insertion count overflowed".into())
            })?;
            stored_id
        } else {
            let rows = sqlx::query(LOAD_EVENT_SQL)
                .bind(fence.tenant_id)
                .bind(fence.run_id)
                .bind(event.id)
                .bind(&event.external_event_id)
                .bind(sequence)
                .fetch_all(&mut **transaction)
                .await
                .map_err(|error| {
                    persistence_error("load duplicate raw Runmill control event", error)
                })?;
            if rows.len() != 1 || !event_matches(&rows[0], fence, event, &canonical_event)? {
                return Err(Error::Conflict(
                    "Runmill control event identity was reused for different semantics".into(),
                ));
            }
            let stored_digest: String =
                required_column(&rows[0], "event_semantic_digest", "event semantic digest")?;
            if stored_digest != event_digest {
                return Err(Error::Persistence(
                    "stored Runmill control event has an invalid semantic digest".into(),
                ));
            }
            required_column(&rows[0], "id", "control event ID")?
        };

        let page_ordinal = i32::try_from(page_ordinal).map_err(|_| {
            Error::Validation("Runmill control event page ordinal overflowed".into())
        })?;
        let linked = sqlx::query_scalar::<_, Uuid>(INSERT_SNAPSHOT_EVENT_SQL)
            .bind(fence.tenant_id)
            .bind(stored_snapshot_id)
            .bind(stored_event_id)
            .bind(page_ordinal)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("link Runmill event to response page", error))?;
        if linked.is_some() {
            linked_event_count = linked_event_count.checked_add(1).ok_or_else(|| {
                Error::Conflict("Runmill control event link count overflowed".into())
            })?;
        } else {
            let rows = sqlx::query(LOAD_SNAPSHOT_EVENT_SQL)
                .bind(fence.tenant_id)
                .bind(stored_snapshot_id)
                .bind(stored_event_id)
                .bind(page_ordinal)
                .fetch_all(&mut **transaction)
                .await
                .map_err(|error| {
                    persistence_error("load duplicate Runmill response-page event link", error)
                })?;
            if rows.len() != 1
                || required_column::<Uuid>(&rows[0], "event_id", "linked control event ID")?
                    != stored_event_id
                || required_column::<i32>(&rows[0], "page_ordinal", "control page ordinal")?
                    != page_ordinal
            {
                return Err(Error::Conflict(
                    "Runmill response-page event link was reused for different semantics".into(),
                ));
            }
        }
    }

    Ok(RunmillControlObservationOutcome {
        snapshot_id: stored_snapshot_id,
        snapshot_inserted,
        snapshot_semantic_digest: snapshot_digest,
        inserted_event_count,
        linked_event_count,
    })
}

/// Resolves a fully committed logical replay without requiring the historical
/// job lease to remain live. Missing event/link children return `None` so the
/// normal write path can repair them only after the database rechecks a live
/// claim. Contradictory identities always fail closed.
async fn load_complete_runmill_control_replay(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
    control_sequence: i64,
    canonical_snapshot: &[u8],
    snapshot_digest: &str,
) -> Result<Option<RunmillControlObservationOutcome>> {
    let snapshot_rows = sqlx::query(LOAD_SNAPSHOT_SQL)
        .bind(fence.tenant_id)
        .bind(incoming.id)
        .bind(fence.workflow_job_id)
        .bind(fence.workflow_job_fence_token)
        .bind(control_sequence)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| persistence_error("load Runmill control replay", error))?;
    if snapshot_rows.is_empty() {
        return Ok(None);
    }
    if snapshot_rows.len() != 1
        || !snapshot_matches(&snapshot_rows[0], fence, incoming, canonical_snapshot)?
    {
        return Err(Error::Conflict(
            "Runmill control snapshot identity was reused for different semantics".into(),
        ));
    }

    let snapshot_row = &snapshot_rows[0];
    let stored_snapshot_id = required_column(snapshot_row, "id", "snapshot ID")?;
    let stored_snapshot_digest: String = required_column(
        snapshot_row,
        "snapshot_semantic_digest",
        "snapshot semantic digest",
    )?;
    if stored_snapshot_digest != snapshot_digest {
        return Err(Error::Persistence(
            "stored Runmill control snapshot has an invalid semantic digest".into(),
        ));
    }

    for (page_ordinal, event) in incoming.events.iter().enumerate() {
        let (canonical_event, event_digest) = event.canonical()?;
        let sequence = i64::try_from(event.sequence).map_err(|_| {
            Error::Validation("Runmill event sequence overflows PostgreSQL bigint".into())
        })?;
        let event_rows = sqlx::query(LOAD_EVENT_SQL)
            .bind(fence.tenant_id)
            .bind(fence.run_id)
            .bind(event.id)
            .bind(&event.external_event_id)
            .bind(sequence)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|error| persistence_error("load Runmill control event replay", error))?;
        if event_rows.is_empty() {
            return Ok(None);
        }
        if event_rows.len() != 1 || !event_matches(&event_rows[0], fence, event, &canonical_event)?
        {
            return Err(Error::Conflict(
                "Runmill control event identity was reused for different semantics".into(),
            ));
        }
        let event_row = &event_rows[0];
        let stored_event_id: Uuid = required_column(event_row, "id", "control event ID")?;
        let stored_event_digest: String =
            required_column(event_row, "event_semantic_digest", "event semantic digest")?;
        if stored_event_digest != event_digest {
            return Err(Error::Persistence(
                "stored Runmill control event has an invalid semantic digest".into(),
            ));
        }

        let page_ordinal = i32::try_from(page_ordinal).map_err(|_| {
            Error::Validation("Runmill control event page ordinal overflowed".into())
        })?;
        let link_rows = sqlx::query(LOAD_SNAPSHOT_EVENT_SQL)
            .bind(fence.tenant_id)
            .bind(stored_snapshot_id)
            .bind(stored_event_id)
            .bind(page_ordinal)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|error| persistence_error("load Runmill response-page replay link", error))?;
        if link_rows.is_empty() {
            return Ok(None);
        }
        if link_rows.len() != 1
            || required_column::<Uuid>(&link_rows[0], "event_id", "linked control event ID")?
                != stored_event_id
            || required_column::<i32>(&link_rows[0], "page_ordinal", "control page ordinal")?
                != page_ordinal
        {
            return Err(Error::Conflict(
                "Runmill response-page event link was reused for different semantics".into(),
            ));
        }
    }

    Ok(Some(RunmillControlObservationOutcome {
        snapshot_id: stored_snapshot_id,
        snapshot_inserted: false,
        snapshot_semantic_digest: snapshot_digest.to_owned(),
        inserted_event_count: 0,
        linked_event_count: 0,
    }))
}

fn snapshot_matches(
    row: &PgRow,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
    canonical_snapshot: &[u8],
) -> Result<bool> {
    Ok(
        required_column::<Uuid>(row, "run_id", "snapshot run")? == fence.run_id
            && required_column::<Uuid>(row, "work_item_id", "snapshot work item")?
                == fence.work_item_id
            && required_column::<Uuid>(row, "attempt_id", "snapshot attempt")? == fence.attempt_id
            && required_column::<Uuid>(row, "work_order_id", "snapshot Work Order")?
                == fence.work_order_id
            && required_column::<String>(row, "work_order_digest", "snapshot Work Order digest")?
                == fence.work_order_digest
            && required_column::<Uuid>(row, "workflow_job_id", "snapshot job")?
                == fence.workflow_job_id
            && required_column::<i64>(row, "workflow_job_fence_token", "snapshot job fence")?
                == fence.workflow_job_fence_token
            && required_column::<i32>(
                row,
                "workflow_job_attempt_count",
                "snapshot job attempt count",
            )? == fence.workflow_job_attempt_count
            && required_column::<String>(row, "workflow_job_owner", "snapshot job owner")?
                == fence.workflow_job_owner
            && required_column::<Uuid>(row, "worker_session_id", "snapshot worker session")?
                == fence.worker_session_id
            && required_column::<Uuid>(row, "worker_id", "snapshot worker")? == fence.worker_id
            && required_column::<i64>(row, "worker_generation", "snapshot worker generation")?
                == fence.worker_generation
            && required_column::<String>(row, "external_run_id", "snapshot external run")?
                == fence.external_run_id
            && required_column::<Uuid>(
                row,
                "run_admission_worker_session_id",
                "snapshot run admission session",
            )? == fence.worker_session_id
            && required_column::<Uuid>(row, "observer_session_id", "snapshot observer session")?
                == fence.observer_session_id
            && required_column::<Uuid>(row, "observation_id", "snapshot observation")?
                == fence.observation_id
            && required_column::<i64>(
                row,
                "requested_after_sequence",
                "snapshot requested cursor",
            )? == fence.requested_after_sequence
            && required_column::<i64>(row, "observation_epoch", "snapshot observation epoch")?
                == fence.observation_epoch
            && required_column::<i64>(row, "control_sequence", "snapshot control sequence")?
                == i64::try_from(incoming.control_sequence).unwrap_or(i64::MIN)
            && optional_column::<String>(
                row,
                "admission_idempotency_key",
                "snapshot admission key",
            )? == incoming
                .admission
                .as_ref()
                .map(|value| value.idempotency_key.clone())
            && optional_column::<String>(
                row,
                "admission_envelope_digest",
                "snapshot admission envelope digest",
            )? == incoming
                .admission
                .as_ref()
                .map(|value| value.envelope_digest.clone())
            && optional_column::<String>(
                row,
                "admission_policy_digest",
                "snapshot admission policy digest",
            )? == incoming
                .admission
                .as_ref()
                .map(|value| value.effective_policy_digest.clone())
            && required_column::<String>(row, "control_operation", "snapshot operation")?
                == incoming.operation.as_database_value()
            && required_column::<i64>(row, "external_generation", "snapshot external generation")?
                == i64::try_from(incoming.external_generation).unwrap_or(i64::MIN)
            && required_column::<i64>(
                row,
                "external_state_version",
                "snapshot external state version",
            )? == i64::try_from(incoming.external_state_version).unwrap_or(i64::MIN)
            && required_column::<i64>(
                row,
                "external_latest_sequence",
                "snapshot external latest sequence",
            )? == i64::try_from(incoming.external_latest_sequence).unwrap_or(i64::MIN)
            && required_column::<Value>(row, "raw_snapshot", "snapshot raw JSON")?
                == incoming.raw_snapshot
            && required_column::<Vec<u8>>(row, "canonical_snapshot", "snapshot canonical JSON")?
                == canonical_snapshot,
    )
}

fn event_matches(
    row: &PgRow,
    fence: &RunmillObservationFence,
    event: &IncomingRunmillControlEvent,
    canonical_event: &[u8],
) -> Result<bool> {
    Ok(
        required_column::<Uuid>(row, "run_id", "control event run")? == fence.run_id
            && required_column::<String>(row, "external_event_id", "control external event ID")?
                == event.external_event_id
            && required_column::<i64>(row, "event_sequence", "control event sequence")?
                == i64::try_from(event.sequence).unwrap_or(i64::MIN)
            && required_column::<String>(row, "event_type", "control event type")?
                == event.event_type
            && required_column::<DateTime<Utc>>(row, "occurred_at", "control event occurrence")?
                == event.occurred_at
            && required_column::<Value>(row, "raw_event", "control raw event JSON")?
                == event.raw_event
            && required_column::<Vec<u8>>(row, "canonical_event", "control canonical event JSON")?
                == canonical_event,
    )
}

fn required_column<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!(
            "read {description} from Runmill control provenance: {error}"
        ))
    })
}

fn optional_column<T>(row: &PgRow, column: &str, description: &str) -> Result<Option<T>>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!(
            "read optional {description} from Runmill control provenance: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    #[test]
    fn semantic_digest_is_stable_across_object_key_order() {
        let first = IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 1,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: 0,
            external_state_version: 1,
            external_latest_sequence: 1,
            observed_at: Utc::now(),
            admission: None,
            raw_response_bytes:
                b"{\"ok\":true,\"data\":{\"z\":[true,1],\"events\":[],\"a\":{\"y\":\"x\"}}}\n"
                    .to_vec(),
            raw_snapshot: json!({"z": [true, 1], "events": [], "a": {"y": "x"}}),
            events: Vec::new(),
        };
        let mut second = first.clone();
        second.raw_response_bytes =
            b"{\"ok\":true,\"data\":{\"a\":{\"y\":\"x\"},\"events\":[],\"z\":[true,1]}}\n".to_vec();
        second.raw_snapshot = json!({"a": {"y": "x"}, "events": [], "z": [true, 1]});
        assert_eq!(first.canonical().unwrap(), second.canonical().unwrap());
    }

    #[test]
    fn snapshot_requires_an_exact_success_response_wire() {
        let raw_snapshot = valid_empty_event_page();
        let mut valid_wire = serde_json::to_vec(&json!({"ok": true, "data": raw_snapshot}))
            .expect("serialize valid response");
        valid_wire.push(b'\n');
        let mut snapshot = IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 1,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: 0,
            external_state_version: 1,
            external_latest_sequence: 1,
            observed_at: Utc::now(),
            admission: None,
            raw_response_bytes: valid_wire,
            raw_snapshot: raw_snapshot.clone(),
            events: Vec::new(),
        };
        assert!(snapshot.validate().is_ok());

        snapshot.raw_response_bytes = b"{\"ok\":true,\"data\":{\"events\":[]}}".to_vec();
        assert!(snapshot.validate().is_err());

        snapshot.raw_response_bytes =
            b"{\"ok\":true,\"data\":{\"events\":[]},\"extra\":false}\n".to_vec();
        assert!(snapshot.validate().is_err());

        snapshot.raw_response_bytes = b"{\"ok\":true,\"data\":{}}\n".to_vec();
        assert!(snapshot.validate().is_err());

        let mut embedded_newline = serde_json::to_vec(&json!({"ok": true, "data": raw_snapshot}))
            .expect("serialize response with whitespace");
        embedded_newline.insert(1, b'\n');
        embedded_newline.push(b'\n');
        snapshot.raw_response_bytes = embedded_newline;
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn snapshot_rejects_duplicate_or_out_of_boundary_event_sequences() {
        let event = IncomingRunmillControlEvent {
            id: Uuid::now_v7(),
            external_event_id: "event-1".into(),
            sequence: 2,
            event_type: "run.progressed".into(),
            occurred_at: Utc::now(),
            raw_event: json!({"type": "run.progressed"}),
        };
        let raw_event = event.raw_event.clone();
        let raw_snapshot = json!({"snapshot": true, "events": [raw_event]});
        let snapshot = IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 1,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: 1,
            external_state_version: 1,
            external_latest_sequence: 1,
            observed_at: Utc::now(),
            admission: None,
            raw_response_bytes: format!(
                "{{\"ok\":true,\"data\":{}}}\n",
                serde_json::to_string(&raw_snapshot).unwrap()
            )
            .into_bytes(),
            raw_snapshot,
            events: vec![event],
        };
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn migration_keeps_control_provenance_outside_raw_run_events() {
        let migration =
            include_str!("../../migrations/0021_runmill_run_observation_provenance.sql");
        assert!(migration.contains("CREATE TABLE runmill_control_snapshots"));
        assert!(migration.contains("CREATE TABLE raw_runmill_control_events"));
        assert!(migration.contains("OBSERVE_RUNMILL_RUN"));
        assert!(migration.contains("raw_response_bytes bytea NOT NULL"));
        assert!(migration.contains("response_wire_digest text NOT NULL"));
        assert!(!migration.contains("raw_snapshot_bytes"));
        assert!(!migration.contains("raw_event_bytes"));
        assert!(migration.contains("BETWEEN 0 AND 9007199254740991"));
        assert!(migration.contains("UNIQUE (tenant_id, run_id, external_event_id)"));
        assert!(migration.contains("job.payload ->> 'run_id' = NEW.run_id::text"));
        assert!(migration.contains("raw_snapshot #>> '{admission,payloadDigest}'"));
        assert!(migration.contains("NEW.raw_event ->> 'event_id'"));
        assert!(migration.contains("retained.event = NEW.raw_event"));
        assert!(migration.contains("runmill_control_snapshots_append_only"));
        assert!(migration.contains("raw_runmill_control_events_append_only"));
        assert!(migration.contains("CREATE TABLE runmill_control_snapshot_events"));
        assert!(migration.contains("runmill_control_snapshot_events_append_only"));
        assert!(!migration.contains("INSERT INTO raw_run_events"));
        assert!(!migration.contains("UPDATE runs"));
    }

    fn valid_empty_event_page() -> Value {
        json!({
            "events": [],
            "nextCursor": 0,
            "hasMore": false,
            "gap": false,
            "compactedThrough": null,
            "snapshot": {
                "run": {
                    "runId": "run-1",
                    "issueId": "issue-1",
                    "repo": "acme/repository",
                    "provider": "github",
                    "state": "RECEIVED",
                    "stateVersion": 1,
                    "attempt": 1,
                    "baseCommit": null,
                    "candidateSha": null,
                    "branch": null,
                    "mode": "asf-worker",
                    "workOrderId": "work-order-1",
                    "attemptId": "attempt-1",
                    "generation": 0,
                    "ownerId": null,
                    "heartbeatAt": null
                },
                "latestSequence": 1
            }
        })
    }
}
