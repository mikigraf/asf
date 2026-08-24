use std::{cmp, sync::Arc, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use sqlx::{PgPool, Row as _, postgres::PgRow};
use tokio::{sync::watch, task::JoinSet, time::MissedTickBehavior};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, HandlerReadiness, HandlerRegistry,
    OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
    REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
    RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID, ReadyClaimSet,
    timers::promote_due_timers,
};
use crate::{
    Error, Result,
    audit::{AuditEventContent, HashedAuditEvent},
    crypto::sha256_digest,
    domain::{EventId, TenantId},
    ledger::{
        ClaimedWorkflowJob, DeadLetterEscalation, FailureDisposition, MAX_JOB_LEASE_DURATION,
        PgLedger, StepAuditEvent, StepOutboxMessage, WorkflowStepFailure,
        WorkflowStepFailureDisposition, WorkflowStepFence, fail_workflow_step,
        produce_due_runmill_observation_jobs, produce_due_runmill_terminal_evidence_jobs,
    },
};

const CLAIM_READY_JOBS_SQL: &str = r"
WITH candidates AS (
    SELECT
        job.id,
        job.status = 'RUNNING' AS reclaiming_expired
    FROM workflow_jobs AS job
    WHERE job.tenant_id = $1
      AND (
          EXISTS (
              SELECT 1
              FROM unnest($5::text[], $6::text[]) AS unscoped_route(job_type, activity_contract_id)
              WHERE unscoped_route.job_type = job.job_type
                AND unscoped_route.activity_contract_id = job.activity_contract_id
          )
          OR (
              job.job_type = 'RECONCILE_WORKER'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($7::text[], $8::text[]) AS reconcile_route(worker_id, activity_contract_id)
                  WHERE reconcile_route.worker_id = job.payload ->> 'worker_id'
                    AND reconcile_route.activity_contract_id = job.activity_contract_id
              )
          )
          OR (
              job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($9::text[], $10::text[]) AS cancellation_route(worker_id, activity_contract_id)
                  WHERE cancellation_route.worker_id = job.payload ->> 'worker_id'
                    AND cancellation_route.activity_contract_id = job.activity_contract_id
              )
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
              )
          )
          OR (
              job.job_type = 'OBSERVE_RUNMILL_RUN'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($11::text[], $12::text[]) AS observation_route(worker_id, activity_contract_id)
                  WHERE observation_route.worker_id = job.payload ->> 'worker_id'
                    AND observation_route.activity_contract_id = job.activity_contract_id
              )
              -- An observer job may only be claimed while it is the exact
              -- active V2 checkpoint of a live stream.  The admission
              -- session remains immutable provenance; `observer_session_id`
              -- is the separately-live control session for this poll.
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN work_orders AS route_work_order
                    ON route_work_order.tenant_id = route_run.tenant_id
                   AND route_work_order.id = route_run.work_order_id
                   AND route_work_order.work_item_id = route_run.work_item_id
                   AND route_work_order.attempt_id = route_run.attempt_id
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  JOIN runmill_run_observation_checkpoints AS checkpoint
                    ON checkpoint.tenant_id = stream.tenant_id
                   AND checkpoint.id::text = job.payload ->> 'observation_id'
                   AND checkpoint.run_id = stream.run_id
                   AND checkpoint.workflow_job_id = job.id
                  JOIN worker_sessions AS observer_session
                    ON observer_session.tenant_id = checkpoint.tenant_id
                   AND observer_session.id = checkpoint.observer_session_id
                   AND observer_session.worker_id = checkpoint.worker_id
                   AND observer_session.worker_generation = checkpoint.worker_generation
                  JOIN workers AS observer_worker
                    ON observer_worker.tenant_id = observer_session.tenant_id
                   AND observer_worker.id = observer_session.worker_id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND jsonb_typeof(job.payload) = 'object'
                    AND job.payload ?& ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ]
                    AND job.payload - ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ] = '{}'::jsonb
                    AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
                    AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
                    AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
                    AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
                    AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.work_order_id::text = job.payload ->> 'work_order_id'
                    AND route_work_order.payload_digest = job.payload ->> 'work_order_digest'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.worker_session_id::text = job.payload ->> 'worker_session_id'
                    AND job.payload -> 'worker_generation' = to_jsonb(route_run.worker_generation)
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.workflow_instance_id = job.workflow_instance_id
                    AND stream.work_item_id = job.work_item_id
                    AND stream.attempt_id = job.attempt_id
                    AND stream.work_order_id = route_run.work_order_id
                    AND stream.work_order_digest = route_work_order.payload_digest
                    AND stream.worker_id = route_run.worker_id
                    AND stream.worker_generation = route_run.worker_generation
                    AND stream.run_admission_worker_session_id = route_run.worker_session_id
                    AND stream.external_run_id = route_run.external_run_id
                    AND stream.state = 'ACTIVE'
                    AND stream.active_job_id = job.id
                    AND stream.active_observation_id = checkpoint.id
                    AND checkpoint.after_sequence = stream.next_after_sequence
                    AND checkpoint.observation_epoch = stream.observation_epoch
                    AND checkpoint.observer_session_id::text = job.payload ->> 'observer_session_id'
                    AND checkpoint.worker_id = stream.worker_id
                    AND checkpoint.worker_generation = stream.worker_generation
                    AND job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)
                    AND job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)
                    AND observer_session.status = 'ACTIVE'
                    AND observer_session.expires_at > clock_timestamp()
                    AND observer_worker.generation = stream.worker_generation
                    AND observer_worker.status <> 'QUARANTINED'
              )
          )
          OR (
              job.job_type = 'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($13::text[], $14::text[]) AS retention_route(worker_id, activity_contract_id)
                  WHERE retention_route.worker_id = job.payload ->> 'worker_id'
                    AND retention_route.activity_contract_id = job.activity_contract_id
              )
              -- A retention job may only be claimed while its stream is still
              -- TERMINAL_READY through the exact observation result whose two
              -- snapshots the payload names, and while a live control session
              -- exists to make the asf.get_evidence read.  The admission
              -- session stays immutable provenance; `observer_session_id` is
              -- the separately-live control session for this read.
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN work_orders AS route_work_order
                    ON route_work_order.tenant_id = route_run.tenant_id
                   AND route_work_order.id = route_run.work_order_id
                   AND route_work_order.work_item_id = route_run.work_item_id
                   AND route_work_order.attempt_id = route_run.attempt_id
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  JOIN runmill_run_observation_results AS result
                    ON result.tenant_id = stream.tenant_id
                   AND result.run_id = stream.run_id
                   AND result.observation_id::text = job.payload ->> 'observation_id'
                  JOIN worker_sessions AS observer_session
                    ON observer_session.tenant_id = stream.tenant_id
                   AND observer_session.id::text = job.payload ->> 'observer_session_id'
                   AND observer_session.worker_id = stream.worker_id
                   AND observer_session.worker_generation = stream.worker_generation
                  JOIN workers AS observer_worker
                    ON observer_worker.tenant_id = observer_session.tenant_id
                   AND observer_worker.id = observer_session.worker_id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND jsonb_typeof(job.payload) = 'object'
                    AND job.payload ?& ARRAY[
                        'schema', 'bundle_id', 'run_id', 'work_order_id', 'work_order_digest',
                        'worker_id', 'worker_session_id', 'worker_generation', 'observer_session_id',
                        'external_run_id', 'observation_id', 'get_run_snapshot_id',
                        'event_page_snapshot_id', 'terminal_phase', 'terminal_event_seq'
                    ]
                    AND job.payload - ARRAY[
                        'schema', 'bundle_id', 'run_id', 'work_order_id', 'work_order_digest',
                        'worker_id', 'worker_session_id', 'worker_generation', 'observer_session_id',
                        'external_run_id', 'observation_id', 'get_run_snapshot_id',
                        'event_page_snapshot_id', 'terminal_phase', 'terminal_event_seq'
                    ] = '{}'::jsonb
                    AND job.payload ->> 'schema' = 'asf.runmill-terminal-evidence/v1'
                    AND jsonb_typeof(job.payload -> 'bundle_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
                    AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'get_run_snapshot_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'event_page_snapshot_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'terminal_phase') = 'string'
                    AND jsonb_typeof(job.payload -> 'terminal_event_seq') = 'number'
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.work_order_id::text = job.payload ->> 'work_order_id'
                    AND route_work_order.payload_digest = job.payload ->> 'work_order_digest'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.worker_session_id::text = job.payload ->> 'worker_session_id'
                    AND job.payload -> 'worker_generation' = to_jsonb(route_run.worker_generation)
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.workflow_instance_id = job.workflow_instance_id
                    AND stream.work_item_id = job.work_item_id
                    AND stream.attempt_id = job.attempt_id
                    AND stream.work_order_id = route_run.work_order_id
                    AND stream.work_order_digest = route_work_order.payload_digest
                    AND stream.worker_id = route_run.worker_id
                    AND stream.worker_generation = route_run.worker_generation
                    AND stream.run_admission_worker_session_id = route_run.worker_session_id
                    AND stream.external_run_id = route_run.external_run_id
                    AND stream.state = 'TERMINAL_READY'
                    AND result.disposition = 'TERMINAL_READY'
                    AND result.get_run_snapshot_id::text = job.payload ->> 'get_run_snapshot_id'
                    AND result.event_page_snapshot_id::text
                        = job.payload ->> 'event_page_snapshot_id'
                    AND job.payload -> 'terminal_event_seq' = to_jsonb(result.next_sequence + 1)
                    AND observer_session.status = 'ACTIVE'
                    AND observer_session.expires_at > clock_timestamp()
                    AND observer_worker.generation = stream.worker_generation
                    AND observer_worker.status <> 'QUARANTINED'
              )
          )
      )
      AND job.attempt_count < job.max_attempts
      AND (
          (
              job.status IN ('PENDING', 'RETRY')
              AND job.available_at <= clock_timestamp()
          )
          OR (
              job.status = 'RUNNING'
              AND job.lease_expires_at <= clock_timestamp()
          )
      )
    ORDER BY job.priority DESC, job.available_at, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT $2
), released_external_effects AS (
    -- Only an expired RUNNING claim can own an in-flight external mutation.
    -- Release that exact effect into explicit uncertainty before changing the
    -- workflow-job fence. Fresh PENDING/RETRY candidates are never touched.
    UPDATE effect_intents AS effect
    SET status = 'AMBIGUOUS',
        owning_workflow_job_id = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error = left(
            concat_ws(
                '; ',
                NULLIF(effect.last_error, ''),
                'owning workflow-job lease expired; exact external-effect reconciliation required'
            ),
            8192
        ),
        updated_at = clock_timestamp()
    FROM candidates
    WHERE candidates.reclaiming_expired
      AND effect.tenant_id = $1
      AND effect.owning_workflow_job_id = candidates.id
      AND effect.status = 'IN_FLIGHT'
      AND (
          (effect.provider = 'runmill' AND effect.effect_type IN (
              'request_cancellation',
              'submit_work_order'
          ))
          OR (effect.provider = 'linear' AND effect.effect_type = 'close_source')
      )
    RETURNING effect.id
)
UPDATE workflow_jobs AS job
SET status = 'RUNNING',
    attempt_count = job.attempt_count + 1,
    fence_token = job.fence_token + 1,
    lease_owner = $3,
    lease_expires_at = clock_timestamp() + ($4::bigint * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.tenant_id = $1
  AND job.id = candidates.id
  AND (SELECT count(*) FROM released_external_effects) >= 0
RETURNING
    job.id,
    job.tenant_id,
    job.workflow_instance_id,
    job.work_item_id,
    job.attempt_id,
    job.job_type,
    job.activity_contract_id,
    job.payload,
    job.idempotency_key,
    job.priority,
    job.attempt_count,
    job.max_attempts,
    job.fence_token,
    job.lease_owner,
    job.lease_expires_at,
    job.created_at
";

const UNKNOWN_OR_INCOMPATIBLE_DUE_JOB_SQL: &str = r"
SELECT job.job_type, job.activity_contract_id
FROM workflow_jobs AS job
WHERE job.tenant_id = $1
  AND NOT EXISTS (
      SELECT 1
      FROM unnest($2::text[], $3::text[]) AS known_route(job_type, activity_contract_id)
      WHERE known_route.job_type = job.job_type
        AND known_route.activity_contract_id = job.activity_contract_id
  )
  AND (
      (job.status IN ('PENDING', 'RETRY') AND job.available_at <= clock_timestamp())
      OR (job.status = 'RUNNING' AND job.lease_expires_at <= clock_timestamp())
  )
ORDER BY job.priority DESC, job.available_at, job.id
LIMIT 1
";

const CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL: &str = r"
WITH candidates AS (
    SELECT
        job.id,
        job.status = 'RUNNING' AS reclaiming_expired
    FROM workflow_jobs AS job
    WHERE job.tenant_id = $1
      AND job.job_type IN (
          'RECONCILE_WORKER',
          'REQUEST_WORK_ITEM_CANCELLATION',
          'OBSERVE_RUNMILL_RUN'
      )
      -- A row whose activity_contract_id is not this job_type's canonical,
      -- currently-installed identity is never route-invalid: it is either an
      -- unrecognized-or-incompatible contract (already rejected fail-closed
      -- before this scan ever runs) or a still-scheduled future contract.
      -- Never dead-letter it here as a merely malformed route.
      AND (
          (job.job_type = 'RECONCILE_WORKER' AND job.activity_contract_id = $4)
          OR (job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' AND job.activity_contract_id = $5)
          OR (job.job_type = 'OBSERVE_RUNMILL_RUN' AND job.activity_contract_id = $6)
      )
      AND (
          jsonb_typeof(job.payload -> 'worker_id') IS DISTINCT FROM 'string'
          OR NOT COALESCE(
              job.payload ->> 'worker_id'
                  ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
              false
          )
          OR (
              job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND NOT EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
              )
          )
          OR (
              job.job_type = 'OBSERVE_RUNMILL_RUN'
              AND NOT EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN work_orders AS route_work_order
                    ON route_work_order.tenant_id = route_run.tenant_id
                   AND route_work_order.id = route_run.work_order_id
                   AND route_work_order.work_item_id = route_run.work_item_id
                   AND route_work_order.attempt_id = route_run.attempt_id
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  JOIN runmill_run_observation_checkpoints AS checkpoint
                    ON checkpoint.tenant_id = stream.tenant_id
                   AND checkpoint.id::text = job.payload ->> 'observation_id'
                   AND checkpoint.run_id = stream.run_id
                   AND checkpoint.workflow_job_id = job.id
                  JOIN worker_sessions AS observer_session
                    ON observer_session.tenant_id = checkpoint.tenant_id
                   AND observer_session.id = checkpoint.observer_session_id
                   AND observer_session.worker_id = checkpoint.worker_id
                   AND observer_session.worker_generation = checkpoint.worker_generation
                  JOIN workers AS observer_worker
                    ON observer_worker.tenant_id = observer_session.tenant_id
                   AND observer_worker.id = observer_session.worker_id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND jsonb_typeof(job.payload) = 'object'
                    AND job.payload ?& ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ]
                    AND job.payload - ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ] = '{}'::jsonb
                    AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
                    AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
                    AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
                    AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
                    AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.work_order_id::text = job.payload ->> 'work_order_id'
                    AND route_work_order.payload_digest = job.payload ->> 'work_order_digest'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.worker_session_id::text = job.payload ->> 'worker_session_id'
                    AND job.payload -> 'worker_generation' = to_jsonb(route_run.worker_generation)
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.workflow_instance_id = job.workflow_instance_id
                    AND stream.work_item_id = job.work_item_id
                    AND stream.attempt_id = job.attempt_id
                    AND stream.work_order_id = route_run.work_order_id
                    AND stream.work_order_digest = route_work_order.payload_digest
                    AND stream.worker_id = route_run.worker_id
                    AND stream.worker_generation = route_run.worker_generation
                    AND stream.run_admission_worker_session_id = route_run.worker_session_id
                    AND stream.external_run_id = route_run.external_run_id
                    AND stream.state = 'ACTIVE'
                    AND stream.active_job_id = job.id
                    AND stream.active_observation_id = checkpoint.id
                    AND checkpoint.after_sequence = stream.next_after_sequence
                    AND checkpoint.observation_epoch = stream.observation_epoch
                    AND checkpoint.observer_session_id::text = job.payload ->> 'observer_session_id'
                    AND checkpoint.worker_id = stream.worker_id
                    AND checkpoint.worker_generation = stream.worker_generation
                    AND job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)
                    AND job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)
                    AND observer_session.status = 'ACTIVE'
                    AND observer_session.expires_at > clock_timestamp()
                    AND observer_worker.generation = stream.worker_generation
                    AND observer_worker.status <> 'QUARANTINED'
              )
          )
      )
      AND (
          (job.status IN ('PENDING', 'RETRY') AND job.available_at <= clock_timestamp())
          OR (job.status = 'RUNNING' AND job.lease_expires_at <= clock_timestamp())
      )
    ORDER BY job.priority DESC, job.available_at, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT 1
), released_external_effects AS (
    UPDATE effect_intents AS effect
    SET status = 'AMBIGUOUS',
        owning_workflow_job_id = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error = left(
            concat_ws(
                '; ',
                NULLIF(effect.last_error, ''),
                'route-invalid scoped workflow job expired while owning the external effect; exact reconciliation required'
            ),
            8192
        ),
        updated_at = clock_timestamp()
    FROM candidates
    WHERE candidates.reclaiming_expired
      AND effect.tenant_id = $1
      AND effect.owning_workflow_job_id = candidates.id
      AND effect.status = 'IN_FLIGHT'
      AND (
          (effect.provider = 'runmill' AND effect.effect_type IN (
              'request_cancellation',
              'submit_work_order'
          ))
          OR (effect.provider = 'linear' AND effect.effect_type = 'close_source')
      )
    RETURNING effect.id
)
UPDATE workflow_jobs AS job
SET status = 'RUNNING',
    attempt_count = GREATEST(job.attempt_count, job.max_attempts),
    fence_token = job.fence_token + 1,
    lease_owner = $2,
    lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.tenant_id = $1
  AND job.id = candidates.id
  AND (SELECT count(*) FROM released_external_effects) >= 0
RETURNING
    job.id,
    job.tenant_id,
    job.workflow_instance_id,
    job.work_item_id,
    job.attempt_id,
    job.job_type,
    job.activity_contract_id,
    job.payload,
    job.idempotency_key,
    job.priority,
    job.attempt_count,
    job.max_attempts,
    job.fence_token,
    job.lease_owner,
    job.lease_expires_at,
    job.created_at
";

const CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL: &str = r"
WITH candidates AS (
    SELECT job.id
    FROM workflow_jobs AS job
    WHERE job.tenant_id = $1
      AND job.status = 'RUNNING'
      AND job.attempt_count >= job.max_attempts
      AND job.lease_expires_at <= clock_timestamp()
      AND (
          (
              job.job_type NOT IN (
                  'RECONCILE_WORKER',
                  'REQUEST_WORK_ITEM_CANCELLATION',
                  'OBSERVE_RUNMILL_RUN',
                  'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
              )
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS unscoped_route(job_type, activity_contract_id)
                  WHERE unscoped_route.job_type = job.job_type
                    AND unscoped_route.activity_contract_id = job.activity_contract_id
              )
          )
          OR (
              job.job_type = 'RECONCILE_WORKER'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($6::text[], $7::text[]) AS reconcile_route(worker_id, activity_contract_id)
                  WHERE reconcile_route.worker_id = job.payload ->> 'worker_id'
                    AND reconcile_route.activity_contract_id = job.activity_contract_id
              )
          )
          OR (
              job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($8::text[], $9::text[]) AS cancellation_route(worker_id, activity_contract_id)
                  WHERE cancellation_route.worker_id = job.payload ->> 'worker_id'
                    AND cancellation_route.activity_contract_id = job.activity_contract_id
              )
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
              )
          )
          OR (
              job.job_type = 'OBSERVE_RUNMILL_RUN'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($10::text[], $11::text[]) AS observation_route(worker_id, activity_contract_id)
                  WHERE observation_route.worker_id = job.payload ->> 'worker_id'
                    AND observation_route.activity_contract_id = job.activity_contract_id
              )
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN work_orders AS route_work_order
                    ON route_work_order.tenant_id = route_run.tenant_id
                   AND route_work_order.id = route_run.work_order_id
                   AND route_work_order.work_item_id = route_run.work_item_id
                   AND route_work_order.attempt_id = route_run.attempt_id
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  JOIN runmill_run_observation_checkpoints AS checkpoint
                    ON checkpoint.tenant_id = stream.tenant_id
                   AND checkpoint.id::text = job.payload ->> 'observation_id'
                   AND checkpoint.run_id = stream.run_id
                   AND checkpoint.workflow_job_id = job.id
                  JOIN worker_sessions AS observer_session
                    ON observer_session.tenant_id = checkpoint.tenant_id
                   AND observer_session.id = checkpoint.observer_session_id
                   AND observer_session.worker_id = checkpoint.worker_id
                   AND observer_session.worker_generation = checkpoint.worker_generation
                  JOIN workers AS observer_worker
                    ON observer_worker.tenant_id = observer_session.tenant_id
                   AND observer_worker.id = observer_session.worker_id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND jsonb_typeof(job.payload) = 'object'
                    AND job.payload ?& ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ]
                    AND job.payload - ARRAY[
                        'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                        'worker_session_id', 'worker_generation', 'external_run_id',
                        'after_sequence', 'observation_epoch', 'observer_session_id'
                    ] = '{}'::jsonb
                    AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
                    AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
                    AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
                    AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
                    AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
                    AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.work_order_id::text = job.payload ->> 'work_order_id'
                    AND route_work_order.payload_digest = job.payload ->> 'work_order_digest'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.worker_session_id::text = job.payload ->> 'worker_session_id'
                    AND job.payload -> 'worker_generation' = to_jsonb(route_run.worker_generation)
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.workflow_instance_id = job.workflow_instance_id
                    AND stream.work_item_id = job.work_item_id
                    AND stream.attempt_id = job.attempt_id
                    AND stream.work_order_id = route_run.work_order_id
                    AND stream.work_order_digest = route_work_order.payload_digest
                    AND stream.worker_id = route_run.worker_id
                    AND stream.worker_generation = route_run.worker_generation
                    AND stream.run_admission_worker_session_id = route_run.worker_session_id
                    AND stream.external_run_id = route_run.external_run_id
                    AND stream.state = 'ACTIVE'
                    AND stream.active_job_id = job.id
                    AND stream.active_observation_id = checkpoint.id
                    AND checkpoint.after_sequence = stream.next_after_sequence
                    AND checkpoint.observation_epoch = stream.observation_epoch
                    AND checkpoint.observer_session_id::text = job.payload ->> 'observer_session_id'
                    AND checkpoint.worker_id = stream.worker_id
                    AND checkpoint.worker_generation = stream.worker_generation
                    AND job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)
                    AND job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)
                    AND observer_session.status = 'ACTIVE'
                    AND observer_session.expires_at > clock_timestamp()
                    AND observer_worker.generation = stream.worker_generation
                    AND observer_worker.status <> 'QUARANTINED'
              )
          )
          OR (
              job.job_type = 'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
              AND EXISTS (
                  SELECT 1
                  FROM unnest($12::text[], $13::text[]) AS retention_route(worker_id, activity_contract_id)
                  WHERE retention_route.worker_id = job.payload ->> 'worker_id'
                    AND retention_route.activity_contract_id = job.activity_contract_id
              )
              -- An exhausted retention job is recovered only when this process
              -- genuinely owns its worker route and the run it names is still
              -- the authoritative one.
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
              )
          )
      )
    ORDER BY job.lease_expires_at, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT 1
), released_external_effects AS (
    -- An expired final claim must release its exact mutable provider effect
    -- before the recovery owner can re-fence and dead-letter the job.
    UPDATE effect_intents AS effect
    SET status = 'AMBIGUOUS',
        owning_workflow_job_id = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error = left(
            concat_ws(
                '; ',
                NULLIF(effect.last_error, ''),
                'owning workflow-job lease expired; exact external-effect reconciliation required'
            ),
            8192
        ),
        updated_at = clock_timestamp()
    FROM candidates
    WHERE effect.tenant_id = $1
      AND effect.owning_workflow_job_id = candidates.id
      AND effect.status = 'IN_FLIGHT'
      AND (
          (effect.provider = 'runmill' AND effect.effect_type IN (
              'request_cancellation',
              'submit_work_order'
          ))
          OR (effect.provider = 'linear' AND effect.effect_type = 'close_source')
      )
    RETURNING effect.id
)
UPDATE workflow_jobs AS job
SET fence_token = job.fence_token + 1,
    lease_owner = $2,
    lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.tenant_id = $1
  AND job.id = candidates.id
  AND (SELECT count(*) FROM released_external_effects) >= 0
RETURNING
    job.id,
    job.tenant_id,
    job.workflow_instance_id,
    job.work_item_id,
    job.attempt_id,
    job.job_type,
    job.activity_contract_id,
    job.payload,
    job.idempotency_key,
    job.priority,
    job.attempt_count,
    job.max_attempts,
    job.fence_token,
    job.lease_owner,
    job.lease_expires_at,
    job.created_at
";

const CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL: &str = r"
WITH candidates AS (
    SELECT
        job.id,
        job.status = 'RUNNING' AS reclaiming_expired
    FROM workflow_jobs AS job
    WHERE job.tenant_id = $1
      AND (
          (job.status IN ('PENDING', 'RETRY') AND job.available_at <= clock_timestamp())
          OR (job.status = 'RUNNING' AND job.lease_expires_at <= clock_timestamp())
      )
      AND (
          (
              job.job_type NOT IN (
                  'RECONCILE_WORKER',
                  'REQUEST_WORK_ITEM_CANCELLATION',
                  'OBSERVE_RUNMILL_RUN',
                  'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
              )
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)
                  WHERE known_route.job_type = job.job_type
                    AND known_route.activity_contract_id = job.activity_contract_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unnest($6::text[], $7::text[]) AS ready_route(job_type, activity_contract_id)
                  WHERE ready_route.job_type = job.job_type
                    AND ready_route.activity_contract_id = job.activity_contract_id
              )
          )
          OR (
              job.job_type = 'RECONCILE_WORKER'
              AND job.activity_contract_id = $8
              -- Unavailable means this process installs no ready handler for
              -- the type at all. A process that serves another worker route
              -- must never dead-letter that other worker jobs.
              AND cardinality($9::text[]) = 0
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)
                  WHERE known_route.job_type = job.job_type
                    AND known_route.activity_contract_id = job.activity_contract_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unnest($9::text[], $10::text[]) AS ready_route(worker_id, activity_contract_id)
                  WHERE ready_route.worker_id = job.payload ->> 'worker_id'
                    AND ready_route.activity_contract_id = job.activity_contract_id
              )
              AND jsonb_typeof(job.payload) = 'object'
              AND job.payload ?& ARRAY['worker_id', 'expected_generation', 'expected_version']
              AND job.payload - ARRAY['worker_id', 'expected_generation', 'expected_version'] = '{}'::jsonb
              AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
              AND COALESCE(
                  job.payload ->> 'worker_id'
                      ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
                  false
              )
              AND jsonb_typeof(job.payload -> 'expected_generation') = 'number'
              AND job.payload ->> 'expected_generation' ~ '^[0-9]+$'
              AND (job.payload ->> 'expected_generation')::bigint > 0
              AND jsonb_typeof(job.payload -> 'expected_version') = 'number'
              AND job.payload ->> 'expected_version' ~ '^[0-9]+$'
              AND (job.payload ->> 'expected_version')::bigint > 0
              AND job.workflow_instance_id IS NULL
              AND job.work_item_id IS NULL
              AND job.attempt_id IS NULL
              AND job.idempotency_key IS NOT NULL
              AND btrim(job.idempotency_key) != ''
          )
          OR (
              job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND job.activity_contract_id = $11
              -- Unavailable means this process installs no ready handler for
              -- the type at all. A process that serves another worker route
              -- must never dead-letter that other worker jobs.
              AND cardinality($12::text[]) = 0
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)
                  WHERE known_route.job_type = job.job_type
                    AND known_route.activity_contract_id = job.activity_contract_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unnest($12::text[], $13::text[]) AS ready_route(worker_id, activity_contract_id)
                  WHERE ready_route.worker_id = job.payload ->> 'worker_id'
                    AND ready_route.activity_contract_id = job.activity_contract_id
              )
              AND jsonb_typeof(job.payload) = 'object'
              AND (job.payload ?& ARRAY['work_item_id', 'worker_id', 'expected_version', 'reason', 'requested_by']
                  OR job.payload ?& ARRAY['work_item_id', 'worker_id', 'expected_version', 'reason', 'requested_by', 'observe_only'])
              AND job.payload - ARRAY['work_item_id', 'worker_id', 'expected_version', 'reason', 'requested_by', 'observe_only'] = '{}'::jsonb
              AND jsonb_typeof(job.payload -> 'work_item_id') = 'string'
              AND job.payload ->> 'work_item_id' = job.work_item_id::text
              AND COALESCE(job.payload ->> 'work_item_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND (jsonb_typeof(job.payload -> 'observe_only') IS NULL OR jsonb_typeof(job.payload -> 'observe_only') = 'boolean')
              AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
              AND COALESCE(
                  job.payload ->> 'worker_id'
                      ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
                  false
              )
              AND jsonb_typeof(job.payload -> 'expected_version') = 'number'
              AND job.payload ->> 'expected_version' ~ '^[0-9]+$'
              AND (job.payload ->> 'expected_version')::bigint > 0
              AND jsonb_typeof(job.payload -> 'reason') = 'string'
              AND job.payload ->> 'reason' = btrim(job.payload ->> 'reason')
              AND char_length(job.payload ->> 'reason') <= 2048
              AND jsonb_typeof(job.payload -> 'requested_by') = 'string'
              AND char_length(job.payload ->> 'requested_by') <= 1024
              AND job.workflow_instance_id IS NOT NULL
              AND job.attempt_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
              )
          )
          OR (
              job.job_type = 'OBSERVE_RUNMILL_RUN'
              AND job.activity_contract_id = $14
              -- Unavailable means this process installs no ready handler for
              -- the type at all. A process that serves another worker route
              -- must never dead-letter that other worker jobs.
              AND cardinality($15::text[]) = 0
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)
                  WHERE known_route.job_type = job.job_type
                    AND known_route.activity_contract_id = job.activity_contract_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unnest($15::text[], $16::text[]) AS ready_route(worker_id, activity_contract_id)
                  WHERE ready_route.worker_id = job.payload ->> 'worker_id'
                    AND ready_route.activity_contract_id = job.activity_contract_id
              )
              AND jsonb_typeof(job.payload) = 'object'
              AND job.payload ?& ARRAY[
                  'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                  'worker_session_id', 'worker_generation', 'external_run_id',
                  'after_sequence', 'observation_epoch', 'observer_session_id'
              ]
              AND job.payload - ARRAY[
                  'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                  'worker_session_id', 'worker_generation', 'external_run_id',
                  'after_sequence', 'observation_epoch', 'observer_session_id'
              ] = '{}'::jsonb
              AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
              AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
              AND COALESCE(job.payload ->> 'observation_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'run_id') = 'string'
              AND COALESCE(job.payload ->> 'run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
              AND COALESCE(job.payload ->> 'work_order_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
              AND COALESCE(job.payload ->> 'work_order_digest' ~ '^sha256:[0-9a-f]{64}$', false)
              AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
              AND COALESCE(job.payload ->> 'worker_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
              AND COALESCE(job.payload ->> 'worker_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
              AND job.payload ->> 'worker_generation' ~ '^[0-9]+$'
              AND (job.payload ->> 'worker_generation')::bigint > 0
              AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
              AND COALESCE(LENGTH(job.payload ->> 'external_run_id') > 0, false)
              AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
              AND job.payload ->> 'after_sequence' ~ '^[0-9]+$'
              AND (job.payload ->> 'after_sequence')::bigint >= 0
              AND (job.payload ->> 'after_sequence')::bigint <= 9007199254740991
              AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
              AND job.payload ->> 'observation_epoch' ~ '^[0-9]+$'
              AND (job.payload ->> 'observation_epoch')::bigint > 0
              AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
              AND COALESCE(job.payload ->> 'observer_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN work_orders AS route_work_order
                    ON route_work_order.tenant_id = route_run.tenant_id
                   AND route_work_order.id = route_run.work_order_id
                   AND route_work_order.work_item_id = route_run.work_item_id
                   AND route_work_order.attempt_id = route_run.attempt_id
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  JOIN runmill_run_observation_checkpoints AS checkpoint
                    ON checkpoint.tenant_id = stream.tenant_id
                   AND checkpoint.run_id = stream.run_id
                   AND checkpoint.workflow_job_id = job.id
                  JOIN worker_sessions AS observer_session
                    ON observer_session.tenant_id = checkpoint.tenant_id
                   AND observer_session.id = checkpoint.observer_session_id
                   AND observer_session.worker_id = checkpoint.worker_id
                   AND observer_session.worker_generation = checkpoint.worker_generation
                  JOIN workers AS observer_worker
                    ON observer_worker.tenant_id = observer_session.tenant_id
                   AND observer_worker.id = observer_session.worker_id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.work_order_id::text = job.payload ->> 'work_order_id'
                    AND route_work_order.payload_digest = job.payload ->> 'work_order_digest'
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.worker_generation = (job.payload ->> 'worker_generation')::bigint
                    AND route_run.worker_session_id::text = job.payload ->> 'worker_session_id'
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.workflow_instance_id = job.workflow_instance_id
                    AND stream.work_item_id = job.work_item_id
                    AND stream.attempt_id = job.attempt_id
                    AND stream.work_order_id = route_run.work_order_id
                    AND stream.work_order_digest = route_work_order.payload_digest
                    AND stream.worker_id = route_run.worker_id
                    AND stream.worker_generation = route_run.worker_generation
                    AND stream.run_admission_worker_session_id = route_run.worker_session_id
                    AND stream.external_run_id = route_run.external_run_id
                    AND stream.state = 'ACTIVE'
                    AND stream.active_job_id = job.id
                    AND stream.active_observation_id = checkpoint.id
                    AND checkpoint.id::text = job.payload ->> 'observation_id'
                    AND checkpoint.after_sequence = stream.next_after_sequence
                    AND checkpoint.observation_epoch = stream.observation_epoch
                    AND checkpoint.observer_session_id::text = job.payload ->> 'observer_session_id'
                    AND checkpoint.worker_id = stream.worker_id
                    AND checkpoint.worker_generation = stream.worker_generation
                    AND job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)
                    AND job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)
                    AND observer_session.status = 'ACTIVE'
                    AND observer_session.expires_at > clock_timestamp()
                    AND observer_worker.generation = stream.worker_generation
                    AND observer_worker.status <> 'QUARANTINED'
              )
          )
          OR (
              job.job_type = 'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
              AND job.activity_contract_id = $17
              -- Unavailable means this process installs no ready handler for
              -- the type at all. A process that serves another worker route
              -- must never dead-letter that other worker jobs.
              AND cardinality($18::text[]) = 0
              AND EXISTS (
                  SELECT 1
                  FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)
                  WHERE known_route.job_type = job.job_type
                    AND known_route.activity_contract_id = job.activity_contract_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unnest($18::text[], $19::text[]) AS ready_route(worker_id, activity_contract_id)
                  WHERE ready_route.worker_id = job.payload ->> 'worker_id'
                    AND ready_route.activity_contract_id = job.activity_contract_id
              )
              AND jsonb_typeof(job.payload) = 'object'
              AND job.payload ?& ARRAY[
                  'schema', 'bundle_id', 'run_id', 'work_order_id', 'work_order_digest',
                  'worker_id', 'worker_session_id', 'worker_generation', 'observer_session_id',
                  'external_run_id', 'observation_id', 'get_run_snapshot_id',
                  'event_page_snapshot_id', 'terminal_phase', 'terminal_event_seq'
              ]
              AND job.payload - ARRAY[
                  'schema', 'bundle_id', 'run_id', 'work_order_id', 'work_order_digest',
                  'worker_id', 'worker_session_id', 'worker_generation', 'observer_session_id',
                  'external_run_id', 'observation_id', 'get_run_snapshot_id',
                  'event_page_snapshot_id', 'terminal_phase', 'terminal_event_seq'
              ] = '{}'::jsonb
              AND job.payload ->> 'schema' = 'asf.runmill-terminal-evidence/v1'
              AND jsonb_typeof(job.payload -> 'bundle_id') = 'string'
              AND COALESCE(job.payload ->> 'bundle_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'run_id') = 'string'
              AND COALESCE(job.payload ->> 'run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
              AND COALESCE(job.payload ->> 'work_order_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
              AND COALESCE(job.payload ->> 'work_order_digest' ~ '^sha256:[0-9a-f]{64}$', false)
              AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
              AND COALESCE(job.payload ->> 'worker_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
              AND COALESCE(job.payload ->> 'worker_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
              AND job.payload ->> 'worker_generation' ~ '^[0-9]+$'
              AND (job.payload ->> 'worker_generation')::bigint > 0
              AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
              AND COALESCE(job.payload ->> 'observer_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
              AND COALESCE(LENGTH(job.payload ->> 'external_run_id') > 0, false)
              AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
              AND COALESCE(job.payload ->> 'observation_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'get_run_snapshot_id') = 'string'
              AND COALESCE(job.payload ->> 'get_run_snapshot_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND jsonb_typeof(job.payload -> 'event_page_snapshot_id') = 'string'
              AND COALESCE(job.payload ->> 'event_page_snapshot_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', false)
              AND job.payload ->> 'get_run_snapshot_id'
                  IS DISTINCT FROM job.payload ->> 'event_page_snapshot_id'
              AND jsonb_typeof(job.payload -> 'terminal_phase') = 'string'
              AND job.payload ->> 'terminal_phase' IN (
                  'COMPLETED', 'CANCELLED', 'FAILED', 'REFUSED', 'QUARANTINED', 'BUDGET_EXHAUSTED'
              )
              AND jsonb_typeof(job.payload -> 'terminal_event_seq') = 'number'
              AND job.payload ->> 'terminal_event_seq' ~ '^[0-9]+$'
              AND (job.payload ->> 'terminal_event_seq')::bigint > 0
              AND (job.payload ->> 'terminal_event_seq')::bigint <= 9007199254740991
              AND job.workflow_instance_id IS NOT NULL
              AND job.work_item_id IS NOT NULL
              AND job.attempt_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM runs AS route_run
                  JOIN runmill_run_observation_streams AS stream
                    ON stream.tenant_id = route_run.tenant_id
                   AND stream.run_id = route_run.id
                  WHERE route_run.tenant_id = job.tenant_id
                    AND route_run.id::text = job.payload ->> 'run_id'
                    AND route_run.work_item_id = job.work_item_id
                    AND route_run.attempt_id = job.attempt_id
                    AND route_run.authoritative
                    AND route_run.worker_id::text = job.payload ->> 'worker_id'
                    AND route_run.external_run_id = job.payload ->> 'external_run_id'
                    AND stream.state = 'TERMINAL_READY'
              )
          )
      )
    ORDER BY job.priority DESC, job.available_at, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT 1
), released_external_effects AS (
    UPDATE effect_intents AS effect
    SET status = 'AMBIGUOUS',
        owning_workflow_job_id = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error = left(
            concat_ws(
                '; ',
                NULLIF(effect.last_error, ''),
                'owning workflow-job lease expired; exact external-effect reconciliation required'
            ),
            8192
        ),
        updated_at = clock_timestamp()
    FROM candidates
    WHERE candidates.reclaiming_expired
      AND effect.tenant_id = $1
      AND effect.owning_workflow_job_id = candidates.id
      AND effect.status = 'IN_FLIGHT'
      AND (
          (effect.provider = 'runmill' AND effect.effect_type IN (
              'request_cancellation',
              'submit_work_order'
          ))
          OR (effect.provider = 'linear' AND effect.effect_type = 'close_source')
      )
    RETURNING effect.id
)
UPDATE workflow_jobs AS job
SET status = 'RUNNING',
    attempt_count = GREATEST(job.attempt_count, job.max_attempts),
    fence_token = job.fence_token + 1,
    lease_owner = $2,
    lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.tenant_id = $1
  AND job.id = candidates.id
  AND (SELECT count(*) FROM released_external_effects) >= 0
RETURNING
    job.id,
    job.tenant_id,
    job.workflow_instance_id,
    job.work_item_id,
    job.attempt_id,
    job.job_type,
    job.activity_contract_id,
    job.payload,
    job.idempotency_key,
    job.priority,
    job.attempt_count,
    job.max_attempts,
    job.fence_token,
    job.lease_owner,
    job.lease_expires_at,
    job.created_at
";

const ORPHANED_FINAL_ATTEMPT_ERROR: &str = "final workflow-job attempt ended without a committed outcome; recovered after its claim expired";
const ROUTE_INVALID_SCOPED_JOB_ERROR: &str = "known worker-scoped workflow job has a missing, malformed, or contradictory immutable route; no daemon call was attempted";
const KNOWN_UNSERVICEABLE_DUE_JOB_ERROR: &str = "known durable activity type is installed as unavailable; workflow job escalated to operational incident";

/// Bounded operational settings for one reactor instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactorOptions {
    pub lease_owner: String,
    pub poll_interval: Duration,
    pub lease_duration: Duration,
    pub max_error_backoff: Duration,
    pub claim_batch_size: u32,
}

impl ReactorOptions {
    pub fn validate(&self) -> Result<()> {
        if self.lease_owner.trim().is_empty() {
            return Err(Error::Validation(
                "reactor lease owner must be non-empty".into(),
            ));
        }
        if self.poll_interval.is_zero() {
            return Err(Error::Validation(
                "reactor poll interval must be positive".into(),
            ));
        }
        if self.lease_duration <= self.poll_interval {
            return Err(Error::Validation(
                "reactor lease duration must exceed its poll interval".into(),
            ));
        }
        if self.lease_duration > MAX_JOB_LEASE_DURATION {
            return Err(Error::Validation(
                "reactor lease duration cannot exceed 24 hours".into(),
            ));
        }
        if self.max_error_backoff < self.poll_interval {
            return Err(Error::Validation(
                "reactor maximum error backoff cannot be shorter than its poll interval".into(),
            ));
        }
        if !(1..=1_000).contains(&self.claim_batch_size) {
            return Err(Error::Validation(
                "reactor claim batch size must be in 1..=1000".into(),
            ));
        }
        Ok(())
    }
}

/// Work performed by one database poll.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReactorPollReport {
    pub reservations_expired: u32,
    /// Cursor jobs installed for due, explicitly-owned Runmill streams.
    pub runmill_observation_jobs_produced: u32,
    /// Streams released from an owned `DEAD` observer job that retained no
    /// remote page. Each release records an immutable terminal-failure fact and
    /// moves the stream to `ESCALATED` at its unchanged cursor.
    pub runmill_observation_streams_escalated: u32,
    /// Retention jobs installed for terminal-ready Runmill streams that still
    /// owe an append-only terminal evidence bundle.
    pub runmill_terminal_evidence_jobs_produced: u32,
    pub timers_promoted: u32,
    pub orphaned_jobs_recovered: u32,
    /// Known scoped jobs rejected without invoking a worker-local handler.
    pub route_invalid_jobs_rejected: u32,
    /// Known jobs with unavailable handlers escalated to operational incident.
    pub known_unserviceable_jobs_escalated: u32,
    pub jobs_claimed: u32,
    pub jobs_completed: u32,
    pub jobs_retried: u32,
    pub jobs_transactionally_finalized: u32,
}

/// One PostgreSQL-backed durable reactor instance.
#[derive(Debug, Clone)]
pub struct ReactorRuntime {
    ledger: PgLedger,
    tenant_id: Uuid,
    handlers: HandlerRegistry,
    options: ReactorOptions,
    maintenance_mode: bool,
}

impl ReactorRuntime {
    pub fn new(
        ledger: PgLedger,
        tenant_id: Uuid,
        handlers: HandlerRegistry,
        options: ReactorOptions,
        maintenance_mode: bool,
    ) -> Result<Self> {
        options.validate()?;
        if tenant_id.is_nil() {
            return Err(Error::Validation(
                "reactor tenant ID must be non-nil".into(),
            ));
        }
        Ok(Self {
            ledger,
            tenant_id,
            handlers,
            options,
            maintenance_mode,
        })
    }

    /// Run until shutdown. Database failures use bounded exponential backoff;
    /// an unknown durable job type is fatal and stops this supervisor.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut error_backoff = self.options.poll_interval;
        info!(
            tenant_id = %self.tenant_id,
            lease_owner = %self.options.lease_owner,
            maintenance_mode = self.maintenance_mode,
            "durable reactor started"
        );

        loop {
            if *shutdown.borrow() {
                break;
            }

            match self.poll_once().await {
                Ok(report) => {
                    error_backoff = self.options.poll_interval;
                    if report != ReactorPollReport::default() {
                        debug!(?report, "durable reactor poll completed");
                    }
                    if wait_or_shutdown(self.options.poll_interval, &mut shutdown).await {
                        break;
                    }
                }
                Err(error @ Error::Validation(_)) => {
                    error!(%error, "durable reactor encountered a fail-closed queue violation");
                    return Err(error);
                }
                Err(error) => {
                    warn!(%error, ?error_backoff, "durable reactor poll failed; backing off");
                    if wait_or_shutdown(error_backoff, &mut shutdown).await {
                        break;
                    }
                    error_backoff = doubled_backoff(error_backoff, self.options.max_error_backoff);
                }
            }
        }

        info!(lease_owner = %self.options.lease_owner, "durable reactor stopped");
        Ok(())
    }

    /// Execute one timer/job scan. Primarily useful for deterministic tests and
    /// administrative one-shot driving.
    pub async fn poll_once(&self) -> Result<ReactorPollReport> {
        let expired_reservations = self
            .ledger
            .expire_elapsed_reservation_sets(
                self.tenant_id,
                "asf:reservation-expiry-sweeper",
                self.options.claim_batch_size,
            )
            .await?;
        let reservations_expired = u32::try_from(expired_reservations.len())
            .map_err(|_| Error::Persistence("expired reservation count overflowed".into()))?;

        let known_routes = self.handlers.known_job_type_contract_pairs();
        reject_unknown_or_incompatible_due_job(self.ledger.pool(), self.tenant_id, &known_routes)
            .await?;
        let ready_claims = self.handlers.ready_claim_set();
        let observation_production = produce_due_runmill_observation_jobs(
            self.ledger.pool(),
            self.tenant_id,
            &ready_claims.observe_runmill_run_worker_ids(),
            self.options.claim_batch_size,
        )
        .await?;
        // Retention is produced after observation in the same pass: a stream
        // that only just reached TERMINAL_READY is picked up on the next one,
        // and a stream that reached it earlier owes exactly one bundle.
        let terminal_evidence_production = produce_due_runmill_terminal_evidence_jobs(
            self.ledger.pool(),
            self.tenant_id,
            &ready_claims.retain_runmill_terminal_evidence_worker_ids(),
            self.options.claim_batch_size,
        )
        .await?;

        // A malformed or nonmatching scoped envelope must not become
        // permanently invisible merely because it cannot match any worker
        // route. Claim it without a handler, exhaust it deliberately, and use
        // the ordinary atomic dead-letter path. No daemon-local external ID is
        // ever sent.
        let mut route_invalid_jobs_rejected = 0_u32;
        for _ in 0..self.options.claim_batch_size {
            let Some(job) =
                claim_one_route_invalid_scoped_job(&self.ledger, self.tenant_id, &self.options)
                    .await?
            else {
                break;
            };
            dead_letter_exhausted_claim(
                &self.ledger,
                &job,
                ROUTE_INVALID_SCOPED_JOB_ERROR,
                Utc::now(),
            )
            .await?;
            route_invalid_jobs_rejected = route_invalid_jobs_rejected
                .checked_add(1)
                .ok_or_else(|| Error::Persistence("rejected route count overflowed".into()))?;
        }

        // A process can terminate after its final claim but before its handler
        // records failure. Such a row is no longer eligible for normal claim
        // SQL. Re-fence it without incrementing attempts, then route it through
        // the same atomic owned dead-letter path used for a returned failure.
        let mut orphaned_jobs_recovered = 0_u32;
        for _ in 0..self.options.claim_batch_size {
            let Some(job) = claim_one_orphaned_exhausted_job(
                &self.ledger,
                self.tenant_id,
                &self.options,
                &ready_claims,
            )
            .await?
            else {
                break;
            };
            dead_letter_exhausted_claim(
                &self.ledger,
                &job,
                ORPHANED_FINAL_ATTEMPT_ERROR,
                Utc::now(),
            )
            .await?;
            orphaned_jobs_recovered = orphaned_jobs_recovered
                .checked_add(1)
                .ok_or_else(|| Error::Persistence("recovered job count overflowed".into()))?;
        }

        // Known activity types installed as unavailable must not remain
        // forever unclaimable. Claim well-formed due jobs whose handler is
        // unavailable and escalate them to an owned operational incident,
        // atomically alongside the terminal job record. This preserves
        // accountability for jobs that cannot be processed by any ready handler.
        let mut known_unserviceable_jobs_escalated = 0_u32;
        for _ in 0..self.options.claim_batch_size {
            let Some(job) = claim_one_known_unserviceable_due_job(
                &self.ledger,
                self.tenant_id,
                &self.options,
                &self.handlers,
            )
            .await?
            else {
                break;
            };
            dead_letter_exhausted_claim(
                &self.ledger,
                &job,
                KNOWN_UNSERVICEABLE_DUE_JOB_ERROR,
                Utc::now(),
            )
            .await?;
            known_unserviceable_jobs_escalated = known_unserviceable_jobs_escalated
                .checked_add(1)
                .ok_or_else(|| {
                    Error::Persistence("known-unserviceable job count overflowed".into())
                })?;
        }

        let scoped_timer_reject_job_types = self.handlers.scoped_timer_reject_job_types();
        let timers_promoted = promote_due_timers(
            self.ledger.pool(),
            self.tenant_id,
            &known_routes,
            ready_claims.unscoped(),
            &scoped_timer_reject_job_types,
            self.options.claim_batch_size,
        )
        .await?;
        let jobs =
            claim_ready_jobs(&self.ledger, self.tenant_id, &self.options, &ready_claims).await?;
        let jobs_claimed = u32::try_from(jobs.len())
            .map_err(|_| Error::Persistence("claimed job count overflowed".into()))?;

        let mut tasks = JoinSet::new();
        for job in jobs {
            let handler = self.handlers.handler(&job.job_type).ok_or_else(|| {
                Error::Validation(format!(
                    "claimed unknown durable job type {:?}",
                    job.job_type
                ))
            })?;
            if !handler.claim_scope().matches(&job) {
                return Err(Error::Validation(format!(
                    "claimed durable job {} does not match handler scope for {:?}",
                    job.id, job.job_type
                )));
            }
            if handler.activity_contract_id() != job.activity_contract_id {
                return Err(Error::Validation(format!(
                    "claimed durable job {} declares activity contract id {:?}, but the installed {:?} handler serves {:?}",
                    job.id,
                    job.activity_contract_id,
                    job.job_type,
                    handler.activity_contract_id()
                )));
            }
            let ledger = self.ledger.clone();
            let options = self.options.clone();
            let controls = ActivityControls::new(self.maintenance_mode);
            tasks.spawn(async move {
                execute_claimed_job(ledger, handler, options, controls, job).await
            });
        }

        let mut report = ReactorPollReport {
            reservations_expired,
            runmill_observation_jobs_produced: observation_production.jobs_enqueued,
            runmill_observation_streams_escalated: observation_production.dead_jobs_escalated,
            runmill_terminal_evidence_jobs_produced: terminal_evidence_production.jobs_enqueued,
            timers_promoted,
            orphaned_jobs_recovered,
            route_invalid_jobs_rejected,
            known_unserviceable_jobs_escalated,
            jobs_claimed,
            jobs_transactionally_finalized: orphaned_jobs_recovered
                .checked_add(route_invalid_jobs_rejected)
                .and_then(|sum| sum.checked_add(known_unserviceable_jobs_escalated))
                .ok_or_else(|| {
                    Error::Persistence("transactionally finalized job count overflowed".into())
                })?,
            ..ReactorPollReport::default()
        };
        while let Some(joined) = tasks.join_next().await {
            let disposition = joined.map_err(|error| {
                Error::Persistence(format!("reactor activity panicked: {error}"))
            })??;
            match disposition {
                ExecutionDisposition::Completed => report.jobs_completed += 1,
                ExecutionDisposition::Retried => report.jobs_retried += 1,
                ExecutionDisposition::TransactionallyFinalized => {
                    report.jobs_transactionally_finalized += 1;
                }
            }
        }
        Ok(report)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionDisposition {
    Completed,
    Retried,
    TransactionallyFinalized,
}

async fn execute_claimed_job(
    ledger: PgLedger,
    handler: Arc<dyn super::JobHandler>,
    options: ReactorOptions,
    controls: ActivityControls,
    job: ClaimedWorkflowJob,
) -> Result<ExecutionDisposition> {
    if handler.readiness() != HandlerReadiness::Ready {
        return Err(Error::Validation(format!(
            "unavailable handler for {} was allowed to claim job {}",
            job.job_type, job.id
        )));
    }

    let heartbeat_period = cmp::max(options.lease_duration / 3, Duration::from_millis(1));
    let start = tokio::time::Instant::now() + heartbeat_period;
    let mut heartbeat = tokio::time::interval_at(start, heartbeat_period);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let execution = async {
        let outcome = handler.execute(&job, controls).await;
        finalize_claimed_job(&ledger, &options, &job, outcome).await
    };
    tokio::pin!(execution);

    // Keep renewal as a sibling future of the handler. A transactionally
    // finalizing handler can hold the workflow_jobs row while it appends audit,
    // outbox, and accountability state. If renewal were awaited *inside* a
    // selected tick branch, it could wait on that row while the handler was no
    // longer being polled to commit: a self-deadlock. The sibling remains
    // independently pollable and is dropped as soon as execution completes.
    let heartbeat_settlement = async {
        loop {
            heartbeat.tick().await;
            if let Err(error) = ledger
                .renew_job_lease(
                    job.tenant_id,
                    job.id,
                    &job.lease_owner,
                    job.fence_token,
                    options.lease_duration,
                )
                .await
            {
                if claim_was_settled_by_same_fence(&ledger, &job).await? {
                    break Ok::<(), Error>(());
                }
                break Err(error);
            }
        }
    };
    tokio::pin!(heartbeat_settlement);

    tokio::select! {
        // If finalization commits while a renewal blocked on its job-row lock,
        // both futures can become ready together. Prefer the durable outcome.
        biased;
        outcome = &mut execution => outcome,
        settlement = &mut heartbeat_settlement => {
            settlement?;
            execution.await
        },
    }
}

async fn finalize_claimed_job(
    ledger: &PgLedger,
    options: &ReactorOptions,
    job: &ClaimedWorkflowJob,
    outcome: Result<ActivityOutcome>,
) -> Result<ExecutionDisposition> {
    match outcome {
        Ok(ActivityOutcome::Complete { result }) => {
            ledger
                .complete_job(
                    job.tenant_id,
                    job.id,
                    &job.lease_owner,
                    job.fence_token,
                    result.as_ref(),
                )
                .await?;
            Ok(ExecutionDisposition::Completed)
        }
        Ok(ActivityOutcome::Retry { error, retry_at }) => {
            record_claim_failure(ledger, job, &error, retry_at).await
        }
        Ok(ActivityOutcome::TransactionCommitted) => {
            verify_handler_finalized(ledger, job, "COMPLETED").await?;
            Ok(ExecutionDisposition::TransactionallyFinalized)
        }
        Ok(ActivityOutcome::DeadLetterCommitted) => {
            verify_handler_finalized(ledger, job, "DEAD").await?;
            Ok(ExecutionDisposition::TransactionallyFinalized)
        }
        Err(error) => {
            let retry_at = Utc::now()
                + chrono::Duration::from_std(job_retry_delay(
                    options.poll_interval,
                    options.max_error_backoff,
                    job.attempt_count,
                ))
                .map_err(|duration_error| {
                    Error::Validation(format!("invalid reactor retry delay: {duration_error}"))
                })?;
            record_claim_failure(ledger, job, &error.to_string(), retry_at).await
        }
    }
}

async fn record_claim_failure(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    error: &str,
    retry_at: DateTime<Utc>,
) -> Result<ExecutionDisposition> {
    if job.attempt_count < job.max_attempts {
        retry_claim(ledger, job, error, retry_at).await?;
        return Ok(ExecutionDisposition::Retried);
    }

    dead_letter_exhausted_claim(ledger, job, error, retry_at).await?;
    Ok(ExecutionDisposition::TransactionallyFinalized)
}

/// Install the owner, deadline, retry policy, audit event, and outbox message
/// in the same transaction as the final job failure. Delivery activities use
/// their work-item escalation and accountability anchor; tenant activities use
/// a separate operational incident and never invent a synthetic work item.
async fn dead_letter_exhausted_claim(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    error: &str,
    retry_at: DateTime<Utc>,
) -> Result<()> {
    match (job.workflow_instance_id, job.work_item_id, job.attempt_id) {
        (Some(_), Some(_), _) => dead_letter_work_item_claim(ledger, job, error, retry_at).await,
        (None, None, None) => dead_letter_operational_claim(ledger, job, error, retry_at).await,
        _ => Err(Error::Validation(format!(
            "exhausted workflow job {} has an incomplete workflow/work-item binding",
            job.id
        ))),
    }
}

async fn dead_letter_work_item_claim(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    error: &str,
    retry_at: DateTime<Utc>,
) -> Result<()> {
    let workflow_instance_id = job.workflow_instance_id.ok_or_else(|| {
        Error::Validation(format!(
            "exhausted workflow job {} has no workflow binding for an owned escalation",
            job.id
        ))
    })?;
    let work_item_id = job.work_item_id.ok_or_else(|| {
        Error::Validation(format!(
            "exhausted workflow job {} has no work-item binding for an owned escalation",
            job.id
        ))
    })?;

    let mut transaction = ledger.pool().begin().await.map_err(|database_error| {
        Error::Persistence(format!(
            "begin exhausted workflow-job escalation: {database_error}"
        ))
    })?;
    // Read aggregate compare-and-swap versions without taking their locks.
    // fail_workflow_step acquires the job row first and then these aggregates,
    // matching normal step-commit lock order; a concurrent version change is
    // rejected rather than creating a work->job lock inversion.
    let row = sqlx::query(
        r"
        SELECT
            work.aggregate_version AS work_item_version,
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence_token,
            COALESCE(anchor.generation, 0) AS anchor_generation,
            work.policy_digest
        FROM work_items AS work
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = work.tenant_id
         AND workflow.id = $3
         AND workflow.work_item_id = work.id
        LEFT JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
        WHERE work.tenant_id = $1
          AND work.id = $2
        ",
    )
    .bind(job.tenant_id)
    .bind(work_item_id)
    .bind(workflow_instance_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "load exhausted workflow-job aggregate fences: {database_error}"
        ))
    })?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "workflow job {} no longer matches its workflow/work-item binding",
            job.id
        ))
    })?;

    let work_item_version: i64 = required(&row, "work_item_version", "work-item version")?;
    let workflow_version: i64 = required(&row, "workflow_version", "workflow version")?;
    let workflow_fence_token: i64 = required(&row, "workflow_fence_token", "workflow fence")?;
    let anchor_generation: i64 = required(&row, "anchor_generation", "anchor generation")?;
    let policy_digest: Option<String> = optional(&row, "policy_digest", "policy digest")?;

    let opened_at = Utc::now();
    let deadline = opened_at
        .checked_add_signed(TimeDelta::hours(4))
        .ok_or_else(|| Error::Validation("dead-letter escalation deadline overflowed".into()))?;
    let escalation_id = Uuid::now_v7();
    let audit_id = Uuid::now_v7();
    let outbox_id = Uuid::now_v7();
    let error_digest = sha256_digest(error.as_bytes());
    let reason = format!(
        "durable activity {} exhausted all {} configured attempts",
        job.job_type, job.max_attempts
    );
    let required_action = "inspect the activity failure evidence, reconcile any remote effect, then explicitly retry, replace, or cancel the work item";
    let correlation_id = format!("workflow-job-exhausted:{}", job.id);
    let failure = WorkflowStepFailure {
        fence: WorkflowStepFence {
            tenant_id: job.tenant_id,
            job_id: job.id,
            workflow_instance_id,
            work_item_id,
            lease_owner: job.lease_owner.clone(),
            job_fence_token: job.fence_token,
            expected_work_item_version: work_item_version,
            expected_workflow_version: workflow_version,
            expected_workflow_fence_token: workflow_fence_token,
            expected_anchor_generation: anchor_generation,
        },
        error_summary: error.into(),
        retry_at,
        dead_letter: DeadLetterEscalation {
            id: escalation_id,
            run_id: None,
            category: "WORKFLOW_JOB_EXHAUSTED".into(),
            severity: "HIGH".into(),
            reason: reason.clone(),
            owner_type: "ON_CALL".into(),
            owner_id: "platform-operations".into(),
            required_action: required_action.into(),
            evidence_references: json!([format!("workflow-job:{}", job.id), error_digest,]),
            deadline,
            escalation_path: json!([
                {"owner_type": "ON_CALL", "owner_id": "platform-operations"},
                {"owner_type": "TEAM", "owner_id": "platform-engineering"},
            ]),
            retry_policy: json!({
                "automatic": false,
                "max_additional_attempts": 0,
                "backoff_seconds": 0,
                "prerequisites": ["remote effects reconciled", "operator decision recorded"],
            }),
            prerequisites: json!([
                "inspect failure evidence",
                "reconcile ambiguous remote effects",
            ]),
            authority_or_effect_active: true,
            idempotency_key: correlation_id.clone(),
            opened_at,
            audit_event: StepAuditEvent {
                id: audit_id,
                attempt_id: job.attempt_id,
                actor_type: "SERVICE".into(),
                actor_id: job.lease_owner.clone(),
                action: "WORKFLOW_JOB_EXHAUSTED".into(),
                subject_type: "WORKFLOW_JOB".into(),
                subject_id: job.id.to_string(),
                correlation_id: correlation_id.clone(),
                trace_id: None,
                policy_digest,
                before_digest: None,
                after_digest: None,
                details: json!({
                    "job_type": job.job_type,
                    "attempt_count": job.attempt_count,
                    "max_attempts": job.max_attempts,
                    "error_digest": error_digest,
                    "escalation_id": escalation_id,
                }),
                occurred_at: opened_at,
            },
            outbox_message: StepOutboxMessage {
                id: outbox_id,
                topic: "attention".into(),
                message_key: work_item_id.to_string(),
                event_type: "workflow_job.exhausted".into(),
                payload: json!({
                    "work_item_id": work_item_id,
                    "workflow_job_id": job.id,
                    "escalation_id": escalation_id,
                    "owner_type": "ON_CALL",
                    "owner_id": "platform-operations",
                    "required_action": required_action,
                    "deadline": deadline,
                    "evidence_references": [
                        format!("workflow-job:{}", job.id),
                        error_digest,
                    ],
                }),
                headers: json!({"schema": "asf.attention-event/v1"}),
                idempotency_key: format!("{correlation_id}:outbox"),
                available_at: opened_at,
            },
        },
    };

    let outcome = fail_workflow_step(&mut transaction, &failure).await?;
    if outcome.disposition != WorkflowStepFailureDisposition::Escalated {
        return Err(Error::Persistence(format!(
            "exhausted workflow job {} was not escalated",
            job.id
        )));
    }
    transaction.commit().await.map_err(|database_error| {
        Error::Persistence(format!(
            "commit exhausted workflow-job escalation: {database_error}"
        ))
    })
}

async fn dead_letter_operational_claim(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    error: &str,
    retry_at: DateTime<Utc>,
) -> Result<()> {
    let mut transaction = ledger.pool().begin().await.map_err(|database_error| {
        Error::Persistence(format!(
            "begin exhausted operational-job incident: {database_error}"
        ))
    })?;
    let owned = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM workflow_jobs AS job
        WHERE job.tenant_id = $1
          AND job.id = $2
          AND job.status = 'RUNNING'
          AND job.workflow_instance_id IS NULL
          AND job.work_item_id IS NULL
          AND job.attempt_id IS NULL
          AND job.attempt_count >= job.max_attempts
          AND job.lease_owner = $3
          AND job.fence_token = $4
          AND job.lease_expires_at > clock_timestamp()
        FOR UPDATE OF job
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "lock exhausted operational workflow job: {database_error}"
        ))
    })?
    .unwrap_or(false);
    if !owned {
        return Err(Error::Conflict(format!(
            "workflow job {} claim is stale, expired, or no longer exhausted",
            job.id
        )));
    }

    let opened_at = Utc::now();
    let deadline = opened_at
        .checked_add_signed(TimeDelta::hours(4))
        .ok_or_else(|| Error::Validation("operational incident deadline overflowed".into()))?;
    let incident_id = Uuid::now_v7();
    let audit_id = Uuid::now_v7();
    let outbox_id = Uuid::now_v7();
    let error_summary = summarize_job_error(error);
    let error_digest = sha256_digest(error.as_bytes());
    let reason = format!(
        "tenant activity {} exhausted all {} configured attempts",
        job.job_type, job.max_attempts
    );
    let required_action = "inspect the tenant activity failure evidence, reconcile any remote effect, then explicitly re-enqueue, replace, or disable the activity";
    let correlation_id = format!("operational-job-exhausted:{}", job.id);
    let evidence_references = json!([format!("workflow-job:{}", job.id), error_digest,]);
    let retry_policy = json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 0,
        "prerequisites": ["remote effects reconciled", "operator decision recorded"],
    });

    sqlx::query(
        r"
        INSERT INTO operational_incidents (
            id, tenant_id, workflow_job_id, category, severity, reason,
            owner_type, owner_id, required_action, evidence_references,
            deadline, escalation_path, retry_policy, prerequisites,
            authority_or_effect_active, idempotency_key, opened_at
        ) VALUES (
            $1, $2, $3, 'WORKFLOW_JOB_EXHAUSTED', 'HIGH', $4,
            'ON_CALL', 'platform-operations', $5, $6, $7, $8, $9, $10,
            true, $11, $12
        )
        ",
    )
    .bind(incident_id)
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(&reason)
    .bind(required_action)
    .bind(&evidence_references)
    .bind(deadline)
    .bind(json!([
        {"owner_type": "ON_CALL", "owner_id": "platform-operations"},
        {"owner_type": "TEAM", "owner_id": "platform-engineering"},
    ]))
    .bind(&retry_policy)
    .bind(json!([
        "inspect failure evidence",
        "reconcile ambiguous remote effects",
    ]))
    .bind(&correlation_id)
    .bind(opened_at)
    .execute(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "insert exhausted operational-job incident: {database_error}"
        ))
    })?;

    // The live owner/fence was validated while locking this job above. That
    // row lock prevents reclamation, so the atomic incident/audit transaction
    // may finish even if wall clock crosses the original lease deadline.
    let changed = sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'DEAD',
            available_at = GREATEST($7, clock_timestamp()),
            last_failure_by = $3,
            last_failure_fence_token = $4,
            last_failure_retry_at = $7,
            last_error = $5,
            dead_letter_operational_incident_id = $6,
            dead_lettered_at = $8,
            lease_owner = NULL,
            lease_expires_at = NULL,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'RUNNING'
          AND workflow_instance_id IS NULL
          AND work_item_id IS NULL
          AND attempt_id IS NULL
          AND attempt_count >= max_attempts
          AND lease_owner = $3
          AND fence_token = $4
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .bind(&error_summary)
    .bind(incident_id)
    .bind(retry_at)
    .bind(opened_at)
    .execute(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "dead-letter exhausted operational workflow job: {database_error}"
        ))
    })?
    .rows_affected();
    if changed != 1 {
        return Err(Error::Conflict(format!(
            "workflow job {} claim became stale while opening its operational incident",
            job.id
        )));
    }

    append_operational_failure_audit(
        &mut transaction,
        job,
        audit_id,
        incident_id,
        &correlation_id,
        &error_digest,
        opened_at,
    )
    .await?;
    sqlx::query(
        r"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload, headers,
            idempotency_key, available_at
        ) VALUES ($1, $2, 'attention', $3, 'operational_job.exhausted', $4, $5, $6, $7)
        ",
    )
    .bind(outbox_id)
    .bind(job.tenant_id)
    .bind(job.id.to_string())
    .bind(json!({
        "workflow_job_id": job.id,
        "operational_incident_id": incident_id,
        "job_type": job.job_type,
        "owner_type": "ON_CALL",
        "owner_id": "platform-operations",
        "required_action": required_action,
        "deadline": deadline,
        "evidence_references": evidence_references,
    }))
    .bind(json!({"schema": "asf.operational-attention-event/v1"}))
    .bind(format!("{correlation_id}:outbox"))
    .bind(opened_at)
    .execute(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "insert exhausted operational-job outbox message: {database_error}"
        ))
    })?;

    let incident_is_complete = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM workflow_jobs AS job
            JOIN operational_incidents AS incident
              ON incident.tenant_id = job.tenant_id
             AND incident.workflow_job_id = job.id
             AND incident.id = job.dead_letter_operational_incident_id
            WHERE job.tenant_id = $1
              AND job.id = $2
              AND job.status = 'DEAD'
              AND incident.id = $3
              AND incident.status IN ('OPEN', 'ACKNOWLEDGED')
              AND incident.owner_id = 'platform-operations'
              AND incident.required_action = $4
              AND incident.deadline > job.dead_lettered_at
              AND jsonb_array_length(incident.evidence_references) > 0
        )
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(incident_id)
    .bind(required_action)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|database_error| {
        Error::Persistence(format!(
            "verify exhausted operational-job incident: {database_error}"
        ))
    })?;
    if !incident_is_complete {
        return Err(Error::Conflict(format!(
            "dead operational workflow job {} has no matching owned incident",
            job.id
        )));
    }

    transaction.commit().await.map_err(|database_error| {
        Error::Persistence(format!(
            "commit exhausted operational-job incident: {database_error}"
        ))
    })
}

async fn append_operational_failure_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &ClaimedWorkflowJob,
    audit_id: Uuid,
    incident_id: Uuid,
    correlation_id: &str,
    error_digest: &str,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(job.tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| Error::Persistence(format!("lock tenant audit chain: {error}")))?;
    let previous_event_hash = sqlx::query_scalar::<_, String>(
        r"
        SELECT event.event_hash
        FROM audit_events AS event
        WHERE event.tenant_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS successor
              WHERE successor.tenant_id = event.tenant_id
                AND successor.previous_event_hash = event.event_hash
          )
        ",
    )
    .bind(job.tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("load tenant audit-chain head: {error}")))?;
    let event = HashedAuditEvent::create(AuditEventContent {
        id: EventId::from_uuid(audit_id),
        tenant_id: TenantId::from_uuid(job.tenant_id),
        work_item_id: None,
        attempt_id: None,
        actor_type: "SERVICE".into(),
        actor_id: job.lease_owner.clone(),
        action: "OPERATIONAL_WORKFLOW_JOB_EXHAUSTED".into(),
        subject_type: "WORKFLOW_JOB".into(),
        subject_id: job.id.to_string(),
        correlation_id: correlation_id.into(),
        trace_id: None,
        policy_digest: None,
        before_digest: None,
        after_digest: None,
        previous_event_hash,
        details: json!({
            "job_type": job.job_type,
            "attempt_count": job.attempt_count,
            "max_attempts": job.max_attempts,
            "error_digest": error_digest,
            "operational_incident_id": incident_id,
        }),
        occurred_at,
    })?;
    event.verify()?;
    sqlx::query(
        r"
        INSERT INTO audit_events (
            id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
            action, subject_type, subject_id, correlation_id, trace_id,
            policy_digest, before_digest, after_digest, previous_event_hash,
            event_hash, details, occurred_at
        ) VALUES (
            $1, $2, NULL, NULL, $3, $4, $5, $6, $7, $8, NULL,
            NULL, NULL, NULL, $9, $10, $11, $12
        )
        ",
    )
    .bind(event.content.id.as_uuid())
    .bind(job.tenant_id)
    .bind(&event.content.actor_type)
    .bind(&event.content.actor_id)
    .bind(&event.content.action)
    .bind(&event.content.subject_type)
    .bind(&event.content.subject_id)
    .bind(&event.content.correlation_id)
    .bind(&event.content.previous_event_hash)
    .bind(&event.event_hash)
    .bind(&event.content.details)
    .bind(event.content.occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("append operational failure audit: {error}")))?;
    Ok(())
}

fn summarize_job_error(error: &str) -> String {
    error.chars().take(8_192).collect()
}

async fn retry_claim(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    error: &str,
    retry_at: DateTime<Utc>,
) -> Result<()> {
    if job.attempt_count >= job.max_attempts {
        return Err(Error::Validation(format!(
            "handler for exhausted workflow job {} must atomically dead-letter it with an owned escalation",
            job.id
        )));
    }
    let outcome = ledger
        .fail_job(
            job.tenant_id,
            job.id,
            &job.lease_owner,
            job.fence_token,
            error,
            retry_at,
        )
        .await?;
    if outcome.disposition != FailureDisposition::RetryScheduled {
        return Err(Error::Persistence(format!(
            "non-exhausted workflow job {} returned an unexpected failure disposition",
            job.id
        )));
    }
    Ok(())
}

async fn verify_handler_finalized(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
    expected_status: &str,
) -> Result<()> {
    let status = sqlx::query_scalar::<_, String>(
        r"
        SELECT status
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .fetch_optional(ledger.pool())
    .await
    .map_err(|error| Error::Persistence(format!("verify handler job finalization: {error}")))?
    .ok_or_else(|| Error::NotFound(format!("workflow job {}", job.id)))?;
    if status == expected_status {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "handler reported {expected_status} for workflow job {}, but durable status is {status}",
            job.id
        )))
    }
}

/// A renewal blocked behind the handler's own final transaction can observe a
/// non-running row after that transaction commits. Treat that as settlement,
/// not lease loss, only when the durable completion/failure metadata carries
/// this exact owner and fence.
async fn claim_was_settled_by_same_fence(
    ledger: &PgLedger,
    job: &ClaimedWorkflowJob,
) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT CASE
            WHEN status = 'COMPLETED'
                THEN COALESCE(completed_by = $3 AND completion_fence_token = $4, false)
            WHEN status IN ('RETRY', 'DEAD')
                THEN COALESCE(last_failure_by = $3 AND last_failure_fence_token = $4, false)
            ELSE false
        END
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .bind(&job.lease_owner)
    .bind(job.fence_token)
    .fetch_optional(ledger.pool())
    .await
    .map_err(|error| Error::Persistence(format!("inspect settled workflow claim: {error}")))
    .map(|settled| settled.unwrap_or(false))
}

async fn claim_ready_jobs(
    ledger: &PgLedger,
    tenant_id: Uuid,
    options: &ReactorOptions,
    ready_claims: &ReadyClaimSet,
) -> Result<Vec<ClaimedWorkflowJob>> {
    if ready_claims.is_empty() {
        return Ok(Vec::new());
    }
    let lease_milliseconds = i64::try_from(options.lease_duration.as_millis())
        .map_err(|_| Error::Validation("reactor workflow lease duration is too large".into()))?;
    let (unscoped_job_types, unscoped_contract_ids) = unzip_routes(ready_claims.unscoped());
    let (reconcile_worker_ids, reconcile_contract_ids) =
        unzip_routes(ready_claims.reconcile_worker());
    let (cancellation_worker_ids, cancellation_contract_ids) =
        unzip_routes(ready_claims.cancellation_worker());
    let (observation_worker_ids, observation_contract_ids) =
        unzip_routes(ready_claims.observe_runmill_run_worker());
    let (retention_worker_ids, retention_contract_ids) =
        unzip_routes(ready_claims.retain_runmill_terminal_evidence_worker());
    let rows = sqlx::query(CLAIM_READY_JOBS_SQL)
        .bind(tenant_id)
        .bind(i64::from(options.claim_batch_size))
        .bind(&options.lease_owner)
        .bind(lease_milliseconds)
        .bind(unscoped_job_types)
        .bind(unscoped_contract_ids)
        .bind(reconcile_worker_ids)
        .bind(reconcile_contract_ids)
        .bind(cancellation_worker_ids)
        .bind(cancellation_contract_ids)
        .bind(observation_worker_ids)
        .bind(observation_contract_ids)
        .bind(retention_worker_ids)
        .bind(retention_contract_ids)
        .fetch_all(ledger.pool())
        .await
        .map_err(|error| Error::Persistence(format!("claim reactor workflow jobs: {error}")))?;
    rows.iter().map(claimed_job_from_row).collect()
}

/// Split a `(route_key, activity_contract_id)` pair list into the two
/// parallel arrays a `PostgreSQL` `unnest($a::text[], $b::text[])` bind
/// requires for safe, index-free tuple matching.
fn unzip_routes(routes: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    routes
        .iter()
        .map(|(route_key, activity_contract_id)| (route_key.clone(), activity_contract_id.clone()))
        .unzip()
}

async fn claim_one_route_invalid_scoped_job(
    ledger: &PgLedger,
    tenant_id: Uuid,
    options: &ReactorOptions,
) -> Result<Option<ClaimedWorkflowJob>> {
    let lease_milliseconds = i64::try_from(options.lease_duration.as_millis())
        .map_err(|_| Error::Validation("reactor workflow lease duration is too large".into()))?;
    let row = sqlx::query(CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL)
        .bind(tenant_id)
        .bind(&options.lease_owner)
        .bind(lease_milliseconds)
        .bind(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .fetch_optional(ledger.pool())
        .await
        .map_err(|error| {
            Error::Persistence(format!("claim route-invalid scoped workflow job: {error}"))
        })?;
    row.as_ref().map(claimed_job_from_row).transpose()
}

/// Fail closed before any producer, route-invalid scan, orphan recovery,
/// timer work, or normal claim runs: a due job whose exact `(job_type,
/// activity_contract_id)` pair is not one this process installed a handler
/// for — whether the `job_type` is wholly unrecognized or recognized but bound
/// to a different, incompatible contract identity — stops the reactor
/// untouched rather than silently mis-claiming or dead-lettering it.
async fn reject_unknown_or_incompatible_due_job(
    pool: &PgPool,
    tenant_id: Uuid,
    known_routes: &[(String, String)],
) -> Result<()> {
    let (known_job_types, known_contract_ids) = unzip_routes(known_routes);
    let unknown = sqlx::query_as::<_, (String, String)>(UNKNOWN_OR_INCOMPATIBLE_DUE_JOB_SQL)
        .bind(tenant_id)
        .bind(known_job_types)
        .bind(known_contract_ids)
        .fetch_optional(pool)
        .await
        .map_err(|error| Error::Persistence(format!("inspect unknown workflow jobs: {error}")))?;
    if let Some((job_type, activity_contract_id)) = unknown {
        if known_routes
            .iter()
            .any(|(known_job_type, _)| known_job_type == &job_type)
        {
            Err(Error::Validation(format!(
                "due durable workflow job type {job_type:?} has incompatible activity contract id {activity_contract_id:?}; no work was claimed"
            )))
        } else {
            Err(Error::Validation(format!(
                "unsupported durable workflow job type {job_type:?}; no work was claimed"
            )))
        }
    } else {
        Ok(())
    }
}

async fn claim_one_orphaned_exhausted_job(
    ledger: &PgLedger,
    tenant_id: Uuid,
    options: &ReactorOptions,
    ready_claims: &ReadyClaimSet,
) -> Result<Option<ClaimedWorkflowJob>> {
    let lease_milliseconds = i64::try_from(options.lease_duration.as_millis())
        .map_err(|_| Error::Validation("reactor workflow lease duration is too large".into()))?;
    let (unscoped_job_types, unscoped_contract_ids) = unzip_routes(ready_claims.unscoped());
    let (reconcile_worker_ids, reconcile_contract_ids) =
        unzip_routes(ready_claims.reconcile_worker());
    let (cancellation_worker_ids, cancellation_contract_ids) =
        unzip_routes(ready_claims.cancellation_worker());
    let (observation_worker_ids, observation_contract_ids) =
        unzip_routes(ready_claims.observe_runmill_run_worker());
    let (retention_worker_ids, retention_contract_ids) =
        unzip_routes(ready_claims.retain_runmill_terminal_evidence_worker());
    let rows = sqlx::query(CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL)
        .bind(tenant_id)
        .bind(&options.lease_owner)
        .bind(lease_milliseconds)
        .bind(unscoped_job_types)
        .bind(unscoped_contract_ids)
        .bind(reconcile_worker_ids)
        .bind(reconcile_contract_ids)
        .bind(cancellation_worker_ids)
        .bind(cancellation_contract_ids)
        .bind(observation_worker_ids)
        .bind(observation_contract_ids)
        .bind(retention_worker_ids)
        .bind(retention_contract_ids)
        .fetch_optional(ledger.pool())
        .await
        .map_err(|error| {
            Error::Persistence(format!("claim orphaned exhausted workflow job: {error}"))
        })?;
    rows.as_ref().map(claimed_job_from_row).transpose()
}

async fn claim_one_known_unserviceable_due_job(
    ledger: &PgLedger,
    tenant_id: Uuid,
    options: &ReactorOptions,
    handlers: &HandlerRegistry,
) -> Result<Option<ClaimedWorkflowJob>> {
    let lease_milliseconds = i64::try_from(options.lease_duration.as_millis())
        .map_err(|_| Error::Validation("reactor workflow lease duration is too large".into()))?;
    let known_routes = handlers.known_job_type_contract_pairs();
    let ready_claims = handlers.ready_claim_set();
    let (known_job_types, known_contract_ids) = unzip_routes(&known_routes);
    let (unscoped_job_types, unscoped_contract_ids) = unzip_routes(ready_claims.unscoped());
    let (reconcile_worker_ids, reconcile_contract_ids) =
        unzip_routes(ready_claims.reconcile_worker());
    let (cancellation_worker_ids, cancellation_contract_ids) =
        unzip_routes(ready_claims.cancellation_worker());
    let (observation_worker_ids, observation_contract_ids) =
        unzip_routes(ready_claims.observe_runmill_run_worker());
    let (retention_worker_ids, retention_contract_ids) =
        unzip_routes(ready_claims.retain_runmill_terminal_evidence_worker());
    let row = sqlx::query(CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL)
        .bind(tenant_id)
        .bind(&options.lease_owner)
        .bind(lease_milliseconds)
        .bind(known_job_types)
        .bind(known_contract_ids)
        .bind(unscoped_job_types)
        .bind(unscoped_contract_ids)
        .bind(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        .bind(reconcile_worker_ids)
        .bind(reconcile_contract_ids)
        .bind(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID)
        .bind(cancellation_worker_ids)
        .bind(cancellation_contract_ids)
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .bind(observation_worker_ids)
        .bind(observation_contract_ids)
        .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID)
        .bind(retention_worker_ids)
        .bind(retention_contract_ids)
        .fetch_optional(ledger.pool())
        .await
        .map_err(|error| {
            Error::Persistence(format!(
                "claim known-unserviceable due workflow job: {error}"
            ))
        })?;
    row.as_ref().map(claimed_job_from_row).transpose()
}

fn claimed_job_from_row(row: &PgRow) -> Result<ClaimedWorkflowJob> {
    Ok(ClaimedWorkflowJob {
        id: required(row, "id", "claimed workflow job ID")?,
        tenant_id: required(row, "tenant_id", "claimed workflow job tenant")?,
        workflow_instance_id: optional(row, "workflow_instance_id", "claimed workflow")?,
        work_item_id: optional(row, "work_item_id", "claimed work item")?,
        attempt_id: optional(row, "attempt_id", "claimed attempt")?,
        job_type: required(row, "job_type", "claimed workflow job type")?,
        activity_contract_id: required(
            row,
            "activity_contract_id",
            "claimed workflow job activity contract id",
        )?,
        payload: required(row, "payload", "claimed workflow job payload")?,
        idempotency_key: required(row, "idempotency_key", "claimed job idempotency key")?,
        priority: required(row, "priority", "claimed workflow job priority")?,
        attempt_count: required(row, "attempt_count", "claimed workflow job attempt count")?,
        max_attempts: required(row, "max_attempts", "claimed workflow job max attempts")?,
        fence_token: required(row, "fence_token", "claimed workflow job fence")?,
        lease_owner: required(row, "lease_owner", "claimed workflow job lease owner")?,
        lease_expires_at: required(row, "lease_expires_at", "claimed workflow job lease expiry")?,
        created_at: required(row, "created_at", "claimed workflow job creation time")?,
    })
}

fn required<T>(row: &PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))
}

fn optional<T>(row: &PgRow, column: &str, context: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))
}

fn job_retry_delay(base: Duration, maximum: Duration, attempt_count: i32) -> Duration {
    let exponent = u32::try_from(attempt_count.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(20);
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    base.checked_mul(multiplier).unwrap_or(maximum).min(maximum)
}

fn doubled_backoff(current: Duration, maximum: Duration) -> Duration {
    current.checked_mul(2).unwrap_or(maximum).min(maximum)
}

async fn wait_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::{
        domain::WorkerId,
        runtime::{ActivityOutcome, JobHandler},
    };

    #[derive(Debug)]
    struct CompleteTestHandler;

    #[async_trait]
    impl JobHandler for CompleteTestHandler {
        fn job_type(&self) -> &'static str {
            "RUNTIME_TEST_COMPLETE"
        }

        fn activity_contract_id(&self) -> &'static str {
            "test.activity/runtime-test-complete/v1"
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete {
                result: Some(json!({"handled": true})),
            })
        }
    }

    fn options() -> ReactorOptions {
        ReactorOptions {
            lease_owner: format!("test-reactor-{}", Uuid::now_v7()),
            poll_interval: Duration::from_millis(10),
            lease_duration: Duration::from_secs(5),
            max_error_backoff: Duration::from_secs(1),
            claim_batch_size: 4,
        }
    }

    #[test]
    fn claim_sql_requires_exact_route_and_contract_pairs() {
        assert!(CLAIM_READY_JOBS_SQL.contains("job.tenant_id = $1"));
        for predicate in [
            "FROM unnest($5::text[], $6::text[]) AS unscoped_route(job_type, activity_contract_id)",
            "unscoped_route.job_type = job.job_type",
            "unscoped_route.activity_contract_id = job.activity_contract_id",
            "FROM unnest($7::text[], $8::text[]) AS reconcile_route(worker_id, activity_contract_id)",
            "reconcile_route.worker_id = job.payload ->> 'worker_id'",
            "reconcile_route.activity_contract_id = job.activity_contract_id",
            "FROM unnest($9::text[], $10::text[]) AS cancellation_route(worker_id, activity_contract_id)",
            "cancellation_route.worker_id = job.payload ->> 'worker_id'",
            "cancellation_route.activity_contract_id = job.activity_contract_id",
            "FROM unnest($11::text[], $12::text[]) AS observation_route(worker_id, activity_contract_id)",
            "observation_route.worker_id = job.payload ->> 'worker_id'",
            "observation_route.activity_contract_id = job.activity_contract_id",
        ] {
            assert!(
                CLAIM_READY_JOBS_SQL.contains(predicate),
                "ready claim must retain {predicate}"
            );
        }
        for predicate in [
            "FROM unnest($4::text[], $5::text[]) AS unscoped_route(job_type, activity_contract_id)",
            "unscoped_route.job_type = job.job_type",
            "unscoped_route.activity_contract_id = job.activity_contract_id",
            "FROM unnest($6::text[], $7::text[]) AS reconcile_route(worker_id, activity_contract_id)",
            "FROM unnest($8::text[], $9::text[]) AS cancellation_route(worker_id, activity_contract_id)",
            "FROM unnest($10::text[], $11::text[]) AS observation_route(worker_id, activity_contract_id)",
        ] {
            assert!(
                CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains(predicate),
                "orphaned exhausted claim must retain {predicate}"
            );
        }
        for predicate in [
            "(job.job_type = 'RECONCILE_WORKER' AND job.activity_contract_id = $4)",
            "(job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' AND job.activity_contract_id = $5)",
            "(job.job_type = 'OBSERVE_RUNMILL_RUN' AND job.activity_contract_id = $6)",
        ] {
            assert!(
                CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL.contains(predicate),
                "route-invalid scan must require the canonical contract: {predicate}"
            );
        }
        for (name, claim_sql) in [
            ("ready", CLAIM_READY_JOBS_SQL),
            ("orphaned exhausted", CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL),
            ("route invalid", CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL),
        ] {
            for predicate in [
                "JOIN work_orders AS route_work_order",
                "route_work_order.tenant_id = route_run.tenant_id",
                "route_work_order.id = route_run.work_order_id",
                "route_work_order.work_item_id = route_run.work_item_id",
                "route_work_order.attempt_id = route_run.attempt_id",
                "route_run.tenant_id = job.tenant_id",
                "route_run.id::text = job.payload ->> 'run_id'",
                "route_run.work_item_id = job.work_item_id",
                "route_run.attempt_id = job.attempt_id",
                "route_run.authoritative",
                "route_run.work_order_id::text = job.payload ->> 'work_order_id'",
                "route_work_order.payload_digest = job.payload ->> 'work_order_digest'",
                "route_run.worker_id::text = job.payload ->> 'worker_id'",
                "route_run.worker_session_id::text = job.payload ->> 'worker_session_id'",
                "job.payload -> 'worker_generation' = to_jsonb(route_run.worker_generation)",
                "route_run.external_run_id = job.payload ->> 'external_run_id'",
                "jsonb_typeof(job.payload) = 'object'",
                "job.payload ->> 'schema' = 'asf.runmill-observation/v2'",
                "job.payload - ARRAY[",
                "jsonb_typeof(job.payload -> 'observation_id') = 'string'",
                "jsonb_typeof(job.payload -> 'after_sequence') = 'number'",
                "jsonb_typeof(job.payload -> 'observation_epoch') = 'number'",
                "JOIN runmill_run_observation_streams AS stream",
                "JOIN runmill_run_observation_checkpoints AS checkpoint",
                "JOIN worker_sessions AS observer_session",
                "JOIN workers AS observer_worker",
                "stream.run_admission_worker_session_id = route_run.worker_session_id",
                "stream.state = 'ACTIVE'",
                "stream.active_job_id = job.id",
                "stream.active_observation_id = checkpoint.id",
                "checkpoint.workflow_job_id = job.id",
                "checkpoint.after_sequence = stream.next_after_sequence",
                "checkpoint.observation_epoch = stream.observation_epoch",
                "checkpoint.observer_session_id::text = job.payload ->> 'observer_session_id'",
                "job.payload -> 'after_sequence' = to_jsonb(stream.next_after_sequence)",
                "job.payload -> 'observation_epoch' = to_jsonb(stream.observation_epoch)",
                "observer_session.status = 'ACTIVE'",
                "observer_session.expires_at > clock_timestamp()",
                "observer_worker.generation = stream.worker_generation",
                "observer_worker.status <> 'QUARANTINED'",
            ] {
                assert!(
                    claim_sql.contains(predicate),
                    "{name} observation route must retain {predicate}"
                );
            }
        }
        for predicate in [
            "JOIN worker_sessions AS observer_session",
            "JOIN workers AS observer_worker",
            "observer_session.status = 'ACTIVE'",
            "observer_session.expires_at > clock_timestamp()",
            "observer_worker.generation = stream.worker_generation",
            "observer_worker.status <> 'QUARANTINED'",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(predicate),
                "known unserviceable observation route must retain {predicate}"
            );
        }
        assert!(CLAIM_READY_JOBS_SQL.contains(
            "job.job_type = 'OBSERVE_RUNMILL_RUN'\n              AND EXISTS (\n                  SELECT 1\n                  FROM unnest($11::text[], $12::text[]) AS observation_route(worker_id, activity_contract_id)"
        ));
        assert!(CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains(
            "job.job_type = 'OBSERVE_RUNMILL_RUN'\n              AND EXISTS (\n                  SELECT 1\n                  FROM unnest($10::text[], $11::text[]) AS observation_route(worker_id, activity_contract_id)"
        ));
        assert!(
            CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL
                .contains("job.job_type = 'OBSERVE_RUNMILL_RUN'\n              AND NOT EXISTS (")
        );
        assert!(
            CLAIM_READY_JOBS_SQL
                .contains("route_run.worker_id::text = job.payload ->> 'worker_id'")
        );
        assert!(CLAIM_READY_JOBS_SQL.contains("FOR UPDATE OF job SKIP LOCKED"));
        assert!(CLAIM_READY_JOBS_SQL.contains("fence_token = job.fence_token + 1"));
        assert!(CLAIM_READY_JOBS_SQL.contains("lease_expires_at <= clock_timestamp()"));
        assert!(CLAIM_READY_JOBS_SQL.contains("job.status = 'RUNNING' AS reclaiming_expired"));
        assert!(CLAIM_READY_JOBS_SQL.contains("WHERE candidates.reclaiming_expired"));
        assert!(CLAIM_READY_JOBS_SQL.contains("SET status = 'AMBIGUOUS'"));
        assert!(CLAIM_READY_JOBS_SQL.contains("owning_workflow_job_id = candidates.id"));
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains("job.attempt_count >= job.max_attempts")
        );
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains(
                "job.job_type NOT IN (\n                  'RECONCILE_WORKER',\n                  'REQUEST_WORK_ITEM_CANCELLATION',\n                  'OBSERVE_RUNMILL_RUN',\n                  'RETAIN_RUNMILL_TERMINAL_EVIDENCE'\n              )\n              AND EXISTS (\n                  SELECT 1\n                  FROM unnest($4::text[], $5::text[]) AS unscoped_route(job_type, activity_contract_id)"
            ),
            "unscoped orphan recovery must require an exact ready (job_type, activity_contract_id) pair, not merely an unrecognized scoped job_type"
        );
        assert!(CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains("FOR UPDATE OF job SKIP LOCKED"));
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL
                .contains("reconcile_route.worker_id = job.payload ->> 'worker_id'")
        );
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL
                .contains("cancellation_route.worker_id = job.payload ->> 'worker_id'")
        );
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL
                .contains("observation_route.worker_id = job.payload ->> 'worker_id'")
        );
        assert!(CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains("SET status = 'AMBIGUOUS'"));
        assert!(
            CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains("owning_workflow_job_id = candidates.id")
        );
        assert!(!CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL.contains("attempt_count ="));
        assert!(CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL.contains(
            "job.job_type IN (\n          'RECONCILE_WORKER',\n          'REQUEST_WORK_ITEM_CANCELLATION',\n          'OBSERVE_RUNMILL_RUN'\n      )"
        ));
        assert!(
            CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL
                .contains("attempt_count = GREATEST(job.attempt_count, job.max_attempts)")
        );
        assert!(CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL.contains("SET status = 'AMBIGUOUS'"));
        assert!(
            CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL
                .contains("effect.owning_workflow_job_id = candidates.id")
        );
        for predicate in [
            "FROM unnest($2::text[], $3::text[]) AS known_route(job_type, activity_contract_id)",
            "known_route.job_type = job.job_type",
            "known_route.activity_contract_id = job.activity_contract_id",
        ] {
            assert!(
                UNKNOWN_OR_INCOMPATIBLE_DUE_JOB_SQL.contains(predicate),
                "unknown-or-incompatible due job check must retain {predicate}"
            );
        }
        assert!(
            !UNKNOWN_OR_INCOMPATIBLE_DUE_JOB_SQL.contains("attempt_count"),
            "the fail-closed preflight must cover every otherwise-due row, including an \
             expired RUNNING final attempt, regardless of attempt_count"
        );
        assert!(
            UNKNOWN_OR_INCOMPATIBLE_DUE_JOB_SQL.contains(
                "  AND (\n      (job.status IN ('PENDING', 'RETRY') AND job.available_at <= clock_timestamp())\n      OR (job.status = 'RUNNING' AND job.lease_expires_at <= clock_timestamp())\n  )"
            ),
            "the fail-closed preflight must directly gate on the due-row predicate, not an attempt-count filter"
        );
        for predicate in [
            "FROM unnest($4::text[], $5::text[]) AS known_route(job_type, activity_contract_id)",
            "known_route.job_type = job.job_type",
            "known_route.activity_contract_id = job.activity_contract_id",
            "FROM unnest($6::text[], $7::text[]) AS ready_route(job_type, activity_contract_id)",
            "ready_route.job_type = job.job_type",
            "ready_route.activity_contract_id = job.activity_contract_id",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(predicate),
                "known-unserviceable claim must retain {predicate}"
            );
        }
        // Verify that known_route is checked with EXISTS and ready_route is checked with NOT EXISTS.
        // Normalize whitespace to handle line wrapping while preserving essential structure.
        let sql_normalized = CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            sql_normalized.contains("EXISTS (")
                && sql_normalized.contains("known_route(job_type, activity_contract_id)"),
            "known-unserviceable claim must have known route guarded by EXISTS"
        );
        assert!(
            sql_normalized.contains("NOT EXISTS ( SELECT 1 FROM unnest($6::text[], $7::text[]) AS ready_route(job_type, activity_contract_id) WHERE ready_route.job_type = job.job_type AND ready_route.activity_contract_id = job.activity_contract_id )"),
            "known-unserviceable claim must have ready_route guarded by NOT EXISTS to exclude jobs whose handler is ready"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("job.activity_contract_id = $8"),
            "known-unserviceable scan must require canonical RECONCILE_WORKER contract"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("job.activity_contract_id = $11"),
            "known-unserviceable scan must require canonical REQUEST_WORK_ITEM_CANCELLATION contract"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("job.activity_contract_id = $14"),
            "known-unserviceable scan must require canonical OBSERVE_RUNMILL_RUN contract"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
                .contains("jsonb_typeof(job.payload -> 'worker_id') = 'string'"),
            "known-unserviceable claim must validate worker_id format for scoped jobs"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("FROM runs AS route_run"),
            "known-unserviceable claim must validate route existence for scoped jobs"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("FOR UPDATE OF job SKIP LOCKED"),
            "known-unserviceable claim must lock only claimable rows"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
                .contains("attempt_count = GREATEST(job.attempt_count, job.max_attempts)"),
            "known-unserviceable claim must set attempt_count to max_attempts for dead-lettering"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("SET status = 'RUNNING'"),
            "known-unserviceable claim must advance job to RUNNING before escalation"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
                .contains("jsonb_typeof(job.payload -> 'observation_id') = 'string'"),
            "known-unserviceable claim must validate all OBSERVE_RUNMILL_RUN payload field types"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
                .contains("jsonb_typeof(job.payload -> 'worker_generation') = 'number'"),
            "known-unserviceable claim must validate numeric field types for observation payloads"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL
                .contains("job.status = 'RUNNING' AS reclaiming_expired"),
            "known-unserviceable claim must track reclaiming_expired to properly release external effects"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("released_external_effects AS ("),
            "known-unserviceable claim must mirror released_external_effects CTE"
        );
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("SET status = 'AMBIGUOUS'"),
            "known-unserviceable claim must transition IN_FLIGHT effects to AMBIGUOUS before refencing"
        );
    }

    #[test]
    fn known_unserviceable_reconcile_worker_rejects_malformed_payloads() {
        for predicate in [
            "job.payload ?& ARRAY['worker_id', 'expected_generation', 'expected_version']",
            "job.payload - ARRAY['worker_id', 'expected_generation', 'expected_version'] = '{}'::jsonb",
            "jsonb_typeof(job.payload -> 'worker_id') = 'string'",
            "[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            "(job.payload ->> 'expected_generation')::bigint > 0",
            "(job.payload ->> 'expected_version')::bigint > 0",
            "job.workflow_instance_id IS NULL",
            "job.work_item_id IS NULL",
            "job.attempt_id IS NULL",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(predicate),
                "known-unserviceable RECONCILE_WORKER must validate payload exactly: {predicate}"
            );
        }
    }

    #[test]
    fn known_unserviceable_cancellation_rejects_invalid_payload() {
        for predicate in [
            "job.payload ?& ARRAY['work_item_id', 'worker_id', 'expected_version', 'reason', 'requested_by']",
            "job.payload - ARRAY['work_item_id', 'worker_id', 'expected_version', 'reason', 'requested_by', 'observe_only'] = '{}'::jsonb",
            "job.payload ->> 'work_item_id' = job.work_item_id::text",
            "jsonb_typeof(job.payload -> 'worker_id') = 'string'",
            "[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            "(job.payload ->> 'expected_version')::bigint > 0",
            "job.payload ->> 'reason' = btrim(job.payload ->> 'reason')",
            "char_length(job.payload ->> 'reason') <= 2048",
            "jsonb_typeof(job.payload -> 'requested_by') = 'string'",
            "char_length(job.payload ->> 'requested_by') <= 1024",
            "job.workflow_instance_id IS NOT NULL",
            "job.attempt_id IS NOT NULL",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(predicate),
                "known-unserviceable REQUEST_WORK_ITEM_CANCELLATION must validate payload exactly: {predicate}"
            );
        }
    }

    #[test]
    fn known_unserviceable_observation_rejects_incomplete_payload() {
        for required_field in [
            "'schema'",
            "'observation_id'",
            "'run_id'",
            "'work_order_id'",
            "'work_order_digest'",
            "'worker_id'",
            "'worker_session_id'",
            "'worker_generation'",
            "'external_run_id'",
            "'after_sequence'",
            "'observation_epoch'",
            "'observer_session_id'",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(required_field),
                "known-unserviceable OBSERVE_RUNMILL_RUN must require {required_field}"
            );
        }
        assert!(
            CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("job.payload - ARRAY[")
                && CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains("] = '{}'::jsonb"),
            "known-unserviceable OBSERVE_RUNMILL_RUN must reject extra fields"
        );
    }

    #[test]
    fn known_unserviceable_observation_validates_field_types() {
        for type_check in [
            "jsonb_typeof(job.payload -> 'observation_id') = 'string'",
            "jsonb_typeof(job.payload -> 'run_id') = 'string'",
            "jsonb_typeof(job.payload -> 'work_order_id') = 'string'",
            "jsonb_typeof(job.payload -> 'work_order_digest') = 'string'",
            "jsonb_typeof(job.payload -> 'worker_id') = 'string'",
            "jsonb_typeof(job.payload -> 'worker_session_id') = 'string'",
            "jsonb_typeof(job.payload -> 'worker_generation') = 'number'",
            "jsonb_typeof(job.payload -> 'external_run_id') = 'string'",
            "jsonb_typeof(job.payload -> 'after_sequence') = 'number'",
            "jsonb_typeof(job.payload -> 'observation_epoch') = 'number'",
            "jsonb_typeof(job.payload -> 'observer_session_id') = 'string'",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(type_check),
                "known-unserviceable OBSERVE_RUNMILL_RUN must validate all field types: {type_check}"
            );
        }
    }

    #[test]
    fn known_unserviceable_observation_validates_uuids_and_digests() {
        for uuid_check in [
            "job.payload ->> 'observation_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            "job.payload ->> 'run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            "job.payload ->> 'work_order_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            "job.payload ->> 'work_order_digest' ~ '^sha256:[0-9a-f]{64}$'",
            "job.payload ->> 'worker_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            "job.payload ->> 'worker_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            "job.payload ->> 'observer_session_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(uuid_check),
                "known-unserviceable OBSERVE_RUNMILL_RUN must validate UUIDs and digests: {uuid_check}"
            );
        }
    }

    #[test]
    fn known_unserviceable_observation_validates_positive_counts_and_bounds() {
        for bound_check in [
            "(job.payload ->> 'worker_generation')::bigint > 0",
            "(job.payload ->> 'observation_epoch')::bigint > 0",
            "(job.payload ->> 'after_sequence')::bigint >= 0",
            "(job.payload ->> 'after_sequence')::bigint <= 9007199254740991",
            "LENGTH(job.payload ->> 'external_run_id') > 0",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(bound_check),
                "known-unserviceable OBSERVE_RUNMILL_RUN must validate bounds: {bound_check}"
            );
        }
    }

    #[test]
    fn known_unserviceable_observation_validates_immutable_bindings() {
        for binding_check in [
            "stream.worker_generation = route_run.worker_generation",
            "stream.run_admission_worker_session_id = route_run.worker_session_id",
            "stream.external_run_id = route_run.external_run_id",
            "route_run.worker_generation = (job.payload ->> 'worker_generation')::bigint",
            "route_run.worker_session_id::text = job.payload ->> 'worker_session_id'",
            "route_run.external_run_id = job.payload ->> 'external_run_id'",
            "checkpoint.worker_generation = stream.worker_generation",
        ] {
            assert!(
                CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL.contains(binding_check),
                "known-unserviceable OBSERVE_RUNMILL_RUN must validate immutable bindings: {binding_check}"
            );
        }
    }

    #[test]
    fn all_claim_sql_have_released_external_effects_cte() {
        for (name, claim_sql) in [
            ("ready", CLAIM_READY_JOBS_SQL),
            ("orphaned exhausted", CLAIM_ORPHANED_EXHAUSTED_JOBS_SQL),
            ("route invalid", CLAIM_ROUTE_INVALID_SCOPED_JOB_SQL),
            ("known unserviceable", CLAIM_KNOWN_UNSERVICEABLE_DUE_JOB_SQL),
        ] {
            assert!(
                claim_sql.contains("WITH candidates AS ("),
                "{name} claim must have candidates CTE"
            );
            assert!(
                claim_sql.contains("released_external_effects AS ("),
                "{name} claim must have released_external_effects CTE"
            );
            assert!(
                claim_sql.contains("UPDATE effect_intents AS effect"),
                "{name} claim released_external_effects must update effect_intents"
            );
            assert!(
                claim_sql.contains("SET status = 'AMBIGUOUS'"),
                "{name} claim must transition IN_FLIGHT effects to AMBIGUOUS"
            );
            if name != "orphaned exhausted" {
                assert!(
                    claim_sql.contains("WHERE candidates.reclaiming_expired"),
                    "{name} claim released_external_effects must filter on reclaiming_expired"
                );
            }
            assert!(
                claim_sql.contains("effect.status = 'IN_FLIGHT'"),
                "{name} claim must only release IN_FLIGHT effects"
            );
            assert!(
                claim_sql.contains("AND (SELECT count(*) FROM released_external_effects) >= 0"),
                "{name} claim must reference released_external_effects CTE in update"
            );
        }
    }

    #[test]
    fn retry_and_supervisor_backoff_are_bounded() {
        let base = Duration::from_secs(1);
        let maximum = Duration::from_secs(30);
        assert_eq!(job_retry_delay(base, maximum, 1), base);
        assert_eq!(job_retry_delay(base, maximum, 4), Duration::from_secs(8));
        assert_eq!(job_retry_delay(base, maximum, i32::MAX), maximum);
        assert_eq!(doubled_backoff(Duration::from_secs(20), maximum), maximum);
    }

    #[test]
    fn options_require_a_bounded_live_lease() {
        assert!(options().validate().is_ok());
        let mut invalid = options();
        invalid.lease_duration = invalid.poll_interval;
        assert!(invalid.validate().is_err());
        invalid = options();
        invalid.claim_batch_size = 1_001;
        assert!(invalid.validate().is_err());

        let mut boundary = options();
        boundary.lease_duration = MAX_JOB_LEASE_DURATION;
        assert!(boundary.validate().is_ok());
        boundary.lease_duration = MAX_JOB_LEASE_DURATION + Duration::from_secs(1);
        assert!(boundary.validate().is_err());
    }

    #[tokio::test]
    async fn live_poll_claims_and_completes_when_database_is_configured() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key, max_attempts
            ) VALUES ($1, $2, 'RUNTIME_TEST_COMPLETE', 'test.activity/runtime-test-complete/v1', '{}'::jsonb, $3, 3)
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(format!("runtime-test-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert runtime job");

        let mut handlers = HandlerRegistry::new();
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register test handler");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");
        let report = reactor.poll_once().await.expect("poll reactor");
        assert_eq!(report.jobs_claimed, 1);
        assert_eq!(report.jobs_completed, 1);
        let (status, fence_token, completed_by): (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status, fence_token, completed_by FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load completed runtime job");
        assert_eq!(status, "COMPLETED");
        assert_eq!(fence_token, 1);
        assert_eq!(
            completed_by.as_deref(),
            Some(reactor.options.lease_owner.as_str())
        );
    }

    #[tokio::test]
    async fn live_poll_fails_closed_on_incompatible_known_job_contract_and_leaves_it_unchanged() {
        const WRONG_CONTRACT: &str = "test.activity/runtime-test-complete/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key, max_attempts
            ) VALUES ($1, $2, 'RUNTIME_TEST_COMPLETE', $3, '{}'::jsonb, $4, 3)
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(WRONG_CONTRACT)
        .bind(format!("runtime-test-incompatible-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert incompatible-contract runtime job");

        let mut handlers = HandlerRegistry::new();
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register test handler");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");
        let error = reactor
            .poll_once()
            .await
            .expect_err("a known job type bound to an incompatible contract must fail closed");
        let Error::Validation(detail) = error else {
            panic!("expected a fail-closed validation error, got {error}");
        };
        assert!(detail.contains("RUNTIME_TEST_COMPLETE"));
        assert!(detail.contains(WRONG_CONTRACT));

        let (status, attempt_count, fence_token): (String, i32, i64) = sqlx::query_as(
            "SELECT status, attempt_count, fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load untouched incompatible-contract job");
        assert_eq!(status, "PENDING");
        assert_eq!(attempt_count, 0);
        assert_eq!(fence_token, 0);
    }

    /// A due job whose exact `(job_type, activity_contract_id)` pair is
    /// unrecognized must fail the reactor closed *before* orphan recovery
    /// ever runs, even when the row is an expired RUNNING final attempt that
    /// would otherwise look like a routine orphaned-exhausted claim. Neither
    /// the unscoped orphan-claim SQL nor the fail-closed preflight may touch
    /// it: it is not recovered, and it is not dead-lettered.
    #[tokio::test]
    async fn live_poll_fails_closed_before_recovering_an_expired_final_unscoped_job_with_incompatible_contract()
     {
        const WRONG_CONTRACT: &str = "test.activity/runtime-test-complete/v2";
        const STALE_LEASE_OWNER: &str = "stale-orphaned-lease-owner";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, status, activity_contract_id, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, 'RUNTIME_TEST_COMPLETE', 'RUNNING', $3, '{}'::jsonb, $4,
                3, 3, 1, $5, clock_timestamp() - interval '1 minute'
            )
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(WRONG_CONTRACT)
        .bind(format!("runtime-test-orphaned-incompatible-{job_id}"))
        .bind(STALE_LEASE_OWNER)
        .execute(ledger.pool())
        .await
        .expect("insert expired final-attempt incompatible-contract runtime job");

        let mut handlers = HandlerRegistry::new();
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register test handler");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");
        let error = reactor.poll_once().await.expect_err(
            "an expired final-attempt job bound to an incompatible contract must fail closed \
             before orphan recovery ever runs",
        );
        let Error::Validation(detail) = error else {
            panic!("expected a fail-closed validation error, got {error}");
        };
        assert!(detail.contains("RUNTIME_TEST_COMPLETE"));
        assert!(detail.contains(WRONG_CONTRACT));

        let (status, attempt_count, fence_token, lease_owner): (String, i32, i64, Option<String>) =
            sqlx::query_as(
                "SELECT status, attempt_count, fence_token, lease_owner FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(job_id)
            .fetch_one(ledger.pool())
            .await
            .expect("load untouched expired final-attempt incompatible-contract job");
        assert_eq!(
            status, "RUNNING",
            "an incompatible expired final claim must not be recovered or dead-lettered"
        );
        assert_eq!(attempt_count, 3);
        assert_eq!(
            fence_token, 1,
            "orphan recovery must never re-fence a contract-incompatible job"
        );
        assert_eq!(lease_owner.as_deref(), Some(STALE_LEASE_OWNER));
    }

    #[tokio::test]
    async fn live_route_invalid_scan_never_dead_letters_a_merely_incompatible_scoped_job() {
        const WRONG_CONTRACT: &str = "asf.activity/reconcile-worker/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");
        let worker_id = WorkerId::new();
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key, max_attempts
            ) VALUES ($1, $2, 'RECONCILE_WORKER', $3, $4, $5, 3)
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(WRONG_CONTRACT)
        .bind(json!({"worker_id": worker_id.to_string()}))
        .bind(format!("reconcile-incompatible-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert incompatible-contract scoped job");

        // Exercise the route-invalid scan directly: even a well-formed worker
        // route must never be dead-lettered here merely because its contract
        // is not the canonical one this daemon currently installs.
        let claimed = claim_one_route_invalid_scoped_job(&ledger, tenant_id, &options())
            .await
            .expect("route-invalid scan must not error on an incompatible contract");
        assert!(
            claimed.is_none(),
            "an incompatible-but-well-formed scoped job must not be claimed as route-invalid"
        );

        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(job_id)
                .fetch_one(ledger.pool())
                .await
                .expect("load untouched incompatible-contract scoped job");
        assert_eq!(status, "PENDING");
    }

    /// A due canonical worker-scoped timer (`RECONCILE_WORKER`,
    /// `REQUEST_WORK_ITEM_CANCELLATION`, or `OBSERVE_RUNMILL_RUN`) can never
    /// gain an exact worker route through the unscoped timer envelope,
    /// regardless of whether its handler happens to be ready. Before this
    /// fix, deriving the scoped-rejection set from `ReadyClaimSet` meant an
    /// unavailable canonical handler's timer silently stayed `SCHEDULED`
    /// forever instead of failing the poll closed. Registering an unrelated
    /// ready unscoped handler alongside it must not change that outcome.
    #[tokio::test]
    async fn live_poll_fails_closed_on_a_due_canonical_scoped_timer_with_an_unavailable_handler() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");

        let timer_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_timers (
                id, tenant_id, workflow_key, timer_key, timer_type,
                activity_contract_id, due_at, payload
            ) VALUES (
                $1, $2, 'timer-test', $3, 'RECONCILE_WORKER', $4,
                clock_timestamp() - interval '1 minute', '{}'::jsonb
            )
            ",
        )
        .bind(timer_id)
        .bind(tenant_id)
        .bind(format!("scoped-{timer_id}"))
        .bind(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        .execute(ledger.pool())
        .await
        .expect("insert due canonical scoped timer");

        let mut handlers = HandlerRegistry::fail_closed_production()
            .expect("build fail-closed production registry");
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register an unrelated ready unscoped handler");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");

        let error = reactor.poll_once().await.expect_err(
            "a due canonical worker-scoped timer must fail the poll closed even when its handler \
             is unavailable and an unrelated unscoped handler is ready",
        );
        let Error::Validation(detail) = error else {
            panic!("expected a fail-closed validation error, got {error}");
        };
        assert!(detail.contains("RECONCILE_WORKER"));

        let status: String = sqlx::query_scalar(
            "SELECT status FROM workflow_timers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(timer_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load untouched scoped timer status");
        assert_eq!(status, "SCHEDULED");
    }

    /// A due job whose `(job_type, activity_contract_id)` pair is known
    /// (via `fail_closed_production` registry) but unavailable (no ready handler)
    /// must be claimed as known-unserviceable, escalated to DEAD with
    /// `attempt_count` = `max_attempts`, and create exactly one owned
    /// escalation/attention receipt. A second poll must not create duplicates.
    #[tokio::test]
    async fn live_poll_escalates_known_unserviceable_due_job_to_dead_with_owned_escalation() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let workflow_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let policy_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");

        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, scope, schema_version, digest, canonical_bytes, policy, created_by) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')",
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(policy_digest)
        .bind(b"{}".as_slice())
        .execute(ledger.pool())
        .await
        .expect("insert policy version");

        // A work item is only storable with its full accepted identity: the
        // source snapshot it came from, its repository, and the policy, budget,
        // and identity authority acceptance froze.
        let repository_id = Uuid::now_v7();
        let source_snapshot_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO repositories (id, tenant_id, owner, name, repository_url, default_branch) VALUES ($1, $2, 'acme', $3, $4, 'main')",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{}", repository_id.simple()))
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert runtime repository");

        sqlx::query(
            "INSERT INTO source_snapshots (id, tenant_id, repository_id, source_system, external_id, source_revision, normalized_content, content_digest, connector_identity, source_updated_at) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', clock_timestamp())",
        )
        .bind(source_snapshot_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(format!("item-{work_item_id}"))
        .bind("sha256:3333333333333333333333333333333333333333333333333333333333333333")
        .execute(ledger.pool())
        .await
        .expect("insert runtime source snapshot");

        // Accepted work, its delivery workflow, its accountability anchor, and
        // the due job that keeps that anchor live all commit together: the
        // anchor check is deferred to commit and refuses anything less.
        let mut work_item_transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin accepted work-item transaction");
        sqlx::query(
            "INSERT INTO work_items (id, tenant_id, source_snapshot_id, source_system, source_external_id, repository_id, state, closure_target, risk_class, policy_digest, budget_limits, identity_requirements, owner_fallback, normalized_priority, discovered_at, accepted_at, aggregate_version) VALUES ($1, $2, $3, 'API', $4, $5, 'RUNNING', 'pull_request', 'low', $6, $7, $8, 'team:platform', 50, clock_timestamp(), clock_timestamp(), 1)",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(source_snapshot_id)
        .bind(format!("item-{work_item_id}"))
        .bind(repository_id)
        .bind(policy_digest)
        .bind(json!({
            "max_cost_microunits": 1_000_000,
            "max_input_tokens": 100_000,
            "max_output_tokens": 100_000,
            "max_implementer_invocations": 2,
            "max_reviewer_invocations": 2,
            "max_fix_iterations": 1,
            "max_wall_time_seconds": 3_600,
            "max_external_api_calls": 10,
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "claude:pr-reviewer",
        }))
        .execute(&mut *work_item_transaction)
        .await
        .expect("insert accepted work item");
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state, reducer_version,
                aggregate_version, fence_token
            ) VALUES ($1, $2, $3, 'KNOWN_UNSERVICEABLE_TEST', 'ACTIVE', 'v1', 1, 0)
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *work_item_transaction)
        .await
        .expect("insert delivery workflow instance");
        sqlx::query(
            "INSERT INTO accountability_anchors (tenant_id, work_item_id, anchor_type, reference_id, authority_or_effect_active) VALUES ($1, $2, 'WORKFLOW', $3, true)",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(workflow_id)
        .execute(&mut *work_item_transaction)
        .await
        .expect("anchor the accepted work item to its delivery workflow");

        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest
            ) VALUES ($1, $2, $3, 1, 'AUTHORIZED', $4, $5, $6, $7, $8)
            ",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(format!("attempt-{attempt_id}"))
        .bind("main")
        .bind("0000000000000000000000000000000000000001")
        .bind("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        .bind(policy_digest)
        .execute(&mut *work_item_transaction)
        .await
        .expect("insert attempt");

        sqlx::query(
            "UPDATE work_items SET current_attempt_id = $3, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .execute(&mut *work_item_transaction)
        .await
        .expect("bind work item to its active attempt");

        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, payload, idempotency_key, max_attempts,
                available_at, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb, $8, 3, clock_timestamp() - interval '1 minute', 'PENDING')
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind("INTAKE_SYNC")
        .bind("asf.activity/intake-sync/v1")
        .bind(format!("known-unserviceable-{job_id}"))
        .execute(&mut *work_item_transaction)
        .await
        .expect("insert known-unserviceable due job");
        // The anchor is only live while this workflow owns a claimable job, so
        // the whole accepted obligation commits as one deferred-checked fact.
        work_item_transaction
            .commit()
            .await
            .expect("commit the accepted work item, its anchor, and its due job");

        let handlers = HandlerRegistry::fail_closed_production()
            .expect("build fail-closed production registry");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");

        let report = reactor.poll_once().await.expect("poll reactor once");
        assert_eq!(
            report.known_unserviceable_jobs_escalated, 1,
            "first poll must escalate exactly one known-unserviceable job"
        );

        let (status, attempt_count, max_attempts, fence_token): (String, i32, i32, i64) = sqlx::query_as(
            "SELECT status, attempt_count, max_attempts, fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load escalated known-unserviceable job");
        assert_eq!(status, "DEAD");
        assert_eq!(attempt_count, max_attempts);
        assert_eq!(fence_token, 1);

        let escalation_count: i64 =
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM escalations WHERE tenant_id = $1 AND work_item_id = $2 AND attempt_id = $3 AND idempotency_key LIKE 'workflow-job-exhausted:%'",
            )
                .bind(tenant_id)
                .bind(work_item_id)
                .bind(attempt_id)
                .fetch_one(ledger.pool())
                .await
                .expect("count escalations owned by exhausted job");
        assert_eq!(escalation_count, 1, "must create exactly one escalation");

        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM outbox WHERE tenant_id = $1 AND topic = 'attention' AND message_key = $2 AND event_type = 'workflow_job.exhausted'",
        )
        .bind(tenant_id)
        .bind(work_item_id.to_string())
        .fetch_one(ledger.pool())
        .await
        .expect("count outbox attention messages");
        assert_eq!(
            outbox_count, 1,
            "must create exactly one owned attention receipt"
        );

        let report2 = reactor.poll_once().await.expect("poll reactor again");
        assert_eq!(
            report2.known_unserviceable_jobs_escalated, 0,
            "second poll must not create duplicate escalations"
        );

        let escalation_count2: i64 =
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM escalations WHERE tenant_id = $1 AND work_item_id = $2 AND attempt_id = $3 AND idempotency_key LIKE 'workflow-job-exhausted:%'",
            )
                .bind(tenant_id)
                .bind(work_item_id)
                .bind(attempt_id)
                .fetch_one(ledger.pool())
                .await
                .expect("count escalations after second poll");
        assert_eq!(
            escalation_count2, 1,
            "second poll must not create duplicate escalation"
        );
    }

    /// A job with an incompatible activity contract that matches a known
    /// job type must remain untouched/fail closed, even for the
    /// known-unserviceable scanner.
    #[tokio::test]
    async fn live_poll_fails_closed_on_incompatible_known_job_contract_for_unserviceable_scan() {
        const WRONG_CONTRACT: &str = "asf.activity/intake-sync/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");

        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key,
                max_attempts, available_at, status
            ) VALUES ($1, $2, 'INTAKE_SYNC', $3, '{}'::jsonb, $4, 3, clock_timestamp() - interval '1 minute', 'PENDING')
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(WRONG_CONTRACT)
        .bind(format!("incompatible-known-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert incompatible-known-type job");

        let handlers = HandlerRegistry::fail_closed_production()
            .expect("build fail-closed production registry");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");

        let error = reactor
            .poll_once()
            .await
            .expect_err("a known job type with incompatible contract must fail closed");
        let Error::Validation(detail) = error else {
            panic!("expected a fail-closed validation error, got {error}");
        };
        assert!(
            detail.contains("INTAKE_SYNC"),
            "error must mention the job type"
        );
        assert!(
            detail.contains(WRONG_CONTRACT),
            "error must mention the incompatible contract"
        );

        let (status, attempt_count, fence_token): (String, i32, i64) = sqlx::query_as(
            "SELECT status, attempt_count, fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load untouched incompatible-known job");
        assert_eq!(status, "PENDING");
        assert_eq!(attempt_count, 0);
        assert_eq!(fence_token, 0);
    }

    /// A due job that matches a known job type and contract pair, but has
    /// a ready handler installed, must NOT be selected by the
    /// known-unserviceable scanner. Instead, the ready handler's standard
    /// claim path should claim it.
    #[tokio::test]
    async fn live_poll_excludes_ready_matching_job_from_known_unserviceable_scan() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Runtime test')")
            .bind(tenant_id)
            .bind(format!("runtime-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert runtime tenant");

        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key,
                max_attempts, available_at, status
            ) VALUES ($1, $2, 'RUNTIME_TEST_COMPLETE', 'test.activity/runtime-test-complete/v1', '{}'::jsonb, $3, 3, clock_timestamp() - interval '1 minute', 'PENDING')
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(format!("ready-excluded-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert ready job");

        let mut handlers = HandlerRegistry::new();
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register ready handler");
        let reactor = ReactorRuntime::new(ledger.clone(), tenant_id, handlers, options(), false)
            .expect("create reactor");

        let report = reactor.poll_once().await.expect("poll reactor");
        assert_eq!(
            report.known_unserviceable_jobs_escalated, 0,
            "ready job must not be selected by known-unserviceable scanner"
        );
        assert_eq!(
            report.jobs_claimed, 1,
            "ready job must be claimed by normal ready handler path"
        );
        assert_eq!(
            report.jobs_completed, 1,
            "ready job must be completed after claiming"
        );

        let (status, fence_token, completed_by): (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status, fence_token, completed_by FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load completed ready job");
        assert_eq!(status, "COMPLETED");
        assert_eq!(fence_token, 1);
        assert_eq!(
            completed_by.as_deref(),
            Some(reactor.options.lease_owner.as_str())
        );
    }

    #[test]
    fn test_handler_is_ready() {
        let mut handlers = HandlerRegistry::new();
        handlers
            .register(Arc::new(CompleteTestHandler))
            .expect("register handler");
        assert_eq!(
            handlers
                .handler("RUNTIME_TEST_COMPLETE")
                .unwrap()
                .readiness(),
            HandlerReadiness::Ready
        );
    }
}
