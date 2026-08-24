//! Atomic, fenced workflow-step persistence.
//!
//! A reactor may perform additional ledger work in the same transaction, so
//! these functions deliberately accept a caller-owned [`Transaction`] instead
//! of opening or committing one themselves.  The caller must commit the
//! transaction before acknowledging the workflow step.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{jobs::is_valid_activity_contract_id, persistence_error};
use crate::{
    Error, Result,
    audit::{AuditEventContent, HashedAuditEvent},
    contracts::RunmillSignedWorkOrderV1,
    crypto::{canonical_json, sha256_digest},
    domain::{AttemptId, EventId, TenantId, WorkItemId},
};

const MAX_JOB_ERROR_CHARACTERS: usize = 8_192;

const LOCK_AUDIT_CHAIN_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))";

const LOAD_AUDIT_CHAIN_HEAD_SQL: &str = r"
SELECT event.event_hash
FROM audit_events AS event
WHERE event.tenant_id = $1
  AND NOT EXISTS (
      SELECT 1
      FROM audit_events AS successor
      WHERE successor.tenant_id = event.tenant_id
        AND successor.previous_event_hash = event.event_hash
  )
";

const LOCK_STEP_JOB_SQL: &str = r"
SELECT
    job.status,
    job.job_type,
    job.workflow_instance_id,
    job.work_item_id,
    job.attempt_id,
    job.attempt_count,
    job.max_attempts,
    job.fence_token,
    job.lease_owner,
    job.lease_expires_at,
    job.lease_expires_at > clock_timestamp() AS lease_is_live,
    job.completed_by,
    job.completion_fence_token,
    job.result,
    job.last_failure_by,
    job.last_failure_fence_token,
    job.last_failure_retry_at,
    job.last_error,
    job.dead_letter_escalation_id,
    job.dead_lettered_at
FROM workflow_jobs AS job
WHERE job.tenant_id = $1
  AND job.id = $2
FOR UPDATE OF job
";

const LOCK_WORK_ORDER_SQL: &str = r"
SELECT
    work_order.id,
    work_order.payload_digest,
    work_order.exact_signed_envelope
FROM work_orders AS work_order
WHERE work_order.tenant_id = $1
  AND work_order.work_item_id = $2
  AND work_order.attempt_id = $3
FOR UPDATE OF work_order
";

const UPDATE_WORK_ITEM_SQL: &str = r"
UPDATE work_items AS work
SET state = $4,
    aggregate_version = work.aggregate_version + 1,
    closed_at = CASE
        WHEN $4 = 'CLOSED' THEN COALESCE(work.closed_at, clock_timestamp())
        ELSE work.closed_at
    END,
    updated_at = clock_timestamp()
WHERE work.tenant_id = $1
  AND work.id = $2
  AND work.aggregate_version = $3
RETURNING work.aggregate_version
";

const UPDATE_WORKFLOW_SQL: &str = r"
UPDATE workflow_instances AS workflow
SET state = $6,
    event_cursor = $7,
    fence_token = workflow.fence_token + 1,
    aggregate_version = workflow.aggregate_version + 1,
    terminal_at = CASE
        WHEN $6 IN ('COMPLETED', 'FAILED', 'CANCELLED')
            THEN COALESCE(workflow.terminal_at, clock_timestamp())
        ELSE NULL
    END,
    updated_at = clock_timestamp()
WHERE workflow.tenant_id = $1
  AND workflow.id = $2
  AND workflow.work_item_id = $3
  AND workflow.aggregate_version = $4
  AND workflow.fence_token = $5
RETURNING workflow.aggregate_version, workflow.fence_token
";

const REPLACE_ACCOUNTABILITY_SQL: &str = r"
INSERT INTO accountability_anchors (
    tenant_id,
    work_item_id,
    anchor_type,
    reference_id,
    wake_or_deadline_at,
    authority_or_effect_active,
    generation,
    updated_at
)
SELECT $1, $2, $3, $4, $5, $6, $8, clock_timestamp()
WHERE $7 = 0
   OR EXISTS (
       SELECT 1
       FROM accountability_anchors AS current_anchor
       WHERE current_anchor.tenant_id = $1
         AND current_anchor.work_item_id = $2
         AND current_anchor.generation = $7
   )
ON CONFLICT (tenant_id, work_item_id) DO UPDATE
SET anchor_type = EXCLUDED.anchor_type,
    reference_id = EXCLUDED.reference_id,
    wake_or_deadline_at = EXCLUDED.wake_or_deadline_at,
    authority_or_effect_active = EXCLUDED.authority_or_effect_active,
    generation = EXCLUDED.generation,
    updated_at = clock_timestamp()
WHERE accountability_anchors.generation = $7
RETURNING generation
";

const COMPLETE_STEP_JOB_SQL: &str = r"
-- lock_step_job has already locked this row and require_live_claim validated
-- lease freshness. Once locked, owner+fence are the durable handoff guard even
-- if wall clock passes the lease deadline during the remaining transaction.
UPDATE workflow_jobs AS job
SET status = 'COMPLETED',
    result = $5,
    completed_by = $3,
    completion_fence_token = $4,
    completed_at = clock_timestamp(),
    lease_owner = NULL,
    lease_expires_at = NULL,
    updated_at = clock_timestamp()
WHERE job.tenant_id = $1
  AND job.id = $2
  AND job.status = 'RUNNING'
  AND job.lease_owner = $3
  AND job.fence_token = $4
RETURNING job.id
";

const FAIL_STEP_JOB_SQL: &str = r"
-- The job row is locked and its lease was live at transaction ownership
-- transfer. Do not re-age the lease while atomic escalation/audit work runs.
UPDATE workflow_jobs AS job
SET status = CASE
        WHEN $9 OR job.attempt_count >= job.max_attempts THEN 'DEAD'
        ELSE 'RETRY'
    END,
    available_at = CASE
        WHEN $9 OR job.attempt_count >= job.max_attempts THEN job.available_at
        ELSE GREATEST($6, clock_timestamp())
    END,
    last_failure_by = $3,
    last_failure_fence_token = $4,
    last_failure_retry_at = $6,
    last_error = $5,
    result = CASE
        WHEN $9 OR job.attempt_count >= job.max_attempts THEN $8
        ELSE NULL
    END,
    dead_letter_escalation_id = CASE
        WHEN $9 OR job.attempt_count >= job.max_attempts THEN $7
        ELSE NULL
    END,
    dead_lettered_at = CASE
        WHEN $9 OR job.attempt_count >= job.max_attempts THEN clock_timestamp()
        ELSE NULL
    END,
    lease_owner = NULL,
    lease_expires_at = NULL,
    updated_at = clock_timestamp()
WHERE job.tenant_id = $1
  AND job.id = $2
  AND job.status = 'RUNNING'
  AND job.lease_owner = $3
  AND job.fence_token = $4
RETURNING job.status
";

const INSERT_STEP_JOB_SQL: &str = r"
INSERT INTO workflow_jobs (
    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
    job_type, activity_contract_id, payload, idempotency_key, priority,
    available_at, max_attempts
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
SET id = workflow_jobs.id
WHERE workflow_jobs.id = EXCLUDED.id
  AND workflow_jobs.workflow_instance_id = EXCLUDED.workflow_instance_id
  AND workflow_jobs.work_item_id = EXCLUDED.work_item_id
  AND workflow_jobs.attempt_id IS NOT DISTINCT FROM EXCLUDED.attempt_id
  AND workflow_jobs.job_type = EXCLUDED.job_type
  AND workflow_jobs.activity_contract_id = EXCLUDED.activity_contract_id
  AND workflow_jobs.payload = EXCLUDED.payload
  AND workflow_jobs.priority = EXCLUDED.priority
  AND workflow_jobs.available_at = EXCLUDED.available_at
  AND workflow_jobs.max_attempts = EXCLUDED.max_attempts
RETURNING workflow_jobs.id
";

const INSERT_STEP_TIMER_SQL: &str = r"
INSERT INTO workflow_timers (
    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
    workflow_key, timer_key, timer_type, activity_contract_id, due_at,
    payload, generation
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, workflow_key, timer_key) DO UPDATE
SET id = workflow_timers.id
WHERE workflow_timers.id = EXCLUDED.id
  AND workflow_timers.workflow_instance_id = EXCLUDED.workflow_instance_id
  AND workflow_timers.work_item_id = EXCLUDED.work_item_id
  AND workflow_timers.attempt_id IS NOT DISTINCT FROM EXCLUDED.attempt_id
  AND workflow_timers.timer_type = EXCLUDED.timer_type
  AND workflow_timers.activity_contract_id = EXCLUDED.activity_contract_id
  AND workflow_timers.due_at = EXCLUDED.due_at
  AND workflow_timers.payload = EXCLUDED.payload
  AND workflow_timers.generation = EXCLUDED.generation
RETURNING workflow_timers.id
";

const INSERT_ESCALATION_SQL: &str = r"
INSERT INTO escalations (
    id,
    tenant_id,
    work_item_id,
    attempt_id,
    run_id,
    category,
    status,
    severity,
    reason,
    owner_type,
    owner_id,
    required_action,
    evidence_references,
    deadline,
    escalation_path,
    retry_policy,
    prerequisites,
    authority_or_effect_active,
    idempotency_key,
    opened_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, 'OPEN', $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18, $19
)
ON CONFLICT (
    tenant_id,
    work_item_id,
    (COALESCE(attempt_id, '00000000-0000-0000-0000-000000000000'::uuid)),
    category
)
WHERE status IN ('OPEN', 'ACKNOWLEDGED')
DO NOTHING
RETURNING
    escalations.tenant_id,
    escalations.work_item_id,
    escalations.attempt_id,
    escalations.id,
    escalations.run_id,
    escalations.category,
    escalations.status,
    escalations.severity,
    escalations.reason,
    escalations.owner_type,
    escalations.owner_id,
    escalations.required_action,
    escalations.evidence_references,
    escalations.deadline,
    escalations.escalation_path,
    escalations.retry_policy,
    escalations.prerequisites,
    escalations.authority_or_effect_active,
    escalations.idempotency_key,
    escalations.aggregate_version,
    escalations.opened_at,
    escalations.acknowledged_at,
    escalations.closed_at
";

const LOAD_ACTIVE_ESCALATION_SQL: &str = r"
SELECT
    escalation.tenant_id,
    escalation.work_item_id,
    escalation.attempt_id,
    escalation.id,
    escalation.run_id,
    escalation.category,
    escalation.status,
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
    escalation.idempotency_key,
    escalation.aggregate_version,
    escalation.opened_at,
    escalation.acknowledged_at,
    escalation.closed_at
FROM escalations AS escalation
WHERE escalation.tenant_id = $1
  AND escalation.work_item_id = $2
  AND escalation.attempt_id IS NOT DISTINCT FROM $3::uuid
  AND escalation.category = $4
  AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
FOR UPDATE OF escalation
";

const MERGE_ACTIVE_ESCALATION_SQL: &str = r"
UPDATE escalations
SET
    severity = CASE
        WHEN escalations.severity = 'CRITICAL' OR $3 = 'CRITICAL' THEN 'CRITICAL'
        ELSE 'HIGH'
    END,
    reason = CASE
        WHEN strpos(escalations.reason, $4) > 0 THEN escalations.reason
        ELSE escalations.reason || E'\n' || $4
    END,
    required_action = CASE
        WHEN strpos(escalations.required_action, $5) > 0
            THEN escalations.required_action
        ELSE escalations.required_action || E'\n' || $5
    END,
    evidence_references = escalations.evidence_references || COALESCE(
        (
            SELECT jsonb_agg(candidate.value ORDER BY candidate.ordinality)
            FROM jsonb_array_elements($6::jsonb)
                 WITH ORDINALITY AS candidate(value, ordinality)
            WHERE NOT escalations.evidence_references
                @> jsonb_build_array(candidate.value)
        ),
        '[]'::jsonb
    ),
    deadline = LEAST(escalations.deadline, $7),
    retry_policy = jsonb_build_object(
        'automatic', false,
        'max_additional_attempts', 0,
        'backoff_seconds', 0,
        'prerequisites', CASE
            WHEN jsonb_typeof(escalations.retry_policy -> 'prerequisites') = 'array'
                THEN escalations.retry_policy -> 'prerequisites'
            ELSE $8::jsonb -> 'prerequisites'
        END
    ),
    authority_or_effect_active = true,
    aggregate_version = escalations.aggregate_version + 1
WHERE escalations.tenant_id = $1
  AND escalations.id = $2
  AND escalations.status IN ('OPEN', 'ACKNOWLEDGED')
RETURNING
    escalations.tenant_id,
    escalations.work_item_id,
    escalations.attempt_id,
    escalations.id,
    escalations.run_id,
    escalations.category,
    escalations.status,
    escalations.severity,
    escalations.reason,
    escalations.owner_type,
    escalations.owner_id,
    escalations.required_action,
    escalations.evidence_references,
    escalations.deadline,
    escalations.escalation_path,
    escalations.retry_policy,
    escalations.prerequisites,
    escalations.authority_or_effect_active,
    escalations.idempotency_key,
    escalations.aggregate_version,
    escalations.opened_at,
    escalations.acknowledged_at,
    escalations.closed_at
";

/// The claimed job and aggregate compare-and-swap values for one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowStepFence {
    pub tenant_id: Uuid,
    pub job_id: Uuid,
    pub workflow_instance_id: Uuid,
    pub work_item_id: Uuid,
    pub lease_owner: String,
    pub job_fence_token: i64,
    pub expected_work_item_version: i64,
    pub expected_workflow_version: i64,
    pub expected_workflow_fence_token: i64,
    /// Zero means that the step is installing the first anchor.
    pub expected_anchor_generation: i64,
}

impl WorkflowStepFence {
    fn validate(&self) -> Result<()> {
        if self.tenant_id.is_nil()
            || self.job_id.is_nil()
            || self.workflow_instance_id.is_nil()
            || self.work_item_id.is_nil()
        {
            return Err(Error::Validation(
                "workflow-step IDs must be non-nil".into(),
            ));
        }
        if self.lease_owner.trim().is_empty() {
            return Err(Error::Validation(
                "workflow-step lease owner must be non-empty".into(),
            ));
        }
        if self.job_fence_token <= 0
            || self.expected_work_item_version <= 0
            || self.expected_workflow_version <= 0
            || self.expected_workflow_fence_token < 0
            || self.expected_anchor_generation < 0
        {
            return Err(Error::Validation(
                "workflow-step fences and aggregate versions are invalid".into(),
            ));
        }
        Ok(())
    }
}

/// The database-backed accountability kind installed by a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerAccountabilityKind {
    Workflow,
    Run,
    Timer,
    Retry,
    Approval,
    Escalation,
    Closure,
    Cancellation,
}

impl LedgerAccountabilityKind {
    const fn as_sql(self) -> &'static str {
        match self {
            Self::Workflow => "WORKFLOW",
            Self::Run => "RUN",
            Self::Timer => "TIMER",
            Self::Retry => "RETRY",
            Self::Approval => "APPROVAL",
            Self::Escalation => "ESCALATION",
            Self::Closure => "CLOSURE",
            Self::Cancellation => "CANCELLATION",
        }
    }

    const fn requires_deadline(self) -> bool {
        matches!(
            self,
            Self::Timer | Self::Retry | Self::Approval | Self::Escalation
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountabilityReplacement {
    pub kind: LedgerAccountabilityKind,
    pub reference_id: Uuid,
    pub wake_or_deadline_at: Option<DateTime<Utc>>,
    pub authority_or_effect_active: bool,
}

impl AccountabilityReplacement {
    fn validate(&self) -> Result<()> {
        if self.reference_id.is_nil() {
            return Err(Error::Validation(
                "accountability reference ID must be non-nil".into(),
            ));
        }
        if self.kind.requires_deadline() != self.wake_or_deadline_at.is_some() {
            return Err(Error::Validation(
                "accountability deadline does not match its anchor kind".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepWorkflowJob {
    pub id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub job_type: String,
    pub activity_contract_id: String,
    pub payload: Value,
    pub idempotency_key: String,
    pub priority: i16,
    pub available_at: DateTime<Utc>,
    pub max_attempts: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepWorkflowTimer {
    pub id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub workflow_key: String,
    pub timer_key: String,
    pub timer_type: String,
    pub activity_contract_id: String,
    pub due_at: DateTime<Utc>,
    pub payload: Value,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunmillSubmissionEffectBinding {
    pub work_order_id: Uuid,
    pub work_order_digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepEffectIntent {
    pub id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub provider: String,
    pub effect_type: String,
    pub idempotency_key: String,
    pub correlation_marker: Option<String>,
    pub request_digest: String,
    pub request_payload: Value,
    /// Required only for `runmill/submit_work_order`.  These columns form a
    /// relational foreign key to the exact immutable Work Order; JSON request
    /// contents alone are not accepted as authority provenance.
    pub runmill_submission: Option<RunmillSubmissionEffectBinding>,
    pub next_attempt_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepOutboxMessage {
    pub id: Uuid,
    pub topic: String,
    pub message_key: String,
    pub event_type: String,
    pub payload: Value,
    pub headers: Value,
    pub idempotency_key: String,
    pub available_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepAuditEvent {
    pub id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub subject_type: String,
    pub subject_id: String,
    pub correlation_id: String,
    pub trace_id: Option<String>,
    pub policy_digest: Option<String>,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub details: Value,
    pub occurred_at: DateTime<Utc>,
}

/// All durable rows produced by a successfully reduced workflow fact.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowStepCommit {
    pub fence: WorkflowStepFence,
    /// Digest of the complete semantic write set, stored on the completed job.
    pub commit_digest: String,
    pub job_result: Option<Value>,
    pub work_item_state: String,
    pub workflow_state: String,
    pub workflow_event_cursor: i64,
    pub accountability: AccountabilityReplacement,
    pub jobs: Vec<StepWorkflowJob>,
    pub timers: Vec<StepWorkflowTimer>,
    pub effects: Vec<StepEffectIntent>,
    pub outbox: Vec<StepOutboxMessage>,
    pub audit_events: Vec<StepAuditEvent>,
}

impl WorkflowStepCommit {
    fn stored_result(&self) -> Value {
        json!({
            "workflow_step_commit_digest": self.commit_digest,
            "result": self.job_result,
        })
    }

    fn validate(&self) -> Result<()> {
        self.fence.validate()?;
        self.accountability.validate()?;
        validate_digest(&self.commit_digest, "workflow-step commit digest")?;
        validate_work_item_state(&self.work_item_state)?;
        validate_workflow_state(&self.workflow_state)?;
        if self.workflow_event_cursor < 0 {
            return Err(Error::Validation(
                "workflow event cursor cannot be negative".into(),
            ));
        }
        if self.audit_events.is_empty() {
            return Err(Error::Validation(
                "a workflow-step commit must contain an audit event".into(),
            ));
        }
        for job in &self.jobs {
            validate_job(job)?;
        }
        for timer in &self.timers {
            validate_timer(timer)?;
        }
        for effect in &self.effects {
            validate_step_effect_intent(effect, self.fence.tenant_id, self.fence.work_item_id)?;
        }
        for message in &self.outbox {
            validate_outbox(message)?;
        }
        for audit in &self.audit_events {
            validate_audit(audit)?;
        }
        validate_anchor_state_compatibility(&self.work_item_state, self.accountability.kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStepCommitOutcome {
    Applied {
        work_item_version: i64,
        workflow_version: i64,
        workflow_fence_token: i64,
        anchor_generation: i64,
    },
    AlreadyApplied,
}

/// Owned dead-letter details required before a job is allowed to become DEAD.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadLetterEscalation {
    pub id: Uuid,
    pub run_id: Option<Uuid>,
    pub category: String,
    pub severity: String,
    pub reason: String,
    pub owner_type: String,
    pub owner_id: String,
    pub required_action: String,
    pub evidence_references: Value,
    pub deadline: DateTime<Utc>,
    pub escalation_path: Value,
    pub retry_policy: Value,
    pub prerequisites: Value,
    pub authority_or_effect_active: bool,
    pub idempotency_key: String,
    pub opened_at: DateTime<Utc>,
    pub audit_event: StepAuditEvent,
    pub outbox_message: StepOutboxMessage,
}

impl DeadLetterEscalation {
    fn validate(&self) -> Result<()> {
        if self.id.is_nil()
            || self.reason.trim().is_empty()
            || self.owner_id.trim().is_empty()
            || self.required_action.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
        {
            return Err(Error::Validation(
                "dead-letter escalation requires an ID, reason, owner, action, and idempotency key"
                    .into(),
            ));
        }
        validate_escalation_category(&self.category)?;
        if self.category != "WORKFLOW_JOB_EXHAUSTED" {
            return Err(Error::Validation(
                "dead-letter escalation category must be WORKFLOW_JOB_EXHAUSTED".into(),
            ));
        }
        validate_escalation_severity(&self.severity)?;
        validate_owner_type(&self.owner_type)?;
        if !self.evidence_references.is_array()
            || !self.escalation_path.is_array()
            || !self.retry_policy.is_object()
            || !self.prerequisites.is_array()
        {
            return Err(Error::Validation(
                "dead-letter escalation JSON fields have invalid shapes".into(),
            ));
        }
        if self.deadline <= self.opened_at {
            return Err(Error::Validation(
                "dead-letter escalation deadline must follow its opening time".into(),
            ));
        }
        validate_audit(&self.audit_event)?;
        validate_outbox(&self.outbox_message)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowStepFailure {
    pub fence: WorkflowStepFence,
    pub error_summary: String,
    pub retry_at: DateTime<Utc>,
    pub dead_letter: DeadLetterEscalation,
}

impl WorkflowStepFailure {
    fn validate(&self) -> Result<()> {
        self.fence.validate()?;
        if self.error_summary.trim().is_empty() {
            return Err(Error::Validation(
                "workflow-step failure summary must be non-empty".into(),
            ));
        }
        self.dead_letter.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStepFailureDisposition {
    RetryScheduled,
    Escalated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowStepFailureOutcome {
    pub disposition: WorkflowStepFailureDisposition,
    pub newly_recorded: bool,
    pub dead_letter_escalation_id: Option<Uuid>,
}

/// Persist a reduced workflow step as one caller-controlled transaction.
///
/// The claim is checked twice: while locking the job and again in the final
/// completion update.  Aggregate versions and the accountability generation
/// are independent compare-and-swap guards.  A response-loss retry is accepted
/// only when the same owner, job fence, and semantic commit digest are already
/// recorded.
///
/// # Errors
///
/// Returns a validation error for malformed rows, a conflict for a stale lease
/// or aggregate fence, and a persistence error for a database failure.
pub async fn commit_workflow_step(
    transaction: &mut Transaction<'_, Postgres>,
    commit: &WorkflowStepCommit,
) -> Result<WorkflowStepCommitOutcome> {
    commit_workflow_step_inner(transaction, commit, false).await
}

/// Commit after this same transaction already locked and validated the exact
/// live workflow-job claim before acquiring any aggregate locks.
///
/// This is crate-private because skipping a second wall-clock lease check is
/// safe only while the original `FOR UPDATE` lock is still held.  Status,
/// owner, and fence are revalidated; the lease is not re-aged while the lock
/// prevents a reaper or replacement claimant from taking ownership.
pub(crate) async fn commit_workflow_step_with_prelocked_claim(
    transaction: &mut Transaction<'_, Postgres>,
    commit: &WorkflowStepCommit,
) -> Result<WorkflowStepCommitOutcome> {
    commit_workflow_step_inner(transaction, commit, true).await
}

async fn commit_workflow_step_inner(
    transaction: &mut Transaction<'_, Postgres>,
    commit: &WorkflowStepCommit,
    claim_was_prelocked_live: bool,
) -> Result<WorkflowStepCommitOutcome> {
    commit.validate()?;
    let stored_result = commit.stored_result();
    let job = lock_step_job(transaction, &commit.fence).await?;
    require_step_binding(&job, &commit.fence)?;
    if completed_step_matches(&job, &commit.fence, &stored_result)? {
        return Ok(WorkflowStepCommitOutcome::AlreadyApplied);
    }
    if claim_was_prelocked_live {
        require_owned_claim(&job, &commit.fence)?;
    } else {
        require_live_claim(&job, &commit.fence)?;
    }

    lock_step_aggregates(transaction, &commit.fence).await?;

    for job in &commit.jobs {
        insert_workflow_job(transaction, &commit.fence, job).await?;
    }
    for timer in &commit.timers {
        insert_workflow_timer(transaction, &commit.fence, timer).await?;
    }
    for effect in &commit.effects {
        insert_effect_intent(transaction, &commit.fence, effect).await?;
    }
    for message in &commit.outbox {
        insert_outbox_message(transaction, commit.fence.tenant_id, message).await?;
    }
    for audit in &commit.audit_events {
        insert_audit_event(transaction, &commit.fence, audit).await?;
    }

    let work_item_version =
        update_work_item(transaction, &commit.fence, &commit.work_item_state).await?;
    let (workflow_version, workflow_fence_token) = update_workflow(
        transaction,
        &commit.fence,
        &commit.workflow_state,
        commit.workflow_event_cursor,
    )
    .await?;
    let anchor_generation =
        replace_accountability(transaction, &commit.fence, &commit.accountability).await?;

    let completed = sqlx::query(COMPLETE_STEP_JOB_SQL)
        .bind(commit.fence.tenant_id)
        .bind(commit.fence.job_id)
        .bind(&commit.fence.lease_owner)
        .bind(commit.fence.job_fence_token)
        .bind(&stored_result)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("complete fenced workflow step", error))?;
    if completed.is_none() {
        return Err(stale_step_error(commit.fence.job_id));
    }

    Ok(WorkflowStepCommitOutcome::Applied {
        work_item_version,
        workflow_version,
        workflow_fence_token,
        anchor_generation,
    })
}

/// Atomically fail a claimed step.
///
/// A non-final failure returns the same job to the retry queue.  If the claim
/// consumed the final allowed attempt, this function refuses to write a naked
/// `DEAD` row: it also opens the supplied owned escalation, moves the work item
/// to `ESCALATED`, leaves the workflow waiting, replaces the accountability
/// anchor, emits an outbox message, and appends an audit event.
///
/// # Errors
///
/// Returns a conflict for a stale claim or aggregate fence and never commits a
/// terminal job without its owned escalation.
pub async fn fail_workflow_step(
    transaction: &mut Transaction<'_, Postgres>,
    failure: &WorkflowStepFailure,
) -> Result<WorkflowStepFailureOutcome> {
    fail_workflow_step_inner(transaction, failure, false, false).await
}

/// Atomically terminally fail a claim that this transaction already locked and
/// proved live before retaining dependent durable evidence.
///
/// This is crate-private because it intentionally bypasses the second
/// wall-clock lease check: the caller must still hold the exact job-row lock
/// obtained while the lease was live. It is also deliberately force-terminal,
/// for structural failures (such as an observed compacted event gap) that must
/// stop the work even when its configured retry budget remains. The existing
/// owned escalation, audit, outbox, accountability, and fenced `DEAD`
/// transition are retained unchanged.
pub(crate) async fn fail_workflow_step_with_prelocked_claim_force_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    failure: &WorkflowStepFailure,
) -> Result<WorkflowStepFailureOutcome> {
    fail_workflow_step_inner(transaction, failure, true, true).await
}

async fn fail_workflow_step_inner(
    transaction: &mut Transaction<'_, Postgres>,
    failure: &WorkflowStepFailure,
    claim_was_prelocked_live: bool,
    force_terminal: bool,
) -> Result<WorkflowStepFailureOutcome> {
    failure.validate()?;
    let error_summary = summarize_error(&failure.error_summary);
    let job = lock_step_job(transaction, &failure.fence).await?;
    require_step_binding(&job, &failure.fence)?;
    let job_type: String = required_column(&job, "job_type", "workflow job type")?;
    let error_digest = sha256_digest(failure.error_summary.as_bytes());

    if let Some(outcome) = repeated_failure_outcome(&job, failure, &error_summary)? {
        if outcome.disposition == WorkflowStepFailureDisposition::Escalated {
            verify_dead_letter_exists(
                transaction,
                failure,
                outcome.dead_letter_escalation_id.ok_or_else(|| {
                    Error::Persistence("dead job has no effective escalation identity".into())
                })?,
                &job_type,
                &error_digest,
            )
            .await?;
        }
        return Ok(outcome);
    }
    if claim_was_prelocked_live {
        require_owned_claim(&job, &failure.fence)?;
    } else {
        require_live_claim(&job, &failure.fence)?;
    }

    let attempt_count: i32 = required_column(&job, "attempt_count", "job attempt count")?;
    let max_attempts: i32 = required_column(&job, "max_attempts", "job maximum attempts")?;
    let is_terminal = force_terminal || attempt_count >= max_attempts;

    let mut effective_escalation_id = None;
    let mut dead_letter_result = None;
    if is_terminal {
        lock_step_aggregates(transaction, &failure.fence).await?;
        let attempt_id: Option<Uuid> =
            optional_column(&job, "attempt_id", "dead-letter job attempt")?;
        let mutation = insert_dead_letter_escalation(
            transaction,
            failure,
            attempt_id,
            &job_type,
            &error_digest,
        )
        .await?;
        let escalation = &mutation.after.record;
        let escalation_fact = dead_letter_escalation_fact(&mutation.after);
        let mutation_fact = dead_letter_mutation_fact(&mutation);
        let audit = effective_dead_letter_audit(
            failure,
            &mutation,
            &escalation_fact,
            &mutation_fact,
            &job_type,
            &error_digest,
        )?;
        let outbox = effective_dead_letter_outbox(
            failure,
            &mutation,
            &escalation_fact,
            &mutation_fact,
            &job_type,
            &error_digest,
        )?;
        insert_outbox_message(transaction, failure.fence.tenant_id, &outbox).await?;
        insert_audit_event(transaction, &failure.fence, &audit).await?;
        update_work_item(transaction, &failure.fence, "ESCALATED").await?;
        let workflow_cursor = current_workflow_cursor(transaction, &failure.fence).await?;
        update_workflow(transaction, &failure.fence, "WAITING", workflow_cursor).await?;
        replace_accountability(
            transaction,
            &failure.fence,
            &AccountabilityReplacement {
                kind: LedgerAccountabilityKind::Escalation,
                reference_id: escalation.id,
                wake_or_deadline_at: Some(escalation.deadline),
                authority_or_effect_active: escalation.authority_or_effect_active,
            },
        )
        .await?;
        effective_escalation_id = Some(escalation.id);
        dead_letter_result = Some(json!({
            "schema": "asf.workflow-job-dead-letter-result/v1",
            "workflow_job_id": failure.fence.job_id,
            "job_type": job_type,
            "error_digest": error_digest,
            "disposition": mutation.disposition.as_str(),
            "escalation": escalation_fact,
            "escalation_mutation": mutation_fact,
            "audit_event_id": audit.id,
            "outbox_id": outbox.id,
        }));
    }

    let updated = sqlx::query(FAIL_STEP_JOB_SQL)
        .bind(failure.fence.tenant_id)
        .bind(failure.fence.job_id)
        .bind(&failure.fence.lease_owner)
        .bind(failure.fence.job_fence_token)
        .bind(&error_summary)
        .bind(failure.retry_at)
        .bind(effective_escalation_id.unwrap_or(failure.dead_letter.id))
        .bind(&dead_letter_result)
        .bind(force_terminal)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("fail fenced workflow step", error))?
        .ok_or_else(|| stale_step_error(failure.fence.job_id))?;
    let status: String = required_column(&updated, "status", "failed job status")?;
    let disposition = match status.as_str() {
        "RETRY" if !is_terminal => WorkflowStepFailureDisposition::RetryScheduled,
        "DEAD" if is_terminal => WorkflowStepFailureDisposition::Escalated,
        _ => {
            return Err(Error::Persistence(format!(
                "workflow job {} returned inconsistent failure status {status}",
                failure.fence.job_id
            )));
        }
    };

    Ok(WorkflowStepFailureOutcome {
        disposition,
        newly_recorded: true,
        dead_letter_escalation_id: effective_escalation_id,
    })
}

async fn lock_step_job(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
) -> Result<PgRow> {
    sqlx::query(LOCK_STEP_JOB_SQL)
        .bind(fence.tenant_id)
        .bind(fence.job_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock workflow-step job", error))?
        .ok_or_else(|| Error::NotFound(format!("workflow job {}", fence.job_id)))
}

async fn lock_step_aggregates(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
) -> Result<()> {
    let work_exists = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM work_items AS work
        WHERE work.tenant_id = $1
          AND work.id = $2
          AND work.aggregate_version = $3
        FOR UPDATE OF work
        ",
    )
    .bind(fence.tenant_id)
    .bind(fence.work_item_id)
    .bind(fence.expected_work_item_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock workflow-step work item", error))?
    .is_some();
    if !work_exists {
        return Err(Error::Conflict(format!(
            "work item {} aggregate version is stale",
            fence.work_item_id
        )));
    }

    let workflow_exists = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM workflow_instances AS workflow
        WHERE workflow.tenant_id = $1
          AND workflow.id = $2
          AND workflow.work_item_id = $3
          AND workflow.aggregate_version = $4
          AND workflow.fence_token = $5
        FOR UPDATE OF workflow
        ",
    )
    .bind(fence.tenant_id)
    .bind(fence.workflow_instance_id)
    .bind(fence.work_item_id)
    .bind(fence.expected_workflow_version)
    .bind(fence.expected_workflow_fence_token)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock workflow-step instance", error))?
    .is_some();
    if !workflow_exists {
        return Err(Error::Conflict(format!(
            "workflow {} aggregate version or fence is stale",
            fence.workflow_instance_id
        )));
    }
    Ok(())
}

fn require_live_claim(job: &PgRow, fence: &WorkflowStepFence) -> Result<()> {
    require_owned_claim(job, fence)?;
    let lease_is_live: bool = required_column(job, "lease_is_live", "workflow job live lease")?;
    if !lease_is_live {
        return Err(stale_step_error(fence.job_id));
    }
    Ok(())
}

fn require_owned_claim(job: &PgRow, fence: &WorkflowStepFence) -> Result<()> {
    let status: String = required_column(job, "status", "workflow job status")?;
    let owner: Option<String> = optional_column(job, "lease_owner", "workflow job owner")?;
    let token: i64 = required_column(job, "fence_token", "workflow job fence")?;

    if status != "RUNNING"
        || owner.as_deref() != Some(fence.lease_owner.as_str())
        || token != fence.job_fence_token
    {
        return Err(stale_step_error(fence.job_id));
    }
    Ok(())
}

fn require_step_binding(job: &PgRow, fence: &WorkflowStepFence) -> Result<()> {
    let workflow_id: Option<Uuid> =
        optional_column(job, "workflow_instance_id", "workflow job instance")?;
    let work_item_id: Option<Uuid> =
        optional_column(job, "work_item_id", "workflow job work item")?;
    if workflow_id == Some(fence.workflow_instance_id) && work_item_id == Some(fence.work_item_id) {
        Ok(())
    } else {
        Err(stale_step_error(fence.job_id))
    }
}

fn completed_step_matches(
    job: &PgRow,
    fence: &WorkflowStepFence,
    stored_result: &Value,
) -> Result<bool> {
    let status: String = required_column(job, "status", "workflow job status")?;
    if status != "COMPLETED" {
        return Ok(false);
    }
    let completed_by: Option<String> =
        optional_column(job, "completed_by", "workflow job completer")?;
    let completion_fence: Option<i64> = optional_column(
        job,
        "completion_fence_token",
        "workflow job completion fence",
    )?;
    let result: Option<Value> = optional_column(job, "result", "workflow job result")?;
    if completed_by.as_deref() == Some(fence.lease_owner.as_str())
        && completion_fence == Some(fence.job_fence_token)
    {
        if result.as_ref() == Some(stored_result) {
            return Ok(true);
        }
        return Err(Error::Conflict(format!(
            "workflow job {} was completed with a different semantic commit",
            fence.job_id
        )));
    }
    Err(stale_step_error(fence.job_id))
}

async fn update_work_item(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    state: &str,
) -> Result<i64> {
    let row = sqlx::query(UPDATE_WORK_ITEM_SQL)
        .bind(fence.tenant_id)
        .bind(fence.work_item_id)
        .bind(fence.expected_work_item_version)
        .bind(state)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("advance workflow-step work item", error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "work item {} aggregate version is stale",
                fence.work_item_id
            ))
        })?;
    required_column(&row, "aggregate_version", "advanced work item version")
}

async fn update_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    state: &str,
    event_cursor: i64,
) -> Result<(i64, i64)> {
    let row = sqlx::query(UPDATE_WORKFLOW_SQL)
        .bind(fence.tenant_id)
        .bind(fence.workflow_instance_id)
        .bind(fence.work_item_id)
        .bind(fence.expected_workflow_version)
        .bind(fence.expected_workflow_fence_token)
        .bind(state)
        .bind(event_cursor)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("advance workflow-step instance", error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "workflow {} aggregate version or fence is stale",
                fence.workflow_instance_id
            ))
        })?;
    Ok((
        required_column(&row, "aggregate_version", "advanced workflow version")?,
        required_column(&row, "fence_token", "advanced workflow fence")?,
    ))
}

async fn current_workflow_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT event_cursor
        FROM workflow_instances
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND aggregate_version = $4
          AND fence_token = $5
        ",
    )
    .bind(fence.tenant_id)
    .bind(fence.workflow_instance_id)
    .bind(fence.work_item_id)
    .bind(fence.expected_workflow_version)
    .bind(fence.expected_workflow_fence_token)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("read workflow cursor for dead letter", error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "workflow {} aggregate version or fence is stale",
            fence.workflow_instance_id
        ))
    })
}

async fn replace_accountability(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    replacement: &AccountabilityReplacement,
) -> Result<i64> {
    let new_generation = fence
        .expected_anchor_generation
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("accountability generation overflowed".into()))?;
    let row = sqlx::query(REPLACE_ACCOUNTABILITY_SQL)
        .bind(fence.tenant_id)
        .bind(fence.work_item_id)
        .bind(replacement.kind.as_sql())
        .bind(replacement.reference_id)
        .bind(replacement.wake_or_deadline_at)
        .bind(replacement.authority_or_effect_active)
        .bind(fence.expected_anchor_generation)
        .bind(new_generation)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("replace accountability anchor", error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "work item {} accountability generation is stale",
                fence.work_item_id
            ))
        })?;
    required_column(&row, "generation", "accountability generation")
}

async fn insert_workflow_job(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    job: &StepWorkflowJob,
) -> Result<()> {
    let row = sqlx::query(INSERT_STEP_JOB_SQL)
        .bind(job.id)
        .bind(fence.tenant_id)
        .bind(fence.workflow_instance_id)
        .bind(fence.work_item_id)
        .bind(job.attempt_id)
        .bind(&job.job_type)
        .bind(&job.activity_contract_id)
        .bind(&job.payload)
        .bind(&job.idempotency_key)
        .bind(job.priority)
        .bind(job.available_at)
        .bind(job.max_attempts)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("insert workflow-step job", error))?;
    if row.is_none() {
        return Err(idempotency_conflict("workflow job", &job.idempotency_key));
    }
    Ok(())
}

async fn insert_workflow_timer(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    timer: &StepWorkflowTimer,
) -> Result<()> {
    let row = sqlx::query(INSERT_STEP_TIMER_SQL)
        .bind(timer.id)
        .bind(fence.tenant_id)
        .bind(fence.workflow_instance_id)
        .bind(fence.work_item_id)
        .bind(timer.attempt_id)
        .bind(&timer.workflow_key)
        .bind(&timer.timer_key)
        .bind(&timer.timer_type)
        .bind(&timer.activity_contract_id)
        .bind(timer.due_at)
        .bind(&timer.payload)
        .bind(timer.generation)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("insert workflow-step timer", error))?;
    if row.is_none() {
        return Err(idempotency_conflict(
            "workflow timer",
            &format!("{}:{}", timer.workflow_key, timer.timer_key),
        ));
    }
    Ok(())
}

async fn insert_effect_intent(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    effect: &StepEffectIntent,
) -> Result<()> {
    let row = sqlx::query(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            idempotency_key, correlation_marker, request_digest,
            request_payload, work_order_id, work_order_digest, next_attempt_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
        SET id = effect_intents.id
        WHERE effect_intents.id = EXCLUDED.id
          AND effect_intents.work_item_id = EXCLUDED.work_item_id
          AND effect_intents.attempt_id IS NOT DISTINCT FROM EXCLUDED.attempt_id
          AND effect_intents.provider = EXCLUDED.provider
          AND effect_intents.effect_type = EXCLUDED.effect_type
          AND effect_intents.correlation_marker IS NOT DISTINCT FROM EXCLUDED.correlation_marker
          AND effect_intents.request_digest = EXCLUDED.request_digest
          AND effect_intents.request_payload = EXCLUDED.request_payload
          AND effect_intents.work_order_id IS NOT DISTINCT FROM EXCLUDED.work_order_id
          AND effect_intents.work_order_digest IS NOT DISTINCT FROM EXCLUDED.work_order_digest
          AND effect_intents.next_attempt_at = EXCLUDED.next_attempt_at
        RETURNING effect_intents.id
        ",
    )
    .bind(effect.id)
    .bind(fence.tenant_id)
    .bind(fence.work_item_id)
    .bind(effect.attempt_id)
    .bind(&effect.provider)
    .bind(&effect.effect_type)
    .bind(&effect.idempotency_key)
    .bind(&effect.correlation_marker)
    .bind(&effect.request_digest)
    .bind(&effect.request_payload)
    .bind(
        effect
            .runmill_submission
            .as_ref()
            .map(|binding| binding.work_order_id),
    )
    .bind(
        effect
            .runmill_submission
            .as_ref()
            .map(|binding| binding.work_order_digest.as_str()),
    )
    .bind(effect.next_attempt_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert workflow-step effect intent", error))?;
    if row.is_none() {
        return Err(idempotency_conflict(
            "effect intent",
            &effect.idempotency_key,
        ));
    }
    Ok(())
}

async fn insert_outbox_message(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    message: &StepOutboxMessage,
) -> Result<()> {
    let row = sqlx::query(
        r"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload, headers,
            idempotency_key, available_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
        SET id = outbox.id
        WHERE outbox.id = EXCLUDED.id
          AND outbox.topic = EXCLUDED.topic
          AND outbox.message_key = EXCLUDED.message_key
          AND outbox.event_type = EXCLUDED.event_type
          AND outbox.payload = EXCLUDED.payload
          AND outbox.headers = EXCLUDED.headers
          AND outbox.available_at = EXCLUDED.available_at
        RETURNING outbox.id
        ",
    )
    .bind(message.id)
    .bind(tenant_id)
    .bind(&message.topic)
    .bind(&message.message_key)
    .bind(&message.event_type)
    .bind(&message.payload)
    .bind(&message.headers)
    .bind(&message.idempotency_key)
    .bind(message.available_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert workflow-step outbox message", error))?;
    if row.is_none() {
        return Err(idempotency_conflict(
            "outbox message",
            &message.idempotency_key,
        ));
    }
    Ok(())
}

async fn insert_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    audit: &StepAuditEvent,
) -> Result<()> {
    sqlx::query(LOCK_AUDIT_CHAIN_SQL)
        .bind(fence.tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock tenant audit chain", error))?;
    let previous_event_hash = sqlx::query_scalar::<_, String>(LOAD_AUDIT_CHAIN_HEAD_SQL)
        .bind(fence.tenant_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("load workflow-step audit-chain head", error))?;
    let event = canonical_step_audit_event(fence, audit, previous_event_hash)?;
    event.verify()?;

    let inserted = sqlx::query(
        r"
        INSERT INTO audit_events (
            id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
            action, subject_type, subject_id, correlation_id, trace_id,
            policy_digest, before_digest, after_digest, previous_event_hash,
            event_hash, details, occurred_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18
        )
        ON CONFLICT (tenant_id, event_hash) DO NOTHING
        RETURNING id
        ",
    )
    .bind(event.content.id.as_uuid())
    .bind(fence.tenant_id)
    .bind(fence.work_item_id)
    .bind(event.content.attempt_id.map(AttemptId::as_uuid))
    .bind(&event.content.actor_type)
    .bind(&event.content.actor_id)
    .bind(&event.content.action)
    .bind(&event.content.subject_type)
    .bind(&event.content.subject_id)
    .bind(&event.content.correlation_id)
    .bind(&event.content.trace_id)
    .bind(&event.content.policy_digest)
    .bind(&event.content.before_digest)
    .bind(&event.content.after_digest)
    .bind(&event.content.previous_event_hash)
    .bind(&event.event_hash)
    .bind(&event.content.details)
    .bind(event.content.occurred_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert workflow-step audit event", error))?;
    if inserted.is_some() {
        Ok(())
    } else {
        Err(idempotency_conflict("audit event", &event.event_hash))
    }
}

fn canonical_step_audit_event(
    fence: &WorkflowStepFence,
    audit: &StepAuditEvent,
    previous_event_hash: Option<String>,
) -> Result<HashedAuditEvent> {
    HashedAuditEvent::create(AuditEventContent {
        id: EventId::from_uuid(audit.id),
        tenant_id: TenantId::from_uuid(fence.tenant_id),
        work_item_id: Some(WorkItemId::from_uuid(fence.work_item_id)),
        attempt_id: audit.attempt_id.map(AttemptId::from_uuid),
        actor_type: audit.actor_type.clone(),
        actor_id: audit.actor_id.clone(),
        action: audit.action.clone(),
        subject_type: audit.subject_type.clone(),
        subject_id: audit.subject_id.clone(),
        correlation_id: audit.correlation_id.clone(),
        trace_id: audit.trace_id.clone(),
        policy_digest: audit.policy_digest.clone(),
        before_digest: audit.before_digest.clone(),
        after_digest: audit.after_digest.clone(),
        previous_event_hash,
        details: audit.details.clone(),
        occurred_at: audit.occurred_at,
    })
}

#[derive(Debug, Clone)]
struct EffectiveDeadLetterEscalation {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Option<Uuid>,
    status: String,
    aggregate_version: i64,
    acknowledged_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    record: DeadLetterEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadLetterMutationDisposition {
    Opened,
    AdoptedActive,
}

impl DeadLetterMutationDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "OPENED",
            Self::AdoptedActive => "ADOPTED_ACTIVE",
        }
    }
}

#[derive(Debug, Clone)]
struct DeadLetterMutation {
    disposition: DeadLetterMutationDisposition,
    before: Option<EffectiveDeadLetterEscalation>,
    after: EffectiveDeadLetterEscalation,
}

async fn insert_dead_letter_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    failure: &WorkflowStepFailure,
    attempt_id: Option<Uuid>,
    job_type: &str,
    error_digest: &str,
) -> Result<DeadLetterMutation> {
    let (escalation, reason_fact, action_fact) = normalized_dead_letter(
        &failure.dead_letter,
        failure.fence.job_id,
        job_type,
        error_digest,
    )?;

    if let Some(row) = load_active_dead_letter(
        transaction,
        failure.fence.tenant_id,
        failure.fence.work_item_id,
        attempt_id,
        &escalation.category,
    )
    .await?
    {
        let before = effective_dead_letter_from_row(&row, escalation.clone())?;
        let after = merge_active_dead_letter(
            transaction,
            &before,
            &escalation,
            &reason_fact,
            &action_fact,
        )
        .await?;
        return Ok(DeadLetterMutation {
            disposition: DeadLetterMutationDisposition::AdoptedActive,
            before: Some(before),
            after,
        });
    }

    let inserted = sqlx::query(INSERT_ESCALATION_SQL)
        .bind(escalation.id)
        .bind(failure.fence.tenant_id)
        .bind(failure.fence.work_item_id)
        .bind(attempt_id)
        .bind(escalation.run_id)
        .bind(&escalation.category)
        .bind(&escalation.severity)
        .bind(&escalation.reason)
        .bind(&escalation.owner_type)
        .bind(&escalation.owner_id)
        .bind(&escalation.required_action)
        .bind(&escalation.evidence_references)
        .bind(escalation.deadline)
        .bind(&escalation.escalation_path)
        .bind(&escalation.retry_policy)
        .bind(&escalation.prerequisites)
        .bind(escalation.authority_or_effect_active)
        .bind(&escalation.idempotency_key)
        .bind(escalation.opened_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("insert workflow dead-letter escalation", error))?;
    if let Some(row) = inserted {
        return Ok(DeadLetterMutation {
            disposition: DeadLetterMutationDisposition::Opened,
            before: None,
            after: effective_dead_letter_from_row(&row, escalation)?,
        });
    }

    // A concurrent insert can win after the first lookup. ON CONFLICT waits
    // without aborting this transaction; this new statement snapshot can then
    // lock and conservatively merge that committed owner.
    let row = load_active_dead_letter(
        transaction,
        failure.fence.tenant_id,
        failure.fence.work_item_id,
        attempt_id,
        &escalation.category,
    )
    .await?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "active exhaustion escalation for workflow job {} changed during adoption",
            failure.fence.job_id
        ))
    })?;
    let before = effective_dead_letter_from_row(&row, escalation.clone())?;
    let after = merge_active_dead_letter(
        transaction,
        &before,
        &escalation,
        &reason_fact,
        &action_fact,
    )
    .await?;
    Ok(DeadLetterMutation {
        disposition: DeadLetterMutationDisposition::AdoptedActive,
        before: Some(before),
        after,
    })
}

async fn load_active_dead_letter(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Option<Uuid>,
    category: &str,
) -> Result<Option<PgRow>> {
    sqlx::query(LOAD_ACTIVE_ESCALATION_SQL)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(category)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock active workflow dead-letter escalation", error))
}

async fn merge_active_dead_letter(
    transaction: &mut Transaction<'_, Postgres>,
    before: &EffectiveDeadLetterEscalation,
    proposed: &DeadLetterEscalation,
    reason_fact: &str,
    action_fact: &str,
) -> Result<EffectiveDeadLetterEscalation> {
    let row = sqlx::query(MERGE_ACTIVE_ESCALATION_SQL)
        .bind(before.tenant_id)
        .bind(before.record.id)
        .bind(&proposed.severity)
        .bind(reason_fact)
        .bind(action_fact)
        .bind(&proposed.evidence_references)
        .bind(proposed.deadline)
        .bind(&proposed.retry_policy)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("merge active workflow dead-letter escalation", error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "active exhaustion escalation {} advanced during adoption",
                before.record.id
            ))
        })?;
    effective_dead_letter_from_row(&row, proposed.clone())
}

fn normalized_dead_letter(
    proposed: &DeadLetterEscalation,
    job_id: Uuid,
    job_type: &str,
    error_digest: &str,
) -> Result<(DeadLetterEscalation, String, String)> {
    validate_digest(error_digest, "workflow-job error digest")?;
    let marker = format!("[workflow-job:{job_id}]");
    let reason_fact =
        format!("{marker} activity {job_type} exhausted with error digest {error_digest}.");
    let action_fact = format!(
        "{marker} reconcile activity {job_type} and error digest {error_digest} before explicit retry, replacement, or cancellation."
    );
    let mut escalation = proposed.clone();
    if !escalation.reason.contains(&marker) {
        escalation.reason = format!("{}\n{reason_fact}", escalation.reason);
    }
    if !escalation.required_action.contains(&marker) {
        escalation.required_action = format!("{}\n{action_fact}", escalation.required_action);
    }
    let evidence = escalation
        .evidence_references
        .as_array_mut()
        .ok_or_else(|| Error::Validation("dead-letter evidence must be an array".into()))?;
    let exact_evidence = [
        format!("workflow-job:{job_id}"),
        format!("workflow-job-type:{job_id}:{job_type}"),
        format!("workflow-job-error:{job_id}:{error_digest}"),
    ];
    for reference in exact_evidence {
        if !evidence
            .iter()
            .any(|existing| existing.as_str() == Some(reference.as_str()))
        {
            evidence.push(Value::String(reference));
        }
    }
    if evidence.iter().any(|reference| {
        reference
            .as_str()
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return Err(Error::Validation(
            "dead-letter evidence references must be non-empty strings".into(),
        ));
    }
    let retry_prerequisites = escalation
        .retry_policy
        .get("prerequisites")
        .filter(|value| value.is_array())
        .cloned()
        .unwrap_or_else(|| json!([]));
    escalation.retry_policy = json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 0,
        "prerequisites": retry_prerequisites,
    });
    escalation.severity = if escalation.severity == "CRITICAL" {
        "CRITICAL".into()
    } else {
        "HIGH".into()
    };
    escalation.authority_or_effect_active = true;
    Ok((escalation, reason_fact, action_fact))
}

fn effective_dead_letter_from_row(
    row: &PgRow,
    mut escalation: DeadLetterEscalation,
) -> Result<EffectiveDeadLetterEscalation> {
    let tenant_id = required_column(row, "tenant_id", "effective escalation tenant")?;
    let work_item_id = required_column(row, "work_item_id", "effective escalation work item")?;
    let attempt_id = optional_column(row, "attempt_id", "effective escalation attempt")?;
    escalation.id = required_column(row, "id", "effective escalation ID")?;
    escalation.run_id = optional_column(row, "run_id", "effective escalation run")?;
    escalation.category = required_column(row, "category", "effective escalation category")?;
    escalation.severity = required_column(row, "severity", "effective escalation severity")?;
    escalation.reason = required_column(row, "reason", "effective escalation reason")?;
    escalation.owner_type = required_column(row, "owner_type", "effective escalation owner type")?;
    escalation.owner_id = required_column(row, "owner_id", "effective escalation owner")?;
    escalation.required_action =
        required_column(row, "required_action", "effective escalation action")?;
    escalation.evidence_references =
        required_column(row, "evidence_references", "effective escalation evidence")?;
    escalation.deadline = required_column(row, "deadline", "effective escalation deadline")?;
    escalation.escalation_path =
        required_column(row, "escalation_path", "effective escalation path")?;
    escalation.retry_policy =
        required_column(row, "retry_policy", "effective escalation retry policy")?;
    escalation.prerequisites =
        required_column(row, "prerequisites", "effective escalation prerequisites")?;
    escalation.authority_or_effect_active = required_column(
        row,
        "authority_or_effect_active",
        "effective escalation authority state",
    )?;
    escalation.idempotency_key = required_column(
        row,
        "idempotency_key",
        "effective escalation idempotency key",
    )?;
    escalation.opened_at = required_column(row, "opened_at", "effective escalation opening")?;
    Ok(EffectiveDeadLetterEscalation {
        tenant_id,
        work_item_id,
        attempt_id,
        status: required_column(row, "status", "effective escalation status")?,
        aggregate_version: required_column(
            row,
            "aggregate_version",
            "effective escalation version",
        )?,
        acknowledged_at: optional_column(
            row,
            "acknowledged_at",
            "effective escalation acknowledgement",
        )?,
        closed_at: optional_column(row, "closed_at", "effective escalation closure")?,
        record: escalation,
    })
}

fn dead_letter_escalation_fact(escalation: &EffectiveDeadLetterEscalation) -> Value {
    let record = &escalation.record;
    json!({
        "tenant_id": escalation.tenant_id,
        "work_item_id": escalation.work_item_id,
        "attempt_id": escalation.attempt_id,
        "id": record.id,
        "run_id": record.run_id,
        "category": record.category,
        "status": escalation.status,
        "severity": record.severity,
        "reason": record.reason,
        "owner_type": record.owner_type,
        "owner_id": record.owner_id,
        "required_action": record.required_action,
        "evidence_references": record.evidence_references,
        "deadline": record.deadline,
        "escalation_path": record.escalation_path,
        "retry_policy": record.retry_policy,
        "prerequisites": record.prerequisites,
        "authority_or_effect_active": record.authority_or_effect_active,
        "idempotency_key": record.idempotency_key,
        "aggregate_version": escalation.aggregate_version,
        "opened_at": record.opened_at,
        "acknowledged_at": escalation.acknowledged_at,
        "closed_at": escalation.closed_at,
    })
}

fn dead_letter_mutation_fact(mutation: &DeadLetterMutation) -> Value {
    json!({
        "disposition": mutation.disposition.as_str(),
        "before": mutation.before.as_ref().map(dead_letter_escalation_fact),
        "after": dead_letter_escalation_fact(&mutation.after),
    })
}

fn effective_dead_letter_audit(
    failure: &WorkflowStepFailure,
    mutation: &DeadLetterMutation,
    escalation_fact: &Value,
    mutation_fact: &Value,
    job_type: &str,
    error_digest: &str,
) -> Result<StepAuditEvent> {
    let escalation = &mutation.after.record;
    let mut audit = failure.dead_letter.audit_event.clone();
    let details = audit.details.as_object_mut().ok_or_else(|| {
        Error::Validation("dead-letter audit details must be a JSON object".into())
    })?;
    details.insert(
        "workflow_job_id".into(),
        Value::String(failure.fence.job_id.to_string()),
    );
    details.insert("job_type".into(), Value::String(job_type.into()));
    details.insert("error_digest".into(), Value::String(error_digest.into()));
    details.insert(
        "escalation_id".into(),
        Value::String(escalation.id.to_string()),
    );
    details.insert("escalation".into(), escalation_fact.clone());
    details.insert("escalation_mutation".into(), mutation_fact.clone());
    details.insert("deadline".into(), json!(escalation.deadline));
    details.insert(
        "owner_type".into(),
        Value::String(escalation.owner_type.clone()),
    );
    details.insert(
        "owner_id".into(),
        Value::String(escalation.owner_id.clone()),
    );
    details.insert(
        "required_action".into(),
        Value::String(escalation.required_action.clone()),
    );
    audit.subject_type = "WORKFLOW_JOB".into();
    audit.subject_id = failure.fence.job_id.to_string();
    audit.before_digest = mutation
        .before
        .as_ref()
        .map(dead_letter_escalation_fact)
        .map(|fact| canonical_json(&fact).map(|bytes| sha256_digest(&bytes)))
        .transpose()?;
    audit.after_digest = Some(sha256_digest(&canonical_json(escalation_fact)?));
    validate_audit(&audit)?;
    Ok(audit)
}

fn effective_dead_letter_outbox(
    failure: &WorkflowStepFailure,
    mutation: &DeadLetterMutation,
    escalation_fact: &Value,
    mutation_fact: &Value,
    job_type: &str,
    error_digest: &str,
) -> Result<StepOutboxMessage> {
    let escalation = &mutation.after.record;
    let mut outbox = failure.dead_letter.outbox_message.clone();
    let payload = outbox.payload.as_object_mut().ok_or_else(|| {
        Error::Validation("dead-letter outbox payload must be a JSON object".into())
    })?;
    payload.insert(
        "work_item_id".into(),
        Value::String(failure.fence.work_item_id.to_string()),
    );
    payload.insert(
        "workflow_job_id".into(),
        Value::String(failure.fence.job_id.to_string()),
    );
    payload.insert("job_type".into(), Value::String(job_type.into()));
    payload.insert("error_digest".into(), Value::String(error_digest.into()));
    payload.insert(
        "escalation_id".into(),
        Value::String(escalation.id.to_string()),
    );
    payload.insert("escalation".into(), escalation_fact.clone());
    payload.insert("escalation_mutation".into(), mutation_fact.clone());
    payload.insert(
        "category".into(),
        Value::String(escalation.category.clone()),
    );
    payload.insert(
        "severity".into(),
        Value::String(escalation.severity.clone()),
    );
    payload.insert(
        "status".into(),
        Value::String(mutation.after.status.clone()),
    );
    payload.insert("deadline".into(), json!(escalation.deadline));
    payload.insert(
        "owner_type".into(),
        Value::String(escalation.owner_type.clone()),
    );
    payload.insert(
        "owner_id".into(),
        Value::String(escalation.owner_id.clone()),
    );
    payload.insert(
        "required_action".into(),
        Value::String(escalation.required_action.clone()),
    );
    payload.insert(
        "evidence_references".into(),
        escalation.evidence_references.clone(),
    );
    validate_outbox(&outbox)?;
    Ok(outbox)
}

async fn verify_dead_letter_exists(
    transaction: &mut Transaction<'_, Postgres>,
    failure: &WorkflowStepFailure,
    escalation_id: Uuid,
    job_type: &str,
    error_digest: &str,
) -> Result<()> {
    let matches = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM workflow_jobs AS job
            JOIN escalations AS escalation
              ON escalation.tenant_id = job.tenant_id
             AND escalation.id = job.dead_letter_escalation_id
             AND escalation.work_item_id = job.work_item_id
             AND escalation.attempt_id IS NOT DISTINCT FROM job.attempt_id
            JOIN audit_events AS audit
              ON audit.tenant_id = job.tenant_id
             AND audit.id::text = job.result ->> 'audit_event_id'
             AND audit.subject_type = 'WORKFLOW_JOB'
             AND audit.subject_id = job.id::text
             AND audit.action = 'WORKFLOW_JOB_EXHAUSTED'
            JOIN outbox
              ON outbox.tenant_id = job.tenant_id
             AND outbox.id::text = job.result ->> 'outbox_id'
             AND outbox.event_type = 'workflow_job.exhausted'
            WHERE job.tenant_id = $1
              AND job.id = $2
              AND job.status = 'DEAD'
              AND escalation.id = $3
              AND escalation.work_item_id = $4
              AND job.result ->> 'workflow_job_id' = job.id::text
              AND job.result ->> 'job_type' = $5
              AND job.result ->> 'error_digest' = $6
              AND job.result #>> '{escalation,id}' = escalation.id::text
              AND audit.details ->> 'workflow_job_id' = job.id::text
              AND audit.details ->> 'job_type' = $5
              AND audit.details ->> 'error_digest' = $6
              AND audit.details ->> 'escalation_id' = escalation.id::text
              AND audit.details -> 'escalation' = job.result -> 'escalation'
              AND audit.details -> 'escalation_mutation'
                    = job.result -> 'escalation_mutation'
              AND outbox.payload ->> 'workflow_job_id' = job.id::text
              AND outbox.payload ->> 'job_type' = $5
              AND outbox.payload ->> 'error_digest' = $6
              AND outbox.payload ->> 'escalation_id' = escalation.id::text
              AND outbox.payload -> 'escalation' = job.result -> 'escalation'
              AND outbox.payload -> 'escalation_mutation'
                    = job.result -> 'escalation_mutation'
        )
        ",
    )
    .bind(failure.fence.tenant_id)
    .bind(failure.fence.job_id)
    .bind(escalation_id)
    .bind(failure.fence.work_item_id)
    .bind(job_type)
    .bind(error_digest)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("verify workflow dead-letter anchor", error))?;
    if matches {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "dead workflow job {} has no matching owned escalation anchor",
            failure.fence.job_id
        )))
    }
}

fn repeated_failure_outcome(
    job: &PgRow,
    failure: &WorkflowStepFailure,
    error_summary: &str,
) -> Result<Option<WorkflowStepFailureOutcome>> {
    let status: String = required_column(job, "status", "workflow job status")?;
    if status != "RETRY" && status != "DEAD" {
        return Ok(None);
    }
    let failed_by: Option<String> =
        optional_column(job, "last_failure_by", "workflow job failure owner")?;
    let failure_fence: Option<i64> = optional_column(
        job,
        "last_failure_fence_token",
        "workflow job failure fence",
    )?;
    let retry_at: Option<DateTime<Utc>> = optional_column(
        job,
        "last_failure_retry_at",
        "workflow job failure retry time",
    )?;
    let stored_error: Option<String> =
        optional_column(job, "last_error", "workflow job failure summary")?;
    let dead_letter_id: Option<Uuid> = optional_column(
        job,
        "dead_letter_escalation_id",
        "workflow job dead-letter escalation",
    )?;
    if failed_by.as_deref() != Some(failure.fence.lease_owner.as_str())
        || failure_fence != Some(failure.fence.job_fence_token)
    {
        return Err(stale_step_error(failure.fence.job_id));
    }
    if retry_at != Some(failure.retry_at) || stored_error.as_deref() != Some(error_summary) {
        return Err(Error::Conflict(format!(
            "workflow job {} failure was retried with different details",
            failure.fence.job_id
        )));
    }
    if status == "DEAD" && dead_letter_id.is_none() {
        return Err(Error::Persistence(format!(
            "workflow job {} is DEAD without a linked escalation",
            failure.fence.job_id
        )));
    }
    Ok(Some(WorkflowStepFailureOutcome {
        disposition: if status == "DEAD" {
            WorkflowStepFailureDisposition::Escalated
        } else {
            WorkflowStepFailureDisposition::RetryScheduled
        },
        newly_recorded: false,
        dead_letter_escalation_id: dead_letter_id,
    }))
}

fn validate_job(job: &StepWorkflowJob) -> Result<()> {
    if job.id.is_nil()
        || job.attempt_id.is_some_and(|id| id.is_nil())
        || job.job_type.trim().is_empty()
        || job.idempotency_key.trim().is_empty()
        || !job.payload.is_object()
        || job.max_attempts <= 0
    {
        return Err(Error::Validation(
            "workflow-step child job is invalid".into(),
        ));
    }
    if !is_valid_activity_contract_id(&job.activity_contract_id) {
        return Err(Error::Validation(format!(
            "workflow-step child job activity contract id {:?} is invalid",
            job.activity_contract_id
        )));
    }
    Ok(())
}

fn validate_timer(timer: &StepWorkflowTimer) -> Result<()> {
    if timer.id.is_nil()
        || timer.attempt_id.is_some_and(|id| id.is_nil())
        || timer.workflow_key.trim().is_empty()
        || timer.timer_key.trim().is_empty()
        || timer.timer_type.trim().is_empty()
        || !timer.payload.is_object()
        || timer.generation <= 0
    {
        return Err(Error::Validation("workflow-step timer is invalid".into()));
    }
    if !is_valid_activity_contract_id(&timer.activity_contract_id) {
        return Err(Error::Validation(format!(
            "workflow-step timer activity contract id {:?} is invalid",
            timer.activity_contract_id
        )));
    }
    Ok(())
}

/// Build a submission effect intent from a stored work order row.
///
/// This function reconstructs a [`StepEffectIntent`] from exact work order data
/// persisted in the database. It locks the `work_orders` row, retrieves the exact
/// signed envelope bytes, decodes them as [`RunmillSignedWorkOrderV1`], verifies
/// structural invariants (canonical bytes, ID consistency, payload digest), and
/// assembles the effect intent without any outbound dispatch.
///
/// # Arguments
/// * `transaction` - Mutable transaction for database operations
/// * `fence` - Workflow step fence with tenant, job, `work_item` IDs
/// * `effect_id` - UUID for the effect intent row
/// * `next_attempt_at` - When to retry the submission if it fails
///
/// # Returns
/// A [`StepEffectIntent`] ready to be persisted, or an error if:
/// - The workflow job has no attempt ID
/// - The work order row is not found
/// - The exact envelope fails to deserialize as [`RunmillSignedWorkOrderV1`]
/// - Canonical envelope bytes differ from stored exact bytes
/// - Work order IDs do not match the job and fence
/// - Payload digest does not match the stored value
pub async fn build_submission_effect_from_stored_work_order(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &WorkflowStepFence,
    effect_id: Uuid,
    next_attempt_at: DateTime<Utc>,
) -> Result<StepEffectIntent> {
    let job = lock_step_job(transaction, fence).await?;
    let attempt_id: Option<Uuid> = optional_column(&job, "attempt_id", "workflow job attempt")?;
    let attempt_id =
        attempt_id.ok_or_else(|| Error::Validation("workflow job has no attempt ID".into()))?;

    let work_order_row = sqlx::query(LOCK_WORK_ORDER_SQL)
        .bind(fence.tenant_id)
        .bind(fence.work_item_id)
        .bind(attempt_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock work order for effect", error))?
        .ok_or_else(|| Error::NotFound("work order not found".into()))?;

    let work_order_id: Uuid = required_column(&work_order_row, "id", "work order id")?;
    let payload_digest: String = required_column(
        &work_order_row,
        "payload_digest",
        "work order payload digest",
    )?;
    let exact_signed_envelope: Vec<u8> = required_column(
        &work_order_row,
        "exact_signed_envelope",
        "exact signed envelope",
    )?;

    let envelope: RunmillSignedWorkOrderV1 = serde_json::from_slice(&exact_signed_envelope)
        .map_err(|error| {
            Error::Validation(format!(
                "stored work order envelope is not a valid RunmillSignedWorkOrderV1: {error}"
            ))
        })?;

    let canonical_envelope = envelope.canonical_bytes()?;
    if canonical_envelope.as_slice() != exact_signed_envelope.as_slice() {
        return Err(Error::Validation(
            "work order canonical bytes differ from stored exact bytes".into(),
        ));
    }

    if envelope.payload.work_order_id != work_order_id.to_string()
        || envelope.payload.tenant_id != fence.tenant_id.to_string()
        || envelope.payload.work_item_id != fence.work_item_id.to_string()
        || envelope.payload.attempt_id != attempt_id.to_string()
    {
        return Err(Error::Validation(
            "stored work order IDs do not match workflow step fence".into(),
        ));
    }

    let computed_payload_digest = envelope.payload_digest()?;
    if computed_payload_digest != payload_digest {
        return Err(Error::Validation(
            "stored work order payload digest mismatch".into(),
        ));
    }

    let request_digest = sha256_digest(&canonical_envelope);
    let request_payload = serde_json::to_value(&envelope)
        .map_err(|error| Error::Serialization(format!("serialize work order envelope: {error}")))?;

    let idempotency_key = format!(
        "runmill:submit:{}/{}/{}",
        fence.tenant_id, work_order_id, attempt_id
    );

    let runmill_submission = RunmillSubmissionEffectBinding {
        work_order_id,
        work_order_digest: payload_digest,
    };

    Ok(StepEffectIntent {
        id: effect_id,
        attempt_id: Some(attempt_id),
        provider: "runmill".into(),
        effect_type: "submit_work_order".into(),
        idempotency_key,
        correlation_marker: None,
        request_digest,
        request_payload,
        runmill_submission: Some(runmill_submission),
        next_attempt_at,
    })
}

fn validate_effect(effect: &StepEffectIntent, tenant_id: Uuid, work_item_id: Uuid) -> Result<()> {
    if effect.id.is_nil()
        || effect.attempt_id.is_some_and(|id| id.is_nil())
        || effect.provider.trim().is_empty()
        || effect.effect_type.trim().is_empty()
        || effect.idempotency_key.trim().is_empty()
        || !effect.request_payload.is_object()
    {
        return Err(Error::Validation(
            "workflow-step effect intent is invalid".into(),
        ));
    }
    validate_digest(&effect.request_digest, "effect request digest")?;
    let is_runmill_submission =
        effect.provider == "runmill" && effect.effect_type == "submit_work_order";
    if is_runmill_submission != effect.runmill_submission.is_some() {
        return Err(Error::Validation(
            "only a Runmill submission effect must carry an immutable Work Order binding".into(),
        ));
    }
    if let Some(binding) = &effect.runmill_submission {
        if binding.work_order_id.is_nil() || effect.attempt_id.is_none() {
            return Err(Error::Validation(
                "Runmill submission effect requires a non-nil Work Order and attempt".into(),
            ));
        }
        validate_digest(
            &binding.work_order_digest,
            "Runmill submission Work Order digest",
        )?;
        let envelope: RunmillSignedWorkOrderV1 =
            serde_json::from_value(effect.request_payload.clone()).map_err(|error| {
                Error::Validation(format!(
                    "Runmill submission request is not an exact signed Work Order envelope: {error}"
                ))
            })?;
        let canonical_envelope = envelope.canonical_bytes()?;
        let attempt_id = effect.attempt_id.expect("validated as present");
        if envelope.payload.work_order_id != binding.work_order_id.to_string()
            || envelope.payload.tenant_id != tenant_id.to_string()
            || envelope.payload.work_item_id != work_item_id.to_string()
            || envelope.payload.attempt_id != attempt_id.to_string()
            || envelope.payload_digest()? != binding.work_order_digest
            || sha256_digest(&canonical_envelope) != effect.request_digest
        {
            return Err(Error::Validation(
                "Runmill submission request contradicts its immutable Work Order binding".into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_step_effect_intent(
    effect: &StepEffectIntent,
    tenant_id: Uuid,
    work_item_id: Uuid,
) -> Result<()> {
    validate_effect(effect, tenant_id, work_item_id)
}

fn validate_outbox(message: &StepOutboxMessage) -> Result<()> {
    if message.id.is_nil()
        || message.topic.trim().is_empty()
        || message.message_key.trim().is_empty()
        || message.event_type.trim().is_empty()
        || message.idempotency_key.trim().is_empty()
        || !message.headers.is_object()
    {
        return Err(Error::Validation(
            "workflow-step outbox message is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_audit(audit: &StepAuditEvent) -> Result<()> {
    if audit.id.is_nil()
        || audit.attempt_id.is_some_and(|id| id.is_nil())
        || audit.actor_type.trim().is_empty()
        || audit.actor_id.trim().is_empty()
        || audit.action.trim().is_empty()
        || audit.subject_type.trim().is_empty()
        || audit.subject_id.trim().is_empty()
        || audit.correlation_id.trim().is_empty()
        || !audit.details.is_object()
    {
        return Err(Error::Validation(
            "workflow-step audit event is invalid".into(),
        ));
    }
    for (value, label) in [
        (&audit.policy_digest, "audit policy digest"),
        (&audit.before_digest, "audit before digest"),
        (&audit.after_digest, "audit after digest"),
    ] {
        if let Some(value) = value {
            validate_digest(value, label)?;
        }
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 71
        && bytes.starts_with(b"sha256:")
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
    if valid {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "{label} must be a lowercase sha256 digest"
        )))
    }
}

fn validate_work_item_state(state: &str) -> Result<()> {
    const STATES: &[&str] = &[
        "DISCOVERED",
        "READINESS_PENDING",
        "NEEDS_SPEC",
        "READY",
        "ACCEPTED",
        "PLANNED",
        "SCHEDULED",
        "DISPATCHING",
        "RUNNING",
        "VERIFYING_OUTCOME",
        "TARGET_REACHED",
        "CLOSING_SOURCE",
        "CLOSED",
        "WAITING_DEPENDENCY",
        "WAITING_APPROVAL",
        "RETRY_SCHEDULED",
        "BLOCKED_EXTERNAL",
        "BUDGET_EXHAUSTED",
        "REFUSED",
        "QUARANTINED",
        "CANCEL_REQUESTED",
        "CANCELLED",
        "ESCALATED",
    ];
    if STATES.contains(&state) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unsupported work-item state {state}"
        )))
    }
}

fn validate_workflow_state(state: &str) -> Result<()> {
    if ["ACTIVE", "WAITING", "COMPLETED", "FAILED", "CANCELLED"].contains(&state) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unsupported workflow state {state}"
        )))
    }
}

fn validate_anchor_state_compatibility(state: &str, kind: LedgerAccountabilityKind) -> Result<()> {
    let compatible = match state {
        "CLOSED" => kind == LedgerAccountabilityKind::Closure,
        "CANCELLED" => kind == LedgerAccountabilityKind::Cancellation,
        "WAITING_APPROVAL" => kind == LedgerAccountabilityKind::Approval,
        "RETRY_SCHEDULED" => kind == LedgerAccountabilityKind::Retry,
        "ESCALATED" => kind == LedgerAccountabilityKind::Escalation,
        _ => true,
    };
    if compatible {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "work-item state {state} is incompatible with {} accountability",
            kind.as_sql()
        )))
    }
}

fn validate_escalation_category(category: &str) -> Result<()> {
    const CATEGORIES: &[&str] = &[
        "NEEDS_SPEC",
        "NEEDS_APPROVAL",
        "BLOCKED_DEPENDENCY",
        "BLOCKED_EXTERNAL",
        "IDENTITY_UNAVAILABLE",
        "WORKER_UNAVAILABLE",
        "VERIFICATION_FAILED",
        "REVIEW_BLOCKED",
        "CI_FAILED",
        "REMOTE_EFFECT_AMBIGUOUS",
        "BUDGET_EXHAUSTED",
        "PROVIDER_REFUSED",
        "POLICY_REFUSED",
        "WORKFLOW_JOB_EXHAUSTED",
        "QUARANTINED",
        "SECURITY_INCIDENT",
    ];
    if CATEGORIES.contains(&category) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unsupported escalation category {category}"
        )))
    }
}

fn validate_escalation_severity(severity: &str) -> Result<()> {
    if ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].contains(&severity) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unsupported escalation severity {severity}"
        )))
    }
}

fn validate_owner_type(owner_type: &str) -> Result<()> {
    if ["PERSON", "TEAM", "ON_CALL"].contains(&owner_type) {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unsupported escalation owner type {owner_type}"
        )))
    }
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

fn stale_step_error(job_id: Uuid) -> Error {
    Error::Conflict(format!(
        "workflow job {job_id} lease, owner, fence, or aggregate binding is stale"
    ))
}

fn idempotency_conflict(kind: &str, key: &str) -> Error {
    Error::Conflict(format!(
        "{kind} idempotency key {key} was reused for different semantics"
    ))
}

fn summarize_error(value: &str) -> String {
    value.chars().take(MAX_JOB_ERROR_CHARACTERS).collect()
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn fence() -> WorkflowStepFence {
        WorkflowStepFence {
            tenant_id: Uuid::now_v7(),
            job_id: Uuid::now_v7(),
            workflow_instance_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            lease_owner: "reactor-1".into(),
            job_fence_token: 3,
            expected_work_item_version: 7,
            expected_workflow_version: 9,
            expected_workflow_fence_token: 4,
            expected_anchor_generation: 5,
        }
    }

    #[test]
    fn step_sql_guards_every_mutation_with_tenant_and_fence() {
        for sql in [
            LOCK_STEP_JOB_SQL,
            UPDATE_WORK_ITEM_SQL,
            UPDATE_WORKFLOW_SQL,
            COMPLETE_STEP_JOB_SQL,
            FAIL_STEP_JOB_SQL,
        ] {
            assert!(
                sql.contains("tenant_id = $1"),
                "missing tenant guard: {sql}"
            );
        }
        assert!(LOCK_STEP_JOB_SQL.contains("FOR UPDATE OF job"));
        assert!(
            LOCK_STEP_JOB_SQL.contains("lease_expires_at > clock_timestamp() AS lease_is_live")
        );
        assert!(COMPLETE_STEP_JOB_SQL.contains("job.lease_owner = $3"));
        assert!(COMPLETE_STEP_JOB_SQL.contains("job.fence_token = $4"));
        assert!(!COMPLETE_STEP_JOB_SQL.contains("lease_expires_at > clock_timestamp()"));
        assert!(!FAIL_STEP_JOB_SQL.contains("lease_expires_at > clock_timestamp()"));
        assert!(UPDATE_WORK_ITEM_SQL.contains("work.aggregate_version = $3"));
        assert!(UPDATE_WORKFLOW_SQL.contains("workflow.fence_token = $5"));
        assert!(REPLACE_ACCOUNTABILITY_SQL.contains("accountability_anchors.generation = $7"));
    }

    #[test]
    fn terminal_failure_sql_cannot_be_used_without_owned_dead_letter_data() {
        assert!(FAIL_STEP_JOB_SQL.contains("attempt_count >= job.max_attempts"));
        assert!(FAIL_STEP_JOB_SQL.contains("WHEN $9 OR job.attempt_count >= job.max_attempts"));
        assert!(INSERT_ESCALATION_SQL.contains("owner_type"));
        assert!(INSERT_ESCALATION_SQL.contains("owner_id"));
        assert!(INSERT_ESCALATION_SQL.contains("required_action"));
        assert!(INSERT_ESCALATION_SQL.contains("deadline"));
        assert!(INSERT_ESCALATION_SQL.contains("retry_policy"));
        assert_eq!(LedgerAccountabilityKind::Escalation.as_sql(), "ESCALATION");
    }

    #[test]
    fn workflow_step_child_job_and_timer_sql_compare_activity_contract_id_on_conflict() {
        assert!(
            INSERT_STEP_JOB_SQL
                .contains("workflow_jobs.activity_contract_id = EXCLUDED.activity_contract_id")
        );
        assert!(INSERT_STEP_JOB_SQL.contains("job_type, activity_contract_id, payload"));
        assert!(
            INSERT_STEP_TIMER_SQL
                .contains("workflow_timers.activity_contract_id = EXCLUDED.activity_contract_id")
        );
        assert!(INSERT_STEP_TIMER_SQL.contains("timer_type, activity_contract_id, due_at"));
    }

    fn step_job() -> StepWorkflowJob {
        StepWorkflowJob {
            id: Uuid::now_v7(),
            attempt_id: None,
            job_type: "continue".into(),
            activity_contract_id: "test.activity/continue/v1".into(),
            payload: json!({}),
            idempotency_key: "step-job".into(),
            priority: 0,
            available_at: Utc::now(),
            max_attempts: 3,
        }
    }

    fn step_timer() -> StepWorkflowTimer {
        StepWorkflowTimer {
            id: Uuid::now_v7(),
            attempt_id: None,
            workflow_key: "workflow".into(),
            timer_key: "timer".into(),
            timer_type: "continue".into(),
            activity_contract_id: "test.activity/continue/v1".into(),
            due_at: Utc::now(),
            payload: json!({}),
            generation: 1,
        }
    }

    #[test]
    fn step_job_validation_rejects_invalid_activity_contract_id() {
        let mut job = step_job();
        assert!(validate_job(&job).is_ok());
        job.activity_contract_id = String::new();
        assert!(validate_job(&job).is_err());
        job.activity_contract_id = "Not-Lowercase".into();
        assert!(validate_job(&job).is_err());
    }

    #[test]
    fn step_timer_validation_rejects_invalid_activity_contract_id() {
        let mut timer = step_timer();
        assert!(validate_timer(&timer).is_ok());
        timer.activity_contract_id = String::new();
        assert!(validate_timer(&timer).is_err());
        timer.activity_contract_id = "Not-Lowercase".into();
        assert!(validate_timer(&timer).is_err());
    }

    #[test]
    fn step_audit_hash_is_canonical_and_bound_to_the_fence() {
        let fence = fence();
        let previous_hash = digest('f');
        let audit = StepAuditEvent {
            id: Uuid::now_v7(),
            attempt_id: None,
            actor_type: "SERVICE".into(),
            actor_id: "reactor-1".into(),
            action: "WORKFLOW_STEP_COMMITTED".into(),
            subject_type: "WORK_ITEM".into(),
            subject_id: fence.work_item_id.to_string(),
            correlation_id: fence.job_id.to_string(),
            trace_id: None,
            policy_digest: None,
            before_digest: None,
            after_digest: None,
            details: json!({"job_id": fence.job_id}),
            occurred_at: Utc::now(),
        };

        let event = canonical_step_audit_event(&fence, &audit, Some(previous_hash.clone()))
            .expect("hash canonical step audit event");
        event.verify().expect("canonical event verifies");
        assert_eq!(event.content.tenant_id.as_uuid(), fence.tenant_id);
        assert_eq!(
            event.content.work_item_id.map(WorkItemId::as_uuid),
            Some(fence.work_item_id)
        );
        assert_eq!(
            event.content.previous_event_hash.as_deref(),
            Some(previous_hash.as_str())
        );
        assert!(LOCK_AUDIT_CHAIN_SQL.contains("pg_advisory_xact_lock"));
        assert!(LOAD_AUDIT_CHAIN_HEAD_SQL.contains("event.tenant_id = $1"));
        assert!(LOAD_AUDIT_CHAIN_HEAD_SQL.contains("successor.previous_event_hash"));
    }

    #[test]
    fn terminal_states_require_matching_accountability() {
        assert!(
            validate_anchor_state_compatibility("CLOSED", LedgerAccountabilityKind::Closure)
                .is_ok()
        );
        assert!(
            validate_anchor_state_compatibility("CLOSED", LedgerAccountabilityKind::Workflow)
                .is_err()
        );
        assert!(
            validate_anchor_state_compatibility("ESCALATED", LedgerAccountabilityKind::Escalation)
                .is_ok()
        );
    }

    #[test]
    fn commit_validation_requires_auditing_and_a_semantic_digest() {
        let commit = WorkflowStepCommit {
            fence: fence(),
            commit_digest: digest('a'),
            job_result: None,
            work_item_state: "PLANNED".into(),
            workflow_state: "ACTIVE".into(),
            workflow_event_cursor: 1,
            accountability: AccountabilityReplacement {
                kind: LedgerAccountabilityKind::Workflow,
                reference_id: Uuid::now_v7(),
                wake_or_deadline_at: None,
                authority_or_effect_active: false,
            },
            jobs: Vec::new(),
            timers: Vec::new(),
            effects: Vec::new(),
            outbox: Vec::new(),
            audit_events: Vec::new(),
        };
        assert!(commit.validate().is_err());
    }

    #[test]
    fn submission_effect_validation_requires_exact_work_order_binding() {
        let fence = fence();
        let attempt_id = Uuid::now_v7();
        let work_order_id = Uuid::now_v7();
        let mut request_payload: Value = serde_json::from_str(include_str!(
            "../../contracts/fixtures/work-order-envelope-v1.json"
        ))
        .expect("decode exact Runmill Work Order fixture");
        let payload = request_payload
            .get_mut("payload")
            .and_then(Value::as_object_mut)
            .expect("fixture payload object");
        payload.insert("work_order_id".into(), work_order_id.to_string().into());
        payload.insert("tenant_id".into(), fence.tenant_id.to_string().into());
        payload.insert("work_item_id".into(), fence.work_item_id.to_string().into());
        payload.insert("attempt_id".into(), attempt_id.to_string().into());
        payload.insert(
            "idempotency_key".into(),
            format!("{}/{}/{}", fence.tenant_id, fence.work_item_id, attempt_id).into(),
        );
        let envelope: RunmillSignedWorkOrderV1 =
            serde_json::from_value(request_payload.clone()).expect("typed Work Order envelope");
        let request_digest = sha256_digest(
            &envelope
                .canonical_bytes()
                .expect("canonical Work Order envelope"),
        );
        let work_order_digest = envelope
            .payload_digest()
            .expect("Work Order payload digest");
        let mut effect = StepEffectIntent {
            id: Uuid::now_v7(),
            attempt_id: Some(attempt_id),
            provider: "runmill".into(),
            effect_type: "submit_work_order".into(),
            idempotency_key: format!("submit-{attempt_id}"),
            correlation_marker: None,
            request_digest,
            request_payload,
            runmill_submission: None,
            next_attempt_at: Utc::now(),
        };
        assert!(validate_step_effect_intent(&effect, fence.tenant_id, fence.work_item_id).is_err());

        effect.runmill_submission = Some(RunmillSubmissionEffectBinding {
            work_order_id,
            work_order_digest,
        });
        validate_step_effect_intent(&effect, fence.tenant_id, fence.work_item_id)
            .expect("bound Runmill submission effect");

        effect.request_digest = digest('a');
        assert!(validate_step_effect_intent(&effect, fence.tenant_id, fence.work_item_id).is_err());

        effect.provider = "linear".into();
        assert!(validate_step_effect_intent(&effect, fence.tenant_id, fence.work_item_id).is_err());
    }

    #[test]
    fn failure_summaries_are_utf8_safe_and_bounded() {
        let value = "é".repeat(MAX_JOB_ERROR_CHARACTERS + 10);
        let summary = summarize_error(&value);
        assert_eq!(summary.chars().count(), MAX_JOB_ERROR_CHARACTERS);
        assert!(summary.is_char_boundary(summary.len()));
    }

    #[tokio::test]
    async fn live_step_commit_is_atomic_when_database_is_configured() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = super::super::PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let mut transaction = ledger.pool().begin().await.expect("begin transaction");

        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let next_job_id = Uuid::now_v7();
        let now = Utc::now();
        let policy_digest = digest('b');

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("tenant-{tenant_id}"))
            .bind("Workflow step test")
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
              VALUES ($1, $2, 'owner', $3, 'https://example.invalid/repo', 'main', $4)",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{repository_id}"))
        .bind(&policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert repository");
        sqlx::query(
            r"INSERT INTO source_snapshots
              (id, tenant_id, repository_id, source_system, external_id, source_revision,
               normalized_content, content_digest, connector_identity, source_updated_at)
              VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', $6)",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(format!("item-{work_item_id}"))
        .bind(digest('c'))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .expect("insert snapshot");
        sqlx::query(
            r"INSERT INTO work_items
              (id, tenant_id, source_snapshot_id, source_system, source_external_id,
               repository_id, state, closure_target, risk_class, policy_digest,
               budget_limits, identity_requirements, owner_fallback,
               normalized_priority, accepted_at)
              VALUES ($1, $2, $3, 'API', $4, $5, 'ACCEPTED', 'pull_request', 'low',
                      $6, jsonb_build_object(
                          'max_cost_microunits', 1000000,
                          'max_input_tokens', 100000,
                          'max_output_tokens', 100000,
                          'max_implementer_invocations', 2,
                          'max_reviewer_invocations', 2,
                          'max_fix_iterations', 1,
                          'max_wall_time_seconds', 3600,
                          'max_external_api_calls', 10
                      ),
                      jsonb_build_object(
                          'implementer', 'codex:implementer',
                          'local_reviewer', 'claude:local-reviewer',
                          'pr_reviewer', 'claude:pr-reviewer'
                      ),
                      'platform', 50, GREATEST($7, clock_timestamp()))",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(format!("item-{work_item_id}"))
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .expect("insert work item");
        sqlx::query(
            r"INSERT INTO workflow_instances
              (id, tenant_id, work_item_id, workflow_type, reducer_version)
              VALUES ($1, $2, $3, 'delivery', 'v1')",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert workflow");
        sqlx::query(
            r"INSERT INTO workflow_jobs
              (id, tenant_id, workflow_instance_id, work_item_id, job_type,
               activity_contract_id, status, payload, idempotency_key,
               attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at)
              VALUES ($1, $2, $3, $4, 'reduce', 'test.activity/reduce/v1', 'RUNNING',
                      '{}'::jsonb, $5, 1, 3, 1, 'reactor-live-test', $6)",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(work_item_id)
        .bind(format!("job-{job_id}"))
        .bind(now + Duration::minutes(5))
        .execute(&mut *transaction)
        .await
        .expect("insert claimed job");
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
        .expect("insert anchor");

        let commit = WorkflowStepCommit {
            fence: WorkflowStepFence {
                tenant_id,
                job_id,
                workflow_instance_id: workflow_id,
                work_item_id,
                lease_owner: "reactor-live-test".into(),
                job_fence_token: 1,
                expected_work_item_version: 1,
                expected_workflow_version: 1,
                expected_workflow_fence_token: 0,
                expected_anchor_generation: 1,
            },
            commit_digest: digest('d'),
            job_result: Some(json!({"ok": true})),
            work_item_state: "PLANNED".into(),
            workflow_state: "ACTIVE".into(),
            workflow_event_cursor: 1,
            accountability: AccountabilityReplacement {
                kind: LedgerAccountabilityKind::Workflow,
                reference_id: workflow_id,
                wake_or_deadline_at: None,
                authority_or_effect_active: false,
            },
            jobs: vec![StepWorkflowJob {
                id: next_job_id,
                attempt_id: None,
                job_type: "continue".into(),
                activity_contract_id: "test.activity/continue/v1".into(),
                payload: json!({}),
                idempotency_key: format!("next-{next_job_id}"),
                priority: 0,
                available_at: now,
                max_attempts: 3,
            }],
            timers: Vec::new(),
            effects: vec![StepEffectIntent {
                id: Uuid::now_v7(),
                attempt_id: None,
                provider: "linear".into(),
                effect_type: "comment".into(),
                idempotency_key: format!("effect-{job_id}"),
                correlation_marker: Some(format!("asf:{job_id}")),
                request_digest: digest('e'),
                request_payload: json!({}),
                runmill_submission: None,
                next_attempt_at: now,
            }],
            outbox: vec![StepOutboxMessage {
                id: Uuid::now_v7(),
                topic: "work-items".into(),
                message_key: work_item_id.to_string(),
                event_type: "work_item.planned".into(),
                payload: json!({}),
                headers: json!({}),
                idempotency_key: format!("outbox-{job_id}"),
                available_at: now,
            }],
            audit_events: vec![StepAuditEvent {
                id: Uuid::now_v7(),
                attempt_id: None,
                actor_type: "SERVICE".into(),
                actor_id: "reactor-live-test".into(),
                action: "WORKFLOW_STEP_COMMITTED".into(),
                subject_type: "WORK_ITEM".into(),
                subject_id: work_item_id.to_string(),
                correlation_id: job_id.to_string(),
                trace_id: None,
                policy_digest: Some(policy_digest),
                before_digest: None,
                after_digest: None,
                details: json!({}),
                occurred_at: now,
            }],
        };

        let outcome = commit_workflow_step(&mut transaction, &commit)
            .await
            .expect("commit workflow step");
        assert!(matches!(outcome, WorkflowStepCommitOutcome::Applied { .. }));
        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(job_id)
                .fetch_one(&mut *transaction)
                .await
                .expect("load committed job");
        assert_eq!(status, "COMPLETED");
        transaction.rollback().await.expect("rollback test data");
    }
}
