use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use super::{MAX_JOB_LEASE_DURATION, PgLedger, persistence_error};
use crate::{Error, Result};

const MAX_JOB_ERROR_CHARACTERS: usize = 8_192;
const MAX_CLAIM_BATCH: u32 = 1_000;

const CLAIM_JOBS_SQL: &str = r"
WITH candidates AS (
    SELECT job.id
    FROM workflow_jobs AS job
    WHERE job.tenant_id = $1
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
    -- An expired job claim cannot be re-fenced while its exact mutable claim is
    -- still referenced by an external effect.  Make the uncertain provider
    -- outcome explicit in the same statement before reclaiming the job.  This
    -- is a release to reconciliation, never permission to resend a submission.
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
SET status = 'RUNNING',
    attempt_count = job.attempt_count + 1,
    fence_token = job.fence_token + 1,
    lease_owner = $3,
    lease_expires_at = clock_timestamp() + ($4::bigint * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.id = candidates.id
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

const INSERT_JOB_SQL: &str = r"
INSERT INTO workflow_jobs (
    id,
    tenant_id,
    workflow_instance_id,
    work_item_id,
    attempt_id,
    job_type,
    activity_contract_id,
    payload,
    idempotency_key,
    priority,
    available_at,
    max_attempts
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
";

const LOAD_IDEMPOTENT_JOB_SQL: &str = r"
SELECT
    id,
    workflow_instance_id IS NOT DISTINCT FROM $3::uuid
        AND work_item_id IS NOT DISTINCT FROM $4::uuid
        AND attempt_id IS NOT DISTINCT FROM $5::uuid
        AND job_type = $6
        AND activity_contract_id = $7
        AND payload = $8::jsonb
        AND priority = $9
        AND available_at = $10::timestamptz
        AND max_attempts = $11 AS request_matches
FROM workflow_jobs
WHERE tenant_id = $1 AND idempotency_key = $2
";

/// A durable workflow job to enqueue.
#[derive(Debug, Clone, PartialEq)]
pub struct NewWorkflowJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub workflow_instance_id: Option<Uuid>,
    pub work_item_id: Option<Uuid>,
    pub attempt_id: Option<Uuid>,
    pub job_type: String,
    pub activity_contract_id: String,
    pub payload: Value,
    pub idempotency_key: String,
    pub priority: i16,
    pub available_at: DateTime<Utc>,
    pub max_attempts: i32,
}

impl NewWorkflowJob {
    fn validate(&self) -> Result<()> {
        if self.id.is_nil() || self.tenant_id.is_nil() {
            return Err(Error::Validation(
                "workflow job and tenant IDs must be non-nil".into(),
            ));
        }
        if self.workflow_instance_id.is_some_and(|id| id.is_nil())
            || self.work_item_id.is_some_and(|id| id.is_nil())
            || self.attempt_id.is_some_and(|id| id.is_nil())
        {
            return Err(Error::Validation(
                "workflow job bindings must use non-nil IDs".into(),
            ));
        }
        if self.workflow_instance_id.is_some() != self.work_item_id.is_some() {
            return Err(Error::Validation(
                "workflow jobs must be either tenant-scoped or bind both a workflow and work item"
                    .into(),
            ));
        }
        if self.attempt_id.is_some() && self.work_item_id.is_none() {
            return Err(Error::Validation(
                "an attempt-bound job must name its work item".into(),
            ));
        }
        if self.job_type.trim().is_empty() {
            return Err(Error::Validation(
                "workflow job type must be non-empty".into(),
            ));
        }
        if !is_valid_activity_contract_id(&self.activity_contract_id) {
            return Err(Error::Validation(format!(
                "workflow job activity contract id {:?} is invalid",
                self.activity_contract_id
            )));
        }
        if !self.payload.is_object() {
            return Err(Error::Validation(
                "workflow job payload must be a JSON object".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(Error::Validation(
                "workflow job idempotency key must be non-empty".into(),
            ));
        }
        if self.max_attempts <= 0 {
            return Err(Error::Validation(
                "workflow job max_attempts must be positive".into(),
            ));
        }
        Ok(())
    }
}

/// Result of an idempotent enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueueJobOutcome {
    pub job_id: Uuid,
    pub inserted: bool,
}

/// A job claim whose owner and fence token must accompany every mutation.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedWorkflowJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub workflow_instance_id: Option<Uuid>,
    pub work_item_id: Option<Uuid>,
    pub attempt_id: Option<Uuid>,
    pub job_type: String,
    pub activity_contract_id: String,
    pub payload: Value,
    pub idempotency_key: String,
    pub priority: i16,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub fence_token: i64,
    pub lease_owner: String,
    pub lease_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Completion is retry-safe when the caller lost the first response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteJobOutcome {
    Completed,
    AlreadyCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDisposition {
    RetryScheduled,
    Dead,
}

/// Failure recording is retry-safe for the same owner and fence token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailJobOutcome {
    pub disposition: FailureDisposition,
    pub newly_recorded: bool,
}

impl PgLedger {
    /// Idempotently enqueue a job. Reusing a key with different job semantics
    /// is a conflict rather than an accidental alias.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid job, a conflict if the key
    /// names a different request, or a persistence error when `PostgreSQL` fails.
    pub async fn enqueue_job(&self, job: &NewWorkflowJob) -> Result<EnqueueJobOutcome> {
        job.validate()?;
        if insert_job(self, job).await? {
            return Ok(EnqueueJobOutcome {
                job_id: job.id,
                inserted: true,
            });
        }
        let existing = load_idempotent_job(self, job).await?;
        Ok(EnqueueJobOutcome {
            job_id: validate_idempotent_job(&existing, job)?,
            inserted: false,
        })
    }

    /// Atomically claim due work in deterministic order. Expired claims are
    /// reclaimable, and every claim increments the fence token.
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsafe claim settings or a persistence
    /// error when `PostgreSQL` cannot atomically claim the jobs.
    pub async fn claim_jobs(
        &self,
        tenant_id: Uuid,
        lease_owner: &str,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<ClaimedWorkflowJob>> {
        validate_claim_request(lease_owner, limit, lease_duration)?;
        let lease_milliseconds = i64::try_from(lease_duration.as_millis()).map_err(|_error| {
            Error::Validation("workflow job lease duration is too large".into())
        })?;

        let rows = sqlx::query(CLAIM_JOBS_SQL)
            .bind(tenant_id)
            .bind(i64::from(limit))
            .bind(lease_owner)
            .bind(lease_milliseconds)
            .fetch_all(self.pool())
            .await
            .map_err(|error| persistence_error("claim workflow jobs", error))?;

        rows.iter().map(claimed_job_from_row).collect()
    }

    /// Extend a live claim. An expired or superseded claim cannot be renewed.
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsafe lease settings, a conflict for an
    /// expired/stale fence, or a persistence error when `PostgreSQL` fails.
    pub async fn renew_job_lease(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        lease_owner: &str,
        fence_token: i64,
        lease_duration: Duration,
    ) -> Result<DateTime<Utc>> {
        validate_claim_request(lease_owner, 1, lease_duration)?;
        if fence_token <= 0 {
            return Err(Error::Validation("job fence token must be positive".into()));
        }
        let lease_milliseconds = i64::try_from(lease_duration.as_millis()).map_err(|_error| {
            Error::Validation("workflow job lease duration is too large".into())
        })?;

        let row = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET lease_expires_at = clock_timestamp() + ($4::bigint * interval '1 millisecond'),
                updated_at = clock_timestamp()
            WHERE id = $1
              AND tenant_id = $5
              AND status = 'RUNNING'
              AND lease_owner = $2
              AND fence_token = $3
              AND lease_expires_at > clock_timestamp()
            RETURNING lease_expires_at
            ",
        )
        .bind(job_id)
        .bind(lease_owner)
        .bind(fence_token)
        .bind(lease_milliseconds)
        .bind(tenant_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|error| persistence_error("renew workflow job lease", error))?
        .ok_or_else(|| fenced_claim_error(job_id))?;

        row.try_get("lease_expires_at")
            .map_err(|error| persistence_error("decode renewed workflow job lease", error))
    }

    /// Complete a live claim. Retrying the same completion after a lost
    /// response returns [`CompleteJobOutcome::AlreadyCompleted`].
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid claim data, a conflict for a
    /// stale fence or changed retry result, or a persistence error.
    pub async fn complete_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        lease_owner: &str,
        fence_token: i64,
        result: Option<&Value>,
    ) -> Result<CompleteJobOutcome> {
        validate_job_mutation(lease_owner, fence_token)?;

        let updated = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'COMPLETED',
                result = $4,
                completed_by = $2,
                completion_fence_token = $3,
                completed_at = clock_timestamp(),
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = clock_timestamp()
            WHERE id = $1
              AND tenant_id = $5
              AND status = 'RUNNING'
              AND lease_owner = $2
              AND fence_token = $3
              AND lease_expires_at > clock_timestamp()
            ",
        )
        .bind(job_id)
        .bind(lease_owner)
        .bind(fence_token)
        .bind(result)
        .bind(tenant_id)
        .execute(self.pool())
        .await
        .map_err(|error| persistence_error("complete workflow job", error))?
        .rows_affected();

        if updated == 1 {
            return Ok(CompleteJobOutcome::Completed);
        }

        let row = load_job_completion_state(self, tenant_id, job_id, result).await?;
        let status: String = required_column(&row, "status", "workflow job status")?;
        let completed_by: Option<String> = optional_column(&row, "completed_by", "job completer")?;
        let completion_fence: Option<i64> =
            optional_column(&row, "completion_fence_token", "job completion fence")?;
        let result_matches: bool = required_column(
            &row,
            "result_matches",
            "workflow job completion-result comparison",
        )?;
        if status == "COMPLETED"
            && completed_by.as_deref() == Some(lease_owner)
            && completion_fence == Some(fence_token)
        {
            if !result_matches {
                return Err(Error::Conflict(format!(
                    "workflow job {job_id} completion was retried with a different result"
                )));
            }
            return Ok(CompleteJobOutcome::AlreadyCompleted);
        }

        Err(fenced_claim_error(job_id))
    }

    /// Record a failed execution that still has retry capacity.
    ///
    /// Exhausted workflow jobs require [`crate::ledger::fail_workflow_step`] so the `DEAD`
    /// transition and its owned escalation are one transaction. This generic
    /// helper deliberately refuses to create a naked dead-letter row.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid claim data, a conflict for a
    /// stale fence or changed retry details, or a persistence error.
    pub async fn fail_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        lease_owner: &str,
        fence_token: i64,
        error_summary: &str,
        retry_at: DateTime<Utc>,
    ) -> Result<FailJobOutcome> {
        validate_job_mutation(lease_owner, fence_token)?;
        let error_summary = summarize_error(error_summary);

        let row = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'RETRY',
                available_at = GREATEST($5, clock_timestamp()),
                last_failure_by = $2,
                last_failure_fence_token = $3,
                last_failure_retry_at = $5,
                last_error = $4,
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = clock_timestamp()
            WHERE id = $1
              AND tenant_id = $6
              AND status = 'RUNNING'
              AND lease_owner = $2
              AND fence_token = $3
              AND lease_expires_at > clock_timestamp()
              AND attempt_count < max_attempts
            RETURNING status
            ",
        )
        .bind(job_id)
        .bind(lease_owner)
        .bind(fence_token)
        .bind(&error_summary)
        .bind(retry_at)
        .bind(tenant_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|error| persistence_error("fail workflow job", error))?;

        if let Some(row) = row {
            let status: String = required_column(&row, "status", "failed workflow job status")?;
            return Ok(FailJobOutcome {
                disposition: failure_disposition(&status)?,
                newly_recorded: true,
            });
        }

        let row = load_job_failure_state(self, tenant_id, job_id, retry_at).await?;
        let status: String = required_column(&row, "status", "workflow job status")?;
        let attempt_count: i32 =
            required_column(&row, "attempt_count", "workflow job attempt count")?;
        let max_attempts: i32 =
            required_column(&row, "max_attempts", "workflow job maximum attempts")?;
        let current_owner: Option<String> =
            optional_column(&row, "lease_owner", "workflow job lease owner")?;
        let current_fence: i64 =
            required_column(&row, "fence_token", "workflow job current fence")?;
        let claim_is_live: bool =
            required_column(&row, "claim_is_live", "workflow job claim liveness")?;
        if status == "RUNNING"
            && attempt_count >= max_attempts
            && current_owner.as_deref() == Some(lease_owner)
            && current_fence == fence_token
            && claim_is_live
        {
            return Err(Error::Conflict(format!(
                "workflow job {job_id} exhausted its attempts; use fail_workflow_step with an owned escalation"
            )));
        }
        let failed_by: Option<String> =
            optional_column(&row, "last_failure_by", "workflow job failure owner")?;
        let failure_fence: Option<i64> = optional_column(
            &row,
            "last_failure_fence_token",
            "workflow job failure fence",
        )?;
        let stored_error: Option<String> =
            optional_column(&row, "last_error", "workflow job failure summary")?;
        let retry_time_matches: bool = required_column(
            &row,
            "retry_time_matches",
            "workflow job requested retry-time comparison",
        )?;
        if failed_by.as_deref() == Some(lease_owner) && failure_fence == Some(fence_token) {
            if stored_error.as_deref() != Some(error_summary.as_str()) || !retry_time_matches {
                return Err(Error::Conflict(format!(
                    "workflow job {job_id} failure was retried with different details"
                )));
            }
            return Ok(FailJobOutcome {
                disposition: if status == "DEAD" {
                    FailureDisposition::Dead
                } else {
                    FailureDisposition::RetryScheduled
                },
                newly_recorded: false,
            });
        }

        Err(fenced_claim_error(job_id))
    }
}

async fn insert_job(ledger: &PgLedger, job: &NewWorkflowJob) -> Result<bool> {
    let inserted = sqlx::query(INSERT_JOB_SQL)
        .bind(job.id)
        .bind(job.tenant_id)
        .bind(job.workflow_instance_id)
        .bind(job.work_item_id)
        .bind(job.attempt_id)
        .bind(&job.job_type)
        .bind(&job.activity_contract_id)
        .bind(&job.payload)
        .bind(&job.idempotency_key)
        .bind(job.priority)
        .bind(job.available_at)
        .bind(job.max_attempts)
        .execute(ledger.pool())
        .await
        .map_err(|error| persistence_error("enqueue workflow job", error))?;
    Ok(inserted.rows_affected() == 1)
}

async fn load_idempotent_job(ledger: &PgLedger, job: &NewWorkflowJob) -> Result<PgRow> {
    sqlx::query(LOAD_IDEMPOTENT_JOB_SQL)
        .bind(job.tenant_id)
        .bind(&job.idempotency_key)
        .bind(job.workflow_instance_id)
        .bind(job.work_item_id)
        .bind(job.attempt_id)
        .bind(&job.job_type)
        .bind(&job.activity_contract_id)
        .bind(&job.payload)
        .bind(job.priority)
        .bind(job.available_at)
        .bind(job.max_attempts)
        .fetch_optional(ledger.pool())
        .await
        .map_err(|error| persistence_error("load idempotent workflow job", error))?
        .ok_or_else(|| {
            Error::Persistence(
                "workflow job conflict was observed but the existing row was not visible".into(),
            )
        })
}

fn validate_idempotent_job(existing: &PgRow, job: &NewWorkflowJob) -> Result<Uuid> {
    let existing_id: Uuid = required_column(existing, "id", "workflow job id")?;
    let same_request: bool = required_column(
        existing,
        "request_matches",
        "workflow job request comparison",
    )?;
    if same_request {
        Ok(existing_id)
    } else {
        Err(Error::Conflict(format!(
            "workflow job idempotency key {} was reused for a different request",
            job.idempotency_key
        )))
    }
}

async fn load_job_failure_state(
    ledger: &PgLedger,
    tenant_id: Uuid,
    job_id: Uuid,
    requested_retry_at: DateTime<Utc>,
) -> Result<PgRow> {
    sqlx::query(
        r"
        SELECT
            status,
            attempt_count,
            max_attempts,
            lease_owner,
            fence_token,
            COALESCE(lease_expires_at > clock_timestamp(), false) AS claim_is_live,
            last_failure_by,
            last_failure_fence_token,
            last_error,
            COALESCE(
                last_failure_retry_at = $3::timestamptz,
                false
            ) AS retry_time_matches
        FROM workflow_jobs
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(job_id)
    .bind(tenant_id)
    .bind(requested_retry_at)
    .fetch_optional(ledger.pool())
    .await
    .map_err(|error| persistence_error("load workflow job failure state", error))?
    .ok_or_else(|| Error::NotFound(format!("workflow job {job_id}")))
}

async fn load_job_completion_state(
    ledger: &PgLedger,
    tenant_id: Uuid,
    job_id: Uuid,
    requested_result: Option<&Value>,
) -> Result<PgRow> {
    sqlx::query(
        r"
        SELECT
            status,
            completed_by,
            completion_fence_token,
            result IS NOT DISTINCT FROM $3::jsonb AS result_matches
        FROM workflow_jobs
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(job_id)
    .bind(tenant_id)
    .bind(requested_result)
    .fetch_optional(ledger.pool())
    .await
    .map_err(|error| persistence_error("load workflow job completion state", error))?
    .ok_or_else(|| Error::NotFound(format!("workflow job {job_id}")))
}

fn claimed_job_from_row(row: &PgRow) -> Result<ClaimedWorkflowJob> {
    Ok(ClaimedWorkflowJob {
        id: required_column(row, "id", "claimed workflow job id")?,
        tenant_id: required_column(row, "tenant_id", "claimed workflow job tenant")?,
        workflow_instance_id: optional_column(
            row,
            "workflow_instance_id",
            "claimed workflow job workflow",
        )?,
        work_item_id: optional_column(row, "work_item_id", "claimed workflow job work item")?,
        attempt_id: optional_column(row, "attempt_id", "claimed workflow job attempt")?,
        job_type: required_column(row, "job_type", "claimed workflow job type")?,
        activity_contract_id: required_column(
            row,
            "activity_contract_id",
            "claimed workflow job activity contract id",
        )?,
        payload: required_column(row, "payload", "claimed workflow job payload")?,
        idempotency_key: required_column(
            row,
            "idempotency_key",
            "claimed workflow job idempotency key",
        )?,
        priority: required_column(row, "priority", "claimed workflow job priority")?,
        attempt_count: required_column(row, "attempt_count", "claimed workflow job attempt count")?,
        max_attempts: required_column(row, "max_attempts", "claimed workflow job max attempts")?,
        fence_token: required_column(row, "fence_token", "claimed workflow job fence")?,
        lease_owner: required_column(row, "lease_owner", "claimed workflow job lease owner")?,
        lease_expires_at: required_column(
            row,
            "lease_expires_at",
            "claimed workflow job lease expiry",
        )?,
        created_at: required_column(row, "created_at", "claimed workflow job creation time")?,
    })
}

fn required_column<T>(row: &PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|error| persistence_error(&format!("decode {context}"), error))
}

fn optional_column<T>(row: &PgRow, column: &str, context: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|error| persistence_error(&format!("decode {context}"), error))
}

fn failure_disposition(status: &str) -> Result<FailureDisposition> {
    match status {
        "RETRY" => Ok(FailureDisposition::RetryScheduled),
        "DEAD" => Ok(FailureDisposition::Dead),
        other => Err(Error::Persistence(format!(
            "unexpected workflow job failure status {other}"
        ))),
    }
}

fn validate_claim_request(lease_owner: &str, limit: u32, lease_duration: Duration) -> Result<()> {
    if lease_owner.trim().is_empty() {
        return Err(Error::Validation(
            "job lease owner must be non-empty".into(),
        ));
    }
    if limit == 0 || limit > MAX_CLAIM_BATCH {
        return Err(Error::Validation(format!(
            "job claim limit must be in 1..={MAX_CLAIM_BATCH}"
        )));
    }
    if lease_duration.is_zero() || lease_duration > MAX_JOB_LEASE_DURATION {
        return Err(Error::Validation(
            "job lease duration must be positive and at most 24 hours".into(),
        ));
    }
    Ok(())
}

fn validate_job_mutation(lease_owner: &str, fence_token: i64) -> Result<()> {
    if lease_owner.trim().is_empty() {
        return Err(Error::Validation(
            "job lease owner must be non-empty".into(),
        ));
    }
    if fence_token <= 0 {
        return Err(Error::Validation("job fence token must be positive".into()));
    }
    Ok(())
}

fn fenced_claim_error(job_id: Uuid) -> Error {
    Error::Conflict(format!(
        "workflow job {job_id} claim is expired, completed, or superseded by a newer fence"
    ))
}

fn summarize_error(value: &str) -> String {
    value.chars().take(MAX_JOB_ERROR_CHARACTERS).collect()
}

/// Strict, fail-closed activity contract id shape: nonblank, at most 128
/// bytes, and a lowercase URI-like `segment([./-]segment)*` pattern. This
/// mirrors the database check constraint installed by migration 0023.
pub(crate) fn is_valid_activity_contract_id(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > 128 {
        return false;
    }
    let mut previous_was_separator = true;
    for byte in candidate.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_separator = false,
            b'.' | b'/' | b'-' => {
                if previous_was_separator {
                    return false;
                }
                previous_was_separator = true;
            }
            _ => return false,
        }
    }
    !previous_was_separator
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use serde_json::json;

    use super::*;

    // A non-production job_type's activity contract must not borrow the
    // real ADVANCE_ACCEPTED_WORK_ITEM production identity: these fixtures
    // only exercise generic binding/payload/idempotency validation and must
    // not be mistaken for coverage of a specific production handler.
    const TEST_ACTIVITY_CONTRACT_ID: &str = "test.activity/advance-work-item/v1";

    fn valid_job() -> NewWorkflowJob {
        NewWorkflowJob {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: "advance_work_item".into(),
            activity_contract_id: TEST_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"work_item_id": Uuid::now_v7()}),
            idempotency_key: "work-item:advance:1".into(),
            priority: 10,
            available_at: Utc::now().trunc_subsecs(6),
            max_attempts: 5,
        }
    }

    #[test]
    fn job_validation_rejects_non_object_payloads() {
        let mut job = valid_job();
        job.payload = json!(["not", "an", "object"]);
        assert!(job.validate().is_err());
    }

    #[test]
    fn job_validation_rejects_bindings_without_work_item() {
        let mut job = valid_job();
        job.workflow_instance_id = Some(Uuid::now_v7());
        assert!(job.validate().is_err());

        job.workflow_instance_id = None;
        job.attempt_id = Some(Uuid::now_v7());
        assert!(job.validate().is_err());

        job.attempt_id = None;
        job.work_item_id = Some(Uuid::now_v7());
        assert!(job.validate().is_err());
    }

    #[test]
    fn job_validation_rejects_invalid_activity_contract_id() {
        let mut job = valid_job();
        job.activity_contract_id = String::new();
        assert!(job.validate().is_err());

        job.activity_contract_id = "Not-Lowercase/v1".into();
        assert!(job.validate().is_err());

        job.activity_contract_id = "asf.activity//double-slash".into();
        assert!(job.validate().is_err());

        job.activity_contract_id = "a".repeat(129);
        assert!(job.validate().is_err());

        job.activity_contract_id = TEST_ACTIVITY_CONTRACT_ID.into();
        assert!(job.validate().is_ok());
    }

    #[test]
    fn activity_contract_id_grammar_matches_migration_0023() {
        assert!(is_valid_activity_contract_id("asf.activity/intake-sync/v1"));
        assert!(!is_valid_activity_contract_id(""));
        assert!(!is_valid_activity_contract_id("-leading-separator"));
        assert!(!is_valid_activity_contract_id("trailing-separator-"));
        assert!(!is_valid_activity_contract_id("double//separator"));
        assert!(!is_valid_activity_contract_id("Has-Upper-Case"));
        assert!(!is_valid_activity_contract_id(&"a".repeat(129)));
        assert!(is_valid_activity_contract_id(&"a".repeat(128)));
    }

    #[test]
    fn idempotent_job_conflict_compares_activity_contract_id() {
        assert!(INSERT_JOB_SQL.contains("activity_contract_id"));
        assert!(LOAD_IDEMPOTENT_JOB_SQL.contains("activity_contract_id = $7"));
        assert!(CLAIM_JOBS_SQL.contains("job.activity_contract_id"));
    }

    #[test]
    fn claim_validation_bounds_batch_and_lease() {
        assert!(
            validate_claim_request("worker-1", MAX_CLAIM_BATCH, Duration::from_mins(1)).is_ok()
        );
        assert!(
            validate_claim_request("worker-1", MAX_CLAIM_BATCH + 1, Duration::from_mins(1))
                .is_err()
        );
        assert!(validate_claim_request("worker-1", 1, Duration::ZERO).is_err());
    }

    #[test]
    fn error_summary_is_utf8_safe_and_bounded() {
        let summary = summarize_error(&"é".repeat(MAX_JOB_ERROR_CHARACTERS + 10));
        assert_eq!(summary.chars().count(), MAX_JOB_ERROR_CHARACTERS);
        assert!(summary.is_char_boundary(summary.len()));
    }

    #[test]
    fn claim_query_uses_skip_locked_and_fencing() {
        assert!(CLAIM_JOBS_SQL.contains("FOR UPDATE OF job SKIP LOCKED"));
        assert!(CLAIM_JOBS_SQL.contains("fence_token = job.fence_token + 1"));
        assert!(CLAIM_JOBS_SQL.contains("lease_expires_at <= clock_timestamp()"));
    }

    #[test]
    fn failure_status_is_strictly_decoded() {
        assert_eq!(
            failure_disposition("RETRY").expect("retry is valid"),
            FailureDisposition::RetryScheduled
        );
        assert!(failure_disposition("RUNNING").is_err());
    }
}
