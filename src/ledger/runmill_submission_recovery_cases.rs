use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use super::{PgLedger, persistence_error};
use crate::{Error, Result};

/// A new runmill submission recovery case to persist.
#[derive(Debug, Clone)]
pub struct NewRunmillSubmissionRecoveryCase {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub effect_intent_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub work_order_id: Uuid,
    pub payload_digest: String,
    pub request_digest: String,
    pub remote_idempotency_key: String,
    pub worker_id: Uuid,
    pub worker_generation: i64,
    pub worker_session_id: Uuid,
    pub escalation_id: Uuid,
    pub owner_type: String,
    pub owner_id: String,
    pub deadline: DateTime<Utc>,
}

impl NewRunmillSubmissionRecoveryCase {
    fn validate(&self) -> Result<()> {
        if self.id.is_nil()
            || self.tenant_id.is_nil()
            || self.effect_intent_id.is_nil()
            || self.work_item_id.is_nil()
            || self.attempt_id.is_nil()
            || self.work_order_id.is_nil()
            || self.worker_id.is_nil()
            || self.worker_session_id.is_nil()
            || self.escalation_id.is_nil()
        {
            return Err(Error::Validation("all UUID fields must be non-nil".into()));
        }

        if !is_valid_sha256_digest(&self.payload_digest) {
            return Err(Error::Validation(format!(
                "payload_digest {:?} must be a valid SHA256 digest",
                self.payload_digest
            )));
        }

        if !is_valid_sha256_digest(&self.request_digest) {
            return Err(Error::Validation(format!(
                "request_digest {:?} must be a valid SHA256 digest",
                self.request_digest
            )));
        }

        if self.remote_idempotency_key.trim().is_empty() {
            return Err(Error::Validation(
                "remote_idempotency_key must be non-blank".into(),
            ));
        }

        if self.worker_generation <= 0 {
            return Err(Error::Validation(
                "worker_generation must be positive".into(),
            ));
        }

        if self.owner_type.trim().is_empty() {
            return Err(Error::Validation("owner_type must be non-blank".into()));
        }

        if self.owner_id.trim().is_empty() {
            return Err(Error::Validation("owner_id must be non-blank".into()));
        }

        Ok(())
    }
}

/// A persisted runmill submission recovery case.
#[derive(Debug, Clone)]
pub struct RunmillSubmissionRecoveryCase {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub effect_intent_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub work_order_id: Uuid,
    pub payload_digest: String,
    pub request_digest: String,
    pub remote_idempotency_key: String,
    pub worker_id: Uuid,
    pub worker_generation: i64,
    pub worker_session_id: Uuid,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of creating or getting a runmill submission recovery case with its escalation.
#[derive(Debug, Clone)]
pub struct RunmillSubmissionRecoveryCaseWithEscalation {
    pub case: RunmillSubmissionRecoveryCase,
    pub escalation_id: Uuid,
}

impl PgLedger {
    /// Create or get a runmill submission recovery case with an associated escalation.
    /// On conflict with `(tenant_id, effect_intent_id)`, loads the existing case and validates
    /// that all immutable input fields match exactly. Returns a conflict if
    /// the existing case has mismatched immutable fields.
    ///
    /// In the same transaction, inserts or loads a `REMOTE_EFFECT_AMBIGUOUS` escalation
    /// with the supplied `escalation_id`, owner, and deadline. Uses ON CONFLICT on the
    /// idempotency key to load the existing escalation and verifies it matches.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid input, a conflict if the
    /// recovery case or escalation have mismatched fields, or a persistence error when `PostgreSQL` fails.
    pub async fn create_or_get_runmill_submission_recovery_case(
        &self,
        input: NewRunmillSubmissionRecoveryCase,
    ) -> Result<RunmillSubmissionRecoveryCaseWithEscalation> {
        input.validate()?;

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|error| persistence_error("begin recovery case transaction", error))?;

        // Load/lock existing recovery case by tenant/effect at transaction start
        if let Some(existing) =
            load_recovery_case(&mut tx, input.tenant_id, input.effect_intent_id).await?
        {
            // Existing case found; compare immutable fields
            if !case_fields_match(&existing, &input) {
                tx.rollback().await.map_err(|error| {
                    persistence_error("rollback recovery case transaction", error)
                })?;
                return Err(Error::Conflict(format!(
                    "runmill submission recovery case (tenant {}, effect {}) has mismatched immutable fields",
                    input.tenant_id, input.effect_intent_id
                )));
            }
        } else {
            // No existing case; insert the new one
            let insert_case_sql = r"
                INSERT INTO runmill_submission_recovery_cases (
                    id,
                    tenant_id,
                    effect_intent_id,
                    work_item_id,
                    attempt_id,
                    work_order_id,
                    payload_digest,
                    request_digest,
                    remote_idempotency_key,
                    worker_id,
                    worker_generation,
                    worker_session_id,
                    state
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'PENDING_EXTERNAL_LOOKUP')
                ON CONFLICT (tenant_id, effect_intent_id) DO NOTHING
            ";

            let _rows_affected = sqlx::query(insert_case_sql)
                .bind(input.id)
                .bind(input.tenant_id)
                .bind(input.effect_intent_id)
                .bind(input.work_item_id)
                .bind(input.attempt_id)
                .bind(input.work_order_id)
                .bind(&input.payload_digest)
                .bind(&input.request_digest)
                .bind(&input.remote_idempotency_key)
                .bind(input.worker_id)
                .bind(input.worker_generation)
                .bind(input.worker_session_id)
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    persistence_error("insert runmill submission recovery case", error)
                })?
                .rows_affected();
        }

        let case = load_recovery_case(&mut tx, input.tenant_id, input.effect_intent_id)
            .await?
            .ok_or_else(|| Error::Persistence("failed to load recovery case".into()))?;

        let idempotency_key = format!("runmill-submission-recovery:{}", input.effect_intent_id);
        let evidence = json!([
            format!("effect-intent:{}", input.effect_intent_id),
            format!("runmill-submission-recovery-case:{}", input.id),
            format!("work-order:{}", input.work_order_id),
            format!("payload-digest:{}", input.payload_digest),
            format!("request-digest:{}", input.request_digest),
            format!("remote-idempotency-key:{}", input.remote_idempotency_key),
        ]);
        let retry_policy = json!({
            "automatic": false,
            "max_additional_attempts": 0,
            "backoff_seconds": 0,
            "prerequisites": []
        });

        let insert_escalation_sql = r"
            INSERT INTO escalations (
                id,
                tenant_id,
                work_item_id,
                attempt_id,
                category,
                severity,
                reason,
                owner_type,
                owner_id,
                required_action,
                evidence_references,
                deadline,
                retry_policy,
                authority_or_effect_active,
                idempotency_key
            )
            VALUES (
                $1, $2, $3, $4, 'REMOTE_EFFECT_AMBIGUOUS', 'HIGH',
                'Runmill submission requires recovery and reconciliation',
                $5, $6, 'reconcile exact Runmill admission',
                $7::jsonb, $8, $9::jsonb,
                true, $10
            )
            ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
            SET aggregate_version = escalations.aggregate_version
            RETURNING id
        ";

        let esc_row = sqlx::query(insert_escalation_sql)
            .bind(input.escalation_id)
            .bind(input.tenant_id)
            .bind(input.work_item_id)
            .bind(input.attempt_id)
            .bind(&input.owner_type)
            .bind(&input.owner_id)
            .bind(evidence)
            .bind(input.deadline)
            .bind(retry_policy)
            .bind(&idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| persistence_error("insert or load recovery case escalation", error))?;

        let returned_escalation_id: Uuid = esc_row
            .try_get("id")
            .map_err(|error| persistence_error("decode escalation id", error))?;

        if returned_escalation_id != input.escalation_id {
            tx.rollback()
                .await
                .map_err(|error| persistence_error("rollback recovery case transaction", error))?;
            return Err(Error::Conflict(format!(
                "runmill submission recovery escalation (tenant {}, effect {}) has mismatched id: expected {}, got {}",
                input.tenant_id,
                input.effect_intent_id,
                input.escalation_id,
                returned_escalation_id
            )));
        }

        tx.commit()
            .await
            .map_err(|error| persistence_error("commit recovery case transaction", error))?;

        Ok(RunmillSubmissionRecoveryCaseWithEscalation {
            case,
            escalation_id: input.escalation_id,
        })
    }
}

async fn load_recovery_case(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    effect_intent_id: Uuid,
) -> Result<Option<RunmillSubmissionRecoveryCase>> {
    let sql = r"
        SELECT
            id,
            tenant_id,
            effect_intent_id,
            work_item_id,
            attempt_id,
            work_order_id,
            payload_digest,
            request_digest,
            remote_idempotency_key,
            worker_id,
            worker_generation,
            worker_session_id,
            state,
            created_at,
            updated_at
        FROM runmill_submission_recovery_cases
        WHERE tenant_id = $1
          AND effect_intent_id = $2
        FOR KEY SHARE
    ";

    let row = sqlx::query(sql)
        .bind(tenant_id)
        .bind(effect_intent_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| persistence_error("load recovery case", error))?;

    match row {
        Some(row) => recovery_case_from_row(&row).map(Some),
        None => Ok(None),
    }
}

fn recovery_case_from_row(row: &PgRow) -> Result<RunmillSubmissionRecoveryCase> {
    Ok(RunmillSubmissionRecoveryCase {
        id: row
            .try_get("id")
            .map_err(|error| persistence_error("decode recovery case id", error))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|error| persistence_error("decode recovery case tenant_id", error))?,
        effect_intent_id: row
            .try_get("effect_intent_id")
            .map_err(|error| persistence_error("decode recovery case effect_intent_id", error))?,
        work_item_id: row
            .try_get("work_item_id")
            .map_err(|error| persistence_error("decode recovery case work_item_id", error))?,
        attempt_id: row
            .try_get("attempt_id")
            .map_err(|error| persistence_error("decode recovery case attempt_id", error))?,
        work_order_id: row
            .try_get("work_order_id")
            .map_err(|error| persistence_error("decode recovery case work_order_id", error))?,
        payload_digest: row
            .try_get("payload_digest")
            .map_err(|error| persistence_error("decode recovery case payload_digest", error))?,
        request_digest: row
            .try_get("request_digest")
            .map_err(|error| persistence_error("decode recovery case request_digest", error))?,
        remote_idempotency_key: row.try_get("remote_idempotency_key").map_err(|error| {
            persistence_error("decode recovery case remote_idempotency_key", error)
        })?,
        worker_id: row
            .try_get("worker_id")
            .map_err(|error| persistence_error("decode recovery case worker_id", error))?,
        worker_generation: row
            .try_get("worker_generation")
            .map_err(|error| persistence_error("decode recovery case worker_generation", error))?,
        worker_session_id: row
            .try_get("worker_session_id")
            .map_err(|error| persistence_error("decode recovery case worker_session_id", error))?,
        state: row
            .try_get("state")
            .map_err(|error| persistence_error("decode recovery case state", error))?,
        created_at: row
            .try_get("created_at")
            .map_err(|error| persistence_error("decode recovery case created_at", error))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|error| persistence_error("decode recovery case updated_at", error))?,
    })
}

fn case_fields_match(
    existing: &RunmillSubmissionRecoveryCase,
    input: &NewRunmillSubmissionRecoveryCase,
) -> bool {
    existing.id == input.id
        && existing.work_item_id == input.work_item_id
        && existing.attempt_id == input.attempt_id
        && existing.work_order_id == input.work_order_id
        && existing.payload_digest == input.payload_digest
        && existing.request_digest == input.request_digest
        && existing.remote_idempotency_key == input.remote_idempotency_key
        && existing.worker_id == input.worker_id
        && existing.worker_generation == input.worker_generation
        && existing.worker_session_id == input.worker_session_id
}

fn is_valid_sha256_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest[7..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use super::*;
    use chrono::Duration;

    fn new_valid_recovery_case() -> NewRunmillSubmissionRecoveryCase {
        NewRunmillSubmissionRecoveryCase {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            effect_intent_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            payload_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            request_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            remote_idempotency_key: "key".into(),
            worker_id: Uuid::now_v7(),
            worker_generation: 1,
            worker_session_id: Uuid::now_v7(),
            escalation_id: Uuid::now_v7(),
            owner_type: "TEAM".into(),
            owner_id: "platform-operations".into(),
            deadline: Utc::now().trunc_subsecs(6) + Duration::hours(4),
        }
    }

    #[test]
    fn validation_rejects_nil_id() {
        let mut case = new_valid_recovery_case();
        case.id = Uuid::nil();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_nil_tenant_id() {
        let mut case = new_valid_recovery_case();
        case.tenant_id = Uuid::nil();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_nil_escalation_id() {
        let mut case = new_valid_recovery_case();
        case.escalation_id = Uuid::nil();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_payload_digest() {
        let mut case = new_valid_recovery_case();
        case.payload_digest = "sha256:invalid".into();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_request_digest() {
        let mut case = new_valid_recovery_case();
        case.request_digest = "md5:bad".into();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_blank_idempotency_key() {
        let mut case = new_valid_recovery_case();
        case.remote_idempotency_key = "  ".into();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_generation() {
        let mut case = new_valid_recovery_case();
        case.worker_generation = 0;
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_negative_generation() {
        let mut case = new_valid_recovery_case();
        case.worker_generation = -1;
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_blank_owner_type() {
        let mut case = new_valid_recovery_case();
        case.owner_type = "  ".into();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_rejects_blank_owner_id() {
        let mut case = new_valid_recovery_case();
        case.owner_id = "  ".into();
        assert!(case.validate().is_err());
    }

    #[test]
    fn validation_accepts_valid_case() {
        let case = new_valid_recovery_case();
        assert!(case.validate().is_ok());
    }

    #[test]
    fn valid_sha256_digest_accepted() {
        assert!(is_valid_sha256_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_valid_sha256_digest(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        assert!(is_valid_sha256_digest(
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
    }

    #[test]
    fn invalid_sha256_digests_rejected() {
        assert!(!is_valid_sha256_digest("sha256:invalid"));
        assert!(!is_valid_sha256_digest("sha256:"));
        assert!(!is_valid_sha256_digest(
            "md5:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_valid_sha256_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000z"
        ));
        assert!(!is_valid_sha256_digest(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }
}
