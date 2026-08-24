use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{PgLedger, persistence_error};
use crate::{
    Error, Result,
    audit::{AuditEventContent, HashedAuditEvent},
    crypto::{canonical_json, sha256_digest},
    domain::{EventId, TenantId},
    security::reject_sensitive_fields,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationalIncidentStatus {
    Open,
    Acknowledged,
    Resolved,
    Cancelled,
}

impl OperationalIncidentStatus {
    fn from_persisted(value: &str) -> Result<Self> {
        match value {
            "OPEN" => Ok(Self::Open),
            "ACKNOWLEDGED" => Ok(Self::Acknowledged),
            "RESOLVED" => Ok(Self::Resolved),
            "CANCELLED" => Ok(Self::Cancelled),
            other => Err(Error::Persistence(format!(
                "unknown operational incident status {other}"
            ))),
        }
    }

    const fn as_persisted(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Acknowledged => "ACKNOWLEDGED",
            Self::Resolved => "RESOLVED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// The only supported lifecycle mutations for an operational incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationalIncidentTransition {
    Acknowledge { actor: String },
    Resolve { actor: String, resolution: String },
    Cancel { actor: String, resolution: String },
}

impl OperationalIncidentTransition {
    fn validate(&self) -> Result<()> {
        if self.actor().trim().is_empty() {
            return Err(Error::Validation(
                "operational incident transition actor must be non-empty".into(),
            ));
        }
        if self
            .resolution()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(Error::Validation(
                "operational incident closure requires a non-empty resolution".into(),
            ));
        }
        Ok(())
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Acknowledge { .. } => "ACKNOWLEDGE",
            Self::Resolve { .. } => "RESOLVE",
            Self::Cancel { .. } => "CANCEL",
        }
    }

    const fn required_status(&self) -> OperationalIncidentStatus {
        match self {
            Self::Acknowledge { .. } => OperationalIncidentStatus::Open,
            Self::Resolve { .. } | Self::Cancel { .. } => OperationalIncidentStatus::Acknowledged,
        }
    }

    const fn resulting_status(&self) -> OperationalIncidentStatus {
        match self {
            Self::Acknowledge { .. } => OperationalIncidentStatus::Acknowledged,
            Self::Resolve { .. } => OperationalIncidentStatus::Resolved,
            Self::Cancel { .. } => OperationalIncidentStatus::Cancelled,
        }
    }

    const fn audit_action(&self) -> &'static str {
        match self {
            Self::Acknowledge { .. } => "OPERATIONAL_INCIDENT_ACKNOWLEDGED",
            Self::Resolve { .. } => "OPERATIONAL_INCIDENT_RESOLVED",
            Self::Cancel { .. } => "OPERATIONAL_INCIDENT_CANCELLED",
        }
    }

    const fn event_type(&self) -> &'static str {
        match self {
            Self::Acknowledge { .. } => "operational_incident.acknowledged",
            Self::Resolve { .. } => "operational_incident.resolved",
            Self::Cancel { .. } => "operational_incident.cancelled",
        }
    }

    fn actor(&self) -> &str {
        match self {
            Self::Acknowledge { actor }
            | Self::Resolve { actor, .. }
            | Self::Cancel { actor, .. } => actor,
        }
    }

    fn resolution(&self) -> Option<&str> {
        match self {
            Self::Acknowledge { .. } => None,
            Self::Resolve { resolution, .. } | Self::Cancel { resolution, .. } => Some(resolution),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalIncidentLifecycle {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub workflow_job_id: Uuid,
    pub status: OperationalIncidentStatus,
    pub aggregate_version: u64,
    pub authority_or_effect_active: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub closed_at: Option<DateTime<Utc>>,
    pub closed_by: Option<String>,
    pub resolution: Option<String>,
}

#[derive(Debug, Serialize)]
struct OperationalIncidentSemanticRequest<'a> {
    schema: &'static str,
    tenant_id: Uuid,
    incident_id: Uuid,
    expected_version: u64,
    transition: &'static str,
    actor: &'a str,
    resolution: Option<&'a str>,
}

impl PgLedger {
    /// Atomically and idempotently advance an operational incident.
    ///
    /// The receipt key is `(tenant, incident, expected_version)`. Exact replay
    /// adopts its original database-timestamped snapshot even after later
    /// transitions, while different semantics at that fence conflict.
    /// `PostgreSQL` commits the update, hash-chained audit fact, outbox event,
    /// and immutable receipt in one transaction.
    pub async fn transition_operational_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        expected_version: u64,
        transition: &OperationalIncidentTransition,
    ) -> Result<OperationalIncidentLifecycle> {
        transition.validate()?;
        let expected_version_i64 = i64::try_from(expected_version).map_err(|_error| {
            Error::Validation("operational incident version exceeds PostgreSQL bigint".into())
        })?;
        if expected_version_i64 <= 0 {
            return Err(Error::Validation(
                "operational incident expected version must be positive".into(),
            ));
        }
        let actor = transition.actor().trim();
        let resolution = transition.resolution().map(str::trim);
        let semantics = OperationalIncidentSemanticRequest {
            schema: "asf.operational-incident-transition-request/v1",
            tenant_id,
            incident_id,
            expected_version,
            transition: transition.kind(),
            actor,
            resolution,
        };
        let semantic_value = serde_json::to_value(&semantics).map_err(|error| {
            Error::Serialization(format!(
                "serialize operational incident transition: {error}"
            ))
        })?;
        reject_sensitive_fields(&semantic_value)?;
        let request_digest = sha256_digest(&canonical_json(&semantics)?);

        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                persistence_error("begin operational incident transition", error)
            })?;
        let current_row = sqlx::query(
            r"
            SELECT id, tenant_id, workflow_job_id, status, aggregate_version,
                   authority_or_effect_active, acknowledged_at, acknowledged_by,
                   closed_at, closed_by, resolution
            FROM operational_incidents
            WHERE tenant_id = $1 AND id = $2
            FOR UPDATE
            ",
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| persistence_error("lock operational incident", error))?;
        let Some(current_row) = current_row else {
            return Err(Error::NotFound(format!(
                "operational incident {incident_id}"
            )));
        };

        if let Some(receipt) = load_transition_receipt(
            &mut transaction,
            tenant_id,
            incident_id,
            expected_version_i64,
        )
        .await?
        {
            if receipt.request_digest != request_digest {
                return Err(Error::Conflict(format!(
                    "operational incident {incident_id} version {expected_version} was already transitioned with different semantics"
                )));
            }
            let snapshot = receipt.snapshot()?;
            transaction.commit().await.map_err(|error| {
                persistence_error("commit adopted operational incident transition", error)
            })?;
            return Ok(snapshot);
        }

        let before = incident_from_row(&current_row)?;
        if before.aggregate_version != expected_version
            || before.status != transition.required_status()
        {
            return Err(Error::Conflict(format!(
                "operational incident {incident_id} is {} at version {}, expected {} at version {expected_version}",
                before.status.as_persisted(),
                before.aggregate_version,
                transition.required_status().as_persisted(),
            )));
        }

        let updated_row = update_incident(
            &mut transaction,
            tenant_id,
            incident_id,
            expected_version_i64,
            transition,
            actor,
            resolution,
        )
        .await?;
        let after = incident_from_row(&updated_row)?;
        if after.status != transition.resulting_status()
            || after.aggregate_version != expected_version + 1
        {
            return Err(Error::Persistence(
                "operational incident transition returned an invalid lifecycle snapshot".into(),
            ));
        }
        let occurred_at = transition_timestamp(&after, transition)?;
        let before_digest = lifecycle_digest(&before)?;
        let after_digest = lifecycle_digest(&after)?;
        let audit_event_id = Uuid::now_v7();
        let outbox_id = Uuid::now_v7();
        let correlation_id = format!("operational-incident:{incident_id}:{expected_version}");
        let details = json!({
            "schema": "asf.operational-incident-transition-audit/v1",
            "operational_incident_id": incident_id,
            "workflow_job_id": after.workflow_job_id,
            "transition": transition.kind(),
            "from_status": before.status,
            "to_status": after.status,
            "expected_version": expected_version,
            "result_aggregate_version": after.aggregate_version,
            "request_digest": request_digest,
            "resolution": resolution,
        });
        reject_sensitive_fields(&details)?;
        append_transition_audit(
            &mut transaction,
            &after,
            transition,
            actor,
            &correlation_id,
            audit_event_id,
            &before_digest,
            &after_digest,
            &details,
            occurred_at,
        )
        .await?;
        let outbox_payload = json!({
            "schema": "asf.operational-incident-lifecycle-event/v1",
            "tenant_id": tenant_id,
            "operational_incident_id": incident_id,
            "workflow_job_id": after.workflow_job_id,
            "transition": transition.kind(),
            "status": after.status,
            "actor": actor,
            "expected_version": expected_version,
            "aggregate_version": after.aggregate_version,
            "request_digest": request_digest,
            "resolution": resolution,
            "audit_event_id": audit_event_id,
            "occurred_at": occurred_at,
        });
        reject_sensitive_fields(&outbox_payload)?;
        insert_transition_outbox(
            &mut transaction,
            &after,
            transition,
            &correlation_id,
            outbox_id,
            &outbox_payload,
            occurred_at,
        )
        .await?;
        insert_transition_receipt(
            &mut transaction,
            &after,
            transition,
            expected_version_i64,
            &request_digest,
            audit_event_id,
            outbox_id,
            occurred_at,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| persistence_error("commit operational incident transition", error))?;
        Ok(after)
    }
}

async fn update_incident(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    incident_id: Uuid,
    expected_version: i64,
    transition: &OperationalIncidentTransition,
    actor: &str,
    resolution: Option<&str>,
) -> Result<PgRow> {
    let row = match transition {
        OperationalIncidentTransition::Acknowledge { .. } => {
            sqlx::query(
                r"
            UPDATE operational_incidents
            SET status = 'ACKNOWLEDGED',
                acknowledged_at = clock_timestamp(),
                acknowledged_by = $4,
                aggregate_version = aggregate_version + 1
            WHERE tenant_id = $1 AND id = $2
              AND status = 'OPEN' AND aggregate_version = $3
            RETURNING id, tenant_id, workflow_job_id, status, aggregate_version,
                      authority_or_effect_active, acknowledged_at, acknowledged_by,
                      closed_at, closed_by, resolution
            ",
            )
            .bind(tenant_id)
            .bind(incident_id)
            .bind(expected_version)
            .bind(actor)
            .fetch_optional(&mut **transaction)
            .await
        }
        OperationalIncidentTransition::Resolve { .. }
        | OperationalIncidentTransition::Cancel { .. } => {
            sqlx::query(
                r"
            UPDATE operational_incidents
            SET status = $4,
                closed_at = clock_timestamp(),
                closed_by = $5,
                resolution = $6,
                authority_or_effect_active = false,
                aggregate_version = aggregate_version + 1
            WHERE tenant_id = $1 AND id = $2
              AND status = 'ACKNOWLEDGED' AND aggregate_version = $3
            RETURNING id, tenant_id, workflow_job_id, status, aggregate_version,
                      authority_or_effect_active, acknowledged_at, acknowledged_by,
                      closed_at, closed_by, resolution
            ",
            )
            .bind(tenant_id)
            .bind(incident_id)
            .bind(expected_version)
            .bind(transition.resulting_status().as_persisted())
            .bind(actor)
            .bind(resolution)
            .fetch_optional(&mut **transaction)
            .await
        }
    }
    .map_err(|error| persistence_error("update operational incident lifecycle", error))?;
    row.ok_or_else(|| {
        Error::Conflict(format!(
            "operational incident {incident_id} lifecycle fence changed while locked"
        ))
    })
}

#[derive(Debug)]
struct StoredTransitionReceipt {
    request_digest: String,
    row: PgRow,
}

impl StoredTransitionReceipt {
    fn snapshot(&self) -> Result<OperationalIncidentLifecycle> {
        let version = self
            .row
            .try_get::<i64, _>("result_aggregate_version")
            .map_err(|error| persistence_error("decode incident receipt version", error))?;
        Ok(OperationalIncidentLifecycle {
            id: self
                .row
                .try_get("incident_id")
                .map_err(|error| persistence_error("decode incident receipt id", error))?,
            tenant_id: self
                .row
                .try_get("tenant_id")
                .map_err(|error| persistence_error("decode incident receipt tenant", error))?,
            workflow_job_id: self.row.try_get("workflow_job_id").map_err(|error| {
                persistence_error("decode incident receipt workflow job", error)
            })?,
            status: OperationalIncidentStatus::from_persisted(
                &self
                    .row
                    .try_get::<String, _>("result_status")
                    .map_err(|error| persistence_error("decode incident receipt status", error))?,
            )?,
            aggregate_version: positive_version(version, "incident receipt version")?,
            authority_or_effect_active: self
                .row
                .try_get("result_authority_or_effect_active")
                .map_err(|error| persistence_error("decode incident receipt authority", error))?,
            acknowledged_at: self.row.try_get("acknowledged_at").map_err(|error| {
                persistence_error("decode incident receipt acknowledgement time", error)
            })?,
            acknowledged_by: self.row.try_get("acknowledged_by").map_err(|error| {
                persistence_error("decode incident receipt acknowledgement actor", error)
            })?,
            closed_at: self
                .row
                .try_get("closed_at")
                .map_err(|error| persistence_error("decode incident receipt close time", error))?,
            closed_by: self
                .row
                .try_get("closed_by")
                .map_err(|error| persistence_error("decode incident receipt close actor", error))?,
            resolution: self
                .row
                .try_get("resolution")
                .map_err(|error| persistence_error("decode incident receipt resolution", error))?,
        })
    }
}

async fn load_transition_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    incident_id: Uuid,
    expected_version: i64,
) -> Result<Option<StoredTransitionReceipt>> {
    sqlx::query(
        r"
        SELECT tenant_id, incident_id, workflow_job_id, request_digest,
               result_status, result_aggregate_version,
               result_authority_or_effect_active, acknowledged_at,
               acknowledged_by, closed_at, closed_by, resolution
        FROM operational_incident_transition_receipts
        WHERE tenant_id = $1 AND incident_id = $2 AND expected_version = $3
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(expected_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load operational incident transition receipt", error))?
    .map(|row| {
        let request_digest = row
            .try_get("request_digest")
            .map_err(|error| persistence_error("decode incident receipt request digest", error))?;
        Ok(StoredTransitionReceipt {
            request_digest,
            row,
        })
    })
    .transpose()
}

async fn append_transition_audit(
    transaction: &mut Transaction<'_, Postgres>,
    incident: &OperationalIncidentLifecycle,
    transition: &OperationalIncidentTransition,
    actor: &str,
    correlation_id: &str,
    audit_event_id: Uuid,
    before_digest: &str,
    after_digest: &str,
    details: &Value,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(incident.tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock tenant audit chain", error))?;
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
    .bind(incident.tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load tenant audit-chain head", error))?;
    let event = HashedAuditEvent::create(AuditEventContent {
        id: EventId::from_uuid(audit_event_id),
        tenant_id: TenantId::from_uuid(incident.tenant_id),
        work_item_id: None,
        attempt_id: None,
        actor_type: "OPERATOR".into(),
        actor_id: actor.into(),
        action: transition.audit_action().into(),
        subject_type: "OPERATIONAL_INCIDENT".into(),
        subject_id: incident.id.to_string(),
        correlation_id: correlation_id.into(),
        trace_id: None,
        policy_digest: None,
        before_digest: Some(before_digest.into()),
        after_digest: Some(after_digest.into()),
        previous_event_hash,
        details: details.clone(),
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
            NULL, $9, $10, $11, $12, $13, $14
        )
        ",
    )
    .bind(event.content.id.as_uuid())
    .bind(incident.tenant_id)
    .bind(&event.content.actor_type)
    .bind(&event.content.actor_id)
    .bind(&event.content.action)
    .bind(&event.content.subject_type)
    .bind(&event.content.subject_id)
    .bind(&event.content.correlation_id)
    .bind(&event.content.before_digest)
    .bind(&event.content.after_digest)
    .bind(&event.content.previous_event_hash)
    .bind(&event.event_hash)
    .bind(&event.content.details)
    .bind(event.content.occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("append incident transition audit", error))?;
    Ok(())
}

async fn insert_transition_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    incident: &OperationalIncidentLifecycle,
    transition: &OperationalIncidentTransition,
    correlation_id: &str,
    outbox_id: Uuid,
    payload: &Value,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload, headers,
            idempotency_key, available_at
        ) VALUES ($1, $2, 'attention', $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(outbox_id)
    .bind(incident.tenant_id)
    .bind(incident.id.to_string())
    .bind(transition.event_type())
    .bind(payload)
    .bind(json!({"schema": "asf.operational-incident-lifecycle-event/v1"}))
    .bind(format!("{correlation_id}:outbox"))
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert incident transition outbox", error))?;
    Ok(())
}

async fn insert_transition_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    incident: &OperationalIncidentLifecycle,
    transition: &OperationalIncidentTransition,
    expected_version: i64,
    request_digest: &str,
    audit_event_id: Uuid,
    outbox_id: Uuid,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO operational_incident_transition_receipts (
            tenant_id, incident_id, workflow_job_id, expected_version,
            request_digest, transition_kind, result_status,
            result_aggregate_version, result_authority_or_effect_active,
            acknowledged_at, acknowledged_by, closed_at, closed_by,
            resolution, occurred_at, audit_event_id, outbox_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16, $17
        )
        ",
    )
    .bind(incident.tenant_id)
    .bind(incident.id)
    .bind(incident.workflow_job_id)
    .bind(expected_version)
    .bind(request_digest)
    .bind(transition.kind())
    .bind(incident.status.as_persisted())
    .bind(i64::try_from(incident.aggregate_version).map_err(|_error| {
        Error::Persistence("incident result version exceeds PostgreSQL bigint".into())
    })?)
    .bind(incident.authority_or_effect_active)
    .bind(incident.acknowledged_at)
    .bind(&incident.acknowledged_by)
    .bind(incident.closed_at)
    .bind(&incident.closed_by)
    .bind(&incident.resolution)
    .bind(occurred_at)
    .bind(audit_event_id)
    .bind(outbox_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert incident transition receipt", error))?;
    Ok(())
}

fn incident_from_row(row: &PgRow) -> Result<OperationalIncidentLifecycle> {
    let version = row
        .try_get::<i64, _>("aggregate_version")
        .map_err(|error| persistence_error("decode operational incident version", error))?;
    Ok(OperationalIncidentLifecycle {
        id: row
            .try_get("id")
            .map_err(|error| persistence_error("decode operational incident id", error))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|error| persistence_error("decode operational incident tenant", error))?,
        workflow_job_id: row
            .try_get("workflow_job_id")
            .map_err(|error| persistence_error("decode operational incident job", error))?,
        status: OperationalIncidentStatus::from_persisted(
            &row.try_get::<String, _>("status")
                .map_err(|error| persistence_error("decode operational incident status", error))?,
        )?,
        aggregate_version: positive_version(version, "operational incident version")?,
        authority_or_effect_active: row.try_get("authority_or_effect_active").map_err(|error| {
            persistence_error("decode operational incident authority state", error)
        })?,
        acknowledged_at: row.try_get("acknowledged_at").map_err(|error| {
            persistence_error("decode operational incident acknowledgement time", error)
        })?,
        acknowledged_by: row.try_get("acknowledged_by").map_err(|error| {
            persistence_error("decode operational incident acknowledgement actor", error)
        })?,
        closed_at: row
            .try_get("closed_at")
            .map_err(|error| persistence_error("decode operational incident close time", error))?,
        closed_by: row
            .try_get("closed_by")
            .map_err(|error| persistence_error("decode operational incident close actor", error))?,
        resolution: row
            .try_get("resolution")
            .map_err(|error| persistence_error("decode operational incident resolution", error))?,
    })
}

fn positive_version(value: i64, context: &str) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| Error::Persistence(format!("{context} is not positive")))
}

fn transition_timestamp(
    lifecycle: &OperationalIncidentLifecycle,
    transition: &OperationalIncidentTransition,
) -> Result<DateTime<Utc>> {
    match transition {
        OperationalIncidentTransition::Acknowledge { .. } => lifecycle.acknowledged_at,
        OperationalIncidentTransition::Resolve { .. }
        | OperationalIncidentTransition::Cancel { .. } => lifecycle.closed_at,
    }
    .ok_or_else(|| Error::Persistence("incident transition timestamp is absent".into()))
}

fn lifecycle_digest(lifecycle: &OperationalIncidentLifecycle) -> Result<String> {
    canonical_json(lifecycle).map(|bytes| sha256_digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_metadata_is_required() {
        assert!(
            OperationalIncidentTransition::Acknowledge { actor: " ".into() }
                .validate()
                .is_err()
        );
        assert!(
            OperationalIncidentTransition::Resolve {
                actor: "operator".into(),
                resolution: " ".into(),
            }
            .validate()
            .is_err()
        );
    }
}
