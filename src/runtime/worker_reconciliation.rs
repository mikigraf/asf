//! Production Runmill worker-health reconciliation.
//!
//! The private control client already validates the complete health response,
//! including sandbox and credential-denial proofs.  This activity turns that
//! read-side fact into a durable worker projection.  It never invents a worker
//! generation, session, or capability: those authority-bearing values must
//! already be registered in ASF.  Worker mutation, audit append, and workflow
//! job completion share one fenced `PostgreSQL` transaction.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, JobClaimScope, JobHandler, RECONCILE_WORKER,
    RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
};
use crate::{
    Error, Result,
    adapters::{
        RunmillControlClient, RunmillControlError, RunmillHealthComponent, RunmillHealthReport,
        RunmillHealthStatus, runmill_ready_health_is_fresh, runmill_ready_health_proofs_valid,
    },
    audit::{AuditEventContent, HashedAuditEvent},
    crypto::{canonical_json, sha256_digest},
    domain::{EventId, TenantId, WorkerCapabilities, WorkerId},
    ledger::{ClaimedWorkflowJob, PgLedger, release_active_worker_reservations},
    security::reject_sensitive_fields,
};

#[async_trait]
trait WorkerHealthControl: Send + Sync + fmt::Debug {
    async fn health(&self) -> std::result::Result<RunmillHealthReport, RunmillControlError>;
}

#[async_trait]
impl WorkerHealthControl for RunmillControlClient {
    async fn health(&self) -> std::result::Result<RunmillHealthReport, RunmillControlError> {
        RunmillControlClient::health(self).await
    }
}

/// Reconciles one configured ASF worker row with one private Runmill daemon.
#[derive(Clone)]
pub struct RunmillWorkerReconciliationHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    worker_id: WorkerId,
    control: Arc<dyn WorkerHealthControl>,
}

impl fmt::Debug for RunmillWorkerReconciliationHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillWorkerReconciliationHandler")
            .field("ledger", &self.ledger)
            .field("tenant_id", &self.tenant_id)
            .field("worker_id", &self.worker_id)
            .field("control", &"RunmillControlClient([REDACTED])")
            .finish()
    }
}

impl RunmillWorkerReconciliationHandler {
    #[must_use]
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: RunmillControlClient,
    ) -> Self {
        Self::with_control(ledger, tenant_id, worker_id, Arc::new(control))
    }

    fn with_control(
        ledger: PgLedger,
        tenant_id: TenantId,
        worker_id: WorkerId,
        control: Arc<dyn WorkerHealthControl>,
    ) -> Self {
        Self {
            ledger,
            tenant_id,
            worker_id,
            control,
        }
    }

    async fn reconcile(
        &self,
        job: &ClaimedWorkflowJob,
        observation: &HealthObservation,
    ) -> Result<ActivityOutcome> {
        let mut transaction =
            self.ledger.pool().begin().await.map_err(|error| {
                database_error("begin worker reconciliation transaction", &error)
            })?;
        lock_live_tenant_job(&mut transaction, job).await?;
        lock_worker_authority(
            &mut transaction,
            self.tenant_id.as_uuid(),
            self.worker_id.as_uuid(),
        )
        .await?;
        let worker = lock_worker(
            &mut transaction,
            self.tenant_id.as_uuid(),
            self.worker_id.as_uuid(),
        )
        .await?;
        let current_generation = positive_u64(
            required::<i64>(&worker, "generation", "worker generation")?,
            "worker generation",
        )?;
        let current_version = positive_u64(
            required::<i64>(&worker, "aggregate_version", "worker version")?,
            "worker version",
        )?;
        let payload = WorkerReconciliationPayload::parse(job, self.tenant_id, self.worker_id)?;

        let before_status: String = required(&worker, "status", "worker status")?;
        let before_digest = worker_fact_digest(
            self.worker_id,
            &before_status,
            current_generation,
            current_version,
            &required(&worker, "capabilities", "worker capabilities")?,
        )?;

        let superseded = current_generation != payload.expected_generation
            || current_version != payload.expected_version;
        let forced_safety_quarantine = superseded
            && observation.requested_status == "QUARANTINED"
            && before_status != "QUARANTINED";
        let (status, next_version, qualification_code) = if forced_safety_quarantine {
            let next_version = current_version
                .checked_add(1)
                .ok_or_else(|| Error::Conflict("worker version overflowed".into()))?;
            let changed = sqlx::query(
                r"
                UPDATE workers
                SET status = 'QUARANTINED',
                    last_seen_at = CASE WHEN $4 THEN clock_timestamp() ELSE last_seen_at END,
                    aggregate_version = aggregate_version + 1,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1
                  AND id = $2
                  AND aggregate_version = $3
                ",
            )
            .bind(self.tenant_id.as_uuid())
            .bind(self.worker_id.as_uuid())
            .bind(i64_from_u64(current_version, "worker version")?)
            .bind(observation.contact_succeeded)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("force safety quarantine", &error))?
            .rows_affected();
            if changed != 1 {
                return Err(Error::Conflict(format!(
                    "worker {} changed while safety quarantine was committing",
                    self.worker_id
                )));
            }
            ("QUARANTINED".to_owned(), next_version, observation.code)
        } else if superseded {
            (before_status.clone(), current_version, "SUPERSEDED")
        } else {
            let qualification = qualify_worker(&mut transaction, &worker, observation).await?;
            let next_version = current_version
                .checked_add(1)
                .ok_or_else(|| Error::Conflict("worker version overflowed".into()))?;
            let changed = sqlx::query(
                r"
                UPDATE workers
                SET status = $4,
                    last_seen_at = CASE WHEN $5 THEN clock_timestamp() ELSE last_seen_at END,
                    aggregate_version = aggregate_version + 1,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1
                  AND id = $2
                  AND aggregate_version = $3
                ",
            )
            .bind(self.tenant_id.as_uuid())
            .bind(self.worker_id.as_uuid())
            .bind(i64_from_u64(current_version, "worker version")?)
            .bind(qualification.status)
            .bind(observation.contact_succeeded)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("update reconciled worker", &error))?
            .rows_affected();
            if changed != 1 {
                return Err(Error::Conflict(format!(
                    "worker {} changed while reconciliation was committing",
                    self.worker_id
                )));
            }
            (
                qualification.status.to_owned(),
                next_version,
                qualification.code,
            )
        };
        let released_reservations = if status == "QUARANTINED" {
            // Quarantine is an invariant, not merely a state transition.  A
            // superseded reconciliation must still revoke any session created
            // after the original unsafe observation.
            let released = release_active_worker_reservations(
                &mut transaction,
                self.tenant_id.as_uuid(),
                self.worker_id.as_uuid(),
                job.lease_owner.as_str(),
                "Runmill health reconciliation quarantined the worker",
            )
            .await?;
            revoke_active_sessions(
                &mut transaction,
                self.tenant_id.as_uuid(),
                self.worker_id.as_uuid(),
            )
            .await?;
            released
        } else {
            0
        };

        let after_digest = worker_fact_digest(
            self.worker_id,
            &status,
            current_generation,
            next_version,
            &required(&worker, "capabilities", "worker capabilities")?,
        )?;
        let result = json!({
            "worker_id": self.worker_id,
            "status": status,
            "version": next_version,
            "generation": current_generation,
            "probe_code": observation.code,
            "qualification_code": qualification_code,
            "health_digest": observation.digest,
            "superseded": superseded,
            "forced_safety_quarantine": forced_safety_quarantine,
            "released_reservations": released_reservations,
        });
        reject_sensitive_fields(&result)?;
        append_worker_audit(
            &mut transaction,
            self.tenant_id,
            self.worker_id,
            job,
            if forced_safety_quarantine {
                "WORKER_RECONCILIATION_SAFETY_QUARANTINED"
            } else if superseded {
                "WORKER_RECONCILIATION_SUPERSEDED"
            } else {
                "WORKER_RECONCILED"
            },
            &before_digest,
            &after_digest,
            &result,
        )
        .await?;
        complete_tenant_job(&mut transaction, job, &result).await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_error("commit worker reconciliation transaction", &error))?;
        Ok(ActivityOutcome::TransactionCommitted)
    }
}

#[async_trait]
impl JobHandler for RunmillWorkerReconciliationHandler {
    fn job_type(&self) -> &str {
        RECONCILE_WORKER
    }

    fn activity_contract_id(&self) -> &str {
        RECONCILE_WORKER_ACTIVITY_CONTRACT_ID
    }

    fn claim_scope(&self) -> JobClaimScope {
        JobClaimScope::ReconcileWorker(self.worker_id)
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        WorkerReconciliationPayload::parse(job, self.tenant_id, self.worker_id)?;
        let observation = HealthObservation::from_result(self.control.health().await)?;
        self.reconcile(job, &observation).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReconciliationPayload {
    worker_id: WorkerId,
    expected_generation: u64,
    expected_version: u64,
}

impl WorkerReconciliationPayload {
    fn parse(job: &ClaimedWorkflowJob, tenant_id: TenantId, worker_id: WorkerId) -> Result<Self> {
        if job.job_type != RECONCILE_WORKER
            || job.activity_contract_id != RECONCILE_WORKER_ACTIVITY_CONTRACT_ID
            || job.tenant_id != tenant_id.as_uuid()
            || job.workflow_instance_id.is_some()
            || job.work_item_id.is_some()
            || job.attempt_id.is_some()
            || job.idempotency_key.trim().is_empty()
        {
            return Err(Error::Validation(
                "worker reconciliation job has invalid type, activity contract, tenant, binding, or idempotency"
                    .into(),
            ));
        }
        let payload: Self = serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!("invalid worker reconciliation payload: {error}"))
        })?;
        if payload.worker_id != worker_id
            || payload.worker_id.as_uuid().is_nil()
            || payload.expected_generation == 0
            || payload.expected_version == 0
        {
            return Err(Error::Validation(
                "worker reconciliation payload is not bound to the configured worker and positive fences"
                    .into(),
            ));
        }
        Ok(payload)
    }
}

struct HealthObservation {
    code: &'static str,
    digest: String,
    requested_status: &'static str,
    contact_succeeded: bool,
    ready_report: bool,
    reported_max_concurrency: Option<u64>,
}

impl HealthObservation {
    fn from_result(
        result: std::result::Result<RunmillHealthReport, RunmillControlError>,
    ) -> Result<Self> {
        let (code, requested_status, contact_succeeded, ready_report, reported, summary) =
            match result {
                Ok(report) => {
                    let (code, requested_status, ready_report) = match report.status {
                        RunmillHealthStatus::Ready
                            if !runmill_ready_health_proofs_valid(&report) =>
                        {
                            ("READY_PROOF_MISMATCH", "QUARANTINED", false)
                        }
                        RunmillHealthStatus::Ready
                            if !runmill_ready_health_is_fresh(&report, Utc::now()) =>
                        {
                            ("READY_REPORT_STALE", "QUARANTINED", false)
                        }
                        RunmillHealthStatus::Ready => ("RUNMILL_READY", "READY", true),
                        RunmillHealthStatus::Degraded => ("RUNMILL_DEGRADED", "DRAINING", false),
                        RunmillHealthStatus::Refusing => ("RUNMILL_REFUSING", "QUARANTINED", false),
                    };
                    let reported = report
                        .components
                        .worker
                        .details
                        .as_ref()
                        .and_then(|details| details.get("max_concurrency"))
                        .and_then(Value::as_u64);
                    let summary = health_summary(&report);
                    (
                        code,
                        requested_status,
                        true,
                        ready_report,
                        reported,
                        summary,
                    )
                }
                Err(error) => {
                    let (code, quarantine) = control_error_code(&error);
                    (
                        code,
                        if quarantine { "QUARANTINED" } else { "OFFLINE" },
                        false,
                        false,
                        None,
                        json!({"schema": "asf.runmill-health-observation/v1", "error": code}),
                    )
                }
            };
        reject_sensitive_fields(&summary)?;
        let digest = sha256_digest(&canonical_json(&summary)?);
        Ok(Self {
            code,
            digest,
            requested_status,
            contact_succeeded,
            ready_report,
            reported_max_concurrency: reported,
        })
    }
}

struct WorkerQualification {
    status: &'static str,
    code: &'static str,
}

async fn qualify_worker(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    observation: &HealthObservation,
) -> Result<WorkerQualification> {
    if required::<String>(row, "status", "worker status")? == "QUARANTINED" {
        return Ok(WorkerQualification {
            status: "QUARANTINED",
            code: "OPERATOR_UNQUARANTINE_REQUIRED",
        });
    }
    if observation.requested_status != "READY" || !observation.ready_report {
        return Ok(WorkerQualification {
            status: observation.requested_status,
            code: observation.code,
        });
    }

    let tenant_id: Uuid = required(row, "tenant_id", "worker tenant")?;
    let worker_id: Uuid = required(row, "id", "worker ID")?;
    let generation = positive_u64(
        required::<i64>(row, "generation", "worker generation")?,
        "worker generation",
    )?;
    let max_concurrency_i32: i32 = required(row, "max_concurrency", "worker concurrency")?;
    let max_concurrency = u16::try_from(max_concurrency_i32)
        .map_err(|_| Error::Persistence("worker concurrency exceeds u16".into()))?;
    if observation.reported_max_concurrency != Some(u64::from(max_concurrency)) {
        return Ok(WorkerQualification {
            status: "QUARANTINED",
            code: "CONCURRENCY_CONTRACT_MISMATCH",
        });
    }
    let capabilities: WorkerCapabilities =
        serde_json::from_value(required(row, "capabilities", "worker capabilities")?)
            .map_err(|error| Error::Persistence(format!("decode worker capabilities: {error}")))?;
    if !capabilities.production_qualified() {
        return Ok(WorkerQualification {
            status: "QUARANTINED",
            code: "CONFIGURED_CAPABILITIES_UNQUALIFIED",
        });
    }
    let active_slots_i64: i64 = required(row, "active_slots", "worker active slots")?;
    let active_slots = u16::try_from(active_slots_i64)
        .map_err(|_| Error::Persistence("worker active slots exceed u16".into()))?;
    let live_session = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM worker_sessions
        WHERE tenant_id = $1
          AND worker_id = $2
          AND worker_generation = $3
          AND status = 'ACTIVE'
          AND expires_at > clock_timestamp()
        ORDER BY expires_at DESC, id
        LIMIT 1
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(worker_id)
    .bind(i64_from_u64(generation, "worker generation")?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("verify live worker session", &error))?;
    if live_session.is_none() {
        return Ok(WorkerQualification {
            status: "REGISTERED",
            code: "WORKER_SESSION_MISSING",
        });
    }

    if let Some(qualification) = capacity_qualification(active_slots, max_concurrency) {
        return Ok(qualification);
    }
    Ok(WorkerQualification {
        status: "READY",
        code: "QUALIFIED",
    })
}

fn capacity_qualification(active_slots: u16, max_concurrency: u16) -> Option<WorkerQualification> {
    (active_slots >= max_concurrency).then_some(WorkerQualification {
        status: "DRAINING",
        code: "CAPACITY_FULL",
    })
}

fn health_summary(report: &RunmillHealthReport) -> Value {
    json!({
        "schema": "asf.runmill-health-observation/v1",
        "runmill_schema": report.schema,
        "mode": report.mode,
        "checked_at": report.checked_at,
        "status": health_status(report.status),
        "ready": report.ready,
        "components": {
            "service": component_summary(&report.components.service),
            "database": component_summary(&report.components.database),
            "worker": component_summary(&report.components.worker),
            "sandbox": component_summary(&report.components.sandbox),
            "ctxlane": component_summary(&report.components.ctxlane),
            "github": component_summary(&report.components.github),
            "mcp": component_summary(&report.components.mcp),
            "backlog": component_summary(&report.components.backlog),
        },
        "qualification_proofs": qualification_proof_summary(report),
    })
}

fn component_summary(component: &RunmillHealthComponent) -> Value {
    json!({
        "status": health_status(component.status),
        "observed_at": component.observed_at,
        "age_ms": component.age_ms,
        "reasons": component.reasons,
    })
}

fn qualification_proof_summary(report: &RunmillHealthReport) -> Value {
    let service = report.components.service.details.as_ref();
    let worker = report.components.worker.details.as_ref();
    let sandbox = report.components.sandbox.details.as_ref();
    let isolation = sandbox.and_then(|details| details.get("denial_proofs"));
    let ctxlane = report.components.ctxlane.details.as_ref();
    let github = report.components.github.details.as_ref();
    let mcp = report.components.mcp.details.as_ref();
    let backlog = report.components.backlog.details.as_ref();
    json!({
        "service_accepting": detail_bool(service, "accepting_submissions"),
        "recovery_complete": detail_bool(service, "recovery_complete"),
        "scheduler_running": detail_bool(worker, "scheduler_running"),
        "fencing_store_ready": detail_bool(worker, "fencing_store_ready"),
        "sandbox_installed": detail_bool(sandbox, "installed"),
        "sandbox_self_test": detail_bool(sandbox, "enforcement_self_test_passed"),
        "sandbox_not_downgraded": detail_bool(sandbox, "enforcement_downgraded")
            .map(|value| !value),
        "fresh_candidate_verification": detail_bool(sandbox, "fresh_candidate_verification"),
        "tool_network_enforced": detail_bool(sandbox, "tool_network_policy_enforced"),
        "verification_network_disabled": detail_bool(sandbox, "verification_network_disabled"),
        "isolation": {
            "provider_auth_denied": detail_bool(isolation, "provider_credentials"),
            "identity_broker_socket_denied": detail_bool(isolation, "ctxlane_socket"),
            "forge_auth_denied": detail_bool(isolation, "github_credentials"),
            "control_plane_auth_denied": detail_bool(isolation, "asf_credentials"),
            "backlog_auth_denied": detail_bool(isolation, "backlog_credentials"),
            "host_ssh_agent_denied": detail_bool(isolation, "host_ssh_agent"),
            "cloud_metadata_denied": detail_bool(isolation, "cloud_metadata"),
            "other_workspaces_denied": detail_bool(isolation, "other_workspaces"),
            "docker_socket_denied": detail_bool(isolation, "docker_socket"),
            "worker_control_denied": detail_bool(isolation, "mcp_control_endpoint"),
        },
        "identity_broker_reachable": detail_bool(ctxlane, "reachable"),
        "identity_broker_mutual_auth": detail_bool(ctxlane, "mutually_authenticated"),
        "identity_lease_probe": detail_bool(ctxlane, "automation_lease_probe_passed"),
        "forge_reachable": detail_bool(github, "reachable"),
        "forge_authenticated": detail_bool(github, "authenticated"),
        "forge_exact_head_ready": detail_bool(github, "exact_head_observation_ready"),
        "forge_reconciliation_ready": detail_bool(github, "reconciliation_ready"),
        "forge_admin_disabled": detail_bool(github, "administration_allowed")
            .map(|value| !value),
        "private_worker_control": detail_bool(mcp, "private_control_ready"),
        "controller_authenticated": detail_bool(mcp, "controller_authenticated"),
        "worker_control_not_exposed": detail_bool(mcp, "exposed_to_workers")
            .map(|value| !value),
        "backlog_selection_disabled": detail_bool(backlog, "selection_enabled")
            .map(|value| !value),
        "backlog_mutations_disabled": detail_bool(backlog, "mutations_enabled")
            .map(|value| !value),
    })
}

fn detail_bool(details: Option<&Value>, key: &str) -> Option<bool> {
    details
        .and_then(|details| details.get(key))
        .and_then(Value::as_bool)
}

const fn health_status(status: RunmillHealthStatus) -> &'static str {
    match status {
        RunmillHealthStatus::Ready => "ready",
        RunmillHealthStatus::Degraded => "degraded",
        RunmillHealthStatus::Refusing => "refusing",
    }
}

const fn control_error_code(error: &RunmillControlError) -> (&'static str, bool) {
    match error {
        RunmillControlError::InvalidConfiguration(_) => ("INVALID_CONFIGURATION", true),
        RunmillControlError::RegistryUnavailable => ("REGISTRY_UNAVAILABLE", false),
        RunmillControlError::InsecureRegistry(_) => ("INSECURE_REGISTRY", true),
        RunmillControlError::InsecureSocket(_) => ("INSECURE_SOCKET", true),
        RunmillControlError::UnsupportedProtocol { .. } => ("UNSUPPORTED_PROTOCOL", true),
        RunmillControlError::InvalidRequest(_) => ("INVALID_REQUEST", true),
        RunmillControlError::IncompatibleWorkOrderContract => ("INCOMPATIBLE_WORK_ORDER", true),
        RunmillControlError::RequestTooLarge => ("REQUEST_TOO_LARGE", true),
        RunmillControlError::ResponseTooLarge => ("RESPONSE_TOO_LARGE", true),
        RunmillControlError::Timeout => ("TIMEOUT", false),
        RunmillControlError::ResponseLost => ("RESPONSE_LOST", false),
        RunmillControlError::TransportUnavailable => ("TRANSPORT_UNAVAILABLE", false),
        RunmillControlError::MalformedResponse => ("MALFORMED_RESPONSE", true),
        RunmillControlError::RemoteRejected => ("REMOTE_REJECTED", false),
        RunmillControlError::RemoteAsf(_) => ("REMOTE_ASF_ERROR", false),
        RunmillControlError::AdmissionBindingMismatch => ("ADMISSION_BINDING_MISMATCH", true),
        RunmillControlError::AmbiguousOutcome { .. } => ("AMBIGUOUS_READ_OUTCOME", true),
    }
}

async fn lock_live_tenant_job(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
) -> Result<()> {
    let row = sqlx::query(
        r"
        SELECT status, workflow_instance_id, work_item_id, attempt_id,
               job_type, activity_contract_id, idempotency_key, lease_owner, fence_token,
               lease_expires_at > clock_timestamp() AS lease_is_live
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(job.tenant_id)
    .bind(job.id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock worker reconciliation job", &error))?
    .ok_or_else(|| Error::Conflict(format!("worker reconciliation job {} disappeared", job.id)))?;
    let exact = required::<String>(&row, "status", "job status")? == "RUNNING"
        && optional::<Uuid>(&row, "workflow_instance_id", "job workflow")?.is_none()
        && optional::<Uuid>(&row, "work_item_id", "job work item")?.is_none()
        && optional::<Uuid>(&row, "attempt_id", "job attempt")?.is_none()
        && required::<String>(&row, "job_type", "job type")? == RECONCILE_WORKER
        && required::<String>(&row, "activity_contract_id", "job activity contract")?
            == RECONCILE_WORKER_ACTIVITY_CONTRACT_ID
        && required::<String>(&row, "idempotency_key", "job idempotency")? == job.idempotency_key
        && optional::<String>(&row, "lease_owner", "job owner")?.as_deref()
            == Some(job.lease_owner.as_str())
        && required::<i64>(&row, "fence_token", "job fence")? == job.fence_token
        && required::<bool>(&row, "lease_is_live", "job lease status")?;
    if !exact {
        return Err(Error::Conflict(format!(
            "worker reconciliation job {} no longer owns its exact live claim",
            job.id
        )));
    }
    Ok(())
}

async fn lock_worker(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    worker_id: Uuid,
) -> Result<PgRow> {
    sqlx::query(
        r"
        SELECT worker.id, worker.tenant_id, worker.name, worker.endpoint,
               worker.status, worker.capabilities, worker.generation,
               worker.max_concurrency, worker.aggregate_version,
               COALESCE((
                   SELECT SUM(reservation.units)::bigint
                   FROM reservation_sets AS reservation_set
                   JOIN reservations AS reservation
                     ON reservation.tenant_id = reservation_set.tenant_id
                    AND reservation.reservation_set_id = reservation_set.id
                    AND reservation.kind = 'WORKER_SLOT'
                   WHERE reservation_set.tenant_id = worker.tenant_id
                     AND reservation_set.worker_id = worker.id
                     AND reservation_set.state = 'ACTIVE'
                     AND reservation_set.expires_at > clock_timestamp()
               ), 0::bigint) AS active_slots
        FROM workers AS worker
        WHERE worker.tenant_id = $1 AND worker.id = $2
        FOR UPDATE OF worker
        ",
    )
    .bind(tenant_id)
    .bind(worker_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock reconciled worker", &error))?
    .ok_or_else(|| Error::NotFound(format!("worker {worker_id}")))
}

async fn lock_worker_authority(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    worker_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("worker-authority:{tenant_id}:{worker_id}"))
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("lock worker authority", &error))?;
    Ok(())
}

async fn revoke_active_sessions(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    worker_id: Uuid,
) -> Result<()> {
    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'REVOKED',
            closed_at = clock_timestamp(),
            close_reason = 'Runmill health reconciliation quarantined the worker'
        WHERE tenant_id = $1
          AND worker_id = $2
          AND status = 'ACTIVE'
        ",
    )
    .bind(tenant_id)
    .bind(worker_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("revoke quarantined worker sessions", &error))?;
    Ok(())
}

async fn append_worker_audit(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    worker_id: WorkerId,
    job: &ClaimedWorkflowJob,
    action: &str,
    before_digest: &str,
    after_digest: &str,
    details: &Value,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(tenant_id.as_uuid())
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("lock worker audit chain", &error))?;
    let heads = sqlx::query_scalar::<_, String>(
        r"
        SELECT candidate.event_hash
        FROM audit_events AS candidate
        WHERE candidate.tenant_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS child
              WHERE child.tenant_id = candidate.tenant_id
                AND child.previous_event_hash = candidate.event_hash
          )
        ORDER BY candidate.ingested_at DESC, candidate.id DESC
        LIMIT 2
        ",
    )
    .bind(tenant_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| database_error("load worker audit-chain head", &error))?;
    if heads.len() > 1 {
        return Err(Error::Persistence(
            "tenant audit ledger contains multiple chain heads".into(),
        ));
    }
    let event = HashedAuditEvent::create(AuditEventContent {
        id: EventId::new(),
        tenant_id,
        work_item_id: None,
        attempt_id: None,
        actor_type: "SYSTEM".into(),
        actor_id: "runtime:runmill-worker-reconciliation".into(),
        action: action.into(),
        subject_type: "WORKER".into(),
        subject_id: worker_id.to_string(),
        correlation_id: format!("worker-reconciliation-job:{}", job.id),
        trace_id: None,
        policy_digest: None,
        before_digest: Some(before_digest.into()),
        after_digest: Some(after_digest.into()),
        previous_event_hash: heads.into_iter().next(),
        details: details.clone(),
        occurred_at: Utc::now(),
    })?;
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
    .bind(event.content.tenant_id.as_uuid())
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
    .map_err(|error| database_error("append worker reconciliation audit", &error))?;
    Ok(())
}

async fn complete_tenant_job(
    transaction: &mut Transaction<'_, Postgres>,
    job: &ClaimedWorkflowJob,
    result: &Value,
) -> Result<()> {
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
    .bind(result)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("complete worker reconciliation job", &error))?
    .rows_affected();
    if changed != 1 {
        return Err(Error::Conflict(format!(
            "worker reconciliation job {} lost its completion fence",
            job.id
        )));
    }
    Ok(())
}

fn worker_fact_digest(
    worker_id: WorkerId,
    status: &str,
    generation: u64,
    version: u64,
    capabilities: &Value,
) -> Result<String> {
    let fact = json!({
        "worker_id": worker_id,
        "status": status,
        "generation": generation,
        "version": version,
        "capabilities_digest": sha256_digest(&canonical_json(&capabilities)?),
    });
    Ok(sha256_digest(&canonical_json(&fact)?))
}

fn required<T>(row: &PgRow, name: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(name)
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))?
        .ok_or_else(|| Error::Persistence(format!("{context} is unexpectedly NULL")))
}

fn optional<T>(row: &PgRow, name: &str, context: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))
}

fn positive_u64(value: i64, context: &str) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| Error::Persistence(format!("{context} is not positive")))
}

fn i64_from_u64(value: u64, context: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| Error::Validation(format!("{context} exceeds PostgreSQL bigint capacity")))
}

fn database_error(context: &str, error: &impl fmt::Display) -> Error {
    Error::Persistence(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use std::time::Duration as StdDuration;

    use super::*;
    use crate::adapters::{RUNMILL_HEALTH_SCHEMA, RunmillHealthComponents};
    use chrono::DateTime;
    use url::Url;

    #[derive(Debug)]
    struct FixedHealthControl(RunmillHealthReport);

    #[async_trait]
    impl WorkerHealthControl for FixedHealthControl {
        async fn health(&self) -> std::result::Result<RunmillHealthReport, RunmillControlError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct InsecureHealthControl;

    #[async_trait]
    impl WorkerHealthControl for InsecureHealthControl {
        async fn health(&self) -> std::result::Result<RunmillHealthReport, RunmillControlError> {
            Err(RunmillControlError::InsecureSocket("group-writable"))
        }
    }

    #[derive(Debug)]
    struct TimeoutHealthControl;

    #[async_trait]
    impl WorkerHealthControl for TimeoutHealthControl {
        async fn health(&self) -> std::result::Result<RunmillHealthReport, RunmillControlError> {
            Err(RunmillControlError::Timeout)
        }
    }

    fn claimed_job(tenant_id: TenantId, worker_id: WorkerId) -> ClaimedWorkflowJob {
        claimed_job_at_version(tenant_id, worker_id, 1)
    }

    fn claimed_job_at_version(
        tenant_id: TenantId,
        worker_id: WorkerId,
        expected_version: u64,
    ) -> ClaimedWorkflowJob {
        let id = Uuid::now_v7();
        ClaimedWorkflowJob {
            id,
            tenant_id: tenant_id.as_uuid(),
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: RECONCILE_WORKER.into(),
            activity_contract_id: RECONCILE_WORKER_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({
                "worker_id": worker_id,
                "expected_generation": 1,
                "expected_version": expected_version,
            }),
            idempotency_key: format!("worker-reconcile:{id}"),
            priority: 50,
            attempt_count: 1,
            max_attempts: 3,
            fence_token: 1,
            lease_owner: "reactor:test".into(),
            lease_expires_at: Utc::now().trunc_subsecs(6) + chrono::Duration::minutes(5),
            created_at: Utc::now().trunc_subsecs(6),
        }
    }

    #[test]
    fn payload_is_exact_tenant_scoped_and_worker_bound() {
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let job = claimed_job(tenant_id, worker_id);
        WorkerReconciliationPayload::parse(&job, tenant_id, worker_id).expect("valid payload");

        let mut unknown = job.clone();
        unknown.payload["extra"] = json!(true);
        assert!(WorkerReconciliationPayload::parse(&unknown, tenant_id, worker_id).is_err());
        assert!(WorkerReconciliationPayload::parse(&job, tenant_id, WorkerId::new()).is_err());
        assert!(WorkerReconciliationPayload::parse(&job, TenantId::new(), worker_id).is_err());

        let mut wrong_job_type = job.clone();
        wrong_job_type.job_type = "SOME_OTHER_JOB".into();
        assert!(WorkerReconciliationPayload::parse(&wrong_job_type, tenant_id, worker_id).is_err());

        let mut wrong_contract = job;
        wrong_contract.activity_contract_id = "asf.activity/reconcile-worker/v2".into();
        assert!(matches!(
            WorkerReconciliationPayload::parse(&wrong_contract, tenant_id, worker_id),
            Err(Error::Validation(detail)) if detail.contains("activity contract")
        ));
    }

    #[test]
    fn unsafe_health_failures_quarantine_while_transport_loss_goes_offline() {
        let insecure = HealthObservation::from_result(Err(RunmillControlError::InsecureSocket(
            "group-writable",
        )))
        .expect("safe observation");
        assert_eq!(insecure.requested_status, "QUARANTINED");
        assert!(!insecure.contact_succeeded);

        let unavailable =
            HealthObservation::from_result(Err(RunmillControlError::TransportUnavailable))
                .expect("safe observation");
        assert_eq!(unavailable.requested_status, "OFFLINE");
        assert!(!unavailable.contact_succeeded);
        assert_ne!(insecure.digest, unavailable.digest);
    }

    #[test]
    fn ready_requires_true_fresh_proofs_and_refusing_is_quarantined() {
        let now = Utc::now().trunc_subsecs(6);
        let ready = HealthObservation::from_result(Ok(ready_health_report(now)))
            .expect("valid production-ready observation");
        assert_eq!(ready.requested_status, "READY");
        assert!(ready.ready_report);

        let mut unsafe_report = ready_health_report(now);
        unsafe_report.components.sandbox.details.as_mut().unwrap()["denial_proofs"]["provider_credentials"] =
            false.into();
        let unsafe_observation = HealthObservation::from_result(Ok(unsafe_report))
            .expect("unsafe proof is represented without sensitive details");
        assert_eq!(unsafe_observation.requested_status, "QUARANTINED");
        assert_eq!(unsafe_observation.code, "READY_PROOF_MISMATCH");

        let stale = HealthObservation::from_result(Ok(ready_health_report(
            now - chrono::Duration::minutes(2),
        )))
        .expect("stale report is represented");
        assert_eq!(stale.requested_status, "QUARANTINED");
        assert_eq!(stale.code, "READY_REPORT_STALE");

        let mut refusing_report = ready_health_report(now);
        refusing_report.status = RunmillHealthStatus::Refusing;
        refusing_report.ready = false;
        refusing_report.components.sandbox.status = RunmillHealthStatus::Refusing;
        refusing_report.components.sandbox.reasons = vec!["sandbox.denial_proof_failed".into()];
        let refusing = HealthObservation::from_result(Ok(refusing_report))
            .expect("refusing report is represented");
        assert_eq!(refusing.requested_status, "QUARANTINED");
        assert_eq!(refusing.code, "RUNMILL_REFUSING");
    }

    #[test]
    fn ordinary_capacity_saturation_drains_instead_of_quarantining() {
        let qualification = capacity_qualification(1, 1).expect("full capacity qualification");
        assert_eq!(qualification.status, "DRAINING");
        assert_eq!(qualification.code, "CAPACITY_FULL");
        assert!(capacity_qualification(0, 1).is_none());
    }

    struct ScopedDatabase {
        ledger: PgLedger,
        admin: sqlx::PgPool,
        schema: String,
    }

    impl ScopedDatabase {
        async fn create(database_url: &str) -> Self {
            let admin = sqlx::PgPool::connect(database_url)
                .await
                .expect("connect worker-reconciliation test administrator");
            let schema = format!("asf_worker_reconcile_{}", Uuid::now_v7().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated worker-reconciliation schema");
            let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated worker-reconciliation ledger");
            ledger
                .migrate()
                .await
                .expect("migrate isolated worker-reconciliation schema");
            Self {
                ledger,
                admin,
                schema,
            }
        }

        async fn cleanup(self) {
            self.ledger.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .expect("drop isolated worker-reconciliation schema");
            self.admin.close().await;
        }
    }

    #[tokio::test]
    async fn live_reconciliation_atomically_qualifies_worker_audits_and_completes_job() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let session_id = Uuid::now_v7();
        let job = claimed_job(tenant_id, worker_id);
        let now = Utc::now().trunc_subsecs(6);
        let capabilities = json!({
            "protocol_schema": "asf.control/v1",
            "work_order_schemas": ["asf.work-order/v1"],
            "evidence_schemas": ["runmill.evidence/v1"],
            "closure_targets": ["pr"],
            "sandbox_profiles": ["linux-production-v1"],
            "supports_cursor_events": true,
            "supports_idempotent_submission": true,
            "supports_signed_evidence": true
        });
        let mut transaction = database.ledger.pool().begin().await.expect("begin fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.as_uuid())
            .bind(format!("worker-reconcile-{tenant_id}"))
            .bind("Worker reconciliation test")
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
        sqlx::query(
            r"
            INSERT INTO workers (
                id, tenant_id, name, endpoint, status, capabilities,
                generation, max_concurrency, signing_key_id, signing_public_key
            ) VALUES (
                $1, $2, 'local-runmill', 'unix:private-control', 'REGISTERED',
                $3, 1, 1, 'runmill-test', 'base64url:test'
            )
            ",
        )
        .bind(worker_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(&capabilities)
        .execute(&mut *transaction)
        .await
        .expect("insert worker");
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 1, $4)
            ",
        )
        .bind(session_id)
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .bind(now + chrono::Duration::minutes(10))
        .execute(&mut *transaction)
        .await
        .expect("insert live worker session");
        insert_claimed_job(&mut transaction, &job).await;
        transaction.commit().await.expect("commit fixture");

        let handler = RunmillWorkerReconciliationHandler::with_control(
            database.ledger.clone(),
            tenant_id,
            worker_id,
            Arc::new(FixedHealthControl(ready_health_report(now))),
        );
        assert_eq!(
            handler
                .execute(&job, ActivityControls::new(true))
                .await
                .expect("reconcile worker during maintenance"),
            ActivityOutcome::TransactionCommitted
        );

        let worker = sqlx::query(
            "SELECT status, aggregate_version, last_seen_at FROM workers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .fetch_one(database.ledger.pool())
        .await
        .expect("load reconciled worker");
        assert_eq!(worker.try_get::<String, _>("status").unwrap(), "READY");
        assert_eq!(worker.try_get::<i64, _>("aggregate_version").unwrap(), 2);
        assert!(
            worker
                .try_get::<Option<DateTime<Utc>>, _>("last_seen_at")
                .unwrap()
                .is_some()
        );
        let completed = sqlx::query(
            "SELECT status, result, completed_by, completion_fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load completed worker job");
        assert_eq!(
            completed.try_get::<String, _>("status").unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            completed.try_get::<String, _>("completed_by").unwrap(),
            job.lease_owner
        );
        assert_eq!(
            completed
                .try_get::<i64, _>("completion_fence_token")
                .unwrap(),
            job.fence_token
        );
        let result: Value = completed.try_get("result").unwrap();
        assert_eq!(result["status"], "READY");
        assert_eq!(result["qualification_code"], "QUALIFIED");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT action FROM audit_events WHERE tenant_id = $1 AND subject_id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(worker_id.to_string())
            .fetch_one(database.ledger.pool())
            .await
            .expect("load worker audit"),
            "WORKER_RECONCILED"
        );

        let stale_job = claimed_job_at_version(tenant_id, worker_id, 1);
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin stale job");
        insert_claimed_job(&mut transaction, &stale_job).await;
        transaction.commit().await.expect("commit stale job");
        handler
            .execute(&stale_job, ActivityControls::new(false))
            .await
            .expect("complete superseded reconciliation");
        let stale_result = sqlx::query_scalar::<_, Value>(
            "SELECT result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(stale_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load superseded result");
        assert_eq!(stale_result["superseded"], true);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT aggregate_version FROM workers WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(worker_id.as_uuid())
            .fetch_one(database.ledger.pool())
            .await
            .expect("load worker version after stale job"),
            2
        );
        sqlx::query("UPDATE workers SET max_concurrency = 2 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id.as_uuid())
            .bind(worker_id.as_uuid())
            .execute(database.ledger.pool())
            .await
            .expect_err("worker capacity authority cannot change inside one generation");

        // A stale safe observation above is discardable.  A stale unsafe
        // observation is not: even though its expected version has been
        // superseded, it must quarantine current authority and revoke the
        // current session.
        let quarantine_job = claimed_job_at_version(tenant_id, worker_id, 1);
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin quarantine job");
        insert_claimed_job(&mut transaction, &quarantine_job).await;
        transaction.commit().await.expect("commit quarantine job");
        let quarantine_handler = RunmillWorkerReconciliationHandler::with_control(
            database.ledger.clone(),
            tenant_id,
            worker_id,
            Arc::new(InsecureHealthControl),
        );
        quarantine_handler
            .execute(&quarantine_job, ActivityControls::new(false))
            .await
            .expect("quarantine unsafe control socket");
        let quarantine_result = sqlx::query_scalar::<_, Value>(
            "SELECT result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(quarantine_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load forced safety quarantine result");
        assert_eq!(quarantine_result["superseded"], true);
        assert_eq!(quarantine_result["forced_safety_quarantine"], true);
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM workers WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(worker_id.as_uuid())
            .fetch_one(database.ledger.pool())
            .await
            .expect("load quarantined worker"),
            "QUARANTINED"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM worker_sessions WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(session_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load revoked worker session"),
            "REVOKED"
        );

        let replacement_session_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '10 minutes')
            ",
        )
        .bind(replacement_session_id)
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .execute(database.ledger.pool())
        .await
        .expect_err("quarantined worker cannot open a replacement session");
        let timeout_job = claimed_job_at_version(tenant_id, worker_id, 3);
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin quarantined timeout job");
        insert_claimed_job(&mut transaction, &timeout_job).await;
        transaction
            .commit()
            .await
            .expect("commit quarantined timeout job");
        let timeout_handler = RunmillWorkerReconciliationHandler::with_control(
            database.ledger.clone(),
            tenant_id,
            worker_id,
            Arc::new(TimeoutHealthControl),
        );
        timeout_handler
            .execute(&timeout_job, ActivityControls::new(false))
            .await
            .expect("transport timeout cannot weaken quarantine");
        let timeout_result = sqlx::query_scalar::<_, Value>(
            "SELECT result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(timeout_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load quarantined timeout result");
        assert_eq!(timeout_result["status"], "QUARANTINED");
        assert_eq!(
            timeout_result["qualification_code"],
            "OPERATOR_UNQUARANTINE_REQUIRED"
        );
        assert_eq!(timeout_result["released_reservations"], 0);

        let ready_recovery_session_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '10 minutes')
            ",
        )
        .bind(ready_recovery_session_id)
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .execute(database.ledger.pool())
        .await
        .expect_err("ready observation cannot pre-open a quarantined session");
        let recovery_job = claimed_job_at_version(tenant_id, worker_id, 4);
        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin ready recovery job");
        insert_claimed_job(&mut transaction, &recovery_job).await;
        transaction
            .commit()
            .await
            .expect("commit ready recovery job");
        handler
            .execute(&recovery_job, ActivityControls::new(false))
            .await
            .expect("ready report cannot automatically escape quarantine");
        let recovery_result = sqlx::query_scalar::<_, Value>(
            "SELECT result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(recovery_job.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load ready recovery result");
        assert_eq!(recovery_result["status"], "QUARANTINED");
        assert_eq!(
            recovery_result["qualification_code"],
            "OPERATOR_UNQUARANTINE_REQUIRED"
        );
        assert_eq!(recovery_result["released_reservations"], 0);

        sqlx::query("UPDATE workers SET status = 'REGISTERED' WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id.as_uuid())
            .bind(worker_id.as_uuid())
            .execute(database.ledger.pool())
            .await
            .expect_err("quarantine cannot be escaped inside the compromised generation");
        sqlx::query(
            r"
            UPDATE workers
            SET status = 'REGISTERED', generation = generation + 1,
                max_concurrency = 2, aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .execute(database.ledger.pool())
        .await
        .expect("clean next generation is the controlled quarantine repair path");
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 2, clock_timestamp() + interval '10 minutes')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id.as_uuid())
        .bind(worker_id.as_uuid())
        .execute(database.ledger.pool())
        .await
        .expect("repaired generation may open a new snapshotted session");

        database.cleanup().await;
    }

    #[tokio::test]
    async fn prelocked_worker_job_completion_does_not_reage_the_lease() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let mut job = claimed_job(tenant_id, worker_id);
        job.lease_expires_at = Utc::now().trunc_subsecs(6) + chrono::Duration::seconds(1);
        let mut fixture = database.ledger.pool().begin().await.expect("begin fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.as_uuid())
            .bind(format!("worker-prelock-{tenant_id}"))
            .bind("Worker prelocked completion test")
            .execute(&mut *fixture)
            .await
            .expect("insert prelock tenant");
        insert_claimed_job(&mut fixture, &job).await;
        fixture.commit().await.expect("commit prelock fixture");

        let mut finalizer = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin prelocked finalization");
        lock_live_tenant_job(&mut finalizer, &job)
            .await
            .expect("take ownership while lease is live");
        tokio::time::sleep(StdDuration::from_millis(1_200)).await;
        complete_tenant_job(
            &mut finalizer,
            &job,
            &json!({"schema": "asf.worker-prelock-regression/v1"}),
        )
        .await
        .expect("the prelocked owner remains entitled to finalize");
        finalizer
            .commit()
            .await
            .expect("commit prelocked finalization");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(job.id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load prelocked completed job"),
            "COMPLETED"
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn forged_wrong_contract_owning_row_cannot_satisfy_the_reconciliation_authority_sql() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let tenant_id = TenantId::new();
        let worker_id = WorkerId::new();
        let job = claimed_job(tenant_id, worker_id);
        let mut fixture = database.ledger.pool().begin().await.expect("begin fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.as_uuid())
            .bind(format!("worker-forged-contract-{tenant_id}"))
            .bind("Worker forged-contract test")
            .execute(&mut *fixture)
            .await
            .expect("insert forged-contract tenant");
        // The persisted row claims a different activity contract than the one
        // this handler is compiled to trust, even though its job_type is the
        // canonical RECONCILE_WORKER. The in-memory `job` still reports the
        // canonical contract, simulating a caller that trusts a stale or
        // forged claim: the database predicate, not the caller's struct,
        // must be what decides authority.
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, status, payload, idempotency_key,
                priority, attempt_count, max_attempts, fence_token,
                lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, 'RECONCILE_WORKER', 'asf.activity/reconcile-worker/v2', 'RUNNING', $3, $4,
                50, 1, 3, 1, $5, $6
            )
            ",
        )
        .bind(job.id)
        .bind(job.tenant_id)
        .bind(&job.payload)
        .bind(&job.idempotency_key)
        .bind(&job.lease_owner)
        .bind(job.lease_expires_at)
        .execute(&mut *fixture)
        .await
        .expect("insert forged wrong-contract claimed job");
        fixture
            .commit()
            .await
            .expect("commit forged-contract fixture");

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin forged-contract authority check");
        assert!(
            lock_live_tenant_job(&mut transaction, &job).await.is_err(),
            "a persisted row with a non-canonical activity contract must never satisfy \
             worker-reconciliation authority, regardless of the caller's claimed contract"
        );
        transaction
            .rollback()
            .await
            .expect("rollback forged-contract authority check");

        database.cleanup().await;
    }

    async fn insert_claimed_job(
        transaction: &mut Transaction<'_, Postgres>,
        job: &ClaimedWorkflowJob,
    ) {
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, status, payload, idempotency_key,
                priority, attempt_count, max_attempts, fence_token,
                lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, 'RECONCILE_WORKER', $3, 'RUNNING', $4, $5,
                50, 1, 3, 1, $6, $7
            )
            ",
        )
        .bind(job.id)
        .bind(job.tenant_id)
        .bind(&job.activity_contract_id)
        .bind(&job.payload)
        .bind(&job.idempotency_key)
        .bind(&job.lease_owner)
        .bind(job.lease_expires_at)
        .execute(&mut **transaction)
        .await
        .expect("insert claimed worker job");
    }

    fn ready_health_report(now: DateTime<Utc>) -> RunmillHealthReport {
        let component = |details| RunmillHealthComponent {
            status: RunmillHealthStatus::Ready,
            observed_at: Some(now),
            age_ms: Some(0),
            reasons: Vec::new(),
            details: Some(details),
        };
        let denial_proofs = json!({
            "provider_credentials": true,
            "ctxlane_socket": true,
            "github_credentials": true,
            "asf_credentials": true,
            "backlog_credentials": true,
            "host_ssh_agent": true,
            "cloud_metadata": true,
            "other_workspaces": true,
            "docker_socket": true,
            "mcp_control_endpoint": true
        });
        RunmillHealthReport {
            schema: RUNMILL_HEALTH_SCHEMA.into(),
            mode: "asf-worker".into(),
            checked_at: now,
            probe_duration_ms: 1,
            status: RunmillHealthStatus::Ready,
            ready: true,
            components: RunmillHealthComponents {
                service: component(json!({
                    "mode": "asf-worker",
                    "state": "running",
                    "accepting_submissions": true,
                    "recovery_complete": true
                })),
                database: component(json!({
                    "reachable": true,
                    "schema_version": 1,
                    "integrity_check_passed": true,
                    "write_probe_passed": true,
                    "expected_schema_version": 1
                })),
                worker: component(json!({
                    "heartbeat_at": now,
                    "scheduler_running": true,
                    "fencing_store_ready": true,
                    "max_concurrency": 1,
                    "active_runs": 0,
                    "queued_runs": 0,
                    "expected_max_concurrency": 1,
                    "heartbeat_age_ms": 0,
                    "available_capacity": 1
                })),
                sandbox: component(json!({
                    "mechanism": "bubblewrap",
                    "installed": true,
                    "enforcement_self_test_passed": true,
                    "enforcement_downgraded": false,
                    "fresh_candidate_verification": true,
                    "tool_network_policy_enforced": true,
                    "verification_network_disabled": true,
                    "denial_proofs": denial_proofs
                })),
                ctxlane: component(json!({
                    "reachable": true,
                    "mutually_authenticated": true,
                    "automation_lease_probe_passed": true
                })),
                github: component(json!({
                    "credential_in_controller": true,
                    "reachable": true,
                    "authenticated": true,
                    "repository_reachable": true,
                    "branch_push_allowed": true,
                    "pull_request_create_allowed": true,
                    "exact_head_observation_ready": true,
                    "ci_context_read_ready": true,
                    "reconciliation_ready": true,
                    "merge_allowed": false,
                    "administration_allowed": false
                })),
                mcp: component(json!({
                    "private_control_ready": true,
                    "controller_authenticated": true,
                    "exposed_to_workers": false
                })),
                backlog: component(json!({
                    "selection_enabled": false,
                    "mutations_enabled": false
                })),
            },
        }
    }
}
