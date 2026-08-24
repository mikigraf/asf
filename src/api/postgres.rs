//! `PostgreSQL` implementation of the operator API.
//!
//! Reads are tenant-scoped and mutations use the authoritative ledger tables.
//! Every API mutation is paired with an idempotency record in the same
//! transaction as its job/aggregate/audit writes.

use std::fmt;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    API_INTAKE_RECEIPT_SCHEMA_V1, API_INTAKE_REQUEST_SCHEMA_V1, ApiBackend, ApiIntakeDisposition,
    ApiIntakeReceipt, ApiIntakeRequest, ApprovalDecisionRequest, AttentionItemView,
    CancellationRequest, EvidenceView, MutationReceipt, Page, PageQuery, VersionedMutation,
    WorkItemDetail, WorkItemView, WorkerView,
};
use crate::{
    Error, Result,
    application::{
        AttentionItem as ApplicationAttentionItem, AttentionItemKind, AttentionObligationKind,
        AttentionProjectionError, AttentionSeverity, PersistedAttentionItem,
        UncoveredAttentionObligation,
    },
    audit::{AuditEventContent, HashedAuditEvent},
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
    domain::{
        ApprovalId, AttemptId, BudgetLimits, ClosureTarget, EscalationCategory, EventId,
        EvidenceId, RepositoryId, RiskClass, SourceSnapshot, SourceSnapshotContent,
        SourceSnapshotId, SourceSystem, TenantId, WorkItemId, WorkItemState, WorkOrderIdentities,
        WorkerId,
    },
    ledger::PgLedger,
    runtime::{
        ADVANCE_ACCEPTED_WORK_ITEM, ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        APPLY_SIGNED_APPROVAL_DECISION, APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID,
        ApiActivityCapabilities, CLOSE_SOURCE, HandlerRegistry, INTAKE_SYNC,
        INTAKE_SYNC_ACTIVITY_CONTRACT_ID, IntakeOutcome, IntakeProvenance, IntakeTransactionWriter,
        OBSERVE_RUNMILL_RUN, RECONCILE_WORKER, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
        REQUEST_WORK_ITEM_CANCELLATION, REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
        VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID, validate_snapshot_core,
    },
    security::{Caller, reject_sensitive_fields},
};

const CURSOR_VERSION: u8 = 1;
const IDEMPOTENCY_RETENTION_DAYS: i32 = 7;
const DETAIL_EVENT_LIMIT: i64 = 100;

const OP_INTAKE_SYNC: &str = "api.intake.sync";
const OP_API_INTAKE: &str = "api.intake";
const OP_ACCEPT_WORK_ITEM: &str = "api.work_item.accept";
const OP_CANCEL_WORK_ITEM: &str = "api.work_item.cancel";
const OP_DECIDE_APPROVAL: &str = "api.approval.decision";
const OP_RECONCILE_WORKER: &str = "api.worker.reconcile";
const OP_VERIFY_EVIDENCE: &str = "api.evidence.verify";

/// Stable, server-fixed connector identity for candidate snapshots submitted through direct
/// API intake. Never derived from caller input.
const API_INTAKE_CONNECTOR_IDENTITY: &str = "asf-api:v1";

/// Tenant-bound `PostgreSQL` API backend.
#[derive(Clone)]
pub struct PostgresApiBackend {
    pool: PgPool,
    tenant_id: TenantId,
    activity_capabilities: ApiActivityCapabilities,
}

impl fmt::Debug for PostgresApiBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresApiBackend")
            .field("tenant_id", &self.tenant_id)
            .field("activity_capabilities", &self.activity_capabilities)
            .field("pool", &"PgPool")
            .finish()
    }
}

impl PostgresApiBackend {
    /// Construct a tenant-bound backend from an existing pool.
    #[must_use]
    pub fn new(pool: PgPool, tenant_id: TenantId) -> Self {
        Self {
            pool,
            tenant_id,
            activity_capabilities: HandlerRegistry::new().api_activity_capabilities(),
        }
    }

    /// Reuse the centrally configured ledger pool.
    #[must_use]
    pub fn from_ledger(ledger: &PgLedger, tenant_id: TenantId) -> Self {
        Self::new(ledger.pool().clone(), tenant_id)
    }

    /// Bind API mutation authority to the activity registry installed in this
    /// same process. The safe default grants neither capability.
    #[must_use]
    pub fn with_activity_capabilities(mut self, capabilities: ApiActivityCapabilities) -> Self {
        self.activity_capabilities = capabilities;
        self
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    fn require_bound_tenant(&self, tenant_id: TenantId) -> Result<Uuid> {
        if tenant_id != self.tenant_id {
            return Err(Error::NotFound("tenant".into()));
        }
        Ok(tenant_id.as_uuid())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysetCursor {
    version: u8,
    kind: String,
    at: DateTime<Utc>,
    id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttentionKeysetCursor {
    version: u8,
    kind: String,
    severity: AttentionSeverity,
    deadline: DateTime<Utc>,
    id: Uuid,
}

#[derive(Debug)]
struct IdempotencyClaim<T> {
    record_id: Uuid,
    replay: Option<T>,
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ApiBackend for PostgresApiBackend {
    async fn health(&self) -> Result<()> {
        let value = sqlx::query_scalar::<_, i32>("SELECT 1::integer")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| database_error("PostgreSQL health query", &error))?;
        if value == 1 {
            Ok(())
        } else {
            Err(Error::Persistence(
                "PostgreSQL health query returned an unexpected value".into(),
            ))
        }
    }

    async fn ready(&self) -> Result<()> {
        let ready = sqlx::query_scalar::<_, bool>(
            r"
            SELECT
                tenant.status = 'ACTIVE'
                AND EXISTS (
                    SELECT 1
                    FROM v1_tenant_deployment_guards AS guard
                    WHERE guard.singleton
                      AND guard.configured_tenant_id = tenant.id
                )
                AND to_regclass('workflow_jobs') IS NOT NULL
                AND to_regclass('idempotency_records') IS NOT NULL
                AND to_regclass('audit_events') IS NOT NULL
            FROM tenants AS tenant
            WHERE tenant.id = $1
            ",
        )
        .bind(self.tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("PostgreSQL readiness query", &error))?
        .unwrap_or(false);
        if !ready {
            return Err(Error::ExternalUnavailable(
                "tenant or PostgreSQL ledger is not ready".into(),
            ));
        }

        let production_job_types = [
            INTAKE_SYNC,
            ADVANCE_ACCEPTED_WORK_ITEM,
            REQUEST_WORK_ITEM_CANCELLATION,
            APPLY_SIGNED_APPROVAL_DECISION,
            RECONCILE_WORKER,
            OBSERVE_RUNMILL_RUN,
            VERIFY_EVIDENCE,
            CLOSE_SOURCE,
        ]
        .map(str::to_owned);
        let live_routes = sqlx::query(
            r"
            SELECT
                job.job_type,
                job.activity_contract_id,
                CASE
                    WHEN job.job_type IN (
                        'RECONCILE_WORKER',
                        'REQUEST_WORK_ITEM_CANCELLATION',
                        'OBSERVE_RUNMILL_RUN'
                    ) THEN job.payload ->> 'worker_id'
                    ELSE NULL
                END AS worker_id,
                count(*)::bigint AS obligation_count
            FROM workflow_jobs AS job
            WHERE job.tenant_id = $1
              AND job.job_type = ANY($2::text[])
              AND job.status IN ('PENDING', 'RETRY', 'RUNNING')
            GROUP BY job.job_type, job.activity_contract_id, worker_id
            ORDER BY job.job_type, job.activity_contract_id, worker_id NULLS FIRST
            ",
        )
        .bind(self.tenant_id.as_uuid())
        .bind(production_job_types.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|error| database_error("unserviceable activity readiness query", &error))?;
        let mut obligations = Vec::new();
        for row in &live_routes {
            let job_type: String = required(row, "job_type", "live production job type")?;
            // The persisted, immutable contract identity this exact job was
            // created with — never a canonical identity re-derived from
            // job_type, which would hide a stored job bound to an
            // incompatible (e.g. superseded or not-yet-supported) contract.
            let activity_contract_id: String = required(
                row,
                "activity_contract_id",
                "live production job activity contract id",
            )?;
            let worker_id: Option<String> =
                optional(row, "worker_id", "live production job worker route")?;
            let route_is_supported = self.activity_capabilities.supports_persisted_job_route(
                &job_type,
                &activity_contract_id,
                worker_id.as_deref(),
            );
            if route_is_supported {
                continue;
            }
            let count: i64 = required(row, "obligation_count", "live obligation count")?;
            if matches!(
                job_type.as_str(),
                RECONCILE_WORKER | REQUEST_WORK_ITEM_CANCELLATION | OBSERVE_RUNMILL_RUN
            ) {
                let route = match worker_id {
                    Some(worker_id) => worker_id,
                    None => "<missing>".into(),
                };
                obligations.push(format!(
                    "{job_type}[worker_id={route}, activity_contract_id={activity_contract_id}]={count}"
                ));
            } else {
                obligations.push(format!(
                    "{job_type}[activity_contract_id={activity_contract_id}]={count}"
                ));
            }
        }
        if obligations.is_empty() {
            return Ok(());
        }
        Err(Error::ExternalUnavailable(format!(
            "unavailable durable activities own live obligations: {}",
            obligations.join(", ")
        )))
    }

    async fn intake_sync(&self, caller: &Caller, idempotency_key: &str) -> Result<MutationReceipt> {
        validate_mutation_identity(caller, idempotency_key)?;
        let tenant_id = self.tenant_id.as_uuid();
        let request = json!({"tenant_id": tenant_id, "action": "sync"});
        let request_digest = digest_value(&request)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_INTAKE_SYNC,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        if !self
            .activity_capabilities
            .supports_unscoped(INTAKE_SYNC, INTAKE_SYNC_ACTIVITY_CONTRACT_ID)
        {
            return Err(Error::ExternalUnavailable(
                "intake-sync activity is unavailable; refusing to create an orphaned intake obligation"
                    .into(),
            ));
        }

        let job_id = Uuid::now_v7();
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: None,
                work_item_id: None,
                attempt_id: None,
                job_type: INTAKE_SYNC,
                activity_contract_id: INTAKE_SYNC_ACTIVITY_CONTRACT_ID,
                payload: &request,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_INTAKE_SYNC,
                    idempotency_key,
                ),
                priority: 0,
            },
        )
        .await?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: None,
                attempt_id: None,
                actor: caller,
                action: "INTAKE_SYNC_QUEUED",
                subject_type: "TENANT",
                subject_id: &tenant_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: None,
                before_digest: None,
                after_digest: Some(&request_digest),
                details: &json!({"job_id": job_id}),
            },
        )
        .await?;
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: job_id.to_string(),
            status: "queued".into(),
            version: None,
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 202).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn intake(
        &self,
        request: &ApiIntakeRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<ApiIntakeReceipt> {
        validate_mutation_identity(caller, idempotency_key)?;
        if request.schema_version != API_INTAKE_REQUEST_SCHEMA_V1 {
            return Err(Error::Validation(format!(
                "unsupported intake request schema {}",
                request.schema_version
            )));
        }
        let request_value = serde_json::to_value(request)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        reject_sensitive_fields(&request_value)?;
        let request_digest = digest_value(&request_value)?;

        let tenant_id = self.tenant_id.as_uuid();
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim: IdempotencyClaim<ApiIntakeReceipt> = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_API_INTAKE,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }

        let repository_row = sqlx::query(
            r"
            SELECT owner, name
            FROM repositories
            WHERE tenant_id = $1 AND id = $2 AND active
            FOR SHARE
            ",
        )
        .bind(tenant_id)
        .bind(request.repository_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("lock API intake repository", &error))?
        .ok_or_else(|| Error::NotFound(format!("repository {}", request.repository_id)))?;
        let owner: String = required(&repository_row, "owner", "API intake repository owner")?;
        let name: String = required(&repository_row, "name", "API intake repository name")?;
        let repository_hint = format!("{owner}/{name}");

        let now = Utc::now();
        let content = SourceSnapshotContent {
            source: SourceSystem::Api,
            external_id: request.external_id.clone(),
            source_revision: request.source_revision.clone(),
            source_url: request.source_url.clone(),
            title: request.title.clone(),
            objective: request.objective.clone(),
            acceptance_criteria: request.acceptance_criteria.clone(),
            non_goals: request.non_goals.clone(),
            labels: request.labels.clone(),
            normalized_priority: request.normalized_priority,
            source_state: request.source_state.clone(),
            assignee: request.assignee.clone(),
            repository_hint: Some(repository_hint),
            source_updated_at: request.source_updated_at,
        };
        let snapshot = SourceSnapshot::create(
            self.tenant_id,
            Some(request.repository_id),
            content,
            API_INTAKE_CONNECTOR_IDENTITY.into(),
            now,
        )?;
        validate_snapshot_core(&snapshot, self.tenant_id)?;

        let mut writer = IntakeTransactionWriter::lock(&mut transaction, self.tenant_id).await?;
        let result = writer
            .persist_snapshot(
                &snapshot,
                &claim.record_id.to_string(),
                IntakeProvenance::ApiCaller(caller),
                now,
            )
            .await?;
        drop(writer);

        let disposition = match result.outcome {
            IntakeOutcome::Discovered => ApiIntakeDisposition::Discovered,
            IntakeOutcome::Unchanged => ApiIntakeDisposition::Unchanged,
            IntakeOutcome::ReadinessRequeued => ApiIntakeDisposition::ReadinessRequeued,
            IntakeOutcome::AuthorityReevaluationRequired => {
                ApiIntakeDisposition::AuthorityReevaluationRequired
            }
        };
        let receipt = ApiIntakeReceipt {
            schema_version: API_INTAKE_RECEIPT_SCHEMA_V1.into(),
            idempotency_key: idempotency_key.into(),
            work_item_id: WorkItemId::from_uuid(result.work_item_id),
            source_snapshot_id: SourceSnapshotId::from_uuid(result.snapshot_id),
            content_digest: result.content_digest,
            disposition,
            state: result.work_item_state,
            version: result.aggregate_version,
            accepted: result.already_accepted,
        };
        let response_status = if disposition == ApiIntakeDisposition::Discovered {
            201
        } else {
            200
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, response_status).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn list_work_items(
        &self,
        tenant_id: TenantId,
        page: &PageQuery,
    ) -> Result<Page<WorkItemView>> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let cursor = decode_cursor(page.cursor.as_deref(), "work-items")?;
        let (cursor_at, cursor_id) = cursor_parts(cursor);
        let mut rows = sqlx::query(
            r"
            SELECT
                id, source_system, source_external_id, repository_id, state,
                closure_target, risk_class, normalized_priority, owner_fallback,
                due_at, aggregate_version, discovered_at, updated_at
            FROM work_items
            WHERE tenant_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR (updated_at, id) < ($2::timestamptz, $3::uuid)
              )
            ORDER BY updated_at DESC, id DESC
            LIMIT $4
            ",
        )
        .bind(tenant_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(i64::from(page.limit) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| database_error("list work items", &error))?;
        let has_more = rows.len() > usize::from(page.limit);
        rows.truncate(usize::from(page.limit));
        let next_cursor = if has_more {
            rows.last()
                .map(|row| cursor_from_row(row, "work-items", "updated_at"))
                .transpose()?
        } else {
            None
        };
        let items = rows.iter().map(work_item_from_row).collect::<Result<_>>()?;
        Ok(Page { items, next_cursor })
    }

    async fn get_work_item(&self, tenant_id: TenantId, id: WorkItemId) -> Result<WorkItemDetail> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let work_item_id = id.as_uuid();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin work-item read", &error))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("configure work-item read", &error))?;

        let row = sqlx::query(
            r"
            SELECT
                work.id, work.source_system, work.source_external_id,
                work.repository_id, work.state, work.closure_target,
                work.risk_class, work.normalized_priority, work.owner_fallback,
                work.due_at, work.aggregate_version, work.discovered_at,
                work.updated_at,
                jsonb_build_object(
                    'id', snapshot.id,
                    'source_system', snapshot.source_system,
                    'external_id', snapshot.external_id,
                    'source_revision', snapshot.source_revision,
                    'source_url', snapshot.source_url,
                    'content_digest', snapshot.content_digest,
                    'normalized_content', snapshot.normalized_content,
                    'captured_at', snapshot.captured_at,
                    'source_updated_at', snapshot.source_updated_at
                ) AS source_snapshot
            FROM work_items AS work
            JOIN source_snapshots AS snapshot
              ON snapshot.tenant_id = work.tenant_id
             AND snapshot.id = work.source_snapshot_id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("get work item", &error))?
        .ok_or_else(|| Error::NotFound(format!("work item {id}")))?;
        let work_item = work_item_from_row(&row)?;
        let source_snapshot = sanitized_column(&row, "source_snapshot")?;

        let plan = fetch_optional_json(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'id', id,
                'version', plan_version,
                'status', status,
                'proposal', proposal,
                'proposal_digest', proposal_digest,
                'planner_digest', planner_digest,
                'created_by', created_by,
                'created_at', created_at,
                'decided_at', decided_at
            ) AS value
            FROM plans
            WHERE tenant_id = $1 AND work_item_id = $2
            ORDER BY plan_version DESC
            LIMIT 1
            ",
            tenant_id,
            work_item_id,
            "load work-item plan",
        )
        .await?;
        let policy = fetch_optional_json(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'digest', policy.digest,
                'scope', policy.scope,
                'schema_version', policy.schema_version,
                'repository_id', policy.repository_id,
                'policy', policy.policy,
                'created_at', policy.created_at,
                'expires_at', policy.expires_at
            ) AS value
            FROM work_items AS work
            JOIN policy_versions AS policy
              ON policy.tenant_id = work.tenant_id
             AND policy.digest = work.policy_digest
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
            tenant_id,
            work_item_id,
            "load work-item policy",
        )
        .await?;
        let dependencies = fetch_json_list(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'work_item_id', dependency.depends_on_work_item_id,
                'type', dependency.dependency_type,
                'state', depended.state,
                'source_external_id', depended.source_external_id
            ) AS value
            FROM dependencies AS dependency
            JOIN work_items AS depended
              ON depended.tenant_id = dependency.tenant_id
             AND depended.id = dependency.depends_on_work_item_id
            WHERE dependency.tenant_id = $1 AND dependency.work_item_id = $2
            ORDER BY dependency.depends_on_work_item_id
            ",
            tenant_id,
            work_item_id,
            "load work-item dependencies",
        )
        .await?;
        let attempts = fetch_json_list(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'id', id,
                'ordinal', ordinal,
                'state', state,
                'base_ref', base_ref,
                'base_sha', base_sha,
                'source_snapshot_digest', source_snapshot_digest,
                'policy_digest', policy_digest,
                'work_order_digest', work_order_digest,
                'fence_token', fence_token,
                'version', aggregate_version,
                'created_at', created_at,
                'started_at', started_at,
                'terminal_at', terminal_at,
                'updated_at', updated_at
            ) AS value
            FROM attempts
            WHERE tenant_id = $1 AND work_item_id = $2
            ORDER BY ordinal DESC
            ",
            tenant_id,
            work_item_id,
            "load work-item attempts",
        )
        .await?;
        let events = fetch_work_item_events(
            &mut transaction,
            tenant_id,
            work_item_id,
            None,
            None,
            DETAIL_EVENT_LIMIT,
        )
        .await?;
        let evidence = fetch_json_list(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'id', evidence.id,
                'attempt_id', evidence.attempt_id,
                'run_id', evidence.run_id,
                'payload_digest', evidence.payload_digest,
                'work_order_digest', evidence.work_order_digest,
                'candidate_sha', evidence.candidate_sha,
                'requested_target', evidence.requested_target,
                'target_satisfied', evidence.target_satisfied,
                'produced_at', evidence.produced_at,
                'verification_status', verification.status,
                'verified_at', verification.verified_at
            ) AS value
            FROM evidence_bundles AS evidence
            LEFT JOIN runs AS run
              ON run.tenant_id = evidence.tenant_id AND run.id = evidence.run_id
            LEFT JOIN evidence_verifications AS verification
              ON verification.tenant_id = evidence.tenant_id
             AND verification.evidence_id = evidence.id
             AND verification.expectation_digest = run.evidence_expectation_digest
            WHERE evidence.tenant_id = $1 AND evidence.work_item_id = $2
            ORDER BY evidence.produced_at DESC, evidence.id DESC
            ",
            tenant_id,
            work_item_id,
            "load work-item evidence",
        )
        .await?;
        let accountability = fetch_optional_json(
            &mut transaction,
            r"
            SELECT jsonb_build_object(
                'kind', anchor_type,
                'reference_id', reference_id,
                'wake_or_deadline_at', wake_or_deadline_at,
                'authority_or_effect_active', authority_or_effect_active,
                'generation', generation,
                'updated_at', updated_at
            ) AS value
            FROM accountability_anchors
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
            tenant_id,
            work_item_id,
            "load work-item accountability",
        )
        .await?;
        commit_transaction(transaction).await?;
        Ok(WorkItemDetail {
            work_item,
            source_snapshot,
            readiness: None,
            plan,
            policy,
            dependencies,
            attempts,
            events,
            evidence,
            accountability,
        })
    }

    async fn accept_work_item(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        request: &VersionedMutation,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        validate_mutation_identity(caller, idempotency_key)?;
        let work_item_id = id.as_uuid();
        let request_value = json!({
            "work_item_id": work_item_id,
            "expected_version": request.expected_version,
        });
        let request_digest = digest_value(&request_value)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_ACCEPT_WORK_ITEM,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        if !self.activity_capabilities.supports_unscoped(
            ADVANCE_ACCEPTED_WORK_ITEM,
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        ) {
            return Err(Error::ExternalUnavailable(
                "accepted-work activity is unavailable; refusing to create an orphaned accepted obligation"
                    .into(),
            ));
        }

        let row = lock_work_item(&mut transaction, tenant_id, work_item_id).await?;
        let state: String = required(&row, "state", "work-item state")?;
        let version = positive_u64(
            required::<i64>(&row, "aggregate_version", "work-item version")?,
            "work-item version",
        )?;
        require_expected_version("work item", request.expected_version, version)?;
        if state != "READY" {
            return Err(Error::InvalidTransition {
                from: state,
                to: "ACCEPTED".into(),
            });
        }
        validate_acceptance_row(&row)?;

        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, reducer_version
            ) VALUES ($1, $2, $3, 'WORK_ITEM_DELIVERY', 'asf.workflow/v1')
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_error("create accepted-work workflow", &error))?;
        let next_version = version
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("work-item version overflowed".into()))?;
        let job_payload = json!({
            "work_item_id": work_item_id,
            "accepted_version": next_version,
            "request_digest": request_digest,
        });
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: None,
                job_type: ADVANCE_ACCEPTED_WORK_ITEM,
                activity_contract_id: ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
                payload: &job_payload,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_ACCEPT_WORK_ITEM,
                    idempotency_key,
                ),
                priority: required(&row, "normalized_priority", "work-item priority")?,
            },
        )
        .await?;
        upsert_workflow_anchor(&mut transaction, tenant_id, work_item_id, workflow_id).await?;
        let changed = sqlx::query(
            r"
            UPDATE work_items
            SET state = 'ACCEPTED',
                accepted_at = clock_timestamp(),
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2 AND aggregate_version = $3
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(i64_from_u64(version, "work-item version")?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_error("accept work item", &error))?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Conflict(format!(
                "work item {id} changed while it was being accepted"
            )));
        }
        let policy_digest: Option<String> = optional(&row, "policy_digest", "policy digest")?;
        let before_digest = digest_value(&json!({"state": "READY", "version": version}))?;
        let after_digest = digest_value(&json!({
            "state": "ACCEPTED",
            "version": next_version,
            "workflow_id": workflow_id,
            "job_id": job_id,
        }))?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: Some(work_item_id),
                attempt_id: None,
                actor: caller,
                action: "WORK_ITEM_ACCEPTED",
                subject_type: "WORK_ITEM",
                subject_id: &work_item_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: policy_digest.as_deref(),
                before_digest: Some(&before_digest),
                after_digest: Some(&after_digest),
                details: &json!({"workflow_id": workflow_id, "job_id": job_id}),
            },
        )
        .await?;
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: id.to_string(),
            status: "accepted".into(),
            version: Some(next_version),
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 200).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn cancel_work_item(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        request: &CancellationRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        validate_mutation_identity(caller, idempotency_key)?;
        let reason = request.reason.trim();
        if reason.is_empty() {
            return Err(Error::Validation("cancellation reason is required".into()));
        }
        reject_sensitive_fields(&json!(reason))?;
        let work_item_id = id.as_uuid();
        let request_value = json!({
            "work_item_id": work_item_id,
            "expected_version": request.expected_version,
            "reason": reason,
        });
        let request_digest = digest_value(&request_value)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_CANCEL_WORK_ITEM,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }

        let row = lock_work_item(&mut transaction, tenant_id, work_item_id).await?;
        let state: String = required(&row, "state", "work-item state")?;
        let version = positive_u64(
            required::<i64>(&row, "aggregate_version", "work-item version")?,
            "work-item version",
        )?;
        require_expected_version("work item", request.expected_version, version)?;
        if !state_allows_cancellation(&state) {
            return Err(Error::InvalidTransition {
                from: state,
                to: "CANCEL_REQUESTED".into(),
            });
        }
        let current_attempt_id: Option<Uuid> =
            optional(&row, "current_attempt_id", "current attempt")?;
        if state == "ACCEPTED" && current_attempt_id.is_none() {
            let policy_digest: Option<String> = optional(&row, "policy_digest", "policy digest")?;
            let receipt = cancel_accepted_before_dispatch(
                &mut transaction,
                PreDispatchCancellation {
                    tenant_id,
                    work_item_id,
                    version,
                    request_digest: &request_digest,
                    reason,
                    caller,
                    correlation_id: claim.record_id,
                    policy_digest: policy_digest.as_deref(),
                    idempotency_key,
                },
            )
            .await?;
            complete_idempotency(&mut transaction, claim.record_id, &receipt, 200).await?;
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        // This row is the shared predicate lock for births/reactivations of
        // work-bound cancellation authority. Take it immediately after the
        // work aggregate, before run/workflow/escalation rows. Non-escalated
        // work must have no live escalation at all; ESCALATED work is checked
        // against its one exact owner after that owner is locked below.
        lock_work_cancellation_authority_guard(&mut transaction, tenant_id, work_item_id).await?;
        if state != "ESCALATED" {
            require_no_other_active_cancellation_escalations(
                &mut transaction,
                tenant_id,
                work_item_id,
                None,
            )
            .await?;
        }
        let attempt_id: Uuid = current_attempt_id.ok_or_else(|| {
            Error::Conflict(format!(
                "work item {work_item_id} has no current attempt bound to a Runmill worker"
            ))
        })?;
        let worker_id = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT run.worker_id
            FROM runs AS run
            WHERE run.tenant_id = $1
              AND run.work_item_id = $2
              AND run.attempt_id = $3
              AND run.authoritative
              AND run.state IN (
                  'ADOPTED', 'RUNNING', 'WAITING_APPROVAL', 'VERIFYING',
                  'CANCEL_REQUESTED'
              )
            FOR SHARE OF run
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("load cancellation worker route", &error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "work item {work_item_id} has no live authoritative Runmill run to cancel"
            ))
        })?;
        let cancellation_worker = WorkerId::from_uuid(worker_id);
        if !self.activity_capabilities.supports_cancellation_worker(
            cancellation_worker,
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
        ) {
            return Err(Error::ExternalUnavailable(format!(
                "Runmill cancellation activity for worker {cancellation_worker} is unavailable; refusing to create an orphaned cancellation obligation"
            )));
        }

        let workflow_id = ensure_active_workflow(
            &mut transaction,
            tenant_id,
            work_item_id,
            "WORK_ITEM_CANCELLATION",
        )
        .await?;
        // Match the runtime's aggregate order: work/run -> workflow ->
        // escalation -> accountability anchor. An ESCALATED item cannot shed
        // an unmatched live attention owner merely because it also has a
        // cancellable Runmill route.
        let exhausted_escalation = if state == "ESCALATED" {
            Some(
                lock_current_exhausted_cancellation_escalation(
                    &mut transaction,
                    tenant_id,
                    work_item_id,
                    attempt_id,
                )
                .await?
                .ok_or_else(|| {
                    Error::Conflict(format!(
                        "escalated work item {work_item_id} is not owned by its current attempt's active workflow-job exhaustion escalation"
                    ))
                })?,
            )
        } else {
            None
        };
        let job_id = Uuid::now_v7();
        let next_version = version
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("work-item version overflowed".into()))?;
        let job_payload = json!({
            "work_item_id": work_item_id,
            "worker_id": worker_id,
            "expected_version": next_version,
            "reason": reason,
            "requested_by": caller.subject,
        });
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                job_type: REQUEST_WORK_ITEM_CANCELLATION,
                activity_contract_id: REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
                payload: &job_payload,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_CANCEL_WORK_ITEM,
                    idempotency_key,
                ),
                priority: required(&row, "normalized_priority", "work-item priority")?,
            },
        )
        .await?;
        // Close the exact active exhaustion owner while its escalation row is
        // still locked. The accountability swap follows in the same
        // transaction, so a DEAD job remains immutable historical evidence
        // without leaving a second active operator obligation.
        let closed_exhausted_escalation = match exhausted_escalation {
            Some(escalation) => Some(
                close_exhausted_cancellation_escalation(
                    &mut transaction,
                    tenant_id,
                    work_item_id,
                    attempt_id,
                    escalation,
                )
                .await?,
            ),
            None => None,
        };
        let anchor_generation_after =
            upsert_workflow_anchor(&mut transaction, tenant_id, work_item_id, workflow_id).await?;
        let changed = sqlx::query(
            r"
            UPDATE work_items
            SET state = 'CANCEL_REQUESTED',
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2 AND aggregate_version = $3
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(i64_from_u64(version, "work-item version")?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_error("request work-item cancellation", &error))?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Conflict(format!(
                "work item {id} changed while cancellation was requested"
            )));
        }
        let policy_digest: Option<String> = optional(&row, "policy_digest", "policy digest")?;
        let before_digest = digest_value(&json!({"state": state, "version": version}))?;
        let after_digest = digest_value(&json!({
            "state": "CANCEL_REQUESTED",
            "version": next_version,
            "workflow_id": workflow_id,
            "job_id": job_id,
            "worker_id": worker_id,
        }))?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                actor: caller,
                action: "WORK_ITEM_CANCELLATION_REQUESTED",
                subject_type: "WORK_ITEM",
                subject_id: &work_item_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: policy_digest.as_deref(),
                before_digest: Some(&before_digest),
                after_digest: Some(&after_digest),
                details: &json!({
                    "reason": reason,
                    "job_id": job_id,
                    "worker_id": worker_id,
                }),
            },
        )
        .await?;
        if let Some(escalation) = closed_exhausted_escalation {
            let cancellation_authority_generation = load_work_cancellation_authority_generation(
                &mut transaction,
                tenant_id,
                work_item_id,
            )
            .await?;
            append_cancellation_escalation_supersession(
                &mut transaction,
                CancellationEscalationSupersession {
                    tenant_id,
                    work_item_id,
                    attempt_id,
                    work_item_version_before: version,
                    work_item_version_after: next_version,
                    replacement_workflow_id: workflow_id,
                    replacement_job_id: job_id,
                    anchor_generation_after,
                    cancellation_authority_generation,
                    idempotency_record_id: claim.record_id,
                    request_digest: &request_digest,
                    reason,
                    caller,
                    policy_digest: policy_digest.as_deref(),
                    escalation,
                },
            )
            .await?;
        }
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: id.to_string(),
            status: "cancellation_requested".into(),
            version: Some(next_version),
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 202).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn work_item_events(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        page: &PageQuery,
    ) -> Result<Page<Value>> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let work_item_id = id.as_uuid();
        ensure_work_item_exists(&self.pool, tenant_id, work_item_id).await?;
        let cursor = decode_cursor(page.cursor.as_deref(), "work-item-events")?;
        let (cursor_at, cursor_id) = cursor_parts(cursor);
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin event read", &error))?;
        let mut rows = fetch_work_item_event_rows(
            &mut transaction,
            tenant_id,
            work_item_id,
            cursor_at,
            cursor_id,
            i64::from(page.limit) + 1,
        )
        .await?;
        let has_more = rows.len() > usize::from(page.limit);
        rows.truncate(usize::from(page.limit));
        let next_cursor = if has_more {
            rows.last()
                .map(|row| cursor_from_row(row, "work-item-events", "occurred_at"))
                .transpose()?
        } else {
            None
        };
        let items = rows
            .iter()
            .map(audit_value_from_row)
            .collect::<Result<_>>()?;
        commit_transaction(transaction).await?;
        Ok(Page { items, next_cursor })
    }

    async fn attention(
        &self,
        tenant_id: TenantId,
        page: &PageQuery,
    ) -> Result<Page<AttentionItemView>> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let cursor = decode_attention_cursor(page.cursor.as_deref())?;
        let (cursor_severity, cursor_deadline, cursor_id) =
            cursor.map_or((None, None, None), |cursor| {
                (
                    Some(cursor.severity.rank()),
                    Some(cursor.deadline),
                    Some(cursor.id),
                )
            });
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin attention read", &error))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("set attention snapshot isolation", &error))?;
        ensure_attention_coverage(&mut transaction, tenant_id).await?;
        let mut rows = sqlx::query(
            r"
            WITH attention_records AS (
                SELECT
                    'ESCALATION'::text AS kind, id, work_item_id,
                    NULL::uuid AS workflow_job_id,
                    category, severity, owner_type, owner_id,
                    required_action, evidence_references, deadline, opened_at,
                    retry_policy, authority_or_effect_active
                FROM escalations
                WHERE tenant_id = $1
                  AND status IN ('OPEN', 'ACKNOWLEDGED')

                UNION ALL

                SELECT
                    'OPERATIONAL_INCIDENT'::text AS kind, id,
                    NULL::uuid AS work_item_id, workflow_job_id, category, severity,
                    owner_type, owner_id, required_action, evidence_references,
                    deadline, opened_at, retry_policy,
                    authority_or_effect_active
                FROM operational_incidents
                WHERE tenant_id = $1
                  AND status IN ('OPEN', 'ACKNOWLEDGED')
            ), ranked_attention AS (
                SELECT
                    kind, id, work_item_id, workflow_job_id, category, severity,
                    owner_type, owner_id,
                    required_action, evidence_references, deadline, opened_at,
                    retry_policy, authority_or_effect_active,
                    CASE severity
                        WHEN 'CRITICAL' THEN 5::smallint
                        WHEN 'HIGH' THEN 4::smallint
                        WHEN 'MEDIUM' THEN 3::smallint
                        WHEN 'LOW' THEN 2::smallint
                        WHEN 'INFO' THEN 1::smallint
                    END AS severity_rank
                FROM attention_records
            )
            SELECT
                kind, id, work_item_id, workflow_job_id, category, severity,
                owner_type, owner_id,
                required_action, evidence_references, deadline, opened_at,
                retry_policy, authority_or_effect_active, severity_rank
            FROM ranked_attention
            WHERE (
                  $2::smallint IS NULL
                  OR severity_rank < $2::smallint
                  OR (
                      severity_rank = $2::smallint
                      AND (deadline, id) > ($3::timestamptz, $4::uuid)
                  )
              )
            ORDER BY severity_rank DESC, deadline ASC, id ASC
            LIMIT $5
            ",
        )
        .bind(tenant_id)
        .bind(cursor_severity)
        .bind(cursor_deadline)
        .bind(cursor_id)
        .bind(i64::from(page.limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| database_error("list attention items", &error))?;
        let has_more = rows.len() > usize::from(page.limit);
        rows.truncate(usize::from(page.limit));
        let next_cursor = if has_more {
            rows.last().map(attention_cursor_from_row).transpose()?
        } else {
            None
        };
        let items = rows.iter().map(attention_from_row).collect::<Result<_>>()?;
        commit_transaction(transaction).await?;
        Ok(Page { items, next_cursor })
    }

    async fn decide_approval(
        &self,
        tenant_id: TenantId,
        id: ApprovalId,
        request: &ApprovalDecisionRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        validate_mutation_identity(caller, idempotency_key)?;
        if !matches!(
            request.decision.as_str(),
            "approve" | "reject" | "request_changes"
        ) {
            return Err(Error::Validation("unsupported approval decision".into()));
        }
        if request.decision == "request_changes"
            && request
                .reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(Error::Validation(
                "request_changes requires a reason".into(),
            ));
        }
        if let Some(reason) = request.reason.as_deref() {
            reject_sensitive_fields(&json!(reason))?;
        }
        let approval_id = id.as_uuid();
        let request_value = json!({
            "approval_id": approval_id,
            "decision": request.decision,
            "reason": request.reason,
            "expected_version": request.expected_version,
        });
        let request_digest = digest_value(&request_value)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_DECIDE_APPROVAL,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        if !self.activity_capabilities.supports_unscoped(
            APPLY_SIGNED_APPROVAL_DECISION,
            APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID,
        ) {
            return Err(Error::ExternalUnavailable(
                "signed approval activity is unavailable; refusing to create an orphaned authority decision"
                    .into(),
            ));
        }

        let row = sqlx::query(
            r"
            SELECT
                id, work_item_id, attempt_id, status, aggregate_version,
                expires_at, policy_digest, work_order_digest, candidate_sha,
                evidence_digest, decision_effect_type
            FROM approvals
            WHERE tenant_id = $1 AND id = $2
            FOR UPDATE
            ",
        )
        .bind(tenant_id)
        .bind(approval_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("lock approval", &error))?
        .ok_or_else(|| Error::NotFound(format!("approval {id}")))?;
        let version = positive_u64(
            required::<i64>(&row, "aggregate_version", "approval version")?,
            "approval version",
        )?;
        require_expected_version("approval", request.expected_version, version)?;
        let status: String = required(&row, "status", "approval status")?;
        let expires_at: DateTime<Utc> = required(&row, "expires_at", "approval expiry")?;
        if status != "PENDING" {
            return Err(Error::Conflict(format!(
                "approval {id} is already {status}"
            )));
        }
        if expires_at <= Utc::now() {
            return Err(Error::Conflict(format!("approval {id} has expired")));
        }

        // Approval rows are authority-bearing and the initial schema does not
        // yet store an exact signed decision envelope. Queue application of the
        // decision so the authority service can sign, revalidate all bindings,
        // and atomically advance the workflow; do not mutate the approval here.
        let work_item_id: Uuid = required(&row, "work_item_id", "approval work item")?;
        let workflow_id =
            require_active_delivery_workflow(&mut transaction, tenant_id, work_item_id).await?;
        let attempt_id: Option<Uuid> = optional(&row, "attempt_id", "approval attempt")?;
        let policy_digest: String = required(&row, "policy_digest", "approval policy digest")?;
        let work_order_digest: Option<String> =
            optional(&row, "work_order_digest", "work-order digest")?;
        let candidate_sha: Option<String> = optional(&row, "candidate_sha", "candidate SHA")?;
        let evidence_digest: Option<String> = optional(&row, "evidence_digest", "evidence digest")?;
        let decision_effect_type: String =
            required(&row, "decision_effect_type", "decision effect")?;
        let job_id = Uuid::now_v7();
        let job_payload = json!({
            "approval_id": approval_id,
            "expected_version": version,
            "decision": request.decision,
            "reason": request.reason,
            "decision_subject": caller.subject,
            "roles": caller.roles,
            "binding": {
                "work_order_digest": work_order_digest,
                "candidate_sha": candidate_sha,
                "evidence_digest": evidence_digest,
                "decision_effect_type": decision_effect_type,
                "policy_digest": policy_digest,
            }
        });
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id,
                job_type: APPLY_SIGNED_APPROVAL_DECISION,
                activity_contract_id: APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID,
                payload: &job_payload,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_DECIDE_APPROVAL,
                    idempotency_key,
                ),
                priority: 100,
            },
        )
        .await?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: Some(work_item_id),
                attempt_id,
                actor: caller,
                action: "APPROVAL_DECISION_QUEUED",
                subject_type: "APPROVAL",
                subject_id: &approval_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: Some(&policy_digest),
                before_digest: None,
                after_digest: Some(&request_digest),
                details: &json!({
                    "decision": request.decision,
                    "reason": request.reason,
                    "job_id": job_id,
                    "workflow_id": workflow_id,
                }),
            },
        )
        .await?;
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: id.to_string(),
            status: "decision_queued".into(),
            version: Some(version),
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 202).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn workers(&self, tenant_id: TenantId) -> Result<Vec<WorkerView>> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let rows = sqlx::query(
            r"
            SELECT
                worker.id,
                worker.name,
                worker.status,
                worker.generation,
                worker.capabilities,
                worker.max_concurrency,
                worker.last_seen_at,
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
            WHERE worker.tenant_id = $1
            ORDER BY worker.name, worker.id
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| database_error("list workers", &error))?;
        rows.iter().map(worker_from_row).collect()
    }

    async fn reconcile_worker(
        &self,
        tenant_id: TenantId,
        id: WorkerId,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        validate_mutation_identity(caller, idempotency_key)?;
        let worker_id = id.as_uuid();
        let request_value = json!({"worker_id": worker_id});
        let request_digest = digest_value(&request_value)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_RECONCILE_WORKER,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        if !self
            .activity_capabilities
            .supports_reconcile_worker(id, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        {
            return Err(Error::ExternalUnavailable(format!(
                "worker-reconciliation activity for worker {id} is unavailable; refusing to create an orphaned reconciliation obligation"
            )));
        }
        let row = sqlx::query(
            r"
            SELECT generation, aggregate_version, status
            FROM workers
            WHERE tenant_id = $1 AND id = $2
            FOR SHARE
            ",
        )
        .bind(tenant_id)
        .bind(worker_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("load worker for reconciliation", &error))?
        .ok_or_else(|| Error::NotFound(format!("worker {id}")))?;
        let generation = positive_u64(
            required::<i64>(&row, "generation", "worker generation")?,
            "worker generation",
        )?;
        let version = positive_u64(
            required::<i64>(&row, "aggregate_version", "worker version")?,
            "worker version",
        )?;
        let job_id = Uuid::now_v7();
        let payload = json!({
            "worker_id": worker_id,
            "expected_generation": generation,
            "expected_version": version,
        });
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: None,
                work_item_id: None,
                attempt_id: None,
                job_type: RECONCILE_WORKER,
                activity_contract_id: RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
                payload: &payload,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_RECONCILE_WORKER,
                    idempotency_key,
                ),
                priority: 50,
            },
        )
        .await?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: None,
                attempt_id: None,
                actor: caller,
                action: "WORKER_RECONCILIATION_QUEUED",
                subject_type: "WORKER",
                subject_id: &worker_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: None,
                before_digest: None,
                after_digest: Some(&request_digest),
                details: &json!({"job_id": job_id, "generation": generation}),
            },
        )
        .await?;
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: id.to_string(),
            status: "reconciliation_queued".into(),
            version: Some(version),
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 202).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn evidence(&self, tenant_id: TenantId, id: EvidenceId) -> Result<EvidenceView> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        let row = sqlx::query(
            r"
            SELECT
                evidence.id,
                evidence.payload_digest,
                evidence.work_order_digest,
                evidence.target_satisfied,
                evidence.exact_signed_envelope,
                verification.status AS verification_status
            FROM evidence_bundles AS evidence
            JOIN runs AS run
              ON run.tenant_id = evidence.tenant_id AND run.id = evidence.run_id
            LEFT JOIN evidence_verifications AS verification
              ON verification.tenant_id = evidence.tenant_id
             AND verification.evidence_id = evidence.id
             AND verification.expectation_digest = run.evidence_expectation_digest
            WHERE evidence.tenant_id = $1 AND evidence.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("get evidence", &error))?
        .ok_or_else(|| Error::NotFound(format!("evidence {id}")))?;
        let exact_envelope: Vec<u8> = required(&row, "exact_signed_envelope", "evidence envelope")?;
        let signed_envelope: Value = serde_json::from_slice(&exact_envelope)
            .map_err(|_| Error::Persistence("stored evidence envelope is not valid JSON".into()))?;
        reject_sensitive_fields(&signed_envelope).map_err(|_error| {
            Error::Persistence("stored evidence envelope is not safe for disclosure".into())
        })?;
        Ok(EvidenceView {
            id: EvidenceId::from_uuid(required(&row, "id", "evidence id")?),
            payload_digest: required(&row, "payload_digest", "evidence payload digest")?,
            work_order_digest: required(&row, "work_order_digest", "work-order digest")?,
            target_satisfied: required(&row, "target_satisfied", "target satisfaction")?,
            verification_status: optional(&row, "verification_status", "verification status")?,
            signed_envelope,
        })
    }

    async fn verify_evidence(
        &self,
        tenant_id: TenantId,
        id: EvidenceId,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        validate_mutation_identity(caller, idempotency_key)?;
        let evidence_id = id.as_uuid();
        let request_value = json!({"evidence_id": evidence_id});
        let request_digest = digest_value(&request_value)?;
        let mut transaction = begin_mutation(&self.pool, tenant_id).await?;
        let claim = claim_idempotency(
            &mut transaction,
            tenant_id,
            caller,
            OP_VERIFY_EVIDENCE,
            idempotency_key,
            &request_digest,
        )
        .await?;
        if let Some(receipt) = claim.replay {
            commit_transaction(transaction).await?;
            return Ok(receipt);
        }
        if !self
            .activity_capabilities
            .supports_unscoped(VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
        {
            return Err(Error::ExternalUnavailable(
                "evidence-verification activity is unavailable; refusing to create an orphaned verification obligation"
                    .into(),
            ));
        }
        let row = sqlx::query(
            r"
            SELECT
                evidence.work_item_id,
                evidence.attempt_id,
                evidence.run_id,
                evidence.payload_digest,
                evidence.work_order_digest,
                run.evidence_expectation_digest
            FROM evidence_bundles AS evidence
            JOIN runs AS run
              ON run.tenant_id = evidence.tenant_id
             AND run.id = evidence.run_id
            WHERE evidence.tenant_id = $1 AND evidence.id = $2
            FOR SHARE OF evidence, run
            ",
        )
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_error("load evidence for verification", &error))?
        .ok_or_else(|| Error::NotFound(format!("evidence {id}")))?;
        let work_item_id: Uuid = required(&row, "work_item_id", "evidence work item")?;
        let workflow_id =
            require_active_delivery_workflow(&mut transaction, tenant_id, work_item_id).await?;
        let attempt_id: Uuid = required(&row, "attempt_id", "evidence attempt")?;
        let job_id = Uuid::now_v7();
        let payload = json!({
            "evidence_id": evidence_id,
            "run_id": required::<Uuid>(&row, "run_id", "evidence run")?,
            "payload_digest": required::<String>(&row, "payload_digest", "evidence payload digest")?,
            "work_order_digest": required::<String>(&row, "work_order_digest", "work-order digest")?,
            "expectation_digest": required::<String>(&row, "evidence_expectation_digest", "evidence expectation")?,
        });
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                job_type: VERIFY_EVIDENCE,
                activity_contract_id: VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID,
                payload: &payload,
                idempotency_key: &job_idempotency_key(
                    tenant_id,
                    caller,
                    OP_VERIFY_EVIDENCE,
                    idempotency_key,
                ),
                priority: 75,
            },
        )
        .await?;
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                actor: caller,
                action: "EVIDENCE_VERIFICATION_QUEUED",
                subject_type: "EVIDENCE",
                subject_id: &evidence_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: None,
                before_digest: None,
                after_digest: Some(&request_digest),
                details: &json!({"job_id": job_id, "workflow_id": workflow_id}),
            },
        )
        .await?;
        let receipt = MutationReceipt {
            idempotency_key: idempotency_key.into(),
            resource_id: id.to_string(),
            status: "verification_queued".into(),
            version: None,
        };
        complete_idempotency(&mut transaction, claim.record_id, &receipt, 202).await?;
        commit_transaction(transaction).await?;
        Ok(receipt)
    }

    async fn explain_policy(&self, tenant_id: TenantId, digest: &str) -> Result<Value> {
        let tenant_id = self.require_bound_tenant(tenant_id)?;
        if !is_sha256_digest(digest) {
            return Err(Error::Validation(
                "policy digest must use sha256:<64 lowercase hex>".into(),
            ));
        }
        let row = sqlx::query(
            r"
            SELECT jsonb_build_object(
                'id', id,
                'digest', digest,
                'scope', scope,
                'repository_id', repository_id,
                'schema_version', schema_version,
                'policy', policy,
                'created_by', created_by,
                'created_at', created_at,
                'expires_at', expires_at
            ) AS value
            FROM policy_versions
            WHERE tenant_id = $1 AND digest = $2
            ",
        )
        .bind(tenant_id)
        .bind(digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("explain policy", &error))?
        .ok_or_else(|| Error::NotFound(format!("policy {digest}")))?;
        sanitized_column(&row, "value")
    }
}

struct JobInsert<'a> {
    id: Uuid,
    tenant_id: Uuid,
    workflow_instance_id: Option<Uuid>,
    work_item_id: Option<Uuid>,
    attempt_id: Option<Uuid>,
    job_type: &'a str,
    activity_contract_id: &'a str,
    payload: &'a Value,
    idempotency_key: &'a str,
    priority: i16,
}

struct AuditInsert<'a> {
    tenant_id: Uuid,
    work_item_id: Option<Uuid>,
    attempt_id: Option<Uuid>,
    actor: &'a Caller,
    action: &'a str,
    subject_type: &'a str,
    subject_id: &'a str,
    correlation_id: &'a str,
    policy_digest: Option<&'a str>,
    before_digest: Option<&'a str>,
    after_digest: Option<&'a str>,
    details: &'a Value,
}

struct PreDispatchCancellation<'a> {
    tenant_id: Uuid,
    work_item_id: Uuid,
    version: u64,
    request_digest: &'a str,
    reason: &'a str,
    caller: &'a Caller,
    correlation_id: Uuid,
    policy_digest: Option<&'a str>,
    idempotency_key: &'a str,
}

struct PreDispatchCancellationBinding {
    job_id: Uuid,
    job_fence_token: i64,
    job_attempt_count: i32,
    workflow_id: Uuid,
    workflow_version: i64,
    workflow_fence_token: i64,
    workflow_event_cursor: i64,
    anchor_generation: i64,
    dispatch_guard_generation: i64,
}

struct ExhaustedCancellationEscalation {
    id: Uuid,
    status_before: String,
    aggregate_version_before: i64,
    before_digest: String,
    anchor_generation_before: i64,
    dead_workflow_job_ids: Vec<Uuid>,
}

struct ClosedExhaustedCancellationEscalation {
    binding: ExhaustedCancellationEscalation,
    aggregate_version_after: i64,
    after_digest: String,
    superseded_at: DateTime<Utc>,
}

struct CancellationEscalationSupersession<'a> {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_item_version_before: u64,
    work_item_version_after: u64,
    replacement_workflow_id: Uuid,
    replacement_job_id: Uuid,
    anchor_generation_after: i64,
    cancellation_authority_generation: i64,
    idempotency_record_id: Uuid,
    request_digest: &'a str,
    reason: &'a str,
    caller: &'a Caller,
    policy_digest: Option<&'a str>,
    escalation: ClosedExhaustedCancellationEscalation,
}

async fn begin_mutation(pool: &PgPool, tenant_id: Uuid) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database_error("begin API mutation", &error))?;
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM tenants WHERE id = $1 FOR SHARE")
            .bind(tenant_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| database_error("lock API tenant", &error))?
            .ok_or_else(|| Error::NotFound("tenant".into()))?;
    if status != "ACTIVE" {
        return Err(Error::ExternalUnavailable(format!(
            "tenant is not active ({status})"
        )));
    }
    Ok(transaction)
}

async fn commit_transaction(transaction: Transaction<'_, Postgres>) -> Result<()> {
    transaction
        .commit()
        .await
        .map_err(|error| database_error("commit PostgreSQL transaction", &error))
}

async fn claim_idempotency<T>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    caller: &Caller,
    operation: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<IdempotencyClaim<T>>
where
    T: serde::de::DeserializeOwned,
{
    let record_id = Uuid::now_v7();
    let inserted = sqlx::query(
        r"
        INSERT INTO idempotency_records (
            id, tenant_id, actor_id, operation, idempotency_key,
            request_digest, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            clock_timestamp() + ($7::integer * interval '1 day')
        )
        ON CONFLICT (tenant_id, actor_id, operation, idempotency_key)
        DO NOTHING
        ",
    )
    .bind(record_id)
    .bind(tenant_id)
    .bind(&caller.subject)
    .bind(operation)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(IDEMPOTENCY_RETENTION_DAYS)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("claim API idempotency key", &error))?
    .rows_affected()
        == 1;

    let row = sqlx::query(
        r"
        SELECT id, request_digest, state, response_body
        FROM idempotency_records
        WHERE tenant_id = $1
          AND actor_id = $2
          AND operation = $3
          AND idempotency_key = $4
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(&caller.subject)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("load API idempotency key", &error))?
    .ok_or_else(|| {
        Error::Persistence("idempotency claim disappeared inside its transaction".into())
    })?;
    let stored_digest: String = required(&row, "request_digest", "idempotency request digest")?;
    if stored_digest != request_digest {
        return Err(Error::Conflict(
            "idempotency key was reused for a different request".into(),
        ));
    }
    let stored_id: Uuid = required(&row, "id", "idempotency record id")?;
    let state: String = required(&row, "state", "idempotency state")?;
    if state == "COMPLETED" {
        let response: Option<Value> = optional(&row, "response_body", "idempotent response")?;
        let receipt = response
            .ok_or_else(|| {
                Error::Persistence("completed idempotency record has no response".into())
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| {
                    Error::Persistence("stored idempotent response is malformed".into())
                })
            })?;
        return Ok(IdempotencyClaim {
            record_id: stored_id,
            replay: Some(receipt),
        });
    }
    if !inserted {
        return Err(Error::Conflict(
            "matching idempotent request is already in progress".into(),
        ));
    }
    if state != "IN_PROGRESS" {
        return Err(Error::Conflict(format!(
            "idempotent request cannot run from state {state}"
        )));
    }
    Ok(IdempotencyClaim {
        record_id: stored_id,
        replay: None,
    })
}

async fn complete_idempotency<T>(
    transaction: &mut Transaction<'_, Postgres>,
    record_id: Uuid,
    receipt: &T,
    response_status: i32,
) -> Result<()>
where
    T: Serialize,
{
    let response = serde_json::to_value(receipt)
        .map_err(|_| Error::Serialization("serialize mutation receipt".into()))?;
    let changed = sqlx::query(
        r"
        UPDATE idempotency_records
        SET state = 'COMPLETED',
            response_status = $2,
            response_body = $3,
            completed_at = clock_timestamp()
        WHERE id = $1 AND state = 'IN_PROGRESS'
        ",
    )
    .bind(record_id)
    .bind(response_status)
    .bind(response)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("complete API idempotency record", &error))?
    .rows_affected();
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict(
            "API idempotency record was concurrently completed".into(),
        ))
    }
}

async fn enqueue_job(
    transaction: &mut Transaction<'_, Postgres>,
    job: JobInsert<'_>,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, payload, idempotency_key, priority
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(job.id)
    .bind(job.tenant_id)
    .bind(job.workflow_instance_id)
    .bind(job.work_item_id)
    .bind(job.attempt_id)
    .bind(job.job_type)
    .bind(job.activity_contract_id)
    .bind(job.payload)
    .bind(job.idempotency_key)
    .bind(job.priority)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("enqueue API workflow job", &error))?;
    Ok(())
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    audit: AuditInsert<'_>,
) -> Result<Uuid> {
    reject_sensitive_fields(audit.details)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(audit.tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("lock tenant audit chain", &error))?;
    let previous_event_hash = sqlx::query_scalar::<_, String>(
        r"
        SELECT event_hash
        FROM audit_events
        WHERE tenant_id = $1
        ORDER BY ingested_at DESC, id DESC
        LIMIT 1
        ",
    )
    .bind(audit.tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("load audit-chain head", &error))?;
    // Hash the exact precision PostgreSQL will persist. Hashing a local
    // nanosecond timestamp and then binding it to timestamptz would discard
    // sub-microsecond digits and make the durable audit hash unreproducible.
    let occurred_at = sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| database_error("load audit timestamp", &error))?;
    let event = HashedAuditEvent::create(AuditEventContent {
        id: EventId::new(),
        tenant_id: TenantId::from_uuid(audit.tenant_id),
        work_item_id: audit.work_item_id.map(WorkItemId::from_uuid),
        attempt_id: audit.attempt_id.map(AttemptId::from_uuid),
        actor_type: "API_CALLER".into(),
        actor_id: audit.actor.subject.clone(),
        action: audit.action.into(),
        subject_type: audit.subject_type.into(),
        subject_id: audit.subject_id.into(),
        correlation_id: audit.correlation_id.into(),
        trace_id: None,
        policy_digest: audit.policy_digest.map(str::to_owned),
        before_digest: audit.before_digest.map(str::to_owned),
        after_digest: audit.after_digest.map(str::to_owned),
        previous_event_hash,
        details: audit.details.clone(),
        occurred_at,
    })?;
    sqlx::query(
        r"
        INSERT INTO audit_events (
            id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
            action, subject_type, subject_id, correlation_id, policy_digest,
            before_digest, after_digest, previous_event_hash, event_hash,
            details, occurred_at
        ) VALUES (
            $1, $2, $3, $4, 'API_CALLER', $5,
            $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16
        )
        ",
    )
    .bind(event.content.id.as_uuid())
    .bind(audit.tenant_id)
    .bind(audit.work_item_id)
    .bind(audit.attempt_id)
    .bind(&audit.actor.subject)
    .bind(audit.action)
    .bind(audit.subject_type)
    .bind(audit.subject_id)
    .bind(audit.correlation_id)
    .bind(audit.policy_digest)
    .bind(audit.before_digest)
    .bind(audit.after_digest)
    .bind(&event.content.previous_event_hash)
    .bind(&event.event_hash)
    .bind(audit.details)
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("append API audit event", &error))?;
    Ok(event.content.id.as_uuid())
}

async fn lock_work_item(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
) -> Result<PgRow> {
    sqlx::query(
        r"
        SELECT
            state, aggregate_version, normalized_priority, repository_id,
            closure_target, risk_class, policy_digest, budget_limits,
            owner_fallback, identity_requirements, current_attempt_id
        FROM work_items
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock work item", &error))?
    .ok_or_else(|| Error::NotFound(format!("work item {work_item_id}")))
}

fn validate_acceptance_row(row: &PgRow) -> Result<()> {
    let repository_id: Option<Uuid> = optional(row, "repository_id", "repository")?;
    let closure_target: Option<String> = optional(row, "closure_target", "closure target")?;
    let risk_class: Option<String> = optional(row, "risk_class", "risk class")?;
    let policy_digest: Option<String> = optional(row, "policy_digest", "policy digest")?;
    let budget_limits: Option<Value> = optional(row, "budget_limits", "budget limits")?;
    let identity_requirements: Option<Value> =
        optional(row, "identity_requirements", "identity requirements")?;
    let owner: Option<String> = optional(row, "owner_fallback", "owner fallback")?;
    if repository_id.is_none()
        || closure_target.is_none()
        || risk_class.is_none()
        || policy_digest.is_none()
        || budget_limits.is_none()
        || identity_requirements.is_none()
        || owner.as_deref().is_none_or(|value| value.trim().is_empty())
    {
        return Err(Error::Validation(
            "work item is missing required acceptance fields".into(),
        ));
    }
    if closure_target.as_deref() != Some("pull_request") {
        return Err(Error::Validation(
            "only pull-request closure is production-supported".into(),
        ));
    }
    if matches!(risk_class.as_deref(), Some("critical" | "unknown")) {
        return Err(Error::Validation(
            "critical or unknown-risk work cannot be accepted unattended".into(),
        ));
    }
    serde_json::from_value::<BudgetLimits>(budget_limits.expect("presence checked above"))
        .map_err(|_| Error::Validation("work item has invalid budget limits".into()))?
        .validate()?;
    serde_json::from_value::<WorkOrderIdentities>(
        identity_requirements.expect("presence checked above"),
    )
    .map_err(|_| Error::Validation("work item has invalid identity requirements".into()))?
    .validate()?;
    Ok(())
}

async fn ensure_active_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    workflow_type: &str,
) -> Result<Uuid> {
    if let Some(row) = sqlx::query(
        r"
        SELECT id, state
        FROM workflow_instances
        WHERE tenant_id = $1 AND work_item_id = $2 AND workflow_type = $3
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_type)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("load workflow instance", &error))?
    {
        let state: String = required(&row, "state", "workflow state")?;
        if !matches!(state.as_str(), "ACTIVE" | "WAITING") {
            return Err(Error::Conflict(format!(
                "{workflow_type} workflow is already {state}"
            )));
        }
        return required(&row, "id", "workflow id");
    }
    let workflow_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_instances (
            id, tenant_id, work_item_id, workflow_type, reducer_version
        ) VALUES ($1, $2, $3, $4, 'asf.workflow/v1')
        ",
    )
    .bind(workflow_id)
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_type)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("create workflow instance", &error))?;
    Ok(workflow_id)
}

async fn require_active_delivery_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
) -> Result<Uuid> {
    let row = sqlx::query(
        r"
        SELECT id, state
        FROM workflow_instances
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND workflow_type = 'WORK_ITEM_DELIVERY'
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("load accepted-work delivery workflow", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} has no durable delivery workflow"
        ))
    })?;
    let state: String = required(&row, "state", "delivery workflow state")?;
    if !matches!(state.as_str(), "ACTIVE" | "WAITING") {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} delivery workflow is {state}"
        )));
    }
    required(&row, "id", "delivery workflow id")
}

async fn upsert_workflow_anchor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    workflow_id: Uuid,
) -> Result<i64> {
    let generation = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO accountability_anchors (
            tenant_id, work_item_id, anchor_type, reference_id,
            wake_or_deadline_at, authority_or_effect_active
        ) VALUES ($1, $2, 'WORKFLOW', $3, NULL, false)
        ON CONFLICT (tenant_id, work_item_id) DO UPDATE
        SET anchor_type = 'WORKFLOW',
            reference_id = EXCLUDED.reference_id,
            wake_or_deadline_at = NULL,
            authority_or_effect_active = false,
            generation = accountability_anchors.generation + 1,
            updated_at = clock_timestamp()
        RETURNING generation
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| database_error("update accountability anchor", &error))?;
    Ok(generation)
}

async fn lock_work_cancellation_authority_guard(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
) -> Result<()> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT generation
        FROM work_cancellation_authority_guards
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND terminal_receipt_id IS NULL
          AND source_closure_effect_intent_id IS NULL
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock cancellation-authority predicate", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} has terminal cancellation or source-closure finality"
        ))
    })?;
    Ok(())
}

async fn load_work_cancellation_authority_generation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT generation
        FROM work_cancellation_authority_guards
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND terminal_receipt_id IS NULL
          AND source_closure_effect_intent_id IS NULL
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("load cancellation-authority generation", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} acquired terminal cancellation or source-closure finality"
        ))
    })
}

async fn lock_current_exhausted_cancellation_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
) -> Result<Option<ExhaustedCancellationEscalation>> {
    let row = sqlx::query(
        r"
        SELECT
            escalation.id,
            escalation.status,
            escalation.aggregate_version,
            ARRAY(
                SELECT dead_job.id
                FROM workflow_jobs AS dead_job
                WHERE dead_job.tenant_id = escalation.tenant_id
                  AND dead_job.work_item_id = escalation.work_item_id
                  AND dead_job.attempt_id IS NOT DISTINCT FROM escalation.attempt_id
                  AND dead_job.status = 'DEAD'
                  AND dead_job.dead_letter_escalation_id = escalation.id
                ORDER BY dead_job.id
            ) AS dead_workflow_job_ids
        FROM accountability_anchors AS anchor
        JOIN escalations AS escalation
          ON escalation.tenant_id = anchor.tenant_id
         AND escalation.work_item_id = anchor.work_item_id
         AND escalation.id = anchor.reference_id
        WHERE anchor.tenant_id = $1
          AND anchor.work_item_id = $2
          AND anchor.anchor_type = 'ESCALATION'
          AND anchor.wake_or_deadline_at = escalation.deadline
          AND anchor.authority_or_effect_active
          AND escalation.attempt_id = $3
          AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
          AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
          AND escalation.authority_or_effect_active
        FOR UPDATE OF escalation
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock cancellation recovery escalation", &error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: Uuid = required(&row, "id", "cancellation recovery escalation")?;
    let dead_workflow_job_ids: Vec<Uuid> = required(
        &row,
        "dead_workflow_job_ids",
        "cancellation recovery exhausted workflow jobs",
    )?;
    if dead_workflow_job_ids.is_empty() {
        return Err(Error::Persistence(format!(
            "active workflow-job exhaustion escalation {id} owns no immutable DEAD workflow job"
        )));
    }
    let anchor_generation_before = sqlx::query_scalar::<_, i64>(
        r"
        SELECT anchor.generation
        FROM accountability_anchors AS anchor
        JOIN escalations AS escalation
          ON escalation.tenant_id = anchor.tenant_id
         AND escalation.work_item_id = anchor.work_item_id
         AND escalation.id = anchor.reference_id
        WHERE anchor.tenant_id = $1
          AND anchor.work_item_id = $2
          AND anchor.anchor_type = 'ESCALATION'
          AND anchor.reference_id = $3
          AND anchor.wake_or_deadline_at = escalation.deadline
          AND anchor.authority_or_effect_active
        FOR UPDATE OF anchor
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock cancellation recovery anchor", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "workflow-job exhaustion escalation {id} lost its accountability anchor"
        ))
    })?;
    require_no_other_active_cancellation_escalations(
        transaction,
        tenant_id,
        work_item_id,
        Some(id),
    )
    .await?;
    let before_digest =
        sqlx::query_scalar::<_, String>("SELECT asf_terminal_conflict_escalation_digest($1, $2)")
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| database_error("digest cancellation recovery escalation", &error))?
            .ok_or_else(|| {
                Error::Persistence(format!(
                    "locked workflow-job exhaustion escalation {id} disappeared"
                ))
            })?;
    Ok(Some(ExhaustedCancellationEscalation {
        id,
        status_before: required(&row, "status", "cancellation recovery escalation status")?,
        aggregate_version_before: required(
            &row,
            "aggregate_version",
            "cancellation recovery escalation version",
        )?,
        before_digest,
        anchor_generation_before,
        dead_workflow_job_ids,
    }))
}

async fn require_no_other_active_cancellation_escalations(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    excluded_escalation_id: Option<Uuid>,
) -> Result<()> {
    let active_escalations = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM escalations
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND ($3::uuid IS NULL OR id <> $3)
          AND status IN ('OPEN', 'ACKNOWLEDGED')
          AND authority_or_effect_active
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(excluded_escalation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| database_error("check competing cancellation escalations", &error))?;
    if active_escalations != 0 {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} has {active_escalations} competing active escalation owner(s)"
        )));
    }
    Ok(())
}

async fn close_exhausted_cancellation_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    binding: ExhaustedCancellationEscalation,
) -> Result<ClosedExhaustedCancellationEscalation> {
    let aggregate_version_after = binding
        .aggregate_version_before
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("escalation version overflowed".into()))?;
    let closed = sqlx::query(
        r"
        UPDATE escalations
        SET status = 'CANCELLED',
            authority_or_effect_active = false,
            aggregate_version = $7,
            closed_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND attempt_id = $4
          AND category = 'WORKFLOW_JOB_EXHAUSTED'
          AND status = $5
          AND aggregate_version = $6
          AND authority_or_effect_active
          AND closed_at IS NULL
        RETURNING aggregate_version, closed_at
        ",
    )
    .bind(tenant_id)
    .bind(binding.id)
    .bind(work_item_id)
    .bind(attempt_id)
    .bind(&binding.status_before)
    .bind(binding.aggregate_version_before)
    .bind(aggregate_version_after)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("supersede cancellation recovery escalation", &error))?;
    let Some(closed) = closed else {
        return Err(Error::Conflict(format!(
            "workflow-job exhaustion escalation {} changed during cancellation recovery",
            binding.id
        )));
    };
    let closed_version: i64 = required(
        &closed,
        "aggregate_version",
        "superseded cancellation escalation version",
    )?;
    if closed_version != aggregate_version_after {
        return Err(Error::Persistence(format!(
            "workflow-job exhaustion escalation {} returned inconsistent version {closed_version}",
            binding.id
        )));
    }
    let superseded_at: DateTime<Utc> = required(
        &closed,
        "closed_at",
        "superseded cancellation escalation timestamp",
    )?;
    let after_digest =
        sqlx::query_scalar::<_, String>("SELECT asf_terminal_conflict_escalation_digest($1, $2)")
            .bind(tenant_id)
            .bind(binding.id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| database_error("digest superseded cancellation escalation", &error))?
            .ok_or_else(|| {
                Error::Persistence(format!(
                    "superseded workflow-job exhaustion escalation {} disappeared",
                    binding.id
                ))
            })?;
    Ok(ClosedExhaustedCancellationEscalation {
        binding,
        aggregate_version_after,
        after_digest,
        superseded_at,
    })
}

async fn append_cancellation_escalation_supersession(
    transaction: &mut Transaction<'_, Postgres>,
    supersession: CancellationEscalationSupersession<'_>,
) -> Result<()> {
    let receipt_id = derived_api_record_id(supersession.idempotency_record_id, 3);
    let outbox_event_id = derived_api_record_id(supersession.idempotency_record_id, 4);
    let escalation = &supersession.escalation;
    let details = json!({
        "schema": "asf.cancellation-escalation-supersession-audit/v1",
        "work_item_id": supersession.work_item_id,
        "attempt_id": supersession.attempt_id,
        "escalation_id": escalation.binding.id,
        "idempotency_record_id": supersession.idempotency_record_id,
        "request_digest": supersession.request_digest,
        "actor": supersession.caller.subject,
        "reason": supersession.reason,
        "replacement_workflow_id": supersession.replacement_workflow_id,
        "replacement_job_id": supersession.replacement_job_id,
        "work_item_version_before": supersession.work_item_version_before,
        "work_item_version_after": supersession.work_item_version_after,
        "anchor_generation_before": escalation.binding.anchor_generation_before,
        "anchor_generation_after": supersession.anchor_generation_after,
        "cancellation_authority_generation": supersession.cancellation_authority_generation,
        "escalation_status_before": escalation.binding.status_before,
        "escalation_status_after": "CANCELLED",
        "escalation_version_before": escalation.binding.aggregate_version_before,
        "escalation_version_after": escalation.aggregate_version_after,
        "escalation_before_digest": escalation.binding.before_digest,
        "escalation_after_digest": escalation.after_digest,
        "dead_workflow_job_ids": escalation.binding.dead_workflow_job_ids,
        "superseded_at": escalation.superseded_at,
        "receipt_id": receipt_id,
    });
    let audit_id = append_audit(
        transaction,
        AuditInsert {
            tenant_id: supersession.tenant_id,
            work_item_id: Some(supersession.work_item_id),
            attempt_id: Some(supersession.attempt_id),
            actor: supersession.caller,
            action: "WORKFLOW_JOB_EXHAUSTION_SUPERSEDED_BY_CANCELLATION",
            subject_type: "ESCALATION",
            subject_id: &escalation.binding.id.to_string(),
            correlation_id: &supersession.idempotency_record_id.to_string(),
            policy_digest: supersession.policy_digest,
            before_digest: Some(&escalation.binding.before_digest),
            after_digest: Some(&escalation.after_digest),
            details: &details,
        },
    )
    .await?;
    let outbox_payload = json!({
        "schema": "asf.cancellation-escalation-supersession-event/v1",
        "tenant_id": supersession.tenant_id,
        "work_item_id": supersession.work_item_id,
        "attempt_id": supersession.attempt_id,
        "escalation_id": escalation.binding.id,
        "idempotency_record_id": supersession.idempotency_record_id,
        "request_digest": supersession.request_digest,
        "actor": supersession.caller.subject,
        "replacement_workflow_id": supersession.replacement_workflow_id,
        "replacement_job_id": supersession.replacement_job_id,
        "work_item_version_before": supersession.work_item_version_before,
        "work_item_version_after": supersession.work_item_version_after,
        "anchor_generation_before": escalation.binding.anchor_generation_before,
        "anchor_generation_after": supersession.anchor_generation_after,
        "cancellation_authority_generation": supersession.cancellation_authority_generation,
        "escalation_status_before": escalation.binding.status_before,
        "escalation_status_after": "CANCELLED",
        "escalation_version_before": escalation.binding.aggregate_version_before,
        "escalation_version_after": escalation.aggregate_version_after,
        "escalation_before_digest": escalation.binding.before_digest,
        "escalation_after_digest": escalation.after_digest,
        "dead_workflow_job_ids": escalation.binding.dead_workflow_job_ids,
        "superseded_at": escalation.superseded_at,
        "audit_event_id": audit_id,
        "receipt_id": receipt_id,
    });
    sqlx::query(
        r#"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload,
            headers, idempotency_key, available_at
        ) VALUES (
            $1, $2, 'attention', $3,
            'workflow_job_exhaustion.superseded_by_cancellation', $4,
            '{"schema":"asf.cancellation-escalation-supersession-event/v1"}'::jsonb,
            $5, $6
        )
        "#,
    )
    .bind(outbox_event_id)
    .bind(supersession.tenant_id)
    .bind(escalation.binding.id.to_string())
    .bind(&outbox_payload)
    .bind(format!(
        "api-cancellation-escalation-supersession:{}:outbox",
        supersession.idempotency_record_id
    ))
    .bind(escalation.superseded_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("append cancellation supersession outbox", &error))?;
    sqlx::query(
        r"
        INSERT INTO cancellation_escalation_supersession_receipts (
            id, tenant_id, work_item_id, attempt_id, escalation_id,
            idempotency_record_id, actor_id, request_digest,
            replacement_workflow_id, replacement_job_id,
            work_item_version_before, work_item_version_after,
            anchor_generation_before, anchor_generation_after,
            cancellation_authority_generation,
            escalation_status_before,
            escalation_version_before, escalation_version_after,
            escalation_before_digest, escalation_after_digest,
            dead_workflow_job_ids, audit_event_id, outbox_event_id,
            superseded_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8,
            $9, $10,
            $11, $12,
            $13, $14,
            $15,
            $16,
            $17, $18,
            $19, $20,
            $21, $22, $23,
            $24
        )
        ",
    )
    .bind(receipt_id)
    .bind(supersession.tenant_id)
    .bind(supersession.work_item_id)
    .bind(supersession.attempt_id)
    .bind(escalation.binding.id)
    .bind(supersession.idempotency_record_id)
    .bind(&supersession.caller.subject)
    .bind(supersession.request_digest)
    .bind(supersession.replacement_workflow_id)
    .bind(supersession.replacement_job_id)
    .bind(i64_from_u64(
        supersession.work_item_version_before,
        "supersession work-item version",
    )?)
    .bind(i64_from_u64(
        supersession.work_item_version_after,
        "supersession work-item version",
    )?)
    .bind(escalation.binding.anchor_generation_before)
    .bind(supersession.anchor_generation_after)
    .bind(supersession.cancellation_authority_generation)
    .bind(&escalation.binding.status_before)
    .bind(escalation.binding.aggregate_version_before)
    .bind(escalation.aggregate_version_after)
    .bind(&escalation.binding.before_digest)
    .bind(&escalation.after_digest)
    .bind(&escalation.binding.dead_workflow_job_ids)
    .bind(audit_id)
    .bind(outbox_event_id)
    .bind(escalation.superseded_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("insert cancellation supersession receipt", &error))?;
    Ok(())
}

async fn lock_pre_dispatch_cancellation_binding(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    accepted_version: u64,
) -> Result<PreDispatchCancellationBinding> {
    // The reactor owns job rows before it locks the work aggregate. This
    // branch already owns the work row, so every reverse-order job lock must
    // be non-blocking: a claimed or concurrently changing job means dispatch
    // won the race and cancellation must fail closed.
    let jobs = sqlx::query(
        r"
        SELECT
            job.id,
            job.workflow_instance_id,
            job.attempt_id,
            job.job_type,
            job.activity_contract_id,
            job.status,
            job.attempt_count,
            job.max_attempts,
            job.fence_token,
            job.payload,
            (
                job.result IS NULL
                AND job.lease_owner IS NULL
                AND job.lease_expires_at IS NULL
                AND job.completed_by IS NULL
                AND job.completion_fence_token IS NULL
                AND job.completed_at IS NULL
                AND job.dead_letter_escalation_id IS NULL
                AND job.dead_letter_operational_incident_id IS NULL
                AND job.dead_lettered_at IS NULL
            ) AS clean_live_shape
        FROM workflow_jobs AS job
        WHERE job.tenant_id = $1
          AND job.work_item_id = $2
        ORDER BY job.id
        FOR UPDATE OF job NOWAIT
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| database_error("lock pre-dispatch workflow jobs", &error))?;
    if jobs.len() != 1 {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} does not have exactly one pre-dispatch workflow job"
        )));
    }
    let job = &jobs[0];
    let job_id: Uuid = required(job, "id", "pre-dispatch workflow-job id")?;
    let workflow_id: Uuid = optional(job, "workflow_instance_id", "delivery workflow binding")?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "work item {work_item_id} advance job is not bound to a workflow"
            ))
        })?;
    let attempt_id: Option<Uuid> = optional(job, "attempt_id", "advance-job attempt binding")?;
    let job_type: String = required(job, "job_type", "pre-dispatch workflow-job type")?;
    // The persisted, immutable contract identity this exact job was created
    // with — never a canonical identity re-derived from job_type, which
    // would let a future/incompatible advance job be synchronously
    // cancelled and interpreted by this (older) code as if it matched.
    let activity_contract_id: String = required(
        job,
        "activity_contract_id",
        "pre-dispatch workflow-job activity contract id",
    )?;
    let status: String = required(job, "status", "pre-dispatch workflow-job status")?;
    let attempt_count: i32 = required(job, "attempt_count", "advance-job attempt count")?;
    let max_attempts: i32 = required(job, "max_attempts", "advance-job maximum attempts")?;
    let clean_live_shape: bool = required(job, "clean_live_shape", "advance-job live shape")?;
    let payload: Value = required(job, "payload", "advance-job payload")?;
    let payload_object = payload.as_object().ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} advance job has a non-object payload"
        ))
    })?;
    let payload_work_item_id = payload_object
        .get("work_item_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let payload_accepted_version = payload_object
        .get("accepted_version")
        .and_then(Value::as_u64);
    let payload_request_digest = payload_object.get("request_digest").and_then(Value::as_str);
    let exact_payload = payload_object.len() == 3
        && payload_work_item_id == Some(work_item_id)
        && payload_accepted_version == Some(accepted_version)
        && payload_request_digest.is_some_and(is_sha256_digest);
    if attempt_id.is_some()
        || job_type != ADVANCE_ACCEPTED_WORK_ITEM
        || activity_contract_id != ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
        || !matches!(status.as_str(), "PENDING" | "RETRY")
        || attempt_count >= max_attempts
        || !clean_live_shape
        || !exact_payload
    {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} has crossed the synchronous pre-dispatch cancellation boundary"
        )));
    }
    let job_fence_token: i64 = required(job, "fence_token", "advance-job fence token")?;

    let workflow = sqlx::query(
        r"
        SELECT
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence_token,
            workflow.event_cursor AS workflow_event_cursor,
            anchor.generation AS anchor_generation
        FROM workflow_instances AS workflow
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = workflow.tenant_id
         AND anchor.work_item_id = workflow.work_item_id
         AND anchor.anchor_type = 'WORKFLOW'
         AND anchor.reference_id = workflow.id
         AND anchor.wake_or_deadline_at IS NULL
         AND NOT anchor.authority_or_effect_active
        WHERE workflow.tenant_id = $1
          AND workflow.work_item_id = $2
          AND workflow.id = $3
          AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
          AND workflow.reducer_version = 'asf.workflow/v1'
          AND workflow.state = 'ACTIVE'
          AND workflow.terminal_at IS NULL
        FOR UPDATE OF workflow, anchor NOWAIT
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock pre-dispatch delivery workflow", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} has no exact active delivery workflow and WORKFLOW anchor"
        ))
    })?;
    let workflow_version: i64 = required(&workflow, "workflow_version", "workflow version")?;
    let workflow_fence_token: i64 =
        required(&workflow, "workflow_fence_token", "workflow fence token")?;
    let workflow_event_cursor: i64 =
        required(&workflow, "workflow_event_cursor", "workflow event cursor")?;
    let anchor_generation: i64 =
        required(&workflow, "anchor_generation", "accountability generation")?;

    // Dispatch-fact writers take the work row before advancing this guard.
    // NOWAIT keeps this reverse-path cancellation from waiting behind a
    // dispatcher that has already begun producing attempt/run authority.
    let dispatch_guard = sqlx::query(
        r"
        SELECT generation, dispatch_started
        FROM work_dispatch_fact_guards
        WHERE tenant_id = $1 AND work_item_id = $2
        FOR UPDATE NOWAIT
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock pre-dispatch fact guard", &error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} has no dispatch-fact guard"
        ))
    })?;
    let dispatch_guard_generation: i64 = required(
        &dispatch_guard,
        "generation",
        "dispatch-fact guard generation",
    )?;
    let dispatch_started: bool = required(
        &dispatch_guard,
        "dispatch_started",
        "dispatch-fact guard state",
    )?;
    if job_fence_token < 0
        || workflow_version <= 0
        || workflow_fence_token < 0
        || workflow_event_cursor < 0
        || anchor_generation <= 0
        || dispatch_guard_generation <= 0
    {
        return Err(Error::Persistence(format!(
            "work item {work_item_id} has invalid pre-dispatch ledger counters"
        )));
    }
    if dispatch_started {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} has crossed the synchronous pre-dispatch cancellation boundary (dispatch guard is started)"
        )));
    }

    let ready_version = accepted_version.checked_sub(1).ok_or_else(|| {
        Error::Conflict(format!(
            "work item {work_item_id} has an invalid accepted version"
        ))
    })?;
    let acceptance_before_digest = digest_value(&json!({
        "state": "READY",
        "version": ready_version,
    }))?;
    let acceptance_after_digest = digest_value(&json!({
        "state": "ACCEPTED",
        "version": accepted_version,
        "workflow_id": workflow_id,
        "job_id": job_id,
    }))?;
    let accepted_version_i64 = i64_from_u64(accepted_version, "accepted work-item version")?;
    let acceptance_proofs = sqlx::query(
        r"
        SELECT audit.id
        FROM audit_events AS audit
        JOIN idempotency_records AS idempotency
          ON idempotency.tenant_id = audit.tenant_id
         AND idempotency.id::text = audit.correlation_id
         AND idempotency.actor_id = audit.actor_id
        JOIN work_items AS work
          ON work.tenant_id = audit.tenant_id
         AND work.id = audit.work_item_id
        WHERE audit.tenant_id = $1
          AND audit.work_item_id = $2
          AND audit.attempt_id IS NULL
          AND audit.actor_type = 'API_CALLER'
          AND audit.action = 'WORK_ITEM_ACCEPTED'
          AND audit.subject_type = 'WORK_ITEM'
          AND audit.subject_id = $2::text
          AND audit.policy_digest IS NOT DISTINCT FROM work.policy_digest
          AND audit.before_digest = $5
          AND audit.after_digest = $6
          AND audit.details = jsonb_build_object(
              'workflow_id', $3::uuid,
              'job_id', $4::uuid
          )
          AND idempotency.operation = 'api.work_item.accept'
          AND idempotency.request_digest = $7
          AND idempotency.state = 'COMPLETED'
          AND idempotency.response_status = 200
          AND idempotency.response_body = jsonb_build_object(
              'idempotency_key', idempotency.idempotency_key,
              'resource_id', $2::text,
              'status', 'accepted',
              'version', $8::bigint
          )
          AND idempotency.completed_at IS NOT NULL
        ORDER BY audit.id
        FOR SHARE OF idempotency NOWAIT
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_id)
    .bind(job_id)
    .bind(&acceptance_before_digest)
    .bind(&acceptance_after_digest)
    .bind(payload_request_digest)
    .bind(accepted_version_i64)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| database_error("lock pre-dispatch acceptance proof", &error))?;
    if acceptance_proofs.len() != 1 {
        return Err(Error::Conflict(format!(
            "work item {work_item_id} has no exact accepted-work audit and idempotency proof"
        )));
    }
    Ok(PreDispatchCancellationBinding {
        job_id,
        job_fence_token,
        job_attempt_count: attempt_count,
        workflow_id,
        workflow_version,
        workflow_fence_token,
        workflow_event_cursor,
        anchor_generation,
        dispatch_guard_generation,
    })
}

async fn require_pristine_pre_dispatch_boundary(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    delivery_workflow_id: Uuid,
) -> Result<()> {
    let row = sqlx::query(
        r"
        SELECT
            (SELECT count(*) FROM attempts
             WHERE tenant_id = $1 AND work_item_id = $2) AS attempts,
            (SELECT count(*) FROM workflow_instances
             WHERE tenant_id = $1 AND work_item_id = $2 AND id <> $3) AS extra_workflows,
            (SELECT count(*) FROM workflow_timers
             WHERE tenant_id = $1 AND work_item_id = $2) AS timers,
            (SELECT count(*) FROM reservation_sets
             WHERE tenant_id = $1 AND work_item_id = $2) AS reservations,
            (SELECT count(*) FROM effect_intents
             WHERE tenant_id = $1 AND work_item_id = $2) AS effects,
            (SELECT count(*) FROM runs
             WHERE tenant_id = $1 AND work_item_id = $2) AS runs,
            (SELECT count(*) FROM work_orders
             WHERE tenant_id = $1 AND work_item_id = $2) AS work_orders,
            (SELECT count(*) FROM approvals
             WHERE tenant_id = $1 AND work_item_id = $2) AS approvals,
            (SELECT count(*) FROM evidence_bundles
             WHERE tenant_id = $1 AND work_item_id = $2) AS evidence,
            (SELECT count(*) FROM escalations
             WHERE tenant_id = $1 AND work_item_id = $2) AS escalations,
            (SELECT count(*) FROM budget_ledger
             WHERE tenant_id = $1 AND work_item_id = $2) AS budget_facts,
            (SELECT count(*)
             FROM operational_incidents AS incident
             JOIN workflow_jobs AS incident_job
               ON incident_job.tenant_id = incident.tenant_id
              AND incident_job.id = incident.workflow_job_id
             WHERE incident_job.tenant_id = $1
               AND incident_job.work_item_id = $2) AS operational_incidents,
            (SELECT count(*) FROM cancellation_terminal_receipts
             WHERE tenant_id = $1 AND work_item_id = $2) AS terminal_receipts,
            (SELECT count(*) FROM audit_events
             WHERE tenant_id = $1
               AND work_item_id = $2
               AND action = 'WORK_ITEM_CANCELLED') AS terminal_audits,
            (SELECT count(*) FROM outbox
             WHERE tenant_id = $1
               AND message_key = $2::text
               AND event_type = 'work_item.cancelled') AS terminal_outbox
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(delivery_workflow_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| database_error("prove the pre-dispatch cancellation boundary", &error))?;
    let facts = [
        (
            "attempts",
            required::<i64>(&row, "attempts", "attempt count")?,
        ),
        (
            "extra_workflows",
            required::<i64>(&row, "extra_workflows", "extra workflow count")?,
        ),
        ("timers", required::<i64>(&row, "timers", "timer count")?),
        (
            "reservations",
            required::<i64>(&row, "reservations", "reservation count")?,
        ),
        ("effects", required::<i64>(&row, "effects", "effect count")?),
        ("runs", required::<i64>(&row, "runs", "run count")?),
        (
            "work_orders",
            required::<i64>(&row, "work_orders", "work-order count")?,
        ),
        (
            "approvals",
            required::<i64>(&row, "approvals", "approval count")?,
        ),
        (
            "evidence",
            required::<i64>(&row, "evidence", "evidence count")?,
        ),
        (
            "escalations",
            required::<i64>(&row, "escalations", "escalation count")?,
        ),
        (
            "budget_facts",
            required::<i64>(&row, "budget_facts", "budget-ledger fact count")?,
        ),
        (
            "operational_incidents",
            required::<i64>(&row, "operational_incidents", "operational-incident count")?,
        ),
        (
            "terminal_receipts",
            required::<i64>(&row, "terminal_receipts", "terminal receipt count")?,
        ),
        (
            "terminal_audits",
            required::<i64>(&row, "terminal_audits", "terminal cancellation audit count")?,
        ),
        (
            "terminal_outbox",
            required::<i64>(
                &row,
                "terminal_outbox",
                "terminal cancellation outbox count",
            )?,
        ),
    ];
    let crossed = facts
        .into_iter()
        .filter(|(_, count)| *count != 0)
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>();
    if crossed.is_empty() {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "work item {work_item_id} has crossed the synchronous pre-dispatch cancellation boundary ({})",
            crossed.join(", ")
        )))
    }
}

async fn cancel_accepted_before_dispatch(
    transaction: &mut Transaction<'_, Postgres>,
    cancellation: PreDispatchCancellation<'_>,
) -> Result<MutationReceipt> {
    let binding = lock_pre_dispatch_cancellation_binding(
        transaction,
        cancellation.tenant_id,
        cancellation.work_item_id,
        cancellation.version,
    )
    .await?;
    require_pristine_pre_dispatch_boundary(
        transaction,
        cancellation.tenant_id,
        cancellation.work_item_id,
        binding.workflow_id,
    )
    .await?;

    let requested_version = cancellation
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("work-item version overflowed".into()))?;
    let cancelled_version = requested_version
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("work-item version overflowed".into()))?;
    let final_job_fence = binding
        .job_fence_token
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("advance-job fence overflowed".into()))?;
    let final_workflow_version = binding
        .workflow_version
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("delivery workflow version overflowed".into()))?;
    let final_workflow_fence = binding
        .workflow_fence_token
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("delivery workflow fence overflowed".into()))?;
    let next_anchor_generation = binding
        .anchor_generation
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("accountability generation overflowed".into()))?;
    let terminal_receipt_id = derived_api_record_id(cancellation.correlation_id, 1);
    let outbox_event_id = derived_api_record_id(cancellation.correlation_id, 2);
    let requested = sqlx::query(
        r"
        UPDATE work_items
        SET state = 'CANCEL_REQUESTED',
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND state = 'ACCEPTED'
          AND current_attempt_id IS NULL
          AND aggregate_version = $3
        ",
    )
    .bind(cancellation.tenant_id)
    .bind(cancellation.work_item_id)
    .bind(i64_from_u64(cancellation.version, "work-item version")?)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("enter synchronous cancellation", &error))?
    .rows_affected();
    if requested != 1 {
        return Err(Error::Conflict(format!(
            "work item {} changed at the pre-dispatch cancellation boundary",
            cancellation.work_item_id
        )));
    }

    let job_result = json!({
        "schema": "asf.pre-dispatch-cancellation-result/v1",
        "disposition": "cancelled_before_dispatch",
        "work_item_id": cancellation.work_item_id,
        "workflow_id": binding.workflow_id,
        "accepted_version": cancellation.version,
        "cancelled_version": cancelled_version,
        "request_digest": cancellation.request_digest,
        "terminal_receipt_id": terminal_receipt_id,
    });
    let cancelled_job_fence = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE workflow_jobs
        SET status = 'CANCELLED',
            result = $6,
            fence_token = fence_token + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND workflow_instance_id = $3
          AND work_item_id = $4
          AND attempt_id IS NULL
          AND job_type = $7
          AND activity_contract_id = $8
          AND status IN ('PENDING', 'RETRY')
          AND fence_token = $5
          AND attempt_count < max_attempts
          AND result IS NULL
          AND lease_owner IS NULL
          AND lease_expires_at IS NULL
          AND completed_by IS NULL
          AND completion_fence_token IS NULL
          AND completed_at IS NULL
        RETURNING fence_token
        ",
    )
    .bind(cancellation.tenant_id)
    .bind(binding.job_id)
    .bind(binding.workflow_id)
    .bind(cancellation.work_item_id)
    .bind(binding.job_fence_token)
    .bind(&job_result)
    .bind(ADVANCE_ACCEPTED_WORK_ITEM)
    .bind(ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("cancel pre-dispatch advance job", &error))?;
    if cancelled_job_fence != Some(final_job_fence) {
        return Err(Error::Conflict(format!(
            "work item {} advance job changed during synchronous cancellation",
            cancellation.work_item_id
        )));
    }

    let next_workflow_cursor = binding
        .workflow_event_cursor
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("delivery workflow cursor overflowed".into()))?;
    let terminal_workflow = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE workflow_instances
        SET state = 'CANCELLED',
            event_cursor = $7,
            fence_token = fence_token + 1,
            aggregate_version = aggregate_version + 1,
            terminal_at = clock_timestamp(),
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND work_item_id = $3
          AND workflow_type = 'WORK_ITEM_DELIVERY'
          AND reducer_version = 'asf.workflow/v1'
          AND state = 'ACTIVE'
          AND aggregate_version = $4
          AND fence_token = $5
          AND event_cursor = $6
          AND terminal_at IS NULL
        RETURNING id
        ",
    )
    .bind(cancellation.tenant_id)
    .bind(binding.workflow_id)
    .bind(cancellation.work_item_id)
    .bind(binding.workflow_version)
    .bind(binding.workflow_fence_token)
    .bind(binding.workflow_event_cursor)
    .bind(next_workflow_cursor)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("terminalize pre-dispatch delivery workflow", &error))?;
    if terminal_workflow != Some(binding.workflow_id) {
        return Err(Error::Conflict(format!(
            "work item {} delivery workflow changed during synchronous cancellation",
            cancellation.work_item_id
        )));
    }

    let before_digest = digest_value(&json!({
        "state": "ACCEPTED",
        "version": cancellation.version,
    }))?;
    let after_digest = digest_value(&json!({
        "state": "CANCELLED",
        "version": cancelled_version,
        "workflow_id": binding.workflow_id,
        "job_id": binding.job_id,
        "request_digest": cancellation.request_digest,
    }))?;
    let audit_id = append_audit(
        transaction,
        AuditInsert {
            tenant_id: cancellation.tenant_id,
            work_item_id: Some(cancellation.work_item_id),
            attempt_id: None,
            actor: cancellation.caller,
            action: "WORK_ITEM_CANCELLED",
            subject_type: "WORK_ITEM",
            subject_id: &cancellation.work_item_id.to_string(),
            correlation_id: &cancellation.correlation_id.to_string(),
            policy_digest: cancellation.policy_digest,
            before_digest: Some(&before_digest),
            after_digest: Some(&after_digest),
            details: &json!({
                "job_id": binding.job_id,
                "reason": cancellation.reason,
                "request_digest": cancellation.request_digest,
                "route": "synchronous_pre_dispatch",
                "terminal_receipt_id": terminal_receipt_id,
                "workflow_id": binding.workflow_id,
            }),
        },
    )
    .await?;

    let outbox_payload = json!({
        "work_item_id": cancellation.work_item_id,
        "route": "synchronous_pre_dispatch",
        "terminal_receipt_id": terminal_receipt_id,
        "request_digest": cancellation.request_digest,
        "version": cancelled_version,
    });
    let outbox_idempotency_key = format!(
        "api-pre-dispatch-cancellation:{}:outbox",
        cancellation.correlation_id
    );
    sqlx::query(
        r#"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload,
            headers, idempotency_key
        ) VALUES (
            $1, $2, 'work-items', $3, 'work_item.cancelled', $4,
            '{"schema":"asf.work-item-event/v1"}'::jsonb, $5
        )
        "#,
    )
    .bind(outbox_event_id)
    .bind(cancellation.tenant_id)
    .bind(cancellation.work_item_id.to_string())
    .bind(&outbox_payload)
    .bind(&outbox_idempotency_key)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("append pre-dispatch cancellation outbox", &error))?;

    sqlx::query(
        r"
        INSERT INTO cancellation_terminal_receipts (
            id, tenant_id, work_item_id, route, outcome,
            attempt_id, run_id, effect_intent_id, terminal_observation_id,
            workflow_instance_id, workflow_job_id,
            workflow_job_fence_token, workflow_job_attempt_count,
            workflow_job_completed_by, audit_event_id, outbox_event_id,
            idempotency_record_id, escalation_id,
            work_item_version_before, work_item_version_after,
            attempt_version_before, attempt_version_after, attempt_fence_token,
            run_version_before, run_version_after,
            workflow_version_before, workflow_version_after,
            workflow_fence_before, workflow_fence_after,
            anchor_generation_before, anchor_generation_after,
            dispatch_guard_generation, released_reservations,
            audit_before_digest, audit_after_digest
        ) VALUES (
            $1, $2, $3, 'PRE_DISPATCH', 'CANCELLED',
            NULL, NULL, NULL, NULL,
            $4, $5, $6, $7, NULL, $8, $9, $10, NULL,
            $11, $12,
            NULL, NULL, NULL,
            NULL, NULL,
            $13, $14, $15, $16, $17, $18, $19, 0, $20, $21
        )
        ",
    )
    .bind(terminal_receipt_id)
    .bind(cancellation.tenant_id)
    .bind(cancellation.work_item_id)
    .bind(binding.workflow_id)
    .bind(binding.job_id)
    .bind(final_job_fence)
    .bind(binding.job_attempt_count)
    .bind(audit_id)
    .bind(outbox_event_id)
    .bind(cancellation.correlation_id)
    .bind(i64_from_u64(
        cancellation.version,
        "accepted work-item version",
    )?)
    .bind(i64_from_u64(
        cancelled_version,
        "cancelled work-item version",
    )?)
    .bind(binding.workflow_version)
    .bind(final_workflow_version)
    .bind(binding.workflow_fence_token)
    .bind(final_workflow_fence)
    .bind(binding.anchor_generation)
    .bind(next_anchor_generation)
    .bind(binding.dispatch_guard_generation)
    .bind(&before_digest)
    .bind(&after_digest)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("insert pre-dispatch cancellation receipt", &error))?;

    let replaced_anchor = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE accountability_anchors
        SET anchor_type = 'CANCELLATION',
            reference_id = $4,
            wake_or_deadline_at = NULL,
            authority_or_effect_active = false,
            generation = $6,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND anchor_type = 'WORKFLOW'
          AND reference_id = $3
          AND generation = $5
          AND wake_or_deadline_at IS NULL
          AND NOT authority_or_effect_active
        RETURNING generation
        ",
    )
    .bind(cancellation.tenant_id)
    .bind(cancellation.work_item_id)
    .bind(binding.workflow_id)
    .bind(terminal_receipt_id)
    .bind(binding.anchor_generation)
    .bind(next_anchor_generation)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("replace pre-dispatch accountability anchor", &error))?;
    if replaced_anchor != Some(next_anchor_generation) {
        return Err(Error::Conflict(format!(
            "work item {} accountability changed during synchronous cancellation",
            cancellation.work_item_id
        )));
    }

    let cancelled = sqlx::query(
        r"
        UPDATE work_items
        SET state = 'CANCELLED',
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND state = 'CANCEL_REQUESTED'
          AND current_attempt_id IS NULL
          AND aggregate_version = $3
        ",
    )
    .bind(cancellation.tenant_id)
    .bind(cancellation.work_item_id)
    .bind(i64_from_u64(requested_version, "work-item version")?)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("complete synchronous cancellation", &error))?
    .rows_affected();
    if cancelled != 1 {
        return Err(Error::Conflict(format!(
            "work item {} changed while synchronous cancellation completed",
            cancellation.work_item_id
        )));
    }

    Ok(MutationReceipt {
        idempotency_key: cancellation.idempotency_key.into(),
        resource_id: cancellation.work_item_id.to_string(),
        status: "cancelled".into(),
        version: Some(cancelled_version),
    })
}

async fn ensure_work_item_exists(pool: &PgPool, tenant_id: Uuid, work_item_id: Uuid) -> Result<()> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM work_items WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_one(pool)
    .await
    .map_err(|error| database_error("check work-item existence", &error))?;
    if exists {
        Ok(())
    } else {
        Err(Error::NotFound(format!("work item {work_item_id}")))
    }
}

async fn ensure_attention_coverage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<()> {
    let uncovered = sqlx::query(
        r"
        WITH complete_escalations AS (
            SELECT escalation.id, escalation.work_item_id,
                   escalation.attempt_id, escalation.category
            FROM escalations AS escalation
            WHERE escalation.tenant_id = $1
              AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
              AND escalation.owner_type IN ('PERSON', 'TEAM', 'ON_CALL')
              AND btrim(escalation.owner_id) <> ''
              AND btrim(escalation.required_action) <> ''
              AND escalation.deadline > escalation.opened_at
              AND jsonb_typeof(escalation.evidence_references) = 'array'
              AND jsonb_array_length(escalation.evidence_references) > 0
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(escalation.evidence_references) AS reference(value)
                  WHERE jsonb_typeof(reference.value) IS DISTINCT FROM 'string'
                     OR btrim(reference.value #>> '{}') = ''
              )
              AND jsonb_typeof(escalation.retry_policy) = 'object'
              AND (
                  SELECT count(*) = 4
                  FROM jsonb_object_keys(escalation.retry_policy)
              )
              AND escalation.retry_policy ?& ARRAY[
                  'automatic', 'max_additional_attempts',
                  'backoff_seconds', 'prerequisites'
              ]::text[]
              AND jsonb_typeof(escalation.retry_policy -> 'automatic') = 'boolean'
              AND jsonb_typeof(escalation.retry_policy -> 'max_additional_attempts') = 'number'
              AND jsonb_typeof(escalation.retry_policy -> 'backoff_seconds') = 'number'
              AND jsonb_typeof(escalation.retry_policy -> 'prerequisites') = 'array'
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      CASE
                          WHEN jsonb_typeof(escalation.retry_policy -> 'prerequisites') = 'array'
                              THEN escalation.retry_policy -> 'prerequisites'
                          ELSE '[]'::jsonb
                      END
                  ) AS prerequisite(value)
                  WHERE jsonb_typeof(prerequisite.value) IS DISTINCT FROM 'string'
                     OR btrim(prerequisite.value #>> '{}') = ''
              )
        ), complete_operational_incidents AS (
            SELECT incident.id, incident.workflow_job_id, incident.category
            FROM operational_incidents AS incident
            WHERE incident.tenant_id = $1
              AND incident.status IN ('OPEN', 'ACKNOWLEDGED')
              AND incident.owner_type IN ('PERSON', 'TEAM', 'ON_CALL')
              AND btrim(incident.owner_id) <> ''
              AND btrim(incident.required_action) <> ''
              AND incident.deadline > incident.opened_at
              AND jsonb_typeof(incident.evidence_references) = 'array'
              AND jsonb_array_length(incident.evidence_references) > 0
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(incident.evidence_references) AS reference(value)
                  WHERE jsonb_typeof(reference.value) IS DISTINCT FROM 'string'
                     OR btrim(reference.value #>> '{}') = ''
              )
              AND jsonb_typeof(incident.retry_policy) = 'object'
              AND (
                  SELECT count(*) = 4
                  FROM jsonb_object_keys(incident.retry_policy)
              )
              AND incident.retry_policy ?& ARRAY[
                  'automatic', 'max_additional_attempts',
                  'backoff_seconds', 'prerequisites'
              ]::text[]
              AND jsonb_typeof(incident.retry_policy -> 'automatic') = 'boolean'
              AND jsonb_typeof(incident.retry_policy -> 'max_additional_attempts') = 'number'
              AND jsonb_typeof(incident.retry_policy -> 'backoff_seconds') = 'number'
              AND jsonb_typeof(incident.retry_policy -> 'prerequisites') = 'array'
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      CASE
                          WHEN jsonb_typeof(incident.retry_policy -> 'prerequisites') = 'array'
                              THEN incident.retry_policy -> 'prerequisites'
                          ELSE '[]'::jsonb
                      END
                  ) AS prerequisite(value)
                  WHERE jsonb_typeof(prerequisite.value) IS DISTINCT FROM 'string'
                     OR btrim(prerequisite.value #>> '{}') = ''
              )
        ), uncovered AS (
            SELECT 'OPEN_ESCALATION'::text AS obligation_kind,
                   escalation.id AS source_id,
                   escalation.work_item_id
            FROM escalations AS escalation
            WHERE escalation.tenant_id = $1
              AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
              AND NOT EXISTS (
                  SELECT 1
                  FROM complete_escalations AS complete
                  WHERE complete.id = escalation.id
              )

            UNION ALL

            SELECT 'OPEN_OPERATIONAL_INCIDENT'::text,
                   incident.id,
                   NULL::uuid
            FROM operational_incidents AS incident
            WHERE incident.tenant_id = $1
              AND incident.status IN ('OPEN', 'ACKNOWLEDGED')
              AND NOT EXISTS (
                  SELECT 1
                  FROM complete_operational_incidents AS complete
                  WHERE complete.id = incident.id
              )

            UNION ALL

            SELECT 'PENDING_APPROVAL'::text,
                   approval.id,
                   approval.work_item_id
            FROM approvals AS approval
            WHERE approval.tenant_id = $1
              AND approval.status = 'PENDING'
              AND NOT EXISTS (
                  SELECT 1
                  FROM complete_escalations AS escalation
                  WHERE escalation.work_item_id = approval.work_item_id
                    AND escalation.attempt_id IS NOT DISTINCT FROM approval.attempt_id
                    AND escalation.category = 'NEEDS_APPROVAL'
              )

            UNION ALL

            SELECT CASE work.state
                       WHEN 'NEEDS_SPEC' THEN 'WORK_NEEDS_SPEC'
                       WHEN 'WAITING_DEPENDENCY' THEN 'WORK_WAITING_DEPENDENCY'
                       WHEN 'WAITING_APPROVAL' THEN 'WORK_WAITING_APPROVAL'
                       WHEN 'BLOCKED_EXTERNAL' THEN 'WORK_BLOCKED_EXTERNAL'
                       WHEN 'BUDGET_EXHAUSTED' THEN 'WORK_BUDGET_EXHAUSTED'
                       WHEN 'QUARANTINED' THEN 'WORK_QUARANTINED'
                       WHEN 'ESCALATED' THEN 'WORK_ESCALATED'
                   END,
                   work.id,
                   work.id
            FROM work_items AS work
            WHERE work.tenant_id = $1
              AND work.state IN (
                  'NEEDS_SPEC', 'WAITING_DEPENDENCY', 'WAITING_APPROVAL',
                  'BLOCKED_EXTERNAL', 'BUDGET_EXHAUSTED', 'QUARANTINED',
                  'ESCALATED'
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM complete_escalations AS escalation
                  WHERE escalation.work_item_id = work.id
                    AND (
                        work.state = 'ESCALATED'
                        OR escalation.category = CASE work.state
                            WHEN 'NEEDS_SPEC' THEN 'NEEDS_SPEC'
                            WHEN 'WAITING_DEPENDENCY' THEN 'BLOCKED_DEPENDENCY'
                            WHEN 'WAITING_APPROVAL' THEN 'NEEDS_APPROVAL'
                            WHEN 'BLOCKED_EXTERNAL' THEN 'BLOCKED_EXTERNAL'
                            WHEN 'BUDGET_EXHAUSTED' THEN 'BUDGET_EXHAUSTED'
                            WHEN 'QUARANTINED' THEN 'QUARANTINED'
                        END
                    )
              )

            UNION ALL

            SELECT 'DEAD_WORKFLOW_JOB'::text,
                   job.id,
                   job.work_item_id
            FROM workflow_jobs AS job
            WHERE job.tenant_id = $1
              AND job.status = 'DEAD'
              AND (
                  (
                      job.work_item_id IS NOT NULL
                      AND NOT EXISTS (
                          -- A terminal escalation remains the durable historical
                          -- owner of an exhausted job without remaining active
                          -- operator attention.
                          SELECT 1
                          FROM escalations AS escalation
                          WHERE escalation.id = job.dead_letter_escalation_id
                            AND escalation.tenant_id = job.tenant_id
                            AND escalation.work_item_id = job.work_item_id
                            AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
                      )
                  )
                  OR (
                      job.work_item_id IS NULL
                      AND NOT EXISTS (
                          -- Resolution closes the active obligation; it does not
                          -- erase the immutable ownership link retained by the
                          -- DEAD workflow job.
                          SELECT 1
                          FROM operational_incidents AS incident
                          WHERE incident.id = job.dead_letter_operational_incident_id
                            AND incident.tenant_id = job.tenant_id
                            AND incident.workflow_job_id = job.id
                            AND incident.category = 'WORKFLOW_JOB_EXHAUSTED'
                      )
                  )
              )
        )
        SELECT obligation_kind, source_id, work_item_id
        FROM uncovered
        ORDER BY obligation_kind, source_id
        LIMIT 1
        ",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("validate attention coverage", &error))?;

    let Some(row) = uncovered else {
        return Ok(());
    };
    let obligation = UncoveredAttentionObligation {
        kind: AttentionObligationKind::from_persisted(&required::<String>(
            &row,
            "obligation_kind",
            "attention obligation kind",
        )?)
        .map_err(|error| attention_projection_error(&error))?,
        source_id: required(&row, "source_id", "attention obligation id")?,
        work_item_id: optional::<Uuid>(&row, "work_item_id", "attention obligation work-item id")?
            .map(WorkItemId::from_uuid),
    };
    Err(attention_projection_error(&obligation.into_error()))
}

async fn fetch_optional_json(
    transaction: &mut Transaction<'_, Postgres>,
    sql: &str,
    tenant_id: Uuid,
    work_item_id: Uuid,
    context: &str,
) -> Result<Option<Value>> {
    sqlx::query(sql)
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| database_error(context, &error))?
        .map(|row| sanitized_column(&row, "value"))
        .transpose()
}

async fn fetch_json_list(
    transaction: &mut Transaction<'_, Postgres>,
    sql: &str,
    tenant_id: Uuid,
    work_item_id: Uuid,
    context: &str,
) -> Result<Vec<Value>> {
    let rows = sqlx::query(sql)
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| database_error(context, &error))?;
    rows.iter()
        .map(|row| sanitized_column(row, "value"))
        .collect()
}

async fn fetch_work_item_events(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    cursor_at: Option<DateTime<Utc>>,
    cursor_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<Value>> {
    let rows = fetch_work_item_event_rows(
        transaction,
        tenant_id,
        work_item_id,
        cursor_at,
        cursor_id,
        limit,
    )
    .await?;
    rows.iter().map(audit_value_from_row).collect()
}

async fn fetch_work_item_event_rows(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    cursor_at: Option<DateTime<Utc>>,
    cursor_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<PgRow>> {
    sqlx::query(
        r"
        SELECT
            id, actor_type, actor_id, action, subject_type, subject_id,
            correlation_id, trace_id, policy_digest, before_digest,
            after_digest, event_hash, details, occurred_at, ingested_at
        FROM audit_events
        WHERE tenant_id = $1 AND work_item_id = $2
          AND (
              $3::timestamptz IS NULL
              OR (occurred_at, id) < ($3::timestamptz, $4::uuid)
          )
        ORDER BY occurred_at DESC, id DESC
        LIMIT $5
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(cursor_at)
    .bind(cursor_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| database_error("load work-item events", &error))
}

fn audit_value_from_row(row: &PgRow) -> Result<Value> {
    let mut value = json!({
        "id": required::<Uuid>(row, "id", "audit id")?,
        "actor_type": required::<String>(row, "actor_type", "audit actor type")?,
        "actor_id": required::<String>(row, "actor_id", "audit actor")?,
        "action": required::<String>(row, "action", "audit action")?,
        "subject_type": required::<String>(row, "subject_type", "audit subject type")?,
        "subject_id": required::<String>(row, "subject_id", "audit subject")?,
        "correlation_id": required::<String>(row, "correlation_id", "audit correlation")?,
        "trace_id": optional::<String>(row, "trace_id", "audit trace")?,
        "policy_digest": optional::<String>(row, "policy_digest", "audit policy")?,
        "before_digest": optional::<String>(row, "before_digest", "audit before digest")?,
        "after_digest": optional::<String>(row, "after_digest", "audit after digest")?,
        "event_hash": required::<String>(row, "event_hash", "audit event hash")?,
        "details": required::<Value>(row, "details", "audit details")?,
        "occurred_at": required::<DateTime<Utc>>(row, "occurred_at", "audit occurrence")?,
        "ingested_at": required::<DateTime<Utc>>(row, "ingested_at", "audit ingestion")?,
    });
    redact_sensitive(&mut value);
    Ok(value)
}

fn work_item_from_row(row: &PgRow) -> Result<WorkItemView> {
    let priority = required::<i16>(row, "normalized_priority", "work-item priority")?;
    Ok(WorkItemView {
        id: WorkItemId::from_uuid(required(row, "id", "work-item id")?),
        source_system: required(row, "source_system", "source system")?,
        source_external_id: required(row, "source_external_id", "source external id")?,
        repository_id: optional::<Uuid>(row, "repository_id", "repository id")?
            .map(RepositoryId::from_uuid),
        state: parse_work_item_state(&required::<String>(row, "state", "work-item state")?)?,
        closure_target: optional::<String>(row, "closure_target", "closure target")?
            .map(|value| parse_closure_target(&value))
            .transpose()?,
        risk_class: optional::<String>(row, "risk_class", "risk class")?
            .map(|value| parse_risk_class(&value))
            .transpose()?,
        priority: u8::try_from(priority)
            .map_err(|_| Error::Persistence("invalid persisted work-item priority".into()))?,
        owner: optional(row, "owner_fallback", "work-item owner")?,
        deadline: optional(row, "due_at", "work-item deadline")?,
        version: positive_u64(
            required(row, "aggregate_version", "work-item version")?,
            "work-item version",
        )?,
        discovered_at: required(row, "discovered_at", "work-item discovery time")?,
        updated_at: required(row, "updated_at", "work-item update time")?,
    })
}

fn attention_from_row(row: &PgRow) -> Result<AttentionItemView> {
    let mut evidence_references: Value =
        required(row, "evidence_references", "evidence references")?;
    redact_sensitive(&mut evidence_references);
    let mut retry_policy: Value = required(row, "retry_policy", "retry policy")?;
    redact_sensitive(&mut retry_policy);
    let item = ApplicationAttentionItem::try_from(PersistedAttentionItem {
        kind: AttentionItemKind::from_persisted(&required::<String>(
            row,
            "kind",
            "attention item kind",
        )?)
        .map_err(|error| attention_projection_error(&error))?,
        id: required(row, "id", "attention record id")?,
        work_item_id: optional::<Uuid>(row, "work_item_id", "work-item id")?
            .map(WorkItemId::from_uuid),
        workflow_job_id: optional(row, "workflow_job_id", "workflow-job id")?,
        category: parse_escalation_category(&required::<String>(
            row,
            "category",
            "escalation category",
        )?)?,
        severity: required(row, "severity", "escalation severity")?,
        owner_kind: required(row, "owner_type", "escalation owner type")?,
        owner_id: redacted_text(required(row, "owner_id", "escalation owner")?),
        required_action: redacted_text(required(row, "required_action", "required action")?),
        evidence_references,
        deadline: required(row, "deadline", "escalation deadline")?,
        opened_at: required(row, "opened_at", "escalation opening time")?,
        retry_policy,
        authority_or_effect_active: required(
            row,
            "authority_or_effect_active",
            "active authority/effect flag",
        )?,
    })
    .map_err(|error| attention_projection_error(&error))?;
    let retry_policy = serde_json::to_value(&item.retry_policy)
        .map_err(|_error| Error::Serialization("serialize attention retry policy".into()))?;
    Ok(AttentionItemView {
        kind: item.kind,
        id: item.id,
        work_item_id: item.work_item_id,
        workflow_job_id: item.workflow_job_id,
        category: item.category,
        severity: item.severity.as_persisted().into(),
        owner: item.owner.id,
        required_action: item.required_action,
        evidence_references: item.evidence_references,
        deadline: item.deadline,
        retry_policy,
        authority_or_effect_active: item.authority_or_effect_active,
    })
}

fn worker_from_row(row: &PgRow) -> Result<WorkerView> {
    let mut capabilities: Value = required(row, "capabilities", "worker capabilities")?;
    redact_sensitive(&mut capabilities);
    let active_slots = required::<i64>(row, "active_slots", "active worker slots")?;
    let max_concurrency = required::<i32>(row, "max_concurrency", "worker concurrency")?;
    Ok(WorkerView {
        id: WorkerId::from_uuid(required(row, "id", "worker id")?),
        name: required(row, "name", "worker name")?,
        status: required(row, "status", "worker status")?,
        generation: positive_u64(
            required(row, "generation", "worker generation")?,
            "worker generation",
        )?,
        capabilities,
        active_slots: u16::try_from(active_slots)
            .map_err(|_| Error::Persistence("invalid active worker-slot count".into()))?,
        max_concurrency: u16::try_from(max_concurrency)
            .map_err(|_| Error::Persistence("invalid worker concurrency".into()))?,
        last_seen_at: optional(row, "last_seen_at", "worker last-seen time")?,
    })
}

fn sanitized_column(row: &PgRow, column: &str) -> Result<Value> {
    let mut value: Value = required(row, column, "JSON response")?;
    redact_sensitive(&mut value);
    Ok(value)
}

fn redact_sensitive(value: &mut Value) {
    const FRAGMENTS: &[&str] = &[
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "secret",
        "password",
        "credential",
        "keyring",
        "execution_handle",
        "vendor_home",
        "state_dir",
        "token_file",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase();
                if FRAGMENTS
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                {
                    *child = Value::String("[REDACTED]".into());
                } else {
                    redact_sensitive(child);
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_sensitive(child);
            }
        }
        Value::String(string) => {
            let normalized = string.to_ascii_lowercase();
            if normalized.starts_with("bearer ")
                || normalized.contains("-----begin private key-----")
                || normalized.contains("github_pat_")
            {
                *string = "[REDACTED]".into();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn redacted_text(value: String) -> String {
    let mut value = Value::String(value);
    redact_sensitive(&mut value);
    value
        .as_str()
        .expect("redacting a JSON string preserves its type")
        .into()
}

fn encode_cursor(kind: &str, at: DateTime<Utc>, id: Uuid) -> Result<String> {
    let bytes = serde_json::to_vec(&KeysetCursor {
        version: CURSOR_VERSION,
        kind: kind.into(),
        at,
        id,
    })
    .map_err(|_| Error::Serialization("serialize page cursor".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(value: Option<&str>, expected_kind: &str) -> Result<Option<KeysetCursor>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Validation("invalid page cursor".into()))?;
    let cursor: KeysetCursor = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Validation("invalid page cursor".into()))?;
    if cursor.version != CURSOR_VERSION || cursor.kind != expected_kind {
        return Err(Error::Validation(
            "page cursor does not belong to this collection".into(),
        ));
    }
    Ok(Some(cursor))
}

fn encode_attention_cursor(
    severity: AttentionSeverity,
    deadline: DateTime<Utc>,
    id: Uuid,
) -> Result<String> {
    let bytes = serde_json::to_vec(&AttentionKeysetCursor {
        version: CURSOR_VERSION,
        kind: "attention".into(),
        severity,
        deadline,
        id,
    })
    .map_err(|_| Error::Serialization("serialize attention page cursor".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_attention_cursor(value: Option<&str>) -> Result<Option<AttentionKeysetCursor>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Validation("invalid attention page cursor".into()))?;
    let cursor: AttentionKeysetCursor = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Validation("invalid attention page cursor".into()))?;
    if cursor.version != CURSOR_VERSION || cursor.kind != "attention" {
        return Err(Error::Validation(
            "page cursor does not belong to the attention collection".into(),
        ));
    }
    Ok(Some(cursor))
}

fn cursor_parts(cursor: Option<KeysetCursor>) -> (Option<DateTime<Utc>>, Option<Uuid>) {
    cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)))
}

fn cursor_from_row(row: &PgRow, kind: &str, time_column: &str) -> Result<String> {
    encode_cursor(
        kind,
        required(row, time_column, "cursor timestamp")?,
        required(row, "id", "cursor id")?,
    )
}

fn attention_cursor_from_row(row: &PgRow) -> Result<String> {
    let severity = AttentionSeverity::from_persisted(&required::<String>(
        row,
        "severity",
        "attention cursor severity",
    )?)
    .map_err(|error| attention_projection_error(&error))?;
    encode_attention_cursor(
        severity,
        required(row, "deadline", "attention cursor deadline")?,
        required(row, "id", "attention cursor id")?,
    )
}

fn attention_projection_error(error: &AttentionProjectionError) -> Error {
    Error::Persistence(error.to_string())
}

fn parse_work_item_state(value: &str) -> Result<WorkItemState> {
    let state = match value {
        "DISCOVERED" => WorkItemState::Discovered,
        "READINESS_PENDING" => WorkItemState::ReadinessPending,
        "NEEDS_SPEC" => WorkItemState::NeedsSpec,
        "READY" => WorkItemState::Ready,
        "ACCEPTED" => WorkItemState::Accepted,
        "PLANNED" => WorkItemState::Planned,
        "SCHEDULED" => WorkItemState::Scheduled,
        "DISPATCHING" => WorkItemState::Dispatching,
        "RUNNING" => WorkItemState::Running,
        "VERIFYING_OUTCOME" => WorkItemState::VerifyingOutcome,
        "TARGET_REACHED" => WorkItemState::TargetReached,
        "CLOSING_SOURCE" => WorkItemState::ClosingSource,
        "CLOSED" => WorkItemState::Closed,
        "WAITING_DEPENDENCY" => WorkItemState::WaitingDependency,
        "WAITING_APPROVAL" => WorkItemState::WaitingApproval,
        "RETRY_SCHEDULED" => WorkItemState::RetryScheduled,
        "BLOCKED_EXTERNAL" => WorkItemState::BlockedExternal,
        "BUDGET_EXHAUSTED" => WorkItemState::BudgetExhausted,
        "REFUSED" => WorkItemState::Refused,
        "QUARANTINED" => WorkItemState::Quarantined,
        "CANCEL_REQUESTED" => WorkItemState::CancelRequested,
        "CANCELLED" => WorkItemState::Cancelled,
        "ESCALATED" => WorkItemState::Escalated,
        other => {
            return Err(Error::Persistence(format!(
                "unknown persisted work-item state {other}"
            )));
        }
    };
    Ok(state)
}

fn parse_closure_target(value: &str) -> Result<ClosureTarget> {
    match value {
        "pull_request" => Ok(ClosureTarget::PullRequest),
        "merge" => Ok(ClosureTarget::Merge),
        "deploy" => Ok(ClosureTarget::Deploy),
        "observe" => Ok(ClosureTarget::Observe),
        other => Err(Error::Persistence(format!(
            "unknown persisted closure target {other}"
        ))),
    }
}

fn parse_risk_class(value: &str) -> Result<RiskClass> {
    match value {
        "low" => Ok(RiskClass::Low),
        "medium" => Ok(RiskClass::Medium),
        "high" => Ok(RiskClass::High),
        "critical" => Ok(RiskClass::Critical),
        "unknown" => Ok(RiskClass::Unknown),
        other => Err(Error::Persistence(format!(
            "unknown persisted risk class {other}"
        ))),
    }
}

fn parse_escalation_category(value: &str) -> Result<EscalationCategory> {
    match value {
        "NEEDS_SPEC" => Ok(EscalationCategory::NeedsSpec),
        "NEEDS_APPROVAL" => Ok(EscalationCategory::NeedsApproval),
        "BLOCKED_DEPENDENCY" => Ok(EscalationCategory::BlockedDependency),
        "BLOCKED_EXTERNAL" => Ok(EscalationCategory::BlockedExternal),
        "IDENTITY_UNAVAILABLE" => Ok(EscalationCategory::IdentityUnavailable),
        "WORKER_UNAVAILABLE" => Ok(EscalationCategory::WorkerUnavailable),
        "VERIFICATION_FAILED" => Ok(EscalationCategory::VerificationFailed),
        "REVIEW_BLOCKED" => Ok(EscalationCategory::ReviewBlocked),
        "CI_FAILED" => Ok(EscalationCategory::CiFailed),
        "REMOTE_EFFECT_AMBIGUOUS" => Ok(EscalationCategory::RemoteEffectAmbiguous),
        "BUDGET_EXHAUSTED" => Ok(EscalationCategory::BudgetExhausted),
        "PROVIDER_REFUSED" => Ok(EscalationCategory::ProviderRefused),
        "POLICY_REFUSED" => Ok(EscalationCategory::PolicyRefused),
        "WORKFLOW_JOB_EXHAUSTED" => Ok(EscalationCategory::WorkflowJobExhausted),
        "QUARANTINED" => Ok(EscalationCategory::Quarantined),
        "SECURITY_INCIDENT" => Ok(EscalationCategory::SecurityIncident),
        other => Err(Error::Persistence(format!(
            "unknown persisted escalation category {other}"
        ))),
    }
}

fn state_allows_cancellation(value: &str) -> bool {
    matches!(
        value,
        "ACCEPTED"
            | "PLANNED"
            | "SCHEDULED"
            | "DISPATCHING"
            | "RUNNING"
            | "WAITING_DEPENDENCY"
            | "WAITING_APPROVAL"
            | "RETRY_SCHEDULED"
            | "BLOCKED_EXTERNAL"
            | "BUDGET_EXHAUSTED"
            | "QUARANTINED"
            | "ESCALATED"
    )
}

fn validate_mutation_identity(caller: &Caller, idempotency_key: &str) -> Result<()> {
    if caller.subject.trim().is_empty() {
        return Err(Error::Validation("caller subject is required".into()));
    }
    if idempotency_key.trim().is_empty() || idempotency_key.len() > 512 {
        return Err(Error::Validation(
            "idempotency key must be 1..=512 bytes".into(),
        ));
    }
    Ok(())
}

fn require_expected_version(resource: &str, expected: u64, actual: u64) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::Conflict(format!(
            "{resource} version mismatch: expected {expected}, current {actual}"
        )))
    }
}

fn job_idempotency_key(
    tenant_id: Uuid,
    caller: &Caller,
    operation: &str,
    idempotency_key: &str,
) -> String {
    let digest = sha256_digest(
        format!(
            "{tenant_id}\0{}\0{operation}\0{idempotency_key}",
            caller.subject
        )
        .as_bytes(),
    );
    format!("api-job:{digest}")
}

fn derived_api_record_id(base: Uuid, discriminator: u8) -> Uuid {
    let mut bytes = *base.as_bytes();
    bytes[15] ^= discriminator;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn digest_value(value: &Value) -> Result<String> {
    canonical_json(value).map(|bytes| sha256_digest(&bytes))
}

fn positive_u64(value: i64, context: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Persistence(format!("invalid persisted {context}")))
}

fn i64_from_u64(value: u64, context: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Validation(format!("{context} is too large")))
}

fn required<T>(row: &PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|_error| Error::Persistence(format!("cannot decode {context}")))
}

fn optional<T>(row: &PgRow, column: &str, context: &str) -> Result<Option<T>>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|_error| Error::Persistence(format!("cannot decode {context}")))
}

fn database_error(context: &str, error: &sqlx::Error) -> Error {
    let code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    match code.as_deref() {
        Some("55P03") => Error::Conflict(format!(
            "{context} could not acquire the ledger row without waiting"
        )),
        Some("23505" | "23514" | "40001" | "40P01") => {
            Error::Conflict(format!("{context} was rejected by the ledger"))
        }
        Some("23503") => Error::Validation(format!("{context} references stale ledger state")),
        _ => Error::Persistence(format!("{context} failed")),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use async_trait::async_trait;
    use chrono::{Duration, TimeZone as _};
    use serde_json::json;

    use super::*;
    use crate::{
        ledger::ClaimedWorkflowJob,
        runtime::{
            ActivityControls, ActivityOutcome, JobClaimScope, JobHandler,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID, production_activity_contract_id,
        },
    };

    #[derive(Debug)]
    struct ReadyApiActivity {
        job_type: &'static str,
        activity_contract_id: &'static str,
        claim_scope: JobClaimScope,
    }

    impl ReadyApiActivity {
        fn unscoped(job_type: &'static str) -> Self {
            Self {
                job_type,
                activity_contract_id: production_activity_contract_id(job_type)
                    .expect("fixture job type is a recognized production activity"),
                claim_scope: JobClaimScope::Unscoped,
            }
        }

        const fn reconcile_worker(worker_id: WorkerId) -> Self {
            Self {
                job_type: RECONCILE_WORKER,
                activity_contract_id: RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
                claim_scope: JobClaimScope::ReconcileWorker(worker_id),
            }
        }

        const fn observe_runmill_run_worker(worker_id: WorkerId) -> Self {
            Self {
                job_type: OBSERVE_RUNMILL_RUN,
                activity_contract_id: OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
                claim_scope: JobClaimScope::ObserveRunmillRunWorker(worker_id),
            }
        }
    }

    #[async_trait]
    impl JobHandler for ReadyApiActivity {
        fn job_type(&self) -> &str {
            self.job_type
        }

        fn activity_contract_id(&self) -> &str {
            self.activity_contract_id
        }

        fn claim_scope(&self) -> JobClaimScope {
            self.claim_scope
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            unreachable!("API capability fixture must never execute")
        }
    }

    fn caller() -> Caller {
        Caller {
            subject: "operator:1".into(),
            roles: BTreeSet::new(),
        }
    }

    async fn insert_attention_work(pool: &PgPool, tenant_id: Uuid, work_item_id: Uuid) {
        let snapshot_id = Uuid::now_v7();
        let external_id = format!("attention-{work_item_id}");
        let content_digest = format!("sha256:{:064x}", work_item_id.as_u128());
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, source_system, external_id, source_revision,
                normalized_content, content_digest, connector_identity,
                source_updated_at
            ) VALUES (
                $1, $2, 'API', $3, '1', '{}'::jsonb, $4, 'attention-test',
                clock_timestamp()
            )
            ",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(&external_id)
        .bind(content_digest)
        .execute(pool)
        .await
        .expect("insert attention source snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, state, normalized_priority
            ) VALUES ($1, $2, $3, 'API', $4, 'NEEDS_SPEC', 50)
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(external_id)
        .execute(pool)
        .await
        .expect("insert attention work item");
    }

    async fn insert_attention_escalation(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
        escalation_id: Uuid,
        severity: &str,
        opened_at: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) {
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, category, severity, reason,
                owner_type, owner_id, required_action, evidence_references,
                deadline, retry_policy, authority_or_effect_active,
                idempotency_key, opened_at
            ) VALUES (
                $1, $2, $3, 'NEEDS_SPEC', $4, 'specification is incomplete',
                'TEAM', 'intake-owners', 'complete the missing specification',
                jsonb_build_array($5::text), $6,
                jsonb_build_object(
                    'automatic', false,
                    'max_additional_attempts', 0,
                    'backoff_seconds', 300,
                    'prerequisites', jsonb_build_array('complete specification')
                ),
                false, $7, $8
            )
            ",
        )
        .bind(escalation_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(severity)
        .bind(format!("work-item:{work_item_id}"))
        .bind(deadline)
        .bind(format!("attention-{escalation_id}"))
        .bind(opened_at)
        .execute(pool)
        .await
        .expect("insert complete attention escalation");
    }

    async fn insert_ready_api_work(
        pool: &PgPool,
        tenant_id: Uuid,
        repository_id: Uuid,
        policy_digest: &str,
        label: &str,
    ) -> (Uuid, String) {
        let snapshot_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let external_id = format!("{label}-{work_item_id}");
        let source_digest = sha256_digest(external_id.as_bytes());
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, repository_id, source_system, external_id,
                source_revision, normalized_content, content_digest,
                connector_identity, source_updated_at
            ) VALUES (
                $1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test',
                clock_timestamp()
            )
            ",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(&external_id)
        .bind(&source_digest)
        .execute(pool)
        .await
        .expect("insert ready API source snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, repository_id, state, closure_target,
                risk_class, policy_digest, budget_limits,
                identity_requirements, owner_fallback, normalized_priority,
                ready_at
            ) VALUES (
                $1, $2, $3, 'API', $4, $5, 'READY', 'pull_request',
                'low', $6, $7, $8, 'team:platform', 50, clock_timestamp()
            )
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(&external_id)
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
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "codex:pr-reviewer"
        }))
        .execute(pool)
        .await
        .expect("insert ready API work item");
        (work_item_id, source_digest)
    }

    async fn insert_accepted_api_boundary_with_payload(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
        policy_digest: &str,
        acceptance_idempotency_key: &str,
        job_payload: &Value,
        activity_contract_id: &str,
    ) {
        let actor = caller();
        let acceptance_request_digest = digest_value(&json!({
            "work_item_id": work_item_id,
            "expected_version": 1,
        }))
        .expect("digest handcrafted acceptance request");
        let mut transaction = begin_mutation(pool, tenant_id)
            .await
            .expect("begin handcrafted accepted boundary");
        let claim: IdempotencyClaim<MutationReceipt> = claim_idempotency(
            &mut transaction,
            tenant_id,
            &actor,
            OP_ACCEPT_WORK_ITEM,
            acceptance_idempotency_key,
            &acceptance_request_digest,
        )
        .await
        .expect("claim handcrafted acceptance idempotency");
        assert!(claim.replay.is_none());

        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, reducer_version
            ) VALUES ($1, $2, $3, 'WORK_ITEM_DELIVERY', 'asf.workflow/v1')
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert handcrafted accepted-work workflow");
        let job_key = job_idempotency_key(
            tenant_id,
            &actor,
            OP_ACCEPT_WORK_ITEM,
            acceptance_idempotency_key,
        );
        enqueue_job(
            &mut transaction,
            JobInsert {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: None,
                job_type: ADVANCE_ACCEPTED_WORK_ITEM,
                activity_contract_id,
                payload: job_payload,
                idempotency_key: &job_key,
                priority: 50,
            },
        )
        .await
        .expect("insert handcrafted advance job");
        upsert_workflow_anchor(&mut transaction, tenant_id, work_item_id, workflow_id)
            .await
            .expect("insert handcrafted workflow anchor");

        let changed = sqlx::query(
            r"
            UPDATE work_items
            SET state = 'ACCEPTED',
                accepted_at = clock_timestamp(),
                aggregate_version = 2,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND id = $2
              AND state = 'READY'
              AND aggregate_version = 1
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("transition handcrafted work to accepted")
        .rows_affected();
        assert_eq!(changed, 1);

        let before_digest =
            digest_value(&json!({"state": "READY", "version": 1})).expect("digest READY work");
        let after_digest = digest_value(&json!({
            "state": "ACCEPTED",
            "version": 2,
            "workflow_id": workflow_id,
            "job_id": job_id,
        }))
        .expect("digest ACCEPTED work");
        append_audit(
            &mut transaction,
            AuditInsert {
                tenant_id,
                work_item_id: Some(work_item_id),
                attempt_id: None,
                actor: &actor,
                action: "WORK_ITEM_ACCEPTED",
                subject_type: "WORK_ITEM",
                subject_id: &work_item_id.to_string(),
                correlation_id: &claim.record_id.to_string(),
                policy_digest: Some(policy_digest),
                before_digest: Some(&before_digest),
                after_digest: Some(&after_digest),
                details: &json!({"workflow_id": workflow_id, "job_id": job_id}),
            },
        )
        .await
        .expect("append handcrafted acceptance audit");
        complete_idempotency(
            &mut transaction,
            claim.record_id,
            &MutationReceipt {
                idempotency_key: acceptance_idempotency_key.into(),
                resource_id: work_item_id.to_string(),
                status: "accepted".into(),
                version: Some(2),
            },
            200,
        )
        .await
        .expect("complete handcrafted acceptance idempotency");
        commit_transaction(transaction)
            .await
            .expect("commit handcrafted accepted boundary");
    }

    #[test]
    fn keyset_cursors_are_typed_and_round_trip() {
        let at = Utc
            .with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
            .single()
            .expect("valid timestamp");
        let id = Uuid::now_v7();
        let encoded = encode_cursor("work-items", at, id).expect("encode cursor");
        let decoded = decode_cursor(Some(&encoded), "work-items")
            .expect("decode cursor")
            .expect("cursor exists");
        assert_eq!(decoded.at, at);
        assert_eq!(decoded.id, id);
        assert!(decode_cursor(Some(&encoded), "attention").is_err());
    }

    #[test]
    fn attention_cursor_round_trips_all_ordering_fields() {
        let deadline = Utc
            .with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
            .single()
            .expect("valid timestamp");
        let id = Uuid::from_u128(42);
        let encoded = encode_attention_cursor(AttentionSeverity::Critical, deadline, id)
            .expect("encode attention cursor");
        let decoded = decode_attention_cursor(Some(&encoded))
            .expect("decode attention cursor")
            .expect("cursor exists");
        assert_eq!(decoded.severity, AttentionSeverity::Critical);
        assert_eq!(decoded.deadline, deadline);
        assert_eq!(decoded.id, id);
        assert!(decode_cursor(Some(&encoded), "work-items").is_err());

        let work_cursor = encode_cursor("work-items", deadline, id).expect("encode work cursor");
        assert!(decode_attention_cursor(Some(&work_cursor)).is_err());
    }

    #[test]
    fn redaction_covers_keys_and_credential_shaped_values() {
        let mut value = json!({
            "nested": {"access_token": "secret-value"},
            "message": "Bearer abc",
            "safe": "visible"
        });
        redact_sensitive(&mut value);
        assert_eq!(value["nested"]["access_token"], "[REDACTED]");
        assert_eq!(value["message"], "[REDACTED]");
        assert_eq!(value["safe"], "visible");
    }

    #[test]
    fn job_keys_bind_actor_operation_and_tenant_without_raw_key() {
        let tenant = Uuid::now_v7();
        let first = job_idempotency_key(tenant, &caller(), OP_INTAKE_SYNC, "same-key");
        let second = job_idempotency_key(tenant, &caller(), OP_VERIFY_EVIDENCE, "same-key");
        assert_ne!(first, second);
        assert!(!first.contains("same-key"));
        assert!(first.starts_with("api-job:sha256:"));
    }

    #[test]
    fn internal_wire_mappings_are_strict() {
        assert_eq!(
            parse_closure_target("pull_request").expect("known target"),
            ClosureTarget::PullRequest
        );
        assert!(parse_work_item_state("ready").is_err());
        assert_eq!(
            parse_escalation_category("WORKFLOW_JOB_EXHAUSTED").expect("known category"),
            EscalationCategory::WorkflowJobExhausted
        );
        assert!(parse_escalation_category("unknown").is_err());
    }

    #[test]
    fn cancellation_states_match_the_domain_transition_boundary() {
        assert!(state_allows_cancellation("RUNNING"));
        assert!(state_allows_cancellation("ESCALATED"));
        assert!(!state_allows_cancellation("READY"));
        assert!(!state_allows_cancellation("CLOSED"));
    }

    #[tokio::test]
    async fn optional_live_health_and_tenant_readiness() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect to ASF_TEST_DATABASE_URL");
        let tenant_id = std::env::var("ASF_TEST_TENANT_ID")
            .ok()
            .map_or_else(TenantId::new, |value| {
                value.parse::<TenantId>().expect("valid ASF_TEST_TENANT_ID")
            });
        let backend = PostgresApiBackend::new(pool, tenant_id);
        backend.health().await.expect("live PostgreSQL health");
        if std::env::var_os("ASF_TEST_TENANT_ID").is_some() {
            backend.ready().await.expect("live tenant readiness");
            let page = backend
                .list_work_items(
                    tenant_id,
                    &PageQuery {
                        cursor: None,
                        limit: 1,
                    },
                )
                .await
                .expect("live tenant-scoped list");
            assert!(page.items.len() <= 1);
        }
    }

    #[tokio::test]
    async fn acceptance_requires_a_ready_activity_but_prior_receipts_still_replay() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect acceptance-gate administrator");
        let schema = format!("asf_acceptance_gate_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated acceptance-gate schema");
        let mut scoped_url = url::Url::parse(&database_url).expect("parse acceptance database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated acceptance-gate PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate acceptance-gate PostgreSQL");

        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let policy_digest = sha256_digest(b"acceptance-gate-policy");
        let source_digest = sha256_digest(b"acceptance-gate-source");
        let external_id = format!("acceptance-gate-{work_item_id}");
        let mut transaction = ledger.pool().begin().await.expect("begin gate fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("acceptance-gate-{tenant_id}"))
            .bind("Acceptance gate test")
            .execute(&mut *transaction)
            .await
            .expect("insert gate tenant");
        sqlx::query(
            "UPDATE v1_tenant_deployment_guards \
             SET configured_tenant_id = $1 WHERE singleton",
        )
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await
        .expect("activate gate tenant deployment boundary");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'acme', $3, $4, 'main')
            ",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(format!("gate-{}", repository_id.simple()))
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert gate repository");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, repository_id, scope, schema_version, digest,
                canonical_bytes, policy, created_by
            ) VALUES ($1, $2, $3, 'REPOSITORY', 'test/v1', $4, $5, '{}'::jsonb, 'test')
            ",
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(br"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert gate policy");
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, repository_id, source_system, external_id,
                source_revision, normalized_content, content_digest,
                connector_identity, source_updated_at
            ) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', clock_timestamp())
            ",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(&external_id)
        .bind(&source_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert gate source snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, repository_id, state, closure_target,
                risk_class, policy_digest, budget_limits,
                identity_requirements, owner_fallback, normalized_priority,
                ready_at
            ) VALUES (
                $1, $2, $3, 'API', $4, $5, 'READY', 'pull_request',
                'low', $6, $7, $8, 'team:platform', 50, clock_timestamp()
            )
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(&external_id)
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(json!({
            "max_cost_microunits": 1_000_000,
            "max_input_tokens": 100_000,
            "max_output_tokens": 100_000,
            "max_implementer_invocations": 2,
            "max_reviewer_invocations": 2,
            "max_fix_iterations": 1,
            "max_wall_time_seconds": 3_600,
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "codex:pr-reviewer"
        }))
        .execute(&mut *transaction)
        .await
        .expect("insert ready gate work item");
        transaction.commit().await.expect("commit gate fixture");

        let tenant = TenantId::from_uuid(tenant_id);
        let work_item = WorkItemId::from_uuid(work_item_id);
        let request = VersionedMutation {
            expected_version: 1,
        };
        let unavailable = PostgresApiBackend::from_ledger(&ledger, tenant);
        assert!(matches!(
            unavailable.intake_sync(&caller(), "intake-gate").await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains("orphaned intake obligation")
        ));
        assert!(matches!(
            unavailable
                .reconcile_worker(tenant, WorkerId::new(), &caller(), "reconcile-gate")
                .await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains("orphaned reconciliation obligation")
        ));
        assert!(matches!(
            unavailable
                .verify_evidence(tenant, EvidenceId::new(), &caller(), "verification-gate")
                .await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains("orphaned verification obligation")
        ));
        assert!(matches!(
            unavailable
                .accept_work_item(tenant, work_item, &request, &caller(), "accept-gate")
                .await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains("refusing to create an orphaned accepted obligation")
        ));
        let untouched: (String, i64, i64) = sqlx::query_as(
            r"
            SELECT work.state,
                   (SELECT count(*) FROM workflow_jobs WHERE tenant_id = work.tenant_id),
                   (SELECT count(*) FROM idempotency_records WHERE tenant_id = work.tenant_id)
            FROM work_items AS work
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load rejected acceptance state");
        assert_eq!(untouched, ("READY".into(), 0, 0));

        unavailable
            .ready()
            .await
            .expect("no unavailable activity owns an obligation before acceptance");
        let mut accepted_registry = HandlerRegistry::new();
        accepted_registry
            .register(Arc::new(ReadyApiActivity::unscoped(
                ADVANCE_ACCEPTED_WORK_ITEM,
            )))
            .expect("register accepted-work activity");
        let ready = PostgresApiBackend::from_ledger(&ledger, tenant)
            .with_activity_capabilities(accepted_registry.api_activity_capabilities());
        let accepted = ready
            .accept_work_item(tenant, work_item, &request, &caller(), "accept-gate")
            .await
            .expect("accept when the activity is installed");
        ready
            .ready()
            .await
            .expect("the installed activity owns its accepted obligation");
        let replayed = unavailable
            .accept_work_item(tenant, work_item, &request, &caller(), "accept-gate")
            .await
            .expect("replay prior receipt after activity loss");
        assert_eq!(replayed, accepted);
        assert!(matches!(
            unavailable.ready().await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains(&format!(
                    "ADVANCE_ACCEPTED_WORK_ITEM[activity_contract_id={ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID}]=1"
                ))
        ));

        let serviced_worker = WorkerId::new();
        let unserviced_worker = WorkerId::new();
        let serviced_observation_worker = WorkerId::new();
        let unserviced_observation_worker = WorkerId::new();
        for (sequence, worker_id) in [serviced_worker, unserviced_worker, unserviced_worker]
            .into_iter()
            .enumerate()
        {
            let job_id = Uuid::now_v7();
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, job_type, activity_contract_id, payload, idempotency_key
                ) VALUES ($1, $2, 'RECONCILE_WORKER', $3, $4, $5)
                ",
            )
            .bind(job_id)
            .bind(tenant_id)
            .bind(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
            .bind(json!({"worker_id": worker_id}))
            .bind(format!("readiness-route:{sequence}:{job_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert exact worker-route readiness obligation");
        }
        for (sequence, worker_id) in [
            serviced_observation_worker,
            unserviced_observation_worker,
            unserviced_observation_worker,
        ]
        .into_iter()
        .enumerate()
        {
            let job_id = Uuid::now_v7();
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, job_type, activity_contract_id, payload, idempotency_key
                ) VALUES ($1, $2, 'OBSERVE_RUNMILL_RUN', $3, $4, $5)
                ",
            )
            .bind(job_id)
            .bind(tenant_id)
            .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
            .bind(json!({"worker_id": worker_id}))
            .bind(format!("readiness-observation-route:{sequence}:{job_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert exact Runmill observation-route readiness obligation");
        }
        accepted_registry
            .register(Arc::new(ReadyApiActivity::reconcile_worker(
                serviced_worker,
            )))
            .expect("register exact worker-reconciliation activity");
        accepted_registry
            .register(Arc::new(ReadyApiActivity::observe_runmill_run_worker(
                serviced_observation_worker,
            )))
            .expect("register exact Runmill observation activity");
        let routed = PostgresApiBackend::from_ledger(&ledger, tenant)
            .with_activity_capabilities(accepted_registry.api_activity_capabilities());
        let route_error = routed
            .ready()
            .await
            .expect_err("an unserviceable exact worker route must fail readiness");
        let Error::ExternalUnavailable(route_detail) = route_error else {
            panic!("unexpected exact-route readiness error: {route_error}");
        };
        assert!(route_detail.contains(&format!(
            "RECONCILE_WORKER[worker_id={unserviced_worker}, activity_contract_id={RECONCILE_WORKER_ACTIVITY_CONTRACT_ID}]=2"
        )));
        assert!(route_detail.contains(&format!(
            "OBSERVE_RUNMILL_RUN[worker_id={unserviced_observation_worker}, activity_contract_id={OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID}]=2"
        )));
        assert!(!route_detail.contains(serviced_worker.to_string().as_str()));
        assert!(!route_detail.contains(serviced_observation_worker.to_string().as_str()));
        assert!(!route_detail.contains("ADVANCE_ACCEPTED_WORK_ITEM"));

        let approval_id = ApprovalId::new();
        let decision = ApprovalDecisionRequest {
            decision: "approve".into(),
            reason: None,
            expected_version: 1,
        };
        assert!(matches!(
            unavailable
                .decide_approval(
                    tenant,
                    approval_id,
                    &decision,
                    &caller(),
                    "approval-gate",
                )
                .await,
            Err(Error::ExternalUnavailable(detail))
                if detail.contains("refusing to create an orphaned authority decision")
        ));
        let idempotency_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM idempotency_records WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(ledger.pool())
        .await
        .expect("count rolled-back approval claims");
        assert_eq!(idempotency_count, 1);
        ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("drop isolated acceptance-gate schema");
        admin.close().await;
    }

    #[tokio::test]
    async fn readyz_reports_a_persisted_wrong_contract_unserviceable_even_when_the_job_type_is_locally_ready()
     {
        const WRONG_CONTRACT: &str = "asf.activity/advance-accepted-work-item/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect readyz-contract administrator");
        let schema = format!("asf_readyz_contract_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated readyz-contract schema");
        let mut scoped_url =
            url::Url::parse(&database_url).expect("parse readyz-contract database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated readyz-contract PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate readyz-contract PostgreSQL");

        let tenant_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("readyz-contract-{tenant_id}"))
            .bind("Readyz contract test")
            .execute(ledger.pool())
            .await
            .expect("insert readyz-contract tenant");
        sqlx::query(
            "UPDATE v1_tenant_deployment_guards \
             SET configured_tenant_id = $1 WHERE singleton",
        )
        .bind(tenant_id)
        .execute(ledger.pool())
        .await
        .expect("activate readyz-contract tenant deployment boundary");
        let job_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key
            ) VALUES ($1, $2, 'ADVANCE_ACCEPTED_WORK_ITEM', $3, '{}'::jsonb, $4)
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(WRONG_CONTRACT)
        .bind(format!("readyz-contract-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert persisted wrong-contract obligation");

        let tenant = TenantId::from_uuid(tenant_id);
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ReadyApiActivity::unscoped(
                ADVANCE_ACCEPTED_WORK_ITEM,
            )))
            .expect("register locally ready accepted-work activity");
        let backend = PostgresApiBackend::from_ledger(&ledger, tenant)
            .with_activity_capabilities(registry.api_activity_capabilities());

        let error = backend
            .ready()
            .await
            .expect_err("a persisted wrong contract must be unserviceable even though the job type is locally ready");
        let Error::ExternalUnavailable(detail) = error else {
            panic!("unexpected readyz error for a persisted wrong contract: {error}");
        };
        assert!(detail.contains("ADVANCE_ACCEPTED_WORK_ITEM"));
        assert!(detail.contains(WRONG_CONTRACT));

        ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("drop isolated readyz-contract schema");
        admin.close().await;
    }

    #[tokio::test]
    async fn accepted_pre_dispatch_cancellation_is_synchronous_and_fail_closed() {
        const WRONG_CONTRACT: &str = "asf.activity/advance-accepted-work-item/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect pre-dispatch-cancellation administrator");
        let schema = format!("asf_pre_dispatch_cancel_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated pre-dispatch-cancellation schema");
        let mut scoped_url =
            url::Url::parse(&database_url).expect("parse cancellation database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated pre-dispatch-cancellation PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate pre-dispatch-cancellation PostgreSQL");

        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let policy_digest = sha256_digest(b"pre-dispatch-cancellation-policy");
        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin cancellation fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("pre-dispatch-cancel-{tenant_id}"))
            .bind("Pre-dispatch cancellation test")
            .execute(&mut *transaction)
            .await
            .expect("insert cancellation tenant");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'acme', $3, $4, 'main')
            ",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(format!("cancel-{}", repository_id.simple()))
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert cancellation repository");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, repository_id, scope, schema_version, digest,
                canonical_bytes, policy, created_by
            ) VALUES ($1, $2, $3, 'REPOSITORY', 'test/v1', $4, $5, '{}'::jsonb, 'test')
            ",
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(br"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert cancellation policy");
        transaction
            .commit()
            .await
            .expect("commit cancellation fixture");

        let (work_item_id, _) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-clean",
        )
        .await;
        let (crossed_work_item_id, crossed_source_digest) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-crossed",
        )
        .await;
        let (malformed_version_work_item_id, _) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-malformed-version",
        )
        .await;
        let (malformed_shape_work_item_id, _) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-malformed-shape",
        )
        .await;
        let (forged_acceptance_work_item_id, _) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-forged-acceptance",
        )
        .await;
        let (wrong_contract_work_item_id, _) = insert_ready_api_work(
            ledger.pool(),
            tenant_id,
            repository_id,
            &policy_digest,
            "cancel-wrong-contract",
        )
        .await;
        let tenant = TenantId::from_uuid(tenant_id);
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ReadyApiActivity::unscoped(
                ADVANCE_ACCEPTED_WORK_ITEM,
            )))
            .expect("register accepted-work test activity");
        let ready = PostgresApiBackend::from_ledger(&ledger, tenant)
            .with_activity_capabilities(registry.api_activity_capabilities());
        let unavailable = PostgresApiBackend::from_ledger(&ledger, tenant);
        for (work_item_id, key) in [
            (work_item_id, "accept-clean"),
            (crossed_work_item_id, "accept-crossed"),
        ] {
            let receipt = ready
                .accept_work_item(
                    tenant,
                    WorkItemId::from_uuid(work_item_id),
                    &VersionedMutation {
                        expected_version: 1,
                    },
                    &caller(),
                    key,
                )
                .await
                .expect("accept pre-dispatch cancellation fixture");
            assert_eq!(receipt.status, "accepted");
            assert_eq!(receipt.version, Some(2));
        }

        let malformed_version_acceptance_digest = digest_value(&json!({
            "work_item_id": malformed_version_work_item_id,
            "expected_version": 1,
        }))
        .expect("digest malformed-version acceptance request");
        insert_accepted_api_boundary_with_payload(
            ledger.pool(),
            tenant_id,
            malformed_version_work_item_id,
            &policy_digest,
            "accept-malformed-version",
            &json!({
                "work_item_id": malformed_version_work_item_id,
                "accepted_version": 3,
                "request_digest": malformed_version_acceptance_digest,
            }),
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        )
        .await;
        let malformed_shape_acceptance_digest = digest_value(&json!({
            "work_item_id": malformed_shape_work_item_id,
            "expected_version": 1,
        }))
        .expect("digest malformed-shape acceptance request");
        insert_accepted_api_boundary_with_payload(
            ledger.pool(),
            tenant_id,
            malformed_shape_work_item_id,
            &policy_digest,
            "accept-malformed-shape",
            &json!({
                "work_item_id": malformed_shape_work_item_id,
                "accepted_version": 2,
                "request_digest": malformed_shape_acceptance_digest,
                "unexpected": true,
            }),
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        )
        .await;
        let forged_acceptance_digest = sha256_digest(b"forged accepted-work request");
        insert_accepted_api_boundary_with_payload(
            ledger.pool(),
            tenant_id,
            forged_acceptance_work_item_id,
            &policy_digest,
            "accept-forged-acceptance",
            &json!({
                "work_item_id": forged_acceptance_work_item_id,
                "accepted_version": 2,
                "request_digest": forged_acceptance_digest,
            }),
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        )
        .await;
        // Syntactically well-formed and exact in every other respect, but
        // persisted under a different activity contract than this process's
        // ADVANCE_ACCEPTED_WORK_ITEM handler declares. The synchronous
        // pre-dispatch cancellation boundary must not interpret this as the
        // job it knows how to cancel.
        let wrong_contract_acceptance_digest = digest_value(&json!({
            "work_item_id": wrong_contract_work_item_id,
            "expected_version": 1,
        }))
        .expect("digest wrong-contract acceptance request");
        insert_accepted_api_boundary_with_payload(
            ledger.pool(),
            tenant_id,
            wrong_contract_work_item_id,
            &policy_digest,
            "accept-wrong-contract",
            &json!({
                "work_item_id": wrong_contract_work_item_id,
                "accepted_version": 2,
                "request_digest": wrong_contract_acceptance_digest,
            }),
            WRONG_CONTRACT,
        )
        .await;

        let cancellation = CancellationRequest {
            expected_version: 2,
            reason: "operator cancelled before dispatch".into(),
        };
        let malformed_version = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(malformed_version_work_item_id),
                &cancellation,
                &caller(),
                "cancel-malformed-version",
            )
            .await
            .expect_err("a mismatched accepted version must fail closed");
        assert!(matches!(
            malformed_version,
            Error::Conflict(detail)
                if detail.contains("pre-dispatch cancellation boundary")
        ));

        let malformed_shape = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(malformed_shape_work_item_id),
                &cancellation,
                &caller(),
                "cancel-malformed-shape",
            )
            .await
            .expect_err("a non-exact advance payload must fail closed");
        assert!(matches!(
            malformed_shape,
            Error::Conflict(detail)
                if detail.contains("pre-dispatch cancellation boundary")
        ));

        let forged_acceptance = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(forged_acceptance_work_item_id),
                &cancellation,
                &caller(),
                "cancel-forged-acceptance",
            )
            .await
            .expect_err("an advance payload without acceptance proof must fail closed");
        assert!(matches!(
            forged_acceptance,
            Error::Conflict(detail)
                if detail.contains("accepted-work audit and idempotency proof")
        ));

        let wrong_contract = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(wrong_contract_work_item_id),
                &cancellation,
                &caller(),
                "cancel-wrong-contract",
            )
            .await
            .expect_err(
                "an advance job persisted under a different activity contract must fail closed",
            );
        assert!(matches!(
            wrong_contract,
            Error::Conflict(detail)
                if detail.contains("pre-dispatch cancellation boundary")
        ));

        let malformed_states: Vec<(Uuid, String, i64, String, i64)> = sqlx::query_as(
            r"
            SELECT
                work.id,
                work.state,
                work.aggregate_version,
                job.status,
                (SELECT count(*) FROM cancellation_terminal_receipts AS receipt
                 WHERE receipt.tenant_id = work.tenant_id
                   AND receipt.work_item_id = work.id)
            FROM work_items AS work
            JOIN workflow_jobs AS job
              ON job.tenant_id = work.tenant_id
             AND job.work_item_id = work.id
             AND job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
            WHERE work.tenant_id = $1
              AND work.id = ANY($2::uuid[])
            ORDER BY work.id
            ",
        )
        .bind(tenant_id)
        .bind(vec![
            malformed_version_work_item_id,
            malformed_shape_work_item_id,
            forged_acceptance_work_item_id,
            wrong_contract_work_item_id,
        ])
        .fetch_all(ledger.pool())
        .await
        .expect("load rolled-back malformed pre-dispatch cancellations");
        assert_eq!(malformed_states.len(), 4);
        for (_, work_state, work_version, job_status, receipt_count) in malformed_states {
            assert_eq!(work_state, "ACCEPTED");
            assert_eq!(work_version, 2);
            assert_eq!(job_status, "PENDING");
            assert_eq!(receipt_count, 0);
        }
        let malformed_idempotency_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM idempotency_records
            WHERE tenant_id = $1
              AND operation = 'api.work_item.cancel'
              AND idempotency_key IN (
                  'cancel-malformed-version',
                  'cancel-malformed-shape',
                  'cancel-forged-acceptance',
                  'cancel-wrong-contract'
              )
            ",
        )
        .bind(tenant_id)
        .fetch_one(ledger.pool())
        .await
        .expect("count rolled-back malformed cancellation claims");
        assert_eq!(malformed_idempotency_count, 0);

        let mut held_guard = ledger
            .pool()
            .begin()
            .await
            .expect("begin competing dispatch-fact writer");
        sqlx::query(
            r"
            SELECT generation
            FROM work_dispatch_fact_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            FOR UPDATE
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *held_guard)
        .await
        .expect("hold dispatch-fact guard without locking the work item");
        let guard_raced = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ready.cancel_work_item(
                tenant,
                WorkItemId::from_uuid(work_item_id),
                &cancellation,
                &caller(),
                "cancel-clean",
            ),
        )
        .await
        .expect("NOWAIT dispatch-guard race must return promptly")
        .expect_err("a locked dispatch-fact guard must close the cancellation boundary");
        assert!(matches!(
            guard_raced,
            Error::Conflict(detail)
                if detail.contains("lock pre-dispatch fact guard")
                    && detail.contains("without waiting")
        ));
        held_guard
            .rollback()
            .await
            .expect("release competing dispatch-fact guard");

        let mut held_job = ledger
            .pool()
            .begin()
            .await
            .expect("begin competing advance-job claim");
        let held_job_id = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM workflow_jobs
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
            FOR UPDATE
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(&mut *held_job)
        .await
        .expect("hold sole advance job without locking the work item");
        let raced = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ready.cancel_work_item(
                tenant,
                WorkItemId::from_uuid(work_item_id),
                &cancellation,
                &caller(),
                "cancel-clean",
            ),
        )
        .await
        .expect("NOWAIT cancellation race must return promptly")
        .expect_err("a locked advance job must win the dispatch boundary race");
        assert!(matches!(
            raced,
            Error::Conflict(detail)
                if detail.contains("lock pre-dispatch workflow jobs")
                    && detail.contains("without waiting")
        ));
        let raced_state: (String, i64, String, i64) = sqlx::query_as(
            r"
            SELECT
                work.state,
                work.aggregate_version,
                job.status,
                (SELECT count(*)
                 FROM idempotency_records AS record
                 WHERE record.tenant_id = work.tenant_id
                   AND record.operation = 'api.work_item.cancel'
                   AND record.idempotency_key = 'cancel-clean')
            FROM work_items AS work
            JOIN workflow_jobs AS job
              ON job.tenant_id = work.tenant_id
             AND job.id = $3
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(held_job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load state after refused NOWAIT cancellation race");
        assert_eq!(raced_state, ("ACCEPTED".into(), 2, "PENDING".into(), 0));
        held_job
            .rollback()
            .await
            .expect("release competing advance-job claim");

        let cancelled = ready
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(work_item_id),
                &cancellation,
                &caller(),
                "cancel-clean",
            )
            .await
            .expect("cancel accepted work synchronously without a worker route");
        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(cancelled.version, Some(4));
        let replayed = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(work_item_id),
                &cancellation,
                &caller(),
                "cancel-clean",
            )
            .await
            .expect("replay synchronous cancellation with an unavailable registry");
        assert_eq!(replayed, cancelled);
        let cancellation_idempotency: (Uuid, i32, Value) = sqlx::query_as(
            r"
            SELECT id, response_status, response_body
            FROM idempotency_records
            WHERE tenant_id = $1
              AND operation = 'api.work_item.cancel'
              AND idempotency_key = 'cancel-clean'
            ",
        )
        .bind(tenant_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load synchronous cancellation idempotency proof");
        assert_eq!(cancellation_idempotency.1, 200);
        assert_eq!(
            cancellation_idempotency.2,
            serde_json::to_value(&cancelled).expect("serialize expected cancellation receipt")
        );
        let terminal_receipt_id = derived_api_record_id(cancellation_idempotency.0, 1);
        let outbox_event_id = derived_api_record_id(cancellation_idempotency.0, 2);

        let work: (String, i64, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT state, aggregate_version, current_attempt_id
            FROM work_items
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load synchronously cancelled work item");
        assert_eq!(work, ("CANCELLED".into(), 4, None));

        let jobs: Vec<(Uuid, Uuid, String, i64, Value)> = sqlx::query_as(
            r"
            SELECT id, workflow_instance_id, status, fence_token, result
            FROM workflow_jobs
            WHERE tenant_id = $1 AND work_item_id = $2
            ORDER BY id
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_all(ledger.pool())
        .await
        .expect("load cancelled advance job");
        assert_eq!(
            jobs.len(),
            1,
            "synchronous cancellation must not enqueue an orphan job"
        );
        let (job_id, workflow_id, job_status, job_fence, job_result) = &jobs[0];
        assert_eq!(*job_id, held_job_id);
        assert_eq!(job_status, "CANCELLED");
        assert_eq!(*job_fence, 1);
        let cancellation_digest = digest_value(&json!({
            "work_item_id": work_item_id,
            "expected_version": 2,
            "reason": cancellation.reason,
        }))
        .expect("digest cancellation request");
        assert_eq!(
            job_result,
            &json!({
                "schema": "asf.pre-dispatch-cancellation-result/v1",
                "disposition": "cancelled_before_dispatch",
                "work_item_id": work_item_id,
                "workflow_id": workflow_id,
                "accepted_version": 2,
                "cancelled_version": 4,
                "request_digest": cancellation_digest,
                "terminal_receipt_id": terminal_receipt_id,
            })
        );

        let workflow: (String, i64, i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            r"
            SELECT state, aggregate_version, fence_token, event_cursor, terminal_at
            FROM workflow_instances
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(workflow_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load terminal delivery workflow");
        assert_eq!(workflow.0, "CANCELLED");
        assert_eq!((workflow.1, workflow.2, workflow.3), (2, 1, 1));
        assert!(workflow.4.is_some());

        let audit: (Uuid, String, String, String, Option<Uuid>, Value) = sqlx::query_as(
            r"
            SELECT id, action, subject_type, subject_id, attempt_id, details
            FROM audit_events
            WHERE tenant_id = $1
              AND work_item_id = $2
              AND action = 'WORK_ITEM_CANCELLED'
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load exact API cancellation audit");
        assert_eq!(audit.1, "WORK_ITEM_CANCELLED");
        assert_eq!(audit.2, "WORK_ITEM");
        assert_eq!(audit.3, work_item_id.to_string());
        assert_eq!(audit.4, None);
        assert_eq!(
            audit.5,
            json!({
                "job_id": job_id,
                "reason": cancellation.reason,
                "request_digest": cancellation_digest,
                "route": "synchronous_pre_dispatch",
                "terminal_receipt_id": terminal_receipt_id,
                "workflow_id": workflow_id,
            })
        );
        let anchor: (String, Uuid, i64, Option<DateTime<Utc>>, bool) = sqlx::query_as(
            r"
            SELECT anchor_type, reference_id, generation,
                   wake_or_deadline_at, authority_or_effect_active
            FROM accountability_anchors
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load terminal cancellation anchor");
        assert_eq!(
            anchor,
            ("CANCELLATION".into(), terminal_receipt_id, 2, None, false)
        );
        let outbox: (Uuid, String, String, String, Value, Value, String) = sqlx::query_as(
            r"
            SELECT id, topic, message_key, event_type, payload, headers, idempotency_key
            FROM outbox
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(outbox_event_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load terminal pre-dispatch cancellation outbox");
        assert_eq!(outbox.0, outbox_event_id);
        assert_eq!(outbox.1, "work-items");
        assert_eq!(outbox.2, work_item_id.to_string());
        assert_eq!(outbox.3, "work_item.cancelled");
        assert_eq!(
            outbox.4,
            json!({
                "work_item_id": work_item_id,
                "route": "synchronous_pre_dispatch",
                "terminal_receipt_id": terminal_receipt_id,
                "request_digest": cancellation_digest,
                "version": 4,
            })
        );
        assert_eq!(outbox.5, json!({"schema": "asf.work-item-event/v1"}));
        assert_eq!(
            outbox.6,
            format!(
                "api-pre-dispatch-cancellation:{}:outbox",
                cancellation_idempotency.0
            )
        );

        let terminal_receipt = sqlx::query(
            r"
            SELECT *
            FROM cancellation_terminal_receipts
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(terminal_receipt_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load exact pre-dispatch terminal receipt");
        assert_eq!(
            terminal_receipt.try_get::<String, _>("route").unwrap(),
            "PRE_DISPATCH"
        );
        assert_eq!(
            terminal_receipt.try_get::<String, _>("outcome").unwrap(),
            "CANCELLED"
        );
        for column in [
            "attempt_id",
            "run_id",
            "effect_intent_id",
            "terminal_observation_id",
            "escalation_id",
        ] {
            assert!(
                terminal_receipt
                    .try_get::<Option<Uuid>, _>(column)
                    .unwrap()
                    .is_none(),
                "pre-dispatch receipt column {column} must remain null"
            );
        }
        assert!(
            terminal_receipt
                .try_get::<Option<String>, _>("workflow_job_completed_by")
                .unwrap()
                .is_none()
        );
        for column in [
            "attempt_version_before",
            "attempt_version_after",
            "attempt_fence_token",
            "run_version_before",
            "run_version_after",
        ] {
            assert!(
                terminal_receipt
                    .try_get::<Option<i64>, _>(column)
                    .unwrap()
                    .is_none(),
                "pre-dispatch receipt column {column} must remain null"
            );
        }
        assert_eq!(
            terminal_receipt
                .try_get::<Uuid, _>("workflow_instance_id")
                .unwrap(),
            *workflow_id
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Uuid, _>("workflow_job_id")
                .unwrap(),
            *job_id
        );
        assert_eq!(
            terminal_receipt
                .try_get::<i64, _>("workflow_job_fence_token")
                .unwrap(),
            1
        );
        assert_eq!(
            terminal_receipt
                .try_get::<i32, _>("workflow_job_attempt_count")
                .unwrap(),
            0
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Uuid, _>("audit_event_id")
                .unwrap(),
            audit.0
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Uuid, _>("outbox_event_id")
                .unwrap(),
            outbox_event_id
        );
        assert_eq!(
            terminal_receipt
                .try_get::<Option<Uuid>, _>("idempotency_record_id")
                .unwrap(),
            Some(cancellation_idempotency.0)
        );
        assert_eq!(
            (
                terminal_receipt
                    .try_get::<i64, _>("work_item_version_before")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("work_item_version_after")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("workflow_version_before")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("workflow_version_after")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("workflow_fence_before")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("workflow_fence_after")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("anchor_generation_before")
                    .unwrap(),
                terminal_receipt
                    .try_get::<i64, _>("anchor_generation_after")
                    .unwrap(),
            ),
            (2, 4, 1, 2, 0, 1, 1, 2)
        );
        assert_eq!(
            terminal_receipt
                .try_get::<i64, _>("released_reservations")
                .unwrap(),
            0
        );
        let audit_digests: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT before_digest, after_digest FROM audit_events WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(audit.0)
        .fetch_one(ledger.pool())
        .await
        .expect("load pre-dispatch audit digests");
        assert_eq!(
            terminal_receipt
                .try_get::<Option<String>, _>("audit_before_digest")
                .unwrap(),
            audit_digests.0
        );
        assert_eq!(
            terminal_receipt
                .try_get::<String, _>("audit_after_digest")
                .unwrap(),
            audit_digests.1.expect("terminal audit after digest")
        );
        assert!(is_sha256_digest(
            &terminal_receipt
                .try_get::<String, _>("receipt_digest")
                .unwrap()
        ));
        let guard: (i64, bool) = sqlx::query_as(
            r"
            SELECT generation, dispatch_started
            FROM work_dispatch_fact_guards
            WHERE tenant_id = $1 AND work_item_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load frozen pre-dispatch guard");
        assert!(!guard.1);
        assert_eq!(
            terminal_receipt
                .try_get::<i64, _>("dispatch_guard_generation")
                .unwrap(),
            guard.0
        );
        let terminal_fact_counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM cancellation_terminal_receipts
                 WHERE tenant_id = $1 AND work_item_id = $2),
                (SELECT count(*) FROM audit_events
                 WHERE tenant_id = $1 AND work_item_id = $2
                   AND action = 'WORK_ITEM_CANCELLED'),
                (SELECT count(*) FROM outbox
                 WHERE tenant_id = $1 AND message_key = $2::text
                   AND event_type = 'work_item.cancelled')
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("count replay-stable pre-dispatch terminal facts");
        assert_eq!(terminal_fact_counts, (1, 1, 1));

        let crossed_attempt_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest
            ) VALUES (
                $1, $2, $3, 1, 'CREATED', $4, 'main', $5, $6, $7
            )
            ",
        )
        .bind(crossed_attempt_id)
        .bind(tenant_id)
        .bind(crossed_work_item_id)
        .bind(format!("crossed-attempt-{crossed_attempt_id}"))
        .bind(format!("{:040x}", crossed_attempt_id.as_u128()))
        .bind(crossed_source_digest)
        .bind(&policy_digest)
        .execute(ledger.pool())
        .await
        .expect("insert crossed dispatch-boundary attempt fact");
        let crossed = unavailable
            .cancel_work_item(
                tenant,
                WorkItemId::from_uuid(crossed_work_item_id),
                &CancellationRequest {
                    expected_version: 2,
                    reason: "too late for synchronous cancellation".into(),
                },
                &caller(),
                "cancel-crossed",
            )
            .await
            .expect_err("an attempt fact must close the synchronous cancellation boundary");
        assert!(matches!(
            crossed,
            Error::Conflict(detail)
                if detail.contains("pre-dispatch cancellation boundary")
                    && (detail.contains("attempts=1")
                        || detail.contains("dispatch guard is started"))
        ));
        let refused: (String, i64, String, String, i64) = sqlx::query_as(
            r"
            SELECT
                work.state,
                work.aggregate_version,
                job.status,
                anchor.anchor_type,
                (SELECT count(*)
                 FROM idempotency_records AS record
                 WHERE record.tenant_id = work.tenant_id
                   AND record.operation = 'api.work_item.cancel'
                   AND record.idempotency_key = 'cancel-crossed')
            FROM work_items AS work
            JOIN workflow_jobs AS job
              ON job.tenant_id = work.tenant_id
             AND job.work_item_id = work.id
            JOIN accountability_anchors AS anchor
              ON anchor.tenant_id = work.tenant_id
             AND anchor.work_item_id = work.id
            WHERE work.tenant_id = $1 AND work.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(crossed_work_item_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load refused crossed-boundary state");
        assert_eq!(
            refused,
            ("ACCEPTED".into(), 2, "PENDING".into(), "WORKFLOW".into(), 0)
        );

        ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("drop isolated pre-dispatch-cancellation schema");
        admin.close().await;
    }

    #[tokio::test]
    async fn optional_live_attention_fails_uncovered_and_pages_in_display_order() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");

        let tenant_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("attention-{tenant_id}"))
            .bind("Attention projection test")
            .execute(ledger.pool())
            .await
            .expect("insert attention tenant");
        let backend =
            PostgresApiBackend::new(ledger.pool().clone(), TenantId::from_uuid(tenant_id));
        let page = PageQuery {
            cursor: None,
            limit: 2,
        };
        let now = Utc::now();

        let critical_earlier_work = Uuid::now_v7();
        let critical_earlier = Uuid::now_v7();
        insert_attention_work(ledger.pool(), tenant_id, critical_earlier_work).await;
        let error = backend
            .attention(TenantId::from_uuid(tenant_id), &page)
            .await
            .expect_err("uncovered attention work must fail closed");
        assert!(matches!(
            error,
            Error::Persistence(detail)
                if detail.contains("WorkNeedsSpec")
                    && detail.contains(&critical_earlier_work.to_string())
        ));
        insert_attention_escalation(
            ledger.pool(),
            tenant_id,
            critical_earlier_work,
            critical_earlier,
            "CRITICAL",
            now,
            now + Duration::hours(1),
        )
        .await;

        let critical_later_a_work = Uuid::now_v7();
        let critical_later_a = Uuid::now_v7();
        insert_attention_work(ledger.pool(), tenant_id, critical_later_a_work).await;
        insert_attention_escalation(
            ledger.pool(),
            tenant_id,
            critical_later_a_work,
            critical_later_a,
            "CRITICAL",
            now,
            now + Duration::hours(2),
        )
        .await;
        let critical_later_b_work = Uuid::now_v7();
        let critical_later_b = Uuid::now_v7();
        insert_attention_work(ledger.pool(), tenant_id, critical_later_b_work).await;
        insert_attention_escalation(
            ledger.pool(),
            tenant_id,
            critical_later_b_work,
            critical_later_b,
            "CRITICAL",
            now,
            now + Duration::hours(2),
        )
        .await;
        let low_work = Uuid::now_v7();
        let low = Uuid::now_v7();
        insert_attention_work(ledger.pool(), tenant_id, low_work).await;
        insert_attention_escalation(
            ledger.pool(),
            tenant_id,
            low_work,
            low,
            "LOW",
            now,
            now + Duration::minutes(30),
        )
        .await;

        let other_tenant = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(other_tenant)
            .bind(format!("attention-{other_tenant}"))
            .bind("Other attention tenant")
            .execute(ledger.pool())
            .await
            .expect("insert other attention tenant");
        let other_work = Uuid::now_v7();
        insert_attention_work(ledger.pool(), other_tenant, other_work).await;
        insert_attention_escalation(
            ledger.pool(),
            other_tenant,
            other_work,
            Uuid::now_v7(),
            "CRITICAL",
            now,
            now + Duration::minutes(1),
        )
        .await;

        let (stable_first, stable_second) = if critical_later_a < critical_later_b {
            (critical_later_a, critical_later_b)
        } else {
            (critical_later_b, critical_later_a)
        };
        let first = backend
            .attention(TenantId::from_uuid(tenant_id), &page)
            .await
            .expect("first attention page");
        assert_eq!(
            first.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![critical_earlier, stable_first]
        );
        let second = backend
            .attention(
                TenantId::from_uuid(tenant_id),
                &PageQuery {
                    cursor: first.next_cursor,
                    limit: 2,
                },
            )
            .await
            .expect("second attention page");
        assert_eq!(
            second.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![stable_second, low]
        );
        assert!(second.next_cursor.is_none());
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct IntakeCoreCounts {
        snapshots: i64,
        work_items: i64,
        audits: i64,
        outbox: i64,
    }

    const NO_EXECUTION_OR_ACCEPTANCE_AUTHORITY_TABLES: [&str; 13] = [
        "workflow_instances",
        "workflow_jobs",
        "workflow_timers",
        "attempts",
        "reservation_sets",
        "reservations",
        "work_orders",
        "runs",
        "raw_run_events",
        "approvals",
        "effect_intents",
        "budget_ledger",
        "accountability_anchors",
    ];

    async fn count_tenant_rows(pool: &PgPool, table: &str, tenant_id: Uuid) -> i64 {
        sqlx::query_scalar::<_, i64>(&format!(
            "SELECT count(*) FROM {table} WHERE tenant_id = $1"
        ))
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("count {table} rows for tenant {tenant_id}: {error}"))
    }

    async fn intake_core_counts(pool: &PgPool, tenant_id: Uuid) -> IntakeCoreCounts {
        IntakeCoreCounts {
            snapshots: count_tenant_rows(pool, "source_snapshots", tenant_id).await,
            work_items: count_tenant_rows(pool, "work_items", tenant_id).await,
            audits: count_tenant_rows(pool, "audit_events", tenant_id).await,
            outbox: count_tenant_rows(pool, "outbox", tenant_id).await,
        }
    }

    async fn assert_zero_execution_or_acceptance_authority_rows(pool: &PgPool, tenant_id: Uuid) {
        for table in NO_EXECUTION_OR_ACCEPTANCE_AUTHORITY_TABLES {
            let count = count_tenant_rows(pool, table, tenant_id).await;
            assert_eq!(
                count, 0,
                "expected zero {table} rows for tenant {tenant_id}"
            );
        }
    }

    /// Per-table row counts across every execution-or-acceptance-authority table, for tenants
    /// that legitimately hold some of these rows (e.g. an accepted-work fixture's single
    /// accountability anchor) and therefore cannot assert a flat zero baseline.
    async fn execution_or_acceptance_authority_snapshot(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Vec<(&'static str, i64)> {
        let mut snapshot = Vec::with_capacity(NO_EXECUTION_OR_ACCEPTANCE_AUTHORITY_TABLES.len());
        for table in NO_EXECUTION_OR_ACCEPTANCE_AUTHORITY_TABLES {
            snapshot.push((table, count_tenant_rows(pool, table, tenant_id).await));
        }
        snapshot
    }

    /// The accepted work item's complete authority projection: every `work_items` column, as
    /// `to_jsonb(work_items)` scoped to one tenant/work ID. A source-change authority
    /// reevaluation must retain the entire row untouched (`repository_id`, source identity,
    /// `state`, `closure_target`, `risk_class`, `risk_assessment`, `policy_digest`,
    /// `budget_limits`, `identity_requirements`, `owner_fallback`, `normalized_priority`,
    /// `due_at`, `current_attempt_id`, `aggregate_version`, `discovered_at`, `ready_at`,
    /// `accepted_at`, `closed_at`, and `updated_at`) while it records the reevaluation
    /// requirement, so comparing the whole row is a strictly stronger proof than naming a
    /// subset of columns.
    #[derive(Debug, Clone, PartialEq)]
    struct AcceptedWorkAuthorityProjection(Value);

    impl AcceptedWorkAuthorityProjection {
        fn get(&self, field: &str) -> &Value {
            &self.0[field]
        }

        fn policy_digest(&self) -> Option<String> {
            self.get("policy_digest").as_str().map(str::to_owned)
        }

        fn state(&self) -> &str {
            self.get("state")
                .as_str()
                .expect("authority projection state is a string")
        }

        fn aggregate_version(&self) -> i64 {
            self.get("aggregate_version")
                .as_i64()
                .expect("authority projection aggregate_version is an integer")
        }

        fn source_snapshot_id(&self) -> Uuid {
            self.get("source_snapshot_id")
                .as_str()
                .and_then(|value| value.parse().ok())
                .expect("authority projection source_snapshot_id is a UUID")
        }
    }

    async fn load_accepted_work_authority_projection(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
    ) -> AcceptedWorkAuthorityProjection {
        let projection: Value = sqlx::query_scalar(
            r"
            SELECT to_jsonb(work_items)
            FROM work_items
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(pool)
        .await
        .expect("load accepted work authority projection");
        AcceptedWorkAuthorityProjection(projection)
    }

    /// Exact count of `outbox` rows for `event_type` whose payload's `work_item_id` matches
    /// `work_item_id`, scoped to `tenant_id`. Stronger than a total outbox row-count delta,
    /// which cannot distinguish "one row of this event type for this work item" from "one row
    /// of some other event type, or for a different work item, happened to land at the same
    /// count".
    async fn outbox_event_count_for_work_item(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
        event_type: &str,
    ) -> i64 {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*) FROM outbox
            WHERE tenant_id = $1 AND event_type = $2
              AND payload ->> 'work_item_id' = $3
            ",
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(work_item_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count outbox rows for work item and event type")
    }

    /// The exactly-one durable outbox row for `event_type` whose payload's `work_item_id`
    /// matches `work_item_id`, used to inspect the full source-intake event envelope (row
    /// identity, ingestion time, semantic payload, and first-writer headers) rather than just
    /// its count.
    struct StoredOutboxEvent {
        id: Uuid,
        event_type: String,
        payload: Value,
        headers: Value,
        created_at: DateTime<Utc>,
    }

    async fn load_outbox_event_for_work_item(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
        event_type: &str,
    ) -> StoredOutboxEvent {
        let row = sqlx::query(
            r"
            SELECT id, event_type, payload, headers, created_at
            FROM outbox
            WHERE tenant_id = $1 AND event_type = $2
              AND payload ->> 'work_item_id' = $3
            ",
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(work_item_id.to_string())
        .fetch_one(pool)
        .await
        .expect("load the single outbox row for this work item and event type");
        StoredOutboxEvent {
            id: row.try_get("id").expect("outbox row id"),
            event_type: row.try_get("event_type").expect("outbox row event_type"),
            payload: row.try_get("payload").expect("outbox row payload"),
            headers: row.try_get("headers").expect("outbox row headers"),
            created_at: row.try_get("created_at").expect("outbox row created_at"),
        }
    }

    async fn load_source_snapshot_captured_at(
        pool: &PgPool,
        tenant_id: Uuid,
        snapshot_id: Uuid,
    ) -> DateTime<Utc> {
        sqlx::query_scalar::<_, DateTime<Utc>>(
            r"
            SELECT captured_at FROM source_snapshots WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(snapshot_id)
        .fetch_one(pool)
        .await
        .expect("load source snapshot captured_at")
    }

    struct StoredIdempotencyRecord {
        id: Uuid,
        response_status: i32,
        response_body: Value,
    }

    async fn load_idempotency_record(
        pool: &PgPool,
        tenant_id: Uuid,
        actor_id: &str,
        idempotency_key: &str,
    ) -> StoredIdempotencyRecord {
        let row = sqlx::query(
            r"
            SELECT id, response_status, response_body
            FROM idempotency_records
            WHERE tenant_id = $1 AND actor_id = $2 AND operation = $3 AND idempotency_key = $4
            ",
        )
        .bind(tenant_id)
        .bind(actor_id)
        .bind(OP_API_INTAKE)
        .bind(idempotency_key)
        .fetch_one(pool)
        .await
        .expect("load API intake idempotency record");
        StoredIdempotencyRecord {
            id: row.try_get("id").expect("idempotency record id"),
            response_status: row
                .try_get("response_status")
                .expect("idempotency response status"),
            response_body: row
                .try_get("response_body")
                .expect("idempotency response body"),
        }
    }

    async fn idempotency_record_count(
        pool: &PgPool,
        tenant_id: Uuid,
        actor_id: &str,
        idempotency_key: &str,
    ) -> i64 {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*) FROM idempotency_records
            WHERE tenant_id = $1 AND actor_id = $2 AND operation = $3 AND idempotency_key = $4
            ",
        )
        .bind(tenant_id)
        .bind(actor_id)
        .bind(OP_API_INTAKE)
        .bind(idempotency_key)
        .fetch_one(pool)
        .await
        .expect("count API intake idempotency records")
    }

    /// Total tenant-scoped `idempotency_records` count for `operation`, independent of actor
    /// or key. Used to prove a rejected or duplicated call leaves no stray claim behind, not
    /// merely that the specific actor/key row under test is absent.
    async fn idempotency_op_record_count(pool: &PgPool, tenant_id: Uuid, operation: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*) FROM idempotency_records
            WHERE tenant_id = $1 AND operation = $2
            ",
        )
        .bind(tenant_id)
        .bind(operation)
        .fetch_one(pool)
        .await
        .expect("count tenant-scoped idempotency records for operation")
    }

    async fn insert_active_intake_tenant_and_repository(pool: &PgPool) -> (Uuid, Uuid, String) {
        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("api-intake-contract-{tenant_id}"))
            .bind("API intake contract test")
            .execute(pool)
            .await
            .expect("insert API intake contract tenant");
        let repository_name = format!("contract-repo-{}", repository_id.simple());
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'contract-owner', $3, $4, 'main')
            ",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(&repository_name)
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(pool)
        .await
        .expect("insert API intake contract repository");
        (
            tenant_id,
            repository_id,
            format!("contract-owner/{repository_name}"),
        )
    }

    fn intake_discovery_request(
        repository_id: RepositoryId,
        external_id: &str,
        source_revision: &str,
        objective: &str,
        source_updated_at: DateTime<Utc>,
    ) -> ApiIntakeRequest {
        ApiIntakeRequest {
            schema_version: API_INTAKE_REQUEST_SCHEMA_V1.into(),
            repository_id,
            external_id: external_id.into(),
            source_revision: source_revision.into(),
            source_url: None,
            title: "Discovery replay and revision contract".into(),
            objective: objective.into(),
            acceptance_criteria: vec!["the documented contract holds".into()],
            non_goals: Vec::new(),
            labels: BTreeSet::new(),
            normalized_priority: 50,
            source_state: "open".into(),
            assignee: None,
            source_updated_at,
        }
    }

    #[tokio::test]
    async fn optional_live_api_intake_discovery_replay_and_revision_contract() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect API intake contract PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate API intake contract PostgreSQL");
        let pool = ledger.pool();

        let (tenant_id, repository_id, repository_hint) =
            insert_active_intake_tenant_and_repository(pool).await;
        let backend = PostgresApiBackend::new(pool.clone(), TenantId::from_uuid(tenant_id));

        let caller_primary = Caller {
            subject: "asf-api-contract:primary".into(),
            roles: BTreeSet::new(),
        };
        let caller_secondary = Caller {
            subject: "asf-api-contract:secondary".into(),
            roles: BTreeSet::new(),
        };

        let external_id = format!("asf-api-contract-{tenant_id}");
        let key1 = "intake-key-1";
        let request1 = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &external_id,
            "revision-1",
            "Ship the discovery replay contract",
            Utc::now(),
        );

        // 1) First intake discovers a new work item.
        let receipt1 = backend
            .intake(&request1, &caller_primary, key1)
            .await
            .expect("first API intake discovers a work item");
        assert_eq!(receipt1.schema_version, API_INTAKE_RECEIPT_SCHEMA_V1);
        assert_eq!(receipt1.disposition, ApiIntakeDisposition::Discovered);
        assert_eq!(receipt1.state, WorkItemState::Discovered);
        assert_eq!(receipt1.version, 1);
        assert!(!receipt1.accepted);
        let snapshot_id = receipt1.source_snapshot_id.as_uuid();
        let work_item_id = receipt1.work_item_id.as_uuid();

        let snapshot_row = sqlx::query(
            r"
            SELECT tenant_id, repository_id, source_system, external_id,
                   source_revision, content_digest, connector_identity
            FROM source_snapshots
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(snapshot_id)
        .fetch_one(pool)
        .await
        .expect("load discovered source snapshot row");
        assert_eq!(
            snapshot_row.try_get::<Uuid, _>("tenant_id").unwrap(),
            tenant_id
        );
        assert_eq!(
            snapshot_row
                .try_get::<Option<Uuid>, _>("repository_id")
                .unwrap(),
            Some(repository_id)
        );
        assert_eq!(
            snapshot_row.try_get::<String, _>("source_system").unwrap(),
            "API"
        );
        assert_eq!(
            snapshot_row.try_get::<String, _>("external_id").unwrap(),
            external_id
        );
        assert_eq!(
            snapshot_row
                .try_get::<String, _>("source_revision")
                .unwrap(),
            "revision-1"
        );
        assert_eq!(
            snapshot_row.try_get::<String, _>("content_digest").unwrap(),
            receipt1.content_digest
        );
        assert_eq!(
            snapshot_row
                .try_get::<String, _>("connector_identity")
                .unwrap(),
            API_INTAKE_CONNECTOR_IDENTITY
        );
        let stored_repository_hint: Option<String> = sqlx::query_scalar(
            r"
            SELECT normalized_content ->> 'repository_hint'
            FROM source_snapshots
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(snapshot_id)
        .fetch_one(pool)
        .await
        .expect("load discovered source snapshot repository hint");
        assert_eq!(stored_repository_hint, Some(repository_hint));

        let work_row = sqlx::query(
            r"
            SELECT source_snapshot_id, accepted_at, current_attempt_id, closure_target,
                   risk_class, policy_digest, budget_limits, identity_requirements
            FROM work_items
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(pool)
        .await
        .expect("load discovered work item row");
        assert_eq!(
            work_row.try_get::<Uuid, _>("source_snapshot_id").unwrap(),
            snapshot_id
        );
        assert!(
            work_row
                .try_get::<Option<DateTime<Utc>>, _>("accepted_at")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<Uuid>, _>("current_attempt_id")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<String>, _>("closure_target")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<String>, _>("risk_class")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<String>, _>("policy_digest")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<Value>, _>("budget_limits")
                .unwrap()
                .is_none()
        );
        assert!(
            work_row
                .try_get::<Option<Value>, _>("identity_requirements")
                .unwrap()
                .is_none()
        );

        let record1 = load_idempotency_record(pool, tenant_id, &caller_primary.subject, key1).await;
        assert_eq!(record1.response_status, 201);
        assert_eq!(
            record1.response_body,
            serde_json::to_value(&receipt1).expect("serialize discovery receipt")
        );

        let discovered_audit = sqlx::query(
            r"
            SELECT actor_type, actor_id, correlation_id
            FROM audit_events
            WHERE tenant_id = $1 AND action = 'SOURCE_WORK_ITEM_DISCOVERED'
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .expect("load the single discovery audit event");
        assert_eq!(
            discovered_audit.try_get::<String, _>("actor_type").unwrap(),
            "API_CALLER"
        );
        assert_eq!(
            discovered_audit.try_get::<String, _>("actor_id").unwrap(),
            caller_primary.subject
        );
        assert_eq!(
            discovered_audit
                .try_get::<String, _>("correlation_id")
                .unwrap(),
            record1.id.to_string()
        );

        let discovered_outbox_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox WHERE tenant_id = $1 AND event_type = 'WORK_ITEM_DISCOVERED'",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .expect("count discovery outbox rows");
        assert_eq!(discovered_outbox_count, 1);

        // The durable outbox row *is* the event envelope: row id is the event identity,
        // event_type and the payload's schema/event/aggregate_version carry stable event
        // semantics, occurred_at pins the payload to the immutable candidate snapshot's
        // persisted capture time (never the current call's retry time), created_at is the
        // ingestion timestamp, and the headers carry immutable first-writer provenance.
        let discovered_snapshot_captured_at =
            load_source_snapshot_captured_at(pool, tenant_id, snapshot_id).await;
        let discovered_outbox =
            load_outbox_event_for_work_item(pool, tenant_id, work_item_id, "WORK_ITEM_DISCOVERED")
                .await;
        assert_ne!(
            discovered_outbox.id,
            Uuid::nil(),
            "outbox row id is the event identity"
        );
        assert_eq!(discovered_outbox.event_type, "WORK_ITEM_DISCOVERED");
        assert_eq!(
            discovered_outbox.payload["schema"],
            json!("asf.work-item-source-event.v1")
        );
        assert_eq!(discovered_outbox.payload["event"], json!("discovered"));
        assert_eq!(discovered_outbox.payload["aggregate_version"], json!(1));
        assert_eq!(discovered_outbox.payload["tenant_id"], json!(tenant_id));
        assert_eq!(
            discovered_outbox.payload["work_item_id"],
            json!(work_item_id)
        );
        assert_eq!(discovered_outbox.payload["source_system"], json!("API"));
        assert_eq!(
            discovered_outbox.payload["source_external_id"],
            json!(external_id)
        );
        assert_eq!(
            discovered_outbox.payload["source_snapshot_id"],
            json!(snapshot_id)
        );
        assert_eq!(
            discovered_outbox.payload["source_revision"],
            json!("revision-1")
        );
        assert_eq!(
            discovered_outbox.payload["content_digest"],
            json!(receipt1.content_digest)
        );
        assert!(
            discovered_outbox.payload["retained_authority_snapshot_id"].is_null(),
            "discovery has no prior authoritative snapshot to retain"
        );
        assert_eq!(
            discovered_outbox.payload["occurred_at"],
            json!(discovered_snapshot_captured_at)
        );
        assert!(discovered_outbox.created_at >= discovered_snapshot_captured_at);
        assert!(discovered_outbox.payload["policy_digest"].is_null());
        assert_eq!(
            discovered_outbox.headers["schema"],
            json!("asf.work-item-source-event-headers.v1")
        );
        assert_eq!(discovered_outbox.headers["actor_type"], json!("API_CALLER"));
        assert_eq!(
            discovered_outbox.headers["actor_id"],
            json!(caller_primary.subject)
        );
        assert_eq!(
            discovered_outbox.headers["correlation_id"],
            json!(record1.id.to_string())
        );
        assert!(discovered_outbox.headers["trace_id"].is_null());
        assert!(discovered_outbox.headers["policy_digest"].is_null());

        // 2) Discovery leaves exactly one snapshot/work/audit/outbox row.
        let baseline_counts = intake_core_counts(pool, tenant_id).await;
        assert_eq!(
            baseline_counts,
            IntakeCoreCounts {
                snapshots: 1,
                work_items: 1,
                audits: 1,
                outbox: 1,
            }
        );

        // 3) Discovery grants no execution or acceptance authority.
        assert_zero_execution_or_acceptance_authority_rows(pool, tenant_id).await;

        // 4) Deactivating the repository does not affect an exact idempotent replay.
        sqlx::query("UPDATE repositories SET active = false WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(repository_id)
            .execute(pool)
            .await
            .expect("deactivate contract repository");
        let replay_while_inactive = backend
            .intake(&request1, &caller_primary, key1)
            .await
            .expect("idempotent replay must short-circuit before the repository recheck");
        assert_eq!(replay_while_inactive, receipt1);
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);
        assert_zero_execution_or_acceptance_authority_rows(pool, tenant_id).await;
        sqlx::query("UPDATE repositories SET active = true WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(repository_id)
            .execute(pool)
            .await
            .expect("reactivate contract repository");

        // 5a) Reusing the original key with a changed objective conflicts and leaves no residue.
        let mut conflicting_objective_request = request1.clone();
        conflicting_objective_request.objective = "Ship an incompatible scope change".into();
        let key_conflict = backend
            .intake(&conflicting_objective_request, &caller_primary, key1)
            .await
            .expect_err("reusing an idempotency key for a different request body must conflict");
        assert!(matches!(
            key_conflict,
            Error::Conflict(ref detail)
                if detail.contains("idempotency key was reused for a different request")
        ));
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);

        // 5b) The same body under a fresh key is business-idempotent (UNCHANGED, 200).
        let key2 = "intake-key-2";
        let receipt_fresh_key_same_body = backend
            .intake(&request1, &caller_primary, key2)
            .await
            .expect("identical content under a fresh key is business-idempotent");
        assert_eq!(
            receipt_fresh_key_same_body.work_item_id,
            receipt1.work_item_id
        );
        assert_eq!(
            receipt_fresh_key_same_body.source_snapshot_id,
            receipt1.source_snapshot_id
        );
        assert_eq!(
            receipt_fresh_key_same_body.content_digest,
            receipt1.content_digest
        );
        assert_eq!(
            receipt_fresh_key_same_body.disposition,
            ApiIntakeDisposition::Unchanged
        );
        assert_eq!(receipt_fresh_key_same_body.state, WorkItemState::Discovered);
        assert_eq!(receipt_fresh_key_same_body.version, 1);
        let record2 = load_idempotency_record(pool, tenant_id, &caller_primary.subject, key2).await;
        assert_eq!(record2.response_status, 200);
        assert_eq!(
            record2.response_body,
            serde_json::to_value(&receipt_fresh_key_same_body)
                .expect("serialize unchanged receipt")
        );
        assert_ne!(
            record2.id, record1.id,
            "a distinct idempotency key for the same caller mints its own idempotency record ID"
        );
        assert_ne!(
            discovered_outbox.headers["correlation_id"],
            json!(record2.id.to_string()),
            "the first-writer correlation stays pinned to record1, not the later-adopting record2"
        );
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);

        // 6) A different caller subject reusing the original key is independently scoped.
        let receipt_other_caller = backend
            .intake(&request1, &caller_secondary, key1)
            .await
            .expect("a distinct caller subject is independently scoped under the same key");
        assert_eq!(receipt_other_caller.work_item_id, receipt1.work_item_id);
        assert_eq!(
            receipt_other_caller.source_snapshot_id,
            receipt1.source_snapshot_id
        );
        assert_eq!(
            receipt_other_caller.disposition,
            ApiIntakeDisposition::Unchanged
        );
        assert_eq!(receipt_other_caller.version, 1);
        let other_caller_record =
            load_idempotency_record(pool, tenant_id, &caller_secondary.subject, key1).await;
        assert_eq!(other_caller_record.response_status, 200);
        assert_ne!(
            other_caller_record.id, record1.id,
            "a distinct caller subject mints its own idempotency record ID even under the same key"
        );
        assert_ne!(
            discovered_outbox.headers["correlation_id"],
            json!(other_caller_record.id.to_string()),
            "the first-writer correlation stays pinned to record1, not the later-adopting \
             other_caller_record"
        );
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);

        // The same-candidate call by a different caller creates no second outbox row and does
        // not alter the original first-writer's provenance headers: the discovery event's
        // headers still cite caller_primary and key1's own correlation, not caller_secondary's.
        let discovered_outbox_after_secondary_caller =
            load_outbox_event_for_work_item(pool, tenant_id, work_item_id, "WORK_ITEM_DISCOVERED")
                .await;
        assert_eq!(
            discovered_outbox_after_secondary_caller.id, discovered_outbox.id,
            "no second WORK_ITEM_DISCOVERED outbox row was created"
        );
        assert_eq!(
            discovered_outbox_after_secondary_caller.headers, discovered_outbox.headers,
            "the original first-writer headers are unchanged by a different caller's replay"
        );

        // 7) A fresh key with the same external ID/revision but a changed objective conflicts
        //    and its idempotency claim rolls back.
        let key3 = "intake-key-3";
        let revision_conflict = backend
            .intake(&conflicting_objective_request, &caller_primary, key3)
            .await
            .expect_err("a revision-identical candidate with different content must conflict");
        assert!(matches!(
            revision_conflict,
            Error::Conflict(ref detail) if detail.contains("already has different canonical content")
        ));
        assert_eq!(
            idempotency_record_count(pool, tenant_id, &caller_primary.subject, key3).await,
            0
        );
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);

        // 8) A fresh key with a new revision and changed objective requeues readiness.
        let key4 = "intake-key-4";
        let mut requeue_request = request1.clone();
        requeue_request.source_revision = "revision-2".into();
        requeue_request.objective = "Ship a revised scope for round two".into();
        let receipt_requeued = backend
            .intake(&requeue_request, &caller_primary, key4)
            .await
            .expect("a new revision with changed content requeues readiness");
        assert_eq!(receipt_requeued.work_item_id, receipt1.work_item_id);
        assert_ne!(
            receipt_requeued.source_snapshot_id,
            receipt1.source_snapshot_id
        );
        assert_ne!(receipt_requeued.content_digest, receipt1.content_digest);
        assert_eq!(
            receipt_requeued.disposition,
            ApiIntakeDisposition::ReadinessRequeued
        );
        assert_eq!(receipt_requeued.state, WorkItemState::ReadinessPending);
        assert_eq!(receipt_requeued.version, 2);
        assert!(!receipt_requeued.accepted);
        let record4 = load_idempotency_record(pool, tenant_id, &caller_primary.subject, key4).await;
        assert_eq!(record4.response_status, 200);
        assert_eq!(
            record4.response_body,
            serde_json::to_value(&receipt_requeued).expect("serialize requeued receipt")
        );
        let requeued_counts = intake_core_counts(pool, tenant_id).await;
        assert_eq!(
            requeued_counts,
            IntakeCoreCounts {
                snapshots: 2,
                work_items: 1,
                audits: 2,
                outbox: 2,
            }
        );
        assert_zero_execution_or_acceptance_authority_rows(pool, tenant_id).await;

        // The revision-2 (readiness-requeued) outbox row carries the same durable-envelope
        // contract at its own aggregate version, pinned to revision 2's own persisted capture
        // time and correlated to key4's own idempotency record.
        let requeued_snapshot_captured_at = load_source_snapshot_captured_at(
            pool,
            tenant_id,
            receipt_requeued.source_snapshot_id.as_uuid(),
        )
        .await;
        let requeued_outbox = load_outbox_event_for_work_item(
            pool,
            tenant_id,
            work_item_id,
            "WORK_ITEM_READINESS_REEVALUATION_REQUESTED",
        )
        .await;
        assert_ne!(
            requeued_outbox.id,
            Uuid::nil(),
            "outbox row id is the event identity"
        );
        assert_eq!(
            requeued_outbox.event_type,
            "WORK_ITEM_READINESS_REEVALUATION_REQUESTED"
        );
        assert_eq!(
            requeued_outbox.payload["schema"],
            json!("asf.work-item-source-event.v1")
        );
        assert_eq!(
            requeued_outbox.payload["event"],
            json!("readiness_requeued")
        );
        assert_eq!(requeued_outbox.payload["aggregate_version"], json!(2));
        assert_eq!(requeued_outbox.payload["tenant_id"], json!(tenant_id));
        assert_eq!(requeued_outbox.payload["work_item_id"], json!(work_item_id));
        assert_eq!(requeued_outbox.payload["source_system"], json!("API"));
        assert_eq!(
            requeued_outbox.payload["source_external_id"],
            json!(external_id)
        );
        assert_eq!(
            requeued_outbox.payload["source_snapshot_id"],
            json!(receipt_requeued.source_snapshot_id.as_uuid())
        );
        assert_eq!(
            requeued_outbox.payload["source_revision"],
            json!("revision-2")
        );
        assert_eq!(
            requeued_outbox.payload["content_digest"],
            json!(receipt_requeued.content_digest)
        );
        assert_eq!(
            requeued_outbox.payload["retained_authority_snapshot_id"],
            json!(snapshot_id),
            "readiness requeue retains revision 1's snapshot id as the prior authority"
        );
        assert_eq!(
            requeued_outbox.payload["occurred_at"],
            json!(requeued_snapshot_captured_at)
        );
        assert!(requeued_outbox.created_at >= requeued_snapshot_captured_at);
        assert!(requeued_outbox.payload["policy_digest"].is_null());
        assert_eq!(
            requeued_outbox.headers["schema"],
            json!("asf.work-item-source-event-headers.v1")
        );
        assert_eq!(requeued_outbox.headers["actor_type"], json!("API_CALLER"));
        assert_eq!(
            requeued_outbox.headers["actor_id"],
            json!(caller_primary.subject)
        );
        assert_eq!(
            requeued_outbox.headers["correlation_id"],
            json!(record4.id.to_string())
        );
        assert!(requeued_outbox.headers["trace_id"].is_null());
        assert!(requeued_outbox.headers["policy_digest"].is_null());

        let replay_requeue = backend
            .intake(&requeue_request, &caller_primary, key4)
            .await
            .expect("exact replay of the requeue key returns the stored receipt");
        assert_eq!(replay_requeue, receipt_requeued);
        assert_eq!(intake_core_counts(pool, tenant_id).await, requeued_counts);
        assert_zero_execution_or_acceptance_authority_rows(pool, tenant_id).await;

        ledger.close().await;
    }

    /// Asserts that `request` is rejected under `idempotency_key` and that the rejection
    /// leaves no residue: no idempotency claim under this actor/key, no growth in the total
    /// tenant-scoped `api.intake` idempotency record count, no core intake rows, no growth in
    /// the tenant's exact `escalations` row count, and no execution-or-acceptance-authority
    /// rows for `tenant_id`.
    ///
    /// `escalations` is deliberately excluded from
    /// `NO_EXECUTION_OR_ACCEPTANCE_AUTHORITY_TABLES` because accepted-work source reevaluation
    /// intentionally opens an owned escalation; that table alone cannot stand in for "an
    /// escalation was not opened by this rejected call", so the exact baseline is asserted here.
    async fn assert_intake_rejected_without_residue(
        pool: &PgPool,
        backend: &PostgresApiBackend,
        tenant_id: Uuid,
        caller: &Caller,
        request: &ApiIntakeRequest,
        idempotency_key: &str,
        baseline_counts: IntakeCoreCounts,
        baseline_op_count: i64,
        baseline_escalations: i64,
    ) -> Error {
        let error = backend
            .intake(request, caller, idempotency_key)
            .await
            .expect_err("ambiguous or untrusted intake input must be rejected");
        assert_eq!(
            idempotency_record_count(pool, tenant_id, &caller.subject, idempotency_key).await,
            0,
            "rejected intake must not leave an idempotency claim behind"
        );
        assert_eq!(
            idempotency_op_record_count(pool, tenant_id, OP_API_INTAKE).await,
            baseline_op_count,
            "rejected intake must not grow the tenant's total api.intake idempotency record count"
        );
        assert_eq!(intake_core_counts(pool, tenant_id).await, baseline_counts);
        assert_eq!(
            count_tenant_rows(pool, "escalations", tenant_id).await,
            baseline_escalations,
            "rejected intake must not open an escalation"
        );
        assert_zero_execution_or_acceptance_authority_rows(pool, tenant_id).await;
        error
    }

    #[tokio::test]
    async fn optional_live_api_intake_rejects_ambiguous_and_untrusted_inputs_without_residue() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect API intake rejection PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate API intake rejection PostgreSQL");
        let pool = ledger.pool();

        let (tenant_id, repository_id, _repository_hint) =
            insert_active_intake_tenant_and_repository(pool).await;
        let backend = PostgresApiBackend::new(pool.clone(), TenantId::from_uuid(tenant_id));
        let caller = caller();

        let inactive_repository_id = Uuid::now_v7();
        let inactive_repository_name = format!("inactive-repo-{}", inactive_repository_id.simple());
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch, active
            ) VALUES ($1, $2, 'contract-owner', $3, $4, 'main', false)
            ",
        )
        .bind(inactive_repository_id)
        .bind(tenant_id)
        .bind(&inactive_repository_name)
        .bind(format!("https://example.invalid/{inactive_repository_id}"))
        .execute(pool)
        .await
        .expect("insert inactive intake repository");

        let (foreign_tenant_id, foreign_repository_id, _foreign_repository_hint) =
            insert_active_intake_tenant_and_repository(pool).await;

        let missing_repository_id = Uuid::now_v7();

        let baseline_counts = intake_core_counts(pool, tenant_id).await;
        let baseline_op_count = idempotency_op_record_count(pool, tenant_id, OP_API_INTAKE).await;
        let baseline_escalations = count_tenant_rows(pool, "escalations", tenant_id).await;
        let foreign_baseline_counts = intake_core_counts(pool, foreign_tenant_id).await;
        let foreign_baseline_op_count =
            idempotency_op_record_count(pool, foreign_tenant_id, OP_API_INTAKE).await;
        let foreign_baseline_escalations =
            count_tenant_rows(pool, "escalations", foreign_tenant_id).await;

        // Inactive repository within the same tenant.
        let request_inactive_repo = intake_discovery_request(
            RepositoryId::from_uuid(inactive_repository_id),
            &format!("inactive-repo-external-{tenant_id}"),
            "revision-inactive-repo",
            "Attempt intake against an inactive repository",
            Utc::now(),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_inactive_repo,
            "intake-key-inactive-repo",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::NotFound(_)),
            "expected NotFound for an inactive same-tenant repository, got {error:?}"
        );

        // Repository that belongs to a different tenant.
        let request_foreign_repo = intake_discovery_request(
            RepositoryId::from_uuid(foreign_repository_id),
            &format!("foreign-repo-external-{tenant_id}"),
            "revision-foreign-repo",
            "Attempt intake against a foreign tenant repository",
            Utc::now(),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_foreign_repo,
            "intake-key-foreign-repo",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::NotFound(_)),
            "expected NotFound for a foreign-tenant repository, got {error:?}"
        );

        // Repository that does not exist at all.
        let request_missing_repo = intake_discovery_request(
            RepositoryId::from_uuid(missing_repository_id),
            &format!("missing-repo-external-{tenant_id}"),
            "revision-missing-repo",
            "Attempt intake against a missing repository",
            Utc::now(),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_missing_repo,
            "intake-key-missing-repo",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::NotFound(_)),
            "expected NotFound for a missing repository, got {error:?}"
        );

        // Unsupported schema version.
        let mut request_wrong_schema = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &format!("wrong-schema-external-{tenant_id}"),
            "revision-wrong-schema",
            "Attempt intake with an unsupported schema version",
            Utc::now(),
        );
        request_wrong_schema.schema_version = "asf.api-intake-request/v0".into();
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_wrong_schema,
            "intake-key-wrong-schema",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::Validation(_)),
            "expected Validation for an unsupported schema version, got {error:?}"
        );

        // Credential-shaped value in an otherwise allowed field.
        let request_credential_shaped = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &format!("credential-shaped-external-{tenant_id}"),
            "revision-credential-shaped",
            "Bearer intake-should-reject-this-credential-shaped-objective",
            Utc::now(),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_credential_shaped,
            "intake-key-credential-shaped",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::Validation(_)),
            "expected Validation for a credential-shaped objective, got {error:?}"
        );

        // Source URL with embedded userinfo.
        let mut request_userinfo_url = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &format!("userinfo-url-external-{tenant_id}"),
            "revision-userinfo-url",
            "Attempt intake with a source URL containing embedded userinfo",
            Utc::now(),
        );
        request_userinfo_url.source_url = Some(
            url::Url::parse("https://intake-user:intake-pass@example.invalid/issue/1")
                .expect("parse source URL with embedded userinfo"),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_userinfo_url,
            "intake-key-userinfo-url",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::Validation(_)),
            "expected Validation for a source URL with embedded userinfo, got {error:?}"
        );

        // Oversized external ID (over the 512-byte identity-field bound).
        let oversized_external_id = "e".repeat(513);
        let request_oversized_external_id = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &oversized_external_id,
            "revision-oversized-external-id",
            "Attempt intake with an oversized external identifier",
            Utc::now(),
        );
        let error = assert_intake_rejected_without_residue(
            pool,
            &backend,
            tenant_id,
            &caller,
            &request_oversized_external_id,
            "intake-key-oversized-external-id",
            baseline_counts,
            baseline_op_count,
            baseline_escalations,
        )
        .await;
        assert!(
            matches!(error, Error::Validation(_)),
            "expected Validation for an oversized external ID, got {error:?}"
        );

        // The foreign tenant never had a chance to accumulate intake rows either.
        assert_eq!(
            intake_core_counts(pool, foreign_tenant_id).await,
            foreign_baseline_counts
        );
        assert_eq!(
            idempotency_op_record_count(pool, foreign_tenant_id, OP_API_INTAKE).await,
            foreign_baseline_op_count,
            "rejected same-tenant intake attempts must not grow the foreign tenant's \
             api.intake idempotency record count"
        );
        assert_eq!(
            count_tenant_rows(pool, "escalations", foreign_tenant_id).await,
            foreign_baseline_escalations,
            "rejected same-tenant intake attempts must not open an escalation for the foreign tenant"
        );
        assert_zero_execution_or_acceptance_authority_rows(pool, foreign_tenant_id).await;

        ledger.close().await;
    }

    /// Moves a discovered work item through `READY` -> `ACCEPTED` with a legal fixture,
    /// entirely outside the production accept endpoint: `accept_work_item` creates a delivery
    /// workflow/job, which an intake-boundary test must not exercise. Returns the aggregate
    /// version stamped by acceptance.
    async fn accept_work_item_fixture(
        pool: &PgPool,
        tenant_id: Uuid,
        work_item_id: Uuid,
        repository_id: Uuid,
        owner_fallback: &str,
    ) -> i64 {
        // The ACCEPTED-work invariant is enforced by a trigger that requires an
        // accountability anchor to exist by commit time, so the READY -> ACCEPTED
        // transition and its anchor must land in the same transaction.
        let mut transaction = pool
            .begin()
            .await
            .expect("begin accepted-work fixture transaction");

        let policy_digest = format!("sha256:{:064x}", Uuid::now_v7().as_u128());
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, scope, schema_version, digest, canonical_bytes,
                policy, created_by
            ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(&policy_digest)
        .bind(br"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert accepted-fixture policy version");

        // Fenced on the exact pre-fixture state/version (READINESS_PENDING at aggregate
        // version 2, stamped by the caller's two prior direct-intake calls) so a fixture that
        // no longer matches the assumed starting state fails loudly instead of silently
        // producing an unreachable ACCEPTED row.
        let ready_at = Utc::now();
        let ready_version: i64 = sqlx::query_scalar(
            r"
            UPDATE work_items
            SET state = 'READY', repository_id = $3, closure_target = 'pull_request',
                risk_class = 'low', policy_digest = $4, budget_limits = $5,
                identity_requirements = $6, owner_fallback = $7,
                ready_at = $8, aggregate_version = aggregate_version + 1, updated_at = $8
            WHERE tenant_id = $1 AND id = $2 AND state = 'READINESS_PENDING'
              AND aggregate_version = 2
            RETURNING aggregate_version
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(json!({
            "max_cost_microunits": 1000,
            "max_input_tokens": 1000,
            "max_output_tokens": 1000,
            "max_implementer_invocations": 1,
            "max_reviewer_invocations": 1,
            "max_fix_iterations": 0,
            "max_wall_time_seconds": 600,
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "codex:pr-reviewer"
        }))
        .bind(owner_fallback)
        .bind(ready_at)
        .fetch_one(&mut *transaction)
        .await
        .expect(
            "ready the work item for the accepted-work fixture: expected READINESS_PENDING at \
             aggregate version 2",
        );
        assert_eq!(
            ready_version, 3,
            "READINESS_PENDING -> READY fixture transition must land exactly at aggregate \
             version 3"
        );

        let accepted_at = Utc::now();
        let accepted_version: i64 = sqlx::query_scalar(
            r"
            UPDATE work_items
            SET state = 'ACCEPTED', accepted_at = $3,
                aggregate_version = aggregate_version + 1, updated_at = $3
            WHERE tenant_id = $1 AND id = $2 AND state = 'READY' AND aggregate_version = 3
            RETURNING aggregate_version
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(accepted_at)
        .fetch_one(&mut *transaction)
        .await
        .expect(
            "accept the work item for the accepted-work fixture: expected READY at aggregate \
             version 3",
        );
        assert_eq!(
            accepted_version, 4,
            "READY -> ACCEPTED fixture transition must land exactly at aggregate version 4"
        );

        // The smallest escalation-backed accountability anchor the ACCEPTED invariant
        // requires: one open escalation owning one accountability-anchor row.
        let anchor_escalation_id = Uuid::now_v7();
        let anchor_deadline = Utc::now() + Duration::hours(1);
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, category, severity, reason,
                owner_type, owner_id, required_action, deadline, retry_policy,
                authority_or_effect_active, idempotency_key
            ) VALUES (
                $1, $2, $3, 'NEEDS_APPROVAL', 'MEDIUM', 'accepted-fixture accountability anchor',
                'TEAM', $4, 'approve fixture', $5, '{}'::jsonb, false, $6
            )
            ",
        )
        .bind(anchor_escalation_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(owner_fallback)
        .bind(anchor_deadline)
        .bind(format!("api-authority-test-anchor:{work_item_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert the accepted-work fixture's accountability-anchor escalation");
        sqlx::query(
            r"
            INSERT INTO accountability_anchors (
                tenant_id, work_item_id, anchor_type, reference_id,
                wake_or_deadline_at, authority_or_effect_active
            ) VALUES ($1, $2, 'ESCALATION', $3, $4, false)
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(anchor_escalation_id)
        .bind(anchor_deadline)
        .execute(&mut *transaction)
        .await
        .expect("install the accepted-work fixture's accountability anchor");

        transaction
            .commit()
            .await
            .expect("commit accepted-work fixture transaction");

        accepted_version
    }

    #[tokio::test]
    async fn optional_live_api_intake_accepted_work_source_change_requires_authority_reevaluation()
    {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect API intake authority-reevaluation PostgreSQL");
        ledger
            .migrate()
            .await
            .expect("migrate API intake authority-reevaluation PostgreSQL");
        let pool = ledger.pool();

        let (tenant_id, repository_id, _repository_hint) =
            insert_active_intake_tenant_and_repository(pool).await;
        let backend = PostgresApiBackend::new(pool.clone(), TenantId::from_uuid(tenant_id));
        let caller = caller();
        let caller_secondary = Caller {
            subject: "operator:2".into(),
            roles: BTreeSet::new(),
        };
        let owner_fallback = "team:api-authority-test";

        // 1) Directly ingest revision 1 (discovered), then revision 2 (readiness requeued and
        //    authoritative).
        let external_id = format!("asf-api-authority-{tenant_id}");
        let key1 = "authority-key-1";
        let request1 = intake_discovery_request(
            RepositoryId::from_uuid(repository_id),
            &external_id,
            "revision-1",
            "Ship the authority-reevaluation contract",
            Utc::now(),
        );
        let receipt1 = backend
            .intake(&request1, &caller, key1)
            .await
            .expect("revision 1 discovers a work item");
        assert_eq!(receipt1.disposition, ApiIntakeDisposition::Discovered);
        let work_item_id = receipt1.work_item_id.as_uuid();

        let key2 = "authority-key-2";
        let mut request2 = request1.clone();
        request2.source_revision = "revision-2".into();
        request2.objective = "Ship the authority-reevaluation contract, revision 2".into();
        let receipt2 = backend
            .intake(&request2, &caller, key2)
            .await
            .expect("revision 2 requeues readiness and becomes authoritative");
        assert_eq!(
            receipt2.disposition,
            ApiIntakeDisposition::ReadinessRequeued
        );
        assert_eq!(receipt2.state, WorkItemState::ReadinessPending);
        assert_eq!(receipt2.version, 2);

        // 2) Legal READINESS_PENDING -> READY -> ACCEPTED fixture transition, bypassing the
        //    production accept endpoint.
        let accepted_version =
            accept_work_item_fixture(pool, tenant_id, work_item_id, repository_id, owner_fallback)
                .await;

        // 3) Capture exact baselines after the accepted fixture.
        let baseline_counts = intake_core_counts(pool, tenant_id).await;
        let baseline_escalations = count_tenant_rows(pool, "escalations", tenant_id).await;
        assert_eq!(
            baseline_escalations, 1,
            "the accepted fixture owns exactly one escalation"
        );
        assert_eq!(
            count_tenant_rows(pool, "accountability_anchors", tenant_id).await,
            1,
            "the accepted fixture owns exactly one accountability anchor"
        );
        let baseline_authority_rows =
            execution_or_acceptance_authority_snapshot(pool, tenant_id).await;
        let baseline_op_count = idempotency_op_record_count(pool, tenant_id, OP_API_INTAKE).await;
        let baseline_authority_projection =
            load_accepted_work_authority_projection(pool, tenant_id, work_item_id).await;
        assert_eq!(baseline_authority_projection.state(), "ACCEPTED");
        assert_eq!(
            baseline_authority_projection.aggregate_version(),
            accepted_version
        );
        assert_eq!(
            baseline_authority_projection.source_snapshot_id(),
            receipt2.source_snapshot_id.as_uuid(),
            "the accepted fixture's authority snapshot is revision 2"
        );

        // 4) A materially changed revision 3 after acceptance requires authority
        //    reevaluation: authority is retained, not overwritten.
        let key3 = "authority-key-3";
        let mut request3 = request1.clone();
        request3.source_revision = "revision-3".into();
        request3.objective =
            "Ship the authority-reevaluation contract, materially changed after acceptance".into();
        let receipt3 = backend
            .intake(&request3, &caller, key3)
            .await
            .expect("revision 3 after acceptance requires authority reevaluation");
        assert_eq!(
            receipt3.disposition,
            ApiIntakeDisposition::AuthorityReevaluationRequired
        );
        assert!(receipt3.accepted);
        assert_eq!(receipt3.state, WorkItemState::Accepted);
        assert_eq!(
            receipt3.version,
            u64::try_from(accepted_version).expect("accepted aggregate version fits in u64")
        );
        assert_eq!(receipt3.work_item_id.as_uuid(), work_item_id);

        let candidate_row = sqlx::query(
            r"
            SELECT source_revision, content_digest
            FROM source_snapshots
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(receipt3.source_snapshot_id.as_uuid())
        .fetch_one(pool)
        .await
        .expect("load the candidate revision-3 snapshot row");
        assert_eq!(
            candidate_row
                .try_get::<String, _>("source_revision")
                .unwrap(),
            "revision-3"
        );
        assert_eq!(
            candidate_row
                .try_get::<String, _>("content_digest")
                .unwrap(),
            receipt3.content_digest
        );

        let retained_snapshot_id: Uuid = sqlx::query_scalar(
            "SELECT source_snapshot_id FROM work_items WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(pool)
        .await
        .expect("load the work item's retained source snapshot id");
        assert_eq!(
            retained_snapshot_id,
            receipt2.source_snapshot_id.as_uuid(),
            "authority is retained on revision 2 pending operator reevaluation"
        );

        // The entire accepted work authority projection - not just the retained snapshot ID -
        // is byte-for-byte unchanged by the source-change reevaluation.
        let after_revision3_authority_projection =
            load_accepted_work_authority_projection(pool, tenant_id, work_item_id).await;
        assert_eq!(
            after_revision3_authority_projection, baseline_authority_projection,
            "revision 3's authority reevaluation must not alter any authority-bearing column"
        );

        // 5) Exactly one candidate snapshot, one intake audit, one source-reevaluation outbox
        //    row, and one owned BLOCKED_EXTERNAL escalation are added by the source change.
        let after_reevaluation_counts = intake_core_counts(pool, tenant_id).await;
        assert_eq!(
            after_reevaluation_counts,
            IntakeCoreCounts {
                snapshots: baseline_counts.snapshots + 1,
                work_items: baseline_counts.work_items,
                audits: baseline_counts.audits + 1,
                outbox: baseline_counts.outbox + 1,
            }
        );
        assert_eq!(
            outbox_event_count_for_work_item(
                pool,
                tenant_id,
                work_item_id,
                "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED",
            )
            .await,
            1,
            "exactly one WORK_ITEM_SOURCE_REEVALUATION_REQUIRED outbox row must exist for this \
             work item, not merely one more than the prior total outbox count"
        );
        let after_reevaluation_escalations =
            count_tenant_rows(pool, "escalations", tenant_id).await;
        assert_eq!(after_reevaluation_escalations, baseline_escalations + 1);

        let escalation_row = sqlx::query(
            r"
            SELECT status, owner_type, owner_id, authority_or_effect_active
            FROM escalations
            WHERE tenant_id = $1 AND work_item_id = $2 AND category = 'BLOCKED_EXTERNAL'
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(pool)
        .await
        .expect("load the single owned BLOCKED_EXTERNAL source-change escalation");
        assert_eq!(
            escalation_row.try_get::<String, _>("status").unwrap(),
            "OPEN"
        );
        assert_eq!(
            escalation_row.try_get::<String, _>("owner_type").unwrap(),
            "TEAM"
        );
        assert_eq!(
            escalation_row.try_get::<String, _>("owner_id").unwrap(),
            owner_fallback
        );
        assert!(
            escalation_row
                .try_get::<bool, _>("authority_or_effect_active")
                .unwrap()
        );

        let audit_row = sqlx::query(
            r"
            SELECT actor_type, actor_id, correlation_id, policy_digest
            FROM audit_events
            WHERE tenant_id = $1 AND work_item_id = $2
              AND action = 'SOURCE_AUTHORITY_REEVALUATION_REQUIRED'
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .fetch_one(pool)
        .await
        .expect("load the single source-reevaluation audit event");
        assert_eq!(
            audit_row.try_get::<String, _>("actor_type").unwrap(),
            "API_CALLER"
        );
        assert_eq!(
            audit_row.try_get::<String, _>("actor_id").unwrap(),
            caller.subject
        );
        assert_eq!(
            audit_row
                .try_get::<Option<String>, _>("policy_digest")
                .unwrap(),
            baseline_authority_projection.policy_digest(),
            "the reevaluation audit event's policy_digest equals the retained accepted work's \
             own policy digest, provenance the audit trail must carry independently of the \
             outbox payload"
        );

        let idempotency_record3 =
            load_idempotency_record(pool, tenant_id, &caller.subject, key3).await;
        assert_eq!(idempotency_record3.response_status, 200);
        assert_eq!(
            idempotency_record3.response_body,
            serde_json::to_value(&receipt3).expect("serialize authority-reevaluation receipt")
        );
        assert_eq!(
            audit_row.try_get::<String, _>("correlation_id").unwrap(),
            idempotency_record3.id.to_string(),
            "the audit fact correlates to the claiming idempotency record"
        );

        // The authority-reevaluation outbox row does not bump the work item's version: its
        // payload carries the retained, unchanged aggregate version 4, pairs occurred_at with
        // the revision-3 candidate's own persisted capture time, and carries the retained
        // accepted work's policy digest (not null, unlike discovery/requeue events) in both the
        // payload and the mirrored header, correlated to key3's first-writer provenance.
        let reevaluation_snapshot_captured_at = load_source_snapshot_captured_at(
            pool,
            tenant_id,
            receipt3.source_snapshot_id.as_uuid(),
        )
        .await;
        let reevaluation_outbox = load_outbox_event_for_work_item(
            pool,
            tenant_id,
            work_item_id,
            "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED",
        )
        .await;
        assert_ne!(
            reevaluation_outbox.id,
            Uuid::nil(),
            "outbox row id is the event identity"
        );
        assert!(reevaluation_outbox.created_at >= reevaluation_snapshot_captured_at);
        assert_eq!(
            reevaluation_outbox.event_type,
            "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED"
        );
        assert_eq!(
            reevaluation_outbox.payload["schema"],
            json!("asf.work-item-source-event.v1")
        );
        assert_eq!(
            reevaluation_outbox.payload["event"],
            json!("authority_reevaluation_required")
        );
        assert_eq!(reevaluation_outbox.payload["aggregate_version"], json!(4));
        assert_eq!(reevaluation_outbox.payload["tenant_id"], json!(tenant_id));
        assert_eq!(
            reevaluation_outbox.payload["work_item_id"],
            json!(work_item_id)
        );
        assert_eq!(reevaluation_outbox.payload["source_system"], json!("API"));
        assert_eq!(
            reevaluation_outbox.payload["source_external_id"],
            json!(external_id)
        );
        assert_eq!(
            reevaluation_outbox.payload["source_snapshot_id"],
            json!(receipt3.source_snapshot_id.as_uuid())
        );
        assert_eq!(
            reevaluation_outbox.payload["source_revision"],
            json!("revision-3")
        );
        assert_eq!(
            reevaluation_outbox.payload["content_digest"],
            json!(receipt3.content_digest)
        );
        assert_eq!(
            reevaluation_outbox.payload["retained_authority_snapshot_id"],
            json!(receipt2.source_snapshot_id.as_uuid()),
            "accepted authority reevaluation retains revision 2's snapshot id, the snapshot \
             that was authoritative at acceptance time"
        );
        assert_eq!(
            reevaluation_outbox.payload["occurred_at"],
            json!(reevaluation_snapshot_captured_at)
        );
        assert_eq!(
            reevaluation_outbox.payload["policy_digest"],
            json!(baseline_authority_projection.policy_digest()),
            "the authority-reevaluation event retains the accepted work's own policy digest"
        );
        assert_eq!(
            reevaluation_outbox.headers["schema"],
            json!("asf.work-item-source-event-headers.v1")
        );
        assert_eq!(
            reevaluation_outbox.headers["actor_type"],
            json!("API_CALLER")
        );
        assert_eq!(
            reevaluation_outbox.headers["actor_id"],
            json!(caller.subject)
        );
        assert_eq!(
            reevaluation_outbox.headers["correlation_id"],
            json!(idempotency_record3.id.to_string())
        );
        assert!(reevaluation_outbox.headers["trace_id"].is_null());
        assert_eq!(
            reevaluation_outbox.headers["policy_digest"],
            json!(baseline_authority_projection.policy_digest())
        );

        // 6) No workflow, job, timer, attempt, reservation set, reservation, work order, run,
        //    raw run event, approval, effect intent, budget ledger, or accountability anchor is
        //    added by the source change. Compared against the accepted-fixture baseline, since
        //    that fixture already owns one accountability anchor.
        assert_eq!(
            execution_or_acceptance_authority_snapshot(pool, tenant_id).await,
            baseline_authority_rows
        );
        let post_reevaluation_op_count =
            idempotency_op_record_count(pool, tenant_id, OP_API_INTAKE).await;
        assert_eq!(post_reevaluation_op_count, baseline_op_count + 1);

        // 7) The exact same revision-3 request under a fresh idempotency key AND a genuinely
        //    different API caller still returns AUTHORITY_REEVALUATION_REQUIRED, never
        //    UNCHANGED, with the same candidate ID and digest; no duplicate snapshot, outbox,
        //    audit, escalation, or authority rows are created, and only the new completed
        //    api.intake idempotency record is added.
        let key4 = "authority-key-4";
        let receipt4 = backend
            .intake(&request3, &caller_secondary, key4)
            .await
            .expect(
                "replaying revision 3 under a new key and a different caller still requires \
                 authority reevaluation",
            );
        assert_eq!(
            receipt4.disposition,
            ApiIntakeDisposition::AuthorityReevaluationRequired
        );
        assert_eq!(receipt4.source_snapshot_id, receipt3.source_snapshot_id);
        assert_eq!(receipt4.content_digest, receipt3.content_digest);
        assert_eq!(receipt4.version, receipt3.version);
        assert!(receipt4.accepted);
        assert_eq!(receipt4.state, WorkItemState::Accepted);

        assert_eq!(
            intake_core_counts(pool, tenant_id).await,
            after_reevaluation_counts,
            "the replayed revision 3 must not insert a duplicate snapshot, audit, or outbox row"
        );
        assert_eq!(
            count_tenant_rows(pool, "escalations", tenant_id).await,
            after_reevaluation_escalations,
            "the replayed revision 3 must not insert a duplicate escalation"
        );
        assert_eq!(
            execution_or_acceptance_authority_snapshot(pool, tenant_id).await,
            baseline_authority_rows
        );
        assert_eq!(
            outbox_event_count_for_work_item(
                pool,
                tenant_id,
                work_item_id,
                "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED",
            )
            .await,
            1,
            "the replayed revision 3 must not insert a duplicate \
             WORK_ITEM_SOURCE_REEVALUATION_REQUIRED outbox row"
        );
        assert_eq!(
            load_accepted_work_authority_projection(pool, tenant_id, work_item_id).await,
            baseline_authority_projection,
            "replaying revision 3 under a fresh key must not alter any authority-bearing column"
        );
        assert_eq!(
            idempotency_op_record_count(pool, tenant_id, OP_API_INTAKE).await,
            post_reevaluation_op_count + 1,
            "only key4's new completed api.intake idempotency record was added"
        );

        // The single stored WORK_ITEM_SOURCE_REEVALUATION_REQUIRED event retains its original
        // first-writer (caller/key3) headers: a fresh key under a genuinely different caller
        // adopts the existing row rather than overwriting its provenance.
        let reevaluation_outbox_after_secondary_caller = load_outbox_event_for_work_item(
            pool,
            tenant_id,
            work_item_id,
            "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED",
        )
        .await;
        assert_eq!(
            reevaluation_outbox_after_secondary_caller.id, reevaluation_outbox.id,
            "no second WORK_ITEM_SOURCE_REEVALUATION_REQUIRED outbox row was created"
        );
        assert_eq!(
            reevaluation_outbox_after_secondary_caller.headers, reevaluation_outbox.headers,
            "the original first-writer headers are unchanged by a different caller's replay"
        );
        assert_eq!(
            reevaluation_outbox_after_secondary_caller.headers["actor_id"],
            json!(caller.subject),
            "the retained headers still cite the original caller, not caller_secondary"
        );

        let idempotency_record4 =
            load_idempotency_record(pool, tenant_id, &caller_secondary.subject, key4).await;
        assert_eq!(idempotency_record4.response_status, 200);
        assert_eq!(
            idempotency_record4.response_body,
            serde_json::to_value(&receipt4)
                .expect("serialize replayed authority-reevaluation receipt")
        );
        assert_ne!(
            idempotency_record4.id, idempotency_record3.id,
            "a distinct caller/key scope mints its own idempotency record ID"
        );
        assert_ne!(
            reevaluation_outbox.headers["correlation_id"],
            json!(idempotency_record4.id.to_string()),
            "the first-writer correlation stays pinned to idempotency_record3, not the \
             later-adopting idempotency_record4"
        );

        ledger.close().await;
    }
}
