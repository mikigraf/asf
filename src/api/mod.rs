use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

mod postgres;

use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

pub use crate::application::AttentionItemKind;

use crate::{
    Error, Result,
    auth::ApiAuthenticator,
    domain::{
        ApprovalId, ClosureTarget, EscalationCategory, EvidenceId, RepositoryId, RiskClass,
        SourceSnapshotId, TenantId, WorkItemId, WorkItemState, WorkerId,
    },
    security::{Caller, Permission},
};

pub use postgres::PostgresApiBackend;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    pub cursor: Option<String>,
    #[serde(default = "default_page_limit")]
    pub limit: u16,
}

const fn default_page_limit() -> u16 {
    50
}

impl PageQuery {
    fn validate(&self) -> Result<()> {
        if self.limit == 0 || self.limit > 200 {
            return Err(Error::Validation("page limit must be in 1..=200".into()));
        }
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 1024)
        {
            return Err(Error::Validation("page cursor is too long".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemView {
    pub id: WorkItemId,
    pub source_system: String,
    pub source_external_id: String,
    pub repository_id: Option<RepositoryId>,
    pub state: WorkItemState,
    pub closure_target: Option<ClosureTarget>,
    pub risk_class: Option<RiskClass>,
    pub priority: u8,
    pub owner: Option<String>,
    pub deadline: Option<DateTime<Utc>>,
    pub version: u64,
    pub discovered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemDetail {
    pub work_item: WorkItemView,
    pub source_snapshot: Value,
    pub readiness: Option<Value>,
    pub plan: Option<Value>,
    pub policy: Option<Value>,
    pub dependencies: Vec<Value>,
    pub attempts: Vec<Value>,
    pub events: Vec<Value>,
    pub evidence: Vec<Value>,
    pub accountability: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionItemView {
    /// Additive discriminator for the two durable record types exposed by v1.
    pub kind: AttentionItemKind,
    /// Stable record UUID. Incident IDs are deliberately not typed as escalation IDs.
    pub id: Uuid,
    /// Present only when `kind` is `ESCALATION`.
    pub work_item_id: Option<WorkItemId>,
    /// Present only when `kind` is `OPERATIONAL_INCIDENT`.
    pub workflow_job_id: Option<Uuid>,
    pub category: EscalationCategory,
    pub severity: String,
    pub owner: String,
    pub required_action: String,
    pub evidence_references: Vec<String>,
    pub deadline: DateTime<Utc>,
    pub retry_policy: Value,
    pub authority_or_effect_active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerView {
    pub id: WorkerId,
    pub name: String,
    pub status: String,
    pub generation: u64,
    pub capabilities: Value,
    pub active_slots: u16,
    pub max_concurrency: u16,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReceipt {
    pub idempotency_key: String,
    pub resource_id: String,
    pub status: String,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceView {
    pub id: EvidenceId,
    pub payload_digest: String,
    pub work_order_digest: String,
    pub target_satisfied: bool,
    pub verification_status: Option<String>,
    pub signed_envelope: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedMutation {
    pub expected_version: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    pub expected_version: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionRequest {
    pub decision: String,
    pub reason: Option<String>,
    pub expected_version: u64,
}

/// Schema identity required on every `POST /v1/intake` request body.
pub const API_INTAKE_REQUEST_SCHEMA_V1: &str = "asf.api-intake-request/v1";

/// Schema identity stamped on every `ApiIntakeReceipt`.
pub const API_INTAKE_RECEIPT_SCHEMA_V1: &str = "asf.api-intake-receipt/v1";

/// Authenticated, direct submission of one candidate source snapshot into intake.
///
/// Intake is discovery only: it can create a `DISCOVERED` work item, leave an
/// unchanged item alone, requeue readiness for a pre-acceptance change, or
/// flag an accepted work item for authority re-evaluation. It never accepts,
/// plans, dispatches, or grants any acceptance/accountability authority over
/// a work item, and it carries no tenant, connector-identity, caller,
/// policy, credential, or approval fields — those are server-derived or
/// out of scope for this endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiIntakeRequest {
    pub schema_version: String,
    pub repository_id: RepositoryId,
    pub external_id: String,
    pub source_revision: String,
    pub source_url: Option<Url>,
    pub title: String,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub non_goals: Vec<String>,
    pub labels: BTreeSet<String>,
    pub normalized_priority: u8,
    pub source_state: String,
    pub assignee: Option<String>,
    pub source_updated_at: DateTime<Utc>,
}

impl ApiIntakeRequest {
    /// Rejects a request whose `schema_version` is not exactly the current
    /// intake request schema. This is a narrow, HTTP-layer check ahead of the
    /// backend; the `PostgreSQL` backend keeps its own equivalent check as
    /// defense in depth.
    fn validate_schema_version(&self) -> Result<()> {
        if self.schema_version == API_INTAKE_REQUEST_SCHEMA_V1 {
            Ok(())
        } else {
            Err(Error::Validation(format!(
                "unsupported intake request schema {}",
                self.schema_version
            )))
        }
    }
}

/// Disposition of one direct-intake call against the candidate snapshot's current work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApiIntakeDisposition {
    /// A new work item was discovered from this external identity.
    Discovered,
    /// The candidate snapshot is already the work item's authoritative content.
    Unchanged,
    /// Pre-acceptance content changed, so readiness was requeued.
    ReadinessRequeued,
    /// Content changed after acceptance; authority is retained pending operator re-evaluation.
    AuthorityReevaluationRequired,
}

impl ApiIntakeDisposition {
    /// `DISCOVERED` is a creation (201); every other disposition reuses an existing work item
    /// and returns 200 — including on an exact idempotent replay of a `DISCOVERED` call, whose
    /// stored receipt still reports `DISCOVERED` and therefore still replays as 201.
    #[must_use]
    pub const fn http_status(self) -> StatusCode {
        match self {
            Self::Discovered => StatusCode::CREATED,
            Self::Unchanged | Self::ReadinessRequeued | Self::AuthorityReevaluationRequired => {
                StatusCode::OK
            }
        }
    }
}

/// Receipt for a direct-intake call.
///
/// `source_snapshot_id` and `content_digest` always identify the same candidate snapshot.
/// Intake never grants acceptance, so `accepted` only reports the work item's pre-existing
/// acceptance state at the time of this call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiIntakeReceipt {
    pub schema_version: String,
    pub idempotency_key: String,
    pub work_item_id: WorkItemId,
    pub source_snapshot_id: SourceSnapshotId,
    pub content_digest: String,
    pub disposition: ApiIntakeDisposition,
    pub state: WorkItemState,
    pub version: u64,
    pub accepted: bool,
}

#[async_trait]
pub trait ApiBackend: Send + Sync + 'static {
    async fn health(&self) -> Result<()>;
    async fn ready(&self) -> Result<()>;
    async fn intake_sync(&self, caller: &Caller, idempotency_key: &str) -> Result<MutationReceipt>;
    async fn intake(
        &self,
        request: &ApiIntakeRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<ApiIntakeReceipt>;
    async fn list_work_items(
        &self,
        tenant_id: TenantId,
        page: &PageQuery,
    ) -> Result<Page<WorkItemView>>;
    async fn get_work_item(&self, tenant_id: TenantId, id: WorkItemId) -> Result<WorkItemDetail>;
    async fn accept_work_item(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        request: &VersionedMutation,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt>;
    async fn cancel_work_item(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        request: &CancellationRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt>;
    async fn work_item_events(
        &self,
        tenant_id: TenantId,
        id: WorkItemId,
        page: &PageQuery,
    ) -> Result<Page<Value>>;
    async fn attention(
        &self,
        tenant_id: TenantId,
        page: &PageQuery,
    ) -> Result<Page<AttentionItemView>>;
    async fn decide_approval(
        &self,
        tenant_id: TenantId,
        id: ApprovalId,
        request: &ApprovalDecisionRequest,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt>;
    async fn workers(&self, tenant_id: TenantId) -> Result<Vec<WorkerView>>;
    async fn reconcile_worker(
        &self,
        tenant_id: TenantId,
        id: WorkerId,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt>;
    async fn evidence(&self, tenant_id: TenantId, id: EvidenceId) -> Result<EvidenceView>;
    async fn verify_evidence(
        &self,
        tenant_id: TenantId,
        id: EvidenceId,
        caller: &Caller,
        idempotency_key: &str,
    ) -> Result<MutationReceipt>;
    async fn explain_policy(&self, tenant_id: TenantId, digest: &str) -> Result<Value>;
}

#[derive(Clone)]
pub struct ApiState {
    pub tenant_id: TenantId,
    pub authenticator: ApiAuthenticator,
    pub backend: Arc<dyn ApiBackend>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiState")
            .field("tenant_id", &self.tenant_id)
            .field("authenticator", &self.authenticator)
            .field("backend", &"dyn ApiBackend")
            .finish()
    }
}

pub fn router(state: ApiState) -> Router {
    let authenticated = Router::new()
        .route("/intake", post(intake))
        .route("/intake/sync", post(intake_sync))
        .route("/work-items", get(list_work_items))
        .route("/work-items/{id}", get(get_work_item))
        .route("/work-items/{id}/accept", post(accept_work_item))
        .route("/work-items/{id}/cancel", post(cancel_work_item))
        .route("/work-items/{id}/events", get(work_item_events))
        .route("/attention", get(attention))
        .route("/approvals/{id}/decision", post(decide_approval))
        .route("/workers", get(workers))
        .route("/workers/{id}/reconcile", post(reconcile_worker))
        .route("/evidence/{id}", get(evidence))
        .route("/evidence/{id}/verify", post(verify_evidence))
        .route("/policies/{digest}/explain", get(explain_policy))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate));

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .nest("/v1", authenticated)
        .with_state(state)
}

async fn authenticate(
    State(state): State<ApiState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let caller = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Unauthenticated)
        .and_then(|value| state.authenticator.authenticate_header(value));
    match caller {
        Ok(caller) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Err(error) => ApiError(error).into_response(),
    }
}

async fn health(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    state.backend.health().await?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

async fn ready(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    state.backend.ready().await?;
    Ok(Json(serde_json::json!({"status": "ready"})))
}

async fn intake_sync(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<MutationReceipt>), ApiError> {
    caller.require(Permission::AcceptWork)?;
    let key = idempotency_key(&headers)?;
    let receipt = state.backend.intake_sync(&caller, key).await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn intake(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(request): Json<ApiIntakeRequest>,
) -> Result<(StatusCode, Json<ApiIntakeReceipt>), ApiError> {
    caller.require(Permission::SubmitIntake)?;
    let key = idempotency_key(&headers)?;
    request.validate_schema_version()?;
    let receipt = state.backend.intake(&request, &caller, key).await?;
    Ok((receipt.disposition.http_status(), Json(receipt)))
}

async fn list_work_items(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<WorkItemView>>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    page.validate()?;
    Ok(Json(
        state
            .backend
            .list_work_items(state.tenant_id, &page)
            .await?,
    ))
}

async fn get_work_item(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<WorkItemId>,
) -> Result<Json<WorkItemDetail>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    Ok(Json(
        state.backend.get_work_item(state.tenant_id, id).await?,
    ))
}

async fn accept_work_item(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<WorkItemId>,
    headers: HeaderMap,
    Json(request): Json<VersionedMutation>,
) -> Result<Json<MutationReceipt>, ApiError> {
    caller.require(Permission::AcceptWork)?;
    let key = idempotency_key(&headers)?;
    Ok(Json(
        state
            .backend
            .accept_work_item(state.tenant_id, id, &request, &caller, key)
            .await?,
    ))
}

async fn cancel_work_item(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<WorkItemId>,
    headers: HeaderMap,
    Json(request): Json<CancellationRequest>,
) -> Result<Json<MutationReceipt>, ApiError> {
    caller.require(Permission::CancelWork)?;
    if request.reason.trim().is_empty() {
        return Err(Error::Validation("cancellation reason is required".into()).into());
    }
    let key = idempotency_key(&headers)?;
    Ok(Json(
        state
            .backend
            .cancel_work_item(state.tenant_id, id, &request, &caller, key)
            .await?,
    ))
}

async fn work_item_events(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<WorkItemId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<Value>>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    page.validate()?;
    Ok(Json(
        state
            .backend
            .work_item_events(state.tenant_id, id, &page)
            .await?,
    ))
}

async fn attention(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<AttentionItemView>>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    page.validate()?;
    Ok(Json(state.backend.attention(state.tenant_id, &page).await?))
}

async fn decide_approval(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<ApprovalId>,
    headers: HeaderMap,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<MutationReceipt>, ApiError> {
    caller.require(Permission::DecideApproval)?;
    if !matches!(
        request.decision.as_str(),
        "approve" | "reject" | "request_changes"
    ) {
        return Err(Error::Validation("unsupported approval decision".into()).into());
    }
    let key = idempotency_key(&headers)?;
    Ok(Json(
        state
            .backend
            .decide_approval(state.tenant_id, id, &request, &caller, key)
            .await?,
    ))
}

async fn workers(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<Vec<WorkerView>>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    Ok(Json(state.backend.workers(state.tenant_id).await?))
}

async fn reconcile_worker(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<WorkerId>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<MutationReceipt>), ApiError> {
    caller.require(Permission::Reconcile)?;
    let key = idempotency_key(&headers)?;
    let receipt = state
        .backend
        .reconcile_worker(state.tenant_id, id, &caller, key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn evidence(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<EvidenceId>,
) -> Result<Json<EvidenceView>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    Ok(Json(state.backend.evidence(state.tenant_id, id).await?))
}

async fn verify_evidence(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<EvidenceId>,
    headers: HeaderMap,
) -> Result<Json<MutationReceipt>, ApiError> {
    caller.require(Permission::Reconcile)?;
    let key = idempotency_key(&headers)?;
    Ok(Json(
        state
            .backend
            .verify_evidence(state.tenant_id, id, &caller, key)
            .await?,
    ))
}

async fn explain_policy(
    State(state): State<ApiState>,
    Extension(caller): Extension<Caller>,
    Path(digest): Path<String>,
) -> Result<Json<Value>, ApiError> {
    caller.require(Permission::ViewLedger)?;
    Ok(Json(
        state
            .backend
            .explain_policy(state.tenant_id, &digest)
            .await?,
    ))
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str> {
    let value = headers
        .get("idempotency-key")
        .ok_or_else(|| Error::Validation("Idempotency-Key header is required".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Idempotency-Key header is not valid ASCII".into()))?;
    if value.trim().is_empty() || value.len() > 512 {
        return Err(Error::Validation(
            "Idempotency-Key must be 1..=512 bytes".into(),
        ));
    }
    Ok(value)
}

#[derive(Debug)]
struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, title) = match &self.0 {
            Error::Validation(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                "Validation failed",
            ),
            Error::InvalidTransition { .. } | Error::Conflict(_) => {
                (StatusCode::CONFLICT, "conflict", "Conflict")
            }
            Error::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", "Not found"),
            Error::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Authentication required",
            ),
            Error::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden", "Forbidden"),
            Error::Crypto(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "verification_failed",
                "Verification failed",
            ),
            Error::ExternalUnavailable(_) | Error::Persistence(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "Temporarily unavailable",
            ),
            Error::AmbiguousEffect(_) => (
                StatusCode::CONFLICT,
                "remote_effect_ambiguous",
                "Remote effect is ambiguous",
            ),
            Error::Serialization(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal error",
            ),
        };
        let detail = match &self.0 {
            Error::Unauthenticated => "valid bearer authentication is required".into(),
            Error::Crypto(_) | Error::Serialization(_) => title.into(),
            error => error.to_string(),
        };
        let problem = ProblemDetails {
            problem_type: format!("urn:asf:error:{code}"),
            title: title.into(),
            status: status.as_u16(),
            code: code.into(),
            detail,
            extensions: BTreeMap::new(),
        };
        (status, Json(problem)).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ProblemDetails {
    #[serde(rename = "type")]
    problem_type: String,
    title: String,
    status: u16,
    code: String,
    detail: String,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::TimeZone as _;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::*;

    fn attention(kind: AttentionItemKind) -> AttentionItemView {
        let is_escalation = kind == AttentionItemKind::Escalation;
        AttentionItemView {
            kind,
            id: Uuid::from_u128(1),
            work_item_id: is_escalation.then(|| WorkItemId::from_uuid(Uuid::from_u128(2))),
            workflow_job_id: (!is_escalation).then(|| Uuid::from_u128(3)),
            category: EscalationCategory::WorkflowJobExhausted,
            severity: "HIGH".into(),
            owner: "platform-operations".into(),
            required_action: "reconcile the exhausted job".into(),
            evidence_references: vec!["audit:sha256:evidence".into()],
            deadline: Utc
                .with_ymd_and_hms(2026, 8, 22, 12, 0, 0)
                .single()
                .expect("fixed timestamp"),
            retry_policy: json!({
                "automatic": false,
                "max_additional_attempts": 0,
                "backoff_seconds": 300,
                "prerequisites": ["operator reconciliation"]
            }),
            authority_or_effect_active: true,
        }
    }

    #[test]
    fn attention_v1_serialization_explicitly_discriminates_escalations() {
        let value = serde_json::to_value(attention(AttentionItemKind::Escalation))
            .expect("serialize escalation attention");
        assert_eq!(value["kind"], "ESCALATION");
        assert_eq!(value["id"], Uuid::from_u128(1).to_string());
        assert_eq!(value["work_item_id"], Uuid::from_u128(2).to_string());
        assert!(value["workflow_job_id"].is_null());
    }

    #[test]
    fn attention_v1_serialization_exposes_operational_job_identity_without_fake_work() {
        let value = serde_json::to_value(attention(AttentionItemKind::OperationalIncident))
            .expect("serialize operational attention");
        assert_eq!(value["kind"], "OPERATIONAL_INCIDENT");
        assert_eq!(value["id"], Uuid::from_u128(1).to_string());
        assert!(value["work_item_id"].is_null());
        assert_eq!(value["workflow_job_id"], Uuid::from_u128(3).to_string());
    }

    #[test]
    fn intake_disposition_http_status_marks_only_discovered_as_created() {
        assert_eq!(
            ApiIntakeDisposition::Discovered.http_status(),
            StatusCode::CREATED
        );
        for disposition in [
            ApiIntakeDisposition::Unchanged,
            ApiIntakeDisposition::ReadinessRequeued,
            ApiIntakeDisposition::AuthorityReevaluationRequired,
        ] {
            assert_eq!(
                disposition.http_status(),
                StatusCode::OK,
                "disposition {disposition:?} must reuse the existing work item, not create one"
            );
        }
    }

    fn valid_intake_body() -> Value {
        json!({
            "schema_version": API_INTAKE_REQUEST_SCHEMA_V1,
            "repository_id": Uuid::from_u128(7).to_string(),
            "external_id": "issue-42",
            "source_revision": "rev-abc123",
            "source_url": "https://example.com/issues/42",
            "title": "Fix flaky test",
            "objective": "Stabilize the flaky retry test",
            "acceptance_criteria": ["test passes 100 consecutive runs"],
            "non_goals": ["no unrelated refactors"],
            "labels": ["bug", "flaky"],
            "normalized_priority": 3,
            "source_state": "open",
            "assignee": "octocat",
            "source_updated_at": "2026-08-01T12:00:00Z",
        })
    }

    #[test]
    fn intake_request_deserialization_rejects_forbidden_authority_fields() {
        let forbidden_fields: [(&str, Value); 7] = [
            ("tenant_id", json!(Uuid::from_u128(99).to_string())),
            ("source", json!("github")),
            ("connector_identity", json!("connector:github:123")),
            ("policy_digest", json!("sha256:aaaa")),
            ("identity_requirements", json!({"mfa": true})),
            ("accepted", json!(true)),
            ("service_account_credential", json!("secret-token-value")),
        ];
        for (field, value) in forbidden_fields {
            let mut body = valid_intake_body();
            body.as_object_mut()
                .expect("intake body is an object")
                .insert(field.to_string(), value);
            assert!(
                serde_json::from_value::<ApiIntakeRequest>(body).is_err(),
                "field {field} must be rejected by strict deserialization"
            );
        }
    }

    #[test]
    fn intake_request_deserialization_round_trips_with_only_allowed_fields() {
        let request: ApiIntakeRequest = serde_json::from_value(valid_intake_body())
            .expect("a request with only allowed fields deserializes");
        assert_eq!(request.schema_version, API_INTAKE_REQUEST_SCHEMA_V1);
        assert_eq!(
            request.repository_id,
            RepositoryId::from_uuid(Uuid::from_u128(7))
        );
        assert_eq!(request.external_id, "issue-42");
        assert_eq!(
            request.labels,
            BTreeSet::from(["bug".to_string(), "flaky".to_string()])
        );
    }

    fn sample_receipt(disposition: ApiIntakeDisposition) -> ApiIntakeReceipt {
        ApiIntakeReceipt {
            schema_version: API_INTAKE_RECEIPT_SCHEMA_V1.to_string(),
            idempotency_key: "key-1".to_string(),
            work_item_id: WorkItemId::from_uuid(Uuid::from_u128(42)),
            source_snapshot_id: SourceSnapshotId::from_uuid(Uuid::from_u128(43)),
            content_digest:
                "sha256:423fa956c78c1e9fe9e63a4911421d032b1116d590578add0d2cf93dbe8a2a50"
                    .to_string(),
            disposition,
            state: WorkItemState::Discovered,
            version: 1,
            accepted: false,
        }
    }

    fn unsupported() -> Error {
        Error::Validation("stub backend: method unused by direct-intake contract tests".into())
    }

    #[derive(Debug)]
    struct RecordingApiBackend {
        intake_calls: AtomicUsize,
        accept_calls: AtomicUsize,
        receipt: ApiIntakeReceipt,
    }

    impl RecordingApiBackend {
        fn new(receipt: ApiIntakeReceipt) -> Self {
            Self {
                intake_calls: AtomicUsize::new(0),
                accept_calls: AtomicUsize::new(0),
                receipt,
            }
        }

        fn calls(&self) -> usize {
            self.intake_calls.load(Ordering::SeqCst)
        }

        fn accept_calls(&self) -> usize {
            self.accept_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ApiBackend for RecordingApiBackend {
        async fn health(&self) -> Result<()> {
            Err(unsupported())
        }

        async fn ready(&self) -> Result<()> {
            Err(unsupported())
        }

        async fn intake_sync(
            &self,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            Err(unsupported())
        }

        async fn intake(
            &self,
            _request: &ApiIntakeRequest,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<ApiIntakeReceipt> {
            self.intake_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.receipt.clone())
        }

        async fn list_work_items(
            &self,
            _tenant_id: TenantId,
            _page: &PageQuery,
        ) -> Result<Page<WorkItemView>> {
            Err(unsupported())
        }

        async fn get_work_item(
            &self,
            _tenant_id: TenantId,
            _id: WorkItemId,
        ) -> Result<WorkItemDetail> {
            Err(unsupported())
        }

        async fn accept_work_item(
            &self,
            _tenant_id: TenantId,
            _id: WorkItemId,
            _request: &VersionedMutation,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            self.accept_calls.fetch_add(1, Ordering::SeqCst);
            Err(unsupported())
        }

        async fn cancel_work_item(
            &self,
            _tenant_id: TenantId,
            _id: WorkItemId,
            _request: &CancellationRequest,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            Err(unsupported())
        }

        async fn work_item_events(
            &self,
            _tenant_id: TenantId,
            _id: WorkItemId,
            _page: &PageQuery,
        ) -> Result<Page<Value>> {
            Err(unsupported())
        }

        async fn attention(
            &self,
            _tenant_id: TenantId,
            _page: &PageQuery,
        ) -> Result<Page<AttentionItemView>> {
            Err(unsupported())
        }

        async fn decide_approval(
            &self,
            _tenant_id: TenantId,
            _id: ApprovalId,
            _request: &ApprovalDecisionRequest,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            Err(unsupported())
        }

        async fn workers(&self, _tenant_id: TenantId) -> Result<Vec<WorkerView>> {
            Err(unsupported())
        }

        async fn reconcile_worker(
            &self,
            _tenant_id: TenantId,
            _id: WorkerId,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            Err(unsupported())
        }

        async fn evidence(&self, _tenant_id: TenantId, _id: EvidenceId) -> Result<EvidenceView> {
            Err(unsupported())
        }

        async fn verify_evidence(
            &self,
            _tenant_id: TenantId,
            _id: EvidenceId,
            _caller: &Caller,
            _idempotency_key: &str,
        ) -> Result<MutationReceipt> {
            Err(unsupported())
        }

        async fn explain_policy(&self, _tenant_id: TenantId, _digest: &str) -> Result<Value> {
            Err(unsupported())
        }
    }

    fn owner_token() -> String {
        format!("owner-token-{}", "a".repeat(32))
    }

    fn viewer_token() -> String {
        format!("viewer-token-{}", "b".repeat(32))
    }

    fn intake_submitter_token() -> String {
        format!("intake-submitter-token-{}", "c".repeat(32))
    }

    fn approver_token() -> String {
        format!("approver-token-{}", "d".repeat(32))
    }

    fn operator_token() -> String {
        format!("operator-token-{}", "e".repeat(32))
    }

    fn test_authenticator() -> ApiAuthenticator {
        let config = json!([
            {"token": owner_token(), "subject": "user:owner", "roles": ["repository_owner"]},
            {"token": viewer_token(), "subject": "user:viewer", "roles": ["viewer"]},
            {"token": intake_submitter_token(), "subject": "user:intake-submitter", "roles": ["intake_submitter"]},
            {"token": approver_token(), "subject": "user:approver", "roles": ["approver"]},
            {"token": operator_token(), "subject": "user:operator", "roles": ["operator"]},
        ]);
        ApiAuthenticator::from_json(&config.to_string()).expect("valid authenticator config")
    }

    fn test_router(backend: Arc<RecordingApiBackend>) -> Router {
        router(ApiState {
            tenant_id: TenantId::new(),
            authenticator: test_authenticator(),
            backend,
        })
    }

    async fn send_intake(
        router: Router,
        token: Option<&str>,
        idempotency_key: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/intake")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        let request = builder
            .body(Body::from(
                serde_json::to_vec(body).expect("serialize intake body"),
            ))
            .expect("build intake request");
        let response = router
            .oneshot(request)
            .await
            .expect("router handles request");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let payload = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, payload)
    }

    async fn send_accept(
        router: Router,
        token: Option<&str>,
        id: WorkItemId,
        idempotency_key: Option<&str>,
    ) -> StatusCode {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/v1/work-items/{id}/accept"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        let request = builder
            .body(Body::from(
                serde_json::to_vec(&json!({"expected_version": 1})).expect("serialize body"),
            ))
            .expect("build accept request");
        router
            .oneshot(request)
            .await
            .expect("router handles request")
            .status()
    }

    #[tokio::test]
    async fn intake_without_bearer_returns_401_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(router, None, Some("key-1"), &valid_intake_body()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_with_invalid_bearer_returns_401_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some("not-a-real-token"),
            Some("key-1"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_viewer_without_accept_work_returns_403_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&viewer_token()),
            Some("key-1"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_missing_idempotency_key_returns_422_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) =
            send_intake(router, Some(&owner_token()), None, &valid_intake_body()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_blank_idempotency_key_returns_422_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&owner_token()),
            Some("   "),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_oversized_idempotency_key_returns_422_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let oversized_key = "k".repeat(513);
        let (status, _) = send_intake(
            router,
            Some(&owner_token()),
            Some(&oversized_key),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_non_ascii_idempotency_key_returns_422_and_skips_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&owner_token()),
            Some("café-key-☕"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_wrong_schema_version_returns_422_before_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let mut body = valid_intake_body();
        body["schema_version"] = json!("asf.api-intake-request/v0");
        let (status, _) = send_intake(router, Some(&owner_token()), Some("key-1"), &body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_unknown_authority_field_returns_json_rejection_before_backend() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let mut body = valid_intake_body();
        body["tenant_id"] = json!(Uuid::from_u128(99).to_string());
        let (status, _) = send_intake(router, Some(&owner_token()), Some("key-1"), &body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_owner_valid_request_returns_backend_receipt_with_disposition_status() {
        for disposition in [
            ApiIntakeDisposition::Discovered,
            ApiIntakeDisposition::Unchanged,
            ApiIntakeDisposition::ReadinessRequeued,
            ApiIntakeDisposition::AuthorityReevaluationRequired,
        ] {
            let receipt = sample_receipt(disposition);
            let backend = Arc::new(RecordingApiBackend::new(receipt.clone()));
            let router = test_router(Arc::clone(&backend));
            let (status, body) = send_intake(
                router,
                Some(&owner_token()),
                Some("key-1"),
                &valid_intake_body(),
            )
            .await;
            let expected_status = if disposition == ApiIntakeDisposition::Discovered {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            assert_eq!(status, expected_status, "disposition {disposition:?}");
            assert_eq!(
                body,
                serde_json::to_value(&receipt).expect("serialize receipt")
            );
            assert_eq!(backend.calls(), 1);
        }
    }

    #[tokio::test]
    async fn intake_submitter_valid_request_succeeds_at_direct_intake() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&intake_submitter_token()),
            Some("key-1"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn approver_forbidden_at_direct_intake() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&approver_token()),
            Some("key-1"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn operator_forbidden_at_direct_intake() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let (status, _) = send_intake(
            router,
            Some(&operator_token()),
            Some("key-1"),
            &valid_intake_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(backend.calls(), 0);
    }

    #[tokio::test]
    async fn intake_submitter_forbidden_at_work_acceptance() {
        let backend = Arc::new(RecordingApiBackend::new(sample_receipt(
            ApiIntakeDisposition::Discovered,
        )));
        let router = test_router(Arc::clone(&backend));
        let status = send_accept(
            router,
            Some(&intake_submitter_token()),
            WorkItemId::from_uuid(Uuid::from_u128(1)),
            Some("key-1"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(backend.accept_calls(), 0);
    }
}
