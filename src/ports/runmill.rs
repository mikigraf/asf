use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    contracts::{
        EVIDENCE_SCHEMA_V1, ProductEvent, SignedEvidenceBundle, SignedWorkOrder,
        WORK_ORDER_SCHEMA_V1,
    },
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
    domain::{AttemptId, RunId, TenantId, WorkItemId, WorkOrderId, WorkerId},
};

pub const RUNMILL_GATEWAY_SCHEMA_V1: &str = "asf.runmill-gateway.v1";
pub const RUNMILL_CAPABILITY_REQUEST_SCHEMA_V1: &str = "asf.runmill-capability-request.v1";
pub const RUNMILL_CAPABILITIES_SCHEMA_V1: &str = "asf.runmill-capabilities.v1";
pub const SUBMIT_WORK_ORDER_REQUEST_SCHEMA_V1: &str = "asf.runmill-submit-work-order-request.v1";
pub const SUBMIT_WORK_ORDER_RECEIPT_SCHEMA_V1: &str = "asf.runmill-submit-work-order-receipt.v1";
pub const GET_RUN_REQUEST_SCHEMA_V1: &str = "asf.runmill-get-run-request.v1";
pub const GET_RUN_RECEIPT_SCHEMA_V1: &str = "asf.runmill-get-run-receipt.v1";
pub const RUN_SNAPSHOT_SCHEMA_V1: &str = "asf.runmill-run-snapshot.v1";
pub const GET_RUN_EVENTS_REQUEST_SCHEMA_V1: &str = "asf.runmill-get-run-events-request.v1";
pub const RUN_EVENT_PAGE_SCHEMA_V1: &str = "asf.runmill-run-event-page.v1";
pub const CANCEL_RUN_REQUEST_SCHEMA_V1: &str = "asf.runmill-cancel-run-request.v1";
pub const CANCEL_RUN_RECEIPT_SCHEMA_V1: &str = "asf.runmill-cancel-run-receipt.v1";
pub const GET_EVIDENCE_REQUEST_SCHEMA_V1: &str = "asf.runmill-get-evidence-request.v1";
pub const GET_EVIDENCE_RECEIPT_SCHEMA_V1: &str = "asf.runmill-get-evidence-receipt.v1";
pub const ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1: &str =
    "asf.runmill-acknowledge-outcome-request.v1";
pub const ACKNOWLEDGE_OUTCOME_RECEIPT_SCHEMA_V1: &str =
    "asf.runmill-acknowledge-outcome-receipt.v1";
pub const PRODUCT_EVENT_SCHEMA_V1: &str = "asf.product-event.v1";

pub const RUNMILL_CAPABILITY_REQUEST_SCHEMA_V2: &str = "asf.runmill-capability-request.v2";
pub const RUNMILL_CAPABILITIES_SCHEMA_V2: &str = "asf.runmill-capabilities.v2";
pub const LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1: &str =
    "asf.runmill-lookup-qualified-submission-request.v1";
pub const LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1: &str =
    "asf.runmill-lookup-qualified-submission-receipt.v1";

/// Semantic operations ASF requires from a compatible Runmill worker.
///
/// These are deliberately not MCP tool names. No compatible tool-name contract
/// currently exists, so transport bindings must not infer one from this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillOperation {
    SubmitWorkOrder,
    GetRun,
    GetRunEvents,
    CancelRun,
    GetEvidence,
    AcknowledgeOutcome,
}

impl RunmillOperation {
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::SubmitWorkOrder,
            Self::GetRun,
            Self::GetRunEvents,
            Self::CancelRun,
            Self::GetEvidence,
            Self::AcknowledgeOutcome,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityNegotiationRequest {
    pub schema: String,
    pub gateway_schema: String,
    pub accepted_work_order_schemas: BTreeSet<String>,
    pub accepted_event_schemas: BTreeSet<String>,
    pub accepted_evidence_schemas: BTreeSet<String>,
    pub required_operations: BTreeSet<RunmillOperation>,
    pub require_durable_async_runs: bool,
    pub require_idempotent_submission: bool,
    pub require_cursor_events: bool,
    pub require_signed_evidence: bool,
    pub require_disconnect_survival: bool,
    pub require_asf_source_ownership: bool,
}

impl CapabilityNegotiationRequest {
    #[must_use]
    pub fn asf_v1() -> Self {
        Self {
            schema: RUNMILL_CAPABILITY_REQUEST_SCHEMA_V1.into(),
            gateway_schema: RUNMILL_GATEWAY_SCHEMA_V1.into(),
            accepted_work_order_schemas: BTreeSet::from([WORK_ORDER_SCHEMA_V1.into()]),
            accepted_event_schemas: BTreeSet::from([PRODUCT_EVENT_SCHEMA_V1.into()]),
            accepted_evidence_schemas: BTreeSet::from([EVIDENCE_SCHEMA_V1.into()]),
            required_operations: RunmillOperation::all().into_iter().collect(),
            require_durable_async_runs: true,
            require_idempotent_submission: true,
            require_cursor_events: true,
            require_signed_evidence: true,
            require_disconnect_survival: true,
            require_asf_source_ownership: true,
        }
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != RUNMILL_CAPABILITY_REQUEST_SCHEMA_V1
            || self.gateway_schema != RUNMILL_GATEWAY_SCHEMA_V1
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported capability negotiation schema".into(),
            ));
        }
        if self.accepted_work_order_schemas.is_empty()
            || self.accepted_event_schemas.is_empty()
            || self.accepted_evidence_schemas.is_empty()
            || self.required_operations.is_empty()
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "capability negotiation must name every required schema and operation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCapabilities {
    pub schema: String,
    pub gateway_schema: String,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub accepted_work_order_schemas: BTreeSet<String>,
    pub emitted_event_schemas: BTreeSet<String>,
    pub emitted_evidence_schemas: BTreeSet<String>,
    pub operations: BTreeSet<RunmillOperation>,
    pub durable_async_runs: bool,
    pub idempotent_submission: bool,
    pub cursor_events: bool,
    pub signed_evidence: bool,
    pub survives_control_disconnect: bool,
    pub asf_owns_source_mutations: bool,
    pub max_event_page_size: u32,
}

impl RunmillCapabilities {
    #[must_use]
    pub fn prospective_v1(worker_id: WorkerId, worker_generation: u64) -> Self {
        Self {
            schema: RUNMILL_CAPABILITIES_SCHEMA_V1.into(),
            gateway_schema: RUNMILL_GATEWAY_SCHEMA_V1.into(),
            worker_id,
            worker_generation,
            accepted_work_order_schemas: BTreeSet::from([WORK_ORDER_SCHEMA_V1.into()]),
            emitted_event_schemas: BTreeSet::from([PRODUCT_EVENT_SCHEMA_V1.into()]),
            emitted_evidence_schemas: BTreeSet::from([EVIDENCE_SCHEMA_V1.into()]),
            operations: RunmillOperation::all().into_iter().collect(),
            durable_async_runs: true,
            idempotent_submission: true,
            cursor_events: true,
            signed_evidence: true,
            survives_control_disconnect: true,
            asf_owns_source_mutations: true,
            max_event_page_size: 1_000,
        }
    }

    pub fn satisfy(&self, request: &CapabilityNegotiationRequest) -> RunmillResult<()> {
        request.validate()?;
        let schemas_match = self.schema == RUNMILL_CAPABILITIES_SCHEMA_V1
            && self.gateway_schema == request.gateway_schema
            && !self
                .accepted_work_order_schemas
                .is_disjoint(&request.accepted_work_order_schemas)
            && !self
                .emitted_event_schemas
                .is_disjoint(&request.accepted_event_schemas)
            && !self
                .emitted_evidence_schemas
                .is_disjoint(&request.accepted_evidence_schemas);
        let operations_match = request.required_operations.is_subset(&self.operations);
        let guarantees_match = (!request.require_durable_async_runs || self.durable_async_runs)
            && (!request.require_idempotent_submission || self.idempotent_submission)
            && (!request.require_cursor_events || self.cursor_events)
            && (!request.require_signed_evidence || self.signed_evidence)
            && (!request.require_disconnect_survival || self.survives_control_disconnect)
            && (!request.require_asf_source_ownership || self.asf_owns_source_mutations)
            && self.max_event_page_size > 0;

        if schemas_match && operations_match && guarantees_match {
            Ok(())
        } else {
            Err(RunmillGatewayError::UnsupportedContract {
                detail: "worker does not satisfy ASF's required schemas, operations, and durability guarantees"
                    .into(),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Accepted,
    Adopted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitWorkOrderRequest {
    pub schema: String,
    pub idempotency_key: String,
    pub work_order_digest: String,
    pub work_order: SignedWorkOrder,
}

impl SubmitWorkOrderRequest {
    pub fn new(work_order: SignedWorkOrder) -> RunmillResult<Self> {
        let idempotency_key = work_order.payload.idempotency_key.clone();
        let work_order_digest = work_order.payload.digest().map_err(|error| {
            RunmillGatewayError::InvalidRequest(format!("invalid Work Order: {error}"))
        })?;
        let request = Self {
            schema: SUBMIT_WORK_ORDER_REQUEST_SCHEMA_V1.into(),
            idempotency_key,
            work_order_digest,
            work_order,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != SUBMIT_WORK_ORDER_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported work-order submission request schema".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(RunmillGatewayError::InvalidRequest(
                "submission idempotency key is required".into(),
            ));
        }
        self.work_order.payload.validate().map_err(|error| {
            RunmillGatewayError::InvalidRequest(format!("invalid Work Order: {error}"))
        })?;
        let digest = self.work_order.payload.digest().map_err(|error| {
            RunmillGatewayError::InvalidRequest(format!("invalid Work Order: {error}"))
        })?;
        if self.idempotency_key != self.work_order.payload.idempotency_key
            || self.work_order_digest != digest
            || self.work_order.payload_digest != digest
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "submission identity or digest does not match the signed Work Order".into(),
            ));
        }
        if self.work_order.envelope_schema != "asf.work-order-envelope/v1"
            || self.work_order.algorithm != "EdDSA"
            || self.work_order.key_id.trim().is_empty()
            || self.work_order.signature.trim().is_empty()
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "signed Work Order envelope is incomplete or unsupported".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitWorkOrderReceipt {
    pub schema: String,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub idempotency_key: String,
    pub work_order_digest: String,
    pub disposition: SubmissionDisposition,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum RunLookup {
    RunId(RunId),
    AttemptId(AttemptId),
    IdempotencyKey(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetRunRequest {
    pub schema: String,
    pub lookup: RunLookup,
}

impl GetRunRequest {
    #[must_use]
    pub fn by_run_id(run_id: RunId) -> Self {
        Self {
            schema: GET_RUN_REQUEST_SCHEMA_V1.into(),
            lookup: RunLookup::RunId(run_id),
        }
    }

    #[must_use]
    pub fn by_attempt_id(attempt_id: AttemptId) -> Self {
        Self {
            schema: GET_RUN_REQUEST_SCHEMA_V1.into(),
            lookup: RunLookup::AttemptId(attempt_id),
        }
    }

    #[must_use]
    pub fn by_idempotency_key(idempotency_key: impl Into<String>) -> Self {
        Self {
            schema: GET_RUN_REQUEST_SCHEMA_V1.into(),
            lookup: RunLookup::IdempotencyKey(idempotency_key.into()),
        }
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != GET_RUN_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported get-run request schema".into(),
            ));
        }
        if matches!(&self.lookup, RunLookup::IdempotencyKey(key) if key.trim().is_empty()) {
            return Err(RunmillGatewayError::InvalidRequest(
                "run lookup idempotency key is required".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillRunState {
    Accepted,
    Queued,
    Running,
    WaitingApproval,
    NeedsHuman,
    BlockedExternal,
    CancelRequested,
    Cancelled,
    TargetReached,
    Failed,
    Quarantined,
}

impl RunmillRunState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::TargetReached | Self::Failed | Self::Quarantined
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSnapshot {
    pub schema: String,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub idempotency_key: String,
    pub work_order_digest: String,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub state: RunmillRunState,
    pub aggregate_version: u64,
    pub last_event_cursor: Option<EventCursor>,
    pub evidence_digest: Option<String>,
    pub outcome_acknowledged: bool,
    pub accepted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetRunReceipt {
    pub schema: String,
    pub run: Option<RunSnapshot>,
}

/// Opaque, run-scoped position after a delivered event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventCursor(String);

impl EventCursor {
    pub fn from_opaque(value: impl Into<String>) -> RunmillResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RunmillGatewayError::InvalidCursor(
                "event cursor cannot be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetRunEventsRequest {
    pub schema: String,
    pub run_id: RunId,
    pub after: Option<EventCursor>,
    pub limit: u32,
}

impl GetRunEventsRequest {
    #[must_use]
    pub fn first_page(run_id: RunId, limit: u32) -> Self {
        Self {
            schema: GET_RUN_EVENTS_REQUEST_SCHEMA_V1.into(),
            run_id,
            after: None,
            limit,
        }
    }

    pub fn validate(&self, max_page_size: u32) -> RunmillResult<()> {
        if self.schema != GET_RUN_EVENTS_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported run-event request schema".into(),
            ));
        }
        if self.limit == 0 || self.limit > max_page_size {
            return Err(RunmillGatewayError::InvalidRequest(format!(
                "event page limit must be within 1..={max_page_size}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEventPage {
    pub schema: String,
    pub run_id: RunId,
    pub after: Option<EventCursor>,
    pub events: Vec<ProductEvent>,
    pub next_cursor: Option<EventCursor>,
    pub has_more: bool,
    pub snapshot: RunSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRunRequest {
    pub schema: String,
    pub run_id: RunId,
    pub idempotency_key: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
}

impl CancelRunRequest {
    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != CANCEL_RUN_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported cancel-run request schema".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() || self.reason.trim().is_empty() {
            return Err(RunmillGatewayError::InvalidRequest(
                "cancellation idempotency key and reason are required".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationDisposition {
    Requested,
    Adopted,
    AlreadyTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRunReceipt {
    pub schema: String,
    pub run_id: RunId,
    pub idempotency_key: String,
    pub disposition: CancellationDisposition,
    pub state: RunmillRunState,
    pub aggregate_version: u64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetEvidenceRequest {
    pub schema: String,
    pub run_id: RunId,
}

impl GetEvidenceRequest {
    #[must_use]
    pub fn for_run(run_id: RunId) -> Self {
        Self {
            schema: GET_EVIDENCE_REQUEST_SCHEMA_V1.into(),
            run_id,
        }
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != GET_EVIDENCE_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported get-evidence request schema".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetEvidenceReceipt {
    pub schema: String,
    pub run_id: RunId,
    pub evidence: Option<SignedEvidenceBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeOutcomeRequest {
    pub schema: String,
    pub run_id: RunId,
    pub idempotency_key: String,
    pub evidence_digest: String,
    pub acknowledged_at: DateTime<Utc>,
}

impl AcknowledgeOutcomeRequest {
    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported outcome-acknowledgement request schema".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() || self.evidence_digest.trim().is_empty() {
            return Err(RunmillGatewayError::InvalidRequest(
                "acknowledgement idempotency key and evidence digest are required".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementDisposition {
    Recorded,
    Adopted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeOutcomeReceipt {
    pub schema: String,
    pub run_id: RunId,
    pub idempotency_key: String,
    pub evidence_digest: String,
    pub disposition: AcknowledgementDisposition,
    pub aggregate_version: u64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillOperationV2 {
    LookupQualifiedSubmissionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSubmissionIdentityV1 {
    pub tenant_id: TenantId,
    pub work_order_id: WorkOrderId,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub idempotency_key: String,
    pub work_order_digest: String,
    pub request_digest: String,
}

impl QualifiedSubmissionIdentityV1 {
    pub fn from_submit_work_order_request(request: &SubmitWorkOrderRequest) -> RunmillResult<Self> {
        request.validate()?;
        let request_digest =
            sha256_digest(&canonical_json(&request.work_order).map_err(|error| {
                RunmillGatewayError::InvalidRequest(format!(
                    "invalid signed Work Order envelope: {error}"
                ))
            })?);
        let identity = Self {
            tenant_id: request.work_order.payload.tenant_id,
            work_order_id: request.work_order.payload.work_order_id,
            work_item_id: request.work_order.payload.work_item_id,
            attempt_id: request.work_order.payload.attempt_id,
            idempotency_key: request.idempotency_key.clone(),
            work_order_digest: request.work_order_digest.clone(),
            request_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.tenant_id.as_uuid().is_nil() {
            return Err(RunmillGatewayError::InvalidRequest(
                "tenant_id cannot be nil".into(),
            ));
        }
        if self.work_order_id.as_uuid().is_nil() {
            return Err(RunmillGatewayError::InvalidRequest(
                "work_order_id cannot be nil".into(),
            ));
        }
        if self.work_item_id.as_uuid().is_nil() {
            return Err(RunmillGatewayError::InvalidRequest(
                "work_item_id cannot be nil".into(),
            ));
        }
        if self.attempt_id.as_uuid().is_nil() {
            return Err(RunmillGatewayError::InvalidRequest(
                "attempt_id cannot be nil".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(RunmillGatewayError::InvalidRequest(
                "idempotency key is required".into(),
            ));
        }
        if !is_sha256_digest(&self.work_order_digest) {
            return Err(RunmillGatewayError::InvalidRequest(
                "work_order_digest must be a valid SHA256 digest".into(),
            ));
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err(RunmillGatewayError::InvalidRequest(
                "request_digest must be a valid SHA256 digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupQualifiedSubmissionRequest {
    pub schema: String,
    pub qualification: QualifiedSubmissionIdentityV1,
}

impl LookupQualifiedSubmissionRequest {
    pub fn new(qualification: QualifiedSubmissionIdentityV1) -> RunmillResult<Self> {
        let request = Self {
            schema: LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1.into(),
            qualification,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported lookup-qualified-submission request schema".into(),
            ));
        }
        self.qualification.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSubmissionAdmissionWorkerV1 {
    pub worker_id: WorkerId,
    pub worker_generation: u64,
}

impl QualifiedSubmissionAdmissionWorkerV1 {
    pub fn validate(&self) -> RunmillResult<()> {
        if self.worker_id.as_uuid().is_nil() {
            return Err(RunmillGatewayError::InvalidRequest(
                "worker_id cannot be nil".into(),
            ));
        }
        if self.worker_generation == 0 {
            return Err(RunmillGatewayError::InvalidRequest(
                "worker_generation must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSubmissionFound {
    pub qualification: QualifiedSubmissionIdentityV1,
    pub run: RunSnapshot,
    pub admission_worker: QualifiedSubmissionAdmissionWorkerV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LookupQualifiedSubmissionOutcome {
    Found(Box<QualifiedSubmissionFound>),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupQualifiedSubmissionReceipt {
    pub schema: String,
    pub outcome: LookupQualifiedSubmissionOutcome,
}

impl LookupQualifiedSubmissionReceipt {
    pub fn validate_against(
        &self,
        request: &LookupQualifiedSubmissionRequest,
    ) -> RunmillResult<()> {
        if self.schema != LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1 {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported lookup-qualified-submission receipt schema".into(),
            ));
        }
        match &self.outcome {
            LookupQualifiedSubmissionOutcome::Found(found) => {
                if found.qualification != request.qualification {
                    return Err(RunmillGatewayError::InvalidRequest(
                        "receipt qualification does not match request qualification".into(),
                    ));
                }
                if found.run.attempt_id != request.qualification.attempt_id
                    || found.run.idempotency_key != request.qualification.idempotency_key
                    || found.run.work_order_digest != request.qualification.work_order_digest
                {
                    return Err(RunmillGatewayError::InvalidRequest(
                        "receipt run does not match request qualification".into(),
                    ));
                }
                found.admission_worker.validate()?;
                if found.admission_worker.worker_id != found.run.worker_id {
                    return Err(RunmillGatewayError::InvalidRequest(
                        "receipt admission worker ID does not match run worker ID".into(),
                    ));
                }
                if found.admission_worker.worker_generation != found.run.worker_generation {
                    return Err(RunmillGatewayError::InvalidRequest(
                        "receipt admission worker generation does not match run worker generation"
                            .into(),
                    ));
                }
                Ok(())
            }
            LookupQualifiedSubmissionOutcome::NotFound => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityNegotiationRequestV2 {
    pub schema: String,
    pub gateway_schema: String,
    pub supported_lookup_schemas: BTreeSet<String>,
    pub accepted_work_order_schemas: BTreeSet<String>,
    pub accepted_event_schemas: BTreeSet<String>,
    pub accepted_evidence_schemas: BTreeSet<String>,
    pub required_operations: BTreeSet<RunmillOperationV2>,
}

impl CapabilityNegotiationRequestV2 {
    #[must_use]
    pub fn asf_v2() -> Self {
        Self {
            schema: RUNMILL_CAPABILITY_REQUEST_SCHEMA_V2.into(),
            gateway_schema: RUNMILL_GATEWAY_SCHEMA_V1.into(),
            supported_lookup_schemas: BTreeSet::from([
                LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1.into(),
                LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
            ]),
            accepted_work_order_schemas: BTreeSet::from([WORK_ORDER_SCHEMA_V1.into()]),
            accepted_event_schemas: BTreeSet::from([PRODUCT_EVENT_SCHEMA_V1.into()]),
            accepted_evidence_schemas: BTreeSet::from([EVIDENCE_SCHEMA_V1.into()]),
            required_operations: BTreeSet::from([RunmillOperationV2::LookupQualifiedSubmissionV1]),
        }
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != RUNMILL_CAPABILITY_REQUEST_SCHEMA_V2
            || self.gateway_schema != RUNMILL_GATEWAY_SCHEMA_V1
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported capability negotiation schema".into(),
            ));
        }
        if !self
            .supported_lookup_schemas
            .contains(LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1)
            || !self
                .supported_lookup_schemas
                .contains(LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1)
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "capability negotiation must include both lookup request and receipt schemas"
                    .into(),
            ));
        }
        if self.accepted_work_order_schemas.is_empty()
            || self.accepted_event_schemas.is_empty()
            || self.accepted_evidence_schemas.is_empty()
            || self.required_operations.is_empty()
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "capability negotiation must name every required schema and operation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCapabilitiesV2 {
    pub schema: String,
    pub gateway_schema: String,
    pub supported_lookup_schemas: BTreeSet<String>,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub accepted_work_order_schemas: BTreeSet<String>,
    pub emitted_event_schemas: BTreeSet<String>,
    pub emitted_evidence_schemas: BTreeSet<String>,
    pub operations: BTreeSet<RunmillOperationV2>,
}

impl RunmillCapabilitiesV2 {
    #[must_use]
    pub fn prospective_v2(worker_id: WorkerId, worker_generation: u64) -> Self {
        Self {
            schema: RUNMILL_CAPABILITIES_SCHEMA_V2.into(),
            gateway_schema: RUNMILL_GATEWAY_SCHEMA_V1.into(),
            supported_lookup_schemas: BTreeSet::from([
                LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1.into(),
                LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
            ]),
            worker_id,
            worker_generation,
            accepted_work_order_schemas: BTreeSet::from([WORK_ORDER_SCHEMA_V1.into()]),
            emitted_event_schemas: BTreeSet::from([PRODUCT_EVENT_SCHEMA_V1.into()]),
            emitted_evidence_schemas: BTreeSet::from([EVIDENCE_SCHEMA_V1.into()]),
            operations: BTreeSet::from([RunmillOperationV2::LookupQualifiedSubmissionV1]),
        }
    }

    pub fn validate(&self) -> RunmillResult<()> {
        if self.schema != RUNMILL_CAPABILITIES_SCHEMA_V2
            || self.gateway_schema != RUNMILL_GATEWAY_SCHEMA_V1
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "unsupported capabilities schema".into(),
            ));
        }
        if !self
            .supported_lookup_schemas
            .contains(LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1)
            || !self
                .supported_lookup_schemas
                .contains(LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1)
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "capabilities must include both lookup request and receipt schemas".into(),
            ));
        }
        Ok(())
    }

    pub fn satisfy(&self, request: &CapabilityNegotiationRequestV2) -> RunmillResult<()> {
        request.validate()?;
        self.validate()?;
        let schemas_match = self.schema == RUNMILL_CAPABILITIES_SCHEMA_V2
            && self.gateway_schema == request.gateway_schema
            && !self
                .accepted_work_order_schemas
                .is_disjoint(&request.accepted_work_order_schemas)
            && !self
                .emitted_event_schemas
                .is_disjoint(&request.accepted_event_schemas)
            && !self
                .emitted_evidence_schemas
                .is_disjoint(&request.accepted_evidence_schemas)
            && !self
                .supported_lookup_schemas
                .is_disjoint(&request.supported_lookup_schemas);
        let operations_match = request.required_operations.is_subset(&self.operations);

        if schemas_match && operations_match {
            Ok(())
        } else {
            Err(RunmillGatewayError::UnsupportedContract {
                detail: "worker does not satisfy ASF's required schemas and operations".into(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RunmillGatewayError {
    #[error("unsupported Runmill contract: {detail}")]
    UnsupportedContract { detail: String },
    #[error(
        "Runmill idempotency conflict for {idempotency_key}: existing digest {existing_digest}, submitted digest {submitted_digest}"
    )]
    IdempotencyConflict {
        idempotency_key: String,
        existing_digest: String,
        submitted_digest: String,
    },
    #[error("invalid Runmill request: {0}")]
    InvalidRequest(String),
    #[error("invalid Runmill event cursor: {0}")]
    InvalidCursor(String),
    #[error("Runmill run not found: {0}")]
    RunNotFound(RunId),
    #[error("Runmill evidence is unavailable: {0}")]
    EvidenceUnavailable(String),
    #[error("Runmill transport is unavailable: {0}")]
    TransportUnavailable(String),
}

pub type RunmillResult<T> = Result<T, RunmillGatewayError>;

#[async_trait]
pub trait RunmillGateway: Send + Sync {
    async fn negotiate(
        &self,
        request: &CapabilityNegotiationRequest,
    ) -> RunmillResult<RunmillCapabilities>;

    async fn submit_work_order(
        &self,
        request: &SubmitWorkOrderRequest,
    ) -> RunmillResult<SubmitWorkOrderReceipt>;

    async fn get_run(&self, request: &GetRunRequest) -> RunmillResult<GetRunReceipt>;

    async fn get_run_events(&self, request: &GetRunEventsRequest) -> RunmillResult<RunEventPage>;

    async fn cancel_run(&self, request: &CancelRunRequest) -> RunmillResult<CancelRunReceipt>;

    async fn get_evidence(&self, request: &GetEvidenceRequest)
    -> RunmillResult<GetEvidenceReceipt>;

    async fn acknowledge_outcome(
        &self,
        request: &AcknowledgeOutcomeRequest,
    ) -> RunmillResult<AcknowledgeOutcomeReceipt>;

    async fn negotiate_v2(
        &self,
        request: &CapabilityNegotiationRequestV2,
    ) -> RunmillResult<RunmillCapabilitiesV2> {
        request.validate()?;
        Err(RunmillGatewayError::UnsupportedContract {
            detail: "V2 capability negotiation is not supported".into(),
        })
    }

    async fn lookup_qualified_submission(
        &self,
        request: &LookupQualifiedSubmissionRequest,
    ) -> RunmillResult<LookupQualifiedSubmissionReceipt> {
        request.validate()?;
        Err(RunmillGatewayError::UnsupportedContract {
            detail: "qualified submission lookup is not supported".into(),
        })
    }
}
