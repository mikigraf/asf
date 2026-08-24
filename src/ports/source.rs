use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    contracts::PullRequestEvidence,
    crypto::{canonical_json, sha256_digest},
    domain::{ClosureTarget, EvidenceId, SourceSnapshot, SourceSystem, TenantId, WorkItemId},
};

pub const SOURCE_GATEWAY_SCHEMA_V1: &str = "asf.source-gateway.v1";
pub const SOURCE_INTAKE_REQUEST_SCHEMA_V1: &str = "asf.source-intake-request.v1";
pub const SOURCE_INTAKE_PAGE_SCHEMA_V1: &str = "asf.source-intake-page.v1";
pub const OBSERVE_SOURCE_REQUEST_SCHEMA_V1: &str = "asf.observe-source-request.v1";
pub const SOURCE_OBSERVATION_SCHEMA_V1: &str = "asf.source-observation.v1";
pub const SOURCE_CLOSE_EFFECT_SCHEMA_V1: &str = "asf.source-close-effect.v1";
pub const CLOSE_SOURCE_REQUEST_SCHEMA_V1: &str = "asf.close-source-request.v1";
pub const SOURCE_CLOSE_RECEIPT_SCHEMA_V1: &str = "asf.source-close-receipt.v1";
pub const RECONCILE_SOURCE_CLOSE_REQUEST_SCHEMA_V1: &str = "asf.reconcile-source-close-request.v1";
pub const SOURCE_CLOSE_RECONCILIATION_SCHEMA_V1: &str = "asf.source-close-reconciliation.v1";
pub const MAX_SOURCE_INTAKE_PAGE_SIZE: u32 = 1_000;

/// Stable external identity of a source item inside a tenant boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceItemRef {
    pub tenant_id: TenantId,
    pub source: SourceSystem,
    pub external_id: String,
}

impl SourceItemRef {
    pub fn validate(&self) -> SourceResult<()> {
        if self.external_id.trim().is_empty() {
            return Err(SourceGatewayError::InvalidRequest(
                "source external ID is required".into(),
            ));
        }
        Ok(())
    }
}

/// Opaque connector-scoped position after a page of normalized snapshots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceCursor(String);

impl SourceCursor {
    pub fn from_opaque(value: impl Into<String>) -> SourceResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SourceGatewayError::InvalidCursor(
                "source cursor cannot be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Requests current, explicitly opted-in source items.
///
/// Product logic consumes only the normalized immutable [`SourceSnapshot`]s in
/// the response. Raw webhook bodies and provider credentials are deliberately
/// absent from this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIntakeRequest {
    pub schema: String,
    pub tenant_id: TenantId,
    pub opt_in_label: String,
    pub after: Option<SourceCursor>,
    pub limit: u32,
}

impl SourceIntakeRequest {
    #[must_use]
    pub fn first_page(tenant_id: TenantId, opt_in_label: impl Into<String>, limit: u32) -> Self {
        Self {
            schema: SOURCE_INTAKE_REQUEST_SCHEMA_V1.into(),
            tenant_id,
            opt_in_label: opt_in_label.into(),
            after: None,
            limit,
        }
    }

    pub fn validate(&self) -> SourceResult<()> {
        if self.schema != SOURCE_INTAKE_REQUEST_SCHEMA_V1 {
            return Err(SourceGatewayError::InvalidRequest(
                "unsupported source-intake request schema".into(),
            ));
        }
        if self.opt_in_label.trim().is_empty() {
            return Err(SourceGatewayError::InvalidRequest(
                "source opt-in label is required".into(),
            ));
        }
        if self.limit == 0 || self.limit > MAX_SOURCE_INTAKE_PAGE_SIZE {
            return Err(SourceGatewayError::InvalidRequest(format!(
                "source page limit must be within 1..={MAX_SOURCE_INTAKE_PAGE_SIZE}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIntakePage {
    pub schema: String,
    pub snapshots: Vec<SourceSnapshot>,
    pub next_cursor: Option<SourceCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveSourceRequest {
    pub schema: String,
    pub item: SourceItemRef,
}

impl ObserveSourceRequest {
    #[must_use]
    pub fn new(item: SourceItemRef) -> Self {
        Self {
            schema: OBSERVE_SOURCE_REQUEST_SCHEMA_V1.into(),
            item,
        }
    }

    pub fn validate(&self) -> SourceResult<()> {
        if self.schema != OBSERVE_SOURCE_REQUEST_SCHEMA_V1 {
            return Err(SourceGatewayError::InvalidRequest(
                "unsupported source-observation request schema".into(),
            ));
        }
        self.item.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLifecycle {
    Active,
    Completed,
    Canceled,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservation {
    pub schema: String,
    pub item: SourceItemRef,
    pub lifecycle: SourceLifecycle,
    pub current_snapshot: Option<SourceSnapshot>,
    pub applied_closure: Option<SourceCloseReceipt>,
    pub observed_at: DateTime<Utc>,
}

/// Evidence-backed final information ASF is allowed to write to the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceClosure {
    pub work_item_id: WorkItemId,
    pub target: ClosureTarget,
    pub pull_request: Option<PullRequestEvidence>,
    pub evidence_id: EvidenceId,
    pub evidence_digest: String,
    pub final_outcome_summary: String,
    pub cost_microunits: Option<u64>,
    pub wall_time_seconds: Option<u64>,
}

impl SourceClosure {
    pub fn validate(&self) -> SourceResult<()> {
        if !self.target.production_supported_v1() {
            return Err(SourceGatewayError::InvalidRequest(
                "only pull-request source closure is supported in V1".into(),
            ));
        }
        if self.evidence_digest.trim().is_empty() || self.final_outcome_summary.trim().is_empty() {
            return Err(SourceGatewayError::InvalidRequest(
                "source closure requires evidence and a final outcome summary".into(),
            ));
        }
        let pull_request = self.pull_request.as_ref().ok_or_else(|| {
            SourceGatewayError::InvalidRequest(
                "pull-request source closure requires a pull-request reference".into(),
            )
        })?;
        if pull_request.repository.trim().is_empty()
            || pull_request.number == 0
            || pull_request.url.trim().is_empty()
            || pull_request.base_sha.trim().is_empty()
            || pull_request.head_sha.trim().is_empty()
            || !pull_request
                .required_ci_contexts
                .is_subset(&pull_request.successful_ci_contexts)
        {
            return Err(SourceGatewayError::InvalidRequest(
                "pull-request closure reference is incomplete or required CI is not successful"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Canonical logical source effect. It is immutable once placed in an outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCloseEffect {
    pub schema: String,
    pub item: SourceItemRef,
    pub expected_source_revision: String,
    pub expected_snapshot_digest: String,
    pub correlation_marker: String,
    pub closure: SourceClosure,
}

impl SourceCloseEffect {
    pub fn new(
        item: SourceItemRef,
        expected_source_revision: impl Into<String>,
        expected_snapshot_digest: impl Into<String>,
        correlation_marker: impl Into<String>,
        closure: SourceClosure,
    ) -> SourceResult<Self> {
        let effect = Self {
            schema: SOURCE_CLOSE_EFFECT_SCHEMA_V1.into(),
            item,
            expected_source_revision: expected_source_revision.into(),
            expected_snapshot_digest: expected_snapshot_digest.into(),
            correlation_marker: correlation_marker.into(),
            closure,
        };
        effect.validate()?;
        Ok(effect)
    }

    pub fn validate(&self) -> SourceResult<()> {
        if self.schema != SOURCE_CLOSE_EFFECT_SCHEMA_V1 {
            return Err(SourceGatewayError::InvalidRequest(
                "unsupported source-close effect schema".into(),
            ));
        }
        self.item.validate()?;
        if self.expected_source_revision.trim().is_empty()
            || self.expected_snapshot_digest.trim().is_empty()
            || self.correlation_marker.trim().is_empty()
        {
            return Err(SourceGatewayError::InvalidRequest(
                "source close requires expected revision, snapshot digest, and correlation marker"
                    .into(),
            ));
        }
        self.closure.validate()
    }

    pub fn digest(&self) -> SourceResult<String> {
        self.validate()?;
        let canonical = canonical_json(self)
            .map_err(|error| SourceGatewayError::InvalidRequest(error.to_string()))?;
        Ok(sha256_digest(&canonical))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseSourceRequest {
    pub schema: String,
    pub idempotency_key: String,
    pub effect_digest: String,
    pub effect: SourceCloseEffect,
    pub requested_at: DateTime<Utc>,
}

impl CloseSourceRequest {
    pub fn new(
        idempotency_key: impl Into<String>,
        effect: SourceCloseEffect,
        requested_at: DateTime<Utc>,
    ) -> SourceResult<Self> {
        let effect_digest = effect.digest()?;
        let request = Self {
            schema: CLOSE_SOURCE_REQUEST_SCHEMA_V1.into(),
            idempotency_key: idempotency_key.into(),
            effect_digest,
            effect,
            requested_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> SourceResult<()> {
        if self.schema != CLOSE_SOURCE_REQUEST_SCHEMA_V1 {
            return Err(SourceGatewayError::InvalidRequest(
                "unsupported close-source request schema".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(SourceGatewayError::InvalidRequest(
                "source-close idempotency key is required".into(),
            ));
        }
        let expected_digest = self.effect.digest()?;
        if self.effect_digest != expected_digest {
            return Err(SourceGatewayError::InvalidRequest(
                "source-close effect digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCloseDisposition {
    Applied,
    Adopted,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCloseReceipt {
    pub schema: String,
    pub item: SourceItemRef,
    pub idempotency_key: String,
    pub effect_digest: String,
    pub correlation_marker: String,
    pub disposition: SourceCloseDisposition,
    pub provider_revision: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileSourceCloseRequest {
    pub schema: String,
    pub item: SourceItemRef,
    pub idempotency_key: String,
    pub effect_digest: String,
    pub correlation_marker: String,
}

impl ReconcileSourceCloseRequest {
    #[must_use]
    pub fn from_close(request: &CloseSourceRequest) -> Self {
        Self {
            schema: RECONCILE_SOURCE_CLOSE_REQUEST_SCHEMA_V1.into(),
            item: request.effect.item.clone(),
            idempotency_key: request.idempotency_key.clone(),
            effect_digest: request.effect_digest.clone(),
            correlation_marker: request.effect.correlation_marker.clone(),
        }
    }

    pub fn validate(&self) -> SourceResult<()> {
        if self.schema != RECONCILE_SOURCE_CLOSE_REQUEST_SCHEMA_V1 {
            return Err(SourceGatewayError::InvalidRequest(
                "unsupported source-close reconciliation schema".into(),
            ));
        }
        self.item.validate()?;
        if self.idempotency_key.trim().is_empty()
            || self.effect_digest.trim().is_empty()
            || self.correlation_marker.trim().is_empty()
        {
            return Err(SourceGatewayError::InvalidRequest(
                "source-close reconciliation identity is incomplete".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "receipt")]
pub enum SourceCloseReconciliation {
    Applied(SourceCloseReceipt),
    NotObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SourceGatewayError {
    #[error("unsupported source connector contract: {detail}")]
    UnsupportedContract { detail: String },
    #[error("invalid source request: {0}")]
    InvalidRequest(String),
    #[error("invalid source cursor: {0}")]
    InvalidCursor(String),
    #[error("source item not found")]
    ItemNotFound,
    #[error("source item changed or is not mutable in its current lifecycle")]
    SourceStateConflict,
    #[error(
        "source idempotency conflict for {idempotency_key}: existing digest {existing_digest}, submitted digest {submitted_digest}"
    )]
    IdempotencyConflict {
        idempotency_key: String,
        existing_digest: String,
        submitted_digest: String,
    },
    #[error(
        "source effect outcome is ambiguous for idempotency key {idempotency_key}; reconcile digest {effect_digest} before retrying"
    )]
    AmbiguousEffect {
        idempotency_key: String,
        effect_digest: String,
    },
    #[error("source connector transport is unavailable")]
    TransportUnavailable,
    #[error("source provider rejected the operation ({code})")]
    ProviderRejected { code: String },
    #[error("source provider returned an invalid or incomplete response")]
    InvalidProviderResponse,
    #[error("source provider response exceeded the configured byte limit")]
    ResponseTooLarge,
}

pub type SourceResult<T> = Result<T, SourceGatewayError>;

/// Semantic source-system operations owned by ASF.
///
/// Implementations must process `close_source` idempotently. A transport error
/// after the provider applied a mutation must be returned as
/// [`SourceGatewayError::AmbiguousEffect`], never guessed as failure; callers
/// then use `reconcile_source_close` with the same effect identity.
#[async_trait]
pub trait SourceGateway: Send + Sync {
    async fn intake(&self, request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage>;

    async fn observe_source(
        &self,
        request: &ObserveSourceRequest,
    ) -> SourceResult<SourceObservation>;

    async fn close_source(&self, request: &CloseSourceRequest) -> SourceResult<SourceCloseReceipt>;

    async fn reconcile_source_close(
        &self,
        request: &ReconcileSourceCloseRequest,
    ) -> SourceResult<SourceCloseReconciliation>;
}
