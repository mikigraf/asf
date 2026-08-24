//! Exact client for Runmill's private ASF control socket.
//!
//! The higher-level gateway in [`super::runmill`] remains the in-process
//! semantic fake used by workflow tests. This module binds the published
//! newline-delimited JSON protocol without guessing at MCP tool names.

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Read as _,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    contracts::{RunmillSignedWorkOrderV1, SignedWorkOrder},
    crypto::{canonical_json, sha256_digest},
    security::reject_sensitive_fields,
};
use ed25519_dalek::VerifyingKey;

pub const RUNMILL_CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const RUNMILL_MAX_CONTROL_BYTES: usize = 2 * 1024 * 1024;
pub const RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA: &str = "asf.work-order-envelope/v1";
pub const RUNMILL_WORK_ORDER_SCHEMA: &str = "asf.work-order/v1";
pub const RUNMILL_RUN_EVENT_SCHEMA: &str = "asf.run-event/v1";
pub const RUNMILL_EVIDENCE_VIEW_SCHEMA: &str = "asf.evidence-view/v1";
pub const RUNMILL_HEALTH_SCHEMA: &str = "asf.health/v1";
pub const RUNMILL_CONTROL_ERROR_SCHEMA: &str = "asf.control-error/v1";
pub const RUNMILL_CANCELLATION_SCHEMA: &str = "asf.cancellation-request/v1";
pub const RUNMILL_OUTCOME_ACKNOWLEDGEMENT_SCHEMA: &str = "asf.outcome-acknowledgement/v1";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunmillControlOperation {
    Health,
    SubmitWorkOrder,
    GetRun,
    ListRunEvents,
    GetEvidence,
    RequestCancel,
    AcknowledgeOutcome,
}

impl RunmillControlOperation {
    const fn mutates(self) -> bool {
        matches!(
            self,
            Self::SubmitWorkOrder | Self::RequestCancel | Self::AcknowledgeOutcome
        )
    }
}

impl fmt::Display for RunmillControlOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Health => "health",
            Self::SubmitWorkOrder => "submit-work-order",
            Self::GetRun => "get-run",
            Self::ListRunEvents => "list-run-events",
            Self::GetEvidence => "get-evidence",
            Self::RequestCancel => "request-cancel",
            Self::AcknowledgeOutcome => "acknowledge-outcome",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguousControlFailure {
    Timeout,
    ResponseLost,
    ResponseTooLarge,
    MalformedResponse,
    TransportInterrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunmillRetryDisposition {
    Safe,
    ReconcileFirst,
    NewAttemptRequired,
    Prohibited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunmillRequiredActor {
    Asf,
    RepositoryOwner,
    PlatformOperator,
    Security,
    ProviderAdministrator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillControlFix {
    pub description: String,
    pub command: Option<String>,
}

/// Public-safe catalogued error returned by Runmill.
///
/// Narratives and commands are preserved for an authorized caller, but are
/// deliberately omitted from `Debug` and the enclosing error's `Display`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillAsfControlError {
    pub schema: String,
    pub code: String,
    pub title: String,
    pub what_happened: String,
    pub why: String,
    pub fixes: Vec<RunmillControlFix>,
    pub docs_url: String,
    pub recoverable: bool,
    pub run_id: Option<RunmillRunId>,
    pub checkpoint: Option<String>,
    pub retry_disposition: Option<RunmillRetryDisposition>,
    pub required_actor: Option<RunmillRequiredActor>,
    pub required_action: Option<String>,
    pub evidence_refs: Vec<String>,
}

impl fmt::Debug for RunmillAsfControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillAsfControlError")
            .field("schema", &self.schema)
            .field("code", &self.code)
            .field("title", &"[REDACTED]")
            .field("what_happened", &"[REDACTED]")
            .field("why", &"[REDACTED]")
            .field("fixes", &"[REDACTED]")
            .field("docs_url", &"[REDACTED]")
            .field("recoverable", &self.recoverable)
            .field("run_id", &self.run_id)
            .field("checkpoint", &self.checkpoint)
            .field("retry_disposition", &self.retry_disposition)
            .field("required_actor", &self.required_actor)
            .field("required_action", &"[REDACTED]")
            .field("evidence_refs", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RunmillAsfControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runmill ASF control error {}", self.code)
    }
}

#[derive(Debug, Error)]
pub enum RunmillControlError {
    #[error("invalid Runmill control configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("Runmill daemon registry is unavailable or invalid")]
    RegistryUnavailable,
    #[error("Runmill daemon registry failed private-file checks: {0}")]
    InsecureRegistry(&'static str),
    #[error("Runmill daemon socket failed private-socket checks: {0}")]
    InsecureSocket(&'static str),
    #[error("unsupported Runmill daemon registry protocol version {observed}")]
    UnsupportedProtocol { observed: u64 },
    #[error("invalid Runmill control request: {0}")]
    InvalidRequest(&'static str),
    #[error("current ASF SignedWorkOrder is not wire-compatible with Runmill's exact envelope")]
    IncompatibleWorkOrderContract,
    #[error("Runmill control request exceeds the 2 MiB protocol limit")]
    RequestTooLarge,
    #[error("Runmill control response exceeds the 2 MiB protocol limit")]
    ResponseTooLarge,
    #[error("timed out waiting for Runmill control")]
    Timeout,
    #[error("Runmill control response was lost")]
    ResponseLost,
    #[error("Runmill control transport is unavailable")]
    TransportUnavailable,
    #[error("Runmill returned a malformed or incompatible control response")]
    MalformedResponse,
    #[error("Runmill rejected the request without a catalogued public ASF error")]
    RemoteRejected,
    #[error("Runmill admission snapshot does not exactly bind the submitted Work Order envelope")]
    AdmissionBindingMismatch,
    #[error("{0}")]
    RemoteAsf(Box<RunmillAsfControlError>),
    #[error("Runmill {operation} outcome is ambiguous after {reason:?}")]
    AmbiguousOutcome {
        operation: RunmillControlOperation,
        reason: AmbiguousControlFailure,
    },
}

pub type RunmillControlResult<T> = Result<T, RunmillControlError>;

/// Runmill's external string run identity. It is intentionally unrelated to
/// ASF's UUID-backed domain `RunId`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunmillRunId(String);

impl RunmillRunId {
    pub fn parse(value: impl Into<String>) -> RunmillControlResult<Self> {
        let value = value.into();
        if !valid_identifier(&value, 256, true) {
            return Err(RunmillControlError::InvalidRequest(
                "Runmill run ID is malformed",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunmillRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RunmillRunId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for RunmillRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for RunmillRunId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RunmillRunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Strictly validated, already-signed Runmill envelope. The client neither
/// projects nor re-signs ASF's distinct Work Order contract.
#[derive(Clone, PartialEq)]
pub struct RunmillWorkOrderEnvelope(Value);

impl RunmillWorkOrderEnvelope {
    pub fn parse(value: Value) -> RunmillControlResult<Self> {
        validate_work_order_envelope(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn payload_digest(&self) -> RunmillControlResult<String> {
        let payload = self.payload_object()?;
        let bytes = canonical_json(payload).map_err(|_| {
            RunmillControlError::InvalidRequest("Runmill Work Order cannot be canonicalized")
        })?;
        Ok(sha256_digest(&bytes))
    }

    /// SHA-256 of the canonical exact envelope bytes, distinct from
    /// [`Self::payload_digest`], which digests only the inner payload.
    pub fn envelope_digest(&self) -> RunmillControlResult<String> {
        let bytes = canonical_json(&self.0).map_err(|_| {
            RunmillControlError::InvalidRequest(
                "Runmill Work Order envelope cannot be canonicalized",
            )
        })?;
        Ok(sha256_digest(&bytes))
    }

    /// The original payload idempotency key, exactly as signed. This is the
    /// only key that may be used to look up a possibly-lost submission; it
    /// is unrelated to ASF's own internal `runmill:submit:` effect-intent key.
    pub fn idempotency_key(&self) -> RunmillControlResult<&str> {
        self.payload_field("idempotency_key")
    }

    pub fn work_order_id(&self) -> RunmillControlResult<&str> {
        self.payload_field("work_order_id")
    }

    pub fn tenant_id(&self) -> RunmillControlResult<&str> {
        self.payload_field("tenant_id")
    }

    pub fn attempt_id(&self) -> RunmillControlResult<&str> {
        self.payload_field("attempt_id")
    }

    fn payload_object(&self) -> RunmillControlResult<&Map<String, Value>> {
        self.0
            .as_object()
            .and_then(|envelope| envelope.get("payload"))
            .and_then(Value::as_object)
            .ok_or(RunmillControlError::InvalidRequest(
                "Runmill Work Order payload is missing",
            ))
    }

    fn payload_field(&self, field: &'static str) -> RunmillControlResult<&str> {
        self.payload_object()?
            .get(field)
            .and_then(Value::as_str)
            .ok_or(RunmillControlError::InvalidRequest(
                "Runmill Work Order payload field is missing",
            ))
    }
}

impl fmt::Debug for RunmillWorkOrderEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RunmillWorkOrderEnvelope")
            .field(&"[REDACTED SIGNED ENVELOPE]")
            .finish()
    }
}

impl Serialize for RunmillWorkOrderEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Compatibility guard for the adjacent projects' currently divergent Work
/// Order contracts. Success means strict Runmill parsing rejected the exact
/// serialization; it never attempts a lossy projection or replacement signature.
pub fn assert_current_signed_work_order_is_incompatible(
    work_order: &SignedWorkOrder,
) -> RunmillControlResult<()> {
    let serialized = serde_json::to_value(work_order)
        .map_err(|_| RunmillControlError::IncompatibleWorkOrderContract)?;
    if RunmillWorkOrderEnvelope::parse(serialized).is_err() {
        Ok(())
    } else {
        Err(RunmillControlError::IncompatibleWorkOrderContract)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillSubmissionDisposition {
    Accepted,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillSubmitWorkOrderResult {
    pub run_id: RunmillRunId,
    pub disposition: RunmillSubmissionDisposition,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunmillRunPhase {
    Received,
    Admitted,
    RepositoryLeased,
    IdentityReady,
    WorkspaceReady,
    TaskPacketReady,
    Implementing,
    CandidateReady,
    LocalVerify,
    LocalReview,
    Fixing,
    DeliveryReady,
    Pushed,
    PrOpen,
    CiWait,
    PrReview,
    PrDelivered,
    MergeQueueWait,
    MergeReady,
    Merged,
    EvidenceFinalized,
    Completed,
    CancelRequested,
    Cancelling,
    WaitingApproval,
    NeedsSpec,
    BlockedExternal,
    BudgetExhausted,
    Refused,
    Quarantined,
    Cancelled,
    Failed,
}

impl RunmillRunPhase {
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Cancelled
                | Self::Failed
                | Self::Refused
                | Self::Quarantined
                | Self::BudgetExhausted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillRunRow {
    pub run_id: RunmillRunId,
    pub issue_id: String,
    pub repo: String,
    pub provider: String,
    pub state: RunmillRunPhase,
    pub state_version: u64,
    pub attempt: u64,
    pub base_commit: Option<String>,
    pub candidate_sha: Option<String>,
    pub branch: Option<String>,
    pub mode: String,
    pub work_order_id: String,
    pub attempt_id: String,
    pub generation: u64,
    pub owner_id: Option<String>,
    pub heartbeat_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillAdmissionSnapshot {
    pub idempotency_key: String,
    pub work_order_id: String,
    pub attempt_id: String,
    pub tenant_id: String,
    pub payload_digest: String,
    pub envelope_digest: String,
    pub effective_policy_digest: String,
    pub signature_key_id: String,
    pub signature_algorithm: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillRunSnapshot {
    pub run: RunmillRunRow,
    pub admission: RunmillAdmissionSnapshot,
    pub latest_sequence: u64,
}

/// A strictly validated successful control read with durable wire provenance.
///
/// `response_wire` is the complete response received from the private control
/// socket, including its required trailing NDJSON newline. `data` is the
/// exact JSON value parsed from that response's `data` member before typed
/// deserialization. This type is only constructed after both raw-shape and
/// typed semantic validation have succeeded.
#[derive(Clone, PartialEq)]
pub struct RunmillValidatedRead<T> {
    value: T,
    response_wire: Vec<u8>,
    data: Value,
}

impl<T> RunmillValidatedRead<T> {
    /// Returns the strictly validated typed response.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Returns the complete validated NDJSON response, including its newline.
    #[must_use]
    pub fn response_wire(&self) -> &[u8] {
        &self.response_wire
    }

    /// Returns the exact parsed value from the success envelope's `data` member.
    #[must_use]
    pub const fn data(&self) -> &Value {
        &self.data
    }

    /// Consumes the proof and returns its validated typed value, exact wire,
    /// and parsed success data.
    #[must_use]
    pub fn into_parts(self) -> (T, Vec<u8>, Value) {
        (self.value, self.response_wire, self.data)
    }
}

impl<T> fmt::Debug for RunmillValidatedRead<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillValidatedRead")
            .field("value", &self.value)
            .field("response_wire", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillRunEvent {
    pub schema: String,
    pub event_id: String,
    pub run_id: RunmillRunId,
    pub work_order_id: String,
    pub attempt_id: String,
    pub seq: u64,
    pub occurred_at: DateTime<Utc>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub phase: RunmillRunPhase,
    pub payload: Map<String, Value>,
    pub policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillRunCursorSnapshot {
    pub run: RunmillRunRow,
    pub latest_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillEventPage {
    pub events: Vec<RunmillRunEvent>,
    pub next_cursor: u64,
    pub has_more: bool,
    pub gap: bool,
    pub compacted_through: Option<u64>,
    pub snapshot: RunmillRunCursorSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillEvidenceStatus {
    Current,
    Stopped,
    Finalizing,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillRetentionClass {
    Portable,
    Protected,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillArtifactReference {
    pub artifact_id: String,
    pub kind: String,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
    pub retention_class: RunmillRetentionClass,
    pub location_ref: String,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillEvidenceView {
    pub schema: String,
    pub run_id: RunmillRunId,
    pub work_order_id: String,
    pub attempt_id: String,
    pub phase: RunmillRunPhase,
    pub candidate_sha: Option<String>,
    pub policy_digest: String,
    pub latest_sequence: u64,
    pub status: RunmillEvidenceStatus,
    pub complete: bool,
    pub bundle_digest: Option<String>,
    pub artifacts: Vec<RunmillArtifactReference>,
    pub latest_event: Option<RunmillRunEvent>,
    pub signed_bundle: Option<Value>,
    pub terminal_bundle_digest: Option<String>,
    pub signed_terminal_bundle: Option<Value>,
}

impl fmt::Debug for RunmillEvidenceView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillEvidenceView")
            .field("schema", &self.schema)
            .field("run_id", &self.run_id)
            .field("work_order_id", &self.work_order_id)
            .field("attempt_id", &self.attempt_id)
            .field("phase", &self.phase)
            .field("candidate_sha", &self.candidate_sha)
            .field("policy_digest", &self.policy_digest)
            .field("latest_sequence", &self.latest_sequence)
            .field("status", &self.status)
            .field("complete", &self.complete)
            .field("bundle_digest", &self.bundle_digest)
            .field("artifacts", &self.artifacts)
            .field("latest_event", &self.latest_event)
            .field("signed_bundle", &"[REDACTED SIGNED EVIDENCE]")
            .field("terminal_bundle_digest", &self.terminal_bundle_digest)
            .field(
                "signed_terminal_bundle",
                &"[REDACTED SIGNED TERMINAL EVIDENCE]",
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillCancellationMode {
    Graceful,
    Forced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCancellationRequester {
    pub subject: String,
    pub authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillCancellationRequest {
    pub schema: String,
    pub request_id: String,
    pub run_id: RunmillRunId,
    pub requester: RunmillCancellationRequester,
    pub reason: String,
    pub mode: RunmillCancellationMode,
    pub grace_seconds: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunmillCancellationDisposition {
    Requested,
    Existing,
    AlreadyTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillCancellationResult {
    pub request_id: String,
    pub run_id: RunmillRunId,
    pub disposition: RunmillCancellationDisposition,
    pub state: RunmillRunPhase,
    pub generation: u64,
    pub request_digest: String,
    pub reconciliation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillAcknowledgedBy {
    pub subject: String,
    pub authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillOutcomeAcknowledgement {
    pub schema: String,
    pub acknowledgement_id: String,
    pub run_id: RunmillRunId,
    pub bundle_digest: String,
    pub acknowledged_by: RunmillAcknowledgedBy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillAcknowledgementDisposition {
    Recorded,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunmillOutcomeAcknowledgementResult {
    pub acknowledgement_id: String,
    pub run_id: RunmillRunId,
    pub bundle_digest: String,
    pub disposition: RunmillAcknowledgementDisposition,
    pub acknowledged_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunmillHealthStatus {
    Ready,
    Degraded,
    Refusing,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillHealthComponent {
    pub status: RunmillHealthStatus,
    pub observed_at: Option<DateTime<Utc>>,
    pub age_ms: Option<u64>,
    pub reasons: Vec<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillHealthComponents {
    pub service: RunmillHealthComponent,
    pub database: RunmillHealthComponent,
    pub worker: RunmillHealthComponent,
    pub sandbox: RunmillHealthComponent,
    pub ctxlane: RunmillHealthComponent,
    pub github: RunmillHealthComponent,
    pub mcp: RunmillHealthComponent,
    pub backlog: RunmillHealthComponent,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillHealthReport {
    pub schema: String,
    pub mode: String,
    pub checked_at: DateTime<Utc>,
    pub probe_duration_ms: u64,
    pub status: RunmillHealthStatus,
    pub ready: bool,
    pub components: RunmillHealthComponents,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DaemonRegistry {
    protocol_version: u64,
    pid: u32,
    socket_path: String,
    started_at: DateTime<Utc>,
    repo_root: String,
    config_path: String,
}

#[derive(Clone)]
pub struct RunmillControlClient {
    registry_path: PathBuf,
    timeout: Duration,
    expected_uid: u32,
}

impl fmt::Debug for RunmillControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillControlClient")
            .field("registry_path", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("expected_uid", &"[REDACTED]")
            .finish()
    }
}

impl RunmillControlClient {
    pub fn new(registry_path: impl Into<PathBuf>, timeout: Duration) -> RunmillControlResult<Self> {
        let registry_path = registry_path.into();
        if !normalized_absolute_path(&registry_path) {
            return Err(RunmillControlError::InvalidConfiguration(
                "registry path must be normalized and absolute",
            ));
        }
        if timeout.is_zero() || timeout > Duration::from_mins(5) {
            return Err(RunmillControlError::InvalidConfiguration(
                "timeout must be within 1ns..=300s",
            ));
        }
        Ok(Self {
            registry_path,
            timeout,
            expected_uid: effective_uid()?,
        })
    }

    pub async fn health(&self) -> RunmillControlResult<RunmillHealthReport> {
        self.call(
            RunmillControlOperation::Health,
            json!({"type": "asf.health"}),
        )
        .await
    }

    pub async fn submit_work_order(
        &self,
        envelope: &RunmillWorkOrderEnvelope,
    ) -> RunmillControlResult<RunmillSubmitWorkOrderResult> {
        let result: RunmillSubmitWorkOrderResult = self
            .call(
                RunmillControlOperation::SubmitWorkOrder,
                json!({"type": "asf.submit_work_order", "envelope": envelope}),
            )
            .await?;
        if result.payload_digest != envelope.payload_digest()? {
            return Err(RunmillControlError::AmbiguousOutcome {
                operation: RunmillControlOperation::SubmitWorkOrder,
                reason: AmbiguousControlFailure::MalformedResponse,
            });
        }
        Ok(result)
    }

    pub async fn get_run(&self, run_id: &RunmillRunId) -> RunmillControlResult<RunmillRunSnapshot> {
        self.get_run_with_provenance(run_id)
            .await
            .map(|read| read.value)
    }

    /// Reads a run snapshot and retains the exact validated response for a
    /// caller that needs to persist observation provenance.
    pub async fn get_run_with_provenance(
        &self,
        run_id: &RunmillRunId,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillRunSnapshot>> {
        let read: RunmillValidatedRead<RunmillRunSnapshot> = self
            .call_validated(
                RunmillControlOperation::GetRun,
                json!({"type": "asf.get_run", "runId": run_id}),
            )
            .await?;
        if &read.value.run.run_id != run_id {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(read)
    }

    /// Loose observation-only lookup by idempotency key.
    ///
    /// This proves only that *some* run is bound to `key`; it does not prove
    /// that run's admission matches any particular Work Order, tenant,
    /// attempt, or payload/envelope digest. It is **not** sufficient to
    /// recover a possibly-lost successful submission and must never be used
    /// to decide whether a resend is safe. Callers that need to adopt an
    /// existing run after response loss must use [`Self::reconcile_submission`],
    /// which proves the exact admission bindings before returning.
    pub async fn get_run_by_idempotency_key(
        &self,
        key: &str,
    ) -> RunmillControlResult<RunmillRunSnapshot> {
        self.get_run_by_idempotency_key_with_provenance(key)
            .await
            .map(|read| read.value)
    }

    /// Loose observation-only lookup by idempotency key, retaining
    /// provenance. See [`Self::get_run_by_idempotency_key`] for why this is
    /// not sufficient to authorize recovery on its own.
    pub async fn get_run_by_idempotency_key_with_provenance(
        &self,
        key: &str,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillRunSnapshot>> {
        if !valid_idempotency_key(key) {
            return Err(RunmillControlError::InvalidRequest(
                "idempotency key is malformed",
            ));
        }
        let read: RunmillValidatedRead<RunmillRunSnapshot> = self
            .call_validated(
                RunmillControlOperation::GetRun,
                json!({"type": "asf.get_run", "idempotencyKey": key}),
            )
            .await?;
        if read.value.run.run_id.as_str().is_empty() {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(read)
    }

    /// Loose observation-only recovery of a possibly-lost successful submission.
    ///
    /// Proves exact admission bindings, never by generating a new attempt, but does
    /// NOT verify the Work Order envelope's cryptographic signature or binding against
    /// a specific signing key. This is sufficient for observation and reconciliation
    /// of a loose idempotency key lookup, but is not authoritative for recovering
    /// a possibly-lost submission.
    ///
    /// For authoritative recovery that cryptographically verifies the exact envelope
    /// before any network request, use [`Self::reconcile_verified_submission`] instead.
    ///
    /// Looks up the run by the envelope's own payload idempotency key, then
    /// proves every binding below before returning it:
    ///
    /// - `admission.idempotency_key` equals the envelope payload's key;
    /// - `admission.work_order_id`, `.tenant_id`, `.attempt_id` equal the
    ///   envelope payload's values;
    /// - `admission.payload_digest` equals [`RunmillWorkOrderEnvelope::payload_digest`];
    /// - `admission.envelope_digest` equals [`RunmillWorkOrderEnvelope::envelope_digest`];
    /// - `run.work_order_id` and `run.attempt_id` equal the admission values
    ///   (already enforced by [`RunmillRunSnapshot`]'s response validation).
    ///
    /// A missing run, transport failure, or any binding mismatch is never
    /// treated as permission to resubmit: the caller must observe again or
    /// escalate, not attempt a new submission from this result alone.
    pub async fn reconcile_submission(
        &self,
        envelope: &RunmillWorkOrderEnvelope,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillRunSnapshot>> {
        let idempotency_key = envelope.idempotency_key()?;
        let work_order_id = envelope.work_order_id()?;
        let tenant_id = envelope.tenant_id()?;
        let attempt_id = envelope.attempt_id()?;
        let payload_digest = envelope.payload_digest()?;
        let envelope_digest = envelope.envelope_digest()?;

        let read = self
            .get_run_by_idempotency_key_with_provenance(idempotency_key)
            .await?;
        let admission = &read.value.admission;
        if admission.idempotency_key != idempotency_key
            || admission.work_order_id != work_order_id
            || admission.tenant_id != tenant_id
            || admission.attempt_id != attempt_id
            || admission.payload_digest != payload_digest
            || admission.envelope_digest != envelope_digest
        {
            return Err(RunmillControlError::AdmissionBindingMismatch);
        }
        Ok(read)
    }

    /// Authoritative recovery of a possibly-lost successful submission by verifying
    /// the Work Order envelope's cryptographic signature before any network request.
    ///
    /// Requires that the envelope's key ID exactly matches the caller's configured
    /// trusted key ID (obtained from key resolver / configuration). This binding is
    /// checked before verification or any network operation.
    ///
    /// Verifies the envelope's integrity against the provided signing key, then
    /// deserializes it to a wire-compatible form and reuses [`Self::reconcile_submission`]
    /// for idempotency key-based recovery and admission binding verification.
    ///
    /// Additionally rejects the result with [`RunmillControlError::AdmissionBindingMismatch`]
    /// unless the returned admission's binding fields exactly match the envelope:
    /// - `admission.effective_policy_digest` equals `envelope.payload.policy_digest`;
    /// - `admission.signature_key_id` equals `envelope.key_id`;
    /// - `admission.signature_algorithm` equals `envelope.algorithm`.
    ///
    /// The key ID mismatch or verification failure on the envelope is translated to
    /// [`RunmillControlError::InvalidRequest`] and occurs before any network operation.
    pub async fn reconcile_verified_submission(
        &self,
        trusted_key_id: &str,
        envelope: &RunmillSignedWorkOrderV1,
        verifying_key: &VerifyingKey,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillRunSnapshot>> {
        if envelope.key_id != trusted_key_id {
            return Err(RunmillControlError::InvalidRequest(
                "Work Order envelope key ID does not match trusted key ID",
            ));
        }

        envelope.verify_integrity(verifying_key).map_err(|_| {
            RunmillControlError::InvalidRequest("Work Order envelope verification failed")
        })?;

        let serialized = serde_json::to_value(envelope).map_err(|_| {
            RunmillControlError::InvalidRequest("Work Order envelope cannot be serialized")
        })?;
        let work_order_envelope = RunmillWorkOrderEnvelope::parse(serialized)?;

        let read = self.reconcile_submission(&work_order_envelope).await?;
        let admission = &read.value.admission;

        if admission.effective_policy_digest != envelope.payload.policy_digest
            || admission.signature_key_id != envelope.key_id
            || admission.signature_algorithm != envelope.algorithm
        {
            return Err(RunmillControlError::AdmissionBindingMismatch);
        }

        Ok(read)
    }

    pub async fn list_run_events(
        &self,
        run_id: &RunmillRunId,
        after: u64,
        limit: u16,
    ) -> RunmillControlResult<RunmillEventPage> {
        self.list_run_events_with_provenance(run_id, after, limit)
            .await
            .map(|read| read.value)
    }

    /// Lists run events and retains the exact validated response for a caller
    /// that needs to persist observation provenance.
    pub async fn list_run_events_with_provenance(
        &self,
        run_id: &RunmillRunId,
        after: u64,
        limit: u16,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillEventPage>> {
        if after > MAX_SAFE_INTEGER || !(1..=1_000).contains(&limit) {
            return Err(RunmillControlError::InvalidRequest(
                "event cursor or page limit is outside the protocol range",
            ));
        }
        let read: RunmillValidatedRead<RunmillEventPage> = self
            .call_validated(
                RunmillControlOperation::ListRunEvents,
                json!({
                    "type": "asf.list_run_events",
                    "runId": run_id,
                    "after": after,
                    "limit": limit,
                }),
            )
            .await?;
        read.value.validate_for_request(run_id, after, limit)?;
        Ok(read)
    }

    pub async fn get_evidence(
        &self,
        run_id: &RunmillRunId,
    ) -> RunmillControlResult<RunmillEvidenceView> {
        self.get_evidence_with_provenance(run_id)
            .await
            .map(|read| read.value)
    }

    /// Reads an evidence view and retains the exact validated response for a
    /// caller that needs to persist observation provenance.
    pub async fn get_evidence_with_provenance(
        &self,
        run_id: &RunmillRunId,
    ) -> RunmillControlResult<RunmillValidatedRead<RunmillEvidenceView>> {
        let read: RunmillValidatedRead<RunmillEvidenceView> = self
            .call_validated(
                RunmillControlOperation::GetEvidence,
                json!({"type": "asf.get_evidence", "runId": run_id}),
            )
            .await?;
        if &read.value.run_id != run_id {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(read)
    }

    pub async fn request_cancel(
        &self,
        request: &RunmillCancellationRequest,
    ) -> RunmillControlResult<RunmillCancellationResult> {
        request.validate()?;
        let expected_request_digest = request.digest()?;
        let result: RunmillCancellationResult = self
            .call(
                RunmillControlOperation::RequestCancel,
                json!({"type": "asf.request_cancel", "request": request}),
            )
            .await?;
        if result.run_id != request.run_id
            || result.request_id != request.request_id
            || result.request_digest != expected_request_digest
        {
            return Err(RunmillControlError::AmbiguousOutcome {
                operation: RunmillControlOperation::RequestCancel,
                reason: AmbiguousControlFailure::MalformedResponse,
            });
        }
        Ok(result)
    }

    pub async fn acknowledge_outcome(
        &self,
        acknowledgement: &RunmillOutcomeAcknowledgement,
    ) -> RunmillControlResult<RunmillOutcomeAcknowledgementResult> {
        acknowledgement.validate()?;
        let result: RunmillOutcomeAcknowledgementResult = self
            .call(
                RunmillControlOperation::AcknowledgeOutcome,
                json!({
                    "type": "asf.acknowledge_outcome",
                    "acknowledgement": acknowledgement,
                }),
            )
            .await?;
        if result.run_id != acknowledgement.run_id
            || result.acknowledgement_id != acknowledgement.acknowledgement_id
            || result.bundle_digest != acknowledgement.bundle_digest
        {
            return Err(RunmillControlError::AmbiguousOutcome {
                operation: RunmillControlOperation::AcknowledgeOutcome,
                reason: AmbiguousControlFailure::MalformedResponse,
            });
        }
        Ok(result)
    }

    async fn call<T>(
        &self,
        operation: RunmillControlOperation,
        request: Value,
    ) -> RunmillControlResult<T>
    where
        T: DeserializeOwned + ExactResponse,
    {
        self.call_validated(operation, request)
            .await
            .map(|read| read.value)
    }

    async fn call_validated<T>(
        &self,
        operation: RunmillControlOperation,
        request: Value,
    ) -> RunmillControlResult<RunmillValidatedRead<T>>
    where
        T: DeserializeOwned + ExactResponse,
    {
        reject_sensitive_fields(&request).map_err(|_| {
            RunmillControlError::InvalidRequest("control request contains credential-shaped data")
        })?;
        let mut request_line = serde_json::to_vec(&request)
            .map_err(|_| RunmillControlError::InvalidRequest("request cannot be encoded"))?;
        request_line.push(b'\n');
        if request_line.len() > RUNMILL_MAX_CONTROL_BYTES {
            return Err(RunmillControlError::RequestTooLarge);
        }
        let registry = self.read_registry()?;
        let socket_identity = self.validate_socket(&registry)?;
        let mut stream = timeout(self.timeout, UnixStream::connect(&registry.socket_path))
            .await
            .map_err(|_| RunmillControlError::Timeout)?
            .map_err(|_| RunmillControlError::TransportUnavailable)?;
        Self::validate_connected_socket(&registry, &socket_identity)?;

        let wire = timeout(self.timeout, async {
            stream
                .write_all(&request_line)
                .await
                .map_err(|_| WireFailure::TransportInterrupted)?;
            stream
                .shutdown()
                .await
                .map_err(|_| WireFailure::TransportInterrupted)?;
            let mut response = Vec::new();
            let mut chunk = [0_u8; 8 * 1024];
            loop {
                let read = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|_| WireFailure::TransportInterrupted)?;
                if read == 0 {
                    break;
                }
                if response.len().saturating_add(read) > RUNMILL_MAX_CONTROL_BYTES {
                    return Err(WireFailure::ResponseTooLarge);
                }
                response.extend_from_slice(&chunk[..read]);
            }
            if response.is_empty() {
                return Err(WireFailure::ResponseLost);
            }
            Ok(response)
        })
        .await
        .map_err(|_| Self::wire_error(operation, WireFailure::Timeout))?
        .map_err(|failure| Self::wire_error(operation, failure))?;

        let data = match parse_control_response(&wire) {
            Ok(data) => data,
            Err(ControlResponseFailure::Remote(error)) => return Err(error),
            Err(ControlResponseFailure::Malformed) => {
                return Err(Self::wire_error(operation, WireFailure::MalformedResponse));
            }
        };
        T::validate_raw(&data)
            .map_err(|_| Self::wire_error(operation, WireFailure::MalformedResponse))?;
        let value: T = serde_json::from_value(data.clone())
            .map_err(|_| Self::wire_error(operation, WireFailure::MalformedResponse))?;
        value
            .validate()
            .map_err(|_| Self::wire_error(operation, WireFailure::MalformedResponse))?;
        Ok(RunmillValidatedRead {
            value,
            response_wire: wire,
            data,
        })
    }

    fn wire_error(operation: RunmillControlOperation, failure: WireFailure) -> RunmillControlError {
        let reason = match failure {
            WireFailure::Timeout => AmbiguousControlFailure::Timeout,
            WireFailure::ResponseLost => AmbiguousControlFailure::ResponseLost,
            WireFailure::ResponseTooLarge => AmbiguousControlFailure::ResponseTooLarge,
            WireFailure::MalformedResponse => AmbiguousControlFailure::MalformedResponse,
            WireFailure::TransportInterrupted => AmbiguousControlFailure::TransportInterrupted,
        };
        if operation.mutates() {
            return RunmillControlError::AmbiguousOutcome { operation, reason };
        }
        match failure {
            WireFailure::Timeout => RunmillControlError::Timeout,
            WireFailure::ResponseLost => RunmillControlError::ResponseLost,
            WireFailure::ResponseTooLarge => RunmillControlError::ResponseTooLarge,
            WireFailure::MalformedResponse => RunmillControlError::MalformedResponse,
            WireFailure::TransportInterrupted => RunmillControlError::TransportUnavailable,
        }
    }

    fn read_registry(&self) -> RunmillControlResult<DaemonRegistry> {
        let parent = self
            .registry_path
            .parent()
            .ok_or(RunmillControlError::InsecureRegistry(
                "registry has no runtime directory",
            ))?;
        validate_directory(parent, self.expected_uid)?;
        let before = fs::symlink_metadata(&self.registry_path)
            .map_err(|_| RunmillControlError::RegistryUnavailable)?;
        validate_private_file(&before, self.expected_uid)?;
        if before.len() > RUNMILL_MAX_CONTROL_BYTES as u64 {
            return Err(RunmillControlError::RegistryUnavailable);
        }
        let file = File::open(&self.registry_path)
            .map_err(|_| RunmillControlError::RegistryUnavailable)?;
        let opened = file
            .metadata()
            .map_err(|_| RunmillControlError::RegistryUnavailable)?;
        if !same_file(&before, &opened) {
            return Err(RunmillControlError::InsecureRegistry(
                "registry changed while opening",
            ));
        }
        let mut bytes = Vec::new();
        file.take((RUNMILL_MAX_CONTROL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RunmillControlError::RegistryUnavailable)?;
        if bytes.len() > RUNMILL_MAX_CONTROL_BYTES {
            return Err(RunmillControlError::RegistryUnavailable);
        }
        let registry: DaemonRegistry =
            serde_json::from_slice(&bytes).map_err(|_| RunmillControlError::RegistryUnavailable)?;
        if registry.protocol_version != u64::from(RUNMILL_CONTROL_PROTOCOL_VERSION) {
            return Err(RunmillControlError::UnsupportedProtocol {
                observed: registry.protocol_version,
            });
        }
        if registry.pid == 0
            || !valid_public_string(&registry.repo_root, 4_096)
            || !valid_public_string(&registry.config_path, 4_096)
        {
            return Err(RunmillControlError::RegistryUnavailable);
        }
        let socket_path = Path::new(&registry.socket_path);
        if !normalized_absolute_path(socket_path)
            || socket_path.parent() != Some(parent)
            || !valid_public_string(&registry.socket_path, 4_096)
        {
            return Err(RunmillControlError::InsecureRegistry(
                "socket path is outside the private runtime directory",
            ));
        }
        let _ = registry.started_at;
        Ok(registry)
    }

    fn validate_socket(&self, registry: &DaemonRegistry) -> RunmillControlResult<FileIdentity> {
        let metadata = fs::symlink_metadata(&registry.socket_path)
            .map_err(|_| RunmillControlError::TransportUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(RunmillControlError::InsecureSocket(
                "socket path is a symlink or not a Unix socket",
            ));
        }
        if metadata.mode() & 0o777 != PRIVATE_FILE_MODE || metadata.uid() != self.expected_uid {
            return Err(RunmillControlError::InsecureSocket(
                "socket mode or owner is not private",
            ));
        }
        Ok(FileIdentity::from_metadata(&metadata))
    }

    fn validate_connected_socket(
        registry: &DaemonRegistry,
        expected: &FileIdentity,
    ) -> RunmillControlResult<()> {
        let metadata = fs::symlink_metadata(&registry.socket_path).map_err(|_| {
            RunmillControlError::InsecureSocket("socket disappeared while connecting")
        })?;
        if FileIdentity::from_metadata(&metadata) != *expected
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
        {
            return Err(RunmillControlError::InsecureSocket(
                "socket changed while connecting",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum WireFailure {
    Timeout,
    ResponseLost,
    ResponseTooLarge,
    MalformedResponse,
    TransportInterrupted,
}

enum ControlResponseFailure {
    Remote(RunmillControlError),
    Malformed,
}

fn parse_control_response(bytes: &[u8]) -> Result<Value, ControlResponseFailure> {
    if bytes.last() != Some(&b'\n') || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err(ControlResponseFailure::Malformed);
    }
    let value: Value = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| ControlResponseFailure::Malformed)?;
    let object = value.as_object().ok_or(ControlResponseFailure::Malformed)?;
    match object.get("ok").and_then(Value::as_bool) {
        Some(true) if exact_keys(object, &["ok", "data"]) => object
            .get("data")
            .cloned()
            .ok_or(ControlResponseFailure::Malformed),
        Some(false)
            if exact_keys(object, &["ok", "error"])
                || exact_keys(object, &["ok", "error", "asfError"]) =>
        {
            if !object.get("error").is_some_and(Value::is_string) {
                return Err(ControlResponseFailure::Malformed);
            }
            let Some(asf_error) = object.get("asfError") else {
                return Err(ControlResponseFailure::Remote(
                    RunmillControlError::RemoteRejected,
                ));
            };
            reject_sensitive_fields(asf_error).map_err(|_| ControlResponseFailure::Malformed)?;
            let Some(error_object) = asf_error.as_object() else {
                return Err(ControlResponseFailure::Malformed);
            };
            if !exact_keys(
                error_object,
                &[
                    "schema",
                    "code",
                    "title",
                    "what_happened",
                    "why",
                    "fixes",
                    "docs_url",
                    "recoverable",
                    "run_id",
                    "checkpoint",
                    "retry_disposition",
                    "required_actor",
                    "required_action",
                    "evidence_refs",
                ],
            ) {
                return Err(ControlResponseFailure::Malformed);
            }
            let error: RunmillAsfControlError = serde_json::from_value(asf_error.clone())
                .map_err(|_| ControlResponseFailure::Malformed)?;
            error
                .validate()
                .map_err(|_| ControlResponseFailure::Malformed)?;
            Err(ControlResponseFailure::Remote(
                RunmillControlError::RemoteAsf(Box::new(error)),
            ))
        }
        _ => Err(ControlResponseFailure::Malformed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        }
    }
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    FileIdentity::from_metadata(left) == FileIdentity::from_metadata(right)
}

fn validate_directory(path: &Path, expected_uid: u32) -> RunmillControlResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RunmillControlError::RegistryUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        || metadata.uid() != expected_uid
    {
        return Err(RunmillControlError::InsecureRegistry(
            "runtime directory mode, type, or owner is not private",
        ));
    }
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata, expected_uid: u32) -> RunmillControlResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunmillControlError::InsecureRegistry(
            "registry is a symlink or not a regular file",
        ));
    }
    if metadata.mode() & 0o777 != PRIVATE_FILE_MODE || metadata.uid() != expected_uid {
        return Err(RunmillControlError::InsecureRegistry(
            "registry mode or owner is not private",
        ));
    }
    Ok(())
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

struct UidProbe(PathBuf);

impl Drop for UidProbe {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn effective_uid() -> RunmillControlResult<u32> {
    let path = std::env::temp_dir().join(format!(
        ".asf-runmill-uid-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let probe = UidProbe(path.clone());
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&path)
        .map_err(|_| {
            RunmillControlError::InvalidConfiguration("cannot determine effective Unix user")
        })?;
    let metadata = file.metadata().map_err(|_| {
        RunmillControlError::InvalidConfiguration("cannot determine effective Unix user")
    })?;
    drop(file);
    drop(probe);
    Ok(metadata.uid())
}

trait ExactResponse {
    fn validate_raw(_value: &Value) -> RunmillControlResult<()> {
        Ok(())
    }

    fn validate(&self) -> RunmillControlResult<()>;
}

impl ExactResponse for RunmillSubmitWorkOrderResult {
    fn validate(&self) -> RunmillControlResult<()> {
        require_digest(&self.payload_digest)
    }
}

impl ExactResponse for RunmillRunSnapshot {
    fn validate_raw(value: &Value) -> RunmillControlResult<()> {
        let snapshot = require_response_object(value, &["run", "admission", "latestSequence"])?;
        validate_run_row_raw(
            snapshot
                .get("run")
                .ok_or(RunmillControlError::MalformedResponse)?,
        )?;
        require_response_object(
            snapshot
                .get("admission")
                .ok_or(RunmillControlError::MalformedResponse)?,
            &[
                "idempotencyKey",
                "workOrderId",
                "attemptId",
                "tenantId",
                "payloadDigest",
                "envelopeDigest",
                "effectivePolicyDigest",
                "signatureKeyId",
                "signatureAlgorithm",
                "acceptedAt",
            ],
        )?;
        Ok(())
    }

    fn validate(&self) -> RunmillControlResult<()> {
        self.run.validate()?;
        self.admission.validate()?;
        if self.latest_sequence == 0
            || self.latest_sequence > MAX_SAFE_INTEGER
            || self.latest_sequence != self.run.state_version
            || self.run.work_order_id != self.admission.work_order_id
            || self.run.attempt_id != self.admission.attempt_id
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

impl RunmillRunSnapshot {
    /// Re-applies the exact raw-shape and typed response contract before a
    /// control read is accepted as durable provenance outside this adapter.
    pub(crate) fn validate_provenance_data(value: &Value) -> RunmillControlResult<Self> {
        <Self as ExactResponse>::validate_raw(value)?;
        let snapshot: Self = serde_json::from_value(value.clone())
            .map_err(|_| RunmillControlError::MalformedResponse)?;
        <Self as ExactResponse>::validate(&snapshot)?;
        Ok(snapshot)
    }
}

impl ExactResponse for RunmillEventPage {
    fn validate_raw(value: &Value) -> RunmillControlResult<()> {
        let page = require_response_object(
            value,
            &[
                "events",
                "nextCursor",
                "hasMore",
                "gap",
                "compactedThrough",
                "snapshot",
            ],
        )?;
        let snapshot = require_response_object(
            page.get("snapshot")
                .ok_or(RunmillControlError::MalformedResponse)?,
            &["run", "latestSequence"],
        )?;
        validate_run_row_raw(
            snapshot
                .get("run")
                .ok_or(RunmillControlError::MalformedResponse)?,
        )?;
        let events = page
            .get("events")
            .and_then(Value::as_array)
            .ok_or(RunmillControlError::MalformedResponse)?;
        for event in events {
            validate_event_raw(event)?;
        }
        Ok(())
    }

    fn validate(&self) -> RunmillControlResult<()> {
        self.snapshot.run.validate()?;
        if self.snapshot.latest_sequence == 0
            || self.snapshot.latest_sequence > MAX_SAFE_INTEGER
            || self.snapshot.latest_sequence != self.snapshot.run.state_version
            || self.next_cursor > MAX_SAFE_INTEGER
            || self.gap != self.compacted_through.is_some()
            || self
                .compacted_through
                .is_some_and(|sequence| sequence > self.snapshot.latest_sequence)
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        for event in &self.events {
            event.validate()?;
            if event.run_id != self.snapshot.run.run_id
                || event.work_order_id != self.snapshot.run.work_order_id
                || event.attempt_id != self.snapshot.run.attempt_id
                || event.seq > self.snapshot.latest_sequence
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        if !self.event_sequences_are_contiguous() {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

impl RunmillEventPage {
    fn event_sequences_are_contiguous(&self) -> bool {
        self.events
            .windows(2)
            .all(|pair| pair[0].seq.checked_add(1) == Some(pair[1].seq))
    }

    /// Re-applies the exact raw-shape and typed response contract before a
    /// control page is accepted as durable provenance outside this adapter.
    pub(crate) fn validate_provenance_data(value: &Value) -> RunmillControlResult<Self> {
        <Self as ExactResponse>::validate_raw(value)?;
        let page: Self = serde_json::from_value(value.clone())
            .map_err(|_| RunmillControlError::MalformedResponse)?;
        <Self as ExactResponse>::validate(&page)?;
        Ok(page)
    }

    /// Re-prove that a retained page is the exact response to the named
    /// cursor request. This is used after durable deserialization so test
    /// seams and replayed provenance cannot bypass request-relative cursor
    /// checks performed by the live transport.
    pub(crate) fn validate_provenance_request(
        &self,
        run_id: &RunmillRunId,
        after: u64,
        limit: u16,
    ) -> RunmillControlResult<()> {
        self.validate_for_request(run_id, after, limit)
    }

    fn validate_for_request(
        &self,
        run_id: &RunmillRunId,
        after: u64,
        limit: u16,
    ) -> RunmillControlResult<()> {
        if &self.snapshot.run.run_id != run_id
            || self.events.len() > usize::from(limit)
            || !self.event_sequences_are_contiguous()
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        let latest = self.snapshot.latest_sequence;
        if self.gap {
            let compacted = self
                .compacted_through
                .ok_or(RunmillControlError::MalformedResponse)?;
            if compacted <= after
                || self.events.first().map(|event| event.seq) != Some(compacted + 1)
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        } else if self.compacted_through.is_some()
            || self
                .events
                .first()
                .is_some_and(|event| event.seq != after + 1)
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        if self.events.is_empty() {
            if self.gap || after != latest || self.next_cursor != latest || self.has_more {
                return Err(RunmillControlError::MalformedResponse);
            }
        } else if self.events.last().map(|event| event.seq) != Some(self.next_cursor) {
            return Err(RunmillControlError::MalformedResponse);
        }
        if self.has_more {
            if self.events.len() != usize::from(limit) || self.next_cursor >= latest {
                return Err(RunmillControlError::MalformedResponse);
            }
        } else if self.next_cursor != latest {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

impl ExactResponse for RunmillEvidenceView {
    fn validate_raw(value: &Value) -> RunmillControlResult<()> {
        let evidence = require_response_object(
            value,
            &[
                "schema",
                "runId",
                "workOrderId",
                "attemptId",
                "phase",
                "candidateSha",
                "policyDigest",
                "latestSequence",
                "status",
                "complete",
                "bundleDigest",
                "artifacts",
                "latestEvent",
                "signedBundle",
                "terminalBundleDigest",
                "signedTerminalBundle",
            ],
        )?;
        if let Some(event) = evidence.get("latestEvent").filter(|event| !event.is_null()) {
            validate_event_raw(event)?;
        }
        let artifacts = evidence
            .get("artifacts")
            .and_then(Value::as_array)
            .ok_or(RunmillControlError::MalformedResponse)?;
        for artifact in artifacts {
            require_response_object(
                artifact,
                &[
                    "artifactId",
                    "kind",
                    "digest",
                    "sizeBytes",
                    "mediaType",
                    "retentionClass",
                    "locationRef",
                ],
            )?;
        }
        Ok(())
    }

    fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_EVIDENCE_VIEW_SCHEMA
            || !valid_public_string(&self.work_order_id, 1_024)
            || !valid_public_string(&self.attempt_id, 1_024)
            || self.latest_sequence > MAX_SAFE_INTEGER
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        require_digest(&self.policy_digest)?;
        if self
            .candidate_sha
            .as_deref()
            .is_some_and(|sha| !valid_git_sha(sha, false))
        {
            return Err(RunmillControlError::MalformedResponse);
        }

        let has_terminal_digest = self.terminal_bundle_digest.is_some();
        let has_terminal_bundle = self.signed_terminal_bundle.is_some();
        if has_terminal_digest != has_terminal_bundle {
            return Err(RunmillControlError::MalformedResponse);
        }

        if self.phase.terminal() {
            if !self.complete || !has_terminal_digest || !has_terminal_bundle {
                return Err(RunmillControlError::MalformedResponse);
            }
        } else if has_terminal_digest || has_terminal_bundle {
            return Err(RunmillControlError::MalformedResponse);
        }

        match self.status {
            RunmillEvidenceStatus::Current => {
                if self.complete
                    || self.bundle_digest.is_some()
                    || !self.artifacts.is_empty()
                    || self.signed_bundle.is_some()
                {
                    return Err(RunmillControlError::MalformedResponse);
                }
            }
            RunmillEvidenceStatus::Stopped => {
                if self.bundle_digest.is_some()
                    || !self.artifacts.is_empty()
                    || self.signed_bundle.is_some()
                {
                    return Err(RunmillControlError::MalformedResponse);
                }
                if !self.phase.terminal() && self.complete {
                    return Err(RunmillControlError::MalformedResponse);
                }
            }
            RunmillEvidenceStatus::Finalizing => {
                if self.complete || self.bundle_digest.is_none() || self.signed_bundle.is_none() {
                    return Err(RunmillControlError::MalformedResponse);
                }
            }
            RunmillEvidenceStatus::Final => {
                if !self.complete || self.bundle_digest.is_none() || self.signed_bundle.is_none() {
                    return Err(RunmillControlError::MalformedResponse);
                }
            }
        }
        if self.phase.terminal() && self.status == RunmillEvidenceStatus::Current {
            return Err(RunmillControlError::MalformedResponse);
        }
        if let Some(digest) = &self.bundle_digest {
            require_digest(digest)?;
        }
        if let Some(digest) = &self.terminal_bundle_digest {
            require_digest(digest)?;
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        if let Some(event) = &self.latest_event {
            event.validate()?;
            if event.run_id != self.run_id
                || event.work_order_id != self.work_order_id
                || event.attempt_id != self.attempt_id
                || event.seq != self.latest_sequence
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        if let Some(bundle) = &self.signed_bundle {
            validate_signed_evidence(bundle, self.bundle_digest.as_deref())?;
        }
        if let Some(bundle) = &self.signed_terminal_bundle {
            reject_sensitive_fields(bundle).map_err(|_| RunmillControlError::MalformedResponse)?;
            if !bundle.is_object() {
                return Err(RunmillControlError::MalformedResponse);
            }
            let obj = bundle
                .as_object()
                .ok_or(RunmillControlError::MalformedResponse)?;
            if obj.is_empty() {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        Ok(())
    }
}

impl RunmillEvidenceView {
    /// Re-applies the exact raw-shape and typed response contract before an
    /// evidence view is accepted as durable provenance outside this adapter.
    pub(crate) fn validate_provenance_data(value: &Value) -> RunmillControlResult<Self> {
        <Self as ExactResponse>::validate_raw(value)?;
        let view: Self = serde_json::from_value(value.clone())
            .map_err(|_| RunmillControlError::MalformedResponse)?;
        <Self as ExactResponse>::validate(&view)?;
        Ok(view)
    }
}

impl RunmillArtifactReference {
    fn validate(&self) -> RunmillControlResult<()> {
        if !valid_identifier(&self.artifact_id, 256, true)
            || !valid_public_string(&self.kind, 256)
            || self.size_bytes > 1_073_741_824
            || !valid_media_type(&self.media_type)
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        require_digest(&self.digest)?;
        let Some(location_digest) = self.location_ref.strip_prefix("cas://sha256/") else {
            return Err(RunmillControlError::MalformedResponse);
        };
        if location_digest.len() != 64 || !lower_hex(location_digest) {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

impl ExactResponse for RunmillCancellationResult {
    fn validate(&self) -> RunmillControlResult<()> {
        let disposition_matches_state = match self.disposition {
            RunmillCancellationDisposition::Requested
            | RunmillCancellationDisposition::Existing => matches!(
                self.state,
                RunmillRunPhase::CancelRequested | RunmillRunPhase::Cancelling
            ),
            RunmillCancellationDisposition::AlreadyTerminal => self.state.terminal(),
        };
        if !valid_identifier(&self.request_id, 256, true)
            || self.generation > MAX_SAFE_INTEGER
            || !disposition_matches_state
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        require_digest(&self.request_digest)
    }
}

impl ExactResponse for RunmillOutcomeAcknowledgementResult {
    fn validate(&self) -> RunmillControlResult<()> {
        if !valid_identifier(&self.acknowledgement_id, 256, true) {
            return Err(RunmillControlError::MalformedResponse);
        }
        require_digest(&self.bundle_digest)
    }
}

impl ExactResponse for RunmillHealthReport {
    fn validate_raw(value: &Value) -> RunmillControlResult<()> {
        let report = require_response_object(
            value,
            &[
                "schema",
                "mode",
                "checked_at",
                "probe_duration_ms",
                "status",
                "ready",
                "components",
            ],
        )?;
        let components = require_response_object(
            report
                .get("components")
                .ok_or(RunmillControlError::MalformedResponse)?,
            &[
                "service", "database", "worker", "sandbox", "ctxlane", "github", "mcp", "backlog",
            ],
        )?;
        for component in components.values() {
            require_response_object(
                component,
                &["status", "observed_at", "age_ms", "reasons", "details"],
            )?;
        }
        Ok(())
    }

    fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_HEALTH_SCHEMA
            || self.mode != "asf-worker"
            || self.probe_duration_ms > 2_147_483_647
            || self.ready != (self.status == RunmillHealthStatus::Ready)
            || (self.status == RunmillHealthStatus::Ready
                && !runmill_ready_health_proofs_valid(self))
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        let components = [
            ("service", &self.components.service),
            ("database", &self.components.database),
            ("worker", &self.components.worker),
            ("sandbox", &self.components.sandbox),
            ("ctxlane", &self.components.ctxlane),
            ("github", &self.components.github),
            ("mcp", &self.components.mcp),
            ("backlog", &self.components.backlog),
        ];
        for (name, component) in components {
            validate_health_component(name, component)?;
        }
        let expected = if components
            .iter()
            .any(|(_, component)| component.status == RunmillHealthStatus::Refusing)
        {
            RunmillHealthStatus::Refusing
        } else if components
            .iter()
            .any(|(_, component)| component.status == RunmillHealthStatus::Degraded)
        {
            RunmillHealthStatus::Degraded
        } else {
            RunmillHealthStatus::Ready
        };
        if self.status != expected {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

impl RunmillRunRow {
    fn validate(&self) -> RunmillControlResult<()> {
        if !valid_public_string(&self.issue_id, 1_024)
            || !valid_repository(&self.repo)
            || !valid_public_string(&self.provider, 1_024)
            || self.state_version == 0
            || self.state_version > MAX_SAFE_INTEGER
            || self.attempt == 0
            || self.attempt > MAX_SAFE_INTEGER
            || self.generation > MAX_SAFE_INTEGER
            || self.mode != "asf-worker"
            || !valid_public_string(&self.work_order_id, 1_024)
            || !valid_public_string(&self.attempt_id, 1_024)
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        for sha in [self.base_commit.as_deref(), self.candidate_sha.as_deref()]
            .into_iter()
            .flatten()
        {
            if !valid_git_sha(sha, false) {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        for value in [self.branch.as_deref(), self.owner_id.as_deref()]
            .into_iter()
            .flatten()
        {
            if !valid_public_string(value, 1_024) {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        Ok(())
    }
}

impl RunmillAdmissionSnapshot {
    fn validate(&self) -> RunmillControlResult<()> {
        if !valid_idempotency_key(&self.idempotency_key)
            || !valid_public_string(&self.work_order_id, 1_024)
            || !valid_public_string(&self.attempt_id, 1_024)
            || !valid_public_string(&self.tenant_id, 1_024)
            || !valid_identifier(&self.signature_key_id, 256, false)
            || self.signature_algorithm != "EdDSA"
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        for digest in [
            &self.payload_digest,
            &self.envelope_digest,
            &self.effective_policy_digest,
        ] {
            require_digest(digest)?;
        }
        Ok(())
    }
}

impl RunmillRunEvent {
    fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_RUN_EVENT_SCHEMA
            || !valid_public_string(&self.event_id, 1_024)
            || !valid_public_string(&self.work_order_id, 1_024)
            || !valid_public_string(&self.attempt_id, 1_024)
            || self.seq == 0
            || self.seq > MAX_SAFE_INTEGER
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        require_digest(&self.policy_digest)?;
        validate_event_payload(self)
    }
}

impl RunmillCancellationRequest {
    pub fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_CANCELLATION_SCHEMA
            || !valid_identifier(&self.request_id, 256, true)
            || !valid_identifier(&self.requester.subject, 256, true)
            || self.requester.authority != "asf:cancel"
            || self.reason.trim().is_empty()
            || self.reason.trim() != self.reason
            || self.reason.len() > 2_048
            || (self.mode == RunmillCancellationMode::Graceful
                && !(1..=300).contains(&self.grace_seconds))
            || (self.mode == RunmillCancellationMode::Forced && self.grace_seconds != 0)
        {
            return Err(RunmillControlError::InvalidRequest(
                "cancellation request is malformed",
            ));
        }
        Ok(())
    }

    /// SHA-256 of the request's RFC 8785/JCS bytes, exactly matching the
    /// immutable request digest persisted by Runmill.
    pub fn digest(&self) -> RunmillControlResult<String> {
        self.validate()?;
        let bytes = canonical_json(self).map_err(|_| {
            RunmillControlError::InvalidRequest("cancellation request cannot be canonicalized")
        })?;
        Ok(sha256_digest(&bytes))
    }
}

impl RunmillOutcomeAcknowledgement {
    pub fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_OUTCOME_ACKNOWLEDGEMENT_SCHEMA
            || !valid_identifier(&self.acknowledgement_id, 256, true)
            || !valid_identifier(&self.acknowledged_by.subject, 256, true)
            || self.acknowledged_by.authority != "asf:acknowledge-outcome"
        {
            return Err(RunmillControlError::InvalidRequest(
                "outcome acknowledgement is malformed",
            ));
        }
        require_request_digest(&self.bundle_digest)
    }
}

impl RunmillAsfControlError {
    fn validate(&self) -> RunmillControlResult<()> {
        if self.schema != RUNMILL_CONTROL_ERROR_SCHEMA
            || !valid_public_string(&self.code, 256)
            || !valid_public_string(&self.title, 2_048)
            || !valid_public_string(&self.what_happened, 16 * 1_024)
            || !valid_public_string(&self.why, 16 * 1_024)
            || !valid_public_string(&self.docs_url, 4_096)
            || self
                .checkpoint
                .as_deref()
                .is_some_and(|value| !valid_public_string(value, 1_024))
            || self
                .required_action
                .as_deref()
                .is_some_and(|value| !valid_public_string(value, 16 * 1_024))
            || self.evidence_refs.len() > 4_096
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        for fix in &self.fixes {
            if !valid_public_string(&fix.description, 16 * 1_024)
                || fix
                    .command
                    .as_deref()
                    .is_some_and(|command| !valid_public_string(command, 16 * 1_024))
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        if self
            .evidence_refs
            .iter()
            .any(|reference| !valid_public_string(reference, 1_024))
        {
            return Err(RunmillControlError::MalformedResponse);
        }
        Ok(())
    }
}

fn validate_work_order_envelope(value: &Value) -> RunmillControlResult<()> {
    let envelope = require_exact_object(
        value,
        &[
            "schema",
            "key_id",
            "algorithm",
            "issued_at",
            "not_before",
            "expires_at",
            "payload",
            "signature",
        ],
    )?;
    require_literal(envelope, "schema", RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA)?;
    require_literal(envelope, "algorithm", "EdDSA")?;
    require_identifier_field(envelope, "key_id", 256, false)?;
    for key in ["issued_at", "not_before", "expires_at"] {
        require_timestamp_field(envelope, key)?;
    }
    let signature = require_string(envelope, "signature")?;
    let Some(encoded) = signature.strip_prefix("base64url:") else {
        return invalid_request("Runmill Work Order signature is malformed");
    };
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        RunmillControlError::InvalidRequest("Runmill Work Order signature is malformed")
    })?;
    if decoded.is_empty() || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return invalid_request("Runmill Work Order signature is malformed");
    }

    let payload = require_exact_object(
        envelope
            .get("payload")
            .ok_or(RunmillControlError::InvalidRequest(
                "Work Order payload is missing",
            ))?,
        &[
            "schema",
            "work_order_id",
            "tenant_id",
            "work_item_id",
            "attempt_id",
            "idempotency_key",
            "source",
            "repository",
            "objective",
            "scope",
            "verification",
            "identities",
            "runtime",
            "budgets",
            "delivery",
            "policy_digest",
            "harness_digest",
        ],
    )?;
    require_literal(payload, "schema", RUNMILL_WORK_ORDER_SCHEMA)?;
    for key in ["work_order_id", "tenant_id", "work_item_id", "attempt_id"] {
        require_identifier_field(payload, key, 256, false)?;
    }
    let idempotency_key = require_string(payload, "idempotency_key")?;
    if !valid_idempotency_key(idempotency_key) {
        return invalid_request("Runmill Work Order idempotency key is malformed");
    }
    for key in ["policy_digest", "harness_digest"] {
        require_request_digest(require_string(payload, key)?)?;
    }

    let source = nested_exact(
        payload,
        "source",
        &["system", "external_id", "snapshot_digest"],
    )?;
    require_identifier_field(source, "system", 256, false)?;
    require_identifier_field(source, "external_id", 256, false)?;
    require_request_digest(require_string(source, "snapshot_digest")?)?;

    let repository = nested_exact(
        payload,
        "repository",
        &["forge", "repository", "base_ref", "base_sha"],
    )?;
    require_identifier_field(repository, "forge", 256, false)?;
    if !valid_repository(require_string(repository, "repository")?)
        || !valid_branch_ref(require_string(repository, "base_ref")?)
        || !valid_git_sha(require_string(repository, "base_sha")?, true)
    {
        return invalid_request("Runmill Work Order repository binding is malformed");
    }

    let objective = nested_exact(
        payload,
        "objective",
        &["title", "description", "acceptance_criteria", "non_goals"],
    )?;
    if !valid_public_string(require_string(objective, "title")?, 1_024)
        || !valid_public_string(
            require_string(objective, "description")?,
            RUNMILL_MAX_CONTROL_BYTES,
        )
    {
        return invalid_request("Runmill Work Order objective is malformed");
    }
    require_string_array(objective, "acceptance_criteria", true, 1_024)?;
    require_string_array(objective, "non_goals", false, 1_024)?;

    let scope = nested_exact(
        payload,
        "scope",
        &["allowed_paths", "forbidden_paths", "risk_class"],
    )?;
    require_string_array(scope, "allowed_paths", true, 1_024)?;
    require_string_array(scope, "forbidden_paths", false, 1_024)?;
    if !matches!(
        require_string(scope, "risk_class")?,
        "low" | "medium" | "high" | "critical"
    ) {
        return invalid_request("Runmill Work Order risk class is malformed");
    }

    let verification = nested_exact(
        payload,
        "verification",
        &[
            "required_local_check_ids",
            "required_remote_checks",
            "policy_snapshot_digest",
        ],
    )?;
    require_string_array(verification, "required_local_check_ids", false, 512)?;
    require_string_array(verification, "required_remote_checks", false, 512)?;
    require_request_digest(require_string(verification, "policy_snapshot_digest")?)?;

    let identities = nested_exact(
        payload,
        "identities",
        &["implementer", "local_reviewer", "pr_reviewer"],
    )?;
    for key in ["implementer", "local_reviewer", "pr_reviewer"] {
        require_identifier_field(identities, key, 256, true)?;
    }

    let runtime = nested_exact(
        payload,
        "runtime",
        &["sandbox_profile", "tool_policy", "network_policy"],
    )?;
    for key in ["sandbox_profile", "tool_policy", "network_policy"] {
        require_identifier_field(runtime, key, 256, false)?;
    }

    let budgets = nested_exact(
        payload,
        "budgets",
        &[
            "wall_seconds",
            "max_cost_usd",
            "max_agent_invocations",
            "max_fix_iterations",
        ],
    )?;
    require_positive_safe_integer(budgets, "wall_seconds")?;
    require_nonnegative_number(budgets, "max_cost_usd")?;
    require_positive_safe_integer(budgets, "max_agent_invocations")?;
    require_nonnegative_safe_integer(budgets, "max_fix_iterations")?;

    let delivery = nested_exact(
        payload,
        "delivery",
        &["closure_target", "draft_pr", "merge_policy_ref"],
    )?;
    if !matches!(
        require_string(delivery, "closure_target")?,
        "pr" | "merge" | "deploy" | "observe"
    ) || !delivery.get("draft_pr").is_some_and(Value::is_boolean)
        || !delivery.get("merge_policy_ref").is_some_and(|value| {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|text| valid_public_string(text, 512))
        })
    {
        return invalid_request("Runmill Work Order delivery is malformed");
    }
    Ok(())
}

fn validate_event_payload(event: &RunmillRunEvent) -> RunmillControlResult<()> {
    let (expected_phase, required, optional) = event_contract(&event.event_type, &event.payload)?;
    if event.phase != expected_phase || !exact_required_optional(&event.payload, required, optional)
    {
        return Err(RunmillControlError::MalformedResponse);
    }
    validate_event_payload_shape(&event.event_type, &event.payload)?;
    Ok(())
}

fn event_contract(
    event_type: &str,
    payload: &Map<String, Value>,
) -> RunmillControlResult<(
    RunmillRunPhase,
    &'static [&'static str],
    &'static [&'static str],
)> {
    use RunmillRunPhase as P;
    const NONE: &[&str] = &[];
    const STOP: &[&str] = &[
        "code",
        "summary",
        "checkpoint",
        "retry_disposition",
        "required_actor",
        "required_action",
        "evidence_refs",
    ];
    const CANCELLATION: &[&str] = &[
        "code",
        "summary",
        "checkpoint",
        "retry_disposition",
        "required_actor",
        "required_action",
        "evidence_refs",
        "request_id",
        "requester",
        "reason",
        "mode",
        "grace_seconds",
    ];
    const CANDIDATE_OPTIONAL: &[&str] = &["candidate_sha"];
    let contract = match event_type {
        "work_order.admitted" => (
            P::Admitted,
            &[
                "work_order_id",
                "attempt_id",
                "tenant_id",
                "payload_digest",
                "envelope_digest",
                "signature",
            ][..],
            NONE,
        ),
        "repository.lease_acquired" => {
            (P::RepositoryLeased, &["repository", "generation"][..], NONE)
        }
        "identity.leases_acquired" => (
            P::IdentityReady,
            &["attributions_digest", "roles", "attributions"][..],
            NONE,
        ),
        "workspace.prepared" => (
            P::WorkspaceReady,
            &[
                "workspace_id",
                "sandbox_profile",
                "isolation_evidence_digest",
            ][..],
            NONE,
        ),
        "task_packet.created" => (
            P::TaskPacketReady,
            &["task_packet_digest", "source_snapshot_digest"][..],
            NONE,
        ),
        "implementation.started" => (P::Implementing, &["session", "checkpoint_digest"][..], NONE),
        "candidate.created" => (
            P::CandidateReady,
            &["candidate_sha", "parent_sha", "tree_digest"][..],
            NONE,
        ),
        "verification.started" => (
            P::LocalVerify,
            &["candidate_sha", "required_check_ids"][..],
            NONE,
        ),
        "verification.completed" => (
            P::LocalVerify,
            &["candidate_sha", "check_id", "outcome", "evidence_digest"][..],
            NONE,
        ),
        "review.started" => (
            P::LocalReview,
            &["candidate_sha", "reviewer_attribution"][..],
            NONE,
        ),
        "review.completed" => (
            P::LocalReview,
            &[
                "candidate_sha",
                "reviewer_attribution",
                "outcome",
                "findings_digest",
            ][..],
            NONE,
        ),
        "fixing.started" => (P::Fixing, &["candidate_sha", "iteration"][..], NONE),
        "delivery.ready" => (
            P::DeliveryReady,
            &["candidate_sha", "required_remote_checks"][..],
            NONE,
        ),
        "branch.pushed" => (
            P::Pushed,
            &["candidate_sha", "remote_ref", "observed_remote_sha"][..],
            NONE,
        ),
        "pull_request.opened" => (
            P::PrOpen,
            &[
                "candidate_sha",
                "repository",
                "number",
                "url",
                "observed_head_sha",
                "base_sha",
            ][..],
            NONE,
        ),
        "ci.waiting" => (P::CiWait, &["candidate_sha", "snapshot_digest"][..], NONE),
        "ci.completed" => (
            P::CiWait,
            &[
                "candidate_sha",
                "outcome",
                "checks_digest",
                "checks",
                "observed_at",
            ][..],
            NONE,
        ),
        "ci.recheck_completed" => (
            P::CiWait,
            &[
                "candidate_sha",
                "outcome",
                "observation_intent_digest",
                "observation_digest",
                "observation_fencing_generation",
                "checks_digest",
                "checks",
                "observed_at",
            ][..],
            NONE,
        ),
        "pr_review.started" => (
            P::PrReview,
            &["candidate_sha", "reviewer_attribution"][..],
            NONE,
        ),
        "pr_review.completed" => (
            P::PrReview,
            &[
                "candidate_sha",
                "reviewer_attribution",
                "outcome",
                "findings_digest",
            ][..],
            NONE,
        ),
        "ci.revalidated" => (
            P::PrReview,
            &[
                "candidate_sha",
                "outcome",
                "observation_intent_digest",
                "observation_digest",
                "observation_fencing_generation",
                "checks_digest",
                "checks",
                "observed_at",
            ][..],
            NONE,
        ),
        "pull_request.delivered" => (
            P::PrDelivered,
            &[
                "candidate_sha",
                "repository",
                "number",
                "url",
                "head_ref",
                "base_ref",
                "marker",
                "head_sha",
                "observed_head_sha",
                "current_base_sha",
                "collision_set_digest",
                "base_observation_digest",
                "protection_digest",
                "protection",
                "state",
                "draft",
                "delivery_observation_intent_digest",
                "delivery_observation_digest",
                "observed_at",
                "final_ci_observation_intent_digest",
                "final_ci_observation_digest",
                "final_ci_observation_fencing_generation",
                "final_ci_checks_digest",
                "final_ci_checks",
                "final_ci_observed_at",
            ][..],
            NONE,
        ),
        "merge_queue.entered" => (
            P::MergeQueueWait,
            &["candidate_sha", "merge_group_sha"][..],
            NONE,
        ),
        "merge.ready" => (
            P::MergeReady,
            &["candidate_sha", "merge_group_sha", "evidence_digest"][..],
            NONE,
        ),
        "merge.completed" => (
            P::Merged,
            &["candidate_sha", "merge_sha", "evidence_digest"][..],
            NONE,
        ),
        "evidence.finalized" => (
            P::EvidenceFinalized,
            &["candidate_sha", "bundle_digest"][..],
            NONE,
        ),
        "run.completed" => (
            P::Completed,
            &[
                "candidate_sha",
                "closure_target",
                "satisfied",
                "evidence_bundle_digest",
            ][..],
            &["terminal_evidence_bundle_digest"][..],
        ),
        "run.resumed" => {
            let phase = payload
                .get("resume_phase")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .ok_or(RunmillControlError::MalformedResponse)?;
            match payload.get("interrupted_phase").and_then(Value::as_str) {
                Some("WAITING_APPROVAL") => (
                    phase,
                    &[
                        "interrupted_phase",
                        "resume_phase",
                        "evidence_digest",
                        "approval_id",
                    ][..],
                    &["candidate_sha"][..],
                ),
                Some("BLOCKED_EXTERNAL") => (
                    phase,
                    &[
                        "interrupted_phase",
                        "resume_phase",
                        "evidence_digest",
                        "reconciliation",
                    ][..],
                    &["candidate_sha"][..],
                ),
                _ => return Err(RunmillControlError::MalformedResponse),
            }
        }
        "cancellation.requested" | "cancellation.escalated" => (
            P::CancelRequested,
            CANCELLATION,
            &["candidate_sha", "reconciliation_origin"][..],
        ),
        "cancellation.started" => (
            P::Cancelling,
            CANCELLATION,
            &["candidate_sha", "reconciliation_origin"][..],
        ),
        "run.waiting_approval" => (
            P::WaitingApproval,
            STOP,
            &["candidate_sha", "decision_type", "requested_effect"][..],
        ),
        "run.needs_spec" => (P::NeedsSpec, STOP, CANDIDATE_OPTIONAL),
        "run.blocked_external" => (
            P::BlockedExternal,
            STOP,
            &["candidate_sha", "continuation"][..],
        ),
        "budget.exhausted" => (
            P::BudgetExhausted,
            STOP,
            &["candidate_sha", "terminal_evidence_bundle_digest"][..],
        ),
        "run.refused" => (
            P::Refused,
            STOP,
            &["candidate_sha", "terminal_evidence_bundle_digest"][..],
        ),
        "run.quarantined" => (
            P::Quarantined,
            STOP,
            &["candidate_sha", "terminal_evidence_bundle_digest"][..],
        ),
        "run.cancelled" => (
            P::Cancelled,
            CANCELLATION,
            &[
                "candidate_sha",
                "reconciliation_origin",
                "terminal_evidence_bundle_digest",
            ][..],
        ),
        "run.failed" => (
            P::Failed,
            STOP,
            &["candidate_sha", "terminal_evidence_bundle_digest"][..],
        ),
        _ => return Err(RunmillControlError::MalformedResponse),
    };
    Ok(contract)
}

fn malformed_event<T>() -> RunmillControlResult<T> {
    Err(RunmillControlError::MalformedResponse)
}

fn event_string<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
    max: usize,
) -> RunmillControlResult<&'a str> {
    let value = payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or(RunmillControlError::MalformedResponse)?;
    if valid_public_string(value, max) {
        Ok(value)
    } else {
        malformed_event()
    }
}

fn event_identifier(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    event_string(payload, key, 16 * 1_024).map(|_| ())
}

fn event_digest(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    require_digest(
        payload
            .get(key)
            .and_then(Value::as_str)
            .ok_or(RunmillControlError::MalformedResponse)?,
    )
}

fn event_sha(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    if payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| valid_git_sha(value, false))
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn event_positive(payload: &Map<String, Value>, key: &str, safe: bool) -> RunmillControlResult<()> {
    if payload
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|value| value > 0 && (!safe || value <= MAX_SAFE_INTEGER))
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn event_timestamp(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    if payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(valid_timestamp)
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn event_enum(
    payload: &Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> RunmillControlResult<()> {
    if payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| allowed.contains(&value))
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn event_string_array(
    payload: &Map<String, Value>,
    key: &str,
    max: usize,
    max_items: usize,
) -> RunmillControlResult<()> {
    let values = payload
        .get(key)
        .and_then(Value::as_array)
        .ok_or(RunmillControlError::MalformedResponse)?;
    if values.len() <= max_items
        && values.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|text| valid_public_string(text, max))
        })
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn event_phase(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    serde_json::from_value::<RunmillRunPhase>(
        payload
            .get(key)
            .cloned()
            .ok_or(RunmillControlError::MalformedResponse)?,
    )
    .map(|_| ())
    .map_err(|_| RunmillControlError::MalformedResponse)
}

fn event_object<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
    fields: &[&str],
) -> RunmillControlResult<&'a Map<String, Value>> {
    require_exact_object(
        payload
            .get(key)
            .ok_or(RunmillControlError::MalformedResponse)?,
        fields,
    )
    .map_err(|_| RunmillControlError::MalformedResponse)
}

fn event_object_optional<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> RunmillControlResult<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or(RunmillControlError::MalformedResponse)?;
    if exact_required_optional(object, required, optional) {
        Ok(object)
    } else {
        malformed_event()
    }
}

fn validate_event_checks(value: &Value, passed_only: bool) -> RunmillControlResult<()> {
    let checks = value
        .as_array()
        .ok_or(RunmillControlError::MalformedResponse)?;
    if checks.len() > 10_000 {
        return malformed_event();
    }
    for check in checks {
        let object = require_exact_object(check, &["context", "outcome", "evidence_digest"])
            .map_err(|_| RunmillControlError::MalformedResponse)?;
        let context = object
            .get("context")
            .and_then(Value::as_str)
            .ok_or(RunmillControlError::MalformedResponse)?;
        let outcome = object
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or(RunmillControlError::MalformedResponse)?;
        if !valid_public_string(context, 512)
            || !(if passed_only {
                outcome == "passed"
            } else {
                matches!(outcome, "passed" | "failed" | "pending" | "not-scheduled")
            })
        {
            return malformed_event();
        }
        require_digest(
            object
                .get("evidence_digest")
                .and_then(Value::as_str)
                .ok_or(RunmillControlError::MalformedResponse)?,
        )?;
    }
    Ok(())
}

fn validate_stop_payload(payload: &Map<String, Value>) -> RunmillControlResult<()> {
    let code = event_string(payload, "code", 256)?;
    if !code
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase())
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return malformed_event();
    }
    event_string(payload, "summary", 2_048)?;
    event_phase(payload, "checkpoint")?;
    event_enum(
        payload,
        "retry_disposition",
        &[
            "safe",
            "reconcile-first",
            "new-attempt-required",
            "prohibited",
        ],
    )?;
    event_enum(
        payload,
        "required_actor",
        &[
            "asf",
            "repository-owner",
            "platform-operator",
            "security",
            "provider-administrator",
        ],
    )?;
    event_string(payload, "required_action", 2_048)?;
    event_string_array(payload, "evidence_refs", 1_024, 10_000)
}

fn validate_event_payload_shape(
    event_type: &str,
    payload: &Map<String, Value>,
) -> RunmillControlResult<()> {
    match event_type {
        "work_order.admitted" => {
            for key in ["work_order_id", "attempt_id", "tenant_id"] {
                event_identifier(payload, key)?;
            }
            for key in ["payload_digest", "envelope_digest"] {
                event_digest(payload, key)?;
            }
            let signature =
                event_object(payload, "signature", &["verified", "key_id", "algorithm"])?;
            if signature.get("verified") != Some(&Value::Bool(true))
                || signature.get("algorithm").and_then(Value::as_str) != Some("EdDSA")
                || !signature
                    .get("key_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| valid_public_string(value, 16 * 1_024))
            {
                return malformed_event();
            }
        }
        "repository.lease_acquired" => {
            if !payload
                .get("repository")
                .and_then(Value::as_str)
                .is_some_and(valid_repository)
            {
                return malformed_event();
            }
            event_positive(payload, "generation", false)?;
        }
        "identity.leases_acquired" => {
            event_digest(payload, "attributions_digest")?;
            let roles = payload
                .get("roles")
                .and_then(Value::as_array)
                .ok_or(RunmillControlError::MalformedResponse)?;
            if roles.len() != 3
                || roles
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    != BTreeSet::from(["implementer", "local-reviewer", "pr-reviewer"])
            {
                return malformed_event();
            }
            let attributions = payload
                .get("attributions")
                .and_then(Value::as_array)
                .ok_or(RunmillControlError::MalformedResponse)?;
            if attributions.len() != 3 {
                return malformed_event();
            }
            for attribution in attributions {
                let value = require_exact_object(
                    attribution,
                    &[
                        "schema",
                        "role",
                        "provider",
                        "principal_id",
                        "profile",
                        "fencing_generation",
                        "issued_at",
                        "expires_at",
                        "lease_attribution_digest",
                    ],
                )
                .map_err(|_| RunmillControlError::MalformedResponse)?;
                if value.get("schema").and_then(Value::as_str)
                    != Some("asf.identity-lease-attribution/v1")
                {
                    return malformed_event();
                }
                let role = value
                    .get("role")
                    .and_then(Value::as_str)
                    .ok_or(RunmillControlError::MalformedResponse)?;
                if !["implementer", "local-reviewer", "pr-reviewer"].contains(&role)
                    || ["provider", "principal_id", "profile"].iter().any(|key| {
                        !value
                            .get(*key)
                            .and_then(Value::as_str)
                            .is_some_and(|text| valid_public_string(text, 512))
                    })
                    || !value
                        .get("fencing_generation")
                        .and_then(Value::as_u64)
                        .is_some_and(|number| (1..=MAX_SAFE_INTEGER).contains(&number))
                    || !value
                        .get("issued_at")
                        .and_then(Value::as_str)
                        .is_some_and(valid_timestamp)
                    || !value
                        .get("expires_at")
                        .and_then(Value::as_str)
                        .is_some_and(valid_timestamp)
                {
                    return malformed_event();
                }
                require_digest(
                    value
                        .get("lease_attribution_digest")
                        .and_then(Value::as_str)
                        .ok_or(RunmillControlError::MalformedResponse)?,
                )?;
            }
        }
        "workspace.prepared" => {
            for key in ["workspace_id", "sandbox_profile"] {
                event_identifier(payload, key)?;
            }
            event_digest(payload, "isolation_evidence_digest")?;
        }
        "task_packet.created" => {
            for key in ["task_packet_digest", "source_snapshot_digest"] {
                event_digest(payload, key)?;
            }
        }
        "implementation.started" => {
            event_enum(payload, "session", &["new", "resumed"])?;
            event_digest(payload, "checkpoint_digest")?;
        }
        "candidate.created" => {
            event_sha(payload, "candidate_sha")?;
            event_sha(payload, "parent_sha")?;
            event_digest(payload, "tree_digest")?;
        }
        "verification.started" => {
            event_sha(payload, "candidate_sha")?;
            event_string_array(payload, "required_check_ids", 16 * 1_024, 10_000)?;
        }
        "verification.completed" => {
            event_sha(payload, "candidate_sha")?;
            event_identifier(payload, "check_id")?;
            event_enum(payload, "outcome", &["passed", "failed", "blocked"])?;
            event_digest(payload, "evidence_digest")?;
        }
        "review.started" | "pr_review.started" => {
            event_sha(payload, "candidate_sha")?;
            event_identifier(payload, "reviewer_attribution")?;
        }
        "review.completed" | "pr_review.completed" => {
            event_sha(payload, "candidate_sha")?;
            event_identifier(payload, "reviewer_attribution")?;
            event_enum(
                payload,
                "outcome",
                &["approved", "changes-requested", "blocked"],
            )?;
            event_digest(payload, "findings_digest")?;
        }
        "fixing.started" => {
            event_sha(payload, "candidate_sha")?;
            event_positive(payload, "iteration", false)?;
        }
        "delivery.ready" => {
            event_sha(payload, "candidate_sha")?;
            event_string_array(payload, "required_remote_checks", 16 * 1_024, 10_000)?;
        }
        "branch.pushed" => {
            event_sha(payload, "candidate_sha")?;
            event_string(payload, "remote_ref", 16 * 1_024)?;
            event_sha(payload, "observed_remote_sha")?;
        }
        "pull_request.opened" => {
            event_sha(payload, "candidate_sha")?;
            if !payload
                .get("repository")
                .and_then(Value::as_str)
                .is_some_and(valid_repository)
            {
                return malformed_event();
            }
            event_positive(payload, "number", false)?;
            validate_event_url(payload, "url")?;
            event_sha(payload, "observed_head_sha")?;
            event_sha(payload, "base_sha")?;
        }
        "ci.waiting" => {
            event_sha(payload, "candidate_sha")?;
            event_digest(payload, "snapshot_digest")?;
        }
        "ci.completed" | "ci.recheck_completed" | "ci.revalidated" => {
            event_sha(payload, "candidate_sha")?;
            let outcomes: &[&str] = if event_type == "ci.completed" {
                &["passed", "failed", "pending", "not-scheduled"]
            } else if event_type == "ci.recheck_completed" {
                &["failed", "pending", "not-scheduled"]
            } else {
                &["passed"]
            };
            event_enum(payload, "outcome", outcomes)?;
            if event_type != "ci.completed" {
                for key in ["observation_intent_digest", "observation_digest"] {
                    event_digest(payload, key)?;
                }
                event_positive(payload, "observation_fencing_generation", false)?;
            }
            event_digest(payload, "checks_digest")?;
            validate_event_checks(
                payload
                    .get("checks")
                    .ok_or(RunmillControlError::MalformedResponse)?,
                event_type == "ci.revalidated",
            )?;
            event_timestamp(payload, "observed_at")?;
        }
        "pull_request.delivered" => validate_delivery_payload(payload)?,
        "merge_queue.entered" => {
            event_sha(payload, "candidate_sha")?;
            event_sha(payload, "merge_group_sha")?;
        }
        "merge.ready" => {
            event_sha(payload, "candidate_sha")?;
            event_sha(payload, "merge_group_sha")?;
            event_digest(payload, "evidence_digest")?;
        }
        "merge.completed" => {
            event_sha(payload, "candidate_sha")?;
            event_sha(payload, "merge_sha")?;
            event_digest(payload, "evidence_digest")?;
        }
        "evidence.finalized" => {
            event_sha(payload, "candidate_sha")?;
            event_digest(payload, "bundle_digest")?;
        }
        "run.completed" => {
            event_sha(payload, "candidate_sha")?;
            event_enum(payload, "closure_target", &["pr", "merge"])?;
            if payload.get("satisfied") != Some(&Value::Bool(true)) {
                return malformed_event();
            }
            event_digest(payload, "evidence_bundle_digest")?;
            if payload.contains_key("terminal_evidence_bundle_digest") {
                event_digest(payload, "terminal_evidence_bundle_digest")?;
            }
        }
        "run.resumed" => validate_resumed_payload(payload)?,
        "cancellation.requested"
        | "cancellation.escalated"
        | "cancellation.started"
        | "run.cancelled" => validate_cancellation_payload(payload)?,
        "run.waiting_approval" => {
            validate_stop_payload(payload)?;
            for key in ["decision_type", "requested_effect"] {
                if payload.contains_key(key) {
                    event_identifier(payload, key)?;
                }
            }
        }
        "run.needs_spec" | "budget.exhausted" | "run.refused" | "run.quarantined"
        | "run.failed" => validate_stop_payload(payload)?,
        "run.blocked_external" => {
            validate_stop_payload(payload)?;
            if let Some(value) = payload.get("continuation") {
                validate_block_continuation(value)?;
            }
        }
        _ => return malformed_event(),
    }
    if payload.contains_key("candidate_sha") {
        event_sha(payload, "candidate_sha")?;
    }
    if payload.contains_key("terminal_evidence_bundle_digest") {
        event_digest(payload, "terminal_evidence_bundle_digest")?;
    }
    Ok(())
}

fn validate_event_url(payload: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    if payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| url::Url::parse(value).is_ok())
    {
        Ok(())
    } else {
        malformed_event()
    }
}

fn validate_delivery_payload(payload: &Map<String, Value>) -> RunmillControlResult<()> {
    event_sha(payload, "candidate_sha")?;
    if !payload
        .get("repository")
        .and_then(Value::as_str)
        .is_some_and(valid_repository)
    {
        return malformed_event();
    }
    event_positive(payload, "number", false)?;
    validate_event_url(payload, "url")?;
    for key in ["head_ref", "base_ref"] {
        if !payload
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(valid_run_event_branch_ref)
        {
            return malformed_event();
        }
    }
    event_identifier(payload, "marker")?;
    for key in ["head_sha", "observed_head_sha", "current_base_sha"] {
        event_sha(payload, key)?;
    }
    for key in [
        "collision_set_digest",
        "base_observation_digest",
        "protection_digest",
        "delivery_observation_intent_digest",
        "delivery_observation_digest",
        "final_ci_observation_intent_digest",
        "final_ci_observation_digest",
        "final_ci_checks_digest",
    ] {
        event_digest(payload, key)?;
    }
    let protection = event_object(
        payload,
        "protection",
        &[
            "required_checks",
            "requires_approval",
            "requires_conversation_resolution",
            "uses_merge_queue",
        ],
    )?;
    let required = protection
        .get("required_checks")
        .and_then(Value::as_array)
        .ok_or(RunmillControlError::MalformedResponse)?;
    if required.len() > 10_000
        || required.iter().any(|value| {
            !value
                .as_str()
                .is_some_and(|text| valid_public_string(text, 512))
        })
        || [
            "requires_approval",
            "requires_conversation_resolution",
            "uses_merge_queue",
        ]
        .iter()
        .any(|key| !protection.get(*key).is_some_and(Value::is_boolean))
        || payload.get("state").and_then(Value::as_str) != Some("open")
        || !payload.get("draft").is_some_and(Value::is_boolean)
    {
        return malformed_event();
    }
    event_timestamp(payload, "observed_at")?;
    event_positive(payload, "final_ci_observation_fencing_generation", false)?;
    validate_event_checks(
        payload
            .get("final_ci_checks")
            .ok_or(RunmillControlError::MalformedResponse)?,
        true,
    )?;
    event_timestamp(payload, "final_ci_observed_at")
}

fn valid_run_event_branch_ref(value: &str) -> bool {
    value.strip_prefix("refs/heads/").is_some_and(|branch| {
        !branch.is_empty()
            && branch.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
            })
    })
}

fn validate_resumed_payload(payload: &Map<String, Value>) -> RunmillControlResult<()> {
    event_phase(payload, "resume_phase")?;
    event_digest(payload, "evidence_digest")?;
    match payload.get("interrupted_phase").and_then(Value::as_str) {
        Some("WAITING_APPROVAL") => event_identifier(payload, "approval_id"),
        Some("BLOCKED_EXTERNAL") => {
            let reconciliation = event_object_optional(
                payload
                    .get("reconciliation")
                    .ok_or(RunmillControlError::MalformedResponse)?,
                &[
                    "schema",
                    "operation_id",
                    "result_digest",
                    "pending_set_digest",
                    "checkpoint_digest",
                    "blocked_event_id",
                    "interrupted_event_seq",
                    "action",
                ],
                &["provider_budget_settlement_digests"],
            )?;
            if reconciliation.get("schema").and_then(Value::as_str)
                != Some("asf.reconciliation-continuation-result/v1")
            {
                return malformed_event();
            }
            for key in ["operation_id", "blocked_event_id"] {
                if !reconciliation
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|text| valid_public_string(text, 16 * 1_024))
                {
                    return malformed_event();
                }
            }
            for key in ["result_digest", "pending_set_digest", "checkpoint_digest"] {
                require_digest(
                    reconciliation
                        .get(key)
                        .and_then(Value::as_str)
                        .ok_or(RunmillControlError::MalformedResponse)?,
                )?;
            }
            if !reconciliation
                .get("interrupted_event_seq")
                .and_then(Value::as_u64)
                .is_some_and(|value| (1..=MAX_SAFE_INTEGER).contains(&value))
                || !reconciliation
                    .get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        [
                            "continue-confirmed",
                            "replay-not-applied",
                            "continue-cancellation",
                        ]
                        .contains(&value)
                    })
            {
                return malformed_event();
            }
            if let Some(values) = reconciliation.get("provider_budget_settlement_digests") {
                let values = values
                    .as_array()
                    .ok_or(RunmillControlError::MalformedResponse)?;
                if values.len() > 20_000 {
                    return malformed_event();
                }
                for value in values {
                    require_digest(
                        value
                            .as_str()
                            .ok_or(RunmillControlError::MalformedResponse)?,
                    )?;
                }
            }
            Ok(())
        }
        _ => malformed_event(),
    }
}

fn validate_cancellation_payload(payload: &Map<String, Value>) -> RunmillControlResult<()> {
    validate_stop_payload(payload)?;
    for key in ["request_id", "requester"] {
        event_identifier(payload, key)?;
    }
    event_string(payload, "reason", 2_048)?;
    event_enum(payload, "mode", &["graceful", "forced"])?;
    if payload
        .get("grace_seconds")
        .and_then(Value::as_u64)
        .is_none()
    {
        return malformed_event();
    }
    if payload.contains_key("reconciliation_origin") {
        event_enum(
            payload,
            "reconciliation_origin",
            &[
                "none",
                "preexisting",
                "durable-effects",
                "forced-cancellation-cleanup",
            ],
        )?;
    }
    Ok(())
}

fn validate_block_continuation(value: &Value) -> RunmillControlResult<()> {
    let continuation = event_object_optional(
        value,
        &[
            "schema",
            "disposition",
            "interrupted_event_seq",
            "resume_phase",
            "checkpoint_digest",
            "pending_set_digest",
        ],
        &[
            "cancellation_event_id",
            "cancellation_event_digest",
            "cancellation_request_id",
        ],
    )?;
    if continuation.get("schema").and_then(Value::as_str)
        != Some("asf.reconciliation-continuation/v1")
        || !continuation
            .get("disposition")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                ["retry-interrupted-phase", "finish-cancellation"].contains(&value)
            })
        || !continuation
            .get("interrupted_event_seq")
            .and_then(Value::as_u64)
            .is_some_and(|value| (1..=MAX_SAFE_INTEGER).contains(&value))
    {
        return malformed_event();
    }
    serde_json::from_value::<RunmillRunPhase>(
        continuation
            .get("resume_phase")
            .cloned()
            .ok_or(RunmillControlError::MalformedResponse)?,
    )
    .map_err(|_| RunmillControlError::MalformedResponse)?;
    for key in ["checkpoint_digest", "pending_set_digest"] {
        require_digest(
            continuation
                .get(key)
                .and_then(Value::as_str)
                .ok_or(RunmillControlError::MalformedResponse)?,
        )?;
    }
    if let Some(value) = continuation.get("cancellation_event_id")
        && !value
            .as_str()
            .is_some_and(|text| valid_public_string(text, 16 * 1_024))
    {
        return malformed_event();
    }
    if let Some(value) = continuation.get("cancellation_event_digest") {
        require_digest(
            value
                .as_str()
                .ok_or(RunmillControlError::MalformedResponse)?,
        )?;
    }
    if let Some(value) = continuation.get("cancellation_request_id")
        && !value
            .as_str()
            .is_some_and(|text| valid_public_string(text, 16 * 1_024))
    {
        return malformed_event();
    }
    Ok(())
}

fn validate_signed_evidence(
    value: &Value,
    expected_digest: Option<&str>,
) -> RunmillControlResult<()> {
    let bundle = require_exact_object(
        value,
        &[
            "schema",
            "key_id",
            "algorithm",
            "issued_at",
            "bundle_digest",
            "statement",
            "signature",
        ],
    )?;
    if bundle.get("schema").and_then(Value::as_str) != Some("asf.signed-evidence/v1")
        || bundle.get("algorithm").and_then(Value::as_str) != Some("EdDSA")
        || !bundle
            .get("key_id")
            .and_then(Value::as_str)
            .is_some_and(|key| valid_identifier(key, 256, true))
        || !bundle
            .get("issued_at")
            .and_then(Value::as_str)
            .is_some_and(valid_timestamp)
    {
        return Err(RunmillControlError::MalformedResponse);
    }
    let digest = bundle
        .get("bundle_digest")
        .and_then(Value::as_str)
        .ok_or(RunmillControlError::MalformedResponse)?;
    require_digest(digest)?;
    if expected_digest != Some(digest) {
        return Err(RunmillControlError::MalformedResponse);
    }
    let signature = bundle
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(RunmillControlError::MalformedResponse)?;
    if !signature
        .strip_prefix("base64url:")
        .is_some_and(|encoded| !encoded.is_empty() && URL_SAFE_NO_PAD.decode(encoded).is_ok())
    {
        return Err(RunmillControlError::MalformedResponse);
    }
    let statement = require_exact_object(
        bundle
            .get("statement")
            .ok_or(RunmillControlError::MalformedResponse)?,
        &["_type", "subject", "predicateType", "predicate"],
    )?;
    if statement.get("_type").and_then(Value::as_str) != Some("https://in-toto.io/Statement/v1")
        || statement.get("predicateType").and_then(Value::as_str)
            != Some("https://runmill.dev/attestations/asf-evidence/v1")
        || !statement.get("subject").is_some_and(Value::is_array)
        || statement
            .get("predicate")
            .and_then(Value::as_object)
            .and_then(|predicate| predicate.get("schema"))
            .and_then(Value::as_str)
            != Some("asf.evidence-bundle/v1")
    {
        return Err(RunmillControlError::MalformedResponse);
    }
    Ok(())
}

fn validate_health_component(
    name: &str,
    component: &RunmillHealthComponent,
) -> RunmillControlResult<()> {
    if component.age_ms.is_some_and(|age| age > 2_147_483_647)
        || component.reasons.len() > 16
        || component.reasons.iter().collect::<BTreeSet<_>>().len() != component.reasons.len()
        || component
            .reasons
            .iter()
            .any(|reason| !HEALTH_REASONS.contains(&reason.as_str()))
        || (component.details.is_none() && component.status != RunmillHealthStatus::Refusing)
    {
        return Err(RunmillControlError::MalformedResponse);
    }
    let expected = if component.reasons.is_empty() {
        RunmillHealthStatus::Ready
    } else if component
        .reasons
        .iter()
        .all(|reason| DEGRADED_HEALTH_REASONS.contains(&reason.as_str()))
    {
        RunmillHealthStatus::Degraded
    } else {
        RunmillHealthStatus::Refusing
    };
    if component.status != expected {
        return Err(RunmillControlError::MalformedResponse);
    }
    if let Some(details) = &component.details {
        validate_health_details(name, details)?;
    }
    Ok(())
}

/// A top-level `ready` bit is not an authority proof.  Every safety-critical
/// detail emitted by Runmill must independently describe the exact production
/// posture ASF requires before a worker can be admitted.
pub(crate) fn runmill_ready_health_proofs_valid(report: &RunmillHealthReport) -> bool {
    if report.status != RunmillHealthStatus::Ready || !report.ready {
        return false;
    }
    let Some(service) = health_details(&report.components.service) else {
        return false;
    };
    let Some(database) = health_details(&report.components.database) else {
        return false;
    };
    let Some(worker) = health_details(&report.components.worker) else {
        return false;
    };
    let Some(sandbox) = health_details(&report.components.sandbox) else {
        return false;
    };
    let Some(ctxlane) = health_details(&report.components.ctxlane) else {
        return false;
    };
    let Some(github) = health_details(&report.components.github) else {
        return false;
    };
    let Some(mcp) = health_details(&report.components.mcp) else {
        return false;
    };
    let Some(backlog) = health_details(&report.components.backlog) else {
        return false;
    };
    let Some(denial_proofs) = sandbox.get("denial_proofs").and_then(Value::as_object) else {
        return false;
    };

    let max_concurrency = health_u64(worker, "max_concurrency");
    let expected_max_concurrency = health_u64(worker, "expected_max_concurrency");
    let active_runs = health_u64(worker, "active_runs");
    let queued_runs = health_u64(worker, "queued_runs");
    let available_capacity = health_u64(worker, "available_capacity");
    let worker_capacity_is_consistent = max_concurrency.is_some_and(|maximum| {
        maximum > 0
            && expected_max_concurrency == Some(maximum)
            && active_runs.is_some_and(|active| active < maximum)
            && queued_runs == Some(0)
            && available_capacity == active_runs.and_then(|active| maximum.checked_sub(active))
    });
    let database_schema_is_consistent = health_u64(database, "schema_version")
        .zip(health_u64(database, "expected_schema_version"))
        .is_some_and(|(actual, expected)| actual == expected);

    service.get("mode").and_then(Value::as_str) == Some("asf-worker")
        && service.get("state").and_then(Value::as_str) == Some("running")
        && health_bool(service, "accepting_submissions") == Some(true)
        && health_bool(service, "recovery_complete") == Some(true)
        && health_bool(database, "reachable") == Some(true)
        && database_schema_is_consistent
        && health_bool(database, "integrity_check_passed") == Some(true)
        && health_bool(database, "write_probe_passed") == Some(true)
        && health_bool(worker, "scheduler_running") == Some(true)
        && health_bool(worker, "fencing_store_ready") == Some(true)
        && worker_capacity_is_consistent
        && matches!(
            sandbox.get("mechanism").and_then(Value::as_str),
            Some("bubblewrap" | "microvm")
        )
        && health_bool(sandbox, "installed") == Some(true)
        && health_bool(sandbox, "enforcement_self_test_passed") == Some(true)
        && health_bool(sandbox, "enforcement_downgraded") == Some(false)
        && health_bool(sandbox, "fresh_candidate_verification") == Some(true)
        && health_bool(sandbox, "tool_network_policy_enforced") == Some(true)
        && health_bool(sandbox, "verification_network_disabled") == Some(true)
        && [
            "provider_credentials",
            "ctxlane_socket",
            "github_credentials",
            "asf_credentials",
            "backlog_credentials",
            "host_ssh_agent",
            "cloud_metadata",
            "other_workspaces",
            "docker_socket",
            "mcp_control_endpoint",
        ]
        .into_iter()
        .all(|proof| health_bool(denial_proofs, proof) == Some(true))
        && health_bool(ctxlane, "reachable") == Some(true)
        && health_bool(ctxlane, "mutually_authenticated") == Some(true)
        && health_bool(ctxlane, "automation_lease_probe_passed") == Some(true)
        && health_bool(github, "credential_in_controller") == Some(true)
        && health_bool(github, "reachable") == Some(true)
        && health_bool(github, "authenticated") == Some(true)
        && health_bool(github, "repository_reachable") == Some(true)
        && health_bool(github, "branch_push_allowed") == Some(true)
        && health_bool(github, "pull_request_create_allowed") == Some(true)
        && health_bool(github, "exact_head_observation_ready") == Some(true)
        && health_bool(github, "ci_context_read_ready") == Some(true)
        && health_bool(github, "reconciliation_ready") == Some(true)
        && health_bool(github, "merge_allowed") == Some(false)
        && health_bool(github, "administration_allowed") == Some(false)
        && health_bool(mcp, "private_control_ready") == Some(true)
        && health_bool(mcp, "controller_authenticated") == Some(true)
        && health_bool(mcp, "exposed_to_workers") == Some(false)
        && health_bool(backlog, "selection_enabled") == Some(false)
        && health_bool(backlog, "mutations_enabled") == Some(false)
}

/// Bound READY to a recent, internally coherent observation.  Transport
/// authenticity does not make a replayed health report current.
pub(crate) fn runmill_ready_health_is_fresh(
    report: &RunmillHealthReport,
    now: DateTime<Utc>,
) -> bool {
    const MAX_AGE_MS: i64 = 60_000;
    const MAX_FUTURE_SKEW_MS: i64 = 5_000;
    const AGE_TOLERANCE_MS: i64 = 5_000;

    fn is_current(
        now: DateTime<Utc>,
        observed_at: DateTime<Utc>,
        max_age_ms: i64,
        max_future_skew_ms: i64,
    ) -> bool {
        let age = now.signed_duration_since(observed_at).num_milliseconds();
        (-max_future_skew_ms..=max_age_ms).contains(&age)
    }

    if !is_current(now, report.checked_at, MAX_AGE_MS, MAX_FUTURE_SKEW_MS) {
        return false;
    }
    for component in [
        &report.components.service,
        &report.components.database,
        &report.components.worker,
        &report.components.sandbox,
        &report.components.ctxlane,
        &report.components.github,
        &report.components.mcp,
        &report.components.backlog,
    ] {
        let Some(observed_at) = component.observed_at else {
            return false;
        };
        let Some(reported_age) = component.age_ms.and_then(|age| i64::try_from(age).ok()) else {
            return false;
        };
        let derived_age = report
            .checked_at
            .signed_duration_since(observed_at)
            .num_milliseconds();
        if !is_current(now, observed_at, MAX_AGE_MS, MAX_FUTURE_SKEW_MS)
            || derived_age < -MAX_FUTURE_SKEW_MS
            || derived_age.abs_diff(reported_age) > AGE_TOLERANCE_MS.unsigned_abs()
        {
            return false;
        }
    }

    let Some(worker) = health_details(&report.components.worker) else {
        return false;
    };
    let Some(heartbeat_at) = worker
        .get("heartbeat_at")
        .and_then(Value::as_str)
        .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc))
    else {
        return false;
    };
    let Some(reported_heartbeat_age) =
        health_u64(worker, "heartbeat_age_ms").and_then(|age| i64::try_from(age).ok())
    else {
        return false;
    };
    let derived_heartbeat_age = report
        .checked_at
        .signed_duration_since(heartbeat_at)
        .num_milliseconds();
    is_current(now, heartbeat_at, MAX_AGE_MS, MAX_FUTURE_SKEW_MS)
        && derived_heartbeat_age >= -MAX_FUTURE_SKEW_MS
        && derived_heartbeat_age.abs_diff(reported_heartbeat_age) <= AGE_TOLERANCE_MS.unsigned_abs()
}

fn health_details(component: &RunmillHealthComponent) -> Option<&Map<String, Value>> {
    (component.status == RunmillHealthStatus::Ready
        && component.reasons.is_empty()
        && component.observed_at.is_some()
        && component.age_ms.is_some())
    .then_some(component.details.as_ref()?.as_object())?
}

fn health_bool(details: &Map<String, Value>, key: &str) -> Option<bool> {
    details.get(key).and_then(Value::as_bool)
}

fn health_u64(details: &Map<String, Value>, key: &str) -> Option<u64> {
    details.get(key).and_then(Value::as_u64)
}

const DEGRADED_HEALTH_REASONS: &[&str] = &[
    "service.recovering",
    "service.stopping",
    "service.not_accepting",
    "worker.capacity_full",
    "worker.queue_nonempty",
    "ctxlane.unreachable",
    "ctxlane.lease_unavailable",
    "github.unreachable",
    "github.unauthenticated",
    "github.capability_unavailable",
    "mcp.control_unavailable",
    "mcp.controller_unauthenticated",
];

const HEALTH_REASONS: &[&str] = &[
    "observation.missing",
    "observation.invalid",
    "observation.stale",
    "observation.future",
    "probe.failed",
    "probe.timeout",
    "service.recovering",
    "service.stopping",
    "service.not_accepting",
    "service.contradictory",
    "database.unreachable",
    "database.schema_mismatch",
    "database.integrity_failed",
    "database.write_failed",
    "database.contradictory",
    "worker.heartbeat_stale",
    "worker.heartbeat_future",
    "worker.scheduler_stopped",
    "worker.fencing_unavailable",
    "worker.concurrency_mismatch",
    "worker.capacity_contradictory",
    "worker.capacity_full",
    "worker.queue_nonempty",
    "sandbox.mechanism_mismatch",
    "sandbox.unavailable",
    "sandbox.enforcement_failed",
    "sandbox.downgraded",
    "sandbox.verification_unavailable",
    "sandbox.network_unenforced",
    "sandbox.denial_proof_failed",
    "ctxlane.unreachable",
    "ctxlane.unauthenticated",
    "ctxlane.lease_unavailable",
    "ctxlane.contradictory",
    "github.credential_boundary_failed",
    "github.unreachable",
    "github.unauthenticated",
    "github.capability_unavailable",
    "github.excess_authority",
    "github.contradictory",
    "mcp.control_unavailable",
    "mcp.controller_unauthenticated",
    "mcp.exposed_to_worker",
    "mcp.contradictory",
    "backlog.selection_enabled",
    "backlog.mutations_enabled",
];

fn validate_health_details(name: &str, value: &Value) -> RunmillControlResult<()> {
    let keys: &[&str] = match name {
        "service" => &[
            "mode",
            "state",
            "accepting_submissions",
            "recovery_complete",
        ],
        "database" => &[
            "reachable",
            "schema_version",
            "integrity_check_passed",
            "write_probe_passed",
            "expected_schema_version",
        ],
        "worker" => &[
            "heartbeat_at",
            "scheduler_running",
            "fencing_store_ready",
            "max_concurrency",
            "active_runs",
            "queued_runs",
            "expected_max_concurrency",
            "heartbeat_age_ms",
            "available_capacity",
        ],
        "sandbox" => &[
            "mechanism",
            "installed",
            "enforcement_self_test_passed",
            "enforcement_downgraded",
            "fresh_candidate_verification",
            "tool_network_policy_enforced",
            "verification_network_disabled",
            "denial_proofs",
        ],
        "ctxlane" => &[
            "reachable",
            "mutually_authenticated",
            "automation_lease_probe_passed",
        ],
        "github" => &[
            "credential_in_controller",
            "reachable",
            "authenticated",
            "repository_reachable",
            "branch_push_allowed",
            "pull_request_create_allowed",
            "exact_head_observation_ready",
            "ci_context_read_ready",
            "reconciliation_ready",
            "merge_allowed",
            "administration_allowed",
        ],
        "mcp" => &[
            "private_control_ready",
            "controller_authenticated",
            "exposed_to_workers",
        ],
        "backlog" => &["selection_enabled", "mutations_enabled"],
        _ => return Err(RunmillControlError::MalformedResponse),
    };
    let details = require_exact_object(value, keys)?;
    match name {
        "service" => {
            if details.get("mode").and_then(Value::as_str) != Some("asf-worker")
                || !matches!(
                    details.get("state").and_then(Value::as_str),
                    Some("running" | "recovering" | "stopping")
                )
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        "worker" => {
            if !details
                .get("heartbeat_at")
                .and_then(Value::as_str)
                .is_some_and(valid_timestamp)
            {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        "sandbox" => {
            if !matches!(
                details.get("mechanism").and_then(Value::as_str),
                Some("bubblewrap" | "microvm" | "seatbelt" | "none")
            ) {
                return Err(RunmillControlError::MalformedResponse);
            }
            let denial = require_exact_object(
                details
                    .get("denial_proofs")
                    .ok_or(RunmillControlError::MalformedResponse)?,
                &[
                    "provider_credentials",
                    "ctxlane_socket",
                    "github_credentials",
                    "asf_credentials",
                    "backlog_credentials",
                    "host_ssh_agent",
                    "cloud_metadata",
                    "other_workspaces",
                    "docker_socket",
                    "mcp_control_endpoint",
                ],
            )?;
            if denial.values().any(|value| !value.is_boolean()) {
                return Err(RunmillControlError::MalformedResponse);
            }
        }
        _ => {}
    }
    for (key, field) in details {
        if matches!(
            key.as_str(),
            "mode" | "state" | "heartbeat_at" | "mechanism" | "denial_proofs"
        ) {
            continue;
        }
        if key.ends_with("_version")
            || key.ends_with("_concurrency")
            || key.ends_with("_runs")
            || key.ends_with("_ms")
            || key == "max_concurrency"
            || key == "queued_runs"
            || key == "available_capacity"
        {
            if !field.is_null() && field.as_u64().is_none_or(|number| number > 2_147_483_647) {
                return Err(RunmillControlError::MalformedResponse);
            }
        } else if !field.is_boolean() {
            return Err(RunmillControlError::MalformedResponse);
        }
    }
    Ok(())
}

fn require_response_object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> RunmillControlResult<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or(RunmillControlError::MalformedResponse)?;
    if !exact_keys(object, keys) {
        return Err(RunmillControlError::MalformedResponse);
    }
    Ok(object)
}

fn validate_run_row_raw(value: &Value) -> RunmillControlResult<()> {
    require_response_object(
        value,
        &[
            "runId",
            "issueId",
            "repo",
            "provider",
            "state",
            "stateVersion",
            "attempt",
            "baseCommit",
            "candidateSha",
            "branch",
            "mode",
            "workOrderId",
            "attemptId",
            "generation",
            "ownerId",
            "heartbeatAt",
        ],
    )?;
    Ok(())
}

fn validate_event_raw(value: &Value) -> RunmillControlResult<()> {
    require_response_object(
        value,
        &[
            "schema",
            "event_id",
            "run_id",
            "work_order_id",
            "attempt_id",
            "seq",
            "occurred_at",
            "type",
            "phase",
            "payload",
            "policy_digest",
        ],
    )?;
    Ok(())
}

fn require_exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> RunmillControlResult<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or(RunmillControlError::MalformedResponse)?;
    if !exact_keys(object, keys) {
        return Err(RunmillControlError::MalformedResponse);
    }
    Ok(object)
}

fn nested_exact<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    keys: &[&str],
) -> RunmillControlResult<&'a Map<String, Value>> {
    require_exact_object(
        object.get(key).ok_or(RunmillControlError::InvalidRequest(
            "Work Order field is missing",
        ))?,
        keys,
    )
    .map_err(|_| RunmillControlError::InvalidRequest("Work Order object shape is malformed"))
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn exact_required_optional(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> bool {
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn require_literal(
    object: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> RunmillControlResult<()> {
    if object.get(key).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        invalid_request("Runmill Work Order schema or algorithm is incompatible")
    }
}

fn require_string<'a>(object: &'a Map<String, Value>, key: &str) -> RunmillControlResult<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(RunmillControlError::InvalidRequest(
            "Runmill Work Order string field is malformed",
        ))
}

fn require_identifier_field(
    object: &Map<String, Value>,
    key: &str,
    max: usize,
    allow_colon: bool,
) -> RunmillControlResult<()> {
    if valid_identifier(require_string(object, key)?, max, allow_colon) {
        Ok(())
    } else {
        invalid_request("Runmill Work Order identifier is malformed")
    }
}

fn require_timestamp_field(object: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    if valid_timestamp(require_string(object, key)?) {
        Ok(())
    } else {
        invalid_request("Runmill Work Order timestamp is malformed")
    }
}

fn require_string_array(
    object: &Map<String, Value>,
    key: &str,
    nonempty: bool,
    max_item: usize,
) -> RunmillControlResult<()> {
    let values =
        object
            .get(key)
            .and_then(Value::as_array)
            .ok_or(RunmillControlError::InvalidRequest(
                "Runmill Work Order array is malformed",
            ))?;
    if (nonempty && values.is_empty())
        || values.iter().any(|value| {
            !value
                .as_str()
                .is_some_and(|text| valid_public_string(text, max_item))
        })
    {
        return invalid_request("Runmill Work Order array is malformed");
    }
    Ok(())
}

fn require_positive_safe_integer(
    object: &Map<String, Value>,
    key: &str,
) -> RunmillControlResult<()> {
    if object
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|number| (1..=MAX_SAFE_INTEGER).contains(&number))
    {
        Ok(())
    } else {
        invalid_request("Runmill Work Order budget is malformed")
    }
}

fn require_nonnegative_safe_integer(
    object: &Map<String, Value>,
    key: &str,
) -> RunmillControlResult<()> {
    if object
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|number| number <= MAX_SAFE_INTEGER)
    {
        Ok(())
    } else {
        invalid_request("Runmill Work Order budget is malformed")
    }
}

fn require_nonnegative_number(object: &Map<String, Value>, key: &str) -> RunmillControlResult<()> {
    if object
        .get(key)
        .and_then(Value::as_f64)
        .is_some_and(|number| number.is_finite() && number >= 0.0)
    {
        Ok(())
    } else {
        invalid_request("Runmill Work Order budget is malformed")
    }
}

fn require_digest(value: &str) -> RunmillControlResult<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(RunmillControlError::MalformedResponse)
    }
}

fn require_request_digest(value: &str) -> RunmillControlResult<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        invalid_request("digest is malformed")
    }
}

fn invalid_request<T>(message: &'static str) -> RunmillControlResult<T> {
    Err(RunmillControlError::InvalidRequest(message))
}

fn valid_identifier(value: &str, max: usize, allow_colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
                || (allow_colon && byte == b':')
        })
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 768
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn valid_public_string(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
}

fn valid_timestamp(value: &str) -> bool {
    value.len() <= 64 && value.parse::<DateTime<Utc>>().is_ok()
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| digest.len() == 64 && lower_hex(digest))
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_git_sha(value: &str, allow_uppercase: bool) -> bool {
    value.len() == 40
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || (b'a'..=b'f').contains(&byte)
                || (allow_uppercase && (b'A'..=b'F').contains(&byte))
        })
}

fn valid_repository(value: &str) -> bool {
    value.split_once('/').is_some_and(|(owner, name)| {
        !owner.is_empty()
            && !name.is_empty()
            && !name.contains('/')
            && !owner.chars().any(char::is_whitespace)
            && !name.chars().any(char::is_whitespace)
    })
}

fn valid_branch_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.contains("//")
        && !branch.ends_with(['/', '.'])
        && !branch.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || component.as_bytes().ends_with(b".lock")
        })
        && !branch.bytes().any(|byte| {
            byte <= 0x20
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn valid_media_type(value: &str) -> bool {
    value.split_once('/').is_some_and(|(kind, subtype)| {
        !kind.is_empty()
            && !subtype.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                    )
            })
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::Permissions,
        io::Write as _,
        os::unix::fs::PermissionsExt as _,
        sync::{Arc, Mutex},
    };

    use tempfile::TempDir;
    use tokio::{net::UnixListener, task::JoinHandle};

    use super::*;

    const NOW: &str = "2026-08-21T12:00:00Z";
    const SHA: &str = "0123456789012345678901234567890123456789";

    #[derive(Debug)]
    enum FixtureResponse {
        Json(Value),
        Raw(Vec<u8>),
        Close,
        Delay(Duration),
        Oversize,
    }

    impl FixtureResponse {
        fn success(data: Value) -> Self {
            let mut response = Map::new();
            response.insert("ok".into(), Value::Bool(true));
            response.insert("data".into(), data);
            Self::Json(Value::Object(response))
        }
    }

    fn success_wire(data: &Value) -> Vec<u8> {
        let response = json!({"ok": true, "data": data});
        let mut wire = b" \t".to_vec();
        wire.extend(serde_json::to_vec(&response).expect("encode success response"));
        wire.extend(b" \n");
        wire
    }

    struct ControlFixture {
        _directory: TempDir,
        registry_path: PathBuf,
        socket_path: PathBuf,
        requests: Arc<Mutex<Vec<Value>>>,
        server: JoinHandle<()>,
    }

    impl ControlFixture {
        fn new(responses: Vec<FixtureResponse>) -> Self {
            Self::with_protocol(responses, RUNMILL_CONTROL_PROTOCOL_VERSION)
        }

        fn with_protocol(responses: Vec<FixtureResponse>, protocol_version: u16) -> Self {
            let directory = tempfile::tempdir().expect("create fixture runtime directory");
            fs::set_permissions(
                directory.path(),
                Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )
            .expect("secure fixture runtime directory");
            let socket_path = directory.path().join("control.sock");
            let registry_path = directory.path().join("daemon.json");
            let listener = UnixListener::bind(&socket_path).expect("bind fixture socket");
            fs::set_permissions(&socket_path, Permissions::from_mode(PRIVATE_FILE_MODE))
                .expect("secure fixture socket");
            let registry = json!({
                "protocolVersion": protocol_version,
                "pid": std::process::id(),
                "socketPath": socket_path,
                "startedAt": NOW,
                "repoRoot": "/srv/repository",
                "configPath": "/srv/repository/runmill.json"
            });
            write_registry(&registry_path, &registry);

            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&requests);
            let server = tokio::spawn(async move {
                for response in responses {
                    let (mut stream, _) = listener.accept().await.expect("accept fixture request");
                    let mut request = Vec::new();
                    let mut byte = [0_u8; 1];
                    loop {
                        let count = stream.read(&mut byte).await.expect("read fixture request");
                        if count == 0 || byte[0] == b'\n' {
                            break;
                        }
                        request.push(byte[0]);
                        assert!(request.len() <= RUNMILL_MAX_CONTROL_BYTES);
                    }
                    let request = serde_json::from_slice(&request).expect("parse fixture request");
                    captured
                        .lock()
                        .expect("lock captured requests")
                        .push(request);

                    match response {
                        FixtureResponse::Json(value) => {
                            let mut bytes = serde_json::to_vec(&value).expect("encode response");
                            bytes.push(b'\n');
                            stream.write_all(&bytes).await.expect("write response");
                        }
                        FixtureResponse::Raw(bytes) => {
                            stream.write_all(&bytes).await.expect("write raw response");
                        }
                        FixtureResponse::Close => {}
                        FixtureResponse::Delay(duration) => tokio::time::sleep(duration).await,
                        FixtureResponse::Oversize => {
                            let bytes = vec![b'x'; RUNMILL_MAX_CONTROL_BYTES + 1];
                            let _ = stream.write_all(&bytes).await;
                        }
                    }
                }
            });

            Self {
                _directory: directory,
                registry_path,
                socket_path,
                requests,
                server,
            }
        }

        fn client(&self, timeout: Duration) -> RunmillControlClient {
            RunmillControlClient::new(self.registry_path.clone(), timeout)
                .expect("construct fixture client")
        }

        fn requests(&self) -> Vec<Value> {
            self.requests
                .lock()
                .expect("lock captured requests")
                .clone()
        }
    }

    impl Drop for ControlFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn write_registry(path: &Path, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE)
            .open(path)
            .expect("open fixture registry");
        serde_json::to_writer(&mut file, value).expect("write fixture registry");
        file.flush().expect("flush fixture registry");
        fs::set_permissions(path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("secure fixture registry");
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn run_row() -> Value {
        json!({
            "runId": "run-1",
            "issueId": "issue-1",
            "repo": "acme/app",
            "provider": "ctxlane",
            "state": "ADMITTED",
            "stateVersion": 1,
            "attempt": 1,
            "baseCommit": SHA,
            "candidateSha": null,
            "branch": null,
            "mode": "asf-worker",
            "workOrderId": "work-order-1",
            "attemptId": "attempt-1",
            "generation": 0,
            "ownerId": null,
            "heartbeatAt": null
        })
    }

    fn run_snapshot() -> Value {
        json!({
            "run": run_row(),
            "admission": {
                "idempotencyKey": "tenant/work-order-1/attempt-1",
                "workOrderId": "work-order-1",
                "attemptId": "attempt-1",
                "tenantId": "tenant-1",
                "payloadDigest": digest('a'),
                "envelopeDigest": digest('b'),
                "effectivePolicyDigest": digest('c'),
                "signatureKeyId": "key-1",
                "signatureAlgorithm": "EdDSA",
                "acceptedAt": NOW
            },
            "latestSequence": 1
        })
    }

    fn event_page() -> Value {
        json!({
            "events": [],
            "nextCursor": 1,
            "hasMore": false,
            "gap": false,
            "compactedThrough": null,
            "snapshot": {"run": run_row(), "latestSequence": 1}
        })
    }

    fn run_event(event_type: &str, phase: &str, sequence: u64, payload: &Value) -> RunmillRunEvent {
        serde_json::from_value(json!({
            "schema": RUNMILL_RUN_EVENT_SCHEMA,
            "event_id": format!("event-{sequence}"),
            "run_id": "run-1",
            "work_order_id": "work-order-1",
            "attempt_id": "attempt-1",
            "seq": sequence,
            "occurred_at": NOW,
            "type": event_type,
            "phase": phase,
            "payload": payload,
            "policy_digest": digest('f'),
        }))
        .expect("parse Runmill event fixture")
    }

    fn identity_attribution(role: &str) -> Value {
        json!({
            "schema": "asf.identity-lease-attribution/v1",
            "role": role,
            "provider": "ctxlane",
            "principal_id": format!("principal-{role}"),
            "profile": "default",
            "fencing_generation": 1,
            "issued_at": NOW,
            "expires_at": "2026-08-21T13:00:00Z",
            "lease_attribution_digest": digest('a'),
        })
    }

    fn event_check(outcome: &str) -> Value {
        json!({
            "context": "ci/test",
            "outcome": outcome,
            "evidence_digest": digest('e'),
        })
    }

    fn evidence_view() -> Value {
        json!({
            "schema": RUNMILL_EVIDENCE_VIEW_SCHEMA,
            "runId": "run-1",
            "workOrderId": "work-order-1",
            "attemptId": "attempt-1",
            "phase": "ADMITTED",
            "candidateSha": null,
            "policyDigest": digest('c'),
            "latestSequence": 1,
            "status": "current",
            "complete": false,
            "bundleDigest": null,
            "artifacts": [],
            "latestEvent": null,
            "signedBundle": null,
            "terminalBundleDigest": null,
            "signedTerminalBundle": null
        })
    }

    fn ready_component(details: Value) -> Value {
        let mut component = Map::new();
        component.insert("status".into(), Value::String("ready".into()));
        component.insert("observed_at".into(), Value::String(NOW.into()));
        component.insert("age_ms".into(), Value::from(0));
        component.insert("reasons".into(), Value::Array(Vec::new()));
        component.insert("details".into(), details);
        Value::Object(component)
    }

    fn health_report() -> Value {
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
        json!({
            "schema": RUNMILL_HEALTH_SCHEMA,
            "mode": "asf-worker",
            "checked_at": NOW,
            "probe_duration_ms": 1,
            "status": "ready",
            "ready": true,
            "components": {
                "service": ready_component(json!({
                    "mode": "asf-worker", "state": "running",
                    "accepting_submissions": true, "recovery_complete": true
                })),
                "database": ready_component(json!({
                    "reachable": true, "schema_version": 1,
                    "integrity_check_passed": true, "write_probe_passed": true,
                    "expected_schema_version": 1
                })),
                "worker": ready_component(json!({
                    "heartbeat_at": NOW, "scheduler_running": true,
                    "fencing_store_ready": true, "max_concurrency": 1,
                    "active_runs": 0, "queued_runs": 0,
                    "expected_max_concurrency": 1, "heartbeat_age_ms": 0,
                    "available_capacity": 1
                })),
                "sandbox": ready_component(json!({
                    "mechanism": "bubblewrap", "installed": true,
                    "enforcement_self_test_passed": true,
                    "enforcement_downgraded": false,
                    "fresh_candidate_verification": true,
                    "tool_network_policy_enforced": true,
                    "verification_network_disabled": true,
                    "denial_proofs": denial_proofs
                })),
                "ctxlane": ready_component(json!({
                    "reachable": true, "mutually_authenticated": true,
                    "automation_lease_probe_passed": true
                })),
                "github": ready_component(json!({
                    "credential_in_controller": true, "reachable": true,
                    "authenticated": true, "repository_reachable": true,
                    "branch_push_allowed": true, "pull_request_create_allowed": true,
                    "exact_head_observation_ready": true, "ci_context_read_ready": true,
                    "reconciliation_ready": true, "merge_allowed": false,
                    "administration_allowed": false
                })),
                "mcp": ready_component(json!({
                    "private_control_ready": true, "controller_authenticated": true,
                    "exposed_to_workers": false
                })),
                "backlog": ready_component(json!({
                    "selection_enabled": false, "mutations_enabled": false
                }))
            }
        })
    }

    fn exact_work_order_value() -> Value {
        json!({
            "schema": RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA,
            "key_id": "key-1",
            "algorithm": "EdDSA",
            "issued_at": NOW,
            "not_before": NOW,
            "expires_at": "2026-08-21T13:00:00Z",
            "payload": {
                "schema": RUNMILL_WORK_ORDER_SCHEMA,
                "work_order_id": "work-order-1",
                "tenant_id": "tenant-1",
                "work_item_id": "work-item-1",
                "attempt_id": "attempt-1",
                "idempotency_key": "tenant/work-order-1/attempt-1",
                "source": {
                    "system": "linear", "external_id": "LIN-1",
                    "snapshot_digest": digest('d')
                },
                "repository": {
                    "forge": "github", "repository": "acme/app",
                    "base_ref": "refs/heads/main", "base_sha": SHA
                },
                "objective": {
                    "title": "Implement change", "description": "Exact bounded objective",
                    "acceptance_criteria": ["Tests pass"], "non_goals": []
                },
                "scope": {
                    "allowed_paths": ["src/**"], "forbidden_paths": [".git/**"],
                    "risk_class": "low"
                },
                "verification": {
                    "required_local_check_ids": ["test"], "required_remote_checks": ["ci"],
                    "policy_snapshot_digest": digest('e')
                },
                "identities": {
                    "implementer": "codex:implementer",
                    "local_reviewer": "claude:local-reviewer",
                    "pr_reviewer": "claude:pr-reviewer"
                },
                "runtime": {
                    "sandbox_profile": "sandbox-v1", "tool_policy": "tools-v1",
                    "network_policy": "network-v1"
                },
                "budgets": {
                    "wall_seconds": 600, "max_cost_usd": 1.25,
                    "max_agent_invocations": 3, "max_fix_iterations": 1
                },
                "delivery": {
                    "closure_target": "pr", "draft_pr": true, "merge_policy_ref": null
                },
                "policy_digest": digest('f'),
                "harness_digest": digest('0')
            },
            "signature": "base64url:AQ"
        })
    }

    #[tokio::test]
    async fn binds_read_operations_to_exact_ndjson_requests() {
        let fixture = ControlFixture::new(vec![
            FixtureResponse::success(health_report()),
            FixtureResponse::success(run_snapshot()),
            FixtureResponse::success(event_page()),
            FixtureResponse::success(evidence_view()),
        ]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        client.health().await.unwrap();
        client.get_run(&run_id).await.unwrap();
        client.list_run_events(&run_id, 1, 100).await.unwrap();
        client.get_evidence(&run_id).await.unwrap();

        assert_eq!(
            fixture.requests(),
            vec![
                json!({"type": "asf.health"}),
                json!({"type": "asf.get_run", "runId": "run-1"}),
                json!({
                    "type": "asf.list_run_events", "runId": "run-1",
                    "after": 1, "limit": 100
                }),
                json!({"type": "asf.get_evidence", "runId": "run-1"})
            ]
        );
    }

    #[tokio::test]
    async fn validated_reads_preserve_exact_wire_and_parsed_data() {
        let snapshot_data = run_snapshot();
        let event_page_data = event_page();
        let snapshot_wire = success_wire(&snapshot_data);
        let event_page_wire = success_wire(&event_page_data);
        let fixture = ControlFixture::new(vec![
            FixtureResponse::Raw(snapshot_wire.clone()),
            FixtureResponse::Raw(event_page_wire.clone()),
        ]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let snapshot = client.get_run_with_provenance(&run_id).await.unwrap();
        let events = client
            .list_run_events_with_provenance(&run_id, 1, 100)
            .await
            .unwrap();

        assert_eq!(snapshot.response_wire, snapshot_wire);
        assert_eq!(snapshot.data, snapshot_data);
        assert_eq!(
            snapshot.value,
            serde_json::from_value::<RunmillRunSnapshot>(snapshot.data.clone()).unwrap()
        );
        assert_eq!(events.response_wire, event_page_wire);
        assert_eq!(events.data, event_page_data);
        assert_eq!(
            events.value,
            serde_json::from_value::<RunmillEventPage>(events.data.clone()).unwrap()
        );
    }

    #[tokio::test]
    async fn validated_evidence_read_preserves_exact_wire_and_parsed_data() {
        let evidence_data = evidence_view();
        let evidence_wire = success_wire(&evidence_data);
        let fixture = ControlFixture::new(vec![FixtureResponse::Raw(evidence_wire.clone())]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let evidence = client.get_evidence_with_provenance(&run_id).await.unwrap();

        assert_eq!(evidence.response_wire, evidence_wire);
        assert_eq!(evidence.data, evidence_data);
        assert_eq!(
            evidence.value,
            serde_json::from_value::<RunmillEvidenceView>(evidence.data.clone()).unwrap()
        );
    }

    #[tokio::test]
    async fn legacy_read_methods_remain_compatible() {
        let snapshot_data = run_snapshot();
        let event_page_data = event_page();
        let fixture = ControlFixture::new(vec![
            FixtureResponse::success(snapshot_data.clone()),
            FixtureResponse::success(event_page_data.clone()),
        ]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        assert_eq!(
            client.get_run(&run_id).await.unwrap(),
            serde_json::from_value::<RunmillRunSnapshot>(snapshot_data).unwrap()
        );
        assert_eq!(
            client.list_run_events(&run_id, 1, 100).await.unwrap(),
            serde_json::from_value::<RunmillEventPage>(event_page_data).unwrap()
        );
    }

    #[tokio::test]
    async fn validated_reads_keep_malformed_and_remote_errors_public_safe() {
        let run_id = RunmillRunId::parse("run-1").unwrap();
        let legacy_malformed = ControlFixture::new(vec![FixtureResponse::success(json!({}))]);
        assert!(matches!(
            legacy_malformed
                .client(Duration::from_secs(1))
                .get_run(&run_id)
                .await,
            Err(RunmillControlError::MalformedResponse)
        ));

        let malformed = ControlFixture::new(vec![FixtureResponse::success(json!({}))]);
        assert!(matches!(
            malformed
                .client(Duration::from_secs(1))
                .get_run_with_provenance(&run_id)
                .await,
            Err(RunmillControlError::MalformedResponse)
        ));

        let remote_narrative = "private daemon diagnostic";
        let remote = ControlFixture::new(vec![FixtureResponse::Json(json!({
            "ok": false,
            "error": remote_narrative,
        }))]);
        let error = remote
            .client(Duration::from_secs(1))
            .list_run_events_with_provenance(&run_id, 1, 100)
            .await
            .unwrap_err();
        assert!(matches!(error, RunmillControlError::RemoteRejected));
        assert!(!format!("{error:?} {error}").contains(remote_narrative));

        let legacy_remote = ControlFixture::new(vec![FixtureResponse::Json(json!({
            "ok": false,
            "error": remote_narrative,
        }))]);
        let error = legacy_remote
            .client(Duration::from_secs(1))
            .list_run_events(&run_id, 1, 100)
            .await
            .unwrap_err();
        assert!(matches!(error, RunmillControlError::RemoteRejected));
        assert!(!format!("{error:?} {error}").contains(remote_narrative));
    }

    #[tokio::test]
    async fn ready_health_rejects_false_production_proofs() {
        let mut unsafe_report = health_report();
        unsafe_report["components"]["sandbox"]["details"]["denial_proofs"]["provider_credentials"] =
            false.into();
        let fixture = ControlFixture::new(vec![FixtureResponse::success(unsafe_report)]);
        assert!(matches!(
            fixture
                .client(Duration::from_secs(1))
                .health()
                .await
                .expect_err("a READY bit cannot override a failed denial proof"),
            RunmillControlError::MalformedResponse
        ));
    }

    #[tokio::test]
    async fn binds_mutations_exactly_and_checks_result_identity() {
        let envelope = RunmillWorkOrderEnvelope::parse(exact_work_order_value()).unwrap();
        let payload_digest = envelope.payload_digest().unwrap();
        let run_id = RunmillRunId::parse("run-1").unwrap();
        let cancellation = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: "cancel-1".into(),
            run_id: run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "operator:alice".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        let request_digest = cancellation.digest().unwrap();
        let bundle_digest = digest('2');
        let fixture = ControlFixture::new(vec![
            FixtureResponse::success(json!({
                "runId": "run-1", "disposition": "accepted",
                "payloadDigest": payload_digest
            })),
            FixtureResponse::success(json!({
                "requestId": "cancel-1", "runId": "run-1", "disposition": "requested",
                "state": "CANCEL_REQUESTED", "generation": 1,
                "requestDigest": request_digest, "reconciliationRequired": true
            })),
            FixtureResponse::success(json!({
                "acknowledgementId": "ack-1", "runId": "run-1",
                "bundleDigest": bundle_digest, "disposition": "recorded",
                "acknowledgedAt": NOW
            })),
        ]);
        let client = fixture.client(Duration::from_secs(1));
        let acknowledgement = RunmillOutcomeAcknowledgement {
            schema: RUNMILL_OUTCOME_ACKNOWLEDGEMENT_SCHEMA.into(),
            acknowledgement_id: "ack-1".into(),
            run_id,
            bundle_digest: bundle_digest.clone(),
            acknowledged_by: RunmillAcknowledgedBy {
                subject: "asf:controller".into(),
                authority: "asf:acknowledge-outcome".into(),
            },
        };

        client.submit_work_order(&envelope).await.unwrap();
        client.request_cancel(&cancellation).await.unwrap();
        client.acknowledge_outcome(&acknowledgement).await.unwrap();

        let requests = fixture.requests();
        assert_eq!(
            requests[0],
            json!({"type": "asf.submit_work_order", "envelope": exact_work_order_value()})
        );
        assert_eq!(
            requests[1],
            json!({"type": "asf.request_cancel", "request": cancellation})
        );
        assert_eq!(
            requests[2],
            json!({"type": "asf.acknowledge_outcome", "acknowledgement": acknowledgement})
        );
    }

    #[tokio::test]
    async fn cancellation_rejects_a_response_digest_not_bound_to_exact_request_jcs() {
        let run_id = RunmillRunId::parse("run-1").unwrap();
        let cancellation = RunmillCancellationRequest {
            schema: RUNMILL_CANCELLATION_SCHEMA.into(),
            request_id: "cancel-digest-check".into(),
            run_id: run_id.clone(),
            requester: RunmillCancellationRequester {
                subject: "asf:controller".into(),
                authority: "asf:cancel".into(),
            },
            reason: "Operator requested cancellation".into(),
            mode: RunmillCancellationMode::Graceful,
            grace_seconds: 30,
        };
        let fixture = ControlFixture::new(vec![FixtureResponse::success(json!({
            "requestId": cancellation.request_id,
            "runId": run_id,
            "disposition": "requested",
            "state": "CANCEL_REQUESTED",
            "generation": 1,
            "requestDigest": digest('f'),
            "reconciliationRequired": false
        }))]);
        let error = fixture
            .client(Duration::from_secs(1))
            .request_cancel(&cancellation)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RunmillControlError::AmbiguousOutcome {
                operation: RunmillControlOperation::RequestCancel,
                reason: AmbiguousControlFailure::MalformedResponse,
            }
        ));
    }

    #[tokio::test]
    async fn preserves_structured_recovery_metadata_but_redacts_diagnostics() {
        let response = json!({
            "ok": false,
            "error": "raw daemon narrative must not escape",
            "asfError": {
                "schema": RUNMILL_CONTROL_ERROR_SCHEMA,
                "code": "github.push_observation_unknown",
                "title": "sensitive title",
                "what_happened": "sensitive incident narrative",
                "why": "sensitive provider details",
                "fixes": [{"description": "sensitive fix", "command": "sensitive command"}],
                "docs_url": "https://runmill.dev/errors/push-observation",
                "recoverable": true,
                "run_id": "run-1",
                "checkpoint": "delivery",
                "retry_disposition": "reconcile-first",
                "required_actor": "repository-owner",
                "required_action": "Inspect the exact remote head",
                "evidence_refs": ["event:event-1"]
            }
        });
        let fixture = ControlFixture::new(vec![FixtureResponse::Json(response)]);
        let error = fixture
            .client(Duration::from_secs(1))
            .health()
            .await
            .unwrap_err();
        let RunmillControlError::RemoteAsf(structured) = &error else {
            panic!("expected structured Runmill error, got {error:?}");
        };
        assert_eq!(
            structured.retry_disposition,
            Some(RunmillRetryDisposition::ReconcileFirst)
        );
        assert_eq!(
            structured.required_actor,
            Some(RunmillRequiredActor::RepositoryOwner)
        );
        assert_eq!(
            structured.required_action.as_deref(),
            Some("Inspect the exact remote head")
        );
        assert_eq!(structured.evidence_refs, ["event:event-1"]);
        let diagnostics = format!("{error:?} {error}");
        for sensitive in [
            "raw daemon narrative",
            "sensitive incident narrative",
            "sensitive provider details",
            "sensitive command",
            "Inspect the exact remote head",
            "event:event-1",
        ] {
            assert!(!diagnostics.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn distinguishes_read_failures_from_ambiguous_mutation_outcomes() {
        let read_fixture =
            ControlFixture::new(vec![FixtureResponse::Delay(Duration::from_millis(200))]);
        assert!(matches!(
            read_fixture
                .client(Duration::from_millis(20))
                .health()
                .await,
            Err(RunmillControlError::Timeout)
        ));

        let envelope = RunmillWorkOrderEnvelope::parse(exact_work_order_value()).unwrap();
        let lost_fixture = ControlFixture::new(vec![FixtureResponse::Close]);
        assert!(matches!(
            lost_fixture
                .client(Duration::from_secs(1))
                .submit_work_order(&envelope)
                .await,
            Err(RunmillControlError::AmbiguousOutcome {
                operation: RunmillControlOperation::SubmitWorkOrder,
                reason: AmbiguousControlFailure::ResponseLost
            })
        ));

        let malformed_fixture = ControlFixture::new(vec![FixtureResponse::Raw(
            b"{\"ok\":true,\"data\":{}}".to_vec(),
        )]);
        assert!(matches!(
            malformed_fixture
                .client(Duration::from_secs(1))
                .submit_work_order(&envelope)
                .await,
            Err(RunmillControlError::AmbiguousOutcome {
                reason: AmbiguousControlFailure::MalformedResponse,
                ..
            })
        ));

        let oversize_fixture = ControlFixture::new(vec![FixtureResponse::Oversize]);
        assert!(matches!(
            oversize_fixture
                .client(Duration::from_secs(1))
                .health()
                .await,
            Err(RunmillControlError::ResponseTooLarge)
        ));
    }

    #[tokio::test]
    async fn rejects_insecure_or_incompatible_registry_and_socket_metadata() {
        let registry_fixture = ControlFixture::new(vec![FixtureResponse::success(health_report())]);
        fs::set_permissions(
            &registry_fixture.registry_path,
            Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            registry_fixture
                .client(Duration::from_secs(1))
                .health()
                .await,
            Err(RunmillControlError::InsecureRegistry(_))
        ));

        let socket_fixture = ControlFixture::new(vec![FixtureResponse::success(health_report())]);
        fs::set_permissions(&socket_fixture.socket_path, Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            socket_fixture.client(Duration::from_secs(1)).health().await,
            Err(RunmillControlError::InsecureSocket(_))
        ));

        let protocol_fixture = ControlFixture::with_protocol(
            vec![FixtureResponse::success(health_report())],
            RUNMILL_CONTROL_PROTOCOL_VERSION + 1,
        );
        assert!(matches!(
            protocol_fixture
                .client(Duration::from_secs(1))
                .health()
                .await,
            Err(RunmillControlError::UnsupportedProtocol { observed: 2 })
        ));
    }

    #[test]
    fn validates_expanded_runmill_event_contracts_strictly() {
        let identities = run_event(
            "identity.leases_acquired",
            "IDENTITY_READY",
            1,
            &json!({
                "attributions_digest": digest('a'),
                "roles": ["implementer", "local-reviewer", "pr-reviewer"],
                "attributions": [
                    identity_attribution("implementer"),
                    identity_attribution("local-reviewer"),
                    identity_attribution("pr-reviewer"),
                ],
            }),
        );
        assert!(identities.validate().is_ok());

        let rechecked = run_event(
            "ci.recheck_completed",
            "CI_WAIT",
            2,
            &json!({
                "candidate_sha": SHA,
                "outcome": "pending",
                "observation_intent_digest": digest('b'),
                "observation_digest": digest('c'),
                "observation_fencing_generation": 2,
                "checks_digest": digest('d'),
                "checks": [event_check("pending")],
                "observed_at": NOW,
            }),
        );
        assert!(rechecked.validate().is_ok());

        let delivered = run_event(
            "pull_request.delivered",
            "PR_DELIVERED",
            3,
            &json!({
                "candidate_sha": SHA, "repository": "acme/app", "number": 42,
                "url": "https://github.example/acme/app/pull/42",
                "head_ref": "refs/heads/asf/change", "base_ref": "refs/heads/main",
                "marker": "asf-change-42", "head_sha": SHA, "observed_head_sha": SHA,
                "current_base_sha": SHA, "collision_set_digest": digest('1'),
                "base_observation_digest": digest('2'), "protection_digest": digest('3'),
                "protection": {"required_checks": ["ci/test"], "requires_approval": true,
                    "requires_conversation_resolution": true, "uses_merge_queue": false},
                "state": "open", "draft": false,
                "delivery_observation_intent_digest": digest('4'),
                "delivery_observation_digest": digest('5'), "observed_at": NOW,
                "final_ci_observation_intent_digest": digest('6'),
                "final_ci_observation_digest": digest('7'),
                "final_ci_observation_fencing_generation": 3,
                "final_ci_checks_digest": digest('8'), "final_ci_checks": [event_check("passed")],
                "final_ci_observed_at": NOW,
            }),
        );
        assert!(delivered.validate().is_ok());

        let resumed = run_event(
            "run.resumed",
            "CANCELLING",
            4,
            &json!({
                "interrupted_phase": "BLOCKED_EXTERNAL", "resume_phase": "CANCELLING",
                "evidence_digest": digest('9'),
                "reconciliation": {"schema": "asf.reconciliation-continuation-result/v1",
                    "operation_id": "operation-1", "result_digest": digest('a'),
                    "pending_set_digest": digest('b'), "checkpoint_digest": digest('c'),
                    "blocked_event_id": "event-3", "interrupted_event_seq": 3,
                    "action": "continue-cancellation"},
            }),
        );
        assert!(resumed.validate().is_ok());

        let mut malformed = rechecked.clone();
        malformed.payload.remove("observed_at");
        assert!(matches!(
            malformed.validate(),
            Err(RunmillControlError::MalformedResponse)
        ));
        let mut unknown = identities.clone();
        unknown
            .payload
            .insert("unexpected".into(), Value::Bool(true));
        assert!(matches!(
            unknown.validate(),
            Err(RunmillControlError::MalformedResponse)
        ));
    }

    #[test]
    fn enforces_runmill_event_page_cursor_invariants() {
        let run_id = RunmillRunId::parse("run-1").unwrap();
        let mut page: RunmillEventPage = serde_json::from_value(event_page()).unwrap();
        page.snapshot.latest_sequence = 3;
        page.events = vec![
            run_event(
                "work_order.admitted",
                "ADMITTED",
                2,
                &json!({
                    "work_order_id": "work-order-1", "attempt_id": "attempt-1", "tenant_id": "tenant-1",
                    "payload_digest": digest('a'), "envelope_digest": digest('b'),
                    "signature": {"verified": true, "key_id": "key-1", "algorithm": "EdDSA"},
                }),
            ),
            run_event(
                "repository.lease_acquired",
                "REPOSITORY_LEASED",
                3,
                &json!({"repository": "acme/app", "generation": 1}),
            ),
        ];
        page.next_cursor = 3;
        page.has_more = false;
        page.gap = false;
        page.compacted_through = None;
        assert!(page.validate_for_request(&run_id, 1, 2).is_ok());

        let mut internal_hole = page.clone();
        internal_hole.events[1].seq = 4;
        internal_hole.next_cursor = 4;
        internal_hole.snapshot.latest_sequence = 4;
        internal_hole.snapshot.run.state_version = 4;
        assert!(matches!(
            <RunmillEventPage as ExactResponse>::validate(&internal_hole),
            Err(RunmillControlError::MalformedResponse)
        ));
        assert!(matches!(
            internal_hole.validate_for_request(&run_id, 1, 2),
            Err(RunmillControlError::MalformedResponse)
        ));

        page.gap = true;
        page.compacted_through = Some(1);
        assert!(page.validate_for_request(&run_id, 0, 2).is_ok());

        page.compacted_through = Some(2);
        assert!(matches!(
            page.validate_for_request(&run_id, 0, 2),
            Err(RunmillControlError::MalformedResponse)
        ));

        page.gap = false;
        page.compacted_through = None;
        page.has_more = true;
        assert!(matches!(
            page.validate_for_request(&run_id, 1, 2),
            Err(RunmillControlError::MalformedResponse)
        ));
    }

    #[test]
    fn parses_exact_work_order_envelope_and_validates_accessors() {
        let envelope_value = exact_work_order_value();
        let envelope = RunmillWorkOrderEnvelope::parse(envelope_value.clone())
            .expect("parse exact work order envelope");

        // Assert payload accessors return the expected values from the fixture
        assert_eq!(
            envelope.idempotency_key().unwrap(),
            "tenant/work-order-1/attempt-1"
        );
        assert_eq!(envelope.work_order_id().unwrap(), "work-order-1");
        assert_eq!(envelope.tenant_id().unwrap(), "tenant-1");
        assert_eq!(envelope.attempt_id().unwrap(), "attempt-1");

        // Assert idempotency key does not start with the internal effect key prefix
        assert!(
            !envelope
                .idempotency_key()
                .unwrap()
                .starts_with("runmill:submit:"),
            "envelope idempotency key should not use internal effect prefix"
        );

        // Assert payload_digest matches the canonical digest of just the payload
        let payload_digest = envelope.payload_digest().unwrap();
        let payload_object = envelope_value["payload"].as_object().unwrap();
        let canonical_payload = canonical_json(payload_object).expect("canonicalize payload");
        let expected_payload_digest = sha256_digest(&canonical_payload);
        assert_eq!(payload_digest, expected_payload_digest);

        // Assert envelope_digest matches the canonical digest of the entire envelope
        let envelope_digest = envelope.envelope_digest().unwrap();
        let canonical_envelope = canonical_json(&envelope_value).expect("canonicalize envelope");
        let expected_envelope_digest = sha256_digest(&canonical_envelope);
        assert_eq!(envelope_digest, expected_envelope_digest);

        // Assert idempotency with repeated parsing produces same digests
        let envelope2 = RunmillWorkOrderEnvelope::parse(envelope_value)
            .expect("re-parse exact work order envelope");
        assert_eq!(
            envelope.payload_digest().unwrap(),
            envelope2.payload_digest().unwrap()
        );
        assert_eq!(
            envelope.envelope_digest().unwrap(),
            envelope2.envelope_digest().unwrap()
        );
    }

    #[tokio::test]
    async fn reconcile_submission_uses_idempotency_key() {
        let envelope = RunmillWorkOrderEnvelope::parse(exact_work_order_value()).unwrap();
        let idempotency_key = envelope.idempotency_key().unwrap();
        let work_order_id = envelope.work_order_id().unwrap();
        let tenant_id = envelope.tenant_id().unwrap();
        let attempt_id = envelope.attempt_id().unwrap();
        let payload_digest = envelope.payload_digest().unwrap();
        let envelope_digest = envelope.envelope_digest().unwrap();

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] = Value::String(idempotency_key.to_string());
        snapshot["admission"]["workOrderId"] = Value::String(work_order_id.to_string());
        snapshot["admission"]["tenantId"] = Value::String(tenant_id.to_string());
        snapshot["admission"]["attemptId"] = Value::String(attempt_id.to_string());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["run"]["workOrderId"] = Value::String(work_order_id.to_string());
        snapshot["run"]["attemptId"] = Value::String(attempt_id.to_string());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        client.reconcile_submission(&envelope).await.unwrap();

        assert_eq!(
            fixture.requests(),
            vec![json!({
                "type": "asf.get_run",
                "idempotencyKey": "tenant/work-order-1/attempt-1"
            })]
        );
    }

    #[tokio::test]
    async fn reconcile_submission_detects_tenant_id_mismatch() {
        let envelope = RunmillWorkOrderEnvelope::parse(exact_work_order_value()).unwrap();
        let idempotency_key = envelope.idempotency_key().unwrap();
        let work_order_id = envelope.work_order_id().unwrap();
        let attempt_id = envelope.attempt_id().unwrap();
        let payload_digest = envelope.payload_digest().unwrap();
        let envelope_digest = envelope.envelope_digest().unwrap();

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] = Value::String(idempotency_key.to_string());
        snapshot["admission"]["workOrderId"] = Value::String(work_order_id.to_string());
        snapshot["admission"]["tenantId"] = "different-tenant".into();
        snapshot["admission"]["attemptId"] = Value::String(attempt_id.to_string());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["run"]["workOrderId"] = Value::String(work_order_id.to_string());
        snapshot["run"]["attemptId"] = Value::String(attempt_id.to_string());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        let result = client.reconcile_submission(&envelope).await;
        assert!(matches!(
            result,
            Err(RunmillControlError::AdmissionBindingMismatch)
        ));

        assert_eq!(
            fixture.requests(),
            vec![json!({
                "type": "asf.get_run",
                "idempotencyKey": "tenant/work-order-1/attempt-1"
            })]
        );
    }

    fn make_signed_work_order() -> (RunmillSignedWorkOrderV1, VerifyingKey) {
        use crate::contracts::RunmillWorkOrderV1;
        use crate::crypto::Ed25519Signer;

        let now = Utc::now();
        let signer = Ed25519Signer::generate("key-1");
        let verifying_key = signer.verifying_key();

        let work_order_value = exact_work_order_value();
        let mut payload: RunmillWorkOrderV1 =
            serde_json::from_value(work_order_value["payload"].clone())
                .expect("deserialize work order payload");

        payload.idempotency_key = format!(
            "{}/{}/{}",
            payload.tenant_id, payload.work_item_id, payload.attempt_id
        );

        let signed = RunmillSignedWorkOrderV1::sign(
            payload,
            &signer,
            now,
            now,
            now + chrono::Duration::hours(1),
        )
        .expect("sign work order");

        (signed, verifying_key)
    }

    #[tokio::test]
    async fn reconcile_verified_submission_succeeds_with_valid_signature_and_matching_admission() {
        let (signed_envelope, verifying_key) = make_signed_work_order();
        let trusted_key_id = signed_envelope.key_id.clone();
        let envelope_digest = signed_envelope.envelope_digest().expect("envelope digest");
        let payload_digest = signed_envelope.payload_digest().expect("payload digest");

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] =
            Value::String(signed_envelope.payload.idempotency_key.clone());
        snapshot["admission"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["admission"]["tenantId"] =
            Value::String(signed_envelope.payload.tenant_id.clone());
        snapshot["admission"]["attemptId"] =
            Value::String(signed_envelope.payload.attempt_id.clone());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["admission"]["effectivePolicyDigest"] =
            Value::String(signed_envelope.payload.policy_digest.clone());
        snapshot["admission"]["signatureKeyId"] = Value::String(signed_envelope.key_id.clone());
        snapshot["admission"]["signatureAlgorithm"] =
            Value::String(signed_envelope.algorithm.clone());
        snapshot["run"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["run"]["attemptId"] = Value::String(signed_envelope.payload.attempt_id.clone());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        let read = client
            .reconcile_verified_submission(&trusted_key_id, &signed_envelope, &verifying_key)
            .await
            .expect("reconcile verified submission");

        assert_eq!(
            read.value().run.run_id.as_str(),
            "run-1",
            "returned run_id should be 'run-1'"
        );
        assert!(
            !read.response_wire().is_empty(),
            "response_wire should not be empty"
        );
    }

    #[tokio::test]
    async fn reconcile_verified_submission_rejects_invalid_signature() {
        let (mut signed_envelope, verifying_key) = make_signed_work_order();
        let trusted_key_id = signed_envelope.key_id.clone();

        signed_envelope.signature = "base64url:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();

        let fixture = ControlFixture::new(vec![]);
        let client = fixture.client(Duration::from_secs(1));

        let error = client
            .reconcile_verified_submission(&trusted_key_id, &signed_envelope, &verifying_key)
            .await
            .expect_err("should reject invalid signature");

        assert!(
            matches!(error, RunmillControlError::InvalidRequest(_)),
            "expected InvalidRequest, got {error:?}"
        );
        assert!(
            fixture.requests().is_empty(),
            "requests should be empty, got {:?}",
            fixture.requests()
        );
    }

    #[tokio::test]
    async fn reconcile_verified_submission_rejects_mismatched_policy_digest() {
        let (signed_envelope, verifying_key) = make_signed_work_order();
        let trusted_key_id = signed_envelope.key_id.clone();
        let envelope_digest = signed_envelope.envelope_digest().expect("envelope digest");
        let payload_digest = signed_envelope.payload_digest().expect("payload digest");

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] =
            Value::String(signed_envelope.payload.idempotency_key.clone());
        snapshot["admission"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["admission"]["tenantId"] =
            Value::String(signed_envelope.payload.tenant_id.clone());
        snapshot["admission"]["attemptId"] =
            Value::String(signed_envelope.payload.attempt_id.clone());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["admission"]["effectivePolicyDigest"] = Value::String(digest('9'));
        snapshot["admission"]["signatureKeyId"] = Value::String(signed_envelope.key_id.clone());
        snapshot["admission"]["signatureAlgorithm"] =
            Value::String(signed_envelope.algorithm.clone());
        snapshot["run"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["run"]["attemptId"] = Value::String(signed_envelope.payload.attempt_id.clone());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        let error = client
            .reconcile_verified_submission(&trusted_key_id, &signed_envelope, &verifying_key)
            .await
            .expect_err("should reject mismatched policy digest");

        assert!(
            matches!(error, RunmillControlError::AdmissionBindingMismatch),
            "expected AdmissionBindingMismatch, got {error:?}"
        );
    }

    #[tokio::test]
    async fn reconcile_verified_submission_rejects_mismatched_trusted_key_id() {
        let (signed_envelope, verifying_key) = make_signed_work_order();
        let wrong_key_id = "different-key-id";

        let fixture = ControlFixture::new(vec![]);
        let client = fixture.client(Duration::from_secs(1));

        let error = client
            .reconcile_verified_submission(wrong_key_id, &signed_envelope, &verifying_key)
            .await
            .expect_err("should reject mismatched trusted key ID");

        assert!(
            matches!(error, RunmillControlError::InvalidRequest(_)),
            "expected InvalidRequest, got {error:?}"
        );
        assert!(
            fixture.requests().is_empty(),
            "requests should be empty (validation before network I/O), got {:?}",
            fixture.requests()
        );
    }

    #[tokio::test]
    async fn reconcile_verified_submission_rejects_keyid_mismatch() {
        let (signed_envelope, verifying_key) = make_signed_work_order();
        let trusted_key_id = signed_envelope.key_id.clone();
        let envelope_digest = signed_envelope.envelope_digest().expect("envelope digest");
        let payload_digest = signed_envelope.payload_digest().expect("payload digest");

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] =
            Value::String(signed_envelope.payload.idempotency_key.clone());
        snapshot["admission"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["admission"]["tenantId"] =
            Value::String(signed_envelope.payload.tenant_id.clone());
        snapshot["admission"]["attemptId"] =
            Value::String(signed_envelope.payload.attempt_id.clone());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["admission"]["effectivePolicyDigest"] =
            Value::String(signed_envelope.payload.policy_digest.clone());
        snapshot["admission"]["signatureKeyId"] = Value::String("other-key-id".into());
        snapshot["admission"]["signatureAlgorithm"] =
            Value::String(signed_envelope.algorithm.clone());
        snapshot["run"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["run"]["attemptId"] = Value::String(signed_envelope.payload.attempt_id.clone());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        let error = client
            .reconcile_verified_submission(&trusted_key_id, &signed_envelope, &verifying_key)
            .await
            .expect_err("should reject keyid mismatch");

        assert!(
            matches!(error, RunmillControlError::AdmissionBindingMismatch),
            "expected AdmissionBindingMismatch, got {error:?}"
        );
    }

    #[tokio::test]
    async fn reconcile_verified_submission_rejects_unsupported_admission_algorithm() {
        let (signed_envelope, verifying_key) = make_signed_work_order();
        let trusted_key_id = signed_envelope.key_id.clone();
        let envelope_digest = signed_envelope.envelope_digest().expect("envelope digest");
        let payload_digest = signed_envelope.payload_digest().expect("payload digest");

        let mut snapshot = run_snapshot();
        snapshot["admission"]["idempotencyKey"] =
            Value::String(signed_envelope.payload.idempotency_key.clone());
        snapshot["admission"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["admission"]["tenantId"] =
            Value::String(signed_envelope.payload.tenant_id.clone());
        snapshot["admission"]["attemptId"] =
            Value::String(signed_envelope.payload.attempt_id.clone());
        snapshot["admission"]["payloadDigest"] = Value::String(payload_digest);
        snapshot["admission"]["envelopeDigest"] = Value::String(envelope_digest);
        snapshot["admission"]["effectivePolicyDigest"] =
            Value::String(signed_envelope.payload.policy_digest.clone());
        snapshot["admission"]["signatureKeyId"] = Value::String(signed_envelope.key_id.clone());
        snapshot["admission"]["signatureAlgorithm"] = Value::String("ECDSA".into());
        snapshot["run"]["workOrderId"] =
            Value::String(signed_envelope.payload.work_order_id.clone());
        snapshot["run"]["attemptId"] = Value::String(signed_envelope.payload.attempt_id.clone());

        let fixture = ControlFixture::new(vec![FixtureResponse::success(snapshot)]);
        let client = fixture.client(Duration::from_secs(1));

        let error = client
            .reconcile_verified_submission(&trusted_key_id, &signed_envelope, &verifying_key)
            .await
            .expect_err("should reject unsupported algorithm");

        assert!(
            matches!(error, RunmillControlError::MalformedResponse),
            "expected MalformedResponse, got {error:?}"
        );
    }

    #[tokio::test]
    async fn evidence_view_accepts_valid_terminal_response() {
        let mut evidence = evidence_view();
        evidence["phase"] = Value::String("COMPLETED".into());
        evidence["status"] = Value::String("final".into());
        evidence["complete"] = Value::Bool(true);
        evidence["bundleDigest"] = Value::String(digest('a'));
        evidence["signedBundle"] = Value::Object(signed_evidence());
        evidence["terminalBundleDigest"] = Value::String(digest('b'));
        evidence["signedTerminalBundle"] = Value::Object(signed_evidence_with_digest('b'));

        let fixture = ControlFixture::new(vec![FixtureResponse::success(evidence.clone())]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let result = client
            .get_evidence(&run_id)
            .await
            .expect("should accept terminal response");
        assert!(result.complete);
        assert!(result.terminal_bundle_digest.is_some());
        assert!(result.signed_terminal_bundle.is_some());
    }

    #[tokio::test]
    async fn evidence_view_rejects_terminal_digest_without_signed_bundle() {
        let mut evidence = evidence_view();
        evidence["phase"] = Value::String("COMPLETED".into());
        evidence["status"] = Value::String("final".into());
        evidence["complete"] = Value::Bool(true);
        evidence["bundleDigest"] = Value::String(digest('a'));
        evidence["signedBundle"] = Value::Object(signed_evidence());
        evidence["terminalBundleDigest"] = Value::String(digest('b'));
        evidence["signedTerminalBundle"] = Value::Null;

        let fixture = ControlFixture::new(vec![FixtureResponse::success(evidence.clone())]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let error = client
            .get_evidence(&run_id)
            .await
            .expect_err("should reject mismatched terminal fields");

        assert!(
            matches!(error, RunmillControlError::MalformedResponse),
            "expected MalformedResponse, got {error:?}"
        );
    }

    #[tokio::test]
    async fn evidence_view_rejects_terminal_fields_in_nonterminal_phase() {
        let mut evidence = evidence_view();
        evidence["phase"] = Value::String("IMPLEMENTING".into());
        evidence["status"] = Value::String("current".into());
        evidence["complete"] = Value::Bool(false);
        evidence["bundleDigest"] = Value::Null;
        evidence["signedBundle"] = Value::Null;
        evidence["terminalBundleDigest"] = Value::String(digest('b'));
        evidence["signedTerminalBundle"] = Value::Object(signed_evidence_with_digest('b'));

        let fixture = ControlFixture::new(vec![FixtureResponse::success(evidence.clone())]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let error = client
            .get_evidence(&run_id)
            .await
            .expect_err("should reject terminal fields in nonterminal phase");

        assert!(
            matches!(error, RunmillControlError::MalformedResponse),
            "expected MalformedResponse, got {error:?}"
        );
    }

    fn signed_evidence() -> Map<String, Value> {
        serde_json::from_value::<Map<String, Value>>(json!({
            "schema": "asf.signed-evidence/v1",
            "key_id": "key-1",
            "algorithm": "EdDSA",
            "issued_at": NOW,
            "bundle_digest": digest('a'),
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [],
                "predicateType": "https://runmill.dev/attestations/asf-evidence/v1",
                "predicate": {
                    "schema": "asf.evidence-bundle/v1"
                }
            },
            "signature": "base64url:AQ"
        }))
        .expect("parse signed evidence")
    }

    fn signed_evidence_with_digest(character: char) -> Map<String, Value> {
        serde_json::from_value::<Map<String, Value>>(json!({
            "schema": "asf.signed-evidence/v1",
            "key_id": "key-1",
            "algorithm": "EdDSA",
            "issued_at": NOW,
            "bundle_digest": digest(character),
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [],
                "predicateType": "https://runmill.dev/attestations/asf-evidence/v1",
                "predicate": {
                    "schema": "asf.evidence-bundle/v1"
                }
            },
            "signature": "base64url:AQ"
        }))
        .expect("parse signed evidence")
    }

    #[tokio::test]
    async fn evidence_view_accepts_stopped_terminal_with_opaque_terminal_bundle() {
        let mut evidence = evidence_view();
        evidence["phase"] = Value::String("FAILED".into());
        evidence["status"] = Value::String("stopped".into());
        evidence["complete"] = Value::Bool(true);
        evidence["bundleDigest"] = Value::Null;
        evidence["signedBundle"] = Value::Null;
        evidence["terminalBundleDigest"] = Value::String(digest('b'));
        evidence["signedTerminalBundle"] = Value::Object({
            let mut obj = Map::new();
            obj.insert(
                "metadata".into(),
                Value::String("opaque-terminal-evidence".into()),
            );
            obj.insert("data".into(), Value::String("base64-encoded".into()));
            obj
        });

        let fixture = ControlFixture::new(vec![FixtureResponse::success(evidence.clone())]);
        let client = fixture.client(Duration::from_secs(1));
        let run_id = RunmillRunId::parse("run-1").unwrap();

        let result = client
            .get_evidence(&run_id)
            .await
            .expect("should accept stopped terminal response with opaque terminal bundle");
        assert!(result.complete);
        assert!(result.bundle_digest.is_none());
        assert!(result.signed_bundle.is_none());
        assert!(result.terminal_bundle_digest.is_some());
        assert!(result.signed_terminal_bundle.is_some());
    }
}
