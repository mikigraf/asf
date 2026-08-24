use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{AttemptId, EventId, RunId, TenantId, WorkItemId};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEvent {
    pub schema: String,
    pub event_id: EventId,
    pub tenant_id: TenantId,
    pub work_item_id: Option<WorkItemId>,
    pub attempt_id: Option<AttemptId>,
    pub work_order_digest: Option<String>,
    pub run_id: Option<RunId>,
    pub aggregate_version: u64,
    pub occurred_at: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
    pub actor: String,
    pub event_type: String,
    pub payload: Value,
    pub policy_digest: Option<String>,
    pub trace_id: String,
    pub correlation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEventCursor {
    pub run_id: String,
    pub after: Option<String>,
}
