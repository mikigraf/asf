use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{AttemptId, RunId, WorkItemId, WorkerId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptState {
    Authorizing,
    Dispatching,
    Running,
    Verifying,
    TargetReached,
    RetryableFailure,
    Escalated,
    Cancelled,
    Quarantined,
}

impl AttemptState {
    #[must_use]
    pub const fn active(self) -> bool {
        matches!(
            self,
            Self::Authorizing | Self::Dispatching | Self::Running | Self::Verifying
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub id: AttemptId,
    pub work_item_id: WorkItemId,
    pub ordinal: u32,
    pub state: AttemptState,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub work_order_digest: Option<String>,
    pub run_id: Option<RunId>,
    pub last_event_cursor: Option<String>,
    pub version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
