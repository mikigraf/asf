use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{RepositoryId, TenantId, WorkerId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    Observe,
    SupervisedPullRequest,
    AutomaticVerifiedPullRequest,
    GuardedMergeCandidate,
    GuardedMergeEnabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: RepositoryId,
    pub tenant_id: TenantId,
    pub forge: String,
    pub owner: String,
    pub name: String,
    pub base_ref: String,
    pub policy_digest: String,
    pub harness_digest: String,
    pub required_local_checks: BTreeSet<String>,
    pub required_remote_checks: BTreeSet<String>,
    pub wip_limit: u16,
    pub autonomy_level: AutonomyLevel,
    pub preferred_worker_id: Option<WorkerId>,
    pub enabled: bool,
    pub version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Repository {
    #[must_use]
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    #[must_use]
    pub fn production_wip_limit(&self) -> u16 {
        // The V1 product contract hard-caps the normal configuration at one.
        self.wip_limit.min(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealth {
    Healthy,
    Degraded,
    Offline,
    Fenced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapabilities {
    pub protocol_schema: String,
    pub work_order_schemas: BTreeSet<String>,
    pub evidence_schemas: BTreeSet<String>,
    pub closure_targets: BTreeSet<String>,
    pub sandbox_profiles: BTreeSet<String>,
    pub supports_cursor_events: bool,
    pub supports_idempotent_submission: bool,
    pub supports_signed_evidence: bool,
}

impl WorkerCapabilities {
    /// Static protocol and evidence capabilities required for production work.
    /// Capacity is deliberately evaluated separately because ordinary
    /// saturation is a draining condition, not a security quarantine.
    #[must_use]
    pub fn production_qualified(&self) -> bool {
        self.supports_cursor_events
            && self.supports_idempotent_submission
            && self.supports_signed_evidence
            && self.work_order_schemas.contains("asf.work-order/v1")
            && self.evidence_schemas.contains("runmill.evidence/v1")
            && self.closure_targets.contains("pr")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub id: WorkerId,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub endpoint: String,
    pub generation: u64,
    pub health: WorkerHealth,
    pub capabilities: WorkerCapabilities,
    pub max_concurrency: u16,
    pub active_slots: u16,
    pub last_seen_at: DateTime<Utc>,
}

impl Worker {
    #[must_use]
    pub fn production_ready(&self) -> bool {
        self.health == WorkerHealth::Healthy
            && self.active_slots < self.max_concurrency
            && self.capabilities.production_qualified()
    }
}
