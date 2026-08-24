use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{AttemptId, EscalationId, RunId, WorkItemId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EscalationCategory {
    NeedsSpec,
    NeedsApproval,
    BlockedDependency,
    BlockedExternal,
    IdentityUnavailable,
    WorkerUnavailable,
    VerificationFailed,
    ReviewBlocked,
    CiFailed,
    RemoteEffectAmbiguous,
    BudgetExhausted,
    ProviderRefused,
    PolicyRefused,
    WorkflowJobExhausted,
    Quarantined,
    SecurityIncident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum EscalationOwner {
    Person(String),
    Team(String),
    OnCallRole(String),
}

impl EscalationOwner {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Person(value) | Self::Team(value) | Self::OnCallRole(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    pub automatic: bool,
    pub max_additional_attempts: u32,
    pub backoff_seconds: u64,
    pub prerequisites: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    Open,
    Snoozed,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    pub id: EscalationId,
    pub work_item_id: WorkItemId,
    pub attempt_id: Option<AttemptId>,
    pub run_id: Option<RunId>,
    pub category: EscalationCategory,
    pub stable_reason_code: String,
    pub reason: String,
    pub severity: EscalationSeverity,
    pub owner: EscalationOwner,
    pub required_action: String,
    pub evidence_references: Vec<String>,
    pub deadline: DateTime<Utc>,
    pub escalation_path: Vec<EscalationOwner>,
    pub retry_policy: RetryPolicy,
    pub authority_or_effect_active: bool,
    pub status: EscalationStatus,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub resolution: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Escalation {
    pub fn validate(&self) -> Result<()> {
        if self.stable_reason_code.trim().is_empty()
            || self.reason.trim().is_empty()
            || self.owner.name().trim().is_empty()
            || self.required_action.trim().is_empty()
        {
            return Err(Error::Validation(
                "escalation requires category reason, owner, and action".into(),
            ));
        }
        if self.deadline <= self.created_at {
            return Err(Error::Validation(
                "escalation deadline must be after creation".into(),
            ));
        }
        Ok(())
    }

    pub fn snooze(&mut self, until: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
        if until <= now {
            return Err(Error::Validation(
                "snooze requires a future wake time".into(),
            ));
        }
        if self.status == EscalationStatus::Resolved {
            return Err(Error::Conflict(
                "resolved escalation cannot be snoozed".into(),
            ));
        }
        self.status = EscalationStatus::Snoozed;
        self.snoozed_until = Some(until);
        self.updated_at = now;
        Ok(())
    }

    pub fn resolve(&mut self, resolution: String, now: DateTime<Utc>) -> Result<()> {
        if resolution.trim().is_empty() {
            return Err(Error::Validation(
                "closing an escalation requires a resolution".into(),
            ));
        }
        self.status = EscalationStatus::Resolved;
        self.resolution = Some(resolution);
        self.updated_at = now;
        Ok(())
    }
}
