use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{
    AttemptId, BudgetLimits, RepositoryId, SourceSnapshotId, TenantId, WorkItemId,
    WorkOrderIdentities,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureTarget {
    #[serde(rename = "pr")]
    PullRequest,
    #[serde(rename = "merge")]
    Merge,
    #[serde(rename = "deploy")]
    Deploy,
    #[serde(rename = "observe")]
    Observe,
}

impl ClosureTarget {
    #[must_use]
    pub const fn production_supported_v1(self) -> bool {
        matches!(self, Self::PullRequest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkItemState {
    Discovered,
    ReadinessPending,
    NeedsSpec,
    Ready,
    Accepted,
    Planned,
    Scheduled,
    Dispatching,
    Running,
    VerifyingOutcome,
    TargetReached,
    ClosingSource,
    Closed,
    WaitingDependency,
    WaitingApproval,
    RetryScheduled,
    BlockedExternal,
    BudgetExhausted,
    Refused,
    Quarantined,
    CancelRequested,
    Cancelled,
    Escalated,
}

impl fmt::Display for WorkItemState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl WorkItemState {
    #[must_use]
    pub const fn is_pre_acceptance(self) -> bool {
        matches!(
            self,
            Self::Discovered
                | Self::ReadinessPending
                | Self::NeedsSpec
                | Self::Ready
                | Self::Refused
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Cancelled)
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use WorkItemState as S;
        matches!(
            (self, next),
            (S::Discovered, S::ReadinessPending)
                | (
                    S::ReadinessPending,
                    S::NeedsSpec | S::Ready | S::Refused | S::WaitingDependency
                )
                | (S::NeedsSpec, S::ReadinessPending | S::Refused)
                | (S::Ready, S::Accepted | S::ReadinessPending | S::Refused)
                | (
                    S::Accepted,
                    S::Planned
                        | S::Scheduled
                        | S::WaitingApproval
                        | S::WaitingDependency
                        | S::CancelRequested
                        | S::Escalated
                )
                | (
                    S::Planned,
                    S::Scheduled
                        | S::WaitingApproval
                        | S::WaitingDependency
                        | S::CancelRequested
                        | S::Escalated
                )
                | (
                    S::Scheduled,
                    S::Dispatching
                        | S::WaitingApproval
                        | S::WaitingDependency
                        | S::RetryScheduled
                        | S::CancelRequested
                        | S::Escalated
                )
                | (
                    S::Dispatching,
                    S::Running
                        | S::RetryScheduled
                        | S::BlockedExternal
                        | S::CancelRequested
                        | S::Escalated
                        | S::Quarantined
                )
                | (
                    S::Running,
                    S::VerifyingOutcome
                        | S::WaitingApproval
                        | S::RetryScheduled
                        | S::BlockedExternal
                        | S::BudgetExhausted
                        | S::CancelRequested
                        | S::Escalated
                        | S::Quarantined
                )
                | (
                    S::VerifyingOutcome,
                    S::TargetReached
                        | S::RetryScheduled
                        | S::BlockedExternal
                        | S::WaitingApproval
                        | S::Escalated
                        | S::Quarantined
                )
                | (S::TargetReached, S::ClosingSource | S::Quarantined)
                | (
                    S::ClosingSource,
                    S::Closed | S::BlockedExternal | S::Escalated
                )
                | (
                    S::WaitingDependency,
                    S::Scheduled | S::ReadinessPending | S::CancelRequested | S::Escalated
                )
                | (
                    S::WaitingApproval,
                    S::Scheduled
                        | S::Dispatching
                        | S::Running
                        | S::VerifyingOutcome
                        | S::CancelRequested
                        | S::Escalated
                        | S::Refused
                )
                | (
                    S::RetryScheduled,
                    S::Scheduled | S::ReadinessPending | S::CancelRequested | S::Escalated
                )
                | (
                    S::BlockedExternal,
                    S::RetryScheduled
                        | S::Running
                        | S::ClosingSource
                        | S::CancelRequested
                        | S::Escalated
                        | S::Quarantined
                )
                | (
                    S::BudgetExhausted,
                    S::WaitingApproval | S::RetryScheduled | S::CancelRequested | S::Escalated
                )
                | (
                    S::Quarantined,
                    S::RetryScheduled | S::CancelRequested | S::Escalated
                )
                | (
                    S::CancelRequested,
                    S::Cancelled | S::BlockedExternal | S::Escalated
                )
                | (
                    S::Escalated,
                    S::ReadinessPending
                        | S::Scheduled
                        | S::RetryScheduled
                        | S::CancelRequested
                        | S::Cancelled
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub class: RiskClass,
    pub reasons: Vec<String>,
    pub matched_rules: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    pub id: WorkItemId,
    pub tenant_id: TenantId,
    pub source_snapshot_id: SourceSnapshotId,
    pub repository_id: Option<RepositoryId>,
    pub state: WorkItemState,
    pub closure_target: Option<ClosureTarget>,
    pub risk: Option<RiskAssessment>,
    pub policy_digest: Option<String>,
    pub budgets: Option<BudgetLimits>,
    pub identity_requirements: Option<WorkOrderIdentities>,
    pub owner_fallback: Option<String>,
    pub active_attempt_id: Option<AttemptId>,
    pub priority: u8,
    pub version: u64,
    pub discovered_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl WorkItem {
    #[must_use]
    pub fn discovered(
        tenant_id: TenantId,
        source_snapshot_id: SourceSnapshotId,
        priority: u8,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: WorkItemId::new(),
            tenant_id,
            source_snapshot_id,
            repository_id: None,
            state: WorkItemState::Discovered,
            closure_target: None,
            risk: None,
            policy_digest: None,
            budgets: None,
            identity_requirements: None,
            owner_fallback: None,
            active_attempt_id: None,
            priority,
            version: 1,
            discovered_at: now,
            ready_at: None,
            accepted_at: None,
            updated_at: now,
        }
    }

    pub fn transition(&mut self, next: WorkItemState, now: DateTime<Utc>) -> Result<()> {
        if !self.state.can_transition_to(next) {
            return Err(Error::InvalidTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }
        // Validate acceptance before mutating the aggregate. A failed transition must be atomic.
        if next == WorkItemState::Accepted {
            self.validate_acceptance_fields()?;
        }
        self.state = next;
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("work item aggregate version overflowed".into()))?;
        self.updated_at = now;
        if next == WorkItemState::Ready {
            self.ready_at = Some(now);
        }
        if next == WorkItemState::Accepted {
            self.accepted_at = Some(now);
        }
        Ok(())
    }

    pub fn validate_acceptance_fields(&self) -> Result<()> {
        if self.repository_id.is_none()
            || self.closure_target.is_none()
            || self.risk.is_none()
            || self.policy_digest.is_none()
            || self.budgets.is_none()
            || self.identity_requirements.is_none()
            || self
                .owner_fallback
                .as_deref()
                .is_none_or(|owner| owner.trim().is_empty())
        {
            return Err(Error::Validation(
                "accepted work requires repository, closure target, risk, policy, budgets, identity requirements, and owner fallback"
                    .into(),
            ));
        }
        if let Some(identity_requirements) = &self.identity_requirements {
            identity_requirements.validate()?;
        }
        if !self
            .closure_target
            .is_some_and(ClosureTarget::production_supported_v1)
        {
            return Err(Error::Validation(
                "only pull-request closure is production-supported in V1".into(),
            ));
        }
        if matches!(
            self.risk.as_ref().map(|risk| risk.class),
            Some(RiskClass::Critical | RiskClass::Unknown)
        ) {
            return Err(Error::Validation(
                "critical or unknown-risk work cannot be accepted for unattended V1 execution"
                    .into(),
            ));
        }
        self.budgets.expect("checked above").validate()
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::Utc;

    use super::*;

    #[test]
    fn cannot_skip_readiness_and_acceptance() {
        let now = Utc::now().trunc_subsecs(6);
        let mut item = WorkItem::discovered(TenantId::new(), SourceSnapshotId::new(), 50, now);
        assert!(item.transition(WorkItemState::Accepted, now).is_err());
        assert_eq!(item.state, WorkItemState::Discovered);
    }

    #[test]
    fn failed_acceptance_is_atomic() {
        let now = Utc::now().trunc_subsecs(6);
        let mut item = WorkItem::discovered(TenantId::new(), SourceSnapshotId::new(), 50, now);
        item.state = WorkItemState::Ready;
        assert!(item.transition(WorkItemState::Accepted, now).is_err());
        assert_eq!(item.state, WorkItemState::Ready);
        assert_eq!(item.version, 1);
    }

    #[test]
    fn no_transition_leaves_closed_state() {
        for state in [WorkItemState::Closed, WorkItemState::Cancelled] {
            for next in [
                WorkItemState::Scheduled,
                WorkItemState::Running,
                WorkItemState::Escalated,
            ] {
                assert!(!state.can_transition_to(next));
            }
        }
    }
}
