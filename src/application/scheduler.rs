use std::cmp::Ordering;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{RepositoryId, WorkItemId};

const AGING_INTERVAL: Duration = Duration::hours(24);
const MAX_AGING_BONUS: u8 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingCandidate {
    pub work_item_id: WorkItemId,
    pub repository_id: RepositoryId,
    pub normalized_priority: u8,
    pub ready_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub dependencies_ready: bool,
    pub source_current: bool,
    pub approvals_ready: bool,
    pub budget_available: bool,
    pub worker_available: bool,
    pub identity_available: bool,
    pub repository_wip_available: bool,
    pub breaker_open: bool,
}

impl SchedulingCandidate {
    #[must_use]
    pub fn effective_priority(&self, now: DateTime<Utc>) -> u8 {
        let age = now
            .signed_duration_since(self.ready_at)
            .max(Duration::zero());
        let bounded_bonus =
            (age.num_seconds() / AGING_INTERVAL.num_seconds()).clamp(0, i64::from(MAX_AGING_BONUS));
        let bonus = u8::try_from(bounded_bonus).expect("aging bonus is clamped to u8");
        self.normalized_priority
            .saturating_add(bonus)
            .min(100 + MAX_AGING_BONUS)
    }

    #[must_use]
    pub fn rejection_reasons(&self) -> Vec<SchedulingRejection> {
        let checks = [
            (
                !self.dependencies_ready,
                SchedulingRejection::DependencyBlocked,
            ),
            (!self.source_current, SchedulingRejection::StaleSource),
            (!self.approvals_ready, SchedulingRejection::ApprovalMissing),
            (
                !self.budget_available,
                SchedulingRejection::BudgetUnavailable,
            ),
            (
                !self.worker_available,
                SchedulingRejection::WorkerUnavailable,
            ),
            (
                !self.identity_available,
                SchedulingRejection::IdentityUnavailable,
            ),
            (
                !self.repository_wip_available,
                SchedulingRejection::RepositoryWipFull,
            ),
            (self.breaker_open, SchedulingRejection::CircuitBreakerOpen),
        ];
        checks
            .into_iter()
            .filter_map(|(rejected, reason)| rejected.then_some(reason))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingRejection {
    DependencyBlocked,
    StaleSource,
    ApprovalMissing,
    BudgetUnavailable,
    WorkerUnavailable,
    IdentityUnavailable,
    RepositoryWipFull,
    CircuitBreakerOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingDecision {
    pub selected: Option<WorkItemId>,
    pub evaluations: Vec<CandidateEvaluation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEvaluation {
    pub work_item_id: WorkItemId,
    pub effective_priority: u8,
    pub selected: bool,
    pub rejections: Vec<SchedulingRejection>,
}

#[derive(Debug, Default)]
pub struct DeterministicScheduler;

impl DeterministicScheduler {
    #[must_use]
    pub fn select(
        &self,
        candidates: &[SchedulingCandidate],
        now: DateTime<Utc>,
    ) -> SchedulingDecision {
        let mut eligible: Vec<&SchedulingCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.rejection_reasons().is_empty())
            .collect();
        eligible.sort_by(|left, right| compare_candidates(left, right, now));
        let selected = eligible.first().map(|candidate| candidate.work_item_id);
        let evaluations = candidates
            .iter()
            .map(|candidate| CandidateEvaluation {
                work_item_id: candidate.work_item_id,
                effective_priority: candidate.effective_priority(now),
                selected: selected == Some(candidate.work_item_id),
                rejections: candidate.rejection_reasons(),
            })
            .collect();
        SchedulingDecision {
            selected,
            evaluations,
        }
    }
}

fn compare_candidates(
    left: &SchedulingCandidate,
    right: &SchedulingCandidate,
    now: DateTime<Utc>,
) -> Ordering {
    right
        .effective_priority(now)
        .cmp(&left.effective_priority(now))
        .then_with(|| compare_due_date(left.due_at, right.due_at))
        .then_with(|| left.ready_at.cmp(&right.ready_at))
        .then_with(|| left.work_item_id.cmp(&right.work_item_id))
}

fn compare_due_date(left: Option<DateTime<Utc>>, right: Option<DateTime<Utc>>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(now: DateTime<Utc>, priority: u8) -> SchedulingCandidate {
        SchedulingCandidate {
            work_item_id: WorkItemId::new(),
            repository_id: RepositoryId::new(),
            normalized_priority: priority,
            ready_at: now,
            due_at: None,
            dependencies_ready: true,
            source_current: true,
            approvals_ready: true,
            budget_available: true,
            worker_available: true,
            identity_available: true,
            repository_wip_available: true,
            breaker_open: false,
        }
    }

    #[test]
    fn bounded_aging_can_prevent_starvation() {
        let now = Utc::now();
        let mut old = candidate(now - Duration::days(30), 50);
        let recent = candidate(now, 60);
        old.ready_at = now - Duration::days(30);
        let decision = DeterministicScheduler.select(&[recent, old.clone()], now);
        assert_eq!(decision.selected, Some(old.work_item_id));
    }

    #[test]
    fn blocked_candidates_are_explained_and_never_selected() {
        let now = Utc::now();
        let mut blocked = candidate(now, 100);
        blocked.approvals_ready = false;
        let blocked_id = blocked.work_item_id;
        let eligible = candidate(now, 10);
        let decision = DeterministicScheduler.select(&[blocked, eligible.clone()], now);
        assert_eq!(decision.selected, Some(eligible.work_item_id));
        assert!(
            decision
                .evaluations
                .iter()
                .find(|item| item.work_item_id == blocked_id)
                .unwrap()
                .rejections
                .contains(&SchedulingRejection::ApprovalMissing)
        );
    }
}
