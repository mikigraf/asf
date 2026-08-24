use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::domain::{
    AccountabilityAnchor, Attempt, AttemptId, AttemptState, RepositoryId, WorkItem, WorkItemId,
    WorkItemState, validate_accountability,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationSnapshot<'a> {
    pub work_items: &'a [WorkItem],
    pub attempts: &'a [Attempt],
    pub work_order_attempts: &'a BTreeSet<AttemptId>,
    pub authoritative_run_attempts: &'a BTreeSet<AttemptId>,
    pub accountability: &'a BTreeMap<WorkItemId, AccountabilityAnchor>,
    pub live_repository_reservations: &'a [(RepositoryId, AttemptId)],
    pub stale_worker_attempts: &'a BTreeSet<AttemptId>,
    pub closure_evidence_items: &'a BTreeSet<WorkItemId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvariantCode {
    MissingAccountability,
    MultipleActiveAttempts,
    RepositoryWipExceeded,
    ActiveAttemptMissingWorkOrder,
    ActiveAttemptMissingRun,
    StaleWorkerGeneration,
    ClosedWithoutEvidence,
    ActiveAttemptNotLinked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantViolation {
    pub code: InvariantCode,
    pub work_item_id: Option<WorkItemId>,
    pub attempt_id: Option<AttemptId>,
    pub repository_id: Option<RepositoryId>,
    pub detail: String,
    pub quarantine_required: bool,
}

#[derive(Debug, Default)]
pub struct GlobalReconciler;

impl GlobalReconciler {
    #[must_use]
    pub fn audit(&self, snapshot: &ReconciliationSnapshot<'_>) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        for item in snapshot.work_items {
            if validate_accountability(
                item.state,
                item.accepted_at,
                snapshot.accountability.get(&item.id),
            )
            .is_err()
            {
                violations.push(InvariantViolation {
                    code: InvariantCode::MissingAccountability,
                    work_item_id: Some(item.id),
                    attempt_id: item.active_attempt_id,
                    repository_id: item.repository_id,
                    detail: "accepted item has no live progress, timer, retry, approval, escalation, or verified closure".into(),
                    quarantine_required: true,
                });
            }
            if item.state == WorkItemState::Closed
                && !snapshot.closure_evidence_items.contains(&item.id)
            {
                violations.push(InvariantViolation {
                    code: InvariantCode::ClosedWithoutEvidence,
                    work_item_id: Some(item.id),
                    attempt_id: item.active_attempt_id,
                    repository_id: item.repository_id,
                    detail: "closed item has no independently valid target evidence".into(),
                    quarantine_required: true,
                });
            }
        }

        let mut attempts_by_item: BTreeMap<WorkItemId, Vec<&Attempt>> = BTreeMap::new();
        for attempt in snapshot.attempts {
            if attempt.state.active() {
                attempts_by_item
                    .entry(attempt.work_item_id)
                    .or_default()
                    .push(attempt);
                if !snapshot.work_order_attempts.contains(&attempt.id) {
                    violations.push(attempt_violation(
                        InvariantCode::ActiveAttemptMissingWorkOrder,
                        attempt,
                        "active attempt has no immutable Work Order",
                    ));
                }
                if matches!(
                    attempt.state,
                    AttemptState::Running | AttemptState::Verifying
                ) && !snapshot.authoritative_run_attempts.contains(&attempt.id)
                {
                    violations.push(attempt_violation(
                        InvariantCode::ActiveAttemptMissingRun,
                        attempt,
                        "running attempt has no authoritative Runmill run",
                    ));
                }
                if snapshot.stale_worker_attempts.contains(&attempt.id) {
                    violations.push(attempt_violation(
                        InvariantCode::StaleWorkerGeneration,
                        attempt,
                        "attempt is bound to a stale worker generation",
                    ));
                }
            }
        }
        for (work_item_id, attempts) in attempts_by_item {
            if attempts.len() > 1 {
                violations.push(InvariantViolation {
                    code: InvariantCode::MultipleActiveAttempts,
                    work_item_id: Some(work_item_id),
                    attempt_id: None,
                    repository_id: None,
                    detail: format!("{} active attempts found", attempts.len()),
                    quarantine_required: true,
                });
            }
        }

        let mut reservations_by_repository: BTreeMap<RepositoryId, Vec<AttemptId>> =
            BTreeMap::new();
        for (repository_id, attempt_id) in snapshot.live_repository_reservations {
            reservations_by_repository
                .entry(*repository_id)
                .or_default()
                .push(*attempt_id);
        }
        for (repository_id, attempts) in reservations_by_repository {
            if attempts.len() > 1 {
                violations.push(InvariantViolation {
                    code: InvariantCode::RepositoryWipExceeded,
                    work_item_id: None,
                    attempt_id: None,
                    repository_id: Some(repository_id),
                    detail: format!("{} live repository reservations found", attempts.len()),
                    quarantine_required: true,
                });
            }
        }

        for item in snapshot.work_items {
            if let Some(active_attempt_id) = item.active_attempt_id
                && !snapshot.attempts.iter().any(|attempt| {
                    attempt.id == active_attempt_id && attempt.work_item_id == item.id
                })
            {
                violations.push(InvariantViolation {
                    code: InvariantCode::ActiveAttemptNotLinked,
                    work_item_id: Some(item.id),
                    attempt_id: Some(active_attempt_id),
                    repository_id: item.repository_id,
                    detail: "work item points to a missing or foreign attempt".into(),
                    quarantine_required: true,
                });
            }
        }

        violations.sort_by_key(|violation| {
            (
                violation.code,
                violation.work_item_id,
                violation.attempt_id,
                violation.repository_id,
            )
        });
        violations
    }
}

fn attempt_violation(code: InvariantCode, attempt: &Attempt, detail: &str) -> InvariantViolation {
    InvariantViolation {
        code,
        work_item_id: Some(attempt.work_item_id),
        attempt_id: Some(attempt.id),
        repository_id: None,
        detail: detail.into(),
        quarantine_required: true,
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::Utc;

    use super::*;
    use crate::domain::{SourceSnapshotId, TenantId};

    #[test]
    fn finds_orphaned_accepted_work() {
        let now = Utc::now().trunc_subsecs(6);
        let mut item = WorkItem::discovered(TenantId::new(), SourceSnapshotId::new(), 50, now);
        item.state = WorkItemState::Accepted;
        item.accepted_at = Some(now);
        let work_items = [item];
        let snapshot = ReconciliationSnapshot {
            work_items: &work_items,
            attempts: &[],
            work_order_attempts: &BTreeSet::new(),
            authoritative_run_attempts: &BTreeSet::new(),
            accountability: &BTreeMap::new(),
            live_repository_reservations: &[],
            stale_worker_attempts: &BTreeSet::new(),
            closure_evidence_items: &BTreeSet::new(),
        };
        let violations = GlobalReconciler.audit(&snapshot);
        assert_eq!(violations[0].code, InvariantCode::MissingAccountability);
    }
}
