use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{
    AccountabilityAnchor, AccountabilityKind, ApprovalType, EscalationCategory, EvidenceId, RunId,
    WorkItemId,
};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStage {
    Accepted,
    WaitingSchedule,
    Authorizing,
    Dispatching,
    ObservingRun,
    VerifyingEvidence,
    ClosingSource,
    Closed,
    WaitingRetry,
    WaitingApproval,
    Escalated,
    Cancelling,
    Cancelled,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowState {
    pub work_item_id: WorkItemId,
    pub stage: WorkflowStage,
    pub generation: u64,
    pub run_id: Option<RunId>,
    pub evidence_id: Option<EvidenceId>,
    pub attempt_number: u32,
    pub retry_count: u32,
    pub accountability: AccountabilityAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowFact {
    ScheduleRequested,
    ScheduleGranted,
    WorkOrderStored { digest: String },
    SubmissionAccepted { run_id: RunId },
    SubmissionAmbiguous,
    RunStopped(RunStop),
    EvidenceValidated { evidence_id: EvidenceId },
    EvidenceRejected { reason: String },
    SourceCloseConfirmed,
    SourceCloseAmbiguous,
    RetryDue,
    ApprovalGranted { approval_type: ApprovalType },
    ApprovalRejected { reason: String },
    CancelRequested,
    CancellationConfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStop {
    EvidenceAvailable {
        evidence_id: EvidenceId,
    },
    RetryableFailure {
        reason: String,
    },
    ApprovalRequired {
        approval_type: ApprovalType,
        reason: String,
    },
    BudgetExhausted {
        reason: String,
    },
    ProviderRefused {
        reason: String,
    },
    VerificationFailed {
        reason: String,
    },
    ReviewBlocked {
        reason: String,
    },
    CiFailed {
        reason: String,
    },
    AmbiguousRemoteEffect {
        reason: String,
    },
    Quarantined {
        reason: String,
    },
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowEffect {
    EnqueueScheduler,
    ReserveAndCreateAttempt,
    SignAndStoreWorkOrder,
    SubmitStoredWorkOrder,
    ObserveRun {
        run_id: RunId,
    },
    ReconcileSubmission,
    FetchAndVerifyEvidence {
        evidence_id: EvidenceId,
    },
    ScheduleRetry {
        at: DateTime<Utc>,
        reason: String,
    },
    RequestApproval {
        approval_type: ApprovalType,
        reason: String,
    },
    OpenEscalation {
        category: EscalationCategory,
        reason: String,
    },
    CloseSource {
        evidence_id: EvidenceId,
    },
    ReconcileSourceClosure,
    RequestRunCancellation,
    ReleaseReservations,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowTransition {
    pub state: WorkflowState,
    pub effects: Vec<WorkflowEffect>,
}

impl WorkflowState {
    #[must_use]
    pub fn accepted(work_item_id: WorkItemId, now: DateTime<Utc>) -> Self {
        Self {
            work_item_id,
            stage: WorkflowStage::Accepted,
            generation: 1,
            run_id: None,
            evidence_id: None,
            attempt_number: 0,
            retry_count: 0,
            accountability: anchor(
                work_item_id,
                AccountabilityKind::ActiveWorkflow,
                "workflow:accepted",
                None,
                1,
                now,
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowReducer {
    pub retry_backoff: Duration,
    pub escalation_sla: Duration,
    pub approval_sla: Duration,
    pub max_retries: u32,
}

impl Default for WorkflowReducer {
    fn default() -> Self {
        Self {
            retry_backoff: Duration::minutes(5),
            escalation_sla: Duration::hours(4),
            approval_sla: Duration::hours(8),
            max_retries: 2,
        }
    }
}

impl WorkflowReducer {
    pub fn apply(
        &self,
        mut state: WorkflowState,
        fact: WorkflowFact,
        now: DateTime<Utc>,
    ) -> Result<WorkflowTransition> {
        let current = state.stage;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("workflow generation overflowed".into()))?;
        let (stage, effects, kind, reference, wake) = match (current, fact) {
            (WorkflowStage::Accepted, WorkflowFact::ScheduleRequested) => (
                WorkflowStage::WaitingSchedule,
                vec![WorkflowEffect::EnqueueScheduler],
                AccountabilityKind::ActiveWorkflow,
                "scheduler:queued".into(),
                None,
            ),
            (WorkflowStage::WaitingSchedule, WorkflowFact::ScheduleGranted) => {
                state.attempt_number += 1;
                (
                    WorkflowStage::Authorizing,
                    vec![WorkflowEffect::ReserveAndCreateAttempt],
                    AccountabilityKind::ActiveWorkflow,
                    format!("attempt:{}:authorizing", state.attempt_number),
                    None,
                )
            }
            (WorkflowStage::Authorizing, WorkflowFact::WorkOrderStored { digest }) => (
                WorkflowStage::Dispatching,
                vec![WorkflowEffect::SubmitStoredWorkOrder],
                AccountabilityKind::ActiveWorkflow,
                digest,
                None,
            ),
            (WorkflowStage::Dispatching, WorkflowFact::SubmissionAccepted { run_id }) => {
                state.run_id = Some(run_id);
                (
                    WorkflowStage::ObservingRun,
                    vec![WorkflowEffect::ObserveRun { run_id }],
                    AccountabilityKind::ActiveRun,
                    run_id.to_string(),
                    None,
                )
            }
            (WorkflowStage::Dispatching, WorkflowFact::SubmissionAmbiguous) => (
                WorkflowStage::Dispatching,
                vec![WorkflowEffect::ReconcileSubmission],
                AccountabilityKind::Timer,
                "dispatch:reconcile".into(),
                Some(now + Duration::seconds(10)),
            ),
            (WorkflowStage::ObservingRun, WorkflowFact::RunStopped(stop)) => {
                self.handle_run_stop(&mut state, stop, now)
            }
            (WorkflowStage::VerifyingEvidence, WorkflowFact::EvidenceValidated { evidence_id }) => {
                state.evidence_id = Some(evidence_id);
                (
                    WorkflowStage::ClosingSource,
                    vec![WorkflowEffect::CloseSource { evidence_id }],
                    AccountabilityKind::ActiveWorkflow,
                    format!("source-close:{evidence_id}"),
                    None,
                )
            }
            (WorkflowStage::VerifyingEvidence, WorkflowFact::EvidenceRejected { reason }) => (
                WorkflowStage::Quarantined,
                vec![WorkflowEffect::OpenEscalation {
                    category: EscalationCategory::VerificationFailed,
                    reason,
                }],
                AccountabilityKind::Escalation,
                "escalation:verification-failed".into(),
                Some(now + self.escalation_sla),
            ),
            (WorkflowStage::ClosingSource, WorkflowFact::SourceCloseConfirmed) => (
                WorkflowStage::Closed,
                vec![WorkflowEffect::ReleaseReservations],
                AccountabilityKind::VerifiedClosure,
                state
                    .evidence_id
                    .map_or_else(|| "evidence:missing".into(), |id| id.to_string()),
                None,
            ),
            (WorkflowStage::ClosingSource, WorkflowFact::SourceCloseAmbiguous) => (
                WorkflowStage::ClosingSource,
                vec![WorkflowEffect::ReconcileSourceClosure],
                AccountabilityKind::Timer,
                "source-close:reconcile".into(),
                Some(now + Duration::seconds(30)),
            ),
            (WorkflowStage::WaitingRetry, WorkflowFact::RetryDue) => (
                WorkflowStage::WaitingSchedule,
                vec![WorkflowEffect::EnqueueScheduler],
                AccountabilityKind::ActiveWorkflow,
                "scheduler:retry".into(),
                None,
            ),
            (
                WorkflowStage::WaitingApproval,
                WorkflowFact::ApprovalGranted { approval_type: _ },
            ) => (
                WorkflowStage::WaitingSchedule,
                vec![WorkflowEffect::EnqueueScheduler],
                AccountabilityKind::ActiveWorkflow,
                "scheduler:approved".into(),
                None,
            ),
            (WorkflowStage::WaitingApproval, WorkflowFact::ApprovalRejected { reason }) => (
                WorkflowStage::Escalated,
                vec![WorkflowEffect::OpenEscalation {
                    category: EscalationCategory::NeedsApproval,
                    reason,
                }],
                AccountabilityKind::Escalation,
                "escalation:approval-rejected".into(),
                Some(now + self.escalation_sla),
            ),
            (
                WorkflowStage::Accepted
                | WorkflowStage::WaitingSchedule
                | WorkflowStage::Authorizing
                | WorkflowStage::Dispatching
                | WorkflowStage::ObservingRun
                | WorkflowStage::VerifyingEvidence
                | WorkflowStage::WaitingRetry
                | WorkflowStage::WaitingApproval
                | WorkflowStage::Escalated
                | WorkflowStage::Quarantined,
                WorkflowFact::CancelRequested,
            ) => (
                WorkflowStage::Cancelling,
                vec![WorkflowEffect::RequestRunCancellation],
                AccountabilityKind::ActiveWorkflow,
                "cancellation:requested".into(),
                None,
            ),
            (WorkflowStage::Cancelling, WorkflowFact::CancellationConfirmed) => (
                WorkflowStage::Cancelled,
                vec![WorkflowEffect::ReleaseReservations],
                AccountabilityKind::Cancellation,
                "cancelled".into(),
                None,
            ),
            (_, fact) => {
                return Err(Error::InvalidTransition {
                    from: format!("{current:?}"),
                    to: format!("{fact:?}"),
                });
            }
        };
        state.stage = stage;
        state.accountability = anchor(
            state.work_item_id,
            kind,
            reference,
            wake,
            state.generation,
            now,
        );
        Ok(WorkflowTransition { state, effects })
    }

    fn handle_run_stop(
        &self,
        state: &mut WorkflowState,
        stop: RunStop,
        now: DateTime<Utc>,
    ) -> (
        WorkflowStage,
        Vec<WorkflowEffect>,
        AccountabilityKind,
        String,
        Option<DateTime<Utc>>,
    ) {
        match stop {
            RunStop::EvidenceAvailable { evidence_id } => (
                WorkflowStage::VerifyingEvidence,
                vec![WorkflowEffect::FetchAndVerifyEvidence { evidence_id }],
                AccountabilityKind::ActiveWorkflow,
                format!("evidence:{evidence_id}:verify"),
                None,
            ),
            RunStop::RetryableFailure { reason } if state.retry_count < self.max_retries => {
                state.retry_count += 1;
                let multiplier = i32::try_from(state.retry_count).unwrap_or(i32::MAX);
                let at = now + self.retry_backoff * multiplier;
                (
                    WorkflowStage::WaitingRetry,
                    vec![WorkflowEffect::ScheduleRetry {
                        at,
                        reason: reason.clone(),
                    }],
                    AccountabilityKind::Retry,
                    format!("retry:{}:{reason}", state.retry_count),
                    Some(at),
                )
            }
            RunStop::RetryableFailure { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::BlockedExternal,
                format!("retry limit reached: {reason}"),
                now + self.escalation_sla,
            ),
            RunStop::ApprovalRequired {
                approval_type,
                reason,
            } => (
                WorkflowStage::WaitingApproval,
                vec![WorkflowEffect::RequestApproval {
                    approval_type,
                    reason: reason.clone(),
                }],
                AccountabilityKind::Approval,
                format!("approval:{approval_type:?}:{reason}"),
                Some(now + self.approval_sla),
            ),
            RunStop::BudgetExhausted { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::BudgetExhausted,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::ProviderRefused { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::ProviderRefused,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::VerificationFailed { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::VerificationFailed,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::ReviewBlocked { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::ReviewBlocked,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::CiFailed { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::CiFailed,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::AmbiguousRemoteEffect { reason } => escalation(
                WorkflowStage::Escalated,
                EscalationCategory::RemoteEffectAmbiguous,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::Quarantined { reason } => escalation(
                WorkflowStage::Quarantined,
                EscalationCategory::Quarantined,
                reason,
                now + self.escalation_sla,
            ),
            RunStop::Cancelled => (
                WorkflowStage::Cancelled,
                vec![WorkflowEffect::ReleaseReservations],
                AccountabilityKind::Cancellation,
                "run:cancelled".into(),
                None,
            ),
        }
    }
}

fn escalation(
    stage: WorkflowStage,
    category: EscalationCategory,
    reason: String,
    deadline: DateTime<Utc>,
) -> (
    WorkflowStage,
    Vec<WorkflowEffect>,
    AccountabilityKind,
    String,
    Option<DateTime<Utc>>,
) {
    (
        stage,
        vec![WorkflowEffect::OpenEscalation { category, reason }],
        AccountabilityKind::Escalation,
        format!("escalation:{category:?}"),
        Some(deadline),
    )
}

fn anchor(
    work_item_id: WorkItemId,
    kind: AccountabilityKind,
    reference_id: impl Into<String>,
    wake_or_deadline_at: Option<DateTime<Utc>>,
    generation: u64,
    now: DateTime<Utc>,
) -> AccountabilityAnchor {
    AccountabilityAnchor {
        work_item_id,
        kind,
        reference_id: reference_id.into(),
        wake_or_deadline_at,
        generation,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observing(now: DateTime<Utc>) -> WorkflowState {
        let mut state = WorkflowState::accepted(WorkItemId::new(), now);
        state.stage = WorkflowStage::ObservingRun;
        state.run_id = Some(RunId::new());
        state
    }

    #[test]
    fn every_run_stop_has_an_accountable_next_action() {
        let now = Utc::now();
        let stops = vec![
            RunStop::EvidenceAvailable {
                evidence_id: EvidenceId::new(),
            },
            RunStop::RetryableFailure {
                reason: "io".into(),
            },
            RunStop::ApprovalRequired {
                approval_type: ApprovalType::ProtectedPath,
                reason: "protected".into(),
            },
            RunStop::BudgetExhausted {
                reason: "cost".into(),
            },
            RunStop::ProviderRefused {
                reason: "policy".into(),
            },
            RunStop::VerificationFailed {
                reason: "tests".into(),
            },
            RunStop::ReviewBlocked {
                reason: "finding".into(),
            },
            RunStop::CiFailed {
                reason: "ci".into(),
            },
            RunStop::AmbiguousRemoteEffect {
                reason: "timeout".into(),
            },
            RunStop::Quarantined {
                reason: "invariant".into(),
            },
            RunStop::Cancelled,
        ];
        for stop in stops {
            let transition = WorkflowReducer::default()
                .apply(observing(now), WorkflowFact::RunStopped(stop), now)
                .unwrap();
            assert!(!transition.state.accountability.reference_id.is_empty());
            assert!(!transition.effects.is_empty());
        }
    }

    #[test]
    fn ambiguous_submission_reconciles_without_new_attempt() {
        let now = Utc::now();
        let mut state = WorkflowState::accepted(WorkItemId::new(), now);
        state.stage = WorkflowStage::Dispatching;
        state.attempt_number = 1;
        let transition = WorkflowReducer::default()
            .apply(state, WorkflowFact::SubmissionAmbiguous, now)
            .unwrap();
        assert_eq!(transition.state.attempt_number, 1);
        assert_eq!(transition.state.stage, WorkflowStage::Dispatching);
        assert_eq!(
            transition.effects,
            vec![WorkflowEffect::ReconcileSubmission]
        );
    }
}
