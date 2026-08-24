use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{ApprovalId, AttemptId, WorkItemId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalType {
    PlannerInterpretation,
    RiskImplementation,
    ProtectedPath,
    PullRequestDeliveryException,
    GuardedMerge,
    AmbiguousExternalEffect,
    BudgetIncrease,
    Cancellation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    ChangesRequested,
}

/// Every authority-bearing input to an approval. Any changed value invalidates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub work_item_id: WorkItemId,
    pub attempt_id: Option<AttemptId>,
    pub work_order_digest: Option<String>,
    pub candidate_sha: Option<String>,
    pub decision_type: ApprovalType,
    pub risk_digest: String,
    pub policy_digest: String,
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub binding: ApprovalBinding,
    pub owner: String,
    pub one_sentence_request: String,
    pub rationale: String,
    pub consequence_on_approve: String,
    pub consequence_on_reject: String,
    pub consequence_on_timeout: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decision: Option<ApprovalDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionRecord {
    pub decision: ApprovalDecision,
    pub approver_subject: String,
    pub approver_role: String,
    pub reason: Option<String>,
    pub decided_at: DateTime<Utc>,
}

impl ApprovalRequest {
    pub fn decide(
        &mut self,
        binding: &ApprovalBinding,
        decision: ApprovalDecisionRecord,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.decision.is_some() {
            return Err(Error::Conflict("approval has already been decided".into()));
        }
        if now >= self.expires_at {
            return Err(Error::Conflict("approval has expired".into()));
        }
        if &self.binding != binding {
            return Err(Error::Conflict(
                "approval binding changed; a new approval is required".into(),
            ));
        }
        if decision.approver_subject.trim().is_empty() || decision.approver_role.trim().is_empty() {
            return Err(Error::Validation(
                "approver subject and role must be recorded".into(),
            ));
        }
        self.decision = Some(decision);
        Ok(())
    }

    #[must_use]
    pub fn is_effective_for(&self, binding: &ApprovalBinding, now: DateTime<Utc>) -> bool {
        self.binding == *binding
            && now < self.expires_at
            && self
                .decision
                .as_ref()
                .is_some_and(|decision| decision.decision == ApprovalDecision::Approved)
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::Duration;

    use super::*;

    fn binding() -> ApprovalBinding {
        ApprovalBinding {
            work_item_id: WorkItemId::new(),
            attempt_id: Some(AttemptId::new()),
            work_order_digest: Some("sha256:work-order".into()),
            candidate_sha: Some("abc".into()),
            decision_type: ApprovalType::GuardedMerge,
            risk_digest: "sha256:risk".into(),
            policy_digest: "sha256:policy".into(),
            evidence_digest: Some("sha256:evidence".into()),
        }
    }

    #[test]
    fn any_bound_digest_change_invalidates_approval() {
        let now = Utc::now().trunc_subsecs(6);
        let original = binding();
        let request = ApprovalRequest {
            id: ApprovalId::new(),
            binding: original.clone(),
            owner: "repo-owner".into(),
            one_sentence_request: "Merge the exact candidate?".into(),
            rationale: "Policy requires approval".into(),
            consequence_on_approve: "enqueue merge".into(),
            consequence_on_reject: "escalate".into(),
            consequence_on_timeout: "escalate".into(),
            issued_at: now,
            expires_at: now + Duration::hours(1),
            decision: Some(ApprovalDecisionRecord {
                decision: ApprovalDecision::Approved,
                approver_subject: "user:1".into(),
                approver_role: "repository_owner".into(),
                reason: None,
                decided_at: now,
            }),
        };

        let mut changed = original;
        changed.policy_digest = "sha256:new-policy".into();
        assert!(!request.is_effective_for(&changed, now));
    }
}
