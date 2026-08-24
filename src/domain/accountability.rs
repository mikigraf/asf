use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{WorkItemId, WorkItemState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityKind {
    ActiveWorkflow,
    ActiveRun,
    Timer,
    Retry,
    Approval,
    Escalation,
    VerifiedClosure,
    Cancellation,
}

/// The single durable answer to “what will move this accepted item next?”.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityAnchor {
    pub work_item_id: WorkItemId,
    pub kind: AccountabilityKind,
    pub reference_id: String,
    pub wake_or_deadline_at: Option<DateTime<Utc>>,
    pub generation: u64,
    pub updated_at: DateTime<Utc>,
}

pub fn validate_accountability(
    state: WorkItemState,
    accepted_at: Option<DateTime<Utc>>,
    anchor: Option<&AccountabilityAnchor>,
) -> Result<()> {
    // Several lifecycle states (for example WAITING_DEPENDENCY and REFUSED)
    // may occur on either side of acceptance. The immutable acceptance fact,
    // not the state name, determines whether ASF owns an obligation.
    if accepted_at.is_none() {
        return Ok(());
    }
    let anchor = anchor.ok_or_else(|| {
        Error::Validation("accepted work item has no accountability anchor".into())
    })?;
    if anchor.reference_id.trim().is_empty() {
        return Err(Error::Validation(
            "accountability anchor reference is empty".into(),
        ));
    }
    if state == WorkItemState::Closed && anchor.kind != AccountabilityKind::VerifiedClosure {
        return Err(Error::Validation(
            "closed work must have a verified-closure anchor".into(),
        ));
    }
    if state == WorkItemState::Cancelled && anchor.kind != AccountabilityKind::Cancellation {
        return Err(Error::Validation(
            "cancelled work must have a cancellation anchor".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_work_without_anchor_is_a_defect() {
        let accepted_at = Utc::now();
        assert!(validate_accountability(WorkItemState::Accepted, Some(accepted_at), None).is_err());
        assert!(validate_accountability(WorkItemState::Discovered, None, None).is_ok());
        assert!(validate_accountability(WorkItemState::WaitingDependency, None, None).is_ok());
        assert!(validate_accountability(WorkItemState::Refused, Some(accepted_at), None).is_err());
    }

    #[test]
    fn accepted_cancellation_requires_a_terminal_anchor() {
        let now = Utc::now();
        let item_id = WorkItemId::new();
        let mut anchor = AccountabilityAnchor {
            work_item_id: item_id,
            kind: AccountabilityKind::ActiveWorkflow,
            reference_id: "workflow-1".into(),
            wake_or_deadline_at: None,
            generation: 1,
            updated_at: now,
        };
        assert!(
            validate_accountability(WorkItemState::Cancelled, Some(now), Some(&anchor)).is_err()
        );
        anchor.kind = AccountabilityKind::Cancellation;
        assert!(
            validate_accountability(WorkItemState::Cancelled, Some(now), Some(&anchor)).is_ok()
        );
    }
}
