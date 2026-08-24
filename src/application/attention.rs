use std::cmp::Ordering;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{EscalationCategory, RetryPolicy, WorkItemId};

/// Durable record type represented in the shared operator-attention queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionItemKind {
    Escalation,
    OperationalIncident,
}

impl AttentionItemKind {
    pub fn from_persisted(value: &str) -> Result<Self, AttentionProjectionError> {
        match value {
            "ESCALATION" => Ok(Self::Escalation),
            "OPERATIONAL_INCIDENT" => Ok(Self::OperationalIncident),
            other => Err(AttentionProjectionError::UnknownItemKind(other.into())),
        }
    }
}

/// Stable ordering used by the Attention Center and its keyset cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AttentionSeverity {
    /// Decode the database representation without accepting unknown severities.
    pub fn from_persisted(value: &str) -> Result<Self, AttentionProjectionError> {
        match value {
            "INFO" => Ok(Self::Info),
            "LOW" => Ok(Self::Low),
            "MEDIUM" => Ok(Self::Medium),
            "HIGH" => Ok(Self::High),
            "CRITICAL" => Ok(Self::Critical),
            other => Err(AttentionProjectionError::UnknownSeverity(other.into())),
        }
    }

    /// Higher ranks sort before lower ranks.
    #[must_use]
    pub const fn rank(self) -> i16 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    #[must_use]
    pub const fn as_persisted(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionOwnerKind {
    Person,
    Team,
    OnCall,
}

impl AttentionOwnerKind {
    fn from_persisted(value: &str) -> Option<Self> {
        match value {
            "PERSON" => Some(Self::Person),
            "TEAM" => Some(Self::Team),
            "ON_CALL" => Some(Self::OnCall),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionOwner {
    pub kind: AttentionOwnerKind,
    pub id: String,
}

/// A durable condition that cannot disappear from the queue until a complete
/// active attention record covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionObligationKind {
    OpenEscalation,
    OpenOperationalIncident,
    PendingApproval,
    WorkNeedsSpec,
    WorkWaitingDependency,
    WorkWaitingApproval,
    WorkBlockedExternal,
    WorkBudgetExhausted,
    WorkQuarantined,
    WorkEscalated,
    DeadWorkflowJob,
}

impl AttentionObligationKind {
    pub fn from_persisted(value: &str) -> Result<Self, AttentionProjectionError> {
        match value {
            "OPEN_ESCALATION" => Ok(Self::OpenEscalation),
            "OPEN_OPERATIONAL_INCIDENT" => Ok(Self::OpenOperationalIncident),
            "PENDING_APPROVAL" => Ok(Self::PendingApproval),
            "WORK_NEEDS_SPEC" => Ok(Self::WorkNeedsSpec),
            "WORK_WAITING_DEPENDENCY" => Ok(Self::WorkWaitingDependency),
            "WORK_WAITING_APPROVAL" => Ok(Self::WorkWaitingApproval),
            "WORK_BLOCKED_EXTERNAL" => Ok(Self::WorkBlockedExternal),
            "WORK_BUDGET_EXHAUSTED" => Ok(Self::WorkBudgetExhausted),
            "WORK_QUARANTINED" => Ok(Self::WorkQuarantined),
            "WORK_ESCALATED" => Ok(Self::WorkEscalated),
            "DEAD_WORKFLOW_JOB" => Ok(Self::DeadWorkflowJob),
            other => Err(AttentionProjectionError::UnknownObligationKind(
                other.into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncoveredAttentionObligation {
    pub kind: AttentionObligationKind,
    pub source_id: Uuid,
    pub work_item_id: Option<WorkItemId>,
}

impl UncoveredAttentionObligation {
    #[must_use]
    pub fn into_error(self) -> AttentionProjectionError {
        AttentionProjectionError::MissingCoveringEscalation {
            kind: self.kind,
            source_id: self.source_id,
            work_item_id: self.work_item_id,
        }
    }
}

/// Raw fields loaded from the durable escalation record. Construction of an
/// API item is deliberately fallible so malformed JSON never becomes a
/// partially truthful operator instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedAttentionItem {
    pub kind: AttentionItemKind,
    pub id: Uuid,
    pub work_item_id: Option<WorkItemId>,
    pub workflow_job_id: Option<Uuid>,
    pub category: EscalationCategory,
    pub severity: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub required_action: String,
    pub evidence_references: Value,
    pub deadline: DateTime<Utc>,
    pub opened_at: DateTime<Utc>,
    pub retry_policy: Value,
    pub authority_or_effect_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionItem {
    pub kind: AttentionItemKind,
    pub id: Uuid,
    pub work_item_id: Option<WorkItemId>,
    pub workflow_job_id: Option<Uuid>,
    pub category: EscalationCategory,
    pub severity: AttentionSeverity,
    pub owner: AttentionOwner,
    pub required_action: String,
    pub evidence_references: Vec<String>,
    pub deadline: DateTime<Utc>,
    pub retry_policy: RetryPolicy,
    pub authority_or_effect_active: bool,
}

/// Compare queue items by severity, then earliest SLA, then stable record
/// identity. `PostgreSQL` uses the same ordering for keyset pagination.
#[must_use]
pub fn compare_attention_items(left: &AttentionItem, right: &AttentionItem) -> Ordering {
    right
        .severity
        .rank()
        .cmp(&left.severity.rank())
        .then_with(|| left.deadline.cmp(&right.deadline))
        .then_with(|| left.id.cmp(&right.id))
}

impl TryFrom<PersistedAttentionItem> for AttentionItem {
    type Error = AttentionProjectionError;

    fn try_from(value: PersistedAttentionItem) -> Result<Self, Self::Error> {
        match (value.kind, value.work_item_id, value.workflow_job_id) {
            (AttentionItemKind::Escalation, Some(_), None)
            | (AttentionItemKind::OperationalIncident, None, Some(_)) => {}
            _ => {
                return Err(AttentionProjectionError::InvalidAttentionField {
                    attention_id: value.id,
                    field: "kind/association",
                });
            }
        }
        let severity = AttentionSeverity::from_persisted(&value.severity)?;
        let owner_kind = AttentionOwnerKind::from_persisted(&value.owner_kind).ok_or(
            AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "owner_type",
            },
        )?;
        if value.owner_id.trim().is_empty() {
            return Err(AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "owner_id",
            });
        }
        if value.required_action.trim().is_empty() {
            return Err(AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "required_action",
            });
        }
        if value.deadline <= value.opened_at {
            return Err(AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "deadline",
            });
        }
        let evidence_references = serde_json::from_value::<Vec<String>>(value.evidence_references)
            .map_err(|_error| AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "evidence_references",
            })?;
        if evidence_references.is_empty()
            || evidence_references
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "evidence_references",
            });
        }
        let retry_policy =
            serde_json::from_value::<RetryPolicy>(value.retry_policy).map_err(|_error| {
                AttentionProjectionError::InvalidAttentionField {
                    attention_id: value.id,
                    field: "retry_policy",
                }
            })?;
        if retry_policy
            .prerequisites
            .iter()
            .any(|prerequisite| prerequisite.trim().is_empty())
        {
            return Err(AttentionProjectionError::InvalidAttentionField {
                attention_id: value.id,
                field: "retry_policy",
            });
        }

        Ok(Self {
            kind: value.kind,
            id: value.id,
            work_item_id: value.work_item_id,
            workflow_job_id: value.workflow_job_id,
            category: value.category,
            severity,
            owner: AttentionOwner {
                kind: owner_kind,
                id: value.owner_id,
            },
            required_action: value.required_action,
            evidence_references,
            deadline: value.deadline,
            retry_policy,
            authority_or_effect_active: value.authority_or_effect_active,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttentionProjectionError {
    #[error("unknown persisted attention severity {0}")]
    UnknownSeverity(String),
    #[error("unknown persisted attention item kind {0}")]
    UnknownItemKind(String),
    #[error("unknown persisted attention obligation kind {0}")]
    UnknownObligationKind(String),
    #[error(
        "attention obligation {kind:?} {source_id} for work item {work_item_id:?} has no complete open covering record"
    )]
    MissingCoveringEscalation {
        kind: AttentionObligationKind,
        source_id: Uuid,
        work_item_id: Option<WorkItemId>,
    },
    #[error("attention record {attention_id} has invalid persisted field {field}")]
    InvalidAttentionField {
        attention_id: Uuid,
        field: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn persisted() -> PersistedAttentionItem {
        let opened_at = Utc::now();
        PersistedAttentionItem {
            kind: AttentionItemKind::Escalation,
            id: Uuid::now_v7(),
            work_item_id: Some(WorkItemId::new()),
            workflow_job_id: None,
            category: EscalationCategory::NeedsApproval,
            severity: "HIGH".into(),
            owner_kind: "TEAM".into(),
            owner_id: "repository-owners".into(),
            required_action: "decide the bound approval".into(),
            evidence_references: json!(["sha256:evidence"]),
            deadline: opened_at + Duration::hours(1),
            opened_at,
            retry_policy: json!({
                "automatic": false,
                "max_additional_attempts": 0,
                "backoff_seconds": 300,
                "prerequisites": ["approval decision"]
            }),
            authority_or_effect_active: true,
        }
    }

    #[test]
    fn complete_persisted_item_is_typed() {
        let item = AttentionItem::try_from(persisted()).expect("complete attention item");
        assert_eq!(item.severity, AttentionSeverity::High);
        assert_eq!(item.severity.rank(), 4);
        assert_eq!(item.owner.kind, AttentionOwnerKind::Team);
        assert_eq!(item.retry_policy.backoff_seconds, 300);
    }

    #[test]
    fn incomplete_retry_policy_fails_closed() {
        let mut value = persisted();
        value.retry_policy = json!({});
        assert!(matches!(
            AttentionItem::try_from(value),
            Err(AttentionProjectionError::InvalidAttentionField {
                field: "retry_policy",
                ..
            })
        ));
    }

    #[test]
    fn blank_retry_prerequisite_fails_closed() {
        let mut value = persisted();
        value.retry_policy["prerequisites"] = json!(["  "]);
        assert!(matches!(
            AttentionItem::try_from(value),
            Err(AttentionProjectionError::InvalidAttentionField {
                field: "retry_policy",
                ..
            })
        ));
    }

    #[test]
    fn severity_rank_is_total_and_stable() {
        let values = [
            AttentionSeverity::Info,
            AttentionSeverity::Low,
            AttentionSeverity::Medium,
            AttentionSeverity::High,
            AttentionSeverity::Critical,
        ];
        assert_eq!(values.map(AttentionSeverity::rank), [1, 2, 3, 4, 5]);
        for severity in values {
            assert_eq!(
                AttentionSeverity::from_persisted(severity.as_persisted()).expect("known severity"),
                severity
            );
        }
    }

    #[test]
    fn queue_order_is_severity_then_sla_then_stable_id() {
        let mut low = AttentionItem::try_from(persisted()).expect("complete low item");
        low.severity = AttentionSeverity::Low;
        let mut critical_later = low.clone();
        critical_later.id = Uuid::from_u128(3);
        critical_later.severity = AttentionSeverity::Critical;
        critical_later.deadline += Duration::hours(2);
        let mut critical_earlier = critical_later.clone();
        critical_earlier.id = Uuid::from_u128(4);
        critical_earlier.deadline -= Duration::hours(1);
        let mut critical_first_id = critical_later.clone();
        critical_first_id.id = Uuid::from_u128(1);
        let mut critical_second_id = critical_later.clone();
        critical_second_id.id = Uuid::from_u128(2);

        let mut items = [
            low,
            critical_second_id.clone(),
            critical_later,
            critical_earlier.clone(),
            critical_first_id.clone(),
        ];
        items.sort_by(compare_attention_items);
        assert_eq!(items[0].id, critical_earlier.id);
        assert_eq!(items[1].id, critical_first_id.id);
        assert_eq!(items[2].id, critical_second_id.id);
        assert_eq!(items[4].severity, AttentionSeverity::Low);
    }

    #[test]
    fn empty_evidence_fails_closed() {
        let mut value = persisted();
        value.evidence_references = json!([]);
        assert!(matches!(
            AttentionItem::try_from(value),
            Err(AttentionProjectionError::InvalidAttentionField {
                field: "evidence_references",
                ..
            })
        ));
    }

    #[test]
    fn uncovered_obligation_retains_source_identity() {
        let source_id = Uuid::now_v7();
        let work_item_id = WorkItemId::new();
        let error = UncoveredAttentionObligation {
            kind: AttentionObligationKind::DeadWorkflowJob,
            source_id,
            work_item_id: Some(work_item_id),
        }
        .into_error();
        assert!(matches!(
            error,
            AttentionProjectionError::MissingCoveringEscalation {
                kind: AttentionObligationKind::DeadWorkflowJob,
                source_id: actual_source,
                work_item_id: Some(actual_work),
            } if actual_source == source_id && actual_work == work_item_id
        ));
    }

    #[test]
    fn tenant_operational_attention_needs_no_synthetic_work_item() {
        let mut value = persisted();
        value.kind = AttentionItemKind::OperationalIncident;
        value.work_item_id = None;
        value.workflow_job_id = Some(Uuid::now_v7());
        value.category = EscalationCategory::WorkflowJobExhausted;
        let item = AttentionItem::try_from(value).expect("complete operational attention item");
        assert!(item.work_item_id.is_none());
        assert!(item.workflow_job_id.is_some());
    }

    #[test]
    fn mismatched_attention_kind_and_association_fail_closed() {
        let mut value = persisted();
        value.workflow_job_id = Some(Uuid::now_v7());
        assert!(matches!(
            AttentionItem::try_from(value),
            Err(AttentionProjectionError::InvalidAttentionField {
                field: "kind/association",
                ..
            })
        ));
    }
}
