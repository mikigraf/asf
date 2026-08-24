use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{
    AutomationEnvironment, ClosureTarget, IdentityReadiness, IdentityReadinessExpectation,
    IdentityRole, Repository, RiskAssessment, RiskClass, SourceSnapshot, WorkOrderIdentities,
    Worker,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessStatus {
    Ready,
    NeedsSpec,
    NeedsApproval,
    Unsupported,
    BlockedDependency,
    PolicyRefused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessIssue {
    pub code: String,
    pub field: String,
    pub owner: String,
    pub suggested_action: String,
    pub reevaluation_trigger: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessReport {
    pub status: ReadinessStatus,
    pub issues: Vec<ReadinessIssue>,
    pub evaluated_at: DateTime<Utc>,
    pub source_snapshot_digest: String,
    pub policy_digest: String,
}

#[derive(Debug)]
pub struct ReadinessContext<'a> {
    pub snapshot: &'a SourceSnapshot,
    pub source_is_current: bool,
    pub repository: Option<&'a Repository>,
    pub closure_target: ClosureTarget,
    pub risk: &'a RiskAssessment,
    pub dependencies_known: bool,
    pub dependency_cycle: bool,
    pub dependencies_satisfied: bool,
    pub exact_base_sha: Option<&'a str>,
    pub path_and_check_policy_compiled: bool,
    pub identity_requirements: &'a WorkOrderIdentities,
    pub identity_environment: &'a AutomationEnvironment,
    pub identities: &'a [IdentityReadiness],
    pub worker: Option<&'a Worker>,
    pub budgets_reservable: bool,
    pub required_approval_present_or_scheduled: bool,
    pub policy_digest: &'a str,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct ReadinessEngine;

impl ReadinessEngine {
    #[must_use]
    pub fn evaluate(&self, context: &ReadinessContext<'_>) -> ReadinessReport {
        let mut issues = Vec::new();
        let source_owner = context
            .snapshot
            .content
            .assignee
            .as_deref()
            .unwrap_or("product-owner");

        if context.repository.is_none() {
            issues.push(issue(
                "REPOSITORY_MAPPING_MISSING",
                "repository",
                source_owner,
                "map the source item to a registered repository",
                "repository configuration changed",
            ));
        }
        if !context.source_is_current {
            issues.push(issue(
                "SOURCE_SNAPSHOT_STALE",
                "source_snapshot",
                source_owner,
                "refresh and re-evaluate the source snapshot",
                "new source snapshot captured",
            ));
        }
        if context.snapshot.content.objective.trim().is_empty() {
            issues.push(issue(
                "OBJECTIVE_MISSING",
                "objective",
                source_owner,
                "provide a concrete objective",
                "source objective changed",
            ));
        }
        if context.snapshot.content.acceptance_criteria.is_empty()
            || context
                .snapshot
                .content
                .acceptance_criteria
                .iter()
                .any(|criterion| criterion.trim().is_empty())
        {
            issues.push(issue(
                "ACCEPTANCE_CRITERIA_UNTESTABLE",
                "acceptance_criteria",
                source_owner,
                "provide observable acceptance criteria",
                "source acceptance criteria changed",
            ));
        }
        if !context.dependencies_known {
            issues.push(issue(
                "DEPENDENCIES_UNKNOWN",
                "dependencies",
                source_owner,
                "identify blocking dependencies",
                "dependency graph changed",
            ));
        } else if context.dependency_cycle {
            issues.push(issue(
                "DEPENDENCY_CYCLE",
                "dependencies",
                "repository-owner",
                "break the dependency cycle",
                "dependency graph changed",
            ));
        } else if !context.dependencies_satisfied {
            issues.push(issue(
                "DEPENDENCY_BLOCKED",
                "dependencies",
                source_owner,
                "complete or waive the blocking dependency",
                "dependency target reached",
            ));
        }
        if context.exact_base_sha.is_none_or(str::is_empty) {
            issues.push(issue(
                "BASE_SHA_UNRESOLVED",
                "base_sha",
                "repository-owner",
                "resolve the configured base ref to an exact commit",
                "repository base becomes reachable",
            ));
        }
        if !context.path_and_check_policy_compiled {
            issues.push(issue(
                "POLICY_COMPILE_FAILED",
                "policy",
                "policy-admin",
                "repair the path and check policy",
                "policy version changed",
            ));
        }
        if !context.closure_target.production_supported_v1() {
            issues.push(issue(
                "CLOSURE_TARGET_UNSUPPORTED",
                "closure_target",
                "repository-owner",
                "select the pull-request closure target for V1",
                "target or adapter support changed",
            ));
        }
        if matches!(context.risk.class, RiskClass::Critical | RiskClass::Unknown) {
            issues.push(issue(
                "RISK_NOT_AUTOMATABLE_V1",
                "risk",
                "policy-admin",
                "refuse, narrow, or route the item to human-controlled delivery",
                "risk assessment or policy changed",
            ));
        }
        if context.identities.len() != 3 {
            issues.push(issue(
                "IDENTITY_ROLES_INCOMPLETE",
                "identities",
                "platform-operator",
                "configure implementer, local reviewer, and PR reviewer profiles",
                "identity configuration changed",
            ));
        }
        let worker_binding = context.worker.map(|worker| (worker.id, worker.generation));
        for role in [
            IdentityRole::Implementer,
            IdentityRole::LocalReviewer,
            IdentityRole::PrReviewer,
        ] {
            let matching: Vec<&IdentityReadiness> = context
                .identities
                .iter()
                .filter(|readiness| readiness.role == role)
                .collect();
            let bound_ready = worker_binding.is_some_and(|(worker_id, worker_generation)| {
                matching.len() == 1
                    && matching[0]
                        .ensure_ready_for(&IdentityReadinessExpectation {
                            profile_ref: context.identity_requirements.profile_for(role),
                            role,
                            environment: context.identity_environment,
                            worker_id,
                            worker_generation,
                            policy_digest: context.policy_digest,
                            at: context.now,
                        })
                        .is_ok()
            });
            if !bound_ready {
                issues.push(issue(
                    matching
                        .first()
                        .and_then(|readiness| readiness.refusal_code.as_deref())
                        .unwrap_or("IDENTITY_BINDING_NOT_READY"),
                    "identities",
                    "platform-operator",
                    "restore the role-bound identity readiness proof and re-run preflight",
                    "fresh ctxlane readiness result received",
                ));
            }
        }
        let implementer_principal = context
            .identities
            .iter()
            .find(|readiness| readiness.role == IdentityRole::Implementer)
            .and_then(|readiness| readiness.principal_ref.as_ref());
        let reviewers_are_independent = implementer_principal.is_some_and(|implementer| {
            [IdentityRole::LocalReviewer, IdentityRole::PrReviewer]
                .into_iter()
                .all(|role| {
                    context
                        .identities
                        .iter()
                        .find(|readiness| readiness.role == role)
                        .and_then(|readiness| readiness.principal_ref.as_ref())
                        .is_some_and(|reviewer| reviewer != implementer)
                })
        });
        if !reviewers_are_independent {
            issues.push(issue(
                context
                    .identities
                    .iter()
                    .find_map(|readiness| readiness.refusal_code.as_deref())
                    .unwrap_or("IDENTITY_PRINCIPAL_SEPARATION_UNPROVEN"),
                "identities",
                "platform-operator",
                "have ctxlane prove implementer/reviewer principal separation",
                "fresh ctxlane principal attestations received",
            ));
        }
        if context
            .worker
            .is_none_or(|worker| !worker.production_ready())
        {
            issues.push(issue(
                "WORKER_UNAVAILABLE",
                "worker",
                "platform-operator",
                "register or recover a compatible healthy worker",
                "worker health or capabilities changed",
            ));
        }
        if !context.budgets_reservable {
            issues.push(issue(
                "BUDGET_UNAVAILABLE",
                "budgets",
                "platform-operator",
                "wait for budget release or approve a bound increase",
                "budget ledger changed",
            ));
        }
        if !context.required_approval_present_or_scheduled {
            issues.push(issue(
                "APPROVAL_PATH_MISSING",
                "approvals",
                "repository-owner",
                "supply or schedule the required approval",
                "approval request created or decided",
            ));
        }

        let status = classify(&issues);
        ReadinessReport {
            status,
            issues,
            evaluated_at: context.now,
            source_snapshot_digest: context.snapshot.content_digest.clone(),
            policy_digest: context.policy_digest.into(),
        }
    }
}

fn issue(
    code: &str,
    field: &str,
    owner: &str,
    suggested_action: &str,
    reevaluation_trigger: &str,
) -> ReadinessIssue {
    ReadinessIssue {
        code: code.into(),
        field: field.into(),
        owner: owner.into(),
        suggested_action: suggested_action.into(),
        reevaluation_trigger: reevaluation_trigger.into(),
    }
}

fn classify(issues: &[ReadinessIssue]) -> ReadinessStatus {
    if issues.is_empty() {
        return ReadinessStatus::Ready;
    }
    if issues.iter().any(|item| {
        matches!(
            item.code.as_str(),
            "CLOSURE_TARGET_UNSUPPORTED" | "WORKER_PROTOCOL_UNSUPPORTED"
        )
    }) {
        ReadinessStatus::Unsupported
    } else if issues.iter().any(|item| item.code == "DEPENDENCY_BLOCKED") {
        ReadinessStatus::BlockedDependency
    } else if issues.iter().any(|item| {
        matches!(
            item.code.as_str(),
            "POLICY_COMPILE_FAILED" | "RISK_NOT_AUTOMATABLE_V1" | "DEPENDENCY_CYCLE"
        )
    }) {
        ReadinessStatus::PolicyRefused
    } else if issues
        .iter()
        .any(|item| item.code == "APPROVAL_PATH_MISSING")
    {
        ReadinessStatus::NeedsApproval
    } else {
        ReadinessStatus::NeedsSpec
    }
}
