use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    crypto::{
        Ed25519Signer, canonical_json, is_sha256_digest, sha256_digest, verify_domain_signature,
    },
    domain::{
        AttemptId, ClosureTarget, DeliveryPermission, ExecutionAuthority, RepositoryId,
        RiskAssessment, RiskClass, SourceSystem, TenantId, WorkItemId, WorkOrderId,
        WorkOrderIdentities,
    },
};

pub const WORK_ORDER_SCHEMA_V1: &str = "asf.work-order/v1";
pub const WORK_ORDER_ENVELOPE_SCHEMA_V1: &str = "asf.work-order-envelope/v1";
const WORK_ORDER_SIGNATURE_DOMAIN: &str = "asf.work-order-envelope/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequirements {
    pub local_check_ids: BTreeSet<String>,
    pub remote_ci_contexts: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTarget {
    pub repository_id: RepositoryId,
    pub forge: String,
    pub owner: String,
    pub name: String,
    pub base_ref: String,
    pub base_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDigests {
    pub policy: String,
    pub repository_policy: String,
    pub planner: String,
    pub harness: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderV1 {
    pub schema: String,
    pub work_order_id: WorkOrderId,
    pub tenant_id: TenantId,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub idempotency_key: String,
    pub source_system: SourceSystem,
    pub source_external_id: String,
    pub source_snapshot_digest: String,
    pub source_reference: String,
    pub repository: RepositoryTarget,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub non_goals: Vec<String>,
    pub checks: CheckRequirements,
    pub risk: RiskAssessment,
    pub identities: WorkOrderIdentities,
    pub authority: ExecutionAuthority,
    pub closure_target: ClosureTarget,
    pub digests: ContractDigests,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl WorkOrderV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != WORK_ORDER_SCHEMA_V1 {
            return Err(Error::Validation(format!(
                "unsupported Work Order schema: {}",
                self.schema
            )));
        }
        if self.idempotency_key.trim().is_empty()
            || self.source_external_id.trim().is_empty()
            || self.source_reference.trim().is_empty()
            || self.objective.trim().is_empty()
            || self.acceptance_criteria.is_empty()
            || self
                .acceptance_criteria
                .iter()
                .any(|criterion| criterion.trim().is_empty())
            || self
                .non_goals
                .iter()
                .any(|non_goal| non_goal.trim().is_empty())
            || self
                .checks
                .local_check_ids
                .iter()
                .chain(&self.checks.remote_ci_contexts)
                .any(|check| check.trim().is_empty())
            || self.repository.base_ref.trim().is_empty()
            || self.repository.base_sha.trim().is_empty()
        {
            return Err(Error::Validation(
                "Work Order identity, source, objective, criteria, checks, and exact base must be complete"
                    .into(),
            ));
        }
        if self.idempotency_key.len() > 512 {
            return Err(Error::Validation(
                "Work Order idempotency key exceeds 512 bytes".into(),
            ));
        }
        for (name, digest) in [
            ("source snapshot", self.source_snapshot_digest.as_str()),
            ("policy", self.digests.policy.as_str()),
            ("repository policy", self.digests.repository_policy.as_str()),
            ("planner", self.digests.planner.as_str()),
            ("harness", self.digests.harness.as_str()),
        ] {
            if !is_sha256_digest(digest) {
                return Err(Error::Validation(format!(
                    "{name} digest must be a lowercase sha256 digest"
                )));
            }
        }
        if !matches!(self.repository.forge.as_str(), "github")
            || self.repository.owner.trim().is_empty()
            || self.repository.name.trim().is_empty()
            || !is_git_sha(&self.repository.base_sha)
        {
            return Err(Error::Validation(
                "Work Order requires a GitHub repository and exact 40/64-hex base SHA".into(),
            ));
        }
        if !self.closure_target.production_supported_v1() {
            return Err(Error::Validation(
                "only pull-request closure can be dispatched in V1".into(),
            ));
        }
        if self.authority.effects.delivery != DeliveryPermission::PullRequest
            || self.authority.effects.deployment_environment.is_some()
        {
            return Err(Error::Validation(
                "V1 pull-request Work Orders require exactly pull-request delivery authority and no deployment scope"
                    .into(),
            ));
        }
        if matches!(self.risk.class, RiskClass::Critical | RiskClass::Unknown)
            || self.risk.reasons.is_empty()
            || self.risk.matched_rules.is_empty()
            || self
                .risk
                .reasons
                .iter()
                .any(|reason| reason.trim().is_empty())
            || self
                .risk
                .matched_rules
                .iter()
                .any(|rule| rule.trim().is_empty())
        {
            return Err(Error::Validation(
                "V1 Work Order risk must be automatable and carry non-empty policy rationale"
                    .into(),
            ));
        }
        if self.risk.class == RiskClass::High && self.authority.required_approval_types.is_empty() {
            return Err(Error::Validation(
                "high-risk V1 Work Orders require an explicit bound approval type".into(),
            ));
        }
        if self.not_before < self.issued_at || self.expires_at <= self.not_before {
            return Err(Error::Validation(
                "Work Order timestamps must satisfy issued <= not-before < expiration".into(),
            ));
        }
        self.identities.validate()?;
        self.authority.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }
}

fn is_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkOrder {
    #[serde(rename = "schema")]
    pub envelope_schema: String,
    pub algorithm: String,
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub payload_digest: String,
    pub payload: WorkOrderV1,
    pub signature: String,
}

impl SignedWorkOrder {
    pub fn sign(payload: WorkOrderV1, signer: &Ed25519Signer) -> Result<Self> {
        let bytes = payload.canonical_bytes()?;
        let mut envelope = Self {
            envelope_schema: WORK_ORDER_ENVELOPE_SCHEMA_V1.into(),
            algorithm: "EdDSA".into(),
            key_id: signer.key_id().into(),
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            payload_digest: sha256_digest(&bytes),
            payload,
            signature: String::new(),
        };
        envelope.signature = signer.sign_domain(
            WORK_ORDER_SIGNATURE_DOMAIN,
            &envelope.protected_canonical_bytes()?,
        );
        Ok(envelope)
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<()> {
        self.verify_integrity(key)?;
        if now < self.not_before {
            return Err(Error::Validation("Work Order is not active yet".into()));
        }
        if now >= self.expires_at {
            return Err(Error::Validation("Work Order has expired".into()));
        }
        Ok(())
    }

    /// Verify immutable origin and contents without applying the admission window.
    /// This is used when validating final evidence after an accepted order expired.
    pub fn verify_integrity(&self, key: &VerifyingKey) -> Result<()> {
        if self.envelope_schema != WORK_ORDER_ENVELOPE_SCHEMA_V1 || self.algorithm != "EdDSA" {
            return Err(Error::Crypto("unsupported signed envelope".into()));
        }
        let bytes = self.payload.canonical_bytes()?;
        if sha256_digest(&bytes) != self.payload_digest {
            return Err(Error::Crypto("Work Order payload digest mismatch".into()));
        }
        if self.issued_at != self.payload.issued_at
            || self.not_before != self.payload.not_before
            || self.expires_at != self.payload.expires_at
        {
            return Err(Error::Crypto(
                "Work Order envelope and payload validity windows differ".into(),
            ));
        }
        verify_domain_signature(
            key,
            WORK_ORDER_SIGNATURE_DOMAIN,
            &self.protected_canonical_bytes()?,
            &self.signature,
        )?;
        Ok(())
    }

    fn protected_canonical_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct ProtectedEnvelope<'a> {
            schema: &'a str,
            key_id: &'a str,
            algorithm: &'a str,
            issued_at: DateTime<Utc>,
            not_before: DateTime<Utc>,
            expires_at: DateTime<Utc>,
            payload_digest: &'a str,
            payload: &'a WorkOrderV1,
        }

        canonical_json(&ProtectedEnvelope {
            schema: &self.envelope_schema,
            key_id: &self.key_id,
            algorithm: &self.algorithm,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            payload_digest: &self.payload_digest,
            payload: &self.payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use serde_json::json;

    use super::*;
    use crate::domain::{
        BudgetLimits, CtxlaneProfileRef, DeliveryPermission, EffectAuthority, PathAuthority,
        RiskClass, ToolAuthority,
    };

    fn profile(value: &str) -> CtxlaneProfileRef {
        value
            .parse()
            .unwrap_or_else(|error| panic!("valid ctxlane profile ref: {error}"))
    }

    fn strings(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn valid_work_order() -> WorkOrderV1 {
        let now = DateTime::parse_from_rfc3339("2026-08-21T10:00:00Z").map_or_else(
            |error| panic!("valid test time: {error}"),
            |value| value.with_timezone(&Utc),
        );
        WorkOrderV1 {
            schema: WORK_ORDER_SCHEMA_V1.into(),
            work_order_id: WorkOrderId::new(),
            tenant_id: TenantId::new(),
            work_item_id: WorkItemId::new(),
            attempt_id: AttemptId::new(),
            idempotency_key: "tenant/work-item/attempt".into(),
            source_system: SourceSystem::Linear,
            source_external_id: "ENG-123".into(),
            source_snapshot_digest: sha256_digest(b"source"),
            source_reference: "linear:ENG-123".into(),
            repository: RepositoryTarget {
                repository_id: RepositoryId::new(),
                forge: "github".into(),
                owner: "acme".into(),
                name: "payments".into(),
                base_ref: "refs/heads/main".into(),
                base_sha: "0123456789012345678901234567890123456789".into(),
            },
            objective: "Fix the bounded defect".into(),
            acceptance_criteria: vec!["The regression test passes".into()],
            non_goals: vec!["No unrelated refactor".into()],
            checks: CheckRequirements {
                local_check_ids: strings(&["unit"]),
                remote_ci_contexts: strings(&["ci/test"]),
            },
            risk: RiskAssessment {
                class: RiskClass::Low,
                reasons: vec!["bounded change".into()],
                matched_rules: strings(&["low-risk-default"]),
            },
            identities: WorkOrderIdentities {
                implementer: profile("codex:asf-production"),
                local_reviewer: profile("claude:asf-review"),
                pr_reviewer: profile("claude:asf-review"),
            },
            authority: ExecutionAuthority {
                paths: PathAuthority {
                    allowed: strings(&["src/**", "tests/**"]),
                    forbidden: strings(&[".github/**"]),
                },
                tools: ToolAuthority {
                    allowed_tools: strings(&["filesystem", "shell"]),
                    allowed_commands: strings(&["cargo test"]),
                    network_destinations: BTreeSet::new(),
                },
                effects: EffectAuthority {
                    delivery: DeliveryPermission::PullRequest,
                    may_comment: false,
                    may_update_checks: false,
                    deployment_environment: None,
                },
                budgets: BudgetLimits {
                    max_cost_microunits: 10_000_000,
                    max_input_tokens: 100_000,
                    max_output_tokens: 50_000,
                    max_implementer_invocations: 4,
                    max_reviewer_invocations: 2,
                    max_fix_iterations: 2,
                    max_wall_time_seconds: 3_600,
                    max_external_api_calls: 20,
                },
                required_approval_types: BTreeSet::new(),
                sandbox_policy_ref: "linux-production-v1".into(),
            },
            closure_target: ClosureTarget::PullRequest,
            digests: ContractDigests {
                policy: sha256_digest(b"policy"),
                repository_policy: sha256_digest(b"repository-policy"),
                planner: sha256_digest(b"planner"),
                harness: sha256_digest(b"harness"),
            },
            issued_at: now,
            not_before: now,
            expires_at: now + TimeDelta::minutes(15),
        }
    }

    #[test]
    fn work_order_serializes_exact_role_profile_references_at_top_level() {
        let order = valid_work_order();
        order
            .validate()
            .unwrap_or_else(|error| panic!("valid Work Order: {error}"));

        let value = serde_json::to_value(&order)
            .unwrap_or_else(|error| panic!("serialize Work Order: {error}"));
        assert_eq!(value["identities"]["implementer"], "codex:asf-production");
        assert_eq!(value["identities"]["local_reviewer"], "claude:asf-review");
        assert_eq!(value["identities"]["pr_reviewer"], "claude:asf-review");
        assert!(value["authority"].get("identities").is_none());
        assert!(value["identities"].get("provider").is_none());
        assert!(value["identities"].get("expected_principal").is_none());
    }

    #[test]
    fn work_order_identity_input_rejects_paths_unknown_fields_and_shared_implementer() {
        let order = valid_work_order();
        let mut value = serde_json::to_value(&order)
            .unwrap_or_else(|error| panic!("serialize Work Order: {error}"));
        value["identities"]["implementer"] = json!("codex:/run/credential");
        assert!(serde_json::from_value::<WorkOrderV1>(value).is_err());

        let mut value = serde_json::to_value(&order)
            .unwrap_or_else(|error| panic!("serialize Work Order: {error}"));
        value["identities"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("identity requirements must be an object"))
            .insert("execution_handle".into(), json!("exec_unsafe"));
        assert!(serde_json::from_value::<WorkOrderV1>(value).is_err());

        let mut shared = order;
        shared.identities.local_reviewer = shared.identities.implementer.clone();
        assert!(shared.validate().is_err());
    }

    #[test]
    fn signature_binds_the_validity_window_and_payload() {
        let order = valid_work_order();
        let signer = Ed25519Signer::generate("asf-test");
        let key = signer.verifying_key();
        let now = order.not_before;
        let signed = SignedWorkOrder::sign(order, &signer).unwrap();
        signed.verify(&key, now).unwrap();

        let mut changed_window = signed.clone();
        changed_window.expires_at += TimeDelta::minutes(5);
        assert!(changed_window.verify(&key, now).is_err());

        let mut changed_payload = signed;
        changed_payload
            .payload
            .objective
            .push_str(" with wider scope");
        assert!(changed_payload.verify(&key, now).is_err());
    }

    #[test]
    fn pr_order_rejects_merge_authority_and_incomplete_signed_inputs() {
        let mut merge_authority = valid_work_order();
        merge_authority.authority.effects.delivery = DeliveryPermission::DirectMerge;
        assert!(merge_authority.validate().is_err());

        let mut blank_criterion = valid_work_order();
        blank_criterion.acceptance_criteria = vec!["  ".into()];
        assert!(blank_criterion.validate().is_err());

        let mut unexplained_risk = valid_work_order();
        unexplained_risk.risk.reasons.clear();
        assert!(unexplained_risk.validate().is_err());

        let mut unapproved_high_risk = valid_work_order();
        unapproved_high_risk.risk.class = RiskClass::High;
        assert!(unapproved_high_risk.validate().is_err());
    }
}
