//! Wire-exact Work Order contract accepted by the adjacent Runmill service.
//!
//! This contract intentionally lives beside ASF's richer internal authority
//! model. A controller must construct and sign this exact payload directly;
//! it must never reinterpret or re-sign an already signed internal envelope.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    crypto::{Ed25519Signer, canonical_json, is_sha256_digest, sha256_digest, verify_signature},
    security::reject_sensitive_fields,
};

pub const RUNMILL_WORK_ORDER_SCHEMA_V1: &str = "asf.work-order/v1";
pub const RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA_V1: &str = "asf.work-order-envelope/v1";

const SIGNATURE_PREFIX: &str = "base64url:";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 768;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillWorkOrderSourceV1 {
    pub system: String,
    pub external_id: String,
    pub snapshot_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillRepositoryTargetV1 {
    pub forge: String,
    pub repository: String,
    pub base_ref: String,
    pub base_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillObjectiveV1 {
    pub title: String,
    pub description: String,
    pub acceptance_criteria: Vec<String>,
    pub non_goals: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunmillRiskClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillWorkScopeV1 {
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub risk_class: RunmillRiskClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillVerificationRequirementsV1 {
    pub required_local_check_ids: Vec<String>,
    pub required_remote_checks: Vec<String>,
    pub policy_snapshot_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillIdentityRequirementsV1 {
    pub implementer: String,
    pub local_reviewer: String,
    pub pr_reviewer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillRuntimePolicyV1 {
    pub sandbox_profile: String,
    pub tool_policy: String,
    pub network_policy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillBudgetLimitsV1 {
    pub wall_seconds: u64,
    pub max_cost_usd: f64,
    pub max_agent_invocations: u64,
    pub max_fix_iterations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunmillWorkOrderClosureTarget {
    Pr,
    Merge,
    Deploy,
    Observe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillDeliveryAuthorityV1 {
    pub closure_target: RunmillWorkOrderClosureTarget,
    pub draft_pr: bool,
    pub merge_policy_ref: Option<String>,
}

/// Exact `asf.work-order/v1` payload parsed by Runmill's strict Zod schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillWorkOrderV1 {
    pub schema: String,
    pub work_order_id: String,
    pub tenant_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub idempotency_key: String,
    pub source: RunmillWorkOrderSourceV1,
    pub repository: RunmillRepositoryTargetV1,
    pub objective: RunmillObjectiveV1,
    pub scope: RunmillWorkScopeV1,
    pub verification: RunmillVerificationRequirementsV1,
    pub identities: RunmillIdentityRequirementsV1,
    pub runtime: RunmillRuntimePolicyV1,
    pub budgets: RunmillBudgetLimitsV1,
    pub delivery: RunmillDeliveryAuthorityV1,
    pub policy_digest: String,
    pub harness_digest: String,
}

impl RunmillWorkOrderV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNMILL_WORK_ORDER_SCHEMA_V1 {
            return Err(Error::Validation(
                "unsupported Runmill Work Order schema".into(),
            ));
        }
        for (label, value) in [
            ("work-order ID", self.work_order_id.as_str()),
            ("tenant ID", self.tenant_id.as_str()),
            ("work-item ID", self.work_item_id.as_str()),
            ("attempt ID", self.attempt_id.as_str()),
            ("source system", self.source.system.as_str()),
            ("source external ID", self.source.external_id.as_str()),
            ("forge", self.repository.forge.as_str()),
            ("sandbox profile", self.runtime.sandbox_profile.as_str()),
            ("tool policy", self.runtime.tool_policy.as_str()),
            ("network policy", self.runtime.network_policy.as_str()),
        ] {
            if !valid_identifier(value, false) {
                return Err(Error::Validation(format!(
                    "Runmill {label} is not a valid identifier"
                )));
            }
        }
        for (label, value) in [
            ("implementer identity", self.identities.implementer.as_str()),
            (
                "local-reviewer identity",
                self.identities.local_reviewer.as_str(),
            ),
            ("PR-reviewer identity", self.identities.pr_reviewer.as_str()),
        ] {
            if !valid_identifier(value, true) {
                return Err(Error::Validation(format!(
                    "Runmill {label} is not a valid identity"
                )));
            }
        }
        let expected_key = format!(
            "{}/{}/{}",
            self.tenant_id, self.work_item_id, self.attempt_id
        );
        if self.idempotency_key != expected_key || !valid_idempotency_key(&self.idempotency_key) {
            return Err(Error::Validation(
                "Runmill idempotency key must exactly bind tenant, work item, and attempt".into(),
            ));
        }
        if !is_sha256_digest(&self.source.snapshot_digest)
            || !is_sha256_digest(&self.verification.policy_snapshot_digest)
            || !is_sha256_digest(&self.policy_digest)
            || !is_sha256_digest(&self.harness_digest)
        {
            return Err(Error::Validation(
                "Runmill Work Order digests must be tagged lowercase SHA-256 values".into(),
            ));
        }
        if !valid_repository(&self.repository.repository)
            || !valid_base_ref(&self.repository.base_ref)
            || !valid_git_sha(&self.repository.base_sha)
        {
            return Err(Error::Validation(
                "Runmill repository target is malformed or not bound to an exact branch SHA".into(),
            ));
        }
        if self.objective.title.is_empty()
            || self.objective.title.len() > 1_024
            || self.objective.description.is_empty()
            || self.objective.acceptance_criteria.is_empty()
            || self
                .objective
                .acceptance_criteria
                .iter()
                .chain(&self.objective.non_goals)
                .any(String::is_empty)
        {
            return Err(Error::Validation(
                "Runmill objective and acceptance criteria must be complete".into(),
            ));
        }
        if self.scope.allowed_paths.is_empty()
            || self
                .scope
                .allowed_paths
                .iter()
                .chain(&self.scope.forbidden_paths)
                .any(|path| path.is_empty() || path.len() > 1_024)
        {
            return Err(Error::Validation(
                "Runmill path scope must have bounded non-empty allow patterns".into(),
            ));
        }
        if self
            .verification
            .required_local_check_ids
            .iter()
            .any(|check| !valid_identifier(check, false))
            || self
                .verification
                .required_remote_checks
                .iter()
                .any(|check| !valid_remote_check(check))
        {
            return Err(Error::Validation(
                "Runmill verification requirements contain an invalid check".into(),
            ));
        }
        if self.budgets.wall_seconds == 0
            || !self.budgets.max_cost_usd.is_finite()
            || self.budgets.max_cost_usd.is_sign_negative()
            || self.budgets.max_agent_invocations == 0
        {
            return Err(Error::Validation(
                "Runmill budgets require positive wall/invocation limits and finite nonnegative cost"
                    .into(),
            ));
        }
        if self.delivery.closure_target == RunmillWorkOrderClosureTarget::Pr
            && self.delivery.merge_policy_ref.is_some()
        {
            return Err(Error::Validation(
                "a PR-only Runmill Work Order cannot carry merge authority".into(),
            ));
        }
        if self
            .delivery
            .merge_policy_ref
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
        {
            return Err(Error::Validation(
                "Runmill merge-policy reference is invalid".into(),
            ));
        }
        reject_sensitive_fields(&serde_json::to_value(self).map_err(|error| {
            Error::Serialization(format!(
                "serialize Runmill Work Order for safety scan: {error}"
            ))
        })?)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }
}

/// Exact `asf.work-order-envelope/v1` signed by ASF for Runmill admission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunmillSignedWorkOrderV1 {
    pub schema: String,
    pub key_id: String,
    pub algorithm: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub payload: RunmillWorkOrderV1,
    pub signature: String,
}

impl RunmillSignedWorkOrderV1 {
    pub fn sign(
        payload: RunmillWorkOrderV1,
        signer: &Ed25519Signer,
        issued_at: DateTime<Utc>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        payload.validate()?;
        validate_window(issued_at, not_before, expires_at)?;
        if !valid_identifier(signer.key_id(), false) {
            return Err(Error::Validation(
                "Runmill Work Order signing key ID is invalid".into(),
            ));
        }
        let mut envelope = Self {
            schema: RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA_V1.into(),
            key_id: signer.key_id().into(),
            algorithm: "EdDSA".into(),
            issued_at,
            not_before,
            expires_at,
            payload,
            signature: String::new(),
        };
        envelope.signature = format!(
            "{SIGNATURE_PREFIX}{}",
            signer.sign(&envelope.signing_bytes()?)
        );
        Ok(envelope)
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<()> {
        self.verify_integrity(key)?;
        if now < self.not_before {
            return Err(Error::Validation(
                "Runmill Work Order is not active yet".into(),
            ));
        }
        if now >= self.expires_at {
            return Err(Error::Validation("Runmill Work Order has expired".into()));
        }
        Ok(())
    }

    pub fn verify_integrity(&self, key: &VerifyingKey) -> Result<()> {
        self.validate_envelope()?;
        let signature = self
            .signature
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or_else(|| {
                Error::Crypto("Runmill Work Order signature lacks base64url prefix".into())
            })?;
        if signature.is_empty() {
            return Err(Error::Crypto(
                "Runmill Work Order signature is empty".into(),
            ));
        }
        verify_signature(key, &self.signing_bytes()?, signature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_envelope()?;
        canonical_json(self)
    }

    pub fn envelope_digest(&self) -> Result<String> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }

    pub fn payload_digest(&self) -> Result<String> {
        self.payload.digest()
    }

    fn validate_envelope(&self) -> Result<()> {
        if self.schema != RUNMILL_WORK_ORDER_ENVELOPE_SCHEMA_V1
            || self.algorithm != "EdDSA"
            || !valid_identifier(&self.key_id, false)
        {
            return Err(Error::Validation(
                "Runmill Work Order envelope is unsupported or malformed".into(),
            ));
        }
        validate_window(self.issued_at, self.not_before, self.expires_at)?;
        self.payload.validate()?;
        let signature = self
            .signature
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or_else(|| {
                Error::Validation("Runmill Work Order signature must use base64url prefix".into())
            })?;
        if signature.is_empty()
            || !signature
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::Validation(
                "Runmill Work Order signature is not canonical base64url".into(),
            ));
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct ProtectedEnvelope<'a> {
            schema: &'a str,
            key_id: &'a str,
            algorithm: &'a str,
            issued_at: DateTime<Utc>,
            not_before: DateTime<Utc>,
            expires_at: DateTime<Utc>,
            payload: &'a RunmillWorkOrderV1,
        }

        canonical_json(&ProtectedEnvelope {
            schema: &self.schema,
            key_id: &self.key_id,
            algorithm: &self.algorithm,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            payload: &self.payload,
        })
    }
}

fn validate_window(
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    if issued_at > not_before || not_before >= expires_at {
        return Err(Error::Validation(
            "Runmill Work Order requires issued_at <= not_before < expires_at".into(),
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, allow_colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
                || (allow_colon && byte == b':')
        })
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn valid_repository(value: &str) -> bool {
    let mut components = value.split('/');
    components.next().is_some_and(|component| {
        !component.is_empty() && !component.chars().any(char::is_whitespace)
    }) && components.next().is_some_and(|component| {
        !component.is_empty() && !component.chars().any(char::is_whitespace)
    }) && components.next().is_none()
}

fn valid_base_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.contains("//")
        && !branch.ends_with(['/', '.'])
        && !branch.bytes().any(|byte| {
            byte <= 0x20
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        && branch.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.as_bytes().ends_with(b".lock")
        })
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_remote_check(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::TimeDelta;
    use serde_json::json;

    use super::*;

    fn valid_payload() -> RunmillWorkOrderV1 {
        let tenant_id = "0198c8d2-77af-7000-8000-000000000001";
        let work_item_id = "0198c8d2-77af-7000-8000-000000000002";
        let attempt_id = "0198c8d2-77af-7000-8000-000000000003";
        RunmillWorkOrderV1 {
            schema: RUNMILL_WORK_ORDER_SCHEMA_V1.into(),
            work_order_id: "0198c8d2-77af-7000-8000-000000000004".into(),
            tenant_id: tenant_id.into(),
            work_item_id: work_item_id.into(),
            attempt_id: attempt_id.into(),
            idempotency_key: format!("{tenant_id}/{work_item_id}/{attempt_id}"),
            source: RunmillWorkOrderSourceV1 {
                system: "linear".into(),
                external_id: "ASF-42".into(),
                snapshot_digest: sha256_digest(b"source"),
            },
            repository: RunmillRepositoryTargetV1 {
                forge: "github".into(),
                repository: "acme/payments".into(),
                base_ref: "refs/heads/main".into(),
                base_sha: "1".repeat(40),
            },
            objective: RunmillObjectiveV1 {
                title: "Repair bounded regression".into(),
                description: "Reject duplicated settlement".into(),
                acceptance_criteria: vec!["regression test passes".into()],
                non_goals: vec!["no deployment".into()],
            },
            scope: RunmillWorkScopeV1 {
                allowed_paths: vec!["src/**".into(), "tests/**".into()],
                forbidden_paths: vec![".github/**".into()],
                risk_class: RunmillRiskClass::Low,
            },
            verification: RunmillVerificationRequirementsV1 {
                required_local_check_ids: vec!["cargo-test".into()],
                required_remote_checks: vec!["ci/test".into()],
                policy_snapshot_digest: sha256_digest(b"repository-policy"),
            },
            identities: RunmillIdentityRequirementsV1 {
                implementer: "codex:payments-implementer".into(),
                local_reviewer: "claude:payments-local-review".into(),
                pr_reviewer: "claude:payments-pr-review".into(),
            },
            runtime: RunmillRuntimePolicyV1 {
                sandbox_profile: "linux-production-v1".into(),
                tool_policy: "rust-v1".into(),
                network_policy: "github-only-v1".into(),
            },
            budgets: RunmillBudgetLimitsV1 {
                wall_seconds: 3_600,
                max_cost_usd: 5.0,
                max_agent_invocations: 6,
                max_fix_iterations: 2,
            },
            delivery: RunmillDeliveryAuthorityV1 {
                closure_target: RunmillWorkOrderClosureTarget::Pr,
                draft_pr: true,
                merge_policy_ref: None,
            },
            policy_digest: sha256_digest(b"policy"),
            harness_digest: sha256_digest(b"harness"),
        }
    }

    #[test]
    fn envelope_is_runmill_exact_and_uses_direct_jcs_signature() {
        let issued_at = DateTime::parse_from_rfc3339("2026-08-21T10:00:00Z")
            .expect("valid time")
            .with_timezone(&Utc);
        let signer = Ed25519Signer::from_base64_seed(
            "asf-control-v1",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .expect("fixed signer");
        let envelope = RunmillSignedWorkOrderV1::sign(
            valid_payload(),
            &signer,
            issued_at,
            issued_at,
            issued_at + TimeDelta::hours(1),
        )
        .expect("sign exact envelope");
        envelope
            .verify(&signer.verifying_key(), issued_at)
            .expect("verify exact envelope");

        let value = serde_json::to_value(&envelope).expect("serialize envelope");
        let keys = value.as_object().expect("envelope object");
        assert_eq!(keys.len(), 8);
        assert!(keys.get("payload_digest").is_none());
        assert!(envelope.signature.starts_with(SIGNATURE_PREFIX));
        assert_eq!(
            value["payload"]["repository"]["repository"],
            "acme/payments"
        );
        assert_eq!(value["payload"]["delivery"]["closure_target"], "pr");
        assert_eq!(
            envelope.payload_digest().expect("payload digest"),
            sha256_digest(&envelope.payload.canonical_bytes().expect("payload bytes"))
        );
    }

    #[test]
    fn exact_envelope_rejects_unknown_fields_tampering_and_widened_authority() {
        let now = Utc::now().trunc_subsecs(6);
        let signer = Ed25519Signer::generate("asf-control-v1");
        let envelope = RunmillSignedWorkOrderV1::sign(
            valid_payload(),
            &signer,
            now,
            now,
            now + TimeDelta::minutes(30),
        )
        .expect("sign envelope");

        let mut unknown = serde_json::to_value(&envelope).expect("serialize envelope");
        unknown.as_object_mut().expect("object").insert(
            "payload_digest".into(),
            json!(envelope.payload_digest().expect("digest")),
        );
        assert!(serde_json::from_value::<RunmillSignedWorkOrderV1>(unknown).is_err());

        let mut tampered = envelope.clone();
        tampered
            .payload
            .objective
            .description
            .push_str(" and deploy");
        assert!(tampered.verify_integrity(&signer.verifying_key()).is_err());

        let mut merge_authority = envelope.payload;
        merge_authority.delivery.merge_policy_ref = Some("merge-v1".into());
        assert!(merge_authority.validate().is_err());
    }

    #[test]
    fn payload_rejects_secret_material_and_nonbinding_idempotency() {
        let mut payload = valid_payload();
        payload.idempotency_key = "unbound/key".into();
        assert!(payload.validate().is_err());

        let mut payload = valid_payload();
        payload.objective.description = "Bearer abcdefghijklmnop".into();
        assert!(payload.validate().is_err());
    }
}
