use std::{fmt, ops::Deref, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Error, Result};

use super::{RunId, WorkerId};

const MAX_PROFILE_NAME_BYTES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 64;
const MAX_REASON_CODE_BYTES: usize = 96;
const MAX_LEASE_ID_BYTES: usize = 128;
const MAX_ATTRIBUTION_REF_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CtxlaneProvider {
    Claude,
    Codex,
}

impl fmt::Display for CtxlaneProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        })
    }
}

/// An explicit, non-secret ctxlane profile selector.
///
/// The wire representation intentionally matches ctxlane's current `provider:name`
/// contract. It is not a credential, principal, vendor-home path, or execution handle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CtxlaneProfileRef(String);

impl CtxlaneProfileRef {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn provider(&self) -> CtxlaneProvider {
        if self.0.starts_with("claude:") {
            CtxlaneProvider::Claude
        } else {
            // Construction and deserialization are validated, so Codex is the
            // only remaining provider.
            CtxlaneProvider::Codex
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.0.split_once(':').map_or("", |(_provider, name)| name)
    }
}

impl fmt::Display for CtxlaneProfileRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CtxlaneProfileRef {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let (provider, name) = value.split_once(':').ok_or_else(|| {
            Error::Validation(format!(
                "ctxlane profile reference {value:?} must have the form `claude:name` or `codex:name`"
            ))
        })?;
        if name.contains(':') {
            return Err(Error::Validation(format!(
                "ctxlane profile reference {value:?} contains too many `:` separators"
            )));
        }
        if !matches!(provider, "claude" | "codex") {
            return Err(Error::Validation(format!(
                "ctxlane profile reference {value:?} has an unsupported provider"
            )));
        }
        validate_profile_name(name)?;
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for CtxlaneProfileRef {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl<'de> Deserialize<'de> for CtxlaneProfileRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn validate_profile_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_PROFILE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        return Err(Error::Validation(
            "ctxlane profile name must be 1-64 ASCII letters, digits, `-`, or `_`, and start with a letter or digit"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityRole {
    Implementer,
    LocalReviewer,
    PrReviewer,
}

impl fmt::Display for IdentityRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Implementer => "implementer",
            Self::LocalReviewer => "local-reviewer",
            Self::PrReviewer => "pr-reviewer",
        })
    }
}

/// Exact role-to-profile requirements signed into a Work Order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderIdentities {
    pub implementer: CtxlaneProfileRef,
    pub local_reviewer: CtxlaneProfileRef,
    pub pr_reviewer: CtxlaneProfileRef,
}

impl WorkOrderIdentities {
    pub fn validate(&self) -> Result<()> {
        // Different refs are only an early necessary check. ctxlane remains
        // authoritative for proving that they resolve to different principals.
        if self.implementer == self.local_reviewer || self.implementer == self.pr_reviewer {
            return Err(Error::Validation(
                "implementer and reviewer ctxlane profile references must differ".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn profile_for(&self, role: IdentityRole) -> &CtxlaneProfileRef {
        match role {
            IdentityRole::Implementer => &self.implementer,
            IdentityRole::LocalReviewer => &self.local_reviewer,
            IdentityRole::PrReviewer => &self.pr_reviewer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct AutomationEnvironment(String);

impl AutomationEnvironment {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AutomationEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AutomationEnvironment {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        validate_safe_atom(
            "automation environment",
            value,
            MAX_ENVIRONMENT_BYTES,
            false,
        )?;
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for AutomationEnvironment {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct IdentityReasonCode(String);

impl IdentityReasonCode {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentityReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Deref for IdentityReasonCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for IdentityReasonCode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        validate_safe_atom("identity reason code", value, MAX_REASON_CODE_BYTES, true)?;
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for IdentityReasonCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn validate_safe_atom(label: &str, value: &str, max_bytes: usize, allow_dot: bool) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_')
                || (allow_dot && byte == b'.')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        return Err(Error::Validation(format!(
            "{label} must be a bounded ASCII machine identifier"
        )));
    }
    Ok(())
}

macro_rules! non_secret_reference {
    ($name:ident, $label:literal, $max:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                validate_non_secret_reference($label, value, $max)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CtxlaneLeaseId(String);

impl CtxlaneLeaseId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CtxlaneLeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CtxlaneLeaseId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        validate_safe_atom("ctxlane lease ID", value, MAX_LEASE_ID_BYTES, true)?;
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for CtxlaneLeaseId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

non_secret_reference!(
    CtxlanePrincipalRef,
    "ctxlane principal reference",
    MAX_ATTRIBUTION_REF_BYTES
);
non_secret_reference!(
    CtxlaneWorkspaceRef,
    "ctxlane workspace reference",
    MAX_ATTRIBUTION_REF_BYTES
);

fn validate_non_secret_reference(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(Error::Validation(format!(
            "{label} must be non-empty, bounded, and contain no whitespace or control characters"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CtxlaneAuthMode {
    Wif,
    SubscriptionToken,
    ChatgptOauth,
    ApiKey,
    AccessToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialIsolation {
    CredentialIsolated,
    Unproven,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessCheckStatus {
    Passed,
    Failed,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReadinessChecks {
    pub metadata_valid: ReadinessCheckStatus,
    pub credential_source_available: ReadinessCheckStatus,
    pub upstream_identity_token_current: ReadinessCheckStatus,
    pub provider_harness_trusted: ReadinessCheckStatus,
    pub provider_principal_verified: ReadinessCheckStatus,
    pub expected_workspace_verified: ReadinessCheckStatus,
    pub automation_policy_permitted: ReadinessCheckStatus,
}

impl IdentityReadinessChecks {
    #[must_use]
    pub const fn permits_dispatch(&self) -> bool {
        matches!(self.metadata_valid, ReadinessCheckStatus::Passed)
            && matches!(
                self.credential_source_available,
                ReadinessCheckStatus::Passed
            )
            && matches!(
                self.upstream_identity_token_current,
                ReadinessCheckStatus::Passed | ReadinessCheckStatus::NotApplicable
            )
            && matches!(self.provider_harness_trusted, ReadinessCheckStatus::Passed)
            && matches!(
                self.provider_principal_verified,
                ReadinessCheckStatus::Passed
            )
            && matches!(
                self.expected_workspace_verified,
                ReadinessCheckStatus::Passed | ReadinessCheckStatus::NotApplicable
            )
            && matches!(
                self.automation_policy_permitted,
                ReadinessCheckStatus::Passed
            )
    }
}

/// A credential-free, worker-bound snapshot of ctxlane profile readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReadiness {
    pub profile_ref: CtxlaneProfileRef,
    pub role: IdentityRole,
    pub environment: AutomationEnvironment,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub policy_digest: String,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub checks: IdentityReadinessChecks,
    pub principal_ref: Option<CtxlanePrincipalRef>,
    pub workspace_ref: Option<CtxlaneWorkspaceRef>,
    pub auth_mode: Option<CtxlaneAuthMode>,
    pub isolation: CredentialIsolation,
    pub refusal_code: Option<IdentityReasonCode>,
}

#[derive(Debug, Clone, Copy)]
pub struct IdentityReadinessExpectation<'a> {
    pub profile_ref: &'a CtxlaneProfileRef,
    pub role: IdentityRole,
    pub environment: &'a AutomationEnvironment,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub policy_digest: &'a str,
    pub at: DateTime<Utc>,
}

impl IdentityReadiness {
    pub fn validate(&self) -> Result<()> {
        if self.worker_generation == 0 || self.policy_digest.trim().is_empty() {
            return Err(Error::Validation(
                "identity readiness requires a worker generation and policy digest".into(),
            ));
        }
        if self.valid_until <= self.checked_at {
            return Err(Error::Validation(
                "identity readiness validity must end after it was checked".into(),
            ));
        }
        if matches!(
            self.checks.provider_principal_verified,
            ReadinessCheckStatus::Passed
        ) && self.principal_ref.is_none()
        {
            return Err(Error::Validation(
                "verified provider-principal readiness requires non-secret principal attribution"
                    .into(),
            ));
        }
        if matches!(
            self.checks.expected_workspace_verified,
            ReadinessCheckStatus::Passed
        ) && self.workspace_ref.is_none()
        {
            return Err(Error::Validation(
                "verified workspace readiness requires non-secret workspace attribution".into(),
            ));
        }

        let ready = self.checks.permits_dispatch()
            && self.auth_mode.is_some()
            && self.isolation == CredentialIsolation::CredentialIsolated;
        if ready == self.refusal_code.is_some() {
            return Err(Error::Validation(
                "ready identity records must omit a refusal code and non-ready records must include one"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn ensure_ready_for(&self, expected: &IdentityReadinessExpectation<'_>) -> Result<()> {
        self.validate()?;
        if &self.profile_ref != expected.profile_ref
            || self.role != expected.role
            || &self.environment != expected.environment
            || self.worker_id != expected.worker_id
            || self.worker_generation != expected.worker_generation
            || self.policy_digest != expected.policy_digest
        {
            return Err(Error::Validation(
                "identity readiness is not bound to the requested profile, role, environment, worker generation, and policy"
                    .into(),
            ));
        }
        if expected.at < self.checked_at || expected.at >= self.valid_until {
            return Err(Error::Validation(
                "identity readiness is not currently valid".into(),
            ));
        }
        if !self.checks.permits_dispatch()
            || self.auth_mode.is_none()
            || self.isolation != CredentialIsolation::CredentialIsolated
            || self.refusal_code.is_some()
        {
            return Err(Error::Validation(
                "identity readiness did not prove every required production check".into(),
            ));
        }
        Ok(())
    }

    /// A conservative convenience for readiness aggregation when all binding
    /// fields have already been checked by the caller.
    #[must_use]
    pub fn production_ready_at(&self, at: DateTime<Utc>) -> bool {
        self.validate().is_ok()
            && at >= self.checked_at
            && at < self.valid_until
            && self.checks.permits_dispatch()
            && self.auth_mode.is_some()
            && self.isolation == CredentialIsolation::CredentialIsolated
            && self.refusal_code.is_none()
    }
}

/// The safe subset of lease attribution that Runmill may return to ASF.
///
/// Deliberately absent: credentials, token or vendor-state paths, reconstructed
/// environments, and ctxlane execution handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLeaseAttribution {
    pub lease_id: CtxlaneLeaseId,
    pub profile_ref: CtxlaneProfileRef,
    pub principal_ref: CtxlanePrincipalRef,
    pub workspace_ref: Option<CtxlaneWorkspaceRef>,
    pub auth_mode: CtxlaneAuthMode,
    pub role: IdentityRole,
    pub run_id: RunId,
    pub worker_id: WorkerId,
    pub policy_digest: String,
    pub fencing_generation: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub isolation: CredentialIsolation,
}

impl IdentityLeaseAttribution {
    pub fn validate(&self) -> Result<()> {
        if self.policy_digest.trim().is_empty() || self.fencing_generation == 0 {
            return Err(Error::Validation(
                "identity attribution requires a policy digest and positive fencing generation"
                    .into(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Validation(
                "identity lease attribution must expire after issuance".into(),
            ));
        }
        Ok(())
    }

    pub fn ensure_production_safe_for(
        &self,
        identities: &WorkOrderIdentities,
        role: IdentityRole,
        run_id: RunId,
        worker_id: WorkerId,
        policy_digest: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if &self.profile_ref != identities.profile_for(role)
            || self.role != role
            || self.run_id != run_id
            || self.worker_id != worker_id
            || self.policy_digest != policy_digest
        {
            return Err(Error::Validation(
                "identity lease attribution is not bound to the expected Work Order role and run"
                    .into(),
            ));
        }
        if at < self.issued_at || at >= self.expires_at {
            return Err(Error::Validation(
                "identity lease attribution is not currently valid".into(),
            ));
        }
        if self.isolation != CredentialIsolation::CredentialIsolated {
            return Err(Error::Validation(
                "production identity attribution must prove credential isolation".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use serde_json::json;

    use super::*;

    fn at(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value).map_or_else(
            |error| panic!("valid test time: {error}"),
            |value| value.with_timezone(&Utc),
        )
    }

    fn profile(value: &str) -> CtxlaneProfileRef {
        value
            .parse()
            .unwrap_or_else(|error| panic!("valid test profile ref: {error}"))
    }

    fn ready_identity(now: DateTime<Utc>) -> IdentityReadiness {
        IdentityReadiness {
            profile_ref: profile("codex:asf-production"),
            role: IdentityRole::Implementer,
            environment: "production"
                .parse()
                .unwrap_or_else(|error| panic!("valid environment: {error}")),
            worker_id: WorkerId::new(),
            worker_generation: 7,
            policy_digest: "sha256:policy".into(),
            checked_at: now,
            valid_until: now + TimeDelta::minutes(5),
            checks: IdentityReadinessChecks {
                metadata_valid: ReadinessCheckStatus::Passed,
                credential_source_available: ReadinessCheckStatus::Passed,
                upstream_identity_token_current: ReadinessCheckStatus::Passed,
                provider_harness_trusted: ReadinessCheckStatus::Passed,
                provider_principal_verified: ReadinessCheckStatus::Passed,
                expected_workspace_verified: ReadinessCheckStatus::Passed,
                automation_policy_permitted: ReadinessCheckStatus::Passed,
            },
            principal_ref: Some(
                "service-account:software-factory"
                    .parse()
                    .unwrap_or_else(|error| panic!("valid principal ref: {error}")),
            ),
            workspace_ref: Some(
                "chatgpt-workspace:ws_test"
                    .parse()
                    .unwrap_or_else(|error| panic!("valid workspace ref: {error}")),
            ),
            auth_mode: Some(CtxlaneAuthMode::Wif),
            isolation: CredentialIsolation::CredentialIsolated,
            refusal_code: None,
        }
    }

    #[test]
    fn profile_ref_matches_ctxlane_grammar_and_string_wire_shape() {
        for value in ["claude:a", "codex:Work_9-test"] {
            let parsed = profile(value);
            assert_eq!(parsed.as_str(), value);
            assert_eq!(
                serde_json::to_string(&parsed)
                    .unwrap_or_else(|error| panic!("serialize profile: {error}")),
                format!("\"{value}\"")
            );
        }

        for invalid in [
            "",
            "claude",
            "Claude:work",
            "claude:",
            "claude:-work",
            "claude:work.prod",
            "claude:work:other",
            "codex:/tmp/profile",
            "other:work",
        ] {
            assert!(invalid.parse::<CtxlaneProfileRef>().is_err(), "{invalid}");
            let encoded = serde_json::to_string(invalid)
                .unwrap_or_else(|error| panic!("encode invalid profile: {error}"));
            assert!(
                serde_json::from_str::<CtxlaneProfileRef>(&encoded).is_err(),
                "{invalid}"
            );
        }
        assert!(
            format!("claude:{}", "a".repeat(65))
                .parse::<CtxlaneProfileRef>()
                .is_err()
        );
    }

    #[test]
    fn work_order_roles_require_reviewer_profile_separation() {
        let valid = WorkOrderIdentities {
            implementer: profile("codex:implementer"),
            local_reviewer: profile("claude:reviewer"),
            pr_reviewer: profile("claude:reviewer"),
        };
        assert!(valid.validate().is_ok());

        let invalid = WorkOrderIdentities {
            implementer: profile("codex:shared"),
            local_reviewer: profile("codex:shared"),
            pr_reviewer: profile("claude:reviewer"),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn readiness_is_bound_and_fails_closed() {
        let now = at("2026-08-21T10:00:00Z");
        let ready = ready_identity(now);
        let expected = IdentityReadinessExpectation {
            profile_ref: &ready.profile_ref,
            role: ready.role,
            environment: &ready.environment,
            worker_id: ready.worker_id,
            worker_generation: ready.worker_generation,
            policy_digest: &ready.policy_digest,
            at: now + TimeDelta::minutes(1),
        };
        assert!(ready.ensure_ready_for(&expected).is_ok());

        let mut unknown = ready.clone();
        unknown.checks.provider_principal_verified = ReadinessCheckStatus::Unknown;
        unknown.refusal_code = Some(
            "PRINCIPAL_UNVERIFIED"
                .parse()
                .unwrap_or_else(|error| panic!("valid reason: {error}")),
        );
        assert!(unknown.ensure_ready_for(&expected).is_err());

        let mut unisolated = ready.clone();
        unisolated.isolation = CredentialIsolation::Unproven;
        unisolated.refusal_code = Some(
            "ISOLATION_UNPROVEN"
                .parse()
                .unwrap_or_else(|error| panic!("valid reason: {error}")),
        );
        assert!(unisolated.ensure_ready_for(&expected).is_err());

        let stale = IdentityReadinessExpectation {
            at: ready.valid_until,
            ..expected
        };
        assert!(ready.ensure_ready_for(&stale).is_err());
    }

    #[test]
    fn safe_attribution_rejects_execution_handles_and_credential_fields() {
        let now = at("2026-08-21T10:00:00Z");
        let attribution = IdentityLeaseAttribution {
            lease_id: "lease_01JTEST"
                .parse()
                .unwrap_or_else(|error| panic!("valid lease ID: {error}")),
            profile_ref: profile("codex:asf-production"),
            principal_ref: "service-account:software-factory"
                .parse()
                .unwrap_or_else(|error| panic!("valid principal ref: {error}")),
            workspace_ref: Some(
                "chatgpt-workspace:ws_test"
                    .parse()
                    .unwrap_or_else(|error| panic!("valid workspace ref: {error}")),
            ),
            auth_mode: CtxlaneAuthMode::Wif,
            role: IdentityRole::Implementer,
            run_id: RunId::new(),
            worker_id: WorkerId::new(),
            policy_digest: "sha256:policy".into(),
            fencing_generation: 1,
            issued_at: now,
            expires_at: now + TimeDelta::minutes(15),
            isolation: CredentialIsolation::CredentialIsolated,
        };
        assert!(attribution.validate().is_ok());

        let identities = WorkOrderIdentities {
            implementer: attribution.profile_ref.clone(),
            local_reviewer: profile("claude:local-reviewer"),
            pr_reviewer: profile("claude:pr-reviewer"),
        };
        assert!(
            attribution
                .ensure_production_safe_for(
                    &identities,
                    IdentityRole::Implementer,
                    attribution.run_id,
                    attribution.worker_id,
                    &attribution.policy_digest,
                    now + TimeDelta::minutes(1),
                )
                .is_ok()
        );
        assert!(
            attribution
                .ensure_production_safe_for(
                    &identities,
                    IdentityRole::Implementer,
                    attribution.run_id,
                    attribution.worker_id,
                    &attribution.policy_digest,
                    attribution.expires_at,
                )
                .is_err()
        );

        let mut value = serde_json::to_value(&attribution)
            .unwrap_or_else(|error| panic!("serialize attribution: {error}"));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("attribution must serialize as an object"))
            .insert("execution_handle".into(), json!("exec_unsafe"));
        assert!(serde_json::from_value::<IdentityLeaseAttribution>(value).is_err());

        let mut value = serde_json::to_value(&attribution)
            .unwrap_or_else(|error| panic!("serialize attribution: {error}"));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("attribution must serialize as an object"))
            .insert("credential_path".into(), json!("/run/secret"));
        assert!(serde_json::from_value::<IdentityLeaseAttribution>(value).is_err());
    }
}
