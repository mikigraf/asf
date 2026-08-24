use std::collections::BTreeSet;

use chrono::Duration;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAuthority {
    pub allowed: BTreeSet<String>,
    pub forbidden: BTreeSet<String>,
}

impl PathAuthority {
    pub fn validate(&self) -> Result<()> {
        if self.allowed.is_empty() {
            return Err(Error::Validation("allowed path scope is empty".into()));
        }
        for path in self.allowed.iter().chain(&self.forbidden) {
            validate_repo_path_pattern(path)?;
        }
        Ok(())
    }

    /// Returns the narrower intersection. A child authority can never widen its parent.
    #[must_use]
    pub fn intersect(&self, restriction: &Self) -> Self {
        let allowed = self
            .allowed
            .intersection(&restriction.allowed)
            .cloned()
            .collect();
        let forbidden = self
            .forbidden
            .union(&restriction.forbidden)
            .cloned()
            .collect();
        Self { allowed, forbidden }
    }

    /// Check an exact repository-relative path against the frozen allow/deny scope.
    ///
    /// Patterns support `?` and `*` within one path segment and `**` across
    /// segment boundaries. Deny rules always win.
    #[must_use]
    pub fn allows_path(&self, path: &str) -> bool {
        is_safe_repository_path(path)
            && self
                .allowed
                .iter()
                .any(|pattern| wildcard_matches(pattern.as_bytes(), path.as_bytes()))
            && !self
                .forbidden
                .iter()
                .any(|pattern| wildcard_matches(pattern.as_bytes(), path.as_bytes()))
    }
}

fn validate_repo_path_pattern(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with("./")
        || path.ends_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
        || path.contains('\0')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(Error::Validation(format!(
            "unsafe repository path pattern: {path:?}"
        )));
    }
    Ok(())
}

fn is_safe_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with("./")
        && !path.ends_with('/')
        && !path.contains('*')
        && !path.contains('?')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    let mut reachable = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    reachable[0][0] = true;
    for pattern_index in 0..pattern.len() {
        for value_index in 0..=value.len() {
            if !reachable[pattern_index][value_index] {
                continue;
            }
            match pattern[pattern_index] {
                b'*' if pattern.get(pattern_index + 1) == Some(&b'*') => {
                    reachable[pattern_index + 2][value_index] = true;
                    if value_index < value.len() {
                        reachable[pattern_index][value_index + 1] = true;
                    }
                }
                b'*' => {
                    reachable[pattern_index + 1][value_index] = true;
                    if value.get(value_index).is_some_and(|byte| *byte != b'/') {
                        reachable[pattern_index][value_index + 1] = true;
                    }
                }
                b'?' if value.get(value_index).is_some_and(|byte| *byte != b'/') => {
                    reachable[pattern_index + 1][value_index + 1] = true;
                }
                literal if value.get(value_index) == Some(&literal) => {
                    reachable[pattern_index + 1][value_index + 1] = true;
                }
                _ => {}
            }
        }
    }
    reachable[pattern.len()][value.len()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAuthority {
    pub allowed_tools: BTreeSet<String>,
    pub allowed_commands: BTreeSet<String>,
    pub network_destinations: BTreeSet<String>,
}

impl ToolAuthority {
    #[must_use]
    pub fn intersect(&self, restriction: &Self) -> Self {
        Self {
            allowed_tools: self
                .allowed_tools
                .intersection(&restriction.allowed_tools)
                .cloned()
                .collect(),
            allowed_commands: self
                .allowed_commands
                .intersection(&restriction.allowed_commands)
                .cloned()
                .collect(),
            network_destinations: self
                .network_destinations
                .intersection(&restriction.network_destinations)
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPermission {
    None,
    PullRequest,
    MergeQueue,
    DirectMerge,
}

impl DeliveryPermission {
    #[must_use]
    pub const fn restrict(self, other: Self) -> Self {
        use DeliveryPermission::{DirectMerge, MergeQueue, None, PullRequest};
        match (self, other) {
            (None, _) | (_, None) => None,
            (PullRequest, _) | (_, PullRequest) => PullRequest,
            (MergeQueue, _) | (_, MergeQueue) => MergeQueue,
            (DirectMerge, DirectMerge) => DirectMerge,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthority {
    pub delivery: DeliveryPermission,
    pub may_comment: bool,
    pub may_update_checks: bool,
    pub deployment_environment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub max_cost_microunits: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_implementer_invocations: u32,
    pub max_reviewer_invocations: u32,
    pub max_fix_iterations: u32,
    pub max_wall_time_seconds: u64,
    pub max_external_api_calls: u32,
}

impl BudgetLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_wall_time_seconds == 0
            || self.max_implementer_invocations == 0
            || self.max_reviewer_invocations == 0
        {
            return Err(Error::Validation(
                "wall time and role invocation budgets must be positive".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn wall_time(self) -> Duration {
        Duration::seconds(i64::try_from(self.max_wall_time_seconds).unwrap_or(i64::MAX))
    }

    #[must_use]
    pub fn restrict(self, other: Self) -> Self {
        Self {
            max_cost_microunits: self.max_cost_microunits.min(other.max_cost_microunits),
            max_input_tokens: self.max_input_tokens.min(other.max_input_tokens),
            max_output_tokens: self.max_output_tokens.min(other.max_output_tokens),
            max_implementer_invocations: self
                .max_implementer_invocations
                .min(other.max_implementer_invocations),
            max_reviewer_invocations: self
                .max_reviewer_invocations
                .min(other.max_reviewer_invocations),
            max_fix_iterations: self.max_fix_iterations.min(other.max_fix_iterations),
            max_wall_time_seconds: self.max_wall_time_seconds.min(other.max_wall_time_seconds),
            max_external_api_calls: self
                .max_external_api_calls
                .min(other.max_external_api_calls),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthority {
    pub paths: PathAuthority,
    pub tools: ToolAuthority,
    pub effects: EffectAuthority,
    pub budgets: BudgetLimits,
    pub required_approval_types: BTreeSet<String>,
    pub sandbox_policy_ref: String,
}

impl ExecutionAuthority {
    pub fn validate(&self) -> Result<()> {
        self.paths.validate()?;
        self.budgets.validate()?;
        for (label, value) in self
            .tools
            .allowed_tools
            .iter()
            .map(|value| ("tool", value))
            .chain(
                self.tools
                    .allowed_commands
                    .iter()
                    .map(|value| ("command", value)),
            )
            .chain(
                self.required_approval_types
                    .iter()
                    .map(|value| ("approval type", value)),
            )
        {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(Error::Validation(format!(
                    "authority {label} must be non-empty and contain no control characters"
                )));
            }
        }
        if self.sandbox_policy_ref.trim().is_empty()
            || self.sandbox_policy_ref.chars().any(char::is_control)
        {
            return Err(Error::Validation(
                "sandbox policy reference must be non-empty and contain no control characters"
                    .into(),
            ));
        }
        if self
            .effects
            .deployment_environment
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(Error::Validation(
                "deployment environment must be non-empty and contain no control characters".into(),
            ));
        }
        for destination in &self.tools.network_destinations {
            let url = Url::parse(destination).map_err(|error| {
                Error::Validation(format!(
                    "invalid network destination {destination:?}: {error}"
                ))
            })?;
            if !matches!(url.scheme(), "https" | "ssh")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(Error::Validation(format!(
                    "network destination must be a credential-free https or ssh endpoint: {destination}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_authority_matches_segments_and_deny_wins() {
        let authority = PathAuthority {
            allowed: BTreeSet::from(["src/**".into(), "tests/*.rs".into()]),
            forbidden: BTreeSet::from(["src/generated/**".into()]),
        };
        assert!(authority.allows_path("src/lib.rs"));
        assert!(authority.allows_path("src/nested/module.rs"));
        assert!(authority.allows_path("tests/unit.rs"));
        assert!(!authority.allows_path("tests/nested/unit.rs"));
        assert!(!authority.allows_path("src/generated/schema.rs"));
        assert!(!authority.allows_path("../Cargo.toml"));
        assert!(!authority.allows_path("src\\lib.rs"));
    }

    #[test]
    fn execution_authority_rejects_credential_bearing_network_scope() {
        let mut authority = ExecutionAuthority {
            paths: PathAuthority {
                allowed: BTreeSet::from(["src/**".into()]),
                forbidden: BTreeSet::new(),
            },
            tools: ToolAuthority {
                allowed_tools: BTreeSet::from(["shell".into()]),
                allowed_commands: BTreeSet::from(["cargo test".into()]),
                network_destinations: BTreeSet::from(["https://token@example.test/api".into()]),
            },
            effects: EffectAuthority {
                delivery: DeliveryPermission::PullRequest,
                may_comment: false,
                may_update_checks: false,
                deployment_environment: None,
            },
            budgets: BudgetLimits {
                max_cost_microunits: 1,
                max_input_tokens: 1,
                max_output_tokens: 1,
                max_implementer_invocations: 1,
                max_reviewer_invocations: 1,
                max_fix_iterations: 0,
                max_wall_time_seconds: 1,
                max_external_api_calls: 0,
            },
            required_approval_types: BTreeSet::new(),
            sandbox_policy_ref: "linux-v1".into(),
        };
        assert!(authority.validate().is_err());

        authority.tools.network_destinations = BTreeSet::from(["https://example.test/api".into()]);
        assert!(authority.validate().is_ok());
    }
}
