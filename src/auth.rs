use std::{collections::BTreeSet, fmt};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    Error, Result,
    security::{Caller, Role},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiTokenConfig {
    token: String,
    subject: String,
    roles: BTreeSet<Role>,
}

#[derive(Clone)]
struct StoredCredential {
    token_hash: [u8; 32],
    caller: Caller,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCredential")
            .field("token_hash", &"[REDACTED]")
            .field("caller", &self.caller)
            .finish()
    }
}

#[derive(Clone)]
pub struct ApiAuthenticator {
    credentials: Vec<StoredCredential>,
}

impl fmt::Debug for ApiAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiAuthenticator")
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl ApiAuthenticator {
    pub fn from_json(value: &str) -> Result<Self> {
        let configs: Vec<ApiTokenConfig> = serde_json::from_str(value)
            .map_err(|error| Error::Validation(format!("invalid API token config: {error}")))?;
        if configs.is_empty() {
            return Err(Error::Validation(
                "at least one API credential is required".into(),
            ));
        }
        let mut hashes = BTreeSet::new();
        let mut credentials = Vec::with_capacity(configs.len());
        for config in configs {
            if config.token.len() < 32
                || config.subject.trim().is_empty()
                || config.roles.is_empty()
            {
                return Err(Error::Validation(
                    "API credentials require a >=32-byte token, subject, and roles".into(),
                ));
            }
            let token_hash: [u8; 32] = Sha256::digest(config.token.as_bytes()).into();
            if !hashes.insert(token_hash) {
                return Err(Error::Validation("duplicate API token".into()));
            }
            credentials.push(StoredCredential {
                token_hash,
                caller: Caller {
                    subject: config.subject,
                    roles: config.roles,
                },
            });
        }
        Ok(Self { credentials })
    }

    pub fn authenticate_header(&self, authorization: &str) -> Result<Caller> {
        let token = authorization
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty())
            .ok_or(Error::Unauthenticated)?;
        let candidate: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        // Always inspect every credential to avoid leaking its index through early return timing.
        for credential in &self.credentials {
            if credential.token_hash.ct_eq(&candidate).into() {
                matched = Some(credential.caller.clone());
            }
        }
        matched.ok_or(Error::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Permission, role_allows};

    #[test]
    fn authenticates_without_retaining_plaintext_in_debug() {
        let token = "a-very-long-token-that-is-at-least-32-bytes";
        let auth = ApiAuthenticator::from_json(&format!(
            r#"[{{"token":"{token}","subject":"operator:1","roles":["operator"]}}]"#
        ))
        .unwrap();
        assert_eq!(
            auth.authenticate_header(&format!("Bearer {token}"))
                .unwrap()
                .subject,
            "operator:1"
        );
        assert!(!format!("{auth:?}").contains(token));
        assert!(auth.authenticate_header("Bearer wrong").is_err());
    }

    #[test]
    fn config_parses_intake_submitter_role_with_only_submit_intake() {
        let token = "an-intake-submitter-token-32-bytes-long";
        let auth = ApiAuthenticator::from_json(&format!(
            r#"[{{"token":"{token}","subject":"connector:intake","roles":["intake_submitter"]}}]"#
        ))
        .expect("intake_submitter is a recognized role");
        let caller = auth
            .authenticate_header(&format!("Bearer {token}"))
            .expect("token authenticates");
        assert!(caller.roles.contains(&Role::IntakeSubmitter));
        assert!(role_allows(Role::IntakeSubmitter, Permission::SubmitIntake));
        assert!(!role_allows(Role::IntakeSubmitter, Permission::AcceptWork));
    }

    #[test]
    fn config_rejects_unknown_role() {
        let token = "a-token-with-an-unknown-role-32-bytes-x";
        let error = ApiAuthenticator::from_json(&format!(
            r#"[{{"token":"{token}","subject":"user:x","roles":["totally_bogus_role"]}}]"#
        ))
        .expect_err("unknown role must be rejected");
        assert!(matches!(error, Error::Validation(_)));
    }
}
