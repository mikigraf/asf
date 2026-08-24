use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PlatformAdmin,
    PolicyAdmin,
    RepositoryOwner,
    Approver,
    Operator,
    Auditor,
    Viewer,
    IntakeSubmitter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ViewLedger,
    ViewProtectedEvidence,
    AcceptWork,
    CancelWork,
    DecideApproval,
    ManagePolicy,
    ManageRepository,
    Reconcile,
    ManageWorkers,
    ManagePlatform,
    ExportAudit,
    SubmitIntake,
}

#[must_use]
pub fn role_allows(role: Role, permission: Permission) -> bool {
    use Permission as P;
    use Role as R;
    match role {
        R::PlatformAdmin => true,
        R::PolicyAdmin => matches!(permission, P::ViewLedger | P::ManagePolicy | P::ExportAudit),
        R::RepositoryOwner => matches!(
            permission,
            P::ViewLedger
                | P::AcceptWork
                | P::CancelWork
                | P::DecideApproval
                | P::ManageRepository
                | P::SubmitIntake
        ),
        R::Approver => matches!(permission, P::ViewLedger | P::DecideApproval),
        R::Operator => matches!(
            permission,
            P::ViewLedger | P::CancelWork | P::Reconcile | P::ManageWorkers
        ),
        R::Auditor => matches!(
            permission,
            P::ViewLedger | P::ViewProtectedEvidence | P::ExportAudit
        ),
        R::Viewer => permission == P::ViewLedger,
        R::IntakeSubmitter => permission == P::SubmitIntake,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub subject: String,
    pub roles: BTreeSet<Role>,
}

impl Caller {
    pub fn require(&self, permission: Permission) -> Result<()> {
        if self
            .roles
            .iter()
            .copied()
            .any(|role| role_allows(role, permission))
        {
            Ok(())
        } else {
            Err(Error::Forbidden(format!(
                "subject {} lacks permission {permission:?}",
                self.subject
            )))
        }
    }
}

const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "secret",
    "password",
    "credential",
    "keyring",
    "execution_handle",
    "vendor_home",
    "state_dir",
    "token_file",
];

/// Fails portable-evidence ingestion if a credential-shaped field is present.
pub fn reject_sensitive_fields(value: &Value) -> Result<()> {
    inspect(value, "$")
}

fn inspect(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase();
                if SENSITIVE_KEY_FRAGMENTS
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                {
                    return Err(Error::Validation(format!(
                        "portable evidence contains forbidden sensitive field at {path}.{key}"
                    )));
                }
                inspect(child, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                inspect(child, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::String(value) => {
            let lowercase = value.to_ascii_lowercase();
            if lowercase.starts_with("bearer ")
                || lowercase.contains("-----begin private key-----")
                || lowercase.contains("github_pat_")
            {
                return Err(Error::Validation(format!(
                    "portable evidence contains credential-shaped value at {path}"
                )));
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn roles_remain_distinct() {
        assert!(role_allows(Role::Approver, Permission::DecideApproval));
        assert!(!role_allows(Role::Approver, Permission::ManagePolicy));
        assert!(role_allows(Role::Auditor, Permission::ExportAudit));
        assert!(!role_allows(Role::Auditor, Permission::CancelWork));
    }

    #[test]
    fn intake_submitter_holds_only_submit_intake() {
        assert!(role_allows(Role::IntakeSubmitter, Permission::SubmitIntake));
        assert!(!role_allows(Role::IntakeSubmitter, Permission::AcceptWork));
        assert!(!role_allows(Role::IntakeSubmitter, Permission::ViewLedger));
        assert!(!role_allows(Role::IntakeSubmitter, Permission::CancelWork));
        assert!(!role_allows(
            Role::IntakeSubmitter,
            Permission::ManageRepository
        ));
    }

    #[test]
    fn repository_owner_gains_submit_intake_and_keeps_existing_permissions() {
        assert!(role_allows(Role::RepositoryOwner, Permission::SubmitIntake));
        assert!(role_allows(Role::RepositoryOwner, Permission::ViewLedger));
        assert!(role_allows(Role::RepositoryOwner, Permission::AcceptWork));
        assert!(role_allows(Role::RepositoryOwner, Permission::CancelWork));
        assert!(role_allows(
            Role::RepositoryOwner,
            Permission::DecideApproval
        ));
        assert!(role_allows(
            Role::RepositoryOwner,
            Permission::ManageRepository
        ));
    }

    #[test]
    fn platform_admin_allows_submit_intake() {
        assert!(role_allows(Role::PlatformAdmin, Permission::SubmitIntake));
    }

    #[test]
    fn other_roles_do_not_gain_submit_intake() {
        for role in [
            Role::PolicyAdmin,
            Role::Approver,
            Role::Operator,
            Role::Auditor,
            Role::Viewer,
        ] {
            assert!(
                !role_allows(role, Permission::SubmitIntake),
                "role {role:?} must not gain SubmitIntake"
            );
        }
    }

    #[test]
    fn intake_submitter_role_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(Role::IntakeSubmitter).unwrap(),
            serde_json::json!("intake_submitter")
        );
        assert_eq!(
            serde_json::from_value::<Role>(serde_json::json!("intake_submitter")).unwrap(),
            Role::IntakeSubmitter
        );
    }

    #[test]
    fn portable_evidence_rejects_secret_shaped_content() {
        assert!(reject_sensitive_fields(&json!({"result": "passed"})).is_ok());
        assert!(reject_sensitive_fields(&json!({"access_token": "oops"})).is_err());
        assert!(reject_sensitive_fields(&json!({"nested": ["Bearer abc"]})).is_err());
    }
}
