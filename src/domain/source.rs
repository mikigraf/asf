use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result, crypto::sha256_digest};

use super::{RepositoryId, SourceSnapshotId, TenantId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSystem {
    Linear,
    Api,
    Github,
}

/// Normalized immutable source data. It deliberately contains no authority fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotContent {
    pub source: SourceSystem,
    pub external_id: String,
    pub source_revision: String,
    pub source_url: Option<Url>,
    pub title: String,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub non_goals: Vec<String>,
    pub labels: BTreeSet<String>,
    pub normalized_priority: u8,
    pub source_state: String,
    pub assignee: Option<String>,
    pub repository_hint: Option<String>,
    pub source_updated_at: DateTime<Utc>,
}

impl SourceSnapshotContent {
    pub fn validate(&self) -> Result<()> {
        if self.external_id.trim().is_empty() || self.source_revision.trim().is_empty() {
            return Err(Error::Validation(
                "source external ID and revision must be non-empty".into(),
            ));
        }
        if self.title.trim().is_empty() || self.objective.trim().is_empty() {
            return Err(Error::Validation(
                "source title and objective must be non-empty".into(),
            ));
        }
        if self.normalized_priority > 100 {
            return Err(Error::Validation(
                "normalized priority must be in 0..=100".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        let canonical =
            serde_jcs::to_vec(self).map_err(|error| Error::Serialization(error.to_string()))?;
        Ok(sha256_digest(&canonical))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub id: SourceSnapshotId,
    pub tenant_id: TenantId,
    pub repository_id: Option<RepositoryId>,
    pub content: SourceSnapshotContent,
    pub content_digest: String,
    pub captured_at: DateTime<Utc>,
    pub connector_identity: String,
}

impl SourceSnapshot {
    pub fn create(
        tenant_id: TenantId,
        repository_id: Option<RepositoryId>,
        content: SourceSnapshotContent,
        connector_identity: String,
        captured_at: DateTime<Utc>,
    ) -> Result<Self> {
        content.validate()?;
        if connector_identity.trim().is_empty() {
            return Err(Error::Validation(
                "connector identity must be non-empty".into(),
            ));
        }
        let content_digest = content.digest()?;
        Ok(Self {
            id: SourceSnapshotId::new(),
            tenant_id,
            repository_id,
            content,
            content_digest,
            captured_at,
            connector_identity,
        })
    }
}
