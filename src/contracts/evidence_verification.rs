//! Append-only receipt for ASF's independent verification of Runmill evidence.
//!
//! The signed Runmill bundle proves what the worker observed.  This receipt is
//! deliberately separate: it records the exact immutable ledger coordinates
//! and the pull-request/CI reality observed by ASF's read-only forge adapter.
//! Source closure may trust neither record in isolation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, Result,
    contracts::PullRequestEvidence,
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
    domain::{AttemptId, EvidenceId, RunId, WorkItemId},
    security::reject_sensitive_fields,
};

pub const EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1: &str = "asf.evidence-verification-receipt.v1";

/// Exact result persisted in `evidence_verifications.details` for a `VALID`
/// decision.  The table row remains the status/index projection; this object
/// carries the independently observed facts needed to reconstruct closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVerificationReceiptV1 {
    pub schema: String,
    pub evidence_id: EvidenceId,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub run_id: RunId,
    pub evidence_digest: String,
    pub work_order_digest: String,
    pub expectation_digest: String,
    /// Exact durable activity claim that produced this receipt. These fields
    /// are repeated in the relational row so a VALID decision cannot be
    /// detached from its completed, immutable workflow job.
    pub verification_job_id: Uuid,
    pub verification_job_fence_token: i64,
    pub verification_job_completed_by: String,
    pub verifier: String,
    pub pull_request: PullRequestEvidence,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
}

impl EvidenceVerificationReceiptV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1 {
            return Err(Error::Validation(
                "unsupported evidence-verification receipt schema".into(),
            ));
        }
        if self.evidence_id.as_uuid().is_nil()
            || self.work_item_id.as_uuid().is_nil()
            || self.attempt_id.as_uuid().is_nil()
            || self.run_id.as_uuid().is_nil()
            || !is_sha256_digest(&self.evidence_digest)
            || !is_sha256_digest(&self.work_order_digest)
            || !is_sha256_digest(&self.expectation_digest)
            || self.verification_job_id.is_nil()
            || self.verification_job_fence_token <= 0
            || !valid_public_text(&self.verification_job_completed_by, 512)
            || !valid_public_text(&self.verifier, 256)
            || !valid_public_text(&self.provider_revision, 1_024)
        {
            return Err(Error::Validation(
                "evidence-verification receipt has invalid immutable coordinates".into(),
            ));
        }
        let pull_request = &self.pull_request;
        if !valid_repository(&pull_request.repository)
            || pull_request.number == 0
            || !valid_https_url(&pull_request.url)
            || !valid_git_sha(&pull_request.base_sha)
            || !valid_git_sha(&pull_request.head_sha)
            || pull_request
                .required_ci_contexts
                .iter()
                .chain(&pull_request.successful_ci_contexts)
                .any(|context| !valid_public_text(context, 512))
            || !pull_request
                .required_ci_contexts
                .is_subset(&pull_request.successful_ci_contexts)
        {
            return Err(Error::Validation(
                "evidence-verification receipt has incomplete exact-candidate pull-request evidence"
                    .into(),
            ));
        }
        reject_sensitive_fields(
            &serde_json::to_value(self).map_err(|error| Error::Serialization(error.to_string()))?,
        )
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(sha256_digest(&canonical_json(self)?))
    }
}

fn valid_public_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    !owner.is_empty()
        && !repository.is_empty()
        && parts.next().is_none()
        && [owner, repository].into_iter().all(|part| {
            part.len() <= 100
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_https_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn receipt() -> EvidenceVerificationReceiptV1 {
        EvidenceVerificationReceiptV1 {
            schema: EVIDENCE_VERIFICATION_RECEIPT_SCHEMA_V1.into(),
            evidence_id: EvidenceId::new(),
            work_item_id: WorkItemId::new(),
            attempt_id: AttemptId::new(),
            run_id: RunId::new(),
            evidence_digest: digest('a'),
            work_order_digest: digest('b'),
            expectation_digest: digest('c'),
            verification_job_id: Uuid::now_v7(),
            verification_job_fence_token: 3,
            verification_job_completed_by: "reactor:test".into(),
            verifier: "asf:github-evidence-verifier/v1".into(),
            pull_request: PullRequestEvidence {
                repository: "acme/app".into(),
                number: 7,
                url: "https://github.com/acme/app/pull/7".into(),
                base_sha: "1".repeat(40),
                head_sha: "2".repeat(40),
                required_ci_contexts: BTreeSet::from(["build".into()]),
                successful_ci_contexts: BTreeSet::from(["build".into()]),
            },
            provider_revision: "github:pull-request:7:revision".into(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn receipt_is_strict_deterministic_and_exact_candidate_bound() {
        let receipt = receipt();
        receipt.validate().unwrap();
        assert_eq!(receipt.digest().unwrap(), receipt.digest().unwrap());

        let mut missing_ci = receipt.clone();
        missing_ci.pull_request.successful_ci_contexts.clear();
        assert!(missing_ci.validate().is_err());

        let mut insecure_url = receipt;
        insecure_url.pull_request.url = "http://github.example/acme/app/pull/7".into();
        assert!(insecure_url.validate().is_err());
    }
}
