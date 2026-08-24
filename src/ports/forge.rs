use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::contracts::PullRequestEvidence;

pub const FORGE_GATEWAY_SCHEMA_V1: &str = "asf.forge-gateway.v1";
pub const RESOLVE_BASE_REF_SCHEMA_V1: &str = "asf.resolve-base-ref.v1";
pub const BASE_REF_OBSERVATION_SCHEMA_V1: &str = "asf.base-ref-observation.v1";
pub const OBSERVE_PULL_REQUEST_SCHEMA_V1: &str = "asf.observe-pull-request.v1";
pub const PULL_REQUEST_OBSERVATION_SCHEMA_V1: &str = "asf.pull-request-observation.v1";

/// Request for the current commit at one exact repository branch reference.
///
/// `repository` is the provider's canonical, case-preserving `owner/name`
/// slug. `base_ref` is always a fully qualified branch ref; aliases such as
/// `main`, tags, abbreviated refs, and commit-ish expressions are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveBaseRefRequest {
    pub schema: String,
    pub repository: String,
    pub base_ref: String,
}

impl ResolveBaseRefRequest {
    #[must_use]
    pub fn new(repository: impl Into<String>, base_ref: impl Into<String>) -> Self {
        Self {
            schema: RESOLVE_BASE_REF_SCHEMA_V1.into(),
            repository: repository.into(),
            base_ref: base_ref.into(),
        }
    }

    pub fn validate(&self) -> ForgeResult<()> {
        if self.schema != RESOLVE_BASE_REF_SCHEMA_V1 {
            return Err(ForgeGatewayError::InvalidRequest(
                "unsupported base-ref resolution schema".into(),
            ));
        }
        if !valid_repository(&self.repository) {
            return Err(ForgeGatewayError::InvalidRequest(
                "base-ref resolution requires a canonical owner/name repository".into(),
            ));
        }
        if !valid_base_ref(&self.base_ref) {
            return Err(ForgeGatewayError::InvalidRequest(
                "base-ref resolution requires an exact refs/heads/... reference".into(),
            ));
        }
        Ok(())
    }
}

/// Independently observed provider state for one exact repository branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseRefObservation {
    pub schema: String,
    pub repository: String,
    pub base_ref: String,
    pub base_sha: String,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
}

impl BaseRefObservation {
    pub fn validate(&self) -> ForgeResult<()> {
        if self.schema != BASE_REF_OBSERVATION_SCHEMA_V1 {
            return Err(ForgeGatewayError::InvalidObservation(
                "unsupported base-ref observation schema".into(),
            ));
        }
        if !valid_repository(&self.repository)
            || !valid_base_ref(&self.base_ref)
            || !valid_git_sha(&self.base_sha)
            || !valid_provider_revision(&self.provider_revision)
        {
            return Err(ForgeGatewayError::InvalidObservation(
                "base-ref observation is incomplete or malformed".into(),
            ));
        }
        Ok(())
    }

    /// Validate both contracts and prove that the provider answered the exact
    /// repository and ref that were requested.
    pub fn validate_for(&self, request: &ResolveBaseRefRequest) -> ForgeResult<()> {
        request.validate()?;
        self.validate()?;
        if self.repository != request.repository || self.base_ref != request.base_ref {
            return Err(ForgeGatewayError::InvalidObservation(
                "provider returned a different repository or base ref than requested".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestRef {
    /// Canonical `owner/name` repository slug.
    pub repository: String,
    pub number: u64,
}

impl PullRequestRef {
    pub fn validate(&self) -> ForgeResult<()> {
        let mut segments = self.repository.split('/');
        let owner = segments.next().unwrap_or_default();
        let name = segments.next().unwrap_or_default();
        if owner.trim().is_empty()
            || name.trim().is_empty()
            || owner != owner.trim()
            || name != name.trim()
            || owner.chars().any(char::is_whitespace)
            || name.chars().any(char::is_whitespace)
            || segments.next().is_some()
            || self.number == 0
        {
            return Err(ForgeGatewayError::InvalidRequest(
                "pull-request reference requires an owner/name repository and non-zero number"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservePullRequestRequest {
    pub schema: String,
    pub pull_request: PullRequestRef,
    pub expected_base_sha: String,
    pub expected_candidate_sha: String,
    pub required_ci_contexts: BTreeSet<String>,
}

impl ObservePullRequestRequest {
    #[must_use]
    pub fn new(
        pull_request: PullRequestRef,
        expected_base_sha: impl Into<String>,
        expected_candidate_sha: impl Into<String>,
        required_ci_contexts: BTreeSet<String>,
    ) -> Self {
        Self {
            schema: OBSERVE_PULL_REQUEST_SCHEMA_V1.into(),
            pull_request,
            expected_base_sha: expected_base_sha.into(),
            expected_candidate_sha: expected_candidate_sha.into(),
            required_ci_contexts,
        }
    }

    pub fn validate(&self) -> ForgeResult<()> {
        if self.schema != OBSERVE_PULL_REQUEST_SCHEMA_V1 {
            return Err(ForgeGatewayError::InvalidRequest(
                "unsupported pull-request observation schema".into(),
            ));
        }
        self.pull_request.validate()?;
        if !valid_revision(&self.expected_base_sha) || !valid_revision(&self.expected_candidate_sha)
        {
            return Err(ForgeGatewayError::InvalidRequest(
                "exact base and candidate revisions are required".into(),
            ));
        }
        if self
            .required_ci_contexts
            .iter()
            .any(|context| context.trim().is_empty())
        {
            return Err(ForgeGatewayError::InvalidRequest(
                "required CI context names cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestState {
    Open,
    Closed,
    Merged,
}

impl PullRequestState {
    #[must_use]
    pub const fn usable_for_pr_closure(self) -> bool {
        matches!(self, Self::Open | Self::Merged)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteCiState {
    Queued,
    InProgress,
    Success,
    Failure,
    Cancelled,
    Skipped,
    Neutral,
}

impl RemoteCiState {
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::InProgress)
    }

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Current normalized rollup for one CI context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCiObservation {
    /// Commit on which this result actually ran. A successful stale result is
    /// never transferable to a newer pull-request head.
    pub candidate_sha: String,
    pub state: RemoteCiState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestObservation {
    pub schema: String,
    pub pull_request: PullRequestRef,
    pub url: String,
    pub state: PullRequestState,
    pub base_sha: String,
    pub head_sha: String,
    pub merge_sha: Option<String>,
    pub ci: BTreeMap<String, RemoteCiObservation>,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
}

impl PullRequestObservation {
    pub fn validate(&self) -> ForgeResult<()> {
        if self.schema != PULL_REQUEST_OBSERVATION_SCHEMA_V1 {
            return Err(ForgeGatewayError::InvalidObservation(
                "unsupported pull-request observation schema".into(),
            ));
        }
        self.pull_request.validate()?;
        if !safe_http_url(&self.url)
            || !valid_revision(&self.base_sha)
            || !valid_revision(&self.head_sha)
            || self
                .merge_sha
                .as_deref()
                .is_some_and(|revision| !valid_revision(revision))
            || self.provider_revision.trim().is_empty()
            || self.ci.iter().any(|(context, observation)| {
                context.trim().is_empty() || !valid_revision(&observation.candidate_sha)
            })
        {
            return Err(ForgeGatewayError::InvalidObservation(
                "pull-request observation is incomplete or unsafe".into(),
            ));
        }
        if (self.state == PullRequestState::Merged) != self.merge_sha.is_some() {
            return Err(ForgeGatewayError::InvalidObservation(
                "merged state and merge revision must agree".into(),
            ));
        }
        Ok(())
    }

    pub fn assess_exact_candidate(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<ExactCandidateAssessment> {
        self.validate()?;
        request.validate()?;
        if self.pull_request != request.pull_request {
            return Err(ForgeGatewayError::InvalidObservation(
                "provider returned a different pull request than requested".into(),
            ));
        }

        let mut missing_contexts = BTreeSet::new();
        let mut stale_contexts = BTreeSet::new();
        let mut pending_contexts = BTreeSet::new();
        let mut unsuccessful_contexts = BTreeSet::new();

        for context in &request.required_ci_contexts {
            match self.ci.get(context) {
                None => {
                    missing_contexts.insert(context.clone());
                }
                Some(observation)
                    if observation.candidate_sha != request.expected_candidate_sha =>
                {
                    stale_contexts.insert(context.clone());
                }
                Some(observation) if observation.state.is_pending() => {
                    pending_contexts.insert(context.clone());
                }
                Some(observation) if !observation.state.is_success() => {
                    unsuccessful_contexts.insert(context.clone());
                }
                Some(_) => {}
            }
        }

        let assessment = ExactCandidateAssessment {
            pull_request_usable: self.state.usable_for_pr_closure(),
            base_matches: self.base_sha == request.expected_base_sha,
            head_matches: self.head_sha == request.expected_candidate_sha,
            missing_contexts,
            stale_contexts,
            pending_contexts,
            unsuccessful_contexts,
        };
        Ok(assessment)
    }

    /// Convert independently observed GitHub state into the existing evidence
    /// contract only when every requirement is current on the exact candidate.
    pub fn exact_candidate_evidence(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<PullRequestEvidence> {
        let assessment = self.assess_exact_candidate(request)?;
        if !assessment.satisfied() {
            return Err(ForgeGatewayError::ExactCandidateNotSatisfied {
                assessment: Box::new(assessment),
            });
        }
        Ok(PullRequestEvidence {
            repository: self.pull_request.repository.clone(),
            number: self.pull_request.number,
            url: self.url.clone(),
            base_sha: self.base_sha.clone(),
            head_sha: self.head_sha.clone(),
            required_ci_contexts: request.required_ci_contexts.clone(),
            successful_ci_contexts: request.required_ci_contexts.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCandidateAssessment {
    pub pull_request_usable: bool,
    pub base_matches: bool,
    pub head_matches: bool,
    pub missing_contexts: BTreeSet<String>,
    pub stale_contexts: BTreeSet<String>,
    pub pending_contexts: BTreeSet<String>,
    pub unsuccessful_contexts: BTreeSet<String>,
}

impl ExactCandidateAssessment {
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.pull_request_usable
            && self.base_matches
            && self.head_matches
            && self.missing_contexts.is_empty()
            && self.stale_contexts.is_empty()
            && self.pending_contexts.is_empty()
            && self.unsuccessful_contexts.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForgeGatewayError {
    #[error("unsupported forge contract: {detail}")]
    UnsupportedContract { detail: String },
    #[error("invalid forge request: {0}")]
    InvalidRequest(String),
    #[error("invalid forge observation: {0}")]
    InvalidObservation(String),
    #[error("pull request not found")]
    PullRequestNotFound,
    #[error("base ref not found")]
    BaseRefNotFound,
    #[error("forge provider rejected the request with HTTP status {status}")]
    ProviderRejected { status: u16 },
    #[error("exact candidate or required CI is not currently satisfied")]
    ExactCandidateNotSatisfied {
        assessment: Box<ExactCandidateAssessment>,
    },
    #[error(
        "forge idempotency conflict for {idempotency_key}: existing digest {existing_digest}, submitted digest {submitted_digest}"
    )]
    IdempotencyConflict {
        idempotency_key: String,
        existing_digest: String,
        submitted_digest: String,
    },
    #[error(
        "forge effect outcome is ambiguous for idempotency key {idempotency_key}; reconcile digest {effect_digest} before retrying"
    )]
    AmbiguousEffect {
        idempotency_key: String,
        effect_digest: String,
    },
    #[error("forge state conflicts with the requested logical effect")]
    EffectConflict,
    #[error("forge transport is unavailable")]
    TransportUnavailable,
}

pub type ForgeResult<T> = Result<T, ForgeGatewayError>;

/// Read-only forge boundary used by ASF to verify external GitHub reality.
///
/// Runmill owns branch/PR/CI delivery effects. ASF deliberately receives no
/// forge mutation capability here and never trusts a worker's self-report in
/// place of this exact-candidate observation.
#[async_trait]
pub trait ForgeGateway: Send + Sync {
    async fn resolve_base_ref(
        &self,
        request: &ResolveBaseRefRequest,
    ) -> ForgeResult<BaseRefObservation>;

    async fn observe_pull_request(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<PullRequestObservation>;
}

fn valid_revision(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_whitespace)
}

fn valid_repository(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || value.trim() != value {
        return false;
    }
    let mut components = value.split('/');
    let Some(owner) = components.next() else {
        return false;
    };
    let Some(name) = components.next() else {
        return false;
    };
    components.next().is_none()
        && valid_repository_component(owner)
        && valid_repository_component(name)
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_base_ref(value: &str) -> bool {
    if value.len() > 1_024 {
        return false;
    }
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && branch != "@"
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
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_provider_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn safe_http_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}
