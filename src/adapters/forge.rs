use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    crypto::{canonical_json, sha256_digest},
    ports::forge::{
        BaseRefObservation, ForgeGateway, ForgeGatewayError, ForgeResult,
        ObservePullRequestRequest, PullRequestObservation, PullRequestRef, ResolveBaseRefRequest,
    },
};

pub use super::github::GitHubApiAdapter;

pub const SIMULATED_GITHUB_PULL_REQUEST_EFFECT_SCHEMA_V1: &str =
    "asf.test.github-pull-request-effect.v1";
pub const SIMULATED_GITHUB_PULL_REQUEST_RECEIPT_SCHEMA_V1: &str =
    "asf.test.github-pull-request-receipt.v1";

/// Fake-only representation of the PR delivery effect owned by Runmill.
///
/// This is deliberately not part of [`ForgeGateway`]: ASF production code may
/// observe GitHub but must not acquire Runmill's repository mutation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatedGitHubPullRequestEffect {
    pub schema: String,
    pub idempotency_key: String,
    pub effect_digest: String,
    pub observation_after_apply: PullRequestObservation,
}

impl SimulatedGitHubPullRequestEffect {
    pub fn new(
        idempotency_key: impl Into<String>,
        observation_after_apply: PullRequestObservation,
    ) -> ForgeResult<Self> {
        observation_after_apply.validate()?;
        let effect_digest = digest_observation(&observation_after_apply)?;
        let effect = Self {
            schema: SIMULATED_GITHUB_PULL_REQUEST_EFFECT_SCHEMA_V1.into(),
            idempotency_key: idempotency_key.into(),
            effect_digest,
            observation_after_apply,
        };
        effect.validate()?;
        Ok(effect)
    }

    pub fn validate(&self) -> ForgeResult<()> {
        if self.schema != SIMULATED_GITHUB_PULL_REQUEST_EFFECT_SCHEMA_V1 {
            return Err(ForgeGatewayError::InvalidRequest(
                "unsupported simulated GitHub effect schema".into(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(ForgeGatewayError::InvalidRequest(
                "simulated GitHub effect requires an idempotency key".into(),
            ));
        }
        self.observation_after_apply.validate()?;
        if self.effect_digest != digest_observation(&self.observation_after_apply)? {
            return Err(ForgeGatewayError::InvalidRequest(
                "simulated GitHub effect digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatedGitHubEffectDisposition {
    Applied,
    Adopted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatedGitHubPullRequestReceipt {
    pub schema: String,
    pub idempotency_key: String,
    pub effect_digest: String,
    pub pull_request: PullRequestRef,
    pub disposition: SimulatedGitHubEffectDisposition,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct GitHubEffectRecord {
    effect: SimulatedGitHubPullRequestEffect,
    receipt: SimulatedGitHubPullRequestReceipt,
}

#[derive(Debug, Default)]
struct GitHubFakeState {
    base_refs: BTreeMap<(String, String), BaseRefObservation>,
    pull_requests: BTreeMap<PullRequestRef, PullRequestObservation>,
    effects_by_idempotency_key: BTreeMap<String, GitHubEffectRecord>,
    idempotency_key_by_pull_request: BTreeMap<PullRequestRef, String>,
    logical_effects: BTreeMap<PullRequestRef, u64>,
    lose_next_effect_response: bool,
}

/// Deterministic in-memory GitHub observer and delivery-effect fixture.
#[derive(Debug, Clone, Default)]
pub struct InMemoryGitHubGateway {
    state: Arc<Mutex<GitHubFakeState>>,
}

impl InMemoryGitHubGateway {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed or advance an exact externally observed branch ref. This remains a
    /// fixture-only operation and is deliberately absent from [`ForgeGateway`].
    pub async fn set_base_ref_observation(
        &self,
        observation: BaseRefObservation,
    ) -> ForgeResult<()> {
        observation.validate()?;
        let key = (observation.repository.clone(), observation.base_ref.clone());
        self.state.lock().await.base_refs.insert(key, observation);
        Ok(())
    }

    /// Seed or advance externally observed PR/CI state without granting that
    /// mutation capability to the production port (for example, CI completes).
    pub async fn set_observation(&self, observation: PullRequestObservation) -> ForgeResult<()> {
        observation.validate()?;
        self.state
            .lock()
            .await
            .pull_requests
            .insert(observation.pull_request.clone(), observation);
        Ok(())
    }

    /// Inject one timeout after the next new simulated Runmill-owned PR effect
    /// has been durably applied.
    pub async fn lose_next_effect_response(&self) {
        self.state.lock().await.lose_next_effect_response = true;
    }

    /// Apply a fake Runmill-owned PR effect. This helper exists solely for
    /// end-to-end failure injection; it is intentionally absent from the ASF
    /// forge trait.
    pub async fn apply_pull_request_effect(
        &self,
        effect: &SimulatedGitHubPullRequestEffect,
    ) -> ForgeResult<SimulatedGitHubPullRequestReceipt> {
        effect.validate()?;
        let mut state = self.state.lock().await;
        if let Some(existing) = state
            .effects_by_idempotency_key
            .get(&effect.idempotency_key)
        {
            if existing.effect.effect_digest != effect.effect_digest {
                return Err(ForgeGatewayError::IdempotencyConflict {
                    idempotency_key: effect.idempotency_key.clone(),
                    existing_digest: existing.effect.effect_digest.clone(),
                    submitted_digest: effect.effect_digest.clone(),
                });
            }
            if existing.effect != *effect {
                return Err(ForgeGatewayError::EffectConflict);
            }
            let mut receipt = existing.receipt.clone();
            receipt.disposition = SimulatedGitHubEffectDisposition::Adopted;
            return Ok(receipt);
        }

        let pull_request = effect.observation_after_apply.pull_request.clone();
        if state
            .idempotency_key_by_pull_request
            .contains_key(&pull_request)
        {
            return Err(ForgeGatewayError::EffectConflict);
        }

        let receipt = SimulatedGitHubPullRequestReceipt {
            schema: SIMULATED_GITHUB_PULL_REQUEST_RECEIPT_SCHEMA_V1.into(),
            idempotency_key: effect.idempotency_key.clone(),
            effect_digest: effect.effect_digest.clone(),
            pull_request: pull_request.clone(),
            disposition: SimulatedGitHubEffectDisposition::Applied,
            recorded_at: effect.observation_after_apply.observed_at,
        };
        state
            .pull_requests
            .insert(pull_request.clone(), effect.observation_after_apply.clone());
        state
            .logical_effects
            .entry(pull_request.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        state
            .idempotency_key_by_pull_request
            .insert(pull_request, effect.idempotency_key.clone());
        state.effects_by_idempotency_key.insert(
            effect.idempotency_key.clone(),
            GitHubEffectRecord {
                effect: effect.clone(),
                receipt: receipt.clone(),
            },
        );

        if state.lose_next_effect_response {
            state.lose_next_effect_response = false;
            return Err(ForgeGatewayError::AmbiguousEffect {
                idempotency_key: effect.idempotency_key.clone(),
                effect_digest: effect.effect_digest.clone(),
            });
        }
        Ok(receipt)
    }

    #[must_use]
    pub async fn logical_pull_request_effect_count(&self, pull_request: &PullRequestRef) -> u64 {
        self.state
            .lock()
            .await
            .logical_effects
            .get(pull_request)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl ForgeGateway for InMemoryGitHubGateway {
    async fn resolve_base_ref(
        &self,
        request: &ResolveBaseRefRequest,
    ) -> ForgeResult<BaseRefObservation> {
        request.validate()?;
        let key = (request.repository.clone(), request.base_ref.clone());
        let observation = self
            .state
            .lock()
            .await
            .base_refs
            .get(&key)
            .cloned()
            .ok_or(ForgeGatewayError::BaseRefNotFound)?;
        observation.validate_for(request)?;
        Ok(observation)
    }

    async fn observe_pull_request(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<PullRequestObservation> {
        request.validate()?;
        let observation = self
            .state
            .lock()
            .await
            .pull_requests
            .get(&request.pull_request)
            .cloned()
            .ok_or(ForgeGatewayError::PullRequestNotFound)?;
        observation.validate()?;
        Ok(observation)
    }
}

fn digest_observation(observation: &PullRequestObservation) -> ForgeResult<String> {
    let canonical = canonical_json(observation)
        .map_err(|error| ForgeGatewayError::InvalidRequest(error.to_string()))?;
    Ok(sha256_digest(&canonical))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{TimeZone, Utc};

    use crate::ports::forge::{
        BASE_REF_OBSERVATION_SCHEMA_V1, BaseRefObservation, ForgeGateway, ForgeGatewayError,
        ObservePullRequestRequest, PULL_REQUEST_OBSERVATION_SCHEMA_V1, PullRequestObservation,
        PullRequestRef, PullRequestState, RemoteCiObservation, RemoteCiState,
        ResolveBaseRefRequest,
    };

    use super::{
        GitHubApiAdapter, InMemoryGitHubGateway, SimulatedGitHubEffectDisposition,
        SimulatedGitHubPullRequestEffect,
    };

    fn observation() -> PullRequestObservation {
        PullRequestObservation {
            schema: PULL_REQUEST_OBSERVATION_SCHEMA_V1.into(),
            pull_request: PullRequestRef {
                repository: "acme/app".into(),
                number: 7,
            },
            url: "https://github.test/acme/app/pull/7".into(),
            state: PullRequestState::Open,
            base_sha: "base-sha".into(),
            head_sha: "candidate-sha".into(),
            merge_sha: None,
            ci: BTreeMap::from([
                (
                    "build".into(),
                    RemoteCiObservation {
                        candidate_sha: "candidate-sha".into(),
                        state: RemoteCiState::Success,
                    },
                ),
                (
                    "test".into(),
                    RemoteCiObservation {
                        candidate_sha: "candidate-sha".into(),
                        state: RemoteCiState::Success,
                    },
                ),
            ]),
            provider_revision: "github:pr-7:v1".into(),
            observed_at: Utc
                .with_ymd_and_hms(2026, 8, 21, 11, 0, 0)
                .single()
                .unwrap(),
        }
    }

    fn request() -> ObservePullRequestRequest {
        ObservePullRequestRequest::new(
            PullRequestRef {
                repository: "acme/app".into(),
                number: 7,
            },
            "base-sha",
            "candidate-sha",
            BTreeSet::from(["build".into(), "test".into()]),
        )
    }

    fn base_ref_observation(sha: &str, revision: &str, second: u32) -> BaseRefObservation {
        BaseRefObservation {
            schema: BASE_REF_OBSERVATION_SCHEMA_V1.into(),
            repository: "acme/app".into(),
            base_ref: "refs/heads/main".into(),
            base_sha: sha.into(),
            provider_revision: revision.into(),
            observed_at: Utc
                .with_ymd_and_hms(2026, 8, 21, 11, 0, second)
                .single()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn fake_base_ref_observer_advances_exact_ref_without_mutation_authority() {
        let fake = InMemoryGitHubGateway::new();
        let request = ResolveBaseRefRequest::new("acme/app", "refs/heads/main");
        let first = base_ref_observation(
            "1111111111111111111111111111111111111111",
            "github:git-ref:node:1111111111111111111111111111111111111111",
            0,
        );
        fake.set_base_ref_observation(first.clone()).await.unwrap();
        assert_eq!(fake.resolve_base_ref(&request).await.unwrap(), first);

        let moved = base_ref_observation(
            "2222222222222222222222222222222222222222",
            "github:git-ref:node:2222222222222222222222222222222222222222",
            1,
        );
        fake.set_base_ref_observation(moved.clone()).await.unwrap();
        assert_eq!(fake.resolve_base_ref(&request).await.unwrap(), moved);
    }

    #[tokio::test]
    async fn exact_candidate_assessment_rejects_stale_or_skipped_required_ci() {
        let fake = InMemoryGitHubGateway::new();
        let current = observation();
        fake.set_observation(current).await.unwrap();
        let observed = fake.observe_pull_request(&request()).await.unwrap();
        assert!(
            observed
                .assess_exact_candidate(&request())
                .unwrap()
                .satisfied()
        );
        let evidence = observed.exact_candidate_evidence(&request()).unwrap();
        assert_eq!(evidence.head_sha, "candidate-sha");
        assert_eq!(
            evidence.successful_ci_contexts,
            BTreeSet::from(["build".into(), "test".into()])
        );

        let mut stale = observed;
        stale.ci.get_mut("test").unwrap().candidate_sha = "older-sha".into();
        stale.ci.get_mut("build").unwrap().state = RemoteCiState::Skipped;
        stale.provider_revision = "github:pr-7:v2".into();
        fake.set_observation(stale).await.unwrap();
        let observed = fake.observe_pull_request(&request()).await.unwrap();
        let assessment = observed.assess_exact_candidate(&request()).unwrap();
        assert!(!assessment.satisfied());
        assert_eq!(assessment.stale_contexts, BTreeSet::from(["test".into()]));
        assert_eq!(
            assessment.unsuccessful_contexts,
            BTreeSet::from(["build".into()])
        );
        assert!(matches!(
            observed.exact_candidate_evidence(&request()).unwrap_err(),
            ForgeGatewayError::ExactCandidateNotSatisfied { .. }
        ));
    }

    #[tokio::test]
    async fn applied_but_response_lost_is_observable_and_creates_one_pr_effect() {
        let fake = InMemoryGitHubGateway::new();
        let effect =
            SimulatedGitHubPullRequestEffect::new("github-delivery-1", observation()).unwrap();
        fake.lose_next_effect_response().await;
        assert!(matches!(
            fake.apply_pull_request_effect(&effect).await.unwrap_err(),
            ForgeGatewayError::AmbiguousEffect { .. }
        ));

        let observed = fake.observe_pull_request(&request()).await.unwrap();
        assert!(
            observed
                .assess_exact_candidate(&request())
                .unwrap()
                .satisfied()
        );
        let adopted = fake.apply_pull_request_effect(&effect).await.unwrap();
        assert_eq!(
            adopted.disposition,
            SimulatedGitHubEffectDisposition::Adopted
        );
        assert_eq!(
            fake.logical_pull_request_effect_count(&effect.observation_after_apply.pull_request)
                .await,
            1
        );
    }

    #[tokio::test]
    async fn changed_effect_under_same_github_idempotency_key_conflicts() {
        let fake = InMemoryGitHubGateway::new();
        let first =
            SimulatedGitHubPullRequestEffect::new("github-delivery-1", observation()).unwrap();
        fake.apply_pull_request_effect(&first).await.unwrap();

        let mut changed_observation = observation();
        changed_observation.head_sha = "different-candidate".into();
        changed_observation.provider_revision = "github:pr-7:v2".into();
        let changed =
            SimulatedGitHubPullRequestEffect::new("github-delivery-1", changed_observation)
                .unwrap();
        assert!(matches!(
            fake.apply_pull_request_effect(&changed).await.unwrap_err(),
            ForgeGatewayError::IdempotencyConflict { .. }
        ));
        assert_eq!(
            fake.logical_pull_request_effect_count(&first.observation_after_apply.pull_request)
                .await,
            1
        );
    }

    #[tokio::test]
    async fn production_github_placeholder_fails_closed_without_exposing_auth() {
        let adapter = GitHubApiAdapter::default();
        let error = adapter.observe_pull_request(&request()).await.unwrap_err();
        assert!(matches!(
            &error,
            ForgeGatewayError::UnsupportedContract { .. }
        ));
        assert!(!error.to_string().to_ascii_lowercase().contains("token"));
        assert!(!error.to_string().to_ascii_lowercase().contains("secret"));
    }
}
