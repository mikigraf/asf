use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::ports::forge::{
    BASE_REF_OBSERVATION_SCHEMA_V1, BaseRefObservation, ForgeGateway, ForgeGatewayError,
    ForgeResult, ObservePullRequestRequest, PULL_REQUEST_OBSERVATION_SCHEMA_V1,
    PullRequestObservation, PullRequestState, RemoteCiObservation, RemoteCiState,
    ResolveBaseRefRequest,
};

const GITHUB_API_VERSION: &str = "2026-03-10";
const MAX_PROVIDER_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CI_OBSERVATIONS: usize = 1_000;
const PAGE_SIZE: usize = 100;
const UNCONFIGURED_GITHUB_CONTRACT: &str =
    "GitHub API base URL and trusted controller authentication are not configured";

#[derive(Debug, Clone, Copy)]
enum NotFoundResource {
    PullRequest,
    BaseRef,
    Provider,
}

#[derive(Clone)]
struct GitHubHttpConfig {
    client: Client,
    api_base: Url,
    bearer_token: SecretString,
}

impl fmt::Debug for GitHubHttpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubHttpConfig")
            .field("api_base", &self.api_base)
            .field("bearer_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Deterministic, read-only GitHub REST observer used by ASF to validate the
/// exact pull-request candidate independently of Runmill evidence.
///
/// The bearer credential exists only in this trusted controller adapter. It is
/// redacted from `Debug`, never appears in an error, and redirects are disabled
/// so an untrusted endpoint cannot move the authorization header to another
/// origin. The adapter intentionally has no branch, pull-request, status, or
/// merge mutation methods; those effects remain Runmill's responsibility.
#[derive(Clone, Default)]
pub struct GitHubApiAdapter {
    config: Option<Arc<GitHubHttpConfig>>,
}

impl fmt::Debug for GitHubApiAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubApiAdapter")
            .field("config", &self.config)
            .finish()
    }
}

impl GitHubApiAdapter {
    /// Configure GitHub.com or a GitHub Enterprise REST API root.
    ///
    /// Examples are `https://api.github.com/` and
    /// `https://github.example/api/v3/`. Only HTTPS, credential-free URLs are
    /// accepted in production.
    pub fn new(api_base: Url, bearer_token: SecretString) -> ForgeResult<Self> {
        Self::build(api_base, bearer_token, false)
    }

    fn build(
        mut api_base: Url,
        bearer_token: SecretString,
        allow_insecure_loopback: bool,
    ) -> ForgeResult<Self> {
        validate_api_base(&api_base, allow_insecure_loopback)?;
        validate_bearer_token(bearer_token.expose_secret())?;
        if !api_base.path().ends_with('/') {
            let path = format!("{}/", api_base.path());
            api_base.set_path(&path);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(Policy::none())
            .user_agent(concat!("asf-github/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ForgeGatewayError::TransportUnavailable)?;
        Ok(Self {
            config: Some(Arc::new(GitHubHttpConfig {
                client,
                api_base,
                bearer_token,
            })),
        })
    }

    #[cfg(test)]
    fn new_for_loopback_test(api_base: Url, bearer_token: SecretString) -> ForgeResult<Self> {
        Self::build(api_base, bearer_token, true)
    }

    fn configured(&self) -> ForgeResult<&GitHubHttpConfig> {
        self.config
            .as_deref()
            .ok_or_else(|| ForgeGatewayError::UnsupportedContract {
                detail: UNCONFIGURED_GITHUB_CONTRACT.into(),
            })
    }

    async fn get_json<T>(&self, relative: &str, not_found: NotFoundResource) -> ForgeResult<T>
    where
        T: DeserializeOwned,
    {
        let config = self.configured()?;
        let url = config
            .api_base
            .join(relative)
            .map_err(|_| ForgeGatewayError::InvalidRequest("invalid GitHub API path".into()))?;
        let mut response = config
            .client
            .get(url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .bearer_auth(config.bearer_token.expose_secret())
            .send()
            .await
            .map_err(|_| ForgeGatewayError::TransportUnavailable)?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            match not_found {
                NotFoundResource::PullRequest => {
                    return Err(ForgeGatewayError::PullRequestNotFound);
                }
                NotFoundResource::BaseRef => return Err(ForgeGatewayError::BaseRefNotFound),
                NotFoundResource::Provider => {}
            }
        }
        if status.is_server_error()
            || status == StatusCode::REQUEST_TIMEOUT
            || response_is_rate_limited(status, response.headers())
        {
            return Err(ForgeGatewayError::TransportUnavailable);
        }
        if status == StatusCode::FORBIDDEN {
            let body = read_bounded_response_body(&mut response).await?;
            if github_error_indicates_rate_limit(&body) {
                return Err(ForgeGatewayError::TransportUnavailable);
            }
            return Err(ForgeGatewayError::ProviderRejected {
                status: status.as_u16(),
            });
        }
        if !status.is_success() {
            return Err(ForgeGatewayError::ProviderRejected {
                status: status.as_u16(),
            });
        }
        let body = read_bounded_response_body(&mut response).await?;
        serde_json::from_slice(&body).map_err(|_| invalid_provider_response())
    }

    async fn observe_statuses(
        &self,
        repository_path: &str,
        candidate_sha: &str,
    ) -> ForgeResult<Vec<GitHubCommitStatus>> {
        let encoded_sha = urlencoding::encode(candidate_sha);
        let first_path = format!(
            "repos/{repository_path}/commits/{encoded_sha}/status?per_page={PAGE_SIZE}&page=1"
        );
        let first: GitHubCombinedStatus = self
            .get_json(&first_path, NotFoundResource::Provider)
            .await?;
        if first.sha != candidate_sha || first.total_count > MAX_CI_OBSERVATIONS {
            return Err(invalid_provider_response());
        }
        let mut statuses = first.statuses;
        let mut page = 2;
        while statuses.len() < first.total_count {
            let path = format!(
                "repos/{repository_path}/commits/{encoded_sha}/status?per_page={PAGE_SIZE}&page={page}"
            );
            let next: GitHubCombinedStatus =
                self.get_json(&path, NotFoundResource::Provider).await?;
            if next.sha != candidate_sha
                || next.total_count != first.total_count
                || next.statuses.is_empty()
            {
                return Err(invalid_provider_response());
            }
            statuses.extend(next.statuses);
            if statuses.len() > MAX_CI_OBSERVATIONS {
                return Err(invalid_provider_response());
            }
            page += 1;
        }
        statuses.truncate(first.total_count);
        Ok(statuses)
    }

    async fn observe_check_runs(
        &self,
        repository_path: &str,
        candidate_sha: &str,
    ) -> ForgeResult<Vec<GitHubCheckRun>> {
        let encoded_sha = urlencoding::encode(candidate_sha);
        let mut page = 1;
        let mut expected_total = None;
        let mut checks = Vec::new();
        loop {
            let path = format!(
                "repos/{repository_path}/commits/{encoded_sha}/check-runs?filter=latest&per_page={PAGE_SIZE}&page={page}"
            );
            let response: GitHubCheckRuns =
                self.get_json(&path, NotFoundResource::Provider).await?;
            if response.total_count > MAX_CI_OBSERVATIONS {
                return Err(invalid_provider_response());
            }
            if expected_total
                .replace(response.total_count)
                .is_some_and(|total| total != response.total_count)
            {
                return Err(invalid_provider_response());
            }
            if response.check_runs.is_empty() && checks.len() < response.total_count {
                return Err(invalid_provider_response());
            }
            checks.extend(response.check_runs);
            if checks.len() >= response.total_count {
                checks.truncate(response.total_count);
                return Ok(checks);
            }
            page += 1;
        }
    }
}

#[async_trait]
impl ForgeGateway for GitHubApiAdapter {
    async fn resolve_base_ref(
        &self,
        request: &ResolveBaseRefRequest,
    ) -> ForgeResult<BaseRefObservation> {
        request.validate()?;
        let config = self.configured()?;
        let api_base = config.api_base.clone();
        let repository_path = encoded_repository_path(&request.repository)?;
        let provider_ref = request
            .base_ref
            .strip_prefix("refs/")
            .ok_or_else(|| ForgeGatewayError::InvalidRequest("invalid base ref".into()))?;
        let encoded_provider_ref = encode_path(provider_ref);
        let ref_path = format!("repos/{repository_path}/git/ref/{encoded_provider_ref}");
        let git_ref: GitHubGitRef = self.get_json(&ref_path, NotFoundResource::BaseRef).await?;

        let expected_ref_url = api_base
            .join(&format!(
                "repos/{repository_path}/git/refs/{encoded_provider_ref}"
            ))
            .map_err(|_| invalid_provider_response())?;
        let encoded_sha = urlencoding::encode(&git_ref.object.sha);
        let expected_object_url = api_base
            .join(&format!(
                "repos/{repository_path}/git/commits/{encoded_sha}"
            ))
            .map_err(|_| invalid_provider_response())?;
        if git_ref.reference != request.base_ref
            || git_ref.object.object_type != "commit"
            || !valid_git_sha(&git_ref.object.sha)
            || !valid_provider_node_id(&git_ref.node_id)
            || !exact_provider_url(&git_ref.url, &expected_ref_url)
            || !exact_provider_url(&git_ref.object.url, &expected_object_url)
        {
            return Err(invalid_provider_response());
        }

        let observation = BaseRefObservation {
            schema: BASE_REF_OBSERVATION_SCHEMA_V1.into(),
            repository: request.repository.clone(),
            base_ref: request.base_ref.clone(),
            base_sha: git_ref.object.sha.clone(),
            provider_revision: format!("github:git-ref:{}:{}", git_ref.node_id, git_ref.object.sha),
            observed_at: Utc::now(),
        };
        observation.validate_for(request)?;
        Ok(observation)
    }

    async fn observe_pull_request(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<PullRequestObservation> {
        request.validate()?;
        let repository_path = encoded_repository_path(&request.pull_request.repository)?;
        let pull_path = format!(
            "repos/{repository_path}/pulls/{}",
            request.pull_request.number
        );
        let pull: GitHubPullRequest = self
            .get_json(&pull_path, NotFoundResource::PullRequest)
            .await?;
        if pull.number != request.pull_request.number
            || !pull
                .base
                .repository
                .full_name
                .eq_ignore_ascii_case(&request.pull_request.repository)
            || !pull
                .head
                .repository
                .full_name
                .eq_ignore_ascii_case(&request.pull_request.repository)
        {
            return Err(invalid_provider_response());
        }

        let statuses = self
            .observe_statuses(&repository_path, &pull.head.sha)
            .await?;
        let checks = self
            .observe_check_runs(&repository_path, &pull.head.sha)
            .await?;
        let ci = normalize_ci(&pull.head.sha, statuses, checks)?;
        let state = normalize_pull_request_state(&pull)?;
        let merge_sha = (state == PullRequestState::Merged)
            .then_some(pull.merge_commit_sha)
            .flatten();
        let observation = PullRequestObservation {
            schema: PULL_REQUEST_OBSERVATION_SCHEMA_V1.into(),
            pull_request: request.pull_request.clone(),
            url: pull.html_url,
            state,
            base_sha: pull.base.sha,
            head_sha: pull.head.sha.clone(),
            merge_sha,
            ci,
            provider_revision: format!(
                "github:pull:{}:{}:{}",
                pull.number,
                pull.updated_at.to_rfc3339(),
                pull.head.sha
            ),
            observed_at: Utc::now(),
        };
        observation.validate()?;
        Ok(observation)
    }
}

fn validate_api_base(api_base: &Url, allow_insecure_loopback: bool) -> ForgeResult<()> {
    let secure = api_base.scheme() == "https";
    let loopback_http = allow_insecure_loopback
        && api_base.scheme() == "http"
        && api_base
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (!secure && !loopback_http)
        || api_base.host_str().is_none()
        || !api_base.username().is_empty()
        || api_base.password().is_some()
        || api_base.query().is_some()
        || api_base.fragment().is_some()
    {
        return Err(ForgeGatewayError::InvalidRequest(
            "GitHub API base must be a credential-free HTTPS URL".into(),
        ));
    }
    Ok(())
}

fn validate_bearer_token(token: &str) -> ForgeResult<()> {
    if token.len() < 16 || token.trim() != token || token.chars().any(char::is_control) {
        return Err(ForgeGatewayError::InvalidRequest(
            "GitHub controller authentication is missing or malformed".into(),
        ));
    }
    Ok(())
}

fn response_is_rate_limited(status: StatusCode, headers: &header::HeaderMap) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (headers
                .get("x-ratelimit-remaining")
                .is_some_and(|remaining| remaining.as_bytes() == b"0")
                || headers.contains_key(header::RETRY_AFTER)))
}

async fn read_bounded_response_body(response: &mut reqwest::Response) -> ForgeResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(invalid_provider_response());
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(MAX_PROVIDER_RESPONSE_BYTES);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ForgeGatewayError::TransportUnavailable)?
    {
        if chunk.len() > MAX_PROVIDER_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(invalid_provider_response());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn github_error_indicates_rate_limit(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct GitHubErrorMessage {
        message: String,
    }

    serde_json::from_slice::<GitHubErrorMessage>(body).is_ok_and(|error| {
        let message = error.message.to_ascii_lowercase();
        message.contains("rate limit") || message.contains("abuse detection")
    })
}

fn encoded_repository_path(repository: &str) -> ForgeResult<String> {
    let (owner, name) = repository
        .split_once('/')
        .ok_or_else(|| ForgeGatewayError::InvalidRequest("invalid repository slug".into()))?;
    Ok(format!(
        "{}/{}",
        urlencoding::encode(owner),
        urlencoding::encode(name)
    ))
}

fn encode_path(value: &str) -> String {
    value
        .split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn exact_provider_url(value: &str, expected: &Url) -> bool {
    Url::parse(value).is_ok_and(|actual| {
        actual.scheme() == expected.scheme()
            && actual.host_str() == expected.host_str()
            && actual.port_or_known_default() == expected.port_or_known_default()
            && actual.username().is_empty()
            && actual.password().is_none()
            && actual.path() == expected.path()
            && actual.query().is_none()
            && actual.fragment().is_none()
    })
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_provider_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn invalid_provider_response() -> ForgeGatewayError {
    ForgeGatewayError::InvalidObservation(
        "GitHub returned an incomplete, inconsistent, or oversized response".into(),
    )
}

fn normalize_pull_request_state(pull: &GitHubPullRequest) -> ForgeResult<PullRequestState> {
    match (pull.state.as_str(), pull.merged) {
        (_, true) if pull.merge_commit_sha.is_some() => Ok(PullRequestState::Merged),
        ("open", false) => Ok(PullRequestState::Open),
        ("closed", false) => Ok(PullRequestState::Closed),
        _ => Err(invalid_provider_response()),
    }
}

fn normalize_ci(
    candidate_sha: &str,
    statuses: Vec<GitHubCommitStatus>,
    checks: Vec<GitHubCheckRun>,
) -> ForgeResult<BTreeMap<String, RemoteCiObservation>> {
    let mut normalized = BTreeMap::new();
    for status in statuses {
        if status.context.trim().is_empty() {
            return Err(invalid_provider_response());
        }
        insert_ci(
            &mut normalized,
            status.context,
            RemoteCiObservation {
                candidate_sha: candidate_sha.into(),
                state: normalize_commit_status(&status.state)?,
            },
        );
    }
    for check in checks {
        if check.name.trim().is_empty() {
            return Err(invalid_provider_response());
        }
        let observation = RemoteCiObservation {
            candidate_sha: check.head_sha,
            state: normalize_check_run(&check.status, check.conclusion.as_deref())?,
        };
        insert_ci(&mut normalized, check.name, observation);
    }
    Ok(normalized)
}

fn insert_ci(
    observations: &mut BTreeMap<String, RemoteCiObservation>,
    name: String,
    candidate: RemoteCiObservation,
) {
    match observations.get_mut(&name) {
        None => {
            observations.insert(name, candidate);
        }
        Some(current) => {
            if current.candidate_sha != candidate.candidate_sha {
                current.candidate_sha = candidate.candidate_sha;
            }
            current.state = conservative_ci_state(current.state, candidate.state);
        }
    }
}

const fn conservative_ci_state(left: RemoteCiState, right: RemoteCiState) -> RemoteCiState {
    if ci_state_rank(left) >= ci_state_rank(right) {
        left
    } else {
        right
    }
}

const fn ci_state_rank(state: RemoteCiState) -> u8 {
    match state {
        RemoteCiState::Success => 0,
        RemoteCiState::Queued | RemoteCiState::InProgress => 1,
        RemoteCiState::Neutral => 2,
        RemoteCiState::Skipped => 3,
        RemoteCiState::Cancelled => 4,
        RemoteCiState::Failure => 5,
    }
}

fn normalize_commit_status(state: &str) -> ForgeResult<RemoteCiState> {
    match state {
        "pending" => Ok(RemoteCiState::InProgress),
        "success" => Ok(RemoteCiState::Success),
        "failure" | "error" => Ok(RemoteCiState::Failure),
        _ => Err(invalid_provider_response()),
    }
}

fn normalize_check_run(status: &str, conclusion: Option<&str>) -> ForgeResult<RemoteCiState> {
    match status {
        "queued" | "pending" | "waiting" | "requested" => Ok(RemoteCiState::Queued),
        "in_progress" => Ok(RemoteCiState::InProgress),
        "completed" => match conclusion {
            Some("success") => Ok(RemoteCiState::Success),
            Some("cancelled") => Ok(RemoteCiState::Cancelled),
            Some("skipped") => Ok(RemoteCiState::Skipped),
            Some("neutral") => Ok(RemoteCiState::Neutral),
            Some("failure" | "timed_out" | "action_required" | "startup_failure" | "stale") => {
                Ok(RemoteCiState::Failure)
            }
            _ => Err(invalid_provider_response()),
        },
        _ => Err(invalid_provider_response()),
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRepositoryRef {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubGitRef {
    #[serde(rename = "ref")]
    reference: String,
    node_id: String,
    url: String,
    object: GitHubGitObject,
}

#[derive(Debug, Deserialize)]
struct GitHubGitObject {
    #[serde(rename = "type")]
    object_type: String,
    sha: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitRef {
    sha: String,
    #[serde(rename = "repo")]
    repository: GitHubRepositoryRef,
}

#[derive(Debug, Deserialize)]
struct GitHubPullRequest {
    number: u64,
    html_url: String,
    state: String,
    merged: bool,
    merge_commit_sha: Option<String>,
    updated_at: DateTime<Utc>,
    base: GitHubCommitRef,
    head: GitHubCommitRef,
}

#[derive(Debug, Deserialize)]
struct GitHubCombinedStatus {
    sha: String,
    total_count: usize,
    statuses: Vec<GitHubCommitStatus>,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitStatus {
    context: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckRuns {
    total_count: usize,
    check_runs: Vec<GitHubCheckRun>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckRun {
    name: String,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Json, Router,
        extract::{Request, State},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
        routing::get,
    };
    use secrecy::SecretString;
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use crate::ports::forge::{
        ForgeGateway as _, ForgeGatewayError, ObservePullRequestRequest, PullRequestRef,
        RemoteCiState, ResolveBaseRefRequest,
    };

    use super::{GitHubApiAdapter, MAX_PROVIDER_RESPONSE_BYTES};

    const TEST_TOKEN: &str = "github-test-controller-token";
    const FIRST_SHA: &str = "1111111111111111111111111111111111111111";
    const SECOND_SHA: &str = "2222222222222222222222222222222222222222";

    #[derive(Debug, Clone, Copy)]
    enum BaseRefScenario {
        Stable,
        Moving,
        ShortSha,
        UppercaseSha,
        CrossRepositoryUrls,
        WrongRefUrl,
        SingularRefUrl,
        WrongBodyRef,
        NotFound,
        Unauthorized,
        Forbidden,
        RateLimitedForbidden,
        SecondaryRateLimitedForbidden,
        ServerError,
    }

    #[derive(Debug, Clone)]
    struct BaseRefFixtureState {
        api_base: String,
        scenario: BaseRefScenario,
        calls: Arc<AtomicUsize>,
        paths: Arc<Mutex<Vec<String>>>,
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

    fn base_ref_request() -> ResolveBaseRefRequest {
        ResolveBaseRefRequest::new("acme/app", "refs/heads/release/next")
    }

    async fn base_ref_fixture(
        State(state): State<BaseRefFixtureState>,
        request: Request,
    ) -> Response {
        if request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some("Bearer github-test-controller-token")
            || request
                .headers()
                .get("X-GitHub-Api-Version")
                .and_then(|value| value.to_str().ok())
                != Some("2026-03-10")
        {
            return StatusCode::IM_A_TEAPOT.into_response();
        }

        let path = request.uri().path().to_owned();
        state.paths.lock().unwrap().push(path.clone());
        if path != "/repos/acme/app/git/ref/heads/release/next" {
            return StatusCode::NOT_FOUND.into_response();
        }
        let call = state.calls.fetch_add(1, Ordering::SeqCst);
        match state.scenario {
            BaseRefScenario::NotFound => return StatusCode::NOT_FOUND.into_response(),
            BaseRefScenario::Unauthorized => {
                return (StatusCode::UNAUTHORIZED, TEST_TOKEN).into_response();
            }
            BaseRefScenario::Forbidden => return StatusCode::FORBIDDEN.into_response(),
            BaseRefScenario::RateLimitedForbidden => {
                let mut response = StatusCode::FORBIDDEN.into_response();
                response.headers_mut().insert(
                    "x-ratelimit-remaining",
                    header::HeaderValue::from_static("0"),
                );
                return response;
            }
            BaseRefScenario::SecondaryRateLimitedForbidden => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "message": "You have exceeded a secondary rate limit."
                    })),
                )
                    .into_response();
            }
            BaseRefScenario::ServerError => {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            BaseRefScenario::Stable
            | BaseRefScenario::Moving
            | BaseRefScenario::ShortSha
            | BaseRefScenario::UppercaseSha
            | BaseRefScenario::CrossRepositoryUrls
            | BaseRefScenario::WrongRefUrl
            | BaseRefScenario::SingularRefUrl
            | BaseRefScenario::WrongBodyRef => {}
        }

        let sha = match state.scenario {
            BaseRefScenario::Moving if call > 0 => SECOND_SHA,
            BaseRefScenario::ShortSha => "abc123",
            BaseRefScenario::UppercaseSha => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            _ => FIRST_SHA,
        };
        let repository = if matches!(state.scenario, BaseRefScenario::CrossRepositoryUrls) {
            "other/app"
        } else {
            "acme/app"
        };
        let reference = if matches!(state.scenario, BaseRefScenario::WrongBodyRef) {
            "refs/heads/release/other"
        } else {
            "refs/heads/release/next"
        };
        let ref_url = match state.scenario {
            BaseRefScenario::WrongRefUrl => format!(
                "{}repos/{repository}/git/refs/heads/release/other",
                state.api_base
            ),
            BaseRefScenario::SingularRefUrl => format!(
                "{}repos/{repository}/git/ref/heads/release/next",
                state.api_base
            ),
            _ => format!(
                "{}repos/{repository}/git/refs/heads/release/next",
                state.api_base
            ),
        };
        Json(json!({
            "ref": reference,
            "node_id": "REF_node_acme_app_release_next",
            "url": ref_url,
            "object": {
                "type": "commit",
                "sha": sha,
                "url": format!("{}repos/{repository}/git/commits/{sha}", state.api_base)
            }
        }))
        .into_response()
    }

    async fn base_ref_fixture_adapter(
        scenario: BaseRefScenario,
    ) -> (
        GitHubApiAdapter,
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let api_base = format!("http://{address}/");
        let calls = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = BaseRefFixtureState {
            api_base: api_base.clone(),
            scenario,
            calls: Arc::clone(&calls),
            paths: Arc::clone(&paths),
        };
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(get(base_ref_fixture))
                    .with_state(state)
                    .into_make_service(),
            )
            .await
            .unwrap();
        });
        let adapter = GitHubApiAdapter::new_for_loopback_test(
            api_base.parse().unwrap(),
            SecretString::from(TEST_TOKEN),
        )
        .unwrap();
        (adapter, server, calls, paths)
    }

    #[tokio::test]
    async fn base_ref_resolver_binds_exact_nested_ref_and_provider_revision() {
        let (adapter, server, calls, paths) =
            base_ref_fixture_adapter(BaseRefScenario::Stable).await;
        let request = base_ref_request();
        let observation = adapter.resolve_base_ref(&request).await.unwrap();
        server.abort();

        assert_eq!(observation.repository, "acme/app");
        assert_eq!(observation.base_ref, "refs/heads/release/next");
        assert_eq!(observation.base_sha, FIRST_SHA);
        assert_eq!(
            observation.provider_revision,
            format!("github:git-ref:REF_node_acme_app_release_next:{FIRST_SHA}")
        );
        observation.validate_for(&request).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *paths.lock().unwrap(),
            ["/repos/acme/app/git/ref/heads/release/next"]
        );
    }

    #[tokio::test]
    async fn moved_nested_ref_is_resolved_fresh_on_every_request() {
        let (adapter, server, calls, paths) =
            base_ref_fixture_adapter(BaseRefScenario::Moving).await;
        let request = base_ref_request();
        let first = adapter.resolve_base_ref(&request).await.unwrap();
        let second = adapter.resolve_base_ref(&request).await.unwrap();
        server.abort();

        assert_eq!(first.base_sha, FIRST_SHA);
        assert_eq!(second.base_sha, SECOND_SHA);
        assert_ne!(first.provider_revision, second.provider_revision);
        assert!(second.observed_at >= first.observed_at);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *paths.lock().unwrap(),
            [
                "/repos/acme/app/git/ref/heads/release/next",
                "/repos/acme/app/git/ref/heads/release/next"
            ]
        );
    }

    #[test]
    fn exact_base_ref_contract_rejects_single_at_ref() {
        let request = ResolveBaseRefRequest::new("acme/app", "refs/heads/@");
        assert!(matches!(
            request.validate(),
            Err(ForgeGatewayError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn malformed_or_non_lowercase_git_shas_fail_closed() {
        for scenario in [BaseRefScenario::ShortSha, BaseRefScenario::UppercaseSha] {
            let (adapter, server, _, _) = base_ref_fixture_adapter(scenario).await;
            let error = adapter
                .resolve_base_ref(&base_ref_request())
                .await
                .unwrap_err();
            server.abort();
            assert!(matches!(error, ForgeGatewayError::InvalidObservation(_)));
        }
    }

    #[tokio::test]
    async fn cross_repository_ref_and_noncanonical_response_urls_fail_closed() {
        for scenario in [
            BaseRefScenario::CrossRepositoryUrls,
            BaseRefScenario::WrongRefUrl,
            BaseRefScenario::SingularRefUrl,
            BaseRefScenario::WrongBodyRef,
        ] {
            let (adapter, server, _, _) = base_ref_fixture_adapter(scenario).await;
            let error = adapter
                .resolve_base_ref(&base_ref_request())
                .await
                .unwrap_err();
            server.abort();
            assert!(matches!(error, ForgeGatewayError::InvalidObservation(_)));
        }
    }

    #[tokio::test]
    async fn base_ref_provider_failures_are_typed_and_never_expose_authentication() {
        for (scenario, expected) in [
            (
                BaseRefScenario::NotFound,
                ForgeGatewayError::BaseRefNotFound,
            ),
            (
                BaseRefScenario::Unauthorized,
                ForgeGatewayError::ProviderRejected { status: 401 },
            ),
            (
                BaseRefScenario::Forbidden,
                ForgeGatewayError::ProviderRejected { status: 403 },
            ),
            (
                BaseRefScenario::RateLimitedForbidden,
                ForgeGatewayError::TransportUnavailable,
            ),
            (
                BaseRefScenario::SecondaryRateLimitedForbidden,
                ForgeGatewayError::TransportUnavailable,
            ),
            (
                BaseRefScenario::ServerError,
                ForgeGatewayError::TransportUnavailable,
            ),
        ] {
            let (adapter, server, _, _) = base_ref_fixture_adapter(scenario).await;
            let error = adapter
                .resolve_base_ref(&base_ref_request())
                .await
                .unwrap_err();
            server.abort();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains(TEST_TOKEN));
            assert!(!format!("{adapter:?}").contains(TEST_TOKEN));
        }
    }

    #[tokio::test]
    async fn chunked_provider_body_is_rejected_at_the_size_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4_096];
            let _ = connection.read(&mut request).await;
            connection
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 1024 * 1024];
            for _ in 0..=MAX_PROVIDER_RESPONSE_BYTES / chunk.len() {
                if connection
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .is_err()
                    || connection.write_all(&chunk).await.is_err()
                    || connection.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = connection.write_all(b"0\r\n\r\n").await;
        });
        let adapter = GitHubApiAdapter::new_for_loopback_test(
            format!("http://{address}/").parse().unwrap(),
            SecretString::from(TEST_TOKEN),
        )
        .unwrap();
        let error = adapter
            .resolve_base_ref(&base_ref_request())
            .await
            .unwrap_err();
        server.abort();

        assert!(
            matches!(error, ForgeGatewayError::InvalidObservation(_)),
            "unexpected oversized-body error: {error:?}"
        );
    }

    async fn github_fixture(request: Request) -> Response {
        if request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some("Bearer github-test-controller-token")
            || request
                .headers()
                .get("X-GitHub-Api-Version")
                .and_then(|value| value.to_str().ok())
                != Some("2026-03-10")
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let payload = match request.uri().path() {
            "/repos/acme/app/pulls/7" => json!({
                "number": 7,
                "html_url": "https://github.example/acme/app/pull/7",
                "state": "open",
                "merged": false,
                "merge_commit_sha": "temporary-test-merge",
                "updated_at": "2026-08-21T10:00:00Z",
                "base": {"sha": "base-sha", "repo": {"full_name": "acme/app"}},
                "head": {"sha": "candidate-sha", "repo": {"full_name": "acme/app"}}
            }),
            "/repos/acme/app/commits/candidate-sha/status" => json!({
                "sha": "candidate-sha",
                "total_count": 1,
                "statuses": [{"context": "build", "state": "success"}]
            }),
            "/repos/acme/app/commits/candidate-sha/check-runs" => json!({
                "total_count": 1,
                "check_runs": [{
                    "name": "test",
                    "head_sha": "candidate-sha",
                    "status": "completed",
                    "conclusion": "success"
                }]
            }),
            _ => return StatusCode::NOT_FOUND.into_response(),
        };
        Json(payload).into_response()
    }

    async fn fixture_adapter() -> (GitHubApiAdapter, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(get(github_fixture))
                    .into_make_service(),
            )
            .await
            .unwrap();
        });
        let adapter = GitHubApiAdapter::new_for_loopback_test(
            format!("http://{address}/").parse().unwrap(),
            SecretString::from(TEST_TOKEN),
        )
        .unwrap();
        (adapter, server)
    }

    #[tokio::test]
    async fn configured_observer_reads_exact_pr_status_and_check_run_state() {
        let (adapter, server) = fixture_adapter().await;
        let observation = adapter.observe_pull_request(&request()).await.unwrap();
        server.abort();

        assert_eq!(observation.base_sha, "base-sha");
        assert_eq!(observation.head_sha, "candidate-sha");
        assert_eq!(observation.ci["build"].state, RemoteCiState::Success);
        assert_eq!(observation.ci["test"].state, RemoteCiState::Success);
        assert!(
            observation
                .assess_exact_candidate(&request())
                .unwrap()
                .satisfied()
        );
        let debug = format!("{adapter:?}");
        assert!(!debug.contains(TEST_TOKEN));
        assert!(debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn provider_auth_rejection_is_typed_and_never_echoes_credentials() {
        let (configured, server) = fixture_adapter().await;
        let base = configured.configured().unwrap().api_base.clone();
        let adapter = GitHubApiAdapter::new_for_loopback_test(
            base,
            SecretString::from("different-controller-token"),
        )
        .unwrap();
        let error = adapter.observe_pull_request(&request()).await.unwrap_err();
        server.abort();

        assert_eq!(error, ForgeGatewayError::ProviderRejected { status: 401 });
        let rendered = error.to_string();
        assert!(!rendered.contains("different-controller-token"));
    }

    #[test]
    fn production_configuration_requires_https_and_redacts_authentication() {
        let token = SecretString::from(TEST_TOKEN);
        assert!(
            GitHubApiAdapter::new("http://github.example/".parse().unwrap(), token.clone())
                .is_err()
        );
        let adapter =
            GitHubApiAdapter::new("https://api.github.com/".parse().unwrap(), token).unwrap();
        assert!(!format!("{adapter:?}").contains(TEST_TOKEN));
    }
}
