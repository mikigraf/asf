use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac as _};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use url::Url;

use crate::{
    crypto::{canonical_json, sha256_digest},
    domain::{RepositoryId, SourceSnapshot, SourceSnapshotContent, SourceSystem, TenantId},
    ports::source::{
        CloseSourceRequest, ObserveSourceRequest, ReconcileSourceCloseRequest,
        SOURCE_CLOSE_RECEIPT_SCHEMA_V1, SOURCE_INTAKE_PAGE_SCHEMA_V1, SOURCE_OBSERVATION_SCHEMA_V1,
        SourceCloseDisposition, SourceCloseReceipt, SourceCloseReconciliation, SourceCursor,
        SourceGateway, SourceGatewayError, SourceIntakePage, SourceIntakeRequest, SourceItemRef,
        SourceLifecycle, SourceObservation, SourceResult,
    },
    security::reject_sensitive_fields,
};

const LINEAR_GRAPHQL_ENDPOINT: &str = "https://api.linear.app/graphql";
const UNCONFIGURED_LINEAR_CONTRACT: &str =
    "Linear tenant, team mappings, completed states, and authentication are not configured";
const MAX_LINEAR_PAGE_SIZE: u32 = 250;
const MAX_LABELS_PER_ISSUE: usize = 100;
const MAX_COMMENT_BODY_BYTES: usize = 32 * 1024;
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const CURSOR_PREFIX: &str = "linear.v1";
const CURSOR_DOMAIN: &[u8] = b"asf.linear.cursor.v1\0";
const MARKER_PREFIX: &str = "<!-- asf-linear-close:v1:";
const MARKER_SUFFIX: &str = " -->";
const MARKER_DOMAIN: &[u8] = b"asf.linear.close-marker.v1\0";

const INTAKE_QUERY: &str = r"
query AsfLinearIntake($first: Int!, $after: String, $label: String!, $teamIds: [ID!]!) {
  issues(
    first: $first
    after: $after
    orderBy: updatedAt
    filter: {
      labels: { name: { eq: $label } }
      team: { id: { in: $teamIds } }
      archivedAt: { null: true }
    }
  ) {
    nodes {
      id identifier title description url priority updatedAt archivedAt canceledAt completedAt
      state { id name type }
      assignee { id name }
      team { id key name }
      labels(first: 100) { nodes { name } pageInfo { hasNextPage endCursor } }
    }
    pageInfo { hasNextPage endCursor }
  }
}
";

const OBSERVE_QUERY: &str = r"
query AsfLinearObserve($id: String!, $commentsFirst: Int!, $commentsAfter: String) {
  issue(id: $id) {
    id identifier title description url priority updatedAt archivedAt canceledAt completedAt
    state { id name type }
    assignee { id name }
    team { id key name }
    labels(first: 100) { nodes { name } pageInfo { hasNextPage endCursor } }
    comments(first: $commentsFirst, after: $commentsAfter) {
      nodes { id body createdAt }
      pageInfo { hasNextPage endCursor }
    }
  }
}
";

const COMMENT_CREATE_MUTATION: &str = r"
mutation AsfLinearCommentCreate($issueId: String!, $body: String!) {
  commentCreate(input: { issueId: $issueId, body: $body }) {
    success
    comment { id body createdAt }
  }
}
";

const ISSUE_UPDATE_MUTATION: &str = r"
mutation AsfLinearIssueUpdate($issueId: String!, $stateId: String!) {
  issueUpdate(id: $issueId, input: { stateId: $stateId }) {
    success
    issue { id updatedAt state { id name type } }
  }
}
";

/// Authentication accepted by Linear's official GraphQL endpoint.
#[derive(Clone)]
pub enum LinearAuthentication {
    /// A personal Linear API key, sent directly in the `Authorization` header.
    PersonalApiKey(SecretString),
    /// An OAuth access token, sent as `Authorization: Bearer ...`.
    OAuthBearer(SecretString),
}

impl fmt::Debug for LinearAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::PersonalApiKey(_) => "PersonalApiKey",
            Self::OAuthBearer(_) => "OAuthBearer",
        };
        formatter.debug_tuple(kind).field(&"[REDACTED]").finish()
    }
}

impl LinearAuthentication {
    fn credential(&self) -> &str {
        match self {
            Self::PersonalApiKey(secret) | Self::OAuthBearer(secret) => secret.expose_secret(),
        }
    }

    fn header_value(&self) -> SourceResult<header::HeaderValue> {
        let value = match self {
            Self::PersonalApiKey(secret) => secret.expose_secret().to_owned(),
            Self::OAuthBearer(secret) => format!("Bearer {}", secret.expose_secret()),
        };
        header::HeaderValue::from_str(&value).map_err(|_| {
            SourceGatewayError::InvalidRequest(
                "Linear controller authentication is malformed".into(),
            )
        })
    }
}

/// Trusted interpretation of one Linear team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearTeamMapping {
    pub repository_id: RepositoryId,
    pub repository: String,
    pub completed_state_id: String,
}

/// Explicit configuration for a single tenant's Linear connector.
#[derive(Clone)]
pub struct LinearApiConfig {
    pub tenant_id: TenantId,
    pub authentication: LinearAuthentication,
    /// Linear team ID to ASF repository and trusted terminal-state mapping.
    pub team_mappings: BTreeMap<String, LinearTeamMapping>,
    pub connector_identity: String,
    /// Tenant-scoped secret used to authenticate cursors and provider markers.
    pub correlation_secret: SecretString,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_page_size: u32,
    pub max_comment_pages: usize,
}

impl LinearApiConfig {
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        authentication: LinearAuthentication,
        team_mappings: BTreeMap<String, LinearTeamMapping>,
        connector_identity: impl Into<String>,
        correlation_secret: SecretString,
    ) -> Self {
        Self {
            tenant_id,
            authentication,
            team_mappings,
            connector_identity: connector_identity.into(),
            correlation_secret,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
            max_page_size: 100,
            max_comment_pages: 20,
        }
    }

    /// Validate the tenant, credentials, trusted mappings, and transport
    /// bounds without performing any network I/O.
    pub fn validate(&self) -> SourceResult<()> {
        validate_config(self)
    }
}

impl fmt::Debug for LinearApiConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearApiConfig")
            .field("tenant_id", &self.tenant_id)
            .field("authentication", &self.authentication)
            .field("team_mappings", &self.team_mappings)
            .field("connector_identity", &self.connector_identity)
            .field("correlation_secret", &"[REDACTED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_page_size", &self.max_page_size)
            .field("max_comment_pages", &self.max_comment_pages)
            .finish()
    }
}

#[derive(Clone)]
struct ConfiguredLinear {
    client: Client,
    endpoint: Url,
    config: LinearApiConfig,
}

impl fmt::Debug for ConfiguredLinear {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredLinear")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Production Linear GraphQL implementation of [`SourceGateway`].
///
/// `Default` is deliberately unconfigured. Production construction always
/// targets Linear's exact HTTPS GraphQL endpoint, disables redirects, and
/// binds all requests to one tenant and an allowlist of Linear teams.
#[derive(Clone, Default)]
pub struct LinearApiAdapter {
    configured: Option<Arc<ConfiguredLinear>>,
}

impl fmt::Debug for LinearApiAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearApiAdapter")
            .field("configured", &self.configured)
            .finish()
    }
}

impl LinearApiAdapter {
    /// Configure the adapter for Linear's official GraphQL endpoint.
    pub fn new(config: LinearApiConfig) -> SourceResult<Self> {
        let endpoint = Url::parse(LINEAR_GRAPHQL_ENDPOINT).map_err(|_| {
            SourceGatewayError::InvalidRequest("invalid built-in Linear endpoint".into())
        })?;
        Self::build(config, endpoint, false)
    }

    fn build(
        config: LinearApiConfig,
        endpoint: Url,
        allow_insecure_loopback: bool,
    ) -> SourceResult<Self> {
        config.validate()?;
        validate_endpoint(&endpoint, allow_insecure_loopback)?;
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(Policy::none())
            .user_agent(concat!("asf-linear/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| SourceGatewayError::TransportUnavailable)?;
        Ok(Self {
            configured: Some(Arc::new(ConfiguredLinear {
                client,
                endpoint,
                config,
            })),
        })
    }

    #[cfg(test)]
    fn new_for_loopback_test(config: LinearApiConfig, endpoint: Url) -> SourceResult<Self> {
        Self::build(config, endpoint, true)
    }

    fn configured(&self) -> SourceResult<&ConfiguredLinear> {
        self.configured
            .as_deref()
            .ok_or_else(|| SourceGatewayError::UnsupportedContract {
                detail: UNCONFIGURED_LINEAR_CONTRACT.into(),
            })
    }

    fn require_tenant(&self, tenant_id: TenantId) -> SourceResult<&ConfiguredLinear> {
        let configured = self.configured()?;
        if configured.config.tenant_id != tenant_id {
            return Err(SourceGatewayError::InvalidRequest(
                "source tenant is outside this Linear connector boundary".into(),
            ));
        }
        Ok(configured)
    }

    async fn graphql<T, V>(
        &self,
        operation_name: &'static str,
        query: &'static str,
        variables: &V,
        ambiguous: Option<AmbiguousIdentity<'_>>,
    ) -> SourceResult<T>
    where
        T: DeserializeOwned,
        V: Serialize + Sync,
    {
        let configured = self.configured()?;
        let authorization = configured.config.authentication.header_value()?;
        let response = configured
            .client
            .post(configured.endpoint.clone())
            .header(header::AUTHORIZATION, authorization)
            .header(header::ACCEPT, "application/json")
            .json(&GraphQlRequest {
                operation_name,
                query,
                variables,
            })
            .send()
            .await
            .map_err(|_| ambiguous_or_transport(ambiguous))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(ambiguous_or_rejected(ambiguous, "REDIRECT_REJECTED"));
        }
        if !status.is_success() {
            if status.is_server_error() || status == StatusCode::REQUEST_TIMEOUT {
                return Err(ambiguous_or_transport(ambiguous));
            }
            return Err(ambiguous_or_rejected(
                ambiguous,
                &format!("HTTP_{}", status.as_u16()),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > configured.config.max_response_bytes as u64)
        {
            return Err(ambiguous_or_response_too_large(ambiguous));
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ambiguous_or_transport(ambiguous))?
        {
            if body.len().saturating_add(chunk.len()) > configured.config.max_response_bytes {
                return Err(ambiguous_or_response_too_large(ambiguous));
            }
            body.extend_from_slice(&chunk);
        }
        let envelope: GraphQlEnvelope<T> =
            serde_json::from_slice(&body).map_err(|_| ambiguous_or_invalid_response(ambiguous))?;
        if let Some(error) = envelope.errors.first() {
            return Err(match ambiguous {
                Some(identity) => identity.error(),
                None => SourceGatewayError::ProviderRejected {
                    code: sanitize_graphql_code(error),
                },
            });
        }
        envelope
            .data
            .ok_or_else(|| ambiguous_or_invalid_response(ambiguous))
    }

    async fn query_issue(&self, item: &SourceItemRef) -> SourceResult<Option<ObservedIssue>> {
        let configured = self.require_linear_item(item)?;
        let mut after = None;
        let mut cursors = BTreeSet::new();
        let mut expected_issue = None;
        let mut comments = Vec::new();
        for _ in 0..configured.config.max_comment_pages {
            let data: ObserveData = self
                .graphql(
                    "AsfLinearObserve",
                    OBSERVE_QUERY,
                    &ObserveVariables {
                        id: &item.external_id,
                        comments_first: configured.config.max_page_size,
                        comments_after: after.as_deref(),
                    },
                    None,
                )
                .await?;
            let Some(issue) = data.issue else {
                return if expected_issue.is_none() {
                    Ok(None)
                } else {
                    Err(SourceGatewayError::SourceStateConflict)
                };
            };
            if issue.core.id != item.external_id {
                return Err(invalid_provider_response());
            }
            if expected_issue
                .as_ref()
                .is_some_and(|expected| expected != &issue.core)
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            expected_issue.get_or_insert_with(|| issue.core.clone());
            if issue.comments.nodes.len() > configured.config.max_page_size as usize {
                return Err(invalid_provider_response());
            }
            comments.extend(issue.comments.nodes);
            if !issue.comments.page_info.has_next_page {
                return Ok(Some(ObservedIssue {
                    core: expected_issue.expect("issue was inserted above"),
                    comments,
                }));
            }
            let cursor = issue
                .comments
                .page_info
                .end_cursor
                .filter(|cursor| !cursor.is_empty())
                .ok_or_else(invalid_provider_response)?;
            if !cursors.insert(cursor.clone()) {
                return Err(invalid_provider_response());
            }
            after = Some(cursor);
        }
        Err(invalid_provider_response())
    }

    fn require_linear_item(&self, item: &SourceItemRef) -> SourceResult<&ConfiguredLinear> {
        item.validate()?;
        if item.source != SourceSystem::Linear {
            return Err(SourceGatewayError::InvalidRequest(
                "Linear adapter requires a Linear source item".into(),
            ));
        }
        self.require_tenant(item.tenant_id)
    }

    fn normalize_issue(
        &self,
        tenant_id: TenantId,
        issue: &LinearIssue,
    ) -> SourceResult<SourceSnapshot> {
        let configured = self.require_tenant(tenant_id)?;
        let mapping = team_mapping(configured, &issue.team.id)?;
        validate_issue(issue)?;
        let labels = issue
            .labels
            .nodes
            .iter()
            .map(|label| label.name.trim().to_owned())
            .collect::<BTreeSet<_>>();
        if labels.contains("") || labels.len() != issue.labels.nodes.len() {
            return Err(invalid_provider_response());
        }
        let source_url = issue.url.as_deref().map(parse_provider_url).transpose()?;
        let (objective, acceptance_criteria, non_goals) =
            normalize_description(issue.description.as_deref(), &issue.title);
        let content = SourceSnapshotContent {
            source: SourceSystem::Linear,
            external_id: issue.id.clone(),
            source_revision: provider_revision(issue.updated_at),
            source_url,
            title: issue.title.trim().to_owned(),
            objective,
            acceptance_criteria,
            non_goals,
            labels,
            normalized_priority: normalize_priority(issue.priority)?,
            source_state: issue.state.kind.trim().to_ascii_lowercase(),
            assignee: issue
                .assignee
                .as_ref()
                .map(|assignee| assignee.name.trim().to_owned())
                .filter(|name| !name.is_empty()),
            repository_hint: Some(mapping.repository.clone()),
            source_updated_at: issue.updated_at,
        };
        SourceSnapshot::create(
            tenant_id,
            Some(mapping.repository_id),
            content,
            configured.config.connector_identity.clone(),
            issue.updated_at,
        )
        .map_err(|_| invalid_provider_response())
    }

    fn signed_markers(&self, observed: &ObservedIssue) -> SourceResult<Vec<ObservedMarker>> {
        let configured = self.configured()?;
        let mut markers = Vec::new();
        for comment in &observed.comments {
            if comment.id.trim().is_empty() {
                return Err(invalid_provider_response());
            }
            for payload in decode_markers(&configured.config, &comment.body) {
                markers.push(ObservedMarker {
                    payload,
                    comment_id: comment.id.clone(),
                    recorded_at: comment.created_at,
                });
            }
        }
        Ok(markers)
    }

    fn marker_for_close(
        &self,
        observed: &ObservedIssue,
        request: &CloseSourceRequest,
    ) -> SourceResult<Option<ObservedMarker>> {
        let mut exact = None;
        for marker in self.signed_markers(observed)? {
            if marker.payload.tenant_id != request.effect.item.tenant_id.to_string()
                || marker.payload.external_id != request.effect.item.external_id
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            if marker.payload.idempotency_key == request.idempotency_key {
                if marker.payload.effect_digest != request.effect_digest {
                    return Err(idempotency_conflict(
                        &request.idempotency_key,
                        &marker.payload.effect_digest,
                        &request.effect_digest,
                    ));
                }
                if marker.payload.correlation_marker != request.effect.correlation_marker {
                    return Err(SourceGatewayError::SourceStateConflict);
                }
                if exact.is_none() {
                    exact = Some(marker);
                }
            } else if marker.payload.correlation_marker == request.effect.correlation_marker {
                return Err(idempotency_conflict(
                    &request.idempotency_key,
                    &marker.payload.effect_digest,
                    &request.effect_digest,
                ));
            } else {
                // A different authenticated ASF close is already in flight or
                // applied for this item. Never layer another logical close on it.
                return Err(SourceGatewayError::SourceStateConflict);
            }
        }
        Ok(exact)
    }

    fn marker_for_reconciliation(
        &self,
        observed: &ObservedIssue,
        request: &ReconcileSourceCloseRequest,
    ) -> SourceResult<Option<ObservedMarker>> {
        let mut exact = None;
        for marker in self.signed_markers(observed)? {
            if marker.payload.tenant_id != request.item.tenant_id.to_string()
                || marker.payload.external_id != request.item.external_id
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            if marker.payload.idempotency_key == request.idempotency_key {
                if marker.payload.effect_digest != request.effect_digest {
                    return Err(idempotency_conflict(
                        &request.idempotency_key,
                        &marker.payload.effect_digest,
                        &request.effect_digest,
                    ));
                }
                if marker.payload.correlation_marker != request.correlation_marker {
                    return Err(SourceGatewayError::SourceStateConflict);
                }
                if exact.is_none() {
                    exact = Some(marker);
                }
            } else if marker.payload.correlation_marker == request.correlation_marker {
                return Err(idempotency_conflict(
                    &request.idempotency_key,
                    &marker.payload.effect_digest,
                    &request.effect_digest,
                ));
            }
        }
        Ok(exact)
    }

    fn observed_applied_marker(
        &self,
        item: &SourceItemRef,
        observed: &ObservedIssue,
    ) -> SourceResult<Option<ObservedMarker>> {
        let mut unique: Option<ObservedMarker> = None;
        for marker in self.signed_markers(observed)? {
            if marker.payload.tenant_id != item.tenant_id.to_string()
                || marker.payload.external_id != item.external_id
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            match &mut unique {
                None => unique = Some(marker),
                Some(current) if current.payload == marker.payload => {
                    if (marker.recorded_at, &marker.comment_id)
                        < (current.recorded_at, &current.comment_id)
                    {
                        *current = marker;
                    }
                }
                Some(_) => return Err(SourceGatewayError::SourceStateConflict),
            }
        }
        Ok(unique)
    }

    fn receipt(
        item: SourceItemRef,
        marker: &ObservedMarker,
        disposition: SourceCloseDisposition,
        revision: String,
    ) -> SourceCloseReceipt {
        SourceCloseReceipt {
            schema: SOURCE_CLOSE_RECEIPT_SCHEMA_V1.into(),
            item,
            idempotency_key: marker.payload.idempotency_key.clone(),
            effect_digest: marker.payload.effect_digest.clone(),
            correlation_marker: marker.payload.correlation_marker.clone(),
            disposition,
            provider_revision: revision,
            recorded_at: marker.recorded_at,
        }
    }
}

#[async_trait]
impl SourceGateway for LinearApiAdapter {
    async fn intake(&self, request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage> {
        request.validate()?;
        let configured = self.require_tenant(request.tenant_id)?;
        if request.limit > configured.config.max_page_size {
            return Err(SourceGatewayError::InvalidRequest(format!(
                "Linear page limit must be within 1..={}",
                configured.config.max_page_size
            )));
        }
        let scope_digest = intake_scope_digest(configured, &request.opt_in_label)?;
        let after = request
            .after
            .as_ref()
            .map(|cursor| decode_cursor(&configured.config, cursor, &scope_digest))
            .transpose()?;
        let team_ids = configured
            .config
            .team_mappings
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let data: IntakeData = self
            .graphql(
                "AsfLinearIntake",
                INTAKE_QUERY,
                &IntakeVariables {
                    first: request.limit,
                    after: after.as_deref(),
                    label: &request.opt_in_label,
                    team_ids: &team_ids,
                },
                None,
            )
            .await?;
        if data.issues.nodes.len() > request.limit as usize {
            return Err(invalid_provider_response());
        }
        let mut snapshots = Vec::with_capacity(data.issues.nodes.len());
        let mut seen = BTreeSet::new();
        for issue in data.issues.nodes {
            if !seen.insert(issue.id.clone())
                || !issue
                    .labels
                    .nodes
                    .iter()
                    .any(|label| label.name == request.opt_in_label)
            {
                return Err(invalid_provider_response());
            }
            snapshots.push(self.normalize_issue(request.tenant_id, &issue)?);
        }
        let next_cursor = if data.issues.page_info.has_next_page {
            let provider_cursor = data
                .issues
                .page_info
                .end_cursor
                .filter(|cursor| !cursor.is_empty())
                .ok_or_else(invalid_provider_response)?;
            Some(encode_cursor(
                &configured.config,
                &scope_digest,
                &provider_cursor,
            )?)
        } else {
            None
        };
        Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots,
            has_more: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn observe_source(
        &self,
        request: &ObserveSourceRequest,
    ) -> SourceResult<SourceObservation> {
        request.validate()?;
        self.require_linear_item(&request.item)?;
        let observed_at = Utc::now();
        let Some(observed) = self.query_issue(&request.item).await? else {
            return Ok(SourceObservation {
                schema: SOURCE_OBSERVATION_SCHEMA_V1.into(),
                item: request.item.clone(),
                lifecycle: SourceLifecycle::Deleted,
                current_snapshot: None,
                applied_closure: None,
                observed_at,
            });
        };
        let snapshot = self.normalize_issue(request.item.tenant_id, &observed.core)?;
        let lifecycle = source_lifecycle(self.configured()?, &observed.core)?;
        let marker = self.observed_applied_marker(&request.item, &observed)?;
        let applied_closure = if lifecycle == SourceLifecycle::Completed {
            marker.as_ref().map(|marker| {
                Self::receipt(
                    request.item.clone(),
                    marker,
                    SourceCloseDisposition::Reconciled,
                    provider_revision(observed.core.updated_at),
                )
            })
        } else {
            None
        };
        Ok(SourceObservation {
            schema: SOURCE_OBSERVATION_SCHEMA_V1.into(),
            item: request.item.clone(),
            lifecycle,
            current_snapshot: Some(snapshot),
            applied_closure,
            observed_at,
        })
    }

    async fn close_source(&self, request: &CloseSourceRequest) -> SourceResult<SourceCloseReceipt> {
        request.validate()?;
        let configured = self.require_linear_item(&request.effect.item)?;
        reject_sensitive_fields(&serde_json::to_value(&request.effect.closure).map_err(|_| {
            SourceGatewayError::InvalidRequest("source closure cannot be encoded".into())
        })?)
        .map_err(|_| {
            SourceGatewayError::InvalidRequest(
                "source closure contains credential-shaped content".into(),
            )
        })?;
        let Some(observed) = self.query_issue(&request.effect.item).await? else {
            return Err(SourceGatewayError::ItemNotFound);
        };
        let mapping = team_mapping(configured, &observed.core.team.id)?;
        let exact_marker = self.marker_for_close(&observed, request)?;
        if is_trusted_completed(configured, &observed.core)? {
            return exact_marker.map_or(Err(SourceGatewayError::SourceStateConflict), |marker| {
                Ok(Self::receipt(
                    request.effect.item.clone(),
                    &marker,
                    SourceCloseDisposition::Adopted,
                    provider_revision(observed.core.updated_at),
                ))
            });
        }
        if !is_mutable_active(&observed.core) {
            return Err(SourceGatewayError::SourceStateConflict);
        }

        let marker_existed = exact_marker.is_some();
        let marker = if let Some(marker) = exact_marker {
            marker
        } else {
            let snapshot = self.normalize_issue(request.effect.item.tenant_id, &observed.core)?;
            if snapshot.content.source_revision != request.effect.expected_source_revision
                || snapshot.content_digest != request.effect.expected_snapshot_digest
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            validate_closure_repository(request, mapping)?;
            let payload = LinearCloseMarker {
                version: 1,
                tenant_id: request.effect.item.tenant_id.to_string(),
                external_id: request.effect.item.external_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                effect_digest: request.effect_digest.clone(),
                correlation_marker: request.effect.correlation_marker.clone(),
            };
            let signed_marker = encode_marker(&configured.config, &payload)?;
            let body = close_comment(request, &signed_marker)?;
            let identity = AmbiguousIdentity::from_close(request);
            let data: CommentCreateData = self
                .graphql(
                    "AsfLinearCommentCreate",
                    COMMENT_CREATE_MUTATION,
                    &CommentCreateVariables {
                        issue_id: &observed.core.id,
                        body: &body,
                    },
                    Some(identity),
                )
                .await?;
            if !data.comment_create.success
                || data.comment_create.comment.id.trim().is_empty()
                || data.comment_create.comment.body != body
            {
                return Err(identity.error());
            }
            ObservedMarker {
                payload,
                comment_id: data.comment_create.comment.id,
                recorded_at: data.comment_create.comment.created_at,
            }
        };

        let identity = AmbiguousIdentity::from_close(request);
        let data: IssueUpdateData = self
            .graphql(
                "AsfLinearIssueUpdate",
                ISSUE_UPDATE_MUTATION,
                &IssueUpdateVariables {
                    issue_id: &observed.core.id,
                    state_id: &mapping.completed_state_id,
                },
                Some(identity),
            )
            .await?;
        if !data.issue_update.success
            || data.issue_update.issue.id != observed.core.id
            || data.issue_update.issue.state.id != mapping.completed_state_id
        {
            return Err(identity.error());
        }
        Ok(Self::receipt(
            request.effect.item.clone(),
            &marker,
            if marker_existed {
                SourceCloseDisposition::Adopted
            } else {
                SourceCloseDisposition::Applied
            },
            provider_revision(data.issue_update.issue.updated_at),
        ))
    }

    async fn reconcile_source_close(
        &self,
        request: &ReconcileSourceCloseRequest,
    ) -> SourceResult<SourceCloseReconciliation> {
        request.validate()?;
        let configured = self.require_linear_item(&request.item)?;
        let Some(observed) = self.query_issue(&request.item).await? else {
            return Ok(SourceCloseReconciliation::NotObserved);
        };
        let marker = self.marker_for_reconciliation(&observed, request)?;
        if let Some(marker) = marker
            && is_trusted_completed(configured, &observed.core)?
        {
            return Ok(SourceCloseReconciliation::Applied(Self::receipt(
                request.item.clone(),
                &marker,
                SourceCloseDisposition::Reconciled,
                provider_revision(observed.core.updated_at),
            )));
        }
        Ok(SourceCloseReconciliation::NotObserved)
    }
}

fn validate_config(config: &LinearApiConfig) -> SourceResult<()> {
    if config.tenant_id.as_uuid().is_nil() {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear connector tenant cannot be nil".into(),
        ));
    }
    validate_credential(config.authentication.credential())?;
    let secret = config.correlation_secret.expose_secret();
    if secret.len() < 32 || secret.trim() != secret || secret.chars().any(char::is_control) {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear correlation secret must contain at least 32 non-control bytes".into(),
        ));
    }
    if config.connector_identity.trim().is_empty()
        || config.connector_identity.trim() != config.connector_identity
        || config.connector_identity.len() > 256
    {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear connector identity is missing or malformed".into(),
        ));
    }
    if config.team_mappings.is_empty() {
        return Err(SourceGatewayError::InvalidRequest(
            "at least one trusted Linear team mapping is required".into(),
        ));
    }
    let mut completed_states = BTreeSet::new();
    for (team_id, mapping) in &config.team_mappings {
        if !valid_provider_id(team_id) || !valid_provider_id(&mapping.completed_state_id) {
            return Err(SourceGatewayError::InvalidRequest(
                "Linear team and completed-state IDs must be non-empty provider IDs".into(),
            ));
        }
        validate_repository_slug(&mapping.repository)?;
        if !completed_states.insert(&mapping.completed_state_id) {
            return Err(SourceGatewayError::InvalidRequest(
                "Linear completed-state IDs must be unique across trusted teams".into(),
            ));
        }
    }
    if config.connect_timeout.is_zero()
        || config.request_timeout.is_zero()
        || config.connect_timeout > config.request_timeout
        || !(1_024..=16 * 1024 * 1024).contains(&config.max_response_bytes)
        || !(1..=MAX_LINEAR_PAGE_SIZE).contains(&config.max_page_size)
        || !(1..=100).contains(&config.max_comment_pages)
    {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear HTTP and pagination limits are outside safe bounds".into(),
        ));
    }
    Ok(())
}

fn validate_endpoint(endpoint: &Url, allow_insecure_loopback: bool) -> SourceResult<()> {
    let exact_production = endpoint.as_str() == LINEAR_GRAPHQL_ENDPOINT;
    let loopback_test = allow_insecure_loopback
        && endpoint.scheme() == "http"
        && endpoint
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (!exact_production && !loopback_test)
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear GraphQL endpoint must be the official HTTPS endpoint".into(),
        ));
    }
    Ok(())
}

fn validate_credential(credential: &str) -> SourceResult<()> {
    if credential.len() < 16
        || credential.trim() != credential
        || credential.chars().any(char::is_control)
    {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear controller authentication is missing or malformed".into(),
        ));
    }
    Ok(())
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_repository_slug(repository: &str) -> SourceResult<()> {
    let Some((owner, name)) = repository.split_once('/') else {
        return Err(SourceGatewayError::InvalidRequest(
            "trusted repository must be an owner/name slug".into(),
        ));
    };
    if owner.is_empty()
        || name.is_empty()
        || name.contains('/')
        || repository.trim() != repository
        || repository.chars().any(char::is_control)
    {
        return Err(SourceGatewayError::InvalidRequest(
            "trusted repository must be an owner/name slug".into(),
        ));
    }
    Ok(())
}

fn validate_issue(issue: &LinearIssue) -> SourceResult<()> {
    if !valid_provider_id(&issue.id)
        || !valid_provider_id(&issue.identifier)
        || issue.title.trim().is_empty()
        || !valid_provider_id(&issue.state.id)
        || issue.state.name.trim().is_empty()
        || issue.state.kind.trim().is_empty()
        || !valid_provider_id(&issue.team.id)
        || issue.labels.nodes.len() > MAX_LABELS_PER_ISSUE
        || issue.labels.page_info.has_next_page
    {
        return Err(invalid_provider_response());
    }
    Ok(())
}

fn parse_provider_url(value: &str) -> SourceResult<Url> {
    let url = Url::parse(value).map_err(|_| invalid_provider_response())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid_provider_response());
    }
    Ok(url)
}

fn team_mapping<'a>(
    configured: &'a ConfiguredLinear,
    team_id: &str,
) -> SourceResult<&'a LinearTeamMapping> {
    configured
        .config
        .team_mappings
        .get(team_id)
        .ok_or_else(invalid_provider_response)
}

fn source_lifecycle(
    configured: &ConfiguredLinear,
    issue: &LinearIssue,
) -> SourceResult<SourceLifecycle> {
    let mapping = team_mapping(configured, &issue.team.id)?;
    if issue.archived_at.is_some() {
        Ok(SourceLifecycle::Deleted)
    } else if issue.canceled_at.is_some() || issue.state.kind.eq_ignore_ascii_case("canceled") {
        Ok(SourceLifecycle::Canceled)
    } else if issue.state.id == mapping.completed_state_id {
        Ok(SourceLifecycle::Completed)
    } else {
        Ok(SourceLifecycle::Active)
    }
}

fn is_trusted_completed(configured: &ConfiguredLinear, issue: &LinearIssue) -> SourceResult<bool> {
    Ok(issue.state.id == team_mapping(configured, &issue.team.id)?.completed_state_id)
}

fn is_mutable_active(issue: &LinearIssue) -> bool {
    issue.archived_at.is_none()
        && issue.canceled_at.is_none()
        && issue.completed_at.is_none()
        && !matches!(
            issue.state.kind.to_ascii_lowercase().as_str(),
            "completed" | "canceled"
        )
}

fn normalize_priority(priority: i32) -> SourceResult<u8> {
    match priority {
        0 => Ok(0),
        1 => Ok(100),
        2 => Ok(75),
        3 => Ok(50),
        4 => Ok(25),
        _ => Err(invalid_provider_response()),
    }
}

fn provider_revision(updated_at: DateTime<Utc>) -> String {
    updated_at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Clone, Copy)]
struct AmbiguousIdentity<'a> {
    idempotency_key: &'a str,
    effect_digest: &'a str,
}

impl<'a> AmbiguousIdentity<'a> {
    fn from_close(request: &'a CloseSourceRequest) -> Self {
        Self {
            idempotency_key: &request.idempotency_key,
            effect_digest: &request.effect_digest,
        }
    }

    fn error(self) -> SourceGatewayError {
        SourceGatewayError::AmbiguousEffect {
            idempotency_key: self.idempotency_key.into(),
            effect_digest: self.effect_digest.into(),
        }
    }
}

fn ambiguous_or_transport(identity: Option<AmbiguousIdentity<'_>>) -> SourceGatewayError {
    identity.map_or(
        SourceGatewayError::TransportUnavailable,
        AmbiguousIdentity::error,
    )
}

fn ambiguous_or_rejected(
    identity: Option<AmbiguousIdentity<'_>>,
    code: &str,
) -> SourceGatewayError {
    identity.map_or_else(
        || SourceGatewayError::ProviderRejected { code: code.into() },
        AmbiguousIdentity::error,
    )
}

fn ambiguous_or_invalid_response(identity: Option<AmbiguousIdentity<'_>>) -> SourceGatewayError {
    identity.map_or(
        SourceGatewayError::InvalidProviderResponse,
        AmbiguousIdentity::error,
    )
}

fn ambiguous_or_response_too_large(identity: Option<AmbiguousIdentity<'_>>) -> SourceGatewayError {
    identity.map_or(
        SourceGatewayError::ResponseTooLarge,
        AmbiguousIdentity::error,
    )
}

fn invalid_provider_response() -> SourceGatewayError {
    SourceGatewayError::InvalidProviderResponse
}

fn idempotency_conflict(
    idempotency_key: &str,
    existing_digest: &str,
    submitted_digest: &str,
) -> SourceGatewayError {
    SourceGatewayError::IdempotencyConflict {
        idempotency_key: idempotency_key.into(),
        existing_digest: existing_digest.into(),
        submitted_digest: submitted_digest.into(),
    }
}

fn sanitize_graphql_code(error: &GraphQlError) -> String {
    error
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.code.as_deref())
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
        .unwrap_or("GRAPHQL_ERROR")
        .into()
}

fn intake_scope_digest(configured: &ConfiguredLinear, opt_in_label: &str) -> SourceResult<String> {
    #[derive(Serialize)]
    struct Scope<'a> {
        tenant_id: String,
        opt_in_label: &'a str,
        team_ids: Vec<&'a str>,
    }
    let scope = Scope {
        tenant_id: configured.config.tenant_id.to_string(),
        opt_in_label,
        team_ids: configured
            .config
            .team_mappings
            .keys()
            .map(String::as_str)
            .collect(),
    };
    canonical_json(&scope)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| SourceGatewayError::InvalidCursor("cursor scope cannot be encoded".into()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinearCursorPayload {
    version: u8,
    tenant_id: String,
    scope_digest: String,
    provider_cursor: String,
}

fn encode_cursor(
    config: &LinearApiConfig,
    scope_digest: &str,
    provider_cursor: &str,
) -> SourceResult<SourceCursor> {
    if provider_cursor.is_empty() || provider_cursor.len() > MAX_CURSOR_BYTES {
        return Err(invalid_provider_response());
    }
    let payload = LinearCursorPayload {
        version: 1,
        tenant_id: config.tenant_id.to_string(),
        scope_digest: scope_digest.into(),
        provider_cursor: provider_cursor.into(),
    };
    let bytes = canonical_json(&payload)
        .map_err(|_| SourceGatewayError::InvalidCursor("cursor cannot be encoded".into()))?;
    let signature = sign_blob(
        config.correlation_secret.expose_secret(),
        CURSOR_DOMAIN,
        &bytes,
    )?;
    SourceCursor::from_opaque(format!(
        "{CURSOR_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn decode_cursor(
    config: &LinearApiConfig,
    cursor: &SourceCursor,
    expected_scope: &str,
) -> SourceResult<String> {
    if cursor.as_str().len() > MAX_CURSOR_BYTES {
        return Err(SourceGatewayError::InvalidCursor(
            "Linear cursor is oversized".into(),
        ));
    }
    let mut pieces = cursor.as_str().split('.');
    let valid_prefix = pieces.next() == Some("linear") && pieces.next() == Some("v1");
    let Some(encoded_payload) = pieces.next() else {
        return Err(SourceGatewayError::InvalidCursor(
            "malformed Linear cursor".into(),
        ));
    };
    let Some(encoded_signature) = pieces.next() else {
        return Err(SourceGatewayError::InvalidCursor(
            "malformed Linear cursor".into(),
        ));
    };
    if !valid_prefix || pieces.next().is_some() {
        return Err(SourceGatewayError::InvalidCursor(
            "malformed Linear cursor".into(),
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| SourceGatewayError::InvalidCursor("malformed Linear cursor payload".into()))?;
    let signature = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| {
        SourceGatewayError::InvalidCursor("malformed Linear cursor signature".into())
    })?;
    verify_blob(
        config.correlation_secret.expose_secret(),
        CURSOR_DOMAIN,
        &payload_bytes,
        &signature,
    )
    .map_err(|_| SourceGatewayError::InvalidCursor("Linear cursor signature mismatch".into()))?;
    let payload: LinearCursorPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| SourceGatewayError::InvalidCursor("malformed Linear cursor".into()))?;
    if payload.version != 1
        || payload.tenant_id != config.tenant_id.to_string()
        || payload.scope_digest != expected_scope
        || payload.provider_cursor.is_empty()
        || payload.provider_cursor.len() > MAX_CURSOR_BYTES
    {
        return Err(SourceGatewayError::InvalidCursor(
            "Linear cursor is outside this intake scope".into(),
        ));
    }
    Ok(payload.provider_cursor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinearCloseMarker {
    version: u8,
    tenant_id: String,
    external_id: String,
    idempotency_key: String,
    effect_digest: String,
    correlation_marker: String,
}

#[derive(Debug, Clone)]
struct ObservedMarker {
    payload: LinearCloseMarker,
    comment_id: String,
    recorded_at: DateTime<Utc>,
}

fn encode_marker(config: &LinearApiConfig, payload: &LinearCloseMarker) -> SourceResult<String> {
    let bytes = canonical_json(payload).map_err(|_| {
        SourceGatewayError::InvalidRequest("source correlation marker cannot be encoded".into())
    })?;
    let signature = sign_blob(
        config.correlation_secret.expose_secret(),
        MARKER_DOMAIN,
        &bytes,
    )?;
    Ok(format!(
        "{MARKER_PREFIX}{}:{}{MARKER_SUFFIX}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn decode_markers(config: &LinearApiConfig, body: &str) -> Vec<LinearCloseMarker> {
    let mut remaining = body;
    let mut markers = Vec::new();
    while let Some(prefix_index) = remaining.find(MARKER_PREFIX) {
        remaining = &remaining[prefix_index + MARKER_PREFIX.len()..];
        let Some(suffix_index) = remaining.find(MARKER_SUFFIX) else {
            break;
        };
        let candidate = &remaining[..suffix_index];
        remaining = &remaining[suffix_index + MARKER_SUFFIX.len()..];
        let Some((encoded_payload, encoded_signature)) = candidate.split_once(':') else {
            continue;
        };
        let (Ok(payload), Ok(signature)) = (
            URL_SAFE_NO_PAD.decode(encoded_payload),
            URL_SAFE_NO_PAD.decode(encoded_signature),
        ) else {
            continue;
        };
        if verify_blob(
            config.correlation_secret.expose_secret(),
            MARKER_DOMAIN,
            &payload,
            &signature,
        )
        .is_err()
        {
            continue;
        }
        if let Ok(marker) = serde_json::from_slice::<LinearCloseMarker>(&payload)
            && marker.version == 1
        {
            markers.push(marker);
        }
    }
    markers
}

fn sign_blob(secret: &str, domain: &[u8], payload: &[u8]) -> SourceResult<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        SourceGatewayError::InvalidRequest("Linear correlation secret is malformed".into())
    })?;
    mac.update(domain);
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_blob(secret: &str, domain: &[u8], payload: &[u8], signature: &[u8]) -> SourceResult<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        SourceGatewayError::InvalidRequest("Linear correlation secret is malformed".into())
    })?;
    mac.update(domain);
    mac.update(payload);
    mac.verify_slice(signature)
        .map_err(|_| SourceGatewayError::InvalidRequest("signature mismatch".into()))
}

fn validate_closure_repository(
    request: &CloseSourceRequest,
    mapping: &LinearTeamMapping,
) -> SourceResult<()> {
    let pull_request = request
        .effect
        .closure
        .pull_request
        .as_ref()
        .ok_or_else(|| {
            SourceGatewayError::InvalidRequest("pull-request evidence is required".into())
        })?;
    if pull_request.repository != mapping.repository {
        return Err(SourceGatewayError::SourceStateConflict);
    }
    parse_provider_url(&pull_request.url).map(|_| ())
}

fn close_comment(request: &CloseSourceRequest, marker: &str) -> SourceResult<String> {
    let closure = &request.effect.closure;
    let pull_request = closure.pull_request.as_ref().ok_or_else(|| {
        SourceGatewayError::InvalidRequest("pull-request evidence is required".into())
    })?;
    let mut body = format!(
        "ASF verified delivery\n\n- Outcome: {}\n- Pull request: [{}#{}]({})\n- Evidence: `{}` (`{}`)",
        closure.final_outcome_summary.trim(),
        pull_request.repository,
        pull_request.number,
        pull_request.url,
        closure.evidence_id,
        closure.evidence_digest
    );
    if let Some(cost) = closure.cost_microunits {
        write!(body, "\n- Cost: {cost} microunits").expect("writing to a String cannot fail");
    }
    if let Some(seconds) = closure.wall_time_seconds {
        write!(body, "\n- Wall time: {seconds} seconds").expect("writing to a String cannot fail");
    }
    body.push_str("\n\n");
    body.push_str(marker);
    if body.len() > MAX_COMMENT_BODY_BYTES {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear close comment exceeds the configured safe size".into(),
        ));
    }
    Ok(body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DescriptionSection {
    Objective,
    AcceptanceCriteria,
    NonGoals,
    Other,
}

fn normalize_description(
    description: Option<&str>,
    title: &str,
) -> (String, Vec<String>, Vec<String>) {
    let description = description.unwrap_or("").trim();
    if description.is_empty() {
        return (title.trim().to_owned(), Vec::new(), Vec::new());
    }
    let mut section = DescriptionSection::Other;
    let mut objective = Vec::new();
    let mut acceptance = Vec::new();
    let mut non_goals = Vec::new();
    let mut saw_heading = false;
    for line in description.lines() {
        if let Some(heading) = markdown_heading(line) {
            section = match heading.as_str() {
                "objective" => DescriptionSection::Objective,
                "acceptance criteria" | "acceptance criterion" => {
                    DescriptionSection::AcceptanceCriteria
                }
                "non-goals" | "non goals" | "non-goal" | "non goal" => DescriptionSection::NonGoals,
                _ => DescriptionSection::Other,
            };
            saw_heading |= section != DescriptionSection::Other;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match section {
            DescriptionSection::Objective => objective.push(trimmed.to_owned()),
            DescriptionSection::AcceptanceCriteria => acceptance.push(strip_list_marker(trimmed)),
            DescriptionSection::NonGoals => non_goals.push(strip_list_marker(trimmed)),
            DescriptionSection::Other => {}
        }
    }
    let objective = if saw_heading && !objective.is_empty() {
        objective.join("\n")
    } else {
        description.to_owned()
    };
    (objective, acceptance, non_goals)
}

fn markdown_heading(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let without_hash = trimmed.trim_start_matches('#').trim();
    let looks_like_heading = trimmed.starts_with('#') || without_hash.ends_with(':');
    looks_like_heading.then(|| {
        without_hash
            .trim_end_matches(':')
            .trim()
            .to_ascii_lowercase()
    })
}

fn strip_list_marker(line: &str) -> String {
    let stripped = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .unwrap_or(line);
    let numbered = stripped
        .split_once(". ")
        .filter(|(number, _)| number.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(stripped, |(_, value)| value);
    numbered.trim().to_owned()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphQlRequest<'a, V> {
    operation_name: &'static str,
    query: &'static str,
    variables: &'a V,
}

#[derive(Deserialize)]
struct GraphQlEnvelope<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Deserialize)]
struct GraphQlError {
    extensions: Option<GraphQlErrorExtensions>,
}

#[derive(Deserialize)]
struct GraphQlErrorExtensions {
    code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntakeVariables<'a> {
    first: u32,
    after: Option<&'a str>,
    label: &'a str,
    team_ids: &'a [String],
}

#[derive(Deserialize)]
struct IntakeData {
    issues: IssueConnection,
}

#[derive(Deserialize)]
struct IssueConnection {
    nodes: Vec<LinearIssue>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObserveVariables<'a> {
    id: &'a str,
    comments_first: u32,
    comments_after: Option<&'a str>,
}

#[derive(Deserialize)]
struct ObserveData {
    issue: Option<LinearIssueWithComments>,
}

#[derive(Deserialize)]
struct LinearIssueWithComments {
    #[serde(flatten)]
    core: LinearIssue,
    comments: CommentConnection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinearIssue {
    id: String,
    identifier: String,
    title: String,
    description: Option<String>,
    url: Option<String>,
    priority: i32,
    updated_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    canceled_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    state: LinearState,
    assignee: Option<LinearAssignee>,
    team: LinearTeam,
    labels: LabelConnection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LinearState {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LinearAssignee {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LinearTeam {
    id: String,
    key: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LabelConnection {
    nodes: Vec<LinearLabel>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LinearLabel {
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
struct CommentConnection {
    nodes: Vec<LinearComment>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Deserialize)]
struct LinearComment {
    id: String,
    body: String,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
}

struct ObservedIssue {
    core: LinearIssue,
    comments: Vec<LinearComment>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommentCreateVariables<'a> {
    issue_id: &'a str,
    body: &'a str,
}

#[derive(Deserialize)]
struct CommentCreateData {
    #[serde(rename = "commentCreate")]
    comment_create: CommentCreatePayload,
}

#[derive(Deserialize)]
struct CommentCreatePayload {
    success: bool,
    comment: LinearComment,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueUpdateVariables<'a> {
    issue_id: &'a str,
    state_id: &'a str,
}

#[derive(Deserialize)]
struct IssueUpdateData {
    #[serde(rename = "issueUpdate")]
    issue_update: IssueUpdatePayload,
}

#[derive(Deserialize)]
struct IssueUpdatePayload {
    success: bool,
    issue: UpdatedIssue,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatedIssue {
    id: String,
    updated_at: DateTime<Utc>,
    state: LinearState,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        sync::{Arc, Mutex},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use chrono::{TimeZone as _, Utc};
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use tokio::{net::TcpListener, task::JoinHandle};

    use crate::{
        contracts::PullRequestEvidence,
        domain::{ClosureTarget, EvidenceId, RepositoryId, SourceSystem, TenantId, WorkItemId},
        ports::source::{
            CloseSourceRequest, ObserveSourceRequest, ReconcileSourceCloseRequest,
            SourceCloseDisposition, SourceCloseEffect, SourceCloseReconciliation, SourceClosure,
            SourceGateway as _, SourceGatewayError, SourceIntakeRequest, SourceItemRef,
            SourceLifecycle,
        },
    };

    use super::{
        LinearApiAdapter, LinearApiConfig, LinearAuthentication, LinearTeamMapping, MARKER_PREFIX,
    };

    const TEST_TOKEN: &str = "lin_api_fixture_controller_token";
    const TEST_SECRET: &str = "linear-fixture-correlation-secret-32-bytes-minimum";
    const TEAM_ID: &str = "team-1";
    const ACTIVE_STATE_ID: &str = "state-active";
    const COMPLETED_STATE_ID: &str = "state-completed";
    const ISSUE_ID: &str = "issue-1";

    enum FixtureResponse {
        Json(StatusCode, Value),
        EchoComment,
    }

    #[derive(Default)]
    struct FixtureState {
        responses: Mutex<VecDeque<FixtureResponse>>,
        requests: Mutex<Vec<Value>>,
        authorizations: Mutex<Vec<String>>,
    }

    async fn fixture_handler(
        State(state): State<Arc<FixtureState>>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Response {
        state.authorizations.lock().unwrap().push(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        state.requests.lock().unwrap().push(request.clone());
        match state.responses.lock().unwrap().pop_front() {
            Some(FixtureResponse::Json(status, body)) => (status, Json(body)).into_response(),
            Some(FixtureResponse::EchoComment) => {
                let body = request["variables"]["body"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                Json(json!({
                    "data": {
                        "commentCreate": {
                            "success": true,
                            "comment": {
                                "id": "comment-1",
                                "body": body,
                                "createdAt": "2026-08-21T10:02:00Z"
                            }
                        }
                    }
                }))
                .into_response()
            }
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    struct Fixture {
        adapter: LinearApiAdapter,
        state: Arc<FixtureState>,
        server: JoinHandle<()>,
        tenant_id: TenantId,
        repository_id: RepositoryId,
    }

    impl Fixture {
        async fn start() -> Self {
            let state = Arc::new(FixtureState::default());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_state = Arc::clone(&state);
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new()
                        .route("/graphql", post(fixture_handler))
                        .with_state(server_state),
                )
                .await
                .unwrap();
            });
            let tenant_id = TenantId::new();
            let repository_id = RepositoryId::new();
            let config = test_config(tenant_id, repository_id);
            let endpoint = format!("http://{address}/graphql").parse().unwrap();
            let adapter = LinearApiAdapter::new_for_loopback_test(config, endpoint).unwrap();
            Self {
                adapter,
                state,
                server,
                tenant_id,
                repository_id,
            }
        }

        fn push(&self, status: StatusCode, body: Value) {
            self.state
                .responses
                .lock()
                .unwrap()
                .push_back(FixtureResponse::Json(status, body));
        }

        fn echo_comment(&self) {
            self.state
                .responses
                .lock()
                .unwrap()
                .push_back(FixtureResponse::EchoComment);
        }

        fn requests(&self) -> Vec<Value> {
            self.state.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn test_config(tenant_id: TenantId, repository_id: RepositoryId) -> LinearApiConfig {
        LinearApiConfig::new(
            tenant_id,
            LinearAuthentication::PersonalApiKey(SecretString::from(TEST_TOKEN)),
            BTreeMap::from([(
                TEAM_ID.into(),
                LinearTeamMapping {
                    repository_id,
                    repository: "acme/app".into(),
                    completed_state_id: COMPLETED_STATE_ID.into(),
                },
            )]),
            "linear:test-controller",
            SecretString::from(TEST_SECRET),
        )
    }

    fn issue_json(state_id: &str, state_type: &str, updated_at: &str, comments: &[Value]) -> Value {
        let completed_at = if state_id == COMPLETED_STATE_ID {
            Value::String(updated_at.into())
        } else {
            Value::Null
        };
        json!({
            "id": ISSUE_ID,
            "identifier": "ASF-1",
            "title": "Ship deterministic intake",
            "description": "## Objective\nImplement the adapter.\n\n## Acceptance Criteria\n- Contract tests pass\n\n## Non-goals\n- Deploy production",
            "url": "https://linear.app/acme/issue/ASF-1",
            "priority": 2,
            "updatedAt": updated_at,
            "archivedAt": null,
            "canceledAt": null,
            "completedAt": completed_at,
            "state": {"id": state_id, "name": state_type, "type": state_type},
            "assignee": {"id": "user-1", "name": "Platform Team"},
            "team": {"id": TEAM_ID, "key": "ASF", "name": "ASF"},
            "labels": {
                "nodes": [{"name": "asf-ready"}, {"name": "backend"}],
                "pageInfo": {"hasNextPage": false, "endCursor": null}
            },
            "comments": {
                "nodes": comments,
                "pageInfo": {"hasNextPage": false, "endCursor": null}
            }
        })
    }

    fn intake_response(issue: &Value, has_more: bool, cursor: Option<&str>) -> Value {
        json!({
            "data": {
                "issues": {
                    "nodes": [issue],
                    "pageInfo": {"hasNextPage": has_more, "endCursor": cursor}
                }
            }
        })
    }

    fn observe_response(issue: &Value) -> Value {
        json!({"data": {"issue": issue}})
    }

    fn item(tenant_id: TenantId) -> SourceItemRef {
        SourceItemRef {
            tenant_id,
            source: SourceSystem::Linear,
            external_id: ISSUE_ID.into(),
        }
    }

    fn timestamp(minute: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 10, minute, 0)
            .single()
            .unwrap()
    }

    fn close_request(
        snapshot: &crate::domain::SourceSnapshot,
        tenant_id: TenantId,
    ) -> CloseSourceRequest {
        let closure = SourceClosure {
            work_item_id: WorkItemId::new(),
            target: ClosureTarget::PullRequest,
            pull_request: Some(PullRequestEvidence {
                repository: "acme/app".into(),
                number: 42,
                url: "https://github.example/acme/app/pull/42".into(),
                base_sha: "base-sha".into(),
                head_sha: "candidate-sha".into(),
                required_ci_contexts: BTreeSet::from(["test".into()]),
                successful_ci_contexts: BTreeSet::from(["test".into()]),
            }),
            evidence_id: EvidenceId::new(),
            evidence_digest: "sha256:test-evidence".into(),
            final_outcome_summary: "Verified pull request delivered".into(),
            cost_microunits: Some(123),
            wall_time_seconds: Some(45),
        };
        let effect = SourceCloseEffect::new(
            item(tenant_id),
            snapshot.content.source_revision.clone(),
            snapshot.content_digest.clone(),
            "asf-close:work-item-1",
            closure,
        )
        .unwrap();
        CloseSourceRequest::new("source-close-1", effect, timestamp(2)).unwrap()
    }

    #[tokio::test]
    async fn default_fails_closed_and_configuration_redacts_both_secrets() {
        let tenant_id = TenantId::new();
        let request = SourceIntakeRequest::first_page(tenant_id, "asf-ready", 10);
        assert!(matches!(
            LinearApiAdapter::default()
                .intake(&request)
                .await
                .unwrap_err(),
            SourceGatewayError::UnsupportedContract { .. }
        ));

        let config = test_config(tenant_id, RepositoryId::new());
        let configured = LinearApiAdapter::new(config).unwrap();
        let rendered = format!("{configured:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(TEST_TOKEN));
        assert!(!rendered.contains(TEST_SECRET));
    }

    #[tokio::test]
    async fn intake_uses_label_team_and_relay_cursor_and_normalizes_trusted_mapping() {
        let fixture = Fixture::start().await;
        fixture.push(
            StatusCode::OK,
            intake_response(
                &issue_json(ACTIVE_STATE_ID, "started", "2026-08-21T10:00:00Z", &[]),
                true,
                Some("provider-cursor-1"),
            ),
        );
        let request = SourceIntakeRequest::first_page(fixture.tenant_id, "asf-ready", 1);
        let first = fixture.adapter.intake(&request).await.unwrap();
        assert!(first.has_more);
        let cursor = first.next_cursor.clone().unwrap();
        assert!(!cursor.as_str().contains("provider-cursor-1"));
        assert_eq!(
            first.snapshots[0].repository_id,
            Some(fixture.repository_id)
        );
        assert_eq!(
            first.snapshots[0].content.repository_hint.as_deref(),
            Some("acme/app")
        );
        assert_eq!(
            first.snapshots[0].content.objective,
            "Implement the adapter."
        );
        assert_eq!(
            first.snapshots[0].content.acceptance_criteria,
            ["Contract tests pass"]
        );
        assert_eq!(first.snapshots[0].content.normalized_priority, 75);

        let mut tampered_request = request.clone();
        tampered_request.after = Some(
            crate::ports::source::SourceCursor::from_opaque(format!("{}x", cursor.as_str()))
                .unwrap(),
        );
        assert!(matches!(
            fixture.adapter.intake(&tampered_request).await.unwrap_err(),
            SourceGatewayError::InvalidCursor(_)
        ));

        fixture.push(
            StatusCode::OK,
            json!({
                "data": {
                    "issues": {
                        "nodes": [],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }
                }
            }),
        );
        let mut next_request = request;
        next_request.after = Some(cursor);
        let second = fixture.adapter.intake(&next_request).await.unwrap();
        assert!(!second.has_more);

        let requests = fixture.requests();
        assert!(
            requests[0]["query"]
                .as_str()
                .unwrap()
                .contains("labels: { name: { eq: $label } }")
        );
        assert!(
            requests[0]["query"]
                .as_str()
                .unwrap()
                .contains("team: { id: { in: $teamIds } }")
        );
        assert_eq!(requests[0]["variables"]["label"], "asf-ready");
        assert_eq!(requests[0]["variables"]["teamIds"], json!([TEAM_ID]));
        assert_eq!(requests[1]["variables"]["after"], "provider-cursor-1");
        assert!(
            fixture
                .state
                .authorizations
                .lock()
                .unwrap()
                .iter()
                .all(|authorization| authorization == TEST_TOKEN)
        );
    }

    #[tokio::test]
    async fn graphql_errors_are_checked_even_with_http_success() {
        let fixture = Fixture::start().await;
        fixture.push(
            StatusCode::OK,
            json!({
                "data": null,
                "errors": [{
                    "message": "this must never be echoed",
                    "extensions": {"code": "RATELIMITED"}
                }]
            }),
        );
        let error = fixture
            .adapter
            .intake(&SourceIntakeRequest::first_page(
                fixture.tenant_id,
                "asf-ready",
                1,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            SourceGatewayError::ProviderRejected {
                code: "RATELIMITED".into()
            }
        );
        assert!(!error.to_string().contains("never be echoed"));
    }

    #[tokio::test]
    async fn ambiguous_update_reconciles_and_retry_adopts_signed_marker_without_duplicate_comment()
    {
        let fixture = Fixture::start().await;
        let active = issue_json(ACTIVE_STATE_ID, "started", "2026-08-21T10:00:00Z", &[]);
        fixture.push(StatusCode::OK, intake_response(&active, false, None));
        let snapshot = fixture
            .adapter
            .intake(&SourceIntakeRequest::first_page(
                fixture.tenant_id,
                "asf-ready",
                1,
            ))
            .await
            .unwrap()
            .snapshots
            .remove(0);
        let close = close_request(&snapshot, fixture.tenant_id);

        fixture.push(StatusCode::OK, observe_response(&active));
        fixture.echo_comment();
        fixture.push(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"errors": [{"extensions": {"code": "INTERNAL_ERROR"}}]}),
        );
        assert!(matches!(
            fixture.adapter.close_source(&close).await.unwrap_err(),
            SourceGatewayError::AmbiguousEffect { .. }
        ));

        let requests = fixture.requests();
        let comment_request = requests
            .iter()
            .find(|request| request["operationName"] == "AsfLinearCommentCreate")
            .unwrap();
        let comment_body = comment_request["variables"]["body"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(comment_body.contains("Verified pull request delivered"));
        assert!(comment_body.contains("https://github.example/acme/app/pull/42"));
        assert!(comment_body.contains(MARKER_PREFIX));

        let signed_comment = json!({
            "id": "comment-1",
            "body": comment_body,
            "createdAt": "2026-08-21T10:02:00Z"
        });
        let completed = issue_json(
            COMPLETED_STATE_ID,
            "completed",
            "2026-08-21T10:03:00Z",
            &[signed_comment],
        );
        fixture.push(StatusCode::OK, observe_response(&completed));
        let reconciliation = fixture
            .adapter
            .reconcile_source_close(&ReconcileSourceCloseRequest::from_close(&close))
            .await
            .unwrap();
        let SourceCloseReconciliation::Applied(receipt) = reconciliation else {
            panic!("the signed marker and trusted state must reconcile")
        };
        assert_eq!(receipt.disposition, SourceCloseDisposition::Reconciled);
        assert_eq!(receipt.effect_digest, close.effect_digest);

        fixture.push(StatusCode::OK, observe_response(&completed));
        let adopted = fixture.adapter.close_source(&close).await.unwrap();
        assert_eq!(adopted.disposition, SourceCloseDisposition::Adopted);
        let requests = fixture.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["operationName"] == "AsfLinearCommentCreate")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["operationName"] == "AsfLinearIssueUpdate")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn completed_state_without_valid_signed_marker_never_grants_asf_closure() {
        let fixture = Fixture::start().await;
        let spoof = json!({
            "id": "comment-spoof",
            "body": "asf-close:work-item-1 source-close-1",
            "createdAt": "2026-08-21T10:02:00Z"
        });
        fixture.push(
            StatusCode::OK,
            observe_response(&issue_json(
                COMPLETED_STATE_ID,
                "completed",
                "2026-08-21T10:03:00Z",
                &[spoof],
            )),
        );
        let observation = fixture
            .adapter
            .observe_source(&ObserveSourceRequest::new(item(fixture.tenant_id)))
            .await
            .unwrap();
        assert_eq!(observation.lifecycle, SourceLifecycle::Completed);
        assert!(observation.applied_closure.is_none());
    }
}
