use std::{
    collections::BTreeMap, env, fmt, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration,
};

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use url::Url;

use crate::{
    Error, Result,
    adapters::{
        GitHubApiAdapter, LinearApiConfig, LinearAuthentication, LinearTeamMapping,
        RunmillControlClient,
    },
    artifacts::{S3ArtifactStore, S3ArtifactStoreSettings, S3ServerSideEncryption},
    auth::ApiAuthenticator,
    crypto::Ed25519Signer,
    domain::{RepositoryId, TenantId},
    ledger::MAX_JOB_LEASE_DURATION,
};

const GITHUB_OBSERVATION_ENV_NAMES: [&str; 2] = ["ASF_GITHUB_API_BASE", "ASF_GITHUB_BEARER_TOKEN"];

const LINEAR_ENV_NAMES: [&str; 7] = [
    "ASF_LINEAR_AUTH_MODE",
    "ASF_LINEAR_API_TOKEN",
    "ASF_LINEAR_TEAM_MAPPINGS_JSON",
    "ASF_LINEAR_CORRELATION_SECRET",
    "ASF_LINEAR_CONNECTOR_IDENTITY",
    "ASF_LINEAR_OPT_IN_LABEL",
    "ASF_LINEAR_PAGE_SIZE",
];
const MAX_LINEAR_TEAM_MAPPINGS_JSON_BYTES: usize = 64 * 1024;
const MAX_LINEAR_TEAM_MAPPINGS: usize = 128;
const MAX_LINEAR_OPT_IN_LABEL_BYTES: usize = 256;
const MAX_LINEAR_PAGE_SIZE: u32 = 250;
const RUNMILL_CONTROL_ENV_NAMES: [&str; 5] = [
    "ASF_RUNMILL_REGISTRY_PATH",
    "ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS",
    "ASF_RUNMILL_CONTROLLER_SUBJECT",
    "ASF_RUNMILL_CANCELLATION_GRACE_SECONDS",
    "ASF_RUNMILL_WORKER_ID",
];
const MAX_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS: u64 = 60_000;
/// Artifact storage is an all-or-nothing group: without every value there is no
/// way to reach a bucket, and a partial group is a deployment mistake rather
/// than a reason to silently fall back to local disk.
const ARTIFACT_STORAGE_ENV_NAMES: [&str; 5] = [
    "ASF_ARTIFACT_S3_ENDPOINT",
    "ASF_ARTIFACT_S3_REGION",
    "ASF_ARTIFACT_S3_BUCKET",
    "ASF_ARTIFACT_S3_ACCESS_KEY_ID",
    "ASF_ARTIFACT_S3_SECRET_ACCESS_KEY",
];
const DEFAULT_ARTIFACT_S3_PREFIX: &str = "sha256";
const DEFAULT_ARTIFACT_S3_TIMEOUT_MILLISECONDS: u64 = 30_000;

/// Complete controller-side credentials for read-only GitHub observation.
///
/// The group is optional, but never partial. The bearer token remains in the
/// trusted ASF process and is never exposed through `Debug`.
#[derive(Clone)]
pub struct GitHubObservationSettings {
    api_base: Url,
    bearer_token: SecretString,
}

impl fmt::Debug for GitHubObservationSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubObservationSettings")
            .field("api_base", &self.api_base)
            .field("bearer_token", &"[REDACTED]")
            .finish()
    }
}

impl GitHubObservationSettings {
    /// Construct the read-only production observer. Adapter validation rejects
    /// insecure or credential-bearing URLs and malformed controller tokens.
    pub fn adapter(&self) -> Result<GitHubApiAdapter> {
        GitHubApiAdapter::new(self.api_base.clone(), self.bearer_token.clone()).map_err(|error| {
            Error::Validation(format!("invalid GitHub observation configuration: {error}"))
        })
    }

    #[must_use]
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    fn validate(&self) -> Result<()> {
        self.adapter().map(|_adapter| ())
    }
}

/// Complete configuration for the same-UID private Runmill control socket.
///
/// The group is optional, but never partial. The registry path is treated as
/// deployment-private metadata in diagnostics even though it is not a bearer
/// credential.
#[derive(Clone)]
pub struct RunmillControlSettings {
    registry_path: PathBuf,
    timeout: Duration,
    controller_subject: String,
    cancellation_grace_seconds: u16,
    worker_id: crate::domain::WorkerId,
}

impl fmt::Debug for RunmillControlSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunmillControlSettings")
            .field("registry_path", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("controller_subject", &self.controller_subject)
            .field(
                "cancellation_grace_seconds",
                &self.cancellation_grace_seconds,
            )
            .field("worker_id", &self.worker_id)
            .finish()
    }
}

impl RunmillControlSettings {
    pub fn client(&self) -> Result<RunmillControlClient> {
        RunmillControlClient::new(self.registry_path.clone(), self.timeout).map_err(|error| {
            Error::Validation(format!("invalid Runmill control settings: {error}"))
        })
    }

    #[must_use]
    pub fn controller_subject(&self) -> &str {
        &self.controller_subject
    }

    #[must_use]
    pub const fn cancellation_grace_seconds(&self) -> u16 {
        self.cancellation_grace_seconds
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Exact tenant worker row bound to this private Runmill daemon.
    #[must_use]
    pub const fn worker_id(&self) -> crate::domain::WorkerId {
        self.worker_id
    }

    fn validate(&self) -> Result<()> {
        if !valid_runmill_identifier(&self.controller_subject) {
            return Err(Error::Validation(
                "ASF_RUNMILL_CONTROLLER_SUBJECT must be a 1..=256 byte Runmill identifier".into(),
            ));
        }
        if !(1..=300).contains(&self.cancellation_grace_seconds) {
            return Err(Error::Validation(
                "ASF_RUNMILL_CANCELLATION_GRACE_SECONDS must be within 1..=300".into(),
            ));
        }
        self.client().map(|_client| ())
    }
}

/// Complete, tenant-fenced deployment settings for production Linear intake.
///
/// This value is either constructed in full or omitted. Credential material
/// is never exposed through `Debug`.
#[derive(Clone)]
pub struct LinearIntakeSettings {
    tenant_id: TenantId,
    authentication: LinearAuthentication,
    team_mappings: BTreeMap<String, LinearTeamMapping>,
    connector_identity: String,
    correlation_secret: SecretString,
    opt_in_label: String,
    page_size: u32,
}

impl fmt::Debug for LinearIntakeSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authentication = match self.authentication {
            LinearAuthentication::PersonalApiKey(_) => "personal_api_key [REDACTED]",
            LinearAuthentication::OAuthBearer(_) => "oauth_bearer [REDACTED]",
        };
        formatter
            .debug_struct("LinearIntakeSettings")
            .field("tenant_id", &self.tenant_id)
            .field("authentication", &authentication)
            .field("team_mapping_count", &self.team_mappings.len())
            .field("connector_identity", &self.connector_identity)
            .field("correlation_secret", &"[REDACTED]")
            .field("opt_in_label", &self.opt_in_label)
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl LinearIntakeSettings {
    /// Build the adapter's exact production configuration. The tenant comes
    /// from `ASF_TENANT_ID`; Linear cannot introduce a second tenant boundary.
    #[must_use]
    pub fn api_config(&self) -> LinearApiConfig {
        let mut config = LinearApiConfig::new(
            self.tenant_id,
            self.authentication.clone(),
            self.team_mappings.clone(),
            self.connector_identity.clone(),
            self.correlation_secret.clone(),
        );
        config.max_page_size = self.page_size;
        config
    }

    #[must_use]
    pub fn opt_in_label(&self) -> &str {
        &self.opt_in_label
    }

    #[must_use]
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    #[must_use]
    pub fn team_mapping_count(&self) -> usize {
        self.team_mappings.len()
    }

    /// Unique ASF repository bindings trusted by the Linear team mappings.
    #[must_use]
    pub fn repository_bindings(&self) -> BTreeMap<RepositoryId, String> {
        self.team_mappings
            .values()
            .map(|mapping| (mapping.repository_id, mapping.repository.clone()))
            .collect()
    }

    fn validate(&self) -> Result<()> {
        validate_bounded_text(
            "ASF_LINEAR_OPT_IN_LABEL",
            &self.opt_in_label,
            MAX_LINEAR_OPT_IN_LABEL_BYTES,
        )?;
        if !(1..=MAX_LINEAR_PAGE_SIZE).contains(&self.page_size) {
            return Err(Error::Validation(format!(
                "ASF_LINEAR_PAGE_SIZE must be within 1..={MAX_LINEAR_PAGE_SIZE}"
            )));
        }
        self.api_config()
            .validate()
            .map_err(|error| Error::Validation(format!("invalid Linear configuration: {error}")))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinearTeamMappingInput {
    team_id: String,
    repository_id: RepositoryId,
    repository: String,
    completed_state_id: String,
}

#[derive(Clone)]
pub struct Settings {
    pub tenant_id: TenantId,
    pub database_url: SecretString,
    pub bind_address: SocketAddr,
    pub artifact_root: PathBuf,
    pub signing_key_id: String,
    pub signing_seed_base64: SecretString,
    pub api_tokens_json: SecretString,
    pub database_max_connections: u32,
    pub workflow_poll_interval: Duration,
    pub workflow_lease_duration: Duration,
    pub maintenance_mode: bool,
    pub github_observation: Option<GitHubObservationSettings>,
    pub linear_intake: Option<LinearIntakeSettings>,
    pub runmill_control: Option<RunmillControlSettings>,
    /// Production artifact storage. When absent, the development filesystem
    /// store under `artifact_root` is used instead.
    pub artifact_storage: Option<S3ArtifactStoreSettings>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("tenant_id", &self.tenant_id)
            .field("database_url", &"[REDACTED]")
            .field("bind_address", &self.bind_address)
            .field("artifact_root", &self.artifact_root)
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_seed_base64", &"[REDACTED]")
            .field("api_tokens_json", &"[REDACTED]")
            .field("database_max_connections", &self.database_max_connections)
            .field("workflow_poll_interval", &self.workflow_poll_interval)
            .field("workflow_lease_duration", &self.workflow_lease_duration)
            .field("maintenance_mode", &self.maintenance_mode)
            .field("github_observation", &self.github_observation)
            .field("linear_intake", &self.linear_intake)
            .field("runmill_control", &self.runmill_control)
            .field("artifact_storage", &self.artifact_storage)
            .finish()
    }
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let tenant_id = parse("ASF_TENANT_ID", "")?;
        Ok(Self {
            tenant_id,
            database_url: SecretString::from(required("ASF_DATABASE_URL")?),
            bind_address: parse("ASF_BIND_ADDRESS", "127.0.0.1:8080")?,
            artifact_root: PathBuf::from(optional("ASF_ARTIFACT_ROOT", "./var/artifacts")),
            signing_key_id: required("ASF_SIGNING_KEY_ID")?,
            signing_seed_base64: SecretString::from(required("ASF_SIGNING_SEED_BASE64")?),
            api_tokens_json: SecretString::from(required("ASF_API_TOKENS_JSON")?),
            database_max_connections: parse("ASF_DATABASE_MAX_CONNECTIONS", "20")?,
            workflow_poll_interval: Duration::from_millis(parse(
                "ASF_WORKFLOW_POLL_MILLISECONDS",
                "1000",
            )?),
            workflow_lease_duration: Duration::from_secs(parse(
                "ASF_WORKFLOW_LEASE_SECONDS",
                "30",
            )?),
            maintenance_mode: parse("ASF_MAINTENANCE_MODE", "false")?,
            github_observation: parse_github_observation_settings(env_value)?,
            linear_intake: parse_linear_intake_settings(tenant_id, env_value)?,
            runmill_control: parse_runmill_control_settings(env_value)?,
            artifact_storage: parse_artifact_storage_settings(env_value)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.signing_key_id.trim().is_empty() {
            return Err(Error::Validation("signing key ID is empty".into()));
        }
        if self.database_max_connections == 0 {
            return Err(Error::Validation(
                "database connection limit must be positive".into(),
            ));
        }
        if self.workflow_lease_duration <= self.workflow_poll_interval {
            return Err(Error::Validation(
                "workflow lease must exceed the poll interval".into(),
            ));
        }
        if self.workflow_lease_duration > MAX_JOB_LEASE_DURATION {
            return Err(Error::Validation(
                "workflow lease cannot exceed 24 hours".into(),
            ));
        }
        Ed25519Signer::from_base64_seed(
            self.signing_key_id.clone(),
            self.signing_seed_base64.expose_secret(),
        )?;
        ApiAuthenticator::from_json(self.api_tokens_json.expose_secret())?;
        if let Some(github) = &self.github_observation {
            github.validate()?;
        }
        if let Some(linear) = &self.linear_intake {
            linear.validate()?;
        }
        if let Some(runmill) = &self.runmill_control {
            runmill.validate()?;
        }
        Ok(())
    }
}

fn parse_github_observation_settings<F>(mut lookup: F) -> Result<Option<GitHubObservationSettings>>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let mut values = BTreeMap::new();
    for name in GITHUB_OBSERVATION_ENV_NAMES {
        if let Some(value) = lookup(name)? {
            values.insert(name, value);
        }
    }
    if values.is_empty() {
        return Ok(None);
    }

    let missing = GITHUB_OBSERVATION_ENV_NAMES
        .iter()
        .filter(|name| !values.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(Error::Validation(format!(
            "GitHub observation configuration is partial; missing {}",
            missing.join(", ")
        )));
    }

    let api_base = values
        .get("ASF_GITHUB_API_BASE")
        .ok_or_else(|| Error::Validation("required ASF_GITHUB_API_BASE is missing".into()))?
        .parse::<Url>()
        .map_err(|error| Error::Validation(format!("invalid ASF_GITHUB_API_BASE: {error}")))?;
    let bearer_token = SecretString::from(
        values
            .get("ASF_GITHUB_BEARER_TOKEN")
            .cloned()
            .ok_or_else(|| {
                Error::Validation("required ASF_GITHUB_BEARER_TOKEN is missing".into())
            })?,
    );
    let settings = GitHubObservationSettings {
        api_base,
        bearer_token,
    };
    settings.validate()?;
    Ok(Some(settings))
}

/// Parse the optional S3-compatible artifact storage group.
///
/// Every artifact ASF stores is content-addressed evidence, so the endpoint is
/// validated the same way the store itself validates it: the group is complete
/// or absent, and an unusable endpoint is a startup error rather than a runtime
/// surprise on the first verification.
fn parse_artifact_storage_settings<F>(mut lookup: F) -> Result<Option<S3ArtifactStoreSettings>>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let mut values = BTreeMap::new();
    for name in ARTIFACT_STORAGE_ENV_NAMES {
        if let Some(value) = lookup(name)? {
            values.insert(name, value);
        }
    }
    if values.is_empty() {
        return Ok(None);
    }

    let missing = ARTIFACT_STORAGE_ENV_NAMES
        .iter()
        .filter(|name| !values.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(Error::Validation(format!(
            "artifact storage configuration is partial; missing {}",
            missing.join(", ")
        )));
    }

    let take = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| Error::Validation(format!("required {name} is missing")))
    };
    let endpoint = Url::parse(&take("ASF_ARTIFACT_S3_ENDPOINT")?)
        .map_err(|error| Error::Validation(format!("invalid ASF_ARTIFACT_S3_ENDPOINT: {error}")))?;
    let timeout_milliseconds = match lookup("ASF_ARTIFACT_S3_TIMEOUT_MILLISECONDS")? {
        Some(value) => value.parse::<u64>().map_err(|error| {
            Error::Validation(format!(
                "invalid ASF_ARTIFACT_S3_TIMEOUT_MILLISECONDS: {error}"
            ))
        })?,
        None => DEFAULT_ARTIFACT_S3_TIMEOUT_MILLISECONDS,
    };
    let path_style = match lookup("ASF_ARTIFACT_S3_PATH_STYLE")? {
        Some(value) => value.parse::<bool>().map_err(|error| {
            Error::Validation(format!("invalid ASF_ARTIFACT_S3_PATH_STYLE: {error}"))
        })?,
        None => true,
    };
    let server_side_encryption = match lookup("ASF_ARTIFACT_S3_ENCRYPTION")?.as_deref() {
        None | Some("bucket-managed") => S3ServerSideEncryption::BucketManaged,
        Some("aes256") => S3ServerSideEncryption::Aes256,
        Some("aws-kms") => S3ServerSideEncryption::AwsKms {
            key_id: lookup("ASF_ARTIFACT_S3_KMS_KEY_ID")?.ok_or_else(|| {
                Error::Validation(
                    "ASF_ARTIFACT_S3_ENCRYPTION=aws-kms requires ASF_ARTIFACT_S3_KMS_KEY_ID".into(),
                )
            })?,
        },
        Some(other) => {
            return Err(Error::Validation(format!(
                "invalid ASF_ARTIFACT_S3_ENCRYPTION {other}; expected bucket-managed, aes256, or aws-kms"
            )));
        }
    };

    let settings = S3ArtifactStoreSettings {
        endpoint,
        region: take("ASF_ARTIFACT_S3_REGION")?,
        bucket: take("ASF_ARTIFACT_S3_BUCKET")?,
        prefix: lookup("ASF_ARTIFACT_S3_PREFIX")?
            .unwrap_or_else(|| DEFAULT_ARTIFACT_S3_PREFIX.to_owned()),
        access_key_id: take("ASF_ARTIFACT_S3_ACCESS_KEY_ID")?,
        secret_access_key: SecretString::from(take("ASF_ARTIFACT_S3_SECRET_ACCESS_KEY")?),
        path_style,
        server_side_encryption,
        timeout: Duration::from_millis(timeout_milliseconds),
    };
    // Constructing the store is the validation: a configuration that cannot
    // build one must fail at startup, not at the first artifact read.
    S3ArtifactStore::new(settings.clone())?;
    Ok(Some(settings))
}

fn parse_runmill_control_settings<F>(mut lookup: F) -> Result<Option<RunmillControlSettings>>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let mut values = BTreeMap::new();
    for name in RUNMILL_CONTROL_ENV_NAMES {
        if let Some(value) = lookup(name)? {
            values.insert(name, value);
        }
    }
    if values.is_empty() {
        return Ok(None);
    }

    let missing = RUNMILL_CONTROL_ENV_NAMES
        .iter()
        .filter(|name| !values.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(Error::Validation(format!(
            "Runmill control configuration is partial; missing {}",
            missing.join(", ")
        )));
    }

    let take = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| Error::Validation(format!("required {name} is missing")))
    };
    let timeout_milliseconds = take("ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS")?
        .parse::<u64>()
        .map_err(|error| {
            Error::Validation(format!(
                "invalid ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS: {error}"
            ))
        })?;
    if !(1..=MAX_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS).contains(&timeout_milliseconds) {
        return Err(Error::Validation(format!(
            "ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS must be within 1..={MAX_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS}"
        )));
    }
    let cancellation_grace_seconds = take("ASF_RUNMILL_CANCELLATION_GRACE_SECONDS")?
        .parse::<u16>()
        .map_err(|error| {
            Error::Validation(format!(
                "invalid ASF_RUNMILL_CANCELLATION_GRACE_SECONDS: {error}"
            ))
        })?;
    let settings = RunmillControlSettings {
        registry_path: PathBuf::from(take("ASF_RUNMILL_REGISTRY_PATH")?),
        timeout: Duration::from_millis(timeout_milliseconds),
        controller_subject: take("ASF_RUNMILL_CONTROLLER_SUBJECT")?,
        cancellation_grace_seconds,
        worker_id: take("ASF_RUNMILL_WORKER_ID")?.parse()?,
    };
    settings.validate()?;
    Ok(Some(settings))
}

fn parse_linear_intake_settings<F>(
    tenant_id: TenantId,
    mut lookup: F,
) -> Result<Option<LinearIntakeSettings>>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let mut values = BTreeMap::new();
    for name in LINEAR_ENV_NAMES {
        if let Some(value) = lookup(name)? {
            values.insert(name, value);
        }
    }
    if values.is_empty() {
        return Ok(None);
    }

    let missing = LINEAR_ENV_NAMES
        .iter()
        .filter(|name| !values.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(Error::Validation(format!(
            "Linear intake configuration is partial; missing {}",
            missing.join(", ")
        )));
    }

    let take = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| Error::Validation(format!("required {name} is missing")))
    };
    let authentication = match take("ASF_LINEAR_AUTH_MODE")?.as_str() {
        "personal_api_key" => {
            LinearAuthentication::PersonalApiKey(SecretString::from(take("ASF_LINEAR_API_TOKEN")?))
        }
        "oauth_bearer" => {
            LinearAuthentication::OAuthBearer(SecretString::from(take("ASF_LINEAR_API_TOKEN")?))
        }
        _ => {
            return Err(Error::Validation(
                "ASF_LINEAR_AUTH_MODE must be exactly personal_api_key or oauth_bearer".into(),
            ));
        }
    };
    let mappings_json = take("ASF_LINEAR_TEAM_MAPPINGS_JSON")?;
    if mappings_json.len() > MAX_LINEAR_TEAM_MAPPINGS_JSON_BYTES {
        return Err(Error::Validation(format!(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON exceeds {MAX_LINEAR_TEAM_MAPPINGS_JSON_BYTES} bytes"
        )));
    }
    let mapping_inputs: Vec<LinearTeamMappingInput> = serde_json::from_str(&mappings_json)
        .map_err(|error| {
            Error::Validation(format!("invalid ASF_LINEAR_TEAM_MAPPINGS_JSON: {error}"))
        })?;
    if mapping_inputs.is_empty() || mapping_inputs.len() > MAX_LINEAR_TEAM_MAPPINGS {
        return Err(Error::Validation(format!(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON must contain 1..={MAX_LINEAR_TEAM_MAPPINGS} entries"
        )));
    }
    let mut team_mappings = BTreeMap::new();
    let mut repository_slugs_by_id = BTreeMap::new();
    let mut repository_ids_by_slug = BTreeMap::new();
    for mapping in mapping_inputs {
        if mapping.repository_id.as_uuid().is_nil() {
            return Err(Error::Validation(
                "Linear repository mapping cannot use a nil repository ID".into(),
            ));
        }
        if repository_slugs_by_id
            .insert(mapping.repository_id, mapping.repository.clone())
            .is_some_and(|existing| existing != mapping.repository)
        {
            return Err(Error::Validation(
                "one Linear repository_id cannot map to multiple repository slugs".into(),
            ));
        }
        if repository_ids_by_slug
            .insert(mapping.repository.clone(), mapping.repository_id)
            .is_some_and(|existing| existing != mapping.repository_id)
        {
            return Err(Error::Validation(
                "one Linear repository slug cannot map to multiple repository IDs".into(),
            ));
        }
        if team_mappings
            .insert(
                mapping.team_id.clone(),
                LinearTeamMapping {
                    repository_id: mapping.repository_id,
                    repository: mapping.repository,
                    completed_state_id: mapping.completed_state_id,
                },
            )
            .is_some()
        {
            return Err(Error::Validation(
                "ASF_LINEAR_TEAM_MAPPINGS_JSON contains a duplicate team_id".into(),
            ));
        }
    }
    let page_size = take("ASF_LINEAR_PAGE_SIZE")?
        .parse::<u32>()
        .map_err(|error| Error::Validation(format!("invalid ASF_LINEAR_PAGE_SIZE: {error}")))?;
    let settings = LinearIntakeSettings {
        tenant_id,
        authentication,
        team_mappings,
        connector_identity: take("ASF_LINEAR_CONNECTOR_IDENTITY")?,
        correlation_secret: SecretString::from(take("ASF_LINEAR_CORRELATION_SECRET")?),
        opt_in_label: take("ASF_LINEAR_OPT_IN_LABEL")?,
        page_size,
    };
    settings.validate()?;
    Ok(Some(settings))
}

fn validate_bounded_text(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Validation(format!(
            "{name} must be non-empty, trimmed, control-free, and at most {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn valid_runmill_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 256
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
}

fn env_value(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(Error::Validation(format!(
            "environment variable {name} is not valid Unicode"
        ))),
    }
}

fn required(name: &str) -> Result<String> {
    env::var(name)
        .map_err(|_| Error::Validation(format!("required environment variable {name} is unset")))
}

fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.into())
}

fn parse<T>(name: &str, default: &str) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    optional(name, default)
        .parse()
        .map_err(|error| Error::Validation(format!("invalid {name}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(seed: &str) -> Settings {
        Settings {
            tenant_id: TenantId::new(),
            database_url: SecretString::from("postgresql://localhost/asf"),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            artifact_root: PathBuf::from("var/artifacts"),
            signing_key_id: "test-signing-key".into(),
            signing_seed_base64: SecretString::from(seed),
            api_tokens_json: SecretString::from(
                r#"[{"token":"a-test-token-that-is-at-least-32-bytes","subject":"test","roles":["platform_admin"]}]"#,
            ),
            database_max_connections: 4,
            workflow_poll_interval: Duration::from_secs(1),
            workflow_lease_duration: Duration::from_secs(30),
            maintenance_mode: true,
            github_observation: None,
            linear_intake: None,
            runmill_control: None,
            artifact_storage: None,
        }
    }

    #[test]
    fn startup_validation_checks_cryptographic_and_authentication_material() {
        assert!(
            settings("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .validate()
                .is_ok()
        );
        assert!(settings("not-a-32-byte-seed").validate().is_err());

        let mut invalid_auth = settings("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        invalid_auth.api_tokens_json = SecretString::from("[]");
        assert!(invalid_auth.validate().is_err());
    }

    #[test]
    fn workflow_lease_accepts_exactly_24_hours_and_rejects_longer() {
        let mut bounded = settings("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        bounded.workflow_lease_duration = MAX_JOB_LEASE_DURATION;
        assert!(bounded.validate().is_ok());

        bounded.workflow_lease_duration = MAX_JOB_LEASE_DURATION + Duration::from_secs(1);
        assert!(bounded.validate().is_err());
    }

    fn complete_github_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("ASF_GITHUB_API_BASE", "https://api.github.com/".into()),
            (
                "ASF_GITHUB_BEARER_TOKEN",
                "github-fixture-controller-token".into(),
            ),
        ])
    }

    fn parse_github(
        values: &BTreeMap<&'static str, String>,
    ) -> Result<Option<GitHubObservationSettings>> {
        parse_github_observation_settings(|name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn github_observation_configuration_is_optional_atomic_and_redacted() {
        assert!(parse_github(&BTreeMap::new()).unwrap().is_none());

        let mut partial = complete_github_values();
        partial.remove("ASF_GITHUB_API_BASE");
        let error = parse_github(&partial).unwrap_err().to_string();
        assert!(error.contains("partial"));
        assert!(error.contains("ASF_GITHUB_API_BASE"));
        assert!(!error.contains("github-fixture-controller-token"));

        let configured = parse_github(&complete_github_values()).unwrap().unwrap();
        assert_eq!(configured.api_base().as_str(), "https://api.github.com/");
        let debug = format!("{configured:?}");
        assert!(debug.contains("api.github.com"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("github-fixture-controller-token"));
    }

    #[test]
    fn github_observation_rejects_untrusted_endpoints_and_malformed_tokens() {
        let mut insecure = complete_github_values();
        insecure.insert("ASF_GITHUB_API_BASE", "http://github.example/api/v3".into());
        assert!(parse_github(&insecure).is_err());

        let mut credentialed = complete_github_values();
        credentialed.insert(
            "ASF_GITHUB_API_BASE",
            "https://user:password@github.example/api/v3".into(),
        );
        assert!(parse_github(&credentialed).is_err());

        let mut queried = complete_github_values();
        queried.insert(
            "ASF_GITHUB_API_BASE",
            "https://github.example/api/v3?token=unsafe".into(),
        );
        assert!(parse_github(&queried).is_err());

        let mut malformed_token = complete_github_values();
        malformed_token.insert("ASF_GITHUB_BEARER_TOKEN", " sensitive-short ".into());
        let error = parse_github(&malformed_token).unwrap_err().to_string();
        assert!(!error.contains("sensitive-short"));
    }

    fn complete_linear_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("ASF_LINEAR_AUTH_MODE", "personal_api_key".into()),
            (
                "ASF_LINEAR_API_TOKEN",
                "lin_api_fixture_token_at_least_32_bytes".into(),
            ),
            (
                "ASF_LINEAR_TEAM_MAPPINGS_JSON",
                r#"[{"team_id":"linear-team-1","repository_id":"0198efb8-0000-7000-8000-000000000010","repository":"cloudsail/asf","completed_state_id":"linear-state-done-1"}]"#.into(),
            ),
            (
                "ASF_LINEAR_CORRELATION_SECRET",
                "fixture-correlation-secret-at-least-32-bytes".into(),
            ),
            (
                "ASF_LINEAR_CONNECTOR_IDENTITY",
                "linear:production-controller".into(),
            ),
            ("ASF_LINEAR_OPT_IN_LABEL", "asf:autonomous".into()),
            ("ASF_LINEAR_PAGE_SIZE", "100".into()),
        ])
    }

    fn parse_linear(
        values: &BTreeMap<&'static str, String>,
    ) -> Result<Option<LinearIntakeSettings>> {
        parse_linear_intake_settings(TenantId::new(), |name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn linear_configuration_is_optional_but_never_partial() {
        assert!(parse_linear(&BTreeMap::new()).unwrap().is_none());

        let mut partial = complete_linear_values();
        partial.remove("ASF_LINEAR_CORRELATION_SECRET");
        let error = parse_linear(&partial).unwrap_err().to_string();
        assert!(error.contains("partial"));
        assert!(error.contains("ASF_LINEAR_CORRELATION_SECRET"));
        assert!(!error.contains("fixture-correlation-secret"));
    }

    #[test]
    fn linear_configuration_is_tenant_bound_and_debug_redacts_secrets() {
        let tenant_id = TenantId::new();
        let values = complete_linear_values();
        let linear = parse_linear_intake_settings(tenant_id, |name| Ok(values.get(name).cloned()))
            .unwrap()
            .unwrap();

        assert_eq!(linear.api_config().tenant_id, tenant_id);
        assert_eq!(linear.api_config().max_page_size, 100);
        assert_eq!(linear.opt_in_label(), "asf:autonomous");
        let debug = format!("{linear:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("lin_api_fixture_token"));
        assert!(!debug.contains("fixture-correlation-secret"));
    }

    #[test]
    fn linear_mapping_json_and_page_size_are_strictly_bounded() {
        let mut unknown_field = complete_linear_values();
        unknown_field.insert(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON",
            r#"[{"team_id":"team","repository_id":"0198efb8-0000-7000-8000-000000000010","repository":"cloudsail/asf","completed_state_id":"done","unexpected":true}]"#.into(),
        );
        assert!(parse_linear(&unknown_field).is_err());

        let mut duplicate = complete_linear_values();
        let mapping = r#"{"team_id":"team","repository_id":"0198efb8-0000-7000-8000-000000000010","repository":"cloudsail/asf","completed_state_id":"done"}"#;
        duplicate.insert(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON",
            format!("[{mapping},{mapping}]"),
        );
        assert!(
            parse_linear(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let mut oversized_page = complete_linear_values();
        oversized_page.insert("ASF_LINEAR_PAGE_SIZE", "251".into());
        assert!(parse_linear(&oversized_page).is_err());

        let mut oversized_json = complete_linear_values();
        oversized_json.insert(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON",
            "x".repeat(MAX_LINEAR_TEAM_MAPPINGS_JSON_BYTES + 1),
        );
        assert!(
            parse_linear(&oversized_json)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );

        let mapping = r#"{"team_id":"team","repository_id":"0198efb8-0000-7000-8000-000000000010","repository":"cloudsail/asf","completed_state_id":"done"}"#;
        let mut too_many = complete_linear_values();
        too_many.insert(
            "ASF_LINEAR_TEAM_MAPPINGS_JSON",
            format!(
                "[{}]",
                vec![mapping; MAX_LINEAR_TEAM_MAPPINGS + 1].join(",")
            ),
        );
        assert!(
            parse_linear(&too_many)
                .unwrap_err()
                .to_string()
                .contains("1..=128")
        );
    }

    #[test]
    fn linear_authentication_mode_is_explicit_and_secret_errors_are_redacted() {
        let mut values = complete_linear_values();
        values.insert("ASF_LINEAR_AUTH_MODE", "bearer".into());
        let error = parse_linear(&values).unwrap_err().to_string();
        assert!(error.contains("personal_api_key or oauth_bearer"));
        assert!(!error.contains("lin_api_fixture_token"));

        let mut short_secret = complete_linear_values();
        short_secret.insert("ASF_LINEAR_CORRELATION_SECRET", "sensitive-short".into());
        let error = parse_linear(&short_secret).unwrap_err().to_string();
        assert!(!error.contains("sensitive-short"));
    }

    fn complete_runmill_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "ASF_RUNMILL_REGISTRY_PATH",
                "/run/user/1000/runmill/daemon.json".into(),
            ),
            ("ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS", "5000".into()),
            (
                "ASF_RUNMILL_CONTROLLER_SUBJECT",
                "asf:production-controller".into(),
            ),
            ("ASF_RUNMILL_CANCELLATION_GRACE_SECONDS", "30".into()),
            (
                "ASF_RUNMILL_WORKER_ID",
                crate::domain::WorkerId::new().to_string(),
            ),
        ])
    }

    fn parse_runmill(
        values: &BTreeMap<&'static str, String>,
    ) -> Result<Option<RunmillControlSettings>> {
        parse_runmill_control_settings(|name| Ok(values.get(name).cloned()))
    }

    fn complete_artifact_storage_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "ASF_ARTIFACT_S3_ENDPOINT",
                "https://s3.example.invalid".into(),
            ),
            ("ASF_ARTIFACT_S3_REGION", "us-east-1".into()),
            ("ASF_ARTIFACT_S3_BUCKET", "asf-artifacts".into()),
            (
                "ASF_ARTIFACT_S3_ACCESS_KEY_ID",
                "AKIAIOSFODNN7EXAMPLE".into(),
            ),
            (
                "ASF_ARTIFACT_S3_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ),
        ])
    }

    fn parse_artifact_storage(
        values: &BTreeMap<&'static str, String>,
    ) -> Result<Option<S3ArtifactStoreSettings>> {
        parse_artifact_storage_settings(|name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn artifact_storage_configuration_is_optional_atomic_and_redacted() {
        // Absent means the development filesystem store, which the daemon
        // announces rather than assuming.
        assert!(parse_artifact_storage(&BTreeMap::new()).unwrap().is_none());

        let mut partial = complete_artifact_storage_values();
        partial.remove("ASF_ARTIFACT_S3_BUCKET");
        let error = parse_artifact_storage(&partial).unwrap_err().to_string();
        assert!(error.contains("partial"));
        assert!(error.contains("ASF_ARTIFACT_S3_BUCKET"));

        let configured = parse_artifact_storage(&complete_artifact_storage_values())
            .unwrap()
            .unwrap();
        assert_eq!(configured.bucket, "asf-artifacts");
        assert_eq!(configured.prefix, "sha256");
        assert!(configured.path_style);
        assert_eq!(configured.timeout, Duration::from_secs(30));
        assert_eq!(
            configured.server_side_encryption,
            S3ServerSideEncryption::BucketManaged
        );
        let debug = format!("{configured:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("wJalrXUtnFEMI"));
        assert!(!debug.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn artifact_storage_refuses_a_configuration_it_could_not_use() {
        // A plaintext endpoint outside loopback would put evidence bytes and a
        // signed credential on the wire in the clear.
        let mut plaintext = complete_artifact_storage_values();
        plaintext.insert(
            "ASF_ARTIFACT_S3_ENDPOINT",
            "http://s3.example.invalid".into(),
        );
        assert!(parse_artifact_storage(&plaintext).is_err());

        let mut malformed = complete_artifact_storage_values();
        malformed.insert("ASF_ARTIFACT_S3_ENDPOINT", "not a url".into());
        assert!(parse_artifact_storage(&malformed).is_err());

        let mut bucket = complete_artifact_storage_values();
        bucket.insert("ASF_ARTIFACT_S3_BUCKET", "Not-A-Bucket".into());
        assert!(parse_artifact_storage(&bucket).is_err());

        let mut encryption = complete_artifact_storage_values();
        encryption.insert("ASF_ARTIFACT_S3_ENCRYPTION", "rot13".into());
        assert!(parse_artifact_storage(&encryption).is_err());

        // KMS encryption without a key names no key at all.
        let mut kms = complete_artifact_storage_values();
        kms.insert("ASF_ARTIFACT_S3_ENCRYPTION", "aws-kms".into());
        assert!(parse_artifact_storage(&kms).is_err());
        kms.insert("ASF_ARTIFACT_S3_KMS_KEY_ID", "arn:aws:kms:key/1".into());
        assert_eq!(
            parse_artifact_storage(&kms)
                .unwrap()
                .unwrap()
                .server_side_encryption,
            S3ServerSideEncryption::AwsKms {
                key_id: "arn:aws:kms:key/1".into()
            }
        );
    }

    #[test]
    fn a_local_minio_endpoint_is_usable_for_development() {
        let mut local = complete_artifact_storage_values();
        local.insert("ASF_ARTIFACT_S3_ENDPOINT", "http://127.0.0.1:9000".into());
        local.insert("ASF_ARTIFACT_S3_PATH_STYLE", "true".into());
        let configured = parse_artifact_storage(&local).unwrap().unwrap();
        assert_eq!(configured.endpoint.port(), Some(9000));
        assert!(configured.path_style);
    }

    #[test]
    fn runmill_control_configuration_is_optional_atomic_bounded_and_redacted() {
        assert!(parse_runmill(&BTreeMap::new()).unwrap().is_none());

        let mut partial = complete_runmill_values();
        partial.remove("ASF_RUNMILL_CONTROLLER_SUBJECT");
        let error = parse_runmill(&partial).unwrap_err().to_string();
        assert!(error.contains("partial"));
        assert!(error.contains("ASF_RUNMILL_CONTROLLER_SUBJECT"));

        let configured = parse_runmill(&complete_runmill_values()).unwrap().unwrap();
        assert_eq!(configured.timeout(), Duration::from_secs(5));
        assert_eq!(configured.cancellation_grace_seconds(), 30);
        assert_eq!(configured.controller_subject(), "asf:production-controller");
        let debug = format!("{configured:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("/run/user/1000"));

        let mut relative = complete_runmill_values();
        relative.insert("ASF_RUNMILL_REGISTRY_PATH", "relative/daemon.json".into());
        assert!(parse_runmill(&relative).is_err());

        let mut oversized_timeout = complete_runmill_values();
        oversized_timeout.insert("ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS", "60001".into());
        assert!(parse_runmill(&oversized_timeout).is_err());

        let mut forced_grace = complete_runmill_values();
        forced_grace.insert("ASF_RUNMILL_CANCELLATION_GRACE_SECONDS", "0".into());
        assert!(parse_runmill(&forced_grace).is_err());

        let mut invalid_subject = complete_runmill_values();
        invalid_subject.insert("ASF_RUNMILL_CONTROLLER_SUBJECT", "asf controller".into());
        assert!(parse_runmill(&invalid_subject).is_err());
    }
}
