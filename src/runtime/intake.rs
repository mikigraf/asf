use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    ActivityControls, ActivityOutcome, INTAKE_SYNC, INTAKE_SYNC_ACTIVITY_CONTRACT_ID, JobHandler,
};
use crate::{
    Error, Result,
    audit::{AuditEventContent, HashedAuditEvent},
    domain::{EventId, SourceSnapshot, SourceSystem, TenantId, WorkItemId, WorkItemState},
    ledger::{ClaimedWorkflowJob, PgLedger},
    ports::{
        MAX_SOURCE_INTAKE_PAGE_SIZE, SOURCE_INTAKE_PAGE_SCHEMA_V1, SourceCursor, SourceGateway,
        SourceGatewayError, SourceIntakeRequest,
    },
    security::{Caller, reject_sensitive_fields},
};

const MAX_INTAKE_PAGES: usize = 10_000;
const MAX_INTAKE_SNAPSHOTS: usize = 100_000;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_SNAPSHOT_BYTES: usize = 1_048_576;
const SOURCE_EVENT_SCHEMA_V1: &str = "asf.work-item-source-event.v1";
const SOURCE_EVENT_HEADERS_SCHEMA_V1: &str = "asf.work-item-source-event-headers.v1";
const REEVALUATION_DEADLINE_HOURS: i64 = 24;

/// Durable, tenant-fenced implementation of the API's `INTAKE_SYNC` job.
pub struct IntakeSyncHandler {
    ledger: PgLedger,
    tenant_id: TenantId,
    source: Arc<dyn SourceGateway>,
    opt_in_label: String,
    page_size: u32,
}

impl fmt::Debug for IntakeSyncHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntakeSyncHandler")
            .field("tenant_id", &self.tenant_id)
            .field("opt_in_label", &self.opt_in_label)
            .field("page_size", &self.page_size)
            .finish_non_exhaustive()
    }
}

impl IntakeSyncHandler {
    /// Construct an intake handler with an explicit tenant fence.
    pub fn new(
        ledger: PgLedger,
        tenant_id: TenantId,
        source: Arc<dyn SourceGateway>,
        opt_in_label: impl Into<String>,
        page_size: u32,
    ) -> Result<Self> {
        let opt_in_label = opt_in_label.into();
        if opt_in_label.trim().is_empty() {
            return Err(Error::Validation(
                "source intake opt-in label must be non-empty".into(),
            ));
        }
        if page_size == 0 || page_size > MAX_SOURCE_INTAKE_PAGE_SIZE {
            return Err(Error::Validation(format!(
                "source intake page size must be within 1..={MAX_SOURCE_INTAKE_PAGE_SIZE}"
            )));
        }
        Ok(Self {
            ledger,
            tenant_id,
            source,
            opt_in_label,
            page_size,
        })
    }

    async fn persist(
        &self,
        job: &ClaimedWorkflowJob,
        collection: &CollectedSnapshots,
    ) -> Result<IntakePersistenceSummary> {
        let mut transaction = self
            .ledger
            .pool()
            .begin()
            .await
            .map_err(|error| database_error("begin source intake transaction", &error))?;
        require_available_tenant(&mut transaction, self.tenant_id).await?;
        let mut writer = IntakeTransactionWriter::lock(&mut transaction, self.tenant_id).await?;
        let now = Utc::now();
        let correlation_id = job.id.to_string();
        let mut summary = IntakePersistenceSummary {
            pages_fetched: collection.pages_fetched,
            snapshots_received: collection.snapshots.len(),
            ..IntakePersistenceSummary::default()
        };

        for snapshot in &collection.snapshots {
            let result = writer
                .persist_snapshot(
                    snapshot,
                    &correlation_id,
                    IntakeProvenance::System(SystemIntakeActor::IntakeSync),
                    now,
                )
                .await?;
            if result.snapshot_inserted {
                summary.snapshots_inserted += 1;
            } else {
                summary.snapshots_adopted += 1;
            }
            match result.outcome {
                IntakeOutcome::Discovered => summary.work_items_discovered += 1,
                IntakeOutcome::Unchanged => summary.unchanged_work_items += 1,
                IntakeOutcome::ReadinessRequeued => summary.readiness_requeued += 1,
                IntakeOutcome::AuthorityReevaluationRequired => {
                    summary.reevaluations_required += 1;
                }
            }
        }

        transaction
            .commit()
            .await
            .map_err(|error| database_error("commit source intake transaction", &error))?;
        Ok(summary)
    }
}

#[async_trait]
impl JobHandler for IntakeSyncHandler {
    fn job_type(&self) -> &str {
        INTAKE_SYNC
    }

    fn activity_contract_id(&self) -> &str {
        INTAKE_SYNC_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        validate_job(job, self.tenant_id)?;
        // Fetch and validate every page before opening the ledger transaction.
        // A provider failure therefore cannot leave a partially applied sync.
        let collection = collect_source_snapshots(
            self.source.as_ref(),
            self.tenant_id,
            &self.opt_in_label,
            self.page_size,
        )
        .await?;
        let summary = self.persist(job, &collection).await?;
        let result = serde_json::to_value(summary)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        Ok(ActivityOutcome::Complete {
            result: Some(result),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntakeSyncPayload {
    tenant_id: TenantId,
    action: String,
}

fn validate_job(job: &ClaimedWorkflowJob, tenant_id: TenantId) -> Result<()> {
    if job.job_type != INTAKE_SYNC || job.activity_contract_id != INTAKE_SYNC_ACTIVITY_CONTRACT_ID {
        return Err(Error::Validation(format!(
            "intake handler cannot execute job type {:?} with activity contract {:?}",
            job.job_type, job.activity_contract_id
        )));
    }
    if job.tenant_id != tenant_id.as_uuid() {
        return Err(Error::Validation(
            "source intake job crosses the handler tenant boundary".into(),
        ));
    }
    if job.workflow_instance_id.is_some() || job.work_item_id.is_some() || job.attempt_id.is_some()
    {
        return Err(Error::Validation(
            "source intake must be a tenant-level workflow job".into(),
        ));
    }
    if job.idempotency_key.trim().is_empty() {
        return Err(Error::Validation(
            "source intake job idempotency key must be non-empty".into(),
        ));
    }
    let payload: IntakeSyncPayload =
        serde_json::from_value(job.payload.clone()).map_err(|error| {
            Error::Validation(format!("invalid source intake job payload: {error}"))
        })?;
    if payload.tenant_id != tenant_id || payload.tenant_id.as_uuid() != job.tenant_id {
        return Err(Error::Validation(
            "source intake payload crosses the claimed tenant boundary".into(),
        ));
    }
    if payload.action != "sync" {
        return Err(Error::Validation(
            "source intake job action must be exactly \"sync\"".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CollectedSnapshots {
    pages_fetched: usize,
    snapshots: Vec<SourceSnapshot>,
}

async fn collect_source_snapshots(
    source: &dyn SourceGateway,
    tenant_id: TenantId,
    opt_in_label: &str,
    page_size: u32,
) -> Result<CollectedSnapshots> {
    let mut after: Option<SourceCursor> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut snapshots_by_item: BTreeMap<(String, String), SourceSnapshot> = BTreeMap::new();
    let mut snapshot_ids: BTreeMap<Uuid, (String, String, String)> = BTreeMap::new();

    for page_index in 0..MAX_INTAKE_PAGES {
        let request = SourceIntakeRequest {
            schema: crate::ports::SOURCE_INTAKE_REQUEST_SCHEMA_V1.into(),
            tenant_id,
            opt_in_label: opt_in_label.into(),
            after: after.clone(),
            limit: page_size,
        };
        request.validate().map_err(map_source_error)?;
        let page = source.intake(&request).await.map_err(map_source_error)?;
        if page.schema != SOURCE_INTAKE_PAGE_SCHEMA_V1 {
            return Err(Error::Validation(
                "source provider returned an unsupported intake-page schema".into(),
            ));
        }
        let page_limit = usize::try_from(page_size)
            .map_err(|_| Error::Validation("source page size cannot fit this platform".into()))?;
        if page.snapshots.len() > page_limit {
            return Err(Error::Validation(
                "source provider returned more snapshots than requested".into(),
            ));
        }
        if page.has_more && page.snapshots.is_empty() {
            return Err(Error::Validation(
                "source provider returned an empty non-terminal intake page".into(),
            ));
        }

        for snapshot in page.snapshots {
            validate_snapshot(&snapshot, tenant_id, opt_in_label)?;
            let key = (
                source_system_db(snapshot.content.source).to_owned(),
                snapshot.content.external_id.clone(),
            );
            let id_semantics = (
                key.0.clone(),
                key.1.clone(),
                snapshot.content_digest.clone(),
            );
            if let Some(existing) = snapshot_ids.insert(snapshot.id.as_uuid(), id_semantics.clone())
                && existing != id_semantics
            {
                return Err(Error::Conflict(
                    "source provider reused one snapshot ID for conflicting content".into(),
                ));
            }
            if let Some(existing) = snapshots_by_item.get(&key) {
                if !same_snapshot_semantics(existing, &snapshot) {
                    return Err(Error::Conflict(format!(
                        "source provider returned conflicting snapshots for {} {} in one sync",
                        key.0, key.1
                    )));
                }
                continue;
            }
            if snapshots_by_item.len() >= MAX_INTAKE_SNAPSHOTS {
                return Err(Error::Validation(format!(
                    "source intake exceeded the {MAX_INTAKE_SNAPSHOTS} snapshot bound"
                )));
            }
            snapshots_by_item.insert(key, snapshot);
        }

        match (page.has_more, page.next_cursor) {
            (false, None) => {
                return Ok(CollectedSnapshots {
                    pages_fetched: page_index + 1,
                    snapshots: snapshots_by_item.into_values().collect(),
                });
            }
            (true, Some(cursor)) => {
                if cursor.as_str().len() > MAX_CURSOR_BYTES {
                    return Err(Error::Validation(
                        "source intake cursor exceeded the configured size bound".into(),
                    ));
                }
                if after.as_ref() == Some(&cursor)
                    || !seen_cursors.insert(cursor.as_str().to_owned())
                {
                    return Err(Error::Validation(
                        "source provider repeated an intake cursor".into(),
                    ));
                }
                after = Some(cursor);
            }
            (true, None) => {
                return Err(Error::Validation(
                    "source provider omitted the cursor for a non-terminal intake page".into(),
                ));
            }
            (false, Some(_cursor)) => {
                return Err(Error::Validation(
                    "source provider returned a cursor for a terminal intake page".into(),
                ));
            }
        }
    }

    Err(Error::Validation(format!(
        "source intake exceeded the {MAX_INTAKE_PAGES} page bound"
    )))
}

/// Enforces every snapshot invariant shared by all intake paths (sync and direct API
/// intake): tenant fencing, canonical digest agreement, identity-field bounds, a safe
/// HTTP(S) source URL without embedded userinfo, and the serialized-snapshot byte bound.
/// Callers that require the sync opt-in label must additionally check for it themselves.
pub(crate) fn validate_snapshot_core(snapshot: &SourceSnapshot, tenant_id: TenantId) -> Result<()> {
    if snapshot.tenant_id != tenant_id {
        return Err(Error::Validation(
            "source provider returned a snapshot for another tenant".into(),
        ));
    }
    snapshot.content.validate()?;
    if snapshot.content.digest()? != snapshot.content_digest {
        return Err(Error::Crypto(
            "source snapshot content digest does not match its canonical content".into(),
        ));
    }
    if snapshot.connector_identity.trim().is_empty()
        || snapshot.connector_identity.len() > 512
        || snapshot.content.external_id.len() > 512
        || snapshot.content.source_revision.len() > 1_024
    {
        return Err(Error::Validation(
            "source snapshot identity fields are empty or exceed their bounds".into(),
        ));
    }
    if snapshot.content.source_url.as_ref().is_some_and(|url| {
        !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
    }) {
        return Err(Error::Validation(
            "source snapshot URL is not a safe HTTP(S) reference".into(),
        ));
    }
    let encoded =
        serde_json::to_vec(snapshot).map_err(|error| Error::Serialization(error.to_string()))?;
    if encoded.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::Validation(format!(
            "source snapshot exceeded the {MAX_SNAPSHOT_BYTES} byte bound"
        )));
    }
    Ok(())
}

/// Sync-only snapshot validation: the shared core checks plus the configured opt-in label.
fn validate_snapshot(
    snapshot: &SourceSnapshot,
    tenant_id: TenantId,
    opt_in_label: &str,
) -> Result<()> {
    validate_snapshot_core(snapshot, tenant_id)?;
    if !snapshot.content.labels.contains(opt_in_label) {
        return Err(Error::Validation(
            "source provider returned a snapshot without the configured opt-in label".into(),
        ));
    }
    Ok(())
}

fn same_snapshot_semantics(left: &SourceSnapshot, right: &SourceSnapshot) -> bool {
    left.tenant_id == right.tenant_id
        && left.repository_id == right.repository_id
        && left.content == right.content
        && left.content_digest == right.content_digest
        && left.connector_identity == right.connector_identity
}

fn map_source_error(error: SourceGatewayError) -> Error {
    match error {
        SourceGatewayError::TransportUnavailable => Error::ExternalUnavailable(
            "source connector transport is unavailable during intake".into(),
        ),
        SourceGatewayError::AmbiguousEffect {
            idempotency_key,
            effect_digest,
        } => Error::AmbiguousEffect(format!(
            "unexpected ambiguous source effect during read-only intake for {idempotency_key} ({effect_digest})"
        )),
        SourceGatewayError::IdempotencyConflict {
            idempotency_key,
            existing_digest,
            submitted_digest,
        } => Error::Conflict(format!(
            "source intake idempotency conflict for {idempotency_key}: {existing_digest} != {submitted_digest}"
        )),
        SourceGatewayError::SourceStateConflict => {
            Error::Conflict("source changed while the intake page was being read".into())
        }
        SourceGatewayError::UnsupportedContract { detail } => {
            Error::Validation(format!("unsupported source intake contract: {detail}"))
        }
        SourceGatewayError::InvalidRequest(detail) | SourceGatewayError::InvalidCursor(detail) => {
            Error::Validation(format!("invalid source intake exchange: {detail}"))
        }
        SourceGatewayError::ItemNotFound => {
            Error::Validation("source provider lost an item during intake".into())
        }
        SourceGatewayError::ProviderRejected { code } => {
            Error::Validation(format!("source provider rejected intake with code {code}"))
        }
        SourceGatewayError::InvalidProviderResponse => {
            Error::Validation("source provider returned an invalid intake response".into())
        }
        SourceGatewayError::ResponseTooLarge => {
            Error::Validation("source provider intake response exceeded its byte limit".into())
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct IntakePersistenceSummary {
    pages_fetched: usize,
    snapshots_received: usize,
    snapshots_inserted: usize,
    snapshots_adopted: usize,
    work_items_discovered: usize,
    readiness_requeued: usize,
    reevaluations_required: usize,
    unchanged_work_items: usize,
}

struct StoredSnapshot {
    id: Uuid,
    captured_at: chrono::DateTime<Utc>,
    inserted: bool,
}

async fn require_available_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
) -> Result<()> {
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM tenants WHERE id = $1 FOR SHARE")
            .bind(tenant_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| database_error("lock source intake tenant", &error))?
            .ok_or_else(|| Error::NotFound(format!("tenant {tenant_id}")))?;
    if matches!(status.as_str(), "ACTIVE" | "MAINTENANCE") {
        Ok(())
    } else {
        Err(Error::ExternalUnavailable(format!(
            "source intake tenant is not available ({status})"
        )))
    }
}

async fn lock_tenant_intake(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
) -> Result<()> {
    let lock_key = format!("source-intake:{tenant_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("lock tenant source intake", &error))?;
    Ok(())
}

async fn store_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    snapshot: &SourceSnapshot,
) -> Result<StoredSnapshot> {
    let tenant_id = snapshot.tenant_id.as_uuid();
    let source_system = source_system_db(snapshot.content.source);
    let normalized_content = serde_json::to_value(&snapshot.content)
        .map_err(|error| Error::Serialization(error.to_string()))?;

    let revision_digests = sqlx::query_scalar::<_, String>(
        r"
        SELECT content_digest
        FROM source_snapshots
        WHERE tenant_id = $1
          AND source_system = $2
          AND external_id = $3
          AND source_revision = $4
        ",
    )
    .bind(tenant_id)
    .bind(source_system)
    .bind(&snapshot.content.external_id)
    .bind(&snapshot.content.source_revision)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| database_error("check source snapshot revision", &error))?;
    if revision_digests
        .iter()
        .any(|digest| digest != &snapshot.content_digest)
    {
        return Err(Error::Conflict(format!(
            "source revision {} for {} {} already has different canonical content",
            snapshot.content.source_revision, source_system, snapshot.content.external_id
        )));
    }

    if let Some(row) = sqlx::query(
        r"
        SELECT id, tenant_id, repository_id, source_system, external_id,
               source_revision, normalized_content, content_digest,
               connector_identity, captured_at
        FROM source_snapshots
        WHERE id = $1
        ",
    )
    .bind(snapshot.id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("check source snapshot ID", &error))?
    {
        validate_stored_snapshot(
            &row,
            snapshot,
            source_system,
            &normalized_content,
            "snapshot ID",
        )?;
        let captured_at: chrono::DateTime<Utc> = row.try_get("captured_at").map_err(|error| {
            database_error("decode existing source snapshot capture time", &error)
        })?;
        return Ok(StoredSnapshot {
            id: snapshot.id.as_uuid(),
            captured_at,
            inserted: false,
        });
    }

    let inserted_row = sqlx::query(
        r"
        INSERT INTO source_snapshots (
            id, tenant_id, repository_id, source_system, external_id,
            source_revision, source_url, normalized_content, content_digest,
            connector_identity, captured_at, source_updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (
            tenant_id, source_system, external_id, source_revision, content_digest
        ) DO NOTHING
        RETURNING id, captured_at
        ",
    )
    .bind(snapshot.id.as_uuid())
    .bind(tenant_id)
    .bind(
        snapshot
            .repository_id
            .map(crate::domain::RepositoryId::as_uuid),
    )
    .bind(source_system)
    .bind(&snapshot.content.external_id)
    .bind(&snapshot.content.source_revision)
    .bind(snapshot.content.source_url.as_ref().map(url::Url::as_str))
    .bind(&normalized_content)
    .bind(&snapshot.content_digest)
    .bind(&snapshot.connector_identity)
    .bind(snapshot.captured_at)
    .bind(snapshot.content.source_updated_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("insert immutable source snapshot", &error))?;
    if let Some(row) = inserted_row {
        let id: Uuid = row
            .try_get("id")
            .map_err(|error| database_error("decode inserted source snapshot ID", &error))?;
        let captured_at: chrono::DateTime<Utc> = row.try_get("captured_at").map_err(|error| {
            database_error("decode inserted source snapshot capture time", &error)
        })?;
        return Ok(StoredSnapshot {
            id,
            captured_at,
            inserted: true,
        });
    }

    let row = sqlx::query(
        r"
        SELECT id, tenant_id, repository_id, source_system, external_id,
               source_revision, normalized_content, content_digest,
               connector_identity, captured_at
        FROM source_snapshots
        WHERE tenant_id = $1
          AND source_system = $2
          AND external_id = $3
          AND source_revision = $4
          AND content_digest = $5
        ",
    )
    .bind(tenant_id)
    .bind(source_system)
    .bind(&snapshot.content.external_id)
    .bind(&snapshot.content.source_revision)
    .bind(&snapshot.content_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("adopt immutable source snapshot", &error))?
    .ok_or_else(|| {
        Error::Conflict("source snapshot insert conflicted without identical semantics".into())
    })?;
    validate_stored_snapshot(
        &row,
        snapshot,
        source_system,
        &normalized_content,
        "semantic identity",
    )?;
    let id: Uuid = row
        .try_get("id")
        .map_err(|error| database_error("decode adopted source snapshot ID", &error))?;
    let captured_at: chrono::DateTime<Utc> = row
        .try_get("captured_at")
        .map_err(|error| database_error("decode adopted source snapshot capture time", &error))?;
    Ok(StoredSnapshot {
        id,
        captured_at,
        inserted: false,
    })
}

fn validate_stored_snapshot(
    row: &sqlx::postgres::PgRow,
    expected: &SourceSnapshot,
    source_system: &str,
    normalized_content: &Value,
    identity: &str,
) -> Result<()> {
    let stored_tenant: Uuid = row
        .try_get("tenant_id")
        .map_err(|error| database_error("decode stored snapshot tenant", &error))?;
    let stored_repository: Option<Uuid> = row
        .try_get("repository_id")
        .map_err(|error| database_error("decode stored snapshot repository", &error))?;
    let stored_source: String = row
        .try_get("source_system")
        .map_err(|error| database_error("decode stored snapshot source", &error))?;
    let stored_external: String = row
        .try_get("external_id")
        .map_err(|error| database_error("decode stored snapshot external ID", &error))?;
    let stored_revision: String = row
        .try_get("source_revision")
        .map_err(|error| database_error("decode stored snapshot revision", &error))?;
    let stored_content: Value = row
        .try_get("normalized_content")
        .map_err(|error| database_error("decode stored snapshot content", &error))?;
    let stored_digest: String = row
        .try_get("content_digest")
        .map_err(|error| database_error("decode stored snapshot digest", &error))?;
    let stored_connector: String = row
        .try_get("connector_identity")
        .map_err(|error| database_error("decode stored snapshot connector", &error))?;
    if stored_tenant != expected.tenant_id.as_uuid()
        || stored_repository
            != expected
                .repository_id
                .map(crate::domain::RepositoryId::as_uuid)
        || stored_source != source_system
        || stored_external != expected.content.external_id
        || stored_revision != expected.content.source_revision
        || stored_content != *normalized_content
        || stored_digest != expected.content_digest
        || stored_connector != expected.connector_identity
    {
        return Err(Error::Conflict(format!(
            "existing source snapshot {identity} has different semantics"
        )));
    }
    Ok(())
}

struct WorkItemRow {
    id: Uuid,
    source_snapshot_id: Uuid,
    current_snapshot_source: String,
    current_snapshot_external_id: String,
    current_snapshot_digest: String,
    state: String,
    aggregate_version: i64,
    accepted_at: Option<chrono::DateTime<Utc>>,
    current_attempt_id: Option<Uuid>,
    owner_fallback: Option<String>,
    policy_digest: Option<String>,
}

/// Converts a stored `bigint` aggregate version into the positive `u64` every caller of
/// this module's structured results expects, rejecting the zero/negative values the
/// `aggregate_version > 0` schema check should already have excluded.
fn positive_aggregate_version(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| {
            database_error(
                "decode source work aggregate version",
                &format!("expected a positive version, got {value}"),
            )
        })
}

/// Outcome of persisting one snapshot against its work item, matching the exact branches
/// the sync job has always taken (a later API intake pass reuses the same branches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntakeOutcome {
    /// A new external identity was inserted as a freshly discovered work item.
    Discovered,
    /// The candidate snapshot is already the work item's authoritative content, i.e. the
    /// candidate itself is authoritative/current (matches the stored snapshot or digest).
    Unchanged,
    /// Pre-acceptance content changed, so readiness was reset and the version bumped.
    ReadinessRequeued,
    /// Content changed for accepted (or otherwise non-requeueable) work and the candidate
    /// is not authoritative, so the existing authoritative snapshot is retained pending
    /// reevaluation. Covers both the reevaluation event being newly recorded (with its
    /// outbox/escalation/audit trail written) and it already having been recorded by a
    /// prior pass (no duplicate outbox/escalation/audit write, reevaluation still pending).
    AuthorityReevaluationRequired,
}

/// Structured result of persisting one snapshot, returned instead of exposing the raw
/// storage/work-item helpers to callers. The sync handler reads `outcome` and
/// `snapshot_inserted`; direct API intake maps the rest into `ApiIntakeReceipt`.
pub(crate) struct IntakeSnapshotResult {
    pub(crate) snapshot_id: Uuid,
    pub(crate) snapshot_inserted: bool,
    pub(crate) work_item_id: Uuid,
    pub(crate) work_item_state: WorkItemState,
    pub(crate) aggregate_version: u64,
    pub(crate) already_accepted: bool,
    pub(crate) content_digest: String,
    pub(crate) outcome: IntakeOutcome,
}

fn parse_work_item_state(state: &str) -> Result<WorkItemState> {
    serde_json::from_value(Value::String(state.to_owned()))
        .map_err(|error| database_error("decode source work item state", &error))
}

async fn apply_snapshot_to_work_item(
    transaction: &mut Transaction<'_, Postgres>,
    audit_chain: &mut AuditChainWriter,
    snapshot: &SourceSnapshot,
    stored: &StoredSnapshot,
    correlation_id: &str,
    provenance: &IntakeProvenance<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<IntakeSnapshotResult> {
    let stored_snapshot_id = stored.id;
    let tenant_id = snapshot.tenant_id.as_uuid();
    let source_system = source_system_db(snapshot.content.source);
    let existing_row = sqlx::query(
        r"
        SELECT work.id, work.source_snapshot_id, work.state, work.aggregate_version,
               work.accepted_at, work.current_attempt_id, work.owner_fallback,
               work.policy_digest,
               current_snapshot.source_system AS current_snapshot_source,
               current_snapshot.external_id AS current_snapshot_external_id,
               current_snapshot.content_digest AS current_snapshot_digest
        FROM work_items AS work
        JOIN source_snapshots AS current_snapshot
          ON current_snapshot.tenant_id = work.tenant_id
         AND current_snapshot.id = work.source_snapshot_id
        WHERE work.tenant_id = $1
          AND work.source_system = $2
          AND work.source_external_id = $3
        FOR UPDATE OF work
        ",
    )
    .bind(tenant_id)
    .bind(source_system)
    .bind(&snapshot.content.external_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("lock source work item", &error))?;
    let existing = existing_row.as_ref().map(work_item_from_row).transpose()?;

    let Some(work) = existing else {
        let work_item_id = WorkItemId::new().as_uuid();
        let aggregate_version = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, repository_id, state, normalized_priority,
                discovered_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, 'DISCOVERED', $7, $8, $8)
            RETURNING aggregate_version
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(stored_snapshot_id)
        .bind(source_system)
        .bind(&snapshot.content.external_id)
        .bind(
            snapshot
                .repository_id
                .map(crate::domain::RepositoryId::as_uuid),
        )
        .bind(i16::from(snapshot.content.normalized_priority))
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| database_error("discover source work item", &error))?;
        let aggregate_version = positive_aggregate_version(aggregate_version)?;
        let payload = source_event_payload(
            "discovered",
            snapshot,
            work_item_id,
            stored_snapshot_id,
            None,
            aggregate_version,
            stored.captured_at,
            None,
        );
        insert_outbox_exact(
            transaction,
            work_item_id,
            "WORK_ITEM_DISCOVERED",
            &payload,
            &format!(
                "source-intake:discovered:{work_item_id}:{}",
                snapshot.content_digest
            ),
            provenance,
            correlation_id,
        )
        .await?;
        audit_chain
            .append(
                transaction,
                AuditFact {
                    work_item_id,
                    action: "SOURCE_WORK_ITEM_DISCOVERED",
                    correlation_id,
                    before_digest: None,
                    after_digest: Some(&snapshot.content_digest),
                    details: &payload,
                    policy_digest: None,
                },
                provenance,
                now,
            )
            .await?;
        return Ok(IntakeSnapshotResult {
            snapshot_id: stored_snapshot_id,
            snapshot_inserted: stored.inserted,
            work_item_id,
            work_item_state: WorkItemState::Discovered,
            aggregate_version,
            already_accepted: false,
            content_digest: snapshot.content_digest.clone(),
            outcome: IntakeOutcome::Discovered,
        });
    };

    if work.current_snapshot_source != source_system
        || work.current_snapshot_external_id != snapshot.content.external_id
    {
        return Err(Error::Conflict(format!(
            "work item {} points at a source snapshot with a different external identity",
            work.id
        )));
    }

    if work.source_snapshot_id == stored_snapshot_id
        || work.current_snapshot_digest == snapshot.content_digest
    {
        return Ok(IntakeSnapshotResult {
            snapshot_id: stored_snapshot_id,
            snapshot_inserted: stored.inserted,
            work_item_id: work.id,
            work_item_state: parse_work_item_state(&work.state)?,
            aggregate_version: positive_aggregate_version(work.aggregate_version)?,
            already_accepted: work.accepted_at.is_some(),
            content_digest: snapshot.content_digest.clone(),
            outcome: IntakeOutcome::Unchanged,
        });
    }

    if work.accepted_at.is_none() && readiness_can_be_requeued(&work.state) {
        let updated = sqlx::query_scalar::<_, i64>(
            r"
            UPDATE work_items
            SET source_snapshot_id = $3,
                repository_id = $4,
                state = 'READINESS_PENDING',
                closure_target = NULL,
                risk_class = NULL,
                risk_assessment = NULL,
                policy_digest = NULL,
                budget_limits = NULL,
                identity_requirements = NULL,
                owner_fallback = NULL,
                due_at = NULL,
                normalized_priority = $5,
                ready_at = NULL,
                aggregate_version = aggregate_version + 1,
                updated_at = $6
            WHERE tenant_id = $1 AND id = $2
            RETURNING aggregate_version
            ",
        )
        .bind(tenant_id)
        .bind(work.id)
        .bind(stored_snapshot_id)
        .bind(
            snapshot
                .repository_id
                .map(crate::domain::RepositoryId::as_uuid),
        )
        .bind(i16::from(snapshot.content.normalized_priority))
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| database_error("requeue source work readiness", &error))?;
        let Some(aggregate_version) = updated else {
            return Err(Error::Conflict(format!(
                "source work item {} disappeared while locked",
                work.id
            )));
        };
        let aggregate_version = positive_aggregate_version(aggregate_version)?;
        let payload = source_event_payload(
            "readiness_requeued",
            snapshot,
            work.id,
            stored_snapshot_id,
            Some(work.source_snapshot_id),
            aggregate_version,
            stored.captured_at,
            None,
        );
        insert_outbox_exact(
            transaction,
            work.id,
            "WORK_ITEM_READINESS_REEVALUATION_REQUESTED",
            &payload,
            &format!(
                "source-intake:readiness:{work_item}:{}",
                snapshot.content_digest,
                work_item = work.id
            ),
            provenance,
            correlation_id,
        )
        .await?;
        audit_chain
            .append(
                transaction,
                AuditFact {
                    work_item_id: work.id,
                    action: "SOURCE_READINESS_REEVALUATION_REQUESTED",
                    correlation_id,
                    before_digest: Some(&work.current_snapshot_digest),
                    after_digest: Some(&snapshot.content_digest),
                    details: &payload,
                    policy_digest: None,
                },
                provenance,
                now,
            )
            .await?;
        return Ok(IntakeSnapshotResult {
            snapshot_id: stored_snapshot_id,
            snapshot_inserted: stored.inserted,
            work_item_id: work.id,
            work_item_state: WorkItemState::ReadinessPending,
            aggregate_version,
            already_accepted: false,
            content_digest: snapshot.content_digest.clone(),
            outcome: IntakeOutcome::ReadinessRequeued,
        });
    }

    // Authority reevaluation never bumps the work item's version; it only records that the
    // candidate is not authoritative, so the event's aggregate_version is the current,
    // unchanged version.
    let aggregate_version = positive_aggregate_version(work.aggregate_version)?;
    let payload = source_event_payload(
        "authority_reevaluation_required",
        snapshot,
        work.id,
        stored_snapshot_id,
        Some(work.source_snapshot_id),
        aggregate_version,
        stored.captured_at,
        work.policy_digest.as_deref(),
    );
    let outbox_inserted = insert_outbox_exact(
        transaction,
        work.id,
        "WORK_ITEM_SOURCE_REEVALUATION_REQUIRED",
        &payload,
        &format!(
            "source-intake:authority-reevaluation:{work_item}:{}",
            snapshot.content_digest,
            work_item = work.id
        ),
        provenance,
        correlation_id,
    )
    .await?;
    if !outbox_inserted {
        return Ok(IntakeSnapshotResult {
            snapshot_id: stored_snapshot_id,
            snapshot_inserted: stored.inserted,
            work_item_id: work.id,
            work_item_state: parse_work_item_state(&work.state)?,
            aggregate_version,
            already_accepted: work.accepted_at.is_some(),
            content_digest: snapshot.content_digest.clone(),
            outcome: IntakeOutcome::AuthorityReevaluationRequired,
        });
    }

    if work.accepted_at.is_some() {
        insert_dispatch_fence(
            transaction,
            snapshot.tenant_id,
            work.id,
            stored_snapshot_id,
            &snapshot.content_digest,
            work.source_snapshot_id,
            &work.current_snapshot_digest,
        )
        .await?;
        insert_owned_source_escalation(transaction, snapshot, &work, stored_snapshot_id, now)
            .await?;
    }
    audit_chain
        .append(
            transaction,
            AuditFact {
                work_item_id: work.id,
                action: "SOURCE_AUTHORITY_REEVALUATION_REQUIRED",
                correlation_id,
                before_digest: Some(&work.current_snapshot_digest),
                after_digest: Some(&snapshot.content_digest),
                details: &payload,
                policy_digest: work.policy_digest.as_deref(),
            },
            provenance,
            now,
        )
        .await?;
    Ok(IntakeSnapshotResult {
        snapshot_id: stored_snapshot_id,
        snapshot_inserted: stored.inserted,
        work_item_id: work.id,
        work_item_state: parse_work_item_state(&work.state)?,
        aggregate_version,
        already_accepted: work.accepted_at.is_some(),
        content_digest: snapshot.content_digest.clone(),
        outcome: IntakeOutcome::AuthorityReevaluationRequired,
    })
}

fn work_item_from_row(row: &sqlx::postgres::PgRow) -> Result<WorkItemRow> {
    Ok(WorkItemRow {
        id: row
            .try_get("id")
            .map_err(|error| database_error("decode source work item ID", &error))?,
        source_snapshot_id: row
            .try_get("source_snapshot_id")
            .map_err(|error| database_error("decode current source snapshot ID", &error))?,
        current_snapshot_source: row
            .try_get("current_snapshot_source")
            .map_err(|error| database_error("decode current source snapshot system", &error))?,
        current_snapshot_external_id: row
            .try_get("current_snapshot_external_id")
            .map_err(|error| database_error("decode current source external ID", &error))?,
        current_snapshot_digest: row
            .try_get("current_snapshot_digest")
            .map_err(|error| database_error("decode current source snapshot digest", &error))?,
        state: row
            .try_get("state")
            .map_err(|error| database_error("decode source work item state", &error))?,
        aggregate_version: row
            .try_get("aggregate_version")
            .map_err(|error| database_error("decode source work item aggregate version", &error))?,
        accepted_at: row
            .try_get("accepted_at")
            .map_err(|error| database_error("decode source work acceptance", &error))?,
        current_attempt_id: row
            .try_get("current_attempt_id")
            .map_err(|error| database_error("decode source work attempt", &error))?,
        owner_fallback: row
            .try_get("owner_fallback")
            .map_err(|error| database_error("decode source work owner", &error))?,
        policy_digest: row
            .try_get("policy_digest")
            .map_err(|error| database_error("decode source work policy digest", &error))?,
    })
}

fn readiness_can_be_requeued(state: &str) -> bool {
    matches!(
        state,
        "DISCOVERED" | "READINESS_PENDING" | "NEEDS_SPEC" | "READY" | "WAITING_DEPENDENCY"
    )
}

/// Builds the durable, stable-shape payload for a source-intake outbox event. `aggregate_version`
/// is the work item's version after this event's effect (the post-discovery/requeue version, or
/// the unchanged current version when an authority-reevaluation event does not itself bump the
/// version). `occurred_at` is the candidate snapshot's persisted `source_snapshots.captured_at`,
/// never the current call's retry time. `policy_digest` is `None` for discovery/requeue and the
/// retained work policy digest where applicable for an accepted/non-requeueable authority
/// reevaluation.
fn source_event_payload(
    event: &str,
    snapshot: &SourceSnapshot,
    work_item_id: Uuid,
    snapshot_id: Uuid,
    retained_snapshot_id: Option<Uuid>,
    aggregate_version: u64,
    occurred_at: chrono::DateTime<Utc>,
    policy_digest: Option<&str>,
) -> Value {
    json!({
        "schema": SOURCE_EVENT_SCHEMA_V1,
        "event": event,
        "tenant_id": snapshot.tenant_id,
        "work_item_id": work_item_id,
        "aggregate_version": aggregate_version,
        "source_system": source_system_db(snapshot.content.source),
        "source_external_id": snapshot.content.external_id,
        "source_snapshot_id": snapshot_id,
        "source_revision": snapshot.content.source_revision,
        "content_digest": snapshot.content_digest,
        "retained_authority_snapshot_id": retained_snapshot_id,
        "occurred_at": occurred_at,
        "policy_digest": policy_digest,
    })
}

/// Builds the initial headers for a source-intake outbox event: a versioned envelope schema plus
/// the first-writer provenance (`actor_type`/`actor_id` from `provenance`, `correlation_id`), a
/// null `trace_id`, and `policy_digest` mirrored from the semantic payload so a later reader can
/// validate the two agree without decoding the payload twice.
fn source_event_headers(
    provenance: &IntakeProvenance<'_>,
    correlation_id: &str,
    policy_digest: Option<&str>,
) -> Value {
    json!({
        "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
        "actor_type": provenance.actor_type(),
        "actor_id": provenance.actor_id(),
        "correlation_id": correlation_id,
        "trace_id": Value::Null,
        "policy_digest": policy_digest,
    })
}

/// The exact, fixed set of keys a source-event header envelope must carry — no more, no
/// fewer. An extra key (e.g. a smuggled credential field) fails closed just like a missing
/// or malformed one.
const SOURCE_EVENT_HEADER_KEYS: [&str; 6] = [
    "schema",
    "actor_type",
    "actor_id",
    "correlation_id",
    "trace_id",
    "policy_digest",
];

/// Validates that `headers` is a well-formed, first-writer source-event envelope for
/// `payload`: exactly the six recognized keys (no extras), the exact versioned schema,
/// nonblank `actor_type`/`actor_id`/`correlation_id` fields with `actor_type` one of the two
/// recognized values, a `trace_id` that is exactly `null`, and a `policy_digest` identical to
/// the one already validated as part of `payload`. This never compares `headers` against the
/// currently attempted provenance: a prior writer's headers are adopted as-is once they pass
/// this shape check.
fn validate_stored_source_event_headers(headers: &Value, payload: &Value) -> Result<()> {
    let well_formed = headers.as_object().is_some_and(|object| {
        object.len() == SOURCE_EVENT_HEADER_KEYS.len()
            && SOURCE_EVENT_HEADER_KEYS
                .iter()
                .all(|key| object.contains_key(*key))
            && object.get("schema").and_then(Value::as_str) == Some(SOURCE_EVENT_HEADERS_SCHEMA_V1)
            && matches!(
                object.get("actor_type").and_then(Value::as_str),
                Some("SYSTEM" | "API_CALLER")
            )
            && object
                .get("actor_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            && object
                .get("correlation_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            && matches!(object.get("trace_id"), Some(Value::Null))
            && object.get("policy_digest") == payload.get("policy_digest")
    });
    if well_formed && reject_sensitive_fields(headers).is_ok() {
        Ok(())
    } else {
        Err(Error::Conflict(
            "source intake outbox idempotency key has a malformed stored source-event envelope"
                .into(),
        ))
    }
}

/// Inserts one exactly-once outbox row for a source-intake event, stamping it with the
/// first-writer's provenance headers (built from `provenance`/`correlation_id` via
/// [`source_event_headers`]). On a semantic-idempotency conflict, the stored row's topic,
/// message key, event type, and payload must be exactly identical, and its stored headers
/// must be a well-formed source-event envelope (see [`validate_stored_source_event_headers`]);
/// the current caller's provenance is never compared against the adopted headers, and the
/// existing row is never mutated.
async fn insert_outbox_exact(
    transaction: &mut Transaction<'_, Postgres>,
    work_item_id: Uuid,
    event_type: &str,
    payload: &Value,
    idempotency_key: &str,
    provenance: &IntakeProvenance<'_>,
    correlation_id: &str,
) -> Result<bool> {
    reject_sensitive_fields(payload)?;
    let tenant_id: Uuid = serde_json::from_value(payload["tenant_id"].clone())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    let policy_digest = payload.get("policy_digest").and_then(Value::as_str);
    let headers = source_event_headers(provenance, correlation_id, policy_digest);
    reject_sensitive_fields(&headers)?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload,
            headers, idempotency_key
        ) VALUES ($1, $2, 'work-items', $3, $4, $5, $6, $7)
        ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        RETURNING id
        ",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(work_item_id.to_string())
    .bind(event_type)
    .bind(payload)
    .bind(&headers)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("insert source intake outbox event", &error))?;
    if inserted.is_some() {
        return Ok(true);
    }

    let row = sqlx::query(
        r"
        SELECT topic, message_key, event_type, payload, headers
        FROM outbox
        WHERE tenant_id = $1 AND idempotency_key = $2
        ",
    )
    .bind(tenant_id)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("adopt source intake outbox event", &error))?
    .ok_or_else(|| Error::Conflict("source intake outbox conflict has no adoptable row".into()))?;
    let topic: String = row
        .try_get("topic")
        .map_err(|error| database_error("decode source outbox topic", &error))?;
    let message_key: String = row
        .try_get("message_key")
        .map_err(|error| database_error("decode source outbox key", &error))?;
    let stored_event_type: String = row
        .try_get("event_type")
        .map_err(|error| database_error("decode source outbox event type", &error))?;
    let stored_payload: Value = row
        .try_get("payload")
        .map_err(|error| database_error("decode source outbox payload", &error))?;
    let stored_headers: Value = row
        .try_get("headers")
        .map_err(|error| database_error("decode source outbox headers", &error))?;
    if topic != "work-items"
        || message_key != work_item_id.to_string()
        || stored_event_type != event_type
        || stored_payload != *payload
    {
        return Err(Error::Conflict(
            "source intake outbox idempotency key has different semantics".into(),
        ));
    }
    validate_stored_source_event_headers(&stored_headers, &stored_payload)?;
    Ok(false)
}

async fn insert_dispatch_fence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    work_item_id: Uuid,
    candidate_snapshot_id: Uuid,
    candidate_snapshot_digest: &str,
    authoritative_snapshot_id: Uuid,
    authoritative_snapshot_digest: &str,
) -> Result<()> {
    let inserted = sqlx::query_scalar::<_, String>(
        r"
        INSERT INTO work_item_dispatch_fences (
            tenant_id, work_item_id, generation, paused,
            candidate_snapshot_id, candidate_snapshot_digest,
            authoritative_snapshot_id, authoritative_snapshot_digest,
            reason, opened_at, created_at, updated_at
        ) VALUES ($1, $2, 1, true, $3, $4, $5, $6, 'SOURCE_CHANGED_AFTER_ACCEPTANCE',
                  CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (tenant_id, work_item_id) DO NOTHING
        RETURNING candidate_snapshot_digest
        ",
    )
    .bind(tenant_id.as_uuid())
    .bind(work_item_id)
    .bind(candidate_snapshot_id)
    .bind(candidate_snapshot_digest)
    .bind(authoritative_snapshot_id)
    .bind(authoritative_snapshot_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("insert dispatch fence", &error))?;

    if inserted.is_some() {
        return Ok(());
    }

    let stored_digest = sqlx::query_scalar::<_, String>(
        r"
        SELECT candidate_snapshot_digest
        FROM work_item_dispatch_fences
        WHERE tenant_id = $1 AND work_item_id = $2
        ",
    )
    .bind(tenant_id.as_uuid())
    .bind(work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_error("check dispatch fence", &error))?;

    if let Some(digest) = stored_digest
        && digest != candidate_snapshot_digest
    {
        return Err(Error::Conflict(
            "dispatch fence exists with a different candidate snapshot digest".into(),
        ));
    }

    Ok(())
}

async fn insert_owned_source_escalation(
    transaction: &mut Transaction<'_, Postgres>,
    snapshot: &SourceSnapshot,
    work: &WorkItemRow,
    candidate_snapshot_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let owner = work.owner_fallback.as_deref().ok_or_else(|| {
        Error::Conflict(format!(
            "accepted work item {} has no owner for source re-evaluation",
            work.id
        ))
    })?;
    let deadline = now + Duration::hours(REEVALUATION_DEADLINE_HOURS);
    let evidence_references = json!([
        format!("source-snapshot:{candidate_snapshot_id}"),
        format!("content-digest:{}", snapshot.content_digest),
        format!(
            "retained-authority-source-snapshot:{}",
            work.source_snapshot_id
        ),
    ]);
    let retry_policy = json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 300,
        "prerequisites": ["operator source-authority re-evaluation"],
    });
    reject_sensitive_fields(&evidence_references)?;
    reject_sensitive_fields(&retry_policy)?;
    sqlx::query(
        r"
        INSERT INTO escalations (
            id, tenant_id, work_item_id, attempt_id, category, status,
            severity, reason, owner_type, owner_id, required_action,
            evidence_references, deadline, retry_policy,
            authority_or_effect_active, idempotency_key, opened_at
        ) VALUES (
            $1, $2, $3, $4, 'BLOCKED_EXTERNAL', 'OPEN', 'HIGH',
            'The opted-in source changed after work acceptance',
            'TEAM', $5,
            'Re-evaluate the retained Work Order authority against the candidate source snapshot',
            $6, $7, $8, $9, $10, $11
        )
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(Uuid::now_v7())
    .bind(snapshot.tenant_id.as_uuid())
    .bind(work.id)
    .bind(work.current_attempt_id)
    .bind(owner)
    .bind(evidence_references)
    .bind(deadline)
    .bind(retry_policy)
    .bind(!matches!(work.state.as_str(), "CLOSED" | "CANCELLED"))
    .bind(format!(
        "source-intake:escalation:{}:{}",
        work.id, snapshot.content_digest
    ))
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_error("insert owned source-change escalation", &error))?;
    Ok(())
}

struct AuditChainWriter {
    tenant_id: TenantId,
    previous_event_hash: Option<String>,
}

impl AuditChainWriter {
    async fn lock(
        transaction: &mut Transaction<'_, Postgres>,
        tenant_id: TenantId,
    ) -> Result<Self> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
            .bind(tenant_id.as_uuid())
            .execute(&mut **transaction)
            .await
            .map_err(|error| database_error("lock tenant audit chain", &error))?;
        let heads = sqlx::query_scalar::<_, String>(
            r"
            SELECT candidate.event_hash
            FROM audit_events AS candidate
            WHERE candidate.tenant_id = $1
              AND NOT EXISTS (
                  SELECT 1
                  FROM audit_events AS child
                  WHERE child.tenant_id = candidate.tenant_id
                    AND child.previous_event_hash = candidate.event_hash
              )
            ORDER BY candidate.ingested_at DESC, candidate.id DESC
            LIMIT 2
            ",
        )
        .bind(tenant_id.as_uuid())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| database_error("load tenant audit-chain head", &error))?;
        if heads.len() > 1 {
            return Err(Error::Persistence(
                "tenant audit ledger contains multiple chain heads".into(),
            ));
        }
        Ok(Self {
            tenant_id,
            previous_event_hash: heads.into_iter().next(),
        })
    }

    async fn append(
        &mut self,
        transaction: &mut Transaction<'_, Postgres>,
        fact: AuditFact<'_>,
        provenance: &IntakeProvenance<'_>,
        occurred_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        reject_sensitive_fields(fact.details)?;
        let event = HashedAuditEvent::create(AuditEventContent {
            id: EventId::new(),
            tenant_id: self.tenant_id,
            work_item_id: Some(WorkItemId::from_uuid(fact.work_item_id)),
            attempt_id: None,
            actor_type: provenance.actor_type().into(),
            actor_id: provenance.actor_id().into(),
            action: fact.action.into(),
            subject_type: "WORK_ITEM".into(),
            subject_id: fact.work_item_id.to_string(),
            correlation_id: fact.correlation_id.into(),
            trace_id: None,
            policy_digest: fact.policy_digest.map(str::to_owned),
            before_digest: fact.before_digest.map(str::to_owned),
            after_digest: fact.after_digest.map(str::to_owned),
            previous_event_hash: self.previous_event_hash.clone(),
            details: fact.details.clone(),
            occurred_at,
        })?;
        sqlx::query(
            r"
            INSERT INTO audit_events (
                id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
                action, subject_type, subject_id, correlation_id, trace_id,
                policy_digest, before_digest, after_digest, previous_event_hash,
                event_hash, details, occurred_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17, $18
            )
            ",
        )
        .bind(event.content.id.as_uuid())
        .bind(event.content.tenant_id.as_uuid())
        .bind(event.content.work_item_id.map(WorkItemId::as_uuid))
        .bind(
            event
                .content
                .attempt_id
                .map(crate::domain::AttemptId::as_uuid),
        )
        .bind(&event.content.actor_type)
        .bind(&event.content.actor_id)
        .bind(&event.content.action)
        .bind(&event.content.subject_type)
        .bind(&event.content.subject_id)
        .bind(&event.content.correlation_id)
        .bind(&event.content.trace_id)
        .bind(&event.content.policy_digest)
        .bind(&event.content.before_digest)
        .bind(&event.content.after_digest)
        .bind(&event.content.previous_event_hash)
        .bind(&event.event_hash)
        .bind(&event.content.details)
        .bind(event.content.occurred_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("append source intake audit event", &error))?;
        self.previous_event_hash = Some(event.event_hash);
        Ok(())
    }
}

struct AuditFact<'a> {
    work_item_id: Uuid,
    action: &'a str,
    correlation_id: &'a str,
    before_digest: Option<&'a str>,
    after_digest: Option<&'a str>,
    details: &'a Value,
    policy_digest: Option<&'a str>,
}

/// The fixed set of system identities allowed to author an intake audit event. This is
/// intentionally not a free-form string: only the sync job's identity exists today, and a
/// later API intake pass adds its own dedicated variant rather than an arbitrary string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemIntakeActor {
    IntakeSync,
}

impl SystemIntakeActor {
    const fn actor_id(self) -> &'static str {
        match self {
            Self::IntakeSync => "runtime:intake-sync",
        }
    }
}

/// The only two ways an intake write may be attributed: a typed system identity, or an
/// authenticated API caller. Nothing else can construct an `actor_type`/`actor_id` pair.
/// `System` is used by the sync handler; `ApiCaller` is used by direct API intake.
pub(crate) enum IntakeProvenance<'a> {
    System(SystemIntakeActor),
    ApiCaller(&'a Caller),
}

impl IntakeProvenance<'_> {
    const fn actor_type(&self) -> &'static str {
        match self {
            Self::System(_) => "SYSTEM",
            Self::ApiCaller(_) => "API_CALLER",
        }
    }

    fn actor_id(&self) -> &str {
        match self {
            Self::System(actor) => actor.actor_id(),
            Self::ApiCaller(caller) => caller.subject.as_str(),
        }
    }
}

/// Narrow, transaction-scoped writer for source-intake persistence. Holds a mutable borrow
/// of the exact `Transaction` that acquired the source-intake and audit-chain advisory locks,
/// so the writer is statically tied to that transaction: it cannot be used against, or
/// outlive, any other transaction, and every snapshot persisted through it shares the one
/// advisory-lock acquisition and one audit-hash chain without exposing the underlying
/// storage/audit primitives to callers.
pub(crate) struct IntakeTransactionWriter<'a, 'c> {
    transaction: &'a mut Transaction<'c, Postgres>,
    tenant_id: TenantId,
    audit_chain: AuditChainWriter,
}

impl<'a, 'c> IntakeTransactionWriter<'a, 'c> {
    /// Takes the source-intake advisory lock, then the audit-chain advisory lock, in that
    /// order, on `transaction`, loads the current audit-chain head for `tenant_id`, and holds
    /// `transaction` for the writer's lifetime so it can only ever write through the
    /// transaction that acquired those locks.
    pub(crate) async fn lock(
        transaction: &'a mut Transaction<'c, Postgres>,
        tenant_id: TenantId,
    ) -> Result<Self> {
        lock_tenant_intake(transaction, tenant_id).await?;
        let audit_chain = AuditChainWriter::lock(transaction, tenant_id).await?;
        Ok(Self {
            transaction,
            tenant_id,
            audit_chain,
        })
    }

    /// Stores the snapshot (inserting or adopting it) and applies it to its work item,
    /// appending exactly one audit event under the writer's locked chain when the snapshot
    /// changes anything. Writes always go through the transaction the writer locked; there is
    /// no way to pass a different one in.
    pub(crate) async fn persist_snapshot(
        &mut self,
        snapshot: &SourceSnapshot,
        correlation_id: &str,
        provenance: IntakeProvenance<'_>,
        now: chrono::DateTime<Utc>,
    ) -> Result<IntakeSnapshotResult> {
        if snapshot.tenant_id != self.tenant_id {
            return Err(Error::Validation(
                "source snapshot crosses the locked intake-writer tenant boundary".into(),
            ));
        }
        let stored = store_snapshot(self.transaction, snapshot).await?;
        apply_snapshot_to_work_item(
            self.transaction,
            &mut self.audit_chain,
            snapshot,
            &stored,
            correlation_id,
            &provenance,
            now,
        )
        .await
    }
}

const fn source_system_db(source: SourceSystem) -> &'static str {
    match source {
        SourceSystem::Linear => "LINEAR",
        SourceSystem::Api => "API",
        SourceSystem::Github => "GITHUB",
    }
}

fn database_error(context: &str, error: &impl fmt::Display) -> Error {
    Error::Persistence(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};

    use chrono::TimeDelta;
    use tokio::sync::Mutex;
    use url::Url;

    use super::*;
    use crate::{
        adapters::InMemoryLinearGateway,
        domain::{RepositoryId, SourceSnapshotContent},
        ports::{
            CloseSourceRequest, ObserveSourceRequest, ReconcileSourceCloseRequest,
            SourceCloseReceipt, SourceCloseReconciliation, SourceIntakePage, SourceObservation,
            SourceResult,
        },
    };

    fn snapshot(
        tenant_id: TenantId,
        repository_id: Option<RepositoryId>,
        external_id: &str,
        revision: &str,
        objective: &str,
    ) -> SourceSnapshot {
        let now = Utc::now();
        SourceSnapshot::create(
            tenant_id,
            repository_id,
            SourceSnapshotContent {
                source: SourceSystem::Linear,
                external_id: external_id.into(),
                source_revision: revision.into(),
                source_url: Some(
                    Url::parse(&format!("https://linear.example/{external_id}"))
                        .expect("valid test URL"),
                ),
                title: format!("Work {external_id}"),
                objective: objective.into(),
                acceptance_criteria: vec!["the requested change is verified".into()],
                non_goals: Vec::new(),
                labels: BTreeSet::from(["asf-ready".into()]),
                normalized_priority: 70,
                source_state: "started".into(),
                assignee: Some("team:source".into()),
                repository_hint: Some("acme/widget".into()),
                source_updated_at: now,
            },
            "linear:test-connector".into(),
            now,
        )
        .expect("valid test source snapshot")
    }

    #[derive(Debug)]
    struct ScriptedGateway {
        responses: Mutex<VecDeque<SourceResult<SourceIntakePage>>>,
    }

    impl ScriptedGateway {
        fn new(responses: Vec<SourceResult<SourceIntakePage>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
            }
        }
    }

    #[async_trait]
    impl SourceGateway for ScriptedGateway {
        async fn intake(&self, _request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage> {
            self.responses
                .lock()
                .await
                .pop_front()
                .unwrap_or(Err(SourceGatewayError::InvalidProviderResponse))
        }

        async fn observe_source(
            &self,
            _request: &ObserveSourceRequest,
        ) -> SourceResult<SourceObservation> {
            Err(SourceGatewayError::UnsupportedContract {
                detail: "not used by intake tests".into(),
            })
        }

        async fn close_source(
            &self,
            _request: &CloseSourceRequest,
        ) -> SourceResult<SourceCloseReceipt> {
            Err(SourceGatewayError::UnsupportedContract {
                detail: "not used by intake tests".into(),
            })
        }

        async fn reconcile_source_close(
            &self,
            _request: &ReconcileSourceCloseRequest,
        ) -> SourceResult<SourceCloseReconciliation> {
            Err(SourceGatewayError::UnsupportedContract {
                detail: "not used by intake tests".into(),
            })
        }
    }

    #[tokio::test]
    async fn collects_every_page_and_deduplicates_only_identical_snapshots() {
        let tenant_id = TenantId::new();
        let gateway = InMemoryLinearGateway::new();
        for external_id in ["ASF-1", "ASF-2", "ASF-3"] {
            gateway
                .upsert_snapshot(snapshot(
                    tenant_id,
                    None,
                    external_id,
                    "revision-1",
                    "bounded objective",
                ))
                .await
                .expect("seed source fake");
        }
        let collected = collect_source_snapshots(&gateway, tenant_id, "asf-ready", 1)
            .await
            .expect("collect all source pages");
        assert_eq!(collected.pages_fetched, 3);
        assert_eq!(collected.snapshots.len(), 3);

        let duplicate = snapshot(
            tenant_id,
            None,
            "ASF-duplicate",
            "revision-1",
            "same objective",
        );
        let scripted = ScriptedGateway::new(vec![Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots: vec![duplicate.clone(), duplicate],
            next_cursor: None,
            has_more: false,
        })]);
        let collected = collect_source_snapshots(&scripted, tenant_id, "asf-ready", 2)
            .await
            .expect("identical duplicate is idempotent");
        assert_eq!(collected.snapshots.len(), 1);
    }

    #[tokio::test]
    async fn rejects_cursor_loops_conflicts_and_cross_tenant_snapshots() {
        let tenant_id = TenantId::new();
        let repeated = SourceCursor::from_opaque("cursor:repeated").expect("valid cursor");
        let looped = ScriptedGateway::new(vec![
            Ok(SourceIntakePage {
                schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
                snapshots: vec![snapshot(tenant_id, None, "ASF-1", "1", "first")],
                next_cursor: Some(repeated.clone()),
                has_more: true,
            }),
            Ok(SourceIntakePage {
                schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
                snapshots: vec![snapshot(tenant_id, None, "ASF-2", "1", "second")],
                next_cursor: Some(repeated),
                has_more: true,
            }),
        ]);
        assert!(matches!(
            collect_source_snapshots(&looped, tenant_id, "asf-ready", 1).await,
            Err(Error::Validation(detail)) if detail.contains("repeated")
        ));

        let first = snapshot(tenant_id, None, "ASF-conflict", "1", "first");
        let second = snapshot(tenant_id, None, "ASF-conflict", "2", "second");
        let conflicting = ScriptedGateway::new(vec![Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots: vec![first, second],
            next_cursor: None,
            has_more: false,
        })]);
        assert!(matches!(
            collect_source_snapshots(&conflicting, tenant_id, "asf-ready", 2).await,
            Err(Error::Conflict(detail)) if detail.contains("conflicting snapshots")
        ));

        let other_tenant = ScriptedGateway::new(vec![Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots: vec![snapshot(TenantId::new(), None, "ASF-other", "1", "other")],
            next_cursor: None,
            has_more: false,
        })]);
        assert!(matches!(
            collect_source_snapshots(&other_tenant, tenant_id, "asf-ready", 1).await,
            Err(Error::Validation(detail)) if detail.contains("another tenant")
        ));
    }

    #[tokio::test]
    async fn temporary_provider_failure_remains_retryable() {
        let gateway = ScriptedGateway::new(vec![Err(SourceGatewayError::TransportUnavailable)]);
        assert!(matches!(
            collect_source_snapshots(&gateway, TenantId::new(), "asf-ready", 10).await,
            Err(Error::ExternalUnavailable(detail)) if detail.contains("transport")
        ));
    }

    fn claimed_job(tenant_id: TenantId, id: Uuid) -> ClaimedWorkflowJob {
        let now = Utc::now();
        ClaimedWorkflowJob {
            id,
            tenant_id: tenant_id.as_uuid(),
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: INTAKE_SYNC.into(),
            activity_contract_id: INTAKE_SYNC_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"tenant_id": tenant_id, "action": "sync"}),
            idempotency_key: format!("intake:{id}"),
            priority: 0,
            attempt_count: 1,
            max_attempts: 25,
            fence_token: 1,
            lease_owner: "intake-test".into(),
            lease_expires_at: now + TimeDelta::minutes(1),
            created_at: now,
        }
    }

    #[test]
    fn payload_validation_is_exact_and_tenant_fenced() {
        let tenant_id = TenantId::new();
        let id = Uuid::now_v7();
        let valid = claimed_job(tenant_id, id);
        validate_job(&valid, tenant_id).expect("valid API intake payload");

        let mut unknown = valid.clone();
        unknown.payload["surprise"] = json!(true);
        assert!(validate_job(&unknown, tenant_id).is_err());

        let mut crossed = valid.clone();
        crossed.payload["tenant_id"] = json!(TenantId::new());
        assert!(validate_job(&crossed, tenant_id).is_err());

        let mut wrong_job_type = valid.clone();
        wrong_job_type.job_type = "SOME_OTHER_JOB".into();
        assert!(validate_job(&wrong_job_type, tenant_id).is_err());

        let mut wrong_contract = valid;
        wrong_contract.activity_contract_id = "asf.activity/intake-sync/v2".into();
        assert!(matches!(
            validate_job(&wrong_contract, tenant_id),
            Err(Error::Validation(detail)) if detail.contains("activity contract")
        ));
    }

    #[derive(Debug, Default)]
    struct PanicIfCalledGateway;

    #[async_trait]
    impl SourceGateway for PanicIfCalledGateway {
        async fn intake(&self, _request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage> {
            panic!("source gateway must not be called for a wrong-contract claimed job")
        }

        async fn observe_source(
            &self,
            _request: &ObserveSourceRequest,
        ) -> SourceResult<SourceObservation> {
            panic!("source gateway must not be called for a wrong-contract claimed job")
        }

        async fn close_source(
            &self,
            _request: &CloseSourceRequest,
        ) -> SourceResult<SourceCloseReceipt> {
            panic!("source gateway must not be called for a wrong-contract claimed job")
        }

        async fn reconcile_source_close(
            &self,
            _request: &ReconcileSourceCloseRequest,
        ) -> SourceResult<SourceCloseReconciliation> {
            panic!("source gateway must not be called for a wrong-contract claimed job")
        }
    }

    #[tokio::test]
    async fn wrong_contract_claimed_job_is_rejected_before_the_source_gateway_is_ever_called() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect intake wrong-contract test ledger");
        let tenant_id = TenantId::new();
        let handler = IntakeSyncHandler::new(
            ledger.clone(),
            tenant_id,
            Arc::new(PanicIfCalledGateway),
            "asf-ready",
            1,
        )
        .expect("construct intake handler");
        let mut wrong_contract = claimed_job(tenant_id, Uuid::now_v7());
        wrong_contract.activity_contract_id = "asf.activity/intake-sync/v2".into();
        assert!(matches!(
            handler
                .execute(&wrong_contract, ActivityControls::new(false))
                .await,
            Err(Error::Validation(detail)) if detail.contains("activity contract")
        ));
        ledger.close().await;
    }

    struct ScopedDatabase {
        ledger: PgLedger,
        admin: sqlx::PgPool,
        schema: String,
    }

    impl ScopedDatabase {
        async fn create(database_url: &str) -> Self {
            let admin = sqlx::PgPool::connect(database_url)
                .await
                .expect("connect intake-test administrator");
            let schema = format!("asf_intake_test_{}", Uuid::now_v7().simple());
            assert!(
                schema
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            );
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create isolated intake-test schema");
            let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
            scoped_url
                .query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema}"));
            let ledger = PgLedger::connect(scoped_url.as_str())
                .await
                .expect("connect isolated intake ledger");
            ledger
                .migrate()
                .await
                .expect("migrate isolated intake schema");
            Self {
                ledger,
                admin,
                schema,
            }
        }

        async fn cleanup(self) {
            self.ledger.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .expect("drop isolated intake-test schema");
            self.admin.close().await;
        }
    }

    #[tokio::test]
    async fn optional_live_intake_is_atomic_idempotent_and_preserves_accepted_authority() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let tenant_id = TenantId::new();
        let repository_id = RepositoryId::new();
        let policy_digest = format!("sha256:{:064x}", 10);
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.as_uuid())
            .bind(format!("intake-{tenant_id}"))
            .bind("Intake integration tenant")
            .execute(database.ledger.pool())
            .await
            .expect("insert intake tenant");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'acme', 'widget', $3, 'main')
            ",
        )
        .bind(repository_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(database.ledger.pool())
        .await
        .expect("insert intake repository");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, scope, schema_version, digest, canonical_bytes,
                policy, created_by
            ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id.as_uuid())
        .bind(&policy_digest)
        .bind(br"{}".as_slice())
        .execute(database.ledger.pool())
        .await
        .expect("insert intake policy");

        let gateway = InMemoryLinearGateway::new();
        let revision_one = snapshot(
            tenant_id,
            Some(repository_id),
            "ASF-42",
            "revision-1",
            "initial objective",
        );
        gateway
            .upsert_snapshot(revision_one.clone())
            .await
            .expect("seed initial source snapshot");
        let handler = IntakeSyncHandler::new(
            database.ledger.clone(),
            tenant_id,
            Arc::new(gateway.clone()),
            "asf-ready",
            1,
        )
        .expect("construct intake handler");
        let first_job = claimed_job(tenant_id, Uuid::now_v7());
        handler
            .execute(&first_job, ActivityControls::new(false))
            .await
            .expect("persist initial intake");
        handler
            .execute(&first_job, ActivityControls::new(false))
            .await
            .expect("adopt retry idempotently");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM source_snapshots WHERE tenant_id = $1"
            )
            .bind(tenant_id.as_uuid())
            .fetch_one(database.ledger.pool())
            .await
            .expect("count initial snapshots"),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE tenant_id = $1")
                .bind(tenant_id.as_uuid())
                .fetch_one(database.ledger.pool())
                .await
                .expect("count initial audit events"),
            1
        );

        let revision_two = snapshot(
            tenant_id,
            Some(repository_id),
            "ASF-42",
            "revision-2",
            "materially revised objective",
        );
        gateway
            .upsert_snapshot(revision_two.clone())
            .await
            .expect("update source before acceptance");
        handler
            .execute(
                &claimed_job(tenant_id, Uuid::now_v7()),
                ActivityControls::new(true),
            )
            .await
            .expect("maintenance permits intake observation");
        let work_row = sqlx::query(
            "SELECT id, source_snapshot_id, state, aggregate_version FROM work_items \
             WHERE tenant_id = $1 AND source_external_id = 'ASF-42'",
        )
        .bind(tenant_id.as_uuid())
        .fetch_one(database.ledger.pool())
        .await
        .expect("load pre-acceptance work item");
        let work_item_id: Uuid = work_row.try_get("id").expect("decode work ID");
        let authority_snapshot_id: Uuid = work_row
            .try_get("source_snapshot_id")
            .expect("decode source authority");
        assert_eq!(authority_snapshot_id, revision_two.id.as_uuid());
        assert_eq!(
            work_row
                .try_get::<String, _>("state")
                .expect("decode state"),
            "READINESS_PENDING"
        );
        assert_eq!(
            work_row
                .try_get::<i64, _>("aggregate_version")
                .expect("decode aggregate version"),
            2
        );

        let mut acceptance = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin acceptance fixture");
        sqlx::query(
            r"
            UPDATE work_items
            SET state = 'READY', closure_target = 'pull_request', risk_class = 'low',
                policy_digest = $3, budget_limits = $4,
                identity_requirements = $5, owner_fallback = 'team:source',
                ready_at = clock_timestamp(), aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(work_item_id)
        .bind(&policy_digest)
        .bind(json!({
            "max_cost_microunits": 1000,
            "max_input_tokens": 1000,
            "max_output_tokens": 1000,
            "max_implementer_invocations": 1,
            "max_reviewer_invocations": 1,
            "max_fix_iterations": 0,
            "max_wall_time_seconds": 600,
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "codex:pr-reviewer"
        }))
        .execute(&mut *acceptance)
        .await
        .expect("make work ready");
        sqlx::query(
            r"
            UPDATE work_items
            SET state = 'ACCEPTED', accepted_at = clock_timestamp(),
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(work_item_id)
        .execute(&mut *acceptance)
        .await
        .expect("accept work");
        let anchor_escalation_id = Uuid::now_v7();
        let anchor_deadline = Utc::now() + TimeDelta::hours(1);
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, category, severity, reason,
                owner_type, owner_id, required_action, deadline, retry_policy,
                authority_or_effect_active, idempotency_key
            ) VALUES (
                $1, $2, $3, 'NEEDS_APPROVAL', 'MEDIUM', 'test acceptance anchor',
                'TEAM', 'team:source', 'approve fixture', $4,
                '{}'::jsonb, false, $5
            )
            ",
        )
        .bind(anchor_escalation_id)
        .bind(tenant_id.as_uuid())
        .bind(work_item_id)
        .bind(anchor_deadline)
        .bind(format!("intake-test-anchor:{work_item_id}"))
        .execute(&mut *acceptance)
        .await
        .expect("insert acceptance anchor escalation");
        sqlx::query(
            r"
            INSERT INTO accountability_anchors (
                tenant_id, work_item_id, anchor_type, reference_id,
                wake_or_deadline_at, authority_or_effect_active
            ) VALUES ($1, $2, 'ESCALATION', $3, $4, false)
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(work_item_id)
        .bind(anchor_escalation_id)
        .bind(anchor_deadline)
        .execute(&mut *acceptance)
        .await
        .expect("install acceptance accountability anchor");
        acceptance.commit().await.expect("commit accepted fixture");

        let revision_three = snapshot(
            tenant_id,
            Some(repository_id),
            "ASF-42",
            "revision-3",
            "changed after acceptance",
        );
        gateway
            .upsert_snapshot(revision_three.clone())
            .await
            .expect("update source after acceptance");
        let accepted_job = claimed_job(tenant_id, Uuid::now_v7());
        handler
            .execute(&accepted_job, ActivityControls::new(false))
            .await
            .expect("record accepted source change");
        handler
            .execute(&accepted_job, ActivityControls::new(false))
            .await
            .expect("adopt accepted source-change retry");
        let accepted_row = sqlx::query(
            "SELECT source_snapshot_id, state, aggregate_version FROM work_items \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(work_item_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load accepted work after source change");
        assert_eq!(
            accepted_row
                .try_get::<Uuid, _>("source_snapshot_id")
                .expect("decode retained authority snapshot"),
            authority_snapshot_id
        );
        assert_eq!(
            accepted_row
                .try_get::<String, _>("state")
                .expect("decode retained state"),
            "ACCEPTED"
        );
        assert_eq!(
            accepted_row
                .try_get::<i64, _>("aggregate_version")
                .expect("decode retained version"),
            4
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM escalations WHERE tenant_id = $1 \
                 AND work_item_id = $2 AND category = 'BLOCKED_EXTERNAL'"
            )
            .bind(tenant_id.as_uuid())
            .bind(work_item_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count owned source-change escalation"),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE tenant_id = $1")
                .bind(tenant_id.as_uuid())
                .fetch_one(database.ledger.pool())
                .await
                .expect("count source-change audit events"),
            3
        );

        let conflicting_revision = snapshot(
            tenant_id,
            Some(repository_id),
            "ASF-42",
            "revision-3",
            "conflicting content for one provider revision",
        );
        let malicious_gateway = Arc::new(ScriptedGateway::new(vec![Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots: vec![conflicting_revision],
            next_cursor: None,
            has_more: false,
        })]));
        let malicious_handler = IntakeSyncHandler::new(
            database.ledger.clone(),
            tenant_id,
            malicious_gateway,
            "asf-ready",
            10,
        )
        .expect("construct conflicting intake handler");
        assert!(matches!(
            malicious_handler
                .execute(
                    &claimed_job(tenant_id, Uuid::now_v7()),
                    ActivityControls::new(false)
                )
                .await,
            Err(Error::Conflict(detail)) if detail.contains("different canonical content")
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM source_snapshots WHERE tenant_id = $1"
            )
            .bind(tenant_id.as_uuid())
            .fetch_one(database.ledger.pool())
            .await
            .expect("count snapshots after conflicting rollback"),
            3
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE tenant_id = $1")
                .bind(tenant_id.as_uuid())
                .fetch_one(database.ledger.pool())
                .await
                .expect("count audit rows after conflicting rollback"),
            3
        );

        database.cleanup().await;
    }

    #[test]
    fn core_validator_allows_a_missing_opt_in_label_but_the_sync_wrapper_requires_it() {
        let tenant_id = TenantId::new();
        let now = Utc::now();
        let content = SourceSnapshotContent {
            source: SourceSystem::Linear,
            external_id: "ASF-unlabeled".into(),
            source_revision: "revision-1".into(),
            source_url: None,
            title: "Work ASF-unlabeled".into(),
            objective: "bounded objective".into(),
            acceptance_criteria: vec!["the requested change is verified".into()],
            non_goals: Vec::new(),
            labels: BTreeSet::new(),
            normalized_priority: 50,
            source_state: "started".into(),
            assignee: None,
            repository_hint: None,
            source_updated_at: now,
        };
        let unlabeled = SourceSnapshot::create(
            tenant_id,
            None,
            content,
            "linear:test-connector".into(),
            now,
        )
        .expect("valid unlabeled snapshot");

        validate_snapshot_core(&unlabeled, tenant_id)
            .expect("core validator does not enforce the opt-in label");
        assert!(matches!(
            validate_snapshot(&unlabeled, tenant_id, "asf-ready"),
            Err(Error::Validation(detail)) if detail.contains("opt-in label")
        ));
    }

    #[test]
    fn positive_aggregate_version_rejects_nonpositive_values() {
        assert_eq!(
            positive_aggregate_version(1).expect("one is a valid positive version"),
            1
        );
        assert!(positive_aggregate_version(0).is_err());
        assert!(positive_aggregate_version(-1).is_err());
    }

    #[test]
    fn source_event_headers_built_by_the_writer_validate() {
        let system_headers = source_event_headers(
            &IntakeProvenance::System(SystemIntakeActor::IntakeSync),
            "correlation-system",
            None,
        );
        validate_stored_source_event_headers(&system_headers, &json!({"policy_digest": null}))
            .expect("freshly built system-provenance headers are a well-formed envelope");

        let caller = Caller {
            subject: "user:header-test".into(),
            roles: BTreeSet::new(),
        };
        let policy_digest = format!("sha256:{:064x}", 7);
        let api_headers = source_event_headers(
            &IntakeProvenance::ApiCaller(&caller),
            "correlation-api",
            Some(&policy_digest),
        );
        validate_stored_source_event_headers(
            &api_headers,
            &json!({"policy_digest": policy_digest}),
        )
        .expect("freshly built API-caller-provenance headers are a well-formed envelope");
    }

    #[test]
    fn malformed_stored_source_event_headers_fail_closed() {
        let payload = json!({"policy_digest": Value::Null});
        let well_formed = json!({
            "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
            "actor_type": "SYSTEM",
            "actor_id": "runtime:intake-sync",
            "correlation_id": "correlation-1",
            "trace_id": null,
            "policy_digest": null,
        });
        validate_stored_source_event_headers(&well_formed, &payload)
            .expect("a well-formed stored envelope validates");

        let cases: &[(&str, Value)] = &[
            ("not an object", json!("not-an-object")),
            (
                "wrong schema",
                json!({
                    "schema": "asf.some-other-schema.v1",
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                }),
            ),
            (
                "missing schema",
                json!({
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                }),
            ),
            (
                "unrecognized actor_type",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "ROBOT",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                }),
            ),
            (
                "blank actor_id",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "   ",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                }),
            ),
            (
                "blank correlation_id",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "",
                    "trace_id": null,
                    "policy_digest": null,
                }),
            ),
            (
                "non-null trace_id",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": "trace-1",
                    "policy_digest": null,
                }),
            ),
            (
                "missing trace_id",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "policy_digest": null,
                }),
            ),
            (
                "policy_digest mismatched with payload",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": format!("sha256:{:064x}", 1),
                }),
            ),
            (
                "extra sensitive authorization field",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                    "authorization": "Bearer smuggled-credential-value",
                }),
            ),
            (
                "extra innocuous field",
                json!({
                    "schema": SOURCE_EVENT_HEADERS_SCHEMA_V1,
                    "actor_type": "SYSTEM",
                    "actor_id": "runtime:intake-sync",
                    "correlation_id": "correlation-1",
                    "trace_id": null,
                    "policy_digest": null,
                    "extra_innocuous_field": "harmless",
                }),
            ),
        ];
        for (label, headers) in cases {
            assert!(
                matches!(
                    validate_stored_source_event_headers(headers, &payload),
                    Err(Error::Conflict(_))
                ),
                "expected a fail-closed Conflict for malformed headers case {label:?}, headers: \
                 {headers}"
            );
        }
    }

    #[tokio::test]
    async fn intake_transaction_writer_reports_structured_outcomes_and_provenance() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let database = ScopedDatabase::create(&database_url).await;
        let tenant_id = TenantId::new();
        let repository_id = RepositoryId::new();
        let policy_digest = format!("sha256:{:064x}", 11);
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.as_uuid())
            .bind(format!("intake-writer-{tenant_id}"))
            .bind("Intake writer unit tenant")
            .execute(database.ledger.pool())
            .await
            .expect("insert intake writer tenant");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'acme', 'widget', $3, 'main')
            ",
        )
        .bind(repository_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(database.ledger.pool())
        .await
        .expect("insert intake writer repository");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, scope, schema_version, digest, canonical_bytes,
                policy, created_by
            ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id.as_uuid())
        .bind(&policy_digest)
        .bind(br"{}".as_slice())
        .execute(database.ledger.pool())
        .await
        .expect("insert intake writer policy");

        let mut transaction = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin writer transaction");
        let mut writer = IntakeTransactionWriter::lock(&mut transaction, tenant_id)
            .await
            .expect("lock intake transaction writer");

        let first = snapshot(
            tenant_id,
            None,
            "ASF-writer-1",
            "revision-1",
            "first objective",
        );
        let discovered = writer
            .persist_snapshot(
                &first,
                "correlation-discover",
                IntakeProvenance::System(SystemIntakeActor::IntakeSync),
                Utc::now(),
            )
            .await
            .expect("persist discovered snapshot");
        assert_eq!(discovered.outcome, IntakeOutcome::Discovered);
        assert!(discovered.snapshot_inserted);
        assert_eq!(discovered.work_item_state, WorkItemState::Discovered);
        assert_eq!(discovered.aggregate_version, 1);
        assert!(!discovered.already_accepted);
        assert_eq!(discovered.content_digest, first.content_digest);

        let caller = Caller {
            subject: "user:writer-test".into(),
            roles: BTreeSet::new(),
        };
        let second = snapshot(
            tenant_id,
            None,
            "ASF-writer-1",
            "revision-2",
            "revised objective",
        );
        let requeued = writer
            .persist_snapshot(
                &second,
                "correlation-requeue",
                IntakeProvenance::ApiCaller(&caller),
                Utc::now(),
            )
            .await
            .expect("persist readiness-requeued snapshot under API-caller provenance");
        assert_eq!(requeued.outcome, IntakeOutcome::ReadinessRequeued);
        assert!(requeued.snapshot_inserted);
        assert_eq!(requeued.work_item_id, discovered.work_item_id);
        assert_eq!(requeued.work_item_state, WorkItemState::ReadinessPending);
        assert_eq!(requeued.aggregate_version, 2);
        assert!(!requeued.already_accepted);
        assert_eq!(requeued.content_digest, second.content_digest);

        let retried = writer
            .persist_snapshot(
                &second,
                "correlation-retry",
                IntakeProvenance::System(SystemIntakeActor::IntakeSync),
                Utc::now(),
            )
            .await
            .expect("adopt retried snapshot idempotently");
        assert_eq!(retried.outcome, IntakeOutcome::Unchanged);
        assert!(!retried.snapshot_inserted);
        assert_eq!(retried.aggregate_version, 2);
        assert_eq!(retried.content_digest, second.content_digest);

        // The writer statically borrows this transaction, so a fixture update issued directly
        // against the transaction must happen while the writer's borrow isn't live: drop it,
        // mutate, then reacquire a fresh writer on the same (still-open) transaction.
        drop(writer);
        sqlx::query(
            r"
            UPDATE work_items
            SET state = 'READY', repository_id = $3, closure_target = 'pull_request',
                risk_class = 'low', policy_digest = $4, budget_limits = $5,
                identity_requirements = $6, owner_fallback = 'team:writer-test',
                ready_at = $7, aggregate_version = aggregate_version + 1, updated_at = $7
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(discovered.work_item_id)
        .bind(repository_id.as_uuid())
        .bind(&policy_digest)
        .bind(json!({
            "max_cost_microunits": 1000,
            "max_input_tokens": 1000,
            "max_output_tokens": 1000,
            "max_implementer_invocations": 1,
            "max_reviewer_invocations": 1,
            "max_fix_iterations": 0,
            "max_wall_time_seconds": 600,
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "codex:pr-reviewer"
        }))
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .expect("ready work item for authority-reevaluation fixture");
        sqlx::query(
            r"
            UPDATE work_items
            SET state = 'ACCEPTED', accepted_at = $3,
                aggregate_version = aggregate_version + 1, updated_at = $3
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(discovered.work_item_id)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .expect("accept work item for authority-reevaluation fixture");
        let anchor_escalation_id = Uuid::now_v7();
        let anchor_deadline = Utc::now() + TimeDelta::hours(1);
        sqlx::query(
            r"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, category, severity, reason,
                owner_type, owner_id, required_action, deadline, retry_policy,
                authority_or_effect_active, idempotency_key
            ) VALUES (
                $1, $2, $3, 'NEEDS_APPROVAL', 'MEDIUM', 'writer test acceptance anchor',
                'TEAM', 'team:writer-test', 'approve fixture', $4,
                '{}'::jsonb, false, $5
            )
            ",
        )
        .bind(anchor_escalation_id)
        .bind(tenant_id.as_uuid())
        .bind(discovered.work_item_id)
        .bind(anchor_deadline)
        .bind(format!(
            "intake-writer-test-anchor:{}",
            discovered.work_item_id
        ))
        .execute(&mut *transaction)
        .await
        .expect("insert writer acceptance anchor escalation");
        sqlx::query(
            r"
            INSERT INTO accountability_anchors (
                tenant_id, work_item_id, anchor_type, reference_id,
                wake_or_deadline_at, authority_or_effect_active
            ) VALUES ($1, $2, 'ESCALATION', $3, $4, false)
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(discovered.work_item_id)
        .bind(anchor_escalation_id)
        .bind(anchor_deadline)
        .execute(&mut *transaction)
        .await
        .expect("install writer acceptance accountability anchor");
        let mut writer = IntakeTransactionWriter::lock(&mut transaction, tenant_id)
            .await
            .expect("reacquire intake transaction writer after fixture update");

        let third = snapshot(
            tenant_id,
            None,
            "ASF-writer-1",
            "revision-3",
            "changed after acceptance",
        );
        let reevaluated = writer
            .persist_snapshot(
                &third,
                "correlation-reevaluate",
                IntakeProvenance::System(SystemIntakeActor::IntakeSync),
                Utc::now(),
            )
            .await
            .expect("persist authority-reevaluation-required snapshot");
        assert_eq!(
            reevaluated.outcome,
            IntakeOutcome::AuthorityReevaluationRequired
        );
        assert!(reevaluated.snapshot_inserted);
        assert!(reevaluated.already_accepted);
        assert_eq!(reevaluated.aggregate_version, 4);
        assert_eq!(reevaluated.content_digest, third.content_digest);

        let reevaluated_retry = writer
            .persist_snapshot(
                &third,
                "correlation-reevaluate-retry",
                IntakeProvenance::System(SystemIntakeActor::IntakeSync),
                Utc::now(),
            )
            .await
            .expect("adopt retried authority-reevaluation snapshot idempotently");
        assert_eq!(
            reevaluated_retry.outcome,
            IntakeOutcome::AuthorityReevaluationRequired
        );
        assert!(!reevaluated_retry.snapshot_inserted);
        assert!(reevaluated_retry.already_accepted);
        assert_eq!(reevaluated_retry.aggregate_version, 4);
        assert_eq!(reevaluated_retry.content_digest, third.content_digest);

        transaction
            .commit()
            .await
            .expect("commit writer transaction");

        let audit_rows = sqlx::query(
            "SELECT actor_type, actor_id, policy_digest FROM audit_events WHERE tenant_id = $1 \
             ORDER BY occurred_at, id",
        )
        .bind(tenant_id.as_uuid())
        .fetch_all(database.ledger.pool())
        .await
        .expect("load intake audit events");
        assert_eq!(audit_rows.len(), 3);
        assert_eq!(
            audit_rows[0]
                .try_get::<String, _>("actor_type")
                .expect("decode discover actor type"),
            "SYSTEM"
        );
        assert_eq!(
            audit_rows[0]
                .try_get::<String, _>("actor_id")
                .expect("decode discover actor id"),
            "runtime:intake-sync"
        );
        assert_eq!(
            audit_rows[1]
                .try_get::<String, _>("actor_type")
                .expect("decode requeue actor type"),
            "API_CALLER"
        );
        assert_eq!(
            audit_rows[1]
                .try_get::<String, _>("actor_id")
                .expect("decode requeue actor id"),
            caller.subject
        );
        assert_eq!(
            audit_rows[2]
                .try_get::<String, _>("actor_type")
                .expect("decode reevaluation actor type"),
            "SYSTEM"
        );
        assert_eq!(
            audit_rows[2]
                .try_get::<String, _>("actor_id")
                .expect("decode reevaluation actor id"),
            "runtime:intake-sync"
        );
        assert!(
            audit_rows[0]
                .try_get::<Option<String>, _>("policy_digest")
                .expect("decode discover policy digest")
                .is_none(),
            "discovery never has a policy digest"
        );
        assert!(
            audit_rows[1]
                .try_get::<Option<String>, _>("policy_digest")
                .expect("decode requeue policy digest")
                .is_none(),
            "readiness requeue never has a policy digest"
        );
        assert_eq!(
            audit_rows[2]
                .try_get::<Option<String>, _>("policy_digest")
                .expect("decode reevaluation policy digest"),
            Some(policy_digest.clone()),
            "the reevaluation audit event's policy_digest equals the accepted work's retained \
             policy digest"
        );

        database.cleanup().await;
    }
}
