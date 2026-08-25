//! Durable ingestion of the signed Runmill evidence bundle and its manifest.
//!
//! One successful `asf.get_evidence` response carries two distinct signed
//! facts: the terminal evidence bundle, which proves the run stopped, and the
//! evidence bundle itself, which is what an independent verifier reads. This
//! module retains the second one.
//!
//! It is deliberately a persistence primitive, not a verifier. It proves that
//! the retained row cannot disagree with the signed bytes, that the manifest
//! maps bijectively onto durable artifact metadata, and that every coordinate
//! belongs to the exact run the caller already fenced. Whether the evidence is
//! *true* — whether its checks passed, its artifacts match their bytes, its
//! signer is trusted, and the forge agrees — stays the verifier's job.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{persistence_error, runmill_terminal_evidence::RunmillTerminalEvidenceFence};
use crate::{
    Error, Result,
    adapters::runmill_control::{
        RunmillEvidenceView, RunmillRetentionClass as ControlRetentionClass,
    },
    contracts::{
        RunmillArtifactKind, RunmillClosureTarget, RunmillEvidenceArtifact, RunmillRetentionClass,
        SignedRunmillEvidenceBundle,
    },
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
};

const MAX_EVIDENCE_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MIN_EVIDENCE_DOCUMENT_BYTES: usize = 2;
/// ASF stores every Runmill artifact under its own content-addressed digest.
const DIGEST_ALGORITHM: &str = "sha256";
const ARTIFACT_PRODUCER: &str = "runmill:evidence-ingestion";
const ARTIFACT_ENCRYPTION_CLASS: &str = "none";
const ARTIFACT_ACCESS_POLICY: &str = "tenant";

/// The exact run coordinates an ingested bundle is read under. The run's own
/// evidence expectation is returned because it is what the verification
/// obligation must carry, and it is never invented by the caller.
const LOAD_RUN_EXPECTATION_SQL: &str = r"
SELECT run.evidence_expectation_digest
FROM runs AS run
WHERE run.tenant_id = $1
  AND run.id = $2
  AND run.work_item_id = $3
  AND run.attempt_id = $4
  AND run.work_order_id = $5
  AND run.worker_id = $6
  AND run.worker_generation = $7
  AND run.worker_session_id = $8
  AND run.external_run_id = $9
  AND run.authoritative
FOR SHARE
";

const LOAD_EVIDENCE_REPLAY_SQL: &str = r"
SELECT
    id, work_item_id, attempt_id, worker_id, worker_generation, schema_version,
    envelope_schema, algorithm, key_id, work_order_digest, base_sha,
    candidate_sha, requested_target, target_satisfied, canonical_payload,
    signature, exact_signed_envelope, produced_at
FROM evidence_bundles
WHERE tenant_id = $1
  AND run_id = $2
  AND payload_digest = $3
FOR SHARE
";

const INSERT_EVIDENCE_SQL: &str = r"
INSERT INTO evidence_bundles (
    id, tenant_id, work_item_id, attempt_id, run_id, worker_id,
    worker_generation, schema_version, envelope_schema, algorithm, key_id,
    payload_digest, work_order_digest, base_sha, candidate_sha,
    requested_target, target_satisfied, canonical_payload, payload, signature,
    exact_signed_envelope, produced_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
    $17, $18, $19, $20, $21, $22
)
ON CONFLICT DO NOTHING
RETURNING id
";

/// What one ingestion durably established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillEvidenceIngestionOutcome {
    pub evidence_id: Uuid,
    /// False when an identical bundle was already durable.
    pub inserted: bool,
    pub payload_digest: String,
    pub work_order_digest: String,
    /// The run's own immutable evidence expectation, which the verification
    /// obligation must carry.
    pub expectation_digest: String,
    pub artifacts_bound: usize,
}

/// Every `evidence_bundles` column reproduced from the exact signed bytes.
#[derive(Debug, Clone)]
struct EvidenceRecord {
    schema_version: String,
    envelope_schema: String,
    algorithm: String,
    key_id: String,
    payload_digest: String,
    work_order_digest: String,
    base_sha: String,
    candidate_sha: String,
    requested_target: String,
    target_satisfied: bool,
    canonical_payload: Vec<u8>,
    payload: Value,
    signature: String,
    exact_signed_envelope: Vec<u8>,
    produced_at: DateTime<Utc>,
    artifacts: Vec<RunmillEvidenceArtifact>,
}

/// Retain the signed evidence bundle this read returned, together with durable
/// metadata for every artifact its signed manifest names.
///
/// The bundle is bound to the same fence the terminal evidence was proved
/// under, so an evidence bundle can never be attributed to a run, attempt, or
/// Work Order the caller did not already own. Ingestion is idempotent on the
/// bundle's own payload digest: a replay returns the retained row, and a
/// retained row that disagrees is a conflict rather than an overwrite.
///
/// # Errors
///
/// Returns [`Error::Validation`] when the read carries no signed bundle or the
/// bundle contradicts its own digest, its manifest, or the fence;
/// [`Error::Conflict`] when the run is not the exact authoritative one or a
/// retained bundle or artifact disagrees; and [`Error::Persistence`] on
/// database failure.
pub async fn record_runmill_evidence_ingestion(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    view: &RunmillEvidenceView,
) -> Result<RunmillEvidenceIngestionOutcome> {
    let record = EvidenceRecord::from_evidence_view(fence, view)?;
    let expectation_digest = load_run_expectation(transaction, fence).await?;

    if let Some(retained) = load_evidence_replay(transaction, fence, &record).await? {
        return Ok(RunmillEvidenceIngestionOutcome {
            evidence_id: retained,
            inserted: false,
            payload_digest: record.payload_digest,
            work_order_digest: record.work_order_digest,
            expectation_digest,
            artifacts_bound: record.artifacts.len(),
        });
    }

    let evidence_id = Uuid::now_v7();
    let inserted = sqlx::query_scalar::<_, Uuid>(INSERT_EVIDENCE_SQL)
        .bind(evidence_id)
        .bind(fence.tenant_id)
        .bind(fence.work_item_id)
        .bind(fence.attempt_id)
        .bind(fence.run_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .bind(&record.schema_version)
        .bind(&record.envelope_schema)
        .bind(&record.algorithm)
        .bind(&record.key_id)
        .bind(&record.payload_digest)
        .bind(&record.work_order_digest)
        .bind(&record.base_sha)
        .bind(&record.candidate_sha)
        .bind(&record.requested_target)
        .bind(record.target_satisfied)
        .bind(&record.canonical_payload)
        .bind(&record.payload)
        .bind(&record.signature)
        .bind(&record.exact_signed_envelope)
        .bind(record.produced_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("store Runmill evidence bundle", error))?;

    let Some(evidence_id) = inserted else {
        // Another writer committed the same durable fact between the replay
        // read and this insert. Adopt it rather than creating a second one.
        let retained = load_evidence_replay(transaction, fence, &record)
            .await?
            .ok_or_else(|| {
                Error::Conflict(format!(
                    "Runmill evidence {} conflicts with an invisible retained bundle",
                    record.payload_digest
                ))
            })?;
        return Ok(RunmillEvidenceIngestionOutcome {
            evidence_id: retained,
            inserted: false,
            payload_digest: record.payload_digest,
            work_order_digest: record.work_order_digest,
            expectation_digest,
            artifacts_bound: record.artifacts.len(),
        });
    };

    for artifact in &record.artifacts {
        bind_manifest_artifact(transaction, fence.tenant_id, evidence_id, artifact).await?;
    }

    Ok(RunmillEvidenceIngestionOutcome {
        evidence_id,
        inserted: true,
        payload_digest: record.payload_digest,
        work_order_digest: record.work_order_digest,
        expectation_digest,
        artifacts_bound: record.artifacts.len(),
    })
}

impl EvidenceRecord {
    /// Reproduce every retained column from the signed bundle the evidence read
    /// returned, and refuse anything that contradicts the fence or itself.
    fn from_evidence_view(
        fence: &RunmillTerminalEvidenceFence,
        view: &RunmillEvidenceView,
    ) -> Result<Self> {
        let signed_bundle = view.signed_bundle.as_ref().ok_or_else(|| {
            Error::Validation("Runmill evidence view carries no signed evidence bundle".into())
        })?;
        let exact_signed_envelope = serde_json::to_vec(signed_bundle).map_err(|error| {
            Error::Serialization(format!("serialize signed Runmill evidence bundle: {error}"))
        })?;
        require_document_size(exact_signed_envelope.len(), "signed evidence envelope")?;
        let bundle = SignedRunmillEvidenceBundle::from_json(&exact_signed_envelope)?;

        let bundle_digest = view.bundle_digest.as_deref().ok_or_else(|| {
            Error::Validation("Runmill evidence view carries no evidence bundle digest".into())
        })?;
        if !is_sha256_digest(bundle_digest) || bundle.bundle_digest != bundle_digest {
            return Err(Error::Validation(
                "signed evidence bundle digest contradicts the evidence view".into(),
            ));
        }

        let payload = serde_json::to_value(&bundle.statement).map_err(|error| {
            Error::Serialization(format!("serialize Runmill evidence statement: {error}"))
        })?;
        let canonical_payload = canonical_json(&payload)?;
        require_document_size(canonical_payload.len(), "evidence statement")?;
        if sha256_digest(&canonical_payload) != bundle.bundle_digest {
            return Err(Error::Validation(
                "signed evidence bundle digest is not the digest of its own statement".into(),
            ));
        }

        let predicate = &bundle.statement.predicate;
        if predicate.run.run_id.as_str() != fence.external_run_id
            || predicate.run.work_order_id.to_string() != fence.work_order_id.to_string()
            || predicate.run.attempt_id.to_string() != fence.attempt_id.to_string()
        {
            return Err(Error::Validation(
                "signed evidence bundle names a different run, Work Order, or attempt than its fence"
                    .into(),
            ));
        }
        // The evidence read and the signature must agree about the candidate,
        // otherwise the row would record a commit nobody attested to.
        if view.candidate_sha.as_deref() != Some(predicate.source.candidate_sha.as_str()) {
            return Err(Error::Validation(
                "Runmill evidence view candidate commit contradicts its signed source".into(),
            ));
        }
        if !is_sha256_digest(&predicate.work_order.payload_digest) {
            return Err(Error::Validation(
                "signed evidence bundle carries an invalid Work Order payload digest".into(),
            ));
        }

        // The unsigned list the read returned must be exactly the signed
        // manifest: a read cannot add, drop, or restate an artifact.
        assert_view_manifest_agrees(view, &predicate.artifacts)?;

        Ok(Self {
            schema_version: predicate.schema.clone(),
            envelope_schema: bundle.schema.clone(),
            algorithm: algorithm_database_value(&bundle)?,
            key_id: bundle.key_id.clone(),
            payload_digest: bundle.bundle_digest.clone(),
            work_order_digest: predicate.work_order.payload_digest.clone(),
            base_sha: predicate.source.base_sha.clone(),
            candidate_sha: predicate.source.candidate_sha.clone(),
            requested_target: closure_target_database_value(predicate.delivery.closure_target)
                .to_owned(),
            target_satisfied: predicate.delivery.satisfied,
            canonical_payload,
            payload,
            signature: bundle.signature.clone(),
            exact_signed_envelope,
            produced_at: bundle.issued_at.to_utc()?,
            artifacts: predicate.artifacts.clone(),
        })
    }
}

/// The evidence view's own artifact list is unsigned. It is retained nowhere,
/// but it must not contradict the signed manifest: a disagreement means the
/// read and the signature describe different runs.
fn assert_view_manifest_agrees(
    view: &RunmillEvidenceView,
    manifest: &[RunmillEvidenceArtifact],
) -> Result<()> {
    if view.artifacts.len() != manifest.len() {
        return Err(Error::Validation(
            "Runmill evidence view lists a different artifact count than its signed manifest"
                .into(),
        ));
    }
    for signed in manifest {
        let matched = view.artifacts.iter().any(|listed| {
            listed.artifact_id == signed.artifact_id
                && listed.digest == signed.digest
                && listed.size_bytes == signed.size_bytes
                && listed.media_type == signed.media_type
                && listed.location_ref == signed.location_ref
                && control_retention_database_value(listed.retention_class)
                    == retention_database_value(signed.retention_class)
        });
        if !matched {
            return Err(Error::Validation(format!(
                "Runmill evidence view contradicts signed manifest artifact {}",
                signed.artifact_id
            )));
        }
    }
    Ok(())
}

async fn load_run_expectation(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
) -> Result<String> {
    let expectation = sqlx::query_scalar::<_, String>(LOAD_RUN_EXPECTATION_SQL)
        .bind(fence.tenant_id)
        .bind(fence.run_id)
        .bind(fence.work_item_id)
        .bind(fence.attempt_id)
        .bind(fence.work_order_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .bind(fence.worker_session_id)
        .bind(&fence.external_run_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("load Runmill evidence run expectation", error))?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "Runmill evidence for run {} lacks its exact authoritative run binding",
                fence.run_id
            ))
        })?;
    if !is_sha256_digest(&expectation) {
        return Err(Error::Persistence(
            "authoritative run carries an unusable evidence expectation digest".into(),
        ));
    }
    Ok(expectation)
}

/// Resolve an already-retained identical bundle. A retained row with the same
/// identity but different semantics is a conflict, never an overwrite.
async fn load_evidence_replay(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    record: &EvidenceRecord,
) -> Result<Option<Uuid>> {
    let Some(row) = sqlx::query(LOAD_EVIDENCE_REPLAY_SQL)
        .bind(fence.tenant_id)
        .bind(fence.run_id)
        .bind(&record.payload_digest)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("load retained Runmill evidence bundle", error))?
    else {
        return Ok(None);
    };
    if !evidence_matches(&row, fence, record)? {
        return Err(Error::Conflict(format!(
            "retained Runmill evidence {} states different semantics than this read",
            record.payload_digest
        )));
    }
    Ok(Some(required_column(&row, "id", "evidence ID")?))
}

fn evidence_matches(
    row: &PgRow,
    fence: &RunmillTerminalEvidenceFence,
    record: &EvidenceRecord,
) -> Result<bool> {
    Ok(
        required_column::<Uuid>(row, "work_item_id", "evidence work item")? == fence.work_item_id
            && required_column::<Uuid>(row, "attempt_id", "evidence attempt")? == fence.attempt_id
            && required_column::<Uuid>(row, "worker_id", "evidence worker")? == fence.worker_id
            && required_column::<i64>(row, "worker_generation", "evidence worker generation")?
                == fence.worker_generation
            && required_column::<String>(row, "schema_version", "evidence schema")?
                == record.schema_version
            && required_column::<String>(row, "envelope_schema", "evidence envelope schema")?
                == record.envelope_schema
            && required_column::<String>(row, "algorithm", "evidence algorithm")?
                == record.algorithm
            && required_column::<String>(row, "key_id", "evidence signing key")? == record.key_id
            && required_column::<String>(row, "work_order_digest", "evidence Work Order digest")?
                == record.work_order_digest
            && required_column::<String>(row, "base_sha", "evidence base commit")?
                == record.base_sha
            && required_column::<String>(row, "candidate_sha", "evidence candidate commit")?
                == record.candidate_sha
            && required_column::<String>(row, "requested_target", "evidence closure target")?
                == record.requested_target
            && required_column::<bool>(row, "target_satisfied", "evidence target satisfaction")?
                == record.target_satisfied
            && required_column::<Vec<u8>>(row, "canonical_payload", "evidence canonical payload")?
                == record.canonical_payload
            && required_column::<String>(row, "signature", "evidence signature")?
                == record.signature
            && required_column::<Vec<u8>>(row, "exact_signed_envelope", "evidence envelope")?
                == record.exact_signed_envelope
            && required_column::<DateTime<Utc>>(row, "produced_at", "evidence production")?
                == record.produced_at,
    )
}

/// Bind one signed manifest entry to durable artifact metadata.
///
/// Artifacts are content-addressed, so the same bytes may already be stored for
/// an earlier run. That row is adopted only when every metadata field it
/// carries matches this manifest entry exactly; otherwise two different
/// artifacts would share one digest, which is a conflict rather than a reuse.
async fn bind_manifest_artifact(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    evidence_id: Uuid,
    artifact: &RunmillEvidenceArtifact,
) -> Result<()> {
    let byte_size = i64::try_from(artifact.size_bytes).map_err(|_| {
        Error::Validation(format!(
            "Runmill artifact {} size overflows PostgreSQL bigint",
            artifact.artifact_id
        ))
    })?;
    let retention_class = retention_database_value(artifact.retention_class);
    let manifest_kind = artifact_kind_database_value(artifact.kind);

    let artifact_id = Uuid::now_v7();
    let stored = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO artifacts (
            id, tenant_id, digest_algorithm, digest, media_type, byte_size,
            object_key, encryption_class, retention_class, access_policy, producer
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT DO NOTHING
        RETURNING id
        ",
    )
    .bind(artifact_id)
    .bind(tenant_id)
    .bind(DIGEST_ALGORITHM)
    .bind(&artifact.digest)
    .bind(&artifact.media_type)
    .bind(byte_size)
    .bind(&artifact.location_ref)
    .bind(ARTIFACT_ENCRYPTION_CLASS)
    .bind(retention_class)
    .bind(ARTIFACT_ACCESS_POLICY)
    .bind(ARTIFACT_PRODUCER)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("store Runmill evidence artifact metadata", error))?;

    let artifact_id = match stored {
        Some(artifact_id) => artifact_id,
        None => adopt_existing_artifact(transaction, tenant_id, artifact, byte_size).await?,
    };

    sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship,
            manifest_artifact_id, manifest_kind
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_id)
    .bind(artifact_relationship(artifact.kind))
    .bind(&artifact.artifact_id)
    .bind(manifest_kind)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("link Runmill evidence artifact", error))?;
    Ok(())
}

async fn adopt_existing_artifact(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    artifact: &RunmillEvidenceArtifact,
    byte_size: i64,
) -> Result<Uuid> {
    let row = sqlx::query(
        r"
        SELECT id, media_type, byte_size, object_key, retention_class
        FROM artifacts
        WHERE tenant_id = $1 AND digest_algorithm = $2 AND digest = $3
        FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(DIGEST_ALGORITHM)
    .bind(&artifact.digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load retained Runmill evidence artifact", error))?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill artifact {} could not be stored or adopted",
            artifact.artifact_id
        ))
    })?;

    let matches = required_column::<String>(&row, "media_type", "artifact media type")?
        == artifact.media_type
        && required_column::<i64>(&row, "byte_size", "artifact size")? == byte_size
        && required_column::<String>(&row, "object_key", "artifact object key")?
            == artifact.location_ref
        && required_column::<String>(&row, "retention_class", "artifact retention")?
            == retention_database_value(artifact.retention_class);
    if !matches {
        return Err(Error::Conflict(format!(
            "retained artifact {} states different metadata than this signed manifest",
            artifact.digest
        )));
    }
    required_column(&row, "id", "artifact ID")
}

/// The durable relationship an artifact plays for its evidence. It is derived
/// from the signed kind rather than supplied, so the two can never disagree.
const fn artifact_relationship(kind: RunmillArtifactKind) -> &'static str {
    match kind {
        RunmillArtifactKind::NormalizedDiff => "DIFF",
        RunmillArtifactKind::Verification | RunmillArtifactKind::CiObservation => "CHECK_REPORT",
        RunmillArtifactKind::Review => "REVIEW_REPORT",
        RunmillArtifactKind::WorkOrderEnvelope
        | RunmillArtifactKind::EffectivePolicy
        | RunmillArtifactKind::RuntimeManifest => "PROVENANCE",
        RunmillArtifactKind::AgentOutcome => "TRANSCRIPT",
        RunmillArtifactKind::SideEffect | RunmillArtifactKind::Approval => "OTHER",
    }
}

const fn artifact_kind_database_value(kind: RunmillArtifactKind) -> &'static str {
    match kind {
        RunmillArtifactKind::WorkOrderEnvelope => "work-order-envelope",
        RunmillArtifactKind::EffectivePolicy => "effective-policy",
        RunmillArtifactKind::NormalizedDiff => "normalized-diff",
        RunmillArtifactKind::AgentOutcome => "agent-outcome",
        RunmillArtifactKind::Verification => "verification",
        RunmillArtifactKind::CiObservation => "ci-observation",
        RunmillArtifactKind::Review => "review",
        RunmillArtifactKind::SideEffect => "side-effect",
        RunmillArtifactKind::Approval => "approval",
        RunmillArtifactKind::RuntimeManifest => "runtime-manifest",
    }
}

/// The same durable retention vocabulary, reached from the unsigned control
/// listing rather than from the signed manifest.
const fn control_retention_database_value(retention: ControlRetentionClass) -> &'static str {
    match retention {
        ControlRetentionClass::Portable => "portable",
        ControlRetentionClass::Protected => "protected",
        ControlRetentionClass::Restricted => "restricted",
    }
}

const fn retention_database_value(retention: RunmillRetentionClass) -> &'static str {
    match retention {
        RunmillRetentionClass::Portable => "portable",
        RunmillRetentionClass::Protected => "protected",
        RunmillRetentionClass::Restricted => "restricted",
    }
}

const fn closure_target_database_value(target: RunmillClosureTarget) -> &'static str {
    match target {
        RunmillClosureTarget::Pr => "pull_request",
    }
}

fn algorithm_database_value(bundle: &SignedRunmillEvidenceBundle) -> Result<String> {
    match serde_json::to_value(bundle.algorithm) {
        Ok(Value::String(value)) => Ok(value),
        _ => Err(Error::Serialization(
            "Runmill evidence algorithm cannot be encoded as its database value".into(),
        )),
    }
}

fn require_document_size(length: usize, description: &str) -> Result<()> {
    if !(MIN_EVIDENCE_DOCUMENT_BYTES..=MAX_EVIDENCE_DOCUMENT_BYTES).contains(&length) {
        return Err(Error::Validation(format!(
            "{description} must be between 2 bytes and 2 MiB"
        )));
    }
    Ok(())
}

fn required_column<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!("read {description} from Runmill evidence: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationships_and_kinds_cover_every_signed_artifact_kind() {
        for kind in [
            RunmillArtifactKind::WorkOrderEnvelope,
            RunmillArtifactKind::EffectivePolicy,
            RunmillArtifactKind::NormalizedDiff,
            RunmillArtifactKind::AgentOutcome,
            RunmillArtifactKind::Verification,
            RunmillArtifactKind::CiObservation,
            RunmillArtifactKind::Review,
            RunmillArtifactKind::SideEffect,
            RunmillArtifactKind::Approval,
            RunmillArtifactKind::RuntimeManifest,
        ] {
            // Both values are database-constrained; neither may ever be blank.
            assert!(
                [
                    "LOG",
                    "DIFF",
                    "CHECK_REPORT",
                    "REVIEW_REPORT",
                    "PROVENANCE",
                    "TRANSCRIPT",
                    "OTHER"
                ]
                .contains(&artifact_relationship(kind))
            );
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                Value::String(artifact_kind_database_value(kind).into())
            );
        }
    }

    #[test]
    fn retention_and_target_values_match_their_database_domains() {
        for retention in [
            RunmillRetentionClass::Portable,
            RunmillRetentionClass::Protected,
            RunmillRetentionClass::Restricted,
        ] {
            assert!(
                ["portable", "protected", "restricted"]
                    .contains(&retention_database_value(retention))
            );
        }
        assert_eq!(
            closure_target_database_value(RunmillClosureTarget::Pr),
            "pull_request"
        );
    }

    #[test]
    fn insert_reproduces_the_signed_columns_and_never_verifies() {
        for column in [
            "payload_digest",
            "work_order_digest",
            "canonical_payload",
            "exact_signed_envelope",
            "target_satisfied",
            "produced_at",
        ] {
            assert!(INSERT_EVIDENCE_SQL.contains(column), "missing {column}");
        }
        assert!(INSERT_EVIDENCE_SQL.contains("ON CONFLICT DO NOTHING"));
        // Ingestion retains; it never records a verdict or closes anything.
        for forbidden in ["evidence_verifications", "UPDATE runs", "work_items"] {
            assert!(
                !INSERT_EVIDENCE_SQL.contains(forbidden),
                "ingestion must not touch {forbidden}"
            );
        }
        assert!(LOAD_RUN_EXPECTATION_SQL.contains("run.authoritative"));
    }
}
