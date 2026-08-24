//! Append-only persistence for Runmill terminal evidence bundles.
//!
//! A terminal evidence bundle is the durable proof that one exact ASF run
//! reached one exact terminal phase at one exact external event sequence. This
//! module is a persistence primitive only: it retains the exact successful
//! `asf.get_evidence` wire and the signed envelope that wire carried, together
//! with the coordinates that make them attributable. It never projects Runmill
//! events into `raw_run_events`, never updates `runs`, and never advances an
//! observation stream.
//!
//! The signer is never taken on trust. Nothing is inserted until the fenced
//! worker session's own signing authority has been read under `FOR SHARE` and
//! the retained envelope has verified against exactly that key, issued inside
//! exactly that session's signing window. What is then proved is that the
//! retained row cannot disagree with the retained bytes, exactly as migration
//! 0035's insert guard re-proves under lock.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::persistence_error;
use crate::{
    Error, Result,
    adapters::runmill_control::{RunmillEvidenceView, RunmillRunPhase, RunmillValidatedRead},
    contracts::{ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA, SignedAsfTerminalEvidenceBundle},
    crypto::{canonical_json, decode_verifying_key, is_sha256_digest, sha256_digest},
};

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_EVIDENCE_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MIN_EVIDENCE_DOCUMENT_BYTES: usize = 2;
const TERMINAL_SIGNATURE_PREFIX: &str = "base64url:";
const ED25519_BASE64URL_LENGTH: usize = 86;
const GET_RUN: &str = "GET_RUN";
const LIST_RUN_EVENTS: &str = "LIST_RUN_EVENTS";
/// A revoked session's key is withdrawn retroactively, so nothing it ever
/// signed is trusted here — not even a bundle issued inside its own window.
const REVOKED_SESSION_STATUS: &str = "REVOKED";

/// The signing authority of the exact worker session this bundle is fenced to.
///
/// The session is named by all four of its immutable coordinates, so a bundle
/// cannot borrow the key of a different session, worker, or generation. The row
/// is taken `FOR SHARE` so the authority cannot be rotated, closed, or revoked
/// between this check and the insert that depends on it.
const LOAD_SIGNING_SESSION_SQL: &str = r"
SELECT signing_key_id, signing_public_key, started_at, expires_at, closed_at, status
FROM worker_sessions
WHERE tenant_id = $1
  AND id = $2
  AND worker_id = $3
  AND worker_generation = $4
FOR SHARE
";

/// One control snapshot (0021) in the exact role and ownership this bundle
/// claims. Both roles are proved before the bundle row is written so a
/// mispaired snapshot fails as a named ASF conflict rather than as an opaque
/// trigger abort.
const LOAD_CONTROL_SNAPSHOT_SQL: &str = r"
SELECT observation_id, external_latest_sequence
FROM runmill_control_snapshots
WHERE tenant_id = $1
  AND id = $2
  AND control_operation = $3
  AND run_id = $4
  AND work_item_id = $5
  AND attempt_id = $6
  AND work_order_id = $7
  AND work_order_digest = $8
  AND worker_session_id = $9
  AND worker_id = $10
  AND worker_generation = $11
  AND external_run_id = $12
FOR SHARE
";

const INSERT_BUNDLE_SQL: &str = r"
INSERT INTO runmill_terminal_evidence_bundles (
    id, tenant_id, run_id, work_item_id, attempt_id, work_order_id,
    work_order_digest, worker_session_id, worker_id, worker_generation,
    external_run_id, get_run_snapshot_id, event_page_snapshot_id,
    terminal_evidence_response_wire_digest, exact_terminal_evidence_response_wire,
    terminal_bundle_digest, terminal_phase, terminal_event_seq, base_sha,
    candidate_sha, canonical_statement, statement_digest, predicate,
    envelope_schema, signature_algorithm, signing_key_id, terminal_signature,
    exact_signed_envelope, issued_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29
)
ON CONFLICT DO NOTHING
RETURNING id, statement_digest
";

const LOAD_BUNDLE_SQL: &str = r"
SELECT
    id, run_id, work_item_id, attempt_id, work_order_id, work_order_digest,
    worker_session_id, worker_id, worker_generation, external_run_id,
    get_run_snapshot_id, event_page_snapshot_id,
    terminal_evidence_response_wire_digest, exact_terminal_evidence_response_wire,
    terminal_bundle_digest, terminal_phase, terminal_event_seq, base_sha,
    candidate_sha, canonical_statement, statement_digest, predicate,
    envelope_schema, signature_algorithm, signing_key_id, terminal_signature,
    exact_signed_envelope, issued_at
FROM runmill_terminal_evidence_bundles
WHERE tenant_id = $1
  AND (
      id = $2
      OR (run_id = $3 AND terminal_bundle_digest = $4)
  )
FOR SHARE
";

/// The exact local ownership coordinates, the two control snapshots, and the
/// terminal observation that a retained terminal evidence bundle must bind.
///
/// Every field here is something the caller already proved. Nothing in this
/// module invents a coordinate: the evidence view and its signed envelope are
/// checked against these values and refused when they disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillTerminalEvidenceFence {
    /// Immutable identity of the bundle row this call intends to write.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub work_order_id: Uuid,
    pub work_order_digest: String,
    /// Immutable worker session that admitted the run.
    pub worker_session_id: Uuid,
    pub worker_id: Uuid,
    pub worker_generation: i64,
    /// Runmill's own external run identity, unrelated to `run_id`.
    pub external_run_id: String,
    /// The exact `GET_RUN` control snapshot the terminal phase was read from.
    pub get_run_snapshot_id: Uuid,
    /// The exact `LIST_RUN_EVENTS` control snapshot the terminal sequence was
    /// read from.
    pub event_page_snapshot_id: Uuid,
    /// The terminal phase the caller already observed for this run.
    pub terminal_phase: RunmillRunPhase,
    /// External sequence of the terminal event itself, one past the last
    /// sequence the event page observed.
    pub terminal_event_seq: i64,
}

impl RunmillTerminalEvidenceFence {
    /// The logical identity of this retention. Two calls that name the same
    /// tenant, run, and terminal bundle digest are the same durable fact, and
    /// the second is a replay rather than a second bundle. The bundle row's own
    /// uuid is deliberately not part of the key: a retried retention that mints
    /// a fresh row identity is still the same fact.
    #[must_use]
    pub fn idempotency_key(&self, terminal_bundle_digest: &str) -> String {
        format!(
            "runmill-terminal-evidence:{}:{}:{}",
            self.tenant_id, self.run_id, terminal_bundle_digest
        )
    }

    fn validate(&self) -> Result<()> {
        if [
            self.id,
            self.tenant_id,
            self.run_id,
            self.work_item_id,
            self.attempt_id,
            self.work_order_id,
            self.worker_session_id,
            self.worker_id,
            self.get_run_snapshot_id,
            self.event_page_snapshot_id,
        ]
        .into_iter()
        .any(|value| value.is_nil())
        {
            return Err(Error::Validation(
                "Runmill terminal evidence provenance requires non-nil IDs".into(),
            ));
        }
        if self.get_run_snapshot_id == self.event_page_snapshot_id {
            return Err(Error::Validation(
                "Runmill terminal evidence requires two distinct control snapshots".into(),
            ));
        }
        if !is_sha256_digest(&self.work_order_digest)
            || self.worker_generation <= 0
            || self.external_run_id.trim().is_empty()
        {
            return Err(Error::Validation(
                "Runmill terminal evidence provenance has an invalid Work Order digest, worker generation, or external run ID"
                    .into(),
            ));
        }
        if !self.terminal_phase.terminal() {
            return Err(Error::Validation(
                "Runmill terminal evidence requires a terminal run phase".into(),
            ));
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.terminal_event_seq) {
            return Err(Error::Validation(
                "Runmill terminal event sequence is outside the supported safe-integer range"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Result of idempotently retaining one terminal evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillTerminalEvidenceOutcome {
    pub bundle_id: Uuid,
    /// False when an identical bundle was already durable.
    pub inserted: bool,
    pub idempotency_key: String,
    pub terminal_bundle_digest: String,
    pub statement_digest: String,
}

/// Every migration 0035 column reproduced from the exact retained bytes.
///
/// Nothing on this struct is separately caller-supplied: the fence is the
/// caller's already-proved ownership, and every other field is derived from the
/// exact `asf.get_evidence` wire and the signed envelope that wire carried, so
/// the row and the bytes cannot disagree. Building one is pure: it performs no
/// database I/O and no signature verification. Retention proves the signature
/// separately, against the fenced worker session's own signing authority, using
/// the [`signed_bundle`](Self::signed_bundle) this record keeps.
#[derive(Debug, Clone)]
pub struct RunmillTerminalEvidenceRecord {
    /// The ownership, snapshot pair, and terminal observation every derived
    /// field below was proved against.
    pub fence: RunmillTerminalEvidenceFence,
    /// The complete successful `asf.get_evidence` NDJSON line, newline included.
    pub exact_response_wire: Vec<u8>,
    /// SHA-256 of `exact_response_wire`, derived from those exact bytes.
    pub response_wire_digest: String,
    pub terminal_bundle_digest: String,
    /// The terminal phase in its exact database spelling.
    pub terminal_phase: String,
    pub terminal_event_seq: i64,
    pub base_sha: String,
    pub candidate_sha: Option<String>,
    /// The exact canonical (JCS) encoding of the signed in-toto statement.
    pub canonical_statement: Vec<u8>,
    /// SHA-256 of `canonical_statement`; the signer's own bundle digest.
    pub statement_digest: String,
    pub predicate: Value,
    pub envelope_schema: String,
    pub signature_algorithm: String,
    pub signing_key_id: String,
    pub terminal_signature: String,
    /// The exact signed terminal envelope JSON the evidence read returned.
    pub exact_signed_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    /// The parsed envelope those columns were reproduced from. Retention keeps
    /// it so the signature can be proved against the fenced worker session's
    /// trusted key without re-parsing bytes it has already validated.
    pub signed_bundle: SignedAsfTerminalEvidenceBundle,
}

/// Retain one Runmill terminal evidence bundle in a caller-owned transaction.
///
/// The read must be an exact successful `get-evidence` response for the fenced
/// run. Its `signed_terminal_bundle` is parsed as the ASF signed terminal
/// evidence contract, its statement is canonicalized, and every indexed column
/// is reproduced from those bytes. The database re-proves all of it under lock,
/// including that the two control snapshots carry the exact operation and
/// ownership claimed here and that the observation stream actually reached
/// `TERMINAL_READY`.
///
/// Before any of that reaches an insert, the signer is proved: the fenced
/// worker session's signing authority is read `FOR SHARE`, the envelope must
/// name that exact key and verify under it, and it must have been issued inside
/// that session's own signing window. A revoked session is refused outright.
///
/// This function never projects Runmill events and never updates `runs`.
pub async fn record_runmill_terminal_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    read: RunmillValidatedRead<RunmillEvidenceView>,
) -> Result<RunmillTerminalEvidenceOutcome> {
    sqlx::query("SAVEPOINT asf_runmill_terminal_evidence")
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("start Runmill terminal evidence savepoint", error))?;

    let result = record_runmill_terminal_evidence_inner(transaction, fence, read).await;
    if let Err(error) = result {
        sqlx::query("ROLLBACK TO SAVEPOINT asf_runmill_terminal_evidence")
            .execute(&mut **transaction)
            .await
            .map_err(|rollback_error| {
                persistence_error(
                    "roll back failed Runmill terminal evidence savepoint",
                    rollback_error,
                )
            })?;
        sqlx::query("RELEASE SAVEPOINT asf_runmill_terminal_evidence")
            .execute(&mut **transaction)
            .await
            .map_err(|release_error| {
                persistence_error(
                    "release failed Runmill terminal evidence savepoint",
                    release_error,
                )
            })?;
        return Err(error);
    }

    sqlx::query("RELEASE SAVEPOINT asf_runmill_terminal_evidence")
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("release Runmill terminal evidence savepoint", error))?;
    result
}

async fn record_runmill_terminal_evidence_inner(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    read: RunmillValidatedRead<RunmillEvidenceView>,
) -> Result<RunmillTerminalEvidenceOutcome> {
    let derived = RunmillTerminalEvidenceRecord::from_validated_read(fence, read)?;
    let idempotency_key = fence.idempotency_key(&derived.terminal_bundle_digest);
    // Trust first: an unsigned or wrongly-signed bundle is refused before it
    // can be matched against a replay or reach the insert.
    assert_trusted_signer(transaction, fence, &derived, &idempotency_key).await?;
    assert_snapshot_pairing(transaction, fence, &idempotency_key).await?;

    if let Some(replay) =
        load_terminal_evidence_replay(transaction, fence, &derived, &idempotency_key).await?
    {
        return Ok(replay);
    }

    let inserted = sqlx::query_as::<_, (Uuid, String)>(INSERT_BUNDLE_SQL)
        .bind(fence.id)
        .bind(fence.tenant_id)
        .bind(fence.run_id)
        .bind(fence.work_item_id)
        .bind(fence.attempt_id)
        .bind(fence.work_order_id)
        .bind(&fence.work_order_digest)
        .bind(fence.worker_session_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .bind(&fence.external_run_id)
        .bind(fence.get_run_snapshot_id)
        .bind(fence.event_page_snapshot_id)
        .bind(&derived.response_wire_digest)
        .bind(&derived.exact_response_wire)
        .bind(&derived.terminal_bundle_digest)
        .bind(&derived.terminal_phase)
        .bind(derived.terminal_event_seq)
        .bind(&derived.base_sha)
        .bind(derived.candidate_sha.as_ref())
        .bind(&derived.canonical_statement)
        .bind(&derived.statement_digest)
        .bind(&derived.predicate)
        .bind(&derived.envelope_schema)
        .bind(&derived.signature_algorithm)
        .bind(&derived.signing_key_id)
        .bind(&derived.terminal_signature)
        .bind(&derived.exact_signed_envelope)
        .bind(derived.issued_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("store Runmill terminal evidence bundle", error))?;

    let Some((stored_id, stored_statement_digest)) = inserted else {
        return load_terminal_evidence_replay(transaction, fence, &derived, &idempotency_key)
            .await?
            .ok_or_else(|| {
                Error::Conflict(format!(
                    "Runmill terminal evidence {idempotency_key} conflicts with an invisible retained bundle"
                ))
            });
    };
    if stored_statement_digest != derived.statement_digest {
        return Err(Error::Persistence(
            "Runmill terminal evidence statement digest disagrees with ledger semantics".into(),
        ));
    }

    Ok(RunmillTerminalEvidenceOutcome {
        bundle_id: stored_id,
        inserted: true,
        idempotency_key,
        terminal_bundle_digest: derived.terminal_bundle_digest,
        statement_digest: derived.statement_digest,
    })
}

impl RunmillTerminalEvidenceRecord {
    /// Reproduce every migration 0035 column from the exact successful
    /// `get-evidence` response and the signed envelope it carried.
    ///
    /// The fence is validated first, the read is consumed for its exact typed
    /// view, wire, and success data, and the retained bytes are then required
    /// to state this fence's run, ownership, terminal phase, and terminal
    /// sequence. Nothing here is taken on trust: every digest is re-derived
    /// from the bytes it is a digest of, exactly as the migration's insert
    /// guard re-proves under lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] when the fence is not a storable terminal
    /// claim, the wire is not one exact `{ok:true,data:...}` line, the evidence
    /// view or its signed envelope is not the exact contract, or any binding
    /// between the two disagrees with the fence.
    pub fn from_validated_read(
        fence: &RunmillTerminalEvidenceFence,
        read: RunmillValidatedRead<RunmillEvidenceView>,
    ) -> Result<Self> {
        fence.validate()?;
        let (typed_view, response_wire, data) = read.into_parts();
        Self::from_exact_evidence_read(fence, &typed_view, response_wire, &data)
    }

    /// The exact-bytes derivation, separated from [`RunmillValidatedRead`] so
    /// the bindings can be exercised against deliberately tampered evidence
    /// without a public way to forge control provenance.
    fn from_exact_evidence_read(
        fence: &RunmillTerminalEvidenceFence,
        typed_view: &RunmillEvidenceView,
        response_wire: Vec<u8>,
        data: &Value,
    ) -> Result<Self> {
        assert_exact_success_wire(&response_wire, data)?;
        let view = RunmillEvidenceView::validate_provenance_data(data).map_err(|_| {
            Error::Validation(
            "validated get-evidence proof no longer satisfies the exact Runmill response contract"
                .into(),
        )
        })?;
        if typed_view != &view {
            return Err(Error::Validation(
                "validated get-evidence proof typed value contradicts its exact response data"
                    .into(),
            ));
        }

        if view.run_id.as_str() != fence.external_run_id {
            return Err(Error::Validation(
                "Runmill evidence view names a different external run than its fence".into(),
            ));
        }
        if view.work_order_id != fence.work_order_id.to_string()
            || view.attempt_id != fence.attempt_id.to_string()
        {
            return Err(Error::Validation(
                "Runmill evidence view ownership contradicts its fence".into(),
            ));
        }
        if view.phase != fence.terminal_phase {
            return Err(Error::Validation(
                "Runmill evidence view phase contradicts the fenced terminal phase".into(),
            ));
        }
        let latest_sequence = i64::try_from(view.latest_sequence).map_err(|_| {
            Error::Validation("Runmill evidence latest sequence overflows PostgreSQL bigint".into())
        })?;
        if latest_sequence != fence.terminal_event_seq {
            return Err(Error::Validation(
            "Runmill evidence view latest sequence contradicts the fenced terminal event sequence"
                .into(),
        ));
        }

        let terminal_bundle_digest = view.terminal_bundle_digest.as_deref().ok_or_else(|| {
            Error::Validation("Runmill evidence view carries no terminal bundle digest".into())
        })?;
        if !is_sha256_digest(terminal_bundle_digest) {
            return Err(Error::Validation(
                "Runmill terminal bundle digest is not a SHA-256 digest".into(),
            ));
        }
        let signed_terminal_bundle = view.signed_terminal_bundle.as_ref().ok_or_else(|| {
            Error::Validation("Runmill evidence view carries no signed terminal bundle".into())
        })?;

        let bundle = SignedAsfTerminalEvidenceBundle::from_json(signed_terminal_bundle)?;
        if bundle.bundle_digest != terminal_bundle_digest {
            return Err(Error::Validation(
                "signed terminal bundle digest contradicts the evidence view's terminal digest"
                    .into(),
            ));
        }

        let statement = serde_json::to_value(&bundle.statement).map_err(|error| {
            Error::Serialization(format!("serialize terminal evidence statement: {error}"))
        })?;
        let canonical_statement = canonical_json(&statement)?;
        let statement_digest = sha256_digest(&canonical_statement);
        if statement_digest != bundle.bundle_digest {
            return Err(Error::Validation(
                "terminal evidence statement digest contradicts the signer's bundle digest".into(),
            ));
        }
        require_document_size(
            canonical_statement.len(),
            "terminal evidence canonical statement",
        )?;
        let predicate = statement
            .get("predicate")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| {
                Error::Validation("terminal evidence statement carries no predicate object".into())
            })?;

        let run = &bundle.statement.predicate.run;
        let terminal_phase = phase_database_value(fence.terminal_phase)?;
        let terminal_event_seq = i64::try_from(run.terminal_event_seq).map_err(|_| {
            Error::Validation("terminal event sequence overflows PostgreSQL bigint".into())
        })?;
        if run.run_id != fence.external_run_id
            || run.work_order_id != fence.work_order_id.to_string()
            || run.attempt_id != fence.attempt_id.to_string()
            || run.terminal_phase != terminal_phase
            || terminal_event_seq != fence.terminal_event_seq
        {
            return Err(Error::Validation(
                "terminal evidence predicate run binding contradicts its fence".into(),
            ));
        }
        if bundle
            .statement
            .predicate
            .admission
            .work_order_payload_digest
            != fence.work_order_digest
        {
            return Err(Error::Validation(
                "terminal evidence admission contradicts the fenced Work Order digest".into(),
            ));
        }

        let source = &bundle.statement.predicate.source;
        if !is_git_sha(&source.base_sha)
            || source
                .candidate_sha
                .as_deref()
                .is_some_and(|sha| !is_git_sha(sha))
        {
            return Err(Error::Validation(
                "terminal evidence source commits are not 40-character lowercase SHA-1 values"
                    .into(),
            ));
        }
        // The read that returned the envelope must name the same candidate the
        // signer attested to; a disagreement is contradictory evidence, never a
        // storable bundle.
        if view.candidate_sha != source.candidate_sha {
            return Err(Error::Validation(
                "Runmill evidence view candidate commit contradicts its signed source".into(),
            ));
        }

        if bundle.schema != ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA
            || bundle.algorithm != "EdDSA"
            || bundle.key_id.trim().is_empty()
            || !is_terminal_signature(&bundle.signature)
        {
            return Err(Error::Validation(
                "signed terminal evidence envelope is not the exact EdDSA signing contract".into(),
            ));
        }
        let issued_at = DateTime::parse_from_rfc3339(&bundle.issued_at)
            .map_err(|error| {
                Error::Validation(format!(
                    "signed terminal evidence issued_at is not an RFC 3339 instant: {error}"
                ))
            })?
            .with_timezone(&Utc);

        let exact_signed_envelope =
            serde_json::to_vec(signed_terminal_bundle).map_err(|error| {
                Error::Serialization(format!(
                    "serialize signed terminal evidence envelope: {error}"
                ))
            })?;
        require_document_size(
            exact_signed_envelope.len(),
            "signed terminal evidence envelope",
        )?;

        let response_wire_digest = sha256_digest(&response_wire);
        Ok(Self {
            fence: fence.clone(),
            exact_response_wire: response_wire,
            response_wire_digest,
            terminal_bundle_digest: terminal_bundle_digest.to_owned(),
            terminal_phase,
            terminal_event_seq,
            base_sha: source.base_sha.clone(),
            candidate_sha: source.candidate_sha.clone(),
            canonical_statement,
            statement_digest,
            predicate,
            envelope_schema: bundle.schema.clone(),
            signature_algorithm: bundle.algorithm.clone(),
            signing_key_id: bundle.key_id.clone(),
            terminal_signature: bundle.signature.clone(),
            exact_signed_envelope,
            issued_at,
            signed_bundle: bundle,
        })
    }
}

/// One trusted terminal evidence signer, exactly as the caller resolved it.
///
/// This is the caller's already-resolved trust decision reduced to the four
/// things a retained bundle can be checked against: which key signed it, the
/// key's public half, the window the key was allowed to sign in, and whether
/// that key has since been revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunmillTerminalEvidenceSigner {
    /// The key identity the envelope must name.
    pub key_id: String,
    /// Base64url-encoded Ed25519 verifying key for [`key_id`](Self::key_id).
    pub public_key: String,
    /// First instant this key was allowed to sign, inclusive.
    pub valid_from: DateTime<Utc>,
    /// First instant this key was no longer allowed to sign, exclusive.
    pub valid_until: DateTime<Utc>,
    /// True once the key is withdrawn; a revoked key verifies nothing.
    pub revoked: bool,
}

/// Verify that one retained terminal evidence bundle was signed by this exact
/// trusted signer, in force at the instant the bundle claims it was issued.
///
/// The signer must be a usable trust statement: a non-empty key identity and
/// public key, not revoked, and a non-empty validity window. The bundle must
/// name that same key identity and state an RFC 3339 issuance inside
/// `[valid_from, valid_until)` — the upper bound is exclusive so a key's last
/// instant and its successor's first instant cannot both accept one bundle.
/// Only then is the envelope's own integrity proved against the signer's public
/// key with [`SignedAsfTerminalEvidenceBundle::verify_wire_integrity_only`].
///
/// This is a pure check: it performs no database I/O and decides nothing about
/// whether the bundle may be retained.
///
/// # Errors
///
/// Returns [`Error::Validation`] when the signer is not a usable trust
/// statement or the bundle's `issued_at` is not an RFC 3339 instant, and
/// [`Error::Crypto`] when the bundle names a different key, the signer is
/// revoked, the issuance falls outside the key's window, or the envelope's
/// digest or signature does not verify under the signer's public key.
pub fn verify_terminal_bundle_signer(
    bundle: &SignedAsfTerminalEvidenceBundle,
    signer: &RunmillTerminalEvidenceSigner,
) -> Result<()> {
    if signer.key_id.trim().is_empty() || signer.public_key.trim().is_empty() {
        return Err(Error::Validation(
            "terminal evidence signer requires a non-empty key ID and public key".into(),
        ));
    }
    if signer.valid_from >= signer.valid_until {
        return Err(Error::Validation(
            "terminal evidence signer validity window is empty".into(),
        ));
    }
    if bundle.key_id != signer.key_id {
        return Err(Error::Crypto(
            "signed terminal evidence names a different signing key than its trusted signer".into(),
        ));
    }
    if signer.revoked {
        return Err(Error::Crypto(
            "signed terminal evidence names a revoked terminal evidence signer".into(),
        ));
    }

    let issued_at = DateTime::parse_from_rfc3339(&bundle.issued_at)
        .map_err(|error| {
            Error::Validation(format!(
                "signed terminal evidence issued_at is not an RFC 3339 instant: {error}"
            ))
        })?
        .with_timezone(&Utc);
    if issued_at < signer.valid_from || issued_at >= signer.valid_until {
        return Err(Error::Crypto(
            "signed terminal evidence was issued outside its signing key's validity window".into(),
        ));
    }

    bundle.verify_wire_integrity_only(&signer.public_key)
}

/// The retained wire must be one complete newline-terminated Runmill success
/// envelope whose only keys are `ok` and `data`, with `data` the exact value
/// the typed response was parsed from.
fn assert_exact_success_wire(response_wire: &[u8], data: &Value) -> Result<()> {
    if response_wire.len() > MAX_EVIDENCE_DOCUMENT_BYTES
        || response_wire.len() < MIN_EVIDENCE_DOCUMENT_BYTES
        || response_wire.last() != Some(&b'\n')
        || response_wire[..response_wire.len() - 1].contains(&b'\n')
    {
        return Err(Error::Validation(
            "Runmill evidence response wire must be newline-terminated and at most 2 MiB".into(),
        ));
    }
    let response = serde_json::from_slice::<Value>(response_wire).map_err(|_| {
        Error::Validation("Runmill evidence response wire must be UTF-8 JSON".into())
    })?;
    let Some(envelope) = response.as_object() else {
        return Err(Error::Validation(
            "Runmill evidence response wire must be a success envelope object".into(),
        ));
    };
    if envelope.len() != 2
        || envelope.get("ok") != Some(&Value::Bool(true))
        || envelope.get("data") != Some(data)
    {
        return Err(Error::Validation(
            "Runmill evidence response wire must be exactly {ok:true,data:evidence}".into(),
        ));
    }
    Ok(())
}

/// The last instant a worker session could still have signed, exclusive.
///
/// A session stops signing when it closes or when it expires, whichever comes
/// first. A session closed after it had already expired never reopens the gap
/// between the two, and one closed before expiry never keeps signing to expiry.
fn session_signing_window_end(
    expires_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    closed_at.map_or(expires_at, |closed_at| closed_at.min(expires_at))
}

/// Nothing is retained until the fenced worker session itself vouches for the
/// signature. The session's signing authority is read under `FOR SHARE`, the
/// envelope must name that exact key, and it must have been issued inside the
/// session's own half-open signing window `[started_at, min(closed_at,
/// expires_at))`. A revoked session vouches for nothing.
///
/// This is mandatory: an unverifiable bundle is refused rather than retained,
/// because a retained bundle is durable proof and a proof nobody signed is not
/// a proof.
async fn assert_trusted_signer(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    derived: &RunmillTerminalEvidenceRecord,
    idempotency_key: &str,
) -> Result<()> {
    let session = sqlx::query(LOAD_SIGNING_SESSION_SQL)
        .bind(fence.tenant_id)
        .bind(fence.worker_session_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| {
            persistence_error("load Runmill terminal evidence signing session", error)
        })?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "Runmill terminal evidence {idempotency_key} names a worker session that does not carry its exact ownership"
            ))
        })?;

    let public_key: String = required_column(
        &session,
        "signing_public_key",
        "worker-session signing public key",
    )?;
    let expires_at: DateTime<Utc> =
        required_column(&session, "expires_at", "worker-session expiry")?;
    let closed_at: Option<DateTime<Utc>> =
        optional_column(&session, "closed_at", "worker-session close")?;
    let status: String = required_column(&session, "status", "worker-session status")?;

    // A persisted key that cannot be decoded is a ledger fault, not a claim
    // about this bundle, so it is named as one rather than as a bad signature.
    decode_verifying_key(&public_key).map_err(|error| {
        Error::Persistence(format!(
            "Runmill terminal evidence {idempotency_key} names a worker session whose signing public key is unusable: {error}"
        ))
    })?;

    let signer = RunmillTerminalEvidenceSigner {
        key_id: required_column(&session, "signing_key_id", "worker-session signing key")?,
        public_key,
        valid_from: required_column(&session, "started_at", "worker-session start")?,
        valid_until: session_signing_window_end(expires_at, closed_at),
        revoked: status == REVOKED_SESSION_STATUS,
    };
    verify_terminal_bundle_signer(&derived.signed_bundle, &signer).map_err(|error| {
        Error::Validation(format!(
            "Runmill terminal evidence {idempotency_key} is not signed by its worker session's trusted key: {error}"
        ))
    })
}

/// Both control snapshots must carry this bundle's exact ownership in their
/// exact roles, belong to one observation, and leave the event page one
/// sequence below the terminal event. The trigger re-proves this under lock;
/// checking it here turns a mispairing into a named ASF conflict.
async fn assert_snapshot_pairing(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    idempotency_key: &str,
) -> Result<()> {
    let get_run = load_control_snapshot(transaction, fence, GET_RUN, fence.get_run_snapshot_id)
        .await?
        .ok_or_else(|| {
            Error::Conflict(format!(
                "Runmill terminal evidence {idempotency_key} names a GET_RUN snapshot that does not carry its exact ownership"
            ))
        })?;
    let event_page = load_control_snapshot(
        transaction,
        fence,
        LIST_RUN_EVENTS,
        fence.event_page_snapshot_id,
    )
    .await?
    .ok_or_else(|| {
        Error::Conflict(format!(
            "Runmill terminal evidence {idempotency_key} names a LIST_RUN_EVENTS snapshot that does not carry its exact ownership"
        ))
    })?;

    let observation: Option<Uuid> =
        optional_column(&get_run, "observation_id", "GET_RUN observation")?;
    let page_observation: Option<Uuid> =
        optional_column(&event_page, "observation_id", "event page observation")?;
    if observation.is_none() || observation != page_observation {
        return Err(Error::Conflict(format!(
            "Runmill terminal evidence {idempotency_key} pairs snapshots from different observations"
        )));
    }

    let observed: i64 = required_column(
        &event_page,
        "external_latest_sequence",
        "event page latest sequence",
    )?;
    if observed != fence.terminal_event_seq - 1 {
        return Err(Error::Conflict(format!(
            "Runmill terminal evidence {idempotency_key} contradicts the event page's observed sequence boundary"
        )));
    }
    Ok(())
}

async fn load_control_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    operation: &str,
    snapshot_id: Uuid,
) -> Result<Option<PgRow>> {
    sqlx::query(LOAD_CONTROL_SNAPSHOT_SQL)
        .bind(fence.tenant_id)
        .bind(snapshot_id)
        .bind(operation)
        .bind(fence.run_id)
        .bind(fence.work_item_id)
        .bind(fence.attempt_id)
        .bind(fence.work_order_id)
        .bind(&fence.work_order_digest)
        .bind(fence.worker_session_id)
        .bind(fence.worker_id)
        .bind(fence.worker_generation)
        .bind(&fence.external_run_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| {
            persistence_error("load Runmill terminal evidence control snapshot", error)
        })
}

/// Resolve an already-durable identical bundle. A retained row that shares this
/// identity but states different semantics is always a conflict, never an
/// overwrite: bundles are append-only and corrections are new bundles.
async fn load_terminal_evidence_replay(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &RunmillTerminalEvidenceFence,
    derived: &RunmillTerminalEvidenceRecord,
    idempotency_key: &str,
) -> Result<Option<RunmillTerminalEvidenceOutcome>> {
    let rows = sqlx::query(LOAD_BUNDLE_SQL)
        .bind(fence.tenant_id)
        .bind(fence.id)
        .bind(fence.run_id)
        .bind(&derived.terminal_bundle_digest)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| persistence_error("load Runmill terminal evidence bundle", error))?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != 1 || !bundle_matches(&rows[0], fence, derived)? {
        return Err(Error::Conflict(format!(
            "Runmill terminal evidence {idempotency_key} was reused for different semantics"
        )));
    }
    Ok(Some(RunmillTerminalEvidenceOutcome {
        bundle_id: required_column(&rows[0], "id", "terminal evidence bundle ID")?,
        inserted: false,
        idempotency_key: idempotency_key.to_owned(),
        terminal_bundle_digest: derived.terminal_bundle_digest.clone(),
        statement_digest: derived.statement_digest.clone(),
    }))
}

fn bundle_matches(
    row: &PgRow,
    fence: &RunmillTerminalEvidenceFence,
    derived: &RunmillTerminalEvidenceRecord,
) -> Result<bool> {
    Ok(required_column::<Uuid>(row, "id", "bundle ID")? == fence.id
        && required_column::<Uuid>(row, "run_id", "bundle run")? == fence.run_id
        && required_column::<Uuid>(row, "work_item_id", "bundle work item")? == fence.work_item_id
        && required_column::<Uuid>(row, "attempt_id", "bundle attempt")? == fence.attempt_id
        && required_column::<Uuid>(row, "work_order_id", "bundle Work Order")?
            == fence.work_order_id
        && required_column::<String>(row, "work_order_digest", "bundle Work Order digest")?
            == fence.work_order_digest
        && required_column::<Uuid>(row, "worker_session_id", "bundle worker session")?
            == fence.worker_session_id
        && required_column::<Uuid>(row, "worker_id", "bundle worker")? == fence.worker_id
        && required_column::<i64>(row, "worker_generation", "bundle worker generation")?
            == fence.worker_generation
        && required_column::<String>(row, "external_run_id", "bundle external run")?
            == fence.external_run_id
        && required_column::<Uuid>(row, "get_run_snapshot_id", "bundle GET_RUN snapshot")?
            == fence.get_run_snapshot_id
        && required_column::<Uuid>(
            row,
            "event_page_snapshot_id",
            "bundle LIST_RUN_EVENTS snapshot",
        )? == fence.event_page_snapshot_id
        && required_column::<Vec<u8>>(
            row,
            "exact_terminal_evidence_response_wire",
            "bundle evidence wire",
        )? == derived.exact_response_wire
        && required_column::<String>(
            row,
            "terminal_evidence_response_wire_digest",
            "bundle evidence wire digest",
        )? == derived.response_wire_digest
        && required_column::<String>(row, "terminal_bundle_digest", "bundle terminal digest")?
            == derived.terminal_bundle_digest
        && required_column::<String>(row, "terminal_phase", "bundle terminal phase")?
            == derived.terminal_phase
        && required_column::<i64>(row, "terminal_event_seq", "bundle terminal sequence")?
            == derived.terminal_event_seq
        && required_column::<String>(row, "base_sha", "bundle base commit")? == derived.base_sha
        && optional_column::<String>(row, "candidate_sha", "bundle candidate commit")?
            == derived.candidate_sha
        && required_column::<Vec<u8>>(row, "canonical_statement", "bundle canonical statement")?
            == derived.canonical_statement
        && required_column::<String>(row, "statement_digest", "bundle statement digest")?
            == derived.statement_digest
        && required_column::<Value>(row, "predicate", "bundle predicate")? == derived.predicate
        && required_column::<String>(row, "envelope_schema", "bundle envelope schema")?
            == derived.envelope_schema
        && required_column::<String>(row, "signature_algorithm", "bundle algorithm")?
            == derived.signature_algorithm
        && required_column::<String>(row, "signing_key_id", "bundle signing key")?
            == derived.signing_key_id
        && required_column::<String>(row, "terminal_signature", "bundle signature")?
            == derived.terminal_signature
        && required_column::<Vec<u8>>(row, "exact_signed_envelope", "bundle signed envelope")?
            == derived.exact_signed_envelope
        && required_column::<DateTime<Utc>>(row, "issued_at", "bundle issuance")?
            == derived.issued_at)
}

fn phase_database_value(phase: RunmillRunPhase) -> Result<String> {
    match serde_json::to_value(phase) {
        Ok(Value::String(value)) => Ok(value),
        _ => Err(Error::Serialization(
            "Runmill run phase cannot be encoded as its database value".into(),
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

fn is_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// An Ed25519 signature is 64 bytes, i.e. exactly 86 unpadded base64url
/// characters behind the contract's transport prefix.
fn is_terminal_signature(value: &str) -> bool {
    value
        .strip_prefix(TERMINAL_SIGNATURE_PREFIX)
        .is_some_and(|encoded| {
            encoded.len() == ED25519_BASE64URL_LENGTH
                && encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

fn required_column<T>(row: &PgRow, column: &str, description: &str) -> Result<T>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!(
            "read {description} from Runmill terminal evidence provenance: {error}"
        ))
    })
}

fn optional_column<T>(row: &PgRow, column: &str, description: &str) -> Result<Option<T>>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(|error| {
        Error::Persistence(format!(
            "read optional {description} from Runmill terminal evidence provenance: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        adapters::runmill_control::RUNMILL_EVIDENCE_VIEW_SCHEMA,
        contracts::{
            ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA, ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE,
            ASF_TERMINAL_IN_TOTO_STATEMENT_V1, AsfTerminalEvidenceStatement,
        },
        crypto::{Ed25519Signer, encode_verifying_key},
    };

    const BUNDLE_ISSUED_AT: &str = "2026-08-24T17:00:00Z";
    const BUNDLE_ADMITTED_AT: &str = "2026-08-24T16:59:00Z";

    fn valid_fence() -> RunmillTerminalEvidenceFence {
        RunmillTerminalEvidenceFence {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            work_order_digest: format!("sha256:{}", "a".repeat(64)),
            worker_session_id: Uuid::now_v7(),
            worker_id: Uuid::now_v7(),
            worker_generation: 1,
            external_run_id: "run-123".into(),
            get_run_snapshot_id: Uuid::now_v7(),
            event_page_snapshot_id: Uuid::now_v7(),
            terminal_phase: RunmillRunPhase::Completed,
            terminal_event_seq: 10,
        }
    }

    /// One in-toto terminal evidence statement that satisfies the signed
    /// terminal evidence contract's own bindings, so a bundle built from it
    /// parses and can then be genuinely signed.
    fn terminal_statement() -> Value {
        json!({
            "_type": ASF_TERMINAL_IN_TOTO_STATEMENT_V1,
            "predicateType": ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE,
            "subject": [{
                "name": "asf-run:run-123",
                "digest": {"sha1": "c".repeat(40)},
            }],
            "predicate": {
                "schema": ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA,
                "run": {
                    "run_id": "run-123",
                    "work_order_id": "wo-456",
                    "attempt_id": "attempt-789",
                    "terminal_phase": "COMPLETED",
                    "terminal_event_seq": 10,
                },
                "admission": {
                    "work_order_envelope_digest": format!("sha256:{}", "1".repeat(64)),
                    "work_order_payload_digest": format!("sha256:{}", "a".repeat(64)),
                    "effective_policy_digest": format!("sha256:{}", "3".repeat(64)),
                    "work_order_envelope": {},
                    "signature_verification": {
                        "verified": true,
                        "key_id": "admission-key-1",
                        "algorithm": "EdDSA",
                    },
                    "effective_policy": {},
                },
                "source": {
                    "repository": "owner/repo",
                    "base_sha": "b".repeat(40),
                    "candidate_sha": "c".repeat(40),
                    "subject_kind": "candidate",
                    "subject_sha": "c".repeat(40),
                },
                "stop": {
                    "code": "SUCCESS",
                    "summary": "Run completed successfully",
                    "interrupted_phase": "delivery",
                    "retry_disposition": "safe",
                    "required_actor": "asf",
                    "required_action": "none",
                    "evidence_refs": [],
                },
                "cancellation": null,
                "budget": {
                    "wall_seconds_limit": 3600,
                    "max_cost_usd": 10.0,
                    "max_agent_invocations": 100,
                    "max_fix_iterations": 5,
                    "observed_fix_iterations": 2,
                    "evidence_refs": [],
                    "provider_usage": {},
                },
                "side_effects": {"effects": []},
                "timing": {
                    "admitted_at": BUNDLE_ADMITTED_AT,
                    "terminal_evidence_at": BUNDLE_ISSUED_AT,
                    "elapsed_ms": 60_000,
                },
                "cleanup": {
                    "intent_id": "intent-100",
                    "intent_digest": format!("sha256:{}", "5".repeat(64)),
                    "observation_digest": format!("sha256:{}", "6".repeat(64)),
                    "identity_leases": "released",
                    "repository_lease": "released",
                    "workspace": "removed",
                    "unresolved_effects": 0,
                },
                "evidence": {
                    "preceding_event_count": 9,
                    "preceding_event_chain_digest": format!("sha256:{}", "7".repeat(64)),
                    "observations": [],
                    "events": [],
                    "delivery_bundle_digest": format!("sha256:{}", "8".repeat(64)),
                },
            },
        })
    }

    /// One exactly signed terminal evidence bundle and the trusted signer that
    /// signed it. The digest and signature are derived from the parsed bundle's
    /// own bytes, so wire integrity genuinely verifies rather than being
    /// asserted around.
    fn signed_terminal_bundle() -> (
        SignedAsfTerminalEvidenceBundle,
        RunmillTerminalEvidenceSigner,
    ) {
        let signer = Ed25519Signer::generate("terminal-key-1");
        let mut bundle = SignedAsfTerminalEvidenceBundle::from_json(&json!({
            "schema": ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA,
            "key_id": signer.key_id(),
            "algorithm": "EdDSA",
            "issued_at": BUNDLE_ISSUED_AT,
            "bundle_digest": format!("sha256:{}", "0".repeat(64)),
            "statement": terminal_statement(),
            "signature": format!("base64url:{}", "A".repeat(ED25519_BASE64URL_LENGTH)),
        }))
        .expect("terminal evidence fixture must satisfy the signed bundle contract");

        let statement = serde_json::to_value(&bundle.statement).unwrap();
        bundle.bundle_digest = sha256_digest(&canonical_json(&statement).unwrap());
        let unsigned = json!({
            "schema": bundle.schema,
            "key_id": bundle.key_id,
            "algorithm": bundle.algorithm,
            "issued_at": bundle.issued_at,
            "bundle_digest": bundle.bundle_digest,
            "statement": statement,
        });
        bundle.signature = format!(
            "base64url:{}",
            signer.sign(&canonical_json(&unsigned).unwrap())
        );

        let trusted = RunmillTerminalEvidenceSigner {
            key_id: signer.key_id().to_owned(),
            public_key: encode_verifying_key(&signer.verifying_key()),
            valid_from: "2026-08-24T00:00:00Z".parse().unwrap(),
            valid_until: "2026-08-25T00:00:00Z".parse().unwrap(),
            revoked: false,
        };
        (bundle, trusted)
    }

    #[test]
    fn signer_verification_accepts_the_matching_key_inside_its_window() {
        let (bundle, signer) = signed_terminal_bundle();
        assert!(verify_terminal_bundle_signer(&bundle, &signer).is_ok());
    }

    #[test]
    fn signer_verification_rejects_a_bundle_signed_under_another_key_id() {
        let (bundle, signer) = signed_terminal_bundle();
        for key_id in ["terminal-key-2", ""] {
            let other = RunmillTerminalEvidenceSigner {
                key_id: key_id.into(),
                ..signer.clone()
            };
            assert!(verify_terminal_bundle_signer(&bundle, &other).is_err());
        }
    }

    #[test]
    fn signer_verification_rejects_a_revoked_signer() {
        let (bundle, signer) = signed_terminal_bundle();
        let revoked = RunmillTerminalEvidenceSigner {
            revoked: true,
            ..signer
        };
        assert!(verify_terminal_bundle_signer(&bundle, &revoked).is_err());
    }

    #[test]
    fn signer_verification_rejects_an_issuance_outside_the_validity_window() {
        let (bundle, signer) = signed_terminal_bundle();
        let issued_at: DateTime<Utc> = BUNDLE_ISSUED_AT.parse().unwrap();

        // The upper bound is exclusive: a key that expires exactly at issuance
        // did not sign this bundle.
        let expired = RunmillTerminalEvidenceSigner {
            valid_until: issued_at,
            ..signer.clone()
        };
        assert!(verify_terminal_bundle_signer(&bundle, &expired).is_err());

        let not_yet_valid = RunmillTerminalEvidenceSigner {
            valid_from: issued_at + chrono::Duration::seconds(1),
            ..signer.clone()
        };
        assert!(verify_terminal_bundle_signer(&bundle, &not_yet_valid).is_err());

        let empty_window = RunmillTerminalEvidenceSigner {
            valid_until: signer.valid_from,
            ..signer
        };
        assert!(verify_terminal_bundle_signer(&bundle, &empty_window).is_err());
    }

    #[test]
    fn fence_accepts_exact_terminal_provenance() {
        assert!(valid_fence().validate().is_ok());
    }

    #[test]
    fn fence_rejects_missing_or_out_of_range_authority() {
        for invalid in [
            RunmillTerminalEvidenceFence {
                id: Uuid::nil(),
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                worker_session_id: Uuid::nil(),
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                work_order_digest: "not-a-digest".into(),
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                worker_generation: 0,
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                external_run_id: "   ".into(),
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                terminal_event_seq: 0,
                ..valid_fence()
            },
            RunmillTerminalEvidenceFence {
                terminal_event_seq: MAX_SAFE_INTEGER + 1,
                ..valid_fence()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn fence_rejects_a_non_terminal_phase() {
        let fence = RunmillTerminalEvidenceFence {
            terminal_phase: RunmillRunPhase::Implementing,
            ..valid_fence()
        };
        assert!(fence.validate().is_err());
    }

    #[test]
    fn fence_rejects_one_snapshot_in_both_roles() {
        let shared = Uuid::now_v7();
        let fence = RunmillTerminalEvidenceFence {
            get_run_snapshot_id: shared,
            event_page_snapshot_id: shared,
            ..valid_fence()
        };
        assert!(fence.validate().is_err());
    }

    #[test]
    fn idempotency_key_binds_tenant_run_and_terminal_digest() {
        let fence = valid_fence();
        let digest = format!("sha256:{}", "b".repeat(64));
        let key = fence.idempotency_key(&digest);
        assert_eq!(
            key,
            format!(
                "runmill-terminal-evidence:{}:{}:{digest}",
                fence.tenant_id, fence.run_id
            )
        );
        assert_eq!(key, fence.idempotency_key(&digest));

        let other_digest = format!("sha256:{}", "c".repeat(64));
        assert_ne!(key, fence.idempotency_key(&other_digest));

        // A retried retention that mints a fresh bundle row identity is still
        // the same durable fact, so the key must not depend on that uuid.
        let retried = RunmillTerminalEvidenceFence {
            id: Uuid::now_v7(),
            ..fence.clone()
        };
        assert_eq!(key, retried.idempotency_key(&digest));

        let other_run = RunmillTerminalEvidenceFence {
            run_id: Uuid::now_v7(),
            ..fence
        };
        assert_ne!(key, other_run.idempotency_key(&digest));
    }

    #[test]
    fn terminal_phase_database_values_match_the_migration_check() {
        for (phase, expected) in [
            (RunmillRunPhase::Completed, "COMPLETED"),
            (RunmillRunPhase::Cancelled, "CANCELLED"),
            (RunmillRunPhase::Failed, "FAILED"),
            (RunmillRunPhase::Refused, "REFUSED"),
            (RunmillRunPhase::Quarantined, "QUARANTINED"),
            (RunmillRunPhase::BudgetExhausted, "BUDGET_EXHAUSTED"),
        ] {
            assert!(phase.terminal());
            assert_eq!(phase_database_value(phase).unwrap(), expected);
        }
    }

    #[test]
    fn terminal_signature_shape_is_the_exact_ed25519_transport() {
        assert!(is_terminal_signature(&format!(
            "base64url:{}",
            "A".repeat(ED25519_BASE64URL_LENGTH)
        )));
        assert!(is_terminal_signature(&format!(
            "base64url:-_{}",
            "a".repeat(ED25519_BASE64URL_LENGTH - 2)
        )));
        assert!(!is_terminal_signature(
            &"A".repeat(ED25519_BASE64URL_LENGTH)
        ));
        assert!(!is_terminal_signature(&format!(
            "base64url:{}",
            "A".repeat(ED25519_BASE64URL_LENGTH - 1)
        )));
        assert!(!is_terminal_signature(&format!(
            "base64url:{}=",
            "A".repeat(ED25519_BASE64URL_LENGTH - 1)
        )));
    }

    #[test]
    fn git_sha_shape_is_lowercase_forty_hex() {
        assert!(is_git_sha(&"a".repeat(40)));
        assert!(is_git_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_git_sha(&"A".repeat(40)));
        assert!(!is_git_sha(&"a".repeat(39)));
        assert!(!is_git_sha(&"a".repeat(41)));
    }

    #[test]
    fn exact_success_wire_rejects_anything_but_one_ok_data_line() {
        let data = json!({"schema": "asf.evidence-view/v1"});
        let mut wire = serde_json::to_vec(&json!({"ok": true, "data": data})).unwrap();
        wire.push(b'\n');
        assert!(assert_exact_success_wire(&wire, &data).is_ok());

        let unterminated = &wire[..wire.len() - 1];
        assert!(assert_exact_success_wire(unterminated, &data).is_err());

        let mut interior_newline = wire.clone();
        interior_newline.insert(1, b'\n');
        assert!(assert_exact_success_wire(&interior_newline, &data).is_err());

        let mut extra_key =
            serde_json::to_vec(&json!({"ok": true, "data": data, "extra": false})).unwrap();
        extra_key.push(b'\n');
        assert!(assert_exact_success_wire(&extra_key, &data).is_err());

        let mut failure = serde_json::to_vec(&json!({"ok": false, "error": "no"})).unwrap();
        failure.push(b'\n');
        assert!(assert_exact_success_wire(&failure, &data).is_err());

        let mut other_data = serde_json::to_vec(&json!({"ok": true, "data": {}})).unwrap();
        other_data.push(b'\n');
        assert!(assert_exact_success_wire(&other_data, &data).is_err());
    }

    #[test]
    fn document_size_bounds_match_the_migration_octet_checks() {
        assert!(require_document_size(MIN_EVIDENCE_DOCUMENT_BYTES, "statement").is_ok());
        assert!(require_document_size(MAX_EVIDENCE_DOCUMENT_BYTES, "statement").is_ok());
        assert!(require_document_size(1, "statement").is_err());
        assert!(require_document_size(MAX_EVIDENCE_DOCUMENT_BYTES + 1, "statement").is_err());
    }

    #[test]
    fn insert_binds_every_migration_column_and_never_projects_run_state() {
        for column in [
            "get_run_snapshot_id",
            "event_page_snapshot_id",
            "exact_terminal_evidence_response_wire",
            "terminal_evidence_response_wire_digest",
            "canonical_statement",
            "statement_digest",
            "predicate",
            "exact_signed_envelope",
            "terminal_signature",
            "issued_at",
        ] {
            assert!(INSERT_BUNDLE_SQL.contains(column), "missing {column}");
        }
        assert!(INSERT_BUNDLE_SQL.contains("ON CONFLICT DO NOTHING"));
        for forbidden in [
            "UPDATE runs",
            "raw_run_events",
            "runmill_run_observation_streams",
        ] {
            assert!(
                !INSERT_BUNDLE_SQL.contains(forbidden),
                "terminal evidence retention must not touch {forbidden}"
            );
        }
        assert!(LOAD_BUNDLE_SQL.contains("terminal_bundle_digest = $4"));
        assert!(LOAD_CONTROL_SNAPSHOT_SQL.contains("control_operation = $3"));
    }

    #[test]
    fn migration_keeps_terminal_evidence_append_only_and_snapshot_bound() {
        let migration =
            include_str!("../../migrations/0035_runmill_terminal_evidence_provenance.sql");
        for required in [
            "CREATE TABLE runmill_terminal_evidence_bundles",
            "exact_terminal_evidence_response_wire bytea NOT NULL",
            "terminal_evidence_response_wire_digest text NOT NULL",
            "UNIQUE (tenant_id, run_id, terminal_bundle_digest)",
            "UNIQUE (tenant_id, get_run_snapshot_id)",
            "UNIQUE (tenant_id, event_page_snapshot_id)",
            "CHECK (get_run_snapshot_id <> event_page_snapshot_id)",
            "envelope_schema = 'asf.signed-terminal-evidence/v1'",
            "signature_algorithm = 'EdDSA'",
            "^base64url:[A-Za-z0-9_-]{86}$",
            "runmill_terminal_evidence_bundle_append_only",
            "runmill_terminal_evidence_bundle_truncate_forbidden",
            "stream.state = 'TERMINAL_READY'",
            "result.next_sequence = NEW.terminal_event_seq - 1",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
        for forbidden in ["INSERT INTO raw_run_events", "UPDATE runs"] {
            assert!(!migration.contains(forbidden), "unexpected {forbidden}");
        }
    }

    fn fixture_digest(fragment: &str) -> String {
        format!("sha256:{}", fragment.repeat(64))
    }

    fn fixture_commit(fragment: &str) -> String {
        fragment.repeat(40)
    }

    /// The exact in-toto statement a conformant terminal bundle signs for
    /// [`valid_fence`].
    fn fixture_statement(fence: &RunmillTerminalEvidenceFence) -> Value {
        json!({
            "_type": ASF_TERMINAL_IN_TOTO_STATEMENT_V1,
            "subject": [{
                "name": format!("asf-run:{}", fence.external_run_id),
                "digest": {"sha1": fixture_commit("c")}
            }],
            "predicateType": ASF_TERMINAL_EVIDENCE_PREDICATE_TYPE,
            "predicate": {
                "schema": ASF_TERMINAL_EVIDENCE_PREDICATE_SCHEMA,
                "run": {
                    "run_id": fence.external_run_id,
                    "work_order_id": fence.work_order_id.to_string(),
                    "attempt_id": fence.attempt_id.to_string(),
                    "terminal_phase": "COMPLETED",
                    "terminal_event_seq": fence.terminal_event_seq
                },
                "admission": {
                    "work_order_envelope_digest": fixture_digest("1"),
                    "work_order_payload_digest": fence.work_order_digest,
                    "effective_policy_digest": fixture_digest("3"),
                    "work_order_envelope": {"schema": "asf.work-order/v1"},
                    "signature_verification": {
                        "verified": true,
                        "key_id": "asf-terminal-key-1",
                        "algorithm": "EdDSA"
                    },
                    "effective_policy": {"digest": fixture_digest("3")}
                },
                "source": {
                    "repository": "owner/repo",
                    "base_sha": fixture_commit("b"),
                    "candidate_sha": fixture_commit("c"),
                    "subject_kind": "candidate",
                    "subject_sha": fixture_commit("c")
                },
                "stop": {
                    "code": "SUCCESS",
                    "summary": "run reached its terminal phase",
                    "interrupted_phase": "delivery",
                    "retry_disposition": "safe",
                    "required_actor": "asf",
                    "required_action": "none",
                    "evidence_refs": []
                },
                "cancellation": null,
                "budget": {
                    "wall_seconds_limit": 3600,
                    "max_cost_usd": 10.5,
                    "max_agent_invocations": 100,
                    "max_fix_iterations": 5,
                    "observed_fix_iterations": 2,
                    "evidence_refs": [],
                    "provider_usage": {"invocations": []}
                },
                "side_effects": {"effects": []},
                "timing": {
                    "admitted_at": BUNDLE_ADMITTED_AT,
                    "terminal_evidence_at": BUNDLE_ISSUED_AT,
                    "elapsed_ms": 60_000
                },
                "cleanup": {
                    "intent_id": "intent-1",
                    "intent_digest": fixture_digest("5"),
                    "observation_digest": fixture_digest("6"),
                    "identity_leases": "released",
                    "repository_lease": "released",
                    "workspace": "removed",
                    "unresolved_effects": 0
                },
                "evidence": {
                    "preceding_event_count": fence.terminal_event_seq - 1,
                    "preceding_event_chain_digest": fixture_digest("7"),
                    "observations": [],
                    "events": [],
                    "delivery_bundle_digest": fixture_digest("8")
                }
            }
        })
    }

    /// The signer's own bundle digest, derived exactly as the record derives
    /// it: SHA-256 of the canonical JCS encoding of the parsed statement.
    fn fixture_statement_digest(statement: &Value) -> String {
        let parsed: AsfTerminalEvidenceStatement =
            serde_json::from_value(statement.clone()).expect("statement fixture parses");
        let canonical = canonical_json(&serde_json::to_value(&parsed).expect("encode statement"))
            .expect("canonicalize statement");
        sha256_digest(&canonical)
    }

    fn fixture_envelope(statement: &Value) -> Value {
        json!({
            "schema": ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA,
            "key_id": "asf-terminal-key-1",
            "algorithm": "EdDSA",
            "issued_at": BUNDLE_ISSUED_AT,
            "bundle_digest": fixture_statement_digest(statement),
            "statement": statement,
            "signature": format!("base64url:{}", "A".repeat(ED25519_BASE64URL_LENGTH))
        })
    }

    /// One exact `asf.evidence-view/v1` object carrying the signed envelope its
    /// own terminal digest names.
    fn fixture_evidence_data(fence: &RunmillTerminalEvidenceFence, statement: &Value) -> Value {
        let envelope = fixture_envelope(statement);
        json!({
            "schema": RUNMILL_EVIDENCE_VIEW_SCHEMA,
            "runId": fence.external_run_id,
            "workOrderId": fence.work_order_id.to_string(),
            "attemptId": fence.attempt_id.to_string(),
            "phase": "COMPLETED",
            "candidateSha": fixture_commit("c"),
            "policyDigest": fixture_digest("d"),
            "latestSequence": fence.terminal_event_seq,
            "status": "stopped",
            "complete": true,
            "bundleDigest": null,
            "artifacts": [],
            "latestEvent": null,
            "signedBundle": null,
            "terminalBundleDigest": envelope["bundle_digest"],
            "signedTerminalBundle": envelope
        })
    }

    fn fixture_success_wire(data: &Value) -> Vec<u8> {
        let mut wire = serde_json::to_vec(&json!({"ok": true, "data": data})).expect("encode wire");
        wire.push(b'\n');
        wire
    }

    /// Derive a record from evidence bytes exactly as `from_validated_read`
    /// does once it has consumed its proof.
    fn record_from_evidence(
        fence: &RunmillTerminalEvidenceFence,
        data: &Value,
    ) -> Result<RunmillTerminalEvidenceRecord> {
        let typed_view: RunmillEvidenceView =
            serde_json::from_value(data.clone()).expect("evidence view fixture parses");
        RunmillTerminalEvidenceRecord::from_exact_evidence_read(
            fence,
            &typed_view,
            fixture_success_wire(data),
            data,
        )
    }

    #[test]
    fn record_reproduces_every_migration_column_from_the_exact_evidence_bytes() {
        let fence = valid_fence();
        let statement = fixture_statement(&fence);
        let data = fixture_evidence_data(&fence, &statement);
        let wire = fixture_success_wire(&data);

        let record = record_from_evidence(&fence, &data).expect("exact evidence derives a record");

        assert_eq!(record.fence, fence);
        assert_eq!(record.exact_response_wire, wire);
        assert_eq!(record.response_wire_digest, sha256_digest(&wire));
        assert_eq!(record.terminal_phase, "COMPLETED");
        assert_eq!(record.terminal_event_seq, fence.terminal_event_seq);
        assert_eq!(record.base_sha, fixture_commit("b"));
        assert_eq!(record.candidate_sha, Some(fixture_commit("c")));
        assert_eq!(record.envelope_schema, ASF_SIGNED_TERMINAL_EVIDENCE_SCHEMA);
        assert_eq!(record.signature_algorithm, "EdDSA");
        assert_eq!(record.signing_key_id, "asf-terminal-key-1");
        assert!(is_terminal_signature(&record.terminal_signature));
        assert_eq!(record.issued_at.to_rfc3339(), "2026-08-24T17:00:00+00:00");

        // Every digest is the digest of the bytes retained beside it, and the
        // signer's bundle digest is that same statement digest.
        assert_eq!(
            record.statement_digest,
            sha256_digest(&record.canonical_statement)
        );
        assert_eq!(record.terminal_bundle_digest, record.statement_digest);
        assert_eq!(
            serde_json::from_slice::<Value>(&record.canonical_statement).expect("canonical JSON"),
            statement
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&record.exact_signed_envelope)
                .expect("envelope JSON")
                .get("bundle_digest")
                .and_then(Value::as_str),
            Some(record.statement_digest.as_str())
        );
        assert_eq!(record.predicate, statement["predicate"]);
    }

    #[test]
    fn record_rejects_a_tampered_terminal_digest() {
        let fence = valid_fence();

        // A view digest that no longer names the envelope it carries.
        let mut relabelled = fixture_evidence_data(&fence, &fixture_statement(&fence));
        relabelled["terminalBundleDigest"] = json!(fixture_digest("9"));
        assert!(
            matches!(
                record_from_evidence(&fence, &relabelled),
                Err(Error::Validation(_))
            ),
            "the view's terminal digest must name the envelope it returned"
        );

        // A digest restated consistently on both sides, but not the digest of
        // the statement the envelope actually signs.
        let mut forged = fixture_evidence_data(&fence, &fixture_statement(&fence));
        forged["terminalBundleDigest"] = json!(fixture_digest("9"));
        forged["signedTerminalBundle"]["bundle_digest"] = json!(fixture_digest("9"));
        assert!(
            matches!(
                record_from_evidence(&fence, &forged),
                Err(Error::Validation(_))
            ),
            "the terminal digest must be the SHA-256 of the canonical statement"
        );
    }

    #[test]
    fn record_rejects_a_tampered_external_run() {
        let fence = valid_fence();

        // The evidence read names a run this fence never claimed.
        let mut foreign_view = fixture_evidence_data(&fence, &fixture_statement(&fence));
        foreign_view["runId"] = json!("run-999");
        assert!(
            matches!(
                record_from_evidence(&fence, &foreign_view),
                Err(Error::Validation(_))
            ),
            "the evidence view must name the fenced external run"
        );

        // The signed predicate names a different run. Its digests are
        // recomputed so the only disagreement left is the run binding itself.
        let mut tampered = fixture_statement(&fence);
        tampered["predicate"]["run"]["run_id"] = json!("run-999");
        let foreign_predicate = fixture_evidence_data(&fence, &tampered);
        assert!(
            matches!(
                record_from_evidence(&fence, &foreign_predicate),
                Err(Error::Validation(_))
            ),
            "the signed predicate must name the fenced external run"
        );
    }
}
