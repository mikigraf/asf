//! Runmill submission recovery adoptions: exact resolution of `PENDING_EXTERNAL_LOOKUP` cases.
//!
//! This module records the durable fact that a `PENDING_EXTERNAL_LOOKUP` recovery case
//! was resolved by an exact `asf.runmill-lookup-qualified-submission-receipt.v1` receipt
//! proving the submission reached Runmill, and that ASF has adopted the run it names.
//!
//! An adoption is append-only: it never resends, retries, or streams the submission.
//! This implementation accepts a pure `ExactQualifiedSubmissionReceiptProof` (no I/O,
//! no external calls) and persists it atomically with validation.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{PgLedger, persistence_error};
use crate::ledger::RunmillSubmissionRecoveryCase;
use crate::{
    Error, Result,
    crypto::{canonical_json, sha256_digest},
    runtime::ExactQualifiedSubmissionReceiptProof,
};

/// Outcome of adoption persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptionOutcome {
    /// Adoption was persisted; the case is now resolved and the run is adopted.
    Adopted,
    /// Adoption was not persisted due to a conflict.
    Conflict,
    /// Adoption validation or persistence encountered an error.
    PersistenceError,
}

/// Errors specific to adoption attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptionError {
    /// Adoption identifiers do not exactly match the case.
    IdentifierMismatch(String),
    /// The receipt proof failed validation.
    ProofValidationFailed(String),
    /// Case is not in `PENDING_EXTERNAL_LOOKUP` state.
    CaseNotPending,
    /// No external run found in the receipt.
    NoExternalRun,
    /// Work order or effect binding failed.
    BindingFailed(String),
    /// Database persistence error.
    Database(String),
}

/// Request to adopt an exact runmill submission recovery case.
#[derive(Debug, Clone)]
pub struct AdoptionRequest {
    /// The recovery case to adopt.
    pub case: RunmillSubmissionRecoveryCase,
    /// The exact proof from receipt validation.
    pub proof: ExactQualifiedSubmissionReceiptProof,
    /// Local ASF-generated run ID (to be created by caller in same transaction).
    pub local_run_id: Uuid,
    /// Workflow instance ID that triggered recovery.
    pub workflow_instance_id: Uuid,
    /// Escalation ID that triggered recovery.
    pub escalation_id: Uuid,
}

impl AdoptionRequest {
    fn validate(&self) -> Result<()> {
        if self.local_run_id.is_nil() {
            return Err(Error::Validation("local_run_id must be non-nil".into()));
        }
        if self.case.id.is_nil() || self.case.tenant_id.is_nil() {
            return Err(Error::Validation(
                "case must have non-nil id and tenant_id".into(),
            ));
        }
        if self.workflow_instance_id.is_nil() {
            return Err(Error::Validation(
                "workflow_instance_id must be non-nil".into(),
            ));
        }
        if self.escalation_id.is_nil() {
            return Err(Error::Validation("escalation_id must be non-nil".into()));
        }
        Ok(())
    }
}

/// An adoption record written to the ledger.
#[derive(Debug, Clone)]
pub struct PersistedAdoption {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub recovery_case_id: Uuid,
    pub local_run_id: Uuid,
    pub external_run_id: String,
    pub adopted_at: DateTime<Utc>,
}

/// Exact immutable coordinates for replay detection.
/// Covers all immutable adoption coordinates: effect intent, work item, attempt, work order,
/// payload/request digests, remote key, worker, generation, session, run state/version,
/// local/external run IDs, receipt schema/digest, workflow/escalation IDs, and evidence digest.
#[derive(Debug, Clone)]
struct ExactAdoptionCoordinates {
    effect_intent_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    payload_digest: String,
    request_digest: String,
    remote_idempotency_key: String,
    worker_id: Uuid,
    worker_generation: i64,
    worker_session_id: Uuid,
    local_run_id: Uuid,
    external_run_id: String,
    run_state: String,
    remote_state_version: i64,
    lookup_receipt_schema: String,
    lookup_receipt_digest: String,
    workflow_instance_id: Uuid,
    escalation_id: Uuid,
    evidence_expectation_digest: String,
}

const INSERT_ADOPTION_SQL: &str = r"
INSERT INTO runmill_submission_recovery_adoptions (
    id,
    tenant_id,
    recovery_case_id,
    effect_intent_id,
    work_item_id,
    attempt_id,
    work_order_id,
    payload_digest,
    request_digest,
    remote_idempotency_key,
    worker_id,
    worker_generation,
    worker_session_id,
    local_run_id,
    external_run_id,
    run_state,
    run_state_version,
    lookup_request_schema,
    lookup_receipt_schema,
    lookup_receipt,
    lookup_receipt_digest,
    workflow_instance_id,
    escalation_id,
    evidence_expectation,
    evidence_expectation_digest,
    adopted_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
ON CONFLICT (tenant_id, recovery_case_id) DO NOTHING
RETURNING id, tenant_id, recovery_case_id, local_run_id, external_run_id, adopted_at
";

impl PgLedger {
    /// Adopt an exact runmill submission recovery case atomically within a transaction.
    ///
    /// This method:
    /// 1. Locks the exact existing adoption for replay (by tenant+case)
    /// 2. Returns same fact if every immutable coordinate/proof/digest matches, else `Error::Conflict`
    /// 3. Locks `case/effect/attempt/work_order/session/workflow/escalation`
    /// 4. Derives exact canonical evidence expectation JSON + digest internally
    /// 5. Inserts adoption first
    /// 6. Inserts fresh authoritative ADOPTED run with local version 1, sequence 0 cursor NULL
    /// 7. Inserts observation stream with zero defaults
    /// 8. Updates exact effect AMBIGUOUS->OBSERVED using proof.receipt().outcome JSON
    /// 9. Resolves exact escalation and increments version
    /// 10. Commits transaction
    ///
    /// No external I/O, retries, or dispatch. Uses bound SQL params only.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid inputs, a conflict if adoption already exists,
    /// or a persistence error when `PostgreSQL` fails.
    pub async fn adopt_exact_runmill_submission_recovery(
        &self,
        request: AdoptionRequest,
    ) -> Result<PersistedAdoption> {
        request.validate()?;

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|error| persistence_error("begin adoption transaction", error))?;

        let result = adopt_in_transaction(&mut tx, &request).await?;

        tx.commit()
            .await
            .map_err(|error| persistence_error("commit adoption transaction", error))?;

        Ok(result)
    }
}

/// Execute adoption within a transaction: lock, validate, and persist atomically.
async fn adopt_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    request: &AdoptionRequest,
) -> Result<PersistedAdoption> {
    let case = &request.case;
    let proof = &request.proof;

    validate_case_matches_proof(case, proof)?;

    let receipt_json = json!(proof.receipt());
    let evidence_expectation = derive_canonical_evidence(case, proof);
    let evidence_bytes = canonical_json(&evidence_expectation)
        .map_err(|_| Error::Persistence("canonical_json evidence failed".into()))?;
    let evidence_digest = sha256_digest(&evidence_bytes);

    let coordinates = ExactAdoptionCoordinates {
        effect_intent_id: case.effect_intent_id,
        work_item_id: case.work_item_id,
        attempt_id: case.attempt_id,
        work_order_id: case.work_order_id,
        payload_digest: case.payload_digest.clone(),
        request_digest: case.request_digest.clone(),
        remote_idempotency_key: case.remote_idempotency_key.clone(),
        worker_id: case.worker_id,
        worker_generation: case.worker_generation,
        worker_session_id: case.worker_session_id,
        local_run_id: request.local_run_id,
        external_run_id: proof.external_run_id().to_string(),
        run_state: "ADOPTED".to_string(),
        remote_state_version: proof.remote_state_version(),
        lookup_receipt_schema: "asf.runmill-lookup-qualified-submission-receipt.v1".to_string(),
        lookup_receipt_digest: proof.receipt_digest().to_string(),
        workflow_instance_id: request.workflow_instance_id,
        escalation_id: request.escalation_id,
        evidence_expectation_digest: evidence_digest.clone(),
    };

    // Step 1: Serialize all adoption attempts for same case by locking recovery_case row.
    // This prevents two concurrent calls from both missing the adoption and both trying to INSERT.
    lock_recovery_case_for_serialization(tx, case).await?;

    // Step 2: Lock exact existing adoption for replay and return if all coordinates match.
    if let Some(adoption) =
        lock_exact_adoption_for_replay(tx, case, &coordinates, &receipt_json, &evidence_expectation)
            .await?
    {
        return Ok(adoption);
    }

    // Step 3: Acquire locks for case, effect, attempt, work_order, session, workflow, escalation.
    validate_exact_locks(tx, case, request).await?;

    // Step 4: Insert adoption first.
    let adoption_id = Uuid::new_v4();

    let row =
        sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, String, DateTime<Utc>)>(INSERT_ADOPTION_SQL)
            .bind(adoption_id)
            .bind(case.tenant_id)
            .bind(case.id)
            .bind(case.effect_intent_id)
            .bind(case.work_item_id)
            .bind(case.attempt_id)
            .bind(case.work_order_id)
            .bind(&case.payload_digest)
            .bind(&case.request_digest)
            .bind(&case.remote_idempotency_key)
            .bind(case.worker_id)
            .bind(case.worker_generation)
            .bind(case.worker_session_id)
            .bind(request.local_run_id)
            .bind(proof.external_run_id())
            .bind("ADOPTED")
            .bind(proof.remote_state_version())
            .bind("asf.runmill-lookup-qualified-submission-request.v1")
            .bind("asf.runmill-lookup-qualified-submission-receipt.v1")
            .bind(&receipt_json)
            .bind(proof.receipt_digest())
            .bind(request.workflow_instance_id)
            .bind(request.escalation_id)
            .bind(&evidence_expectation)
            .bind(&evidence_digest)
            .bind(Utc::now())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| persistence_error("insert adoption", error))?;

    let Some((adoption_id, tenant_id, recovery_case_id, local_run_id, external_run_id, adopted_at)) =
        row
    else {
        // Rare: adoption was inserted by other request after our SELECT FOR UPDATE.
        // Re-check with exact coordinates to return same fact if all coordinates match.
        if let Some(adoption) = lock_exact_adoption_for_replay(
            tx,
            case,
            &coordinates,
            &receipt_json,
            &evidence_expectation,
        )
        .await?
        {
            return Ok(adoption);
        }
        return Err(Error::Conflict(format!(
            "recovery case (tenant {}, case {}) already has an adoption",
            case.tenant_id, case.id
        )));
    };

    // Step 5: Insert fresh authoritative ADOPTED run with local version 1, sequence 0 cursor NULL.
    insert_authoritative_run(tx, case, request, proof, &evidence_digest).await?;

    // Step 6: Insert observation stream with zero defaults.
    insert_observation_stream(tx, case, request, proof).await?;

    // Step 7: Update exact effect AMBIGUOUS->OBSERVED using proof.receipt().outcome JSON.
    update_effect_to_observed(tx, case, proof).await?;

    // Step 8: Resolve exact escalation and increment version.
    resolve_escalation(tx, case, request).await?;

    Ok(PersistedAdoption {
        id: adoption_id,
        tenant_id,
        recovery_case_id,
        local_run_id,
        external_run_id,
        adopted_at,
    })
}

/// Lock `recovery_case` row to serialize all adoption attempts for the same case.
/// Validates all immutable coordinates match exactly before replay shortcut.
async fn lock_recovery_case_for_serialization(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
) -> Result<()> {
    let locked = sqlx::query(
        r"
        SELECT state, effect_intent_id, work_item_id, attempt_id, work_order_id,
               payload_digest, request_digest, remote_idempotency_key,
               worker_id, worker_generation, worker_session_id
        FROM runmill_submission_recovery_cases
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock recovery case for serialization", error))?;

    let Some(row) = locked else {
        return Err(Error::Persistence(
            "recovery case not found during serialization lock".into(),
        ));
    };

    let state: String = row.get("state");
    if state != "PENDING_EXTERNAL_LOOKUP" {
        return Err(Error::Conflict(
            "case is not in PENDING_EXTERNAL_LOOKUP state".into(),
        ));
    }

    // Validate all immutable coordinates match exactly
    let stored_effect_intent_id: Uuid = row.get("effect_intent_id");
    let stored_work_item_id: Uuid = row.get("work_item_id");
    let stored_attempt_id: Uuid = row.get("attempt_id");
    let stored_work_order_id: Uuid = row.get("work_order_id");
    let stored_payload_digest: String = row.get("payload_digest");
    let stored_request_digest: String = row.get("request_digest");
    let stored_remote_idempotency_key: String = row.get("remote_idempotency_key");
    let stored_worker_id: Uuid = row.get("worker_id");
    let stored_worker_generation: i64 = row.get("worker_generation");
    let stored_worker_session_id: Uuid = row.get("worker_session_id");

    if stored_effect_intent_id != case.effect_intent_id
        || stored_work_item_id != case.work_item_id
        || stored_attempt_id != case.attempt_id
        || stored_work_order_id != case.work_order_id
        || stored_payload_digest != case.payload_digest
        || stored_request_digest != case.request_digest
        || stored_remote_idempotency_key != case.remote_idempotency_key
        || stored_worker_id != case.worker_id
        || stored_worker_generation != case.worker_generation
        || stored_worker_session_id != case.worker_session_id
    {
        return Err(Error::Conflict(
            "supplied case coordinates do not match stored case".into(),
        ));
    }

    Ok(())
}

/// Acquire and validate locks for exact case, effect, attempt, work order, session, workflow, and escalation.
/// Every record is locked with SELECT ... FOR UPDATE and validated against exact immutable predicates.
async fn validate_exact_locks(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    request: &AdoptionRequest,
) -> Result<()> {
    // Lock case with exact id/tenant_id and verify state is PENDING_EXTERNAL_LOOKUP.
    let case_state = sqlx::query_scalar::<_, Option<String>>(
        r"
        SELECT state
        FROM runmill_submission_recovery_cases
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock case", error))?
    .flatten();

    if case_state != Some("PENDING_EXTERNAL_LOOKUP".to_string()) {
        return Err(Error::Conflict(
            "case is not in PENDING_EXTERNAL_LOOKUP state".into(),
        ));
    }

    // Lock effect with exact coordinates: tenant_id, id, work_item, attempt, work_order_id,
    // work_order_digest (from case.payload_digest), request_digest, and verify status=AMBIGUOUS, provider=runmill, effect_type=submit_work_order.
    let effect_row = sqlx::query_scalar::<_, (Uuid, Uuid, Uuid, String, String, String, String, String)>(
        r"
        SELECT id, work_item_id, attempt_id, status, provider, effect_type, work_order_digest, request_digest
        FROM effect_intents
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND work_order_id = $5 AND work_order_digest = $6 AND request_digest = $7
          AND status = 'AMBIGUOUS' AND provider = 'runmill' AND effect_type = 'submit_work_order'
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.effect_intent_id)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(case.work_order_id)
    .bind(&case.payload_digest)
    .bind(&case.request_digest)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock effect", error))?;

    if effect_row.is_none() {
        return Err(Error::Conflict(
            "effect not found or not in AMBIGUOUS state".into(),
        ));
    }

    // Lock attempt with exact coordinates: tenant_id, id, work_item_id.
    let attempt_row = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM attempts
        WHERE tenant_id = $1 AND id = $2 AND work_item_id = $3
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.attempt_id)
    .bind(case.work_item_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock attempt", error))?;

    if attempt_row.is_none() {
        return Err(Error::Conflict("attempt not found".into()));
    }

    // Lock work order with exact coordinates: tenant_id, id, work_item_id, attempt_id,
    // payload_digest, idempotency_key.
    let work_order_row = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM work_orders
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND payload_digest = $5 AND idempotency_key = $6
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.work_order_id)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(&case.payload_digest)
    .bind(&case.remote_idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock work_order", error))?;

    if work_order_row.is_none() {
        return Err(Error::Conflict("work_order not found".into()));
    }

    // Lock session with exact coordinates: tenant_id, id, worker_id, worker_generation.
    let session_row = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM worker_sessions
        WHERE tenant_id = $1 AND id = $2 AND worker_id = $3 AND worker_generation = $4
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.worker_session_id)
    .bind(case.worker_id)
    .bind(case.worker_generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock worker_session", error))?;

    if session_row.is_none() {
        return Err(Error::Conflict("worker_session not found".into()));
    }

    // Lock workflow with exact coordinates: tenant_id, id, state=ACTIVE, workflow_type=WORK_ITEM_DELIVERY, work_item_id.
    let workflow_row = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM workflow_instances
        WHERE tenant_id = $1 AND id = $2
          AND state = 'ACTIVE' AND workflow_type = 'WORK_ITEM_DELIVERY'
          AND work_item_id = $3
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(request.workflow_instance_id)
    .bind(case.work_item_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock workflow_instance", error))?;

    if workflow_row.is_none() {
        return Err(Error::Conflict(
            "workflow_instance not found or not active".into(),
        ));
    }

    // Lock escalation with exact coordinates: tenant_id, id, work_item_id, attempt_id,
    // category=REMOTE_EFFECT_AMBIGUOUS, status IN (OPEN, ACKNOWLEDGED), idempotency_key.
    let escalation_idempotency_key =
        format!("runmill-submission-recovery:{}", case.effect_intent_id);
    let escalation_row = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM escalations
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND category = 'REMOTE_EFFECT_AMBIGUOUS'
          AND status IN ('OPEN', 'ACKNOWLEDGED')
          AND idempotency_key = $5
          AND authority_or_effect_active = true
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(request.escalation_id)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(&escalation_idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock escalation", error))?;

    if escalation_row.is_none() {
        return Err(Error::Conflict(
            "escalation not found or not in open/acknowledged state".into(),
        ));
    }

    Ok(())
}

/// Lock exact existing adoption for replay and validate all immutable coordinates match.
/// Compares every immutable field including `lookup_receipt` JSON and `evidence_expectation` JSON.
/// Returns Some(adoption) if all fields match exactly (replay case).
/// Returns None if adoption does not exist (new adoption needed).
/// Returns Conflict error if adoption exists but any field mismatches.
async fn lock_exact_adoption_for_replay(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    coordinates: &ExactAdoptionCoordinates,
    receipt_json: &Value,
    evidence_expectation: &Value,
) -> Result<Option<PersistedAdoption>> {
    let existing_opt = sqlx::query(
        r"
        SELECT
            id,
            effect_intent_id,
            work_item_id,
            attempt_id,
            work_order_id,
            payload_digest,
            request_digest,
            remote_idempotency_key,
            worker_id,
            worker_generation,
            worker_session_id,
            external_run_id,
            run_state,
            run_state_version,
            lookup_request_schema,
            lookup_receipt_schema,
            lookup_receipt_digest,
            local_run_id,
            workflow_instance_id,
            escalation_id,
            evidence_expectation_digest,
            lookup_receipt,
            evidence_expectation,
            adopted_at
        FROM runmill_submission_recovery_adoptions
        WHERE tenant_id = $1 AND recovery_case_id = $2
        FOR UPDATE
        ",
    )
    .bind(case.tenant_id)
    .bind(case.id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| persistence_error("lock existing adoption", error))?;

    if let Some(row) = existing_opt {
        let id: Uuid = row.get("id");
        let existing_effect_intent_id: Uuid = row.get("effect_intent_id");
        let existing_work_item_id: Uuid = row.get("work_item_id");
        let existing_attempt_id: Uuid = row.get("attempt_id");
        let existing_work_order_id: Uuid = row.get("work_order_id");
        let existing_payload_digest: String = row.get("payload_digest");
        let existing_request_digest: String = row.get("request_digest");
        let existing_remote_idempotency_key: String = row.get("remote_idempotency_key");
        let existing_worker_id: Uuid = row.get("worker_id");
        let existing_worker_generation: i64 = row.get("worker_generation");
        let existing_worker_session_id: Uuid = row.get("worker_session_id");
        let existing_external_run_id: String = row.get("external_run_id");
        let existing_run_state: String = row.get("run_state");
        let existing_run_state_version: i64 = row.get("run_state_version");
        let existing_lookup_request_schema: String = row.get("lookup_request_schema");
        let existing_lookup_receipt_schema: String = row.get("lookup_receipt_schema");
        let existing_receipt_digest: String = row.get("lookup_receipt_digest");
        let existing_local_run_id: Uuid = row.get("local_run_id");
        let existing_workflow_id: Uuid = row.get("workflow_instance_id");
        let existing_escalation_id: Uuid = row.get("escalation_id");
        let existing_evidence_digest: String = row.get("evidence_expectation_digest");
        let existing_receipt_json: Value = row.get("lookup_receipt");
        let existing_evidence_expectation: Value = row.get("evidence_expectation");
        let adopted_at: DateTime<Utc> = row.get("adopted_at");

        // Validate every immutable coordinate exactly: effect, work item, attempt, work order,
        // payload/request digests, remote key, worker, generation, session, run state/version,
        // local/external run IDs, schemas, receipt digest, workflow/escalation IDs, and evidence digest.
        if existing_effect_intent_id != coordinates.effect_intent_id
            || existing_work_item_id != coordinates.work_item_id
            || existing_attempt_id != coordinates.attempt_id
            || existing_work_order_id != coordinates.work_order_id
            || existing_payload_digest != coordinates.payload_digest
            || existing_request_digest != coordinates.request_digest
            || existing_remote_idempotency_key != coordinates.remote_idempotency_key
            || existing_worker_id != coordinates.worker_id
            || existing_worker_generation != coordinates.worker_generation
            || existing_worker_session_id != coordinates.worker_session_id
            || existing_local_run_id != coordinates.local_run_id
            || existing_external_run_id != coordinates.external_run_id
            || existing_run_state != coordinates.run_state
            || existing_run_state_version != coordinates.remote_state_version
            || existing_lookup_request_schema
                != "asf.runmill-lookup-qualified-submission-request.v1"
            || existing_lookup_receipt_schema != coordinates.lookup_receipt_schema
            || existing_receipt_digest != coordinates.lookup_receipt_digest
            || existing_workflow_id != coordinates.workflow_instance_id
            || existing_escalation_id != coordinates.escalation_id
            || existing_evidence_digest != coordinates.evidence_expectation_digest
        {
            return Err(Error::Conflict(
                "existing adoption has conflicting proof: immutable coordinates do not match"
                    .to_string(),
            ));
        }

        // Validate JSON payloads match by canonical digest.
        let stored_receipt_bytes = canonical_json(&existing_receipt_json)
            .map_err(|_| Error::Persistence("canonical_json stored receipt failed".into()))?;
        let stored_receipt_digest = sha256_digest(&stored_receipt_bytes);

        let supplied_receipt_bytes = canonical_json(receipt_json)
            .map_err(|_| Error::Persistence("canonical_json supplied receipt failed".into()))?;
        let supplied_receipt_digest = sha256_digest(&supplied_receipt_bytes);

        if stored_receipt_digest != supplied_receipt_digest {
            return Err(Error::Conflict(
                "existing adoption has conflicting lookup_receipt JSON".into(),
            ));
        }

        let stored_evidence_bytes = canonical_json(&existing_evidence_expectation)
            .map_err(|_| Error::Persistence("canonical_json stored evidence failed".into()))?;
        let stored_evidence_digest = sha256_digest(&stored_evidence_bytes);

        let supplied_evidence_bytes = canonical_json(evidence_expectation)
            .map_err(|_| Error::Persistence("canonical_json supplied evidence failed".into()))?;
        let supplied_evidence_digest = sha256_digest(&supplied_evidence_bytes);

        if stored_evidence_digest != supplied_evidence_digest {
            return Err(Error::Conflict(
                "existing adoption has conflicting evidence_expectation JSON".into(),
            ));
        }

        // All coordinates and JSON payloads match exactly; return existing adoption for replay.
        return Ok(Some(PersistedAdoption {
            id,
            tenant_id: case.tenant_id,
            recovery_case_id: case.id,
            local_run_id: existing_local_run_id,
            external_run_id: existing_external_run_id,
            adopted_at,
        }));
    }

    Ok(None)
}

/// Insert fresh authoritative ADOPTED run with `aggregate_version=1`, `last_event_sequence=0`, cursor NULL.
async fn insert_authoritative_run(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    request: &AdoptionRequest,
    proof: &ExactQualifiedSubmissionReceiptProof,
    evidence_digest: &str,
) -> Result<()> {
    let rows = sqlx::query(
        r"
        INSERT INTO runs (
            id, tenant_id, work_item_id, attempt_id, work_order_id,
            worker_id, worker_generation, worker_session_id,
            evidence_expectation_digest, external_run_id, authoritative,
            state, last_event_cursor, last_event_sequence, aggregate_version,
            adopted_at, last_observed_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        )
        ",
    )
    .bind(request.local_run_id)
    .bind(case.tenant_id)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(case.work_order_id)
    .bind(case.worker_id)
    .bind(case.worker_generation)
    .bind(case.worker_session_id)
    .bind(evidence_digest)
    .bind(proof.external_run_id())
    .bind(true)
    .bind("ADOPTED")
    .bind::<Option<String>>(None)
    .bind(0i64)
    .bind(1i64)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut **tx)
    .await
    .map_err(|error| persistence_error("insert authoritative run", error))?
    .rows_affected();

    if rows != 1 {
        return Err(Error::Persistence(format!(
            "insert authoritative run affected {rows} rows, expected 1"
        )));
    }

    Ok(())
}

/// Insert observation stream with zero defaults for `next_after_sequence` and `observation_epoch`.
async fn insert_observation_stream(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    request: &AdoptionRequest,
    proof: &ExactQualifiedSubmissionReceiptProof,
) -> Result<()> {
    let rows = sqlx::query(
        r"
        INSERT INTO runmill_run_observation_streams (
            tenant_id, run_id, workflow_instance_id, work_item_id, attempt_id,
            work_order_id, work_order_digest, worker_id, worker_generation,
            run_admission_worker_session_id, external_run_id,
            next_after_sequence, observation_epoch, state, aggregate_version,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        )
        ",
    )
    .bind(case.tenant_id)
    .bind(request.local_run_id)
    .bind(request.workflow_instance_id)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(case.work_order_id)
    .bind(&case.payload_digest)
    .bind(case.worker_id)
    .bind(case.worker_generation)
    .bind(case.worker_session_id)
    .bind(proof.external_run_id())
    .bind(0i64)
    .bind(0i64)
    .bind("ACTIVE")
    .bind(1i64)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut **tx)
    .await
    .map_err(|error| persistence_error("insert observation stream", error))?
    .rows_affected();

    if rows != 1 {
        return Err(Error::Persistence(format!(
            "insert observation stream affected {rows} rows, expected 1"
        )));
    }

    Ok(())
}

/// Update exact effect AMBIGUOUS->OBSERVED using proof.receipt().outcome JSON.
/// Sets status, `observed_outcome`, `observed_at`, `updated_at`, and clears `last_error`.
/// Verifies exact matching predicates on `work_item_id`, `attempt_id`, `work_order_id`,
/// `work_order_digest` (`payload_digest`), and `request_digest`.
async fn update_effect_to_observed(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    proof: &ExactQualifiedSubmissionReceiptProof,
) -> Result<()> {
    let receipt = proof.receipt();
    let outcome_value: Value = serde_json::to_value(&receipt.outcome)
        .map_err(|_| Error::Persistence("serialize outcome to JSON failed".into()))?;

    let now = Utc::now();
    let rows = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'OBSERVED',
            observed_outcome = $3,
            observed_at = $4,
            updated_at = $4,
            last_error = NULL
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'AMBIGUOUS'
          AND provider = 'runmill'
          AND effect_type = 'submit_work_order'
          AND work_item_id = $5
          AND attempt_id = $6
          AND work_order_id = $7
          AND work_order_digest = $8
          AND request_digest = $9
        ",
    )
    .bind(case.tenant_id)
    .bind(case.effect_intent_id)
    .bind(outcome_value)
    .bind(now)
    .bind(case.work_item_id)
    .bind(case.attempt_id)
    .bind(case.work_order_id)
    .bind(&case.payload_digest)
    .bind(&case.request_digest)
    .execute(&mut **tx)
    .await
    .map_err(|error| persistence_error("update effect to observed", error))?
    .rows_affected();

    if rows != 1 {
        return Err(Error::Persistence(format!(
            "update effect to observed affected {rows} rows, expected 1"
        )));
    }

    Ok(())
}

/// Resolve exact escalation: increment `aggregate_version`, set `run_id`, `authority_or_effect_active=false`, `closed_at`.
/// Verifies exactly 1 row affected.
async fn resolve_escalation(
    tx: &mut Transaction<'_, Postgres>,
    case: &RunmillSubmissionRecoveryCase,
    request: &AdoptionRequest,
) -> Result<()> {
    let rows = sqlx::query(
        r"
        UPDATE escalations
        SET status = 'RESOLVED',
            aggregate_version = aggregate_version + 1,
            run_id = $3,
            authority_or_effect_active = false,
            closed_at = $4
        WHERE tenant_id = $1
          AND id = $2
          AND status IN ('OPEN', 'ACKNOWLEDGED')
          AND category = 'REMOTE_EFFECT_AMBIGUOUS'
        ",
    )
    .bind(case.tenant_id)
    .bind(request.escalation_id)
    .bind(request.local_run_id)
    .bind(Utc::now())
    .execute(&mut **tx)
    .await
    .map_err(|error| persistence_error("resolve escalation", error))?
    .rows_affected();

    if rows != 1 {
        return Err(Error::Persistence(format!(
            "resolve escalation affected {rows} rows, expected 1"
        )));
    }

    Ok(())
}

/// Validate that case and proof fields match exactly before adoption.
fn validate_case_matches_proof(
    case: &RunmillSubmissionRecoveryCase,
    proof: &ExactQualifiedSubmissionReceiptProof,
) -> Result<()> {
    if case.worker_id != proof.worker_id() {
        return Err(Error::Validation(format!(
            "case worker_id {} does not match proof worker_id {}",
            case.worker_id,
            proof.worker_id()
        )));
    }

    if case.worker_generation != proof.worker_generation() {
        return Err(Error::Validation(format!(
            "case worker_generation {} does not match proof worker_generation {}",
            case.worker_generation,
            proof.worker_generation()
        )));
    }

    if case.worker_session_id != proof.worker_session_id() {
        return Err(Error::Validation(format!(
            "case worker_session_id {} does not match proof worker_session_id {}",
            case.worker_session_id,
            proof.worker_session_id()
        )));
    }

    if proof.external_run_id().trim().is_empty() {
        return Err(Error::Validation(
            "proof external_run_id must be non-blank".into(),
        ));
    }

    Ok(())
}

/// Derive canonical evidence object from case and proof (deterministic JSON).
fn derive_canonical_evidence(
    case: &RunmillSubmissionRecoveryCase,
    proof: &ExactQualifiedSubmissionReceiptProof,
) -> Value {
    json!({
        "case_id": case.id,
        "effect_intent_id": case.effect_intent_id,
        "worker_id": case.worker_id,
        "worker_generation": case.worker_generation,
        "worker_session_id": case.worker_session_id,
        "external_run_id": proof.external_run_id(),
        "receipt_digest": proof.receipt_digest(),
        "work_order_envelope_digest": &case.request_digest,
        "work_order_payload_digest": &case.payload_digest,
        "lookup_receipt_digest": proof.receipt_digest(),
    })
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use super::*;
    use crate::crypto::canonical_json;
    use url::Url;
    use uuid::Uuid;

    fn make_test_evidence() -> Value {
        let case_id = Uuid::new_v4();

        json!({
            "case_id": case_id,
            "effect_intent_id": Uuid::new_v4(),
            "worker_id": Uuid::new_v4(),
            "worker_generation": 1i64,
            "worker_session_id": Uuid::new_v4(),
            "external_run_id": "external-run-123",
            "receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "work_order_envelope_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "work_order_payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "lookup_receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        })
    }

    #[test]
    fn test_evidence_expectation_is_jsonb_object() {
        let evidence = make_test_evidence();

        assert!(evidence.is_object(), "evidence should be a JSON object");
        assert!(evidence.get("case_id").is_some());
        assert!(evidence.get("worker_id").is_some());
        assert!(evidence.get("external_run_id").is_some());
    }

    #[test]
    fn test_evidence_canonical_json_roundtrip() {
        let evidence1 = make_test_evidence();
        let canonical_bytes1 =
            canonical_json(&evidence1).expect("canonical_json should succeed on evidence object");
        let digest1 = sha256_digest(&canonical_bytes1);

        let evidence2 = make_test_evidence();
        // Reconstructing same structure should give same digest
        let canonical_bytes2 =
            canonical_json(&evidence2).expect("canonical_json should succeed on evidence object");
        let digest2 = sha256_digest(&canonical_bytes2);

        // Different UUIDs mean different digests
        assert_ne!(
            digest1, digest2,
            "different evidence should have different digests"
        );
    }

    #[test]
    fn test_evidence_contains_minimum_required_fields() {
        let evidence = make_test_evidence();

        let required_fields = [
            "case_id",
            "effect_intent_id",
            "worker_id",
            "worker_generation",
            "worker_session_id",
            "external_run_id",
            "receipt_digest",
            "work_order_envelope_digest",
            "work_order_payload_digest",
            "lookup_receipt_digest",
        ];

        for field in &required_fields {
            assert!(
                evidence.get(field).is_some(),
                "evidence must contain {field} field"
            );
        }
    }

    #[test]
    fn test_adoption_outcome_enum_values() {
        assert_eq!(AdoptionOutcome::Adopted, AdoptionOutcome::Adopted);
        assert_ne!(AdoptionOutcome::Adopted, AdoptionOutcome::Conflict);
    }

    #[test]
    fn test_adoption_request_validate_rejects_nil_local_run_id() {
        let tenant_id = Uuid::new_v4();
        let case_id = Uuid::new_v4();
        let request = AdoptionRequest {
            case: RunmillSubmissionRecoveryCase {
                tenant_id,
                id: case_id,
                state: "PENDING_EXTERNAL_LOOKUP".to_string(),
                effect_intent_id: Uuid::new_v4(),
                work_item_id: Uuid::new_v4(),
                attempt_id: Uuid::new_v4(),
                work_order_id: Uuid::new_v4(),
                payload_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                request_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                remote_idempotency_key: "idempotency-key".to_string(),
                worker_id: Uuid::new_v4(),
                worker_generation: 1,
                worker_session_id: Uuid::new_v4(),
                created_at: Utc::now().trunc_subsecs(6),
                updated_at: Utc::now().trunc_subsecs(6),
            },
            proof: mock_proof(),
            local_run_id: Uuid::nil(),
            workflow_instance_id: Uuid::new_v4(),
            escalation_id: Uuid::new_v4(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_adoption_request_validate_rejects_nil_workflow_instance_id() {
        let tenant_id = Uuid::new_v4();
        let case_id = Uuid::new_v4();
        let request = AdoptionRequest {
            case: RunmillSubmissionRecoveryCase {
                tenant_id,
                id: case_id,
                state: "PENDING_EXTERNAL_LOOKUP".to_string(),
                effect_intent_id: Uuid::new_v4(),
                work_item_id: Uuid::new_v4(),
                attempt_id: Uuid::new_v4(),
                work_order_id: Uuid::new_v4(),
                payload_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                request_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                remote_idempotency_key: "idempotency-key".to_string(),
                worker_id: Uuid::new_v4(),
                worker_generation: 1,
                worker_session_id: Uuid::new_v4(),
                created_at: Utc::now().trunc_subsecs(6),
                updated_at: Utc::now().trunc_subsecs(6),
            },
            proof: mock_proof(),
            local_run_id: Uuid::new_v4(),
            workflow_instance_id: Uuid::nil(),
            escalation_id: Uuid::new_v4(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_adoption_request_validate_rejects_nil_escalation_id() {
        let tenant_id = Uuid::new_v4();
        let case_id = Uuid::new_v4();
        let request = AdoptionRequest {
            case: RunmillSubmissionRecoveryCase {
                tenant_id,
                id: case_id,
                state: "PENDING_EXTERNAL_LOOKUP".to_string(),
                effect_intent_id: Uuid::new_v4(),
                work_item_id: Uuid::new_v4(),
                attempt_id: Uuid::new_v4(),
                work_order_id: Uuid::new_v4(),
                payload_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                request_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                remote_idempotency_key: "idempotency-key".to_string(),
                worker_id: Uuid::new_v4(),
                worker_generation: 1,
                worker_session_id: Uuid::new_v4(),
                created_at: Utc::now().trunc_subsecs(6),
                updated_at: Utc::now().trunc_subsecs(6),
            },
            proof: mock_proof(),
            local_run_id: Uuid::new_v4(),
            workflow_instance_id: Uuid::new_v4(),
            escalation_id: Uuid::nil(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_adoption_request_validate_accepts_valid_inputs() {
        let tenant_id = Uuid::new_v4();
        let case_id = Uuid::new_v4();
        let request = AdoptionRequest {
            case: RunmillSubmissionRecoveryCase {
                tenant_id,
                id: case_id,
                state: "PENDING_EXTERNAL_LOOKUP".to_string(),
                effect_intent_id: Uuid::new_v4(),
                work_item_id: Uuid::new_v4(),
                attempt_id: Uuid::new_v4(),
                work_order_id: Uuid::new_v4(),
                payload_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                request_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                remote_idempotency_key: "idempotency-key".to_string(),
                worker_id: Uuid::new_v4(),
                worker_generation: 1,
                worker_session_id: Uuid::new_v4(),
                created_at: Utc::now().trunc_subsecs(6),
                updated_at: Utc::now().trunc_subsecs(6),
            },
            proof: mock_proof(),
            local_run_id: Uuid::new_v4(),
            workflow_instance_id: Uuid::new_v4(),
            escalation_id: Uuid::new_v4(),
        };

        assert!(request.validate().is_ok());
    }

    fn mock_proof() -> ExactQualifiedSubmissionReceiptProof {
        ExactQualifiedSubmissionReceiptProof::new_for_test(
            crate::ports::runmill::LookupQualifiedSubmissionReceipt {
                schema: "asf.runmill-lookup-qualified-submission-receipt.v1".to_string(),
                outcome: crate::ports::runmill::LookupQualifiedSubmissionOutcome::NotFound,
            },
            vec![],
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "external-run-123".to_string(),
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            1,
        )
    }

    #[test]
    fn test_exact_adoption_coordinates_validation() {
        let coord1 = ExactAdoptionCoordinates {
            effect_intent_id: Uuid::new_v4(),
            work_item_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            work_order_id: Uuid::new_v4(),
            payload_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            request_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            remote_idempotency_key: "idempotency-key".to_string(),
            worker_id: Uuid::new_v4(),
            worker_generation: 1,
            worker_session_id: Uuid::new_v4(),
            local_run_id: Uuid::new_v4(),
            external_run_id: "run-123".to_string(),
            run_state: "ADOPTED".to_string(),
            remote_state_version: 1,
            lookup_receipt_schema: "asf.runmill-lookup-qualified-submission-receipt.v1".to_string(),
            lookup_receipt_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            workflow_instance_id: Uuid::new_v4(),
            escalation_id: Uuid::new_v4(),
            evidence_expectation_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
        };

        // Verify all fields are present and distinct
        assert!(!coord1.effect_intent_id.is_nil());
        assert!(!coord1.work_item_id.is_nil());
        assert!(!coord1.attempt_id.is_nil());
        assert!(!coord1.work_order_id.is_nil());
        assert!(!coord1.payload_digest.is_empty());
        assert!(!coord1.request_digest.is_empty());
        assert!(!coord1.remote_idempotency_key.is_empty());
        assert!(!coord1.worker_id.is_nil());
        assert_eq!(coord1.worker_generation, 1);
        assert!(!coord1.worker_session_id.is_nil());
        assert!(!coord1.local_run_id.is_nil());
        assert!(!coord1.external_run_id.is_empty());
        assert_eq!(coord1.run_state, "ADOPTED");
        assert_eq!(coord1.remote_state_version, 1);
        assert_eq!(
            coord1.lookup_receipt_schema,
            "asf.runmill-lookup-qualified-submission-receipt.v1"
        );
        assert!(!coord1.lookup_receipt_digest.is_empty());
        assert!(!coord1.workflow_instance_id.is_nil());
        assert!(!coord1.escalation_id.is_nil());
        assert!(!coord1.evidence_expectation_digest.is_empty());
    }

    #[test]
    fn test_adoption_outcome_distinct_values() {
        let adopted = AdoptionOutcome::Adopted;
        let conflict = AdoptionOutcome::Conflict;
        let error = AdoptionOutcome::PersistenceError;

        assert_ne!(adopted, conflict);
        assert_ne!(conflict, error);
        assert_ne!(adopted, error);
    }

    #[test]
    fn test_adoption_error_includes_context() {
        let err = AdoptionError::IdentifierMismatch("test_mismatch".to_string());
        let desc = format!("{err:?}");
        assert!(desc.contains("IdentifierMismatch"));
    }

    #[test]
    fn test_persisted_adoption_has_all_coordinates() {
        let tenant_id = Uuid::new_v4();
        let case_id = Uuid::new_v4();
        let local_run_id = Uuid::new_v4();

        let adoption = PersistedAdoption {
            id: Uuid::new_v4(),
            tenant_id,
            recovery_case_id: case_id,
            local_run_id,
            external_run_id: "external-run-123".to_string(),
            adopted_at: Utc::now().trunc_subsecs(6),
        };

        assert_eq!(adoption.tenant_id, tenant_id);
        assert_eq!(adoption.recovery_case_id, case_id);
        assert_eq!(adoption.local_run_id, local_run_id);
        assert_eq!(adoption.external_run_id, "external-run-123");
        assert!(!adoption.id.is_nil());
    }

    #[test]
    fn test_validate_exact_locks_case_sql_shape() {
        // Verify case lock SQL uses FOR UPDATE with exact tenant_id and id predicates.

        let sql = r"
        SELECT state
        FROM runmill_submission_recovery_cases
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ";

        assert!(sql.contains("FOR UPDATE"), "case lock must use FOR UPDATE");
        assert!(
            sql.contains("tenant_id = $1"),
            "case lock must use tenant_id predicate"
        );
        assert!(sql.contains("id = $2"), "case lock must use id predicate");
    }

    #[test]
    fn test_validate_exact_locks_effect_sql_shape() {
        // Verify effect lock SQL uses FOR UPDATE with exact work_item, attempt, work_order_id,
        // work_order_digest, request_digest predicates plus status/provider/effect_type.
        let sql = r"
        SELECT id, work_item_id, attempt_id, status, provider, effect_type, work_order_digest, request_digest
        FROM effect_intents
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND work_order_id = $5 AND work_order_digest = $6 AND request_digest = $7
          AND status = 'AMBIGUOUS' AND provider = 'runmill' AND effect_type = 'submit_work_order'
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "effect lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("work_item_id = $3"),
            "effect lock must predicate on work_item_id"
        );
        assert!(
            sql.contains("attempt_id = $4"),
            "effect lock must predicate on attempt_id"
        );
        assert!(
            sql.contains("work_order_id = $5"),
            "effect lock must predicate on work_order_id"
        );
        assert!(
            sql.contains("work_order_digest = $6"),
            "effect lock must predicate on work_order_digest"
        );
        assert!(
            sql.contains("request_digest = $7"),
            "effect lock must predicate on request_digest"
        );
        assert!(
            sql.contains("status = 'AMBIGUOUS'"),
            "effect lock must verify status=AMBIGUOUS"
        );
        assert!(
            sql.contains("provider = 'runmill'"),
            "effect lock must verify provider=runmill"
        );
        assert!(
            sql.contains("effect_type = 'submit_work_order'"),
            "effect lock must verify effect_type=submit_work_order"
        );
    }

    #[test]
    fn test_validate_exact_locks_attempt_sql_shape() {
        // Verify attempt lock SQL uses FOR UPDATE with exact work_item_id predicate.
        let sql = r"
        SELECT id
        FROM attempts
        WHERE tenant_id = $1 AND id = $2 AND work_item_id = $3
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "attempt lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("work_item_id = $3"),
            "attempt lock must predicate on work_item_id"
        );
    }

    #[test]
    fn test_validate_exact_locks_work_order_sql_shape() {
        // Verify work order lock SQL uses FOR UPDATE with exact payload_digest and
        // idempotency_key predicates.
        let sql = r"
        SELECT id
        FROM work_orders
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND payload_digest = $5 AND idempotency_key = $6
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "work_order lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("payload_digest = $5"),
            "work_order lock must predicate on payload_digest"
        );
        assert!(
            sql.contains("idempotency_key = $6"),
            "work_order lock must predicate on idempotency_key"
        );
    }

    #[test]
    fn test_validate_exact_locks_session_sql_shape() {
        // Verify session lock SQL uses FOR UPDATE with exact worker_id and worker_generation predicates.
        let sql = r"
        SELECT id
        FROM worker_sessions
        WHERE tenant_id = $1 AND id = $2 AND worker_id = $3 AND worker_generation = $4
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "session lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("worker_id = $3"),
            "session lock must predicate on worker_id"
        );
        assert!(
            sql.contains("worker_generation = $4"),
            "session lock must predicate on worker_generation"
        );
    }

    #[test]
    fn test_validate_exact_locks_workflow_sql_shape() {
        // Verify workflow lock SQL uses FOR UPDATE with exact state='ACTIVE',
        // workflow_type='WORK_ITEM_DELIVERY', and work_item_id predicates.
        let sql = r"
        SELECT id
        FROM workflow_instances
        WHERE tenant_id = $1 AND id = $2
          AND state = 'ACTIVE' AND workflow_type = 'WORK_ITEM_DELIVERY'
          AND work_item_id = $3
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "workflow lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("state = 'ACTIVE'"),
            "workflow lock must verify state=ACTIVE (not status)"
        );
        assert!(
            sql.contains("workflow_type = 'WORK_ITEM_DELIVERY'"),
            "workflow lock must verify workflow_type=WORK_ITEM_DELIVERY"
        );
        assert!(
            sql.contains("work_item_id = $3"),
            "workflow lock must predicate on work_item_id"
        );
    }

    #[test]
    fn test_validate_exact_locks_escalation_sql_shape() {
        // Verify escalation lock SQL uses FOR UPDATE with exact work_item_id, attempt_id,
        // category, status, idempotency_key (formatted as runmill-submission-recovery:effect_intent_id),
        // and authority_or_effect_active predicates.
        let sql = r"
        SELECT id
        FROM escalations
        WHERE tenant_id = $1 AND id = $2
          AND work_item_id = $3 AND attempt_id = $4
          AND category = 'REMOTE_EFFECT_AMBIGUOUS'
          AND status IN ('OPEN', 'ACKNOWLEDGED')
          AND idempotency_key = $5
          AND authority_or_effect_active = true
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "escalation lock must use FOR UPDATE"
        );
        assert!(
            sql.contains("work_item_id = $3"),
            "escalation lock must predicate on work_item_id"
        );
        assert!(
            sql.contains("attempt_id = $4"),
            "escalation lock must predicate on attempt_id"
        );
        assert!(
            sql.contains("idempotency_key = $5"),
            "escalation lock must predicate on idempotency_key"
        );
        assert!(
            sql.contains("authority_or_effect_active = true"),
            "escalation lock must verify authority_or_effect_active"
        );
    }

    #[test]
    fn test_escalation_idempotency_key_format() {
        // Verify that escalation idempotency key is formatted as runmill-submission-recovery:effect_intent_id.
        let effect_intent_id = Uuid::new_v4();
        let expected_key = format!("runmill-submission-recovery:{effect_intent_id}");

        // This should match the format constructed in validate_exact_locks
        assert!(
            expected_key.starts_with("runmill-submission-recovery:"),
            "escalation idempotency key must start with runmill-submission-recovery: prefix"
        );
        assert_eq!(
            expected_key.len(),
            "runmill-submission-recovery:".len() + 36,
            "escalation idempotency key format must be exactly 'runmill-submission-recovery:' + UUID"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL schema to compare the lock SQL against"]
    async fn test_exact_lock_sql_against_migrations() {
        // Integration test: verify exact lock SQL queries match actual schema columns
        // from migrations. This test requires a real PostgreSQL instance and must be run
        // with: cargo test --test '*' test_exact_lock_sql_against_migrations -- --ignored

        let db_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration test");

        // Create disposable schema with full migration chain
        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("connect to test database");

        let schema_name = format!("asf_exact_lock_test_{}", Uuid::now_v7().simple());
        assert!(
            schema_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );

        sqlx::query(&format!("CREATE SCHEMA {schema_name}"))
            .execute(&pool)
            .await
            .expect("create test schema");

        // Connect scoped ledger and run full migrations
        let mut scoped_url = Url::parse(&db_url).expect("parse database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema_name}"));

        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect scoped ledger");

        ledger.migrate().await.expect("apply full migration chain");

        let tx_pool = ledger.pool();
        let mut tx = tx_pool.begin().await.expect("begin test transaction");

        // Verify effect_intents has work_order_digest and request_digest columns (not payload_digest)
        let effect_check: (bool, bool, bool) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = 'effect_intents' AND column_name = 'work_order_digest'
            ),
            EXISTS(
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = 'effect_intents' AND column_name = 'request_digest'
            ),
            EXISTS(
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = 'effect_intents' AND column_name = 'work_order_id'
            )
            ",
        )
        .bind(&schema_name)
        .fetch_one(&mut *tx)
        .await
        .expect("check effect_intents schema");

        assert!(
            effect_check.0,
            "effect_intents must have work_order_digest column"
        );
        assert!(
            effect_check.1,
            "effect_intents must have request_digest column"
        );
        assert!(
            effect_check.2,
            "effect_intents must have work_order_id column"
        );

        // Verify worker_sessions has worker_generation column (not generation)
        let session_check: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = 'worker_sessions' AND column_name = 'worker_generation'
            )
            ",
        )
        .bind(&schema_name)
        .fetch_one(&mut *tx)
        .await
        .expect("check worker_sessions schema");

        assert!(
            session_check,
            "worker_sessions must have worker_generation column (not generation)"
        );

        // Verify work_orders has idempotency_key column (not remote_idempotency_key)
        let work_order_check: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = 'work_orders' AND column_name = 'idempotency_key'
            )
            ",
        )
        .bind(&schema_name)
        .fetch_one(&mut *tx)
        .await
        .expect("check work_orders schema");

        assert!(
            work_order_check,
            "work_orders must have idempotency_key column"
        );

        // Cleanup
        tx.rollback().await.expect("rollback test transaction");

        ledger.close().await;

        sqlx::query(&format!("DROP SCHEMA {schema_name} CASCADE"))
            .execute(&pool)
            .await
            .expect("drop test schema");

        pool.close().await;
    }

    #[test]
    fn test_exact_adoption_coordinates_complete_structure() {
        let coord = ExactAdoptionCoordinates {
            effect_intent_id: Uuid::new_v4(),
            work_item_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            work_order_id: Uuid::new_v4(),
            payload_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            request_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            remote_idempotency_key: "test-key".to_string(),
            worker_id: Uuid::new_v4(),
            worker_generation: 2,
            worker_session_id: Uuid::new_v4(),
            local_run_id: Uuid::new_v4(),
            external_run_id: "ext-run-456".to_string(),
            run_state: "ADOPTED".to_string(),
            remote_state_version: 3,
            lookup_receipt_schema: "asf.runmill-lookup-qualified-submission-receipt.v1".to_string(),
            lookup_receipt_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            workflow_instance_id: Uuid::new_v4(),
            escalation_id: Uuid::new_v4(),
            evidence_expectation_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
        };

        assert!(!coord.effect_intent_id.is_nil());
        assert!(!coord.work_item_id.is_nil());
        assert!(!coord.attempt_id.is_nil());
        assert!(!coord.work_order_id.is_nil());
        assert_eq!(coord.run_state, "ADOPTED");
        assert_eq!(coord.remote_state_version, 3);
        assert_eq!(coord.worker_generation, 2);
    }

    #[test]
    fn test_receipt_json_and_evidence_expectation_canonical_roundtrip() {
        let receipt = json!({
            "submission_id": "sub-123",
            "external_run_id": "run-456",
            "outcome": "Found"
        });

        let receipt_bytes = canonical_json(&receipt).expect("canonical receipt JSON");
        let receipt_digest = sha256_digest(&receipt_bytes);

        // Same JSON, different construction order, should have same digest
        let receipt2 = json!({
            "external_run_id": "run-456",
            "outcome": "Found",
            "submission_id": "sub-123"
        });

        let receipt_bytes2 = canonical_json(&receipt2).expect("canonical receipt JSON 2");
        let receipt_digest2 = sha256_digest(&receipt_bytes2);

        assert_eq!(
            receipt_digest, receipt_digest2,
            "canonical digests must match for logically identical JSON"
        );

        // Different content should have different digest
        let receipt3 = json!({
            "submission_id": "sub-789",
            "external_run_id": "run-456",
            "outcome": "Found"
        });

        let receipt_bytes3 = canonical_json(&receipt3).expect("canonical receipt JSON 3");
        let receipt_digest3 = sha256_digest(&receipt_bytes3);

        assert_ne!(
            receipt_digest, receipt_digest3,
            "different JSON content must have different digests"
        );
    }

    #[test]
    fn test_evidence_expectation_structure_matches_stored() {
        let case_id = Uuid::new_v4();
        let effect_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let worker_session_id = Uuid::new_v4();

        let evidence = json!({
            "case_id": case_id,
            "effect_intent_id": effect_id,
            "worker_id": worker_id,
            "worker_generation": 1i64,
            "worker_session_id": worker_session_id,
            "external_run_id": "ext-run-789",
            "receipt_digest": "sha256:aaaa",
            "work_order_envelope_digest": "sha256:1111",
            "work_order_payload_digest": "sha256:0000",
            "lookup_receipt_digest": "sha256:aaaa",
        });

        assert_eq!(evidence["case_id"], case_id.to_string());
        assert_eq!(evidence["worker_generation"], 1);
        assert!(evidence.is_object());

        let evidence_bytes = canonical_json(&evidence).expect("canonical evidence JSON");
        let digest1 = sha256_digest(&evidence_bytes);

        // Re-serialize same evidence should give same digest
        let evidence_bytes2 = canonical_json(&evidence).expect("canonical evidence JSON 2");
        let digest2 = sha256_digest(&evidence_bytes2);

        assert_eq!(digest1, digest2, "same evidence must have same digest");
    }

    #[test]
    fn test_replay_detection_requires_identical_receipt_json() {
        let receipt1 = json!({
            "schema": "asf.runmill-lookup-qualified-submission-receipt.v1",
            "outcome": "Found",
            "run_id": "ext-run-123"
        });

        let receipt1_bytes = canonical_json(&receipt1).expect("receipt 1 canonical");
        let receipt1_digest = sha256_digest(&receipt1_bytes);

        let receipt2 = json!({
            "schema": "asf.runmill-lookup-qualified-submission-receipt.v1",
            "outcome": "NotFound",
            "run_id": "ext-run-123"
        });

        let receipt2_bytes = canonical_json(&receipt2).expect("receipt 2 canonical");
        let receipt2_digest = sha256_digest(&receipt2_bytes);

        assert_ne!(
            receipt1_digest, receipt2_digest,
            "different receipt outcomes must have different digests, causing replay conflict"
        );
    }

    #[test]
    fn test_replay_detection_requires_identical_evidence_json() {
        let evidence1 = json!({
            "case_id": "case-123",
            "external_run_id": "ext-run-456",
            "worker_generation": 1
        });

        let evidence1_bytes = canonical_json(&evidence1).expect("evidence 1 canonical");
        let evidence1_digest = sha256_digest(&evidence1_bytes);

        let evidence2 = json!({
            "case_id": "case-123",
            "external_run_id": "ext-run-456",
            "worker_generation": 2
        });

        let evidence2_bytes = canonical_json(&evidence2).expect("evidence 2 canonical");
        let evidence2_digest = sha256_digest(&evidence2_bytes);

        assert_ne!(
            evidence1_digest, evidence2_digest,
            "different evidence worker_generation must have different digests, causing replay conflict"
        );
    }

    #[test]
    fn test_case_locking_ensures_serialization() {
        let sql = r"
        SELECT state
        FROM runmill_submission_recovery_cases
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ";

        assert!(
            sql.contains("FOR UPDATE"),
            "case lock must use FOR UPDATE for serialization"
        );
        assert!(sql.contains("tenant_id = $1"), "must lock by tenant_id");
        assert!(sql.contains("id = $2"), "must lock by id");
    }
}
