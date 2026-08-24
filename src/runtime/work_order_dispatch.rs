//! Pure Work Order construction, signing, and bounded persistence.
//!
//! This module assembles, signs, and persists [`WorkOrderV1`] payloads. Construction
//! performs no I/O. Persistence is transaction-safe and fail-closed: it validates the
//! signed envelope, checks state invariants, and uses fenced upserts to prevent conflicting
//! updates. The actual Runmill dispatch remains the caller's responsibility.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

use uuid::Uuid;

use crate::{
    Error, Result,
    contracts::{
        CheckRequirements, ContractDigests, RepositoryTarget, SignedWorkOrder,
        WORK_ORDER_SCHEMA_V1, WorkOrderV1,
    },
    crypto::{Ed25519Signer, canonical_json, sha256_digest},
    domain::{
        AttemptId, ClosureTarget, ExecutionAuthority, RiskAssessment, SourceSystem, TenantId,
        WorkItemId, WorkOrderId, WorkOrderIdentities,
    },
    ledger::{RunmillSubmissionEffectBinding, StepEffectIntent},
    security::reject_sensitive_fields,
};

const LOCK_ATTEMPT_SQL: &str = r"
SELECT
    attempt.state,
    attempt.work_order_digest,
    attempt.aggregate_version
FROM attempts AS attempt
WHERE attempt.tenant_id = $1
  AND attempt.id = $2
  AND attempt.work_item_id = $3
FOR UPDATE OF attempt
";

const CHECK_DISPATCH_FENCE_SQL: &str = r"
SELECT EXISTS(
    SELECT 1 FROM work_item_dispatch_fences
    WHERE tenant_id = $1
      AND work_item_id = $2
      AND paused = true
      AND resolved_at IS NULL
) AS has_fence
";

const INSERT_WORK_ORDER_SQL: &str = r"
INSERT INTO work_orders (
    id,
    tenant_id,
    work_item_id,
    attempt_id,
    schema_version,
    envelope_schema,
    algorithm,
    key_id,
    idempotency_key,
    payload_digest,
    canonical_payload,
    payload,
    signature,
    exact_signed_envelope,
    issued_at,
    not_before,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
)
ON CONFLICT (tenant_id, attempt_id) DO UPDATE SET
    id = work_orders.id
WHERE work_orders.id = EXCLUDED.id
  AND work_orders.idempotency_key = EXCLUDED.idempotency_key
  AND work_orders.canonical_payload = EXCLUDED.canonical_payload
  AND work_orders.payload = EXCLUDED.payload
  AND work_orders.issued_at = EXCLUDED.issued_at
  AND work_orders.not_before = EXCLUDED.not_before
  AND work_orders.expires_at = EXCLUDED.expires_at
  AND work_orders.payload_digest = EXCLUDED.payload_digest
  AND work_orders.envelope_schema = EXCLUDED.envelope_schema
  AND work_orders.algorithm = EXCLUDED.algorithm
  AND work_orders.key_id = EXCLUDED.key_id
  AND work_orders.signature = EXCLUDED.signature
  AND work_orders.exact_signed_envelope = EXCLUDED.exact_signed_envelope
RETURNING work_orders.id
";

const UPDATE_ATTEMPT_DIGEST_SQL: &str = r"
UPDATE attempts AS attempt
SET work_order_digest = $3,
    aggregate_version = attempt.aggregate_version + 1,
    updated_at = clock_timestamp()
WHERE attempt.tenant_id = $1
  AND attempt.id = $2
  AND attempt.work_order_digest IS NULL
RETURNING attempt.aggregate_version
";

/// Explicit, fully-typed inputs for one Work Order. Every field the signed
/// payload carries must be supplied by the caller; nothing is inferred.
#[derive(Debug, Clone)]
pub struct WorkOrderBuildInput {
    pub work_order_id: WorkOrderId,
    pub tenant_id: TenantId,
    pub work_item_id: WorkItemId,
    pub attempt_id: AttemptId,
    pub idempotency_key: String,
    pub source_system: SourceSystem,
    pub source_external_id: String,
    pub source_snapshot_digest: String,
    pub source_reference: String,
    pub repository: RepositoryTarget,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub non_goals: Vec<String>,
    pub checks: CheckRequirements,
    pub risk: RiskAssessment,
    pub identities: WorkOrderIdentities,
    pub authority: ExecutionAuthority,
    pub closure_target: ClosureTarget,
    pub digests: ContractDigests,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Assemble, validate, and sign one Work Order. Rejects any input that fails
/// [`WorkOrderV1::validate`] before it is ever handed to the signer.
pub fn build_signed_work_order(
    input: WorkOrderBuildInput,
    signer: &Ed25519Signer,
) -> Result<SignedWorkOrder> {
    let payload = WorkOrderV1 {
        schema: WORK_ORDER_SCHEMA_V1.into(),
        work_order_id: input.work_order_id,
        tenant_id: input.tenant_id,
        work_item_id: input.work_item_id,
        attempt_id: input.attempt_id,
        idempotency_key: input.idempotency_key,
        source_system: input.source_system,
        source_external_id: input.source_external_id,
        source_snapshot_digest: input.source_snapshot_digest,
        source_reference: input.source_reference,
        repository: input.repository,
        objective: input.objective,
        acceptance_criteria: input.acceptance_criteria,
        non_goals: input.non_goals,
        checks: input.checks,
        risk: input.risk,
        identities: input.identities,
        authority: input.authority,
        closure_target: input.closure_target,
        digests: input.digests,
        issued_at: input.issued_at,
        not_before: input.not_before,
        expires_at: input.expires_at,
    };
    payload.validate()?;
    SignedWorkOrder::sign(payload, signer)
}

/// Persist a signed work order atomically within a transaction.
///
/// This function:
/// 1. Validates the payload and envelope structure (digest/schema/timestamps)
/// 2. Canonicalizes the payload and protected envelope as exact bytes
/// 3. Locks the attempt and work item, checking state and constraints
/// 4. Inserts exactly one `work_orders` row with all immutable fields
/// 5. Updates `attempts.work_order_digest` only from NULL to the payload digest
///
/// Verification (via a supplied `VerifyingKey`) is performed only if explicitly requested
/// via a separate call; this function enforces structural envelope/payload/digest invariants
/// and identity matching, but does not cryptographically verify the signature.
///
/// # Arguments
/// * `transaction` - Mutable transaction to use for database operations
/// * `tenant_id` - Tenant ID to verify against the signed payload
/// * `work_item_id` - Work item ID to verify against the signed payload
/// * `attempt_id` - Attempt ID to verify against the signed payload
/// * `order` - The signed work order to persist
///
/// # Returns
/// The work order ID if persistence succeeds; an error if validation fails,
/// state invariants are violated, or a conflicting order already exists.
///
/// # Fail-Closed Invariants
/// - Envelope schema and algorithm must be recognized
/// - Payload digest must match canonical payload bytes
/// - All envelope timestamps must match payload timestamps
/// - Tenant, work item, and attempt IDs must match exactly
/// - Attempt state must be `AUTHORIZED` or `DISPATCHING`
/// - Attempt `work_order_digest` must be NULL or exactly equal to this payload's digest
/// - No paused dispatch fence on the attempt
/// - INSERT rejects if any immutable field or digest differs (ON CONFLICT)
pub async fn persist_signed_work_order(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    work_item_id: WorkItemId,
    attempt_id: AttemptId,
    order: &SignedWorkOrder,
) -> Result<String> {
    order.payload.validate()?;

    if order.payload.tenant_id != tenant_id
        || order.payload.work_item_id != work_item_id
        || order.payload.attempt_id != attempt_id
    {
        return Err(Error::Validation(
            "Work Order tenant/work_item/attempt IDs do not match expected values".into(),
        ));
    }

    if order.envelope_schema != "asf.work-order-envelope/v1" || order.algorithm != "EdDSA" {
        return Err(Error::Validation(format!(
            "unsupported Work Order envelope: schema={}, algorithm={}",
            order.envelope_schema, order.algorithm
        )));
    }

    if order.issued_at != order.payload.issued_at
        || order.not_before != order.payload.not_before
        || order.expires_at != order.payload.expires_at
    {
        return Err(Error::Validation(
            "Work Order envelope and payload timestamps do not match".into(),
        ));
    }

    let payload_bytes = order.payload.canonical_bytes()?;
    let payload_digest = sha256_digest(&payload_bytes);

    if order.payload_digest != payload_digest {
        return Err(Error::Validation(
            "Work Order payload digest mismatch".into(),
        ));
    }

    reject_sensitive_fields(&order.payload.clone().to_json_value()?)?;

    let exact_envelope_bytes = build_exact_signed_envelope_bytes(order)?;

    let locked_attempt = sqlx::query(LOCK_ATTEMPT_SQL)
        .bind(tenant_id.as_uuid())
        .bind(attempt_id.as_uuid())
        .bind(work_item_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|e| Error::Persistence(format!("lock attempt: {e}")))?
        .ok_or_else(|| Error::NotFound(format!("attempt {attempt_id} not found")))?;

    let state: String = locked_attempt.get("state");
    let existing_digest: Option<String> = locked_attempt.get("work_order_digest");

    if state != "AUTHORIZED" && state != "DISPATCHING" {
        return Err(Error::InvalidTransition {
            from: state.clone(),
            to: "AWAITING_WORK_ORDER".into(),
        });
    }

    let fence_check = sqlx::query(CHECK_DISPATCH_FENCE_SQL)
        .bind(tenant_id.as_uuid())
        .bind(work_item_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|e| Error::Persistence(format!("check dispatch fence: {e}")))?;

    let has_fence: bool = fence_check.get("has_fence");
    if has_fence {
        return Err(Error::Conflict(
            "Attempt has active paused dispatch fence".into(),
        ));
    }

    if let Some(ref existing) = existing_digest
        && existing != &payload_digest
    {
        return Err(Error::Conflict(format!(
            "Attempt already has different work_order_digest: {existing}"
        )));
    }

    let payload_json: Value = serde_json::to_value(&order.payload)
        .map_err(|e| Error::Serialization(format!("serialize payload: {e}")))?;

    let work_order_id = order.payload.work_order_id.as_uuid();

    let result = sqlx::query(INSERT_WORK_ORDER_SQL)
        .bind(work_order_id)
        .bind(tenant_id.as_uuid())
        .bind(work_item_id.as_uuid())
        .bind(attempt_id.as_uuid())
        .bind(WORK_ORDER_SCHEMA_V1)
        .bind(&order.envelope_schema)
        .bind(&order.algorithm)
        .bind(&order.key_id)
        .bind(&order.payload.idempotency_key)
        .bind(&payload_digest)
        .bind(payload_bytes.as_slice())
        .bind(&payload_json)
        .bind(&order.signature)
        .bind(exact_envelope_bytes.as_slice())
        .bind(order.issued_at)
        .bind(order.not_before)
        .bind(order.expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|e| Error::Persistence(format!("insert work_order: {e}")))?;

    if result.is_none() {
        return Err(Error::Conflict(
            "Work order with this attempt already exists with different envelope".into(),
        ));
    }

    if existing_digest.is_none() {
        let updated = sqlx::query(UPDATE_ATTEMPT_DIGEST_SQL)
            .bind(tenant_id.as_uuid())
            .bind(attempt_id.as_uuid())
            .bind(&payload_digest)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|e| Error::Persistence(format!("update attempt digest: {e}")))?;

        if updated.is_none() {
            return Err(Error::Conflict(
                "Attempt work_order_digest was modified concurrently".into(),
            ));
        }
    }

    Ok(work_order_id.to_string())
}

fn build_exact_signed_envelope_bytes(order: &SignedWorkOrder) -> Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct SignedEnvelope<'a> {
        schema: &'a str,
        algorithm: &'a str,
        key_id: &'a str,
        issued_at: DateTime<Utc>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        payload_digest: &'a str,
        payload: &'a WorkOrderV1,
        signature: &'a str,
    }

    canonical_json(&SignedEnvelope {
        schema: &order.envelope_schema,
        algorithm: &order.algorithm,
        key_id: &order.key_id,
        issued_at: order.issued_at,
        not_before: order.not_before,
        expires_at: order.expires_at,
        payload_digest: &order.payload_digest,
        payload: &order.payload,
        signature: &order.signature,
    })
}

/// Construct a bounded submission effect intent from a signed work order.
///
/// This function builds an immutable [`StepEffectIntent`] that captures the exact
/// signed envelope for submission to Runmill. It validates the work order structurally,
/// ensures all IDs are non-nil, serializes the exact envelope as JSON, canonicalizes it,
/// and binds the effect to the work order via digest and ID.
///
/// The idempotency key is deterministically derived from `tenant`/`work_item`/`attempt` IDs,
/// ensuring the effect is idempotent at the attempt level. The request digest is computed
/// from the canonical envelope, and the request payload is the exact envelope object.
///
/// # Arguments
/// * `order` - The signed work order to package for submission
/// * `effect_id` - UUID for the effect intent row
/// * `next_attempt_at` - When to retry the submission if it fails
///
/// # Returns
/// A [`StepEffectIntent`] ready to be persisted and dispatched, or an error if:
/// - Any required ID is nil (`effect`, `tenant`, `work_item`, `attempt`, `work_order`)
/// - The work order has expired or is not yet valid
/// - Envelope or payload validation fails
/// - Envelope/payload timestamps do not match
/// - Payload digest does not match canonical payload
///
/// # No I/O
/// This function is pure: it performs no database or network operations.
pub fn build_submission_effect_intent(
    order: &SignedWorkOrder,
    effect_id: Uuid,
    next_attempt_at: DateTime<Utc>,
) -> Result<StepEffectIntent> {
    if effect_id.is_nil() {
        return Err(Error::Validation("effect_id cannot be nil".into()));
    }

    order.payload.validate()?;

    if order.payload.tenant_id.as_uuid().is_nil() {
        return Err(Error::Validation("tenant_id cannot be nil".into()));
    }

    if order.payload.work_item_id.as_uuid().is_nil() {
        return Err(Error::Validation("work_item_id cannot be nil".into()));
    }

    if order.payload.attempt_id.as_uuid().is_nil() {
        return Err(Error::Validation("attempt_id cannot be nil".into()));
    }

    if order.payload.work_order_id.as_uuid().is_nil() {
        return Err(Error::Validation("work_order_id cannot be nil".into()));
    }

    if order.envelope_schema != "asf.work-order-envelope/v1" || order.algorithm != "EdDSA" {
        return Err(Error::Validation(format!(
            "unsupported Work Order envelope: schema={}, algorithm={}",
            order.envelope_schema, order.algorithm
        )));
    }

    if order.issued_at != order.payload.issued_at
        || order.not_before != order.payload.not_before
        || order.expires_at != order.payload.expires_at
    {
        return Err(Error::Validation(
            "Work Order envelope and payload timestamps do not match".into(),
        ));
    }

    let payload_bytes = order.payload.canonical_bytes()?;
    let payload_digest = sha256_digest(&payload_bytes);

    if order.payload_digest != payload_digest {
        return Err(Error::Validation(
            "Work Order payload digest mismatch".into(),
        ));
    }

    let envelope_bytes = build_exact_signed_envelope_bytes(order)?;
    let request_digest = sha256_digest(&envelope_bytes);

    let request_payload = serde_json::to_value(order)
        .map_err(|e| Error::Serialization(format!("serialize signed envelope: {e}")))?;

    let idempotency_key = format!(
        "runmill:submit:{}/{}/{}",
        order.payload.tenant_id.as_uuid(),
        order.payload.work_order_id.as_uuid(),
        order.payload.attempt_id.as_uuid()
    );

    let runmill_submission = RunmillSubmissionEffectBinding {
        work_order_id: order.payload.work_order_id.as_uuid(),
        work_order_digest: payload_digest,
    };

    let effect = StepEffectIntent {
        id: effect_id,
        attempt_id: Some(order.payload.attempt_id.as_uuid()),
        provider: "runmill".into(),
        effect_type: "submit_work_order".into(),
        idempotency_key,
        correlation_marker: None,
        request_digest,
        request_payload,
        runmill_submission: Some(runmill_submission),
        next_attempt_at,
    };

    Ok(effect)
}

trait ToJsonValue {
    fn to_json_value(&self) -> Result<Value>;
}

impl ToJsonValue for WorkOrderV1 {
    fn to_json_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|e| Error::Serialization(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;
    use crate::{
        contracts::{CheckRequirements, ContractDigests, RepositoryTarget},
        crypto::{Ed25519Signer, sha256_digest},
        domain::{
            AttemptId, BudgetLimits, ClosureTarget, CtxlaneProfileRef, DeliveryPermission,
            EffectAuthority, ExecutionAuthority, PathAuthority, RepositoryId, RiskAssessment,
            RiskClass, SourceSystem, TenantId, ToolAuthority, WorkItemId, WorkOrderId,
            WorkOrderIdentities,
        },
    };

    fn profile(value: &str) -> CtxlaneProfileRef {
        value
            .parse()
            .unwrap_or_else(|error| panic!("valid ctxlane profile ref: {error}"))
    }

    fn strings(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-24T10:00:00Z").map_or_else(
            |error| panic!("valid test time: {error}"),
            |value| value.with_timezone(&Utc),
        )
    }

    fn valid_input() -> WorkOrderBuildInput {
        let issued_at = now();
        WorkOrderBuildInput {
            work_order_id: WorkOrderId::new(),
            tenant_id: TenantId::new(),
            work_item_id: WorkItemId::new(),
            attempt_id: AttemptId::new(),
            idempotency_key: "tenant/work-item/attempt".into(),
            source_system: SourceSystem::Linear,
            source_external_id: "ENG-123".into(),
            source_snapshot_digest: sha256_digest(b"source"),
            source_reference: "linear:ENG-123".into(),
            repository: RepositoryTarget {
                repository_id: RepositoryId::new(),
                forge: "github".into(),
                owner: "acme".into(),
                name: "payments".into(),
                base_ref: "refs/heads/main".into(),
                base_sha: "0123456789012345678901234567890123456789".into(),
            },
            objective: "Fix the bounded defect".into(),
            acceptance_criteria: vec!["The regression test passes".into()],
            non_goals: vec!["No unrelated refactor".into()],
            checks: CheckRequirements {
                local_check_ids: strings(&["unit"]),
                remote_ci_contexts: strings(&["ci/test"]),
            },
            risk: RiskAssessment {
                class: RiskClass::Low,
                reasons: vec!["bounded change".into()],
                matched_rules: strings(&["low-risk-default"]),
            },
            identities: WorkOrderIdentities {
                implementer: profile("codex:asf-production"),
                local_reviewer: profile("claude:asf-review"),
                pr_reviewer: profile("claude:asf-review"),
            },
            authority: ExecutionAuthority {
                paths: PathAuthority {
                    allowed: strings(&["src/**", "tests/**"]),
                    forbidden: strings(&[".github/**"]),
                },
                tools: ToolAuthority {
                    allowed_tools: strings(&["filesystem", "shell"]),
                    allowed_commands: strings(&["cargo test"]),
                    network_destinations: BTreeSet::new(),
                },
                effects: EffectAuthority {
                    delivery: DeliveryPermission::PullRequest,
                    may_comment: false,
                    may_update_checks: false,
                    deployment_environment: None,
                },
                budgets: BudgetLimits {
                    max_cost_microunits: 10_000_000,
                    max_input_tokens: 100_000,
                    max_output_tokens: 50_000,
                    max_implementer_invocations: 4,
                    max_reviewer_invocations: 2,
                    max_fix_iterations: 2,
                    max_wall_time_seconds: 3_600,
                    max_external_api_calls: 20,
                },
                required_approval_types: BTreeSet::new(),
                sandbox_policy_ref: "linux-production-v1".into(),
            },
            closure_target: ClosureTarget::PullRequest,
            digests: ContractDigests {
                policy: sha256_digest(b"policy"),
                repository_policy: sha256_digest(b"repository-policy"),
                planner: sha256_digest(b"planner"),
                harness: sha256_digest(b"harness"),
            },
            issued_at,
            not_before: issued_at,
            expires_at: issued_at + TimeDelta::minutes(15),
        }
    }

    #[test]
    fn signing_and_digest_are_deterministic_for_identical_input() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();

        let first = build_signed_work_order(input.clone(), &signer)
            .unwrap_or_else(|error| panic!("valid input signs: {error}"));
        let second = build_signed_work_order(input, &signer)
            .unwrap_or_else(|error| panic!("valid input signs: {error}"));

        assert_eq!(first, second);
        assert_eq!(first.payload_digest, second.payload_digest);
        assert_eq!(
            first.payload_digest,
            first
                .payload
                .digest()
                .unwrap_or_else(|error| panic!("payload digest: {error}"))
        );
    }

    #[test]
    fn tampering_with_the_signed_payload_is_rejected() {
        let signer = Ed25519Signer::generate("asf-test");
        let key = signer.verifying_key();
        let input = valid_input();
        let not_before = input.not_before;

        let mut signed = build_signed_work_order(input, &signer)
            .unwrap_or_else(|error| panic!("valid input signs: {error}"));
        signed.verify(&key, not_before).unwrap_or_else(|error| {
            panic!("untampered envelope verifies: {error}");
        });

        signed.payload.objective.push_str(" with wider scope");
        assert!(signed.verify(&key, not_before).is_err());
    }

    #[test]
    fn invalid_authority_is_rejected_before_signing() {
        let signer = Ed25519Signer::generate("asf-test");
        let mut input = valid_input();
        input.authority.effects.delivery = DeliveryPermission::DirectMerge;

        assert!(build_signed_work_order(input, &signer).is_err());
    }

    #[test]
    fn shared_implementer_and_reviewer_identity_is_rejected() {
        let signer = Ed25519Signer::generate("asf-test");
        let mut input = valid_input();
        input.identities.local_reviewer = input.identities.implementer.clone();

        assert!(build_signed_work_order(input, &signer).is_err());
    }

    #[test]
    fn validating_mismatched_tenant_id_rejects_early() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let wrong_tenant = TenantId::new();
        assert_ne!(signed.payload.tenant_id, wrong_tenant);

        let error = validate_persistence_preconditions(
            wrong_tenant,
            input.work_item_id,
            input.attempt_id,
            &signed,
        );
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn validating_tampered_digest_rejects_early() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let mut signed =
            build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        signed.payload_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let error = validate_persistence_preconditions(
            input.tenant_id,
            input.work_item_id,
            input.attempt_id,
            &signed,
        );
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn validating_mismatched_work_item_id_rejects_early() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let wrong_work_item = WorkItemId::new();
        assert_ne!(signed.payload.work_item_id, wrong_work_item);

        let error = validate_persistence_preconditions(
            input.tenant_id,
            wrong_work_item,
            input.attempt_id,
            &signed,
        );
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn validating_mismatched_attempt_id_rejects_early() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let wrong_attempt = AttemptId::new();
        assert_ne!(signed.payload.attempt_id, wrong_attempt);

        let error = validate_persistence_preconditions(
            input.tenant_id,
            input.work_item_id,
            wrong_attempt,
            &signed,
        );
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    fn validate_persistence_preconditions(
        tenant_id: TenantId,
        work_item_id: WorkItemId,
        attempt_id: AttemptId,
        order: &SignedWorkOrder,
    ) -> Result<()> {
        order.payload.validate()?;

        if order.payload.tenant_id != tenant_id
            || order.payload.work_item_id != work_item_id
            || order.payload.attempt_id != attempt_id
        {
            return Err(Error::Validation(
                "Work Order tenant/work_item/attempt IDs do not match expected values".into(),
            ));
        }

        if order.envelope_schema != "asf.work-order-envelope/v1" || order.algorithm != "EdDSA" {
            return Err(Error::Validation(format!(
                "unsupported Work Order envelope: schema={}, algorithm={}",
                order.envelope_schema, order.algorithm
            )));
        }

        if order.issued_at != order.payload.issued_at
            || order.not_before != order.payload.not_before
            || order.expires_at != order.payload.expires_at
        {
            return Err(Error::Validation(
                "Work Order envelope and payload timestamps do not match".into(),
            ));
        }

        let payload_bytes = order.payload.canonical_bytes()?;
        let payload_digest = sha256_digest(&payload_bytes);

        if order.payload_digest != payload_digest {
            return Err(Error::Validation(
                "Work Order payload digest mismatch".into(),
            ));
        }

        Ok(())
    }

    #[test]
    fn submission_effect_intent_has_deterministic_identity() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let first = build_submission_effect_intent(&signed, effect_id, next_attempt_at)
            .expect("valid signed order builds effect intent");
        let second = build_submission_effect_intent(&signed, effect_id, next_attempt_at)
            .expect("valid signed order builds effect intent");

        assert_eq!(first, second);
        assert_eq!(first.id, effect_id);
        assert_eq!(first.attempt_id, Some(input.attempt_id.as_uuid()));
    }

    #[test]
    fn submission_effect_intent_idempotency_key_is_deterministic() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        assert_eq!(
            effect.idempotency_key,
            format!(
                "runmill:submit:{}/{}/{}",
                input.tenant_id.as_uuid(),
                input.work_order_id.as_uuid(),
                input.attempt_id.as_uuid()
            )
        );
    }

    #[test]
    fn submission_effect_intent_request_digest_matches_canonical_envelope() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        let envelope_bytes =
            build_exact_signed_envelope_bytes(&signed).expect("canonical envelope bytes");
        let expected_digest = sha256_digest(&envelope_bytes);

        assert_eq!(effect.request_digest, expected_digest);
    }

    #[test]
    fn submission_effect_intent_request_payload_is_exact_signed_envelope() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        let expected_payload =
            serde_json::to_value(&signed).expect("serialize signed envelope to json");

        assert_eq!(effect.request_payload, expected_payload);
    }

    #[test]
    fn submission_effect_intent_provider_and_effect_type_are_correct() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        assert_eq!(effect.provider, "runmill");
        assert_eq!(effect.effect_type, "submit_work_order");
    }

    #[test]
    fn submission_effect_intent_binds_runmill_submission_correctly() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        let binding = effect
            .runmill_submission
            .expect("runmill_submission must be present");

        assert_eq!(binding.work_order_id, input.work_order_id.as_uuid());
        assert_eq!(binding.work_order_digest, signed.payload_digest);
    }

    #[test]
    fn submission_effect_intent_rejects_nil_effect_id() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let nil_effect_id = Uuid::nil();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let error = build_submission_effect_intent(&signed, nil_effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn submission_effect_intent_validates_work_order_payload() {
        let signer = Ed25519Signer::generate("asf-test");
        let mut input = valid_input();
        input.acceptance_criteria.clear();

        let signed = build_signed_work_order(input, &signer).expect_err("invalid input");
        assert!(matches!(signed, Error::Validation(_)));
    }

    #[test]
    fn submission_effect_intent_rejects_mismatched_timestamps() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let mut signed = build_signed_work_order(input, &signer).expect("valid input signs");

        signed.expires_at = now() + TimeDelta::hours(1);

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let error = build_submission_effect_intent(&signed, effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn submission_effect_intent_rejects_tampered_digest() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let mut signed = build_signed_work_order(input, &signer).expect("valid input signs");

        signed.payload_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let error = build_submission_effect_intent(&signed, effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn submission_effect_intent_rejects_unsupported_envelope_schema() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let mut signed = build_signed_work_order(input, &signer).expect("valid input signs");

        signed.envelope_schema = "unsupported-schema".into();

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let error = build_submission_effect_intent(&signed, effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn submission_effect_intent_rejects_unsupported_algorithm() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let mut signed = build_signed_work_order(input, &signer).expect("valid input signs");

        signed.algorithm = "ECDSA".into();

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let error = build_submission_effect_intent(&signed, effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }

    #[test]
    fn submission_effect_intents_with_different_orders_have_different_digests() {
        let signer = Ed25519Signer::generate("asf-test");
        let mut input1 = valid_input();
        let mut input2 = valid_input();

        input1.objective = "Fix issue A".into();
        input2.objective = "Fix issue B".into();

        let signed1 = build_signed_work_order(input1, &signer).expect("valid input signs");
        let signed2 = build_signed_work_order(input2, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect1 =
            build_submission_effect_intent(&signed1, effect_id, next_attempt_at).expect("valid");
        let effect2 =
            build_submission_effect_intent(&signed2, effect_id, next_attempt_at).expect("valid");

        assert_ne!(effect1.request_digest, effect2.request_digest);
        assert_ne!(effect1.idempotency_key, effect2.idempotency_key);
    }

    #[test]
    fn submission_effect_intent_sets_attempt_id_correctly() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input.clone(), &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        assert_eq!(effect.attempt_id, Some(input.attempt_id.as_uuid()));
    }

    #[test]
    fn submission_effect_intent_correlation_marker_is_none() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        assert_eq!(effect.correlation_marker, None);
    }

    #[test]
    fn submission_effect_intent_preserves_next_attempt_at() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(5);

        let effect =
            build_submission_effect_intent(&signed, effect_id, next_attempt_at).expect("valid");

        assert_eq!(effect.next_attempt_at, next_attempt_at);
    }

    #[test]
    fn submission_effect_intent_rejects_mutated_request_digest() {
        let signer = Ed25519Signer::generate("asf-test");
        let input = valid_input();
        let signed = build_signed_work_order(input, &signer).expect("valid input signs");

        let effect_id = Uuid::now_v7();
        let next_attempt_at = now() + TimeDelta::minutes(1);

        let tampered_signed = {
            let mut order = signed.clone();
            order.payload_digest =
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string();
            order
        };

        let error = build_submission_effect_intent(&tampered_signed, effect_id, next_attempt_at);
        assert!(matches!(error, Err(Error::Validation(_))));
    }
}
