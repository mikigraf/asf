use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{PgLedger, persistence_error};
use crate::{
    Error, Result,
    crypto::{canonical_json, sha256_digest},
    domain::{BudgetLimits, CtxlaneProfileRef, WorkOrderIdentities},
};

const MAX_SAFE_TEXT_BYTES: usize = 512;
const MAX_EXPIRY_SWEEP_BATCH_SIZE: u32 = 1_000;
const ACQUISITION_REASON: &str = "atomic admission acquired";
const EXPIRY_SWEEP_REASON: &str = "reservation TTL elapsed";
const INTERNAL_IDEMPOTENCY_NAMESPACE_PREFIX: &str = "asf-internal:";
const EXPIRY_SWEEP_IDEMPOTENCY_PREFIX: &str = "asf-internal:reservation-expiry:v1:";
const WORK_CLOSURE_IDEMPOTENCY_PREFIX: &str = "work-closure:v1:";
const RUNMILL_CANCELLATION_IDEMPOTENCY_PREFIX: &str = "runmill-cancellation:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationBudgetDimension {
    CostMicrounits,
    InputTokens,
    OutputTokens,
    ImplementerInvocations,
    ReviewerInvocations,
    FixIterations,
    WallTimeSeconds,
    ExternalApiCalls,
}

impl ReservationBudgetDimension {
    const ALL: [Self; 8] = [
        Self::CostMicrounits,
        Self::InputTokens,
        Self::OutputTokens,
        Self::ImplementerInvocations,
        Self::ReviewerInvocations,
        Self::FixIterations,
        Self::WallTimeSeconds,
        Self::ExternalApiCalls,
    ];

    const fn database_value(self) -> &'static str {
        match self {
            Self::CostMicrounits => "COST_MICROUNITS",
            Self::InputTokens => "INPUT_TOKENS",
            Self::OutputTokens => "OUTPUT_TOKENS",
            Self::ImplementerInvocations => "IMPLEMENTER_INVOCATIONS",
            Self::ReviewerInvocations => "REVIEWER_INVOCATIONS",
            Self::FixIterations => "FIX_ITERATIONS",
            Self::WallTimeSeconds => "WALL_TIME_SECONDS",
            Self::ExternalApiCalls => "EXTERNAL_API_CALLS",
        }
    }

    const fn unit(self) -> &'static str {
        match self {
            Self::CostMicrounits => "microunits",
            Self::InputTokens | Self::OutputTokens => "tokens",
            Self::ImplementerInvocations | Self::ReviewerInvocations => "invocations",
            Self::FixIterations => "iterations",
            Self::WallTimeSeconds => "seconds",
            Self::ExternalApiCalls => "calls",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReservationAmounts {
    pub cost_microunits: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub implementer_invocations: u32,
    pub reviewer_invocations: u32,
    pub fix_iterations: u32,
    pub wall_time_seconds: u64,
    pub external_api_calls: u32,
}

impl BudgetReservationAmounts {
    const fn amount(self, dimension: ReservationBudgetDimension) -> u64 {
        match dimension {
            ReservationBudgetDimension::CostMicrounits => self.cost_microunits,
            ReservationBudgetDimension::InputTokens => self.input_tokens,
            ReservationBudgetDimension::OutputTokens => self.output_tokens,
            ReservationBudgetDimension::ImplementerInvocations => {
                self.implementer_invocations as u64
            }
            ReservationBudgetDimension::ReviewerInvocations => self.reviewer_invocations as u64,
            ReservationBudgetDimension::FixIterations => self.fix_iterations as u64,
            ReservationBudgetDimension::WallTimeSeconds => self.wall_time_seconds,
            ReservationBudgetDimension::ExternalApiCalls => self.external_api_calls as u64,
        }
    }

    fn validate(self) -> Result<()> {
        for dimension in ReservationBudgetDimension::ALL {
            i64::try_from(self.amount(dimension)).map_err(|_| {
                Error::Validation(format!(
                    "budget reservation for {} exceeds PostgreSQL bigint capacity",
                    dimension.database_value()
                ))
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCapacityRequest {
    pub profile_ref: CtxlaneProfileRef,
    pub units: u32,
    pub expected_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationRequest {
    /// Proposed ID used only when the idempotency key has not been seen.
    pub reservation_set_id: Uuid,
    pub tenant_id: Uuid,
    pub work_item_id: Uuid,
    pub attempt_id: Uuid,
    pub repository_id: Uuid,
    pub expected_repository_generation: u64,
    pub worker_id: Uuid,
    /// Exact live session whose worker epoch authorizes this admission.
    pub worker_session_id: Uuid,
    pub expected_worker_generation: u64,
    pub identities: Vec<IdentityCapacityRequest>,
    pub budget: BudgetReservationAmounts,
    pub expires_at: DateTime<Utc>,
    pub actor_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDisposition {
    Acquired,
    Adopted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationKind {
    RepositoryWip,
    WorkerSlot,
    IdentityCapacity,
    Budget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedResource {
    pub id: Uuid,
    pub kind: ReservationKind,
    pub resource_key: String,
    pub budget_dimension: Option<ReservationBudgetDimension>,
    pub units: u64,
    pub resource_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReservationReceipt {
    pub reservation_set_id: Uuid,
    pub disposition: AdmissionDisposition,
    pub request_digest: String,
    pub fence_token: u64,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub acquisition_event_id: Uuid,
    pub resources: Vec<ReservedResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationTransitionRequest {
    pub tenant_id: Uuid,
    pub reservation_set_id: Uuid,
    pub expected_fence_token: u64,
    pub actor_id: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationTerminalState {
    Released,
    Expired,
}

/// Closed set of durable idempotency namespaces for terminal attempt releases.
///
/// These values are receipt semantics, not caller-controlled labels. In
/// particular, source-closure receipts are relationally verified by migration
/// 0013 and must retain their exact historical `work-closure:v1` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptReservationReleaseNamespace {
    WorkClosure,
    RunmillCancellation { terminal_receipt_id: Uuid },
}

impl AttemptReservationReleaseNamespace {
    const fn prefix(self) -> &'static str {
        match self {
            Self::WorkClosure => "work-closure",
            Self::RunmillCancellation { .. } => "runmill-cancellation",
        }
    }

    const fn cancellation_terminal_receipt_id(self) -> Option<Uuid> {
        match self {
            Self::WorkClosure => None,
            Self::RunmillCancellation {
                terminal_receipt_id,
            } => Some(terminal_receipt_id),
        }
    }

    fn idempotency_key(
        self,
        work_item_id: Uuid,
        attempt_id: Uuid,
        reservation_set_id: Uuid,
        current_fence: i64,
    ) -> String {
        format!(
            "{}:v1:{work_item_id}:{attempt_id}:{reservation_set_id}:fence:{current_fence}",
            self.prefix()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationTransitionDisposition {
    Applied,
    Adopted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationTransitionReceipt {
    pub reservation_set_id: Uuid,
    pub state: ReservationTerminalState,
    pub disposition: ReservationTransitionDisposition,
    pub previous_fence_token: u64,
    pub fence_token: u64,
    pub actor_id: String,
    pub reason: String,
    pub idempotency_key: String,
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct AdmissionSemantics<'a> {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    repository_id: Uuid,
    expected_repository_generation: u64,
    worker_id: Uuid,
    worker_session_id: Uuid,
    expected_worker_generation: u64,
    identities: &'a [IdentityCapacityRequest],
    budget: BudgetReservationAmounts,
    expires_at: DateTime<Utc>,
    actor_id: &'a str,
}

impl AdmissionReservationRequest {
    fn validate(&self) -> Result<Vec<IdentityCapacityRequest>> {
        for (label, id) in [
            ("reservation set", self.reservation_set_id),
            ("tenant", self.tenant_id),
            ("work item", self.work_item_id),
            ("attempt", self.attempt_id),
            ("repository", self.repository_id),
            ("worker", self.worker_id),
            ("worker session", self.worker_session_id),
        ] {
            if id.is_nil() {
                return Err(Error::Validation(format!(
                    "admission reservation {label} ID must be non-nil"
                )));
            }
        }
        if self.expected_repository_generation == 0 || self.expected_worker_generation == 0 {
            return Err(Error::Validation(
                "admission resource generations must be positive".into(),
            ));
        }
        validate_safe_text("admission actor", &self.actor_id)?;
        validate_external_idempotency_key("admission idempotency key", &self.idempotency_key)?;
        self.budget.validate()?;
        if self.identities.is_empty() {
            return Err(Error::Validation(
                "admission must reserve every required identity profile".into(),
            ));
        }
        let mut identities = self.identities.clone();
        identities.sort_by(|left, right| left.profile_ref.cmp(&right.profile_ref));
        let mut seen = BTreeSet::new();
        for identity in &identities {
            if identity.units == 0 || identity.expected_generation == 0 {
                return Err(Error::Validation(
                    "identity reservation units and generation must be positive".into(),
                ));
            }
            if !seen.insert(identity.profile_ref.clone()) {
                return Err(Error::Validation(format!(
                    "identity profile {} occurs more than once in admission",
                    identity.profile_ref
                )));
            }
        }
        Ok(identities)
    }

    fn request_digest(&self, identities: &[IdentityCapacityRequest]) -> Result<String> {
        let semantics = AdmissionSemantics {
            tenant_id: self.tenant_id,
            work_item_id: self.work_item_id,
            attempt_id: self.attempt_id,
            repository_id: self.repository_id,
            expected_repository_generation: self.expected_repository_generation,
            worker_id: self.worker_id,
            worker_session_id: self.worker_session_id,
            expected_worker_generation: self.expected_worker_generation,
            identities,
            budget: self.budget,
            expires_at: self.expires_at,
            actor_id: &self.actor_id,
        };
        canonical_json(&semantics).map(|bytes| sha256_digest(&bytes))
    }
}

impl ReservationTransitionRequest {
    fn validate(&self) -> Result<()> {
        if self.tenant_id.is_nil() || self.reservation_set_id.is_nil() {
            return Err(Error::Validation(
                "reservation transition IDs must be non-nil".into(),
            ));
        }
        if self.expected_fence_token == 0 {
            return Err(Error::Validation(
                "reservation transition fence must be positive".into(),
            ));
        }
        validate_safe_text("reservation transition actor", &self.actor_id)?;
        validate_safe_text("reservation transition reason", &self.reason)?;
        validate_external_idempotency_key(
            "reservation transition idempotency key",
            &self.idempotency_key,
        )
    }
}

impl PgLedger {
    /// Atomically acquire repository, worker, identity, and all budget
    /// reservations for an existing attempt.
    pub async fn acquire_admission_reservations(
        &self,
        request: &AdmissionReservationRequest,
    ) -> Result<AdmissionReservationReceipt> {
        let identities = request.validate()?;
        let request_digest = request.request_digest(&identities)?;
        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|error| persistence_error("begin admission reservation", error))?;

        advisory_lock(
            &mut transaction,
            &format!(
                "reservation-idempotency:{}:{}",
                request.tenant_id, request.idempotency_key
            ),
        )
        .await?;
        // Worker admission, session creation/revocation, and health
        // reconciliation share this first authority lock.  In particular, a
        // quarantining reconciler may release budget reservations while it
        // holds the worker row without deadlocking an admission that acquired
        // budget locks first.
        advisory_lock(
            &mut transaction,
            &format!(
                "worker-authority:{}:{}",
                request.tenant_id, request.worker_id
            ),
        )
        .await?;
        if let Some(existing) = load_set_by_idempotency_key(
            &mut transaction,
            request.tenant_id,
            &request.idempotency_key,
        )
        .await?
        {
            let receipt =
                adopt_existing_set(&mut transaction, request, &request_digest, &existing).await?;
            transaction
                .commit()
                .await
                .map_err(|error| persistence_error("commit adopted reservation", error))?;
            return Ok(receipt);
        }

        let resource_keys = admission_lock_keys(request, &identities);
        for resource_key in resource_keys {
            advisory_lock(&mut transaction, &resource_key).await?;
        }
        let now = database_now(&mut transaction).await?;
        if request.expires_at <= now {
            return Err(Error::Validation(
                "admission reservation expiry must be in the future".into(),
            ));
        }

        let context = load_and_validate_context(&mut transaction, request, &identities).await?;
        reject_existing_attempt_reservation(&mut transaction, request).await?;
        enforce_capacity(&mut transaction, request, &identities, &context).await?;
        let acquired_at =
            insert_reservation_set(&mut transaction, request, &request_digest).await?;
        insert_resources_and_budget_ledger(
            &mut transaction,
            request,
            &identities,
            &context,
            acquired_at,
        )
        .await?;
        let acquisition_event_id = insert_set_event(
            &mut transaction,
            request.tenant_id,
            request.reservation_set_id,
            "ACQUIRED",
            0,
            1,
            &request.actor_id,
            ACQUISITION_REASON,
            &request.idempotency_key,
            acquired_at,
        )
        .await?;
        let resources = load_resources(
            &mut transaction,
            request.tenant_id,
            request.reservation_set_id,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| persistence_error("commit admission reservation", error))?;
        Ok(AdmissionReservationReceipt {
            reservation_set_id: request.reservation_set_id,
            disposition: AdmissionDisposition::Acquired,
            request_digest,
            fence_token: 1,
            acquired_at,
            expires_at: request.expires_at,
            acquisition_event_id,
            resources,
        })
    }

    /// Release an active reservation set with an owner-supplied fence.
    pub async fn release_reservation_set(
        &self,
        request: &ReservationTransitionRequest,
    ) -> Result<ReservationTransitionReceipt> {
        transition_reservation_set(self, request, ReservationTerminalState::Released).await
    }

    /// Mark an elapsed reservation set expired with an owner-supplied fence.
    pub async fn expire_reservation_set(
        &self,
        request: &ReservationTransitionRequest,
    ) -> Result<ReservationTransitionReceipt> {
        transition_reservation_set(self, request, ReservationTerminalState::Expired).await
    }

    /// Durably expire a bounded batch of elapsed reservation sets.
    ///
    /// Capacity calculations stop counting elapsed sets immediately, but this
    /// sweep is what advances their durable state, fence, audit event, and
    /// budget-release entries. The database clock is authoritative. Concurrent
    /// sweepers use row locks with `SKIP LOCKED`, and explicit owner transitions
    /// serialize through the same budget/admission lock before taking a set
    /// lock.
    pub async fn expire_elapsed_reservation_sets(
        &self,
        tenant_id: Uuid,
        actor_id: &str,
        limit: u32,
    ) -> Result<Vec<ReservationTransitionReceipt>> {
        if tenant_id.is_nil() {
            return Err(Error::Validation(
                "reservation expiry sweep tenant ID must be non-nil".into(),
            ));
        }
        validate_safe_text("reservation expiry sweep actor", actor_id)?;
        if !(1..=MAX_EXPIRY_SWEEP_BATCH_SIZE).contains(&limit) {
            return Err(Error::Validation(format!(
                "reservation expiry sweep limit must be in 1..={MAX_EXPIRY_SWEEP_BATCH_SIZE}"
            )));
        }

        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|error| persistence_error("begin reservation expiry sweep", error))?;
        let candidates = sqlx::query(
            r"
            SELECT id, work_item_id
            FROM reservation_sets
            WHERE tenant_id = $1
              AND state = 'ACTIVE'
              AND expires_at <= clock_timestamp()
            ORDER BY expires_at, id
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| persistence_error("select elapsed reservation sets", error))?;

        let mut reservation_set_ids = Vec::with_capacity(candidates.len());
        let mut budget_lock_keys = BTreeSet::new();
        for candidate in &candidates {
            let reservation_set_id: Uuid = decode(candidate, "id", "elapsed reservation set ID")?;
            let work_item_id: Uuid =
                decode(candidate, "work_item_id", "elapsed reservation work item")?;
            reservation_set_ids.push(reservation_set_id);
            budget_lock_keys.insert(format!("admission:{tenant_id}:budget:{work_item_id}"));
        }
        for lock_key in budget_lock_keys {
            advisory_lock(&mut transaction, &lock_key).await?;
        }

        let rows = sqlx::query(
            r"
            SELECT id, fence_token, work_item_id, attempt_id
            FROM reservation_sets
            WHERE tenant_id = $1
              AND id = ANY($2)
              AND state = 'ACTIVE'
              AND expires_at <= clock_timestamp()
            ORDER BY expires_at, id
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(tenant_id)
        .bind(&reservation_set_ids)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| persistence_error("lock elapsed reservation sets", error))?;

        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let reservation_set_id: Uuid = decode(&row, "id", "elapsed reservation set ID")?;
            let current_fence: i64 = decode(&row, "fence_token", "reservation fence")?;
            let work_item_id: Uuid = decode(&row, "work_item_id", "elapsed reservation work item")?;
            let attempt_id: Uuid = decode(&row, "attempt_id", "elapsed reservation attempt")?;
            let request = ReservationTransitionRequest {
                tenant_id,
                reservation_set_id,
                expected_fence_token: positive_u64(current_fence)?,
                actor_id: actor_id.to_owned(),
                reason: EXPIRY_SWEEP_REASON.into(),
                idempotency_key: expiry_sweep_idempotency_key(reservation_set_id, current_fence),
            };
            receipts.push(
                apply_active_reservation_transition(
                    &mut transaction,
                    &request,
                    ReservationTerminalState::Expired,
                    current_fence,
                    work_item_id,
                    attempt_id,
                    None,
                )
                .await?,
            );
        }

        transaction
            .commit()
            .await
            .map_err(|error| persistence_error("commit reservation expiry sweep", error))?;
        Ok(receipts)
    }
}

async fn reject_existing_attempt_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
) -> Result<()> {
    let existing = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM reservation_sets
        WHERE tenant_id = $1
          AND attempt_id = $2
          AND state = 'ACTIVE'
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("inspect active attempt reservation", error))?;
    if let Some(reservation_set_id) = existing {
        Err(Error::Conflict(format!(
            "attempt {} already has active reservation set {reservation_set_id}; adopt its idempotency key or transition it first",
            request.attempt_id
        )))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct AdmissionContext {
    repository_generation: u64,
    repository_capacity: u64,
    worker_generation: u64,
    worker_capacity: u64,
    attempt_generation: u64,
    budget_limits: BudgetLimits,
    identity_capacities: BTreeMap<CtxlaneProfileRef, (u64, u64)>,
}

#[derive(Debug)]
struct ExistingSet {
    id: Uuid,
    worker_session_id: Option<Uuid>,
    worker_generation: Option<i64>,
    request_digest: String,
    state: String,
    fence_token: i64,
    acquired_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn load_and_validate_context(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    identities: &[IdentityCapacityRequest],
) -> Result<AdmissionContext> {
    let tenant_status =
        sqlx::query_scalar::<_, String>("SELECT status FROM tenants WHERE id = $1 FOR SHARE")
            .bind(request.tenant_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| persistence_error("lock admission tenant", error))?
            .ok_or_else(|| Error::NotFound(format!("tenant {}", request.tenant_id)))?;
    if tenant_status != "ACTIVE" {
        return Err(Error::Conflict(format!(
            "tenant {} is {tenant_status}; new admission is disabled",
            request.tenant_id
        )));
    }

    let work_item = sqlx::query(
        r"
        SELECT repository_id, budget_limits, identity_requirements,
               current_attempt_id, accepted_at
        FROM work_items
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock admission work item", error))?
    .ok_or_else(|| Error::NotFound(format!("work item {}", request.work_item_id)))?;
    let repository_id: Option<Uuid> = decode(&work_item, "repository_id", "work repository")?;
    let current_attempt_id: Option<Uuid> =
        decode(&work_item, "current_attempt_id", "current attempt")?;
    let accepted_at: Option<DateTime<Utc>> = decode(&work_item, "accepted_at", "acceptance")?;
    if accepted_at.is_none()
        || repository_id != Some(request.repository_id)
        || current_attempt_id != Some(request.attempt_id)
    {
        return Err(Error::Conflict(
            "admission is not bound to the accepted work item's current attempt and repository"
                .into(),
        ));
    }
    let budget_value: Value = decode(&work_item, "budget_limits", "work budget limits")?;
    let budget_limits: BudgetLimits = serde_json::from_value(budget_value)
        .map_err(|error| Error::Persistence(format!("decode persisted budget limits: {error}")))?;
    budget_limits.validate()?;
    let identity_value: Value = decode(
        &work_item,
        "identity_requirements",
        "work identity requirements",
    )?;
    let required_identities: WorkOrderIdentities =
        serde_json::from_value(identity_value).map_err(|error| {
            Error::Persistence(format!("decode persisted identity requirements: {error}"))
        })?;
    required_identities.validate()?;
    validate_requested_identities(identities, &required_identities)?;

    let attempt = sqlx::query(
        r"
        SELECT state, aggregate_version
        FROM attempts
        WHERE tenant_id = $1 AND id = $2 AND work_item_id = $3
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.attempt_id)
    .bind(request.work_item_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock admission attempt", error))?
    .ok_or_else(|| Error::NotFound(format!("attempt {}", request.attempt_id)))?;
    let attempt_state: String = decode(&attempt, "state", "attempt state")?;
    if !matches!(attempt_state.as_str(), "CREATED" | "AUTHORIZED") {
        return Err(Error::Conflict(format!(
            "attempt {} is {attempt_state}, not admissible",
            request.attempt_id
        )));
    }
    let attempt_generation = positive_u64(decode::<i64>(
        &attempt,
        "aggregate_version",
        "attempt generation",
    )?)?;

    let repository = sqlx::query(
        r"
        SELECT active, wip_limit, aggregate_version
        FROM repositories
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.repository_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock admission repository", error))?
    .ok_or_else(|| Error::NotFound(format!("repository {}", request.repository_id)))?;
    let repository_active: bool = decode(&repository, "active", "repository active flag")?;
    let repository_capacity = positive_u64(i64::from(decode::<i32>(
        &repository,
        "wip_limit",
        "repository WIP limit",
    )?))?;
    let repository_generation = positive_u64(decode::<i64>(
        &repository,
        "aggregate_version",
        "repository generation",
    )?)?;
    if !repository_active || repository_generation != request.expected_repository_generation {
        return Err(Error::Conflict(
            "repository is disabled or its generation changed before admission".into(),
        ));
    }

    let worker = sqlx::query(
        r"
        SELECT status, max_concurrency, generation
        FROM workers
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.worker_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock admission worker", error))?
    .ok_or_else(|| Error::NotFound(format!("worker {}", request.worker_id)))?;
    let worker_status: String = decode(&worker, "status", "worker status")?;
    let worker_capacity = positive_u64(i64::from(decode::<i32>(
        &worker,
        "max_concurrency",
        "worker concurrency",
    )?))?;
    let worker_generation =
        positive_u64(decode::<i64>(&worker, "generation", "worker generation")?)?;
    if worker_status != "READY" || worker_generation != request.expected_worker_generation {
        return Err(Error::Conflict(
            "worker is not ready or its generation changed before admission".into(),
        ));
    }

    let worker_session = sqlx::query(
        r"
        SELECT worker_id, worker_generation, status, expires_at
        FROM worker_sessions
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.worker_session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock admission worker session", error))?
    .ok_or_else(|| Error::NotFound(format!("worker session {}", request.worker_session_id)))?;
    let session_worker_id: Uuid = decode(&worker_session, "worker_id", "session worker")?;
    let session_generation = positive_u64(decode::<i64>(
        &worker_session,
        "worker_generation",
        "session worker generation",
    )?)?;
    let session_status: String = decode(&worker_session, "status", "worker session status")?;
    let session_expires_at: DateTime<Utc> =
        decode(&worker_session, "expires_at", "worker session expiry")?;
    let now = database_now(transaction).await?;
    if session_worker_id != request.worker_id
        || session_generation != request.expected_worker_generation
        || session_status != "ACTIVE"
        || session_expires_at <= now
        || request.expires_at > session_expires_at
    {
        return Err(Error::Conflict(
            "worker session is not active, is expired, is shorter than the reservation, or does not exactly bind the requested worker generation"
                .into(),
        ));
    }

    let mut identity_capacities = BTreeMap::new();
    for identity in identities {
        let capacity = sqlx::query(
            r"
            SELECT capacity, generation, enabled
            FROM identity_capacity_limits
            WHERE tenant_id = $1 AND profile_ref = $2
            FOR UPDATE
            ",
        )
        .bind(request.tenant_id)
        .bind(identity.profile_ref.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock identity capacity", error))?
        .ok_or_else(|| {
            Error::NotFound(format!("identity capacity for {}", identity.profile_ref))
        })?;
        let configured_capacity =
            positive_u64(decode::<i64>(&capacity, "capacity", "identity capacity")?)?;
        let generation = positive_u64(decode::<i64>(
            &capacity,
            "generation",
            "identity capacity generation",
        )?)?;
        let enabled: bool = decode(&capacity, "enabled", "identity capacity enabled flag")?;
        if !enabled || generation != identity.expected_generation {
            return Err(Error::Conflict(format!(
                "identity capacity for {} is disabled or changed generation",
                identity.profile_ref
            )));
        }
        identity_capacities.insert(
            identity.profile_ref.clone(),
            (configured_capacity, generation),
        );
    }

    Ok(AdmissionContext {
        repository_generation,
        repository_capacity,
        worker_generation,
        worker_capacity,
        attempt_generation,
        budget_limits,
        identity_capacities,
    })
}

fn validate_requested_identities(
    requested: &[IdentityCapacityRequest],
    required: &WorkOrderIdentities,
) -> Result<()> {
    let mut expected = BTreeMap::<CtxlaneProfileRef, u32>::new();
    for profile in [
        &required.implementer,
        &required.local_reviewer,
        &required.pr_reviewer,
    ] {
        let units = expected.entry(profile.clone()).or_default();
        *units = units
            .checked_add(1)
            .ok_or_else(|| Error::Validation("identity role count overflowed".into()))?;
    }
    let actual: BTreeMap<_, _> = requested
        .iter()
        .map(|identity| (identity.profile_ref.clone(), identity.units))
        .collect();
    if actual != expected {
        return Err(Error::Conflict(
            "identity reservations do not exactly cover the accepted role requirements".into(),
        ));
    }
    Ok(())
}

async fn enforce_capacity(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    identities: &[IdentityCapacityRequest],
    context: &AdmissionContext,
) -> Result<()> {
    require_capacity(
        transaction,
        request.tenant_id,
        "REPOSITORY_WIP",
        &repository_resource_key(request.repository_id),
        1,
        context.repository_capacity,
    )
    .await?;
    require_capacity(
        transaction,
        request.tenant_id,
        "WORKER_SLOT",
        &worker_resource_key(request.worker_id),
        1,
        context.worker_capacity,
    )
    .await?;
    for identity in identities {
        let (capacity, _generation) = context
            .identity_capacities
            .get(&identity.profile_ref)
            .ok_or_else(|| Error::Persistence("locked identity capacity disappeared".into()))?;
        require_capacity(
            transaction,
            request.tenant_id,
            "IDENTITY_CAPACITY",
            &identity_resource_key(&identity.profile_ref),
            u64::from(identity.units),
            *capacity,
        )
        .await?;
    }
    for dimension in ReservationBudgetDimension::ALL {
        let requested = request.budget.amount(dimension);
        let limit = budget_limit(context.budget_limits, dimension);
        let resource_key = budget_resource_key(request.work_item_id, dimension);
        let active =
            active_reserved_units(transaction, request.tenant_id, "BUDGET", &resource_key).await?;
        let consumed = consumed_budget(
            transaction,
            request.tenant_id,
            request.work_item_id,
            dimension,
        )
        .await?;
        let committed = consumed
            .checked_add(active)
            .and_then(|value| value.checked_add(requested))
            .ok_or_else(|| Error::Conflict("budget capacity arithmetic overflowed".into()))?;
        if committed > limit {
            return Err(Error::Conflict(format!(
                "{} budget is exhausted: consumed {consumed}, active reservations {active}, requested {requested}, limit {limit}",
                dimension.database_value()
            )));
        }
    }
    Ok(())
}

async fn require_capacity(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    kind: &str,
    resource_key: &str,
    requested: u64,
    capacity: u64,
) -> Result<()> {
    let active = active_reserved_units(transaction, tenant_id, kind, resource_key).await?;
    if active
        .checked_add(requested)
        .is_none_or(|total| total > capacity)
    {
        return Err(Error::Conflict(format!(
            "{kind} capacity is exhausted for {resource_key}"
        )));
    }
    Ok(())
}

async fn active_reserved_units(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    kind: &str,
    resource_key: &str,
) -> Result<u64> {
    let amount = sqlx::query_scalar::<_, String>(
        r"
        SELECT COALESCE(SUM(reservation.units::numeric), 0)::text
        FROM reservations AS reservation
        JOIN reservation_sets AS reservation_set
          ON reservation_set.tenant_id = reservation.tenant_id
         AND reservation_set.id = reservation.reservation_set_id
        WHERE reservation.tenant_id = $1
          AND reservation.kind = $2
          AND reservation.resource_key = $3
          AND reservation_set.state = 'ACTIVE'
          AND reservation_set.expires_at > clock_timestamp()
        ",
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(resource_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("sum active reservation capacity", error))?;
    parse_u64(&amount, "active reservation capacity")
}

async fn consumed_budget(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    dimension: ReservationBudgetDimension,
) -> Result<u64> {
    let amount = sqlx::query_scalar::<_, String>(
        r"
        SELECT COALESCE(SUM(amount::numeric), 0)::text
        FROM budget_ledger
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND dimension = $3
          AND entry_type IN ('CONSUME', 'ADJUST')
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(dimension.database_value())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("sum consumed work-item budget", error))?;
    parse_u64(&amount, "consumed budget")
}

async fn insert_reservation_set(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    request_digest: &str,
) -> Result<DateTime<Utc>> {
    sqlx::query_scalar(
        r"
        INSERT INTO reservation_sets (
            id, tenant_id, work_item_id, attempt_id, repository_id, worker_id,
            worker_session_id, worker_generation, request_digest,
            idempotency_key, acquired_by, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING acquired_at
        ",
    )
    .bind(request.reservation_set_id)
    .bind(request.tenant_id)
    .bind(request.work_item_id)
    .bind(request.attempt_id)
    .bind(request.repository_id)
    .bind(request.worker_id)
    .bind(request.worker_session_id)
    .bind(
        i64::try_from(request.expected_worker_generation).map_err(|_| {
            Error::Validation("worker generation exceeds PostgreSQL bigint capacity".into())
        })?,
    )
    .bind(request_digest)
    .bind(&request.idempotency_key)
    .bind(&request.actor_id)
    .bind(request.expires_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert reservation set", error))
}

async fn insert_resources_and_budget_ledger(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    identities: &[IdentityCapacityRequest],
    context: &AdmissionContext,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    insert_resource(
        transaction,
        request,
        ReservationKind::RepositoryWip,
        &repository_resource_key(request.repository_id),
        None,
        1,
        context.repository_generation,
    )
    .await?;
    insert_resource(
        transaction,
        request,
        ReservationKind::WorkerSlot,
        &worker_resource_key(request.worker_id),
        None,
        1,
        context.worker_generation,
    )
    .await?;
    for identity in identities {
        let (_capacity, generation) = context
            .identity_capacities
            .get(&identity.profile_ref)
            .ok_or_else(|| Error::Persistence("locked identity capacity disappeared".into()))?;
        insert_resource(
            transaction,
            request,
            ReservationKind::IdentityCapacity,
            &identity_resource_key(&identity.profile_ref),
            None,
            u64::from(identity.units),
            *generation,
        )
        .await?;
    }
    for dimension in ReservationBudgetDimension::ALL {
        let units = request.budget.amount(dimension);
        let reservation_id = insert_resource(
            transaction,
            request,
            ReservationKind::Budget,
            &budget_resource_key(request.work_item_id, dimension),
            Some(dimension),
            units,
            context.attempt_generation,
        )
        .await?;
        insert_budget_entry(
            transaction,
            request.tenant_id,
            request.work_item_id,
            request.attempt_id,
            reservation_id,
            dimension,
            "RESERVE",
            units,
            &format!(
                "{}:budget-reserve:{}",
                request.idempotency_key,
                dimension.database_value()
            ),
            json_metadata(&request.idempotency_key),
            occurred_at,
        )
        .await?;
    }
    Ok(())
}

async fn insert_resource(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    kind: ReservationKind,
    resource_key: &str,
    budget_dimension: Option<ReservationBudgetDimension>,
    units: u64,
    resource_generation: u64,
) -> Result<Uuid> {
    let id = Uuid::now_v7();
    let units = i64::try_from(units)
        .map_err(|_| Error::Validation("reservation units exceed PostgreSQL bigint".into()))?;
    let resource_generation = i64::try_from(resource_generation)
        .map_err(|_| Error::Validation("resource generation exceeds PostgreSQL bigint".into()))?;
    sqlx::query(
        r"
        INSERT INTO reservations (
            id, tenant_id, reservation_set_id, kind, resource_key,
            budget_dimension, units, idempotency_key, resource_generation
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(id)
    .bind(request.tenant_id)
    .bind(request.reservation_set_id)
    .bind(reservation_kind_value(kind))
    .bind(resource_key)
    .bind(budget_dimension.map(ReservationBudgetDimension::database_value))
    .bind(units)
    .bind(format!(
        "{}:{}:{resource_key}",
        request.idempotency_key,
        reservation_kind_value(kind)
    ))
    .bind(resource_generation)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert capacity reservation", error))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
async fn insert_budget_entry(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    reservation_id: Uuid,
    dimension: ReservationBudgetDimension,
    entry_type: &str,
    amount: u64,
    idempotency_key: &str,
    metadata: Value,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    let amount = i64::try_from(amount)
        .map_err(|_| Error::Validation("budget amount exceeds PostgreSQL bigint".into()))?;
    sqlx::query(
        r"
        INSERT INTO budget_ledger (
            id, tenant_id, work_item_id, attempt_id, reservation_id,
            scope_type, scope_id, dimension, entry_type, amount, unit,
            idempotency_key, metadata, occurred_at
        ) VALUES ($1, $2, $3, $4, $5, 'ATTEMPT', $6, $7, $8, $9, $10, $11, $12, $13)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(attempt_id)
    .bind(reservation_id)
    .bind(attempt_id.to_string())
    .bind(dimension.database_value())
    .bind(entry_type)
    .bind(amount)
    .bind(dimension.unit())
    .bind(idempotency_key)
    .bind(metadata)
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert reservation budget entry", error))?;
    Ok(())
}

async fn adopt_existing_set(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdmissionReservationRequest,
    request_digest: &str,
    existing: &ExistingSet,
) -> Result<AdmissionReservationReceipt> {
    let expected_generation = i64::try_from(request.expected_worker_generation).map_err(|_| {
        Error::Validation("worker generation exceeds PostgreSQL bigint capacity".into())
    })?;
    if existing.worker_session_id != Some(request.worker_session_id)
        || existing.worker_generation != Some(expected_generation)
        || existing.request_digest != request_digest
    {
        return Err(Error::Conflict(format!(
            "reservation idempotency key {} was reused with different admission semantics",
            request.idempotency_key
        )));
    }
    let now = database_now(transaction).await?;
    if existing.state != "ACTIVE" || existing.expires_at <= now {
        return Err(Error::Conflict(format!(
            "reservation idempotency key {} names a reservation that is no longer active",
            request.idempotency_key
        )));
    }
    let authority = sqlx::query(
        r"
        SELECT session.status AS session_status,
               session.expires_at AS session_expires_at,
               worker.status AS worker_status,
               worker.generation AS worker_generation
        FROM worker_sessions AS session
        JOIN workers AS worker
          ON worker.tenant_id = session.tenant_id
         AND worker.id = session.worker_id
        WHERE session.tenant_id = $1
          AND session.id = $2
          AND session.worker_id = $3
          AND session.worker_generation = $4
        FOR UPDATE OF session, worker
        ",
    )
    .bind(request.tenant_id)
    .bind(request.worker_session_id)
    .bind(request.worker_id)
    .bind(expected_generation)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("revalidate adopted reservation authority", error))?
    .ok_or_else(|| {
        Error::Conflict(
            "adopted reservation no longer has its exact worker-session authority".into(),
        )
    })?;
    let session_status: String = decode(&authority, "session_status", "session status")?;
    let session_expires_at: DateTime<Utc> =
        decode(&authority, "session_expires_at", "session expiry")?;
    let worker_status: String = decode(&authority, "worker_status", "worker status")?;
    let worker_generation: i64 = decode(&authority, "worker_generation", "worker generation")?;
    if session_status != "ACTIVE"
        || session_expires_at <= now
        || existing.expires_at > session_expires_at
        || worker_status == "QUARANTINED"
        || worker_generation != expected_generation
    {
        return Err(Error::Conflict(
            "adopted reservation's worker-session authority is no longer live".into(),
        ));
    }
    let acquisition_event_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM reservation_set_events
        WHERE tenant_id = $1
          AND reservation_set_id = $2
          AND event_type = 'ACQUIRED'
          AND idempotency_key = $3
        ",
    )
    .bind(request.tenant_id)
    .bind(existing.id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load reservation acquisition event", error))?
    .ok_or_else(|| Error::Persistence("active reservation has no acquisition event".into()))?;
    Ok(AdmissionReservationReceipt {
        reservation_set_id: existing.id,
        disposition: AdmissionDisposition::Adopted,
        request_digest: existing.request_digest.clone(),
        fence_token: positive_u64(existing.fence_token)?,
        acquired_at: existing.acquired_at,
        expires_at: existing.expires_at,
        acquisition_event_id,
        resources: load_resources(transaction, request.tenant_id, existing.id).await?,
    })
}

async fn load_set_by_idempotency_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    idempotency_key: &str,
) -> Result<Option<ExistingSet>> {
    sqlx::query(
        r"
        SELECT id, worker_session_id, worker_generation, request_digest,
               state, fence_token, acquired_at, expires_at
        FROM reservation_sets
        WHERE tenant_id = $1 AND idempotency_key = $2
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load idempotent reservation set", error))?
    .map(|row| existing_set_from_row(&row))
    .transpose()
}

fn existing_set_from_row(row: &PgRow) -> Result<ExistingSet> {
    Ok(ExistingSet {
        id: decode(row, "id", "reservation set ID")?,
        worker_session_id: decode(row, "worker_session_id", "reservation worker session")?,
        worker_generation: decode(row, "worker_generation", "reservation worker generation")?,
        request_digest: decode(row, "request_digest", "reservation request digest")?,
        state: decode(row, "state", "reservation state")?,
        fence_token: decode(row, "fence_token", "reservation fence")?,
        acquired_at: decode(row, "acquired_at", "reservation acquisition time")?,
        expires_at: decode(row, "expires_at", "reservation expiry")?,
    })
}

async fn load_resources(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    reservation_set_id: Uuid,
) -> Result<Vec<ReservedResource>> {
    let rows = sqlx::query(
        r"
        SELECT id, kind, resource_key, budget_dimension, units, resource_generation
        FROM reservations
        WHERE tenant_id = $1 AND reservation_set_id = $2
        ORDER BY kind, resource_key
        ",
    )
    .bind(tenant_id)
    .bind(reservation_set_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load reservation resources", error))?;
    rows.iter().map(resource_from_row).collect()
}

fn resource_from_row(row: &PgRow) -> Result<ReservedResource> {
    let kind: String = decode(row, "kind", "reservation kind")?;
    let budget_dimension: Option<String> =
        decode(row, "budget_dimension", "reservation budget dimension")?;
    Ok(ReservedResource {
        id: decode(row, "id", "reservation ID")?,
        kind: parse_reservation_kind(&kind)?,
        resource_key: decode(row, "resource_key", "reservation resource key")?,
        budget_dimension: budget_dimension
            .as_deref()
            .map(parse_budget_dimension)
            .transpose()?,
        units: nonnegative_u64(decode::<i64>(row, "units", "reservation units")?)?,
        resource_generation: positive_u64(decode::<i64>(
            row,
            "resource_generation",
            "reservation resource generation",
        )?)?,
    })
}

async fn transition_reservation_set(
    ledger: &PgLedger,
    request: &ReservationTransitionRequest,
    target: ReservationTerminalState,
) -> Result<ReservationTransitionReceipt> {
    request.validate()?;
    let expected_fence = i64::try_from(request.expected_fence_token)
        .map_err(|_| Error::Validation("reservation transition fence is too large".into()))?;
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .map_err(|error| persistence_error("begin reservation transition", error))?;
    let lock_work_item_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT work_item_id
        FROM reservation_sets
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(request.tenant_id)
    .bind(request.reservation_set_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| persistence_error("locate reservation transition", error))?
    .ok_or_else(|| Error::NotFound(format!("reservation set {}", request.reservation_set_id)))?;
    advisory_lock(
        &mut transaction,
        &format!("admission:{}:budget:{lock_work_item_id}", request.tenant_id),
    )
    .await?;
    advisory_lock(
        &mut transaction,
        &format!(
            "reservation-set:{}:{}",
            request.tenant_id, request.reservation_set_id
        ),
    )
    .await?;
    let row = sqlx::query(
        r"
        SELECT state, fence_token, expires_at, work_item_id, attempt_id
        FROM reservation_sets
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant_id)
    .bind(request.reservation_set_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| persistence_error("lock reservation transition", error))?
    .ok_or_else(|| Error::NotFound(format!("reservation set {}", request.reservation_set_id)))?;
    let state: String = decode(&row, "state", "reservation state")?;
    let current_fence: i64 = decode(&row, "fence_token", "reservation fence")?;
    let expires_at: DateTime<Utc> = decode(&row, "expires_at", "reservation expiry")?;
    let work_item_id: Uuid = decode(&row, "work_item_id", "reservation work item")?;
    let attempt_id: Uuid = decode(&row, "attempt_id", "reservation attempt")?;
    let target_value = terminal_state_value(target);

    if state != "ACTIVE" {
        if state != target_value || current_fence != expected_fence.saturating_add(1) {
            return Err(Error::Conflict(format!(
                "reservation set {} is already {state} at fence {current_fence}",
                request.reservation_set_id
            )));
        }
        let receipt = load_transition_receipt(&mut transaction, request, target).await?;
        transaction
            .commit()
            .await
            .map_err(|error| persistence_error("commit adopted reservation transition", error))?;
        return Ok(receipt);
    }
    if current_fence != expected_fence {
        return Err(Error::Conflict(format!(
            "reservation set {} fence is {current_fence}, expected {expected_fence}",
            request.reservation_set_id
        )));
    }
    if target == ReservationTerminalState::Expired
        && expires_at > database_now(&mut transaction).await?
    {
        return Err(Error::Conflict(format!(
            "reservation set {} has not expired",
            request.reservation_set_id
        )));
    }
    let receipt = apply_active_reservation_transition(
        &mut transaction,
        request,
        target,
        current_fence,
        work_item_id,
        attempt_id,
        None,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| persistence_error("commit reservation transition", error))?;
    Ok(receipt)
}

async fn apply_active_reservation_transition(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReservationTransitionRequest,
    target: ReservationTerminalState,
    current_fence: i64,
    work_item_id: Uuid,
    attempt_id: Uuid,
    cancellation_terminal_receipt_id: Option<Uuid>,
) -> Result<ReservationTransitionReceipt> {
    let next_fence = current_fence
        .checked_add(1)
        .ok_or_else(|| Error::Conflict("reservation fence overflowed".into()))?;
    let expected_fence = i64::try_from(request.expected_fence_token)
        .map_err(|_| Error::Validation("reservation transition fence is too large".into()))?;
    let target_value = terminal_state_value(target);
    let occurred_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        r"
        UPDATE reservation_sets
        SET state = $3,
            fence_token = $4,
            released_at = clock_timestamp(),
            released_by = $5,
            release_reason = $6,
            transition_idempotency_key = $7,
            cancellation_terminal_receipt_id = $8
        WHERE tenant_id = $1
          AND id = $2
          AND state = 'ACTIVE'
          AND fence_token = $9
        RETURNING released_at
        ",
    )
    .bind(request.tenant_id)
    .bind(request.reservation_set_id)
    .bind(target_value)
    .bind(next_fence)
    .bind(&request.actor_id)
    .bind(&request.reason)
    .bind(&request.idempotency_key)
    .bind(cancellation_terminal_receipt_id)
    .bind(expected_fence)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("transition reservation set", error))?
    .ok_or_else(|| Error::Conflict("reservation transition lost its fence".into()))?;

    let budget_rows = sqlx::query(
        r"
        SELECT id, budget_dimension, units
        FROM reservations
        WHERE tenant_id = $1
          AND reservation_set_id = $2
          AND kind = 'BUDGET'
        ORDER BY budget_dimension
        ",
    )
    .bind(request.tenant_id)
    .bind(request.reservation_set_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load released budget reservations", error))?;
    for budget_row in budget_rows {
        let reservation_id: Uuid = decode(&budget_row, "id", "budget reservation ID")?;
        let dimension_value: String = decode(&budget_row, "budget_dimension", "budget dimension")?;
        let dimension = parse_budget_dimension(&dimension_value)?;
        let units = nonnegative_u64(decode::<i64>(
            &budget_row,
            "units",
            "budget reservation units",
        )?)?;
        insert_budget_entry(
            transaction,
            request.tenant_id,
            work_item_id,
            attempt_id,
            reservation_id,
            dimension,
            "RELEASE",
            units,
            &format!(
                "{}:budget-release:{}",
                request.idempotency_key,
                dimension.database_value()
            ),
            json_metadata(&request.idempotency_key),
            occurred_at,
        )
        .await?;
    }
    let event_id = insert_set_event(
        transaction,
        request.tenant_id,
        request.reservation_set_id,
        target_value,
        current_fence,
        next_fence,
        &request.actor_id,
        &request.reason,
        &request.idempotency_key,
        occurred_at,
    )
    .await?;
    Ok(ReservationTransitionReceipt {
        reservation_set_id: request.reservation_set_id,
        state: target,
        disposition: ReservationTransitionDisposition::Applied,
        previous_fence_token: request.expected_fence_token,
        fence_token: positive_u64(next_fence)?,
        actor_id: request.actor_id.clone(),
        reason: request.reason.clone(),
        idempotency_key: request.idempotency_key.clone(),
        event_id,
        occurred_at,
    })
}

/// Release every active reservation whose authority belongs to one worker.
///
/// The caller must already hold the worker-authority advisory lock.  Keeping
/// this operation on the caller's transaction makes worker quarantine,
/// capacity release, budget accounting, session revocation, and job fencing a
/// single durable state change.
pub(crate) async fn release_active_worker_reservations(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    worker_id: Uuid,
    actor_id: &str,
    reason: &str,
) -> Result<usize> {
    let candidates = sqlx::query(
        r"
        SELECT id, work_item_id
        FROM reservation_sets
        WHERE tenant_id = $1
          AND worker_id = $2
          AND state = 'ACTIVE'
        ORDER BY work_item_id, id
        ",
    )
    .bind(tenant_id)
    .bind(worker_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("locate worker reservations for revocation", error))?;

    let mut work_items = BTreeSet::new();
    for candidate in &candidates {
        work_items.insert(decode::<Uuid>(
            candidate,
            "work_item_id",
            "worker reservation work item",
        )?);
    }
    for work_item_id in work_items {
        advisory_lock(
            transaction,
            &format!("admission:{tenant_id}:budget:{work_item_id}"),
        )
        .await?;
    }

    let rows = sqlx::query(
        r"
        SELECT id, worker_session_id, fence_token, work_item_id, attempt_id
        FROM reservation_sets
        WHERE tenant_id = $1
          AND worker_id = $2
          AND state = 'ACTIVE'
        ORDER BY work_item_id, id
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(worker_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock worker reservations for revocation", error))?;

    let mut released = 0usize;
    for row in rows {
        let reservation_set_id: Uuid = decode(&row, "id", "worker reservation set ID")?;
        let worker_session_id: Option<Uuid> =
            decode(&row, "worker_session_id", "worker reservation session")?;
        let current_fence: i64 = decode(&row, "fence_token", "worker reservation fence")?;
        let work_item_id: Uuid = decode(&row, "work_item_id", "worker reservation work item")?;
        let attempt_id: Uuid = decode(&row, "attempt_id", "worker reservation attempt")?;
        let session_component = worker_session_id
            .map_or_else(|| "legacy".to_owned(), |session_id| session_id.to_string());
        let request = ReservationTransitionRequest {
            tenant_id,
            reservation_set_id,
            expected_fence_token: positive_u64(current_fence)?,
            actor_id: actor_id.to_owned(),
            reason: reason.to_owned(),
            idempotency_key: format!(
                "worker-session-revocation:v1:{session_component}:{reservation_set_id}:fence:{current_fence}"
            ),
        };
        apply_active_reservation_transition(
            transaction,
            &request,
            ReservationTerminalState::Released,
            current_fence,
            work_item_id,
            attempt_id,
            None,
        )
        .await?;
        released = released
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("released reservation count overflowed".into()))?;
    }
    Ok(released)
}

/// Release every active reservation set for one exact terminal attempt.
///
/// Terminal workflows call this on their existing aggregate transaction so
/// WIP, worker, identity, and budget capacity become available in the same
/// commit that makes the work terminal. Budget RELEASE entries and the
/// reservation transition event are produced by the normal fenced transition
/// path.
///
/// The caller must acquire `lock_attempt_reservation_release_authority` before
/// taking aggregate row locks. This function reacquires those transaction-level
/// advisory locks defensively, then rejects any active set that is not owned by
/// the exact authoritative worker rather than releasing capacity under the
/// wrong worker authority.
pub(crate) async fn release_active_attempt_reservations(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    expected_worker_id: Uuid,
    namespace: AttemptReservationReleaseNamespace,
    actor_id: &str,
    reason: &str,
) -> Result<usize> {
    if expected_worker_id.is_nil() {
        return Err(Error::Validation(
            "terminal attempt reservation worker ID must be non-nil".into(),
        ));
    }
    lock_attempt_reservation_release_authority(
        transaction,
        tenant_id,
        work_item_id,
        expected_worker_id,
    )
    .await?;
    let rows = sqlx::query(
        r"
        SELECT id, worker_id, fence_token
        FROM reservation_sets
        WHERE tenant_id = $1
          AND work_item_id = $2
          AND attempt_id = $3
          AND state = 'ACTIVE'
        ORDER BY id
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(attempt_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| persistence_error("lock terminal attempt reservations", error))?;

    for row in &rows {
        let reservation_set_id: Uuid = decode(row, "id", "attempt reservation set ID")?;
        let reservation_worker_id: Uuid =
            decode(row, "worker_id", "attempt reservation worker ID")?;
        if reservation_worker_id != expected_worker_id {
            return Err(Error::Conflict(format!(
                "terminal attempt reservation {reservation_set_id} belongs to worker {reservation_worker_id}, not authoritative worker {expected_worker_id}"
            )));
        }
    }

    let mut released = 0usize;
    for row in rows {
        let reservation_set_id: Uuid = decode(&row, "id", "attempt reservation set ID")?;
        let current_fence: i64 = decode(&row, "fence_token", "attempt reservation fence")?;
        let request = ReservationTransitionRequest {
            tenant_id,
            reservation_set_id,
            expected_fence_token: positive_u64(current_fence)?,
            actor_id: actor_id.to_owned(),
            reason: reason.to_owned(),
            idempotency_key: namespace.idempotency_key(
                work_item_id,
                attempt_id,
                reservation_set_id,
                current_fence,
            ),
        };
        apply_active_reservation_transition(
            transaction,
            &request,
            ReservationTerminalState::Released,
            current_fence,
            work_item_id,
            attempt_id,
            namespace.cancellation_terminal_receipt_id(),
        )
        .await?;
        released = released
            .checked_add(1)
            .ok_or_else(|| Error::Conflict("released reservation count overflowed".into()))?;
    }
    Ok(released)
}

/// Acquire the same authority locks as admission before a terminal workflow
/// takes aggregate rows and later releases attempt-owned capacity. This keeps
/// terminal source closure and cancellation ordered with concurrent admission
/// and worker quarantine.
pub(crate) async fn lock_attempt_reservation_release_authority(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    work_item_id: Uuid,
    worker_id: Uuid,
) -> Result<()> {
    advisory_lock(
        transaction,
        &format!("worker-authority:{tenant_id}:{worker_id}"),
    )
    .await?;
    advisory_lock(
        transaction,
        &format!("admission:{tenant_id}:budget:{work_item_id}"),
    )
    .await
}

async fn load_transition_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReservationTransitionRequest,
    target: ReservationTerminalState,
) -> Result<ReservationTransitionReceipt> {
    let row = sqlx::query(
        r"
        SELECT id, event_type, previous_fence_token, fence_token,
               actor_id, reason, idempotency_key, occurred_at
        FROM reservation_set_events
        WHERE tenant_id = $1 AND idempotency_key = $2
        ",
    )
    .bind(request.tenant_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load idempotent reservation transition", error))?
    .ok_or_else(|| {
        Error::Conflict(
            "terminal reservation cannot be adopted without the exact transition event".into(),
        )
    })?;
    let event_type: String = decode(&row, "event_type", "reservation event type")?;
    let previous_fence: i64 = decode(&row, "previous_fence_token", "previous fence")?;
    let fence: i64 = decode(&row, "fence_token", "event fence")?;
    let actor_id: String = decode(&row, "actor_id", "reservation event actor")?;
    let reason: String = decode(&row, "reason", "reservation event reason")?;
    let reservation_set_id: Uuid = sqlx::query_scalar(
        r"
        SELECT reservation_set_id
        FROM reservation_set_events
        WHERE tenant_id = $1 AND idempotency_key = $2
        ",
    )
    .bind(request.tenant_id)
    .bind(&request.idempotency_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| persistence_error("load transition reservation set", error))?;
    if reservation_set_id != request.reservation_set_id
        || event_type != terminal_state_value(target)
        || previous_fence != i64::try_from(request.expected_fence_token).unwrap_or(i64::MAX)
        || actor_id != request.actor_id
        || reason != request.reason
    {
        return Err(Error::Conflict(
            "reservation transition idempotency key was reused with different semantics".into(),
        ));
    }
    Ok(ReservationTransitionReceipt {
        reservation_set_id,
        state: target,
        disposition: ReservationTransitionDisposition::Adopted,
        previous_fence_token: positive_u64(previous_fence)?,
        fence_token: positive_u64(fence)?,
        actor_id,
        reason,
        idempotency_key: decode(&row, "idempotency_key", "transition idempotency key")?,
        event_id: decode(&row, "id", "reservation event ID")?,
        occurred_at: decode(&row, "occurred_at", "reservation event time")?,
    })
}

#[allow(clippy::too_many_arguments)]
async fn insert_set_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    reservation_set_id: Uuid,
    event_type: &str,
    previous_fence_token: i64,
    fence_token: i64,
    actor_id: &str,
    reason: &str,
    idempotency_key: &str,
    occurred_at: DateTime<Utc>,
) -> Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO reservation_set_events (
            id, tenant_id, reservation_set_id, event_type,
            previous_fence_token, fence_token, actor_id, reason,
            idempotency_key, occurred_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(reservation_set_id)
    .bind(event_type)
    .bind(previous_fence_token)
    .bind(fence_token)
    .bind(actor_id)
    .bind(reason)
    .bind(idempotency_key)
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| persistence_error("insert reservation set event", error))?;
    Ok(id)
}

fn admission_lock_keys(
    request: &AdmissionReservationRequest,
    identities: &[IdentityCapacityRequest],
) -> Vec<String> {
    let mut keys = vec![
        format!(
            "admission:{}:attempt:{}",
            request.tenant_id, request.attempt_id
        ),
        format!(
            "admission:{}:budget:{}",
            request.tenant_id, request.work_item_id
        ),
        format!(
            "admission:{}:repository:{}",
            request.tenant_id, request.repository_id
        ),
        format!(
            "admission:{}:worker:{}",
            request.tenant_id, request.worker_id
        ),
    ];
    keys.extend(identities.iter().map(|identity| {
        format!(
            "admission:{}:identity:{}",
            request.tenant_id, identity.profile_ref
        )
    }));
    keys.sort();
    keys.dedup();
    keys
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    resource_key: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(resource_key)
        .execute(&mut **transaction)
        .await
        .map_err(|error| persistence_error("lock reservation resource", error))?;
    Ok(())
}

async fn database_now(transaction: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| persistence_error("read reservation database clock", error))
}

fn repository_resource_key(repository_id: Uuid) -> String {
    format!("repository:{repository_id}")
}

fn worker_resource_key(worker_id: Uuid) -> String {
    format!("worker:{worker_id}")
}

fn identity_resource_key(profile_ref: &CtxlaneProfileRef) -> String {
    format!("identity:{profile_ref}")
}

fn budget_resource_key(work_item_id: Uuid, dimension: ReservationBudgetDimension) -> String {
    format!(
        "budget:work-item:{work_item_id}:{}",
        dimension.database_value()
    )
}

const fn budget_limit(limits: BudgetLimits, dimension: ReservationBudgetDimension) -> u64 {
    match dimension {
        ReservationBudgetDimension::CostMicrounits => limits.max_cost_microunits,
        ReservationBudgetDimension::InputTokens => limits.max_input_tokens,
        ReservationBudgetDimension::OutputTokens => limits.max_output_tokens,
        ReservationBudgetDimension::ImplementerInvocations => {
            limits.max_implementer_invocations as u64
        }
        ReservationBudgetDimension::ReviewerInvocations => limits.max_reviewer_invocations as u64,
        ReservationBudgetDimension::FixIterations => limits.max_fix_iterations as u64,
        ReservationBudgetDimension::WallTimeSeconds => limits.max_wall_time_seconds,
        ReservationBudgetDimension::ExternalApiCalls => limits.max_external_api_calls as u64,
    }
}

const fn reservation_kind_value(kind: ReservationKind) -> &'static str {
    match kind {
        ReservationKind::RepositoryWip => "REPOSITORY_WIP",
        ReservationKind::WorkerSlot => "WORKER_SLOT",
        ReservationKind::IdentityCapacity => "IDENTITY_CAPACITY",
        ReservationKind::Budget => "BUDGET",
    }
}

fn parse_reservation_kind(value: &str) -> Result<ReservationKind> {
    match value {
        "REPOSITORY_WIP" => Ok(ReservationKind::RepositoryWip),
        "WORKER_SLOT" => Ok(ReservationKind::WorkerSlot),
        "IDENTITY_CAPACITY" => Ok(ReservationKind::IdentityCapacity),
        "BUDGET" => Ok(ReservationKind::Budget),
        other => Err(Error::Persistence(format!(
            "unknown persisted reservation kind {other}"
        ))),
    }
}

fn parse_budget_dimension(value: &str) -> Result<ReservationBudgetDimension> {
    ReservationBudgetDimension::ALL
        .into_iter()
        .find(|dimension| dimension.database_value() == value)
        .ok_or_else(|| Error::Persistence(format!("unknown persisted budget dimension {value}")))
}

const fn terminal_state_value(state: ReservationTerminalState) -> &'static str {
    match state {
        ReservationTerminalState::Released => "RELEASED",
        ReservationTerminalState::Expired => "EXPIRED",
    }
}

fn json_metadata(admission_idempotency_key: &str) -> Value {
    serde_json::json!({"admission_idempotency_key": admission_idempotency_key})
}

fn decode<T>(row: &PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|error| persistence_error(&format!("decode {context}"), error))
}

fn parse_u64(value: &str, context: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))
}

fn positive_u64(value: i64) -> Result<u64> {
    let value = u64::try_from(value)
        .map_err(|_| Error::Persistence("persisted positive value was negative".into()))?;
    if value == 0 {
        Err(Error::Persistence(
            "persisted positive value was zero".into(),
        ))
    } else {
        Ok(value)
    }
}

fn nonnegative_u64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| Error::Persistence("persisted nonnegative value was negative".into()))
}

fn validate_safe_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_SAFE_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Validation(format!(
            "{label} must be non-empty, bounded, trimmed, and contain no control characters"
        )));
    }
    Ok(())
}

fn validate_external_idempotency_key(label: &str, value: &str) -> Result<()> {
    validate_safe_text(label, value)?;
    if [
        INTERNAL_IDEMPOTENCY_NAMESPACE_PREFIX,
        WORK_CLOSURE_IDEMPOTENCY_PREFIX,
        RUNMILL_CANCELLATION_IDEMPOTENCY_PREFIX,
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
    {
        return Err(Error::Validation(format!(
            "{label} uses the reserved ASF internal namespace"
        )));
    }
    Ok(())
}

fn expiry_sweep_idempotency_key(reservation_set_id: Uuid, current_fence: i64) -> String {
    format!("{EXPIRY_SWEEP_IDEMPOTENCY_PREFIX}{reservation_set_id}:fence:{current_fence}")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use chrono::Duration;

    use super::*;

    fn request() -> AdmissionReservationRequest {
        AdmissionReservationRequest {
            reservation_set_id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            repository_id: Uuid::now_v7(),
            expected_repository_generation: 1,
            worker_id: Uuid::now_v7(),
            worker_session_id: Uuid::now_v7(),
            expected_worker_generation: 1,
            identities: vec![
                IdentityCapacityRequest {
                    profile_ref: CtxlaneProfileRef::from_str("codex:implementer").unwrap(),
                    units: 1,
                    expected_generation: 1,
                },
                IdentityCapacityRequest {
                    profile_ref: CtxlaneProfileRef::from_str("claude:local-reviewer").unwrap(),
                    units: 1,
                    expected_generation: 1,
                },
                IdentityCapacityRequest {
                    profile_ref: CtxlaneProfileRef::from_str("codex:pr-reviewer").unwrap(),
                    units: 1,
                    expected_generation: 1,
                },
            ],
            budget: BudgetReservationAmounts {
                cost_microunits: 100,
                input_tokens: 1_000,
                output_tokens: 500,
                implementer_invocations: 1,
                reviewer_invocations: 2,
                fix_iterations: 1,
                wall_time_seconds: 60,
                external_api_calls: 5,
            },
            expires_at: Utc::now() + Duration::hours(1),
            actor_id: "scheduler:test".into(),
            idempotency_key: "admission:test:1".into(),
        }
    }

    #[test]
    fn admission_digest_normalizes_identity_order_and_excludes_proposed_set_id() {
        let first = request();
        let first_identities = first.validate().unwrap();
        let first_digest = first.request_digest(&first_identities).unwrap();

        let mut equivalent = first.clone();
        equivalent.reservation_set_id = Uuid::now_v7();
        equivalent.identities.reverse();
        let identities = equivalent.validate().unwrap();
        assert_eq!(
            equivalent.request_digest(&identities).unwrap(),
            first_digest
        );

        equivalent.budget.external_api_calls += 1;
        let identities = equivalent.validate().unwrap();
        assert_ne!(
            equivalent.request_digest(&identities).unwrap(),
            first_digest
        );

        let mut different_session = first.clone();
        different_session.worker_session_id = Uuid::now_v7();
        let identities = different_session.validate().unwrap();
        assert_ne!(
            different_session.request_digest(&identities).unwrap(),
            first_digest
        );
    }

    #[test]
    fn admission_validation_rejects_duplicate_profiles_and_unrepresentable_budgets() {
        let mut duplicate = request();
        duplicate.identities[1].profile_ref = duplicate.identities[0].profile_ref.clone();
        assert!(duplicate.validate().is_err());

        let mut too_large = request();
        too_large.budget.cost_microunits = u64::MAX;
        assert!(too_large.validate().is_err());
    }

    #[test]
    fn public_reservation_requests_reject_internal_idempotency_namespace() {
        let reservation_set_id = Uuid::now_v7();
        for internal_key in [
            expiry_sweep_idempotency_key(reservation_set_id, 1),
            format!("{WORK_CLOSURE_IDEMPOTENCY_PREFIX}{reservation_set_id}"),
            format!("{RUNMILL_CANCELLATION_IDEMPOTENCY_PREFIX}{reservation_set_id}"),
        ] {
            let mut admission = request();
            admission.idempotency_key.clone_from(&internal_key);
            assert!(matches!(admission.validate(), Err(Error::Validation(_))));

            let transition = ReservationTransitionRequest {
                tenant_id: admission.tenant_id,
                reservation_set_id,
                expected_fence_token: 1,
                actor_id: "scheduler:test".into(),
                reason: "release".into(),
                idempotency_key: internal_key,
            };
            assert!(matches!(transition.validate(), Err(Error::Validation(_))));
        }
    }

    #[test]
    fn terminal_attempt_release_namespaces_are_closed_and_stable() {
        let work_item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let attempt_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let reservation_set_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();

        assert_eq!(
            AttemptReservationReleaseNamespace::WorkClosure.idempotency_key(
                work_item_id,
                attempt_id,
                reservation_set_id,
                7,
            ),
            concat!(
                "work-closure:v1:00000000-0000-0000-0000-000000000001:",
                "00000000-0000-0000-0000-000000000002:",
                "00000000-0000-0000-0000-000000000003:fence:7"
            ),
        );
        assert_eq!(
            AttemptReservationReleaseNamespace::RunmillCancellation {
                terminal_receipt_id: Uuid::parse_str("00000000-0000-0000-0000-000000000004",)
                    .unwrap(),
            }
            .idempotency_key(work_item_id, attempt_id, reservation_set_id, 7,),
            concat!(
                "runmill-cancellation:v1:00000000-0000-0000-0000-000000000001:",
                "00000000-0000-0000-0000-000000000002:",
                "00000000-0000-0000-0000-000000000003:fence:7"
            ),
        );
    }
}
