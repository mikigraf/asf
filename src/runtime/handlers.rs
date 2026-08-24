use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{Error, Result, domain::WorkerId, ledger::ClaimedWorkflowJob};

/// Durable production job types recognized by the reactor.
pub const INTAKE_SYNC: &str = "INTAKE_SYNC";
pub const ADVANCE_ACCEPTED_WORK_ITEM: &str = "ADVANCE_ACCEPTED_WORK_ITEM";
pub const REQUEST_WORK_ITEM_CANCELLATION: &str = "REQUEST_WORK_ITEM_CANCELLATION";
pub const APPLY_SIGNED_APPROVAL_DECISION: &str = "APPLY_SIGNED_APPROVAL_DECISION";
pub const RECONCILE_WORKER: &str = "RECONCILE_WORKER";
pub const OBSERVE_RUNMILL_RUN: &str = "OBSERVE_RUNMILL_RUN";
pub const RETAIN_RUNMILL_TERMINAL_EVIDENCE: &str = "RETAIN_RUNMILL_TERMINAL_EVIDENCE";
pub const VERIFY_EVIDENCE: &str = "VERIFY_EVIDENCE";
pub const CLOSE_SOURCE: &str = "CLOSE_SOURCE";

const PRODUCTION_JOB_TYPES: [&str; 9] = [
    INTAKE_SYNC,
    ADVANCE_ACCEPTED_WORK_ITEM,
    REQUEST_WORK_ITEM_CANCELLATION,
    APPLY_SIGNED_APPROVAL_DECISION,
    RECONCILE_WORKER,
    OBSERVE_RUNMILL_RUN,
    RETAIN_RUNMILL_TERMINAL_EVIDENCE,
    VERIFY_EVIDENCE,
    CLOSE_SOURCE,
];

/// Canonical activity contract identities for the nine production job
/// types. Every handler registered for a recognized production job type
/// (ready or fail-closed placeholder) must declare exactly its mapped
/// identity; [`HandlerRegistry`] enforces this at registration.
pub const INTAKE_SYNC_ACTIVITY_CONTRACT_ID: &str = "asf.activity/intake-sync/v1";
pub const ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID: &str =
    "asf.activity/advance-accepted-work-item/v1";
pub const REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID: &str =
    "asf.activity/request-work-item-cancellation/v1";
pub const APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID: &str =
    "asf.activity/apply-signed-approval-decision/v1";
pub const RECONCILE_WORKER_ACTIVITY_CONTRACT_ID: &str = "asf.activity/reconcile-worker/v1";
pub const OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID: &str = "asf.activity/observe-runmill-run/v2";
pub const RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID: &str =
    "asf.activity/retain-runmill-terminal-evidence/v1";
pub const VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID: &str = "asf.activity/verify-evidence/v1";
pub const CLOSE_SOURCE_ACTIVITY_CONTRACT_ID: &str = "asf.activity/close-source/v1";

/// The canonical activity contract identity for a recognized production job
/// type, or `None` for any other job type.
#[must_use]
pub fn production_activity_contract_id(job_type: &str) -> Option<&'static str> {
    match job_type {
        INTAKE_SYNC => Some(INTAKE_SYNC_ACTIVITY_CONTRACT_ID),
        ADVANCE_ACCEPTED_WORK_ITEM => Some(ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID),
        REQUEST_WORK_ITEM_CANCELLATION => Some(REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID),
        APPLY_SIGNED_APPROVAL_DECISION => Some(APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID),
        RECONCILE_WORKER => Some(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID),
        OBSERVE_RUNMILL_RUN => Some(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID),
        RETAIN_RUNMILL_TERMINAL_EVIDENCE => {
            Some(RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID)
        }
        VERIFY_EVIDENCE => Some(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID),
        CLOSE_SOURCE => Some(CLOSE_SOURCE_ACTIVITY_CONTRACT_ID),
        _ => None,
    }
}

/// API mutation capabilities derived from the exact activity implementations
/// installed in the same process.
///
/// The fields are intentionally private and there is no public constructor: an
/// embedding must obtain this value from [`HandlerRegistry`] rather than
/// asserting readiness with a free-standing boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiActivityCapabilities {
    ready_claims: ReadyClaimSet,
}

impl ApiActivityCapabilities {
    /// `job_type` and `activity_contract_id` must both match a ready route
    /// exactly; neither dimension is wildcarded against the other.
    pub(crate) fn supports_unscoped(&self, job_type: &str, activity_contract_id: &str) -> bool {
        self.ready_claims
            .unscoped
            .iter()
            .any(|(ready_job_type, ready_contract_id)| {
                ready_job_type == job_type && ready_contract_id == activity_contract_id
            })
    }

    pub(crate) fn supports_reconcile_worker(
        &self,
        worker_id: WorkerId,
        activity_contract_id: &str,
    ) -> bool {
        let worker_id = worker_id.to_string();
        self.ready_claims
            .reconcile_worker
            .iter()
            .any(|(ready_worker_id, ready_contract_id)| {
                *ready_worker_id == worker_id && ready_contract_id == activity_contract_id
            })
    }

    pub(crate) fn supports_cancellation_worker(
        &self,
        worker_id: WorkerId,
        activity_contract_id: &str,
    ) -> bool {
        let worker_id = worker_id.to_string();
        self.ready_claims
            .cancellation_worker
            .iter()
            .any(|(ready_worker_id, ready_contract_id)| {
                *ready_worker_id == worker_id && ready_contract_id == activity_contract_id
            })
    }

    #[cfg(test)]
    pub(crate) fn supports_retain_runmill_terminal_evidence_worker(
        &self,
        worker_id: WorkerId,
        activity_contract_id: &str,
    ) -> bool {
        let worker_id = worker_id.to_string();
        self.ready_claims
            .retain_runmill_terminal_evidence_worker
            .iter()
            .any(|(ready_worker_id, ready_contract_id)| {
                *ready_worker_id == worker_id && ready_contract_id == activity_contract_id
            })
    }

    #[cfg(test)]
    pub(crate) fn supports_observe_runmill_run_worker(
        &self,
        worker_id: WorkerId,
        activity_contract_id: &str,
    ) -> bool {
        let worker_id = worker_id.to_string();
        self.ready_claims.observe_runmill_run_worker.iter().any(
            |(ready_worker_id, ready_contract_id)| {
                *ready_worker_id == worker_id && ready_contract_id == activity_contract_id
            },
        )
    }

    /// `job_type` and `activity_contract_id` are the exact request identity
    /// of a persisted job; `worker_id` is `Some` only for a scoped route.
    pub(crate) fn supports_persisted_job_route(
        &self,
        job_type: &str,
        activity_contract_id: &str,
        worker_id: Option<&str>,
    ) -> bool {
        match job_type {
            RECONCILE_WORKER => worker_id.is_some_and(|worker_id| {
                self.ready_claims.reconcile_worker.iter().any(
                    |(ready_worker_id, ready_contract_id)| {
                        ready_worker_id == worker_id && ready_contract_id == activity_contract_id
                    },
                )
            }),
            REQUEST_WORK_ITEM_CANCELLATION => worker_id.is_some_and(|worker_id| {
                self.ready_claims.cancellation_worker.iter().any(
                    |(ready_worker_id, ready_contract_id)| {
                        ready_worker_id == worker_id && ready_contract_id == activity_contract_id
                    },
                )
            }),
            OBSERVE_RUNMILL_RUN => worker_id.is_some_and(|worker_id| {
                self.ready_claims.observe_runmill_run_worker.iter().any(
                    |(ready_worker_id, ready_contract_id)| {
                        ready_worker_id == worker_id && ready_contract_id == activity_contract_id
                    },
                )
            }),
            RETAIN_RUNMILL_TERMINAL_EVIDENCE => worker_id.is_some_and(|worker_id| {
                self.ready_claims
                    .retain_runmill_terminal_evidence_worker
                    .iter()
                    .any(|(ready_worker_id, ready_contract_id)| {
                        ready_worker_id == worker_id && ready_contract_id == activity_contract_id
                    })
            }),
            _ => worker_id.is_none() && self.supports_unscoped(job_type, activity_contract_id),
        }
    }
}

/// Whether an activity implementation is safe to claim in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerReadiness {
    Ready,
    Unavailable { reason: String },
}

/// The durable queue subset one ready handler is authorized to lease.
///
/// Runmill daemon operations are deliberately different from ordinary
/// tenant-wide activities: one process is connected to one private daemon, so
/// it may lease only jobs whose immutable payload names that exact worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobClaimScope {
    Unscoped,
    ReconcileWorker(WorkerId),
    CancellationWorker(WorkerId),
    ObserveRunmillRunWorker(WorkerId),
    RetainRunmillTerminalEvidenceWorker(WorkerId),
}

impl JobClaimScope {
    pub(crate) fn matches(self, job: &ClaimedWorkflowJob) -> bool {
        match self {
            Self::Unscoped => true,
            Self::ReconcileWorker(worker_id) => {
                job.job_type == RECONCILE_WORKER
                    && job.payload.get("worker_id").and_then(Value::as_str)
                        == Some(worker_id.to_string().as_str())
            }
            Self::CancellationWorker(worker_id) => {
                job.job_type == REQUEST_WORK_ITEM_CANCELLATION
                    && job.payload.get("worker_id").and_then(Value::as_str)
                        == Some(worker_id.to_string().as_str())
            }
            Self::ObserveRunmillRunWorker(worker_id) => {
                job.job_type == OBSERVE_RUNMILL_RUN
                    && job.payload.get("worker_id").and_then(Value::as_str)
                        == Some(worker_id.to_string().as_str())
            }
            Self::RetainRunmillTerminalEvidenceWorker(worker_id) => {
                job.job_type == RETAIN_RUNMILL_TERMINAL_EVIDENCE
                    && job.payload.get("worker_id").and_then(Value::as_str)
                        == Some(worker_id.to_string().as_str())
            }
        }
    }
}

/// Runtime controls passed to every activity invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivityControls {
    maintenance_mode: bool,
}

impl ActivityControls {
    #[must_use]
    pub const fn new(maintenance_mode: bool) -> Self {
        Self { maintenance_mode }
    }

    #[must_use]
    pub const fn maintenance_mode(self) -> bool {
        self.maintenance_mode
    }

    /// Fail closed at the exact point where an activity would create a new
    /// attempt or submit a new Runmill run.
    pub fn require_new_dispatch_permitted(self) -> Result<()> {
        if self.maintenance_mode {
            Err(Error::ExternalUnavailable(
                "new dispatch is disabled by maintenance mode".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// The durable disposition requested by an activity.
#[derive(Debug, Clone, PartialEq)]
pub enum ActivityOutcome {
    /// The reactor performs the owner/fence-checked completion update.
    Complete { result: Option<Value> },
    /// The activity committed its aggregate transition and job completion in
    /// one caller-owned transaction (for example with `commit_workflow_step`).
    TransactionCommitted,
    /// The reactor performs the owner/fence-checked retry update.
    Retry {
        error: String,
        retry_at: DateTime<Utc>,
    },
    /// The activity atomically installed the owned escalation and committed
    /// the terminal job failure (for example with `fail_workflow_step`).
    DeadLetterCommitted,
}

/// One implementation of a durable job type.
#[async_trait]
pub trait JobHandler: Send + Sync + fmt::Debug {
    fn job_type(&self) -> &str;

    /// The exact activity implementation identity this handler serves. A
    /// recognized production job type must declare its canonical mapping
    /// from [`production_activity_contract_id`]; [`HandlerRegistry`]
    /// rejects registration otherwise.
    fn activity_contract_id(&self) -> &str;

    fn readiness(&self) -> HandlerReadiness {
        HandlerReadiness::Ready
    }

    fn claim_scope(&self) -> JobClaimScope {
        JobClaimScope::Unscoped
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        controls: ActivityControls,
    ) -> Result<ActivityOutcome>;
}

/// Exact, fail-closed mapping from durable job type to implementation.
#[derive(Clone, Default)]
pub struct HandlerRegistry {
    handlers: BTreeMap<String, Arc<dyn JobHandler>>,
}

/// Ready queue routes, separated so a scoped activity can never accidentally
/// enter the unscoped `job_type = ANY(...)` branch of the claim query.
///
/// Each vector pairs its route key (job type for an unscoped route, worker ID
/// for a scoped one) with the exact activity contract identity its ready
/// handler declared. These are the only representation kept: the reactor's
/// persisted claim queries bind both halves of each pair together (never the
/// route key alone), so an incompatible contract can never wildcard-match a
/// known route, and there is exactly one array per route kind to keep in
/// sync instead of a route array and a duplicate plain array that could drift
/// apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ReadyClaimSet {
    unscoped: Vec<(String, String)>,
    reconcile_worker: Vec<(String, String)>,
    cancellation_worker: Vec<(String, String)>,
    observe_runmill_run_worker: Vec<(String, String)>,
    retain_runmill_terminal_evidence_worker: Vec<(String, String)>,
}

impl ReadyClaimSet {
    #[must_use]
    pub(super) fn is_empty(&self) -> bool {
        self.unscoped.is_empty()
            && self.reconcile_worker.is_empty()
            && self.cancellation_worker.is_empty()
            && self.observe_runmill_run_worker.is_empty()
            && self.retain_runmill_terminal_evidence_worker.is_empty()
    }

    /// Exact `(job_type, activity_contract_id)` pairs ready for the unscoped
    /// claim branch.
    #[must_use]
    pub(super) fn unscoped(&self) -> &[(String, String)] {
        &self.unscoped
    }

    /// Exact `(worker_id, activity_contract_id)` pairs ready for
    /// `RECONCILE_WORKER`.
    #[must_use]
    pub(super) fn reconcile_worker(&self) -> &[(String, String)] {
        &self.reconcile_worker
    }

    /// Exact `(worker_id, activity_contract_id)` pairs ready for
    /// `REQUEST_WORK_ITEM_CANCELLATION`.
    #[must_use]
    pub(super) fn cancellation_worker(&self) -> &[(String, String)] {
        &self.cancellation_worker
    }

    /// Exact `(worker_id, activity_contract_id)` pairs ready for
    /// `OBSERVE_RUNMILL_RUN`.
    #[must_use]
    pub(super) fn observe_runmill_run_worker(&self) -> &[(String, String)] {
        &self.observe_runmill_run_worker
    }

    /// Exact `(worker_id, activity_contract_id)` pairs ready for
    /// `RETAIN_RUNMILL_TERMINAL_EVIDENCE`.
    #[must_use]
    pub(super) fn retain_runmill_terminal_evidence_worker(&self) -> &[(String, String)] {
        &self.retain_runmill_terminal_evidence_worker
    }

    /// Worker IDs alone, for the observation producer: it mints brand-new
    /// observation jobs with a hardcoded contract identity rather than
    /// matching an existing persisted route, so it never needs the paired
    /// contract half.
    #[must_use]
    pub(super) fn observe_runmill_run_worker_ids(&self) -> Vec<String> {
        self.observe_runmill_run_worker
            .iter()
            .map(|(worker_id, _activity_contract_id)| worker_id.clone())
            .collect()
    }

    /// Worker IDs alone, for the terminal evidence producer, which likewise
    /// mints brand-new retention jobs with a hardcoded contract identity.
    #[must_use]
    pub(super) fn retain_runmill_terminal_evidence_worker_ids(&self) -> Vec<String> {
        self.retain_runmill_terminal_evidence_worker
            .iter()
            .map(|(worker_id, _activity_contract_id)| worker_id.clone())
            .collect()
    }
}

impl fmt::Debug for HandlerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerRegistry")
            .field("job_types", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl HandlerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler. Duplicate job types are rejected so deployment
    /// ordering cannot silently replace an authority-bearing implementation.
    pub fn register(&mut self, handler: Arc<dyn JobHandler>) -> Result<()> {
        let job_type = handler.job_type().trim();
        if job_type.is_empty() {
            return Err(Error::Validation(
                "reactor handler job type must be non-empty".into(),
            ));
        }
        if self.handlers.contains_key(job_type) {
            return Err(Error::Conflict(format!(
                "reactor handler for job type {job_type} is already registered"
            )));
        }
        validate_claim_scope(job_type, handler.as_ref())?;
        validate_activity_contract_id(job_type, handler.as_ref())?;
        self.validate_activity_dependencies(job_type, handler.as_ref())?;
        self.handlers.insert(job_type.into(), handler);
        Ok(())
    }

    /// Replace one recognized fail-closed production placeholder with a ready
    /// implementation.
    ///
    /// The replacement is deliberately narrow: unknown job types, unavailable
    /// replacements, and attempts to replace an already-ready handler are all
    /// rejected. This prevents deployment ordering from silently changing an
    /// authority-bearing implementation.
    pub fn replace_unavailable(&mut self, handler: Arc<dyn JobHandler>) -> Result<()> {
        let job_type = handler.job_type().trim();
        if job_type.is_empty() {
            return Err(Error::Validation(
                "reactor handler job type must be non-empty".into(),
            ));
        }
        if !PRODUCTION_JOB_TYPES.contains(&job_type) {
            return Err(Error::Validation(format!(
                "reactor job type {job_type} is not a recognized production activity"
            )));
        }
        if handler.readiness() != HandlerReadiness::Ready {
            return Err(Error::Validation(format!(
                "replacement reactor handler for {job_type} is not ready"
            )));
        }
        validate_claim_scope(job_type, handler.as_ref())?;
        validate_activity_contract_id(job_type, handler.as_ref())?;
        self.validate_activity_dependencies(job_type, handler.as_ref())?;
        let current = self.handlers.get(job_type).ok_or_else(|| {
            Error::Conflict(format!(
                "reactor handler for production job type {job_type} was not pre-registered"
            ))
        })?;
        if current.readiness() == HandlerReadiness::Ready {
            return Err(Error::Conflict(format!(
                "ready reactor handler for job type {job_type} cannot be replaced"
            )));
        }
        self.handlers.insert(job_type.into(), handler);
        Ok(())
    }

    /// Registry used by the current daemon. The job types are recognized, but
    /// deliberately not claimable until their production dependencies exist.
    pub fn fail_closed_production() -> Result<Self> {
        let mut registry = Self::new();
        for job_type in PRODUCTION_JOB_TYPES {
            let activity_contract_id = production_activity_contract_id(job_type)
                .expect("every production job type has a canonical activity contract id");
            registry.register(Arc::new(UnavailableJobHandler::new(
                job_type,
                activity_contract_id,
                unavailable_reason(job_type),
            )))?;
        }
        Ok(registry)
    }

    #[must_use]
    pub fn handler(&self, job_type: &str) -> Option<Arc<dyn JobHandler>> {
        self.handlers.get(job_type).cloned()
    }

    #[must_use]
    pub fn known_job_types(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    #[must_use]
    pub fn ready_job_types(&self) -> Vec<String> {
        self.handlers
            .iter()
            .filter(|(_job_type, handler)| handler.readiness() == HandlerReadiness::Ready)
            .map(|(job_type, _handler)| job_type.clone())
            .collect()
    }

    /// Mint the API authority corresponding to this registry's exact ready
    /// handlers. Recognized fail-closed placeholders do not grant authority.
    #[must_use]
    pub fn api_activity_capabilities(&self) -> ApiActivityCapabilities {
        ApiActivityCapabilities {
            ready_claims: self.ready_claim_set(),
        }
    }

    #[must_use]
    pub(super) fn ready_claim_set(&self) -> ReadyClaimSet {
        let mut claims = ReadyClaimSet::default();
        for (job_type, handler) in &self.handlers {
            if handler.readiness() != HandlerReadiness::Ready {
                continue;
            }
            let activity_contract_id = handler.activity_contract_id().to_owned();
            match handler.claim_scope() {
                JobClaimScope::Unscoped => {
                    claims
                        .unscoped
                        .push((job_type.clone(), activity_contract_id));
                }
                JobClaimScope::ReconcileWorker(worker_id) => {
                    claims
                        .reconcile_worker
                        .push((worker_id.to_string(), activity_contract_id));
                }
                JobClaimScope::CancellationWorker(worker_id) => {
                    claims
                        .cancellation_worker
                        .push((worker_id.to_string(), activity_contract_id));
                }
                JobClaimScope::ObserveRunmillRunWorker(worker_id) => {
                    claims
                        .observe_runmill_run_worker
                        .push((worker_id.to_string(), activity_contract_id));
                }
                JobClaimScope::RetainRunmillTerminalEvidenceWorker(worker_id) => {
                    claims
                        .retain_runmill_terminal_evidence_worker
                        .push((worker_id.to_string(), activity_contract_id));
                }
            }
        }
        claims
    }

    /// Exact `(job_type, activity_contract_id)` pairs for every registered
    /// handler, ready or fail-closed placeholder alike. The reactor uses this
    /// to fail closed on a due job or timer whose persisted job/timer type is
    /// wholly unrecognized *or* recognized but bound to a different contract
    /// identity than the one implementation this process has installed for
    /// it.
    #[must_use]
    pub(super) fn known_job_type_contract_pairs(&self) -> Vec<(String, String)> {
        self.handlers
            .iter()
            .map(|(job_type, handler)| {
                (job_type.clone(), handler.activity_contract_id().to_owned())
            })
            .collect()
    }

    /// Registered job types that a due timer must never be promoted through
    /// the unscoped timer envelope for, independent of handler readiness.
    ///
    /// A canonical worker-scoped production job type (`RECONCILE_WORKER`,
    /// `REQUEST_WORK_ITEM_CANCELLATION`, `OBSERVE_RUNMILL_RUN`,
    /// `RETAIN_RUNMILL_TERMINAL_EVIDENCE`) is included
    /// whenever it is registered at all — ready or a fail-closed unavailable
    /// placeholder alike — because the unscoped timer envelope can never
    /// establish an exact worker route for it regardless of readiness. Any
    /// other registered handler that declares a scoped [`JobClaimScope`] is
    /// included as well. This grants no claim authority; it only marks a job
    /// type as ineligible for the unscoped timer promotion path.
    #[must_use]
    pub(super) fn scoped_timer_reject_job_types(&self) -> Vec<String> {
        self.handlers
            .iter()
            .filter(|(job_type, handler)| {
                is_canonical_worker_scoped_job_type(job_type)
                    || !matches!(handler.claim_scope(), JobClaimScope::Unscoped)
            })
            .map(|(job_type, _handler)| job_type.clone())
            .collect()
    }

    #[must_use]
    pub fn unavailable_handlers(&self) -> Vec<(String, String)> {
        self.handlers
            .iter()
            .filter_map(|(job_type, handler)| match handler.readiness() {
                HandlerReadiness::Ready => None,
                HandlerReadiness::Unavailable { reason } => Some((job_type.clone(), reason)),
            })
            .collect()
    }

    fn handler_is_ready(&self, job_type: &str) -> bool {
        self.handlers
            .get(job_type)
            .is_some_and(|handler| handler.readiness() == HandlerReadiness::Ready)
    }

    fn validate_activity_dependencies(
        &self,
        job_type: &str,
        handler: &dyn JobHandler,
    ) -> Result<()> {
        if job_type == VERIFY_EVIDENCE
            && handler.readiness() == HandlerReadiness::Ready
            && !self.handler_is_ready(CLOSE_SOURCE)
        {
            return Err(Error::Validation(
                "a ready VERIFY_EVIDENCE handler requires a ready CLOSE_SOURCE handler in the same registry"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Whether `job_type` is one of the three canonical worker-scoped production
/// job types, regardless of whether any handler is currently registered for
/// it.
fn is_canonical_worker_scoped_job_type(job_type: &str) -> bool {
    matches!(
        job_type,
        RECONCILE_WORKER
            | REQUEST_WORK_ITEM_CANCELLATION
            | OBSERVE_RUNMILL_RUN
            | RETAIN_RUNMILL_TERMINAL_EVIDENCE
    )
}

fn validate_claim_scope(job_type: &str, handler: &dyn JobHandler) -> Result<()> {
    match (job_type, handler.readiness(), handler.claim_scope()) {
        (RECONCILE_WORKER, HandlerReadiness::Ready, JobClaimScope::ReconcileWorker(worker_id))
            if !worker_id.as_uuid().is_nil() =>
        {
            Ok(())
        }
        (RECONCILE_WORKER, HandlerReadiness::Ready, _) => Err(Error::Validation(
            "a ready RECONCILE_WORKER handler must declare one non-nil worker claim scope".into(),
        )),
        (
            REQUEST_WORK_ITEM_CANCELLATION,
            HandlerReadiness::Ready,
            JobClaimScope::CancellationWorker(worker_id),
        ) if !worker_id.as_uuid().is_nil() => Ok(()),
        (REQUEST_WORK_ITEM_CANCELLATION, HandlerReadiness::Ready, _) => Err(Error::Validation(
            "a ready REQUEST_WORK_ITEM_CANCELLATION handler must declare one non-nil worker claim scope"
                .into(),
        )),
        (
            OBSERVE_RUNMILL_RUN,
            HandlerReadiness::Ready,
            JobClaimScope::ObserveRunmillRunWorker(worker_id),
        )
        if !worker_id.as_uuid().is_nil() => Ok(()),
        (OBSERVE_RUNMILL_RUN, HandlerReadiness::Ready, _) => Err(Error::Validation(
            "a ready OBSERVE_RUNMILL_RUN handler must declare one non-nil worker claim scope"
                .into(),
        )),
        (
            RETAIN_RUNMILL_TERMINAL_EVIDENCE,
            HandlerReadiness::Ready,
            JobClaimScope::RetainRunmillTerminalEvidenceWorker(worker_id),
        ) if !worker_id.as_uuid().is_nil() => Ok(()),
        (RETAIN_RUNMILL_TERMINAL_EVIDENCE, HandlerReadiness::Ready, _) => Err(Error::Validation(
            "a ready RETAIN_RUNMILL_TERMINAL_EVIDENCE handler must declare one non-nil worker claim scope"
                .into(),
        )),
        (
            _,
            _,
            JobClaimScope::ReconcileWorker(_)
            | JobClaimScope::CancellationWorker(_)
            | JobClaimScope::ObserveRunmillRunWorker(_)
            | JobClaimScope::RetainRunmillTerminalEvidenceWorker(_),
        ) => Err(Error::Validation(format!(
            "worker claim scope is invalid for reactor job type {job_type}"
        ))),
        (_, _, JobClaimScope::Unscoped) => Ok(()),
    }
}

/// Reject a blank, oversized, syntactically invalid, or (for a recognized
/// production job type) non-canonical activity contract identity. This
/// applies to every handler, ready or fail-closed, so a placeholder can
/// never be replaced by an implementation whose declared identity would
/// silently diverge from the immutable identity backfilled by migration
/// 0023.
fn validate_activity_contract_id(job_type: &str, handler: &dyn JobHandler) -> Result<()> {
    let activity_contract_id = handler.activity_contract_id();
    if !is_valid_activity_contract_id(activity_contract_id) {
        return Err(Error::Validation(format!(
            "reactor handler for job type {job_type} declares an invalid activity contract id {activity_contract_id:?}"
        )));
    }
    if let Some(canonical_activity_contract_id) = production_activity_contract_id(job_type)
        && activity_contract_id != canonical_activity_contract_id
    {
        return Err(Error::Validation(format!(
            "reactor handler for production job type {job_type} must declare the canonical activity contract id {canonical_activity_contract_id:?}, found {activity_contract_id:?}"
        )));
    }
    Ok(())
}

/// Strict, fail-closed activity contract id shape: nonblank, at most 128
/// bytes, and a lowercase URI-like `segment([./-]segment)*` pattern. This
/// mirrors the database check constraint installed by migration 0023.
fn is_valid_activity_contract_id(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > 128 {
        return false;
    }
    let mut previous_was_separator = true;
    for byte in candidate.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_separator = false,
            b'.' | b'/' | b'-' => {
                if previous_was_separator {
                    return false;
                }
                previous_was_separator = true;
            }
            _ => return false,
        }
    }
    !previous_was_separator
}

#[derive(Debug)]
struct UnavailableJobHandler {
    job_type: &'static str,
    activity_contract_id: &'static str,
    reason: String,
}

impl UnavailableJobHandler {
    fn new(
        job_type: &'static str,
        activity_contract_id: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            job_type,
            activity_contract_id,
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl JobHandler for UnavailableJobHandler {
    fn job_type(&self) -> &str {
        self.job_type
    }

    fn activity_contract_id(&self) -> &str {
        self.activity_contract_id
    }

    fn readiness(&self) -> HandlerReadiness {
        HandlerReadiness::Unavailable {
            reason: self.reason.clone(),
        }
    }

    async fn execute(
        &self,
        _job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        Err(Error::ExternalUnavailable(self.reason.clone()))
    }
}

fn unavailable_reason(job_type: &str) -> &'static str {
    match job_type {
        INTAKE_SYNC => "production Linear/GitHub intake adapter is not configured",
        ADVANCE_ACCEPTED_WORK_ITEM => {
            "production scheduler, ctxlane, Work Order, and Runmill dispatch activities are not configured"
        }
        REQUEST_WORK_ITEM_CANCELLATION => {
            "production Runmill cancellation activity is not configured"
        }
        APPLY_SIGNED_APPROVAL_DECISION => {
            "production signed approval authority activity is not configured"
        }
        RECONCILE_WORKER => "production Runmill worker reconciliation activity is not configured",
        OBSERVE_RUNMILL_RUN => "production Runmill run-observation activity is not configured",
        RETAIN_RUNMILL_TERMINAL_EVIDENCE => {
            "production Runmill terminal evidence retention activity is not configured"
        }
        VERIFY_EVIDENCE => {
            "production artifact, signer, and forge evidence verification activity is not configured"
        }
        CLOSE_SOURCE => "production evidence-bound source closure activity is not configured",
        _ => "activity is not configured",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ReadyTestHandler(&'static str);

    #[async_trait]
    impl JobHandler for ReadyTestHandler {
        fn job_type(&self) -> &str {
            self.0
        }

        fn activity_contract_id(&self) -> &str {
            production_activity_contract_id(self.0).unwrap_or("test.activity/ready-test-handler/v1")
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete { result: None })
        }
    }

    #[derive(Debug)]
    struct UnreadyTestHandler;

    #[async_trait]
    impl JobHandler for UnreadyTestHandler {
        fn job_type(&self) -> &str {
            INTAKE_SYNC
        }

        fn activity_contract_id(&self) -> &str {
            INTAKE_SYNC_ACTIVITY_CONTRACT_ID
        }

        fn readiness(&self) -> HandlerReadiness {
            HandlerReadiness::Unavailable {
                reason: "fixture unavailable".into(),
            }
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            unreachable!("an unavailable fixture must never execute")
        }
    }

    #[derive(Debug)]
    struct ScopedReconcileTestHandler(WorkerId);

    #[async_trait]
    impl JobHandler for ScopedReconcileTestHandler {
        fn job_type(&self) -> &str {
            RECONCILE_WORKER
        }

        fn activity_contract_id(&self) -> &str {
            RECONCILE_WORKER_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::ReconcileWorker(self.0)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete { result: None })
        }
    }

    #[derive(Debug)]
    struct ScopedCancellationTestHandler(WorkerId);

    #[async_trait]
    impl JobHandler for ScopedCancellationTestHandler {
        fn job_type(&self) -> &str {
            REQUEST_WORK_ITEM_CANCELLATION
        }

        fn activity_contract_id(&self) -> &str {
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::CancellationWorker(self.0)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete { result: None })
        }
    }

    #[derive(Debug)]
    struct ScopedObserveRunmillRunTestHandler(WorkerId);

    #[async_trait]
    impl JobHandler for ScopedObserveRunmillRunTestHandler {
        fn job_type(&self) -> &str {
            OBSERVE_RUNMILL_RUN
        }

        fn activity_contract_id(&self) -> &str {
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::ObserveRunmillRunWorker(self.0)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete { result: None })
        }
    }

    #[derive(Debug)]
    struct ScopedRetainTerminalEvidenceTestHandler(WorkerId);

    #[async_trait]
    impl JobHandler for ScopedRetainTerminalEvidenceTestHandler {
        fn job_type(&self) -> &str {
            RETAIN_RUNMILL_TERMINAL_EVIDENCE
        }

        fn activity_contract_id(&self) -> &str {
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::RetainRunmillTerminalEvidenceWorker(self.0)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            Ok(ActivityOutcome::Complete { result: None })
        }
    }

    #[derive(Debug)]
    struct MisScopedHandler(WorkerId);

    #[async_trait]
    impl JobHandler for MisScopedHandler {
        fn job_type(&self) -> &str {
            INTAKE_SYNC
        }

        fn activity_contract_id(&self) -> &str {
            INTAKE_SYNC_ACTIVITY_CONTRACT_ID
        }

        fn claim_scope(&self) -> JobClaimScope {
            JobClaimScope::ReconcileWorker(self.0)
        }

        async fn execute(
            &self,
            _job: &ClaimedWorkflowJob,
            _controls: ActivityControls,
        ) -> Result<ActivityOutcome> {
            unreachable!("mis-scoped handler must not register")
        }
    }

    #[test]
    fn production_registry_recognizes_but_does_not_claim_placeholders() {
        let registry = HandlerRegistry::fail_closed_production().expect("build registry");
        assert_eq!(registry.known_job_types().len(), PRODUCTION_JOB_TYPES.len());
        assert!(matches!(
            registry
                .handler(OBSERVE_RUNMILL_RUN)
                .expect("load observation placeholder")
                .readiness(),
            HandlerReadiness::Unavailable { .. }
        ));
        assert!(registry.ready_job_types().is_empty());
        assert_eq!(
            registry.unavailable_handlers().len(),
            PRODUCTION_JOB_TYPES.len()
        );
    }

    #[test]
    fn only_a_ready_recognized_handler_can_replace_a_placeholder() {
        let mut registry = HandlerRegistry::fail_closed_production().expect("build registry");
        registry
            .replace_unavailable(Arc::new(ReadyTestHandler(INTAKE_SYNC)))
            .expect("enable intake");

        assert_eq!(registry.ready_job_types(), vec![INTAKE_SYNC.to_owned()]);
        assert_eq!(
            registry.unavailable_handlers().len(),
            PRODUCTION_JOB_TYPES.len() - 1
        );
        assert!(
            registry
                .replace_unavailable(Arc::new(ReadyTestHandler(INTAKE_SYNC)))
                .is_err()
        );
        assert!(
            registry
                .replace_unavailable(Arc::new(ReadyTestHandler("UNKNOWN")))
                .is_err()
        );

        let mut fresh = HandlerRegistry::fail_closed_production().expect("build registry");
        assert!(
            fresh
                .replace_unavailable(Arc::new(UnreadyTestHandler))
                .is_err()
        );
        assert!(fresh.ready_job_types().is_empty());
    }

    #[test]
    fn api_capabilities_are_minted_only_from_exact_ready_handlers() {
        let mut registry = HandlerRegistry::fail_closed_production().expect("build registry");
        let unavailable = registry.api_activity_capabilities();
        assert!(!unavailable.supports_unscoped(INTAKE_SYNC, INTAKE_SYNC_ACTIVITY_CONTRACT_ID));
        assert!(!unavailable.supports_unscoped(
            ADVANCE_ACCEPTED_WORK_ITEM,
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
        ));
        assert!(!unavailable.supports_unscoped(
            APPLY_SIGNED_APPROVAL_DECISION,
            APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID
        ));
        assert!(
            !unavailable.supports_unscoped(VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
        );
        assert!(!unavailable.supports_unscoped(CLOSE_SOURCE, CLOSE_SOURCE_ACTIVITY_CONTRACT_ID));

        registry
            .replace_unavailable(Arc::new(ReadyTestHandler(ADVANCE_ACCEPTED_WORK_ITEM)))
            .expect("enable accepted-work activity");
        let accepted_only = registry.api_activity_capabilities();
        assert!(accepted_only.supports_unscoped(
            ADVANCE_ACCEPTED_WORK_ITEM,
            ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
        ));
        assert!(!accepted_only.supports_unscoped(INTAKE_SYNC, INTAKE_SYNC_ACTIVITY_CONTRACT_ID));
        assert!(!accepted_only.supports_unscoped(
            APPLY_SIGNED_APPROVAL_DECISION,
            APPLY_SIGNED_APPROVAL_DECISION_ACTIVITY_CONTRACT_ID
        ));

        for job_type in [
            INTAKE_SYNC,
            APPLY_SIGNED_APPROVAL_DECISION,
            CLOSE_SOURCE,
            VERIFY_EVIDENCE,
        ] {
            registry
                .replace_unavailable(Arc::new(ReadyTestHandler(job_type)))
                .expect("enable exact unscoped activity");
        }
        let reconcile_worker = WorkerId::new();
        let cancellation_worker = WorkerId::new();
        let observation_worker = WorkerId::new();
        let retention_worker = WorkerId::new();
        registry
            .replace_unavailable(Arc::new(ScopedReconcileTestHandler(reconcile_worker)))
            .expect("enable exact reconciliation route");
        registry
            .replace_unavailable(Arc::new(ScopedCancellationTestHandler(cancellation_worker)))
            .expect("enable exact cancellation route");
        registry
            .replace_unavailable(Arc::new(ScopedObserveRunmillRunTestHandler(
                observation_worker,
            )))
            .expect("enable exact Runmill observation route");
        registry
            .replace_unavailable(Arc::new(ScopedRetainTerminalEvidenceTestHandler(
                retention_worker,
            )))
            .expect("enable exact Runmill terminal evidence route");

        let complete = registry.api_activity_capabilities();
        for job_type in [
            INTAKE_SYNC,
            ADVANCE_ACCEPTED_WORK_ITEM,
            APPLY_SIGNED_APPROVAL_DECISION,
            VERIFY_EVIDENCE,
            CLOSE_SOURCE,
        ] {
            let activity_contract_id = production_activity_contract_id(job_type)
                .expect("every tested job type has a canonical activity contract id");
            assert!(complete.supports_unscoped(job_type, activity_contract_id));
            assert!(complete.supports_persisted_job_route(job_type, activity_contract_id, None));
            assert!(!complete.supports_persisted_job_route(
                job_type,
                activity_contract_id,
                Some(reconcile_worker.to_string().as_str())
            ));
        }
        assert!(
            complete
                .supports_reconcile_worker(reconcile_worker, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        );
        assert!(
            !complete.supports_reconcile_worker(
                cancellation_worker,
                RECONCILE_WORKER_ACTIVITY_CONTRACT_ID
            )
        );
        assert!(complete.supports_cancellation_worker(
            cancellation_worker,
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
        ));
        assert!(!complete.supports_cancellation_worker(
            reconcile_worker,
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
        ));
        assert!(complete.supports_observe_runmill_run_worker(
            observation_worker,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
        ));
        assert!(!complete.supports_observe_runmill_run_worker(
            reconcile_worker,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
        ));
        assert!(!complete.supports_observe_runmill_run_worker(
            cancellation_worker,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID
        ));
        assert!(complete.supports_persisted_job_route(
            RECONCILE_WORKER,
            RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
            Some(reconcile_worker.to_string().as_str())
        ));
        assert!(!complete.supports_persisted_job_route(
            RECONCILE_WORKER,
            RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
            None
        ));
        assert!(complete.supports_persisted_job_route(
            REQUEST_WORK_ITEM_CANCELLATION,
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
            Some(cancellation_worker.to_string().as_str())
        ));
        assert!(!complete.supports_persisted_job_route(
            REQUEST_WORK_ITEM_CANCELLATION,
            REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
            Some(reconcile_worker.to_string().as_str())
        ));
        assert!(complete.supports_persisted_job_route(
            OBSERVE_RUNMILL_RUN,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
            Some(observation_worker.to_string().as_str())
        ));
        assert!(!complete.supports_persisted_job_route(
            OBSERVE_RUNMILL_RUN,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
            None
        ));
        assert!(!complete.supports_persisted_job_route(
            OBSERVE_RUNMILL_RUN,
            OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
            Some(reconcile_worker.to_string().as_str())
        ));
        // Terminal evidence retention is its own worker-scoped route: it is
        // never claimable unscoped, and never through another worker's route.
        assert!(complete.supports_retain_runmill_terminal_evidence_worker(
            retention_worker,
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID
        ));
        assert!(!complete.supports_retain_runmill_terminal_evidence_worker(
            observation_worker,
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID
        ));
        assert!(complete.supports_persisted_job_route(
            RETAIN_RUNMILL_TERMINAL_EVIDENCE,
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID,
            Some(retention_worker.to_string().as_str())
        ));
        assert!(!complete.supports_persisted_job_route(
            RETAIN_RUNMILL_TERMINAL_EVIDENCE,
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID,
            None
        ));
        assert!(!complete.supports_persisted_job_route(
            RETAIN_RUNMILL_TERMINAL_EVIDENCE,
            RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID,
            Some(observation_worker.to_string().as_str())
        ));
    }

    #[test]
    fn a_ready_retention_handler_must_declare_its_exact_worker_scope() {
        let mut registry = HandlerRegistry::fail_closed_production().expect("build registry");
        // A ready retention handler with no worker scope can never establish
        // which private daemon it is allowed to read.
        assert!(
            registry
                .replace_unavailable(Arc::new(ReadyTestHandler(RETAIN_RUNMILL_TERMINAL_EVIDENCE)))
                .is_err()
        );
        assert!(
            registry
                .replace_unavailable(Arc::new(ScopedRetainTerminalEvidenceTestHandler(
                    WorkerId::from_uuid(uuid::Uuid::nil())
                )))
                .is_err()
        );
        registry
            .replace_unavailable(Arc::new(ScopedRetainTerminalEvidenceTestHandler(
                WorkerId::new(),
            )))
            .expect("a non-nil worker scope is the only ready retention route");
    }

    #[test]
    fn known_job_type_contract_pairs_report_every_registered_handler_including_placeholders() {
        let registry = HandlerRegistry::fail_closed_production().expect("build registry");
        let pairs = registry.known_job_type_contract_pairs();
        assert_eq!(pairs.len(), PRODUCTION_JOB_TYPES.len());
        for job_type in PRODUCTION_JOB_TYPES {
            let activity_contract_id = production_activity_contract_id(job_type)
                .expect("every production job type has a canonical activity contract id");
            assert!(
                pairs.iter().any(
                    |(pair_job_type, pair_contract_id)| pair_job_type == job_type
                        && pair_contract_id == activity_contract_id
                ),
                "missing known pair for placeholder {job_type}"
            );
        }
    }

    #[test]
    fn wrong_contract_never_matches_the_same_unscoped_job_type() {
        const TEST_JOB_TYPE: &str = "TEST_UNSCOPED_JOB";
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ReadyTestHandler(TEST_JOB_TYPE)))
            .expect("register unscoped test handler");
        let ready_contract_id = registry
            .handler(TEST_JOB_TYPE)
            .expect("load registered test handler")
            .activity_contract_id()
            .to_owned();
        let capabilities = registry.api_activity_capabilities();

        assert!(capabilities.supports_unscoped(TEST_JOB_TYPE, &ready_contract_id));
        assert!(!capabilities.supports_unscoped(TEST_JOB_TYPE, "test.activity/wrong-contract/v1"));
        assert!(capabilities.supports_persisted_job_route(TEST_JOB_TYPE, &ready_contract_id, None));
        assert!(!capabilities.supports_persisted_job_route(
            TEST_JOB_TYPE,
            "test.activity/wrong-contract/v1",
            None
        ));
    }

    #[test]
    fn wrong_contract_never_matches_the_same_scoped_worker() {
        let worker_id = WorkerId::new();
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ScopedReconcileTestHandler(worker_id)))
            .expect("register scoped reconciliation handler");
        let capabilities = registry.api_activity_capabilities();

        assert!(
            capabilities
                .supports_reconcile_worker(worker_id, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        );
        assert!(
            !capabilities.supports_reconcile_worker(worker_id, "asf.activity/reconcile-worker/v2")
        );
        assert!(capabilities.supports_persisted_job_route(
            RECONCILE_WORKER,
            RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
            Some(worker_id.to_string().as_str())
        ));
        assert!(!capabilities.supports_persisted_job_route(
            RECONCILE_WORKER,
            "asf.activity/reconcile-worker/v2",
            Some(worker_id.to_string().as_str())
        ));
    }

    #[test]
    fn ready_worker_reconciliation_requires_one_non_nil_exact_scope() {
        let mut unscoped = HandlerRegistry::new();
        assert!(
            unscoped
                .register(Arc::new(ReadyTestHandler(RECONCILE_WORKER)))
                .is_err()
        );

        let mut nil = HandlerRegistry::new();
        assert!(
            nil.register(Arc::new(ScopedReconcileTestHandler(WorkerId::from_uuid(
                uuid::Uuid::nil()
            ))))
            .is_err()
        );

        let worker_id = WorkerId::new();
        let mut scoped = HandlerRegistry::new();
        scoped
            .register(Arc::new(ScopedReconcileTestHandler(worker_id)))
            .expect("register scoped worker reconciliation");
        let claims = scoped.ready_claim_set();
        assert!(claims.unscoped().is_empty());
        assert_eq!(
            claims.reconcile_worker(),
            &[(
                worker_id.to_string(),
                RECONCILE_WORKER_ACTIVITY_CONTRACT_ID.to_owned()
            )]
        );
        assert_eq!(
            scoped.scoped_timer_reject_job_types(),
            vec![RECONCILE_WORKER]
        );

        let mut wrong_type = HandlerRegistry::new();
        assert!(
            wrong_type
                .register(Arc::new(MisScopedHandler(worker_id)))
                .is_err()
        );
    }

    #[test]
    fn ready_cancellation_requires_one_non_nil_exact_worker_scope() {
        let mut unscoped = HandlerRegistry::new();
        assert!(
            unscoped
                .register(Arc::new(ReadyTestHandler(REQUEST_WORK_ITEM_CANCELLATION)))
                .is_err()
        );

        let mut nil = HandlerRegistry::new();
        assert!(
            nil.register(Arc::new(ScopedCancellationTestHandler(
                WorkerId::from_uuid(uuid::Uuid::nil())
            )))
            .is_err()
        );

        let worker_id = WorkerId::new();
        let mut scoped = HandlerRegistry::new();
        scoped
            .register(Arc::new(ScopedCancellationTestHandler(worker_id)))
            .expect("register scoped cancellation");
        let claims = scoped.ready_claim_set();
        assert!(claims.unscoped().is_empty());
        assert_eq!(
            claims.cancellation_worker(),
            &[(
                worker_id.to_string(),
                REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID.to_owned()
            )]
        );
        assert_eq!(
            scoped.scoped_timer_reject_job_types(),
            vec![REQUEST_WORK_ITEM_CANCELLATION]
        );
    }

    #[test]
    fn ready_runmill_observation_requires_one_non_nil_exact_worker_scope() {
        let mut unscoped = HandlerRegistry::new();
        assert!(
            unscoped
                .register(Arc::new(ReadyTestHandler(OBSERVE_RUNMILL_RUN)))
                .is_err()
        );

        let mut nil = HandlerRegistry::new();
        assert!(
            nil.register(Arc::new(ScopedObserveRunmillRunTestHandler(
                WorkerId::from_uuid(uuid::Uuid::nil())
            )))
            .is_err()
        );

        let worker_id = WorkerId::new();
        let mut scoped = HandlerRegistry::new();
        scoped
            .register(Arc::new(ScopedObserveRunmillRunTestHandler(worker_id)))
            .expect("register scoped Runmill observation");
        let claims = scoped.ready_claim_set();
        assert!(claims.unscoped().is_empty());
        assert_eq!(
            claims.observe_runmill_run_worker(),
            &[(
                worker_id.to_string(),
                OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID.to_owned()
            )]
        );
        assert_eq!(
            claims.observe_runmill_run_worker_ids(),
            vec![worker_id.to_string()]
        );
        assert_eq!(
            scoped.scoped_timer_reject_job_types(),
            vec![OBSERVE_RUNMILL_RUN]
        );
    }

    #[test]
    fn scoped_timer_reject_job_types_include_canonical_types_even_when_unavailable() {
        let registry = HandlerRegistry::fail_closed_production().expect("build registry");
        assert!(registry.ready_job_types().is_empty());
        assert_eq!(
            registry.scoped_timer_reject_job_types(),
            vec![
                OBSERVE_RUNMILL_RUN.to_owned(),
                RECONCILE_WORKER.to_owned(),
                REQUEST_WORK_ITEM_CANCELLATION.to_owned(),
                RETAIN_RUNMILL_TERMINAL_EVIDENCE.to_owned(),
            ]
        );
    }

    #[test]
    fn scoped_timer_reject_job_types_excludes_unscoped_handlers_and_grants_no_authority() {
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ReadyTestHandler(INTAKE_SYNC)))
            .expect("register unscoped handler");
        assert!(registry.scoped_timer_reject_job_types().is_empty());
        assert!(
            !registry
                .api_activity_capabilities()
                .supports_unscoped(RECONCILE_WORKER, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
        );
    }

    #[test]
    fn scoped_timer_reject_job_types_includes_a_custom_scoped_handler() {
        let worker_id = WorkerId::new();
        let mut registry = HandlerRegistry::new();
        registry
            .register(Arc::new(ScopedCancellationTestHandler(worker_id)))
            .expect("register scoped cancellation handler");
        assert_eq!(
            registry.scoped_timer_reject_job_types(),
            vec![REQUEST_WORK_ITEM_CANCELLATION]
        );
    }

    #[test]
    fn maintenance_blocks_only_the_new_dispatch_operation() {
        let maintenance = ActivityControls::new(true);
        assert!(maintenance.maintenance_mode());
        assert!(maintenance.require_new_dispatch_permitted().is_err());
        assert!(
            ActivityControls::new(false)
                .require_new_dispatch_permitted()
                .is_ok()
        );
    }

    #[test]
    fn evidence_verification_requires_the_terminal_source_closure_handler() {
        let mut registry = HandlerRegistry::fail_closed_production().expect("build registry");
        assert!(
            registry
                .replace_unavailable(Arc::new(ReadyTestHandler(VERIFY_EVIDENCE)))
                .is_err()
        );
        assert!(
            !registry
                .api_activity_capabilities()
                .supports_unscoped(VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
        );

        registry
            .replace_unavailable(Arc::new(ReadyTestHandler(CLOSE_SOURCE)))
            .expect("enable source closure first");
        registry
            .replace_unavailable(Arc::new(ReadyTestHandler(VERIFY_EVIDENCE)))
            .expect("enable verification after its terminal dependency");
        assert!(
            registry
                .api_activity_capabilities()
                .supports_unscoped(VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
        );
    }
}
