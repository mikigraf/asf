use chrono::SubsecRound as _;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use asf::{
    Error, Result,
    api::{ApiBackend, PageQuery, PostgresApiBackend},
    domain::{EscalationCategory, TenantId, WorkerId},
    ledger::{ClaimedWorkflowJob, NewWorkflowJob, PgLedger},
    runtime::{
        ADVANCE_ACCEPTED_WORK_ITEM, ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        ActivityControls, ActivityOutcome, HandlerRegistry, JobClaimScope, JobHandler,
        RECONCILE_WORKER, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID, ReactorOptions, ReactorPollReport,
        ReactorRuntime,
    },
};
use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use sqlx::{PgPool, Row as _};
use url::Url;
use uuid::Uuid;

const RESTART_JOB: &str = "RUNTIME_TEST_RESTART";
const UNKNOWN_JOB: &str = "RUNTIME_TEST_UNKNOWN";
const FINAL_FAILURE_JOB: &str = "RUNTIME_TEST_FINAL_FAILURE";
const TRANSACTIONAL_LOCK_JOB: &str = "RUNTIME_TEST_TRANSACTIONAL_LOCK";
const FINAL_ATTEMPT_PANIC_JOB: &str = "RUNTIME_TEST_FINAL_ATTEMPT_PANIC";
const MAINTENANCE_OBSERVATION_JOB: &str = "RUNTIME_TEST_MAINTENANCE_OBSERVATION";

const RESTART_JOB_ACTIVITY_CONTRACT_ID: &str = "test.activity/runtime-test-restart/v1";
const UNKNOWN_JOB_ACTIVITY_CONTRACT_ID: &str = "test.activity/runtime-test-unknown/v1";
const FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID: &str = "test.activity/runtime-test-final-failure/v1";
const TRANSACTIONAL_LOCK_JOB_ACTIVITY_CONTRACT_ID: &str =
    "test.activity/runtime-test-transactional-lock/v1";
const FINAL_ATTEMPT_PANIC_JOB_ACTIVITY_CONTRACT_ID: &str =
    "test.activity/runtime-test-final-attempt-panic/v1";
const MAINTENANCE_OBSERVATION_JOB_ACTIVITY_CONTRACT_ID: &str =
    "test.activity/runtime-test-maintenance-observation/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    NewDispatch,
    Observation,
    Recovery,
}

/// Every job type a `ProbeHandler` is constructed with must be mapped here:
/// production types resolve to their canonical activity contract identity,
/// test-only types get a fixture-specific one.
fn probe_activity_contract_id(job_type: &str) -> &'static str {
    match job_type {
        ADVANCE_ACCEPTED_WORK_ITEM => ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        RECONCILE_WORKER => RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
        MAINTENANCE_OBSERVATION_JOB => MAINTENANCE_OBSERVATION_JOB_ACTIVITY_CONTRACT_ID,
        other => panic!("unmapped ProbeHandler job type {other}"),
    }
}

/// Every job type this fixture file enqueues as a durable row (not just
/// `ProbeHandler`-backed ones) must resolve to an explicit activity contract
/// identity here.
fn test_job_activity_contract_id(job_type: &str) -> &'static str {
    match job_type {
        RESTART_JOB => RESTART_JOB_ACTIVITY_CONTRACT_ID,
        UNKNOWN_JOB => UNKNOWN_JOB_ACTIVITY_CONTRACT_ID,
        FINAL_FAILURE_JOB => FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID,
        TRANSACTIONAL_LOCK_JOB => TRANSACTIONAL_LOCK_JOB_ACTIVITY_CONTRACT_ID,
        FINAL_ATTEMPT_PANIC_JOB => FINAL_ATTEMPT_PANIC_JOB_ACTIVITY_CONTRACT_ID,
        ADVANCE_ACCEPTED_WORK_ITEM | RECONCILE_WORKER | MAINTENANCE_OBSERVATION_JOB => {
            probe_activity_contract_id(job_type)
        }
        other => panic!("unmapped workflow job type {other}"),
    }
}

#[derive(Debug)]
struct ProbeHandler {
    job_type: &'static str,
    activity_contract_id: &'static str,
    kind: ProbeKind,
    claim_scope: JobClaimScope,
    invocations: Arc<AtomicUsize>,
    logical_effects: Arc<AtomicUsize>,
    saw_maintenance: Arc<AtomicBool>,
}

impl ProbeHandler {
    fn new(job_type: &'static str, kind: ProbeKind) -> Self {
        Self {
            job_type,
            activity_contract_id: probe_activity_contract_id(job_type),
            kind,
            claim_scope: JobClaimScope::Unscoped,
            invocations: Arc::new(AtomicUsize::new(0)),
            logical_effects: Arc::new(AtomicUsize::new(0)),
            saw_maintenance: Arc::new(AtomicBool::new(false)),
        }
    }

    fn reconcile(worker_id: WorkerId) -> Self {
        Self {
            claim_scope: JobClaimScope::ReconcileWorker(worker_id),
            ..Self::new(RECONCILE_WORKER, ProbeKind::Recovery)
        }
    }

    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    fn logical_effects(&self) -> usize {
        self.logical_effects.load(Ordering::SeqCst)
    }

    fn saw_maintenance(&self) -> bool {
        self.saw_maintenance.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JobHandler for ProbeHandler {
    fn job_type(&self) -> &str {
        self.job_type
    }

    fn activity_contract_id(&self) -> &str {
        self.activity_contract_id
    }

    fn claim_scope(&self) -> JobClaimScope {
        self.claim_scope
    }

    async fn execute(
        &self,
        _job: &ClaimedWorkflowJob,
        controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.saw_maintenance
            .store(controls.maintenance_mode(), Ordering::SeqCst);
        if self.kind == ProbeKind::NewDispatch {
            controls.require_new_dispatch_permitted()?;
        }
        self.logical_effects.fetch_add(1, Ordering::SeqCst);
        Ok(ActivityOutcome::Complete {
            result: Some(json!({"handled": self.job_type})),
        })
    }
}

/// Models a provider adapter which adopts an already-applied effect by the
/// durable job idempotency key after the first process loses its response.
#[derive(Debug)]
struct IdempotentEffectHandler {
    invocations: AtomicUsize,
    logical_effects: AtomicUsize,
    adopted_effects: AtomicUsize,
    effect_keys: Mutex<BTreeSet<String>>,
}

impl IdempotentEffectHandler {
    fn new() -> Self {
        Self {
            invocations: AtomicUsize::new(0),
            logical_effects: AtomicUsize::new(0),
            adopted_effects: AtomicUsize::new(0),
            effect_keys: Mutex::new(BTreeSet::new()),
        }
    }

    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    fn logical_effects(&self) -> usize {
        self.logical_effects.load(Ordering::SeqCst)
    }

    fn adopted_effects(&self) -> usize {
        self.adopted_effects.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JobHandler for IdempotentEffectHandler {
    fn job_type(&self) -> &str {
        RESTART_JOB
    }

    fn activity_contract_id(&self) -> &str {
        RESTART_JOB_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let newly_applied = self
            .effect_keys
            .lock()
            .expect("effect-key mutex was poisoned")
            .insert(job.idempotency_key.clone());
        if newly_applied {
            self.logical_effects.fetch_add(1, Ordering::SeqCst);
        } else {
            self.adopted_effects.fetch_add(1, Ordering::SeqCst);
        }
        Ok(ActivityOutcome::Complete {
            result: Some(json!({"effect_adopted": !newly_applied})),
        })
    }
}

#[derive(Debug)]
struct AlwaysFailHandler;

#[async_trait]
impl JobHandler for AlwaysFailHandler {
    fn job_type(&self) -> &str {
        FINAL_FAILURE_JOB
    }

    fn activity_contract_id(&self) -> &str {
        FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        _job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        Err(Error::ExternalUnavailable(
            "deterministic final-attempt failure".into(),
        ))
    }
}

#[derive(Debug)]
struct TransactionalLockHandler {
    pool: PgPool,
    hold_duration: Duration,
}

#[async_trait]
impl JobHandler for TransactionalLockHandler {
    fn job_type(&self) -> &str {
        TRANSACTIONAL_LOCK_JOB
    }

    fn activity_contract_id(&self) -> &str {
        TRANSACTIONAL_LOCK_JOB_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| Error::Persistence(format!("begin lock fixture: {error}")))?;
        let locked = sqlx::query_scalar::<_, bool>(
            r"
            SELECT true
            FROM workflow_jobs
            WHERE tenant_id = $1
              AND id = $2
              AND status = 'RUNNING'
              AND lease_owner = $3
              AND fence_token = $4
            FOR UPDATE
            ",
        )
        .bind(job.tenant_id)
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(job.fence_token)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| Error::Persistence(format!("lock finalizing job fixture: {error}")))?
        .unwrap_or(false);
        if !locked {
            return Err(Error::Conflict(
                "transactional fixture lost its claim".into(),
            ));
        }

        // Hold the row across more than one heartbeat and past the original
        // lease deadline. The row lock, owner, and fence make this transaction
        // authoritative; the heartbeat must not stop polling this handler.
        tokio::time::sleep(self.hold_duration).await;
        let changed = sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'COMPLETED',
                result = jsonb_build_object('transactional', true),
                completed_by = $3,
                completion_fence_token = $4,
                completed_at = clock_timestamp(),
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1
              AND id = $2
              AND status = 'RUNNING'
              AND lease_owner = $3
              AND fence_token = $4
            ",
        )
        .bind(job.tenant_id)
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(job.fence_token)
        .execute(&mut *transaction)
        .await
        .map_err(|error| Error::Persistence(format!("complete lock fixture: {error}")))?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Conflict(
                "transactional fixture could not finalize its fenced job".into(),
            ));
        }
        transaction
            .commit()
            .await
            .map_err(|error| Error::Persistence(format!("commit lock fixture: {error}")))?;
        Ok(ActivityOutcome::TransactionCommitted)
    }
}

#[derive(Debug)]
struct FinalAttemptPanicHandler;

#[async_trait]
impl JobHandler for FinalAttemptPanicHandler {
    fn job_type(&self) -> &str {
        FINAL_ATTEMPT_PANIC_JOB
    }

    fn activity_contract_id(&self) -> &str {
        FINAL_ATTEMPT_PANIC_JOB_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        _job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        panic!("deterministic final-attempt crash fixture")
    }
}

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect reactor-test administrator");
        let schema = format!("asf_reactor_test_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated reactor-test schema");
        let mut scoped_url = Url::parse(database_url).expect("parse reactor test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated reactor ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated reactor schema");
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
            .expect("drop isolated reactor-test schema");
        self.admin.close().await;
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn claimed_job(job_type: &str) -> ClaimedWorkflowJob {
    ClaimedWorkflowJob {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        workflow_instance_id: None,
        work_item_id: None,
        attempt_id: None,
        job_type: job_type.into(),
        activity_contract_id: test_job_activity_contract_id(job_type).into(),
        payload: json!({}),
        idempotency_key: format!("deterministic:{job_type}"),
        priority: 0,
        attempt_count: 1,
        max_attempts: 5,
        fence_token: 1,
        lease_owner: "deterministic-reactor".into(),
        lease_expires_at: Utc::now().trunc_subsecs(6) + ChronoDuration::minutes(1),
        created_at: Utc::now().trunc_subsecs(6),
    }
}

fn options(lease_owner: &str) -> ReactorOptions {
    ReactorOptions {
        lease_owner: lease_owner.into(),
        poll_interval: Duration::from_millis(10),
        lease_duration: Duration::from_secs(5),
        max_error_backoff: Duration::from_secs(1),
        claim_batch_size: 16,
    }
}

fn job(tenant_id: Uuid, job_type: &str, idempotency_key: String) -> NewWorkflowJob {
    NewWorkflowJob {
        id: Uuid::now_v7(),
        tenant_id,
        workflow_instance_id: None,
        work_item_id: None,
        attempt_id: None,
        job_type: job_type.into(),
        activity_contract_id: test_job_activity_contract_id(job_type).into(),
        payload: json!({"test": "reactor-restart"}),
        idempotency_key,
        priority: 0,
        available_at: Utc::now().trunc_subsecs(6) - ChronoDuration::seconds(1),
        max_attempts: 5,
    }
}

fn registry(handlers: &[Arc<ProbeHandler>]) -> HandlerRegistry {
    let mut registry = HandlerRegistry::new();
    for handler in handlers {
        registry
            .register(handler.clone())
            .expect("register probe handler");
    }
    registry
}

#[tokio::test]
async fn maintenance_controls_are_fail_closed_at_dispatch_but_allow_observation_and_recovery() {
    let recovery_worker_id = WorkerId::new();
    let dispatch = Arc::new(ProbeHandler::new(
        ADVANCE_ACCEPTED_WORK_ITEM,
        ProbeKind::NewDispatch,
    ));
    let observation = Arc::new(ProbeHandler::new(
        MAINTENANCE_OBSERVATION_JOB,
        ProbeKind::Observation,
    ));
    let recovery = Arc::new(ProbeHandler::reconcile(recovery_worker_id));
    let registry = registry(&[dispatch.clone(), observation.clone(), recovery.clone()]);
    let maintenance = ActivityControls::new(true);

    let dispatch_error = registry
        .handler(ADVANCE_ACCEPTED_WORK_ITEM)
        .expect("registered dispatch handler")
        .execute(&claimed_job(ADVANCE_ACCEPTED_WORK_ITEM), maintenance)
        .await
        .expect_err("maintenance must suppress a new dispatch effect");
    assert!(matches!(dispatch_error, Error::ExternalUnavailable(_)));
    assert_eq!(dispatch.invocations(), 1);
    assert_eq!(dispatch.logical_effects(), 0);

    for (job_type, handler) in [
        (MAINTENANCE_OBSERVATION_JOB, &observation),
        (RECONCILE_WORKER, &recovery),
    ] {
        let outcome = registry
            .handler(job_type)
            .expect("registered non-dispatch handler")
            .execute(&claimed_job(job_type), maintenance)
            .await
            .expect("maintenance must preserve observation and recovery work");
        assert!(matches!(outcome, ActivityOutcome::Complete { .. }));
        assert_eq!(handler.logical_effects(), 1);
        assert!(handler.saw_maintenance());
    }

    registry
        .handler(ADVANCE_ACCEPTED_WORK_ITEM)
        .expect("registered dispatch handler")
        .execute(
            &claimed_job(ADVANCE_ACCEPTED_WORK_ITEM),
            ActivityControls::new(false),
        )
        .await
        .expect("dispatch is permitted outside maintenance");
    assert_eq!(dispatch.logical_effects(), 1);
    assert!(registry.handler(UNKNOWN_JOB).is_none());
}

#[tokio::test]
async fn live_worker_scoped_reactors_isolate_normal_expired_orphaned_and_malformed_jobs() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-worker-route-{tenant_id}"))
        .bind("Reactor worker routing test")
        .execute(database.ledger.pool())
        .await
        .expect("insert worker-routing tenant");

    let worker_a = WorkerId::new();
    let worker_b = WorkerId::new();
    let mut normal_a = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-a:{tenant_id}"),
    );
    normal_a.payload = json!({"worker_id": worker_a});

    let mut normal_b = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-b:{tenant_id}"),
    );
    normal_b.payload = json!({"worker_id": worker_b});
    normal_b.priority = 100;

    let mut expired_b = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-b-expired:{tenant_id}"),
    );
    expired_b.payload = json!({"worker_id": worker_b});
    expired_b.priority = 90;

    let mut orphaned_b = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-b-orphaned:{tenant_id}"),
    );
    orphaned_b.payload = json!({"worker_id": worker_b});
    orphaned_b.priority = 80;
    orphaned_b.max_attempts = 1;

    let mut malformed = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-malformed:{tenant_id}"),
    );
    malformed.payload = json!({"worker_id": "not-a-uuid"});
    malformed.priority = 110;

    let mut missing = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("worker-route-missing:{tenant_id}"),
    );
    missing.payload = json!({"expected_generation": 1});
    missing.priority = 109;

    for queued in [
        &normal_a,
        &normal_b,
        &expired_b,
        &orphaned_b,
        &malformed,
        &missing,
    ] {
        database
            .ledger
            .enqueue_job(queued)
            .await
            .expect("enqueue worker-routing fixture");
    }
    for (id, attempts, owner) in [
        (expired_b.id, 1_i32, "crashed-worker-b"),
        (orphaned_b.id, 1_i32, "crashed-final-worker-b"),
    ] {
        sqlx::query(
            r"
            UPDATE workflow_jobs
            SET status = 'RUNNING',
                attempt_count = $3,
                fence_token = 1,
                lease_owner = $4,
                lease_expires_at = clock_timestamp() - interval '1 second',
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(attempts)
        .bind(owner)
        .execute(database.ledger.pool())
        .await
        .expect("install expired worker-routing claim");
    }

    let handler_a = Arc::new(ProbeHandler::reconcile(worker_a));
    let reactor_a = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        registry(std::slice::from_ref(&handler_a)),
        options("reactor-worker-a"),
        false,
    )
    .expect("construct worker A reactor");
    assert_eq!(
        reactor_a.poll_once().await.expect("poll worker A route"),
        ReactorPollReport {
            route_invalid_jobs_rejected: 2,
            jobs_claimed: 1,
            jobs_completed: 1,
            jobs_transactionally_finalized: 2,
            ..ReactorPollReport::default()
        }
    );
    assert_eq!(handler_a.invocations(), 1);

    let states_after_a: Vec<(Uuid, String, i32, Option<String>)> = sqlx::query_as(
        r"
        SELECT id, status, attempt_count, lease_owner
        FROM workflow_jobs
        WHERE tenant_id = $1
          AND id = ANY($2::uuid[])
        ORDER BY id
        ",
    )
    .bind(tenant_id)
    .bind(vec![
        normal_b.id,
        expired_b.id,
        orphaned_b.id,
        malformed.id,
        missing.id,
    ])
    .fetch_all(database.ledger.pool())
    .await
    .expect("load foreign worker jobs after worker A poll");
    assert_eq!(states_after_a.len(), 5);
    for (id, status, attempts, owner) in states_after_a {
        if id == normal_b.id {
            assert_eq!(status, "PENDING");
            assert_eq!(attempts, 0);
            assert!(owner.is_none());
        } else if id == malformed.id || id == missing.id {
            assert_eq!(status, "DEAD");
            assert_eq!(attempts, malformed.max_attempts);
            assert!(owner.is_none());
        } else {
            assert_eq!(status, "RUNNING");
            assert_eq!(attempts, 1);
            assert!(
                owner
                    .as_deref()
                    .is_some_and(|value| value.starts_with("crashed"))
            );
        }
    }

    let handler_b = Arc::new(ProbeHandler::reconcile(worker_b));
    let reactor_b = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        registry(std::slice::from_ref(&handler_b)),
        options("reactor-worker-b"),
        false,
    )
    .expect("construct worker B reactor");
    assert_eq!(
        reactor_b.poll_once().await.expect("poll worker B route"),
        ReactorPollReport {
            orphaned_jobs_recovered: 1,
            jobs_claimed: 2,
            jobs_completed: 2,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );
    assert_eq!(handler_b.invocations(), 2);

    let (normal_b_status, normal_b_attempts, normal_b_owner): (String, i32, Option<String>) =
        sqlx::query_as(
            "SELECT status, attempt_count, completed_by FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(normal_b.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load completed worker B job");
    assert_eq!(normal_b_status, "COMPLETED");
    assert_eq!(normal_b_attempts, 1);
    assert_eq!(normal_b_owner.as_deref(), Some("reactor-worker-b"));

    let (expired_b_status, expired_b_attempts, expired_b_owner): (String, i32, Option<String>) =
        sqlx::query_as(
            "SELECT status, attempt_count, completed_by FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(expired_b.id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load reclaimed worker B job");
    assert_eq!(expired_b_status, "COMPLETED");
    assert_eq!(expired_b_attempts, 2);
    assert_eq!(expired_b_owner.as_deref(), Some("reactor-worker-b"));

    let orphaned_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(orphaned_b.id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load dead-lettered worker B orphan");
    assert_eq!(orphaned_status, "DEAD");

    let malformed_state: (String, i32, Option<String>, Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT status, attempt_count, lease_owner, dead_letter_operational_incident_id, last_error FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(malformed.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load malformed worker route");
    assert_eq!(malformed_state.0, "DEAD");
    assert_eq!(malformed_state.1, malformed.max_attempts);
    assert!(malformed_state.2.is_none());
    assert!(malformed_state.3.is_some());
    assert!(
        malformed_state
            .4
            .as_deref()
            .is_some_and(|error| error.contains("missing, malformed, or contradictory"))
    );
    let missing_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(missing.id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load missing worker route");
    assert_eq!(missing_status, "DEAD");

    database.cleanup().await;
}

#[tokio::test]
async fn live_worker_scoped_timer_is_rejected_without_firing_or_enqueuing() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let worker_id = WorkerId::new();
    let timer_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-worker-timer-{tenant_id}"))
        .bind("Reactor worker timer routing test")
        .execute(database.ledger.pool())
        .await
        .expect("insert scoped-timer tenant");
    sqlx::query(
        r"
        INSERT INTO workflow_timers (
            id, tenant_id, workflow_key, timer_key, timer_type,
            activity_contract_id, due_at, payload
        )
        VALUES (
            $1, $2, $3, $4, 'RECONCILE_WORKER', $5,
            clock_timestamp() - interval '1 second', $6
        )
        ",
    )
    .bind(timer_id)
    .bind(tenant_id)
    .bind(format!("worker-timer:{worker_id}"))
    .bind(format!("reconcile:{worker_id}"))
    .bind(RECONCILE_WORKER_ACTIVITY_CONTRACT_ID)
    .bind(json!({"worker_id": worker_id}))
    .execute(database.ledger.pool())
    .await
    .expect("insert unsupported scoped timer");

    let handler = Arc::new(ProbeHandler::reconcile(worker_id));
    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        registry(&[handler]),
        options("reactor-worker-timer"),
        false,
    )
    .expect("construct scoped-timer reactor");
    let error = reactor
        .poll_once()
        .await
        .expect_err("generic timer promotion must reject scoped worker work");
    assert!(matches!(error, Error::Validation(_)));

    let timer_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_timers WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(timer_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load rejected scoped timer");
    assert_eq!(timer_status, "SCHEDULED");
    let job_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_jobs WHERE tenant_id = $1 AND job_type = 'RECONCILE_WORKER'",
    )
    .bind(tenant_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count jobs after rejected scoped timer");
    assert_eq!(job_count, 0);

    database.cleanup().await;
}

#[tokio::test]
async fn live_timer_promotion_copies_the_timer_activity_contract_id_unchanged() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let timer_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-timer-promotion-{tenant_id}"))
        .bind("Reactor timer promotion test")
        .execute(database.ledger.pool())
        .await
        .expect("insert timer-promotion tenant");
    sqlx::query(
        r"
        INSERT INTO workflow_timers (
            id, tenant_id, workflow_key, timer_key, timer_type,
            activity_contract_id, due_at, payload
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            clock_timestamp() - interval '1 second', $7
        )
        ",
    )
    .bind(timer_id)
    .bind(tenant_id)
    .bind(format!("timer-promotion:{timer_id}"))
    .bind(format!("fire:{timer_id}"))
    .bind(MAINTENANCE_OBSERVATION_JOB)
    .bind(MAINTENANCE_OBSERVATION_JOB_ACTIVITY_CONTRACT_ID)
    .bind(json!({"probe": "timer-promotion"}))
    .execute(database.ledger.pool())
    .await
    .expect("insert unscoped due timer");

    let observation = Arc::new(ProbeHandler::new(
        MAINTENANCE_OBSERVATION_JOB,
        ProbeKind::Observation,
    ));
    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        registry(&[observation]),
        options("reactor-timer-promotion"),
        false,
    )
    .expect("construct timer-promotion reactor");
    let report = reactor
        .poll_once()
        .await
        .expect("promote the unscoped due timer");
    assert_eq!(report.timers_promoted, 1);

    let timer_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_timers WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(timer_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load fired timer");
    assert_eq!(timer_status, "FIRED");

    let promoted_activity_contract_id: String = sqlx::query_scalar(
        "SELECT activity_contract_id FROM workflow_jobs
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant_id)
    .bind(format!("workflow-timer:{timer_id}:1"))
    .fetch_one(database.ledger.pool())
    .await
    .expect("load promoted workflow job");
    assert_eq!(
        promoted_activity_contract_id,
        MAINTENANCE_OBSERVATION_JOB_ACTIVITY_CONTRACT_ID
    );

    database.cleanup().await;
}

#[tokio::test]
async fn live_transactional_handler_keeps_progress_while_heartbeat_waits_on_its_job_lock() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-heartbeat-{tenant_id}"))
        .bind("Reactor heartbeat lock test")
        .execute(database.ledger.pool())
        .await
        .expect("insert heartbeat tenant");
    database
        .ledger
        .enqueue_job(&NewWorkflowJob {
            id: job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: TRANSACTIONAL_LOCK_JOB.into(),
            activity_contract_id: TRANSACTIONAL_LOCK_JOB_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"scope": "heartbeat-lock"}),
            idempotency_key: format!("heartbeat-lock:{job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6) - ChronoDuration::seconds(1),
            max_attempts: 2,
        })
        .await
        .expect("enqueue heartbeat-lock job");

    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(TransactionalLockHandler {
            pool: database.ledger.pool().clone(),
            hold_duration: Duration::from_millis(450),
        }))
        .expect("register transactional-lock handler");
    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        handlers,
        ReactorOptions {
            lease_owner: "reactor-heartbeat-lock".into(),
            poll_interval: Duration::from_millis(25),
            lease_duration: Duration::from_millis(300),
            max_error_backoff: Duration::from_secs(1),
            claim_batch_size: 1,
        },
        false,
    )
    .expect("construct heartbeat-lock reactor");

    let report = tokio::time::timeout(Duration::from_secs(3), reactor.poll_once())
        .await
        .expect("heartbeat must not self-deadlock the final transaction")
        .expect("transactional handler must commit under its original fence");
    assert_eq!(
        report,
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );
    let (status, completed_by, completion_fence): (String, Option<String>, Option<i64>) =
        sqlx::query_as(
            "SELECT status, completed_by, completion_fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load heartbeat-lock completion");
    assert_eq!(status, "COMPLETED");
    assert_eq!(completed_by.as_deref(), Some("reactor-heartbeat-lock"));
    assert_eq!(completion_fence, Some(1));

    drop(reactor);
    database.cleanup().await;
}

#[tokio::test]
async fn live_expired_final_attempt_after_handler_panic_is_reclaimed_into_owned_attention() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-panic-{tenant_id}"))
        .bind("Reactor final-attempt panic test")
        .execute(database.ledger.pool())
        .await
        .expect("insert panic-recovery tenant");
    database
        .ledger
        .enqueue_job(&NewWorkflowJob {
            id: job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: FINAL_ATTEMPT_PANIC_JOB.into(),
            activity_contract_id: FINAL_ATTEMPT_PANIC_JOB_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"scope": "panic-recovery"}),
            idempotency_key: format!("panic-recovery:{job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6) - ChronoDuration::seconds(1),
            max_attempts: 1,
        })
        .await
        .expect("enqueue final-attempt panic job");

    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(FinalAttemptPanicHandler))
        .expect("register final-attempt panic handler");
    let crash_options = ReactorOptions {
        lease_owner: "reactor-before-panic".into(),
        poll_interval: Duration::from_millis(10),
        lease_duration: Duration::from_millis(80),
        max_error_backoff: Duration::from_secs(1),
        claim_batch_size: 1,
    };
    let crashing = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        handlers.clone(),
        crash_options.clone(),
        false,
    )
    .expect("construct crashing reactor");
    let crash = crashing
        .poll_once()
        .await
        .expect_err("handler panic must terminate its claimed task");
    assert!(crash.to_string().contains("panicked"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let recovering = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        handlers,
        ReactorOptions {
            lease_owner: "reactor-after-panic".into(),
            ..crash_options
        },
        false,
    )
    .expect("construct panic-recovery reactor");
    assert_eq!(
        recovering
            .poll_once()
            .await
            .expect("expired final attempt must be atomically recovered"),
        ReactorPollReport {
            orphaned_jobs_recovered: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );

    let (status, attempt_count, fence_token, incident_id): (String, i32, i64, Option<Uuid>) =
        sqlx::query_as(
            r"
            SELECT status, attempt_count, fence_token, dead_letter_operational_incident_id
            FROM workflow_jobs
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load recovered final-attempt job");
    assert_eq!(status, "DEAD");
    assert_eq!(
        attempt_count, 1,
        "recovery is not another execution attempt"
    );
    assert_eq!(fence_token, 2, "recovery must supersede the crashed owner");
    assert!(incident_id.is_some());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM operational_incidents WHERE tenant_id = $1 AND workflow_job_id = $2 AND status = 'OPEN'",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count recovered operational incidents"),
        1
    );
    assert_eq!(
        recovering
            .poll_once()
            .await
            .expect("recovered dead job is stable"),
        ReactorPollReport::default()
    );

    drop(crashing);
    drop(recovering);
    database.cleanup().await;
}

#[tokio::test]
async fn live_final_failure_is_atomically_owned_and_dead_lettered_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let repository_id = Uuid::now_v7();
    let policy_id = Uuid::now_v7();
    let snapshot_id = Uuid::now_v7();
    let work_item_id = Uuid::now_v7();
    let workflow_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    let policy_digest = digest('a');
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin final-failure fixture");
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-final-{tenant_id}"))
        .bind("Reactor final failure test")
        .execute(&mut *transaction)
        .await
        .expect("insert final-failure tenant");
    sqlx::query(
        r"
        INSERT INTO policy_versions (
            id, tenant_id, scope, schema_version, digest, canonical_bytes,
            policy, created_by
        ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')
        ",
    )
    .bind(policy_id)
    .bind(tenant_id)
    .bind(&policy_digest)
    .bind(br"{}".as_slice())
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure policy");
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, owner, name, repository_url, default_branch,
            default_policy_digest
        ) VALUES ($1, $2, 'acme', 'reactor', $3, 'main', $4)
        ",
    )
    .bind(repository_id)
    .bind(tenant_id)
    .bind(format!("https://example.invalid/{repository_id}"))
    .bind(&policy_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure repository");
    sqlx::query(
        r"
        INSERT INTO source_snapshots (
            id, tenant_id, repository_id, source_system, external_id,
            source_revision, normalized_content, content_digest,
            connector_identity, source_updated_at
        ) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5,
                  'test:reactor', clock_timestamp())
        ",
    )
    .bind(snapshot_id)
    .bind(tenant_id)
    .bind(repository_id)
    .bind(format!("final-{work_item_id}"))
    .bind(digest('b'))
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure source snapshot");
    sqlx::query(
        r"
        INSERT INTO work_items (
            id, tenant_id, source_snapshot_id, source_system,
            source_external_id, repository_id, state, closure_target,
            risk_class, policy_digest, budget_limits,
            identity_requirements, owner_fallback, normalized_priority,
            accepted_at
        ) VALUES (
            $1, $2, $3, 'API', $4, $5, 'ACCEPTED', 'pull_request', 'low', $6,
            jsonb_build_object(
                'max_cost_microunits', 1000000,
                'max_input_tokens', 100000,
                'max_output_tokens', 100000,
                'max_implementer_invocations', 2,
                'max_reviewer_invocations', 2,
                'max_fix_iterations', 1,
                'max_wall_time_seconds', 3600,
                'max_external_api_calls', 10
            ),
            jsonb_build_object(
                'implementer', 'codex:implementer',
                'local_reviewer', 'claude:local-reviewer',
                'pr_reviewer', 'codex:pr-reviewer'
            ),
            'platform-operations', 50, clock_timestamp()
        )
        ",
    )
    .bind(work_item_id)
    .bind(tenant_id)
    .bind(snapshot_id)
    .bind(format!("final-{work_item_id}"))
    .bind(repository_id)
    .bind(&policy_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure work item");
    sqlx::query(
        r"
        INSERT INTO workflow_instances (
            id, tenant_id, work_item_id, workflow_type, reducer_version
        ) VALUES ($1, $2, $3, 'delivery', 'v1')
        ",
    )
    .bind(workflow_id)
    .bind(tenant_id)
    .bind(work_item_id)
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure workflow");
    sqlx::query(
        r"
        INSERT INTO accountability_anchors (
            tenant_id, work_item_id, anchor_type, reference_id, generation
        ) VALUES ($1, $2, 'WORKFLOW', $3, 1)
        ",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .bind(workflow_id)
    .execute(&mut *transaction)
    .await
    .expect("insert final-failure accountability anchor");
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, job_type,
            activity_contract_id, payload, idempotency_key, max_attempts
        ) VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, $7, 1)
        ",
    )
    .bind(job_id)
    .bind(tenant_id)
    .bind(workflow_id)
    .bind(work_item_id)
    .bind(FINAL_FAILURE_JOB)
    .bind(FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID)
    .bind(format!("final-failure:{job_id}"))
    .execute(&mut *transaction)
    .await
    .expect("insert final-attempt job");
    transaction
        .commit()
        .await
        .expect("commit final-failure fixture");

    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(AlwaysFailHandler))
        .expect("register final-failure handler");
    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        handlers,
        options("reactor-final-failure"),
        false,
    )
    .expect("construct final-failure reactor");
    let report = reactor
        .poll_once()
        .await
        .expect("final failure must be atomically dead-lettered");
    assert_eq!(
        report,
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );

    let row = sqlx::query(
        r"
        SELECT
            job.status AS job_status,
            job.dead_letter_escalation_id,
            work.state AS work_state,
            workflow.state AS workflow_state,
            anchor.anchor_type,
            anchor.reference_id,
            escalation.owner_type,
            escalation.owner_id,
            escalation.required_action,
            escalation.evidence_references,
            escalation.deadline,
            escalation.retry_policy,
            escalation.authority_or_effect_active
        FROM workflow_jobs AS job
        JOIN work_items AS work
          ON work.tenant_id = job.tenant_id AND work.id = job.work_item_id
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = job.tenant_id
         AND workflow.id = job.workflow_instance_id
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = job.tenant_id
         AND anchor.work_item_id = job.work_item_id
        JOIN escalations AS escalation
          ON escalation.tenant_id = job.tenant_id
         AND escalation.id = job.dead_letter_escalation_id
        WHERE job.tenant_id = $1 AND job.id = $2
        ",
    )
    .bind(tenant_id)
    .bind(job_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load atomically dead-lettered job");
    let escalation_id: Uuid = row
        .try_get("dead_letter_escalation_id")
        .expect("decode escalation identity");
    assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "DEAD");
    assert_eq!(row.try_get::<String, _>("work_state").unwrap(), "ESCALATED");
    assert_eq!(
        row.try_get::<String, _>("workflow_state").unwrap(),
        "WAITING"
    );
    assert_eq!(
        row.try_get::<String, _>("anchor_type").unwrap(),
        "ESCALATION"
    );
    assert_eq!(
        row.try_get::<Uuid, _>("reference_id").unwrap(),
        escalation_id
    );
    assert_eq!(row.try_get::<String, _>("owner_type").unwrap(), "ON_CALL");
    assert_eq!(
        row.try_get::<String, _>("owner_id").unwrap(),
        "platform-operations"
    );
    assert!(
        row.try_get::<String, _>("required_action")
            .unwrap()
            .contains("reconcile")
    );
    assert!(
        row.try_get::<serde_json::Value, _>("evidence_references")
            .unwrap()
            .as_array()
            .is_some_and(|references| !references.is_empty())
    );
    assert!(
        row.try_get::<serde_json::Value, _>("retry_policy")
            .unwrap()
            .get("automatic")
            .is_some_and(|value| value == false)
    );
    assert!(
        row.try_get::<bool, _>("authority_or_effect_active")
            .unwrap()
    );
    assert!(
        row.try_get::<chrono::DateTime<Utc>, _>("deadline").unwrap() > Utc::now().trunc_subsecs(6)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'WORKFLOW_JOB_EXHAUSTED'"
        )
        .bind(tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count final-failure audit events"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox WHERE tenant_id = $1 AND event_type = 'workflow_job.exhausted'"
        )
        .bind(tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count final-failure outbox messages"),
        1
    );
    assert_eq!(
        reactor
            .poll_once()
            .await
            .expect("dead-lettered job is not reclaimed"),
        ReactorPollReport::default()
    );
    drop(reactor);
    database.cleanup().await;
}

#[tokio::test]
async fn live_tenant_job_exhaustion_is_an_atomic_operational_incident_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-operational-{tenant_id}"))
        .bind("Reactor operational failure test")
        .execute(database.ledger.pool())
        .await
        .expect("insert operational-failure tenant");
    database
        .ledger
        .enqueue_job(&NewWorkflowJob {
            id: job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: FINAL_FAILURE_JOB.into(),
            activity_contract_id: FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"scope": "tenant"}),
            idempotency_key: format!("operational-final-failure:{job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6) - ChronoDuration::seconds(1),
            max_attempts: 1,
        })
        .await
        .expect("enqueue tenant-level final-attempt job");

    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(AlwaysFailHandler))
        .expect("register operational final-failure handler");
    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        tenant_id,
        handlers,
        options("reactor-operational-final-failure"),
        false,
    )
    .expect("construct operational final-failure reactor");
    assert_eq!(
        reactor
            .poll_once()
            .await
            .expect("tenant-level final failure must become an operational incident"),
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );

    let row = sqlx::query(
        r"
        SELECT
            job.status AS job_status,
            job.lease_owner,
            job.dead_letter_escalation_id,
            job.dead_letter_operational_incident_id,
            incident.workflow_job_id,
            incident.category,
            incident.status AS incident_status,
            incident.owner_type,
            incident.owner_id,
            incident.required_action,
            incident.evidence_references,
            incident.deadline,
            incident.retry_policy,
            incident.authority_or_effect_active
        FROM workflow_jobs AS job
        JOIN operational_incidents AS incident
          ON incident.tenant_id = job.tenant_id
         AND incident.workflow_job_id = job.id
         AND incident.id = job.dead_letter_operational_incident_id
        WHERE job.tenant_id = $1 AND job.id = $2
        ",
    )
    .bind(tenant_id)
    .bind(job_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load atomically dead-lettered operational job");
    let incident_id: Uuid = row
        .try_get("dead_letter_operational_incident_id")
        .expect("decode operational incident identity");
    assert_eq!(row.try_get::<String, _>("job_status").unwrap(), "DEAD");
    assert!(
        row.try_get::<Option<String>, _>("lease_owner")
            .unwrap()
            .is_none()
    );
    assert!(
        row.try_get::<Option<Uuid>, _>("dead_letter_escalation_id")
            .unwrap()
            .is_none()
    );
    assert_eq!(row.try_get::<Uuid, _>("workflow_job_id").unwrap(), job_id);
    assert_eq!(
        row.try_get::<String, _>("category").unwrap(),
        "WORKFLOW_JOB_EXHAUSTED"
    );
    assert_eq!(row.try_get::<String, _>("incident_status").unwrap(), "OPEN");
    assert_eq!(row.try_get::<String, _>("owner_type").unwrap(), "ON_CALL");
    assert_eq!(
        row.try_get::<String, _>("owner_id").unwrap(),
        "platform-operations"
    );
    assert!(
        row.try_get::<String, _>("required_action")
            .unwrap()
            .contains("reconcile")
    );
    assert!(
        row.try_get::<serde_json::Value, _>("evidence_references")
            .unwrap()
            .as_array()
            .is_some_and(|references| references.len() == 2)
    );
    assert!(
        row.try_get::<serde_json::Value, _>("retry_policy")
            .unwrap()
            .get("automatic")
            .is_some_and(|value| value == false)
    );
    assert!(
        row.try_get::<bool, _>("authority_or_effect_active")
            .unwrap()
    );
    assert!(
        row.try_get::<chrono::DateTime<Utc>, _>("deadline").unwrap() > Utc::now().trunc_subsecs(6)
    );

    let audit = sqlx::query(
        r"
        SELECT work_item_id, action, subject_type, subject_id, details
        FROM audit_events
        WHERE tenant_id = $1 AND action = 'OPERATIONAL_WORKFLOW_JOB_EXHAUSTED'
        ",
    )
    .bind(tenant_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load operational final-failure audit event");
    assert!(
        audit
            .try_get::<Option<Uuid>, _>("work_item_id")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        audit.try_get::<String, _>("subject_type").unwrap(),
        "WORKFLOW_JOB"
    );
    assert_eq!(
        audit.try_get::<String, _>("subject_id").unwrap(),
        job_id.to_string()
    );
    assert_eq!(
        audit
            .try_get::<serde_json::Value, _>("details")
            .unwrap()
            .get("operational_incident_id")
            .and_then(serde_json::Value::as_str),
        Some(incident_id.to_string().as_str())
    );

    let outbox = sqlx::query(
        r"
        SELECT message_key, payload, headers
        FROM outbox
        WHERE tenant_id = $1 AND event_type = 'operational_job.exhausted'
        ",
    )
    .bind(tenant_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load operational attention outbox message");
    assert_eq!(
        outbox.try_get::<String, _>("message_key").unwrap(),
        job_id.to_string()
    );
    let payload: serde_json::Value = outbox.try_get("payload").unwrap();
    assert_eq!(
        payload
            .get("operational_incident_id")
            .and_then(serde_json::Value::as_str),
        Some(incident_id.to_string().as_str())
    );
    assert!(payload.get("work_item_id").is_none());
    assert_eq!(
        outbox
            .try_get::<serde_json::Value, _>("headers")
            .unwrap()
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some("asf.operational-attention-event/v1")
    );

    let backend = PostgresApiBackend::from_ledger(&database.ledger, TenantId::from_uuid(tenant_id));
    let attention = backend
        .attention(
            TenantId::from_uuid(tenant_id),
            &PageQuery {
                cursor: None,
                limit: 10,
            },
        )
        .await
        .expect("operational incident must project into attention");
    assert_eq!(attention.items.len(), 1);
    assert_eq!(attention.items[0].id, incident_id);
    assert!(attention.items[0].work_item_id.is_none());
    assert_eq!(attention.items[0].workflow_job_id, Some(job_id));
    assert_eq!(
        attention.items[0].category,
        EscalationCategory::WorkflowJobExhausted
    );

    assert_eq!(
        reactor
            .poll_once()
            .await
            .expect("dead operational job is not orphaned or reclaimed"),
        ReactorPollReport::default()
    );

    let naked_job_id = Uuid::now_v7();
    database
        .ledger
        .enqueue_job(&NewWorkflowJob {
            id: naked_job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: FINAL_FAILURE_JOB.into(),
            activity_contract_id: FINAL_FAILURE_JOB_ACTIVITY_CONTRACT_ID.into(),
            payload: json!({"scope": "tenant"}),
            idempotency_key: format!("naked-operational-dead-letter:{naked_job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6),
            max_attempts: 1,
        })
        .await
        .expect("enqueue naked-dead-letter guard fixture");
    let naked_error = sqlx::query(
        "UPDATE workflow_jobs SET status = 'DEAD', dead_lettered_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(naked_job_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("database must reject a tenant job dead-lettered without an incident");
    assert!(
        naked_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == "23514")
    );

    drop(reactor);
    database.cleanup().await;
}

#[tokio::test]
async fn live_reactor_reclaims_after_restart_and_prevents_duplicate_effects_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };

    let first_ledger = PgLedger::connect(&database_url)
        .await
        .expect("connect first process to test PostgreSQL");
    first_ledger
        .migrate()
        .await
        .expect("migrate test PostgreSQL");
    let tenant_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("reactor-restart-{tenant_id}"))
        .bind("Reactor restart integration test")
        .execute(first_ledger.pool())
        .await
        .expect("insert isolated reactor test tenant");

    let restart_job = job(tenant_id, RESTART_JOB, format!("restart-once:{tenant_id}"));
    assert!(
        first_ledger
            .enqueue_job(&restart_job)
            .await
            .expect("enqueue restart job")
            .inserted
    );
    let original_claim = first_ledger
        .claim_jobs(
            tenant_id,
            "reactor-process-before-crash",
            1,
            Duration::from_secs(30),
        )
        .await
        .expect("claim job in first process")
        .pop()
        .expect("first process claimed restart job");
    assert_eq!(original_claim.fence_token, 1);
    assert_eq!(original_claim.attempt_count, 1);

    let restart_handler = Arc::new(IdempotentEffectHandler::new());
    let lost_completion = restart_handler
        .execute(&original_claim, ActivityControls::new(false))
        .await
        .expect("first process applies its idempotent effect");
    assert!(matches!(lost_completion, ActivityOutcome::Complete { .. }));
    assert_eq!(restart_handler.invocations(), 1);
    assert_eq!(restart_handler.logical_effects(), 1);

    sqlx::query(
        "UPDATE workflow_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(restart_job.id)
    .execute(first_ledger.pool())
    .await
    .expect("expire crashed process lease");
    first_ledger.close().await;

    let second_ledger = PgLedger::connect(&database_url)
        .await
        .expect("connect replacement process to test PostgreSQL");
    let mut restart_registry = HandlerRegistry::new();
    restart_registry
        .register(restart_handler.clone())
        .expect("register idempotent restart handler");
    let replacement = ReactorRuntime::new(
        second_ledger.clone(),
        tenant_id,
        restart_registry.clone(),
        options("reactor-process-after-crash"),
        false,
    )
    .expect("construct replacement reactor");
    let reclaimed = replacement
        .poll_once()
        .await
        .expect("replacement reactor reclaims expired work");
    assert_eq!(
        reclaimed,
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_completed: 1,
            ..ReactorPollReport::default()
        }
    );
    assert_eq!(restart_handler.logical_effects(), 1);
    assert_eq!(restart_handler.invocations(), 2);
    assert_eq!(restart_handler.adopted_effects(), 1);

    let (status, attempt_count, fence_token, completed_by): (String, i32, i64, Option<String>) =
        sqlx::query_as(
            "SELECT status, attempt_count, fence_token, completed_by FROM workflow_jobs \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(restart_job.id)
        .fetch_one(second_ledger.pool())
        .await
        .expect("load reclaimed job");
    assert_eq!(status, "COMPLETED");
    assert_eq!(attempt_count, 2);
    assert_eq!(fence_token, 2);
    assert_eq!(completed_by.as_deref(), Some("reactor-process-after-crash"));

    let stale_completion = second_ledger
        .complete_job(
            tenant_id,
            original_claim.id,
            &original_claim.lease_owner,
            original_claim.fence_token,
            Some(&json!({"stale": true})),
        )
        .await
        .expect_err("superseded process fence must not complete reclaimed work");
    assert!(matches!(stale_completion, Error::Conflict(_)));

    let adopted_enqueue = second_ledger
        .enqueue_job(&restart_job)
        .await
        .expect("retry enqueue adopts the original durable job");
    assert!(!adopted_enqueue.inserted);
    assert_eq!(adopted_enqueue.job_id, restart_job.id);
    let duplicate_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_jobs WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant_id)
    .bind(&restart_job.idempotency_key)
    .fetch_one(second_ledger.pool())
    .await
    .expect("count idempotent restart jobs");
    assert_eq!(duplicate_rows, 1);

    drop(replacement);
    second_ledger.close().await;
    let third_ledger = PgLedger::connect(&database_url)
        .await
        .expect("connect another replacement process");
    let after_completion_restart = ReactorRuntime::new(
        third_ledger.clone(),
        tenant_id,
        restart_registry,
        options("reactor-process-after-completion"),
        false,
    )
    .expect("construct post-completion reactor");
    assert_eq!(
        after_completion_restart
            .poll_once()
            .await
            .expect("poll after completed-job restart"),
        ReactorPollReport::default()
    );
    assert_eq!(restart_handler.logical_effects(), 1);
    assert_eq!(restart_handler.invocations(), 2);

    let unknown = job(
        tenant_id,
        UNKNOWN_JOB,
        format!("unknown-fail-closed:{tenant_id}"),
    );
    third_ledger
        .enqueue_job(&unknown)
        .await
        .expect("enqueue unknown job type");
    let unknown_error = after_completion_restart
        .poll_once()
        .await
        .expect_err("unknown due job type must fail the poll closed");
    assert!(matches!(unknown_error, Error::Validation(_)));
    let (unknown_status, unknown_attempts, unknown_owner): (String, i32, Option<String>) =
        sqlx::query_as(
            "SELECT status, attempt_count, lease_owner FROM workflow_jobs \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(unknown.id)
        .fetch_one(third_ledger.pool())
        .await
        .expect("load unknown job after rejected poll");
    assert_eq!(unknown_status, "PENDING");
    assert_eq!(unknown_attempts, 0);
    assert!(unknown_owner.is_none());
    sqlx::query(
        "UPDATE workflow_jobs SET available_at = clock_timestamp() + interval '1 day', \
         updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(unknown.id)
    .execute(third_ledger.pool())
    .await
    .expect("defer isolated unknown test job outside this poll window");

    let dispatch = Arc::new(ProbeHandler::new(
        ADVANCE_ACCEPTED_WORK_ITEM,
        ProbeKind::NewDispatch,
    ));
    let observation = Arc::new(ProbeHandler::new(
        MAINTENANCE_OBSERVATION_JOB,
        ProbeKind::Observation,
    ));
    let recovery_worker_id = WorkerId::new();
    let recovery = Arc::new(ProbeHandler::reconcile(recovery_worker_id));
    let mut recovery_job = job(
        tenant_id,
        RECONCILE_WORKER,
        format!("maintenance-recovery:{tenant_id}"),
    );
    recovery_job.payload = json!({"worker_id": recovery_worker_id});
    let maintenance_jobs = [
        job(
            tenant_id,
            ADVANCE_ACCEPTED_WORK_ITEM,
            format!("maintenance-dispatch:{tenant_id}"),
        ),
        job(
            tenant_id,
            MAINTENANCE_OBSERVATION_JOB,
            format!("maintenance-observation:{tenant_id}"),
        ),
        recovery_job,
    ];
    for maintenance_job in &maintenance_jobs {
        third_ledger
            .enqueue_job(maintenance_job)
            .await
            .expect("enqueue maintenance-mode test job");
    }
    let maintenance_reactor = ReactorRuntime::new(
        third_ledger.clone(),
        tenant_id,
        registry(&[dispatch.clone(), observation.clone(), recovery.clone()]),
        options("reactor-maintenance"),
        true,
    )
    .expect("construct maintenance reactor");
    let maintenance_report = maintenance_reactor
        .poll_once()
        .await
        .expect("maintenance poll retains observation and recovery");
    assert_eq!(maintenance_report.jobs_claimed, 3);
    assert_eq!(maintenance_report.jobs_completed, 2);
    assert_eq!(maintenance_report.jobs_retried, 1);
    assert_eq!(dispatch.invocations(), 1);
    assert_eq!(dispatch.logical_effects(), 0);
    assert!(dispatch.saw_maintenance());
    assert_eq!(observation.logical_effects(), 1);
    assert!(observation.saw_maintenance());
    assert_eq!(recovery.logical_effects(), 1);
    assert!(recovery.saw_maintenance());

    let dispatch_state: (String, Option<String>) = sqlx::query_as(
        "SELECT status, last_error FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(maintenance_jobs[0].id)
    .fetch_one(third_ledger.pool())
    .await
    .expect("load maintenance-suppressed dispatch job");
    assert_eq!(dispatch_state.0, "RETRY");
    assert!(
        dispatch_state
            .1
            .as_deref()
            .is_some_and(|error| error.contains("new dispatch is disabled by maintenance mode"))
    );
    for completed_job in &maintenance_jobs[1..] {
        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(completed_job.id)
                .fetch_one(third_ledger.pool())
                .await
                .expect("load maintenance-allowed job");
        assert_eq!(status, "COMPLETED");
    }

    // Workflow jobs are durable receipts and cannot be deleted. This test uses
    // a unique tenant, so closing the ledger is its isolation boundary.
    third_ledger.close().await;
}
