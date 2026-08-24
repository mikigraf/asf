//! Live upgrade regression for migration 0023's activity-contract backfill.
//!
//! Migration 0017 installed `workflow_jobs_note_dispatch_fact_mutation` and
//! `workflow_timers_note_dispatch_fact_mutation` as BEFORE UPDATE/DELETE
//! triggers that mark a work item's `work_dispatch_fact_guards` row
//! `dispatch_started = true` on any ordinary UPDATE. Migration 0023's
//! blanket `UPDATE ... SET activity_contract_id = ...` backfills must not
//! be allowed to trip that guard for historical, still pre-dispatch,
//! accepted work. This test upgrades an isolated schema from 0022 to 0023
//! with exactly such a pre-dispatch fixture in place and proves the guard
//! survives, the two named triggers are disabled only for the backfill, and
//! ordinary mutations are observed normally again immediately afterward.
//!
//! `workflow_jobs` and `workflow_timers` also carry several other
//! DEFERRABLE INITIALLY DEFERRED constraint triggers from migrations 0001,
//! 0013, 0014, and 0017 (e.g. `workflow_jobs_preserve_cancellation_receipt`)
//! that the blanket backfill UPDATEs queue a pending event for on every row,
//! independent of the two dispatch-fact triggers above. `PostgreSQL` 55006
//! ("cannot ALTER TABLE because it has pending trigger events") rejects
//! `ALTER TABLE ... ENABLE TRIGGER` while those events remain queued, so
//! 0023 drains them with `SET CONSTRAINTS ALL IMMEDIATE` and restores
//! `DEFERRED` before re-enabling the dispatch-fact triggers. This fixture's
//! seeded `workflow_jobs`/`workflow_timers` rows exercise exactly that
//! drain: applying 0023 below fails with 55006 if it regresses.

use std::env::VarError;

use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

use asf::{
    ledger::PgLedger,
    runtime::{
        ADVANCE_ACCEPTED_WORK_ITEM, ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID, CLOSE_SOURCE,
        CLOSE_SOURCE_ACTIVITY_CONTRACT_ID, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID,
        REQUEST_WORK_ITEM_CANCELLATION, REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
    },
};

fn test_database_url() -> Option<String> {
    match std::env::var("ASF_TEST_DATABASE_URL") {
        Ok(database_url) => {
            assert!(
                !database_url.trim().is_empty(),
                "ASF_TEST_DATABASE_URL is present but empty"
            );
            Some(database_url)
        }
        Err(VarError::NotPresent) if std::env::var_os("CI").is_some() => {
            panic!("CI must configure ASF_TEST_DATABASE_URL");
        }
        Err(VarError::NotPresent) => None,
        Err(error) => panic!("read ASF_TEST_DATABASE_URL: {error}"),
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create_through_0022_if_configured() -> Option<Self> {
        let database_url = test_database_url()?;
        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect activity-contract test administrator");
        let schema = format!("asf_activity_contract_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated activity-contract schema");

        let mut scoped_url = Url::parse(&database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated activity-contract ledger");

        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin migrations through 0022");
        for migration in [
            include_str!("../migrations/0001_initial.sql"),
            include_str!("../migrations/0002_operational_incident_lifecycle.sql"),
            include_str!("../migrations/0003_work_attempt_bindings_and_shared_escalations.sql"),
            include_str!("../migrations/0004_reservation_internal_event_guard.sql"),
            include_str!("../migrations/0005_effect_intent_exact_job_ownership.sql"),
            include_str!("../migrations/0006_cross_binding_and_terminal_guards.sql"),
            include_str!("../migrations/0007_operational_incident_reciprocal_proofs.sql"),
            include_str!("../migrations/0008_runmill_submission_effect_ownership.sql"),
            include_str!("../migrations/0009_linear_source_closure_ownership.sql"),
            include_str!("../migrations/0010_reservation_worker_session_fencing.sql"),
            include_str!("../migrations/0011_worker_session_signing_authority.sql"),
            include_str!(
                "../migrations/0012_worker_authority_lifetime_and_closure_preservation.sql"
            ),
            include_str!("../migrations/0013_source_closure_terminal_invariants.sql"),
            include_str!("../migrations/0014_evidence_verification_job_ownership.sql"),
            include_str!("../migrations/0015_verified_evidence_artifact_integrity.sql"),
            include_str!("../migrations/0016_evidence_verification_receipt_integrity.sql"),
            include_str!("../migrations/0017_cancellation_receipt_integrity.sql"),
            include_str!("../migrations/0018_cancellation_escalation_supersession.sql"),
            include_str!("../migrations/0019_shared_work_finality_gate.sql"),
            include_str!("../migrations/0020_v1_single_tenant_boundary.sql"),
            include_str!("../migrations/0021_runmill_run_observation_provenance.sql"),
            include_str!("../migrations/0022_runmill_observation_streams.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&mut *transaction)
                .await
                .expect("apply migration through 0022");
        }
        transaction
            .commit()
            .await
            .expect("commit migrations through 0022");

        Some(Self {
            ledger,
            admin,
            schema,
        })
    }

    async fn apply_0023(&self) {
        let mut transaction = self
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin 0023 activity-contract upgrade");
        sqlx::raw_sql(include_str!(
            "../migrations/0023_workflow_activity_contracts.sql"
        ))
        .execute(&mut *transaction)
        .await
        .expect("apply 0023 activity-contract backfill");
        transaction
            .commit()
            .await
            .expect("commit 0023 activity-contract upgrade");
    }

    /// Apply 0024, asserting it commits. Callers that must observe a refused
    /// upgrade use [`Self::apply_0024_result`] instead.
    async fn apply_0024(&self) {
        self.apply_0024_result()
            .await
            .expect("apply 0024 activity contract authority proofs");
    }

    /// Apply 0024 in its own transaction, committing on success and rolling
    /// back on failure so a refused upgrade (poisoned-history preflight)
    /// leaves the connection usable for further assertions instead of stuck
    /// in an aborted transaction.
    async fn apply_0024_result(&self) -> Result<(), sqlx::Error> {
        let mut transaction = self
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin 0024 activity-contract authority-proof upgrade");
        match sqlx::raw_sql(include_str!(
            "../migrations/0024_activity_contract_authority_proofs.sql"
        ))
        .execute(&mut *transaction)
        .await
        {
            Ok(_) => {
                transaction.commit().await?;
                Ok(())
            }
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .expect("roll back refused 0024 activity-contract authority-proof upgrade");
                Err(error)
            }
        }
    }

    async fn cleanup(self) {
        self.ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop isolated activity-contract schema");
        self.admin.close().await;
    }
}

/// An accepted work item, still pre-dispatch, with exactly the baseline
/// `ADVANCE_ACCEPTED_WORK_ITEM` acceptance job migration 0017 exempts from
/// counting as a dispatch fact, plus a tenant-scoped timer with no work
/// binding at all. A work-bound timer would itself necessarily count as
/// dispatch under 0017 (`asf_note_work_dispatch_fact` has no pristine
/// exemption for `workflow_timers`), so it is intentionally omitted here.
struct PreDispatchFixture {
    tenant: Uuid,
    work_item: Uuid,
    workflow: Uuid,
    job: Uuid,
    timer: Uuid,
}

async fn seed_pre_dispatch_fixture(ledger: &PgLedger) -> PreDispatchFixture {
    seed_pre_dispatch_fixture_with_baseline_job(ledger, true).await
}

/// Seeds the same workflow/guard/timer setup as [`seed_pre_dispatch_fixture`],
/// through migration 0022, optionally omitting the baseline pristine
/// `ADVANCE_ACCEPTED_WORK_ITEM` job insert so a caller can insert its own
/// first job for this work item under a later schema instead. The returned
/// coordinates (including the predetermined job id) are identical either
/// way.
///
/// When `include_baseline_job` is `false`, the work item is seeded
/// `DISCOVERED` with `accepted_at` left `NULL` and no `WORKFLOW`
/// accountability anchor, since accepting the work here with no live job or
/// timer bound to it would leave the anchor non-live and the deferred
/// `asf_assert_accountability_anchor` constraint would refuse to commit.
/// The delivery workflow, dispatch-fact guard, and predetermined `job` id
/// are still established so a caller can accept the work item and insert
/// its own first job atomically under a later schema.
async fn seed_pre_dispatch_fixture_with_baseline_job(
    ledger: &PgLedger,
    include_baseline_job: bool,
) -> PreDispatchFixture {
    let tenant = Uuid::now_v7();
    let repository_id = Uuid::now_v7();
    let snapshot_id = Uuid::now_v7();
    let policy_id = Uuid::now_v7();
    let work_item = Uuid::now_v7();
    let workflow_id = Uuid::now_v7();
    let job = Uuid::now_v7();
    let timer = Uuid::now_v7();
    let policy_digest = digest('1');
    let source_digest = digest('2');
    let now = Utc::now();

    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin pre-dispatch fixture");

    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant)
        .bind(format!("activity-contract-{tenant}"))
        .bind("Activity contract backfill test")
        .execute(&mut *transaction)
        .await
        .expect("insert tenant");
    sqlx::query(
        r"
        INSERT INTO policy_versions (
            id, tenant_id, scope, schema_version, digest, canonical_bytes,
            policy, created_by
        ) VALUES ($1, $2, 'TENANT', 'v1', $3, '{}'::bytea, '{}'::jsonb, 'test')
        ",
    )
    .bind(policy_id)
    .bind(tenant)
    .bind(&policy_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert policy");
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, owner, name, repository_url, default_branch
        ) VALUES ($1, $2, 'acme', $3, $4, 'main')
        ",
    )
    .bind(repository_id)
    .bind(tenant)
    .bind(format!("repo-{}", repository_id.simple()))
    .bind(format!("https://example.invalid/{repository_id}"))
    .execute(&mut *transaction)
    .await
    .expect("insert repository");
    sqlx::query(
        r"
        INSERT INTO source_snapshots (
            id, tenant_id, repository_id, source_system, external_id,
            source_revision, normalized_content, content_digest,
            connector_identity, source_updated_at
        ) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', $6)
        ",
    )
    .bind(snapshot_id)
    .bind(tenant)
    .bind(repository_id)
    .bind(format!("item-{work_item}"))
    .bind(&source_digest)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .expect("insert source snapshot");
    let work_item_insert = if include_baseline_job {
        r"
        INSERT INTO work_items (
            id, tenant_id, source_snapshot_id, source_system,
            source_external_id, repository_id, state, closure_target,
            risk_class, policy_digest, budget_limits,
            identity_requirements, owner_fallback, normalized_priority,
            accepted_at
        ) VALUES (
            $1, $2, $3, 'API', $4, $5, 'ACCEPTED', 'pull_request',
            'low', $6, $7, $8, 'team:platform', 50, clock_timestamp()
        )
        "
    } else {
        // No accountability anchor is seeded below for this variant, so the
        // work item must stay pre-acceptance (accepted_at NULL) or the
        // deferred `asf_assert_accountability_anchor` constraint would
        // refuse to commit this transaction for lack of one.
        r"
        INSERT INTO work_items (
            id, tenant_id, source_snapshot_id, source_system,
            source_external_id, repository_id, state, closure_target,
            risk_class, policy_digest, budget_limits,
            identity_requirements, owner_fallback, normalized_priority,
            accepted_at
        ) VALUES (
            $1, $2, $3, 'API', $4, $5, 'DISCOVERED', 'pull_request',
            'low', $6, $7, $8, 'team:platform', 50, NULL
        )
        "
    };
    sqlx::query(work_item_insert)
        .bind(work_item)
        .bind(tenant)
        .bind(snapshot_id)
        .bind(format!("item-{work_item}"))
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(json!({
            "max_cost_microunits": 1_000_000,
            "max_input_tokens": 100_000,
            "max_output_tokens": 100_000,
            "max_implementer_invocations": 2,
            "max_reviewer_invocations": 2,
            "max_fix_iterations": 1,
            "max_wall_time_seconds": 3_600,
            "max_external_api_calls": 10
        }))
        .bind(json!({
            "implementer": "codex:implementer",
            "local_reviewer": "claude:local-reviewer",
            "pr_reviewer": "claude:pr-reviewer"
        }))
        .execute(&mut *transaction)
        .await
        .expect(if include_baseline_job {
            "insert accepted, still pre-dispatch, work item"
        } else {
            "insert discovered, not-yet-accepted, work item"
        });
    sqlx::query(
        r"
        INSERT INTO workflow_instances (
            id, tenant_id, work_item_id, workflow_type, reducer_version
        ) VALUES ($1, $2, $3, 'WORK_ITEM_DELIVERY', 'asf.workflow/v1')
        ",
    )
    .bind(workflow_id)
    .bind(tenant)
    .bind(work_item)
    .execute(&mut *transaction)
    .await
    .expect("insert delivery workflow instance");
    // Omitted when `include_baseline_job` is false: with no live job or
    // timer bound to the delivery workflow yet, a WORKFLOW anchor here would
    // be non-live and the deferred `asf_assert_accountability_anchor`
    // constraint would refuse to commit. The work item stays unaccepted
    // (accepted_at NULL) above instead, which requires no anchor at all.
    if include_baseline_job {
        sqlx::query(
            r"
            INSERT INTO accountability_anchors (
                tenant_id, work_item_id, anchor_type, reference_id, generation
            ) VALUES ($1, $2, 'WORKFLOW', $3, 1)
            ",
        )
        .bind(tenant)
        .bind(work_item)
        .bind(workflow_id)
        .execute(&mut *transaction)
        .await
        .expect("insert accountability anchor");
    }
    // The exact pre-dispatch baseline shape migration 0017's
    // `asf_note_work_dispatch_fact` exempts on INSERT: attempt_id NULL,
    // status PENDING, non-exhausted, no lease/result/completion, bound to
    // the fresh WORK_ITEM_DELIVERY workflow, and the only workflow job for
    // this work item.
    if include_baseline_job {
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, job_type,
                payload, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, 'ADVANCE_ACCEPTED_WORK_ITEM', '{}'::jsonb, $5
            )
            ",
        )
        .bind(job)
        .bind(tenant)
        .bind(workflow_id)
        .bind(work_item)
        .bind(format!("advance-accepted-{job}"))
        .execute(&mut *transaction)
        .await
        .expect("insert baseline pre-dispatch acceptance job");
    }
    // A legitimate tenant-scoped timer with no work binding at all (e.g. a
    // periodic worker-reconciliation sweep). `work_item_id IS NULL` means
    // `asf_note_work_dispatch_fact` never touches any dispatch guard for it.
    sqlx::query(
        r"
        INSERT INTO workflow_timers (
            id, tenant_id, workflow_key, timer_key, timer_type, due_at
        ) VALUES ($1, $2, $3, 'sweep', 'RECONCILE_WORKER', $4)
        ",
    )
    .bind(timer)
    .bind(tenant)
    .bind(format!("tenant-reconcile:{tenant}"))
    .bind(now + chrono::Duration::hours(1))
    .execute(&mut *transaction)
    .await
    .expect("insert unscoped tenant-level timer");

    transaction
        .commit()
        .await
        .expect("commit pre-dispatch fixture");

    PreDispatchFixture {
        tenant,
        work_item,
        workflow: workflow_id,
        job,
        timer,
    }
}

async fn load_guard(pool: &PgPool, tenant_id: Uuid, work_item_id: Uuid) -> (bool, i64) {
    let guard: (bool, i64) = sqlx::query_as(
        "SELECT dispatch_started, generation FROM work_dispatch_fact_guards \
         WHERE tenant_id = $1 AND work_item_id = $2",
    )
    .bind(tenant_id)
    .bind(work_item_id)
    .fetch_one(pool)
    .await
    .expect("load work dispatch-fact guard");
    guard
}

async fn trigger_enabled(pool: &PgPool, table: &str, trigger: &str) -> bool {
    let status: String = sqlx::query_scalar(
        r"
        SELECT tgenabled::text
        FROM pg_trigger
        JOIN pg_class ON pg_class.oid = pg_trigger.tgrelid
        WHERE pg_class.relname = $1
          AND pg_class.relnamespace = (
              SELECT oid FROM pg_namespace WHERE nspname = current_schema()
          )
          AND pg_trigger.tgname = $2
        ",
    )
    .bind(table)
    .bind(trigger)
    .fetch_one(pool)
    .await
    .expect("load trigger enabled status");
    status == "O"
}

#[tokio::test]
async fn activity_contract_backfill_preserves_pre_dispatch_guard_and_reenables_mutation_triggers() {
    let Some(database) = ScopedDatabase::create_through_0022_if_configured().await else {
        return;
    };
    let fixture = seed_pre_dispatch_fixture(&database.ledger).await;

    let (before_dispatch_started, before_generation) =
        load_guard(database.ledger.pool(), fixture.tenant, fixture.work_item).await;
    assert!(
        !before_dispatch_started,
        "fixture must start pre-dispatch before the 0023 upgrade"
    );
    assert_eq!(before_generation, 1);

    database.apply_0023().await;

    let job_contract: String = sqlx::query_scalar(
        "SELECT activity_contract_id FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant)
    .bind(fixture.job)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load backfilled job activity contract id");
    assert_eq!(
        job_contract,
        ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
    );

    let timer_contract: String = sqlx::query_scalar(
        "SELECT activity_contract_id FROM workflow_timers WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant)
    .bind(fixture.timer)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load backfilled timer activity contract id");
    assert_eq!(timer_contract, RECONCILE_WORKER_ACTIVITY_CONTRACT_ID);

    let (after_dispatch_started, after_generation) =
        load_guard(database.ledger.pool(), fixture.tenant, fixture.work_item).await;
    assert!(
        !after_dispatch_started,
        "the 0023 backfill must not fabricate a dispatch fact for historical pre-dispatch work"
    );
    assert_eq!(
        after_generation, before_generation,
        "the 0023 backfill must not advance the dispatch-fact guard generation"
    );

    for (table, trigger) in [
        ("workflow_jobs", "workflow_jobs_note_dispatch_fact_mutation"),
        (
            "workflow_timers",
            "workflow_timers_note_dispatch_fact_mutation",
        ),
    ] {
        assert!(
            trigger_enabled(database.ledger.pool(), table, trigger).await,
            "{trigger} must be re-enabled once the 0023 backfill has committed"
        );
    }

    // Prove the re-enabled trigger still does its job: an ordinary dispatch
    // claim (the same shape ReactorRuntime uses to move an
    // ADVANCE_ACCEPTED_WORK_ITEM job from PENDING to RUNNING) must still
    // mark the work item as dispatched.
    sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'RUNNING',
            attempt_count = attempt_count + 1,
            fence_token = fence_token + 1,
            lease_owner = $3,
            lease_expires_at = clock_timestamp() + interval '5 minutes',
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant)
    .bind(fixture.job)
    .bind("reactor:activity-contract-backfill-test")
    .execute(database.ledger.pool())
    .await
    .expect("ordinary post-upgrade dispatch claim must still succeed");

    let (dispatched_started, dispatched_generation) =
        load_guard(database.ledger.pool(), fixture.tenant, fixture.work_item).await;
    assert!(
        dispatched_started,
        "a genuine post-upgrade dispatch claim must still mark the guard dispatched"
    );
    assert_eq!(dispatched_generation, before_generation + 1);

    // activity_contract_id remains immutable, on both the now-dispatched job
    // and the still-scheduled timer.
    let job_rejection = sqlx::query(
        "UPDATE workflow_jobs SET activity_contract_id = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant)
    .bind(fixture.job)
    .bind("asf.activity/forbidden/v1")
    .execute(database.ledger.pool())
    .await
    .expect_err("changing a job's activity_contract_id must be rejected");
    assert_eq!(
        job_rejection
            .as_database_error()
            .map(|error| error.message().to_owned()),
        Some("workflow job identity and request fields are immutable".to_owned())
    );

    let timer_rejection = sqlx::query(
        "UPDATE workflow_timers SET activity_contract_id = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant)
    .bind(fixture.timer)
    .bind("asf.activity/forbidden/v1")
    .execute(database.ledger.pool())
    .await
    .expect_err("changing a timer's activity_contract_id must be rejected");
    assert_eq!(
        timer_rejection
            .as_database_error()
            .map(|error| error.message().to_owned()),
        Some("workflow timer identity and request fields are immutable".to_owned())
    );

    let unchanged_job_contract: String = sqlx::query_scalar(
        "SELECT activity_contract_id FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant)
    .bind(fixture.job)
    .fetch_one(database.ledger.pool())
    .await
    .expect("reload unchanged job activity contract id");
    assert_eq!(
        unchanged_job_contract,
        ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
    );

    database.cleanup().await;
}

async fn insert_bare_tenant(pool: &PgPool) -> Uuid {
    let tenant = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant)
        .bind(format!("activity-contract-authority-proof-{tenant}"))
        .bind("Activity contract authority proof test")
        .execute(pool)
        .await
        .expect("insert bare tenant");
    tenant
}

/// Insert a workflow job with no work/workflow/attempt binding at all, so no
/// dispatch-fact, cancellation-authority, or source-closure trigger on
/// `workflow_jobs` does anything with it -- it is a fully isolated queue row
/// from birth.
async fn insert_unbound_job(
    pool: &PgPool,
    tenant: Uuid,
    job_type: &str,
    activity_contract_id: &str,
    status: &str,
) -> Uuid {
    let job = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, job_type, activity_contract_id, status, payload,
            idempotency_key
        ) VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6)
        ",
    )
    .bind(job)
    .bind(tenant)
    .bind(job_type)
    .bind(activity_contract_id)
    .bind(status)
    .bind(format!("unbound-{job_type}-{job}"))
    .execute(pool)
    .await
    .expect("insert unbound workflow job");
    job
}

async fn load_job_contract_and_status(pool: &PgPool, tenant: Uuid, job: Uuid) -> (String, String) {
    sqlx::query_as(
        "SELECT activity_contract_id, status FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant)
    .bind(job)
    .fetch_one(pool)
    .await
    .expect("load job activity contract id and status")
}

async fn function_definition(pool: &PgPool, function_name: &str) -> String {
    sqlx::query_scalar("SELECT pg_get_functiondef($1::regprocedure)")
        .bind(format!("{function_name}()"))
        .fetch_one(pool)
        .await
        .expect("load function definition")
}

/// Migration 0023's history upgrades cleanly through 0024: the canonical
/// pre-dispatch fixture used by the 0022-to-0023 test above carries only
/// production job types whose `activity_contract_id` already matches their
/// canonical contract, so it has no poisoned history for 0024's preflight to
/// refuse, and every hardened function gains its exact contract predicate.
#[tokio::test]
async fn canonical_0023_history_upgrades_through_0024() {
    let Some(database) = ScopedDatabase::create_through_0022_if_configured().await else {
        return;
    };
    seed_pre_dispatch_fixture(&database.ledger).await;

    database.apply_0023().await;
    database.apply_0024().await;

    let hardened =
        function_definition(database.ledger.pool(), "asf_stamp_runmill_control_snapshot").await;
    assert!(
        hardened.contains("asf.activity/observe-runmill-run/v2"),
        "the hardened OBSERVE_RUNMILL_RUN control-snapshot function must require the exact \
         observer-v2 activity_contract_id predicate"
    );

    database.cleanup().await;
}

/// An isolated PENDING or RETRY job with a wrong `activity_contract_id` and
/// no durable proof root (no owned effect intent, no observation, no
/// receipt, no result chain) is not rooted in poisoned history. 0024's
/// preflight is scan-only and never inspects `job.status`, so these rows
/// must be left completely alone by the upgrade.
#[tokio::test]
async fn isolated_incompatible_pending_and_retry_jobs_do_not_block_0024() {
    let Some(database) = ScopedDatabase::create_through_0022_if_configured().await else {
        return;
    };
    database.apply_0023().await;

    let tenant = insert_bare_tenant(database.ledger.pool()).await;
    let pending_job = insert_unbound_job(
        database.ledger.pool(),
        tenant,
        ADVANCE_ACCEPTED_WORK_ITEM,
        CLOSE_SOURCE_ACTIVITY_CONTRACT_ID,
        "PENDING",
    )
    .await;
    let retry_job = insert_unbound_job(
        database.ledger.pool(),
        tenant,
        CLOSE_SOURCE,
        REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID,
        "RETRY",
    )
    .await;

    database.apply_0024().await;

    let (pending_contract, pending_status) =
        load_job_contract_and_status(database.ledger.pool(), tenant, pending_job).await;
    assert_eq!(pending_contract, CLOSE_SOURCE_ACTIVITY_CONTRACT_ID);
    assert_eq!(pending_status, "PENDING");

    let (retry_contract, retry_status) =
        load_job_contract_and_status(database.ledger.pool(), tenant, retry_job).await;
    assert_eq!(
        retry_contract,
        REQUEST_WORK_ITEM_CANCELLATION_ACTIVITY_CONTRACT_ID
    );
    assert_eq!(retry_status, "RETRY");

    database.cleanup().await;
}

/// A wrong-contract `REQUEST_WORK_ITEM_CANCELLATION` job whose durable
/// `result` names a child `observation_job` is rooted in poisoned history:
/// the pre-0024 schema already accepted that reference as authority proof,
/// so 0024 must refuse to install the hardened predicate over it rather than
/// silently paper over the wrong identity. The refusal must roll the whole
/// upgrade back -- no function is partially replaced.
#[tokio::test]
async fn poisoned_historical_authority_proof_refuses_0024_and_rolls_back() {
    let Some(database) = ScopedDatabase::create_through_0022_if_configured().await else {
        return;
    };
    database.apply_0023().await;

    let tenant = insert_bare_tenant(database.ledger.pool()).await;
    let poisoned_job = Uuid::now_v7();
    let observation_job = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, job_type, activity_contract_id, status, payload,
            result, idempotency_key, completed_by, fence_token,
            completion_fence_token, completed_at
        ) VALUES (
            $1, $2, $3, $4, 'COMPLETED', '{}'::jsonb, $5, $6,
            'test:poisoned-history', 1, 1, clock_timestamp()
        )
        ",
    )
    .bind(poisoned_job)
    .bind(tenant)
    .bind(REQUEST_WORK_ITEM_CANCELLATION)
    // Wrong contract identity for a REQUEST_WORK_ITEM_CANCELLATION job: any
    // canonical literal other than its own is grammar-valid but poisoned.
    .bind(CLOSE_SOURCE_ACTIVITY_CONTRACT_ID)
    .bind(json!({
        "result": {
            "observation_job": {
                "id": observation_job,
            }
        }
    }))
    .bind(format!("poisoned-history-{poisoned_job}"))
    .execute(database.ledger.pool())
    .await
    .expect("insert wrong-contract job with a durable observation_job result reference");

    let refusal = database
        .apply_0024_result()
        .await
        .expect_err("0024 must refuse to upgrade over poisoned history");
    let database_error = refusal
        .as_database_error()
        .expect("poisoned-history refusal must be a PostgreSQL error");
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(
        database_error.constraint(),
        Some("activity_contract_authority_proof_upgrade_preflight")
    );

    // No partial replacement: an early 0024 target function still has its
    // pre-0024 body, with no activity_contract_id predicate at all.
    let unreplaced = function_definition(
        database.ledger.pool(),
        "asf_assert_runmill_observation_gap_escalation_binding_insert",
    )
    .await;
    assert!(
        !unreplaced.contains("activity_contract_id"),
        "a refused 0024 upgrade must not have partially replaced any function"
    );

    let (unchanged_contract, unchanged_status) =
        load_job_contract_and_status(database.ledger.pool(), tenant, poisoned_job).await;
    assert_eq!(unchanged_contract, CLOSE_SOURCE_ACTIVITY_CONTRACT_ID);
    assert_eq!(unchanged_status, "COMPLETED");

    database.cleanup().await;
}

/// Migration 0024 narrows both the pristine `ADVANCE_ACCEPTED_WORK_ITEM`
/// insert exception in `asf_note_work_dispatch_fact` and its terminalization
/// counterpart in `asf_note_work_dispatch_fact_mutation` /
/// `asf_guard_cancellation_job_terminal_transition` to require the exact
/// `asf.activity/advance-accepted-work-item/v1` contract identity, not
/// merely the job's row shape. A job born after 0024 with a grammar-valid
/// but wrong contract identity (e.g. `.../v2`) can therefore ride neither
/// pristine exception: its birth INSERT, as the first job for its work item,
/// must mark the dispatch-fact guard dispatched immediately, and a later
/// otherwise-canonical PENDING->CANCELLED pre-dispatch cancellation on it
/// must be refused rather than silently exempted. A canonical control
/// fixture (correct contract, seeded through the ordinary wrapper with its
/// baseline job) is upgraded alongside to prove the narrowing is isolated to
/// contract identity rather than a regression of the pristine exception
/// itself.
#[tokio::test]
async fn wrong_contract_advance_job_born_after_0024_forfeits_pre_dispatch_exception() {
    // Born after 0023/0024: the exact pristine ADVANCE_ACCEPTED_WORK_ITEM
    // row/payload/idempotency shape from the fixture, as the first
    // workflow_jobs row for this work item, but a grammar-valid wrong
    // activity_contract_id. activity_contract_id is never updated below.
    const WRONG_CONTRACT: &str = "asf.activity/advance-accepted-work-item/v2";

    let Some(database) = ScopedDatabase::create_through_0022_if_configured().await else {
        return;
    };

    let control = seed_pre_dispatch_fixture(&database.ledger).await;
    let broken = seed_pre_dispatch_fixture_with_baseline_job(&database.ledger, false).await;

    database.apply_0023().await;
    database.apply_0024().await;

    let (control_dispatch_started, _) =
        load_guard(database.ledger.pool(), control.tenant, control.work_item).await;
    assert!(
        !control_dispatch_started,
        "the canonical control fixture's pristine ADVANCE job must remain exempt after 0024"
    );

    let (before_dispatch_started, before_generation) =
        load_guard(database.ledger.pool(), broken.tenant, broken.work_item).await;
    assert!(
        !before_dispatch_started,
        "the broken fixture's work item must still be pre-dispatch before its wrong-contract job \
         is born"
    );

    // The broken fixture was seeded DISCOVERED with no accountability
    // anchor, since no live job or timer existed yet to keep one live. Walk
    // it through its ordinary acceptance transitions, plant its WORKFLOW
    // anchor, and give birth to the wrong-contract job -- all in one
    // transaction -- so that when it commits, deferred accountability sees
    // the new job as a live child of the anchor instead of ever observing
    // the work item accepted with no live progress at all.
    let mut acceptance = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin broken work item acceptance and wrong-contract job birth");
    for target_state in ["READINESS_PENDING", "READY"] {
        sqlx::query(
            r"
            UPDATE work_items
            SET state = $3,
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(broken.tenant)
        .bind(broken.work_item)
        .bind(target_state)
        .execute(&mut *acceptance)
        .await
        .unwrap_or_else(|error| panic!("advance broken work item to {target_state}: {error}"));
    }
    sqlx::query(
        r"
        UPDATE work_items
        SET state = 'ACCEPTED',
            accepted_at = clock_timestamp(),
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(broken.tenant)
    .bind(broken.work_item)
    .execute(&mut *acceptance)
    .await
    .expect("accept broken work item");
    sqlx::query(
        r"
        INSERT INTO accountability_anchors (
            tenant_id, work_item_id, anchor_type, reference_id, generation
        ) VALUES ($1, $2, 'WORKFLOW', $3, 1)
        ",
    )
    .bind(broken.tenant)
    .bind(broken.work_item)
    .bind(broken.workflow)
    .execute(&mut *acceptance)
    .await
    .expect("insert broken work item's accountability anchor");
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, job_type,
            activity_contract_id, payload, idempotency_key
        ) VALUES (
            $1, $2, $3, $4, 'ADVANCE_ACCEPTED_WORK_ITEM', $5, '{}'::jsonb, $6
        )
        ",
    )
    .bind(broken.job)
    .bind(broken.tenant)
    .bind(broken.workflow)
    .bind(broken.work_item)
    .bind(WRONG_CONTRACT)
    .bind(format!("advance-accepted-{}", broken.job))
    .execute(&mut *acceptance)
    .await
    .expect("insert pristine-shaped, wrong-contract advance job");
    acceptance
        .commit()
        .await
        .expect("commit broken work item acceptance and wrong-contract job birth");

    let (after_insert_dispatch_started, after_insert_generation) =
        load_guard(database.ledger.pool(), broken.tenant, broken.work_item).await;
    assert!(
        after_insert_dispatch_started,
        "a wrong-contract ADVANCE_ACCEPTED_WORK_ITEM insert must not take the narrowed pristine \
         exception"
    );
    assert_eq!(after_insert_generation, before_generation + 1);

    // An otherwise canonical PENDING->CANCELLED pre-dispatch cancellation:
    // fence_token advances by exactly one, the result is the exact
    // asf.pre-dispatch-cancellation-result/v1 shape with the correct
    // work_item_id and a non-null terminal_receipt_id, and every
    // lease/completion column stays null. activity_contract_id is untouched.
    let terminal_receipt_id = Uuid::now_v7();
    let cancellation_update = sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'CANCELLED',
            fence_token = fence_token + 1,
            result = $3,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(broken.tenant)
    .bind(broken.job)
    .bind(json!({
        "schema": "asf.pre-dispatch-cancellation-result/v1",
        "disposition": "cancelled_before_dispatch",
        "work_item_id": broken.work_item.to_string(),
        "terminal_receipt_id": terminal_receipt_id,
    }))
    .execute(database.ledger.pool())
    .await
    .expect_err(
        "an otherwise canonical pre-dispatch cancellation of a wrong-contract job must be refused",
    );

    let database_error = cancellation_update
        .as_database_error()
        .expect("pre-dispatch cancellation refusal must be a PostgreSQL error");
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(
        database_error.constraint(),
        Some("workflow_jobs_exact_pre_dispatch_cancellation")
    );

    let (rolled_back_contract, rolled_back_status) =
        load_job_contract_and_status(database.ledger.pool(), broken.tenant, broken.job).await;
    assert_eq!(rolled_back_status, "PENDING");
    assert_eq!(rolled_back_contract, WRONG_CONTRACT);

    let rolled_back_fence_token: i64 = sqlx::query_scalar(
        "SELECT fence_token FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(broken.tenant)
    .bind(broken.job)
    .fetch_one(database.ledger.pool())
    .await
    .expect("reload rolled-back fence token");
    assert_eq!(rolled_back_fence_token, 0);

    let (after_rollback_dispatch_started, after_rollback_generation) =
        load_guard(database.ledger.pool(), broken.tenant, broken.work_item).await;
    assert!(
        after_rollback_dispatch_started,
        "the already-true dispatch guard must remain true after the refused statement rolls back"
    );
    assert_eq!(after_rollback_generation, after_insert_generation);

    database.cleanup().await;
}
