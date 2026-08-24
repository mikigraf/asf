use chrono::SubsecRound as _;
use std::{sync::Arc, time::Duration as StdDuration};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use asf::{
    Result,
    crypto::{canonical_json, sha256_digest},
    ledger::{
        AccountabilityReplacement, ClaimedWorkflowJob, LedgerAccountabilityKind, PgLedger,
        StepAuditEvent, WorkflowStepCommit, WorkflowStepCommitOutcome, commit_workflow_step,
    },
    runtime::{
        ADVANCE_ACCEPTED_WORK_ITEM, ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID,
        ActivityControls, ActivityOutcome, HandlerRegistry, JobHandler, ReactorOptions,
        ReactorPollReport, ReactorRuntime,
    },
};

#[derive(Debug)]
struct RetryDispatchHandler;

#[async_trait]
impl JobHandler for RetryDispatchHandler {
    fn job_type(&self) -> &str {
        ADVANCE_ACCEPTED_WORK_ITEM
    }

    fn activity_contract_id(&self) -> &str {
        ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID
    }

    async fn execute(
        &self,
        _job: &ClaimedWorkflowJob,
        _controls: ActivityControls,
    ) -> Result<ActivityOutcome> {
        Ok(ActivityOutcome::Retry {
            error: "test handler leaves the obligation claimable".into(),
            retry_at: Utc::now().trunc_subsecs(6) + Duration::minutes(1),
        })
    }
}

fn reactor(ledger: &PgLedger, tenant_id: Uuid, lease_owner: &str) -> ReactorRuntime {
    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(RetryDispatchHandler))
        .expect("register dispatch reclaim fixture");
    ReactorRuntime::new(
        ledger.clone(),
        tenant_id,
        handlers,
        ReactorOptions {
            lease_owner: lease_owner.into(),
            poll_interval: StdDuration::from_millis(10),
            lease_duration: StdDuration::from_secs(5),
            max_error_backoff: StdDuration::from_secs(1),
            claim_batch_size: 4,
        },
        false,
    )
    .expect("construct dispatch reclaim reactor")
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
            .expect("connect submission-effect test administrator");
        let schema = format!("asf_submit_effect_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated submission-effect schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated submission-effect ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated submission-effect schema");
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
            .expect("drop isolated submission-effect schema");
        self.admin.close().await;
    }

    async fn create_through_0007(database_url: &str) -> Self {
        let admin = sqlx::PgPool::connect(database_url)
            .await
            .expect("connect submission-effect upgrade administrator");
        let schema = format!("asf_submit_upgrade_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated submission-effect upgrade schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated submission-effect upgrade ledger");
        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin legacy migrations");
        for migration in [
            include_str!("../migrations/0001_initial.sql"),
            include_str!("../migrations/0002_operational_incident_lifecycle.sql"),
            include_str!("../migrations/0003_work_attempt_bindings_and_shared_escalations.sql"),
            include_str!("../migrations/0004_reservation_internal_event_guard.sql"),
            include_str!("../migrations/0005_effect_intent_exact_job_ownership.sql"),
            include_str!("../migrations/0006_cross_binding_and_terminal_guards.sql"),
            include_str!("../migrations/0007_operational_incident_reciprocal_proofs.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&mut *transaction)
                .await
                .expect("apply legacy migration");
        }
        transaction
            .commit()
            .await
            .expect("commit legacy migrations");
        Self::shim_pre_0023_activity_contract_column(&ledger).await;
        Self {
            ledger,
            admin,
            schema,
        }
    }

    /// Test-only forward-compatibility shim -- NOT a production migration and
    /// not migration 0008, which is what `migration_0008_upgrades_legacy_submission_states_and_reinstalls_terminal_guard`
    /// actually exercises. `Fixture::insert` is written against the current
    /// (post-0023) schema and unconditionally writes
    /// `workflow_jobs.activity_contract_id`, but this scoped database
    /// deliberately stops at migration 0007 so migration 0008's own upgrade
    /// behavior can be exercised against a schema that genuinely predates
    /// it. This shim adds only the minimum column shape needed to let that
    /// current fixture run at all: a bare nullable `text` column on
    /// `workflow_jobs`, with none of migration 0023's backfill, `NOT NULL`,
    /// shape `CHECK`, or trigger changes. It runs after the real legacy
    /// migrations above are committed, so it plays no part in exercising
    /// migration 0008, and migration 0008 neither reads nor writes this
    /// column (its `workflow_jobs` references are the pre-existing `id`,
    /// `tenant_id`, `work_item_id`, `attempt_id`, `job_type`, `status`,
    /// `lease_owner`, and `fence_token` columns), so its presence changes
    /// nothing about migration 0008's own behavior. `Fixture::insert` still
    /// supplies its own canonical, exact contract id -- this shim never
    /// invents or defaults one.
    async fn shim_pre_0023_activity_contract_column(ledger: &PgLedger) {
        sqlx::query("ALTER TABLE workflow_jobs ADD COLUMN activity_contract_id text")
            .execute(ledger.pool())
            .await
            .expect("apply test-only pre-0023 activity-contract column shim");
    }
}

#[derive(Debug)]
struct Fixture {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    request_digest: String,
    request_payload: serde_json::Value,
    job_id: Uuid,
    effect_id: Uuid,
    lease_owner: String,
}

impl Fixture {
    async fn insert(ledger: &PgLedger) -> Self {
        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let workflow_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let work_order_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let effect_id = Uuid::now_v7();
        let policy_digest = digest('1');
        let source_digest = digest('2');
        let lease_owner = "reactor:submission-effect-test".to_owned();
        let now = Utc::now().trunc_subsecs(6);
        let mut request_payload: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/fixtures/work-order-envelope-v1.json"
        ))
        .expect("decode Runmill Work Order fixture");
        let payload = request_payload
            .get_mut("payload")
            .and_then(serde_json::Value::as_object_mut)
            .expect("Runmill fixture payload object");
        payload.insert("work_order_id".into(), work_order_id.to_string().into());
        payload.insert("tenant_id".into(), tenant_id.to_string().into());
        payload.insert("work_item_id".into(), work_item_id.to_string().into());
        payload.insert("attempt_id".into(), attempt_id.to_string().into());
        payload.insert(
            "idempotency_key".into(),
            format!("{tenant_id}/{work_item_id}/{attempt_id}").into(),
        );
        let work_order_payload = request_payload["payload"].clone();
        let canonical_payload =
            canonical_json(&work_order_payload).expect("canonicalize Runmill Work Order payload");
        let work_order_digest = sha256_digest(&canonical_payload);
        let exact_signed_envelope = canonical_json(&request_payload)
            .expect("canonicalize signed Runmill Work Order envelope");
        let request_digest = sha256_digest(&exact_signed_envelope);
        let mut transaction = ledger.pool().begin().await.expect("begin fixture");

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("submit-{tenant_id}"))
            .bind("Submission effect test")
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
        .bind(tenant_id)
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
        .bind(tenant_id)
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
        .bind(tenant_id)
        .bind(repository_id)
        .bind(format!("item-{work_item_id}"))
        .bind(&source_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .expect("insert source snapshot");
        sqlx::query(
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
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(format!("item-{work_item_id}"))
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
        .expect("insert accepted work item");
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, reducer_version
            ) VALUES ($1, $2, $3, 'WORK_ITEM_DELIVERY', 'asf.workflow/v1')
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert workflow");
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
        .expect("insert accountability anchor");
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest
            ) VALUES (
                $1, $2, $3, 1, 'AUTHORIZED', $4, 'refs/heads/main', $5, $6, $7
            )
            ",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(format!("{tenant_id}/{work_item_id}/{attempt_id}"))
        .bind("a".repeat(40))
        .bind(&source_digest)
        .bind(&policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert attempt");
        sqlx::query(
            r"
            UPDATE work_items
            SET current_attempt_id = $3,
                aggregate_version = aggregate_version + 1,
                updated_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .execute(&mut *transaction)
        .await
        .expect("bind current attempt");
        sqlx::query(
            r"
            INSERT INTO work_orders (
                id, tenant_id, work_item_id, attempt_id, schema_version,
                envelope_schema, algorithm, key_id, idempotency_key,
                payload_digest, canonical_payload, payload, signature,
                exact_signed_envelope, issued_at, not_before, expires_at
            ) VALUES (
                $1, $2, $3, $4, 'asf.work-order/v1',
                'asf.work-order-envelope/v1', 'EdDSA', 'test-key', $5,
                $6, $7, $8, 'base64url:test', $9, $10, $10, $11
            )
            ",
        )
        .bind(work_order_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(format!("{tenant_id}/{work_item_id}/{attempt_id}"))
        .bind(&work_order_digest)
        .bind(&canonical_payload)
        .bind(&work_order_payload)
        .bind(&exact_signed_envelope)
        .bind(now)
        .bind(now + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert immutable Work Order");
        sqlx::query("UPDATE attempts SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(attempt_id)
            .bind(&work_order_digest)
            .execute(&mut *transaction)
            .await
            .expect("bind attempt Work Order");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'ADVANCE_ACCEPTED_WORK_ITEM', $6, 'RUNNING',
                '{}'::jsonb, $7, 1, 3, 1, $8, $9
            )
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID)
        .bind(format!("dispatch-{job_id}"))
        .bind(&lease_owner)
        .bind(now + Duration::minutes(5))
        .execute(&mut *transaction)
        .await
        .expect("insert exact dispatch owner");

        transaction.commit().await.expect("commit fixture");
        Self {
            tenant_id,
            work_item_id,
            attempt_id,
            work_order_id,
            work_order_digest,
            request_digest,
            request_payload,
            job_id,
            effect_id,
            lease_owner,
        }
    }

    async fn insert_effect(&self, ledger: &PgLedger, id: Uuid, idempotency_key: &str) {
        sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                idempotency_key, request_digest, request_payload,
                work_order_id, work_order_digest
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'submit_work_order',
                $5, $6, $7, $8, $9
            )
            ",
        )
        .bind(id)
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .bind(idempotency_key)
        .bind(&self.request_digest)
        .bind(&self.request_payload)
        .bind(self.work_order_id)
        .bind(&self.work_order_digest)
        .execute(ledger.pool())
        .await
        .expect("insert bound submission intent");
    }
}

#[tokio::test]
async fn exact_submission_binding_owner_and_single_intent_are_database_enforced() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    fixture
        .insert_effect(
            &database.ledger,
            fixture.effect_id,
            &format!("submit-effect:{}", fixture.attempt_id),
        )
        .await;

    let mut contradictory_request = fixture.request_payload.clone();
    contradictory_request["payload"]["objective"]["title"] =
        "A different outbound Work Order".into();
    let contradictory_request = sqlx::query(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            idempotency_key, request_digest, request_payload,
            work_order_id, work_order_digest
        ) VALUES (
            $1, $2, $3, $4, 'runmill', 'submit_work_order',
            $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(format!("contradictory-submit:{}", fixture.attempt_id))
    .bind(sha256_digest(
        &canonical_json(&contradictory_request).expect("canonical contradictory request"),
    ))
    .bind(&contradictory_request)
    .bind(fixture.work_order_id)
    .bind(&fixture.work_order_digest)
    .execute(database.ledger.pool())
    .await
    .expect_err("declared Work Order A cannot carry outbound request B");
    assert_constraint(
        &contradictory_request,
        "effect_intents_exact_submission_request",
    );

    let stale_fence = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', attempt_count = 1, fence_token = 2,
            lease_owner = $3, lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(&fixture.lease_owner)
    .bind(fixture.job_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("stale effect fence must not borrow the live job identity");
    assert_constraint(&stale_fence, "effect_intents_exact_external_mutation_owner");

    sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', attempt_count = 1, fence_token = 1,
            lease_owner = $3, lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(&fixture.lease_owner)
    .bind(fixture.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("exact live dispatch job owns submission");

    let retired_owner = sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'RETRY', lease_owner = NULL, lease_expires_at = NULL,
            available_at = clock_timestamp(), updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("a job cannot retire while its external mutation is in flight");
    assert_constraint(&retired_owner, "effect_intents_exact_workflow_job_claim_fk");

    let replacement_job_id = Uuid::now_v7();
    let replacement_owner = "reactor:submission-effect-replacement";
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, status, payload, idempotency_key,
            attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
        )
        SELECT $3, tenant_id, workflow_instance_id, work_item_id, attempt_id,
               job_type, activity_contract_id, 'RUNNING', payload, $4, 1,
               max_attempts, 2, $5, clock_timestamp() + interval '5 minutes'
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .bind(replacement_job_id)
    .bind(format!("replacement-dispatch-{replacement_job_id}"))
    .bind(replacement_owner)
    .execute(database.ledger.pool())
    .await
    .expect("insert a second exact live dispatch job");

    let stolen_owner = sqlx::query(
        r"
        UPDATE effect_intents
        SET owning_workflow_job_id = $3, fence_token = 2, lease_owner = $4,
            lease_expires_at = clock_timestamp() + interval '5 minutes'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(replacement_job_id)
    .bind(replacement_owner)
    .execute(database.ledger.pool())
    .await
    .expect_err("one live job cannot steal another live job's in-flight mutation");
    assert_constraint(
        &stolen_owner,
        "effect_intents_owner_handoff_requires_release",
    );

    sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'AMBIGUOUS', lease_owner = NULL, lease_expires_at = NULL,
            owning_workflow_job_id = NULL
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .execute(database.ledger.pool())
    .await
    .expect("ambiguous submission relinquishes its owner");

    let blind_resubmission = sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', fence_token = 2, lease_owner = $3,
            lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(replacement_owner)
    .bind(replacement_job_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("an ambiguous submission cannot be blindly dispatched again");
    assert_constraint(
        &blind_resubmission,
        "effect_intents_ambiguous_submission_reconciliation_gate",
    );

    let mutated_authority = sqlx::query(
        "UPDATE effect_intents SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(digest('9'))
    .execute(database.ledger.pool())
    .await
    .expect_err("submission authority binding must be immutable");
    assert_constraint(
        &mutated_authority,
        "effect_intents_identity_request_immutable",
    );

    let duplicate = sqlx::query(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            idempotency_key, request_digest, request_payload,
            work_order_id, work_order_digest
        ) VALUES (
            $1, $2, $3, $4, 'runmill', 'submit_work_order',
            $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(format!("second-submit:{}", fixture.attempt_id))
    .bind(&fixture.request_digest)
    .bind(&fixture.request_payload)
    .bind(fixture.work_order_id)
    .bind(&fixture.work_order_digest)
    .execute(database.ledger.pool())
    .await
    .expect_err("one attempt must not own two Runmill submission intents");
    assert_constraint(
        &duplicate,
        "effect_intents_one_runmill_submission_per_attempt_idx",
    );

    let unbound = sqlx::query(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            idempotency_key, request_digest, request_payload
        ) VALUES (
            $1, $2, $3, $4, 'runmill', 'submit_work_order',
            $5, $6, $7
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(format!("unbound-submit:{}", fixture.attempt_id))
    .bind(&fixture.request_digest)
    .bind(&fixture.request_payload)
    .execute(database.ledger.pool())
    .await
    .expect_err("submission without relational Work Order authority must fail");
    assert_constraint(&unbound, "effect_intents_submission_binding_shape");

    database.cleanup().await;
}

#[tokio::test]
async fn migration_0008_upgrades_legacy_submission_states_and_reinstalls_terminal_guard() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create_through_0007(&database_url).await;
    let mut legacy = Vec::new();
    for status in ["PENDING", "IN_FLIGHT", "OBSERVED", "CANCELLED"] {
        let fixture = Fixture::insert(&database.ledger).await;
        let effect_id = Uuid::now_v7();
        let lease_owner = (status == "IN_FLIGHT").then_some(fixture.lease_owner.as_str());
        let lease_expires_at =
            (status == "IN_FLIGHT").then_some(Utc::now().trunc_subsecs(6) + Duration::minutes(5));
        let observed_outcome = (status == "OBSERVED").then(|| {
            json!({
                "schema": "asf.legacy-runmill-submission-receipt/v1",
                "status": "observed"
            })
        });
        let observed_at = (status == "OBSERVED").then(Utc::now);
        sqlx::query(
            r"
            INSERT INTO effect_intents (
                id, tenant_id, work_item_id, attempt_id, provider, effect_type,
                status, idempotency_key, request_digest, request_payload,
                observed_outcome, attempt_count, fence_token, lease_owner,
                lease_expires_at, observed_at
            ) VALUES (
                $1, $2, $3, $4, 'runmill', 'submit_work_order', $5, $6, $7,
                $8, $9, $10, $11, $12, $13, $14
            )
            ",
        )
        .bind(effect_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(status)
        .bind(format!("legacy-submit-{status}-{effect_id}"))
        .bind(&fixture.request_digest)
        .bind(&fixture.request_payload)
        .bind(observed_outcome)
        .bind(i32::from(status == "IN_FLIGHT"))
        .bind(i64::from(status == "IN_FLIGHT"))
        .bind(lease_owner)
        .bind(lease_expires_at)
        .bind(observed_at)
        .execute(database.ledger.pool())
        .await
        .expect("insert legacy submission state");
        legacy.push((status, effect_id, fixture));
    }

    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin 0008 upgrade");
    sqlx::raw_sql(include_str!(
        "../migrations/0008_runmill_submission_effect_ownership.sql"
    ))
    .execute(&mut *transaction)
    .await
    .expect("upgrade populated and terminal legacy submission intents");
    transaction.commit().await.expect("commit 0008 upgrade");

    for (legacy_status, effect_id, fixture) in &legacy {
        let (status, work_order_id, work_order_digest, owner, request_payload): (
            String,
            Option<Uuid>,
            Option<String>,
            Option<Uuid>,
            serde_json::Value,
        ) = sqlx::query_as(
            r"
            SELECT status, work_order_id, work_order_digest,
                   owning_workflow_job_id, request_payload
            FROM effect_intents
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(effect_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load upgraded legacy submission");
        assert_eq!(
            status,
            if *legacy_status == "IN_FLIGHT" {
                "AMBIGUOUS"
            } else {
                *legacy_status
            }
        );
        assert_eq!(work_order_id, Some(fixture.work_order_id));
        assert_eq!(
            work_order_digest.as_deref(),
            Some(fixture.work_order_digest.as_str())
        );
        assert_eq!(owner, None);
        assert_eq!(request_payload, fixture.request_payload);
    }

    let (_, terminal_effect_id, terminal_fixture) = legacy
        .iter()
        .find(|(status, _, _)| *status == "OBSERVED")
        .expect("observed legacy fixture");
    let terminal_rewrite = sqlx::query(
        "UPDATE effect_intents SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(terminal_fixture.tenant_id)
    .bind(terminal_effect_id)
    .bind(digest('f'))
    .execute(database.ledger.pool())
    .await
    .expect_err("the expanded terminal guard must be reinstalled after backfill");
    assert_constraint(&terminal_rewrite, "effect_intents_terminal_immutable");

    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin 0009 follow-on upgrade");
    sqlx::raw_sql(include_str!(
        "../migrations/0009_linear_source_closure_ownership.sql"
    ))
    .execute(&mut *transaction)
    .await
    .expect("follow-on migration preserves upgraded terminal submissions");
    transaction
        .commit()
        .await
        .expect("commit 0009 follow-on upgrade");

    database.cleanup().await;
}

#[tokio::test]
async fn expired_job_reclaim_atomically_releases_submission_into_ambiguity() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    fixture
        .insert_effect(
            &database.ledger,
            fixture.effect_id,
            &format!("expired-owner-submit:{}", fixture.attempt_id),
        )
        .await;
    sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', attempt_count = 1, fence_token = 1,
            lease_owner = $3, lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .bind(&fixture.lease_owner)
    .bind(fixture.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("bind submission to its initially live owner");
    sqlx::query(
        r"
        UPDATE workflow_jobs
        SET lease_expires_at = clock_timestamp() + interval '250 milliseconds'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("shorten the owning job lease while it remains live");
    tokio::time::sleep(StdDuration::from_millis(350)).await;

    let claimed = database
        .ledger
        .claim_jobs(
            fixture.tenant_id,
            "reactor:expired-submission-recovery",
            1,
            StdDuration::from_mins(5),
        )
        .await
        .expect("reclaim expired job and release external effect atomically");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, fixture.job_id);
    assert_eq!(claimed[0].fence_token, 2);

    let (status, owner, lease_owner, last_error): (
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        r"
        SELECT status, owning_workflow_job_id, lease_owner, last_error
        FROM effect_intents
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.effect_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load atomically released submission effect");
    assert_eq!(status, "AMBIGUOUS");
    assert_eq!(owner, None);
    assert_eq!(lease_owner, None);
    assert!(
        last_error
            .as_deref()
            .is_some_and(|error| error.contains("exact external-effect reconciliation required"))
    );

    database.cleanup().await;
}

#[tokio::test]
async fn reactor_reclaim_and_orphan_paths_release_only_expired_owned_submissions() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;

    let reclaimed = Fixture::insert(&database.ledger).await;
    reclaimed
        .insert_effect(
            &database.ledger,
            reclaimed.effect_id,
            &format!("reactor-reclaim-submit:{}", reclaimed.attempt_id),
        )
        .await;
    sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', attempt_count = 1, fence_token = 1,
            lease_owner = $3, lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(reclaimed.tenant_id)
    .bind(reclaimed.effect_id)
    .bind(&reclaimed.lease_owner)
    .bind(reclaimed.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("bind reactor-reclaimed submission effect");
    sqlx::query(
        "UPDATE workflow_jobs SET lease_expires_at = clock_timestamp() + interval '250 milliseconds' \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(reclaimed.tenant_id)
    .bind(reclaimed.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("shorten reactor-reclaimed submission owner lease");
    tokio::time::sleep(StdDuration::from_millis(350)).await;

    assert_eq!(
        reactor(
            &database.ledger,
            reclaimed.tenant_id,
            "reactor:submission-normal-reclaim"
        )
        .poll_once()
        .await
        .expect("reactor reclaims expired submission owner"),
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_retried: 1,
            ..ReactorPollReport::default()
        }
    );
    let reclaimed_effect: (String, Option<Uuid>, Option<String>, Option<String>) = sqlx::query_as(
        r"
            SELECT status, owning_workflow_job_id, lease_owner, last_error
            FROM effect_intents
            WHERE tenant_id = $1 AND id = $2
            ",
    )
    .bind(reclaimed.tenant_id)
    .bind(reclaimed.effect_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load reactor-released submission");
    assert_eq!(reclaimed_effect.0, "AMBIGUOUS");
    assert!(reclaimed_effect.1.is_none());
    assert!(reclaimed_effect.2.is_none());
    assert!(
        reclaimed_effect
            .3
            .as_deref()
            .is_some_and(|error| error.contains("exact external-effect reconciliation required"))
    );

    let fresh = Fixture::insert(&database.ledger).await;
    fresh
        .insert_effect(
            &database.ledger,
            fresh.effect_id,
            &format!("fresh-pending-submit:{}", fresh.attempt_id),
        )
        .await;
    sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'RETRY', lease_owner = NULL, lease_expires_at = NULL,
            available_at = clock_timestamp() - interval '1 second',
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fresh.tenant_id)
    .bind(fresh.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("make fresh retry job due");
    assert_eq!(
        reactor(&database.ledger, fresh.tenant_id, "reactor:fresh-retry")
            .poll_once()
            .await
            .expect("reactor claims fresh retry"),
        ReactorPollReport {
            jobs_claimed: 1,
            jobs_retried: 1,
            ..ReactorPollReport::default()
        }
    );
    let fresh_effect_status: String =
        sqlx::query_scalar("SELECT status FROM effect_intents WHERE tenant_id = $1 AND id = $2")
            .bind(fresh.tenant_id)
            .bind(fresh.effect_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load untouched fresh submission effect");
    assert_eq!(fresh_effect_status, "PENDING");

    let orphaned = Fixture::insert(&database.ledger).await;
    orphaned
        .insert_effect(
            &database.ledger,
            orphaned.effect_id,
            &format!("reactor-orphan-submit:{}", orphaned.attempt_id),
        )
        .await;
    sqlx::query(
        r"
        UPDATE effect_intents
        SET status = 'IN_FLIGHT', attempt_count = 1, fence_token = 1,
            lease_owner = $3, lease_expires_at = clock_timestamp() + interval '5 minutes',
            owning_workflow_job_id = $4
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(orphaned.tenant_id)
    .bind(orphaned.effect_id)
    .bind(&orphaned.lease_owner)
    .bind(orphaned.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("bind orphaned submission effect");
    sqlx::query(
        r"
        UPDATE workflow_jobs
        SET attempt_count = max_attempts,
            lease_expires_at = clock_timestamp() + interval '250 milliseconds',
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(orphaned.tenant_id)
    .bind(orphaned.job_id)
    .execute(database.ledger.pool())
    .await
    .expect("shorten final submission owner claim");
    tokio::time::sleep(StdDuration::from_millis(350)).await;
    assert_eq!(
        reactor(
            &database.ledger,
            orphaned.tenant_id,
            "reactor:submission-orphan-recovery"
        )
        .poll_once()
        .await
        .expect("reactor recovers orphaned final submission claim"),
        ReactorPollReport {
            orphaned_jobs_recovered: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );
    let orphaned_state: (String, String, Option<Uuid>, Option<String>) = sqlx::query_as(
        r"
        SELECT job.status, effect.status, effect.owning_workflow_job_id, effect.lease_owner
        FROM workflow_jobs AS job
        JOIN effect_intents AS effect
          ON effect.tenant_id = job.tenant_id
         AND effect.id = $3
        WHERE job.tenant_id = $1 AND job.id = $2
        ",
    )
    .bind(orphaned.tenant_id)
    .bind(orphaned.job_id)
    .bind(orphaned.effect_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load recovered final submission state");
    assert_eq!(orphaned_state.0, "DEAD");
    assert_eq!(orphaned_state.1, "AMBIGUOUS");
    assert!(orphaned_state.2.is_none());
    assert!(orphaned_state.3.is_none());

    database.cleanup().await;
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected),
        "unexpected database error: {error}"
    );
}

#[tokio::test]
#[ignore = "requires ASF_TEST_DATABASE_URL"]
async fn build_submission_effect_from_stored_work_order_with_fence_and_transaction() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;

    let (workflow_instance_id, job_fence_token, lease_owner): (Uuid, i64, String) = sqlx::query_as(
        r"
        SELECT workflow_instance_id, fence_token, lease_owner
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("query workflow job");

    let expected_work_item_version: i64 = sqlx::query_scalar(
        "SELECT aggregate_version FROM work_items WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("query work item version");

    let (expected_workflow_version, expected_workflow_fence_token): (i64, Option<i64>) =
        sqlx::query_as(
            "SELECT aggregate_version, fence_token FROM workflow_instances WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(workflow_instance_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("query workflow instance");

    let expected_anchor_generation: i64 = sqlx::query_scalar(
        r"
        SELECT generation
        FROM accountability_anchors
        WHERE tenant_id = $1 AND work_item_id = $2 AND anchor_type = 'WORKFLOW'
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("query anchor generation");

    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin test transaction");

    let fence = asf::ledger::WorkflowStepFence {
        tenant_id: fixture.tenant_id,
        job_id: fixture.job_id,
        workflow_instance_id,
        work_item_id: fixture.work_item_id,
        lease_owner,
        job_fence_token,
        expected_work_item_version,
        expected_workflow_version,
        expected_workflow_fence_token: expected_workflow_fence_token.unwrap_or(0),
        expected_anchor_generation: expected_anchor_generation as i64,
    };

    let effect_id = Uuid::now_v7();
    let next_attempt_at = Utc::now().trunc_subsecs(6) + Duration::minutes(1);

    let effect = asf::ledger::build_submission_effect_from_stored_work_order(
        &mut transaction,
        &fence,
        effect_id,
        next_attempt_at,
    )
    .await
    .expect("build submission effect from stored work order");

    assert_eq!(effect.id, effect_id);
    assert_eq!(effect.provider, "runmill");
    assert_eq!(effect.effect_type, "submit_work_order");
    assert_eq!(effect.attempt_id, Some(fixture.attempt_id));
    assert_eq!(effect.request_digest, fixture.request_digest);
    assert_eq!(effect.request_payload, fixture.request_payload);

    let binding = effect
        .runmill_submission
        .as_ref()
        .expect("effect has runmill submission binding");
    assert_eq!(binding.work_order_id, fixture.work_order_id);
    assert_eq!(binding.work_order_digest, fixture.work_order_digest);

    let policy_digest: String =
        sqlx::query_scalar("SELECT policy_digest FROM work_items WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(fixture.work_item_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("query policy digest from work item");

    let commit = WorkflowStepCommit {
        fence: fence.clone(),
        commit_digest: digest('d'),
        job_result: Some(json!({"ok": true})),
        work_item_state: "ACCEPTED".to_string(),
        workflow_state: "ACTIVE".to_string(),
        workflow_event_cursor: 1,
        accountability: AccountabilityReplacement {
            kind: LedgerAccountabilityKind::Workflow,
            reference_id: fence.workflow_instance_id,
            wake_or_deadline_at: None,
            authority_or_effect_active: false,
        },
        jobs: vec![],
        timers: vec![],
        outbox: vec![],
        effects: vec![effect.clone()],
        audit_events: vec![StepAuditEvent {
            id: Uuid::now_v7(),
            attempt_id: Some(fixture.attempt_id),
            actor_type: "SERVICE".to_string(),
            actor_id: "reactor:test".to_string(),
            action: "WORKFLOW_STEP_COMMITTED".to_string(),
            subject_type: "WORK_ITEM".to_string(),
            subject_id: fixture.work_item_id.to_string(),
            correlation_id: fixture.job_id.to_string(),
            trace_id: None,
            policy_digest: Some(policy_digest.clone()),
            before_digest: None,
            after_digest: None,
            details: json!({}),
            occurred_at: Utc::now().trunc_subsecs(6),
        }],
    };

    let initial_result = commit_workflow_step(&mut transaction, &commit)
        .await
        .expect("apply patch");
    match &initial_result {
        WorkflowStepCommitOutcome::Applied { .. } => {}
        WorkflowStepCommitOutcome::AlreadyApplied => {
            panic!("expected Applied on initial commit, got AlreadyApplied")
        }
    }

    let replay_result = commit_workflow_step(&mut transaction, &commit)
        .await
        .expect("replay patch");
    match &replay_result {
        WorkflowStepCommitOutcome::AlreadyApplied => {}
        WorkflowStepCommitOutcome::Applied { .. } => {
            panic!("expected AlreadyApplied on replay, got Applied")
        }
    }

    let (effect_status, effect_count, work_order_id, work_order_digest): (
        String,
        i64,
        Uuid,
        String,
    ) = sqlx::query_as(
        r"
        SELECT status, COUNT(*), work_order_id, work_order_digest
        FROM effect_intents
        WHERE tenant_id = $1 AND id = $2
        GROUP BY id, status, work_order_id, work_order_digest
        ",
    )
    .bind(fixture.tenant_id)
    .bind(effect.id)
    .fetch_one(&mut *transaction)
    .await
    .expect("query effect intent state");
    assert_eq!(effect_status, "PENDING");
    assert_eq!(effect_count, 1);
    assert_eq!(work_order_id, fixture.work_order_id);
    assert_eq!(work_order_digest, fixture.work_order_digest);

    let runs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runs WHERE tenant_id = $1")
        .bind(fixture.tenant_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("query runs count");
    assert_eq!(runs_count, 0);

    transaction.rollback().await.expect("rollback transaction");
    database.cleanup().await;
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

#[tokio::test]
#[ignore = "requires ASF_TEST_DATABASE_URL"]
async fn recovery_case_create_or_get_with_ambiguous_effect_and_worker_session() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;

    let worker_id = Uuid::now_v7();
    let worker_generation = 1i64;
    let worker_session_id = Uuid::now_v7();

    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin recovery case test transaction");

    sqlx::query(
        r"
        INSERT INTO workers (
            id, tenant_id, name, endpoint, status, capabilities, generation,
            max_concurrency, signing_key_id, signing_public_key
        ) VALUES ($1, $2, $3, $4, 'READY', '{}'::jsonb, $5, 1, 'test-key', 'test-pubkey')
        ",
    )
    .bind(worker_id)
    .bind(fixture.tenant_id)
    .bind(format!("recovery-worker-{}", worker_id.simple()))
    .bind("http://test.invalid")
    .bind(worker_generation)
    .execute(&mut *transaction)
    .await
    .expect("insert test worker");

    sqlx::query(
        r"
        INSERT INTO worker_sessions (
            id, tenant_id, worker_id, worker_generation, status,
            started_at, expires_at
        ) VALUES ($1, $2, $3, $4, 'ACTIVE', clock_timestamp(), clock_timestamp() + interval '1 hour')
        ",
    )
    .bind(worker_session_id)
    .bind(fixture.tenant_id)
    .bind(worker_id)
    .bind(worker_generation)
    .execute(&mut *transaction)
    .await
    .expect("insert test worker session");

    let effect_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO effect_intents (
            id, tenant_id, work_item_id, attempt_id, provider, effect_type,
            status, idempotency_key, request_digest, request_payload,
            work_order_id, work_order_digest
        ) VALUES (
            $1, $2, $3, $4, 'runmill', 'submit_work_order', 'AMBIGUOUS',
            $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(effect_id)
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(format!("recovery-effect:{}", fixture.attempt_id))
    .bind(&fixture.request_digest)
    .bind(&fixture.request_payload)
    .bind(fixture.work_order_id)
    .bind(&fixture.work_order_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert ambiguous effect intent");

    transaction
        .commit()
        .await
        .expect("commit setup transaction");

    let recovery_case_id = Uuid::now_v7();
    let escalation_id = Uuid::now_v7();
    let remote_idempotency_key = format!(
        "{}/{}/{}",
        fixture.tenant_id, fixture.work_item_id, fixture.attempt_id
    );

    let input = asf::ledger::NewRunmillSubmissionRecoveryCase {
        id: recovery_case_id,
        tenant_id: fixture.tenant_id,
        effect_intent_id: effect_id,
        work_item_id: fixture.work_item_id,
        attempt_id: fixture.attempt_id,
        work_order_id: fixture.work_order_id,
        payload_digest: fixture.work_order_digest.clone(),
        request_digest: fixture.request_digest.clone(),
        remote_idempotency_key: remote_idempotency_key.clone(),
        worker_id,
        worker_generation,
        worker_session_id,
        escalation_id,
        owner_type: "TEAM".into(),
        owner_id: "platform-operations".into(),
        deadline: Utc::now().trunc_subsecs(6) + Duration::hours(4),
    };

    let case = database
        .ledger
        .create_or_get_runmill_submission_recovery_case(input.clone())
        .await
        .expect("create initial recovery case");

    assert_eq!(case.case.id, recovery_case_id);
    assert_eq!(case.case.tenant_id, fixture.tenant_id);
    assert_eq!(case.case.effect_intent_id, effect_id);
    assert_eq!(case.case.work_item_id, fixture.work_item_id);
    assert_eq!(case.case.attempt_id, fixture.attempt_id);
    assert_eq!(case.case.work_order_id, fixture.work_order_id);
    assert_eq!(case.case.payload_digest, fixture.work_order_digest);
    assert_eq!(case.case.request_digest, fixture.request_digest);
    assert_eq!(case.case.state, "PENDING_EXTERNAL_LOOKUP");
    assert_eq!(case.case.worker_id, worker_id);
    assert_eq!(case.case.worker_generation, worker_generation);
    assert_eq!(case.case.worker_session_id, worker_session_id);
    assert_eq!(case.escalation_id, escalation_id);

    let case2 = database
        .ledger
        .create_or_get_runmill_submission_recovery_case(input.clone())
        .await
        .expect("second call with identical inputs");

    assert_eq!(case2.case.id, case.case.id);
    assert_eq!(case2.case.state, "PENDING_EXTERNAL_LOOKUP");

    let mut conflicting_input = input.clone();
    conflicting_input.request_digest = digest('f');

    let conflict_error = database
        .ledger
        .create_or_get_runmill_submission_recovery_case(conflicting_input)
        .await
        .expect_err("changed request_digest must conflict");

    assert!(
        matches!(conflict_error, asf::Error::Conflict(_)),
        "expected Conflict error, got {conflict_error:?}"
    );

    let runs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runs WHERE tenant_id = $1")
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("query runs count");
    assert_eq!(
        runs_count, 0,
        "no runs row should be created by recovery case"
    );

    let observation_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM runmill_run_observation_streams WHERE tenant_id = $1",
    )
    .bind(fixture.tenant_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("query observation stream count");
    assert_eq!(
        observation_count, 0,
        "no runmill observation stream should be created by recovery case"
    );

    database.cleanup().await;
}
