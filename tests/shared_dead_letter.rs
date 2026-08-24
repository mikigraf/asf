use std::{collections::BTreeSet, time::Duration};

use asf::{
    Error,
    api::{ApiBackend, PageQuery, PostgresApiBackend},
    domain::TenantId,
    ledger::{
        ClaimedWorkflowJob, DeadLetterEscalation, PgLedger, StepAuditEvent, StepOutboxMessage,
        WorkflowStepFailure, WorkflowStepFailureDisposition, WorkflowStepFailureOutcome,
        WorkflowStepFence, fail_workflow_step,
    },
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};
use url::Url;
use uuid::Uuid;

const JOB_TYPE: &str = "TEST_SHARED_FINAL_FAILURE";
const JOB_TYPE_ACTIVITY_CONTRACT_ID: &str = "test.activity/test-shared-final-failure/v1";

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect shared-dead-letter administrator");
        let schema = format!("asf_shared_dead_letter_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated shared-dead-letter schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated shared-dead-letter ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated shared-dead-letter schema");
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
            .expect("drop isolated shared-dead-letter schema");
        self.admin.close().await;
    }
}

#[derive(Debug, Clone, Copy)]
struct Fixture {
    tenant_id: Uuid,
    work_a: Uuid,
    work_b: Uuid,
    attempt_a: Uuid,
    attempt_b: Uuid,
    workflow_a: Uuid,
    job_a: Uuid,
    job_b: Uuid,
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

async fn insert_fixture(ledger: &PgLedger) -> Fixture {
    let fixture = Fixture {
        tenant_id: Uuid::now_v7(),
        work_a: Uuid::now_v7(),
        work_b: Uuid::now_v7(),
        attempt_a: Uuid::now_v7(),
        attempt_b: Uuid::now_v7(),
        workflow_a: Uuid::now_v7(),
        job_a: Uuid::now_v7(),
        job_b: Uuid::now_v7(),
    };
    let repository_id = Uuid::now_v7();
    let policy_id = Uuid::now_v7();
    let snapshot_id = Uuid::now_v7();
    let policy_digest = digest('a');
    let snapshot_digest = digest('b');
    let mut transaction = ledger.pool().begin().await.expect("begin fixture");

    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(fixture.tenant_id)
        .bind(format!("shared-dead-letter-{}", fixture.tenant_id))
        .bind("Shared dead-letter test")
        .execute(&mut *transaction)
        .await
        .expect("insert tenant");
    sqlx::query(
        r"
        INSERT INTO policy_versions (
            id, tenant_id, scope, schema_version, digest, canonical_bytes,
            policy, created_by
        ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')
        ",
    )
    .bind(policy_id)
    .bind(fixture.tenant_id)
    .bind(&policy_digest)
    .bind(br"{}".as_slice())
    .execute(&mut *transaction)
    .await
    .expect("insert policy");
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, owner, name, repository_url, default_branch,
            default_policy_digest
        ) VALUES ($1, $2, 'acme', 'shared-dead-letter', $3, 'main', $4)
        ",
    )
    .bind(repository_id)
    .bind(fixture.tenant_id)
    .bind(format!("https://example.invalid/{repository_id}"))
    .bind(&policy_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert repository");
    sqlx::query(
        r"
        INSERT INTO source_snapshots (
            id, tenant_id, repository_id, source_system, external_id,
            source_revision, normalized_content, content_digest,
            connector_identity, source_updated_at
        ) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5,
                  'test:shared-dead-letter', clock_timestamp())
        ",
    )
    .bind(snapshot_id)
    .bind(fixture.tenant_id)
    .bind(repository_id)
    .bind(format!("shared-{}", fixture.tenant_id))
    .bind(&snapshot_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert source snapshot");

    for (work_item_id, suffix) in [(fixture.work_a, "a"), (fixture.work_b, "b")] {
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, repository_id, state, closure_target,
                risk_class, policy_digest, budget_limits,
                identity_requirements, owner_fallback, normalized_priority,
                accepted_at
            ) VALUES (
                $1, $2, $3, 'API', $4, $5, $7, 'pull_request',
                'low', $6,
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
                'platform-operations', 50,
                CASE WHEN $7 = 'ACCEPTED' THEN clock_timestamp() ELSE NULL END
            )
            ",
        )
        .bind(work_item_id)
        .bind(fixture.tenant_id)
        .bind(snapshot_id)
        .bind(format!("shared-{suffix}-{work_item_id}"))
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(if suffix == "a" { "ACCEPTED" } else { "READY" })
        .execute(&mut *transaction)
        .await
        .expect("insert work item");
    }

    for (attempt_id, work_item_id, suffix) in [
        (fixture.attempt_a, fixture.work_a, "a"),
        (fixture.attempt_b, fixture.work_b, "b"),
    ] {
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest
            ) VALUES (
                $1, $2, $3, 1, 'CREATED', $4, 'refs/heads/main', $5, $6, $7
            )
            ",
        )
        .bind(attempt_id)
        .bind(fixture.tenant_id)
        .bind(work_item_id)
        .bind(format!("attempt-{suffix}-{attempt_id}"))
        .bind("a".repeat(40))
        .bind(&snapshot_digest)
        .bind(&policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert attempt");
    }

    sqlx::query(
        r"
        UPDATE work_items
        SET current_attempt_id = $3,
            aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
    .bind(fixture.attempt_a)
    .execute(&mut *transaction)
    .await
    .expect("bind work A current attempt");

    sqlx::query(
        r"
        INSERT INTO workflow_instances (
            id, tenant_id, work_item_id, workflow_type, reducer_version
        ) VALUES ($1, $2, $3, 'delivery', 'v1')
        ",
    )
    .bind(fixture.workflow_a)
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
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
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
    .bind(fixture.workflow_a)
    .execute(&mut *transaction)
    .await
    .expect("insert accountability anchor");

    for (job_id, priority) in [(fixture.job_a, 10_i16), (fixture.job_b, 0_i16)] {
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, priority, payload, idempotency_key,
                available_at, max_attempts
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, $9,
                clock_timestamp() - interval '1 second', 1
            )
            ",
        )
        .bind(job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.workflow_a)
        .bind(fixture.work_a)
        .bind(fixture.attempt_a)
        .bind(JOB_TYPE)
        .bind(JOB_TYPE_ACTIVITY_CONTRACT_ID)
        .bind(priority)
        .bind(format!("shared-job-{job_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert final-attempt job");
    }

    transaction.commit().await.expect("commit fixture");
    fixture
}

async fn claim_one(ledger: &PgLedger, tenant_id: Uuid, owner: &str) -> ClaimedWorkflowJob {
    let jobs = ledger
        .claim_jobs(tenant_id, owner, 1, Duration::from_secs(30))
        .await
        .expect("claim final-attempt job");
    assert_eq!(jobs.len(), 1);
    jobs.into_iter().next().unwrap()
}

async fn build_failure(
    ledger: &PgLedger,
    claim: &ClaimedWorkflowJob,
    proposed_escalation_id: Uuid,
    owner_id: &str,
    error_summary: &str,
    retry_at: DateTime<Utc>,
) -> WorkflowStepFailure {
    let work_item_id = claim.work_item_id.expect("work-bound claim");
    let workflow_instance_id = claim.workflow_instance_id.expect("workflow-bound claim");
    let row = sqlx::query(
        r"
        SELECT
            work.aggregate_version AS work_version,
            workflow.aggregate_version AS workflow_version,
            workflow.fence_token AS workflow_fence,
            anchor.generation AS anchor_generation,
            work.policy_digest
        FROM work_items AS work
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = work.tenant_id
         AND workflow.id = $3
         AND workflow.work_item_id = work.id
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
        WHERE work.tenant_id = $1 AND work.id = $2
        ",
    )
    .bind(claim.tenant_id)
    .bind(work_item_id)
    .bind(workflow_instance_id)
    .fetch_one(ledger.pool())
    .await
    .expect("load failure fences");
    let opened_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(ledger.pool())
        .await
        .expect("load database clock");
    let deadline = opened_at + ChronoDuration::hours(4);
    let correlation_id = format!("workflow-job-exhausted:{}", claim.id);
    let policy_digest: String = row.try_get("policy_digest").unwrap();

    WorkflowStepFailure {
        fence: WorkflowStepFence {
            tenant_id: claim.tenant_id,
            job_id: claim.id,
            workflow_instance_id,
            work_item_id,
            lease_owner: claim.lease_owner.clone(),
            job_fence_token: claim.fence_token,
            expected_work_item_version: row.try_get("work_version").unwrap(),
            expected_workflow_version: row.try_get("workflow_version").unwrap(),
            expected_workflow_fence_token: row.try_get("workflow_fence").unwrap(),
            expected_anchor_generation: row.try_get("anchor_generation").unwrap(),
        },
        error_summary: error_summary.into(),
        retry_at,
        dead_letter: DeadLetterEscalation {
            id: proposed_escalation_id,
            run_id: None,
            category: "WORKFLOW_JOB_EXHAUSTED".into(),
            severity: "HIGH".into(),
            reason: format!("proposal reason for {}", claim.id),
            owner_type: "ON_CALL".into(),
            owner_id: owner_id.into(),
            required_action: format!("proposal action for {}", claim.id),
            evidence_references: json!([format!("fixture-evidence:{}", claim.id)]),
            deadline,
            escalation_path: json!([{"owner_type": "ON_CALL", "owner_id": owner_id}]),
            retry_policy: json!({
                "automatic": false,
                "max_additional_attempts": 0,
                "backoff_seconds": 0,
                "prerequisites": [format!("proposal-prerequisite:{}", claim.id)],
            }),
            prerequisites: json!([format!("top-level-prerequisite:{}", claim.id)]),
            authority_or_effect_active: true,
            idempotency_key: correlation_id.clone(),
            opened_at,
            audit_event: StepAuditEvent {
                id: Uuid::now_v7(),
                attempt_id: claim.attempt_id,
                actor_type: "SERVICE".into(),
                actor_id: claim.lease_owner.clone(),
                action: "WORKFLOW_JOB_EXHAUSTED".into(),
                subject_type: "WORKFLOW_JOB".into(),
                subject_id: claim.id.to_string(),
                correlation_id: correlation_id.clone(),
                trace_id: None,
                policy_digest: Some(policy_digest),
                before_digest: None,
                after_digest: None,
                details: json!({"attempt_count": claim.attempt_count}),
                occurred_at: opened_at,
            },
            outbox_message: StepOutboxMessage {
                id: Uuid::now_v7(),
                topic: "attention".into(),
                message_key: work_item_id.to_string(),
                event_type: "workflow_job.exhausted".into(),
                payload: json!({"proposal_owner": owner_id, "deadline": deadline}),
                headers: json!({"schema": "asf.attention-event/v1"}),
                idempotency_key: format!("{correlation_id}:outbox"),
                available_at: opened_at,
            },
        },
    }
}

async fn commit_failure(
    ledger: &PgLedger,
    failure: &WorkflowStepFailure,
) -> WorkflowStepFailureOutcome {
    let mut transaction = ledger.pool().begin().await.expect("begin failure");
    let outcome = fail_workflow_step(&mut transaction, failure)
        .await
        .expect("record workflow-step failure");
    transaction.commit().await.expect("commit failure");
    outcome
}

async fn retry_time(ledger: &PgLedger) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp() + interval '1 minute'")
        .fetch_one(ledger.pool())
        .await
        .expect("load retry time")
}

#[tokio::test]
async fn distinct_exhausted_jobs_share_exact_active_owner_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = insert_fixture(&database.ledger).await;
    let proposed_a = Uuid::now_v7();
    let proposed_b = Uuid::now_v7();

    let claim_a = claim_one(&database.ledger, fixture.tenant_id, "shared-worker-a").await;
    assert_eq!(claim_a.id, fixture.job_a);
    let failure_a = build_failure(
        &database.ledger,
        &claim_a,
        proposed_a,
        "primary-owner",
        "first deterministic failure",
        retry_time(&database.ledger).await,
    )
    .await;
    assert_eq!(
        commit_failure(&database.ledger, &failure_a).await,
        WorkflowStepFailureOutcome {
            disposition: WorkflowStepFailureDisposition::Escalated,
            newly_recorded: true,
            dead_letter_escalation_id: Some(proposed_a),
        }
    );
    assert_eq!(
        commit_failure(&database.ledger, &failure_a).await,
        WorkflowStepFailureOutcome {
            disposition: WorkflowStepFailureDisposition::Escalated,
            newly_recorded: false,
            dead_letter_escalation_id: Some(proposed_a),
        }
    );

    let mut transaction = database.ledger.pool().begin().await.unwrap();
    let overdue_deadline: DateTime<Utc> = sqlx::query_scalar(
        r"
        UPDATE escalations
        SET status = 'ACKNOWLEDGED',
            acknowledged_at = clock_timestamp(),
            deadline = opened_at + interval '1 millisecond',
            aggregate_version = aggregate_version + 1
        WHERE tenant_id = $1 AND id = $2
        RETURNING deadline
        ",
    )
    .bind(fixture.tenant_id)
    .bind(proposed_a)
    .fetch_one(&mut *transaction)
    .await
    .expect("acknowledge and age first escalation");
    sqlx::query(
        r"
        UPDATE accountability_anchors
        SET wake_or_deadline_at = $3, updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND work_item_id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
    .bind(overdue_deadline)
    .execute(&mut *transaction)
    .await
    .expect("retain coherent overdue anchor");
    transaction.commit().await.unwrap();
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(database.ledger.pool())
        .await
        .unwrap();
    assert!(overdue_deadline < database_now);

    let before_b = sqlx::query(
        r"
        SELECT status, opened_at, acknowledged_at, deadline, owner_type,
               owner_id, idempotency_key, escalation_path, prerequisites,
               aggregate_version
        FROM escalations WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(proposed_a)
    .fetch_one(database.ledger.pool())
    .await
    .unwrap();

    let claim_b = claim_one(&database.ledger, fixture.tenant_id, "shared-worker-b").await;
    assert_eq!(claim_b.id, fixture.job_b);
    let failure_b = build_failure(
        &database.ledger,
        &claim_b,
        proposed_b,
        "replacement-must-not-win",
        "second deterministic failure",
        retry_time(&database.ledger).await,
    )
    .await;
    assert_eq!(
        commit_failure(&database.ledger, &failure_b).await,
        WorkflowStepFailureOutcome {
            disposition: WorkflowStepFailureDisposition::Escalated,
            newly_recorded: true,
            dead_letter_escalation_id: Some(proposed_a),
        }
    );
    assert_eq!(
        commit_failure(&database.ledger, &failure_b).await,
        WorkflowStepFailureOutcome {
            disposition: WorkflowStepFailureDisposition::Escalated,
            newly_recorded: false,
            dead_letter_escalation_id: Some(proposed_a),
        }
    );

    let mut contradictory = failure_b.clone();
    contradictory.error_summary.push_str(" changed");
    let mut transaction = database.ledger.pool().begin().await.unwrap();
    let error = fail_workflow_step(&mut transaction, &contradictory)
        .await
        .expect_err("changed replay semantics must conflict");
    assert!(matches!(error, Error::Conflict(_)));
    transaction.rollback().await.unwrap();

    let after_b = sqlx::query(
        r"
        SELECT status, opened_at, acknowledged_at, deadline, owner_type,
               owner_id, idempotency_key, escalation_path, prerequisites,
               aggregate_version, evidence_references, reason, required_action,
               retry_policy, authority_or_effect_active
        FROM escalations WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(proposed_a)
    .fetch_one(database.ledger.pool())
    .await
    .unwrap();
    for column in [
        "status",
        "opened_at",
        "acknowledged_at",
        "deadline",
        "owner_type",
        "owner_id",
        "idempotency_key",
        "escalation_path",
        "prerequisites",
    ] {
        let before: Value = match column {
            "opened_at" | "acknowledged_at" | "deadline" => {
                json!(before_b.try_get::<DateTime<Utc>, _>(column).unwrap())
            }
            "escalation_path" | "prerequisites" => before_b.try_get::<Value, _>(column).unwrap(),
            _ => json!(before_b.try_get::<String, _>(column).unwrap()),
        };
        let after: Value = match column {
            "opened_at" | "acknowledged_at" | "deadline" => {
                json!(after_b.try_get::<DateTime<Utc>, _>(column).unwrap())
            }
            "escalation_path" | "prerequisites" => after_b.try_get::<Value, _>(column).unwrap(),
            _ => json!(after_b.try_get::<String, _>(column).unwrap()),
        };
        assert_eq!(after, before, "shared escalation changed {column}");
    }
    assert_eq!(after_b.try_get::<i64, _>("aggregate_version").unwrap(), 3);
    assert!(
        after_b
            .try_get::<bool, _>("authority_or_effect_active")
            .unwrap()
    );
    let retry_policy: Value = after_b.try_get("retry_policy").unwrap();
    assert_eq!(retry_policy.get("automatic"), Some(&json!(false)));
    assert_eq!(retry_policy.get("max_additional_attempts"), Some(&json!(0)));
    assert_eq!(retry_policy.get("backoff_seconds"), Some(&json!(0)));

    let evidence: Vec<String> = after_b
        .try_get::<Value, _>("evidence_references")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    for job_id in [fixture.job_a, fixture.job_b] {
        assert_eq!(
            evidence
                .iter()
                .filter(|reference| *reference == &format!("workflow-job:{job_id}"))
                .count(),
            1
        );
        assert!(
            after_b
                .try_get::<String, _>("reason")
                .unwrap()
                .contains(&format!("[workflow-job:{job_id}]"))
        );
        assert!(
            after_b
                .try_get::<String, _>("required_action")
                .unwrap()
                .contains(&format!("[workflow-job:{job_id}]"))
        );
    }

    let jobs = sqlx::query(
        r"
        SELECT id, status, dead_letter_escalation_id, dead_lettered_at, result
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = ANY($2::uuid[])
        ORDER BY id
        ",
    )
    .bind(fixture.tenant_id)
    .bind(vec![fixture.job_a, fixture.job_b])
    .fetch_all(database.ledger.pool())
    .await
    .unwrap();
    assert_eq!(jobs.len(), 2);
    for job in &jobs {
        assert_eq!(job.try_get::<String, _>("status").unwrap(), "DEAD");
        assert_eq!(
            job.try_get::<Uuid, _>("dead_letter_escalation_id").unwrap(),
            proposed_a
        );
        let result: Value = job.try_get("result").unwrap();
        assert_eq!(
            result.pointer("/escalation/id").and_then(Value::as_str),
            Some(proposed_a.to_string().as_str())
        );
        assert!(result.pointer("/escalation/status").is_some());
        assert!(result.pointer("/escalation/aggregate_version").is_some());
    }
    let job_b_dead_lettered_at: DateTime<Utc> = jobs
        .iter()
        .find(|row| row.try_get::<Uuid, _>("id").unwrap() == fixture.job_b)
        .unwrap()
        .try_get("dead_lettered_at")
        .unwrap();
    assert!(job_b_dead_lettered_at > overdue_deadline);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*) FROM escalations
            WHERE tenant_id = $1 AND work_item_id = $2 AND attempt_id = $3
              AND category = 'WORKFLOW_JOB_EXHAUSTED'
            ",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_a)
        .bind(fixture.attempt_a)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'WORKFLOW_JOB_EXHAUSTED'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox WHERE tenant_id = $1 AND event_type = 'workflow_job.exhausted'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        2
    );
    let actual_ids: Vec<String> = sqlx::query_scalar(
        r"
        SELECT details ->> 'escalation_id' FROM audit_events
        WHERE tenant_id = $1 AND action = 'WORKFLOW_JOB_EXHAUSTED'
        UNION ALL
        SELECT payload ->> 'escalation_id' FROM outbox
        WHERE tenant_id = $1 AND event_type = 'workflow_job.exhausted'
        ",
    )
    .bind(fixture.tenant_id)
    .fetch_all(database.ledger.pool())
    .await
    .unwrap();
    assert_eq!(actual_ids.len(), 4);
    assert!(actual_ids.iter().all(|id| id == &proposed_a.to_string()));

    let backend =
        PostgresApiBackend::from_ledger(&database.ledger, TenantId::from_uuid(fixture.tenant_id));
    let attention = backend
        .attention(
            TenantId::from_uuid(fixture.tenant_id),
            &PageQuery {
                cursor: None,
                limit: 10,
            },
        )
        .await
        .expect("shared escalation must remain complete attention");
    assert_eq!(attention.items.len(), 1);
    assert_eq!(attention.items[0].id, proposed_a);

    // Later lifecycle progress may close the active obligation and replace its
    // anchor. Immutable failure receipts must still adopt the original result.
    let recovery_job = Uuid::now_v7();
    let mut transaction = database.ledger.pool().begin().await.unwrap();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, payload, idempotency_key, max_attempts
        ) VALUES (
            $1, $2, $3, $4, $5, 'RECOVERY', 'test.activity/recovery/v1',
            '{}'::jsonb, $6, 3
        )
        ",
    )
    .bind(recovery_job)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_a)
    .bind(fixture.work_a)
    .bind(fixture.attempt_a)
    .bind(format!("recovery-{recovery_job}"))
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r"
        UPDATE work_items
        SET state = 'SCHEDULED', aggregate_version = aggregate_version + 1,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r"
        UPDATE accountability_anchors
        SET anchor_type = 'WORKFLOW', reference_id = $3,
            wake_or_deadline_at = NULL, authority_or_effect_active = false,
            generation = generation + 1, updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND work_item_id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_a)
    .bind(fixture.workflow_a)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r"
        UPDATE escalations
        SET status = 'RESOLVED', closed_at = clock_timestamp(),
            authority_or_effect_active = false,
            aggregate_version = aggregate_version + 1
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(proposed_a)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();

    for failure in [&failure_a, &failure_b] {
        assert!(
            !commit_failure(&database.ledger, failure)
                .await
                .newly_recorded
        );
    }
    let attention = backend
        .attention(
            TenantId::from_uuid(fixture.tenant_id),
            &PageQuery {
                cursor: None,
                limit: 10,
            },
        )
        .await
        .expect("terminal historical owner must not fail attention");
    assert!(attention.items.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'WORKFLOW_JOB_EXHAUSTED'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        2
    );

    for mutation in [
        "UPDATE workflow_jobs SET status = 'RETRY' WHERE tenant_id = $1 AND id = $2",
        "UPDATE workflow_jobs SET result = '{}'::jsonb WHERE tenant_id = $1 AND id = $2",
        "UPDATE workflow_jobs SET dead_letter_escalation_id = NULL WHERE tenant_id = $1 AND id = $2",
    ] {
        assert!(
            sqlx::query(mutation)
                .bind(fixture.tenant_id)
                .bind(fixture.job_a)
                .execute(database.ledger.pool())
                .await
                .is_err(),
            "terminal workflow job mutation unexpectedly succeeded: {mutation}"
        );
    }

    database.cleanup().await;
}

#[tokio::test]
async fn cross_bound_attempts_and_mutable_outbox_facts_are_rejected_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = insert_fixture(&database.ledger).await;

    let expected_constraints: BTreeSet<String> = [
        "work_orders_attempt_work_item_fk",
        "runs_attempt_work_item_fk",
        "approvals_attempt_work_item_fk",
        "escalations_attempt_work_item_fk",
        "evidence_bundles_attempt_work_item_fk",
        "budget_ledger_attempt_work_item_fk",
        "workflow_jobs_attempt_work_item_fk",
        "workflow_timers_attempt_work_item_fk",
        "effect_intents_attempt_work_item_fk",
        "audit_events_attempt_work_item_fk",
        "reservation_sets_work_repository_fk",
        "runs_work_order_binding_fk",
        "evidence_bundles_work_order_binding_fk",
        "evidence_bundles_run_worker_binding_fk",
        "escalations_run_binding_fk",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let installed: BTreeSet<String> = sqlx::query_scalar(
        r"
        SELECT conname FROM pg_constraint
        WHERE conname = ANY($1::text[])
        ",
    )
    .bind(
        expected_constraints
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .fetch_all(database.ledger.pool())
    .await
    .unwrap()
    .into_iter()
    .collect();
    assert_eq!(installed, expected_constraints);

    let poisoned_job = Uuid::now_v7();
    let error = sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, payload, idempotency_key
        ) VALUES ($1, $2, $3, $4, $5, 'POISON', 'test.activity/poison/v1', '{}'::jsonb, $6)
        ",
    )
    .bind(poisoned_job)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_a)
    .bind(fixture.work_a)
    .bind(fixture.attempt_b)
    .bind(format!("poison-{poisoned_job}"))
    .execute(database.ledger.pool())
    .await
    .expect_err("attempt B cannot bind workflow/work A");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23503")
    );

    let attempt_only_job = Uuid::now_v7();
    assert!(
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, attempt_id, job_type, activity_contract_id, payload, idempotency_key
            ) VALUES ($1, $2, $3, 'POISON', 'test.activity/poison/v1', '{}'::jsonb, $4)
            ",
        )
        .bind(attempt_only_job)
        .bind(fixture.tenant_id)
        .bind(fixture.attempt_a)
        .bind(format!("attempt-only-{attempt_only_job}"))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );

    let work_without_workflow = Uuid::now_v7();
    assert!(
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, work_item_id, job_type, activity_contract_id, payload, idempotency_key
            ) VALUES ($1, $2, $3, 'POISON', 'test.activity/poison/v1', '{}'::jsonb, $4)
            ",
        )
        .bind(work_without_workflow)
        .bind(fixture.tenant_id)
        .bind(fixture.work_a)
        .bind(format!("work-only-{work_without_workflow}"))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );

    let unbound_job = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (id, tenant_id, job_type, activity_contract_id, payload, idempotency_key)
        VALUES ($1, $2, 'TENANT_JOB', 'test.activity/tenant-job/v1', '{}'::jsonb, $3)
        ",
    )
    .bind(unbound_job)
    .bind(fixture.tenant_id)
    .bind(format!("unbound-{unbound_job}"))
    .execute(database.ledger.pool())
    .await
    .expect("tenant-scoped job remains supported");
    let cancelled_job = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, job_type, activity_contract_id, status, payload, idempotency_key
        ) VALUES (
            $1, $2, 'CANCELLED_TENANT_JOB', 'test.activity/cancelled-tenant-job/v1',
            'CANCELLED', '{}'::jsonb, $3
        )
        ",
    )
    .bind(cancelled_job)
    .bind(fixture.tenant_id)
    .bind(format!("cancelled-unbound-{cancelled_job}"))
    .execute(database.ledger.pool())
    .await
    .expect("insert terminal cancelled job");
    assert!(
        sqlx::query(
            "UPDATE workflow_jobs SET status = 'PENDING' WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(cancelled_job)
        .execute(database.ledger.pool())
        .await
        .is_err(),
        "CANCELLED workflow job must not be resurrected"
    );
    let bound_without_attempt = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id,
            job_type, activity_contract_id, payload, idempotency_key
        ) VALUES ($1, $2, $3, $4, 'WORK_JOB', 'test.activity/work-job/v1', '{}'::jsonb, $5)
        ",
    )
    .bind(bound_without_attempt)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_a)
    .bind(fixture.work_a)
    .bind(format!("bound-null-attempt-{bound_without_attempt}"))
    .execute(database.ledger.pool())
    .await
    .expect("workflow/work job with NULL attempt remains supported");

    let poisoned_escalation = Uuid::now_v7();
    assert!(
        sqlx::query(
            r#"
            INSERT INTO escalations (
                id, tenant_id, work_item_id, attempt_id, category, severity,
                reason, owner_type, owner_id, required_action,
                evidence_references, deadline, retry_policy,
                authority_or_effect_active, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, 'WORKFLOW_JOB_EXHAUSTED', 'HIGH', 'poison',
                'ON_CALL', 'test', 'reject poison', '["poison"]'::jsonb,
                clock_timestamp() + interval '1 hour',
                '{"automatic":false,"max_additional_attempts":0,"backoff_seconds":0,"prerequisites":[]}'::jsonb,
                true, $5
            )
            "#,
        )
        .bind(poisoned_escalation)
        .bind(fixture.tenant_id)
        .bind(fixture.work_a)
        .bind(fixture.attempt_b)
        .bind(format!("poison-escalation-{poisoned_escalation}"))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );
    let poisoned_audit = Uuid::now_v7();
    assert!(
        sqlx::query(
            r"
            INSERT INTO audit_events (
                id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
                action, subject_type, subject_id, correlation_id, event_hash,
                occurred_at
            ) VALUES (
                $1, $2, $3, $4, 'SERVICE', 'test', 'POISON', 'WORK_ITEM',
                $3::text, $5, $6, clock_timestamp()
            )
            ",
        )
        .bind(poisoned_audit)
        .bind(fixture.tenant_id)
        .bind(fixture.work_a)
        .bind(fixture.attempt_b)
        .bind(format!("poison-audit-{poisoned_audit}"))
        .bind(digest('f'))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(poisoned_job)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM workflow_jobs WHERE tenant_id = $1 AND status = 'DEAD'",
        )
        .bind(fixture.tenant_id)
        .fetch_one(database.ledger.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM escalations WHERE tenant_id = $1",)
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE tenant_id = $1",)
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .unwrap(),
        0
    );

    let observed_effect_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO effect_intents (
            id, tenant_id, provider, effect_type, status, idempotency_key,
            request_digest, request_payload, observed_outcome, observed_at
        ) VALUES (
            $1, $2, 'test-provider', 'terminal-receipt', 'OBSERVED', $3,
            $4, '{}'::jsonb, '{"result":"accepted"}'::jsonb,
            clock_timestamp()
        )
        "#,
    )
    .bind(observed_effect_id)
    .bind(fixture.tenant_id)
    .bind(format!("observed-effect-{observed_effect_id}"))
    .bind(digest('e'))
    .execute(database.ledger.pool())
    .await
    .expect("insert observed effect receipt");
    let effect_tamper = sqlx::query(
        r#"
        UPDATE effect_intents
        SET observed_outcome = '{"result":"rewritten"}'::jsonb
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(fixture.tenant_id)
    .bind(observed_effect_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("observed effect receipt must be immutable");
    assert_eq!(
        effect_tamper
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("effect_intents_terminal_immutable")
    );

    let outbox_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload,
            idempotency_key
        ) VALUES ($1, $2, 'test', 'key', 'test.event', '{"fact":1}'::jsonb, $3)
        "#,
    )
    .bind(outbox_id)
    .bind(fixture.tenant_id)
    .bind(format!("outbox-{outbox_id}"))
    .execute(database.ledger.pool())
    .await
    .unwrap();
    sqlx::query(
        r"
        UPDATE outbox
        SET status = 'RETRY', attempt_count = 1,
            available_at = clock_timestamp() + interval '1 minute',
            last_error = 'transient'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(outbox_id)
    .execute(database.ledger.pool())
    .await
    .expect("delivery state remains mutable");
    assert!(
        sqlx::query(
            "UPDATE outbox SET payload = '{\"fact\":2}'::jsonb WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(outbox_id)
        .execute(database.ledger.pool())
        .await
        .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM outbox WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(outbox_id)
            .execute(database.ledger.pool())
            .await
            .is_err()
    );

    let timer_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workflow_timers (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            workflow_key, timer_key, timer_type, activity_contract_id, due_at, payload
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 'TEST_TIMER', 'test.activity/test-timer/v1',
            clock_timestamp() + interval '1 minute', '{}'::jsonb
        )
        ",
    )
    .bind(timer_id)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_a)
    .bind(fixture.work_a)
    .bind(fixture.attempt_a)
    .bind(format!("workflow-{timer_id}"))
    .bind(format!("timer-{timer_id}"))
    .execute(database.ledger.pool())
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "UPDATE workflow_timers SET status = 'FIRED' WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(timer_id)
        .execute(database.ledger.pool())
        .await
        .is_err()
    );
    sqlx::query(
        r"
        UPDATE workflow_timers
        SET status = 'FIRED', fired_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(timer_id)
    .execute(database.ledger.pool())
    .await
    .expect("scheduled timer can become coherently fired");
    for mutation in [
        "UPDATE workflow_timers SET status = 'SCHEDULED', fired_at = NULL WHERE tenant_id = $1 AND id = $2",
        "UPDATE workflow_timers SET payload = '{\"changed\":true}'::jsonb WHERE tenant_id = $1 AND id = $2",
        "DELETE FROM workflow_timers WHERE tenant_id = $1 AND id = $2",
    ] {
        assert!(
            sqlx::query(mutation)
                .bind(fixture.tenant_id)
                .bind(timer_id)
                .execute(database.ledger.pool())
                .await
                .is_err(),
            "terminal timer mutation unexpectedly succeeded: {mutation}"
        );
    }

    let idempotency_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO idempotency_records (
            id, tenant_id, actor_id, operation, idempotency_key,
            request_digest, expires_at
        ) VALUES (
            $1, $2, 'operator:test', 'test.operation', $3, $4,
            clock_timestamp() + interval '1 day'
        )
        ",
    )
    .bind(idempotency_id)
    .bind(fixture.tenant_id)
    .bind(format!("idempotency-{idempotency_id}"))
    .bind(digest('1'))
    .execute(database.ledger.pool())
    .await
    .unwrap();
    assert!(
        sqlx::query(
            r"
            UPDATE idempotency_records
            SET state = 'COMPLETED', completed_at = clock_timestamp()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(fixture.tenant_id)
        .bind(idempotency_id)
        .execute(database.ledger.pool())
        .await
        .is_err()
    );
    sqlx::query(
        r#"
        UPDATE idempotency_records
        SET state = 'COMPLETED', response_status = 200,
            response_body = '{"receipt":"durable"}'::jsonb,
            completed_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(fixture.tenant_id)
    .bind(idempotency_id)
    .execute(database.ledger.pool())
    .await
    .expect("in-progress idempotency record can complete coherently");
    for mutation in [
        "UPDATE idempotency_records SET state = 'IN_PROGRESS', response_status = NULL, response_body = NULL, completed_at = NULL WHERE tenant_id = $1 AND id = $2",
        "UPDATE idempotency_records SET response_body = '{\"receipt\":\"rewritten\"}'::jsonb WHERE tenant_id = $1 AND id = $2",
        "DELETE FROM idempotency_records WHERE tenant_id = $1 AND id = $2",
    ] {
        assert!(
            sqlx::query(mutation)
                .bind(fixture.tenant_id)
                .bind(idempotency_id)
                .execute(database.ledger.pool())
                .await
                .is_err(),
            "terminal idempotency mutation unexpectedly succeeded: {mutation}"
        );
    }
    let expired_idempotency_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO idempotency_records (
            id, tenant_id, actor_id, operation, idempotency_key,
            request_digest, created_at, expires_at
        ) VALUES (
            $1, $2, 'operator:test', 'expired.operation', $3, $4,
            clock_timestamp() - interval '2 hours',
            clock_timestamp() - interval '1 hour'
        )
        ",
    )
    .bind(expired_idempotency_id)
    .bind(fixture.tenant_id)
    .bind(format!("expired-{expired_idempotency_id}"))
    .bind(digest('2'))
    .execute(database.ledger.pool())
    .await
    .unwrap();
    assert_eq!(
        sqlx::query("DELETE FROM idempotency_records WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(expired_idempotency_id)
            .execute(database.ledger.pool())
            .await
            .expect("expired idempotency cleanup remains allowed")
            .rows_affected(),
        1
    );

    let false_authority_incident = Uuid::now_v7();
    assert!(
        sqlx::query(
            r#"
            INSERT INTO operational_incidents (
                id, tenant_id, workflow_job_id, category, severity, reason,
                owner_type, owner_id, required_action, evidence_references,
                deadline, retry_policy, authority_or_effect_active,
                idempotency_key
            ) VALUES (
                $1, $2, $3, 'WORKFLOW_JOB_EXHAUSTED', 'HIGH', 'invalid owner',
                'ON_CALL', 'test', 'must reject false authority', '["evidence"]'::jsonb,
                clock_timestamp() + interval '1 hour',
                '{"automatic":false,"max_additional_attempts":0,"backoff_seconds":0,"prerequisites":[]}'::jsonb,
                false, $4
            )
            "#,
        )
        .bind(false_authority_incident)
        .bind(fixture.tenant_id)
        .bind(unbound_job)
        .bind(format!("false-authority-{false_authority_incident}"))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );

    let poisoned_budget = Uuid::now_v7();
    assert!(
        sqlx::query(
            r"
            INSERT INTO budget_ledger (
                id, tenant_id, work_item_id, attempt_id, scope_type, scope_id,
                dimension, entry_type, amount, unit, idempotency_key, occurred_at
            ) VALUES (
                $1, $2, $3, $4, 'ATTEMPT', 'wrong-attempt',
                'EXTERNAL_API_CALLS', 'ADJUST', 0, 'calls', $5,
                clock_timestamp()
            )
            ",
        )
        .bind(poisoned_budget)
        .bind(fixture.tenant_id)
        .bind(fixture.work_a)
        .bind(fixture.attempt_a)
        .bind(format!("poison-budget-{poisoned_budget}"))
        .execute(database.ledger.pool())
        .await
        .is_err()
    );

    database.cleanup().await;
}
