//! Live `PostgreSQL` coverage for the read-only Runmill observation provenance.

use chrono::SubsecRound as _;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::Barrier;
use url::Url;
use uuid::Uuid;

use asf::{
    crypto::sha256_digest,
    ledger::{
        IncomingRunmillControlEvent, IncomingRunmillControlSnapshot, PgLedger,
        RunmillAdmissionProvenance, RunmillControlObservationOutcome, RunmillControlOperation,
        RunmillObservationFence, record_runmill_control_observation,
    },
    runtime::OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
};

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect Runmill observation test administrator");
        let schema = format!("asf_runmill_observation_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated Runmill observation schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated Runmill observation ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated Runmill observation schema");
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
            .expect("drop isolated Runmill observation schema");
        self.admin.close().await;
    }
}

#[derive(Debug)]
struct Fixture {
    tenant_id: Uuid,
    work_item_id: Uuid,
    workflow_instance_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    policy_digest: String,
    envelope_digest: String,
    worker_id: Uuid,
    worker_session_id: Uuid,
    observer_session_id: Uuid,
    run_id: Uuid,
    external_run_id: String,
    job_id: Uuid,
    observation_id: Uuid,
    lease_owner: String,
    occurred_at: DateTime<Utc>,
}

impl Fixture {
    async fn insert(ledger: &PgLedger) -> Self {
        let fixture = Self {
            tenant_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            workflow_instance_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            work_order_id: Uuid::now_v7(),
            work_order_digest: digest('b'),
            policy_digest: digest('a'),
            envelope_digest: sha256_digest(b"exact signed envelope"),
            worker_id: Uuid::now_v7(),
            worker_session_id: Uuid::now_v7(),
            observer_session_id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            external_run_id: format!("run_{}", Uuid::now_v7().simple()),
            job_id: Uuid::now_v7(),
            observation_id: Uuid::now_v7(),
            lease_owner: "reactor:runmill-observation-test".into(),
            occurred_at: Utc::now().trunc_subsecs(6),
        };
        let repository_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin observation fixture");

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(fixture.tenant_id)
            .bind(format!("runmill-observation-{}", fixture.tenant_id))
            .bind("Runmill observation test")
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, scope, schema_version, digest, canonical_bytes, policy, created_by) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')",
        )
        .bind(policy_id)
        .bind(fixture.tenant_id)
        .bind(&fixture.policy_digest)
        .bind(b"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert policy");
        sqlx::query(
            "INSERT INTO repositories (id, tenant_id, owner, name, repository_url, default_branch) VALUES ($1, $2, 'acme', $3, $4, 'main')",
        )
        .bind(repository_id)
        .bind(fixture.tenant_id)
        .bind(format!("repo-{}", repository_id.simple()))
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert repository");
        sqlx::query(
            "INSERT INTO source_snapshots (id, tenant_id, repository_id, source_system, external_id, source_revision, normalized_content, content_digest, connector_identity, source_updated_at) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', $6)",
        )
        .bind(snapshot_id)
        .bind(fixture.tenant_id)
        .bind(repository_id)
        .bind(format!("item-{}", fixture.work_item_id))
        .bind(digest('c'))
        .bind(fixture.occurred_at)
        .execute(&mut *transaction)
        .await
        .expect("insert source snapshot");
        sqlx::query(
            "INSERT INTO work_items (id, tenant_id, source_snapshot_id, source_system, source_external_id, repository_id, state, closure_target, risk_class, policy_digest, budget_limits, identity_requirements, owner_fallback, normalized_priority, discovered_at, accepted_at) VALUES ($1, $2, $3, 'API', $4, $5, 'RUNNING', 'pull_request', 'low', $6, $7, $8, 'team:platform', 50, $9, $9)",
        )
        .bind(fixture.work_item_id)
        .bind(fixture.tenant_id)
        .bind(snapshot_id)
        .bind(format!("item-{}", fixture.work_item_id))
        .bind(repository_id)
        .bind(&fixture.policy_digest)
        .bind(budget_limits())
        .bind(identity_requirements())
        .bind(fixture.occurred_at)
        .execute(&mut *transaction)
        .await
        .expect("insert accepted work item");
        sqlx::query(
            "INSERT INTO workflow_instances (id, tenant_id, work_item_id, workflow_type, state, reducer_version) VALUES ($1, $2, $3, 'RUNMILL_OBSERVATION_TEST', 'ACTIVE', 'v1')",
        )
        .bind(fixture.workflow_instance_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert observation workflow");
        sqlx::query(
            "INSERT INTO attempts (id, tenant_id, work_item_id, ordinal, state, idempotency_key, base_ref, base_sha, source_snapshot_digest, policy_digest) VALUES ($1, $2, $3, 1, 'AUTHORIZED', $4, 'main', $5, $6, $7)",
        )
        .bind(fixture.attempt_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!("attempt-{}", fixture.attempt_id))
        .bind("a".repeat(40))
        .bind(digest('d'))
        .bind(&fixture.policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert attempt");
        sqlx::query(
            "UPDATE work_items SET current_attempt_id = $3, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .execute(&mut *transaction)
        .await
        .expect("bind observation work item to its current attempt");
        sqlx::query(
            "INSERT INTO work_orders (id, tenant_id, work_item_id, attempt_id, schema_version, envelope_schema, algorithm, key_id, idempotency_key, payload_digest, canonical_payload, payload, signature, exact_signed_envelope, issued_at, not_before, expires_at) VALUES ($1, $2, $3, $4, 'v1', 'envelope-v1', 'EdDSA', 'key-1', $5, $6, $7, '{}'::jsonb, 'signature', $8, $9, $9, $10)",
        )
        .bind(fixture.work_order_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("{}/{}/{}", fixture.tenant_id, fixture.work_item_id, fixture.attempt_id))
        .bind(&fixture.work_order_digest)
        .bind(b"{}".as_slice())
        .bind(b"exact signed envelope".as_slice())
        .bind(fixture.occurred_at)
        .bind(fixture.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert Work Order");
        sqlx::query("UPDATE attempts SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(fixture.attempt_id)
            .bind(&fixture.work_order_digest)
            .execute(&mut *transaction)
            .await
            .expect("bind Work Order to attempt");
        sqlx::query(
            "INSERT INTO workers (id, tenant_id, name, endpoint, generation, signing_key_id, signing_public_key) VALUES ($1, $2, $3, $4, 3, 'key-1', 'public-key')",
        )
        .bind(fixture.worker_id)
        .bind(fixture.tenant_id)
        .bind(format!("worker-{}", fixture.worker_id))
        .bind(format!("local://{}", fixture.worker_id))
        .execute(&mut *transaction)
        .await
        .expect("insert worker");
        sqlx::query(
            "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, expires_at) VALUES ($1, $2, $3, 3, $4)",
        )
        .bind(fixture.worker_session_id)
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id)
        .bind(fixture.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert active worker session");
        sqlx::query(
            "INSERT INTO runs (id, tenant_id, work_item_id, attempt_id, work_order_id, worker_id, worker_generation, worker_session_id, evidence_expectation_digest, external_run_id, state) VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8, $9, 'ADOPTED')",
        )
        .bind(fixture.run_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.work_order_id)
        .bind(fixture.worker_id)
        .bind(fixture.worker_session_id)
        .bind(digest('e'))
        .bind(&fixture.external_run_id)
        .execute(&mut *transaction)
        .await
        .expect("insert authoritative run");
        sqlx::query(
            "UPDATE worker_sessions SET status = 'CLOSED', closed_at = clock_timestamp(), close_reason = 'observer session rotation' WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.worker_session_id)
        .execute(&mut *transaction)
        .await
        .expect("close immutable run-admission session before observer rotation");
        sqlx::query(
            "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, expires_at) VALUES ($1, $2, $3, 3, $4)",
        )
        .bind(fixture.observer_session_id)
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id)
        .bind(fixture.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert live observer control session");
        sqlx::query(
            "INSERT INTO accountability_anchors (tenant_id, work_item_id, anchor_type, reference_id, authority_or_effect_active) VALUES ($1, $2, 'RUN', $3, true)",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.run_id)
        .execute(&mut *transaction)
        .await
        .expect("anchor accepted work to its authoritative run");
        sqlx::query(
            "INSERT INTO runmill_run_observation_streams (tenant_id, run_id, workflow_instance_id, work_item_id, attempt_id, work_order_id, work_order_digest, worker_id, worker_generation, run_admission_worker_session_id, external_run_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 3, $9, $10)",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(fixture.work_order_id)
        .bind(&fixture.work_order_digest)
        .bind(fixture.worker_id)
        .bind(fixture.worker_session_id)
        .bind(&fixture.external_run_id)
        .execute(&mut *transaction)
        .await
        .expect("insert idle durable Runmill observation stream");
        let payload = json!({
            "schema": "asf.runmill-observation/v2",
            "observation_id": fixture.observation_id.to_string(),
            "run_id": fixture.run_id.to_string(),
            "work_order_id": fixture.work_order_id.to_string(),
            "work_order_digest": fixture.work_order_digest,
            "worker_id": fixture.worker_id.to_string(),
            "worker_session_id": fixture.worker_session_id.to_string(),
            "worker_generation": 3,
            "external_run_id": fixture.external_run_id,
            "after_sequence": 0,
            "observation_epoch": 1,
            "observer_session_id": fixture.observer_session_id.to_string(),
        });
        sqlx::query(
            "INSERT INTO workflow_jobs (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type, activity_contract_id, status, payload, idempotency_key, max_attempts) VALUES ($1, $2, $3, $4, $5, 'OBSERVE_RUNMILL_RUN', $6, 'PENDING', $7, $8, 3)",
        )
        .bind(fixture.job_id)
        .bind(fixture.tenant_id)
        .bind(fixture.workflow_instance_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .bind(payload)
        .bind(format!("observe-{}", fixture.job_id))
        .execute(&mut *transaction)
        .await
        .expect("insert pending V2 observation job");
        sqlx::query(
            "INSERT INTO runmill_run_observation_checkpoints (id, tenant_id, run_id, workflow_job_id, after_sequence, observation_epoch, observer_session_id, worker_id, worker_generation) VALUES ($1, $2, $3, $4, 0, 1, $5, $6, 3)",
        )
        .bind(fixture.observation_id)
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.job_id)
        .bind(fixture.observer_session_id)
        .bind(fixture.worker_id)
        .execute(&mut *transaction)
        .await
        .expect("insert immutable V2 observation checkpoint");
        sqlx::query(
            "UPDATE runmill_run_observation_streams SET observation_epoch = 1, active_job_id = $3, active_observation_id = $4, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND run_id = $2 AND aggregate_version = 1",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(fixture.job_id)
        .bind(fixture.observation_id)
        .execute(&mut *transaction)
        .await
        .expect("activate V2 observation checkpoint");
        sqlx::query(
            "UPDATE workflow_jobs SET status = 'RUNNING', attempt_count = 1, fence_token = 1, lease_owner = $3, lease_expires_at = $4, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.job_id)
        .bind(&fixture.lease_owner)
        .bind(fixture.occurred_at + Duration::minutes(5))
        .execute(&mut *transaction)
        .await
        .expect("claim active V2 observation job");
        transaction
            .commit()
            .await
            .expect("commit observation fixture");
        fixture
    }

    fn fence(&self) -> RunmillObservationFence {
        RunmillObservationFence {
            tenant_id: self.tenant_id,
            run_id: self.run_id,
            work_item_id: self.work_item_id,
            attempt_id: self.attempt_id,
            work_order_id: self.work_order_id,
            work_order_digest: self.work_order_digest.clone(),
            workflow_job_id: self.job_id,
            workflow_job_fence_token: 1,
            workflow_job_attempt_count: 1,
            workflow_job_owner: self.lease_owner.clone(),
            worker_session_id: self.worker_session_id,
            observer_session_id: self.observer_session_id,
            observation_id: self.observation_id,
            requested_after_sequence: 0,
            observation_epoch: 1,
            worker_id: self.worker_id,
            worker_generation: 3,
            external_run_id: self.external_run_id.clone(),
        }
    }

    async fn reclaim_observation_fence(&self, ledger: &PgLedger) -> RunmillObservationFence {
        let workflow_job_owner = format!("{}:reclaimed", self.lease_owner);
        let result = sqlx::query(
            "UPDATE workflow_jobs SET attempt_count = 2, fence_token = 2, lease_owner = $3, lease_expires_at = $4 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.job_id)
        .bind(&workflow_job_owner)
        .bind(Utc::now().trunc_subsecs(6) + Duration::minutes(5))
        .execute(ledger.pool())
        .await
        .expect("reclaim live Runmill observation job");
        assert_eq!(
            result.rows_affected(),
            1,
            "reclaim the exact observation job"
        );

        let mut fence = self.fence();
        fence.workflow_job_fence_token = 2;
        fence.workflow_job_attempt_count = 2;
        fence.workflow_job_owner = workflow_job_owner;
        fence
    }

    fn get_run_snapshot(&self) -> IncomingRunmillControlSnapshot {
        let raw_snapshot = json!({
            "run": {
                "runId": self.external_run_id,
                "issueId": format!("item-{}", self.work_item_id),
                "repo": "acme/repository",
                "provider": "github",
                "state": "REPOSITORY_LEASED",
                "workOrderId": self.work_order_id.to_string(),
                "attemptId": self.attempt_id.to_string(),
                "generation": 3,
                "stateVersion": 1,
                "attempt": 1,
                "baseCommit": "a".repeat(40),
                "candidateSha": null,
                "branch": null,
                "mode": "asf-worker",
                "ownerId": null,
                "heartbeatAt": self.occurred_at.to_rfc3339(),
            },
            "latestSequence": 1,
            "admission": {
                "idempotencyKey": format!("{}/{}/{}", self.tenant_id, self.work_item_id, self.attempt_id),
                "workOrderId": self.work_order_id.to_string(),
                "attemptId": self.attempt_id.to_string(),
                "tenantId": self.tenant_id.to_string(),
                "payloadDigest": self.work_order_digest,
                "envelopeDigest": self.envelope_digest,
                "effectivePolicyDigest": self.policy_digest,
                "signatureKeyId": "key-1",
                "signatureAlgorithm": "EdDSA",
                "acceptedAt": self.occurred_at.to_rfc3339(),
            },
        });
        IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 1,
            operation: RunmillControlOperation::GetRun,
            external_generation: 3,
            external_state_version: 1,
            external_latest_sequence: 1,
            observed_at: self.occurred_at,
            admission: Some(RunmillAdmissionProvenance {
                idempotency_key: format!(
                    "{}/{}/{}",
                    self.tenant_id, self.work_item_id, self.attempt_id
                ),
                envelope_digest: self.envelope_digest.clone(),
                effective_policy_digest: self.policy_digest.clone(),
            }),
            raw_response_bytes: successful_response_bytes(&raw_snapshot),
            raw_snapshot,
            events: vec![],
        }
    }

    fn list_run_events_snapshot(
        &self,
        event: IncomingRunmillControlEvent,
    ) -> IncomingRunmillControlSnapshot {
        let retained_event = event.raw_event.clone();
        let raw_snapshot = json!({
            "snapshot": {
                "run": {
                    "runId": self.external_run_id,
                    "issueId": format!("item-{}", self.work_item_id),
                    "repo": "acme/repository",
                    "provider": "github",
                    "state": "REPOSITORY_LEASED",
                    "workOrderId": self.work_order_id.to_string(),
                    "attemptId": self.attempt_id.to_string(),
                    "generation": 3,
                    "stateVersion": 1,
                    "attempt": 1,
                    "baseCommit": "a".repeat(40),
                    "candidateSha": null,
                    "branch": null,
                    "mode": "asf-worker",
                    "ownerId": null,
                    "heartbeatAt": self.occurred_at.to_rfc3339(),
                },
                "latestSequence": 1,
            },
            "events": [retained_event],
            "nextCursor": 1,
            "hasMore": false,
            "gap": false,
            "compactedThrough": null,
        });
        IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 2,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: 3,
            external_state_version: 1,
            external_latest_sequence: 1,
            observed_at: self.occurred_at + Duration::seconds(1),
            admission: None,
            raw_response_bytes: successful_response_bytes(&raw_snapshot),
            raw_snapshot,
            events: vec![event],
        }
    }

    fn event(
        &self,
        external_event_id: &str,
        sequence: u64,
        event_type: &str,
    ) -> IncomingRunmillControlEvent {
        let occurred_at = self.occurred_at
            + Duration::seconds(i64::try_from(sequence).expect("test event sequence fits i64"));
        let raw_event = json!({
            "schema": "asf.run-event/v1",
            "event_id": external_event_id,
            "run_id": self.external_run_id,
            "work_order_id": self.work_order_id.to_string(),
            "attempt_id": self.attempt_id.to_string(),
            "seq": sequence,
            "type": event_type,
            "phase": "REPOSITORY_LEASED",
            "occurred_at": occurred_at.to_rfc3339(),
            "policy_digest": self.policy_digest,
            "payload": {
                "repository": "acme/repository",
                "generation": 3,
            },
        });
        IncomingRunmillControlEvent {
            id: Uuid::now_v7(),
            external_event_id: external_event_id.into(),
            sequence,
            event_type: event_type.into(),
            occurred_at,
            raw_event,
        }
    }
}

#[tokio::test]
async fn concurrent_replays_of_one_active_checkpoint_share_one_control_event() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let first_fence = fixture.fence();
    let event = fixture.event("run-event-overlap", 1, "repository.lease_acquired");
    let first_page = fixture.list_run_events_snapshot(event.clone());
    let reconnect_page = first_page.clone();

    let barrier = Arc::new(Barrier::new(3));
    let first_task = concurrent_observation_task(
        database.ledger.pool().clone(),
        barrier.clone(),
        first_fence.clone(),
        first_page.clone(),
        "first overlapping event-page observation",
    );
    let reconnect_task = concurrent_observation_task(
        database.ledger.pool().clone(),
        barrier.clone(),
        first_fence,
        reconnect_page.clone(),
        "reconnect overlapping event-page observation",
    );
    barrier.wait().await;

    let (first_task_result, reconnect_task_result) = tokio::join!(first_task, reconnect_task);
    let first = first_task_result
        .expect("first overlapping observation task must not panic")
        .expect("first overlapping observation transaction must succeed");
    let reconnect = reconnect_task_result
        .expect("reconnect overlapping observation task must not panic")
        .expect("reconnect overlapping observation transaction must succeed");
    assert_ne!(first.snapshot_inserted, reconnect.snapshot_inserted);
    assert_eq!(
        first.inserted_event_count + reconnect.inserted_event_count,
        1
    );
    assert_eq!(first.linked_event_count + reconnect.linked_event_count, 1);

    let normalized_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count normalized remote events after reconnect");
    let (stored_event_id, first_snapshot_id, stored_raw_event): (Uuid, Uuid, Value) =
        sqlx::query_as(
            "SELECT id, first_snapshot_id, raw_event FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2 AND external_event_id = $3",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .bind(&event.external_event_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("load immutable normalized event after reconnect");
    let association_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(stored_event_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count event-page associations after reconnect");
    let distinct_snapshot_count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT snapshot_id) FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(stored_event_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count distinct retained pages for overlapping remote event");

    assert_eq!(normalized_event_count, 1);
    assert_eq!(association_count, 1);
    assert_eq!(distinct_snapshot_count, 1);
    assert_eq!(stored_event_id, event.id);
    assert_eq!(first_snapshot_id, first_page.id);
    assert_eq!(stored_raw_event, event.raw_event);

    database.cleanup().await;
}

fn concurrent_observation_task(
    pool: PgPool,
    barrier: Arc<Barrier>,
    fence: RunmillObservationFence,
    incoming: IncomingRunmillControlSnapshot,
    description: &'static str,
) -> tokio::task::JoinHandle<Result<RunmillControlObservationOutcome, String>> {
    tokio::spawn(async move {
        let transaction = pool.begin().await;
        barrier.wait().await;
        let mut transaction =
            transaction.map_err(|error| format!("begin {description}: {error}"))?;
        let outcome = record_runmill_control_observation(&mut transaction, &fence, &incoming)
            .await
            .map_err(|error| format!("record {description}: {error}"))?;
        transaction
            .commit()
            .await
            .map_err(|error| format!("commit {description}: {error}"))?;
        Ok(outcome)
    })
}

#[tokio::test]
async fn runmill_control_observation_is_fenced_idempotent_append_only_and_read_only() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let fence = fixture.fence();
    let before_run: (String, Option<Value>, i64, i64) = sqlx::query_as(
        "SELECT state, snapshot, last_event_sequence, aggregate_version FROM runs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load unprojected run");

    let get_run = fixture.get_run_snapshot();
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin get-run observation");
    let stored = record_runmill_control_observation(&mut transaction, &fence, &get_run)
        .await
        .expect("store exact get-run raw bytes");
    assert!(stored.snapshot_inserted);
    assert_eq!(stored.inserted_event_count, 0);
    assert_eq!(stored.linked_event_count, 0);
    transaction
        .commit()
        .await
        .expect("commit get-run observation");
    let retained_get_run_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT raw_response_bytes FROM runmill_control_snapshots WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(get_run.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load exact get-run response bytes");
    assert_eq!(retained_get_run_bytes, get_run.raw_response_bytes);
    assert_eq!(retained_get_run_bytes.last(), Some(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<Value>(&retained_get_run_bytes)
            .expect("decode retained get-run success envelope"),
        json!({"ok": true, "data": get_run.raw_snapshot}),
    );
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin exact get-run replay");
    let replay = record_runmill_control_observation(&mut transaction, &fence, &get_run)
        .await
        .expect("replay exact get-run observation");
    assert!(!replay.snapshot_inserted);
    assert_eq!(replay.inserted_event_count, 0);
    assert_eq!(replay.linked_event_count, 0);
    transaction
        .commit()
        .await
        .expect("commit exact get-run replay");

    let mut crash_replay = get_run.clone();
    crash_replay.id = Uuid::now_v7();
    crash_replay.observed_at += Duration::seconds(1);
    crash_replay.raw_response_bytes =
        reordered_successful_response_bytes(&crash_replay.raw_snapshot);
    assert_ne!(crash_replay.raw_response_bytes, get_run.raw_response_bytes);
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin crash-style get-run replay");
    let replay = record_runmill_control_observation(&mut transaction, &fence, &crash_replay)
        .await
        .expect("recover an already-stored semantic get-run observation");
    assert!(!replay.snapshot_inserted);
    assert_eq!(replay.snapshot_id, get_run.id);
    assert_eq!(replay.inserted_event_count, 0);
    assert_eq!(replay.linked_event_count, 0);
    transaction
        .commit()
        .await
        .expect("commit crash-style get-run replay");
    let replayed_snapshot_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1")
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count exact get-run replay");
    assert_eq!(replayed_snapshot_count, 1);

    let event = fixture.event("run-event-1", 1, "repository.lease_acquired");
    let list_events = fixture.list_run_events_snapshot(event.clone());
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin list-events observation");
    let stored = record_runmill_control_observation(&mut transaction, &fence, &list_events)
        .await
        .expect("store list-run-events snake_case event");
    assert!(stored.snapshot_inserted);
    assert_eq!(stored.inserted_event_count, 1);
    assert_eq!(stored.linked_event_count, 1);
    transaction
        .commit()
        .await
        .expect("commit list-events observation");

    let snapshot_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1")
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count control snapshots");
    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count retained control events");
    let projected_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count projected run events");
    assert_eq!(snapshot_count, 2);
    assert_eq!(event_count, 1);
    let original_link_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(event.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count original retained response-page event link");
    assert_eq!(original_link_count, 1);
    assert_eq!(
        projected_event_count, 0,
        "observer must not project raw run events"
    );
    let after_run: (String, Option<Value>, i64, i64) = sqlx::query_as(
        "SELECT state, snapshot, last_event_sequence, aggregate_version FROM runs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load run after observation");
    assert_eq!(
        after_run, before_run,
        "observer must not mutate the run projection"
    );

    let mut contradictory = fixture.get_run_snapshot();
    contradictory.control_sequence = 3;
    contradictory.external_state_version = 3;
    contradictory.external_latest_sequence = 3;
    expect_observation_failure(
        &database.ledger,
        &fence,
        &contradictory,
        "indexed provenance contradicts its validated response",
    )
    .await;

    let mut stale_fence = fence.clone();
    stale_fence.workflow_job_fence_token = 2;
    expect_observation_failure(
        &database.ledger,
        &stale_fence,
        &fixture.get_run_snapshot(),
        "lacks its exact live observation stream claim",
    )
    .await;
    let mut wrong_cursor = fence.clone();
    wrong_cursor.requested_after_sequence = 1;
    expect_observation_failure(
        &database.ledger,
        &wrong_cursor,
        &list_events,
        "contradicts its scheduled cursor or page limit",
    )
    .await;
    let mut wrong_session = fence.clone();
    wrong_session.worker_session_id = Uuid::now_v7();
    expect_observation_failure(
        &database.ledger,
        &wrong_session,
        &fixture.get_run_snapshot(),
        "identity was reused for different semantics",
    )
    .await;
    let mut wrong_run = fence.clone();
    wrong_run.run_id = Uuid::now_v7();
    expect_observation_failure(
        &database.ledger,
        &wrong_run,
        &fixture.get_run_snapshot(),
        "identity was reused for different semantics",
    )
    .await;

    let mut changed_event = fixture.event("run-event-1", 1, "repository.lease_acquired");
    changed_event.raw_event["payload"]["generation"] = json!(4);
    let candidate_event_id = changed_event.id;
    let mut changed_event_id = fixture.list_run_events_snapshot(changed_event);
    changed_event_id.control_sequence = 4;
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin committed semantic event collision");
    let error = record_runmill_control_observation(&mut transaction, &fence, &changed_event_id)
        .await
        .expect_err("reused remote event identity must conflict");
    assert!(
        error
            .to_string()
            .contains("identity was reused for different semantics")
    );
    transaction
        .commit()
        .await
        .expect("commit outer transaction after savepoint rollback");
    let candidate_snapshot_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(changed_event_id.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count rolled-back candidate snapshot");
    let candidate_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM raw_runmill_control_events WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(candidate_event_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count rolled-back candidate event");
    let candidate_link_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND snapshot_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(changed_event_id.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count rolled-back candidate links");
    assert_eq!(candidate_snapshot_count, 0);
    assert_eq!(candidate_event_count, 0);
    assert_eq!(candidate_link_count, 0);
    let changed_event = fixture.event("run-event-2", 1, "repository.lease_acquired");
    let mut changed_sequence = fixture.list_run_events_snapshot(changed_event);
    changed_sequence.control_sequence = 5;
    expect_observation_conflict(&database.ledger, &fence, &changed_sequence).await;

    let reclaimed_fence = fixture.reclaim_observation_fence(&database.ledger).await;
    let mut reclaimed_list_events = fixture.list_run_events_snapshot(event.clone());
    reclaimed_list_events.control_sequence = 1;
    reclaimed_list_events.observed_at += Duration::seconds(2);
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin reclaimed list-events observation");
    let reclaimed = record_runmill_control_observation(
        &mut transaction,
        &reclaimed_fence,
        &reclaimed_list_events,
    )
    .await
    .expect("re-observe the same remote event under a reclaimed fence");
    assert!(reclaimed.snapshot_inserted);
    assert_eq!(reclaimed.inserted_event_count, 0);
    assert_eq!(reclaimed.linked_event_count, 1);
    transaction
        .commit()
        .await
        .expect("commit reclaimed list-events observation");

    let mut stale_get_run_replay = get_run.clone();
    stale_get_run_replay.id = Uuid::now_v7();
    stale_get_run_replay.observed_at += Duration::seconds(3);
    stale_get_run_replay.raw_response_bytes =
        reordered_successful_response_bytes(&stale_get_run_replay.raw_snapshot);
    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin stale-fence complete get-run replay");
    let stale_replay =
        record_runmill_control_observation(&mut transaction, &fence, &stale_get_run_replay)
            .await
            .expect("replay a complete historical observation after its fence was reclaimed");
    assert!(!stale_replay.snapshot_inserted);
    assert_eq!(stale_replay.snapshot_id, get_run.id);
    assert_eq!(stale_replay.inserted_event_count, 0);
    assert_eq!(stale_replay.linked_event_count, 0);
    transaction
        .commit()
        .await
        .expect("commit stale-fence complete get-run replay");
    let reclaimed_snapshot_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runmill_control_snapshots WHERE tenant_id = $1")
            .bind(fixture.tenant_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count snapshots after reclaimed observation");
    let reclaimed_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM raw_runmill_control_events WHERE tenant_id = $1 AND run_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count remote events after reclaimed observation");
    let reclaimed_link_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(event.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count response-page links after reclaimed observation");
    assert_eq!(reclaimed_snapshot_count, 3);
    assert_eq!(reclaimed_event_count, 1);
    assert_eq!(reclaimed_link_count, 2);

    let snapshot_update = sqlx::query("UPDATE runmill_control_snapshots SET observed_at = observed_at + interval '1 second' WHERE tenant_id = $1 AND id = $2")
        .bind(fixture.tenant_id)
        .bind(get_run.id)
        .execute(database.ledger.pool())
        .await
        .expect_err("control snapshots must be append-only");
    assert!(snapshot_update.to_string().contains("append-only"));
    let snapshot_event_update = sqlx::query("UPDATE runmill_control_snapshot_events SET page_ordinal = 1 WHERE tenant_id = $1 AND snapshot_id = $2 AND event_id = $3")
        .bind(fixture.tenant_id)
        .bind(list_events.id)
        .bind(event.id)
        .execute(database.ledger.pool())
        .await
        .expect_err("response-page event links must be append-only");
    assert!(snapshot_event_update.to_string().contains("append-only"));
    let snapshot_event_delete = sqlx::query("DELETE FROM runmill_control_snapshot_events WHERE tenant_id = $1 AND snapshot_id = $2 AND event_id = $3")
        .bind(fixture.tenant_id)
        .bind(list_events.id)
        .bind(event.id)
        .execute(database.ledger.pool())
        .await
        .expect_err("response-page event links must be append-only");
    assert!(snapshot_event_delete.to_string().contains("append-only"));
    let invalid_link = sqlx::query("INSERT INTO runmill_control_snapshot_events (tenant_id, snapshot_id, event_id, page_ordinal) VALUES ($1, $2, $3, 0)")
        .bind(fixture.tenant_id)
        .bind(get_run.id)
        .bind(event.id)
        .execute(database.ledger.pool())
        .await
        .expect_err("a GET response cannot be linked to an event page row");
    assert!(
        invalid_link
            .to_string()
            .contains("lacks its exact retained response page")
    );
    let event_delete =
        sqlx::query("DELETE FROM raw_runmill_control_events WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(event.id)
            .execute(database.ledger.pool())
            .await
            .expect_err("control events must be append-only");
    assert!(event_delete.to_string().contains("append-only"));

    database.cleanup().await;
}

async fn expect_observation_failure(
    ledger: &PgLedger,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
    expected: &str,
) {
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin rejected observation");
    let error = record_runmill_control_observation(&mut transaction, fence, incoming)
        .await
        .expect_err("observation must be rejected");
    assert!(
        error.to_string().contains(expected),
        "unexpected error: {error}"
    );
    transaction
        .rollback()
        .await
        .expect("rollback rejected observation");
}

async fn expect_observation_conflict(
    ledger: &PgLedger,
    fence: &RunmillObservationFence,
    incoming: &IncomingRunmillControlSnapshot,
) {
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin conflicting observation");
    let error = record_runmill_control_observation(&mut transaction, fence, incoming)
        .await
        .expect_err("reused per-run event identity must conflict");
    assert!(
        error
            .to_string()
            .contains("identity was reused for different semantics")
    );
    transaction
        .rollback()
        .await
        .expect("rollback conflicting observation");
}

fn budget_limits() -> Value {
    json!({
        "max_cost_microunits": 1_000_000,
        "max_input_tokens": 100_000,
        "max_output_tokens": 100_000,
        "max_implementer_invocations": 2,
        "max_reviewer_invocations": 2,
        "max_fix_iterations": 1,
        "max_wall_time_seconds": 3_600,
        "max_external_api_calls": 10,
    })
}

fn identity_requirements() -> Value {
    json!({
        "implementer": "codex:implementer",
        "local_reviewer": "claude:local-reviewer",
        "pr_reviewer": "claude:pr-reviewer",
    })
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn successful_response_bytes(raw_snapshot: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"ok": true, "data": raw_snapshot}))
        .expect("serialize complete Runmill success envelope");
    bytes.push(b'\n');
    bytes
}

fn reordered_successful_response_bytes(raw_snapshot: &Value) -> Vec<u8> {
    format!(
        "{{\"data\":{},\"ok\":true}}\n",
        serde_json::to_string(raw_snapshot).expect("serialize reordered Runmill success data")
    )
    .into_bytes()
}
