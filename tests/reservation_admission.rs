use std::{str::FromStr as _, sync::Arc, time::Duration as StdDuration};

use asf::{
    Error,
    api::{ApiBackend as _, PostgresApiBackend},
    domain::{CtxlaneProfileRef, TenantId},
    ledger::{
        AdmissionDisposition, AdmissionReservationRequest, BudgetReservationAmounts,
        IdentityCapacityRequest, PgLedger, ReservationTerminalState,
        ReservationTransitionDisposition, ReservationTransitionRequest,
    },
    runtime::{
        ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID, HandlerRegistry, ReactorOptions,
        ReactorPollReport, ReactorRuntime,
    },
};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::{Barrier, oneshot};
use url::Url;
use uuid::Uuid;

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect reservation-test administrator");
        let schema = format!("asf_reservation_test_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated reservation-test schema");

        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated reservation ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated reservation schema");
        let current_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(ledger.pool())
            .await
            .expect("read reservation-test schema");
        assert_eq!(current_schema, schema);
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
            .expect("drop isolated reservation-test schema");
        self.admin.close().await;
    }
}

#[derive(Clone, Copy)]
struct WorkFixture {
    work_item_id: Uuid,
    attempt_id: Uuid,
}

struct Fixture {
    tenant_id: Uuid,
    repository_id: Uuid,
    worker_id: Uuid,
    worker_session_id: Uuid,
    work: Vec<WorkFixture>,
}

impl Fixture {
    async fn insert(ledger: &PgLedger, work_count: usize) -> Self {
        Self::insert_with_worker_capacity(ledger, work_count, 1).await
    }

    async fn insert_with_worker_capacity(
        ledger: &PgLedger,
        work_count: usize,
        worker_capacity: i32,
    ) -> Self {
        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let worker_id = Uuid::now_v7();
        let worker_session_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let policy_digest = digest('a');
        let snapshot_digest = digest('b');
        let mut transaction = ledger.pool().begin().await.expect("begin fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("reservation-{tenant_id}"))
            .bind("Reservation integration tenant")
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch,
                active, wip_limit
            ) VALUES ($1, $2, 'acme', 'widget', $3, 'main', true, 1)
            ",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert repository");
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
        .expect("insert policy");
        sqlx::query(
            r"
            INSERT INTO workers (
                id, tenant_id, name, endpoint, status, generation,
                max_concurrency, signing_key_id, signing_public_key
            ) VALUES ($1, $2, 'worker-1', 'unix:///run/test.sock', 'READY', 1,
                      $3, 'worker-key', 'public-key')
            ",
        )
        .bind(worker_id)
        .bind(tenant_id)
        .bind(worker_capacity)
        .execute(&mut *transaction)
        .await
        .expect("insert worker");
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '1 hour')
            ",
        )
        .bind(worker_session_id)
        .bind(tenant_id)
        .bind(worker_id)
        .execute(&mut *transaction)
        .await
        .expect("insert worker session");
        for profile in [
            "codex:implementer",
            "claude:local-reviewer",
            "codex:pr-reviewer",
        ] {
            sqlx::query(
                "INSERT INTO identity_capacity_limits \
                 (tenant_id, profile_ref, capacity, generation) VALUES ($1, $2, 1, 1)",
            )
            .bind(tenant_id)
            .bind(profile)
            .execute(&mut *transaction)
            .await
            .expect("insert identity capacity");
        }

        let mut work = Vec::new();
        for ordinal in 0..work_count {
            let work_item_id = Uuid::now_v7();
            let attempt_id = Uuid::now_v7();
            let snapshot_id = Uuid::now_v7();
            let workflow_id = Uuid::now_v7();
            sqlx::query(
                r"
                INSERT INTO source_snapshots (
                    id, tenant_id, repository_id, source_system, external_id,
                    source_revision, normalized_content, content_digest,
                    connector_identity, source_updated_at
                ) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5,
                          'test:connector', clock_timestamp())
                ",
            )
            .bind(snapshot_id)
            .bind(tenant_id)
            .bind(repository_id)
            .bind(format!("reservation-item-{work_item_id}"))
            .bind(&snapshot_digest)
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
                    current_attempt_id, accepted_at
                ) VALUES (
                    $1, $2, $3, 'API', $4, $5, 'ACCEPTED', 'pull_request',
                    'low', $6, $7, $8, 'team:platform', 50, $9,
                    clock_timestamp()
                )
                ",
            )
            .bind(work_item_id)
            .bind(tenant_id)
            .bind(snapshot_id)
            .bind(format!("reservation-item-{work_item_id}"))
            .bind(repository_id)
            .bind(&policy_digest)
            .bind(budget_limits())
            .bind(identity_requirements())
            .bind(attempt_id)
            .execute(&mut *transaction)
            .await
            .expect("insert accepted work item");
            sqlx::query(
                r"
                INSERT INTO attempts (
                    id, tenant_id, work_item_id, ordinal, state,
                    idempotency_key, base_ref, base_sha,
                    source_snapshot_digest, policy_digest
                ) VALUES ($1, $2, $3, $4, 'CREATED', $5, 'main', $6, $7, $8)
                ",
            )
            .bind(attempt_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(i32::try_from(ordinal + 1).expect("fixture ordinal fits i32"))
            .bind(format!("attempt:{attempt_id}"))
            .bind("1".repeat(40))
            .bind(&snapshot_digest)
            .bind(&policy_digest)
            .execute(&mut *transaction)
            .await
            .expect("insert attempt");
            sqlx::query(
                "INSERT INTO workflow_instances \
                 (id, tenant_id, work_item_id, workflow_type, reducer_version) \
                 VALUES ($1, $2, $3, 'delivery', 'v1')",
            )
            .bind(workflow_id)
            .bind(tenant_id)
            .bind(work_item_id)
            .execute(&mut *transaction)
            .await
            .expect("insert workflow");
            sqlx::query(
                r"
                INSERT INTO workflow_jobs (
                    id, tenant_id, workflow_instance_id, work_item_id,
                    attempt_id, job_type, activity_contract_id, payload, idempotency_key
                ) VALUES ($1, $2, $3, $4, $5, 'ADVANCE_ACCEPTED_WORK_ITEM',
                          $6, '{}'::jsonb, $7)
                ",
            )
            .bind(Uuid::now_v7())
            .bind(tenant_id)
            .bind(workflow_id)
            .bind(work_item_id)
            .bind(attempt_id)
            .bind(ADVANCE_ACCEPTED_WORK_ITEM_ACTIVITY_CONTRACT_ID)
            .bind(format!("reservation-progress:{work_item_id}"))
            .execute(&mut *transaction)
            .await
            .expect("insert workflow progress job");
            sqlx::query(
                "INSERT INTO accountability_anchors \
                 (tenant_id, work_item_id, anchor_type, reference_id, generation) \
                 VALUES ($1, $2, 'WORKFLOW', $3, 1)",
            )
            .bind(tenant_id)
            .bind(work_item_id)
            .bind(workflow_id)
            .execute(&mut *transaction)
            .await
            .expect("insert accountability anchor");
            work.push(WorkFixture {
                work_item_id,
                attempt_id,
            });
        }
        transaction.commit().await.expect("commit fixture");
        Self {
            tenant_id,
            repository_id,
            worker_id,
            worker_session_id,
            work,
        }
    }

    fn request(&self, index: usize, key: &str) -> AdmissionReservationRequest {
        let work = self.work[index];
        AdmissionReservationRequest {
            reservation_set_id: Uuid::now_v7(),
            tenant_id: self.tenant_id,
            work_item_id: work.work_item_id,
            attempt_id: work.attempt_id,
            repository_id: self.repository_id,
            expected_repository_generation: 1,
            worker_id: self.worker_id,
            worker_session_id: self.worker_session_id,
            expected_worker_generation: 1,
            identities: identity_requests(),
            budget: budget_request(),
            expires_at: Utc::now() + Duration::minutes(5),
            actor_id: "scheduler:integration-test".into(),
            idempotency_key: format!("{key}:{}", self.tenant_id),
        }
    }
}

#[tokio::test]
async fn admission_requires_and_persists_the_exact_live_worker_session_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger, 4).await;

    let omitted_binding = sqlx::query(
        r"
        INSERT INTO reservation_sets (
            id, tenant_id, work_item_id, attempt_id, repository_id, worker_id,
            request_digest, idempotency_key, acquired_by, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            'hostile:direct-sql', clock_timestamp() + interval '5 minutes'
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.work[0].work_item_id)
    .bind(fixture.work[0].attempt_id)
    .bind(fixture.repository_id)
    .bind(fixture.worker_id)
    .bind(digest('d'))
    .bind(format!("omitted-worker-session:{}", fixture.tenant_id))
    .execute(database.ledger.pool())
    .await
    .expect_err("new direct reservation insert without a worker session must fail closed");
    assert_eq!(
        omitted_binding
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    let unrelated_worker_id = Uuid::now_v7();
    let unrelated_session_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workers (
            id, tenant_id, name, endpoint, status, generation,
            max_concurrency, signing_key_id, signing_public_key
        ) VALUES (
            $1, $2, $3, $4, 'READY', 1, 1, 'unrelated-key', 'public-key'
        )
        ",
    )
    .bind(unrelated_worker_id)
    .bind(fixture.tenant_id)
    .bind(format!("unrelated-{unrelated_worker_id}"))
    .bind(format!("local://{unrelated_worker_id}"))
    .execute(database.ledger.pool())
    .await
    .expect("insert unrelated worker");
    sqlx::query(
        r"
        INSERT INTO worker_sessions (
            id, tenant_id, worker_id, worker_generation, expires_at
        ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '1 hour')
        ",
    )
    .bind(unrelated_session_id)
    .bind(fixture.tenant_id)
    .bind(unrelated_worker_id)
    .execute(database.ledger.pool())
    .await
    .expect("insert unrelated worker session");

    let mut crossed = fixture.request(0, "crossed-worker-session");
    crossed.worker_session_id = unrelated_session_id;
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&crossed)
            .await,
        Err(Error::Conflict(_))
    ));

    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'CLOSED', closed_at = clock_timestamp(),
            close_reason = 'reservation admission test'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.worker_session_id)
    .execute(database.ledger.pool())
    .await
    .expect("close fixture worker session");
    let closed = fixture.request(1, "closed-worker-session");
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&closed)
            .await,
        Err(Error::Conflict(_))
    ));

    let expired_session_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO worker_sessions (
            id, tenant_id, worker_id, worker_generation, expires_at
        ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '1 second')
        ",
    )
    .bind(expired_session_id)
    .bind(fixture.tenant_id)
    .bind(fixture.worker_id)
    .execute(database.ledger.pool())
    .await
    .expect("insert soon-expiring worker session");
    tokio::time::sleep(StdDuration::from_millis(1_100)).await;
    let mut expired = fixture.request(2, "expired-worker-session");
    expired.worker_session_id = expired_session_id;
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&expired)
            .await,
        Err(Error::Conflict(_))
    ));

    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'CLOSED', closed_at = clock_timestamp(),
            close_reason = 'expired reservation admission test session'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(expired_session_id)
    .execute(database.ledger.pool())
    .await
    .expect("close expired worker session");
    let replacement_session_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO worker_sessions (
            id, tenant_id, worker_id, worker_generation, expires_at
        ) VALUES ($1, $2, $3, 1, clock_timestamp() + interval '1 hour')
        ",
    )
    .bind(replacement_session_id)
    .bind(fixture.tenant_id)
    .bind(fixture.worker_id)
    .execute(database.ledger.pool())
    .await
    .expect("insert replacement worker session");

    let mut too_long = fixture.request(0, "reservation-outlives-session");
    too_long.worker_session_id = replacement_session_id;
    too_long.expires_at = Utc::now() + Duration::hours(2);
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&too_long)
            .await,
        Err(Error::Conflict(_))
    ));
    let direct_too_long = sqlx::query(
        r"
        INSERT INTO reservation_sets (
            id, tenant_id, work_item_id, attempt_id, repository_id, worker_id,
            worker_session_id, worker_generation, request_digest,
            idempotency_key, acquired_by, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 1, $8, $9,
            'hostile:direct-sql', clock_timestamp() + interval '2 hours'
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.work[1].work_item_id)
    .bind(fixture.work[1].attempt_id)
    .bind(fixture.repository_id)
    .bind(fixture.worker_id)
    .bind(replacement_session_id)
    .bind(digest('e'))
    .bind(format!("direct-session-overrun:{}", fixture.tenant_id))
    .execute(database.ledger.pool())
    .await
    .expect_err("direct SQL cannot create a reservation beyond its session");
    assert_eq!(
        direct_too_long
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("reservation_sets_require_full_session_lifetime")
    );

    let mut exact = fixture.request(3, "exact-worker-session");
    exact.worker_session_id = replacement_session_id;
    let receipt = database
        .ledger
        .acquire_admission_reservations(&exact)
        .await
        .expect("admit exact live worker session");
    let persisted: (Uuid, i64) = sqlx::query_as(
        r"
        SELECT worker_session_id, worker_generation
        FROM reservation_sets
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load durable reservation worker-session binding");
    assert_eq!(persisted, (replacement_session_id, 1));

    let mut adopted = exact.clone();
    adopted.reservation_set_id = Uuid::now_v7();
    assert_eq!(
        database
            .ledger
            .acquire_admission_reservations(&adopted)
            .await
            .expect("adopt exact worker-session-bound admission")
            .disposition,
        AdmissionDisposition::Adopted
    );
    adopted.worker_session_id = unrelated_session_id;
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&adopted)
            .await,
        Err(Error::Conflict(_))
    ));

    let mut sever = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin active-session sever attempt");
    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'REVOKED', closed_at = clock_timestamp(),
            close_reason = 'hostile active-reservation sever'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(replacement_session_id)
    .execute(&mut *sever)
    .await
    .expect("stage session revocation for deferred reciprocal proof");
    assert!(
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *sever)
            .await
            .is_err(),
        "a session cannot be revoked while its reservation is ACTIVE"
    );
    sever
        .rollback()
        .await
        .expect("rollback active-session sever attempt");

    database
        .ledger
        .release_reservation_set(&ReservationTransitionRequest {
            tenant_id: fixture.tenant_id,
            reservation_set_id: receipt.reservation_set_id,
            expected_fence_token: receipt.fence_token,
            actor_id: "scheduler:session-lifetime-test".into(),
            reason: "release before worker-session close".into(),
            idempotency_key: format!("release-session-lifetime:{}", fixture.tenant_id),
        })
        .await
        .expect("release exact active reservation before session close");
    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'CLOSED', closed_at = clock_timestamp(),
            close_reason = 'reservation released'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(replacement_session_id)
    .execute(database.ledger.pool())
    .await
    .expect("close session after its reservation is terminal");

    database.cleanup().await;
}

#[tokio::test]
async fn reservations_are_atomic_race_safe_fenced_and_multidimensional_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger, 4).await;
    let first = fixture.request(0, "concurrent-first");
    let second = fixture.request(1, "concurrent-second");
    let barrier = Arc::new(Barrier::new(3));
    let first_task = {
        let ledger = database.ledger.clone();
        let request = first.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            ledger.acquire_admission_reservations(&request).await
        })
    };
    let second_task = {
        let ledger = database.ledger.clone();
        let request = second.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            ledger.acquire_admission_reservations(&request).await
        })
    };
    barrier.wait().await;
    let first_result = first_task.await.expect("join first admission");
    let second_result = second_task.await.expect("join second admission");
    let (winner, loser, receipt) = match (first_result, second_result) {
        (Ok(receipt), Err(Error::Conflict(_))) => (first, second, receipt),
        (Err(Error::Conflict(_)), Ok(receipt)) => (second, first, receipt),
        (left, right) => {
            panic!("expected one admission and one capacity conflict: {left:?} {right:?}")
        }
    };
    assert_eq!(receipt.disposition, AdmissionDisposition::Acquired);
    assert_eq!(receipt.resources.len(), 13);
    assert_eq!(count(&database.ledger, "reservation_sets").await, 1);
    assert_eq!(count(&database.ledger, "reservations").await, 13);
    assert_eq!(count(&database.ledger, "reservation_set_events").await, 1);
    assert_eq!(count(&database.ledger, "budget_ledger").await, 8);

    let backend =
        PostgresApiBackend::from_ledger(&database.ledger, TenantId::from_uuid(fixture.tenant_id));
    let workers = backend
        .workers(TenantId::from_uuid(fixture.tenant_id))
        .await
        .expect("list workers with an active reservation set");
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0].active_slots, 1);

    let mut adoption = winner.clone();
    adoption.reservation_set_id = Uuid::now_v7();
    adoption.identities.reverse();
    let adopted = database
        .ledger
        .acquire_admission_reservations(&adoption)
        .await
        .expect("adopt identical admission");
    assert_eq!(adopted.disposition, AdmissionDisposition::Adopted);
    assert_eq!(adopted.reservation_set_id, receipt.reservation_set_id);
    assert_eq!(adopted.resources, receipt.resources);
    let mut changed = adoption;
    changed.budget.external_api_calls -= 1;
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&changed)
            .await,
        Err(Error::Conflict(_))
    ));

    // A linked ledger row cannot borrow a valid reservation ID while changing
    // its dimension, even under a caller-controlled idempotency key.
    let budget_reservation_id: Uuid = sqlx::query_scalar(
        r"
        SELECT id
        FROM reservations
        WHERE tenant_id = $1
          AND reservation_set_id = $2
          AND kind = 'BUDGET'
          AND budget_dimension = 'COST_MICROUNITS'
        ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load budget reservation for binding poison");
    let binding_poison = sqlx::query(
        r"
        INSERT INTO budget_ledger (
            id, tenant_id, work_item_id, attempt_id, reservation_id,
            scope_type, scope_id, dimension, entry_type, amount, unit,
            idempotency_key, occurred_at
        ) VALUES (
            $1, $2, $3, $4, $5, 'ATTEMPT', $6, 'INPUT_TOKENS',
            'CONSUME', 1, 'tokens', $7, clock_timestamp()
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(winner.work_item_id)
    .bind(winner.attempt_id)
    .bind(budget_reservation_id)
    .bind(winner.attempt_id.to_string())
    .bind(format!("linked-dimension-poison:{}", fixture.tenant_id))
    .execute(database.ledger.pool())
    .await;
    assert!(matches!(
        binding_poison,
        Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")
    ));

    // The terminal event alone is not sufficient.  Omitting even one set of
    // per-dimension RELEASE rows makes the deferred parent proof reject the
    // whole transition, after which the normal atomic release remains usable.
    let omitted_release_key = format!("omitted-budget-release:{}", fixture.tenant_id);
    let omitted_release_reason = "direct transition omitted budget accounting";
    let mut incomplete = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin incomplete direct release");
    let incomplete_released_at: DateTime<Utc> = sqlx::query_scalar(
        r"
        UPDATE reservation_sets
        SET state = 'RELEASED',
            fence_token = 2,
            released_at = clock_timestamp(),
            released_by = 'hostile:direct-sql',
            release_reason = $3,
            transition_idempotency_key = $4
        WHERE tenant_id = $1 AND id = $2
        RETURNING released_at
        ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .bind(omitted_release_reason)
    .bind(&omitted_release_key)
    .fetch_one(&mut *incomplete)
    .await
    .expect("stage release without budget accounting");
    sqlx::query(
        r"
        INSERT INTO reservation_set_events (
            id, tenant_id, reservation_set_id, event_type,
            previous_fence_token, fence_token, actor_id, reason,
            idempotency_key, occurred_at
        ) VALUES ($1, $2, $3, 'RELEASED', 1, 2, 'hostile:direct-sql', $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .bind(omitted_release_reason)
    .bind(&omitted_release_key)
    .bind(incomplete_released_at)
    .execute(&mut *incomplete)
    .await
    .expect("stage exact event without release ledger");
    let incomplete_commit = incomplete
        .commit()
        .await
        .expect_err("terminal set without budget RELEASE rows must roll back");
    assert_eq!(
        incomplete_commit
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    let premature_expiry = sqlx::query(
        r"
        UPDATE reservation_sets
        SET state = 'EXPIRED',
            fence_token = 2,
            released_at = clock_timestamp(),
            released_by = 'hostile:direct-sql',
            release_reason = 'premature expiry',
            transition_idempotency_key = $3
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .bind(format!("premature-expiry:{}", fixture.tenant_id))
    .execute(database.ledger.pool())
    .await;
    assert!(matches!(
        premature_expiry,
        Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")
    ));

    let release = transition(&fixture, receipt.reservation_set_id, 1, "release-winner");
    let released = database
        .ledger
        .release_reservation_set(&release)
        .await
        .expect("release winning reservations");
    assert_eq!(released.state, ReservationTerminalState::Released);
    assert_eq!(
        released.disposition,
        ReservationTransitionDisposition::Applied
    );
    assert_eq!(released.fence_token, 2);
    let workers = backend
        .workers(TenantId::from_uuid(fixture.tenant_id))
        .await
        .expect("list workers after reservation release");
    assert_eq!(workers[0].active_slots, 0);
    let release_adopted = database
        .ledger
        .release_reservation_set(&release)
        .await
        .expect("adopt identical release");
    assert_eq!(
        release_adopted.disposition,
        ReservationTransitionDisposition::Adopted
    );
    assert_eq!(release_adopted.event_id, released.event_id);
    assert_eq!(release_adopted.occurred_at, released.occurred_at);

    let loser_receipt = database
        .ledger
        .acquire_admission_reservations(&loser)
        .await
        .expect("released capacity admits former loser");
    database
        .ledger
        .release_reservation_set(&transition(
            &fixture,
            loser_receipt.reservation_set_id,
            1,
            "release-loser",
        ))
        .await
        .expect("release former loser");

    insert_external_api_consumption(&database.ledger, &fixture, 2, 5).await;
    let mut budget_blocked = fixture.request(2, "budget-consumption-blocked");
    budget_blocked.budget = BudgetReservationAmounts {
        external_api_calls: 1,
        ..BudgetReservationAmounts::default()
    };
    let sets_before = count(&database.ledger, "reservation_sets").await;
    let children_before = count(&database.ledger, "reservations").await;
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&budget_blocked)
            .await,
        Err(Error::Conflict(_))
    ));
    assert_eq!(
        count(&database.ledger, "reservation_sets").await,
        sets_before
    );
    assert_eq!(
        count(&database.ledger, "reservations").await,
        children_before
    );

    let mut expiring = fixture.request(3, "expiring");
    expiring.expires_at = Utc::now() + Duration::seconds(2);
    let expiring_receipt = database
        .ledger
        .acquire_admission_reservations(&expiring)
        .await
        .expect("acquire expiring reservations");
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let expiry = transition(
        &fixture,
        expiring_receipt.reservation_set_id,
        1,
        "expire-set",
    );
    let expired = database
        .ledger
        .expire_reservation_set(&expiry)
        .await
        .expect("fenced expiration");
    assert_eq!(expired.state, ReservationTerminalState::Expired);
    assert_eq!(expired.fence_token, 2);
    assert_eq!(
        database
            .ledger
            .expire_reservation_set(&expiry)
            .await
            .expect("adopt identical expiration")
            .disposition,
        ReservationTransitionDisposition::Adopted
    );
    let stale = ReservationTransitionRequest {
        idempotency_key: format!("stale:{}", fixture.tenant_id),
        reason: "stale release".into(),
        ..expiry
    };
    assert!(matches!(
        database.ledger.release_reservation_set(&stale).await,
        Err(Error::Conflict(_))
    ));

    database.cleanup().await;
}

#[tokio::test]
async fn elapsed_reservation_sweep_is_bounded_durable_and_race_safe_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert_with_worker_capacity(&database.ledger, 3, 4).await;
    raise_fixture_capacity(&database.ledger, &fixture, 4).await;

    assert!(matches!(
        database
            .ledger
            .expire_elapsed_reservation_sets(Uuid::nil(), "sweeper:test", 1)
            .await,
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        database
            .ledger
            .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:test", 0)
            .await,
        Err(Error::Validation(_))
    ));

    let deadline = Utc::now() + Duration::seconds(2);
    let mut requests = Vec::new();
    let mut receipts = Vec::new();
    for index in 0..3 {
        let mut request = fixture.request(index, &format!("sweep-{index}"));
        request.expires_at = deadline;
        receipts.push(
            database
                .ledger
                .acquire_admission_reservations(&request)
                .await
                .expect("acquire sweep fixture reservation"),
        );
        requests.push(request);
    }
    assert_eq!(count(&database.ledger, "reservation_sets").await, 3);
    assert_eq!(count(&database.ledger, "reservation_set_events").await, 3);
    assert_eq!(count(&database.ledger, "budget_ledger").await, 24);

    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let first = database
        .ledger
        .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:test", 1)
        .await
        .expect("expire first bounded batch");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].state, ReservationTerminalState::Expired);
    assert_eq!(first[0].fence_token, 2);
    assert_eq!(terminal_set_count(&database.ledger, "EXPIRED").await, 1);

    let second = database
        .ledger
        .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:test", 1)
        .await
        .expect("expire second bounded batch");
    assert_eq!(second.len(), 1);
    assert_eq!(terminal_set_count(&database.ledger, "EXPIRED").await, 2);
    assert_eq!(count(&database.ledger, "reservation_set_events").await, 5);
    assert_eq!(count(&database.ledger, "budget_ledger").await, 40);

    let raced_set_id = receipts[2].reservation_set_id;
    let release = transition(&fixture, raced_set_id, 1, "race-expiry-release");
    let barrier = Arc::new(Barrier::new(3));
    let sweep_task = {
        let ledger = database.ledger.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            ledger
                .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:test", 1)
                .await
        })
    };
    let release_task = {
        let ledger = database.ledger.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            ledger.release_reservation_set(&release).await
        })
    };
    barrier.wait().await;
    let sweep_result = sweep_task.await.expect("join expiry sweep");
    let release_result = release_task.await.expect("join owner release");
    match (sweep_result, release_result) {
        (Ok(expired), Err(Error::Conflict(_))) => assert_eq!(expired.len(), 1),
        (Ok(expired), Ok(released)) => {
            assert!(expired.is_empty());
            assert_eq!(released.state, ReservationTerminalState::Released);
        }
        (left, right) => panic!("unexpected expiry/release race: {left:?} {right:?}"),
    }
    assert_eq!(
        terminal_event_count(&database.ledger, raced_set_id).await,
        1
    );
    assert_eq!(
        reservation_budget_entry_count(&database.ledger, raced_set_id).await,
        16
    );

    let empty = database
        .ledger
        .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:test", 10)
        .await
        .expect("adopt fully swept ledger");
    assert!(empty.is_empty());

    let mut recovered = requests.remove(2);
    recovered.reservation_set_id = Uuid::now_v7();
    recovered.expires_at = Utc::now() + Duration::minutes(5);
    recovered.idempotency_key = format!("recovered:{}", fixture.tenant_id);
    let recovered = database
        .ledger
        .acquire_admission_reservations(&recovered)
        .await
        .expect("durable expiry clears the per-attempt active fence");
    database
        .ledger
        .release_reservation_set(&transition(
            &fixture,
            recovered.reservation_set_id,
            recovered.fence_token,
            "release-recovered",
        ))
        .await
        .expect("release recovered reservation");

    database.cleanup().await;
}

#[tokio::test]
async fn expiry_sweep_internal_namespace_cannot_be_poisoned_or_starved_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert_with_worker_capacity(&database.ledger, 3, 3).await;
    raise_fixture_capacity(&database.ledger, &fixture, 3).await;

    let deadline = Utc::now() + Duration::seconds(2);
    let mut first_target = fixture.request(0, "expiry-poison-target-one");
    first_target.expires_at = deadline;
    let first_target = database
        .ledger
        .acquire_admission_reservations(&first_target)
        .await
        .expect("acquire first expiry target");

    // This was the exact poisoning pattern before the sweep received a
    // reserved namespace: an unrelated acquisition event could occupy the
    // predictable tenant-global key for the oldest elapsed set.
    let legacy_poison_key = format!(
        "reservation-expiry:{}:fence:1",
        first_target.reservation_set_id
    );
    let mut legacy_poison = fixture.request(2, "legacy-expiry-poison");
    legacy_poison.idempotency_key.clone_from(&legacy_poison_key);
    let legacy_poison = database
        .ledger
        .acquire_admission_reservations(&legacy_poison)
        .await
        .expect("legacy external key no longer aliases the internal sweep key");

    let internal_key = format!(
        "asf-internal:reservation-expiry:v1:{}:fence:1",
        first_target.reservation_set_id
    );
    let mut public_poison = fixture.request(1, "reserved-expiry-poison");
    public_poison.idempotency_key.clone_from(&internal_key);
    assert!(matches!(
        database
            .ledger
            .acquire_admission_reservations(&public_poison)
            .await,
        Err(Error::Validation(_))
    ));

    let reserved_transition = ReservationTransitionRequest {
        tenant_id: fixture.tenant_id,
        reservation_set_id: legacy_poison.reservation_set_id,
        expected_fence_token: legacy_poison.fence_token,
        actor_id: "scheduler:integration-test".into(),
        reason: "attempt internal-key poisoning".into(),
        idempotency_key: internal_key.clone(),
    };
    assert!(matches!(
        database
            .ledger
            .release_reservation_set(&reserved_transition)
            .await,
        Err(Error::Validation(_))
    ));

    // The database independently rejects a cross-set internal event even if a
    // caller bypasses both Rust entry points. The set ID encoded in the key has
    // to be the event's own set ID.
    let direct_poison = sqlx::query(
        r"
        INSERT INTO reservation_set_events (
            id, tenant_id, reservation_set_id, event_type,
            previous_fence_token, fence_token, actor_id, reason, idempotency_key
        ) VALUES ($1, $2, $3, 'EXPIRED', 1, 2, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(legacy_poison.reservation_set_id)
    .bind("hostile:direct-sql")
    .bind("cross-set namespace poison")
    .bind(&internal_key)
    .execute(database.ledger.pool())
    .await;
    assert!(matches!(
        direct_poison,
        Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")
    ));

    // Encoding the target set itself is still insufficient: while that set is
    // ACTIVE, a direct writer must not be able to reserve the exact event key
    // and fence that its future expiry sweep will require.
    let same_set_future_poison = sqlx::query(
        r"
        INSERT INTO reservation_set_events (
            id, tenant_id, reservation_set_id, event_type,
            previous_fence_token, fence_token, actor_id, reason, idempotency_key
        ) VALUES ($1, $2, $3, 'EXPIRED', 1, 2, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(first_target.reservation_set_id)
    .bind("hostile:direct-sql")
    .bind("same-set future namespace poison")
    .bind(&internal_key)
    .execute(database.ledger.pool())
    .await;
    assert!(matches!(
        same_set_future_poison,
        Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")
    ));

    // Budget ledger keys live in a separate tenant-global unique namespace.
    // Even a correctly shaped release row cannot reserve a sweep's future key
    // while the named reservation set is still active.
    let direct_budget_poison = sqlx::query(
        r"
        INSERT INTO budget_ledger (
            id, tenant_id, work_item_id, attempt_id, reservation_id,
            scope_type, scope_id, dimension, entry_type, amount, unit,
            idempotency_key, occurred_at
        )
        SELECT
            $1, reservation_set.tenant_id, reservation_set.work_item_id,
            reservation_set.attempt_id, reservation.id, 'ATTEMPT',
            reservation_set.attempt_id::text, reservation.budget_dimension,
            'RELEASE', reservation.units, 'microunits', $3, clock_timestamp()
        FROM reservation_sets AS reservation_set
        JOIN reservations AS reservation
          ON reservation.tenant_id = reservation_set.tenant_id
         AND reservation.reservation_set_id = reservation_set.id
         AND reservation.kind = 'BUDGET'
         AND reservation.budget_dimension = 'COST_MICROUNITS'
        WHERE reservation_set.tenant_id = $2
          AND reservation_set.id = $4
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(format!("{internal_key}:budget-release:COST_MICROUNITS"))
    .bind(first_target.reservation_set_id)
    .execute(database.ledger.pool())
    .await;
    assert!(matches!(
        direct_budget_poison,
        Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")
    ));

    let mut second_target = fixture.request(1, "expiry-poison-target-two");
    second_target.expires_at = deadline;
    let second_target = database
        .ledger
        .acquire_admission_reservations(&second_target)
        .await
        .expect("acquire second expiry target after rejected poison");

    tokio::time::sleep(StdDuration::from_millis(2_100)).await;
    let first_batch = database
        .ledger
        .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:poison-test", 1)
        .await
        .expect("expire oldest set despite legacy poison");
    let second_batch = database
        .ledger
        .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:poison-test", 1)
        .await
        .expect("expire next set without cross-set starvation");
    assert_eq!(first_batch.len(), 1);
    assert_eq!(second_batch.len(), 1);
    let expired_ids = [
        first_batch[0].reservation_set_id,
        second_batch[0].reservation_set_id,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        expired_ids,
        [
            first_target.reservation_set_id,
            second_target.reservation_set_id,
        ]
        .into_iter()
        .collect()
    );
    for receipt in first_batch.iter().chain(&second_batch) {
        assert_eq!(
            receipt.idempotency_key,
            format!(
                "asf-internal:reservation-expiry:v1:{}:fence:1",
                receipt.reservation_set_id
            )
        );
    }
    assert_eq!(terminal_set_count(&database.ledger, "EXPIRED").await, 2);
    assert_eq!(
        database
            .ledger
            .expire_elapsed_reservation_sets(fixture.tenant_id, "sweeper:poison-test", 3)
            .await
            .expect("committed expiry replay has no remaining candidates")
            .len(),
        0
    );

    database.cleanup().await;
}

#[tokio::test]
async fn linked_budget_writers_take_the_admission_lock_before_reservation_rows_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger, 1).await;
    let request = fixture.request(0, "linked-ledger-lock-order");
    let receipt = database
        .ledger
        .acquire_admission_reservations(&request)
        .await
        .expect("acquire lock-order reservation");
    let reservation_id: Uuid = sqlx::query_scalar(
        r"
        SELECT id
        FROM reservations
        WHERE tenant_id = $1
          AND reservation_set_id = $2
          AND kind = 'BUDGET'
          AND budget_dimension = 'COST_MICROUNITS'
        ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load lock-order budget reservation");

    let advisory_key = format!(
        "admission:{}:budget:{}",
        fixture.tenant_id, request.work_item_id
    );
    let mut owner = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin advisory-lock owner");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(&advisory_key)
        .execute(&mut *owner)
        .await
        .expect("hold admission budget advisory lock");

    let (pid_sender, pid_receiver) = oneshot::channel();
    let writer_ledger = database.ledger.clone();
    let writer_key = format!("linked-lock-order-consume:{}", fixture.tenant_id);
    let tenant_id = fixture.tenant_id;
    let work_item_id = request.work_item_id;
    let attempt_id = request.attempt_id;
    let writer = tokio::spawn(async move {
        let mut transaction = writer_ledger.pool().begin().await?;
        let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await?;
        let _ = pid_sender.send(backend_pid);
        sqlx::query(
            r"
            INSERT INTO budget_ledger (
                id, tenant_id, work_item_id, attempt_id, reservation_id,
                scope_type, scope_id, dimension, entry_type, amount, unit,
                idempotency_key, occurred_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'ATTEMPT', $6, 'COST_MICROUNITS',
                'CONSUME', 1, 'microunits', $7, clock_timestamp()
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(reservation_id)
        .bind(attempt_id.to_string())
        .bind(writer_key)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await
    });
    let writer_pid = pid_receiver
        .await
        .expect("receive linked-writer backend PID");
    tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            let wait_event: Option<String> =
                sqlx::query_scalar("SELECT wait_event FROM pg_stat_activity WHERE pid = $1")
                    .bind(writer_pid)
                    .fetch_one(&database.admin)
                    .await
                    .expect("inspect linked-writer wait event");
            if wait_event.as_deref() == Some("advisory") {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("linked writer must wait on the advisory lock first");

    // If its binding trigger had row-locked the parent first, this NOWAIT lock
    // would fail and the opposite-order owner/writer pair could deadlock.
    sqlx::query(
        "SELECT 1 FROM reservation_sets WHERE tenant_id = $1 AND id = $2 FOR UPDATE NOWAIT",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .execute(&mut *owner)
    .await
    .expect("advisory owner can lock reservation set without inversion");
    owner
        .rollback()
        .await
        .expect("release advisory and reservation locks");
    writer
        .await
        .expect("join linked budget writer")
        .expect("linked budget writer completes after lock release");

    database.cleanup().await;
}

#[tokio::test]
async fn late_budget_child_serializes_with_terminal_parent_transition_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger, 1).await;
    let work = fixture.work[0];
    let reservation_set_id = Uuid::now_v7();
    let admission_key = format!("late-budget-race:{}", fixture.tenant_id);

    // Start from a valid ACTIVE set with no budget children. A direct writer
    // can then add the first budget child while a different transaction makes
    // the parent terminal. The ordinary budget advisory trigger is redundant
    // with this database invariant and would serialize the two transactions
    // before the parent-version race this regression is intended to exercise.
    sqlx::query(
        "ALTER TABLE budget_ledger DISABLE TRIGGER budget_ledger_serializes_with_admission",
    )
    .execute(database.ledger.pool())
    .await
    .expect("disable isolated-schema budget advisory trigger");

    let mut acquisition = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin minimal reservation-set acquisition");
    let acquired_at: DateTime<Utc> = sqlx::query_scalar(
        r"
        INSERT INTO reservation_sets (
            id, tenant_id, work_item_id, attempt_id, repository_id, worker_id,
            worker_session_id, worker_generation, request_digest,
            idempotency_key, acquired_by, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 1, $8, $9,
            'scheduler:late-child-race', clock_timestamp() + interval '5 minutes'
        )
        RETURNING acquired_at
        ",
    )
    .bind(reservation_set_id)
    .bind(fixture.tenant_id)
    .bind(work.work_item_id)
    .bind(work.attempt_id)
    .bind(fixture.repository_id)
    .bind(fixture.worker_id)
    .bind(fixture.worker_session_id)
    .bind(digest('c'))
    .bind(&admission_key)
    .fetch_one(&mut *acquisition)
    .await
    .expect("insert minimal active reservation set");
    sqlx::query(
        r"
        INSERT INTO reservation_set_events (
            id, tenant_id, reservation_set_id, event_type,
            previous_fence_token, fence_token, actor_id, reason,
            idempotency_key, occurred_at
        ) VALUES (
            $1, $2, $3, 'ACQUIRED', 0, 1, 'scheduler:late-child-race',
            'atomic admission acquired', $4, $5
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(reservation_set_id)
    .bind(&admission_key)
    .bind(acquired_at)
    .execute(&mut *acquisition)
    .await
    .expect("insert exact acquisition event");
    sqlx::query("SET CONSTRAINTS reservation_sets_require_event IMMEDIATE")
        .execute(&mut *acquisition)
        .await
        .expect("validate minimal active reservation set");
    acquisition
        .commit()
        .await
        .expect("commit minimal active reservation set");

    let late_reservation_id = Uuid::now_v7();
    let mut late_child = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin late budget child");
    let late_child_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *late_child)
        .await
        .expect("load late-child backend PID");
    sqlx::query(
        r"
        INSERT INTO reservations (
            id, tenant_id, reservation_set_id, kind, resource_key,
            budget_dimension, units, idempotency_key, resource_generation
        ) VALUES (
            $1, $2, $3, 'BUDGET', $4, 'COST_MICROUNITS', 7, $5, 1
        )
        ",
    )
    .bind(late_reservation_id)
    .bind(fixture.tenant_id)
    .bind(reservation_set_id)
    .bind(format!("late-budget:{late_reservation_id}"))
    .bind(format!("late-budget-reservation:{late_reservation_id}"))
    .execute(&mut *late_child)
    .await
    .expect("insert late budget reservation while parent is active");
    sqlx::query(
        r"
        INSERT INTO budget_ledger (
            id, tenant_id, work_item_id, attempt_id, reservation_id,
            scope_type, scope_id, dimension, entry_type, amount, unit,
            idempotency_key, occurred_at
        ) VALUES (
            $1, $2, $3, $4, $5, 'ATTEMPT', $6, 'COST_MICROUNITS',
            'RESERVE', 7, 'microunits', $7, $8
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(work.work_item_id)
    .bind(work.attempt_id)
    .bind(late_reservation_id)
    .bind(work.attempt_id.to_string())
    .bind(format!("{admission_key}:budget-reserve:COST_MICROUNITS"))
    .bind(acquired_at)
    .execute(&mut *late_child)
    .await
    .expect("insert exact RESERVE accounting for late budget child");

    // The 0006 child proof advances a guarded parent accounting version. Keep
    // that transaction open after validation so an older-snapshot terminal
    // writer must serialize behind the write instead of overlooking the child.
    sqlx::query("SET CONSTRAINTS budget_reservations_require_accounting IMMEDIATE")
        .execute(&mut *late_child)
        .await
        .expect("validate late child and lock its active parent");

    let transition_key = format!("late-budget-terminal:{}", fixture.tenant_id);
    let transition_actor = "scheduler:late-child-race";
    let transition_reason = "release during late budget insertion";
    let mut terminal_parent = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin concurrent terminal parent transition");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *terminal_parent)
        .await
        .expect("use a stable old snapshot for terminal parent");
    let (terminal_parent_pid, visible_accounting_version): (i32, i64) = sqlx::query_as(
        "SELECT pg_backend_pid(), budget_accounting_version \
         FROM reservation_sets WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(reservation_set_id)
    .fetch_one(&mut *terminal_parent)
    .await
    .expect("fix terminal-parent snapshot before the child commits");
    assert_eq!(visible_accounting_version, 0);
    let terminal_transition = tokio::spawn(async move {
        let released_at = match sqlx::query_scalar::<_, DateTime<Utc>>(
            r"
            UPDATE reservation_sets
            SET state = 'RELEASED',
                fence_token = 2,
                released_at = clock_timestamp(),
                released_by = $3,
                release_reason = $4,
                transition_idempotency_key = $5
            WHERE tenant_id = $1
              AND id = $2
              AND state = 'ACTIVE'
              AND fence_token = 1
            RETURNING released_at
            ",
        )
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .bind(transition_actor)
        .bind(transition_reason)
        .bind(&transition_key)
        .fetch_one(&mut *terminal_parent)
        .await
        {
            Ok(released_at) => released_at,
            Err(error) => {
                let error = sqlx_error_parts(error);
                terminal_parent
                    .rollback()
                    .await
                    .expect("roll back serialization-rejected terminal parent");
                return Some(error);
            }
        };
        sqlx::query(
            r"
            INSERT INTO reservation_set_events (
                id, tenant_id, reservation_set_id, event_type,
                previous_fence_token, fence_token, actor_id, reason,
                idempotency_key, occurred_at
            ) VALUES ($1, $2, $3, 'RELEASED', 1, 2, $4, $5, $6, $7)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(fixture.tenant_id)
        .bind(reservation_set_id)
        .bind(transition_actor)
        .bind(transition_reason)
        .bind(&transition_key)
        .bind(released_at)
        .execute(&mut *terminal_parent)
        .await
        .expect("insert exact concurrent terminal event");
        let result = sqlx::query("SET CONSTRAINTS reservation_sets_require_event IMMEDIATE")
            .execute(&mut *terminal_parent)
            .await;
        let error = result.err().map(sqlx_error_parts);
        terminal_parent
            .rollback()
            .await
            .expect("roll back rejected terminal parent");
        error
    });

    tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            assert!(
                !terminal_transition.is_finished(),
                "terminal transition returned before the child released its parent row lock"
            );
            let wait_event_type: Option<String> =
                sqlx::query_scalar("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1")
                    .bind(terminal_parent_pid)
                    .fetch_one(&database.admin)
                    .await
                    .expect("inspect terminal-parent wait");
            if wait_event_type.as_deref() == Some("Lock") {
                let blockers: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
                    .bind(terminal_parent_pid)
                    .fetch_one(&database.admin)
                    .await
                    .expect("inspect exact terminal-parent blocker");
                if blockers.contains(&late_child_pid) {
                    break;
                }
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("terminal parent must wait for the child proof's row lock");

    late_child
        .commit()
        .await
        .expect("commit validated late child while terminal parent waits");
    let terminal_error = terminal_transition
        .await
        .expect("join terminal parent transition")
        .expect("terminal parent must not commit from its older child snapshot");
    assert_eq!(terminal_error.0.as_deref(), Some("40001"));

    let (state, fence_token, accounting_version): (String, i64, i64) = sqlx::query_as(
        "SELECT state, fence_token, budget_accounting_version \
         FROM reservation_sets WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(reservation_set_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load committed terminal parent");
    assert_eq!(state, "ACTIVE");
    assert_eq!(fence_token, 1);
    assert_eq!(accounting_version, 1);
    let late_child_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reservations WHERE id = $1")
            .bind(late_reservation_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("count rolled-back late budget child");
    assert_eq!(late_child_count, 1);

    database.cleanup().await;
}

#[tokio::test]
async fn reactor_poll_durably_sweeps_elapsed_reservations_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger, 1).await;
    let mut request = fixture.request(0, "reactor-expiry");
    request.expires_at = Utc::now() + Duration::seconds(2);
    let receipt = database
        .ledger
        .acquire_admission_reservations(&request)
        .await
        .expect("acquire reactor expiry fixture");
    tokio::time::sleep(StdDuration::from_millis(2_100)).await;

    let reactor = ReactorRuntime::new(
        database.ledger.clone(),
        fixture.tenant_id,
        HandlerRegistry::fail_closed_production().expect("build fail-closed handlers"),
        ReactorOptions {
            lease_owner: "reactor:reservation-expiry-test".into(),
            poll_interval: StdDuration::from_millis(10),
            lease_duration: StdDuration::from_secs(1),
            max_error_backoff: StdDuration::from_secs(1),
            claim_batch_size: 8,
        },
        true,
    )
    .expect("construct reservation expiry reactor");
    let report = reactor
        .poll_once()
        .await
        .expect("reactor poll sweeps elapsed reservation");
    // The fixture's accepted work item owns a due ADVANCE_ACCEPTED_WORK_ITEM
    // job, and this reactor installs every production activity as unavailable,
    // so the same poll also escalates that one known-unserviceable obligation
    // instead of leaving it silently unclaimable.
    assert_eq!(
        report,
        ReactorPollReport {
            reservations_expired: 1,
            known_unserviceable_jobs_escalated: 1,
            jobs_transactionally_finalized: 1,
            ..ReactorPollReport::default()
        }
    );

    let (state, fence_token, actor_id, event_type): (String, i64, String, String) = sqlx::query_as(
        r"
            SELECT reservation_set.state, reservation_set.fence_token,
                   event.actor_id, event.event_type
            FROM reservation_sets AS reservation_set
            JOIN reservation_set_events AS event
              ON event.tenant_id = reservation_set.tenant_id
             AND event.reservation_set_id = reservation_set.id
             AND event.fence_token = reservation_set.fence_token
            WHERE reservation_set.tenant_id = $1
              AND reservation_set.id = $2
            ",
    )
    .bind(fixture.tenant_id)
    .bind(receipt.reservation_set_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load reactor expiry transition");
    assert_eq!(state, "EXPIRED");
    assert_eq!(fence_token, 2);
    assert_eq!(actor_id, "asf:reservation-expiry-sweeper");
    assert_eq!(event_type, "EXPIRED");
    assert_eq!(
        reservation_budget_entry_count(&database.ledger, receipt.reservation_set_id).await,
        16
    );

    let second_poll = reactor
        .poll_once()
        .await
        .expect("repeated reactor poll is idempotent");
    assert_eq!(second_poll.reservations_expired, 0);

    database.cleanup().await;
}

fn transition(
    fixture: &Fixture,
    reservation_set_id: Uuid,
    expected_fence_token: u64,
    suffix: &str,
) -> ReservationTransitionRequest {
    ReservationTransitionRequest {
        tenant_id: fixture.tenant_id,
        reservation_set_id,
        expected_fence_token,
        actor_id: "scheduler:integration-test".into(),
        reason: suffix.into(),
        idempotency_key: format!("{suffix}:{}", fixture.tenant_id),
    }
}

async fn count(ledger: &PgLedger, table: &str) -> i64 {
    assert!(matches!(
        table,
        "reservation_sets" | "reservations" | "reservation_set_events" | "budget_ledger"
    ));
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(ledger.pool())
        .await
        .expect("count reservation test rows")
}

async fn terminal_set_count(ledger: &PgLedger, state: &str) -> i64 {
    assert!(matches!(state, "RELEASED" | "EXPIRED"));
    sqlx::query_scalar("SELECT count(*) FROM reservation_sets WHERE state = $1")
        .bind(state)
        .fetch_one(ledger.pool())
        .await
        .expect("count terminal reservation sets")
}

async fn terminal_event_count(ledger: &PgLedger, reservation_set_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM reservation_set_events \
         WHERE reservation_set_id = $1 AND event_type IN ('RELEASED', 'EXPIRED')",
    )
    .bind(reservation_set_id)
    .fetch_one(ledger.pool())
    .await
    .expect("count terminal reservation events")
}

async fn reservation_budget_entry_count(ledger: &PgLedger, reservation_set_id: Uuid) -> i64 {
    sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM budget_ledger AS entry
        JOIN reservations AS reservation
          ON reservation.tenant_id = entry.tenant_id
         AND reservation.id = entry.reservation_id
        WHERE reservation.reservation_set_id = $1
        ",
    )
    .bind(reservation_set_id)
    .fetch_one(ledger.pool())
    .await
    .expect("count reservation budget entries")
}

async fn raise_fixture_capacity(ledger: &PgLedger, fixture: &Fixture, capacity: i32) {
    let mut transaction = ledger.pool().begin().await.expect("begin capacity raise");
    sqlx::query(
        "UPDATE repositories SET wip_limit = $3 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.repository_id)
    .bind(capacity)
    .execute(&mut *transaction)
    .await
    .expect("raise repository capacity");
    sqlx::query("UPDATE identity_capacity_limits SET capacity = $2 WHERE tenant_id = $1")
        .bind(fixture.tenant_id)
        .bind(i64::from(capacity))
        .execute(&mut *transaction)
        .await
        .expect("raise identity capacity");
    transaction.commit().await.expect("commit capacity raise");
}

async fn insert_external_api_consumption(
    ledger: &PgLedger,
    fixture: &Fixture,
    work_index: usize,
    amount: i64,
) {
    let work = fixture.work[work_index];
    sqlx::query(
        r"
        INSERT INTO budget_ledger (
            id, tenant_id, work_item_id, attempt_id, scope_type, scope_id,
            dimension, entry_type, amount, unit, idempotency_key, occurred_at
        ) VALUES ($1, $2, $3, $4, 'ATTEMPT', $5, 'EXTERNAL_API_CALLS',
                  'CONSUME', $6, 'calls', $7, clock_timestamp())
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(work.work_item_id)
    .bind(work.attempt_id)
    .bind(work.attempt_id.to_string())
    .bind(amount)
    .bind(format!("external-consumption:{}", work.attempt_id))
    .execute(ledger.pool())
    .await
    .expect("insert persisted external API consumption");
}

fn identity_requests() -> Vec<IdentityCapacityRequest> {
    [
        "codex:implementer",
        "claude:local-reviewer",
        "codex:pr-reviewer",
    ]
    .into_iter()
    .map(|profile| IdentityCapacityRequest {
        profile_ref: CtxlaneProfileRef::from_str(profile).expect("valid profile"),
        units: 1,
        expected_generation: 1,
    })
    .collect()
}

fn budget_request() -> BudgetReservationAmounts {
    BudgetReservationAmounts {
        cost_microunits: 100,
        input_tokens: 1_000,
        output_tokens: 500,
        implementer_invocations: 1,
        reviewer_invocations: 2,
        fix_iterations: 1,
        wall_time_seconds: 60,
        external_api_calls: 5,
    }
}

fn budget_limits() -> serde_json::Value {
    json!({
        "max_cost_microunits": 100,
        "max_input_tokens": 1_000,
        "max_output_tokens": 500,
        "max_implementer_invocations": 1,
        "max_reviewer_invocations": 2,
        "max_fix_iterations": 1,
        "max_wall_time_seconds": 60,
        "max_external_api_calls": 5
    })
}

fn identity_requirements() -> serde_json::Value {
    json!({
        "implementer": "codex:implementer",
        "local_reviewer": "claude:local-reviewer",
        "pr_reviewer": "codex:pr-reviewer"
    })
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn sqlx_error_parts(error: sqlx::Error) -> (Option<String>, String) {
    match error {
        sqlx::Error::Database(error) => (
            error.code().map(std::borrow::Cow::into_owned),
            error.message().to_owned(),
        ),
        error => (None, error.to_string()),
    }
}
