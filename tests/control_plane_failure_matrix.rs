//! Deterministic control-plane portion of ASF's failure-injection matrix.
//!
//! The companion integration tests cover the other rows without pretending to
//! qualify an external Runmill/ctxlane sandbox:
//! - `reactor_restart`: claim crash/restart, lease fencing, maintenance gating,
//!   and terminal accountability;
//! - `reservation_admission`: concurrent admission and durable expiry;
//! - `vertical_slice`: ambiguous provider responses and exactly-once adoption.
//!
//! This target covers the remaining durable run-event and signed-evidence
//! boundaries against public ASF APIs. CI runs it on Linux with a fresh
//! `PostgreSQL` service as part of `cargo test --all-targets --all-features`.

use chrono::SubsecRound as _;
use std::collections::BTreeSet;

use asf::{
    Error, Result,
    contracts::{
        AuthorizedRunmillReviewer, ProductEvent, PullRequestEvidence, RunmillEvidenceExpectation,
        RunmillReviewStage, SignedRunmillEvidenceBundle, TrustedRunmillEvidenceSigner,
    },
    crypto::decode_verifying_key,
    domain::{AttemptId, EventId, RunId, TenantId, WorkItemId},
    ledger::{
        IncomingRunEvent, PgLedger, RunEventIngestionDisposition, RunEventIngestionOutcome,
        RunEventProjectionBlock, WorkerSessionFence, ingest_run_event,
    },
    ports::PRODUCT_EVENT_SCHEMA_V1,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

const FIXTURE_WORKER_KEY: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
const STALE_CANDIDATE_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect failure-matrix PostgreSQL administrator");
        let schema = format!("asf_failure_matrix_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated failure-matrix schema");
        let mut scoped_url = Url::parse(database_url).expect("parse failure-matrix database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated failure-matrix ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated failure-matrix schema");
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
            .expect("drop isolated failure-matrix schema");
        self.admin.close().await;
    }
}

#[derive(Debug)]
struct RunFixture {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    worker_id: Uuid,
    worker_session_id: Uuid,
    run_id: Uuid,
    policy_digest: String,
    work_order_digest: String,
    occurred_at: DateTime<Utc>,
}

impl RunFixture {
    async fn insert(ledger: &PgLedger) -> Self {
        let fixture = Self {
            tenant_id: Uuid::now_v7(),
            work_item_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            worker_id: Uuid::now_v7(),
            worker_session_id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            policy_digest: digest('a'),
            work_order_digest: digest('b'),
            occurred_at: Utc::now().trunc_subsecs(6),
        };
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let work_order_id = Uuid::now_v7();
        let mut transaction = ledger.pool().begin().await.expect("begin run fixture");

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(fixture.tenant_id)
            .bind(format!("failure-matrix-{}", fixture.tenant_id))
            .bind("Control-plane failure matrix")
            .execute(&mut *transaction)
            .await
            .expect("insert failure-matrix tenant");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, scope, schema_version, digest, canonical_bytes,
                policy, created_by
            ) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'failure-matrix')
            ",
        )
        .bind(policy_id)
        .bind(fixture.tenant_id)
        .bind(&fixture.policy_digest)
        .bind(br"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix policy");
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, source_system, external_id, source_revision,
                normalized_content, content_digest, connector_identity,
                source_updated_at
            ) VALUES ($1, $2, 'API', $3, '1', '{}'::jsonb, $4,
                      'failure-matrix:source', $5)
            ",
        )
        .bind(snapshot_id)
        .bind(fixture.tenant_id)
        .bind(format!("event-{}", fixture.work_item_id))
        .bind(digest('c'))
        .bind(fixture.occurred_at)
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, state, normalized_priority
            ) VALUES ($1, $2, $3, 'API', $4, 'DISCOVERED', 50)
            ",
        )
        .bind(fixture.work_item_id)
        .bind(fixture.tenant_id)
        .bind(snapshot_id)
        .bind(format!("event-{}", fixture.work_item_id))
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix work item");
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest
            ) VALUES ($1, $2, $3, 1, 'CREATED', $4, 'main', $5, $6, $7)
            ",
        )
        .bind(fixture.attempt_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(format!("event-attempt-{}", fixture.attempt_id))
        .bind("1".repeat(40))
        .bind(digest('d'))
        .bind(&fixture.policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix attempt");
        sqlx::query(
            r"
            INSERT INTO work_orders (
                id, tenant_id, work_item_id, attempt_id, schema_version,
                envelope_schema, algorithm, key_id, idempotency_key,
                payload_digest, canonical_payload, payload, signature,
                exact_signed_envelope, issued_at, not_before, expires_at
            ) VALUES (
                $1, $2, $3, $4, 'v1', 'envelope-v1', 'EdDSA', 'asf-test',
                $5, $6, $7, '{}'::jsonb, 'signature', $8, $9, $9, $10
            )
            ",
        )
        .bind(work_order_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(format!("event-order-{work_order_id}"))
        .bind(&fixture.work_order_digest)
        .bind(br"{}".as_slice())
        .bind(b"signed-envelope".as_slice())
        .bind(fixture.occurred_at)
        .bind(fixture.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix Work Order");
        sqlx::query(
            r"
            INSERT INTO workers (
                id, tenant_id, name, endpoint, generation, signing_key_id,
                signing_public_key
            ) VALUES ($1, $2, $3, $4, 3, 'worker-test', 'public-key')
            ",
        )
        .bind(fixture.worker_id)
        .bind(fixture.tenant_id)
        .bind(format!("failure-worker-{}", fixture.worker_id))
        .bind(format!("local://{}", fixture.worker_id))
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix worker");
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, expires_at
            ) VALUES ($1, $2, $3, 3, $4)
            ",
        )
        .bind(fixture.worker_session_id)
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id)
        .bind(fixture.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix worker session");
        sqlx::query(
            r"
            INSERT INTO runs (
                id, tenant_id, work_item_id, attempt_id, work_order_id,
                worker_id, worker_generation, worker_session_id,
                evidence_expectation_digest, external_run_id, state
            ) VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8, $9, 'ADOPTED')
            ",
        )
        .bind(fixture.run_id)
        .bind(fixture.tenant_id)
        .bind(fixture.work_item_id)
        .bind(fixture.attempt_id)
        .bind(work_order_id)
        .bind(fixture.worker_id)
        .bind(fixture.worker_session_id)
        .bind(digest('e'))
        .bind(format!("run_{}", fixture.run_id.simple()))
        .execute(&mut *transaction)
        .await
        .expect("insert failure-matrix run");
        transaction.commit().await.expect("commit run fixture");
        fixture
    }

    const fn fence(&self) -> WorkerSessionFence {
        WorkerSessionFence {
            tenant_id: self.tenant_id,
            session_id: self.worker_session_id,
            worker_id: self.worker_id,
            generation: 3,
        }
    }

    fn event(&self, sequence: i64, aggregate_version: i64, event_type: &str) -> IncomingRunEvent {
        let event_id = EventId::new();
        let occurred_at = self.occurred_at + Duration::seconds(sequence);
        let product_event = ProductEvent {
            schema: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_id,
            tenant_id: TenantId::from_uuid(self.tenant_id),
            work_item_id: Some(WorkItemId::from_uuid(self.work_item_id)),
            attempt_id: Some(AttemptId::from_uuid(self.attempt_id)),
            work_order_digest: Some(self.work_order_digest.clone()),
            run_id: Some(RunId::from_uuid(self.run_id)),
            aggregate_version: u64::try_from(aggregate_version)
                .expect("fixture aggregate version is positive"),
            occurred_at,
            ingested_at: occurred_at,
            actor: "runmill:failure-worker".into(),
            event_type: event_type.into(),
            payload: json!({"checkpoint": sequence}),
            policy_digest: Some(self.policy_digest.clone()),
            trace_id: format!("trace-{event_id}"),
            correlation_id: format!("correlation-{event_id}"),
        };
        IncomingRunEvent {
            id: Uuid::now_v7(),
            run_id: self.run_id,
            external_event_id: event_id.to_string(),
            cursor: format!("cursor-{sequence}"),
            sequence,
            aggregate_version,
            schema_version: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_type: event_type.into(),
            occurred_at,
            raw_event: serde_json::to_value(product_event).expect("serialize product event"),
        }
    }
}

async fn ingest_committed(
    ledger: &PgLedger,
    fence: WorkerSessionFence,
    event: &IncomingRunEvent,
) -> Result<RunEventIngestionOutcome> {
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin event-ingestion transaction");
    match ingest_run_event(&mut transaction, fence, event).await {
        Ok(outcome) => {
            transaction
                .commit()
                .await
                .expect("commit event-ingestion transaction");
            Ok(outcome)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .expect("roll back rejected event ingestion");
            Err(error)
        }
    }
}

#[tokio::test]
async fn matrix_cursor_replay_out_of_order_cross_attempt_and_stale_generation_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = RunFixture::insert(&database.ledger).await;
    let fence = fixture.fence();

    let unrelated_worker_id = Uuid::now_v7();
    let unrelated_session_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO workers (
            id, tenant_id, name, endpoint, generation, signing_key_id,
            signing_public_key
        ) VALUES ($1, $2, $3, $4, 1, 'unrelated-worker', 'public-key')
        ",
    )
    .bind(unrelated_worker_id)
    .bind(fixture.tenant_id)
    .bind(format!("unrelated-worker-{unrelated_worker_id}"))
    .bind(format!("local://{unrelated_worker_id}"))
    .execute(database.ledger.pool())
    .await
    .expect("insert unrelated live worker");
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
    .expect("insert unrelated live worker session");
    let crossed_session = sqlx::query(
        r"
        INSERT INTO raw_run_events (
            id, tenant_id, run_id, worker_session_id, worker_id,
            worker_generation, external_event_id, cursor, sequence,
            run_aggregate_version, schema_version, event_type, occurred_at,
            payload
        ) VALUES (
            $1, $2, $3, $4, $5, 1, $6, 'crossed-session-cursor', 1, 2,
            $7, 'run.running', clock_timestamp(), '{}'::jsonb
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .bind(unrelated_session_id)
    .bind(unrelated_worker_id)
    .bind(EventId::new().to_string())
    .bind(PRODUCT_EVENT_SCHEMA_V1)
    .execute(database.ledger.pool())
    .await
    .expect_err("a live same-tenant session must not poison another run's sequence");
    assert_eq!(
        crossed_session
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("raw_run_events_run_worker_binding_fk")
    );

    let second = fixture.event(2, 3, "run.verifying");

    let gap = ingest_committed(&database.ledger, fence, &second)
        .await
        .expect("retain an out-of-order event");
    assert_eq!(
        gap.disposition,
        RunEventIngestionDisposition::RetainedUnapplied(RunEventProjectionBlock::SequenceGap {
            expected: 1
        })
    );
    assert!(gap.inserted);
    assert_eq!(gap.last_event_sequence, 0);
    assert_eq!(gap.run_aggregate_version, 1);

    let first = fixture.event(1, 2, "run.running");
    let drained = ingest_committed(&database.ledger, fence, &first)
        .await
        .expect("fill the gap and drain the retained suffix");
    assert_eq!(drained.disposition, RunEventIngestionDisposition::Applied);
    assert_eq!(drained.applied_event_count, 2);
    assert_eq!(drained.last_event_cursor.as_deref(), Some("cursor-2"));
    assert_eq!(drained.last_event_sequence, 2);
    assert_eq!(drained.run_aggregate_version, 3);

    let replay = ingest_committed(&database.ledger, fence, &second)
        .await
        .expect("adopt an exact replay");
    assert_eq!(
        replay.disposition,
        RunEventIngestionDisposition::DuplicateApplied
    );
    assert!(!replay.inserted);
    assert_eq!(replay.applied_event_count, 0);

    let mut collision = second.clone();
    collision.external_event_id = EventId::new().to_string();
    assert!(matches!(
        ingest_committed(&database.ledger, fence, &collision).await,
        Err(Error::Conflict(detail)) if detail.contains("reused for different semantics")
    ));

    let mut crossed_attempt = fixture.event(3, 4, "run.succeeded");
    crossed_attempt.raw_event["attempt_id"] = json!(Uuid::now_v7());
    let quarantined = ingest_committed(&database.ledger, fence, &crossed_attempt)
        .await
        .expect("retain but do not project a cross-attempt event");
    assert!(matches!(
        quarantined.disposition,
        RunEventIngestionDisposition::RetainedUnapplied(
            RunEventProjectionBlock::InvalidKnownEnvelope { .. }
        )
    ));
    assert_eq!(quarantined.last_event_sequence, 2);
    assert_eq!(quarantined.run_aggregate_version, 3);

    sqlx::query(
        r"
        UPDATE worker_sessions
        SET status = 'REVOKED',
            closed_at = clock_timestamp(),
            close_reason = 'failure-matrix generation rollover'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.worker_session_id)
    .execute(database.ledger.pool())
    .await
    .expect("revoke stale worker session");
    sqlx::query("UPDATE workers SET generation = 4 WHERE tenant_id = $1 AND id = $2")
        .bind(fixture.tenant_id)
        .bind(fixture.worker_id)
        .execute(database.ledger.pool())
        .await
        .expect("advance worker generation");

    let stale = fixture.event(4, 5, "run.succeeded");
    assert!(matches!(
        ingest_committed(&database.ledger, fence, &stale).await,
        Err(Error::Conflict(detail)) if detail.contains("generation 3 is stale")
    ));

    let projection: (String, i64, i64, Option<String>) = sqlx::query_as(
        r"
        SELECT state, last_event_sequence, aggregate_version, last_event_cursor
        FROM runs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load fenced run projection");
    assert_eq!(
        projection,
        ("VERIFYING".into(), 2, 3, Some("cursor-2".into()))
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM raw_run_events WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count retained raw events"),
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM run_event_applications WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(fixture.tenant_id)
        .bind(fixture.run_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count applied run events"),
        2
    );

    database.cleanup().await;
}

#[test]
fn matrix_signed_evidence_rejects_tamper_and_stale_independent_candidate() {
    let bundle = SignedRunmillEvidenceBundle::from_json(include_bytes!(
        "../contracts/fixtures/runmill-signed-evidence-v1.json"
    ))
    .expect("decode exact signed Runmill evidence fixture");
    let predicate = &bundle.statement.predicate;
    let source = &predicate.source;
    let delivery = &predicate.delivery.pull_request;
    let changed_paths = source
        .changed_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_local_checks = predicate
        .policy
        .required_local_checks
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_ci_contexts = predicate
        .policy
        .required_ci_contexts
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let independently_observed_pull_request = PullRequestEvidence {
        repository: delivery.repository.clone(),
        number: delivery.number,
        url: delivery.url.clone(),
        base_sha: source.base_sha.clone(),
        head_sha: source.candidate_sha.clone(),
        required_ci_contexts: required_ci_contexts.clone(),
        successful_ci_contexts: required_ci_contexts.clone(),
    };
    let local_review = predicate
        .reviews
        .iter()
        .find(|review| review.stage == RunmillReviewStage::Local)
        .expect("fixture contains a local review");
    let pull_request_review = predicate
        .reviews
        .iter()
        .find(|review| review.stage == RunmillReviewStage::PullRequest)
        .expect("fixture contains a pull-request review");
    let verifying_key = decode_verifying_key(FIXTURE_WORKER_KEY)
        .expect("decode fixture Runmill worker verifying key");
    let expectation = RunmillEvidenceExpectation {
        trusted_signer: TrustedRunmillEvidenceSigner {
            key_id: &bundle.key_id,
            verifying_key: &verifying_key,
            valid_from: at("2026-08-21T00:00:00Z"),
            valid_until: at("2026-08-22T00:00:00Z"),
            revoked: false,
        },
        observed_at: at("2026-08-21T10:21:00Z"),
        run_id: &predicate.run.run_id,
        attempt_id: predicate.run.attempt_id,
        work_order_id: predicate.run.work_order_id,
        work_order_key_id: &predicate.work_order.signature.key_id,
        work_order_envelope_digest: &predicate.work_order.envelope_digest,
        work_order_payload_digest: &predicate.work_order.payload_digest,
        effective_policy_digest: &predicate.policy.effective_policy_digest,
        forge: &source.forge,
        repository: &source.repository,
        base_ref: &source.base_ref,
        base_sha: &source.base_sha,
        candidate_sha: &source.candidate_sha,
        tree_digest: &source.tree_digest,
        normalized_diff_digest: &source.normalized_diff_digest,
        changed_paths: &changed_paths,
        required_local_checks: &required_local_checks,
        required_ci_contexts: &required_ci_contexts,
        local_reviewer: Some(AuthorizedRunmillReviewer {
            principal_id: &local_review.reviewer_principal,
            profile_id: &local_review.reviewer_profile,
        }),
        pull_request_reviewer: Some(AuthorizedRunmillReviewer {
            principal_id: &pull_request_review.reviewer_principal,
            profile_id: &pull_request_review.reviewer_profile,
        }),
        pull_request_head_ref: &delivery.head_ref,
        independently_observed_pull_request: &independently_observed_pull_request,
    };

    bundle
        .verify(&expectation)
        .expect("valid exact-candidate evidence fixture");

    let mut tampered = bundle.clone();
    tampered.statement.predicate.source.candidate_sha = STALE_CANDIDATE_SHA.into();
    assert!(tampered.verify(&expectation).is_err());

    let stale_expectation = RunmillEvidenceExpectation {
        candidate_sha: STALE_CANDIDATE_SHA,
        ..expectation.clone()
    };
    assert!(bundle.verify(&stale_expectation).is_err());
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp is RFC 3339")
        .with_timezone(&Utc)
}
