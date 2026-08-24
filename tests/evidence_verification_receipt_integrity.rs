use std::env::VarError;

use asf::{ledger::PgLedger, runtime::VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

const EXACT_COMPLETION_CONSTRAINT: &str = "workflow_jobs_exact_verify_evidence_completion";
const STRICT_RECEIPT_CONSTRAINT: &str = "evidence_verifications_valid_receipt_v1_strict";
const RECEIPT_CLOCK_CONSTRAINT: &str = "evidence_verifications_valid_receipt_db_clock";

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create_if_configured() -> Option<Self> {
        let database_url = match std::env::var("ASF_TEST_DATABASE_URL") {
            Ok(database_url) => {
                assert!(
                    !database_url.trim().is_empty(),
                    "ASF_TEST_DATABASE_URL is present but empty"
                );
                database_url
            }
            Err(VarError::NotPresent) if std::env::var_os("CI").is_some() => {
                panic!("CI must configure ASF_TEST_DATABASE_URL")
            }
            Err(VarError::NotPresent) => return None,
            Err(error) => panic!("read ASF_TEST_DATABASE_URL: {error}"),
        };

        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect receipt-integrity test administrator");
        let schema = format!("asf_receipt_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated receipt-integrity schema");

        let mut scoped_url = Url::parse(&database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated receipt-integrity ledger");
        ledger
            .migrate()
            .await
            .expect("apply full receipt-integrity migration chain");

        Some(Self {
            ledger,
            admin,
            schema,
        })
    }

    async fn cleanup(self) {
        self.ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop isolated receipt-integrity schema");
        self.admin.close().await;
    }
}

#[derive(Debug)]
struct ClaimFixture {
    tenant_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    workflow_id: Uuid,
    job_id: Uuid,
    lease_owner: String,
}

impl ClaimFixture {
    async fn insert(ledger: &PgLedger) -> Self {
        let tenant_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let policy_digest = digest('a');
        let source_digest = digest('b');
        let lease_owner = "reactor:receipt-integrity-test".to_owned();

        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin exact verification-claim fixture");
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("receipt-{}", tenant_id.simple()))
            .bind("Receipt integrity test")
            .execute(&mut *transaction)
            .await
            .expect("insert receipt-integrity tenant");
        sqlx::query(
            r"
            INSERT INTO policy_versions (
                id, tenant_id, scope, schema_version, digest,
                canonical_bytes, policy, created_by
            ) VALUES ($1, $2, 'TENANT', 'asf.policy/v1', $3, $4, '{}'::jsonb, $5)
            ",
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(&policy_digest)
        .bind(b"{}".as_slice())
        .bind("operator:receipt-integrity-test")
        .execute(&mut *transaction)
        .await
        .expect("insert receipt-integrity policy");
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, source_system, external_id, source_revision,
                normalized_content, content_digest, connector_identity,
                source_updated_at
            ) VALUES (
                $1, $2, 'API', $3, 'revision-1', '{}'::jsonb, $4,
                'connector:receipt-integrity-test', clock_timestamp()
            )
            ",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(format!("receipt-{work_item_id}"))
        .bind(&source_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert receipt-integrity source snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, state, normalized_priority
            ) VALUES ($1, $2, $3, 'API', $4, 'DISCOVERED', 50)
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(format!("receipt-{work_item_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert receipt-integrity work item");
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest,
                fence_token
            ) VALUES (
                $1, $2, $3, 1, 'CREATED', $4, 'refs/heads/main', $5,
                $6, $7, 1
            )
            ",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(format!("receipt-attempt:{attempt_id}"))
        .bind("1".repeat(40))
        .bind(&source_digest)
        .bind(&policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert receipt-integrity attempt");
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state,
                reducer_version, event_cursor, fence_token
            ) VALUES (
                $1, $2, $3, 'RECEIPT_INTEGRITY_TEST', 'ACTIVE',
                'asf.workflow/v1', 0, 1
            )
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert receipt-integrity workflow");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'VERIFY_EVIDENCE', $6, 'RUNNING',
                '{}'::jsonb, $7, 1, 25, 1, $8,
                clock_timestamp() + interval '5 minutes'
            )
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
        .bind(format!("receipt-verify:{job_id}"))
        .bind(&lease_owner)
        .execute(&mut *transaction)
        .await
        .expect("insert exact running verification claim");
        transaction
            .commit()
            .await
            .expect("commit exact verification-claim fixture");

        Self {
            tenant_id,
            work_item_id,
            attempt_id,
            workflow_id,
            job_id,
            lease_owner,
        }
    }
}

fn digest(nibble: char) -> String {
    format!("sha256:{}", nibble.to_string().repeat(64))
}

fn receipt_details(
    fixture: &ClaimFixture,
    evidence_id: Uuid,
    run_id: Uuid,
    observed_at: DateTime<Utc>,
    required_ci_contexts: &Value,
    successful_ci_contexts: &Value,
) -> Value {
    json!({
        "schema": "asf.evidence-verification-receipt.v1",
        "evidence_id": evidence_id,
        "work_item_id": fixture.work_item_id,
        "attempt_id": fixture.attempt_id,
        "run_id": run_id,
        "evidence_digest": digest('c'),
        "work_order_digest": digest('d'),
        "expectation_digest": digest('e'),
        "verification_job_id": fixture.job_id,
        "verification_job_fence_token": 1,
        "verification_job_completed_by": fixture.lease_owner,
        "verifier": "asf:github-evidence-verifier/v1",
        "pull_request": {
            "repository": "acme/widgets",
            "number": 42,
            "url": "https://github.com/acme/widgets/pull/42",
            "base_sha": "1".repeat(40),
            "head_sha": "2".repeat(40),
            "required_ci_contexts": required_ci_contexts,
            "successful_ci_contexts": successful_ci_contexts,
        },
        "provider_revision": "github:pull:42:revision",
        "observed_at": observed_at,
    })
}

async fn insert_valid_receipt_attack(
    fixture: &ClaimFixture,
    ledger: &PgLedger,
    details: Value,
    verified_at: DateTime<Utc>,
) -> sqlx::Error {
    let evidence_id = details
        .get("evidence_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("attack details carry an evidence UUID");
    let run_id = details
        .get("run_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("attack details carry a run UUID");
    sqlx::query(
        r"
        INSERT INTO evidence_verifications (
            id, tenant_id, evidence_id, work_item_id, attempt_id, run_id,
            evidence_digest, work_order_digest, verifier, status,
            expectation_digest, workflow_job_id, workflow_job_fence_token,
            workflow_job_completed_by, details, verified_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            'asf:github-evidence-verifier/v1', 'VALID', $9,
            $10, 1, $11, $12, $13
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.tenant_id)
    .bind(evidence_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(run_id)
    .bind(digest('c'))
    .bind(digest('d'))
    .bind(digest('e'))
    .bind(fixture.job_id)
    .bind(&fixture.lease_owner)
    .bind(details)
    .bind(verified_at)
    .execute(ledger.pool())
    .await
    .expect_err("malformed VALID receipt must be rejected before foreign-key resolution")
}

fn constraint(error: &sqlx::Error) -> Option<&str> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
}

#[tokio::test]
async fn migration_0016_guards_exact_completion_receipt_shape_and_clock() {
    let Some(database) = ScopedDatabase::create_if_configured().await else {
        return;
    };
    let fixture = ClaimFixture::insert(&database.ledger).await;

    let direct_job_id = Uuid::now_v7();
    let direct_completion = sqlx::query(
        r"
        INSERT INTO workflow_jobs (
            id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
            job_type, activity_contract_id, status, payload, result, idempotency_key,
            attempt_count, max_attempts, fence_token, completed_by, completion_fence_token,
            completed_at
        ) VALUES (
            $1, $2, $3, $4, $5, 'VERIFY_EVIDENCE', $6, 'COMPLETED',
            '{}'::jsonb, '{}'::jsonb, $7, 1, 25, 1, $8, 1,
            clock_timestamp()
        )
        ",
    )
    .bind(direct_job_id)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID)
    .bind(format!("receipt-direct-complete:{direct_job_id}"))
    .bind(&fixture.lease_owner)
    .execute(database.ledger.pool())
    .await
    .expect_err("direct terminal VERIFY_EVIDENCE insertion must fail");
    assert_eq!(
        constraint(&direct_completion),
        Some(EXACT_COMPLETION_CONSTRAINT)
    );

    let completed_at: DateTime<Utc> = sqlx::query_scalar(
        r"
        UPDATE workflow_jobs
        SET status = 'COMPLETED',
            result = '{}'::jsonb,
            completed_by = lease_owner,
            completion_fence_token = fence_token,
            completed_at = '2000-01-01T00:00:00Z'::timestamptz,
            lease_owner = NULL,
            lease_expires_at = NULL,
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        RETURNING completed_at
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("exact RUNNING verification claim can complete");
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(database.ledger.pool())
        .await
        .expect("read database clock after exact completion");
    assert!(
        completed_at > Utc::now() - Duration::minutes(1)
            && completed_at <= database_now
            && database_now - completed_at < Duration::seconds(5),
        "the completion trigger must replace caller time with the database clock"
    );
    let completed_claim: (String, String, i64, i32) = sqlx::query_as(
        r"
        SELECT status, completed_by, completion_fence_token, attempt_count
        FROM workflow_jobs
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load exact completed verification claim");
    assert_eq!(
        completed_claim,
        ("COMPLETED".to_owned(), fixture.lease_owner.clone(), 1, 1),
        "the completed row must retain the exact owner, fence, and attempt"
    );

    let duplicate_evidence_id = Uuid::now_v7();
    let duplicate_run_id = Uuid::now_v7();
    let duplicate_details = receipt_details(
        &fixture,
        duplicate_evidence_id,
        duplicate_run_id,
        Utc::now(),
        &json!(["build", "build"]),
        &json!(["build"]),
    );
    let duplicate_ci =
        insert_valid_receipt_attack(&fixture, &database.ledger, duplicate_details, Utc::now())
            .await;
    assert_eq!(constraint(&duplicate_ci), Some(STRICT_RECEIPT_CONSTRAINT));

    let stale_details = receipt_details(
        &fixture,
        Uuid::now_v7(),
        Uuid::now_v7(),
        Utc::now() - Duration::days(1),
        &json!(["build"]),
        &json!(["build"]),
    );
    let stale_clock = insert_valid_receipt_attack(
        &fixture,
        &database.ledger,
        stale_details,
        Utc::now() - Duration::days(1),
    )
    .await;
    assert_eq!(constraint(&stale_clock), Some(RECEIPT_CLOCK_CONSTRAINT));

    database.cleanup().await;
}

#[test]
fn production_verifier_happy_path_remains_in_its_dedicated_integration_suite() {
    let production_suite = include_str!("evidence_verification.rs");
    for marker in [
        "production_verifier_atomically_proves_and_advances_exact_evidence",
        "EvidenceVerificationHandler::new",
        "ActivityOutcome::TransactionCommitted",
    ] {
        assert!(
            production_suite.contains(marker),
            "production verifier coverage lost marker {marker}"
        );
    }
}
