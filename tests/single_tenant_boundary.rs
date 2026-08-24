use std::{env::VarError, sync::Arc};

use asf::ledger::PgLedger;
use sqlx::PgPool;
use tokio::sync::Barrier;
use url::Url;
use uuid::Uuid;

const UPGRADE_FAILURE_CONSTRAINT: &str = "v1_tenant_boundary_upgrade_requires_at_most_one_tenant";
const CONFIGURED_TENANT_CONSTRAINT: &str = "v1_tenant_boundary_configured_tenant_only";
const ACTIVATION_EXACT_TENANT_CONSTRAINT: &str =
    "v1_tenant_deployment_guard_requires_exactly_one_tenant";
const ACTIVATION_TARGET_MISSING_CONSTRAINT: &str = "v1_tenant_deployment_guard_target_missing";
const GUARD_APPEND_ONLY_CONSTRAINT: &str = "v1_tenant_deployment_guard_append_only";
const GUARD_TRUNCATE_CONSTRAINT: &str = "v1_tenant_deployment_guard_truncate_forbidden";
const TENANT_DELETE_CONSTRAINT: &str = "v1_tenant_boundary_delete_forbidden";
const TENANT_TRUNCATE_CONSTRAINT: &str = "v1_tenant_boundary_truncate_forbidden";

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create_legacy_if_configured() -> Option<Self> {
        let database_url = test_database_url()?;
        let admin = PgPool::connect(&database_url)
            .await
            .expect("connect single-tenant test administrator");
        let schema = format!("asf_single_tenant_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated single-tenant schema");

        let mut scoped_url = Url::parse(&database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated single-tenant ledger");
        apply_migrations_through_0019(&ledger).await;

        Some(Self {
            ledger,
            admin,
            schema,
        })
    }

    async fn create_fully_migrated_if_configured() -> Option<Self> {
        let database = Self::create_legacy_if_configured().await?;
        apply_0020(&database.ledger).await;
        Some(database)
    }

    async fn cleanup(self) {
        self.ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop isolated single-tenant schema");
        self.admin.close().await;
    }
}

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

async fn apply_migrations_through_0019(ledger: &PgLedger) {
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin migrations through 0019");
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
        include_str!("../migrations/0012_worker_authority_lifetime_and_closure_preservation.sql"),
        include_str!("../migrations/0013_source_closure_terminal_invariants.sql"),
        include_str!("../migrations/0014_evidence_verification_job_ownership.sql"),
        include_str!("../migrations/0015_verified_evidence_artifact_integrity.sql"),
        include_str!("../migrations/0016_evidence_verification_receipt_integrity.sql"),
        include_str!("../migrations/0017_cancellation_receipt_integrity.sql"),
        include_str!("../migrations/0018_cancellation_escalation_supersession.sql"),
        include_str!("../migrations/0019_shared_work_finality_gate.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut *transaction)
            .await
            .expect("apply migration through 0019");
    }
    transaction
        .commit()
        .await
        .expect("commit migrations through 0019");
}

async fn apply_0020(ledger: &PgLedger) {
    let mut transaction = ledger.pool().begin().await.expect("begin 0020 upgrade");
    sqlx::raw_sql(include_str!(
        "../migrations/0020_v1_single_tenant_boundary.sql"
    ))
    .execute(&mut *transaction)
    .await
    .expect("apply 0020 single-tenant boundary");
    transaction.commit().await.expect("commit 0020 upgrade");
}

async fn insert_tenant(pool: &PgPool, id: Uuid, slug_prefix: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("{slug_prefix}-{}", id.simple()))
        .bind("Single tenant boundary test")
        .execute(pool)
        .await
        .map(|_| ())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some(expected)
    );
}

async fn provision_or_attempt_tenant(
    pool: &PgPool,
    id: Uuid,
    slug_prefix: &str,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await?;
    let configured_tenant: Option<Uuid> = sqlx::query_scalar(
        "SELECT configured_tenant_id \
         FROM v1_tenant_deployment_guards \
         WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await?;

    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("{slug_prefix}-{}", id.simple()))
        .bind("Single tenant boundary test")
        .execute(&mut *transaction)
        .await?;
    if configured_tenant.is_none() {
        sqlx::query(
            "UPDATE v1_tenant_deployment_guards \
             SET configured_tenant_id = $1 WHERE singleton",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await
}

#[tokio::test]
async fn single_tenant_upgrade_accepts_empty_and_one_tenant_databases() {
    let Some(empty_database) = ScopedDatabase::create_legacy_if_configured().await else {
        return;
    };
    apply_0020(&empty_database.ledger).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT configured_tenant_id FROM v1_tenant_deployment_guards WHERE singleton",
        )
        .fetch_one(empty_database.ledger.pool())
        .await
        .expect("load empty upgraded deployment guard"),
        None
    );
    empty_database.cleanup().await;

    let Some(one_tenant_database) = ScopedDatabase::create_legacy_if_configured().await else {
        unreachable!("the configured database URL must remain available");
    };
    let tenant_id = Uuid::now_v7();
    insert_tenant(one_tenant_database.ledger.pool(), tenant_id, "legacy")
        .await
        .expect("insert one legacy tenant");
    apply_0020(&one_tenant_database.ledger).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT configured_tenant_id FROM v1_tenant_deployment_guards WHERE singleton",
        )
        .fetch_one(one_tenant_database.ledger.pool())
        .await
        .expect("load upgraded configured tenant"),
        Some(tenant_id)
    );
    one_tenant_database.cleanup().await;
}

#[tokio::test]
async fn single_tenant_upgrade_rejects_two_legacy_tenants_and_rolls_back() {
    let Some(database) = ScopedDatabase::create_legacy_if_configured().await else {
        return;
    };
    insert_tenant(database.ledger.pool(), Uuid::now_v7(), "legacy-a")
        .await
        .expect("insert first legacy tenant");
    insert_tenant(database.ledger.pool(), Uuid::now_v7(), "legacy-b")
        .await
        .expect("insert second legacy tenant");

    let mut transaction = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin rejected 0020 upgrade");
    let error = sqlx::raw_sql(include_str!(
        "../migrations/0020_v1_single_tenant_boundary.sql"
    ))
    .execute(&mut *transaction)
    .await
    .expect_err("two legacy tenants must reject the 0020 upgrade");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some(UPGRADE_FAILURE_CONSTRAINT)
    );
    transaction
        .rollback()
        .await
        .expect("roll back rejected 0020 upgrade");

    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS (\
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = current_schema() \
                  AND table_name = 'v1_tenant_deployment_guards'\
            )"
        )
        .fetch_one(database.ledger.pool())
        .await
        .expect("verify rejected upgrade left no deployment guard")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM tenants")
            .fetch_one(database.ledger.pool())
            .await
            .expect("count tenants after rejected upgrade"),
        2
    );
    database.cleanup().await;
}

#[tokio::test]
async fn deployment_guard_cannot_activate_one_of_multiple_unconfigured_tenants() {
    let Some(database) = ScopedDatabase::create_fully_migrated_if_configured().await else {
        return;
    };
    let configured_tenant = Uuid::now_v7();
    insert_tenant(database.ledger.pool(), configured_tenant, "fixture-a")
        .await
        .expect("insert first unconfigured fixture tenant");
    insert_tenant(database.ledger.pool(), Uuid::now_v7(), "fixture-b")
        .await
        .expect("insert second unconfigured fixture tenant");

    let error = sqlx::query(
        "UPDATE v1_tenant_deployment_guards \
         SET configured_tenant_id = $1 WHERE singleton",
    )
    .bind(configured_tenant)
    .execute(database.ledger.pool())
    .await
    .expect_err("the guard cannot bind one tenant while another fixture remains");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some(ACTIVATION_EXACT_TENANT_CONSTRAINT)
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT configured_tenant_id FROM v1_tenant_deployment_guards WHERE singleton",
        )
        .fetch_one(database.ledger.pool())
        .await
        .expect("load unactivated deployment guard"),
        None
    );
    database.cleanup().await;
}

#[tokio::test]
async fn activated_boundary_rejects_every_direct_rebinding_or_erasure_path() {
    let Some(database) = ScopedDatabase::create_fully_migrated_if_configured().await else {
        return;
    };
    let tenant_id = Uuid::now_v7();
    let missing_id = Uuid::now_v7();

    let missing = sqlx::query(
        "UPDATE v1_tenant_deployment_guards \
         SET configured_tenant_id = $1 WHERE singleton",
    )
    .bind(missing_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("an absent tenant cannot activate the guard");
    assert_constraint(&missing, ACTIVATION_TARGET_MISSING_CONSTRAINT);

    insert_tenant(database.ledger.pool(), tenant_id, "configured")
        .await
        .expect("insert configured tenant");
    sqlx::query(
        "UPDATE v1_tenant_deployment_guards \
         SET configured_tenant_id = $1 WHERE singleton",
    )
    .bind(tenant_id)
    .execute(database.ledger.pool())
    .await
    .expect("activate deployment boundary");

    sqlx::query("UPDATE tenants SET status = 'MAINTENANCE' WHERE id = $1")
        .bind(tenant_id)
        .execute(database.ledger.pool())
        .await
        .expect("ordinary configured-tenant updates remain legal");

    let foreign_id = Uuid::now_v7();
    let foreign = insert_tenant(database.ledger.pool(), foreign_id, "foreign")
        .await
        .expect_err("a foreign tenant cannot enter an activated deployment");
    assert_constraint(&foreign, CONFIGURED_TENANT_CONSTRAINT);

    let rebind_tenant = sqlx::query("UPDATE tenants SET id = $2 WHERE id = $1")
        .bind(tenant_id)
        .bind(foreign_id)
        .execute(database.ledger.pool())
        .await
        .expect_err("the configured tenant ID cannot be rebound");
    assert_constraint(&rebind_tenant, CONFIGURED_TENANT_CONSTRAINT);

    for query in [
        "UPDATE v1_tenant_deployment_guards SET configured_tenant_id = NULL WHERE singleton",
        "DELETE FROM v1_tenant_deployment_guards WHERE singleton",
    ] {
        let error = sqlx::query(query)
            .execute(database.ledger.pool())
            .await
            .expect_err("the activated guard cannot be reset or deleted");
        assert_constraint(&error, GUARD_APPEND_ONLY_CONSTRAINT);
    }

    let delete_tenant = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(database.ledger.pool())
        .await
        .expect_err("the configured tenant cannot be deleted");
    assert_constraint(&delete_tenant, TENANT_DELETE_CONSTRAINT);

    let truncate_guard = sqlx::query("TRUNCATE v1_tenant_deployment_guards")
        .execute(database.ledger.pool())
        .await
        .expect_err("the deployment guard cannot be truncated");
    assert_constraint(&truncate_guard, GUARD_TRUNCATE_CONSTRAINT);

    let truncate_tenants = sqlx::query("TRUNCATE tenants CASCADE")
        .execute(database.ledger.pool())
        .await
        .expect_err("an activated tenant table cannot be truncated");
    assert_constraint(&truncate_tenants, TENANT_TRUNCATE_CONSTRAINT);

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_post_migration_tenant_bootstraps_allow_exactly_one_tenant() {
    let Some(database) = ScopedDatabase::create_fully_migrated_if_configured().await else {
        return;
    };
    let barrier = Arc::new(Barrier::new(2));
    let first_pool = database.ledger.pool().clone();
    let second_pool = database.ledger.pool().clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);

    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        provision_or_attempt_tenant(&first_pool, Uuid::now_v7(), "concurrent-a").await
    });
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        provision_or_attempt_tenant(&second_pool, Uuid::now_v7(), "concurrent-b").await
    });
    let first = first
        .await
        .expect("first concurrent insert task must not panic");
    let second = second
        .await
        .expect("second concurrent insert task must not panic");
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let error = first
        .err()
        .or_else(|| second.err())
        .expect("one concurrent bootstrap insert must lose the deployment boundary");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some(CONFIGURED_TENANT_CONSTRAINT)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM tenants")
            .fetch_one(database.ledger.pool())
            .await
            .expect("count post-concurrency tenants"),
        1
    );
    database.cleanup().await;
}
