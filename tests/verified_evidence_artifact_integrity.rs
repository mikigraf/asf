use std::{env::VarError, time::Duration as StdDuration};

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

const PREREQUISITE_SCHEMA: &str = r"
CREATE FUNCTION asf_reject_row_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'test append-only relation cannot be mutated'
        USING ERRCODE = '23514', CONSTRAINT = 'test_append_only';
END;
$$;

CREATE TABLE evidence_bundles (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE evidence_verifications (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('VALID', 'INVALID', 'INCONCLUSIVE')),
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_bundles(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE artifacts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    digest_algorithm text NOT NULL,
    digest text NOT NULL,
    media_type text NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    object_key text NOT NULL,
    retention_class text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, digest_algorithm, digest)
);

CREATE TABLE evidence_artifacts (
    tenant_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    relationship text NOT NULL,
    PRIMARY KEY (tenant_id, evidence_id, artifact_id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_bundles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES artifacts(tenant_id, id) ON DELETE RESTRICT
);
";

struct ScopedDatabase {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create_if_configured(label: &str) -> Option<Self> {
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
            .expect("connect artifact-integrity test administrator");
        let schema = format!("asf_artifact_{label}_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated artifact-integrity schema");

        let mut scoped_url = Url::parse(&database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let pool = PgPool::connect(scoped_url.as_str())
            .await
            .expect("connect isolated artifact-integrity database");
        sqlx::raw_sql(PREREQUISITE_SCHEMA)
            .execute(&pool)
            .await
            .expect("create migration prerequisite tables");
        sqlx::raw_sql(include_str!(
            "../migrations/0015_verified_evidence_artifact_integrity.sql"
        ))
        .execute(&pool)
        .await
        .expect("apply migration 0015 unchanged");

        Some(Self {
            pool,
            admin,
            schema,
        })
    }

    async fn cleanup(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop isolated artifact-integrity schema");
        self.admin.close().await;
    }
}

#[derive(Clone, Debug)]
struct ManifestArtifact {
    artifact_id: String,
    kind: String,
    digest: String,
    media_type: String,
    size_bytes: i64,
    location_ref: String,
}

impl ManifestArtifact {
    fn new(artifact_id: &str, kind: &str, digest_nibble: char, size_bytes: i64) -> Self {
        let hex = digest_nibble.to_string().repeat(64);
        Self {
            artifact_id: artifact_id.into(),
            kind: kind.into(),
            digest: format!("sha256:{hex}"),
            media_type: "application/octet-stream".into(),
            size_bytes,
            location_ref: format!("cas://sha256/{hex}"),
        }
    }

    fn signed_value(&self) -> Value {
        json!({
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "digest": self.digest,
            "retention_class": "portable",
            "location_ref": self.location_ref,
        })
    }
}

fn required_manifest(extra: bool) -> Vec<ManifestArtifact> {
    let mut manifest = vec![
        ManifestArtifact::new("work-order", "work-order-envelope", 'a', 11),
        ManifestArtifact::new("policy", "effective-policy", 'b', 12),
        ManifestArtifact::new("diff", "normalized-diff", 'c', 13),
    ];
    if extra {
        manifest.push(ManifestArtifact::new(
            "agent-outcome",
            "agent-outcome",
            'd',
            14,
        ));
    }
    manifest
}

fn evidence_payload(manifest: &[ManifestArtifact]) -> Value {
    let work_order_digest = manifest
        .iter()
        .find(|artifact| artifact.kind == "work-order-envelope")
        .expect("work-order artifact")
        .digest
        .clone();
    let policy_digest = manifest
        .iter()
        .find(|artifact| artifact.kind == "effective-policy")
        .expect("policy artifact")
        .digest
        .clone();
    let diff_digest = manifest
        .iter()
        .find(|artifact| artifact.kind == "normalized-diff")
        .expect("diff artifact")
        .digest
        .clone();
    json!({
        "predicate": {
            "artifacts": manifest
                .iter()
                .map(ManifestArtifact::signed_value)
                .collect::<Vec<_>>(),
            "work_order": {
                "envelope_digest": work_order_digest,
                "envelope_artifact_digest": work_order_digest,
            },
            "policy": {
                "effective_policy_digest": policy_digest,
                "effective_policy_artifact_digest": policy_digest,
            },
            "source": {
                "normalized_diff_digest": diff_digest,
                "normalized_diff_artifact_digest": diff_digest,
            }
        }
    })
}

async fn insert_evidence(
    pool: &PgPool,
    tenant_id: Uuid,
    evidence_id: Uuid,
    manifest: &[ManifestArtifact],
) {
    sqlx::query("INSERT INTO evidence_bundles (tenant_id, id, payload) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(evidence_id)
        .bind(evidence_payload(manifest))
        .execute(pool)
        .await
        .expect("insert evidence and its serialization guard");
}

async fn insert_artifact(
    pool: &PgPool,
    tenant_id: Uuid,
    artifact_id: Uuid,
    artifact: &ManifestArtifact,
    created_at: DateTime<Utc>,
) {
    sqlx::query(
        r"
        INSERT INTO artifacts (
            tenant_id, id, digest_algorithm, digest, media_type, byte_size,
            object_key, retention_class, created_at, expires_at
        ) VALUES ($1, $2, 'sha256', $3, $4, $5, $6, 'portable', $7, NULL)
        ",
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .bind(&artifact.digest)
    .bind(&artifact.media_type)
    .bind(artifact.size_bytes)
    .bind(&artifact.location_ref)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert artifact metadata");
}

async fn insert_link(pool: &PgPool, tenant_id: Uuid, evidence_id: Uuid, artifact_id: Uuid) {
    sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship
        ) VALUES ($1, $2, $3, 'OTHER')
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_id)
    .execute(pool)
    .await
    .expect("insert signed artifact link");
}

#[derive(Debug)]
struct DatabaseFailure {
    code: Option<String>,
    constraint: Option<String>,
}

impl DatabaseFailure {
    fn from_error(error: &sqlx::Error) -> Self {
        let Some(database_error) = error.as_database_error() else {
            return Self {
                code: None,
                constraint: None,
            };
        };
        Self {
            code: database_error.code().map(std::borrow::Cow::into_owned),
            constraint: database_error.constraint().map(str::to_owned),
        }
    }
}

#[tokio::test]
async fn repeatable_read_valid_receipt_serializes_with_a_concurrent_manifest_link() {
    let Some(database) = ScopedDatabase::create_if_configured("rr_race").await else {
        return;
    };
    let tenant_id = Uuid::now_v7();
    let evidence_id = Uuid::now_v7();
    let manifest = required_manifest(true);
    let created_at = Utc::now() - Duration::minutes(5);
    insert_evidence(&database.pool, tenant_id, evidence_id, &manifest).await;

    let artifact_ids = (0..manifest.len())
        .map(|_| Uuid::now_v7())
        .collect::<Vec<_>>();
    for (artifact_id, artifact) in artifact_ids.iter().zip(&manifest) {
        insert_artifact(
            &database.pool,
            tenant_id,
            *artifact_id,
            artifact,
            created_at,
        )
        .await;
    }
    for artifact_id in artifact_ids.iter().take(3) {
        insert_link(&database.pool, tenant_id, evidence_id, *artifact_id).await;
    }

    let mut verification = database
        .pool
        .begin()
        .await
        .expect("begin stale verification transaction");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *verification)
        .await
        .expect("set stable verification snapshot");
    let (verification_pid, visible_links, visible_generation): (i32, i64, i64) = sqlx::query_as(
        r"
            SELECT pg_backend_pid(), count(link.artifact_id), guard.generation
            FROM evidence_artifact_manifest_guards AS guard
            LEFT JOIN evidence_artifacts AS link
              ON link.tenant_id = guard.tenant_id
             AND link.evidence_id = guard.evidence_id
            WHERE guard.tenant_id = $1 AND guard.evidence_id = $2
            GROUP BY guard.generation
            ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&mut *verification)
    .await
    .expect("fix verification snapshot before concurrent link");
    assert_eq!(visible_links, 3);
    assert_eq!(visible_generation, 3);

    let mut late_link = database
        .pool
        .begin()
        .await
        .expect("begin concurrent expected-link insertion");
    let late_link_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *late_link)
        .await
        .expect("load link-writer backend PID");
    sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship
        ) VALUES ($1, $2, $3, 'OTHER')
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_ids[3])
    .execute(&mut *late_link)
    .await
    .expect("insert expected link while retaining its guard-row write lock");
    let derived: (String, String) = sqlx::query_as(
        r"
        SELECT manifest_artifact_id, manifest_kind
        FROM evidence_artifacts
        WHERE tenant_id = $1 AND evidence_id = $2 AND artifact_id = $3
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_ids[3])
    .fetch_one(&mut *late_link)
    .await
    .expect("load trigger-derived identity for uncommitted link");
    assert_eq!(derived, ("agent-outcome".into(), "agent-outcome".into()));

    let verification_id = Uuid::now_v7();
    let verifier = tokio::spawn(async move {
        let insertion = sqlx::query(
            r"
            INSERT INTO evidence_verifications (
                tenant_id, id, evidence_id, status, verified_at
            ) VALUES ($1, $2, $3, 'VALID', clock_timestamp())
            ",
        )
        .bind(tenant_id)
        .bind(verification_id)
        .bind(evidence_id)
        .execute(&mut *verification)
        .await;
        if let Err(error) = insertion {
            let failure = DatabaseFailure::from_error(&error);
            verification
                .rollback()
                .await
                .expect("roll back rejected verification insertion");
            return Err(failure);
        }
        verification
            .commit()
            .await
            .map_err(|error| DatabaseFailure::from_error(&error))
    });

    tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            assert!(
                !verifier.is_finished(),
                "verification returned before the concurrent guard writer released its lock"
            );
            let state: Option<(Option<String>, Vec<i32>)> = sqlx::query_as(
                r"
                SELECT wait_event_type, pg_blocking_pids(pid)
                FROM pg_stat_activity
                WHERE pid = $1
                ",
            )
            .bind(verification_pid)
            .fetch_optional(&database.admin)
            .await
            .expect("inspect verification backend lock wait");
            if let Some((Some(wait_event_type), blockers)) = state
                && wait_event_type == "Lock"
                && blockers.contains(&late_link_pid)
            {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("verification must wait on the manifest guard row");

    late_link
        .commit()
        .await
        .expect("commit concurrent expected manifest link");
    let failure = verifier
        .await
        .expect("join stale verification transaction")
        .expect_err("stale REPEATABLE READ verification must not commit");
    assert_eq!(failure.code.as_deref(), Some("40001"), "{failure:?}");

    let (committed_links, committed_generation, valid_receipts): (i64, i64, i64) = sqlx::query_as(
        r"
            SELECT
                (SELECT count(*) FROM evidence_artifacts
                 WHERE tenant_id = $1 AND evidence_id = $2),
                (SELECT generation FROM evidence_artifact_manifest_guards
                 WHERE tenant_id = $1 AND evidence_id = $2),
                (SELECT count(*) FROM evidence_verifications
                 WHERE tenant_id = $1 AND evidence_id = $2 AND status = 'VALID')
            ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&database.pool)
    .await
    .expect("load committed winner after serialization race");
    assert_eq!(
        (committed_links, committed_generation, valid_receipts),
        (4, 4, 0)
    );

    let retry_id = Uuid::now_v7();
    let mut retry = database
        .pool
        .begin()
        .await
        .expect("begin verification retry");
    sqlx::query(
        r"
        INSERT INTO evidence_verifications (
            tenant_id, id, evidence_id, status, verified_at
        ) VALUES ($1, $2, $3, 'VALID', clock_timestamp())
        ",
    )
    .bind(tenant_id)
    .bind(retry_id)
    .bind(evidence_id)
    .execute(&mut *retry)
    .await
    .expect("insert retry receipt after observing committed link");
    retry
        .commit()
        .await
        .expect("commit exact verification retry");
    let generation_after_retry: i64 = sqlx::query_scalar(
        "SELECT generation FROM evidence_artifact_manifest_guards \
         WHERE tenant_id = $1 AND evidence_id = $2",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&database.pool)
    .await
    .expect("load guard advanced by VALID retry");
    assert_eq!(generation_after_retry, 5);

    database.cleanup().await;
}

#[tokio::test]
async fn link_identity_is_derived_and_claimed_identity_or_duplicate_digest_is_rejected() {
    let Some(database) = ScopedDatabase::create_if_configured("identity").await else {
        return;
    };
    let tenant_id = Uuid::now_v7();
    let evidence_id = Uuid::now_v7();
    let manifest = required_manifest(false);
    let created_at = Utc::now() - Duration::minutes(5);
    insert_evidence(&database.pool, tenant_id, evidence_id, &manifest).await;
    let artifact_ids = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    for (artifact_id, artifact) in artifact_ids.iter().zip(&manifest) {
        insert_artifact(
            &database.pool,
            tenant_id,
            *artifact_id,
            artifact,
            created_at,
        )
        .await;
    }

    insert_link(&database.pool, tenant_id, evidence_id, artifact_ids[0]).await;
    let derived: (String, String) = sqlx::query_as(
        r"
        SELECT manifest_artifact_id, manifest_kind
        FROM evidence_artifacts
        WHERE tenant_id = $1 AND evidence_id = $2 AND artifact_id = $3
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_ids[0])
    .fetch_one(&database.pool)
    .await
    .expect("load auto-derived signed identity");
    assert_eq!(derived, ("work-order".into(), "work-order-envelope".into()));

    let wrong_id = sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship,
            manifest_artifact_id, manifest_kind
        ) VALUES ($1, $2, $3, 'OTHER', 'forged-policy-id', 'effective-policy')
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_ids[1])
    .execute(&database.pool)
    .await
    .expect_err("caller cannot substitute a signed manifest artifact ID");
    let wrong_id = DatabaseFailure::from_error(&wrong_id);
    assert_eq!(wrong_id.code.as_deref(), Some("23514"), "{wrong_id:?}");
    assert_eq!(
        wrong_id.constraint.as_deref(),
        Some("evidence_artifact_link_exact_signed_entry"),
        "{wrong_id:?}"
    );

    let wrong_kind = sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship,
            manifest_artifact_id, manifest_kind
        ) VALUES ($1, $2, $3, 'OTHER', 'policy', 'review')
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(artifact_ids[1])
    .execute(&database.pool)
    .await
    .expect_err("caller cannot substitute a signed manifest kind");
    let wrong_kind = DatabaseFailure::from_error(&wrong_kind);
    assert_eq!(wrong_kind.code.as_deref(), Some("23514"), "{wrong_kind:?}");
    assert_eq!(
        wrong_kind.constraint.as_deref(),
        Some("evidence_artifact_link_exact_signed_entry"),
        "{wrong_kind:?}"
    );

    let duplicate_evidence_id = Uuid::now_v7();
    let mut duplicate_manifest = manifest.clone();
    let mut duplicate = ManifestArtifact::new("duplicate-work-order", "agent-outcome", 'd', 14);
    duplicate.digest.clone_from(&manifest[0].digest);
    duplicate.location_ref.clone_from(&manifest[0].location_ref);
    duplicate_manifest.push(duplicate);
    insert_evidence(
        &database.pool,
        tenant_id,
        duplicate_evidence_id,
        &duplicate_manifest,
    )
    .await;
    let duplicate_digest = sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship
        ) VALUES ($1, $2, $3, 'OTHER')
        ",
    )
    .bind(tenant_id)
    .bind(duplicate_evidence_id)
    .bind(artifact_ids[0])
    .execute(&database.pool)
    .await
    .expect_err("one content digest cannot identify two signed manifest entries");
    let duplicate_digest = DatabaseFailure::from_error(&duplicate_digest);
    assert_eq!(
        duplicate_digest.code.as_deref(),
        Some("23514"),
        "{duplicate_digest:?}"
    );
    assert_eq!(
        duplicate_digest.constraint.as_deref(),
        Some("evidence_artifact_link_exact_signed_entry"),
        "{duplicate_digest:?}"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn valid_receipt_rejects_artifacts_created_after_its_verification_time() {
    let Some(database) = ScopedDatabase::create_if_configured("creation_time").await else {
        return;
    };
    let tenant_id = Uuid::now_v7();
    let evidence_id = Uuid::now_v7();
    let manifest = required_manifest(false);
    let verification_time = Utc::now();
    insert_evidence(&database.pool, tenant_id, evidence_id, &manifest).await;

    for (position, artifact) in manifest.iter().enumerate() {
        let artifact_id = Uuid::now_v7();
        let created_at = if position == 2 {
            verification_time + Duration::minutes(1)
        } else {
            verification_time - Duration::minutes(1)
        };
        insert_artifact(&database.pool, tenant_id, artifact_id, artifact, created_at).await;
        insert_link(&database.pool, tenant_id, evidence_id, artifact_id).await;
    }
    let generation_before: i64 = sqlx::query_scalar(
        "SELECT generation FROM evidence_artifact_manifest_guards \
         WHERE tenant_id = $1 AND evidence_id = $2",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&database.pool)
    .await
    .expect("load guard before invalid verification");
    assert_eq!(generation_before, 3);

    let mut transaction = database
        .pool
        .begin()
        .await
        .expect("begin creation-time verification");
    sqlx::query(
        r"
        INSERT INTO evidence_verifications (
            tenant_id, id, evidence_id, status, verified_at
        ) VALUES ($1, $2, $3, 'VALID', $4)
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::now_v7())
    .bind(evidence_id)
    .bind(verification_time)
    .execute(&mut *transaction)
    .await
    .expect("defer exact-artifact validation until commit");
    let error = transaction
        .commit()
        .await
        .expect_err("VALID receipt cannot predate a linked artifact");
    let failure = DatabaseFailure::from_error(&error);
    assert_eq!(failure.code.as_deref(), Some("23514"), "{failure:?}");
    assert_eq!(
        failure.constraint.as_deref(),
        Some("evidence_verifications_require_exact_artifacts"),
        "{failure:?}"
    );

    let (generation_after, receipt_count): (i64, i64) = sqlx::query_as(
        r"
        SELECT guard.generation, count(verification.id)
        FROM evidence_artifact_manifest_guards AS guard
        LEFT JOIN evidence_verifications AS verification
          ON verification.tenant_id = guard.tenant_id
         AND verification.evidence_id = guard.evidence_id
        WHERE guard.tenant_id = $1 AND guard.evidence_id = $2
        GROUP BY guard.generation
        ",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&database.pool)
    .await
    .expect("load state after rejected creation-time proof");
    assert_eq!((generation_after, receipt_count), (3, 0));

    database.cleanup().await;
}
