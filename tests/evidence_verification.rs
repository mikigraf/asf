use chrono::SubsecRound as _;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use asf::{
    Error, Result,
    artifacts::{ArtifactStore, StoredArtifact},
    contracts::{
        RunmillEvidenceTimestamp, RunmillRetentionClass, RunmillSignedWorkOrderV1,
        SignedRunmillEvidenceBundle,
    },
    crypto::{Ed25519Signer, canonical_json, encode_verifying_key, sha256_digest},
    domain::TenantId,
    ledger::{ClaimedWorkflowJob, PgLedger},
    ports::{
        BaseRefObservation, ForgeGateway, ForgeGatewayError, ForgeResult,
        ObservePullRequestRequest, PULL_REQUEST_OBSERVATION_SCHEMA_V1, PullRequestObservation,
        PullRequestState, RemoteCiObservation, RemoteCiState, ResolveBaseRefRequest,
    },
    runtime::{
        ActivityControls, ActivityOutcome, EvidenceVerificationHandler, JobHandler,
        VERIFY_EVIDENCE, VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID,
    },
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::RwLock;
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
            .expect("connect evidence-verification test administrator");
        let schema = format!("asf_evidence_verify_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated evidence-verification schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated evidence-verification ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated evidence-verification schema");
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
            .expect("drop isolated evidence-verification schema");
        self.admin.close().await;
    }
}

#[derive(Debug, Default)]
struct MemoryArtifactStore {
    bytes: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl MemoryArtifactStore {
    fn with_artifacts(bytes: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            bytes: RwLock::new(bytes),
        }
    }

    async fn corrupt(&self, digest: &str) {
        self.bytes
            .write()
            .await
            .insert(digest.to_owned(), b"corrupt artifact bytes".to_vec());
    }
}

#[async_trait]
impl ArtifactStore for MemoryArtifactStore {
    async fn put(
        &self,
        bytes: &[u8],
        media_type: &str,
        producer: &str,
        retention_class: &str,
    ) -> Result<StoredArtifact> {
        let digest = sha256_digest(bytes);
        self.bytes
            .write()
            .await
            .insert(digest.clone(), bytes.to_vec());
        Ok(StoredArtifact {
            digest,
            media_type: media_type.to_owned(),
            size: bytes.len() as u64,
            producer: producer.to_owned(),
            retention_class: retention_class.to_owned(),
            stored_at: Utc::now().trunc_subsecs(6),
        })
    }

    async fn get(&self, digest: &str) -> Result<Vec<u8>> {
        self.bytes
            .read()
            .await
            .get(digest)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("test artifact {digest}")))
    }
}

#[derive(Debug, Clone, Copy)]
enum ForgeMode {
    Valid,
    StaleCi,
    StaleObservation,
    QuarantineDuringObservation,
}

#[derive(Debug)]
struct FakeForge {
    mode: ForgeMode,
    calls: AtomicUsize,
    quarantine: Option<(PgPool, Uuid, Uuid)>,
}

impl FakeForge {
    fn new(mode: ForgeMode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            quarantine: None,
        }
    }

    fn with_quarantine(pool: PgPool, tenant_id: Uuid, worker_id: Uuid) -> Self {
        Self {
            mode: ForgeMode::QuarantineDuringObservation,
            calls: AtomicUsize::new(0),
            quarantine: Some((pool, tenant_id, worker_id)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ForgeGateway for FakeForge {
    async fn resolve_base_ref(
        &self,
        _request: &ResolveBaseRefRequest,
    ) -> ForgeResult<BaseRefObservation> {
        Err(ForgeGatewayError::UnsupportedContract {
            detail: "not used by evidence-verification tests".into(),
        })
    }

    async fn observe_pull_request(
        &self,
        request: &ObservePullRequestRequest,
    ) -> ForgeResult<PullRequestObservation> {
        request.validate()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((pool, tenant_id, worker_id)) = &self.quarantine {
            sqlx::query(
                r"
                UPDATE workers
                SET status = 'QUARANTINED',
                    aggregate_version = aggregate_version + 1,
                    updated_at = clock_timestamp()
                WHERE tenant_id = $1 AND id = $2
                ",
            )
            .bind(tenant_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .expect("quarantine worker during independent forge observation");
        }
        let ci_sha = if matches!(self.mode, ForgeMode::StaleCi) {
            "c".repeat(40)
        } else {
            request.expected_candidate_sha.clone()
        };
        Ok(PullRequestObservation {
            schema: PULL_REQUEST_OBSERVATION_SCHEMA_V1.into(),
            pull_request: request.pull_request.clone(),
            url: format!(
                "https://github.com/{}/pull/{}",
                request.pull_request.repository, request.pull_request.number
            ),
            state: PullRequestState::Open,
            base_sha: request.expected_base_sha.clone(),
            head_sha: request.expected_candidate_sha.clone(),
            merge_sha: None,
            ci: BTreeMap::from([(
                "ci/test".into(),
                RemoteCiObservation {
                    candidate_sha: ci_sha,
                    state: RemoteCiState::Success,
                },
            )]),
            provider_revision: "github:pr:42:head-a:ci-success".into(),
            observed_at: if matches!(self.mode, ForgeMode::StaleObservation) {
                Utc::now().trunc_subsecs(6) - Duration::minutes(6)
            } else {
                Utc::now().trunc_subsecs(6)
            },
        })
    }
}

struct Fixture {
    tenant_id: Uuid,
    work_item_id: Uuid,
    evidence_id: Uuid,
    worker_id: Uuid,
    job: ClaimedWorkflowJob,
    work_order_key_id: String,
    work_order_key: ed25519_dalek::VerifyingKey,
    artifacts: Arc<MemoryArtifactStore>,
    artifact_digests: Vec<String>,
}

impl Fixture {
    async fn insert_with_evidence_age(
        ledger: &PgLedger,
        forge_worker_signature: bool,
        evidence_age_minutes: i64,
    ) -> Self {
        Self::insert_with_evidence_age_and_persisted_contract(
            ledger,
            forge_worker_signature,
            evidence_age_minutes,
            VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID,
        )
        .await
    }

    /// Persists the owning `workflow_jobs` row with `persisted_activity_contract_id`
    /// from its initial INSERT (never via a later UPDATE, which migration 0023's
    /// immutability trigger rejects). The in-memory `ClaimedWorkflowJob` always
    /// carries the canonical contract, so tests that use this to exercise a
    /// mismatch drive failure through the SQL `activity_contract_id` predicate
    /// rather than any in-memory/parser check.
    async fn insert_with_evidence_age_and_persisted_contract(
        ledger: &PgLedger,
        forge_worker_signature: bool,
        evidence_age_minutes: i64,
        persisted_activity_contract_id: &str,
    ) -> Self {
        let tenant_id = Uuid::now_v7();
        let repository_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let work_item_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let work_order_id = Uuid::now_v7();
        let worker_id = Uuid::now_v7();
        let worker_session_id = Uuid::now_v7();
        let run_id = Uuid::now_v7();
        let evidence_id = Uuid::now_v7();
        let workflow_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let source_bytes = br#"{"source":"ASF-42"}"#;
        let source_digest = sha256_digest(source_bytes);
        let policy_bytes = br#"{"policy":"verifier-test"}"#.to_vec();
        let policy_digest = sha256_digest(&policy_bytes);
        let diff_bytes = b"diff --git a/src/lib.rs b/src/lib.rs\n".to_vec();
        let diff_digest = sha256_digest(&diff_bytes);
        let expectation_digest = sha256_digest(b"exact-candidate-expectation");
        let base_sha = "b".repeat(40);
        let candidate_sha = "a".repeat(40);
        let external_run_id = "run_01JVERIFY";
        let now = Utc::now().trunc_subsecs(6);
        let work_order_issued_at = now - Duration::minutes(evidence_age_minutes + 8);
        let work_order_not_before = now - Duration::minutes(evidence_age_minutes + 7);
        let run_completed_at = now - Duration::minutes(evidence_age_minutes + 1);
        let evidence_issued_at = now - Duration::minutes(evidence_age_minutes);
        let attempt_terminal_at = evidence_issued_at + Duration::seconds(15);
        let worker_session_started_at = now - Duration::minutes(evidence_age_minutes + 6);
        let run_adopted_at = now - Duration::minutes(evidence_age_minutes + 5);
        let work_order_expires_at = now + Duration::hours(1);

        let work_order_signer = Ed25519Signer::generate("asf-verifier-test");
        let mut work_order_fixture: RunmillSignedWorkOrderV1 = serde_json::from_slice(
            include_bytes!("../contracts/fixtures/work-order-envelope-v1.json"),
        )
        .expect("decode Work Order fixture");
        let work_order = &mut work_order_fixture.payload;
        work_order.work_order_id = work_order_id.to_string();
        work_order.tenant_id = tenant_id.to_string();
        work_order.work_item_id = work_item_id.to_string();
        work_order.attempt_id = attempt_id.to_string();
        work_order.idempotency_key = format!("{tenant_id}/{work_item_id}/{attempt_id}");
        work_order.source.system = "linear".into();
        work_order.source.external_id = "ASF-42".into();
        work_order.source.snapshot_digest.clone_from(&source_digest);
        work_order.repository.forge = "github".into();
        work_order.repository.repository = "acme/widgets".into();
        work_order.repository.base_ref = "refs/heads/main".into();
        work_order.repository.base_sha.clone_from(&base_sha);
        work_order.policy_digest.clone_from(&policy_digest);
        work_order
            .verification
            .policy_snapshot_digest
            .clone_from(&policy_digest);
        work_order.verification.required_local_check_ids = vec!["lint".into()];
        work_order.verification.required_remote_checks = vec!["ci/test".into()];
        work_order.identities.local_reviewer = "profile-local".parse().expect("local profile");
        work_order.identities.pr_reviewer = "profile-pr".parse().expect("PR profile");
        let signed_work_order = RunmillSignedWorkOrderV1::sign(
            work_order.clone(),
            &work_order_signer,
            work_order_issued_at,
            work_order_not_before,
            work_order_expires_at,
        )
        .expect("sign current Work Order");
        let work_order_payload_digest = signed_work_order
            .payload_digest()
            .expect("Work Order payload digest");
        let work_order_exact = signed_work_order
            .canonical_bytes()
            .expect("canonical Work Order");
        let work_order_envelope_digest = sha256_digest(&work_order_exact);

        let evidence_fixture = SignedRunmillEvidenceBundle::from_json(include_bytes!(
            "../contracts/fixtures/runmill-signed-evidence-v1.json"
        ))
        .expect("decode evidence fixture");
        let mut statement = serde_json::to_value(evidence_fixture.statement)
            .expect("encode evidence statement fixture");
        let artifact_snapshot = statement
            .pointer("/predicate/artifacts")
            .and_then(Value::as_array)
            .expect("artifact manifest")
            .clone();
        let mut replacement = BTreeMap::new();
        let mut bytes_by_id = BTreeMap::new();
        for artifact in artifact_snapshot {
            let artifact_id = artifact["artifact_id"]
                .as_str()
                .expect("artifact fixture ID")
                .to_owned();
            let old_digest = artifact["digest"]
                .as_str()
                .expect("artifact fixture digest")
                .to_owned();
            let bytes = match artifact_id.as_str() {
                "artifact-work-order" => work_order_exact.clone(),
                "artifact-policy" => policy_bytes.clone(),
                "artifact-diff" => diff_bytes.clone(),
                _ => format!("portable evidence artifact:{artifact_id}").into_bytes(),
            };
            replacement.insert(old_digest, sha256_digest(&bytes));
            bytes_by_id.insert(artifact_id, bytes);
        }
        replace_artifact_references(&mut statement, &replacement);
        for artifact in statement
            .pointer_mut("/predicate/artifacts")
            .and_then(Value::as_array_mut)
            .expect("mutable artifact manifest")
        {
            let artifact_id = artifact["artifact_id"]
                .as_str()
                .expect("artifact ID after replacement");
            let bytes = bytes_by_id.get(artifact_id).expect("artifact test bytes");
            let digest = sha256_digest(bytes);
            artifact["digest"] = json!(digest);
            artifact["size_bytes"] = json!(bytes.len() as u64);
            artifact["location_ref"] = json!(format!(
                "cas://sha256/{}",
                digest.strip_prefix("sha256:").expect("sha256 artifact")
            ));
        }
        statement["subject"][0]["name"] = json!("github:acme/widgets");
        statement["subject"][0]["digest"]["sha1"] = json!(&candidate_sha);
        statement["predicate"]["work_order"]["envelope_digest"] =
            json!(&work_order_envelope_digest);
        statement["predicate"]["work_order"]["payload_digest"] = json!(&work_order_payload_digest);
        statement["predicate"]["work_order"]["envelope_artifact_digest"] =
            json!(&work_order_envelope_digest);
        statement["predicate"]["work_order"]["signature"]["key_id"] =
            json!(signed_work_order.key_id.clone());
        statement["predicate"]["policy"]["effective_policy_digest"] = json!(&policy_digest);
        statement["predicate"]["policy"]["effective_policy_artifact_digest"] =
            json!(&policy_digest);
        statement["predicate"]["policy"]["required_local_checks"] = json!(["lint"]);
        statement["predicate"]["policy"]["required_ci_contexts"] = json!(["ci/test"]);
        statement["predicate"]["source"]["forge"] = json!("github");
        statement["predicate"]["source"]["repository"] = json!("acme/widgets");
        statement["predicate"]["source"]["base_ref"] = json!("refs/heads/main");
        statement["predicate"]["source"]["base_sha"] = json!(&base_sha);
        statement["predicate"]["source"]["candidate_sha"] = json!(&candidate_sha);
        statement["predicate"]["source"]["remote_head_sha"] = json!(&candidate_sha);
        statement["predicate"]["source"]["normalized_diff_digest"] = json!(&diff_digest);
        statement["predicate"]["source"]["normalized_diff_artifact_digest"] = json!(&diff_digest);
        statement["predicate"]["delivery"]["pull_request"]["repository"] = json!("acme/widgets");
        statement["predicate"]["delivery"]["pull_request"]["base_ref"] = json!("refs/heads/main");
        statement["predicate"]["delivery"]["pull_request"]["head_sha"] = json!(&candidate_sha);
        statement["predicate"]["delivery"]["pull_request"]["observed_at"] =
            json!((now - Duration::minutes(4)).to_rfc3339());
        statement["predicate"]["run"]["run_id"] = json!(external_run_id);
        statement["predicate"]["run"]["attempt_id"] = json!(attempt_id);
        statement["predicate"]["run"]["work_order_id"] = json!(work_order_id);
        statement["predicate"]["run"]["completed_at"] = json!(run_completed_at.to_rfc3339());

        let statement = serde_json::from_value(statement).expect("decode bound evidence statement");
        let worker_signer = Ed25519Signer::generate("runmill-worker-verifier-test");
        let mut evidence = SignedRunmillEvidenceBundle::sign(
            statement,
            RunmillEvidenceTimestamp::new(evidence_issued_at.to_rfc3339())
                .expect("evidence timestamp"),
            &worker_signer,
        )
        .expect("sign bound evidence");
        if forge_worker_signature {
            let first_signature_byte = "base64url:".len();
            let replacement = if evidence.signature.as_bytes()[first_signature_byte] == b'A' {
                "B"
            } else {
                "A"
            };
            evidence
                .signature
                .replace_range(first_signature_byte..=first_signature_byte, replacement);
        }
        let evidence_digest = evidence.bundle_digest.clone();
        let evidence_payload = serde_json::to_value(&evidence.statement).expect("evidence payload");
        let evidence_canonical = canonical_json(&evidence.statement).expect("canonical evidence");
        let evidence_exact = canonical_json(&evidence).expect("exact evidence envelope");
        let worker_public_key = encode_verifying_key(&worker_signer.verifying_key());

        let mut artifact_bytes = BTreeMap::new();
        for artifact in &evidence.statement.predicate.artifacts {
            let bytes = bytes_by_id
                .get(&artifact.artifact_id)
                .expect("manifest artifact bytes")
                .clone();
            assert_eq!(sha256_digest(&bytes), artifact.digest);
            artifact_bytes.insert(artifact.digest.clone(), bytes);
        }
        let artifacts = Arc::new(MemoryArtifactStore::with_artifacts(artifact_bytes));

        let job_payload = json!({
            "evidence_id": evidence_id,
            "run_id": run_id,
            "payload_digest": evidence_digest,
            "work_order_digest": work_order_payload_digest,
            "expectation_digest": expectation_digest,
        });
        let lease_owner = "reactor:evidence-verifier-test".to_owned();
        let lease_expires_at = now + Duration::minutes(20);
        let mut transaction = ledger.pool().begin().await.expect("begin verifier fixture");
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Verifier test')",
        )
        .bind(tenant_id)
        .bind(format!("verifier-{tenant_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert verifier tenant");
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
        .bind(&policy_bytes)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier policy");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, owner, name, repository_url, default_branch
            ) VALUES ($1, $2, 'acme', 'widgets', 'https://github.com/acme/widgets', 'main')
            ",
        )
        .bind(repository_id)
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier repository");
        sqlx::query(
            r"
            INSERT INTO source_snapshots (
                id, tenant_id, repository_id, source_system, external_id,
                source_revision, normalized_content, content_digest,
                connector_identity, source_updated_at
            ) VALUES (
                $1, $2, $3, 'LINEAR', 'ASF-42', 'linear-rev-1',
                '{}'::jsonb, $4, 'linear:test', $5
            )
            ",
        )
        .bind(snapshot_id)
        .bind(tenant_id)
        .bind(repository_id)
        .bind(&source_digest)
        .bind(now - Duration::minutes(20))
        .execute(&mut *transaction)
        .await
        .expect("insert verifier source snapshot");
        sqlx::query(
            r"
            INSERT INTO work_items (
                id, tenant_id, source_snapshot_id, source_system,
                source_external_id, repository_id, state, closure_target,
                risk_class, policy_digest, budget_limits,
                identity_requirements, owner_fallback, normalized_priority,
                current_attempt_id, discovered_at, accepted_at
            ) VALUES (
                $1, $2, $3, 'LINEAR', 'ASF-42', $4, 'VERIFYING_OUTCOME',
                'pull_request', 'low', $5, $6, $7, 'team:platform', 50,
                $8, $9 - interval '1 minute', $9
            )
            ",
        )
        .bind(work_item_id)
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(repository_id)
        .bind(&policy_digest)
        .bind(valid_budget_limits())
        .bind(valid_identity_requirements())
        .bind(attempt_id)
        .bind(now - Duration::minutes(15))
        .execute(&mut *transaction)
        .await
        .expect("insert verifier work item");
        sqlx::query(
            r"
            INSERT INTO attempts (
                id, tenant_id, work_item_id, ordinal, state, idempotency_key,
                base_ref, base_sha, source_snapshot_digest, policy_digest,
                work_order_digest, fence_token, created_at, terminal_at
            ) VALUES (
                $1, $2, $3, 1, 'SUCCEEDED', $4, 'refs/heads/main', $5,
                $6, $7, $8, 7, $9, $10
            )
            ",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(format!("{tenant_id}/{work_item_id}/{attempt_id}"))
        .bind(&base_sha)
        .bind(&source_digest)
        .bind(&policy_digest)
        .bind(&work_order_payload_digest)
        .bind(now - Duration::minutes(14))
        .bind(attempt_terminal_at)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier attempt");
        sqlx::query(
            r"
            INSERT INTO work_orders (
                id, tenant_id, work_item_id, attempt_id, schema_version,
                envelope_schema, algorithm, key_id, idempotency_key,
                payload_digest, canonical_payload, payload, signature,
                exact_signed_envelope, issued_at, not_before, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17
            )
            ",
        )
        .bind(work_order_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(&signed_work_order.payload.schema)
        .bind(&signed_work_order.schema)
        .bind(&signed_work_order.algorithm)
        .bind(&signed_work_order.key_id)
        .bind(&signed_work_order.payload.idempotency_key)
        .bind(&work_order_payload_digest)
        .bind(canonical_json(&signed_work_order.payload).expect("canonical Work Order payload"))
        .bind(serde_json::to_value(&signed_work_order.payload).expect("Work Order payload JSON"))
        .bind(&signed_work_order.signature)
        .bind(&work_order_exact)
        .bind(signed_work_order.issued_at)
        .bind(signed_work_order.not_before)
        .bind(signed_work_order.expires_at)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier Work Order");
        sqlx::query(
            r"
            INSERT INTO workers (
                id, tenant_id, name, endpoint, status, capabilities,
                generation, max_concurrency, signing_key_id, signing_public_key
            ) VALUES ($1, $2, $3, $4, 'READY', '{}'::jsonb, 1, 1, $5, $6)
            ",
        )
        .bind(worker_id)
        .bind(tenant_id)
        .bind(format!("worker-{}", worker_id.simple()))
        .bind(format!("https://worker.invalid/{worker_id}"))
        .bind(&evidence.key_id)
        .bind(&worker_public_key)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier worker");
        sqlx::query(
            r"
            INSERT INTO worker_sessions (
                id, tenant_id, worker_id, worker_generation, status,
                started_at, expires_at
            ) VALUES ($1, $2, $3, 1, 'ACTIVE', $4, $5)
            ",
        )
        .bind(worker_session_id)
        .bind(tenant_id)
        .bind(worker_id)
        .bind(worker_session_started_at)
        .bind(now + Duration::minutes(40))
        .execute(&mut *transaction)
        .await
        .expect("insert verifier worker session");
        sqlx::query(
            r"
            INSERT INTO runs (
                id, tenant_id, work_item_id, attempt_id, work_order_id,
                worker_id, worker_generation, worker_session_id,
                evidence_expectation_digest, external_run_id, authoritative,
                state, adopted_at, last_observed_at, terminal_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 1, $7, $8, $9, true,
                'SUCCEEDED', $10, $11, $11
            )
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(work_order_id)
        .bind(worker_id)
        .bind(worker_session_id)
        .bind(&expectation_digest)
        .bind(external_run_id)
        .bind(run_adopted_at)
        .bind(run_completed_at)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier run");
        sqlx::query(
            r"
            INSERT INTO evidence_bundles (
                id, tenant_id, work_item_id, attempt_id, run_id, worker_id,
                worker_generation, schema_version, envelope_schema, algorithm,
                key_id, payload_digest, work_order_digest, base_sha, candidate_sha,
                requested_target, target_satisfied, canonical_payload, payload,
                signature, exact_signed_envelope, produced_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 1, $7, $8, 'EdDSA', $9, $10,
                $11, $12, $13, 'pull_request', true, $14, $15, $16, $17, $18
            )
            ",
        )
        .bind(evidence_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(run_id)
        .bind(worker_id)
        .bind(&evidence.statement.predicate.schema)
        .bind(&evidence.schema)
        .bind(&evidence.key_id)
        .bind(&evidence_digest)
        .bind(&work_order_payload_digest)
        .bind(&base_sha)
        .bind(&candidate_sha)
        .bind(evidence_canonical)
        .bind(evidence_payload)
        .bind(&evidence.signature)
        .bind(evidence_exact)
        .bind(evidence_issued_at)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier evidence");
        for artifact in &evidence.statement.predicate.artifacts {
            let artifact_id = Uuid::now_v7();
            let retention = match artifact.retention_class {
                RunmillRetentionClass::Portable => "portable",
                RunmillRetentionClass::Protected => "protected",
                RunmillRetentionClass::Restricted => "restricted",
            };
            sqlx::query(
                r"
                INSERT INTO artifacts (
                    id, tenant_id, digest_algorithm, digest, media_type,
                    byte_size, object_key, encryption_class, retention_class,
                    access_policy, producer
                ) VALUES (
                    $1, $2, 'sha256', $3, $4, $5, $6, 'none', $7,
                    'tenant', 'runmill:test'
                )
                ",
            )
            .bind(artifact_id)
            .bind(tenant_id)
            .bind(&artifact.digest)
            .bind(&artifact.media_type)
            .bind(i64::try_from(artifact.size_bytes).expect("artifact size fits bigint"))
            .bind(&artifact.location_ref)
            .bind(retention)
            .execute(&mut *transaction)
            .await
            .expect("insert verifier artifact metadata");
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
            .execute(&mut *transaction)
            .await
            .expect("link verifier evidence artifact");
        }
        sqlx::query(
            r"
            INSERT INTO workflow_instances (
                id, tenant_id, work_item_id, workflow_type, state,
                reducer_version, event_cursor, fence_token
            ) VALUES (
                $1, $2, $3, 'WORK_ITEM_DELIVERY', 'ACTIVE',
                'asf.workflow/v1', 4, 2
            )
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .bind(work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier workflow");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
                job_type, activity_contract_id, status, payload, idempotency_key,
                attempt_count, max_attempts, fence_token, lease_owner, lease_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'VERIFY_EVIDENCE', $6, 'RUNNING', $7, $8,
                1, 25, 1, $9, $10
            )
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(persisted_activity_contract_id)
        .bind(&job_payload)
        .bind(format!("verify-evidence:{evidence_id}"))
        .bind(&lease_owner)
        .bind(lease_expires_at)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier job");
        sqlx::query(
            r"
            INSERT INTO accountability_anchors (
                tenant_id, work_item_id, anchor_type, reference_id,
                authority_or_effect_active, generation
            ) VALUES ($1, $2, 'WORKFLOW', $3, true, 1)
            ",
        )
        .bind(tenant_id)
        .bind(work_item_id)
        .bind(workflow_id)
        .execute(&mut *transaction)
        .await
        .expect("insert verifier accountability anchor");
        transaction.commit().await.expect("commit verifier fixture");

        Self {
            tenant_id,
            work_item_id,
            evidence_id,
            worker_id,
            job: ClaimedWorkflowJob {
                id: job_id,
                tenant_id,
                workflow_instance_id: Some(workflow_id),
                work_item_id: Some(work_item_id),
                attempt_id: Some(attempt_id),
                job_type: VERIFY_EVIDENCE.into(),
                activity_contract_id: VERIFY_EVIDENCE_ACTIVITY_CONTRACT_ID.into(),
                payload: job_payload,
                idempotency_key: format!("verify-evidence:{evidence_id}"),
                priority: 80,
                attempt_count: 1,
                max_attempts: 25,
                fence_token: 1,
                lease_owner,
                lease_expires_at,
                created_at: now,
            },
            work_order_key_id: signed_work_order.key_id.clone(),
            work_order_key: work_order_signer.verifying_key(),
            artifacts,
            artifact_digests: evidence
                .statement
                .predicate
                .artifacts
                .iter()
                .map(|artifact| artifact.digest.clone())
                .collect(),
        }
    }

    fn handler(
        &self,
        ledger: &PgLedger,
        forge: Arc<dyn ForgeGateway>,
    ) -> EvidenceVerificationHandler {
        EvidenceVerificationHandler::new(
            ledger.clone(),
            TenantId::from_uuid(self.tenant_id),
            forge,
            self.artifacts.clone(),
            self.work_order_key_id.clone(),
            self.work_order_key,
        )
        .expect("construct production evidence verifier")
    }
}

fn replace_artifact_references(value: &mut Value, replacements: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            if let Some(replacement) = replacements.get(text) {
                *text = replacement.clone();
                return;
            }
            for (old, new) in replacements {
                let old_location = format!(
                    "cas://sha256/{}",
                    old.strip_prefix("sha256:").expect("fixture sha256 digest")
                );
                if text == &old_location {
                    *text = format!(
                        "cas://sha256/{}",
                        new.strip_prefix("sha256:")
                            .expect("replacement sha256 digest")
                    );
                    return;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                replace_artifact_references(value, replacements);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_artifact_references(value, replacements);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn valid_budget_limits() -> Value {
    json!({
        "max_cost_microunits": 10_000_000,
        "max_input_tokens": 100_000,
        "max_output_tokens": 100_000,
        "max_implementer_invocations": 2,
        "max_reviewer_invocations": 2,
        "max_fix_iterations": 2,
        "max_wall_time_seconds": 7_200,
        "max_external_api_calls": 20
    })
}

fn valid_identity_requirements() -> Value {
    json!({
        "implementer": "codex:implementer",
        "local_reviewer": "claude:local-reviewer",
        "pr_reviewer": "claude:pr-reviewer"
    })
}

async fn setup(forge_worker_signature: bool) -> Option<(ScopedDatabase, Fixture)> {
    setup_with_evidence_age(forge_worker_signature, 2).await
}

async fn setup_with_wrong_persisted_contract(
    persisted_activity_contract_id: &str,
) -> Option<(ScopedDatabase, Fixture)> {
    let database_url = match std::env::var("ASF_TEST_DATABASE_URL") {
        Ok(database_url) => database_url,
        Err(error) if std::env::var_os("CI").is_some() => {
            panic!("CI must configure ASF_TEST_DATABASE_URL: {error}")
        }
        Err(_) => return None,
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert_with_evidence_age_and_persisted_contract(
        &database.ledger,
        false,
        2,
        persisted_activity_contract_id,
    )
    .await;
    Some((database, fixture))
}

async fn setup_with_evidence_age(
    forge_worker_signature: bool,
    evidence_age_minutes: i64,
) -> Option<(ScopedDatabase, Fixture)> {
    let database_url = match std::env::var("ASF_TEST_DATABASE_URL") {
        Ok(database_url) => database_url,
        Err(error) if std::env::var_os("CI").is_some() => {
            panic!("CI must configure ASF_TEST_DATABASE_URL: {error}")
        }
        Err(_) => return None,
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert_with_evidence_age(
        &database.ledger,
        forge_worker_signature,
        evidence_age_minutes,
    )
    .await;
    Some((database, fixture))
}

async fn assert_unverified(ledger: &PgLedger, fixture: &Fixture) {
    let state: (String, i64, String) = sqlx::query_as(
        r"
        SELECT work.state,
               (SELECT count(*) FROM evidence_verifications
                WHERE tenant_id = work.tenant_id AND evidence_id = $3),
               job.status
        FROM work_items AS work
        JOIN workflow_jobs AS job
          ON job.tenant_id = work.tenant_id AND job.id = $4
        WHERE work.tenant_id = $1 AND work.id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.evidence_id)
    .bind(fixture.job.id)
    .fetch_one(ledger.pool())
    .await
    .expect("load unverified state");
    assert_eq!(state, ("VERIFYING_OUTCOME".into(), 0, "RUNNING".into()));
}

#[tokio::test]
async fn production_verifier_atomically_proves_and_advances_exact_evidence() {
    let Some((database, fixture)) = setup(false).await else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::Valid));
    let handler = fixture.handler(&database.ledger, forge.clone());
    let outcome = handler
        .execute(&fixture.job, ActivityControls::new(false))
        .await
        .expect("verify exact production evidence");
    assert_eq!(outcome, ActivityOutcome::TransactionCommitted);
    assert_eq!(forge.calls(), 1);
    let state: (String, String, i64, i64, Uuid, i64, String) = sqlx::query_as(
        r"
        SELECT work.state, verification.status,
               verification.workflow_job_fence_token,
               count(close_job.id), verification.workflow_job_id,
               source_job.completion_fence_token,
               source_job.completed_by
        FROM work_items AS work
        JOIN evidence_verifications AS verification
          ON verification.tenant_id = work.tenant_id
         AND verification.evidence_id = $3
        JOIN workflow_jobs AS source_job
          ON source_job.tenant_id = verification.tenant_id
         AND source_job.id = verification.workflow_job_id
        LEFT JOIN workflow_jobs AS close_job
          ON close_job.tenant_id = work.tenant_id
         AND close_job.work_item_id = work.id
         AND close_job.job_type = 'CLOSE_SOURCE'
         AND close_job.status = 'PENDING'
        WHERE work.tenant_id = $1 AND work.id = $2
        GROUP BY work.state, verification.status,
                 verification.workflow_job_fence_token,
                 verification.workflow_job_id,
                 source_job.completion_fence_token, source_job.completed_by
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.work_item_id)
    .bind(fixture.evidence_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load atomic verification commit");
    assert_eq!(state.0, "CLOSING_SOURCE");
    assert_eq!(state.1, "VALID");
    assert_eq!(state.2, 1);
    assert_eq!(state.3, 1);
    assert_eq!(state.4, fixture.job.id);
    assert_eq!(state.5, 1);
    assert_eq!(state.6, fixture.job.lease_owner);

    let artifact_id: Uuid = sqlx::query_scalar(
        r"
        SELECT artifact_id
        FROM evidence_artifacts
        WHERE tenant_id = $1 AND evidence_id = $2
        ORDER BY artifact_id
        LIMIT 1
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.evidence_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load a verified artifact link");
    let artifact_mutation = sqlx::query(
        "UPDATE artifacts SET object_key = object_key || ':rewritten' \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(artifact_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("verified content-addressed artifact metadata is immutable");
    assert!(artifact_mutation.to_string().contains("append-only"));

    let link_deletion = sqlx::query(
        "DELETE FROM evidence_artifacts \
         WHERE tenant_id = $1 AND evidence_id = $2 AND artifact_id = $3",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.evidence_id)
    .bind(artifact_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("verified artifact links cannot be deleted");
    assert!(link_deletion.to_string().contains("append-only"));

    let unexpected_bytes = b"unexpected post-verification artifact";
    let unexpected_digest = sha256_digest(unexpected_bytes);
    let unexpected_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO artifacts (
            id, tenant_id, digest_algorithm, digest, media_type,
            byte_size, object_key, encryption_class, retention_class,
            access_policy, producer
        ) VALUES (
            $1, $2, 'sha256', $3, 'application/octet-stream', $4, $5,
            'none', 'portable', 'tenant', 'asf:test'
        )
        ",
    )
    .bind(unexpected_id)
    .bind(fixture.tenant_id)
    .bind(&unexpected_digest)
    .bind(i64::try_from(unexpected_bytes.len()).expect("test artifact size fits bigint"))
    .bind(format!(
        "cas://sha256/{}",
        unexpected_digest
            .strip_prefix("sha256:")
            .expect("sha256 test artifact")
    ))
    .execute(database.ledger.pool())
    .await
    .expect("insert unlinked supplemental artifact metadata");
    let link_insertion = sqlx::query(
        r"
        INSERT INTO evidence_artifacts (
            tenant_id, evidence_id, artifact_id, relationship
        ) VALUES ($1, $2, $3, 'OTHER')
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.evidence_id)
    .bind(unexpected_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("a VALID signed manifest cannot gain an artifact link");
    assert_eq!(
        link_insertion
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("valid_evidence_artifact_links_frozen")
    );

    assert!(
        sqlx::query("TRUNCATE evidence_artifacts")
            .execute(database.ledger.pool())
            .await
            .is_err(),
        "append-only evidence links cannot be bypassed with TRUNCATE"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn forged_worker_signature_is_rejected_before_forge_observation() {
    let Some((database, fixture)) = setup(true).await else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::Valid));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err()
    );
    assert_eq!(forge.calls(), 0);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}

#[tokio::test]
async fn wrong_contract_claimed_job_is_rejected_before_forge_observation() {
    let Some((database, fixture)) = setup(false).await else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::Valid));
    let handler = fixture.handler(&database.ledger, forge.clone());
    let mut wrong_contract = fixture.job.clone();
    wrong_contract.activity_contract_id = "asf.activity/verify-evidence/v2".into();
    let error = handler
        .execute(&wrong_contract, ActivityControls::new(false))
        .await
        .expect_err("a wrong-contract claimed job must fail closed");
    assert!(matches!(error, Error::Validation(_)));
    assert_eq!(forge.calls(), 0);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}

#[tokio::test]
async fn forged_wrong_contract_owning_row_cannot_satisfy_verification_authority_sql() {
    // Persist the owning row with a wrong contract from its initial INSERT:
    // migration 0023's immutability trigger rejects any later UPDATE of
    // activity_contract_id, so the mismatch must be born with the row. The
    // in-memory claim (and its job_type) stays canonical, so the SQL
    // predicate, not the caller-supplied struct, is what decides authority.
    let Some((database, fixture)) =
        setup_with_wrong_persisted_contract("asf.activity/verify-evidence/v2").await
    else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::Valid));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err(),
        "a persisted row with a non-canonical activity contract must never satisfy \
         evidence-verification authority, regardless of the caller's claimed contract"
    );
    assert_eq!(forge.calls(), 0);
    database.cleanup().await;
}

#[tokio::test]
async fn wrong_contract_owning_row_rejects_raw_completion_update_via_db_trigger() {
    // Unlike `forged_wrong_contract_owning_row_cannot_satisfy_verification_authority_sql`
    // above, which drives `EvidenceVerificationHandler::execute` to show the SQL authority
    // predicate (not the caller-supplied claim) decides eligibility, this test never invokes
    // the handler or the forge. It issues a raw UPDATE that is otherwise an exact
    // RUNNING->COMPLETED claim transition, so migration 0024's row-level completion trigger
    // alone must reject the wrong-contract row, before any receipt or deferred proof is ever
    // relevant.
    let Some((database, fixture)) =
        setup_with_wrong_persisted_contract("asf.activity/verify-evidence/v2").await
    else {
        return;
    };

    let forged_completion = sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'COMPLETED',
            result = $3,
            completed_by = $4,
            completion_fence_token = $5,
            completed_at = clock_timestamp(),
            lease_owner = NULL,
            lease_expires_at = NULL
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job.id)
    .bind(json!({"schema": "asf.activity-result/verify-evidence.v1", "verified": true}))
    .bind(&fixture.job.lease_owner)
    .bind(fixture.job.fence_token)
    .execute(database.ledger.pool())
    .await
    .expect_err(
        "a row born with a non-canonical activity contract must never satisfy the exact \
         VERIFY_EVIDENCE completion trigger, even for an otherwise-exact claim transition",
    );
    assert_eq!(
        forged_completion
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    assert_eq!(
        forged_completion
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("workflow_jobs_exact_verify_evidence_completion")
    );

    let row: (
        String,
        Option<String>,
        Option<i64>,
        Option<chrono::DateTime<Utc>>,
        String,
    ) = sqlx::query_as(
        r"
            SELECT status, completed_by, completion_fence_token, completed_at,
                   activity_contract_id
            FROM workflow_jobs
            WHERE tenant_id = $1 AND id = $2
            ",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.job.id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load job row after rejected raw completion update");
    assert_eq!(row.0, "RUNNING");
    assert_eq!(row.1, None);
    assert_eq!(row.2, None);
    assert_eq!(row.3, None);
    assert_eq!(row.4, "asf.activity/verify-evidence/v2");

    database.cleanup().await;
}

#[tokio::test]
async fn artifact_byte_mismatch_is_rejected_before_forge_observation() {
    let Some((database, fixture)) = setup(false).await else {
        return;
    };
    fixture
        .artifacts
        .corrupt(&fixture.artifact_digests[0])
        .await;
    let forge = Arc::new(FakeForge::new(ForgeMode::Valid));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err()
    );
    assert_eq!(forge.calls(), 0);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}

#[tokio::test]
async fn stale_ci_observation_cannot_create_a_valid_receipt() {
    let Some((database, fixture)) = setup(false).await else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::StaleCi));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err()
    );
    assert_eq!(forge.calls(), 1);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}

#[tokio::test]
async fn replayed_old_forge_observation_cannot_create_a_valid_receipt() {
    let Some((database, fixture)) = setup_with_evidence_age(false, 7).await else {
        return;
    };
    let forge = Arc::new(FakeForge::new(ForgeMode::StaleObservation));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err()
    );
    assert_eq!(forge.calls(), 1);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}

#[tokio::test]
async fn authority_change_during_forge_observation_blocks_final_commit() {
    let Some((database, fixture)) = setup(false).await else {
        return;
    };
    let forge = Arc::new(FakeForge::with_quarantine(
        database.ledger.pool().clone(),
        fixture.tenant_id,
        fixture.worker_id,
    ));
    let handler = fixture.handler(&database.ledger, forge.clone());
    assert!(
        handler
            .execute(&fixture.job, ActivityControls::new(false))
            .await
            .is_err()
    );
    assert_eq!(forge.calls(), 1);
    assert_unverified(&database.ledger, &fixture).await;
    database.cleanup().await;
}
