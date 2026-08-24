//! Live `PostgreSQL` coverage for terminal evidence provenance.
//!
//! Migration 0035 is the contract boundary for a retained terminal evidence
//! bundle: it reparses the signed envelope, re-derives every digest from the
//! bytes it is a digest of, binds the retained `asf.get_evidence` wire to the
//! row, and requires both control snapshots and the observation stream to
//! independently prove the same terminal observation. None of that can be
//! exercised in-process, so it is exercised here against a real database.
//!
//! The production retention activity is exercised the same way: through a real
//! Runmill control socket, a real claimed workflow job, and the real ledger
//! transaction it commits.

use std::{
    fs::{self, File, Permissions},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    time::Duration as StdDuration,
};

use chrono::{DateTime, Duration, SecondsFormat, SubsecRound as _, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgDatabaseError};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
};
use url::Url;
use uuid::Uuid;

use asf::{
    adapters::{RUNMILL_CONTROL_PROTOCOL_VERSION, RunmillControlClient},
    crypto::{Ed25519Signer, canonical_json, encode_verifying_key, sha256_digest},
    domain::{TenantId, WorkerId},
    ledger::{
        ClaimedWorkflowJob, IncomingRunmillControlEvent, IncomingRunmillControlSnapshot, PgLedger,
        RunmillAdmissionProvenance, RunmillControlOperation, RunmillObservationFence,
        produce_due_runmill_terminal_evidence_jobs, record_runmill_control_observation,
    },
    runtime::{
        ActivityControls, ActivityOutcome, JobHandler, OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID,
        RETAIN_RUNMILL_TERMINAL_EVIDENCE, RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID,
        RunmillTerminalEvidenceHandler,
    },
};

const SIGNED_TERMINAL_EVIDENCE_SCHEMA: &str = "asf.signed-terminal-evidence/v1";
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
const TERMINAL_EVIDENCE_PREDICATE_TYPE: &str =
    "https://runmill.dev/attestations/asf-terminal-evidence/v1";
const TERMINAL_EVIDENCE_PREDICATE_SCHEMA: &str = "asf.terminal-evidence/v1";
const EVIDENCE_VIEW_SCHEMA: &str = "asf.evidence-view/v1";
const TERMINAL_PHASE: &str = "COMPLETED";
/// The last external sequence the event page observed. The terminal event is
/// the one appended after it.
const OBSERVED_SEQUENCE: i64 = 1;
const TERMINAL_EVENT_SEQ: i64 = OBSERVED_SEQUENCE + 1;
const ELAPSED_MS: i64 = 60_000;
const INSERT_BUNDLE_SQL: &str = r"
INSERT INTO runmill_terminal_evidence_bundles (
    id, tenant_id, run_id, work_item_id, attempt_id, work_order_id,
    work_order_digest, worker_session_id, worker_id, worker_generation,
    external_run_id, get_run_snapshot_id, event_page_snapshot_id,
    terminal_evidence_response_wire_digest, exact_terminal_evidence_response_wire,
    terminal_bundle_digest, terminal_phase, terminal_event_seq, base_sha,
    candidate_sha, canonical_statement, statement_digest, predicate,
    envelope_schema, signature_algorithm, signing_key_id, terminal_signature,
    exact_signed_envelope, issued_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29
)
";

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Self {
        let admin = PgPool::connect(database_url)
            .await
            .expect("connect terminal evidence test administrator");
        let schema = format!("asf_terminal_evidence_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated terminal evidence schema");
        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated terminal evidence ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated terminal evidence schema");
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
            .expect("drop isolated terminal evidence schema");
        self.admin.close().await;
    }
}

/// One run that genuinely reached `TERMINAL_READY` through two retained
/// control snapshots and one immutable observation result.
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
    observation_job_id: Uuid,
    observation_id: Uuid,
    get_run_snapshot_id: Uuid,
    event_page_snapshot_id: Uuid,
    lease_owner: String,
    occurred_at: DateTime<Utc>,
    /// The signed bundle's issuance instant. It must fall inside the admitting
    /// worker session's own signing window, so it is derived from the fixture's
    /// clock rather than pinned to a literal.
    issued_at: DateTime<Utc>,
    signer: Ed25519Signer,
}

impl Fixture {
    async fn insert(ledger: &PgLedger) -> Self {
        let signer = Ed25519Signer::generate("asf-terminal-key-1");
        let mut fixture = Self {
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
            observation_job_id: Uuid::now_v7(),
            observation_id: Uuid::now_v7(),
            get_run_snapshot_id: Uuid::nil(),
            event_page_snapshot_id: Uuid::nil(),
            lease_owner: "reactor:terminal-evidence-test".into(),
            occurred_at: Utc::now(),
            issued_at: Utc::now().trunc_subsecs(0),
            signer,
        };
        fixture.insert_authority(ledger).await;
        fixture.observe_terminal_run(ledger).await;
        fixture
    }

    /// Everything migration 0035's foreign keys require, exactly as the
    /// observation path itself creates it.
    async fn insert_authority(&self, ledger: &PgLedger) {
        let repository_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();
        let mut transaction = ledger
            .pool()
            .begin()
            .await
            .expect("begin terminal evidence fixture");

        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
            .bind(self.tenant_id)
            .bind(format!("terminal-evidence-{}", self.tenant_id))
            .bind("Terminal evidence test")
            .execute(&mut *transaction)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, scope, schema_version, digest, canonical_bytes, policy, created_by) VALUES ($1, $2, 'TENANT', 'v1', $3, $4, '{}'::jsonb, 'test')",
        )
        .bind(policy_id)
        .bind(self.tenant_id)
        .bind(&self.policy_digest)
        .bind(b"{}".as_slice())
        .execute(&mut *transaction)
        .await
        .expect("insert policy");
        sqlx::query(
            "INSERT INTO repositories (id, tenant_id, owner, name, repository_url, default_branch) VALUES ($1, $2, 'acme', $3, $4, 'main')",
        )
        .bind(repository_id)
        .bind(self.tenant_id)
        .bind(format!("repo-{}", repository_id.simple()))
        .bind(format!("https://example.invalid/{repository_id}"))
        .execute(&mut *transaction)
        .await
        .expect("insert repository");
        sqlx::query(
            "INSERT INTO source_snapshots (id, tenant_id, repository_id, source_system, external_id, source_revision, normalized_content, content_digest, connector_identity, source_updated_at) VALUES ($1, $2, $3, 'API', $4, '1', '{}'::jsonb, $5, 'test', $6)",
        )
        .bind(snapshot_id)
        .bind(self.tenant_id)
        .bind(repository_id)
        .bind(format!("item-{}", self.work_item_id))
        .bind(digest('c'))
        .bind(self.occurred_at)
        .execute(&mut *transaction)
        .await
        .expect("insert source snapshot");
        sqlx::query(
            "INSERT INTO work_items (id, tenant_id, source_snapshot_id, source_system, source_external_id, repository_id, state, closure_target, risk_class, policy_digest, budget_limits, identity_requirements, owner_fallback, normalized_priority, discovered_at, accepted_at) VALUES ($1, $2, $3, 'API', $4, $5, 'RUNNING', 'pull_request', 'low', $6, $7, $8, 'team:platform', 50, $9, $9)",
        )
        .bind(self.work_item_id)
        .bind(self.tenant_id)
        .bind(snapshot_id)
        .bind(format!("item-{}", self.work_item_id))
        .bind(repository_id)
        .bind(&self.policy_digest)
        .bind(budget_limits())
        .bind(identity_requirements())
        .bind(self.occurred_at)
        .execute(&mut *transaction)
        .await
        .expect("insert accepted work item");
        sqlx::query(
            "INSERT INTO workflow_instances (id, tenant_id, work_item_id, workflow_type, state, reducer_version) VALUES ($1, $2, $3, 'RUNMILL_TERMINAL_EVIDENCE_TEST', 'ACTIVE', 'v1')",
        )
        .bind(self.workflow_instance_id)
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .execute(&mut *transaction)
        .await
        .expect("insert workflow");
        sqlx::query(
            "INSERT INTO attempts (id, tenant_id, work_item_id, ordinal, state, idempotency_key, base_ref, base_sha, source_snapshot_digest, policy_digest) VALUES ($1, $2, $3, 1, 'AUTHORIZED', $4, 'main', $5, $6, $7)",
        )
        .bind(self.attempt_id)
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(format!("attempt-{}", self.attempt_id))
        .bind(commit('b'))
        .bind(digest('d'))
        .bind(&self.policy_digest)
        .execute(&mut *transaction)
        .await
        .expect("insert attempt");
        sqlx::query(
            "UPDATE work_items SET current_attempt_id = $3, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .execute(&mut *transaction)
        .await
        .expect("bind work item to its current attempt");
        sqlx::query(
            "INSERT INTO work_orders (id, tenant_id, work_item_id, attempt_id, schema_version, envelope_schema, algorithm, key_id, idempotency_key, payload_digest, canonical_payload, payload, signature, exact_signed_envelope, issued_at, not_before, expires_at) VALUES ($1, $2, $3, $4, 'v1', 'envelope-v1', 'EdDSA', 'key-1', $5, $6, $7, '{}'::jsonb, 'signature', $8, $9, $9, $10)",
        )
        .bind(self.work_order_id)
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .bind(format!("{}/{}/{}", self.tenant_id, self.work_item_id, self.attempt_id))
        .bind(&self.work_order_digest)
        .bind(b"{}".as_slice())
        .bind(b"exact signed envelope".as_slice())
        .bind(self.occurred_at)
        .bind(self.occurred_at + Duration::hours(1))
        .execute(&mut *transaction)
        .await
        .expect("insert Work Order");
        sqlx::query("UPDATE attempts SET work_order_digest = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(self.tenant_id)
            .bind(self.attempt_id)
            .bind(&self.work_order_digest)
            .execute(&mut *transaction)
            .await
            .expect("bind Work Order to attempt");
        // The worker's signing authority is the authority every session
        // inherits, and the key the retained envelope must verify under.
        sqlx::query(
            "INSERT INTO workers (id, tenant_id, name, endpoint, generation, signing_key_id, signing_public_key) VALUES ($1, $2, $3, $4, 3, $5, $6)",
        )
        .bind(self.worker_id)
        .bind(self.tenant_id)
        .bind(format!("worker-{}", self.worker_id))
        .bind(format!("local://{}", self.worker_id))
        .bind(self.signer.key_id())
        .bind(encode_verifying_key(&self.signer.verifying_key()))
        .execute(&mut *transaction)
        .await
        .expect("insert worker");
        sqlx::query(
            "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, started_at, expires_at) VALUES ($1, $2, $3, 3, $4, $5)",
        )
        .bind(self.worker_session_id)
        .bind(self.tenant_id)
        .bind(self.worker_id)
        .bind(self.occurred_at - Duration::hours(1))
        .bind(self.occurred_at + Duration::hours(6))
        .execute(&mut *transaction)
        .await
        .expect("insert run-admission worker session");
        sqlx::query(
            "INSERT INTO runs (id, tenant_id, work_item_id, attempt_id, work_order_id, worker_id, worker_generation, worker_session_id, evidence_expectation_digest, external_run_id, state) VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8, $9, 'ADOPTED')",
        )
        .bind(self.run_id)
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .bind(self.work_order_id)
        .bind(self.worker_id)
        .bind(self.worker_session_id)
        .bind(digest('e'))
        .bind(&self.external_run_id)
        .execute(&mut *transaction)
        .await
        .expect("insert authoritative run");
        // One live session per worker: the immutable session that admitted the
        // run is closed before the separately-live observer session opens, and
        // it keeps signing authority for everything issued inside its window.
        sqlx::query(
            "UPDATE worker_sessions SET status = 'CLOSED', closed_at = clock_timestamp(), close_reason = 'observer session rotation' WHERE tenant_id = $1 AND id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.worker_session_id)
        .execute(&mut *transaction)
        .await
        .expect("close the run-admission session before observer rotation");
        sqlx::query(
            "INSERT INTO worker_sessions (id, tenant_id, worker_id, worker_generation, started_at, expires_at) VALUES ($1, $2, $3, 3, $4, $5)",
        )
        .bind(self.observer_session_id)
        .bind(self.tenant_id)
        .bind(self.worker_id)
        .bind(self.occurred_at - Duration::hours(1))
        .bind(self.occurred_at + Duration::hours(6))
        .execute(&mut *transaction)
        .await
        .expect("insert live observer control session");
        sqlx::query(
            "INSERT INTO accountability_anchors (tenant_id, work_item_id, anchor_type, reference_id, authority_or_effect_active) VALUES ($1, $2, 'RUN', $3, true)",
        )
        .bind(self.tenant_id)
        .bind(self.work_item_id)
        .bind(self.run_id)
        .execute(&mut *transaction)
        .await
        .expect("anchor accepted work to its authoritative run");
        sqlx::query(
            "INSERT INTO runmill_run_observation_streams (tenant_id, run_id, workflow_instance_id, work_item_id, attempt_id, work_order_id, work_order_digest, worker_id, worker_generation, run_admission_worker_session_id, external_run_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 3, $9, $10)",
        )
        .bind(self.tenant_id)
        .bind(self.run_id)
        .bind(self.workflow_instance_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .bind(self.work_order_id)
        .bind(&self.work_order_digest)
        .bind(self.worker_id)
        .bind(self.worker_session_id)
        .bind(&self.external_run_id)
        .execute(&mut *transaction)
        .await
        .expect("insert idle durable observation stream");
        // The checkpoint guard requires an idle stream and a still-pending job,
        // so the observer claim is taken only after the checkpoint exists.
        sqlx::query(
            "INSERT INTO workflow_jobs (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type, activity_contract_id, status, payload, idempotency_key, max_attempts) VALUES ($1, $2, $3, $4, $5, 'OBSERVE_RUNMILL_RUN', $6, 'PENDING', $7, $8, 3)",
        )
        .bind(self.observation_job_id)
        .bind(self.tenant_id)
        .bind(self.workflow_instance_id)
        .bind(self.work_item_id)
        .bind(self.attempt_id)
        .bind(OBSERVE_RUNMILL_RUN_ACTIVITY_CONTRACT_ID)
        .bind(self.observation_payload())
        .bind(format!("observe-{}", self.observation_job_id))
        .execute(&mut *transaction)
        .await
        .expect("insert pending observation job");
        sqlx::query(
            "INSERT INTO runmill_run_observation_checkpoints (id, tenant_id, run_id, workflow_job_id, after_sequence, observation_epoch, observer_session_id, worker_id, worker_generation) VALUES ($1, $2, $3, $4, 0, 1, $5, $6, 3)",
        )
        .bind(self.observation_id)
        .bind(self.tenant_id)
        .bind(self.run_id)
        .bind(self.observation_job_id)
        .bind(self.observer_session_id)
        .bind(self.worker_id)
        .execute(&mut *transaction)
        .await
        .expect("insert immutable observation checkpoint");
        sqlx::query(
            "UPDATE runmill_run_observation_streams SET observation_epoch = 1, active_job_id = $3, active_observation_id = $4, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND run_id = $2 AND aggregate_version = 1",
        )
        .bind(self.tenant_id)
        .bind(self.run_id)
        .bind(self.observation_job_id)
        .bind(self.observation_id)
        .execute(&mut *transaction)
        .await
        .expect("activate the observation checkpoint");
        sqlx::query(
            "UPDATE workflow_jobs SET status = 'RUNNING', attempt_count = 1, fence_token = 1, lease_owner = $3, lease_expires_at = $4, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.observation_job_id)
        .bind(&self.lease_owner)
        .bind(self.occurred_at + Duration::minutes(5))
        .execute(&mut *transaction)
        .await
        .expect("claim the active observation job");
        transaction
            .commit()
            .await
            .expect("commit terminal evidence fixture");
    }

    /// Retain the two exact control snapshots, record the immutable
    /// `TERMINAL_READY` result, and release the stream through it — the same
    /// transition the observation activity performs.
    async fn observe_terminal_run(&mut self, ledger: &PgLedger) {
        let get_run = self.get_run_snapshot();
        let event_page = self.list_run_events_snapshot();
        let fence = self.observation_fence();

        let mut transaction = ledger.pool().begin().await.expect("begin observation");
        let get_run_outcome =
            record_runmill_control_observation(&mut transaction, &fence, &get_run)
                .await
                .expect("retain the exact GET_RUN snapshot");
        let event_page_outcome =
            record_runmill_control_observation(&mut transaction, &fence, &event_page)
                .await
                .expect("retain the exact LIST_RUN_EVENTS snapshot");
        self.get_run_snapshot_id = get_run_outcome.snapshot_id;
        self.event_page_snapshot_id = event_page_outcome.snapshot_id;

        sqlx::query(
            "INSERT INTO runmill_run_observation_results (id, tenant_id, run_id, observation_id, after_sequence, next_sequence, has_more, gap, compacted_through, get_run_snapshot_id, event_page_snapshot_id, disposition) VALUES ($1, $2, $3, $4, 0, $5, false, false, NULL, $6, $7, 'TERMINAL_READY')",
        )
        .bind(Uuid::now_v7())
        .bind(self.tenant_id)
        .bind(self.run_id)
        .bind(self.observation_id)
        .bind(OBSERVED_SEQUENCE)
        .bind(self.get_run_snapshot_id)
        .bind(self.event_page_snapshot_id)
        .execute(&mut *transaction)
        .await
        .expect("record the immutable terminal-ready observation result");
        sqlx::query(
            "UPDATE runmill_run_observation_streams SET next_after_sequence = $3, active_job_id = NULL, active_observation_id = NULL, state = 'TERMINAL_READY', last_snapshot_id = $4, aggregate_version = aggregate_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND run_id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.run_id)
        .bind(OBSERVED_SEQUENCE)
        .bind(self.event_page_snapshot_id)
        .execute(&mut *transaction)
        .await
        .expect("release the stream into TERMINAL_READY through its result");
        sqlx::query(
            "UPDATE workflow_jobs SET status = 'COMPLETED', result = '{}'::jsonb, completed_by = $3, completion_fence_token = 1, completed_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL WHERE tenant_id = $1 AND id = $2",
        )
        .bind(self.tenant_id)
        .bind(self.observation_job_id)
        .bind(&self.lease_owner)
        .execute(&mut *transaction)
        .await
        .expect("complete the observation job");
        transaction.commit().await.expect("commit observation");
    }

    fn observation_payload(&self) -> Value {
        json!({
            "schema": "asf.runmill-observation/v2",
            "observation_id": self.observation_id.to_string(),
            "run_id": self.run_id.to_string(),
            "work_order_id": self.work_order_id.to_string(),
            "work_order_digest": self.work_order_digest,
            "worker_id": self.worker_id.to_string(),
            "worker_session_id": self.worker_session_id.to_string(),
            "worker_generation": 3,
            "external_run_id": self.external_run_id,
            "after_sequence": 0,
            "observation_epoch": 1,
            "observer_session_id": self.observer_session_id.to_string(),
        })
    }

    fn observation_fence(&self) -> RunmillObservationFence {
        RunmillObservationFence {
            tenant_id: self.tenant_id,
            run_id: self.run_id,
            work_item_id: self.work_item_id,
            attempt_id: self.attempt_id,
            work_order_id: self.work_order_id,
            work_order_digest: self.work_order_digest.clone(),
            workflow_job_id: self.observation_job_id,
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

    fn run_object(&self) -> Value {
        json!({
            "runId": self.external_run_id,
            "issueId": format!("item-{}", self.work_item_id),
            "repo": "acme/repository",
            "provider": "github",
            "state": TERMINAL_PHASE,
            "workOrderId": self.work_order_id.to_string(),
            "attemptId": self.attempt_id.to_string(),
            "generation": 3,
            "stateVersion": OBSERVED_SEQUENCE,
            "attempt": 1,
            "baseCommit": commit('b'),
            "candidateSha": commit('c'),
            "branch": null,
            "mode": "asf-worker",
            "ownerId": null,
            "heartbeatAt": self.occurred_at.to_rfc3339(),
        })
    }

    fn get_run_snapshot(&self) -> IncomingRunmillControlSnapshot {
        let raw_snapshot = json!({
            "run": self.run_object(),
            "latestSequence": OBSERVED_SEQUENCE,
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
            external_state_version: u64::try_from(OBSERVED_SEQUENCE).unwrap(),
            external_latest_sequence: u64::try_from(OBSERVED_SEQUENCE).unwrap(),
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

    fn list_run_events_snapshot(&self) -> IncomingRunmillControlSnapshot {
        let event = self.event();
        let retained_event = event.raw_event.clone();
        let raw_snapshot = json!({
            "snapshot": {
                "run": self.run_object(),
                "latestSequence": OBSERVED_SEQUENCE,
            },
            "events": [retained_event],
            "nextCursor": OBSERVED_SEQUENCE,
            "hasMore": false,
            "gap": false,
            "compactedThrough": null,
        });
        IncomingRunmillControlSnapshot {
            id: Uuid::now_v7(),
            control_sequence: 2,
            operation: RunmillControlOperation::ListRunEvents,
            external_generation: 3,
            external_state_version: u64::try_from(OBSERVED_SEQUENCE).unwrap(),
            external_latest_sequence: u64::try_from(OBSERVED_SEQUENCE).unwrap(),
            observed_at: self.occurred_at + Duration::seconds(1),
            admission: None,
            raw_response_bytes: successful_response_bytes(&raw_snapshot),
            raw_snapshot,
            events: vec![event],
        }
    }

    fn event(&self) -> IncomingRunmillControlEvent {
        let occurred_at = self.occurred_at + Duration::seconds(OBSERVED_SEQUENCE);
        let raw_event = json!({
            "schema": "asf.run-event/v1",
            "event_id": format!("event-{}", OBSERVED_SEQUENCE),
            "run_id": self.external_run_id,
            "work_order_id": self.work_order_id.to_string(),
            "attempt_id": self.attempt_id.to_string(),
            "seq": OBSERVED_SEQUENCE,
            "type": "run.completed",
            "phase": TERMINAL_PHASE,
            "occurred_at": occurred_at.to_rfc3339(),
            "policy_digest": self.policy_digest,
            "payload": {
                "candidate_sha": commit('c'),
                "closure_target": "pr",
                "satisfied": true,
                "evidence_bundle_digest": digest('f'),
            },
        });
        IncomingRunmillControlEvent {
            id: Uuid::now_v7(),
            external_event_id: format!("event-{OBSERVED_SEQUENCE}"),
            sequence: u64::try_from(OBSERVED_SEQUENCE).unwrap(),
            event_type: "run.completed".into(),
            occurred_at,
            raw_event,
        }
    }

    fn issued_at_text(&self) -> String {
        self.issued_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    fn admitted_at_text(&self) -> String {
        (self.issued_at - Duration::milliseconds(ELAPSED_MS))
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    /// The exact in-toto statement a conformant terminal bundle signs.
    fn statement(&self) -> Value {
        json!({
            "_type": IN_TOTO_STATEMENT_V1,
            "subject": [{
                "name": format!("asf-run:{}", self.external_run_id),
                "digest": {"sha1": commit('c')},
            }],
            "predicateType": TERMINAL_EVIDENCE_PREDICATE_TYPE,
            "predicate": {
                "schema": TERMINAL_EVIDENCE_PREDICATE_SCHEMA,
                "run": {
                    "run_id": self.external_run_id,
                    "work_order_id": self.work_order_id.to_string(),
                    "attempt_id": self.attempt_id.to_string(),
                    "terminal_phase": TERMINAL_PHASE,
                    "terminal_event_seq": TERMINAL_EVENT_SEQ,
                },
                "admission": {
                    "work_order_envelope_digest": self.envelope_digest,
                    "work_order_payload_digest": self.work_order_digest,
                    "effective_policy_digest": self.policy_digest,
                    "work_order_envelope": {"schema": "asf.work-order/v1"},
                    "signature_verification": {
                        "verified": true,
                        "key_id": "key-1",
                        "algorithm": "EdDSA",
                    },
                    "effective_policy": {"digest": self.policy_digest},
                },
                "source": {
                    "repository": "acme/repository",
                    "base_sha": commit('b'),
                    "candidate_sha": commit('c'),
                    "subject_kind": "candidate",
                    "subject_sha": commit('c'),
                },
                "stop": {
                    "code": "SUCCESS",
                    "summary": "run reached its terminal phase",
                    "interrupted_phase": "delivery",
                    "retry_disposition": "safe",
                    "required_actor": "asf",
                    "required_action": "none",
                    "evidence_refs": [],
                },
                "cancellation": null,
                "budget": {
                    "wall_seconds_limit": 3600,
                    "max_cost_usd": 10.5,
                    "max_agent_invocations": 100,
                    "max_fix_iterations": 5,
                    "observed_fix_iterations": 2,
                    "evidence_refs": [],
                    "provider_usage": {"invocations": []},
                },
                "side_effects": {"effects": []},
                "timing": {
                    "admitted_at": self.admitted_at_text(),
                    "terminal_evidence_at": self.issued_at_text(),
                    "elapsed_ms": ELAPSED_MS,
                },
                "cleanup": {
                    "intent_id": "intent-1",
                    "intent_digest": digest('5'),
                    "observation_digest": digest('6'),
                    "identity_leases": "released",
                    "repository_lease": "released",
                    "workspace": "removed",
                    "unresolved_effects": 0,
                },
                "evidence": {
                    "preceding_event_count": TERMINAL_EVENT_SEQ - 1,
                    "preceding_event_chain_digest": digest('7'),
                    "observations": [],
                    "events": [],
                    "delivery_bundle_digest": digest('8'),
                },
            },
        })
    }

    /// One genuinely signed envelope: the digest is the digest of the canonical
    /// statement, and the signature verifies under the worker's own key.
    fn envelope(&self, statement: &Value) -> Value {
        let canonical = canonical_json(statement).expect("canonicalize statement");
        let bundle_digest = sha256_digest(&canonical);
        let unsigned = json!({
            "schema": SIGNED_TERMINAL_EVIDENCE_SCHEMA,
            "key_id": self.signer.key_id(),
            "algorithm": "EdDSA",
            "issued_at": self.issued_at_text(),
            "bundle_digest": bundle_digest,
            "statement": statement,
        });
        let signature = format!(
            "base64url:{}",
            self.signer
                .sign(&canonical_json(&unsigned).expect("canonicalize unsigned envelope"))
        );
        json!({
            "schema": SIGNED_TERMINAL_EVIDENCE_SCHEMA,
            "key_id": self.signer.key_id(),
            "algorithm": "EdDSA",
            "issued_at": self.issued_at_text(),
            "bundle_digest": bundle_digest,
            "statement": statement,
            "signature": signature,
        })
    }

    fn evidence_view(&self, envelope: &Value) -> Value {
        json!({
            "schema": EVIDENCE_VIEW_SCHEMA,
            "runId": self.external_run_id,
            "workOrderId": self.work_order_id.to_string(),
            "attemptId": self.attempt_id.to_string(),
            "phase": TERMINAL_PHASE,
            "candidateSha": commit('c'),
            "policyDigest": self.policy_digest,
            "latestSequence": TERMINAL_EVENT_SEQ,
            "status": "stopped",
            "complete": true,
            "bundleDigest": null,
            "artifacts": [],
            "latestEvent": null,
            "signedBundle": null,
            "terminalBundleDigest": envelope["bundle_digest"],
            "signedTerminalBundle": envelope,
        })
    }
}

/// Every migration 0035 column, so one test can perturb exactly one of them.
#[derive(Debug, Clone)]
struct BundleRow {
    id: Uuid,
    tenant_id: Uuid,
    run_id: Uuid,
    work_item_id: Uuid,
    attempt_id: Uuid,
    work_order_id: Uuid,
    work_order_digest: String,
    worker_session_id: Uuid,
    worker_id: Uuid,
    worker_generation: i64,
    external_run_id: String,
    get_run_snapshot_id: Uuid,
    event_page_snapshot_id: Uuid,
    response_wire_digest: String,
    response_wire: Vec<u8>,
    terminal_bundle_digest: String,
    terminal_phase: String,
    terminal_event_seq: i64,
    base_sha: String,
    candidate_sha: Option<String>,
    canonical_statement: Vec<u8>,
    statement_digest: String,
    predicate: Value,
    envelope_schema: String,
    signature_algorithm: String,
    signing_key_id: String,
    terminal_signature: String,
    exact_signed_envelope: Vec<u8>,
    issued_at: DateTime<Utc>,
}

impl BundleRow {
    /// The row the production activity would write for this fixture: every
    /// digest derived from the exact bytes retained beside it.
    fn conformant(fixture: &Fixture) -> Self {
        let statement = fixture.statement();
        let envelope = fixture.envelope(&statement);
        let view = fixture.evidence_view(&envelope);
        let wire = success_wire(&view);
        let canonical_statement = canonical_json(&statement).expect("canonicalize statement");
        let statement_digest = sha256_digest(&canonical_statement);
        Self {
            id: Uuid::now_v7(),
            tenant_id: fixture.tenant_id,
            run_id: fixture.run_id,
            work_item_id: fixture.work_item_id,
            attempt_id: fixture.attempt_id,
            work_order_id: fixture.work_order_id,
            work_order_digest: fixture.work_order_digest.clone(),
            worker_session_id: fixture.worker_session_id,
            worker_id: fixture.worker_id,
            worker_generation: 3,
            external_run_id: fixture.external_run_id.clone(),
            get_run_snapshot_id: fixture.get_run_snapshot_id,
            event_page_snapshot_id: fixture.event_page_snapshot_id,
            response_wire_digest: sha256_digest(&wire),
            response_wire: wire,
            terminal_bundle_digest: statement_digest.clone(),
            terminal_phase: TERMINAL_PHASE.into(),
            terminal_event_seq: TERMINAL_EVENT_SEQ,
            base_sha: commit('b'),
            candidate_sha: Some(commit('c')),
            canonical_statement,
            statement_digest,
            predicate: statement["predicate"].clone(),
            envelope_schema: SIGNED_TERMINAL_EVIDENCE_SCHEMA.into(),
            signature_algorithm: "EdDSA".into(),
            signing_key_id: fixture.signer.key_id().to_owned(),
            terminal_signature: envelope["signature"]
                .as_str()
                .expect("signature is a string")
                .to_owned(),
            exact_signed_envelope: serde_json::to_vec(&envelope).expect("encode envelope"),
            issued_at: fixture.issued_at,
        }
    }

    async fn insert(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(INSERT_BUNDLE_SQL)
            .bind(self.id)
            .bind(self.tenant_id)
            .bind(self.run_id)
            .bind(self.work_item_id)
            .bind(self.attempt_id)
            .bind(self.work_order_id)
            .bind(&self.work_order_digest)
            .bind(self.worker_session_id)
            .bind(self.worker_id)
            .bind(self.worker_generation)
            .bind(&self.external_run_id)
            .bind(self.get_run_snapshot_id)
            .bind(self.event_page_snapshot_id)
            .bind(&self.response_wire_digest)
            .bind(&self.response_wire)
            .bind(&self.terminal_bundle_digest)
            .bind(&self.terminal_phase)
            .bind(self.terminal_event_seq)
            .bind(&self.base_sha)
            .bind(self.candidate_sha.as_ref())
            .bind(&self.canonical_statement)
            .bind(&self.statement_digest)
            .bind(&self.predicate)
            .bind(&self.envelope_schema)
            .bind(&self.signature_algorithm)
            .bind(&self.signing_key_id)
            .bind(&self.terminal_signature)
            .bind(&self.exact_signed_envelope)
            .bind(self.issued_at)
            .execute(pool)
            .await
            .map(|_| ())
    }
}

#[tokio::test]
async fn terminal_evidence_bundles_are_exactly_bound_and_strictly_append_only() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let pool = database.ledger.pool().clone();

    let bundle = BundleRow::conformant(&fixture);
    bundle
        .insert(&pool)
        .await
        .expect("an exactly bound terminal evidence bundle is storable");

    let (retained_digest, retained_seq, stored_at): (String, i64, DateTime<Utc>) =
        sqlx::query_as("SELECT terminal_bundle_digest, terminal_event_seq, stored_at FROM runmill_terminal_evidence_bundles WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(bundle.id)
            .fetch_one(&pool)
            .await
            .expect("the retained bundle is readable");
    assert_eq!(retained_digest, bundle.terminal_bundle_digest);
    assert_eq!(retained_seq, TERMINAL_EVENT_SEQ);
    assert!(stored_at <= Utc::now());

    // The same durable fact cannot be retained twice, and neither control
    // snapshot can back a second bundle.
    let replay = BundleRow {
        id: Uuid::now_v7(),
        ..bundle.clone()
    };
    let error = replay
        .insert(&pool)
        .await
        .expect_err("one run retains one bundle per terminal digest");
    assert!(matches!(error, sqlx::Error::Database(_)), "{error}");

    // Append-only: no column may ever be updated and no row deleted.
    let update = sqlx::query(
        "UPDATE runmill_terminal_evidence_bundles SET terminal_phase = 'FAILED' WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(bundle.id)
    .execute(&pool)
    .await
    .expect_err("terminal evidence bundles cannot be updated");
    assert_eq!(
        constraint_of(&update),
        Some("runmill_terminal_evidence_bundles_append_only".into())
    );
    let delete = sqlx::query(
        "DELETE FROM runmill_terminal_evidence_bundles WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(bundle.id)
    .execute(&pool)
    .await
    .expect_err("terminal evidence bundles cannot be deleted");
    assert_eq!(
        constraint_of(&delete),
        Some("runmill_terminal_evidence_bundles_append_only".into())
    );
    sqlx::query("TRUNCATE runmill_terminal_evidence_bundles")
        .execute(&pool)
        .await
        .expect_err("terminal evidence bundles cannot be truncated");

    database.cleanup().await;
}

/// One named guard, the contradiction that must trip it, and the perturbation
/// that introduces exactly that contradiction.
type GuardCase = (
    &'static str,
    &'static str,
    Box<dyn Fn(&Fixture, &mut BundleRow)>,
);

#[tokio::test]
async fn terminal_evidence_insert_guard_rejects_every_contradiction() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let pool = database.ledger.pool().clone();

    // Each case perturbs exactly one thing about an otherwise storable bundle
    // and names the guard that must reject it.
    let cases: Vec<GuardCase> = vec![
        (
            "envelope bytes that are not a JSON object",
            "runmill_terminal_evidence_bundles_exact_envelope",
            Box::new(|_fixture, row| row.exact_signed_envelope = b"not json".to_vec()),
        ),
        (
            "an envelope whose key set is not the signing contract",
            "runmill_terminal_evidence_bundles_envelope_contract",
            Box::new(|_fixture, row| {
                let mut envelope: Value =
                    serde_json::from_slice(&row.exact_signed_envelope).unwrap();
                envelope["unexpected"] = json!(true);
                row.exact_signed_envelope = serde_json::to_vec(&envelope).unwrap();
            }),
        ),
        (
            "an indexed signing key that the envelope never named",
            "runmill_terminal_evidence_bundles_envelope_contract",
            Box::new(|_fixture, row| row.signing_key_id = "someone-elses-key".into()),
        ),
        (
            "canonical bytes that decode to a different statement",
            "runmill_terminal_evidence_bundles_canonical_statement",
            // Only the retained bytes move: every digest still names the
            // envelope, so the sole disagreement is what those bytes decode to.
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["stop"]["summary"] = json!("a different summary");
                row.canonical_statement = canonical_json(&statement).unwrap();
            }),
        ),
        (
            "a retained predicate that is not the signed predicate",
            "runmill_terminal_evidence_bundles_predicate_binding",
            Box::new(|_fixture, row| {
                row.predicate["stop"]["summary"] = json!("a different summary");
            }),
        ),
        (
            "a predicate run binding that contradicts the indexed run",
            "runmill_terminal_evidence_bundles_predicate_run_binding",
            Box::new(|_fixture, row| row.external_run_id = "run-999".into()),
        ),
        (
            "an admission digest that is not the indexed Work Order digest",
            "runmill_terminal_evidence_bundles_predicate_admission_binding",
            Box::new(|_fixture, row| row.work_order_digest = digest('9')),
        ),
        (
            "a base commit the signed source never attested",
            "runmill_terminal_evidence_bundles_predicate_source_binding",
            Box::new(|_fixture, row| row.base_sha = commit('d')),
        ),
        (
            "a subject that no longer names the attested candidate",
            "runmill_terminal_evidence_bundles_predicate_source_binding",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["source"]["candidate_sha"] = Value::Null;
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "an admission signature that was never positively verified",
            "runmill_terminal_evidence_bundles_predicate_admission_signature",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["admission"]["signature_verification"]["verified"] =
                    json!(false);
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "an event chain that contradicts the terminal sequence",
            "runmill_terminal_evidence_bundles_predicate_evidence_binding",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["evidence"]["preceding_event_count"] = json!(0);
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "a cleanup that does not prove a closed run",
            "runmill_terminal_evidence_bundles_predicate_cleanup_closure",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["cleanup"]["repository_lease"] = json!("held");
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "an elapsed time that does not span admission through issuance",
            "runmill_terminal_evidence_bundles_predicate_timing_binding",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["timing"]["elapsed_ms"] = json!(ELAPSED_MS + 1);
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "a statement subject that is not the attested run subject",
            "runmill_terminal_evidence_bundles_statement_subject",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["subject"][0]["digest"]["sha1"] = json!(commit('d'));
                reseal(fixture, row, &statement);
            }),
        ),
        (
            "a wire digest that is not the digest of the retained wire",
            "runmill_terminal_evidence_bundles_exact_digests",
            Box::new(|_fixture, row| row.response_wire_digest = digest('9')),
        ),
        (
            "an evidence wire that is not one exact success line",
            "runmill_terminal_evidence_bundles_exact_evidence_wire",
            Box::new(|fixture, row| {
                let envelope = fixture.envelope(&fixture.statement());
                let view = fixture.evidence_view(&envelope);
                let mut wire = serde_json::to_vec(&json!({"ok": false, "data": view})).unwrap();
                wire.push(b'\n');
                row.response_wire_digest = sha256_digest(&wire);
                row.response_wire = wire;
            }),
        ),
        (
            "an evidence wire carrying an unknown view key",
            "runmill_terminal_evidence_bundles_evidence_view_contract",
            Box::new(|fixture, row| {
                let envelope = fixture.envelope(&fixture.statement());
                let mut view = fixture.evidence_view(&envelope);
                view["unexpected"] = json!(true);
                let wire = success_wire(&view);
                row.response_wire_digest = sha256_digest(&wire);
                row.response_wire = wire;
            }),
        ),
        (
            "an evidence view that contradicts the row it is retained for",
            "runmill_terminal_evidence_bundles_evidence_view_binding",
            Box::new(|fixture, row| {
                let envelope = fixture.envelope(&fixture.statement());
                let mut view = fixture.evidence_view(&envelope);
                view["latestSequence"] = json!(TERMINAL_EVENT_SEQ + 5);
                let wire = success_wire(&view);
                row.response_wire_digest = sha256_digest(&wire);
                row.response_wire = wire;
            }),
        ),
        (
            "the two snapshot roles satisfied in the wrong order",
            "runmill_terminal_evidence_bundles_exact_snapshots",
            Box::new(|fixture, row| {
                row.get_run_snapshot_id = fixture.event_page_snapshot_id;
                row.event_page_snapshot_id = fixture.get_run_snapshot_id;
            }),
        ),
        (
            "a terminal sequence the event page never observed",
            "runmill_terminal_evidence_bundles_terminal_observation",
            Box::new(|fixture, row| {
                let mut statement = fixture.statement();
                statement["predicate"]["run"]["terminal_event_seq"] = json!(TERMINAL_EVENT_SEQ + 1);
                statement["predicate"]["evidence"]["preceding_event_count"] =
                    json!(TERMINAL_EVENT_SEQ);
                row.terminal_event_seq = TERMINAL_EVENT_SEQ + 1;
                reseal_with_view(fixture, row, &statement, TERMINAL_EVENT_SEQ + 1);
            }),
        ),
    ];

    for (description, constraint, mutate) in cases {
        let mut row = BundleRow::conformant(&fixture);
        row.id = Uuid::now_v7();
        mutate(&fixture, &mut row);
        let error = row
            .insert(&pool)
            .await
            .expect_err(&format!("{description} must be refused"));
        assert_eq!(
            constraint_of(&error).as_deref(),
            Some(constraint),
            "{description} must be refused by {constraint}, got {error}"
        );
    }

    database.cleanup().await;
}

/// Re-derive every digest, the envelope, and the wire after a statement was
/// deliberately changed, so the only remaining disagreement is the one the case
/// is about.
fn reseal(fixture: &Fixture, row: &mut BundleRow, statement: &Value) {
    reseal_with_view(fixture, row, statement, TERMINAL_EVENT_SEQ);
}

fn reseal_with_view(
    fixture: &Fixture,
    row: &mut BundleRow,
    statement: &Value,
    latest_sequence: i64,
) {
    let envelope = fixture.envelope(statement);
    let mut view = fixture.evidence_view(&envelope);
    view["latestSequence"] = json!(latest_sequence);
    let wire = success_wire(&view);
    let canonical = canonical_json(statement).expect("canonicalize statement");
    row.statement_digest = sha256_digest(&canonical);
    row.terminal_bundle_digest = row.statement_digest.clone();
    row.canonical_statement = canonical;
    row.predicate = statement["predicate"].clone();
    envelope["signature"]
        .as_str()
        .unwrap()
        .clone_into(&mut row.terminal_signature);
    row.exact_signed_envelope = serde_json::to_vec(&envelope).expect("encode envelope");
    row.response_wire_digest = sha256_digest(&wire);
    row.response_wire = wire;
}

#[tokio::test]
async fn production_retention_activity_records_the_bundle_from_a_live_evidence_read() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let pool = database.ledger.pool().clone();

    let statement = fixture.statement();
    let envelope = fixture.envelope(&statement);
    let view = fixture.evidence_view(&envelope);
    let control = ControlFixture::new(json!({"ok": true, "data": view}));

    let bundle_id = Uuid::now_v7();
    let job = claimed_retention_job(&pool, &fixture, bundle_id).await;
    let handler = RunmillTerminalEvidenceHandler::new(
        database.ledger.clone(),
        TenantId::from_uuid(fixture.tenant_id),
        WorkerId::from_uuid(fixture.worker_id),
        control.client(),
    )
    .expect("construct the tenant-bound retention activity");

    let outcome = handler
        .execute(&job, ActivityControls::new(false))
        .await
        .expect("a live terminal evidence read is retained");
    assert_eq!(outcome, ActivityOutcome::TransactionCommitted);

    // The activity requested exactly the evidence for its own external run.
    assert_eq!(
        control.request().await,
        json!({"type": "asf.get_evidence", "runId": fixture.external_run_id})
    );

    let (retained_id, retained_digest, wire_digest): (Uuid, String, String) = sqlx::query_as(
        "SELECT id, terminal_bundle_digest, terminal_evidence_response_wire_digest FROM runmill_terminal_evidence_bundles WHERE tenant_id = $1 AND run_id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(&pool)
    .await
    .expect("the production activity retained exactly one bundle");
    assert_eq!(retained_id, bundle_id);
    assert_eq!(retained_digest, envelope["bundle_digest"].as_str().unwrap());
    assert_eq!(
        wire_digest,
        sha256_digest(&success_wire(&fixture.evidence_view(&envelope)))
    );

    let (status, result): (String, Value) =
        sqlx::query_as("SELECT status, result FROM workflow_jobs WHERE tenant_id = $1 AND id = $2")
            .bind(fixture.tenant_id)
            .bind(job.id)
            .fetch_one(&pool)
            .await
            .expect("the retention job is settled in the same transaction");
    assert_eq!(status, "COMPLETED");
    assert_eq!(
        result["schema"],
        json!("asf.runmill-terminal-evidence-result/v1")
    );
    assert_eq!(result["inserted"], json!(true));
    assert_eq!(result["bundle_id"], json!(bundle_id));

    // Retention observes; it never projects events or rewrites run state.
    let (run_state, projected_events): (String, i64) = sqlx::query_as(
        "SELECT run.state, (SELECT count(*) FROM raw_run_events AS event WHERE event.tenant_id = run.tenant_id AND event.run_id = run.id) FROM runs AS run WHERE run.tenant_id = $1 AND run.id = $2",
    )
    .bind(fixture.tenant_id)
    .bind(fixture.run_id)
    .fetch_one(&pool)
    .await
    .expect("the authoritative run is readable");
    assert_eq!(run_state, "ADOPTED");
    assert_eq!(projected_events, 0);

    database.cleanup().await;
}

#[tokio::test]
async fn terminal_ready_streams_produce_exactly_one_retention_job_until_a_bundle_exists() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let fixture = Fixture::insert(&database.ledger).await;
    let pool = database.ledger.pool().clone();
    let ready_workers = vec![fixture.worker_id.to_string()];

    // A worker this process does not own is never produced for.
    let foreign = produce_due_runmill_terminal_evidence_jobs(
        &pool,
        fixture.tenant_id,
        &[Uuid::now_v7().to_string()],
        100,
    )
    .await
    .expect("production over a foreign worker route succeeds trivially");
    assert_eq!(foreign.jobs_enqueued, 0);

    let first =
        produce_due_runmill_terminal_evidence_jobs(&pool, fixture.tenant_id, &ready_workers, 100)
            .await
            .expect("a terminal-ready stream owes exactly one retention job");
    assert_eq!(first.jobs_enqueued, 1);

    let (job_type, payload, idempotency_key): (String, Value, String) = sqlx::query_as(
        "SELECT job_type, payload, idempotency_key FROM workflow_jobs WHERE tenant_id = $1 AND job_type = $2",
    )
    .bind(fixture.tenant_id)
    .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE)
    .fetch_one(&pool)
    .await
    .expect("exactly one retention job exists");
    assert_eq!(job_type, RETAIN_RUNMILL_TERMINAL_EVIDENCE);
    assert_eq!(
        idempotency_key,
        format!(
            "runmill-terminal-evidence:{}:{}",
            fixture.run_id, fixture.observation_id
        )
    );
    // The payload states the terminal observation the stream actually reached,
    // one sequence past the page the event snapshot observed.
    assert_eq!(payload["terminal_event_seq"], json!(TERMINAL_EVENT_SEQ));
    assert_eq!(payload["terminal_phase"], json!(TERMINAL_PHASE));
    assert_eq!(
        payload["get_run_snapshot_id"],
        json!(fixture.get_run_snapshot_id)
    );
    assert_eq!(
        payload["event_page_snapshot_id"],
        json!(fixture.event_page_snapshot_id)
    );
    assert_eq!(
        payload["worker_session_id"],
        json!(fixture.worker_session_id),
        "the payload names the immutable admitting session, not the observer"
    );

    // The same terminal observation is one durable fact: a second pass adds
    // nothing while the first job is still pending.
    let replay =
        produce_due_runmill_terminal_evidence_jobs(&pool, fixture.tenant_id, &ready_workers, 100)
            .await
            .expect("re-production is idempotent");
    assert_eq!(replay.jobs_enqueued, 0);

    // Once the bundle is retained the stream owes nothing further.
    BundleRow::conformant(&fixture)
        .insert(&pool)
        .await
        .expect("retain the terminal evidence bundle");
    let retained =
        produce_due_runmill_terminal_evidence_jobs(&pool, fixture.tenant_id, &ready_workers, 100)
            .await
            .expect("production over a retained run succeeds trivially");
    assert_eq!(retained.jobs_enqueued, 0);

    database.cleanup().await;
}

/// One claimed `RETAIN_RUNMILL_TERMINAL_EVIDENCE` job, exactly as the producer
/// mints it and the reactor leases it.
async fn claimed_retention_job(
    pool: &PgPool,
    fixture: &Fixture,
    bundle_id: Uuid,
) -> ClaimedWorkflowJob {
    let job_id = Uuid::now_v7();
    let lease_owner = "reactor:terminal-evidence-activity".to_owned();
    let lease_expires_at = Utc::now() + Duration::minutes(5);
    let payload = json!({
        "schema": "asf.runmill-terminal-evidence/v1",
        "bundle_id": bundle_id,
        "run_id": fixture.run_id,
        "work_order_id": fixture.work_order_id,
        "work_order_digest": fixture.work_order_digest,
        "worker_id": fixture.worker_id,
        "worker_session_id": fixture.worker_session_id,
        "worker_generation": 3,
        "observer_session_id": fixture.observer_session_id,
        "external_run_id": fixture.external_run_id,
        "observation_id": fixture.observation_id,
        "get_run_snapshot_id": fixture.get_run_snapshot_id,
        "event_page_snapshot_id": fixture.event_page_snapshot_id,
        "terminal_phase": TERMINAL_PHASE,
        "terminal_event_seq": TERMINAL_EVENT_SEQ,
    });
    sqlx::query(
        "INSERT INTO workflow_jobs (id, tenant_id, workflow_instance_id, work_item_id, attempt_id, job_type, activity_contract_id, status, payload, idempotency_key, priority, max_attempts, attempt_count, fence_token, lease_owner, lease_expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'RUNNING', $8, $9, 70, 25, 1, 1, $10, $11)",
    )
    .bind(job_id)
    .bind(fixture.tenant_id)
    .bind(fixture.workflow_instance_id)
    .bind(fixture.work_item_id)
    .bind(fixture.attempt_id)
    .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE)
    .bind(RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID)
    .bind(&payload)
    .bind(format!(
        "runmill-terminal-evidence:{}:{}",
        fixture.run_id, fixture.observation_id
    ))
    .bind(&lease_owner)
    .bind(lease_expires_at)
    .execute(pool)
    .await
    .expect("insert the claimed retention job");

    ClaimedWorkflowJob {
        id: job_id,
        tenant_id: fixture.tenant_id,
        workflow_instance_id: Some(fixture.workflow_instance_id),
        work_item_id: Some(fixture.work_item_id),
        attempt_id: Some(fixture.attempt_id),
        job_type: RETAIN_RUNMILL_TERMINAL_EVIDENCE.into(),
        activity_contract_id: RETAIN_RUNMILL_TERMINAL_EVIDENCE_ACTIVITY_CONTRACT_ID.into(),
        payload,
        idempotency_key: format!(
            "runmill-terminal-evidence:{}:{}",
            fixture.run_id, fixture.observation_id
        ),
        priority: 70,
        attempt_count: 1,
        max_attempts: 25,
        fence_token: 1,
        lease_owner,
        lease_expires_at,
        created_at: Utc::now(),
    }
}

/// A private Runmill control daemon that answers exactly one request.
struct ControlFixture {
    _directory: TempDir,
    registry_path: PathBuf,
    request: tokio::sync::oneshot::Receiver<Value>,
}

impl ControlFixture {
    fn new(response: Value) -> Self {
        let directory = tempfile::tempdir().expect("create fixture runtime directory");
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700))
            .expect("secure fixture runtime directory");
        let socket_path = directory.path().join("control.sock");
        let registry_path = directory.path().join("daemon.json");
        let listener = UnixListener::bind(&socket_path).expect("bind fixture socket");
        fs::set_permissions(&socket_path, Permissions::from_mode(0o600))
            .expect("secure fixture socket");

        let registry = json!({
            "protocolVersion": RUNMILL_CONTROL_PROTOCOL_VERSION,
            "pid": std::process::id(),
            "socketPath": socket_path,
            "startedAt": "2026-08-24T16:00:00Z",
            "repoRoot": "/srv/repository",
            "configPath": "/srv/repository/runmill.json",
        });
        let mut file = File::create(&registry_path).expect("create fixture registry");
        file.write_all(&serde_json::to_vec(&registry).expect("encode registry"))
            .expect("write fixture registry");
        file.set_permissions(Permissions::from_mode(0o600))
            .expect("secure fixture registry");
        drop(file);

        let (sender, request) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept fixture request");
            let observed = serve_once(stream, response).await;
            let _ = sender.send(observed);
        });

        Self {
            _directory: directory,
            registry_path,
            request,
        }
    }

    fn client(&self) -> RunmillControlClient {
        RunmillControlClient::new(self.registry_path.clone(), StdDuration::from_secs(10))
            .expect("construct fixture control client")
    }

    async fn request(self) -> Value {
        self.request.await.expect("the daemon observed one request")
    }
}

async fn serve_once(mut stream: UnixStream, response: Value) -> Value {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte).await.expect("read fixture request");
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        request.push(byte[0]);
    }
    let mut bytes = serde_json::to_vec(&response).expect("encode fixture response");
    bytes.push(b'\n');
    stream.write_all(&bytes).await.expect("write response");
    stream.shutdown().await.expect("close fixture response");
    serde_json::from_slice(&request).expect("parse fixture request")
}

fn constraint_of(error: &sqlx::Error) -> Option<String> {
    let sqlx::Error::Database(database) = error else {
        return None;
    };
    database
        .try_downcast_ref::<PgDatabaseError>()
        .and_then(|error| error.constraint())
        .map(ToOwned::to_owned)
}

fn success_wire(view: &Value) -> Vec<u8> {
    let mut wire = serde_json::to_vec(&json!({"ok": true, "data": view})).expect("encode wire");
    wire.push(b'\n');
    wire
}

fn successful_response_bytes(raw_snapshot: &Value) -> Vec<u8> {
    let mut wire =
        serde_json::to_vec(&json!({"ok": true, "data": raw_snapshot})).expect("encode wire");
    wire.push(b'\n');
    wire
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn commit(character: char) -> String {
    character.to_string().repeat(40)
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
