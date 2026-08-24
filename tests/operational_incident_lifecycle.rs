use asf::{
    Error,
    api::{ApiBackend as _, PageQuery, PostgresApiBackend},
    application::AttentionItemKind,
    crypto::{canonical_json, sha256_digest},
    domain::TenantId,
    ledger::{NewWorkflowJob, OperationalIncidentStatus, OperationalIncidentTransition, PgLedger},
};
use chrono::SubsecRound as _;
use chrono::Utc;
use serde_json::json;
use sqlx::{PgPool, Row as _};
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
            .expect("connect operational-incident test administrator");
        let schema = format!("asf_incident_test_{}", Uuid::now_v7().simple());
        assert!(
            schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated operational-incident schema");

        let mut scoped_url = Url::parse(database_url).expect("parse test database URL");
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str())
            .await
            .expect("connect isolated operational-incident ledger");
        ledger
            .migrate()
            .await
            .expect("migrate isolated operational-incident schema");
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
            .expect("drop isolated operational-incident schema");
        self.admin.close().await;
    }
}

async fn insert_owned_dead_job(ledger: &PgLedger, tenant_id: Uuid) -> (Uuid, Uuid) {
    let job_id = Uuid::now_v7();
    let incident_id = Uuid::now_v7();
    ledger
        .enqueue_job(&NewWorkflowJob {
            id: job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: "OPERATIONAL_LIFECYCLE_TEST".into(),
            activity_contract_id: "test.activity/operational-lifecycle-test/v1".into(),
            payload: json!({"scope": "tenant"}),
            idempotency_key: format!("incident-lifecycle-job:{job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6),
            max_attempts: 1,
        })
        .await
        .expect("enqueue operational lifecycle fixture");

    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .expect("begin operational incident fixture");
    sqlx::query(
        r"
        INSERT INTO operational_incidents (
            id, tenant_id, workflow_job_id, category, status, severity,
            reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key
        ) VALUES (
            $1, $2, $3, 'WORKFLOW_JOB_EXHAUSTED', 'OPEN', 'HIGH',
            'tenant-scoped workflow job exhausted its retry budget',
            'ON_CALL', 'platform-operations',
            'reconcile the exhausted job and record the outcome',
            $4, clock_timestamp() + interval '1 hour', '[]'::jsonb, $5,
            '[]'::jsonb, true, $6
        )
        ",
    )
    .bind(incident_id)
    .bind(tenant_id)
    .bind(job_id)
    .bind(json!([
        format!("workflow-job:{job_id}"),
        "failure:last-attempt"
    ]))
    .bind(json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 300,
        "prerequisites": ["operator reconciliation"]
    }))
    .bind(format!("operational-job-exhausted:{job_id}"))
    .execute(&mut *transaction)
    .await
    .expect("insert operational incident fixture");

    sqlx::query(
        r"
        UPDATE workflow_jobs
        SET status = 'DEAD',
            dead_letter_operational_incident_id = $3,
            dead_lettered_at = clock_timestamp(),
            updated_at = clock_timestamp()
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(incident_id)
    .execute(&mut *transaction)
    .await
    .expect("bind dead job to its operational incident");
    transaction
        .commit()
        .await
        .expect("commit atomically owned operational incident fixture");
    (job_id, incident_id)
}

#[tokio::test]
async fn live_resolved_incident_leaves_history_but_not_active_attention_when_configured() {
    let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
        return;
    };
    let database = ScopedDatabase::create(&database_url).await;
    let tenant_id = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(format!("incident-lifecycle-{tenant_id}"))
        .bind("Operational incident lifecycle test")
        .execute(database.ledger.pool())
        .await
        .expect("insert operational-incident tenant");
    let (job_id, incident_id) = insert_owned_dead_job(&database.ledger, tenant_id).await;
    let backend = PostgresApiBackend::from_ledger(&database.ledger, TenantId::from_uuid(tenant_id));
    let page = PageQuery {
        cursor: None,
        limit: 10,
    };

    let open = backend
        .attention(TenantId::from_uuid(tenant_id), &page)
        .await
        .expect("open incident is complete active attention");
    assert_eq!(open.items.len(), 1);
    assert_eq!(open.items[0].kind, AttentionItemKind::OperationalIncident);
    assert_eq!(open.items[0].id, incident_id);
    assert_eq!(open.items[0].work_item_id, None);
    assert_eq!(open.items[0].workflow_job_id, Some(job_id));

    let skipped = sqlx::query(
        r"
        UPDATE operational_incidents
        SET status = 'RESOLVED', aggregate_version = 3,
            acknowledged_at = clock_timestamp(), acknowledged_by = 'operator',
            closed_at = clock_timestamp(), closed_by = 'operator',
            resolution = 'reconciled', authority_or_effect_active = false
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("database rejects skipped acknowledgement");
    assert_eq!(
        skipped
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    let malformed_acknowledgement = sqlx::query(
        r"
        UPDATE operational_incidents
        SET status = 'ACKNOWLEDGED', aggregate_version = 2,
            acknowledged_at = clock_timestamp(), acknowledged_by = ''
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("database rejects blank acknowledgement metadata");
    assert_eq!(
        malformed_acknowledgement
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    let sensitive = database
        .ledger
        .transition_operational_incident(
            tenant_id,
            incident_id,
            1,
            &OperationalIncidentTransition::Acknowledge {
                actor: "Bearer must-not-persist".into(),
            },
        )
        .await
        .expect_err("credential-shaped transition metadata is rejected");
    assert!(matches!(sensitive, Error::Validation(_)));

    let acknowledgement = OperationalIncidentTransition::Acknowledge {
        actor: "operator:on-call".into(),
    };
    // Simulate a committed first call whose response was lost to the caller.
    let first_acknowledgement = database
        .ledger
        .transition_operational_incident(tenant_id, incident_id, 1, &acknowledgement)
        .await
        .expect("acknowledge incident atomically");
    let acknowledged = database
        .ledger
        .transition_operational_incident(tenant_id, incident_id, 1, &acknowledgement)
        .await
        .expect("exact acknowledgement replay adopts its durable receipt");
    assert_eq!(acknowledged, first_acknowledgement);
    assert_eq!(acknowledged.status, OperationalIncidentStatus::Acknowledged);
    assert_eq!(acknowledged.aggregate_version, 2);
    assert_eq!(
        acknowledged.acknowledged_by.as_deref(),
        Some("operator:on-call")
    );
    let contradictory_actor = database
        .ledger
        .transition_operational_incident(
            tenant_id,
            incident_id,
            1,
            &OperationalIncidentTransition::Acknowledge {
                actor: "operator:different".into(),
            },
        )
        .await
        .expect_err("changed actor contradicts the acknowledged receipt");
    assert!(matches!(contradictory_actor, Error::Conflict(_)));

    let acknowledgement_effects = sqlx::query_as::<_, (i64, i64, i64)>(
        r"
        SELECT
            (SELECT count(*) FROM operational_incident_transition_receipts
             WHERE tenant_id = $1 AND incident_id = $2 AND expected_version = 1),
            (SELECT count(*) FROM audit_events
             WHERE tenant_id = $1 AND subject_type = 'OPERATIONAL_INCIDENT'
               AND subject_id = $2::text AND action = 'OPERATIONAL_INCIDENT_ACKNOWLEDGED'),
            (SELECT count(*) FROM outbox
             WHERE tenant_id = $1 AND message_key = $2::text
               AND event_type = 'operational_incident.acknowledged')
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count acknowledgement transition effects");
    assert_eq!(acknowledgement_effects, (1, 1, 1));

    let acknowledged_attention = backend
        .attention(TenantId::from_uuid(tenant_id), &page)
        .await
        .expect("acknowledged incident remains active attention");
    assert_eq!(acknowledged_attention.items.len(), 1);

    let stale = database
        .ledger
        .transition_operational_incident(
            tenant_id,
            incident_id,
            1,
            &OperationalIncidentTransition::Resolve {
                actor: "operator:on-call".into(),
                resolution: "provider state reconciled".into(),
            },
        )
        .await
        .expect_err("stale lifecycle version is rejected");
    assert!(matches!(stale, Error::Conflict(_)));

    let resolution = OperationalIncidentTransition::Resolve {
        actor: "operator:on-call".into(),
        resolution: "provider state reconciled and no effect remains active".into(),
    };
    let resolved = database
        .ledger
        .transition_operational_incident(tenant_id, incident_id, 2, &resolution)
        .await
        .expect("resolve acknowledged incident atomically");
    let replayed_resolution = database
        .ledger
        .transition_operational_incident(tenant_id, incident_id, 2, &resolution)
        .await
        .expect("exact resolution replay adopts its durable receipt");
    assert_eq!(replayed_resolution, resolved);
    let changed_resolution = database
        .ledger
        .transition_operational_incident(
            tenant_id,
            incident_id,
            2,
            &OperationalIncidentTransition::Resolve {
                actor: "operator:on-call".into(),
                resolution: "different reconciliation claim".into(),
            },
        )
        .await
        .expect_err("changed resolution contradicts the durable receipt");
    assert!(matches!(changed_resolution, Error::Conflict(_)));
    assert_eq!(resolved.status, OperationalIncidentStatus::Resolved);
    assert_eq!(resolved.aggregate_version, 3);
    assert_eq!(resolved.closed_by.as_deref(), Some("operator:on-call"));
    assert!(resolved.closed_at >= resolved.acknowledged_at);

    // The acknowledgement receipt remains adoptable after the incident has
    // advanced to a later aggregate version.
    let late_acknowledgement_replay = database
        .ledger
        .transition_operational_incident(tenant_id, incident_id, 1, &acknowledgement)
        .await
        .expect("old exact receipt survives later lifecycle progress");
    assert_eq!(late_acknowledgement_replay, first_acknowledgement);

    let transition_audits = sqlx::query(
        r"
        SELECT action, event_hash, previous_event_hash, details, occurred_at
        FROM audit_events
        WHERE tenant_id = $1
          AND subject_type = 'OPERATIONAL_INCIDENT'
          AND subject_id = $2::text
        ORDER BY occurred_at, id
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_all(database.ledger.pool())
    .await
    .expect("load transition audit chain");
    assert_eq!(transition_audits.len(), 2);
    let first_hash: String = transition_audits[0].try_get("event_hash").unwrap();
    assert!(
        transition_audits[0]
            .try_get::<Option<String>, _>("previous_event_hash")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        transition_audits[1]
            .try_get::<Option<String>, _>("previous_event_hash")
            .unwrap()
            .as_deref(),
        Some(first_hash.as_str())
    );
    let resolution_details: serde_json::Value = transition_audits[1].try_get("details").unwrap();
    assert_eq!(
        resolution_details
            .get("resolution")
            .and_then(serde_json::Value::as_str),
        Some("provider state reconciled and no effect remains active")
    );

    let durable_resolution = sqlx::query(
        r"
        SELECT receipt.resolution, receipt.occurred_at,
               audit.occurred_at AS audit_occurred_at,
               outbox.available_at AS outbox_available_at,
               outbox.payload
        FROM operational_incident_transition_receipts AS receipt
        JOIN audit_events AS audit
          ON audit.tenant_id = receipt.tenant_id
         AND audit.id = receipt.audit_event_id
        JOIN outbox
          ON outbox.tenant_id = receipt.tenant_id
         AND outbox.id = receipt.outbox_id
        WHERE receipt.tenant_id = $1
          AND receipt.incident_id = $2
          AND receipt.expected_version = 2
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load durable resolution receipt and effects");
    assert_eq!(
        durable_resolution
            .try_get::<Option<String>, _>("resolution")
            .unwrap()
            .as_deref(),
        Some("provider state reconciled and no effect remains active")
    );
    let closed_at = resolved.closed_at.expect("resolved timestamp");
    assert_eq!(
        durable_resolution
            .try_get::<chrono::DateTime<Utc>, _>("occurred_at")
            .unwrap(),
        closed_at
    );
    assert_eq!(
        durable_resolution
            .try_get::<chrono::DateTime<Utc>, _>("audit_occurred_at")
            .unwrap(),
        closed_at
    );
    assert_eq!(
        durable_resolution
            .try_get::<chrono::DateTime<Utc>, _>("outbox_available_at")
            .unwrap(),
        closed_at
    );
    let resolution_payload: serde_json::Value = durable_resolution.try_get("payload").unwrap();
    assert_eq!(
        resolution_payload
            .get("resolution")
            .and_then(serde_json::Value::as_str),
        Some("provider state reconciled and no effect remains active")
    );
    assert_eq!(
        resolution_payload
            .get("actor")
            .and_then(serde_json::Value::as_str),
        Some("operator:on-call")
    );
    let transition_effect_counts = sqlx::query_as::<_, (i64, i64, i64)>(
        r"
        SELECT
            (SELECT count(*) FROM operational_incident_transition_receipts
             WHERE tenant_id = $1 AND incident_id = $2),
            (SELECT count(*) FROM audit_events
             WHERE tenant_id = $1 AND subject_type = 'OPERATIONAL_INCIDENT'
               AND subject_id = $2::text),
            (SELECT count(*) FROM outbox
             WHERE tenant_id = $1 AND message_key = $2::text
               AND event_type LIKE 'operational_incident.%')
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("count exact transition effects per lifecycle fence");
    assert_eq!(transition_effect_counts, (2, 2, 2));

    let receipt_mutation = sqlx::query(
        r"
        UPDATE operational_incident_transition_receipts
        SET request_digest = request_digest
        WHERE tenant_id = $1 AND incident_id = $2 AND expected_version = 2
        ",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("transition receipts are append-only even for no-op updates");
    assert_eq!(
        receipt_mutation
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000")
    );

    let (_cancelled_job_id, cancelled_incident_id) =
        insert_owned_dead_job(&database.ledger, tenant_id).await;
    database
        .ledger
        .transition_operational_incident(
            tenant_id,
            cancelled_incident_id,
            1,
            &OperationalIncidentTransition::Acknowledge {
                actor: "operator:cancellation".into(),
            },
        )
        .await
        .expect("acknowledge incident before cancellation");
    let cancelled = database
        .ledger
        .transition_operational_incident(
            tenant_id,
            cancelled_incident_id,
            2,
            &OperationalIncidentTransition::Cancel {
                actor: "operator:cancellation".into(),
                resolution: "incident superseded by a corrected durable job".into(),
            },
        )
        .await
        .expect("cancel acknowledged incident through the supported lifecycle");
    assert_eq!(cancelled.status, OperationalIncidentStatus::Cancelled);
    assert_eq!(cancelled.aggregate_version, 3);
    assert!(!cancelled.authority_or_effect_active);
    assert_eq!(
        cancelled.resolution.as_deref(),
        Some("incident superseded by a corrected durable job")
    );
    let cancel_receipt = sqlx::query_as::<_, (String, String, Option<String>)>(
        r"
        SELECT transition_kind, result_status, resolution
        FROM operational_incident_transition_receipts
        WHERE tenant_id = $1 AND incident_id = $2 AND expected_version = 2
        ",
    )
    .bind(tenant_id)
    .bind(cancelled_incident_id)
    .fetch_one(database.ledger.pool())
    .await
    .expect("load cancellation transition receipt");
    assert_eq!(
        cancel_receipt,
        (
            "CANCEL".into(),
            "CANCELLED".into(),
            Some("incident superseded by a corrected durable job".into())
        )
    );

    // The DEAD row and its historical ownership link are immutable receipts.
    sqlx::query(
        "UPDATE workflow_jobs SET updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(job_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("terminal workflow job ownership cannot be rewritten");

    let after_resolution = backend
        .attention(TenantId::from_uuid(tenant_id), &page)
        .await
        .expect("resolved historical incident does not fail attention coverage");
    assert!(after_resolution.items.is_empty());

    let terminal_mutation = sqlx::query(
        "UPDATE operational_incidents SET resolution = 'rewritten' \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .execute(database.ledger.pool())
    .await
    .expect_err("database rejects mutation after terminal resolution");
    assert_eq!(
        terminal_mutation
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    // Even an otherwise legal direct lifecycle UPDATE is rejected at commit
    // because it lacks the immutable receipt and its FK-backed audit/outbox.
    let (_unreceipted_job_id, unreceipted_incident_id) =
        insert_owned_dead_job(&database.ledger, tenant_id).await;
    let mut unreceipted = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin unreceipted direct transition");
    sqlx::query(
        r"
        UPDATE operational_incidents
        SET status = 'ACKNOWLEDGED', aggregate_version = 2,
            acknowledged_at = clock_timestamp(), acknowledged_by = 'direct-writer'
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(unreceipted_incident_id)
    .execute(&mut *unreceipted)
    .await
    .expect("shape-valid direct transition reaches deferred receipt check");
    let unreceipted_error = unreceipted
        .commit()
        .await
        .expect_err("commit rejects transition without receipt/audit/outbox");
    assert_eq!(
        unreceipted_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );

    // Exact receipt semantics still reject two independent integrity poisons:
    // an arbitrary well-formed audit hash, and an exact outbox inserted as if
    // it had already been published. Each case keeps every other field exact.
    for poison_case in ["forged-audit-hash", "prepublished-outbox"] {
        let (_poison_job_id, poison_incident_id) =
            insert_owned_dead_job(&database.ledger, tenant_id).await;
        let mut poison = database
            .ledger
            .pool()
            .begin()
            .await
            .expect("begin forged audit-hash poison");
        let poison_occurred_at =
            sqlx::query_scalar::<_, chrono::DateTime<Utc>>("SELECT clock_timestamp()")
                .fetch_one(&mut *poison)
                .await
                .expect("capture poison transition timestamp");
        sqlx::query(
            r"
        UPDATE operational_incidents
        SET status = 'ACKNOWLEDGED', aggregate_version = 2,
            acknowledged_at = $3, acknowledged_by = 'internal-poison'
        WHERE tenant_id = $1 AND id = $2
        ",
        )
        .bind(tenant_id)
        .bind(poison_incident_id)
        .bind(poison_occurred_at)
        .execute(&mut *poison)
        .await
        .expect("shape-valid poison transition reaches deferred proof");
        let poison_job_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT workflow_job_id FROM operational_incidents WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(poison_incident_id)
        .fetch_one(&mut *poison)
        .await
        .expect("load poison incident workflow job");
        let previous_event_hash = sqlx::query_scalar::<_, String>(
            r"
        SELECT event.event_hash
        FROM audit_events AS event
        WHERE event.tenant_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS successor
              WHERE successor.tenant_id = event.tenant_id
                AND successor.previous_event_hash = event.event_hash
          )
        ",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *poison)
        .await
        .expect("load poison tenant audit head");
        let poison_audit_id = Uuid::now_v7();
        let poison_outbox_id = Uuid::now_v7();
        let poison_digest = sha256_digest(
            &canonical_json(&json!({
                "schema": "asf.operational-incident-transition-request/v1",
                "tenant_id": tenant_id,
                "incident_id": poison_incident_id,
                "expected_version": 1,
                "transition": "ACKNOWLEDGE",
                "actor": "internal-poison",
                "resolution": null,
            }))
            .expect("canonicalize poison request semantics"),
        );
        let exact_before_digest = sha256_digest(
            &canonical_json(&json!({
                "id": poison_incident_id,
                "tenant_id": tenant_id,
                "workflow_job_id": poison_job_id,
                "status": "OPEN",
                "aggregate_version": 1,
                "authority_or_effect_active": true,
                "acknowledged_at": null,
                "acknowledged_by": null,
                "closed_at": null,
                "closed_by": null,
                "resolution": null,
            }))
            .expect("canonicalize exact pre-transition lifecycle"),
        );
        let exact_after_digest = sha256_digest(
            &canonical_json(&json!({
                "id": poison_incident_id,
                "tenant_id": tenant_id,
                "workflow_job_id": poison_job_id,
                "status": "ACKNOWLEDGED",
                "aggregate_version": 2,
                "authority_or_effect_active": true,
                "acknowledged_at": poison_occurred_at,
                "acknowledged_by": "internal-poison",
                "closed_at": null,
                "closed_by": null,
                "resolution": null,
            }))
            .expect("canonicalize exact post-transition lifecycle"),
        );
        let poison_correlation_id = format!("operational-incident:{poison_incident_id}:1");
        let poison_event_hash = if poison_case == "forged-audit-hash" {
            format!("sha256:{}", "d".repeat(64))
        } else {
            sqlx::query_scalar::<_, String>(
                r"
            SELECT asf_operational_incident_transition_audit_hash(
                $1, $2, 'OPERATOR', 'internal-poison',
                'OPERATIONAL_INCIDENT_ACKNOWLEDGED', 'OPERATIONAL_INCIDENT',
                $3, $4, $5, $6, $7, $8, $9, $10,
                'ACKNOWLEDGE', 'OPEN', 'ACKNOWLEDGED', 1, 2, $11, NULL
            )
            ",
            )
            .bind(poison_audit_id)
            .bind(tenant_id)
            .bind(poison_incident_id.to_string())
            .bind(&poison_correlation_id)
            .bind(&exact_before_digest)
            .bind(&exact_after_digest)
            .bind(&previous_event_hash)
            .bind(poison_occurred_at)
            .bind(poison_incident_id)
            .bind(poison_job_id)
            .bind(&poison_digest)
            .fetch_one(&mut *poison)
            .await
            .expect("derive exact poison audit hash")
        };
        sqlx::query(
            r"
        INSERT INTO audit_events (
            id, tenant_id, work_item_id, attempt_id, actor_type, actor_id,
            action, subject_type, subject_id, correlation_id, trace_id,
            policy_digest, before_digest, after_digest, previous_event_hash,
            event_hash, details, occurred_at
        ) VALUES (
            $1, $2, NULL, NULL, 'OPERATOR', 'internal-poison',
            'OPERATIONAL_INCIDENT_ACKNOWLEDGED', 'OPERATIONAL_INCIDENT', $3,
            $4, NULL, NULL, $5, $6, $7, $8, $9, $10
        )
        ",
        )
        .bind(poison_audit_id)
        .bind(tenant_id)
        .bind(poison_incident_id.to_string())
        .bind(&poison_correlation_id)
        .bind(&exact_before_digest)
        .bind(&exact_after_digest)
        .bind(&previous_event_hash)
        .bind(&poison_event_hash)
        .bind(json!({
            "schema": "asf.operational-incident-transition-audit/v1",
            "operational_incident_id": poison_incident_id,
            "workflow_job_id": poison_job_id,
            "transition": "ACKNOWLEDGE",
            "from_status": "OPEN",
            "to_status": "ACKNOWLEDGED",
            "expected_version": 1,
            "result_aggregate_version": 2,
            "request_digest": poison_digest,
            "resolution": null,
        }))
        .bind(poison_occurred_at)
        .execute(&mut *poison)
        .await
        .expect("insert exact audit content with forged event hash");
        sqlx::query(
            r"
        INSERT INTO outbox (
            id, tenant_id, topic, message_key, event_type, payload, headers,
            idempotency_key, available_at, status, attempt_count,
            fence_token, published_at
        ) VALUES (
            $1, $2, 'attention', $3, 'operational_incident.acknowledged',
            $4, $5, $6, $7, $8, $9, $10, $11
        )
        ",
        )
        .bind(poison_outbox_id)
        .bind(tenant_id)
        .bind(poison_incident_id.to_string())
        .bind(json!({
            "schema": "asf.operational-incident-lifecycle-event/v1",
            "tenant_id": tenant_id,
            "operational_incident_id": poison_incident_id,
            "workflow_job_id": poison_job_id,
            "transition": "ACKNOWLEDGE",
            "status": "ACKNOWLEDGED",
            "actor": "internal-poison",
            "expected_version": 1,
            "aggregate_version": 2,
            "request_digest": poison_digest,
            "resolution": null,
            "audit_event_id": poison_audit_id,
            "occurred_at": poison_occurred_at,
        }))
        .bind(json!({"schema": "asf.operational-incident-lifecycle-event/v1"}))
        .bind(format!("{poison_correlation_id}:outbox"))
        .bind(poison_occurred_at)
        .bind(if poison_case == "prepublished-outbox" {
            "PUBLISHED"
        } else {
            "PENDING"
        })
        .bind(i32::from(poison_case == "prepublished-outbox"))
        .bind(i64::from(poison_case == "prepublished-outbox"))
        .bind((poison_case == "prepublished-outbox").then_some(poison_occurred_at))
        .execute(&mut *poison)
        .await
        .expect("insert exact poison outbox");
        sqlx::query(
            r"
        INSERT INTO operational_incident_transition_receipts (
            tenant_id, incident_id, workflow_job_id, expected_version,
            request_digest, transition_kind, result_status,
            result_aggregate_version, result_authority_or_effect_active,
            acknowledged_at, acknowledged_by, closed_at, closed_by,
            resolution, occurred_at, audit_event_id, outbox_id
        ) VALUES (
            $1, $2, $3, 1, $4, 'ACKNOWLEDGE', 'ACKNOWLEDGED',
            2, true, $5, 'internal-poison', NULL, NULL, NULL, $5, $6, $7
        )
        ",
        )
        .bind(tenant_id)
        .bind(poison_incident_id)
        .bind(poison_job_id)
        .bind(&poison_digest)
        .bind(poison_occurred_at)
        .bind(poison_audit_id)
        .bind(poison_outbox_id)
        .execute(&mut *poison)
        .await
        .expect("insert exact poison receipt");
        let poison_error = poison
            .commit()
            .await
            .expect_err("commit rejects forged audit hash or prepublished outbox");
        assert_eq!(
            poison_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM operational_incidents WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(poison_incident_id)
            .fetch_one(database.ledger.pool())
            .await
            .expect("load incident after rolled-back poison"),
            "OPEN"
        );
    }

    // Pre-inserting an otherwise plausible incident cannot reserve the unique
    // job/category or idempotency slots while leaving the referenced job live.
    // The reciprocal proof runs at commit so the production insert-then-DEAD
    // ordering in one transaction remains valid.
    let orphan_job_id = Uuid::now_v7();
    let orphan_incident_id = Uuid::now_v7();
    database
        .ledger
        .enqueue_job(&NewWorkflowJob {
            id: orphan_job_id,
            tenant_id,
            workflow_instance_id: None,
            work_item_id: None,
            attempt_id: None,
            job_type: "OPERATIONAL_ORPHAN_POISON_TEST".into(),
            activity_contract_id: "test.activity/operational-orphan-poison-test/v1".into(),
            payload: json!({"scope": "tenant"}),
            idempotency_key: format!("incident-orphan-job:{orphan_job_id}"),
            priority: 0,
            available_at: Utc::now().trunc_subsecs(6),
            max_attempts: 1,
        })
        .await
        .expect("enqueue orphan-poison job");
    let mut orphan = database
        .ledger
        .pool()
        .begin()
        .await
        .expect("begin orphan incident poison");
    sqlx::query(
        r"
        INSERT INTO operational_incidents (
            id, tenant_id, workflow_job_id, category, status, severity,
            reason, owner_type, owner_id, required_action,
            evidence_references, deadline, escalation_path, retry_policy,
            prerequisites, authority_or_effect_active, idempotency_key
        ) VALUES (
            $1, $2, $3, 'WORKFLOW_JOB_EXHAUSTED', 'OPEN', 'HIGH',
            'pre-inserted incident intended to occupy the production slot',
            'ON_CALL', 'platform-operations',
            'reconcile the exhausted job and record the outcome',
            $4, clock_timestamp() + interval '1 hour', '[]'::jsonb, $5,
            '[]'::jsonb, true, $6
        )
        ",
    )
    .bind(orphan_incident_id)
    .bind(tenant_id)
    .bind(orphan_job_id)
    .bind(json!([
        format!("workflow-job:{orphan_job_id}"),
        "failure:invented"
    ]))
    .bind(json!({
        "automatic": false,
        "max_additional_attempts": 0,
        "backoff_seconds": 300,
        "prerequisites": ["operator reconciliation"]
    }))
    .bind(format!("operational-job-exhausted:{orphan_job_id}"))
    .execute(&mut *orphan)
    .await
    .expect("shape-valid orphan reaches deferred owner proof");
    let orphan_error = orphan
        .commit()
        .await
        .expect_err("commit rejects incident whose workflow job remains live");
    assert_eq!(
        orphan_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM operational_incidents WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(orphan_incident_id)
        .fetch_one(database.ledger.pool())
        .await
        .expect("count rolled-back orphan incident"),
        0
    );

    database.cleanup().await;
}
