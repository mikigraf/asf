-- Durable, read-only provenance for observations of an already-authoritative
-- Runmill run.  These rows deliberately do not feed raw_run_events or mutate
-- runs: a later reducer must explicitly consume this evidence under its own
-- authority rules.

-- PostgreSQL jsonb cannot reproduce RFC 8785/JCS for every JSON number.  The
-- trusted Rust client therefore supplies JCS bytes.  PostgreSQL independently
-- proves that those bytes decode to the retained semantic value and derives
-- their digest from the bytes themselves.  Exact wire bytes are retained for
-- the complete successful control response, including its framing newline.

CREATE TABLE runmill_control_snapshots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    work_order_id uuid NOT NULL,
    work_order_digest text NOT NULL CHECK (work_order_digest ~ '^sha256:[0-9a-f]{64}$'),
    workflow_job_id uuid NOT NULL,
    workflow_job_fence_token bigint NOT NULL CHECK (workflow_job_fence_token > 0),
    workflow_job_attempt_count integer NOT NULL CHECK (workflow_job_attempt_count > 0),
    workflow_job_owner text NOT NULL CHECK (btrim(workflow_job_owner) <> ''),
    worker_session_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    external_run_id text NOT NULL CHECK (btrim(external_run_id) <> ''),
    admission_idempotency_key text,
    admission_envelope_digest text,
    admission_policy_digest text,
    control_sequence bigint NOT NULL CHECK (control_sequence > 0),
    control_operation text NOT NULL CHECK (control_operation IN ('GET_RUN', 'LIST_RUN_EVENTS')),
    external_generation bigint NOT NULL
        CHECK (external_generation BETWEEN 0 AND 9007199254740991),
    external_state_version bigint NOT NULL
        CHECK (external_state_version BETWEEN 1 AND 9007199254740991),
    external_latest_sequence bigint NOT NULL
        CHECK (external_latest_sequence BETWEEN 1 AND 9007199254740991),
    observed_at timestamptz NOT NULL,
    raw_response_bytes bytea NOT NULL
        CHECK (octet_length(raw_response_bytes) BETWEEN 2 AND 2097152),
    response_wire_digest text NOT NULL
        CHECK (response_wire_digest ~ '^sha256:[0-9a-f]{64}$'),
    raw_snapshot jsonb NOT NULL CHECK (jsonb_typeof(raw_snapshot) = 'object'),
    canonical_snapshot bytea NOT NULL CHECK (octet_length(canonical_snapshot) > 0),
    snapshot_semantic_digest text NOT NULL
        CHECK (snapshot_semantic_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, workflow_job_id, workflow_job_fence_token, control_sequence),
    UNIQUE (
        tenant_id, id, run_id, work_item_id, attempt_id, work_order_id,
        work_order_digest, workflow_job_id, workflow_job_fence_token,
        workflow_job_attempt_count, workflow_job_owner, worker_session_id,
        worker_id, worker_generation
    ),
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
        REFERENCES attempts(tenant_id, id, work_item_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_order_id, work_order_digest, work_item_id, attempt_id)
        REFERENCES work_orders(tenant_id, id, payload_digest, work_item_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, run_id, work_item_id, attempt_id)
        REFERENCES runs(tenant_id, id, work_item_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_session_id, worker_id, worker_generation)
        REFERENCES worker_sessions(tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs(tenant_id, id) ON DELETE RESTRICT,
    CHECK (
        (
            control_operation = 'GET_RUN'
            AND admission_idempotency_key IS NOT NULL
            AND btrim(admission_idempotency_key) <> ''
            AND admission_envelope_digest IS NOT NULL
            AND admission_envelope_digest ~ '^sha256:[0-9a-f]{64}$'
            AND admission_policy_digest IS NOT NULL
            AND admission_policy_digest ~ '^sha256:[0-9a-f]{64}$'
        ) OR (
            control_operation = 'LIST_RUN_EVENTS'
            AND admission_idempotency_key IS NULL
            AND admission_envelope_digest IS NULL
            AND admission_policy_digest IS NULL
        )
    ),
    CHECK (external_state_version = external_latest_sequence)
);

CREATE INDEX runmill_control_snapshots_run_observed_idx
    ON runmill_control_snapshots (tenant_id, run_id, observed_at, id);

-- This trigger is the authority boundary.  A future observer must hold the
-- exact live, attempt-bound OBSERVE_RUNMILL_RUN claim and may only report for
-- the run's immutable Work Order and exact active worker session/generation.
CREATE FUNCTION asf_stamp_runmill_control_snapshot() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    decoded_response jsonb;
    decoded_canonical jsonb;
BEGIN
    IF octet_length(NEW.raw_response_bytes) NOT BETWEEN 2 AND 2097152 THEN
        RAISE EXCEPTION 'Runmill control response wire is outside the protocol size limit'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END IF;
    BEGIN
        decoded_response := convert_from(NEW.raw_response_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Runmill control response bytes are not UTF-8 JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END;
    IF jsonb_typeof(decoded_response) IS DISTINCT FROM 'object'
       OR decoded_response ?& ARRAY['ok', 'data'] IS NOT TRUE
       OR decoded_response - ARRAY['ok', 'data'] <> '{}'::jsonb
       OR decoded_response -> 'ok' IS DISTINCT FROM 'true'::jsonb
       OR decoded_response -> 'data' IS DISTINCT FROM NEW.raw_snapshot
       OR get_byte(NEW.raw_response_bytes, octet_length(NEW.raw_response_bytes) - 1) <> 10
       OR position(decode('0a', 'hex') in NEW.raw_response_bytes)
          <> octet_length(NEW.raw_response_bytes)
       OR NEW.response_wire_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.raw_response_bytes), 'hex'
       ) THEN
        RAISE EXCEPTION 'Runmill control response bytes contradict their exact success envelope'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END IF;
    BEGIN
        decoded_canonical := convert_from(NEW.canonical_snapshot, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Runmill control snapshot JCS bytes are not UTF-8 JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_canonical_semantics';
    END;
    IF decoded_canonical IS DISTINCT FROM NEW.raw_snapshot
       OR NEW.snapshot_semantic_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.canonical_snapshot), 'hex'
       ) THEN
        RAISE EXCEPTION 'Runmill control snapshot canonical bytes or semantic digest is invalid'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_canonical_semantics';
    END IF;

    PERFORM 1
    FROM workflow_jobs AS job
    WHERE job.tenant_id = NEW.tenant_id
      AND job.id = NEW.workflow_job_id
      AND job.work_item_id = NEW.work_item_id
      AND job.attempt_id = NEW.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.status = 'RUNNING'
      AND job.fence_token = NEW.workflow_job_fence_token
      AND job.attempt_count = NEW.workflow_job_attempt_count
      AND job.lease_owner = NEW.workflow_job_owner
      AND job.lease_expires_at > clock_timestamp()
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id'
      ]
      AND job.payload - ARRAY[
          'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id'
      ] = '{}'::jsonb
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND job.payload ->> 'run_id' = NEW.run_id::text
      AND job.payload ->> 'work_order_id' = NEW.work_order_id::text
      AND job.payload ->> 'work_order_digest' = NEW.work_order_digest
      AND job.payload ->> 'worker_id' = NEW.worker_id::text
      AND job.payload ->> 'worker_session_id' = NEW.worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(NEW.worker_generation)
      AND job.payload ->> 'external_run_id' = NEW.external_run_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot lacks its exact live observation claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_job_claim';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM runmill_control_snapshots AS prior
        WHERE prior.tenant_id = NEW.tenant_id
          AND prior.workflow_job_id = NEW.workflow_job_id
          AND prior.workflow_job_fence_token = NEW.workflow_job_fence_token
          AND prior.control_sequence > NEW.control_sequence
    ) THEN
        RAISE EXCEPTION 'Runmill control sequence moved backwards within one job claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_monotonic_control_sequence';
    END IF;

    IF (
        NEW.control_operation = 'GET_RUN'
        AND (
            NEW.raw_snapshot #>> '{run,runId}' IS DISTINCT FROM NEW.external_run_id
            OR NEW.raw_snapshot #>> '{run,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{run,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{run,generation}' IS DISTINCT FROM NEW.external_generation::text
            OR NEW.raw_snapshot #>> '{run,stateVersion}' IS DISTINCT FROM NEW.external_state_version::text
            OR NEW.raw_snapshot ->> 'latestSequence' IS DISTINCT FROM NEW.external_latest_sequence::text
            OR NEW.raw_snapshot #>> '{admission,idempotencyKey}' IS DISTINCT FROM NEW.admission_idempotency_key
            OR NEW.raw_snapshot #>> '{admission,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{admission,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{admission,tenantId}' IS DISTINCT FROM NEW.tenant_id::text
            OR NEW.raw_snapshot #>> '{admission,payloadDigest}' IS DISTINCT FROM NEW.work_order_digest
            OR NEW.raw_snapshot #>> '{admission,envelopeDigest}' IS DISTINCT FROM NEW.admission_envelope_digest
            OR NEW.raw_snapshot #>> '{admission,effectivePolicyDigest}' IS DISTINCT FROM NEW.admission_policy_digest
        )
    ) OR (
        NEW.control_operation = 'LIST_RUN_EVENTS'
        AND (
            jsonb_typeof(NEW.raw_snapshot -> 'events') IS DISTINCT FROM 'array'
            OR CASE
                WHEN jsonb_typeof(NEW.raw_snapshot -> 'events') = 'array'
                THEN jsonb_array_length(NEW.raw_snapshot -> 'events') > 1000
                ELSE false
            END
            OR
            NEW.raw_snapshot #>> '{snapshot,run,runId}' IS DISTINCT FROM NEW.external_run_id
            OR NEW.raw_snapshot #>> '{snapshot,run,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,generation}' IS DISTINCT FROM NEW.external_generation::text
            OR NEW.raw_snapshot #>> '{snapshot,run,stateVersion}' IS DISTINCT FROM NEW.external_state_version::text
            OR NEW.raw_snapshot #>> '{snapshot,latestSequence}' IS DISTINCT FROM NEW.external_latest_sequence::text
        )
    ) THEN
        RAISE EXCEPTION 'Runmill control snapshot indexed provenance contradicts raw JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_raw_json_binding';
    END IF;

    PERFORM 1
    FROM workers AS worker
    JOIN worker_sessions AS session
      ON session.tenant_id = worker.tenant_id
     AND session.worker_id = worker.id
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
      AND session.id = NEW.worker_session_id
      AND session.worker_generation = NEW.worker_generation
      AND session.status = 'ACTIVE'
      AND session.expires_at > clock_timestamp()
    FOR SHARE OF worker, session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot has a stale, closed, or expired worker session generation'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'runmill_control_snapshots_live_worker_session';
    END IF;

    PERFORM 1
    FROM runs AS run
    JOIN work_orders AS work_order
      ON work_order.tenant_id = run.tenant_id
     AND work_order.id = run.work_order_id
    JOIN attempts AS attempt
      ON attempt.tenant_id = run.tenant_id
     AND attempt.id = run.attempt_id
     AND attempt.work_item_id = run.work_item_id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND work_order.payload_digest = NEW.work_order_digest
      AND run.worker_session_id = NEW.worker_session_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.external_run_id = NEW.external_run_id
      AND run.authoritative
      AND (
          NEW.control_operation = 'LIST_RUN_EVENTS'
          OR (
              work_order.idempotency_key = NEW.admission_idempotency_key
              AND work_order.key_id = NEW.raw_snapshot #>> '{admission,signatureKeyId}'
              AND work_order.algorithm = NEW.raw_snapshot #>> '{admission,signatureAlgorithm}'
              AND attempt.policy_digest = NEW.admission_policy_digest
              AND NEW.admission_envelope_digest = 'sha256:' || encode(
                  sha256(work_order.exact_signed_envelope), 'hex'
              )
          )
      )
    FOR SHARE OF run, work_order, attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot lacks the exact authoritative run binding'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_run_binding';
    END IF;

    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_control_snapshots_stamp
    BEFORE INSERT ON runmill_control_snapshots
    FOR EACH ROW EXECUTE FUNCTION asf_stamp_runmill_control_snapshot();
CREATE TRIGGER runmill_control_snapshots_append_only
    BEFORE UPDATE OR DELETE ON runmill_control_snapshots
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER runmill_control_snapshots_truncate_forbidden
    BEFORE TRUNCATE ON runmill_control_snapshots
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TABLE raw_runmill_control_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    first_snapshot_id uuid NOT NULL,
    run_id uuid NOT NULL,
    external_event_id text NOT NULL CHECK (btrim(external_event_id) <> ''),
    event_sequence bigint NOT NULL
        CHECK (event_sequence BETWEEN 1 AND 9007199254740991),
    event_type text NOT NULL CHECK (btrim(event_type) <> ''),
    occurred_at timestamptz NOT NULL,
    raw_event jsonb NOT NULL CHECK (jsonb_typeof(raw_event) = 'object'),
    canonical_event bytea NOT NULL CHECK (octet_length(canonical_event) > 0),
    event_semantic_digest text NOT NULL
        CHECK (event_semantic_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, run_id, external_event_id),
    UNIQUE (tenant_id, run_id, event_sequence),
    FOREIGN KEY (tenant_id, first_snapshot_id)
        REFERENCES runmill_control_snapshots(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX raw_runmill_control_events_run_sequence_idx
    ON raw_runmill_control_events (tenant_id, run_id, event_sequence, recorded_at);

CREATE FUNCTION asf_stamp_raw_runmill_control_event() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    first_snapshot runmill_control_snapshots%ROWTYPE;
    decoded_canonical jsonb;
BEGIN
    BEGIN
        decoded_canonical := convert_from(NEW.canonical_event, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Runmill control event JCS bytes are not UTF-8 JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'raw_runmill_control_events_canonical_semantics';
    END;
    IF decoded_canonical IS DISTINCT FROM NEW.raw_event
       OR NEW.event_semantic_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.canonical_event), 'hex'
       ) THEN
        RAISE EXCEPTION 'Runmill control event canonical bytes or semantic digest is invalid'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'raw_runmill_control_events_canonical_semantics';
    END IF;

    SELECT snapshot.* INTO first_snapshot
    FROM runmill_control_snapshots AS snapshot
    WHERE snapshot.tenant_id = NEW.tenant_id
      AND snapshot.id = NEW.first_snapshot_id
      AND snapshot.run_id = NEW.run_id
      AND snapshot.control_operation = 'LIST_RUN_EVENTS'
    FOR SHARE;
    IF NOT FOUND OR NEW.event_sequence > first_snapshot.external_latest_sequence THEN
        RAISE EXCEPTION 'Runmill control event is outside its exact snapshot provenance'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'raw_runmill_control_events_exact_snapshot';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM runmill_control_snapshots AS snapshot
        CROSS JOIN LATERAL jsonb_array_elements(snapshot.raw_snapshot -> 'events') AS retained(event)
        WHERE snapshot.tenant_id = NEW.tenant_id
          AND snapshot.id = NEW.first_snapshot_id
          AND snapshot.control_operation = 'LIST_RUN_EVENTS'
          AND retained.event = NEW.raw_event
    ) THEN
        RAISE EXCEPTION 'Runmill control event is absent from its exact retained response page'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'raw_runmill_control_events_exact_page_membership';
    END IF;
    IF NEW.raw_event ->> 'schema' IS DISTINCT FROM 'asf.run-event/v1'
       OR NEW.raw_event ->> 'event_id' IS DISTINCT FROM NEW.external_event_id
       OR NEW.raw_event ->> 'run_id' IS DISTINCT FROM first_snapshot.external_run_id
       OR NEW.raw_event ->> 'work_order_id' IS DISTINCT FROM first_snapshot.work_order_id::text
       OR NEW.raw_event ->> 'attempt_id' IS DISTINCT FROM first_snapshot.attempt_id::text
       OR NEW.raw_event ->> 'seq' IS DISTINCT FROM NEW.event_sequence::text
       OR NEW.raw_event ->> 'type' IS DISTINCT FROM NEW.event_type
       OR (NEW.raw_event ->> 'occurred_at')::timestamptz IS DISTINCT FROM NEW.occurred_at
       OR NEW.raw_event ->> 'policy_digest' IS DISTINCT FROM (
           SELECT attempt.policy_digest
           FROM attempts AS attempt
           WHERE attempt.tenant_id = NEW.tenant_id
             AND attempt.id = first_snapshot.attempt_id
             AND attempt.work_item_id = first_snapshot.work_item_id
       ) THEN
        RAISE EXCEPTION 'Runmill control event indexed provenance contradicts raw JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'raw_runmill_control_events_raw_json_binding';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER raw_runmill_control_events_stamp
    BEFORE INSERT ON raw_runmill_control_events
    FOR EACH ROW EXECUTE FUNCTION asf_stamp_raw_runmill_control_event();
CREATE TRIGGER raw_runmill_control_events_append_only
    BEFORE UPDATE OR DELETE ON raw_runmill_control_events
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER raw_runmill_control_events_truncate_forbidden
    BEFORE TRUNCATE ON raw_runmill_control_events
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- A remote event has one immutable first-seen origin, but overlapping pages
-- and a reclaimed observer may truthfully see it again.  Keep those page
-- observations separate from the event identity so a new job fence cannot
-- rewrite the original row or turn a valid reconnect into an identity clash.
CREATE TABLE runmill_control_snapshot_events (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    snapshot_id uuid NOT NULL,
    event_id uuid NOT NULL,
    page_ordinal integer NOT NULL CHECK (page_ordinal BETWEEN 0 AND 999),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, snapshot_id, event_id),
    UNIQUE (tenant_id, snapshot_id, page_ordinal),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES runmill_control_snapshots(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES raw_runmill_control_events(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX runmill_control_snapshot_events_event_idx
    ON runmill_control_snapshot_events (tenant_id, event_id, snapshot_id);

CREATE FUNCTION asf_stamp_runmill_control_snapshot_event() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_run_id uuid;
    snapshot_operation text;
    snapshot_latest_sequence bigint;
    retained_event jsonb;
    event_run_id uuid;
    event_sequence bigint;
    event_raw jsonb;
BEGIN
    SELECT
        snapshot.run_id,
        snapshot.control_operation,
        snapshot.external_latest_sequence,
        snapshot.raw_snapshot -> 'events' -> NEW.page_ordinal
    INTO
        snapshot_run_id,
        snapshot_operation,
        snapshot_latest_sequence,
        retained_event
    FROM runmill_control_snapshots AS snapshot
    WHERE snapshot.tenant_id = NEW.tenant_id
      AND snapshot.id = NEW.snapshot_id
    FOR SHARE;
    IF NOT FOUND OR snapshot_operation <> 'LIST_RUN_EVENTS' OR retained_event IS NULL THEN
        RAISE EXCEPTION 'Runmill control event link lacks its exact retained response page'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshot_events_exact_page';
    END IF;

    SELECT event.run_id, event.event_sequence, event.raw_event
    INTO event_run_id, event_sequence, event_raw
    FROM raw_runmill_control_events AS event
    WHERE event.tenant_id = NEW.tenant_id
      AND event.id = NEW.event_id
    FOR SHARE;
    IF NOT FOUND
       OR event_run_id IS DISTINCT FROM snapshot_run_id
       OR event_sequence > snapshot_latest_sequence
       OR event_raw IS DISTINCT FROM retained_event THEN
        RAISE EXCEPTION 'Runmill control event link contradicts its exact retained response page'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshot_events_exact_membership';
    END IF;

    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_control_snapshot_events_stamp
    BEFORE INSERT ON runmill_control_snapshot_events
    FOR EACH ROW EXECUTE FUNCTION asf_stamp_runmill_control_snapshot_event();
CREATE TRIGGER runmill_control_snapshot_events_append_only
    BEFORE UPDATE OR DELETE ON runmill_control_snapshot_events
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER runmill_control_snapshot_events_truncate_forbidden
    BEFORE TRUNCATE ON runmill_control_snapshot_events
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
