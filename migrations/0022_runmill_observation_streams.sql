-- Durable cursor ownership for Runmill observation.
--
-- Migration 0021 deliberately retained one bounded, read-only observation
-- without advancing an ASF cursor.  A durable reconnecting observer needs a
-- separate aggregate that owns that cursor, serializes one active observer job
-- per authoritative run, and records the observer-control session separately
-- from the immutable session that admitted the run.
--
-- Apply only after draining every pre-0022 nonterminal observation job.  Those
-- envelopes have seven fields and cannot prove the cursor/epoch or a current
-- observer session required below.  Completed historical observations remain
-- valid immutable history and are deliberately not backfilled into streams:
-- old rows do not prove which workflow instance owned a run at adoption.

LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_control_snapshots IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_jobs AS job
        WHERE job.job_type = 'OBSERVE_RUNMILL_RUN'
          AND job.status IN ('PENDING', 'RUNNING', 'RETRY')
          AND (
              jsonb_typeof(job.payload) IS DISTINCT FROM 'object'
              OR job.payload ?& ARRAY[
                  'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                  'worker_session_id', 'worker_generation', 'external_run_id',
                  'after_sequence', 'observation_epoch', 'observer_session_id'
              ] IS NOT TRUE
              OR job.payload - ARRAY[
                  'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
                  'worker_session_id', 'worker_generation', 'external_run_id',
                  'after_sequence', 'observation_epoch', 'observer_session_id'
              ] <> '{}'::jsonb
              OR job.payload ->> 'schema' IS DISTINCT FROM 'asf.runmill-observation/v2'
              OR jsonb_typeof(job.payload -> 'observation_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'run_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'work_order_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'work_order_digest') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'worker_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'worker_session_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'worker_generation') IS DISTINCT FROM 'number'
              OR jsonb_typeof(job.payload -> 'external_run_id') IS DISTINCT FROM 'string'
              OR jsonb_typeof(job.payload -> 'after_sequence') IS DISTINCT FROM 'number'
              OR jsonb_typeof(job.payload -> 'observation_epoch') IS DISTINCT FROM 'number'
              OR jsonb_typeof(job.payload -> 'observer_session_id') IS DISTINCT FROM 'string'
          )
    ) THEN
        RAISE EXCEPTION
            'cannot upgrade while a legacy OBSERVE_RUNMILL_RUN job is live; drain or explicitly reconcile it before migration 0022'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'runmill_observation_streams_require_no_live_legacy_jobs';
    END IF;
END;
$$;

-- A stream is created atomically with a future authoritative run adoption.
-- No automatic backfill is safe: the old runs table has no immutable pointer
-- to the workflow instance that owned dispatch.  Operators must reconcile old
-- active runs into an owned escalation or establish the binding explicitly.
CREATE TABLE runmill_run_observation_streams (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    workflow_instance_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    work_order_id uuid NOT NULL,
    work_order_digest text NOT NULL
        CHECK (work_order_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    -- Immutable historic session that admitted the run.  It may legitimately
    -- be CLOSED after a worker restart and is never used as current control
    -- authority for a later observer job.
    run_admission_worker_session_id uuid NOT NULL,
    external_run_id text NOT NULL CHECK (btrim(external_run_id) <> ''),

    -- `next_after_sequence` is the exclusive cursor supplied to Runmill.
    -- `observation_epoch` changes for every newly enqueued poll, including an
    -- empty poll at an unchanged cursor, so completed immutable jobs never
    -- prevent a later liveness poll from being enqueued.
    next_after_sequence bigint NOT NULL DEFAULT 0
        CHECK (next_after_sequence BETWEEN 0 AND 9007199254740991),
    observation_epoch bigint NOT NULL DEFAULT 0
        CHECK (observation_epoch BETWEEN 0 AND 9007199254740991),
    active_job_id uuid,
    active_observation_id uuid,
    state text NOT NULL DEFAULT 'ACTIVE'
        CHECK (state IN (
            'ACTIVE', 'BLOCKED_GAP', 'BLOCKED_PROJECTION', 'TERMINAL_READY', 'ESCALATED'
        )),
    next_poll_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_snapshot_id uuid,
    escalation_id uuid,
    last_error_digest text
        CHECK (last_error_digest IS NULL OR last_error_digest ~ '^sha256:[0-9a-f]{64}$'),
    aggregate_version bigint NOT NULL DEFAULT 1 CHECK (aggregate_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, active_job_id),
    UNIQUE (tenant_id, active_observation_id),
    FOREIGN KEY (tenant_id, run_id, work_item_id, attempt_id)
        REFERENCES runs (tenant_id, id, work_item_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workflow_instance_id, work_item_id)
        REFERENCES workflow_instances (tenant_id, id, work_item_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_order_id, work_order_digest, work_item_id, attempt_id)
        REFERENCES work_orders (
            tenant_id, id, payload_digest, work_item_id, attempt_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (
        tenant_id, run_admission_worker_session_id, worker_id, worker_generation
    ) REFERENCES worker_sessions (tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, active_job_id)
        REFERENCES workflow_jobs (tenant_id, id)
        ON DELETE RESTRICT,
    CHECK (
        (active_job_id IS NULL) = (active_observation_id IS NULL)
    ),
    CHECK (
        (state = 'ACTIVE' AND escalation_id IS NULL)
        OR (state = 'TERMINAL_READY' AND active_job_id IS NULL AND escalation_id IS NULL)
        OR (state IN ('BLOCKED_GAP', 'BLOCKED_PROJECTION', 'ESCALATED')
            AND active_job_id IS NULL
            AND escalation_id IS NOT NULL)
    )
);

-- This is the immutable identity of one scheduled observation.  It binds the
-- V2 payload's observation UUID to one stream cursor/epoch before a worker is
-- allowed to claim the job.  No mutable status lives here: job lifecycle and
-- stream state are the authoritative mutable records.
CREATE TABLE runmill_run_observation_checkpoints (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    after_sequence bigint NOT NULL CHECK (after_sequence BETWEEN 0 AND 9007199254740991),
    observation_epoch bigint NOT NULL CHECK (observation_epoch BETWEEN 1 AND 9007199254740991),
    observer_session_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, workflow_job_id),
    UNIQUE (tenant_id, run_id, observation_epoch),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runmill_run_observation_streams (tenant_id, run_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, observer_session_id, worker_id, worker_generation)
        REFERENCES worker_sessions (tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT
);

-- Completion facts are separate from the scheduling checkpoint.  This makes
-- a crash between the remote reads and stream advancement auditable without
-- granting any right to mutate the run projection or raw_run_events.
CREATE TABLE runmill_run_observation_results (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    after_sequence bigint NOT NULL CHECK (after_sequence BETWEEN 0 AND 9007199254740991),
    next_sequence bigint NOT NULL CHECK (next_sequence BETWEEN 0 AND 9007199254740991),
    has_more boolean NOT NULL,
    gap boolean NOT NULL,
    compacted_through bigint
        CHECK (compacted_through IS NULL OR compacted_through BETWEEN 0 AND 9007199254740991),
    get_run_snapshot_id uuid NOT NULL,
    event_page_snapshot_id uuid NOT NULL,
    disposition text NOT NULL CHECK (
        disposition IN ('ADVANCED', 'TERMINAL_READY', 'BLOCKED_GAP', 'BLOCKED_PROJECTION')
    ),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, observation_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runmill_run_observation_streams (tenant_id, run_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES runmill_run_observation_checkpoints (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, get_run_snapshot_id)
        REFERENCES runmill_control_snapshots (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_page_snapshot_id)
        REFERENCES runmill_control_snapshots (tenant_id, id)
        ON DELETE RESTRICT,
    CHECK (next_sequence >= after_sequence),
    CHECK (gap = (compacted_through IS NOT NULL)),
    CHECK (
        (disposition = 'BLOCKED_GAP' AND gap)
        OR (disposition = 'BLOCKED_PROJECTION' AND NOT gap)
        OR (disposition IN ('ADVANCED', 'TERMINAL_READY')
            AND NOT gap
            AND next_sequence >= after_sequence)
    )
);

CREATE FUNCTION asf_assert_runmill_observation_result_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM runmill_run_observation_checkpoints AS checkpoint
    JOIN runmill_control_snapshots AS get_snapshot
      ON get_snapshot.tenant_id = checkpoint.tenant_id
     AND get_snapshot.id = NEW.get_run_snapshot_id
    JOIN runmill_control_snapshots AS page_snapshot
      ON page_snapshot.tenant_id = checkpoint.tenant_id
     AND page_snapshot.id = NEW.event_page_snapshot_id
    WHERE checkpoint.tenant_id = NEW.tenant_id
      AND checkpoint.id = NEW.observation_id
      AND checkpoint.run_id = NEW.run_id
      AND checkpoint.after_sequence = NEW.after_sequence
      AND get_snapshot.run_id = NEW.run_id
      AND get_snapshot.observation_id = checkpoint.id
      AND get_snapshot.control_operation = 'GET_RUN'
      AND page_snapshot.run_id = NEW.run_id
      AND page_snapshot.observation_id = checkpoint.id
      AND page_snapshot.control_operation = 'LIST_RUN_EVENTS'
      AND page_snapshot.requested_after_sequence = NEW.after_sequence
      AND page_snapshot.external_latest_sequence >= NEW.next_sequence
      AND (page_snapshot.raw_snapshot ->> 'nextCursor')::bigint = NEW.next_sequence
      AND (page_snapshot.raw_snapshot ->> 'hasMore')::boolean = NEW.has_more
      AND (page_snapshot.raw_snapshot ->> 'gap')::boolean = NEW.gap
      AND (page_snapshot.raw_snapshot ->> 'compactedThrough')::bigint
          IS NOT DISTINCT FROM NEW.compacted_through
    FOR SHARE OF checkpoint, get_snapshot, page_snapshot;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation result contradicts its immutable checkpoint or exact get/page snapshots'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_results_exact_provenance';
    END IF;
    IF NEW.has_more AND NEW.next_sequence >= (
        SELECT snapshot.external_latest_sequence
        FROM runmill_control_snapshots AS snapshot
        WHERE snapshot.tenant_id = NEW.tenant_id
          AND snapshot.id = NEW.event_page_snapshot_id
    ) THEN
        RAISE EXCEPTION 'Runmill observation result marks has_more at a terminal cursor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_results_cursor_shape';
    END IF;
    IF NEW.disposition = 'TERMINAL_READY' AND (
        NEW.has_more
        OR NEW.next_sequence <> (
            SELECT snapshot.external_latest_sequence
            FROM runmill_control_snapshots AS snapshot
            WHERE snapshot.tenant_id = NEW.tenant_id
              AND snapshot.id = NEW.event_page_snapshot_id
        )
    ) THEN
        RAISE EXCEPTION 'terminal-ready observation result does not reach its exact page latest sequence'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_results_terminal_cursor';
    END IF;
    IF NEW.disposition = 'TERMINAL_READY' AND NOT EXISTS (
        SELECT 1
        FROM runmill_control_snapshots AS snapshot
        WHERE snapshot.tenant_id = NEW.tenant_id
          AND snapshot.id = NEW.event_page_snapshot_id
          AND snapshot.raw_snapshot #>> '{snapshot,run,state}' IN (
              'COMPLETED', 'CANCELLED', 'FAILED', 'REFUSED',
              'QUARANTINED', 'BUDGET_EXHAUSTED'
          )
    ) THEN
        RAISE EXCEPTION 'terminal-ready observation result lacks an exact terminal Runmill state'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_results_terminal_phase';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION asf_guard_runmill_observation_result() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Runmill observation results are append-only immutable facts'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER runmill_observation_result_insert_guard
    BEFORE INSERT ON runmill_run_observation_results
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_observation_result_insert();
CREATE TRIGGER runmill_observation_result_append_only
    BEFORE UPDATE OR DELETE ON runmill_run_observation_results
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_observation_result();
CREATE TRIGGER runmill_observation_result_truncate_forbidden
    BEFORE TRUNCATE ON runmill_run_observation_results
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Exhaustion escalations are deliberately shared by work item, attempt, and
-- category. A compacted observation gap therefore needs its own immutable
-- proof when the effective shared escalation has no run_id or names another
-- run. Never rewrite that shared escalation's run identity.
CREATE TABLE runmill_observation_gap_escalation_bindings (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    event_page_snapshot_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, observation_id),
    UNIQUE (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runmill_run_observation_streams (tenant_id, run_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES runmill_run_observation_checkpoints (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES escalations (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_page_snapshot_id)
        REFERENCES runmill_control_snapshots (tenant_id, id)
        ON DELETE RESTRICT
);

CREATE FUNCTION asf_assert_runmill_observation_gap_escalation_binding_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM runmill_run_observation_checkpoints AS checkpoint
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = checkpoint.tenant_id
     AND stream.run_id = checkpoint.run_id
    JOIN runmill_run_observation_results AS result
      ON result.tenant_id = checkpoint.tenant_id
     AND result.observation_id = checkpoint.id
     AND result.run_id = checkpoint.run_id
    JOIN workflow_jobs AS job
      ON job.tenant_id = checkpoint.tenant_id
     AND job.id = checkpoint.workflow_job_id
    JOIN runmill_control_snapshots AS page_snapshot
      ON page_snapshot.tenant_id = checkpoint.tenant_id
     AND page_snapshot.id = result.event_page_snapshot_id
    JOIN escalations AS escalation
      ON escalation.tenant_id = job.tenant_id
     AND escalation.id = job.dead_letter_escalation_id
    WHERE checkpoint.tenant_id = NEW.tenant_id
      AND checkpoint.id = NEW.observation_id
      AND checkpoint.run_id = NEW.run_id
      AND checkpoint.workflow_job_id = NEW.workflow_job_id
      AND stream.active_observation_id = NEW.observation_id
      AND stream.active_job_id = NEW.workflow_job_id
      AND stream.state = 'ACTIVE'
      AND result.disposition = 'BLOCKED_GAP'
      AND result.gap
      AND result.event_page_snapshot_id = NEW.event_page_snapshot_id
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.status = 'DEAD'
      AND job.dead_letter_escalation_id = NEW.escalation_id
      AND page_snapshot.observation_id = NEW.observation_id
      AND page_snapshot.workflow_job_id = NEW.workflow_job_id
      AND page_snapshot.control_operation = 'LIST_RUN_EVENTS'
      AND escalation.id = NEW.escalation_id
      AND escalation.work_item_id = stream.work_item_id
      AND escalation.attempt_id = stream.attempt_id
      AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
      AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
      AND escalation.authority_or_effect_active
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job:' || NEW.workflow_job_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'runmill-observation:' || NEW.observation_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'run:' || NEW.run_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'runmill-control-snapshot:' || NEW.event_page_snapshot_id::text
      )
    FOR SHARE OF checkpoint, stream, result, job, page_snapshot, escalation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill gap escalation binding lacks its exact result, job, page, or shared escalation proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_gap_bindings_exact_proof';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_observation_gap_binding_insert_guard
    BEFORE INSERT ON runmill_observation_gap_escalation_bindings
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_observation_gap_escalation_binding_insert();
CREATE TRIGGER runmill_observation_gap_binding_append_only
    BEFORE UPDATE OR DELETE ON runmill_observation_gap_escalation_bindings
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER runmill_observation_gap_binding_truncate_forbidden
    BEFORE TRUNCATE ON runmill_observation_gap_escalation_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- An ordinary observer job can also reach `DEAD` without ever retaining a
-- remote page: retry exhaustion, route-invalid rejection, or expired/orphan
-- final-attempt recovery.  No `runmill_run_observation_results` row can exist
-- for that observation, so the result-backed release above cannot apply and the
-- stream would stay pinned forever.  This append-only fact is the only other
-- proof that may release the active pointers, and it deliberately carries no
-- snapshot and no next cursor: nothing about the remote run was observed.
CREATE TABLE runmill_observation_terminal_failure_facts (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    after_sequence bigint NOT NULL
        CHECK (after_sequence BETWEEN 0 AND 9007199254740991),
    observation_epoch bigint NOT NULL
        CHECK (observation_epoch BETWEEN 1 AND 9007199254740991),
    failure_digest text NOT NULL
        CHECK (failure_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, observation_id),
    UNIQUE (tenant_id, run_id),
    UNIQUE (tenant_id, workflow_job_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runmill_run_observation_streams (tenant_id, run_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES runmill_run_observation_checkpoints (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs (tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES escalations (tenant_id, id)
        ON DELETE RESTRICT
);

CREATE FUNCTION asf_assert_runmill_observation_terminal_failure_fact_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Every coordinate is re-proved here under lock, so a direct writer cannot
    -- forge a release for a live job, a stale pointer, another checkpoint,
    -- another escalation, a different cursor/epoch, or an unproved digest.
    PERFORM 1
    FROM runmill_run_observation_checkpoints AS checkpoint
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = checkpoint.tenant_id
     AND stream.run_id = checkpoint.run_id
    JOIN workflow_jobs AS job
      ON job.tenant_id = checkpoint.tenant_id
     AND job.id = checkpoint.workflow_job_id
    JOIN escalations AS escalation
      ON escalation.tenant_id = job.tenant_id
     AND escalation.id = job.dead_letter_escalation_id
    WHERE checkpoint.tenant_id = NEW.tenant_id
      AND checkpoint.id = NEW.observation_id
      AND checkpoint.run_id = NEW.run_id
      AND checkpoint.workflow_job_id = NEW.workflow_job_id
      AND checkpoint.after_sequence = NEW.after_sequence
      AND checkpoint.observation_epoch = NEW.observation_epoch
      AND checkpoint.worker_id = stream.worker_id
      AND checkpoint.worker_generation = stream.worker_generation
      AND stream.state = 'ACTIVE'
      AND stream.active_observation_id = NEW.observation_id
      AND stream.active_job_id = NEW.workflow_job_id
      AND stream.next_after_sequence = NEW.after_sequence
      AND stream.observation_epoch = NEW.observation_epoch
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.status = 'DEAD'
      AND job.dead_letter_escalation_id = NEW.escalation_id
      AND job.dead_letter_operational_incident_id IS NULL
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'observation_id' = checkpoint.id::text
      AND job.payload ->> 'run_id' = stream.run_id::text
      AND job.payload ->> 'work_order_id' = stream.work_order_id::text
      AND job.payload ->> 'work_order_digest' = stream.work_order_digest
      AND job.payload ->> 'worker_id' = stream.worker_id::text
      AND job.payload ->> 'worker_session_id' = stream.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(stream.worker_generation)
      AND job.payload ->> 'external_run_id' = stream.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = checkpoint.observer_session_id::text
      -- The digest must come from the job's own durable terminal receipt, not
      -- from the caller.  `fail_workflow_step` writes this result in the same
      -- transaction that made the job DEAD and named its effective escalation.
      AND jsonb_typeof(job.result) = 'object'
      AND job.result ->> 'schema' = 'asf.workflow-job-dead-letter-result/v1'
      AND job.result ->> 'workflow_job_id' = job.id::text
      AND job.result ->> 'job_type' = 'OBSERVE_RUNMILL_RUN'
      AND jsonb_typeof(job.result -> 'error_digest') = 'string'
      AND job.result ->> 'error_digest' = NEW.failure_digest
      AND job.result #>> '{escalation,id}' = NEW.escalation_id::text
      -- Exhaustion escalations are shared by work item, attempt, and category,
      -- so the effective row may legitimately carry a null or foreign run_id.
      -- Never rewrite it; prove ownership through the exact per-job evidence
      -- markers that both a newly opened and an adopted escalation must carry.
      AND escalation.work_item_id = stream.work_item_id
      AND escalation.attempt_id = stream.attempt_id
      AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
      AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
      AND escalation.authority_or_effect_active
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job:' || NEW.workflow_job_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job-type:' || NEW.workflow_job_id::text || ':OBSERVE_RUNMILL_RUN'
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job-error:' || NEW.workflow_job_id::text || ':' || NEW.failure_digest
      )
      -- A retained remote page has its own result-backed release. Two competing
      -- receipts for one observation are always a fail-closed contradiction.
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_run_observation_results AS result
          WHERE result.tenant_id = checkpoint.tenant_id
            AND result.observation_id = checkpoint.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_observation_gap_escalation_bindings AS binding
          WHERE binding.tenant_id = checkpoint.tenant_id
            AND binding.observation_id = checkpoint.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_control_snapshots AS snapshot
          WHERE snapshot.tenant_id = checkpoint.tenant_id
            AND snapshot.observation_id = checkpoint.id
      )
    FOR SHARE OF checkpoint, stream, job, escalation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation terminal-failure fact lacks its exact active stream, dead V2 job, owned escalation, or durable failure digest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_terminal_failure_facts_exact_proof';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_observation_terminal_failure_fact_insert_guard
    BEFORE INSERT ON runmill_observation_terminal_failure_facts
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_observation_terminal_failure_fact_insert();
CREATE TRIGGER runmill_observation_terminal_failure_fact_append_only
    BEFORE UPDATE OR DELETE ON runmill_observation_terminal_failure_facts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER runmill_observation_terminal_failure_fact_truncate_forbidden
    BEFORE TRUNCATE ON runmill_observation_terminal_failure_facts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

COMMENT ON TABLE runmill_observation_terminal_failure_facts IS
    'Append-only proof that one active observation checkpoint ended as an owned WORKFLOW_JOB_EXHAUSTED dead job with no retained remote page. It releases the stream into ESCALATED only, never advances a cursor, and never substitutes for an observation result.';

CREATE FUNCTION asf_assert_runmill_observation_checkpoint_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The producer inserts the immutable job and checkpoint first, then
    -- advances the stream epoch and installs both active pointers in the same
    -- transaction.  Therefore the checkpoint must be exactly one epoch ahead
    -- of an idle stream at the same cursor; it can never be forged for an
    -- already-owned stream.
    PERFORM 1
    FROM runmill_run_observation_streams AS stream
    JOIN workflow_jobs AS job
      ON job.tenant_id = stream.tenant_id
     AND job.id = NEW.workflow_job_id
    JOIN runs AS run
      ON run.tenant_id = stream.tenant_id
     AND run.id = stream.run_id
     AND run.work_item_id = stream.work_item_id
     AND run.attempt_id = stream.attempt_id
     AND run.work_order_id = stream.work_order_id
     AND run.worker_id = stream.worker_id
     AND run.worker_generation = stream.worker_generation
     AND run.worker_session_id = stream.run_admission_worker_session_id
     AND run.external_run_id = stream.external_run_id
     AND run.authoritative
    JOIN work_orders AS work_order
      ON work_order.tenant_id = stream.tenant_id
     AND work_order.id = stream.work_order_id
     AND work_order.work_item_id = stream.work_item_id
     AND work_order.attempt_id = stream.attempt_id
     AND work_order.payload_digest = stream.work_order_digest
    JOIN attempts AS attempt
      ON attempt.tenant_id = stream.tenant_id
     AND attempt.id = stream.attempt_id
     AND attempt.work_item_id = stream.work_item_id
     AND attempt.work_order_digest = stream.work_order_digest
    JOIN work_items AS work
      ON work.tenant_id = stream.tenant_id
     AND work.id = stream.work_item_id
     AND work.current_attempt_id = stream.attempt_id
     AND work.accepted_at IS NOT NULL
     AND work.state NOT IN ('CLOSED', 'CANCELLED')
    JOIN workflow_instances AS workflow
      ON workflow.tenant_id = stream.tenant_id
     AND workflow.id = stream.workflow_instance_id
     AND workflow.work_item_id = stream.work_item_id
     AND workflow.state IN ('ACTIVE', 'WAITING')
    JOIN worker_sessions AS observer_session
      ON observer_session.tenant_id = stream.tenant_id
     AND observer_session.id = NEW.observer_session_id
     AND observer_session.worker_id = NEW.worker_id
     AND observer_session.worker_generation = NEW.worker_generation
    JOIN workers AS worker
      ON worker.tenant_id = observer_session.tenant_id
     AND worker.id = observer_session.worker_id
    WHERE stream.tenant_id = NEW.tenant_id
      AND stream.run_id = NEW.run_id
      AND stream.state = 'ACTIVE'
      AND stream.active_job_id IS NULL
      AND stream.active_observation_id IS NULL
      AND stream.next_after_sequence = NEW.after_sequence
      AND stream.observation_epoch + 1 = NEW.observation_epoch
      AND NEW.worker_id = stream.worker_id
      AND NEW.worker_generation = stream.worker_generation
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.status = 'PENDING'
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'observation_id' = NEW.id::text
      AND job.payload ->> 'run_id' = stream.run_id::text
      AND job.payload ->> 'work_order_id' = stream.work_order_id::text
      AND job.payload ->> 'work_order_digest' = stream.work_order_digest
      AND job.payload ->> 'worker_id' = stream.worker_id::text
      AND job.payload ->> 'worker_session_id' = stream.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(stream.worker_generation)
      AND job.payload ->> 'external_run_id' = stream.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = NEW.observer_session_id::text
      AND observer_session.status = 'ACTIVE'
      AND observer_session.expires_at > clock_timestamp()
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
    FOR UPDATE OF stream, job, run, work_order, attempt, work, workflow, observer_session, worker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation checkpoint lacks the exact idle stream, pending V2 job, and live current observer session'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_checkpoints_exact_schedule';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION asf_guard_runmill_observation_checkpoint() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Runmill observation checkpoints are append-only immutable facts'
            USING ERRCODE = '55000';
    END IF;
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'Runmill observation checkpoints are append-only immutable facts'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_observation_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON runmill_run_observation_checkpoints
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_observation_checkpoint();
CREATE TRIGGER runmill_observation_checkpoint_insert_guard
    BEFORE INSERT ON runmill_run_observation_checkpoints
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_observation_checkpoint_insert();
CREATE TRIGGER runmill_observation_checkpoint_truncate_forbidden
    BEFORE TRUNCATE ON runmill_run_observation_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

ALTER TABLE runmill_run_observation_streams
    ADD CONSTRAINT runmill_observation_stream_active_checkpoint_fk
        FOREIGN KEY (tenant_id, active_observation_id)
        REFERENCES runmill_run_observation_checkpoints (tenant_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT runmill_observation_stream_escalation_fk
        FOREIGN KEY (tenant_id, escalation_id, work_item_id)
        REFERENCES escalations (tenant_id, id, work_item_id)
        ON DELETE RESTRICT;

CREATE INDEX runmill_run_observation_streams_due_idx
    ON runmill_run_observation_streams (tenant_id, worker_id, next_poll_at, run_id)
    WHERE state = 'ACTIVE' AND active_job_id IS NULL;

COMMENT ON TABLE runmill_run_observation_streams IS
    'One durable cursor/reconciliation stream per authoritative Runmill run. Historical migration-0021 observations are intentionally not inferred into this table.';
COMMENT ON COLUMN runmill_run_observation_streams.run_admission_worker_session_id IS
    'Immutable session that admitted the run; distinct from the live observer-control session carried by each observation job and snapshot.';
COMMENT ON COLUMN runmill_run_observation_streams.active_job_id IS
    'At most one PENDING/RUNNING/RETRY observer job may advance this stream. It is cleared atomically with cursor advancement and job completion.';
COMMENT ON TABLE runmill_run_observation_checkpoints IS
    'Append-only V2 observation schedule checkpoints binding one observer job to one immutable cursor, epoch, and current observer session.';

CREATE FUNCTION asf_assert_runmill_observation_stream_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.active_job_id IS NOT NULL
       OR NEW.state <> 'ACTIVE'
       OR NEW.next_after_sequence <> 0
       OR NEW.observation_epoch <> 0
       OR NEW.last_snapshot_id IS NOT NULL
       OR NEW.active_observation_id IS NOT NULL
       OR NEW.escalation_id IS NOT NULL
       OR NEW.last_error_digest IS NOT NULL
    THEN
        RAISE EXCEPTION 'a new Runmill observation stream must start active, cursor zero, and without a job or retained result'
            USING ERRCODE = '23514';
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
    JOIN work_items AS work
      ON work.tenant_id = run.tenant_id
     AND work.id = run.work_item_id
    JOIN workflow_instances AS workflow
      ON workflow.tenant_id = run.tenant_id
     AND workflow.id = NEW.workflow_instance_id
     AND workflow.work_item_id = run.work_item_id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.worker_session_id = NEW.run_admission_worker_session_id
      AND run.external_run_id = NEW.external_run_id
      AND run.authoritative
      AND work_order.payload_digest = NEW.work_order_digest
      AND attempt.work_order_digest = NEW.work_order_digest
      AND work.current_attempt_id = NEW.attempt_id
      AND work.accepted_at IS NOT NULL
      AND work.state NOT IN ('CLOSED', 'CANCELLED')
      AND workflow.state IN ('ACTIVE', 'WAITING')
    FOR SHARE OF run, work_order, attempt, work, workflow;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation stream lacks an exact live authoritative run, Work Order, attempt, work, and workflow binding'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_streams_exact_authority';
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION asf_guard_runmill_observation_stream() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    active_job workflow_jobs%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Runmill observation streams cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.tenant_id, NEW.run_id, NEW.workflow_instance_id, NEW.work_item_id,
        NEW.attempt_id, NEW.work_order_id, NEW.work_order_digest, NEW.worker_id,
        NEW.worker_generation, NEW.run_admission_worker_session_id,
        NEW.external_run_id, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.tenant_id, OLD.run_id, OLD.workflow_instance_id, OLD.work_item_id,
        OLD.attempt_id, OLD.work_order_id, OLD.work_order_digest, OLD.worker_id,
        OLD.worker_generation, OLD.run_admission_worker_session_id,
        OLD.external_run_id, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'Runmill observation stream identity and authority binding are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.next_after_sequence < OLD.next_after_sequence
       OR NEW.observation_epoch < OLD.observation_epoch
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
    THEN
        RAISE EXCEPTION 'Runmill observation stream cursor, epoch, or version moved backwards or skipped its fenced transition'
            USING ERRCODE = '40001';
    END IF;

    IF OLD.state <> 'ACTIVE' AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION 'blocked, terminal-ready, or escalated observation streams cannot be reopened implicitly'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.state <> 'ACTIVE' AND NEW.active_job_id IS NOT NULL THEN
        RAISE EXCEPTION 'only an active Runmill observation stream may retain a live observer job'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.escalation_id IS NOT NULL THEN
        PERFORM 1
        FROM escalations AS escalation
        WHERE escalation.tenant_id = NEW.tenant_id
          AND escalation.id = NEW.escalation_id
          AND escalation.work_item_id = NEW.work_item_id
          AND escalation.attempt_id = NEW.attempt_id
          AND (
              escalation.run_id = NEW.run_id
              OR (
                  NEW.state = 'ESCALATED'
                  AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
                  AND EXISTS (
                      SELECT 1
                      FROM runmill_observation_gap_escalation_bindings AS binding
                      WHERE binding.tenant_id = NEW.tenant_id
                        AND binding.run_id = NEW.run_id
                        AND binding.observation_id = OLD.active_observation_id
                        AND binding.workflow_job_id = OLD.active_job_id
                        AND binding.escalation_id = NEW.escalation_id
                        AND binding.event_page_snapshot_id = NEW.last_snapshot_id
                  )
              )
              OR (
                  -- Ordinary terminal observer failure: no page was retained,
                  -- so the shared escalation is bound through the append-only
                  -- terminal-failure fact instead of a run_id rewrite.
                  NEW.state = 'ESCALATED'
                  AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
                  AND EXISTS (
                      SELECT 1
                      FROM runmill_observation_terminal_failure_facts AS fact
                      WHERE fact.tenant_id = NEW.tenant_id
                        AND fact.run_id = NEW.run_id
                        AND fact.observation_id = OLD.active_observation_id
                        AND fact.workflow_job_id = OLD.active_job_id
                        AND fact.escalation_id = NEW.escalation_id
                        AND fact.after_sequence = NEW.next_after_sequence
                        AND fact.observation_epoch = NEW.observation_epoch
                        AND fact.failure_digest = NEW.last_error_digest
                  )
              )
          )
          AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
          AND escalation.authority_or_effect_active
          AND (
              (NEW.state = 'BLOCKED_GAP' AND escalation.category = 'BLOCKED_EXTERNAL')
              OR (NEW.state = 'BLOCKED_PROJECTION' AND escalation.category = 'QUARANTINED')
              OR (NEW.state = 'ESCALATED' AND escalation.category IN (
                  'BLOCKED_EXTERNAL', 'QUARANTINED', 'WORKFLOW_JOB_EXHAUSTED'
              ))
          )
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Runmill observation stream escalation is not an exact open owned reconciliation escalation'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_observation_streams_exact_escalation';
        END IF;
    END IF;

    -- A stream can release an active observation only by consuming its one
    -- immutable completion fact.  This prevents a crash-recovery or operator
    -- update from advancing (or silently discarding) a cursor without the
    -- exact get/page evidence that explains the transition.
    IF OLD.active_observation_id IS NOT NULL
       AND NEW.active_observation_id IS NULL THEN
        PERFORM 1
        FROM runmill_run_observation_results AS result
        WHERE result.tenant_id = NEW.tenant_id
          AND result.run_id = NEW.run_id
          AND result.observation_id = OLD.active_observation_id
          AND result.after_sequence = OLD.next_after_sequence
          AND result.event_page_snapshot_id = NEW.last_snapshot_id
          AND (
              (
                  result.disposition = 'ADVANCED'
                  AND NEW.state = 'ACTIVE'
                  AND NEW.next_after_sequence = result.next_sequence
                  AND NEW.escalation_id IS NULL
              )
              OR (
                  result.disposition = 'TERMINAL_READY'
                  AND NEW.state = 'TERMINAL_READY'
                  AND NEW.next_after_sequence = result.next_sequence
                  AND NEW.escalation_id IS NULL
              )
              OR (
                  result.disposition = 'BLOCKED_GAP'
                  -- A compaction gap is a forced external escalation in the
                  -- runtime path.  Keep the immutable result disposition
                  -- specific to the observed gap while permitting the stream
                  -- to retain the resulting forced ESCALATED state.
                  AND NEW.state IN ('BLOCKED_GAP', 'ESCALATED')
                  AND NEW.next_after_sequence = OLD.next_after_sequence
              )
              OR (
                  result.disposition = 'BLOCKED_PROJECTION'
                  AND NEW.state = 'BLOCKED_PROJECTION'
                  AND NEW.next_after_sequence = OLD.next_after_sequence
              )
          )
        FOR SHARE;
        IF NOT FOUND THEN
            -- The only other legal release is an owned terminal observer
            -- failure that retained no remote page.  It may move the stream to
            -- ESCALATED alone, must not move the cursor or epoch, must not
            -- invent a snapshot, and must carry the exact effective escalation
            -- and durable failure digest recorded by the immutable fact.
            PERFORM 1
            FROM runmill_observation_terminal_failure_facts AS fact
            WHERE fact.tenant_id = NEW.tenant_id
              AND fact.run_id = NEW.run_id
              AND fact.observation_id = OLD.active_observation_id
              AND fact.workflow_job_id = OLD.active_job_id
              AND fact.after_sequence = OLD.next_after_sequence
              AND fact.observation_epoch = OLD.observation_epoch
              AND NEW.state = 'ESCALATED'
              AND NEW.active_job_id IS NULL
              AND NEW.next_after_sequence = OLD.next_after_sequence
              AND NEW.observation_epoch = OLD.observation_epoch
              AND NEW.last_snapshot_id IS NOT DISTINCT FROM OLD.last_snapshot_id
              AND NEW.escalation_id = fact.escalation_id
              AND NEW.last_error_digest = fact.failure_digest
            FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Runmill observation stream release lacks the exact immutable completion checkpoint'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runmill_observation_streams_exact_result';
            END IF;
        END IF;
    END IF;

    IF NEW.active_job_id IS NOT NULL THEN
        SELECT job.* INTO active_job
        FROM workflow_jobs AS job
        JOIN runmill_run_observation_checkpoints AS checkpoint
          ON checkpoint.tenant_id = job.tenant_id
         AND checkpoint.workflow_job_id = job.id
         AND checkpoint.id = NEW.active_observation_id
         AND checkpoint.run_id = NEW.run_id
         AND checkpoint.after_sequence = NEW.next_after_sequence
         AND checkpoint.observation_epoch = NEW.observation_epoch
        JOIN worker_sessions AS observer_session
          ON observer_session.tenant_id = job.tenant_id
         AND observer_session.id = checkpoint.observer_session_id
         AND observer_session.worker_id = NEW.worker_id
         AND observer_session.worker_generation = NEW.worker_generation
        JOIN workers AS worker
          ON worker.tenant_id = observer_session.tenant_id
         AND worker.id = observer_session.worker_id
        WHERE job.tenant_id = NEW.tenant_id
          AND job.id = NEW.active_job_id
          AND job.workflow_instance_id = NEW.workflow_instance_id
          AND job.work_item_id = NEW.work_item_id
          AND job.attempt_id = NEW.attempt_id
          AND job.job_type = 'OBSERVE_RUNMILL_RUN'
          AND job.status IN ('PENDING', 'RUNNING', 'RETRY')
          AND jsonb_typeof(job.payload) = 'object'
          AND job.payload ?& ARRAY[
              'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
              'worker_session_id', 'worker_generation', 'external_run_id',
              'after_sequence', 'observation_epoch', 'observer_session_id'
          ]
          AND job.payload - ARRAY[
              'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
              'worker_session_id', 'worker_generation', 'external_run_id',
              'after_sequence', 'observation_epoch', 'observer_session_id'
          ] = '{}'::jsonb
          AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
          AND job.payload ->> 'observation_id' = checkpoint.id::text
          AND jsonb_typeof(job.payload -> 'run_id') = 'string'
          AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
          AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
          AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
          AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
          AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
          AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
          AND job.payload ->> 'run_id' = NEW.run_id::text
          AND job.payload ->> 'work_order_id' = NEW.work_order_id::text
          AND job.payload ->> 'work_order_digest' = NEW.work_order_digest
          AND job.payload ->> 'worker_id' = NEW.worker_id::text
          AND job.payload ->> 'worker_session_id' = NEW.run_admission_worker_session_id::text
          AND job.payload -> 'worker_generation' = to_jsonb(NEW.worker_generation)
          AND job.payload ->> 'external_run_id' = NEW.external_run_id
          AND job.payload -> 'after_sequence' = to_jsonb(NEW.next_after_sequence)
          AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
          AND job.payload ->> 'observer_session_id' = checkpoint.observer_session_id::text
          AND observer_session.status = 'ACTIVE'
          AND observer_session.expires_at > clock_timestamp()
          AND worker.generation = NEW.worker_generation
          AND worker.status <> 'QUARANTINED'
        FOR SHARE OF job, observer_session, worker;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Runmill observation stream active job lacks its exact cursor, epoch, worker, or current observer-session authority'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_observation_streams_exact_active_job';
        END IF;
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_observation_stream_insert_guard
    BEFORE INSERT ON runmill_run_observation_streams
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_observation_stream_insert();
CREATE TRIGGER runmill_observation_stream_mutation_guard
    BEFORE UPDATE OR DELETE ON runmill_run_observation_streams
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_observation_stream();
CREATE TRIGGER runmill_observation_stream_truncate_forbidden
    BEFORE TRUNCATE ON runmill_run_observation_streams
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Preserve migration-0021 history while splitting its overloaded session
-- coordinate.  The pre-0022 `worker_session_id` remains the immutable run
-- admission session for compatibility; a new observer-session column records
-- the currently-live control identity that actually performed each read.
ALTER TABLE runmill_control_snapshots
    ADD COLUMN run_admission_worker_session_id uuid,
    ADD COLUMN observer_session_id uuid,
    ADD COLUMN observation_id uuid,
    ADD COLUMN requested_after_sequence bigint,
    ADD COLUMN observation_epoch bigint;

UPDATE runmill_control_snapshots
SET run_admission_worker_session_id = worker_session_id,
    observer_session_id = worker_session_id,
    requested_after_sequence = 0,
    observation_epoch = 0
WHERE run_admission_worker_session_id IS NULL
   OR observer_session_id IS NULL
   OR requested_after_sequence IS NULL
   OR observation_epoch IS NULL;

ALTER TABLE runmill_control_snapshots
    ALTER COLUMN run_admission_worker_session_id SET NOT NULL,
    ALTER COLUMN observer_session_id SET NOT NULL,
    ALTER COLUMN requested_after_sequence SET NOT NULL,
    ALTER COLUMN observation_epoch SET NOT NULL,
    ADD CONSTRAINT runmill_control_snapshots_legacy_admission_session_check
        CHECK (worker_session_id = run_admission_worker_session_id),
    ADD CONSTRAINT runmill_control_snapshots_requested_after_range
        CHECK (requested_after_sequence BETWEEN 0 AND 9007199254740991),
    ADD CONSTRAINT runmill_control_snapshots_observation_epoch_range
        CHECK (observation_epoch BETWEEN 0 AND 9007199254740991),
    ADD CONSTRAINT runmill_control_snapshots_observation_id_shape
        CHECK (
            (observation_epoch = 0 AND observation_id IS NULL)
            OR (observation_epoch > 0 AND observation_id IS NOT NULL)
        ),
    ADD CONSTRAINT runmill_control_snapshots_run_admission_session_fk
        FOREIGN KEY (
            tenant_id, run_admission_worker_session_id, worker_id, worker_generation
        ) REFERENCES worker_sessions (tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    ADD CONSTRAINT runmill_control_snapshots_observer_session_fk
        FOREIGN KEY (
            tenant_id, observer_session_id, worker_id, worker_generation
        ) REFERENCES worker_sessions (tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    ADD CONSTRAINT runmill_control_snapshots_checkpoint_fk
        FOREIGN KEY (tenant_id, observation_id)
        REFERENCES runmill_run_observation_checkpoints (tenant_id, id)
        ON DELETE RESTRICT;

ALTER TABLE runmill_run_observation_streams
    ADD CONSTRAINT runmill_observation_stream_last_snapshot_fk
        FOREIGN KEY (tenant_id, last_snapshot_id)
        REFERENCES runmill_control_snapshots (tenant_id, id)
        ON DELETE RESTRICT;

CREATE INDEX runmill_control_snapshots_stream_cursor_idx
    ON runmill_control_snapshots (
        tenant_id, run_id, observation_epoch, requested_after_sequence, recorded_at, id
    );

-- The terminal-failure guard must cheaply prove that one checkpoint retained
-- no remote page at all before it may release a stream.
CREATE INDEX runmill_control_snapshots_observation_idx
    ON runmill_control_snapshots (tenant_id, observation_id);

COMMENT ON COLUMN runmill_control_snapshots.run_admission_worker_session_id IS
    'Immutable session bound to runs.worker_session_id when Runmill admitted the Work Order.';
COMMENT ON COLUMN runmill_control_snapshots.observer_session_id IS
    'Current active controller session that performed this observation; it may differ from the historic run-admission session after a restart.';

-- Replace the migration-0021 authority trigger.  It retains every exact-wire,
-- canonical, admission, event-page, and append-only proof from 0021 while
-- additionally requiring the stream's exact cursor/epoch and a live current
-- observer session.  Historical rows need no stream because this trigger is
-- only evaluated on new INSERTs.
CREATE OR REPLACE FUNCTION asf_stamp_runmill_control_snapshot() RETURNS trigger
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

    -- `worker_session_id` is retained as a compatibility alias for the
    -- immutable admission session.  Never allow a new row to smuggle a
    -- current observer session into that historical coordinate.
    IF NEW.worker_session_id IS DISTINCT FROM NEW.run_admission_worker_session_id
       OR NEW.observation_epoch <= 0
       OR NEW.observation_id IS NULL
       OR NEW.requested_after_sequence > NEW.external_latest_sequence THEN
        RAISE EXCEPTION 'Runmill control snapshot has an invalid admission session, epoch, or requested cursor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_stream_cursor';
    END IF;

    PERFORM 1
    FROM workflow_jobs AS job
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = job.tenant_id
     AND stream.run_id = NEW.run_id
    JOIN runmill_run_observation_checkpoints AS checkpoint
      ON checkpoint.tenant_id = stream.tenant_id
     AND checkpoint.id = NEW.observation_id
     AND checkpoint.run_id = stream.run_id
     AND checkpoint.workflow_job_id = job.id
     AND checkpoint.after_sequence = NEW.requested_after_sequence
     AND checkpoint.observation_epoch = NEW.observation_epoch
     AND checkpoint.observer_session_id = NEW.observer_session_id
    WHERE job.tenant_id = NEW.tenant_id
      AND job.id = NEW.workflow_job_id
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = NEW.work_item_id
      AND job.attempt_id = NEW.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.status = 'RUNNING'
      AND job.fence_token = NEW.workflow_job_fence_token
      AND job.attempt_count = NEW.workflow_job_attempt_count
      AND job.lease_owner = NEW.workflow_job_owner
      AND job.lease_expires_at > clock_timestamp()
      AND stream.workflow_instance_id = job.workflow_instance_id
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.work_order_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.run_admission_worker_session_id
      AND stream.external_run_id = NEW.external_run_id
      AND stream.state = 'ACTIVE'
      AND stream.active_job_id = job.id
      AND stream.active_observation_id = checkpoint.id
      AND stream.next_after_sequence = NEW.requested_after_sequence
      AND stream.observation_epoch = NEW.observation_epoch
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND job.payload ->> 'observation_id' = checkpoint.id::text
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'run_id' = NEW.run_id::text
      AND job.payload ->> 'work_order_id' = NEW.work_order_id::text
      AND job.payload ->> 'work_order_digest' = NEW.work_order_digest
      AND job.payload ->> 'worker_id' = NEW.worker_id::text
      AND job.payload ->> 'worker_session_id' = NEW.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(NEW.worker_generation)
      AND job.payload ->> 'external_run_id' = NEW.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.requested_after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = NEW.observer_session_id::text
    FOR UPDATE OF job, stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot lacks its exact live observation stream claim'
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
            OR NEW.raw_snapshot #>> '{snapshot,run,runId}' IS DISTINCT FROM NEW.external_run_id
            OR NEW.raw_snapshot #>> '{snapshot,run,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,generation}' IS DISTINCT FROM NEW.external_generation::text
            OR NEW.raw_snapshot #>> '{snapshot,run,stateVersion}' IS DISTINCT FROM NEW.external_state_version::text
            OR NEW.raw_snapshot #>> '{snapshot,latestSequence}' IS DISTINCT FROM NEW.external_latest_sequence::text
            OR jsonb_typeof(NEW.raw_snapshot -> 'nextCursor') IS DISTINCT FROM 'number'
            OR (NEW.raw_snapshot ->> 'nextCursor')::bigint < NEW.requested_after_sequence
            OR (NEW.raw_snapshot ->> 'nextCursor')::bigint > NEW.external_latest_sequence
        )
    ) THEN
        RAISE EXCEPTION 'Runmill control snapshot indexed provenance contradicts raw JSON or its requested cursor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_raw_json_binding';
    END IF;

    -- The control session must be current.  The run-admission session above is
    -- immutable historic provenance and is intentionally not required to be
    -- live: requiring it prevented restart/reconnect observation.
    PERFORM 1
    FROM workers AS worker
    JOIN worker_sessions AS observer_session
      ON observer_session.tenant_id = worker.tenant_id
     AND observer_session.worker_id = worker.id
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
      AND observer_session.id = NEW.observer_session_id
      AND observer_session.worker_generation = NEW.worker_generation
      AND observer_session.status = 'ACTIVE'
      AND observer_session.expires_at > clock_timestamp()
    FOR SHARE OF worker, observer_session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot has a stale, closed, or expired current observer session generation'
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
      AND run.worker_session_id = NEW.run_admission_worker_session_id
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

-- Existing append-only triggers remain installed.  They protect both the
-- historical backfilled rows and all stream-bound future provenance.
COMMENT ON FUNCTION asf_stamp_runmill_control_snapshot() IS
    'Requires an exact stream cursor/epoch, immutable run admission provenance, and a separately-live observer control session for new Runmill observations.';
