-- Runmill submission recovery adoptions record the durable fact that a
-- PENDING_EXTERNAL_LOOKUP recovery case (migration 0026) was resolved by an
-- exact `asf.runmill-lookup-qualified-submission-receipt.v1` receipt showing
-- the submission reached Runmill, and that ASF has adopted the run it names.
--
-- An adoption is append-only: it never resends, retries, or streams the
-- submission. Its authority is proved twice: once here on INSERT against the
-- exact pending case, ambiguous effect, and immutable work order, and once
-- more at commit time by a deferred constraint trigger against the exact
-- authoritative `runs` row and `runmill_run_observation_streams` row that the
-- same transaction must have created for this recovered run.
--
-- Apply with executors quiesced, matching migration 0026: the table lock
-- preserves the global effect -> recovery case -> adoption ordering used by
-- recovery reconciliation.
LOCK TABLE runmill_submission_recovery_cases IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_streams IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE runmill_submission_recovery_adoptions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    recovery_case_id uuid NOT NULL,
    effect_intent_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    work_order_id uuid NOT NULL,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    remote_idempotency_key text NOT NULL CHECK (btrim(remote_idempotency_key) <> ''),
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    worker_session_id uuid NOT NULL,
    local_run_id uuid NOT NULL,
    external_run_id text NOT NULL CHECK (btrim(external_run_id) <> ''),
    run_state text NOT NULL DEFAULT 'ADOPTED' CHECK (run_state = 'ADOPTED'),
    run_state_version bigint NOT NULL CHECK (run_state_version > 0),
    latest_sequence bigint NOT NULL CHECK (latest_sequence >= 0),
    lookup_request_schema text NOT NULL
        CHECK (lookup_request_schema = 'asf.runmill-lookup-qualified-submission-request.v1'),
    lookup_receipt_schema text NOT NULL
        CHECK (lookup_receipt_schema = 'asf.runmill-lookup-qualified-submission-receipt.v1'),
    lookup_receipt jsonb NOT NULL CHECK (jsonb_typeof(lookup_receipt) = 'object'),
    lookup_receipt_digest text NOT NULL CHECK (lookup_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    adopted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, recovery_case_id),
    UNIQUE (tenant_id, effect_intent_id),
    UNIQUE (tenant_id, local_run_id),
    FOREIGN KEY (tenant_id, recovery_case_id)
        REFERENCES runmill_submission_recovery_cases(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, effect_intent_id)
        REFERENCES effect_intents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
        REFERENCES attempts(tenant_id, id, work_item_id)
        MATCH SIMPLE ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_order_id, payload_digest, work_item_id, attempt_id)
        REFERENCES work_orders(tenant_id, id, payload_digest, work_item_id, attempt_id)
        MATCH SIMPLE ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_id)
        REFERENCES workers(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_session_id, worker_id, worker_generation)
        REFERENCES worker_sessions(tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, local_run_id)
        REFERENCES runs(tenant_id, id)
        DEFERRABLE INITIALLY DEFERRED
);

COMMENT ON TABLE runmill_submission_recovery_adoptions IS
    'Append-only proof that a PENDING_EXTERNAL_LOOKUP recovery case (0026) was resolved by an exact found qualified-submission receipt and the named run adopted. Never resent, retried, or streamed by this fact alone.';
COMMENT ON COLUMN runmill_submission_recovery_adoptions.local_run_id IS
    'The ASF-generated uuid of the newly adopted runs row. Not present anywhere in the external Runmill receipt.';
COMMENT ON COLUMN runmill_submission_recovery_adoptions.external_run_id IS
    'Runmill''s own run identifier, exactly the receipt outcome.run.run_id string. Distinct from local_run_id.';
COMMENT ON COLUMN runmill_submission_recovery_adoptions.lookup_receipt IS
    'The exact asf.runmill-lookup-qualified-submission-receipt.v1 envelope proving the submission reached Runmill.';

CREATE INDEX runmill_submission_recovery_adoptions_work_order_idx
    ON runmill_submission_recovery_adoptions (tenant_id, work_order_id);

CREATE INDEX runmill_submission_recovery_adoptions_worker_session_idx
    ON runmill_submission_recovery_adoptions (tenant_id, worker_session_id, id);

CREATE INDEX runmill_submission_recovery_adoptions_external_run_idx
    ON runmill_submission_recovery_adoptions (tenant_id, external_run_id);

-- Before-insert validation: the adoption must name an exact pending recovery
-- case whose linked effect is an AMBIGUOUS runmill submit_work_order, whose
-- linked work order and admission session match exactly, and no authoritative
-- run may already own the attempt. The lookup receipt is validated strictly
-- against the current Rust serde shape of LookupQualifiedSubmissionReceipt.
CREATE FUNCTION asf_assert_runmill_submission_recovery_adoption_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    outcome jsonb;
    qualification jsonb;
    run_obj jsonb;
    admission_worker jsonb;
BEGIN
    PERFORM 1
    FROM runmill_submission_recovery_cases AS recovery_case
    JOIN effect_intents AS effect
      ON effect.tenant_id = recovery_case.tenant_id
     AND effect.id = recovery_case.effect_intent_id
    JOIN work_orders AS work_order
      ON work_order.tenant_id = recovery_case.tenant_id
     AND work_order.id = recovery_case.work_order_id
     AND work_order.payload_digest = recovery_case.payload_digest
    JOIN worker_sessions AS admission_session
      ON admission_session.tenant_id = recovery_case.tenant_id
     AND admission_session.id = recovery_case.worker_session_id
     AND admission_session.worker_id = recovery_case.worker_id
     AND admission_session.worker_generation = recovery_case.worker_generation
    WHERE recovery_case.tenant_id = NEW.tenant_id
      AND recovery_case.id = NEW.recovery_case_id
      AND recovery_case.state = 'PENDING_EXTERNAL_LOOKUP'
      AND recovery_case.effect_intent_id = NEW.effect_intent_id
      AND recovery_case.work_item_id = NEW.work_item_id
      AND recovery_case.attempt_id = NEW.attempt_id
      AND recovery_case.work_order_id = NEW.work_order_id
      AND recovery_case.payload_digest = NEW.payload_digest
      AND recovery_case.request_digest = NEW.request_digest
      AND recovery_case.remote_idempotency_key = NEW.remote_idempotency_key
      AND recovery_case.worker_id = NEW.worker_id
      AND recovery_case.worker_generation = NEW.worker_generation
      AND recovery_case.worker_session_id = NEW.worker_session_id
      AND effect.status = 'AMBIGUOUS'
      AND effect.provider = 'runmill'
      AND effect.effect_type = 'submit_work_order'
      AND effect.work_item_id = NEW.work_item_id
      AND effect.attempt_id = NEW.attempt_id
      AND effect.work_order_id = NEW.work_order_id
      AND effect.work_order_digest = NEW.payload_digest
      AND effect.request_digest = NEW.request_digest
      AND work_order.work_item_id = NEW.work_item_id
      AND work_order.attempt_id = NEW.attempt_id
      AND work_order.idempotency_key = NEW.remote_idempotency_key
    FOR SHARE OF recovery_case, effect, work_order, admission_session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact pending recovery case, ambiguous Runmill submission effect, and immutable work order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_case';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM runs AS existing_run
        WHERE existing_run.tenant_id = NEW.tenant_id
          AND existing_run.attempt_id = NEW.attempt_id
          AND existing_run.authoritative
    ) THEN
        RAISE EXCEPTION 'attempt already has an authoritative run; recovery adoption is not permitted'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_no_existing_authoritative_run';
    END IF;

    IF jsonb_typeof(NEW.lookup_receipt) <> 'object'
       OR NOT (NEW.lookup_receipt ?& ARRAY['schema', 'outcome'])
       OR NEW.lookup_receipt - ARRAY['schema', 'outcome'] <> '{}'::jsonb
       OR jsonb_typeof(NEW.lookup_receipt -> 'schema') <> 'string'
       OR NEW.lookup_receipt ->> 'schema' <> NEW.lookup_receipt_schema
       OR NEW.lookup_receipt ->> 'schema' <> 'asf.runmill-lookup-qualified-submission-receipt.v1'
       OR jsonb_typeof(NEW.lookup_receipt -> 'outcome') <> 'object'
    THEN
        RAISE EXCEPTION 'lookup receipt does not match the exact asf.runmill-lookup-qualified-submission-receipt.v1 envelope shape'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_receipt_envelope';
    END IF;

    outcome := NEW.lookup_receipt -> 'outcome';
    IF NOT (outcome ?& ARRAY['kind', 'qualification', 'run', 'admission_worker'])
       OR outcome - ARRAY['kind', 'qualification', 'run', 'admission_worker'] <> '{}'::jsonb
       OR jsonb_typeof(outcome -> 'kind') <> 'string'
       OR outcome ->> 'kind' <> 'found'
       OR jsonb_typeof(outcome -> 'qualification') <> 'object'
       OR jsonb_typeof(outcome -> 'run') <> 'object'
       OR jsonb_typeof(outcome -> 'admission_worker') <> 'object'
    THEN
        RAISE EXCEPTION 'lookup receipt outcome is not an exact found qualified submission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_receipt_outcome';
    END IF;

    qualification := outcome -> 'qualification';
    IF NOT (qualification ?& ARRAY[
                'tenant_id', 'work_order_id', 'work_item_id', 'attempt_id',
                'idempotency_key', 'work_order_digest', 'request_digest'
            ])
       OR qualification - ARRAY[
                'tenant_id', 'work_order_id', 'work_item_id', 'attempt_id',
                'idempotency_key', 'work_order_digest', 'request_digest'
            ] <> '{}'::jsonb
       OR jsonb_typeof(qualification -> 'tenant_id') <> 'string'
       OR jsonb_typeof(qualification -> 'work_order_id') <> 'string'
       OR jsonb_typeof(qualification -> 'work_item_id') <> 'string'
       OR jsonb_typeof(qualification -> 'attempt_id') <> 'string'
       OR jsonb_typeof(qualification -> 'idempotency_key') <> 'string'
       OR jsonb_typeof(qualification -> 'work_order_digest') <> 'string'
       OR jsonb_typeof(qualification -> 'request_digest') <> 'string'
       OR qualification ->> 'tenant_id' <> NEW.tenant_id::text
       OR qualification ->> 'work_order_id' <> NEW.work_order_id::text
       OR qualification ->> 'work_item_id' <> NEW.work_item_id::text
       OR qualification ->> 'attempt_id' <> NEW.attempt_id::text
       OR qualification ->> 'idempotency_key' <> NEW.remote_idempotency_key
       OR qualification ->> 'work_order_digest' <> NEW.payload_digest
       OR qualification ->> 'request_digest' <> NEW.request_digest
    THEN
        RAISE EXCEPTION 'lookup receipt qualification does not match the adoption exact submission identity'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_receipt_qualification';
    END IF;

    run_obj := outcome -> 'run';
    IF NOT (run_obj ?& ARRAY[
                'schema', 'run_id', 'attempt_id', 'idempotency_key', 'work_order_digest',
                'worker_id', 'worker_generation', 'state', 'aggregate_version',
                'last_event_cursor', 'evidence_digest', 'outcome_acknowledged',
                'accepted_at', 'updated_at'
            ])
       OR run_obj - ARRAY[
                'schema', 'run_id', 'attempt_id', 'idempotency_key', 'work_order_digest',
                'worker_id', 'worker_generation', 'state', 'aggregate_version',
                'last_event_cursor', 'evidence_digest', 'outcome_acknowledged',
                'accepted_at', 'updated_at'
            ] <> '{}'::jsonb
       OR jsonb_typeof(run_obj -> 'schema') <> 'string'
       OR jsonb_typeof(run_obj -> 'run_id') <> 'string'
       OR jsonb_typeof(run_obj -> 'attempt_id') <> 'string'
       OR jsonb_typeof(run_obj -> 'idempotency_key') <> 'string'
       OR jsonb_typeof(run_obj -> 'work_order_digest') <> 'string'
       OR jsonb_typeof(run_obj -> 'worker_id') <> 'string'
       OR jsonb_typeof(run_obj -> 'worker_generation') <> 'number'
       OR jsonb_typeof(run_obj -> 'state') <> 'string'
       OR jsonb_typeof(run_obj -> 'aggregate_version') <> 'number'
       OR jsonb_typeof(run_obj -> 'last_event_cursor') NOT IN ('string', 'null')
       OR jsonb_typeof(run_obj -> 'evidence_digest') NOT IN ('string', 'null')
       OR jsonb_typeof(run_obj -> 'outcome_acknowledged') <> 'boolean'
       OR jsonb_typeof(run_obj -> 'accepted_at') <> 'string'
       OR jsonb_typeof(run_obj -> 'updated_at') <> 'string'
       OR run_obj ->> 'schema' <> 'asf.runmill-run-snapshot.v1'
       OR run_obj ->> 'run_id' <> NEW.external_run_id
       OR run_obj ->> 'attempt_id' <> NEW.attempt_id::text
       OR run_obj ->> 'idempotency_key' <> NEW.remote_idempotency_key
       OR run_obj ->> 'work_order_digest' <> NEW.payload_digest
       OR run_obj ->> 'worker_id' <> NEW.worker_id::text
       OR run_obj -> 'worker_generation' <> to_jsonb(NEW.worker_generation)
       OR run_obj -> 'aggregate_version' <> to_jsonb(NEW.run_state_version)
    THEN
        RAISE EXCEPTION 'lookup receipt run does not match the adoption exact external run identity'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_receipt_run';
    END IF;

    admission_worker := outcome -> 'admission_worker';
    IF NOT (admission_worker ?& ARRAY['worker_id', 'worker_generation'])
       OR admission_worker - ARRAY['worker_id', 'worker_generation'] <> '{}'::jsonb
       OR jsonb_typeof(admission_worker -> 'worker_id') <> 'string'
       OR jsonb_typeof(admission_worker -> 'worker_generation') <> 'number'
       OR admission_worker ->> 'worker_id' <> NEW.worker_id::text
       OR admission_worker -> 'worker_generation' <> to_jsonb(NEW.worker_generation)
    THEN
        RAISE EXCEPTION 'lookup receipt admission worker does not match the adoption exact worker identity'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_receipt_admission_worker';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_submission_recovery_adoption_insert_guard
    BEFORE INSERT ON runmill_submission_recovery_adoptions
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_submission_recovery_adoption_insert();

-- Append-only: no update, delete, or truncate is ever permitted.
CREATE TRIGGER runmill_submission_recovery_adoption_append_only
    BEFORE UPDATE OR DELETE ON runmill_submission_recovery_adoptions
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TRIGGER runmill_submission_recovery_adoption_truncate_forbidden
    BEFORE TRUNCATE ON runmill_submission_recovery_adoptions
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Deferred authority check: by commit time the same transaction must also
-- have created the exact authoritative ADOPTED run this adoption names, the
-- exact matching runmill_run_observation_streams row for that run, and there
-- must be a currently active session for the same worker and generation.
CREATE FUNCTION asf_assert_runmill_submission_recovery_adoption_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM runs AS run
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = run.tenant_id
     AND stream.run_id = run.id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.local_run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.worker_session_id = NEW.worker_session_id
      AND run.external_run_id = NEW.external_run_id
      AND run.state = NEW.run_state
      AND run.authoritative
      AND run.aggregate_version = NEW.run_state_version
      AND run.last_event_sequence = NEW.latest_sequence
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.payload_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.worker_session_id
      AND stream.external_run_id = NEW.external_run_id
    FOR SHARE OF run, stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact authoritative ADOPTED run and matching observation stream'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_run_and_stream';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM worker_sessions AS current_session
        JOIN workers AS worker
          ON worker.tenant_id = current_session.tenant_id
         AND worker.id = current_session.worker_id
        WHERE current_session.tenant_id = NEW.tenant_id
          AND current_session.worker_id = NEW.worker_id
          AND current_session.worker_generation = NEW.worker_generation
          AND current_session.status = 'ACTIVE'
          AND current_session.expires_at > clock_timestamp()
          AND worker.generation = NEW.worker_generation
          AND worker.status <> 'QUARANTINED'
    ) THEN
        RAISE EXCEPTION 'recovery adoption requires a current active session for the same worker and generation'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_current_active_session';
    END IF;

    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER runmill_submission_recovery_adoption_authority_check
    AFTER INSERT ON runmill_submission_recovery_adoptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_submission_recovery_adoption_authority();

-- Recreate only asf_assert_run_worker_session: the standard live-session
-- check still runs first and covers every ordinary insert and update. The
-- historical exception is INSERT-only, and only for a run that is exactly
-- the authoritative ADOPTED run named by one runmill_submission_recovery_adoptions
-- fact with every coordinate matching. Sessions can never be rebound onto a
-- historical exception via UPDATE.
CREATE OR REPLACE FUNCTION asf_assert_run_worker_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF asf_live_worker_session(
        NEW.tenant_id,
        NEW.worker_session_id,
        NEW.worker_id,
        NEW.worker_generation
    ) THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT'
       AND NEW.state = 'ADOPTED'
       AND NEW.authoritative
       AND EXISTS (
           SELECT 1
           FROM runmill_submission_recovery_adoptions AS adoption
           WHERE adoption.tenant_id = NEW.tenant_id
             AND adoption.local_run_id = NEW.id
             AND adoption.work_item_id = NEW.work_item_id
             AND adoption.attempt_id = NEW.attempt_id
             AND adoption.work_order_id = NEW.work_order_id
             AND adoption.worker_id = NEW.worker_id
             AND adoption.worker_generation = NEW.worker_generation
             AND adoption.worker_session_id = NEW.worker_session_id
             AND adoption.external_run_id = NEW.external_run_id
             AND adoption.run_state = 'ADOPTED'
       )
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'run is bound to a closed, expired, or stale worker session'
        USING ERRCODE = '40001';
END;
$$;
