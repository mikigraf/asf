-- Validate adoption facts for runmill submission recovery against authoritative sources.
-- An adoption is only valid if:
-- 1. All adoption identifiers exactly match the recovery case
-- 2. The recovery case is in PENDING_EXTERNAL_LOOKUP state
-- 3. The linked effect is exactly runmill/submit_work_order/AMBIGUOUS with matching digests
-- 4. The linked work order is exact
-- 5. The linked worker session is exact
-- 6. No authoritative run already exists for the attempt
-- 7. The lookup receipt envelope is valid JSON matching expected schema

LOCK TABLE runmill_submission_recovery_adoptions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_submission_recovery_cases IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;

CREATE FUNCTION asf_guard_runmill_submission_recovery_adoption_fact_validation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_case runmill_submission_recovery_cases%ROWTYPE;
    linked_effect effect_intents%ROWTYPE;
    linked_work_order work_orders%ROWTYPE;
    linked_session worker_sessions%ROWTYPE;
    existing_authoritative_run runs%ROWTYPE;
    outcome_obj jsonb;
    qualification_obj jsonb;
    admission_worker_obj jsonb;
    run_obj jsonb;
    top_keys text[];
    outcome_keys text[];
    qualification_keys text[];
    admission_worker_keys text[];
BEGIN
    -- Load the recovery case to validate exact binding.
    SELECT case_row.*
    INTO linked_case
    FROM runmill_submission_recovery_cases AS case_row
    WHERE case_row.tenant_id = NEW.tenant_id
      AND case_row.id = NEW.recovery_case_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no linked recovery case'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_case_binding';
    END IF;

    -- Validate all adoption identifiers exactly equal the case.
    IF linked_case.effect_intent_id IS DISTINCT FROM NEW.effect_intent_id
       OR linked_case.work_item_id IS DISTINCT FROM NEW.work_item_id
       OR linked_case.attempt_id IS DISTINCT FROM NEW.attempt_id
       OR linked_case.work_order_id IS DISTINCT FROM NEW.work_order_id
       OR linked_case.payload_digest IS DISTINCT FROM NEW.payload_digest
       OR linked_case.request_digest IS DISTINCT FROM NEW.request_digest
       OR linked_case.remote_idempotency_key IS DISTINCT FROM NEW.remote_idempotency_key
       OR linked_case.worker_id IS DISTINCT FROM NEW.worker_id
       OR linked_case.worker_generation IS DISTINCT FROM NEW.worker_generation
       OR linked_case.worker_session_id IS DISTINCT FROM NEW.worker_session_id THEN
        RAISE EXCEPTION 'adoption identifiers do not exactly match the recovery case'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_case_exact_match';
    END IF;

    -- Validate recovery case is in PENDING_EXTERNAL_LOOKUP state.
    IF linked_case.state IS DISTINCT FROM 'PENDING_EXTERNAL_LOOKUP' THEN
        RAISE EXCEPTION 'recovery case is not in PENDING_EXTERNAL_LOOKUP state'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_case_pending_state';
    END IF;

    -- Load and validate the linked effect intent.
    SELECT effect.*
    INTO linked_effect
    FROM effect_intents AS effect
    WHERE effect.tenant_id = NEW.tenant_id
      AND effect.id = NEW.effect_intent_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no linked effect intent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_effect_binding';
    END IF;

    -- Validate exact provider, effect_type, and status.
    IF linked_effect.provider IS DISTINCT FROM 'runmill'
       OR linked_effect.effect_type IS DISTINCT FROM 'submit_work_order'
       OR linked_effect.status IS DISTINCT FROM 'AMBIGUOUS' THEN
        RAISE EXCEPTION 'effect intent is not exactly runmill/submit_work_order/AMBIGUOUS'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_effect_exact_state';
    END IF;

    -- Validate linked effect identifiers match exactly.
    IF linked_effect.work_item_id IS DISTINCT FROM NEW.work_item_id
       OR linked_effect.attempt_id IS DISTINCT FROM NEW.attempt_id
       OR linked_effect.work_order_id IS DISTINCT FROM NEW.work_order_id
       OR linked_effect.work_order_digest IS DISTINCT FROM NEW.payload_digest
       OR linked_effect.request_digest IS DISTINCT FROM NEW.request_digest THEN
        RAISE EXCEPTION 'effect intent identifiers do not match adoption'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_effect_exact_identifiers';
    END IF;

    -- Load and validate the linked work order.
    SELECT work_order.*
    INTO linked_work_order
    FROM work_orders AS work_order
    WHERE work_order.tenant_id = NEW.tenant_id
      AND work_order.id = NEW.work_order_id
      AND work_order.payload_digest = NEW.payload_digest;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no exact linked work order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_work_order_binding';
    END IF;

    -- Validate work order identifiers match exactly.
    IF linked_work_order.work_item_id IS DISTINCT FROM NEW.work_item_id
       OR linked_work_order.attempt_id IS DISTINCT FROM NEW.attempt_id
       OR linked_work_order.idempotency_key IS DISTINCT FROM NEW.remote_idempotency_key THEN
        RAISE EXCEPTION 'work order identifiers do not match adoption'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_work_order_exact_identifiers';
    END IF;

    -- Load and validate the linked worker session.
    SELECT session.*
    INTO linked_session
    FROM worker_sessions AS session
    WHERE session.tenant_id = NEW.tenant_id
      AND session.id = NEW.worker_session_id
      AND session.worker_id = NEW.worker_id
      AND session.worker_generation = NEW.worker_generation;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no exact linked worker session'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_session_exact_binding';
    END IF;

    -- Reject if any authoritative run already exists for this attempt.
    SELECT run.*
    INTO existing_authoritative_run
    FROM runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.attempt_id = NEW.attempt_id
      AND run.authoritative = true
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'an authoritative run already exists for this attempt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_no_prior_authoritative_run';
    END IF;

    -- Validate lookup receipt JSON schema conservatively.
    -- Extract top-level keys to validate no unknown keys.
    top_keys := ARRAY(SELECT jsonb_object_keys(NEW.lookup_receipt));

    -- Top-level keys must be exactly {schema, outcome}
    IF NOT (top_keys::text[] @> ARRAY['schema', 'outcome'] AND array_length(top_keys, 1) = 2) THEN
        RAISE EXCEPTION 'lookup receipt top-level keys must be exactly {schema, outcome}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_top_keys';
    END IF;

    -- Validate schema is exactly the expected v1 schema.
    IF (NEW.lookup_receipt->>'schema') IS DISTINCT FROM 'asf.runmill-lookup-qualified-submission-receipt.v1' THEN
        RAISE EXCEPTION 'lookup receipt schema is not asf.runmill-lookup-qualified-submission-receipt.v1'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_schema_version';
    END IF;

    -- Extract and validate outcome object.
    outcome_obj := NEW.lookup_receipt->'outcome';
    IF outcome_obj IS NULL OR jsonb_typeof(outcome_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_outcome_object';
    END IF;

    outcome_keys := ARRAY(SELECT jsonb_object_keys(outcome_obj));

    -- outcome keys must be exactly: {kind, qualification, admission_worker, run}
    IF NOT (outcome_keys::text[] @> ARRAY['kind', 'qualification', 'admission_worker', 'run']
            AND array_length(outcome_keys, 1) = 4) THEN
        RAISE EXCEPTION 'lookup receipt outcome must have exactly these keys: {kind, qualification, admission_worker, run}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_outcome_exact_keys';
    END IF;

    -- Validate outcome kind is exactly "found".
    IF (outcome_obj->>'kind') IS DISTINCT FROM 'found' THEN
        RAISE EXCEPTION 'lookup receipt outcome kind must be "found"'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_outcome_kind';
    END IF;

    -- Extract and validate qualification object.
    qualification_obj := outcome_obj->'qualification';
    IF qualification_obj IS NULL OR jsonb_typeof(qualification_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.qualification must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_qualification_object';
    END IF;

    qualification_keys := ARRAY(SELECT jsonb_object_keys(qualification_obj));

    -- qualification keys must be exactly: {tenant_id, work_order_id, work_item_id, attempt_id, idempotency_key, work_order_digest, request_digest}
    IF NOT (qualification_keys::text[] @> ARRAY['tenant_id', 'work_order_id', 'work_item_id', 'attempt_id', 'idempotency_key', 'work_order_digest', 'request_digest']
            AND array_length(qualification_keys, 1) = 7) THEN
        RAISE EXCEPTION 'lookup receipt qualification must have exactly these keys: {tenant_id, work_order_id, work_item_id, attempt_id, idempotency_key, work_order_digest, request_digest}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_qualification_exact_keys';
    END IF;

    -- Validate qualification values match the row exactly.
    IF (qualification_obj->>'tenant_id')::uuid IS DISTINCT FROM NEW.tenant_id
       OR (qualification_obj->>'work_order_id')::uuid IS DISTINCT FROM NEW.work_order_id
       OR (qualification_obj->>'work_item_id')::uuid IS DISTINCT FROM NEW.work_item_id
       OR (qualification_obj->>'attempt_id')::uuid IS DISTINCT FROM NEW.attempt_id
       OR (qualification_obj->>'idempotency_key') IS DISTINCT FROM NEW.remote_idempotency_key
       OR (qualification_obj->>'work_order_digest') IS DISTINCT FROM NEW.payload_digest
       OR (qualification_obj->>'request_digest') IS DISTINCT FROM NEW.request_digest THEN
        RAISE EXCEPTION 'lookup receipt qualification values do not match adoption row'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_qualification_values';
    END IF;

    -- Extract and validate admission_worker object.
    admission_worker_obj := outcome_obj->'admission_worker';
    IF admission_worker_obj IS NULL OR jsonb_typeof(admission_worker_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.admission_worker must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_object';
    END IF;

    admission_worker_keys := ARRAY(SELECT jsonb_object_keys(admission_worker_obj));

    -- admission_worker keys must be exactly: {worker_id, worker_generation}
    IF NOT (admission_worker_keys::text[] @> ARRAY['worker_id', 'worker_generation']
            AND array_length(admission_worker_keys, 1) = 2) THEN
        RAISE EXCEPTION 'lookup receipt admission_worker must have exactly these keys: {worker_id, worker_generation}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_exact_keys';
    END IF;

    -- Validate admission_worker values match the row exactly.
    IF (admission_worker_obj->>'worker_id')::uuid IS DISTINCT FROM NEW.worker_id
       OR (admission_worker_obj->>'worker_generation')::bigint IS DISTINCT FROM NEW.worker_generation THEN
        RAISE EXCEPTION 'lookup receipt admission_worker values do not match adoption row'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_values';
    END IF;

    -- Extract and validate run object.
    run_obj := outcome_obj->'run';
    IF run_obj IS NULL OR jsonb_typeof(run_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.run must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_run_object';
    END IF;

    -- Validate required run fields are present.
    IF (run_obj->>'run_id') IS NULL
       OR (run_obj->>'attempt_id') IS NULL
       OR (run_obj->>'idempotency_key') IS NULL
       OR (run_obj->>'work_order_digest') IS NULL
       OR (run_obj->>'worker_id') IS NULL
       OR (run_obj->>'worker_generation') IS NULL
       OR (run_obj->>'state') IS NULL
       OR (run_obj->>'aggregate_version') IS NULL THEN
        RAISE EXCEPTION 'lookup receipt run is missing required fields'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_run_required_fields';
    END IF;

    -- Validate run field values match exactly where required.
    IF (run_obj->>'run_id') IS DISTINCT FROM NEW.external_run_id
       OR (run_obj->>'attempt_id')::uuid IS DISTINCT FROM NEW.attempt_id
       OR (run_obj->>'idempotency_key') IS DISTINCT FROM NEW.remote_idempotency_key
       OR (run_obj->>'work_order_digest') IS DISTINCT FROM NEW.payload_digest
       OR (run_obj->>'worker_id')::uuid IS DISTINCT FROM NEW.worker_id
       OR (run_obj->>'worker_generation')::bigint IS DISTINCT FROM NEW.worker_generation
       OR (run_obj->>'aggregate_version')::bigint IS DISTINCT FROM NEW.run_state_version THEN
        RAISE EXCEPTION 'lookup receipt run field values do not match adoption row'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_run_field_values';
    END IF;

    -- NOTE: Digest validation and additional run field validation is deferred to Rust transaction logic.
    -- The Rust code must verify remaining RunSnapshot fields (schema, last_event_cursor, evidence_digest,
    -- outcome_acknowledged, accepted_at, updated_at) and calculate the canonical digest according to
    -- the runmill protocol. We do not attempt to verify the digest here, as SQL cannot replicate
    -- the exact Rust serde serialization and canonical digest calculation.

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_submission_recovery_adoptions_fact_validation
    BEFORE INSERT ON runmill_submission_recovery_adoptions
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_submission_recovery_adoption_fact_validation();
