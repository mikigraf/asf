-- Forward-only repair migration for runmill submission recovery adoption guards.
--
-- Defects corrected:
-- 1. 0027 deferred authority trigger references dropped latest_sequence column.
--    Replace with fresh-start coordinates: aggregate_version=1, last_event_sequence=0, last_event_cursor NULL.
--    Require exact observation stream with next_after_sequence=0, observation_epoch=0.
--
-- 2. 0030 validator has incorrect field names for workflow_instances and escalations.
--    Fixes: workflow_instances.state (not status), workflow_instances.workflow_type (not delivery_type).
--    Fixes: escalations.category (not escalation_type), escalations.authority_or_effect_active (not authority).
--
-- 3. 0029 historical session guard references dropped latest_sequence column.
--    Replace with fresh-start coordinates: aggregate_version=1, last_event_sequence=0, last_event_cursor NULL.
--    Require exact observation stream with next_after_sequence=0, observation_epoch=0.
--
-- 4. 0031 transition guards have incorrect field name and missing state restrictions.
--    Fixes: escalations.category (not escalation_type).
--    Fixes: Restrict OLD status to OPEN/ACKNOWLEDGED before permitting transition to RESOLVED.
--    Fixes: Add validation that effect.observed_outcome exactly equals adoption.lookup_receipt.outcome.
--
-- Transaction order:
-- 1. Lock all adoption-related tables to preserve global ordering.
-- 2. Drop and replace the defective 0027 deferred authority trigger.
-- 3. Drop and replace the defective 0029 historical session guard trigger.
-- 4. Drop and replace the defective 0031 transition guard triggers.
-- 5. Replace the defective 0030 validator function (used by 0030 trigger, not dropped here).
--
-- All changes are forward-only: new adoptions must comply with corrected guards.

LOCK TABLE runmill_submission_recovery_adoptions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_submission_recovery_cases IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_streams IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;

-- Transaction step 1: Drop and replace the defective 0027 deferred authority trigger.
-- The original function referenced NEW.latest_sequence (dropped in 0030).
-- New function requires fresh-start coordinates: aggregate_version=1, last_event_sequence=0, last_event_cursor NULL.
-- Stream must have next_after_sequence=0, observation_epoch=0.
DROP TRIGGER IF EXISTS runmill_submission_recovery_adoption_authority_check ON runmill_submission_recovery_adoptions;
DROP FUNCTION IF EXISTS asf_assert_runmill_submission_recovery_adoption_authority();

CREATE FUNCTION asf_assert_runmill_submission_recovery_adoption_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Verify: an exact authoritative ADOPTED run exists with fresh-start coordinates:
    -- aggregate_version=1, last_event_sequence=0, last_event_cursor IS NULL.
    PERFORM 1
    FROM runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.local_run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.worker_session_id = NEW.worker_session_id
      AND run.external_run_id = NEW.external_run_id
      AND run.state = 'ADOPTED'
      AND run.authoritative = true
      AND run.aggregate_version = 1
      AND run.last_event_sequence = 0
      AND run.last_event_cursor IS NULL
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact authoritative ADOPTED run with fresh-start coordinates'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_run_fresh_start';
    END IF;

    -- Verify: an exact matching runmill_run_observation_streams row exists with
    -- fresh-start coordinates: next_after_sequence=0, observation_epoch=0.
    PERFORM 1
    FROM runmill_run_observation_streams AS stream
    WHERE stream.tenant_id = NEW.tenant_id
      AND stream.run_id = NEW.local_run_id
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.payload_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.worker_session_id
      AND stream.external_run_id = NEW.external_run_id
      AND stream.next_after_sequence = 0
      AND stream.observation_epoch = 0
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact observation stream with fresh-start coordinates'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_stream_fresh_start';
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

-- Transaction step 2: Drop and replace the defective 0029 historical session guard trigger.
-- The original function referenced NEW.latest_sequence (dropped in 0030).
-- New function requires fresh-start coordinates: aggregate_version=1, last_event_sequence=0, last_event_cursor NULL.
-- Stream must have next_after_sequence=0, observation_epoch=0.
DROP TRIGGER IF EXISTS runmill_recovery_adoption_historical_session_guard ON runmill_submission_recovery_adoptions;
DROP FUNCTION IF EXISTS asf_guard_runmill_recovery_adoption_historical_session();

CREATE FUNCTION asf_guard_runmill_recovery_adoption_historical_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authoritative_run runs%ROWTYPE;
    observation_stream runmill_run_observation_streams%ROWTYPE;
    current_worker_session worker_sessions%ROWTYPE;
    worker_row workers%ROWTYPE;
BEGIN
    -- Verify: an exact authoritative ADOPTED run with fresh-start coordinates:
    -- aggregate_version=1, last_event_sequence=0, last_event_cursor IS NULL.
    SELECT run.*
    INTO authoritative_run
    FROM runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.local_run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.worker_session_id = NEW.worker_session_id
      AND run.external_run_id = NEW.external_run_id
      AND run.state = 'ADOPTED'
      AND run.authoritative = true
      AND run.aggregate_version = 1
      AND run.last_event_sequence = 0
      AND run.last_event_cursor IS NULL
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a run that does not match exact ADOPTED fresh-start coordinates'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_authoritative_run_fresh';
    END IF;

    -- Verify: an exact matching runmill_run_observation_streams row with
    -- fresh-start coordinates: next_after_sequence=0, observation_epoch=0.
    SELECT stream.*
    INTO observation_stream
    FROM runmill_run_observation_streams AS stream
    WHERE stream.tenant_id = NEW.tenant_id
      AND stream.run_id = NEW.local_run_id
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.payload_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.worker_session_id
      AND stream.external_run_id = NEW.external_run_id
      AND stream.next_after_sequence = 0
      AND stream.observation_epoch = 0
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent or mismatched observation stream with exact fresh-start coordinates'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_observation_stream_fresh';
    END IF;

    -- Verify: a currently active, unexpired worker session exists.
    SELECT session.*
    INTO current_worker_session
    FROM worker_sessions AS session
    WHERE session.tenant_id = NEW.tenant_id
      AND session.worker_id = NEW.worker_id
      AND session.worker_generation = NEW.worker_generation
      AND session.status = 'ACTIVE'
      AND session.expires_at > clock_timestamp()
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption requires a current active session for the same worker and generation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_current_active_session';
    END IF;

    -- Verify: the worker entry has matching generation and is not quarantined.
    SELECT worker.*
    INTO worker_row
    FROM workers AS worker
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent, non-matching-generation, or quarantined worker'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_matching_worker_generation';
    END IF;

    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER runmill_recovery_adoption_historical_session_guard
    AFTER INSERT ON runmill_submission_recovery_adoptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_recovery_adoption_historical_session();

-- Transaction step 3: Drop and replace the defective 0031 transition guard triggers.
-- Fixes: use escalations.category instead of escalation_type.
-- Fixes: restrict OLD status to OPEN/ACKNOWLEDGED before permitting RESOLVED transition.
-- Fixes: add validation that effect.observed_outcome exactly equals adoption.lookup_receipt.outcome.
DROP TRIGGER IF EXISTS runmill_effect_transition_to_observed_guard ON effect_intents;
DROP FUNCTION IF EXISTS asf_guard_runmill_effect_transition_to_observed();

CREATE FUNCTION asf_guard_runmill_effect_transition_to_observed() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_adoption runmill_submission_recovery_adoptions%ROWTYPE;
BEGIN
    -- Only guard AMBIGUOUS → OBSERVED transitions for runmill/submit_work_order effects.
    -- All other state transitions (failed, retried, etc.) are allowed without adoption.
    IF OLD.status = 'AMBIGUOUS'
       AND NEW.status = 'OBSERVED'
       AND NEW.provider = 'runmill'
       AND NEW.effect_type = 'submit_work_order'
    THEN
        -- Require an exact matching adoption fact with same tenant and effect_intent_id.
        SELECT adoption.*
        INTO linked_adoption
        FROM runmill_submission_recovery_adoptions AS adoption
        WHERE adoption.tenant_id = NEW.tenant_id
          AND adoption.effect_intent_id = NEW.id
        FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'effect_intent transition from AMBIGUOUS to OBSERVED for runmill/submit_work_order requires an exact matching adoption fact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_effect_transition_to_observed_requires_adoption';
        END IF;

        -- Require effect.observed_outcome to exactly equal adoption.lookup_receipt.outcome.
        IF NEW.observed_outcome IS DISTINCT FROM (linked_adoption.lookup_receipt -> 'outcome') THEN
            RAISE EXCEPTION 'effect_intent observed_outcome does not match adoption lookup_receipt.outcome'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_effect_transition_observed_outcome_matches_adoption';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_effect_transition_to_observed_guard
    BEFORE UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_effect_transition_to_observed();

-- Escalation resolution guard: restrict to OPEN/ACKNOWLEDGED status before permitting RESOLVED.
DROP TRIGGER IF EXISTS runmill_escalation_resolution_guard ON escalations;
DROP FUNCTION IF EXISTS asf_guard_runmill_escalation_resolution_requires_adoption();

CREATE FUNCTION asf_guard_runmill_escalation_resolution_requires_adoption() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_adoption runmill_submission_recovery_adoptions%ROWTYPE;
BEGIN
    -- Only guard transitions to RESOLVED for REMOTE_EFFECT_AMBIGUOUS escalations.
    -- Restrict: only OPEN or ACKNOWLEDGED status can transition to RESOLVED.
    -- All other escalation types and non-resolution transitions are allowed.
    IF OLD.status IN ('OPEN', 'ACKNOWLEDGED')
       AND NEW.status = 'RESOLVED'
       AND NEW.category = 'REMOTE_EFFECT_AMBIGUOUS'
    THEN
        -- Require an exact matching adoption fact with same tenant and escalation_id.
        SELECT adoption.*
        INTO linked_adoption
        FROM runmill_submission_recovery_adoptions AS adoption
        WHERE adoption.tenant_id = NEW.tenant_id
          AND adoption.escalation_id = NEW.id
        FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'escalation resolution for REMOTE_EFFECT_AMBIGUOUS requires an exact matching adoption fact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_escalation_resolution_requires_adoption';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_escalation_resolution_guard
    BEFORE UPDATE ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_escalation_resolution_requires_adoption();

-- Transaction step 4: Replace the defective 0030 validator function.
-- Fixes: use workflow_instances.state (not status) = 'ACTIVE'.
-- Fixes: use workflow_instances.workflow_type (not delivery_type) = 'WORK_ITEM_DELIVERY'.
-- Fixes: use escalations.category (not escalation_type) = 'REMOTE_EFFECT_AMBIGUOUS'.
-- Fixes: use escalations.authority_or_effect_active (not authority) = true.
CREATE OR REPLACE FUNCTION asf_guard_runmill_submission_recovery_adoption_fact_validation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_case runmill_submission_recovery_cases%ROWTYPE;
    linked_effect effect_intents%ROWTYPE;
    linked_work_order work_orders%ROWTYPE;
    linked_session worker_sessions%ROWTYPE;
    linked_workflow workflow_instances%ROWTYPE;
    linked_escalation escalations%ROWTYPE;
    existing_authoritative_run runs%ROWTYPE;
    outcome_obj jsonb;
    qualification_obj jsonb;
    admission_worker_obj jsonb;
    run_obj jsonb;
    evidence_obj jsonb;
    evidence_keys text[];
    top_keys text[];
    outcome_keys text[];
    qualification_keys text[];
    admission_worker_keys text[];
    evidence_expectation_keys text[];
BEGIN
    -- Load the exact PENDING recovery case.
    SELECT case_row.*
    INTO linked_case
    FROM runmill_submission_recovery_cases AS case_row
    WHERE case_row.tenant_id = NEW.tenant_id
      AND case_row.id = NEW.recovery_case_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no linked recovery case'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_case_binding';
    END IF;

    IF linked_case.state IS DISTINCT FROM 'PENDING_EXTERNAL_LOOKUP' THEN
        RAISE EXCEPTION 'recovery case is not in PENDING_EXTERNAL_LOOKUP state'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_case_pending_state';
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

    -- Load and validate the linked AMBIGUOUS runmill/submit_work_order effect.
    SELECT effect.*
    INTO linked_effect
    FROM effect_intents AS effect
    WHERE effect.tenant_id = NEW.tenant_id
      AND effect.id = NEW.effect_intent_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no linked effect intent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_effect_binding';
    END IF;

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

    -- Load and validate the exact immutable work order.
    SELECT work_order.*
    INTO linked_work_order
    FROM work_orders AS work_order
    WHERE work_order.tenant_id = NEW.tenant_id
      AND work_order.id = NEW.work_order_id
      AND work_order.payload_digest = NEW.payload_digest
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption has no exact linked work order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_work_order_binding';
    END IF;

    -- Validate work order identifiers.
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
      AND session.worker_generation = NEW.worker_generation
    FOR SHARE;

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
    FOR SHARE
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'an authoritative run already exists for this attempt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_no_prior_authoritative_run';
    END IF;

    -- Load and validate the exact active/WORK_ITEM_DELIVERY workflow instance.
    -- CORRECTION: use workflow_instances.state (not status) and workflow_type (not delivery_type).
    SELECT wf.*
    INTO linked_workflow
    FROM workflow_instances AS wf
    WHERE wf.tenant_id = NEW.tenant_id
      AND wf.id = NEW.workflow_instance_id
      AND wf.work_item_id = NEW.work_item_id
      AND wf.state = 'ACTIVE'
      AND wf.workflow_type = 'WORK_ITEM_DELIVERY'
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references no exact active WORK_ITEM_DELIVERY workflow instance'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_workflow_instance_exact';
    END IF;

    -- Load and validate the exact open or acknowledged REMOTE_EFFECT_AMBIGUOUS escalation with authority.
    -- CORRECTION: use escalations.category (not escalation_type) and authority_or_effect_active (not authority).
    SELECT esc.*
    INTO linked_escalation
    FROM escalations AS esc
    WHERE esc.tenant_id = NEW.tenant_id
      AND esc.id = NEW.escalation_id
      AND esc.work_item_id = NEW.work_item_id
      AND esc.status IN ('OPEN', 'ACKNOWLEDGED')
      AND esc.category = 'REMOTE_EFFECT_AMBIGUOUS'
      AND esc.authority_or_effect_active = true
      AND esc.idempotency_key = 'runmill-submission-recovery:' || NEW.effect_intent_id::text
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references no exact open/acknowledged REMOTE_EFFECT_AMBIGUOUS escalation with authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_escalation_exact';
    END IF;

    -- Validate Rust V2 receipt JSON structure: top-level schema/outcome.
    top_keys := ARRAY(SELECT jsonb_object_keys(NEW.lookup_receipt));
    IF NOT (top_keys::text[] @> ARRAY['schema', 'outcome'] AND array_length(top_keys, 1) = 2) THEN
        RAISE EXCEPTION 'lookup receipt top-level keys must be exactly {schema, outcome}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_top_keys';
    END IF;

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
    IF NOT (outcome_keys::text[] @> ARRAY['kind', 'qualification', 'admission_worker', 'run']
            AND array_length(outcome_keys, 1) = 4) THEN
        RAISE EXCEPTION 'lookup receipt outcome must have exactly these keys: {kind, qualification, admission_worker, run}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_outcome_exact_keys';
    END IF;

    IF (outcome_obj->>'kind') IS DISTINCT FROM 'found' THEN
        RAISE EXCEPTION 'lookup receipt outcome kind must be "found"'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_outcome_kind';
    END IF;

    -- Extract and validate qualification with exact request digest.
    qualification_obj := outcome_obj->'qualification';
    IF qualification_obj IS NULL OR jsonb_typeof(qualification_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.qualification must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_qualification_object';
    END IF;

    qualification_keys := ARRAY(SELECT jsonb_object_keys(qualification_obj));
    IF NOT (qualification_keys::text[] @> ARRAY['tenant_id', 'work_order_id', 'work_item_id', 'attempt_id', 'idempotency_key', 'work_order_digest', 'request_digest']
            AND array_length(qualification_keys, 1) = 7) THEN
        RAISE EXCEPTION 'lookup receipt qualification must have exactly these keys: {tenant_id, work_order_id, work_item_id, attempt_id, idempotency_key, work_order_digest, request_digest}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_qualification_exact_keys';
    END IF;

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

    -- Extract and validate admission_worker {worker_id, worker_generation}.
    admission_worker_obj := outcome_obj->'admission_worker';
    IF admission_worker_obj IS NULL OR jsonb_typeof(admission_worker_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.admission_worker must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_object';
    END IF;

    admission_worker_keys := ARRAY(SELECT jsonb_object_keys(admission_worker_obj));
    IF NOT (admission_worker_keys::text[] @> ARRAY['worker_id', 'worker_generation']
            AND array_length(admission_worker_keys, 1) = 2) THEN
        RAISE EXCEPTION 'lookup receipt admission_worker must have exactly these keys: {worker_id, worker_generation}'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_exact_keys';
    END IF;

    IF (admission_worker_obj->>'worker_id')::uuid IS DISTINCT FROM NEW.worker_id
       OR (admission_worker_obj->>'worker_generation')::bigint IS DISTINCT FROM NEW.worker_generation THEN
        RAISE EXCEPTION 'lookup receipt admission_worker values do not match adoption row'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_admission_worker_values';
    END IF;

    -- Extract and validate RunSnapshot with exact identity.
    run_obj := outcome_obj->'run';
    IF run_obj IS NULL OR jsonb_typeof(run_obj) <> 'object' THEN
        RAISE EXCEPTION 'lookup receipt outcome.run must be an object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_receipt_run_object';
    END IF;

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

    -- Validate evidence_expectation as exact JSONB object per asf.runmill-recovery-evidence-expectation/v1.
    -- Minimum known fields: work_order_envelope_digest, work_order_payload_digest, lookup_receipt_digest,
    -- external_run_id, worker_id, worker_generation, worker_session_id.
    IF jsonb_typeof(NEW.evidence_expectation) <> 'object' THEN
        RAISE EXCEPTION 'evidence_expectation must be a JSON object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_evidence_expectation_object';
    END IF;

    evidence_expectation_keys := ARRAY(SELECT jsonb_object_keys(NEW.evidence_expectation));
    IF NOT (evidence_expectation_keys::text[] @> ARRAY[
                'work_order_envelope_digest', 'work_order_payload_digest', 'lookup_receipt_digest',
                'external_run_id', 'worker_id', 'worker_generation', 'worker_session_id'
            ]) THEN
        RAISE EXCEPTION 'evidence_expectation missing required minimum fields'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_evidence_expectation_minimum_fields';
    END IF;

    RETURN NEW;
END;
$$;
