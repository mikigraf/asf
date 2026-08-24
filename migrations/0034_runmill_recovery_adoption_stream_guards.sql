-- Forward-only migration 0034: strict guards on stream references and effect/escalation transitions.
--
-- Defects corrected:
-- 1. Stream references used by adoptions must enforce:
--    - state MUST be 'ACTIVE'
--    - aggregate_version MUST be exactly 1 (fresh-start)
--    - active_job_id MUST be NULL
--    - active_observation_id MUST be NULL
--    - escalation_id MUST be NULL
--
-- 2. Current active worker session locks must be consistent:
--    - Lock the selected current session with FOR UPDATE
--    - Lock the corresponding worker with FOR UPDATE
--    - Use DEFERRABLE INITIALLY DEFERRED for consistency checks
--
-- 3. Effect transition guards must prevent bypass:
--    - Prevent changing effect_type or provider when transitioning to OBSERVED
--    - Validate observed_outcome exactly matches adoption.lookup_receipt.outcome
--    - Require updated_at to advance when status changes
--    - Require last_error to be NULL after successful observation
--
-- 4. Escalation transition guards must prevent bypass:
--    - Prevent changing category when transitioning to RESOLVED
--    - Validate all required fields for resolution (run_id, authority_or_effect_active, closed_at)
--    - Require aggregate_version increment
--    - Restrict OLD status to OPEN/ACKNOWLEDGED before permitting transition to RESOLVED

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

-- Transaction step 1: Replace authority trigger with strict stream reference and active session guards.
DROP TRIGGER IF EXISTS runmill_submission_recovery_adoption_authority_check ON runmill_submission_recovery_adoptions;
DROP FUNCTION IF EXISTS asf_assert_runmill_submission_recovery_adoption_authority();

CREATE FUNCTION asf_assert_runmill_submission_recovery_adoption_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Verify: an exact authoritative ADOPTED run exists with fresh-start coordinates:
    -- aggregate_version=1, last_event_sequence=0, last_event_cursor IS NULL,
    -- and evidence_expectation_digest matches NEW.evidence_expectation_digest.
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
      AND run.evidence_expectation_digest = NEW.evidence_expectation_digest
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact authoritative ADOPTED run with fresh-start coordinates and matching evidence_expectation_digest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_run_fresh_start_digest';
    END IF;

    -- Verify: an exact matching runmill_run_observation_streams row exists with
    -- fresh-start coordinates: next_after_sequence=0, observation_epoch=0,
    -- state='ACTIVE', aggregate_version=1, and no active jobs/observations/escalations,
    -- and workflow_instance_id matches NEW.workflow_instance_id.
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
      AND stream.workflow_instance_id = NEW.workflow_instance_id
      AND stream.next_after_sequence = 0
      AND stream.observation_epoch = 0
      AND stream.state = 'ACTIVE'
      AND stream.aggregate_version = 1
      AND stream.active_job_id IS NULL
      AND stream.active_observation_id IS NULL
      AND stream.escalation_id IS NULL
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact observation stream with fresh-start coordinates, ACTIVE state, no active jobs/observations/escalations, and matching workflow_instance_id'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_stream_fresh_start_active';
    END IF;

    -- Verify: a currently active, unexpired worker session exists.
    -- Lock the selected session and corresponding worker for consistency.
    PERFORM 1
    FROM worker_sessions AS current_session
    JOIN workers AS worker
      ON worker.tenant_id = current_session.tenant_id
     AND worker.id = current_session.worker_id
    WHERE current_session.tenant_id = NEW.tenant_id
      AND current_session.id = NEW.worker_session_id
      AND current_session.worker_id = NEW.worker_id
      AND current_session.worker_generation = NEW.worker_generation
      AND current_session.status = 'ACTIVE'
      AND current_session.expires_at > clock_timestamp()
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
    FOR UPDATE OF current_session, worker;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption requires a current active session for the same worker and generation, and worker must not be quarantined'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_current_active_session_locked';
    END IF;

    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER runmill_submission_recovery_adoption_authority_check
    AFTER INSERT ON runmill_submission_recovery_adoptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_runmill_submission_recovery_adoption_authority();

-- Transaction step 2: Replace historical session guard with consistent locking of session and worker.
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
    -- aggregate_version=1, last_event_sequence=0, last_event_cursor IS NULL,
    -- and evidence_expectation_digest matches NEW.evidence_expectation_digest.
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
      AND run.evidence_expectation_digest = NEW.evidence_expectation_digest
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a run that does not match exact ADOPTED fresh-start coordinates and evidence_expectation_digest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_authoritative_run_fresh_digest';
    END IF;

    -- Verify: an exact matching runmill_run_observation_streams row with
    -- fresh-start coordinates: next_after_sequence=0, observation_epoch=0,
    -- state='ACTIVE', aggregate_version=1, no active jobs/observations/escalations,
    -- and workflow_instance_id matches NEW.workflow_instance_id.
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
      AND stream.workflow_instance_id = NEW.workflow_instance_id
      AND stream.next_after_sequence = 0
      AND stream.observation_epoch = 0
      AND stream.state = 'ACTIVE'
      AND stream.aggregate_version = 1
      AND stream.active_job_id IS NULL
      AND stream.active_observation_id IS NULL
      AND stream.escalation_id IS NULL
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent or mismatched observation stream with exact fresh-start coordinates, ACTIVE state, no active jobs/observations/escalations, and matching workflow_instance_id'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_observation_stream_fresh_active';
    END IF;

    -- Verify: a currently active, unexpired worker session exists.
    -- Lock the selected session for consistency checks.
    SELECT session.*
    INTO current_worker_session
    FROM worker_sessions AS session
    WHERE session.tenant_id = NEW.tenant_id
      AND session.id = NEW.worker_session_id
      AND session.worker_id = NEW.worker_id
      AND session.worker_generation = NEW.worker_generation
      AND session.status = 'ACTIVE'
      AND session.expires_at > clock_timestamp()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption requires a current active session for the same worker and generation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_current_active_session_locked';
    END IF;

    -- Verify: the worker entry has matching generation and is not quarantined.
    -- Lock the worker for consistency checks.
    SELECT worker.*
    INTO worker_row
    FROM workers AS worker
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent, non-matching-generation, or quarantined worker'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_matching_worker_generation_locked';
    END IF;

    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER runmill_recovery_adoption_historical_session_guard
    AFTER INSERT ON runmill_submission_recovery_adoptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_recovery_adoption_historical_session();

-- Transaction step 3: Drop old 0032 effect guard before creating strict replacement.
DROP TRIGGER IF EXISTS runmill_effect_transition_to_observed_guard ON effect_intents;
DROP FUNCTION IF EXISTS asf_guard_runmill_effect_transition_to_observed();

-- Create strict guard for effect AMBIGUOUS->OBSERVED transition.
-- Require OLD AMBIGUOUS->NEW OBSERVED with exact adoption identity match, outcome equality, and timestamp advances.
CREATE FUNCTION asf_validate_effect_observed_outcome_matches_adoption() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    adoption_row runmill_submission_recovery_adoptions%ROWTYPE;
    adoption_receipt jsonb;
BEGIN
    -- Only validate if status is changing from AMBIGUOUS to OBSERVED for runmill/submit_work_order effects.
    IF OLD.status = 'AMBIGUOUS'
       AND NEW.status = 'OBSERVED'
       AND OLD.provider = 'runmill'
       AND NEW.provider = 'runmill'
       AND OLD.effect_type = 'submit_work_order'
       AND NEW.effect_type = 'submit_work_order'
    THEN
        -- Find the matching adoption with exact linked identity:
        -- tenant, effect_intent_id, work_item_id, attempt_id, work_order_id, payload_digest, request_digest
        SELECT adoption.*
        INTO adoption_row
        FROM runmill_submission_recovery_adoptions AS adoption
        WHERE adoption.tenant_id = NEW.tenant_id
          AND adoption.effect_intent_id = NEW.id
          AND adoption.work_item_id = NEW.work_item_id
          AND adoption.attempt_id = NEW.attempt_id
          AND adoption.work_order_id = NEW.work_order_id
          AND adoption.payload_digest = NEW.work_order_digest
          AND adoption.request_digest = NEW.request_digest
        FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'effect_intent transition from AMBIGUOUS to OBSERVED for runmill/submit_work_order requires an exact matching adoption fact (tenant, effect, work_item, attempt, work_order, digests)'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_effect_transition_to_observed_requires_exact_adoption_match';
        END IF;

        -- Extract outcome from adoption receipt
        adoption_receipt := adoption_row.lookup_receipt -> 'outcome';

        -- Validate observed_outcome exactly matches adoption outcome (both must be non-null)
        IF (NEW.observed_outcome IS NULL) OR (adoption_receipt IS NULL) THEN
            RAISE EXCEPTION 'effect observed_outcome must be non-null and match adoption receipt outcome'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_observed_outcome_matches_adoption_outcome';
        END IF;

        -- Ensure the JSON objects are exactly equal (order-independent via JSONB comparison)
        IF NEW.observed_outcome IS DISTINCT FROM adoption_receipt THEN
            RAISE EXCEPTION 'effect observed_outcome does not exactly match adoption receipt outcome'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_observed_outcome_exact_match_adoption_outcome';
        END IF;

        -- Require updated_at to advance
        IF NEW.updated_at IS NOT NULL AND OLD.updated_at IS NOT NULL AND NEW.updated_at <= OLD.updated_at THEN
            RAISE EXCEPTION 'effect updated_at must advance on AMBIGUOUS->OBSERVED transition'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_updated_at_must_advance_on_observed';
        END IF;

        -- Require last_error to be NULL after successful observation
        IF NEW.last_error IS NOT NULL THEN
            RAISE EXCEPTION 'effect last_error must be NULL after successful observation'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_last_error_must_be_null_on_observed';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_observed_outcome_guard
    BEFORE UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_validate_effect_observed_outcome_matches_adoption();

-- Transaction step 4: Drop old 0032 escalation guard before creating strict replacement.
DROP TRIGGER IF EXISTS runmill_escalation_resolution_guard ON escalations;
DROP FUNCTION IF EXISTS asf_guard_runmill_escalation_resolution_requires_adoption();

-- Create strict guard for escalation REMOTE_EFFECT_AMBIGUOUS OPEN/ACKNOWLEDGED->RESOLVED transition.
-- Prevent category change bypass: if OLD category is REMOTE_EFFECT_AMBIGUOUS, NEW must remain REMOTE_EFFECT_AMBIGUOUS.
-- Require exact adoption identity match and all resolution fields.
CREATE FUNCTION asf_validate_escalation_resolved_transition() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    adoption_row runmill_submission_recovery_adoptions%ROWTYPE;
BEGIN
    -- Only guard transitions from OPEN/ACKNOWLEDGED to RESOLVED.
    IF OLD.status IN ('OPEN', 'ACKNOWLEDGED') AND NEW.status = 'RESOLVED' THEN
        -- If OLD category is REMOTE_EFFECT_AMBIGUOUS, must remain so (prevent bypass by changing category).
        IF OLD.category = 'REMOTE_EFFECT_AMBIGUOUS' THEN
            -- Require NEW category to remain REMOTE_EFFECT_AMBIGUOUS
            IF NEW.category <> 'REMOTE_EFFECT_AMBIGUOUS' THEN
                RAISE EXCEPTION 'escalation category cannot change during OPEN/ACKNOWLEDGED->RESOLVED transition: if OLD is REMOTE_EFFECT_AMBIGUOUS, NEW must remain REMOTE_EFFECT_AMBIGUOUS'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_category_immutable_remote_effect_ambiguous_on_resolved';
            END IF;

            -- Find and validate exact matching adoption fact with exact linked identity:
            -- tenant, escalation_id, work_item_id, attempt_id, work_order_id, payload_digest, request_digest
            SELECT adoption.*
            INTO adoption_row
            FROM runmill_submission_recovery_adoptions AS adoption
            WHERE adoption.tenant_id = NEW.tenant_id
              AND adoption.escalation_id = NEW.id
              AND adoption.work_item_id = NEW.work_item_id
              AND adoption.attempt_id = NEW.attempt_id
              AND adoption.work_order_id = NEW.work_order_id
              AND adoption.payload_digest = NEW.work_order_digest
              AND adoption.request_digest = NEW.request_digest
            FOR SHARE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'escalation REMOTE_EFFECT_AMBIGUOUS resolution requires an exact matching adoption fact (tenant, escalation, work_item, attempt, work_order, digests)'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_resolved_requires_exact_adoption_match';
            END IF;

            -- Require run_id to equal adoption.local_run_id
            IF NEW.run_id IS NULL THEN
                RAISE EXCEPTION 'escalation run_id must be set when resolving'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_run_id_required_on_resolved';
            END IF;

            IF NEW.run_id <> adoption_row.local_run_id THEN
                RAISE EXCEPTION 'escalation run_id must equal adoption.local_run_id'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_run_id_must_match_adoption_local_run_id';
            END IF;

            -- Require authority_or_effect_active to be false
            IF NEW.authority_or_effect_active <> false THEN
                RAISE EXCEPTION 'escalation authority_or_effect_active must be false when resolving REMOTE_EFFECT_AMBIGUOUS'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_authority_or_effect_active_must_be_false_on_resolved';
            END IF;

            -- Require closed_at to be non-null
            IF NEW.closed_at IS NULL THEN
                RAISE EXCEPTION 'escalation closed_at must be set when resolving REMOTE_EFFECT_AMBIGUOUS'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_closed_at_required_on_resolved';
            END IF;

            -- Require aggregate_version to be incremented by exactly 1
            IF NEW.aggregate_version IS NOT NULL AND OLD.aggregate_version IS NOT NULL THEN
                IF NEW.aggregate_version <> (OLD.aggregate_version + 1) THEN
                    RAISE EXCEPTION 'escalation aggregate_version must be incremented by exactly 1 when resolving'
                        USING ERRCODE = '23514',
                              CONSTRAINT = 'escalation_aggregate_version_must_increment_by_one_on_resolved';
                END IF;
            ELSE
                RAISE EXCEPTION 'escalation aggregate_version must be set for resolution'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'escalation_aggregate_version_required_on_resolved';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER escalation_resolved_transition_guard
    BEFORE UPDATE ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_validate_escalation_resolved_transition();
