-- Forward-only migration 0033: bind adoption stream to workflow_instance_id
-- and require runs.evidence_expectation_digest to match adoption.evidence_expectation_digest.
--
-- Changes to authority/historical guards:
-- 1. Authority check now validates stream.workflow_instance_id = NEW.workflow_instance_id
-- 2. Authority check now validates runs.evidence_expectation_digest = NEW.evidence_expectation_digest
-- 3. Historical session guard applies the same two validations.
--
-- All other logic from 0032 remains unchanged.
-- Lock all adoption-related tables to preserve global ordering.

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

-- Transaction step 1: Drop and replace the authority trigger with stream/digest validation.
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
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery adoption lacks its exact observation stream with fresh-start coordinates and matching workflow_instance_id'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_adoptions_exact_stream_fresh_start_workflow';
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

-- Transaction step 2: Drop and replace the historical session guard with stream/digest validation.
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
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent or mismatched observation stream with exact fresh-start coordinates and workflow_instance_id'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_observation_stream_fresh_workflow';
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
