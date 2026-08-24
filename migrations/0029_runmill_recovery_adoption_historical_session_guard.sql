-- Guard historical worker session adoption facts: verify that a recovery adoption
-- can only commit if it references:
-- 1. An exact authoritative ADOPTED run with all adoption coordinates, external ID,
--    worker identity, and historic session binding, whose aggregate_version matches
--    run_state_version and whose last_event_sequence does not exceed latest_sequence
--    (no cursor invention).
-- 2. An exact matching runmill_run_observation_streams row with all coordinates,
--    payload digest, worker generation, run-admission session, and external ID.
-- 3. A currently active, unexpired worker session for the same tenant, worker, and
--    generation. The historic session bound to the adoption itself may be CLOSED
--    after a worker restart; we never mutate it. The current session verifies the
--    worker remains healthy.
--
-- The constraint is DEFERRABLE INITIALLY DEFERRED: by transaction commit, the Rust
-- application must have created the run and stream rows. The trigger uses FOR SHARE
-- locks to prevent concurrent modifications during the final authority check.
--
-- Rationale: The recovery adoption fact alone is not sufficient to prove the run's
-- correctness. The run must exist, must be marked authoritative and ADOPTED, must
-- contain the exact external ID, must be bound to the recovery case's historic
-- session, and must not include an invented cursor. The observation stream proves
-- the run was accepted into the observation pipeline with the same coordinates.
-- The current worker session proves the worker is alive and not quarantined.
--
-- Future adoptions are only permitted when all three conditions hold. This makes
-- the recovery adoption commit an atomic fact that can never be partially satisfied.

LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_submission_recovery_adoptions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_streams IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION asf_assert_run_worker_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Standard live-session check: permits any run bound to an active, unexpired
    -- session for the same worker and generation.
    IF asf_live_worker_session(
        NEW.tenant_id,
        NEW.worker_session_id,
        NEW.worker_id,
        NEW.worker_generation
    ) THEN
        RETURN NEW;
    END IF;

    -- Historical exception: INSERT-only for a run that is exactly an authoritative
    -- ADOPTED run named by a matching recovery adoption fact. Never permits UPDATE,
    -- as sessions can never be rebound onto a historical exception.
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

CREATE FUNCTION asf_guard_runmill_recovery_adoption_historical_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authoritative_run runs%ROWTYPE;
    observation_stream runmill_run_observation_streams%ROWTYPE;
    current_worker_session worker_sessions%ROWTYPE;
    worker_row workers%ROWTYPE;
BEGIN
    -- Verify: an exact authoritative ADOPTED run exists with all adoption coordinates,
    -- external ID, worker identity, historic session binding, matching aggregate_version
    -- (run_state_version), and last_event_sequence <= latest_sequence (no cursor invention).
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
      AND run.state = NEW.run_state
      AND run.state = 'ADOPTED'
      AND run.authoritative = true
      AND run.aggregate_version = NEW.run_state_version
      AND run.last_event_sequence <= NEW.latest_sequence
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent, non-authoritative, non-ADOPTED, or invalid-cursor run'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_authoritative_run';
    END IF;

    -- Verify: an exact matching runmill_run_observation_streams row exists with all
    -- coordinates, payload digest, worker generation, run-admission session, and external ID.
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
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'adoption references a non-existent or mismatched observation stream'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_recovery_adoption_exact_observation_stream';
    END IF;

    -- Verify: a currently active, unexpired worker session exists for the same tenant,
    -- worker, and generation. The historic session bound to the adoption itself may be
    -- CLOSED after a worker restart; we never mutate it. This check verifies the worker
    -- remains healthy.
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

    -- Verify: the current worker entry has a generation that matches the adoption.
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

-- Deferred constraint trigger: verified at commit time, after the Rust application
-- has created the run and observation stream rows. The FOR SHARE locks prevent
-- concurrent modifications while the authority check proceeds.
CREATE CONSTRAINT TRIGGER runmill_recovery_adoption_historical_session_guard
    AFTER INSERT ON runmill_submission_recovery_adoptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_recovery_adoption_historical_session();
