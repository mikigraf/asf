-- Preserve three authority facts reciprocally:
--
-- * an admission reservation cannot outlive the exact worker session that
--   authorized it;
-- * quarantined workers cannot continue to submit runs or raw events through
--   an otherwise-live session; and
-- * a run mutation cannot invalidate evidence that already closed a source
--   obligation.
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_sets IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM reservation_sets AS reservation_set
        LEFT JOIN worker_sessions AS session
          ON session.tenant_id = reservation_set.tenant_id
         AND session.id = reservation_set.worker_session_id
         AND session.worker_id = reservation_set.worker_id
         AND session.worker_generation = reservation_set.worker_generation
        WHERE reservation_set.state = 'ACTIVE'
          AND (
              reservation_set.worker_session_id IS NULL
              OR reservation_set.worker_generation IS NULL
              OR session.id IS NULL
              OR session.status <> 'ACTIVE'
              OR reservation_set.expires_at > session.expires_at
          )
    ) THEN
        RAISE EXCEPTION 'active reservation lacks full-lifetime worker-session authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_sets_require_full_session_lifetime';
    END IF;
END;
$$;

-- Direct SQL session creators take the same first lock as application
-- admission and worker reconciliation.  This prevents a new session or
-- admission from appearing between quarantine validation and revocation.
CREATE FUNCTION asf_lock_worker_session_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'worker-authority:' || NEW.tenant_id::text || ':' || NEW.worker_id::text,
        0
    ));
    RETURN NEW;
END;
$$;

CREATE TRIGGER a_worker_session_authority_lock
    BEFORE INSERT ON worker_sessions
    FOR EACH ROW EXECUTE FUNCTION asf_lock_worker_session_authority();

CREATE OR REPLACE FUNCTION asf_assert_reservation_worker_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_worker_status text;
    current_worker_generation bigint;
    current_session_status text;
    current_session_expiry timestamptz;
BEGIN
    IF NEW.worker_session_id IS NULL OR NEW.worker_generation IS NULL THEN
        RAISE EXCEPTION 'new reservation set requires an exact worker session binding'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'worker-authority:' || NEW.tenant_id::text || ':' || NEW.worker_id::text,
        0
    ));

    SELECT worker.status, worker.generation
    INTO current_worker_status, current_worker_generation
    FROM workers AS worker
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
    FOR UPDATE;

    IF NOT FOUND
       OR current_worker_status <> 'READY'
       OR current_worker_generation <> NEW.worker_generation THEN
        RAISE EXCEPTION 'reservation worker is not READY at the requested generation'
            USING ERRCODE = '40001';
    END IF;

    SELECT session.status, session.expires_at
    INTO current_session_status, current_session_expiry
    FROM worker_sessions AS session
    WHERE session.tenant_id = NEW.tenant_id
      AND session.id = NEW.worker_session_id
      AND session.worker_id = NEW.worker_id
      AND session.worker_generation = NEW.worker_generation
    FOR UPDATE;

    IF NOT FOUND
       OR current_session_status <> 'ACTIVE'
       OR current_session_expiry <= clock_timestamp()
       OR NEW.expires_at > current_session_expiry THEN
        RAISE EXCEPTION 'reservation worker session is absent, stale, inactive, or shorter than the reservation'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'reservation_sets_require_full_session_lifetime';
    END IF;

    RETURN NEW;
END;
$$;

-- A session cannot be closed, revoked, or shortened while any durable ACTIVE
-- reservation still names it.  The quarantine activity first performs the
-- existing fenced reservation transition (including budget RELEASE entries),
-- then revokes the session in the same transaction.
CREATE FUNCTION asf_assert_session_preserves_reservations() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM reservation_sets AS reservation_set
        WHERE reservation_set.tenant_id = OLD.tenant_id
          AND reservation_set.worker_session_id = OLD.id
          AND reservation_set.worker_id = OLD.worker_id
          AND reservation_set.worker_generation = OLD.worker_generation
          AND reservation_set.state = 'ACTIVE'
          AND (
              NEW.status <> 'ACTIVE'
              OR reservation_set.expires_at > NEW.expires_at
          )
    ) THEN
        RAISE EXCEPTION 'worker-session mutation would sever an active reservation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'worker_sessions_preserve_active_reservations';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER worker_sessions_preserve_active_reservations
    AFTER UPDATE ON worker_sessions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_session_preserves_reservations();

CREATE OR REPLACE FUNCTION asf_live_worker_session(
    candidate_tenant uuid,
    candidate_session uuid,
    candidate_worker uuid,
    candidate_generation bigint
) RETURNS boolean
LANGUAGE sql
VOLATILE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM worker_sessions AS session
        JOIN workers AS worker
          ON worker.tenant_id = session.tenant_id
         AND worker.id = session.worker_id
        WHERE session.tenant_id = candidate_tenant
          AND session.id = candidate_session
          AND session.worker_id = candidate_worker
          AND session.worker_generation = candidate_generation
          AND session.status = 'ACTIVE'
          AND session.expires_at > clock_timestamp()
          AND worker.generation = candidate_generation
          AND worker.status <> 'QUARANTINED'
    );
$$;

-- Runs are mutable while work is progressing, but once their exact evidence
-- participates in a CLOSED Linear chain they may no longer be rewritten into
-- a fact that makes that chain false.
CREATE FUNCTION asf_assert_run_preserves_observed_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_bundles AS evidence
        JOIN work_items AS work
          ON work.tenant_id = evidence.tenant_id
         AND work.id = evidence.work_item_id
        WHERE evidence.tenant_id = OLD.tenant_id
          AND evidence.run_id = OLD.id
          AND work.state = 'CLOSED'
          AND NOT asf_observed_source_closure_is_valid(work.tenant_id, work.id)
    ) THEN
        RAISE EXCEPTION 'run mutation would sever an observed source closure'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER runs_preserve_observed_source_closure
    AFTER UPDATE OR DELETE ON runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_run_preserves_observed_source_closure();
