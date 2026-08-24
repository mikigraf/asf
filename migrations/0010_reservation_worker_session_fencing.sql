-- Admission is authorized by one concrete, expiring worker session, not only
-- by a reusable worker identity and generation.  Historical reservation sets
-- predate this binding and cannot be reconstructed safely, so they retain
-- NULL provenance; every new row is required to carry the exact binding by
-- the insert guard below.
ALTER TABLE reservation_sets
    ADD COLUMN worker_session_id uuid,
    ADD COLUMN worker_generation bigint,
    ADD CONSTRAINT reservation_sets_worker_session_pair CHECK (
        (worker_session_id IS NULL) = (worker_generation IS NULL)
        AND (worker_generation IS NULL OR worker_generation > 0)
    ),
    ADD CONSTRAINT reservation_sets_worker_session_fk
        FOREIGN KEY (
            tenant_id,
            worker_session_id,
            worker_id,
            worker_generation
        )
        REFERENCES worker_sessions (
            tenant_id,
            id,
            worker_id,
            worker_generation
        )
        ON DELETE RESTRICT;

CREATE INDEX reservation_sets_worker_session_idx
    ON reservation_sets (tenant_id, worker_session_id, id)
    WHERE worker_session_id IS NOT NULL;

-- Lock both the worker epoch and the exact session until the admission
-- transaction commits.  A concurrent quarantine/generation change or session
-- close/revoke must therefore serialize before or after this proof; it cannot
-- race between validation and insertion.
CREATE FUNCTION asf_assert_reservation_worker_session() RETURNS trigger
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
       OR current_session_expiry <= clock_timestamp() THEN
        RAISE EXCEPTION 'reservation worker session is absent, stale, or inactive'
            USING ERRCODE = '40001';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER reservation_sets_worker_session_guard
    BEFORE INSERT ON reservation_sets
    FOR EACH ROW EXECUTE FUNCTION asf_assert_reservation_worker_session();

-- The exact session and generation are part of immutable admission semantics.
-- Keep the budget-accounting pulse and fenced terminal transition behavior
-- introduced in migration 0006 unchanged.
CREATE OR REPLACE FUNCTION asf_guard_reservation_set_update() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.worker_id IS DISTINCT FROM OLD.worker_id
       OR NEW.worker_session_id IS DISTINCT FROM OLD.worker_session_id
       OR NEW.worker_generation IS DISTINCT FROM OLD.worker_generation
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.acquired_by IS DISTINCT FROM OLD.acquired_by
       OR NEW.acquired_at IS DISTINCT FROM OLD.acquired_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'reservation-set admission semantics are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.state = 'ACTIVE'
       AND NEW.state = 'ACTIVE'
       AND NEW.id = OLD.id
       AND NEW.fence_token = OLD.fence_token
       AND NEW.released_at IS NOT DISTINCT FROM OLD.released_at
       AND NEW.released_by IS NOT DISTINCT FROM OLD.released_by
       AND NEW.release_reason IS NOT DISTINCT FROM OLD.release_reason
       AND NEW.transition_idempotency_key
            IS NOT DISTINCT FROM OLD.transition_idempotency_key
       AND NEW.budget_accounting_version = OLD.budget_accounting_version + 1 THEN
        RETURN NEW;
    END IF;

    IF OLD.state <> 'ACTIVE'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.state NOT IN ('RELEASED', 'EXPIRED')
       OR NEW.fence_token <> OLD.fence_token + 1
       OR NEW.budget_accounting_version <> OLD.budget_accounting_version THEN
        RAISE EXCEPTION 'reservation-set transition is stale or invalid'
            USING ERRCODE = '40001';
    END IF;
    RETURN NEW;
END;
$$;
