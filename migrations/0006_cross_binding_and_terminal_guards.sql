-- Raw events must come from the exact worker session that owns their run, not
-- merely from any live same-tenant session.  This also makes the immutable
-- `(run, sequence)` slot impossible to poison with another worker's envelope.
ALTER TABLE runs
    ADD CONSTRAINT runs_event_worker_binding_unique
    UNIQUE (tenant_id, id, worker_session_id, worker_id, worker_generation);

ALTER TABLE raw_run_events
    ADD CONSTRAINT raw_run_events_run_worker_binding_fk
    FOREIGN KEY (
        tenant_id,
        run_id,
        worker_session_id,
        worker_id,
        worker_generation
    )
    REFERENCES runs (
        tenant_id,
        id,
        worker_session_id,
        worker_id,
        worker_generation
    )
    ON DELETE RESTRICT;

-- A row lock refreshes a waiter at READ COMMITTED, but REPEATABLE READ keeps
-- its transaction snapshot.  Give every validated budget-child insertion a
-- real parent-row version change so a terminal writer with an older snapshot
-- receives a serialization failure instead of overlooking the committed
-- child.  The guarded pulse changes no admission or terminal semantics.
ALTER TABLE reservation_sets
    ADD COLUMN budget_accounting_version bigint NOT NULL DEFAULT 0
        CHECK (budget_accounting_version >= 0);

CREATE OR REPLACE FUNCTION asf_guard_reservation_set_update() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.worker_id IS DISTINCT FROM OLD.worker_id
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

-- A late budget child and a concurrent terminal parent transition must not
-- both validate against different MVCC snapshots.  The deferred child proof
-- advances the parent's accounting version before deciding whether RELEASE
-- accounting is required.  READ COMMITTED waiters recheck the new row;
-- stricter old-snapshot writers fail serialization on the changed version.
CREATE OR REPLACE FUNCTION asf_assert_budget_reservation_accounting() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_set reservation_sets%ROWTYPE;
BEGIN
    IF NEW.kind <> 'BUDGET' THEN
        RETURN NULL;
    END IF;

    UPDATE reservation_sets AS reservation_set
    SET budget_accounting_version =
        reservation_set.budget_accounting_version + 1
    WHERE reservation_set.tenant_id = NEW.tenant_id
      AND reservation_set.id = NEW.reservation_set_id
      AND reservation_set.state = 'ACTIVE'
    RETURNING reservation_set.* INTO parent_set;

    IF NOT FOUND THEN
        SELECT *
        INTO parent_set
        FROM reservation_sets AS reservation_set
        WHERE reservation_set.tenant_id = NEW.tenant_id
          AND reservation_set.id = NEW.reservation_set_id
        FOR UPDATE;
    END IF;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM budget_ledger AS entry
        WHERE entry.tenant_id = NEW.tenant_id
          AND entry.reservation_id = NEW.id
          AND entry.work_item_id = parent_set.work_item_id
          AND entry.attempt_id = parent_set.attempt_id
          AND entry.scope_type = 'ATTEMPT'
          AND entry.scope_id = parent_set.attempt_id::text
          AND entry.dimension = NEW.budget_dimension
          AND entry.entry_type = 'RESERVE'
          AND entry.amount = NEW.units
          AND entry.idempotency_key =
              parent_set.idempotency_key || ':budget-reserve:' || NEW.budget_dimension
          AND entry.occurred_at = parent_set.acquired_at
    ) THEN
        RAISE EXCEPTION 'budget reservation % has no exact RESERVE accounting row', NEW.id
            USING ERRCODE = '23514';
    END IF;

    IF parent_set.state <> 'ACTIVE' AND NOT EXISTS (
        SELECT 1
        FROM budget_ledger AS entry
        WHERE entry.tenant_id = NEW.tenant_id
          AND entry.reservation_id = NEW.id
          AND entry.work_item_id = parent_set.work_item_id
          AND entry.attempt_id = parent_set.attempt_id
          AND entry.scope_type = 'ATTEMPT'
          AND entry.scope_id = parent_set.attempt_id::text
          AND entry.dimension = NEW.budget_dimension
          AND entry.entry_type = 'RELEASE'
          AND entry.amount = NEW.units
          AND entry.idempotency_key =
              parent_set.transition_idempotency_key || ':budget-release:'
              || NEW.budget_dimension
          AND entry.occurred_at = parent_set.released_at
    ) THEN
        RAISE EXCEPTION 'budget reservation % has no exact RELEASE accounting row', NEW.id
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END;
$$;

-- CANCELLED is terminal just like COMPLETED and DEAD.  Request identity stays
-- immutable for every job; no terminal job can be resurrected or rewritten.
CREATE OR REPLACE FUNCTION asf_guard_workflow_job_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow jobs cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('COMPLETED', 'DEAD', 'CANCELLED')
       AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal workflow jobs are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.workflow_instance_id,
        NEW.work_item_id,
        NEW.attempt_id,
        NEW.job_type,
        NEW.payload,
        NEW.idempotency_key,
        NEW.priority,
        NEW.max_attempts,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.workflow_instance_id,
        OLD.work_item_id,
        OLD.attempt_id,
        OLD.job_type,
        OLD.payload,
        OLD.idempotency_key,
        OLD.priority,
        OLD.max_attempts,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'workflow job identity and request fields are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- Observed/cancelled effects are semantic receipts.  Retryable effect states
-- may advance lease/error fields, but terminal outcomes cannot be reopened or
-- rewritten.  The original request-identity protections remain unchanged.
CREATE OR REPLACE FUNCTION asf_guard_effect_intent_update() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'effect intents cannot be deleted'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_identity_request_immutable';
    END IF;
    IF OLD.status IN ('OBSERVED', 'CANCELLED') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal effect intents are immutable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'effect_intents_terminal_immutable';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.effect_type IS DISTINCT FROM OLD.effect_type
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.correlation_marker IS DISTINCT FROM OLD.correlation_marker
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_payload IS DISTINCT FROM OLD.request_payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'effect intent identity and request are immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_identity_request_immutable';
    END IF;
    RETURN NEW;
END;
$$;
