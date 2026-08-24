-- Prevent a direct ledger writer from pre-occupying the deterministic key
-- that a future reservation-expiry sweep must use.  The table-level CHECK
-- binds the key text to the event row; this trigger additionally binds the
-- row to the exact, already-applied reservation-set transition.
CREATE FUNCTION asf_guard_internal_reservation_event_key() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_state text;
    bound_fence bigint;
    bound_transition_key text;
    bound_released_at timestamptz;
    bound_released_by text;
    bound_release_reason text;
    expected_transition_key text;
BEGIN
    IF NEW.idempotency_key NOT LIKE 'asf-internal:%' THEN
        RETURN NEW;
    END IF;

    SELECT
        reservation_set.state,
        reservation_set.fence_token,
        reservation_set.transition_idempotency_key,
        reservation_set.released_at,
        reservation_set.released_by,
        reservation_set.release_reason
    INTO
        bound_state,
        bound_fence,
        bound_transition_key,
        bound_released_at,
        bound_released_by,
        bound_release_reason
    FROM reservation_sets AS reservation_set
    WHERE reservation_set.tenant_id = NEW.tenant_id
      AND reservation_set.id = NEW.reservation_set_id
    FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'ASF-internal reservation event has no exact reservation-set binding'
            USING ERRCODE = '23514';
    END IF;

    expected_transition_key :=
        'asf-internal:reservation-expiry:v1:' || NEW.reservation_set_id::text
        || ':fence:' || (bound_fence - 1)::text;

    IF bound_state <> 'EXPIRED'
       OR bound_transition_key IS DISTINCT FROM expected_transition_key
       OR NEW.idempotency_key <> expected_transition_key
       OR NEW.event_type <> 'EXPIRED'
       OR NEW.previous_fence_token <> bound_fence - 1
       OR NEW.fence_token <> bound_fence
       OR NEW.actor_id IS DISTINCT FROM bound_released_by
       OR NEW.reason IS DISTINCT FROM bound_release_reason
       OR NEW.occurred_at IS DISTINCT FROM bound_released_at THEN
        RAISE EXCEPTION 'ASF-internal reservation event contradicts its reservation set/fence'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER reservation_set_events_internal_key_guard
    BEFORE INSERT ON reservation_set_events
    FOR EACH ROW EXECUTE FUNCTION asf_guard_internal_reservation_event_key();

-- A capacity reservation owns at most one acquisition and one release entry.
-- Consumption and adjustment entries remain append-only and may occur more
-- than once, but they cannot impersonate either ownership transition.
CREATE UNIQUE INDEX budget_ledger_one_reservation_transition_idx
    ON budget_ledger (tenant_id, reservation_id, entry_type)
    WHERE reservation_id IS NOT NULL
      AND entry_type IN ('RESERVE', 'RELEASE');

-- Any ledger row linked to a budget reservation must carry the reservation
-- set's exact work/attempt/dimension coordinate.  RESERVE and RELEASE rows
-- additionally bind their amount, key, and database timestamp to the owning
-- set transition.  This applies to caller keys as well as ASF-internal keys.
CREATE FUNCTION asf_guard_reservation_budget_ledger_binding() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_kind text;
    bound_dimension text;
    bound_units bigint;
    bound_work_item_id uuid;
    bound_attempt_id uuid;
    bound_set_state text;
    bound_admission_key text;
    bound_acquired_at timestamptz;
    bound_transition_key text;
    bound_released_at timestamptz;
    expected_key text;
    expected_unit text;
BEGIN
    IF NEW.reservation_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT
        reservation.kind,
        reservation.budget_dimension,
        reservation.units,
        reservation_set.work_item_id,
        reservation_set.attempt_id,
        reservation_set.state,
        reservation_set.idempotency_key,
        reservation_set.acquired_at,
        reservation_set.transition_idempotency_key,
        reservation_set.released_at
    INTO
        bound_kind,
        bound_dimension,
        bound_units,
        bound_work_item_id,
        bound_attempt_id,
        bound_set_state,
        bound_admission_key,
        bound_acquired_at,
        bound_transition_key,
        bound_released_at
    FROM reservations AS reservation
    JOIN reservation_sets AS reservation_set
      ON reservation_set.tenant_id = reservation.tenant_id
     AND reservation_set.id = reservation.reservation_set_id
    WHERE reservation.tenant_id = NEW.tenant_id
      AND reservation.id = NEW.reservation_id
    FOR KEY SHARE OF reservation, reservation_set;

    IF NOT FOUND OR bound_kind <> 'BUDGET' THEN
        RAISE EXCEPTION 'budget-ledger reservation link has no exact budget reservation'
            USING ERRCODE = '23514';
    END IF;

    expected_unit := CASE bound_dimension
        WHEN 'COST_MICROUNITS' THEN 'microunits'
        WHEN 'INPUT_TOKENS' THEN 'tokens'
        WHEN 'OUTPUT_TOKENS' THEN 'tokens'
        WHEN 'IMPLEMENTER_INVOCATIONS' THEN 'invocations'
        WHEN 'REVIEWER_INVOCATIONS' THEN 'invocations'
        WHEN 'FIX_ITERATIONS' THEN 'iterations'
        WHEN 'WALL_TIME_SECONDS' THEN 'seconds'
        WHEN 'EXTERNAL_API_CALLS' THEN 'calls'
        ELSE NULL
    END;

    IF NEW.work_item_id IS DISTINCT FROM bound_work_item_id
       OR NEW.attempt_id IS DISTINCT FROM bound_attempt_id
       OR NEW.scope_type <> 'ATTEMPT'
       OR NEW.scope_id <> bound_attempt_id::text
       OR NEW.dimension <> bound_dimension
       OR NEW.unit IS DISTINCT FROM expected_unit THEN
        RAISE EXCEPTION 'budget-ledger row contradicts its reservation coordinate'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.entry_type = 'RESERVE' THEN
        expected_key := bound_admission_key || ':budget-reserve:' || bound_dimension;
        IF bound_set_state <> 'ACTIVE'
           OR NEW.amount <> bound_units
           OR NEW.idempotency_key <> expected_key
           OR NEW.occurred_at IS DISTINCT FROM bound_acquired_at THEN
            RAISE EXCEPTION 'budget RESERVE row contradicts its admission transition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.entry_type = 'RELEASE' THEN
        expected_key := bound_transition_key || ':budget-release:' || bound_dimension;
        IF bound_set_state NOT IN ('RELEASED', 'EXPIRED')
           OR bound_transition_key IS NULL
           OR bound_released_at IS NULL
           OR NEW.amount <> bound_units
           OR NEW.idempotency_key <> expected_key
           OR NEW.occurred_at IS DISTINCT FROM bound_released_at THEN
            RAISE EXCEPTION 'budget RELEASE row contradicts its terminal transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- Trigger names determine order for the same event/timing in PostgreSQL.  The
-- `zz` prefix places this after budget_ledger_serializes_with_admission, so the
-- shared advisory lock is always acquired before this function row-locks the
-- reservation and its set.
CREATE TRIGGER budget_ledger_zz_reservation_binding_guard
    BEFORE INSERT ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION asf_guard_reservation_budget_ledger_binding();

ALTER TABLE reservation_sets
    ADD CONSTRAINT reservation_sets_terminal_transition_time CHECK (
        state = 'ACTIVE'
        OR (state = 'RELEASED' AND released_at >= acquired_at)
        OR (state = 'EXPIRED' AND released_at >= expires_at)
    );

-- Rebuild the deferred parent proof so a set cannot commit without its exact
-- transition event and one exact accounting row for every budget reservation.
CREATE OR REPLACE FUNCTION asf_assert_reservation_set_event() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    required_event_type text;
    required_previous_fence bigint;
    required_idempotency_key text;
    required_actor_id text;
    required_reason text;
    required_occurred_at timestamptz;
BEGIN
    IF NEW.state = 'ACTIVE' THEN
        required_event_type := 'ACQUIRED';
        required_previous_fence := 0;
        required_idempotency_key := NEW.idempotency_key;
        required_actor_id := NEW.acquired_by;
        required_reason := 'atomic admission acquired';
        required_occurred_at := NEW.acquired_at;
    ELSE
        required_event_type := NEW.state;
        required_previous_fence := NEW.fence_token - 1;
        required_idempotency_key := NEW.transition_idempotency_key;
        required_actor_id := NEW.released_by;
        required_reason := NEW.release_reason;
        required_occurred_at := NEW.released_at;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM reservation_set_events AS event
        WHERE event.tenant_id = NEW.tenant_id
          AND event.reservation_set_id = NEW.id
          AND event.event_type = required_event_type
          AND event.previous_fence_token = required_previous_fence
          AND event.fence_token = NEW.fence_token
          AND event.actor_id = required_actor_id
          AND event.reason = required_reason
          AND event.idempotency_key = required_idempotency_key
          AND event.occurred_at = required_occurred_at
    ) THEN
        RAISE EXCEPTION 'reservation set % has no exact matching fenced audit event', NEW.id
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM reservations AS reservation
        WHERE reservation.tenant_id = NEW.tenant_id
          AND reservation.reservation_set_id = NEW.id
          AND reservation.kind = 'BUDGET'
          AND NOT EXISTS (
              SELECT 1
              FROM budget_ledger AS entry
              WHERE entry.tenant_id = reservation.tenant_id
                AND entry.reservation_id = reservation.id
                AND entry.work_item_id = NEW.work_item_id
                AND entry.attempt_id = NEW.attempt_id
                AND entry.scope_type = 'ATTEMPT'
                AND entry.scope_id = NEW.attempt_id::text
                AND entry.dimension = reservation.budget_dimension
                AND entry.entry_type = 'RESERVE'
                AND entry.amount = reservation.units
                AND entry.idempotency_key =
                    NEW.idempotency_key || ':budget-reserve:'
                    || reservation.budget_dimension
                AND entry.occurred_at = NEW.acquired_at
          )
    ) THEN
        RAISE EXCEPTION 'reservation set % has incomplete budget RESERVE accounting', NEW.id
            USING ERRCODE = '23514';
    END IF;

    IF NEW.state <> 'ACTIVE' AND EXISTS (
        SELECT 1
        FROM reservations AS reservation
        WHERE reservation.tenant_id = NEW.tenant_id
          AND reservation.reservation_set_id = NEW.id
          AND reservation.kind = 'BUDGET'
          AND NOT EXISTS (
              SELECT 1
              FROM budget_ledger AS entry
              WHERE entry.tenant_id = reservation.tenant_id
                AND entry.reservation_id = reservation.id
                AND entry.work_item_id = NEW.work_item_id
                AND entry.attempt_id = NEW.attempt_id
                AND entry.scope_type = 'ATTEMPT'
                AND entry.scope_id = NEW.attempt_id::text
                AND entry.dimension = reservation.budget_dimension
                AND entry.entry_type = 'RELEASE'
                AND entry.amount = reservation.units
                AND entry.idempotency_key =
                    NEW.transition_idempotency_key || ':budget-release:'
                    || reservation.budget_dimension
                AND entry.occurred_at = NEW.released_at
          )
    ) THEN
        RAISE EXCEPTION 'reservation set % has incomplete budget RELEASE accounting', NEW.id
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END;
$$;

-- A budget reservation inserted after its parent row must queue the same
-- deferred completeness proof; otherwise a late child could evade the parent
-- trigger that was checked at the set's earlier commit.
CREATE FUNCTION asf_assert_budget_reservation_accounting() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_set reservation_sets%ROWTYPE;
BEGIN
    IF NEW.kind <> 'BUDGET' THEN
        RETURN NULL;
    END IF;

    SELECT *
    INTO parent_set
    FROM reservation_sets AS reservation_set
    WHERE reservation_set.tenant_id = NEW.tenant_id
      AND reservation_set.id = NEW.reservation_set_id;

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

CREATE CONSTRAINT TRIGGER budget_reservations_require_accounting
    AFTER INSERT ON reservations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_budget_reservation_accounting();
