-- Runmill submission recovery cases capture the state of externally-sent
-- work orders when the submission's outcome is ambiguous (already reached Runmill,
-- but the effect intent status is unresolved). A recovery case is recovery-only:
-- it cannot be sent, retried, or streamed. It exists solely for exact reconciliation
-- by read-side observability of the external Runmill state against the persisted
-- immutable request identifiers. One case per tenant/effect.
--
-- Apply with executors quiesced so the table lock preserves the global
-- effect -> recovery case ordering used by recovery reconciliation.
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE runmill_submission_recovery_cases (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    effect_intent_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    work_order_id uuid NOT NULL,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    remote_idempotency_key text NOT NULL,
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    worker_session_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'PENDING_EXTERNAL_LOOKUP'
        CHECK (state = 'PENDING_EXTERNAL_LOOKUP'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, effect_intent_id),
    UNIQUE (tenant_id, work_item_id, attempt_id),
    FOREIGN KEY (tenant_id, effect_intent_id)
        REFERENCES effect_intents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, attempt_id)
        REFERENCES attempts(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_order_id)
        REFERENCES work_orders(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_id)
        REFERENCES workers(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_session_id, worker_id, worker_generation)
        REFERENCES worker_sessions(tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    CHECK (btrim(payload_digest) <> ''),
    CHECK (btrim(request_digest) <> ''),
    CHECK (btrim(remote_idempotency_key) <> '')
);

COMMENT ON TABLE runmill_submission_recovery_cases IS
    'Captures immutable submission state for recovery-only reconciliation of ambiguous Runmill submissions. One case per tenant/effect.';
COMMENT ON COLUMN runmill_submission_recovery_cases.effect_intent_id IS
    'The effect intent in AMBIGUOUS status whose submission outcome is being reconciled.';
COMMENT ON COLUMN runmill_submission_recovery_cases.work_item_id IS
    'The work item that sourced the submission, denormalized for lookup efficiency.';
COMMENT ON COLUMN runmill_submission_recovery_cases.attempt_id IS
    'The attempt that authored the submission, denormalized for lookup efficiency.';
COMMENT ON COLUMN runmill_submission_recovery_cases.work_order_id IS
    'The exact work order that was submitted to Runmill, immutable.';
COMMENT ON COLUMN runmill_submission_recovery_cases.payload_digest IS
    'The SHA-256 digest of the work order payload, immutable, enables exact lookup.';
COMMENT ON COLUMN runmill_submission_recovery_cases.request_digest IS
    'The SHA-256 digest of the exact signed envelope sent to Runmill, immutable.';
COMMENT ON COLUMN runmill_submission_recovery_cases.remote_idempotency_key IS
    'The idempotency key sent to Runmill, used to match the submission against external state.';
COMMENT ON COLUMN runmill_submission_recovery_cases.worker_id IS
    'The worker that owned the submission effect, denormalized for validation.';
COMMENT ON COLUMN runmill_submission_recovery_cases.worker_generation IS
    'The generation of the owning worker, must match the session generation.';
COMMENT ON COLUMN runmill_submission_recovery_cases.worker_session_id IS
    'The session of the owning worker that authorized the submission.';
COMMENT ON COLUMN runmill_submission_recovery_cases.state IS
    'The state of the recovery case. Always PENDING_EXTERNAL_LOOKUP; never changes.';

-- Validate that the linked effect intent is in the exact state required for recovery:
-- status must be AMBIGUOUS, provider must be runmill, effect_type must be submit_work_order,
-- and all immutable identifiers (work_order id/digest/request_digest) must match exactly.
-- Also validate that the work order idempotency key matches remote_idempotency_key,
-- and that the linked worker/session generation is exact.
CREATE FUNCTION asf_guard_runmill_recovery_case_validation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_effect effect_intents%ROWTYPE;
    linked_work_order work_orders%ROWTYPE;
    linked_session worker_sessions%ROWTYPE;
BEGIN
    -- Load the linked effect intent to validate exact ownership and state.
    SELECT effect.*
    INTO linked_effect
    FROM effect_intents AS effect
    WHERE effect.tenant_id = NEW.tenant_id
      AND effect.id = NEW.effect_intent_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery case has no linked effect intent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_effect';
    END IF;

    -- The effect must be for exactly this tenant, work item, and attempt.
    IF linked_effect.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR linked_effect.work_item_id IS DISTINCT FROM NEW.work_item_id
       OR linked_effect.attempt_id IS DISTINCT FROM NEW.attempt_id THEN
        RAISE EXCEPTION 'recovery case effect intent does not match tenant/work_item/attempt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_effect_binding';
    END IF;

    -- The effect must be in AMBIGUOUS status for a Runmill submission.
    IF linked_effect.provider IS DISTINCT FROM 'runmill'
       OR linked_effect.effect_type IS DISTINCT FROM 'submit_work_order'
       OR linked_effect.status IS DISTINCT FROM 'AMBIGUOUS' THEN
        RAISE EXCEPTION 'recovery case effect intent is not an ambiguous Runmill submission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_effect_state';
    END IF;

    -- Load the linked work order to validate matching identifiers.
    SELECT work_order.*
    INTO linked_work_order
    FROM work_orders AS work_order
    WHERE work_order.tenant_id = NEW.tenant_id
      AND work_order.id = NEW.work_order_id
      AND work_order.payload_digest = NEW.payload_digest;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery case has no exact immutable work order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_work_order';
    END IF;

    -- The work order must be for exactly this attempt.
    IF linked_work_order.work_item_id IS DISTINCT FROM NEW.work_item_id
       OR linked_work_order.attempt_id IS DISTINCT FROM NEW.attempt_id THEN
        RAISE EXCEPTION 'recovery case work order does not match attempt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_work_order_binding';
    END IF;

    -- The linked effect must have the exact same work order reference.
    IF linked_effect.work_order_id IS DISTINCT FROM NEW.work_order_id
       OR linked_effect.work_order_digest IS DISTINCT FROM NEW.payload_digest THEN
        RAISE EXCEPTION 'recovery case work order contradicts the linked effect intent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_effect_work_order';
    END IF;

    -- The linked effect must have the exact same request digest.
    IF linked_effect.request_digest IS DISTINCT FROM NEW.request_digest THEN
        RAISE EXCEPTION 'recovery case request digest contradicts the linked effect intent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_effect_request';
    END IF;

    -- The remote idempotency key must exactly match the work order idempotency key.
    IF linked_work_order.idempotency_key IS DISTINCT FROM NEW.remote_idempotency_key THEN
        RAISE EXCEPTION 'recovery case remote idempotency key does not match work order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_idempotency';
    END IF;

    -- Load the linked worker session to validate exact generation match.
    SELECT session.*
    INTO linked_session
    FROM worker_sessions AS session
    WHERE session.tenant_id = NEW.tenant_id
      AND session.id = NEW.worker_session_id
      AND session.worker_id = NEW.worker_id
      AND session.worker_generation = NEW.worker_generation;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery case has no exact linked worker session'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_worker_session';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_submission_recovery_cases_exact_validation
    BEFORE INSERT OR UPDATE ON runmill_submission_recovery_cases
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_recovery_case_validation();

-- Validate that recovery cases have not been populated with contradictory data
-- before the immutability trigger is installed.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runmill_submission_recovery_cases AS case_row
        WHERE NOT EXISTS (
            SELECT 1
            FROM effect_intents AS effect
            WHERE effect.tenant_id = case_row.tenant_id
              AND effect.id = case_row.effect_intent_id
              AND effect.work_item_id = case_row.work_item_id
              AND effect.attempt_id = case_row.attempt_id
              AND effect.provider = 'runmill'
              AND effect.effect_type = 'submit_work_order'
              AND effect.status = 'AMBIGUOUS'
              AND effect.work_order_id = case_row.work_order_id
              AND effect.work_order_digest = case_row.payload_digest
              AND effect.request_digest = case_row.request_digest
        )
        OR NOT EXISTS (
            SELECT 1
            FROM work_orders AS work_order
            WHERE work_order.tenant_id = case_row.tenant_id
              AND work_order.id = case_row.work_order_id
              AND work_order.payload_digest = case_row.payload_digest
              AND work_order.work_item_id = case_row.work_item_id
              AND work_order.attempt_id = case_row.attempt_id
              AND work_order.idempotency_key = case_row.remote_idempotency_key
        )
        OR NOT EXISTS (
            SELECT 1
            FROM worker_sessions AS session
            WHERE session.tenant_id = case_row.tenant_id
              AND session.id = case_row.worker_session_id
              AND session.worker_id = case_row.worker_id
              AND session.worker_generation = case_row.worker_generation
        )
    ) THEN
        RAISE EXCEPTION 'recovery case is contradictory with its linked entities'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_exact_validation';
    END IF;
END;
$$;

-- Recovery cases are immutable except for the updated_at timestamp. State is locked to
-- PENDING_EXTERNAL_LOOKUP and cannot be changed; all other columns are immutable.
CREATE FUNCTION asf_guard_runmill_recovery_case_immutability() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'recovery cases cannot be deleted'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_immutable';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.effect_intent_id IS DISTINCT FROM OLD.effect_intent_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.work_order_id IS DISTINCT FROM OLD.work_order_id
       OR NEW.payload_digest IS DISTINCT FROM OLD.payload_digest
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.remote_idempotency_key IS DISTINCT FROM OLD.remote_idempotency_key
       OR NEW.worker_id IS DISTINCT FROM OLD.worker_id
       OR NEW.worker_generation IS DISTINCT FROM OLD.worker_generation
       OR NEW.worker_session_id IS DISTINCT FROM OLD.worker_session_id
       OR NEW.state IS DISTINCT FROM OLD.state
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'recovery case is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_submission_recovery_cases_immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_submission_recovery_cases_immutable
    BEFORE UPDATE OR DELETE ON runmill_submission_recovery_cases
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_recovery_case_immutability();

-- Indexes for efficient recovery case lookup and state queries.
CREATE UNIQUE INDEX runmill_submission_recovery_cases_effect_intent_idx
    ON runmill_submission_recovery_cases (tenant_id, effect_intent_id);

CREATE UNIQUE INDEX runmill_submission_recovery_cases_attempt_idx
    ON runmill_submission_recovery_cases (tenant_id, work_item_id, attempt_id);

CREATE INDEX runmill_submission_recovery_cases_work_order_idx
    ON runmill_submission_recovery_cases (tenant_id, work_order_id);

CREATE INDEX runmill_submission_recovery_cases_state_idx
    ON runmill_submission_recovery_cases (tenant_id, state, created_at)
    WHERE state = 'PENDING_EXTERNAL_LOOKUP';

CREATE INDEX runmill_submission_recovery_cases_worker_session_idx
    ON runmill_submission_recovery_cases (tenant_id, worker_session_id, id);
