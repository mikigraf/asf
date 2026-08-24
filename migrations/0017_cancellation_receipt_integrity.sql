-- Cancellation is authority-bearing, not merely a terminal state.  Preserve
-- the exact dispatch boundary, every Runmill observation, and the final
-- local decision as immutable relational receipts.
--
-- Apply with executors quiesced.  The lock order matches the runtime:
-- workflow job -> work item -> dispatch guard -> attempt/run/effect.
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_timers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_sets IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_set_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE approvals IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE budget_ledger IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE operational_incidents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE outbox IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE idempotency_records IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE accountability_anchors IN SHARE ROW EXCLUSIVE MODE;

-- Reproduce the stable UUID construction used by the Rust cancellation path.
-- These identities are part of the idempotency contract, not caller-chosen
-- labels that a coherent direct writer may substitute.
CREATE FUNCTION asf_uuid_from_digest_prefix(candidate bytea) RETURNS uuid
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    bytes bytea;
    encoded text;
BEGIN
    IF octet_length(candidate) < 16 THEN
        RAISE EXCEPTION 'stable UUID input is shorter than 16 bytes'
            USING ERRCODE = '22000';
    END IF;
    bytes := substring(candidate FROM 1 FOR 16);
    bytes := set_byte(bytes, 6, (get_byte(bytes, 6) & 15) | 128);
    bytes := set_byte(bytes, 8, (get_byte(bytes, 8) & 63) | 128);
    encoded := encode(bytes, 'hex');
    RETURN (
        substring(encoded FROM 1 FOR 8) || '-' ||
        substring(encoded FROM 9 FOR 4) || '-' ||
        substring(encoded FROM 13 FOR 4) || '-' ||
        substring(encoded FROM 17 FOR 4) || '-' ||
        substring(encoded FROM 21 FOR 12)
    )::uuid;
END;
$$;

CREATE FUNCTION asf_derived_uuid(candidate uuid, discriminator integer)
RETURNS uuid
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    bytes bytea := uuid_send(candidate);
BEGIN
    IF discriminator NOT BETWEEN 0 AND 255 THEN
        RAISE EXCEPTION 'stable UUID discriminator is outside one byte'
            USING ERRCODE = '22000';
    END IF;
    bytes := set_byte(
        bytes, 15, get_byte(bytes, 15) # discriminator
    );
    RETURN asf_uuid_from_digest_prefix(bytes);
END;
$$;

CREATE FUNCTION asf_stable_cancellation_receipt_uuid(
    receipt_namespace text,
    workflow_job_id uuid,
    workflow_job_fence_token bigint
) RETURNS uuid
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
DECLARE
    identity_bytes bytea;
BEGIN
    IF receipt_namespace IS NULL OR workflow_job_id IS NULL THEN
        RETURN NULL;
    END IF;
    identity_bytes := convert_to(receipt_namespace, 'UTF8') || uuid_send(workflow_job_id);
    IF workflow_job_fence_token IS NOT NULL THEN
        identity_bytes := identity_bytes || int8send(workflow_job_fence_token);
    END IF;
    RETURN asf_uuid_from_digest_prefix(sha256(identity_bytes));
END;
$$;

-- Pre-0017 rows do not contain enough information to reconstruct either the
-- leased claim which observed Runmill or the negative dispatch proof used by
-- synchronous cancellation.  Refuse the upgrade instead of inventing it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM work_items WHERE state = 'CANCELLED'
    ) OR EXISTS (
        SELECT 1 FROM accountability_anchors WHERE anchor_type = 'CANCELLATION'
    ) OR EXISTS (
        SELECT 1
        FROM effect_intents
        WHERE provider = 'runmill'
          AND effect_type = 'request_cancellation'
          AND status IN ('OBSERVED', 'CANCELLED')
    ) OR EXISTS (
        SELECT 1
        FROM workflow_jobs
        WHERE job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND status = 'COMPLETED'
    ) OR EXISTS (
        SELECT 1
        FROM audit_events
        WHERE action IN (
            'WORK_ITEM_CANCELLED',
            'work_item.cancelled',
            'RUNMILL_CANCELLATION_ALREADY_TERMINAL'
        )
    ) OR EXISTS (
        SELECT 1
        FROM runs
        WHERE snapshot ? 'runmill_cancellation'
    ) THEN
        RAISE EXCEPTION
            'historical cancellation provenance cannot be reconstructed safely'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_receipt_upgrade_requires_exact_history';
    END IF;
END;
$$;

-- One row is the predicate lock for the absence of dispatch facts.  Once a
-- fact is seen, dispatch_started can never return to false.
CREATE TABLE work_dispatch_fact_guards (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    dispatch_started boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, work_item_id),
    UNIQUE (tenant_id, work_item_id, generation),
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT
);

INSERT INTO work_dispatch_fact_guards (
    tenant_id, work_item_id, generation, dispatch_started
)
SELECT
    work.tenant_id,
    work.id,
    CASE WHEN facts.dispatch_started THEN 2 ELSE 1 END,
    facts.dispatch_started
FROM work_items AS work
CROSS JOIN LATERAL (
    SELECT
        EXISTS (SELECT 1 FROM attempts WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM workflow_timers WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM reservation_sets WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM effect_intents WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM runs WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM work_orders WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM approvals WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM evidence_bundles WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM escalations WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (SELECT 1 FROM budget_ledger WHERE tenant_id = work.tenant_id AND work_item_id = work.id)
        OR EXISTS (
            SELECT 1
            FROM operational_incidents AS incident
            JOIN workflow_jobs AS incident_job
              ON incident_job.tenant_id = incident.tenant_id
             AND incident_job.id = incident.workflow_job_id
            WHERE incident_job.tenant_id = work.tenant_id
              AND incident_job.work_item_id = work.id
        )
        OR EXISTS (
            SELECT 1
            FROM workflow_instances AS workflow
            WHERE workflow.tenant_id = work.tenant_id
              AND workflow.work_item_id = work.id
              AND workflow.workflow_type <> 'WORK_ITEM_DELIVERY'
        )
        OR EXISTS (
            SELECT 1
            FROM workflow_jobs AS job
            WHERE job.tenant_id = work.tenant_id
              AND job.work_item_id = work.id
              AND NOT (
                  job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
                  AND job.attempt_id IS NULL
                  AND job.status IN ('PENDING', 'RETRY')
                  AND job.attempt_count < job.max_attempts
                  AND job.result IS NULL
                  AND job.lease_owner IS NULL
                  AND job.lease_expires_at IS NULL
                  AND job.completed_by IS NULL
                  AND job.completion_fence_token IS NULL
                  AND job.completed_at IS NULL
              )
        ) AS dispatch_started
) AS facts;

CREATE FUNCTION asf_create_work_dispatch_fact_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO work_dispatch_fact_guards (tenant_id, work_item_id)
    VALUES (NEW.tenant_id, NEW.id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER work_items_create_dispatch_fact_guard
    AFTER INSERT ON work_items
    FOR EACH ROW EXECUTE FUNCTION asf_create_work_dispatch_fact_guard();

CREATE FUNCTION asf_guard_work_dispatch_fact_guard_update() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.dispatch_started AND NOT NEW.dispatch_started)
       OR NEW.generation <> OLD.generation + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'work dispatch-fact guards are monotonic'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'work_dispatch_fact_guards_monotonic';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = OLD.tenant_id
          AND receipt.work_item_id = OLD.work_item_id
          AND receipt.route = 'PRE_DISPATCH'
    ) THEN
        RAISE EXCEPTION 'a terminal pre-dispatch proof freezes its dispatch guard'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_dispatch_fact_guards_preserve_pre_dispatch_receipt';
    END IF;
    RETURN NEW;
END;
$$;

-- The terminal-receipt table is created below.  Install this trigger after it
-- exists; the function body is resolved when invoked.

CREATE FUNCTION asf_note_work_dispatch_fact() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_work uuid;
    locked_work uuid;
    new_row jsonb := to_jsonb(NEW);
BEGIN
    candidate_work := NEW.work_item_id;
    IF candidate_work IS NULL THEN
        RETURN NEW;
    END IF;

    -- The initial delivery workflow and its pristine ADVANCE job are the
    -- acceptance obligation, not evidence that dispatch began.
    IF TG_TABLE_NAME = 'workflow_instances' THEN
        IF new_row ->> 'workflow_type' = 'WORK_ITEM_DELIVERY'
           AND NOT EXISTS (
               SELECT 1 FROM workflow_instances
               WHERE tenant_id = NEW.tenant_id AND work_item_id = candidate_work
           ) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_TABLE_NAME = 'workflow_jobs' THEN
        IF new_row ->> 'job_type' = 'ADVANCE_ACCEPTED_WORK_ITEM'
           AND new_row ->> 'attempt_id' IS NULL
           AND new_row ->> 'status' IN ('PENDING', 'RETRY')
           AND (new_row ->> 'attempt_count')::integer <
               (new_row ->> 'max_attempts')::integer
           AND new_row ->> 'result' IS NULL
           AND new_row ->> 'lease_owner' IS NULL
           AND new_row ->> 'lease_expires_at' IS NULL
           AND new_row ->> 'completed_by' IS NULL
           AND new_row ->> 'completion_fence_token' IS NULL
           AND new_row ->> 'completed_at' IS NULL
           AND EXISTS (
               SELECT 1
               FROM workflow_instances AS workflow
               WHERE workflow.tenant_id = NEW.tenant_id
                 AND workflow.id =
                     NULLIF(new_row ->> 'workflow_instance_id', '')::uuid
                 AND workflow.work_item_id = candidate_work
                 AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
           )
           AND NOT EXISTS (
               SELECT 1 FROM workflow_jobs
               WHERE tenant_id = NEW.tenant_id AND work_item_id = candidate_work
           ) THEN
            RETURN NEW;
        END IF;
    END IF;

    -- Once the monotonic boundary has crossed, later lifecycle writes add no
    -- information to the negative proof.  Avoid turning every claim/heartbeat
    -- batch into parent-work locks and a hot guard-row rewrite.
    IF EXISTS (
        SELECT 1
        FROM work_dispatch_fact_guards AS guard
        WHERE guard.tenant_id = NEW.tenant_id
          AND guard.work_item_id = candidate_work
          AND guard.dispatch_started
    ) THEN
        RETURN NEW;
    END IF;

    -- Deadlock-critical order: parent work first, guard second.
    SELECT id INTO locked_work
    FROM work_items
    WHERE tenant_id = NEW.tenant_id AND id = candidate_work
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.work_item_id = candidate_work
          AND receipt.route = 'PRE_DISPATCH'
    ) THEN
        RAISE EXCEPTION 'dispatch fact cannot follow terminal pre-dispatch cancellation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'dispatch_facts_preserve_pre_dispatch_receipt';
    END IF;

    UPDATE work_dispatch_fact_guards
    SET dispatch_started = true,
        generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id AND work_item_id = candidate_work;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'work item has no dispatch-fact guard'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_dispatch_fact_guard';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER attempts_note_dispatch_fact BEFORE INSERT ON attempts
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER workflow_instances_note_dispatch_fact BEFORE INSERT ON workflow_instances
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER workflow_jobs_note_dispatch_fact BEFORE INSERT ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER workflow_timers_note_dispatch_fact BEFORE INSERT ON workflow_timers
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER reservation_sets_note_dispatch_fact BEFORE INSERT ON reservation_sets
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER effect_intents_note_dispatch_fact BEFORE INSERT ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER runs_note_dispatch_fact BEFORE INSERT ON runs
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER work_orders_note_dispatch_fact BEFORE INSERT ON work_orders
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER approvals_note_dispatch_fact BEFORE INSERT ON approvals
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER evidence_bundles_note_dispatch_fact BEFORE INSERT ON evidence_bundles
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER escalations_note_dispatch_fact BEFORE INSERT ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();
CREATE TRIGGER budget_ledger_note_dispatch_fact BEFORE INSERT ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact();

-- One durable row serializes the creation of new execution authority with a
-- terminal cancellation receipt.  Unlike a commit-time advisory lock, the
-- immediate row update participates in PostgreSQL's normal MVCC conflict
-- machinery: READ COMMITTED follows the winning row version and stronger
-- isolation levels fail with a serialization error instead of admitting a
-- write skew.
CREATE TABLE work_cancellation_authority_guards (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    terminal_receipt_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, work_item_id),
    UNIQUE (tenant_id, work_item_id, generation),
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT
);

INSERT INTO work_cancellation_authority_guards (tenant_id, work_item_id)
SELECT tenant_id, id FROM work_items;

CREATE FUNCTION asf_create_work_cancellation_authority_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO work_cancellation_authority_guards (tenant_id, work_item_id)
    VALUES (NEW.tenant_id, NEW.id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER work_items_create_cancellation_authority_guard
    AFTER INSERT ON work_items
    FOR EACH ROW EXECUTE FUNCTION asf_create_work_cancellation_authority_guard();

CREATE FUNCTION asf_guard_work_cancellation_authority_update() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.generation <> OLD.generation + 1
       OR NEW.updated_at < OLD.updated_at
       OR OLD.terminal_receipt_id IS NOT NULL THEN
        RAISE EXCEPTION 'work cancellation-authority guards are monotonic and terminal'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'work_cancellation_authority_guards_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER work_cancellation_authority_guards_monotonic
    BEFORE UPDATE OR DELETE ON work_cancellation_authority_guards
    FOR EACH ROW EXECUTE FUNCTION asf_guard_work_cancellation_authority_update();
CREATE TRIGGER work_cancellation_authority_guards_truncate_forbidden
    BEFORE TRUNCATE ON work_cancellation_authority_guards
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE FUNCTION asf_cancellation_authority_row_is_live(
    candidate_table text,
    candidate_row jsonb
) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT CASE candidate_table
        WHEN 'attempts' THEN candidate_row ->> 'state' IN (
            'CREATED', 'AUTHORIZED', 'DISPATCHING', 'RUNNING',
            'VERIFYING', 'WAITING_APPROVAL', 'CANCEL_REQUESTED'
        )
        WHEN 'runs' THEN candidate_row ->> 'state' IN (
            'ADOPTED', 'RUNNING', 'WAITING_APPROVAL', 'VERIFYING',
            'CANCEL_REQUESTED'
        )
        WHEN 'workflow_instances' THEN
            candidate_row ->> 'state' IN ('ACTIVE', 'WAITING')
        WHEN 'workflow_jobs' THEN
            candidate_row ->> 'status' IN ('PENDING', 'RUNNING', 'RETRY')
        WHEN 'workflow_timers' THEN
            candidate_row ->> 'status' = 'SCHEDULED'
        WHEN 'effect_intents' THEN candidate_row ->> 'status' IN (
            'PENDING', 'IN_FLIGHT', 'AMBIGUOUS'
        )
        WHEN 'reservation_sets' THEN candidate_row ->> 'state' = 'ACTIVE'
        WHEN 'approvals' THEN candidate_row ->> 'status' = 'PENDING'
        WHEN 'escalations' THEN
            candidate_row ->> 'status' IN ('OPEN', 'ACKNOWLEDGED')
            AND candidate_row ->> 'authority_or_effect_active' = 'true'
        WHEN 'work_orders' THEN true
        ELSE false
    END;
$$;

CREATE FUNCTION asf_note_cancellation_authority_fact() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_row jsonb := '{}'::jsonb;
    new_row jsonb := to_jsonb(NEW);
    candidate_work uuid := NULLIF(new_row ->> 'work_item_id', '')::uuid;
    old_live boolean := false;
    new_live boolean := asf_cancellation_authority_row_is_live(
        TG_TABLE_NAME, new_row
    );
BEGIN
    IF candidate_work IS NULL OR NOT new_live THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        old_row := to_jsonb(OLD);
        old_live := asf_cancellation_authority_row_is_live(
            TG_TABLE_NAME, old_row
        );
        IF old_live
           AND ROW(NEW.tenant_id, candidate_work) IS NOT DISTINCT FROM
               ROW(
                   OLD.tenant_id,
                   NULLIF(old_row ->> 'work_item_id', '')::uuid
               ) THEN
            RETURN NEW;
        END IF;
    END IF;

    UPDATE work_cancellation_authority_guards
    SET generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id
      AND work_item_id = candidate_work
      AND terminal_receipt_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'live execution authority cannot follow terminal cancellation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_authority_facts_preserve_terminal_receipt';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER attempts_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON attempts
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER runs_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON runs
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER workflow_instances_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON workflow_instances
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER workflow_jobs_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER workflow_timers_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON workflow_timers
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER effect_intents_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER reservation_sets_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON reservation_sets
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER approvals_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON approvals
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER escalations_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();
CREATE TRIGGER work_orders_zz_note_cancellation_authority
    AFTER INSERT OR UPDATE ON work_orders
    FOR EACH ROW EXECUTE FUNCTION asf_note_cancellation_authority_fact();

CREATE FUNCTION asf_note_reopened_work_cancellation_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state IS NOT DISTINCT FROM OLD.state OR NEW.state = 'CANCELLED' THEN
        RETURN NEW;
    END IF;
    UPDATE work_cancellation_authority_guards
    SET generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id
      AND work_item_id = NEW.id
      AND terminal_receipt_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cancelled work item cannot be reopened'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_preserve_terminal_cancellation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER work_items_note_reopened_cancellation_authority
    AFTER UPDATE ON work_items
    FOR EACH ROW EXECUTE FUNCTION asf_note_reopened_work_cancellation_authority();

-- Operational incidents are the tenant-scoped DEAD-job ownership route;
-- work-bound jobs use escalations.  Enforce that existing architecture here
-- so an incident cannot appear as an unguarded indirect work-item phantom.
CREATE FUNCTION asf_operational_incident_requires_tenant_job() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_jobs AS job
        WHERE job.tenant_id = NEW.tenant_id
          AND job.id = NEW.workflow_job_id
          AND job.work_item_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'work-bound workflow jobs require an escalation, not an operational incident'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'operational_incidents_require_tenant_scoped_job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER operational_incidents_require_tenant_scoped_job
    BEFORE INSERT OR UPDATE ON operational_incidents
    FOR EACH ROW EXECUTE FUNCTION asf_operational_incident_requires_tenant_job();

ALTER TABLE effect_intents
    ADD COLUMN initial_cancellation_observation_id uuid;

CREATE TABLE runmill_cancellation_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    run_id uuid NOT NULL,
    effect_intent_id uuid NOT NULL,
    workflow_instance_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    workflow_job_fence_token bigint NOT NULL CHECK (workflow_job_fence_token > 0),
    workflow_job_attempt_count integer NOT NULL CHECK (workflow_job_attempt_count > 0),
    workflow_job_owner text NOT NULL CHECK (btrim(workflow_job_owner) <> ''),
    route text NOT NULL CHECK (route IN ('INITIAL', 'OBSERVER')),
    prior_observation_id uuid,
    request_id text NOT NULL CHECK (btrim(request_id) <> ''),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    disposition text NOT NULL CHECK (disposition IN ('REQUESTED', 'EXISTING', 'ALREADY_TERMINAL')),
    external_phase text NOT NULL CHECK (external_phase IN (
        'CANCEL_REQUESTED', 'CANCELLING', 'SUCCEEDED', 'FAILED',
        'REFUSED', 'QUARANTINED', 'CANCELLED'
    )),
    external_generation bigint NOT NULL
        CHECK (external_generation BETWEEN 1 AND 9007199254740991),
    external_state_version bigint NOT NULL
        CHECK (external_state_version BETWEEN 1 AND 9007199254740991),
    external_latest_sequence bigint NOT NULL
        CHECK (
            external_latest_sequence BETWEEN 1 AND 9007199254740991
            AND external_latest_sequence = external_state_version
        ),
    reconciliation_required boolean NOT NULL,
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, id, effect_intent_id, work_item_id, attempt_id),
    UNIQUE (tenant_id, id, effect_intent_id, work_item_id, attempt_id, run_id),
    UNIQUE (tenant_id, workflow_job_id, workflow_job_fence_token),
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
        REFERENCES attempts(tenant_id, id, work_item_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, run_id, work_item_id, attempt_id)
        REFERENCES runs(tenant_id, id, work_item_id, attempt_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, effect_intent_id)
        REFERENCES effect_intents(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, workflow_instance_id, work_item_id)
        REFERENCES workflow_instances(tenant_id, id, work_item_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (route = 'INITIAL' AND prior_observation_id IS NULL)
        OR (route = 'OBSERVER' AND prior_observation_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX runmill_cancellation_one_initial_observation
    ON runmill_cancellation_observations (tenant_id, effect_intent_id)
    WHERE route = 'INITIAL';
CREATE UNIQUE INDEX runmill_cancellation_observation_one_successor
    ON runmill_cancellation_observations (tenant_id, prior_observation_id)
    WHERE prior_observation_id IS NOT NULL;

ALTER TABLE runmill_cancellation_observations
    ADD CONSTRAINT runmill_cancellation_observation_prior_fk
    FOREIGN KEY (
        tenant_id, prior_observation_id, effect_intent_id,
        work_item_id, attempt_id, run_id
    ) REFERENCES runmill_cancellation_observations (
        tenant_id, id, effect_intent_id, work_item_id, attempt_id, run_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE effect_intents
    ADD CONSTRAINT effect_intents_initial_cancellation_observation_fk
    FOREIGN KEY (tenant_id, initial_cancellation_observation_id, id, work_item_id, attempt_id)
    REFERENCES runmill_cancellation_observations (
        tenant_id, id, effect_intent_id, work_item_id, attempt_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT effect_intents_observed_cancellation_has_initial_receipt CHECK (
        (
            provider = 'runmill'
            AND effect_type = 'request_cancellation'
            AND status = 'OBSERVED'
            AND initial_cancellation_observation_id IS NOT NULL
        ) OR (
            (provider <> 'runmill' OR effect_type <> 'request_cancellation' OR status <> 'OBSERVED')
            AND initial_cancellation_observation_id IS NULL
        )
    );

CREATE FUNCTION asf_stamp_runmill_cancellation_observation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    prior runmill_cancellation_observations%ROWTYPE;
BEGIN
    PERFORM 1
    FROM workflow_jobs AS job
    WHERE job.tenant_id = NEW.tenant_id
      AND job.id = NEW.workflow_job_id
      AND job.workflow_instance_id = NEW.workflow_instance_id
      AND job.work_item_id = NEW.work_item_id
      AND job.attempt_id = NEW.attempt_id
      AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
      AND job.status = 'RUNNING'
      AND job.fence_token = NEW.workflow_job_fence_token
      AND job.attempt_count = NEW.workflow_job_attempt_count
      AND job.lease_owner = NEW.workflow_job_owner
      AND job.lease_expires_at > transaction_timestamp()
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill cancellation observation lacks its exact live workflow claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_cancellation_observations_exact_provenance';
    END IF;
    PERFORM 1
    FROM runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.authoritative
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill cancellation observation lacks its authoritative run'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_cancellation_observations_exact_provenance';
    END IF;
    PERFORM 1
    FROM effect_intents AS effect
    WHERE effect.tenant_id = NEW.tenant_id
      AND effect.id = NEW.effect_intent_id
      AND effect.work_item_id = NEW.work_item_id
      AND effect.attempt_id = NEW.attempt_id
      AND effect.provider = 'runmill'
      AND effect.effect_type = 'request_cancellation'
      AND effect.request_digest = NEW.request_digest
      AND effect.correlation_marker = NEW.request_id
      AND (
          (NEW.route = 'INITIAL' AND effect.status = 'IN_FLIGHT'
             AND effect.owning_workflow_job_id = NEW.workflow_job_id
             AND effect.fence_token = NEW.workflow_job_fence_token
             AND effect.lease_owner = NEW.workflow_job_owner)
          OR (NEW.route = 'OBSERVER' AND effect.status = 'OBSERVED')
      )
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill cancellation observation lacks its exact effect request'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_cancellation_observations_exact_provenance';
    END IF;

    IF NEW.id IS DISTINCT FROM asf_stable_cancellation_receipt_uuid(
           'asf.runmill-cancellation-observation/v1',
           NEW.workflow_job_id,
           NEW.workflow_job_fence_token
       )
       OR NEW.effect_intent_id IS DISTINCT FROM asf_derived_uuid(NEW.run_id, 4)
       OR (
           NEW.route = 'INITIAL'
           AND (
               (
                   NEW.disposition IN ('REQUESTED', 'EXISTING')
                   AND NEW.external_phase NOT IN (
                       'CANCEL_REQUESTED', 'CANCELLING',
                       'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED',
                       'CANCELLED'
                   )
               ) OR (
                   NEW.disposition = 'ALREADY_TERMINAL'
                   AND NEW.external_phase NOT IN (
                       'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED', 'CANCELLED'
                   )
               )
           )
       )
       OR NEW.observed_at NOT BETWEEN clock_timestamp() - interval '5 minutes'
                                  AND clock_timestamp() + interval '5 minutes'
       OR NOT EXISTS (
           SELECT 1
           FROM workflow_jobs AS job
           WHERE job.tenant_id = NEW.tenant_id
             AND job.id = NEW.workflow_job_id
             AND job.workflow_instance_id = NEW.workflow_instance_id
             AND job.work_item_id = NEW.work_item_id
             AND job.attempt_id = NEW.attempt_id
             AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
             AND job.status = 'RUNNING'
             AND job.fence_token = NEW.workflow_job_fence_token
             AND job.attempt_count = NEW.workflow_job_attempt_count
             AND job.lease_owner = NEW.workflow_job_owner
             AND job.lease_expires_at > transaction_timestamp()
       ) OR NOT EXISTS (
           SELECT 1
           FROM runs AS run
           WHERE run.tenant_id = NEW.tenant_id
             AND run.id = NEW.run_id
             AND run.work_item_id = NEW.work_item_id
             AND run.attempt_id = NEW.attempt_id
             AND run.authoritative
       ) OR NOT EXISTS (
           SELECT 1
           FROM effect_intents AS effect
           WHERE effect.tenant_id = NEW.tenant_id
             AND effect.id = NEW.effect_intent_id
             AND effect.work_item_id = NEW.work_item_id
             AND effect.attempt_id = NEW.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
             AND effect.request_digest = NEW.request_digest
             AND effect.correlation_marker = NEW.request_id
             AND (
                 (NEW.route = 'INITIAL' AND effect.status = 'IN_FLIGHT'
                    AND effect.owning_workflow_job_id = NEW.workflow_job_id
                    AND effect.fence_token = NEW.workflow_job_fence_token
                    AND effect.lease_owner = NEW.workflow_job_owner)
                 OR (NEW.route = 'OBSERVER' AND effect.status = 'OBSERVED')
             )
       ) THEN
        RAISE EXCEPTION 'Runmill cancellation observation lacks an exact live claim/effect/run'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_cancellation_observations_exact_provenance';
    END IF;

    IF NEW.route = 'OBSERVER' THEN
        SELECT * INTO prior
        FROM runmill_cancellation_observations AS observation
        WHERE observation.tenant_id = NEW.tenant_id
          AND observation.id = NEW.prior_observation_id
          AND observation.effect_intent_id = NEW.effect_intent_id
        FOR SHARE;
        IF NOT FOUND
           OR EXISTS (
               SELECT 1 FROM runmill_cancellation_observations AS successor
               WHERE successor.tenant_id = prior.tenant_id
                 AND successor.prior_observation_id = prior.id
           )
           OR prior.external_generation <> NEW.external_generation
           OR NEW.external_latest_sequence < prior.external_latest_sequence
           OR NEW.disposition <> prior.disposition
           OR NEW.reconciliation_required <> prior.reconciliation_required
           OR NEW.request_id <> prior.request_id
           OR NEW.request_digest <> prior.request_digest
           OR NEW.workflow_instance_id <> prior.workflow_instance_id
           OR NEW.observed_at < prior.observed_at
           OR prior.external_phase NOT IN ('CANCEL_REQUESTED', 'CANCELLING')
           OR (
               NEW.external_phase = prior.external_phase
               AND NEW.external_state_version < prior.external_state_version
           )
           OR (
               NEW.external_phase <> prior.external_phase
               AND NEW.external_state_version <= prior.external_state_version
           )
           OR (
               prior.external_phase = 'CANCELLING'
               AND NEW.external_phase = 'CANCEL_REQUESTED'
           ) THEN
            RAISE EXCEPTION 'Runmill cancellation observation does not extend the exact monotonic tail'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_cancellation_observations_monotonic_chain';
        END IF;
    END IF;

    NEW.recorded_at := clock_timestamp();
    NEW.receipt_digest := 'sha256:' || encode(sha256(convert_to(
        jsonb_build_object(
            'schema', 'asf.runmill-cancellation-observation-receipt/v1',
            'id', NEW.id,
            'tenant_id', NEW.tenant_id,
            'work_item_id', NEW.work_item_id,
            'attempt_id', NEW.attempt_id,
            'run_id', NEW.run_id,
            'effect_intent_id', NEW.effect_intent_id,
            'workflow_instance_id', NEW.workflow_instance_id,
            'workflow_job_id', NEW.workflow_job_id,
            'workflow_job_fence_token', NEW.workflow_job_fence_token,
            'workflow_job_attempt_count', NEW.workflow_job_attempt_count,
            'workflow_job_owner', NEW.workflow_job_owner,
            'route', NEW.route,
            'prior_observation_id', NEW.prior_observation_id,
            'request_id', NEW.request_id,
            'request_digest', NEW.request_digest,
            'disposition', NEW.disposition,
            'external_phase', NEW.external_phase,
            'external_generation', NEW.external_generation,
            'external_state_version', NEW.external_state_version,
            'external_latest_sequence', NEW.external_latest_sequence,
            'reconciliation_required', NEW.reconciliation_required,
            'observed_at', NEW.observed_at
        )::text, 'UTF8'
    )), 'hex');
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_cancellation_observations_stamp
    BEFORE INSERT ON runmill_cancellation_observations
    FOR EACH ROW EXECUTE FUNCTION asf_stamp_runmill_cancellation_observation();
CREATE TRIGGER runmill_cancellation_observations_append_only
    BEFORE UPDATE OR DELETE ON runmill_cancellation_observations
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER runmill_cancellation_observations_truncate_forbidden
    BEFORE TRUNCATE ON runmill_cancellation_observations
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TABLE cancellation_terminal_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    route text NOT NULL CHECK (route IN ('PRE_DISPATCH', 'RUNMILL')),
    outcome text NOT NULL CHECK (outcome IN ('CANCELLED', 'TERMINAL_CONFLICT')),
    attempt_id uuid,
    run_id uuid,
    effect_intent_id uuid,
    terminal_observation_id uuid,
    workflow_instance_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    workflow_job_fence_token bigint NOT NULL CHECK (workflow_job_fence_token >= 0),
    workflow_job_attempt_count integer NOT NULL CHECK (workflow_job_attempt_count >= 0),
    workflow_job_completed_by text,
    audit_event_id uuid NOT NULL,
    outbox_event_id uuid NOT NULL,
    idempotency_record_id uuid,
    escalation_id uuid,
    work_item_version_before bigint NOT NULL CHECK (work_item_version_before > 0),
    work_item_version_after bigint NOT NULL CHECK (work_item_version_after > 0),
    attempt_version_before bigint,
    attempt_version_after bigint,
    attempt_fence_token bigint,
    run_version_before bigint,
    run_version_after bigint,
    workflow_version_before bigint NOT NULL CHECK (workflow_version_before > 0),
    workflow_version_after bigint NOT NULL CHECK (workflow_version_after > 0),
    workflow_fence_before bigint NOT NULL CHECK (workflow_fence_before >= 0),
    workflow_fence_after bigint NOT NULL CHECK (workflow_fence_after >= 0),
    anchor_generation_before bigint NOT NULL CHECK (anchor_generation_before > 0),
    anchor_generation_after bigint NOT NULL CHECK (anchor_generation_after > 0),
    dispatch_guard_generation bigint CHECK (dispatch_guard_generation > 0),
    cancellation_authority_generation bigint CHECK (
        cancellation_authority_generation IS NULL
        OR cancellation_authority_generation > 0
    ),
    released_reservations bigint NOT NULL CHECK (released_reservations >= 0),
    audit_before_digest text CHECK (
        audit_before_digest IS NULL OR audit_before_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    audit_after_digest text CHECK (
        audit_after_digest IS NULL OR audit_after_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, workflow_job_id),
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, workflow_instance_id, work_item_id)
        REFERENCES workflow_instances(tenant_id, id, work_item_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, audit_event_id)
        REFERENCES audit_events(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, outbox_event_id)
        REFERENCES outbox(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, idempotency_record_id)
        REFERENCES idempotency_records(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, escalation_id, work_item_id)
        REFERENCES escalations(tenant_id, id, work_item_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, terminal_observation_id, effect_intent_id, work_item_id, attempt_id, run_id)
        REFERENCES runmill_cancellation_observations(
            tenant_id, id, effect_intent_id, work_item_id, attempt_id, run_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (
            route = 'PRE_DISPATCH'
            AND outcome = 'CANCELLED'
            AND attempt_id IS NULL
            AND run_id IS NULL
            AND effect_intent_id IS NULL
            AND terminal_observation_id IS NULL
            AND workflow_job_completed_by IS NULL
            AND idempotency_record_id IS NOT NULL
            AND escalation_id IS NULL
            AND attempt_version_before IS NULL
            AND attempt_version_after IS NULL
            AND attempt_fence_token IS NULL
            AND run_version_before IS NULL
            AND run_version_after IS NULL
            AND dispatch_guard_generation IS NOT NULL
            AND cancellation_authority_generation IS NOT NULL
            AND released_reservations = 0
            AND audit_before_digest IS NOT NULL
            AND audit_after_digest IS NOT NULL
        ) OR (
            route = 'RUNMILL'
            AND attempt_id IS NOT NULL
            AND run_id IS NOT NULL
            AND effect_intent_id IS NOT NULL
            AND terminal_observation_id IS NOT NULL
            AND workflow_job_completed_by IS NOT NULL
            AND idempotency_record_id IS NULL
            AND attempt_version_before IS NOT NULL
            AND attempt_version_after IS NOT NULL
            AND attempt_fence_token IS NOT NULL
            AND run_version_before IS NOT NULL
            AND run_version_after IS NOT NULL
            AND dispatch_guard_generation IS NULL
            AND (
                (
                    outcome = 'CANCELLED'
                    AND escalation_id IS NULL
                    AND cancellation_authority_generation IS NOT NULL
                ) OR (
                    outcome = 'TERMINAL_CONFLICT'
                    AND escalation_id IS NOT NULL
                    AND cancellation_authority_generation IS NULL
                )
            )
        )
    )
);

CREATE UNIQUE INDEX cancellation_terminal_receipts_pre_dispatch_idempotency
    ON cancellation_terminal_receipts (tenant_id, idempotency_record_id)
    WHERE route = 'PRE_DISPATCH';
CREATE UNIQUE INDEX cancellation_terminal_receipts_runmill_observation
    ON cancellation_terminal_receipts (tenant_id, terminal_observation_id)
    WHERE route = 'RUNMILL';

ALTER TABLE work_cancellation_authority_guards
    ADD CONSTRAINT work_cancellation_authority_terminal_receipt_fk
    FOREIGN KEY (tenant_id, terminal_receipt_id)
    REFERENCES cancellation_terminal_receipts (tenant_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION asf_assert_terminal_cancellation_authority_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.terminal_receipt_id IS NULL THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.work_item_id = NEW.work_item_id
          AND receipt.id = NEW.terminal_receipt_id
          AND receipt.outcome = 'CANCELLED'
          AND receipt.cancellation_authority_generation = NEW.generation
    ) THEN
        RAISE EXCEPTION
            'work cancellation-authority guard lacks its exact terminal receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_cancellation_authority_guard_terminal_receipt';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER work_cancellation_authority_guard_requires_receipt
    AFTER UPDATE ON work_cancellation_authority_guards
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_terminal_cancellation_authority_guard();

-- A release counted by a Runmill terminal receipt must be born in the same
-- atomic commit as that receipt.  The deferred FK prevents an earlier
-- transaction from freeing capacity under the predictable cancellation key;
-- the closed CHECK reserves that namespace and binds it to the exact set
-- coordinate/fence.
ALTER TABLE reservation_sets
    ADD COLUMN cancellation_terminal_receipt_id uuid,
    ADD CONSTRAINT reservation_sets_cancellation_terminal_receipt_fk
        FOREIGN KEY (tenant_id, cancellation_terminal_receipt_id)
        REFERENCES cancellation_terminal_receipts (tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    -- Admission is caller-controlled.  It may not pre-occupy either
    -- deterministic terminal-release namespace in the set or event indexes.
    ADD CONSTRAINT reservation_sets_reserved_terminal_admission_namespace CHECK (
        idempotency_key NOT LIKE 'work-closure:v1:%'
        AND idempotency_key NOT LIKE 'runmill-cancellation:v1:%'
    ),
    -- Source closure has no separate receipt row: its complete observed
    -- closure graph is the receipt.  Close the key shape here and verify that
    -- graph in a deferred trigger below, after the atomic closure commit has
    -- finished constructing it.
    ADD CONSTRAINT reservation_sets_work_closure_release_provenance CHECK (
        transition_idempotency_key IS NULL
        OR transition_idempotency_key NOT LIKE 'work-closure:v1:%'
        OR (
            state = 'RELEASED'
            AND cancellation_terminal_receipt_id IS NULL
            AND transition_idempotency_key =
                'work-closure:v1:' || work_item_id::text || ':' ||
                attempt_id::text || ':' || id::text || ':fence:' ||
                (fence_token - 1)::text
            AND release_reason =
                'verified source closure completed the authoritative attempt'
        )
    ),
    ADD CONSTRAINT reservation_sets_cancellation_release_provenance CHECK (
        (
            cancellation_terminal_receipt_id IS NULL
            AND (
                transition_idempotency_key IS NULL
                OR transition_idempotency_key NOT LIKE
                    'runmill-cancellation:v1:%'
            )
        ) OR (
            cancellation_terminal_receipt_id IS NOT NULL
            AND state = 'RELEASED'
            AND transition_idempotency_key =
                'runmill-cancellation:v1:' || work_item_id::text || ':' ||
                attempt_id::text || ':' || id::text || ':fence:' ||
                (fence_token - 1)::text
            AND release_reason =
                'terminal Runmill cancellation observation completed the authoritative attempt'
        )
    );

-- The append-only event and budget ledgers share tenant-global uniqueness
-- domains with predictable terminal release keys.  Their row shapes must be
-- closed even when a direct writer bypasses Rust validation.
ALTER TABLE reservation_set_events
    ADD CONSTRAINT reservation_set_events_terminal_release_namespace CHECK (
        (
            idempotency_key NOT LIKE 'work-closure:v1:%'
            AND idempotency_key NOT LIKE 'runmill-cancellation:v1:%'
        ) OR event_type = 'RELEASED'
    );

ALTER TABLE budget_ledger
    ADD CONSTRAINT budget_ledger_terminal_release_namespace CHECK (
        (
            idempotency_key NOT LIKE 'work-closure:v1:%'
            AND idempotency_key NOT LIKE 'runmill-cancellation:v1:%'
        ) OR (
            entry_type = 'RELEASE'
            AND reservation_id IS NOT NULL
        )
    );

CREATE FUNCTION asf_assert_cancellation_reservation_release_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.cancellation_terminal_receipt_id IS NULL THEN
        RETURN NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        JOIN runmill_cancellation_observations AS observation
          ON observation.tenant_id = receipt.tenant_id
         AND observation.id = receipt.terminal_observation_id
         AND observation.work_item_id = receipt.work_item_id
         AND observation.attempt_id = receipt.attempt_id
        JOIN runs AS run
          ON run.tenant_id = receipt.tenant_id
         AND run.id = receipt.run_id
         AND run.work_item_id = receipt.work_item_id
         AND run.attempt_id = receipt.attempt_id
         AND run.authoritative
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.id = NEW.cancellation_terminal_receipt_id
          AND receipt.route = 'RUNMILL'
          AND receipt.work_item_id = NEW.work_item_id
          AND receipt.attempt_id = NEW.attempt_id
          AND NEW.worker_id = run.worker_id
          AND receipt.workflow_job_completed_by = NEW.released_by
          AND NEW.state = 'RELEASED'
          AND NEW.released_at BETWEEN
              observation.observed_at AND receipt.recorded_at
          AND receipt.released_reservations = (
              SELECT count(*)
              FROM reservation_sets AS released_set
              WHERE released_set.tenant_id = receipt.tenant_id
                AND released_set.work_item_id = receipt.work_item_id
                AND released_set.attempt_id = receipt.attempt_id
                AND released_set.state = 'RELEASED'
                AND released_set.worker_id = run.worker_id
                AND released_set.cancellation_terminal_receipt_id = receipt.id
                AND released_set.released_at BETWEEN
                    observation.observed_at AND receipt.recorded_at
                AND released_set.fence_token > 1
                AND released_set.transition_idempotency_key =
                    'runmill-cancellation:v1:' || receipt.work_item_id::text || ':' ||
                    receipt.attempt_id::text || ':' || released_set.id::text ||
                    ':fence:' || (released_set.fence_token - 1)::text
                AND released_set.released_by =
                    receipt.workflow_job_completed_by
                AND released_set.release_reason =
                    'terminal Runmill cancellation observation completed the authoritative attempt'
          )
    ) THEN
        RAISE EXCEPTION
            'Runmill cancellation reservation release lacks its exact terminal receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_sets_cancellation_release_provenance';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER reservation_sets_require_cancellation_release_provenance
    AFTER INSERT OR UPDATE ON reservation_sets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_cancellation_reservation_release_provenance();

-- A work-closure release is valid only in the atomic commit whose completed
-- job/effect/workflow graph reconstructs as the exact observed source-closure
-- receipt.  This also prevents a direct writer from releasing a set early to
-- occupy its predictable future transition key.
CREATE FUNCTION asf_work_closure_reservation_release_is_valid(
    candidate_tenant uuid,
    candidate_reservation_set uuid
) RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM reservation_sets AS reservation_set
        JOIN work_items AS work
          ON work.tenant_id = reservation_set.tenant_id
         AND work.id = reservation_set.work_item_id
         AND work.current_attempt_id = reservation_set.attempt_id
         AND work.state = 'CLOSED'
        JOIN workflow_jobs AS observing_job
          ON observing_job.tenant_id = reservation_set.tenant_id
         AND observing_job.work_item_id = reservation_set.work_item_id
         AND observing_job.attempt_id = reservation_set.attempt_id
         AND observing_job.job_type = 'CLOSE_SOURCE'
         AND observing_job.status = 'COMPLETED'
         AND observing_job.completed_by = reservation_set.released_by
         AND observing_job.result #>> '{result,schema}' =
             'asf.source-close-workflow-result.v1'
         AND observing_job.result #>> '{result,work_item_id}' =
             reservation_set.work_item_id::text
         AND observing_job.result #>> '{result,attempt_id}' =
             reservation_set.attempt_id::text
        JOIN effect_intents AS effect
          ON effect.tenant_id = reservation_set.tenant_id
         AND effect.work_item_id = reservation_set.work_item_id
         AND effect.attempt_id = reservation_set.attempt_id
         AND effect.provider = 'linear'
         AND effect.effect_type = 'close_source'
         AND effect.status = 'OBSERVED'
         AND effect.observing_workflow_job_id = observing_job.id
        JOIN runs AS run
          ON run.tenant_id = reservation_set.tenant_id
         AND run.work_item_id = reservation_set.work_item_id
         AND run.attempt_id = reservation_set.attempt_id
         AND run.authoritative
         AND run.id::text = observing_job.result #>> '{result,run_id}'
         AND run.worker_id = reservation_set.worker_id
        WHERE reservation_set.tenant_id = candidate_tenant
          AND reservation_set.id = candidate_reservation_set
          AND reservation_set.state = 'RELEASED'
          AND reservation_set.cancellation_terminal_receipt_id IS NULL
          AND reservation_set.fence_token > 1
          AND reservation_set.transition_idempotency_key =
              'work-closure:v1:' || reservation_set.work_item_id::text || ':' ||
              reservation_set.attempt_id::text || ':' ||
              reservation_set.id::text || ':fence:' ||
              (reservation_set.fence_token - 1)::text
          AND reservation_set.release_reason =
              'verified source closure completed the authoritative attempt'
          AND effect.observed_at <= reservation_set.released_at
          AND reservation_set.released_at <= observing_job.completed_at
          AND asf_observed_source_closure_is_valid(
              reservation_set.tenant_id,
              reservation_set.work_item_id
          )
    );
$$;

CREATE FUNCTION asf_assert_work_closure_reservation_release_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.transition_idempotency_key IS NULL
       OR NEW.transition_idempotency_key NOT LIKE 'work-closure:v1:%' THEN
        RETURN NULL;
    END IF;

    IF NOT asf_work_closure_reservation_release_is_valid(
        NEW.tenant_id,
        NEW.id
    ) THEN
        RAISE EXCEPTION
            'work-closure reservation release lacks its exact terminal closure proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_sets_work_closure_release_provenance';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER reservation_sets_require_work_closure_release_provenance
    AFTER INSERT OR UPDATE ON reservation_sets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_work_closure_reservation_release_provenance();

-- A reserved event key is accepted only after the exact parent transition has
-- been applied.  The parent's deferred provenance trigger then requires the
-- matching cancellation receipt or complete observed source-closure graph in
-- the same commit.  An insert against an ACTIVE or unrelated set therefore
-- cannot poison the append-only tenant-global event key.
CREATE FUNCTION asf_guard_terminal_reservation_event_key() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_work_item_id uuid;
    bound_attempt_id uuid;
    bound_state text;
    bound_fence bigint;
    bound_transition_key text;
    bound_released_at timestamptz;
    bound_released_by text;
    bound_release_reason text;
    bound_cancellation_receipt_id uuid;
    expected_transition_key text;
    expected_release_reason text;
    is_runmill_cancellation boolean;
BEGIN
    is_runmill_cancellation :=
        NEW.idempotency_key LIKE 'runmill-cancellation:v1:%';
    IF NOT is_runmill_cancellation
       AND NEW.idempotency_key NOT LIKE 'work-closure:v1:%' THEN
        RETURN NEW;
    END IF;

    SELECT
        reservation_set.work_item_id,
        reservation_set.attempt_id,
        reservation_set.state,
        reservation_set.fence_token,
        reservation_set.transition_idempotency_key,
        reservation_set.released_at,
        reservation_set.released_by,
        reservation_set.release_reason,
        reservation_set.cancellation_terminal_receipt_id
    INTO
        bound_work_item_id,
        bound_attempt_id,
        bound_state,
        bound_fence,
        bound_transition_key,
        bound_released_at,
        bound_released_by,
        bound_release_reason,
        bound_cancellation_receipt_id
    FROM reservation_sets AS reservation_set
    WHERE reservation_set.tenant_id = NEW.tenant_id
      AND reservation_set.id = NEW.reservation_set_id
    FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'terminal reservation event has no exact reservation-set binding'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_set_events_terminal_release_namespace';
    END IF;

    expected_transition_key := CASE
        WHEN is_runmill_cancellation THEN 'runmill-cancellation:v1:'
        ELSE 'work-closure:v1:'
    END || bound_work_item_id::text || ':' || bound_attempt_id::text || ':' ||
        NEW.reservation_set_id::text || ':fence:' || (bound_fence - 1)::text;
    expected_release_reason := CASE
        WHEN is_runmill_cancellation THEN
            'terminal Runmill cancellation observation completed the authoritative attempt'
        ELSE
            'verified source closure completed the authoritative attempt'
    END;

    IF bound_state <> 'RELEASED'
       OR bound_fence <= 1
       OR bound_transition_key IS DISTINCT FROM expected_transition_key
       OR NEW.idempotency_key <> expected_transition_key
       OR NEW.event_type <> 'RELEASED'
       OR NEW.previous_fence_token <> bound_fence - 1
       OR NEW.fence_token <> bound_fence
       OR NEW.actor_id IS DISTINCT FROM bound_released_by
       OR NEW.reason IS DISTINCT FROM bound_release_reason
       OR NEW.reason <> expected_release_reason
       OR NEW.occurred_at IS DISTINCT FROM bound_released_at
       OR (
           is_runmill_cancellation
           AND bound_cancellation_receipt_id IS NULL
       )
       OR (
           NOT is_runmill_cancellation
           AND bound_cancellation_receipt_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'terminal reservation event contradicts its reserved release namespace'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_set_events_terminal_release_namespace';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER reservation_set_events_terminal_release_key_guard
    BEFORE INSERT ON reservation_set_events
    FOR EACH ROW EXECUTE FUNCTION asf_guard_terminal_reservation_event_key();

-- Run after the generic reservation-accounting guard.  That guard proves the
-- complete ledger coordinate, amount, unit, and database timestamp; this one
-- additionally closes the deterministic namespace and parent provenance.
CREATE FUNCTION asf_guard_terminal_reservation_budget_key() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_kind text;
    bound_dimension text;
    bound_work_item_id uuid;
    bound_attempt_id uuid;
    bound_set_id uuid;
    bound_set_state text;
    bound_set_fence bigint;
    bound_transition_key text;
    bound_cancellation_receipt_id uuid;
    expected_transition_key text;
    is_runmill_cancellation boolean;
BEGIN
    is_runmill_cancellation :=
        NEW.idempotency_key LIKE 'runmill-cancellation:v1:%';
    IF NOT is_runmill_cancellation
       AND NEW.idempotency_key NOT LIKE 'work-closure:v1:%' THEN
        RETURN NEW;
    END IF;

    SELECT
        reservation.kind,
        reservation.budget_dimension,
        reservation_set.work_item_id,
        reservation_set.attempt_id,
        reservation_set.id,
        reservation_set.state,
        reservation_set.fence_token,
        reservation_set.transition_idempotency_key,
        reservation_set.cancellation_terminal_receipt_id
    INTO
        bound_kind,
        bound_dimension,
        bound_work_item_id,
        bound_attempt_id,
        bound_set_id,
        bound_set_state,
        bound_set_fence,
        bound_transition_key,
        bound_cancellation_receipt_id
    FROM reservations AS reservation
    JOIN reservation_sets AS reservation_set
      ON reservation_set.tenant_id = reservation.tenant_id
     AND reservation_set.id = reservation.reservation_set_id
    WHERE reservation.tenant_id = NEW.tenant_id
      AND reservation.id = NEW.reservation_id
    FOR KEY SHARE OF reservation, reservation_set;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'terminal reservation budget key has no exact budget reservation binding'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'budget_ledger_terminal_release_namespace';
    END IF;

    expected_transition_key := CASE
        WHEN is_runmill_cancellation THEN 'runmill-cancellation:v1:'
        ELSE 'work-closure:v1:'
    END || bound_work_item_id::text || ':' || bound_attempt_id::text || ':' ||
        bound_set_id::text || ':fence:' || (bound_set_fence - 1)::text;

    IF bound_kind <> 'BUDGET'
       OR bound_set_state <> 'RELEASED'
       OR bound_set_fence <= 1
       OR bound_transition_key IS DISTINCT FROM expected_transition_key
       OR NEW.entry_type <> 'RELEASE'
       OR NEW.idempotency_key <>
           expected_transition_key || ':budget-release:' || bound_dimension
       OR (
           is_runmill_cancellation
           AND bound_cancellation_receipt_id IS NULL
       )
       OR (
           NOT is_runmill_cancellation
           AND bound_cancellation_receipt_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'terminal reservation budget key contradicts its reserved release namespace'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'budget_ledger_terminal_release_namespace';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER budget_ledger_zzz_terminal_release_key_guard
    BEFORE INSERT ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION asf_guard_terminal_reservation_budget_key();

-- BEFORE triggers protect new writes; explicitly audit append-only historical
-- rows as part of the upgrade so a prefix occupied before this migration does
-- not survive and starve a later terminal transition.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM reservation_sets AS reservation_set
        WHERE reservation_set.transition_idempotency_key LIKE
              'work-closure:v1:%'
          AND NOT asf_work_closure_reservation_release_is_valid(
              reservation_set.tenant_id,
              reservation_set.id
          )
    ) THEN
        RAISE EXCEPTION
            'historical work-closure reservation release lacks exact row provenance'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_sets_work_closure_release_provenance';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM reservation_set_events AS event
        LEFT JOIN reservation_sets AS reservation_set
          ON reservation_set.tenant_id = event.tenant_id
         AND reservation_set.id = event.reservation_set_id
        WHERE (
            event.idempotency_key LIKE 'work-closure:v1:%'
            OR event.idempotency_key LIKE 'runmill-cancellation:v1:%'
        )
          AND (
              reservation_set.id IS NULL
              OR reservation_set.state <> 'RELEASED'
              OR reservation_set.fence_token <= 1
              OR reservation_set.transition_idempotency_key IS DISTINCT FROM
                  event.idempotency_key
              OR event.idempotency_key <> CASE
                  WHEN event.idempotency_key LIKE 'runmill-cancellation:v1:%'
                      THEN 'runmill-cancellation:v1:'
                  ELSE 'work-closure:v1:'
              END || reservation_set.work_item_id::text || ':' ||
                  reservation_set.attempt_id::text || ':' ||
                  reservation_set.id::text || ':fence:' ||
                  (reservation_set.fence_token - 1)::text
              OR event.event_type <> 'RELEASED'
              OR event.previous_fence_token <> reservation_set.fence_token - 1
              OR event.fence_token <> reservation_set.fence_token
              OR event.actor_id IS DISTINCT FROM reservation_set.released_by
              OR event.reason IS DISTINCT FROM reservation_set.release_reason
              OR event.occurred_at IS DISTINCT FROM reservation_set.released_at
              OR (
                  event.idempotency_key LIKE 'runmill-cancellation:v1:%'
                  AND reservation_set.cancellation_terminal_receipt_id IS NULL
              )
              OR (
                  event.idempotency_key LIKE 'work-closure:v1:%'
                  AND (
                      reservation_set.cancellation_terminal_receipt_id IS NOT NULL
                      OR NOT asf_work_closure_reservation_release_is_valid(
                          reservation_set.tenant_id,
                          reservation_set.id
                      )
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION
            'historical terminal reservation event occupies a reserved namespace without exact provenance'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'reservation_set_events_terminal_release_namespace';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM budget_ledger AS entry
        LEFT JOIN reservations AS reservation
          ON reservation.tenant_id = entry.tenant_id
         AND reservation.id = entry.reservation_id
        LEFT JOIN reservation_sets AS reservation_set
          ON reservation_set.tenant_id = reservation.tenant_id
         AND reservation_set.id = reservation.reservation_set_id
        WHERE (
            entry.idempotency_key LIKE 'work-closure:v1:%'
            OR entry.idempotency_key LIKE 'runmill-cancellation:v1:%'
        )
          AND (
              reservation.id IS NULL
              OR reservation_set.id IS NULL
              OR reservation.kind <> 'BUDGET'
              OR reservation_set.state <> 'RELEASED'
              OR reservation_set.fence_token <= 1
              OR reservation_set.transition_idempotency_key IS NULL
              OR reservation_set.transition_idempotency_key <> CASE
                  WHEN entry.idempotency_key LIKE 'runmill-cancellation:v1:%'
                      THEN 'runmill-cancellation:v1:'
                  ELSE 'work-closure:v1:'
              END || reservation_set.work_item_id::text || ':' ||
                  reservation_set.attempt_id::text || ':' ||
                  reservation_set.id::text || ':fence:' ||
                  (reservation_set.fence_token - 1)::text
              OR entry.idempotency_key <>
                  reservation_set.transition_idempotency_key ||
                  ':budget-release:' || reservation.budget_dimension
              OR entry.entry_type <> 'RELEASE'
              OR entry.work_item_id IS DISTINCT FROM reservation_set.work_item_id
              OR entry.attempt_id IS DISTINCT FROM reservation_set.attempt_id
              OR entry.scope_type <> 'ATTEMPT'
              OR entry.scope_id <> reservation_set.attempt_id::text
              OR entry.dimension <> reservation.budget_dimension
              OR entry.amount <> reservation.units
              OR entry.occurred_at IS DISTINCT FROM reservation_set.released_at
              OR (
                  entry.idempotency_key LIKE 'runmill-cancellation:v1:%'
                  AND reservation_set.cancellation_terminal_receipt_id IS NULL
              )
              OR (
                  entry.idempotency_key LIKE 'work-closure:v1:%'
                  AND (
                      reservation_set.cancellation_terminal_receipt_id IS NOT NULL
                      OR NOT asf_work_closure_reservation_release_is_valid(
                          reservation_set.tenant_id,
                          reservation_set.id
                      )
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION
            'historical terminal reservation budget key occupies a reserved namespace without exact provenance'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'budget_ledger_terminal_release_namespace';
    END IF;
END;
$$;

CREATE FUNCTION asf_stamp_cancellation_terminal_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'cancellation receipt ID must be non-nil'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_terminal_receipts_non_nil';
    END IF;
    IF NEW.outcome = 'CANCELLED' THEN
        UPDATE work_cancellation_authority_guards
        SET generation = generation + 1,
            terminal_receipt_id = NEW.id,
            updated_at = clock_timestamp()
        WHERE tenant_id = NEW.tenant_id
          AND work_item_id = NEW.work_item_id
          AND terminal_receipt_id IS NULL
        RETURNING generation INTO NEW.cancellation_authority_generation;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'cancellation receipt has no unfrozen work authority guard'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_terminal_receipts_require_authority_guard';
        END IF;
    ELSE
        NEW.cancellation_authority_generation := NULL;
    END IF;
    NEW.recorded_at := clock_timestamp();
    NEW.receipt_digest := 'sha256:' || encode(sha256(convert_to(
        jsonb_strip_nulls(jsonb_build_object(
            'schema', 'asf.cancellation-terminal-receipt/v1',
            'id', NEW.id,
            'tenant_id', NEW.tenant_id,
            'work_item_id', NEW.work_item_id,
            'route', NEW.route,
            'outcome', NEW.outcome,
            'attempt_id', NEW.attempt_id,
            'run_id', NEW.run_id,
            'effect_intent_id', NEW.effect_intent_id,
            'terminal_observation_id', NEW.terminal_observation_id,
            'workflow_instance_id', NEW.workflow_instance_id,
            'workflow_job_id', NEW.workflow_job_id,
            'workflow_job_fence_token', NEW.workflow_job_fence_token,
            'workflow_job_attempt_count', NEW.workflow_job_attempt_count,
            'workflow_job_completed_by', NEW.workflow_job_completed_by,
            'audit_event_id', NEW.audit_event_id,
            'outbox_event_id', NEW.outbox_event_id,
            'idempotency_record_id', NEW.idempotency_record_id,
            'escalation_id', NEW.escalation_id,
            'work_item_version_before', NEW.work_item_version_before,
            'work_item_version_after', NEW.work_item_version_after,
            'attempt_version_before', NEW.attempt_version_before,
            'attempt_version_after', NEW.attempt_version_after,
            'attempt_fence_token', NEW.attempt_fence_token,
            'run_version_before', NEW.run_version_before,
            'run_version_after', NEW.run_version_after,
            'workflow_version_before', NEW.workflow_version_before,
            'workflow_version_after', NEW.workflow_version_after,
            'workflow_fence_before', NEW.workflow_fence_before,
            'workflow_fence_after', NEW.workflow_fence_after,
            'anchor_generation_before', NEW.anchor_generation_before,
            'anchor_generation_after', NEW.anchor_generation_after,
            'dispatch_guard_generation', NEW.dispatch_guard_generation,
            'cancellation_authority_generation',
                NEW.cancellation_authority_generation,
            'released_reservations', NEW.released_reservations,
            'audit_before_digest', NEW.audit_before_digest,
            'audit_after_digest', NEW.audit_after_digest
        ))::text, 'UTF8'
    )), 'hex');
    RETURN NEW;
END;
$$;

CREATE TRIGGER cancellation_terminal_receipts_stamp
    BEFORE INSERT ON cancellation_terminal_receipts
    FOR EACH ROW EXECUTE FUNCTION asf_stamp_cancellation_terminal_receipt();
CREATE TRIGGER cancellation_terminal_receipts_append_only
    BEFORE UPDATE OR DELETE ON cancellation_terminal_receipts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_terminal_receipts_truncate_forbidden
    BEFORE TRUNCATE ON cancellation_terminal_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Now that the referenced table exists, freeze guard rows after a terminal
-- negative proof has been recorded.
CREATE TRIGGER work_dispatch_fact_guards_monotonic
    BEFORE UPDATE OR DELETE ON work_dispatch_fact_guards
    FOR EACH ROW EXECUTE FUNCTION asf_guard_work_dispatch_fact_guard_update();
CREATE TRIGGER work_dispatch_fact_guards_truncate_forbidden
    BEFORE TRUNCATE ON work_dispatch_fact_guards
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_accountability_anchors_truncate_forbidden
    BEFORE TRUNCATE ON accountability_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_reservation_sets_truncate_forbidden
    BEFORE TRUNCATE ON reservation_sets
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- The semantic predicates below are authority only if their cited audit rows
-- also carry the exact RFC 8785 hash that Rust computed over every field.
CREATE FUNCTION asf_recomputed_audit_event_hash(
    candidate_tenant uuid,
    candidate_event uuid
) RETURNS text
LANGUAGE sql STABLE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'id', audit.id,
        'tenant_id', audit.tenant_id,
        'work_item_id', audit.work_item_id,
        'attempt_id', audit.attempt_id,
        'actor_type', audit.actor_type,
        'actor_id', audit.actor_id,
        'action', audit.action,
        'subject_type', audit.subject_type,
        'subject_id', audit.subject_id,
        'correlation_id', audit.correlation_id,
        'trace_id', audit.trace_id,
        'policy_digest', audit.policy_digest,
        'before_digest', audit.before_digest,
        'after_digest', audit.after_digest,
        'previous_event_hash', audit.previous_event_hash,
        'details', audit.details,
        'occurred_at', asf_chrono_utc(audit.occurred_at)
    ))
    FROM audit_events AS audit
    WHERE audit.tenant_id = candidate_tenant
      AND audit.id = candidate_event;
$$;

-- Older API binaries hashed a nanosecond `Utc::now()` and then persisted it in
-- PostgreSQL's microsecond-precision timestamptz. The discarded digits cannot
-- be reconstructed. Refuse an upgrade that would strand a currently pristine
-- accepted item behind an unverifiable acceptance boundary.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = work.tenant_id
         AND workflow.work_item_id = work.id
         AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
         AND workflow.state = 'ACTIVE'
        JOIN workflow_jobs AS job
          ON job.tenant_id = workflow.tenant_id
         AND job.workflow_instance_id = workflow.id
         AND job.work_item_id = work.id
         AND job.attempt_id IS NULL
         AND job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
         AND job.status IN ('PENDING', 'RETRY')
        WHERE work.state = 'ACCEPTED'
          AND work.current_attempt_id IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS accepted_audit
              WHERE accepted_audit.tenant_id = work.tenant_id
                AND accepted_audit.work_item_id = work.id
                AND accepted_audit.attempt_id IS NULL
                AND accepted_audit.action = 'WORK_ITEM_ACCEPTED'
                AND accepted_audit.event_hash = asf_recomputed_audit_event_hash(
                    accepted_audit.tenant_id, accepted_audit.id
                )
          )
    ) THEN
        RAISE EXCEPTION
            'pristine accepted work has no reproducible acceptance audit hash'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_upgrade_requires_reproducible_acceptance_hash';
    END IF;
END;
$$;

CREATE FUNCTION asf_valid_pre_dispatch_cancellation_receipt(
    candidate_tenant uuid,
    candidate_receipt uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        JOIN work_items AS work
          ON work.tenant_id = receipt.tenant_id
         AND work.id = receipt.work_item_id
        JOIN work_dispatch_fact_guards AS dispatch_guard
          ON dispatch_guard.tenant_id = work.tenant_id
         AND dispatch_guard.work_item_id = work.id
        JOIN work_cancellation_authority_guards AS authority_guard
          ON authority_guard.tenant_id = work.tenant_id
         AND authority_guard.work_item_id = work.id
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = receipt.tenant_id
         AND workflow.id = receipt.workflow_instance_id
         AND workflow.work_item_id = receipt.work_item_id
        JOIN workflow_jobs AS job
          ON job.tenant_id = receipt.tenant_id
         AND job.id = receipt.workflow_job_id
         AND job.workflow_instance_id = receipt.workflow_instance_id
         AND job.work_item_id = receipt.work_item_id
        JOIN audit_events AS audit
          ON audit.tenant_id = receipt.tenant_id
         AND audit.id = receipt.audit_event_id
        JOIN outbox
          ON outbox.tenant_id = receipt.tenant_id
         AND outbox.id = receipt.outbox_event_id
        JOIN idempotency_records AS idempotency
          ON idempotency.tenant_id = receipt.tenant_id
         AND idempotency.id = receipt.idempotency_record_id
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = receipt.tenant_id
         AND anchor.work_item_id = receipt.work_item_id
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.id = candidate_receipt
          AND receipt.route = 'PRE_DISPATCH'
          AND receipt.outcome = 'CANCELLED'
          AND receipt.id = asf_derived_uuid(idempotency.id, 1)
          AND outbox.id = asf_derived_uuid(idempotency.id, 2)
          AND work.state = 'CANCELLED'
          AND work.current_attempt_id IS NULL
          AND work.aggregate_version = receipt.work_item_version_after
          AND receipt.work_item_version_after = receipt.work_item_version_before + 2
          AND dispatch_guard.generation = receipt.dispatch_guard_generation
          AND NOT dispatch_guard.dispatch_started
          AND authority_guard.generation =
              receipt.cancellation_authority_generation
          AND authority_guard.terminal_receipt_id = receipt.id
          AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
          AND workflow.reducer_version = 'asf.workflow/v1'
          AND workflow.state = 'CANCELLED'
          AND workflow.terminal_at IS NOT NULL
          AND workflow.aggregate_version = receipt.workflow_version_after
          AND workflow.fence_token = receipt.workflow_fence_after
          AND receipt.workflow_version_after = receipt.workflow_version_before + 1
          AND receipt.workflow_fence_after = receipt.workflow_fence_before + 1
          AND job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
          AND job.attempt_id IS NULL
          AND job.status = 'CANCELLED'
          AND job.fence_token = receipt.workflow_job_fence_token
          AND job.attempt_count = receipt.workflow_job_attempt_count
          AND job.payload -> 'work_item_id' = to_jsonb(receipt.work_item_id::text)
          AND job.payload -> 'accepted_version' =
              to_jsonb(receipt.work_item_version_before)
          AND jsonb_typeof(job.payload -> 'request_digest') = 'string'
          AND job.payload ->> 'request_digest' ~ '^sha256:[0-9a-f]{64}$'
          AND job.payload - ARRAY[
              'work_item_id', 'accepted_version', 'request_digest'
          ]::text[] = '{}'::jsonb
          AND jsonb_typeof(job.result -> 'schema') = 'string'
          AND jsonb_typeof(job.result -> 'disposition') = 'string'
          AND jsonb_typeof(job.result -> 'terminal_receipt_id') = 'string'
          AND jsonb_typeof(job.result -> 'work_item_id') = 'string'
          AND jsonb_typeof(job.result -> 'workflow_id') = 'string'
          AND job.result ->> 'schema' = 'asf.pre-dispatch-cancellation-result/v1'
          AND job.result ->> 'disposition' = 'cancelled_before_dispatch'
          AND job.result ->> 'terminal_receipt_id' = receipt.id::text
          AND job.result ->> 'work_item_id' = receipt.work_item_id::text
          AND job.result ->> 'workflow_id' = receipt.workflow_instance_id::text
          AND job.result -> 'accepted_version' =
              to_jsonb(receipt.work_item_version_before)
          AND job.result -> 'cancelled_version' =
              to_jsonb(receipt.work_item_version_after)
          AND jsonb_typeof(job.result -> 'request_digest') = 'string'
          AND job.result ->> 'request_digest' = idempotency.request_digest
          AND job.result - ARRAY[
              'schema', 'disposition', 'work_item_id', 'workflow_id',
              'accepted_version', 'cancelled_version', 'request_digest',
              'terminal_receipt_id'
          ]::text[] = '{}'::jsonb
          AND job.lease_owner IS NULL
          AND job.lease_expires_at IS NULL
          AND job.completed_by IS NULL
          AND job.completion_fence_token IS NULL
          AND job.completed_at IS NULL
          AND audit.work_item_id = receipt.work_item_id
          AND audit.attempt_id IS NULL
          AND audit.actor_type = 'API_CALLER'
          AND audit.trace_id IS NULL
          AND audit.action = 'WORK_ITEM_CANCELLED'
          AND audit.subject_type = 'WORK_ITEM'
          AND audit.subject_id = receipt.work_item_id::text
          AND audit.before_digest = receipt.audit_before_digest
          AND audit.after_digest = receipt.audit_after_digest
          AND audit.policy_digest = work.policy_digest
          AND audit.event_hash = asf_recomputed_audit_event_hash(
              audit.tenant_id, audit.id
          )
          AND jsonb_typeof(audit.details -> 'reason') = 'string'
          AND receipt.audit_before_digest = asf_source_closure_digest(
              jsonb_build_object(
                  'state', 'ACCEPTED',
                  'version', receipt.work_item_version_before
              )
          )
          AND receipt.audit_after_digest = asf_source_closure_digest(
              jsonb_build_object(
                  'state', 'CANCELLED',
                  'version', receipt.work_item_version_after,
                  'workflow_id', receipt.workflow_instance_id,
                  'job_id', receipt.workflow_job_id,
                  'request_digest', idempotency.request_digest
              )
          )
          AND audit.details ->> 'terminal_receipt_id' = receipt.id::text
          AND audit.details ->> 'job_id' = receipt.workflow_job_id::text
          AND audit.details ->> 'workflow_id' = receipt.workflow_instance_id::text
          AND audit.details ->> 'request_digest' = idempotency.request_digest
          AND audit.details ->> 'route' = 'synchronous_pre_dispatch'
          AND audit.details - ARRAY[
              'job_id', 'reason', 'request_digest', 'route',
              'terminal_receipt_id', 'workflow_id'
          ]::text[] = '{}'::jsonb
          AND audit.correlation_id = idempotency.id::text
          AND audit.actor_id = idempotency.actor_id
          AND outbox.topic = 'work-items'
          AND outbox.message_key = receipt.work_item_id::text
          AND outbox.event_type = 'work_item.cancelled'
          AND outbox.headers = '{"schema":"asf.work-item-event/v1"}'::jsonb
          AND outbox.payload - ARRAY[
              'work_item_id', 'route', 'terminal_receipt_id',
              'request_digest', 'version'
          ]::text[] = '{}'::jsonb
          AND outbox.payload ->> 'work_item_id' = receipt.work_item_id::text
          AND outbox.payload ->> 'route' = 'synchronous_pre_dispatch'
          AND outbox.payload ->> 'terminal_receipt_id' = receipt.id::text
          AND outbox.payload ->> 'request_digest' = idempotency.request_digest
          AND outbox.payload -> 'version' =
              to_jsonb(receipt.work_item_version_after)
          AND outbox.idempotency_key =
              'api-pre-dispatch-cancellation:' || idempotency.id::text ||
              ':outbox'
          AND idempotency.operation = 'api.work_item.cancel'
          AND idempotency.state = 'COMPLETED'
          AND idempotency.response_status = 200
          AND idempotency.request_digest ~ '^sha256:[0-9a-f]{64}$'
          AND idempotency.request_digest = asf_source_closure_digest(
              jsonb_build_object(
                  'work_item_id', receipt.work_item_id,
                  'expected_version', receipt.work_item_version_before,
                  'reason', audit.details ->> 'reason'
              )
          )
          AND idempotency.response_body ->> 'resource_id' = receipt.work_item_id::text
          AND idempotency.response_body ->> 'status' = 'cancelled'
          AND idempotency.response_body -> 'version' =
              to_jsonb(receipt.work_item_version_after)
          AND idempotency.response_body ->> 'idempotency_key' = idempotency.idempotency_key
          AND idempotency.response_body - ARRAY[
              'idempotency_key', 'resource_id', 'status', 'version'
          ]::text[] = '{}'::jsonb
          AND EXISTS (
              SELECT 1
              FROM audit_events AS accepted_audit
              JOIN idempotency_records AS acceptance
                ON acceptance.tenant_id = accepted_audit.tenant_id
               AND acceptance.id::text = accepted_audit.correlation_id
              WHERE accepted_audit.tenant_id = receipt.tenant_id
                AND accepted_audit.work_item_id = receipt.work_item_id
                AND accepted_audit.attempt_id IS NULL
                AND accepted_audit.actor_type = 'API_CALLER'
                AND accepted_audit.trace_id IS NULL
                AND accepted_audit.action = 'WORK_ITEM_ACCEPTED'
                AND accepted_audit.subject_type = 'WORK_ITEM'
                AND accepted_audit.subject_id = receipt.work_item_id::text
                AND accepted_audit.actor_id = acceptance.actor_id
                AND accepted_audit.policy_digest = work.policy_digest
                AND accepted_audit.event_hash = asf_recomputed_audit_event_hash(
                    accepted_audit.tenant_id, accepted_audit.id
                )
                AND accepted_audit.details = jsonb_build_object(
                    'workflow_id', receipt.workflow_instance_id,
                    'job_id', receipt.workflow_job_id
                )
                AND acceptance.operation = 'api.work_item.accept'
                AND acceptance.state = 'COMPLETED'
                AND acceptance.response_status = 200
                AND acceptance.request_digest = job.payload ->> 'request_digest'
                AND acceptance.request_digest = asf_source_closure_digest(
                    jsonb_build_object(
                        'work_item_id', receipt.work_item_id,
                        'expected_version', receipt.work_item_version_before - 1
                    )
                )
                AND accepted_audit.before_digest = asf_source_closure_digest(
                    jsonb_build_object(
                        'state', 'READY',
                        'version', receipt.work_item_version_before - 1
                    )
                )
                AND accepted_audit.after_digest = asf_source_closure_digest(
                    jsonb_build_object(
                        'state', 'ACCEPTED',
                        'version', receipt.work_item_version_before,
                        'workflow_id', receipt.workflow_instance_id,
                        'job_id', receipt.workflow_job_id
                    )
                )
                AND acceptance.response_body ->> 'idempotency_key' =
                    acceptance.idempotency_key
                AND acceptance.response_body ->> 'resource_id' =
                    receipt.work_item_id::text
                AND acceptance.response_body ->> 'status' = 'accepted'
                AND acceptance.response_body -> 'version' =
                    to_jsonb(receipt.work_item_version_before)
                AND acceptance.response_body - ARRAY[
                    'idempotency_key', 'resource_id', 'status', 'version'
                ]::text[] = '{}'::jsonb
                AND job.idempotency_key =
                    'api-job:sha256:' || encode(sha256(
                        convert_to(receipt.tenant_id::text, 'UTF8') || decode('00', 'hex') ||
                        convert_to(acceptance.actor_id, 'UTF8') || decode('00', 'hex') ||
                        convert_to(acceptance.operation, 'UTF8') || decode('00', 'hex') ||
                        convert_to(acceptance.idempotency_key, 'UTF8')
                    ), 'hex')
          )
          AND anchor.anchor_type = 'CANCELLATION'
          AND anchor.reference_id = receipt.id
          AND anchor.wake_or_deadline_at IS NULL
          AND NOT anchor.authority_or_effect_active
          AND anchor.generation = receipt.anchor_generation_after
          AND receipt.anchor_generation_after = receipt.anchor_generation_before + 1
          AND (SELECT count(*) FROM workflow_instances AS other
               WHERE other.tenant_id = receipt.tenant_id
                 AND other.work_item_id = receipt.work_item_id) = 1
          AND (SELECT count(*) FROM workflow_jobs AS other
               WHERE other.tenant_id = receipt.tenant_id
                 AND other.work_item_id = receipt.work_item_id) = 1
          AND NOT EXISTS (SELECT 1 FROM attempts WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM workflow_timers WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM reservation_sets WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM effect_intents WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM runs WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM work_orders WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM approvals WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM evidence_bundles WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM escalations WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (SELECT 1 FROM budget_ledger WHERE tenant_id = receipt.tenant_id AND work_item_id = receipt.work_item_id)
          AND NOT EXISTS (
              SELECT 1
              FROM operational_incidents AS incident
              JOIN workflow_jobs AS incident_job
                ON incident_job.tenant_id = incident.tenant_id
               AND incident_job.id = incident.workflow_job_id
              WHERE incident_job.tenant_id = receipt.tenant_id
                AND incident_job.work_item_id = receipt.work_item_id
          )
    );
$$;

CREATE FUNCTION asf_valid_runmill_cancellation_effect_request(
    candidate_tenant uuid,
    candidate_effect uuid,
    candidate_run uuid
) RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM effect_intents AS effect
        JOIN runs AS run
          ON run.tenant_id = effect.tenant_id
         AND run.id = candidate_run
         AND run.work_item_id = effect.work_item_id
         AND run.attempt_id = effect.attempt_id
        WHERE effect.tenant_id = candidate_tenant
          AND effect.id = candidate_effect
          AND effect.provider = 'runmill'
          AND effect.effect_type = 'request_cancellation'
          AND effect.work_item_id IS NOT NULL
          AND effect.attempt_id IS NOT NULL
          AND run.authoritative
          AND jsonb_typeof(effect.request_payload -> 'schema') = 'string'
          AND jsonb_typeof(effect.request_payload -> 'request_id') = 'string'
          AND jsonb_typeof(effect.request_payload -> 'run_id') = 'string'
          AND jsonb_typeof(effect.request_payload -> 'mode') = 'string'
          AND jsonb_typeof(effect.request_payload -> 'reason') = 'string'
          AND effect.request_payload ->> 'schema' =
              'asf.cancellation-request/v1'
          AND effect.request_payload ->> 'request_id' =
              'asf-cancel:' || replace(effect.tenant_id::text, '-', '') || ':' ||
              replace(effect.work_item_id::text, '-', '') || ':' ||
              replace(effect.attempt_id::text, '-', '') || ':' ||
              replace(run.id::text, '-', '')
          AND effect.correlation_marker = effect.request_payload ->> 'request_id'
          AND effect.idempotency_key =
              'runmill-cancellation:' || (effect.request_payload ->> 'request_id')
          AND effect.request_payload ->> 'run_id' = run.external_run_id
          AND effect.request_payload ->> 'mode' = 'graceful'
          AND effect.request_payload ->> 'reason' =
              btrim(effect.request_payload ->> 'reason')
          AND octet_length(effect.request_payload ->> 'reason') BETWEEN 1 AND 2048
          AND jsonb_typeof(effect.request_payload -> 'grace_seconds') = 'number'
          AND CASE
              WHEN (effect.request_payload -> 'grace_seconds')::text ~ '^[0-9]+$'
              THEN ((effect.request_payload -> 'grace_seconds')::text)::numeric
                   BETWEEN 1 AND 300
              ELSE false
          END
          AND jsonb_typeof(effect.request_payload -> 'requester') = 'object'
          AND jsonb_typeof(effect.request_payload #> '{requester,authority}') = 'string'
          AND jsonb_typeof(effect.request_payload #> '{requester,subject}') = 'string'
          AND effect.request_payload #>> '{requester,authority}' = 'asf:cancel'
          AND effect.request_payload #>> '{requester,subject}' =
              btrim(effect.request_payload #>> '{requester,subject}')
          AND octet_length(effect.request_payload #>> '{requester,subject}') BETWEEN 1 AND 256
          AND effect.request_payload #>> '{requester,subject}' ~
              '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
          AND (effect.request_payload -> 'requester') - ARRAY[
              'subject', 'authority'
          ]::text[] = '{}'::jsonb
          AND effect.request_payload - ARRAY[
              'schema', 'request_id', 'run_id', 'requester', 'reason',
              'mode', 'grace_seconds'
          ]::text[] = '{}'::jsonb
          AND effect.request_digest =
              asf_source_closure_digest(effect.request_payload)
    );
$$;

CREATE FUNCTION asf_valid_runmill_cancellation_effect_observation(
    candidate_tenant uuid,
    candidate_effect uuid,
    candidate_observation uuid
) RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM effect_intents AS effect
        JOIN runmill_cancellation_observations AS observation
          ON observation.tenant_id = effect.tenant_id
         AND observation.id = candidate_observation
         AND observation.effect_intent_id = effect.id
         AND observation.work_item_id = effect.work_item_id
         AND observation.attempt_id = effect.attempt_id
        WHERE effect.tenant_id = candidate_tenant
          AND effect.id = candidate_effect
          AND effect.provider = 'runmill'
          AND effect.effect_type = 'request_cancellation'
          AND effect.status = 'OBSERVED'
          AND effect.initial_cancellation_observation_id = observation.id
          AND effect.fence_token = observation.workflow_job_fence_token
          AND effect.observed_at = observation.observed_at
          AND effect.owning_workflow_job_id IS NULL
          AND effect.lease_owner IS NULL
          AND effect.lease_expires_at IS NULL
          AND effect.last_error IS NULL
          AND observation.route = 'INITIAL'
          AND observation.prior_observation_id IS NULL
          AND asf_valid_runmill_cancellation_effect_request(
              effect.tenant_id, effect.id, observation.run_id
          )
          AND jsonb_typeof(effect.observed_outcome -> 'schema') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'status') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'request_id') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'request_digest') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'disposition') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'external_phase') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'external_generation') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'external_state_version') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'external_latest_sequence') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'reconciliation_required') = 'boolean'
          AND jsonb_typeof(effect.observed_outcome -> 'cancellation_observation_id') = 'string'
          AND effect.observed_outcome ->> 'schema' =
              'asf.runmill-cancellation-effect/v1'
          AND effect.observed_outcome ->> 'status' = 'observed'
          AND effect.observed_outcome ->> 'request_id' = observation.request_id
          AND effect.observed_outcome ->> 'request_digest' = observation.request_digest
          AND effect.observed_outcome ->> 'disposition' = CASE
              observation.disposition
              WHEN 'REQUESTED' THEN 'requested'
              WHEN 'EXISTING' THEN 'existing'
              WHEN 'ALREADY_TERMINAL' THEN 'already-terminal'
          END
          AND effect.observed_outcome ->> 'external_phase' = CASE
              observation.external_phase
              WHEN 'SUCCEEDED' THEN 'COMPLETED'
              WHEN 'FAILED' THEN effect.observed_outcome ->> 'external_phase'
              ELSE observation.external_phase
          END
          AND (
              observation.external_phase <> 'FAILED'
              OR effect.observed_outcome ->> 'external_phase' IN (
                  'FAILED', 'BUDGET_EXHAUSTED'
              )
          )
          AND effect.observed_outcome -> 'external_generation' =
              to_jsonb(observation.external_generation)
          AND effect.observed_outcome -> 'external_state_version' =
              to_jsonb(observation.external_state_version)
          AND effect.observed_outcome -> 'external_latest_sequence' =
              to_jsonb(observation.external_latest_sequence)
          AND effect.observed_outcome -> 'reconciliation_required' =
              to_jsonb(observation.reconciliation_required)
          AND effect.observed_outcome ->> 'cancellation_observation_id' =
              observation.id::text
          AND effect.observed_outcome - ARRAY[
              'schema', 'status', 'request_id', 'request_digest',
              'disposition', 'external_phase', 'external_generation',
              'external_state_version', 'external_latest_sequence',
              'reconciliation_required', 'cancellation_observation_id'
          ]::text[] = '{}'::jsonb
    );
$$;

-- OBSERVED cancellation effects must transition from the exact IN_FLIGHT
-- owner and bind the INITIAL observation written under that same claim.
CREATE FUNCTION asf_guard_runmill_cancellation_effect_observation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    observation runmill_cancellation_observations%ROWTYPE;
BEGIN
    IF NEW.provider = 'runmill'
       AND NEW.effect_type = 'request_cancellation'
       AND NEW.status = 'OBSERVED' THEN
        IF TG_OP = 'INSERT' OR OLD.status <> 'IN_FLIGHT' THEN
            RAISE EXCEPTION 'Runmill cancellation effect lacks its exact initial observation claim'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_runmill_cancellation_observation';
        END IF;
        SELECT candidate.* INTO observation
        FROM runmill_cancellation_observations AS candidate
        WHERE candidate.tenant_id = NEW.tenant_id
          AND candidate.id = NEW.initial_cancellation_observation_id
          AND candidate.effect_intent_id = NEW.id
          AND candidate.work_item_id = NEW.work_item_id
          AND candidate.attempt_id = NEW.attempt_id
          AND candidate.route = 'INITIAL'
          AND candidate.prior_observation_id IS NULL
          AND candidate.workflow_job_id = OLD.owning_workflow_job_id
          AND candidate.workflow_job_fence_token = OLD.fence_token
          AND candidate.workflow_job_owner = OLD.lease_owner
          AND candidate.request_digest = OLD.request_digest
        FOR SHARE;
        IF NOT FOUND
           OR OLD.attempt_count <= 0
           OR OLD.lease_owner IS NULL
           OR OLD.lease_expires_at IS NULL
           OR NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
           OR NEW.fence_token IS DISTINCT FROM OLD.fence_token
           OR NEW.observed_at IS DISTINCT FROM observation.observed_at
           OR NEW.owning_workflow_job_id IS NOT NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL
           OR NEW.last_error IS NOT NULL
           OR NOT asf_valid_runmill_cancellation_effect_request(
               NEW.tenant_id, NEW.id, observation.run_id
           )
           OR jsonb_typeof(NEW.observed_outcome -> 'schema') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'status') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'request_id') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'request_digest') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'disposition') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'external_phase') IS DISTINCT FROM 'string'
           OR jsonb_typeof(NEW.observed_outcome -> 'external_generation') IS DISTINCT FROM 'number'
           OR jsonb_typeof(NEW.observed_outcome -> 'external_state_version') IS DISTINCT FROM 'number'
           OR jsonb_typeof(NEW.observed_outcome -> 'external_latest_sequence') IS DISTINCT FROM 'number'
           OR jsonb_typeof(NEW.observed_outcome -> 'reconciliation_required') IS DISTINCT FROM 'boolean'
           OR jsonb_typeof(NEW.observed_outcome -> 'cancellation_observation_id') IS DISTINCT FROM 'string'
           OR NEW.observed_outcome ->> 'schema' IS DISTINCT FROM
              'asf.runmill-cancellation-effect/v1'
           OR NEW.observed_outcome ->> 'status' IS DISTINCT FROM 'observed'
           OR NEW.observed_outcome ->> 'request_id' IS DISTINCT FROM
              observation.request_id
           OR NEW.observed_outcome ->> 'request_digest' IS DISTINCT FROM
              observation.request_digest
           OR NEW.observed_outcome ->> 'disposition' IS DISTINCT FROM (CASE
              observation.disposition
              WHEN 'REQUESTED' THEN 'requested'
              WHEN 'EXISTING' THEN 'existing'
              WHEN 'ALREADY_TERMINAL' THEN 'already-terminal'
           END)
           OR NEW.observed_outcome ->> 'external_phase' IS DISTINCT FROM (CASE
              observation.external_phase
              WHEN 'SUCCEEDED' THEN 'COMPLETED'
              WHEN 'FAILED' THEN NEW.observed_outcome ->> 'external_phase'
              ELSE observation.external_phase
           END)
           OR (
               observation.external_phase = 'FAILED'
               AND NEW.observed_outcome ->> 'external_phase' NOT IN (
                   'FAILED', 'BUDGET_EXHAUSTED'
               )
           )
           OR NEW.observed_outcome -> 'external_generation' IS DISTINCT FROM
              to_jsonb(observation.external_generation)
           OR NEW.observed_outcome -> 'external_state_version' IS DISTINCT FROM
              to_jsonb(observation.external_state_version)
           OR NEW.observed_outcome -> 'external_latest_sequence' IS DISTINCT FROM
              to_jsonb(observation.external_latest_sequence)
           OR NEW.observed_outcome -> 'reconciliation_required' IS DISTINCT FROM
              to_jsonb(observation.reconciliation_required)
           OR NEW.observed_outcome ->> 'cancellation_observation_id' IS DISTINCT FROM
              observation.id::text
           OR NEW.observed_outcome - ARRAY[
               'schema', 'status', 'request_id', 'request_digest',
               'disposition', 'external_phase', 'external_generation',
               'external_state_version', 'external_latest_sequence',
               'reconciliation_required', 'cancellation_observation_id'
           ]::text[] <> '{}'::jsonb THEN
            RAISE EXCEPTION 'Runmill cancellation effect observation payload is not the exact initial receipt'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_runmill_cancellation_observation';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.initial_cancellation_observation_id IS NOT NULL
       AND NEW.initial_cancellation_observation_id IS DISTINCT FROM
           OLD.initial_cancellation_observation_id THEN
        RAISE EXCEPTION 'Runmill cancellation initial observation is immutable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'effect_intents_initial_cancellation_observation_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_intents_exact_runmill_cancellation_observation
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_cancellation_effect_observation();

-- Completion itself is a receipt: capture the exact RUNNING claim and do not
-- allow a queue row to jump directly to COMPLETED.
CREATE FUNCTION asf_guard_cancellation_job_terminal_transition() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
       AND NEW.status = 'COMPLETED'
       AND OLD.status IS DISTINCT FROM 'COMPLETED'
       AND (
           OLD.status <> 'RUNNING'
           OR OLD.workflow_instance_id IS NULL
           OR OLD.work_item_id IS NULL
           OR OLD.attempt_id IS NULL
           OR OLD.attempt_count <= 0
           OR OLD.attempt_count > OLD.max_attempts
           OR OLD.fence_token <= 0
           OR OLD.lease_owner IS NULL
           OR OLD.lease_expires_at IS NULL
           OR OLD.lease_expires_at <= transaction_timestamp()
           OR ROW(
               NEW.tenant_id, NEW.id, NEW.workflow_instance_id,
               NEW.work_item_id, NEW.attempt_id, NEW.job_type,
               NEW.payload, NEW.idempotency_key, NEW.attempt_count,
               NEW.max_attempts, NEW.fence_token, NEW.created_at
           ) IS DISTINCT FROM ROW(
               OLD.tenant_id, OLD.id, OLD.workflow_instance_id,
               OLD.work_item_id, OLD.attempt_id, OLD.job_type,
               OLD.payload, OLD.idempotency_key, OLD.attempt_count,
               OLD.max_attempts, OLD.fence_token, OLD.created_at
           )
           OR NEW.completed_by IS DISTINCT FROM OLD.lease_owner
           OR NEW.completion_fence_token IS DISTINCT FROM OLD.fence_token
           OR NEW.completed_at IS NULL
           OR NEW.result IS NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'cancellation completion does not capture its exact executed claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_exact_cancellation_completion';
    END IF;

    IF NEW.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
       AND NEW.status = 'CANCELLED'
       AND OLD.status IS DISTINCT FROM 'CANCELLED'
       AND (
           OLD.status NOT IN ('PENDING', 'RETRY')
           OR OLD.workflow_instance_id IS NULL
           OR OLD.work_item_id IS NULL
           OR OLD.attempt_id IS NOT NULL
           OR OLD.attempt_count >= OLD.max_attempts
           OR OLD.result IS NOT NULL
           OR OLD.lease_owner IS NOT NULL
           OR OLD.lease_expires_at IS NOT NULL
           OR OLD.completed_by IS NOT NULL
           OR OLD.completion_fence_token IS NOT NULL
           OR OLD.completed_at IS NOT NULL
           OR NEW.fence_token <> OLD.fence_token + 1
           OR NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
           OR NEW.result ->> 'schema' IS DISTINCT FROM
              'asf.pre-dispatch-cancellation-result/v1'
           OR NEW.result ->> 'disposition' IS DISTINCT FROM
              'cancelled_before_dispatch'
           OR NEW.result ->> 'work_item_id' IS DISTINCT FROM OLD.work_item_id::text
           OR NEW.result ->> 'terminal_receipt_id' IS NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL
           OR NEW.completed_by IS NOT NULL
           OR NEW.completion_fence_token IS NOT NULL
           OR NEW.completed_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'pre-dispatch cancellation does not fence the pristine advance job'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_exact_pre_dispatch_cancellation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_jobs_exact_cancellation_terminal_transition
    BEFORE UPDATE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_guard_cancellation_job_terminal_transition();

CREATE FUNCTION asf_assert_completed_cancellation_observation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.route = 'INITIAL' OR NEW.external_phase IN (
        'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED', 'CANCELLED'
    )) AND NOT EXISTS (
        SELECT 1
        FROM workflow_jobs AS job
        WHERE job.tenant_id = NEW.tenant_id
          AND job.id = NEW.workflow_job_id
          AND job.workflow_instance_id = NEW.workflow_instance_id
          AND job.work_item_id = NEW.work_item_id
          AND job.attempt_id = NEW.attempt_id
          AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND job.status = 'COMPLETED'
          AND job.fence_token = NEW.workflow_job_fence_token
          AND job.completion_fence_token = NEW.workflow_job_fence_token
          AND job.attempt_count = NEW.workflow_job_attempt_count
          AND job.completed_by = NEW.workflow_job_owner
          AND job.completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cancellation observation lacks its exact completed workflow claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_cancellation_observation_completed_claim';
    END IF;
    IF NEW.external_phase IN (
        'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED', 'CANCELLED'
    ) AND NOT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.work_item_id = NEW.work_item_id
          AND receipt.attempt_id = NEW.attempt_id
          AND receipt.run_id = NEW.run_id
          AND receipt.effect_intent_id = NEW.effect_intent_id
          AND receipt.terminal_observation_id = NEW.id
          AND receipt.workflow_instance_id = NEW.workflow_instance_id
          AND receipt.workflow_job_id = NEW.workflow_job_id
          AND receipt.workflow_job_fence_token = NEW.workflow_job_fence_token
          AND receipt.workflow_job_attempt_count = NEW.workflow_job_attempt_count
          AND receipt.workflow_job_completed_by = NEW.workflow_job_owner
          AND receipt.route = 'RUNMILL'
          AND asf_valid_runmill_cancellation_receipt(
              receipt.tenant_id, receipt.id
          )
    ) THEN
        RAISE EXCEPTION 'terminal cancellation observation has no exact terminal receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_observations_require_terminal_receipt';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER runmill_cancellation_observations_completed_claim
    AFTER INSERT ON runmill_cancellation_observations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_completed_cancellation_observation();

CREATE FUNCTION asf_assert_completed_cancellation_job_observation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
       AND NEW.status = 'COMPLETED'
       AND OLD.status IS DISTINCT FROM 'COMPLETED'
       AND NOT EXISTS (
           SELECT 1
           FROM runmill_cancellation_observations AS observation
           JOIN runs AS run
             ON run.tenant_id = observation.tenant_id
            AND run.id = observation.run_id
            AND run.work_item_id = observation.work_item_id
            AND run.attempt_id = observation.attempt_id
            JOIN work_items AS work
              ON work.tenant_id = observation.tenant_id
             AND work.id = observation.work_item_id
            JOIN effect_intents AS effect
              ON effect.tenant_id = observation.tenant_id
             AND effect.id = observation.effect_intent_id
             AND effect.work_item_id = observation.work_item_id
             AND effect.attempt_id = observation.attempt_id
             AND effect.provider = 'runmill'
             AND effect.effect_type = 'request_cancellation'
           WHERE observation.tenant_id = NEW.tenant_id
             AND observation.workflow_instance_id = NEW.workflow_instance_id
             AND observation.workflow_job_id = NEW.id
             AND observation.work_item_id = NEW.work_item_id
             AND observation.attempt_id = NEW.attempt_id
             AND observation.workflow_job_fence_token = NEW.fence_token
             AND observation.workflow_job_attempt_count = NEW.attempt_count
             AND observation.workflow_job_owner = NEW.completed_by
             AND run.authoritative
             AND jsonb_typeof(NEW.payload) = 'object'
             AND NEW.payload ?& ARRAY[
                 'work_item_id', 'worker_id', 'expected_version',
                 'reason', 'requested_by'
             ]::text[]
             AND NEW.payload - ARRAY[
                 'work_item_id', 'worker_id', 'expected_version',
                 'reason', 'requested_by', 'observe_only'
             ]::text[] = '{}'::jsonb
             AND jsonb_typeof(NEW.payload -> 'work_item_id') = 'string'
             AND NEW.payload ->> 'work_item_id' = observation.work_item_id::text
             AND jsonb_typeof(NEW.payload -> 'worker_id') = 'string'
             AND NEW.payload ->> 'worker_id' = run.worker_id::text
             AND jsonb_typeof(NEW.payload -> 'expected_version') = 'number'
             AND NEW.payload ->> 'expected_version' ~ '^[1-9][0-9]*$'
             AND (NEW.payload ->> 'expected_version')::numeric =
                 work.aggregate_version - 1
             AND jsonb_typeof(NEW.payload -> 'reason') = 'string'
             AND btrim(NEW.payload ->> 'reason') = NEW.payload ->> 'reason'
             AND btrim(NEW.payload ->> 'reason') <> ''
             AND octet_length(NEW.payload ->> 'reason') <= 2048
             AND jsonb_typeof(NEW.payload -> 'requested_by') = 'string'
             AND btrim(NEW.payload ->> 'requested_by') <> ''
             AND octet_length(NEW.payload ->> 'requested_by') <= 1024
             AND (
                 (
                     observation.route = 'INITIAL'
                     AND NOT (NEW.payload ? 'observe_only')
                     AND NEW.payload - ARRAY[
                         'work_item_id', 'worker_id', 'expected_version',
                         'reason', 'requested_by'
                     ]::text[] = '{}'::jsonb
                 ) OR (
                     observation.route = 'OBSERVER'
                     AND (
                         (
                             NOT (NEW.payload ? 'observe_only')
                             AND NEW.payload - ARRAY[
                                 'work_item_id', 'worker_id', 'expected_version',
                                 'reason', 'requested_by'
                             ]::text[] = '{}'::jsonb
                         ) OR (
                             jsonb_typeof(NEW.payload -> 'observe_only') = 'boolean'
                             AND NEW.payload -> 'observe_only' = 'true'::jsonb
                         )
                     )
                 )
             )
             AND jsonb_typeof(NEW.result) = 'object'
             AND NEW.result ?& ARRAY[
                 'workflow_step_commit_digest', 'result'
             ]::text[]
             AND jsonb_typeof(NEW.result -> 'workflow_step_commit_digest') = 'string'
             AND NEW.result ->> 'workflow_step_commit_digest' ~
                 '^sha256:[0-9a-f]{64}$'
             AND NEW.result - ARRAY[
                 'workflow_step_commit_digest', 'result'
             ]::text[] = '{}'::jsonb
             AND jsonb_typeof(NEW.result -> 'result') = 'object'
             AND (NEW.result -> 'result') ?& ARRAY[
                 'schema', 'request_id', 'request_digest', 'external_run_id',
                 'disposition', 'external_phase', 'reconciliation_required',
                 'route', 'released_reservations',
                 'cancellation_observation_id', 'terminal_receipt_id',
                 'observation_job', 'escalation_id', 'escalation_deadline',
                 'escalation_disposition', 'escalation_before_digest',
                 'escalation_after_digest'
             ]::text[]
             AND NEW.result #>> '{result,schema}' =
                 'asf.runmill-cancellation-result/v1'
             AND jsonb_typeof(NEW.result #> '{result,schema}') = 'string'
             AND NEW.result #>> '{result,cancellation_observation_id}' =
                 observation.id::text
             AND jsonb_typeof(
                 NEW.result #> '{result,cancellation_observation_id}'
             ) = 'string'
             AND NEW.result #>> '{result,request_id}' = observation.request_id
             AND jsonb_typeof(NEW.result #> '{result,request_id}') = 'string'
             AND NEW.result #>> '{result,request_digest}' = observation.request_digest
             AND jsonb_typeof(NEW.result #> '{result,request_digest}') = 'string'
             AND NEW.result #>> '{result,external_run_id}' = run.external_run_id
             AND jsonb_typeof(NEW.result #> '{result,external_run_id}') = 'string'
             AND NEW.result #>> '{result,disposition}' = CASE
                 observation.disposition
                 WHEN 'REQUESTED' THEN 'requested'
                 WHEN 'EXISTING' THEN 'existing'
                 WHEN 'ALREADY_TERMINAL' THEN 'already-terminal'
             END
             AND jsonb_typeof(NEW.result #> '{result,disposition}') = 'string'
             AND NEW.result #>> '{result,external_phase}' = CASE
                 observation.external_phase
                 WHEN 'SUCCEEDED' THEN 'COMPLETED'
                 WHEN 'FAILED' THEN NEW.result #>> '{result,external_phase}'
                 ELSE observation.external_phase
             END
             AND jsonb_typeof(NEW.result #> '{result,external_phase}') = 'string'
             AND (
                 observation.external_phase <> 'FAILED'
                 OR NEW.result #>> '{result,external_phase}' IN (
                     'FAILED', 'BUDGET_EXHAUSTED'
                 )
             )
             AND NEW.result #>> '{result,reconciliation_required}' =
                 observation.reconciliation_required::text
             AND jsonb_typeof(
                 NEW.result #> '{result,reconciliation_required}'
             ) = 'boolean'
             AND jsonb_typeof(
                 NEW.result #> '{result,released_reservations}'
             ) = 'number'
             AND NEW.result #>> '{result,released_reservations}' ~
                 '^(0|[1-9][0-9]*)$'
             AND jsonb_typeof(NEW.result #> '{result,route}') = 'string'
             AND jsonb_typeof(
                 NEW.result #> '{result,terminal_receipt_id}'
             ) IN ('null', 'string')
             AND jsonb_typeof(
                 NEW.result #> '{result,observation_job}'
             ) IN ('null', 'object')
             AND jsonb_typeof(NEW.result #> '{result,escalation_id}')
                 IN ('null', 'string')
             AND jsonb_typeof(NEW.result #> '{result,escalation_deadline}')
                 IN ('null', 'string')
             AND jsonb_typeof(NEW.result #> '{result,escalation_disposition}')
                 IN ('null', 'string')
             AND jsonb_typeof(NEW.result #> '{result,escalation_before_digest}')
                 IN ('null', 'string')
             AND jsonb_typeof(NEW.result #> '{result,escalation_after_digest}')
                 IN ('null', 'string')
             AND (NEW.result -> 'result') - ARRAY[
                 'schema', 'request_id', 'request_digest', 'external_run_id',
                 'disposition', 'external_phase', 'reconciliation_required',
                 'route', 'released_reservations',
                 'cancellation_observation_id', 'terminal_receipt_id',
                 'observation_job', 'escalation_id', 'escalation_deadline',
                 'escalation_disposition', 'escalation_before_digest',
                 'escalation_after_digest'
             ]::text[] = '{}'::jsonb
             AND (
                 observation.external_phase NOT IN (
                     'CANCEL_REQUESTED', 'CANCELLING'
                 ) OR (
                     observation.route = 'INITIAL'
                     AND NEW.result #>> '{result,route}' =
                         'cancellation_in_progress'
                     AND NEW.result #>> '{result,released_reservations}' = '0'
                     AND NEW.result #> '{result,terminal_receipt_id}' = 'null'::jsonb
                     AND NEW.result #> '{result,escalation_id}' = 'null'::jsonb
                     AND NEW.result #> '{result,escalation_deadline}' = 'null'::jsonb
                     AND NEW.result #> '{result,escalation_disposition}' = 'null'::jsonb
                     AND NEW.result #> '{result,escalation_before_digest}' = 'null'::jsonb
                     AND NEW.result #> '{result,escalation_after_digest}' = 'null'::jsonb
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job}'
                     ) = 'object'
                     AND (NEW.result #> '{result,observation_job}') ?& ARRAY[
                         'id', 'attempt_id', 'job_type', 'payload',
                         'idempotency_key', 'priority', 'available_at',
                         'max_attempts'
                     ]::text[]
                     AND (NEW.result #> '{result,observation_job}') - ARRAY[
                         'id', 'attempt_id', 'job_type', 'payload',
                         'idempotency_key', 'priority', 'available_at',
                         'max_attempts'
                     ]::text[] = '{}'::jsonb
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,id}'
                     ) = 'string'
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,attempt_id}'
                     ) = 'string'
                     AND NEW.result #>> '{result,observation_job,attempt_id}' =
                         observation.attempt_id::text
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,job_type}'
                     ) = 'string'
                     AND NEW.result #>> '{result,observation_job,job_type}' =
                         'REQUEST_WORK_ITEM_CANCELLATION'
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,payload}'
                     ) = 'object'
                     AND NEW.result #> '{result,observation_job,payload}' =
                         jsonb_build_object(
                             'work_item_id', observation.work_item_id,
                             'worker_id', run.worker_id,
                             'expected_version', work.aggregate_version,
                             'reason', NEW.payload ->> 'reason',
                             'requested_by', NEW.payload ->> 'requested_by',
                             'observe_only', true
                         )
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,idempotency_key}'
                     ) = 'string'
                     AND NEW.result #>> '{result,observation_job,idempotency_key}' =
                         'runmill-cancellation:' || observation.request_id ||
                         ':observe-terminal'
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,priority}'
                     ) = 'number'
                     AND NEW.result #>> '{result,observation_job,priority}' ~
                         '^-?(0|[1-9][0-9]*)$'
                     AND (NEW.result #>> '{result,observation_job,priority}')::numeric =
                         NEW.priority
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,available_at}'
                     ) = 'string'
                     AND jsonb_typeof(
                         NEW.result #> '{result,observation_job,max_attempts}'
                     ) = 'number'
                     AND NEW.result #>> '{result,observation_job,max_attempts}' ~
                         '^[1-9][0-9]*$'
                     AND (NEW.result #>> '{result,observation_job,max_attempts}')::numeric =
                         NEW.max_attempts
                     AND jsonb_typeof(effect.request_payload) = 'object'
                     AND effect.request_payload ->> 'request_id' =
                         observation.request_id
                     AND effect.request_payload ->> 'run_id' = run.external_run_id
                     AND effect.request_payload ->> 'mode' = 'graceful'
                     AND jsonb_typeof(
                         effect.request_payload -> 'grace_seconds'
                     ) = 'number'
                     AND effect.request_payload ->> 'grace_seconds' ~
                         '^[1-9][0-9]*$'
                     AND (effect.request_payload ->> 'grace_seconds')::numeric
                         BETWEEN 1 AND 300
                     AND NEW.result #>> '{result,observation_job,id}' =
                         asf_derived_uuid(
                             observation.effect_intent_id, 5
                         )::text
                     AND EXISTS (
                         SELECT 1
                         FROM workflow_jobs AS observer
                         WHERE observer.tenant_id = NEW.tenant_id
                           AND observer.id = (
                               NEW.result #>> '{result,observation_job,id}'
                           )::uuid
                           AND observer.workflow_instance_id =
                               NEW.workflow_instance_id
                           AND observer.work_item_id = NEW.work_item_id
                           AND observer.attempt_id = NEW.attempt_id
                           AND observer.job_type =
                               'REQUEST_WORK_ITEM_CANCELLATION'
                           AND observer.payload =
                               NEW.result #> '{result,observation_job,payload}'
                           AND observer.idempotency_key =
                               NEW.result #>>
                                   '{result,observation_job,idempotency_key}'
                           AND observer.priority = NEW.priority
                           AND observer.priority::numeric =
                               (NEW.result #>>
                                   '{result,observation_job,priority}')::numeric
                           AND observer.available_at =
                               (NEW.result #>>
                                   '{result,observation_job,available_at}')::timestamptz
                           AND observer.available_at = observation.observed_at +
                               make_interval(
                                   secs => (
                                       effect.request_payload ->> 'grace_seconds'
                                   )::double precision
                               )
                           AND observer.max_attempts = NEW.max_attempts
                           AND observer.max_attempts::numeric =
                               (NEW.result #>>
                                   '{result,observation_job,max_attempts}')::numeric
                           AND observer.status = 'PENDING'
                           AND observer.attempt_count = 0
                           AND observer.fence_token = 0
                           AND observer.result IS NULL
                           AND observer.lease_owner IS NULL
                           AND observer.lease_expires_at IS NULL
                           AND observer.completed_by IS NULL
                           AND observer.completion_fence_token IS NULL
                           AND observer.completed_at IS NULL
                           AND observer.last_failure_by IS NULL
                           AND observer.last_failure_fence_token IS NULL
                           AND observer.last_failure_retry_at IS NULL
                           AND observer.last_error IS NULL
                           AND observer.dead_letter_escalation_id IS NULL
                           AND observer.dead_letter_operational_incident_id IS NULL
                           AND observer.dead_lettered_at IS NULL
                     )
                     AND asf_valid_runmill_cancellation_effect_observation(
                         observation.tenant_id,
                         observation.effect_intent_id,
                         observation.id
                     )
                     AND EXISTS (
                         SELECT 1
                         FROM attempts AS attempt
                         JOIN workflow_instances AS workflow
                           ON workflow.tenant_id = attempt.tenant_id
                          AND workflow.id = NEW.workflow_instance_id
                          AND workflow.work_item_id = observation.work_item_id
                         JOIN accountability_anchors AS anchor
                           ON anchor.tenant_id = observation.tenant_id
                          AND anchor.work_item_id = observation.work_item_id
                         JOIN audit_events AS audit
                           ON audit.tenant_id = observation.tenant_id
                          AND audit.id = asf_derived_uuid(NEW.id, 1)
                         JOIN outbox AS emitted
                           ON emitted.tenant_id = observation.tenant_id
                          AND emitted.id = asf_derived_uuid(NEW.id, 2)
                         WHERE attempt.tenant_id = observation.tenant_id
                           AND attempt.id = observation.attempt_id
                           AND attempt.work_item_id = observation.work_item_id
                           AND attempt.state = 'CANCEL_REQUESTED'
                           AND attempt.terminal_at IS NULL
                           AND work.state = 'CANCEL_REQUESTED'
                           AND work.current_attempt_id = observation.attempt_id
                           AND workflow.workflow_type = 'WORK_ITEM_CANCELLATION'
                           AND workflow.reducer_version = 'asf.workflow/v1'
                           AND workflow.state = 'WAITING'
                           AND workflow.terminal_at IS NULL
                           AND anchor.anchor_type = 'WORKFLOW'
                           AND anchor.reference_id = workflow.id
                           AND anchor.wake_or_deadline_at IS NULL
                           AND NOT anchor.authority_or_effect_active
                           AND run.state = 'CANCEL_REQUESTED'
                           AND run.terminal_at IS NULL
                           AND run.last_observed_at = observation.observed_at
                           AND run.snapshot -> 'runmill_cancellation' =
                               jsonb_build_object(
                                   'schema',
                                       'asf.runmill-cancellation-observation/v1',
                                   'request_id', observation.request_id,
                                   'request_digest', observation.request_digest,
                                   'disposition', NEW.result #>>
                                       '{result,disposition}',
                                   'external_phase', NEW.result #>>
                                       '{result,external_phase}',
                                   'external_generation',
                                       observation.external_generation,
                                   'external_state_version',
                                       observation.external_state_version,
                                   'external_latest_sequence',
                                       observation.external_latest_sequence,
                                   'reconciliation_required',
                                       observation.reconciliation_required,
                                   'cancellation_observation_id', observation.id,
                                   'prior_cancellation_observation_id',
                                       observation.prior_observation_id,
                                   'observed_at',
                                       asf_chrono_utc(observation.observed_at)
                               )
                           AND NEW.result ->> 'workflow_step_commit_digest' =
                               asf_source_closure_digest(jsonb_build_object(
                                   'job_id', NEW.id,
                                   'run_id', observation.run_id,
                                   'request_digest', observation.request_digest,
                                   'job_result', NEW.result -> 'result',
                                   'work_item_state', work.state,
                                   'workflow_state', workflow.state,
                                   'accountability_kind', anchor.anchor_type,
                                   'accountability_reference', anchor.reference_id,
                                   'released_reservations', 0,
                                   'cancellation_observation_id', observation.id,
                                   'prior_cancellation_observation_id',
                                       observation.prior_observation_id,
                                   'terminal_receipt_id', NEW.result #>
                                       '{result,terminal_receipt_id}',
                                   'observation_job', NEW.result #>
                                       '{result,observation_job}',
                                   'escalation_id', NEW.result #>
                                       '{result,escalation_id}',
                                   'escalation_deadline', NEW.result #>
                                       '{result,escalation_deadline}',
                                   'escalation_disposition', NEW.result #>
                                       '{result,escalation_disposition}',
                                   'escalation_before_digest', NEW.result #>
                                       '{result,escalation_before_digest}',
                                   'escalation_after_digest', NEW.result #>
                                       '{result,escalation_after_digest}'
                               ))
                           AND audit.work_item_id = observation.work_item_id
                           AND audit.attempt_id = observation.attempt_id
                           AND audit.actor_type = 'SERVICE'
                           AND audit.actor_id = NEW.completed_by
                           AND audit.action = 'RUNMILL_CANCELLATION_ACCEPTED'
                           AND audit.subject_type = 'RUN'
                           AND audit.subject_id = observation.run_id::text
                           AND audit.correlation_id = observation.request_id
                           AND audit.trace_id IS NULL
                           AND audit.policy_digest IS NOT DISTINCT FROM
                               work.policy_digest
                           AND audit.before_digest IS NULL
                           AND audit.after_digest = observation.request_digest
                           AND audit.occurred_at = observation.observed_at
                           AND audit.details = jsonb_build_object(
                               'work_item_id', observation.work_item_id,
                               'attempt_id', observation.attempt_id,
                               'external_run_id', run.external_run_id,
                               'request_id', observation.request_id,
                               'request_digest', observation.request_digest,
                               'request_reason_digest',
                                   asf_source_closure_digest(jsonb_build_object(
                                       'reason', effect.request_payload ->> 'reason'
                                   )),
                               'runmill_requester_subject',
                                   effect.request_payload #>> '{requester,subject}',
                               'reconciliation_job_reason_digest',
                                   asf_source_closure_digest(jsonb_build_object(
                                       'reason', NEW.payload ->> 'reason'
                                   )),
                               'reconciliation_requested_by',
                                   NEW.payload ->> 'requested_by',
                               'persisted_request_adopted',
                                   effect.request_payload ->> 'reason' <>
                                   NEW.payload ->> 'reason',
                               'disposition', NEW.result #>> '{result,disposition}',
                               'external_phase', NEW.result #>>
                                   '{result,external_phase}',
                               'reconciliation_required',
                                   observation.reconciliation_required,
                               'route', 'cancellation_in_progress',
                               'released_reservations', 0,
                               'cancellation_observation_id', observation.id,
                               'terminal_receipt_id', NEW.result #>
                                   '{result,terminal_receipt_id}',
                               'observation_job_id', NEW.result #>
                                   '{result,observation_job,id}',
                               'observation_available_at', NEW.result #>
                                   '{result,observation_job,available_at}',
                               'escalation_id', NEW.result #>
                                   '{result,escalation_id}',
                               'escalation_deadline', NEW.result #>
                                   '{result,escalation_deadline}',
                               'escalation_disposition', NEW.result #>
                                   '{result,escalation_disposition}',
                               'escalation_before_digest', NEW.result #>
                                   '{result,escalation_before_digest}',
                               'escalation_after_digest', NEW.result #>
                                   '{result,escalation_after_digest}'
                           )
                           AND audit.event_hash = asf_recomputed_audit_event_hash(
                               audit.tenant_id, audit.id
                           )
                           AND emitted.topic = 'work-items'
                           AND emitted.message_key = observation.work_item_id::text
                           AND emitted.event_type =
                               'work_item.cancellation_in_progress'
                           AND emitted.headers =
                               '{"schema":"asf.work-item-event/v1"}'::jsonb
                           AND emitted.idempotency_key =
                               'runmill-cancellation:' || NEW.id::text || ':outbox'
                           AND emitted.available_at = observation.observed_at
                           AND emitted.created_at BETWEEN
                               observation.observed_at AND NEW.completed_at
                           AND emitted.status = 'PENDING'
                           AND emitted.attempt_count = 0
                           AND emitted.fence_token = 0
                           AND emitted.lease_owner IS NULL
                           AND emitted.lease_expires_at IS NULL
                           AND emitted.last_error IS NULL
                           AND emitted.published_at IS NULL
                           AND emitted.payload = jsonb_build_object(
                               'work_item_id', observation.work_item_id,
                               'attempt_id', observation.attempt_id,
                               'run_id', observation.run_id,
                               'external_run_id', run.external_run_id,
                               'request_id', observation.request_id,
                               'request_digest', observation.request_digest,
                               'external_phase', NEW.result #>>
                                   '{result,external_phase}',
                               'route', 'cancellation_in_progress',
                               'released_reservations', 0,
                               'cancellation_observation_id', observation.id,
                               'terminal_receipt_id', NEW.result #>
                                   '{result,terminal_receipt_id}',
                               'observation_job_id', NEW.result #>
                                   '{result,observation_job,id}',
                               'observation_available_at', NEW.result #>
                                   '{result,observation_job,available_at}',
                               'escalation_id', NEW.result #>
                                   '{result,escalation_id}',
                               'escalation_deadline', NEW.result #>
                                   '{result,escalation_deadline}',
                               'escalation_disposition', NEW.result #>
                                   '{result,escalation_disposition}',
                               'escalation_before_digest', NEW.result #>
                                   '{result,escalation_before_digest}',
                               'escalation_after_digest', NEW.result #>
                                   '{result,escalation_after_digest}'
                           )
                     )
                 )
             )
       ) THEN
        RAISE EXCEPTION 'completed cancellation job has no exact observation receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'completed_cancellation_jobs_require_observation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_jobs_completed_cancellation_observation
    AFTER UPDATE ON workflow_jobs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_completed_cancellation_job_observation();

-- PostgreSQL owns the digest representation of persisted escalation JSON, and
-- Rust reads this function's result instead of independently serializing the
-- row. Keeping the helper independent of the table also lets the UPDATE
-- trigger authenticate both OLD and NEW; the prior row is otherwise
-- unrecoverable after the statement finishes.
CREATE FUNCTION asf_terminal_conflict_escalation_row_digest(
    escalation_id uuid,
    escalation_tenant_id uuid,
    escalation_work_item_id uuid,
    escalation_attempt_id uuid,
    escalation_run_id uuid,
    escalation_category text,
    escalation_status text,
    escalation_severity text,
    escalation_reason text,
    escalation_owner_type text,
    escalation_owner_id text,
    escalation_required_action text,
    escalation_evidence_references jsonb,
    escalation_deadline timestamptz,
    escalation_escalation_path jsonb,
    escalation_retry_policy jsonb,
    escalation_prerequisites jsonb,
    escalation_authority_or_effect_active boolean,
    escalation_idempotency_key text,
    escalation_aggregate_version bigint,
    escalation_opened_at timestamptz,
    escalation_acknowledged_at timestamptz,
    escalation_closed_at timestamptz
) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.terminal-conflict-escalation-state/v1',
        'id', escalation_id,
        'tenant_id', escalation_tenant_id,
        'work_item_id', escalation_work_item_id,
        'attempt_id', escalation_attempt_id,
        'run_id', escalation_run_id,
        'category', escalation_category,
        'status', escalation_status,
        'severity', escalation_severity,
        'reason', escalation_reason,
        'owner_type', escalation_owner_type,
        'owner_id', escalation_owner_id,
        'required_action', escalation_required_action,
        'evidence_references', escalation_evidence_references,
        'deadline', asf_chrono_utc(escalation_deadline),
        'escalation_path', escalation_escalation_path,
        'retry_policy', escalation_retry_policy,
        'prerequisites', escalation_prerequisites,
        'authority_or_effect_active', escalation_authority_or_effect_active,
        'idempotency_key', escalation_idempotency_key,
        'aggregate_version', escalation_aggregate_version,
        'opened_at', asf_chrono_utc(escalation_opened_at),
        'acknowledged_at', CASE
            WHEN escalation_acknowledged_at IS NULL THEN NULL
            ELSE asf_chrono_utc(escalation_acknowledged_at)
        END,
        'closed_at', CASE
            WHEN escalation_closed_at IS NULL THEN NULL
            ELSE asf_chrono_utc(escalation_closed_at)
        END
    ));
$$;

CREATE FUNCTION asf_terminal_conflict_escalation_digest(
    candidate_tenant uuid,
    candidate_escalation uuid
) RETURNS text
LANGUAGE sql STABLE
AS $$
    SELECT asf_terminal_conflict_escalation_row_digest(
        escalation.id,
        escalation.tenant_id,
        escalation.work_item_id,
        escalation.attempt_id,
        escalation.run_id,
        escalation.category,
        escalation.status,
        escalation.severity,
        escalation.reason,
        escalation.owner_type,
        escalation.owner_id,
        escalation.required_action,
        escalation.evidence_references,
        escalation.deadline,
        escalation.escalation_path,
        escalation.retry_policy,
        escalation.prerequisites,
        escalation.authority_or_effect_active,
        escalation.idempotency_key,
        escalation.aggregate_version,
        escalation.opened_at,
        escalation.acknowledged_at,
        escalation.closed_at
    )
    FROM escalations AS escalation
    WHERE escalation.tenant_id = candidate_tenant
      AND escalation.id = candidate_escalation;
$$;

-- These helpers mirror the Rust merge operators.  Array membership uses full
-- JSON equality (rather than jsonb containment, whose object-subset semantics
-- would not match `Value::contains`).
CREATE FUNCTION asf_append_semantic_clause(
    existing_value text,
    addition text
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN position(addition IN existing_value) > 0 THEN existing_value
        ELSE existing_value || '; ' || addition
    END;
$$;

CREATE FUNCTION asf_merge_jsonb_arrays(
    existing_values jsonb,
    additions jsonb
) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    merged jsonb := existing_values;
    addition jsonb;
BEGIN
    IF jsonb_typeof(existing_values) <> 'array'
       OR jsonb_typeof(additions) <> 'array' THEN
        RAISE EXCEPTION 'semantic merge operands must both be JSON arrays'
            USING ERRCODE = '22023';
    END IF;
    FOR addition IN SELECT value FROM jsonb_array_elements(additions)
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(merged) AS present(value)
            WHERE present.value = addition
        ) THEN
            merged := merged || jsonb_build_array(addition);
        END IF;
    END LOOP;
    RETURN merged;
END;
$$;

CREATE FUNCTION asf_nonempty_jsonb_string_array(candidate jsonb)
RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(candidate) = 'array'
       AND jsonb_array_length(candidate) > 0
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(candidate) AS element(value)
           WHERE jsonb_typeof(element.value) <> 'string'
              OR btrim(element.value #>> '{}') = ''
       );
$$;

-- A merged REMOTE_EFFECT_AMBIGUOUS escalation reports the digest of its OLD
-- row in the terminal job/audit/outbox.  Preserve that otherwise-ephemeral
-- state as a trigger-generated, append-only transition receipt.
CREATE TABLE terminal_conflict_escalation_merge_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    escalation_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    run_id_after uuid NOT NULL,
    effect_intent_id uuid NOT NULL,
    terminal_observation_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    aggregate_version_before bigint NOT NULL CHECK (aggregate_version_before > 0),
    aggregate_version_after bigint NOT NULL CHECK (aggregate_version_after > 1),
    before_digest text NOT NULL CHECK (before_digest ~ '^sha256:[0-9a-f]{64}$'),
    after_digest text NOT NULL CHECK (after_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, escalation_id, aggregate_version_after),
    FOREIGN KEY (tenant_id, escalation_id, work_item_id)
        REFERENCES escalations(tenant_id, id, work_item_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, run_id_after, work_item_id, attempt_id)
        REFERENCES runs(tenant_id, id, work_item_id, attempt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        tenant_id, terminal_observation_id, effect_intent_id,
        work_item_id, attempt_id, run_id_after
    ) REFERENCES runmill_cancellation_observations (
        tenant_id, id, effect_intent_id, work_item_id, attempt_id, run_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, workflow_job_id)
        REFERENCES workflow_jobs(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (aggregate_version_after = aggregate_version_before + 1),
    CHECK (
        id = asf_stable_cancellation_receipt_uuid(
            'asf.terminal-conflict-escalation-merge-receipt/v1',
            escalation_id,
            aggregate_version_after
        )
    )
);

CREATE FUNCTION asf_stamp_terminal_conflict_escalation_merge_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- A direct INSERT enters this trigger at depth one.  The only supported
    -- producer is the nested INSERT made by the escalations AFTER UPDATE
    -- trigger below.
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION
            'terminal-conflict escalation merge receipts are trigger-generated'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'terminal_conflict_escalation_merge_receipts_generated_only';
    END IF;

    NEW.id := asf_stable_cancellation_receipt_uuid(
        'asf.terminal-conflict-escalation-merge-receipt/v1',
        NEW.escalation_id,
        NEW.aggregate_version_after
    );
    NEW.recorded_at := clock_timestamp();
    NEW.receipt_digest := asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.terminal-conflict-escalation-merge-receipt/v1',
        'id', NEW.id,
        'tenant_id', NEW.tenant_id,
        'escalation_id', NEW.escalation_id,
        'work_item_id', NEW.work_item_id,
        'attempt_id', NEW.attempt_id,
        'run_id_after', NEW.run_id_after,
        'effect_intent_id', NEW.effect_intent_id,
        'terminal_observation_id', NEW.terminal_observation_id,
        'workflow_job_id', NEW.workflow_job_id,
        'aggregate_version_before', NEW.aggregate_version_before,
        'aggregate_version_after', NEW.aggregate_version_after,
        'before_digest', NEW.before_digest,
        'after_digest', NEW.after_digest
    ));
    RETURN NEW;
END;
$$;

CREATE TRIGGER terminal_conflict_escalation_merge_receipts_stamp
    BEFORE INSERT ON terminal_conflict_escalation_merge_receipts
    FOR EACH ROW
    EXECUTE FUNCTION asf_stamp_terminal_conflict_escalation_merge_receipt();
CREATE TRIGGER terminal_conflict_escalation_merge_receipts_append_only
    BEFORE UPDATE OR DELETE ON terminal_conflict_escalation_merge_receipts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER terminal_conflict_escalation_merge_receipts_truncate_forbidden
    BEFORE TRUNCATE ON terminal_conflict_escalation_merge_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE FUNCTION asf_capture_terminal_conflict_escalation_merge_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    cancellation_context record;
    cancellation_reason text;
    cancellation_action text :=
        'inspect the terminal Runmill evidence and explicitly close, retry, or cancel the work item';
    cancellation_evidence jsonb;
    cancellation_path jsonb := jsonb_build_array(
        jsonb_build_object(
            'owner_type', 'ON_CALL',
            'owner_id', 'platform-operations'
        ),
        jsonb_build_object(
            'owner_type', 'TEAM',
            'owner_id', 'platform-engineering'
        )
    );
    cancellation_prerequisites jsonb := jsonb_build_array(
        'verify terminal Runmill evidence',
        'reconcile remote delivery effects',
        'record an explicit operator disposition'
    );
    expected_evidence jsonb;
    expected_path jsonb;
    expected_prerequisites jsonb;
    expected_retry_policy jsonb;
BEGIN
    -- Only the transaction which has just recorded an exact terminal Runmill
    -- observation under its still-RUNNING claim can produce this receipt.
    -- Ordinary escalation updates therefore never add an escalation -> run FK
    -- lock edge, preserving the runtime's run -> escalation lock order.
    SELECT
        observation.id AS terminal_observation_id,
        observation.effect_intent_id,
        observation.workflow_job_id,
        observation.request_id,
        observation.observed_at,
        run.external_run_id,
        run.snapshot #>> '{runmill_cancellation,external_phase}' AS external_phase
    INTO cancellation_context
    FROM runmill_cancellation_observations AS observation
    JOIN effect_intents AS effect
      ON effect.tenant_id = observation.tenant_id
     AND effect.id = observation.effect_intent_id
     AND effect.work_item_id = observation.work_item_id
     AND effect.attempt_id = observation.attempt_id
    JOIN runmill_cancellation_observations AS initial_observation
      ON initial_observation.tenant_id = effect.tenant_id
     AND initial_observation.id = effect.initial_cancellation_observation_id
     AND initial_observation.effect_intent_id = effect.id
     AND initial_observation.work_item_id = effect.work_item_id
     AND initial_observation.attempt_id = effect.attempt_id
     AND initial_observation.run_id = observation.run_id
     AND initial_observation.workflow_instance_id =
         observation.workflow_instance_id
    JOIN runs AS run
      ON run.tenant_id = observation.tenant_id
     AND run.id = observation.run_id
     AND run.work_item_id = observation.work_item_id
     AND run.attempt_id = observation.attempt_id
    JOIN workflow_jobs AS job
      ON job.tenant_id = observation.tenant_id
     AND job.id = observation.workflow_job_id
     AND job.workflow_instance_id = observation.workflow_instance_id
     AND job.work_item_id = observation.work_item_id
     AND job.attempt_id = observation.attempt_id
    WHERE observation.tenant_id = NEW.tenant_id
      AND observation.work_item_id = NEW.work_item_id
      AND observation.attempt_id = NEW.attempt_id
      AND observation.run_id = NEW.run_id
      AND observation.external_phase IN (
          'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED'
      )
      AND (
          (observation.route = 'INITIAL'
           AND observation.id = initial_observation.id)
          OR
          observation.route = 'OBSERVER'
      )
      AND run.authoritative
      AND run.state IN ('SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED')
      AND run.last_observed_at = observation.observed_at
      AND run.terminal_at = observation.observed_at
      AND run.snapshot #>>
          '{runmill_cancellation,cancellation_observation_id}' =
          observation.id::text
      AND run.snapshot #>> '{runmill_cancellation,request_id}' =
          observation.request_id
      AND run.snapshot #>> '{runmill_cancellation,request_digest}' =
          observation.request_digest
      AND (
          (observation.external_phase = 'SUCCEEDED'
           AND run.snapshot #>> '{runmill_cancellation,external_phase}' =
               'COMPLETED')
          OR
          (observation.external_phase = 'FAILED'
           AND run.snapshot #>> '{runmill_cancellation,external_phase}' IN (
               'FAILED', 'BUDGET_EXHAUSTED'
           ))
          OR
          (observation.external_phase IN ('REFUSED', 'QUARANTINED')
           AND run.snapshot #>> '{runmill_cancellation,external_phase}' =
               observation.external_phase)
      )
      AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
      AND job.status = 'RUNNING'
      AND job.fence_token = observation.workflow_job_fence_token
      AND job.attempt_count = observation.workflow_job_attempt_count
      AND job.lease_owner = observation.workflow_job_owner
      AND job.lease_expires_at > transaction_timestamp()
      AND asf_valid_runmill_cancellation_effect_observation(
          effect.tenant_id, effect.id, initial_observation.id
      );

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    cancellation_reason :=
        'Runmill was already terminal in ' ||
        cancellation_context.external_phase ||
        ' when cancellation was reconciled';
    cancellation_evidence := jsonb_build_array(
        'run:' || NEW.run_id::text,
        'external-run:' || cancellation_context.external_run_id,
        'cancellation-request:' || cancellation_context.request_id,
        'effect-intent:' || cancellation_context.effect_intent_id::text
    );
    expected_evidence := asf_merge_jsonb_arrays(
        OLD.evidence_references, cancellation_evidence
    );
    IF OLD.run_id IS NOT NULL AND OLD.run_id <> NEW.run_id THEN
        expected_evidence := asf_merge_jsonb_arrays(
            expected_evidence,
            jsonb_build_array('prior-escalation-run:' || OLD.run_id::text)
        );
    END IF;
    expected_path := asf_merge_jsonb_arrays(
        OLD.escalation_path, cancellation_path
    );
    expected_prerequisites := asf_merge_jsonb_arrays(
        OLD.prerequisites, cancellation_prerequisites
    );
    IF OLD.retry_policy ? 'prerequisites' THEN
        expected_prerequisites := asf_merge_jsonb_arrays(
            expected_prerequisites,
            OLD.retry_policy -> 'prerequisites'
        );
    END IF;
    expected_retry_policy := jsonb_build_object(
        'automatic', false,
        'max_additional_attempts', 0,
        'backoff_seconds', 0,
        'prerequisites', expected_prerequisites
    );

    IF OLD.category <> 'REMOTE_EFFECT_AMBIGUOUS'
       OR NEW.category <> OLD.category
       OR OLD.status NOT IN ('OPEN', 'ACKNOWLEDGED')
       OR NEW.status <> OLD.status
       OR NEW.id <> OLD.id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.work_item_id <> OLD.work_item_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.attempt_id IS NULL
       OR NEW.run_id IS NULL
       OR NEW.owner_type <> OLD.owner_type
       OR NEW.owner_id <> OLD.owner_id
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.opened_at <> OLD.opened_at
       OR NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
       OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.severity <> (CASE
           WHEN OLD.severity = 'CRITICAL' THEN 'CRITICAL'
           ELSE 'HIGH'
       END)
       OR NEW.reason <> asf_append_semantic_clause(
           OLD.reason, cancellation_reason
       )
       OR NEW.required_action <> asf_append_semantic_clause(
           OLD.required_action, cancellation_action
       )
       OR NEW.evidence_references <> expected_evidence
       OR NOT asf_nonempty_jsonb_string_array(NEW.evidence_references)
       OR NEW.deadline <> LEAST(
           OLD.deadline,
           cancellation_context.observed_at + interval '4 hours'
       )
       OR NEW.escalation_path <> expected_path
       OR NEW.prerequisites <> expected_prerequisites
       OR NOT asf_nonempty_jsonb_string_array(NEW.prerequisites)
       OR NEW.retry_policy <> expected_retry_policy
       OR NOT NEW.authority_or_effect_active THEN
        RAISE EXCEPTION
            'terminal-conflict escalation update is not the conservative cancellation merge'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'terminal_conflict_escalation_merge_exact';
    END IF;

    INSERT INTO terminal_conflict_escalation_merge_receipts (
        tenant_id,
        escalation_id,
        work_item_id,
        attempt_id,
        run_id_after,
        effect_intent_id,
        terminal_observation_id,
        workflow_job_id,
        aggregate_version_before,
        aggregate_version_after,
        before_digest,
        after_digest
    ) VALUES (
        NEW.tenant_id,
        NEW.id,
        NEW.work_item_id,
        NEW.attempt_id,
        NEW.run_id,
        cancellation_context.effect_intent_id,
        cancellation_context.terminal_observation_id,
        cancellation_context.workflow_job_id,
        OLD.aggregate_version,
        NEW.aggregate_version,
        asf_terminal_conflict_escalation_row_digest(
            OLD.id,
            OLD.tenant_id,
            OLD.work_item_id,
            OLD.attempt_id,
            OLD.run_id,
            OLD.category,
            OLD.status,
            OLD.severity,
            OLD.reason,
            OLD.owner_type,
            OLD.owner_id,
            OLD.required_action,
            OLD.evidence_references,
            OLD.deadline,
            OLD.escalation_path,
            OLD.retry_policy,
            OLD.prerequisites,
            OLD.authority_or_effect_active,
            OLD.idempotency_key,
            OLD.aggregate_version,
            OLD.opened_at,
            OLD.acknowledged_at,
            OLD.closed_at
        ),
        asf_terminal_conflict_escalation_row_digest(
            NEW.id,
            NEW.tenant_id,
            NEW.work_item_id,
            NEW.attempt_id,
            NEW.run_id,
            NEW.category,
            NEW.status,
            NEW.severity,
            NEW.reason,
            NEW.owner_type,
            NEW.owner_id,
            NEW.required_action,
            NEW.evidence_references,
            NEW.deadline,
            NEW.escalation_path,
            NEW.retry_policy,
            NEW.prerequisites,
            NEW.authority_or_effect_active,
            NEW.idempotency_key,
            NEW.aggregate_version,
            NEW.opened_at,
            NEW.acknowledged_at,
            NEW.closed_at
        )
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER escalations_capture_terminal_conflict_merge_receipt
    AFTER UPDATE ON escalations
    FOR EACH ROW
    EXECUTE FUNCTION asf_capture_terminal_conflict_escalation_merge_receipt();

-- A CANCELLED receipt closes every remaining execution-authority route for the
-- work item, not only the exact attempt/run cited by the receipt.  Historical
-- terminal rows remain admissible, while anything claimable, scheduled,
-- leased, reserved, approval-gated, or actively escalated makes the negative
-- proof false.
CREATE FUNCTION asf_runmill_cancelled_work_has_no_live_authority(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT
        NOT EXISTS (
            SELECT 1
            FROM attempts AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.state IN (
                  'CREATED', 'AUTHORIZED', 'DISPATCHING', 'RUNNING',
                  'VERIFYING', 'WAITING_APPROVAL', 'CANCEL_REQUESTED'
              )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM runs AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.state IN (
                  'ADOPTED', 'RUNNING', 'WAITING_APPROVAL', 'VERIFYING',
                  'CANCEL_REQUESTED'
              )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_instances AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.state IN ('ACTIVE', 'WAITING')
        )
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_jobs AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.status IN ('PENDING', 'RUNNING', 'RETRY')
        )
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_timers AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.status = 'SCHEDULED'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM effect_intents AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.status IN ('PENDING', 'IN_FLIGHT', 'AMBIGUOUS')
        )
        AND NOT EXISTS (
            SELECT 1
            FROM reservation_sets AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.state = 'ACTIVE'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM approvals AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.status = 'PENDING'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM escalations AS candidate
            WHERE candidate.tenant_id = candidate_tenant
              AND candidate.work_item_id = candidate_work_item
              AND candidate.status IN ('OPEN', 'ACKNOWLEDGED')
              AND candidate.authority_or_effect_active
        );
$$;

CREATE FUNCTION asf_valid_runmill_cancellation_receipt(
    candidate_tenant uuid,
    candidate_receipt uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        JOIN work_items AS work
          ON work.tenant_id = receipt.tenant_id
         AND work.id = receipt.work_item_id
        JOIN work_cancellation_authority_guards AS authority_guard
          ON authority_guard.tenant_id = work.tenant_id
         AND authority_guard.work_item_id = work.id
        JOIN attempts AS attempt
          ON attempt.tenant_id = receipt.tenant_id
         AND attempt.id = receipt.attempt_id
         AND attempt.work_item_id = receipt.work_item_id
        JOIN runs AS run
          ON run.tenant_id = receipt.tenant_id
         AND run.id = receipt.run_id
         AND run.work_item_id = receipt.work_item_id
         AND run.attempt_id = receipt.attempt_id
        JOIN effect_intents AS effect
          ON effect.tenant_id = receipt.tenant_id
         AND effect.id = receipt.effect_intent_id
         AND effect.work_item_id = receipt.work_item_id
         AND effect.attempt_id = receipt.attempt_id
        JOIN runmill_cancellation_observations AS observation
          ON observation.tenant_id = receipt.tenant_id
         AND observation.id = receipt.terminal_observation_id
         AND observation.effect_intent_id = receipt.effect_intent_id
         AND observation.work_item_id = receipt.work_item_id
         AND observation.attempt_id = receipt.attempt_id
         AND observation.run_id = receipt.run_id
         AND observation.workflow_instance_id = receipt.workflow_instance_id
         AND observation.workflow_job_id = receipt.workflow_job_id
        JOIN runmill_cancellation_observations AS initial_observation
          ON initial_observation.tenant_id = effect.tenant_id
         AND initial_observation.id = effect.initial_cancellation_observation_id
         AND initial_observation.effect_intent_id = effect.id
         AND initial_observation.work_item_id = effect.work_item_id
         AND initial_observation.attempt_id = effect.attempt_id
         AND initial_observation.run_id = receipt.run_id
         AND initial_observation.workflow_instance_id =
             receipt.workflow_instance_id
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = receipt.tenant_id
         AND workflow.id = receipt.workflow_instance_id
         AND workflow.work_item_id = receipt.work_item_id
        JOIN workflow_jobs AS job
          ON job.tenant_id = receipt.tenant_id
         AND job.id = receipt.workflow_job_id
         AND job.workflow_instance_id = receipt.workflow_instance_id
         AND job.work_item_id = receipt.work_item_id
         AND job.attempt_id = receipt.attempt_id
        JOIN audit_events AS audit
          ON audit.tenant_id = receipt.tenant_id
         AND audit.id = receipt.audit_event_id
        JOIN outbox
          ON outbox.tenant_id = receipt.tenant_id
         AND outbox.id = receipt.outbox_event_id
        LEFT JOIN escalations AS escalation
          ON escalation.tenant_id = receipt.tenant_id
         AND escalation.id = receipt.escalation_id
         AND escalation.work_item_id = receipt.work_item_id
         AND escalation.attempt_id = receipt.attempt_id
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = receipt.tenant_id
         AND anchor.work_item_id = receipt.work_item_id
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.id = candidate_receipt
          AND receipt.route = 'RUNMILL'
          AND (
              (
                  receipt.outcome = 'CANCELLED'
                  AND authority_guard.generation =
                      receipt.cancellation_authority_generation
                  AND authority_guard.terminal_receipt_id = receipt.id
              ) OR (
                  receipt.outcome = 'TERMINAL_CONFLICT'
                  AND receipt.cancellation_authority_generation IS NULL
              )
          )
          AND receipt.dispatch_guard_generation IS NULL
          AND receipt.audit_before_digest IS NULL
          AND receipt.audit_after_digest IS NULL
          AND effect.id = asf_derived_uuid(run.id, 4)
          AND observation.id = asf_stable_cancellation_receipt_uuid(
              'asf.runmill-cancellation-observation/v1',
              job.id,
              job.fence_token
          )
          AND initial_observation.id = asf_stable_cancellation_receipt_uuid(
              'asf.runmill-cancellation-observation/v1',
              initial_observation.workflow_job_id,
              initial_observation.workflow_job_fence_token
          )
          AND receipt.id = asf_stable_cancellation_receipt_uuid(
              'asf.runmill-cancellation-terminal-receipt/v1',
              job.id,
              NULL::bigint
          )
          AND audit.id = asf_derived_uuid(job.id, 1)
          AND outbox.id = asf_derived_uuid(job.id, 2)
          AND receipt.work_item_version_after = receipt.work_item_version_before + 1
          AND receipt.attempt_version_after = receipt.attempt_version_before + 1
          AND receipt.run_version_after = receipt.run_version_before + 1
          AND receipt.workflow_version_after = receipt.workflow_version_before + 1
          AND receipt.workflow_fence_after = receipt.workflow_fence_before + 1
          AND receipt.anchor_generation_after = receipt.anchor_generation_before + 1
          AND work.current_attempt_id = receipt.attempt_id
          AND work.aggregate_version = receipt.work_item_version_after
          AND attempt.aggregate_version = receipt.attempt_version_after
          AND attempt.fence_token = receipt.attempt_fence_token
          AND attempt.terminal_at IS NOT NULL
          AND run.authoritative
          AND run.aggregate_version = receipt.run_version_after
          AND run.terminal_at IS NOT NULL
          AND run.last_observed_at = observation.observed_at
          AND run.snapshot -> 'runmill_cancellation' = jsonb_build_object(
              'schema', 'asf.runmill-cancellation-observation/v1',
              'request_id', observation.request_id,
              'request_digest', observation.request_digest,
              'disposition', job.result #>> '{result,disposition}',
              'external_phase', job.result #>> '{result,external_phase}',
              'external_generation', observation.external_generation,
              'external_state_version', observation.external_state_version,
              'external_latest_sequence', observation.external_latest_sequence,
              'reconciliation_required', observation.reconciliation_required,
              'cancellation_observation_id', observation.id,
              'prior_cancellation_observation_id', observation.prior_observation_id,
              'observed_at', asf_chrono_utc(observation.observed_at)
          )
          AND workflow.workflow_type = 'WORK_ITEM_CANCELLATION'
          AND workflow.reducer_version = 'asf.workflow/v1'
          AND workflow.aggregate_version = receipt.workflow_version_after
          AND workflow.fence_token = receipt.workflow_fence_after
          AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND job.status = 'COMPLETED'
          AND job.fence_token = receipt.workflow_job_fence_token
          AND job.completion_fence_token = receipt.workflow_job_fence_token
          AND job.attempt_count = receipt.workflow_job_attempt_count
          AND job.completed_by = receipt.workflow_job_completed_by
          AND job.completed_at IS NOT NULL
          AND job.payload -> 'work_item_id' =
              to_jsonb(receipt.work_item_id::text)
          AND job.payload -> 'worker_id' = to_jsonb(run.worker_id::text)
          AND job.payload -> 'expected_version' =
              to_jsonb(receipt.work_item_version_before)
          AND jsonb_typeof(job.payload -> 'reason') = 'string'
          AND job.payload ->> 'reason' = btrim(job.payload ->> 'reason')
          AND octet_length(job.payload ->> 'reason') BETWEEN 1 AND 2048
          AND jsonb_typeof(job.payload -> 'requested_by') = 'string'
          AND octet_length(btrim(job.payload ->> 'requested_by')) BETWEEN 1 AND 1024
          AND (
              (
                  observation.route = 'INITIAL'
                  AND job.payload - ARRAY[
                      'work_item_id', 'worker_id', 'expected_version',
                      'reason', 'requested_by'
                  ]::text[] = '{}'::jsonb
              ) OR (
                  observation.route = 'OBSERVER'
                  AND (
                      (
                          NOT (job.payload ? 'observe_only')
                          AND job.payload - ARRAY[
                              'work_item_id', 'worker_id', 'expected_version',
                              'reason', 'requested_by'
                          ]::text[] = '{}'::jsonb
                      ) OR (
                          job.payload -> 'observe_only' = 'true'::jsonb
                          AND job.payload - ARRAY[
                              'work_item_id', 'worker_id', 'expected_version',
                              'reason', 'requested_by', 'observe_only'
                          ]::text[] = '{}'::jsonb
                          AND job.idempotency_key =
                              'runmill-cancellation:' || observation.request_id ||
                              ':observe-terminal'
                      )
                  )
              )
          )
          AND job.result - ARRAY[
              'workflow_step_commit_digest', 'result'
          ]::text[] = '{}'::jsonb
          AND job.result ->> 'workflow_step_commit_digest' =
              asf_source_closure_digest(jsonb_build_object(
                  'job_id', job.id,
                  'run_id', receipt.run_id,
                  'request_digest', observation.request_digest,
                  'job_result', job.result -> 'result',
                  'work_item_state', work.state,
                  'workflow_state', workflow.state,
                  'accountability_kind', anchor.anchor_type,
                  'accountability_reference', anchor.reference_id,
                  'released_reservations', receipt.released_reservations,
                  'cancellation_observation_id', observation.id,
                  'prior_cancellation_observation_id', observation.prior_observation_id,
                  'terminal_receipt_id', receipt.id,
                  'observation_job', job.result #> '{result,observation_job}',
                  'escalation_id', receipt.escalation_id,
                  'escalation_deadline', job.result #> '{result,escalation_deadline}',
                  'escalation_disposition', job.result #> '{result,escalation_disposition}',
                  'escalation_before_digest', job.result #> '{result,escalation_before_digest}',
                  'escalation_after_digest', job.result #> '{result,escalation_after_digest}'
              ))
          AND (job.result -> 'result') - ARRAY[
              'schema', 'request_id', 'request_digest', 'external_run_id',
              'disposition', 'external_phase', 'reconciliation_required',
              'route', 'released_reservations',
              'cancellation_observation_id', 'terminal_receipt_id',
              'observation_job', 'escalation_id', 'escalation_deadline',
              'escalation_disposition', 'escalation_before_digest',
              'escalation_after_digest'
          ]::text[] = '{}'::jsonb
          AND jsonb_typeof(job.result #> '{result,schema}') = 'string'
          AND jsonb_typeof(job.result #> '{result,request_id}') = 'string'
          AND jsonb_typeof(job.result #> '{result,request_digest}') = 'string'
          AND jsonb_typeof(job.result #> '{result,external_run_id}') = 'string'
          AND jsonb_typeof(job.result #> '{result,disposition}') = 'string'
          AND jsonb_typeof(job.result #> '{result,external_phase}') = 'string'
          AND jsonb_typeof(job.result #> '{result,cancellation_observation_id}') = 'string'
          AND jsonb_typeof(job.result #> '{result,terminal_receipt_id}') = 'string'
          AND job.result #>> '{result,schema}' =
              'asf.runmill-cancellation-result/v1'
          AND job.result #>> '{result,terminal_receipt_id}' = receipt.id::text
          AND job.result #>> '{result,cancellation_observation_id}' = observation.id::text
          AND job.result #>> '{result,request_id}' = observation.request_id
          AND job.result #>> '{result,request_digest}' = observation.request_digest
          AND job.result #>> '{result,external_run_id}' = run.external_run_id
          AND job.result #>> '{result,disposition}' = CASE
              observation.disposition
              WHEN 'REQUESTED' THEN 'requested'
              WHEN 'EXISTING' THEN 'existing'
              WHEN 'ALREADY_TERMINAL' THEN 'already-terminal'
          END
          AND (
              (observation.external_phase = 'SUCCEEDED'
               AND job.result #>> '{result,external_phase}' = 'COMPLETED')
              OR (observation.external_phase = 'FAILED'
                  AND job.result #>> '{result,external_phase}' IN (
                      'FAILED', 'BUDGET_EXHAUSTED'
                  ))
              OR (observation.external_phase IN (
                      'REFUSED', 'QUARANTINED', 'CANCELLED'
                  )
                  AND job.result #>> '{result,external_phase}' =
                      observation.external_phase)
          )
          AND jsonb_typeof(job.result #> '{result,reconciliation_required}') = 'boolean'
          AND job.result #>> '{result,reconciliation_required}' =
              observation.reconciliation_required::text
          AND jsonb_typeof(job.result #> '{result,released_reservations}') = 'number'
          AND job.result #>> '{result,released_reservations}' =
              receipt.released_reservations::text
          AND job.result #> '{result,observation_job}' = 'null'::jsonb
          AND effect.provider = 'runmill'
          AND effect.effect_type = 'request_cancellation'
          AND effect.status = 'OBSERVED'
          AND asf_valid_runmill_cancellation_effect_observation(
              receipt.tenant_id,
              effect.id,
              initial_observation.id
          )
          AND asf_valid_runmill_cancellation_effect_request(
              receipt.tenant_id, effect.id, receipt.run_id
          )
          AND effect.initial_cancellation_observation_id IS NOT NULL
          AND effect.request_digest = observation.request_digest
          AND effect.correlation_marker = observation.request_id
          AND effect.observed_at = initial_observation.observed_at
          AND jsonb_typeof(effect.observed_outcome -> 'schema') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'status') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'request_id') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'request_digest') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'disposition') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'external_phase') = 'string'
          AND jsonb_typeof(effect.observed_outcome -> 'external_generation') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'external_state_version') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'external_latest_sequence') = 'number'
          AND jsonb_typeof(effect.observed_outcome -> 'reconciliation_required') = 'boolean'
          AND jsonb_typeof(effect.observed_outcome -> 'cancellation_observation_id') = 'string'
          AND effect.observed_outcome ->> 'schema' =
              'asf.runmill-cancellation-effect/v1'
          AND effect.observed_outcome ->> 'status' = 'observed'
          AND effect.observed_outcome ->> 'request_id' = initial_observation.request_id
          AND effect.observed_outcome ->> 'request_digest' =
              initial_observation.request_digest
          AND effect.observed_outcome ->> 'disposition' = CASE
              initial_observation.disposition
              WHEN 'REQUESTED' THEN 'requested'
              WHEN 'EXISTING' THEN 'existing'
              WHEN 'ALREADY_TERMINAL' THEN 'already-terminal'
          END
          AND effect.observed_outcome ->> 'external_phase' = CASE
              initial_observation.external_phase
              WHEN 'SUCCEEDED' THEN 'COMPLETED'
              WHEN 'FAILED' THEN effect.observed_outcome ->> 'external_phase'
              ELSE initial_observation.external_phase
          END
          AND (
              initial_observation.external_phase <> 'FAILED'
              OR effect.observed_outcome ->> 'external_phase' IN (
                  'FAILED', 'BUDGET_EXHAUSTED'
              )
          )
          AND effect.observed_outcome -> 'external_generation' =
              to_jsonb(initial_observation.external_generation)
          AND effect.observed_outcome -> 'external_state_version' =
              to_jsonb(initial_observation.external_state_version)
          AND effect.observed_outcome -> 'external_latest_sequence' =
              to_jsonb(initial_observation.external_latest_sequence)
          AND effect.observed_outcome -> 'reconciliation_required' =
              to_jsonb(initial_observation.reconciliation_required)
          AND effect.observed_outcome ->> 'cancellation_observation_id' =
              initial_observation.id::text
          AND effect.observed_outcome - ARRAY[
              'schema', 'status', 'request_id', 'request_digest',
              'disposition', 'external_phase', 'external_generation',
              'external_state_version', 'external_latest_sequence',
              'reconciliation_required', 'cancellation_observation_id'
          ]::text[] = '{}'::jsonb
          AND initial_observation.route = 'INITIAL'
          AND initial_observation.prior_observation_id IS NULL
          AND observation.workflow_instance_id = workflow.id
          AND observation.workflow_job_id = job.id
          AND observation.workflow_job_fence_token = job.fence_token
          AND observation.workflow_job_attempt_count = job.attempt_count
          AND observation.workflow_job_owner = job.completed_by
          AND NOT EXISTS (
              SELECT 1
              FROM runmill_cancellation_observations AS successor
              WHERE successor.tenant_id = observation.tenant_id
                AND successor.prior_observation_id = observation.id
          )
          AND observation.external_phase IN (
              'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED', 'CANCELLED'
          )
          AND run.state = observation.external_phase
          AND attempt.state = observation.external_phase
          AND audit.work_item_id = receipt.work_item_id
          AND audit.attempt_id = receipt.attempt_id
          AND audit.actor_type = 'SERVICE'
          AND audit.actor_id = receipt.workflow_job_completed_by
          AND audit.subject_type = 'RUN'
          AND audit.subject_id = receipt.run_id::text
          AND audit.correlation_id = observation.request_id
          AND audit.trace_id IS NULL
          AND audit.policy_digest = work.policy_digest
          AND audit.occurred_at = observation.observed_at
          AND audit.event_hash = asf_recomputed_audit_event_hash(
              audit.tenant_id, audit.id
          )
          AND audit.details - ARRAY[
              'work_item_id', 'attempt_id', 'external_run_id', 'request_id',
              'request_digest', 'request_reason_digest',
              'runmill_requester_subject',
              'reconciliation_job_reason_digest',
              'reconciliation_requested_by', 'persisted_request_adopted',
              'disposition', 'external_phase', 'reconciliation_required',
              'route', 'released_reservations',
              'cancellation_observation_id', 'terminal_receipt_id',
              'observation_job_id', 'observation_available_at',
              'escalation_id', 'escalation_deadline',
              'escalation_disposition', 'escalation_before_digest',
              'escalation_after_digest'
          ]::text[] = '{}'::jsonb
          AND audit.details ->> 'work_item_id' = receipt.work_item_id::text
          AND audit.details ->> 'attempt_id' = receipt.attempt_id::text
          AND audit.details ->> 'external_run_id' = run.external_run_id
          AND audit.details ->> 'request_id' = observation.request_id
          AND audit.details ->> 'terminal_receipt_id' = receipt.id::text
          AND audit.details ->> 'cancellation_observation_id' = observation.id::text
          AND audit.details ->> 'request_digest' = observation.request_digest
          AND audit.details ->> 'request_reason_digest' =
              asf_source_closure_digest(jsonb_build_object(
                  'reason', effect.request_payload ->> 'reason'
              ))
          AND audit.details ->> 'runmill_requester_subject' =
              effect.request_payload #>> '{requester,subject}'
          AND audit.details ->> 'reconciliation_job_reason_digest' =
              asf_source_closure_digest(jsonb_build_object(
                  'reason', job.payload ->> 'reason'
              ))
          AND audit.details ->> 'reconciliation_requested_by' =
              job.payload ->> 'requested_by'
          AND jsonb_typeof(audit.details -> 'persisted_request_adopted') = 'boolean'
          AND audit.details ->> 'persisted_request_adopted' =
              (effect.request_payload ->> 'reason' <>
               job.payload ->> 'reason')::text
          AND audit.details ->> 'disposition' =
              job.result #>> '{result,disposition}'
          AND audit.details ->> 'external_phase' =
              job.result #>> '{result,external_phase}'
          AND jsonb_typeof(audit.details -> 'reconciliation_required') = 'boolean'
          AND audit.details ->> 'reconciliation_required' =
              observation.reconciliation_required::text
          AND audit.details ->> 'route' = job.result #>> '{result,route}'
          AND jsonb_typeof(audit.details -> 'released_reservations') = 'number'
          AND audit.details ->> 'released_reservations' =
              receipt.released_reservations::text
          AND audit.details -> 'observation_job_id' = 'null'::jsonb
          AND audit.details -> 'observation_available_at' = 'null'::jsonb
          AND outbox.topic = 'work-items'
          AND outbox.message_key = receipt.work_item_id::text
          AND outbox.headers = '{"schema":"asf.work-item-event/v1"}'::jsonb
          AND outbox.idempotency_key =
              'runmill-cancellation:' || job.id::text || ':outbox'
          AND outbox.payload - ARRAY[
              'work_item_id', 'attempt_id', 'run_id', 'external_run_id',
              'request_id', 'request_digest', 'external_phase', 'route',
              'released_reservations', 'cancellation_observation_id',
              'terminal_receipt_id', 'observation_job_id',
              'observation_available_at', 'escalation_id',
              'escalation_deadline', 'escalation_disposition',
              'escalation_before_digest', 'escalation_after_digest'
          ]::text[] = '{}'::jsonb
          AND outbox.payload ->> 'work_item_id' = receipt.work_item_id::text
          AND outbox.payload ->> 'attempt_id' = receipt.attempt_id::text
          AND outbox.payload ->> 'run_id' = receipt.run_id::text
          AND outbox.payload ->> 'external_run_id' = run.external_run_id
          AND outbox.payload ->> 'request_id' = observation.request_id
          AND outbox.payload ->> 'terminal_receipt_id' = receipt.id::text
          AND outbox.payload ->> 'cancellation_observation_id' = observation.id::text
          AND outbox.payload ->> 'request_digest' = observation.request_digest
          AND outbox.payload ->> 'external_phase' =
              job.result #>> '{result,external_phase}'
          AND outbox.payload ->> 'route' = job.result #>> '{result,route}'
          AND jsonb_typeof(outbox.payload -> 'released_reservations') = 'number'
          AND outbox.payload ->> 'released_reservations' =
              receipt.released_reservations::text
          AND outbox.payload -> 'observation_job_id' = 'null'::jsonb
          AND outbox.payload -> 'observation_available_at' = 'null'::jsonb
          AND NOT EXISTS (
              SELECT 1
              FROM reservation_sets AS active_set
              WHERE active_set.tenant_id = receipt.tenant_id
                AND active_set.work_item_id = receipt.work_item_id
                AND active_set.attempt_id = receipt.attempt_id
                AND active_set.state = 'ACTIVE'
          )
          AND (
              SELECT count(*)
              FROM reservation_sets AS released_set
              WHERE released_set.tenant_id = receipt.tenant_id
                AND released_set.work_item_id = receipt.work_item_id
                AND released_set.attempt_id = receipt.attempt_id
                AND released_set.state = 'RELEASED'
                AND released_set.worker_id = run.worker_id
                AND released_set.cancellation_terminal_receipt_id = receipt.id
                AND released_set.released_at BETWEEN
                    observation.observed_at AND receipt.recorded_at
                AND released_set.fence_token > 1
                AND released_set.transition_idempotency_key =
                    'runmill-cancellation:v1:' || receipt.work_item_id::text || ':' ||
                    receipt.attempt_id::text || ':' || released_set.id::text ||
                    ':fence:' || (released_set.fence_token - 1)::text
                AND released_set.released_by = receipt.workflow_job_completed_by
                AND released_set.release_reason =
                    'terminal Runmill cancellation observation completed the authoritative attempt'
          ) = receipt.released_reservations
          AND anchor.generation = receipt.anchor_generation_after
          AND (
              (
                  receipt.outcome = 'CANCELLED'
                  AND observation.external_phase = 'CANCELLED'
                  AND work.state = 'CANCELLED'
                  AND workflow.state = 'CANCELLED'
                  AND workflow.terminal_at IS NOT NULL
                  AND audit.action = 'WORK_ITEM_CANCELLED'
                  AND audit.before_digest IS NULL
                  AND audit.after_digest = observation.request_digest
                  AND outbox.event_type = 'work_item.cancelled'
                  AND receipt.escalation_id IS NULL
                  AND job.result #>> '{result,route}' = 'cancelled'
                  AND job.result #> '{result,escalation_id}' = 'null'::jsonb
                  AND job.result #> '{result,escalation_deadline}' = 'null'::jsonb
                  AND job.result #> '{result,escalation_disposition}' = 'null'::jsonb
                  AND job.result #> '{result,escalation_before_digest}' = 'null'::jsonb
                  AND job.result #> '{result,escalation_after_digest}' = 'null'::jsonb
                  AND audit.details -> 'escalation_id' = 'null'::jsonb
                  AND audit.details -> 'escalation_deadline' = 'null'::jsonb
                  AND audit.details -> 'escalation_disposition' = 'null'::jsonb
                  AND audit.details -> 'escalation_before_digest' = 'null'::jsonb
                  AND audit.details -> 'escalation_after_digest' = 'null'::jsonb
                  AND outbox.payload -> 'escalation_id' = 'null'::jsonb
                  AND outbox.payload -> 'escalation_deadline' = 'null'::jsonb
                  AND outbox.payload -> 'escalation_disposition' = 'null'::jsonb
                  AND outbox.payload -> 'escalation_before_digest' = 'null'::jsonb
                  AND outbox.payload -> 'escalation_after_digest' = 'null'::jsonb
                  AND anchor.anchor_type = 'CANCELLATION'
                  AND anchor.reference_id = receipt.id
                  AND anchor.wake_or_deadline_at IS NULL
                  AND NOT anchor.authority_or_effect_active
                  AND asf_runmill_cancelled_work_has_no_live_authority(
                      receipt.tenant_id, receipt.work_item_id
                  )
              ) OR (
                  receipt.outcome = 'TERMINAL_CONFLICT'
                  AND observation.external_phase <> 'CANCELLED'
                  AND work.state = 'ESCALATED'
                  AND workflow.state = 'WAITING'
                  AND workflow.terminal_at IS NULL
                  AND audit.action = 'RUNMILL_CANCELLATION_ALREADY_TERMINAL'
                  AND outbox.event_type = 'work_item.cancellation_terminal_conflict'
                  AND job.result #>> '{result,route}' =
                      'terminal_conflict_escalated'
                  AND escalation.id = receipt.escalation_id
                  AND escalation.run_id = receipt.run_id
                  AND escalation.category = 'REMOTE_EFFECT_AMBIGUOUS'
                  AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
                  AND escalation.authority_or_effect_active
                  AND job.result #>> '{result,escalation_id}' = escalation.id::text
                  AND job.result #>> '{result,escalation_deadline}' =
                      asf_chrono_utc(escalation.deadline)
                  AND job.result #>> '{result,escalation_after_digest}' =
                      asf_terminal_conflict_escalation_digest(
                          escalation.tenant_id, escalation.id
                      )
                  AND job.result #>> '{result,escalation_disposition}' = CASE
                      WHEN job.result #> '{result,escalation_before_digest}' =
                           'null'::jsonb THEN 'created'
                      ELSE 'merged'
                  END
                  AND (
                      job.result #> '{result,escalation_before_digest}' = 'null'::jsonb
                      OR job.result #>> '{result,escalation_before_digest}' ~
                         '^sha256:[0-9a-f]{64}$'
                  )
                  AND (
                      (
                          job.result #> '{result,escalation_before_digest}' =
                              'null'::jsonb
                          AND job.result #>> '{result,escalation_disposition}' =
                              'created'
                          AND escalation.id = asf_derived_uuid(run.id, 3)
                          AND escalation.status = 'OPEN'
                          AND escalation.severity = 'HIGH'
                          AND escalation.reason =
                              'Runmill was already terminal in ' ||
                              (job.result #>> '{result,external_phase}') ||
                              ' when cancellation was reconciled'
                          AND escalation.owner_type = 'ON_CALL'
                          AND escalation.owner_id = 'platform-operations'
                          AND escalation.required_action =
                              'inspect the terminal Runmill evidence and explicitly close, retry, or cancel the work item'
                          AND escalation.evidence_references = jsonb_build_array(
                              'run:' || run.id::text,
                              'external-run:' || run.external_run_id,
                              'cancellation-request:' || observation.request_id,
                              'effect-intent:' || effect.id::text
                          )
                          AND escalation.deadline =
                              escalation.opened_at + interval '4 hours'
                          AND escalation.opened_at = observation.observed_at
                          AND escalation.escalation_path = jsonb_build_array(
                              jsonb_build_object(
                                  'owner_type', 'ON_CALL',
                                  'owner_id', 'platform-operations'
                              ),
                              jsonb_build_object(
                                  'owner_type', 'TEAM',
                                  'owner_id', 'platform-engineering'
                              )
                          )
                          AND escalation.prerequisites = jsonb_build_array(
                              'verify terminal Runmill evidence',
                              'reconcile remote delivery effects',
                              'record an explicit operator disposition'
                          )
                          AND escalation.retry_policy = jsonb_build_object(
                              'automatic', false,
                              'max_additional_attempts', 0,
                              'backoff_seconds', 0,
                              'prerequisites', escalation.prerequisites
                          )
                          AND escalation.idempotency_key =
                              'runmill-cancellation:' || observation.request_id ||
                              ':terminal-conflict'
                          AND escalation.aggregate_version = 1
                          AND escalation.acknowledged_at IS NULL
                          AND escalation.closed_at IS NULL
                      ) OR (
                          job.result #>> '{result,escalation_before_digest}' ~
                              '^sha256:[0-9a-f]{64}$'
                          AND job.result #>> '{result,escalation_disposition}' =
                              'merged'
                          AND escalation.aggregate_version >= 2
                          AND EXISTS (
                              SELECT 1
                              FROM terminal_conflict_escalation_merge_receipts
                                  AS merge_receipt
                              WHERE merge_receipt.tenant_id =
                                    escalation.tenant_id
                                AND merge_receipt.escalation_id = escalation.id
                                AND merge_receipt.work_item_id =
                                    receipt.work_item_id
                                AND merge_receipt.attempt_id =
                                    receipt.attempt_id
                                AND merge_receipt.run_id_after = receipt.run_id
                                AND merge_receipt.effect_intent_id =
                                    receipt.effect_intent_id
                                AND merge_receipt.terminal_observation_id =
                                    observation.id
                                AND merge_receipt.workflow_job_id = job.id
                                AND merge_receipt.aggregate_version_before =
                                    escalation.aggregate_version - 1
                                AND merge_receipt.aggregate_version_after =
                                    escalation.aggregate_version
                                AND merge_receipt.before_digest =
                                    job.result #>>
                                        '{result,escalation_before_digest}'
                                AND merge_receipt.after_digest =
                                    job.result #>>
                                        '{result,escalation_after_digest}'
                                AND merge_receipt.after_digest =
                                    asf_terminal_conflict_escalation_digest(
                                        escalation.tenant_id, escalation.id
                                    )
                          )
                          AND escalation.severity IN ('HIGH', 'CRITICAL')
                          AND position(
                              'Runmill was already terminal in ' ||
                              (job.result #>> '{result,external_phase}') ||
                              ' when cancellation was reconciled'
                              IN escalation.reason
                          ) > 0
                          AND position(
                              'inspect the terminal Runmill evidence and explicitly close, retry, or cancel the work item'
                              IN escalation.required_action
                          ) > 0
                          AND escalation.evidence_references @> jsonb_build_array(
                              'run:' || run.id::text,
                              'external-run:' || run.external_run_id,
                              'cancellation-request:' || observation.request_id,
                              'effect-intent:' || effect.id::text
                          )
                          AND escalation.escalation_path @> jsonb_build_array(
                              jsonb_build_object(
                                  'owner_type', 'ON_CALL',
                                  'owner_id', 'platform-operations'
                              ),
                              jsonb_build_object(
                                  'owner_type', 'TEAM',
                                  'owner_id', 'platform-engineering'
                              )
                          )
                          AND escalation.prerequisites @> jsonb_build_array(
                              'verify terminal Runmill evidence',
                              'reconcile remote delivery effects',
                              'record an explicit operator disposition'
                          )
                          AND escalation.retry_policy = jsonb_build_object(
                              'automatic', false,
                              'max_additional_attempts', 0,
                              'backoff_seconds', 0,
                              'prerequisites', escalation.prerequisites
                          )
                          AND escalation.deadline <=
                              receipt.recorded_at + interval '4 hours'
                      )
                  )
                  AND audit.before_digest IS NOT DISTINCT FROM
                      NULLIF(
                          job.result #>> '{result,escalation_before_digest}',
                          ''
                      )
                  AND audit.after_digest =
                      job.result #>> '{result,escalation_after_digest}'
                  AND audit.details -> 'escalation_id' =
                      job.result #> '{result,escalation_id}'
                  AND audit.details -> 'escalation_deadline' =
                      job.result #> '{result,escalation_deadline}'
                  AND audit.details -> 'escalation_disposition' =
                      job.result #> '{result,escalation_disposition}'
                  AND audit.details -> 'escalation_before_digest' =
                      job.result #> '{result,escalation_before_digest}'
                  AND audit.details -> 'escalation_after_digest' =
                      job.result #> '{result,escalation_after_digest}'
                  AND outbox.payload -> 'escalation_id' =
                      job.result #> '{result,escalation_id}'
                  AND outbox.payload -> 'escalation_deadline' =
                      job.result #> '{result,escalation_deadline}'
                  AND outbox.payload -> 'escalation_disposition' =
                      job.result #> '{result,escalation_disposition}'
                  AND outbox.payload -> 'escalation_before_digest' =
                      job.result #> '{result,escalation_before_digest}'
                  AND outbox.payload -> 'escalation_after_digest' =
                      job.result #> '{result,escalation_after_digest}'
                  AND anchor.anchor_type = 'ESCALATION'
                  AND anchor.reference_id = escalation.id
                  AND anchor.wake_or_deadline_at = escalation.deadline
                  AND anchor.authority_or_effect_active =
                      escalation.authority_or_effect_active
              )
          )
    );
$$;

CREATE FUNCTION asf_valid_cancellation_terminal_receipt(
    candidate_tenant uuid,
    candidate_receipt uuid
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    receipt_route text;
BEGIN
    SELECT route INTO receipt_route
    FROM cancellation_terminal_receipts
    WHERE tenant_id = candidate_tenant AND id = candidate_receipt;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF receipt_route = 'PRE_DISPATCH' THEN
        RETURN asf_valid_pre_dispatch_cancellation_receipt(
            candidate_tenant, candidate_receipt
        );
    END IF;
    IF receipt_route = 'RUNMILL' THEN
        RETURN asf_valid_runmill_cancellation_receipt(
            candidate_tenant, candidate_receipt
        );
    END IF;
    RETURN false;
END;
$$;

CREATE FUNCTION asf_assert_exact_cancellation_terminal_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT asf_valid_cancellation_terminal_receipt(NEW.tenant_id, NEW.id) THEN
        RAISE EXCEPTION 'cancellation terminal receipt has no exact durable proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_terminal_receipts_require_exact_proof';
    END IF;
    -- This trigger runs at the receipt-creating transaction's deferred commit
    -- boundary, so it can require the event to be genuinely publishable then
    -- without freezing legitimate publisher lifecycle changes afterwards.
    IF NOT EXISTS (
        SELECT 1
        FROM outbox AS emitted
        JOIN audit_events AS audit
          ON audit.tenant_id = NEW.tenant_id
         AND audit.id = NEW.audit_event_id
        LEFT JOIN runmill_cancellation_observations AS observation
          ON observation.tenant_id = NEW.tenant_id
         AND observation.id = NEW.terminal_observation_id
        WHERE emitted.tenant_id = NEW.tenant_id
          AND emitted.id = NEW.outbox_event_id
          AND emitted.status = 'PENDING'
          AND emitted.attempt_count = 0
          AND emitted.fence_token = 0
          AND emitted.lease_owner IS NULL
          AND emitted.lease_expires_at IS NULL
          AND emitted.last_error IS NULL
          AND emitted.published_at IS NULL
          AND emitted.created_at BETWEEN audit.occurred_at AND NEW.recorded_at
          AND (
              (NEW.route = 'RUNMILL'
               AND observation.id IS NOT NULL
               AND emitted.available_at = observation.observed_at)
              OR
              (NEW.route = 'PRE_DISPATCH'
               AND observation.id IS NULL
               AND emitted.available_at BETWEEN
                   audit.occurred_at AND NEW.recorded_at)
          )
    ) THEN
        RAISE EXCEPTION
            'cancellation terminal receipt outbox was not freshly publishable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_terminal_receipts_require_fresh_outbox';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cancellation_terminal_receipts_require_exact_proof
    AFTER INSERT ON cancellation_terminal_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_exact_cancellation_terminal_receipt();

-- A completed nonterminal INITIAL claim creates a durable obligation to keep
-- observing the one deterministic child.  Normal claim/retry/dead-letter
-- lifecycle remains available, but a direct CANCELLED transition may only
-- follow an immutable terminal receipt for this exact Runmill chain.
CREATE FUNCTION asf_assert_nonterminal_cancellation_observer_obligation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type <> 'REQUEST_WORK_ITEM_CANCELLATION'
       OR NEW.status <> 'CANCELLED'
       OR OLD.status = 'CANCELLED' THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_jobs AS parent
        JOIN runmill_cancellation_observations AS initial_observation
          ON initial_observation.tenant_id = parent.tenant_id
         AND initial_observation.id::text =
             parent.result #>> '{result,cancellation_observation_id}'
         AND initial_observation.workflow_job_id = parent.id
         AND initial_observation.workflow_instance_id =
             parent.workflow_instance_id
         AND initial_observation.work_item_id = parent.work_item_id
         AND initial_observation.attempt_id = parent.attempt_id
        WHERE parent.tenant_id = NEW.tenant_id
          AND parent.workflow_instance_id = NEW.workflow_instance_id
          AND parent.work_item_id = NEW.work_item_id
          AND parent.attempt_id = NEW.attempt_id
          AND parent.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND parent.status = 'COMPLETED'
          AND parent.result #>> '{result,route}' =
              'cancellation_in_progress'
          AND parent.result #>> '{result,observation_job,id}' = NEW.id::text
          AND initial_observation.route = 'INITIAL'
          AND initial_observation.prior_observation_id IS NULL
          AND initial_observation.external_phase IN (
              'CANCEL_REQUESTED', 'CANCELLING'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM cancellation_terminal_receipts AS receipt
              JOIN runmill_cancellation_observations AS terminal_observation
                ON terminal_observation.tenant_id = receipt.tenant_id
               AND terminal_observation.id = receipt.terminal_observation_id
               AND terminal_observation.work_item_id = receipt.work_item_id
               AND terminal_observation.attempt_id = receipt.attempt_id
               AND terminal_observation.run_id = receipt.run_id
               AND terminal_observation.effect_intent_id =
                   receipt.effect_intent_id
               AND terminal_observation.workflow_instance_id =
                   receipt.workflow_instance_id
              WHERE receipt.tenant_id = initial_observation.tenant_id
                AND receipt.route = 'RUNMILL'
                AND receipt.work_item_id = initial_observation.work_item_id
                AND receipt.attempt_id = initial_observation.attempt_id
                AND receipt.run_id = initial_observation.run_id
                AND receipt.effect_intent_id =
                    initial_observation.effect_intent_id
                AND receipt.workflow_instance_id =
                    initial_observation.workflow_instance_id
                AND terminal_observation.route = 'OBSERVER'
                AND terminal_observation.external_phase IN (
                    'SUCCEEDED', 'FAILED', 'REFUSED', 'QUARANTINED',
                    'CANCELLED'
                )
                AND (
                    (terminal_observation.external_phase = 'CANCELLED'
                     AND receipt.outcome = 'CANCELLED')
                    OR
                    (terminal_observation.external_phase <>
                         'CANCELLED'
                     AND receipt.outcome = 'TERMINAL_CONFLICT')
                )
          )
    ) THEN
        RAISE EXCEPTION
            'nonterminal Runmill cancellation observer cannot be cancelled before terminal proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'nonterminal_cancellation_observer_obligation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_jobs_preserve_nonterminal_cancellation_observer
    AFTER UPDATE ON workflow_jobs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_nonterminal_cancellation_observer_obligation();

-- Preserve every existing accountability route while replacing the weak
-- audit-name-only CANCELLATION branch with the exact terminal predicate.
ALTER FUNCTION asf_accountability_reference_is_live(
    uuid, uuid, text, uuid, timestamptz, boolean
) RENAME TO asf_accountability_reference_is_live_before_cancellation_receipts;

CREATE FUNCTION asf_accountability_reference_is_live(
    candidate_tenant uuid,
    candidate_work_item uuid,
    candidate_anchor_type text,
    candidate_reference uuid,
    candidate_wake_or_deadline timestamptz,
    candidate_authority_or_effect_active boolean
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT CASE
        WHEN candidate_anchor_type = 'CANCELLATION' THEN
            candidate_wake_or_deadline IS NULL
            AND NOT candidate_authority_or_effect_active
            AND EXISTS (
                SELECT 1
                FROM cancellation_terminal_receipts AS receipt
                WHERE receipt.tenant_id = candidate_tenant
                  AND receipt.work_item_id = candidate_work_item
                  AND receipt.id = candidate_reference
                  AND receipt.outcome = 'CANCELLED'
                  AND asf_valid_cancellation_terminal_receipt(
                      receipt.tenant_id, receipt.id
                  )
            )
        ELSE asf_accountability_reference_is_live_before_cancellation_receipts(
            candidate_tenant,
            candidate_work_item,
            candidate_anchor_type,
            candidate_reference,
            candidate_wake_or_deadline,
            candidate_authority_or_effect_active
        )
    END;
$$;

CREATE FUNCTION asf_assert_cancellation_receipts_for_work(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
    current_state text;
BEGIN
    -- Ordinary child writers avoid a child -> parent row-lock edge. New live
    -- authority has already serialized on work_cancellation_authority_guards;
    -- once a CANCELLED fact is visible, take the parent lock and preserve the
    -- rest of its exact terminal proof.
    IF NOT EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.tenant_id = candidate_tenant
          AND work.id = candidate_work_item
          AND work.state = 'CANCELLED'
    ) AND NOT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.work_item_id = candidate_work_item
          AND receipt.outcome = 'CANCELLED'
    ) THEN
        RETURN;
    END IF;

    SELECT work.state INTO current_state
    FROM work_items AS work
    WHERE work.tenant_id = candidate_tenant
      AND work.id = candidate_work_item
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    FOR candidate IN
        SELECT receipt.id, receipt.outcome
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.work_item_id = candidate_work_item
    LOOP
        -- A terminal conflict is a certified historical snapshot: the
        -- deferred INSERT trigger proved the exact open escalation, WAITING
        -- workflow, ESCALATED work item, and anchor at creation time.  Its
        -- row is append-only and every semantic parent is FK-retained with
        -- independently immutable identity/receipt fields, so later operator
        -- resolution must be allowed to advance the mutable lifecycle.
        IF candidate.outcome <> 'TERMINAL_CONFLICT'
           AND NOT asf_valid_cancellation_terminal_receipt(
               candidate_tenant, candidate.id
           ) THEN
            RAISE EXCEPTION 'mutation would sever cancellation terminal receipt %',
                candidate.id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_terminal_receipt_reciprocal_guard';
        END IF;
    END LOOP;

    IF current_state = 'CANCELLED' AND NOT EXISTS (
        SELECT 1
        FROM cancellation_terminal_receipts AS receipt
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.work_item_id = candidate_work_item
          AND receipt.outcome = 'CANCELLED'
          AND asf_valid_cancellation_terminal_receipt(
              receipt.tenant_id, receipt.id
          )
    ) THEN
        RAISE EXCEPTION 'cancelled work item has no exact terminal cancellation receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_cancellation_terminal_receipt';
    END IF;
END;
$$;

CREATE FUNCTION asf_assert_work_preserves_cancellation_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM asf_assert_cancellation_receipts_for_work(OLD.tenant_id, OLD.id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR ROW(NEW.tenant_id, NEW.id) IS DISTINCT FROM ROW(OLD.tenant_id, OLD.id)) THEN
        PERFORM asf_assert_cancellation_receipts_for_work(NEW.tenant_id, NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER work_items_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON work_items
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_work_preserves_cancellation_receipt();

CREATE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_row jsonb := '{}'::jsonb;
    new_row jsonb := '{}'::jsonb;
    old_tenant uuid;
    old_work uuid;
    new_tenant uuid;
    new_work uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_row := to_jsonb(OLD);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_row := to_jsonb(NEW);
    END IF;
    old_tenant := NULLIF(old_row ->> 'tenant_id', '')::uuid;
    old_work := NULLIF(old_row ->> 'work_item_id', '')::uuid;
    new_tenant := NULLIF(new_row ->> 'tenant_id', '')::uuid;
    new_work := NULLIF(new_row ->> 'work_item_id', '')::uuid;

    IF old_tenant IS NOT NULL AND old_work IS NOT NULL THEN
        PERFORM asf_assert_cancellation_receipts_for_work(old_tenant, old_work);
    END IF;
    IF new_tenant IS NOT NULL
       AND new_work IS NOT NULL
       AND ROW(new_tenant, new_work) IS DISTINCT FROM ROW(old_tenant, old_work) THEN
        PERFORM asf_assert_cancellation_receipts_for_work(new_tenant, new_work);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_instances_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON workflow_instances
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER workflow_jobs_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON workflow_jobs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER workflow_timers_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON workflow_timers
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER attempts_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER runs_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER effect_intents_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON effect_intents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER reservation_sets_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON reservation_sets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER work_orders_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON work_orders
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER approvals_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON approvals
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER evidence_bundles_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON evidence_bundles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER escalations_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON escalations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER budget_ledger_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON budget_ledger
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER accountability_anchors_preserve_cancellation_receipt
    AFTER INSERT OR UPDATE OR DELETE ON accountability_anchors
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();
CREATE CONSTRAINT TRIGGER cancellation_observations_preserve_terminal_receipt
    AFTER INSERT OR UPDATE OR DELETE ON runmill_cancellation_observations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_cancellation_receipt();

-- Completed idempotency facts are immutable until retention expiry in the
-- base schema.  Once one participates in a cancellation proof, expiry must
-- not be allowed to sever either the acceptance or cancellation provenance.
CREATE FUNCTION asf_assert_idempotency_preserves_cancellation_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
BEGIN
    FOR candidate IN
        SELECT DISTINCT audit.tenant_id, audit.work_item_id
        FROM audit_events AS audit
        WHERE audit.tenant_id = OLD.tenant_id
          AND audit.correlation_id = OLD.id::text
          AND audit.work_item_id IS NOT NULL
          AND audit.action IN ('WORK_ITEM_ACCEPTED', 'WORK_ITEM_CANCELLED')
    LOOP
        PERFORM asf_assert_cancellation_receipts_for_work(
            candidate.tenant_id, candidate.work_item_id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER idempotency_records_preserve_cancellation_receipt
    AFTER DELETE ON idempotency_records
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_idempotency_preserves_cancellation_receipt();

-- INSERT triggers above close the phantom race.  Deletes and identity-moving
-- updates must also be unable to erase the durable fact and reopen the
-- negative boundary.  Same-identity updates advance the marker unless they
-- are the exact synchronous terminalization of the baseline workflow/job.
CREATE FUNCTION asf_note_work_dispatch_fact_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_row jsonb := to_jsonb(OLD);
    new_row jsonb := '{}'::jsonb;
    candidate_tenant uuid;
    candidate_work uuid;
    locked_work uuid;
BEGIN
    IF TG_OP <> 'DELETE' THEN
        new_row := to_jsonb(NEW);
        IF ROW(NEW.tenant_id, NEW.work_item_id) IS DISTINCT FROM
           ROW(OLD.tenant_id, OLD.work_item_id) THEN
            RAISE EXCEPTION 'dispatch-fact authority coordinates are immutable'
                USING ERRCODE = '55000',
                      CONSTRAINT = 'dispatch_fact_work_binding_immutable';
        END IF;
    END IF;

    candidate_tenant := NULLIF(old_row ->> 'tenant_id', '')::uuid;
    candidate_work := NULLIF(old_row ->> 'work_item_id', '')::uuid;
    IF candidate_tenant IS NULL OR candidate_work IS NULL THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'workflow_jobs' THEN
        IF old_row ->> 'job_type' = 'ADVANCE_ACCEPTED_WORK_ITEM'
           AND old_row ->> 'attempt_id' IS NULL
           AND old_row ->> 'status' IN ('PENDING', 'RETRY')
           AND new_row ->> 'status' = 'CANCELLED'
           AND new_row ->> 'attempt_id' IS NULL
           AND (new_row -> 'result') ->> 'schema' =
               'asf.pre-dispatch-cancellation-result/v1'
           AND (new_row -> 'result') ->> 'disposition' =
               'cancelled_before_dispatch'
           AND (new_row ->> 'fence_token')::bigint =
               (old_row ->> 'fence_token')::bigint + 1 THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'workflow_instances' THEN
        IF old_row ->> 'workflow_type' = 'WORK_ITEM_DELIVERY'
           AND old_row ->> 'state' = 'ACTIVE'
           AND new_row ->> 'state' = 'CANCELLED'
           AND (new_row ->> 'aggregate_version')::bigint =
               (old_row ->> 'aggregate_version')::bigint + 1
           AND (new_row ->> 'fence_token')::bigint =
               (old_row ->> 'fence_token')::bigint + 1 THEN
            RETURN NEW;
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM work_dispatch_fact_guards AS guard
        WHERE guard.tenant_id = candidate_tenant
          AND guard.work_item_id = candidate_work
          AND guard.dispatch_started
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    SELECT id INTO locked_work
    FROM work_items
    WHERE tenant_id = candidate_tenant AND id = candidate_work
    FOR UPDATE;
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    UPDATE work_dispatch_fact_guards
    SET dispatch_started = true,
        generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = candidate_tenant AND work_item_id = candidate_work;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'work item has no dispatch-fact guard'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_dispatch_fact_guard';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER attempts_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON attempts
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER workflow_instances_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON workflow_instances
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER workflow_jobs_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER workflow_timers_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON workflow_timers
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER reservation_sets_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON reservation_sets
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER effect_intents_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER runs_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON runs
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER work_orders_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON work_orders
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER approvals_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON approvals
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER evidence_bundles_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON evidence_bundles
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER escalations_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
CREATE TRIGGER budget_ledger_note_dispatch_fact_mutation
    BEFORE UPDATE OR DELETE ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION asf_note_work_dispatch_fact_mutation();
