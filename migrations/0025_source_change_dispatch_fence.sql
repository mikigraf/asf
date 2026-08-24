-- Introduce a dispatch fence for work items to control which incoming source changes
-- are allowed to create new attempts, work orders, and other dispatch-producing rows
-- while a work item is undergoing a focused source change operation.
--
-- The fence is established to prevent concurrent cross-dispatch-point mutations and
-- ensures strict ordering of dispatch-producing operations. An active paused fence
-- blocks insert attempts into dispatch-sensitive tables until resolved.

CREATE TABLE work_item_dispatch_fences (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    paused boolean NOT NULL DEFAULT false,
    candidate_snapshot_id uuid NOT NULL,
    candidate_snapshot_digest text NOT NULL CHECK (candidate_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    authoritative_snapshot_id uuid NOT NULL,
    authoritative_snapshot_digest text NOT NULL CHECK (authoritative_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason text NOT NULL CHECK (length(btrim(reason)) > 0),
    opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, work_item_id),
    FOREIGN KEY (tenant_id, work_item_id) REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, candidate_snapshot_id)
        REFERENCES source_snapshots(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, authoritative_snapshot_id)
        REFERENCES source_snapshots(tenant_id, id) ON DELETE RESTRICT,
    CHECK (resolved_at IS NULL OR resolved_at >= opened_at)
);

CREATE INDEX work_item_dispatch_fences_paused_idx
    ON work_item_dispatch_fences (tenant_id, work_item_id)
    WHERE paused = true AND resolved_at IS NULL;

-- Guard against insertion of dispatch-producing rows when a work item has an active
-- paused dispatch fence. This ensures that while a source change operation is paused,
-- new attempts, work orders, and other changes cannot be admitted into the system.
--
-- SECURITY DEFINER allows this function to check the fence table without requiring
-- explicit permissions from the caller, ensuring the fence cannot be bypassed.
CREATE FUNCTION asf_check_work_item_dispatch_fence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Reject if work item has an active (paused=true, resolved_at IS NULL) dispatch fence.
    -- This blocks admission of new attempts, work orders, reservation sets, and effect intents.
    IF EXISTS (
        SELECT 1
        FROM work_item_dispatch_fences
        WHERE tenant_id = NEW.tenant_id
          AND work_item_id = NEW.work_item_id
          AND paused = true
          AND resolved_at IS NULL
    ) THEN
        RAISE EXCEPTION 'work item has an active dispatch fence and cannot accept new %',
            LOWER(TG_TABLE_NAME)
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- Guard for workflow jobs with dispatch-producing semantics. Unlike other tables,
-- workflow jobs include non-dispatching operations (intake, reconcile, cancel, observe)
-- that must be allowed even when a fence is paused, since they do not mutate the
-- dispatch state or create new work orders.
CREATE FUNCTION asf_check_workflow_job_dispatch_fence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Non-dispatching job types are always allowed, even during a paused fence.
    IF NEW.job_type IN ('INTAKE_SYNC', 'RECONCILE_WORKER', 'REQUEST_WORK_ITEM_CANCELLATION', 'OBSERVE_RUNMILL_RUN') THEN
        RETURN NEW;
    END IF;

    -- Dispatch-producing job types are blocked by an active paused fence.
    IF NEW.work_item_id IS NOT NULL THEN
        IF EXISTS (
            SELECT 1
            FROM work_item_dispatch_fences
            WHERE tenant_id = NEW.tenant_id
              AND work_item_id = NEW.work_item_id
              AND paused = true
              AND resolved_at IS NULL
        ) THEN
            RAISE EXCEPTION 'work item has an active dispatch fence and cannot accept new workflow job'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- Apply fence check to attempts: no new attempts allowed during paused fence.
CREATE TRIGGER work_item_dispatch_fence_attempts
    BEFORE INSERT ON attempts
    FOR EACH ROW EXECUTE FUNCTION asf_check_work_item_dispatch_fence();

-- Apply fence check to work_orders: no new work orders allowed during paused fence.
CREATE TRIGGER work_item_dispatch_fence_work_orders
    BEFORE INSERT ON work_orders
    FOR EACH ROW EXECUTE FUNCTION asf_check_work_item_dispatch_fence();

-- Apply fence check to reservation_sets: no new reservations allowed during paused fence.
CREATE TRIGGER work_item_dispatch_fence_reservation_sets
    BEFORE INSERT ON reservation_sets
    FOR EACH ROW EXECUTE FUNCTION asf_check_work_item_dispatch_fence();

-- Apply fence check to effect_intents: no new effects allowed during paused fence.
CREATE TRIGGER work_item_dispatch_fence_effect_intents
    BEFORE INSERT ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_check_work_item_dispatch_fence();

-- Apply dispatch-aware fence check to workflow_jobs.
-- Non-dispatching jobs (intake, reconcile, cancel, observe) bypass the fence,
-- allowing control-plane operations to proceed during a paused fence.
CREATE TRIGGER work_item_dispatch_fence_workflow_jobs
    BEFORE INSERT ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_check_workflow_job_dispatch_fence();
