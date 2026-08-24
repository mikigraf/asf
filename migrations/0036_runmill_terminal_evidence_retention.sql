-- Forward-only migration 0036: terminal evidence retention is non-dispatching.
--
-- Migration 0035 retains the terminal evidence bundle. Migration 0025 blocks
-- every workflow job that is not explicitly non-dispatching while a work item
-- carries a paused source-change dispatch fence.
--
-- Retaining terminal evidence for a run that was already dispatched creates no
-- attempt, Work Order, reservation, or effect intent: it is one read-only
-- asf.get_evidence call whose only local consequence is an append-only proof
-- row. Leaving it fenced would strand the evidence for an already-running
-- attempt precisely when a source change made that evidence most valuable, and
-- would leave the observation stream TERMINAL_READY with no closure path.
--
-- RETAIN_RUNMILL_TERMINAL_EVIDENCE therefore joins the same non-dispatching
-- allowlist that already carries INTAKE_SYNC, RECONCILE_WORKER,
-- REQUEST_WORK_ITEM_CANCELLATION, and OBSERVE_RUNMILL_RUN. Nothing else about
-- the fence changes: every dispatch-producing job type stays blocked.
--
-- CREATE OR REPLACE keeps the function OID, so the trigger installed by 0025
-- continues to point at this definition without being recreated.

LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION asf_check_workflow_job_dispatch_fence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Non-dispatching job types are always allowed, even during a paused fence.
    IF NEW.job_type IN (
        'INTAKE_SYNC',
        'RECONCILE_WORKER',
        'REQUEST_WORK_ITEM_CANCELLATION',
        'OBSERVE_RUNMILL_RUN',
        'RETAIN_RUNMILL_TERMINAL_EVIDENCE'
    ) THEN
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

COMMENT ON FUNCTION asf_check_workflow_job_dispatch_fence() IS
    'Blocks dispatch-producing workflow jobs while a work item carries a paused source-change dispatch fence. Read-only control-plane job types -- intake, worker reconciliation, cancellation, run observation, and terminal evidence retention -- are always allowed.';
