-- Introduce a per-request, NOT NULL activity_contract_id on workflow_jobs
-- and workflow_timers that pins the durable request to one exact activity
-- implementation identity, in addition to the existing job_type/timer_type.
-- This migration installs the column, backfill, and immutability guard;
-- every Rust struct field, INSERT site, and durable/API serviceability
-- decision binds to it exactly (see src/runtime and src/api/postgres.rs).
--
-- Apply with executors quiesced.  Both tables are locked for the duration:
-- their identity/immutability triggers must be dropped and reinstalled while
-- populating the new column on pre-existing rows, including terminal ones.
LOCK TABLE workflow_jobs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE workflow_timers IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_jobs AS job
        WHERE job.job_type NOT IN (
            'INTAKE_SYNC',
            'ADVANCE_ACCEPTED_WORK_ITEM',
            'REQUEST_WORK_ITEM_CANCELLATION',
            'APPLY_SIGNED_APPROVAL_DECISION',
            'RECONCILE_WORKER',
            'OBSERVE_RUNMILL_RUN',
            'VERIFY_EVIDENCE',
            'CLOSE_SOURCE'
        )
    ) THEN
        RAISE EXCEPTION 'cannot install activity contract identity while a workflow job has a non-production job_type'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'workflow_jobs_activity_contract_backfill_requires_production_job_types';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_timers AS timer
        WHERE timer.timer_type NOT IN (
            'INTAKE_SYNC',
            'ADVANCE_ACCEPTED_WORK_ITEM',
            'REQUEST_WORK_ITEM_CANCELLATION',
            'APPLY_SIGNED_APPROVAL_DECISION',
            'RECONCILE_WORKER',
            'OBSERVE_RUNMILL_RUN',
            'VERIFY_EVIDENCE',
            'CLOSE_SOURCE'
        )
    ) THEN
        RAISE EXCEPTION 'cannot install activity contract identity while a workflow timer has a non-production timer_type'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'workflow_timers_activity_contract_backfill_requires_production_timer_types';
    END IF;
END;
$$;

-- The migration is the sole writer under the table locks.  Temporarily
-- remove the identity/immutability guards so they can populate the new
-- immutable column on pre-existing rows, including terminal ones, then
-- reinstall the expanded guards below.
DROP TRIGGER workflow_jobs_immutable ON workflow_jobs;
DROP TRIGGER workflow_timers_immutable ON workflow_timers;

ALTER TABLE workflow_jobs
    ADD COLUMN activity_contract_id text;

ALTER TABLE workflow_timers
    ADD COLUMN activity_contract_id text;

-- migration 0017 installed workflow_jobs_note_dispatch_fact_mutation and
-- workflow_timers_note_dispatch_fact_mutation as BEFORE UPDATE/DELETE
-- triggers: any ordinary UPDATE of a row bound to a work item marks that
-- work item's work_dispatch_fact_guards row dispatch_started = true and
-- bumps its generation, on the theory that a semantic write to a live job
-- or timer is itself dispatch evidence.  The blanket backfill UPDATEs below
-- are not a semantic write -- they only populate the new
-- activity_contract_id column on pre-existing rows -- so they must not be
-- allowed to fire that trigger and falsely fabricate a dispatch fact for
-- historical accepted, still pre-dispatch work.  Disable only these two
-- named triggers for the duration of the backfill; the migration runs
-- inside a single transaction, so a failure anywhere rolls the trigger
-- state back along with everything else.
ALTER TABLE workflow_jobs DISABLE TRIGGER workflow_jobs_note_dispatch_fact_mutation;
ALTER TABLE workflow_timers DISABLE TRIGGER workflow_timers_note_dispatch_fact_mutation;

UPDATE workflow_jobs
SET activity_contract_id = CASE job_type
    WHEN 'INTAKE_SYNC' THEN 'asf.activity/intake-sync/v1'
    WHEN 'ADVANCE_ACCEPTED_WORK_ITEM' THEN 'asf.activity/advance-accepted-work-item/v1'
    WHEN 'REQUEST_WORK_ITEM_CANCELLATION' THEN 'asf.activity/request-work-item-cancellation/v1'
    WHEN 'APPLY_SIGNED_APPROVAL_DECISION' THEN 'asf.activity/apply-signed-approval-decision/v1'
    WHEN 'RECONCILE_WORKER' THEN 'asf.activity/reconcile-worker/v1'
    WHEN 'OBSERVE_RUNMILL_RUN' THEN 'asf.activity/observe-runmill-run/v2'
    WHEN 'VERIFY_EVIDENCE' THEN 'asf.activity/verify-evidence/v1'
    WHEN 'CLOSE_SOURCE' THEN 'asf.activity/close-source/v1'
END;

UPDATE workflow_timers
SET activity_contract_id = CASE timer_type
    WHEN 'INTAKE_SYNC' THEN 'asf.activity/intake-sync/v1'
    WHEN 'ADVANCE_ACCEPTED_WORK_ITEM' THEN 'asf.activity/advance-accepted-work-item/v1'
    WHEN 'REQUEST_WORK_ITEM_CANCELLATION' THEN 'asf.activity/request-work-item-cancellation/v1'
    WHEN 'APPLY_SIGNED_APPROVAL_DECISION' THEN 'asf.activity/apply-signed-approval-decision/v1'
    WHEN 'RECONCILE_WORKER' THEN 'asf.activity/reconcile-worker/v1'
    WHEN 'OBSERVE_RUNMILL_RUN' THEN 'asf.activity/observe-runmill-run/v2'
    WHEN 'VERIFY_EVIDENCE' THEN 'asf.activity/verify-evidence/v1'
    WHEN 'CLOSE_SOURCE' THEN 'asf.activity/close-source/v1'
END;

-- workflow_jobs and workflow_timers each carry several other DEFERRABLE
-- INITIALLY DEFERRED constraint triggers -- workflow_jobs_require_dead_letter_escalation,
-- workflow_job_parent_anchor_guard, workflow_jobs_preserve_observed_source_closure,
-- workflow_jobs_preserve_valid_evidence_verifications,
-- workflow_jobs_completed_cancellation_observation,
-- workflow_jobs_preserve_nonterminal_cancellation_observer,
-- workflow_jobs_preserve_cancellation_receipt on workflow_jobs, and
-- workflow_timer_parent_anchor_guard, workflow_timer_anchor_guard,
-- workflow_timers_preserve_cancellation_receipt on workflow_timers -- none
-- carrying a WHEN clause. The two blanket UPDATEs above therefore queue a
-- pending event for every one of those triggers on every row, exactly like
-- the dispatch-fact triggers they leave enabled throughout. PostgreSQL
-- refuses ALTER TABLE ... ENABLE TRIGGER while any event remains queued
-- against the target relation (55006: cannot ALTER TABLE because it has
-- pending trigger events), regardless of which trigger is being re-enabled,
-- so those events must be drained before the ENABLE TRIGGER statements
-- below. Fire them now: the backfill only changes activity_contract_id, a
-- column none of these guards inspect, on rows already visible in this
-- transaction, so draining here observes exactly the same facts each would
-- see at commit. Restore INITIALLY DEFERRED immediately afterward so the
-- rest of this transaction keeps the declared default deferral mode.
SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

-- Restore the dispatch-fact mutation guards immediately after the backfill
-- so every subsequent ordinary UPDATE/DELETE on these tables (including any
-- issued later in this same migration) is observed exactly as before.
ALTER TABLE workflow_jobs ENABLE TRIGGER workflow_jobs_note_dispatch_fact_mutation;
ALTER TABLE workflow_timers ENABLE TRIGGER workflow_timers_note_dispatch_fact_mutation;

-- No DEFAULT: every caller must supply the exact contract identity on every
-- insert once this migration lands.
ALTER TABLE workflow_jobs
    ALTER COLUMN activity_contract_id SET NOT NULL,
    ADD CONSTRAINT workflow_jobs_activity_contract_id_shape CHECK (
        activity_contract_id ~ '^[a-z0-9]+([./-][a-z0-9]+)*$'
        AND octet_length(activity_contract_id) <= 128
    );

ALTER TABLE workflow_timers
    ALTER COLUMN activity_contract_id SET NOT NULL,
    ADD CONSTRAINT workflow_timers_activity_contract_id_shape CHECK (
        activity_contract_id ~ '^[a-z0-9]+([./-][a-z0-9]+)*$'
        AND octet_length(activity_contract_id) <= 128
    );

-- Lifecycle behavior preserved verbatim from the latest definition
-- (migration 0006): DELETE is always rejected and COMPLETED/DEAD/CANCELLED
-- jobs are fully immutable.  Only the immutable request-identity tuple
-- gains activity_contract_id.
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
        NEW.activity_contract_id,
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
        OLD.activity_contract_id,
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

CREATE TRIGGER workflow_jobs_immutable
    BEFORE UPDATE OR DELETE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_guard_workflow_job_mutation();

-- Lifecycle behavior preserved verbatim from the latest definition
-- (migration 0003): DELETE is always rejected and FIRED/CANCELLED timers are
-- fully immutable.  Only the immutable request-identity tuple gains
-- activity_contract_id.
CREATE OR REPLACE FUNCTION asf_guard_workflow_timer_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow timers cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('FIRED', 'CANCELLED') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal workflow timers are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.workflow_instance_id,
        NEW.work_item_id,
        NEW.attempt_id,
        NEW.workflow_key,
        NEW.timer_key,
        NEW.timer_type,
        NEW.activity_contract_id,
        NEW.due_at,
        NEW.payload,
        NEW.generation,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.workflow_instance_id,
        OLD.work_item_id,
        OLD.attempt_id,
        OLD.workflow_key,
        OLD.timer_key,
        OLD.timer_type,
        OLD.activity_contract_id,
        OLD.due_at,
        OLD.payload,
        OLD.generation,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'workflow timer identity and request fields are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_timers_immutable
    BEFORE UPDATE OR DELETE ON workflow_timers
    FOR EACH ROW EXECUTE FUNCTION asf_guard_workflow_timer_mutation();
