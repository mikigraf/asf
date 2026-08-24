-- Terminal work is a closed authority boundary.  The cancellation receipt
-- guard already serializes live-authority births with Runmill cancellation;
-- extend that same durable row to verified source closure so neither terminal
-- route can acquire a child -> work-item lock edge.
--
-- Apply with executors quiesced.  The job-first order matches the workflow
-- recovery paths; the remaining locks exclude every writer whose negative
-- existence is certified while existing CLOSED rows are backfilled.
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_timers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_sets IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE approvals IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE source_snapshots IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE repositories IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_verifications IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE accountability_anchors IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_cancellation_authority_guards IN ACCESS EXCLUSIVE MODE;
LOCK TABLE cancellation_terminal_receipts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_escalation_supersession_receipts
    IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE work_cancellation_authority_guards
    ADD COLUMN source_closure_effect_intent_id uuid,
    ADD CONSTRAINT work_authority_guard_one_terminal_route CHECK (
        num_nonnulls(
            terminal_receipt_id,
            source_closure_effect_intent_id
        ) <= 1
    ),
    ADD CONSTRAINT work_authority_guard_source_closure_effect_fk
        FOREIGN KEY (tenant_id, source_closure_effect_intent_id)
        REFERENCES effect_intents (tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX work_authority_guard_source_closure_effect_idx
    ON work_cancellation_authority_guards (
        tenant_id,
        source_closure_effect_intent_id
    )
    WHERE source_closure_effect_intent_id IS NOT NULL;

-- This is the shared negative predicate for both terminal routes.  Work
-- orders and immutable evidence are retained history, not live authority.
CREATE FUNCTION asf_terminal_work_has_no_live_authority(
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

CREATE OR REPLACE FUNCTION asf_runmill_cancelled_work_has_no_live_authority(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT asf_terminal_work_has_no_live_authority(
        candidate_tenant,
        candidate_work_item
    );
$$;

-- Refuse to manufacture a finality marker for history that was already
-- contradictory.  The old closure predicate is still the chain-only
-- predicate at this point in the migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        LEFT JOIN work_cancellation_authority_guards AS authority_guard
          ON authority_guard.tenant_id = work.tenant_id
         AND authority_guard.work_item_id = work.id
        WHERE work.state = 'CLOSED'
          AND (
              authority_guard.work_item_id IS NULL
              OR authority_guard.terminal_receipt_id IS NOT NULL
              OR NOT asf_observed_source_closure_is_valid(
                  work.tenant_id,
                  work.id
              )
              OR NOT asf_terminal_work_has_no_live_authority(
                  work.tenant_id,
                  work.id
              )
              OR (
                  SELECT count(*)
                  FROM effect_intents AS effect
                  WHERE effect.tenant_id = work.tenant_id
                    AND effect.work_item_id = work.id
                    AND effect.attempt_id = work.current_attempt_id
                    AND effect.provider = 'linear'
                    AND effect.effect_type = 'close_source'
                    AND effect.status = 'OBSERVED'
              ) <> 1
          )
    ) THEN
        RAISE EXCEPTION
            'historical CLOSED work cannot be bound to shared finality safely'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'shared_work_finality_upgrade_requires_exact_closure';
    END IF;
END;
$$;

UPDATE work_cancellation_authority_guards AS authority_guard
SET generation = authority_guard.generation + 1,
    source_closure_effect_intent_id = effect.id,
    updated_at = clock_timestamp()
FROM work_items AS work
JOIN effect_intents AS effect
  ON effect.tenant_id = work.tenant_id
 AND effect.work_item_id = work.id
 AND effect.attempt_id = work.current_attempt_id
 AND effect.provider = 'linear'
 AND effect.effect_type = 'close_source'
 AND effect.status = 'OBSERVED'
WHERE work.state = 'CLOSED'
  AND authority_guard.tenant_id = work.tenant_id
  AND authority_guard.work_item_id = work.id
  AND authority_guard.terminal_receipt_id IS NULL
  AND authority_guard.source_closure_effect_intent_id IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        JOIN work_cancellation_authority_guards AS authority_guard
          ON authority_guard.tenant_id = work.tenant_id
         AND authority_guard.work_item_id = work.id
        WHERE work.state = 'CLOSED'
          AND authority_guard.source_closure_effect_intent_id IS NULL
    ) THEN
        RAISE EXCEPTION 'a historical CLOSED work guard was not backfilled'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'shared_work_finality_upgrade_backfill_complete';
    END IF;
END;
$$;

-- Keep the expensive reconstruction as a named chain predicate and make the
-- public predicate include the durable negative boundary.
ALTER FUNCTION asf_observed_source_closure_is_valid(uuid, uuid)
    RENAME TO asf_observed_source_closure_chain_v18;

CREATE FUNCTION asf_observed_source_closure_is_valid(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
AS $$
    SELECT
        asf_observed_source_closure_chain_v18(
            candidate_tenant,
            candidate_work_item
        )
        AND asf_terminal_work_has_no_live_authority(
            candidate_tenant,
            candidate_work_item
        )
        AND EXISTS (
            SELECT 1
            FROM work_cancellation_authority_guards AS authority_guard
            JOIN work_items AS work
              ON work.tenant_id = authority_guard.tenant_id
             AND work.id = authority_guard.work_item_id
             AND work.state = 'CLOSED'
            JOIN effect_intents AS effect
              ON effect.tenant_id = authority_guard.tenant_id
             AND effect.id = authority_guard.source_closure_effect_intent_id
             AND effect.work_item_id = authority_guard.work_item_id
             AND effect.attempt_id = work.current_attempt_id
             AND effect.provider = 'linear'
             AND effect.effect_type = 'close_source'
             AND effect.status = 'OBSERVED'
            WHERE authority_guard.tenant_id = candidate_tenant
              AND authority_guard.work_item_id = candidate_work_item
              AND authority_guard.terminal_receipt_id IS NULL
              AND authority_guard.source_closure_effect_intent_id IS NOT NULL
        );
$$;

CREATE OR REPLACE FUNCTION asf_guard_work_cancellation_authority_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.generation <> OLD.generation + 1
       OR NEW.updated_at < OLD.updated_at
       OR OLD.terminal_receipt_id IS NOT NULL
       OR OLD.source_closure_effect_intent_id IS NOT NULL THEN
        RAISE EXCEPTION 'work authority guards are monotonic and terminal'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'work_cancellation_authority_guards_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

-- INSERT is always a new work-scoped fact.  In particular, a row born in a
-- terminal state is not historical merely because its payload says so.  For
-- UPDATE, retain the cheap path for an already-live same-work row and for
-- terminalization of a pre-existing row; births, reactivation, and a binding
-- move must all cross the guard.
CREATE OR REPLACE FUNCTION asf_note_cancellation_authority_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_row jsonb := '{}'::jsonb;
    new_row jsonb := to_jsonb(NEW);
    candidate_work uuid := NULLIF(new_row ->> 'work_item_id', '')::uuid;
    old_work uuid;
    old_live boolean := false;
    new_live boolean := asf_cancellation_authority_row_is_live(
        TG_TABLE_NAME,
        new_row
    );
    same_binding boolean := false;
BEGIN
    IF candidate_work IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        old_row := to_jsonb(OLD);
        old_work := NULLIF(old_row ->> 'work_item_id', '')::uuid;
        old_live := asf_cancellation_authority_row_is_live(
            TG_TABLE_NAME,
            old_row
        );
        same_binding := ROW(NEW.tenant_id, candidate_work) IS NOT DISTINCT FROM
            ROW(OLD.tenant_id, old_work);
        IF same_binding AND (NOT new_live OR old_live) THEN
            RETURN NEW;
        END IF;
    END IF;

    UPDATE work_cancellation_authority_guards
    SET generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id
      AND work_item_id = candidate_work
      AND terminal_receipt_id IS NULL
      AND source_closure_effect_intent_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'new work-scoped authority or history cannot follow terminal finality'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_authority_facts_preserve_terminal_receipt';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_note_reopened_work_cancellation_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state IS NOT DISTINCT FROM OLD.state
       OR NEW.state IN ('CANCELLED', 'CLOSED') THEN
        RETURN NEW;
    END IF;
    UPDATE work_cancellation_authority_guards
    SET generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id
      AND work_item_id = NEW.id
      AND terminal_receipt_id IS NULL
      AND source_closure_effect_intent_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal work item cannot be reopened'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_preserve_terminal_cancellation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_assert_terminal_cancellation_authority_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.terminal_receipt_id IS NULL
       AND NEW.source_closure_effect_intent_id IS NULL THEN
        RETURN NULL;
    END IF;

    IF NEW.terminal_receipt_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM cancellation_terminal_receipts AS receipt
            WHERE receipt.tenant_id = NEW.tenant_id
              AND receipt.id = NEW.terminal_receipt_id
              AND receipt.work_item_id = NEW.work_item_id
              AND receipt.outcome = 'CANCELLED'
              AND receipt.cancellation_authority_generation = NEW.generation
        ) THEN
            RAISE EXCEPTION
                'work authority guard lacks its exact cancellation receipt'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'work_cancellation_authority_guard_terminal_receipt';
        END IF;
        RETURN NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM work_items AS work
        JOIN effect_intents AS effect
          ON effect.tenant_id = work.tenant_id
         AND effect.id = NEW.source_closure_effect_intent_id
         AND effect.work_item_id = work.id
         AND effect.attempt_id = work.current_attempt_id
         AND effect.provider = 'linear'
         AND effect.effect_type = 'close_source'
         AND effect.status = 'OBSERVED'
        WHERE work.tenant_id = NEW.tenant_id
          AND work.id = NEW.work_item_id
          AND work.state = 'CLOSED'
          AND asf_observed_source_closure_is_valid(
              work.tenant_id,
              work.id
          )
    ) THEN
        RAISE EXCEPTION
            'work authority guard lacks its exact source-closure proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_authority_guard_terminal_source_closure';
    END IF;
    RETURN NULL;
END;
$$;

-- The observed effect exists before the generic workflow-step commit moves
-- the work row to CLOSED.  Freeze immediately at that transition; the exact
-- chain constraint remains deferred until the workflow and job have also
-- reached their terminal rows later in the same transaction.
CREATE FUNCTION asf_freeze_work_source_closure_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    closure_effect_id uuid;
BEGIN
    IF NEW.state <> 'CLOSED'
       OR (TG_OP = 'UPDATE' AND OLD.state = 'CLOSED') THEN
        RETURN NULL;
    END IF;

    SELECT effect.id
    INTO closure_effect_id
    FROM effect_intents AS effect
    WHERE effect.tenant_id = NEW.tenant_id
      AND effect.work_item_id = NEW.id
      AND effect.attempt_id = NEW.current_attempt_id
      AND effect.provider = 'linear'
      AND effect.effect_type = 'close_source'
      AND effect.status = 'OBSERVED';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'CLOSED work has no observed source-close effect to freeze'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'source_closure_requires_unfrozen_work_authority_guard';
    END IF;

    UPDATE work_cancellation_authority_guards
    SET generation = generation + 1,
        source_closure_effect_intent_id = closure_effect_id,
        updated_at = clock_timestamp()
    WHERE tenant_id = NEW.tenant_id
      AND work_item_id = NEW.id
      AND terminal_receipt_id IS NULL
      AND source_closure_effect_intent_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source closure has no unfrozen work authority guard'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'source_closure_requires_unfrozen_work_authority_guard';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER work_items_zz_freeze_source_closure_authority_guard
    AFTER INSERT OR UPDATE ON work_items
    FOR EACH ROW EXECUTE FUNCTION asf_freeze_work_source_closure_guard();

-- Avoid a child -> work row lock when the competing terminal transition is
-- not yet committed.  A child that won the shared guard may commit; the
-- terminal transaction then observes it and fails its negative proof.  Once
-- finality is committed, the immediate child guard rejects before this
-- deferred function is reached.
CREATE OR REPLACE FUNCTION asf_assert_source_closure_for_work(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    candidate_state text;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.tenant_id = candidate_tenant
          AND work.id = candidate_work_item
          AND work.state = 'CLOSED'
    ) AND NOT EXISTS (
        SELECT 1
        FROM work_cancellation_authority_guards AS authority_guard
        WHERE authority_guard.tenant_id = candidate_tenant
          AND authority_guard.work_item_id = candidate_work_item
          AND authority_guard.source_closure_effect_intent_id IS NOT NULL
    ) THEN
        RETURN;
    END IF;

    SELECT work.state
    INTO candidate_state
    FROM work_items AS work
    WHERE work.tenant_id = candidate_tenant
      AND work.id = candidate_work_item
    FOR UPDATE;

    IF FOUND
       AND candidate_state = 'CLOSED'
       AND NOT asf_observed_source_closure_is_valid(
           candidate_tenant,
           candidate_work_item
       ) THEN
        RAISE EXCEPTION
            'closed work item has no exact terminal source-closure proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION asf_assert_exact_source_close_observation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider = 'linear'
       AND NEW.effect_type = 'close_source'
       AND NEW.status = 'OBSERVED' THEN
        IF EXISTS (
            SELECT 1
            FROM work_items AS work
            WHERE work.tenant_id = NEW.tenant_id
              AND work.id = NEW.work_item_id
              AND work.state = 'CLOSED'
        ) OR EXISTS (
            SELECT 1
            FROM work_cancellation_authority_guards AS authority_guard
            WHERE authority_guard.tenant_id = NEW.tenant_id
              AND authority_guard.work_item_id = NEW.work_item_id
              AND authority_guard.source_closure_effect_intent_id IS NOT NULL
        ) THEN
            PERFORM asf_assert_source_closure_for_work(
                NEW.tenant_id,
                NEW.work_item_id
            );
        ELSIF NOT asf_observed_source_closure_is_valid(
            NEW.tenant_id,
            NEW.work_item_id
        ) THEN
            RAISE EXCEPTION
                'observed source-close effect lacks its exact completed workflow claim'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_require_exact_source_close_observation';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION asf_work_closure_reservation_release_is_valid(
    candidate_tenant uuid,
    candidate_reservation_set uuid
) RETURNS boolean
LANGUAGE sql VOLATILE
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

CREATE OR REPLACE FUNCTION asf_stamp_cancellation_terminal_receipt()
RETURNS trigger
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
          AND source_closure_effect_intent_id IS NULL
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

-- Retain the complete 0018 validator as the proof core and put the new
-- mutually-exclusive finality condition in front of every public fresh
-- validation.  The core still obtains the row lock and checks its recorded
-- generation, so this preliminary read cannot weaken the race fence.
ALTER FUNCTION asf_valid_cancellation_escalation_supersession_receipt(
    uuid,
    uuid,
    boolean
) RENAME TO asf_valid_cancellation_supersession_receipt_v18;

CREATE FUNCTION asf_valid_cancellation_escalation_supersession_receipt(
    candidate_tenant uuid,
    candidate_receipt uuid,
    require_fresh boolean
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    receipt_work_item uuid;
BEGIN
    IF require_fresh THEN
        SELECT receipt.work_item_id
        INTO receipt_work_item
        FROM cancellation_escalation_supersession_receipts AS receipt
        WHERE receipt.tenant_id = candidate_tenant
          AND receipt.id = candidate_receipt;
        IF NOT FOUND OR NOT EXISTS (
            SELECT 1
            FROM work_cancellation_authority_guards AS authority_guard
            WHERE authority_guard.tenant_id = candidate_tenant
              AND authority_guard.work_item_id = receipt_work_item
              AND authority_guard.terminal_receipt_id IS NULL
              AND authority_guard.source_closure_effect_intent_id IS NULL
        ) THEN
            RETURN false;
        END IF;
    END IF;
    RETURN asf_valid_cancellation_supersession_receipt_v18(
        candidate_tenant,
        candidate_receipt,
        require_fresh
    );
END;
$$;

-- Rebind the INSERT-side exactness trigger explicitly to the public wrapper;
-- this also avoids relying on cached plans across the function rename above.
CREATE OR REPLACE FUNCTION asf_assert_cancellation_escalation_supersession_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT asf_valid_cancellation_escalation_supersession_receipt(
        NEW.tenant_id,
        NEW.id,
        true
    ) THEN
        RAISE EXCEPTION 'cancellation escalation supersession receipt is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_receipt_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION asf_assert_authority_guard_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.terminal_receipt_id IS NULL
       AND NEW.source_closure_effect_intent_id IS NULL
       AND EXISTS (
           SELECT 1
           FROM work_items AS work
           WHERE work.tenant_id = NEW.tenant_id
             AND work.id = NEW.work_item_id
             AND work.state = 'CANCEL_REQUESTED'
             AND EXISTS (
                 SELECT 1
                 FROM escalations AS other_escalation
                 WHERE other_escalation.tenant_id = work.tenant_id
                   AND other_escalation.work_item_id = work.id
                   AND other_escalation.status IN ('OPEN', 'ACKNOWLEDGED')
                   AND other_escalation.authority_or_effect_active
             )
       ) THEN
        RAISE EXCEPTION
            'cancellation supersession cannot acquire competing escalation authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_authority_guard';
    END IF;
    RETURN NULL;
END;
$$;

-- Validate the staged backfill and every public terminal predicate under the
-- migration locks.  Do not infer or repair a contradictory terminal history.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.state = 'CLOSED'
          AND NOT asf_observed_source_closure_is_valid(
              work.tenant_id,
              work.id
          )
    ) OR EXISTS (
        SELECT 1
        FROM work_cancellation_authority_guards AS authority_guard
        WHERE authority_guard.source_closure_effect_intent_id IS NOT NULL
          AND NOT asf_observed_source_closure_is_valid(
              authority_guard.tenant_id,
              authority_guard.work_item_id
          )
    ) THEN
        RAISE EXCEPTION 'shared source-closure finality validation failed'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'shared_work_finality_requires_exact_closure';
    END IF;
END;
$$;
