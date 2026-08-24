-- Bind the OBSERVE_RUNMILL_RUN authority family to its exact activity
-- contract identity, `asf.activity/observe-runmill-run/v2`, installed by
-- migration 0023 as `workflow_jobs.activity_contract_id`.
--
-- Every observer proof trigger below currently proves `job_type =
-- 'OBSERVE_RUNMILL_RUN'` (or, for the gap-escalation binding, proves
-- neither `job_type` nor `activity_contract_id` at all) but never proves
-- the job's exact contract identity. `job_type` alone is not durable
-- proof of implementation identity: a future job_type could be repointed
-- at a different activity without changing its enum label. This
-- migration closes that gap by additionally requiring the exact
-- `activity_contract_id` match on every one of these authority proofs,
-- with no other behavioral change.
--
-- Exact DB proof binding: each function below is copied verbatim from its
-- final active migration-0022 definition -- same signature, same
-- attributes, same constraint names, same payload/session/fence/status/
-- chronology/digest checks, same trigger wiring -- and CREATE OR REPLACE'd
-- with exactly one added predicate per function: `job.activity_contract_id
-- = 'asf.activity/observe-runmill-run/v2'`. No trigger is dropped,
-- disabled, or recreated; only the underlying function body changes.
--
-- Executor quiescence: PostgreSQL resolves a plpgsql trigger function by
-- OID, and CREATE OR REPLACE FUNCTION keeps the OID stable, so an
-- in-flight concurrent transaction that has already started evaluating
-- one of these triggers could otherwise interleave with this migration's
-- replacement and insert a proof row that only the strictly weaker
-- pre-0024 predicate would have accepted. This migration replaces trigger
-- and helper functions across the ADVANCE_ACCEPTED_WORK_ITEM,
-- REQUEST_WORK_ITEM_CANCELLATION, CLOSE_SOURCE, VERIFY_EVIDENCE, and
-- OBSERVE_RUNMILL_RUN authority-proof families, so the single lock set
-- below -- consolidated, documented, and duplicate-free -- covers every
-- table that can be a writer/trigger entry for any function replaced in
-- this migration, plus every table the poisoned-history preflight below
-- reads as a durable authority/proof root. Acquiring SHARE ROW EXCLUSIVE
-- locks on all of them blocks concurrent INSERT/UPDATE/DELETE against
-- every one for the remainder of this transaction without requiring any
-- trigger to be dropped or disabled. Apply only with all affected
-- executors and direct writers quiesced -- no in-flight
-- ADVANCE_ACCEPTED_WORK_ITEM, REQUEST_WORK_ITEM_CANCELLATION,
-- CLOSE_SOURCE, VERIFY_EVIDENCE, or OBSERVE_RUNMILL_RUN claim, retry,
-- dead-letter, or direct-write transaction against any table locked below
-- -- so no such lock wait is required in practice. Locks are acquired in
-- stable dependency/history order (migration 0001's table-creation order,
-- then migration 0017, 0018, 0021, and 0022 in that order), all before
-- the preflight scan and every function replacement below.
LOCK TABLE repositories IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE source_snapshots IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE approvals IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE operational_incidents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_verifications IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_sets IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_set_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE budget_ledger IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_timers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE outbox IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE accountability_anchors IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE idempotency_records IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_dispatch_fact_guards IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_cancellation_authority_guards IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_cancellation_observations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_terminal_receipts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE terminal_conflict_escalation_merge_receipts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_escalation_supersession_receipts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_supersession_escalation_facts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_supersession_anchor_facts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE cancellation_supersession_work_facts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_control_snapshots IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE raw_runmill_control_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_control_snapshot_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_streams IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_checkpoints IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_results IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_observation_gap_escalation_bindings IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_observation_terminal_failure_facts IN SHARE ROW EXCLUSIVE MODE;

-- Poisoned-history preflight: refuse to install the hardened
-- activity_contract_id predicates below over a production job whose
-- identity is already wrong -- job.activity_contract_id does not match
-- the canonical contract for its job_type -- if that same wrong job is
-- actually rooted in durable authority/proof state for its family. Such a
-- job already produced a proof under the pre-0024, weaker predicate; the
-- upgrade must not silently paper over that poisoned history. A row is
-- proof-bearing only through the explicit direct roots enumerated below
-- per family; job status is never inspected, so an isolated PENDING or
-- RETRY job with a wrong contract id and no durable proof root is not
-- rejected. This is scan-only: it does not update or repair identity.
DO $$
DECLARE
    poisoned RECORD;
BEGIN
    SELECT
        job.id,
        job.tenant_id,
        job.job_type,
        job.activity_contract_id AS actual_contract_id,
        CASE job.job_type
            WHEN 'ADVANCE_ACCEPTED_WORK_ITEM' THEN 'asf.activity/advance-accepted-work-item/v1'
            WHEN 'REQUEST_WORK_ITEM_CANCELLATION' THEN 'asf.activity/request-work-item-cancellation/v1'
            WHEN 'CLOSE_SOURCE' THEN 'asf.activity/close-source/v1'
            WHEN 'VERIFY_EVIDENCE' THEN 'asf.activity/verify-evidence/v1'
            WHEN 'OBSERVE_RUNMILL_RUN' THEN 'asf.activity/observe-runmill-run/v2'
        END AS expected_contract_id
    INTO poisoned
    FROM workflow_jobs AS job
    WHERE job.job_type IN (
        'ADVANCE_ACCEPTED_WORK_ITEM', 'REQUEST_WORK_ITEM_CANCELLATION',
        'CLOSE_SOURCE', 'VERIFY_EVIDENCE', 'OBSERVE_RUNMILL_RUN'
    )
    AND job.activity_contract_id IS DISTINCT FROM CASE job.job_type
        WHEN 'ADVANCE_ACCEPTED_WORK_ITEM' THEN 'asf.activity/advance-accepted-work-item/v1'
        WHEN 'REQUEST_WORK_ITEM_CANCELLATION' THEN 'asf.activity/request-work-item-cancellation/v1'
        WHEN 'CLOSE_SOURCE' THEN 'asf.activity/close-source/v1'
        WHEN 'VERIFY_EVIDENCE' THEN 'asf.activity/verify-evidence/v1'
        WHEN 'OBSERVE_RUNMILL_RUN' THEN 'asf.activity/observe-runmill-run/v2'
    END
    AND (
        -- ADVANCE / REQUEST_CANCELLATION / CLOSE mutation families: the
        -- job owns a direct effect intent.
        (
            job.job_type IN (
                'ADVANCE_ACCEPTED_WORK_ITEM',
                'REQUEST_WORK_ITEM_CANCELLATION',
                'CLOSE_SOURCE'
            )
            AND EXISTS (
                SELECT 1
                FROM effect_intents AS effect
                WHERE effect.tenant_id = job.tenant_id
                  AND effect.owning_workflow_job_id = job.id
            )
        )
        -- CLOSE_SOURCE additionally roots through the observing linear
        -- close_source effect intent (observed source closure, closed-work
        -- finality, and release chains).
        OR (
            job.job_type = 'CLOSE_SOURCE'
            AND EXISTS (
                SELECT 1
                FROM effect_intents AS effect
                WHERE effect.tenant_id = job.tenant_id
                  AND effect.observing_workflow_job_id = job.id
                  AND effect.provider = 'linear'
                  AND effect.effect_type = 'close_source'
            )
        )
        -- ADVANCE_ACCEPTED_WORK_ITEM additionally roots through its own
        -- PRE_DISPATCH cancellation terminal receipt. work_dispatch_fact_guards
        -- is deliberately excluded here: it has no immutable job id and can
        -- false-positive on later, unrelated work against the same work item.
        OR (
            job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'
            AND EXISTS (
                SELECT 1
                FROM cancellation_terminal_receipts AS receipt
                WHERE receipt.tenant_id = job.tenant_id
                  AND receipt.workflow_job_id = job.id
                  AND receipt.route = 'PRE_DISPATCH'
            )
        )
        -- REQUEST_WORK_ITEM_CANCELLATION additionally roots through any of
        -- its direct observation/receipt/supersession facts, or through the
        -- durable parent/child observer result chain: either this job's own
        -- result names a child observation_job, or another cancellation
        -- job's result names this job as its observation_job.
        OR (
            job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
            AND (
                EXISTS (
                    SELECT 1
                    FROM runmill_cancellation_observations AS observation
                    WHERE observation.tenant_id = job.tenant_id
                      AND observation.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM cancellation_terminal_receipts AS receipt
                    WHERE receipt.tenant_id = job.tenant_id
                      AND receipt.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM terminal_conflict_escalation_merge_receipts AS merge_receipt
                    WHERE merge_receipt.tenant_id = job.tenant_id
                      AND merge_receipt.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM cancellation_escalation_supersession_receipts AS supersession
                    WHERE supersession.tenant_id = job.tenant_id
                      AND (
                          supersession.replacement_job_id = job.id
                          OR job.id = ANY(supersession.dead_workflow_job_ids)
                      )
                )
                OR job.result #> '{result,observation_job,id}' IS NOT NULL
                OR EXISTS (
                    SELECT 1
                    FROM workflow_jobs AS parent
                    WHERE parent.tenant_id = job.tenant_id
                      AND parent.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                      AND parent.result #>> '{result,observation_job,id}' = job.id::text
                )
            )
        )
        -- VERIFY_EVIDENCE roots through its own VALID evidence verification.
        OR (
            job.job_type = 'VERIFY_EVIDENCE'
            AND EXISTS (
                SELECT 1
                FROM evidence_verifications AS verification
                WHERE verification.tenant_id = job.tenant_id
                  AND verification.workflow_job_id = job.id
                  AND verification.status = 'VALID'
            )
        )
        -- OBSERVE_RUNMILL_RUN roots through any of its direct checkpoint,
        -- snapshot, active-stream-pointer, gap-escalation, or
        -- terminal-failure facts; checkpoints and snapshots additionally
        -- root their descendant result/event chains.
        OR (
            job.job_type = 'OBSERVE_RUNMILL_RUN'
            AND (
                EXISTS (
                    SELECT 1
                    FROM runmill_run_observation_checkpoints AS checkpoint
                    WHERE checkpoint.tenant_id = job.tenant_id
                      AND checkpoint.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM runmill_control_snapshots AS snapshot
                    WHERE snapshot.tenant_id = job.tenant_id
                      AND snapshot.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM runmill_run_observation_streams AS stream
                    WHERE stream.tenant_id = job.tenant_id
                      AND stream.active_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM runmill_observation_gap_escalation_bindings AS binding
                    WHERE binding.tenant_id = job.tenant_id
                      AND binding.workflow_job_id = job.id
                )
                OR EXISTS (
                    SELECT 1
                    FROM runmill_observation_terminal_failure_facts AS fact
                    WHERE fact.tenant_id = job.tenant_id
                      AND fact.workflow_job_id = job.id
                )
            )
        )
    )
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'migration 0024 refuses to upgrade activity contract authority proofs over poisoned history: a production workflow job is rooted in durable authority/proof state but its activity_contract_id does not match the canonical contract for its job_type'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'activity_contract_authority_proof_upgrade_preflight',
                  DETAIL = format(
                      'workflow_jobs.id=%s job_type=%s actual activity_contract_id=%s expected activity_contract_id=%s',
                      poisoned.id, poisoned.job_type, poisoned.actual_contract_id, poisoned.expected_contract_id
                  );
    END IF;
END;
$$;

-- (1 of 5) Copied verbatim from migration 0022. Its job join previously
-- proved neither `job_type` nor `activity_contract_id`; both are now
-- required.
CREATE OR REPLACE FUNCTION asf_assert_runmill_observation_gap_escalation_binding_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM runmill_run_observation_checkpoints AS checkpoint
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = checkpoint.tenant_id
     AND stream.run_id = checkpoint.run_id
    JOIN runmill_run_observation_results AS result
      ON result.tenant_id = checkpoint.tenant_id
     AND result.observation_id = checkpoint.id
     AND result.run_id = checkpoint.run_id
    JOIN workflow_jobs AS job
      ON job.tenant_id = checkpoint.tenant_id
     AND job.id = checkpoint.workflow_job_id
    JOIN runmill_control_snapshots AS page_snapshot
      ON page_snapshot.tenant_id = checkpoint.tenant_id
     AND page_snapshot.id = result.event_page_snapshot_id
    JOIN escalations AS escalation
      ON escalation.tenant_id = job.tenant_id
     AND escalation.id = job.dead_letter_escalation_id
    WHERE checkpoint.tenant_id = NEW.tenant_id
      AND checkpoint.id = NEW.observation_id
      AND checkpoint.run_id = NEW.run_id
      AND checkpoint.workflow_job_id = NEW.workflow_job_id
      AND stream.active_observation_id = NEW.observation_id
      AND stream.active_job_id = NEW.workflow_job_id
      AND stream.state = 'ACTIVE'
      AND result.disposition = 'BLOCKED_GAP'
      AND result.gap
      AND result.event_page_snapshot_id = NEW.event_page_snapshot_id
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'
      AND job.status = 'DEAD'
      AND job.dead_letter_escalation_id = NEW.escalation_id
      AND page_snapshot.observation_id = NEW.observation_id
      AND page_snapshot.workflow_job_id = NEW.workflow_job_id
      AND page_snapshot.control_operation = 'LIST_RUN_EVENTS'
      AND escalation.id = NEW.escalation_id
      AND escalation.work_item_id = stream.work_item_id
      AND escalation.attempt_id = stream.attempt_id
      AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
      AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
      AND escalation.authority_or_effect_active
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job:' || NEW.workflow_job_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'runmill-observation:' || NEW.observation_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'run:' || NEW.run_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'runmill-control-snapshot:' || NEW.event_page_snapshot_id::text
      )
    FOR SHARE OF checkpoint, stream, result, job, page_snapshot, escalation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill gap escalation binding lacks its exact result, job, page, or shared escalation proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_gap_bindings_exact_proof';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;

-- (2 of 5) Copied verbatim from migration 0022. It already proved
-- `job_type = 'OBSERVE_RUNMILL_RUN'`; the exact `activity_contract_id` is
-- now additionally required.
CREATE OR REPLACE FUNCTION asf_assert_runmill_observation_terminal_failure_fact_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Every coordinate is re-proved here under lock, so a direct writer cannot
    -- forge a release for a live job, a stale pointer, another checkpoint,
    -- another escalation, a different cursor/epoch, or an unproved digest.
    PERFORM 1
    FROM runmill_run_observation_checkpoints AS checkpoint
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = checkpoint.tenant_id
     AND stream.run_id = checkpoint.run_id
    JOIN workflow_jobs AS job
      ON job.tenant_id = checkpoint.tenant_id
     AND job.id = checkpoint.workflow_job_id
    JOIN escalations AS escalation
      ON escalation.tenant_id = job.tenant_id
     AND escalation.id = job.dead_letter_escalation_id
    WHERE checkpoint.tenant_id = NEW.tenant_id
      AND checkpoint.id = NEW.observation_id
      AND checkpoint.run_id = NEW.run_id
      AND checkpoint.workflow_job_id = NEW.workflow_job_id
      AND checkpoint.after_sequence = NEW.after_sequence
      AND checkpoint.observation_epoch = NEW.observation_epoch
      AND checkpoint.worker_id = stream.worker_id
      AND checkpoint.worker_generation = stream.worker_generation
      AND stream.state = 'ACTIVE'
      AND stream.active_observation_id = NEW.observation_id
      AND stream.active_job_id = NEW.workflow_job_id
      AND stream.next_after_sequence = NEW.after_sequence
      AND stream.observation_epoch = NEW.observation_epoch
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'
      AND job.status = 'DEAD'
      AND job.dead_letter_escalation_id = NEW.escalation_id
      AND job.dead_letter_operational_incident_id IS NULL
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'observation_id' = checkpoint.id::text
      AND job.payload ->> 'run_id' = stream.run_id::text
      AND job.payload ->> 'work_order_id' = stream.work_order_id::text
      AND job.payload ->> 'work_order_digest' = stream.work_order_digest
      AND job.payload ->> 'worker_id' = stream.worker_id::text
      AND job.payload ->> 'worker_session_id' = stream.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(stream.worker_generation)
      AND job.payload ->> 'external_run_id' = stream.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = checkpoint.observer_session_id::text
      -- The digest must come from the job's own durable terminal receipt, not
      -- from the caller.  `fail_workflow_step` writes this result in the same
      -- transaction that made the job DEAD and named its effective escalation.
      AND jsonb_typeof(job.result) = 'object'
      AND job.result ->> 'schema' = 'asf.workflow-job-dead-letter-result/v1'
      AND job.result ->> 'workflow_job_id' = job.id::text
      AND job.result ->> 'job_type' = 'OBSERVE_RUNMILL_RUN'
      AND jsonb_typeof(job.result -> 'error_digest') = 'string'
      AND job.result ->> 'error_digest' = NEW.failure_digest
      AND job.result #>> '{escalation,id}' = NEW.escalation_id::text
      -- Exhaustion escalations are shared by work item, attempt, and category,
      -- so the effective row may legitimately carry a null or foreign run_id.
      -- Never rewrite it; prove ownership through the exact per-job evidence
      -- markers that both a newly opened and an adopted escalation must carry.
      AND escalation.work_item_id = stream.work_item_id
      AND escalation.attempt_id = stream.attempt_id
      AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
      AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
      AND escalation.authority_or_effect_active
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job:' || NEW.workflow_job_id::text
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job-type:' || NEW.workflow_job_id::text || ':OBSERVE_RUNMILL_RUN'
      )
      AND escalation.evidence_references @> jsonb_build_array(
          'workflow-job-error:' || NEW.workflow_job_id::text || ':' || NEW.failure_digest
      )
      -- A retained remote page has its own result-backed release. Two competing
      -- receipts for one observation are always a fail-closed contradiction.
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_run_observation_results AS result
          WHERE result.tenant_id = checkpoint.tenant_id
            AND result.observation_id = checkpoint.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_observation_gap_escalation_bindings AS binding
          WHERE binding.tenant_id = checkpoint.tenant_id
            AND binding.observation_id = checkpoint.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM runmill_control_snapshots AS snapshot
          WHERE snapshot.tenant_id = checkpoint.tenant_id
            AND snapshot.observation_id = checkpoint.id
      )
    FOR SHARE OF checkpoint, stream, job, escalation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation terminal-failure fact lacks its exact active stream, dead V2 job, owned escalation, or durable failure digest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_terminal_failure_facts_exact_proof';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

-- (3 of 5) Copied verbatim from migration 0022. It already proved
-- `job_type = 'OBSERVE_RUNMILL_RUN'`; the exact `activity_contract_id` is
-- now additionally required.
CREATE OR REPLACE FUNCTION asf_assert_runmill_observation_checkpoint_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The producer inserts the immutable job and checkpoint first, then
    -- advances the stream epoch and installs both active pointers in the same
    -- transaction.  Therefore the checkpoint must be exactly one epoch ahead
    -- of an idle stream at the same cursor; it can never be forged for an
    -- already-owned stream.
    PERFORM 1
    FROM runmill_run_observation_streams AS stream
    JOIN workflow_jobs AS job
      ON job.tenant_id = stream.tenant_id
     AND job.id = NEW.workflow_job_id
    JOIN runs AS run
      ON run.tenant_id = stream.tenant_id
     AND run.id = stream.run_id
     AND run.work_item_id = stream.work_item_id
     AND run.attempt_id = stream.attempt_id
     AND run.work_order_id = stream.work_order_id
     AND run.worker_id = stream.worker_id
     AND run.worker_generation = stream.worker_generation
     AND run.worker_session_id = stream.run_admission_worker_session_id
     AND run.external_run_id = stream.external_run_id
     AND run.authoritative
    JOIN work_orders AS work_order
      ON work_order.tenant_id = stream.tenant_id
     AND work_order.id = stream.work_order_id
     AND work_order.work_item_id = stream.work_item_id
     AND work_order.attempt_id = stream.attempt_id
     AND work_order.payload_digest = stream.work_order_digest
    JOIN attempts AS attempt
      ON attempt.tenant_id = stream.tenant_id
     AND attempt.id = stream.attempt_id
     AND attempt.work_item_id = stream.work_item_id
     AND attempt.work_order_digest = stream.work_order_digest
    JOIN work_items AS work
      ON work.tenant_id = stream.tenant_id
     AND work.id = stream.work_item_id
     AND work.current_attempt_id = stream.attempt_id
     AND work.accepted_at IS NOT NULL
     AND work.state NOT IN ('CLOSED', 'CANCELLED')
    JOIN workflow_instances AS workflow
      ON workflow.tenant_id = stream.tenant_id
     AND workflow.id = stream.workflow_instance_id
     AND workflow.work_item_id = stream.work_item_id
     AND workflow.state IN ('ACTIVE', 'WAITING')
    JOIN worker_sessions AS observer_session
      ON observer_session.tenant_id = stream.tenant_id
     AND observer_session.id = NEW.observer_session_id
     AND observer_session.worker_id = NEW.worker_id
     AND observer_session.worker_generation = NEW.worker_generation
    JOIN workers AS worker
      ON worker.tenant_id = observer_session.tenant_id
     AND worker.id = observer_session.worker_id
    WHERE stream.tenant_id = NEW.tenant_id
      AND stream.run_id = NEW.run_id
      AND stream.state = 'ACTIVE'
      AND stream.active_job_id IS NULL
      AND stream.active_observation_id IS NULL
      AND stream.next_after_sequence = NEW.after_sequence
      AND stream.observation_epoch + 1 = NEW.observation_epoch
      AND NEW.worker_id = stream.worker_id
      AND NEW.worker_generation = stream.worker_generation
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = stream.work_item_id
      AND job.attempt_id = stream.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'
      AND job.status = 'PENDING'
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND jsonb_typeof(job.payload -> 'observation_id') = 'string'
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'observation_id' = NEW.id::text
      AND job.payload ->> 'run_id' = stream.run_id::text
      AND job.payload ->> 'work_order_id' = stream.work_order_id::text
      AND job.payload ->> 'work_order_digest' = stream.work_order_digest
      AND job.payload ->> 'worker_id' = stream.worker_id::text
      AND job.payload ->> 'worker_session_id' = stream.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(stream.worker_generation)
      AND job.payload ->> 'external_run_id' = stream.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = NEW.observer_session_id::text
      AND observer_session.status = 'ACTIVE'
      AND observer_session.expires_at > clock_timestamp()
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
    FOR UPDATE OF stream, job, run, work_order, attempt, work, workflow, observer_session, worker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill observation checkpoint lacks the exact idle stream, pending V2 job, and live current observer session'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_observation_checkpoints_exact_schedule';
    END IF;
    RETURN NEW;
END;
$$;

-- (4 of 5) Copied verbatim from migration 0022. Its active-job proof already
-- required `job_type = 'OBSERVE_RUNMILL_RUN'`; the exact
-- `activity_contract_id` is now additionally required.
CREATE OR REPLACE FUNCTION asf_guard_runmill_observation_stream() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    active_job workflow_jobs%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Runmill observation streams cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.tenant_id, NEW.run_id, NEW.workflow_instance_id, NEW.work_item_id,
        NEW.attempt_id, NEW.work_order_id, NEW.work_order_digest, NEW.worker_id,
        NEW.worker_generation, NEW.run_admission_worker_session_id,
        NEW.external_run_id, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.tenant_id, OLD.run_id, OLD.workflow_instance_id, OLD.work_item_id,
        OLD.attempt_id, OLD.work_order_id, OLD.work_order_digest, OLD.worker_id,
        OLD.worker_generation, OLD.run_admission_worker_session_id,
        OLD.external_run_id, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'Runmill observation stream identity and authority binding are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.next_after_sequence < OLD.next_after_sequence
       OR NEW.observation_epoch < OLD.observation_epoch
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
    THEN
        RAISE EXCEPTION 'Runmill observation stream cursor, epoch, or version moved backwards or skipped its fenced transition'
            USING ERRCODE = '40001';
    END IF;

    IF OLD.state <> 'ACTIVE' AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION 'blocked, terminal-ready, or escalated observation streams cannot be reopened implicitly'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.state <> 'ACTIVE' AND NEW.active_job_id IS NOT NULL THEN
        RAISE EXCEPTION 'only an active Runmill observation stream may retain a live observer job'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.escalation_id IS NOT NULL THEN
        PERFORM 1
        FROM escalations AS escalation
        WHERE escalation.tenant_id = NEW.tenant_id
          AND escalation.id = NEW.escalation_id
          AND escalation.work_item_id = NEW.work_item_id
          AND escalation.attempt_id = NEW.attempt_id
          AND (
              escalation.run_id = NEW.run_id
              OR (
                  NEW.state = 'ESCALATED'
                  AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
                  AND EXISTS (
                      SELECT 1
                      FROM runmill_observation_gap_escalation_bindings AS binding
                      WHERE binding.tenant_id = NEW.tenant_id
                        AND binding.run_id = NEW.run_id
                        AND binding.observation_id = OLD.active_observation_id
                        AND binding.workflow_job_id = OLD.active_job_id
                        AND binding.escalation_id = NEW.escalation_id
                        AND binding.event_page_snapshot_id = NEW.last_snapshot_id
                  )
              )
              OR (
                  -- Ordinary terminal observer failure: no page was retained,
                  -- so the shared escalation is bound through the append-only
                  -- terminal-failure fact instead of a run_id rewrite.
                  NEW.state = 'ESCALATED'
                  AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
                  AND EXISTS (
                      SELECT 1
                      FROM runmill_observation_terminal_failure_facts AS fact
                      WHERE fact.tenant_id = NEW.tenant_id
                        AND fact.run_id = NEW.run_id
                        AND fact.observation_id = OLD.active_observation_id
                        AND fact.workflow_job_id = OLD.active_job_id
                        AND fact.escalation_id = NEW.escalation_id
                        AND fact.after_sequence = NEW.next_after_sequence
                        AND fact.observation_epoch = NEW.observation_epoch
                        AND fact.failure_digest = NEW.last_error_digest
                  )
              )
          )
          AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
          AND escalation.authority_or_effect_active
          AND (
              (NEW.state = 'BLOCKED_GAP' AND escalation.category = 'BLOCKED_EXTERNAL')
              OR (NEW.state = 'BLOCKED_PROJECTION' AND escalation.category = 'QUARANTINED')
              OR (NEW.state = 'ESCALATED' AND escalation.category IN (
                  'BLOCKED_EXTERNAL', 'QUARANTINED', 'WORKFLOW_JOB_EXHAUSTED'
              ))
          )
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Runmill observation stream escalation is not an exact open owned reconciliation escalation'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_observation_streams_exact_escalation';
        END IF;
    END IF;

    -- A stream can release an active observation only by consuming its one
    -- immutable completion fact.  This prevents a crash-recovery or operator
    -- update from advancing (or silently discarding) a cursor without the
    -- exact get/page evidence that explains the transition.
    IF OLD.active_observation_id IS NOT NULL
       AND NEW.active_observation_id IS NULL THEN
        PERFORM 1
        FROM runmill_run_observation_results AS result
        WHERE result.tenant_id = NEW.tenant_id
          AND result.run_id = NEW.run_id
          AND result.observation_id = OLD.active_observation_id
          AND result.after_sequence = OLD.next_after_sequence
          AND result.event_page_snapshot_id = NEW.last_snapshot_id
          AND (
              (
                  result.disposition = 'ADVANCED'
                  AND NEW.state = 'ACTIVE'
                  AND NEW.next_after_sequence = result.next_sequence
                  AND NEW.escalation_id IS NULL
              )
              OR (
                  result.disposition = 'TERMINAL_READY'
                  AND NEW.state = 'TERMINAL_READY'
                  AND NEW.next_after_sequence = result.next_sequence
                  AND NEW.escalation_id IS NULL
              )
              OR (
                  result.disposition = 'BLOCKED_GAP'
                  -- A compaction gap is a forced external escalation in the
                  -- runtime path.  Keep the immutable result disposition
                  -- specific to the observed gap while permitting the stream
                  -- to retain the resulting forced ESCALATED state.
                  AND NEW.state IN ('BLOCKED_GAP', 'ESCALATED')
                  AND NEW.next_after_sequence = OLD.next_after_sequence
              )
              OR (
                  result.disposition = 'BLOCKED_PROJECTION'
                  AND NEW.state = 'BLOCKED_PROJECTION'
                  AND NEW.next_after_sequence = OLD.next_after_sequence
              )
          )
        FOR SHARE;
        IF NOT FOUND THEN
            -- The only other legal release is an owned terminal observer
            -- failure that retained no remote page.  It may move the stream to
            -- ESCALATED alone, must not move the cursor or epoch, must not
            -- invent a snapshot, and must carry the exact effective escalation
            -- and durable failure digest recorded by the immutable fact.
            PERFORM 1
            FROM runmill_observation_terminal_failure_facts AS fact
            WHERE fact.tenant_id = NEW.tenant_id
              AND fact.run_id = NEW.run_id
              AND fact.observation_id = OLD.active_observation_id
              AND fact.workflow_job_id = OLD.active_job_id
              AND fact.after_sequence = OLD.next_after_sequence
              AND fact.observation_epoch = OLD.observation_epoch
              AND NEW.state = 'ESCALATED'
              AND NEW.active_job_id IS NULL
              AND NEW.next_after_sequence = OLD.next_after_sequence
              AND NEW.observation_epoch = OLD.observation_epoch
              AND NEW.last_snapshot_id IS NOT DISTINCT FROM OLD.last_snapshot_id
              AND NEW.escalation_id = fact.escalation_id
              AND NEW.last_error_digest = fact.failure_digest
            FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Runmill observation stream release lacks the exact immutable completion checkpoint'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runmill_observation_streams_exact_result';
            END IF;
        END IF;
    END IF;

    IF NEW.active_job_id IS NOT NULL THEN
        SELECT job.* INTO active_job
        FROM workflow_jobs AS job
        JOIN runmill_run_observation_checkpoints AS checkpoint
          ON checkpoint.tenant_id = job.tenant_id
         AND checkpoint.workflow_job_id = job.id
         AND checkpoint.id = NEW.active_observation_id
         AND checkpoint.run_id = NEW.run_id
         AND checkpoint.after_sequence = NEW.next_after_sequence
         AND checkpoint.observation_epoch = NEW.observation_epoch
        JOIN worker_sessions AS observer_session
          ON observer_session.tenant_id = job.tenant_id
         AND observer_session.id = checkpoint.observer_session_id
         AND observer_session.worker_id = NEW.worker_id
         AND observer_session.worker_generation = NEW.worker_generation
        JOIN workers AS worker
          ON worker.tenant_id = observer_session.tenant_id
         AND worker.id = observer_session.worker_id
        WHERE job.tenant_id = NEW.tenant_id
          AND job.id = NEW.active_job_id
          AND job.workflow_instance_id = NEW.workflow_instance_id
          AND job.work_item_id = NEW.work_item_id
          AND job.attempt_id = NEW.attempt_id
          AND job.job_type = 'OBSERVE_RUNMILL_RUN'
          AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'
          AND job.status IN ('PENDING', 'RUNNING', 'RETRY')
          AND jsonb_typeof(job.payload) = 'object'
          AND job.payload ?& ARRAY[
              'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
              'worker_session_id', 'worker_generation', 'external_run_id',
              'after_sequence', 'observation_epoch', 'observer_session_id'
          ]
          AND job.payload - ARRAY[
              'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
              'worker_session_id', 'worker_generation', 'external_run_id',
              'after_sequence', 'observation_epoch', 'observer_session_id'
          ] = '{}'::jsonb
          AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
          AND job.payload ->> 'observation_id' = checkpoint.id::text
          AND jsonb_typeof(job.payload -> 'run_id') = 'string'
          AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
          AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
          AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
          AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
          AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
          AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
          AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
          AND job.payload ->> 'run_id' = NEW.run_id::text
          AND job.payload ->> 'work_order_id' = NEW.work_order_id::text
          AND job.payload ->> 'work_order_digest' = NEW.work_order_digest
          AND job.payload ->> 'worker_id' = NEW.worker_id::text
          AND job.payload ->> 'worker_session_id' = NEW.run_admission_worker_session_id::text
          AND job.payload -> 'worker_generation' = to_jsonb(NEW.worker_generation)
          AND job.payload ->> 'external_run_id' = NEW.external_run_id
          AND job.payload -> 'after_sequence' = to_jsonb(NEW.next_after_sequence)
          AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
          AND job.payload ->> 'observer_session_id' = checkpoint.observer_session_id::text
          AND observer_session.status = 'ACTIVE'
          AND observer_session.expires_at > clock_timestamp()
          AND worker.generation = NEW.worker_generation
          AND worker.status <> 'QUARANTINED'
        FOR SHARE OF job, observer_session, worker;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Runmill observation stream active job lacks its exact cursor, epoch, worker, or current observer-session authority'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_observation_streams_exact_active_job';
        END IF;
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

-- (5 of 5) Copied verbatim from its final active migration-0022 definition
-- (the second, CREATE OR REPLACE'd body that superseded migration 0021's
-- obsolete version). It already proved `job_type = 'OBSERVE_RUNMILL_RUN'`;
-- the exact `activity_contract_id` is now additionally required.
CREATE OR REPLACE FUNCTION asf_stamp_runmill_control_snapshot() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    decoded_response jsonb;
    decoded_canonical jsonb;
BEGIN
    IF octet_length(NEW.raw_response_bytes) NOT BETWEEN 2 AND 2097152 THEN
        RAISE EXCEPTION 'Runmill control response wire is outside the protocol size limit'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END IF;
    BEGIN
        decoded_response := convert_from(NEW.raw_response_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Runmill control response bytes are not UTF-8 JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END;
    IF jsonb_typeof(decoded_response) IS DISTINCT FROM 'object'
       OR decoded_response ?& ARRAY['ok', 'data'] IS NOT TRUE
       OR decoded_response - ARRAY['ok', 'data'] <> '{}'::jsonb
       OR decoded_response -> 'ok' IS DISTINCT FROM 'true'::jsonb
       OR decoded_response -> 'data' IS DISTINCT FROM NEW.raw_snapshot
       OR get_byte(NEW.raw_response_bytes, octet_length(NEW.raw_response_bytes) - 1) <> 10
       OR position(decode('0a', 'hex') in NEW.raw_response_bytes)
          <> octet_length(NEW.raw_response_bytes)
       OR NEW.response_wire_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.raw_response_bytes), 'hex'
       ) THEN
        RAISE EXCEPTION 'Runmill control response bytes contradict their exact success envelope'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_response';
    END IF;
    BEGIN
        decoded_canonical := convert_from(NEW.canonical_snapshot, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Runmill control snapshot JCS bytes are not UTF-8 JSON'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_canonical_semantics';
    END;
    IF decoded_canonical IS DISTINCT FROM NEW.raw_snapshot
       OR NEW.snapshot_semantic_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.canonical_snapshot), 'hex'
       ) THEN
        RAISE EXCEPTION 'Runmill control snapshot canonical bytes or semantic digest is invalid'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_canonical_semantics';
    END IF;

    -- `worker_session_id` is retained as a compatibility alias for the
    -- immutable admission session.  Never allow a new row to smuggle a
    -- current observer session into that historical coordinate.
    IF NEW.worker_session_id IS DISTINCT FROM NEW.run_admission_worker_session_id
       OR NEW.observation_epoch <= 0
       OR NEW.observation_id IS NULL
       OR NEW.requested_after_sequence > NEW.external_latest_sequence THEN
        RAISE EXCEPTION 'Runmill control snapshot has an invalid admission session, epoch, or requested cursor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_stream_cursor';
    END IF;

    PERFORM 1
    FROM workflow_jobs AS job
    JOIN runmill_run_observation_streams AS stream
      ON stream.tenant_id = job.tenant_id
     AND stream.run_id = NEW.run_id
    JOIN runmill_run_observation_checkpoints AS checkpoint
      ON checkpoint.tenant_id = stream.tenant_id
     AND checkpoint.id = NEW.observation_id
     AND checkpoint.run_id = stream.run_id
     AND checkpoint.workflow_job_id = job.id
     AND checkpoint.after_sequence = NEW.requested_after_sequence
     AND checkpoint.observation_epoch = NEW.observation_epoch
     AND checkpoint.observer_session_id = NEW.observer_session_id
    WHERE job.tenant_id = NEW.tenant_id
      AND job.id = NEW.workflow_job_id
      AND job.workflow_instance_id = stream.workflow_instance_id
      AND job.work_item_id = NEW.work_item_id
      AND job.attempt_id = NEW.attempt_id
      AND job.job_type = 'OBSERVE_RUNMILL_RUN'
      AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'
      AND job.status = 'RUNNING'
      AND job.fence_token = NEW.workflow_job_fence_token
      AND job.attempt_count = NEW.workflow_job_attempt_count
      AND job.lease_owner = NEW.workflow_job_owner
      AND job.lease_expires_at > clock_timestamp()
      AND stream.workflow_instance_id = job.workflow_instance_id
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.work_order_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.run_admission_worker_session_id
      AND stream.external_run_id = NEW.external_run_id
      AND stream.state = 'ACTIVE'
      AND stream.active_job_id = job.id
      AND stream.active_observation_id = checkpoint.id
      AND stream.next_after_sequence = NEW.requested_after_sequence
      AND stream.observation_epoch = NEW.observation_epoch
      AND jsonb_typeof(job.payload) = 'object'
      AND job.payload ?& ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ]
      AND job.payload - ARRAY[
          'schema', 'observation_id', 'run_id', 'work_order_id', 'work_order_digest', 'worker_id',
          'worker_session_id', 'worker_generation', 'external_run_id',
          'after_sequence', 'observation_epoch', 'observer_session_id'
      ] = '{}'::jsonb
      AND job.payload ->> 'schema' = 'asf.runmill-observation/v2'
      AND job.payload ->> 'observation_id' = checkpoint.id::text
      AND jsonb_typeof(job.payload -> 'run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_id') = 'string'
      AND jsonb_typeof(job.payload -> 'work_order_digest') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_session_id') = 'string'
      AND jsonb_typeof(job.payload -> 'worker_generation') = 'number'
      AND jsonb_typeof(job.payload -> 'external_run_id') = 'string'
      AND jsonb_typeof(job.payload -> 'after_sequence') = 'number'
      AND jsonb_typeof(job.payload -> 'observation_epoch') = 'number'
      AND jsonb_typeof(job.payload -> 'observer_session_id') = 'string'
      AND job.payload ->> 'run_id' = NEW.run_id::text
      AND job.payload ->> 'work_order_id' = NEW.work_order_id::text
      AND job.payload ->> 'work_order_digest' = NEW.work_order_digest
      AND job.payload ->> 'worker_id' = NEW.worker_id::text
      AND job.payload ->> 'worker_session_id' = NEW.run_admission_worker_session_id::text
      AND job.payload -> 'worker_generation' = to_jsonb(NEW.worker_generation)
      AND job.payload ->> 'external_run_id' = NEW.external_run_id
      AND job.payload -> 'after_sequence' = to_jsonb(NEW.requested_after_sequence)
      AND job.payload -> 'observation_epoch' = to_jsonb(NEW.observation_epoch)
      AND job.payload ->> 'observer_session_id' = NEW.observer_session_id::text
    FOR UPDATE OF job, stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot lacks its exact live observation stream claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_job_claim';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM runmill_control_snapshots AS prior
        WHERE prior.tenant_id = NEW.tenant_id
          AND prior.workflow_job_id = NEW.workflow_job_id
          AND prior.workflow_job_fence_token = NEW.workflow_job_fence_token
          AND prior.control_sequence > NEW.control_sequence
    ) THEN
        RAISE EXCEPTION 'Runmill control sequence moved backwards within one job claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_monotonic_control_sequence';
    END IF;

    IF (
        NEW.control_operation = 'GET_RUN'
        AND (
            NEW.raw_snapshot #>> '{run,runId}' IS DISTINCT FROM NEW.external_run_id
            OR NEW.raw_snapshot #>> '{run,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{run,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{run,generation}' IS DISTINCT FROM NEW.external_generation::text
            OR NEW.raw_snapshot #>> '{run,stateVersion}' IS DISTINCT FROM NEW.external_state_version::text
            OR NEW.raw_snapshot ->> 'latestSequence' IS DISTINCT FROM NEW.external_latest_sequence::text
            OR NEW.raw_snapshot #>> '{admission,idempotencyKey}' IS DISTINCT FROM NEW.admission_idempotency_key
            OR NEW.raw_snapshot #>> '{admission,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{admission,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{admission,tenantId}' IS DISTINCT FROM NEW.tenant_id::text
            OR NEW.raw_snapshot #>> '{admission,payloadDigest}' IS DISTINCT FROM NEW.work_order_digest
            OR NEW.raw_snapshot #>> '{admission,envelopeDigest}' IS DISTINCT FROM NEW.admission_envelope_digest
            OR NEW.raw_snapshot #>> '{admission,effectivePolicyDigest}' IS DISTINCT FROM NEW.admission_policy_digest
        )
    ) OR (
        NEW.control_operation = 'LIST_RUN_EVENTS'
        AND (
            jsonb_typeof(NEW.raw_snapshot -> 'events') IS DISTINCT FROM 'array'
            OR CASE
                WHEN jsonb_typeof(NEW.raw_snapshot -> 'events') = 'array'
                THEN jsonb_array_length(NEW.raw_snapshot -> 'events') > 1000
                ELSE false
            END
            OR NEW.raw_snapshot #>> '{snapshot,run,runId}' IS DISTINCT FROM NEW.external_run_id
            OR NEW.raw_snapshot #>> '{snapshot,run,workOrderId}' IS DISTINCT FROM NEW.work_order_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,attemptId}' IS DISTINCT FROM NEW.attempt_id::text
            OR NEW.raw_snapshot #>> '{snapshot,run,generation}' IS DISTINCT FROM NEW.external_generation::text
            OR NEW.raw_snapshot #>> '{snapshot,run,stateVersion}' IS DISTINCT FROM NEW.external_state_version::text
            OR NEW.raw_snapshot #>> '{snapshot,latestSequence}' IS DISTINCT FROM NEW.external_latest_sequence::text
            OR jsonb_typeof(NEW.raw_snapshot -> 'nextCursor') IS DISTINCT FROM 'number'
            OR (NEW.raw_snapshot ->> 'nextCursor')::bigint < NEW.requested_after_sequence
            OR (NEW.raw_snapshot ->> 'nextCursor')::bigint > NEW.external_latest_sequence
        )
    ) THEN
        RAISE EXCEPTION 'Runmill control snapshot indexed provenance contradicts raw JSON or its requested cursor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_raw_json_binding';
    END IF;

    -- The control session must be current.  The run-admission session above is
    -- immutable historic provenance and is intentionally not required to be
    -- live: requiring it prevented restart/reconnect observation.
    PERFORM 1
    FROM workers AS worker
    JOIN worker_sessions AS observer_session
      ON observer_session.tenant_id = worker.tenant_id
     AND observer_session.worker_id = worker.id
    WHERE worker.tenant_id = NEW.tenant_id
      AND worker.id = NEW.worker_id
      AND worker.generation = NEW.worker_generation
      AND worker.status <> 'QUARANTINED'
      AND observer_session.id = NEW.observer_session_id
      AND observer_session.worker_generation = NEW.worker_generation
      AND observer_session.status = 'ACTIVE'
      AND observer_session.expires_at > clock_timestamp()
    FOR SHARE OF worker, observer_session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot has a stale, closed, or expired current observer session generation'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'runmill_control_snapshots_live_worker_session';
    END IF;

    PERFORM 1
    FROM runs AS run
    JOIN work_orders AS work_order
      ON work_order.tenant_id = run.tenant_id
     AND work_order.id = run.work_order_id
    JOIN attempts AS attempt
      ON attempt.tenant_id = run.tenant_id
     AND attempt.id = run.attempt_id
     AND attempt.work_item_id = run.work_item_id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
      AND run.work_order_id = NEW.work_order_id
      AND work_order.payload_digest = NEW.work_order_digest
      AND run.worker_session_id = NEW.run_admission_worker_session_id
      AND run.worker_id = NEW.worker_id
      AND run.worker_generation = NEW.worker_generation
      AND run.external_run_id = NEW.external_run_id
      AND run.authoritative
      AND (
          NEW.control_operation = 'LIST_RUN_EVENTS'
          OR (
              work_order.idempotency_key = NEW.admission_idempotency_key
              AND work_order.key_id = NEW.raw_snapshot #>> '{admission,signatureKeyId}'
              AND work_order.algorithm = NEW.raw_snapshot #>> '{admission,signatureAlgorithm}'
              AND attempt.policy_digest = NEW.admission_policy_digest
              AND NEW.admission_envelope_digest = 'sha256:' || encode(
                  sha256(work_order.exact_signed_envelope), 'hex'
              )
          )
      )
    FOR SHARE OF run, work_order, attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Runmill control snapshot lacks the exact authoritative run binding'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_control_snapshots_exact_run_binding';
    END IF;

    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION asf_stamp_runmill_control_snapshot() IS
    'Requires an exact stream cursor/epoch, immutable run admission provenance, a separately-live observer control session, and the exact asf.activity/observe-runmill-run/v2 contract identity for new Runmill observations.';

-- Bind the source-close and evidence-verification authority-proof families to
-- their exact activity contract identities, `asf.activity/close-source/v1`
-- and `asf.activity/verify-evidence/v1`, installed by migration 0023 as
-- `workflow_jobs.activity_contract_id`.  The REQUEST_WORK_ITEM_CANCELLATION
-- and ADVANCE_ACCEPTED_WORK_ITEM branches of the shared external-mutation
-- owner guard are bound in the same pass since all three branches live in one
-- function and share one trigger.
--
-- Exact DB proof binding: each function below is copied verbatim from its
-- final active definition -- asf_guard_external_mutation_effect_owner from
-- migration 0009; asf_guard_source_close_observation_transition and
-- asf_guard_source_close_job_completion from migration 0013;
-- asf_observed_source_closure_chain_v18 from the body migration 0013 defined
-- as asf_observed_source_closure_is_valid and migration 0019 renamed (not
-- replaced); asf_work_closure_reservation_release_is_valid from its final
-- migration-0019 override (not the migration-0017 original it replaced);
-- asf_guard_verify_evidence_job_completion from migration 0016; and
-- asf_valid_evidence_verification_is_exact from its final migration-0016
-- override (not the migration-0014 original it replaced) -- same signature,
-- same attributes, same constraint names, same
-- payload/owner/session/fence/status/chronology/digest checks, same trigger
-- wiring -- and CREATE OR REPLACE'd with exactly one added predicate per
-- accepted job/effect binding: the exact matching `activity_contract_id`.
-- No trigger is dropped, disabled, or recreated; only the underlying function
-- body changes.
CREATE OR REPLACE FUNCTION asf_guard_external_mutation_effect_owner() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    required_job_type text;
    required_contract_id text;
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.status = 'IN_FLIGHT'
       AND NEW.status = 'IN_FLIGHT'
       AND ROW(
           NEW.owning_workflow_job_id,
           NEW.lease_owner,
           NEW.fence_token
       ) IS DISTINCT FROM ROW(
           OLD.owning_workflow_job_id,
           OLD.lease_owner,
           OLD.fence_token
       ) THEN
        RAISE EXCEPTION 'an in-flight external mutation must release its owner before handoff'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_owner_handoff_requires_release';
    END IF;

    -- A lost Runmill submission has no exact read-side lookup.  It cannot be
    -- made sendable again merely by acquiring another workflow-job lease.
    IF TG_OP = 'UPDATE'
       AND OLD.provider = 'runmill'
       AND OLD.effect_type = 'submit_work_order'
       AND OLD.status = 'AMBIGUOUS'
       AND NEW.status NOT IN ('AMBIGUOUS', 'OBSERVED', 'CANCELLED') THEN
        RAISE EXCEPTION 'ambiguous Runmill submission requires exact reconciliation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_ambiguous_submission_reconciliation_gate';
    END IF;

    -- Linear exposes an exact signed-marker lookup for reconciliation.  That
    -- read-side path does not require making the immutable close request
    -- sendable again.  Once a response is ambiguous, forbid every transition
    -- that could authorize a second mutation; reconciliation may only adopt
    -- an observed receipt or cancel the intent under an explicit repair.
    IF TG_OP = 'UPDATE'
       AND OLD.provider = 'linear'
       AND OLD.effect_type = 'close_source'
       AND OLD.status = 'AMBIGUOUS'
       AND NEW.status NOT IN ('AMBIGUOUS', 'OBSERVED', 'CANCELLED') THEN
        RAISE EXCEPTION 'ambiguous Linear source closure requires exact reconciliation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_ambiguous_source_closure_reconciliation_gate';
    END IF;

    IF NEW.status = 'IN_FLIGHT'
       AND (
           (NEW.provider = 'runmill' AND NEW.effect_type IN (
               'request_cancellation',
               'submit_work_order'
           ))
           OR (NEW.provider = 'linear' AND NEW.effect_type = 'close_source')
       ) THEN
        required_job_type := CASE
            WHEN NEW.provider = 'runmill'
             AND NEW.effect_type = 'request_cancellation'
                THEN 'REQUEST_WORK_ITEM_CANCELLATION'
            WHEN NEW.provider = 'runmill'
             AND NEW.effect_type = 'submit_work_order'
                THEN 'ADVANCE_ACCEPTED_WORK_ITEM'
            WHEN NEW.provider = 'linear'
             AND NEW.effect_type = 'close_source'
                THEN 'CLOSE_SOURCE'
        END;
        required_contract_id := CASE
            WHEN NEW.provider = 'runmill'
             AND NEW.effect_type = 'request_cancellation'
                THEN 'asf.activity/request-work-item-cancellation/v1'
            WHEN NEW.provider = 'runmill'
             AND NEW.effect_type = 'submit_work_order'
                THEN 'asf.activity/advance-accepted-work-item/v1'
            WHEN NEW.provider = 'linear'
             AND NEW.effect_type = 'close_source'
                THEN 'asf.activity/close-source/v1'
        END;

        IF NEW.owning_workflow_job_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM workflow_jobs AS owning_job
            WHERE owning_job.tenant_id = NEW.tenant_id
              AND owning_job.id = NEW.owning_workflow_job_id
              AND owning_job.workflow_instance_id IS NOT NULL
              AND owning_job.work_item_id = NEW.work_item_id
              AND owning_job.attempt_id = NEW.attempt_id
              AND owning_job.job_type = required_job_type
              AND owning_job.activity_contract_id = required_contract_id
              AND owning_job.status = 'RUNNING'
              AND owning_job.lease_owner = NEW.lease_owner
              AND owning_job.fence_token = NEW.fence_token
              AND owning_job.lease_expires_at > clock_timestamp()
        ) THEN
            RAISE EXCEPTION 'external mutation effect has no exact live owning workflow job'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_external_mutation_owner';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_guard_source_close_observation_transition() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider = 'linear'
       AND NEW.effect_type = 'close_source'
       AND NEW.status = 'OBSERVED' THEN
        IF TG_OP = 'INSERT' OR OLD.status NOT IN ('IN_FLIGHT', 'AMBIGUOUS') THEN
            RAISE EXCEPTION
                'a source-close receipt must transition from an executed or ambiguous intent'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_source_close_observation_transition';
        END IF;

        IF OLD.status = 'IN_FLIGHT'
           AND ROW(
               NEW.observing_workflow_job_id,
               NEW.observing_workflow_job_fence_token,
               NEW.observing_workflow_job_completed_by
           ) IS DISTINCT FROM ROW(
               OLD.owning_workflow_job_id,
               OLD.fence_token,
               OLD.lease_owner
           ) THEN
            RAISE EXCEPTION
                'source-close observation does not retain its exact in-flight claim'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_source_close_observer';
        END IF;

        IF OLD.attempt_count <= 0 THEN
            RAISE EXCEPTION
                'source-close observation has no executed effect attempt'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_source_close_attempt_required';
        END IF;

        IF OLD.status = 'AMBIGUOUS'
           AND NEW.observed_outcome ->> 'disposition'
               IS DISTINCT FROM 'reconciled' THEN
            RAISE EXCEPTION
                'ambiguous source-close effects require a reconciled receipt'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_ambiguous_source_close_reconciled';
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM workflow_jobs AS observing_job
            WHERE observing_job.tenant_id = NEW.tenant_id
              AND observing_job.id = NEW.observing_workflow_job_id
              AND observing_job.workflow_instance_id IS NOT NULL
              AND observing_job.work_item_id = NEW.work_item_id
              AND observing_job.attempt_id = NEW.attempt_id
              AND observing_job.job_type = 'CLOSE_SOURCE'
              AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'
              AND observing_job.status = 'RUNNING'
              AND observing_job.attempt_count > 0
              AND observing_job.attempt_count <= observing_job.max_attempts
              AND observing_job.fence_token =
                  NEW.observing_workflow_job_fence_token
              AND observing_job.lease_owner =
                  NEW.observing_workflow_job_completed_by
              -- The application has already locked this exact claim at the
              -- start of the final transaction.  Use that transaction's
              -- fixed authority boundary here: a slow atomic commit must not
              -- lose the claim merely because wall time advances while it
              -- holds the row lock.  A transaction started after expiry still
              -- fails closed.
              AND observing_job.lease_expires_at > transaction_timestamp()
        ) THEN
            RAISE EXCEPTION
                'source-close observation has no exact live observing claim'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_live_source_close_observer';
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM evidence_bundles AS evidence
            JOIN runs AS run
              ON run.tenant_id = evidence.tenant_id
             AND run.id = evidence.run_id
             AND run.work_item_id = evidence.work_item_id
             AND run.attempt_id = evidence.attempt_id
             AND run.worker_id = evidence.worker_id
             AND run.worker_generation = evidence.worker_generation
             AND run.worker_session_id = evidence.worker_session_id
            JOIN workers AS worker
              ON worker.tenant_id = run.tenant_id
             AND worker.id = run.worker_id
             AND worker.status <> 'QUARANTINED'
            WHERE evidence.tenant_id = NEW.tenant_id
              AND evidence.id = NEW.evidence_id
              AND evidence.work_item_id = NEW.work_item_id
              AND evidence.attempt_id = NEW.attempt_id
        ) THEN
            RAISE EXCEPTION
                'source-close observation was made under quarantined or contradictory worker authority'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_source_close_worker_not_quarantined';
        END IF;

        IF asf_source_closure_timestamp(
               NEW.request_payload ->> 'requested_at'
           ) IS NULL
           OR asf_source_closure_timestamp(
               NEW.observed_outcome ->> 'recorded_at'
           ) IS NULL
           OR asf_source_closure_timestamp(
               NEW.request_payload ->> 'requested_at'
           ) > clock_timestamp() + interval '5 minutes'
           OR asf_source_closure_timestamp(
               NEW.observed_outcome ->> 'recorded_at'
           ) > clock_timestamp() + interval '5 minutes' THEN
            RAISE EXCEPTION
                'source-close request or receipt has an invalid future timestamp'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_source_close_clock_bound';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_guard_source_close_job_completion() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type = 'CLOSE_SOURCE'
       AND NEW.status = 'COMPLETED'
       AND OLD.status IS DISTINCT FROM 'COMPLETED'
       AND (
           OLD.status <> 'RUNNING'
           OR OLD.attempt_count <= 0
           OR OLD.attempt_count > OLD.max_attempts
           OR OLD.lease_owner IS NULL
           OR OLD.lease_expires_at IS NULL
           OR OLD.activity_contract_id IS DISTINCT FROM 'asf.activity/close-source/v1'
           OR NEW.activity_contract_id IS DISTINCT FROM 'asf.activity/close-source/v1'
           OR NEW.fence_token IS DISTINCT FROM OLD.fence_token
           OR NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
           OR NEW.completed_by IS DISTINCT FROM OLD.lease_owner
           OR NEW.completion_fence_token IS DISTINCT FROM OLD.fence_token
           OR NEW.completed_at IS NULL
           OR NEW.result IS NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'CLOSE_SOURCE completion does not capture its exact executed claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_exact_source_close_completion';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_observed_source_closure_chain_v18(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM work_items AS work
        JOIN source_snapshots AS snapshot
          ON snapshot.tenant_id = work.tenant_id
         AND snapshot.id = work.source_snapshot_id
         AND snapshot.repository_id = work.repository_id
         AND snapshot.source_system = work.source_system
         AND snapshot.external_id = work.source_external_id
        JOIN repositories AS repository
          ON repository.tenant_id = work.tenant_id
         AND repository.id = work.repository_id
         AND repository.forge = 'github'
        JOIN attempts AS attempt
          ON attempt.tenant_id = work.tenant_id
         AND attempt.id = work.current_attempt_id
         AND attempt.work_item_id = work.id
         AND attempt.state = 'SUCCEEDED'
         AND attempt.terminal_at IS NOT NULL
         AND attempt.source_snapshot_digest = snapshot.content_digest
         AND attempt.policy_digest = work.policy_digest
        JOIN work_orders AS work_order
          ON work_order.tenant_id = attempt.tenant_id
         AND work_order.work_item_id = attempt.work_item_id
         AND work_order.attempt_id = attempt.id
         AND work_order.payload_digest = attempt.work_order_digest
        JOIN runs AS run
          ON run.tenant_id = attempt.tenant_id
         AND run.work_item_id = attempt.work_item_id
         AND run.attempt_id = attempt.id
         AND run.work_order_id = work_order.id
         AND run.authoritative
         AND run.state = 'SUCCEEDED'
         AND run.terminal_at IS NOT NULL
        JOIN workers AS worker
          ON worker.tenant_id = run.tenant_id
         AND worker.id = run.worker_id
        JOIN worker_sessions AS session
          ON session.tenant_id = run.tenant_id
         AND session.id = run.worker_session_id
         AND session.worker_id = run.worker_id
         AND session.worker_generation = run.worker_generation
        JOIN evidence_bundles AS evidence
          ON evidence.tenant_id = run.tenant_id
         AND evidence.work_item_id = run.work_item_id
         AND evidence.attempt_id = run.attempt_id
         AND evidence.run_id = run.id
         AND evidence.worker_id = run.worker_id
         AND evidence.worker_generation = run.worker_generation
         AND evidence.worker_session_id = run.worker_session_id
         AND evidence.key_id = session.signing_key_id
         AND evidence.work_order_digest = work_order.payload_digest
         AND evidence.base_sha = attempt.base_sha
         AND evidence.requested_target = work.closure_target
         AND evidence.target_satisfied
        JOIN evidence_verifications AS verification
          ON verification.tenant_id = evidence.tenant_id
         AND verification.evidence_id = evidence.id
         AND verification.expectation_digest = run.evidence_expectation_digest
         AND verification.status = 'VALID'
        JOIN effect_intents AS effect
          ON effect.tenant_id = work.tenant_id
         AND effect.work_item_id = work.id
         AND effect.attempt_id = attempt.id
         AND effect.provider = 'linear'
         AND effect.effect_type = 'close_source'
         AND effect.status = 'OBSERVED'
         AND effect.source_snapshot_id = snapshot.id
         AND effect.source_revision = snapshot.source_revision
         AND effect.source_snapshot_digest = snapshot.content_digest
         AND effect.evidence_id = evidence.id
         AND effect.evidence_digest = evidence.payload_digest
        JOIN workflow_jobs AS observing_job
          ON observing_job.tenant_id = effect.tenant_id
         AND observing_job.id = effect.observing_workflow_job_id
         AND observing_job.work_item_id = effect.work_item_id
         AND observing_job.attempt_id = effect.attempt_id
         AND observing_job.job_type = 'CLOSE_SOURCE'
         AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'
         AND observing_job.status = 'COMPLETED'
         AND observing_job.attempt_count > 0
         AND observing_job.attempt_count <= observing_job.max_attempts
         AND observing_job.fence_token =
             effect.observing_workflow_job_fence_token
         AND observing_job.completion_fence_token =
             effect.observing_workflow_job_fence_token
         AND observing_job.completed_by =
             effect.observing_workflow_job_completed_by
         AND observing_job.completed_at IS NOT NULL
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = observing_job.tenant_id
         AND workflow.id = observing_job.workflow_instance_id
         AND workflow.work_item_id = work.id
         AND workflow.workflow_type = 'WORK_ITEM_DELIVERY'
         AND workflow.state = 'COMPLETED'
         AND workflow.terminal_at IS NOT NULL
        JOIN accountability_anchors AS anchor
          ON anchor.tenant_id = work.tenant_id
         AND anchor.work_item_id = work.id
         AND anchor.anchor_type = 'CLOSURE'
         AND anchor.reference_id = evidence.id
         AND NOT anchor.authority_or_effect_active
        WHERE work.tenant_id = candidate_tenant
          AND work.id = candidate_work_item
          AND work.state = 'CLOSED'
          AND work.source_system = 'LINEAR'
          AND work.closure_target = 'pull_request'
          AND work.policy_digest IS NOT NULL
          AND work.closed_at IS NOT NULL
          AND work_order.schema_version = 'asf.work-order/v1'
          AND work_order.envelope_schema = 'asf.work-order-envelope/v1'
          AND work_order.algorithm = 'EdDSA'
          AND work_order.payload #>> '{work_order_id}' = work_order.id::text
          AND work_order.payload #>> '{tenant_id}' = work.tenant_id::text
          AND work_order.payload #>> '{work_item_id}' = work.id::text
          AND work_order.payload #>> '{attempt_id}' = attempt.id::text
          AND work_order.payload #>> '{source,system}' = 'linear'
          AND work_order.payload #>> '{source,external_id}' = work.source_external_id
          AND work_order.payload #>> '{source,snapshot_digest}' = snapshot.content_digest
          AND work_order.payload #>> '{repository,forge}' = repository.forge
          AND work_order.payload #>> '{repository,repository}' =
              repository.owner || '/' || repository.name
          AND work_order.payload #>> '{repository,base_ref}' = attempt.base_ref
          AND work_order.payload #>> '{repository,base_sha}' = attempt.base_sha
          AND work_order.payload #>> '{delivery,closure_target}' = 'pr'
          AND work_order.payload ->> 'policy_digest' = work.policy_digest
          AND work_order.payload #>> '{verification,policy_snapshot_digest}' =
              work.policy_digest
          AND work_order.payload ->> 'schema' = work_order.schema_version
          AND work_order.payload ->> 'idempotency_key' = work_order.idempotency_key
          AND work_order.payload #> '{verification,required_local_check_ids}' =
              evidence.payload #> '{predicate,policy,required_local_checks}'
          AND work_order.payload #> '{verification,required_remote_checks}' =
              evidence.payload #> '{predicate,policy,required_ci_contexts}'
          AND asf_source_closure_json(work_order.canonical_payload) =
              work_order.payload
          AND 'sha256:' || encode(sha256(work_order.canonical_payload), 'hex') =
              work_order.payload_digest
          AND asf_source_closure_json(work_order.exact_signed_envelope) - ARRAY[
              'schema',
              'key_id',
              'algorithm',
              'issued_at',
              'not_before',
              'expires_at',
              'payload',
              'signature'
          ]::text[] = '{}'::jsonb
          AND asf_source_closure_json(work_order.exact_signed_envelope) #> '{payload}' =
              work_order.payload
          AND asf_source_closure_json(work_order.exact_signed_envelope) ->> 'schema' =
              work_order.envelope_schema
          AND asf_source_closure_json(work_order.exact_signed_envelope) ->> 'key_id' =
              work_order.key_id
          AND asf_source_closure_json(work_order.exact_signed_envelope) ->> 'algorithm' =
              work_order.algorithm
          AND asf_source_closure_json(work_order.exact_signed_envelope) ->> 'signature' =
              work_order.signature
          AND asf_source_closure_timestamp(
              asf_source_closure_json(work_order.exact_signed_envelope) ->> 'issued_at'
          ) = work_order.issued_at
          AND asf_source_closure_timestamp(
              asf_source_closure_json(work_order.exact_signed_envelope) ->> 'not_before'
          ) = work_order.not_before
          AND asf_source_closure_timestamp(
              asf_source_closure_json(work_order.exact_signed_envelope) ->> 'expires_at'
          ) = work_order.expires_at
          AND evidence.schema_version = 'asf.evidence-bundle/v1'
          AND evidence.envelope_schema = 'asf.signed-evidence/v1'
          AND evidence.algorithm = 'EdDSA'
          AND run.external_run_id = evidence.payload #>> '{predicate,run,run_id}'
          AND evidence.payload #>> '{predicate,run,attempt_id}' = attempt.id::text
          AND evidence.payload #>> '{predicate,run,work_order_id}' = work_order.id::text
          AND evidence.payload #>> '{predicate,schema}' = evidence.schema_version
          AND asf_source_closure_timestamp(
              evidence.payload #>> '{predicate,run,completed_at}'
          ) = run.terminal_at
          AND evidence.payload #>> '{predicate,work_order,envelope_digest}' =
              'sha256:' || encode(sha256(work_order.exact_signed_envelope), 'hex')
          AND evidence.payload #>> '{predicate,work_order,payload_digest}' =
              work_order.payload_digest
          AND evidence.payload #>> '{predicate,work_order,signature,key_id}' =
              work_order.key_id
          AND evidence.payload #>> '{predicate,work_order,signature,algorithm}' =
              'EdDSA'
          AND evidence.payload #> '{predicate,work_order,signature,verified}' =
              'true'::jsonb
          AND evidence.payload #>> '{predicate,policy,effective_policy_digest}' =
              work.policy_digest
          AND evidence.payload #>> '{predicate,source,forge}' = repository.forge
          AND evidence.payload #>> '{predicate,source,repository}' =
              repository.owner || '/' || repository.name
          AND evidence.payload #>> '{predicate,source,base_ref}' = attempt.base_ref
          AND evidence.payload #>> '{predicate,source,base_sha}' = attempt.base_sha
          AND evidence.payload #>> '{predicate,source,candidate_sha}' =
              evidence.candidate_sha
          AND evidence.payload #>> '{predicate,source,remote_head_sha}' =
              evidence.candidate_sha
          AND evidence.payload #> '{predicate,source,merge_sha}' = 'null'::jsonb
          AND evidence.payload #>> '{predicate,delivery,closure_target}' = 'pr'
          AND evidence.payload #> '{predicate,delivery,satisfied}' = 'true'::jsonb
          AND evidence.payload #>> '{predicate,delivery,pull_request,repository}' =
              repository.owner || '/' || repository.name
          AND evidence.payload #>> '{predicate,delivery,pull_request,forge}' =
              repository.forge
          AND evidence.payload #>> '{predicate,delivery,pull_request,base_ref}' =
              attempt.base_ref
          AND evidence.payload #>> '{predicate,delivery,pull_request,head_sha}' =
              evidence.candidate_sha
          AND evidence.payload #> '{predicate,cancellation}' = 'null'::jsonb
          AND evidence.payload #>> '{predicate,budget,stop_reason}' = 'pr-delivered'
          AND asf_source_closure_json(evidence.canonical_payload) = evidence.payload
          AND 'sha256:' || encode(sha256(evidence.canonical_payload), 'hex') =
              evidence.payload_digest
          AND asf_source_closure_json(evidence.exact_signed_envelope) - ARRAY[
              'schema',
              'key_id',
              'algorithm',
              'issued_at',
              'bundle_digest',
              'statement',
              'signature'
          ]::text[] = '{}'::jsonb
          AND asf_source_closure_json(evidence.exact_signed_envelope) #> '{statement}' =
              evidence.payload
          AND asf_source_closure_json(evidence.exact_signed_envelope) ->> 'schema' =
              evidence.envelope_schema
          AND asf_source_closure_json(evidence.exact_signed_envelope) ->> 'key_id' =
              session.signing_key_id
          AND asf_source_closure_json(evidence.exact_signed_envelope) ->> 'algorithm' =
              evidence.algorithm
          AND asf_source_closure_json(evidence.exact_signed_envelope) ->> 'bundle_digest' =
              evidence.payload_digest
          AND asf_source_closure_json(evidence.exact_signed_envelope) ->> 'signature' =
              evidence.signature
          AND asf_source_closure_timestamp(
              asf_source_closure_json(evidence.exact_signed_envelope) ->> 'issued_at'
          ) = evidence.produced_at
          AND session.started_at <= run.adopted_at
          AND run.terminal_at <= evidence.produced_at
          AND run.terminal_at <= attempt.terminal_at
          AND session.started_at <= evidence.produced_at
          AND evidence.produced_at < session.expires_at
          AND (
              session.closed_at IS NULL
              OR evidence.produced_at <= session.closed_at
          )
          AND verification.details ->> 'schema' =
              'asf.evidence-verification-receipt.v1'
          AND verification.details ->> 'evidence_id' = evidence.id::text
          AND verification.details ->> 'work_item_id' = work.id::text
          AND verification.details ->> 'attempt_id' = attempt.id::text
          AND verification.details ->> 'run_id' = run.id::text
          AND verification.details ->> 'evidence_digest' = evidence.payload_digest
          AND verification.details ->> 'work_order_digest' = work_order.payload_digest
          AND verification.details ->> 'expectation_digest' =
              run.evidence_expectation_digest
          AND verification.details ->> 'verifier' = verification.verifier
          AND verification.details -> 'pull_request' =
              effect.request_payload #> '{effect,closure,pull_request}'
          AND verification.details #>> '{pull_request,repository}' =
              evidence.payload #>> '{predicate,delivery,pull_request,repository}'
          AND verification.details #>> '{pull_request,number}' =
              evidence.payload #>> '{predicate,delivery,pull_request,number}'
          AND verification.details #>> '{pull_request,url}' =
              evidence.payload #>> '{predicate,delivery,pull_request,url}'
          AND verification.details #>> '{pull_request,base_sha}' = attempt.base_sha
          AND verification.details #>> '{pull_request,head_sha}' =
              evidence.candidate_sha
          AND verification.details #> '{pull_request,required_ci_contexts}' =
              evidence.payload #> '{predicate,policy,required_ci_contexts}'
          AND (verification.details #> '{pull_request,successful_ci_contexts}') @>
              (verification.details #> '{pull_request,required_ci_contexts}')
          AND btrim(verification.details ->> 'provider_revision') <> ''
          AND evidence.produced_at <= asf_source_closure_timestamp(
              verification.details ->> 'observed_at'
          )
          AND asf_source_closure_timestamp(
              evidence.payload #>> '{predicate,delivery,pull_request,observed_at}'
          ) <= asf_source_closure_timestamp(
              verification.details ->> 'observed_at'
          )
          AND asf_source_closure_timestamp(
              verification.details ->> 'observed_at'
          ) <= verification.verified_at + interval '5 minutes'
          AND effect.request_payload - ARRAY[
              'schema',
              'idempotency_key',
              'effect_digest',
              'effect',
              'requested_at'
          ]::text[] = '{}'::jsonb
          AND effect.request_payload ->> 'schema' = 'asf.close-source-request.v1'
          AND effect.request_payload ->> 'idempotency_key' = effect.idempotency_key
          AND effect.idempotency_key =
              'source-close:' || work.id::text || ':' || evidence.id::text
          AND effect.correlation_marker =
              'asf-close:' || work.id::text || ':' || evidence.id::text
          AND effect.attempt_count > 0
          AND effect.request_digest =
              asf_source_closure_digest(effect.request_payload)
          AND effect.request_payload ->> 'effect_digest' =
              asf_source_closure_digest(effect.request_payload -> 'effect')
          AND (effect.request_payload -> 'effect') - ARRAY[
              'schema',
              'item',
              'expected_source_revision',
              'expected_snapshot_digest',
              'correlation_marker',
              'closure'
          ]::text[] = '{}'::jsonb
          AND effect.request_payload #>> '{effect,schema}' =
              'asf.source-close-effect.v1'
          AND (effect.request_payload #> '{effect,item}') - ARRAY[
              'tenant_id',
              'source',
              'external_id'
          ]::text[] = '{}'::jsonb
          AND effect.request_payload #>> '{effect,item,tenant_id}' =
              work.tenant_id::text
          AND effect.request_payload #>> '{effect,item,source}' = 'linear'
          AND effect.request_payload #>> '{effect,item,external_id}' =
              work.source_external_id
          AND effect.request_payload #>> '{effect,expected_source_revision}' =
              snapshot.source_revision
          AND effect.request_payload #>> '{effect,expected_snapshot_digest}' =
              snapshot.content_digest
          AND effect.request_payload #>> '{effect,correlation_marker}' =
              effect.correlation_marker
          AND (effect.request_payload #> '{effect,closure}') - ARRAY[
              'work_item_id',
              'target',
              'pull_request',
              'evidence_id',
              'evidence_digest',
              'final_outcome_summary',
              'cost_microunits',
              'wall_time_seconds'
          ]::text[] = '{}'::jsonb
          AND effect.request_payload #>> '{effect,closure,work_item_id}' = work.id::text
          AND effect.request_payload #>> '{effect,closure,target}' = 'pr'
          AND effect.request_payload #>> '{effect,closure,evidence_id}' = evidence.id::text
          AND effect.request_payload #>> '{effect,closure,evidence_digest}' =
              evidence.payload_digest
          AND btrim(effect.request_payload #>> '{effect,closure,final_outcome_summary}') <> ''
          AND effect.request_payload #>> '{effect,closure,final_outcome_summary}' =
              'Verified pull request '
              || (verification.details #>> '{pull_request,repository}')
              || '#' || (verification.details #>> '{pull_request,number}')
              || ' at ' || (verification.details #>> '{pull_request,head_sha}')
          AND jsonb_typeof(
              effect.request_payload #> '{effect,closure,cost_microunits}'
          ) = 'number'
          AND effect.request_payload #>> '{effect,closure,cost_microunits}' ~
              '^[0-9]+$'
          AND jsonb_typeof(evidence.payload #> '{predicate,budget,cost_usd}') =
              'number'
          AND (evidence.payload #>> '{predicate,budget,cost_usd}')::numeric >= 0
          AND round(
              (evidence.payload #>> '{predicate,budget,cost_usd}')::numeric
              * 1000000
          ) <= 9007199254740991
          AND abs(
              (evidence.payload #>> '{predicate,budget,cost_usd}')::numeric
              * 1000000
              - round(
                  (evidence.payload #>> '{predicate,budget,cost_usd}')::numeric
                  * 1000000
              )
          ) <= 0.000001
          AND (effect.request_payload #>>
              '{effect,closure,cost_microunits}')::numeric = round(
                  (evidence.payload #>> '{predicate,budget,cost_usd}')::numeric
                  * 1000000
              )
          AND jsonb_typeof(
              effect.request_payload #> '{effect,closure,wall_time_seconds}'
          ) = 'number'
          AND effect.request_payload #>> '{effect,closure,wall_time_seconds}' ~
              '^[0-9]+$'
          AND jsonb_typeof(evidence.payload #> '{predicate,budget,elapsed_ms}') =
              'number'
          AND evidence.payload #>> '{predicate,budget,elapsed_ms}' ~ '^[0-9]+$'
          AND (effect.request_payload #>>
              '{effect,closure,wall_time_seconds}')::numeric = ceil(
                  (evidence.payload #>> '{predicate,budget,elapsed_ms}')::numeric
                  / 1000
              )
          AND asf_source_closure_timestamp(
              effect.request_payload ->> 'requested_at'
          ) >= verification.verified_at
          AND asf_source_closure_timestamp(
              effect.request_payload ->> 'requested_at'
          ) <= effect.observed_at + interval '5 minutes'
          AND effect.observed_outcome - ARRAY[
              'schema',
              'item',
              'idempotency_key',
              'effect_digest',
              'correlation_marker',
              'disposition',
              'provider_revision',
              'recorded_at'
          ]::text[] = '{}'::jsonb
          AND effect.observed_outcome ->> 'schema' =
              'asf.source-close-receipt.v1'
          AND (effect.observed_outcome -> 'item') - ARRAY[
              'tenant_id',
              'source',
              'external_id'
          ]::text[] = '{}'::jsonb
          AND effect.observed_outcome #>> '{item,tenant_id}' = work.tenant_id::text
          AND effect.observed_outcome #>> '{item,source}' = 'linear'
          AND effect.observed_outcome #>> '{item,external_id}' =
              work.source_external_id
          AND effect.observed_outcome ->> 'idempotency_key' = effect.idempotency_key
          AND effect.observed_outcome ->> 'effect_digest' =
              effect.request_payload ->> 'effect_digest'
          AND effect.observed_outcome ->> 'correlation_marker' =
              effect.correlation_marker
          AND effect.observed_outcome ->> 'disposition' IN (
              'applied',
              'adopted',
              'reconciled'
          )
          AND btrim(effect.observed_outcome ->> 'provider_revision') =
              effect.observed_outcome ->> 'provider_revision'
          AND effect.observed_outcome ->> 'provider_revision' <> ''
          AND asf_source_closure_timestamp(
              effect.observed_outcome ->> 'recorded_at'
          ) >= asf_source_closure_timestamp(
              effect.request_payload ->> 'requested_at'
          )
          AND asf_source_closure_timestamp(
              effect.observed_outcome ->> 'recorded_at'
          ) <= effect.observed_at + interval '5 minutes'
          AND observing_job.payload - ARRAY[
              'work_item_id',
              'expected_work_item_version',
              'evidence_id',
              'run_id',
              'payload_digest',
              'work_order_digest',
              'expectation_digest'
          ]::text[] = '{}'::jsonb
          AND observing_job.payload ->> 'work_item_id' = work.id::text
          AND jsonb_typeof(
              observing_job.payload -> 'expected_work_item_version'
          ) = 'number'
          AND observing_job.payload ->> 'expected_work_item_version' ~
              '^[1-9][0-9]*$'
          AND asf_source_closure_bigint(
              observing_job.payload ->> 'expected_work_item_version'
          ) = work.aggregate_version - 1
          AND observing_job.payload ->> 'evidence_id' = evidence.id::text
          AND observing_job.payload ->> 'run_id' = run.id::text
          AND observing_job.payload ->> 'payload_digest' = evidence.payload_digest
          AND observing_job.payload ->> 'work_order_digest' =
              work_order.payload_digest
          AND observing_job.payload ->> 'expectation_digest' =
              run.evidence_expectation_digest
          AND jsonb_typeof(observing_job.result) = 'object'
          AND observing_job.result - ARRAY[
              'workflow_step_commit_digest',
              'result'
          ]::text[] = '{}'::jsonb
          AND observing_job.result ->> 'workflow_step_commit_digest' ~
              '^sha256:[0-9a-f]{64}$'
          AND jsonb_typeof(observing_job.result -> 'result') = 'object'
          AND (observing_job.result -> 'result') - ARRAY[
              'schema',
              'work_item_id',
              'attempt_id',
              'run_id',
              'evidence_id',
              'evidence_digest',
              'source_snapshot_id',
              'source_revision',
              'source_snapshot_digest',
              'request_digest',
              'effect_digest',
              'receipt_digest',
              'provider_revision',
              'disposition',
              'released_reservations'
          ]::text[] = '{}'::jsonb
          AND observing_job.result #>> '{result,schema}' =
              'asf.source-close-workflow-result.v1'
          AND observing_job.result #>> '{result,work_item_id}' = work.id::text
          AND observing_job.result #>> '{result,attempt_id}' = attempt.id::text
          AND observing_job.result #>> '{result,run_id}' = run.id::text
          AND observing_job.result #>> '{result,evidence_id}' = evidence.id::text
          AND observing_job.result #>> '{result,evidence_digest}' =
              evidence.payload_digest
          AND observing_job.result #>> '{result,source_snapshot_id}' =
              snapshot.id::text
          AND observing_job.result #>> '{result,source_revision}' =
              snapshot.source_revision
          AND observing_job.result #>> '{result,source_snapshot_digest}' =
              snapshot.content_digest
          AND observing_job.result #>> '{result,request_digest}' =
              effect.request_digest
          AND observing_job.result #>> '{result,effect_digest}' =
              effect.request_payload ->> 'effect_digest'
          AND observing_job.result #>> '{result,receipt_digest}' ~
              '^sha256:[0-9a-f]{64}$'
          AND observing_job.result #>> '{result,receipt_digest}' =
              asf_source_closure_digest(effect.observed_outcome)
          AND observing_job.result #>> '{result,provider_revision}' =
              effect.observed_outcome ->> 'provider_revision'
          AND observing_job.result #>> '{result,disposition}' =
              effect.observed_outcome ->> 'disposition'
          AND jsonb_typeof(
              observing_job.result #> '{result,released_reservations}'
          ) = 'number'
          AND observing_job.result #>> '{result,released_reservations}' ~
              '^[0-9]+$'
          AND asf_source_closure_bigint(
              observing_job.result #>> '{result,released_reservations}'
          ) = (
              SELECT count(*)
              FROM reservation_sets AS released_set
              WHERE released_set.tenant_id = work.tenant_id
                AND released_set.work_item_id = work.id
                AND released_set.attempt_id = attempt.id
                AND released_set.state = 'RELEASED'
                AND released_set.released_by = observing_job.completed_by
                AND released_set.release_reason =
                    'verified source closure completed the authoritative attempt'
                AND released_set.transition_idempotency_key =
                    'work-closure:v1:' || work.id::text || ':'
                    || attempt.id::text || ':' || released_set.id::text
                    || ':fence:' || (released_set.fence_token - 1)::text
          )
          AND observing_job.result ->> 'workflow_step_commit_digest' =
              asf_source_closure_digest(jsonb_build_object(
                  'job_id', observing_job.id,
                  'job_fence_token', observing_job.fence_token,
                  'work_item_version', work.aggregate_version - 1,
                  'workflow_version', workflow.aggregate_version - 1,
                  'workflow_fence_token', workflow.fence_token - 1,
                  'workflow_event_cursor', workflow.event_cursor,
                  'result', observing_job.result -> 'result',
                  'work_item_state', 'CLOSED',
                  'workflow_state', 'COMPLETED',
                  'closure_evidence_id', evidence.id
              ))
          AND effect.observed_at <= work.closed_at
          AND work.closed_at <= workflow.terminal_at
          AND workflow.terminal_at <= observing_job.completed_at
          AND NOT EXISTS (
              SELECT 1
              FROM reservation_sets AS reservation_set
              WHERE reservation_set.tenant_id = work.tenant_id
                AND reservation_set.work_item_id = work.id
                AND reservation_set.state = 'ACTIVE'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM effect_intents AS cancellation_effect
              WHERE cancellation_effect.tenant_id = work.tenant_id
                AND cancellation_effect.work_item_id = work.id
                AND cancellation_effect.attempt_id = attempt.id
                AND cancellation_effect.provider = 'runmill'
                AND cancellation_effect.effect_type = 'request_cancellation'
                AND cancellation_effect.status <> 'CANCELLED'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_jobs AS cancellation_job
              WHERE cancellation_job.tenant_id = work.tenant_id
                AND cancellation_job.work_item_id = work.id
                AND cancellation_job.attempt_id = attempt.id
                AND cancellation_job.job_type =
                    'REQUEST_WORK_ITEM_CANCELLATION'
                AND cancellation_job.status IN ('PENDING', 'RUNNING', 'RETRY')
          )
          AND NOT EXISTS (
              SELECT 1
              FROM approvals AS approval
              WHERE approval.tenant_id = work.tenant_id
                AND approval.work_item_id = work.id
                AND approval.attempt_id = attempt.id
                AND approval.status <> 'APPROVED'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM escalations AS escalation
              WHERE escalation.tenant_id = work.tenant_id
                AND escalation.work_item_id = work.id
                AND escalation.authority_or_effect_active
          )
    )
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
         AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'
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

CREATE OR REPLACE FUNCTION asf_guard_verify_evidence_job_completion() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type = 'VERIFY_EVIDENCE'
       AND NEW.status = 'COMPLETED' THEN
        IF TG_OP = 'INSERT'
           OR OLD.job_type IS DISTINCT FROM 'VERIFY_EVIDENCE'
           OR OLD.status IS DISTINCT FROM 'RUNNING'
           OR OLD.workflow_instance_id IS NULL
           OR OLD.work_item_id IS NULL
           OR OLD.attempt_id IS NULL
           OR OLD.attempt_count <= 0
           OR OLD.attempt_count > OLD.max_attempts
           OR OLD.fence_token <= 0
           OR OLD.lease_owner IS NULL
           OR OLD.lease_expires_at IS NULL
           OR OLD.lease_expires_at <= transaction_timestamp()
           OR OLD.activity_contract_id IS DISTINCT FROM 'asf.activity/verify-evidence/v1'
           OR NEW.activity_contract_id IS DISTINCT FROM 'asf.activity/verify-evidence/v1'
           OR ROW(
                NEW.tenant_id,
                NEW.id,
                NEW.workflow_instance_id,
                NEW.work_item_id,
                NEW.attempt_id,
                NEW.job_type,
                NEW.payload,
                NEW.idempotency_key,
                NEW.attempt_count,
                NEW.max_attempts,
                NEW.fence_token,
                NEW.created_at
              ) IS DISTINCT FROM ROW(
                OLD.tenant_id,
                OLD.id,
                OLD.workflow_instance_id,
                OLD.work_item_id,
                OLD.attempt_id,
                OLD.job_type,
                OLD.payload,
                OLD.idempotency_key,
                OLD.attempt_count,
                OLD.max_attempts,
                OLD.fence_token,
                OLD.created_at
              )
           OR NEW.completed_by IS DISTINCT FROM OLD.lease_owner
           OR NEW.completion_fence_token IS DISTINCT FROM OLD.fence_token
           OR NEW.completed_at IS NULL
           OR NEW.result IS NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL THEN
            RAISE EXCEPTION
                'VERIFY_EVIDENCE completion does not capture its exact executed claim'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'workflow_jobs_exact_verify_evidence_completion';
        END IF;

        NEW.completed_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION asf_valid_evidence_verification_is_exact(
    candidate_tenant uuid,
    candidate_verification uuid
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
BEGIN
    PERFORM 1
    FROM evidence_verifications AS verification
    JOIN evidence_bundles AS evidence
      ON evidence.tenant_id = verification.tenant_id
     AND evidence.id = verification.evidence_id
     AND evidence.work_item_id = verification.work_item_id
     AND evidence.attempt_id = verification.attempt_id
     AND evidence.run_id = verification.run_id
     AND evidence.payload_digest = verification.evidence_digest
     AND evidence.work_order_digest = verification.work_order_digest
    JOIN runs AS run
      ON run.tenant_id = verification.tenant_id
     AND run.id = verification.run_id
     AND run.work_item_id = verification.work_item_id
     AND run.attempt_id = verification.attempt_id
     AND run.evidence_expectation_digest = verification.expectation_digest
    JOIN workflow_jobs AS job
      ON job.tenant_id = verification.tenant_id
     AND job.id = verification.workflow_job_id
     AND job.work_item_id = verification.work_item_id
     AND job.attempt_id = verification.attempt_id
     AND job.job_type = verification.workflow_job_type
     AND job.activity_contract_id = 'asf.activity/verify-evidence/v1'
     AND job.status = verification.workflow_job_status
     AND job.completion_fence_token =
         verification.workflow_job_fence_token
     AND job.fence_token = verification.workflow_job_fence_token
     AND job.completed_by = verification.workflow_job_completed_by
    CROSS JOIN LATERAL (
        SELECT
            asf_evidence_verification_timestamp(
                verification.details ->> 'observed_at'
            ) AS receipt_observed_at,
            asf_evidence_verification_timestamp(
                evidence.payload #>>
                    '{predicate,delivery,pull_request,observed_at}'
            ) AS delivered_observed_at
    ) AS chronology
    WHERE verification.tenant_id = candidate_tenant
      AND verification.id = candidate_verification
      AND verification.status = 'VALID'
      AND verification.id <> '00000000-0000-0000-0000-000000000000'::uuid
      AND verification.evidence_id <>
          '00000000-0000-0000-0000-000000000000'::uuid
      AND verification.work_item_id <>
          '00000000-0000-0000-0000-000000000000'::uuid
      AND verification.attempt_id <>
          '00000000-0000-0000-0000-000000000000'::uuid
      AND verification.run_id <>
          '00000000-0000-0000-0000-000000000000'::uuid
      AND verification.workflow_job_id <>
          '00000000-0000-0000-0000-000000000000'::uuid
      AND asf_evidence_verification_details_are_strict(verification.details)
      AND verification.details ->> 'evidence_id' = evidence.id::text
      AND verification.details ->> 'work_item_id' =
          verification.work_item_id::text
      AND verification.details ->> 'attempt_id' =
          verification.attempt_id::text
      AND verification.details ->> 'run_id' = run.id::text
      AND verification.details ->> 'evidence_digest' = evidence.payload_digest
      AND verification.details ->> 'work_order_digest' =
          evidence.work_order_digest
      AND verification.details ->> 'expectation_digest' =
          run.evidence_expectation_digest
      AND verification.details ->> 'verification_job_id' = job.id::text
      AND verification.details ->> 'verification_job_fence_token' =
          job.completion_fence_token::text
      AND verification.details ->> 'verification_job_completed_by' =
          job.completed_by
      AND verification.details ->> 'verifier' = verification.verifier
      AND verification.verifier = 'asf:github-evidence-verifier/v1'
      AND job.payload - ARRAY[
          'evidence_id',
          'run_id',
          'payload_digest',
          'work_order_digest',
          'expectation_digest'
      ]::text[] = '{}'::jsonb
      AND job.payload ->> 'evidence_id' = evidence.id::text
      AND job.payload ->> 'run_id' = run.id::text
      AND job.payload ->> 'payload_digest' = evidence.payload_digest
      AND job.payload ->> 'work_order_digest' = evidence.work_order_digest
      AND job.payload ->> 'expectation_digest' =
          run.evidence_expectation_digest
      AND job.attempt_count > 0
      AND job.attempt_count <= job.max_attempts
      AND job.completed_at IS NOT NULL
      AND job.result IS NOT NULL
      AND run.authoritative
      AND run.state = 'SUCCEEDED'
      AND evidence.target_satisfied
      AND evidence.payload #>> '{predicate,source,forge}' = 'github'
      AND evidence.payload #>> '{predicate,delivery,closure_target}' = 'pr'
      AND evidence.payload #> '{predicate,delivery,satisfied}' = 'true'::jsonb
      AND evidence.payload #>> '{predicate,delivery,pull_request,forge}' =
          'github'
      AND jsonb_typeof(
          evidence.payload #> '{predicate,delivery,pull_request,number}'
      ) = 'number'
      AND verification.details #>> '{pull_request,repository}' =
          evidence.payload #>> '{predicate,source,repository}'
      AND verification.details #>> '{pull_request,repository}' =
          evidence.payload #>> '{predicate,delivery,pull_request,repository}'
      AND verification.details #>> '{pull_request,number}' =
          evidence.payload #>> '{predicate,delivery,pull_request,number}'
      AND verification.details #>> '{pull_request,url}' =
          evidence.payload #>> '{predicate,delivery,pull_request,url}'
      AND asf_evidence_verification_github_pr_url(
          verification.details #>> '{pull_request,url}',
          verification.details #>> '{pull_request,repository}',
          verification.details #>> '{pull_request,number}'
      )
      AND verification.details #>> '{pull_request,base_sha}' =
          evidence.base_sha
      AND verification.details #>> '{pull_request,base_sha}' =
          evidence.payload #>> '{predicate,source,base_sha}'
      AND verification.details #>> '{pull_request,head_sha}' =
          evidence.candidate_sha
      AND verification.details #>> '{pull_request,head_sha}' =
          evidence.payload #>> '{predicate,source,candidate_sha}'
      AND verification.details #>> '{pull_request,head_sha}' =
          evidence.payload #>> '{predicate,source,remote_head_sha}'
      AND asf_evidence_verification_ci_set(
          evidence.payload #> '{predicate,policy,required_ci_contexts}'
      )
      AND (verification.details #> '{pull_request,required_ci_contexts}') @>
          (evidence.payload #> '{predicate,policy,required_ci_contexts}')
      AND (evidence.payload #> '{predicate,policy,required_ci_contexts}') @>
          (verification.details #> '{pull_request,required_ci_contexts}')
      AND chronology.receipt_observed_at IS NOT NULL
      AND chronology.delivered_observed_at IS NOT NULL
      AND evidence.produced_at <= chronology.receipt_observed_at
      AND chronology.delivered_observed_at <=
          chronology.receipt_observed_at
      AND chronology.receipt_observed_at >=
          job.created_at - interval '5 minutes'
      AND chronology.receipt_observed_at <=
          verification.verified_at + interval '5 minutes'
      AND chronology.receipt_observed_at <=
          job.completed_at + interval '5 minutes'
      AND verification.verified_at >= job.created_at - interval '5 minutes'
      AND verification.verified_at BETWEEN
          job.completed_at - interval '5 minutes'
          AND job.completed_at + interval '5 minutes'
      AND job.created_at <= job.completed_at + interval '5 minutes'
      AND chronology.receipt_observed_at <=
          clock_timestamp() + interval '5 minutes'
      AND verification.verified_at <=
          clock_timestamp() + interval '5 minutes'
      AND job.completed_at <= clock_timestamp() + interval '5 minutes'
    FOR SHARE OF evidence, run, job;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION asf_guard_external_mutation_effect_owner() IS
    'Requires the exact matching asf.activity/request-work-item-cancellation/v1, asf.activity/advance-accepted-work-item/v1, or asf.activity/close-source/v1 contract identity on the live owning workflow job of an in-flight external mutation effect.';

COMMENT ON FUNCTION asf_observed_source_closure_chain_v18(uuid, uuid) IS
    'Requires the exact asf.activity/close-source/v1 contract identity on the completed observing CLOSE_SOURCE job of an observed Linear source-closure receipt.';

COMMENT ON FUNCTION asf_work_closure_reservation_release_is_valid(uuid, uuid) IS
    'Requires the exact asf.activity/close-source/v1 contract identity on the completed observing CLOSE_SOURCE job that released a work-closure reservation.';

COMMENT ON FUNCTION asf_valid_evidence_verification_is_exact(uuid, uuid) IS
    'Requires the exact asf.activity/verify-evidence/v1 contract identity on the completed VERIFY_EVIDENCE job of a VALID evidence-verification receipt.';

-- Bind the cancellation ownership/initial-observation and dispatch-exception
-- authority-proof foundations to their exact activity contract identities,
-- `asf.activity/request-work-item-cancellation/v1` and
-- `asf.activity/advance-accepted-work-item/v1`, installed by migration 0023
-- as `workflow_jobs.activity_contract_id`.
--
-- `asf_guard_cancellation_effect_owner` (migration 0005) and
-- `asf_guard_runmill_mutation_effect_owner` (migration 0008) are dead code:
-- migration 0008 dropped the former and migration 0009 dropped the latter,
-- both superseded by `asf_guard_external_mutation_effect_owner`, whose
-- REQUEST_WORK_ITEM_CANCELLATION and ADVANCE_ACCEPTED_WORK_ITEM
-- `required_contract_id` binding was already installed earlier in this same
-- migration file. No further change is needed for either superseded name.
--
-- Exact DB proof binding: each function below is copied verbatim from its
-- sole active definition in migration 0017 -- same signature, same
-- attributes, same constraint names, same payload/session/fence/status/
-- chronology/digest/monotonicity checks, same trigger wiring -- and CREATE OR
-- REPLACE'd with exactly the added `activity_contract_id` predicates
-- described in each function's own comment below. No trigger is dropped,
-- disabled, or recreated; only the underlying function body changes.
CREATE OR REPLACE FUNCTION asf_stamp_runmill_cancellation_observation() RETURNS trigger
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
      AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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

COMMENT ON FUNCTION asf_stamp_runmill_cancellation_observation() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on the live owning workflow job bound to both the initial-claim and re-validated proofs of every new Runmill cancellation observation.';

-- `asf_valid_runmill_cancellation_effect_request` is invoked from three
-- contexts: (a) from within `asf_valid_runmill_cancellation_effect_observation`
-- with the effect already durably OBSERVED; (b) from within
-- `asf_guard_runmill_cancellation_effect_observation`'s BEFORE UPDATE
-- transition to OBSERVED, where a SELECT against `effect_intents` inside this
-- STABLE function still observes the pre-transition row -- status IN_FLIGHT
-- with `owning_workflow_job_id` still populated, since the NEW row has not
-- yet been persisted; and (c) durably, post-commit, with status OBSERVED.
-- The added predicate below proves a canonical
-- `asf.activity/request-work-item-cancellation/v1` workflow job through
-- whichever of those two shapes is currently visible: the live IN_FLIGHT
-- owner, or the immutable INITIAL observation's recorded job, with the
-- immutable INITIAL observation additionally bound to the candidate
-- authoritative run via `initial_observation.run_id = run.id`. Every
-- existing immutable request/digest proof is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_valid_runmill_cancellation_effect_request(
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
          AND (
              (
                  effect.status = 'IN_FLIGHT'
                  AND effect.owning_workflow_job_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM workflow_jobs AS owning_job
                      WHERE owning_job.tenant_id = effect.tenant_id
                        AND owning_job.id = effect.owning_workflow_job_id
                        AND owning_job.workflow_instance_id IS NOT NULL
                        AND owning_job.work_item_id = effect.work_item_id
                        AND owning_job.attempt_id = effect.attempt_id
                        AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                        AND owning_job.activity_contract_id =
                            'asf.activity/request-work-item-cancellation/v1'
                        AND owning_job.status = 'RUNNING'
                        AND owning_job.lease_owner = effect.lease_owner
                        AND owning_job.fence_token = effect.fence_token
                        -- transaction_timestamp() (not clock_timestamp())
                        -- preserves the claim-valid-at-transaction-start
                        -- boundary: a finalizer that locked this row FOR
                        -- UPDATE before its lease expired stays valid for
                        -- the rest of that transaction, but any transaction
                        -- begun after expiry is rejected.
                        AND owning_job.lease_expires_at > transaction_timestamp()
                  )
              )
              OR (
                  effect.status = 'OBSERVED'
                  AND effect.initial_cancellation_observation_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM runmill_cancellation_observations AS initial_observation
                      JOIN workflow_jobs AS owning_job
                        ON owning_job.tenant_id = initial_observation.tenant_id
                       AND owning_job.id = initial_observation.workflow_job_id
                      WHERE initial_observation.tenant_id = effect.tenant_id
                        AND initial_observation.id =
                            effect.initial_cancellation_observation_id
                        AND initial_observation.effect_intent_id = effect.id
                        AND initial_observation.work_item_id = effect.work_item_id
                        AND initial_observation.attempt_id = effect.attempt_id
                        AND initial_observation.run_id = run.id
                        AND initial_observation.route = 'INITIAL'
                        AND owning_job.workflow_instance_id =
                            initial_observation.workflow_instance_id
                        AND owning_job.work_item_id = effect.work_item_id
                        AND owning_job.attempt_id = effect.attempt_id
                        AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                        AND owning_job.activity_contract_id =
                            'asf.activity/request-work-item-cancellation/v1'
                        AND owning_job.fence_token =
                            initial_observation.workflow_job_fence_token
                  )
              )
          )
    );
$$;

COMMENT ON FUNCTION asf_valid_runmill_cancellation_effect_request(uuid, uuid, uuid) IS
    'Requires a canonical asf.activity/request-work-item-cancellation/v1 workflow job through the live IN_FLIGHT owner or the immutable INITIAL observation bound to the candidate authoritative run, in addition to the exact immutable request/digest proof.';

-- Bind the INITIAL observation's own recorded workflow job to the exact
-- REQUEST_WORK_ITEM_CANCELLATION contract and its exact tenant/work/attempt/
-- workflow coordinates. Every existing observed-effect proof field
-- (receipt fields, disposition/phase mapping, external generation/version/
-- sequence, reconciliation flag) is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_valid_runmill_cancellation_effect_observation(
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
          AND EXISTS (
              SELECT 1
              FROM workflow_jobs AS owning_job
              WHERE owning_job.tenant_id = observation.tenant_id
                AND owning_job.id = observation.workflow_job_id
                AND owning_job.workflow_instance_id = observation.workflow_instance_id
                AND owning_job.work_item_id = observation.work_item_id
                AND owning_job.attempt_id = observation.attempt_id
                AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
                AND owning_job.activity_contract_id =
                    'asf.activity/request-work-item-cancellation/v1'
          )
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

COMMENT ON FUNCTION asf_valid_runmill_cancellation_effect_observation(uuid, uuid, uuid) IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity and exact tenant/work/attempt/workflow coordinates on the INITIAL observation''s workflow job, in addition to the existing observed-effect proof.';

-- The pristine ADVANCE_ACCEPTED_WORK_ITEM insert exception (the row shape
-- that is the acceptance obligation, not dispatch evidence) now additionally
-- requires the exact activity_contract_id on the JSON row being inserted.
-- Every other row shape and existing exception path is unchanged.
CREATE OR REPLACE FUNCTION asf_note_work_dispatch_fact() RETURNS trigger
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
           AND new_row ->> 'activity_contract_id' =
               'asf.activity/advance-accepted-work-item/v1'
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

COMMENT ON FUNCTION asf_note_work_dispatch_fact() IS
    'The pristine ADVANCE_ACCEPTED_WORK_ITEM insert exception additionally requires the exact asf.activity/advance-accepted-work-item/v1 contract identity on the inserted row.';

-- The pre-dispatch terminalization exception (the synchronous ADVANCE job ->
-- CANCELLED transition that never counted as dispatch evidence) now
-- additionally requires the exact activity_contract_id on both the old and
-- new row. The workflow_instances exception and every other code path is
-- unchanged.
CREATE OR REPLACE FUNCTION asf_note_work_dispatch_fact_mutation() RETURNS trigger
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
           AND old_row ->> 'activity_contract_id' =
               'asf.activity/advance-accepted-work-item/v1'
           AND new_row ->> 'status' = 'CANCELLED'
           AND new_row ->> 'attempt_id' IS NULL
           AND new_row ->> 'activity_contract_id' =
               'asf.activity/advance-accepted-work-item/v1'
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

COMMENT ON FUNCTION asf_note_work_dispatch_fact_mutation() IS
    'The pre-dispatch ADVANCE_ACCEPTED_WORK_ITEM terminalization exception additionally requires the exact asf.activity/advance-accepted-work-item/v1 contract identity on both the old and new row.';

-- Bind the cancellation terminalization foundations -- the pre-dispatch
-- receipt proof, the shared terminal-transition guard, and the completed-
-- observation assertions -- to their exact activity contract identities,
-- `asf.activity/request-work-item-cancellation/v1` and
-- `asf.activity/advance-accepted-work-item/v1`, installed by migration 0023
-- as `workflow_jobs.activity_contract_id`.
--
-- Exact DB proof binding: each function below is copied verbatim from its
-- sole active definition in migration 0017 -- same signature, same
-- attributes, same constraint names, same payload/result/audit/outbox/
-- fence/status/chronology/digest checks, same trigger wiring -- and CREATE
-- OR REPLACE'd with exactly the added `activity_contract_id` predicates
-- described in each function's own comment below. No trigger is dropped,
-- disabled, or recreated; only the underlying function body changes.

-- Bind the pre-dispatch cancellation receipt's joined ADVANCE_ACCEPTED_WORK_ITEM
-- job to its exact activity contract identity. Every other joined table and
-- existing proof predicate is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_valid_pre_dispatch_cancellation_receipt(
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
          AND job.activity_contract_id = 'asf.activity/advance-accepted-work-item/v1'
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

COMMENT ON FUNCTION asf_valid_pre_dispatch_cancellation_receipt(uuid, uuid) IS
    'Requires the exact asf.activity/advance-accepted-work-item/v1 contract identity on the joined ADVANCE_ACCEPTED_WORK_ITEM job, in addition to the existing exact pre-dispatch cancellation receipt proof.';

-- Bind both terminal transitions guarded by this trigger -- the
-- REQUEST_WORK_ITEM_CANCELLATION RUNNING->COMPLETED completion and the
-- pristine ADVANCE_ACCEPTED_WORK_ITEM pre-dispatch->CANCELLED transition --
-- to their exact activity contract identities on both OLD and NEW, so a
-- wrong contract cannot bypass the guard: each check lives in the rejection
-- OR-list, not the opening condition. Every other exact-transition check is
-- preserved unchanged.
CREATE OR REPLACE FUNCTION asf_guard_cancellation_job_terminal_transition() RETURNS trigger
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
           OR OLD.activity_contract_id IS DISTINCT FROM
              'asf.activity/request-work-item-cancellation/v1'
           OR NEW.activity_contract_id IS DISTINCT FROM
              'asf.activity/request-work-item-cancellation/v1'
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
           OR OLD.activity_contract_id IS DISTINCT FROM
              'asf.activity/advance-accepted-work-item/v1'
           OR NEW.activity_contract_id IS DISTINCT FROM
              'asf.activity/advance-accepted-work-item/v1'
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

COMMENT ON FUNCTION asf_guard_cancellation_job_terminal_transition() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on both OLD and NEW for the RUNNING->COMPLETED cancellation-job transition, and the exact asf.activity/advance-accepted-work-item/v1 contract identity on both OLD and NEW for the pristine pre-dispatch ADVANCE_ACCEPTED_WORK_ITEM->CANCELLED transition, in addition to every existing exact-transition check.';

-- Bind the completed REQUEST_WORK_ITEM_CANCELLATION job lookup backing a
-- cancellation observation to its exact activity contract identity. The
-- terminal-receipt proof branch is unchanged.
CREATE OR REPLACE FUNCTION asf_assert_completed_cancellation_observation() RETURNS trigger
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
          AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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

COMMENT ON FUNCTION asf_assert_completed_cancellation_observation() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on the joined completed REQUEST_WORK_ITEM_CANCELLATION job, in addition to the existing exact completed-workflow-claim and terminal-receipt proofs.';

-- Bind the newly completed REQUEST_WORK_ITEM_CANCELLATION job, and the
-- observer-route reconciliation job it schedules, to their exact activity
-- contract identity. Both checks live inside the deferred proof's own
-- EXISTS/NOT EXISTS predicates -- not the opening IF condition -- so a
-- contract mismatch fails the deferred proof instead of silently bypassing
-- it. Every other payload/result/audit/outbox check is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_assert_completed_cancellation_job_observation() RETURNS trigger
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
             AND NEW.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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
                           AND observer.activity_contract_id =
                               'asf.activity/request-work-item-cancellation/v1'
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

COMMENT ON FUNCTION asf_assert_completed_cancellation_job_observation() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on both the newly completed job and its observer-route reconciliation job, in addition to the existing exact observation-receipt proof; a contract mismatch fails the deferred proof rather than bypassing it.';

-- Bind the cancellation authority-proof family -- the terminal-conflict
-- escalation merge receipt, the completed Runmill cancellation receipt, the
-- nonterminal cancellation observer obligation, and the cancellation
-- escalation supersession receipt's renamed v18 core -- to their exact
-- activity contract identity, `asf.activity/request-work-item-cancellation/v1`,
-- installed by migration 0023 as `workflow_jobs.activity_contract_id`.
--
-- Exact DB proof binding: asf_capture_terminal_conflict_escalation_merge_receipt,
-- asf_valid_runmill_cancellation_receipt, and
-- asf_assert_nonterminal_cancellation_observer_obligation are copied verbatim
-- from their sole active definitions in migration 0017;
-- asf_valid_cancellation_supersession_receipt_v18 is copied verbatim from the
-- body migration 0018 defined as
-- asf_valid_cancellation_escalation_supersession_receipt and migration 0019
-- renamed (not replaced) to the v18 name -- same signature, same attributes,
-- same constraint names, same payload/result/audit/outbox/fence/status/
-- chronology/digest checks, same trigger wiring -- and CREATE OR REPLACE'd
-- with exactly the added `activity_contract_id` predicates described in each
-- function's own comment below. No trigger is dropped, disabled, or
-- recreated; only the underlying function body changes.

-- Bind the RUNNING REQUEST_WORK_ITEM_CANCELLATION job whose still-claimed
-- lease backs the terminal-conflict escalation merge receipt to its exact
-- activity contract identity. Every other joined table and existing proof
-- predicate is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_capture_terminal_conflict_escalation_merge_receipt()
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
      AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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

COMMENT ON FUNCTION asf_capture_terminal_conflict_escalation_merge_receipt() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on the RUNNING REQUEST_WORK_ITEM_CANCELLATION job whose still-claimed lease backs the terminal-conflict escalation merge receipt; every other existing merge-receipt proof is preserved unchanged.';

-- Bind the completed REQUEST_WORK_ITEM_CANCELLATION job backing the Runmill
-- cancellation terminal receipt to its exact activity contract identity.
-- Every other joined table and existing proof predicate is preserved
-- unchanged.
CREATE OR REPLACE FUNCTION asf_valid_runmill_cancellation_receipt(
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
          AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
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

COMMENT ON FUNCTION asf_valid_runmill_cancellation_receipt(uuid, uuid) IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on the completed REQUEST_WORK_ITEM_CANCELLATION job backing the Runmill cancellation terminal receipt; every other existing receipt proof field is preserved unchanged.';

-- Bind both the subject observer job and the completed parent
-- REQUEST_WORK_ITEM_CANCELLATION job it was scheduled by to their exact
-- activity contract identity. Both checks fail the deferred obligation
-- closed: a wrong-contract subject job is rejected directly in the outer IF,
-- and a wrong-contract parent is rejected inside the same OR that already
-- rejects a still-missing terminal receipt, so neither can bypass the guard
-- by making the EXISTS/NOT EXISTS vanish. Every other existing predicate is
-- preserved unchanged.
CREATE OR REPLACE FUNCTION asf_assert_nonterminal_cancellation_observer_obligation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.job_type <> 'REQUEST_WORK_ITEM_CANCELLATION'
       OR NEW.status <> 'CANCELLED'
       OR OLD.status = 'CANCELLED' THEN
        RETURN NULL;
    END IF;

    IF NEW.activity_contract_id <>
           'asf.activity/request-work-item-cancellation/v1'
       OR EXISTS (
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
          AND (
              parent.activity_contract_id <>
                  'asf.activity/request-work-item-cancellation/v1'
              OR NOT EXISTS (
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

COMMENT ON FUNCTION asf_assert_nonterminal_cancellation_observer_obligation() IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on both the subject observer job and the completed parent cancellation job whose obligation it discharges, failing the deferred guard closed on either mismatch instead of letting it bypass the check; every other existing predicate is preserved unchanged.';

-- Copied from the body migration 0018 defined as
-- asf_valid_cancellation_escalation_supersession_receipt and migration 0019
-- renamed (not replaced) to asf_valid_cancellation_supersession_receipt_v18.
-- Bind the replacement REQUEST_WORK_ITEM_CANCELLATION job backing the
-- cancellation escalation supersession receipt to its exact activity
-- contract identity. Every other joined table and existing proof predicate
-- is preserved unchanged.
CREATE OR REPLACE FUNCTION asf_valid_cancellation_supersession_receipt_v18(
    candidate_tenant uuid,
    candidate_receipt uuid,
    require_fresh boolean
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    receipt cancellation_escalation_supersession_receipts%ROWTYPE;
    replacement_reason text;
    locked_cancellation_authority_generation bigint;
    expected_audit_details jsonb;
    expected_outbox_payload jsonb;
BEGIN
    SELECT * INTO receipt
    FROM cancellation_escalation_supersession_receipts
    WHERE tenant_id = candidate_tenant AND id = candidate_receipt;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    IF require_fresh THEN
        SELECT authority_guard.generation
        INTO locked_cancellation_authority_generation
        FROM work_cancellation_authority_guards AS authority_guard
        WHERE authority_guard.tenant_id = receipt.tenant_id
          AND authority_guard.work_item_id = receipt.work_item_id
          AND authority_guard.terminal_receipt_id IS NULL
        FOR UPDATE;
        IF NOT FOUND
           OR locked_cancellation_authority_generation <>
              receipt.cancellation_authority_generation THEN
            RETURN false;
        END IF;
    END IF;

    SELECT payload ->> 'reason' INTO replacement_reason
    FROM workflow_jobs
    WHERE tenant_id = receipt.tenant_id
      AND id = receipt.replacement_job_id;
    IF NOT FOUND OR replacement_reason IS NULL THEN
        RETURN false;
    END IF;

    expected_audit_details := jsonb_build_object(
        'schema', 'asf.cancellation-escalation-supersession-audit/v1',
        'work_item_id', receipt.work_item_id,
        'attempt_id', receipt.attempt_id,
        'escalation_id', receipt.escalation_id,
        'idempotency_record_id', receipt.idempotency_record_id,
        'request_digest', receipt.request_digest,
        'actor', receipt.actor_id,
        'reason', replacement_reason,
        'replacement_workflow_id', receipt.replacement_workflow_id,
        'replacement_job_id', receipt.replacement_job_id,
        'work_item_version_before', receipt.work_item_version_before,
        'work_item_version_after', receipt.work_item_version_after,
        'anchor_generation_before', receipt.anchor_generation_before,
        'anchor_generation_after', receipt.anchor_generation_after,
        'cancellation_authority_generation',
            receipt.cancellation_authority_generation,
        'escalation_status_before', receipt.escalation_status_before,
        'escalation_status_after', 'CANCELLED',
        'escalation_version_before', receipt.escalation_version_before,
        'escalation_version_after', receipt.escalation_version_after,
        'escalation_before_digest', receipt.escalation_before_digest,
        'escalation_after_digest', receipt.escalation_after_digest,
        'dead_workflow_job_ids', receipt.dead_workflow_job_ids,
        'superseded_at', asf_chrono_utc(receipt.superseded_at),
        'receipt_id', receipt.id
    );
    expected_outbox_payload := jsonb_build_object(
        'schema', 'asf.cancellation-escalation-supersession-event/v1',
        'tenant_id', receipt.tenant_id,
        'work_item_id', receipt.work_item_id,
        'attempt_id', receipt.attempt_id,
        'escalation_id', receipt.escalation_id,
        'idempotency_record_id', receipt.idempotency_record_id,
        'request_digest', receipt.request_digest,
        'actor', receipt.actor_id,
        'replacement_workflow_id', receipt.replacement_workflow_id,
        'replacement_job_id', receipt.replacement_job_id,
        'work_item_version_before', receipt.work_item_version_before,
        'work_item_version_after', receipt.work_item_version_after,
        'anchor_generation_before', receipt.anchor_generation_before,
        'anchor_generation_after', receipt.anchor_generation_after,
        'cancellation_authority_generation',
            receipt.cancellation_authority_generation,
        'escalation_status_before', receipt.escalation_status_before,
        'escalation_status_after', 'CANCELLED',
        'escalation_version_before', receipt.escalation_version_before,
        'escalation_version_after', receipt.escalation_version_after,
        'escalation_before_digest', receipt.escalation_before_digest,
        'escalation_after_digest', receipt.escalation_after_digest,
        'dead_workflow_job_ids', receipt.dead_workflow_job_ids,
        'superseded_at', asf_chrono_utc(receipt.superseded_at),
        'audit_event_id', receipt.audit_event_id,
        'receipt_id', receipt.id
    );

    RETURN EXISTS (
        SELECT 1
        FROM escalations AS escalation
        JOIN work_items AS work
          ON work.tenant_id = escalation.tenant_id
         AND work.id = escalation.work_item_id
        JOIN attempts AS attempt
          ON attempt.tenant_id = escalation.tenant_id
         AND attempt.id = receipt.attempt_id
         AND attempt.work_item_id = escalation.work_item_id
        JOIN idempotency_records AS idempotency
          ON idempotency.tenant_id = escalation.tenant_id
         AND idempotency.id = receipt.idempotency_record_id
        JOIN workflow_instances AS workflow
          ON workflow.tenant_id = escalation.tenant_id
         AND workflow.id = receipt.replacement_workflow_id
         AND workflow.work_item_id = escalation.work_item_id
        JOIN workflow_jobs AS job
          ON job.tenant_id = escalation.tenant_id
         AND job.id = receipt.replacement_job_id
         AND job.workflow_instance_id = workflow.id
         AND job.work_item_id = escalation.work_item_id
         AND job.attempt_id = receipt.attempt_id
        JOIN audit_events AS audit
          ON audit.tenant_id = escalation.tenant_id
         AND audit.id = receipt.audit_event_id
        JOIN outbox
          ON outbox.tenant_id = escalation.tenant_id
         AND outbox.id = receipt.outbox_event_id
        JOIN cancellation_supersession_escalation_facts AS escalation_fact
          ON escalation_fact.tenant_id = escalation.tenant_id
         AND escalation_fact.escalation_id = escalation.id
         AND escalation_fact.work_item_id = escalation.work_item_id
         AND escalation_fact.attempt_id = receipt.attempt_id
        JOIN cancellation_supersession_anchor_facts AS anchor_fact
          ON anchor_fact.tenant_id = escalation.tenant_id
         AND anchor_fact.escalation_id = escalation.id
         AND anchor_fact.work_item_id = escalation.work_item_id
        JOIN cancellation_supersession_work_facts AS work_fact
          ON work_fact.tenant_id = escalation.tenant_id
         AND work_fact.escalation_id = escalation.id
         AND work_fact.work_item_id = escalation.work_item_id
         AND work_fact.attempt_id = receipt.attempt_id
        WHERE escalation.tenant_id = receipt.tenant_id
          AND escalation.id = receipt.escalation_id
          AND escalation.work_item_id = receipt.work_item_id
          AND escalation.attempt_id = receipt.attempt_id
          AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
          AND escalation.status = 'CANCELLED'
          AND NOT escalation.authority_or_effect_active
          AND escalation.aggregate_version = receipt.escalation_version_after
          AND escalation.closed_at = receipt.superseded_at
          AND receipt.escalation_after_digest =
              asf_terminal_conflict_escalation_digest(
                  escalation.tenant_id, escalation.id
              )
          AND escalation_fact.status_before =
              receipt.escalation_status_before
          AND escalation_fact.version_before =
              receipt.escalation_version_before
          AND escalation_fact.version_after =
              receipt.escalation_version_after
          AND escalation_fact.before_digest =
              receipt.escalation_before_digest
          AND escalation_fact.after_digest = receipt.escalation_after_digest
          AND escalation_fact.superseded_at = receipt.superseded_at
          AND escalation_fact.fact_digest =
              asf_cancellation_supersession_escalation_fact_digest(
                  escalation_fact
              )
          AND anchor_fact.replacement_workflow_id =
              receipt.replacement_workflow_id
          AND anchor_fact.generation_before =
              receipt.anchor_generation_before
          AND anchor_fact.generation_after = receipt.anchor_generation_after
          AND anchor_fact.escalation_deadline = escalation.deadline
          AND anchor_fact.fact_digest =
              asf_cancellation_supersession_anchor_fact_digest(anchor_fact)
          AND work_fact.version_before = receipt.work_item_version_before
          AND work_fact.version_after = receipt.work_item_version_after
          AND work_fact.fact_digest =
              asf_cancellation_supersession_work_fact_digest(work_fact)
          AND receipt.superseded_at <= escalation_fact.recorded_at
          AND escalation_fact.recorded_at <= anchor_fact.transitioned_at
          AND anchor_fact.transitioned_at <= anchor_fact.recorded_at
          AND anchor_fact.recorded_at <= work_fact.transitioned_at
          AND work_fact.transitioned_at <= work_fact.recorded_at
          AND work_fact.recorded_at <= audit.occurred_at
          AND receipt.dead_workflow_job_ids = ARRAY(
              SELECT dead_job.id
              FROM workflow_jobs AS dead_job
              WHERE dead_job.tenant_id = escalation.tenant_id
                AND dead_job.work_item_id = escalation.work_item_id
                AND dead_job.attempt_id IS NOT DISTINCT FROM escalation.attempt_id
                AND dead_job.status = 'DEAD'
                AND dead_job.dead_letter_escalation_id = escalation.id
              ORDER BY dead_job.id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM unnest(receipt.dead_workflow_job_ids) AS retained(job_id)
              LEFT JOIN workflow_jobs AS dead_job
                ON dead_job.tenant_id = receipt.tenant_id
               AND dead_job.id = retained.job_id
               AND dead_job.work_item_id = receipt.work_item_id
               AND dead_job.attempt_id IS NOT DISTINCT FROM receipt.attempt_id
               AND dead_job.status = 'DEAD'
               AND dead_job.dead_letter_escalation_id = receipt.escalation_id
               AND dead_job.dead_lettered_at <= receipt.superseded_at
              WHERE dead_job.id IS NULL
                 OR NOT (
                     escalation.evidence_references @>
                     jsonb_build_array('workflow-job:' || retained.job_id::text)
                 )
          )
          AND idempotency.actor_id = receipt.actor_id
          AND idempotency.operation = 'api.work_item.cancel'
          AND idempotency.request_digest = receipt.request_digest
          AND idempotency.request_digest = asf_source_closure_digest(
              jsonb_build_object(
                  'work_item_id', receipt.work_item_id,
                  'expected_version', receipt.work_item_version_before,
                  'reason', replacement_reason
              )
          )
          AND idempotency.state = 'COMPLETED'
          AND idempotency.response_status = 202
          AND idempotency.response_body = jsonb_build_object(
              'idempotency_key', idempotency.idempotency_key,
              'resource_id', receipt.work_item_id::text,
              'status', 'cancellation_requested',
              'version', receipt.work_item_version_after
          )
          AND idempotency.created_at <= receipt.superseded_at
          AND idempotency.completed_at >= receipt.recorded_at
          AND workflow.workflow_type = 'WORK_ITEM_CANCELLATION'
          AND workflow.reducer_version = 'asf.workflow/v1'
          AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
          AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
          AND job.priority = work.normalized_priority
          AND job.max_attempts = 25
          AND job.created_at BETWEEN
              idempotency.created_at AND receipt.superseded_at
          AND jsonb_typeof(job.payload) = 'object'
          AND job.payload - ARRAY[
              'work_item_id', 'worker_id', 'expected_version',
              'reason', 'requested_by'
          ]::text[] = '{}'::jsonb
          AND job.payload ->> 'work_item_id' = receipt.work_item_id::text
          AND job.payload -> 'expected_version' =
              to_jsonb(receipt.work_item_version_after)
          AND jsonb_typeof(job.payload -> 'reason') = 'string'
          AND btrim(job.payload ->> 'reason') = job.payload ->> 'reason'
          AND btrim(job.payload ->> 'reason') <> ''
          AND job.payload ->> 'requested_by' = receipt.actor_id
          AND jsonb_typeof(job.payload -> 'worker_id') = 'string'
          AND job.idempotency_key = asf_api_job_idempotency_key(
              idempotency.tenant_id,
              idempotency.actor_id,
              idempotency.operation,
              idempotency.idempotency_key
          )
          AND audit.work_item_id = receipt.work_item_id
          AND audit.attempt_id = receipt.attempt_id
          AND audit.actor_type = 'API_CALLER'
          AND audit.actor_id = receipt.actor_id
          AND audit.action =
              'WORKFLOW_JOB_EXHAUSTION_SUPERSEDED_BY_CANCELLATION'
          AND audit.subject_type = 'ESCALATION'
          AND audit.subject_id = receipt.escalation_id::text
          AND audit.correlation_id = receipt.idempotency_record_id::text
          AND audit.trace_id IS NULL
          AND audit.policy_digest = work.policy_digest
          AND audit.before_digest = receipt.escalation_before_digest
          AND audit.after_digest = receipt.escalation_after_digest
          AND audit.details = expected_audit_details
          AND audit.occurred_at BETWEEN
              receipt.superseded_at AND receipt.recorded_at
          AND audit.event_hash = asf_recomputed_audit_event_hash(
              audit.tenant_id, audit.id
          )
          AND outbox.topic = 'attention'
          AND outbox.message_key = receipt.escalation_id::text
          AND outbox.event_type =
              'workflow_job_exhaustion.superseded_by_cancellation'
          AND outbox.payload = expected_outbox_payload
          AND outbox.headers =
              '{"schema":"asf.cancellation-escalation-supersession-event/v1"}'::jsonb
          AND outbox.idempotency_key =
              'api-cancellation-escalation-supersession:' ||
              receipt.idempotency_record_id::text || ':outbox'
          AND outbox.created_at BETWEEN
              audit.occurred_at AND receipt.recorded_at
          AND receipt.receipt_digest =
              asf_cancellation_escalation_supersession_receipt_digest(receipt)
          AND (
              NOT require_fresh
              OR (
                  work.state = 'CANCEL_REQUESTED'
                  AND work.aggregate_version = receipt.work_item_version_after
                  AND work.current_attempt_id = receipt.attempt_id
                  AND workflow.state IN ('ACTIVE', 'WAITING')
                  AND workflow.terminal_at IS NULL
                  AND job.status = 'PENDING'
                  AND job.available_at BETWEEN
                      idempotency.created_at AND job.created_at
                  AND job.attempt_count = 0
                  AND job.fence_token = 0
                  AND job.result IS NULL
                  AND job.lease_owner IS NULL
                  AND job.lease_expires_at IS NULL
                  AND job.completed_by IS NULL
                  AND job.completion_fence_token IS NULL
                  AND job.completed_at IS NULL
                  AND job.last_failure_by IS NULL
                  AND job.last_failure_fence_token IS NULL
                  AND job.last_failure_retry_at IS NULL
                  AND job.last_error IS NULL
                  AND job.dead_letter_escalation_id IS NULL
                  AND job.dead_letter_operational_incident_id IS NULL
                  AND job.dead_lettered_at IS NULL
                  AND outbox.status = 'PENDING'
                  AND outbox.available_at = receipt.superseded_at
                  AND outbox.attempt_count = 0
                  AND outbox.fence_token = 0
                  AND outbox.lease_owner IS NULL
                  AND outbox.lease_expires_at IS NULL
                  AND outbox.last_error IS NULL
                  AND outbox.published_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM escalations AS other_escalation
                      WHERE other_escalation.tenant_id = receipt.tenant_id
                        AND other_escalation.work_item_id = receipt.work_item_id
                        AND other_escalation.id <> receipt.escalation_id
                        AND other_escalation.status IN ('OPEN', 'ACKNOWLEDGED')
                        AND other_escalation.authority_or_effect_active
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM accountability_anchors AS anchor
                      WHERE anchor.tenant_id = receipt.tenant_id
                        AND anchor.work_item_id = receipt.work_item_id
                        AND anchor.anchor_type = 'WORKFLOW'
                        AND anchor.reference_id = receipt.replacement_workflow_id
                        AND anchor.wake_or_deadline_at IS NULL
                        AND NOT anchor.authority_or_effect_active
                        AND anchor.generation = receipt.anchor_generation_after
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM runs AS run
                      WHERE run.tenant_id = receipt.tenant_id
                        AND run.work_item_id = receipt.work_item_id
                        AND run.attempt_id = receipt.attempt_id
                        AND run.authoritative
                        AND run.state IN (
                            'ADOPTED', 'RUNNING', 'WAITING_APPROVAL',
                            'VERIFYING', 'CANCEL_REQUESTED'
                        )
                        AND run.worker_id::text = job.payload ->> 'worker_id'
                  )
              )
          )
    );
END;
$$;

COMMENT ON FUNCTION asf_valid_cancellation_supersession_receipt_v18(uuid, uuid, boolean) IS
    'Requires the exact asf.activity/request-work-item-cancellation/v1 contract identity on the replacement REQUEST_WORK_ITEM_CANCELLATION job backing the cancellation escalation supersession receipt; every other existing receipt proof field is preserved unchanged.';

-- Additional authority-proof families are appended by subsequent implementation passes.
