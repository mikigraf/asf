-- Linear source closure is an externally mutating, evidence-authorized effect.
-- Bind the immutable request to its exact source snapshot and evidence bundle,
-- require the exact live CLOSE_SOURCE job while it is in flight, and make an
-- observed matching receipt a database prerequisite for CLOSED work.
--
-- Apply with executors quiesced.  Jobs are locked before aggregates/effects to
-- preserve the runtime's global recovery lock order.
LOCK TABLE workflow_jobs IN EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE source_snapshots IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN ACCESS EXCLUSIVE MODE;

-- The migration is the sole writer under the table lock.  Temporarily remove
-- the terminal/identity guard so it can populate newly introduced immutable
-- authority columns on existing receipts, then reinstall the expanded guard.
DROP TRIGGER effect_intents_identity_request_immutable ON effect_intents;

ALTER TABLE effect_intents
    ADD COLUMN source_snapshot_id uuid,
    ADD COLUMN source_revision text,
    ADD COLUMN source_snapshot_digest text,
    ADD COLUMN evidence_id uuid,
    ADD COLUMN evidence_digest text;

-- No released ASF runtime has emitted Linear close intents.  If a development
-- writer did, accept only the exact immutable coordinates already encoded in
-- its request.  Missing or contradictory bindings deliberately make the later
-- shape/foreign-key constraints fail instead of guessing authority.
UPDATE effect_intents AS effect
SET source_snapshot_id = snapshot.id,
    source_revision = snapshot.source_revision,
    source_snapshot_digest = snapshot.content_digest,
    evidence_id = evidence.id,
    evidence_digest = evidence.payload_digest
FROM work_items AS work
JOIN source_snapshots AS snapshot
  ON snapshot.tenant_id = work.tenant_id
 AND snapshot.id = work.source_snapshot_id
JOIN evidence_bundles AS evidence
  ON evidence.tenant_id = work.tenant_id
 AND evidence.work_item_id = work.id
WHERE effect.tenant_id = work.tenant_id
  AND effect.work_item_id = work.id
  AND evidence.attempt_id = effect.attempt_id
  AND effect.provider = 'linear'
  AND effect.effect_type = 'close_source'
  AND effect.request_payload #>> '{effect,expected_source_revision}' = snapshot.source_revision
  AND effect.request_payload #>> '{effect,expected_snapshot_digest}' = snapshot.content_digest
  AND effect.request_payload #>> '{effect,closure,evidence_id}' = evidence.id::text
  AND effect.request_payload #>> '{effect,closure,evidence_digest}' = evidence.payload_digest;

-- A legacy in-flight close may already have changed Linear.  Preserve the
-- exact request and force provider reconciliation; never transfer ownership by
-- inferring from non-unique owner text and fence values.
UPDATE effect_intents
SET status = 'AMBIGUOUS',
    owning_workflow_job_id = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error = left(
        concat_ws(
            '; ',
            NULLIF(last_error, ''),
            'migration bound source closure authority; reconcile the unchanged request'
        ),
        8192
    ),
    updated_at = clock_timestamp()
WHERE provider = 'linear'
  AND effect_type = 'close_source'
  AND status = 'IN_FLIGHT';

ALTER TABLE source_snapshots
    ADD CONSTRAINT source_snapshots_closure_binding_key
    UNIQUE (tenant_id, id, source_revision, content_digest);

ALTER TABLE evidence_bundles
    ADD CONSTRAINT evidence_bundles_closure_binding_key
    UNIQUE (tenant_id, id, payload_digest, work_item_id, attempt_id);

ALTER TABLE effect_intents
    ADD CONSTRAINT effect_intents_linear_closure_binding_shape CHECK (
        (
            provider = 'linear'
            AND effect_type = 'close_source'
            AND work_item_id IS NOT NULL
            AND attempt_id IS NOT NULL
            AND source_snapshot_id IS NOT NULL
            AND source_revision IS NOT NULL
            AND btrim(source_revision) <> ''
            AND source_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
            AND evidence_id IS NOT NULL
            AND evidence_digest ~ '^sha256:[0-9a-f]{64}$'
            AND (
                status <> 'OBSERVED'
                OR (observed_outcome IS NOT NULL AND observed_at IS NOT NULL)
            )
        )
        OR (
            (provider <> 'linear' OR effect_type <> 'close_source')
            AND source_snapshot_id IS NULL
            AND source_revision IS NULL
            AND source_snapshot_digest IS NULL
            AND evidence_id IS NULL
            AND evidence_digest IS NULL
        )
    ),
    ADD CONSTRAINT effect_intents_linear_closure_snapshot_fk
    FOREIGN KEY (
        tenant_id,
        source_snapshot_id,
        source_revision,
        source_snapshot_digest
    )
    REFERENCES source_snapshots (
        tenant_id,
        id,
        source_revision,
        content_digest
    )
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT effect_intents_linear_closure_evidence_fk
    FOREIGN KEY (
        tenant_id,
        evidence_id,
        evidence_digest,
        work_item_id,
        attempt_id
    )
    REFERENCES evidence_bundles (
        tenant_id,
        id,
        payload_digest,
        work_item_id,
        attempt_id
    )
    MATCH SIMPLE ON DELETE RESTRICT;

CREATE UNIQUE INDEX effect_intents_one_linear_closure_per_work_item_idx
    ON effect_intents (tenant_id, work_item_id)
    WHERE provider = 'linear'
      AND effect_type = 'close_source'
      AND work_item_id IS NOT NULL;

DROP TRIGGER effect_intents_exact_runmill_mutation_owner ON effect_intents;
DROP FUNCTION asf_guard_runmill_mutation_effect_owner();

ALTER TABLE effect_intents
    DROP CONSTRAINT effect_intents_runmill_mutation_owner_shape,
    ADD CONSTRAINT effect_intents_external_mutation_owner_shape CHECK (
        (
            (
                (provider = 'runmill' AND effect_type IN (
                    'request_cancellation',
                    'submit_work_order'
                ))
                OR (provider = 'linear' AND effect_type = 'close_source')
            )
            AND (
                (status = 'IN_FLIGHT' AND owning_workflow_job_id IS NOT NULL)
                OR (status <> 'IN_FLIGHT' AND owning_workflow_job_id IS NULL)
            )
        )
        OR (
            NOT (
                (provider = 'runmill' AND effect_type IN (
                    'request_cancellation',
                    'submit_work_order'
                ))
                OR (provider = 'linear' AND effect_type = 'close_source')
            )
            AND owning_workflow_job_id IS NULL
        )
    );

CREATE FUNCTION asf_guard_external_mutation_effect_owner() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    required_job_type text;
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

        IF NEW.owning_workflow_job_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM workflow_jobs AS owning_job
            WHERE owning_job.tenant_id = NEW.tenant_id
              AND owning_job.id = NEW.owning_workflow_job_id
              AND owning_job.workflow_instance_id IS NOT NULL
              AND owning_job.work_item_id = NEW.work_item_id
              AND owning_job.attempt_id = NEW.attempt_id
              AND owning_job.job_type = required_job_type
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

CREATE TRIGGER effect_intents_exact_external_mutation_owner
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_external_mutation_effect_owner();

-- The relational source/evidence coordinates are part of the immutable
-- request.  Recovery may change status and lease fields, never authority.
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
       OR NEW.work_order_id IS DISTINCT FROM OLD.work_order_id
       OR NEW.work_order_digest IS DISTINCT FROM OLD.work_order_digest
       OR NEW.source_snapshot_id IS DISTINCT FROM OLD.source_snapshot_id
       OR NEW.source_revision IS DISTINCT FROM OLD.source_revision
       OR NEW.source_snapshot_digest IS DISTINCT FROM OLD.source_snapshot_digest
       OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
       OR NEW.evidence_digest IS DISTINCT FROM OLD.evidence_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'effect intent identity and request are immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_identity_request_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_intents_identity_request_immutable
    BEFORE UPDATE OR DELETE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_effect_intent_update();

-- A CLOSED item must have one exact, terminal Linear receipt tied to the
-- current attempt, current immutable source snapshot, independently VALID
-- evidence, and the closure accountability anchor.
CREATE FUNCTION asf_observed_source_closure_is_valid(
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
        JOIN effect_intents AS effect
          ON effect.tenant_id = work.tenant_id
         AND effect.work_item_id = work.id
         AND effect.attempt_id = work.current_attempt_id
         AND effect.provider = 'linear'
         AND effect.effect_type = 'close_source'
         AND effect.status = 'OBSERVED'
         AND effect.source_snapshot_id = snapshot.id
         AND effect.source_revision = snapshot.source_revision
         AND effect.source_snapshot_digest = snapshot.content_digest
        JOIN evidence_bundles AS evidence
          ON evidence.tenant_id = effect.tenant_id
         AND evidence.id = effect.evidence_id
         AND evidence.payload_digest = effect.evidence_digest
         AND evidence.work_item_id = effect.work_item_id
         AND evidence.attempt_id = effect.attempt_id
        JOIN runs AS run
          ON run.tenant_id = evidence.tenant_id
         AND run.id = evidence.run_id
         AND run.work_item_id = evidence.work_item_id
         AND run.attempt_id = evidence.attempt_id
         AND run.authoritative
         AND run.state = 'SUCCEEDED'
        JOIN evidence_verifications AS verification
          ON verification.tenant_id = evidence.tenant_id
         AND verification.evidence_id = evidence.id
         AND verification.expectation_digest = run.evidence_expectation_digest
         AND verification.status = 'VALID'
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
          AND evidence.requested_target = work.closure_target
          AND evidence.target_satisfied
          AND effect.observed_at IS NOT NULL
          AND effect.request_payload ->> 'schema' = 'asf.close-source-request.v1'
          AND effect.request_payload ->> 'idempotency_key' = effect.idempotency_key
          AND effect.request_payload #>> '{effect,schema}' = 'asf.source-close-effect.v1'
          AND effect.request_payload #>> '{effect,item,tenant_id}' = work.tenant_id::text
          AND effect.request_payload #>> '{effect,item,source}' = 'linear'
          AND effect.request_payload #>> '{effect,item,external_id}' = work.source_external_id
          AND effect.request_payload #>> '{effect,expected_source_revision}' = snapshot.source_revision
          AND effect.request_payload #>> '{effect,expected_snapshot_digest}' = snapshot.content_digest
          AND effect.request_payload #>> '{effect,correlation_marker}' = effect.correlation_marker
          AND effect.request_payload #>> '{effect,closure,work_item_id}' = work.id::text
          AND effect.request_payload #>> '{effect,closure,target}' = 'pr'
         AND effect.request_payload #>> '{effect,closure,evidence_id}' = evidence.id::text
         AND effect.request_payload #>> '{effect,closure,evidence_digest}' = evidence.payload_digest
          AND verification.details ->> 'schema' =
              'asf.evidence-verification-receipt.v1'
          AND verification.details ->> 'evidence_id' = evidence.id::text
          AND verification.details ->> 'work_item_id' = work.id::text
          AND verification.details ->> 'attempt_id' = evidence.attempt_id::text
          AND verification.details ->> 'run_id' = evidence.run_id::text
          AND verification.details ->> 'evidence_digest' = evidence.payload_digest
          AND verification.details ->> 'work_order_digest' = evidence.work_order_digest
          AND verification.details ->> 'expectation_digest' =
              verification.expectation_digest
          AND verification.details ->> 'verifier' = verification.verifier
          AND btrim(verification.details ->> 'provider_revision') <> ''
          AND btrim(verification.details ->> 'observed_at') <> ''
          AND verification.details -> 'pull_request' =
              effect.request_payload #> '{effect,closure,pull_request}'
          AND effect.observed_outcome ->> 'schema' = 'asf.source-close-receipt.v1'
          AND effect.observed_outcome #>> '{item,tenant_id}' = work.tenant_id::text
          AND effect.observed_outcome #>> '{item,source}' = 'linear'
          AND effect.observed_outcome #>> '{item,external_id}' = work.source_external_id
          AND effect.observed_outcome ->> 'idempotency_key' = effect.idempotency_key
          AND effect.observed_outcome ->> 'effect_digest' =
              effect.request_payload ->> 'effect_digest'
          AND effect.observed_outcome ->> 'correlation_marker' = effect.correlation_marker
          AND effect.observed_outcome ->> 'disposition' IN (
              'applied',
              'adopted',
              'reconciled'
          )
          AND btrim(effect.observed_outcome ->> 'provider_revision') <> ''
    )
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.state = 'CLOSED'
          AND NOT asf_observed_source_closure_is_valid(work.tenant_id, work.id)
    ) THEN
        RAISE EXCEPTION 'existing CLOSED work lacks an exact observed source closure'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
END;
$$;

CREATE FUNCTION asf_assert_observed_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'CLOSED'
       AND NOT asf_observed_source_closure_is_valid(NEW.tenant_id, NEW.id) THEN
        RAISE EXCEPTION 'closed work item has no exact observed source closure'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER work_items_require_observed_source_closure
    AFTER INSERT OR UPDATE ON work_items
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_observed_source_closure();

-- The generic accountability invariant proves that a CLOSURE anchor names
-- independently valid evidence.  For a CLOSED source item the stronger fact
-- is also permanent: that exact evidence must remain the evidence adopted by
-- the observed Linear receipt.  Re-check both sides of an anchor rewrite so a
-- direct SQL writer cannot swap an already-closed item to a different valid
-- bundle and thereby sever the source-effect reconstruction chain.
CREATE FUNCTION asf_assert_anchor_preserves_observed_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' AND EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.tenant_id = OLD.tenant_id
          AND work.id = OLD.work_item_id
          AND work.state = 'CLOSED'
          AND NOT asf_observed_source_closure_is_valid(work.tenant_id, work.id)
    ) THEN
        RAISE EXCEPTION 'accountability mutation would sever an observed source closure'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;

    IF TG_OP <> 'DELETE' AND EXISTS (
        SELECT 1
        FROM work_items AS work
        WHERE work.tenant_id = NEW.tenant_id
          AND work.id = NEW.work_item_id
          AND work.state = 'CLOSED'
          AND NOT asf_observed_source_closure_is_valid(work.tenant_id, work.id)
    ) THEN
        RAISE EXCEPTION 'accountability mutation would sever an observed source closure'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER accountability_preserves_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON accountability_anchors
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_anchor_preserves_observed_source_closure();
