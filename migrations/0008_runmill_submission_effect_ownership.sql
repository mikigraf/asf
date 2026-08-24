-- A Runmill submission is an externally mutating effect.  Before a production
-- dispatcher can be enabled it needs the same exact workflow-job ownership
-- proof as cancellation, plus a relational binding to the immutable Work
-- Order it submits.  Apply with executors quiesced so the table locks preserve
-- the global job -> aggregate/effect lock order used by the reactor.
LOCK TABLE workflow_jobs IN EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN ACCESS EXCLUSIVE MODE;

-- Migration-owned backfills must be able to add new immutable authority
-- columns to terminal receipts.  The table lock excludes runtime writers;
-- reinstall the expanded guard after every backfill and validation below.
DROP TRIGGER effect_intents_identity_request_immutable ON effect_intents;

ALTER TABLE effect_intents
    ADD COLUMN work_order_id uuid,
    ADD COLUMN work_order_digest text,
    -- These generated coordinates make the live job claim itself a foreign-key
    -- target.  A job cannot retire, change owner, or change fence while an
    -- external mutation still cites that exact RUNNING claim.
    ADD COLUMN owning_workflow_job_type text GENERATED ALWAYS AS (
        CASE
            WHEN provider = 'runmill' AND effect_type = 'request_cancellation'
                THEN 'REQUEST_WORK_ITEM_CANCELLATION'
            WHEN provider = 'runmill' AND effect_type = 'submit_work_order'
                THEN 'ADVANCE_ACCEPTED_WORK_ITEM'
            WHEN provider = 'linear' AND effect_type = 'close_source'
                THEN 'CLOSE_SOURCE'
            ELSE NULL
        END
    ) STORED,
    ADD COLUMN owning_workflow_job_status text GENERATED ALWAYS AS (
        CASE WHEN owning_workflow_job_id IS NOT NULL THEN 'RUNNING' ELSE NULL END
    ) STORED;

-- No released ASF runtime has emitted Runmill submission intents.  If an
-- operator or development build created one, adopt its unique attempt-bound
-- Work Order rather than guessing from JSON.  A row without that authoritative
-- binding makes the migration fail closed when the shape constraint is added.
UPDATE effect_intents AS effect
SET work_order_id = work_order.id,
    work_order_digest = work_order.payload_digest
FROM work_orders AS work_order
WHERE effect.provider = 'runmill'
  AND effect.effect_type = 'submit_work_order'
  AND work_order.tenant_id = effect.tenant_id
  AND work_order.work_item_id = effect.work_item_id
  AND work_order.attempt_id = effect.attempt_id;

-- A legacy in-flight submission may already have reached Runmill.  Preserve
-- its immutable request but require read-side reconciliation; never let a new
-- workflow-job lease silently adopt the uncertain mutation.
UPDATE effect_intents
SET status = 'AMBIGUOUS',
    lease_owner = NULL,
    lease_expires_at = NULL,
    owning_workflow_job_id = NULL,
    last_error = left(
        concat_ws(
            '; ',
            NULLIF(last_error, ''),
            'migration bound the immutable Work Order; reconcile the unchanged submission request'
        ),
        8192
    ),
    updated_at = clock_timestamp()
WHERE provider = 'runmill'
  AND effect_type = 'submit_work_order'
  AND status = 'IN_FLIGHT';

-- The reciprocal claim foreign key introduced below cannot bless an already
-- stale cancellation owner.  Preserve its request and normalize the lost
-- claim into explicit ambiguity before installing that invariant.
UPDATE effect_intents AS effect
SET status = 'AMBIGUOUS',
    lease_owner = NULL,
    lease_expires_at = NULL,
    owning_workflow_job_id = NULL,
    last_error = left(
        concat_ws(
            '; ',
            NULLIF(effect.last_error, ''),
            'migration found an expired cancellation owner; exact reconciliation required'
        ),
        8192
    ),
    updated_at = clock_timestamp()
WHERE effect.provider = 'runmill'
  AND effect.effect_type = 'request_cancellation'
  AND effect.status = 'IN_FLIGHT'
  AND NOT EXISTS (
      SELECT 1
      FROM workflow_jobs AS owning_job
      WHERE owning_job.tenant_id = effect.tenant_id
        AND owning_job.id = effect.owning_workflow_job_id
        AND owning_job.workflow_instance_id IS NOT NULL
        AND owning_job.work_item_id = effect.work_item_id
        AND owning_job.attempt_id = effect.attempt_id
        AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
        AND owning_job.status = 'RUNNING'
        AND owning_job.lease_owner = effect.lease_owner
        AND owning_job.fence_token = effect.fence_token
        AND owning_job.lease_expires_at > clock_timestamp()
  );

ALTER TABLE work_orders
    ADD CONSTRAINT work_orders_submission_binding_key
    UNIQUE (tenant_id, id, payload_digest, work_item_id, attempt_id);

ALTER TABLE workflow_jobs
    ADD CONSTRAINT workflow_jobs_external_effect_owner_key
    UNIQUE (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        job_type,
        status,
        lease_owner,
        fence_token
    );

ALTER TABLE effect_intents
    ADD CONSTRAINT effect_intents_submission_binding_shape CHECK (
        (
            provider = 'runmill'
            AND effect_type = 'submit_work_order'
            AND work_item_id IS NOT NULL
            AND attempt_id IS NOT NULL
            AND work_order_id IS NOT NULL
            AND work_order_digest IS NOT NULL
            AND work_order_digest ~ '^sha256:[0-9a-f]{64}$'
        )
        OR (
            (provider <> 'runmill' OR effect_type <> 'submit_work_order')
            AND work_order_id IS NULL
            AND work_order_digest IS NULL
        )
    ),
    ADD CONSTRAINT effect_intents_submission_work_order_fk
    FOREIGN KEY (
        tenant_id,
        work_order_id,
        work_order_digest,
        work_item_id,
        attempt_id
    )
    REFERENCES work_orders (
        tenant_id,
        id,
        payload_digest,
        work_item_id,
        attempt_id
    )
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT effect_intents_exact_workflow_job_claim_fk
    FOREIGN KEY (
        tenant_id,
        owning_workflow_job_id,
        work_item_id,
        attempt_id,
        owning_workflow_job_type,
        owning_workflow_job_status,
        lease_owner,
        fence_token
    )
    REFERENCES workflow_jobs (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        job_type,
        status,
        lease_owner,
        fence_token
    )
    MATCH SIMPLE ON DELETE RESTRICT;

-- The immutable effect request is the exact signed envelope bytes stored on
-- the bound Work Order.  A future dispatcher must load those bytes from the
-- Work Order row; it cannot claim authority from A while submitting B.
CREATE FUNCTION asf_guard_runmill_submission_request_binding() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    exact_envelope bytea;
    stored_payload jsonb;
    parsed_envelope jsonb;
BEGIN
    IF NEW.provider = 'runmill' AND NEW.effect_type = 'submit_work_order' THEN
        -- The separate immutable-identity trigger owns diagnostics for attempts
        -- to rewrite an established request/binding.  This trigger validates
        -- creation and every status-only transition of the unchanged request.
        IF TG_OP = 'UPDATE'
           AND (
               NEW.request_payload IS DISTINCT FROM OLD.request_payload
               OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
               OR NEW.work_order_id IS DISTINCT FROM OLD.work_order_id
               OR NEW.work_order_digest IS DISTINCT FROM OLD.work_order_digest
           ) THEN
            RETURN NEW;
        END IF;

        -- Let the declarative shape/foreign-key constraints report absent
        -- coordinates; this trigger proves the exact relationship once present.
        IF NEW.work_order_id IS NULL
           OR NEW.work_order_digest IS NULL
           OR NEW.work_item_id IS NULL
           OR NEW.attempt_id IS NULL THEN
            RETURN NEW;
        END IF;

        SELECT work_order.exact_signed_envelope, work_order.payload
        INTO exact_envelope, stored_payload
        FROM work_orders AS work_order
        WHERE work_order.tenant_id = NEW.tenant_id
          AND work_order.id = NEW.work_order_id
          AND work_order.payload_digest = NEW.work_order_digest
          AND work_order.work_item_id = NEW.work_item_id
          AND work_order.attempt_id = NEW.attempt_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Runmill submission has no exact immutable Work Order'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_submission_request';
        END IF;

        BEGIN
            parsed_envelope := convert_from(exact_envelope, 'UTF8')::jsonb;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'bound Runmill Work Order envelope is not exact UTF-8 JSON'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_submission_request';
        END;

        IF NEW.request_payload IS DISTINCT FROM parsed_envelope
           OR NEW.request_digest IS DISTINCT FROM
                'sha256:' || encode(sha256(exact_envelope), 'hex')
           OR parsed_envelope -> 'payload' IS DISTINCT FROM stored_payload
           OR parsed_envelope #>> '{payload,work_order_id}' IS DISTINCT FROM NEW.work_order_id::text
           OR parsed_envelope #>> '{payload,tenant_id}' IS DISTINCT FROM NEW.tenant_id::text
           OR parsed_envelope #>> '{payload,work_item_id}' IS DISTINCT FROM NEW.work_item_id::text
           OR parsed_envelope #>> '{payload,attempt_id}' IS DISTINCT FROM NEW.attempt_id::text THEN
            RAISE EXCEPTION 'Runmill submission request contradicts its immutable Work Order'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_submission_request';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_intents_exact_submission_request
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_submission_request_binding();

-- Triggers do not retroactively validate rows populated above.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM effect_intents AS effect
        JOIN work_orders AS work_order
          ON work_order.tenant_id = effect.tenant_id
         AND work_order.id = effect.work_order_id
         AND work_order.payload_digest = effect.work_order_digest
         AND work_order.work_item_id = effect.work_item_id
         AND work_order.attempt_id = effect.attempt_id
        WHERE effect.provider = 'runmill'
          AND effect.effect_type = 'submit_work_order'
          AND (
              effect.request_payload IS DISTINCT FROM
                  convert_from(work_order.exact_signed_envelope, 'UTF8')::jsonb
              OR effect.request_digest IS DISTINCT FROM
                  'sha256:' || encode(sha256(work_order.exact_signed_envelope), 'hex')
              OR effect.request_payload -> 'payload' IS DISTINCT FROM work_order.payload
              OR effect.request_payload #>> '{payload,work_order_id}'
                    IS DISTINCT FROM work_order.id::text
              OR effect.request_payload #>> '{payload,tenant_id}'
                    IS DISTINCT FROM effect.tenant_id::text
              OR effect.request_payload #>> '{payload,work_item_id}'
                    IS DISTINCT FROM effect.work_item_id::text
              OR effect.request_payload #>> '{payload,attempt_id}'
                    IS DISTINCT FROM effect.attempt_id::text
          )
    ) THEN
        RAISE EXCEPTION 'legacy Runmill submission contradicts its immutable Work Order'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_exact_submission_request';
    END IF;
END;
$$;

CREATE UNIQUE INDEX effect_intents_one_runmill_submission_per_attempt_idx
    ON effect_intents (tenant_id, work_item_id, attempt_id)
    WHERE provider = 'runmill'
      AND effect_type = 'submit_work_order'
      AND work_item_id IS NOT NULL
      AND attempt_id IS NOT NULL;

DROP TRIGGER effect_intents_exact_cancellation_owner ON effect_intents;
DROP FUNCTION asf_guard_cancellation_effect_owner();

ALTER TABLE effect_intents
    DROP CONSTRAINT effect_intents_cancellation_owner_shape,
    ADD CONSTRAINT effect_intents_runmill_mutation_owner_shape CHECK (
        (
            provider = 'runmill'
            AND effect_type IN ('request_cancellation', 'submit_work_order')
            AND (
                (
                    status = 'IN_FLIGHT'
                    AND owning_workflow_job_id IS NOT NULL
                )
                OR (
                    status <> 'IN_FLIGHT'
                    AND owning_workflow_job_id IS NULL
                )
            )
        )
        OR (
            (
                provider <> 'runmill'
                OR effect_type NOT IN ('request_cancellation', 'submit_work_order')
            )
            AND owning_workflow_job_id IS NULL
        )
    );

CREATE FUNCTION asf_guard_runmill_mutation_effect_owner() RETURNS trigger
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

    -- Runmill exposes no exact lookup for a lost Work Order submission.  Once
    -- ambiguous, this mutation may only remain ambiguous or be closed by an
    -- independently observed terminal receipt; it may never be blindly sent.
    IF TG_OP = 'UPDATE'
       AND OLD.provider = 'runmill'
       AND OLD.effect_type = 'submit_work_order'
       AND OLD.status = 'AMBIGUOUS'
       AND NEW.status NOT IN ('AMBIGUOUS', 'OBSERVED', 'CANCELLED') THEN
        RAISE EXCEPTION 'ambiguous Runmill submission requires exact reconciliation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_ambiguous_submission_reconciliation_gate';
    END IF;

    IF NEW.provider = 'runmill'
       AND NEW.effect_type IN ('request_cancellation', 'submit_work_order')
       AND NEW.status = 'IN_FLIGHT' THEN
        required_job_type := CASE NEW.effect_type
            WHEN 'request_cancellation' THEN 'REQUEST_WORK_ITEM_CANCELLATION'
            WHEN 'submit_work_order' THEN 'ADVANCE_ACCEPTED_WORK_ITEM'
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
            RAISE EXCEPTION 'Runmill mutation effect has no exact live owning workflow job'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_external_mutation_owner';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_intents_exact_runmill_mutation_owner
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_mutation_effect_owner();

-- The relational Work Order binding is part of the immutable request
-- identity.  Status/lease recovery may change, but authority may not.
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
