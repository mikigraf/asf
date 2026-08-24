-- An explicit operator cancellation may recover an ESCALATED work item whose
-- current attempt is owned by an exhausted cancellation observer.  Replacing
-- the accountability anchor without closing that exact escalation would leave
-- two contradictory active obligations.  Preserve the immutable DEAD jobs and
-- their evidence, but terminalize the attention owner under an append-only,
-- API-bound supersession receipt.
--
-- Apply with executors quiesced. Keep the established job-first deployment
-- lock order while excluding every parent writer used by the new proof.
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_cancellation_authority_guards IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE outbox IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE idempotency_records IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE accountability_anchors IN SHARE ROW EXCLUSIVE MODE;

-- The former API path could replace accountability while leaving active
-- escalation authority behind. That OLD transition is unrecoverable after
-- the fact, so refuse an upgrade rather than fabricate a supersession receipt.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM work_items AS work
        JOIN escalations AS escalation
          ON escalation.tenant_id = work.tenant_id
         AND escalation.work_item_id = work.id
        WHERE work.state = 'CANCEL_REQUESTED'
          AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
          AND escalation.authority_or_effect_active
    ) THEN
        RAISE EXCEPTION
            'historical cancellation request retains live escalation authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_upgrade_requires_clean_authority';
    END IF;
END;
$$;

CREATE TABLE cancellation_escalation_supersession_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    idempotency_record_id uuid NOT NULL,
    actor_id text NOT NULL,
    request_digest text NOT NULL CHECK (
        request_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    replacement_workflow_id uuid NOT NULL,
    replacement_job_id uuid NOT NULL,
    work_item_version_before bigint NOT NULL CHECK (
        work_item_version_before > 0
    ),
    work_item_version_after bigint NOT NULL CHECK (
        work_item_version_after > 1
    ),
    anchor_generation_before bigint NOT NULL CHECK (
        anchor_generation_before > 0
    ),
    anchor_generation_after bigint NOT NULL CHECK (
        anchor_generation_after > 1
    ),
    cancellation_authority_generation bigint NOT NULL CHECK (
        cancellation_authority_generation > 0
    ),
    escalation_status_before text NOT NULL CHECK (
        escalation_status_before IN ('OPEN', 'ACKNOWLEDGED')
    ),
    escalation_version_before bigint NOT NULL CHECK (
        escalation_version_before > 0
    ),
    escalation_version_after bigint NOT NULL CHECK (
        escalation_version_after > 1
    ),
    escalation_before_digest text NOT NULL CHECK (
        escalation_before_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    escalation_after_digest text NOT NULL CHECK (
        escalation_after_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    dead_workflow_job_ids uuid[] NOT NULL CHECK (
        cardinality(dead_workflow_job_ids) > 0
        AND array_position(dead_workflow_job_ids, NULL) IS NULL
        AND NOT (
            '00000000-0000-0000-0000-000000000000'::uuid =
            ANY(dead_workflow_job_ids)
        )
    ),
    audit_event_id uuid NOT NULL,
    outbox_event_id uuid NOT NULL,
    superseded_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    receipt_digest text NOT NULL CHECK (
        receipt_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, escalation_id),
    UNIQUE (tenant_id, idempotency_record_id),
    UNIQUE (tenant_id, replacement_job_id),
    UNIQUE (tenant_id, audit_event_id),
    UNIQUE (tenant_id, outbox_event_id),
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
        REFERENCES attempts(tenant_id, id, work_item_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, escalation_id, work_item_id)
        REFERENCES escalations(tenant_id, id, work_item_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, idempotency_record_id)
        REFERENCES idempotency_records(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, replacement_workflow_id, work_item_id)
        REFERENCES workflow_instances(tenant_id, id, work_item_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, replacement_job_id)
        REFERENCES workflow_jobs(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, audit_event_id)
        REFERENCES audit_events(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, outbox_event_id)
        REFERENCES outbox(tenant_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (btrim(actor_id) <> ''),
    CHECK (work_item_version_after = work_item_version_before + 1),
    CHECK (anchor_generation_after = anchor_generation_before + 1),
    CHECK (escalation_version_after = escalation_version_before + 1),
    CHECK (superseded_at <= recorded_at),
    CHECK (escalation_before_digest <> escalation_after_digest),
    CHECK (id = asf_derived_uuid(idempotency_record_id, 3)),
    CHECK (outbox_event_id = asf_derived_uuid(idempotency_record_id, 4))
);

-- The public receipt may only cite OLD values captured by the three aggregate
-- UPDATE triggers below.  These facts are inserted while those triggers still
-- have OLD and NEW, are append-only, and have deferred reciprocal FKs back to
-- the one supersession receipt they authenticate.
CREATE TABLE cancellation_supersession_escalation_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    status_before text NOT NULL CHECK (
        status_before IN ('OPEN', 'ACKNOWLEDGED')
    ),
    version_before bigint NOT NULL CHECK (version_before > 0),
    version_after bigint NOT NULL CHECK (version_after > 1),
    before_digest text NOT NULL CHECK (
        before_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    after_digest text NOT NULL CHECK (
        after_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    superseded_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    fact_digest text NOT NULL CHECK (
        fact_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    UNIQUE (tenant_id, escalation_id),
    FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES cancellation_escalation_supersession_receipts(
            tenant_id, escalation_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (version_after = version_before + 1),
    CHECK (superseded_at <= recorded_at),
    CHECK (before_digest <> after_digest),
    CHECK (
        id = asf_stable_cancellation_receipt_uuid(
            'asf.cancellation-supersession-escalation-fact/v1',
            escalation_id,
            version_after
        )
    )
);

CREATE TABLE cancellation_supersession_anchor_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    replacement_workflow_id uuid NOT NULL,
    generation_before bigint NOT NULL CHECK (generation_before > 0),
    generation_after bigint NOT NULL CHECK (generation_after > 1),
    escalation_deadline timestamptz NOT NULL,
    before_digest text NOT NULL CHECK (
        before_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    after_digest text NOT NULL CHECK (
        after_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    transitioned_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    fact_digest text NOT NULL CHECK (
        fact_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    UNIQUE (tenant_id, escalation_id),
    FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES cancellation_escalation_supersession_receipts(
            tenant_id, escalation_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, replacement_workflow_id, work_item_id)
        REFERENCES workflow_instances(tenant_id, id, work_item_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (generation_after = generation_before + 1),
    CHECK (transitioned_at <= recorded_at),
    CHECK (before_digest <> after_digest),
    CHECK (
        id = asf_stable_cancellation_receipt_uuid(
            'asf.cancellation-supersession-anchor-fact/v1',
            escalation_id,
            generation_after
        )
    )
);

CREATE TABLE cancellation_supersession_work_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    escalation_id uuid NOT NULL,
    version_before bigint NOT NULL CHECK (version_before > 0),
    version_after bigint NOT NULL CHECK (version_after > 1),
    before_digest text NOT NULL CHECK (
        before_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    after_digest text NOT NULL CHECK (
        after_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    transitioned_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    fact_digest text NOT NULL CHECK (
        fact_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    UNIQUE (tenant_id, escalation_id),
    FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES cancellation_escalation_supersession_receipts(
            tenant_id, escalation_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (version_after = version_before + 1),
    CHECK (transitioned_at <= recorded_at),
    CHECK (before_digest <> after_digest),
    CHECK (
        id = asf_stable_cancellation_receipt_uuid(
            'asf.cancellation-supersession-work-fact/v1',
            escalation_id,
            version_after
        )
    )
);

CREATE FUNCTION asf_cancellation_supersession_anchor_row_digest(
    candidate accountability_anchors
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-supersession-anchor-state/v1',
        'tenant_id', candidate.tenant_id,
        'work_item_id', candidate.work_item_id,
        'anchor_type', candidate.anchor_type,
        'reference_id', candidate.reference_id,
        'wake_or_deadline_at', CASE
            WHEN candidate.wake_or_deadline_at IS NULL THEN NULL
            ELSE asf_chrono_utc(candidate.wake_or_deadline_at)
        END,
        'authority_or_effect_active', candidate.authority_or_effect_active,
        'generation', candidate.generation,
        'updated_at', asf_chrono_utc(candidate.updated_at)
    ));
$$;

CREATE FUNCTION asf_cancellation_supersession_work_row_digest(
    candidate work_items
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-supersession-work-state/v1',
        'id', candidate.id,
        'tenant_id', candidate.tenant_id,
        'source_snapshot_id', candidate.source_snapshot_id,
        'source_system', candidate.source_system,
        'source_external_id', candidate.source_external_id,
        'repository_id', candidate.repository_id,
        'state', candidate.state,
        'closure_target', candidate.closure_target,
        'risk_class', candidate.risk_class,
        'risk_assessment', candidate.risk_assessment,
        'policy_digest', candidate.policy_digest,
        'budget_limits', candidate.budget_limits,
        'identity_requirements', candidate.identity_requirements,
        'owner_fallback', candidate.owner_fallback,
        'normalized_priority', candidate.normalized_priority,
        'due_at', CASE WHEN candidate.due_at IS NULL THEN NULL
            ELSE asf_chrono_utc(candidate.due_at) END,
        'current_attempt_id', candidate.current_attempt_id,
        'aggregate_version', candidate.aggregate_version,
        'discovered_at', asf_chrono_utc(candidate.discovered_at),
        'ready_at', CASE WHEN candidate.ready_at IS NULL THEN NULL
            ELSE asf_chrono_utc(candidate.ready_at) END,
        'accepted_at', CASE WHEN candidate.accepted_at IS NULL THEN NULL
            ELSE asf_chrono_utc(candidate.accepted_at) END,
        'closed_at', CASE WHEN candidate.closed_at IS NULL THEN NULL
            ELSE asf_chrono_utc(candidate.closed_at) END,
        'updated_at', asf_chrono_utc(candidate.updated_at)
    ));
$$;

CREATE FUNCTION asf_cancellation_supersession_escalation_fact_digest(
    candidate cancellation_supersession_escalation_facts
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-supersession-escalation-fact/v1',
        'id', candidate.id,
        'tenant_id', candidate.tenant_id,
        'work_item_id', candidate.work_item_id,
        'attempt_id', candidate.attempt_id,
        'escalation_id', candidate.escalation_id,
        'status_before', candidate.status_before,
        'version_before', candidate.version_before,
        'version_after', candidate.version_after,
        'before_digest', candidate.before_digest,
        'after_digest', candidate.after_digest,
        'superseded_at', asf_chrono_utc(candidate.superseded_at),
        'recorded_at', asf_chrono_utc(candidate.recorded_at)
    ));
$$;

CREATE FUNCTION asf_cancellation_supersession_anchor_fact_digest(
    candidate cancellation_supersession_anchor_facts
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-supersession-anchor-fact/v1',
        'id', candidate.id,
        'tenant_id', candidate.tenant_id,
        'work_item_id', candidate.work_item_id,
        'escalation_id', candidate.escalation_id,
        'replacement_workflow_id', candidate.replacement_workflow_id,
        'generation_before', candidate.generation_before,
        'generation_after', candidate.generation_after,
        'escalation_deadline', asf_chrono_utc(candidate.escalation_deadline),
        'before_digest', candidate.before_digest,
        'after_digest', candidate.after_digest,
        'transitioned_at', asf_chrono_utc(candidate.transitioned_at),
        'recorded_at', asf_chrono_utc(candidate.recorded_at)
    ));
$$;

CREATE FUNCTION asf_cancellation_supersession_work_fact_digest(
    candidate cancellation_supersession_work_facts
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-supersession-work-fact/v1',
        'id', candidate.id,
        'tenant_id', candidate.tenant_id,
        'work_item_id', candidate.work_item_id,
        'attempt_id', candidate.attempt_id,
        'escalation_id', candidate.escalation_id,
        'version_before', candidate.version_before,
        'version_after', candidate.version_after,
        'before_digest', candidate.before_digest,
        'after_digest', candidate.after_digest,
        'transitioned_at', asf_chrono_utc(candidate.transitioned_at),
        'recorded_at', asf_chrono_utc(candidate.recorded_at)
    ));
$$;

CREATE FUNCTION asf_stamp_cancellation_supersession_escalation_fact()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'cancellation supersession escalation facts are trigger-generated'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'cancellation_supersession_escalation_facts_generated_only';
    END IF;
    NEW.id := asf_stable_cancellation_receipt_uuid(
        'asf.cancellation-supersession-escalation-fact/v1',
        NEW.escalation_id, NEW.version_after
    );
    NEW.recorded_at := clock_timestamp();
    NEW.fact_digest :=
        asf_cancellation_supersession_escalation_fact_digest(NEW);
    RETURN NEW;
END;
$$;

CREATE FUNCTION asf_stamp_cancellation_supersession_anchor_fact()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'cancellation supersession anchor facts are trigger-generated'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'cancellation_supersession_anchor_facts_generated_only';
    END IF;
    NEW.id := asf_stable_cancellation_receipt_uuid(
        'asf.cancellation-supersession-anchor-fact/v1',
        NEW.escalation_id, NEW.generation_after
    );
    NEW.recorded_at := clock_timestamp();
    NEW.fact_digest := asf_cancellation_supersession_anchor_fact_digest(NEW);
    RETURN NEW;
END;
$$;

CREATE FUNCTION asf_stamp_cancellation_supersession_work_fact()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'cancellation supersession work facts are trigger-generated'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'cancellation_supersession_work_facts_generated_only';
    END IF;
    NEW.id := asf_stable_cancellation_receipt_uuid(
        'asf.cancellation-supersession-work-fact/v1',
        NEW.escalation_id, NEW.version_after
    );
    NEW.recorded_at := clock_timestamp();
    NEW.fact_digest := asf_cancellation_supersession_work_fact_digest(NEW);
    RETURN NEW;
END;
$$;

CREATE TRIGGER cancellation_supersession_escalation_facts_stamp
    BEFORE INSERT ON cancellation_supersession_escalation_facts
    FOR EACH ROW EXECUTE FUNCTION
        asf_stamp_cancellation_supersession_escalation_fact();
CREATE TRIGGER cancellation_supersession_anchor_facts_stamp
    BEFORE INSERT ON cancellation_supersession_anchor_facts
    FOR EACH ROW EXECUTE FUNCTION
        asf_stamp_cancellation_supersession_anchor_fact();
CREATE TRIGGER cancellation_supersession_work_facts_stamp
    BEFORE INSERT ON cancellation_supersession_work_facts
    FOR EACH ROW EXECUTE FUNCTION
        asf_stamp_cancellation_supersession_work_fact();

CREATE TRIGGER cancellation_supersession_escalation_facts_append_only
    BEFORE UPDATE OR DELETE ON cancellation_supersession_escalation_facts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_supersession_anchor_facts_append_only
    BEFORE UPDATE OR DELETE ON cancellation_supersession_anchor_facts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_supersession_work_facts_append_only
    BEFORE UPDATE OR DELETE ON cancellation_supersession_work_facts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_supersession_escalation_facts_truncate_forbidden
    BEFORE TRUNCATE ON cancellation_supersession_escalation_facts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_supersession_anchor_facts_truncate_forbidden
    BEFORE TRUNCATE ON cancellation_supersession_anchor_facts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_supersession_work_facts_truncate_forbidden
    BEFORE TRUNCATE ON cancellation_supersession_work_facts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE FUNCTION asf_cancellation_escalation_supersession_receipt_digest(
    candidate cancellation_escalation_supersession_receipts
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT asf_source_closure_digest(jsonb_build_object(
        'schema', 'asf.cancellation-escalation-supersession-receipt/v1',
        'id', candidate.id,
        'tenant_id', candidate.tenant_id,
        'work_item_id', candidate.work_item_id,
        'attempt_id', candidate.attempt_id,
        'escalation_id', candidate.escalation_id,
        'idempotency_record_id', candidate.idempotency_record_id,
        'actor_id', candidate.actor_id,
        'request_digest', candidate.request_digest,
        'replacement_workflow_id', candidate.replacement_workflow_id,
        'replacement_job_id', candidate.replacement_job_id,
        'work_item_version_before', candidate.work_item_version_before,
        'work_item_version_after', candidate.work_item_version_after,
        'anchor_generation_before', candidate.anchor_generation_before,
        'anchor_generation_after', candidate.anchor_generation_after,
        'cancellation_authority_generation',
            candidate.cancellation_authority_generation,
        'escalation_status_before', candidate.escalation_status_before,
        'escalation_version_before', candidate.escalation_version_before,
        'escalation_version_after', candidate.escalation_version_after,
        'escalation_before_digest', candidate.escalation_before_digest,
        'escalation_after_digest', candidate.escalation_after_digest,
        'dead_workflow_job_ids', candidate.dead_workflow_job_ids,
        'audit_event_id', candidate.audit_event_id,
        'outbox_event_id', candidate.outbox_event_id,
        'superseded_at', asf_chrono_utc(candidate.superseded_at),
        'recorded_at', asf_chrono_utc(candidate.recorded_at)
    ));
$$;

CREATE FUNCTION asf_stamp_cancellation_escalation_supersession_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> asf_derived_uuid(NEW.idempotency_record_id, 3)
       OR NEW.outbox_event_id <>
          asf_derived_uuid(NEW.idempotency_record_id, 4) THEN
        RAISE EXCEPTION 'cancellation escalation supersession receipt has unstable identity'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_stable_identity';
    END IF;
    NEW.recorded_at := clock_timestamp();
    IF NEW.superseded_at > NEW.recorded_at THEN
        RAISE EXCEPTION 'cancellation escalation supersession timestamp is in the future'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_db_time';
    END IF;
    NEW.receipt_digest :=
        asf_cancellation_escalation_supersession_receipt_digest(NEW);
    RETURN NEW;
END;
$$;

CREATE TRIGGER cancellation_escalation_supersession_receipts_stamp
    BEFORE INSERT ON cancellation_escalation_supersession_receipts
    FOR EACH ROW
    EXECUTE FUNCTION asf_stamp_cancellation_escalation_supersession_receipt();
CREATE TRIGGER cancellation_escalation_supersession_receipts_append_only
    BEFORE UPDATE OR DELETE ON cancellation_escalation_supersession_receipts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
CREATE TRIGGER cancellation_escalation_supersession_receipts_truncate_forbidden
    BEFORE TRUNCATE ON cancellation_escalation_supersession_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Match the API's SHA-256 idempotency namespace without ever constructing a
-- PostgreSQL text value containing NUL bytes.
CREATE FUNCTION asf_api_job_idempotency_key(
    candidate_tenant uuid,
    candidate_actor text,
    candidate_operation text,
    candidate_idempotency_key text
) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT 'api-job:sha256:' || encode(sha256(
        convert_to(candidate_tenant::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(candidate_actor, 'UTF8') || decode('00', 'hex') ||
        convert_to(candidate_operation, 'UTF8') || decode('00', 'hex') ||
        convert_to(candidate_idempotency_key, 'UTF8')
    ), 'hex');
$$;

CREATE FUNCTION asf_valid_cancellation_escalation_supersession_receipt(
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

CREATE FUNCTION asf_capture_cancellation_supersession_escalation_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    before_digest text;
    after_digest text;
BEGIN
    IF OLD.category <> 'WORKFLOW_JOB_EXHAUSTED'
       OR OLD.status NOT IN ('OPEN', 'ACKNOWLEDGED')
       OR NOT OLD.authority_or_effect_active
       OR OLD.attempt_id IS NULL
       OR NEW.status <> 'CANCELLED' THEN
        RETURN NULL;
    END IF;
    IF NEW.authority_or_effect_active
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR OLD.closed_at IS NOT NULL
       OR NEW.closed_at IS NULL
       OR NEW.closed_at < OLD.opened_at
       OR ROW(
           NEW.id, NEW.tenant_id, NEW.work_item_id, NEW.attempt_id,
           NEW.run_id, NEW.category, NEW.severity, NEW.reason,
           NEW.owner_type, NEW.owner_id, NEW.required_action,
           NEW.evidence_references, NEW.deadline, NEW.escalation_path,
           NEW.retry_policy, NEW.prerequisites, NEW.idempotency_key,
           NEW.opened_at, NEW.acknowledged_at
       ) IS DISTINCT FROM ROW(
           OLD.id, OLD.tenant_id, OLD.work_item_id, OLD.attempt_id,
           OLD.run_id, OLD.category, OLD.severity, OLD.reason,
           OLD.owner_type, OLD.owner_id, OLD.required_action,
           OLD.evidence_references, OLD.deadline, OLD.escalation_path,
           OLD.retry_policy, OLD.prerequisites, OLD.idempotency_key,
           OLD.opened_at, OLD.acknowledged_at
       ) THEN
        RAISE EXCEPTION
            'workflow-job exhaustion cancellation is not an exact supersession'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_escalation_fact_exact';
    END IF;
    before_digest := asf_terminal_conflict_escalation_row_digest(
        OLD.id, OLD.tenant_id, OLD.work_item_id, OLD.attempt_id, OLD.run_id,
        OLD.category, OLD.status, OLD.severity, OLD.reason, OLD.owner_type,
        OLD.owner_id, OLD.required_action, OLD.evidence_references,
        OLD.deadline, OLD.escalation_path, OLD.retry_policy,
        OLD.prerequisites, OLD.authority_or_effect_active,
        OLD.idempotency_key, OLD.aggregate_version, OLD.opened_at,
        OLD.acknowledged_at, OLD.closed_at
    );
    after_digest := asf_terminal_conflict_escalation_row_digest(
        NEW.id, NEW.tenant_id, NEW.work_item_id, NEW.attempt_id, NEW.run_id,
        NEW.category, NEW.status, NEW.severity, NEW.reason, NEW.owner_type,
        NEW.owner_id, NEW.required_action, NEW.evidence_references,
        NEW.deadline, NEW.escalation_path, NEW.retry_policy,
        NEW.prerequisites, NEW.authority_or_effect_active,
        NEW.idempotency_key, NEW.aggregate_version, NEW.opened_at,
        NEW.acknowledged_at, NEW.closed_at
    );
    INSERT INTO cancellation_supersession_escalation_facts (
        tenant_id, work_item_id, attempt_id, escalation_id, status_before,
        version_before, version_after, before_digest, after_digest,
        superseded_at
    ) VALUES (
        NEW.tenant_id, NEW.work_item_id, NEW.attempt_id, NEW.id, OLD.status,
        OLD.aggregate_version, NEW.aggregate_version, before_digest,
        after_digest, NEW.closed_at
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER escalations_capture_cancellation_supersession_fact
    AFTER UPDATE ON escalations
    FOR EACH ROW
    EXECUTE FUNCTION asf_capture_cancellation_supersession_escalation_fact();

CREATE FUNCTION asf_capture_cancellation_supersession_anchor_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    escalation_fact cancellation_supersession_escalation_facts%ROWTYPE;
    escalation_deadline timestamptz;
BEGIN
    IF OLD.anchor_type <> 'ESCALATION'
       OR NOT OLD.authority_or_effect_active THEN
        RETURN NULL;
    END IF;
    SELECT fact.*
    INTO escalation_fact
    FROM cancellation_supersession_escalation_facts AS fact
    JOIN escalations AS escalation
      ON escalation.tenant_id = fact.tenant_id
     AND escalation.id = fact.escalation_id
    WHERE fact.tenant_id = OLD.tenant_id
      AND fact.work_item_id = OLD.work_item_id
      AND fact.escalation_id = OLD.reference_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT escalation.deadline
    INTO STRICT escalation_deadline
    FROM escalations AS escalation
    WHERE escalation.tenant_id = escalation_fact.tenant_id
      AND escalation.id = escalation_fact.escalation_id;
    IF OLD.wake_or_deadline_at IS DISTINCT FROM escalation_deadline
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.work_item_id <> OLD.work_item_id
       OR NEW.anchor_type <> 'WORKFLOW'
       OR NEW.wake_or_deadline_at IS NOT NULL
       OR NEW.authority_or_effect_active
       OR NEW.generation <> OLD.generation + 1
       OR NEW.updated_at < escalation_fact.superseded_at THEN
        RAISE EXCEPTION
            'cancellation supersession accountability swap is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_anchor_fact_exact';
    END IF;
    INSERT INTO cancellation_supersession_anchor_facts (
        tenant_id, work_item_id, escalation_id, replacement_workflow_id,
        generation_before, generation_after, escalation_deadline,
        before_digest, after_digest, transitioned_at
    ) VALUES (
        NEW.tenant_id, NEW.work_item_id, escalation_fact.escalation_id,
        NEW.reference_id, OLD.generation, NEW.generation,
        escalation_deadline,
        asf_cancellation_supersession_anchor_row_digest(OLD),
        asf_cancellation_supersession_anchor_row_digest(NEW),
        NEW.updated_at
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER accountability_capture_cancellation_supersession_fact
    AFTER UPDATE ON accountability_anchors
    FOR EACH ROW
    EXECUTE FUNCTION asf_capture_cancellation_supersession_anchor_fact();

CREATE FUNCTION asf_capture_cancellation_supersession_work_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    anchor_fact cancellation_supersession_anchor_facts%ROWTYPE;
BEGIN
    IF OLD.state <> 'ESCALATED'
       OR NEW.state <> 'CANCEL_REQUESTED'
       OR OLD.current_attempt_id IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT fact.* INTO anchor_fact
    FROM cancellation_supersession_anchor_facts AS fact
    JOIN accountability_anchors AS anchor
      ON anchor.tenant_id = fact.tenant_id
     AND anchor.work_item_id = fact.work_item_id
     AND anchor.anchor_type = 'WORKFLOW'
     AND anchor.reference_id = fact.replacement_workflow_id
     AND anchor.generation = fact.generation_after
    WHERE fact.tenant_id = NEW.tenant_id
      AND fact.work_item_id = NEW.id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF OLD.current_attempt_id IS NULL
       OR NEW.current_attempt_id IS DISTINCT FROM OLD.current_attempt_id
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at < anchor_fact.transitioned_at
       OR (to_jsonb(NEW) - ARRAY[
               'state', 'aggregate_version', 'updated_at'
           ]::text[]) IS DISTINCT FROM
          (to_jsonb(OLD) - ARRAY[
               'state', 'aggregate_version', 'updated_at'
           ]::text[]) THEN
        RAISE EXCEPTION
            'cancellation supersession work transition is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_work_fact_exact';
    END IF;
    INSERT INTO cancellation_supersession_work_facts (
        tenant_id, work_item_id, attempt_id, escalation_id,
        version_before, version_after, before_digest, after_digest,
        transitioned_at
    ) VALUES (
        NEW.tenant_id, NEW.id, NEW.current_attempt_id,
        anchor_fact.escalation_id, OLD.aggregate_version,
        NEW.aggregate_version,
        asf_cancellation_supersession_work_row_digest(OLD),
        asf_cancellation_supersession_work_row_digest(NEW),
        NEW.updated_at
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER work_items_capture_cancellation_supersession_fact
    AFTER UPDATE ON work_items
    FOR EACH ROW
    EXECUTE FUNCTION asf_capture_cancellation_supersession_work_fact();

CREATE FUNCTION asf_assert_cancellation_supersession_work_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state <> 'ESCALATED'
       OR NEW.state <> 'CANCEL_REQUESTED'
       OR OLD.current_attempt_id IS NULL THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM cancellation_supersession_work_facts AS fact
        JOIN cancellation_escalation_supersession_receipts AS receipt
          ON receipt.tenant_id = fact.tenant_id
         AND receipt.escalation_id = fact.escalation_id
        WHERE fact.tenant_id = NEW.tenant_id
          AND fact.work_item_id = NEW.id
          AND fact.attempt_id = OLD.current_attempt_id
          AND fact.version_before = OLD.aggregate_version
          AND fact.version_after = NEW.aggregate_version
          AND fact.before_digest =
              asf_cancellation_supersession_work_row_digest(OLD)
          AND fact.after_digest =
              asf_cancellation_supersession_work_row_digest(NEW)
          AND receipt.work_item_version_before = OLD.aggregate_version
          AND receipt.work_item_version_after = NEW.aggregate_version
          AND asf_valid_cancellation_escalation_supersession_receipt(
              receipt.tenant_id, receipt.id, true
          )
    ) THEN
        RAISE EXCEPTION
            'ESCALATED cancellation request has no exact supersession transition fact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_supersession_work_transition_receipt';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER work_items_require_cancellation_supersession_fact
    AFTER UPDATE ON work_items
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_cancellation_supersession_work_transition();

-- Authenticate the otherwise-unrecoverable OLD escalation row at commit.
-- Only lifecycle fields may change; every DEAD-job evidence reference remains
-- byte-for-byte covered by the before/after row digests.
CREATE FUNCTION asf_assert_cancellation_escalation_supersession_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_before_digest text;
    expected_after_digest text;
BEGIN
    IF OLD.category <> 'WORKFLOW_JOB_EXHAUSTED'
       OR OLD.status NOT IN ('OPEN', 'ACKNOWLEDGED')
       OR NOT OLD.authority_or_effect_active
       OR OLD.attempt_id IS NULL
       OR NEW.status <> 'CANCELLED' THEN
        RETURN NULL;
    END IF;

    IF NEW.authority_or_effect_active
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR OLD.closed_at IS NOT NULL
       OR NEW.closed_at IS NULL
       OR NEW.closed_at < OLD.opened_at
       OR ROW(
           NEW.id, NEW.tenant_id, NEW.work_item_id, NEW.attempt_id,
           NEW.run_id, NEW.category, NEW.severity, NEW.reason,
           NEW.owner_type, NEW.owner_id, NEW.required_action,
           NEW.evidence_references, NEW.deadline, NEW.escalation_path,
           NEW.retry_policy, NEW.prerequisites, NEW.idempotency_key,
           NEW.opened_at, NEW.acknowledged_at
       ) IS DISTINCT FROM ROW(
           OLD.id, OLD.tenant_id, OLD.work_item_id, OLD.attempt_id,
           OLD.run_id, OLD.category, OLD.severity, OLD.reason,
           OLD.owner_type, OLD.owner_id, OLD.required_action,
           OLD.evidence_references, OLD.deadline, OLD.escalation_path,
           OLD.retry_policy, OLD.prerequisites, OLD.idempotency_key,
           OLD.opened_at, OLD.acknowledged_at
       ) THEN
        RAISE EXCEPTION
            'workflow-job exhaustion cancellation is not an exact supersession'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_exact_transition';
    END IF;

    expected_before_digest := asf_terminal_conflict_escalation_row_digest(
        OLD.id, OLD.tenant_id, OLD.work_item_id, OLD.attempt_id, OLD.run_id,
        OLD.category, OLD.status, OLD.severity, OLD.reason, OLD.owner_type,
        OLD.owner_id, OLD.required_action, OLD.evidence_references,
        OLD.deadline, OLD.escalation_path, OLD.retry_policy,
        OLD.prerequisites, OLD.authority_or_effect_active,
        OLD.idempotency_key, OLD.aggregate_version, OLD.opened_at,
        OLD.acknowledged_at, OLD.closed_at
    );
    expected_after_digest := asf_terminal_conflict_escalation_row_digest(
        NEW.id, NEW.tenant_id, NEW.work_item_id, NEW.attempt_id, NEW.run_id,
        NEW.category, NEW.status, NEW.severity, NEW.reason, NEW.owner_type,
        NEW.owner_id, NEW.required_action, NEW.evidence_references,
        NEW.deadline, NEW.escalation_path, NEW.retry_policy,
        NEW.prerequisites, NEW.authority_or_effect_active,
        NEW.idempotency_key, NEW.aggregate_version, NEW.opened_at,
        NEW.acknowledged_at, NEW.closed_at
    );
    IF NOT EXISTS (
        SELECT 1
        FROM cancellation_escalation_supersession_receipts AS receipt
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.escalation_id = NEW.id
          AND receipt.work_item_id = NEW.work_item_id
          AND receipt.attempt_id = NEW.attempt_id
          AND receipt.escalation_status_before = OLD.status
          AND receipt.escalation_version_before = OLD.aggregate_version
          AND receipt.escalation_version_after = NEW.aggregate_version
          AND receipt.escalation_before_digest = expected_before_digest
          AND receipt.escalation_after_digest = expected_after_digest
          AND receipt.superseded_at = NEW.closed_at
          AND asf_valid_cancellation_escalation_supersession_receipt(
              receipt.tenant_id, receipt.id, true
          )
    ) THEN
        RAISE EXCEPTION
            'cancelled workflow-job exhaustion escalation has no exact supersession receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_transition_receipt';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER escalations_require_cancellation_supersession_receipt
    AFTER UPDATE ON escalations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_cancellation_escalation_supersession_transition();

CREATE FUNCTION asf_assert_cancellation_supersession_anchor_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt cancellation_escalation_supersession_receipts%ROWTYPE;
    escalation_deadline timestamptz;
BEGIN
    IF OLD.anchor_type <> 'ESCALATION'
       OR NOT OLD.authority_or_effect_active THEN
        RETURN NULL;
    END IF;
    SELECT escalation.deadline
    INTO escalation_deadline
    FROM escalations AS escalation
    WHERE escalation.tenant_id = OLD.tenant_id
      AND escalation.work_item_id = OLD.work_item_id
      AND escalation.id = OLD.reference_id
      AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
      AND escalation.attempt_id IS NOT NULL
      AND escalation.status = 'CANCELLED'
      AND NOT escalation.authority_or_effect_active;
    IF NOT FOUND THEN
        -- Ordinary recovery from a RESOLVED exhaustion escalation keeps its
        -- pre-existing lifecycle semantics; only the cancellation-specific
        -- terminal transition is receipt-bound here.
        RETURN NULL;
    END IF;

    SELECT * INTO receipt
    FROM cancellation_escalation_supersession_receipts
    WHERE tenant_id = OLD.tenant_id
      AND work_item_id = OLD.work_item_id
      AND escalation_id = OLD.reference_id;
    IF NOT FOUND
       OR OLD.wake_or_deadline_at IS DISTINCT FROM escalation_deadline
       OR OLD.generation <> receipt.anchor_generation_before
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.work_item_id <> OLD.work_item_id
       OR NEW.anchor_type <> 'WORKFLOW'
       OR NEW.reference_id <> receipt.replacement_workflow_id
       OR NEW.wake_or_deadline_at IS NOT NULL
       OR NEW.authority_or_effect_active
       OR NEW.generation <> OLD.generation + 1
       OR NEW.generation <> receipt.anchor_generation_after
       OR NEW.updated_at < receipt.superseded_at
       OR NEW.updated_at > receipt.recorded_at
       OR NOT asf_valid_cancellation_escalation_supersession_receipt(
           receipt.tenant_id, receipt.id, true
       ) THEN
        RAISE EXCEPTION
            'cancellation escalation supersession has no exact accountability swap'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_anchor_transition';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER accountability_requires_cancellation_supersession
    AFTER UPDATE ON accountability_anchors
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_cancellation_supersession_anchor_transition();

CREATE FUNCTION asf_assert_cancellation_escalation_supersession_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT asf_valid_cancellation_escalation_supersession_receipt(
        NEW.tenant_id, NEW.id, true
    ) THEN
        RAISE EXCEPTION 'cancellation escalation supersession receipt is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'cancellation_escalation_supersession_receipt_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cancellation_escalation_supersession_receipts_exact
    AFTER INSERT ON cancellation_escalation_supersession_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_cancellation_escalation_supersession_receipt();

-- Once terminalized, the exact escalation after-image is immutable.  This is
-- the reciprocal escalation-side proof which lets immutable DEAD jobs retain
-- their historical dead_letter_escalation_id without weakening their strict
-- active-owner requirement at birth.
CREATE FUNCTION asf_assert_escalation_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt record;
BEGIN
    FOR receipt IN
        SELECT id, tenant_id
        FROM cancellation_escalation_supersession_receipts
        WHERE tenant_id = OLD.tenant_id AND escalation_id = OLD.id
    LOOP
        IF TG_OP = 'DELETE'
           OR NOT asf_valid_cancellation_escalation_supersession_receipt(
               receipt.tenant_id, receipt.id, false
           ) THEN
            RAISE EXCEPTION
                'mutation would sever cancellation escalation supersession receipt %',
                receipt.id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_escalation_supersession_reciprocal_guard';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER escalations_preserve_cancellation_supersession
    AFTER UPDATE OR DELETE ON escalations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_escalation_preserves_cancellation_supersession();

CREATE FUNCTION asf_assert_idempotency_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt record;
BEGIN
    FOR receipt IN
        SELECT id, tenant_id
        FROM cancellation_escalation_supersession_receipts
        WHERE tenant_id = OLD.tenant_id
          AND idempotency_record_id = OLD.id
    LOOP
        IF TG_OP = 'DELETE'
           OR NOT asf_valid_cancellation_escalation_supersession_receipt(
               receipt.tenant_id, receipt.id, false
           ) THEN
            RAISE EXCEPTION
                'mutation would sever cancellation supersession idempotency %',
                OLD.id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_escalation_supersession_idempotency_guard';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER idempotency_preserves_cancellation_supersession
    AFTER UPDATE OR DELETE ON idempotency_records
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_idempotency_preserves_cancellation_supersession();

CREATE FUNCTION asf_assert_work_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt record;
BEGIN
    FOR receipt IN
        SELECT id, tenant_id
        FROM cancellation_escalation_supersession_receipts
        WHERE tenant_id = OLD.tenant_id AND work_item_id = OLD.id
    LOOP
        IF TG_OP = 'DELETE'
           OR NOT asf_valid_cancellation_escalation_supersession_receipt(
               receipt.tenant_id, receipt.id, false
           ) THEN
            RAISE EXCEPTION
                'mutation would sever cancellation supersession work provenance %',
                OLD.id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_supersession_work_reciprocal_guard';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER work_items_preserve_cancellation_supersession
    AFTER UPDATE OR DELETE ON work_items
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_work_preserves_cancellation_supersession();

CREATE FUNCTION asf_assert_workflow_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt record;
BEGIN
    FOR receipt IN
        SELECT id, tenant_id
        FROM cancellation_escalation_supersession_receipts
        WHERE tenant_id = OLD.tenant_id
          AND replacement_workflow_id = OLD.id
    LOOP
        IF TG_OP = 'DELETE'
           OR NOT asf_valid_cancellation_escalation_supersession_receipt(
               receipt.tenant_id, receipt.id, false
           ) THEN
            RAISE EXCEPTION
                'mutation would sever cancellation supersession workflow provenance %',
                OLD.id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'cancellation_supersession_workflow_reciprocal_guard';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_instances_preserve_cancellation_supersession
    AFTER UPDATE OR DELETE ON workflow_instances
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_workflow_preserves_cancellation_supersession();

-- A concurrent active-escalation birth increments this predicate row. If it
-- was waiting behind the API's guard lock, its own deferred trigger sees the
-- final CANCEL_REQUESTED work state and rejects the competing owner. This also
-- closes the serialized negative proof for ordinary (non-ESCALATED) API
-- cancellation; normal cancellation jobs may continue evolving because they
-- do not create an active escalation.
CREATE FUNCTION asf_assert_authority_guard_preserves_cancellation_supersession()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.terminal_receipt_id IS NULL
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

CREATE CONSTRAINT TRIGGER cancellation_authority_preserves_supersession
    AFTER UPDATE ON work_cancellation_authority_guards
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION
        asf_assert_authority_guard_preserves_cancellation_supersession();

CREATE FUNCTION asf_reject_workflow_job_supersession_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM cancellation_escalation_supersession_receipts
    ) THEN
        RAISE EXCEPTION
            'workflow jobs cited by cancellation supersession receipts cannot be truncated'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'workflow_jobs_preserve_cancellation_supersession';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER workflow_jobs_preserve_cancellation_supersession_truncate
    BEFORE TRUNCATE ON workflow_jobs
    FOR EACH STATEMENT
    EXECUTE FUNCTION asf_reject_workflow_job_supersession_truncate();

-- Serialize every work-bound transition into DEAD against the work row.  The
-- API owns that row while it freezes the exact DEAD-owner set, so a late child
-- cannot use an earlier statement snapshot to attach itself after the active
-- escalation has been superseded.  DEAD rows themselves are never locked by
-- the API, preserving the reactor's job -> work order.
CREATE FUNCTION asf_serialize_work_bound_dead_job_birth()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    locked_state text;
    locked_attempt uuid;
    locked_escalation uuid;
BEGIN
    IF NEW.work_item_id IS NULL
       OR NEW.status <> 'DEAD'
       OR (TG_OP = 'UPDATE' AND OLD.status = 'DEAD') THEN
        RETURN NEW;
    END IF;
    SELECT state, current_attempt_id
    INTO locked_state, locked_attempt
    FROM work_items
    WHERE tenant_id = NEW.tenant_id AND id = NEW.work_item_id
    FOR UPDATE;
    IF NOT FOUND
       OR locked_state <> 'ESCALATED'
       OR locked_attempt IS DISTINCT FROM NEW.attempt_id THEN
        RAISE EXCEPTION
            'work-bound DEAD workflow job has no serialized escalated aggregate'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_dead_birth_serialized_with_work';
    END IF;
    SELECT id INTO locked_escalation
    FROM escalations
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.dead_letter_escalation_id
      AND work_item_id = NEW.work_item_id
      AND attempt_id IS NOT DISTINCT FROM NEW.attempt_id
      AND category = 'WORKFLOW_JOB_EXHAUSTED'
      AND status IN ('OPEN', 'ACKNOWLEDGED')
      AND authority_or_effect_active
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'work-bound DEAD workflow job has no locked active exhaustion owner'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_dead_birth_locks_active_escalation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_jobs_00_serialize_work_bound_dead_birth
    BEFORE INSERT OR UPDATE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_serialize_work_bound_dead_job_birth();
