-- Every row carrying both a work item and an attempt must bind those values to
-- the same attempt. MATCH SIMPLE deliberately preserves tenant-scoped and
-- work-scoped rows whose optional attempt is NULL.

ALTER TABLE work_items
    ADD CONSTRAINT work_items_repository_binding_key
    UNIQUE (tenant_id, id, repository_id);

ALTER TABLE work_orders
    ADD CONSTRAINT work_orders_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT work_orders_run_binding_key
    UNIQUE (tenant_id, id, work_item_id, attempt_id),
    ADD CONSTRAINT work_orders_digest_binding_key
    UNIQUE (tenant_id, payload_digest, work_item_id, attempt_id);

ALTER TABLE attempts
    ADD CONSTRAINT attempts_exact_work_order_digest_fk
    FOREIGN KEY (tenant_id, work_order_digest, work_item_id, id)
    REFERENCES work_orders(tenant_id, payload_digest, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE runs
    ADD CONSTRAINT runs_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT runs_work_order_binding_fk
    FOREIGN KEY (tenant_id, work_order_id, work_item_id, attempt_id)
    REFERENCES work_orders(tenant_id, id, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT runs_evidence_binding_key
    UNIQUE (tenant_id, id, work_item_id, attempt_id),
    ADD CONSTRAINT runs_worker_evidence_binding_key
    UNIQUE (
        tenant_id, id, work_item_id, attempt_id, worker_id, worker_generation
    );

ALTER TABLE approvals
    ADD CONSTRAINT approvals_work_order_requires_attempt CHECK (
        work_order_digest IS NULL OR attempt_id IS NOT NULL
    ),
    ADD CONSTRAINT approvals_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT approvals_work_order_binding_fk
    FOREIGN KEY (tenant_id, work_order_digest, work_item_id, attempt_id)
    REFERENCES work_orders(tenant_id, payload_digest, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT;

ALTER TABLE escalations
    ADD CONSTRAINT escalations_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT escalations_run_requires_attempt CHECK (
        run_id IS NULL OR attempt_id IS NOT NULL
    ),
    ADD CONSTRAINT escalations_run_binding_fk
    FOREIGN KEY (tenant_id, run_id, work_item_id, attempt_id)
    REFERENCES runs(tenant_id, id, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT;

ALTER TABLE evidence_bundles
    ADD CONSTRAINT evidence_bundles_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_bundles_run_binding_fk
    FOREIGN KEY (tenant_id, run_id, work_item_id, attempt_id)
    REFERENCES runs(tenant_id, id, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_bundles_work_order_binding_fk
    FOREIGN KEY (tenant_id, work_order_digest, work_item_id, attempt_id)
    REFERENCES work_orders(tenant_id, payload_digest, work_item_id, attempt_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_bundles_run_worker_binding_fk
    FOREIGN KEY (
        tenant_id, run_id, work_item_id, attempt_id, worker_id, worker_generation
    )
    REFERENCES runs(
        tenant_id, id, work_item_id, attempt_id, worker_id, worker_generation
    )
    MATCH SIMPLE ON DELETE RESTRICT;

ALTER TABLE budget_ledger
    ADD CONSTRAINT budget_ledger_attempt_requires_work_item CHECK (
        attempt_id IS NULL OR work_item_id IS NOT NULL
    ),
    ADD CONSTRAINT budget_ledger_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT budget_ledger_attempt_scope_binding CHECK (
        scope_type <> 'ATTEMPT'
        OR (
            attempt_id IS NOT NULL
            AND work_item_id IS NOT NULL
            AND scope_id = attempt_id::text
        )
    );

ALTER TABLE reservation_sets
    ADD CONSTRAINT reservation_sets_work_repository_fk
    FOREIGN KEY (tenant_id, work_item_id, repository_id)
    REFERENCES work_items(tenant_id, id, repository_id)
    MATCH SIMPLE ON DELETE RESTRICT;

ALTER TABLE workflow_jobs
    ADD CONSTRAINT workflow_jobs_attempt_requires_work_item CHECK (
        attempt_id IS NULL OR work_item_id IS NOT NULL
    ),
    ADD CONSTRAINT workflow_jobs_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT workflow_jobs_binding_shape CHECK (
        (
            workflow_instance_id IS NULL
            AND work_item_id IS NULL
            AND attempt_id IS NULL
        )
        OR (
            workflow_instance_id IS NOT NULL
            AND work_item_id IS NOT NULL
        )
    );

ALTER TABLE workflow_timers
    ADD CONSTRAINT workflow_timers_attempt_requires_work_item CHECK (
        attempt_id IS NULL OR work_item_id IS NOT NULL
    ),
    ADD CONSTRAINT workflow_timers_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT workflow_timers_binding_shape CHECK (
        (
            workflow_instance_id IS NULL
            AND work_item_id IS NULL
            AND attempt_id IS NULL
        )
        OR (
            workflow_instance_id IS NOT NULL
            AND work_item_id IS NOT NULL
        )
    );

ALTER TABLE effect_intents
    ADD CONSTRAINT effect_intents_attempt_requires_work_item CHECK (
        attempt_id IS NULL OR work_item_id IS NOT NULL
    ),
    ADD CONSTRAINT effect_intents_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_attempt_requires_work_item CHECK (
        attempt_id IS NULL OR work_item_id IS NOT NULL
    ),
    ADD CONSTRAINT audit_events_attempt_work_item_fk
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
    REFERENCES attempts(tenant_id, id, work_item_id)
    MATCH SIMPLE ON DELETE RESTRICT;

-- Multiple exhausted jobs may share their work attempt's one active durable
-- escalation. The original SLA can already be overdue when a later job joins;
-- exact job evidence, rather than a reset deadline, proves that ownership.
CREATE OR REPLACE FUNCTION asf_assert_dead_job_escalation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'DEAD' THEN
        IF NEW.work_item_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM escalations AS escalation
            WHERE escalation.tenant_id = NEW.tenant_id
              AND escalation.work_item_id = NEW.work_item_id
              AND escalation.id = NEW.dead_letter_escalation_id
              AND escalation.attempt_id IS NOT DISTINCT FROM NEW.attempt_id
              AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
              AND escalation.status IN ('OPEN', 'ACKNOWLEDGED')
              AND btrim(escalation.owner_id) <> ''
              AND btrim(escalation.required_action) <> ''
              AND escalation.deadline > escalation.opened_at
              AND jsonb_typeof(escalation.evidence_references) = 'array'
              AND escalation.evidence_references
                    @> jsonb_build_array('workflow-job:' || NEW.id::text)
              AND jsonb_typeof(escalation.retry_policy) = 'object'
        ) THEN
            RAISE EXCEPTION 'dead workflow job % has no durable owned exhaustion escalation', NEW.id
                USING ERRCODE = '23514';
        ELSIF NEW.work_item_id IS NULL AND NOT EXISTS (
            SELECT 1
            FROM operational_incidents AS incident
            WHERE incident.tenant_id = NEW.tenant_id
              AND incident.workflow_job_id = NEW.id
              AND incident.id = NEW.dead_letter_operational_incident_id
              AND incident.category = 'WORKFLOW_JOB_EXHAUSTED'
              AND incident.status IN ('OPEN', 'ACKNOWLEDGED')
              AND incident.authority_or_effect_active
              AND btrim(incident.owner_id) <> ''
              AND btrim(incident.required_action) <> ''
              AND jsonb_typeof(incident.evidence_references) = 'array'
              AND jsonb_array_length(incident.evidence_references) > 0
              AND incident.deadline > NEW.dead_lettered_at
              AND jsonb_typeof(incident.retry_policy) = 'object'
        ) THEN
            RAISE EXCEPTION 'dead operational workflow job % has no durable owned incident', NEW.id
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

-- Active operational ownership must carry live authority. Terminal lifecycle
-- transitions explicitly turn authority off.
ALTER TABLE operational_incidents
    ADD CONSTRAINT operational_incidents_active_authority CHECK (
        status NOT IN ('OPEN', 'ACKNOWLEDGED')
        OR authority_or_effect_active
    );

CREATE FUNCTION asf_guard_active_operational_incident_authority() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('OPEN', 'ACKNOWLEDGED')
        AND NOT NEW.authority_or_effect_active
    THEN
        RAISE EXCEPTION 'active operational incident requires live authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER operational_incident_active_authority_guard
    BEFORE INSERT OR UPDATE ON operational_incidents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_active_operational_incident_authority();

-- Delivery state can advance, but an outbox row's durable event identity and
-- payload are immutable accountability facts once inserted.
CREATE FUNCTION asf_guard_outbox_semantics() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'outbox facts cannot be deleted'
            USING ERRCODE = '23514';
    END IF;

    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.topic,
        NEW.message_key,
        NEW.event_type,
        NEW.payload,
        NEW.headers,
        NEW.idempotency_key,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.topic,
        OLD.message_key,
        OLD.event_type,
        OLD.payload,
        OLD.headers,
        OLD.idempotency_key,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'outbox identity and semantic fields are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_semantics_immutable
    BEFORE UPDATE OR DELETE ON outbox
    FOR EACH ROW EXECUTE FUNCTION asf_guard_outbox_semantics();

-- Workflow-job requests are immutable after enqueue, and terminal results are
-- immutable receipts. Delivery/claim fields may advance only while nonterminal.
CREATE FUNCTION asf_guard_workflow_job_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow jobs cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('COMPLETED', 'DEAD') AND NEW IS DISTINCT FROM OLD THEN
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

ALTER TABLE workflow_timers
    ADD CONSTRAINT workflow_timers_lifecycle_shape CHECK (
        (
            status = 'SCHEDULED'
            AND fired_at IS NULL
            AND cancelled_at IS NULL
        )
        OR (
            status = 'FIRED'
            AND fired_at IS NOT NULL
            AND fired_at >= created_at
            AND cancelled_at IS NULL
        )
        OR (
            status = 'CANCELLED'
            AND cancelled_at IS NOT NULL
            AND cancelled_at >= created_at
            AND fired_at IS NULL
        )
    );

CREATE FUNCTION asf_guard_workflow_timer_mutation() RETURNS trigger
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

ALTER TABLE idempotency_records
    ADD CONSTRAINT idempotency_records_response_shape CHECK (
        (
            state = 'IN_PROGRESS'
            AND response_status IS NULL
            AND response_body IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'COMPLETED'
            AND response_status BETWEEN 200 AND 399
            AND response_body IS NOT NULL
            AND completed_at IS NOT NULL
            AND completed_at >= created_at
        )
        OR (
            state = 'FAILED'
            AND response_status BETWEEN 400 AND 599
            AND response_body IS NOT NULL
            AND completed_at IS NOT NULL
            AND completed_at >= created_at
        )
    );

CREATE FUNCTION asf_guard_idempotency_record_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'unexpired idempotency records cannot be deleted'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.state IN ('COMPLETED', 'FAILED') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal idempotency records are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.actor_id,
        NEW.operation,
        NEW.idempotency_key,
        NEW.request_digest,
        NEW.created_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.actor_id,
        OLD.operation,
        OLD.idempotency_key,
        OLD.request_digest,
        OLD.created_at,
        OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'idempotency identity and request fields are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER idempotency_records_immutable
    BEFORE UPDATE OR DELETE ON idempotency_records
    FOR EACH ROW EXECUTE FUNCTION asf_guard_idempotency_record_mutation();
