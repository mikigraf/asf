-- Operational incidents are immutable ownership records with an explicit,
-- monotonic lifecycle. Closing one removes the active attention obligation but
-- never severs its historical association with the exhausted workflow job.

ALTER TABLE operational_incidents
    ADD COLUMN acknowledged_by text,
    ADD COLUMN closed_by text,
    ADD COLUMN resolution text,
    ADD CONSTRAINT operational_incidents_lifecycle_shape CHECK (
        (
            status = 'OPEN'
            AND aggregate_version = 1
            AND acknowledged_at IS NULL
            AND acknowledged_by IS NULL
            AND closed_at IS NULL
            AND closed_by IS NULL
            AND resolution IS NULL
        )
        OR (
            status = 'ACKNOWLEDGED'
            AND aggregate_version = 2
            AND acknowledged_at IS NOT NULL
            AND acknowledged_by IS NOT NULL
            AND btrim(acknowledged_by) <> ''
            AND closed_at IS NULL
            AND closed_by IS NULL
            AND resolution IS NULL
        )
        OR (
            status IN ('RESOLVED', 'CANCELLED')
            AND aggregate_version = 3
            AND acknowledged_at IS NOT NULL
            AND acknowledged_by IS NOT NULL
            AND btrim(acknowledged_by) <> ''
            AND closed_at IS NOT NULL
            AND closed_at >= acknowledged_at
            AND closed_by IS NOT NULL
            AND btrim(closed_by) <> ''
            AND resolution IS NOT NULL
            AND btrim(resolution) <> ''
            AND authority_or_effect_active = false
        )
    );

CREATE FUNCTION asf_guard_operational_incident_lifecycle() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'OPEN'
            OR NEW.aggregate_version <> 1
            OR NEW.acknowledged_at IS NOT NULL
            OR NEW.acknowledged_by IS NOT NULL
            OR NEW.closed_at IS NOT NULL
            OR NEW.closed_by IS NOT NULL
            OR NEW.resolution IS NOT NULL
        THEN
            RAISE EXCEPTION 'operational incident must be created OPEN at version 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.workflow_job_id,
        NEW.category,
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
        NEW.idempotency_key,
        NEW.opened_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.workflow_job_id,
        OLD.category,
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
        OLD.idempotency_key,
        OLD.opened_at
    ) THEN
        RAISE EXCEPTION 'operational incident identity and ownership fields are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.status = 'OPEN' THEN
        IF NEW.status <> 'ACKNOWLEDGED'
            OR NEW.aggregate_version <> OLD.aggregate_version + 1
            OR NEW.acknowledged_at IS NULL
            OR NEW.acknowledged_at < OLD.opened_at
            OR NEW.acknowledged_by IS NULL
            OR btrim(NEW.acknowledged_by) = ''
            OR NEW.closed_at IS NOT NULL
            OR NEW.closed_by IS NOT NULL
            OR NEW.resolution IS NOT NULL
            OR NEW.authority_or_effect_active IS DISTINCT FROM OLD.authority_or_effect_active
        THEN
            RAISE EXCEPTION 'illegal operational incident transition from OPEN'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.status = 'ACKNOWLEDGED' THEN
        IF NEW.status NOT IN ('RESOLVED', 'CANCELLED')
            OR NEW.aggregate_version <> OLD.aggregate_version + 1
            OR NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
            OR NEW.acknowledged_by IS DISTINCT FROM OLD.acknowledged_by
            OR NEW.closed_at IS NULL
            OR NEW.closed_at < OLD.acknowledged_at
            OR NEW.closed_by IS NULL
            OR btrim(NEW.closed_by) = ''
            OR NEW.resolution IS NULL
            OR btrim(NEW.resolution) = ''
            OR NEW.authority_or_effect_active
        THEN
            RAISE EXCEPTION 'illegal operational incident transition from ACKNOWLEDGED'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'terminal operational incident cannot be changed'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operational_incident_lifecycle_guard
    BEFORE INSERT OR UPDATE ON operational_incidents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_operational_incident_lifecycle();

-- A terminal owner still proves that a DEAD job was durably assigned and
-- reconciled. Only the attention read filters terminal incidents from the
-- active queue.
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
              AND escalation.category = 'WORKFLOW_JOB_EXHAUSTED'
              AND btrim(escalation.owner_id) <> ''
              AND btrim(escalation.required_action) <> ''
              AND escalation.deadline > NEW.dead_lettered_at
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

-- One immutable receipt owns each transition from an expected aggregate
-- version. It makes a lost response adoptable after the incident has advanced
-- again, while a different semantic request for the same transition fence is
-- rejected by its digest.
CREATE TABLE operational_incident_transition_receipts (
    tenant_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    workflow_job_id uuid NOT NULL,
    expected_version bigint NOT NULL CHECK (expected_version > 0),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    transition_kind text NOT NULL
        CHECK (transition_kind IN ('ACKNOWLEDGE', 'RESOLVE', 'CANCEL')),
    result_status text NOT NULL
        CHECK (result_status IN ('ACKNOWLEDGED', 'RESOLVED', 'CANCELLED')),
    result_aggregate_version bigint NOT NULL CHECK (result_aggregate_version > 1),
    result_authority_or_effect_active boolean NOT NULL,
    acknowledged_at timestamptz NOT NULL,
    acknowledged_by text NOT NULL CHECK (btrim(acknowledged_by) <> ''),
    closed_at timestamptz,
    closed_by text,
    resolution text,
    occurred_at timestamptz NOT NULL,
    audit_event_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, incident_id, expected_version),
    UNIQUE (tenant_id, audit_event_id),
    UNIQUE (tenant_id, outbox_id),
    FOREIGN KEY (tenant_id, incident_id, workflow_job_id)
        REFERENCES operational_incidents(tenant_id, id, workflow_job_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, audit_event_id)
        REFERENCES audit_events(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, outbox_id)
        REFERENCES outbox(tenant_id, id) ON DELETE RESTRICT,
    CHECK (result_aggregate_version = expected_version + 1),
    CHECK (
        (
            transition_kind = 'ACKNOWLEDGE'
            AND result_status = 'ACKNOWLEDGED'
            AND closed_at IS NULL
            AND closed_by IS NULL
            AND resolution IS NULL
            AND occurred_at = acknowledged_at
        )
        OR (
            transition_kind = 'RESOLVE'
            AND result_status = 'RESOLVED'
            AND result_authority_or_effect_active = false
            AND closed_at IS NOT NULL
            AND closed_at >= acknowledged_at
            AND closed_by IS NOT NULL
            AND btrim(closed_by) <> ''
            AND resolution IS NOT NULL
            AND btrim(resolution) <> ''
            AND occurred_at = closed_at
        )
        OR (
            transition_kind = 'CANCEL'
            AND result_status = 'CANCELLED'
            AND result_authority_or_effect_active = false
            AND closed_at IS NOT NULL
            AND closed_at >= acknowledged_at
            AND closed_by IS NOT NULL
            AND btrim(closed_by) <> ''
            AND resolution IS NOT NULL
            AND btrim(resolution) <> ''
            AND occurred_at = closed_at
        )
    )
);

CREATE TRIGGER operational_incident_transition_receipts_append_only
    BEFORE UPDATE OR DELETE ON operational_incident_transition_receipts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();

CREATE FUNCTION asf_assert_operational_incident_transition_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_transition text;
BEGIN
    expected_transition := CASE
        WHEN OLD.status = 'OPEN' AND NEW.status = 'ACKNOWLEDGED' THEN 'ACKNOWLEDGE'
        WHEN OLD.status = 'ACKNOWLEDGED' AND NEW.status = 'RESOLVED' THEN 'RESOLVE'
        WHEN OLD.status = 'ACKNOWLEDGED' AND NEW.status = 'CANCELLED' THEN 'CANCEL'
        ELSE NULL
    END;

    IF expected_transition IS NULL OR NOT EXISTS (
        SELECT 1
        FROM operational_incident_transition_receipts AS receipt
        JOIN audit_events AS audit
          ON audit.tenant_id = receipt.tenant_id
         AND audit.id = receipt.audit_event_id
        JOIN outbox
          ON outbox.tenant_id = receipt.tenant_id
         AND outbox.id = receipt.outbox_id
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.incident_id = NEW.id
          AND receipt.workflow_job_id = NEW.workflow_job_id
          AND receipt.expected_version = OLD.aggregate_version
          AND receipt.transition_kind = expected_transition
          AND receipt.result_status = NEW.status
          AND receipt.result_aggregate_version = NEW.aggregate_version
          AND receipt.result_authority_or_effect_active
                IS NOT DISTINCT FROM NEW.authority_or_effect_active
          AND receipt.acknowledged_at IS NOT DISTINCT FROM NEW.acknowledged_at
          AND receipt.acknowledged_by IS NOT DISTINCT FROM NEW.acknowledged_by
          AND receipt.closed_at IS NOT DISTINCT FROM NEW.closed_at
          AND receipt.closed_by IS NOT DISTINCT FROM NEW.closed_by
          AND receipt.resolution IS NOT DISTINCT FROM NEW.resolution
          AND receipt.occurred_at = CASE
              WHEN expected_transition = 'ACKNOWLEDGE' THEN NEW.acknowledged_at
              ELSE NEW.closed_at
          END
          AND audit.actor_type = 'OPERATOR'
          AND audit.actor_id = CASE
              WHEN expected_transition = 'ACKNOWLEDGE' THEN NEW.acknowledged_by
              ELSE NEW.closed_by
          END
          AND audit.action = CASE expected_transition
              WHEN 'ACKNOWLEDGE' THEN 'OPERATIONAL_INCIDENT_ACKNOWLEDGED'
              WHEN 'RESOLVE' THEN 'OPERATIONAL_INCIDENT_RESOLVED'
              WHEN 'CANCEL' THEN 'OPERATIONAL_INCIDENT_CANCELLED'
          END
          AND audit.subject_type = 'OPERATIONAL_INCIDENT'
          AND audit.subject_id = NEW.id::text
          AND audit.occurred_at = receipt.occurred_at
          AND audit.details ->> 'operational_incident_id' = NEW.id::text
          AND audit.details ->> 'workflow_job_id' = NEW.workflow_job_id::text
          AND audit.details ->> 'transition' = expected_transition
          AND audit.details ->> 'request_digest' = receipt.request_digest
          AND audit.details ->> 'resolution' IS NOT DISTINCT FROM NEW.resolution
          AND outbox.topic = 'attention'
          AND outbox.message_key = NEW.id::text
          AND outbox.event_type = CASE expected_transition
              WHEN 'ACKNOWLEDGE' THEN 'operational_incident.acknowledged'
              WHEN 'RESOLVE' THEN 'operational_incident.resolved'
              WHEN 'CANCEL' THEN 'operational_incident.cancelled'
          END
          AND outbox.available_at = receipt.occurred_at
          AND outbox.payload ->> 'operational_incident_id' = NEW.id::text
          AND outbox.payload ->> 'workflow_job_id' = NEW.workflow_job_id::text
          AND outbox.payload ->> 'transition' = expected_transition
          AND outbox.payload ->> 'request_digest' = receipt.request_digest
          AND outbox.payload ->> 'actor' = audit.actor_id
          AND outbox.payload ->> 'resolution' IS NOT DISTINCT FROM NEW.resolution
    ) THEN
        RAISE EXCEPTION 'operational incident transition has no matching immutable receipt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER operational_incident_transition_requires_receipt
    AFTER UPDATE ON operational_incidents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_operational_incident_transition_receipt();
