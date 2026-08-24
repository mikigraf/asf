-- Operational-incident lifecycle receipts must prove the complete semantic
-- audit/outbox facts, including the exact canonical lifecycle digests.  The
-- earlier guard intentionally used a smaller predicate; a coherent internal
-- writer could otherwise fill every checked field while lying in an omitted
-- status/version/schema field.

-- Match chrono's serde RFC 3339 representation for PostgreSQL's microsecond
-- timestamp precision.  `DateTime<Utc>` uses no fractional part, three
-- fractional digits, or six fractional digits and the `Z` suffix.
CREATE FUNCTION asf_chrono_utc(candidate timestamptz) RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT
        to_char(candidate AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
        || CASE
            WHEN to_char(candidate AT TIME ZONE 'UTC', 'US') = '000000'
                THEN ''
            WHEN right(to_char(candidate AT TIME ZONE 'UTC', 'US'), 3) = '000'
                THEN '.' || left(to_char(candidate AT TIME ZONE 'UTC', 'US'), 3)
            ELSE '.' || to_char(candidate AT TIME ZONE 'UTC', 'US')
        END
        || 'Z'
$$;

-- RFC 8785 sorts these object keys lexicographically.  PostgreSQL UUID, text,
-- boolean, and integer JSON encodings match serde_json; timestamps are
-- rendered explicitly above so the database can reproduce the Rust digest
-- without an extension.
CREATE FUNCTION asf_operational_incident_lifecycle_digest(
    incident_id uuid,
    incident_tenant_id uuid,
    incident_workflow_job_id uuid,
    incident_status text,
    incident_aggregate_version bigint,
    incident_authority_or_effect_active boolean,
    incident_acknowledged_at timestamptz,
    incident_acknowledged_by text,
    incident_closed_at timestamptz,
    incident_closed_by text,
    incident_resolution text
) RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT 'sha256:' || encode(
        sha256(convert_to(
            '{'
            || '"acknowledged_at":'
            || CASE
                WHEN incident_acknowledged_at IS NULL THEN 'null'
                ELSE to_json(asf_chrono_utc(incident_acknowledged_at))::text
            END
            || ',"acknowledged_by":' || COALESCE(to_json(incident_acknowledged_by)::text, 'null')
            || ',"aggregate_version":' || incident_aggregate_version::text
            || ',"authority_or_effect_active":' || incident_authority_or_effect_active::text
            || ',"closed_at":'
            || CASE
                WHEN incident_closed_at IS NULL THEN 'null'
                ELSE to_json(asf_chrono_utc(incident_closed_at))::text
            END
            || ',"closed_by":' || COALESCE(to_json(incident_closed_by)::text, 'null')
            || ',"id":' || to_json(incident_id)::text
            || ',"resolution":' || COALESCE(to_json(incident_resolution)::text, 'null')
            || ',"status":' || to_json(incident_status)::text
            || ',"tenant_id":' || to_json(incident_tenant_id)::text
            || ',"workflow_job_id":' || to_json(incident_workflow_job_id)::text
            || '}',
            'UTF8'
        )),
        'hex'
    )
$$;

-- The receipt's request digest is also derived from the resulting lifecycle
-- actor/resolution rather than trusted as an arbitrary matching token shared
-- by the receipt, audit, and outbox rows.
CREATE FUNCTION asf_operational_incident_transition_request_digest(
    request_tenant_id uuid,
    request_incident_id uuid,
    request_expected_version bigint,
    request_transition text,
    request_actor text,
    request_resolution text
) RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT 'sha256:' || encode(
        sha256(convert_to(
            '{'
            || '"actor":' || to_json(request_actor)::text
            || ',"expected_version":' || request_expected_version::text
            || ',"incident_id":' || to_json(request_incident_id)::text
            || ',"resolution":' || COALESCE(to_json(request_resolution)::text, 'null')
            || ',"schema":"asf.operational-incident-transition-request/v1"'
            || ',"tenant_id":' || to_json(request_tenant_id)::text
            || ',"transition":' || to_json(request_transition)::text
            || '}',
            'UTF8'
        )),
        'hex'
    )
$$;

-- Reproduce `HashedAuditEvent::create` for the exact incident-transition
-- content.  The prior semantic predicate bound every business field but did
-- not prove that `event_hash` was actually the RFC 8785 hash of those fields;
-- an arbitrary well-formed digest would therefore poison later chain export.
CREATE FUNCTION asf_operational_incident_transition_audit_hash(
    audit_id uuid,
    audit_tenant_id uuid,
    audit_actor_type text,
    audit_actor_id text,
    audit_action text,
    audit_subject_type text,
    audit_subject_id text,
    audit_correlation_id text,
    audit_before_digest text,
    audit_after_digest text,
    audit_previous_event_hash text,
    audit_occurred_at timestamptz,
    incident_id uuid,
    incident_workflow_job_id uuid,
    incident_transition text,
    incident_from_status text,
    incident_to_status text,
    incident_expected_version bigint,
    incident_result_aggregate_version bigint,
    incident_request_digest text,
    incident_resolution text
) RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT 'sha256:' || encode(
        sha256(convert_to(
            '{'
            || '"action":' || to_json(audit_action)::text
            || ',"actor_id":' || to_json(audit_actor_id)::text
            || ',"actor_type":' || to_json(audit_actor_type)::text
            || ',"after_digest":' || COALESCE(to_json(audit_after_digest)::text, 'null')
            || ',"attempt_id":null'
            || ',"before_digest":' || COALESCE(to_json(audit_before_digest)::text, 'null')
            || ',"correlation_id":' || to_json(audit_correlation_id)::text
            || ',"details":{'
                || '"expected_version":' || incident_expected_version::text
                || ',"from_status":' || to_json(incident_from_status)::text
                || ',"operational_incident_id":' || to_json(incident_id)::text
                || ',"request_digest":' || to_json(incident_request_digest)::text
                || ',"resolution":' || COALESCE(to_json(incident_resolution)::text, 'null')
                || ',"result_aggregate_version":'
                    || incident_result_aggregate_version::text
                || ',"schema":"asf.operational-incident-transition-audit/v1"'
                || ',"to_status":' || to_json(incident_to_status)::text
                || ',"transition":' || to_json(incident_transition)::text
                || ',"workflow_job_id":' || to_json(incident_workflow_job_id)::text
            || '}'
            || ',"id":' || to_json(audit_id)::text
            || ',"occurred_at":' || to_json(asf_chrono_utc(audit_occurred_at))::text
            || ',"policy_digest":null'
            || ',"previous_event_hash":'
                || COALESCE(to_json(audit_previous_event_hash)::text, 'null')
            || ',"subject_id":' || to_json(audit_subject_id)::text
            || ',"subject_type":' || to_json(audit_subject_type)::text
            || ',"tenant_id":' || to_json(audit_tenant_id)::text
            || ',"trace_id":null'
            || ',"work_item_id":null'
            || '}',
            'UTF8'
        )),
        'hex'
    )
$$;

CREATE OR REPLACE FUNCTION asf_assert_operational_incident_transition_receipt() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_transition text;
    expected_action text;
    expected_event_type text;
    expected_actor text;
    expected_correlation_id text;
    expected_before_digest text;
    expected_after_digest text;
    expected_audit_details jsonb;
BEGIN
    expected_transition := CASE
        WHEN OLD.status = 'OPEN' AND NEW.status = 'ACKNOWLEDGED' THEN 'ACKNOWLEDGE'
        WHEN OLD.status = 'ACKNOWLEDGED' AND NEW.status = 'RESOLVED' THEN 'RESOLVE'
        WHEN OLD.status = 'ACKNOWLEDGED' AND NEW.status = 'CANCELLED' THEN 'CANCEL'
        ELSE NULL
    END;
    expected_action := CASE expected_transition
        WHEN 'ACKNOWLEDGE' THEN 'OPERATIONAL_INCIDENT_ACKNOWLEDGED'
        WHEN 'RESOLVE' THEN 'OPERATIONAL_INCIDENT_RESOLVED'
        WHEN 'CANCEL' THEN 'OPERATIONAL_INCIDENT_CANCELLED'
    END;
    expected_event_type := CASE expected_transition
        WHEN 'ACKNOWLEDGE' THEN 'operational_incident.acknowledged'
        WHEN 'RESOLVE' THEN 'operational_incident.resolved'
        WHEN 'CANCEL' THEN 'operational_incident.cancelled'
    END;
    expected_actor := CASE
        WHEN expected_transition = 'ACKNOWLEDGE' THEN NEW.acknowledged_by
        ELSE NEW.closed_by
    END;
    expected_correlation_id :=
        'operational-incident:' || NEW.id::text || ':' || OLD.aggregate_version::text;
    expected_before_digest := asf_operational_incident_lifecycle_digest(
        OLD.id,
        OLD.tenant_id,
        OLD.workflow_job_id,
        OLD.status,
        OLD.aggregate_version,
        OLD.authority_or_effect_active,
        OLD.acknowledged_at,
        OLD.acknowledged_by,
        OLD.closed_at,
        OLD.closed_by,
        OLD.resolution
    );
    expected_after_digest := asf_operational_incident_lifecycle_digest(
        NEW.id,
        NEW.tenant_id,
        NEW.workflow_job_id,
        NEW.status,
        NEW.aggregate_version,
        NEW.authority_or_effect_active,
        NEW.acknowledged_at,
        NEW.acknowledged_by,
        NEW.closed_at,
        NEW.closed_by,
        NEW.resolution
    );
    expected_audit_details := jsonb_build_object(
        'schema', 'asf.operational-incident-transition-audit/v1',
        'operational_incident_id', NEW.id,
        'workflow_job_id', NEW.workflow_job_id,
        'transition', expected_transition,
        'from_status', OLD.status,
        'to_status', NEW.status,
        'expected_version', OLD.aggregate_version,
        'result_aggregate_version', NEW.aggregate_version,
        'request_digest', NULL,
        'resolution', NEW.resolution
    );

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
          AND receipt.request_digest =
              asf_operational_incident_transition_request_digest(
                  NEW.tenant_id,
                  NEW.id,
                  OLD.aggregate_version,
                  expected_transition,
                  expected_actor,
                  NEW.resolution
              )
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
          AND audit.work_item_id IS NULL
          AND audit.attempt_id IS NULL
          AND audit.actor_type = 'OPERATOR'
          AND audit.actor_id = expected_actor
          AND audit.action = expected_action
          AND audit.subject_type = 'OPERATIONAL_INCIDENT'
          AND audit.subject_id = NEW.id::text
          AND audit.correlation_id = expected_correlation_id
          AND audit.trace_id IS NULL
          AND audit.policy_digest IS NULL
          AND audit.before_digest = expected_before_digest
          AND audit.after_digest = expected_after_digest
          AND audit.details = jsonb_set(
              expected_audit_details,
              '{request_digest}',
              to_jsonb(receipt.request_digest)
          )
          AND audit.occurred_at = receipt.occurred_at
          AND audit.event_hash =
              asf_operational_incident_transition_audit_hash(
                  audit.id,
                  audit.tenant_id,
                  audit.actor_type,
                  audit.actor_id,
                  audit.action,
                  audit.subject_type,
                  audit.subject_id,
                  audit.correlation_id,
                  audit.before_digest,
                  audit.after_digest,
                  audit.previous_event_hash,
                  audit.occurred_at,
                  NEW.id,
                  NEW.workflow_job_id,
                  expected_transition,
                  OLD.status,
                  NEW.status,
                  OLD.aggregate_version,
                  NEW.aggregate_version,
                  receipt.request_digest,
                  NEW.resolution
              )
          AND outbox.topic = 'attention'
          AND outbox.message_key = NEW.id::text
          AND outbox.event_type = expected_event_type
          AND outbox.payload = jsonb_build_object(
              'schema', 'asf.operational-incident-lifecycle-event/v1',
              'tenant_id', NEW.tenant_id,
              'operational_incident_id', NEW.id,
              'workflow_job_id', NEW.workflow_job_id,
              'transition', expected_transition,
              'status', NEW.status,
              'actor', expected_actor,
              'expected_version', OLD.aggregate_version,
              'aggregate_version', NEW.aggregate_version,
              'request_digest', receipt.request_digest,
              'resolution', NEW.resolution,
              'audit_event_id', receipt.audit_event_id,
              'occurred_at', asf_chrono_utc(receipt.occurred_at)
          )
          AND outbox.headers =
              '{"schema":"asf.operational-incident-lifecycle-event/v1"}'::jsonb
          AND outbox.idempotency_key = expected_correlation_id || ':outbox'
          AND outbox.available_at = receipt.occurred_at
          AND outbox.status = 'PENDING'
          AND outbox.attempt_count = 0
          AND outbox.fence_token = 0
          AND outbox.lease_owner IS NULL
          AND outbox.lease_expires_at IS NULL
          AND outbox.last_error IS NULL
          AND outbox.published_at IS NULL
    ) THEN
        RAISE EXCEPTION 'operational incident transition has no exact immutable receipt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

-- The job-side deferred proof is necessary but not reciprocal: before this
-- guard, an internal writer could pre-insert an incident for a live job and
-- permanently occupy the unique job/category and idempotency slots.  Every
-- newly inserted incident must itself finish the transaction owned by its
-- exact, tenant-scoped, unbound DEAD job.
ALTER TABLE operational_incidents
    ADD CONSTRAINT operational_incidents_exact_job_idempotency CHECK (
        idempotency_key =
            'operational-job-exhausted:' || workflow_job_id::text
    );

CREATE FUNCTION asf_assert_operational_incident_dead_job_owner() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_jobs AS job
        WHERE job.tenant_id = NEW.tenant_id
          AND job.id = NEW.workflow_job_id
          AND job.workflow_instance_id IS NULL
          AND job.work_item_id IS NULL
          AND job.attempt_id IS NULL
          AND job.status = 'DEAD'
          AND job.dead_letter_escalation_id IS NULL
          AND job.dead_letter_operational_incident_id = NEW.id
          AND NEW.category = 'WORKFLOW_JOB_EXHAUSTED'
          AND NEW.status = 'OPEN'
          AND NEW.authority_or_effect_active
          AND NEW.idempotency_key =
              'operational-job-exhausted:' || NEW.workflow_job_id::text
          AND NEW.evidence_references @>
              jsonb_build_array('workflow-job:' || NEW.workflow_job_id::text)
    ) THEN
        RAISE EXCEPTION 'operational incident % has no exact unbound DEAD workflow-job owner', NEW.id
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER operational_incidents_require_dead_job_owner
    AFTER INSERT ON operational_incidents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_operational_incident_dead_job_owner();
