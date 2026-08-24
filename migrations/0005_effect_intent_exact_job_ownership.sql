-- A workflow-job lease owner and fence token are not a globally unique claim:
-- different jobs claimed by one reactor can carry the same pair.  Persist the
-- exact owning job for the only externally-mutating effect currently executed
-- by ASF so recovery can distinguish a live owner from a replacement job.
-- Apply this migration with executors quiesced: old binaries cannot populate
-- the new ownership field.  Lock jobs before effects to preserve the runtime
-- recovery order for any transaction already draining.
LOCK TABLE workflow_jobs IN EXCLUSIVE MODE;
LOCK TABLE effect_intents IN ACCESS EXCLUSIVE MODE;

ALTER TABLE effect_intents
    ADD COLUMN owning_workflow_job_id uuid;

-- Older deployments did not record an exact owner.  An in-flight request may
-- already have reached Runmill, so preserve its immutable request and route it
-- through the ambiguous-outcome reconciliation path instead of guessing among
-- jobs that happen to share an owner/fence pair.
UPDATE effect_intents
SET status = 'AMBIGUOUS',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error = left(
        concat_ws(
            '; ',
            NULLIF(last_error, ''),
            'migration requires exact workflow-job ownership; reconcile the unchanged request'
        ),
        8192
    ),
    updated_at = clock_timestamp()
WHERE provider = 'runmill'
  AND effect_type = 'request_cancellation'
  AND status = 'IN_FLIGHT';

ALTER TABLE effect_intents
    ADD CONSTRAINT effect_intents_owning_workflow_job_fk
    FOREIGN KEY (tenant_id, owning_workflow_job_id)
    REFERENCES workflow_jobs(tenant_id, id)
    MATCH SIMPLE ON DELETE RESTRICT,
    ADD CONSTRAINT effect_intents_cancellation_owner_shape CHECK (
        (
            provider = 'runmill'
            AND effect_type = 'request_cancellation'
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
            (provider <> 'runmill' OR effect_type <> 'request_cancellation')
            AND owning_workflow_job_id IS NULL
        )
    );

CREATE INDEX effect_intents_owning_workflow_job_idx
    ON effect_intents (tenant_id, owning_workflow_job_id)
    WHERE owning_workflow_job_id IS NOT NULL;

CREATE FUNCTION asf_guard_cancellation_effect_owner() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider = 'runmill'
       AND NEW.effect_type = 'request_cancellation'
       AND NEW.status = 'IN_FLIGHT' THEN
        IF NEW.owning_workflow_job_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM workflow_jobs AS owning_job
            WHERE owning_job.tenant_id = NEW.tenant_id
              AND owning_job.id = NEW.owning_workflow_job_id
              AND owning_job.workflow_instance_id IS NOT NULL
              AND owning_job.work_item_id = NEW.work_item_id
              AND owning_job.attempt_id = NEW.attempt_id
              AND owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
              AND owning_job.status = 'RUNNING'
              AND owning_job.lease_owner = NEW.lease_owner
              AND owning_job.fence_token = NEW.fence_token
              AND owning_job.lease_expires_at > clock_timestamp()
        ) THEN
            RAISE EXCEPTION 'Runmill cancellation effect has no exact live owning workflow job'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'effect_intents_exact_cancellation_owner';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER effect_intents_exact_cancellation_owner
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_cancellation_effect_owner();
