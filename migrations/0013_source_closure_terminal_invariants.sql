-- A CLOSED Linear work item is an authority-bearing terminal receipt, not
-- merely an aggregate state.  Preserve the complete chain from the immutable
-- source and Work Order through the exact run/evidence/verification and the
-- one completed CLOSE_SOURCE claim that observed the provider receipt.
--
-- Apply with executors quiesced.  Jobs are locked first to match the runtime's
-- recovery order; the remaining locks exclude every writer while reciprocal
-- deferred guards are installed.
LOCK TABLE workflow_jobs IN EXCLUSIVE MODE;
LOCK TABLE workflow_instances IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE repositories IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE reservation_sets IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE approvals IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE accountability_anchors IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE effect_intents IN ACCESS EXCLUSIVE MODE;

-- The pre-0013 schema retained only an in-flight owner.  Once an effect became
-- OBSERVED that owner was cleared, so neither timestamps nor payload contents
-- can identify which completed claim performed the observation.  Never infer
-- terminal provenance from non-unique owner/fence values.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM effect_intents
        WHERE provider = 'linear'
          AND effect_type = 'close_source'
          AND status = 'OBSERVED'
    ) OR EXISTS (
        SELECT 1
        FROM work_items
        WHERE state = 'CLOSED'
    ) THEN
        RAISE EXCEPTION
            'historical source-closure observing-job provenance cannot be reconstructed safely'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'source_closure_requires_exact_observing_job_provenance';
    END IF;
END;
$$;

-- A completion fence is the claim fence captured by the owner that completed
-- the job.  Include both columns in the parent key and repeat the effect's one
-- observing fence in the child FK, proving their equality without imposing a
-- global payload validator on unrelated workflow jobs.
ALTER TABLE workflow_jobs
    ADD CONSTRAINT workflow_jobs_source_closure_receipt_key
    UNIQUE (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        job_type,
        status,
        fence_token,
        completion_fence_token,
        completed_by
    );

ALTER TABLE effect_intents
    ADD COLUMN observing_workflow_job_id uuid,
    ADD COLUMN observing_workflow_job_fence_token bigint,
    ADD COLUMN observing_workflow_job_completed_by text,
    ADD COLUMN observing_workflow_job_type text GENERATED ALWAYS AS (
        CASE
            WHEN observing_workflow_job_id IS NOT NULL THEN 'CLOSE_SOURCE'::text
            ELSE NULL
        END
    ) STORED,
    ADD COLUMN observing_workflow_job_status text GENERATED ALWAYS AS (
        CASE
            WHEN observing_workflow_job_id IS NOT NULL THEN 'COMPLETED'::text
            ELSE NULL
        END
    ) STORED,
    ADD CONSTRAINT effect_intents_source_close_observing_job_shape CHECK (
        (
            provider = 'linear'
            AND effect_type = 'close_source'
            AND status = 'OBSERVED'
            AND observing_workflow_job_id IS NOT NULL
            AND observing_workflow_job_fence_token > 0
            AND observing_workflow_job_completed_by IS NOT NULL
            AND btrim(observing_workflow_job_completed_by) =
                observing_workflow_job_completed_by
            AND observing_workflow_job_completed_by <> ''
            AND length(observing_workflow_job_completed_by) <= 512
        )
        OR (
            NOT (
                provider = 'linear'
                AND effect_type = 'close_source'
                AND status = 'OBSERVED'
            )
            AND observing_workflow_job_id IS NULL
            AND observing_workflow_job_fence_token IS NULL
            AND observing_workflow_job_completed_by IS NULL
        )
    ),
    ADD CONSTRAINT effect_intents_one_source_close_receipt_per_job
        UNIQUE (tenant_id, observing_workflow_job_id),
    ADD CONSTRAINT effect_intents_exact_source_close_observing_job_fk
        FOREIGN KEY (
            tenant_id,
            observing_workflow_job_id,
            work_item_id,
            attempt_id,
            observing_workflow_job_type,
            observing_workflow_job_status,
            observing_workflow_job_fence_token,
            observing_workflow_job_fence_token,
            observing_workflow_job_completed_by
        )
        REFERENCES workflow_jobs (
            tenant_id,
            id,
            work_item_id,
            attempt_id,
            job_type,
            status,
            fence_token,
            completion_fence_token,
            completed_by
        )
        MATCH SIMPLE ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX effect_intents_observing_workflow_job_idx
    ON effect_intents (tenant_id, observing_workflow_job_id)
    WHERE observing_workflow_job_id IS NOT NULL;

-- OBSERVED is reached only by transitioning an existing durable request.  A
-- direct terminal insertion has no proof that the immutable request preceded
-- provider I/O.  An in-flight observation must retain its exact live owner;
-- an ambiguous reconciliation may be completed by a later exact claim.
CREATE FUNCTION asf_guard_source_close_observation_transition() RETURNS trigger
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

CREATE TRIGGER effect_intents_source_close_observation_transition
    BEFORE INSERT OR UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_source_close_observation_transition();

-- A terminal CLOSE_SOURCE row is itself an authority receipt.  It may only be
-- captured from the exact RUNNING claim whose owner/fence observed the source
-- effect; a direct PENDING/RETRY-to-COMPLETED rewrite cannot fabricate proof.
CREATE FUNCTION asf_guard_source_close_job_completion() RETURNS trigger
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

CREATE TRIGGER workflow_jobs_exact_source_close_completion
    BEFORE UPDATE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_guard_source_close_job_completion();

-- Malformed timestamp/JSON projections are false proof rather than a cast
-- error that could obscure which terminal invariant failed.
CREATE FUNCTION asf_source_closure_timestamp(candidate text) RETURNS timestamptz
LANGUAGE plpgsql STABLE STRICT
AS $$
BEGIN
    IF length(candidate) > 64
       OR candidate !~ (
           '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]'
           || '[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?'
           || '([Zz]|[+-][0-9]{2}:[0-9]{2})$'
       ) THEN
        RETURN NULL;
    END IF;
    RETURN candidate::timestamptz;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE FUNCTION asf_source_closure_json(candidate bytea) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT
AS $$
BEGIN
    RETURN convert_from(candidate, 'UTF8')::jsonb;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE FUNCTION asf_source_closure_bigint(candidate text) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT
AS $$
BEGIN
    RETURN candidate::bigint;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- The source-close request/effect/receipt/result protocols use RFC 8785
-- canonical JSON and contain only integer JSON numbers plus ASCII field names.
-- This renderer is byte-identical for those strict shapes and lets the
-- terminal predicate derive their digests.  Do not use it to reproduce full
-- Work Order or evidence bytes: those contracts contain f64 fields whose JCS
-- rendering cannot be reconstructed from PostgreSQL jsonb (for example 10.0
-- and 10 have the same jsonb value but different pre-JCS spelling).
CREATE FUNCTION asf_source_closure_canonical_json_text(candidate jsonb)
RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT
AS $$
DECLARE
    rendered text;
BEGIN
    CASE jsonb_typeof(candidate)
        WHEN 'object' THEN
            SELECT '{' || COALESCE(string_agg(
                to_jsonb(member.key)::text || ':' ||
                    asf_source_closure_canonical_json_text(member.value),
                ',' ORDER BY member.key COLLATE "C"
            ), '') || '}'
            INTO rendered
            FROM jsonb_each(candidate) AS member;
        WHEN 'array' THEN
            SELECT '[' || COALESCE(string_agg(
                asf_source_closure_canonical_json_text(element.value),
                ',' ORDER BY element.ordinality
            ), '') || ']'
            INTO rendered
            FROM jsonb_array_elements(candidate) WITH ORDINALITY
                AS element(value, ordinality);
        ELSE
            rendered := candidate::text;
    END CASE;
    RETURN rendered;
END;
$$;

CREATE FUNCTION asf_source_closure_digest(candidate jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT 'sha256:' || encode(
        sha256(convert_to(asf_source_closure_canonical_json_text(candidate), 'UTF8')),
        'hex'
    )
$$;

-- Reconstruct the whole terminal fact.  JSON validation is deliberately
-- scoped to the one referenced CLOSE_SOURCE job and its one observed effect;
-- unrelated or malformed queue data remains insertable and will be rejected
-- only if somebody tries to use it as closure authority.
CREATE OR REPLACE FUNCTION asf_observed_source_closure_is_valid(
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

-- The work row is the serialization point for closure and every reciprocal
-- proof/negative-child mutation.  This closes the absence-check write skew:
-- a late approval, cancellation, escalation, or reservation must order before
-- or after the transaction that makes the work CLOSED.
CREATE FUNCTION asf_assert_source_closure_for_work(
    candidate_tenant uuid,
    candidate_work_item uuid
) RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    candidate_state text;
BEGIN
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
        RAISE EXCEPTION 'closed work item has no exact terminal source-closure proof'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'work_items_require_observed_source_closure';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION asf_assert_observed_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'CLOSED' THEN
        PERFORM asf_assert_source_closure_for_work(NEW.tenant_id, NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

-- An OBSERVED close effect is itself terminal authority and therefore must
-- commit atomically with the CLOSED aggregate/workflow/completed-job receipt.
CREATE FUNCTION asf_assert_exact_source_close_observation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider = 'linear'
       AND NEW.effect_type = 'close_source'
       AND NEW.status = 'OBSERVED'
       AND NOT asf_observed_source_closure_is_valid(
           NEW.tenant_id,
           NEW.work_item_id
       ) THEN
        RAISE EXCEPTION
            'observed source-close effect lacks its exact completed workflow claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'effect_intents_require_exact_source_close_observation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER effect_intents_require_exact_source_close_observation
    AFTER INSERT OR UPDATE ON effect_intents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_exact_source_close_observation();

-- Direct work-scoped children share one targeted reciprocal guard.  Unrelated
-- job/effect kinds return before taking the work serialization lock.
CREATE FUNCTION asf_assert_direct_child_preserves_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_row jsonb := '{}'::jsonb;
    new_row jsonb := '{}'::jsonb;
    old_tenant uuid;
    old_work uuid;
    new_tenant uuid;
    new_work uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_row := to_jsonb(OLD);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_row := to_jsonb(NEW);
    END IF;

    IF TG_TABLE_NAME = 'workflow_jobs'
       AND COALESCE(old_row ->> 'job_type', '') NOT IN (
           'CLOSE_SOURCE',
           'REQUEST_WORK_ITEM_CANCELLATION'
       )
       AND COALESCE(new_row ->> 'job_type', '') NOT IN (
           'CLOSE_SOURCE',
           'REQUEST_WORK_ITEM_CANCELLATION'
       ) THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'workflow_instances'
       AND COALESCE(old_row ->> 'workflow_type', '') <> 'WORK_ITEM_DELIVERY'
       AND COALESCE(new_row ->> 'workflow_type', '') <> 'WORK_ITEM_DELIVERY' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'effect_intents'
       AND NOT (
           COALESCE(old_row ->> 'effect_type', '') IN (
               'close_source',
               'request_cancellation'
           )
           OR COALESCE(new_row ->> 'effect_type', '') IN (
               'close_source',
               'request_cancellation'
           )
       ) THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'attempts'
       AND COALESCE(old_row ->> 'state', '') <> 'SUCCEEDED'
       AND COALESCE(new_row ->> 'state', '') <> 'SUCCEEDED' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'reservation_sets'
       AND COALESCE(old_row ->> 'state', '') <> 'ACTIVE'
       AND COALESCE(new_row ->> 'state', '') <> 'ACTIVE' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'approvals'
       AND (
           TG_OP = 'DELETE'
           OR COALESCE(new_row ->> 'status', '') = 'APPROVED'
       ) THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'escalations'
       AND (
           TG_OP = 'DELETE'
           OR COALESCE((new_row ->> 'authority_or_effect_active')::boolean, false)
               IS NOT TRUE
       ) THEN
        RETURN NULL;
    END IF;

    old_tenant := NULLIF(old_row ->> 'tenant_id', '')::uuid;
    old_work := NULLIF(old_row ->> 'work_item_id', '')::uuid;
    new_tenant := NULLIF(new_row ->> 'tenant_id', '')::uuid;
    new_work := NULLIF(new_row ->> 'work_item_id', '')::uuid;

    IF old_tenant IS NOT NULL AND old_work IS NOT NULL THEN
        PERFORM asf_assert_source_closure_for_work(old_tenant, old_work);
    END IF;
    IF new_tenant IS NOT NULL
       AND new_work IS NOT NULL
       AND ROW(new_tenant, new_work) IS DISTINCT FROM ROW(old_tenant, old_work) THEN
        PERFORM asf_assert_source_closure_for_work(new_tenant, new_work);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER attempts_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER workflow_instances_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON workflow_instances
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER workflow_jobs_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON workflow_jobs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER reservation_sets_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON reservation_sets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER approvals_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON approvals
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER escalations_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON escalations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

CREATE CONSTRAINT TRIGGER effect_intents_preserve_observed_source_closure
    AFTER INSERT OR UPDATE OR DELETE ON effect_intents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_direct_child_preserves_source_closure();

-- Runs and accountability anchors already had reciprocal guards.  Replacing
-- their functions retains the public constraint names while adding the common
-- work-row serialization point and the strengthened predicate.
CREATE OR REPLACE FUNCTION asf_assert_run_preserves_observed_source_closure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(
           NEW.tenant_id,
           NEW.id,
           NEW.work_item_id,
           NEW.attempt_id,
           NEW.work_order_id,
           NEW.worker_id,
           NEW.worker_generation,
           NEW.worker_session_id,
           NEW.evidence_expectation_digest,
           NEW.external_run_id,
           NEW.authoritative,
           NEW.state,
           NEW.adopted_at,
           NEW.terminal_at
       ) IS NOT DISTINCT FROM ROW(
           OLD.tenant_id,
           OLD.id,
           OLD.work_item_id,
           OLD.attempt_id,
           OLD.work_order_id,
           OLD.worker_id,
           OLD.worker_generation,
           OLD.worker_session_id,
           OLD.evidence_expectation_digest,
           OLD.external_run_id,
           OLD.authoritative,
           OLD.state,
           OLD.adopted_at,
           OLD.terminal_at
       ) THEN
        RETURN NULL;
    END IF;

    FOR candidate IN
        SELECT DISTINCT work.tenant_id, work.id
        FROM evidence_bundles AS evidence
        JOIN work_items AS work
          ON work.tenant_id = evidence.tenant_id
         AND work.id = evidence.work_item_id
        WHERE evidence.tenant_id = OLD.tenant_id
          AND evidence.run_id = OLD.id
    LOOP
        PERFORM asf_assert_source_closure_for_work(
            candidate.tenant_id,
            candidate.id
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION asf_assert_anchor_preserves_observed_source_closure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.anchor_type <> 'CLOSURE' THEN
        RETURN NULL;
    ELSIF TG_OP = 'DELETE' AND OLD.anchor_type <> 'CLOSURE' THEN
        RETURN NULL;
    ELSIF TG_OP = 'UPDATE'
          AND OLD.anchor_type <> 'CLOSURE'
          AND NEW.anchor_type <> 'CLOSURE' THEN
        RETURN NULL;
    END IF;

    IF TG_OP <> 'INSERT' THEN
        PERFORM asf_assert_source_closure_for_work(OLD.tenant_id, OLD.work_item_id);
    END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM asf_assert_source_closure_for_work(NEW.tenant_id, NEW.work_item_id);
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.tenant_id, NEW.work_item_id) IS DISTINCT FROM
           ROW(OLD.tenant_id, OLD.work_item_id) THEN
            PERFORM asf_assert_source_closure_for_work(
                NEW.tenant_id,
                NEW.work_item_id
            );
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION asf_assert_repository_preserves_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(NEW.tenant_id, NEW.id, NEW.forge, NEW.owner, NEW.name)
           IS NOT DISTINCT FROM
           ROW(OLD.tenant_id, OLD.id, OLD.forge, OLD.owner, OLD.name) THEN
        RETURN NULL;
    END IF;

    FOR candidate IN
        SELECT work.tenant_id, work.id
        FROM work_items AS work
        WHERE work.repository_id = OLD.id
          AND work.tenant_id = OLD.tenant_id
    LOOP
        PERFORM asf_assert_source_closure_for_work(
            candidate.tenant_id,
            candidate.id
        );
    END LOOP;
    IF TG_OP = 'UPDATE'
       AND ROW(NEW.tenant_id, NEW.id) IS DISTINCT FROM ROW(OLD.tenant_id, OLD.id) THEN
        FOR candidate IN
            SELECT work.tenant_id, work.id
            FROM work_items AS work
            WHERE work.repository_id = NEW.id
              AND work.tenant_id = NEW.tenant_id
        LOOP
            PERFORM asf_assert_source_closure_for_work(
                candidate.tenant_id,
                candidate.id
            );
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER repositories_preserve_observed_source_closure
    AFTER UPDATE OR DELETE ON repositories
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_repository_preserves_source_closure();

CREATE FUNCTION asf_assert_worker_preserves_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(NEW.tenant_id, NEW.id) IS NOT DISTINCT FROM
           ROW(OLD.tenant_id, OLD.id) THEN
        RETURN NULL;
    END IF;

    FOR candidate IN
        SELECT DISTINCT work.tenant_id, work.id
        FROM runs AS run
        JOIN work_items AS work
          ON work.tenant_id = run.tenant_id
         AND work.id = run.work_item_id
         AND work.current_attempt_id = run.attempt_id
        WHERE run.tenant_id = OLD.tenant_id
          AND run.worker_id = OLD.id
    LOOP
        PERFORM asf_assert_source_closure_for_work(candidate.tenant_id, candidate.id);
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workers_preserve_observed_source_closure
    AFTER UPDATE OR DELETE ON workers
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_worker_preserves_source_closure();

CREATE FUNCTION asf_assert_worker_session_preserves_source_closure() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate record;
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(
           NEW.tenant_id,
           NEW.id,
           NEW.worker_id,
           NEW.worker_generation,
           NEW.signing_key_id,
           NEW.started_at,
           NEW.expires_at,
           NEW.closed_at
       ) IS NOT DISTINCT FROM ROW(
           OLD.tenant_id,
           OLD.id,
           OLD.worker_id,
           OLD.worker_generation,
           OLD.signing_key_id,
           OLD.started_at,
           OLD.expires_at,
           OLD.closed_at
       ) THEN
        RETURN NULL;
    END IF;

    FOR candidate IN
        SELECT DISTINCT work.tenant_id, work.id
        FROM runs AS run
        JOIN work_items AS work
          ON work.tenant_id = run.tenant_id
         AND work.id = run.work_item_id
         AND work.current_attempt_id = run.attempt_id
        WHERE run.tenant_id = OLD.tenant_id
          AND run.worker_session_id = OLD.id
    LOOP
        PERFORM asf_assert_source_closure_for_work(candidate.tenant_id, candidate.id);
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER worker_sessions_preserve_observed_source_closure
    AFTER UPDATE OR DELETE ON worker_sessions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_worker_session_preserves_source_closure();
