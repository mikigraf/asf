-- A VALID evidence decision is authority-bearing: source closure may trust it
-- only when it is the immutable receipt of the exact completed
-- VERIFY_EVIDENCE claim that independently observed the forge state.
--
-- The pre-0014 schema did not record job provenance.  No combination of
-- evidence, verifier, or timestamps can reconstruct which leased claim made a
-- historical decision, so refuse any non-empty upgrade instead of guessing.
-- Runtime claim paths lock jobs before run/evidence state.  Use the same
-- direction while excluding every writer that could race provenance checks.
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_verifications IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM evidence_verifications) THEN
        RAISE EXCEPTION
            'historical evidence-verification job provenance cannot be reconstructed safely'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_verifications_require_exact_job_provenance';
    END IF;
END;
$$;

-- These parent keys make every repeated coordinate relational rather than an
-- application convention.  Evidence and terminal workflow jobs are already
-- append-only/immutable; runs receive a reciprocal guard below.
ALTER TABLE evidence_bundles
    ADD CONSTRAINT evidence_bundles_verification_receipt_key
    UNIQUE (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        run_id,
        payload_digest,
        work_order_digest
    );

ALTER TABLE runs
    ADD CONSTRAINT runs_verification_receipt_key
    UNIQUE (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        evidence_expectation_digest
    );

ALTER TABLE workflow_jobs
    ADD CONSTRAINT workflow_jobs_completed_claim_fence_exact CHECK (
        status <> 'COMPLETED'
        OR completion_fence_token = fence_token
    ),
    ADD CONSTRAINT workflow_jobs_verification_receipt_key
    UNIQUE (
        tenant_id,
        id,
        work_item_id,
        attempt_id,
        job_type,
        status,
        completion_fence_token,
        completed_by
    );

ALTER TABLE evidence_verifications
    ADD COLUMN work_item_id uuid NOT NULL,
    ADD COLUMN attempt_id uuid NOT NULL,
    ADD COLUMN run_id uuid NOT NULL,
    ADD COLUMN evidence_digest text NOT NULL
        CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN work_order_digest text NOT NULL
        CHECK (work_order_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN workflow_job_id uuid NOT NULL,
    ADD COLUMN workflow_job_fence_token bigint NOT NULL
        CHECK (workflow_job_fence_token > 0),
    ADD COLUMN workflow_job_completed_by text NOT NULL
        CHECK (
            btrim(workflow_job_completed_by) <> ''
            AND length(workflow_job_completed_by) <= 512
        ),
    ADD COLUMN workflow_job_type text
        GENERATED ALWAYS AS ('VERIFY_EVIDENCE'::text) STORED,
    ADD COLUMN workflow_job_status text
        GENERATED ALWAYS AS ('COMPLETED'::text) STORED,
    ADD CONSTRAINT evidence_verifications_job_once
        UNIQUE (tenant_id, workflow_job_id),
    ADD CONSTRAINT evidence_verifications_exact_evidence_fk
        FOREIGN KEY (
            tenant_id,
            evidence_id,
            work_item_id,
            attempt_id,
            run_id,
            evidence_digest,
            work_order_digest
        )
        REFERENCES evidence_bundles (
            tenant_id,
            id,
            work_item_id,
            attempt_id,
            run_id,
            payload_digest,
            work_order_digest
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT evidence_verifications_exact_run_fk
        FOREIGN KEY (
            tenant_id,
            run_id,
            work_item_id,
            attempt_id,
            expectation_digest
        )
        REFERENCES runs (
            tenant_id,
            id,
            work_item_id,
            attempt_id,
            evidence_expectation_digest
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT evidence_verifications_exact_completed_job_fk
        FOREIGN KEY (
            tenant_id,
            workflow_job_id,
            work_item_id,
            attempt_id,
            workflow_job_type,
            workflow_job_status,
            workflow_job_fence_token,
            workflow_job_completed_by
        )
        REFERENCES workflow_jobs (
            tenant_id,
            id,
            work_item_id,
            attempt_id,
            job_type,
            status,
            completion_fence_token,
            completed_by
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT evidence_verifications_valid_details_exact CHECK (
        status <> 'VALID'
        OR COALESCE((
            jsonb_typeof(details -> 'schema') = 'string'
            AND jsonb_typeof(details -> 'evidence_id') = 'string'
            AND jsonb_typeof(details -> 'work_item_id') = 'string'
            AND jsonb_typeof(details -> 'attempt_id') = 'string'
            AND jsonb_typeof(details -> 'run_id') = 'string'
            AND jsonb_typeof(details -> 'evidence_digest') = 'string'
            AND jsonb_typeof(details -> 'work_order_digest') = 'string'
            AND jsonb_typeof(details -> 'expectation_digest') = 'string'
            AND jsonb_typeof(details -> 'verification_job_id') = 'string'
            AND jsonb_typeof(details -> 'verification_job_completed_by') = 'string'
            AND jsonb_typeof(details -> 'verifier') = 'string'
            AND jsonb_typeof(details -> 'provider_revision') = 'string'
            AND jsonb_typeof(details -> 'observed_at') = 'string'
            AND details ->> 'schema' = 'asf.evidence-verification-receipt.v1'
            AND details ->> 'evidence_id' = evidence_id::text
            AND details ->> 'work_item_id' = work_item_id::text
            AND details ->> 'attempt_id' = attempt_id::text
            AND details ->> 'run_id' = run_id::text
            AND details ->> 'evidence_digest' = evidence_digest
            AND details ->> 'work_order_digest' = work_order_digest
            AND details ->> 'expectation_digest' = expectation_digest
            AND details ->> 'verification_job_id' = workflow_job_id::text
            AND jsonb_typeof(details -> 'verification_job_fence_token') = 'number'
            AND details ->> 'verification_job_fence_token' =
                workflow_job_fence_token::text
            AND details ->> 'verification_job_completed_by' =
                workflow_job_completed_by
            AND details ->> 'verifier' = verifier
            AND btrim(details ->> 'verification_job_completed_by') =
                details ->> 'verification_job_completed_by'
            AND btrim(details ->> 'verifier') = details ->> 'verifier'
            AND length(details ->> 'verifier') <= 256
            AND jsonb_typeof(details -> 'pull_request') = 'object'
            AND (details -> 'pull_request') - ARRAY[
                'repository',
                'number',
                'url',
                'base_sha',
                'head_sha',
                'required_ci_contexts',
                'successful_ci_contexts'
            ]::text[] = '{}'::jsonb
            AND jsonb_typeof(details #> '{pull_request,repository}') = 'string'
            AND jsonb_typeof(details #> '{pull_request,number}') = 'number'
            AND jsonb_typeof(details #> '{pull_request,url}') = 'string'
            AND jsonb_typeof(details #> '{pull_request,base_sha}') = 'string'
            AND jsonb_typeof(details #> '{pull_request,head_sha}') = 'string'
            AND jsonb_typeof(details #> '{pull_request,required_ci_contexts}') = 'array'
            AND jsonb_typeof(details #> '{pull_request,successful_ci_contexts}') = 'array'
            AND details #>> '{pull_request,repository}' ~
                '^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$'
            AND details #>> '{pull_request,number}' ~ '^[1-9][0-9]*$'
            AND details #>> '{pull_request,url}' ~ '^https://[^[:space:]]+$'
            AND details #>> '{pull_request,base_sha}' ~ '^[0-9a-f]{40}$'
            AND details #>> '{pull_request,head_sha}' ~ '^[0-9a-f]{40}$'
            AND btrim(details ->> 'provider_revision') =
                details ->> 'provider_revision'
            AND details ->> 'provider_revision' <> ''
            AND length(details ->> 'provider_revision') <= 1024
            AND btrim(details ->> 'observed_at') = details ->> 'observed_at'
            AND details ->> 'observed_at' <> ''
            AND details - ARRAY[
                'schema',
                'evidence_id',
                'work_item_id',
                'attempt_id',
                'run_id',
                'evidence_digest',
                'work_order_digest',
                'expectation_digest',
                'verification_job_id',
                'verification_job_fence_token',
                'verification_job_completed_by',
                'verifier',
                'pull_request',
                'provider_revision',
                'observed_at'
            ]::text[] = '{}'::jsonb
        ), false)
    );

-- Declarative keys prove row identity.  This predicate additionally proves
-- the immutable VERIFY_EVIDENCE request body and the strict VALID receipt are
-- the same fact.  It deliberately examines only the referenced job, so an
-- unrelated or not-yet-validated malformed payload remains ordinary queue
-- data and is handled by its activity rather than by a global insert trigger.
CREATE FUNCTION asf_valid_evidence_verification_is_exact(
    candidate_tenant uuid,
    candidate_verification uuid
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
BEGIN
    -- FOR SHARE closes the write-skew window with a concurrent non-key update
    -- of run authority/state.  Whichever transaction obtains the parent lock
    -- first forces the other side to validate against its committed result.
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
     AND job.status = verification.workflow_job_status
     AND job.completion_fence_token =
         verification.workflow_job_fence_token
     AND job.fence_token = verification.workflow_job_fence_token
     AND job.completed_by = verification.workflow_job_completed_by
    WHERE verification.tenant_id = candidate_tenant
      AND verification.id = candidate_verification
      AND verification.status = 'VALID'
      AND job.payload - ARRAY[
          'evidence_id',
          'run_id',
          'payload_digest',
          'work_order_digest',
          'expectation_digest'
      ]::text[] = '{}'::jsonb
      AND job.payload ->> 'evidence_id' = verification.evidence_id::text
      AND job.payload ->> 'run_id' = verification.run_id::text
      AND job.payload ->> 'payload_digest' = verification.evidence_digest
      AND job.payload ->> 'work_order_digest' = verification.work_order_digest
      AND job.payload ->> 'expectation_digest' = verification.expectation_digest
      AND verification.details ->> 'verification_job_id' = job.id::text
      AND verification.details ->> 'verification_job_fence_token' =
          job.completion_fence_token::text
      AND verification.details ->> 'verification_job_completed_by' =
          job.completed_by
      AND verification.details ->> 'evidence_id' = evidence.id::text
      AND verification.details ->> 'run_id' = run.id::text
      AND verification.details ->> 'expectation_digest' =
          run.evidence_expectation_digest
      AND run.authoritative
      AND run.state = 'SUCCEEDED'
      AND evidence.target_satisfied
    FOR SHARE OF evidence, run, job;

    RETURN FOUND;
END;
$$;

CREATE FUNCTION asf_assert_valid_evidence_verification_exact() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'VALID'
       AND NOT asf_valid_evidence_verification_is_exact(NEW.tenant_id, NEW.id) THEN
        RAISE EXCEPTION
            'VALID evidence verification lacks its exact completed VERIFY_EVIDENCE claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_verifications_require_exact_completed_job';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_verifications_require_exact_completed_job
    AFTER INSERT OR UPDATE ON evidence_verifications
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_valid_evidence_verification_exact();

CREATE FUNCTION asf_assert_job_preserves_valid_evidence_verification() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_verifications AS verification
        WHERE verification.tenant_id = OLD.tenant_id
          AND verification.workflow_job_id = OLD.id
          AND verification.status = 'VALID'
          AND NOT asf_valid_evidence_verification_is_exact(
              verification.tenant_id,
              verification.id
          )
    ) THEN
        RAISE EXCEPTION 'workflow-job mutation would sever a VALID evidence-verification receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_jobs_preserve_valid_evidence_verifications';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_jobs_preserve_valid_evidence_verifications
    AFTER UPDATE OR DELETE ON workflow_jobs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_job_preserves_valid_evidence_verification();

CREATE FUNCTION asf_assert_evidence_preserves_valid_verification() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_verifications AS verification
        WHERE verification.tenant_id = OLD.tenant_id
          AND verification.evidence_id = OLD.id
          AND verification.status = 'VALID'
          AND NOT asf_valid_evidence_verification_is_exact(
              verification.tenant_id,
              verification.id
          )
    ) THEN
        RAISE EXCEPTION 'evidence mutation would sever a VALID verification receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_bundles_preserve_valid_verifications';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_bundles_preserve_valid_verifications
    AFTER UPDATE OR DELETE ON evidence_bundles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_evidence_preserves_valid_verification();

CREATE FUNCTION asf_assert_run_preserves_valid_evidence_verification() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_verifications AS verification
        WHERE verification.tenant_id = OLD.tenant_id
          AND verification.run_id = OLD.id
          AND verification.status = 'VALID'
          AND NOT asf_valid_evidence_verification_is_exact(
              verification.tenant_id,
              verification.id
          )
    ) THEN
        RAISE EXCEPTION 'run mutation would sever a VALID evidence-verification receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runs_preserve_valid_evidence_verifications';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER runs_preserve_valid_evidence_verifications
    AFTER UPDATE OR DELETE ON runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_run_preserves_valid_evidence_verification();
