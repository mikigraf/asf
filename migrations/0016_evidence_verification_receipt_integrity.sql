-- A VALID evidence-verification row is a durable statement that ASF observed
-- one exact GitHub pull request and completed one exact VERIFY_EVIDENCE claim.
-- 0014 established relational ownership, but its permissive JSON predicates
-- did not fully reproduce the Rust receipt contract or prove when the
-- observation and verification occurred.  Tighten that invariant in place so
-- the existing reciprocal parent guards automatically use the stronger proof.
--
-- Apply with executors quiesced.  Keep the established job-first lock order
-- and exclude receipt writers while the stricter predicate is installed and
-- historical VALID rows are checked.
LOCK TABLE workflow_jobs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_verifications IN ACCESS EXCLUSIVE MODE;

-- Match Rust's public-text rules: a bounded UTF-8 byte length, no leading or
-- trailing Unicode White_Space, no Unicode Cc control character, and no
-- credential-shaped portable-evidence value.
CREATE FUNCTION asf_evidence_verification_public_text(
    candidate text,
    maximum_octets integer
) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    character_index integer;
    code_point integer;
    candidate_length integer;
    normalized text;
BEGIN
    IF maximum_octets < 0
       OR candidate = ''
       OR octet_length(candidate) > maximum_octets THEN
        RETURN false;
    END IF;

    normalized := lower(candidate);
    IF normalized LIKE 'bearer %'
       OR strpos(normalized, 'github_pat_') > 0
       OR strpos(normalized, '-----begin private key-----') > 0 THEN
        RETURN false;
    END IF;

    candidate_length := character_length(candidate);
    FOR character_index IN 1..candidate_length LOOP
        code_point := ascii(substr(candidate, character_index, 1));
        IF code_point BETWEEN 0 AND 31
           OR code_point BETWEEN 127 AND 159 THEN
            RETURN false;
        END IF;

        IF character_index IN (1, candidate_length)
           AND code_point IN (
               9, 10, 11, 12, 13, 32, 133, 160, 5760,
               8192, 8193, 8194, 8195, 8196, 8197, 8198,
               8199, 8200, 8201, 8202, 8232, 8233, 8239,
               8287, 12288
           ) THEN
            RETURN false;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;

-- A receipt serializes BTreeSet<String> values.  The production evidence
-- contract admits at most 256 CI records, so refuse oversized arrays before
-- expanding them and require unique, bounded public strings.
CREATE FUNCTION asf_evidence_verification_ci_set(candidate jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    member jsonb;
BEGIN
    IF jsonb_typeof(candidate) IS DISTINCT FROM 'array'
       OR jsonb_array_length(candidate) > 256 THEN
        RETURN false;
    END IF;

    FOR member IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF jsonb_typeof(member) IS DISTINCT FROM 'string'
           OR NOT COALESCE(
               asf_evidence_verification_public_text(member #>> '{}', 512),
               false
           ) THEN
            RETURN false;
        END IF;
    END LOOP;

    RETURN jsonb_array_length(candidate) = (
        SELECT count(DISTINCT value #>> '{}')
        FROM jsonb_array_elements(candidate)
    );
END;
$$;

CREATE FUNCTION asf_evidence_verification_u64(candidate text) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    parsed numeric;
BEGIN
    IF candidate !~ '^[1-9][0-9]*$' THEN
        RETURN NULL;
    END IF;
    parsed := candidate::numeric;
    IF parsed > 18446744073709551615::numeric THEN
        RETURN NULL;
    END IF;
    RETURN parsed;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- Malformed or zone-less strings are false proof.  The parser accepts the
-- RFC-3339 offsets accepted by chrono while bounding work before the cast.
CREATE FUNCTION asf_evidence_verification_timestamp(candidate text)
RETURNS timestamptz
LANGUAGE plpgsql STABLE STRICT PARALLEL SAFE
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

-- GitHub.com and GitHub Enterprise use the same credential-free HTML path.
-- Binding that path to the canonical repository slug and u64 number prevents
-- a merely-HTTPS but unrelated URL from becoming authority-bearing evidence.
CREATE FUNCTION asf_evidence_verification_github_pr_url(
    candidate text,
    repository text,
    pull_request_number text
) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    remainder text;
    authority text;
    candidate_path text;
    slash_position integer;
    port_text text;
BEGIN
    IF left(candidate, 8) <> 'https://'
       OR repository !~ '^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$'
       OR asf_evidence_verification_u64(pull_request_number) IS NULL THEN
        RETURN false;
    END IF;

    remainder := substr(candidate, 9);
    slash_position := strpos(remainder, '/');
    IF slash_position <= 1 THEN
        RETURN false;
    END IF;
    authority := left(remainder, slash_position - 1);
    candidate_path := substr(remainder, slash_position + 1);

    IF authority !~ E'^([A-Za-z0-9][A-Za-z0-9.-]*|\\[[0-9A-Fa-f:.]+\\])(:[0-9]{1,5})?$'
       OR candidate_path <> repository || '/pull/' || pull_request_number THEN
        RETURN false;
    END IF;

    port_text := substring(authority FROM ':([0-9]{1,5})$');
    IF port_text IS NOT NULL AND port_text::integer > 65535 THEN
        RETURN false;
    END IF;

    RETURN strpos(lower(candidate), 'github_pat_') = 0
       AND strpos(lower(candidate), '-----begin private key-----') = 0;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

-- Intrinsic receipt shape.  Relational equality and chronology are checked by
-- asf_valid_evidence_verification_is_exact below.  Subtracting the complete
-- key lists plus requiring every member gives deny_unknown_fields semantics.
CREATE FUNCTION asf_evidence_verification_details_are_strict(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
    pull_request jsonb;
BEGIN
    IF jsonb_typeof(candidate) IS DISTINCT FROM 'object'
       OR candidate - ARRAY[
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
       ]::text[] <> '{}'::jsonb THEN
        RETURN false;
    END IF;

    IF jsonb_typeof(candidate -> 'schema') IS DISTINCT FROM 'string'
       OR candidate ->> 'schema' <> 'asf.evidence-verification-receipt.v1'
       OR jsonb_typeof(candidate -> 'evidence_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(candidate -> 'work_item_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(candidate -> 'attempt_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(candidate -> 'run_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(candidate -> 'evidence_digest') IS DISTINCT FROM 'string'
       OR candidate ->> 'evidence_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR jsonb_typeof(candidate -> 'work_order_digest') IS DISTINCT FROM 'string'
       OR candidate ->> 'work_order_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR jsonb_typeof(candidate -> 'expectation_digest') IS DISTINCT FROM 'string'
       OR candidate ->> 'expectation_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR jsonb_typeof(candidate -> 'verification_job_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(candidate -> 'verification_job_fence_token') IS DISTINCT FROM 'number'
       OR candidate ->> 'verification_job_fence_token' !~ '^[1-9][0-9]*$'
       OR jsonb_typeof(candidate -> 'verification_job_completed_by') IS DISTINCT FROM 'string'
       OR NOT COALESCE(asf_evidence_verification_public_text(
            candidate ->> 'verification_job_completed_by', 512
       ), false)
       OR jsonb_typeof(candidate -> 'verifier') IS DISTINCT FROM 'string'
       OR NOT COALESCE(asf_evidence_verification_public_text(
            candidate ->> 'verifier', 256
       ), false)
       OR jsonb_typeof(candidate -> 'provider_revision') IS DISTINCT FROM 'string'
       OR NOT COALESCE(asf_evidence_verification_public_text(
            candidate ->> 'provider_revision', 1024
       ), false)
       OR jsonb_typeof(candidate -> 'observed_at') IS DISTINCT FROM 'string'
       OR length(candidate ->> 'observed_at') > 64
       OR candidate ->> 'observed_at' !~ (
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]'
            || '[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?'
            || '([Zz]|[+-][0-9]{2}:[0-9]{2})$'
       ) THEN
        RETURN false;
    END IF;

    pull_request := candidate -> 'pull_request';
    RETURN COALESCE(
        jsonb_typeof(pull_request) = 'object'
        AND pull_request - ARRAY[
            'repository',
            'number',
            'url',
            'base_sha',
            'head_sha',
            'required_ci_contexts',
            'successful_ci_contexts'
        ]::text[] = '{}'::jsonb
        AND jsonb_typeof(pull_request -> 'repository') = 'string'
        AND pull_request ->> 'repository' ~
            '^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$'
        AND asf_evidence_verification_public_text(
            pull_request ->> 'repository', 201
        )
        AND jsonb_typeof(pull_request -> 'number') = 'number'
        AND asf_evidence_verification_u64(
            pull_request ->> 'number'
        ) IS NOT NULL
        AND jsonb_typeof(pull_request -> 'url') = 'string'
        AND jsonb_typeof(pull_request -> 'base_sha') = 'string'
        AND pull_request ->> 'base_sha' ~ '^[0-9a-f]{40}$'
        AND jsonb_typeof(pull_request -> 'head_sha') = 'string'
        AND pull_request ->> 'head_sha' ~ '^[0-9a-f]{40}$'
        AND asf_evidence_verification_ci_set(
            pull_request -> 'required_ci_contexts'
        )
        AND asf_evidence_verification_ci_set(
            pull_request -> 'successful_ci_contexts'
        )
        AND (pull_request -> 'successful_ci_contexts') @>
            (pull_request -> 'required_ci_contexts'),
        false
    );
END;
$$;

-- A VERIFY_EVIDENCE completion is itself an authority receipt.  It must be a
-- direct transition from the exact live claim; direct terminal insertion and
-- owner/fence/attempt substitution are forbidden.  PostgreSQL captures the
-- terminal timestamp so receipt chronology is anchored to the database clock.
CREATE FUNCTION asf_guard_verify_evidence_job_completion() RETURNS trigger
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

CREATE TRIGGER workflow_jobs_exact_verify_evidence_completion
    BEFORE INSERT OR UPDATE ON workflow_jobs
    FOR EACH ROW EXECUTE FUNCTION asf_guard_verify_evidence_job_completion();

-- Refine the 0014 predicate under the same name.  Its existing deferred
-- receipt trigger and reciprocal workflow-job/evidence/run triggers therefore
-- all acquire the stricter semantics without parallel, drifting predicates.
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

-- New VALID rows must be written near the database's own clock.  This is a
-- write-time condition rather than a durable predicate: historical receipts
-- remain valid as wall time advances, while backdated/future forged inserts do
-- not gain authority by pointing at an old terminal job.
CREATE FUNCTION asf_guard_valid_evidence_verification_clock() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_observed_at timestamptz;
BEGIN
    IF NEW.status = 'VALID' THEN
        candidate_observed_at := asf_evidence_verification_timestamp(
            NEW.details ->> 'observed_at'
        );
        IF candidate_observed_at IS NULL
           OR NEW.verified_at NOT BETWEEN
               clock_timestamp() - interval '5 minutes'
               AND clock_timestamp() + interval '5 minutes'
           OR candidate_observed_at NOT BETWEEN
               NEW.verified_at - interval '5 minutes'
               AND NEW.verified_at + interval '5 minutes' THEN
            RAISE EXCEPTION
                'VALID evidence verification is outside the database clock window'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'evidence_verifications_valid_receipt_db_clock';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_verifications_valid_receipt_db_clock
    BEFORE INSERT ON evidence_verifications
    FOR EACH ROW EXECUTE FUNCTION asf_guard_valid_evidence_verification_clock();

-- Refuse an unsafe upgrade instead of freezing a historical VALID receipt
-- whose stored details, external observation, or completed claim cannot satisfy
-- the stronger contract.
DO $$
DECLARE
    invalid_receipt record;
BEGIN
    SELECT verification.tenant_id, verification.id
    INTO invalid_receipt
    FROM evidence_verifications AS verification
    WHERE verification.status = 'VALID'
      AND NOT asf_valid_evidence_verification_is_exact(
          verification.tenant_id,
          verification.id
      )
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'historical VALID evidence verification is not an exact independently observed receipt'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_verification_receipt_upgrade_requires_exact_history';
    END IF;
END;
$$;

ALTER TABLE evidence_verifications
    ADD CONSTRAINT evidence_verifications_valid_receipt_v1_strict CHECK (
        status <> 'VALID'
        OR COALESCE(
            asf_evidence_verification_details_are_strict(details),
            false
        )
    );

-- The append-only row trigger does not fire for TRUNCATE.  Prevent a
-- multi-table truncate from erasing authority receipts and bypassing all
-- reciprocal row-level proofs.
CREATE TRIGGER evidence_verifications_truncate_forbidden
    BEFORE TRUNCATE ON evidence_verifications
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
