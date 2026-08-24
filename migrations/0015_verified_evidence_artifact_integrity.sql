-- A VALID evidence receipt attests to the exact signed artifact manifest that
-- the verifier read.  Preserve that manifest relationally: content-addressed
-- artifact metadata is immutable, evidence links cannot be rewritten, and no
-- link may be appended after a VALID decision.  The evidence table is the
-- migration gate: taking it first drains both evidence ingestion and verifier
-- finalization before the artifact tables are locked, avoiding an artifact /
-- verification-table lock-order cycle during the upgrade.
LOCK TABLE evidence_bundles IN ACCESS EXCLUSIVE MODE;
LOCK TABLE artifacts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE evidence_artifacts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE evidence_verifications IN ACCESS EXCLUSIVE MODE;

-- A row lock alone is not a serialization event under PostgreSQL REPEATABLE
-- READ when two transactions write disjoint child tables.  Both link insertion
-- and VALID verification therefore advance this guard tuple.  A stale RR
-- snapshot loses with a serialization error; READ COMMITTED observes the
-- winning transaction before it makes its decision.
CREATE TABLE evidence_artifact_manifest_guards (
    tenant_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    PRIMARY KEY (tenant_id, evidence_id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_bundles(tenant_id, id) ON DELETE RESTRICT
);

INSERT INTO evidence_artifact_manifest_guards (tenant_id, evidence_id)
SELECT tenant_id, id
FROM evidence_bundles;

CREATE FUNCTION asf_create_evidence_artifact_manifest_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO evidence_artifact_manifest_guards (tenant_id, evidence_id)
    VALUES (NEW.tenant_id, NEW.id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER evidence_bundles_create_artifact_manifest_guard
    AFTER INSERT ON evidence_bundles
    FOR EACH ROW EXECUTE FUNCTION asf_create_evidence_artifact_manifest_guard();

CREATE FUNCTION asf_advance_evidence_artifact_manifest_guard(
    candidate_tenant uuid,
    candidate_evidence uuid
) RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
BEGIN
    UPDATE evidence_artifact_manifest_guards
    SET generation = generation + 1
    WHERE tenant_id = candidate_tenant
      AND evidence_id = candidate_evidence
      AND generation < 9223372036854775807;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'evidence artifact manifest has no advanceable serialization guard'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_artifact_manifest_guard_required';
    END IF;
END;
$$;

CREATE FUNCTION asf_guard_evidence_artifact_manifest_guard_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'UPDATE'
       OR ROW(NEW.tenant_id, NEW.evidence_id) IS DISTINCT FROM
          ROW(OLD.tenant_id, OLD.evidence_id)
       OR NEW.generation IS DISTINCT FROM OLD.generation + 1 THEN
        RAISE EXCEPTION
            'evidence artifact serialization guards are append-only counters'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_artifact_manifest_guard_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_artifact_manifest_guards_monotonic
    BEFORE UPDATE OR DELETE ON evidence_artifact_manifest_guards
    FOR EACH ROW EXECUTE FUNCTION asf_guard_evidence_artifact_manifest_guard_mutation();

CREATE TRIGGER evidence_artifact_manifest_guards_truncate_forbidden
    BEFORE TRUNCATE ON evidence_artifact_manifest_guards
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

-- Store the signed semantic identity beside the content-addressed link.  The
-- current link key can represent a manifest bijectively only when each digest
-- appears once; the signed contract and the predicates below enforce that.
ALTER TABLE evidence_artifacts
    ADD COLUMN manifest_artifact_id text,
    ADD COLUMN manifest_kind text;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_artifacts AS link
        JOIN artifacts AS artifact
          ON artifact.tenant_id = link.tenant_id
         AND artifact.id = link.artifact_id
        JOIN evidence_bundles AS evidence
          ON evidence.tenant_id = link.tenant_id
         AND evidence.id = link.evidence_id
        WHERE (
            SELECT count(*)
            FROM jsonb_array_elements(
                CASE
                    WHEN jsonb_typeof(evidence.payload #> '{predicate,artifacts}') = 'array'
                    THEN evidence.payload #> '{predicate,artifacts}'
                    ELSE '[]'::jsonb
                END
            ) AS expected(value)
            WHERE expected.value ->> 'digest' = artifact.digest
        ) <> 1
    ) THEN
        RAISE EXCEPTION
            'historical evidence artifact links do not map bijectively to signed manifest entries'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_artifact_manifest_upgrade_bijective';
    END IF;
END;
$$;

WITH mappings AS (
    SELECT link.ctid AS link_ctid,
           expected.value ->> 'artifact_id' AS manifest_artifact_id,
           expected.value ->> 'kind' AS manifest_kind
    FROM evidence_artifacts AS link
    JOIN artifacts AS artifact
      ON artifact.tenant_id = link.tenant_id
     AND artifact.id = link.artifact_id
    JOIN evidence_bundles AS evidence
      ON evidence.tenant_id = link.tenant_id
     AND evidence.id = link.evidence_id
    CROSS JOIN LATERAL jsonb_array_elements(
        evidence.payload #> '{predicate,artifacts}'
    ) AS expected(value)
    WHERE expected.value ->> 'digest' = artifact.digest
)
UPDATE evidence_artifacts AS link
SET manifest_artifact_id = mappings.manifest_artifact_id,
    manifest_kind = mappings.manifest_kind
FROM mappings
WHERE link.ctid = mappings.link_ctid;

ALTER TABLE evidence_artifacts
    ALTER COLUMN manifest_artifact_id SET NOT NULL,
    ALTER COLUMN manifest_kind SET NOT NULL,
    ADD CONSTRAINT evidence_artifacts_manifest_id_shape CHECK (
        manifest_artifact_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
    ),
    ADD CONSTRAINT evidence_artifacts_manifest_kind_shape CHECK (
        manifest_kind IN (
            'work-order-envelope', 'effective-policy', 'normalized-diff',
            'agent-outcome', 'verification', 'ci-observation', 'review',
            'side-effect', 'approval', 'runtime-manifest'
        )
    ),
    ADD CONSTRAINT evidence_artifacts_manifest_id_unique UNIQUE (
        tenant_id, evidence_id, manifest_artifact_id
    );

CREATE FUNCTION asf_evidence_artifact_bigint(candidate text) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE
AS $$
BEGIN
    RETURN candidate::bigint;
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RETURN NULL;
END;
$$;

-- This function is intentionally keyed by the verification receipt, not only
-- by the evidence row.  Artifact expiry is evaluated at the independently
-- recorded verification time so historical proof does not become false merely
-- because wall-clock time advances.
CREATE FUNCTION asf_valid_evidence_artifacts_are_exact(
    candidate_tenant uuid,
    candidate_verification uuid
) RETURNS boolean
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    candidate_evidence uuid;
    candidate_payload jsonb;
    candidate_manifest jsonb;
    candidate_verified_at timestamptz;
    candidate_link_count bigint;
BEGIN
    -- Resolve the immutable evidence coordinate, then mutate the same guard
    -- tuple used by link insertion.  The mutation (rather than a row lock)
    -- closes the phantom/write-skew race under both RC and RR isolation.
    SELECT evidence.id,
           evidence.payload,
           verification.verified_at
    INTO candidate_evidence, candidate_payload, candidate_verified_at
    FROM evidence_verifications AS verification
    JOIN evidence_bundles AS evidence
      ON evidence.tenant_id = verification.tenant_id
     AND evidence.id = verification.evidence_id
    WHERE verification.tenant_id = candidate_tenant
      AND verification.id = candidate_verification
      AND verification.status = 'VALID';

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    PERFORM asf_advance_evidence_artifact_manifest_guard(
        candidate_tenant,
        candidate_evidence
    );

    candidate_manifest := candidate_payload #> '{predicate,artifacts}';
    IF jsonb_typeof(candidate_manifest) IS DISTINCT FROM 'array' THEN
        RETURN false;
    END IF;

    -- Existing rows are immutable below; share-locking them makes the lock
    -- discipline explicit and also protects upgrades from a concurrent writer.
    PERFORM 1
    FROM evidence_artifacts AS link
    JOIN artifacts AS artifact
      ON artifact.tenant_id = link.tenant_id
     AND artifact.id = link.artifact_id
    WHERE link.tenant_id = candidate_tenant
      AND link.evidence_id = candidate_evidence
    FOR SHARE OF link, artifact;

    SELECT count(*)
    INTO candidate_link_count
    FROM evidence_artifacts AS link
    WHERE link.tenant_id = candidate_tenant
      AND link.evidence_id = candidate_evidence;

    RETURN COALESCE(
        jsonb_array_length(candidate_manifest) = candidate_link_count
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(candidate_manifest) AS expected(value)
            WHERE jsonb_typeof(expected.value) IS DISTINCT FROM 'object'
               OR expected.value - ARRAY[
                    'artifact_id',
                    'kind',
                    'size_bytes',
                    'media_type',
                    'digest',
                    'retention_class',
                    'location_ref'
                ]::text[] <> '{}'::jsonb
               OR jsonb_typeof(expected.value -> 'artifact_id') IS DISTINCT FROM 'string'
               OR expected.value ->> 'artifact_id' !~
                    '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
               OR jsonb_typeof(expected.value -> 'kind') IS DISTINCT FROM 'string'
               OR expected.value ->> 'kind' NOT IN (
                    'work-order-envelope', 'effective-policy', 'normalized-diff',
                    'agent-outcome', 'verification', 'ci-observation', 'review',
                    'side-effect', 'approval', 'runtime-manifest'
                )
               OR jsonb_typeof(expected.value -> 'size_bytes') IS DISTINCT FROM 'number'
               OR expected.value ->> 'size_bytes' !~ '^(0|[1-9][0-9]*)$'
               OR asf_evidence_artifact_bigint(
                    expected.value ->> 'size_bytes'
                  ) IS NULL
               OR jsonb_typeof(expected.value -> 'media_type') IS DISTINCT FROM 'string'
               OR btrim(expected.value ->> 'media_type') = ''
               OR jsonb_typeof(expected.value -> 'digest') IS DISTINCT FROM 'string'
               OR expected.value ->> 'digest' !~ '^sha256:[0-9a-f]{64}$'
               OR jsonb_typeof(expected.value -> 'retention_class') IS DISTINCT FROM 'string'
               OR expected.value ->> 'retention_class' NOT IN (
                    'portable', 'protected', 'restricted'
                )
               OR jsonb_typeof(expected.value -> 'location_ref') IS DISTINCT FROM 'string'
               OR expected.value ->> 'location_ref' <>
                    'cas://sha256/' || substr(expected.value ->> 'digest', 8)
               OR NOT EXISTS (
                    SELECT 1
                    FROM evidence_artifacts AS link
                    JOIN artifacts AS artifact
                      ON artifact.tenant_id = link.tenant_id
                     AND artifact.id = link.artifact_id
                    WHERE link.tenant_id = candidate_tenant
                      AND link.evidence_id = candidate_evidence
                      AND link.manifest_artifact_id =
                          expected.value ->> 'artifact_id'
                      AND link.manifest_kind = expected.value ->> 'kind'
                      AND artifact.digest_algorithm = 'sha256'
                      AND artifact.digest = expected.value ->> 'digest'
                      AND artifact.byte_size = asf_evidence_artifact_bigint(
                            expected.value ->> 'size_bytes'
                          )
                      AND artifact.media_type = expected.value ->> 'media_type'
                      AND lower(artifact.retention_class) =
                          expected.value ->> 'retention_class'
                      AND artifact.object_key = expected.value ->> 'location_ref'
                      AND artifact.created_at <= candidate_verified_at
                      AND (
                          artifact.expires_at IS NULL
                          OR artifact.expires_at > candidate_verified_at
                      )
                )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(candidate_manifest) AS expected(value)
            GROUP BY expected.value ->> 'artifact_id'
            HAVING count(*) <> 1
        )
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(candidate_manifest) AS expected(value)
            GROUP BY expected.value ->> 'digest'
            HAVING count(*) <> 1
        )
        AND NOT EXISTS (
            SELECT 1
            FROM evidence_artifacts AS link
            JOIN artifacts AS artifact
              ON artifact.tenant_id = link.tenant_id
             AND artifact.id = link.artifact_id
            WHERE link.tenant_id = candidate_tenant
              AND link.evidence_id = candidate_evidence
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(candidate_manifest) AS expected(value)
                  WHERE expected.value ->> 'artifact_id' =
                            link.manifest_artifact_id
                    AND expected.value ->> 'kind' = link.manifest_kind
                    AND expected.value ->> 'digest' = artifact.digest
              )
        )
        -- These three signed subjects are the minimum independently portable
        -- proof set for Work Order authority, evaluated policy, and exact diff.
        AND candidate_payload #>>
                '{predicate,work_order,envelope_artifact_digest}' =
            candidate_payload #>> '{predicate,work_order,envelope_digest}'
        AND candidate_payload #>>
                '{predicate,policy,effective_policy_artifact_digest}' =
            candidate_payload #>>
                '{predicate,policy,effective_policy_digest}'
        AND candidate_payload #>>
                '{predicate,source,normalized_diff_artifact_digest}' =
            candidate_payload #>> '{predicate,source,normalized_diff_digest}'
        AND NOT EXISTS (
            SELECT required.digest
            FROM (VALUES
                (candidate_payload #>>
                    '{predicate,work_order,envelope_artifact_digest}',
                    'work-order-envelope'),
                (candidate_payload #>>
                    '{predicate,policy,effective_policy_artifact_digest}',
                    'effective-policy'),
                (candidate_payload #>>
                    '{predicate,source,normalized_diff_artifact_digest}',
                    'normalized-diff')
            ) AS required(digest, kind)
            WHERE required.digest IS NULL
               OR required.digest !~ '^sha256:[0-9a-f]{64}$'
               OR NOT EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(candidate_manifest) AS expected(value)
                    WHERE expected.value ->> 'digest' = required.digest
                      AND expected.value ->> 'kind' = required.kind
               )
        ),
        false
    );
END;
$$;

CREATE FUNCTION asf_assert_valid_evidence_artifacts_exact() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'VALID'
       AND NOT asf_valid_evidence_artifacts_are_exact(NEW.tenant_id, NEW.id) THEN
        RAISE EXCEPTION
            'VALID evidence verification lacks its exact durable signed artifact manifest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_verifications_require_exact_artifacts';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_verifications_require_exact_artifacts
    AFTER INSERT OR UPDATE ON evidence_verifications
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION asf_assert_valid_evidence_artifacts_exact();

-- Refuse an unsafe upgrade rather than freezing a previously accepted receipt
-- whose relational artifact set does not reproduce its signed manifest.
DO $$
DECLARE
    invalid_receipt record;
BEGIN
    SELECT verification.tenant_id, verification.id
    INTO invalid_receipt
    FROM evidence_verifications AS verification
    WHERE verification.status = 'VALID'
      AND NOT asf_valid_evidence_artifacts_are_exact(
          verification.tenant_id,
          verification.id
      )
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'historical VALID evidence has no exact durable signed artifact manifest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'verified_evidence_artifact_upgrade_requires_exact_history';
    END IF;
END;
$$;

CREATE FUNCTION asf_guard_evidence_artifact_link_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_manifest jsonb;
    candidate_digest text;
    matching_entries bigint;
    expected_artifact_id text;
    expected_kind text;
BEGIN
    PERFORM asf_advance_evidence_artifact_manifest_guard(
        NEW.tenant_id,
        NEW.evidence_id
    );

    IF EXISTS (
        SELECT 1
        FROM evidence_verifications AS verification
        WHERE verification.tenant_id = NEW.tenant_id
          AND verification.evidence_id = NEW.evidence_id
          AND verification.status = 'VALID'
    ) THEN
        RAISE EXCEPTION
            'a VALID evidence artifact manifest cannot gain new links'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'valid_evidence_artifact_links_frozen';
    END IF;

    SELECT evidence.payload #> '{predicate,artifacts}', artifact.digest
    INTO candidate_manifest, candidate_digest
    FROM evidence_bundles AS evidence
    JOIN artifacts AS artifact
      ON artifact.tenant_id = NEW.tenant_id
     AND artifact.id = NEW.artifact_id
    WHERE evidence.tenant_id = NEW.tenant_id
      AND evidence.id = NEW.evidence_id;

    IF NOT FOUND OR jsonb_typeof(candidate_manifest) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION
            'evidence artifact link has no signed manifest or content metadata'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_artifact_link_requires_signed_entry';
    END IF;

    SELECT count(*),
           min(expected.value ->> 'artifact_id'),
           min(expected.value ->> 'kind')
    INTO matching_entries, expected_artifact_id, expected_kind
    FROM jsonb_array_elements(candidate_manifest) AS expected(value)
    WHERE expected.value ->> 'digest' = candidate_digest;

    IF matching_entries <> 1
       OR expected_artifact_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
       OR expected_kind NOT IN (
            'work-order-envelope', 'effective-policy', 'normalized-diff',
            'agent-outcome', 'verification', 'ci-observation', 'review',
            'side-effect', 'approval', 'runtime-manifest'
       )
       OR (
            NEW.manifest_artifact_id IS NOT NULL
            AND NEW.manifest_artifact_id IS DISTINCT FROM expected_artifact_id
       )
       OR (
            NEW.manifest_kind IS NOT NULL
            AND NEW.manifest_kind IS DISTINCT FROM expected_kind
       ) THEN
        RAISE EXCEPTION
            'evidence artifact link is not the unique signed manifest entry'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_artifact_link_exact_signed_entry';
    END IF;

    NEW.manifest_artifact_id := expected_artifact_id;
    NEW.manifest_kind := expected_kind;

    RETURN NEW;
END;
$$;

CREATE TRIGGER valid_evidence_artifact_links_frozen
    BEFORE INSERT ON evidence_artifacts
    FOR EACH ROW EXECUTE FUNCTION asf_guard_evidence_artifact_link_insert();

CREATE TRIGGER artifacts_immutable
    BEFORE UPDATE OR DELETE ON artifacts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TRIGGER artifacts_truncate_forbidden
    BEFORE TRUNCATE ON artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TRIGGER evidence_artifacts_immutable
    BEFORE UPDATE OR DELETE ON evidence_artifacts
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();

CREATE TRIGGER evidence_artifacts_truncate_forbidden
    BEFORE TRUNCATE ON evidence_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
