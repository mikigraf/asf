-- Forward-only migration 0035: terminal evidence bundle provenance.
--
-- A terminal evidence bundle is the append-only proof that an exact ASF run
-- reached an exact terminal phase at an exact external event sequence, bound to:
--   1. the exact ownership coordinates (work item, attempt, work order + digest),
--   2. the exact admitting worker session (worker id + generation),
--   3. the exact external Runmill run id,
--   4. the two exact control snapshots (0021) it was derived from: the GET_RUN
--      snapshot and the terminal event page snapshot,
--   5. the exact successful asf.get_evidence response wire bytes and their
--      digest -- the terminal evidence read itself, which is a provenance
--      distinct from the two snapshots above and is never the GET_RUN wire,
--   6. the exact canonical statement bytes, their digest, and the predicate,
--   7. the exact raw signed-terminal envelope, its signing authority, and the
--      in-toto Statement it carries.
--
-- Bundles are never updated and never deleted. Corrections are new bundles.
--
-- Three provenances are retained side by side and never conflated. The
-- asf.get_evidence response wire is the terminal evidence read: it is the
-- NDJSON success envelope that carried the signed terminal bundle. The GET_RUN
-- snapshot is the phase observation and the event page snapshot is the sequence
-- observation; both are proved separately, and neither one's wire is ever
-- required to be the terminal evidence wire.
--
-- The signed envelope is the contract boundary. PostgreSQL does not trust the
-- indexed columns: the BEFORE INSERT guard reparses the raw envelope bytes,
-- rejects any envelope or in-toto Statement whose object shape is not exactly
-- the contract shape, requires the Runmill predicate to carry every mandatory
-- key of its own schema, and requires every indexed column to be reproduced by
-- that raw JSON. The predicate's own top-level key set is exactly the eleven
-- keys of asf.terminal-evidence/v1, while its nested objects are required-key
-- checked rather than closed: a Runmill addition inside them must not
-- retroactively make already-signed evidence unstorable. Like
-- migration 0021, exact bytes are retained and their digests are derived from
-- the bytes themselves rather than from a caller-supplied claim.

LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_items IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE work_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_control_snapshots IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_streams IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_run_observation_results IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE runmill_terminal_evidence_bundles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL,
    work_item_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    work_order_id uuid NOT NULL,
    work_order_digest text NOT NULL
        CHECK (work_order_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_session_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    worker_generation bigint NOT NULL CHECK (worker_generation > 0),
    external_run_id text NOT NULL CHECK (btrim(external_run_id) <> ''),

    -- Exact control snapshots (0021) this bundle was derived from.
    get_run_snapshot_id uuid NOT NULL,
    event_page_snapshot_id uuid NOT NULL,

    -- Exact successful asf.get_evidence response wire bytes -- the NDJSON
    -- {ok:true,data:<evidence view>} line that carried the signed terminal
    -- bundle. This is not the GET_RUN snapshot wire.
    terminal_evidence_response_wire_digest text NOT NULL
        CHECK (terminal_evidence_response_wire_digest ~ '^sha256:[0-9a-f]{64}$'),
    exact_terminal_evidence_response_wire bytea NOT NULL
        CHECK (octet_length(exact_terminal_evidence_response_wire) BETWEEN 2 AND 2097152),

    terminal_bundle_digest text NOT NULL
        CHECK (terminal_bundle_digest ~ '^sha256:[0-9a-f]{64}$'),
    terminal_phase text NOT NULL
        CHECK (terminal_phase IN (
            'COMPLETED',
            'CANCELLED',
            'FAILED',
            'REFUSED',
            'QUARANTINED',
            'BUDGET_EXHAUSTED'
        )),
    terminal_event_seq bigint NOT NULL
        CHECK (terminal_event_seq BETWEEN 1 AND 9007199254740991),

    -- The base commit is fixed at admission and is always provable. A run may
    -- reach a terminal phase (REFUSED, BUDGET_EXHAUSTED, an early FAILED)
    -- without ever producing a candidate commit, so candidate_sha stays
    -- nullable and the envelope carries JSON null in that case.
    base_sha text NOT NULL CHECK (base_sha ~ '^[0-9a-f]{40}$'),
    candidate_sha text CHECK (candidate_sha IS NULL OR candidate_sha ~ '^[0-9a-f]{40}$'),

    -- Exact canonical statement bytes and their digest.
    canonical_statement bytea NOT NULL
        CHECK (octet_length(canonical_statement) BETWEEN 2 AND 2097152),
    statement_digest text NOT NULL
        CHECK (statement_digest ~ '^sha256:[0-9a-f]{64}$'),
    predicate jsonb NOT NULL CHECK (jsonb_typeof(predicate) = 'object'),

    -- Exact raw signed-terminal envelope and its signing authority. The
    -- envelope is the only thing an external verifier needs: every other
    -- column on this row is a reproduction of its raw JSON.
    envelope_schema text NOT NULL
        CHECK (envelope_schema = 'asf.signed-terminal-evidence/v1'),
    signature_algorithm text NOT NULL CHECK (signature_algorithm = 'EdDSA'),
    signing_key_id text NOT NULL CHECK (btrim(signing_key_id) <> ''),
    -- The contract transports the signature prefixed and over the base64url
    -- alphabet. An Ed25519 signature is 64 bytes, i.e. exactly 86 unpadded
    -- base64url characters; any other shape is refused outright.
    terminal_signature text NOT NULL
        CHECK (terminal_signature ~ '^base64url:[A-Za-z0-9_-]{86}$'),
    exact_signed_envelope bytea NOT NULL
        CHECK (octet_length(exact_signed_envelope) BETWEEN 2 AND 2097152),
    -- The envelope's own issuance instant. The contract requires it to be
    -- exactly the predicate's timing.terminal_evidence_at, so there is no
    -- second production timestamp to record: the insert guard proves the
    -- envelope and the predicate name the same instant.
    issued_at timestamptz NOT NULL,

    stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, run_id, terminal_bundle_digest),

    -- A control snapshot may back at most one terminal evidence bundle, and the
    -- two snapshot roles are never satisfied by the same snapshot row.
    UNIQUE (tenant_id, get_run_snapshot_id),
    UNIQUE (tenant_id, event_page_snapshot_id),
    CHECK (get_run_snapshot_id <> event_page_snapshot_id),

    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_item_id)
        REFERENCES work_items(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, attempt_id, work_item_id)
        REFERENCES attempts(tenant_id, id, work_item_id)
        MATCH SIMPLE ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, work_order_id, work_order_digest, work_item_id, attempt_id)
        REFERENCES work_orders(tenant_id, id, payload_digest, work_item_id, attempt_id)
        MATCH SIMPLE ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_id)
        REFERENCES workers(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, worker_session_id, worker_id, worker_generation)
        REFERENCES worker_sessions(tenant_id, id, worker_id, worker_generation)
        ON DELETE RESTRICT,
    -- A terminal evidence bundle only exists for a run that has an observation
    -- stream; the guard additionally requires that stream to be TERMINAL_READY.
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runmill_run_observation_streams(tenant_id, run_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, get_run_snapshot_id)
        REFERENCES runmill_control_snapshots(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_page_snapshot_id)
        REFERENCES runmill_control_snapshots(tenant_id, id) ON DELETE RESTRICT
);

COMMENT ON TABLE runmill_terminal_evidence_bundles IS
    'Append-only terminal evidence bundles: exact proof that a named run reached a named terminal phase at a named external event sequence, bound to its exact ownership coordinates, admitting worker session, control snapshots, asf.get_evidence response wire bytes, and canonical statement.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.run_id IS
    'ASF-local run uuid. Distinct from external_run_id, which is Runmill''s own run identifier.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.get_run_snapshot_id IS
    'The exact runmill_control_snapshots row (control_operation = GET_RUN) the terminal phase was read from.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.event_page_snapshot_id IS
    'The exact runmill_control_snapshots row (control_operation = LIST_RUN_EVENTS) the terminal event sequence was read from.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.exact_terminal_evidence_response_wire IS
    'Byte-exact successful asf.get_evidence response wire the bundle was derived from: one NDJSON {ok:true,data:<asf.evidence-view/v1>} line. terminal_evidence_response_wire_digest is its sha256. Deliberately not the GET_RUN snapshot wire, which is retained separately as get_run_snapshot_id.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.canonical_statement IS
    'Byte-exact canonical statement encoding. statement_digest is its sha256; predicate is its decoded object form.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.exact_signed_envelope IS
    'Byte-exact asf.signed-terminal-evidence/v1 envelope. Every other column on the row is reproduced from this JSON by the insert guard; nothing here is taken on trust.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.signing_key_id IS
    'Key id the signer claims in the envelope, reproduced from the raw envelope bytes by the insert guard. Verifying the signature itself is the reader''s job; SQL only proves the row cannot disagree with the bytes.';
COMMENT ON COLUMN runmill_terminal_evidence_bundles.candidate_sha IS
    'Candidate commit, or NULL for a terminal phase reached before any candidate existed. The envelope carries JSON null for that case.';

CREATE INDEX runmill_terminal_evidence_bundles_run_idx
    ON runmill_terminal_evidence_bundles (tenant_id, run_id, terminal_event_seq);

CREATE INDEX runmill_terminal_evidence_bundles_work_order_idx
    ON runmill_terminal_evidence_bundles (tenant_id, work_order_id);

CREATE INDEX runmill_terminal_evidence_bundles_worker_session_idx
    ON runmill_terminal_evidence_bundles (tenant_id, worker_session_id, id);

CREATE INDEX runmill_terminal_evidence_bundles_external_run_idx
    ON runmill_terminal_evidence_bundles (tenant_id, external_run_id);

CREATE INDEX runmill_terminal_evidence_bundles_statement_digest_idx
    ON runmill_terminal_evidence_bundles (tenant_id, statement_digest);

-- The insert guard is the contract boundary for terminal evidence.
--
-- It reparses the retained envelope bytes and refuses anything that is not
-- exactly the asf.signed-terminal-evidence/v1 shape. The envelope and the
-- in-toto Statement are ASF's own contracts, so their key sets are closed: an
-- unknown field there is a rejection, never a silently ignored one. The
-- predicate is Runmill's contract, so its objects are checked for the presence
-- and type of every key ASF binds and are left open to additions, because a
-- Runmill schema addition must not retroactively make already-signed evidence
-- unstorable.
--
-- It then re-derives every SHA-256 digest from the bytes it is a digest of,
-- reparses the retained asf.get_evidence response wire as the exact NDJSON
-- {ok:true,data:<asf.evidence-view/v1>} success envelope and binds that
-- evidence view to this row and to the retained signed envelope, proves the two
-- control snapshots carry the exact operation and ownership this bundle claims,
-- and requires the observation stream to have actually reached TERMINAL_READY
-- at this exact sequence. The snapshot guards are a separate provenance from
-- the evidence wire: the GET_RUN wire is never required to be the terminal
-- evidence wire.
--
-- asf_source_closure_json (0013) and asf_evidence_verification_timestamp
-- (0016) are reused deliberately: both are strict, NULL-on-malformed parsers,
-- so a malformed envelope fails a named contract check instead of aborting the
-- transaction with an opaque cast error.
CREATE FUNCTION asf_assert_runmill_terminal_evidence_bundle_insert() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    envelope jsonb;
    evidence_response jsonb;
    evidence_view jsonb;
    attestation jsonb;
    claim jsonb;
    subject_entry jsonb;
    run_claim jsonb;
    admission_claim jsonb;
    source_claim jsonb;
    evidence_claim jsonb;
    cleanup_claim jsonb;
    timing_claim jsonb;
    admitted_instant timestamptz;
    terminal_instant timestamptz;
    get_run runmill_control_snapshots%ROWTYPE;
    event_page runmill_control_snapshots%ROWTYPE;
BEGIN
    envelope := asf_source_closure_json(NEW.exact_signed_envelope);
    IF envelope IS NULL OR jsonb_typeof(envelope) <> 'object' THEN
        RAISE EXCEPTION 'signed terminal evidence envelope bytes are not a UTF-8 JSON object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_envelope';
    END IF;

    -- Outer envelope: exact key set, exact literals, exact indexed columns.
    IF envelope ?& ARRAY[
           'schema', 'key_id', 'algorithm', 'issued_at',
           'bundle_digest', 'statement', 'signature'
       ] IS NOT TRUE
       OR envelope - ARRAY[
           'schema', 'key_id', 'algorithm', 'issued_at',
           'bundle_digest', 'statement', 'signature'
       ] <> '{}'::jsonb
       OR jsonb_typeof(envelope -> 'schema') <> 'string'
       OR jsonb_typeof(envelope -> 'key_id') <> 'string'
       OR jsonb_typeof(envelope -> 'algorithm') <> 'string'
       OR jsonb_typeof(envelope -> 'issued_at') <> 'string'
       OR jsonb_typeof(envelope -> 'bundle_digest') <> 'string'
       OR jsonb_typeof(envelope -> 'statement') <> 'object'
       OR jsonb_typeof(envelope -> 'signature') <> 'string'
       OR envelope ->> 'schema' <> 'asf.signed-terminal-evidence/v1'
       OR envelope ->> 'schema' IS DISTINCT FROM NEW.envelope_schema
       OR envelope ->> 'algorithm' <> 'EdDSA'
       OR envelope ->> 'algorithm' IS DISTINCT FROM NEW.signature_algorithm
       OR envelope ->> 'key_id' IS DISTINCT FROM NEW.signing_key_id
       OR envelope ->> 'bundle_digest' IS DISTINCT FROM NEW.terminal_bundle_digest
       OR envelope ->> 'signature' IS DISTINCT FROM NEW.terminal_signature
       OR asf_evidence_verification_timestamp(envelope ->> 'issued_at')
          IS DISTINCT FROM NEW.issued_at THEN
        RAISE EXCEPTION 'signed terminal evidence envelope is not the exact asf.signed-terminal-evidence/v1 contract'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_envelope_contract';
    END IF;

    -- The retained canonical bytes must decode to the very statement the
    -- signature covers, otherwise statement_digest proves nothing about it.
    attestation := envelope -> 'statement';
    IF attestation IS DISTINCT FROM asf_source_closure_json(NEW.canonical_statement) THEN
        RAISE EXCEPTION 'canonical statement bytes do not decode to the exact signed statement'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_canonical_statement';
    END IF;

    -- in-toto Statement: exact key set and exact type literals.
    IF attestation ?& ARRAY['_type', 'subject', 'predicateType', 'predicate'] IS NOT TRUE
       OR attestation - ARRAY['_type', 'subject', 'predicateType', 'predicate'] <> '{}'::jsonb
       OR jsonb_typeof(attestation -> '_type') <> 'string'
       OR jsonb_typeof(attestation -> 'subject') <> 'array'
       OR jsonb_typeof(attestation -> 'predicateType') <> 'string'
       OR jsonb_typeof(attestation -> 'predicate') <> 'object'
       OR attestation ->> '_type' <> 'https://in-toto.io/Statement/v1'
       OR attestation ->> 'predicateType'
          <> 'https://runmill.dev/attestations/asf-terminal-evidence/v1' THEN
        RAISE EXCEPTION 'terminal evidence statement is not the exact in-toto Statement contract'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_statement_contract';
    END IF;

    -- Predicate: the Runmill asf.terminal-evidence/v1 object. The retained
    -- predicate column must be the signed predicate rather than an
    -- independently supplied object, and the top-level key set is exactly the
    -- eleven keys of the schema -- an unknown top-level key is a different
    -- predicate, not this one. The nested objects below stay open, because an
    -- additive Runmill field inside them must not retroactively make
    -- already-signed evidence unstorable. The envelope's issued_at is the
    -- predicate's own timing.terminal_evidence_at: one instant, stated twice.
    claim := attestation -> 'predicate';
    IF claim IS DISTINCT FROM NEW.predicate THEN
        RAISE EXCEPTION 'retained predicate is not the exact signed predicate'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_binding';
    END IF;
    IF claim ?& ARRAY[
           'schema', 'run', 'admission', 'source', 'stop', 'cancellation',
           'budget', 'side_effects', 'timing', 'cleanup', 'evidence'
       ] IS NOT TRUE
       OR claim - ARRAY[
           'schema', 'run', 'admission', 'source', 'stop', 'cancellation',
           'budget', 'side_effects', 'timing', 'cleanup', 'evidence'
       ] <> '{}'::jsonb
       OR jsonb_typeof(claim -> 'schema') <> 'string'
       OR jsonb_typeof(claim -> 'run') <> 'object'
       OR jsonb_typeof(claim -> 'admission') <> 'object'
       OR jsonb_typeof(claim -> 'source') <> 'object'
       OR jsonb_typeof(claim -> 'timing') <> 'object'
       OR claim ->> 'schema' <> 'asf.terminal-evidence/v1'
       OR jsonb_typeof(claim #> '{timing,terminal_evidence_at}') <> 'string'
       OR claim #>> '{timing,terminal_evidence_at}'
          IS DISTINCT FROM envelope ->> 'issued_at'
       OR asf_evidence_verification_timestamp(claim #>> '{timing,terminal_evidence_at}')
          IS DISTINCT FROM NEW.issued_at THEN
        RAISE EXCEPTION 'terminal evidence predicate is not the exact asf.terminal-evidence/v1 contract'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_contract';
    END IF;

    -- run: predicate.run.run_id is Runmill's own external run identifier, not
    -- the ASF-local run uuid; work_order_id and attempt_id are the stringified
    -- ASF uuids. terminal_event_seq is compared as a JSON number, so a
    -- stringified sequence is a rejection rather than a coincidental text match.
    -- Open key set for the same reason as admission and source above.
    run_claim := claim -> 'run';
    IF run_claim ?& ARRAY[
           'run_id', 'work_order_id', 'attempt_id',
           'terminal_phase', 'terminal_event_seq'
       ] IS NOT TRUE
       OR jsonb_typeof(run_claim -> 'run_id') <> 'string'
       OR jsonb_typeof(run_claim -> 'work_order_id') <> 'string'
       OR jsonb_typeof(run_claim -> 'attempt_id') <> 'string'
       OR jsonb_typeof(run_claim -> 'terminal_phase') <> 'string'
       OR jsonb_typeof(run_claim -> 'terminal_event_seq') <> 'number'
       OR run_claim ->> 'run_id' IS DISTINCT FROM NEW.external_run_id
       OR run_claim ->> 'work_order_id' IS DISTINCT FROM NEW.work_order_id::text
       OR run_claim ->> 'attempt_id' IS DISTINCT FROM NEW.attempt_id::text
       OR run_claim ->> 'terminal_phase' IS DISTINCT FROM NEW.terminal_phase
       OR run_claim -> 'terminal_event_seq' IS DISTINCT FROM to_jsonb(NEW.terminal_event_seq) THEN
        RAISE EXCEPTION 'terminal evidence predicate run binding contradicts its indexed columns'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_run_binding';
    END IF;

    -- admission: the full Runmill admission object. Every field the schema
    -- actually requires must be present and of its declared type -- the two
    -- retained documents included, so admission cannot claim a digest without
    -- carrying what the digest is over. The key set stays open. Only the
    -- immutable Work Order payload digest is reproduced by an indexed column.
    admission_claim := claim -> 'admission';
    IF admission_claim ?& ARRAY[
           'work_order_envelope_digest', 'work_order_payload_digest',
           'effective_policy_digest', 'work_order_envelope',
           'signature_verification', 'effective_policy'
       ] IS NOT TRUE
       OR jsonb_typeof(admission_claim -> 'work_order_envelope_digest') <> 'string'
       OR jsonb_typeof(admission_claim -> 'work_order_payload_digest') <> 'string'
       OR jsonb_typeof(admission_claim -> 'effective_policy_digest') <> 'string'
       OR jsonb_typeof(admission_claim -> 'work_order_envelope') <> 'object'
       OR jsonb_typeof(admission_claim -> 'signature_verification') <> 'object'
       OR jsonb_typeof(admission_claim -> 'effective_policy') <> 'object'
       OR admission_claim ->> 'work_order_envelope_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR admission_claim ->> 'effective_policy_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR admission_claim ->> 'work_order_payload_digest'
          IS DISTINCT FROM NEW.work_order_digest THEN
        RAISE EXCEPTION 'terminal evidence predicate admission binding contradicts its Work Order digest'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_admission_binding';
    END IF;

    -- source: a full Runmill source object. base is always present; candidate is
    -- JSON null exactly when the run reached its terminal phase without ever
    -- producing a candidate. repository, subject_kind and subject_sha are
    -- retained rather than rejected -- subject_sha is what the in-toto subject
    -- below is keyed on.
    source_claim := claim -> 'source';
    IF source_claim ?& ARRAY[
           'repository', 'base_sha', 'candidate_sha', 'subject_kind', 'subject_sha'
       ] IS NOT TRUE
       OR jsonb_typeof(source_claim -> 'repository') <> 'string'
       OR jsonb_typeof(source_claim -> 'base_sha') <> 'string'
       OR jsonb_typeof(source_claim -> 'candidate_sha') NOT IN ('string', 'null')
       OR jsonb_typeof(source_claim -> 'subject_kind') <> 'string'
       OR jsonb_typeof(source_claim -> 'subject_sha') <> 'string'
       OR source_claim ->> 'base_sha' IS DISTINCT FROM NEW.base_sha
       OR source_claim -> 'candidate_sha'
          IS DISTINCT FROM COALESCE(to_jsonb(NEW.candidate_sha), 'null'::jsonb)
       -- Exact candidate null semantics: the subject must truthfully name the
       -- candidate, or the admitted base exactly when there is no candidate.
       -- Spelled without CASE on purpose: plpgsql ends an IF condition at the
       -- first THEN, so a CASE here would truncate the whole guard.
       OR (NEW.candidate_sha IS NULL
           AND source_claim ->> 'subject_kind' IS DISTINCT FROM 'base')
       OR (NEW.candidate_sha IS NOT NULL
           AND source_claim ->> 'subject_kind' IS DISTINCT FROM 'candidate')
       OR source_claim ->> 'subject_sha'
          IS DISTINCT FROM COALESCE(NEW.candidate_sha, NEW.base_sha) THEN
        RAISE EXCEPTION 'terminal evidence predicate source binding contradicts its indexed commits'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_source_binding';
    END IF;

    -- admission signature: the predicate must record a positively verified
    -- EdDSA admission, otherwise the Work Order digest above proves only that
    -- some envelope was seen, not that it was accepted.
    IF (admission_claim -> 'signature_verification') ?& ARRAY[
           'verified', 'key_id', 'algorithm'
       ] IS NOT TRUE
       OR admission_claim #> '{signature_verification,verified}' IS DISTINCT FROM 'true'::jsonb
       OR admission_claim #>> '{signature_verification,algorithm}' IS DISTINCT FROM 'EdDSA'
       OR btrim(coalesce(admission_claim #>> '{signature_verification,key_id}', '')) = '' THEN
        RAISE EXCEPTION 'terminal evidence admission is not a positively verified EdDSA admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_admission_signature';
    END IF;

    -- cancellation evidence is required exactly for a cancelled run.
    IF jsonb_typeof(claim -> 'cancellation') NOT IN ('object', 'null')
       OR (NEW.terminal_phase = 'CANCELLED'
           AND jsonb_typeof(claim -> 'cancellation') <> 'object') THEN
        RAISE EXCEPTION 'CANCELLED terminal evidence must carry cancellation evidence'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_cancellation_binding';
    END IF;

    -- evidence: the terminal event is the event after every preceding event,
    -- and COMPLETED evidence must chain the immutable delivery bundle. The
    -- delivery digest is JSON null exactly when no delivery bundle exists.
    evidence_claim := claim -> 'evidence';
    IF evidence_claim ?& ARRAY[
           'preceding_event_count', 'preceding_event_chain_digest',
           'observations', 'events', 'delivery_bundle_digest'
       ] IS NOT TRUE
       OR jsonb_typeof(evidence_claim -> 'preceding_event_count') <> 'number'
       OR jsonb_typeof(evidence_claim -> 'observations') <> 'array'
       OR jsonb_typeof(evidence_claim -> 'events') <> 'array'
       OR jsonb_typeof(evidence_claim -> 'delivery_bundle_digest') NOT IN ('string', 'null')
       OR evidence_claim -> 'preceding_event_count'
          IS DISTINCT FROM to_jsonb(NEW.terminal_event_seq - 1)
       OR coalesce(evidence_claim ->> 'preceding_event_chain_digest', '')
          !~ '^sha256:[0-9a-f]{64}$'
       OR (jsonb_typeof(evidence_claim -> 'delivery_bundle_digest') = 'string'
           AND evidence_claim ->> 'delivery_bundle_digest' !~ '^sha256:[0-9a-f]{64}$')
       OR (NEW.terminal_phase = 'COMPLETED'
           AND jsonb_typeof(evidence_claim -> 'delivery_bundle_digest') <> 'string') THEN
        RAISE EXCEPTION 'terminal evidence event chain contradicts its indexed terminal sequence or delivery chain'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_evidence_binding';
    END IF;

    -- cleanup: terminal evidence may only be retained for a closed run.
    cleanup_claim := claim -> 'cleanup';
    IF cleanup_claim ?& ARRAY[
           'intent_id', 'intent_digest', 'observation_digest', 'identity_leases',
           'repository_lease', 'workspace', 'unresolved_effects'
       ] IS NOT TRUE
       OR coalesce(cleanup_claim ->> 'intent_digest', '') !~ '^sha256:[0-9a-f]{64}$'
       OR coalesce(cleanup_claim ->> 'observation_digest', '') !~ '^sha256:[0-9a-f]{64}$'
       OR btrim(coalesce(cleanup_claim ->> 'intent_id', '')) = ''
       OR cleanup_claim ->> 'identity_leases' IS DISTINCT FROM 'released'
       OR cleanup_claim ->> 'repository_lease' IS DISTINCT FROM 'released'
       OR cleanup_claim ->> 'workspace' IS DISTINCT FROM 'removed'
       OR cleanup_claim -> 'unresolved_effects' IS DISTINCT FROM to_jsonb(0) THEN
        RAISE EXCEPTION 'terminal evidence cleanup does not prove a closed run'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_cleanup_closure';
    END IF;

    -- timing: issuance is exactly the terminal evidence instant -- not merely
    -- at or after it -- and elapsed_ms exactly spans admission through terminal
    -- evidence.
    timing_claim := claim -> 'timing';
    admitted_instant := asf_evidence_verification_timestamp(timing_claim ->> 'admitted_at');
    terminal_instant := asf_evidence_verification_timestamp(
        timing_claim ->> 'terminal_evidence_at'
    );
    IF timing_claim ?& ARRAY['admitted_at', 'terminal_evidence_at', 'elapsed_ms'] IS NOT TRUE
       OR jsonb_typeof(timing_claim -> 'admitted_at') <> 'string'
       OR jsonb_typeof(timing_claim -> 'elapsed_ms') <> 'number'
       OR admitted_instant IS NULL
       OR terminal_instant IS NULL
       OR terminal_instant IS DISTINCT FROM NEW.issued_at
       OR terminal_instant < admitted_instant
       OR timing_claim -> 'elapsed_ms' IS DISTINCT FROM to_jsonb(
           (extract(epoch FROM (terminal_instant - admitted_instant)) * 1000)::bigint
       ) THEN
        RAISE EXCEPTION 'terminal evidence elapsed time does not bind admission through terminal evidence'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_predicate_timing_binding';
    END IF;

    -- in-toto subject: exactly one entry, named for the external Runmill run and
    -- digested by the predicate's own source subject commit. The subject is not
    -- an artifact digest and not the terminal bundle digest -- the bundle digest
    -- is bound by the envelope's bundle_digest above -- so it is a sha1 commit
    -- identifier keyed under 'sha1', matching predicate.source.subject_sha.
    subject_entry := attestation -> 'subject' -> 0;
    IF jsonb_array_length(attestation -> 'subject') <> 1
       OR jsonb_typeof(subject_entry) <> 'object'
       OR subject_entry ?& ARRAY['name', 'digest'] IS NOT TRUE
       OR subject_entry - ARRAY['name', 'digest'] <> '{}'::jsonb
       OR jsonb_typeof(subject_entry -> 'name') <> 'string'
       OR jsonb_typeof(subject_entry -> 'digest') <> 'object'
       -- Both contracts fix the subject name's shape, not its suffix: the Rust
       -- parser requires only the 'asf-run:' prefix and the Runmill schema only
       -- the identifier charset. The contract's own test vector pairs
       -- 'asf-run:test-run-1' with run.run_id 'run-123', so requiring the
       -- suffix to be the external run id would reject conformant evidence.
       -- The run binding is proven by predicate.run.run_id above, and the
       -- commit binding by the sha1 below.
       OR subject_entry ->> 'name' !~ '^asf-run:[A-Za-z0-9][A-Za-z0-9._:-]*$'
       OR (subject_entry -> 'digest') ?& ARRAY['sha1'] IS NOT TRUE
       OR (subject_entry -> 'digest') - ARRAY['sha1'] <> '{}'::jsonb
       OR jsonb_typeof(subject_entry -> 'digest' -> 'sha1') <> 'string'
       OR subject_entry #>> '{digest,sha1}' !~ '^[0-9a-f]{40}$'
       OR subject_entry -> 'digest' -> 'sha1'
          IS DISTINCT FROM source_claim -> 'subject_sha' THEN
        RAISE EXCEPTION 'terminal evidence statement subject is not the exact attested run subject'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_statement_subject';
    END IF;

    -- Every digest is re-derived from the retained bytes, never trusted. The
    -- envelope's own bundle_digest is the digest of the canonical statement it
    -- carries, so the signer's claim and the stored statement_digest must both
    -- reduce to the same sha256 of the same retained bytes. The evidence wire
    -- digest is the sha256 of the asf.get_evidence wire itself, including its
    -- terminating newline.
    IF NEW.terminal_evidence_response_wire_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.exact_terminal_evidence_response_wire), 'hex'
       )
       OR NEW.statement_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.canonical_statement), 'hex'
       )
       OR NEW.terminal_bundle_digest IS DISTINCT FROM 'sha256:' || encode(
           sha256(NEW.canonical_statement), 'hex'
       ) THEN
        RAISE EXCEPTION 'terminal evidence response or statement digest does not match its exact bytes'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_digests';
    END IF;

    -- The retained terminal evidence wire is the exact successful
    -- asf.get_evidence response: one complete NDJSON line, terminated by a
    -- single trailing newline that no interior byte repeats, decoding to the
    -- closed success envelope {ok:true,data:<object>}. A failure envelope, a
    -- multi-line body, or any extra top-level key is a different response and
    -- is refused outright.
    evidence_response := asf_source_closure_json(NEW.exact_terminal_evidence_response_wire);
    IF evidence_response IS NULL
       OR jsonb_typeof(evidence_response) <> 'object'
       OR evidence_response ?& ARRAY['ok', 'data'] IS NOT TRUE
       OR evidence_response - ARRAY['ok', 'data'] <> '{}'::jsonb
       OR evidence_response -> 'ok' IS DISTINCT FROM 'true'::jsonb
       OR jsonb_typeof(evidence_response -> 'data') <> 'object'
       OR get_byte(
              NEW.exact_terminal_evidence_response_wire,
              octet_length(NEW.exact_terminal_evidence_response_wire) - 1
          ) <> 10
       OR position(decode('0a', 'hex') in NEW.exact_terminal_evidence_response_wire)
          <> octet_length(NEW.exact_terminal_evidence_response_wire) THEN
        RAISE EXCEPTION 'terminal evidence response wire is not one exact {ok:true,data:...} asf.get_evidence success line'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_evidence_wire';
    END IF;

    -- The envelope's data is the Runmill evidence view. Its top-level key set is
    -- exactly the sixteen keys of asf.evidence-view/v1: this is the response
    -- contract ASF reads, so an unknown or missing key means the wire is not the
    -- read this row claims to be derived from.
    evidence_view := evidence_response -> 'data';
    IF evidence_view ?& ARRAY[
           'schema', 'runId', 'workOrderId', 'attemptId', 'phase',
           'candidateSha', 'policyDigest', 'latestSequence', 'status',
           'complete', 'bundleDigest', 'artifacts', 'latestEvent',
           'signedBundle', 'terminalBundleDigest', 'signedTerminalBundle'
       ] IS NOT TRUE
       OR evidence_view - ARRAY[
           'schema', 'runId', 'workOrderId', 'attemptId', 'phase',
           'candidateSha', 'policyDigest', 'latestSequence', 'status',
           'complete', 'bundleDigest', 'artifacts', 'latestEvent',
           'signedBundle', 'terminalBundleDigest', 'signedTerminalBundle'
       ] <> '{}'::jsonb
       OR jsonb_typeof(evidence_view -> 'schema') <> 'string'
       OR evidence_view ->> 'schema' <> 'asf.evidence-view/v1' THEN
        RAISE EXCEPTION 'terminal evidence response wire does not carry the exact asf.evidence-view/v1 object'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_evidence_view_contract';
    END IF;

    -- The evidence view is bound to this exact row. runId is Runmill's own
    -- external run identifier; workOrderId and attemptId are the stringified
    -- ASF uuids. latestSequence is compared as a JSON number, so a stringified
    -- sequence is a rejection rather than a coincidental text match, and it is
    -- the terminal sequence itself -- the evidence read observes the terminal
    -- event, unlike the event page, which observes the sequence before it.
    -- signedTerminalBundle is the very envelope retained in
    -- exact_signed_envelope, so the row cannot carry a signed bundle the read
    -- never returned.
    IF jsonb_typeof(evidence_view -> 'runId') <> 'string'
       OR jsonb_typeof(evidence_view -> 'workOrderId') <> 'string'
       OR jsonb_typeof(evidence_view -> 'attemptId') <> 'string'
       OR jsonb_typeof(evidence_view -> 'phase') <> 'string'
       OR jsonb_typeof(evidence_view -> 'latestSequence') <> 'number'
       OR jsonb_typeof(evidence_view -> 'terminalBundleDigest') <> 'string'
       OR jsonb_typeof(evidence_view -> 'signedTerminalBundle') <> 'object'
       OR evidence_view ->> 'runId' IS DISTINCT FROM NEW.external_run_id
       OR evidence_view ->> 'workOrderId' IS DISTINCT FROM NEW.work_order_id::text
       OR evidence_view ->> 'attemptId' IS DISTINCT FROM NEW.attempt_id::text
       OR evidence_view ->> 'phase' IS DISTINCT FROM NEW.terminal_phase
       OR evidence_view -> 'latestSequence'
          IS DISTINCT FROM to_jsonb(NEW.terminal_event_seq)
       OR evidence_view ->> 'terminalBundleDigest'
          IS DISTINCT FROM NEW.terminal_bundle_digest
       OR evidence_view -> 'signedTerminalBundle' IS DISTINCT FROM envelope THEN
        RAISE EXCEPTION 'terminal evidence response wire contradicts the row it is retained for'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_evidence_view_binding';
    END IF;

    SELECT snapshot.* INTO get_run
    FROM runmill_control_snapshots AS snapshot
    WHERE snapshot.tenant_id = NEW.tenant_id
      AND snapshot.id = NEW.get_run_snapshot_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal evidence bundle references an absent GET_RUN snapshot'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_snapshots';
    END IF;

    SELECT snapshot.* INTO event_page
    FROM runmill_control_snapshots AS snapshot
    WHERE snapshot.tenant_id = NEW.tenant_id
      AND snapshot.id = NEW.event_page_snapshot_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal evidence bundle references an absent LIST_RUN_EVENTS snapshot'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_snapshots';
    END IF;

    -- Exact snapshot roles and exact ownership. Both snapshots must come from
    -- the one stream observation, so a GET_RUN from one poll cannot be paired
    -- with an event page from another.
    IF get_run.control_operation <> 'GET_RUN'
       OR event_page.control_operation <> 'LIST_RUN_EVENTS'
       OR get_run.observation_id IS NULL
       OR get_run.observation_id IS DISTINCT FROM event_page.observation_id
       OR (get_run.run_id, get_run.work_item_id, get_run.attempt_id,
           get_run.work_order_id, get_run.work_order_digest,
           get_run.worker_session_id, get_run.worker_id,
           get_run.worker_generation, get_run.external_run_id)
          IS DISTINCT FROM
          (NEW.run_id, NEW.work_item_id, NEW.attempt_id,
           NEW.work_order_id, NEW.work_order_digest,
           NEW.worker_session_id, NEW.worker_id,
           NEW.worker_generation, NEW.external_run_id)
       OR (event_page.run_id, event_page.work_item_id, event_page.attempt_id,
           event_page.work_order_id, event_page.work_order_digest,
           event_page.worker_session_id, event_page.worker_id,
           event_page.worker_generation, event_page.external_run_id)
          IS DISTINCT FROM
          (NEW.run_id, NEW.work_item_id, NEW.attempt_id,
           NEW.work_order_id, NEW.work_order_digest,
           NEW.worker_session_id, NEW.worker_id,
           NEW.worker_generation, NEW.external_run_id) THEN
        RAISE EXCEPTION 'terminal evidence snapshots contradict their exact operation or ownership'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_exact_snapshots';
    END IF;

    -- Snapshot provenance, separate from the evidence wire above: both
    -- snapshots must independently report the terminal phase. Neither snapshot
    -- wire is required to be the retained asf.get_evidence wire -- they are
    -- different reads of different Runmill endpoints, and conflating them would
    -- make the row's response bytes prove the phase observation instead of the
    -- terminal evidence read. The event page's latest sequence is the last
    -- sequence observed before the terminal event is appended, so it is the
    -- terminal sequence minus one, exactly as the predicate's own
    -- preceding_event_count is.
    IF get_run.raw_snapshot #>> '{run,state}' IS DISTINCT FROM NEW.terminal_phase
       OR event_page.raw_snapshot #>> '{snapshot,run,state}' IS DISTINCT FROM NEW.terminal_phase
       OR event_page.external_latest_sequence
          IS DISTINCT FROM NEW.terminal_event_seq - 1 THEN
        RAISE EXCEPTION 'terminal evidence bundle contradicts its exact terminal snapshot observation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_terminal_observation';
    END IF;

    -- Finally, the stream itself must have reached TERMINAL_READY through the
    -- exact observation result these two snapshots belong to. Without this a
    -- bundle could be minted from snapshots the stream never accepted.
    PERFORM 1
    FROM runmill_run_observation_streams AS stream
    JOIN runmill_run_observation_results AS result
      ON result.tenant_id = stream.tenant_id
     AND result.run_id = stream.run_id
    WHERE stream.tenant_id = NEW.tenant_id
      AND stream.run_id = NEW.run_id
      AND stream.state = 'TERMINAL_READY'
      AND stream.work_item_id = NEW.work_item_id
      AND stream.attempt_id = NEW.attempt_id
      AND stream.work_order_id = NEW.work_order_id
      AND stream.work_order_digest = NEW.work_order_digest
      AND stream.worker_id = NEW.worker_id
      AND stream.worker_generation = NEW.worker_generation
      AND stream.run_admission_worker_session_id = NEW.worker_session_id
      AND stream.external_run_id = NEW.external_run_id
      AND result.disposition = 'TERMINAL_READY'
      AND result.get_run_snapshot_id = NEW.get_run_snapshot_id
      AND result.event_page_snapshot_id = NEW.event_page_snapshot_id
      AND result.next_sequence = NEW.terminal_event_seq - 1
    FOR SHARE OF stream, result;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal evidence bundle lacks a TERMINAL_READY stream and observation result'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_terminal_ready_stream';
    END IF;

    NEW.stored_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER runmill_terminal_evidence_bundle_insert
    BEFORE INSERT ON runmill_terminal_evidence_bundles
    FOR EACH ROW
    EXECUTE FUNCTION asf_assert_runmill_terminal_evidence_bundle_insert();

-- Terminal evidence bundles are strictly append-only: no column may ever be
-- updated and no row may ever be deleted. Corrections are new bundles.
CREATE FUNCTION asf_guard_runmill_terminal_evidence_bundle_append_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'terminal evidence bundles cannot be deleted'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runmill_terminal_evidence_bundles_append_only';
    END IF;

    RAISE EXCEPTION 'terminal evidence bundles cannot be updated'
        USING ERRCODE = '23514',
              CONSTRAINT = 'runmill_terminal_evidence_bundles_append_only';
END;
$$;

CREATE TRIGGER runmill_terminal_evidence_bundle_append_only
    BEFORE UPDATE OR DELETE ON runmill_terminal_evidence_bundles
    FOR EACH ROW
    EXECUTE FUNCTION asf_guard_runmill_terminal_evidence_bundle_append_only();

-- Row-level guards do not fire for TRUNCATE, so immutability needs the same
-- statement-level rejection every other append-only ASF table installs.
CREATE TRIGGER runmill_terminal_evidence_bundle_truncate_forbidden
    BEFORE TRUNCATE ON runmill_terminal_evidence_bundles
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_row_mutation();
