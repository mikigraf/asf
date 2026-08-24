-- A worker generation is an authority epoch only if the signing key used by
-- runs and evidence is retained with that epoch.  Snapshot the exact worker
-- key on every session, bind evidence to the run-owned session, and prohibit
-- same-generation rewrites of endpoint/capability/key authority.
--
-- Apply with executors quiesced.  The pre-0011 schema did not retain historical
-- public keys and even allowed key bytes to change while reusing a key ID.
-- Consequently, a database that already contains a run cannot prove which key
-- authorized that run from SQL state alone.  Refuse that upgrade instead of
-- copying the current key and inventing provenance.  Operators must migrate
-- such history through an independently verified key-history import.
LOCK TABLE workers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE worker_sessions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE runs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE evidence_bundles IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM runs) THEN
        RAISE EXCEPTION 'historical run signing authority cannot be reconstructed safely'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'worker_session_signing_authority_requires_verified_history';
    END IF;
END;
$$;

DROP TRIGGER worker_session_guard ON worker_sessions;
DROP TRIGGER evidence_bundles_immutable ON evidence_bundles;

ALTER TABLE worker_sessions
    ADD COLUMN signing_key_id text,
    ADD COLUMN signing_public_key text;

UPDATE worker_sessions AS session
SET signing_key_id = worker.signing_key_id,
    signing_public_key = worker.signing_public_key
FROM workers AS worker
WHERE worker.tenant_id = session.tenant_id
  AND worker.id = session.worker_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM worker_sessions
        WHERE signing_key_id IS NULL
           OR btrim(signing_key_id) = ''
           OR signing_public_key IS NULL
           OR btrim(signing_public_key) = ''
    ) THEN
        RAISE EXCEPTION 'worker-session signing authority cannot be reconstructed'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'worker_sessions_require_signing_authority';
    END IF;
END;
$$;

ALTER TABLE worker_sessions
    ALTER COLUMN signing_key_id SET NOT NULL,
    ALTER COLUMN signing_public_key SET NOT NULL,
    ADD CONSTRAINT worker_sessions_signing_key_id_nonempty
        CHECK (btrim(signing_key_id) <> ''),
    ADD CONSTRAINT worker_sessions_signing_public_key_nonempty
        CHECK (btrim(signing_public_key) <> ''),
    ADD CONSTRAINT worker_sessions_signing_authority_key
        UNIQUE (
            tenant_id,
            id,
            worker_id,
            worker_generation,
            signing_key_id
        );

ALTER TABLE evidence_bundles
    ADD COLUMN worker_session_id uuid;

UPDATE evidence_bundles AS evidence
SET worker_session_id = run.worker_session_id
FROM runs AS run
JOIN worker_sessions AS session
  ON session.tenant_id = run.tenant_id
 AND session.id = run.worker_session_id
 AND session.worker_id = run.worker_id
 AND session.worker_generation = run.worker_generation
WHERE run.tenant_id = evidence.tenant_id
  AND run.id = evidence.run_id
  AND run.work_item_id = evidence.work_item_id
  AND run.attempt_id = evidence.attempt_id
  AND run.worker_id = evidence.worker_id
  AND run.worker_generation = evidence.worker_generation
  AND session.signing_key_id = evidence.key_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence_bundles
        WHERE worker_session_id IS NULL
    ) THEN
        RAISE EXCEPTION 'evidence signing authority contradicts its exact run session'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_bundles_exact_session_signing_authority';
    END IF;
END;
$$;

ALTER TABLE evidence_bundles
    ALTER COLUMN worker_session_id SET NOT NULL,
    ADD CONSTRAINT evidence_bundles_exact_run_session_fk
        FOREIGN KEY (
            tenant_id,
            run_id,
            worker_session_id,
            worker_id,
            worker_generation
        )
        REFERENCES runs (
            tenant_id,
            id,
            worker_session_id,
            worker_id,
            worker_generation
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_bundles_exact_session_signing_authority_fk
        FOREIGN KEY (
            tenant_id,
            worker_session_id,
            worker_id,
            worker_generation,
            key_id
        )
        REFERENCES worker_sessions (
            tenant_id,
            id,
            worker_id,
            worker_generation,
            signing_key_id
        )
        ON DELETE RESTRICT;

CREATE INDEX evidence_bundles_worker_session_idx
    ON evidence_bundles (tenant_id, worker_session_id, id);

-- Session creation locks the worker row, snapshots its exact current key, and
-- rejects a caller-supplied contradictory snapshot.  The key remains immutable
-- after the row is opened, including after close/revocation.
CREATE OR REPLACE FUNCTION asf_guard_worker_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_worker_generation bigint;
    current_worker_status text;
    current_signing_key_id text;
    current_signing_public_key text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT
            worker.generation,
            worker.status,
            worker.signing_key_id,
            worker.signing_public_key
        INTO
            current_worker_generation,
            current_worker_status,
            current_signing_key_id,
            current_signing_public_key
        FROM workers AS worker
        WHERE worker.tenant_id = NEW.tenant_id
          AND worker.id = NEW.worker_id
        FOR UPDATE;

        IF NOT FOUND OR current_worker_generation <> NEW.worker_generation THEN
            RAISE EXCEPTION 'worker session generation % is stale for worker %',
                NEW.worker_generation, NEW.worker_id
                USING ERRCODE = '40001';
        END IF;
        IF current_worker_status = 'QUARANTINED' THEN
            RAISE EXCEPTION 'a quarantined worker cannot open a new session'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'worker_sessions_refuse_quarantined_worker';
        END IF;
        IF NEW.signing_key_id IS NULL THEN
            NEW.signing_key_id := current_signing_key_id;
        END IF;
        IF NEW.signing_public_key IS NULL THEN
            NEW.signing_public_key := current_signing_public_key;
        END IF;
        IF NEW.signing_key_id IS DISTINCT FROM current_signing_key_id
           OR NEW.signing_public_key IS DISTINCT FROM current_signing_public_key THEN
            RAISE EXCEPTION 'worker session signing authority contradicts its worker epoch'
                USING ERRCODE = '40001',
                      CONSTRAINT = 'worker_sessions_require_current_signing_authority';
        END IF;
        IF NEW.status = 'ACTIVE' AND NEW.expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'active worker session must expire in the future'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id <> OLD.tenant_id
       OR NEW.id <> OLD.id
       OR NEW.worker_id <> OLD.worker_id
       OR NEW.worker_generation <> OLD.worker_generation
       OR NEW.signing_key_id <> OLD.signing_key_id
       OR NEW.signing_public_key <> OLD.signing_public_key
       OR NEW.started_at <> OLD.started_at THEN
        RAISE EXCEPTION 'worker session identity, generation, and signing authority are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'ACTIVE' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'closed or revoked worker sessions are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'CLOSED', 'REVOKED') THEN
        RAISE EXCEPTION 'invalid worker session status transition'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'ACTIVE' AND NEW.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'active worker session must expire in the future'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER worker_session_guard
    BEFORE INSERT OR UPDATE ON worker_sessions
    FOR EACH ROW EXECUTE FUNCTION asf_guard_worker_session();

-- Endpoint, capability, concurrency, and signing-key changes create the next
-- exact epoch; they cannot rewrite the meaning of already admitted sessions
-- and runs.
CREATE OR REPLACE FUNCTION asf_guard_worker_generation() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authority_changed boolean;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'worker identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    authority_changed := ROW(
        NEW.endpoint,
        NEW.capabilities,
        NEW.max_concurrency,
        NEW.signing_key_id,
        NEW.signing_public_key
    ) IS DISTINCT FROM ROW(
        OLD.endpoint,
        OLD.capabilities,
        OLD.max_concurrency,
        OLD.signing_key_id,
        OLD.signing_public_key
    );

    IF NEW.generation IS DISTINCT FROM OLD.generation THEN
        IF NEW.generation <> OLD.generation + 1 THEN
            RAISE EXCEPTION 'worker generation must advance by exactly one'
                USING ERRCODE = '40001';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM worker_sessions AS session
            WHERE session.tenant_id = OLD.tenant_id
              AND session.worker_id = OLD.id
              AND session.status = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'close the active worker session before advancing generation'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.status NOT IN ('REGISTERED', 'QUARANTINED') THEN
            RAISE EXCEPTION 'a new worker generation must be requalified before use'
                USING ERRCODE = '23514';
        END IF;
    ELSIF authority_changed THEN
        RAISE EXCEPTION 'worker authority changes require a new generation'
            USING ERRCODE = '40001',
                  CONSTRAINT = 'workers_authority_requires_new_generation';
    END IF;

    IF OLD.status = 'QUARANTINED'
       AND NEW.status <> 'QUARANTINED'
       AND NEW.generation = OLD.generation THEN
        RAISE EXCEPTION 'quarantined workers require a clean next-generation repair'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'workers_quarantine_is_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

-- Evidence insertion derives its session only from the exact bound run and
-- proves that the signed envelope key is the immutable session key.
CREATE FUNCTION asf_guard_evidence_worker_session() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    exact_session_id uuid;
    exact_worker_id uuid;
    exact_worker_generation bigint;
    exact_signing_key_id text;
BEGIN
    SELECT
        run.worker_session_id,
        run.worker_id,
        run.worker_generation,
        session.signing_key_id
    INTO
        exact_session_id,
        exact_worker_id,
        exact_worker_generation,
        exact_signing_key_id
    FROM runs AS run
    JOIN worker_sessions AS session
      ON session.tenant_id = run.tenant_id
     AND session.id = run.worker_session_id
     AND session.worker_id = run.worker_id
     AND session.worker_generation = run.worker_generation
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.run_id
      AND run.work_item_id = NEW.work_item_id
      AND run.attempt_id = NEW.attempt_id
    FOR KEY SHARE OF run, session;

    IF NOT FOUND
       OR NEW.worker_id IS DISTINCT FROM exact_worker_id
       OR NEW.worker_generation IS DISTINCT FROM exact_worker_generation
       OR NEW.key_id IS DISTINCT FROM exact_signing_key_id
       OR (
           NEW.worker_session_id IS NOT NULL
           AND NEW.worker_session_id IS DISTINCT FROM exact_session_id
       ) THEN
        RAISE EXCEPTION 'evidence does not use its exact run-session signing authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'evidence_bundles_exact_session_signing_authority';
    END IF;
    NEW.worker_session_id := exact_session_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_bundles_worker_session_guard
    BEFORE INSERT ON evidence_bundles
    FOR EACH ROW EXECUTE FUNCTION asf_guard_evidence_worker_session();

CREATE TRIGGER evidence_bundles_immutable
    BEFORE UPDATE OR DELETE ON evidence_bundles
    FOR EACH ROW EXECUTE FUNCTION asf_reject_row_mutation();
