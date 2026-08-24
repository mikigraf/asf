-- V1 is deliberately a single-tenant control plane.  Serialize the
-- historical preflight with every tenant writer before creating the durable
-- deployment boundary.
LOCK TABLE tenants IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM tenants) > 1 THEN
        RAISE EXCEPTION 'V1 supports at most one historical tenant'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'v1_tenant_boundary_upgrade_requires_at_most_one_tenant';
    END IF;
END;
$$;

-- A fresh schema deliberately remains unconfigured so isolated tests and
-- tooling can create fixtures.  A populated single-tenant deployment is
-- bound immediately; production bootstrap binds an empty deployment in the
-- same transaction that creates its configured tenant.
CREATE TABLE v1_tenant_deployment_guards (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    configured_tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT
);

INSERT INTO v1_tenant_deployment_guards (singleton, configured_tenant_id)
SELECT true, (SELECT id FROM tenants LIMIT 1);

CREATE FUNCTION asf_guard_v1_tenant_deployment_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.singleton = NEW.singleton
       AND OLD.configured_tenant_id IS NULL
       AND NEW.configured_tenant_id IS NOT NULL THEN
        -- Tenant DML takes its table lock before it serializes on this guard.
        -- Take the same lock here so direct SQL activation cannot validate
        -- against a tenant set that is changing concurrently.  The production
        -- bootstrap already holds this lock in the same order; a racing direct
        -- update may be aborted by PostgreSQL, but it can never bind an
        -- inconsistent deployment.
        LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE;
        IF NOT EXISTS (
            SELECT 1
            FROM tenants
            WHERE id = NEW.configured_tenant_id
        ) THEN
            RAISE EXCEPTION 'the V1 tenant deployment target does not exist'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'v1_tenant_deployment_guard_target_missing';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM tenants
            WHERE id <> NEW.configured_tenant_id
        ) THEN
            RAISE EXCEPTION 'the V1 tenant deployment requires exactly one tenant'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'v1_tenant_deployment_guard_requires_exactly_one_tenant';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'the V1 tenant deployment guard is append-only'
        USING ERRCODE = '23514',
              CONSTRAINT = 'v1_tenant_deployment_guard_append_only';
END;
$$;

CREATE TRIGGER v1_tenant_deployment_guard_append_only
    BEFORE UPDATE OR DELETE ON v1_tenant_deployment_guards
    FOR EACH ROW EXECUTE FUNCTION asf_guard_v1_tenant_deployment_guard();

CREATE FUNCTION asf_reject_v1_tenant_deployment_guard_truncate() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'the V1 tenant deployment guard cannot be truncated'
        USING ERRCODE = '23514',
              CONSTRAINT = 'v1_tenant_deployment_guard_truncate_forbidden';
END;
$$;

CREATE TRIGGER v1_tenant_deployment_guard_truncate_forbidden
    BEFORE TRUNCATE ON v1_tenant_deployment_guards
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_v1_tenant_deployment_guard_truncate();

CREATE FUNCTION asf_guard_v1_tenant_boundary() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    configured_tenant uuid;
BEGIN
    SELECT guard.configured_tenant_id
      INTO configured_tenant
     FROM v1_tenant_deployment_guards AS guard
     WHERE guard.singleton
       FOR UPDATE;

    IF configured_tenant IS NOT NULL AND NEW.id <> configured_tenant THEN
        RAISE EXCEPTION 'V1 permits rows for only its configured tenant'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'v1_tenant_boundary_configured_tenant_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_v1_single_tenant_boundary
    BEFORE INSERT OR UPDATE OF id ON tenants
    FOR EACH ROW EXECUTE FUNCTION asf_guard_v1_tenant_boundary();

CREATE FUNCTION asf_guard_active_v1_tenant_delete() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    configured_tenant uuid;
BEGIN
    SELECT guard.configured_tenant_id
      INTO configured_tenant
     FROM v1_tenant_deployment_guards AS guard
     WHERE guard.singleton
       FOR UPDATE;

    IF configured_tenant IS NOT NULL AND OLD.id = configured_tenant THEN
        RAISE EXCEPTION 'the configured V1 tenant cannot be deleted'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'v1_tenant_boundary_delete_forbidden';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER tenants_v1_single_tenant_delete_boundary
    BEFORE DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION asf_guard_active_v1_tenant_delete();

CREATE FUNCTION asf_reject_active_v1_tenant_truncate() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    configured_tenant uuid;
BEGIN
    SELECT configured_tenant_id
      INTO configured_tenant
      FROM v1_tenant_deployment_guards
     WHERE singleton
       FOR UPDATE;

    IF configured_tenant IS NOT NULL THEN
        RAISE EXCEPTION 'the configured V1 tenant cannot be truncated'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'v1_tenant_boundary_truncate_forbidden';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER tenants_v1_single_tenant_truncate_boundary
    BEFORE TRUNCATE ON tenants
    FOR EACH STATEMENT EXECUTE FUNCTION asf_reject_active_v1_tenant_truncate();
