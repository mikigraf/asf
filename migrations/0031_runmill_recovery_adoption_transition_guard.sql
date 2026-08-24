-- Forward-only transition guards for runmill submission recovery adoptions:
-- Ensure that an effect_intents transition from AMBIGUOUS to OBSERVED for provider
-- runmill/effect_type submit_work_order is permitted only when an exact matching row
-- exists in runmill_submission_recovery_adoptions (tenant, effect ID, and receipt/run binding).
-- Ensure resolving its linked REMOTE_EFFECT_AMBIGUOUS escalation requires that same
-- adoption fact. Preserve allowed non-adoption state transitions.

LOCK TABLE effect_intents IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE escalations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE runmill_submission_recovery_adoptions IN SHARE ROW EXCLUSIVE MODE;

-- Guard effect_intents transitions to OBSERVED for runmill/submit_work_order effects:
-- Only permit AMBIGUOUS → OBSERVED transitions when an exact matching adoption fact
-- exists with the same tenant and effect_intent_id. The adoption row holds the exact
-- receipt/run binding (external_run_id, worker_id, worker_generation, worker_session_id).
--
-- Non-adoption transitions (e.g., AMBIGUOUS → FAILED, OBSERVED → other states) are not
-- guarded by this trigger and proceed normally.
CREATE FUNCTION asf_guard_runmill_effect_transition_to_observed() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_adoption runmill_submission_recovery_adoptions%ROWTYPE;
BEGIN
    -- Only guard AMBIGUOUS → OBSERVED transitions for runmill/submit_work_order effects.
    -- All other state transitions (failed, retried, etc.) are allowed without adoption.
    IF OLD.status = 'AMBIGUOUS'
       AND NEW.status = 'OBSERVED'
       AND NEW.provider = 'runmill'
       AND NEW.effect_type = 'submit_work_order'
    THEN
        -- Require an exact matching adoption fact with same tenant and effect_intent_id.
        -- The adoption row contains the exact receipt/run binding.
        SELECT adoption.*
        INTO linked_adoption
        FROM runmill_submission_recovery_adoptions AS adoption
        WHERE adoption.tenant_id = NEW.tenant_id
          AND adoption.effect_intent_id = NEW.id
        FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'effect_intent transition from AMBIGUOUS to OBSERVED for runmill/submit_work_order requires an exact matching adoption fact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_effect_transition_to_observed_requires_adoption';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION asf_guard_runmill_effect_transition_to_observed() IS
    'Guard: effect_intents AMBIGUOUS → OBSERVED transition for runmill/submit_work_order only permitted with exact matching adoption fact (tenant, effect_id).';

CREATE TRIGGER runmill_effect_transition_to_observed_guard
    BEFORE UPDATE ON effect_intents
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_effect_transition_to_observed();

-- Guard escalation resolution for REMOTE_EFFECT_AMBIGUOUS escalations:
-- Only permit escalations of type REMOTE_EFFECT_AMBIGUOUS to transition to RESOLVED
-- when an exact matching adoption fact exists with the same tenant and escalation_id.
--
-- Non-REMOTE_EFFECT_AMBIGUOUS escalations and non-resolution state changes are not
-- guarded by this trigger and proceed normally.
CREATE FUNCTION asf_guard_runmill_escalation_resolution_requires_adoption() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_adoption runmill_submission_recovery_adoptions%ROWTYPE;
BEGIN
    -- Only guard transitions to RESOLVED for REMOTE_EFFECT_AMBIGUOUS escalations.
    -- All other escalation types and non-resolution transitions are allowed.
    IF (OLD.status IS DISTINCT FROM 'RESOLVED')
       AND NEW.status = 'RESOLVED'
       AND NEW.escalation_type = 'REMOTE_EFFECT_AMBIGUOUS'
    THEN
        -- Require an exact matching adoption fact with same tenant and escalation_id.
        -- The adoption row is unique per tenant+escalation (see 0030 UNIQUE constraint).
        SELECT adoption.*
        INTO linked_adoption
        FROM runmill_submission_recovery_adoptions AS adoption
        WHERE adoption.tenant_id = NEW.tenant_id
          AND adoption.escalation_id = NEW.id
        FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'escalation resolution for REMOTE_EFFECT_AMBIGUOUS requires an exact matching adoption fact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runmill_escalation_resolution_requires_adoption';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION asf_guard_runmill_escalation_resolution_requires_adoption() IS
    'Guard: escalations REMOTE_EFFECT_AMBIGUOUS → RESOLVED transition only permitted with exact matching adoption fact (tenant, escalation_id).';

CREATE TRIGGER runmill_escalation_resolution_guard
    BEFORE UPDATE ON escalations
    FOR EACH ROW EXECUTE FUNCTION asf_guard_runmill_escalation_resolution_requires_adoption();
