# ctxlane identity unavailable or principal mismatch

**Severity:** high; critical for an unexpected principal. **Primary owner:** identity/platform on-call. **Escalation category:** `IDENTITY_UNAVAILABLE` or `SECURITY_INCIDENT`.

## Trigger and impact

Trigger when worker-side preflight cannot resolve an eligible profile, a lease cannot be issued/renewed, or the observed provider principal differs from the Work Order requirement. ASF does not own provider credentials and cannot safely bypass this check.

## Contain

1. Stop new dispatch in the affected profile/provider/worker scope. Use maintenance mode if the scope is unknown.
2. For principal mismatch, quarantine the worker/run and treat it as possible credential or routing compromise.
3. Do not substitute a personal identity, inject credentials into ASF/Runmill, or edit an in-flight Work Order's identity reference.
4. Preserve the current run and ask Runmill for a bounded safe pause/cancellation; do not assume a failed lease stopped provider activity.
5. Ensure every affected item has an owned escalation and deadline.

## Diagnose

- Record requested profile, role, expected principal, observed principal, worker ID/generation, lease metadata excluding handles/tokens, Runmill run, and Work Order digest.
- Check ctxlane broker health, provider profile eligibility, revocation/expiry, workload identity, clock skew, provider account status, and concurrency limits.
- Determine whether only preflight failed or an active role invocation lost its renewable lease.
- Inspect recent `IDENTITY_UNAVAILABLE`, `PROVIDER_REFUSED`, and `SECURITY_INCIDENT` escalations for common scope.

```sql
SELECT w.id, w.name, w.status, w.generation, w.last_seen_at, w.capabilities
FROM workers AS w
ORDER BY w.last_seen_at NULLS FIRST;

SELECT scope_type, scope_id, breaker_type, state, reason, retry_after
FROM circuit_breakers
WHERE state <> 'CLOSED'
  AND scope_type IN ('WORKER','PROVIDER');
```

## Recover

1. Restore the configured dedicated workload identity in ctxlane and prove its principal through the worker-side trusted preflight.
2. Re-negotiate Runmill/ctxlane capabilities and verify profile, role separation, provider, and lease policy.
3. If the identity reference or authority must change, cancel/revoke safely and create a new attempt with a newly signed Work Order after readiness and any approval. Never rewrite the old order.
4. Resume an existing Runmill checkpoint only if Runmill proves the same attempt/run and safely acquires the expected identity.
5. For mismatch, complete incident review and rotate/revoke affected credentials before restoring dispatch.

## Verify and close

- Implementer and reviewer resolve to distinct eligible principals where policy requires it.
- No provider credential or execution handle appears in ASF, repository sandbox, logs, evidence, or support bundles.
- A canary preflight and bounded non-production invocation show the expected principal and attribution.
- Circuit breaker closure and any changed policy/profile are audited.

Attach redacted preflight results, expected/observed principal IDs, lease timing, affected run list, credential actions, and canary evidence.
