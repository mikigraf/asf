# Provider outage or rate limit

**Severity:** medium to high. **Primary owner:** platform on-call; identity/provider owner assists. **Escalation category:** `BLOCKED_EXTERNAL` or `PROVIDER_REFUSED`.

## Trigger and impact

Trigger on sustained provider errors, global throttling, invalid service responses, or a retry-after window that prevents active runs from making progress. A refusal based on policy/account eligibility is not automatically an outage.

## Contain

1. Open a provider/model-scoped breaker and stop new reservations for the affected scope.
2. Honor server-provided retry windows with bounded jitter. Disable retry storms across roles/workers.
3. Preserve active Runmill runs and their checkpoints. Do not change provider/model identity within an immutable Work Order.
4. Continue event observation, cancellation, reconciliation, and evidence access.
5. Ensure wall-time and budget timers keep advancing according to policy; an outage does not reset budgets.

## Diagnose

- Compare failures across worker, profile, account, region, model, and API operation.
- Separate authentication/principal errors, policy refusal, quota exhaustion, rate limit, transport failure, and provider incident.
- Record provider request/correlation IDs and sanitized status/error categories; never capture authorization headers.
- Check reservation versus consumption and the number of waiting attempts.

```sql
SELECT scope_type, scope_id, dimension,
       sum(amount) FILTER (WHERE entry_type = 'RESERVE') AS reserved,
       sum(amount) FILTER (WHERE entry_type = 'CONSUME') AS consumed,
       sum(amount) FILTER (WHERE entry_type = 'RELEASE') AS released,
       sum(amount) FILTER (WHERE entry_type = 'ADJUST') AS adjusted
FROM budget_ledger
WHERE occurred_at >= clock_timestamp() - interval '24 hours'
GROUP BY scope_type, scope_id, dimension
ORDER BY scope_type, scope_id, dimension;

SELECT state, count(*)
FROM runs
WHERE terminal_at IS NULL
GROUP BY state;
```

## Recover

1. Confirm provider status and a successful trusted health probe for the same workload identity class.
2. Move the breaker to a bounded half-open test; allow one canary, not the entire backlog.
3. Resume the same Runmill runs/checkpoints where safe. A provider/model substitution requires policy evaluation and usually a new Work Order/attempt.
4. Apply documented retry-after times and preserve original idempotency/correlation IDs.
5. Reconcile actual usage before releasing or increasing budget reservations.

## Verify and close

- Error/rate-limit rate is below the configured close threshold for the observation window.
- The canary has correct identity attribution and budget accounting.
- Backlog age is falling without a retry surge.
- All stopped accepted items retain an owner/timer/retry/closure anchor.

Attach provider status evidence, affected scope, sanitized error distribution, breaker timeline, budget impact, canary result, and retry schedule.
