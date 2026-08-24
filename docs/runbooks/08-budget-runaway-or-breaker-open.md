# Budget runaway or breaker open

**Severity:** high; critical for uncontrolled cost/concurrency or policy bypass. **Primary owner:** platform/finance on-call. **Escalation category:** `BUDGET_EXHAUSTED` or `SECURITY_INCIDENT`.

## Trigger and impact

Trigger on spend/token/invocation/wall-time/concurrency/WIP thresholds, rapidly increasing reservations or consumption, repeated fix loops, or a breaker opening from failure/quarantine/reconciliation metrics. Budget state is durable and must not reset with process restart.

## Contain

1. Keep the breaker open at the narrowest proven scope; use tenant maintenance mode if growth continues or scope is uncertain.
2. Stop new reservations and dispatch. Ask Runmill to safely cancel wasteful active runs where policy permits; continue observing cancellation and effects.
3. Do not delete or rewrite budget entries, close the breaker without root cause, or grant a blanket limit increase.
4. Ensure exhausted items receive an owned escalation with retry prerequisites and no hidden active authority.

## Diagnose

```sql
SELECT scope_type, scope_id, dimension, unit, currency,
       sum(amount) FILTER (WHERE entry_type = 'RESERVE') AS reserved,
       sum(amount) FILTER (WHERE entry_type = 'CONSUME') AS consumed,
       sum(amount) FILTER (WHERE entry_type = 'RELEASE') AS released,
       sum(amount) FILTER (WHERE entry_type = 'ADJUST') AS adjusted,
       max(occurred_at) AS latest
FROM budget_ledger
GROUP BY scope_type, scope_id, dimension, unit, currency
ORDER BY scope_type, scope_id, dimension;

SELECT scope_type, scope_id, breaker_type, state, reason, metrics,
       generation, opened_at, retry_after
FROM circuit_breakers
WHERE state <> 'CLOSED'
ORDER BY opened_at;
```

- Break down usage by tenant, repository, worker, provider, model, work class, attempt, role, and time window.
- Compare Runmill usage events/evidence to reservations and append-only consumption.
- Look for duplicated event ingestion, retry loops, stuck jobs, stale reservations, model/provider changes, and malicious or expanded tool use.
- Treat any caller-supplied `asf-internal:` idempotency key as an integrity fault. PostgreSQL accepts that namespace only for the deterministic expiry transition bound to an exact reservation set/prior fence and for the matching per-dimension budget releases; a cross-set or preoccupied future key is rejected.
- Confirm provider billing/usage independently when available.

## Recover

1. Fix the accounting, retry, policy, or workload cause. Corrections are append-only `ADJUST`/`RELEASE` entries with approval/audit, never edits.
2. Reconcile active runs and actual consumption before releasing reservations.
3. A limit increase must be narrowly scoped, digest-bound, time-limited, and approved; it normally creates new authority for a new attempt.
4. Move to half-open with one low-risk canary and tight limits. Close only after the observation window.

## Verify and close

- Ledger totals reconcile with Runmill and provider data.
- Reservation, concurrency, and repository WIP values match live work.
- No retry/fix loop can grow without a durable limit.
- Breaker transition, adjustment, cancellation, and approval are audited.

Attach cost/usage timeline, affected scopes/attempts, provider comparison, breaker generations, append-only corrections, approver, and canary result.
