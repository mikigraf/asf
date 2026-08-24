# Workflow backlog or stuck timer

**Severity:** high when accountability or SLA objectives are at risk. **Primary owner:** platform/database on-call. **Escalation category:** `BLOCKED_EXTERNAL` or a category matching each underlying stop.

## Trigger and impact

Trigger when oldest due job/timer age, expired leases, dead jobs, reconciliation lag, or accepted-without-progress metrics exceed thresholds. The reactor is PostgreSQL-backed, so restarting a process should not lose work.

## Contain

1. Enable maintenance mode if backlog growth, database health, or reactor correctness is uncertain. Keep recovery/observation loops running.
2. Do not delete/requeue rows manually or shorten leases to steal active work.
3. Prevent autoscaling from creating database connection exhaustion.
4. Identify accepted items whose current anchor is near/past deadline and assign incident ownership.

## Diagnose

```sql
SELECT status, count(*) AS jobs,
       min(available_at) FILTER (WHERE status IN ('PENDING','RETRY')) AS oldest_due,
       min(lease_expires_at) FILTER (WHERE status = 'RUNNING') AS oldest_lease
FROM workflow_jobs
GROUP BY status
ORDER BY status;

SELECT id, job_type, status, priority, attempt_count, max_attempts,
       lease_owner, fence_token, lease_expires_at, available_at, last_error
FROM workflow_jobs
WHERE (status IN ('PENDING','RETRY') AND available_at <= clock_timestamp())
   OR (status = 'RUNNING' AND lease_expires_at <= clock_timestamp())
   OR status = 'DEAD'
ORDER BY priority DESC, available_at, id;

SELECT id, workflow_key, timer_key, timer_type, due_at, generation
FROM workflow_timers
WHERE status = 'SCHEDULED' AND due_at <= clock_timestamp()
ORDER BY due_at, id;
```

- Check database availability, locks, connection saturation, replica/primary role, clock, disk, CPU, I/O, and migration compatibility.
- Check each reactor instance's unique lease owner, poll loop, panic/restart history, and lease duration versus poll interval. A configured lease must exceed the poll interval and cannot exceed 24 hours; claims and renewals reject a zero or over-limit duration independently of startup validation.
- Separate capacity backlog from one poison job, a provider outage, schema error, and a globally open breaker.
- Inspect outbox/effect backlogs and accountability anchors, not just workflow jobs.
- For a dead job without a work-item binding, inspect its `dead_letter_operational_incident_id`. Open or acknowledged incidents must appear in attention; a valid resolved/cancelled incident remains its historical ownership record but is no longer active attention.

## Recover

1. Restore database health or roll back the incompatible application release without reversing forward migrations.
2. Restart/scale qualified reactor processes gradually. Expired jobs are reclaimed through normal claim logic with a higher fence token.
3. Let supported retry/dead-letter handling process failures. A work-bound `DEAD` job must produce or adopt the active owned escalation for its exact attempt; multiple exhausted jobs may share that owner, but each must have its own job-ID/type/error evidence and immutable audit/outbox fact. Preserve the earliest deadline and original owner/path/prerequisites. A fully unbound tenant job must retain its owned operational incident. Do not fabricate a work-item UUID for the latter.
4. Fire overdue timers through the normal timer scanner; de-duplicate by timer identity/generation.
5. Run global reconciliation and compare each accepted item to its live anchor before exiting maintenance mode.

Operational incidents advance only `OPEN -> ACKNOWLEDGED -> RESOLVED|CANCELLED` with the expected aggregate version. Use the supported controller method: each transition atomically creates an immutable semantic receipt, hash-linked audit fact, and outbox event. Exact replay returns the original receipt even after a later transition; contradictory replay conflicts. No V1 HTTP transition route exists yet, so do not use direct SQL as a substitute.

## Verify and close

- Oldest due job/timer and reconciliation lag are within targets for a full observation window.
- No expired `RUNNING` lease remains and fence-token conflicts are expected/handled.
- No accepted work item lacks a valid live accountability anchor.
- No duplicate remote effects appeared during replay.
- Every incident transition has exactly one matching immutable receipt, audit event, and outbox event; closed incidents no longer appear in active attention but still cover their historical dead job.

Attach backlog time series, slow/blocked query evidence, reactor release/owner IDs, stale/new fence tokens, dead-job dispositions, and post-recovery invariant scan.
