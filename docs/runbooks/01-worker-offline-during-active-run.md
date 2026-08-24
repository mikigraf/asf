# Worker offline during an active run

**Severity:** high; critical if external effects are ambiguous. **Primary owner:** platform on-call. **Escalation category:** `WORKER_UNAVAILABLE`, or `REMOTE_EFFECT_AMBIGUOUS` when delivery may have occurred.

## Trigger and impact

Trigger when a registered worker misses its heartbeat/readiness window while it owns an `ADOPTED`, `RUNNING`, `WAITING_APPROVAL`, `VERIFYING`, or `CANCEL_REQUESTED` run. The ASF control connection can be lost while Runmill continues durably; offline is not proof of run failure.

## Contain

1. Open or confirm a worker-scoped breaker so it receives no new reservations. If scoped control is unavailable or several workers are affected, enable maintenance mode.
2. Keep the existing attempt, Work Order, run mapping, reservations, cursor, and accountability anchor intact.
3. Do not dispatch a replacement attempt and do not release WIP/worker reservations while the run or a remote effect may still exist.
4. Assign the escalation owner, next check time, recovery action, and whether authority/effects remain active.

## Diagnose

```sql
SELECT id, name, status, generation, last_seen_at, updated_at
FROM workers
ORDER BY last_seen_at NULLS FIRST;

SELECT id, work_item_id, attempt_id, worker_id, worker_generation,
       external_run_id, state, last_event_cursor, last_observed_at
FROM runs
WHERE worker_id = :'worker_id'
  AND state IN ('ADOPTED','RUNNING','WAITING_APPROVAL','VERIFYING','CANCEL_REQUESTED')
ORDER BY last_observed_at;
```

- Confirm host, network, disk, clock, Runmill controller, local ctxlane service, and sandbox runtime health through trusted host telemetry.
- Compare the registered worker generation/public key to the returning controller.
- Determine the last stored Runmill cursor and whether a GitHub effect intent is pending, in flight, or ambiguous.
- Use `asf worker inspect <worker-id>` and `asf worker reconcile <worker-id>` when the API is available.

## Recover

1. Restore the same trusted Runmill controller and local ctxlane path. Restarting a transport is acceptable; recreating an unknown run is not.
2. Negotiate the production contract, then look up the run by Work Order/attempt/idempotency key before any submission retry.
3. Ingest events after the stored cursor, de-duplicating event IDs and enforcing monotonic versions.
4. If the same run is found, resume observation. If no run was ever adopted and Runmill can prove that fact, retry the original idempotent submission.
5. If effects cannot be proved, retain `REMOTE_EFFECT_AMBIGUOUS` for human/provider reconciliation.
6. Only after a terminal snapshot and evidence/reconciliation may ASF release reservations or create a policy-permitted replacement attempt.

## Verify and close

- Worker readiness is current and the generation/key are expected.
- Exactly one authoritative run exists for the attempt.
- The event stream is continuous from the saved cursor.
- Every affected accepted item has a live run, timer, retry, approval, owned escalation, cancellation, or verified closure.
- No duplicate branch, PR, merge, or source effect was created.

Attach heartbeat history, worker generation/key ID, Work Order digest, run/cursor timeline, effect-intent results, and reconciliation outcome. Close the breaker only after a canary reconciliation succeeds.
