# Database restore and workflow reconciliation

**Severity:** critical. **Primary owner:** database/platform incident commander. **Escalation category:** `BLOCKED_EXTERNAL` or `SECURITY_INCIDENT` when integrity is suspect.

A restore is a destructive control-plane event. Restore into a new isolated database first; do not overwrite the only copy or reconnect workers/providers before reconciliation.

## Declare and contain

1. Enable maintenance mode at ingress/scheduler boundaries and stop all ASF processes that can mutate the damaged database.
2. Keep Runmill workers isolated from new submissions. Record that existing Runmill runs may continue durably and remote effects may occur.
3. Freeze database retention/WAL and object-store versions; preserve the failed system read-only when possible.
4. Name the target recovery point and expected data-loss window. Open owned escalations for accepted work in that window.
5. Capture deployed ASF/Runmill/ctxlane versions, schema state, worker generations, last provider cursors, and backup identifiers.

## Restore in isolation

1. Provision a new database and restore the selected base backup plus logs/PITR to the approved timestamp using the database platform's tested procedure.
2. Restore or mount object-store versions into an isolated recovery namespace. Do not overwrite newer objects.
3. Connect only a migration/verification identity. Confirm server version, timezone, extensions, schema compatibility, and migration history.
4. Run read-only integrity/invariant checks before starting ASF.

```sql
SELECT state, count(*) FROM work_items GROUP BY state ORDER BY state;
SELECT status, count(*) FROM workflow_jobs GROUP BY status ORDER BY status;
SELECT status, count(*) FROM outbox GROUP BY status ORDER BY status;
SELECT status, count(*) FROM effect_intents GROUP BY status ORDER BY status;

SELECT w.id, w.state
FROM work_items AS w
LEFT JOIN accountability_anchors AS a
  ON a.tenant_id = w.tenant_id AND a.work_item_id = w.id
WHERE w.accepted_at IS NOT NULL
  AND w.state NOT IN ('CLOSED','CANCELLED')
  AND a.work_item_id IS NULL;

SELECT attempt_id, count(*)
FROM runs
WHERE authoritative
GROUP BY attempt_id
HAVING count(*) > 1;
```

5. Sample immutable Work Order/evidence/audit bytes and recompute digests/signatures. Verify referenced objects exist and match their digests.

## Reconcile before cutover

1. Start one ASF instance in maintenance mode with dispatch disabled. Let migration/schema checks run only if the release is compatible with the recovery point.
2. Fence returning worker generations through the supported registration/reconciliation flow; do not accept stale events blindly.
3. For every non-terminal attempt, query Runmill by Work Order/idempotency key, restore the authoritative run mapping, and resume after the stored cursor.
4. Reconcile GitHub effects by branch/PR/candidate/correlation marker and Linear by external ID/revision. Never replay an ambiguous write as new.
5. Reconcile evidence objects, WIP/worker reservations, budget consumption, circuit breakers, approvals/deadlines, outbox/effect leases, timers, and accountability anchors.
6. Data lost after the recovery point is reconstructed only from authenticated external truth and signed evidence/events. Record supplemental audit facts; never fabricate old rows/signatures.
7. Any unresolved item remains quarantined or escalated with owner, action, deadline, retry policy, and active-effect status.

## Cut over and verify

1. Take a final backup of the recovered database and record its identity.
2. Atomically switch ASF to the recovered database while still in maintenance mode.
3. Verify `/healthz`, `/readyz`, job/timer polling, reconciliation lag, and accepted-work accountability count.
4. Permit one bounded canary reconciliation/dispatch only after Runmill/ctxlane/provider readiness is proven.
5. Exit maintenance mode gradually and monitor duplicate effects, stale fences, evidence failures, breaker changes, and backlog age.

## Close

Confirm the achieved RPO/RTO, exact lost/reconstructed interval, zero unexplained accepted items, zero duplicate authoritative runs/effects, object/digest coverage, and an independently restorable new backup. Attach recovery-point IDs, commands/logs in protected storage, integrity queries, external reconciliation results, cutover approval, and follow-up actions.
