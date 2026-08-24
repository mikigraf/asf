# Linear outage or source-update failure

**Severity:** medium; high if accepted source intent may have changed. **Primary owner:** backlog/platform on-call. **Escalation category:** `BLOCKED_EXTERNAL`.

## Trigger and impact

Trigger when Linear intake polling/webhooks fail, a snapshot cannot be confirmed current, or delivery succeeded but updating/closing the source item fails. Delivery evidence and source closure are separate: successful delivery remains valid while the work item stays `CLOSING_SOURCE`.

## Contain

1. Stop accepting affected source items when snapshot freshness cannot be proven.
2. Preserve source snapshots, revisions, content digests, outbox rows, effect intents, and delivery evidence.
3. Do not mark ASF work `CLOSED` or manually update Linear to hide a failed connector.
4. If a material source change may have occurred after acceptance, pause new dispatch/retry until a fresh snapshot and readiness/policy evaluation exist.
5. Assign an owner and source-retry deadline to every affected accepted item.

## Diagnose

```sql
SELECT id, topic, message_key, event_type, status, attempt_count,
       available_at, lease_expires_at, last_error
FROM outbox
WHERE status IN ('PENDING','PUBLISHING','RETRY','DEAD')
ORDER BY available_at;

SELECT id, source_external_id, state, current_attempt_id, updated_at
FROM work_items
WHERE source_system = 'LINEAR'
  AND state IN ('CLOSING_SOURCE','BLOCKED_EXTERNAL')
ORDER BY updated_at;
```

- Check connector identity/scope, API status, rate limits, webhook delivery cursor, polling checkpoint, and clock.
- Query Linear by stable external ID and compare revision/content digest to the latest immutable snapshot.
- Distinguish read failure, write failure, lost response, authorization error, deletion, cancellation, and material change.

## Recover

1. Restore the deterministic connector and prove read access before enabling intake.
2. Ingest missed source updates idempotently and create new snapshots; never overwrite old snapshots.
3. For an ambiguous mutation, query the source and reconcile the existing correlation marker before retrying the same outbox/effect entry.
4. If intent changed materially, repeat readiness/policy and cancel or supersede authority as required. Do not mutate an in-flight Work Order.
5. After delivery evidence is still current, retry the source update and close only after observed confirmation.

## Verify and close

- Poll and webhook cursors have caught up without duplicate snapshots/events.
- Every `CLOSING_SOURCE` item either closes from observed source state or retains a retry/escalation.
- The source link contains the correct target/evidence reference and no secret/protected artifact.
- New acceptance uses current source snapshots.

Attach source revisions/digests, connector identity, provider request/correlation IDs, affected items, delivery evidence IDs, and final observed source state.
