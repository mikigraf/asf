# GitHub outage or ambiguous mutation

**Severity:** high for ambiguous writes. **Primary owner:** delivery/platform on-call. **Escalation category:** `BLOCKED_EXTERNAL` or `REMOTE_EFFECT_AMBIGUOUS`.

## Trigger and impact

Trigger on sustained GitHub API/webhook failure or when ASF/Runmill cannot tell whether a branch, pull request, check, comment, merge, or other mutation occurred after request transmission. Repeating a write with a new key can create duplicate delivery.

## Contain

1. Open a GitHub/repository-scoped breaker. Pause new delivery effects; broader implementation may continue only if policy and later reconciliation remain safe.
2. Preserve the existing `effect_intents` row, idempotency key, correlation marker, request digest, Work Order, and candidate SHA.
3. Mark an uncertain effect `AMBIGUOUS` through the controller and open an owned escalation. Do not mark it failed merely because the response was lost.
4. Never create another branch/PR/merge request until remote state is queried.
5. Keep verified delivery evidence; a source outage does not invalidate already verified code, but closure remains pending.

## Diagnose

```sql
SELECT id, work_item_id, attempt_id, effect_type, status, idempotency_key,
       correlation_marker, request_digest, attempt_count, next_attempt_at, last_error
FROM effect_intents
WHERE provider = 'github'
  AND status IN ('PENDING','IN_FLIGHT','AMBIGUOUS','FAILED')
ORDER BY updated_at;
```

- Query GitHub read APIs by deterministic branch name, commit SHA, PR head/base, correlation marker, and provider request ID.
- For PR closure, verify repository, base SHA/ref, exact candidate head, required checks, review, and current branch protection.
- Compare webhook delivery IDs and stored run/outbox cursors; de-duplicate before applying.
- Determine whether GitHub is unavailable globally, credentials lack scope, rate limits are exhausted, abuse/secondary-rate limiting is active, or only one repository is affected. The current read-only adapter maps HTTP 429 and rate-limit/abuse-signalling 403 responses to retryable transport unavailability; an ordinary 403 remains a provider rejection. Complete GitHub configuration wires that observer into the durable `VERIFY_EVIDENCE` retry loop only when the Linear source-closure handler is also ready. ASF still has no general GitHub mutation activity or run-driven evidence-ingestion path, so use this distinction only for verification reads and reconcile delivery writes in the system that issued them.

## Recover

1. If the intended effect exists and matches the request digest/candidate, record it as observed and resume from that result.
2. If GitHub proves the effect does not exist, retry the same intent with the same idempotency/correlation identity.
3. If state conflicts or cannot be proven, retain the ambiguous escalation for a repository owner; do not automate merge/closure.
4. Re-fetch required CI/protection state at the exact candidate SHA before accepting delivery evidence.
5. Replay stored webhooks/outbox work idempotently and watch for duplicates.

## Verify and close

- One intended branch/PR/effect exists and it points to the evidenced candidate.
- No duplicate comment/check/PR/merge/source effect was created.
- GitHub, Runmill evidence, and ASF ledger agree.
- Required CI/protection observations are current, not cached from a stale SHA.

Attach effect intent/correlation IDs, GitHub request IDs, branch/PR/commit evidence, outage interval, reconciliation decision, and approver identity for any ambiguity override.
