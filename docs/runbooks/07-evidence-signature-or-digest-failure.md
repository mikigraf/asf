# Evidence signature or digest failure

**Severity:** critical until integrity failure is explained. **Primary owner:** security and platform on-call. **Escalation category:** `VERIFICATION_FAILED`, `QUARANTINED`, or `SECURITY_INCIDENT`.

## Trigger and impact

Trigger when canonical payload digest, envelope signature, Work Order binding, repository/base/candidate identity, worker ID/generation, target evidence, or referenced object digest fails verification. Invalid or inconclusive evidence cannot close work.

## Contain

1. Quarantine the evidence, run, and affected worker generation. Open a worker/key scoped breaker; use maintenance mode if scope is unknown.
2. Block source closure, merge, deployment, and deletion/retention expiry for affected records/objects.
3. Preserve exact signed bytes and content-addressed objects read-only. Do not "repair" or re-sign an existing bundle.
4. Do not trust worker self-report or cached CI results as a substitute.
5. Assign a security owner and record whether any delivery effect remains active.

## Diagnose

```sql
SELECT e.id, e.work_item_id, e.attempt_id, e.run_id, e.worker_id,
       e.worker_generation, e.key_id, e.payload_digest, e.work_order_digest,
       e.base_sha, e.candidate_sha, e.requested_target, e.target_satisfied,
       v.status AS verification_status, v.expectation_digest, v.verified_at
FROM evidence_bundles AS e
LEFT JOIN evidence_verifications AS v
  ON v.tenant_id = e.tenant_id AND v.evidence_id = e.id
WHERE e.id = :'evidence_id';
```

- Recompute canonical JSON and digest from the exact stored payload bytes using the supported schema version.
- Verify the envelope using the registered worker key for the evidenced generation and production algorithm.
- Compare Work Order, attempt, run, worker, base SHA, candidate SHA, requested target, and expectation digest end-to-end.
- Fetch every object by digest and recompute its bytes; compare object-store metadata/version and access logs.
- Determine whether the cause is corruption, unsupported canonicalization/version, stale key/generation, wrong binding, truncated transfer, or tampering.

## Recover

1. If transport/storage corruption is proven and the authoritative worker retains the exact original signed bytes, re-ingest those bytes as a supplemental attempt to store the same digest; never manufacture a new signature.
2. If verifier compatibility is the issue, deploy a tested compatible verifier and append a new verification record. Preserve the failed/inconclusive result.
3. If the worker produced invalid evidence, keep it quarantined and require a new policy-approved attempt after incident resolution.
4. For possible key compromise/tampering, follow the signing-key or sandbox runbook and independently inspect GitHub candidate/effects.
5. Resume closure only when an independent valid verification matches the current exact target.

## Verify and close

- Exact signed envelope, recomputed digest, trusted key/generation, and all entity bindings validate.
- Referenced artifacts are present, authorized, and digest-correct.
- Current GitHub/CI/target state matches the candidate, with no unresolved quarantine or cancellation.
- Scope analysis shows whether other bundles from the signer/generation are affected.

Attach hashes, schemas, verifier/release versions, key ID/generation, object versions, target reconciliation, and the incident decision. Never attach private keys, tokens, or unredacted protected transcripts.
