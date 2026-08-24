# Signing-key compromise or rotation

**Severity:** planned change for routine rotation; critical for suspected compromise. **Primary owner:** security/key-management owner. **Escalation category:** `SECURITY_INCIDENT` for compromise.

ASF Work Order signing keys and Runmill worker evidence keys are separate trust domains. State which key class is in scope before acting.

## Contain a compromise

1. Enable maintenance mode and prevent admission of newly signed Work Orders in the affected key scope.
2. Disable the compromised signing operation at KMS/HSM/secret manager and update trusted verifiers according to incident policy.
3. Quarantine unstarted or newly adopted orders signed during the exposure window. Request cancellation for active runs; do not rewrite their orders.
4. For a worker evidence key, quarantine that worker generation and all not-yet-closed evidence in scope.
5. Preserve public key, key ID, signatures, exact envelopes, issue/adoption times, and key audit logs. Never copy private key material.

## Diagnose

- Identify key ID, algorithm, owner, environment, permitted operation, activation/retirement times, and earliest possible compromise.
- Enumerate Work Orders/evidence by key ID and time; compare issue, admission, run, and effect times.
- Review signer/KMS audit logs, workload identity, access policy, source IP, and release integrity.
- Determine whether private material leaked, signing was abused, trust configuration was changed, or only availability failed.

```sql
SELECT key_id, min(issued_at), max(issued_at), count(*)
FROM work_orders
GROUP BY key_id
ORDER BY key_id;

SELECT key_id, worker_id, worker_generation, min(produced_at), max(produced_at), count(*)
FROM evidence_bundles
GROUP BY key_id, worker_id, worker_generation
ORDER BY key_id, worker_id, worker_generation;
```

## Planned rotation

1. Generate the new key in the production signer; export only its public key and attested key ID.
2. Add the public key to Runmill/verifier trust with a future activation time and narrow environment/scope.
3. Deploy ASF to sign new orders with the new key. Do not re-sign stored orders.
4. Run a bounded canary through signature verification and Runmill adoption.
5. Stop new signing with the old key, but retain its public verification key for historical evidence/retention unless compromise policy revokes trust.
6. Remove admission trust for the old key after all legitimate unexpired orders are terminal/revoked.

## Recover from compromise

Create a new key under a new trusted identity, reconcile every order/evidence/effect in the exposure window, and require fresh attempts/approvals where trust cannot be independently established. Record revoked key IDs; a key-ID rename is not rotation.

## Verify and close

- New signing uses the expected protected key and verifiers accept only intended scope/time.
- Old key cannot sign/admit new authority.
- Historical verification behavior matches the documented compromise decision.
- Every in-scope run/effect/evidence item is reconciled or remains quarantined with an owner.

Attach key IDs/public fingerprints, audit-log references, trust-policy versions, affected envelope list, canary result, retirement/revocation times, and approvals.
