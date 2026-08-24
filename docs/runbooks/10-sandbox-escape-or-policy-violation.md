# Sandbox escape or policy violation

**Severity:** critical. **Primary owner:** security incident commander with worker/platform on-call. **Escalation category:** `QUARANTINED` and `SECURITY_INCIDENT`.

## Trigger and impact

Trigger on access outside allowed paths, forbidden commands/tools, unexpected egress, control-plane reachability, cross-run/repository access, host escape indicators, policy digest mismatch, or any attempt to call privileged Runmill/ctxlane MCP from a coding worker.

## Contain

1. Enable tenant maintenance mode. Quarantine the worker generation, active runs, produced evidence, and affected repositories.
2. Isolate the worker host from control/data/provider networks while preserving the trusted channel needed for a safe cancellation if incident command approves.
3. Revoke worker/provider leases and credentials at their owning controllers. Fence the worker generation so stale events/evidence cannot update ASF.
4. Do not execute repository cleanup scripts or trust evidence produced after the first compromise indicator.
5. Preserve host, runtime, network, policy, Work Order, event, and object evidence under protected access.

## Diagnose

- Establish the exact Work Order/policy/harness digests, allowed paths/tools/network, run/worker generation, candidate, and first violation time.
- Compare deterministic policy decisions to actual sandbox telemetry and tool/effect requests.
- Inspect host/runtime, namespaces/VM boundary, mounts, daemon sockets, metadata reachability, egress, kernel/runtime alerts, and cross-run storage.
- Reconcile all GitHub/Linear/provider actions and ctxlane lease use from the affected worker/time window.
- Scope other workers sharing the same image, host, runtime, base snapshot, policy, or vulnerability.

```sql
SELECT r.id, r.work_item_id, r.attempt_id, r.worker_id, r.worker_generation,
       r.external_run_id, r.state, r.last_event_cursor, r.last_observed_at
FROM runs AS r
WHERE r.worker_id = :'worker_id'
  AND r.worker_generation = :'worker_generation'
ORDER BY r.adopted_at;
```

## Recover

1. Patch the isolation/policy failure and qualify it with a minimal exploit regression plus the full sandbox boundary suite.
2. Rebuild the host and worker image from known-good, signed inputs; rotate reachable secrets and increment worker generation.
3. Independently verify or discard/quarantine affected candidate/evidence. A clean new attempt requires fresh readiness, policy, base SHA, approvals, identities, and Work Order.
4. Reconcile all remote effects before allowing a replacement attempt.
5. Restore one canary repository/work class only after security approval; keep broader breakers open through observation.

## Verify and close

- The exploit fails and privileged endpoints/metadata/control networks are unreachable from the sandbox.
- Cross-repository/run isolation and credential absence tests pass.
- Returning worker key/generation and image provenance are expected.
- Remote-effect and credential-use reconciliation has no unexplained actions.

Attach protected forensic references, policy/Work Order/image digests, worker generation, affected runs/effects, remediation tests, rebuild attestation, and security approval.
