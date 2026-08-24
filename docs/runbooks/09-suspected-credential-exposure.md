# Suspected credential exposure

**Severity:** critical. **Primary owner:** security incident commander. **Escalation category:** `SECURITY_INCIDENT`.

## Trigger and impact

Trigger when a provider/GitHub/Linear/API/database/object-store/signing credential or ctxlane execution handle may appear in a sandbox, repository, patch, log, evidence bundle, support bundle, artifact, image, or external service. Treat suspicion as exposure until disproved.

## Contain

1. Enable tenant maintenance mode and open scoped breakers. Prevent new dispatch and artifact sharing while keeping reconciliation/evidence access available to incident responders.
2. Revoke/disable the exposed credential at its authoritative issuer immediately. Prefer revocation before forensic collection when continued use is possible.
3. Quarantine affected workers/runs and request trusted cancellation. Isolate network access without destroying volatile evidence needed by policy.
4. Restrict affected artifacts and logs; do not paste the secret into tickets, chat, commands, or the incident timeline.
5. If signing keys are involved, follow the signing-key runbook. If the sandbox crossed a boundary, follow the sandbox-escape runbook too.

## Diagnose

- Identify credential class, issuer, principal, scopes, environment, issue/expiry/revocation times, and first/last possible exposure.
- Search by non-secret fingerprint/key ID and secret-scanner findings across sandbox outputs, Git history, images, object versions, logs, evidence, and support exports.
- Review provider audit logs for use by source IP, user agent, action, repository, and time.
- Trace how trusted controller data crossed into untrusted content. ASF's evidence validator intentionally rejects credential-shaped fields, but that is defense in depth, not proof of absence.
- Determine all derived credentials/sessions and systems reachable with the exposed authority.

## Recover

1. Rotate the credential and all dependent/derived sessions using the issuer's documented procedure. Validate the replacement under least privilege.
2. Remove public exposure while retaining a protected forensic copy and audit trail. History rewriting or object deletion requires security/legal approval.
3. Reconcile every potentially authorized GitHub, Linear, provider, object, policy, and database effect during the exposure window.
4. Rebuild compromised workers/images from a known-good source and increment/fence worker generation.
5. Fix the data path, add a regression/security test, and scan the replacement outputs before restoring readiness.

## Verify and close

- Old credentials and sessions are rejected; replacements work only in the trusted component.
- No credential or handle reaches a coding-agent environment or portable evidence in a canary.
- Provider audit reconciliation accounts for every action in scope.
- Incident scope, rotations, worker generations, artifact treatment, and residual risk have security approval.

Store only fingerprints, key IDs, provider audit references, timestamps, affected scopes, rotation confirmations, and redacted scanner output in the incident record.
