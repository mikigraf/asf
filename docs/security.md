# Security and trust boundaries

## Trust classification

Trusted controller components are the ASF policy/workflow process, PostgreSQL/object access layer, Work Order signer, deterministic provider adapters, Runmill controller, and ctxlane broker/provider harness. They still require least privilege, runtime identity, network policy, audit, and independent monitoring.

Potentially hostile data and execution include issue text, comments, attachments, repository files, build scripts, tests, generated patches, model output, tool calls, logs, diffs, and transcripts. Treating a repository as "ours" does not make its build process trusted.

The most important boundary is:

```text
trusted control plane -- signed, narrowed Work Order --> untrusted run sandbox
trusted identity broker -- credential-free lease use --> provider harness
```

No data flowing back from the sandbox creates authority.

## Mandatory controls

1. Source/repository content cannot set identities, credentials, tool allowlists, egress, merge authority, approvals, risk, or deployment scope.
2. Work Orders and approvals are canonical, signed, versioned, expiring, replay-resistant, and bound to exact digests and effects.
3. ASF signing material, API tokens, database credentials, GitHub/Linear credentials, provider credentials, and ctxlane execution handles never enter a repository sandbox or portable evidence.
4. Privileged Runmill and ctxlane tools are callable only by trusted controllers. Runmill's private Unix control socket and any local ctxlane endpoint must not be network-exposed.
5. Worker identity is bound to a registered public key and generation. Stale generations cannot update runs or sign acceptable evidence, and a raw run event must name the exact worker session, worker, and generation already bound to that run.
6. API roles remain distinct: platform admin, policy admin, repository owner, approver, operator, auditor, viewer, and intake submitter. Intake submitter is a least-privileged role scoped to `SubmitIntake` only, for connector or automation principals that submit candidate work via `POST /v1/intake` and must not accept, cancel, approve, or otherwise mutate work.
7. Policy changes, approvals, cancellations, operational-incident lifecycle transitions, reconciliation overrides, evidence acknowledgements, source mutations, and security decisions are audited. Incident creation is reciprocally bound to its exact unbound `DEAD` job. Each lifecycle transition also requires a matching immutable receipt whose complete audit/outbox semantics and canonical before/after state digests are verified in the same transaction. Pre-dispatch cancellation requires a monotonic negative-dispatch proof and an exact terminal receipt; Runmill cancellation requires an immutable observation chain plus an exact terminal receipt binding the claimed job, run projection, audit/outbox facts, accountability anchor, and terminal-only reservation releases. Each such release names that receipt through a deferred same-commit foreign key and a reserved exact set/fence key. A `CANCELLED` receipt also freezes the exact generation of a durable per-work cancellation-authority guard. A valid evidence decision is bound to the exact completed verification claim, frozen artifact manifest, strict receipt contents, and database-anchored observation/verification chronology.
8. Raw artifacts and support bundles are redacted and access-controlled. Transcripts use an explicit protected retention class.
9. Production secrets come from a secret manager or workload identity. `.env` and Compose environment values are local-development conveniences only.
10. Hosted multi-tenancy is prohibited until isolation and deletion controls receive external review.

The V1 deployment boundary is enforced independently of API scoping: migration installs one singleton PostgreSQL guard, provisioning binds it to `ASF_TENANT_ID`, and the database then rejects foreign tenant identity writes or guard erasure. This is a single-tenant safety control, not evidence that hosted multi-tenancy is supported.

## Fail-closed dependency policy

The repository implements a wire-exact private Unix-socket Runmill client and source-tested Work Order/evidence contracts. Complete optional groups can wire cancellation, health reconciliation, and a bounded read-only V2 observation stream for one configured worker, GitHub-backed evidence verification, and Linear intake/source closure. Once an authoritative run already has an explicitly installed stream, the producer creates one exact checkpoint/job at a time from that stream's durable cursor. The run-admission worker session remains immutable provenance; every scheduled checkpoint selects and records the then-live observer session, so ordinary session rotation is fenced rather than treated as a different run. The observer retains one exact `get-run` response and one bounded `list-run-events` page for that cursor. A normal page writes immutable snapshots/result and releases the job while advancing the cursor; a terminal final page leaves the stream `TERMINAL_READY`. A valid compacted page is also retained, but does not advance the cursor: it force-dead-letters the exact job through the owned `WORKFLOW_JOB_EXHAUSTED` escalation/audit/outbox/accountability path and releases the stream as `ESCALATED` with that actual escalation ID. Neither path changes `runs` or `raw_run_events`.

This is still observation provenance, not a Runmill state projection or evidence decision. There is no supported stream-adoption/install workflow for historical or newly adopted runs and no reducer/evidence handoff from retained observations. An ordinary exhausted observer job is recovered only through the append-only `runmill_observation_terminal_failure_facts` binding, whose insert trigger re-proves the exact active stream, checkpoint, dead V2 job payload/cursor/epoch, effective owned `WORKFLOW_JOB_EXHAUSTED` escalation, and the digest carried by the job's own durable dead-letter receipt. It cannot be forged or mutated, it never invents a `GET_RUN`/`LIST_RUN_EVENTS` snapshot or observation result, and it releases the stream only into `ESCALATED` at the unchanged cursor. The daemon also does not wire Work Order signing/submission and dispatch, signed approval application, signed-evidence ingestion, artifact-byte retrieval, or Runmill outcome acknowledgement. Runmill also lacks the lost-submit lookup needed to discover a run by Work Order idempotency key or payload digest, and strict Work Order V1 omits required authority fields. Worker health reconciliation consumes a strictly validated aggregate Runmill report and pre-existing ASF capability/session facts; it is not a cryptographic worker registration handshake or attempt-specific ctxlane preflight. ASF also lacks ctxlane profile/principal/environment lease proof, production S3, OTLP export, and the required external Linux failure matrix. These gaps must not be represented as dispatch-ready or production-qualified. The HTTP `/readyz` endpoint checks the active tenant, its exact activated V1 database guard, and three core tables, then fails with per-type, per-persisted-activity-contract-identity, or exact-worker-route counts for every live production job this process cannot service by its exact job type, persisted activity contract identity, and (for scoped routes) exact worker id, including the bounded observer route; it remains healthy when that backlog is empty. Intake sync, work acceptance, cancellation, approval decision, worker reconciliation, and evidence verification return an exact completed idempotency replay before checking current capability, and gate any new queue obligation on its exact unscoped handler or worker route. `ACCEPTED` work with no attempt can instead be cancelled synchronously only after its locked monotonic guard proves that no dispatch fact has ever appeared; the same transaction writes an exact `PRE_DISPATCH` receipt and needs no worker handler. A live authoritative Runmill run restores the exact-worker cancellation requirement. The verifier is installed only with a ready `CLOSE_SOURCE` handler. These are safety checks, not an aggregate dependency or complete-schema probe. This job-type/activity-contract/worker binding is process-local, not a durable global reactor capability lease, and no unserviceable-obligation scanner exists yet, so none of this is a production-readiness claim.

- No safe Runmill submission-recovery path: do not create or mark a dispatch successful. A successful submission whose response is lost cannot be discovered by idempotency key after its signed envelope expires. The database already requires one immutable Work-Order-bound submission intent and an exact live dispatch-job fence, but those controls cannot resolve remote ambiguity by themselves.
- Unsafe Runmill registry/socket/protocol or malformed health facts: quarantine the configured worker and revoke its active sessions. Transient transport loss makes it offline. A later healthy probe must not automatically unquarantine it, and no health result grants attempt-specific dispatch authority.
- No ctxlane identity/principal proof: dispatch readiness fails and no Work Order is admitted to a worker.
- Evidence signer unknown, stale, or invalid: quarantine the evidence/run and open an owned escalation.
- GitHub/Linear response ambiguous: preserve the same effect intent and reconcile; do not issue a fresh effect. Optional daemon configuration wires the read-only GitHub observer into `VERIFY_EVIDENCE` and the authenticated Linear adapter into `CLOSE_SOURCE`; rate-limit and abuse/secondary-limit GitHub responses are retryable unavailability rather than authorization refusal, and no mutating GitHub capability is exposed.
- Runmill cancellation response ambiguous: retain the same immutable request/effect identity, payload, and digest; observe the exact run and adopt that request only after its recorded workflow-job UUID, owner, and fence no longer identify a live `RUNNING` cancellation claim. Never infer ownership from owner/fence alone or manufacture a replacement cancellation.
- Runmill cancellation observation nonterminal: preserve the append-only `INITIAL` receipt and extend the same workflow to arbitrary depth with one claim-bound monotonic `OBSERVER` at a time. The deterministic observer may be claimed, retried, exhausted, or dead-lettered normally, but it cannot be silently changed to `CANCELLED` before an exact same-chain terminal receipt. Do not release attempt reservations or manufacture terminal completion before that proof. A terminal release is valid only when `reservation_sets.cancellation_terminal_receipt_id` resolves in the same commit and its transition key exactly matches the reserved `runmill-cancellation:v1:{work}:{attempt}:{set}:fence:{prior}` namespace.
- Runmill already terminal during cancellation: retain active-effect accountability and create or conservatively merge an owned `REMOTE_EFFECT_AMBIGUOUS` escalation; do not silently treat the cancellation request as successful. A merge receipt may be trigger-generated only while the exact terminal cancellation claim is live, must bind its job/effect/observation provenance, and must certify the evidence-preserving OLD-to-NEW transform. The resulting `TERMINAL_CONFLICT` receipt is an immutable snapshot of that transition, carries no cancellation-authority generation, and leaves the guard unfrozen. Later legal escalation lifecycle changes do not rewrite it and must use their own fenced/audited path.
- Terminal-cancellation authority race: never treat a deferred check or advisory lock as proof that no concurrent child exists. New or reactivated live authority immediately advances `work_cancellation_authority_guards`; an exact `CANCELLED` receipt advances it to a receipt-bound generation and freezes it. The validator must find no remaining live authority, and every later authority activation or work-item reopen must fail at that durable row boundary.
- Cancellation outbox delivery: the terminal receipt requires a pristine, unclaimed, publishable event at its deferred commit boundary. Do not interpret that historical proof as a lock on later publisher state; ordinary fenced claim, retry, and publication must remain possible.
- Pre-dispatch cancellation uncertainty: a missing attempt row is not evidence of no dispatch. Require the locked, false monotonic dispatch guard plus the exact pristine acceptance proof; fail on lock contention or any guard generation that records a dispatch fact.
- Reservation expiry: never accept caller-controlled `asf-internal:` idempotency keys. PostgreSQL permits internal expiry and budget-release keys only when they match the exact set transition, fence, actor, reason, timestamp, reservation, and dimension; deferred guards reject missing accounting rows and advance a guarded parent accounting version so a terminal transition cannot pass against a different snapshot at any supported PostgreSQL isolation level.
- S3 adapter unavailable: production qualification fails. The local filesystem store is a development-only verifier reader; it does not supply production ingestion or artifact-byte retrieval.
- OTel exporter unavailable: this is an observability readiness defect; it does not justify discarding ledger/audit events.

Never turn one of these cases into a successful dispatch decision to keep the queue moving, regardless of the HTTP health/readiness response.

## Secrets and keys

- Use separate keys/tokens per environment and component. Do not share the Work Order signing key with worker evidence signers.
- Prefer HSM/KMS-backed signing for production. The environment-provided Ed25519 seed is a bootstrap mechanism, not the desired production key architecture.
- Grant ASF adapters only the provider permissions needed for deterministic effects. Workers and coding agents get no controller token.
- Restrict the Runmill registry directory to mode `0700` and its registry/socket to mode `0600`, with no symlinks and the same effective UID as ASF. The client revalidates owner, mode, path placement, protocol version, and socket identity on every call.
- Rotate API and provider credentials without logging old/new values.
- Record key IDs and public keys in durable metadata; retain old verification keys for the evidence retention period unless compromise analysis forbids trust.
- Backups must be encrypted and access-logged. A database backup plus object-store snapshot is sensitive even if credential fields are prohibited.

Follow the [signing-key](runbooks/11-signing-key-compromise-or-rotation.md) and [credential exposure](runbooks/09-suspected-credential-exposure.md) runbooks for rotation or compromise.

## Network layout

Production should separate ingress, control, data, worker-control, and untrusted-run networks. PostgreSQL, object storage, signer, Runmill's Unix control socket, and ctxlane control endpoints are not public. Outbound provider access uses explicit destinations and deterministic controllers. Untrusted runs use their own egress policy and cannot route to control-plane networks or cloud metadata.

Compose binds ports to loopback for convenience; it is not a production network policy, TLS boundary, or secret-management system.

## Verification before a pilot

- Attempt Work Order replay/tampering and unsupported schema versions.
- Inject cross-repository, cross-attempt, and stale-generation events.
- Put credential-shaped fields in evidence and support artifacts.
- Try to reach privileged MCP, PostgreSQL, object storage, signer, and metadata services from a run sandbox.
- Exercise RBAC bypass and approval self-grant attempts.
- Lose GitHub responses after branch/PR creation and prove no duplicate effect.
- Restore database/object evidence into an isolated environment and independently verify hashes/signatures.

The deterministic Rust/PostgreSQL failure matrix covers replay, out-of-order events, identity collisions, cross-attempt isolation, stale worker generations, and signed-evidence tamper/staleness. It does not replace the required Linux cross-product exercise with real Runmill crashes, ctxlane restarts/leases, provider response loss, sandbox credential isolation, and dedicated workload identities.

Any unexplained authority expansion, invalid evidence acceptance, credential observation, or sandbox-to-control reachability blocks production promotion.
