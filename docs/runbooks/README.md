# Required operations runbooks

These are the 12 runbooks required for ASF V1. Configure an on-call owner, alert, communication channel, and exercise cadence for each before a production pilot.

> [!IMPORTANT]
> These runbooks describe the controls a production ASF must provide. `asf-server all` runs the durable reactor, but the current Rust surface does not yet provide Runmill lost-submit lookup, exact ctxlane readiness, complete Work Order authority, production dispatch/run observation/evidence ingestion/artifact retrieval/outcome acknowledgement, or the external Linux qualification matrix. It also does not expose every scoped breaker, quarantine, approval, or provider-reconciliation action. This build is not suitable for a production pilot: use external containment in a test environment, preserve the ledger, and escalate a missing control; never substitute direct SQL.

1. [Worker offline during an active run](01-worker-offline-during-active-run.md)
2. [ctxlane identity unavailable or principal mismatch](02-ctxlane-identity-unavailable.md)
3. [Provider outage or rate limit](03-provider-outage-or-rate-limit.md)
4. [GitHub outage or ambiguous mutation](04-github-outage-or-ambiguous-mutation.md)
5. [Linear outage or source-update failure](05-linear-outage-or-source-update-failure.md)
6. [Workflow backlog or stuck timer](06-workflow-backlog-or-stuck-timer.md)
7. [Evidence signature or digest failure](07-evidence-signature-or-digest-failure.md)
8. [Budget runaway or breaker open](08-budget-runaway-or-breaker-open.md)
9. [Suspected credential exposure](09-suspected-credential-exposure.md)
10. [Sandbox escape or policy violation](10-sandbox-escape-or-policy-violation.md)
11. [Signing-key compromise or rotation](11-signing-key-compromise-or-rotation.md)
12. [Database restore and workflow reconciliation](12-database-restore-and-reconciliation.md)

## Common incident rules

- Name an incident commander and record times in UTC.
- Preserve the accepted-work accountability invariant throughout containment.
- Prefer scoped breakers. Use maintenance mode if scope or effect ambiguity is broad.
- Maintenance mode is passed to activities and its dispatch guard blocks creation of a new attempt or Runmill submission. Intake, configured cancellation/worker reconciliation, configured evidence verification/source closure, and reservation-expiry sweeps continue. No production dispatch or run-observation handler is installed, and approval, signed-evidence ingestion, artifact-byte retrieval, and Runmill outcome acknowledgement remain unavailable, so this control alone does not qualify the target recovery behavior.
- Do not manually mutate ledger state. Read-only SQL is diagnostic; recovery uses authenticated API/controller/reconciler paths so versions, fencing, idempotency, and audit remain intact.
- Operational-incident transitions currently use the Rust ledger/controller contract, not a V1 HTTP route. Exact retries adopt their immutable receipt; direct SQL would bypass the supported request semantics and is prohibited.
- Do not create a new attempt while an existing remote run/effect may exist.
- Treat the dispatch-fact guard as monotonic evidence. A missing attempt or run row is not a safe pre-dispatch proof; only the synchronous API path may lock the false guard and commit the exact `PRE_DISPATCH` receipt.
- Treat `work_cancellation_authority_guards` as the live-child serialization boundary. Every new or reactivated authority route must advance its open generation; a `CANCELLED` receipt owns and permanently freezes the exact terminal generation, so later authority activation or work-item reopening must fail. Do not substitute a deferred check or advisory lock for that durable fact.
- Preserve every Runmill cancellation `INITIAL`/`OBSERVER` receipt and its prior link. The same-workflow monotonic chain may have arbitrary depth. Nonterminal observation is not cancellation completion and must not release attempt reservations. Its deterministic observer may be claimed, retried, exhausted, or dead-lettered normally, but must not be set to `CANCELLED` before a terminal receipt covers an exact same-chain `OBSERVER`, job claim, aggregate/run projection, audit/outbox/anchor facts, and terminal-only releases. Each released set must cite that receipt through `cancellation_terminal_receipt_id` in the same commit and use the exact reserved `runmill-cancellation:v1` work/attempt/set/prior-fence key.
- Confirm a cancellation outbox row was pristine and publishable at the receipt transaction's deferred commit boundary. Its later claim, retry, and publication state is operational lifecycle, not receipt tampering.
- Read a `TERMINAL_CONFLICT` receipt as the historical state certified when cancellation created or merged its escalation. It carries no cancellation-authority generation and must leave the guard unfrozen for remediation. A merge receipt must have been trigger-generated under the live terminal cancellation claim, name its job/effect/observation, and preserve exact OLD/NEW digests for the conservative evidence-preserving transform. New escalation `opened_at` and its four-hour deadline derive from database `observed_at`. Inspect the escalation row and its own lifecycle audit for current status; do not rewrite the receipt when the escalation is later acknowledged, resolved, or cancelled.
- Do not close an escalation until owner, required action, deadline, retry prerequisites, and active authority/effect status are accurate.
- Preserve signed envelopes, hashes, cursors, correlation markers, provider request IDs, logs, and release versions. Never add raw secrets to incident artifacts.
- `/healthz` currently proves PostgreSQL queryability. `/readyz` checks the active tenant plus `workflow_jobs`, `idempotency_records`, and `audit_events`, then fails with per-type, per-persisted-activity-contract-identity, or exact-worker-route counts for every unsupported live production job — serviceable means the exact job type and persisted activity contract identity match (plus exact worker id for scoped routes). All six job-producing API operations preserve exact completed replay and gate fresh queue obligations before mutation or enqueue; `ACCEPTED` work with no attempt is cancelled synchronously only when the locked monotonic guard and pristine acceptance facts support an exact `PRE_DISPATCH` receipt, while a live authoritative run requires its exact cancellation route. Verification also depends on ready source closure. Treat breaker state, dependency preflight, backlog age, reconciliation, complete schema compatibility, and external qualification as separate dispatch-readiness signals; HTTP 200 with no unsupported backlog does not authorize dispatch. This job-type/contract/worker match is process-local, not a durable global reactor capability lease, and no unserviceable-obligation scanner exists yet.

Commands use `psql` with connection details supplied through libpq environment variables or a protected service identity. Avoid connection URLs containing passwords in shell history or process arguments.
