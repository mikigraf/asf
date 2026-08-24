# Autonomous Software Factory

ASF is a Rust work-control plane for accountable autonomous software delivery. It owns the durable obligation from explicit acceptance through verified closure or an owned, actionable escalation. Runmill owns one repository delivery attempt; ctxlane owns the workload identities used inside that attempt.

> [!WARNING]
> This repository is an implementation foundation, not a production-ready ASF release. Exact Runmill Work Order, evidence, and private control contracts exist, and selected production handlers can be enabled, but autonomous dispatch remains fail-closed. Production readiness still requires ctxlane identity preflight, complete dispatch/reconciliation activities, and external failure qualification.

## What is here

- Typed domain models for work, attempts, approvals, authority, identity references, escalations, and accountability anchors.
- Canonical JSON, digest, Ed25519 Work Order, event, and evidence contracts.
- A forward-only PostgreSQL schema with an immutable provisioned V1 tenant guard, immutable authority/evidence and outbox facts, monotonic per-work dispatch-fact and cancellation-authority guards, exact-byte append-only Runmill read provenance, immutable cancellation-observation chains, exact cancellation and verification receipts, frozen verified-artifact manifests, append-only ledgers, exact work/attempt/run/session bindings, reciprocal dead-job/incident ownership, idempotent fully verified incident-lifecycle receipts, durable jobs/timers, fencing, and database-enforced accountability invariants.
- PostgreSQL job-claim primitives using expiring leases capped at 24 hours and monotonically increasing fence tokens.
- Deterministic readiness, policy, scheduling, workflow, and reconciliation logic.
- Versioned HTTP router and an operator CLI client.
- Authenticated Linear and read-only GitHub adapters, an exact private Unix-socket Runmill control client, and in-memory/fake ports for deterministic tests.

## Honest integration status

| Capability                       | Current status                                                                                                                                                                                                        | Required production behavior                                                                                                                                              |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL ledger and migrations | Implemented foundation                                                                                                                                                                                                | Back up, monitor, test restores, and run one migration job per rollout                                                                                                    |
| DB-backed durable reactor        | `asf-server all` runs fenced job/timer polling, reclaims leases, sweeps elapsed reservation sets, and converts exhausted bound jobs to owned escalations and fully unbound tenant jobs to owned operational incidents. Multiple exhausted jobs on one attempt conservatively share one active owner while retaining exact per-job result, audit, and outbox facts | Operate and alert on backlog, dead work, incidents, stale leases, and reconciliation lag                                                                                  |
| Runmill                          | Wire-exact Work Order, evidence, and private Unix-socket control contracts are source-tested against the adjacent Runmill checkout; an optional atomic configuration group enables fenced cancellation with an immutable `INITIAL`/`OBSERVER` observation chain, exact terminal receipt, terminal-only attempt-reservation release, strict health reconciliation, and a durable read-only cursor observer for streams explicitly inserted beneath already-authoritative runs on one pre-registered worker. The reactor produces one exact fenced job per due stream, each job retains `get-run` plus one bounded `list-run-events` page (`limit=100`), and cursor advance, immutable result, job completion, and next scheduling state commit atomically. Admission-session provenance stays immutable while a restarted controller may observe through a new live same-generation session. A compacted event gap retains both exact reads and atomically dead-letters the claim into owned escalation; terminal pages stop at a reducer-ready checkpoint. A non-gap observer that becomes owned `DEAD` work through ordinary retry exhaustion, route-invalid rejection, or expired-claim recovery is reconciled by a bounded `SKIP LOCKED` producer pass: it records one append-only terminal-failure fact binding the exact stream, active checkpoint, job, effective `WORKFLOW_JOB_EXHAUSTED` escalation, and durable failure digest, then releases the stream to `ESCALATED` at its unchanged cursor without inventing a snapshot or observation result. There is still no automatic replacement observer, cursor advance, or authoritative-run adoption workflow. No observation projects into `runs` or `raw_run_events`. | Add the production event reducer/evidence handoff, authoritative-run stream installation/adoption, signing/submission, approval, signed-evidence ingestion, artifact-byte retrieval, and outcome acknowledgement; add cryptographic worker/ctxlane admission proof and close submission response-loss recovery and authority-schema gaps before dispatch |
| ctxlane                          | Non-secret identity/profile references and admission capacity fences only                                                                                                                                             | Add profile-, principal-, environment-, and policy-bound readiness; Runmill must acquire leases and ASF must never receive provider credentials or execution handles      |
| GitHub and Linear                | Optional atomic Linear configuration enables durable snapshot intake and evidence-bound source closure with ambiguity reconciliation; complete GitHub observation additionally enables the read-only observer inside `VERIFY_EVIDENCE` only when that Linear closure handler is ready; GitHub throttling and abuse responses are retryable unavailability | Add the missing evidence-ingestion path and complete external provider ambiguity/outage qualification                                                                      |
| Artifact storage                 | With GitHub observation configured, `all` uses the local content-addressed filesystem adapter as the verifier's development-only reader; no production artifact ingestion or artifact-byte retrieval path is wired    | Add authenticated/encrypted S3-compatible storage plus production ingestion and retrieval                                                                                  |
| OpenTelemetry                    | Local collector topology only                                                                                                                                                                                         | The Rust process does not yet export OTLP; production needs an exporter and durable backend                                                                               |
| Closure targets                  | `pr` is the V1 contract                                                                                                                                                                                               | `merge`, `deploy`, and `observe` remain unsupported until their adapters/evidence contracts exist                                                                         |

The current `/healthz` handler proves that ASF can query PostgreSQL. `/readyz` first checks that the configured tenant is active, its immutable V1 database guard matches, and `workflow_jobs`, `idempotency_records`, and `audit_events` exist, then reports every live `PENDING`, `RETRY`, or `RUNNING` production job whose exact job type and persisted activity contract identity, plus exact worker id for scoped routes, this process cannot serve. Unsupported unscoped activities are counted per type and activity contract identity; `RECONCILE_WORKER`, `REQUEST_WORK_ITEM_CANCELLATION`, `OBSERVE_RUNMILL_RUN`, and `RETAIN_RUNMILL_TERMINAL_EVIDENCE` are counted per type, activity contract identity, and exact worker route. An empty serviceability backlog remains healthy even when handlers are unavailable. This binding is process-local: there is no durable global reactor capability lease and no scanner that promotes a known-unclaimable job into an owned attention/escalation record, so none of this is a production-readiness claim. The six job-producing API operations—intake sync, work acceptance, cancellation, approval decision, worker reconciliation, and evidence verification—first honor an exact completed idempotency replay, then gate the exact queue target before any mutation that would create its obligation. Cancellation of `ACCEPTED` work with no attempt is the non-queueing case: ASF locks the pristine delivery workflow/job and the work item's monotonic dispatch-fact guard, proves the boundary never crossed, and atomically writes the cancelled state, audit/outbox/idempotency facts, accountability anchor, and exact `PRE_DISPATCH` terminal receipt without requiring a worker handler. Any later dispatch-producing fact is rejected. Once a live authoritative Runmill run exists, the exact worker cancellation route is required. The production verifier is registered only when `CLOSE_SOURCE` is also ready, so a valid result cannot strand its terminal obligation. These are orphan-prevention/recovery safety gates, not aggregate Runmill, ctxlane, provider, artifact, or complete-schema probes; `asf doctor` still calls only `/healthz` and `/readyz`. The reactor recognizes eight production job types. By default none is claimable; complete optional groups can enable Linear intake/source closure, GitHub evidence verification, and Runmill cancellation/worker reconciliation plus durable production of bounded cursor-observation jobs for explicit streams, while accepted-work advance and signed approval remain unavailable. The reservation-expiry sweep still runs. Configured reactor leases must exceed the poll interval and be no longer than 24 hours; the claim and renewal primitives independently reject zero or over-limit durations. Operators must not treat a locally usable API as permission to dispatch work.

## Local operator quickstart

Prerequisites are Docker with Compose v2 and, for native development, Rust 1.97.1 as pinned in `rust-toolchain.toml`.

```sh
cp .env.example .env
```

Replace every `REPLACE_...` value in `.env`. Generate the signing seed and API token with a cryptographically secure generator, for example:

```sh
openssl rand -base64 32
openssl rand -hex 32
```

Then start the local topology:

```sh
docker compose up --build --detach
docker compose ps
docker compose logs asf
```

The Compose project binds services to loopback: ASF on `http://127.0.0.1:8080`, PostgreSQL on `127.0.0.1:5432`, MinIO's API/console on ports `9000`/`9001`, and OTLP on ports `4317`/`4318`. MinIO and the collector demonstrate the target deployment shape; the current Rust process does not consume them.

For native checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
```

See the [operator quickstart](docs/operator-quickstart.md) for migration, maintenance-mode, diagnostics, and teardown details.

## Documentation

- [Architecture and durable reactor](docs/architecture.md)
- [Security and trust boundaries](docs/security.md)
- [Deployment and production gaps](docs/deployment.md)
- [P0 qualification status](docs/p0-status.md)
- [Operator quickstart](docs/operator-quickstart.md)
- [Incident runbooks](docs/runbooks/README.md)

## Safety rules

- Intake is not acceptance. The accountability promise begins only at `ACCEPTED`.
- Models propose; trusted policy grants. Source and repository content cannot select credentials, identity, tools, network, merge, or deployment authority.
- Signed Work Orders are immutable. Any authority-bearing change creates a new attempt.
- Effect identity and request semantics are immutable. Retrying an ambiguous effect means reconciling and adopting the same idempotency key, payload, and digest, not creating or rewriting an effect.
- Absence of dispatch is authority-bearing. It is proved by the locked, monotonic dispatch-fact guard rather than a collection of unlocked negative table scans, and a committed `PRE_DISPATCH` receipt permanently closes that boundary.
- Runmill cancellation observations are append-only: the request response creates `INITIAL`, later claims can extend the same workflow to arbitrary depth one `OBSERVER` at a time, and a terminal transition must cite the chain tail in an exact terminal receipt. A deterministic nonterminal observer cannot be silently changed to `CANCELLED` before that same-chain proof, although normal claim, retry, and dead-letter handling remains available. Attempt reservations are released only in the terminal transaction under the authoritative worker. Every such release carries the exact `cancellation_terminal_receipt_id`; its deferred foreign key requires the Runmill receipt in the same commit, while the closed `runmill-cancellation:v1:{work}:{attempt}:{set}:fence:{prior}` namespace prevents an earlier or unrelated transition from impersonating that release.
- A `CANCELLED` terminal receipt advances and permanently freezes the exact generation of the work item's durable cancellation-authority guard. Creating or activating later attempt, run, workflow, job, timer, effect, reservation, approval, active escalation, or Work Order authority must advance that unfrozen row and is therefore rejected after the receipt; reopening the work item is rejected as well. The same receipt proves that its outbox event was pristine and publishable at the deferred commit boundary without freezing later publisher delivery state. A `TERMINAL_CONFLICT` receipt instead certifies the exact escalation snapshot created or conservatively merged under the live cancellation claim, carries no frozen authority generation, and remains historical evidence while an operator advances the escalation through its separately guarded lifecycle.
- `asf-internal:` idempotency keys are reserved for deterministic control-plane operations. PostgreSQL binds reservation expiry, its event, and every budget release to the exact set, prior fence, actor, reason, timestamp, reservation, and dimension. Parent-row serialization prevents a late budget child and terminal transition from both validating against stale snapshots; a terminal set cannot commit with incomplete budget accounting.
- Maintenance mode is passed to every activity and rejects creation of a new attempt or Runmill submission at the dispatch control. Intake, configured cancellation, configured worker reconciliation, durable configured Runmill cursor observation, configured evidence verification/source closure, and reservation sweeps continue; no production dispatch handler is currently installed.
- Never expose Runmill's private Unix control socket or local ctxlane control endpoint over a network. A future remote worker gateway must be mutually authenticated and fenced.

## License

Apache-2.0.
