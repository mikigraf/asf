# Deployment guide

## Supported shape

ASF V1 is a small modular control application, not a microservice fleet. The local Compose topology contains:

- `asf`: the `all` daemon, which serves the API and runs the fenced PostgreSQL reactor; it claims only activity types whose production handlers are ready;
- `asf-migrate`: one-shot forward migration job using the same image as ASF;
- `postgres`: authoritative ledger;
- `minio` and `minio-bootstrap`: S3-compatible object-store shape and a private bucket;
- `otel-collector`: OTLP receiver with local debug output.

Runmill and ctxlane deliberately are not included. They belong on qualified Linux worker hosts with local trusted control sockets. The reactor logs every unavailable activity and does not claim it. All six job-producing API operations gate their exact ready queue target after completed idempotency replay and before any mutation that creates the obligation. Reconciliation always uses its target worker route; cancellation uses the exact worker route once a live authoritative Runmill run exists, while `ACCEPTED` work with no attempt is cancelled synchronously only after its locked monotonic guard proves that no dispatch-producing fact has ever appeared. That local route commits an exact `PRE_DISPATCH` receipt with the cancellation state and emissions and needs no worker handler. `/readyz` remains healthy when no unsupported live production job exists, but fails with per-type, per-persisted-activity-contract-identity, or exact-worker-route counts when such obligations are present. Dispatch remains unavailable.

The MinIO and OTel services are scaffolding. With complete GitHub observation configuration and a ready Linear source-closure handler, `all` instantiates the local filesystem artifact store only as the evidence verifier's development reader; it does not ingest artifacts, retrieve artifact bytes through the API, or use MinIO/S3. The daemon does not export OTLP. Neither scaffold makes those capabilities production-ready, and ASF startup is not gated on MinIO or the collector. The collector's debug exporter is not a durable telemetry backend.

## Local Compose

Create `.env` from `.env.example`, replace every `REPLACE_...` value, then validate the configuration without printing resolved secrets:

```sh
docker compose config --quiet
docker compose up --build
```

Plain `docker compose config` renders secret-bearing environment values. Do not paste, attach, or retain that output in ordinary logs.

Provision one stable `ASF_TENANT_ID` UUID per V1 environment. Migration `0020_v1_single_tenant_boundary` installs a database guard and `asf-server migrate` atomically binds it to that ID while provisioning the tenant. After activation, PostgreSQL rejects another tenant, tenant-ID rebinding, deletion/truncation of the configured tenant, and reset or removal of the guard. `asf-server all` and `/readyz` refuse a missing, null, or mismatched guard. Changing `ASF_TENANT_ID` therefore requires a new isolated database or an approved restore/migration procedure; it is not a restart-time setting.

Migrations run before ASF starts. Migration mode also idempotently provisions the configured tenant row and refuses a slug/status mismatch for that tenant ID instead of silently rebinding it. PostgreSQL and MinIO data, plus the reserved development artifact path, live in named volumes. Published ports are bound to `127.0.0.1`.

## Server configuration contract

Both `asf-server migrate` and `asf-server all` load and validate the full `Settings` object before selecting a mode. Consequently, the following values are required and cryptographic/authentication material is validated for both commands, even where migration does not consume its operational capability:

| Variable | Contract |
| --- | --- |
| `ASF_TENANT_ID` | Required UUID; must match the immutable activated database guard and remain stable for the lifetime of the environment |
| `ASF_DATABASE_URL` | Required PostgreSQL URL; treat as a secret |
| `ASF_SIGNING_KEY_ID` | Required non-empty identifier; the current daemon does not yet wire production Work Order signing |
| `ASF_SIGNING_SEED_BASE64` | Required 32-byte Ed25519 seed encoded as standard or URL-safe Base64, padded or unpadded; successful validation does not make the unwired signer path operational |
| `ASF_API_TOKENS_JSON` | Required credential array with at least one token of 32 or more bytes, a non-empty subject, and one or more roles |

Optional server settings are `ASF_BIND_ADDRESS` (`127.0.0.1:8080`), `ASF_ARTIFACT_ROOT` (`./var/artifacts`), `ASF_DATABASE_MAX_CONNECTIONS` (`20`), `ASF_WORKFLOW_POLL_MILLISECONDS` (`1000`), `ASF_WORKFLOW_LEASE_SECONDS` (`30`), and `ASF_MAINTENANCE_MODE` (`false`). The lease duration must exceed the poll interval and cannot exceed 24 hours; startup and ledger lease operations enforce the same upper bound. `ASF_MIGRATIONS_DIR` is read directly by migration mode and defaults to `./migrations`; the image sets it to the packaged absolute path. `RUST_LOG` controls tracing verbosity.

Production read-only GitHub observation is an optional, atomic configuration group:

| Variable | Contract |
| --- | --- |
| `ASF_GITHUB_API_BASE` | Credential-free HTTPS REST API root, such as `https://api.github.com/` or a GitHub Enterprise `/api/v3/` root; query strings and fragments are rejected |
| `ASF_GITHUB_BEARER_TOKEN` | Controller-only GitHub bearer token of at least 16 trimmed, control-free bytes; secret |

Leave both values unset to keep `VERIFY_EVIDENCE` unavailable. Setting only one is a startup error. With both configured, ASF enables the production verifier only when the Linear `CLOSE_SOURCE` activity is also ready; otherwise it logs the missing terminal dependency and leaves verification unclaimable so a valid result cannot be orphaned. When enabled, the verifier checks signed artifacts through the development-only filesystem reader at `ASF_ARTIFACT_ROOT` and uses the GitHub adapter only for exact-candidate pull-request and CI observation. This does not provide production evidence ingestion, artifact-byte retrieval, or S3 storage. Redirects are disabled so the authorization header cannot be forwarded to another origin, and the API exposes no branch, pull-request, status, or merge mutation. The credential stays in the trusted controller and must never enter a Work Order, Runmill, repository sandbox, portable evidence, log, or error. `/readyz` does not probe GitHub.

Production Linear intake is an optional, atomic configuration group:

| Variable | Contract |
| --- | --- |
| `ASF_LINEAR_AUTH_MODE` | Exactly `personal_api_key` or `oauth_bearer` |
| `ASF_LINEAR_API_TOKEN` | Linear personal API key or OAuth access token matching the selected mode; secret |
| `ASF_LINEAR_TEAM_MAPPINGS_JSON` | Strict JSON array of 1–128 objects with exactly `team_id`, tenant-owned `repository_id`, `repository` (`owner/name`), and `completed_state_id`; maximum 64 KiB |
| `ASF_LINEAR_CORRELATION_SECRET` | Tenant-scoped secret of at least 32 bytes used to authenticate cursors and closure markers |
| `ASF_LINEAR_CONNECTOR_IDENTITY` | Stable, non-secret audit identity for captured snapshots |
| `ASF_LINEAR_OPT_IN_LABEL` | Exact, non-empty Linear label that opts issues into ASF intake; maximum 256 bytes |
| `ASF_LINEAR_PAGE_SIZE` | Integer from 1 through 250 |

Leave all seven values unset to keep both `INTAKE_SYNC` and `CLOSE_SOURCE` unavailable. Setting any subset is a startup error; ASF never silently constructs a partially trusted connector. The global `ASF_TENANT_ID` is the connector tenant—there is no independent Linear tenant override—and repository foreign keys enforce that mapping IDs belong to it. The mapped active repository rows must already exist. Enabling this group makes both Linear activities claimable. It does not enable accepted-work dispatch, run observation, approval application, worker reconciliation, or evidence ingestion; cancellation requires the independent Runmill group, while verification additionally requires the independent GitHub configuration. `/readyz` does not probe Linear; it reports unavailable activities only when they already own live jobs. Inspect structured startup logs.

Compose passes these optional variables through only when the operator supplies them. They remain commented in `.env.example` so the default local topology starts with Linear unavailable. Because both daemon commands validate the complete `Settings` value, `asf-server migrate` also rejects a malformed or partial Linear group even though it does not call Linear.

Production Runmill cancellation, durable bounded cursor observation, and configured-worker health reconciliation share a second optional, atomic configuration group:

| Variable | Contract |
| --- | --- |
| `ASF_RUNMILL_REGISTRY_PATH` | Normalized absolute path to Runmill's private `daemon.json` registry |
| `ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS` | Per-call timeout from 1 through 60,000 milliseconds |
| `ASF_RUNMILL_CONTROLLER_SUBJECT` | Stable 1–256 byte Runmill identifier used as the `asf:cancel` requester |
| `ASF_RUNMILL_CANCELLATION_GRACE_SECONDS` | Graceful-cancellation window from 1 through 300 seconds; this handler never silently upgrades to forced cancellation |
| `ASF_RUNMILL_WORKER_ID` | Existing tenant-owned ASF worker UUID represented by this private Runmill daemon |

Leave all five values unset to keep `REQUEST_WORK_ITEM_CANCELLATION`, `RECONCILE_WORKER`, `OBSERVE_RUNMILL_RUN`, and `RETAIN_RUNMILL_TERMINAL_EVIDENCE` unavailable. Any partial group is a startup error. Enabling it makes those activities claimable for the configured worker and lets each reactor poll produce due V2 observer jobs from streams explicitly inserted beneath already-authoritative runs. Each read-only job fetches one `get-run` snapshot and one `list-run-events` page (`limit=100`) after its exact durable cursor. Immutable checkpoint/result rows, the next cursor or terminal-ready state, and fenced job completion commit atomically; a compacted gap instead retains both exact reads and atomically creates owned terminal escalation without advancing the cursor. A controller restart may use a new live same-generation observer session while the stream preserves the immutable session that admitted the run. An observer that exhausts outside the compacted-gap path is owned `DEAD` work that the same producer transaction reconciles before scheduling: it records one append-only terminal-failure fact and releases the stream as `ESCALATED` at the unchanged cursor. There is still no result fabrication, cursor advance, or replacement job. A stream left `TERMINAL_READY` produces one `RETAIN_RUNMILL_TERMINAL_EVIDENCE` job for that exact terminal observation: it makes a single `asf.get_evidence` call on the same private socket, requires the returned envelope to verify under the admitting worker session's own signing key inside that session's signing window, and commits the append-only evidence bundle together with its own fenced completion. In the same commit it ingests the signed evidence bundle that read carried, binds durable metadata for every artifact its signed manifest names, and enqueues `VERIFY_EVIDENCE` when this process installs a ready verifier; without one it still ingests, and the authenticated API can schedule verification later. A terminal read whose evidence is not `final` carries no signed bundle, and that case is retained without inventing one. Retention never advances the stream, projects an event, or rewrites run state, and it is not re-produced once a bundle for that run exists. This still does not discover/adopt runs, expose a production stream-installation/adoption operation, create streams from dispatch, project into `runs` or `raw_run_events`, reduce terminal state, apply approvals, schedule verification from a retained bundle, or retrieve artifacts. Evidence verification is controlled independently by the GitHub group. The configured worker row must already belong to `ASF_TENANT_ID`; startup fails otherwise. ASF validates the private registry and socket on every call: the containing directory must be mode `0700`, both registry and socket mode `0600`, neither path may be a symlink, both must belong to ASF's effective UID, and the socket must remain beside the registry. The configured timeout does not hold work-item, workflow, run, or worker row locks while doing socket I/O.

Worker reconciliation is deliberately non-authoritative. It never creates a worker, generation, capability set, concurrency limit, or session. A ready Runmill report promotes the row to `READY` only when its reported concurrency matches the stored limit, the stored capabilities pass ASF's production predicate, and a live same-generation session already exists. A missing session leaves the row `REGISTERED`; degraded/refusing health drains or offlines it. Unsafe control metadata, incompatible/malformed protocol facts, concurrency mismatch, or unqualified capabilities quarantine it and revoke active sessions. Health cannot automatically unquarantine a worker. The exact job claim, worker version/generation check, state update, audit append, session revocation, and job completion are transactionally fenced. This projection still does not establish attempt-specific ctxlane leases or dispatch readiness.

PostgreSQL prevents update or deletion of the cancellation effect's identity, binding, idempotency/correlation values, request digest, and payload. Every `IN_FLIGHT` cancellation stores the exact owning workflow-job UUID as well as its owner and fence. If preflight acknowledgement is lost, a later claim may adopt only after that exact recorded job is no longer an unexpired matching `RUNNING` claim; another job with the same reactor owner and per-row fence cannot impersonate it. The effect lease is a diagnostic snapshot, not the ownership oracle.

The first accepted Runmill result creates an immutable `INITIAL` observation receipt. A nonterminal result leaves attempt reservations active and causes later exact claims to extend the same workflow to arbitrary depth, one monotonic `OBSERVER` at a time. The deterministic observer can participate in ordinary claim, retry, exhaustion, and dead-letter handling, but a deferred guard rejects a direct transition to `CANCELLED` until an immutable terminal receipt cites a terminal `OBSERVER` from that exact chain. Only a terminal chain tail may complete the job: the same transaction writes the exact run/attempt/work/workflow projection, audit and outbox facts, terminal receipt and anchor, and releases all active reservations for the attempt under the authoritative worker. Every released set stores the exact `cancellation_terminal_receipt_id`; a deferred foreign key requires receipt and release to commit together, and a closed check reserves the exact `runmill-cancellation:v1:{work}:{attempt}:{set}:fence:{prior}` transition key for this path. The receipt records the exact release count, job owner/fence/attempt count, aggregate versions, chain tail, and emitted facts. A `CANCELLED` receipt also records and freezes the winning generation of `work_cancellation_authority_guards`, so an insert or activation of later live work authority cannot commit. At its deferred commit boundary the cited outbox row must be pristine, unclaimed, unpublished, and publishable; after commit, normal outbox claim/retry/publication remains allowed.

An already-terminal non-cancelled Runmill result routes to an owned `REMOTE_EFFECT_AMBIGUOUS` escalation. A new escalation uses the database observation time as `opened_at` and derives its four-hour deadline from that same value. If another open escalation already owns that generic category, ASF preserves its identity, owner, status, lifecycle timestamps, idempotency, and prior evidence while deterministically augmenting the reason, required action, evidence, path, prerequisites, run binding, active-effect state, no-automatic-retry policy, severity floor, and earlier deadline. The merge receipt is trigger-generated only while the exact terminal cancellation job remains a live claim; it binds that job, effect, and terminal observation and stores complete OLD/NEW digests for the one-version conservative transform. The immutable `TERMINAL_CONFLICT` receipt certifies the exact creation/merge snapshot but carries no cancellation-authority generation and does not freeze the guard. Later legal acknowledgement, resolution, or other remediation therefore advances the escalation under its own lifecycle controls and does not require either historical receipt to describe the current escalation state.

The stock Compose topology passes these variables through but does not mount a host Runmill runtime directory or alter identities. A containerized deployment must arrange a same-UID private runtime mount at the exact absolute path; a host socket owned by a different UID will be rejected. Do not weaken file modes or expose the Unix socket over TCP to make local Compose convenient.

Requiring the migration job to receive signing and API credential material broadens its secret exposure even though it does not use those capabilities. Split mode-specific configuration and secret delivery before production hardening; until then, protect the migration environment to the same standard as the long-running controller.

Set the current maintenance-mode startup signal with:

```sh
ASF_MAINTENANCE_MODE=true docker compose up -d --force-recreate asf
```

The reactor passes this flag to every activity and its dispatch control rejects creation of a new attempt or Runmill submission. Linear intake remains observational and continues. Configured Runmill cancellation/worker reconciliation, durable bounded cursor observation, and configured evidence verification/source closure also continue for their eligible work. Maintenance mode keeps the bounded terminal-failure reconciler active, so a non-gap observer job that exhausted still releases its stream into an owned `ESCALATED` state; deciding what happens to that escalated run remains operator work. The remaining unavailable handlers still prevent this build from qualifying dispatch, event-to-workflow reduction/evidence handoff, approval, evidence ingestion, artifact-byte retrieval, or Runmill outcome acknowledgement.

## Image contract

The multi-stage `Dockerfile`:

- builds both Rust binaries with the pinned toolchain and `Cargo.lock`;
- runs as an unprivileged user;
- contains CA roots, a minimal init, a health-check client, and packaged migrations;
- reserves `/var/lib/asf/artifacts` for the development-only filesystem verifier reader;
- defaults to `all`, serving the API and running the reactor; unavailable activity types remain fail-closed and are not claimed.

Tini runs as PID 1 and forwards the image's explicit `SIGTERM` stop signal. The server stops accepting new HTTP work, signals the reactor to stop claiming work, drains both supervisors, logs the signal, and closes its PostgreSQL pool; Compose allows 45 seconds before forced termination.

Release pipelines should publish the image by immutable digest, produce an SBOM/provenance attestation, scan it, and sign it. Compose tags are explicit local defaults, not a supply-chain guarantee.

## Production requirements not supplied by Compose

- Managed or highly available PostgreSQL with encrypted backups, point-in-time recovery, connection limits, and restore drills.
- S3-compatible storage with TLS, encryption, versioning/immutability as policy requires, lifecycle rules, replicated evidence, and an implemented ASF adapter.
- An OTel exporter in ASF and a durable metrics/logs/traces backend with alerts.
- External TLS ingress, authentication integration, rate limits, and network policy.
- A secret manager/runtime identity; never production `.env` files.
- KMS/HSM or isolated signing service, key rotation, and protected old verification keys.
- Qualified Linux Runmill hosts, local ctxlane, sandbox isolation, worker fencing, and compatible MCP/evidence contracts.
- A Runmill lookup by Work Order idempotency key or payload digest that can recover a successful submission after response loss, including after the signed envelope expires.
- Exact attempt-scoped ctxlane readiness and lease attribution for profile, principal, environment, policy, and worker generation.
- A Work Order successor or immutable referenced authority contract carrying the full source reference, risk reasons, planner digest, command policy, and explicitly named repository-policy digest that strict V1 lacks.
- Production activities for Work Order signing/submission and dispatch, authoritative-run stream installation/adoption, event-to-workflow projection/reduction, approval application, signed-evidence ingestion, artifact-byte retrieval, and Runmill outcome acknowledgement.
- The external Linux qualification matrix with real Runmill crashes, ctxlane restarts/leases, protected-provider response ambiguity, CI edge cases, sandbox isolation, and dedicated workload identities.
- Qualification credentials and failure-injection coverage for the wired GitHub verifier and Linear intake/source-closure adapter.
- Alert routing and ownership for all 12 runbooks.

Until these dependencies exist, ASF is not qualified for production dispatch. The current `/readyz` endpoint checks the active tenant, its exact activated V1 database guard, `workflow_jobs`, `idempotency_records`, and `audit_events`, then fails with per-type, per-persisted-activity-contract-identity, or exact-worker-route counts for every live production job the installed handler capabilities cannot service by its exact job type, persisted activity contract identity, and (for scoped routes) exact worker id, including reconciliation, cancellation, and cursor observation. Intake sync, work acceptance, cancellation, approval decision, worker reconciliation, and evidence verification gate every fresh queue-producing mutation on the corresponding ready type or exact worker route, while an exact completed idempotency replay remains readable after capability loss. `ACCEPTED` work with no attempt has no cancellation queue target: after an exact dispatch-boundary proof, it completes synchronously without a worker handler; a live authoritative run requires its exact worker route. The verifier itself is enabled only when `CLOSE_SOURCE` is ready. HTTP 200 with no unsupported backlog still does not prove that every production dependency or migration is ready, and this job-type/contract/worker binding is checked process-locally: there is no durable global reactor capability lease and no scanner that promotes a known-unclaimable job into an owned attention/escalation record.

## Migration policy

Migrations are forward-only. Back up and verify restoration before rollout and run exactly one migration job. Migration `0005_effect_intent_exact_job_ownership` is a stop-the-world compatibility boundary: drain and stop every old API/reactor process before migrating, then start only the matching new binary. Maintenance mode is insufficient because configured cancellation deliberately continues in maintenance. Old binaries cannot populate the new exact-owner field. Legacy `IN_FLIGHT` cancellations are conservatively changed to `AMBIGUOUS` without guessing an owner; their existing jobs remain fenced until their configured lease expires (at most 24 hours) or an operator performs an audited reconciliation.

Migration `0006_cross_binding_and_terminal_guards` validates existing run/event ownership while adding the exact run-session foreign key; a failure is evidence of inconsistent durable data and must be investigated rather than bypassed. Migration `0007_operational_incident_reciprocal_proofs` validates each existing incident's deterministic job idempotency key and strengthens subsequent incident inserts and lifecycle transitions; it does not invent retrospective receipts. Migration `0008_runmill_submission_effect_ownership` takes strong table locks and must run with executors quiesced. It relationally binds any legacy submission intent to its unique attempt Work Order, changes legacy `IN_FLIGHT` submissions to `AMBIGUOUS`, and fails closed if the authority binding is not uniquely provable. Test the full ordered chain on a restored copy before rollout. Do not apply hand-written corrective `UPDATE`/`DELETE` statements to immutable or append-only tables.

Migrations `0009` through `0016` extend that quiesced, fail-closed chain across Linear closure, exact worker-session admission authority, retained session signing keys, authority lifetime, terminal source-closure receipts, verifier-job provenance, frozen verified-artifact manifests, and strict evidence-verification receipts. In particular, `0016_evidence_verification_receipt_integrity` validates that every existing `VALID` row has the exact receipt shape and relational values for its evidence/run and completed `VERIFY_EVIDENCE` job, with database-bounded observation and verification times; it refuses history that cannot prove those facts. Review each migration's lock and legacy-data preconditions before rollout rather than assuming an empty-schema upgrade profile.

Migration `0017_cancellation_receipt_integrity` is another quiesced compatibility boundary. Stop every API, reactor, cancellation observer, and direct writer before it takes its strong locks; maintenance mode is not sufficient because configured cancellation intentionally remains active there. The migration refuses any historical cancelled work, cancellation anchor, completed cancellation job, terminal cancellation effect, audit marker, or run snapshot whose exact claim/negative-dispatch provenance cannot be reconstructed. It also refuses a pristine accepted item whose acceptance audit hash cannot be recomputed after PostgreSQL timestamp precision, rather than installing a pre-dispatch route on unverifiable acceptance history. On valid history it backfills both the monotonic dispatch-fact guards and the durable `work_cancellation_authority_guards`, installs append-only observation and terminal-receipt tables, and adds deferred reciprocal guards. New or reactivated live authority advances the cancellation guard immediately; only a `CANCELLED` receipt advances it to an exact receipt-bound frozen generation, while `TERMINAL_CONFLICT` leaves it open. The reciprocal guards intentionally return without a parent lock when no committed cancelled state or `CANCELLED` receipt exists because this durable row boundary, not a deferred advisory lock, closes live-child phantoms. Once the cancelled fact is visible they preserve the rest of its exact proof. This avoids adding a child-to-parent deadlock edge against the runtime's parent-to-child order. Start only the matching binary after the migration succeeds, and treat either preflight failure as a data-qualification incident rather than editing immutable history.

Migration `0018_cancellation_escalation_supersession` is the matching recovery boundary for an exhausted cancellation observer. It refuses an upgrade that already has `CANCEL_REQUESTED` work with live escalation authority. New operator recovery accepts only the current attempt's exact active `WORKFLOW_JOB_EXHAUSTED` escalation and accountability anchor, retains the immutable `DEAD` jobs, and commits the escalation cancellation, replacement workflow job, anchor/work transitions, trigger-captured OLD/NEW facts, audit/outbox, idempotency completion, and append-only supersession receipt atomically. Apply it with the same writers quiesced; do not fabricate a receipt for a historical accountability swap whose OLD rows no longer exist.

Migration `0019_shared_work_finality_gate` extends `work_cancellation_authority_guards` into the mutually exclusive cancellation/source-closure finality gate. Under strong deployment locks it refuses any historical `CLOSED` work without one exact observed Linear closure chain or with remaining live authority, then backfills the exact close-effect reference and advances the guard generation. Afterward every guarded work-scoped insert, including terminal-looking history, and every new activation or binding move must cross an unfrozen row. Verified source closure and `CANCELLED` receipts freeze different mutually exclusive references; the public source-closure predicate also requires the frozen guard and the shared no-live proof. Stop all API/reactor/direct writers for this migration and treat either `shared_work_finality_upgrade_*` failure as a data-qualification incident.

Migration `0020_v1_single_tenant_boundary` takes an access-exclusive tenant-table lock and refuses historical databases containing more than one tenant. It backfills the sole historical tenant when present; a fresh empty schema remains deliberately unconfigured until `asf-server migrate` provisions and activates it. Activation and every tenant identity write use one lock order and the singleton guard, after which the binding is immutable. Quiesce direct writers for rollout, record the selected `ASF_TENANT_ID`, and never repair the guard with ad hoc SQL. Migration `0021_runmill_run_observation_provenance` adds append-only storage for strictly validated complete Runmill response wires and their semantic snapshots under a live, run-bound observation claim. Remote event identities retain their immutable first-seen page, while a separate append-only association records every exact page occurrence so overlap after reconnect or fence reclamation remains idempotent. Reuse of one job/fence/control-sequence slot returns its first semantically identical stored snapshot; the first exact wire and observation time remain authoritative for that slot.

Migration `0022_runmill_observation_streams` is a quiesced observer compatibility boundary. It refuses live legacy observation jobs because they cannot prove the new exact cursor/epoch/checkpoint/session payload, but preserves completed historical `0021` provenance at epoch zero. It creates the durable stream/checkpoint/result model, monotonic cursor/version/state guards, and distinct immutable admission versus current live observer-session provenance; it does not insert or infer a stream for any historical run. A future authority-bearing installation/adoption workflow must explicitly create each stream beneath an already-authoritative run. Every active checkpoint release must consume, in the same transaction, either its exact observation result or the append-only `runmill_observation_terminal_failure_facts` row whose insert trigger re-proves the exact active stream, checkpoint, dead V2 job, effective `WORKFLOW_JOB_EXHAUSTED` escalation, and durable failure digest under lock. That fact releases the stream only into `ESCALATED`, never moves the cursor or epoch, and is rejected whenever a snapshot, observation result, or gap binding already exists for the same observation. Apply only after old observer writers are stopped; a refusal is an upgrade-qualification incident, not permission to fabricate cursor history. The migration adds producer/cursor storage and observation safety, but deliberately adds no run/event reducer or historical stream inference.

For a local migration-only run:

```sh
docker compose run --rm asf-migrate
```

For production, use the released ASF image and its migration mode under a database principal allowed to perform DDL and initial single-tenant provisioning. The long-running ASF principal should have narrower permissions where the runtime permits it. Capture the migration job logs, configured tenant ID, and schema version as deployment evidence.

Rollback means deploying compatible application code or restoring into an isolated recovery environment; it does not mean reversing a forward-only migration in place. A destructive restore requires the [database restore runbook](runbooks/12-database-restore-and-reconciliation.md).

## Target availability and rollout

The following procedure applies only after the remaining production activities and adapters are implemented and qualified:

1. Enter maintenance mode and verify new dispatch is zero.
2. Confirm workflow, outbox, and effect backlog age; understand every `DEAD` or `AMBIGUOUS` row.
3. Take and verify database/object-store recovery points.
4. Drain and stop all API/reactor instances; verify no old process can claim or cancel work.
5. Run the migration job once, then start only instances from that matching release.
6. Verify liveness, readiness, DB health, reactor claims, and reconciliation lag.
7. Reconcile Runmill/GitHub/Linear state before enabling dispatch.
8. Exit maintenance mode and watch breakers, duplicate-effect metrics, and orphan-accountability count.

Never infer a failed worker activity from an MCP disconnect. Runs are durable on the Runmill side and must be found by Work Order/idempotency key before retry.

## Backups

Back up PostgreSQL and object evidence on a schedule that meets the five-minute target RPO, including encryption keys and restore metadata. Content addressing detects corruption but does not provide availability. A usable recovery point includes:

- database base backup/WAL or equivalent point-in-time recovery data;
- object versions and metadata consistent enough to reconcile from database references;
- signing and worker verification public keys;
- released ASF/Runmill/ctxlane versions and schema compatibility information;
- audit-preserving restore procedure and a clean-room verification environment.

Exercise the restore runbook regularly; backup-job success alone is not restore evidence.
