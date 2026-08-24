# Operator quickstart

This guide starts the local control-plane topology. It does not qualify Runmill, ctxlane, GitHub, Linear, S3 artifact storage, or OTLP export for production.

## 1. Prepare configuration

```sh
cp .env.example .env
openssl rand -base64 32
openssl rand -hex 32
```

Put the first output in `ASF_SIGNING_SEED_BASE64` and the second inside the token field of `ASF_API_TOKENS_JSON`. Replace the PostgreSQL and MinIO passwords as well. Keep `.env` out of source control.

`ASF_TENANT_ID` is the stable UUID selected for the single V1 tenant. The example UUID is suitable only for this local Compose project; use a deliberately provisioned ID in each real environment. `asf-server migrate` activates an immutable PostgreSQL guard for this ID, and the daemon/readiness check refuse a null or mismatched guard. Once provisioned, changing the ID requires a new isolated database or an approved restore/migration procedure.

The local token config uses the `platform_admin` role to make all CLI reads possible. Production should issue separate credentials with the least-privileged roles described in `docs/security.md`.

Linear integration is disabled by default. To enable it after the mapped repository rows exist, uncomment and replace the complete `ASF_LINEAR_*` group in `.env`. Supplying only part of the group is a startup error. The token and correlation secret are controller credentials: keep them out of source repositories, command arguments, and logs. This enables `INTAKE_SYNC` and `CLOSE_SOURCE`; all other production activity types remain independently fail-closed.

Independent evidence verification is disabled by default. Set both `ASF_GITHUB_API_BASE` and `ASF_GITHUB_BEARER_TOKEN`; a partial group, insecure or credential-bearing URL, or malformed token is a startup error. `VERIFY_EVIDENCE` becomes claimable only when the Linear `CLOSE_SOURCE` activity is also ready, because the current verifier supports that exact terminal chain and must not create an orphaned closure job. When enabled, it uses the filesystem at `ASF_ARTIFACT_ROOT` as a development-only content-addressed reader and GitHub only for current exact-candidate pull-request and CI observations. This does not provide evidence ingestion, artifact-byte retrieval, or production S3 storage. Keep the token in controller secret delivery only. `/readyz` does not probe GitHub.

`ASF_WORKFLOW_LEASE_SECONDS` must be longer than `ASF_WORKFLOW_POLL_MILLISECONDS` and no greater than 86,400 seconds (24 hours). Startup rejects an over-limit value, and the ledger independently applies the same 24-hour maximum to claims and renewals.

## 2. Validate and start

```sh
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

The one-shot `asf-migrate` container must exit successfully before `asf` starts. It applies forward-only migrations, idempotently provisions the configured local tenant, and activates its immutable database guard; a historical second tenant, guard mismatch, derived-slug mismatch, or non-`ACTIVE` row is an error. Migrations `0017` through `0020` require all API/reactor/cancellation/direct writers to be stopped. They fail closed when historical cancellation provenance, cancellation-escalation supersession, pristine acceptance history, verified source-closure finality, or the single-tenant upgrade precondition cannot be proved exactly. Migration `0021` adds append-only exact-wire Runmill observation provenance; `0022` adds the explicit V2 observation stream, immutable checkpoint/result records, and fenced producer/release transitions. `0022` also adds the append-only terminal-failure fact that lets a bounded reconciler release a stream whose exact active observer job became owned `DEAD` work without retaining a remote page. The runtime can poll one bounded page from an already installed authoritative stream and continue at that stream's durable cursor, but it still has no supported stream-adoption/install workflow, projection/reducer, or evidence handoff. Do not repair a preflight with direct SQL; qualify the data in an isolated restored copy and follow the [migration policy](deployment.md#migration-policy). Both `migrate` and `all` currently require every required `ASF_*` setting in `.env`; see the [server configuration contract](deployment.md#server-configuration-contract). Inspect failures with:

```sh
docker compose logs postgres asf-migrate asf
```

## 3. Check the control plane

```sh
curl --fail --silent http://127.0.0.1:8080/healthz
curl --silent --show-error --include http://127.0.0.1:8080/readyz
```

`/healthz` verifies a PostgreSQL query. `/readyz` verifies the active configured tenant plus the presence of `workflow_jobs`, `idempotency_records`, and `audit_events`, then counts every live production job this process cannot claim by its exact job type, persisted activity contract identity, and (for scoped routes) exact worker id. Unscoped obligations are reported per job type and persisted activity contract identity; worker reconciliation, cancellation, and `OBSERVE_RUNMILL_RUN` are reported per type, persisted activity contract identity, and exact `worker_id` route. Expect HTTP 200 when no unsupported live obligation exists, even if some handlers are unavailable, and HTTP 503 with per-type/contract/route counts when work is stranded. The six job-producing endpoints for intake sync, acceptance, cancellation, approval decisions, worker reconciliation, and evidence verification preserve exact completed idempotency replay after capability loss, and gate every fresh queue target before changing an aggregate or inserting its job. Cancellation of `ACCEPTED` work with no attempt is synchronous only after locking the false monotonic dispatch guard and exact pristine acceptance state; it atomically creates a `PRE_DISPATCH` terminal receipt and therefore needs no worker handler. Any lock conflict or prior dispatch fact fails closed. Once a live authoritative Runmill run exists, its exact worker route is required. `VERIFY_EVIDENCE` is registered only with a ready `CLOSE_SOURCE` handler. `asf doctor` calls these same two public endpoints, so it can remain useful for a healthy empty/recovery ledger. This gate prevents new orphan jobs and exposes existing ones; it is not an aggregate GitHub, Runmill, ctxlane, artifact, or complete-schema diagnostic. The type/contract/worker match is process-local, not a durable global reactor capability lease, and no unserviceable-obligation scanner exists yet. The `all` daemon runs the reactor and can claim only handlers enabled by complete optional groups, but autonomous dispatch remains disabled.

To enable Runmill cancellation, worker-health reconciliation, and the bounded observer on a qualified same-UID host, configure all five values together:

```sh
export ASF_RUNMILL_REGISTRY_PATH=/run/user/1000/runmill/daemon.json
export ASF_RUNMILL_CONTROL_TIMEOUT_MILLISECONDS=5000
export ASF_RUNMILL_CONTROLLER_SUBJECT=asf:production-controller
export ASF_RUNMILL_CANCELLATION_GRACE_SECONDS=30
export ASF_RUNMILL_WORKER_ID=0198c8d2-77af-7000-8000-000000000001
```

The worker UUID must already exist under `ASF_TENANT_ID`. ASF does not manufacture its capability, generation, concurrency, or session authority. Before a healthy probe can mark it `READY`, provision production-qualified capabilities and a live session for the same generation; a missing session leaves it `REGISTERED`. Unsafe control metadata quarantines the worker and revokes active sessions, while transient transport loss marks it offline. Only an explicit operator action may remove quarantine.

The registry directory must be private (`0700`), and Runmill's registry and Unix socket must both be `0600`, non-symlink files owned by the ASF process UID. If ASF runs in a container, mount that private runtime directory at the exact configured absolute path without changing ownership. Startup accepts the group atomically; individual calls revalidate the registry, protocol, socket identity, and ownership. The V2 observer is produced only from an explicitly installed authoritative stream: it creates one immutable checkpoint/job for the stream's current cursor, records the live observer session selected for that poll, and keeps the original run-admission session as immutable provenance. A page retains exact `get-run` and bounded event-page responses. A gap-free page advances the cursor and schedules the next poll; a final terminal page changes the stream to `TERMINAL_READY`. A valid `gap=true` page is retained with a `BLOCKED_GAP` result, force-dead-letters its exact job with an owned `WORKFLOW_JOB_EXHAUSTED` escalation, and releases the stream as `ESCALATED` without advancing the cursor. An observer job that instead reaches `DEAD` with no retained page — retry exhaustion, route-invalid rejection (for example an expired observer session on an otherwise admitted stream), or expired/orphan final-attempt recovery — is reconciled by the next producer transaction: it writes one row to `runmill_observation_terminal_failure_facts` and releases the stream as `ESCALATED` at the unchanged cursor. Inspect it with `select run_id, observation_id, workflow_job_id, escalation_id, after_sequence, observation_epoch, failure_digest from runmill_observation_terminal_failure_facts`. None of these observation transitions projects remote state into `runs` or `raw_run_events`, invokes a reducer, or makes an evidence decision. There is currently no supported stream adoption/installation operation, replacement observer, or reducer/evidence handoff; do not attempt any of those with SQL, and never insert a terminal-failure fact by hand — PostgreSQL re-proves every coordinate and rejects a forged or mutated row. Cancellation reuses one immutable effect request per authoritative attempt/run. After preflight response loss, a replacement fence can recover an orphaned `IN_FLIGHT` intent without waiting for its effect lease, but cannot take it while the recorded workflow-job UUID, owner, and fence still form a live claim.

The request result is retained as the chain's `INITIAL` observation. A nonterminal run keeps all attempt reservations active and later exact observer claims extend the same workflow to arbitrary depth with monotonic `OBSERVER` receipts instead of replacing history. Operators may let that deterministic job follow normal claim, retry, exhaustion, and dead-letter handling, but must not cancel it away: PostgreSQL rejects `CANCELLED` until an exact terminal receipt cites a terminal `OBSERVER` from the same chain. If the observer exhausts, an explicit operator cancellation may supersede only its exact current-attempt exhaustion escalation; confirm the append-only supersession receipt and three trigger-captured transition facts before relying on the replacement observer. Only a terminal observation may complete the job, release reservations, and create the exact terminal receipt covering the run projection, aggregate versions, job claim, audit/outbox facts, accountability anchor, and release count. Each released set must cite that receipt through `cancellation_terminal_receipt_id` in the same commit and use its exact reserved `runmill-cancellation:v1` work/attempt/set/prior-fence key. A `CANCELLED` receipt freezes one terminal reference in the shared per-work finality guard; verified source closure freezes the mutually exclusive close-effect reference. Every later guarded work-scoped insert, even terminal-looking history, and every new activation or binding move fails at that row boundary. The outbox must be pristine and publishable when the deferred receipt check commits; its normal publisher lifecycle may advance afterward.

An already-terminal non-cancelled run produces a historical `TERMINAL_CONFLICT` receipt and remains an operator-owned escalation rather than a silent cancellation success. This receipt carries no cancellation-authority generation and leaves the per-work guard unfrozen so its waiting workflow and escalation can be remediated. Creation time and its four-hour deadline derive from the database `observed_at`, not controller wall-clock input. If an existing escalation is merged, confirm the trigger-generated merge receipt names the live cancellation job, effect, and terminal observation and contains the exact before/after digests. A later legal escalation acknowledgement or resolution does not invalidate that historical snapshot. `/readyz` still does not probe Runmill; it reports a live reconciliation, cancellation, or observer job as unsupported unless this process owns the exact configured worker route and its persisted activity contract identity matches. Confirm the structured startup message and exercise non-production cancellation, worker-reconciliation, and bounded-observer fixtures before relying on those handlers.

Request a fenced health refresh with a stable idempotency key:

```sh
cargo run --locked --bin asf -- worker reconcile "${ASF_RUNMILL_WORKER_ID}" \
  --idempotency-key "operator:worker-health:${ASF_RUNMILL_WORKER_ID}:2026-08-22"
```

Build and use the operator CLI from the host:

```sh
cargo build --locked --bin asf
export ASF_API_URL=http://127.0.0.1:8080/
export ASF_API_TOKEN='the-token-placed-in-ASF_API_TOKENS_JSON'
cargo run --locked --bin asf -- doctor
cargo run --locked --bin asf -- --output json work list
cargo run --locked --bin asf -- --output json attention list
```

### Submit intake

```sh
cargo run --locked --bin asf -- intake submit --file candidate.json --idempotency-key "operator:intake:2026-08-24-001"
```

`--file` must contain a top-level JSON object; its contents are sent unchanged as the body of `POST /v1/intake`. If the result of a submission is unknown (timeout, dropped connection, or any other ambiguous outcome), retry with the exact same `--idempotency-key` rather than generating a new one.

Do not put API tokens in command arguments, URLs, shell history, or issue comments.

## 4. Inspect durable state

Read-only SQL is useful during local diagnosis:

```sh
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select status, count(*) from workflow_jobs group by status order by status"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select state, count(*) from work_items where accepted_at is not null group by state order by state"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select category, severity, owner_id, deadline from escalations where status in ('OPEN','ACKNOWLEDGED') order by deadline"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select id, workflow_job_id, status, aggregate_version, owner_id, deadline from operational_incidents order by opened_at"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select work_item_id, generation, dispatch_started from work_dispatch_fact_guards order by work_item_id"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select work_item_id, route, outcome, terminal_observation_id, released_reservations, recorded_at from cancellation_terminal_receipts order by recorded_at"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select effect_intent_id, route, prior_observation_id, external_phase, observed_at from runmill_cancellation_observations order by recorded_at"
docker compose exec postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
  "select escalation_id, effect_intent_id, terminal_observation_id, workflow_job_id, aggregate_version_before, aggregate_version_after from terminal_conflict_escalation_merge_receipts order by recorded_at"
```

Use supported APIs/reconciliation paths for mutations. Manual SQL can bypass audit, versions, fencing, idempotency, and accountability triggers.

## 5. Maintenance-mode configuration

Set the startup flag with:

```sh
ASF_MAINTENANCE_MODE=true docker compose up -d --force-recreate asf
```

The `all` daemon passes this setting to the execution reactor. It suppresses new dispatch while leaving configured drain/recovery work claimable: Runmill cancellation/worker reconciliation, the bounded V2 Runmill observer producer and handler for explicitly installed streams, and evidence verification/Linear source closure remain active, and cancellation always uses graceful mode with the configured deadline. The bounded terminal-failure reconciler also keeps running, so a dead observer still releases its stream into an owned `ESCALATED` state. Stream adoption/installation, a projection/reducer, observation-to-evidence handoff, approval application, evidence ingestion, and artifact-byte retrieval are still unavailable. Verify that no new attempt is dispatched while existing ledger state and configured recovery work remain visible. To clear the startup flag, set `ASF_MAINTENANCE_MODE=false` in the deployment configuration and recreate `asf`.

## 6. Inspect restart durability

With a non-terminal test work item, restart only the ASF process:

```sh
docker compose restart asf
docker compose logs --since 2m asf
```

Verify the ledger retained the attempt, job/timer, cursor, reservation, budget entries, and accountability anchor. For cancellation, verify that `INITIAL` remains immutable across restart, every later same-workflow `OBSERVER` points to the prior chain tail, and no reservation is released before a terminal observation and terminal receipt commit together. Every terminally released set must name that receipt in `cancellation_terminal_receipt_id` and carry the exact reserved `runmill-cancellation:v1` work/attempt/set/prior-fence key. Do not clear a stuck nonterminal observer by setting it to `CANCELLED`; use normal retry/dead-letter diagnosis and retain its owned attention path. Confirm a `CANCELLED` receipt owns the frozen generation of `work_cancellation_authority_guards` and that a `TERMINAL_CONFLICT` receipt does not freeze it. Confirm the receipt's outbox event was pristine at creation, then evaluate its current publisher state separately. A `TERMINAL_CONFLICT` receipt remains after its escalation advances; inspect the escalation lifecycle separately rather than treating the old receipt as its current status. The `all` daemon reclaims expired jobs with a higher fence token and sweeps expired reservation sets before admitting more work. Confirm the old lease owner cannot complete the reclaimed job, the replacement claim is fenced, and each expired reservation set has exactly one terminal event and one release per reserved budget dimension. The `asf-internal:` expiry and budget-release keys must name that exact set and prior fence; caller-supplied or cross-set collisions are rejected by PostgreSQL. Do not delete volumes for this test.

## 7. Exercise graceful shutdown

```sh
docker compose stop asf
docker compose logs --since 2m asf
```

Compose sends `SIGTERM` through Tini and allows 45 seconds for the API to drain in-flight connections and close the PostgreSQL pool. Confirm the `shutdown signal received` log and a clean container exit. Avoid `docker kill`, which bypasses this check.

## 8. Stop or reset

Stop containers while preserving data:

```sh
docker compose down
```

`docker compose down --volumes` permanently deletes the local PostgreSQL, MinIO, and artifact volumes. Use it only for disposable local data after checking the exact Compose project.

## Next steps

- Review the [architecture](architecture.md) and [security boundary](security.md).
- Configure alerts and owners for every [required runbook](runbooks/README.md).
- Complete the production gaps in [deployment](deployment.md) before a pilot.
