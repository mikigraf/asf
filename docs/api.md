# API compatibility notes

## `POST /v1/intake`

Direct, authenticated submission of one candidate source snapshot into
intake, independent of any configured sync connector.

### Authentication and authorization

Like every other `/v1/*` route, `POST /v1/intake` requires bearer
authentication; a missing or invalid `Authorization` header returns 401
before the backend runs. The caller must also hold the `SubmitIntake`
permission. Under the current role mapping `repository_owner`,
`platform_admin`, and `intake_submitter` grant `SubmitIntake`
(`platform_admin` implicitly holds every permission); every other role,
including `viewer`, is rejected with 403 before the backend runs.
`intake_submitter` holds only `SubmitIntake` — it grants no other
permission, so a connector or automation principal scoped to this role
cannot accept, cancel, approve, or otherwise mutate work.

Every call also requires an `Idempotency-Key` request header of 1..=512 ASCII
bytes. A missing, blank, oversized, or non-ASCII key fails with 422 before
the backend runs.

**The authenticated POST itself is the explicit opt-in to direct-source
intake.** Unlike the connector-driven `/v1/intake/sync` path, which requires
the polled snapshot to carry a configured opt-in label, this route performs
no label check: presenting a valid bearer token with `SubmitIntake` for a
caller-supplied candidate is itself the opt-in.

### Request: `asf.api-intake-request/v1`

The body must set `schema_version` to exactly `asf.api-intake-request/v1`.
Deserialization is strict (`deny_unknown_fields`): any field the schema does
not define — including authority, policy, credential, or acceptance-shaped
fields such as `tenant_id`, `source`, `connector_identity`, `policy_digest`,
`identity_requirements`, or `accepted` — is rejected with 422, not silently
ignored. A credential-shaped value anywhere in the body (a bearer token, a
private key block, a GitHub PAT, or a field name containing a fragment like
`secret`, `password`, or `credential`) is likewise rejected with 422, as is
an unsafe `source_url` (see below) or a bounds failure (`external_id` over
512 bytes, `source_revision` over 1024 bytes, `normalized_priority` outside
`0..=100`, or the canonical snapshot exceeding 1 MiB serialized).

```json
{
  "schema_version": "asf.api-intake-request/v1",
  "repository_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "external_id": "issue-42",
  "source_revision": "rev-abc123",
  "source_url": "https://example.com/issues/42",
  "title": "Fix flaky retry test",
  "objective": "Stabilize the flaky retry test",
  "acceptance_criteria": ["test passes 100 consecutive runs"],
  "non_goals": ["no unrelated refactors"],
  "labels": ["bug", "flaky"],
  "normalized_priority": 3,
  "source_state": "open",
  "assignee": "octocat",
  "source_updated_at": "2026-08-01T12:00:00Z"
}
```

`repository_id`, `external_id`, `source_revision`, `title`, `objective`,
`acceptance_criteria`, `non_goals`, `labels`, `normalized_priority`,
`source_state`, and `source_updated_at` are required. `source_url` (must be a
safe `http`/`https` reference: a recognized scheme, a present host, and no
embedded userinfo) and `assignee` are optional.

Tenant, `source` (`API`), connector identity (`asf-api:v1`), the repository
hint (the resolved `owner/name` for `repository_id`), capture time, and the
audit caller are all server-derived from the configured active tenant, the
route itself, the locked repository row, the server clock, and the
authenticated bearer identity, respectively — none of them are accepted from
the request body.

### Response: `asf.api-intake-receipt/v1`

```json
{
  "schema_version": "asf.api-intake-receipt/v1",
  "idempotency_key": "intake-2026-08-23-001",
  "work_item_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "source_snapshot_id": "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  "content_digest": "sha256:423fa956c78c1e9fe9e63a4911421d032b1116d590578add0d2cf93dbe8a2a50",
  "disposition": "DISCOVERED",
  "state": "DISCOVERED",
  "version": 1,
  "accepted": false
}
```

`work_item_id` and `source_snapshot_id` are typed UUIDs (`WorkItemId` and
`SourceSnapshotId`), serialized as UUID strings. `source_snapshot_id` and
`content_digest` always identify the same candidate snapshot; they are never
reported out of pair. `accepted` reports only the work item's pre-existing
acceptance state at the time of the call — intake never grants acceptance.

### Disposition and HTTP status

| `disposition` | HTTP status | Meaning |
| --- | --- | --- |
| `DISCOVERED` | 201 | A new work item was discovered from this external identity. |
| `UNCHANGED` | 200 | The candidate is already the work item's authoritative content. |
| `READINESS_REQUEUED` | 200 | Pre-acceptance content changed, so readiness was reset and the version bumped. |
| `AUTHORITY_REEVALUATION_REQUIRED` | 200 | Content changed for accepted (or otherwise non-requeueable) work; the existing authoritative snapshot is retained pending operator re-evaluation. |

Only `DISCOVERED` is a creation (201); every other disposition reuses the
existing work item and returns 200.

### Idempotency, conflicts, and retries

- **Exact replay:** repeating the exact same `Idempotency-Key` with the same
  canonical typed/JCS request returns the originally stored receipt and HTTP
  status — including a `DISCOVERED` call, which keeps replaying as 201 even
  after the work item has since moved on. The comparison is over the
  canonicalized (JCS) request, not the raw request bytes, so JSON property
  order does not matter.
- **Key reused for a different request:** the same `Idempotency-Key` with a
  different canonical request body returns 409.
- **Same external identity and revision, different content:** the conflict
  lookup is keyed by `(tenant, source, external_id, source_revision)` —
  repository is not part of that lookup identity. If that key already has an
  immutable snapshot with a different `content_digest`, the call returns 409
  — a captured source revision's content is immutable. Repository remains
  part of the canonical content that is digested, so a changed
  `repository_id` for the same revision is itself a content change and
  conflicts under this same rule.
- **Semantic duplicate under a new key:** if the exact same canonical
  snapshot (same tenant, repository, content, digest, and connector
  identity) was already captured, the call adopts the existing immutable
  snapshot row instead of erroring, even under a different
  `Idempotency-Key`.
- **Repository not usable:** an inactive, foreign-tenant, or nonexistent
  `repository_id` returns 404.
- **Pre-acceptance change:** when the work item has not been accepted and
  its state allows requeueing, a changed revision resets readiness
  (`READINESS_REQUEUED`) and bumps the aggregate version.
- **Accepted work:** an accepted candidate retains its current authoritative
  snapshot and authority. The call never overwrites it, and every retry
  against changed content for that work item keeps returning
  `AUTHORITY_REEVALUATION_REQUIRED` until an operator resolves it out of
  band.

### Durable event envelope

Each new semantic disposition other than `UNCHANGED` — the first time a
given `(tenant, work item, candidate content)` produces a `DISCOVERED`,
`READINESS_REQUEUED`, or `AUTHORITY_REEVALUATION_REQUIRED` outcome — writes
exactly one durable `outbox` row, and that row *is* the event envelope; there
is no separate publisher-facing representation to keep in sync. An exact
replay of an already-claimed idempotency key, or a fresh key/caller that
adopts an already-recorded semantic event, writes no new row: it reuses the
existing one and never mutates it.

**This release persists the fact only; it does not deliver it.** The written
row is inserted with `outbox.status = 'PENDING'` and
`outbox.available_at = clock_timestamp()` (both column defaults), which
marks it immediately eligible for a publisher to claim. No such publisher
exists yet for these source-intake event types in this release: there is no
at-least-once external delivery, and no subscriber contract. Durable
persistence of the fact is the only guarantee this route makes today.

- `outbox.id` is the event's identity (`event_id`). It is a fresh UUID minted
  at insert time, not derived from the request or the idempotency key.
- `outbox.topic` is always `work-items`, and `outbox.message_key` is the
  work item's ID (`work_item_id`), formatted as a UUID string.
- `outbox.event_type` is one of `WORK_ITEM_DISCOVERED`,
  `WORK_ITEM_READINESS_REEVALUATION_REQUESTED`, or
  `WORK_ITEM_SOURCE_REEVALUATION_REQUIRED`.
- `outbox.idempotency_key` is a semantic key, not the caller's
  `Idempotency-Key`: `source-intake:{discovered|readiness|authority-
  reevaluation}:{work_item_id}:{content_digest}`. It is what makes a
  replay or a fresh-key/fresh-caller adoption resolve to the same row rather
  than inserting a duplicate.
- `outbox.created_at` is the row's ingestion time (when this server accepted
  and durably recorded the event), not when the underlying source change was
  captured.
- `outbox.payload` (schema `asf.work-item-source-event.v1`) carries the
  stable event semantics: `event`, `tenant_id`, `work_item_id`,
  `aggregate_version`, the source identity and candidate fields
  (`source_system`, `source_external_id`, `source_snapshot_id`,
  `source_revision`, `content_digest`), `retained_authority_snapshot_id`,
  `occurred_at`, and `policy_digest`.
  - `aggregate_version` is the work item's version after this event's
    effect — the post-discovery/requeue version for `DISCOVERED` and
    `READINESS_REQUEUED`, or the unchanged current version for
    `AUTHORITY_REEVALUATION_REQUIRED`. An authority-reevaluation event never
    bumps the work item's version merely to be emitted.
  - `occurred_at` is the candidate snapshot's persisted
    `source_snapshots.captured_at` — the value stored on first write for that
    immutable row — never the current call's (or a retry's) wall-clock time.
  - `policy_digest` is `null` for `DISCOVERED` and `READINESS_REQUEUED`, and
    the retained work item's policy digest for an accepted (or otherwise
    non-requeueable) `AUTHORITY_REEVALUATION_REQUIRED` event, where one
    exists.
  - Accepted-work source-change events carry no attempt, Work Order, or run
    ID anywhere in the envelope. Intake never creates or changes execution or
    acceptance authority (see Scope below), so there is no such ID to carry.
- `outbox.headers` (schema `asf.work-item-source-event-headers.v1`) carries
  immutable first-writer provenance: `actor_type` (`SYSTEM` or
  `API_CALLER`), `actor_id`, `correlation_id` (the claiming idempotency
  record's ID), a `trace_id` that is always `null` today, and a
  `policy_digest` mirrored from the payload field of the same name.
  - **`trace_id` is a known current limitation, not merely an unused field.**
    The PRD calls for a propagated trace ID on emitted events; this release
    always stamps `null` because no trace context is threaded into intake
    yet. Consumers must not treat `null` as a semantically meaningful trace
    ID.

Consumers should dedupe on `outbox.id` (the event ID) together with
`payload.aggregate_version`, and should treat `outbox.created_at` as
ingestion time, not event-occurrence time — use `payload.occurred_at` for
the latter.

**First-writer semantic adoption.** Outbox rows are inserted through the
same exact-semantics idempotency path as everything else in this route: a
conflict on `(tenant_id, idempotency_key)` still requires the exact same
topic, message key, event type, and payload as the attempted write. What is
new is headers: on that conflict, this route validates that the *stored*
headers are a well-formed envelope (the exact schema, nonblank
`actor_type`/`actor_id`/`correlation_id`, a `null` `trace_id`, and a
`policy_digest` equal to the stored payload's), and if so adopts them
as-is — it never compares them against, or overwrites them with, the
currently attempted caller's provenance. This is why the discovery event's
headers keep citing the original caller and correlation ID even after a
later call for the same semantic event arrives under a different
`Idempotency-Key` or a different authenticated caller. Malformed stored
headers, or a stored payload that no longer matches byte-for-byte, fail
closed with 409 rather than silently adopting or overwriting the row; the
existing row itself is never mutated either way.

### Scope

Intake is discovery only. A call to this route creates no acceptance or
execution authority: it never creates an attempt, Work Order, run,
reservation, workflow, job, timer, approval, or other external effect. It
only ever persists immutable source snapshots and audit/outbox facts, and,
where applicable, updates a work item's candidate snapshot and readiness
state.

For a material change to already-accepted work, the route retains the
existing authoritative source snapshot rather than overwriting it, and opens
one owned source re-evaluation escalation. That escalation records an
existing obligation — that an operator must reconcile the retained authority
against the changed candidate — and grants no new execution authority of its
own.

This endpoint records the re-evaluation requirement; it does not itself
prove or implement the PRD-wide dispatch pause that a source change on
accepted work is expected to trigger. That scheduler/dispatch fence is
qualified separately from this route.

`objective` is the normalized direct-source description of the work. Direct
intake v1 has no comment or attachment fields, so policy-enabled comments
and attachments are not captured by this endpoint.

This route alone does not mean the later API-source closure / verified-
delivery loop is implemented. Direct intake and source closure are
independent capabilities, and the existence of this route makes no claim
about the other.

## Queueing mutations and activity authority

The PostgreSQL API backend receives an opaque capability snapshot minted from
the exact ready handlers installed in the same process. A queueing endpoint
cannot assert readiness independently. The six queueing routes require:

| Route | Required ready activity |
| --- | --- |
| `POST /v1/intake/sync` | unscoped `INTAKE_SYNC` |
| `POST /v1/work-items/{id}/accept` | unscoped `ADVANCE_ACCEPTED_WORK_ITEM` |
| `POST /v1/work-items/{id}/cancel` | none for `ACCEPTED` work with no attempt; otherwise `REQUEST_WORK_ITEM_CANCELLATION` for the live authoritative run's exact worker |
| `POST /v1/approvals/{id}/decision` | unscoped `APPLY_SIGNED_APPROVAL_DECISION` |
| `POST /v1/workers/{id}/reconcile` | `RECONCILE_WORKER` for the requested exact worker |
| `POST /v1/evidence/{id}/verify` | unscoped `VERIFY_EVIDENCE` |

Each route validates and claims idempotency first. If the same request already
has a completed receipt, the API returns that receipt even when the activity
has since become unavailable. Otherwise, any route that would create a queue
obligation applies the exact target capability check before its aggregate
mutation or workflow-job insertion; a rejected claim rolls back with the
transaction. Cancellation of `ACCEPTED` work with no current attempt instead
locks the work item, pristine delivery workflow/job, accountability anchor, and
monotonic dispatch-fact guard without waiting. The guard serializes the absence
of every dispatch-producing child row, so a concurrent attempt, timer,
reservation, Work Order, effect, run, or other dispatch fact cannot appear as a
phantom after the negative proof. In one transaction ASF cancels the sole
advance job and workflow, changes the work item, emits exact audit/outbox and
idempotency facts, updates the anchor, and stores an immutable `PRE_DISPATCH`
terminal receipt binding their IDs, versions, fences, canonical request/state
digests, and guard generation. Once that receipt commits, both the guard and
the absence proof are frozen. A lock conflict fails closed and is retried by
the caller; it is never treated as proof that dispatch has not started.

Once a live authoritative Runmill run exists, cancellation reads and locks
that run only to discover its exact worker route before applying the
queue-target gate. It does not create a cancellation workflow or mutate the
work item first. The worker activity persists the stable cancellation request
and its first `INITIAL` observation before later observer claims may extend the
same workflow to arbitrary depth, one monotonic `OBSERVER` at a time. The
deterministic observer obligation may move through normal pending, claim,
retry, and dead-letter states, but it cannot be changed directly to
`CANCELLED` until an immutable terminal receipt cites an `OBSERVER` from that
exact effect/run/workflow chain. A terminal job result includes the observation
and terminal receipt identifiers; nonterminal results do not claim terminal
completion.

For `ESCALATED` work, a fresh cancellation request is accepted only when the
current attempt's exact active `WORKFLOW_JOB_EXHAUSTED` escalation owns the
accountability anchor and no competing escalation exists. The transaction
terminalizes that owner, preserves every immutable `DEAD` job, enqueues the
replacement cancellation job, swaps the anchor, and records trigger-captured
OLD/NEW facts plus an append-only supersession receipt. Other escalation
categories and attempt-less exhaustion are conflicts, not implicit recovery.

A terminal Runmill transaction binds each released `reservation_sets` row to
that exact receipt through `cancellation_terminal_receipt_id`. The deferred
foreign key requires release and receipt to commit together, and the reserved
`runmill-cancellation:v1:{work}:{attempt}:{set}:fence:{prior}` transition key
cannot be used without that binding. For a `CANCELLED` outcome, the receipt
also advances and freezes the exact generation in
`work_cancellation_authority_guards`. Verified source closure freezes a
mutually exclusive reference in that same row. Every later guarded
work-scoped insert, even a terminal-looking one, and every reactivation or
binding move must advance the same unfrozen row and therefore fails. A
`TERMINAL_CONFLICT` receipt carries no authority generation and leaves the
waiting workflow and owned escalation available for normal remediation.

The production server registers `VERIFY_EVIDENCE` only when `CLOSE_SOURCE` is
also ready. This is stricter than the API's immediate queue target because a
valid verification creates a source-closure obligation in its terminal
transaction.

`GET /readyz` first checks the configured active tenant and the three core
tables `workflow_jobs`, `idempotency_records`, and `audit_events`. It then
groups every live `PENDING`, `RETRY`, or `RUNNING` job of the nine recognized
production types. Unscoped jobs are compared by exact job type and persisted
activity contract identity; `RECONCILE_WORKER`, `REQUEST_WORK_ITEM_CANCELLATION`,
`OBSERVE_RUNMILL_RUN`, and `RETAIN_RUNMILL_TERMINAL_EVIDENCE` are additionally
scoped by exact `worker_id`. HTTP 503 reports a count for each
unsupported type/contract/route. HTTP 200 with an empty unsupported backlog
remains possible when handlers are unavailable, and does not constitute an
external dependency, migration, or complete-schema readiness proof. This
job-type/contract/worker match is process-local, not a durable global reactor
capability lease, and no unserviceable-obligation scanner exists yet, so it is
not a production-readiness proof.

## `/v1/attention` record identity

The attention collection is a single ordered queue over two durable record
types. Its V1 representation uses an additive discriminator rather than a new
route:

- `kind: "ESCALATION"` has a real `work_item_id` and a null
  `workflow_job_id`;
- `kind: "OPERATIONAL_INCIDENT"` has a real `workflow_job_id` and a null
  `work_item_id`.

`id` remains the same UUID string that earlier V1 responses returned, but the
Rust response type uses `Uuid` rather than falsely claiming every value is an
`EscalationId`. `kind` and `workflow_job_id` are additive fields; all existing
field names and encodings remain unchanged. No synthetic work-item UUID is
created for tenant-scoped incidents. Clients should discriminate on `kind`
and verify the corresponding association field instead of inferring record
type from a null value.

Resolved and cancelled incidents are historical ownership records and do not
appear in active attention. The read fails closed for incomplete open or
acknowledged records and for genuinely unowned active obligations. PostgreSQL
requires each incident to be reciprocally linked by its exact tenant-scoped,
fully unbound `DEAD` job, so a job whose linked incident was validly closed
remains historically covered.

Lifecycle mutation is fenced by the incident's expected aggregate version.
Each successful transition atomically stores an immutable semantic-request
receipt, appends a hash-linked audit fact, and writes an outbox event using the
same database timestamp as the state change. Repeating the exact request
returns the original receipt snapshot even after a later transition; reusing
that version with a different actor, action, or resolution conflicts. The
database rejects a lifecycle update at commit unless a matching receipt with
foreign-key-backed audit and outbox records exists. The proof checks every
emitted audit/outbox semantic field, the outbox's unpublished initial state,
and database-reconstructed canonical request, before/after lifecycle, and
audit-event hashes—not merely the receipt foreign keys.

This is currently a Rust ledger/controller contract. V1 HTTP exposes incident
records through `GET /v1/attention`, but it does not yet expose an operational-
incident transition route; operators must not substitute direct SQL.
