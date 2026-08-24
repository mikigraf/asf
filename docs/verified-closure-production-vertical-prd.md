# PRD: Production Verified-Closure Vertical

- **Project:** Autonomous Software Factory (ASF)
- **Status:** Proposed implementation contract
- **Date:** 2026-08-22
- **Target release:** First externally usable PR-closure control plane
- **Owners:** ASF maintainers
- **Execution dependency:** Production-qualified Runmill worker
- **Identity dependency:** Production-qualified ctxlane automation identity plane, consumed by Runmill

## 1. Executive summary

ASF already contains a rigorous durable control-plane foundation. It models accepted work as an obligation, keeps authority outside models, persists jobs and timers in PostgreSQL, fences workers, records immutable Work Orders and effects, verifies signed evidence, preserves cancellation chains, and requires every accepted item to retain a live accountability anchor.

The repository is intentionally fail-closed because the production path is incomplete. This PRD defines the smallest complete production vertical that turns the existing foundation into an externally usable system.

The product promise is:

> Once ASF explicitly accepts a bounded engineering task, it remains responsible until it produces a verified pull request and closes the source item, or creates an owned, actionable escalation that preserves the obligation and exact evidence.

The first release does not attempt to be a general autonomous software factory. It proves one narrow obligation-to-closure path under crashes, response loss, provider ambiguity, identity failures, evidence tampering, and operator intervention.

## 2. First production slice

### Supported

- one tenant;
- Linux deployment;
- PostgreSQL as authoritative state;
- authenticated API intake as the minimal required intake path;
- optional existing Linear intake/closure when configured and externally qualified;
- one GitHub repository per Work Order;
- one active attempt per work item;
- PR-only closure target;
- bounded maintenance work with explicit acceptance criteria and path scope;
- one registered Runmill worker route;
- explicit implementer, local-reviewer, and PR-reviewer identities;
- Runmill-controlled coding, verification, review, and GitHub PR effects;
- ctxlane-controlled provider identity leases inside Runmill;
- S3-compatible content-addressed artifact storage;
- signed Work Orders, Runmill attempt evidence, and ASF closure evidence;
- durable cancellation, approval, reconciliation, and owned escalation;
- OpenTelemetry export;
- independently verifiable closure packs.

### First qualification workload

Use a bounded single-repository backend maintenance or internal API-migration task with:

- no dependency-manifest changes;
- no authentication/authorization changes;
- no database migrations;
- no infrastructure or workflow changes;
- no merge/deploy authority;
- deterministic local tests and required GitHub CI;
- exact source and test path allowlists;
- an acceptance oracle that is not visible as editable success criteria to the implementer.

The workload is a qualification fixture and first design-partner scope, not ASF's permanent category boundary.

### Explicitly unsupported

- merge, deploy, and post-deploy observation targets;
- multi-repository transactions;
- multi-tenant SaaS;
- arbitrary backlog connectors;
- work without a credible specification/acceptance oracle;
- production database, incident-response, authentication, billing, or infrastructure changes;
- worker control over ASF acceptance, identity policy, merge, or source closure;
- coding-worker access to ctxlane, Runmill administration, ASF control, GitHub credentials, or artifact signing keys.

## 3. Verified repository baseline

### 3.1 Implemented durable core

The repository currently includes:

- typed work, attempt, approval, authority, identity, escalation, and accountability domains;
- canonical JSON, SHA-256, Ed25519 Work Order and evidence contracts;
- forward-only PostgreSQL migrations;
- durable jobs, timers, leases, fence tokens, outbox, effect intents, reservations, budgets, circuit breakers, audit, and accountability anchors;
- exact Runmill control contracts and source checks against the adjacent Runmill repository;
- authenticated API/CLI surfaces;
- a DB-backed reactor with claim/reclaim, retry, dead-letter, and reservation-expiry handling;
- optional Linear intake/source closure;
- optional GitHub evidence observation;
- optional Runmill cancellation, worker-health reconciliation, and bounded read-only V2 observation streams for explicitly installed authoritative runs;
- strict evidence verification and artifact-manifest integrity;
- exact pre-dispatch cancellation proof;
- arbitrary-depth Runmill cancellation observation chains and terminal receipts;
- owned escalations and operational incidents for exhausted work;
- twelve incident runbooks.

### 3.2 Honest current limitations

The repository's own P0 audit correctly marks ASF not production-ready for autonomous dispatch.

Missing or incomplete production paths include:

- accepted-work advance and dispatch;
- Work Order v2 compilation/signing;
- safe adoption after Runmill submission response loss;
- a supported stream-adoption/install workflow, projection/reducer, and observation-to-evidence handoff (durable terminal-failure facts now recover ordinary exhausted observer jobs without inventing remote observation evidence);
- signed approval application;
- signed evidence ingestion;
- artifact-byte ingestion/retrieval and production object storage;
- Runmill outcome acknowledgement;
- exact attempt-scoped identity readiness/attribution;
- OTLP export;
- external Linux failure qualification.

### 3.3 Current working-tree baseline

The current implementation has a durable V2 observation stream: an explicitly installed authoritative stream produces one cursor/session-bound checkpoint at a time; normal pages persist exact control provenance and advance the cursor, terminal final pages become `TERMINAL_READY`, and retained compaction gaps force an owned dead-letter escalation without advancing the cursor. The run-admission session remains immutable while the producer records a currently live observer session for each checkpoint, so session rotation is explicit and fenced. This is a development baseline only: retained observation is not a projection or evidence decision, and the repository still lacks stream adoption/install, a reducer/evidence handoff, the complete locked migration/upgrade matrix, external Runmill/ctxlane/provider failure coverage, and production readiness. Durable terminal-failure facts now recover ordinary exhausted observer jobs without inventing remote observation evidence.

### 3.4 Cross-product contract blockers

- Runmill's current ctxlane client does not match ctxlane's published lease request/response schemas.
- Runmill requires an external executable runtime composition instead of shipping a complete first-party worker composition.
- Production Runmill control cannot recover a lost successful submit response by Work Order idempotency key plus expected digest.
- Strict Work Order v1 lacks several authority inputs needed by ASF's own P0 audit.

ASF must remain fail-closed until those contracts are fixed and versioned.

### 3.5 Activity contract binding

Every durable job/timer type carries an immutable, per-request `activity_contract_id` (migration 0023) pinning it to one exact activity implementation identity, distinct from its job/timer type. The reactor's claim, orphan-recovery, route-invalid, and timer-promotion queries, the `HandlerRegistry`/`ReadyClaimSet` route model, and the `/readyz` obligation scan all require this exact type-plus-contract pair — a due job or timer bound to a recognized type but an incompatible contract fails closed rather than being claimed, dead-lettered as merely route-invalid, or reported ready. This closes the local, single-process serviceability and execution decision. It does **not** provide durable, cross-process reactor capability leases, nor an unserviceable-obligation scanner that proactively surfaces stuck contract-incompatible work; both remain absent. This is an internal-consistency guarantee, not a production-readiness claim — see §3.2.

## 4. Product goals

### G1. Durable accepted obligation

After `ACCEPTED`, every state has either a runnable durable next activity, a durable timer, a pending approval, an explicit dependency wait, a cancellation path, a verified closure path, or an owned escalation with deadline and required action.

### G2. Complete PR closure

ASF compiles and signs the Work Order, dispatches exactly one logical Runmill attempt, observes it through terminal evidence, independently verifies the result, closes the source, acknowledges the evidence, and records a portable closure pack.

### G3. No blind retries

Every ambiguous external mutation is represented by one immutable effect intent. Recovery observes and adopts the effect or proves it did not happen before attempting it again.

### G4. Identity-bound authority

ASF signs the maximum role/profile authority into the Work Order. Runmill acquires and manages ctxlane leases. ASF never receives provider credentials, lease capabilities, execution handles, or vendor-home paths.

### G5. Verifiable evidence

An independent verifier can validate the closed obligation from signed Work Order through exact Runmill candidate evidence, source closure, acknowledgement, and the final audit span.

### G6. Measurable reliability

The release produces public or design-partner evidence for recovery, duplicate-effect prevention, identity binding, verified closure, human intervention, cost, and time to closure.

## 5. Non-goals

ASF will not, in this release:

- execute repository code;
- hold model-provider credentials;
- start arbitrary binaries on workers;
- expose privileged MCP tools to coding agents;
- select a global ctxlane profile or acquire leases directly;
- infer acceptance from intake;
- infer success from a Runmill terminal label without independent evidence verification;
- silently retry a lost submission or GitHub/Linear mutation;
- equate escalation with closed work;
- close a source item before the exact PR evidence is verified;
- auto-merge or deploy;
- promise deterministic replay of LLM execution;
- benchmark agents against humans as the first product proof;
- add more source systems before the first vertical is qualified.

## 6. Users and jobs

### Work owner

Submits or approves a bounded task, sees whether ASF accepted the obligation, follows progress, and receives either a verified PR or a clear escalation with owner, deadline, evidence, and required action.

### Platform operator

Registers workers and repositories, configures signing/trust, policies, budgets, source/GitHub/object-store adapters, breakers, maintenance mode, retention, and observability.

### Approver

Issues candidate- and policy-bound decisions at explicit checkpoints without obtaining worker or provider credentials.

### Reliability/security operator

Needs exact reconstruction, incident ownership, cancellation, quarantine, key rotation, and proof that stale workers or identities could not continue.

### External auditor or verifier

Validates the portable closure pack using public trust policy, signed artifacts, and immutable digest references without accessing prompts, credentials, or private provider state.

## 7. Product boundaries

| Concern | Owner |
| --- | --- |
| Intake snapshot and explicit acceptance | ASF |
| Work readiness, policy, risk, budgets, closure target | ASF |
| Work Order v2 construction and signature | ASF |
| Attempt scheduling and worker assignment | ASF |
| One repository delivery attempt | Runmill |
| Provider identity lease and harness | ctxlane, called by Runmill |
| Exact-candidate checks/reviews and PR effects | Runmill |
| Signed attempt and cleanup evidence | Runmill |
| Independent evidence verification | ASF |
| Source closure | ASF |
| Final closure pack or owned escalation | ASF |

## 8. End-to-end state model

The implementation should preserve existing `WorkItemState` values rather than introduce a parallel workflow vocabulary.

The primary success path is:

```text
DISCOVERED
  -> READINESS_PENDING
  -> READY
  -> ACCEPTED
  -> PLANNED/SCHEDULED
  -> DISPATCHING
  -> RUNNING
  -> VERIFYING_OUTCOME
  -> TARGET_REACHED
  -> CLOSING_SOURCE
  -> CLOSED
```

Supported controlled side paths include:

```text
WAITING_DEPENDENCY
WAITING_APPROVAL
RETRY_SCHEDULED
BLOCKED_EXTERNAL
BUDGET_EXHAUSTED
QUARANTINED
CANCEL_REQUESTED -> CANCELLED
ESCALATED
```

`ESCALATED` is not successful completion. It is an owned continuation of the accepted obligation. It must preserve an active accountability anchor and may return to a legal workflow state only through an explicit fenced operator action.

## 9. Cross-project contracts

### 9.1 Work Order v2

ASF is the canonical author/signing owner of `asf.work-order/v2`; Runmill is the strict consumer. Both repositories must share fixtures, signing vectors, and canonical digests.

V2 must bind:

- tenant, work item, Work Order, attempt, and stable idempotency key;
- source system, external ID, exact immutable snapshot reference/digest, and source timestamp;
- forge, repository, base ref, exact base SHA, and repository-policy digest;
- objective, acceptance criteria, non-goals, and optional planner artifact digest;
- allowed/forbidden paths;
- risk class, reasons, and matched policy rules;
- local checks, remote CI, review policy, and verification-policy digest;
- command/tool, sandbox, network, dependency, harness, and runtime policy digests;
- implementer/local-reviewer/PR-reviewer immutable ctxlane profile UIDs and aliases;
- per-role ctxlane Work Order authorization or an exact canonical signed reference;
- budgets for time, cost, invocations, fixes/reviews, artifacts, and external effects;
- PR-only delivery authority;
- validity interval, signer key ID, algorithm, payload digest, and envelope digest.

V1 remains read-only/fixture-compatible where necessary. Production dispatch requires v2.

### 9.2 Runmill control

ASF requires exact operations for:

- negotiate capabilities;
- submit Work Order;
- find run by run ID;
- find run by idempotency key plus expected Work Order payload/envelope digest;
- list events after a run-bound cursor;
- get signed evidence and artifact manifest;
- request cancellation;
- record signed approval;
- request reconciliation;
- acknowledge exact evidence outcome;
- health/readiness.

MCP may expose these operations for trusted local composition, but ASF's reactor uses the same semantics through a bounded authenticated local control client. Durability remains in PostgreSQL and Runmill's worker state, not in an open MCP call.

### 9.3 ctxlane identity

ASF validates and signs non-secret identity requirements. Runmill consumes ctxlane's canonical schemas and owns lease lifecycle.

ASF may receive only:

- configured profile UID and display reference;
- provider, role, environment, repository/workspace references;
- readiness class and freshness;
- non-secret principal/workspace attribution where policy allows;
- lease-attribution digest;
- harness/isolation/policy digest;
- issue/expiry/terminal timing and disposition in evidence.

ASF must never receive provider credentials, credential paths, provider homes, lease IDs, execution handles, or privileged ctxlane channels.

### 9.4 Closure evidence

ASF owns a new strict `asf.closure-evidence/v1` envelope. It references rather than duplicates protected artifacts and binds the full obligation lifecycle.

The pack must include or digest-reference:

- immutable accepted source snapshot;
- acceptance receipt and accountability anchor;
- exact signed Work Order v2;
- Runmill worker registration/session/generation;
- Runmill signed attempt evidence;
- Runmill signed terminal cleanup evidence;
- ASF independent evidence-verification receipt;
- artifact manifest and retention/access classes;
- source-close effect intent, observation, reconciliation, and terminal receipt;
- Runmill outcome acknowledgement receipt;
- reservation/budget release summary;
- audit-chain start/end/hash proof;
- final WorkItem state/version;
- closure timestamp and authority;
- explicit coverage/unknown fields.

The closure pack is independently verifiable. It does not claim deterministic replay of agent execution.

## 10. Functional requirements

### ASF-PROD-001: Restore a green baseline

Before enabling any new production activity:

- confirm the current green Rust baseline remains reproducible;
- pass formatting, Clippy, and all locked tests;
- run migrations from an empty database and a representative prior schema;
- ensure the repository tracks all intended source, migration, contract, and test files;
- record the exact commit used for qualification.

No production claim may rest on an untracked or non-reproducible working tree.

### ASF-PROD-002: Minimal authenticated intake

The minimal required vertical begins with authenticated API intake of an immutable source snapshot. Linear may be enabled as an adapter, but it is not required to prove the core control loop.

Intake must:

- store source content/digest/provenance immutably;
- never imply acceptance;
- create no execution authority;
- be idempotent and source-version aware;
- reject tenant/repository ambiguity;
- preserve exact replay.

### ASF-PROD-003: Readiness and explicit acceptance

Readiness evaluates:

- complete specification and acceptance criteria;
- supported PR-only target;
- registered repository and exact base;
- risk and allowed workload class;
- frozen policy and repository-policy digest;
- required checks/reviews;
- budget validity and available capacity;
- three explicit identity requirements;
- registered Runmill worker capability and freshness;
- ctxlane non-secret profile/readiness compatibility reported through the worker preflight;
- owner fallback and escalation route.

Acceptance is an explicit authenticated decision. It atomically creates or confirms:

- `ACCEPTED` state;
- one delivery workflow and runnable next job;
- accountability anchor;
- idempotency, audit, and outbox facts;
- no provider, worker, or GitHub effect yet.

### ASF-PROD-004: Work Order compilation and signing

The `ADVANCE_ACCEPTED_WORK_ITEM` activity compiles v2 from immutable authoritative data, not mutable request content.

Before signing it must lock and verify:

- work item and attempt generation;
- exact source snapshot;
- repository/base observation;
- current frozen policy and risk;
- identity requirements;
- budgets and reservations;
- worker assignment/generation;
- no cancellation/finality conflict.

Signing occurs through a dedicated signer interface. Private keys are not stored in ordinary database rows, workflow payloads, logs, or worker-visible configuration.

The signed envelope and digests are immutable. Any authority-bearing change creates a new attempt and signature.

### ASF-PROD-005: Atomic admission and reservations

Before dispatch, ASF atomically reserves:

- repository WIP;
- worker slot;
- identity capacity declarations;
- all configured budget dimensions;
- attempt ownership generation.

The reservation set is bound to the exact work, attempt, worker, Work Order, and fence. Expiry releases budgets through the existing durable reservation sweep and creates the next owned state; it never silently makes the work selectable again.

### ASF-PROD-006: Durable Runmill submission

Submission follows:

```text
persist immutable Work Order
  -> persist submission intent and owning job/fence
  -> call Runmill submit
  -> persist accepted/existing receipt
```

If the response is lost:

1. never generate another idempotency key;
2. query Runmill by the original key plus expected payload/envelope digest;
3. adopt exactly matching existing run authority;
4. conflict/quarantine mismatched or ambiguous results;
5. retry submission only after Runmill proves the logical effect was not applied.

Successful adoption atomically binds run ID, worker ID/generation/session, attempt, Work Order, submission intent, receipt, event cursor, audit, and accountability anchor.

### ASF-PROD-007: Run/event observation

Implement a production reactor activity that:

- reads events from the durable run-bound cursor;
- validates strict sequence, event digest, worker/session/generation, policy, candidate, and phase monotonicity;
- stores raw normalized events immutably;
- advances the WorkItem/Attempt projection atomically;
- persists the next observer job/timer before completion;
- handles cursor compaction through an exact trusted snapshot;
- reconnects after ASF/Runmill restart;
- rejects another worker/session occupying a run sequence;
- maps every Runmill stop to a bounded ASF action, retry, approval, quarantine, cancellation, or escalation.

### ASF-PROD-008: Approval handling

Wire the existing signed approval domain into a production handler.

Approval must bind:

- tenant/work/attempt/run;
- exact candidate SHA;
- policy and Work Order digests;
- requested effect/checkpoint;
- approver subject/role;
- issued/expiry times;
- idempotency key and signature.

A changed candidate or policy invalidates the approval. Approval can grant only authority already permitted by the Work Order and operator policy.

### ASF-PROD-009: Evidence ingestion and artifact storage

When Runmill reports final evidence availability:

1. retrieve the exact signed attempt and terminal bundles;
2. retrieve referenced artifact bytes through an authenticated bounded channel;
3. stream-verify digest and size before commit;
4. store bytes in encrypted S3-compatible content-addressed storage;
5. persist immutable artifact metadata, producer, encryption/retention/access class, and object version/etag;
6. freeze the exact manifest used by verification;
7. reject missing, changed, duplicate-contradictory, oversized, or credential-shaped portable content;
8. schedule independent verification.

The current local filesystem reader remains development-only. MinIO may qualify the protocol locally; production requires the operator-selected durable S3-compatible deployment, backup, access logging, and restore test.

### ASF-PROD-010: Independent evidence verification

The verifier must not trust Runmill's terminal label alone. It verifies:

- Work Order signature, validity, payload/envelope digest, and v2 authority;
- registered worker evidence signer and validity/revocation window;
- run/attempt/worker/session/generation identity;
- exact base/candidate/remote-head/PR relationship;
- policy and repository-policy digest;
- required local checks and CI at the candidate SHA;
- required independent reviews and candidate binding;
- confirmed GitHub effects and absence of unresolved effects;
- non-secret ctxlane attribution and isolation evidence for every role;
- budgets and conservative unknown usage;
- artifact digest/size/manifest integrity;
- terminal cleanup evidence;
- current read-only GitHub observation of PR/head/check state.

Every verification outcome creates a strict immutable receipt. Missing or unknown evidence is not success.

### ASF-PROD-011: Target reached and source closure

Only a valid evidence-verification receipt may move the item to `TARGET_REACHED` and enqueue `CLOSING_SOURCE`.

Source closure uses one immutable effect intent and stable correlation marker. On response loss it observes before retry. Closure must confirm the source item and target state exactly, without trusting transport success.

For authenticated API intake, source closure may be an internal immutable closure receipt exposed by the API. For configured Linear intake, it is the existing authenticated Linear effect and reconciliation path.

### ASF-PROD-012: Runmill outcome acknowledgement

After evidence verification and source closure, ASF sends an idempotent acknowledgement bound to:

- run ID;
- Work Order/attempt;
- evidence bundle digest;
- ASF verification receipt;
- source closure receipt;
- acknowledgement authority and idempotency key.

Response loss is reconciled through Runmill's run/evidence state. An acknowledgement cannot change or invalidate evidence.

### ASF-PROD-013: Closure transaction and pack

`CLOSED` requires one transaction or database-enforced chain that proves:

- verified target evidence;
- terminal source closure;
- Runmill acknowledgement;
- no live attempt authority, job, timer, effect, approval, reservation, or cancellation conflict;
- budgets released/settled;
- accountability anchor moved to the immutable closure receipt;
- outbox and audit facts created;
- closure evidence manifest frozen.

The signed closure pack may be finalized after the database closure transaction only through a durable intent whose missing artifact keeps an explicit incomplete-evidence alert. A `CLOSED` API response must state whether the portable pack is finalized; production success metrics count only `CLOSED + pack_verified`.

### ASF-PROD-014: Owned escalation guarantee

Every exhausted, unsupported, contradictory, or ambiguous accepted-work path must produce or conservatively merge exactly one active escalation owner while preserving all contributing dead jobs/effects.

An escalation contains:

- owner and fallback owner;
- severity;
- deadline/SLA;
- required actor and action;
- retry policy and whether new authority is required;
- prerequisites;
- exact evidence references;
- active authority/effect state;
- before/after transition receipt;
- idempotency and fence version.

No accepted item may remain in an unsupported queue state without appearing in attention. `/readyz` serviceability detection must be complemented by a durable scanner that converts existing unclaimable accepted obligations into owned attention without fabricating execution authority.

### ASF-PROD-015: Cancellation

Preserve the existing distinction:

- exact synchronous `PRE_DISPATCH` cancellation when the monotonic guard proves dispatch never began;
- Runmill cancellation with immutable `INITIAL`/`OBSERVER` chain after an authoritative run exists.

Cancellation must also ensure:

- Runmill has revoked/closed ctxlane leases;
- no stale worker generation can continue;
- remote GitHub effects are reconciled;
- reservations are released only under exact terminal receipt;
- terminal conflict remains an owned escalation rather than false cancellation.

### ASF-PROD-016: Observability and SLOs

Export OTLP traces, metrics, and structured logs with correlation:

```text
tenant -> source snapshot -> work item -> attempt -> Work Order
       -> submission effect -> Runmill run -> event -> evidence
       -> source closure -> acknowledgement -> closure pack
```

Required metrics:

- count and age by WorkItem state;
- accepted obligations without serviceable next activity;
- queue/lease/reconciliation lag;
- worker heartbeat/generation/capacity;
- submission adoption and ambiguity;
- event cursor lag and gaps;
- verification success/failure by stable code;
- source-close ambiguity;
- active escalations and SLA breach;
- reserved/settled/unknown cost;
- time and cost to verified closure;
- closure-pack finalization/verification;
- duplicate-effect prevention events;
- stale-fence rejections.

No raw source, prompts, model output, credentials, lease handles, signatures/private keys, or unrestricted provider errors enter ordinary telemetry.

### ASF-PROD-017: Operator surfaces

Provide bounded operator commands/APIs for:

- readiness and dependency preflight;
- worker registration/session rotation/quarantine;
- work inspection and complete event/audit reconstruction;
- attention/escalation listing and fenced lifecycle actions;
- cancellation;
- approval submission;
- reconciliation of exact recorded effects;
- breaker/maintenance mode;
- evidence/closure-pack verification;
- key rotation/revocation;
- migration/backup/restore diagnostics.

Direct SQL is not an operational control surface.

## 11. Portable evidence verification

Add a credential-free verifier, proposed as:

```text
asf evidence verify <closure-pack> \
  --trust <public-trust-policy> \
  --artifacts <artifact-root-or-reader> \
  --json
```

The verifier must:

- require strict known schemas;
- verify every signature and key-validity window;
- recompute all canonical digests;
- validate artifact bytes when available;
- traverse Work Order -> Runmill evidence -> ASF verification -> source closure -> acknowledgement -> final state;
- validate audit-chain proofs and accountability anchors;
- reject any inconsistent tenant/work/attempt/run/worker/candidate/policy coordinate;
- report unavailable protected artifacts as coverage gaps, not fabricated failure/success;
- emit a stable decision and machine-readable issue list.

Re-running deterministic tests from the exact candidate may be an optional stronger verification mode. It is not required to validate the signed closure claim and is not called model replay.

## 12. Failure-injection program

### In-process deterministic matrix

Inject failure before and after every durable boundary in:

- acceptance;
- attempt creation;
- reservation;
- Work Order signing/persistence;
- Runmill submission intent/call/receipt;
- run adoption;
- event read/persist/project/cursor;
- approval;
- evidence metadata/byte ingestion;
- artifact manifest freeze;
- verification;
- source close intent/call/observation;
- acknowledgement intent/call/observation;
- finality guard/closure receipt/pack finalization;
- cancellation and escalation lifecycle.

### External qualification matrix

Exercise on a protected Linux deployment:

- ASF process kill/restart;
- PostgreSQL failover/connection loss and restore;
- Runmill kill before/after every attempt checkpoint;
- lost Runmill submission response;
- ctxlane restart, lease expiry, revocation, and generation replacement;
- provider outage, rate limit, timeout, malformed result, and unknown cost;
- GitHub outage, abuse/rate limit, stale PR head, check rerun, and response loss;
- Linear outage and ambiguous source close when enabled;
- object-store timeout, corruption, stale read, and access denial;
- OTLP backend outage;
- clock rollback/forward jump;
- disk full and permission changes;
- worker split-brain/stale generation;
- malicious task/repository content requesting privileged MCP, identity change, credential access, or merge;
- evidence signature/digest/key rotation failure;
- cancellation races with dispatch, terminal evidence, and source closure.

Every case must converge to:

- continued exact attempt;
- a new signed attempt requirement;
- verified closure;
- exact cancellation;
- owned escalation/incident.

No case may create duplicate PRs, lose an accepted obligation, silently reuse ambiguous identity, or mark unverified work closed.

## 13. Qualification evidence and metrics

### Directly controlled reliability metrics

- verified-closure rate;
- accepted items with no accountable next state;
- human-intervention rate;
- owned-escalation rate and reason;
- time to verified PR and time to source closure;
- conservative cost per verified closure;
- crash recovery success and duration;
- duplicate external-effect rate;
- stale-worker rejection rate;
- incorrect identity-binding rate;
- evidence/closure-pack independent verification rate;
- cancellation completion and ambiguity rate;
- acknowledgement lag.

### Do not use initially

Do not lead with “defect rate versus humans.” That comparison requires controlled task matching, credible baselines, sufficient sample size, and independent adjudication. The first proof should measure invariants ASF directly controls.

### Initial release targets

- accepted obligations without closed or owned state: **0**;
- duplicate logical Runmill submission: **0**;
- duplicate branch/PR/source-close effect after response loss: **0**;
- stale worker or identity generation effect accepted: **0**;
- closed item without independently valid evidence: **0**;
- credential/privileged control visible to coding worker: **0**;
- failure-injection case without convergent owned state: **0**;
- closure packs independently validated: **100%**;
- unknown evidence treated as success: **0**.

## 14. Milestones

### M0: Reproducible green baseline

- confirm the current green Rust baseline remains reproducible;
- commit/track intended implementation;
- pass Rust, migration, and PostgreSQL suites;
- record current P0 status from a clean commit.

### M1: Contract freeze

- Work Order v2 and fixtures with Runmill;
- lost-submit lookup;
- ctxlane canonical role authorization references;
- closure evidence v1;
- artifact retrieval/manifest contract;
- cross-repository CI compatibility jobs.

### M2: Dispatch and adoption

- accepted-work activity;
- Work Order compilation/signing;
- reservations;
- Runmill submission intent;
- lost-response lookup/adoption;
- worker/run/session binding.

### M3: Observation, approval, and evidence

- run/event observer and reconnect;
- signed approvals;
- evidence/artifact ingestion;
- S3-compatible storage;
- independent verification.

### M4: Closure and accountability

- target reached;
- source closure;
- Runmill acknowledgement;
- closure transaction/pack;
- unserviceable-obligation scanner;
- complete owned escalation path.

### M5: Operability

- OTLP and dashboards/alerts;
- backup/restore and migration rehearsal;
- key rotation;
- all incident runbooks executable through supported controls;
- SLO/error-budget definition.

### M6: External qualification

- one private acceptance repository;
- one production-shaped Runmill worker and ctxlane service;
- one full success, cancellation, refusal, budget, provider-outage, GitHub-ambiguity, and evidence-tamper scenario;
- complete failure matrix;
- independent security/reliability review;
- immutable qualification report.

### M7: Design-partner proof

- one design partner with a bounded real workload and explicit owner;
- operate the loop on real repository changes;
- capture verified closure, interventions, cost, time, and escalations;
- repeat without bespoke code changes;
- expand to several repositories/partners only after the first deployment is repeatable.

## 15. Acceptance criteria

ASF may enable production dispatch only when all criteria pass:

1. The repository builds and all required tests pass from a clean tracked commit.
2. Work Order v2 is strict, canonical, cross-tested with Runmill, and contains every required authority input.
3. Runmill consumes ctxlane's exact schemas and reports attempt-scoped identity readiness without exposing capabilities.
4. The first-party Runmill worker starts and passes canonical readiness on the target Linux deployment.
5. Acceptance always creates a serviceable next activity and accountability anchor.
6. Dispatch persists reservations, Work Order, submission intent, and owning job/fence before calling Runmill.
7. A lost successful submission response is adopted through idempotency key plus exact digest, with no duplicate run.
8. Run/event observation resumes after ASF and Runmill restarts without gaps, cross-session substitution, or phase regression.
9. Every role has valid non-secret ctxlane attribution bound to the exact attempt and effective policy.
10. Coding workers cannot reach provider credentials, ctxlane/Runmill/ASF control channels, GitHub/source credentials, another workspace, or signing keys.
11. Evidence bytes are authenticated, digest-verified, encrypted at rest, manifest-frozen, and independently verified.
12. A work item cannot reach `TARGET_REACHED` or `CLOSED` from a Runmill status alone.
13. Source closure and Runmill acknowledgement are idempotent and response-loss safe.
14. `CLOSED` has a complete closure receipt, no live authority/effect/reservation, and a finalized or explicitly pending portable pack; only finalized/verified packs count as successful release evidence.
15. Every exhausted or unsupported accepted path appears in attention with one owned escalation/incident and complete evidence references.
16. Cancellation preserves the existing pre-dispatch and Runmill observation-chain proofs and confirms identity cleanup.
17. OTLP metrics and alerts expose stuck obligations, stale workers, ambiguity, evidence failures, and SLA breaches without sensitive content.
18. The full external failure matrix converges without duplicate effects or orphaned obligations.
19. An independent verifier accepts the known-good closure pack and rejects every single-field/signature/artifact tamper fixture.
20. One real private repository task reaches verified PR, source closure, acknowledgement, and independently verified closure pack.

## 16. Rollout policy

### Development

- fakes/local adapters;
- no production dispatch claim;
- synthetic fixtures labelled synthetic;
- maintenance mode available.

### Acceptance environment

- dedicated tenant, repository, worker, ctxlane profiles, provider accounts, GitHub installation/token, object store, and signing keys;
- no customer production repositories;
- failure injection mandatory;
- PR-only, no merge.

### Private pilot

- explicit repository/workload allowlist;
- manual acceptance;
- conservative budgets;
- one active repository task;
- human review before merge outside ASF;
- 24/7 named escalation owner during active runs;
- immediate kill switch and key-revocation path.

### Wider preview

Allowed only after multiple repeatable pilot closures, zero critical invariant failures, successful restore drill, and complete security review. Expanding connectors, merge, deployment, or multi-tenancy requires separate PRDs.

## 17. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Architecture continues expanding without a usable loop | Freeze scope to one authenticated-input, one-repo, PR-only vertical until qualified |
| ASF duplicates Runmill's attempt state | Keep ASF projections/evidence references; Runmill remains authoritative for attempt execution details |
| ASF receives identity capabilities | Runmill alone calls ctxlane; ASF receives only signed/non-secret attribution digests |
| Signed evidence is mistaken for truth | Independently observe GitHub, validate artifacts and cross-bindings, and keep unknown coverage explicit |
| “Replayable” overclaims nondeterministic execution | Make evidence verification deterministic; describe test reproduction separately |
| Escalation becomes a dead-end terminal state | Keep the obligation/accountability anchor live and require owner/deadline/action plus fenced resolution |
| Empty `/readyz` backlog looks production-ready | Add aggregate dependency preflight and dispatch authorization distinct from serviceability |
| Closure pack finalization fails after source close | Persist durable finalization intent, alert, retain artifacts, and distinguish `CLOSED` from `pack_verified` in metrics |
| Source connector delays the first proof | Make authenticated API closure sufficient; qualify Linear as an optional adapter |
| Product is marketed as autonomous merge/deploy | Keep PR-only hard-coded in v1 contracts and readiness |

## 18. Release language

Before every acceptance criterion passes:

> ASF is an implementation foundation for accountable autonomous delivery. Production dispatch remains unavailable.

After qualification:

> ASF turns an explicitly accepted, bounded engineering task into a verified pull request and closed source item—or an owned escalation—with durable recovery and independently verifiable evidence on qualified deployments.

Do not use “fully autonomous software factory,” “exactly once,” “cryptographically proven workload,” or “replayable agent run” as release claims.

## 19. Cross-project delivery order

1. Restore ASF's green tracked baseline.
2. ctxlane publishes complete canonical operation contracts.
3. ASF and Runmill freeze Work Order v2, lookup/adoption, artifact, and closure-pack contracts.
4. Runmill ships its first-party worker and canonical ctxlane integration.
5. ASF wires accepted-work dispatch and lost-response adoption.
6. ASF wires event observation, approval, evidence/artifacts, verification, source closure, acknowledgement, and closure pack.
7. All three repositories execute the external failure matrix.
8. Run the first private acceptance repository, then one design partner.

This sequence makes the integrated vertical the next milestone. No additional control-plane subsystem should pre-empt it unless required to satisfy one of these acceptance criteria.
