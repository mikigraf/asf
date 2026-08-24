# Autonomy evaluation and promotion

ASF evaluates autonomy per exact segment, not per organization, worker, model,
or repository-wide success rate:

```text
(repository_id, work_class, risk_class, closure_target)
```

Evidence from another repository, work class, risk class, or target cannot
qualify the segment. This prevents good low-risk pull-request results from
silently granting authority to high-risk or merge work.

> Release status: `src/application/promotion.rs` is deterministic policy logic.
> ASF does not yet persist these records or enforce effective segment grants in
> acceptance, scheduling, dispatch, or closure. Until those wiring gates exist
> and are tested, operators must not treat a successful in-memory decision as
> production autonomy authority.

## Ladder and authority

The existing autonomy ladder is ordered:

1. `observe`
2. `supervised_pull_request`
3. `automatic_verified_pull_request`
4. `guarded_merge_candidate`
5. `guarded_merge_enabled`

Promotion and rollback move exactly one rung. `guarded_merge_candidate` is an
evaluation-only rung and grants no merge authority. `guarded_merge_enabled` is
categorically unavailable to high- and critical-risk segments, even when all
quality thresholds pass and the repository owner signs the request.

Every promotion expires. Its grant records the immediately previous rung as
the rollback rung. Expiry therefore removes the added authority without
requiring a multi-rung interpretation. A repository owner or operator can also
request an explicit adjacent rollback with an actor and reason.

## Immutable evaluation samples

An evaluation sample is content-addressed with canonical JSON and SHA-256. The
engine recomputes the digest before using a deserialized sample. A changed
measurement, segment, work/attempt reference, identity, or timestamp makes the
sample invalid rather than updating history in place.

Each sample records all PRD quality dimensions:

| Dimension | Representation and promotion treatment |
| --- | --- |
| Correctness | Pass/fail rate with a minimum threshold. |
| Acceptance criteria | Pass/fail rate with a minimum threshold. |
| Scope | In-scope/out-of-scope rate with a minimum threshold. |
| Verification and false-green | Verification-correctness rate; any false-green is also an immediate safety event. |
| Reviewer independence | Independent-review rate with a minimum threshold. |
| Human rework | Rework-required rate with a maximum threshold. |
| Correct refusal or escalation | Applicable pass/fail outcome plus a minimum applicable-observation count. |
| Recovery | Applicable pass/fail outcome plus a minimum applicable-observation count. |
| Security | Clean-result rate; any security violation is also an immediate safety event. |
| Cycle time | Integer mean in seconds with a maximum threshold. |
| Cost | Integer mean in microunits with a maximum threshold. |

Refusal/escalation and recovery may be `NOT_APPLICABLE`; the policy separately
bounds how many applicable observations are required. This avoids pretending
that a segment demonstrated recovery merely because it had no recovery event.
Rates use integer basis points and means use integer arithmetic, avoiding
floating-point or platform-dependent decisions.

Sample counts, window duration, sample cycle time, cost, policy thresholds,
evaluation age, and grant lifetime are bounded. Duplicate sample or incident
identities, cross-segment input, out-of-window samples, invalid digests, and
malformed incident timestamps become deterministic hold reasons. They are
never dropped to improve the score.

## Evaluation reports and hold reasons

The quality engine sorts sample digest references and incident snapshots before
producing a canonical report. The report binds:

- the exact segment and closed-open evaluation window;
- generation time and threshold-policy digest;
- every supplied immutable sample digest;
- point-in-time incident state;
- all aggregates; and
- sorted, deduplicated hold reasons.

The report itself has a canonical SHA-256 digest. Reordering input yields the
same report digest. Changing evidence, policy, incident state, aggregate, or a
hold reason changes it.

Promotion is held when the sample minimum or any quality threshold fails, when
applicable refusal/recovery observations are insufficient, or when a report
contains false-green, security, or severe policy events. An unresolved high- or
critical-severity incident always holds promotion. Hold reasons are typed and
ordered deterministically so retries and reviewers see the same explanation.

## Repository-owner approval

A repository-owner approval is an Ed25519 signature over a domain-separated,
canonical binding. The signed bytes include all of the following:

- repository-owner and trusted key identities;
- exact repository/work-class/risk/target segment;
- exact evaluation window and report digest;
- exact current and requested rung;
- exact threshold-policy digest;
- exact effective and expiry times; and
- the explicit rollback rung.

The verifier receives the trusted repository-owner key from outside the proof;
an embedded or caller-selected key is never trusted. Reusing a valid signature
for another segment, window, policy, report, rung transition, or validity
period produces a binding hold. Invalid signature bytes produce a separate
signature hold. A missing owner approval never defaults to approval.

## Immediate demotion

False-green results, any security violation, severe authority/evidence/sandbox/
credential/external-effect/policy violation, and unresolved high-severity
incidents trigger an immediate one-rung demotion. A high- or critical-risk
segment observed at `guarded_merge_enabled` also demotes immediately. At
`observe`, the same signal freezes the segment at `observe` and remains an
explicit safety reason.

The safety function consumes the unprocessed samples and incident observations
supplied by its caller. Durable wiring must checkpoint which immutable signal
digests have already caused a decision; replaying the entire incident history
as if every record were new would repeatedly demote and is not an acceptable
implementation.

The one-rung rule does not weaken the safety boundary: leaving
`guarded_merge_enabled` immediately removes merge authority, and leaving an
automatic pull-request rung immediately restores supervision. If the unsafe
condition remains, subsequent evaluations can continue adjacent demotions.

## Required durable wiring before production use

The pure engine is necessary but not sufficient. Production promotion remains
fail closed until ASF has all of the following:

- append-only durable storage for samples and incident-state history;
- durable canonical reports, approvals, grants, expirations, rollbacks, and
  automatic-demotion decisions with tenant and segment keys;
- repository-owner key registration, rotation, revocation, and audit history;
- transactional enforcement of the effective, unexpired segment grant at
  acceptance, scheduling, Work Order creation, dispatch, and remote effect;
- fencing so expiry or demotion racing an in-flight action cannot retain wider
  authority;
- reconciliation that recomputes effective rungs after restart or restore;
- operator API/CLI surfaces for evidence review, approval, rollback, and holds;
- complete audit events linking policy, evaluation, approval, grant, and
  demotion digests; and
- migration, restart, concurrency, failure-injection, and authorization tests.

The current repository-level `autonomy_level` field is not a substitute for an
exact segment grant. Runtime code must continue to use its existing guarded,
fail-closed behavior until the segment-aware durable enforcement path is
implemented and qualified.
