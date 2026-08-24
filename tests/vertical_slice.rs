use std::collections::{BTreeMap, BTreeSet, HashSet};

use asf::{
    adapters::{
        InMemoryGitHubGateway, InMemoryLinearGateway, InMemoryRunmillGateway,
        SimulatedGitHubEffectDisposition, SimulatedGitHubPullRequestEffect,
    },
    application::{
        ReadinessContext, ReadinessEngine, ReadinessStatus, RunStop, WorkflowEffect, WorkflowFact,
        WorkflowReducer, WorkflowStage, WorkflowState,
    },
    contracts::{
        ApprovalEvidenceRecord, ArtifactManifestEntry, CheckConclusion, CheckEvidence,
        CheckRequirements, ContractDigests, EVIDENCE_SCHEMA_V1, EvidenceBundleV1,
        EvidenceExpectation, FindingEvidence, ProductEvent, RepositoryTarget, ReviewEvidence,
        RoleIdentityEvidence, RoleOutcomeConclusion, RoleOutcomeEvidence, RuntimeDigestEvidence,
        SideEffectEvidence, SideEffectStatus, SignedEvidenceBundle, SignedWorkOrder, UsageEvidence,
        WORK_ORDER_SCHEMA_V1, WorkOrderV1,
    },
    crypto::{Ed25519Signer, canonical_json, sha256_digest},
    domain::{
        AccountabilityKind, AutomationEnvironment, AutonomyLevel, BudgetLimits, ClosureTarget,
        CredentialIsolation, CtxlaneAuthMode, CtxlaneProfileRef, DeliveryPermission,
        EffectAuthority, EventId, EvidenceId, ExecutionAuthority, IdentityReadiness,
        IdentityReadinessChecks, IdentityRole, PathAuthority, ReadinessCheckStatus, Repository,
        RepositoryId, RiskAssessment, RiskClass, SourceSnapshot, SourceSnapshotContent,
        SourceSystem, TenantId, ToolAuthority, WorkItem, WorkItemState, WorkOrderId,
        WorkOrderIdentities, Worker, WorkerCapabilities, WorkerHealth, WorkerId,
        validate_accountability,
    },
    ports::{
        ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1, AcknowledgeOutcomeRequest,
        AcknowledgementDisposition, CapabilityNegotiationRequest, CloseSourceRequest, ForgeGateway,
        ForgeGatewayError, GET_RUN_EVENTS_REQUEST_SCHEMA_V1, GetEvidenceRequest,
        GetRunEventsRequest, ObservePullRequestRequest, ObserveSourceRequest,
        PRODUCT_EVENT_SCHEMA_V1, PULL_REQUEST_OBSERVATION_SCHEMA_V1, PullRequestObservation,
        PullRequestRef, PullRequestState, ReconcileSourceCloseRequest, RemoteCiObservation,
        RemoteCiState, RunmillGateway, RunmillGatewayError, SourceCloseDisposition,
        SourceCloseEffect, SourceCloseReconciliation, SourceClosure, SourceGateway,
        SourceGatewayError, SourceIntakeRequest, SourceItemRef, SourceLifecycle,
        SubmissionDisposition, SubmitWorkOrderRequest,
    },
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use url::Url;

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("test timestamp must be valid RFC 3339")
        .with_timezone(&Utc)
}

fn profile(value: &str) -> CtxlaneProfileRef {
    value.parse().expect("test profile reference must be valid")
}

fn budgets() -> BudgetLimits {
    BudgetLimits {
        max_cost_microunits: 5_000_000,
        max_input_tokens: 100_000,
        max_output_tokens: 40_000,
        max_implementer_invocations: 3,
        max_reviewer_invocations: 3,
        max_fix_iterations: 2,
        max_wall_time_seconds: 3_600,
        max_external_api_calls: 50,
    }
}

fn authority() -> ExecutionAuthority {
    ExecutionAuthority {
        paths: PathAuthority {
            allowed: BTreeSet::from(["src/**".into(), "tests/**".into()]),
            forbidden: BTreeSet::from([".github/**".into(), ".env".into()]),
        },
        tools: ToolAuthority {
            allowed_tools: BTreeSet::from(["filesystem".into(), "shell".into()]),
            allowed_commands: BTreeSet::from(["cargo test".into()]),
            network_destinations: BTreeSet::new(),
        },
        effects: EffectAuthority {
            delivery: DeliveryPermission::PullRequest,
            may_comment: false,
            may_update_checks: false,
            deployment_environment: None,
        },
        budgets: budgets(),
        required_approval_types: BTreeSet::new(),
        sandbox_policy_ref: "linux-production-v1".into(),
    }
}

fn ready_identity(
    profile_ref: CtxlaneProfileRef,
    role: IdentityRole,
    principal: &str,
    environment: &AutomationEnvironment,
    worker_id: WorkerId,
    worker_generation: u64,
    policy_digest: &str,
    now: DateTime<Utc>,
) -> IdentityReadiness {
    IdentityReadiness {
        profile_ref,
        role,
        environment: environment.clone(),
        worker_id,
        worker_generation,
        policy_digest: policy_digest.into(),
        checked_at: now - TimeDelta::minutes(1),
        valid_until: now + TimeDelta::minutes(30),
        checks: IdentityReadinessChecks {
            metadata_valid: ReadinessCheckStatus::Passed,
            credential_source_available: ReadinessCheckStatus::Passed,
            upstream_identity_token_current: ReadinessCheckStatus::Passed,
            provider_harness_trusted: ReadinessCheckStatus::Passed,
            provider_principal_verified: ReadinessCheckStatus::Passed,
            expected_workspace_verified: ReadinessCheckStatus::Passed,
            automation_policy_permitted: ReadinessCheckStatus::Passed,
        },
        principal_ref: Some(
            principal
                .parse()
                .expect("test principal reference must be safe"),
        ),
        workspace_ref: Some(
            "workspace:asf-production"
                .parse()
                .expect("test workspace reference must be safe"),
        ),
        auth_mode: Some(CtxlaneAuthMode::Wif),
        isolation: CredentialIsolation::CredentialIsolated,
        refusal_code: None,
    }
}

fn run_event(
    tenant_id: TenantId,
    work_item_id: asf::domain::WorkItemId,
    attempt_id: asf::domain::AttemptId,
    run_id: asf::domain::RunId,
    work_order_digest: &str,
    policy_digest: &str,
    aggregate_version: u64,
    event_type: &str,
    occurred_at: DateTime<Utc>,
) -> ProductEvent {
    ProductEvent {
        schema: PRODUCT_EVENT_SCHEMA_V1.into(),
        event_id: EventId::new(),
        tenant_id,
        work_item_id: Some(work_item_id),
        attempt_id: Some(attempt_id),
        work_order_digest: Some(work_order_digest.into()),
        run_id: Some(run_id),
        aggregate_version,
        occurred_at,
        ingested_at: occurred_at,
        actor: "runmill:worker-7".into(),
        event_type: event_type.into(),
        payload: json!({"aggregate_version": aggregate_version}),
        policy_digest: Some(policy_digest.into()),
        trace_id: "trace:v1-lifecycle".into(),
        correlation_id: "correlation:linear-ASF-42".into(),
    }
}

#[tokio::test]
async fn v1_lifecycle_survives_retries_disconnects_and_ambiguous_closure()
-> Result<(), Box<dyn std::error::Error>> {
    let now = at("2026-08-21T10:00:00Z");
    let tenant_id = TenantId::new();
    let repository_id = RepositoryId::new();
    let worker_id = WorkerId::new();
    let worker_generation = 7;
    let policy_digest = sha256_digest(b"tenant-policy-v1");
    let repository_policy_digest = sha256_digest(b"repository-policy-v1");
    let harness_digest = sha256_digest(b"harness-v1");
    let base_sha = "1111111111111111111111111111111111111111";
    let candidate_sha = "2222222222222222222222222222222222222222";
    let local_checks = BTreeSet::from(["cargo-test".into()]);
    let remote_checks = BTreeSet::from(["ci/test".into(), "ci/lint".into()]);

    let repository = Repository {
        id: repository_id,
        tenant_id,
        forge: "github".into(),
        owner: "acme".into(),
        name: "payments".into(),
        base_ref: "refs/heads/main".into(),
        policy_digest: repository_policy_digest.clone(),
        harness_digest: harness_digest.clone(),
        required_local_checks: local_checks.clone(),
        required_remote_checks: remote_checks.clone(),
        wip_limit: 1,
        autonomy_level: AutonomyLevel::AutomaticVerifiedPullRequest,
        preferred_worker_id: Some(worker_id),
        enabled: true,
        version: 1,
        created_at: now,
        updated_at: now,
    };

    // Intake is label-gated and returns immutable normalized Linear snapshots.
    let linear = InMemoryLinearGateway::new();
    let source_content = SourceSnapshotContent {
        source: SourceSystem::Linear,
        external_id: "ASF-42".into(),
        source_revision: "linear-revision-9".into(),
        source_url: Some(Url::parse("https://linear.example/issue/ASF-42")?),
        title: "Repair bounded payment regression".into(),
        objective: "Reject a duplicated settlement without changing unrelated payment paths".into(),
        acceptance_criteria: vec![
            "the duplicate-settlement regression test passes".into(),
            "the required GitHub checks pass on the exact pull-request head".into(),
        ],
        non_goals: vec!["no deployment or direct merge".into()],
        labels: BTreeSet::from(["asf-ready".into()]),
        normalized_priority: 80,
        source_state: "started".into(),
        assignee: Some("team-payments".into()),
        repository_hint: Some("acme/payments".into()),
        source_updated_at: now - TimeDelta::minutes(2),
    };
    let seeded_snapshot = SourceSnapshot::create(
        tenant_id,
        Some(repository_id),
        source_content,
        "linear:production-connector".into(),
        now - TimeDelta::minutes(1),
    )?;
    linear.upsert_snapshot(seeded_snapshot.clone()).await?;
    let intake = linear
        .intake(&SourceIntakeRequest::first_page(tenant_id, "asf-ready", 10))
        .await?;
    assert_eq!(intake.snapshots, vec![seeded_snapshot.clone()]);
    assert!(!intake.has_more);
    let snapshot = intake.snapshots[0].clone();
    assert_eq!(snapshot.content.digest()?, snapshot.content_digest);

    // Negotiate the complete prospective worker contract before readiness.
    let runmill = InMemoryRunmillGateway::new(worker_id, worker_generation);
    let capability_request = CapabilityNegotiationRequest::asf_v1();
    let capabilities = runmill.negotiate(&capability_request).await?;
    capabilities.satisfy(&capability_request)?;
    let worker = Worker {
        id: worker_id,
        tenant_id,
        display_name: "runmill-linux-7".into(),
        endpoint: "in-memory://runmill-linux-7".into(),
        generation: worker_generation,
        health: WorkerHealth::Healthy,
        capabilities: WorkerCapabilities {
            protocol_schema: capabilities.gateway_schema.clone(),
            work_order_schemas: capabilities.accepted_work_order_schemas.clone(),
            evidence_schemas: capabilities.emitted_evidence_schemas.clone(),
            closure_targets: BTreeSet::from(["pr".into()]),
            sandbox_profiles: BTreeSet::from(["linux-production-v1".into()]),
            supports_cursor_events: capabilities.cursor_events,
            supports_idempotent_submission: capabilities.idempotent_submission,
            supports_signed_evidence: capabilities.signed_evidence,
        },
        max_concurrency: 1,
        active_slots: 0,
        last_seen_at: now,
    };
    assert!(worker.production_ready());

    let environment: AutomationEnvironment = "production".parse()?;
    let identities = WorkOrderIdentities {
        implementer: profile("codex:payments-implementer"),
        local_reviewer: profile("claude:payments-local-review"),
        pr_reviewer: profile("claude:payments-pr-review"),
    };
    identities.validate()?;
    let identity_readiness = vec![
        ready_identity(
            identities.implementer.clone(),
            IdentityRole::Implementer,
            "principal:payments-implementer",
            &environment,
            worker_id,
            worker_generation,
            &policy_digest,
            now,
        ),
        ready_identity(
            identities.local_reviewer.clone(),
            IdentityRole::LocalReviewer,
            "principal:payments-local-reviewer",
            &environment,
            worker_id,
            worker_generation,
            &policy_digest,
            now,
        ),
        ready_identity(
            identities.pr_reviewer.clone(),
            IdentityRole::PrReviewer,
            "principal:payments-pr-reviewer",
            &environment,
            worker_id,
            worker_generation,
            &policy_digest,
            now,
        ),
    ];
    let risk = RiskAssessment {
        class: RiskClass::Low,
        reasons: vec!["bounded repository-local regression".into()],
        matched_rules: BTreeSet::from(["low-risk-bounded-change".into()]),
    };
    let readiness = ReadinessEngine;
    let incomplete_context = ReadinessContext {
        snapshot: &snapshot,
        source_is_current: true,
        repository: Some(&repository),
        closure_target: ClosureTarget::PullRequest,
        risk: &risk,
        dependencies_known: true,
        dependency_cycle: false,
        dependencies_satisfied: true,
        exact_base_sha: Some(base_sha),
        path_and_check_policy_compiled: true,
        identity_requirements: &identities,
        identity_environment: &environment,
        identities: &identity_readiness[..2],
        worker: Some(&worker),
        budgets_reservable: true,
        required_approval_present_or_scheduled: true,
        policy_digest: &policy_digest,
        now,
    };
    let incomplete = readiness.evaluate(&incomplete_context);
    assert_ne!(incomplete.status, ReadinessStatus::Ready);
    assert!(
        incomplete
            .issues
            .iter()
            .any(|issue| issue.code == "IDENTITY_ROLES_INCOMPLETE")
    );
    let ready_context = ReadinessContext {
        identities: &identity_readiness,
        ..incomplete_context
    };
    let ready = readiness.evaluate(&ready_context);
    assert_eq!(ready.status, ReadinessStatus::Ready);
    assert!(ready.issues.is_empty());
    assert_eq!(ready.source_snapshot_digest, snapshot.content_digest);

    // Acceptance is atomic and cannot omit any of its durable authority references.
    let mut item = WorkItem::discovered(
        tenant_id,
        snapshot.id,
        snapshot.content.normalized_priority,
        now,
    );
    item.transition(WorkItemState::ReadinessPending, now)?;
    item.transition(WorkItemState::Ready, now)?;
    item.repository_id = Some(repository_id);
    item.closure_target = Some(ClosureTarget::PullRequest);
    item.risk = Some(risk.clone());
    item.policy_digest = Some(policy_digest.clone());
    item.budgets = Some(budgets());
    item.owner_fallback = Some("team-payments-oncall".into());
    let ready_version = item.version;
    assert!(item.transition(WorkItemState::Accepted, now).is_err());
    assert_eq!(item.state, WorkItemState::Ready);
    assert_eq!(item.version, ready_version);
    item.identity_requirements = Some(identities.clone());
    item.transition(WorkItemState::Accepted, now)?;
    item.validate_acceptance_fields()?;
    assert_eq!(item.owner_fallback.as_deref(), Some("team-payments-oncall"));

    // The canonical payload and its validity window are immutable under the ASF signature.
    let attempt_id = asf::domain::AttemptId::new();
    let order = WorkOrderV1 {
        schema: WORK_ORDER_SCHEMA_V1.into(),
        work_order_id: WorkOrderId::new(),
        tenant_id,
        work_item_id: item.id,
        attempt_id,
        idempotency_key: format!("dispatch:{tenant_id}:{attempt_id}"),
        source_system: SourceSystem::Linear,
        source_external_id: snapshot.content.external_id.clone(),
        source_snapshot_digest: snapshot.content_digest.clone(),
        source_reference: snapshot
            .content
            .source_url
            .as_ref()
            .expect("source URL is present")
            .to_string(),
        repository: RepositoryTarget {
            repository_id,
            forge: repository.forge.clone(),
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            base_ref: repository.base_ref.clone(),
            base_sha: base_sha.into(),
        },
        objective: snapshot.content.objective.clone(),
        acceptance_criteria: snapshot.content.acceptance_criteria.clone(),
        non_goals: snapshot.content.non_goals.clone(),
        checks: CheckRequirements {
            local_check_ids: local_checks.clone(),
            remote_ci_contexts: remote_checks.clone(),
        },
        risk: risk.clone(),
        identities: identities.clone(),
        authority: authority(),
        closure_target: ClosureTarget::PullRequest,
        digests: ContractDigests {
            policy: policy_digest.clone(),
            repository_policy: repository_policy_digest,
            planner: sha256_digest(b"planner-v1"),
            harness: harness_digest,
        },
        issued_at: now,
        not_before: now,
        expires_at: now + TimeDelta::hours(1),
    };
    let canonical_order = order.canonical_bytes()?;
    let asf_signer = Ed25519Signer::generate("asf-control-plane-v1");
    let asf_key = asf_signer.verifying_key();
    let signed_order = SignedWorkOrder::sign(order, &asf_signer)?;
    signed_order.verify(&asf_key, now)?;
    let serialized = serde_json::to_vec(&signed_order)?;
    let round_trip: SignedWorkOrder = serde_json::from_slice(&serialized)?;
    assert_eq!(round_trip, signed_order);
    assert_eq!(round_trip.payload.canonical_bytes()?, canonical_order);
    let mut tampered_order = signed_order.clone();
    tampered_order.payload.objective.push_str(" and deploy it");
    assert!(tampered_order.verify(&asf_key, now).is_err());

    let reducer = WorkflowReducer::default();
    let mut workflow = WorkflowState::accepted(item.id, now);
    let transition = reducer.apply(workflow, WorkflowFact::ScheduleRequested, now)?;
    assert_eq!(transition.effects, vec![WorkflowEffect::EnqueueScheduler]);
    workflow = transition.state;
    let transition = reducer.apply(workflow, WorkflowFact::ScheduleGranted, now)?;
    assert_eq!(
        transition.effects,
        vec![WorkflowEffect::ReserveAndCreateAttempt]
    );
    workflow = transition.state;
    item.transition(WorkItemState::Scheduled, now)?;
    validate_accountability(item.state, item.accepted_at, Some(&workflow.accountability))?;
    let work_order_digest = signed_order.payload_digest.clone();
    let transition = reducer.apply(
        workflow,
        WorkflowFact::WorkOrderStored {
            digest: work_order_digest.clone(),
        },
        now,
    )?;
    assert_eq!(
        transition.effects,
        vec![WorkflowEffect::SubmitStoredWorkOrder]
    );
    workflow = transition.state;
    item.transition(WorkItemState::Dispatching, now)?;

    // Repeating the exact dispatch adopts one run; changing the signed content conflicts.
    let submission = SubmitWorkOrderRequest::new(signed_order.clone())?;
    let accepted = runmill.submit_work_order(&submission).await?;
    assert_eq!(accepted.disposition, SubmissionDisposition::Accepted);
    let adopted = runmill.submit_work_order(&submission).await?;
    assert_eq!(adopted.disposition, SubmissionDisposition::Adopted);
    assert_eq!(adopted.run_id, accepted.run_id);
    assert_eq!(runmill.run_count().await, 1);
    let mut different_order = signed_order.payload.clone();
    different_order
        .objective
        .push_str(" with a different intent");
    let conflicting_submission =
        SubmitWorkOrderRequest::new(SignedWorkOrder::sign(different_order, &asf_signer)?)?;
    assert!(matches!(
        runmill
            .submit_work_order(&conflicting_submission)
            .await
            .expect_err("same idempotency key with another digest must conflict"),
        RunmillGatewayError::IdempotencyConflict { .. }
    ));
    assert_eq!(runmill.run_count().await, 1);

    let transition = reducer.apply(
        workflow,
        WorkflowFact::SubmissionAccepted {
            run_id: accepted.run_id,
        },
        now,
    )?;
    assert!(matches!(
        transition.effects.as_slice(),
        [WorkflowEffect::ObserveRun { run_id }] if *run_id == accepted.run_id
    ));
    workflow = transition.state;
    item.transition(WorkItemState::Running, now)?;
    validate_accountability(item.state, item.accepted_at, Some(&workflow.accountability))?;

    // Cursor recovery is exclusive and stable across a simulated observer disconnect.
    let event_two = run_event(
        tenant_id,
        item.id,
        attempt_id,
        accepted.run_id,
        &work_order_digest,
        &policy_digest,
        2,
        "run.started",
        now + TimeDelta::minutes(1),
    );
    runmill
        .append_event(accepted.run_id, event_two.clone())
        .await?;
    assert!(matches!(
        runmill
            .append_event(accepted.run_id, event_two)
            .await
            .expect_err("duplicate event IDs must be rejected"),
        RunmillGatewayError::InvalidRequest(_)
    ));
    let event_three = run_event(
        tenant_id,
        item.id,
        attempt_id,
        accepted.run_id,
        &work_order_digest,
        &policy_digest,
        3,
        "run.candidate-produced",
        now + TimeDelta::minutes(2),
    );
    runmill.append_event(accepted.run_id, event_three).await?;
    let first_request = GetRunEventsRequest::first_page(accepted.run_id, 1);
    let first_page = runmill.get_run_events(&first_request).await?;
    let replayed_first_page = runmill.get_run_events(&first_request).await?;
    assert_eq!(first_page.events, replayed_first_page.events);
    assert_eq!(first_page.next_cursor, replayed_first_page.next_cursor);
    assert!(first_page.has_more);
    let durable_cursor = first_page
        .next_cursor
        .clone()
        .expect("a full first page has a durable continuation cursor");
    let reconnected_observer = runmill.clone();
    let second_page = reconnected_observer
        .get_run_events(&GetRunEventsRequest {
            schema: GET_RUN_EVENTS_REQUEST_SCHEMA_V1.into(),
            run_id: accepted.run_id,
            after: Some(durable_cursor),
            limit: 1,
        })
        .await?;
    assert_eq!(second_page.events.len(), 1);
    assert!(!second_page.has_more);
    let recovered_ids: HashSet<_> = first_page
        .events
        .iter()
        .chain(&second_page.events)
        .map(|event| event.event_id)
        .collect();
    assert_eq!(recovered_ids.len(), 2);
    assert_eq!(second_page.snapshot.aggregate_version, 3);

    // Runmill's simulated PR effect can lose a response without duplicating the PR.
    let pull_request_ref = PullRequestRef {
        repository: repository.slug(),
        number: 42,
    };
    let github_observation = PullRequestObservation {
        schema: PULL_REQUEST_OBSERVATION_SCHEMA_V1.into(),
        pull_request: pull_request_ref.clone(),
        url: "https://github.example/acme/payments/pull/42".into(),
        state: PullRequestState::Open,
        base_sha: base_sha.into(),
        head_sha: candidate_sha.into(),
        merge_sha: None,
        ci: BTreeMap::from([
            (
                "ci/test".into(),
                RemoteCiObservation {
                    candidate_sha: candidate_sha.into(),
                    state: RemoteCiState::Success,
                },
            ),
            (
                "ci/lint".into(),
                RemoteCiObservation {
                    candidate_sha: candidate_sha.into(),
                    state: RemoteCiState::Success,
                },
            ),
        ]),
        provider_revision: "github:pull-42:revision-3".into(),
        observed_at: now + TimeDelta::minutes(3),
    };
    let github = InMemoryGitHubGateway::new();
    let github_effect = SimulatedGitHubPullRequestEffect::new(
        format!("pr-create:{attempt_id}"),
        github_observation,
    )?;
    github.lose_next_effect_response().await;
    assert!(matches!(
        github
            .apply_pull_request_effect(&github_effect)
            .await
            .expect_err("the injected post-commit response must be ambiguous"),
        ForgeGatewayError::AmbiguousEffect { .. }
    ));
    let observe_pr = ObservePullRequestRequest::new(
        pull_request_ref.clone(),
        base_sha,
        candidate_sha,
        remote_checks.clone(),
    );
    let independently_observed = github.observe_pull_request(&observe_pr).await?;
    let independent_pr_evidence = independently_observed.exact_candidate_evidence(&observe_pr)?;
    let adopted_pr = github.apply_pull_request_effect(&github_effect).await?;
    assert_eq!(
        adopted_pr.disposition,
        SimulatedGitHubEffectDisposition::Adopted
    );
    assert_eq!(
        github
            .logical_pull_request_effect_count(&pull_request_ref)
            .await,
        1
    );

    // Worker evidence embeds the exact signed order; ASF verifies it with independent keys and
    // the independently observed GitHub base/head/CI state before allowing source closure.
    let evidence_id = EvidenceId::new();
    let evidence_payload = EvidenceBundleV1 {
        schema: EVIDENCE_SCHEMA_V1.into(),
        evidence_id,
        work_item_id: item.id,
        attempt_id,
        run_id: accepted.run_id,
        worker_id,
        worker_generation,
        work_order_digest: work_order_digest.clone(),
        work_order: signed_order.clone(),
        work_order_signature_verified_by_worker: true,
        source_snapshot_digest: snapshot.content_digest.clone(),
        policy_input_digests: BTreeMap::from([
            ("tenant".into(), policy_digest.clone()),
            (
                "repository".into(),
                signed_order.payload.digests.repository_policy.clone(),
            ),
        ]),
        repository: repository.slug(),
        base_ref: repository.base_ref.clone(),
        base_sha: base_sha.into(),
        candidate_sha: candidate_sha.into(),
        remote_head_sha: candidate_sha.into(),
        merge_sha: None,
        changed_paths: BTreeSet::from(["src/settlement.rs".into(), "tests/settlement.rs".into()]),
        diff_digest: sha256_digest(b"bounded settlement diff"),
        identity_attribution: vec![
            RoleIdentityEvidence {
                role: IdentityRole::Implementer,
                provider: "codex".into(),
                profile_ref: identities.implementer.clone(),
                principal_ref: "principal:payments-implementer".into(),
                lease_id: "lease-implementer-42".into(),
                model: "production-model".into(),
                isolation: "credential-isolated".into(),
            },
            RoleIdentityEvidence {
                role: IdentityRole::LocalReviewer,
                provider: "claude".into(),
                profile_ref: identities.local_reviewer.clone(),
                principal_ref: "principal:payments-local-reviewer".into(),
                lease_id: "lease-local-reviewer-42".into(),
                model: "production-review-model".into(),
                isolation: "credential-isolated".into(),
            },
            RoleIdentityEvidence {
                role: IdentityRole::PrReviewer,
                provider: "claude".into(),
                profile_ref: identities.pr_reviewer.clone(),
                principal_ref: "principal:payments-pr-reviewer".into(),
                lease_id: "lease-pr-reviewer-42".into(),
                model: "production-review-model".into(),
                isolation: "credential-isolated".into(),
            },
        ],
        runtime_digests: RuntimeDigestEvidence {
            harness: signed_order.payload.digests.harness.clone(),
            tool_policy: sha256_digest(b"tool-policy-v1"),
            sandbox: sha256_digest(b"linux-sandbox-v1"),
            dependencies: sha256_digest(b"cargo-lock-v1"),
            runtime: sha256_digest(b"runmill-runtime-v1"),
        },
        role_outcomes: vec![
            RoleOutcomeEvidence {
                role: IdentityRole::Implementer,
                candidate_sha: Some(candidate_sha.into()),
                conclusion: RoleOutcomeConclusion::Completed,
                summary_digest: sha256_digest(b"implementation-summary"),
            },
            RoleOutcomeEvidence {
                role: IdentityRole::LocalReviewer,
                candidate_sha: Some(candidate_sha.into()),
                conclusion: RoleOutcomeConclusion::Completed,
                summary_digest: sha256_digest(b"local-review-summary"),
            },
            RoleOutcomeEvidence {
                role: IdentityRole::PrReviewer,
                candidate_sha: Some(candidate_sha.into()),
                conclusion: RoleOutcomeConclusion::Completed,
                summary_digest: sha256_digest(b"pr-review-summary"),
            },
        ],
        findings: Vec::<FindingEvidence>::new(),
        requested_target: ClosureTarget::PullRequest,
        target_satisfied: true,
        checks: vec![CheckEvidence {
            check_id: "cargo-test".into(),
            candidate_sha: candidate_sha.into(),
            conclusion: CheckConclusion::Passed,
            artifact_digest: Some(sha256_digest(b"cargo-test-report")),
        }],
        review: ReviewEvidence {
            reviewer_profile: identities.pr_reviewer.to_string(),
            reviewer_principal: "principal:payments-pr-reviewer".into(),
            candidate_sha: candidate_sha.into(),
            independent: true,
            approved: true,
            report_digest: sha256_digest(b"independent-pr-review"),
        },
        pull_request: Some(independent_pr_evidence.clone()),
        side_effects: vec![SideEffectEvidence {
            effect_type: "pull_request.create".into(),
            idempotency_key: github_effect.idempotency_key.clone(),
            intent_digest: github_effect.effect_digest.clone(),
            status: SideEffectStatus::Reconciled,
            observation_digest: Some(sha256_digest(&canonical_json(&independently_observed)?)),
            candidate_sha: Some(candidate_sha.into()),
        }],
        approvals: Vec::<ApprovalEvidenceRecord>::new(),
        cancellation: None,
        artifacts: Vec::<ArtifactManifestEntry>::new(),
        usage: UsageEvidence {
            cost_microunits: 900_000,
            input_tokens: 20_000,
            output_tokens: 8_000,
            implementer_invocations: 1,
            reviewer_invocations: 2,
            fix_iterations: 0,
            wall_time_seconds: 420,
        },
        stop_reason: "pull_request_target_satisfied".into(),
        produced_at: now + TimeDelta::minutes(4),
    };
    let worker_signer = Ed25519Signer::generate("runmill-worker-7");
    let worker_key = worker_signer.verifying_key();
    let signed_evidence = SignedEvidenceBundle::sign(evidence_payload, &worker_signer)?;
    runmill
        .attach_evidence(accepted.run_id, signed_evidence.clone())
        .await?;
    let fetched = runmill
        .get_evidence(&GetEvidenceRequest::for_run(accepted.run_id))
        .await?
        .evidence
        .expect("target-reached run must retain its signed evidence");
    let expected_repository = repository.slug();
    let expectation = EvidenceExpectation {
        asf_work_order_key: &asf_key,
        asf_work_order_key_id: "asf-control-plane-v1",
        worker_key_id: "runmill-worker-7",
        work_item_id: item.id,
        attempt_id,
        run_id: accepted.run_id,
        worker_id,
        work_order_digest: &work_order_digest,
        repository: &expected_repository,
        base_sha,
        candidate_sha,
        target: ClosureTarget::PullRequest,
        required_local_checks: &local_checks,
        required_ci_contexts: &remote_checks,
        current_worker_generation: worker_generation,
        independently_observed_pull_request: Some(&independent_pr_evidence),
    };
    fetched.verify(&worker_key, &expectation)?;
    assert_eq!(
        fetched.payload.pull_request,
        Some(independent_pr_evidence.clone())
    );
    assert_eq!(
        fetched.payload.identity_attribution[0].profile_ref,
        identities.implementer
    );
    let mut tampered_evidence = fetched.clone();
    tampered_evidence.payload.remote_head_sha = "3333333333333333333333333333333333333333".into();
    assert!(tampered_evidence.verify(&worker_key, &expectation).is_err());

    let acknowledgement = AcknowledgeOutcomeRequest {
        schema: ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1.into(),
        run_id: accepted.run_id,
        idempotency_key: format!("evidence-ack:{evidence_id}"),
        evidence_digest: fetched.payload_digest.clone(),
        acknowledged_at: now + TimeDelta::minutes(5),
    };
    assert_eq!(
        runmill
            .acknowledge_outcome(&acknowledgement)
            .await?
            .disposition,
        AcknowledgementDisposition::Recorded
    );
    assert_eq!(
        runmill
            .acknowledge_outcome(&acknowledgement)
            .await?
            .disposition,
        AcknowledgementDisposition::Adopted
    );

    let transition = reducer.apply(
        workflow,
        WorkflowFact::RunStopped(RunStop::EvidenceAvailable { evidence_id }),
        now + TimeDelta::minutes(5),
    )?;
    assert!(matches!(
        transition.effects.as_slice(),
        [WorkflowEffect::FetchAndVerifyEvidence { evidence_id: id }] if *id == evidence_id
    ));
    workflow = transition.state;
    item.transition(WorkItemState::VerifyingOutcome, now + TimeDelta::minutes(5))?;
    let transition = reducer.apply(
        workflow,
        WorkflowFact::EvidenceValidated { evidence_id },
        now + TimeDelta::minutes(5),
    )?;
    assert!(matches!(
        transition.effects.as_slice(),
        [WorkflowEffect::CloseSource { evidence_id: id }] if *id == evidence_id
    ));
    workflow = transition.state;
    item.transition(WorkItemState::TargetReached, now + TimeDelta::minutes(5))?;
    item.transition(WorkItemState::ClosingSource, now + TimeDelta::minutes(5))?;
    validate_accountability(item.state, item.accepted_at, Some(&workflow.accountability))?;

    // Linear applies the close, loses the response, and is reconciled by immutable effect identity.
    let source_item = SourceItemRef {
        tenant_id,
        source: SourceSystem::Linear,
        external_id: snapshot.content.external_id.clone(),
    };
    let closure = SourceClosure {
        work_item_id: item.id,
        target: ClosureTarget::PullRequest,
        pull_request: Some(independent_pr_evidence),
        evidence_id,
        evidence_digest: fetched.payload_digest.clone(),
        final_outcome_summary: "Verified pull request 42 is open at the exact tested head".into(),
        cost_microunits: Some(fetched.payload.usage.cost_microunits),
        wall_time_seconds: Some(fetched.payload.usage.wall_time_seconds),
    };
    let close_effect = SourceCloseEffect::new(
        source_item.clone(),
        snapshot.content.source_revision.clone(),
        snapshot.content_digest.clone(),
        format!("asf-close:{}:{evidence_id}", item.id),
        closure,
    )?;
    let close_request = CloseSourceRequest::new(
        format!("source-close:{}:{evidence_id}", item.id),
        close_effect,
        now + TimeDelta::minutes(6),
    )?;
    linear.lose_next_close_response().await;
    assert!(matches!(
        linear
            .close_source(&close_request)
            .await
            .expect_err("the injected post-commit source response must be ambiguous"),
        SourceGatewayError::AmbiguousEffect { .. }
    ));
    let transition = reducer.apply(
        workflow,
        WorkflowFact::SourceCloseAmbiguous,
        now + TimeDelta::minutes(6),
    )?;
    assert_eq!(
        transition.effects,
        vec![WorkflowEffect::ReconcileSourceClosure]
    );
    workflow = transition.state;
    let reconciliation = linear
        .reconcile_source_close(&ReconcileSourceCloseRequest::from_close(&close_request))
        .await?;
    let reconciled_receipt = match reconciliation {
        SourceCloseReconciliation::Applied(receipt) => receipt,
        SourceCloseReconciliation::NotObserved => {
            panic!("the source close was durably applied before its response was lost")
        }
    };
    assert_eq!(
        reconciled_receipt.disposition,
        SourceCloseDisposition::Reconciled
    );
    let adopted_close = linear.close_source(&close_request).await?;
    assert_eq!(adopted_close.disposition, SourceCloseDisposition::Adopted);
    assert_eq!(
        linear.logical_close_effect_count(&source_item).await,
        1,
        "reconciliation and retry must not duplicate the logical source effect"
    );

    let transition = reducer.apply(
        workflow,
        WorkflowFact::SourceCloseConfirmed,
        now + TimeDelta::minutes(7),
    )?;
    assert_eq!(transition.state.stage, WorkflowStage::Closed);
    assert_eq!(
        transition.state.accountability.kind,
        AccountabilityKind::VerifiedClosure
    );
    assert_eq!(
        transition.effects,
        vec![WorkflowEffect::ReleaseReservations]
    );
    workflow = transition.state;
    item.transition(WorkItemState::Closed, now + TimeDelta::minutes(7))?;
    validate_accountability(item.state, item.accepted_at, Some(&workflow.accountability))?;

    let observed_source = linear
        .observe_source(&ObserveSourceRequest::new(source_item.clone()))
        .await?;
    assert_eq!(observed_source.lifecycle, SourceLifecycle::Completed);
    assert_eq!(
        observed_source
            .applied_closure
            .expect("completed source has a close receipt")
            .effect_digest,
        close_request.effect_digest
    );
    let history = linear.snapshot_history(&source_item).await;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0], snapshot,
        "the accepted snapshot remains immutable"
    );
    assert_eq!(runmill.run_count().await, 1);
    assert_eq!(
        github
            .logical_pull_request_effect_count(&pull_request_ref)
            .await,
        1
    );
    assert_eq!(linear.logical_close_effect_count(&source_item).await, 1);

    Ok::<(), Box<dyn std::error::Error>>(())
}
