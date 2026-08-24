use asf::{
    contracts::{
        RUNMILL_WORK_ORDER_SCHEMA_V1, RunmillBudgetLimitsV1, RunmillDeliveryAuthorityV1,
        RunmillIdentityRequirementsV1, RunmillObjectiveV1, RunmillRepositoryTargetV1,
        RunmillRiskClass, RunmillRuntimePolicyV1, RunmillSignedWorkOrderV1,
        RunmillVerificationRequirementsV1, RunmillWorkOrderClosureTarget, RunmillWorkOrderSourceV1,
        RunmillWorkOrderV1, RunmillWorkScopeV1,
    },
    crypto::{Ed25519Signer, encode_verifying_key},
};
use chrono::{DateTime, TimeDelta, Utc};

fn main() {
    let issued_at = DateTime::parse_from_rfc3339("2026-08-21T10:00:00Z")
        .expect("fixture timestamp")
        .with_timezone(&Utc);
    let tenant_id = "018f0000-0000-7000-8000-000000000002";
    let work_item_id = "018f0000-0000-7000-8000-000000000003";
    let attempt_id = "018f0000-0000-7000-8000-000000000004";
    let payload = RunmillWorkOrderV1 {
        schema: RUNMILL_WORK_ORDER_SCHEMA_V1.into(),
        work_order_id: "018f0000-0000-7000-8000-000000000001".into(),
        tenant_id: tenant_id.into(),
        work_item_id: work_item_id.into(),
        attempt_id: attempt_id.into(),
        idempotency_key: format!("{tenant_id}/{work_item_id}/{attempt_id}"),
        source: RunmillWorkOrderSourceV1 {
            system: "linear".into(),
            external_id: "ENG-123".into(),
            snapshot_digest:
                "sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7".into(),
        },
        repository: RunmillRepositoryTargetV1 {
            forge: "github".into(),
            repository: "acme/payments".into(),
            base_ref: "refs/heads/main".into(),
            base_sha: "0123456789012345678901234567890123456789".into(),
        },
        objective: RunmillObjectiveV1 {
            title: "Reject expired checkout sessions".into(),
            description:
                "Expired checkout sessions must be rejected without changing login behavior".into(),
            acceptance_criteria: vec!["Expired sessions return HTTP 401".into()],
            non_goals: vec!["Do not change login behavior".into()],
        },
        scope: RunmillWorkScopeV1 {
            allowed_paths: vec!["src/**".into(), "tests/**".into()],
            forbidden_paths: vec![".github/**".into(), ".runmill/**".into()],
            risk_class: RunmillRiskClass::Low,
        },
        verification: RunmillVerificationRequirementsV1 {
            required_local_check_ids: vec!["fmt".into(), "unit".into()],
            required_remote_checks: vec!["ci/test".into()],
            policy_snapshot_digest:
                "sha256:9fe296a3096e1b1a3be5c7058eb66184e82d5d977483ff237b7917816d177804".into(),
        },
        identities: RunmillIdentityRequirementsV1 {
            implementer: "codex:asf-production".into(),
            local_reviewer: "claude:asf-review".into(),
            pr_reviewer: "claude:asf-review".into(),
        },
        runtime: RunmillRuntimePolicyV1 {
            sandbox_profile: "linux-production-v1".into(),
            tool_policy: "rust-v1".into(),
            network_policy: "github-only-v1".into(),
        },
        budgets: RunmillBudgetLimitsV1 {
            wall_seconds: 3_600,
            max_cost_usd: 10.0,
            max_agent_invocations: 6,
            max_fix_iterations: 2,
        },
        delivery: RunmillDeliveryAuthorityV1 {
            closure_target: RunmillWorkOrderClosureTarget::Pr,
            draft_pr: true,
            merge_policy_ref: None,
        },
        policy_digest: "sha256:823412d1eacb93bd7dfc3e34b0d717f349ba63a70d360b8be98261be736f3a4b"
            .into(),
        harness_digest: "sha256:5e41334048aa3d9e1d5e54a0c137475a5646d968bef1b78372a8dc3b5a951ff9"
            .into(),
    };
    let signer = Ed25519Signer::from_base64_seed(
        "asf-signing-key-fixture",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .expect("fixed signing key");
    let signed = RunmillSignedWorkOrderV1::sign(
        payload,
        &signer,
        issued_at,
        issued_at,
        issued_at + TimeDelta::minutes(15),
    )
    .expect("sign fixture");
    println!(
        "{}",
        serde_json::to_string_pretty(&signed).expect("serialize fixture")
    );
    eprintln!(
        "public_key={}\npayload_digest={}\nenvelope_digest={}\nsignature={}",
        encode_verifying_key(&signer.verifying_key()),
        signed.payload_digest().expect("payload digest"),
        signed.envelope_digest().expect("envelope digest"),
        signed.signature,
    );
}
