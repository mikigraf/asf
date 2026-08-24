use crate::domain::{DeliveryPermission, ExecutionAuthority};

/// Intersects authorities so policy composition can only remove powers.
#[must_use]
pub fn intersect_authority(
    tenant: &ExecutionAuthority,
    repository: &ExecutionAuthority,
    work_order: &ExecutionAuthority,
) -> ExecutionAuthority {
    let paths = tenant
        .paths
        .intersect(&repository.paths)
        .intersect(&work_order.paths);
    let tools = tenant
        .tools
        .intersect(&repository.tools)
        .intersect(&work_order.tools);
    let budgets = tenant
        .budgets
        .restrict(repository.budgets)
        .restrict(work_order.budgets);
    let delivery = tenant
        .effects
        .delivery
        .restrict(repository.effects.delivery)
        .restrict(work_order.effects.delivery);
    let deployment_environment = if tenant.effects.deployment_environment
        == repository.effects.deployment_environment
        && repository.effects.deployment_environment == work_order.effects.deployment_environment
    {
        tenant.effects.deployment_environment.clone()
    } else {
        None
    };
    ExecutionAuthority {
        paths,
        tools,
        effects: crate::domain::EffectAuthority {
            delivery,
            may_comment: tenant.effects.may_comment
                && repository.effects.may_comment
                && work_order.effects.may_comment,
            may_update_checks: tenant.effects.may_update_checks
                && repository.effects.may_update_checks
                && work_order.effects.may_update_checks,
            deployment_environment,
        },
        budgets,
        required_approval_types: tenant
            .required_approval_types
            .union(&repository.required_approval_types)
            .cloned()
            .chain(work_order.required_approval_types.iter().cloned())
            .collect(),
        sandbox_policy_ref: if tenant.sandbox_policy_ref == repository.sandbox_policy_ref
            && repository.sandbox_policy_ref == work_order.sandbox_policy_ref
        {
            tenant.sandbox_policy_ref.clone()
        } else {
            "refused:mismatched-sandbox-policy".into()
        },
    }
}

#[must_use]
pub const fn v1_risk_delivery_cap(risk: crate::domain::RiskClass) -> DeliveryPermission {
    use crate::domain::RiskClass::{Critical, High, Low, Medium, Unknown};
    match risk {
        Low | Medium | High => DeliveryPermission::PullRequest,
        Critical | Unknown => DeliveryPermission::None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;
    use crate::domain::{BudgetLimits, EffectAuthority, PathAuthority, ToolAuthority};

    fn authority(
        allowed_paths: BTreeSet<String>,
        tools: BTreeSet<String>,
        budget: u64,
    ) -> ExecutionAuthority {
        ExecutionAuthority {
            paths: PathAuthority {
                allowed: allowed_paths,
                forbidden: BTreeSet::new(),
            },
            tools: ToolAuthority {
                allowed_tools: tools,
                allowed_commands: BTreeSet::from(["cargo test".into()]),
                network_destinations: BTreeSet::new(),
            },
            effects: EffectAuthority {
                delivery: DeliveryPermission::PullRequest,
                may_comment: true,
                may_update_checks: true,
                deployment_environment: None,
            },
            budgets: BudgetLimits {
                max_cost_microunits: budget,
                max_input_tokens: budget,
                max_output_tokens: budget,
                max_implementer_invocations: 10,
                max_reviewer_invocations: 10,
                max_fix_iterations: 10,
                max_wall_time_seconds: budget,
                max_external_api_calls: 10,
            },
            required_approval_types: BTreeSet::new(),
            sandbox_policy_ref: "linux-production-v1".into(),
        }
    }

    proptest! {
        #[test]
        fn authority_intersection_never_widens(
            tenant_paths in proptest::collection::btree_set("[a-z]{1,8}", 1..8),
            repository_paths in proptest::collection::btree_set("[a-z]{1,8}", 1..8),
            order_paths in proptest::collection::btree_set("[a-z]{1,8}", 1..8),
            tenant_tools in proptest::collection::btree_set("[a-z]{1,8}", 0..8),
            repository_tools in proptest::collection::btree_set("[a-z]{1,8}", 0..8),
            order_tools in proptest::collection::btree_set("[a-z]{1,8}", 0..8),
            tenant_budget in 1u64..1_000_000,
            repository_budget in 1u64..1_000_000,
            order_budget in 1u64..1_000_000,
        ) {
            let tenant = authority(tenant_paths.clone(), tenant_tools.clone(), tenant_budget);
            let repository = authority(repository_paths.clone(), repository_tools.clone(), repository_budget);
            let order = authority(order_paths.clone(), order_tools.clone(), order_budget);
            let effective = intersect_authority(&tenant, &repository, &order);

            prop_assert!(effective.paths.allowed.is_subset(&tenant_paths));
            prop_assert!(effective.paths.allowed.is_subset(&repository_paths));
            prop_assert!(effective.paths.allowed.is_subset(&order_paths));
            prop_assert!(effective.tools.allowed_tools.is_subset(&tenant_tools));
            prop_assert!(effective.tools.allowed_tools.is_subset(&repository_tools));
            prop_assert!(effective.tools.allowed_tools.is_subset(&order_tools));
            prop_assert!(effective.budgets.max_cost_microunits <= tenant_budget);
            prop_assert!(effective.budgets.max_cost_microunits <= repository_budget);
            prop_assert!(effective.budgets.max_cost_microunits <= order_budget);
        }
    }
}
