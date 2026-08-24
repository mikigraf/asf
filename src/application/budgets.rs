use serde::{Deserialize, Serialize};

use crate::domain::BudgetLimits;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConsumption {
    pub cost_microunits: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub implementer_invocations: u32,
    pub reviewer_invocations: u32,
    pub fix_iterations: u32,
    pub wall_time_seconds: u64,
    pub external_api_calls: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    Cost,
    InputTokens,
    OutputTokens,
    ImplementerInvocations,
    ReviewerInvocations,
    FixIterations,
    WallTime,
    ExternalApiCalls,
}

impl BudgetConsumption {
    #[must_use]
    pub fn exceeded_dimensions(&self, limits: &BudgetLimits) -> Vec<BudgetDimension> {
        let checks = [
            (
                self.cost_microunits > limits.max_cost_microunits,
                BudgetDimension::Cost,
            ),
            (
                self.input_tokens > limits.max_input_tokens,
                BudgetDimension::InputTokens,
            ),
            (
                self.output_tokens > limits.max_output_tokens,
                BudgetDimension::OutputTokens,
            ),
            (
                self.implementer_invocations > limits.max_implementer_invocations,
                BudgetDimension::ImplementerInvocations,
            ),
            (
                self.reviewer_invocations > limits.max_reviewer_invocations,
                BudgetDimension::ReviewerInvocations,
            ),
            (
                self.fix_iterations > limits.max_fix_iterations,
                BudgetDimension::FixIterations,
            ),
            (
                self.wall_time_seconds > limits.max_wall_time_seconds,
                BudgetDimension::WallTime,
            ),
            (
                self.external_api_calls > limits.max_external_api_calls,
                BudgetDimension::ExternalApiCalls,
            ),
        ];
        checks
            .into_iter()
            .filter_map(|(exceeded, dimension)| exceeded.then_some(dimension))
            .collect()
    }

    #[must_use]
    pub fn permits_more_work(&self, limits: &BudgetLimits) -> bool {
        self.exceeded_dimensions(limits).is_empty()
            && self.cost_microunits < limits.max_cost_microunits
            && self.wall_time_seconds < limits.max_wall_time_seconds
            && self.implementer_invocations < limits.max_implementer_invocations
    }

    #[must_use]
    pub fn saturating_add(self, increment: Self) -> Self {
        Self {
            cost_microunits: self
                .cost_microunits
                .saturating_add(increment.cost_microunits),
            input_tokens: self.input_tokens.saturating_add(increment.input_tokens),
            output_tokens: self.output_tokens.saturating_add(increment.output_tokens),
            implementer_invocations: self
                .implementer_invocations
                .saturating_add(increment.implementer_invocations),
            reviewer_invocations: self
                .reviewer_invocations
                .saturating_add(increment.reviewer_invocations),
            fix_iterations: self.fix_iterations.saturating_add(increment.fix_iterations),
            wall_time_seconds: self
                .wall_time_seconds
                .saturating_add(increment.wall_time_seconds),
            external_api_calls: self
                .external_api_calls
                .saturating_add(increment.external_api_calls),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerThresholds {
    pub consecutive_failures: u32,
    pub quarantine_count: u32,
    pub identity_mismatches: u32,
    pub reconciliation_backlog: u32,
    pub daily_cost_microunits: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerSignals {
    pub consecutive_failures: u32,
    pub quarantine_count: u32,
    pub identity_mismatches: u32,
    pub reconciliation_backlog: u32,
    pub daily_cost_microunits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerReason {
    ConsecutiveFailures,
    QuarantineRate,
    IdentityMismatch,
    ReconciliationBacklog,
    DailySpend,
}

#[must_use]
pub fn evaluate_breaker(
    signals: BreakerSignals,
    thresholds: BreakerThresholds,
) -> Vec<BreakerReason> {
    let checks = [
        (
            signals.consecutive_failures >= thresholds.consecutive_failures,
            BreakerReason::ConsecutiveFailures,
        ),
        (
            signals.quarantine_count >= thresholds.quarantine_count,
            BreakerReason::QuarantineRate,
        ),
        (
            signals.identity_mismatches >= thresholds.identity_mismatches,
            BreakerReason::IdentityMismatch,
        ),
        (
            signals.reconciliation_backlog >= thresholds.reconciliation_backlog,
            BreakerReason::ReconciliationBacklog,
        ),
        (
            signals.daily_cost_microunits >= thresholds.daily_cost_microunits,
            BreakerReason::DailySpend,
        ),
    ];
    checks
        .into_iter()
        .filter_map(|(open, reason)| open.then_some(reason))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_evaluation_is_saturating_and_multidimensional() {
        let limits = BudgetLimits {
            max_cost_microunits: 100,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_implementer_invocations: 2,
            max_reviewer_invocations: 2,
            max_fix_iterations: 1,
            max_wall_time_seconds: 60,
            max_external_api_calls: 10,
        };
        let usage = BudgetConsumption {
            cost_microunits: 101,
            wall_time_seconds: 61,
            ..BudgetConsumption::default()
        };
        assert_eq!(
            usage.exceeded_dimensions(&limits),
            vec![BudgetDimension::Cost, BudgetDimension::WallTime]
        );
        assert_eq!(
            BudgetConsumption {
                cost_microunits: u64::MAX,
                ..BudgetConsumption::default()
            }
            .saturating_add(BudgetConsumption {
                cost_microunits: 1,
                ..BudgetConsumption::default()
            })
            .cost_microunits,
            u64::MAX
        );
    }

    #[test]
    fn opened_breaker_stops_new_dispatch_for_any_threshold() {
        let reasons = evaluate_breaker(
            BreakerSignals {
                identity_mismatches: 1,
                ..BreakerSignals::default()
            },
            BreakerThresholds {
                consecutive_failures: 5,
                quarantine_count: 5,
                identity_mismatches: 1,
                reconciliation_backlog: 100,
                daily_cost_microunits: 10_000,
            },
        );
        assert_eq!(reasons, vec![BreakerReason::IdentityMismatch]);
    }
}
