//! PostgreSQL-backed durability primitives.
//!
//! The ledger is the system of record. Queue notifications and in-process
//! channels may reduce latency, but correctness comes from `PostgreSQL` rows,
//! leases, and monotonically increasing fence tokens.

mod jobs;
mod operational_incidents;
mod reservations;
mod run_events;
mod runmill_control_observations;
mod runmill_evidence_ingestion;
mod runmill_observation_streams;
mod runmill_submission_recovery_adoptions;
mod runmill_submission_recovery_cases;
mod runmill_terminal_evidence;
mod runmill_terminal_evidence_jobs;
mod steps;

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::{Error, Result};

pub use jobs::*;
pub use operational_incidents::*;
pub use reservations::*;
pub use run_events::*;
pub use runmill_control_observations::*;
pub use runmill_evidence_ingestion::*;
pub use runmill_observation_streams::*;
pub use runmill_submission_recovery_adoptions::*;
pub use runmill_submission_recovery_cases::*;
pub use runmill_terminal_evidence::*;
pub use runmill_terminal_evidence_jobs::*;
pub use steps::*;

const MIGRATIONS_DIRECTORY_ENV: &str = "ASF_MIGRATIONS_DIR";
pub(crate) const MAX_JOB_LEASE_DURATION: Duration = Duration::from_hours(24);

/// Connection-pool settings that do not contain the database URL or secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgLedgerOptions {
    pub min_connections: u32,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
}

impl Default for PgLedgerOptions {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 16,
            acquire_timeout: Duration::from_secs(10),
            idle_timeout: Some(Duration::from_mins(10)),
            max_lifetime: Some(Duration::from_mins(30)),
        }
    }
}

impl PgLedgerOptions {
    fn validate(&self) -> Result<()> {
        if self.max_connections == 0 {
            return Err(Error::Validation(
                "PostgreSQL max_connections must be positive".into(),
            ));
        }
        if self.min_connections > self.max_connections {
            return Err(Error::Validation(
                "PostgreSQL min_connections cannot exceed max_connections".into(),
            ));
        }
        if self.acquire_timeout.is_zero() {
            return Err(Error::Validation(
                "PostgreSQL acquire timeout must be positive".into(),
            ));
        }
        Ok(())
    }
}

/// Cloneable access to ASF's authoritative `PostgreSQL` ledger.
#[derive(Debug, Clone)]
pub struct PgLedger {
    pool: PgPool,
}

impl PgLedger {
    /// Connect using conservative single-tenant defaults.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty URL and a persistence error if
    /// the pool cannot connect or initialize a session.
    pub async fn connect(database_url: &str) -> Result<Self> {
        Self::connect_with_options(database_url, &PgLedgerOptions::default()).await
    }

    /// Connect without retaining or exposing the database URL.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid settings and a persistence error
    /// if the pool cannot connect or initialize a session.
    pub async fn connect_with_options(
        database_url: &str,
        options: &PgLedgerOptions,
    ) -> Result<Self> {
        if database_url.trim().is_empty() {
            return Err(Error::Validation("database URL must be non-empty".into()));
        }
        options.validate()?;

        let pool = PgPoolOptions::new()
            .min_connections(options.min_connections)
            .max_connections(options.max_connections)
            .acquire_timeout(options.acquire_timeout)
            .idle_timeout(options.idle_timeout)
            .max_lifetime(options.max_lifetime)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("SET TIME ZONE 'UTC'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET application_name = 'asf'")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(|error| persistence_error("connect to PostgreSQL", error))?;

        Ok(Self { pool })
    }

    /// Apply the repository's forward-only migrations at runtime.
    ///
    /// The directory defaults to `./migrations` and can be overridden with
    /// `ASF_MIGRATIONS_DIR`. Production images should set the override to an
    /// absolute packaged path.
    ///
    /// # Errors
    ///
    /// Returns a persistence error if migrations cannot be loaded or applied.
    pub async fn migrate(&self) -> Result<()> {
        let directory = std::env::var_os(MIGRATIONS_DIRECTORY_ENV)
            .map_or_else(|| PathBuf::from("migrations"), PathBuf::from);
        self.migrate_from(directory).await
    }

    /// Apply migrations from an explicit directory without `SQLx` build-time
    /// query or migration macros.
    ///
    /// # Errors
    ///
    /// Returns a persistence error if migrations cannot be loaded or applied.
    pub async fn migrate_from(&self, directory: impl AsRef<Path>) -> Result<()> {
        let migrator = sqlx::migrate::Migrator::new(directory.as_ref())
            .await
            .map_err(|error| persistence_error("load PostgreSQL migrations", error))?;
        migrator
            .run(&self.pool)
            .await
            .map_err(|error| persistence_error("apply PostgreSQL migrations", error))
    }

    /// Verify that a connection can be acquired and the primary answers a
    /// trivial query.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when a connection cannot be acquired or
    /// the health query fails.
    pub async fn health(&self) -> Result<()> {
        let value = sqlx::query_scalar::<_, i32>("SELECT 1::integer")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| persistence_error("check PostgreSQL health", error))?;
        if value != 1 {
            return Err(Error::Persistence(
                "PostgreSQL health query returned an unexpected value".into(),
            ));
        }
        Ok(())
    }

    /// Exposes the pool to repository implementations while keeping pool
    /// construction and connection policy centralized.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Close all pool connections, waiting for checked-out connections to be
    /// returned.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

fn persistence_error(context: &str, error: impl std::fmt::Display) -> Error {
    Error::Persistence(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    /// Strips `-- ...` SQL line comments so statement-cardinality assertions
    /// count only executable SQL, not prose that happens to mention the same
    /// command text (e.g. a comment explaining why `ENABLE TRIGGER` is safe).
    fn strip_sql_line_comments(sql: &str) -> String {
        sql.lines()
            .map(|line| line.find("--").map_or(line, |idx| &line[..idx]))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Collapses all runs of whitespace (including newlines) to a single
    /// space, so multi-line SQL and a single-line expected snippet compare
    /// equal regardless of how the migration wraps a clause.
    fn normalize_sql_whitespace(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Locates the exactly one executable `CREATE OR REPLACE FUNCTION
    /// <name>` definition in `executable` (SQL with `-- ...` line comments
    /// already stripped) and returns its full text, from `CREATE OR REPLACE
    /// FUNCTION` through that same function's own closing `$$;` -- never
    /// spilling into a neighboring function's body. Matches on
    /// `FUNCTION <name>(` so a longer name sharing a prefix (e.g. an
    /// `_v18`-suffixed rename) cannot be mistaken for this one.
    ///
    /// Both the target's `AS $$` body open and its selected `$$;` body
    /// terminator are required to occur strictly before the next executable
    /// `CREATE OR REPLACE FUNCTION` header (if any) following the target's
    /// start. Without this boundary check, a target missing its own
    /// terminator would silently borrow the next function's `AS $$` / `$$;`
    /// instead, spilling the extracted definition into the neighboring
    /// function and letting body-scoped assertions be falsely satisfied
    /// there.
    ///
    /// # Panics
    ///
    /// Panics if `name` is defined zero or more than once, if its `AS $$`
    /// body open is missing or occurs at/after the next `CREATE OR REPLACE
    /// FUNCTION` header, or if its `$$;` body terminator is missing or
    /// occurs at/after that next header.
    fn function_definition<'a>(executable: &'a str, name: &str) -> &'a str {
        let marker = format!("CREATE OR REPLACE FUNCTION {name}(");
        let mut occurrences = executable.match_indices(&marker);
        let (start, _) = occurrences
            .next()
            .unwrap_or_else(|| panic!("missing CREATE OR REPLACE FUNCTION {name}"));
        assert!(
            occurrences.next().is_none(),
            "expected exactly one CREATE OR REPLACE FUNCTION {name}, found more than one"
        );
        let rest = &executable[start..];
        let next_header = rest[marker.len()..]
            .find("CREATE OR REPLACE FUNCTION")
            .map(|idx| idx + marker.len());
        let body_open = rest
            .find("AS $$")
            .unwrap_or_else(|| panic!("{name} has no `AS $$` body open"));
        if let Some(next_header) = next_header {
            assert!(
                body_open < next_header,
                "{name} has no `AS $$` body open before the next CREATE OR REPLACE \
                 FUNCTION header; its definition would spill into the neighboring function"
            );
        }
        let after_open = &rest[body_open..];
        let body_close = after_open
            .find("$$;")
            .unwrap_or_else(|| panic!("{name} has no closing `$$;` body terminator"));
        if let Some(next_header) = next_header {
            assert!(
                body_open + body_close < next_header,
                "{name} has no closing `$$;` body terminator before the next CREATE OR \
                 REPLACE FUNCTION header; its definition would spill into the neighboring \
                 function"
            );
        }
        &rest[..body_open + body_close + "$$;".len()]
    }

    /// Asserts that `function_name`'s own definition inside `migration`
    /// contains `snippet`, after whitespace normalization on both sides --
    /// optionally exactly `expected_count` times. Scoped strictly to that one
    /// function's body via [`function_definition`], so it can never be
    /// satisfied by a migration-wide match: not a different function with a
    /// similar predicate, and not explanatory prose that merely mentions the
    /// same text.
    fn assert_function_body_snippet(
        migration: &str,
        function_name: &str,
        snippet: &str,
        expected_count: Option<usize>,
    ) {
        let executable = strip_sql_line_comments(migration);
        let definition = function_definition(&executable, function_name);
        let normalized_definition = normalize_sql_whitespace(definition);
        let normalized_snippet = normalize_sql_whitespace(snippet);
        match expected_count {
            Some(count) => assert_eq!(
                normalized_definition.matches(&normalized_snippet).count(),
                count,
                "{function_name} must contain `{normalized_snippet}` exactly {count} time(s)"
            ),
            None => assert!(
                normalized_definition.contains(&normalized_snippet),
                "{function_name} is missing `{normalized_snippet}`"
            ),
        }
    }

    /// Asserts that each of `snippets` occurs, in order, inside
    /// `function_name`'s own body -- after whitespace normalization -- with
    /// every search starting strictly after the previous snippet's match end.
    ///
    /// This is stricter than calling [`assert_function_body_snippet`] once
    /// per snippet: independent presence checks are satisfied even if a
    /// snippet has been relocated into an unrelated branch elsewhere in the
    /// same function body, as long as the bare text still occurs somewhere.
    /// Chaining the search cursor forward proves the snippets are anchored to
    /// the same relative position in the function -- e.g. a predicate pair
    /// that was moved into a sibling `IF` branch, or two literals swapped
    /// between two `CASE` arms, breaks the ordering and fails here even
    /// though each snippet in isolation would still be found.
    ///
    /// # Panics
    ///
    /// Panics naming `function_name` and the first snippet (after whitespace
    /// normalization) that could not be found at or after the expected
    /// position, if any snippet is out of order or missing.
    fn assert_function_body_ordered_snippets(
        migration: &str,
        function_name: &str,
        snippets: &[&str],
    ) {
        let executable = strip_sql_line_comments(migration);
        let definition = function_definition(&executable, function_name);
        let normalized_definition = normalize_sql_whitespace(definition);
        let mut cursor = 0;
        for snippet in snippets {
            let normalized_snippet = normalize_sql_whitespace(snippet);
            let relative = normalized_definition[cursor..]
                .find(&normalized_snippet)
                .unwrap_or_else(|| {
                    panic!(
                        "{function_name} is missing ordered anchor `{normalized_snippet}` \
                         at or after position {cursor} in its body"
                    )
                });
            cursor += relative + normalized_snippet.len();
        }
    }

    #[test]
    fn function_definition_stops_before_next_function_header() {
        let executable = "\
CREATE OR REPLACE FUNCTION target(a int)
RETURNS void AS $$
BEGIN
  PERFORM 1;
END;
$$;

CREATE OR REPLACE FUNCTION neighbor(a int)
RETURNS void AS $$
BEGIN
  PERFORM 2;
END;
$$;
";
        let definition = function_definition(executable, "target");
        assert!(definition.contains("PERFORM 1"));
        assert!(!definition.contains("PERFORM 2"));
        assert!(!definition.contains("neighbor"));
    }

    #[test]
    #[should_panic(
        expected = "target has no closing `$$;` body terminator before the next \
                                CREATE OR REPLACE FUNCTION header; its definition would spill \
                                into the neighboring function"
    )]
    fn function_definition_rejects_terminator_borrowed_from_neighbor() {
        // `target`'s own body never closes with `$$;` -- the only `$$;` in
        // the file belongs to `neighbor`. Without the next-header boundary
        // check, `function_definition` would silently walk past `target`'s
        // unterminated body and return a slice that spills into
        // `neighbor`'s definition, letting `neighbor`'s body content satisfy
        // `target`-scoped assertions.
        let executable = "\
CREATE OR REPLACE FUNCTION target(a int)
RETURNS void AS $$
BEGIN
  PERFORM 1;
  -- target never terminates its own body, so this would otherwise consume neighbor's body

CREATE OR REPLACE FUNCTION neighbor(a int)
RETURNS void AS $$
BEGIN
  PERFORM 2;
END;
$$;
";
        function_definition(executable, "target");
    }

    #[test]
    #[should_panic(
        expected = "target has no `AS $$` body open before the next CREATE OR \
                                REPLACE FUNCTION header; its definition would spill into the \
                                neighboring function"
    )]
    fn function_definition_rejects_body_open_borrowed_from_neighbor() {
        // `target` never has its own `AS $$`; the only one in the file
        // belongs to `neighbor`. Without the next-header boundary check,
        // `function_definition` would borrow `neighbor`'s `AS $$` as if it
        // were `target`'s own body open.
        let executable = "\
CREATE OR REPLACE FUNCTION target(a int)
RETURNS void;

CREATE OR REPLACE FUNCTION neighbor(a int)
RETURNS void AS $$
BEGIN
  PERFORM 2;
END;
$$;
";
        function_definition(executable, "target");
    }

    #[test]
    fn pool_options_reject_zero_connections() {
        let options = PgLedgerOptions {
            max_connections: 0,
            ..PgLedgerOptions::default()
        };
        assert!(options.validate().is_err());
    }

    #[test]
    fn pool_options_reject_inverted_bounds() {
        let options = PgLedgerOptions {
            min_connections: 3,
            max_connections: 2,
            ..PgLedgerOptions::default()
        };
        assert!(options.validate().is_err());
    }

    #[test]
    fn initial_migration_contains_durability_guards() {
        let migration = include_str!("../../migrations/0001_initial.sql");
        for required in [
            "attempts_one_active_per_work_item_idx",
            "reservation_sets_require_event",
            "reservations_resource_capacity_idx",
            "identity_capacity_limits",
            "accountability_anchor_removal_guard",
            "accountability_anchor_reference_guard",
            "work_items_cannot_be_deleted",
            "work_orders_immutable",
            "budget_ledger_append_only",
            "budget_ledger_internal_key_guard",
            "worker_sessions_one_active_per_worker_idx",
            "raw_event_worker_session_guard",
            "UNIQUE (tenant_id, run_id, run_aggregate_version)",
            "FOREIGN KEY (tenant_id, run_event_id, run_id, run_aggregate_version)",
            "workflow_jobs_require_dead_letter_escalation",
            "operational_incidents_workflow_job_fk",
            "dead_letter_operational_incident_id",
            "WORKFLOW_JOB_EXHAUSTED",
            "asf_valid_budget_limits",
            "asf_valid_identity_requirements",
            "audit_events_one_root_per_tenant_idx",
            "audit_events_one_successor_idx",
            "FOREIGN KEY (tenant_id, previous_event_hash)",
            "^sha256:[0-9a-f]{64}$",
            "`pr` maps to `pull_request`",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn operational_incident_migration_contains_transactional_lifecycle_guards() {
        let migration = include_str!("../../migrations/0002_operational_incident_lifecycle.sql");
        for required in [
            "operational_incidents_lifecycle_shape",
            "operational_incident_lifecycle_guard",
            "operational_incident_transition_receipts",
            "operational_incident_transition_receipts_append_only",
            "operational_incident_transition_requires_receipt",
            "DEFERRABLE INITIALLY DEFERRED",
            "audit.actor_type = 'OPERATOR'",
            "outbox.payload ->> 'request_digest' = receipt.request_digest",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn work_attempt_binding_migration_closes_cross_binding_gaps() {
        let migration =
            include_str!("../../migrations/0003_work_attempt_bindings_and_shared_escalations.sql");
        for required in [
            "work_orders_attempt_work_item_fk",
            "attempts_exact_work_order_digest_fk",
            "runs_work_order_binding_fk",
            "evidence_bundles_run_binding_fk",
            "evidence_bundles_work_order_binding_fk",
            "evidence_bundles_run_worker_binding_fk",
            "approvals_work_order_binding_fk",
            "escalations_run_binding_fk",
            "budget_ledger_attempt_work_item_fk",
            "budget_ledger_attempt_scope_binding",
            "reservation_sets_work_repository_fk",
            "workflow_jobs_attempt_work_item_fk",
            "workflow_timers_attempt_work_item_fk",
            "effect_intents_attempt_work_item_fk",
            "audit_events_attempt_work_item_fk",
            "workflow_jobs_binding_shape",
            "workflow_timers_binding_shape",
            "escalation.attempt_id IS NOT DISTINCT FROM NEW.attempt_id",
            "jsonb_build_array('workflow-job:' || NEW.id::text)",
            "operational_incidents_active_authority",
            "operational_incident_active_authority_guard",
            "outbox_semantics_immutable",
            "outbox identity and semantic fields are immutable",
            "workflow_jobs_immutable",
            "terminal workflow jobs are immutable",
            "workflow_timers_lifecycle_shape",
            "workflow_timers_immutable",
            "terminal workflow timers are immutable",
            "idempotency_records_response_shape",
            "idempotency_records_immutable",
            "terminal idempotency records are immutable",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn reservation_internal_event_migration_binds_future_sweep_keys() {
        let migration = include_str!("../../migrations/0004_reservation_internal_event_guard.sql");
        for required in [
            "asf_guard_internal_reservation_event_key",
            "reservation_set_events_internal_key_guard",
            "budget_ledger_one_reservation_transition_idx",
            "budget_ledger_zz_reservation_binding_guard",
            "budget_reservations_require_accounting",
            "reservation_sets_terminal_transition_time",
            "incomplete budget RELEASE accounting",
            "bound_state <> 'EXPIRED'",
            "NEW.occurred_at IS DISTINCT FROM bound_released_at",
            "FOR KEY SHARE",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn cancellation_effect_owner_migration_uses_exact_workflow_job_identity() {
        let migration = include_str!("../../migrations/0005_effect_intent_exact_job_ownership.sql");
        for required in [
            "owning_workflow_job_id",
            "effect_intents_owning_workflow_job_fk",
            "effect_intents_cancellation_owner_shape",
            "effect_intents_exact_cancellation_owner",
            "owning_job.id = NEW.owning_workflow_job_id",
            "status = 'AMBIGUOUS'",
            "reconcile the unchanged request",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn final_cross_binding_migration_serializes_and_freezes_terminal_facts() {
        let migration = include_str!("../../migrations/0006_cross_binding_and_terminal_guards.sql");
        for required in [
            "runs_event_worker_binding_unique",
            "raw_run_events_run_worker_binding_fk",
            "budget_accounting_version",
            "SET budget_accounting_version =",
            "FOR UPDATE;",
            "OLD.status IN ('COMPLETED', 'DEAD', 'CANCELLED')",
            "effect_intents_terminal_immutable",
            "terminal effect intents are immutable",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn operational_incident_receipts_and_owners_are_reciprocally_proven() {
        let migration =
            include_str!("../../migrations/0007_operational_incident_reciprocal_proofs.sql");
        for required in [
            "asf_operational_incident_lifecycle_digest",
            "asf_operational_incident_transition_request_digest",
            "asf_operational_incident_transition_audit_hash",
            "audit.before_digest = expected_before_digest",
            "audit.after_digest = expected_after_digest",
            "audit.event_hash =",
            "audit.details = jsonb_set",
            "outbox.payload = jsonb_build_object",
            "outbox.headers =",
            "outbox.status = 'PENDING'",
            "outbox.published_at IS NULL",
            "operational_incidents_exact_job_idempotency",
            "operational_incidents_require_dead_job_owner",
            "job.dead_letter_operational_incident_id = NEW.id",
            "'operational-job-exhausted:' || NEW.workflow_job_id::text",
            "jsonb_build_array('workflow-job:' || NEW.workflow_job_id::text)",
            "DEFERRABLE INITIALLY DEFERRED",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn runmill_submission_effects_bind_immutable_authority_and_exact_job_owners() {
        let migration =
            include_str!("../../migrations/0008_runmill_submission_effect_ownership.sql");
        for required in [
            "work_orders_submission_binding_key",
            "effect_intents_submission_binding_shape",
            "effect_intents_submission_work_order_fk",
            "effect_intents_one_runmill_submission_per_attempt_idx",
            "effect_intents_runmill_mutation_owner_shape",
            "effect_intents_exact_runmill_mutation_owner",
            "owning_job.id = NEW.owning_workflow_job_id",
            "owning_job.job_type = required_job_type",
            "ADVANCE_ACCEPTED_WORK_ITEM",
            "NEW.work_order_id IS DISTINCT FROM OLD.work_order_id",
            "NEW.work_order_digest IS DISTINCT FROM OLD.work_order_digest",
            "reconcile the unchanged submission request",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn source_close_observation_uses_the_transaction_start_lease_boundary() {
        let migration =
            include_str!("../../migrations/0013_source_closure_terminal_invariants.sql");
        let guard = migration
            .split_once(
                "CREATE FUNCTION asf_guard_source_close_observation_transition() RETURNS trigger",
            )
            .expect("source-close observation guard exists")
            .1
            .split_once("CREATE TRIGGER effect_intents_source_close_observation_transition")
            .expect("source-close observation trigger exists")
            .0;
        assert!(
            guard.contains("observing_job.lease_expires_at > transaction_timestamp()"),
            "the observation must retain authority from the prelocked transaction start"
        );
        assert!(
            !guard.contains("observing_job.lease_expires_at > clock_timestamp()"),
            "wall-clock drift inside the atomic final transaction must not revoke its prelocked claim"
        );
    }

    #[test]
    fn verified_evidence_freezes_its_exact_signed_artifact_manifest() {
        let migration =
            include_str!("../../migrations/0015_verified_evidence_artifact_integrity.sql");
        for required in [
            "asf_valid_evidence_artifacts_are_exact",
            "evidence_verifications_require_exact_artifacts",
            "valid_evidence_artifact_links_frozen",
            "artifacts_immutable",
            "evidence_artifacts_immutable",
            "artifacts_truncate_forbidden",
            "evidence_artifacts_truncate_forbidden",
            "envelope_artifact_digest",
            "effective_policy_artifact_digest",
            "normalized_diff_artifact_digest",
            "evidence_artifact_manifest_guards",
            "asf_advance_evidence_artifact_manifest_guard",
            "manifest_artifact_id",
            "manifest_kind",
            "artifact.created_at <= candidate_verified_at",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
        assert!(
            !migration.contains("FOR UPDATE OF evidence"),
            "a non-mutating evidence-row lock does not close RR write skew"
        );
    }

    #[test]
    fn valid_evidence_receipts_reproduce_exact_github_and_job_chronology() {
        let migration =
            include_str!("../../migrations/0016_evidence_verification_receipt_integrity.sql");
        for required in [
            "asf_evidence_verification_details_are_strict",
            "asf_evidence_verification_ci_set",
            "asf_evidence_verification_timestamp",
            "asf_evidence_verification_github_pr_url",
            "workflow_jobs_exact_verify_evidence_completion",
            "evidence_verifications_valid_receipt_db_clock",
            "evidence_verification_receipt_upgrade_requires_exact_history",
            "evidence_verifications_valid_receipt_v1_strict",
            "evidence_verifications_truncate_forbidden",
            "OLD.status IS DISTINCT FROM 'RUNNING'",
            "NEW.completed_by IS DISTINCT FROM OLD.lease_owner",
            "NEW.completion_fence_token IS DISTINCT FROM OLD.fence_token",
            "NEW.completed_at := clock_timestamp()",
            "evidence.payload #>> '{predicate,delivery,pull_request,url}'",
            "evidence.payload #> '{predicate,policy,required_ci_contexts}'",
            "verification.verified_at BETWEEN",
            "job.completed_at + interval '5 minutes'",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn v1_single_tenant_migration_uses_an_append_only_deployment_guard() {
        let migration = include_str!("../../migrations/0020_v1_single_tenant_boundary.sql");
        for required in [
            "LOCK TABLE tenants IN ACCESS EXCLUSIVE MODE",
            "v1_tenant_boundary_upgrade_requires_at_most_one_tenant",
            "v1_tenant_deployment_guards",
            "configured_tenant_id uuid REFERENCES tenants(id)",
            "v1_tenant_deployment_guard_append_only",
            "v1_tenant_deployment_guard_requires_exactly_one_tenant",
            "v1_tenant_boundary_configured_tenant_only",
            "v1_tenant_boundary_delete_forbidden",
            "v1_tenant_boundary_truncate_forbidden",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
    }

    #[test]
    fn activity_contract_migration_binds_immutable_identity_with_no_default_and_refusal_guard() {
        let migration = include_str!("../../migrations/0023_workflow_activity_contracts.sql");
        for required in [
            "LOCK TABLE workflow_jobs IN ACCESS EXCLUSIVE MODE",
            "LOCK TABLE workflow_timers IN ACCESS EXCLUSIVE MODE",
            "cannot install activity contract identity while a workflow job has a non-production job_type",
            "workflow_jobs_activity_contract_backfill_requires_production_job_types",
            "cannot install activity contract identity while a workflow timer has a non-production timer_type",
            "workflow_timers_activity_contract_backfill_requires_production_timer_types",
            "ADD COLUMN activity_contract_id text",
            "WHEN 'INTAKE_SYNC' THEN 'asf.activity/intake-sync/v1'",
            "WHEN 'ADVANCE_ACCEPTED_WORK_ITEM' THEN 'asf.activity/advance-accepted-work-item/v1'",
            "WHEN 'REQUEST_WORK_ITEM_CANCELLATION' THEN 'asf.activity/request-work-item-cancellation/v1'",
            "WHEN 'APPLY_SIGNED_APPROVAL_DECISION' THEN 'asf.activity/apply-signed-approval-decision/v1'",
            "WHEN 'RECONCILE_WORKER' THEN 'asf.activity/reconcile-worker/v1'",
            "WHEN 'OBSERVE_RUNMILL_RUN' THEN 'asf.activity/observe-runmill-run/v2'",
            "WHEN 'VERIFY_EVIDENCE' THEN 'asf.activity/verify-evidence/v1'",
            "WHEN 'CLOSE_SOURCE' THEN 'asf.activity/close-source/v1'",
            "No DEFAULT: every caller must supply the exact contract identity",
            "ALTER COLUMN activity_contract_id SET NOT NULL",
            "workflow_jobs_activity_contract_id_shape CHECK (\n        activity_contract_id ~ '^[a-z0-9]+([./-][a-z0-9]+)*$'",
            "workflow_timers_activity_contract_id_shape CHECK (\n        activity_contract_id ~ '^[a-z0-9]+([./-][a-z0-9]+)*$'",
            "NEW.job_type,\n        NEW.activity_contract_id,\n        NEW.payload",
            "OLD.job_type,\n        OLD.activity_contract_id,\n        OLD.payload",
            "NEW.timer_type,\n        NEW.activity_contract_id,\n        NEW.due_at",
            "OLD.timer_type,\n        OLD.activity_contract_id,\n        OLD.due_at",
            "workflow job identity and request fields are immutable",
            "workflow timer identity and request fields are immutable",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
        assert!(!migration.contains("Phase 1"));
        assert!(!migration.contains("phase 2"));
    }

    #[test]
    fn activity_contract_migration_disables_dispatch_fact_mutation_triggers_only_around_the_backfill()
     {
        let migration = include_str!("../../migrations/0023_workflow_activity_contracts.sql");

        let disable_jobs = migration
            .find(
                "ALTER TABLE workflow_jobs DISABLE TRIGGER workflow_jobs_note_dispatch_fact_mutation;",
            )
            .expect("workflow_jobs dispatch-fact mutation trigger must be disabled for the backfill");
        let disable_timers = migration
            .find(
                "ALTER TABLE workflow_timers DISABLE TRIGGER workflow_timers_note_dispatch_fact_mutation;",
            )
            .expect(
                "workflow_timers dispatch-fact mutation trigger must be disabled for the backfill",
            );
        let update_jobs = migration
            .find("UPDATE workflow_jobs\nSET activity_contract_id = CASE job_type")
            .expect("workflow_jobs activity_contract_id backfill must exist");
        let update_timers = migration
            .find("UPDATE workflow_timers\nSET activity_contract_id = CASE timer_type")
            .expect("workflow_timers activity_contract_id backfill must exist");
        let enable_jobs = migration
            .find(
                "ALTER TABLE workflow_jobs ENABLE TRIGGER workflow_jobs_note_dispatch_fact_mutation;",
            )
            .expect(
                "workflow_jobs dispatch-fact mutation trigger must be re-enabled after the backfill",
            );
        let enable_timers = migration
            .find(
                "ALTER TABLE workflow_timers ENABLE TRIGGER workflow_timers_note_dispatch_fact_mutation;",
            )
            .expect(
                "workflow_timers dispatch-fact mutation trigger must be re-enabled after the backfill",
            );
        let drain_immediate = migration
            .find("SET CONSTRAINTS ALL IMMEDIATE;")
            .expect(
                "pending deferred constraint-trigger events must be drained before re-enabling triggers",
            );
        let drain_deferred = migration
            .find("SET CONSTRAINTS ALL DEFERRED;")
            .expect("deferred constraint checking must be restored after draining");

        assert!(
            disable_jobs < update_jobs && disable_timers < update_jobs,
            "both dispatch-fact mutation triggers must be disabled before either backfill UPDATE runs"
        );
        assert!(
            update_jobs < update_timers,
            "the workflow_jobs backfill must run before the workflow_timers backfill"
        );
        assert!(
            update_timers < drain_immediate,
            "both backfill UPDATEs must finish before pending deferred trigger events are drained"
        );
        assert!(
            drain_immediate < drain_deferred,
            "pending events must be fired immediate before deferred checking is restored"
        );
        assert!(
            drain_deferred < enable_jobs && drain_deferred < enable_timers,
            "deferred checking must be restored before either trigger is re-enabled, proving the \
             ALTER TABLE ... ENABLE TRIGGER calls run with no pending trigger events outstanding"
        );

        // Only the two named mutation-note triggers are touched. The
        // identity/immutability triggers are dropped and recreated (not
        // disabled), and no blanket ALL/USER trigger disable is used.
        //
        // These cardinality checks run against `executable`, the migration
        // with `-- ...` comments stripped, so explanatory prose that mentions
        // "ENABLE TRIGGER" or "DISABLE TRIGGER" (as this migration's own
        // comments do) cannot inflate the count of actual statements.
        let executable = strip_sql_line_comments(migration);
        assert!(!executable.contains("DISABLE TRIGGER workflow_jobs_immutable"));
        assert!(!executable.contains("DISABLE TRIGGER workflow_timers_immutable"));
        assert!(!executable.contains("DISABLE TRIGGER ALL"));
        assert!(!executable.contains("DISABLE TRIGGER USER"));
        assert_eq!(executable.matches("DISABLE TRIGGER").count(), 2);
        assert_eq!(executable.matches("ENABLE TRIGGER").count(), 2);
        // Exactly one drain-and-restore pair: the backfill queues pending
        // events on every other DEFERRABLE constraint trigger on these two
        // tables (none carry a WHEN clause), not only on the two disabled
        // above, so all of them must be flushed once before either ALTER
        // TABLE ... ENABLE TRIGGER call, and the deferred default restored
        // exactly once immediately after.
        assert_eq!(
            executable.matches("SET CONSTRAINTS ALL IMMEDIATE;").count(),
            1
        );
        assert_eq!(
            executable.matches("SET CONSTRAINTS ALL DEFERRED;").count(),
            1
        );
    }

    #[tokio::test]
    async fn live_activity_contract_id_is_part_of_the_immutable_request_identity() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Contract test')",
        )
        .bind(tenant_id)
        .bind(format!("contract-{tenant_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert contract-immutability tenant");
        sqlx::query(
            r"
            INSERT INTO workflow_jobs (
                id, tenant_id, job_type, activity_contract_id, payload, idempotency_key
            ) VALUES ($1, $2, 'RUNTIME_TEST_COMPLETE', 'test.activity/runtime-test-complete/v1', '{}'::jsonb, $3)
            ",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(format!("contract-immutability-{job_id}"))
        .execute(ledger.pool())
        .await
        .expect("insert non-terminal contract-immutability job");

        // The identity/request tuple — activity_contract_id included — is
        // immutable even while the job is still PENDING; only lifecycle
        // columns (status, lease, attempt bookkeeping, ...) may change.
        let changed = sqlx::query(
            "UPDATE workflow_jobs SET activity_contract_id = $3 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .bind("test.activity/runtime-test-complete/v2")
        .execute(ledger.pool())
        .await;
        let error = changed
            .expect_err("changing a non-terminal job's activity_contract_id must be rejected");
        let message = error
            .as_database_error()
            .map(|db_error| db_error.message().to_owned());
        assert_eq!(
            message.as_deref(),
            Some("workflow job identity and request fields are immutable")
        );

        let unchanged: String = sqlx::query_scalar(
            "SELECT activity_contract_id FROM workflow_jobs WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load unchanged job activity contract id");
        assert_eq!(unchanged, "test.activity/runtime-test-complete/v1");
    }

    #[tokio::test]
    async fn live_acceptance_json_guards_reject_invalid_objects_when_configured() {
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let (
            valid_budget,
            empty_budget,
            string_budget,
            zero_role_budget,
            extra_budget_key,
            valid_identities,
            empty_identities,
            same_implementer_and_reviewer,
            malformed_identities,
            extra_identity_key,
        ) = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool)>(
            r#"
            SELECT
                asf_valid_budget_limits(
                    '{
                        "max_cost_microunits": 0,
                        "max_input_tokens": 0,
                        "max_output_tokens": 0,
                        "max_implementer_invocations": 1,
                        "max_reviewer_invocations": 1,
                        "max_fix_iterations": 0,
                        "max_wall_time_seconds": 1,
                        "max_external_api_calls": 0
                    }'::jsonb
                ),
                asf_valid_budget_limits('{}'::jsonb),
                asf_valid_budget_limits(
                    '{
                        "max_cost_microunits": "0",
                        "max_input_tokens": 0,
                        "max_output_tokens": 0,
                        "max_implementer_invocations": 1,
                        "max_reviewer_invocations": 1,
                        "max_fix_iterations": 0,
                        "max_wall_time_seconds": 1,
                        "max_external_api_calls": 0
                    }'::jsonb
                ),
                asf_valid_budget_limits(
                    '{
                        "max_cost_microunits": 0,
                        "max_input_tokens": 0,
                        "max_output_tokens": 0,
                        "max_implementer_invocations": 0,
                        "max_reviewer_invocations": 1,
                        "max_fix_iterations": 0,
                        "max_wall_time_seconds": 1,
                        "max_external_api_calls": 0
                    }'::jsonb
                ),
                asf_valid_budget_limits(
                    '{
                        "max_cost_microunits": 0,
                        "max_input_tokens": 0,
                        "max_output_tokens": 0,
                        "max_implementer_invocations": 1,
                        "max_reviewer_invocations": 1,
                        "max_fix_iterations": 0,
                        "max_wall_time_seconds": 1,
                        "max_external_api_calls": 0,
                        "unexpected": true
                    }'::jsonb
                ),
                asf_valid_identity_requirements(
                    '{
                        "implementer": "codex:implementer",
                        "local_reviewer": "claude:local-reviewer",
                        "pr_reviewer": "codex:pr-reviewer"
                    }'::jsonb
                ),
                asf_valid_identity_requirements('{}'::jsonb),
                asf_valid_identity_requirements(
                    '{
                        "implementer": "codex:same",
                        "local_reviewer": "codex:same",
                        "pr_reviewer": "claude:reviewer"
                    }'::jsonb
                ),
                asf_valid_identity_requirements(
                    '{
                        "implementer": "shell:implementer",
                        "local_reviewer": "claude:local-reviewer",
                        "pr_reviewer": "codex:pr-reviewer"
                    }'::jsonb
                ),
                asf_valid_identity_requirements(
                    '{
                        "implementer": "codex:implementer",
                        "local_reviewer": "claude:local-reviewer",
                        "pr_reviewer": "codex:pr-reviewer",
                        "unexpected": true
                    }'::jsonb
                )
            "#,
        )
        .fetch_one(ledger.pool())
        .await
        .expect("evaluate acceptance JSON guards");
        assert!(valid_budget);
        assert!(!empty_budget);
        assert!(!string_budget);
        assert!(!zero_role_budget);
        assert!(!extra_budget_key);
        assert!(valid_identities);
        assert!(!empty_identities);
        assert!(!same_implementer_and_reviewer);
        assert!(!malformed_identities);
        assert!(!extra_identity_key);
    }

    /// Every table `0024` locks `SHARE ROW EXCLUSIVE`, in the exact order the
    /// migration's own comment documents (migration 0001's table-creation
    /// order, then 0017, 0018, 0021, and 0022). This is the full writer/
    /// trigger and poisoned-history-proof-root surface for the
    /// `ADVANCE_ACCEPTED_WORK_ITEM`, `REQUEST_WORK_ITEM_CANCELLATION`,
    /// `CLOSE_SOURCE`, `VERIFY_EVIDENCE`, and `OBSERVE_RUNMILL_RUN` families
    /// this migration touches.
    const ACTIVITY_CONTRACT_AUTHORITY_PROOF_LOCKED_TABLES: [&str; 42] = [
        "repositories",
        "source_snapshots",
        "work_items",
        "workers",
        "worker_sessions",
        "attempts",
        "work_orders",
        "runs",
        "approvals",
        "escalations",
        "operational_incidents",
        "evidence_bundles",
        "evidence_verifications",
        "reservation_sets",
        "reservations",
        "reservation_set_events",
        "budget_ledger",
        "workflow_instances",
        "workflow_jobs",
        "workflow_timers",
        "effect_intents",
        "outbox",
        "audit_events",
        "accountability_anchors",
        "idempotency_records",
        "work_dispatch_fact_guards",
        "work_cancellation_authority_guards",
        "runmill_cancellation_observations",
        "cancellation_terminal_receipts",
        "terminal_conflict_escalation_merge_receipts",
        "cancellation_escalation_supersession_receipts",
        "cancellation_supersession_escalation_facts",
        "cancellation_supersession_anchor_facts",
        "cancellation_supersession_work_facts",
        "runmill_control_snapshots",
        "raw_runmill_control_events",
        "runmill_control_snapshot_events",
        "runmill_run_observation_streams",
        "runmill_run_observation_checkpoints",
        "runmill_run_observation_results",
        "runmill_observation_gap_escalation_bindings",
        "runmill_observation_terminal_failure_facts",
    ];

    /// The exact 25 `CREATE OR REPLACE FUNCTION` names `0024` replaces, in
    /// file order: every trigger/helper function across the
    /// `ADVANCE_ACCEPTED_WORK_ITEM`, `REQUEST_WORK_ITEM_CANCELLATION`,
    /// `CLOSE_SOURCE`, `VERIFY_EVIDENCE`, and `OBSERVE_RUNMILL_RUN` authority-
    /// proof families, each hardened over its final active pre-0024 body.
    /// Most gain exactly one added `activity_contract_id` predicate, but this
    /// is not universal: `asf_guard_external_mutation_effect_owner` adds
    /// three contract literals (one per CASE branch) plus a dynamic
    /// `= required_contract_id` predicate, and `asf_guard_source_close_job_completion`
    /// / `asf_guard_verify_evidence_job_completion` each add one `OLD` and one
    /// `NEW` `IS DISTINCT FROM` predicate. See the body-scoped assertions
    /// below for the exact shape each function gets.
    const ACTIVITY_CONTRACT_AUTHORITY_PROOF_REPLACED_FUNCTIONS: [&str; 25] = [
        "asf_assert_runmill_observation_gap_escalation_binding_insert",
        "asf_assert_runmill_observation_terminal_failure_fact_insert",
        "asf_assert_runmill_observation_checkpoint_insert",
        "asf_guard_runmill_observation_stream",
        // The final active migration-0022 definition of the OBSERVE_RUNMILL_RUN
        // control-snapshot writer, carried forward unrenamed.
        "asf_stamp_runmill_control_snapshot",
        "asf_guard_external_mutation_effect_owner",
        "asf_guard_source_close_observation_transition",
        "asf_guard_source_close_job_completion",
        // Migration 0013 originally defined this as
        // `asf_observed_source_closure_is_valid`; migration 0019 renamed (did
        // not replace) it to this `_v18` name.
        "asf_observed_source_closure_chain_v18",
        "asf_work_closure_reservation_release_is_valid",
        "asf_guard_verify_evidence_job_completion",
        "asf_valid_evidence_verification_is_exact",
        "asf_stamp_runmill_cancellation_observation",
        // Dual-state cancellation request/observation helpers.
        "asf_valid_runmill_cancellation_effect_request",
        "asf_valid_runmill_cancellation_effect_observation",
        // Dispatch-fact functions.
        "asf_note_work_dispatch_fact",
        "asf_note_work_dispatch_fact_mutation",
        "asf_valid_pre_dispatch_cancellation_receipt",
        "asf_guard_cancellation_job_terminal_transition",
        "asf_assert_completed_cancellation_observation",
        "asf_assert_completed_cancellation_job_observation",
        "asf_capture_terminal_conflict_escalation_merge_receipt",
        "asf_valid_runmill_cancellation_receipt",
        "asf_assert_nonterminal_cancellation_observer_obligation",
        // Migration 0018 renamed (did not replace) this from its earlier name
        // to this `_v18` name.
        "asf_valid_cancellation_supersession_receipt_v18",
    ];

    #[test]
    fn activity_contract_authority_proof_migration_locks_every_writer_and_refuses_poisoned_history()
    {
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        assert!(migration.contains("activity_contract_authority_proof_upgrade_preflight"));
        assert!(migration.contains(
            "migration 0024 refuses to upgrade activity contract authority proofs over \
             poisoned history"
        ));

        // No trigger is dropped, disabled, or recreated -- only function
        // bodies change, resolved by stable OID under CREATE OR REPLACE.
        // Comments are stripped first so prose that merely mentions these
        // commands (as this migration's own header does) cannot hide a real
        // one, or be mistaken for one.
        let executable = strip_sql_line_comments(migration);
        for forbidden in ["DISABLE TRIGGER", "DROP TRIGGER", "CREATE TRIGGER"] {
            for line in executable.lines() {
                assert!(
                    !line.trim_start().starts_with(forbidden),
                    "unexpected executable `{forbidden}` line: {line}"
                );
            }
        }

        // The full 42-table lock block, in file order, covers every writer/
        // trigger table these functions touch plus every proof-root table the
        // preflight below reads.
        for table in ACTIVITY_CONTRACT_AUTHORITY_PROOF_LOCKED_TABLES {
            assert!(
                migration.contains(&format!("LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE;")),
                "missing lock on {table}"
            );
        }
        assert_eq!(
            executable.matches("LOCK TABLE").count(),
            ACTIVITY_CONTRACT_AUTHORITY_PROOF_LOCKED_TABLES.len(),
            "the lock block must cover exactly the 42 current tables, no more, no fewer"
        );
        // Explicitly called out by name: workflow_jobs/effect_intents are the
        // shared job/effect writer surface, evidence_verifications and the
        // cancellation receipt family are direct proof roots, the
        // reservation tables are the source-closure release surface, and the
        // runmill_run_observation_* tables are the OBSERVE_RUNMILL_RUN
        // observer proof roots.
        for table in [
            "workflow_jobs",
            "effect_intents",
            "evidence_verifications",
            "cancellation_terminal_receipts",
            "terminal_conflict_escalation_merge_receipts",
            "cancellation_escalation_supersession_receipts",
            "reservation_sets",
            "reservations",
            "runmill_run_observation_streams",
            "runmill_run_observation_checkpoints",
            "runmill_run_observation_results",
            "runmill_observation_gap_escalation_bindings",
            "runmill_observation_terminal_failure_facts",
        ] {
            assert!(
                ACTIVITY_CONTRACT_AUTHORITY_PROOF_LOCKED_TABLES.contains(&table),
                "{table} must be explicitly represented in the lock block"
            );
        }

        // The five canonical contract literals installed by migration 0023.
        for contract_id in [
            "asf.activity/advance-accepted-work-item/v1",
            "asf.activity/request-work-item-cancellation/v1",
            "asf.activity/close-source/v1",
            "asf.activity/verify-evidence/v1",
            "asf.activity/observe-runmill-run/v2",
        ] {
            assert!(
                migration.contains(contract_id),
                "missing canonical contract literal {contract_id}"
            );
        }
        // Representative exact predicates: each authority-proof family gains
        // exactly one added activity_contract_id equality check.
        for predicate in [
            "job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
            "observing_job.activity_contract_id = 'asf.activity/close-source/v1'",
            "job.activity_contract_id = 'asf.activity/verify-evidence/v1'",
            "job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
            "job.activity_contract_id = 'asf.activity/advance-accepted-work-item/v1'",
            "NEW.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
        ] {
            assert!(
                migration.contains(predicate),
                "missing predicate {predicate}"
            );
        }

        // Every direct proof root the poisoned-history preflight reads, plus
        // the durable parent/child observation_job result chain, must be
        // present -- and only within the preflight prefix that runs before
        // any function is replaced.
        let first_function_replacement = executable
            .find("CREATE OR REPLACE FUNCTION")
            .expect("migration replaces at least one function");
        let preflight_prefix = &executable[..first_function_replacement];
        for proof_root in [
            "effect_intents",
            "cancellation_terminal_receipts",
            "runmill_cancellation_observations",
            "terminal_conflict_escalation_merge_receipts",
            "cancellation_escalation_supersession_receipts",
            "evidence_verifications",
            "runmill_run_observation_checkpoints",
            "runmill_control_snapshots",
            "runmill_run_observation_streams",
            "runmill_observation_gap_escalation_bindings",
            "runmill_observation_terminal_failure_facts",
            "result #> '{result,observation_job,id}' IS NOT NULL",
            "parent.result #>> '{result,observation_job,id}' = job.id::text",
        ] {
            assert!(
                preflight_prefix.contains(proof_root),
                "preflight is missing proof root {proof_root}"
            );
        }

        // This protects isolated incompatible queue rows: an isolated
        // PENDING/RETRY job with a wrong contract id and no durable proof
        // root must never be refused, so the preflight must never blanket-
        // filter on job.status at all.
        assert!(!preflight_prefix.contains("job.status NOT IN"));
        assert!(!preflight_prefix.contains("job.status IN"));
    }

    #[test]
    fn activity_contract_authority_proof_migration_replaces_exactly_the_expected_functions() {
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");
        let executable = strip_sql_line_comments(migration);

        for name in ACTIVITY_CONTRACT_AUTHORITY_PROOF_REPLACED_FUNCTIONS {
            assert!(
                migration.contains(&format!("CREATE OR REPLACE FUNCTION {name}")),
                "missing CREATE OR REPLACE FUNCTION {name}"
            );
        }
        assert_eq!(
            executable.matches("CREATE OR REPLACE FUNCTION").count(),
            ACTIVITY_CONTRACT_AUTHORITY_PROOF_REPLACED_FUNCTIONS.len(),
            "0024 must replace exactly the 25 expected functions, no more, no fewer"
        );
    }

    /// The 14 (of `0024`'s 25) functions whose added activity-contract
    /// hardening is exactly one scoped `job_type = '...' AND ...
    /// activity_contract_id = '...'` pair, present exactly once in that
    /// function's own body.
    ///
    /// Every other function among the 25 needs more than one body-scoped
    /// assertion -- e.g. multiple CASE branches, a dynamic predicate, paired
    /// `OLD`/`NEW` checks, a pair occurring more than once, or JSON-accessor
    /// predicates that cannot be expressed as one contiguous snippet -- and
    /// gets its own `#[test]` instead (see the `activity_contract_authority_
    /// proof_*` tests below this table). Together, this table and those
    /// dedicated tests give every one of the 25 functions in
    /// `ACTIVITY_CONTRACT_AUTHORITY_PROOF_REPLACED_FUNCTIONS` at least one
    /// body-scoped contract assertion.
    const ACTIVITY_CONTRACT_SINGLE_SCOPED_PAIR_FUNCTIONS: [(&str, &str); 14] = [
        (
            "asf_assert_runmill_observation_gap_escalation_binding_insert",
            "job.job_type = 'OBSERVE_RUNMILL_RUN' \
             AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
        ),
        (
            "asf_assert_runmill_observation_terminal_failure_fact_insert",
            "job.job_type = 'OBSERVE_RUNMILL_RUN' \
             AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
        ),
        (
            "asf_assert_runmill_observation_checkpoint_insert",
            "job.job_type = 'OBSERVE_RUNMILL_RUN' \
             AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
        ),
        (
            "asf_guard_runmill_observation_stream",
            "job.job_type = 'OBSERVE_RUNMILL_RUN' \
             AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
        ),
        (
            "asf_stamp_runmill_control_snapshot",
            "job.job_type = 'OBSERVE_RUNMILL_RUN' \
             AND job.activity_contract_id = 'asf.activity/observe-runmill-run/v2'",
        ),
        (
            "asf_guard_source_close_observation_transition",
            "observing_job.job_type = 'CLOSE_SOURCE' \
             AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'",
        ),
        (
            "asf_observed_source_closure_chain_v18",
            "observing_job.job_type = 'CLOSE_SOURCE' \
             AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'",
        ),
        (
            "asf_work_closure_reservation_release_is_valid",
            "observing_job.job_type = 'CLOSE_SOURCE' \
             AND observing_job.activity_contract_id = 'asf.activity/close-source/v1'",
        ),
        (
            "asf_valid_evidence_verification_is_exact",
            "job.job_type = verification.workflow_job_type \
             AND job.activity_contract_id = 'asf.activity/verify-evidence/v1'",
        ),
        (
            "asf_valid_pre_dispatch_cancellation_receipt",
            "job.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM' \
             AND job.activity_contract_id = 'asf.activity/advance-accepted-work-item/v1'",
        ),
        (
            "asf_assert_completed_cancellation_observation",
            "job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
        ),
        (
            "asf_capture_terminal_conflict_escalation_merge_receipt",
            "job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
        ),
        (
            "asf_valid_runmill_cancellation_receipt",
            "job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
        ),
        (
            "asf_valid_cancellation_supersession_receipt_v18",
            "job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
        ),
    ];

    #[test]
    fn activity_contract_authority_proof_functions_gain_their_scoped_predicate_pair_exactly_once() {
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");
        for (function_name, snippet) in ACTIVITY_CONTRACT_SINGLE_SCOPED_PAIR_FUNCTIONS {
            assert_function_body_snippet(migration, function_name, snippet, Some(1));
        }
    }

    #[test]
    fn asf_guard_external_mutation_effect_owner_binds_all_three_provider_branches_and_the_dynamic_owner_check()
     {
        const FUNCTION_NAME: &str = "asf_guard_external_mutation_effect_owner";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        // Each CASE branch maps one exact (provider, effect_type) pair to its
        // canonical contract literal, exactly once -- and, critically, each
        // full `WHEN provider AND effect_type THEN contract` clause is
        // anchored, in file order, to the `required_contract_id := CASE`
        // statement specifically. `required_job_type := CASE` immediately
        // above it shares the same three `WHEN` conditions (mapped to job
        // types, not contract literals), so binding the full contiguous
        // `WHEN ... THEN 'asf.activity/...'` clause -- not just the
        // `effect_type`/literal fragment -- proves each mapping is read from
        // its own CASE, in its own branch, not merely present anywhere in
        // the function body.
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "required_contract_id := CASE",
                "WHEN NEW.provider = 'runmill' \
                 AND NEW.effect_type = 'request_cancellation' \
                 THEN 'asf.activity/request-work-item-cancellation/v1'",
                "WHEN NEW.provider = 'runmill' \
                 AND NEW.effect_type = 'submit_work_order' \
                 THEN 'asf.activity/advance-accepted-work-item/v1'",
                "WHEN NEW.provider = 'linear' \
                 AND NEW.effect_type = 'close_source' \
                 THEN 'asf.activity/close-source/v1'",
            ],
        );
        for snippet in [
            "NEW.effect_type = 'request_cancellation' \
             THEN 'asf.activity/request-work-item-cancellation/v1'",
            "NEW.effect_type = 'submit_work_order' \
             THEN 'asf.activity/advance-accepted-work-item/v1'",
            "NEW.effect_type = 'close_source' \
             THEN 'asf.activity/close-source/v1'",
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(1));
        }

        // The owning job is proved against the CASE-derived job type and
        // contract id, not a literal -- each dynamic predicate appears once.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "owning_job.job_type = required_job_type",
            Some(1),
        );
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "owning_job.activity_contract_id = required_contract_id",
            Some(1),
        );
    }

    #[test]
    fn asf_guard_source_close_job_completion_pins_old_and_new_contract_id_and_transition_anchors() {
        const FUNCTION_NAME: &str = "asf_guard_source_close_job_completion";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        for snippet in [
            "OLD.activity_contract_id IS DISTINCT FROM 'asf.activity/close-source/v1'",
            "NEW.activity_contract_id IS DISTINCT FROM 'asf.activity/close-source/v1'",
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(1));
        }
        // Anchors proving this predicate pair guards the CLOSE_SOURCE ->
        // COMPLETED transition, not some other job-type/status combination.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.job_type = 'CLOSE_SOURCE'",
            Some(1),
        );
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.status = 'COMPLETED'",
            Some(1),
        );
    }

    #[test]
    fn asf_guard_verify_evidence_job_completion_pins_old_and_new_contract_id_and_rejection_anchors()
    {
        const FUNCTION_NAME: &str = "asf_guard_verify_evidence_job_completion";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        for snippet in [
            "OLD.activity_contract_id IS DISTINCT FROM 'asf.activity/verify-evidence/v1'",
            "NEW.activity_contract_id IS DISTINCT FROM 'asf.activity/verify-evidence/v1'",
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(1));
        }
        // Anchors proving this predicate pair guards the VERIFY_EVIDENCE ->
        // COMPLETED rejection path, not some other job-type/status combination.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.job_type = 'VERIFY_EVIDENCE'",
            Some(1),
        );
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.status = 'COMPLETED'",
            Some(1),
        );
    }

    #[test]
    fn asf_stamp_runmill_cancellation_observation_reproves_its_owning_job_claim_twice() {
        const FUNCTION_NAME: &str = "asf_stamp_runmill_cancellation_observation";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
            Some(2),
        );

        // The two occurrences of the pair above are not two interchangeable
        // copies of the same predicate: each is bound, in file order, to a
        // distinct location -- the initial `PERFORM 1 ... FOR SHARE` claim
        // proven before the effect/run checks, and the later `OR NOT EXISTS`
        // revalidation of that same claim inside the immutability guard.
        // These two long, normalized-contiguous snippets differ only in
        // their opening/closing anchors (`PERFORM 1 FROM ... FOR SHARE;` vs.
        // `OR NOT EXISTS ( SELECT 1 FROM ... )`), so a body that moved the
        // pair out of either exact query shape -- or duplicated the wrong
        // one -- fails here even though the bare pair count would still be
        // 2.
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "PERFORM 1
    FROM workflow_jobs AS job
    WHERE job.tenant_id = NEW.tenant_id
      AND job.id = NEW.workflow_job_id
      AND job.workflow_instance_id = NEW.workflow_instance_id
      AND job.work_item_id = NEW.work_item_id
      AND job.attempt_id = NEW.attempt_id
      AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
      AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
      AND job.status = 'RUNNING'
      AND job.fence_token = NEW.workflow_job_fence_token
      AND job.attempt_count = NEW.workflow_job_attempt_count
      AND job.lease_owner = NEW.workflow_job_owner
      AND job.lease_expires_at > transaction_timestamp()
    FOR SHARE;",
                "OR NOT EXISTS (
           SELECT 1
           FROM workflow_jobs AS job
           WHERE job.tenant_id = NEW.tenant_id
             AND job.id = NEW.workflow_job_id
             AND job.workflow_instance_id = NEW.workflow_instance_id
             AND job.work_item_id = NEW.work_item_id
             AND job.attempt_id = NEW.attempt_id
             AND job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'
             AND job.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'
             AND job.status = 'RUNNING'
             AND job.fence_token = NEW.workflow_job_fence_token
             AND job.attempt_count = NEW.workflow_job_attempt_count
             AND job.lease_owner = NEW.workflow_job_owner
             AND job.lease_expires_at > transaction_timestamp()
       ) OR NOT EXISTS (",
            ],
        );
    }

    #[test]
    fn asf_valid_runmill_cancellation_effect_request_binds_both_owner_shapes_and_their_anchors() {
        const FUNCTION_NAME: &str = "asf_valid_runmill_cancellation_effect_request";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        // The IN_FLIGHT live-owner shape and the OBSERVED immutable-owner
        // shape each prove the same owning-job contract pair once, for a
        // total of two occurrences in this function's body.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND owning_job.activity_contract_id = \
             'asf.activity/request-work-item-cancellation/v1'",
            Some(2),
        );
        // Anchors proving each occurrence guards its own distinct shape, not
        // a duplicate of the other.
        for (snippet, count) in [
            ("effect.status = 'IN_FLIGHT'", 1),
            ("effect.status = 'OBSERVED'", 1),
            ("initial_observation.run_id = run.id", 1),
            ("owning_job.lease_expires_at > transaction_timestamp()", 1),
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(count));
        }

        // The counts and presence checks above hold even if the IN_FLIGHT
        // and OBSERVED shapes' internals were cross-wired -- e.g. the
        // transaction-timestamp lease predicate moved into the OBSERVED
        // EXISTS, or the run-id binding moved into the IN_FLIGHT EXISTS.
        // Chain them in file order instead: the IN_FLIGHT status flag, its
        // own owning-job pair plus RUNNING status, and its own lease
        // predicate must all appear before the OBSERVED status flag, which
        // must precede the run-id binding, the INITIAL-route anchor, and
        // finally that shape's own owning-job pair (no RUNNING status check
        // in this shape, since the job may since have advanced).
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "effect.status = 'IN_FLIGHT'",
                "owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
                 AND owning_job.activity_contract_id = \
                 'asf.activity/request-work-item-cancellation/v1' \
                 AND owning_job.status = 'RUNNING'",
                "owning_job.lease_expires_at > transaction_timestamp()",
                "effect.status = 'OBSERVED'",
                "initial_observation.run_id = run.id",
                "initial_observation.route = 'INITIAL'",
                "owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
                 AND owning_job.activity_contract_id = \
                 'asf.activity/request-work-item-cancellation/v1'",
            ],
        );
    }

    #[test]
    fn asf_valid_runmill_cancellation_effect_observation_binds_the_initial_owning_job() {
        const FUNCTION_NAME: &str = "asf_valid_runmill_cancellation_effect_observation";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "owning_job.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND owning_job.activity_contract_id = \
             'asf.activity/request-work-item-cancellation/v1'",
            Some(1),
        );
        // Anchor proving the owning-job proof is scoped to the immutable
        // INITIAL observation, not a later OBSERVER reconciliation.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "observation.route = 'INITIAL'",
            Some(1),
        );
    }

    #[test]
    fn asf_note_work_dispatch_fact_pins_the_pristine_advance_row_contract_id() {
        const FUNCTION_NAME: &str = "asf_note_work_dispatch_fact";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        for (snippet, count) in [
            ("new_row ->> 'job_type' = 'ADVANCE_ACCEPTED_WORK_ITEM'", 1),
            (
                "new_row ->> 'activity_contract_id' = \
                 'asf.activity/advance-accepted-work-item/v1'",
                1,
            ),
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(count));
        }
    }

    #[test]
    fn asf_note_work_dispatch_fact_mutation_pins_old_and_new_advance_row_contract_id() {
        const FUNCTION_NAME: &str = "asf_note_work_dispatch_fact_mutation";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        for (snippet, count) in [
            (
                "old_row ->> 'activity_contract_id' = \
                 'asf.activity/advance-accepted-work-item/v1'",
                1,
            ),
            (
                "new_row ->> 'activity_contract_id' = \
                 'asf.activity/advance-accepted-work-item/v1'",
                1,
            ),
            // Anchors proving both checks are scoped to the UPDATE
            // pre-dispatch terminalization branch, not the DELETE path or the
            // sibling workflow_instances branch.
            ("TG_OP = 'UPDATE'", 2),
            ("old_row ->> 'job_type' = 'ADVANCE_ACCEPTED_WORK_ITEM'", 1),
            ("new_row ->> 'status' = 'CANCELLED'", 1),
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(count));
        }

        // Independent generic counts above cannot tell an in-branch
        // predicate from one relocated to a sibling branch (e.g. the
        // workflow_instances CANCELLED transition also has an old/new pair
        // to move into). Chain the whole pristine-ADVANCE/CANCELLED branch
        // in file order instead: the branch guard, the OLD job_type/contract
        // anchors, then the NEW status/contract anchors, all before the
        // branch's own early return.
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'workflow_jobs' THEN",
                "old_row ->> 'job_type' = 'ADVANCE_ACCEPTED_WORK_ITEM'",
                "old_row ->> 'activity_contract_id' = \
                 'asf.activity/advance-accepted-work-item/v1'",
                "new_row ->> 'status' = 'CANCELLED'",
                "new_row ->> 'activity_contract_id' = \
                 'asf.activity/advance-accepted-work-item/v1'",
                "RETURN NEW;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'workflow_instances' THEN",
            ],
        );
    }

    #[test]
    fn asf_guard_cancellation_job_terminal_transition_pins_both_branches_old_and_new() {
        const FUNCTION_NAME: &str = "asf_guard_cancellation_job_terminal_transition";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        for snippet in [
            "OLD.activity_contract_id IS DISTINCT FROM \
             'asf.activity/request-work-item-cancellation/v1'",
            "NEW.activity_contract_id IS DISTINCT FROM \
             'asf.activity/request-work-item-cancellation/v1'",
            "OLD.activity_contract_id IS DISTINCT FROM \
             'asf.activity/advance-accepted-work-item/v1'",
            "NEW.activity_contract_id IS DISTINCT FROM \
             'asf.activity/advance-accepted-work-item/v1'",
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(1));
        }
        // Anchors proving each pair guards its own exact branch: the
        // REQUEST_WORK_ITEM_CANCELLATION RUNNING->COMPLETED completion, and
        // the pristine ADVANCE_ACCEPTED_WORK_ITEM pre-dispatch->CANCELLED
        // transition.
        for (snippet, count) in [
            ("NEW.job_type = 'REQUEST_WORK_ITEM_CANCELLATION'", 1),
            ("NEW.status = 'COMPLETED'", 1),
            ("NEW.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM'", 1),
            ("NEW.status = 'CANCELLED'", 1),
        ] {
            assert_function_body_snippet(migration, FUNCTION_NAME, snippet, Some(count));
        }

        // The four OLD/NEW contract predicates and the four branch anchors
        // above are each individually exact-once, but that alone permits an
        // OLD/NEW pair to be moved wholesale into the other branch (e.g. the
        // REQUEST_WORK_ITEM_CANCELLATION contract pair swapped into the
        // ADVANCE_ACCEPTED_WORK_ITEM branch and vice versa) without changing
        // any count. Chain both branches in file order -- guard, its own
        // OLD/NEW pair, its own RAISE EXCEPTION message -- so a pair
        // relocated into the other branch's OR-list is found only after
        // (or before) the wrong RAISE EXCEPTION anchor and fails here.
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "NEW.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
                 AND NEW.status = 'COMPLETED'",
                "OLD.activity_contract_id IS DISTINCT FROM \
                 'asf.activity/request-work-item-cancellation/v1'",
                "NEW.activity_contract_id IS DISTINCT FROM \
                 'asf.activity/request-work-item-cancellation/v1'",
                "cancellation completion does not capture its exact executed claim",
                "NEW.job_type = 'ADVANCE_ACCEPTED_WORK_ITEM' \
                 AND NEW.status = 'CANCELLED'",
                "OLD.activity_contract_id IS DISTINCT FROM \
                 'asf.activity/advance-accepted-work-item/v1'",
                "NEW.activity_contract_id IS DISTINCT FROM \
                 'asf.activity/advance-accepted-work-item/v1'",
                "pre-dispatch cancellation does not fence the pristine advance job",
            ],
        );
    }

    #[test]
    fn asf_assert_completed_cancellation_job_observation_binds_subject_and_nested_observer() {
        const FUNCTION_NAME: &str = "asf_assert_completed_cancellation_job_observation";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        // The subject job under transition proves its own contract id
        // directly against NEW.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.activity_contract_id = 'asf.activity/request-work-item-cancellation/v1'",
            Some(1),
        );
        // The nested observer-job scheduling proof binds the same contract
        // through its own scoped pair.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "observer.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
             AND observer.activity_contract_id = \
             'asf.activity/request-work-item-cancellation/v1'",
            Some(1),
        );
        // Anchor proving the nested observer proof is scoped to the exact
        // reconciliation branch that schedules the observer job. This is the
        // parent job's own `route = 'INITIAL'` branch (an INITIAL-route
        // completion schedules the OBSERVER-route reconciliation job that
        // will later observe the terminal outcome) -- the function's sole
        // `observation.route = 'OBSERVER'` check instead scopes an unrelated
        // payload-shape predicate earlier in the same body, so anchoring
        // there would not actually tie to the nested `workflow_jobs AS
        // observer` proof. Chain the branch guard, the observer EXISTS
        // subquery open, the observer contract pair, and the trailing
        // observation-validity call in file order so the pair cannot be
        // satisfied by presence alone, nor by drifting into a sibling
        // branch or the unrelated OBSERVER payload-shape predicate.
        assert_function_body_ordered_snippets(
            migration,
            FUNCTION_NAME,
            &[
                "observation.route = 'INITIAL'
                     AND NEW.result #>> '{result,route}' =
                         'cancellation_in_progress'",
                "EXISTS (
                         SELECT 1
                         FROM workflow_jobs AS observer
                         WHERE observer.tenant_id = NEW.tenant_id",
                "observer.job_type = 'REQUEST_WORK_ITEM_CANCELLATION' \
                 AND observer.activity_contract_id = \
                 'asf.activity/request-work-item-cancellation/v1'",
                "asf_valid_runmill_cancellation_effect_observation(",
            ],
        );
    }

    #[test]
    fn asf_assert_nonterminal_cancellation_observer_obligation_fails_closed_on_either_mismatch() {
        const FUNCTION_NAME: &str = "asf_assert_nonterminal_cancellation_observer_obligation";
        let migration =
            include_str!("../../migrations/0024_activity_contract_authority_proofs.sql");

        // The subject observer job's own contract id is checked with a
        // fail-closed negative (`<>`, not `=`): any activity_contract_id
        // other than the exact canonical literal makes the predicate true
        // and raises the guard. `workflow_jobs.activity_contract_id` is
        // schema-NOT-NULL (migration 0023 backfills it and then sets `SET
        // NOT NULL`), so this is not relying on SQL's `<>` having any
        // special NULL-rejecting behavior -- `x <> literal` for a NULL `x`
        // evaluates to NULL, not TRUE. The guard simply never has to
        // consider a NULL `activity_contract_id` in the first place.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "NEW.activity_contract_id <> 'asf.activity/request-work-item-cancellation/v1'",
            Some(1),
        );
        // The completed parent job's contract id is likewise checked with a
        // fail-closed negative, scoped by a normalized snippet anchored to
        // `OR NOT EXISTS` immediately followed by the
        // cancellation_terminal_receipts receipt query -- proving the
        // negative sits inside the same OR-list that already rejects a
        // still-missing terminal receipt, so neither equality nor misplaced
        // logic (e.g. moving the check outside this OR) can pass the guard.
        assert_function_body_snippet(
            migration,
            FUNCTION_NAME,
            "parent.activity_contract_id <> 'asf.activity/request-work-item-cancellation/v1' \
             OR NOT EXISTS ( SELECT 1 FROM cancellation_terminal_receipts AS receipt",
            Some(1),
        );
    }
}
