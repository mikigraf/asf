use serde_json::json;
use sqlx::{PgPool, Row as _, Transaction};
use uuid::Uuid;

use crate::{Error, Result};

const UNKNOWN_OR_INCOMPATIBLE_DUE_TIMER_SQL: &str = r"
SELECT timer.timer_type, timer.activity_contract_id
FROM workflow_timers AS timer
WHERE timer.tenant_id = $1
  AND timer.status = 'SCHEDULED'
  AND timer.due_at <= clock_timestamp()
  AND NOT EXISTS (
      SELECT 1
      FROM unnest($2::text[], $3::text[]) AS known_route(timer_type, activity_contract_id)
      WHERE known_route.timer_type = timer.timer_type
        AND known_route.activity_contract_id = timer.activity_contract_id
  )
ORDER BY timer.due_at, timer.id
LIMIT 1
";

const LOCK_DUE_TIMERS_SQL: &str = r"
SELECT
    timer.id,
    timer.workflow_instance_id,
    timer.work_item_id,
    timer.attempt_id,
    timer.workflow_key,
    timer.timer_key,
    timer.timer_type,
    timer.activity_contract_id,
    timer.payload,
    timer.generation,
    timer.due_at
FROM workflow_timers AS timer
WHERE timer.tenant_id = $1
  AND timer.status = 'SCHEDULED'
  AND timer.due_at <= clock_timestamp()
  AND EXISTS (
      SELECT 1
      FROM unnest($2::text[], $3::text[]) AS ready_route(timer_type, activity_contract_id)
      WHERE ready_route.timer_type = timer.timer_type
        AND ready_route.activity_contract_id = timer.activity_contract_id
  )
ORDER BY timer.due_at, timer.id
FOR UPDATE OF timer SKIP LOCKED
LIMIT $4
";

const SCOPED_DUE_TIMER_SQL: &str = r"
SELECT timer.timer_type
FROM workflow_timers AS timer
WHERE timer.tenant_id = $1
  AND timer.status = 'SCHEDULED'
  AND timer.due_at <= clock_timestamp()
  AND timer.timer_type = ANY($2::text[])
ORDER BY timer.due_at, timer.id
LIMIT 1
";

const PROMOTE_JOB_INSERT_SQL: &str = r"
INSERT INTO workflow_jobs (
    id, tenant_id, workflow_instance_id, work_item_id, attempt_id,
    job_type, activity_contract_id, payload, idempotency_key, available_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, clock_timestamp())
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id
";

pub(super) async fn promote_due_timers(
    pool: &PgPool,
    tenant_id: Uuid,
    known_routes: &[(String, String)],
    ready_routes: &[(String, String)],
    scoped_job_types: &[String],
    limit: u32,
) -> Result<u32> {
    reject_unknown_or_incompatible_due_timer(pool, tenant_id, known_routes).await?;
    reject_scoped_due_timer(pool, tenant_id, scoped_job_types).await?;
    if ready_routes.is_empty() {
        return Ok(0);
    }

    let (ready_timer_types, ready_contract_ids) = unzip_routes(ready_routes);
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| Error::Persistence(format!("begin timer promotion: {error}")))?;
    let rows = sqlx::query(LOCK_DUE_TIMERS_SQL)
        .bind(tenant_id)
        .bind(ready_timer_types)
        .bind(ready_contract_ids)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| Error::Persistence(format!("lock due workflow timers: {error}")))?;
    let mut promoted = 0_u32;
    for row in rows {
        promote_timer(&mut transaction, tenant_id, &row).await?;
        promoted = promoted
            .checked_add(1)
            .ok_or_else(|| Error::Persistence("promoted timer count overflowed".into()))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| Error::Persistence(format!("commit timer promotion: {error}")))?;
    Ok(promoted)
}

async fn reject_scoped_due_timer(
    pool: &PgPool,
    tenant_id: Uuid,
    scoped_job_types: &[String],
) -> Result<()> {
    if scoped_job_types.is_empty() {
        return Ok(());
    }
    let scoped = sqlx::query_scalar::<_, String>(SCOPED_DUE_TIMER_SQL)
        .bind(tenant_id)
        .bind(scoped_job_types)
        .fetch_optional(pool)
        .await
        .map_err(|error| Error::Persistence(format!("inspect scoped workflow timers: {error}")))?;
    if let Some(timer_type) = scoped {
        Err(Error::Validation(format!(
            "scoped durable workflow timer type {timer_type:?} cannot be promoted through the unscoped timer envelope"
        )))
    } else {
        Ok(())
    }
}

/// Fail closed and leave the timer `SCHEDULED`: a due timer whose exact
/// `(timer_type, activity_contract_id)` pair is not one this process
/// installed a handler for — whether the `timer_type` is wholly unrecognized
/// or recognized but bound to a different, incompatible contract identity —
/// must never be silently promoted into a workflow job.
async fn reject_unknown_or_incompatible_due_timer(
    pool: &PgPool,
    tenant_id: Uuid,
    known_routes: &[(String, String)],
) -> Result<()> {
    let (known_timer_types, known_contract_ids) = unzip_routes(known_routes);
    let unknown = sqlx::query_as::<_, (String, String)>(UNKNOWN_OR_INCOMPATIBLE_DUE_TIMER_SQL)
        .bind(tenant_id)
        .bind(known_timer_types)
        .bind(known_contract_ids)
        .fetch_optional(pool)
        .await
        .map_err(|error| Error::Persistence(format!("inspect unknown workflow timers: {error}")))?;
    if let Some((timer_type, activity_contract_id)) = unknown {
        if known_routes
            .iter()
            .any(|(known_timer_type, _)| known_timer_type == &timer_type)
        {
            Err(Error::Validation(format!(
                "due workflow timer type {timer_type:?} has incompatible activity contract id {activity_contract_id:?}; timer remains scheduled"
            )))
        } else {
            Err(Error::Validation(format!(
                "unsupported due workflow timer type {timer_type:?}; timer remains scheduled"
            )))
        }
    } else {
        Ok(())
    }
}

/// Split a `(route_key, activity_contract_id)` pair list into the two
/// parallel arrays a `PostgreSQL` `unnest($a::text[], $b::text[])` bind
/// requires for safe, index-free tuple matching.
fn unzip_routes(routes: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    routes
        .iter()
        .map(|(route_key, activity_contract_id)| (route_key.clone(), activity_contract_id.clone()))
        .unzip()
}

async fn promote_timer(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<()> {
    let timer_id: Uuid = decode(row, "id", "timer ID")?;
    let workflow_instance_id: Option<Uuid> = decode(row, "workflow_instance_id", "timer workflow")?;
    let work_item_id: Option<Uuid> = decode(row, "work_item_id", "timer work item")?;
    let attempt_id: Option<Uuid> = decode(row, "attempt_id", "timer attempt")?;
    let workflow_key: String = decode(row, "workflow_key", "timer workflow key")?;
    let timer_key: String = decode(row, "timer_key", "timer key")?;
    let timer_type: String = decode(row, "timer_type", "timer type")?;
    let activity_contract_id: String =
        decode(row, "activity_contract_id", "timer activity contract id")?;
    let payload: serde_json::Value = decode(row, "payload", "timer payload")?;
    let generation: i64 = decode(row, "generation", "timer generation")?;
    let due_at: chrono::DateTime<chrono::Utc> = decode(row, "due_at", "timer due time")?;
    let job_id = Uuid::now_v7();
    let idempotency_key = format!("workflow-timer:{timer_id}:{generation}");
    let envelope = json!({
        "timer": {
            "id": timer_id,
            "workflow_key": workflow_key,
            "timer_key": timer_key,
            "generation": generation,
            "due_at": due_at,
        },
        "payload": payload,
    });

    let inserted = sqlx::query_scalar::<_, Uuid>(PROMOTE_JOB_INSERT_SQL)
        .bind(job_id)
        .bind(tenant_id)
        .bind(workflow_instance_id)
        .bind(work_item_id)
        .bind(attempt_id)
        .bind(&timer_type)
        .bind(&activity_contract_id)
        .bind(&envelope)
        .bind(&idempotency_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| Error::Persistence(format!("enqueue fired workflow timer: {error}")))?;
    if inserted.is_none() {
        return Err(Error::Conflict(format!(
            "workflow timer {timer_id} generation {generation} already has a job"
        )));
    }

    let fired = sqlx::query(
        r"
        UPDATE workflow_timers
        SET status = 'FIRED', fired_at = clock_timestamp()
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'SCHEDULED'
          AND generation = $3
        ",
    )
    .bind(tenant_id)
    .bind(timer_id)
    .bind(generation)
    .execute(&mut **transaction)
    .await
    .map_err(|error| Error::Persistence(format!("mark workflow timer fired: {error}")))?
    .rows_affected();
    if fired != 1 {
        return Err(Error::Conflict(format!(
            "workflow timer {timer_id} generation changed while firing"
        )));
    }
    Ok(())
}

fn decode<T>(row: &sqlx::postgres::PgRow, column: &str, context: &str) -> Result<T>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|error| Error::Persistence(format!("decode {context}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_queries_are_tenant_scoped_deduplicated_and_skip_locked() {
        assert!(UNKNOWN_OR_INCOMPATIBLE_DUE_TIMER_SQL.contains("timer.tenant_id = $1"));
        assert!(LOCK_DUE_TIMERS_SQL.contains("timer.tenant_id = $1"));
        assert!(LOCK_DUE_TIMERS_SQL.contains("FOR UPDATE OF timer SKIP LOCKED"));
        assert!(SCOPED_DUE_TIMER_SQL.contains("timer.timer_type = ANY($2::text[])"));
    }

    #[test]
    fn unknown_and_ready_timer_checks_require_the_exact_type_and_contract_pair() {
        for predicate in [
            "FROM unnest($2::text[], $3::text[]) AS known_route(timer_type, activity_contract_id)",
            "known_route.timer_type = timer.timer_type",
            "known_route.activity_contract_id = timer.activity_contract_id",
        ] {
            assert!(
                UNKNOWN_OR_INCOMPATIBLE_DUE_TIMER_SQL.contains(predicate),
                "unknown-or-incompatible timer check must retain {predicate}"
            );
        }
        for predicate in [
            "FROM unnest($2::text[], $3::text[]) AS ready_route(timer_type, activity_contract_id)",
            "ready_route.timer_type = timer.timer_type",
            "ready_route.activity_contract_id = timer.activity_contract_id",
        ] {
            assert!(
                LOCK_DUE_TIMERS_SQL.contains(predicate),
                "ready timer lock must retain {predicate}"
            );
        }
    }

    #[test]
    fn promoted_job_insert_propagates_the_timer_activity_contract_id() {
        assert!(LOCK_DUE_TIMERS_SQL.contains("timer.activity_contract_id"));
        assert!(PROMOTE_JOB_INSERT_SQL.contains("activity_contract_id"));
    }

    #[test]
    fn unzip_routes_preserves_pairing_without_index_drift() {
        let routes = vec![
            ("A".to_owned(), "contract-a".to_owned()),
            ("B".to_owned(), "contract-b".to_owned()),
        ];
        let (keys, contracts) = unzip_routes(&routes);
        assert_eq!(keys, vec!["A".to_owned(), "B".to_owned()]);
        assert_eq!(
            contracts,
            vec!["contract-a".to_owned(), "contract-b".to_owned()]
        );
    }

    #[tokio::test]
    async fn live_timer_promotion_matches_contract_and_fails_closed_on_mismatch() {
        const TIMER_TYPE: &str = "RUNTIME_TEST_TIMER";
        const READY_CONTRACT: &str = "test.activity/runtime-test-timer/v1";
        const WRONG_CONTRACT: &str = "test.activity/runtime-test-timer/v2";
        let Ok(database_url) = std::env::var("ASF_TEST_DATABASE_URL") else {
            return;
        };
        let ledger = crate::ledger::PgLedger::connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        ledger.migrate().await.expect("migrate test PostgreSQL");
        let tenant_id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Timer test')")
            .bind(tenant_id)
            .bind(format!("timer-{tenant_id}"))
            .execute(ledger.pool())
            .await
            .expect("insert timer tenant");

        let mismatched_timer_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_timers (
                id, tenant_id, workflow_key, timer_key, timer_type,
                activity_contract_id, due_at, payload
            ) VALUES ($1, $2, 'timer-test', $3, $4, $5, clock_timestamp() - interval '1 minute', '{}'::jsonb)
            ",
        )
        .bind(mismatched_timer_id)
        .bind(tenant_id)
        .bind(format!("mismatched-{mismatched_timer_id}"))
        .bind(TIMER_TYPE)
        .bind(WRONG_CONTRACT)
        .execute(ledger.pool())
        .await
        .expect("insert mismatched due timer");

        let known_routes = vec![(TIMER_TYPE.to_owned(), READY_CONTRACT.to_owned())];
        let error = promote_due_timers(
            ledger.pool(),
            tenant_id,
            &known_routes,
            &known_routes,
            &[],
            10,
        )
        .await
        .expect_err("a known timer type bound to an incompatible contract must fail closed");
        let Error::Validation(detail) = error else {
            panic!("expected a fail-closed validation error, got {error}");
        };
        assert!(detail.contains(TIMER_TYPE));
        assert!(detail.contains(WRONG_CONTRACT));

        let unchanged_status: String = sqlx::query_scalar(
            "SELECT status FROM workflow_timers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(mismatched_timer_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load mismatched timer status");
        assert_eq!(unchanged_status, "SCHEDULED");

        // Retire the incompatible fixture via a legal SCHEDULED -> CANCELLED
        // lifecycle transition (workflow_timers rows cannot be deleted), then
        // prove a matching contract promotes.
        sqlx::query(
            "UPDATE workflow_timers SET status = 'CANCELLED', cancelled_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND status = 'SCHEDULED'",
        )
        .bind(tenant_id)
        .bind(mismatched_timer_id)
        .execute(ledger.pool())
        .await
        .expect("cancel mismatched timer fixture");

        let cancelled_status: String = sqlx::query_scalar(
            "SELECT status FROM workflow_timers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(mismatched_timer_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load cancelled timer status");
        assert_eq!(cancelled_status, "CANCELLED");

        let matching_timer_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO workflow_timers (
                id, tenant_id, workflow_key, timer_key, timer_type,
                activity_contract_id, due_at, payload
            ) VALUES ($1, $2, 'timer-test', $3, $4, $5, clock_timestamp() - interval '1 minute', '{}'::jsonb)
            ",
        )
        .bind(matching_timer_id)
        .bind(tenant_id)
        .bind(format!("matching-{matching_timer_id}"))
        .bind(TIMER_TYPE)
        .bind(READY_CONTRACT)
        .execute(ledger.pool())
        .await
        .expect("insert matching due timer");

        let promoted = promote_due_timers(
            ledger.pool(),
            tenant_id,
            &known_routes,
            &known_routes,
            &[],
            10,
        )
        .await
        .expect("a due timer with the exact ready contract must promote");
        assert_eq!(promoted, 1);
        let (fired_status, job_contract): (String, String) = sqlx::query_as(
            r"
            SELECT timer.status, job.activity_contract_id
            FROM workflow_timers AS timer
            JOIN workflow_jobs AS job
              ON job.tenant_id = timer.tenant_id
             AND job.job_type = timer.timer_type
             AND job.idempotency_key = 'workflow-timer:' || timer.id::text || ':' || timer.generation::text
            WHERE timer.tenant_id = $1 AND timer.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(matching_timer_id)
        .fetch_one(ledger.pool())
        .await
        .expect("load promoted timer and its job");
        assert_eq!(fired_status, "FIRED");
        assert_eq!(job_contract, READY_CONTRACT);
    }
}
