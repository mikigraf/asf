use std::{collections::BTreeMap, process::ExitCode, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use asf::{
    adapters::LinearApiAdapter,
    api::{ApiState, PostgresApiBackend, router},
    artifacts::{ArtifactStore, FileArtifactStore, S3ArtifactStore},
    audit::{AuditEventContent, HashedAuditEvent},
    auth::ApiAuthenticator,
    config::{LinearIntakeSettings, Settings},
    crypto::Ed25519Signer,
    domain::EventId,
    ledger::{PgLedger, PgLedgerOptions},
    ports::ForgeGateway,
    runtime::{
        CLOSE_SOURCE, EvidenceVerificationHandler, EvidenceVerificationHandoff, HandlerRegistry,
        IntakeSyncHandler, LinearSourceClosureHandler, ReactorOptions, ReactorRuntime,
        RunmillCancellationHandler, RunmillObservationHandler, RunmillTerminalEvidenceHandler,
        RunmillWorkerReconciliationHandler, VERIFY_EVIDENCE,
    },
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sqlx::Row as _;
use tokio::{net::TcpListener, signal, sync::watch};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "asf-server", version, about = "ASF control-plane daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum Command {
    /// Apply forward-only migrations and provision the configured V1 tenant.
    Migrate,
    /// Run the API and durable-control-plane supervisors.
    All,
    /// Prove the configured artifact store can hold and return evidence.
    ///
    /// Writes one small probe object and reads it back. Evidence artifacts are
    /// the bytes an independent verifier re-reads, so a deployment should
    /// establish that its storage works before it depends on it rather than
    /// discovering otherwise during the first verification.
    CheckArtifactStorage,
}

enum FirstExit {
    Signal,
    Api(Result<()>),
    Reactor(Result<()>),
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = %format_args!("{error:#}"), "ASF terminated with an error");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let settings = Settings::from_env().context("load ASF configuration")?;
    settings.validate().context("validate ASF configuration")?;
    // Storage is provable without the ledger, and an operator checking their
    // bucket should not need a reachable database to do it.
    if matches!(cli.command, Command::CheckArtifactStorage) {
        return check_artifact_storage(&settings).await;
    }
    let ledger = connect(&settings).await?;

    match cli.command {
        Command::Migrate => {
            ledger.migrate().await.context("apply ASF migrations")?;
            provision_single_tenant(&ledger, &settings).await?;
            info!(tenant_id = %settings.tenant_id, "migrations and tenant provisioning complete");
            ledger.close().await;
            Ok(())
        }
        Command::All => run_all(ledger, settings).await,
        Command::CheckArtifactStorage => unreachable!("storage checks run before the ledger"),
    }
}

/// Write one probe artifact and read it back through the configured store.
///
/// The probe is unique per run, so it never depends on an object an earlier
/// check left behind, and it is content-addressed like every other artifact.
async fn check_artifact_storage(settings: &Settings) -> Result<()> {
    let store = artifact_store(settings).await?;
    let probe = format!(
        "asf-artifact-storage-probe {} {}",
        settings.tenant_id,
        Utc::now().to_rfc3339()
    );

    let stored = store
        .put(
            probe.as_bytes(),
            "text/plain",
            "asf-server:check-artifact-storage",
            "portable",
        )
        .await
        .context("write the artifact storage probe")?;
    let read = store
        .get(&stored.digest)
        .await
        .context("read the artifact storage probe back")?;
    if read != probe.as_bytes() {
        bail!("artifact storage returned different bytes than it was given");
    }

    info!(
        digest = %stored.digest,
        size = stored.size,
        "artifact storage accepted and returned the probe"
    );
    Ok(())
}

async fn connect(settings: &Settings) -> Result<PgLedger> {
    let options = PgLedgerOptions {
        min_connections: 1,
        max_connections: settings.database_max_connections,
        acquire_timeout: Duration::from_secs(10),
        idle_timeout: Some(Duration::from_mins(10)),
        max_lifetime: Some(Duration::from_mins(30)),
    };
    PgLedger::connect_with_options(settings.database_url.expose_secret(), &options)
        .await
        .context("connect to the ASF ledger")
}

async fn provision_single_tenant(ledger: &PgLedger, settings: &Settings) -> Result<()> {
    let tenant_id = settings.tenant_id;
    let slug = format!("tenant-{tenant_id}");
    let mut transaction = ledger
        .pool()
        .begin()
        .await
        .context("begin tenant bootstrap")?;
    // Tenant DML acquires its table lock before its boundary trigger locks the
    // singleton guard.  Preserve that global lock order to avoid a cycle with
    // an in-flight direct writer.
    sqlx::query("LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await
        .context("serialize V1 tenant bootstrap")?;
    let configured_tenant: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT configured_tenant_id \
         FROM v1_tenant_deployment_guards \
         WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await
    .context("lock V1 tenant deployment guard")?;
    if let Some(configured_tenant) = configured_tenant
        && configured_tenant != tenant_id.as_uuid()
    {
        bail!(
            "V1 tenant deployment is already bound to {configured_tenant}, not configured tenant {tenant_id}"
        );
    }
    let foreign_tenant: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE id <> $1 ORDER BY id LIMIT 1")
            .bind(tenant_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .context("check V1 tenant bootstrap has no foreign tenant")?;
    if let Some(foreign_tenant) = foreign_tenant {
        bail!(
            "V1 tenant deployment cannot bind configured tenant {tenant_id}: foreign tenant {foreign_tenant} already exists"
        );
    }

    let inserted = sqlx::query(
        r"
        INSERT INTO tenants (id, slug, display_name)
        VALUES ($1, $2, 'Autonomous Software Factory')
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(tenant_id.as_uuid())
    .bind(&slug)
    .execute(&mut *transaction)
    .await
    .context("provision configured tenant")?
    .rows_affected()
        == 1;

    let row = sqlx::query("SELECT slug, status FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .context("verify configured tenant")?
        .context("configured tenant was not visible after provisioning")?;
    let stored_slug: String = row.try_get("slug").context("decode tenant slug")?;
    let status: String = row.try_get("status").context("decode tenant status")?;
    if stored_slug != slug {
        bail!(
            "configured tenant ID {tenant_id} already belongs to slug {stored_slug:?}, expected {slug:?}"
        );
    }
    if status != "ACTIVE" {
        bail!("configured tenant {tenant_id} is {status}, not ACTIVE");
    }

    if configured_tenant.is_none() {
        sqlx::query(
            "UPDATE v1_tenant_deployment_guards \
             SET configured_tenant_id = $1 WHERE singleton",
        )
        .bind(tenant_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .context("activate V1 tenant deployment boundary")?;
    }

    if inserted {
        let occurred_at = Utc::now();
        let content = AuditEventContent {
            id: EventId::new(),
            tenant_id,
            work_item_id: None,
            attempt_id: None,
            actor_type: "system".into(),
            actor_id: "asf-server:migrate".into(),
            action: "TENANT_PROVISIONED".into(),
            subject_type: "TENANT".into(),
            subject_id: tenant_id.to_string(),
            correlation_id: format!("tenant-bootstrap:{tenant_id}"),
            trace_id: None,
            policy_digest: None,
            before_digest: None,
            after_digest: None,
            previous_event_hash: None,
            details: json!({"slug": slug, "status": status}),
            occurred_at,
        };
        let event = HashedAuditEvent::create(content).context("hash tenant bootstrap audit")?;
        sqlx::query(
            r"
            INSERT INTO audit_events (
                id, tenant_id, actor_type, actor_id, action, subject_type,
                subject_id, correlation_id, previous_event_hash, event_hash,
                details, occurred_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ",
        )
        .bind(event.content.id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(&event.content.actor_type)
        .bind(&event.content.actor_id)
        .bind(&event.content.action)
        .bind(&event.content.subject_type)
        .bind(&event.content.subject_id)
        .bind(&event.content.correlation_id)
        .bind(&event.content.previous_event_hash)
        .bind(&event.event_hash)
        .bind(&event.content.details)
        .bind(event.content.occurred_at)
        .execute(&mut *transaction)
        .await
        .context("record tenant bootstrap audit")?;
    }

    transaction
        .commit()
        .await
        .context("commit tenant bootstrap")
}

async fn run_all(ledger: PgLedger, settings: Settings) -> Result<()> {
    ledger.health().await.context("check ASF ledger")?;
    assert_v1_tenant_boundary(&ledger, settings.tenant_id.as_uuid()).await?;
    let authenticator = ApiAuthenticator::from_json(settings.api_tokens_json.expose_secret())
        .context("load API credentials")?;
    let handlers = production_handlers(&ledger, &settings).await?;
    let api_activity_capabilities = handlers.api_activity_capabilities();
    let backend = PostgresApiBackend::from_ledger(&ledger, settings.tenant_id)
        .with_activity_capabilities(api_activity_capabilities);
    let app = router(ApiState {
        tenant_id: settings.tenant_id,
        authenticator,
        backend: Arc::new(backend),
    });
    let listener = TcpListener::bind(settings.bind_address)
        .await
        .with_context(|| format!("bind ASF API to {}", settings.bind_address))?;

    for (job_type, reason) in handlers.unavailable_handlers() {
        warn!(
            job_type,
            reason, "durable activity is unavailable and will not be claimed"
        );
    }
    let reactor = ReactorRuntime::new(
        ledger.clone(),
        settings.tenant_id.as_uuid(),
        handlers,
        ReactorOptions {
            lease_owner: format!(
                "asf-reactor:{}:{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ),
            poll_interval: settings.workflow_poll_interval,
            lease_duration: settings.workflow_lease_duration,
            max_error_backoff: Duration::from_secs(30).max(settings.workflow_poll_interval),
            claim_batch_size: 16,
        },
        settings.maintenance_mode,
    )
    .context("configure durable reactor")?;

    if settings.maintenance_mode {
        warn!("maintenance mode is active; new dispatch must remain disabled");
    }
    info!(address = %settings.bind_address, tenant_id = %settings.tenant_id, "ASF API and durable reactor starting");

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let api_shutdown = shutdown_receiver.clone();
    let api_service = async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(api_shutdown))
            .await
            .context("serve ASF API")
    };
    let reactor_service = async move {
        reactor
            .run(shutdown_receiver)
            .await
            .context("run durable reactor")
    };
    tokio::pin!(api_service);
    tokio::pin!(reactor_service);

    let first_exit = tokio::select! {
        () = shutdown_signal() => FirstExit::Signal,
        result = &mut api_service => FirstExit::Api(result),
        result = &mut reactor_service => FirstExit::Reactor(result),
    };
    let _sent = shutdown_sender.send(true);
    let service_result = match first_exit {
        FirstExit::Signal => {
            let (api_result, reactor_result) = tokio::join!(api_service, reactor_service);
            api_result.and(reactor_result)
        }
        FirstExit::Api(api_result) => {
            let reactor_result = reactor_service.await;
            api_result?;
            reactor_result?;
            bail!("ASF API stopped before a shutdown signal")
        }
        FirstExit::Reactor(reactor_result) => {
            let api_result = api_service.await;
            api_result?;
            reactor_result?;
            bail!("durable reactor stopped before a shutdown signal")
        }
    };
    ledger.close().await;
    service_result
}

async fn assert_v1_tenant_boundary(ledger: &PgLedger, tenant_id: uuid::Uuid) -> Result<()> {
    let configured_tenant: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT configured_tenant_id FROM v1_tenant_deployment_guards WHERE singleton",
    )
    .fetch_one(ledger.pool())
    .await
    .context("load V1 tenant deployment guard")?;
    if configured_tenant != Some(tenant_id) {
        bail!(
            "V1 tenant deployment guard is bound to {configured_tenant:?}, not configured tenant {tenant_id}"
        );
    }
    Ok(())
}

async fn production_handlers(ledger: &PgLedger, settings: &Settings) -> Result<HandlerRegistry> {
    let mut handlers = HandlerRegistry::fail_closed_production()
        .context("build fail-closed production activity registry")?;
    let github_forge = configured_forge_gateway(settings)?;
    if let Some(linear) = &settings.linear_intake {
        validate_linear_repository_bindings(ledger, settings, linear).await?;
        let adapter = Arc::new(
            LinearApiAdapter::new(linear.api_config())
                .context("construct the tenant-bound Linear API adapter")?,
        );
        let handler = IntakeSyncHandler::new(
            ledger.clone(),
            settings.tenant_id,
            adapter.clone(),
            linear.opt_in_label(),
            linear.page_size(),
        )
        .context("construct the tenant-bound Linear intake handler")?;
        handlers
            .replace_unavailable(Arc::new(handler))
            .context("enable the production Linear intake activity")?;
        let close_handler =
            LinearSourceClosureHandler::new(ledger.clone(), settings.tenant_id, adapter)
                .context("construct the tenant-bound Linear source-closure handler")?;
        handlers
            .replace_unavailable(Arc::new(close_handler))
            .context("enable the production Linear source-closure activity")?;
        info!(
            tenant_id = %settings.tenant_id,
            team_mapping_count = linear.team_mapping_count(),
            page_size = linear.page_size(),
            "production Linear intake and source-closure activities are configured"
        );
    } else {
        warn!(
            "production Linear configuration is absent; INTAKE_SYNC and CLOSE_SOURCE remain unavailable"
        );
    }
    let source_closure_ready = handlers
        .ready_job_types()
        .iter()
        .any(|job_type| job_type == CLOSE_SOURCE);
    match (
        &github_forge,
        &settings.github_observation,
        source_closure_ready,
    ) {
        (Some(gateway), Some(github), true) => {
            let artifacts = artifact_store(settings)
                .await
                .context("open the content-addressed evidence artifact store")?;
            let work_order_signer = Ed25519Signer::from_base64_seed(
                settings.signing_key_id.clone(),
                settings.signing_seed_base64.expose_secret(),
            )
            .context("load the trusted ASF Work Order verification authority")?;
            let verifier = EvidenceVerificationHandler::new(
                ledger.clone(),
                settings.tenant_id,
                gateway.clone(),
                artifacts,
                work_order_signer.key_id(),
                work_order_signer.verifying_key(),
            )
            .context("construct the tenant-bound evidence-verification handler")?;
            handlers
                .replace_unavailable(Arc::new(verifier))
                .context("enable the production evidence-verification activity")?;
            info!(
                tenant_id = %settings.tenant_id,
                api_base = %github.api_base(),
                artifact_root = %settings.artifact_root.display(),
                "production evidence-verification and source-closure chain is configured"
            );
        }
        (Some(_), Some(_), false) => {
            warn!(
                "GitHub observation is configured without the required Linear source-closure activity; VERIFY_EVIDENCE remains unavailable to prevent an orphaned terminal obligation"
            );
        }
        (None, None, _) => {
            warn!(
                "production GitHub observation configuration is absent; VERIFY_EVIDENCE remains unavailable"
            );
        }
        _ => bail!("GitHub observation dependency and configuration disagree"),
    }
    if let Some(runmill) = &settings.runmill_control {
        validate_runmill_worker_binding(ledger, settings, runmill.worker_id()).await?;
        let client = runmill
            .client()
            .context("construct the private Runmill control client")?;
        let cancellation_handler = RunmillCancellationHandler::new(
            ledger.clone(),
            settings.tenant_id,
            runmill.worker_id(),
            client.clone(),
            runmill.controller_subject(),
            runmill.cancellation_grace_seconds(),
        )
        .context("construct the tenant-bound Runmill cancellation handler")?;
        handlers
            .replace_unavailable(Arc::new(cancellation_handler))
            .context("enable the production Runmill cancellation activity")?;
        let observation_handler = RunmillObservationHandler::new(
            ledger.clone(),
            settings.tenant_id,
            runmill.worker_id(),
            client.clone(),
        )
        .context("construct the tenant-bound Runmill observation handler")?;
        handlers
            .replace_unavailable(Arc::new(observation_handler))
            .context("enable the production Runmill observation activity")?;
        // Retention reads the same private daemon as observation and is scoped
        // to the same worker: a terminal-ready stream on this worker is the
        // only thing it can ever act on. It may create the verification
        // obligation only where a ready verifier is installed to serve it.
        let handoff = if handlers
            .ready_job_types()
            .iter()
            .any(|job_type| job_type == VERIFY_EVIDENCE)
        {
            EvidenceVerificationHandoff::Enqueue
        } else {
            EvidenceVerificationHandoff::RetainOnly
        };
        let terminal_evidence_handler = RunmillTerminalEvidenceHandler::new(
            ledger.clone(),
            settings.tenant_id,
            runmill.worker_id(),
            client.clone(),
            handoff,
        )
        .context("construct the tenant-bound Runmill terminal evidence handler")?;
        handlers
            .replace_unavailable(Arc::new(terminal_evidence_handler))
            .context("enable the production Runmill terminal evidence retention activity")?;
        let worker_handler = RunmillWorkerReconciliationHandler::new(
            ledger.clone(),
            settings.tenant_id,
            runmill.worker_id(),
            client,
        );
        handlers
            .replace_unavailable(Arc::new(worker_handler))
            .context("enable the production Runmill worker reconciliation activity")?;
        info!(
            tenant_id = %settings.tenant_id,
            worker_id = %runmill.worker_id(),
            timeout_milliseconds = runmill.timeout().as_millis(),
            grace_seconds = runmill.cancellation_grace_seconds(),
            "production Runmill cancellation, observation, and worker reconciliation activities are configured"
        );
    } else {
        warn!(
            "production Runmill control configuration is absent; REQUEST_WORK_ITEM_CANCELLATION, OBSERVE_RUNMILL_RUN, RETAIN_RUNMILL_TERMINAL_EVIDENCE, and RECONCILE_WORKER remain unavailable"
        );
    }
    Ok(handlers)
}

/// Open the artifact store this deployment is configured for.
///
/// Evidence artifacts are the bytes an independent verifier re-reads, so
/// production stores them on a configured S3-compatible endpoint. The
/// filesystem store remains for development and is announced as such: an
/// operator should never have to guess which one is holding their evidence.
async fn artifact_store(settings: &Settings) -> Result<Arc<dyn ArtifactStore>> {
    let Some(storage) = &settings.artifact_storage else {
        warn!(
            artifact_root = %settings.artifact_root.display(),
            "production artifact storage is absent; using the development filesystem store"
        );
        return Ok(Arc::new(
            FileArtifactStore::open(settings.artifact_root.clone()).await?,
        ));
    };
    let store = S3ArtifactStore::new(storage.clone())
        .context("construct the S3-compatible artifact store")?;
    info!(
        bucket = %storage.bucket,
        region = %storage.region,
        endpoint = %storage.endpoint,
        "production content-addressed artifact storage is configured"
    );
    Ok(Arc::new(store))
}

fn configured_forge_gateway(settings: &Settings) -> Result<Option<Arc<dyn ForgeGateway>>> {
    settings
        .github_observation
        .as_ref()
        .map(|github| {
            github
                .adapter()
                .map(|adapter| Arc::new(adapter) as Arc<dyn ForgeGateway>)
                .context("construct the read-only GitHub observation adapter")
        })
        .transpose()
}

async fn validate_runmill_worker_binding(
    ledger: &PgLedger,
    settings: &Settings,
    worker_id: asf::domain::WorkerId,
) -> Result<()> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM workers WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(settings.tenant_id.as_uuid())
    .bind(worker_id.as_uuid())
    .fetch_one(ledger.pool())
    .await
    .context("validate configured Runmill worker against the tenant inventory")?;
    if !exists {
        bail!(
            "configured Runmill worker {worker_id} is absent from tenant {}",
            settings.tenant_id
        );
    }
    Ok(())
}

async fn validate_linear_repository_bindings(
    ledger: &PgLedger,
    settings: &Settings,
    linear: &LinearIntakeSettings,
) -> Result<()> {
    let expected = linear.repository_bindings();
    let repository_ids = expected
        .keys()
        .map(|repository_id| repository_id.as_uuid())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        r"
        SELECT id, owner, name, active
        FROM repositories
        WHERE tenant_id = $1
          AND id = ANY($2)
        ",
    )
    .bind(settings.tenant_id.as_uuid())
    .bind(&repository_ids)
    .fetch_all(ledger.pool())
    .await
    .context("validate Linear repository mappings against the tenant inventory")?;

    let mut observed = BTreeMap::new();
    for row in rows {
        let repository_id: uuid::Uuid = row.try_get("id")?;
        let owner: String = row.try_get("owner")?;
        let name: String = row.try_get("name")?;
        let active: bool = row.try_get("active")?;
        if !active {
            bail!("Linear mapping references inactive repository {repository_id}");
        }
        observed.insert(repository_id, format!("{owner}/{name}"));
    }

    for (repository_id, expected_slug) in expected {
        let id = repository_id.as_uuid();
        let observed_slug = observed.get(&id).with_context(|| {
            format!(
                "Linear mapping repository {repository_id} is absent from tenant {}",
                settings.tenant_id
            )
        })?;
        if observed_slug != &expected_slug {
            bail!(
                "Linear mapping repository {repository_id} names {expected_slug:?}, but the tenant inventory names {observed_slug:?}"
            );
        }
    }
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    info!("shutdown signal received");
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_deployment_commands() {
        assert!(matches!(
            Cli::try_parse_from(["asf-server", "migrate"])
                .expect("migrate command must parse")
                .command,
            Command::Migrate
        ));
        assert!(matches!(
            Cli::try_parse_from(["asf-server", "all"])
                .expect("all command must parse")
                .command,
            Command::All
        ));
        assert!(matches!(
            Cli::try_parse_from(["asf-server", "check-artifact-storage"])
                .expect("artifact storage check must parse")
                .command,
            Command::CheckArtifactStorage
        ));
    }
}
