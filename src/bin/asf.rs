use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::{Client, Method, Url, header};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "asf", version, about = "ASF operator CLI")]
struct Cli {
    #[arg(long, env = "ASF_API_URL", default_value = "http://127.0.0.1:8080/")]
    api_url: Url,
    #[arg(long, env = "ASF_API_TOKEN", hide_env_values = true)]
    api_token: Option<SecretString>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    Doctor,
    Intake {
        #[command(subcommand)]
        command: IntakeCommand,
    },
    Work {
        #[command(subcommand)]
        command: WorkCommand,
    },
    Attention {
        #[command(subcommand)]
        command: AttentionCommand,
    },
    Approve(DecisionArgs),
    Reject(RejectArgs),
    Worker {
        #[command(subcommand)]
        command: WorkerCommand,
    },
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum IntakeCommand {
    Sync(IdempotentArgs),
    Submit(SubmitArgs),
}

#[derive(Debug, Subcommand)]
enum WorkCommand {
    List(PageArgs),
    Inspect { id: Uuid },
    Accept(WorkVersionArgs),
    Cancel(CancelArgs),
}

#[derive(Debug, Subcommand)]
enum AttentionCommand {
    List(PageArgs),
    Inspect { id: Uuid },
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    List,
    Inspect { id: Uuid },
    Reconcile(WorkerMutationArgs),
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    Verify(IdempotentResourceArgs),
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Explain { digest: String },
}

#[derive(Debug, Args)]
struct PageArgs {
    #[arg(long, default_value_t = 50)]
    limit: u16,
    #[arg(long)]
    cursor: Option<String>,
}

#[derive(Debug, Args)]
struct IdempotentArgs {
    #[arg(long)]
    idempotency_key: Option<String>,
}

/// `--idempotency-key` is required, not auto-generated: an unknown HTTP
/// result (timeout, connection reset) must be retried with the exact same
/// key so the server can replay it, never a fresh one.
#[derive(Debug, Args)]
struct SubmitArgs {
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct IdempotentResourceArgs {
    id: Uuid,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct WorkVersionArgs {
    id: Uuid,
    #[arg(long)]
    expected_version: u64,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct CancelArgs {
    id: Uuid,
    #[arg(long)]
    expected_version: u64,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct DecisionArgs {
    request_id: Uuid,
    #[arg(long)]
    expected_version: u64,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct RejectArgs {
    request_id: Uuid,
    #[arg(long)]
    expected_version: u64,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct WorkerMutationArgs {
    id: Uuid,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug)]
struct ApiClient {
    base: Url,
    token: Option<SecretString>,
    client: Client,
}

impl ApiClient {
    fn new(base: Url, token: Option<SecretString>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("asf-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            base,
            token,
            client,
        })
    }

    async fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, None, None).await
    }

    async fn post(&self, path: &str, body: Value, key: Option<&str>) -> Result<Value> {
        self.request(Method::POST, path, Some(body), key).await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<Value> {
        let url = self
            .base
            .join(path)
            .with_context(|| format!("resolve API path {path}"))?;
        let mut request = self.client.request(method, url);
        if let Some(token) = &self.token {
            let mut value =
                header::HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
                    .context("API token contains invalid header characters")?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("call ASF API")?;
        let status = response.status();
        let bytes = response.bytes().await.context("read ASF API response")?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            json!({
                "status": status.as_u16(),
                "detail": String::from_utf8_lossy(&bytes),
            })
        });
        if !status.is_success() {
            bail!(
                "ASF API returned {}: {}",
                status,
                serde_json::to_string(&value).unwrap_or_else(|_| "unreadable error".into())
            );
        }
        Ok(value)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let client = ApiClient::new(cli.api_url, cli.api_token)?;
    let value = match cli.command {
        Command::Doctor => {
            let health = client.get("healthz").await?;
            let readiness = client.get("readyz").await?;
            json!({"health": health, "readiness": readiness})
        }
        Command::Intake {
            command: IntakeCommand::Sync(args),
        } => {
            let key = key(args.idempotency_key);
            client.post("v1/intake/sync", json!({}), Some(&key)).await?
        }
        Command::Intake {
            command: IntakeCommand::Submit(args),
        } => {
            let object = load_intake_object(&args.file)?;
            client
                .post("v1/intake", object, Some(&args.idempotency_key))
                .await?
        }
        Command::Work { command } => match command {
            WorkCommand::List(page) => client.get(&page_path("v1/work-items", &page)).await?,
            WorkCommand::Inspect { id } => client.get(&format!("v1/work-items/{id}")).await?,
            WorkCommand::Accept(args) => {
                let key = key(args.idempotency_key);
                client
                    .post(
                        &format!("v1/work-items/{}/accept", args.id),
                        json!({"expected_version": args.expected_version}),
                        Some(&key),
                    )
                    .await?
            }
            WorkCommand::Cancel(args) => {
                let key = key(args.idempotency_key);
                client
                    .post(
                        &format!("v1/work-items/{}/cancel", args.id),
                        json!({
                            "expected_version": args.expected_version,
                            "reason": args.reason,
                        }),
                        Some(&key),
                    )
                    .await?
            }
        },
        Command::Attention { command } => match command {
            AttentionCommand::List(page) => client.get(&page_path("v1/attention", &page)).await?,
            AttentionCommand::Inspect { id } => {
                let page = client.get("v1/attention?limit=200").await?;
                page.get("items")
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items.iter().find(|item| {
                            item.get("id").and_then(Value::as_str) == Some(&id.to_string())
                        })
                    })
                    .cloned()
                    .with_context(|| {
                        format!("attention item {id} not found in first 200 open items")
                    })?
            }
        },
        Command::Approve(args) => {
            decide(
                &client,
                args.request_id,
                args.expected_version,
                "approve",
                None,
                args.idempotency_key,
            )
            .await?
        }
        Command::Reject(args) => {
            decide(
                &client,
                args.request_id,
                args.expected_version,
                "reject",
                Some(args.reason),
                args.idempotency_key,
            )
            .await?
        }
        Command::Worker { command } => match command {
            WorkerCommand::List => client.get("v1/workers").await?,
            WorkerCommand::Inspect { id } => {
                let workers = client.get("v1/workers").await?;
                workers
                    .as_array()
                    .and_then(|items| {
                        items.iter().find(|item| {
                            item.get("id").and_then(Value::as_str) == Some(&id.to_string())
                        })
                    })
                    .cloned()
                    .with_context(|| format!("worker {id} not found"))?
            }
            WorkerCommand::Reconcile(args) => {
                let key = key(args.idempotency_key);
                client
                    .post(
                        &format!("v1/workers/{}/reconcile", args.id),
                        json!({}),
                        Some(&key),
                    )
                    .await?
            }
        },
        Command::Evidence {
            command: EvidenceCommand::Verify(args),
        } => {
            let key = key(args.idempotency_key);
            client
                .post(
                    &format!("v1/evidence/{}/verify", args.id),
                    json!({}),
                    Some(&key),
                )
                .await?
        }
        Command::Policy {
            command: PolicyCommand::Explain { digest },
        } => client.get(&format!("v1/policies/{digest}/explain")).await?,
    };
    print_value(&value, cli.output)?;
    Ok(())
}

async fn decide(
    client: &ApiClient,
    id: Uuid,
    expected_version: u64,
    decision: &str,
    reason: Option<String>,
    idempotency_key: Option<String>,
) -> Result<Value> {
    let key = key(idempotency_key);
    client
        .post(
            &format!("v1/approvals/{id}/decision"),
            json!({
                "decision": decision,
                "reason": reason,
                "expected_version": expected_version,
            }),
            Some(&key),
        )
        .await
}

fn key(value: Option<String>) -> String {
    value.unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn load_intake_object(path: &std::path::Path) -> Result<Value> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read intake file {}", path.display()))?;
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("parse intake file {} as JSON", path.display()))?;
    if !value.is_object() {
        bail!(
            "intake file {} must contain a top-level JSON object",
            path.display()
        );
    }
    Ok(value)
}

fn page_path(base: &str, page: &PageArgs) -> String {
    let mut path = format!("{base}?limit={}", page.limit);
    if let Some(cursor) = &page.cursor {
        path.push_str("&cursor=");
        path.push_str(&urlencoding::encode(cursor));
    }
    path
}

fn print_value(value: &Value, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(value)?),
        OutputFormat::Text => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn parses_prd_commands() {
        for arguments in [
            vec!["asf", "doctor"],
            vec!["asf", "intake", "sync"],
            vec!["asf", "work", "list"],
            vec!["asf", "attention", "list"],
            vec!["asf", "worker", "list"],
            vec!["asf", "policy", "explain", "sha256:abc"],
        ] {
            Cli::try_parse_from(arguments).unwrap();
        }
    }

    #[test]
    fn parses_intake_submit_with_required_file_and_idempotency_key() {
        let cli = Cli::try_parse_from([
            "asf",
            "intake",
            "submit",
            "--file",
            "candidate.json",
            "--idempotency-key",
            "operator:submit:2026-08-24-001",
        ])
        .expect("submit parses with required arguments");
        let Command::Intake {
            command: IntakeCommand::Submit(args),
        } = cli.command
        else {
            panic!("expected intake submit command");
        };
        assert_eq!(args.file, PathBuf::from("candidate.json"));
        assert_eq!(args.idempotency_key, "operator:submit:2026-08-24-001");
    }

    #[test]
    fn intake_submit_without_file_fails_to_parse() {
        let error = Cli::try_parse_from([
            "asf",
            "intake",
            "submit",
            "--idempotency-key",
            "operator:submit:2026-08-24-001",
        ])
        .unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn intake_submit_without_idempotency_key_fails_to_parse() {
        let error = Cli::try_parse_from(["asf", "intake", "submit", "--file", "candidate.json"])
            .unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn load_intake_object_rejects_unreadable_file() {
        let missing_path = PathBuf::from("/nonexistent/does-not-exist-asf-intake.json");
        let error = load_intake_object(&missing_path).unwrap_err();
        assert!(format!("{error:#}").contains(&missing_path.display().to_string()));
    }

    #[test]
    fn load_intake_object_rejects_invalid_json() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(b"{ not valid json")
            .expect("write temp file");
        let error = load_intake_object(file.path()).unwrap_err();
        assert!(format!("{error:#}").contains("JSON"));
    }

    #[test]
    fn load_intake_object_rejects_non_object_json() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(b"[1, 2, 3]").expect("write temp file");
        let error = load_intake_object(file.path()).unwrap_err();
        assert!(format!("{error:#}").contains("object"));
    }

    #[test]
    fn load_intake_object_round_trips_valid_object() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        let body = json!({"schema_version": "asf.api-intake-request/v1", "title": "x"});
        file.write_all(serde_json::to_string(&body).unwrap().as_bytes())
            .expect("write temp file");
        let value = load_intake_object(file.path()).expect("valid object loads");
        assert_eq!(value, body);
    }
}
