use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use premier_cli::evidence::{
    DiffStatus, QueryOptions, diff_events, portable_evidence, query_events,
};
use premier_cli::{
    AuthPolicy, app, embedded_viewer_ready, instrumentation_app, validate_bind,
    validate_remote_trace_store,
};
use premier_trace::{
    EventInput, ProcessTermination, RECORDER_LEASE, RecoveryOptions, RedactionConfig,
    TerminationKind, TraceWriter, decode_utf8_chunk, finish_utf8, prepare_trace_output,
    read_events, read_manifest, recover_interrupted_trace, verify,
};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration as StdDuration;
use tracing_subscriber::EnvFilter;

mod adapters;
use adapters::{ADAPTER_SCHEMA_VERSION, AdapterChoice, NativeAdapter, Provider};

#[derive(Parser)]
#[command(
    name = "premier",
    version,
    about = "Local-first agent trace recorder and viewer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record a command and its terminal output into a portable .atrace directory.
    Record {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Human-readable run name shown by list and the trace viewer.
        #[arg(long)]
        name: Option<String>,
        /// Immutable tenant owner recorded in the trace manifest.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Open the viewer focused on this recording when it finishes.
        #[arg(long)]
        open: bool,
        /// Run the command inside a pseudo-terminal (Unix only), preserving
        /// stdout/stderr ordering as one interactive terminal byte stream.
        #[arg(long)]
        pty: bool,
        /// Normalize a provider's native JSONL stream into typed evidence.
        /// Auto activates only when a recognized CLI already uses structured output.
        #[arg(long, default_value = "auto")]
        adapter: AdapterChoice,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
        /// Additional structured payload field name to redact recursively.
        #[arg(long = "redact-field")]
        redact_fields: Vec<String>,
        /// Exact text to redact from persisted terminal output (terminal display stays raw).
        #[arg(long = "redact-literal")]
        redact_literals: Vec<String>,
        /// Regex to redact from persisted terminal output (terminal display stays raw).
        #[arg(long = "redact-regex")]
        redact_regexes: Vec<String>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Generate a rich local multi-agent trace for product evaluation and onboarding.
    Demo {
        #[arg(short, long, default_value = ".premier/traces/multi-agent-demo.atrace")]
        output: PathBuf,
    },
    /// Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`).
    Emit {
        /// Full JSON event body. Use `-` to read from stdin.
        #[arg(long)]
        json: Option<String>,
        /// Event kind (e.g. agent.spawn, model.response, tool.execution).
        #[arg(long)]
        kind: Option<String>,
        /// Actor identity for this event.
        #[arg(long)]
        actor: Option<String>,
        #[arg(long = "actor-type", default_value = "agent")]
        actor_type: String,
        #[arg(long)]
        span: Option<String>,
        #[arg(long = "parent-span")]
        parent_span: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Payload as a JSON object string.
        #[arg(long)]
        payload: Option<String>,
        /// Source label written on the event (default: premier-emit).
        #[arg(long, default_value = "premier-emit")]
        source: String,
    },
    /// Verify a finalized trace's digest, framing, event count, and identity.
    Verify { trace: PathBuf },
    /// Safely finalize an abandoned active trace, discarding only a torn trailing frame.
    Recover {
        trace: PathBuf,
        /// Minimum journal idle time required before recovery.
        #[arg(long, default_value_t = 300)]
        stale_after_seconds: u64,
        /// Recover even when the journal was modified recently.
        #[arg(long)]
        force: bool,
    },
    /// Atomically claim a legacy/local trace for a tenant.
    Claim {
        trace: PathBuf,
        #[arg(long)]
        tenant: String,
    },
    /// Atomically encrypt a finalized trace, or rotate it to a new master key.
    Encrypt {
        trace: PathBuf,
        #[arg(long, value_name = "PATH")]
        new_key_file: PathBuf,
    },
    /// Filter local trace evidence without starting the viewer.
    Query {
        trace: PathBuf,
        /// Exact event kind, matched case-insensitively.
        #[arg(long)]
        kind: Option<String>,
        /// Exact actor id, matched case-insensitively.
        #[arg(long)]
        actor: Option<String>,
        /// Exact event status, matched case-insensitively.
        #[arg(long)]
        status: Option<String>,
        /// Case-insensitive search across event metadata and payload JSON.
        #[arg(long)]
        search: Option<String>,
        /// Maximum events returned (1-1000).
        #[arg(long, default_value_t = 100, value_parser = parse_query_limit)]
        limit: usize,
        /// Emit one structured JSON result instead of the compact text view.
        #[arg(long)]
        json: bool,
    },
    /// Export portable JSON evidence with common secret fields recursively redacted.
    Export {
        trace: PathBuf,
        /// Destination JSON file. Omit to write JSON to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Compare two traces by semantic event structure, ignoring generated identity noise.
    Diff {
        baseline: PathBuf,
        current: PathBuf,
        /// Emit the complete structural comparison as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Replay recorded evidence timing only; this never re-executes the traced command.
    Replay {
        trace: PathBuf,
        /// Playback speed multiplier (for example 2 replays twice as fast).
        #[arg(long, default_value_t = 1.0, value_parser = parse_replay_speed)]
        speed: f64,
        /// Emit evidence immediately while preserving recorded order.
        #[arg(long)]
        no_sleep: bool,
    },
    /// List traces in a directory.
    List {
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
    },
    /// Open the local viewer, optionally focused on one trace.
    Open {
        trace: Option<PathBuf>,
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
    },
    /// Serve the viewer locally or to an authenticated team.
    Serve {
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
        #[arg(long, env = "PREMIER_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// JSON file containing SHA-256 hashed bearer tokens, tenant ownership, and scopes.
        #[arg(long, env = "PREMIER_AUTH_CONFIG")]
        auth_config: Option<PathBuf>,
        /// PEM certificate chain for native HTTPS. Must be paired with --tls-key.
        #[arg(long, env = "PREMIER_TLS_CERT")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for native HTTPS. Must be paired with --tls-cert.
        #[arg(long, env = "PREMIER_TLS_KEY")]
        tls_key: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    match Cli::parse().command {
        Commands::Record {
            output,
            name,
            tenant,
            open,
            pty,
            adapter,
            viewer_dir,
            bind,
            redact_fields,
            redact_literals,
            redact_regexes,
            command,
        } => {
            let redaction = RedactionConfig::new(redact_fields, redact_literals, redact_regexes)?;
            record(RecordOptions {
                output,
                name,
                tenant,
                command,
                open_viewer: open,
                pty,
                adapter,
                viewer_dir,
                bind,
                redaction,
            })
            .await
        }
        Commands::Demo { output } => demo(output),
        Commands::Emit {
            json,
            kind,
            actor,
            actor_type,
            span,
            parent_span,
            status,
            payload,
            source,
        } => {
            emit_event(EmitArgs {
                json,
                kind,
                actor,
                actor_type,
                span,
                parent_span,
                status,
                payload,
                source,
            })
            .await
        }
        Commands::Verify { trace } => {
            let mut manifest = verify(&trace)?;
            if manifest.diagnostics.is_empty() {
                manifest.diagnostics =
                    premier_trace::validate_events(&premier_trace::read_events(&trace)?);
            }
            println!(
                "verified {} ({} events, {} semantic diagnostics)",
                manifest.trace_id,
                manifest.journal.as_ref().unwrap().event_count,
                manifest.diagnostics.len(),
            );
            for diagnostic in &manifest.diagnostics {
                println!(
                    "warning {} at sequence {}: {}",
                    diagnostic.code,
                    diagnostic.sequence.unwrap_or(0),
                    diagnostic.message
                );
            }
            Ok(())
        }
        Commands::Recover {
            trace,
            stale_after_seconds,
            force,
        } => {
            let manifest = recover_interrupted_trace(
                &trace,
                RecoveryOptions {
                    minimum_idle: StdDuration::from_secs(stale_after_seconds),
                    force,
                },
            )?;
            println!(
                "recovered {} ({} events, exit {})",
                manifest.trace_id,
                manifest
                    .journal
                    .as_ref()
                    .map_or(0, |journal| journal.event_count),
                manifest.exit_code.unwrap_or(130)
            );
            Ok(())
        }
        Commands::Claim { trace, tenant } => {
            let manifest = premier_trace::claim_local_trace(&trace, &tenant)?;
            println!(
                "claimed {} for tenant {}",
                manifest.trace_id, manifest.tenant_id
            );
            Ok(())
        }
        Commands::Encrypt {
            trace,
            new_key_file,
        } => {
            let key = premier_trace::EncryptionKey::from_file(&new_key_file)?;
            let manifest = premier_trace::reencrypt_finalized_trace(&trace, key)?;
            println!("encrypted {} ({})", manifest.trace_id, trace.display());
            Ok(())
        }
        Commands::Query {
            trace,
            kind,
            actor,
            status,
            search,
            limit,
            json,
        } => query_trace(
            trace,
            QueryOptions {
                kind,
                actor,
                status,
                search,
                limit,
            },
            json,
        ),
        Commands::Export { trace, output } => export_trace(trace, output),
        Commands::Diff {
            baseline,
            current,
            json,
        } => diff_traces(baseline, current, json),
        Commands::Replay {
            trace,
            speed,
            no_sleep,
        } => replay_trace(trace, speed, no_sleep),
        Commands::List { trace_dir } => list(trace_dir),
        Commands::Open {
            trace,
            trace_dir,
            viewer_dir,
            bind,
        } => {
            let (trace_dir, focus) = if let Some(trace) = trace {
                let manifest = read_manifest(&trace)?;
                (trace_parent_dir(&trace), Some(manifest.trace_id))
            } else {
                (trace_dir, None)
            };
            serve_viewer(
                trace_dir,
                viewer_dir,
                bind,
                AuthPolicy::default(),
                focus,
                true,
                None,
            )
            .await
        }
        Commands::Serve {
            trace_dir,
            viewer_dir,
            bind,
            password,
            auth_config,
            tls_cert,
            tls_key,
        } => {
            let auth = AuthPolicy::from_sources(password, auth_config.as_deref())?;
            let tls = TlsFiles::from_options(tls_cert, tls_key)?;
            serve_viewer(trace_dir, viewer_dir, bind, auth, None, false, tls).await
        }
    }
}

fn parse_query_limit(value: &str) -> std::result::Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "limit must be an integer between 1 and 1000".to_owned())?;
    if !(1..=1_000).contains(&limit) {
        return Err("limit must be between 1 and 1000".into());
    }
    Ok(limit)
}

fn parse_replay_speed(value: &str) -> std::result::Result<f64, String> {
    let speed = value
        .parse::<f64>()
        .map_err(|_| "speed must be a positive finite number".to_owned())?;
    if !speed.is_finite() || speed <= 0.0 {
        return Err("speed must be a positive finite number".into());
    }
    Ok(speed)
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn query_trace(trace: PathBuf, options: QueryOptions, json_output: bool) -> Result<()> {
    read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let result = query_events(&read_events(&trace)?, &options);
    if json_output {
        return print_json(&result);
    }
    for event in &result.events {
        println!(
            "{:>6}  {}  {:<24} {:<18} {}",
            event.sequence,
            event.timestamp,
            event.kind,
            if event.actor_id.is_empty() {
                "root"
            } else {
                &event.actor_id
            },
            event.status
        );
    }
    eprintln!(
        "{} matched; {} returned{}",
        result.matched,
        result.returned,
        if result.truncated {
            " (limit reached)"
        } else {
            ""
        }
    );
    Ok(())
}

fn export_trace(trace: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let manifest =
        read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let export = portable_evidence(&manifest, &read_events(&trace)?);
    if let Some(output) = output {
        let mut bytes = serde_json::to_vec_pretty(&export)?;
        bytes.push(b'\n');
        let temporary = output.with_file_name(format!(
            ".{}.tmp-{}",
            output
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("premier-export"),
            std::process::id()
        ));
        fs::write(&temporary, bytes)
            .with_context(|| format!("cannot write export {}", temporary.display()))?;
        if let Err(error) = fs::rename(&temporary, &output) {
            let _ = fs::remove_file(&temporary);
            return Err(error)
                .with_context(|| format!("cannot publish export {}", output.display()));
        }
        println!("exported redacted evidence to {}", output.display());
        Ok(())
    } else {
        print_json(&export)
    }
}

fn diff_traces(baseline: PathBuf, current: PathBuf, json_output: bool) -> Result<()> {
    read_manifest(&baseline)
        .with_context(|| format!("cannot read baseline trace {}", baseline.display()))?;
    read_manifest(&current)
        .with_context(|| format!("cannot read current trace {}", current.display()))?;
    let diff = diff_events(&read_events(&baseline)?, &read_events(&current)?);
    if json_output {
        return print_json(&diff);
    }
    println!(
        "{} added · {} removed · {} changed · {} unchanged",
        diff.counts.added, diff.counts.removed, diff.counts.changed, diff.counts.unchanged
    );
    for item in diff
        .items
        .iter()
        .filter(|item| item.status != DiffStatus::Unchanged)
    {
        println!(
            "{:?}\t{}\t{} field change{}",
            item.status,
            item.key,
            item.changes.len(),
            if item.changes.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

fn replay_trace(trace: PathBuf, speed: f64, no_sleep: bool) -> Result<()> {
    read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let mut events = read_events(&trace)?;
    events.sort_by_key(|event| event.sequence);
    eprintln!(
        "NON-EXECUTION evidence replay: emitting {} recorded events at {speed}x; no commands, tools, or models will run",
        events.len()
    );
    let mut previous = None;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for event in events {
        if !no_sleep && let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) {
            if let Some(previous) = previous {
                let delay = timestamp.signed_duration_since(previous);
                if let Ok(delay) = delay.to_std()
                    && !delay.is_zero()
                {
                    thread::sleep(StdDuration::from_secs_f64(delay.as_secs_f64() / speed));
                }
            }
            previous = Some(timestamp);
        }
        serde_json::to_writer(&mut output, &event)?;
        writeln!(output)?;
        output.flush()?;
    }
    Ok(())
}

fn resolve_viewer_dir(viewer_dir: Option<PathBuf>) -> Result<Option<PathBuf>> {
    match viewer_dir {
        Some(dir) => {
            if !dir.join("index.html").is_file() {
                bail!(
                    "viewer build not found at {}; omit --viewer-dir to use the embedded viewer, or run `npm run build`",
                    dir.display()
                );
            }
            Ok(Some(dir))
        }
        None => {
            if !embedded_viewer_ready() {
                bail!(
                    "this premier binary was built without the full viewer; reinstall with `./scripts/install.sh` or pass --viewer-dir apps/viewer/dist after `npm run build`"
                );
            }
            Ok(None)
        }
    }
}

async fn serve_viewer(
    trace_dir: PathBuf,
    viewer_dir: Option<PathBuf>,
    bind: SocketAddr,
    auth: AuthPolicy,
    focus_trace: Option<String>,
    launch_browser: bool,
    tls: Option<TlsFiles>,
) -> Result<()> {
    let tls_enabled = tls.is_some();
    validate_bind(bind.ip(), &auth, tls_enabled)?;
    let viewer = resolve_viewer_dir(viewer_dir)?;
    tokio::fs::create_dir_all(&trace_dir).await?;
    if !bind.ip().is_loopback() {
        validate_remote_trace_store(&trace_dir)?;
    }
    let scheme = if tls_enabled { "https" } else { "http" };
    let url = focus_trace
        .map(|trace_id| format!("{scheme}://{bind}/?trace={trace_id}"))
        .unwrap_or_else(|| format!("{scheme}://{bind}"));
    println!("Premier viewer: {url}");
    if launch_browser && let Err(error) = open_browser(&url) {
        tracing::warn!("could not open browser: {error}");
    }
    let router = app(trace_dir, viewer, auth);
    if let Some(tls) = tls {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(tls.cert, tls.key).await?;
        axum_server::bind_rustls(bind, config)
            .serve(router.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        axum::serve(listener, router).await?;
    }
    Ok(())
}

struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsFiles {
    fn from_options(cert: Option<PathBuf>, key: Option<PathBuf>) -> Result<Option<Self>> {
        match (cert, key) {
            (Some(cert), Some(key)) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(&key)?.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        bail!("TLS private key must not be accessible by group or other users")
                    }
                }
                Ok(Some(Self { cert, key }))
            }
            (None, None) => Ok(None),
            _ => bail!("--tls-cert and --tls-key must be provided together"),
        }
    }
}

struct EmitArgs {
    json: Option<String>,
    kind: Option<String>,
    actor: Option<String>,
    actor_type: String,
    span: Option<String>,
    parent_span: Option<String>,
    status: Option<String>,
    payload: Option<String>,
    source: String,
}

async fn emit_event(args: EmitArgs) -> Result<()> {
    let url = std::env::var("PREMIER_COLLECTOR_URL").context(
        "PREMIER_COLLECTOR_URL is not set; run your agent under `premier record -- <command>` so the collector is injected",
    )?;
    let token = std::env::var("PREMIER_COLLECTOR_TOKEN")
        .context("PREMIER_COLLECTOR_TOKEN is not set; run under `premier record -- <command>`")?;

    let body = if let Some(raw) = args.json {
        let text = if raw == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            raw
        };
        serde_json::from_str::<serde_json::Value>(&text).context("invalid JSON for --json")?
    } else {
        let kind = args.kind.context("provide --json or --kind")?;
        let mut event = json!({
            "kind": kind,
            "source": args.source,
            "actor_type": args.actor_type,
        });
        if let Some(actor) = args.actor {
            event["actor_id"] = json!(actor);
        }
        if let Some(span) = args.span {
            event["span_id"] = json!(span);
        }
        if let Some(parent_span) = args.parent_span {
            event["parent_span_id"] = json!(parent_span);
        }
        if let Some(status) = args.status {
            event["status"] = json!(status);
        }
        if let Some(payload) = args.payload {
            event["payload"] =
                serde_json::from_str(&payload).context("invalid JSON for --payload")?;
        }
        event
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed to POST event to {url}"))?;
    let status_code = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status_code.is_success() {
        bail!("collector rejected event ({status_code}): {text}");
    }
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(event_id) = parsed.get("event_id").and_then(|v| v.as_str())
    {
        println!("{event_id}");
    } else {
        println!("ok");
    }
    Ok(())
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.args(["/C", "start"]);
        command
    };
    command.arg(url).spawn()?.wait()?;
    Ok(())
}

fn demo(output: PathBuf) -> Result<()> {
    prepare_trace_output(&output)?;
    let mut writer = TraceWriter::create_named(
        &output,
        vec!["premier".into(), "demo".into()],
        Some("Multi-agent failure investigation".into()),
    )?;
    // Stagger producer times so actor lanes show realistic starts (not wall-clock receipt pile-up).
    let origin = Utc::now() - Duration::seconds(45);
    let at = |offset_ms: i64| (origin + Duration::milliseconds(offset_ms)).to_rfc3339();
    let root = writer.append_input(event(
        0,
        "session.start",
        "coordinator",
        "agent",
        "run",
        "",
        "running",
        json!({"goal": "Ship a verified billing repair", "model": "frontier-large"}),
        at,
    ))?;
    let delegation = writer.append_input(EventInput {
        parent_event_id: root.event_id.clone(),
        correlation_id: "workstream-repair".into(),
        ..event(
            400,
            "agent.delegation",
            "coordinator",
            "agent",
            "delegate",
            "run",
            "running",
            json!({"delegates": ["researcher", "coder"], "scope": "inspect and patch billing ledger"}),
            at,
        )
    })?;
    let researcher = writer.append_input(EventInput {
        parent_event_id: delegation.event_id.clone(),
        links: vec![delegation.event_id.clone()],
        ..event(
            1_200,
            "agent.spawn",
            "researcher",
            "subagent",
            "research",
            "delegate",
            "running",
            json!({"parent_actor": "coordinator", "task": "find the first divergence"}),
            at,
        )
    })?;
    let coder = writer.append_input(EventInput {
        parent_event_id: delegation.event_id.clone(),
        links: vec![delegation.event_id.clone()],
        ..event(
            2_400,
            "agent.spawn",
            "coder",
            "subagent",
            "implementation",
            "delegate",
            "running",
            json!({"parent_actor": "coordinator", "task": "prepare a minimal scoped patch"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: researcher.event_id.clone(),
        duration_ms: 1240,
        ..event(
            3_100,
            "model.response",
            "researcher",
            "subagent",
            "research-model",
            "research",
            "ok",
            json!({
                "provider": "premier-demo",
                "model": "frontier-mini",
                "system_prompt": "You are the billing investigation agent. Preserve evidence, do not mutate files, and cite the event or source behind every conclusion.",
                "developer_prompt": "Inspect the reconciliation path and identify the first causal divergence. Return a concise finding for the coordinator.",
                "messages": [
                    {"role": "user", "content": "Find why negative credits differ by one cent after the ledger repair."}
                ],
                "tools": [
                    {"name": "repo_search", "description": "Search repository text", "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}
                ],
                "usage": {
                    "input_tokens": 1296,
                    "output_tokens": 546,
                    "total_tokens": 1842,
                    "input_tokens_details": {"cached_tokens": 384},
                    "output_tokens_details": {"reasoning_tokens": 212},
                    "input_tokens_by_role": {"system": 302, "developer": 238, "user": 148, "tool": 608},
                    "cost_usd": 0.0047
                },
                "response": "The first divergence occurs after the ledger lock: the patched path rounds the negative credit after locking, producing -12.39 instead of -12.40.",
                "summary": "rounding occurs after ledger lock"
            }),
            at,
        )
    })?;
    let evidence = writer.append_input(EventInput {
        parent_event_id: researcher.event_id.clone(),
        duration_ms: 83,
        ..event(
            4_500,
            "tool.execution",
            "researcher",
            "subagent",
            "repo-search",
            "research",
            "ok",
            json!({"tool": "rg", "query": "reconcileInvoice", "matches": 7, "files": ["src/billing/ledger.ts", "tests/billing.test.ts"]}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: evidence.event_id.clone(),
        links: vec![evidence.event_id.clone(), coder.event_id.clone()],
        ..event(
            5_200,
            "agent.message",
            "researcher",
            "subagent",
            "research-result",
            "research",
            "ok",
            json!({"to": ["coordinator", "coder"], "finding": "round before lock; regression introduced in 9f43c7a"}),
            at,
        )
    })?;
    let approval = writer.append_input(EventInput {
        parent_event_id: coder.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        ..event(
            7_800,
            "approval.request",
            "coder",
            "subagent",
            "patch-approval",
            "implementation",
            "pending",
            json!({"operation": "write", "files": ["src/billing/ledger.ts"], "reason": "apply scoped ordering repair"}),
            at,
        )
    })?;
    let decision = writer.append_input(EventInput {
        parent_event_id: approval.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        ..event(
            12_400,
            "approval.decision",
            "brad",
            "human",
            "approval-decision",
            "patch-approval",
            "approved",
            json!({"scope": "src/billing/ledger.ts only", "expires_after": "single mutation", "receipt": "apr_01J"}),
            at,
        )
    })?;
    let patch = writer.append_input(EventInput {
        parent_event_id: decision.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        links: vec![evidence.event_id.clone(), decision.event_id.clone()],
        duration_ms: 176,
        ..event(
            13_100,
            "tool.execution",
            "coder",
            "subagent",
            "apply-patch",
            "implementation",
            "ok",
            json!({"tool": "apply_patch", "files_changed": 1, "additions": 8, "deletions": 3, "approval_receipt": "apr_01J"}),
            at,
        )
    })?;
    let reviewer = writer.append_input(EventInput {
        parent_event_id: patch.event_id.clone(),
        ..event(
            16_000,
            "agent.spawn",
            "reviewer",
            "subagent",
            "review",
            "run",
            "running",
            json!({"parent_actor": "coordinator", "task": "verify patch and scope"}),
            at,
        )
    })?;
    let failed_test = writer.append_input(EventInput {
        parent_event_id: reviewer.event_id.clone(),
        links: vec![patch.event_id.clone()],
        duration_ms: 912,
        ..event(
            17_200,
            "tool.error",
            "reviewer",
            "subagent",
            "test-suite",
            "review",
            "error",
            json!({"tool": "cargo test", "failed": "rounds_negative_credit", "expected": "-12.40", "actual": "-12.39"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: failed_test.event_id.clone(),
        links: vec![failed_test.event_id.clone(), patch.event_id.clone()],
        ..event(
            18_400,
            "agent.message",
            "reviewer",
            "subagent",
            "review-result",
            "review",
            "error",
            json!({"to": ["coordinator", "coder"], "finding": "negative credit rounding still diverges", "action": "repair before merge"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: root.event_id,
        links: vec![researcher.event_id, coder.event_id, reviewer.event_id],
        ..event(
            20_000,
            "agent.join",
            "coordinator",
            "agent",
            "join",
            "run",
            "error",
            json!({"joined": ["researcher", "coder", "reviewer"], "outcome": "repair required", "open_failures": 1}),
            at,
        )
    })?;
    let manifest = writer.finish(1)?;
    println!("demo trace {} → {}", manifest.trace_id, output.display());
    println!("next: premier open {}", output.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn event(
    offset_ms: i64,
    kind: &str,
    actor_id: &str,
    actor_type: &str,
    span_id: &str,
    parent_span_id: &str,
    status: &str,
    payload: serde_json::Value,
    at: impl Fn(i64) -> String,
) -> EventInput {
    EventInput {
        kind: kind.into(),
        source: "premier-demo".into(),
        actor_id: actor_id.into(),
        actor_type: actor_type.into(),
        span_id: span_id.into(),
        parent_span_id: parent_span_id.into(),
        status: status.into(),
        payload,
        timestamp: Some(at(offset_ms)),
        ..EventInput::default()
    }
}

struct RecordOptions {
    output: Option<PathBuf>,
    name: Option<String>,
    tenant: String,
    command: Vec<String>,
    open_viewer: bool,
    pty: bool,
    adapter: AdapterChoice,
    viewer_dir: Option<PathBuf>,
    bind: SocketAddr,
    redaction: RedactionConfig,
}

async fn record(options: RecordOptions) -> Result<()> {
    let RecordOptions {
        output,
        name,
        tenant,
        command,
        open_viewer,
        pty,
        adapter,
        viewer_dir,
        bind,
        redaction,
    } = options;
    #[cfg(not(unix))]
    if pty {
        bail!("--pty is currently supported only on Unix; use pipe capture without --pty")
    }
    let executable = command.first().context("a command is required")?;
    if pty && adapter.is_explicit() {
        bail!("native adapters require pipe capture with structured JSONL; omit --pty")
    }
    if open_viewer && tenant != premier_trace::LOCAL_TENANT {
        bail!(
            "--open serves the default local viewer identity, which cannot see a trace owned by tenant '{tenant}'; record without --open, then use `premier serve --auth-config` to view it"
        )
    }
    let native_provider = adapter.resolve(executable, &command[1..], pty);
    let output = output.unwrap_or_else(|| {
        let id = uuid_like_timestamp();
        PathBuf::from(format!(".premier/traces/{id}.atrace"))
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut trace_writer = TraceWriter::create_named_for_tenant_with_redaction(
        &output,
        command.clone(),
        name,
        &tenant,
        redaction,
    )?;
    if let Some(provider) = native_provider {
        trace_writer.set_adapter(premier_trace::AdapterProvenance {
            provider: provider.id().into(),
            schema_version: ADAPTER_SCHEMA_VERSION,
            transport: "stdout-jsonl".into(),
            completeness: "provider-native-best-effort".into(),
        })?;
    }
    if pty {
        trace_writer.add_capability("terminal.pty")?;
        trace_writer.add_capability("terminal.merged-output")?;
    }
    let writer = Arc::new(Mutex::new(trace_writer));
    let recorder_lease = RecorderLease::start(&output)?;
    let trace_id = writer.lock().unwrap().trace_id().to_owned();
    let collector_token = uuid::Uuid::now_v7().to_string();
    let collector_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let collector_address = collector_listener.local_addr()?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let collector_writer = writer.clone();
    let collector_token_for_server = collector_token.clone();
    let collector_task = tokio::spawn(async move {
        axum::serve(
            collector_listener,
            instrumentation_app(collector_writer, collector_token_for_server),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .await
    });
    #[cfg(unix)]
    let terminal = pty.then(terminal_size);
    #[cfg(not(unix))]
    let terminal: Option<()> = None;
    let mut session_payload = json!({
        "cwd": std::env::current_dir()?.to_string_lossy(),
        "command": command,
        "instrumentation": format!("http://{collector_address}/v1/events"),
        "capture_mode": if pty { "pty" } else { "pipes" },
        "adapter": native_provider.map(|provider| json!({
            "provider": provider.id(),
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "transport": "stdout-jsonl",
            "completeness": "provider-native-best-effort",
        })),
    });
    #[cfg(unix)]
    if let Some(size) = terminal {
        session_payload["terminal"] = json!({
            "mode": "pty",
            "rows": size.rows,
            "cols": size.cols,
            "pixel_width": size.pixel_width,
            "pixel_height": size.pixel_height,
            "streams": "merged",
        });
    }
    writer.lock().unwrap().append_input(EventInput {
        kind: "session.start".into(),
        source: "premier".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "session".into(),
        status: "running".into(),
        payload: session_payload,
        ..EventInput::default()
    })?;

    let collector_url = format!("http://{collector_address}/v1/events");
    let capture_environment = CaptureEnvironment {
        trace_id: &trace_id,
        collector_url: &collector_url,
        collector_token: &collector_token,
        native_provider,
    };
    let capture = if pty {
        #[cfg(unix)]
        {
            capture_pty(
                executable,
                &command[1..],
                terminal.expect("PTY terminal size"),
                capture_environment,
                &writer,
            )?
        }
        #[cfg(not(unix))]
        unreachable!("non-Unix PTY request rejected before trace creation")
    } else {
        capture_pipes(executable, &command[1..], capture_environment, &writer)?
    };
    recorder_lease.stop()?;
    let termination = capture.termination;
    let recorder_signal = capture.recorder_signal;
    let code = termination.shell_exit_code();
    let command_success = code == 0;
    let mut exit_payload = json!({
        "exit_code": code,
        "success": command_success,
        "termination": match termination.kind {
            TerminationKind::Exit => "exit",
            TerminationKind::Signal => "signal",
            TerminationKind::Interrupted => "interrupted",
        },
    });
    if let Some(signal) = termination.signal {
        exit_payload["signal"] = json!(signal);
    }
    if let Some(signal_name) = termination.signal_name.as_deref() {
        exit_payload["signal_name"] = json!(signal_name);
    }
    if recorder_signal.is_some() {
        exit_payload["forwarded_by_recorder"] = json!(true);
    }
    if capture.core_dumped {
        exit_payload["core_dumped"] = json!(true);
    }
    writer.lock().unwrap().append_input(EventInput {
        kind: "process.exit".into(),
        source: "command".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        status: if command_success { "ok" } else { "error" }.into(),
        payload: exit_payload,
        ..EventInput::default()
    })?;
    let _ = shutdown_sender.send(());
    collector_task.await??;
    let writer = Arc::try_unwrap(writer)
        .map_err(|_| anyhow::anyhow!("collector still owns the trace writer"))?
        .into_inner()
        .map_err(|_| anyhow::anyhow!("trace writer lock was poisoned"))?;
    let manifest = writer.finish_termination(termination.clone())?;
    eprintln!("\ntrace {} → {}", manifest.trace_id, output.display());
    if !command_success {
        match (
            &termination.kind,
            termination.signal,
            termination.signal_name.as_deref(),
        ) {
            (TerminationKind::Signal, Some(signal), Some(name)) => {
                eprintln!("recorded command terminated by {name} (signal {signal})");
            }
            (TerminationKind::Signal, Some(signal), None) => {
                eprintln!("recorded command terminated by signal {signal}");
            }
            _ => eprintln!("recorded command exited with status {code}"),
        }
    }
    eprintln!("next: premier open {}", output.display());
    if open_viewer && recorder_signal.is_none() {
        return serve_viewer(
            trace_parent_dir(&output),
            viewer_dir,
            bind,
            AuthPolicy::default(),
            Some(manifest.trace_id),
            true,
            None,
        )
        .await;
    }
    if command_success {
        Ok(())
    } else {
        std::process::exit(code.clamp(1, 255))
    }
}

#[derive(Clone, Copy)]
struct CaptureEnvironment<'a> {
    trace_id: &'a str,
    collector_url: &'a str,
    collector_token: &'a str,
    native_provider: Option<Provider>,
}

struct CaptureOutcome {
    termination: ProcessTermination,
    recorder_signal: Option<i32>,
    core_dumped: bool,
}

fn capture_pipes(
    executable: &str,
    args: &[String],
    environment: CaptureEnvironment<'_>,
    writer: &Arc<Mutex<TraceWriter>>,
) -> Result<CaptureOutcome> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PREMIER_TRACE_ID", environment.trace_id)
        .env("PREMIER_COLLECTOR_URL", environment.collector_url)
        .env("PREMIER_COLLECTOR_TOKEN", environment.collector_token)
        .spawn()
        .with_context(|| format!("failed to start {executable}"))?;

    #[cfg(unix)]
    let signal_forwarder = UnixSignalForwarder::start(child.id())?;

    // Bounded so a fast child is throttled by journal writes instead of
    // growing an in-memory queue without limit.
    let (sender, receiver) = mpsc::sync_channel::<(&'static str, Vec<u8>)>(256);
    pump(child.stdout.take().unwrap(), sender.clone(), "stdout");
    pump(child.stderr.take().unwrap(), sender, "stderr");
    let mut stdout_pending = Vec::new();
    let mut stderr_pending = Vec::new();
    let mut mirror_stdout = true;
    let mut mirror_stderr = true;
    let mut native_adapter = environment.native_provider.map(NativeAdapter::new);
    for (stream, bytes) in receiver {
        // A closed recorder stdout/stderr (for example `premier record -- cmd | head`)
        // stops mirroring but must never abort evidence capture.
        if stream == "stdout" {
            if mirror_stdout {
                mirror_stdout = std::io::stdout()
                    .write_all(&bytes)
                    .and_then(|()| std::io::stdout().flush())
                    .is_ok();
            }
        } else if mirror_stderr {
            mirror_stderr = std::io::stderr()
                .write_all(&bytes)
                .and_then(|()| std::io::stderr().flush())
                .is_ok();
        }
        let pending = if stream == "stdout" {
            &mut stdout_pending
        } else {
            &mut stderr_pending
        };
        append_process_bytes(writer, &format!("process.{stream}"), pending, &bytes)?;
        if stream == "stdout"
            && let Some(adapter) = native_adapter.as_mut()
        {
            append_adapter_events(writer, adapter.push(&bytes))?;
        }
    }
    for (stream, pending) in [
        ("stdout", &mut stdout_pending),
        ("stderr", &mut stderr_pending),
    ] {
        append_pending_utf8(writer, &format!("process.{stream}"), pending)?;
    }
    if let Some(adapter) = native_adapter.as_mut() {
        append_adapter_events(writer, adapter.finish())?;
    }
    let status = child.wait()?;
    #[cfg(unix)]
    let recorder_signal = signal_forwarder.finish()?;
    #[cfg(not(unix))]
    let recorder_signal: Option<i32> = None;
    let termination = recorder_signal.map_or_else(
        || process_termination(&status),
        |signal| ProcessTermination::signaled(signal, signal_name(signal).map(str::to_owned)),
    );
    #[cfg(unix)]
    let core_dumped = {
        use std::os::unix::process::ExitStatusExt;
        status.core_dumped()
    };
    #[cfg(not(unix))]
    let core_dumped = false;
    Ok(CaptureOutcome {
        termination,
        recorder_signal,
        core_dumped,
    })
}

#[cfg(unix)]
fn capture_pty(
    executable: &str,
    args: &[String],
    size: portable_pty::PtySize,
    environment: CaptureEnvironment<'_>,
    writer: &Arc<Mutex<TraceWriter>>,
) -> Result<CaptureOutcome> {
    use portable_pty::{CommandBuilder, native_pty_system};

    let pair = native_pty_system()
        .openpty(size)
        .context("failed to allocate pseudo-terminal")?;
    let mut command = CommandBuilder::new(executable);
    command.args(args);
    command.env("PREMIER_TRACE_ID", environment.trace_id);
    command.env("PREMIER_COLLECTOR_URL", environment.collector_url);
    command.env("PREMIER_COLLECTOR_TOKEN", environment.collector_token);
    let mut child = pair
        .slave
        .spawn_command(command)
        .with_context(|| format!("failed to start {executable} in pseudo-terminal"))?;
    drop(pair.slave);
    let child_pid = child
        .process_id()
        .context("PTY child process id is unavailable")?;
    let signal_forwarder = UnixSignalForwarder::start_process_group(child_pid)?;
    let mut reader = pair.master.try_clone_reader()?;
    let mut terminal_writer = pair.master.take_writer()?;
    let _raw_terminal = ParentTerminalMode::raw_if_interactive()?;
    let (release_stdin, wait_for_release) = mpsc::channel::<()>();
    thread::spawn(move || {
        let mut input = std::io::stdin();
        let _ = std::io::copy(&mut input, &mut terminal_writer);
        // portable-pty deliberately sends EOT when its writer is dropped.
        // Keep the writer alive after redirected stdin reaches EOF so that EOT
        // is not echoed into the captured stream ahead of the child output.
        let _ = wait_for_release.recv();
    });

    let mut pending = Vec::new();
    let mut buffer = vec![0_u8; 8192];
    let mut mirror = true;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let bytes = &buffer[..count];
                if mirror {
                    mirror = std::io::stdout()
                        .write_all(bytes)
                        .and_then(|()| std::io::stdout().flush())
                        .is_ok();
                }
                append_process_bytes(writer, "process.terminal", &mut pending, bytes)?;
            }
            // Unix PTY masters commonly report EIO after the final slave closes.
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => return Err(error).context("failed to read pseudo-terminal output"),
        }
    }
    append_pending_utf8(writer, "process.terminal", &mut pending)?;
    let status = child.wait()?;
    let _ = release_stdin.send(());
    let recorder_signal = signal_forwarder.finish()?;
    let termination = recorder_signal.map_or_else(
        || portable_process_termination(&status),
        |signal| ProcessTermination::signaled(signal, signal_name(signal).map(str::to_owned)),
    );
    Ok(CaptureOutcome {
        termination,
        recorder_signal,
        core_dumped: false,
    })
}

fn append_process_bytes(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<()> {
    let text = decode_utf8_chunk(pending, bytes);
    if text.is_empty() {
        return Ok(());
    }
    append_process_event(writer, kind, text, bytes.len())
}

fn append_process_event(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    text: String,
    byte_length: usize,
) -> Result<()> {
    writer.lock().unwrap().append_input(EventInput {
        kind: kind.into(),
        source: "command".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        status: "running".into(),
        payload: json!({
            "text": text,
            "byte_length": byte_length,
            "stream": if kind == "process.terminal" { "pty" } else { kind.trim_start_matches("process.") },
        }),
        ..EventInput::default()
    })?;
    Ok(())
}

fn append_pending_utf8(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut Vec<u8>,
) -> Result<()> {
    let byte_length = pending.len();
    let text = finish_utf8(pending);
    if text.is_empty() {
        return Ok(());
    }
    append_process_event(writer, kind, text, byte_length)
}

fn append_adapter_events(writer: &Arc<Mutex<TraceWriter>>, events: Vec<EventInput>) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let mut writer = writer.lock().unwrap();
    for event in events {
        writer.append_input(event)?;
    }
    Ok(())
}

#[cfg(unix)]
fn terminal_size() -> portable_pty::PtySize {
    for file_descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: winsize is a plain C data structure and each descriptor is a
        // process-owned standard stream. ioctl only writes to this local value.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(file_descriptor, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_row > 0
            && size.ws_col > 0
        {
            return portable_pty::PtySize {
                rows: size.ws_row,
                cols: size.ws_col,
                pixel_width: size.ws_xpixel,
                pixel_height: size.ws_ypixel,
            };
        }
    }
    let rows = std::env::var("LINES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(24);
    let cols = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(80);
    portable_pty::PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(unix)]
fn portable_process_termination(status: &portable_pty::ExitStatus) -> ProcessTermination {
    if let Some(description) = status.signal()
        && let Some(signal) = portable_signal_number(description)
    {
        return ProcessTermination::signaled(signal, signal_name(signal).map(str::to_owned));
    }
    ProcessTermination::exited(i32::try_from(status.exit_code()).unwrap_or(1))
}

#[cfg(unix)]
fn portable_signal_number(description: &str) -> Option<i32> {
    let normalized = description.to_ascii_lowercase();
    if normalized.contains("hangup") {
        Some(1)
    } else if normalized.contains("interrupt") {
        Some(2)
    } else if normalized.contains("quit") {
        Some(3)
    } else if normalized.contains("abort") {
        Some(6)
    } else if normalized.contains("killed") {
        Some(9)
    } else if normalized.contains("segmentation") {
        Some(11)
    } else if normalized.contains("broken pipe") {
        Some(13)
    } else if normalized.contains("alarm") {
        Some(14)
    } else if normalized.contains("terminated") {
        Some(15)
    } else {
        None
    }
}

#[cfg(unix)]
struct ParentTerminalMode(Option<libc::termios>);

#[cfg(unix)]
impl ParentTerminalMode {
    fn raw_if_interactive() -> Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(Self(None));
        }
        // SAFETY: tcgetattr/tcsetattr operate on our standard input terminal;
        // the original attributes are retained and restored by Drop.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cannot read terminal mode");
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cannot enter raw terminal mode");
        }
        Ok(Self(Some(original)))
    }
}

#[cfg(unix)]
impl Drop for ParentTerminalMode {
    fn drop(&mut self) {
        if let Some(original) = &self.0 {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
            }
        }
    }
}

struct RecorderLease {
    stop: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl RecorderLease {
    fn start(trace_root: &std::path::Path) -> Result<Self> {
        let path = trace_root.join(RECORDER_LEASE);
        std::fs::write(&path, std::process::id().to_string())?;
        let (stop, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                match receiver.recv_timeout(StdDuration::from_secs(2)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if std::fs::write(&path, std::process::id().to_string()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self { stop, thread })
    }

    fn stop(self) -> Result<()> {
        let _ = self.stop.send(());
        self.thread
            .join()
            .map_err(|_| anyhow::anyhow!("recorder lease thread panicked"))
    }
}

#[cfg(unix)]
struct UnixSignalForwarder {
    handle: signal_hook::iterator::Handle,
    thread: thread::JoinHandle<()>,
    received: Arc<AtomicI32>,
}

#[cfg(unix)]
impl UnixSignalForwarder {
    fn start(child_pid: u32) -> Result<Self> {
        Self::start_target(child_pid, false)
    }

    fn start_process_group(child_pid: u32) -> Result<Self> {
        Self::start_target(child_pid, true)
    }

    fn start_target(child_pid: u32, process_group: bool) -> Result<Self> {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;

        let child_pid = i32::try_from(child_pid).context("child process id exceeds i32")?;
        let signal_target = if process_group { -child_pid } else { child_pid };
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let handle = signals.handle();
        let received = Arc::new(AtomicI32::new(0));
        let received_by_thread = received.clone();
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                received_by_thread
                    .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst)
                    .ok();
                // SAFETY: `child_pid` came from the live child returned by
                // std::process::Command and SIGINT/SIGTERM are valid signals.
                // libc::kill is async-signal-safe; this call runs on the signal
                // iterator thread, not inside the OS signal handler.
                unsafe {
                    libc::kill(signal_target, signal);
                }
            }
        });
        Ok(Self {
            handle,
            thread,
            received,
        })
    }

    fn finish(self) -> Result<Option<i32>> {
        self.handle.close();
        self.thread
            .join()
            .map_err(|_| anyhow::anyhow!("signal forwarding thread panicked"))?;
        match self.received.load(Ordering::SeqCst) {
            0 => Ok(None),
            signal => Ok(Some(signal)),
        }
    }
}

fn process_termination(status: &std::process::ExitStatus) -> ProcessTermination {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ProcessTermination::signaled(signal, signal_name(signal).map(str::to_owned));
        }
    }
    ProcessTermination::exited(status.code().unwrap_or(1))
}

#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return None,
    })
}

#[cfg(not(unix))]
fn signal_name(_signal: i32) -> Option<&'static str> {
    None
}

fn pump(
    mut reader: impl Read + Send + 'static,
    sender: mpsc::SyncSender<(&'static str, Vec<u8>)>,
    stream: &'static str,
) {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send((stream, buffer[..count].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn list(trace_dir: PathBuf) -> Result<()> {
    if !trace_dir.exists() {
        return Ok(());
    }
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(trace_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && let Ok(manifest) = read_manifest(entry.path())
        {
            manifests.push(manifest);
        }
    }
    manifests.sort_by_key(|manifest| std::cmp::Reverse(manifest.started_at));
    for manifest in manifests {
        println!(
            "{}  {}  {}",
            manifest.trace_id,
            manifest.started_at,
            manifest.name.unwrap_or_else(|| manifest.command.join(" "))
        );
    }
    Ok(())
}

/// Directory that contains `trace`, treating the empty parent of a bare
/// relative path (`foo.atrace`) as the current directory so the viewer can
/// list and resolve it.
fn trace_parent_dir(trace: &std::path::Path) -> PathBuf {
    match trace.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn uuid_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "trace-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}
