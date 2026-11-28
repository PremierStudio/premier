//! `premier github` — CLI wrapper for GitHub Companion mode (Squash-Declassify PRs and
//! bidirectional zone sync).
//!
//! All companion state, vault storage, host validation, and git/REST transport delegate directly
//! to [`premier_server::github`] service functions — zero duplicated business logic.

use std::fmt::Write as _;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Subcommand, ValueEnum};
use premier_git_bridge::{ZoneSyncInResult, ZoneSyncOutResult};
use premier_policy::parse_policy_toml;
use premier_proxy::AuditSink;
use premier_server::ServerState;
use premier_server::github::{
    GithubCompanionStatus, GithubConfigPayload, GithubError, GithubPrPreviewResponse,
    GithubPrRequest, PublishGithubPrResult, SyncDirection, SyncInRequest, SyncOutRequest,
    service_configure, service_disconnect, service_preview_pr, service_publish_pr, service_status,
    service_sync_in, service_sync_out,
};
use zeroize::Zeroizing;

const LOCAL_ACTOR: &str = "@local";

/// Trim and drop empty entries from a repeatable host flag or comma-delimited env var.
pub(crate) fn clean_hosts(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SyncDirectionArg {
    Bidirectional,
    Outbound,
    Inbound,
}

impl From<SyncDirectionArg> for SyncDirection {
    fn from(value: SyncDirectionArg) -> Self {
        match value {
            SyncDirectionArg::Bidirectional => Self::Bidirectional,
            SyncDirectionArg::Outbound => Self::Outbound,
            SyncDirectionArg::Inbound => Self::Inbound,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum GithubCmd {
    /// Connect (or update) this repository's GitHub companion configuration.
    Connect {
        /// Target GitHub repository in `owner/repo` format.
        repo: String,
        /// Default branch on GitHub (defaults to `main`).
        #[arg(long = "branch")]
        default_branch: Option<String>,
        /// Optional named policy zone to project to GitHub.
        #[arg(long)]
        zone: Option<String>,
        /// Permitted sync direction with GitHub.
        #[arg(long, value_enum, default_value_t = SyncDirectionArg::Bidirectional)]
        direction: SyncDirectionArg,
        /// GitHub web host (defaults to `github.com`).
        #[arg(long)]
        host: Option<String>,
        /// GitHub REST API host (defaults to `api.github.com` for github.com, or `<host>`).
        #[arg(long = "api-host")]
        api_host: Option<String>,
        /// Enterprise GitHub hostnames permitted for companion connections (repeatable).
        #[arg(
            long = "allow-enterprise-host",
            env = "PREMIER_GITHUB_ENTERPRISE_HOSTS",
            value_delimiter = ','
        )]
        allow_enterprise_host: Vec<String>,
        /// Read the GitHub personal access token as a single line from stdin.
        #[arg(long = "token-stdin")]
        token_stdin: bool,
        /// Environment variable to read the GitHub token from (falls back to `GITHUB_TOKEN` on initial connect).
        #[arg(long = "token-env")]
        token_env: Option<String>,
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Disconnect the GitHub companion and purge its token from the encrypted vault.
    Disconnect {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Show GitHub companion connection status, sync cursors, zones, and PR receipts.
    Status {
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Dry-run a Squash-Declassify GitHub pull request locally (no network).
    PreviewPr {
        /// Canonical source branch to preview.
        branch: String,
        /// Target base branch on GitHub (defaults to the configured default branch).
        #[arg(long)]
        base: Option<String>,
        /// Head branch name to publish on GitHub.
        #[arg(long = "pr-branch")]
        pr_branch: Option<String>,
        /// Pull request title override.
        #[arg(long)]
        title: Option<String>,
        /// Pull request body override.
        #[arg(long)]
        body: Option<String>,
        /// Print unified diff patches for each published file.
        #[arg(long)]
        diff: bool,
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Publish a branch to GitHub as a single Squash-Declassify commit and open a pull request.
    PublishPr {
        /// Canonical source branch to publish.
        branch: String,
        /// Target base branch on GitHub (defaults to the configured default branch).
        #[arg(long)]
        base: Option<String>,
        /// Head branch name to publish on GitHub.
        #[arg(long = "pr-branch")]
        pr_branch: Option<String>,
        /// Pull request title override.
        #[arg(long)]
        title: Option<String>,
        /// Pull request body override.
        #[arg(long)]
        body: Option<String>,
        /// Open the pull request as a draft.
        #[arg(long)]
        draft: bool,
        /// Optional local Premier review change ID to link with the created PR.
        #[arg(long = "change-id")]
        change_id: Option<String>,
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Project the canonical branch's public zone onto GitHub and push it.
    SyncOut {
        /// Canonical source branch (defaults to repository default branch).
        #[arg(long)]
        branch: Option<String>,
        /// Target branch on GitHub (defaults to configured default branch).
        #[arg(long)]
        target: Option<String>,
        /// Optional zone override.
        #[arg(long)]
        zone: Option<String>,
        /// Mirror individual public commits instead of squashing (retains scrubbed commit messages).
        #[arg(long = "no-squash")]
        no_squash: bool,
        /// Collapse pending commits into a single squashed commit (default).
        #[arg(long, conflicts_with = "no_squash")]
        squash: bool,
        /// Commit message used when squashing commits.
        #[arg(long)]
        message: Option<String>,
        /// Plan the sync without pushing or updating sync cursors.
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Import public commits from GitHub onto the canonical branch, preserving hidden files.
    SyncIn {
        /// Upstream ref or branch name on GitHub (defaults to configured default branch).
        #[arg(long = "upstream-ref")]
        upstream_ref: Option<String>,
        /// Pull request number on GitHub (`refs/pull/<N>/head`).
        #[arg(long)]
        pr: Option<u64>,
        /// Canonical target branch (defaults to repository default branch).
        #[arg(long)]
        target: Option<String>,
        /// Plan and validate policy compliance without modifying canonical refs.
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Optional server-enforced `.access.toml` policy override.
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
}

fn should_reuse_existing_token(
    current: Option<&premier_server::github::GithubCompanionConfigStored>,
    requested_host: Option<&str>,
) -> bool {
    let target_host = requested_host
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or("github.com");
    current.is_some_and(|c| c.token_configured && c.host.eq_ignore_ascii_case(target_host))
}

pub async fn handle_github(cmd: GithubCmd) -> Result<()> {
    enum TokenChoice {
        Provided(Option<Zeroizing<String>>),
        PromptOrAmbient,
    }
    let choice = match &cmd {
        GithubCmd::Connect {
            token_stdin,
            token_env,
            ..
        } => {
            if *token_stdin {
                let stdin = std::io::stdin();
                let mut locked = stdin.lock();
                TokenChoice::Provided(Some(read_token_from_reader(&mut locked)?))
            } else if let Some(var_name) = token_env {
                let tok = read_token_from_env(var_name).with_context(|| {
                    format!("environment variable '{var_name}' is not set or is empty")
                })?;
                TokenChoice::Provided(Some(tok))
            } else {
                TokenChoice::PromptOrAmbient
            }
        }
        _ => TokenChoice::Provided(None),
    };

    let cwd = std::env::current_dir()?;
    let state = build_state_for_cmd(&cwd, &cmd)?;
    let supplied_token = match choice {
        TokenChoice::Provided(tok) => tok,
        TokenChoice::PromptOrAmbient => {
            if let GithubCmd::Connect { host, .. } = &cmd {
                let current = service_status(&state, LOCAL_ACTOR)
                    .await
                    .ok()
                    .and_then(|s| s.config);
                if should_reuse_existing_token(current.as_ref(), host.as_deref()) {
                    None
                } else {
                    read_token_from_env("GITHUB_TOKEN")
                }
            } else {
                None
            }
        }
    };
    let mut out = String::new();
    let res = run_github_with_state(&state, cmd, supplied_token, &mut out).await;
    if !out.is_empty() {
        print!("{out}");
    }
    res
}

fn read_token_from_reader(reader: &mut impl BufRead) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(String::new());
    reader
        .read_line(&mut raw)
        .context("failed to read GitHub token from stdin")?;
    let trimmed = Zeroizing::new(raw.trim().to_owned());
    if trimmed.is_empty() {
        bail!("--token-stdin received an empty token");
    }
    Ok(trimmed)
}

fn read_token_from_env(var_name: &str) -> Option<Zeroizing<String>> {
    let raw = Zeroizing::new(std::env::var(var_name).ok()?);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Zeroizing::new(trimmed.to_owned()))
    }
}

fn resolve_in_workspace(workspace_root: &Path, path: &Path) -> PathBuf {
    if path.is_relative() {
        workspace_root.join(path)
    } else {
        path.to_path_buf()
    }
}

fn build_cli_state(
    workspace_root: &Path,
    server_policy_path: Option<&Path>,
    enterprise_hosts: &[String],
) -> Result<ServerState> {
    let mut state = ServerState::try_minimal(
        None,
        None,
        Arc::new(AuditSink::new(Some(premier_server::store::audit_path(
            workspace_root,
        )))),
    )
    .map_err(anyhow::Error::msg)?;
    state.workspace_root = workspace_root.to_path_buf();
    state.persisted = Arc::new(std::sync::Mutex::new(
        premier_server::store::load_state(workspace_root).map_err(anyhow::Error::msg)?,
    ));
    state.auth = Arc::new(premier_server::auth::AuthStore::open(workspace_root));
    state.github_enterprise_hosts = Arc::new(clean_hosts(enterprise_hosts));

    let effective_server_policy: Option<PathBuf> = match server_policy_path {
        Some(path) => Some(resolve_in_workspace(workspace_root, path)),
        None => {
            let marker =
                premier_server::store::state_dir(workspace_root).join("server-policy-path.txt");
            if marker.exists() {
                let raw = std::fs::read_to_string(&marker).with_context(|| {
                    format!(
                        "failed to read persisted server policy marker {}",
                        marker.display()
                    )
                })?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    bail!(
                        "persisted server policy marker {} is empty",
                        marker.display()
                    );
                }
                Some(resolve_in_workspace(workspace_root, Path::new(trimmed)))
            } else {
                None
            }
        }
    };

    if let Some(resolved) = effective_server_policy {
        let text = std::fs::read_to_string(&resolved)
            .with_context(|| format!("failed to read server policy {}", resolved.display()))?;
        parse_policy_toml(&text)
            .with_context(|| format!("failed to parse server policy {}", resolved.display()))?;
        state.server_policy_toml = Some(text);
        state.server_policy_path = Some(resolved);
    }

    // Always enforce the policy committed on the default branch (`HEAD:.access.toml`)
    // layered under the server policy, ignoring any uncommitted working-tree edits.
    state.reload_repo_config().map_err(anyhow::Error::msg)?;

    Ok(state)
}

fn build_state_for_cmd(workspace_root: &Path, cmd: &GithubCmd) -> Result<ServerState> {
    match cmd {
        GithubCmd::Connect {
            allow_enterprise_host,
            server_policy,
            ..
        } => build_cli_state(
            workspace_root,
            server_policy.as_deref(),
            allow_enterprise_host,
        ),
        GithubCmd::Disconnect { .. } => build_cli_state(workspace_root, None, &[]),
        GithubCmd::Status { server_policy, .. }
        | GithubCmd::PreviewPr { server_policy, .. }
        | GithubCmd::PublishPr { server_policy, .. }
        | GithubCmd::SyncOut { server_policy, .. }
        | GithubCmd::SyncIn { server_policy, .. } => {
            build_cli_state(workspace_root, server_policy.as_deref(), &[])
        }
    }
}

async fn run_github_with_state(
    state: &ServerState,
    cmd: GithubCmd,
    supplied_token: Option<Zeroizing<String>>,
    out: &mut String,
) -> Result<()> {
    match cmd {
        GithubCmd::Connect {
            repo,
            default_branch,
            zone,
            direction,
            host,
            api_host,
            token_env,
            json,
            ..
        } => {
            let token = match supplied_token {
                Some(tok) => Some((*tok).clone()),
                None => {
                    let current = service_status(state, LOCAL_ACTOR)
                        .await
                        .map_err(|e| format_github_error(&e, json, out))?;
                    let already_configured =
                        should_reuse_existing_token(current.config.as_ref(), host.as_deref());
                    if !already_configured {
                        let env_hint = token_env.as_deref().unwrap_or("GITHUB_TOKEN");
                        bail!(
                            "no GitHub token supplied: pipe a token via --token-stdin or set the '{env_hint}' environment variable"
                        );
                    }
                    None
                }
            };
            let payload = GithubConfigPayload {
                repo,
                default_branch,
                zone,
                sync_direction: Some(direction.into()),
                host,
                api_host,
                token,
            };
            let status = service_configure(state, LOCAL_ACTOR, payload)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&status))?;
            } else {
                format_connect_summary(out, &status);
            }
            Ok(())
        }

        GithubCmd::Disconnect { json } => {
            service_disconnect(state, LOCAL_ACTOR)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(
                    out,
                    serde_json::to_string_pretty(&serde_json::json!({ "ok": true })),
                )?;
            } else {
                let _ = writeln!(
                    out,
                    "Disconnected GitHub companion (token purged from vault; PR receipts preserved)."
                );
            }
            Ok(())
        }

        GithubCmd::Status { json, .. } => {
            let status = service_status(state, LOCAL_ACTOR)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&status))?;
            } else {
                format_status(out, &status);
            }
            Ok(())
        }

        GithubCmd::PreviewPr {
            branch,
            base,
            pr_branch,
            title,
            body,
            diff,
            json,
            ..
        } => {
            let req = GithubPrRequest {
                source_branch: branch,
                base_branch: base,
                pr_branch,
                title,
                body,
                draft: false,
                change_id: None,
            };
            let preview = service_preview_pr(state, LOCAL_ACTOR, &req)
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&preview))?;
            } else {
                format_preview_pr(out, &preview, diff);
            }
            if !preview.gate_passed {
                let detail = preview
                    .reason
                    .as_deref()
                    .unwrap_or("visibility escalation gate did not pass");
                bail!("preview-pr gate failed: {detail}");
            }
            Ok(())
        }

        GithubCmd::PublishPr {
            branch,
            base,
            pr_branch,
            title,
            body,
            draft,
            change_id,
            json,
            ..
        } => {
            let req = GithubPrRequest {
                source_branch: branch,
                base_branch: base,
                pr_branch,
                title,
                body,
                draft,
                change_id,
            };
            let published = service_publish_pr(state, LOCAL_ACTOR, req)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&published))?;
            } else {
                format_publish_pr(out, &published);
            }
            Ok(())
        }

        GithubCmd::SyncOut {
            branch,
            target,
            zone,
            no_squash,
            squash: _,
            message,
            dry_run,
            json,
            ..
        } => {
            let req = SyncOutRequest {
                source_branch: branch,
                target_branch: target,
                zone,
                squash: !no_squash,
                summary_message: message,
                dry_run,
            };
            let res = service_sync_out(state, LOCAL_ACTOR, req)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&res))?;
            } else {
                format_sync_out(out, &res);
            }
            if !res.blocked.is_empty() {
                bail!(
                    "sync-out blocked: {} public path(s) carry restricted content",
                    res.blocked.len()
                );
            }
            Ok(())
        }

        GithubCmd::SyncIn {
            upstream_ref,
            pr,
            target,
            dry_run,
            json,
            ..
        } => {
            let req = SyncInRequest {
                upstream_ref,
                pr_number: pr,
                target_branch: target,
                dry_run,
            };
            let res = service_sync_in(state, LOCAL_ACTOR, req)
                .await
                .map_err(|e| format_github_error(&e, json, out))?;
            if json {
                write_json(out, serde_json::to_string_pretty(&res))?;
            } else {
                format_sync_in(out, &res);
            }
            if !res.policy_violations.is_empty() {
                bail!(
                    "sync-in refused: {} inbound policy violation(s)",
                    res.policy_violations.len()
                );
            }
            if !res.conflicts.is_empty() {
                bail!(
                    "sync-in refused: {} conflicting path(s)",
                    res.conflicts.len()
                );
            }
            Ok(())
        }
    }
}

fn write_json(out: &mut String, serialized: serde_json::Result<String>) -> Result<()> {
    let serialized = serialized?;
    let _ = writeln!(out, "{serialized}");
    Ok(())
}

fn format_github_error(err: &GithubError, json: bool, out: &mut String) -> anyhow::Error {
    if json {
        if let Ok(serialized) = serde_json::to_string_pretty(&err.body) {
            let _ = writeln!(out, "{serialized}");
        }
        return anyhow::anyhow!("{err}");
    }

    if let Ok(val) = serde_json::to_value(&err.body) {
        if let Some(violations) = val.get("policy_violations").and_then(|v| v.as_array())
            && !violations.is_empty()
        {
            let _ = writeln!(out, "Inbound policy violations ({}):", violations.len());
            for v in violations {
                let oid = v.get("commit_oid").and_then(|x| x.as_str()).unwrap_or("?");
                let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("?");
                let reason = v.get("reason").and_then(|x| x.as_str()).unwrap_or("?");
                let _ = writeln!(out, "  - [{}] {}: {}", short_oid(oid), path, reason);
            }
        }
        if let Some(conflicts) = val.get("conflicts").and_then(|v| v.as_array())
            && !conflicts.is_empty()
        {
            let _ = writeln!(out, "Conflicts ({}):", conflicts.len());
            for c in conflicts {
                if let Some(path) = c.as_str() {
                    let _ = writeln!(out, "  - {path}");
                }
            }
        }
        if let Some(hidden) = val.get("hidden_conflicts").and_then(|v| v.as_u64())
            && hidden > 0
        {
            let _ = writeln!(out, "  (+ {hidden} hidden conflict(s))");
        }
        if let Some(blocked) = val.get("blocked").and_then(|v| v.as_array())
            && !blocked.is_empty()
        {
            let _ = writeln!(out, "Blocked paths ({}):", blocked.len());
            for b in blocked {
                if let Some(path) = b.as_str() {
                    let _ = writeln!(out, "  - {path}");
                }
            }
        }
        if let Some(hidden) = val.get("hidden_blocked").and_then(|v| v.as_u64())
            && hidden > 0
        {
            let _ = writeln!(out, "  (+ {hidden} hidden blocked path(s))");
        }
    }

    anyhow::anyhow!("{err}")
}

fn short_oid(oid: &str) -> &str {
    let end = oid.len().min(12);
    &oid[..end]
}

fn direction_label(dir: SyncDirection) -> &'static str {
    match dir {
        SyncDirection::Bidirectional => "bidirectional",
        SyncDirection::Outbound => "outbound",
        SyncDirection::Inbound => "inbound",
    }
}

fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

fn format_connect_summary(out: &mut String, status: &GithubCompanionStatus) {
    if let Some(cfg) = &status.config {
        let _ = writeln!(out, "Connected GitHub companion: {}", cfg.full_name);
        let _ = writeln!(out, "  host:             {}", cfg.host);
        let _ = writeln!(out, "  api_host:         {}", cfg.api_host);
        let _ = writeln!(out, "  default_branch:   {}", cfg.default_branch);
        let _ = writeln!(
            out,
            "  zone:             {}",
            cfg.zone.as_deref().unwrap_or("(default public)")
        );
        let _ = writeln!(
            out,
            "  sync_direction:   {}",
            direction_label(cfg.sync_direction)
        );
        let _ = writeln!(out, "  token configured: {}", yes_no(cfg.token_configured));
    } else {
        let _ = writeln!(out, "GitHub companion is not connected.");
    }
}

fn format_status(out: &mut String, status: &GithubCompanionStatus) {
    if !status.connected {
        let _ = writeln!(out, "GitHub companion: not connected");
    } else if let Some(cfg) = &status.config {
        let _ = writeln!(out, "GitHub companion: connected");
        let _ = writeln!(out, "  repo:             {}", cfg.full_name);
        let _ = writeln!(out, "  host:             {}", cfg.host);
        let _ = writeln!(out, "  api_host:         {}", cfg.api_host);
        let _ = writeln!(out, "  default_branch:   {}", cfg.default_branch);
        let _ = writeln!(
            out,
            "  zone:             {}",
            cfg.zone.as_deref().unwrap_or("(default public)")
        );
        let _ = writeln!(
            out,
            "  sync_direction:   {}",
            direction_label(cfg.sync_direction)
        );
        let _ = writeln!(out, "  token configured: {}", yes_no(cfg.token_configured));
    }

    if let Some(sync) = &status.sync_state {
        let _ = writeln!(out, "Sync state:");
        let _ = writeln!(
            out,
            "  last_canonical_oid: {}",
            sync.last_canonical_oid
                .as_deref()
                .map(short_oid)
                .unwrap_or("(none)")
        );
        let _ = writeln!(
            out,
            "  last_upstream_oid:  {}",
            sync.last_upstream_oid
                .as_deref()
                .map(short_oid)
                .unwrap_or("(none)")
        );
        let _ = writeln!(out, "  mapped_commits:     {}", sync.mapped_commits);
        let _ = writeln!(
            out,
            "  last_sync_out_at:   {}",
            sync.last_sync_out_at.as_deref().unwrap_or("(never)")
        );
        let _ = writeln!(
            out,
            "  last_sync_in_at:    {}",
            sync.last_sync_in_at.as_deref().unwrap_or("(never)")
        );
        if let Some(summary) = &sync.last_sync_summary {
            let _ = writeln!(out, "  last_sync_summary:  {summary}");
        }
    }

    if status.available_zones.is_empty() {
        let _ = writeln!(out, "Available zones: (none)");
    } else {
        let _ = writeln!(
            out,
            "Available zones: {}",
            status.available_zones.join(", ")
        );
    }

    if !status.enterprise_hosts_allowed.is_empty() {
        let _ = writeln!(
            out,
            "Allowed enterprise hosts: {}",
            status.enterprise_hosts_allowed.join(", ")
        );
    }

    if status.receipts.is_empty() {
        let _ = writeln!(out, "PR receipts: (none)");
    } else {
        let _ = writeln!(out, "PR receipts ({}):", status.receipts.len());
        for r in &status.receipts {
            let _ = writeln!(
                out,
                "  - #{} {} ({} -> {}, published={}, scrubbed={}) {}",
                r.pr_number,
                r.pr_title,
                r.source_branch,
                r.base_branch,
                r.published_paths.len(),
                r.scrubbed_paths_count,
                r.pr_url
            );
        }
    }
}

fn format_preview_pr(out: &mut String, preview: &GithubPrPreviewResponse, show_diff: bool) {
    let _ = writeln!(out, "GitHub PR Preview: {}", preview.repo);
    let _ = writeln!(
        out,
        "  branches:  {} -> {} (pr_branch: {})",
        preview.source_branch, preview.base_branch, preview.pr_branch
    );
    let _ = writeln!(
        out,
        "  zone:      {}",
        preview.zone.as_deref().unwrap_or("(default public)")
    );
    let _ = writeln!(
        out,
        "  gate:      {}",
        if preview.gate_passed {
            "PASSED"
        } else {
            "FAILED"
        }
    );
    if let Some(reason) = &preview.reason {
        let _ = writeln!(out, "  reason:    {reason}");
    }
    let _ = writeln!(out, "  pr_title:  {}", preview.pr_title);

    let meta = &preview.scrubbed_metadata;
    let _ = writeln!(out, "Scrubbed metadata checklist:");
    let _ = writeln!(
        out,
        "  commits_squashed:            {}",
        meta.commits_squashed
    );
    let _ = writeln!(
        out,
        "  private_ancestry_stripped:   {}",
        yes_no(meta.private_ancestry_stripped)
    );
    let _ = writeln!(
        out,
        "  canonical_oids_stripped:     {}",
        yes_no(meta.canonical_oids_stripped)
    );
    let _ = writeln!(
        out,
        "  copyfrom_history_stripped:   {}",
        yes_no(meta.copyfrom_history_stripped)
    );
    let _ = writeln!(
        out,
        "  source_branch_name_redacted: {}",
        yes_no(meta.source_branch_name_redacted)
    );
    let _ = writeln!(
        out,
        "  omitted_paths_count:         {}",
        meta.omitted_paths_count
    );

    let _ = writeln!(out, "Published paths ({}):", preview.published_paths.len());
    for p in &preview.published_paths {
        let _ = writeln!(out, "  + {p}");
    }

    let _ = writeln!(out, "Scrubbed paths ({}):", preview.scrubbed_paths.len());
    for p in &preview.scrubbed_paths {
        if let Some(why) = preview.held_back_reasons.get(p) {
            let _ = writeln!(out, "  - {p} ({why})");
        } else {
            let _ = writeln!(out, "  - {p}");
        }
    }

    if !preview.conflicts.is_empty() {
        let _ = writeln!(out, "Conflicts ({}):", preview.conflicts.len());
        for c in &preview.conflicts {
            let _ = writeln!(out, "  ! {c}");
        }
    }

    if !preview.blocked.is_empty() {
        let _ = writeln!(out, "Blocked ({}):", preview.blocked.len());
        for b in &preview.blocked {
            let _ = writeln!(out, "  x {b}");
        }
    }

    let _ = writeln!(out, "Attestation: {}", preview.attestation_trailer);

    if show_diff {
        let _ = writeln!(out, "Diffs ({}):", preview.diffs.len());
        for d in &preview.diffs {
            let _ = writeln!(
                out,
                "--- {} [{}] (+{}/-{}{}{})",
                d.path,
                d.status,
                d.additions,
                d.deletions,
                if d.binary { ", binary" } else { "" },
                if d.truncated { ", truncated" } else { "" },
            );
            if !d.patch.is_empty() {
                let _ = writeln!(out, "{}", d.patch.trim_end());
            }
        }
        if preview.diff_truncated {
            let _ = writeln!(out, "(diff output truncated)");
        }
    }
}

fn format_publish_pr(out: &mut String, published: &PublishGithubPrResult) {
    let r = &published.receipt;
    let _ = writeln!(out, "Published GitHub PR #{}: {}", r.pr_number, r.pr_url);
    let _ = writeln!(out, "  title:             {}", r.pr_title);
    let _ = writeln!(
        out,
        "  branches:          {} -> {} (pr_branch: {})",
        r.source_branch, r.base_branch, r.pr_branch
    );
    let _ = writeln!(out, "  public_commit_oid: {}", r.public_commit_oid);
    let _ = writeln!(
        out,
        "  published_paths:   {}",
        published.published_paths.len()
    );
    let _ = writeln!(
        out,
        "  scrubbed_paths:    {}",
        published.scrubbed_paths.len()
    );
    let _ = writeln!(out, "  attestation:       {}", r.attestation_trailer);
}

fn format_sync_out(out: &mut String, res: &ZoneSyncOutResult) {
    let _ = writeln!(
        out,
        "GitHub sync-out{}: {} -> {}",
        if res.dry_run { " (dry-run)" } else { "" },
        res.source_branch,
        res.target_branch
    );
    let _ = writeln!(
        out,
        "  zone:              {}",
        res.zone.as_deref().unwrap_or("(default public)")
    );
    let _ = writeln!(out, "  up_to_date:        {}", yes_no(res.up_to_date));
    let _ = writeln!(out, "  commits_projected: {}", res.commits_projected);
    let _ = writeln!(out, "  commits_collapsed: {}", res.commits_collapsed);
    let _ = writeln!(out, "  published_paths:   {}", res.published_paths.len());
    let _ = writeln!(out, "  scrubbed_paths:    {}", res.scrubbed_paths.len());
    let _ = writeln!(out, "  canonical_tip:     {}", res.canonical_tip);
    let _ = writeln!(
        out,
        "  upstream_tip:      {}",
        res.upstream_tip.as_deref().unwrap_or("(none)")
    );
    if !res.blocked.is_empty() {
        let _ = writeln!(out, "  blocked ({}):", res.blocked.len());
        for b in &res.blocked {
            let _ = writeln!(out, "    x {b}");
        }
    }
    let _ = writeln!(out, "  attestation:       {}", res.attestation_trailer);
}

fn format_sync_in(out: &mut String, res: &ZoneSyncInResult) {
    let _ = writeln!(
        out,
        "GitHub sync-in{}: {} -> {}",
        if res.dry_run { " (dry-run)" } else { "" },
        res.upstream_ref,
        res.target_branch
    );
    let _ = writeln!(
        out,
        "  zone:                   {}",
        res.zone.as_deref().unwrap_or("(default public)")
    );
    let _ = writeln!(out, "  up_to_date:             {}", yes_no(res.up_to_date));
    let _ = writeln!(out, "  commits_imported:       {}", res.commits_imported);
    let _ = writeln!(
        out,
        "  imported_paths:         {}",
        res.imported_paths.len()
    );
    let _ = writeln!(
        out,
        "  preserved_hidden_count: {}",
        res.preserved_hidden_count
    );
    let _ = writeln!(out, "  upstream_tip:           {}", res.upstream_tip);
    let _ = writeln!(
        out,
        "  new_canonical_tip:      {}",
        res.new_canonical_tip.as_deref().unwrap_or("(unchanged)")
    );
    if !res.policy_violations.is_empty() {
        let _ = writeln!(
            out,
            "  policy_violations ({}):",
            res.policy_violations.len()
        );
        for v in &res.policy_violations {
            let _ = writeln!(
                out,
                "    - [{}] {}: {}",
                short_oid(&v.commit_oid),
                v.path,
                v.reason
            );
        }
    }
    if !res.conflicts.is_empty() {
        let _ = writeln!(out, "  conflicts ({}):", res.conflicts.len());
        for c in &res.conflicts {
            let _ = writeln!(out, "    ! {c}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Cursor;
    use std::sync::Mutex;

    use clap::Parser;
    use premier_server::github::GithubTestOverride;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::{Cli, Commands};

    const TEST_TOKEN: &str = "ghp_CLI_TEST_TOKEN_0123456789abcdefSECRET";

    const TEST_POLICY: &str = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.public]
paths = ["apps/**", "README.md"]

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=Alice", "-c", "user.email=alice@acme.test"])
            .args(["-c", "core.autocrlf=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn write_files(dir: &Path, files: &[(&str, &str)]) {
        for (rel, content) in files {
            let full = dir.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full, content).unwrap();
        }
    }

    fn commit_files(dir: &Path, files: &[(&str, &str)], message: &str) -> String {
        write_files(dir, files);
        let mut args = vec!["add", "--"];
        args.extend(files.iter().map(|(p, _)| *p));
        git(dir, &args);
        git(dir, &["commit", "-q", "-m", message]);
        git(dir, &["rev-parse", "HEAD"])
    }

    #[derive(Clone, Default)]
    struct MockGithubApi {
        calls: Arc<Mutex<Vec<(String, String, serde_json::Value)>>>,
    }

    impl MockGithubApi {
        async fn start() -> (Self, String) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mock = Self::default();
            let calls = mock.calls.clone();

            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let calls = calls.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let header_end = loop {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    buf.extend_from_slice(&chunk[..n]);
                                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                                    {
                                        break pos + 4;
                                    }
                                }
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                        let mut lines = head.lines();
                        let req_line = lines.next().unwrap_or_default().to_owned();
                        let mut content_length: usize = 0;
                        let mut auth = String::new();
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse().unwrap_or(0);
                                } else if k.eq_ignore_ascii_case("authorization") {
                                    auth = v.trim().to_owned();
                                }
                            }
                        }
                        while buf.len() < header_end + content_length {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let body_bytes =
                            &buf[header_end..(header_end + content_length).min(buf.len())];
                        let body: serde_json::Value =
                            serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null);
                        calls.lock().unwrap().push((req_line, auth, body));

                        let resp_body = serde_json::json!({
                            "number": 42,
                            "html_url": "https://github.com/acme/sdk/pull/42"
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            });

            (mock, format!("http://{addr}"))
        }

        fn calls(&self) -> Vec<(String, String, serde_json::Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[test]
    fn cli_parses_all_github_subcommands_and_serve_enterprise_hosts() {
        let connect = Cli::try_parse_from([
            "premier",
            "github",
            "connect",
            "acme/sdk",
            "--branch",
            "develop",
            "--zone",
            "public",
            "--direction",
            "outbound",
            "--host",
            "ghe.acme.test",
            "--api-host",
            "api.ghe.acme.test",
            "--allow-enterprise-host",
            "ghe.acme.test,api.ghe.acme.test",
            "--token-stdin",
            "--token-env",
            "MY_GH_TOKEN",
            "--server-policy",
            "server.access.toml",
            "--json",
        ])
        .unwrap();
        let Commands::Github {
            cmd:
                GithubCmd::Connect {
                    repo,
                    default_branch,
                    zone,
                    direction,
                    host,
                    api_host,
                    allow_enterprise_host,
                    token_stdin,
                    token_env,
                    server_policy,
                    json,
                },
        } = connect.command
        else {
            panic!("expected github connect");
        };
        assert_eq!(repo, "acme/sdk");
        assert_eq!(default_branch.as_deref(), Some("develop"));
        assert_eq!(zone.as_deref(), Some("public"));
        assert_eq!(direction, SyncDirectionArg::Outbound);
        assert_eq!(host.as_deref(), Some("ghe.acme.test"));
        assert_eq!(api_host.as_deref(), Some("api.ghe.acme.test"));
        assert_eq!(
            allow_enterprise_host,
            vec!["ghe.acme.test", "api.ghe.acme.test"]
        );
        assert!(token_stdin);
        assert_eq!(token_env.as_deref(), Some("MY_GH_TOKEN"));
        assert_eq!(server_policy, Some(PathBuf::from("server.access.toml")));
        assert!(json);

        let disconnect =
            Cli::try_parse_from(["premier", "github", "disconnect", "--json"]).unwrap();
        assert!(matches!(
            disconnect.command,
            Commands::Github {
                cmd: GithubCmd::Disconnect { json: true }
            }
        ));

        let status = Cli::try_parse_from([
            "premier",
            "github",
            "status",
            "--server-policy",
            "srv.toml",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            status.command,
            Commands::Github {
                cmd: GithubCmd::Status {
                    server_policy: Some(_),
                    json: true,
                }
            }
        ));

        // `--policy` is refused across `premier github` export/config commands so only the
        // committed `HEAD:.access.toml` (+ server policy) applies.
        assert!(
            Cli::try_parse_from(["premier", "github", "sync-out", "--policy", ".access.toml"])
                .is_err()
        );

        let preview = Cli::try_parse_from([
            "premier",
            "github",
            "preview-pr",
            "feature/ui",
            "--base",
            "main",
            "--pr-branch",
            "pr/ui",
            "--title",
            "UI update",
            "--body",
            "Details",
            "--diff",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            preview.command,
            Commands::Github {
                cmd: GithubCmd::PreviewPr {
                    ref branch,
                    diff: true,
                    json: true,
                    ..
                }
            } if branch == "feature/ui"
        ));

        let publish = Cli::try_parse_from([
            "premier",
            "github",
            "publish-pr",
            "feature/ui",
            "--base",
            "main",
            "--pr-branch",
            "pr/ui",
            "--title",
            "UI update",
            "--body",
            "Details",
            "--draft",
            "--change-id",
            "chg_123",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            publish.command,
            Commands::Github {
                cmd: GithubCmd::PublishPr {
                    ref branch,
                    draft: true,
                    change_id: Some(ref cid),
                    json: true,
                    ..
                }
            } if branch == "feature/ui" && cid == "chg_123"
        ));

        let sync_out = Cli::try_parse_from([
            "premier",
            "github",
            "sync-out",
            "--branch",
            "main",
            "--target",
            "main",
            "--zone",
            "public",
            "--no-squash",
            "--message",
            "Weekly sync",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            sync_out.command,
            Commands::Github {
                cmd: GithubCmd::SyncOut {
                    no_squash: true,
                    squash: false,
                    dry_run: true,
                    json: true,
                    ..
                }
            }
        ));

        let sync_out_default = Cli::try_parse_from(["premier", "github", "sync-out"]).unwrap();
        assert!(matches!(
            sync_out_default.command,
            Commands::Github {
                cmd: GithubCmd::SyncOut {
                    no_squash: false,
                    ..
                }
            }
        ));

        let sync_in = Cli::try_parse_from([
            "premier",
            "github",
            "sync-in",
            "--upstream-ref",
            "main",
            "--pr",
            "42",
            "--target",
            "main",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            sync_in.command,
            Commands::Github {
                cmd: GithubCmd::SyncIn {
                    pr: Some(42),
                    dry_run: true,
                    json: true,
                    ..
                }
            }
        ));

        let serve = Cli::try_parse_from([
            "premier",
            "serve",
            "--github-enterprise-host",
            "ghe.acme.test",
            "--github-enterprise-host",
            "api.ghe.acme.test",
        ])
        .unwrap();
        let Commands::Serve {
            github_enterprise_hosts,
            ..
        } = serve.command
        else {
            panic!("expected serve");
        };
        assert_eq!(
            clean_hosts(&github_enterprise_hosts),
            vec!["ghe.acme.test", "api.ghe.acme.test"]
        );
    }

    #[test]
    fn cli_rejects_raw_token_flag_and_extra_positional() {
        assert!(
            Cli::try_parse_from([
                "premier",
                "github",
                "connect",
                "acme/sdk",
                "--token",
                "ghp_secret_value",
            ])
            .is_err(),
            "CLI must never accept a raw --token flag"
        );
        assert!(
            Cli::try_parse_from([
                "premier",
                "github",
                "connect",
                "acme/sdk",
                "ghp_secret_value"
            ])
            .is_err(),
            "CLI must never accept a raw positional token"
        );
    }

    #[test]
    fn token_stdin_reader_trims_and_rejects_empty() {
        let mut ok_in = Cursor::new(b"  ghp_example_token_123 \r\n");
        let tok = read_token_from_reader(&mut ok_in).unwrap();
        assert_eq!(tok.as_str(), "ghp_example_token_123");

        let mut empty_in = Cursor::new(b"   \n");
        assert!(read_token_from_reader(&mut empty_in).is_err());
    }

    #[tokio::test]
    async fn connect_status_disconnect_encrypts_token_and_never_leaks_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        commit_files(
            &root,
            &[(".access.toml", TEST_POLICY), ("README.md", "# Hi\n")],
            "init",
        );

        let connect_cmd = GithubCmd::Connect {
            repo: "acme/sdk".to_owned(),
            default_branch: Some("main".to_owned()),
            zone: Some("public".to_owned()),
            direction: SyncDirectionArg::Bidirectional,
            host: None,
            api_host: None,
            allow_enterprise_host: vec![],
            token_stdin: false,
            token_env: None,
            server_policy: None,
            json: false,
        };
        let state = build_state_for_cmd(&root, &connect_cmd).unwrap();

        // Initial connect without token fails closed.
        let mut err_out = String::new();
        assert!(
            run_github_with_state(
                &state,
                GithubCmd::Connect {
                    repo: "acme/sdk".to_owned(),
                    default_branch: Some("main".to_owned()),
                    zone: Some("public".to_owned()),
                    direction: SyncDirectionArg::Bidirectional,
                    host: None,
                    api_host: None,
                    allow_enterprise_host: vec![],
                    token_stdin: false,
                    token_env: None,
                    server_policy: None,
                    json: false,
                },
                None,
                &mut err_out,
            )
            .await
            .is_err()
        );

        // Connect with token succeeds and never prints plaintext token.
        let mut out = String::new();
        run_github_with_state(
            &state,
            connect_cmd,
            Some(Zeroizing::new(TEST_TOKEN.to_owned())),
            &mut out,
        )
        .await
        .unwrap();
        assert!(out.contains("acme/sdk"));
        assert!(out.contains("token configured: yes"));
        assert!(!out.contains(TEST_TOKEN));

        // On-disk github-companion.json must not contain the plaintext token.
        let state_dir = premier_server::store::state_dir(&root);
        let companion_json =
            std::fs::read_to_string(state_dir.join("github-companion.json")).unwrap();
        assert!(!companion_json.contains(TEST_TOKEN));

        // Status JSON and text show token_configured=true and never leak token.
        let mut status_json_out = String::new();
        run_github_with_state(
            &state,
            GithubCmd::Status {
                server_policy: None,
                json: true,
            },
            None,
            &mut status_json_out,
        )
        .await
        .unwrap();
        assert!(!status_json_out.contains(TEST_TOKEN));
        let status_val: serde_json::Value = serde_json::from_str(&status_json_out).unwrap();
        assert_eq!(status_val["connected"], true);
        assert_eq!(status_val["config"]["token_configured"], true);

        // Re-connect without supplying a new token keeps the existing vault token.
        let mut reconnect_out = String::new();
        run_github_with_state(
            &state,
            GithubCmd::Connect {
                repo: "acme/sdk".to_owned(),
                default_branch: Some("main".to_owned()),
                zone: Some("public".to_owned()),
                direction: SyncDirectionArg::Outbound,
                host: None,
                api_host: None,
                allow_enterprise_host: vec![],
                token_stdin: false,
                token_env: None,
                server_policy: None,
                json: false,
            },
            None,
            &mut reconnect_out,
        )
        .await
        .unwrap();
        assert!(reconnect_out.contains("token configured: yes"));
        assert!(!reconnect_out.contains(TEST_TOKEN));
        assert_eq!(
            premier_server::store::load_github_token(&root, "__premier_github__")
                .unwrap()
                .unwrap()
                .as_str(),
            TEST_TOKEN
        );

        // Disconnect purges token and disconnects companion.
        let mut disc_out = String::new();
        run_github_with_state(
            &state,
            GithubCmd::Disconnect { json: true },
            None,
            &mut disc_out,
        )
        .await
        .unwrap();
        let disc_val: serde_json::Value = serde_json::from_str(&disc_out).unwrap();
        assert_eq!(disc_val["ok"], true);

        let mut after_disc = String::new();
        run_github_with_state(
            &state,
            GithubCmd::Status {
                server_policy: None,
                json: true,
            },
            None,
            &mut after_disc,
        )
        .await
        .unwrap();
        let after_val: serde_json::Value = serde_json::from_str(&after_disc).unwrap();
        assert_eq!(after_val["connected"], false);
    }

    #[tokio::test]
    async fn end_to_end_offline_cli_workflow_scrubs_private_and_blocks_inbound_violations() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let remote = tmp.path().join("remote.git");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&remote).unwrap();

        git(&root, &["init", "-q", "-b", "main"]);
        commit_files(
            &root,
            &[
                ("README.md", "# SDK\n"),
                ("apps/web/app.ts", "export const version = 1;\n"),
                ("billing/ledger/tx.rs", "SECRET_LEDGER_DATA\n"),
                (".access.toml", TEST_POLICY),
            ],
            "initial canonical commit",
        );

        git(&remote, &["init", "-q", "--bare", "-b", "main"]);
        let (mock, mock_url) = MockGithubApi::start().await;

        let mut state = build_cli_state(&root, None, &[]).unwrap();
        state.github_test_override = Some(Arc::new(GithubTestOverride {
            bare_remote_path: remote.clone(),
            mock_api_base_url: mock_url,
        }));

        // 1. Connect companion.
        let mut out = String::new();
        run_github_with_state(
            &state,
            GithubCmd::Connect {
                repo: "acme/sdk".to_owned(),
                default_branch: Some("main".to_owned()),
                zone: Some("public".to_owned()),
                direction: SyncDirectionArg::Bidirectional,
                host: None,
                api_host: None,
                allow_enterprise_host: vec![],
                token_stdin: false,
                token_env: None,
                server_policy: None,
                json: false,
            },
            Some(Zeroizing::new(TEST_TOKEN.to_owned())),
            &mut out,
        )
        .await
        .unwrap();
        assert!(!out.contains(TEST_TOKEN));

        // 2. Sync out to bare GitHub remote; private billing/ file must never reach remote.
        out.clear();
        run_github_with_state(
            &state,
            GithubCmd::SyncOut {
                branch: Some("main".to_owned()),
                target: Some("main".to_owned()),
                zone: None,
                no_squash: false,
                squash: false,
                message: None,
                dry_run: false,
                server_policy: None,
                json: true,
            },
            None,
            &mut out,
        )
        .await
        .unwrap();
        let sync_out_val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(sync_out_val["commits_projected"], 1);
        let remote_tree = git(
            &remote,
            &["ls-tree", "-r", "--name-only", "refs/heads/main"],
        );
        assert!(remote_tree.contains("apps/web/app.ts"));
        assert!(remote_tree.contains("README.md"));
        assert!(!remote_tree.contains("billing/ledger/tx.rs"));
        assert!(!remote_tree.contains(".access.toml"));

        // 3. Create feature branch touching both public and private files; preview-pr and publish-pr.
        git(
            &root,
            &["checkout", "-q", "-b", "feature/public-and-private"],
        );
        commit_files(
            &root,
            &[
                ("apps/web/app.ts", "export const version = 2;\n"),
                ("billing/ledger/tx.rs", "UPDATED_SECRET_LEDGER_DATA\n"),
            ],
            "mixed feature change",
        );
        git(&root, &["checkout", "-q", "main"]);

        out.clear();
        run_github_with_state(
            &state,
            GithubCmd::PreviewPr {
                branch: "feature/public-and-private".to_owned(),
                base: Some("main".to_owned()),
                pr_branch: Some("pr/feature-ui".to_owned()),
                title: Some("Update web app".to_owned()),
                body: Some("Public changes only".to_owned()),
                diff: true,
                server_policy: None,
                json: false,
            },
            None,
            &mut out,
        )
        .await
        .unwrap();
        assert!(out.contains("gate:      PASSED"));
        assert!(out.contains("+ apps/web/app.ts"));
        assert!(out.contains("- billing/ledger/tx.rs"));
        assert!(out.contains("Diffs (1):"));
        assert!(!out.contains("UPDATED_SECRET_LEDGER_DATA"));

        out.clear();
        run_github_with_state(
            &state,
            GithubCmd::PublishPr {
                branch: "feature/public-and-private".to_owned(),
                base: Some("main".to_owned()),
                pr_branch: Some("pr/feature-ui".to_owned()),
                title: Some("Update web app".to_owned()),
                body: Some("Public changes only".to_owned()),
                draft: false,
                change_id: None,
                server_policy: None,
                json: true,
            },
            None,
            &mut out,
        )
        .await
        .unwrap();
        let pub_val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(pub_val["receipt"]["pr_number"], 42);
        assert_eq!(
            pub_val["receipt"]["pr_url"],
            "https://github.com/acme/sdk/pull/42"
        );
        let api_calls = mock.calls();
        assert_eq!(api_calls.len(), 1);
        assert!(api_calls[0].0.contains("/repos/acme/sdk/pulls"));
        assert_eq!(api_calls[0].1, format!("Bearer {TEST_TOKEN}"));

        let pr_tree = git(
            &remote,
            &["ls-tree", "-r", "--name-only", "refs/heads/pr/feature-ui"],
        );
        assert!(pr_tree.contains("apps/web/app.ts"));
        assert!(!pr_tree.contains("billing/ledger/tx.rs"));

        // 4. Upstream public commit syncs in cleanly while preserving hidden private files.
        let upstream_clone = tmp.path().join("upstream-clone");
        git(
            tmp.path(),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                upstream_clone.to_str().unwrap(),
            ],
        );
        commit_files(
            &upstream_clone,
            &[("apps/web/app.ts", "export const version = 3;\n")],
            "upstream public update",
        );
        git(&upstream_clone, &["push", "-q", "origin", "main"]);

        out.clear();
        run_github_with_state(
            &state,
            GithubCmd::SyncIn {
                upstream_ref: Some("main".to_owned()),
                pr: None,
                target: Some("main".to_owned()),
                dry_run: false,
                server_policy: None,
                json: true,
            },
            None,
            &mut out,
        )
        .await
        .unwrap();
        let sync_in_val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(sync_in_val["commits_imported"], 1);
        assert_eq!(
            git(&root, &["show", "refs/heads/main:apps/web/app.ts"]),
            "export const version = 3;"
        );
        assert_eq!(
            git(&root, &["show", "refs/heads/main:billing/ledger/tx.rs"]),
            "SECRET_LEDGER_DATA"
        );

        // 5. Disallowed upstream commit touching private billing/ fails closed.
        let tip_before = git(&root, &["rev-parse", "refs/heads/main"]);
        commit_files(
            &upstream_clone,
            &[("billing/ledger/tx.rs", "TAMPERED_FROM_GITHUB\n")],
            "unauthorized billing change",
        );
        git(&upstream_clone, &["push", "-q", "origin", "main"]);

        out.clear();
        let err = run_github_with_state(
            &state,
            GithubCmd::SyncIn {
                upstream_ref: Some("main".to_owned()),
                pr: None,
                target: Some("main".to_owned()),
                dry_run: false,
                server_policy: None,
                json: true,
            },
            None,
            &mut out,
        )
        .await;
        assert!(err.is_err(), "inbound policy violation must fail closed");
        let err_json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let violations = err_json["policy_violations"].as_array().unwrap();
        assert!(!violations.is_empty());
        assert_eq!(violations[0]["path"], "billing/ledger/tx.rs");
        assert_eq!(
            git(&root, &["rev-parse", "refs/heads/main"]),
            tip_before,
            "canonical main must not advance on refused sync-in"
        );

        // Also check human-readable formatting prints policy violations clearly.
        out.clear();
        let err_text = run_github_with_state(
            &state,
            GithubCmd::SyncIn {
                upstream_ref: Some("main".to_owned()),
                pr: None,
                target: Some("main".to_owned()),
                dry_run: true,
                server_policy: None,
                json: false,
            },
            None,
            &mut out,
        )
        .await;
        assert!(err_text.is_err());
        assert!(out.contains("Inbound policy violations"));
        assert!(out.contains("billing/ledger/tx.rs"));
    }

    #[test]
    fn cli_enforces_committed_head_policy_and_persisted_server_policy_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        commit_files(
            &root,
            &[
                (".access.toml", TEST_POLICY),
                ("apps/web/app.ts", "pub fn app() {}\n"),
                ("billing/secret.txt", "SECRET\n"),
            ],
            "init",
        );

        // Working-copy edit trying to weaken `.access.toml` to expose `billing/**` must be ignored.
        write_files(
            &root,
            &[(
                ".access.toml",
                "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\n",
            )],
        );
        let state = build_cli_state(&root, None, &[]).unwrap();
        let policy = state.current_policy().unwrap();
        assert!(
            premier_git_bridge::check_github_exportable(
                &policy,
                None,
                None,
                "main",
                "billing/secret.txt"
            )
            .is_err(),
            "working-copy .access.toml weakens must be ignored in favor of HEAD:.access.toml"
        );
        assert!(
            premier_git_bridge::check_github_exportable(
                &policy,
                None,
                None,
                "main",
                "apps/web/app.ts"
            )
            .is_ok(),
            "public apps/web path must still be exportable under committed HEAD:.access.toml"
        );

        // Persisted server-policy-path.txt from `premier serve --server-policy` overrides repo allow.
        let srv_policy = tmp.path().join("server-override.access.toml");
        std::fs::write(
            &srv_policy,
            "version = 1\n[[rules]]\nid = \"srv-deny-app\"\neffect = \"deny\"\nprincipals = [\"*\"]\npaths = [\"apps/web/**\"]\ncapabilities = [\"traverse\", \"list\", \"read\", \"write\", \"use\"]\n",
        )
        .unwrap();
        let st_dir = premier_server::store::state_dir(&root);
        premier_secrets::create_state_dir(&st_dir).unwrap();
        let marker = st_dir.join("server-policy-path.txt");
        std::fs::write(&marker, srv_policy.to_string_lossy().as_bytes()).unwrap();

        let state = build_cli_state(&root, None, &[]).unwrap();
        let policy = state.current_policy().unwrap();
        assert!(
            premier_git_bridge::check_github_exportable(
                &policy,
                None,
                None,
                "main",
                "apps/web/app.ts"
            )
            .is_err(),
            "persisted server policy hard deny must override repo policy"
        );

        // Deleting the server policy target while marker exists must fail closed.
        std::fs::remove_file(&srv_policy).unwrap();
        assert!(build_cli_state(&root, None, &[]).is_err());

        // Same-host reconnect reuses stored token without pulling ambient GITHUB_TOKEN;
        // switching host requires an explicit or fallback token.
        let cfg = premier_server::github::GithubCompanionConfigStored {
            owner: "acme".to_owned(),
            repo: "sdk".to_owned(),
            full_name: "acme/sdk".to_owned(),
            host: "github.com".to_owned(),
            api_host: "api.github.com".to_owned(),
            default_branch: "main".to_owned(),
            zone: None,
            sync_direction: SyncDirection::Bidirectional,
            token_configured: true,
            token_updated_at: None,
            connected_at: String::new(),
            connected_by: String::new(),
        };
        assert!(should_reuse_existing_token(Some(&cfg), None));
        assert!(should_reuse_existing_token(Some(&cfg), Some("GitHub.com")));
        assert!(!should_reuse_existing_token(
            Some(&cfg),
            Some("ghe.acme.test")
        ));
        assert!(!should_reuse_existing_token(None, None));
    }
}
