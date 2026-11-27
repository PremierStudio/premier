//! `premier` — Premier CLI.

mod github;
mod mcp;

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use premier_core::{Capability, DelegatedIdentity, Environment, Principal, RepoPath};
use premier_git_bridge::PRIVATE_REF_PREFIX;
use premier_policy::{CompiledPolicy, compute_access_diff, parse_policy_toml};
use premier_proxy::{
    AgentLaunch, AuditSink, AutoApproveGate, BuiltinMcpHandler, DenyJitGate,
    HostSandboxCapabilities, InteractiveTtyGate, McpApprovalHandler, McpGateway, McpGatewayConfig,
    ProxyConfig, ResourceLimits, SessionContext, launch_sandboxed_agent, start_proxy,
};
use premier_secrets::{
    ActorClaim, AgeSovereignBackend, EnvSchema, KeychainBackend, MemoryBackend,
    PlaceholderRegistry, ResolveContext, RotationDispatcher, RotationStatus, SecretBackend,
    SecretCoord, SecretLayer, SecretResolver, Sensitivity, WorkloadTokenRequest, mount_fifo,
    run_with_secrets,
};
use premier_server::{ServerState, serve};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "premier",
    version,
    about = "Premier — Granular access control, native secret brokering, and AI-agent-safe workflows"
)]
pub(crate) struct Cli {
    /// Keep ALL server state (accounts, vault, keys, approvals, sessions, audit log) in this
    /// directory instead of inside the repository's working tree. Used by `serve`, `restore`,
    /// `backup`, `auth`, and `github`. State an earlier server left in the working tree is moved in on first start.
    #[arg(long, global = true, env = "PREMIER_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Format for diagnostic logs written to stderr.
    #[arg(
        long,
        global = true,
        env = "PREMIER_LOG_FORMAT",
        value_enum,
        default_value = "text"
    )]
    log_format: LogFormat,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Internal: inside an agent sandbox, relay a loopback port to the session proxy's Unix
    /// socket and run the agent command behind it.
    #[command(name = premier_proxy::cage::CAGE_EXEC, hide = true)]
    CageExec {
        #[arg(long)]
        proxy_socket: PathBuf,
        #[arg(long)]
        listen: SocketAddr,
        /// Address-space cap for the agent (`setrlimit`, and cgroup v2 `memory.max` if allowed).
        #[arg(long)]
        max_memory_mb: Option<u64>,
        /// Process-count cap (Linux cgroup v2 `pids.max` if allowed).
        #[arg(long)]
        max_pids: Option<u64>,
        /// CPU-time cap in seconds (`RLIMIT_CPU`).
        #[arg(long)]
        max_cpu_secs: Option<u64>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Report repository, Studio, and host sandbox readiness.
    Doctor,

    /// Initialize a Git workspace and add starter Premier configuration.
    Init,

    /// Evaluate, validate, and diff `.access.toml` policies.
    Access {
        #[command(subcommand)]
        cmd: AccessCmd,
    },

    /// Mount, list and unmount encrypted personal and team overlays (kept in the state
    /// directory, never in the working tree), and check paths against the push guard.
    Overlay {
        #[command(subcommand)]
        cmd: OverlayCmd,
    },

    /// Validate `.env.schema`, manage secret values, and mount virtual `.env` FIFOs.
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },

    /// Run a command with in-memory secret injection and streaming stdout/stderr redaction.
    Run {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long, default_value = "dev")]
        env: String,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        /// Command and arguments to execute.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Run the standalone host-side AI agent egress capability proxy.
    Proxy {
        #[command(subcommand)]
        cmd: ProxyCmd,
    },

    /// Launch an AI coding agent inside a capability-proxied cage (placeholders only, zero raw secrets).
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },

    /// Run the Model Context Protocol (MCP) JSON-RPC 2.0 stdio server or print client configs.
    Mcp {
        #[command(subcommand)]
        cmd: McpCmd,
    },

    /// Manage private branches and Squash-Declassify publishing onto public branches.
    Branch {
        #[command(subcommand)]
        cmd: BranchCmd,
    },

    /// Connect a GitHub repository for Squash-Declassify PRs and bidirectional zone sync.
    Github {
        #[command(subcommand)]
        cmd: github::GithubCmd,
    },

    /// Recover the Studio owner account of this workspace.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },

    /// Write a Studio-compatible backup archive. The archive contains private workspace state.
    Backup {
        #[arg(long)]
        out: PathBuf,
        /// Workspace to back up.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Name used for this repository by a server with `--state-dir`.
        #[arg(long)]
        name: Option<String>,
    },

    /// Restore a Studio backup (`premier-backup-<date>.tar.gz`) into a workspace directory.
    Restore {
        archive: PathBuf,
        /// Workspace to restore into; the repository is cloned from the bundle if it has no `.git`.
        #[arg(long, default_value = ".")]
        into: PathBuf,
        /// Overwrite existing state (`.premier`, or this repository's part of `--state-dir`).
        #[arg(long)]
        force: bool,
        /// With `--state-dir`: the name the repository is served under (default: the directory
        /// name), which is where its state goes.
        #[arg(long)]
        name: Option<String>,
    },

    /// Start the Premier control-plane HTTP daemon.
    Serve {
        #[arg(long, default_value = "127.0.0.1:7420")]
        bind: SocketAddr,
        /// Working-copy policy file a backup carries. The policy the server enforces is the
        /// `.access.toml` committed on the default branch.
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long, env = "PREMIER_SERVER_POLICY")]
        server_policy: Option<PathBuf>,
        /// Ignored: the env schema is the `.env.schema` committed on the default branch.
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        /// Audit log (default: `.premier-local/audit.jsonl`, or inside `--state-dir`).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Address of a reverse proxy whose X-Forwarded-For/-Proto/-Host headers are believed
        /// (repeatable). From any other peer those headers are ignored.
        #[arg(
            long = "trusted-proxy",
            env = "PREMIER_TRUSTED_PROXIES",
            value_delimiter = ','
        )]
        trusted_proxies: Vec<String>,
        /// Name of the repository in this directory (default: the directory name).
        #[arg(long)]
        name: Option<String>,
        /// Where repositories created or imported from the Studio live
        /// (default: `.premier/repos` in this workspace, or `worktrees` in `--state-dir`).
        #[arg(long, env = "PREMIER_REPOS_DIR")]
        repos_dir: Option<PathBuf>,
        /// Run agent sessions as a plain process of the server user when this host has no
        /// working sandbox (bubblewrap on Linux). Without it such a host refuses them.
        #[arg(long, env = "PREMIER_ALLOW_UNSANDBOXED_AGENTS")]
        allow_unsandboxed_agents: bool,
        /// Let repository imports fetch from private, CGNAT and unique-local addresses.
        #[arg(long, env = "PREMIER_ALLOW_PRIVATE_IMPORTS")]
        allow_private_imports: bool,
        /// Optional address to bind the pure-Rust Git-over-SSH server (e.g. `127.0.0.1:2222`).
        /// An empty or whitespace-only `PREMIER_SSH_BIND` disables the SSH listener.
        #[arg(long, env = "PREMIER_SSH_BIND", value_parser = parse_optional_socket_addr)]
        ssh_bind: Option<OptionalSocketAddr>,
        /// SSH clone base shown to users (e.g. `ssh://git@git.example.com:7429`) when the
        /// published address differs from `--ssh-bind` (Docker, NAT).
        #[arg(long, env = "PREMIER_SSH_PUBLIC_URL", value_parser = parse_ssh_public_url)]
        ssh_public_url: Option<String>,
        /// Enterprise GitHub hostnames permitted for GitHub Companion mode (repeatable).
        #[arg(
            long = "github-enterprise-host",
            env = "PREMIER_GITHUB_ENTERPRISE_HOSTS",
            value_delimiter = ','
        )]
        github_enterprise_hosts: Vec<String>,
    },

    /// Inspect, verify tamper-evident hash chains, and configure `agent-trace` hooks.
    Trace {
        #[command(subcommand)]
        command: TraceCmd,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCmd {
    /// List recorded trace sessions in `.premier/traces.jsonl` with integrity & scrub summary.
    List {
        /// Path to the traces JSONL file (default: `.premier/traces.jsonl`).
        #[arg(long)]
        file: Option<PathBuf>,
        /// Emit raw JSON instead of a human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Cryptographically verify the per-span SHA-256 hash chain of every trace session.
    Verify {
        /// Path to the traces JSONL file (default: `.premier/traces.jsonl`).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Print ready-to-paste hook configuration for a coding agent harness.
    HookConfig {
        /// Target harness: claude, codex, cursor, gemini, or otlp.
        #[arg(default_value = "claude")]
        harness: String,
        /// Premier server origin URL.
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        server: String,
    },
}

/// Wrapper for `--ssh-bind` / `PREMIER_SSH_BIND` so an empty string cleanly disables SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OptionalSocketAddr(Option<SocketAddr>);

fn parse_optional_socket_addr(raw: &str) -> std::result::Result<OptionalSocketAddr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(OptionalSocketAddr(None));
    }
    trimmed
        .parse::<SocketAddr>()
        .map(|addr| OptionalSocketAddr(Some(addr)))
        .map_err(|e| format!("invalid SSH bind address '{trimmed}': {e}"))
}

#[derive(Debug, Subcommand)]
enum AuthCmd {
    /// Set a new password (read from stdin) and revoke every session.
    ResetPassword { username: String },
    /// Turn off two-factor authentication (lost authenticator).
    DisableTotp { username: String },
    /// Offboard a principal: disable (or delete) the account, revoke its sessions, tokens, SSH
    /// keys, JIT approvals and workload tokens, and rotate every secret it could use. Run it
    /// while the server is stopped (like `reset-password`); against a running server use
    /// `POST /v1/security/offboard`, which also kills its live agent sessions.
    Revoke {
        /// `@username` (or `username`).
        principal: String,
        #[arg(long, default_value = "offboarded via CLI")]
        reason: String,
        /// Delete the account instead of disabling it.
        #[arg(long)]
        delete: bool,
        /// Do not rotate the secrets the principal could use.
        #[arg(long)]
        no_rotate: bool,
        #[arg(long, default_value = "prod")]
        env: String,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BranchCmd {
    /// Create a private branch stored under an isolated `refs/premier-private/<name>` ref.
    Create {
        name: String,
        #[arg(long)]
        private: bool,
        #[arg(long = "allow")]
        allow: Vec<String>,
        #[arg(long, default_value = "HEAD")]
        from: String,
    },
    /// Publish a private branch onto a target branch via Squash-Declassify (scrubbing restricted paths & ancestry).
    Publish {
        name: String,
        /// Target branch; left out, the repository's default (checked-out) branch.
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        squash_declassify: bool,
        #[arg(long)]
        message: Option<String>,
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        /// Preview the publish and its declassification firewall report; no ref moves. Exits 1
        /// when the publish would be refused.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        /// Publish despite a blocking firewall report (at least 8 characters, kept with it). Only
        /// where policy allows owner overrides.
        #[arg(long)]
        override_reason: Option<String>,
        /// Vault whose secret values the firewall looks for (used only if it and its key exist).
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendKind {
    /// Read secret values from current process env (ideal for CI & zero-setup demos).
    Env,
    /// Native OS keychain (Linux keyutils / Windows Credential Manager / macOS Keychain).
    Keychain,
    /// Sovereign/air-gapped `age` + AES-256-GCM AEAD vault file with path+key AAD.
    Age,
}

impl BackendKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Keychain => "keychain",
            Self::Age => "age",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LayerArg {
    Org,
    Repo,
    Zone,
    Env,
    Branch,
    Personal,
}

impl From<LayerArg> for SecretLayer {
    fn from(value: LayerArg) -> Self {
        match value {
            LayerArg::Org => Self::Org,
            LayerArg::Repo => Self::Repo,
            LayerArg::Zone => Self::Zone,
            LayerArg::Env => Self::Env,
            LayerArg::Branch => Self::Branch,
            LayerArg::Personal => Self::Personal,
        }
    }
}

#[derive(Debug, Subcommand)]
enum OverlayCmd {
    /// The overlays `--principal` may see: their personal ones and their groups' team ones.
    List {
        #[arg(long, default_value = "@local")]
        principal: String,
        /// A team `--principal` belongs to (repeatable).
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Mount a personal (default) or `team:<name>` overlay, its content encrypted at rest.
    Mount {
        /// Repository-relative path or glob.
        path: String,
        /// `personal` or `team:<name>`.
        #[arg(long, default_value = "personal")]
        scope: String,
        /// Encrypt the content at rest (the default).
        #[arg(long, overrides_with = "no_encrypted")]
        encrypted: bool,
        /// Store the content unencrypted.
        #[arg(long, overrides_with = "encrypted")]
        no_encrypted: bool,
        /// Owner of a personal overlay.
        #[arg(long, default_value = "@local")]
        principal: String,
        /// Take the overlay content from this file.
        #[arg(long, conflicts_with = "content")]
        file: Option<PathBuf>,
        /// The overlay content.
        #[arg(long)]
        content: Option<String>,
    },
    /// Unmount `--principal`'s personal overlay at a path (else the team overlays there).
    Unmount {
        path: String,
        #[arg(long, default_value = "@local")]
        principal: String,
    },
    /// Exit 1 if any path is an overlay that must never be pushed publicly.
    CheckPush {
        #[arg(required = true)]
        paths: Vec<String>,
        /// Extra overlay manifest merged with the stored overlays.
        #[arg(long, default_value = ".premier/overlays.toml")]
        overlays: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AccessCmd {
    /// Run the declassification firewall and instruction quarantine: over what publishing
    /// `--branch` onto `--to` would land, over the given `--file`s, or (default) over the
    /// public and instruction files of the branch itself. Exits 1 when it finds a blocking issue.
    Scan {
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        /// Branch scanned (or published, with `--to`). Default: the one checked out here.
        #[arg(long)]
        branch: Option<String>,
        /// Scan what publishing `--branch` onto this branch would land.
        #[arg(long)]
        to: Option<String>,
        /// Commit message to scan too.
        #[arg(long)]
        message: Option<String>,
        /// Working-tree files to scan as if they landed on the public side of `--branch`.
        #[arg(long = "file")]
        files: Vec<PathBuf>,
        /// Vault whose secret values the firewall looks for (used only if it and its key exist).
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// Validate `.access.toml` syntax and zone/rule integrity.
    Check {
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
    },

    /// Explain effective capabilities (`traverse|list|read|write|use`) for a principal and path.
    Explain {
        /// Principal (`@alice`, `group:billing`, `anonymous`, `service:ci`).
        principal: String,
        /// Repository-relative POSIX path (e.g. `billing/ledger/tx.rs`).
        path: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        /// Optional delegated AI agent profile (`effective = human ∩ agent`).
        #[arg(long)]
        as_agent: Option<String>,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long = "ref")]
        ref_name: Option<String>,
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Compute a PR Access Impact Diff & instruction-file quarantine check between two policy files.
    Diff {
        base_policy: PathBuf,
        head_policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long = "principal", required = true)]
        principals: Vec<String>,
        #[arg(long = "path", required = true)]
        paths: Vec<String>,
        #[arg(long = "changed-file")]
        changed_files: Vec<String>,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long = "ref")]
        ref_name: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EnvCmd {
    /// Validate `.env.schema` and check that required variables resolve cleanly for `--env`.
    Validate {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = "dev")]
        env: String,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// Store a secret value in the configured backend (keychain or sovereign `age` AEAD vault).
    Set {
        key: String,
        /// Secret value (omit and pass `--stdin` to avoid exposing raw secrets on argv).
        #[arg(required_unless_present = "stdin", conflicts_with = "stdin")]
        value: Option<String>,
        /// Read the secret value from stdin (single trailing newline stripped) so raw secrets stay off argv.
        #[arg(long)]
        stdin: bool,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long, value_enum, default_value_t = LayerArg::Env)]
        layer: LayerArg,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, value_enum, default_value_t = BackendKind::Age)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
    },

    /// List schema variables and resolution provenance (never prints raw secret values).
    List {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = "dev")]
        env: String,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
    },

    /// Mount a virtual uncommittable POSIX FIFO `.env` (Linux / macOS / WSL2).
    Mount {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = ".env")]
        path: PathBuf,
        #[arg(long, default_value = "dev")]
        env: String,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
    },

    /// Rotate a secret in the workspace vault through its signed dual-phase webhook.
    Rotate {
        key: String,
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = "manual CLI rotation")]
        reason: String,
        /// Value to store when the webhook's `prepare` does not return one.
        #[arg(long)]
        new_value: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Show the workspace vault's KMS mode and Key Transparency health (no secret values).
    KmsStatus {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// Manage workspace vault Envelope KMS (`status`, `migrate`, `rotate-dek`).
    Kms {
        #[command(subcommand)]
        cmd: KmsCmd,
    },

    /// Mint a short-lived OIDC workload token (scope = what `human ∩ agent` may use).
    OidcToken {
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        agent_profile: Option<String>,
        #[arg(long)]
        task_id: Option<String>,
        #[arg(long = "aud")]
        audiences: Vec<String>,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KmsCmd {
    /// Show the workspace vault's KMS mode and Key Transparency health (no secret values).
    Status {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Migrate the workspace Sovereign `age` vault into an Envelope KMS vault.
    Migrate {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Re-encrypt every Envelope KMS vault entry under a fresh DEK.
    RotateDek {
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProxyCmd {
    /// Start the host-side egress capability proxy and print placeholder env exports.
    Start {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long, default_value = ".premier-local/audit.jsonl")]
        audit: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        #[arg(long)]
        auto_approve_jit: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCmd {
    /// Run an AI coding agent with placeholder-only tokens wired through the host egress proxy.
    Run {
        /// Path to `.env.schema` (defaults to `.env.schema`; falls back to an empty schema if absent).
        #[arg(long)]
        schema: Option<PathBuf>,
        /// Path to `.access.toml` (auto-loads `.access.toml` in the current directory if present).
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long, default_value = "default-agent")]
        profile: String,
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long, default_value = ".premier-local/audit.jsonl")]
        audit: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        /// Disable Linux `bwrap` isolation even if available (needs `--allow-unsandboxed`).
        #[arg(long, requires = "allow_unsandboxed")]
        no_sandbox: bool,
        /// Run even when no kernel sandbox is available: the agent then gets a sanitised
        /// environment only and can read any file this user can.
        #[arg(long)]
        allow_unsandboxed: bool,
        #[arg(long)]
        auto_approve_jit: bool,
        #[arg(long)]
        interactive_jit: bool,
        /// Agent command and arguments to run.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum McpCmd {
    /// Run the Premier MCP JSON-RPC 2.0 server over stdio (logs to stderr only).
    Serve {
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = ".premier/overlays.toml")]
        overlays: PathBuf,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        agent_profile: Option<String>,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
    },

    /// Run the policy-unified MCP tool action gateway over stdio (logs to stderr only).
    Gateway {
        #[arg(long, default_value = ".access.toml")]
        policy: PathBuf,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        #[arg(long, default_value = ".env.schema")]
        schema: PathBuf,
        #[arg(long, default_value = ".premier/overlays.toml")]
        overlays: PathBuf,
        #[arg(long, default_value = "@local")]
        principal: String,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        agent_profile: Option<String>,
        /// Default: the branch checked out here (`main` with a detached HEAD).
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long, value_enum, default_value_t = BackendKind::Env)]
        backend: BackendKind,
        #[arg(long, default_value = ".premier-local/vault.toml")]
        vault: PathBuf,
        #[arg(long, default_value = ".premier-local/age.key")]
        age_key: PathBuf,
        #[arg(long, default_value = ".premier-local/audit.jsonl")]
        audit: PathBuf,
        #[arg(long, default_value = ".premier-local/mcp-pins.json")]
        pins: PathBuf,
        #[arg(long)]
        auto_approve_jit: bool,
        #[arg(long)]
        allow_loopback_http: bool,
        #[arg(long)]
        allow_private_upstreams: bool,
        #[arg(long)]
        no_builtin_tools: bool,
    },

    /// Print ready-to-paste MCP client configuration (strict JSON/TOML on stdout; wrapper hint on stderr).
    Config {
        #[arg(long, value_enum, default_value_t = mcp::McpClient::ClaudeCode)]
        client: mcp::McpClient,
        #[arg(long)]
        agent_profile: Option<String>,
        #[arg(long)]
        principal: Option<String>,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        server_policy: Option<PathBuf>,
        /// Print only the shell-quoted `premier agent run` wrapper command to stdout.
        #[arg(long)]
        wrapper: bool,
        /// Generate config for `premier mcp gateway` instead of read-only `premier mcp serve`.
        #[arg(long)]
        gateway: bool,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_enum)]
        backend: Option<BackendKind>,
    },
}

fn main() -> Result<()> {
    // Windows defaults the main thread stack to 1 MiB, which debug builds of the large
    // multi-subcommand async CLI state machine can exceed. Run on an 8 MiB stack thread
    // (matching Linux's default) with a heap-pinned root future.
    std::thread::Builder::new()
        .name("premier-main".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 * 1024 * 1024)
                .build()
                .context("failed to initialize Tokio runtime")?;
            runtime.block_on(Box::pin(async_main()))
        })
        .context("failed to spawn main CLI thread")?
        .join()
        .unwrap_or_else(|_| Err(anyhow::anyhow!("main CLI thread panicked")))
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();
    // Nothing else is brought up for the relay: it runs inside the sandbox, next to the agent.
    if let Commands::CageExec {
        proxy_socket,
        listen,
        max_memory_mb,
        max_pids,
        max_cpu_secs,
        command,
    } = &cli.command
    {
        let limits = ResourceLimits {
            max_memory_mb: *max_memory_mb,
            max_pids: *max_pids,
            max_cpu_secs: *max_cpu_secs,
        };
        let code =
            premier_proxy::cage::cage_exec_with_limits(proxy_socket, *listen, &limits, command)
                .await
                .context("cage relay failed")?;
        std::process::exit(code);
    }

    // Route diagnostics exclusively to stderr for every CLI subcommand so machine-readable
    // stdout (`--json`, `mcp serve`, `mcp config`) is never polluted.
    let disable_ansi = matches!(
        cli.command,
        Commands::Mcp {
            cmd: McpCmd::Serve { .. } | McpCmd::Gateway { .. }
        }
    );
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false);
    match cli.log_format {
        LogFormat::Text => subscriber.with_ansi(!disable_ansi).init(),
        LogFormat::Json => subscriber.json().with_ansi(false).init(),
    }

    let state_dir = cli.state_dir;
    match cli.command {
        Commands::CageExec { .. } => Ok(()),
        Commands::Init => init_workspace(&std::env::current_dir()?),
        Commands::Doctor => {
            let cwd = std::env::current_dir()?;
            report_workspace_status(&cwd, state_dir.as_deref());
            let caps = HostSandboxCapabilities::detect();
            println!("Host sandbox capabilities");
            println!("  OS / Arch             : {} / {}", caps.os, caps.arch);
            println!(
                "  POSIX FIFO .env mount : {}",
                if caps.posix_fifo_supported {
                    "supported"
                } else {
                    "unavailable (use `premier run -- <cmd>` on native Windows, or WSL2)"
                }
            );
            println!(
                "  Linux bwrap sandbox   : {}",
                if caps.linux_bwrap_available {
                    "available"
                } else {
                    "not available"
                }
            );
            println!(
                "  Linux unshare         : {}",
                if caps.linux_unshare_available {
                    "available"
                } else {
                    "not available"
                }
            );
            println!(
                "  Linux FUSE3 (/dev/fuse): {}",
                if caps.linux_fuse3_available {
                    "available"
                } else {
                    "not available"
                }
            );
            println!(
                "  Windows ProjFS DLL    : {}",
                if caps.windows_projfs_available {
                    "available"
                } else {
                    "not enabled (optional for M3; M1-M2 require zero VFS drivers)"
                }
            );
            Ok(())
        }

        Commands::Access { cmd } => handle_access(cmd),
        Commands::Overlay { cmd } => handle_overlay(cmd, state_dir.as_deref()),
        Commands::Env { cmd } => {
            if let Some(dir) = &state_dir {
                let cwd = std::env::current_dir()?;
                let name = premier_server::repos::repo_name(&cwd, None);
                premier_server::store::bind_state_dir(&cwd, dir, &name, true);
            }
            handle_env(cmd).await
        }

        Commands::Run {
            schema,
            policy,
            server_policy,
            principal,
            groups,
            env,
            branch,
            backend,
            vault,
            age_key,
            command,
        } => {
            let env_schema = load_schema(&schema)?;
            let compiled = load_optional_policy(policy.as_deref(), server_policy.as_deref())?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let backend_impl =
                build_backend(backend, &repo_id, &env, &env_schema, &vault, &age_key)?;

            let identity = DelegatedIdentity::human_only(Principal::parse(&principal)?, groups);
            let ctx = ResolveContext {
                repo_id,
                org: "local".to_owned(),
                env: Environment::parse(&env),
                branch: branch.unwrap_or_else(current_branch),
                identity,
            };

            let resolver =
                SecretResolver::new(&env_schema, compiled.as_ref(), backend_impl.as_ref());
            let resolved = resolver.resolve(&ctx, Capability::READ)?;

            let redact_keys: Vec<String> = env_schema
                .vars
                .iter()
                .filter(|(_, s)| {
                    matches!(s.sensitivity, Sensitivity::Secret | Sensitivity::Restricted)
                })
                .map(|(k, _)| k.clone())
                .collect();

            let (program, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("missing command after `--`"))?;
            let out = run_with_secrets(program, args, &resolved.values, &redact_keys).await?;
            if out.stdout_bytes_scrubbed + out.stderr_bytes_scrubbed > 0 {
                eprintln!(
                    "[premier run] scrubbed {} bytes of secret material from child output",
                    out.stdout_bytes_scrubbed + out.stderr_bytes_scrubbed
                );
            }
            std::process::exit(out.exit_code);
        }

        Commands::Proxy { cmd } => match cmd {
            ProxyCmd::Start {
                bind,
                schema,
                policy,
                server_policy,
                principal,
                groups,
                profile,
                env,
                allow_hosts,
                audit,
                backend,
                vault,
                age_key,
                auto_approve_jit,
            } => {
                let env_schema = load_schema(&schema)?;
                let (cfg, registry, _public_vars) = prepare_proxy_config(
                    bind,
                    env_schema,
                    policy.as_deref(),
                    server_policy.as_deref(),
                    &principal,
                    groups,
                    profile,
                    &env,
                    allow_hosts,
                    audit,
                    backend,
                    &vault,
                    &age_key,
                    auto_approve_jit,
                    true,
                )?;
                let handle = start_proxy(cfg).await?;
                // The URLs carry the session token every request must present.
                println!(
                    "Premier Egress Capability Proxy listening on {}",
                    handle.proxy_url()
                );
                for cap in registry.all() {
                    println!(
                        "  {}={}  (hosts={:?}, reverse={})",
                        cap.var_name,
                        cap.placeholder,
                        cap.egress.hosts,
                        handle.cap_base_url(&cap.var_name)
                    );
                }
                println!("Press Ctrl+C to stop.");
                tokio::signal::ctrl_c().await?;
                handle.shutdown();
                Ok(())
            }
        },

        Commands::Agent { cmd } => match cmd {
            AgentCmd::Run {
                schema,
                policy,
                server_policy,
                principal,
                groups,
                profile,
                env,
                allow_hosts,
                audit,
                backend,
                vault,
                age_key,
                no_sandbox,
                allow_unsandboxed,
                auto_approve_jit,
                interactive_jit,
                command,
            } => {
                // Key material the sandbox hides from the agent.
                let secret_paths = [vault.clone(), age_key.clone(), audit.clone()];
                let cwd = std::env::current_dir()?;
                let env_schema = load_optional_schema(schema.as_deref(), &cwd)?;
                let effective_policy = resolve_agent_policy_path(policy, &cwd);
                let (mut cfg, registry, public_vars) = prepare_proxy_config(
                    "127.0.0.1:0".parse()?,
                    env_schema,
                    effective_policy.as_deref(),
                    server_policy.as_deref(),
                    &principal,
                    groups,
                    Some(profile),
                    &env,
                    allow_hosts,
                    audit,
                    backend,
                    &vault,
                    &age_key,
                    auto_approve_jit,
                    interactive_jit,
                )?;

                // The sandboxed agent's only way out: the proxy's socket, alone in a directory
                // of its own that is bound into the sandbox.
                let socket_dir = std::env::temp_dir().join(format!(
                    "premier-proxy-{}-{}",
                    std::process::id(),
                    clock_nanos()
                ));
                let proxy_socket =
                    (cfg!(unix) && !no_sandbox && std::fs::create_dir(&socket_dir).is_ok())
                        .then(|| socket_dir.join(premier_proxy::cage::PROXY_SOCKET));
                cfg.unix_socket = proxy_socket.clone();

                let handle = start_proxy(cfg).await?;

                // Write ephemeral public CA cert to a scoped temp file (removed when dropped).
                let ca_file_path = std::env::temp_dir().join(format!(
                    "premier-session-ca-{}-{}.pem",
                    std::process::id(),
                    handle.addr.port()
                ));
                std::fs::write(&ca_file_path, &handle.ca_cert_pem)
                    .context("failed to write ephemeral session CA PEM")?;

                let (program, args) = command
                    .split_first()
                    .ok_or_else(|| anyhow::anyhow!("missing agent command after `--`"))?;

                let run_res = launch_sandboxed_agent(
                    program,
                    args,
                    &AgentLaunch {
                        proxy_addr: handle.addr,
                        proxy_token: &handle.auth_token,
                        ca_cert_path: Some(&ca_file_path),
                        proxy_socket: proxy_socket.as_deref(),
                        registry: &registry,
                        public_vars: &public_vars,
                        workspace: &std::env::current_dir()?,
                        secret_paths: &secret_paths,
                        use_sandbox: !no_sandbox,
                        allow_unsandboxed,
                    },
                )
                .await;

                let _ = std::fs::remove_file(&ca_file_path);
                let _ = std::fs::remove_dir_all(&socket_dir);
                let audit_count = handle.audit_sink.snapshot().len();
                handle.shutdown();

                let res = run_res?;
                eprintln!(
                    "[premier agent] mode={} exit={} audit_events={} scrubbed_bytes={}",
                    res.sandbox_mode,
                    res.exit_code,
                    audit_count,
                    res.stdout_bytes_scrubbed + res.stderr_bytes_scrubbed
                );
                std::process::exit(res.exit_code);
            }
        },

        Commands::Branch { cmd } => {
            if let Some(dir) = &state_dir {
                let cwd = std::env::current_dir()?;
                let name = premier_server::repos::repo_name(&cwd, None);
                premier_server::store::bind_state_dir(&cwd, dir, &name, false);
            }
            handle_branch(cmd)
        }

        Commands::Mcp { cmd } => match cmd {
            McpCmd::Serve {
                policy,
                server_policy,
                schema,
                overlays,
                principal,
                groups,
                agent_profile,
                branch,
            } => {
                let ctx = mcp_context(
                    state_dir.as_deref(),
                    &policy,
                    server_policy.as_deref(),
                    &schema,
                    &overlays,
                    &principal,
                    groups,
                    agent_profile,
                    branch.unwrap_or_else(current_branch),
                )?;
                mcp::run_stdio_server(&ctx)
            }
            McpCmd::Gateway {
                policy,
                server_policy,
                schema,
                overlays,
                principal,
                groups,
                agent_profile,
                branch,
                env,
                backend,
                vault,
                age_key,
                audit,
                pins,
                auto_approve_jit,
                allow_loopback_http,
                allow_private_upstreams,
                no_builtin_tools,
            } => {
                validate_gateway_flags(auto_approve_jit, agent_profile.as_deref())?;
                let ref_name = branch.unwrap_or_else(current_branch);
                let ctx = mcp_context(
                    state_dir.as_deref(),
                    &policy,
                    server_policy.as_deref(),
                    &schema,
                    &overlays,
                    &principal,
                    groups,
                    agent_profile,
                    ref_name.clone(),
                )?;
                let repo_id = ctx
                    .env_schema
                    .repo_id
                    .clone()
                    .unwrap_or_else(|| "local/repo".to_owned());
                let backend_impl =
                    build_backend(backend, &repo_id, &env, &ctx.env_schema, &vault, &age_key)?;
                let resolve_ctx = ResolveContext {
                    repo_id,
                    org: "local".to_owned(),
                    env: Environment::parse(&env),
                    branch: ref_name.clone(),
                    identity: ctx.identity.clone(),
                };
                let resolved = SecretResolver::new(
                    &ctx.env_schema,
                    Some(&ctx.compiled_policy),
                    backend_impl.as_ref(),
                )
                .resolve(&resolve_ctx, Capability::USE)?;

                let pins_reg = mcp::load_pin_registry(Some(&pins))?;
                let audit_sink = Arc::new(AuditSink::new(Some(audit)));
                let approval_handler = if auto_approve_jit {
                    McpApprovalHandler::AutoApprove
                } else {
                    McpApprovalHandler::DenyAll
                };
                let builtins = (!no_builtin_tools).then(|| {
                    Arc::new(mcp::PremierBuiltinMcpHandler::new(ctx.clone()))
                        as Arc<dyn BuiltinMcpHandler>
                });
                let gateway = McpGateway::new(McpGatewayConfig {
                    identity: ctx.identity,
                    ref_name,
                    policy: Arc::new(ctx.compiled_policy),
                    env_schema: Arc::new(ctx.env_schema),
                    resolved_secrets: resolved.values,
                    audit_sink,
                    pin_registry: Arc::clone(&pins_reg),
                    approval_handler,
                    allow_loopback_http,
                    allow_private_upstreams,
                    allow_repo_stdio_servers: true,
                    extra_upstream_roots: Vec::new(),
                    custom_upstreams: std::collections::HashMap::new(),
                    builtins,
                })?;
                mcp::run_stdio_gateway(&gateway, &pins_reg, Some(&pins)).await
            }
            McpCmd::Config {
                client,
                agent_profile,
                principal,
                groups,
                policy,
                server_policy,
                wrapper,
                gateway,
                env,
                backend,
            } => {
                if gateway {
                    let server_policy_str = server_policy.as_ref().map(|p| p.to_string_lossy());
                    print!(
                        "{}",
                        mcp::render_gateway_client_config(
                            client,
                            agent_profile.as_deref(),
                            principal.as_deref(),
                            env.as_deref(),
                            backend.map(BackendKind::as_str),
                            server_policy_str.as_deref(),
                        )
                    );
                } else {
                    let opts = mcp::McpConfigOptions {
                        agent_profile: agent_profile.as_deref(),
                        principal: principal.as_deref(),
                        groups: &groups,
                        policy: policy.as_deref(),
                        server_policy: server_policy.as_deref(),
                    };
                    if wrapper {
                        println!("{}", mcp::render_agent_wrapper(client, &opts));
                    } else {
                        print!("{}", mcp::render_client_config(client, &opts));
                        eprintln!(
                            "# Launch inside Premier's capability-proxied cage (use != read):\n# {}",
                            mcp::render_agent_wrapper(client, &opts)
                        );
                    }
                }
                Ok(())
            }
        },

        Commands::Auth { cmd } => {
            if let Some(dir) = &state_dir {
                let cwd = std::env::current_dir()?;
                let name = premier_server::repos::repo_name(&cwd, None);
                premier_server::store::bind_state_dir(&cwd, dir, &name, true);
            }
            handle_auth(cmd).await
        }

        Commands::Github { cmd } => {
            if let Some(dir) = &state_dir {
                let cwd = std::env::current_dir()?;
                let name = premier_server::repos::repo_name(&cwd, None);
                premier_server::store::bind_state_dir(&cwd, dir, &name, true);
            }
            github::handle_github(cmd).await
        }

        Commands::Backup {
            out,
            workspace,
            name,
        } => {
            let workspace = workspace
                .canonicalize()
                .with_context(|| format!("failed to open {}", workspace.display()))?;
            if let Some(dir) = &state_dir {
                let name = premier_server::repos::repo_name(&workspace, name.as_deref());
                premier_server::store::bind_state_dir(&workspace, dir, &name, true);
            }
            let audit = premier_server::store::audit_path(&workspace);
            let policy_marker =
                premier_server::store::state_dir(&workspace).join("server-policy-path.txt");
            let policy_files: Vec<PathBuf> = std::fs::read_to_string(policy_marker)
                .ok()
                .map(|path| PathBuf::from(path.trim()))
                .into_iter()
                .collect();
            premier_server::ops::write_backup(&workspace, &out, Some(&audit), &policy_files)
                .map_err(anyhow::Error::msg)?;
            println!("Wrote backup to {}", out.display());
            Ok(())
        }

        Commands::Restore {
            archive,
            into,
            force,
            name,
        } => {
            if let Some(dir) = &state_dir {
                // Created first: the repository's name comes from the real directory.
                std::fs::create_dir_all(&into)
                    .with_context(|| format!("failed to create {}", into.display()))?;
                let name = premier_server::repos::repo_name(&into, name.as_deref());
                premier_server::store::bind_state_dir(&into, dir, &name, true);
            }
            let done = premier_server::ops::restore_archive(&archive, &into, force)
                .map_err(anyhow::Error::msg)?;
            println!(
                "Restored {} into {}{}",
                premier_git_bridge::plural(done.files_restored, "state file"),
                into.display(),
                if done.repo_cloned {
                    " and cloned the repository from the bundle"
                } else {
                    " (existing repository left untouched)"
                }
            );
            Ok(())
        }

        Commands::Trace { command } => run_trace_cmd(command),

        Commands::Serve {
            bind,
            policy,
            server_policy,
            schema: _,
            audit,
            trusted_proxies,
            name,
            repos_dir,
            allow_unsandboxed_agents,
            allow_private_imports,
            ssh_bind,
            ssh_public_url,
            github_enterprise_hosts,
        } => {
            let server_policy_toml = server_policy
                .as_deref()
                .map(|p| {
                    std::fs::read_to_string(p)
                        .with_context(|| format!("failed to read server policy {}", p.display()))
                })
                .transpose()?;
            if let Some(text) = &server_policy_toml {
                parse_policy_toml(text)?;
            }
            // The repository's policy and env schema are what its default branch has committed;
            // `serve` loads them (a broken committed one is an error there). `--policy` only
            // names the working-copy file a backup carries.
            let cwd = std::env::current_dir()?;
            if let Some(dir) = &state_dir {
                premier_server::repos::configure_state_dir(
                    &cwd,
                    dir,
                    name.as_deref(),
                    repos_dir.is_none(),
                )
                .map_err(anyhow::Error::msg)?;
            }
            let st_dir = premier_server::store::state_dir(&cwd);
            let sp_marker = st_dir.join("server-policy-path.txt");
            if let Some(path) = server_policy.as_deref() {
                let abs = std::fs::canonicalize(path).unwrap_or_else(|_| {
                    if path.is_relative() {
                        cwd.join(path)
                    } else {
                        path.to_path_buf()
                    }
                });
                premier_secrets::create_state_dir(&st_dir).map_err(anyhow::Error::msg)?;
                premier_secrets::write_private(&sp_marker, abs.to_string_lossy().as_bytes())
                    .map_err(anyhow::Error::msg)?;
            } else {
                let _ = std::fs::remove_file(&sp_marker);
            }
            let audit = audit.unwrap_or_else(|| premier_server::store::audit_path(&cwd));
            let mut state =
                ServerState::try_minimal(None, None, Arc::new(AuditSink::new(Some(audit))))
                    .map_err(anyhow::Error::msg)?;
            state.repo_policy_path = Some(policy);
            state.trusted_proxies = Arc::new(parse_trusted_proxies(&trusted_proxies)?);
            state.server_policy_toml = server_policy_toml;
            state.server_policy_path = server_policy;
            state.allow_unsandboxed_agents = allow_unsandboxed_agents;
            state.allow_private_imports = allow_private_imports;
            state.ssh_bind = ssh_bind.and_then(|s| s.0);
            state.ssh_public_url = ssh_public_url.filter(|u| !u.is_empty());
            state.github_enterprise_hosts = Arc::new(github::clean_hosts(&github_enterprise_hosts));
            serve(bind, state, name, repos_dir).await?;
            Ok(())
        }
    }
}

async fn handle_auth(cmd: AuthCmd) -> Result<()> {
    let cwd = std::env::current_dir()?;
    match cmd {
        AuthCmd::ResetPassword { username } => {
            eprintln!("New password for {username} (read from stdin):");
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().read_line(&mut line)?;
            let password = line.trim_end_matches(['\r', '\n']);
            premier_server::auth::reset_password(&cwd, &username, password)
                .map_err(anyhow::Error::msg)?;
            println!("Password reset for {username}; all sessions revoked.");
        }
        AuthCmd::DisableTotp { username } => {
            premier_server::auth::disable_totp(&cwd, &username).map_err(anyhow::Error::msg)?;
            println!("Two-factor authentication disabled for {username}.");
        }
        AuthCmd::Revoke {
            principal,
            reason,
            delete,
            no_rotate,
            env,
            schema,
            policy,
            json,
        } => {
            let env_schema = schema.exists().then(|| load_schema(&schema)).transpose()?;
            let compiled = policy
                .exists()
                .then(|| load_policy(&policy, None))
                .transpose()?;
            let audit = premier_server::store::audit_path(&cwd);
            let mut state = ServerState::try_minimal(
                compiled.map(Arc::new),
                env_schema.map(Arc::new),
                Arc::new(AuditSink::new(Some(audit))),
            )
            .map_err(anyhow::Error::msg)?;
            state.workspace_root = cwd;
            let registry = premier_server::repos::Registry::open(state, None, None);
            let state = registry.default_state();
            let req = premier_server::lifecycle::OffboardRequest {
                principal,
                reason: Some(reason),
                env,
                rotate_secrets: !no_rotate,
                delete_account: delete,
            };
            let receipt = premier_server::lifecycle::offboard(&state, req, CLI_ACTOR, None)
                .await
                .map_err(|(status, msg)| anyhow::anyhow!("{msg} ({status})"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "Offboarded {}: account {}, {} sessions, {} tokens, {} SSH keys, {} approvals revoked; workload tokens revoked.",
                    receipt.principal,
                    if receipt.account_deleted {
                        "deleted"
                    } else if receipt.account_disabled {
                        "disabled"
                    } else {
                        "not found (policy-only principal)"
                    },
                    receipt.sessions_revoked,
                    receipt.tokens_revoked,
                    receipt.ssh_keys_revoked,
                    receipt.approvals_revoked,
                );
                for r in &receipt.rotations {
                    println!(
                        "  {:<24} {:?}{}",
                        r.var_name,
                        r.status,
                        r.error
                            .as_deref()
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Who the offline CLI acts as in audit records and receipts.
const CLI_ACTOR: &str = "@local-cli";

fn handle_branch(cmd: BranchCmd) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let canonical = premier_git_bridge::CanonicalGitRepo::open(&cwd);

    match cmd {
        BranchCmd::Create {
            name,
            private,
            allow,
            from,
        } => {
            if !private && !allow.is_empty() {
                bail!("--allow can only be used together with --private");
            }
            let out = premier_git_bridge::git_command(&cwd)
                .args(["rev-parse", "--verify", &from])
                .output()?;
            if !out.status.success() {
                bail!(
                    "failed to resolve base ref '{}': {}",
                    from,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let base_oid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let full_ref = if private {
                format!("{PRIVATE_REF_PREFIX}{name}")
            } else {
                format!("refs/heads/{name}")
            };
            canonical.update_ref(&full_ref, &base_oid)?;
            let visibility = if private {
                premier_core::Visibility::Restricted(allow.clone())
            } else {
                premier_core::Visibility::Public
            };
            let mut persisted =
                premier_server::store::load_state(&cwd).map_err(anyhow::Error::msg)?;
            persisted.branch_metadata.insert(
                full_ref.clone(),
                (visibility, premier_core::Readiness::Ready),
            );
            premier_server::store::save_state(&cwd, &persisted).map_err(anyhow::Error::msg)?;
            println!(
                "Created {} branch '{}' at {} (ref: {}, allow: {:?})",
                if private { "PRIVATE" } else { "public" },
                name,
                &base_oid[..base_oid.len().min(8)],
                full_ref,
                allow
            );
            Ok(())
        }
        BranchCmd::Publish {
            name,
            to,
            squash_declassify,
            message,
            policy,
            server_policy,
            dry_run,
            json,
            override_reason,
            vault,
            age_key,
        } => {
            if !squash_declassify && !dry_run {
                bail!("pass --squash-declassify to execute the Visibility Escalation Gate");
            }
            let override_reason = override_reason.map(|r| r.trim().to_owned());
            if override_reason
                .as_ref()
                .is_some_and(|r| r.chars().count() < 8)
            {
                bail!("--override-reason needs at least 8 characters");
            }
            let effective_policy = policy;
            let compiled = load_policy(&effective_policy, server_policy.as_deref())?;
            let fp = compute_policy_fingerprint(&effective_policy, server_policy.as_deref())?;

            let source_ref = {
                let priv_ref = format!("{PRIVATE_REF_PREFIX}{name}");
                let check = premier_git_bridge::git_command(&cwd)
                    .args(["rev-parse", "--verify", &priv_ref])
                    .output()?;
                if check.status.success() {
                    String::from_utf8_lossy(&check.stdout).trim().to_owned()
                } else {
                    let head_ref = format!("refs/heads/{name}");
                    let check2 = premier_git_bridge::git_command(&cwd)
                        .args(["rev-parse", "--verify", &head_ref])
                        .output()?;
                    if !check2.status.success() {
                        bail!(
                            "branch '{name}' not found under {PRIVATE_REF_PREFIX} or refs/heads/"
                        );
                    }
                    String::from_utf8_lossy(&check2.stdout).trim().to_owned()
                }
            };

            let target_ref = match to {
                Some(to) => format!("refs/heads/{to}"),
                None => {
                    let head = premier_git_bridge::git_command(&cwd)
                        .args(["symbolic-ref", "-q", "HEAD"])
                        .output()?;
                    if !head.status.success() {
                        bail!("no branch is checked out: pass --to <branch>");
                    }
                    String::from_utf8_lossy(&head.stdout).trim().to_owned()
                }
            };
            let to = target_ref
                .strip_prefix("refs/heads/")
                .unwrap_or(&target_ref);
            let target_parent = premier_git_bridge::git_command(&cwd)
                .args(["rev-parse", "--verify", &target_ref])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());

            let overlay_manifest = workspace_overlays(&cwd.join(".premier/overlays.toml"), &cwd)?;
            let guard = premier_overlay::OverlayGuard::from_manifest(&overlay_manifest)?;
            let msg = message.unwrap_or_else(|| format!("Publish to {to}"));
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let committer = format!("Premier Release Bot <release@premier.local> {now_secs} +0000");
            let vault_index = load_vault_index(&vault, &age_key)?;
            let mut firewall = premier_git_bridge::SquashFirewallInput {
                vault: vault_index.as_ref(),
                actor_is_owner: true,
                ..premier_git_bridge::SquashFirewallInput::default()
            };
            let plan = premier_git_bridge::plan_squash_declassify(
                &canonical,
                &compiled,
                &source_ref,
                &target_ref,
                target_parent.as_deref(),
            )?;
            let report = premier_git_bridge::scan_squash_declassify(
                &canonical,
                &compiled,
                &plan,
                &source_ref,
                &target_ref,
                target_parent.as_deref(),
                &msg,
                &firewall,
            )?;
            if dry_run {
                let refused =
                    !plan.blocked.is_empty() || !plan.conflicts.is_empty() || !report.passed;
                if json {
                    let preview = serde_json::json!({
                        "source_branch": name,
                        "target_ref": target_ref,
                        "published_paths": plan.changes.iter().map(|(p, _)| p).collect::<Vec<_>>(),
                        "scrubbed_paths": plan.scrubbed_paths,
                        "conflicts": plan.conflicts,
                        "blocked": plan.blocked,
                        "declassification_gate_passed": !refused,
                        "declassification_report": report,
                    });
                    println!("{}", serde_json::to_string_pretty(&preview)?);
                } else {
                    println!("Dry run: publish '{name}' -> {target_ref} (nothing is written)");
                    println!(
                        "  {} published, {} held back",
                        premier_git_bridge::plural(plan.changes.len(), "path"),
                        premier_git_bridge::plural(plan.scrubbed_paths.len(), "restricted path")
                    );
                    for path in &plan.conflicts {
                        println!("  [CONFLICT] {path}: changed on both branches");
                    }
                    for path in &plan.blocked {
                        println!(
                            "  [BLOCKED] {path}: would carry the content of a restricted file"
                        );
                    }
                    print_firewall_report(&report);
                }
                if refused {
                    std::process::exit(1);
                }
                return Ok(());
            }
            if override_reason.is_some() && !report.passed {
                firewall.owner_override_digest = Some(report.report_digest.as_str());
            }
            let res = premier_git_bridge::execute_squash_declassify_with_firewall(
                &canonical,
                &compiled,
                &fp[..16],
                Some(&guard),
                &name,
                &source_ref,
                &target_ref,
                target_parent.as_deref(),
                &msg,
                &committer,
                &firewall,
                None,
            );
            let res = match res {
                Err(premier_git_bridge::GitBridgeError::PublishConflict(paths)) => {
                    bail!(
                    "publish refused, nothing was published: changed on both '{name}' and '{to}':
  {}",
                    paths.join("
  ")
                )
                }
                Err(premier_git_bridge::GitBridgeError::FirewallBlocked(report)) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        eprintln!(
                            "publish refused by the declassification firewall, nothing was published"
                        );
                        print_firewall_report(&report);
                        if compiled.firewall_allow_owner_override() {
                            eprintln!(
                                "  (an owner may publish anyway with --override-reason \"<why>\")"
                            );
                        }
                    }
                    std::process::exit(1);
                }
                res => res?,
            };
            if let Some(reason) = override_reason.filter(|_| !report.passed) {
                println!(
                    "Firewall override: {} [report {}] ({reason})",
                    premier_git_bridge::plural(report.blocking_count, "blocking finding"),
                    &report.report_digest[..report.report_digest.len().min(12)]
                );
            }
            println!(
                "Published '{}' -> {} (commit: {}, {} published, {} held back)",
                name,
                res.target_ref,
                &res.new_commit_oid[..8],
                premier_git_bridge::plural(res.published_paths.len(), "path"),
                premier_git_bridge::plural(res.scrubbed_paths.len(), "restricted path")
            );
            println!("  {}", res.attestation.to_git_trailer());
            Ok(())
        }
    }
}

/// The vault's secret values as keyed digests, when the vault and its key both exist (never
/// creates either).
fn load_vault_index(
    vault: &Path,
    age_key: &Path,
) -> Result<Option<premier_policy::VaultSecretIndex>> {
    if !vault.exists() || !age_key.exists() {
        return Ok(None);
    }
    let identity = load_or_create_age_identity(age_key)?;
    let backend = AgeSovereignBackend::new(
        vault,
        "local/repo",
        vault.to_string_lossy(),
        identity,
        vec![],
    );
    let secrets = backend.export_all_zeroizing()?;
    let index = premier_policy::VaultSecretIndex::from_secrets(
        secrets.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    );
    drop(secrets);
    Ok((!index.is_empty()).then_some(index))
}

fn print_firewall_report(report: &premier_policy::DeclassificationReport) {
    let verdict = if report.passed { "PASSED" } else { "BLOCKED" };
    println!(
        "Declassification firewall: {verdict} ({}, {}) [report {}]",
        premier_git_bridge::plural(report.blocking_count, "blocking finding"),
        premier_git_bridge::plural(report.warning_count, "warning"),
        report.report_digest
    );
    for f in &report.findings {
        let at = match f.line {
            Some(line) => format!("{}:{line}", f.location),
            None => f.location.clone(),
        };
        let kind = if f.blocking { "BLOCK" } else { "warn" };
        println!("  [{kind}] {at} {} ({})", f.summary, f.rule_id);
        if let Some(detail) = &f.owner_detail {
            println!("          {detail}");
        }
    }
}

fn rev_of(cwd: &Path, name: &str) -> Option<String> {
    [
        format!("{PRIVATE_REF_PREFIX}{name}"),
        format!("refs/heads/{name}"),
        name.to_owned(),
    ]
    .iter()
    .find_map(|candidate| {
        premier_git_bridge::git_command(cwd)
            .args([
                "rev-parse",
                "-q",
                "--verify",
                &format!("{candidate}^{{commit}}"),
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_access_scan(
    policy: &Path,
    server_policy: Option<&Path>,
    branch: Option<String>,
    to: Option<String>,
    message: Option<String>,
    files: Vec<PathBuf>,
    vault: &Path,
    age_key: &Path,
    json: bool,
) -> Result<()> {
    let compiled = load_policy(policy, server_policy)?;
    let cwd = std::env::current_dir()?;
    let canonical = premier_git_bridge::CanonicalGitRepo::open(&cwd);
    let vault_index = load_vault_index(vault, age_key)?;
    let approved = BTreeMap::new();
    let message = message.unwrap_or_default();
    let messages: Vec<String> = if message.trim().is_empty() {
        Vec::new()
    } else {
        vec![message.clone()]
    };
    let branch = branch.unwrap_or_else(current_branch);

    let report = if let Some(to) = to {
        let source =
            rev_of(&cwd, &branch).with_context(|| format!("branch '{branch}' not found"))?;
        let target_ref = if to.starts_with("refs/") {
            to
        } else {
            format!("refs/heads/{to}")
        };
        let tip = rev_of(&cwd, &target_ref);
        let plan = premier_git_bridge::plan_squash_declassify(
            &canonical,
            &compiled,
            &source,
            &target_ref,
            tip.as_deref(),
        )?;
        premier_git_bridge::scan_squash_declassify(
            &canonical,
            &compiled,
            &plan,
            &source,
            &target_ref,
            tip.as_deref(),
            &message,
            &premier_git_bridge::SquashFirewallInput {
                vault: vault_index.as_ref(),
                actor_is_owner: true,
                ..premier_git_bridge::SquashFirewallInput::default()
            },
        )?
    } else {
        let rev = rev_of(&cwd, &branch).or_else(|| rev_of(&cwd, "HEAD"));
        let ref_name = branch
            .strip_prefix("refs/heads/")
            .or_else(|| branch.strip_prefix(PRIVATE_REF_PREFIX))
            .unwrap_or(&branch);
        if files.is_empty() {
            match rev {
                Some(rev) => premier_server::firewall::audit_tree(
                    &cwd,
                    &compiled,
                    &rev,
                    ref_name,
                    &messages,
                    vault_index.as_ref(),
                    &approved,
                ),
                None => premier_policy::DeclassificationReport::from_findings(Vec::new()),
            }
        } else {
            let targets = files
                .iter()
                .map(|file| {
                    let path = file.to_string_lossy().replace('\\', "/");
                    let path = path.trim_start_matches("./").to_owned();
                    let content = std::fs::read(file)
                        .with_context(|| format!("failed to read {}", file.display()))?;
                    Ok(premier_policy::ScanTargetFile {
                        path,
                        content,
                        deleted: false,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let corpus = rev.filter(|_| compiled.firewall_enabled()).map(|rev| {
                premier_server::firewall::collect_private_corpus(
                    &cwd, &compiled, &rev, ref_name, true,
                )
            });
            premier_policy::run_declassification_firewall(&premier_policy::FirewallScanInput {
                policy: &compiled,
                ref_name,
                commit_messages: &messages,
                files: &targets,
                corpus: corpus.as_ref(),
                vault: vault_index.as_ref(),
                check_cross_boundary: true,
                actor_is_owner: true,
                actor_is_agent: false,
                approved_instructions: &approved,
            })
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_firewall_report(&report);
    }
    if !report.passed {
        std::process::exit(1);
    }
    Ok(())
}

fn handle_access(cmd: AccessCmd) -> Result<()> {
    match cmd {
        AccessCmd::Scan {
            policy,
            server_policy,
            branch,
            to,
            message,
            files,
            vault,
            age_key,
            json,
        } => handle_access_scan(
            &policy,
            server_policy.as_deref(),
            branch,
            to,
            message,
            files,
            &vault,
            &age_key,
            json,
        ),
        AccessCmd::Check {
            policy,
            server_policy,
        } => {
            let _compiled = load_policy(&policy, server_policy.as_deref())?;
            println!("OK: {} compiled cleanly", policy.display());
            Ok(())
        }
        AccessCmd::Explain {
            principal,
            path,
            groups,
            as_agent,
            ref_name,
            policy,
            server_policy,
            json,
        } => {
            let compiled = load_policy(&policy, server_policy.as_deref())?;
            let p = Principal::parse(&principal)?;
            let identity = match as_agent {
                Some(profile) => DelegatedIdentity::delegated(p, groups, profile, "cli-explain"),
                None => DelegatedIdentity::human_only(p, groups),
            };
            let repo_path = RepoPath::new(&path)?;
            let ref_name = ref_name.unwrap_or_else(current_branch);
            let decision = compiled.explain(&identity, &repo_path, &ref_name);

            if json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                println!("Path      : {} (ref: {})", decision.path, decision.ref_name);
                println!("Principal : {}", decision.principal);
                if let Some(ref agent) = decision.agent_profile {
                    println!("Agent     : {agent} (human ∩ agent intersection active)");
                }
                println!("Effective : {}", decision.effective);
                if decision.synthesized_traverse {
                    println!("Note      : structural TRAVERSE synthesized (no LIST/READ leaked)");
                }
                if decision.matched_rules.is_empty() {
                    println!("Rules     : (defaults only)");
                } else {
                    println!("Rules     :");
                    for r in &decision.matched_rules {
                        println!(
                            "  - [{:?}/{:?}] {} ({}) {}",
                            r.layer,
                            r.effect,
                            r.id,
                            r.capabilities.join(","),
                            r.reason.as_deref().unwrap_or("")
                        );
                    }
                }
            }
            Ok(())
        }
        AccessCmd::Diff {
            base_policy,
            head_policy,
            server_policy,
            principals,
            paths,
            changed_files,
            ref_name,
            json,
        } => {
            let base = load_policy(&base_policy, server_policy.as_deref())?;
            let head = load_policy(&head_policy, server_policy.as_deref())?;

            let ids = principals
                .iter()
                .map(|p| Ok(DelegatedIdentity::human_only(Principal::parse(p)?, vec![])))
                .collect::<Result<Vec<_>>>()?;
            let repo_paths = paths
                .iter()
                .map(|p| Ok(RepoPath::new(p)?))
                .collect::<Result<Vec<_>>>()?;
            let changed = changed_files
                .iter()
                .map(|p| {
                    let rp = RepoPath::new(p)?;
                    let bytes = std::fs::read(p).ok();
                    Ok((rp, bytes))
                })
                .collect::<Result<Vec<_>>>()?;

            let ref_name = ref_name.unwrap_or_else(current_branch);
            let diff = compute_access_diff(&base, &head, &ids, &repo_paths, &changed, &ref_name);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                println!("Access Impact Diff (ref: {})", diff.ref_name);
                if diff.deltas.is_empty() {
                    println!("  No capability changes across evaluated principals/paths.");
                } else {
                    for d in &diff.deltas {
                        println!(
                            "  {} on {}: {:?} -> {:?} (+{:?} -{:?})",
                            d.principal, d.path, d.before, d.after, d.granted, d.revoked
                        );
                    }
                }
                for alert in &diff.quarantine_alerts {
                    println!(
                        "  [QUARANTINE:{}] {}: {}",
                        alert.severity.to_uppercase(),
                        alert.path,
                        alert.message
                    );
                }
            }
            Ok(())
        }
    }
}

async fn handle_env(cmd: EnvCmd) -> Result<()> {
    match cmd {
        EnvCmd::Validate {
            schema,
            env,
            branch,
            principal,
            backend,
            vault,
            age_key,
            json,
        } => {
            let env_schema = load_schema(&schema)?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let backend_impl =
                build_backend(backend, &repo_id, &env, &env_schema, &vault, &age_key)?;
            let target_env = Environment::parse(&env);
            let ctx = ResolveContext {
                repo_id,
                org: "local".to_owned(),
                env: target_env.clone(),
                branch: branch.unwrap_or_else(current_branch),
                identity: DelegatedIdentity::human_only(Principal::parse(&principal)?, vec![]),
            };
            let resolver = SecretResolver::new(&env_schema, None, backend_impl.as_ref());
            let resolved = resolver.resolve(&ctx, Capability::READ)?;

            let plain_map: BTreeMap<String, String> = resolved
                .values
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                .collect();
            let report = env_schema.validate_values(&target_env, &plain_map);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if report.is_ok() {
                println!(
                    "OK: {} validated cleanly for env '{}'",
                    premier_git_bridge::plural(report.checked_vars, "variable"),
                    report.environment
                );
            } else {
                println!(
                    "FAIL: {} for env '{}':",
                    premier_git_bridge::plural(report.issues.len(), "validation issue"),
                    report.environment
                );
                for issue in &report.issues {
                    println!("  - {}: {}", issue.var_name, issue.message);
                }
            }
            if !report.is_ok() {
                std::process::exit(1);
            }
            Ok(())
        }

        EnvCmd::Set {
            key,
            value,
            stdin,
            schema,
            env,
            layer,
            scope,
            backend,
            vault,
            age_key,
        } => {
            let secret_val: Zeroizing<String> = if stdin {
                let mut raw = Zeroizing::new(String::new());
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
                    .context("failed to read secret value from stdin")?;
                let trimmed = raw
                    .strip_suffix("\r\n")
                    .or_else(|| raw.strip_suffix('\n'))
                    .unwrap_or(&raw);
                Zeroizing::new(trimmed.to_owned())
            } else {
                Zeroizing::new(
                    value.ok_or_else(|| anyhow::anyhow!("provide a value or pass --stdin"))?,
                )
            };
            let env_schema = load_schema(&schema)?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let backend_impl =
                build_backend(backend, &repo_id, &env, &env_schema, &vault, &age_key)?;
            let coord = SecretCoord {
                repo_id,
                layer: layer.into(),
                scope: scope.unwrap_or(env),
                var_name: key.clone(),
            };
            backend_impl.set(&coord, secret_val.as_str())?;
            println!(
                "Stored '{}' in backend '{}' (layer={:?}, scope={})",
                key,
                backend_impl.name(),
                coord.layer,
                coord.scope
            );
            Ok(())
        }

        EnvCmd::List {
            schema,
            env,
            branch,
            principal,
            backend,
            vault,
            age_key,
        } => {
            let env_schema = load_schema(&schema)?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let backend_impl =
                build_backend(backend, &repo_id, &env, &env_schema, &vault, &age_key)?;
            let ctx = ResolveContext {
                repo_id,
                org: "local".to_owned(),
                env: Environment::parse(&env),
                branch: branch.unwrap_or_else(current_branch),
                identity: DelegatedIdentity::human_only(Principal::parse(&principal)?, vec![]),
            };
            let resolver = SecretResolver::new(&env_schema, None, backend_impl.as_ref());
            let resolved = resolver.resolve(&ctx, Capability::READ)?;

            println!("Schema variables for env '{}' (values never printed):", env);
            for (name, spec) in &env_schema.vars {
                match resolved.provenance.get(name) {
                    Some(prov) => println!(
                        "  [SET]     {:<24} sensitivity={:?} layer={:?} backend={}",
                        name, prov.sensitivity, prov.layer, prov.backend
                    ),
                    None => println!(
                        "  [MISSING] {:<24} sensitivity={:?} required_in={:?}",
                        name, spec.sensitivity, spec.required_in
                    ),
                }
            }
            Ok(())
        }

        EnvCmd::Mount {
            schema,
            path,
            env,
            branch,
            principal,
            backend,
            vault,
            age_key,
        } => {
            premier_secrets::check_fifo_mount_supported()?;
            let env_schema = load_schema(&schema)?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let backend_impl =
                build_backend(backend, &repo_id, &env, &env_schema, &vault, &age_key)?;
            let ctx = ResolveContext {
                repo_id,
                org: "local".to_owned(),
                env: Environment::parse(&env),
                branch: branch.unwrap_or_else(current_branch),
                identity: DelegatedIdentity::human_only(Principal::parse(&principal)?, vec![]),
            };
            let resolver = SecretResolver::new(&env_schema, None, backend_impl.as_ref());
            let resolved = resolver.resolve(&ctx, Capability::READ)?;
            mount_fifo(&path, &resolved.values).await?;
            Ok(())
        }

        EnvCmd::Rotate {
            key,
            env,
            schema,
            reason,
            new_value,
            json,
        } => {
            let env_schema = load_schema(&schema)?;
            let repo_id = env_schema
                .repo_id
                .clone()
                .unwrap_or_else(|| "local/repo".to_owned());
            let rotation = env_schema
                .vars
                .get(&key)
                .with_context(|| format!("'{key}' is not declared in {}", schema.display()))?
                .rotation
                .clone()
                .with_context(|| format!("'{key}' has no [vars.{key}.rotation] webhook"))?;
            let cwd = std::env::current_dir()?;
            let new_value = new_value.map(Zeroizing::new);
            let (root, var, env_bg) = (cwd.clone(), key.clone(), env.clone());
            let receipt = tokio::task::spawn_blocking(move || {
                premier_server::lifecycle::rotate_var_blocking(
                    &root,
                    &repo_id,
                    &RotationDispatcher::default(),
                    &var,
                    &rotation,
                    &env_bg,
                    CLI_ACTOR,
                    &reason,
                    false,
                    new_value.as_deref().map(String::as_str),
                )
            })
            .await?;
            if receipt.status == RotationStatus::Committed {
                let mut st = premier_server::store::load_state(&cwd).map_err(anyhow::Error::msg)?;
                premier_server::lifecycle::note_rotated_in(&mut st, &cwd, &key, &env)
                    .map_err(anyhow::Error::msg)?;
            }
            premier_server::lifecycle::record_rotations(&cwd, std::slice::from_ref(&receipt))
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "Rotation of '{key}' (env={env}): {:?}{}",
                    receipt.status,
                    receipt
                        .error
                        .as_deref()
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default()
                );
            }
            if receipt.status != RotationStatus::Committed {
                std::process::exit(1);
            }
            Ok(())
        }

        EnvCmd::KmsStatus { schema, json }
        | EnvCmd::Kms {
            cmd: KmsCmd::Status { schema, json },
        } => {
            let repo_id = schema
                .exists()
                .then(|| load_schema(&schema))
                .transpose()?
                .and_then(|s| s.repo_id)
                .unwrap_or_else(|| "local/repo".to_owned());
            let cwd = std::env::current_dir()?;
            let status = premier_server::lifecycle::kms_status(&cwd, &repo_id)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                let s = &status.status;
                println!("Vault       : {} ({})", s.vault_path, s.mode);
                println!(
                    "KEK         : {} / {} (separated: {})",
                    s.provider, s.key_id, s.kek_separated
                );
                println!("DEK version : {}", s.dek_version);
                println!("Entries     : {}", s.entry_count);
                println!(
                    "KT log      : {} entries, {}",
                    s.kt_entries,
                    match (&s.kt_valid, &s.kt_error) {
                        (true, _) => "chain valid".to_owned(),
                        (false, Some(e)) => format!("INVALID: {e}"),
                        (false, None) => "INVALID".to_owned(),
                    }
                );
            }
            if !status.status.kt_valid {
                std::process::exit(1);
            }
            Ok(())
        }

        EnvCmd::Kms {
            cmd: KmsCmd::Migrate { schema, json },
        } => {
            let repo_id = schema
                .exists()
                .then(|| load_schema(&schema))
                .transpose()?
                .and_then(|s| s.repo_id)
                .unwrap_or_else(|| "local/repo".to_owned());
            let cwd = std::env::current_dir()?;
            let (migrated, already) =
                premier_server::lifecycle::migrate_to_envelope(&cwd, &repo_id, CLI_ACTOR)
                    .map_err(|(status, msg)| anyhow::anyhow!("{msg} ({status})"))?;
            if !already {
                let mut st = premier_server::store::load_state(&cwd).map_err(anyhow::Error::msg)?;
                for meta in st.secret_meta.values_mut() {
                    "envelope-kms".clone_into(&mut meta.backend);
                }
                premier_server::store::save_state(&cwd, &st).map_err(anyhow::Error::msg)?;
            }
            let status = premier_server::lifecycle::kms_status(&cwd, &repo_id)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "migrated_entries": migrated,
                        "already_migrated": already,
                        "status": status,
                    }))?
                );
            } else if already {
                println!(
                    "Workspace vault is already in envelope KMS mode ({}).",
                    status.status.vault_path
                );
            } else {
                println!(
                    "Migrated {migrated} vault entries from Sovereign age to Envelope KMS ({}).",
                    status.status.vault_path
                );
            }
            Ok(())
        }

        EnvCmd::Kms {
            cmd: KmsCmd::RotateDek { schema, json },
        } => {
            let repo_id = schema
                .exists()
                .then(|| load_schema(&schema))
                .transpose()?
                .and_then(|s| s.repo_id)
                .unwrap_or_else(|| "local/repo".to_owned());
            let cwd = std::env::current_dir()?;
            let dek_version = premier_server::lifecycle::rotate_workspace_dek(&cwd, &repo_id)
                .map_err(|(status, msg)| anyhow::anyhow!("{msg} ({status})"))?;
            let status = premier_server::lifecycle::kms_status(&cwd, &repo_id)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "dek_version": dek_version,
                        "status": status,
                    }))?
                );
            } else {
                println!(
                    "Rotated workspace Envelope KMS DEK to v{dek_version} ({}).",
                    status.status.vault_path
                );
            }
            Ok(())
        }

        EnvCmd::OidcToken {
            principal,
            groups,
            agent_profile,
            task_id,
            audiences,
            branch,
            ttl,
            policy,
            server_policy,
            json,
        } => {
            let compiled = policy
                .exists()
                .then(|| load_policy(&policy, server_policy.as_deref()))
                .transpose()?;
            let schema_path = Path::new(".env.schema");
            let env_schema = schema_path
                .exists()
                .then(|| load_schema(schema_path))
                .transpose()?;
            if let (Some(name), Some(p)) = (&agent_profile, &compiled)
                && !p.has_agent_profile(name)
            {
                bail!(
                    "agent profile '{name}' is not defined in {}",
                    policy.display()
                );
            }
            let p = Principal::parse(&principal)?;
            let task_id = task_id.unwrap_or_else(|| format!("cli-{}", std::process::id()));
            let identity = match &agent_profile {
                Some(prof) => DelegatedIdentity::delegated(
                    p.clone(),
                    groups.clone(),
                    prof.clone(),
                    task_id.clone(),
                ),
                None => DelegatedIdentity::human_only(p.clone(), groups.clone()),
            };
            let branch = branch.unwrap_or_else(current_branch);
            let scope = premier_server::lifecycle::workload_scope(
                compiled.as_ref(),
                env_schema.as_ref(),
                &identity,
                &branch,
            );
            let cwd = std::env::current_dir()?;
            let issuer = premier_server::lifecycle::load_oidc_issuer(&cwd, true);
            let aud = if audiences.is_empty() {
                vec!["premier".to_owned()]
            } else {
                audiences
            };
            let issued = issuer.issue(WorkloadTokenRequest {
                sub: p.canonical_id(),
                act: agent_profile.map(|prof| ActorClaim {
                    sub: format!("agent:{prof}"),
                    profile: prof,
                    task_id,
                }),
                aud,
                repo: env_schema
                    .and_then(|s| s.repo_id)
                    .unwrap_or_else(|| "local/repo".to_owned()),
                branch,
                scope,
                groups,
                ttl_secs: Some(ttl),
            })?;
            if json {
                let out = serde_json::json!({
                    "token": issued.token,
                    "claims": issued.claims,
                    "kid": issued.kid,
                    "alg": issued.alg,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                eprintln!(
                    "Workload token for {} (jti={}, scope={}, expires {})",
                    issued.claims.sub,
                    issued.claims.jti,
                    issued.claims.scope.join(" "),
                    issued.claims.exp
                );
                println!("{}", issued.token);
            }
            Ok(())
        }
    }
}

/// Nanoseconds of the clock, to name a temporary directory.
fn clock_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

#[allow(clippy::too_many_arguments)]
fn prepare_proxy_config(
    bind: SocketAddr,
    env_schema: EnvSchema,
    policy_path: Option<&Path>,
    server_policy_path: Option<&Path>,
    principal: &str,
    groups: Vec<String>,
    profile: Option<String>,
    env: &str,
    allow_hosts: Vec<String>,
    audit_path: PathBuf,
    backend: BackendKind,
    vault: &Path,
    age_key: &Path,
    auto_approve_jit: bool,
    interactive_jit: bool,
) -> Result<(ProxyConfig, PlaceholderRegistry, BTreeMap<String, String>)> {
    let compiled = load_optional_policy(policy_path, server_policy_path)?;
    let repo_id = env_schema
        .repo_id
        .clone()
        .unwrap_or_else(|| "local/repo".to_owned());
    let backend_impl = build_backend(backend, &repo_id, env, &env_schema, vault, age_key)?;

    // Secrets and egress rules are decided for the branch this checkout is on.
    let branch = current_branch();
    let p = Principal::parse(principal)?;
    let identity = match profile.clone() {
        Some(prof) => {
            DelegatedIdentity::delegated(p, groups, prof, format!("pid-{}", std::process::id()))
        }
        None => DelegatedIdentity::human_only(p, groups),
    };

    let ctx = ResolveContext {
        repo_id,
        org: "local".to_owned(),
        env: Environment::parse(env),
        branch: branch.clone(),
        identity: identity.clone(),
    };
    let resolver = SecretResolver::new(&env_schema, compiled.as_ref(), backend_impl.as_ref());
    let resolved = resolver.resolve(&ctx, Capability::USE)?;

    let mut registry = PlaceholderRegistry::new();
    let mut public_vars = BTreeMap::new();

    for (var_name, spec) in &env_schema.vars {
        let Some(val) = resolved.values.get(var_name) else {
            continue;
        };
        if let Some(egress) = &spec.egress {
            registry.register_with_sensitivity(
                var_name.clone(),
                Zeroizing::new(val.as_str().to_owned()),
                egress.clone(),
                spec.zone.clone(),
                spec.sensitivity,
            );
        } else if matches!(
            spec.sensitivity,
            Sensitivity::Public | Sensitivity::Internal
        ) {
            public_vars.insert(var_name.clone(), val.as_str().to_owned());
        }
    }

    let mut passthrough: HashSet<String> = allow_hosts.into_iter().collect();
    if let (Some(c), Some(prof)) = (&compiled, &profile) {
        for h in c.agent_allowed_egress_hosts(prof) {
            passthrough.insert(h);
        }
    }

    let mut cfg = ProxyConfig::new(bind, identity, registry.clone());
    cfg.ref_name = branch;
    cfg.session_context = Some(SessionContext {
        session_id: None,
        branch: Some(cfg.ref_name.clone()),
        command: None,
    });
    cfg.policy = compiled;
    cfg.allow_passthrough_hosts = passthrough;
    cfg.audit_sink = Arc::new(AuditSink::new(Some(audit_path)));
    cfg.approval_gate = if auto_approve_jit {
        Box::new(AutoApproveGate)
    } else if interactive_jit {
        Box::new(InteractiveTtyGate)
    } else {
        Box::new(DenyJitGate)
    };

    Ok((cfg, registry, public_vars))
}

/// The branch a command works on when it is not told: the one checked out in the current
/// directory, or `main` with a detached HEAD (or outside a repository).
fn current_branch() -> String {
    branch_of(Path::new("."))
}

fn branch_of(checkout: &Path) -> String {
    // Plain git, not `git_command`: a subdirectory of the checkout is on its branch too.
    std::process::Command::new("git")
        .current_dir(checkout)
        .args(["symbolic-ref", "--short", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|branch| !branch.is_empty())
        .unwrap_or_else(|| "main".to_owned())
}

fn load_policy(repo_path: &Path, server_path: Option<&Path>) -> Result<CompiledPolicy> {
    let repo_text = std::fs::read_to_string(repo_path)
        .with_context(|| format!("failed to read policy file {}", repo_path.display()))?;
    let repo_file = parse_policy_toml(&repo_text)?;
    let server_file = match server_path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read server policy {}", p.display()))?;
            Some(parse_policy_toml(&text)?)
        }
        None => None,
    };
    Ok(CompiledPolicy::compile(server_file.as_ref(), &repo_file)?)
}

fn compute_policy_fingerprint(repo_path: &Path, server_path: Option<&Path>) -> Result<String> {
    let mut input = std::fs::read_to_string(repo_path)
        .with_context(|| format!("failed to read policy file {}", repo_path.display()))?;
    if let Some(sp) = server_path {
        let server_text = std::fs::read_to_string(sp)
            .with_context(|| format!("failed to read server policy {}", sp.display()))?;
        input.push_str("\n---server-policy---\n");
        input.push_str(&server_text);
    }
    Ok(premier_policy::sha256_hex(input.as_bytes()))
}

fn load_optional_policy(
    repo_path: Option<&Path>,
    server_path: Option<&Path>,
) -> Result<Option<CompiledPolicy>> {
    match (repo_path, server_path) {
        (Some(p), srv) => Ok(Some(load_policy(p, srv)?)),
        (None, Some(sp)) => {
            let text = std::fs::read_to_string(sp)
                .with_context(|| format!("failed to read server policy {}", sp.display()))?;
            let server_file = parse_policy_toml(&text)?;
            let empty_repo = premier_policy::AccessPolicyFile::default();
            Ok(Some(CompiledPolicy::compile(
                Some(&server_file),
                &empty_repo,
            )?))
        }
        (None, None) => Ok(None),
    }
}

fn resolve_agent_policy_path(policy: Option<PathBuf>, cwd: &Path) -> Option<PathBuf> {
    if policy.is_some() {
        return policy;
    }
    let default_policy = cwd.join(".access.toml");
    default_policy.exists().then_some(default_policy)
}

fn load_optional_schema(schema: Option<&Path>, cwd: &Path) -> Result<EnvSchema> {
    match schema {
        Some(explicit) => load_schema(explicit),
        None => {
            let default_schema = cwd.join(".env.schema");
            if default_schema.exists() {
                load_schema(&default_schema)
            } else {
                tracing::warn!(
                    path = %default_schema.display(),
                    "default .env.schema not found; continuing with empty schema"
                );
                Ok(EnvSchema::default())
            }
        }
    }
}

fn load_schema(path: &Path) -> Result<EnvSchema> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read schema {}", path.display()))?;
    Ok(EnvSchema::parse_toml(&text)?)
}

fn build_backend(
    kind: BackendKind,
    repo_id: &str,
    env: &str,
    schema: &EnvSchema,
    vault_path: &Path,
    age_key_path: &Path,
) -> Result<Box<dyn SecretBackend>> {
    match kind {
        BackendKind::Env => {
            let mem = MemoryBackend::new();
            for var_name in schema.vars.keys() {
                if let Ok(val) = std::env::var(var_name) {
                    mem.set(
                        &SecretCoord {
                            repo_id: repo_id.to_owned(),
                            layer: SecretLayer::Env,
                            scope: env.to_owned(),
                            var_name: var_name.clone(),
                        },
                        &val,
                    )?;
                }
            }
            Ok(Box::new(mem))
        }
        BackendKind::Keychain => Ok(Box::new(KeychainBackend::new("premier"))),
        BackendKind::Age => {
            let identity = load_or_create_age_identity(age_key_path)?;
            Ok(Box::new(AgeSovereignBackend::new(
                vault_path,
                repo_id,
                vault_path.to_string_lossy(),
                identity,
                vec![],
            )))
        }
    }
}

fn load_or_create_age_identity(path: &Path) -> Result<age::x25519::Identity> {
    if let Ok(raw) = std::env::var("PREMIER_AGE_IDENTITY") {
        return raw
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|e| anyhow::anyhow!("invalid PREMIER_AGE_IDENTITY: {e}"));
    }
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read age identity {}", path.display()))?;
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("AGE-SECRET-KEY-") {
                return trimmed.parse::<age::x25519::Identity>().map_err(|e| {
                    anyhow::anyhow!("invalid age identity in {}: {e}", path.display())
                });
            }
        }
        bail!("no AGE-SECRET-KEY line found in {}", path.display());
    }

    if let Some(parent) = path.parent() {
        premier_secrets::create_state_dir(parent)?;
    }
    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let secret_str = id.to_string();
    let content = format!(
        "# Premier Sovereign Age Identity (KEEP PRIVATE; never commit)\n# public key: {}\n{}\n",
        id.to_public(),
        secret_str.expose_secret()
    );
    premier_secrets::write_private(path, content.as_bytes())?;
    Ok(id)
}

/// `PREMIER_TRUSTED_PROXIES=` (set but empty, as a compose file leaves it) means none.
fn git_workspace_root(cwd: &Path) -> std::io::Result<Option<PathBuf>> {
    let out = premier_git_bridge::git_command(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    Ok(out
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())))
}

fn init_workspace(cwd: &Path) -> Result<()> {
    use std::io::Write as _;

    let root = match git_workspace_root(cwd).context("failed to run Git")? {
        Some(path) => path,
        None => {
            let bare = premier_git_bridge::git_command(cwd)
                .args(["rev-parse", "--is-bare-repository"])
                .output()?;
            if bare.status.success() && bare.stdout.trim_ascii() == b"true" {
                bail!("premier init requires a working tree");
            }
            let output = premier_git_bridge::git_command(cwd)
                .args(["init", "-b", "main"])
                .output()?;
            if !output.status.success() {
                bail!(
                    "git init failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            cwd.to_path_buf()
        }
    };
    for (name, contents) in [
        (
            ".access.toml",
            premier_server::directory::DEFAULT_POLICY_TOML,
        ),
        (
            ".env.schema",
            "# Declare environment variables here. Store values in the vault.\nversion = 1\n\n[vars]\n",
        ),
    ] {
        let file = root.join(name);
        let mut out = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)
        {
            Ok(out) => out,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && file.is_file() => {
                continue;
            }
            Err(err) => return Err(err).with_context(|| format!("create {}", file.display())),
        };
        out.write_all(contents.as_bytes())
            .with_context(|| format!("write {}", file.display()))?;
    }
    println!("Premier workspace ready at {}", root.display());
    Ok(())
}

fn report_workspace_status(cwd: &Path, state_dir: Option<&Path>) {
    println!("Premier workspace diagnostics");
    match premier_git_bridge::git_command(cwd)
        .arg("--version")
        .output()
    {
        Ok(out) if out.status.success() => println!(
            "  Git                   {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ),
        _ => println!("  Git                   unavailable"),
    }
    let repo = git_workspace_root(cwd).ok().flatten();
    println!(
        "  Repository            {}",
        repo.as_deref().map_or_else(
            || "no Git working tree".into(),
            |root| root.display().to_string()
        )
    );
    let root = repo.as_deref().unwrap_or(cwd);
    for name in [".access.toml", ".env.schema"] {
        let path = root.join(name);
        println!(
            "  {name:22} {} ({})",
            if path.is_file() { "present" } else { "missing" },
            path.display()
        );
    }
    let state = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| premier_server::store::state_dir(root));
    let state_status = if state.is_dir() {
        "present"
    } else if state.exists() {
        "path is a file"
    } else {
        "missing"
    };
    println!(
        "  State directory       {state_status} ({})",
        state.display()
    );
    let ui = std::env::var_os("PREMIER_STATIC_UI_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain([root.join("apps/web/dist")])
        .find(|dir| dir.join("index.html").is_file());
    println!(
        "  Studio UI             {}",
        ui.map_or_else(|| "build missing".into(), |dir| dir.display().to_string())
    );
}

fn parse_trusted_proxies(raw: &[String]) -> Result<Vec<std::net::IpAddr>> {
    raw.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| ip.to_canonical())
                .with_context(|| format!("invalid trusted proxy address '{s}'"))
        })
        .collect()
}

/// `--ssh-public-url`: an `ssh://` URL shown to users as-is, so nothing that could break the
/// hint (spaces, quotes, control characters). Empty (an unset compose variable) means none.
fn parse_ssh_public_url(raw: &str) -> std::result::Result<String, String> {
    let url = raw.trim().trim_end_matches('/');
    if url.is_empty() {
        return Ok(String::new());
    }
    let ok = url
        .strip_prefix("ssh://")
        .is_some_and(|rest| !rest.is_empty())
        && url
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '`' | '<' | '>' | '\\'));
    if ok {
        Ok(url.to_owned())
    } else {
        Err("expected an ssh:// URL such as ssh://git@git.example.com:7429".to_owned())
    }
}

fn handle_overlay(cmd: OverlayCmd, state_dir: Option<&Path>) -> Result<()> {
    use premier_core::OverlayKind;
    let cwd = std::env::current_dir()?;
    if let Some(dir) = state_dir {
        let name = premier_server::repos::repo_name(&cwd, None);
        premier_server::store::bind_state_dir(&cwd, dir, &name, true);
    }
    let store = premier_server::overlay_store(&cwd)?;
    match cmd {
        OverlayCmd::List {
            principal,
            groups,
            json,
        } => {
            let resp = premier_overlay::OverlayListResponse::new(
                store.list_for_principal(&principal, &groups)?,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if resp.entries.is_empty() {
                println!("No overlays for {principal}.");
            } else {
                for e in &resp.entries {
                    let holder = e.owner_principal.as_deref().map_or_else(
                        || format!("team:{}", e.team_group.as_deref().unwrap_or("?")),
                        str::to_owned,
                    );
                    let flags = match (e.encrypted, e.has_payload) {
                        (_, false) => "metadata only",
                        (true, true) => "encrypted",
                        (false, true) => "plaintext",
                    };
                    println!("{holder:<20} {:<40} {flags}", e.path);
                }
            }
        }
        OverlayCmd::Mount {
            path,
            scope,
            encrypted: _,
            no_encrypted,
            principal,
            file,
            content,
        } => {
            let kind = match scope.trim() {
                "personal" => OverlayKind::Personal,
                other => match other.strip_prefix("team:") {
                    Some(team) => OverlayKind::Team(team.trim().to_owned()),
                    None => bail!("--scope must be `personal` or `team:<name>`, not `{other}`"),
                },
            };
            let payload = match (file, content) {
                (Some(f), _) => Some(
                    std::fs::read(&f).with_context(|| format!("failed to read {}", f.display()))?,
                ),
                (None, Some(c)) => Some(c.into_bytes()),
                (None, None) => None,
            };
            let r = store.mount(premier_overlay::MountOverlayInput {
                kind,
                path,
                owner_principal: Some(principal),
                team_group: None,
                encrypted: !no_encrypted,
                payload,
            })?;
            let holder = r
                .owner_principal
                .clone()
                .or_else(|| r.team_group.as_ref().map(|t| format!("team:{t}")))
                .unwrap_or_default();
            println!(
                "Mounted '{}' for {holder}{}.",
                r.path,
                if r.has_payload && r.encrypted {
                    " (content encrypted at rest)"
                } else {
                    ""
                }
            );
        }
        OverlayCmd::Unmount { path, principal } => {
            if store.unmount(&path, &principal)? {
                println!("Unmounted '{path}'.");
            } else {
                println!("No overlay at '{path}' for {principal}.");
            }
        }
        OverlayCmd::CheckPush { paths, overlays } => {
            let mut manifest = workspace_overlays(&cwd.join(overlays), &cwd)?;
            for entry in store.to_manifest()?.entries {
                if !manifest.entries.contains(&entry) {
                    manifest.entries.push(entry);
                }
            }
            let guard = premier_overlay::OverlayGuard::from_manifest(&manifest)?;
            let paths = paths
                .iter()
                .map(|p| RepoPath::new(p).with_context(|| format!("invalid path '{p}'")))
                .collect::<Result<Vec<_>>>()?;
            match guard.validate_public_paths(&paths) {
                Ok(()) => println!("Clean: no overlay files among {} path(s).", paths.len()),
                Err(premier_overlay::OverlayError::LeakBlocked { paths }) => {
                    bail!(
                        "overlay guard blocked {} from a public push: {}",
                        paths.len(),
                        paths.join(", ")
                    )
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}

fn workspace_overlays(
    overlays_path: &Path,
    workspace_root: &Path,
) -> Result<premier_overlay::OverlayManifest> {
    use premier_server::store::{has_state_db, load_state};
    if !has_state_db(workspace_root).map_err(anyhow::Error::msg)? {
        return mcp::load_workspace_overlays(overlays_path, workspace_root);
    }
    let mut manifest = match std::fs::read_to_string(overlays_path) {
        Ok(raw) => mcp::parse_overlay_manifest(&raw)
            .with_context(|| format!("failed to parse {}", overlays_path.display()))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", overlays_path.display()));
        }
    };
    let state = load_state(workspace_root).map_err(anyhow::Error::msg)?;
    for entry in state.overlays.entries {
        if !manifest.entries.contains(&entry) {
            manifest.entries.push(entry);
        }
    }
    Ok(manifest)
}

#[allow(clippy::too_many_arguments)]
fn mcp_context(
    state_dir: Option<&Path>,
    policy: &Path,
    server_policy: Option<&Path>,
    schema: &Path,
    overlays: &Path,
    principal: &str,
    groups: Vec<String>,
    agent_profile: Option<String>,
    branch: String,
) -> Result<mcp::McpContext> {
    let mut ctx = mcp::McpContext::from_paths(
        policy,
        server_policy,
        schema,
        overlays,
        principal,
        groups,
        agent_profile,
        branch,
    )?;
    let workspace = policy
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let workspace = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_owned());
    if let Some(dir) = state_dir {
        let name = premier_server::repos::repo_name(&workspace, None);
        premier_server::store::bind_state_dir(&workspace, dir, &name, false);
    }
    let manifest = workspace_overlays(overlays, &workspace)?;
    ctx.overlay_guard = premier_overlay::OverlayGuard::from_manifest(&manifest)?;
    Ok(ctx)
}

fn validate_gateway_flags(auto_approve_jit: bool, agent_profile: Option<&str>) -> Result<()> {
    if auto_approve_jit && agent_profile.is_some() {
        bail!(
            "refusing --auto-approve-jit when --agent-profile is set; delegated agents require explicit JIT approval via `premier serve`"
        );
    }
    Ok(())
}

fn run_trace_cmd(command: TraceCmd) -> Result<()> {
    match command {
        TraceCmd::List { file, json } => {
            let path = file.unwrap_or_else(|| PathBuf::from(".premier").join("traces.jsonl"));
            let store = premier_trace::TraceStore::new(
                Some(path.clone()),
                premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
            );
            let viewer = DelegatedIdentity::human_only(Principal::User("cli".to_owned()), vec![]);
            let sessions = store.list_sessions_for_viewer(&viewer, None, "main");
            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
                return Ok(());
            }
            if sessions.is_empty() {
                println!("No trace sessions found in {}.", path.display());
                return Ok(());
            }
            println!(
                "{:<24} {:<10} {:<10} {:>6} {:>9} {:<18}",
                "SESSION", "STATUS", "INTEGRITY", "SPANS", "SCRUBBED", "BRANCH"
            );
            for s in &sessions {
                let integrity = format!("{:?}", s.delivery.integrity.status).to_ascii_lowercase();
                let status = format!("{:?}", s.status).to_ascii_lowercase();
                println!(
                    "{:<24} {:<10} {:<10} {:>6} {:>7} B {:<18}",
                    s.session_id,
                    status,
                    integrity,
                    s.delivery.total_spans,
                    s.delivery.bytes_scrubbed,
                    s.branch
                );
            }
            Ok(())
        }
        TraceCmd::Verify { file } => {
            let path = file.unwrap_or_else(|| PathBuf::from(".premier").join("traces.jsonl"));
            let store = premier_trace::TraceStore::new(
                Some(path.clone()),
                premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
            );
            let viewer = DelegatedIdentity::human_only(Principal::User("cli".to_owned()), vec![]);
            let sessions = store.list_sessions_for_viewer(&viewer, None, "main");
            if sessions.is_empty() {
                println!("No trace sessions found in {}.", path.display());
                return Ok(());
            }
            let mut tampered = 0usize;
            for s in &sessions {
                let rep = s.verify_integrity();
                let tag = match rep.status {
                    premier_trace::IntegrityStatus::Verified => "VERIFIED",
                    premier_trace::IntegrityStatus::Live => "LIVE",
                    premier_trace::IntegrityStatus::Tampered => {
                        tampered += 1;
                        "TAMPERED"
                    }
                };
                let head = &rep.head_hash[..rep.head_hash.len().min(12)];
                println!(
                    "[{tag}] {} ({}/{} spans, head={head}{})",
                    s.session_id,
                    rep.verified_spans,
                    s.spans.len(),
                    rep.detail
                        .as_deref()
                        .map(|d| format!(", detail={d}"))
                        .unwrap_or_default()
                );
            }
            if tampered > 0 {
                bail!("{tampered} trace session(s) failed SHA-256 hash-chain verification");
            }
            println!(
                "All {} trace session(s) passed verification.",
                sessions.len()
            );
            Ok(())
        }
        TraceCmd::HookConfig { harness, server } => {
            let ingest_url = format!("{}/v1/traces/ingest", server.trim_end_matches('/'));
            match harness.to_ascii_lowercase().as_str() {
                "claude" | "claude-code" => {
                    let cfg = serde_json::json!({
                        "hooks": {
                            "PostToolUse": [{
                                "matcher": "*",
                                "hooks": [{
                                    "type": "command",
                                    "command": format!(r#"curl -fsS -X POST "{ingest_url}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-"#)
                                }]
                            }],
                            "Stop": [{
                                "hooks": [{
                                    "type": "command",
                                    "command": format!(r#"curl -fsS -X POST "{ingest_url}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-"#)
                                }]
                            }]
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                }
                "codex" => {
                    println!(
                        "notify = [\n  \"sh\", \"-c\",\n  \"curl -fsS -X POST '{ingest_url}' -H 'Authorization: Bearer $PREMIER_TOKEN' -H 'Content-Type: application/json' -d \\\"$1\\\" >/dev/null\",\n  \"--\"\n]"
                    );
                }
                "cursor" => {
                    let cfg = serde_json::json!({
                        "version": 1,
                        "hooks": {
                            "afterFileEdit": [{
                                "command": format!(r#"curl -fsS -X POST "{ingest_url}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-"#)
                            }],
                            "afterShellExecution": [{
                                "command": format!(r#"curl -fsS -X POST "{ingest_url}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-"#)
                            }]
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                }
                "gemini" => {
                    let cfg = serde_json::json!({
                        "hooks": {
                            "AfterTool": [{
                                "matcher": "*",
                                "hooks": [{
                                    "type": "command",
                                    "command": format!(r#"curl -fsS -X POST "{ingest_url}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-"#)
                                }]
                            }]
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                }
                "otlp" => {
                    println!("export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=\"{ingest_url}\"");
                    println!(
                        "export OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer $PREMIER_TOKEN\""
                    );
                }
                other => {
                    bail!(
                        "unknown harness '{other}' (expected one of: claude, codex, cursor, gemini, otlp)"
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn overlay_subcommands_parse() {
        let parse = |args: &[&str]| {
            let mut all = vec!["premier", "overlay"];
            all.extend_from_slice(args);
            match Cli::try_parse_from(all).unwrap().command {
                Commands::Overlay { cmd } => cmd,
                other => panic!("not overlay: {other:?}"),
            }
        };
        let OverlayCmd::List {
            principal,
            groups,
            json,
        } = parse(&[
            "list",
            "--principal",
            "@a",
            "--group",
            "core",
            "--group",
            "ops",
            "--json",
        ])
        else {
            panic!("not list");
        };
        assert_eq!((principal.as_str(), json), ("@a", true));
        assert_eq!(groups, ["core", "ops"]);
        let OverlayCmd::List { principal, .. } = parse(&["list"]) else {
            panic!("not list");
        };
        assert_eq!(principal, "@local");

        let OverlayCmd::Mount {
            path,
            scope,
            no_encrypted,
            content,
            file,
            ..
        } = parse(&["mount", "AGENTS.local.md", "--content", "hi"])
        else {
            panic!("not mount");
        };
        assert_eq!(
            (path.as_str(), scope.as_str()),
            ("AGENTS.local.md", "personal")
        );
        assert!(!no_encrypted, "encrypted by default");
        assert_eq!((content.as_deref(), file), (Some("hi"), None));
        let OverlayCmd::Mount {
            scope,
            no_encrypted,
            file,
            ..
        } = parse(&[
            "mount",
            ".run/x",
            "--scope",
            "team:core",
            "--no-encrypted",
            "--file",
            "a.txt",
        ])
        else {
            panic!("not mount");
        };
        assert_eq!(scope, "team:core");
        assert!(no_encrypted);
        assert_eq!(file, Some(PathBuf::from("a.txt")));
        let OverlayCmd::Mount { no_encrypted, .. } =
            parse(&["mount", "x", "--no-encrypted", "--encrypted"])
        else {
            panic!("not mount");
        };
        assert!(!no_encrypted, "the last flag wins");
        assert!(
            Cli::try_parse_from([
                "premier",
                "overlay",
                "mount",
                "x",
                "--file",
                "a",
                "--content",
                "b"
            ])
            .is_err()
        );

        let OverlayCmd::Unmount { path, principal } =
            parse(&["unmount", "AGENTS.local.md", "--principal", "@bob"])
        else {
            panic!("not unmount");
        };
        assert_eq!(
            (path.as_str(), principal.as_str()),
            ("AGENTS.local.md", "@bob")
        );

        let OverlayCmd::CheckPush { paths, overlays } = parse(&["check-push", "a", "b/c"]) else {
            panic!("not check-push");
        };
        assert_eq!(paths, ["a", "b/c"]);
        assert_eq!(overlays, PathBuf::from(".premier/overlays.toml"));
        assert!(Cli::try_parse_from(["premier", "overlay", "check-push"]).is_err());
        // The global `--state-dir` is accepted after the subcommand too.
        let cli =
            Cli::try_parse_from(["premier", "overlay", "list", "--state-dir", "/tmp/s"]).unwrap();
        assert_eq!(cli.state_dir, Some(PathBuf::from("/tmp/s")));
    }

    #[test]
    fn ssh_public_url_must_be_a_plain_ssh_url() {
        assert_eq!(
            parse_ssh_public_url("ssh://git@host:7429/").unwrap(),
            "ssh://git@host:7429"
        );
        assert_eq!(parse_ssh_public_url("").unwrap(), "");
        for bad in [
            "git@host:7429",
            "https://host",
            "ssh://",
            "ssh://a b",
            "ssh://h\"x",
        ] {
            assert!(parse_ssh_public_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn empty_trusted_proxies_env_is_unset() {
        let list = |raw: &[&str]| {
            parse_trusted_proxies(&raw.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };
        assert!(list(&[""]).unwrap().is_empty());
        assert_eq!(list(&["10.0.0.1", " ::1 "]).unwrap().len(), 2);
        assert!(list(&["nope"]).is_err());
    }

    #[test]
    fn serve_without_a_committed_access_toml_uses_the_private_default() {
        // A working-tree file is not the policy: only what the default branch has committed is.
        let tmp = tempfile::tempdir().unwrap();
        let open = "version = 1
[defaults]
public = [\"read\"]
";
        std::fs::write(tmp.path().join(".access.toml"), open).unwrap();
        let mut state = ServerState::minimal(None, None, Arc::new(AuditSink::default()));
        state.workspace_root = tmp.path().to_path_buf();
        state.reload_repo_config().unwrap();
        let served = state.current_repo_policy_toml();
        assert_eq!(served, premier_server::directory::DEFAULT_POLICY_TOML);
        let file = parse_policy_toml(&served).unwrap();
        assert!(file.defaults.public.is_empty() && file.defaults.authenticated.is_empty());
    }

    #[test]
    fn ref_defaults_to_the_checked_out_branch_and_to_main_when_detached() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(root)
                .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-q", "-b", "feature/x"]);
        // Also before the first commit, and from a subdirectory.
        assert_eq!(branch_of(root), "feature/x");
        std::fs::create_dir(root.join("sub")).unwrap();
        assert_eq!(branch_of(&root.join("sub")), "feature/x");
        git(&["commit", "-q", "--allow-empty", "-m", "one"]);
        git(&["checkout", "-q", "--detach"]);
        assert_eq!(branch_of(root), "main");

        // The flags are optional now; given, they win.
        let cli = Cli::try_parse_from(["premier", "access", "explain", "@a", "x"]).unwrap();
        let Commands::Access {
            cmd: AccessCmd::Explain { ref_name, .. },
        } = cli.command
        else {
            panic!("not access explain");
        };
        assert_eq!(ref_name, None);
        let cli = Cli::try_parse_from(["premier", "env", "list", "--branch", "dev"]).unwrap();
        let Commands::Env {
            cmd: EnvCmd::List { branch, .. },
        } = cli.command
        else {
            panic!("not env list");
        };
        assert_eq!(branch.as_deref(), Some("dev"));
    }

    #[test]
    fn mcp_cli_flags_parse_cleanly() {
        let cli = Cli::try_parse_from([
            "premier",
            "mcp",
            "serve",
            "--policy",
            "custom.access.toml",
            "--server-policy",
            "server.access.toml",
            "--schema",
            "custom.env.schema",
            "--overlays",
            ".premier/custom.toml",
            "--principal",
            "@alice",
            "--group",
            "billing",
            "--group",
            "web",
            "--agent-profile",
            "ui-agent",
            "--branch",
            "release/1.0",
        ])
        .unwrap();
        let Commands::Mcp {
            cmd:
                McpCmd::Serve {
                    policy,
                    server_policy,
                    schema,
                    overlays,
                    principal,
                    groups,
                    agent_profile,
                    branch,
                },
        } = cli.command
        else {
            panic!("not mcp serve");
        };
        assert_eq!(policy, PathBuf::from("custom.access.toml"));
        assert_eq!(server_policy, Some(PathBuf::from("server.access.toml")));
        assert_eq!(schema, PathBuf::from("custom.env.schema"));
        assert_eq!(overlays, PathBuf::from(".premier/custom.toml"));
        assert_eq!(principal, "@alice");
        assert_eq!(groups, vec!["billing", "web"]);
        assert_eq!(agent_profile.as_deref(), Some("ui-agent"));
        assert_eq!(branch.as_deref(), Some("release/1.0"));

        let cfg = Cli::try_parse_from([
            "premier",
            "mcp",
            "config",
            "--client",
            "codex",
            "--agent-profile",
            "ui-agent",
            "--principal",
            "@alice",
            "--group",
            "billing",
            "--group",
            "web",
            "--policy",
            "custom.access.toml",
            "--server-policy",
            "server.access.toml",
            "--wrapper",
        ])
        .unwrap();
        let Commands::Mcp {
            cmd:
                McpCmd::Config {
                    client,
                    agent_profile,
                    principal,
                    groups,
                    policy,
                    server_policy,
                    wrapper,
                    gateway,
                    env,
                    backend,
                },
        } = cfg.command
        else {
            panic!("not mcp config");
        };
        assert_eq!(client, mcp::McpClient::Codex);
        assert_eq!(agent_profile.as_deref(), Some("ui-agent"));
        assert_eq!(principal.as_deref(), Some("@alice"));
        assert_eq!(groups, vec!["billing", "web"]);
        assert_eq!(policy, Some(PathBuf::from("custom.access.toml")));
        assert_eq!(server_policy, Some(PathBuf::from("server.access.toml")));
        assert!(wrapper);

        assert!(!gateway);
        assert_eq!(env, None);
        assert_eq!(backend, None);

        let gw_cfg = Cli::try_parse_from([
            "premier",
            "mcp",
            "config",
            "--gateway",
            "--client",
            "claude-code",
            "--agent-profile",
            "ui-agent",
            "--principal",
            "@alice",
            "--env",
            "staging",
            "--backend",
            "age",
            "--server-policy",
            "org.access.toml",
        ])
        .unwrap();
        let Commands::Mcp {
            cmd:
                McpCmd::Config {
                    client,
                    agent_profile,
                    principal,
                    gateway,
                    env,
                    backend,
                    server_policy,
                    ..
                },
        } = gw_cfg.command
        else {
            panic!("not mcp config --gateway");
        };
        assert_eq!(client, mcp::McpClient::ClaudeCode);
        assert_eq!(agent_profile.as_deref(), Some("ui-agent"));
        assert_eq!(principal.as_deref(), Some("@alice"));
        assert!(gateway);
        assert_eq!(env.as_deref(), Some("staging"));
        assert_eq!(backend, Some(BackendKind::Age));
        assert_eq!(server_policy, Some(PathBuf::from("org.access.toml")));

        let gw_defaults = Cli::try_parse_from(["premier", "mcp", "gateway"]).unwrap();
        let Commands::Mcp {
            cmd:
                McpCmd::Gateway {
                    policy,
                    server_policy,
                    schema,
                    overlays,
                    principal,
                    groups,
                    agent_profile,
                    branch,
                    env,
                    backend,
                    vault,
                    age_key,
                    audit,
                    pins,
                    auto_approve_jit,
                    allow_loopback_http,
                    allow_private_upstreams,
                    no_builtin_tools,
                },
        } = gw_defaults.command
        else {
            panic!("not mcp gateway");
        };
        assert_eq!(policy, PathBuf::from(".access.toml"));
        assert_eq!(server_policy, None);
        assert_eq!(schema, PathBuf::from(".env.schema"));
        assert_eq!(overlays, PathBuf::from(".premier/overlays.toml"));
        assert_eq!(principal, "@local");
        assert!(groups.is_empty());
        assert_eq!(agent_profile, None);
        assert_eq!(branch, None);
        assert_eq!(env, "dev");
        assert_eq!(backend, BackendKind::Env);
        assert_eq!(vault, PathBuf::from(".premier-local/vault.toml"));
        assert_eq!(age_key, PathBuf::from(".premier-local/age.key"));
        assert_eq!(audit, PathBuf::from(".premier-local/audit.jsonl"));
        assert_eq!(pins, PathBuf::from(".premier-local/mcp-pins.json"));
        assert!(!auto_approve_jit);
        assert!(!allow_loopback_http);
        assert!(!allow_private_upstreams);
        assert!(!no_builtin_tools);

        let gw_full = Cli::try_parse_from([
            "premier",
            "mcp",
            "gateway",
            "--policy",
            "custom.access.toml",
            "--server-policy",
            "org.access.toml",
            "--schema",
            "custom.env.schema",
            "--overlays",
            "custom.overlays.toml",
            "--principal",
            "@alice",
            "--group",
            "eng",
            "--agent-profile",
            "ui-agent",
            "--branch",
            "feat/mcp",
            "--env",
            "prod",
            "--backend",
            "age",
            "--vault",
            "custom.vault.toml",
            "--age-key",
            "custom.age.key",
            "--audit",
            "custom.audit.jsonl",
            "--pins",
            "custom.pins.json",
            "--auto-approve-jit",
            "--allow-loopback-http",
            "--allow-private-upstreams",
            "--no-builtin-tools",
        ])
        .unwrap();
        let Commands::Mcp {
            cmd:
                McpCmd::Gateway {
                    auto_approve_jit,
                    allow_loopback_http,
                    allow_private_upstreams,
                    no_builtin_tools,
                    backend,
                    env,
                    ..
                },
        } = gw_full.command
        else {
            panic!("not mcp gateway");
        };
        assert!(auto_approve_jit);
        assert!(allow_loopback_http);
        assert!(allow_private_upstreams);
        assert!(no_builtin_tools);
        assert_eq!(backend, BackendKind::Age);
        assert_eq!(env, "prod");
    }

    #[test]
    fn empty_ssh_bind_parses_as_none() {
        // Direct parser check for empty and whitespace-only values (as produced by PREMIER_SSH_BIND="").
        assert_eq!(parse_optional_socket_addr("").unwrap().0, None);
        assert_eq!(parse_optional_socket_addr("   ").unwrap().0, None);
        assert_eq!(
            parse_optional_socket_addr("0.0.0.0:2222").unwrap().0,
            Some("0.0.0.0:2222".parse().unwrap())
        );
        assert!(parse_optional_socket_addr("not-an-addr").is_err());

        // CLI flag parsing with empty string yields None (never crash-loops).
        let cli = Cli::try_parse_from(["premier", "serve", "--ssh-bind", ""]).unwrap();
        let Commands::Serve { ssh_bind, .. } = cli.command else {
            panic!("not serve");
        };
        assert_eq!(ssh_bind.and_then(|s| s.0), None);

        // Verify the clap argument binds to PREMIER_SSH_BIND.
        use clap::CommandFactory;
        let cmd = Cli::command();
        let serve_cmd = cmd.find_subcommand("serve").unwrap();
        let ssh_arg = serve_cmd
            .get_arguments()
            .find(|a| a.get_id() == "ssh_bind")
            .unwrap();
        assert_eq!(
            ssh_arg.get_env(),
            Some(std::ffi::OsStr::new("PREMIER_SSH_BIND"))
        );
    }

    #[test]
    fn load_optional_policy_compiles_server_policy_without_repo_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let srv_path = tmp.path().join("server.access.toml");
        std::fs::write(
            &srv_path,
            r#"
version = 1
[[rules]]
id = "server-hard-deny"
effect = "deny"
principals = ["*"]
paths = ["secrets/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#,
        )
        .unwrap();

        // Server policy alone MUST NOT fail-open to None.
        let compiled = load_optional_policy(None, Some(&srv_path))
            .unwrap()
            .unwrap();
        let id = DelegatedIdentity::human_only(Principal::parse("@alice").unwrap(), vec![]);
        let decision = compiled.explain(&id, &RepoPath::new("secrets/key.pem").unwrap(), "main");
        assert!(decision.effective.is_empty());

        // Both omitted yields None.
        assert!(load_optional_policy(None, None).unwrap().is_none());
    }

    #[test]
    fn agent_run_auto_loads_policy_and_allows_missing_default_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Missing default `.env.schema` falls back to empty schema.
        let empty = load_optional_schema(None, root).unwrap();
        assert!(empty.vars.is_empty());
        // Explicit missing `--schema` still errors.
        assert!(load_optional_schema(Some(&root.join("missing.schema")), root).is_err());

        // Absent `.access.toml` resolves to None; present `.access.toml` is auto-discovered.
        assert_eq!(resolve_agent_policy_path(None, root), None);
        std::fs::write(root.join(".access.toml"), "not valid toml [[[").unwrap();
        let discovered = resolve_agent_policy_path(None, root).unwrap();
        assert_eq!(discovered, root.join(".access.toml"));
        // Corrupt `.access.toml` fails closed!
        assert!(load_optional_policy(Some(&discovered), None).is_err());
    }

    #[test]
    fn trusted_proxies_canonicalizes_ipv4_mapped_ipv6() {
        let ips = parse_trusted_proxies(&["::ffff:172.28.0.2".to_owned()]).unwrap();
        assert_eq!(ips, vec!["172.28.0.2".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn env_set_supports_stdin_flag_without_positional_value() {
        let cli =
            Cli::try_parse_from(["premier", "env", "set", "STRIPE_API_KEY", "--stdin"]).unwrap();
        let Commands::Env {
            cmd: EnvCmd::Set {
                key, value, stdin, ..
            },
        } = cli.command
        else {
            panic!("not env set");
        };
        assert_eq!(key, "STRIPE_API_KEY");
        assert!(value.is_none());
        assert!(stdin);

        // Passing both positional value and --stdin is rejected.
        assert!(
            Cli::try_parse_from([
                "premier",
                "env",
                "set",
                "STRIPE_API_KEY",
                "raw-val",
                "--stdin",
            ])
            .is_err()
        );
    }

    #[test]
    fn policy_fingerprint_changes_when_server_policy_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_p = tmp.path().join(".access.toml");
        let srv_p = tmp.path().join("server.toml");
        std::fs::write(&repo_p, "version = 1\n").unwrap();
        std::fs::write(&srv_p, "version = 1\n# server rules\n").unwrap();

        let fp_repo_only = compute_policy_fingerprint(&repo_p, None).unwrap();
        let fp_with_srv = compute_policy_fingerprint(&repo_p, Some(&srv_p)).unwrap();
        assert_ne!(fp_repo_only, fp_with_srv);
    }

    #[test]
    fn gateway_refuses_auto_approve_jit_with_agent_profile() {
        assert!(validate_gateway_flags(true, Some("ui-agent")).is_err());
        assert!(validate_gateway_flags(true, None).is_ok());
        assert!(validate_gateway_flags(false, Some("ui-agent")).is_ok());
    }

    #[test]
    fn lifecycle_cli_flags_parse_cleanly() {
        let cli = Cli::try_parse_from([
            "premier",
            "__cage-exec",
            "--proxy-socket",
            "/tmp/p.sock",
            "--listen",
            "127.0.0.1:9",
            "--max-memory-mb",
            "512",
            "--max-pids",
            "64",
            "--max-cpu-secs",
            "30",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .unwrap();
        let Commands::CageExec {
            max_memory_mb,
            max_pids,
            max_cpu_secs,
            command,
            ..
        } = cli.command
        else {
            panic!("not cage-exec");
        };
        assert_eq!(
            (max_memory_mb, max_pids, max_cpu_secs),
            (Some(512), Some(64), Some(30))
        );
        assert_eq!(command, ["sh", "-c", "true"]);
        // The argv the server builds parses back to the same caps.
        let limits = ResourceLimits {
            max_memory_mb: Some(256),
            max_pids: None,
            max_cpu_secs: Some(5),
        };
        let mut argv = vec!["premier".to_owned()];
        argv.extend(
            premier_proxy::cage_exec_argv_with_limits("127.0.0.1:9".parse().unwrap(), &limits)
                .into_iter()
                .skip(1),
        );
        argv.push("true".to_owned());
        let Commands::CageExec {
            max_memory_mb,
            max_pids,
            max_cpu_secs,
            ..
        } = Cli::try_parse_from(argv).unwrap().command
        else {
            panic!("not cage-exec");
        };
        assert_eq!(
            (max_memory_mb, max_pids, max_cpu_secs),
            (Some(256), None, Some(5))
        );

        let cli = Cli::try_parse_from([
            "premier",
            "env",
            "rotate",
            "STRIPE_API_KEY",
            "--env",
            "prod",
            "--reason",
            "leak",
            "--json",
        ])
        .unwrap();
        let Commands::Env {
            cmd:
                EnvCmd::Rotate {
                    key,
                    env,
                    schema,
                    reason,
                    new_value,
                    json,
                },
        } = cli.command
        else {
            panic!("not env rotate");
        };
        assert_eq!(
            (key.as_str(), env.as_str(), reason.as_str()),
            ("STRIPE_API_KEY", "prod", "leak")
        );
        assert_eq!(schema, PathBuf::from(".env.schema"));
        assert!(new_value.is_none() && json);

        let cli = Cli::try_parse_from(["premier", "env", "kms-status", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Env {
                cmd: EnvCmd::KmsStatus { json: true, .. }
            }
        ));

        let cli = Cli::try_parse_from(["premier", "env", "kms", "status", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Env {
                cmd: EnvCmd::Kms {
                    cmd: KmsCmd::Status { json: true, .. }
                }
            }
        ));

        let cli = Cli::try_parse_from(["premier", "env", "kms", "migrate", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Env {
                cmd: EnvCmd::Kms {
                    cmd: KmsCmd::Migrate { json: true, .. }
                }
            }
        ));

        let cli = Cli::try_parse_from(["premier", "env", "kms", "rotate-dek", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Env {
                cmd: EnvCmd::Kms {
                    cmd: KmsCmd::RotateDek { json: true, .. }
                }
            }
        ));

        let cli = Cli::try_parse_from([
            "premier",
            "env",
            "oidc-token",
            "--principal",
            "@alice",
            "--group",
            "web",
            "--agent-profile",
            "ui-agent",
            "--aud",
            "vault",
            "--aud",
            "ci",
            "--ttl",
            "60",
        ])
        .unwrap();
        let Commands::Env {
            cmd:
                EnvCmd::OidcToken {
                    principal,
                    groups,
                    agent_profile,
                    audiences,
                    ttl,
                    policy,
                    ..
                },
        } = cli.command
        else {
            panic!("not env oidc-token");
        };
        assert_eq!(principal, "@alice");
        assert_eq!(groups, ["web"]);
        assert_eq!(agent_profile.as_deref(), Some("ui-agent"));
        assert_eq!(audiences, ["vault", "ci"]);
        assert_eq!(ttl, 60);
        assert_eq!(policy, PathBuf::from(".access.toml"));
        let cli = Cli::try_parse_from(["premier", "env", "oidc-token"]).unwrap();
        let Commands::Env {
            cmd: EnvCmd::OidcToken { principal, ttl, .. },
        } = cli.command
        else {
            panic!("not env oidc-token");
        };
        assert_eq!((principal.as_str(), ttl), ("@local", 300));

        let cli = Cli::try_parse_from([
            "premier",
            "--state-dir",
            "/srv/premier",
            "auth",
            "revoke",
            "@mia",
            "--delete",
            "--no-rotate",
        ])
        .unwrap();
        assert_eq!(cli.state_dir, Some(PathBuf::from("/srv/premier")));
        let Commands::Auth {
            cmd:
                AuthCmd::Revoke {
                    principal,
                    reason,
                    delete,
                    no_rotate,
                    env,
                    ..
                },
        } = cli.command
        else {
            panic!("not auth revoke");
        };
        assert_eq!(
            (principal.as_str(), reason.as_str()),
            ("@mia", "offboarded via CLI")
        );
        assert!(delete && no_rotate);
        assert_eq!(env, "prod");
    }

    #[tokio::test]
    async fn cli_kms_status_and_oidc_token_work_offline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let status = premier_server::lifecycle::kms_status(root, "acme/app").unwrap();
        assert_eq!(status.status.mode, "sovereign_age");
        assert!(status.status.kt_valid);
        let issuer = premier_server::lifecycle::load_oidc_issuer(root, true);
        let token = issuer
            .issue(WorkloadTokenRequest {
                sub: "@alice".to_owned(),
                aud: vec!["premier".to_owned()],
                ..Default::default()
            })
            .unwrap();
        let reloaded = premier_server::lifecycle::load_oidc_issuer(root, false);
        assert_eq!(
            reloaded.verify(&token.token, "premier").unwrap().sub,
            "@alice"
        );
    }

    #[test]
    fn cli_env_kms_migrate_and_rotate_dek_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut st = premier_server::store::load_state(root).unwrap();
        premier_server::store::set_workspace_secret(
            root,
            "acme/app",
            "dev",
            "TOKEN",
            "secret_val",
            &mut st,
        )
        .unwrap();
        let (migrated, already) =
            premier_server::lifecycle::migrate_to_envelope(root, "acme/app", CLI_ACTOR).unwrap();
        assert_eq!(migrated, 1);
        assert!(!already);
        let ver = premier_server::lifecycle::rotate_workspace_dek(root, "acme/app").unwrap();
        assert_eq!(ver, 2);
        let status = premier_server::lifecycle::kms_status(root, "acme/app").unwrap();
        assert_eq!(status.status.mode, "envelope");
        assert_eq!(status.status.dek_version, 2);
        assert!(status.status.kt_valid);
    }
}
