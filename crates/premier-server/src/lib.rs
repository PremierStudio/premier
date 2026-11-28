//! `premier-server` — Axum control-plane daemon powering Premier Studio UI,
//! persistent workspace state, live SSE audit/JIT/session streaming, Zone X-Ray,
//! ACL-scoped search & blame, encrypted age vault, and Reversible Git Smart HTTP v2.

pub mod auth;
mod canon;
pub mod directory;
pub mod firewall;
pub mod github;
pub mod handlers_v1;
pub mod hygiene;
pub mod lanes;
pub mod lifecycle;
pub mod mcp_gateway;
pub mod ops;
pub mod policy_learning;
pub mod repos;
pub mod runner;
pub mod ssh;
pub mod store;
pub mod telemetry;
pub mod traces;
pub mod worktable;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod firewall_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod github_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod lane_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod publish_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod security_tests;

mod db;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive};
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{MethodRouter, delete, get, patch, post, put};
use axum::{Extension, Json, Router};
use http_body_util::BodyExt;
use premier_core::{
    AuditDecision, AuditEvent, Capability, DelegatedIdentity, Environment, Principal, Readiness,
    RepoPath, Visibility,
};
use premier_git_bridge::{
    CanonicalGitRepo, ProjectionAttestation, handle_upload_pack_v2, project_repository,
};
use premier_overlay::{
    OverlayGuard, OverlayListResponse, OverlayManifest, OverlayRecord, OverlayStore,
};
use premier_policy::{
    AccessImpactDiff, AccessPolicyFile, CompiledPolicy, ExplainDecision, MatchedRuleTrace,
    PolicyIntent, PolicyLayer, RuleEffect, SecretProbe, apply_policy_intent, compute_access_diff,
    compute_secret_use_deltas, parse_policy_toml, sha256_hex,
};
use premier_proxy::{ApprovalHub, AuditSink, HostSandboxCapabilities, PendingApproval};
use premier_secrets::{EnvSchema, ValidationReport};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};
use tracing::Instrument;

use crate::runner::SessionManager;
use crate::store::{PersistedState, ReviewComment, StoredReview, load_state, save_state};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("bind/serve error: {0}")]
    Io(String),
}

/// Branch record combining live Git metadata with Premier orthogonal Visibility & Readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    pub name: String,
    pub head_oid: String,
    pub subject: String,
    pub visibility: Visibility,
    pub readiness: Readiness,
    pub is_current: bool,
    pub ahead_commits: usize,
    pub private_paths_touched: Vec<String>,
}

/// Shared state mounted on the Axum control-plane router.
#[derive(Clone)]
pub struct ServerState {
    pub workspace_root: PathBuf,
    pub policy: Arc<RwLock<Option<Arc<CompiledPolicy>>>>,
    pub repo_policy_path: Option<PathBuf>,
    pub repo_policy_file: Arc<RwLock<Option<Arc<AccessPolicyFile>>>>,
    pub repo_policy_toml: Arc<RwLock<Option<String>>>,
    pub server_policy_toml: Option<String>,
    /// Where the server policy was read from, so a backup can carry it when it is a workspace file.
    pub server_policy_path: Option<PathBuf>,
    /// From the default branch tip, like the policy ([`Self::reload_repo_config`]).
    pub env_schema: Arc<RwLock<Option<Arc<EnvSchema>>>>,
    pub audit_sink: Arc<AuditSink>,
    pub(crate) metrics: Arc<RuntimeMetrics>,
    readiness_probe: Arc<tokio::sync::Mutex<Option<(Instant, ReadinessProbe)>>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    pub approval_hub: Arc<ApprovalHub>,
    pub trace_store: Arc<premier_trace::TraceStore>,
    pub persisted: Arc<Mutex<PersistedState>>,
    pub session_manager: Arc<SessionManager>,
    pub static_ui_dir: Option<PathBuf>,
    pub auth: Arc<auth::AuthStore>,
    /// Reverse proxies (by TCP peer address) whose `X-Forwarded-*` headers are believed.
    pub trusted_proxies: Arc<Vec<IpAddr>>,
    /// Set on every repository except the default one: the account state they all share.
    pub account: Option<Arc<repos::Account>>,
    /// This repository's background jobs ([`ops::spawn_background`]), aborted by [`Self::stop`].
    pub jobs: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    /// `--allow-unsandboxed-agents`: run agent sessions as a plain process of the server user
    /// when this host has no working sandbox, instead of refusing them.
    pub allow_unsandboxed_agents: bool,
    /// `--allow-private-imports`: let repository imports fetch from private/CGNAT/ULA addresses.
    pub allow_private_imports: bool,
    /// Where the other repositories live (set by [`repos::Registry::open`]); hidden from agents.
    pub repos_dir: Option<PathBuf>,
    /// Optional address to bind the pure-Rust Git-over-SSH server (`--ssh-bind` / `PREMIER_SSH_BIND`).
    pub ssh_bind: Option<SocketAddr>,
    /// SSH clone base clients should show, e.g. `ssh://git@host:7429` (`--ssh-public-url` /
    /// `PREMIER_SSH_PUBLIC_URL`): behind Docker or NAT the bound port is not the published one.
    pub ssh_public_url: Option<String>,
    /// Tool-definition pins and drift alerts of the MCP gateway (`.premier/mcp-pins.json`).
    pub mcp_pins: Arc<premier_proxy::ToolPinRegistry>,
    /// `--allow-loopback-mcp`: let `http_sse` MCP servers live on loopback (development, tests).
    pub allow_loopback_mcp: bool,
    /// Keyless OIDC workload token issuer, shared by every repository (like `auth`).
    pub oidc_issuer: Arc<premier_secrets::OidcTokenIssuer>,
    /// Sends signed dual-phase secret rotation webhooks.
    pub rotation_dispatcher: Arc<premier_secrets::RotationDispatcher>,
    /// Weak pointer back to the enclosing multi-repo registry when opened via [`repos::Registry::open`].
    pub(crate) repo_registry: Arc<RwLock<Option<repos::RegistryHandle>>>,
    /// Lane created/updated/conflicted events of this repository.
    pub lane_tx: tokio::sync::broadcast::Sender<store::AgentLane>,
    /// Review round/lane-link events of this repository.
    pub review_tx: tokio::sync::broadcast::Sender<ReviewEvent>,
    /// GitHub Enterprise hosts an owner may connect the GitHub companion to (github.com always).
    pub github_enterprise_hosts: Arc<Vec<String>>,
    /// Tests only: a local bare remote and a plain-HTTP mock API instead of GitHub. Never set
    /// from a request or a flag.
    #[doc(hidden)]
    pub github_test_override: Option<Arc<github::GithubTestOverride>>,
}

/// A review of this repository changed (new round, lane linked or conflicted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewEvent {
    pub change_id: String,
    pub visibility: Visibility,
    pub kind: String,
    pub latest_round: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<String>,
}

fn default_rotation_dispatcher() -> premier_secrets::RotationDispatcher {
    let allowed_hosts = std::env::var("PREMIER_ROTATION_ALLOWED_HOSTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    premier_secrets::RotationDispatcher {
        allowed_hosts,
        ..Default::default()
    }
}

/// What a ref nobody declared a visibility for gets. The bridge owns the rule, so the API and the
/// Git projection cannot disagree.
pub(crate) use premier_git_bridge::{PRIVATE_REF_PREFIX, default_ref_visibility};

impl ServerState {
    pub fn try_minimal(
        policy: Option<Arc<CompiledPolicy>>,
        env_schema: Option<Arc<EnvSchema>>,
        audit_sink: Arc<AuditSink>,
    ) -> Result<Self, String> {
        let workspace_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // `PREMIER_STATIC_UI_DIR` (the Studio build baked into the Docker image) wins; otherwise the
        // in-workspace build, as before.
        let static_ui_dir = std::env::var_os("PREMIER_STATIC_UI_DIR")
            .map(PathBuf::from)
            .into_iter()
            .chain([workspace_root.join("apps/web/dist")])
            .find(|dir| dir.join("index.html").exists());
        let persisted = load_state(&workspace_root)?;
        let mcp_pins = Arc::new(mcp_gateway::load_pins(&workspace_root));
        let trace_store = Arc::new(premier_trace::TraceStore::new(
            Some(store::traces_path(&workspace_root)),
            premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
        ));
        let session_manager = Arc::new(
            SessionManager::open(&workspace_root).with_trace_store(Arc::clone(&trace_store)),
        );
        let oidc_root = workspace_root.clone();
        Ok(Self {
            auth: Arc::new(auth::AuthStore::open(&workspace_root)),
            approval_hub: Arc::new(ops::load_approvals(&workspace_root)),
            trace_store,
            session_manager,
            workspace_root,
            policy: Arc::new(RwLock::new(policy)),
            repo_policy_path: None,
            repo_policy_file: Arc::new(RwLock::new(None)),
            repo_policy_toml: Arc::new(RwLock::new(None)),
            server_policy_toml: None,
            server_policy_path: None,
            jobs: Arc::default(),
            env_schema: Arc::new(RwLock::new(env_schema)),
            audit_sink,
            metrics: Arc::new(RuntimeMetrics::new()),
            readiness_probe: Arc::default(),
            shutdown: tokio::sync::watch::channel(false).0,
            persisted: Arc::new(Mutex::new(persisted)),
            static_ui_dir,
            trusted_proxies: Arc::default(),
            account: None,
            allow_unsandboxed_agents: false,
            allow_private_imports: false,
            repos_dir: None,
            ssh_bind: None,
            ssh_public_url: None,
            mcp_pins,
            allow_loopback_mcp: false,
            // Never creates the account directory here; `serve` persists a fresh key.
            oidc_issuer: Arc::new(lifecycle::load_oidc_issuer(&oidc_root, false)),
            rotation_dispatcher: Arc::new(default_rotation_dispatcher()),
            repo_registry: Arc::default(),
            lane_tx: tokio::sync::broadcast::channel(128).0,
            review_tx: tokio::sync::broadcast::channel(128).0,
            github_enterprise_hosts: Arc::default(),
            github_test_override: None,
        })
    }

    pub fn minimal(
        policy: Option<Arc<CompiledPolicy>>,
        env_schema: Option<Arc<EnvSchema>>,
        audit_sink: Arc<AuditSink>,
    ) -> Self {
        Self::try_minimal(policy, env_schema, audit_sink)
            .unwrap_or_else(|e| panic!("failed to load workspace state: {e}"))
    }

    /// Every repository state loaded in this server's registry (or `[self]` for single-repo states).
    pub fn all_repo_states(&self) -> Vec<ServerState> {
        self.repo_registry
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(repos::RegistryHandle::states))
            .unwrap_or_else(|| vec![self.clone()])
    }

    /// Workspace whose `.premier/` holds the accounts, directory and repository list: the
    /// default repository's, shared by every other repository.
    pub fn account_root(&self) -> &Path {
        self.account
            .as_ref()
            .map_or(&self.workspace_root, |a| &a.root)
    }

    /// State holding the server-wide settings (the default repository's).
    pub fn settings_state(&self) -> &Arc<Mutex<PersistedState>> {
        self.account
            .as_ref()
            .map_or(&self.persisted, |a| &a.persisted)
    }

    /// Stop everything running on behalf of this repository (it is being deleted): background
    /// jobs and caged agent sessions.
    pub async fn stop(&self) {
        self.stop_background_jobs();
        self.session_manager.stop_all().await;
    }

    fn stop_background_jobs(&self) {
        let jobs = self
            .jobs
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        for job in jobs {
            job.abort();
        }
    }

    pub fn current_policy(&self) -> Option<Arc<CompiledPolicy>> {
        self.policy.read().ok().and_then(|g| g.clone())
    }

    pub fn current_repo_policy_toml(&self) -> String {
        self.repo_policy_toml
            .read()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn current_repo_policy_file(&self) -> Option<Arc<AccessPolicyFile>> {
        self.repo_policy_file.read().ok().and_then(|g| g.clone())
    }

    pub fn set_repo_policy_metadata(
        &self,
        toml: Option<String>,
        file: Option<Arc<AccessPolicyFile>>,
    ) {
        if let Ok(mut g) = self.repo_policy_toml.write() {
            *g = toml;
        }
        if let Ok(mut g) = self.repo_policy_file.write() {
            *g = file;
        }
    }

    pub fn replace_repo_policy(
        &self,
        compiled: Arc<CompiledPolicy>,
        file: Arc<AccessPolicyFile>,
        toml: String,
    ) {
        if let Ok(mut g) = self.policy.write() {
            *g = Some(compiled);
        }
        if let Ok(mut g) = self.repo_policy_file.write() {
            *g = Some(file);
        }
        if let Ok(mut g) = self.repo_policy_toml.write() {
            *g = Some(toml);
        }
    }

    /// Declared branch metadata, keyed by full ref name (see [`store::full_ref_metadata`]).
    pub fn branch_metadata(&self) -> BTreeMap<String, (Visibility, Readiness)> {
        self.persisted
            .lock()
            .map(|st| store::full_ref_metadata(&st.branch_metadata))
            .unwrap_or_default()
    }

    /// Declared visibility per full ref name.
    pub fn branch_visibility_map(&self) -> HashMap<String, Visibility> {
        self.branch_metadata()
            .into_iter()
            .map(|(k, (v, _))| (k, v))
            .collect()
    }

    /// Visibility of `full_ref`: declared, or [`default_ref_visibility`].
    pub fn ref_visibility(&self, full_ref: &str) -> Visibility {
        self.branch_visibility_map()
            .remove(full_ref)
            .unwrap_or_else(|| default_ref_visibility(full_ref))
    }

    /// Short (16-hex-char) SHA-256 fingerprint of the active repo policy TOML, normalized
    /// consistently across HTTP v2, SSH, attestations, and publish (`b"default"` when empty).
    pub(crate) fn policy_fingerprint(&self) -> String {
        let toml = self.current_repo_policy_toml();
        let fp = sha256_hex(if toml.is_empty() {
            b"default"
        } else {
            toml.as_bytes()
        });
        fp[..16].to_owned()
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    /// Only for an authenticated caller: `/health` itself is public.
    #[serde(flatten)]
    details: Option<HealthDetails>,
}

#[derive(Debug, Serialize)]
struct HealthDetails {
    /// `bwrap`, `none` (agent sessions are refused) or `unsandboxed-allowed`.
    agent_sandbox: &'static str,
    /// Whether the built-in Git-over-SSH server is enabled, and its port if bound.
    ssh_enabled: bool,
    ssh_port: Option<u16>,
    /// The host's layout and sandbox internals: an owner's only.
    #[serde(flatten)]
    host: Option<HostHealth>,
}

#[derive(Debug, Serialize)]
struct HostHealth {
    os: &'static str,
    workspace_root: String,
    policy_loaded: bool,
    server_policy_loaded: bool,
    schema_loaded: bool,
    host_capabilities: HostSandboxCapabilities,
    /// Why it is not `bwrap`, or what is weaker than usual about it; empty when nothing is.
    agent_sandbox_detail: String,
}

#[derive(Debug, Serialize)]
struct PolicySummaryResponse {
    policy_loaded: bool,
    server_policy_loaded: bool,
    /// Owner view: the policy text shown came with an import and is not enforced until saved.
    imported_policy_pending: bool,
    repo_policy_toml: String,
    server_policy_toml: String,
    policy: Option<AccessPolicyFile>,
}

#[derive(Debug, Deserialize)]
pub struct ExplainRequest {
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default)]
    pub agent_task_id: Option<String>,
    pub path: String,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub ref_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepoTreeQuery {
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    /// Branch to read; left out, the one that is checked out.
    #[serde(default)]
    pub ref_name: Option<String>,
    #[serde(default)]
    pub xray: bool,
}

/// A request that names no principal is evaluated as the authenticated caller. Extractors run
/// inside the auth gate's task-local scope, so the caller is known at deserialisation time.
/// Requests may still send a `groups` field; it is ignored (membership is the directory's).
fn default_principal() -> String {
    auth::actor_principal()
}

#[derive(Debug, Serialize)]
struct RepoTreeEntry {
    path: String,
    kind: &'static str,
    visibility_state: &'static str,
    effective: Vec<String>,
    human_effective: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_effective: Option<Vec<String>>,
    synthesized_traverse: bool,
    is_instruction_file: bool,
    matched_rules: Vec<MatchedRuleTrace>,
}

#[derive(Debug, Serialize)]
struct RepoTreeResponse {
    principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_profile: Option<String>,
    ref_name: String,
    xray: bool,
    visible_count: usize,
    traverse_only_count: usize,
    omitted_count: usize,
    entries: Vec<RepoTreeEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AccessDiffRequest {
    pub base_toml: String,
    pub head_toml: String,
    #[serde(default)]
    pub server_toml: Option<String>,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub changed_files: Vec<ChangedFileInput>,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub ref_name: Option<String>,
    /// Also diff every authenticated human delegating to every declared agent profile.
    #[serde(default)]
    pub include_agent_profiles: bool,
    /// Secrets whose `use` to diff for every identity.
    #[serde(default)]
    pub secret_probes: Vec<SecretProbeInput>,
}

/// `{ var_name, zone? }`: same wire shape as the mutator's probes.
pub type SecretProbeInput = SecretProbe;

#[derive(Debug, Deserialize)]
pub struct ChangedFileInput {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SchemaDashboardQuery {
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    agent_profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct SchemaDashboardResponse {
    /// `null` when the repository has no `.env.schema`.
    schema: Option<EnvSchema>,
    reports: BTreeMap<String, ValidationReport>,
    /// Truthful per-variable `Capability::USE` decision evaluated via `CompiledPolicy::can_use_secret`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    can_use: BTreeMap<String, bool>,
}

#[derive(Debug, Deserialize)]
pub struct DecideApprovalRequest {
    pub approved: bool,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub grant_scope: Option<premier_proxy::GrantScope>,
    #[serde(default)]
    pub denial_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OverlayCheckRequest {
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OverlayCheckResponse {
    allowed: bool,
    blocked_paths: Vec<String>,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBranchVisibilityRequest {
    pub branch: String,
    pub visibility: Visibility,
    pub readiness: Readiness,
}

#[derive(Debug, Deserialize)]
pub struct SquashPreviewRequest {
    pub branch: String,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub target_branch: Option<String>,
    #[serde(default)]
    pub summary_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct SquashPreviewResponse {
    source_branch: String,
    target_branch: String,
    private_commits_collapsed: usize,
    /// Paths a publish would add, change or delete on the target.
    published_paths: Vec<String>,
    /// Paths the branch changed that a publish leaves out (the target keeps its own version).
    scrubbed_paths: Vec<String>,
    /// Paths cleanly auto-merged by line-level 3-way merge.
    #[serde(default)]
    merged_paths: Vec<String>,
    /// Published paths the target changed too since the branches forked: a publish is refused
    /// (409) while there are any.
    conflicts: Vec<String>,
    /// Conflicting paths the caller may not list.
    hidden_conflicts: usize,
    /// Published paths that would carry the content of a restricted file: a publish is refused
    /// (409) while there are any.
    blocked: Vec<String>,
    /// Such paths the caller may not list.
    hidden_blocked: usize,
    /// A publish by an owner would go through. Never for a member: publishing is an owner's call.
    declassification_gate_passed: bool,
    /// Why not, in a sentence (one per blocking cause); absent when the gate passes.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// The rule that decides what is held back ([`PUBLISH_RULE`]).
    publish_rule: &'static str,
    /// For each of `scrubbed_paths`, why it is held back.
    held_back_reasons: BTreeMap<String, &'static str>,
    attestation: ProjectionAttestation,
    attestation_trailer: String,
    clean_commit_message: String,
    /// The declassification firewall's report on this publish (redacted for a member).
    #[serde(skip_serializing_if = "Option::is_none")]
    declassification_report: Option<premier_policy::DeclassificationReport>,
    /// The Declassification Airlock detail: an owner's only. A member always gets
    /// [`Airlock::default`], whatever the branch holds.
    #[serde(flatten)]
    airlock: Airlock,
}

/// What an owner reviews before a publish, beyond what every caller gets.
#[derive(Debug, Default, Serialize)]
struct Airlock {
    /// Commits a publish would collapse that changed at least one publishable path.
    public_commits_collapsed: usize,
    /// The newest of the commits a publish would collapse ([`MAX_COLLAPSED_COMMITS`]).
    collapsed_commits: Vec<CollapsedCommitInfo>,
    source_head_oid: Option<String>,
    target_head_oid: Option<String>,
    /// Full canonical OIDs reviewed in this preview, for compare-and-swap on publish.
    source_commit_oid: Option<String>,
    target_commit_oid: Option<String>,
    /// Published paths whose content is a clean 3-way merge of both sides.
    three_way_merged_paths: Vec<String>,
    /// Published paths that are instruction files (`[quarantine]`).
    quarantine_paths: Vec<String>,
    /// Published paths that are team or personal overlay files: a publish is refused.
    overlay_blocked_paths: Vec<String>,
    /// For each scrubbed path, the rule (or the default) that holds it back.
    held_back_rules: BTreeMap<String, HeldBackRuleInfo>,
    /// Zones of the held-back paths, and zones the anonymous public is denied on the target.
    restricted_zones: Vec<String>,
    /// The diff a publish would land, public paths only.
    public_diff: Vec<PublicDiffFile>,
    /// Files or a patch were left out of `public_diff` for size.
    public_diff_truncated: bool,
}

#[derive(Debug, Serialize)]
struct PublicDiffFile {
    path: String,
    /// `added`, `modified` or `deleted`.
    kind: &'static str,
    old_mode: Option<String>,
    new_mode: Option<String>,
    three_way_merged: bool,
    is_instruction_file: bool,
    binary: bool,
    truncated: bool,
    additions: usize,
    deletions: usize,
    patch: String,
}

#[derive(Debug, Serialize)]
struct HeldBackRuleInfo {
    reason: String,
    rule_id: Option<String>,
    layer: Option<PolicyLayer>,
    zones: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CollapsedCommitInfo {
    short_oid: String,
    subject: String,
    touches_public: bool,
}

const MAX_COLLAPSED_COMMITS: usize = 30;
const MAX_PREVIEW_DIFF_FILES: usize = 50;
const MAX_PREVIEW_DIFF_FILE_BYTES: usize = 256 * 1024;
const MAX_PREVIEW_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_PREVIEW_PATCH_BYTES: usize = 32_768;

/// Published paths that an overlay (team or personal file) covers: what
/// `execute_squash_declassify` refuses. Deletions are not written, so not checked.
fn overlay_blocked_paths(
    guard: &OverlayGuard,
    plan: &premier_git_bridge::SquashPlan,
) -> Vec<String> {
    let written: Vec<RepoPath> = plan
        .changes
        .iter()
        .filter(|(_, entry)| entry.is_some())
        .filter_map(|(path, _)| RepoPath::new(path).ok())
        .collect();
    match guard.validate_public_paths(&written) {
        Err(premier_overlay::OverlayError::LeakBlocked { mut paths }) => {
            paths.sort();
            paths.dedup();
            paths
        }
        _ => Vec::new(),
    }
}

/// Why the scrub rule holds `path` back on `ref_name`: the strongest deny rule that takes the
/// anonymous public's `read` on it (or its entry into a directory above it), else the default.
fn held_back_rule(policy: &CompiledPolicy, ref_name: &str, path: &str) -> HeldBackRuleInfo {
    let zones = RepoPath::new(path)
        .map(|rp| policy.matching_zones(&rp))
        .unwrap_or_default();
    let default_deny = |reason: String, zones: Vec<String>| HeldBackRuleInfo {
        reason,
        rule_id: None,
        layer: None,
        zones,
    };
    if path
        .split('/')
        .any(premier_git_bridge::is_reserved_path_component)
    {
        return default_deny(
            "Path contains a reserved server component (.git, .premier, or filesystem alias)"
                .to_owned(),
            zones,
        );
    }
    let public = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
    let enter = Capability::TRAVERSE | Capability::LIST | Capability::READ;
    // The path itself needs `read`; every directory above it one of `enter` (as `publishable`).
    let checks = std::iter::once((path, Capability::READ)).chain(
        path.match_indices('/')
            .map(|(end, _)| (&path[..end], enter)),
    );
    for (at, needed) in checks {
        let Ok(rp) = RepoPath::new(at) else { continue };
        let decision = policy.explain(&public, &rp, ref_name);
        if decision.effective.intersects(needed) {
            continue;
        }
        let names = needed.to_names();
        let deny = |layer| {
            decision.matched_rules.iter().find(|r| {
                r.layer == layer
                    && r.effect == RuleEffect::Deny
                    && r.capabilities.iter().any(|c| names.contains(&c.as_str()))
            })
        };
        return match deny(PolicyLayer::Server).or_else(|| deny(PolicyLayer::Repo)) {
            Some(r) => HeldBackRuleInfo {
                reason: r.reason.clone().unwrap_or_else(|| {
                    let layer = match r.layer {
                        PolicyLayer::Server => "server",
                        PolicyLayer::Repo => "repo",
                    };
                    format!("Denied by {layer} rule '{}'", r.id)
                }),
                rule_id: Some(r.id.clone()),
                layer: Some(r.layer),
                zones,
            },
            None if at == path => default_deny(
                "No allow rule grants anonymous read (default deny)".to_owned(),
                zones,
            ),
            None => default_deny(
                format!("No allow rule lets anonymous visitors enter '{at}' (default deny)"),
                zones,
            ),
        };
    }
    default_deny(
        "No allow rule grants anonymous read (default deny)".to_owned(),
        zones,
    )
}

/// The newest commits of `range` ([`MAX_COLLAPSED_COMMITS`]), each with whether it changed a
/// publishable path.
fn collapsed_commits(
    root: &Path,
    policy: &CompiledPolicy,
    ref_name: &str,
    range: &str,
) -> Vec<CollapsedCommitInfo> {
    let max = format!("--max-count={MAX_COLLAPSED_COMMITS}");
    let args = [
        "log",
        "--no-renames",
        max.as_str(),
        "--format=%x01%h%x00%s",
        "--name-only",
        "-z",
        "--end-of-options",
        range,
    ];
    let Some(log) = repos::git_out(root, &args) else {
        return Vec::new();
    };
    // `\x01<short>\0<subject>\0`, then `\n<path>\0` per changed path.
    log.split('\u{1}')
        .skip(1)
        .filter_map(|commit| {
            let (short_oid, rest) = commit.split_once('\0')?;
            let (subject, names) = rest.split_once('\0').unwrap_or((rest, ""));
            let touches_public = names
                .split(['\0', '\n'])
                .filter(|p| !p.is_empty())
                .any(|p| premier_git_bridge::publishable(policy, ref_name, p));
            Some(CollapsedCommitInfo {
                short_oid: short_oid.to_owned(),
                subject: subject.to_owned(),
                touches_public,
            })
        })
        .collect()
}

fn preview_blob_sizes(
    root: &Path,
    oids: &BTreeSet<&str>,
) -> Result<HashMap<String, usize>, premier_git_bridge::GitBridgeError> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut out_map = HashMap::new();
    if oids.is_empty() {
        return Ok(out_map);
    }
    let input: String = oids.iter().map(|oid| format!("{oid}\n")).collect();
    let mut child = premier_git_bridge::git_command(root)
        .args(["cat-file", "--batch-check=%(objectname) %(objectsize)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| premier_git_bridge::GitBridgeError::Io(format!("git cat-file: {e}")))?;
    let written = child
        .stdin
        .take()
        .map_or(Ok(()), |mut pipe| pipe.write_all(input.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|e| premier_git_bridge::GitBridgeError::Io(format!("git cat-file: {e}")))?;
    written.map_err(|e| premier_git_bridge::GitBridgeError::Io(format!("git cat-file: {e}")))?;
    if !output.status.success() {
        return Err(premier_git_bridge::GitBridgeError::Io(
            "git cat-file --batch-check failed".to_owned(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some((oid, size_str)) = line.split_once(' ')
            && let Ok(size) = size_str.parse::<usize>()
        {
            out_map.insert(oid.to_owned(), size);
        } else {
            return Err(premier_git_bridge::GitBridgeError::GitObject(
                "unreadable git cat-file output".to_owned(),
            ));
        }
    }
    Ok(out_map)
}

/// The unified diff a publish would land, for public paths only: never a scrubbed, blocked or
/// conflicting path (none of them is in `plan.changes`), nor an overlay-blocked one.
fn public_diff(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    ref_name: &str,
    plan: &premier_git_bridge::SquashPlan,
    overlay_blocked: &[String],
) -> Result<(Vec<PublicDiffFile>, bool), premier_git_bridge::GitBridgeError> {
    let mut selected = Vec::new();
    let mut truncated_any = false;
    for (path, entry) in plan.changes.iter().filter(|(path, _)| {
        premier_git_bridge::publishable(policy, ref_name, path) && !overlay_blocked.contains(path)
    }) {
        if selected.len() == MAX_PREVIEW_DIFF_FILES {
            truncated_any = true;
            break;
        }
        selected.push((path, entry));
    }

    let mut oids_to_stat = BTreeSet::new();
    for (path, entry) in &selected {
        if let Some((mode, oid)) = plan.target_before.get(*path)
            && mode != "160000"
        {
            oids_to_stat.insert(oid.as_str());
        }
        if let Some((mode, oid)) = entry
            && !plan.merged_blobs.contains_key(*path)
            && mode != "160000"
        {
            oids_to_stat.insert(oid.as_str());
        }
    }
    let sizes = preview_blob_sizes(canonical.root(), &oids_to_stat)?;

    let read_blob =
        |mode: &str, oid: &str| -> Result<Vec<u8>, premier_git_bridge::GitBridgeError> {
            if mode == "160000" {
                Ok(format!("Subproject commit {oid}\n").into_bytes())
            } else {
                Ok(canonical.read_object(oid)?.data.to_vec())
            }
        };
    let stat_size = |mode: &str, oid: &str| -> usize {
        if mode == "160000" {
            19 + oid.len()
        } else {
            sizes.get(oid).copied().unwrap_or(usize::MAX)
        }
    };

    let mut files = Vec::with_capacity(selected.len());
    let mut total_read_bytes = 0usize;
    for (path, entry) in selected {
        let before = plan.target_before.get(path);
        let kind = match (entry, before) {
            (None, _) => "deleted",
            (Some(_), Some(_)) => "modified",
            (Some(_), None) => "added",
        };
        let old_mode = before.map(|(m, _)| m.clone());
        let new_mode = entry.as_ref().map(|(m, _)| m.clone());

        let old_est = before.map_or(0, |(mode, oid)| stat_size(mode, oid));
        let new_est = match (entry, plan.merged_blobs.get(path)) {
            (None, _) => 0,
            (Some(_), Some(merged)) => merged.len(),
            (Some((mode, oid)), None) => stat_size(mode, oid),
        };
        let est_sum = old_est.saturating_add(new_est);
        let size_exceeded = old_est > MAX_PREVIEW_DIFF_FILE_BYTES
            || new_est > MAX_PREVIEW_DIFF_FILE_BYTES
            || total_read_bytes.saturating_add(est_sum) > MAX_PREVIEW_TOTAL_BYTES;

        let (binary, truncated, patch, additions, deletions) = if size_exceeded {
            (false, true, String::new(), 0, 0)
        } else {
            let old_bytes = match before {
                Some((mode, oid)) => read_blob(mode, oid)?,
                None => Vec::new(),
            };
            let new_bytes = match (entry, plan.merged_blobs.get(path)) {
                (None, _) => Vec::new(),
                (Some(_), Some(merged)) => merged.clone(),
                (Some((mode, oid)), None) => read_blob(mode, oid)?,
            };
            total_read_bytes = total_read_bytes
                .saturating_add(old_bytes.len())
                .saturating_add(new_bytes.len());
            let binary = runner::is_binary_bytes(&old_bytes) || runner::is_binary_bytes(&new_bytes);
            if binary {
                (true, false, String::new(), 0, 0)
            } else {
                let mut patch = runner::unified_diff(
                    path,
                    kind,
                    &String::from_utf8_lossy(&old_bytes),
                    &String::from_utf8_lossy(&new_bytes),
                );
                let (mut additions, mut deletions) = (0, 0);
                // Past the `---`/`+++` header, a line's first byte is its op.
                for line in patch.lines().skip(2) {
                    match line.as_bytes().first() {
                        Some(b'+') => additions += 1,
                        Some(b'-') => deletions += 1,
                        _ => {}
                    }
                }
                let mut truncated = false;
                if patch.len() > MAX_PREVIEW_PATCH_BYTES {
                    let mut end = MAX_PREVIEW_PATCH_BYTES;
                    while !patch.is_char_boundary(end) {
                        end -= 1;
                    }
                    patch.truncate(end);
                    patch.push_str("\n... (truncated)");
                    truncated = true;
                }
                (false, truncated, patch, additions, deletions)
            }
        };
        truncated_any |= truncated;
        files.push(PublicDiffFile {
            path: path.clone(),
            kind,
            old_mode,
            new_mode,
            three_way_merged: plan.merged_blobs.contains_key(path),
            is_instruction_file: RepoPath::new(path)
                .is_ok_and(|rp| policy.is_instruction_file(&rp)),
            binary,
            truncated,
            additions,
            deletions,
            patch,
        });
    }
    Ok((files, truncated_any))
}

/// The airlock detail of a preview. Owners only: it names hidden commits, zones and rules.
fn owner_airlock(
    root: &Path,
    policy: &CompiledPolicy,
    ref_name: &str,
    plan: &premier_git_bridge::SquashPlan,
    overlay_blocked: Vec<String>,
    (source_oid, target_tip, range): (&str, Option<&str>, &str),
) -> Airlock {
    let canonical = CanonicalGitRepo::open(root);
    let (public_diff, public_diff_truncated) =
        public_diff(&canonical, policy, ref_name, plan, &overlay_blocked)
            .unwrap_or_else(|_| (Vec::new(), true));
    let zones_of = |path: &String| {
        RepoPath::new(path)
            .map(|rp| policy.matching_zones(&rp))
            .unwrap_or_default()
    };
    let restricted_zones: BTreeSet<String> = plan
        .scrubbed_paths
        .iter()
        .chain(&plan.blocked)
        .flat_map(zones_of)
        .chain(policy.anonymous_denied_zones(ref_name))
        .collect();
    let short = |oid: &str| oid.chars().take(10).collect::<String>();
    Airlock {
        public_commits_collapsed: plan.source_commits_public,
        collapsed_commits: collapsed_commits(root, policy, ref_name, range),
        source_head_oid: Some(short(source_oid)),
        target_head_oid: target_tip.map(short),
        source_commit_oid: Some(source_oid.to_owned()),
        target_commit_oid: target_tip.map(str::to_owned),
        three_way_merged_paths: plan.merged_blobs.keys().cloned().collect(),
        quarantine_paths: plan
            .changes
            .iter()
            .map(|(path, _)| path)
            .filter(|path| {
                premier_git_bridge::publishable(policy, ref_name, path)
                    && RepoPath::new(path.as_str()).is_ok_and(|rp| policy.is_instruction_file(&rp))
            })
            .cloned()
            .collect(),
        overlay_blocked_paths: overlay_blocked,
        held_back_rules: plan
            .scrubbed_paths
            .iter()
            .map(|path| (path.clone(), held_back_rule(policy, ref_name, path)))
            .collect(),
        restricted_zones: restricted_zones.into_iter().collect(),
        public_diff,
        public_diff_truncated,
    }
}

/// What a publish leaves out, as shown next to a preview.
const PUBLISH_RULE: &str = "A path is published only if anonymous may read it.";

#[derive(Debug, Default, Serialize)]
pub struct ApiError {
    pub(crate) error: String,
    /// A refused publish (409): the conflicting paths the caller may list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) conflicts: Vec<String>,
    /// ... and how many more there are.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hidden_conflicts: Option<u32>,
    /// A refused publish (409): the public paths that would carry restricted content, as far as
    /// the caller may list them, and how many more there are.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) blocked: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hidden_blocked: Option<u32>,
    /// A refused GitHub sync-in (403): the upstream changes policy does not let in.
    /// Boxed (8 bytes): every handler returns this by value, and a bare `Vec` would push it
    /// past clippy's `result_large_err` limit crate-wide.
    #[allow(clippy::box_collection)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_violations: Option<Box<Vec<premier_git_bridge::InboundPolicyViolation>>>,
    /// A refusal by the declassification firewall or the instruction quarantine (boxed: most
    /// errors carry none). Serialized inline as `declassification_report` and
    /// `quarantine_pending_id`.
    #[serde(flatten)]
    pub(crate) firewall: Option<Box<FirewallRefusal>>,
    /// A conflicted agent-session commit (409): the lane its changes were kept on. Boxed so
    /// every error stays small; its fields appear at the top level of the JSON.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub(crate) lane: Option<Box<LaneErrorInfo>>,
}

/// Where a conflicted agent-session commit was kept (`lane_id`, `lane_ref`, `lane_tip`,
/// `lane_conflicts` of an [`ApiError`]).
#[derive(Debug, Default, Serialize)]
pub struct LaneErrorInfo {
    pub(crate) lane_id: String,
    pub(crate) lane_ref: String,
    pub(crate) lane_tip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) lane_conflicts: Vec<premier_git_bridge::LaneConflict>,
}

#[derive(Debug, Default, Serialize)]
pub struct FirewallRefusal {
    /// The full report for an owner, the redacted one for anyone else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) declassification_report: Option<premier_policy::DeclassificationReport>,
    /// An instruction-file edit the quarantine held for an owner's decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quarantine_pending_id: Option<String>,
}

impl FirewallRefusal {
    pub(crate) fn new(
        report: premier_policy::DeclassificationReport,
        quarantine_pending_id: Option<String>,
    ) -> Option<Box<Self>> {
        Some(Box::new(Self {
            declassification_report: Some(report),
            quarantine_pending_id,
        }))
    }
}

/// Workspace administration: wrap a route's methods so members get 403. The one place the
/// owner-only list lives is the `owner(..)` calls in [`build_router`].
fn owner(methods: MethodRouter<ServerState>) -> MethodRouter<ServerState> {
    methods.route_layer(axum::middleware::from_fn(auth::require_owner))
}

/// Construct the Axum router for the Premier control plane.
pub fn build_router(state: ServerState) -> Router {
    let static_ui_dir = state.static_ui_dir.clone();

    let mut router = Router::new()
        .route("/health", get(health_handler))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route(
            "/.well-known/openid-configuration",
            get(lifecycle::oidc_discovery_handler),
        )
        .route("/.well-known/jwks.json", get(lifecycle::jwks_handler))
        .route("/v1/policy/summary", get(policy_summary_handler))
        .route(
            "/v1/policy/repo",
            owner(put(handlers_v1::update_repo_policy_handler)),
        )
        .route("/v1/repo/tree", get(repo_tree_handler))
        .route(
            "/v1/repo/file",
            get(repo_file_handler)
                .put(handlers_v1::write_repo_file_handler)
                .delete(handlers_v1::delete_repo_file_handler),
        )
        .route("/v1/repo/search", get(handlers_v1::repo_search_handler))
        .route("/v1/repo/blame", get(handlers_v1::repo_blame_handler))
        .route("/v1/access/explain", owner(post(explain_handler)))
        .route("/v1/access/diff", owner(post(access_diff_handler)))
        .route("/v1/access/scan", owner(post(firewall::scan_handler)))
        .route(
            "/v1/quarantine",
            owner(get(firewall::list_quarantine_handler)),
        )
        .route(
            "/v1/quarantine/approve",
            owner(post(firewall::approve_quarantine_handler)),
        )
        .route(
            "/v1/quarantine/reject",
            owner(post(firewall::reject_quarantine_handler)),
        )
        .route("/v1/policy/diff", owner(post(access_diff_handler)))
        .route(
            "/v1/policy/propose",
            owner(post(propose_policy_intent_handler)),
        )
        .route(
            "/v1/policy/explain-secrets",
            owner(post(explain_secrets_handler)),
        )
        .route("/v1/env/schema", get(schema_handler))
        .route("/v1/env/dashboard", get(schema_dashboard_handler))
        .route(
            "/v1/secrets/status",
            owner(get(handlers_v1::secrets_status_handler)),
        )
        .route(
            "/v1/secrets/set",
            owner(post(handlers_v1::set_secret_handler)),
        )
        .route(
            "/v1/secrets/{key}",
            owner(delete(handlers_v1::delete_secret_handler)),
        )
        .route(
            "/v1/secrets/{key}/rotate",
            owner(post(lifecycle::rotate_secret_handler)),
        )
        .route(
            "/v1/secrets/rotations",
            owner(get(lifecycle::list_rotations_handler)),
        )
        .route(
            "/v1/secrets/kms/status",
            owner(get(lifecycle::kms_status_handler)),
        )
        .route(
            "/v1/secrets/kms/rotate-dek",
            owner(post(lifecycle::rotate_dek_handler)),
        )
        .route(
            "/v1/secrets/kms/migrate",
            owner(post(lifecycle::migrate_kms_handler)),
        )
        .route("/v1/oidc/discovery", get(lifecycle::oidc_discovery_handler))
        .route("/v1/oidc/token", post(lifecycle::oidc_token_handler))
        .route("/v1/oidc/verify", post(lifecycle::oidc_verify_handler))
        .route(
            "/v1/security/offboard",
            owner(post(lifecycle::offboard_handler)),
        )
        .route(
            "/v1/security/offboard/receipts",
            owner(get(lifecycle::list_offboard_receipts_handler)),
        )
        .route(
            "/v1/auth/offboard",
            owner(post(lifecycle::offboard_handler)),
        )
        .route("/v1/audit", owner(get(audit_handler)))
        .route("/v1/audit/export", owner(get(ops::audit_export_handler)))
        .route(
            "/v1/settings",
            get(ops::get_settings_handler).merge(owner(patch(ops::patch_settings_handler))),
        )
        .route("/v1/backup", owner(get(ops::backup_handler)))
        .route("/v1/approvals", get(list_approvals_handler))
        .route(
            "/v1/approvals/{id}/decide",
            owner(post(decide_approval_handler)),
        )
        .route(
            "/v1/approvals/suggestions",
            owner(get(policy_learning::list_suggestions_handler)),
        )
        .route(
            "/v1/approvals/suggestions/{id}/preview",
            owner(post(policy_learning::preview_suggestion_handler)),
        )
        .route(
            "/v1/approvals/suggestions/{id}/apply",
            owner(post(policy_learning::apply_suggestion_handler)),
        )
        .route(
            "/v1/approvals/suggestions/{id}/dismiss",
            owner(post(policy_learning::dismiss_suggestion_handler)),
        )
        .route("/v1/events/stream", get(events_stream_handler))
        .route("/v1/traces", get(traces::list_traces_handler))
        .route("/v1/traces/blame", get(traces::blame_traces_handler))
        .route("/v1/traces/ingest", post(traces::ingest_trace_handler))
        .route(
            "/v1/traces/sample",
            owner(post(traces::seed_sample_traces_handler)),
        )
        .route(
            "/v1/traces/{session_id}",
            owner(delete(traces::delete_trace_handler)),
        )
        .route("/v1/mcp/gateways", get(mcp_gateway::list_gateways_handler))
        .route(
            "/v1/mcp/explain",
            owner(post(mcp_gateway::explain_tool_handler)),
        )
        .route(
            "/v1/mcp/alerts",
            owner(get(mcp_gateway::list_alerts_handler)),
        )
        .route(
            "/v1/mcp/alerts/{id}/approve",
            owner(post(mcp_gateway::approve_alert_handler)),
        )
        .route(
            "/v1/mcp/alerts/{id}/dismiss",
            owner(post(mcp_gateway::dismiss_alert_handler)),
        )
        .route("/v1/mcp/rpc", post(mcp_gateway::rpc_handler))
        .route(
            "/v1/agents/sessions",
            get(handlers_v1::list_sessions_handler)
                .merge(owner(post(handlers_v1::spawn_session_handler))),
        )
        .route(
            "/v1/agents/sessions/{id}",
            owner(delete(runner::discard_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/diff",
            owner(get(runner::session_diff_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/stop",
            owner(post(runner::stop_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/commit",
            owner(post(runner::commit_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/budget",
            owner(post(lifecycle::raise_budget_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/provenance",
            get(lanes::session_provenance_handler),
        )
        .route(
            "/v1/lanes",
            get(lanes::list_lanes_handler).merge(owner(post(lanes::create_lane_handler))),
        )
        .route(
            "/v1/lanes/{lane_id}",
            get(lanes::get_lane_handler).merge(owner(delete(lanes::delete_lane_handler))),
        )
        .route(
            "/v1/lanes/{lane_id}/rebase",
            owner(post(lanes::rebase_lane_handler)),
        )
        .route(
            "/v1/lanes/{lane_id}/resolve",
            owner(post(lanes::resolve_lane_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/pause",
            owner(post(runner::pause_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/checkpoint",
            owner(post(runner::checkpoint_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/resume",
            owner(post(runner::resume_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/workspace/files",
            owner(get(runner::session_workspace_files_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/workspace/file",
            owner(
                get(runner::session_workspace_read_file_handler)
                    .put(runner::session_workspace_write_file_handler),
            ),
        )
        .route(
            "/v1/hygiene/insights",
            owner(get(hygiene::insights_handler)),
        )
        .route(
            "/v1/hygiene/dismiss",
            owner(post(hygiene::dismiss_insight_handler)),
        )
        .route(
            "/v1/hygiene/restore",
            owner(post(hygiene::restore_insight_handler)),
        )
        .route("/v1/overlays", owner(get(list_overlays_handler)))
        .route("/v1/overlays/check", owner(post(check_overlays_handler)))
        .route(
            "/v1/overlays/mount",
            owner(post(handlers_v1::mount_overlay_handler)),
        )
        .route(
            "/v1/overlays/unmount",
            owner(post(handlers_v1::unmount_overlay_handler)),
        )
        .route("/v1/branches", get(list_branches_handler))
        .route("/v1/worktable", get(worktable::worktable_handler))
        .route(
            "/v1/branches/create",
            post(handlers_v1::create_branch_handler),
        )
        .route(
            "/v1/branches/publish",
            owner(post(handlers_v1::publish_branch_handler)),
        )
        .route(
            "/v1/branches/{*name}",
            owner(delete(handlers_v1::delete_branch_handler)),
        )
        .route(
            "/v1/branches/visibility",
            owner(post(update_branch_visibility_handler)),
        )
        .route("/v1/branches/squash-preview", post(squash_preview_handler))
        .route("/v1/commits", get(list_commits_handler))
        .route("/v1/commits/{oid}", get(read_commit_diff_handler))
        .route("/v1/attestations/{oid}", get(attestation_handler))
        .route(
            "/v1/reviews",
            get(list_reviews_handler).post(handlers_v1::create_review_handler),
        )
        .route(
            "/v1/reviews/{change_id}/comments",
            post(handlers_v1::add_review_comment_handler),
        )
        .route(
            "/v1/reviews/{change_id}/verdict",
            post(handlers_v1::set_review_verdict_handler),
        )
        .route(
            "/v1/reviews/{change_id}/interdiff",
            get(lanes::review_interdiff_handler),
        )
        .route(
            "/v1/reviews/{change_id}/steer",
            owner(post(lanes::steer_review_handler)),
        )
        .route(
            "/git/repo.git/info/refs",
            get(handlers_v1::git_info_refs_v2_handler),
        )
        .route(
            "/git/repo.git/git-upload-pack",
            post(git_upload_pack_handler).layer(DefaultBodyLimit::max(ops::GIT_FETCH_BODY_LIMIT)),
        )
        .route(
            "/git/repo.git/git-receive-pack",
            // Reads its own body, capped at `ops::GIT_BODY_LIMIT`, once admitted.
            post(handlers_v1::git_receive_pack_handler),
        )
        .route(
            "/git/auth/repo.git/info/refs",
            get(handlers_v1::git_info_refs_v2_handler),
        )
        .route(
            "/git/auth/repo.git/git-upload-pack",
            post(git_upload_pack_handler).layer(DefaultBodyLimit::max(ops::GIT_FETCH_BODY_LIMIT)),
        )
        .route(
            "/git/auth/repo.git/git-receive-pack",
            // Reads its own body, capped at `ops::GIT_BODY_LIMIT`, once admitted.
            post(handlers_v1::git_receive_pack_handler),
        )
        .route("/v1/auth/status", get(auth::status_handler))
        .route("/v1/auth/setup", post(auth::setup_handler))
        .route("/v1/auth/login", post(auth::login_handler))
        .route("/v1/auth/logout", post(auth::logout_handler))
        .route("/v1/auth/password", post(auth::password_handler))
        .route("/v1/auth/profile", patch(auth::profile_handler))
        .route("/v1/auth/sessions", get(auth::list_sessions_handler))
        .route(
            "/v1/auth/sessions/revoke-others",
            post(auth::revoke_other_sessions_handler),
        )
        .route(
            "/v1/auth/sessions/{id}",
            delete(auth::revoke_session_handler),
        )
        .route(
            "/v1/auth/tokens",
            get(auth::list_tokens_handler).post(auth::create_token_handler),
        )
        .route("/v1/auth/tokens/{id}", delete(auth::revoke_token_handler))
        .route(
            "/v1/auth/ssh-keys",
            get(auth::list_ssh_keys_handler).post(auth::add_ssh_key_handler),
        )
        .route(
            "/v1/auth/ssh-keys/{id}",
            delete(auth::revoke_ssh_key_handler),
        )
        .route("/v1/auth/totp/begin", post(auth::totp_begin_handler))
        .route("/v1/auth/totp/enable", post(auth::totp_enable_handler))
        .route("/v1/auth/totp/disable", post(auth::totp_disable_handler))
        .route(
            "/v1/auth/totp/recovery-codes",
            post(auth::totp_recovery_codes_handler),
        )
        .route("/v1/auth/events", get(auth::events_handler))
        .route(
            "/v1/users",
            owner(get(auth::list_users_handler).post(auth::create_user_handler)),
        )
        .route(
            "/v1/users/{username}",
            owner(patch(auth::patch_user_handler).delete(auth::delete_user_handler)),
        )
        .route("/v1/directory", get(directory::get_handler))
        .route(
            "/v1/directory/principals/{principal}",
            owner(
                put(directory::put_principal_handler).delete(directory::delete_principal_handler),
            ),
        )
        .route("/v1/github/status", owner(get(github::status_handler)))
        .route(
            "/v1/github/config",
            owner(put(github::configure_handler).delete(github::disconnect_handler)),
        )
        .route(
            "/v1/github/pr/preview",
            owner(post(github::preview_pr_handler)),
        )
        .route(
            "/v1/github/pr/publish",
            owner(post(github::publish_pr_handler)),
        )
        .route("/v1/github/sync/out", owner(post(github::sync_out_handler)))
        .route("/v1/github/sync/in", owner(post(github::sync_in_handler)))
        // JSON bodies are small; only the Git routes above opt into a larger limit.
        .layer(DefaultBodyLimit::max(ops::JSON_BODY_LIMIT))
        // Inside the gate (added before it), so it knows who is calling.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            repos::hide_from_strangers,
        ))
        // The one enforcement point for /v1 and Git. Added before CORS so preflights and 401s
        // still carry CORS headers.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::gate,
        ))
        .with_state(state.clone());

    // Serve built Studio SPA directly from `premier serve` on a single port when `apps/web/dist` exists.
    if let Some(dist_dir) = static_ui_dir {
        let index = dist_dir.join("index.html");
        if index.exists() {
            router = router
                .fallback_service(ServeDir::new(dist_dir).not_found_service(ServeFile::new(index)));
        }
    }

    with_runtime_middleware(router, state)
}

pub(crate) struct RuntimeMetrics {
    started: Instant,
    http: [AtomicU64; 4],
    auth_ok: AtomicU64,
    auth_failed: AtomicU64,
    auth_locked: AtomicU64,
    git_http: AtomicU64,
    git_ssh: AtomicU64,
    sse: AtomicU64,
    pub(crate) scrubbed: AtomicU64,
    limiter: RateLimiter,
    gauges: tokio::sync::Mutex<Option<(Instant, WorkloadGauges)>>,
}

impl RuntimeMetrics {
    fn new() -> Self {
        let setting = |key, default| {
            std::env::var(key)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default)
        };
        Self {
            started: Instant::now(),
            http: Default::default(),
            auth_ok: AtomicU64::default(),
            auth_failed: AtomicU64::default(),
            auth_locked: AtomicU64::default(),
            git_http: AtomicU64::default(),
            git_ssh: AtomicU64::default(),
            sse: AtomicU64::default(),
            scrubbed: AtomicU64::default(),
            gauges: tokio::sync::Mutex::new(None),
            limiter: RateLimiter::new(
                setting("PREMIER_RATE_LIMIT_BURST", 120),
                setting("PREMIER_RATE_LIMIT_RPS", 20),
            ),
        }
    }
}

struct RateLimiter {
    capacity: f64,
    refill: f64,
    table: Mutex<RateTable>,
}

struct RateTable {
    last_pruned: Instant,
    buckets: HashMap<Option<IpAddr>, Bucket>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    fn new(burst: u32, requests_per_sec: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            refill: f64::from(requests_per_sec),
            table: Mutex::new(RateTable {
                last_pruned: Instant::now(),
                buckets: HashMap::new(),
            }),
        }
    }

    fn admit(&self, ip: Option<IpAddr>) -> Result<(), u64> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if now.duration_since(table.last_pruned) >= Duration::from_secs(30) {
            let idle = (self.capacity / self.refill).max(60.0);
            table
                .buckets
                .retain(|_, bucket| now.duration_since(bucket.updated).as_secs_f64() < idle);
            table.last_pruned = now;
        }
        if table.buckets.len() >= 8192 && !table.buckets.contains_key(&ip) {
            let oldest_idle = table
                .buckets
                .iter()
                .filter(|(_, bucket)| {
                    bucket.tokens + now.duration_since(bucket.updated).as_secs_f64() * self.refill
                        >= self.capacity
                })
                .min_by_key(|(_, bucket)| bucket.updated)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest_idle {
                table.buckets.remove(&oldest);
            } else {
                return Err(30);
            }
        }
        let bucket = table.buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            updated: now,
        });
        bucket.tokens = (bucket.tokens
            + now.duration_since(bucket.updated).as_secs_f64() * self.refill)
            .min(self.capacity);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return Err(((1.0 - bucket.tokens) / self.refill).ceil() as u64);
        }
        bucket.tokens -= 1.0;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RuntimeMiddlewareApplied;

fn with_runtime_middleware(router: Router, state: ServerState) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        state,
        runtime_middleware,
    ))
}

async fn runtime_middleware(
    State(state): State<ServerState>,
    mut request: Request,
    next: axum::middleware::Next,
) -> Response {
    if request
        .extensions()
        .get::<RuntimeMiddlewareApplied>()
        .is_some()
    {
        return next.run(request).await;
    }
    request.extensions_mut().insert(RuntimeMiddlewareApplied);
    let request_id = request
        .headers()
        .get("x-request-id")
        .filter(|value| {
            let bytes = value.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 128
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
        })
        .cloned()
        .unwrap_or_else(|| {
            use std::fmt::Write as _;
            let mut id = String::with_capacity(32);
            for b in auth::random_bytes(16) {
                let _ = write!(id, "{b:02x}");
            }
            header::HeaderValue::try_from(id)
                .unwrap_or_else(|_| header::HeaderValue::from_static("unknown"))
        });
    request
        .headers_mut()
        .insert("x-request-id", request_id.clone());
    let span =
        tracing::info_span!("http_request", request_id = ?request_id, method = %request.method());
    async move {
        let path = request.uri().path();
        let path = path.strip_prefix("/r/")
            .and_then(|rest| rest.find('/').map(|split| &rest[split..]))
            .unwrap_or(path);
        let git = path.starts_with("/git/");
        let limited = matches!(path,
            "/v1/repo/search" | "/v1/backup" | "/v1/oidc/token" | "/v1/mcp/rpc"
            | "/readyz" | "/v1/traces/ingest" | "/v1/access/scan");
        let (client, https) = if limited || request.headers().contains_key("x-forwarded-proto") {
            let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
            let mut headers = request.headers().clone();
            let client = auth::client_ip(&state.trusted_proxies, peer, &mut headers);
            (client.parse().ok(), auth::forwarded_https(&headers))
        } else {
            (None, false)
        };
        let admission = if limited {
            state.metrics.limiter.admit(client)
        } else {
            Ok(())
        };
        let mut response = match admission {
            Ok(()) => next.run(request).await,
            Err(delay) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, delay.to_string())],
                Json(serde_json::json!({"error": "rate limit exceeded"})),
            ).into_response(),
        };
        let stats = &state.metrics;
        let status = response.status();
        let class = status.as_u16() / 100;
        if (2..=5).contains(&class) {
            stats.http[usize::from(class - 2)].fetch_add(1, Ordering::Relaxed);
        }
        if git {
            stats.git_http.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(status = status.as_u16(), "HTTP response");
        let headers = response.headers_mut();
        headers.insert("x-request-id", request_id);
        for (name, value) in [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", "default-src 'self'; script-src 'self'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"),
        ] {
            headers.insert(name, header::HeaderValue::from_static(value));
        }
        if https {
            headers.insert(header::STRICT_TRANSPORT_SECURITY,
                header::HeaderValue::from_static("max-age=31536000; includeSubDomains"));
        }
        if headers.get(header::CONTENT_TYPE).is_some_and(|value| value.as_bytes().starts_with(b"text/event-stream")) {
            stats.sse.fetch_add(1, Ordering::Relaxed);
            let guard = SseClient(Arc::clone(stats));
            response = response.map(|body| axum::body::Body::new(body.map_frame(move |frame| {
                let _ = &guard;
                frame
            })));
        }
        response
    }.instrument(span).await
}

struct SseClient(Arc<RuntimeMetrics>);

impl Drop for SseClient {
    fn drop(&mut self) {
        self.0.sse.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn livez() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(state): State<ServerState>) -> Response {
    let cache = Arc::clone(&state.readiness_probe).lock_owned().await;
    let probe = match *cache {
        Some((measured, probe)) if measured.elapsed() < Duration::from_secs(3) => probe,
        _ => {
            // Keep the probe alive if the initiating HTTP client disconnects. The owned lock
            // ensures all concurrent requests share the result of this one probe.
            tokio::spawn(async move {
                let mut cache = cache;
                let probe = probe_readiness(state).await;
                *cache = Some((Instant::now(), probe));
                probe
            })
            .await
            .unwrap_or_default()
        }
    };
    let ready = probe.sqlite && probe.git && probe.ssh.unwrap_or(true);
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(serde_json::json!({
            "status": if ready { "ok" } else { "unavailable" },
            "checks": {
                "sqlite": if probe.sqlite { "ok" } else { "unavailable" },
                "git": if probe.git { "ok" } else { "unavailable" },
                "ssh": match probe.ssh {
                    None => "disabled",
                    Some(true) => "ok",
                    Some(false) => "unavailable",
                },
            },
        })),
    )
        .into_response()
}

#[derive(Clone, Copy, Default)]
struct ReadinessProbe {
    sqlite: bool,
    git: bool,
    ssh: Option<bool>,
}

async fn probe_readiness(state: ServerState) -> ReadinessProbe {
    let ssh = state.ssh_bind;
    let blocking = tokio::task::spawn_blocking(move || {
        let repo_dir = store::state_dir(&state.workspace_root);
        let account_dir = store::account_dir(state.account_root());
        let writable = |dir: &Path| {
            db::StateDb::open(dir)
                .and_then(|mut db| db.probe_write())
                .is_ok()
        };
        let sqlite = writable(&repo_dir) && (account_dir == repo_dir || writable(&account_dir));
        let git = premier_git_bridge::git_command(&state.workspace_root)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success());
        (sqlite, git)
    });
    let ssh_ready = if let Some(mut addr) = ssh {
        if addr.ip().is_unspecified() {
            addr.set_ip(if addr.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            });
        }
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    } else {
        true
    };
    let (sqlite, git) = blocking.await.unwrap_or_default();
    ReadinessProbe {
        sqlite,
        git,
        ssh: ssh.map(|_| ssh_ready),
    }
}

#[derive(Clone, Copy, Default)]
struct WorkloadGauges {
    agents: u64,
    traces: u64,
    spans: u64,
}

impl WorkloadGauges {
    fn collect(state: &ServerState) -> Self {
        let viewer = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let mut totals = Self::default();
        for repo in state.all_repo_states() {
            totals.agents += repo
                .session_manager
                .list()
                .iter()
                .filter(|s| matches!(s.status.as_str(), "running" | "paused"))
                .count() as u64;
            let sessions = repo.trace_store.list_sessions_for_viewer(&viewer, None, "");
            totals.traces += sessions.len() as u64;
            totals.spans += sessions.iter().map(|s| s.spans.len() as u64).sum::<u64>();
        }
        totals
    }
}

async fn metrics_handler(State(state): State<ServerState>) -> Response {
    use std::fmt::Write as _;
    let metrics = state.metrics.clone();
    let workload = {
        // Avoid repeating trace traversal when multiple scrapers arrive together.
        let mut cache = metrics.gauges.lock().await;
        if let Some((updated, gauges)) = *cache
            && updated.elapsed() < Duration::from_secs(5)
        {
            gauges
        } else {
            let gauges = tokio::task::spawn_blocking(move || WorkloadGauges::collect(&state))
                .await
                .unwrap_or_default();
            *cache = Some((Instant::now(), gauges));
            gauges
        }
    };
    let mut body = String::from(
        "# HELP premier_http_requests_total Total HTTP requests handled by status class.\n\
         # TYPE premier_http_requests_total counter\n",
    );
    for (index, count) in metrics.http.iter().enumerate() {
        let _ = writeln!(
            body,
            "premier_http_requests_total{{status_class=\"{}xx\"}} {}",
            index + 2,
            count.load(Ordering::Relaxed)
        );
    }
    let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    for (name, kind, help, value) in [
        (
            "auth_successes_total",
            "counter",
            "Total successful authentication events.",
            read(&metrics.auth_ok),
        ),
        (
            "auth_failures_total",
            "counter",
            "Total failed authentication attempts.",
            read(&metrics.auth_failed),
        ),
        (
            "auth_lockouts_total",
            "counter",
            "Total authentication lockouts triggered.",
            read(&metrics.auth_locked),
        ),
        (
            "git_http_operations_total",
            "counter",
            "Total Git Smart HTTP requests served.",
            read(&metrics.git_http),
        ),
        (
            "git_ssh_operations_total",
            "counter",
            "Total Git SSH operations served.",
            read(&metrics.git_ssh),
        ),
        (
            "active_sse_clients",
            "gauge",
            "Currently connected SSE event stream clients.",
            read(&metrics.sse),
        ),
        (
            "active_agent_sessions",
            "gauge",
            "Currently active agent sessions.",
            workload.agents,
        ),
        (
            "secret_bytes_scrubbed_total",
            "counter",
            "Total secret bytes scrubbed before persistence or egress.",
            read(&metrics.scrubbed),
        ),
        (
            "trace_sessions",
            "gauge",
            "Total recorded agent trace sessions.",
            workload.traces,
        ),
        (
            "trace_spans",
            "gauge",
            "Total recorded agent trace spans.",
            workload.spans,
        ),
        (
            "uptime_seconds",
            "gauge",
            "Server process uptime in seconds.",
            metrics.started.elapsed().as_secs(),
        ),
    ] {
        let _ = writeln!(
            body,
            "# HELP premier_{name} {help}\n# TYPE premier_{name} {kind}\npremier_{name} {value}"
        );
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn health_handler(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
) -> Json<HealthResponse> {
    // `/health` is outside the gate, so the credentials are checked here.
    let user = auth::request_user(&state, &headers).ok().flatten();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        details: user.map(|user| HealthDetails {
            agent_sandbox: runner::sandbox_mode(state.allow_unsandboxed_agents).as_str(),
            ssh_enabled: state.ssh_bind.is_some(),
            ssh_port: state.ssh_bind.map(|a| a.port()),
            host: (user.role == auth::Role::Owner).then(|| HostHealth {
                os: std::env::consts::OS,
                workspace_root: state.workspace_root.display().to_string(),
                policy_loaded: state.current_policy().is_some(),
                server_policy_loaded: state.server_policy_toml.is_some(),
                schema_loaded: state.current_env_schema().is_some(),
                host_capabilities: HostSandboxCapabilities::detect(),
                agent_sandbox_detail: runner::sandbox_detail(state.allow_unsandboxed_agents),
            }),
        }),
    })
}

async fn policy_summary_handler(State(state): State<ServerState>) -> Json<PolicySummaryResponse> {
    // The policy text names restricted paths, zones and rules: only an owner in a browser session
    // receives it; members and access tokens only learn that a policy is loaded.
    let owner = auth::owner_only().is_ok();
    Json(PolicySummaryResponse {
        policy_loaded: state.current_policy().is_some(),
        server_policy_loaded: state.server_policy_toml.is_some(),
        imported_policy_pending: owner
            && store::state_dir(&state.workspace_root)
                .join(repos::PENDING_POLICY)
                .exists(),
        repo_policy_toml: if owner {
            state.current_repo_policy_toml()
        } else {
            String::new()
        },
        server_policy_toml: state
            .server_policy_toml
            .clone()
            .filter(|_| owner)
            .unwrap_or_default(),
        policy: state
            .current_repo_policy_file()
            .filter(|_| owner)
            .as_deref()
            .cloned(),
    })
}

/// Commit ids as the caller's own Git clone has them: the one translation, both ways, for every
/// route. A member's clone holds projected commits, so a canonical id is nothing she can use
/// and, where her projection rewrote or dropped the commit, nothing she may learn. An owner's
/// projection hides nothing: their ids are the canonical ones.
pub(crate) struct GitIds(Option<Arc<premier_git_bridge::ProjectedView>>);

impl GitIds {
    /// For `identity`, the one the request is evaluated as (a member is always themself).
    pub(crate) fn of(
        state: &ServerState,
        identity: &DelegatedIdentity,
    ) -> Result<Self, (StatusCode, Json<ApiError>)> {
        if auth::caller_is_owner() {
            return Ok(Self(None));
        }
        let Some(policy) = state.current_policy() else {
            return Err(err_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                "no compiled policy loaded",
            ));
        };
        // The view a fetch is served from (`git_upload_pack_handler`): the same cache entry.
        let fp_short = state.policy_fingerprint();
        let canonical = CanonicalGitRepo::open(&state.workspace_root);
        project_repository(
            &canonical,
            &policy,
            &fp_short,
            identity,
            &state.branch_visibility_map(),
        )
        .map(|view| Self(Some(view)))
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }

    /// The tip of branch `branch` (short name) whose canonical tip is `canonical_tip`; `None`
    /// when the caller's clone has no such branch.
    pub(crate) fn tip(&self, branch: &str, canonical_tip: &str) -> Option<String> {
        match &self.0 {
            None => Some(canonical_tip.to_owned()),
            Some(view) => view.refs.get(&format!("refs/heads/{branch}")).cloned(),
        }
    }

    /// The canonical tip a caller means by `given`, the tip of `branch` they last saw: their tip
    /// stands for the branch's canonical one (which may carry commits they cannot see). Anything
    /// else, a canonical id included, is no tip at all.
    pub(crate) fn canonical_tip(&self, branch: &str, given: String) -> String {
        let Some(view) = &self.0 else { return given };
        let advertised = format!("refs/heads/{branch}");
        let current = view.refs.get(&advertised).is_some_and(|tip| *tip == given);
        let source = view.ref_sources.get(&advertised).filter(|_| current);
        source
            .map(|(_, canonical)| canonical.clone())
            .unwrap_or_default()
    }

    /// One canonical commit as the caller's clone has it: the commit, or the one it collapsed
    /// onto (it changed nothing they see). Empty when no part of their clone.
    // shortcut: not per branch, so under ref-scoped path rules this can be the commit as another
    // of the caller's branches has it; use `ProjectedView::commits_on` where that matters.
    pub(crate) fn shown(&self, canonical: &str) -> String {
        match &self.0 {
            None => canonical.to_owned(),
            Some(view) => view
                .canonical_to_projected
                .get(canonical)
                .cloned()
                .unwrap_or_default(),
        }
    }

    /// The canonical commit behind an id the caller gave (whole or abbreviated); `None` when it
    /// is no commit of their clone.
    fn canonical(&self, given: &str) -> Option<String> {
        match &self.0 {
            None => Some(given.to_owned()),
            Some(view) => view.canonical_commit(given).map(str::to_owned),
        }
    }
}

/// The authenticated caller's own identity (no "view as" claim).
fn caller_identity(
    state: &ServerState,
    task_tag: &str,
) -> Result<DelegatedIdentity, (StatusCode, Json<ApiError>)> {
    directory::identity(state, &auth::actor_principal(), None, task_tag)
}

/// The env schema as the caller may know it: all of it for an owner, and for a member only the
/// variables policy lets them `use` (none without a policy). `None`: the repository has none.
fn visible_env_schema(
    state: &ServerState,
) -> Result<Option<EnvSchema>, (StatusCode, Json<ApiError>)> {
    let Some(schema) = state.current_env_schema() else {
        return Ok(None);
    };
    let mut schema = (*schema).clone();
    if !auth::caller_is_owner() {
        let me = caller_identity(state, "env-schema")?;
        let policy = state.current_policy();
        let branch = default_branch(&state.workspace_root);
        schema.vars.retain(|name, spec| {
            policy.as_ref().is_some_and(|p| {
                p.can_use_secret(&me, name, spec.zone.as_deref(), &branch)
                    .allows(Capability::USE)
            })
        });
    }
    Ok(Some(schema))
}

async fn repo_tree_handler(
    State(state): State<ServerState>,
    Query(q): Query<RepoTreeQuery>,
) -> Result<Json<RepoTreeResponse>, (StatusCode, Json<ApiError>)> {
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            "no .access.toml policy loaded on this server",
        ));
    };

    let agent_profile = q.agent_profile.filter(|s| !s.trim().is_empty());
    let identity = directory::identity(&state, &q.principal, agent_profile.clone(), "studio-xray")?;
    // X-ray, rule traces, and omitted counts are the owner's browser-session lens only.
    // For members and access tokens, the flag is ignored and no rule traces or counts leave.
    let owner = auth::owner_only().is_ok();
    let xray = q.xray && owner;
    let state_for_tree = state.clone();
    let identity_for_tree = identity.clone();
    let (ref_name, listed) = tokio::task::spawn_blocking(move || {
        let ref_name = q
            .ref_name
            .unwrap_or_else(|| checked_out(&state_for_tree.workspace_root).0);
        let listed = content_source(&state_for_tree, &identity_for_tree, &ref_name)?
            .and_then(|rev| {
                repos::git_out(
                    &state_for_tree.workspace_root,
                    &["ls-tree", "-r", "-t", "-z", &rev],
                )
            })
            .unwrap_or_default();
        Ok::<_, (StatusCode, Json<ApiError>)>((ref_name, listed))
    })
    .await
    .map_err(|err| err_resp(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))??;

    let mut visible_count = 0usize;
    let mut traverse_only_count = 0usize;
    let mut omitted_count = 0usize;
    let mut entries: BTreeMap<String, RepoTreeEntry> = BTreeMap::new();

    // Git lists each directory once with `-t`. Keep the first 250 authorized paths in
    // lexical order while continuing to count authorized and owner-only entries.
    for (raw_path, kind) in revision_paths(&listed) {
        let Ok(repo_path) = RepoPath::new(raw_path) else {
            continue;
        };
        let dec = policy.explain(&identity, &repo_path, &ref_name);
        let is_instruction = policy.is_instruction_file(&repo_path);

        let visibility_state = if dec.effective.is_empty() {
            omitted_count += 1;
            "omitted"
        } else if dec.effective == Capability::TRAVERSE {
            traverse_only_count += 1;
            "traverse_only"
        } else {
            visible_count += 1;
            "visible"
        };

        // In Strict mode (xray = false), omitted paths NEVER leave the server!
        if !xray && visibility_state == "omitted" {
            continue;
        }
        if entries.len() == 250 {
            if entries
                .last_key_value()
                .is_some_and(|(last, _)| last.as_str() <= raw_path)
            {
                continue;
            }
            entries.pop_last();
        }

        entries.insert(
            raw_path.to_owned(),
            RepoTreeEntry {
                path: raw_path.to_owned(),
                kind,
                visibility_state,
                effective: dec
                    .effective
                    .to_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                human_effective: dec
                    .human_effective
                    .to_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                agent_effective: dec
                    .agent_effective
                    .map(|m| m.to_names().into_iter().map(str::to_owned).collect()),
                synthesized_traverse: dec.synthesized_traverse,
                is_instruction_file: is_instruction,
                matched_rules: if owner { dec.matched_rules } else { Vec::new() },
            },
        );
    }

    Ok(Json(RepoTreeResponse {
        principal: identity.principal.canonical_id(),
        agent_profile,
        ref_name,
        xray,
        visible_count,
        traverse_only_count,
        // How much the caller cannot see is the owner's to know.
        omitted_count: if owner { omitted_count } else { 0 },
        entries: entries.into_values().collect(),
    }))
}

/// Directory names the tree view never descends into.
fn not_browsable(name: &str) -> bool {
    let normalized = name
        .split(':')
        .next()
        .unwrap_or(name)
        .trim_end_matches(['.', ' ']);
    if [".git", ".premier", ".premier-local"]
        .iter()
        .any(|internal| normalized.eq_ignore_ascii_case(internal))
    {
        return true;
    }
    matches!(name, "target" | "node_modules" | ".tmp" | ".cache" | "dist")
}

/// Files and directories from Git's NUL-delimited tree listing, to a depth of five.
fn revision_paths(listed: &str) -> impl Iterator<Item = (&str, &'static str)> {
    listed.split('\0').filter_map(|record| {
        let (meta, path) = record.split_once('\t')?;
        let segments = path.split('/');
        if segments.clone().count() > 5 || segments.into_iter().any(not_browsable) {
            return None;
        }
        let kind = if meta.starts_with("040000 tree ") {
            "dir"
        } else {
            "file"
        };
        Some((path, kind))
    })
}

/// Sample paths for policy analysis when the caller does not provide an explicit list.
fn collect_rev_paths(root: &Path, rev: &str, out: &mut BTreeMap<String, &'static str>) {
    let listed =
        repos::git_out(root, &["ls-tree", "-r", "--name-only", "-z", rev]).unwrap_or_default();
    for file in listed.split('\0').filter(|p| !p.is_empty()) {
        let segments: Vec<&str> = file.split('/').collect();
        if segments.iter().any(|s| not_browsable(s)) {
            continue;
        }
        for depth in 1..=segments.len().min(5) {
            if out.len() > 250 {
                return;
            }
            let kind = if depth == segments.len() {
                "file"
            } else {
                "dir"
            };
            out.entry(segments[..depth].join("/")).or_insert(kind);
        }
    }
}

/// The branch the working tree is on: the short name policy is evaluated on and, once it has a
/// commit, the ref (or detached oid) whose visibility decides who may read the working tree.
pub(crate) fn checked_out(root: &Path) -> (String, Option<String>) {
    let tip = repos::git_out(root, &["rev-parse", "-q", "--verify", "HEAD"]);
    match repos::git_out(root, &["symbolic-ref", "-q", "HEAD"]) {
        Some(full) => {
            let short = full
                .strip_prefix("refs/heads/")
                .or_else(|| full.strip_prefix(PRIVATE_REF_PREFIX))
                .unwrap_or(&full)
                .to_owned();
            (short, tip.map(|_| full))
        }
        // Detached, or not a repository: no branch name, so rules are evaluated as on `main`.
        None => ("main".to_owned(), tip),
    }
}

/// Short name of the repository's default (checked-out) branch: what a request that names no
/// branch means, and the branch policy is evaluated on where none is in play.
pub(crate) fn default_branch(root: &Path) -> String {
    checked_out(root).0
}

/// The committed tree a request for content on `requested` reads from, so the policy decision
/// (made on `requested`) and the data agree: always the ref's own tip, never the working tree.
/// `None` only for the default branch of a repository with no commit yet (nothing to show). A ref
/// `identity` cannot see answers like a missing one, so a ref-scoped rule never unlocks another
/// branch's content.
pub(crate) fn content_source(
    state: &ServerState,
    identity: &DelegatedIdentity,
    requested: &str,
) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    let (branch, tip) = checked_out(&state.workspace_root);
    if requested == branch {
        match tip {
            None => return Ok(None),
            // Detached: the commit itself, if a branch the caller sees contains it.
            Some(oid) if !oid.starts_with("refs/") => {
                return visible_refs(state, identity, &oid, false).map(|(rev, _)| Some(rev));
            }
            Some(_) => {}
        }
    }
    let rev = resolve_visible_rev(state, identity, requested)?;
    if rev.starts_with("refs/") {
        Ok(Some(rev))
    } else {
        Err(err_resp(StatusCode::NOT_FOUND, "ref not found"))
    }
}

/// Resolve `path` inside the working tree: the absolute path to open and the path policy must be
/// evaluated on. They differ from the request on filesystems that fold names (`BILLING/x`, 8.3
/// short names): the decision belongs to the file that would really be opened, under its
/// on-disk name. `None` when a component is a symlink or the result leaves the workspace.
// shortcut: checked when called, not when the file is opened, so something that can write the
// workspace concurrently (an agent session, a push) could swap in a symlink in between; open
// with O_NOFOLLOW / openat2(RESOLVE_BENEATH) if that race becomes relevant.
pub(crate) fn working_tree_path(root: &Path, path: &RepoPath) -> Option<(PathBuf, RepoPath)> {
    let root = root.canonicalize().ok()?;
    let segments = path.segments();
    let mut existing = root.clone();
    let mut missing: &[&str] = &[];
    for (idx, segment) in segments.iter().enumerate() {
        let next = existing.join(segment);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => return None,
            Ok(_) => existing = next,
            Err(_) => {
                missing = &segments[idx..];
                break;
            }
        }
    }
    let canonical = existing.canonicalize().ok()?;
    let mut names: Vec<&str> = Vec::new();
    for component in canonical.strip_prefix(&root).ok()?.components() {
        names.push(component.as_os_str().to_str()?);
    }
    names.extend(missing);
    let mut abs = canonical.clone();
    abs.extend(missing);
    Some((abs, RepoPath::new(names.join("/")).ok()?))
}

/// Bytes of `path` as committed at `rev`, capped at `max_bytes` so a huge blob is never read in
/// full into memory. Returns `(bytes, truncated)`.
pub(crate) fn rev_file_capped(
    root: &Path,
    rev: &str,
    path: &RepoPath,
    max_bytes: usize,
) -> Option<(Vec<u8>, bool)> {
    use std::io::Read as _;

    let mut child = premier_git_bridge::git_command(root)
        .args(["cat-file", "blob", &format!("{rev}:{}", path.as_str())])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let _ = stdout
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf);
    let truncated = buf.len() > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
        drop(stdout);
        let _ = child.kill();
        let _ = child.wait();
        return Some((buf, true));
    }
    drop(stdout);
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    Some((buf, false))
}

const DEFAULT_FILE_MAX_BYTES: usize = 32 * 1024;
const MAX_FILE_READ_BYTES: usize = 512 * 1024;
const FILE_BINARY_SNIFF_BYTES: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
pub struct RepoFileQuery {
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    /// Branch to read; left out, the one that is checked out.
    #[serde(default)]
    pub ref_name: Option<String>,
    pub path: String,
    /// Optional read byte cap (default 32 KiB, max 512 KiB).
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RepoFileResponse {
    path: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    truncated: bool,
    binary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tip_oid: Option<String>,
    reason: String,
}

async fn repo_file_handler(
    State(state): State<ServerState>,
    Query(q): Query<RepoFileQuery>,
) -> Result<Json<RepoFileResponse>, (StatusCode, Json<ApiError>)> {
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            "no .access.toml policy loaded on this server",
        ));
    };

    let repo_path =
        RepoPath::new(&q.path).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-file-read")?;

    let not_found = || {
        err_resp(
            StatusCode::NOT_FOUND,
            format!("file '{}' not found on disk", repo_path),
        )
    };
    let ref_name = q
        .ref_name
        .unwrap_or_else(|| checked_out(&state.workspace_root).0);
    let source = content_source(&state, &identity, &ref_name)?;
    let checked_path = &repo_path;

    // Enforce server-side READ capability BEFORE reading content!
    let dec = policy.explain(&identity, checked_path, &ref_name);
    if !dec.allows(Capability::READ) {
        return Ok(Json(RepoFileResponse {
            path: repo_path.to_string(),
            allowed: false,
            content: None,
            truncated: false,
            binary: false,
            tip_oid: None,
            reason: format!(
                "Server policy denied READ for {} on '{}' (effective: {})",
                identity.principal, repo_path, dec.effective
            ),
        }));
    }

    // Server state (auth.json, vault keys, .git) is never repo content, whatever policy allows.
    if auth::is_internal_path(&state.workspace_root, checked_path.as_str()) {
        return Err(not_found());
    }
    let Some(rev) = source else {
        return Err(not_found());
    };
    let max_bytes = q
        .max_bytes
        .unwrap_or(DEFAULT_FILE_MAX_BYTES)
        .clamp(1, MAX_FILE_READ_BYTES);
    let ids = GitIds::of(&state, &identity)?;
    let root = state.workspace_root.clone();
    let rev_bg = rev.clone();
    let path_bg = repo_path.clone();
    let (read_res, canonical_tip) = tokio::task::spawn_blocking(move || {
        let data = rev_file_capped(&root, &rev_bg, &path_bg, max_bytes);
        let tip = canon::tip_of(&root, &rev_bg);
        (data, tip)
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some((bytes, truncated)) = read_res else {
        return Err(not_found());
    };
    let binary = bytes[..bytes.len().min(FILE_BINARY_SNIFF_BYTES)].contains(&0);
    let tip_oid = canonical_tip
        .and_then(|t| ids.tip(&ref_name, &t))
        .filter(|t| !t.is_empty());
    Ok(Json(RepoFileResponse {
        path: repo_path.to_string(),
        allowed: true,
        content: (!binary).then(|| String::from_utf8_lossy(&bytes).into_owned()),
        truncated,
        binary,
        tip_oid,
        reason: "Authorized READ".to_owned(),
    }))
}

async fn explain_handler(
    State(state): State<ServerState>,
    Json(req): Json<ExplainRequest>,
) -> Result<Json<ExplainDecision>, (StatusCode, Json<ApiError>)> {
    // A policy simulator: rule ids and reasons for any principal and path.
    auth::owner_only()?;
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            "no .access.toml policy loaded on this server",
        ));
    };

    let path =
        RepoPath::new(&req.path).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let identity = directory::identity(
        &state,
        &req.principal,
        req.agent_profile,
        req.agent_task_id.as_deref().unwrap_or("api-explain"),
    )?;

    let ref_name = req
        .ref_name
        .unwrap_or_else(|| default_branch(&state.workspace_root));
    let decision = policy.explain(&identity, &path, &ref_name);
    Ok(Json(decision))
}

async fn access_diff_handler(
    State(state): State<ServerState>,
    Json(req): Json<AccessDiffRequest>,
) -> Result<Json<AccessImpactDiff>, (StatusCode, Json<ApiError>)> {
    auth::owner_only()?;
    let base_file = parse_policy_toml(&req.base_toml)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let head_file = parse_policy_toml(&req.head_toml)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;

    let server_toml_opt = req.server_toml.or_else(|| state.server_policy_toml.clone());
    let server_file = match server_toml_opt.filter(|s| !s.trim().is_empty()) {
        Some(raw) => Some(
            parse_policy_toml(&raw)
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?,
        ),
        None => None,
    };

    let base_compiled = CompiledPolicy::compile(server_file.as_ref(), &base_file)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let head_compiled = CompiledPolicy::compile(server_file.as_ref(), &head_file)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut identities = if req.principals.is_empty() {
        directory::all_identities(&state)?
    } else {
        req.principals
            .iter()
            .filter_map(|raw| diff_identity(&state, raw).ok())
            .collect()
    };
    if req.include_agent_profiles {
        add_agent_identities(
            &mut identities,
            [Some(&base_file), Some(&head_file), server_file.as_ref()]
                .into_iter()
                .flatten(),
        );
    }

    let path_list = if req.paths.is_empty() {
        // No paths named: the default branch's own (same walk as the tree view).
        let mut found = BTreeMap::new();
        collect_rev_paths(&state.workspace_root, "HEAD", &mut found);
        found.into_keys().collect()
    } else {
        req.paths
    };

    let repo_paths: Vec<RepoPath> = path_list
        .iter()
        .filter_map(|p| RepoPath::new(p).ok())
        .collect();

    let changed: Vec<(RepoPath, Option<Vec<u8>>)> = req
        .changed_files
        .into_iter()
        .filter_map(|cf| {
            let rp = RepoPath::new(&cf.path).ok()?;
            Some((rp, cf.content.map(|s| s.into_bytes())))
        })
        .collect();

    let ref_name = req
        .ref_name
        .unwrap_or_else(|| default_branch(&state.workspace_root));
    let mut diff = compute_access_diff(
        &base_compiled,
        &head_compiled,
        &identities,
        &repo_paths,
        &changed,
        &ref_name,
    );
    if !req.secret_probes.is_empty() {
        let secrets: Vec<(String, Option<String>)> = req
            .secret_probes
            .into_iter()
            .map(|p| (p.var_name, p.zone))
            .collect();
        diff.deltas.extend(compute_secret_use_deltas(
            &base_compiled,
            &head_compiled,
            &identities,
            &secrets,
            &ref_name,
        ));
    }
    Ok(Json(diff))
}

/// `@user`, or `@user ∩ profile` / `@user::profile` for that user's delegated agent.
fn diff_identity(
    state: &ServerState,
    raw: &str,
) -> Result<DelegatedIdentity, (StatusCode, Json<ApiError>)> {
    match raw.split_once(" ∩ ").or_else(|| raw.split_once("::")) {
        Some((who, profile)) => directory::identity(
            state,
            who.trim(),
            Some(profile.trim().to_owned()),
            "pr-diff",
        ),
        None => directory::identity(state, raw, None, "pr-diff"),
    }
}

/// Pair every authenticated human in `identities` with every agent profile the files declare.
fn add_agent_identities<'a>(
    identities: &mut Vec<DelegatedIdentity>,
    files: impl IntoIterator<Item = &'a AccessPolicyFile>,
) {
    let profiles: BTreeSet<String> = files
        .into_iter()
        .flat_map(|f| f.agent_profiles.iter().map(|p| p.name.clone()))
        .collect();
    let key = |i: &DelegatedIdentity| {
        (
            i.principal.canonical_id(),
            i.agent_task.as_ref().map(|a| a.profile.clone()),
        )
    };
    let mut seen: BTreeSet<_> = identities.iter().map(key).collect();
    let humans: Vec<DelegatedIdentity> = identities
        .iter()
        .filter(|i| i.agent_task.is_none() && i.principal.is_authenticated())
        .cloned()
        .collect();
    for human in humans {
        for profile in &profiles {
            let agent = DelegatedIdentity::delegated(
                human.principal.clone(),
                human.groups.clone(),
                profile.clone(),
                "pr-diff",
            );
            if seen.insert(key(&agent)) {
                identities.push(agent);
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ProposePolicyIntentRequest {
    /// Left out, the repository's current policy.
    #[serde(default)]
    pub base_toml: Option<String>,
    pub intent: PolicyIntent,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub ref_name: Option<String>,
}

/// Where the server policy changes what the proposed repo policy alone would decide.
#[derive(Debug, Serialize)]
pub struct ServerPolicyOverrideFinding {
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub path: String,
    pub repo_only_effective: Vec<String>,
    pub effective_with_server: Vec<String>,
    pub server_rules: Vec<MatchedRuleTrace>,
}

#[derive(Debug, Serialize)]
pub struct ServerOverrideCheck {
    /// No server rule changes the outcome of the proposal (fails closed when the proposal does
    /// not compile under the server policy).
    pub passed: bool,
    pub total_overrides: usize,
    /// The first [`MAX_OVERRIDE_FINDINGS`].
    pub overrides: Vec<ServerPolicyOverrideFinding>,
}

#[derive(Debug, Serialize)]
pub struct ProposePolicyIntentResponse {
    pub base_toml: String,
    pub base_sha256: String,
    pub proposed_toml: String,
    pub rule_id: String,
    pub summary: String,
    pub warnings: Vec<String>,
    /// Why the proposal could not be applied as the repository policy, if it could not.
    pub validation_error: Option<String>,
    pub server_policy_loaded: bool,
    pub server_override_check: ServerOverrideCheck,
    pub target_paths: Vec<String>,
    pub secret_probes: Vec<SecretProbe>,
}

const MAX_OVERRIDE_FINDINGS: usize = 50;

/// Whether a repo path is the target, inside it, or one of its ancestors (whose `traverse` a
/// target rule can change). Glob targets compare by their literal prefix.
fn near_target(path: &str, target: &str) -> bool {
    let prefix = target
        .split('/')
        .take_while(|s| !s.contains(['*', '?', '[', '{', '\\']))
        .collect::<Vec<_>>()
        .join("/");
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix.as_str())
            .is_some_and(|r| r.starts_with('/'))
        || prefix
            .strip_prefix(path)
            .is_some_and(|r| r.starts_with('/'))
}

/// Turn one Studio intent into a proposed `.access.toml` (comments kept), say whether it could be
/// applied, and where the server policy would override it. Nothing is written.
async fn propose_policy_intent_handler(
    State(state): State<ServerState>,
    Json(req): Json<ProposePolicyIntentRequest>,
) -> Result<Json<ProposePolicyIntentResponse>, (StatusCode, Json<ApiError>)> {
    auth::owner_only()?;
    let base_toml = req
        .base_toml
        .unwrap_or_else(|| state.current_repo_policy_toml());
    let base_toml = if base_toml.trim().is_empty() {
        directory::DEFAULT_POLICY_TOML.to_owned()
    } else {
        base_toml
    };
    let mutation = apply_policy_intent(&base_toml, &req.intent)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let validation_error = state.validate_repo_policy(&mutation.proposed_toml).err();

    let proposed_file = parse_policy_toml(&mutation.proposed_toml)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let repo_only = CompiledPolicy::compile(None, &proposed_file)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let server_file = state
        .server_policy_toml
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| parse_policy_toml(s).ok());
    let server_policy_loaded = state
        .server_policy_toml
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());

    let mut check = ServerOverrideCheck {
        passed: true,
        total_overrides: 0,
        overrides: Vec::new(),
    };
    if server_policy_loaded {
        match server_file
            .as_ref()
            .and_then(|srv| CompiledPolicy::compile(Some(srv), &proposed_file).ok())
        {
            None => check.passed = false,
            Some(with_server) => {
                let ref_name = req
                    .ref_name
                    .unwrap_or_else(|| default_branch(&state.workspace_root));
                let mut identities = directory::all_identities(&state)?;
                add_agent_identities(
                    &mut identities,
                    [Some(&proposed_file), server_file.as_ref()]
                        .into_iter()
                        .flatten(),
                );

                let mut found = BTreeMap::new();
                collect_rev_paths(&state.workspace_root, "HEAD", &mut found);
                let all: Vec<String> = found.into_keys().collect();
                let mut paths: Vec<String> = all
                    .iter()
                    .filter(|p| mutation.target_paths.iter().any(|t| near_target(p, t)))
                    .cloned()
                    .collect();
                paths.extend(
                    mutation
                        .target_paths
                        .iter()
                        .filter(|t| !t.contains(['*', '?', '[', '{', '\\']))
                        .cloned(),
                );
                if paths.is_empty() && mutation.secret_probes.is_empty() {
                    paths = all;
                }
                paths.sort();
                paths.dedup();
                let paths: Vec<RepoPath> =
                    paths.iter().filter_map(|p| RepoPath::new(p).ok()).collect();

                let mut compare = |repo: ExplainDecision, srv: ExplainDecision| {
                    let server_rules: Vec<MatchedRuleTrace> = srv
                        .matched_rules
                        .into_iter()
                        .filter(|r| r.layer == PolicyLayer::Server)
                        .collect();
                    if repo.effective == srv.effective || server_rules.is_empty() {
                        return;
                    }
                    check.total_overrides += 1;
                    if check.overrides.len() < MAX_OVERRIDE_FINDINGS {
                        let names =
                            |c: Capability| c.to_names().into_iter().map(str::to_owned).collect();
                        check.overrides.push(ServerPolicyOverrideFinding {
                            principal: srv.principal,
                            agent_profile: srv.agent_profile,
                            path: srv.path,
                            repo_only_effective: names(repo.effective),
                            effective_with_server: names(srv.effective),
                            server_rules,
                        });
                    }
                };
                for identity in &identities {
                    for path in &paths {
                        compare(
                            repo_only.explain(identity, path, &ref_name),
                            with_server.explain(identity, path, &ref_name),
                        );
                    }
                    for probe in &mutation.secret_probes {
                        let zone = probe.zone.as_deref();
                        compare(
                            repo_only.can_use_secret(identity, &probe.var_name, zone, &ref_name),
                            with_server.can_use_secret(identity, &probe.var_name, zone, &ref_name),
                        );
                    }
                }
                check.passed = check.total_overrides == 0;
            }
        }
    }

    let base_sha256 = sha256_hex(base_toml.as_bytes());
    Ok(Json(ProposePolicyIntentResponse {
        base_toml,
        base_sha256,
        proposed_toml: mutation.proposed_toml,
        rule_id: mutation.rule_id,
        summary: mutation.summary,
        warnings: mutation.warnings,
        validation_error,
        server_policy_loaded,
        server_override_check: check,
        target_paths: mutation.target_paths,
        secret_probes: mutation.secret_probes,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ExplainSecretsRequest {
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default)]
    pub ref_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExplainSecretEntry {
    pub name: String,
    pub sensitivity: premier_secrets::Sensitivity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    pub can_use: bool,
    pub has_egress: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<premier_secrets::ApprovalMode>,
}

#[derive(Debug, Serialize)]
pub struct ExplainSecretsResponse {
    pub entries: Vec<ExplainSecretEntry>,
}

/// Evaluate truthful server-side `can_use_secret` (`use ≠ read`) for every variable declared in
/// `.env.schema` under the requested comparison identity. Strictly owner-only.
async fn explain_secrets_handler(
    State(state): State<ServerState>,
    Json(req): Json<ExplainSecretsRequest>,
) -> Result<Json<ExplainSecretsResponse>, (StatusCode, Json<ApiError>)> {
    use premier_secrets::Sensitivity;

    auth::owner_only()?;
    let Some(schema) = state.current_env_schema() else {
        return Ok(Json(ExplainSecretsResponse {
            entries: Vec::new(),
        }));
    };
    let identity = directory::identity(
        &state,
        &req.principal,
        req.agent_profile,
        "studio-mirror-secrets",
    )?;
    let policy = state.current_policy();
    let ref_name = req
        .ref_name
        .unwrap_or_else(|| default_branch(&state.workspace_root));

    let entries = schema
        .vars
        .iter()
        .map(|(name, spec)| {
            let can_use = match spec.sensitivity {
                Sensitivity::Public => true,
                Sensitivity::Internal => identity.principal.is_authenticated(),
                Sensitivity::Secret | Sensitivity::Restricted => {
                    policy.as_ref().is_some_and(|pol| {
                        pol.can_use_secret(&identity, name, spec.zone.as_deref(), &ref_name)
                            .allows(Capability::USE)
                    })
                }
            };
            ExplainSecretEntry {
                name: name.clone(),
                sensitivity: spec.sensitivity,
                zone: spec.zone.clone(),
                can_use,
                has_egress: spec.egress.is_some(),
                approval: spec.egress.as_ref().map(|e| e.approval),
            }
        })
        .collect();

    Ok(Json(ExplainSecretsResponse { entries }))
}

async fn schema_handler(
    State(state): State<ServerState>,
) -> Result<Json<Option<EnvSchema>>, (StatusCode, Json<ApiError>)> {
    visible_env_schema(&state).map(Json)
}

async fn schema_dashboard_handler(
    State(state): State<ServerState>,
    Query(q): Query<SchemaDashboardQuery>,
) -> Result<Json<SchemaDashboardResponse>, (StatusCode, Json<ApiError>)> {
    use premier_secrets::{SecretCoord, SecretLayer};

    let Some(schema) = visible_env_schema(&state)? else {
        return Ok(Json(SchemaDashboardResponse {
            schema: None,
            reports: BTreeMap::new(),
            can_use: BTreeMap::new(),
        }));
    };
    // Optional `?principal=&agent_profile=` lens is honored ONLY for an owner in a browser
    // session; everyone else is evaluated strictly as their own identity.
    let target_identity = if auth::owner_only().is_ok() {
        let principal_raw = q
            .principal
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(auth::actor_principal);
        let agent_profile = q.agent_profile.filter(|s| !s.trim().is_empty());
        directory::identity(&state, &principal_raw, agent_profile, "env-dashboard")?
    } else {
        caller_identity(&state, "env-dashboard")?
    };

    let branch = default_branch(&state.workspace_root);
    let policy = state.current_policy();
    let can_use: BTreeMap<String, bool> = schema
        .vars
        .iter()
        .map(|(name, spec)| {
            let allowed = policy.as_ref().is_some_and(|p| {
                p.can_use_secret(&target_identity, name, spec.zone.as_deref(), &branch)
                    .allows(Capability::USE)
            });
            (name.clone(), allowed)
        })
        .collect();

    // Resolve strictly from workspace vault + `.env.schema` defaults; NEVER read `std::env::var`.
    let repo_id = schema
        .repo_id
        .clone()
        .unwrap_or_else(|| "local/repo".to_owned());
    let vault = if store::has_workspace_vault_or_external(&state.workspace_root) {
        store::resolve_vault_backend(&state.workspace_root, &repo_id).ok()
    } else {
        None
    };

    let mut reports = BTreeMap::new();
    for env in [
        Environment::Dev,
        Environment::Preview,
        Environment::Staging,
        Environment::Prod,
    ] {
        let mut present_env = BTreeMap::new();
        if let Some(ref vault) = vault {
            for var_name in schema.vars.keys() {
                let coord = SecretCoord {
                    repo_id: repo_id.clone(),
                    layer: SecretLayer::Env,
                    scope: env.as_str().to_owned(),
                    var_name: var_name.clone(),
                };
                if let Ok(Some(val)) = vault.get(&coord) {
                    present_env.insert(var_name.clone(), val.as_str().to_owned());
                }
            }
        }
        reports.insert(
            env.as_str().to_owned(),
            schema.validate_values(&env, &present_env),
        );
    }

    Ok(Json(SchemaDashboardResponse {
        schema: Some(schema),
        reports,
        can_use,
    }))
}

async fn audit_handler(
    State(state): State<ServerState>,
    Query(q): Query<ops::AuditQuery>,
) -> Json<Vec<AuditEvent>> {
    let mut events = state.audit_sink.snapshot();
    events.reverse();
    Json(ops::filter_audit(events, &q))
}

async fn list_approvals_handler(State(state): State<ServerState>) -> Json<Vec<PendingApproval>> {
    let mut approvals = state.approval_hub.list();
    if auth::owner_only().is_err() {
        let me = auth::actor_principal();
        approvals.retain(|a| a.principal == me);
    }
    Json(approvals)
}

async fn decide_approval_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<DecideApprovalRequest>,
) -> Result<Json<PendingApproval>, (StatusCode, Json<ApiError>)> {
    let decided = state
        .approval_hub
        .decide_with_options(
            &id,
            premier_proxy::ApprovalDecision {
                approved: req.approved,
                ttl_secs: req.ttl_secs,
                grant_scope: req.grant_scope,
                denial_reason: req.denial_reason,
            },
        )
        .map_err(|why| err_resp(StatusCode::BAD_REQUEST, why))?;
    let Some((updated, transitioned)) = decided else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            format!("approval '{id}' not found"),
        ));
    };

    if transitioned {
        let identity = DelegatedIdentity::delegated(
            Principal::parse(&updated.principal).unwrap_or(Principal::Anonymous),
            vec![],
            updated
                .agent_profile
                .clone()
                .unwrap_or_else(|| "agent".to_owned()),
            updated.id.clone(),
        );
        let approved = updated.status == premier_proxy::ApprovalStatus::Approved;
        let scope_label = match updated.grant_scope {
            Some(premier_proxy::GrantScope::Once) => "once",
            Some(premier_proxy::GrantScope::ExactPath) => "exact_path",
            Some(premier_proxy::GrantScope::ReadOnlyPrefix) => "read_only_prefix",
            Some(premier_proxy::GrantScope::ExactScope) => "exact_scope",
            None => "default",
        };
        let reason = if approved {
            format!(
                "Human approved JIT capability '{}' for {} {} (scope={}, TTL {}s)",
                updated.var_name, updated.method, updated.host, scope_label, updated.ttl_secs
            )
        } else if let Some(why) = &updated.denial_reason {
            format!(
                "Human denied JIT capability '{}' for {} {}: {}",
                updated.var_name, updated.method, updated.host, why
            )
        } else {
            format!(
                "Human denied JIT capability '{}' for {} {}",
                updated.var_name, updated.method, updated.host
            )
        };
        let mut ev = AuditEvent::now(
            &identity,
            "premier-proxy",
            "jit_approval_decision",
            if approved {
                AuditDecision::Allowed
            } else {
                AuditDecision::Denied
            },
            reason,
        );
        ev.capability = Some(updated.var_name.clone());
        ev.target = Some(format!(
            "{} {}{}",
            updated.method, updated.host, updated.path
        ));
        crate::auth::audit(&state.audit_sink, ev);

        if approved {
            let schema = state.current_env_schema();
            if let Ok(mut guard) = state.persisted.lock()
                && policy_learning::record_approval(
                    &mut guard.policy_learning,
                    &updated,
                    schema.as_deref(),
                )
            {
                let _ = save_state(&state.workspace_root, &guard);
            }
        }
    }

    Ok(Json(updated))
}

/// How often a live event stream re-checks its caller's credentials.
const SSE_RECHECK: Duration = Duration::from_millis(if cfg!(test) { 100 } else { 15_000 });

async fn events_stream_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<auth::AuthUser>,
    headers: axum::http::HeaderMap,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // The global audit/approval/session feed requires an owner browser session; access tokens
    // only receive their own member-scoped events.
    let is_owner = user.role == auth::Role::Owner && user.session_id.is_some();
    // Approvals and sessions follow their list routes: a member gets only their own. Decided
    // here because the stream is polled outside the gate's request scope.
    let me = format!("@{}", user.username);
    let me2 = me.clone();
    let me3 = me.clone();
    let viewer_identity = if is_owner {
        None
    } else {
        directory::identity(&state, &me, None, "sse").ok()
    };
    // Emit an immediate ready frame so proxies flush headers and browser EventSource.onopen fires immediately.
    let initial = tokio_stream::once(Ok(Event::default().event("ready").data("ok")));

    let audit_rx = BroadcastStream::new(state.audit_sink.subscribe()).filter_map(move |res| {
        res.ok().filter(|_| is_owner).and_then(|ev| {
            serde_json::to_string(&ev)
                .ok()
                .map(|json| Ok(Event::default().event("audit").data(json)))
        })
    });

    let approval_rx = BroadcastStream::new(state.approval_hub.subscribe()).filter_map(move |res| {
        res.ok()
            .filter(|ap| is_owner || ap.principal == me)
            .and_then(|ap| {
                serde_json::to_string(&ap)
                    .ok()
                    .map(|json| Ok(Event::default().event("approval").data(json)))
            })
    });

    let session_rx =
        BroadcastStream::new(state.session_manager.subscribe()).filter_map(move |res| {
            res.ok()
                .filter(|s| is_owner || s.principal == me2)
                .and_then(|mut s| {
                    // A member's commit ids, conflicts and provenance need her projection & ACL,
                    // so the live feed strips them and the REST endpoints serve the filtered view.
                    // Owner telemetry insights and step-in checkpoints are also owner-only.
                    if !is_owner {
                        (s.base_commit, s.commit) = (None, None);
                        s.conflicts.clear();
                        s.provenance_steps.clear();
                        s.redact_for_member();
                    }
                    serde_json::to_string(&s)
                        .ok()
                        .map(|json| Ok(Event::default().event("session").data(json)))
                })
        });

    // Schema-drift alerts name servers and tools the member may not see: owner-only, like audit.
    let mcp_rx = BroadcastStream::new(state.mcp_pins.subscribe()).filter_map(move |res| {
        res.ok().filter(|_| is_owner).and_then(|alert| {
            serde_json::to_string(&alert)
                .ok()
                .map(|json| Ok(Event::default().event("mcp_alert").data(json)))
        })
    });
    let budget_rx = BroadcastStream::new(state.session_manager.subscribe_budget_alerts())
        .filter_map(move |res| {
            res.ok()
                .filter(|alert| is_owner || alert.principal == me3)
                .and_then(|alert| {
                    serde_json::to_string(&alert)
                        .ok()
                        .map(|json| Ok(Event::default().event("budget_alert").data(json)))
                })
        });

    // A member gets a lane or review frame only when its REST route would answer her: the ref
    // visibility AND some access to the branch it is on (no existence oracle via the feed).
    let viewer_for_lane = viewer_identity.clone();
    let state_for_lane = state.clone();
    let lane_rx = BroadcastStream::new(state.lane_tx.subscribe()).filter_map(move |res| {
        res.ok()
            .filter(|lane| {
                is_owner
                    || viewer_for_lane.as_ref().is_some_and(|id| {
                        premier_git_bridge::can_see_ref(id, &lane.visibility)
                            && resolve_accessible_rev(&state_for_lane, id, &lane.base_branch)
                                .is_ok()
                    })
            })
            .and_then(|mut lane| {
                if !is_owner {
                    lane.base_commit = None;
                    lane.tip_oid = None;
                    lane.conflicts.clear();
                }
                serde_json::to_string(&lane)
                    .ok()
                    .map(|json| Ok(Event::default().event("lane").data(json)))
            })
    });

    let viewer_for_review = viewer_identity;
    let state_for_review = state.clone();
    let review_rx = BroadcastStream::new(state.review_tx.subscribe()).filter_map(move |res| {
        res.ok()
            .filter(|rev| {
                is_owner
                    || viewer_for_review.as_ref().is_some_and(|id| {
                        let branch = state_for_review.persisted.lock().ok().and_then(|st| {
                            st.reviews
                                .iter()
                                .find(|r| r.change_id == rev.change_id)
                                .map(|r| r.branch.clone())
                        });
                        premier_git_bridge::can_see_ref(id, &rev.visibility)
                            && branch.is_some_and(|b| {
                                resolve_accessible_rev(&state_for_review, id, &b).is_ok()
                            })
                    })
            })
            .and_then(|mut rev| {
                // Which lane holds it is the owners' (`GET /v1/reviews` shows a member only a
                // lane she may see).
                if !is_owner {
                    rev.lane_id = None;
                }
                serde_json::to_string(&rev)
                    .ok()
                    .map(|json| Ok(Event::default().event("review").data(json)))
            })
    });

    let insight_rx =
        BroadcastStream::new(state.session_manager.subscribe_insights()).filter_map(move |res| {
            res.ok().filter(|_| is_owner).and_then(|ins| {
                serde_json::to_string(&ins)
                    .ok()
                    .map(|json| Ok(Event::default().event("session_insight").data(json)))
            })
        });

    // Trace SSE frames only signal that a trace updated (no raw span payload over SSE),
    // so clients refetch through the Zone-ACL-filtered `GET /v1/traces` route.
    let me4 = format!("@{}", user.username);
    let trace_rx = BroadcastStream::new(state.trace_store.subscribe()).filter_map(move |res| {
        res.ok()
            .filter(|ev| match ev {
                premier_trace::TraceEvent::SessionRecorded { principal, .. } => {
                    is_owner || principal == &me4
                }
                premier_trace::TraceEvent::SpanRecorded { .. } => is_owner,
            })
            .and_then(|ev| {
                let sid = match ev {
                    premier_trace::TraceEvent::SessionRecorded { session_id, .. }
                    | premier_trace::TraceEvent::SpanRecorded { session_id, .. } => session_id,
                };
                serde_json::to_string(&serde_json::json!({
                    "event": "trace_updated",
                    "session_id": sid
                }))
                .ok()
                .map(|json| Ok(Event::default().event("trace").data(json)))
            })
    });

    // What the stream may carry was decided from the caller at connect. On every tick the
    // credentials are checked again, and the stream ends once they are gone (logout, revoked,
    // disabled) or belong to a different role (demoted).
    let shutdown = state.shutdown.subscribe();
    let shutdown_for_gate = shutdown.clone();
    let shutdown_ticks = tokio_stream::wrappers::WatchStream::new(shutdown)
        .filter(|stopped| *stopped)
        .map(|_| None);
    let still_entitled = move || {
        matches!(
            auth::request_user(&state, &headers),
            Ok(Some(now))
                if now.username == user.username
                    && now.role == user.role
                    && now.session_id.is_some() == user.session_id.is_some()
        )
    };
    let mut interval =
        tokio::time::interval_at(tokio::time::Instant::now() + SSE_RECHECK, SSE_RECHECK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let ticks = tokio_stream::wrappers::IntervalStream::new(interval)
        .map(|_| None)
        .merge(shutdown_ticks);
    let live = audit_rx
        .merge(approval_rx)
        .merge(session_rx)
        .merge(mcp_rx)
        .merge(budget_rx)
        .merge(lane_rx)
        .merge(review_rx)
        .merge(insight_rx)
        .merge(trace_rx)
        .map(Some)
        .merge(ticks)
        .take_while(move |item| {
            !*shutdown_for_gate.borrow() && (item.is_some() || still_entitled())
        })
        .filter_map(|item| item);

    let merged = initial.chain(live);
    Sse::new(merged).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// This repository's overlay store, under its state directory and never the working tree.
pub fn overlay_store(workspace_root: &Path) -> Result<OverlayStore, premier_overlay::OverlayError> {
    OverlayStore::open(
        store::state_dir(workspace_root),
        repos::repo_name(workspace_root, None),
    )
}

/// Every mounted overlay, all principals' and the server-recorded ones, for push exclusion. An
/// unreadable store fails the caller rather than letting an overlay through.
pub(crate) fn overlay_manifest(state: &ServerState) -> Result<OverlayManifest, String> {
    let mut manifest = state
        .persisted
        .lock()
        .map(|g| g.overlays.clone())
        .unwrap_or_default();
    let stored = overlay_store(&state.workspace_root)
        .and_then(|s| s.to_manifest())
        .map_err(|e| format!("overlay store: {e}"))?;
    for entry in stored.entries {
        if !manifest.entries.contains(&entry) {
            manifest.entries.push(entry);
        }
    }
    Ok(manifest)
}

/// HTTP status for a store error: the caller's mistake, someone else's overlay, or ours.
pub(crate) fn overlay_err(e: premier_overlay::OverlayError) -> (StatusCode, Json<ApiError>) {
    use premier_overlay::OverlayError as E;
    let status = match e {
        E::InvalidPath { .. } | E::InvalidGlob { .. } | E::InvalidInput(_) => {
            StatusCode::BAD_REQUEST
        }
        E::AccessDenied { .. } => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err_resp(status, e.to_string())
}

/// The overlays `claimed` (or the caller) may see: their own personal ones, team ones (all of
/// them for the caller, who administers them; their groups' for a "view as" principal), and the
/// server-recorded entries no stored record covers. Never another principal's personal overlay.
pub(crate) fn overlay_list_for(
    state: &ServerState,
    claimed: Option<&str>,
) -> Result<OverlayListResponse, (StatusCode, Json<ApiError>)> {
    let actor = auth::actor_principal();
    let principal = claimed
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map_or_else(|| actor.clone(), auth::effective_principal);
    let store = overlay_store(&state.workspace_root).map_err(overlay_err)?;
    let mut entries = if premier_overlay::normalize_principal(&principal)
        == premier_overlay::normalize_principal(&actor)
    {
        store.list_for_owner(&principal)
    } else {
        let id = directory::identity(state, &principal, None, "overlay-list")?;
        store.list_for_principal(&principal, &id.groups)
    }
    .map_err(overlay_err)?;
    let stored = store.to_manifest().map_err(overlay_err)?;
    let recorded = state
        .persisted
        .lock()
        .map(|g| g.overlays.clone())
        .unwrap_or_default();
    entries.extend(
        recorded
            .entries
            .iter()
            .filter(|e| {
                !stored
                    .entries
                    .iter()
                    .any(|s| s.kind == e.kind && s.path == e.path)
            })
            .map(OverlayRecord::from_legacy),
    );
    Ok(OverlayListResponse::new(entries))
}

#[derive(Debug, Default, Deserialize)]
pub struct OverlayListQuery {
    #[serde(default)]
    pub principal: Option<String>,
}

async fn list_overlays_handler(
    State(state): State<ServerState>,
    Query(q): Query<OverlayListQuery>,
) -> Result<Json<OverlayListResponse>, (StatusCode, Json<ApiError>)> {
    auth::owner_only()?;
    Ok(Json(overlay_list_for(&state, q.principal.as_deref())?))
}

async fn check_overlays_handler(
    State(state): State<ServerState>,
    Json(req): Json<OverlayCheckRequest>,
) -> Result<Json<OverlayCheckResponse>, (StatusCode, Json<ApiError>)> {
    auth::owner_only()?;
    let manifest =
        overlay_manifest(&state).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let guard = OverlayGuard::from_manifest(&manifest)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut repo_paths = Vec::new();
    for raw in &req.paths {
        if let Ok(rp) = RepoPath::new(raw) {
            repo_paths.push(rp);
        }
    }

    match guard.validate_public_paths(&repo_paths) {
        Ok(()) => Ok(Json(OverlayCheckResponse {
            allowed: true,
            blocked_paths: vec![],
            message: "Clean: no team or personal overlay files in candidate public commit"
                .to_owned(),
        })),
        Err(premier_overlay::OverlayError::LeakBlocked { paths }) => {
            Ok(Json(OverlayCheckResponse {
                allowed: false,
                blocked_paths: paths.clone(),
                message: format!(
                    "Structural push guard blocked {} from leaking into public history",
                    premier_git_bridge::plural(paths.len(), "overlay file")
                ),
            }))
        }
        Err(e) => Err(err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// List 100% real Git branches from disk (`refs/heads` + `refs/premier-private`), enriched with
/// persisted orthogonal Visibility/Readiness, real `ahead_commits`, and real `private_paths_touched`.
async fn list_branches_handler(State(state): State<ServerState>) -> Json<Vec<BranchRecord>> {
    let overrides = state.branch_metadata();
    let policy = state.current_policy();
    // Owners administer every branch; a member is only told about the ones they may see. A
    // member whose identity cannot be built sees nothing.
    let member = if auth::caller_is_owner() {
        None
    } else {
        match caller_identity(&state, "studio-branches") {
            Ok(me) => Some(me),
            Err(_) => return Json(vec![]),
        }
    };

    // A member's commit ids are those of her clone.
    let ids = match member.as_ref().map(|me| GitIds::of(&state, me)) {
        Some(Ok(ids)) => ids,
        Some(Err(_)) => return Json(vec![]),
        None => GitIds(None),
    };
    // Everyone a branch can be labelled as visible to, besides the owners (an owner's view only).
    let others: Vec<DelegatedIdentity> = match &member {
        Some(_) => vec![],
        None => directory::all_identities(&state)
            .unwrap_or_default()
            .into_iter()
            .filter(|id| {
                id.principal.is_authenticated()
                    && !id.matches_selector(premier_git_bridge::OWNERS_SELECTOR)
            })
            .collect(),
    };

    let default = default_branch(&state.workspace_root);
    // Both counts below are measured against the default branch: not for a member it is hidden from.
    let measured = member.is_none() || ids.tip(&default, "").is_some();
    let mut branches = Vec::new();
    let mut seen = BTreeSet::new();
    // One `for-each-ref` carries every per-branch fact git has (tip, subject, ahead count).
    let Some(rows) = branch_rows(&state.workspace_root) else {
        return Json(branches);
    };
    // The rest of what the loop needs of git is fetched concurrently up front, never per branch.
    let stored_visibility = |row: &BranchRow| {
        overrides
            .get(&row.full_ref)
            .cloned()
            .unwrap_or_else(|| (default_ref_visibility(&row.full_ref), Readiness::Ready))
    };
    let seeable: Vec<&BranchRow> = rows
        .iter()
        .filter(|row| {
            member
                .as_ref()
                .is_none_or(|me| premier_git_bridge::can_see_ref(me, &stored_visibility(row).0))
        })
        .collect();
    let public: Vec<&BranchRow> = seeable
        .iter()
        .copied()
        .filter(|row| stored_visibility(row).0 == Visibility::Public)
        .collect();
    // Fails closed: no policy, or a tip that cannot be read, serves nobody.
    let served_to_anonymous = served_map(&state, policy.as_deref(), &public);
    let tips_to_list: Vec<&str> = seeable
        .iter()
        .filter(|row| {
            member.is_some()
                || (!others.is_empty() && served_to_anonymous.get(&row.full_ref) == Some(&false))
        })
        .map(|row| row.tip.as_str())
        .collect();
    warm_tree_paths(&state.workspace_root, &tips_to_list);
    // `(index into branches, full ref, name)` of those whose changed paths are still to be read.
    let mut touched_pending: Vec<(usize, String, String)> = Vec::new();

    for row in &rows {
        let full_ref = row.full_ref.as_str();
        let name = ref_short(full_ref).unwrap_or(full_ref).to_owned();
        if !seen.insert(name.clone()) {
            continue;
        }

        let (mut visibility, readiness) = stored_visibility(row);
        if member
            .as_ref()
            .is_some_and(|me| !premier_git_bridge::can_see_ref(me, &visibility))
        {
            continue;
        }
        // A member is told about a branch only if they can list something on it, and its
        // subject is that of the newest commit they are shown (`GET /v1/commits`), if any.
        let subject = match &member {
            None => row.subject.trim().to_owned(),
            Some(me) if lists_some_path(&state, me, full_ref, &name, &row.tip) => {
                let newest = visible_commits(
                    &state,
                    me,
                    &ids,
                    full_ref,
                    std::slice::from_ref(&name),
                    0,
                    1,
                )
                .pop();
                newest.map(|c| c.subject).unwrap_or_default()
            }
            Some(_) => continue,
        };
        // THE RULE for a branch's visibility. Stored, it is a property of the ref: public
        // unless someone chose otherwise (`default_ref_visibility`, the default branch
        // included), and nothing but that choice changes it; path rules then decide what of
        // the branch anyone gets. The label says who that leaves seeing it: public only while
        // an anonymous clone is served the branch (its tip shows them a file they may read,
        // the projection's rule), otherwise restricted to those who list a path on it (an
        // owner is told who; a member only that she is one of them).
        if visibility == Visibility::Public
            && !served_to_anonymous.get(full_ref).copied().unwrap_or(false)
        {
            let lists = who_lists(&state, &others, full_ref, &name, &row.tip);
            let named = others.iter().zip(&lists).filter(|(_, lists)| **lists);
            visibility = Visibility::Restricted(match &member {
                Some(me) => vec![me.principal.canonical_id()],
                None => std::iter::once(premier_git_bridge::OWNERS_SELECTOR.to_owned())
                    .chain(named.map(|(id, _)| id.principal.canonical_id()))
                    .collect(),
            });
        }

        // A branch whose tip the default branch already contains is 0 ahead and changed nothing
        // of its own: no commits to count and nothing to diff, so no `git` for either.
        let level = row.ahead == Some(0);
        let ahead_commits = if name == default || !measured || level {
            0
        } else if let Some(me) = &member {
            // A member's count is of the commits they are shown, not of all there are.
            shown_ahead(&state, me, &ids, &format!("HEAD..{full_ref}"), &name)
        } else if let Some(ahead) = row.ahead {
            ahead
        } else {
            premier_git_bridge::git_command(&state.workspace_root)
                .args(["rev-list", "--count", &format!("HEAD..{full_ref}")])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or(0)
        };
        // What the branch itself changed: from its merge base with the default branch to
        // its tip (as a publish plans it), not what the default branch did since.
        if !(name == default || !measured || level) {
            touched_pending.push((branches.len(), full_ref.to_owned(), name.clone()));
        }

        branches.push(BranchRecord {
            head_oid: match &ids.0 {
                None => row.short_oid.trim().to_owned(),
                // Her tip, or nothing where her clone has no such branch.
                Some(_) => ids
                    .tip(&name, "")
                    .map(|tip| tip[..7].to_owned())
                    .unwrap_or_default(),
            },
            name,
            subject,
            visibility,
            readiness,
            is_current: row.head,
            ahead_commits,
            private_paths_touched: vec![],
        });
    }

    // One `git diff` per branch that has something of its own, run side by side.
    let refs: Vec<&str> = touched_pending.iter().map(|(_, r, _)| r.as_str()).collect();
    let changed = branch_changed_paths(&state.workspace_root, &refs);
    for ((index, _, name), paths) in touched_pending.iter().zip(changed) {
        branches[*index].private_paths_touched = paths
            .into_iter()
            // A member is told only about the ones they may list.
            .filter(|p| {
                member.as_ref().is_none_or(|me| {
                    path_caps(policy.as_deref(), me, p, name).contains(Capability::LIST)
                })
            })
            .collect();
    }

    Json(branches)
}

async fn update_branch_visibility_handler(
    State(state): State<ServerState>,
    Json(req): Json<UpdateBranchVisibilityRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let Some(full_ref) = branch_full_ref(&state.workspace_root, &req.branch) else {
        return Err(err_resp(StatusCode::NOT_FOUND, "branch not found"));
    };
    let mut st = state.persisted.lock().map_err(|_| {
        err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "repository state lock poisoned",
        )
    })?;
    let mut updated = st.clone();
    updated
        .branch_metadata
        .insert(full_ref, (req.visibility.clone(), req.readiness));
    save_state(&state.workspace_root, &updated)
        .map_err(|err| err_resp(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    *st = updated;
    Ok(Json(serde_json::json!({
        "ok": true,
        "branch": req.branch,
        "visibility": req.visibility,
        "readiness": req.readiness,
    })))
}

/// The existing ref a branch name means: a full `refs/heads/…` or `refs/premier-private/…` name as it
/// is, a short name as the branch first and the private-namespace ref second.
pub(crate) fn branch_full_ref(root: &Path, name: &str) -> Option<String> {
    if name.is_empty() || name.contains(char::is_control) {
        return None;
    }
    let candidates = if name.starts_with("refs/heads/") || name.starts_with(PRIVATE_REF_PREFIX) {
        vec![name.to_owned()]
    } else {
        vec![
            format!("refs/heads/{name}"),
            format!("{PRIVATE_REF_PREFIX}{name}"),
        ]
    };
    // One `for-each-ref` for both candidates (a pattern is a prefix or glob, so the exact name is
    // checked on what it printed).
    let listed = repos::git_out(
        root,
        &["for-each-ref", "--format=%(refname)", "--end-of-options"]
            .into_iter()
            .chain(candidates.iter().map(String::as_str))
            .collect::<Vec<_>>(),
    )?;
    candidates
        .into_iter()
        .find(|full| listed.lines().any(|line| line == full))
}

/// Resolve an exact branch ref and enforce the caller's ref visibility.
pub(crate) fn visible_branch(
    state: &ServerState,
    identity: &DelegatedIdentity,
    branch: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let missing = || err_resp(StatusCode::NOT_FOUND, "branch not found");
    let full = branch_full_ref(&state.workspace_root, branch).ok_or_else(missing)?;
    if !premier_git_bridge::can_see_ref(identity, &state.ref_visibility(&full)) {
        return Err(missing());
    }
    Ok(full)
}

async fn squash_preview_handler(
    State(state): State<ServerState>,
    Json(req): Json<SquashPreviewRequest>,
) -> Result<Json<SquashPreviewResponse>, (StatusCode, Json<ApiError>)> {
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let short_fp = state.policy_fingerprint();
    let root = state.workspace_root.clone();

    // Owners administer every branch (as in `list_branches_handler`). A member only diffs refs
    // they can see; a hidden one answers exactly like a missing one.
    let member = if auth::owner_only().is_ok() {
        None
    } else {
        Some(caller_identity(&state, "squash-preview")?)
    };
    let target_ref = handlers_v1::publish_target(&root, req.target_branch.as_deref())?;
    let target_branch = target_ref
        .strip_prefix("refs/heads/")
        .unwrap_or(&target_ref)
        .to_owned();
    let source_rev = match &member {
        Some(me) => {
            resolve_accessible_rev(&state, me, &target_branch)?;
            resolve_accessible_rev(&state, me, &req.branch)?
        }
        None => req.branch.clone(),
    };
    let ids = member
        .as_ref()
        .map(|me| GitIds::of(&state, me))
        .transpose()?;

    // Offload `plan_squash_declassify` + git rev resolution to the blocking pool.
    let (root_bg, policy_bg, source_rev_bg, target_ref_bg) = (
        root.clone(),
        Arc::clone(&policy),
        source_rev.clone(),
        target_ref.clone(),
    );
    let (source_oid, target_tip, plan) = tokio::task::spawn_blocking(move || {
        let source_oid = handlers_v1::resolve_branch_oid(&root_bg, &source_rev_bg)
            .map_err(|_| err_resp(StatusCode::NOT_FOUND, "ref not found"))?;
        let target_tip = canon::tip_of(&root_bg, &target_ref_bg);
        let plan = premier_git_bridge::plan_squash_declassify(
            &premier_git_bridge::CanonicalGitRepo::open(&root_bg),
            &policy_bg,
            &source_oid,
            &target_ref_bg,
            target_tip.as_deref(),
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok::<_, (StatusCode, Json<ApiError>)>((source_oid, target_tip, plan))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    let overlay_manifest =
        overlay_manifest(&state).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let overlay_guard = OverlayGuard::from_manifest(&overlay_manifest)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let range = match &target_tip {
        Some(tip) => format!("{tip}..{source_oid}"),
        None => source_oid.clone(),
    };
    // Exactly what `POST /v1/branches/publish` would apply: the same plan (above), and the same
    // overlay check. The airlock detail is computed for an owner only, never for a member.
    let (plan, overlay_blocked, mut airlock) = tokio::task::spawn_blocking({
        let (root, policy, source_oid, target_tip, range) = (
            root.clone(),
            policy.clone(),
            source_oid.clone(),
            target_tip.clone(),
            range.clone(),
        );
        let (ref_name, is_owner) = (target_branch.clone(), member.is_none());
        move || {
            let overlay_blocked = overlay_blocked_paths(&overlay_guard, &plan);
            let airlock = if is_owner {
                owner_airlock(
                    &root,
                    &policy,
                    &ref_name,
                    &plan,
                    overlay_blocked.clone(),
                    (&source_oid, target_tip.as_deref(), &range),
                )
            } else {
                Airlock::default()
            };
            (plan, overlay_blocked, airlock)
        }
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // A member's count is of the commits they are shown on the source branch, not of all there are.
    let ahead = match &member {
        Some(me) => shown_ahead(
            &state,
            me,
            ids.as_ref().unwrap_or(&GitIds(None)),
            &range,
            ref_short(&source_rev).unwrap_or(&target_branch),
        ),
        None => repos::git_out(&root, &["rev-list", "--count", &range])
            .and_then(|n| n.trim().parse::<usize>().ok())
            .unwrap_or(0),
    };

    // A member is told only about restricted paths they can read themselves, and about
    // published or conflicting ones they may list.
    let shown = |path: &String, cap: Capability| {
        member.as_ref().is_none_or(|me| {
            RepoPath::new(path).is_ok_and(|rp| policy.explain(me, &rp, &target_branch).allows(cap))
        })
    };
    let total_conflicts = plan.conflicts.len();
    let total_blocked = plan.blocked.len();
    // What the declassification firewall would say about this publish (as an owner publishing).
    let summary = req.summary_message.as_deref().unwrap_or_default();
    let vault = firewall::build_vault_secret_index(&state);
    // The firewall blocks a publish carrying a vault secret, but the owner's diff preview must
    // not echo it (raw or encoded) either: withhold any patch that matches the vault index.
    if let Some(index) = vault.as_ref() {
        for file in &mut airlock.public_diff {
            if !index.scan_bytes(file.patch.as_bytes()).is_empty() {
                file.patch = "[patch withheld: it contains a vault secret]".to_owned();
            }
        }
    }
    let report = if plan.changes.is_empty() && summary.trim().is_empty() {
        premier_policy::DeclassificationReport::from_findings(Vec::new())
    } else {
        let approved = firewall::approved_instruction_map(&state);
        premier_git_bridge::scan_squash_declassify(
            &premier_git_bridge::CanonicalGitRepo::open(&root),
            &policy,
            &plan,
            &source_oid,
            &target_ref,
            target_tip.as_deref(),
            summary,
            &premier_git_bridge::SquashFirewallInput {
                vault: vault.as_ref(),
                approved_instructions: Some(&approved),
                actor_is_owner: member.is_none(),
                ..Default::default()
            },
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };
    // One sentence per blocking cause. A member gets none of them: what blocks a publish may be
    // something she cannot see, so her answer is the same whatever does.
    let mut causes = Vec::new();
    if total_conflicts > 0 {
        causes.push(format!(
            "{} changed on both '{}' and '{target_branch}': bring the branch up to date first",
            premier_git_bridge::plural(total_conflicts, "path"),
            req.branch
        ));
    }
    if total_blocked > 0 {
        causes.push(format!(
            "{} would carry the content of restricted files",
            premier_git_bridge::plural(total_blocked, "public path")
        ));
    }
    // As `execute_squash_declassify` refuses it. Only an owner hears this cause (see `reason`).
    if !overlay_blocked.is_empty() {
        causes.push(format!(
            "{} would publish team or personal overlay files",
            premier_git_bridge::plural(overlay_blocked.len(), "public path")
        ));
    }
    // Only when nothing else blocks: the plan's own causes keep their exact wording.
    if !report.passed && total_blocked == 0 {
        causes.push(format!(
            "the declassification firewall found {} (report {})",
            premier_git_bridge::plural(report.blocking_count, "blocking finding"),
            &report.report_digest[..report.report_digest.len().min(12)]
        ));
    }
    if causes.is_empty() && plan.changes.is_empty() {
        causes.push(if plan.scrubbed_paths.is_empty() {
            format!(
                "nothing to publish: '{}' has no changes that '{target_branch}' lacks",
                req.branch
            )
        } else {
            format!(
                "no public-readable changes: every path '{}' changed is held back",
                req.branch
            )
        });
    }
    let reason = match &member {
        Some(_) => Some("an owner must review this publish".to_owned()),
        None => (!causes.is_empty()).then(|| causes.join("; ")),
    };
    let pick = |paths: Vec<String>, cap: Capability| -> Vec<String> {
        paths.into_iter().filter(|p| shown(p, cap)).collect()
    };
    let published_paths = pick(
        plan.changes.into_iter().map(|(path, _)| path).collect(),
        Capability::LIST,
    );
    let scrubbed_paths = pick(plan.scrubbed_paths, Capability::READ);
    let merged_paths = pick(plan.merged_blobs.into_keys().collect(), Capability::LIST);
    let conflicts = pick(plan.conflicts, Capability::LIST);
    let blocked = pick(plan.blocked, Capability::LIST);
    // The causes the scrub rule can tell apart (`premier_git_bridge` `publishable`).
    let held_back_reasons = scrubbed_paths
        .iter()
        .map(|path| {
            let reserved = path
                .split('/')
                .any(premier_git_bridge::is_reserved_path_component);
            let why = if reserved {
                "a reserved server path"
            } else {
                "not readable by anonymous visitors"
            };
            (path.clone(), why)
        })
        .collect();

    // The attestation and message the publish itself would write, byte for byte.
    let source_signed = {
        CanonicalGitRepo::open(&root)
            .read_object(&source_oid)
            .ok()
            .is_some_and(|obj| {
                obj.kind == premier_git_bridge::GitObjectKind::Commit
                    && premier_git_bridge::objects::commit_has_gpgsig(&obj.data)
            })
    };
    let attestation = ProjectionAttestation::build(&source_oid, &short_fp, source_signed);
    let trailer = attestation.to_git_trailer();
    let clean_commit_message = premier_git_bridge::publish_commit_message(
        req.summary_message.as_deref().unwrap_or_default(),
        &target_ref,
        &attestation,
    );

    Ok(Json(SquashPreviewResponse {
        source_branch: req.branch,
        target_branch,
        private_commits_collapsed: ahead,
        published_paths,
        scrubbed_paths,
        merged_paths,
        // How many conflicting paths a member may not list is not theirs to count either.
        hidden_conflicts: if member.is_some() {
            0
        } else {
            total_conflicts - conflicts.len()
        },
        hidden_blocked: if member.is_some() {
            0
        } else {
            total_blocked - blocked.len()
        },
        blocked,
        declassification_gate_passed: member.is_none() && causes.is_empty() && report.passed,
        declassification_report: Some(match &member {
            Some(_) => report.redact_for_non_owner(),
            None => report,
        }),
        reason,
        publish_rule: PUBLISH_RULE,
        held_back_reasons,
        conflicts,
        attestation,
        attestation_trailer: trailer,
        clean_commit_message,
        airlock,
    }))
}

#[derive(Debug, Serialize)]
struct PromptProvenance {
    session_visible: bool,
    agent_profile: String,
    model: String,
    prompt_summary: String,
    tool_calls: Vec<String>,
    redaction_reason: Option<String>,
    /// The review has a session transcript (prompt, commands, output) this viewer may not see:
    /// only owners and the session's own principal may.
    provenance_hidden: bool,
    #[serde(default)]
    steps: Vec<store::ProvenanceStep>,
    // Trust-receipt fields: set only for a viewer who may see the session AND read the path.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_scrubbed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_calls: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_blocked: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReviewDiffHunk {
    id: String,
    path: String,
    zone: String,
    header: String,
    allowed: bool,
    lines: Vec<String>,
    provenance: PromptProvenance,
}

#[derive(Debug, Serialize)]
struct ReviewRound {
    round: u32,
    commit_oid: String,
    label: String,
    created_at: String,
    rebased_cleanly: bool,
    interdiff_summary: String,
    hunks: Vec<ReviewDiffHunk>,
    session_id: Option<String>,
    steering_prompt: Option<String>,
    addressed_comment_ids: Vec<String>,
    conflicts: Vec<premier_git_bridge::LaneConflict>,
}

#[derive(Debug, Serialize)]
struct ChangeReviewRecord {
    change_id: String,
    title: String,
    branch: String,
    base_ref: String,
    author: String,
    delegated_agent: Option<String>,
    visibility: Visibility,
    readiness: Readiness,
    quarantine_flagged: bool,
    /// The captured caged session, only for a viewer who may see it and read a hunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    comments: Vec<ReviewComment>,
    verdicts: BTreeMap<String, String>,
    rounds: Vec<ReviewRound>,
    lane_id: Option<String>,
    lane_status: Option<String>,
    lane_conflicts: Vec<premier_git_bridge::LaneConflict>,
}

#[derive(Debug, Deserialize)]
struct ReviewsQuery {
    #[serde(default = "default_principal")]
    principal: String,
    #[serde(default)]
    agent_profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct GitCommitSummary {
    oid: String,
    short_oid: String,
    subject: String,
    author: String,
    relative_time: String,
    /// Committer date, RFC 3339.
    committed_at: String,
    files_changed: usize,
}

#[derive(Debug, Serialize)]
struct GitCommitDiffResponse {
    oid: String,
    subject: String,
    author: String,
    date: String,
    files: Vec<GitCommitFileDiff>,
    /// Changed files left out because the viewer may not even list them.
    hidden_files: usize,
}

#[derive(Debug, Serialize)]
struct GitCommitFileDiff {
    path: String,
    allowed: bool,
    patch: String,
    /// Primary Zone label; set only for a readable file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    zone: String,
}

#[derive(Debug, Deserialize)]
struct CommitsQuery {
    /// Branch name or commit oid; absent (or `HEAD`) lists the checked-out branch as before.
    #[serde(default, rename = "ref")]
    rev: Option<String>,
    limit: Option<usize>,
    skip: Option<usize>,
    #[serde(default = "default_principal")]
    principal: String,
    #[serde(default)]
    agent_profile: Option<String>,
}

/// Resolve the `ref` query parameter to a revision `identity` may walk (AGENTS.md invariant 3).
///
/// Only an exact branch name the identity can see, or a commit oid contained in such a branch,
/// resolves. Rev expressions (`a..b`, `x~1`, `:/text`, full `refs/...` names) are never handed to
/// git, and a hidden ref answers exactly like a missing one, so this is not an existence oracle.
fn resolve_visible_rev(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    resolve_visible_refs(state, identity, raw).map(|(rev, _)| rev)
}

/// The short name policy is evaluated on for a full branch ref; `None` for anything else.
fn ref_short(full_ref: &str) -> Option<&str> {
    full_ref
        .strip_prefix("refs/heads/")
        .or_else(|| full_ref.strip_prefix(PRIVATE_REF_PREFIX))
}

/// [`resolve_visible_rev`], with the branches (short names) that make the revision visible to
/// `identity`: the branch itself, or for a commit oid every visible branch containing it. Path
/// rules are ref-scoped, so what the identity may see of a commit is decided on THESE refs,
/// never on the default branch.
fn resolve_visible_refs(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
) -> Result<(String, Vec<String>), (StatusCode, Json<ApiError>)> {
    visible_refs(state, identity, raw, true)
}

/// [`resolve_visible_refs`]. `from_caller`: a commit id in `raw` is the caller's own for it
/// ([`GitIds`]) and the revision returned is the canonical commit behind it; otherwise it is a
/// canonical id the server itself read.
fn visible_refs(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
    from_caller: bool,
) -> Result<(String, Vec<String>), (StatusCode, Json<ApiError>)> {
    visible_refs_in(state, identity, raw, from_caller, None)
}

/// Every full ref name of `refs/heads` and the private namespace: one `git for-each-ref`.
pub(crate) fn branch_ref_names(state: &ServerState, contains: Option<&str>) -> Option<Vec<String>> {
    let out = premier_git_bridge::git_command(&state.workspace_root)
        .args(["for-each-ref", "--format=%(refname)"])
        .args(contains)
        .args(["refs/heads", PRIVATE_REF_PREFIX])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// [`visible_refs`] over a ref listing the caller already read (`all`, from [`branch_ref_names`]),
/// so a loop over many branches costs one `git for-each-ref`, not one per branch.
fn visible_refs_in(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
    from_caller: bool,
    all: Option<&[String]>,
) -> Result<(String, Vec<String>), (StatusCode, Json<ApiError>)> {
    if raw.is_empty() || raw.starts_with('-') || raw.len() > 255 || raw.contains(char::is_control) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid ref"));
    }
    let not_found = || err_resp(StatusCode::NOT_FOUND, "ref not found");
    let vis_map = state.branch_visibility_map();
    let visible = |full_ref: &str| {
        let vis = vis_map
            .get(full_ref)
            .cloned()
            .unwrap_or_else(|| default_ref_visibility(full_ref));
        premier_git_bridge::can_see_ref(identity, &vis)
    };

    let fetched;
    let all: &[String] = match all {
        Some(all) => all,
        None => {
            fetched = branch_ref_names(state, None).ok_or_else(not_found)?;
            &fetched
        }
    };
    for ns in ["refs/heads/", PRIVATE_REF_PREFIX] {
        let full = format!("{ns}{raw}");
        if all.contains(&full) {
            return if visible(&full) {
                Ok((full, vec![raw.to_owned()]))
            } else {
                Err(not_found())
            };
        }
    }
    let is_oid = (7..=40).contains(&raw.len()) && raw.chars().all(|c| c.is_ascii_hexdigit());
    if is_oid {
        let canonical = if from_caller {
            GitIds::of(state, identity)?
                .canonical(raw)
                .ok_or_else(not_found)?
        } else {
            raw.to_owned()
        };
        let raw = canonical.as_str();
        let on: Vec<String> = branch_ref_names(state, Some(&format!("--contains={raw}")))
            .unwrap_or_default()
            .iter()
            .filter(|full| visible(full))
            .filter_map(|full| ref_short(full).map(str::to_owned))
            .collect();
        if !on.is_empty() {
            return Ok((raw.to_owned(), on));
        }
    }
    Err(not_found())
}

/// Whether policy lets `identity` into the root of branch `ref_name` at all, which is what
/// "has some access to it" means (an allowed path below synthesizes `traverse` on the root).
/// Fails closed without a policy.
pub(crate) fn enters_root(
    state: &ServerState,
    identity: &DelegatedIdentity,
    ref_name: &str,
) -> bool {
    state.current_policy().is_some_and(|p| {
        p.explain(identity, &RepoPath::root(), ref_name)
            .allows(Capability::TRAVERSE)
    })
}

/// [`resolve_visible_rev`] where seeing the ref is not enough: the identity must also have some
/// access to it ([`enters_root`]), or it answers exactly like a missing one.
pub(crate) fn resolve_accessible_rev(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    resolve_accessible_refs(state, identity, raw).map(|(rev, _)| rev)
}

/// [`resolve_accessible_rev`], with the branches that make it visible ([`resolve_visible_refs`]).
pub(crate) fn resolve_accessible_refs(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
) -> Result<(String, Vec<String>), (StatusCode, Json<ApiError>)> {
    // A bare commit is judged on the visible branches that contain it.
    let (rev, branches) = resolve_visible_refs(state, identity, raw)?;
    if branches
        .iter()
        .any(|branch| enters_root(state, identity, branch))
    {
        Ok((rev, branches))
    } else {
        Err(err_resp(StatusCode::NOT_FOUND, "ref not found"))
    }
}

/// [`resolve_accessible_rev`] succeeds for `raw`, over a ref listing the caller already read
/// ([`branch_ref_names`]): one `git for-each-ref` for a whole list of reviews or branches.
pub(crate) fn accessible_in(
    state: &ServerState,
    identity: &DelegatedIdentity,
    raw: &str,
    all: &[String],
) -> bool {
    visible_refs_in(state, identity, raw, true, Some(all)).is_ok_and(|(_, branches)| {
        branches
            .iter()
            .any(|branch| enters_root(state, identity, branch))
    })
}

/// At most this many `git` children at once from [`par_map`].
const MAX_GIT_PARALLEL: usize = 8;

/// `f` over `items`, a few at a time. A `git` spawn costs tens of milliseconds on Windows and
/// mostly waits on process start-up, so independent ones overlap instead of queueing. Order is
/// kept; a panicking worker yields `R::default()` for its items (the caller fails closed).
pub(crate) fn par_map<T: Sync, R: Send + Default>(
    items: &[T],
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    if items.len() < 2 {
        return items.iter().map(f).collect();
    }
    let f = &f;
    std::thread::scope(|scope| {
        let jobs: Vec<_> = items
            .chunks(items.len().div_ceil(MAX_GIT_PARALLEL))
            .map(|chunk| {
                let job = scope.spawn(move || chunk.iter().map(f).collect::<Vec<R>>());
                (chunk.len(), job)
            })
            .collect();
        jobs.into_iter()
            .flat_map(|(len, job)| {
                job.join()
                    .unwrap_or_else(|_| (0..len).map(|_| R::default()).collect())
            })
            .collect()
    })
}

/// One branch as a single `git for-each-ref` reports it.
pub(crate) struct BranchRow {
    pub(crate) full_ref: String,
    pub(crate) short_oid: String,
    /// Full tip commit id.
    pub(crate) tip: String,
    pub(crate) subject: String,
    pub(crate) head: bool,
    pub(crate) author: String,
    pub(crate) date: String,
    pub(crate) relative: String,
    /// Commits of the tip that HEAD lacks (`git rev-list --count HEAD..ref`); `None` where git
    /// cannot say (no `%(ahead-behind)`, or no HEAD yet).
    pub(crate) ahead: Option<usize>,
}

/// Every `refs/heads` and private-namespace branch with the facts the branch lists show, in ONE
/// `git for-each-ref` (they used to cost a `rev-parse` and a `rev-list` per branch). `%1f` (unit
/// separator) divides the fields: a subject may hold any printable character.
pub(crate) fn branch_rows(root: &Path) -> Option<Vec<BranchRow>> {
    const BASE: &str = "%(refname)%1f%(objectname:short)%1f%(objectname)%1f%(subject)%1f%(HEAD)%1f%(authorname)%1f%(committerdate:iso-strict)%1f%(committerdate:relative)";
    let run = |with_ahead: bool| {
        let format = if with_ahead {
            format!("--format={BASE}%1f%(ahead-behind:HEAD)")
        } else {
            format!("--format={BASE}")
        };
        premier_git_bridge::git_command(root)
            .args(["for-each-ref", &format])
            .args(["refs/heads", PRIVATE_REF_PREFIX])
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    // An old git, or a repository without a commit, rejects `ahead-behind:HEAD`: ask again without.
    let output = run(true).or_else(|| run(false))?;
    let rows = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\x1f').collect();
            if f.len() < 8 {
                return None;
            }
            Some(BranchRow {
                full_ref: f[0].trim().to_owned(),
                short_oid: f[1].to_owned(),
                tip: f[2].trim().to_owned(),
                subject: f[3].to_owned(),
                head: f[4].trim() == "*",
                author: f[5].to_owned(),
                date: f[6].to_owned(),
                relative: f[7].to_owned(),
                ahead: f
                    .get(8)
                    .and_then(|ab| ab.split_whitespace().next())
                    .and_then(|n| n.parse().ok()),
            })
        })
        .collect();
    Some(rows)
}

/// Whether an anonymous clone is served each of `rows`' branches (its tip shows them a file they
/// may read, the projection's rule), keyed by full ref. Fails closed: no policy, or a tip that
/// cannot be read, serves nobody. Concurrent, and tied to nothing but this request's policy.
pub(crate) fn served_map(
    state: &ServerState,
    policy: Option<&CompiledPolicy>,
    rows: &[&BranchRow],
) -> HashMap<String, bool> {
    let Some(policy) = policy else {
        return rows.iter().map(|r| (r.full_ref.clone(), false)).collect();
    };
    let external = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
    let canonical = CanonicalGitRepo::open(&state.workspace_root);
    let served = par_map(rows, |row| {
        let name = ref_short(&row.full_ref).unwrap_or(&row.full_ref);
        premier_git_bridge::tip_is_served(&canonical, policy, &external, name, &row.tip)
            .unwrap_or(false)
    });
    rows.iter()
        .map(|r| r.full_ref.clone())
        .zip(served)
        .collect()
}

/// What each of `refs` changed since its merge base with HEAD (`git diff --name-only HEAD...ref`),
/// every path, unfiltered: viewer rules are applied by the caller. One `git` per ref, side by side.
pub(crate) fn branch_changed_paths(root: &Path, refs: &[&str]) -> Vec<Vec<String>> {
    par_map(refs, |full_ref| {
        premier_git_bridge::git_command(root)
            .args(["-c", "core.quotePath=false", "diff", "--name-only"])
            .arg(format!("HEAD...{full_ref}"))
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Paths of the committed tree at a commit (`git ls-tree -r`), by commit id. Immutable for a
/// commit id and the same for every viewer: callers filter per viewer AFTER the lookup, so the
/// cache holds no access decision.
type TreePathCache = Mutex<HashMap<String, Arc<Vec<String>>>>;

/// [`TreePathCache`], bounded; a miss is read from git.
fn tree_paths(root: &Path, tip: &str) -> Arc<Vec<String>> {
    static CACHE: std::sync::OnceLock<TreePathCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(TreePathCache::default);
    let cacheable = matches!(tip.len(), 40 | 64) && tip.bytes().all(|b| b.is_ascii_hexdigit());
    if cacheable && let Some(hit) = cache.lock().ok().and_then(|c| c.get(tip).cloned()) {
        return hit;
    }
    let listed = premier_git_bridge::git_command(root)
        .args(["ls-tree", "-r", "--name-only", "-z"])
        .arg(tip)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            Arc::new(
                String::from_utf8_lossy(&o.stdout)
                    .split('\0')
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
        });
    match listed {
        Some(paths) => {
            if cacheable && let Ok(mut c) = cache.lock() {
                if c.len() >= 64 {
                    c.clear();
                }
                c.insert(tip.to_owned(), Arc::clone(&paths));
            }
            paths
        }
        None => Arc::default(),
    }
}

/// Read the trees of `tips` into [`tree_paths`]'s cache, side by side.
pub(crate) fn warm_tree_paths(root: &Path, tips: &[&str]) {
    par_map(tips, |tip| tree_paths(root, tip).len());
}

/// Whether policy lets `identity` list any file of the tree at `rev` (tip commit `tip`), policy
/// evaluated on `ref_name`.
pub(crate) fn lists_some_path(
    state: &ServerState,
    identity: &DelegatedIdentity,
    rev: &str,
    ref_name: &str,
    tip: &str,
) -> bool {
    who_lists(state, std::slice::from_ref(identity), rev, ref_name, tip)[0]
}

/// [`lists_some_path`] for each of `identities`, over one listing of the tree.
pub(crate) fn who_lists(
    state: &ServerState,
    identities: &[DelegatedIdentity],
    rev: &str,
    ref_name: &str,
    tip: &str,
) -> Vec<bool> {
    let mut lists = vec![false; identities.len()];
    let Some(policy) = state.current_policy() else {
        return lists;
    };
    if identities.is_empty() {
        return lists;
    }
    // The tip is the commit `rev` named when the caller listed refs; fall back to `rev` itself.
    let tree = tree_paths(
        &state.workspace_root,
        if tip.is_empty() { rev } else { tip },
    );
    for rp in tree.iter().filter_map(|p| RepoPath::new(p).ok()) {
        for (identity, lists) in identities
            .iter()
            .zip(&mut lists)
            .filter(|(_, lists)| !**lists)
        {
            *lists = policy
                .explain(identity, &rp, ref_name)
                .allows(Capability::LIST);
        }
        if lists.iter().all(|lists| *lists) {
            break;
        }
    }
    lists
}

/// A commit as `git log --no-walk` reports it: its one-line `meta` and the paths it changed.
#[derive(Clone, Default)]
pub(crate) struct CommitInfo {
    pub(crate) meta: String,
    pub(crate) paths: Vec<String>,
}

/// One `git log --no-walk --name-only` over `revs`: `(full hash, info)` per commit, where `meta`
/// is `fmt` (a `git log` format) trimmed. Paths: `--root` diffs a root commit against the
/// empty tree (it has no parent, and would otherwise list nothing) and a merge against its first
/// parent, so what it brought in is judged like any other change instead of passing as "no files". Empty on any git failure.
fn run_commit_infos(root: &Path, revs: &[&str], fmt: &str) -> Vec<(String, CommitInfo)> {
    if revs.is_empty() {
        return vec![];
    }
    let Some(out) = premier_git_bridge::git_command(root)
        .args([
            "-c",
            "core.quotePath=false",
            "log",
            "--no-walk=unsorted",
            "--name-only",
            "--root",
            "--diff-merges=first-parent",
        ])
        .arg(format!("--format=%x01%H%x02{fmt}"))
        .arg("--end-of-options")
        .args(revs)
        .output()
        .ok()
        .filter(|o| o.status.success())
    else {
        return vec![];
    };
    let mut infos: Vec<(String, CommitInfo)> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(header) = line.strip_prefix('\x01') {
            let (hash, meta) = header.split_once('\x02').unwrap_or((header, ""));
            infos.push((
                hash.trim().to_owned(),
                CommitInfo {
                    meta: meta.trim().to_owned(),
                    paths: vec![],
                },
            ));
        } else if let Some((_, info)) = infos.last_mut() {
            let path = line.trim();
            if !path.is_empty() {
                info.paths.push(path.to_owned());
            }
        }
    }
    infos
}

/// One commit (any revision git resolves): `None` when it does not exist.
pub(crate) fn commit_info(root: &Path, rev: &str, fmt: &str) -> Option<CommitInfo> {
    run_commit_infos(root, &[rev], fmt)
        .into_iter()
        .next()
        .map(|(_, info)| info)
}

/// [`commit_info`] for every commit of `oids` in ONE `git log` (it used to be a `git show` and a
/// `git diff-tree` per commit), keyed by the id as given. An id the batch did not answer for
/// (not a commit, or not hex) is looked up alone; one that is no commit is absent.
pub(crate) fn commit_infos(root: &Path, oids: &[&str], fmt: &str) -> HashMap<String, CommitInfo> {
    let mut wanted: Vec<&str> = oids.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    let found = run_commit_infos(root, &wanted, fmt);
    let mut map = HashMap::new();
    for oid in wanted {
        let hex = (7..=64).contains(&oid.len()) && oid.bytes().all(|b| b.is_ascii_hexdigit());
        let hit = found
            .iter()
            .find(|(hash, _)| hex && hash.starts_with(&oid.to_ascii_lowercase()))
            .map(|(_, info)| info.clone())
            .or_else(|| commit_info(root, oid, fmt));
        if let Some(info) = hit {
            map.insert(oid.to_owned(), info);
        }
    }
    map
}

/// The `diff --git a/P b/P` (or combined `diff --cc P`) header's path `P`; `None` for any other
/// line, and for a header whose path git had to quote (the caller then asks for that file alone).
fn patch_header_path(line: &str) -> Option<String> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    if let Some(rest) = line.strip_prefix("diff --git ") {
        // `a/P b/P` with one P: its length is fixed by the whole line's.
        let len = rest.len().checked_sub(5)? / 2;
        let path = rest.get(2..2 + len)?;
        return (rest == format!("a/{path} b/{path}")).then(|| path.to_owned());
    }
    line.strip_prefix("diff --cc ")
        .or_else(|| line.strip_prefix("diff --combined "))
        .filter(|p| !p.starts_with('"'))
        .map(str::to_owned)
}

/// A multi-file unified diff cut into its per-file patches, each exactly as `git show -- <path>`
/// prints it, keyed by path. A content line never starts with `diff --git`.
fn split_patch_sections(raw: &str) -> HashMap<String, String> {
    let mut sections = HashMap::new();
    let mut current: Option<(String, usize)> = None;
    let mut pos = 0;
    for line in raw.split_inclusive('\n') {
        if let Some(path) = patch_header_path(line) {
            if let Some((prev, start)) = current.take() {
                sections.insert(prev, raw[start..pos].to_owned());
            }
            current = Some((path, pos));
        }
        pos += line.len();
    }
    if let Some((prev, start)) = current {
        sections.insert(prev, raw[start..].to_owned());
    }
    sections
}

/// The patches `git show` gives for `paths` of commit `oid`, `flags` as on its command line, in
/// ONE `git` (it used to be one per file). Only the `paths` the caller already decided to show
/// are asked for, so no other file's bytes are read. Paths are literal (a file named `*.rs` is
/// that file), renames are not followed (each path's own diff, as before). A path git did not
/// answer for (quoted header, merge with no combined change) is asked for alone.
pub(crate) fn commit_file_patches(
    root: &Path,
    oid: &str,
    paths: &[&str],
    flags: &[&str],
) -> HashMap<String, String> {
    let show = |paths: &[&str]| {
        premier_git_bridge::git_command(root)
            .args(["--literal-pathspecs", "-c", "core.quotePath=false"])
            .args(["show", "--format=", "--no-renames"])
            .args(flags)
            .args(["--end-of-options", oid, "--"])
            .args(paths)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let mut sections = if paths.len() > 1 {
        show(paths)
            .map(|raw| split_patch_sections(&raw))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let mut patches = HashMap::new();
    for path in paths {
        let patch = sections
            .remove(*path)
            .or_else(|| show(&[*path]))
            .unwrap_or_default();
        patches.insert((*path).to_owned(), patch);
    }
    patches
}

/// What `identity` may do with `path` on `branch`. Fails closed: nothing without a compiled
/// policy or for a path that does not parse.
pub(crate) fn path_caps(
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    path: &str,
    branch: &str,
) -> Capability {
    match (policy, RepoPath::new(path)) {
        (Some(policy), Ok(rp)) => policy.explain(identity, &rp, branch).effective,
        _ => Capability::empty(),
    }
}

/// Read real commits directly from the local repository on disk (`git log`).
async fn list_commits_handler(
    State(state): State<ServerState>,
    Query(q): Query<CommitsQuery>,
) -> Result<Json<Vec<GitCommitSummary>>, (StatusCode, Json<ApiError>)> {
    let limit = q.limit.unwrap_or(25).min(200);
    // An offset in the commits this identity is shown, so pages neither overlap nor fall short.
    let skip = q.skip.unwrap_or(0);
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-commits")?;
    let (rev, branches) = match q.rev.as_deref().filter(|r| *r != "HEAD") {
        Some(raw) => resolve_visible_refs(&state, &identity, raw)?,
        // The checked-out branch gets the same visibility check; a hidden (or unborn) HEAD
        // lists nothing.
        None => {
            let git = |args: &[&str]| {
                let out = premier_git_bridge::git_command(&state.workspace_root)
                    .args(args)
                    .output()
                    .ok()
                    .filter(|o| o.status.success())?;
                Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            };
            let head = git(&["symbolic-ref", "-q", "--short", "HEAD"])
                .or_else(|| git(&["rev-parse", "-q", "--verify", "HEAD"]));
            match head.map(|head| visible_refs(&state, &identity, &head, false)) {
                Some(Ok(found)) => found,
                _ => return Ok(Json(vec![])),
            }
        }
    };
    let ids = GitIds::of(&state, &identity)?;
    Ok(Json(visible_commits(
        &state, &identity, &ids, &rev, &branches, skip, limit,
    )))
}

/// How many commits of `range` a member is shown on `branch` (capped: it is a badge, not a census).
fn shown_ahead(
    state: &ServerState,
    me: &DelegatedIdentity,
    ids: &GitIds,
    range: &str,
    branch: &str,
) -> usize {
    visible_commits(state, me, ids, range, &[branch.to_owned()], 0, 1000).len()
}

/// The commits of `rev` that `identity` is shown, newest first: `limit` of them after `skip`.
/// Path rules are evaluated on `branches`, the refs that make `rev` visible to the identity
/// ([`resolve_visible_refs`]): a commit is shown when one of them lets the identity list a file
/// it changed, and counted under that ref's rules. Each carries the id the identity's clone of
/// one of `branches` has for it (`ids`); a commit that is in none of them is not listed.
fn visible_commits(
    state: &ServerState,
    identity: &DelegatedIdentity,
    ids: &GitIds,
    rev: &str,
    branches: &[String],
    skip: usize,
    limit: usize,
) -> Vec<GitCommitSummary> {
    let policy = state.current_policy();
    // A commit that changes no file (`--allow-empty`) has nothing to list: its subject is for
    // those with some access to one of the branches. A merge is not such a commit: it is
    // diffed against its first parent, so one that only brings in hidden paths stays hidden.
    let empty_ok = branches
        .iter()
        .any(|branch| enters_root(state, identity, branch));
    let listable = |paths: &[String]| {
        branches
            .iter()
            .map(|branch| {
                let lists = |p: &&String| {
                    path_caps(policy.as_deref(), identity, p, branch).contains(Capability::LIST)
                };
                paths.iter().filter(lists).count()
            })
            .find(|n| *n > 0)
            .unwrap_or(0)
    };
    let shown: Option<Vec<HashMap<String, String>>> = ids.0.as_ref().map(|view| {
        let on = |branch: &String| view.commits_on(&format!("refs/heads/{branch}"));
        branches.iter().map(on).collect()
    });
    let mine = |canonical: &str| match &shown {
        None => Some(canonical.to_owned()),
        Some(maps) => maps.iter().find_map(|map| map.get(canonical).cloned()),
    };
    // One `git log` for the whole page: a `\x01` line per commit, then the paths it changed.
    let Ok(mut child) = premier_git_bridge::git_command(&state.workspace_root)
        .args(["-c", "core.quotePath=false", "log", "--name-only", "--root"])
        .arg("--diff-merges=first-parent")
        // The subject last: it is the field most likely to hold a `|`.
        .args(["--format=%x01%H|%h|%cI|%cr|%an|%s", "--end-of-options", rev])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return vec![];
    };
    let Some(stdout) = child.stdout.take() else {
        return vec![];
    };
    // A commit that only touches files the identity may not list is left out, subject and author
    // included, and `files_changed` counts only the files it may list.
    let mut list = Vec::new();
    let mut visible = 0usize;
    let mut finish = |pending: Option<(GitCommitSummary, Vec<String>)>| {
        if let Some((mut commit, changed)) = pending
            && {
                commit.files_changed = listable(&changed);
                commit.files_changed > 0 || (changed.is_empty() && empty_ok)
            }
            && let Some(oid) = mine(&commit.oid)
        {
            if oid != commit.oid {
                commit.short_oid = oid[..7].to_owned();
                commit.oid = oid;
            }
            visible += 1;
            if visible > skip {
                list.push(commit);
            }
        }
        visible >= skip.saturating_add(limit)
    };
    // shortcut: gives up after 20x the requested window of raw commits, so a page can still fall
    // short in a history that is almost entirely hidden; return a cursor if that matters.
    let budget = skip.saturating_add(limit).saturating_mul(20);
    let mut scanned = 0usize;
    let mut pending: Option<(GitCommitSummary, Vec<String>)> = None;
    let lines = std::io::BufRead::split(std::io::BufReader::new(stdout), b'\n');
    for line in lines.map_while(Result::ok) {
        let line = String::from_utf8_lossy(&line);
        let Some(header) = line.strip_prefix('\x01') else {
            let path = line.trim();
            if let Some((_, changed)) = pending.as_mut().filter(|_| !path.is_empty()) {
                changed.push(path.to_owned());
            }
            continue;
        };
        scanned += 1;
        if finish(pending.take()) || scanned > budget {
            break;
        }
        let p: Vec<&str> = header.splitn(6, '|').collect();
        if p.len() == 6 {
            let commit = GitCommitSummary {
                oid: p[0].trim().to_owned(),
                short_oid: p[1].trim().to_owned(),
                committed_at: p[2].trim().to_owned(),
                relative_time: p[3].trim().to_owned(),
                author: p[4].trim().to_owned(),
                subject: p[5].trim().to_owned(),
                files_changed: 0,
            };
            pending = Some((commit, Vec::new()));
        }
    }
    finish(pending);
    // Usually stopped early: do not leave `git log` writing the rest of history into a pipe.
    let _ = child.kill();
    let _ = child.wait();
    list
}

/// `GET /v1/attestations/{oid}`: the attestation for a projected commit in the caller's own view
/// of the repository, so a clone can be verified now that projected commits carry no trailer. A
/// commit outside the caller's projection answers exactly like one that does not exist.
async fn attestation_handler(
    State(state): State<ServerState>,
    AxumPath(oid): AxumPath<String>,
) -> Result<Json<ProjectionAttestation>, (StatusCode, Json<ApiError>)> {
    let not_found = || err_resp(StatusCode::NOT_FOUND, "attestation not found");
    let identity = caller_identity(&state, "attestation")?;
    let policy = state.current_policy().ok_or_else(not_found)?;
    // The fingerprint a fetch is projected under (`git_upload_pack_handler`).
    let fp_short = state.policy_fingerprint();
    let vis_map = state.branch_visibility_map();
    let root = state.workspace_root.clone();
    tokio::task::spawn_blocking(move || {
        let canonical = CanonicalGitRepo::open(&root);
        let view = project_repository(&canonical, &policy, &fp_short, &identity, &vis_map).ok()?;
        view.attestation(&oid)
    })
    .await
    .ok()
    .flatten()
    .map(Json)
    .ok_or_else(not_found)
}

/// Read a real commit's per-file patches from disk, enforcing `CompiledPolicy` READ on every file.
async fn read_commit_diff_handler(
    State(state): State<ServerState>,
    AxumPath(oid): AxumPath<String>,
    Query(q): Query<ReviewsQuery>,
) -> Result<Json<GitCommitDiffResponse>, (StatusCode, Json<ApiError>)> {
    if !oid.chars().all(|c| c.is_ascii_hexdigit()) || oid.len() < 7 || oid.len() > 40 {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid commit oid"));
    }

    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-commit-diff")
        .unwrap_or_else(|_| DelegatedIdentity::human_only(Principal::Anonymous, vec![]));
    // Only a commit on a branch the identity can see (invariant 3); one that is only on hidden
    // refs answers exactly like one that does not exist.
    // `given` is the id as the caller has it; `oid` the canonical commit read below.
    let Ok((canonical, branches)) = resolve_visible_refs(&state, &identity, &oid) else {
        return Err(err_resp(StatusCode::NOT_FOUND, "commit not found"));
    };
    let (given, oid) = (oid, canonical);

    // Subject, author, date and the paths it changed: one `git log` (a root commit against the
    // empty tree, a merge against its first parent: see `run_commit_infos`).
    let Some(info) = commit_info(&state.workspace_root, &oid, "%s|%an|%ci") else {
        return Err(err_resp(StatusCode::NOT_FOUND, "commit not found"));
    };
    let parts: Vec<&str> = info.meta.splitn(3, '|').collect();
    let subject = parts.first().copied().unwrap_or("").to_owned();
    let author = parts.get(1).copied().unwrap_or("").to_owned();
    let date = parts.get(2).copied().unwrap_or("").to_owned();

    // A file the viewer cannot `list` is left out, name included (invariant 4), and only counted.
    // That count is the one hidden-derived number a member gets, and only for a commit they see
    // part of (one they see nothing of is a 404 below). One they can list but not read keeps its
    // path and loses its hunks.
    //
    // Rules are ref-scoped: the commit is judged on ONE visible branch containing it, the first
    // that lets the viewer list a file it changed, and hunks are shown under that same branch's
    // rules. Never on the default branch: `docs/**` readable there may be denied on this one.
    let policy = state.current_policy();
    let changed = info.paths;
    let lists_any = |branch: &&String| {
        changed
            .iter()
            .any(|p| path_caps(policy.as_deref(), &identity, p, branch).contains(Capability::LIST))
    };
    let Some(branch) = branches
        .iter()
        .find(lists_any)
        .or(branches.first())
        .cloned()
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "commit not found"));
    };
    // Decide every file's fate first, from policy alone (at most 30 are shown, a file the viewer
    // may list but not read keeps its path and loses its hunks) ...
    let mut shown: Vec<(String, bool)> = Vec::new();
    let mut hidden_files = 0usize;
    for file_path in changed {
        let caps = path_caps(policy.as_deref(), &identity, &file_path, &branch);
        if !caps.contains(Capability::LIST) {
            hidden_files += 1;
            continue;
        }
        if shown.len() >= 30 {
            continue;
        }
        shown.push((file_path, caps.contains(Capability::READ)));
    }
    // ... then read the patches of the readable ones in ONE `git show` (it was one per file, each
    // tens of milliseconds on Windows). A file the viewer may not read is never asked of git.
    let readable: Vec<&str> = shown
        .iter()
        .filter(|(_, readable)| *readable)
        .map(|(path, _)| path.as_str())
        .collect();
    let mut patches = commit_file_patches(
        &state.workspace_root,
        &oid,
        &readable,
        &["--diff-merges=first-parent"],
    );
    let mut files = Vec::new();
    for (file_path, readable) in shown {
        if !readable {
            files.push(GitCommitFileDiff {
                path: file_path,
                allowed: false,
                patch: String::new(),
                zone: String::new(),
            });
            continue;
        }
        let mut patch = patches.remove(&file_path).unwrap_or_default();
        if patch.len() > 16_000 {
            let mut cut = 16_000;
            while !patch.is_char_boundary(cut) {
                cut -= 1;
            }
            patch.truncate(cut);
            patch.push_str("\n... (truncated)");
        }
        let zone = policy
            .as_ref()
            .zip(RepoPath::new(&file_path).ok())
            .and_then(|(pol, r)| pol.primary_zone(&r).map(str::to_owned))
            .unwrap_or_default();
        files.push(GitCommitFileDiff {
            path: file_path,
            allowed: true,
            patch,
            zone,
        });
    }

    // Nothing of it the viewer may list: the commit answers like one that does not exist.
    if files.is_empty() && (hidden_files > 0 || !enters_root(&state, &identity, &branch)) {
        return Err(err_resp(StatusCode::NOT_FOUND, "commit not found"));
    }

    Ok(Json(GitCommitDiffResponse {
        oid: given,
        subject,
        author,
        date,
        files,
        hidden_files,
    }))
}

/// Split a single-file unified diff from `git show` into `(header, lines)` entries per `@@ ... @@`
/// hunk so multi-hunk files keep each hunk's own header and line offsets intact.
fn split_review_patch_hunks(
    patch_raw: &str,
    short_oid: &str,
    path: &str,
) -> Vec<(String, Vec<String>)> {
    const MAX_LINES_PER_HUNK: usize = 28;
    let mut parsed: Vec<(String, Vec<String>)> = Vec::new();
    let mut cur_hdr: Option<String> = None;
    let mut cur_body: Vec<String> = Vec::new();
    let mut cur_truncated = false;

    for l in patch_raw.lines() {
        if l.starts_with("@@") {
            if let Some(hdr) = cur_hdr.take() {
                parsed.push((hdr, std::mem::take(&mut cur_body)));
            }
            cur_hdr = Some(l.to_owned());
            cur_truncated = false;
        } else if cur_hdr.is_some() {
            if cur_truncated {
                continue;
            }
            if cur_body.len() >= MAX_LINES_PER_HUNK {
                cur_body.push("... (view full patch in Commits)".to_owned());
                cur_truncated = true;
            } else {
                cur_body.push(l.to_owned());
            }
        }
    }
    if let Some(hdr) = cur_hdr {
        parsed.push((hdr, cur_body));
    }
    if parsed.is_empty() {
        parsed.push((
            format!("@@ {short_oid} -- {path} @@"),
            vec![" (binary or empty change)".to_owned()],
        ));
    }
    parsed
}

/// 100% REAL persisted `Change-Id` Review Rounds hydrated directly from `.premier/state.json`
/// and local Git commits on disk. Enforces server-side path ACLs
/// on every file hunk and hides private prompt sessions from unauthenticated or unrelated callers.
async fn list_reviews_handler(
    State(state): State<ServerState>,
    Query(q): Query<ReviewsQuery>,
) -> Json<Vec<ChangeReviewRecord>> {
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-review")
        .unwrap_or_else(|_| DelegatedIdentity::human_only(Principal::Anonymous, vec![]));
    let principal = identity.principal.clone();
    let policy = state.current_policy();
    let can_see_prompt_session = principal.is_authenticated();
    // A transcript can quote any file the session read (`cat secret/plan.md`), whatever the
    // viewer may read. Judged for the identity shown: an owner's "view as" lens hides it too.
    let me = auth::actor_principal();
    let sees_transcript = |cap: &crate::store::CapturedProvenance| {
        principal.to_string() == me
            && (auth::caller_is_owner() || cap.principal.as_deref() == Some(me.as_str()))
    };
    let Ok(ids) = GitIds::of(&state, &identity) else {
        return Json(vec![]);
    };

    let (stored_reviews, stored_lanes): (Vec<StoredReview>, Vec<store::AgentLane>) = state
        .persisted
        .lock()
        .map(|s| (s.reviews.clone(), s.lanes.clone()))
        .unwrap_or_default();

    // A review of a branch the identity cannot see, or has no access to, does not exist for it
    // (invariant 3). One listing of the refs answers for every review's branch.
    let all_refs = branch_ref_names(&state, None);
    let mut accessible_branches: HashMap<String, bool> = HashMap::new();
    let stored_reviews: Vec<StoredReview> = stored_reviews
        .into_iter()
        .filter(|rev| {
            *accessible_branches
                .entry(rev.branch.clone())
                .or_insert_with(|| {
                    all_refs
                        .as_deref()
                        .is_some_and(|all| accessible_in(&state, &identity, &rev.branch, all))
                })
        })
        .collect();
    // Every round's subject, age and changed paths: one `git log` for all of them.
    let all_round_oids: Vec<&str> = stored_reviews
        .iter()
        .flat_map(|rev| rev.round_oids.iter().map(String::as_str))
        .collect();
    let infos = commit_infos(&state.workspace_root, &all_round_oids, "%s|%cr");
    // `(record, round index, previous shown oid, oid, fallback count, branch)` of the rounds whose
    // interdiff is counted once the loop is done, all at once.
    let mut pending_interdiff: Vec<(usize, usize, String, String, usize, String)> = Vec::new();
    let mut records = Vec::new();
    for rev in stored_reviews {
        // Filter comments strictly by caller READ ACL on `&rev.branch` first so round metadata
        // `addressed_comment_ids` only references comments visible to this viewer.
        let visible_comments: Vec<ReviewComment> = rev
            .comments
            .into_iter()
            .filter(|c| match (&policy, RepoPath::new(&c.path).ok()) {
                (Some(pol), Some(rp)) => pol
                    .explain(&identity, &rp, &rev.branch)
                    .allows(Capability::READ),
                _ => false,
            })
            .collect();
        let visible_comment_ids: HashSet<String> =
            visible_comments.iter().map(|c| c.id.clone()).collect();

        let mut quarantine_flagged = false;
        let mut any_allowed_hunk = false;
        let mut rounds = Vec::new();
        let mut prev_shown_oid: Option<&str> = None;

        for (idx, oid) in rev.round_oids.iter().enumerate() {
            let raw_round_num = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            let round_meta = rev
                .rounds_meta
                .iter()
                .find(|m| m.round == raw_round_num || m.commit_oid == *oid);
            let cap_opt = round_meta
                .and_then(|m| m.provenance.as_ref())
                .or(rev.provenance.as_ref());

            // The round's commit as the viewer's clone has it.
            let short_oid: String = ids.shown(oid).chars().take(7).collect();
            let info = infos.get(oid.as_str());
            let meta = info.map_or("", |i| i.meta.as_str());
            let (subj, rel_time) = meta.split_once('|').unwrap_or((&rev.title, "now"));

            let touched: &[String] = info.map(|i| i.paths.as_slice()).unwrap_or(&[]);

            // The files that get hunks (the first 8 the viewer may list, if they may read them)
            // have their patches read together, in ONE `git show`.
            let mut selected: Vec<&str> = Vec::new();
            let mut listed = 0usize;
            for path in touched {
                if listed >= 8 {
                    break;
                }
                let Some(dec) = policy
                    .as_ref()
                    .zip(RepoPath::new(path).ok())
                    .map(|(pol, r)| pol.explain(&identity, &r, &rev.branch))
                    .filter(|dec| dec.allows(Capability::LIST))
                else {
                    continue;
                };
                listed += 1;
                if dec.allows(Capability::READ) {
                    selected.push(path.as_str());
                }
            }
            let mut patches = commit_file_patches(&state.workspace_root, oid, &selected, &["-U2"]);

            let mut hunks = Vec::new();
            let mut files_shown = 0usize;
            for path in touched {
                if files_shown >= 8 || hunks.len() >= 24 {
                    break;
                }
                let rp = RepoPath::new(path).ok();
                // Evaluate strictly against `rev.branch` (never `default_branch`) and require
                // `Capability::LIST` so `TRAVERSE`-only filenames are never leaked.
                let Some(dec) = policy
                    .as_ref()
                    .zip(rp.as_ref())
                    .map(|(pol, r)| pol.explain(&identity, r, &rev.branch))
                    .filter(|dec| dec.allows(Capability::LIST))
                else {
                    continue;
                };
                files_shown += 1;
                if let (Some(pol), Some(r)) = (&policy, &rp)
                    && pol.is_instruction_file(r)
                {
                    quarantine_flagged = true;
                }
                let allowed = dec.allows(Capability::READ);
                any_allowed_hunk |= allowed;
                let file_hunks: Vec<(String, Vec<String>)> = if allowed {
                    let patch_raw = patches.remove(path.as_str()).unwrap_or_default();
                    split_review_patch_hunks(&patch_raw, &short_oid, path)
                } else {
                    vec![(
                        "@@ redacted @@".to_owned(),
                        vec![format!(
                            "// [SERVER-REDACTED] Caller '{}' lacks READ on '{}'",
                            identity.principal, path
                        )],
                    )]
                };

                for (header_line, lines) in file_hunks {
                    if hunks.len() >= 24 {
                        break;
                    }
                    let provenance = if can_see_prompt_session && allowed {
                        if let Some(cap) = cap_opt {
                            if sees_transcript(cap) {
                                PromptProvenance {
                                    session_visible: true,
                                    agent_profile: cap.agent_profile.clone(),
                                    model: cap.session_id.clone(),
                                    prompt_summary: cap.prompt_summary.clone(),
                                    // A session's command and output are not filtered per path: an
                                    // owner's session may print files a member may not read.
                                    tool_calls: if auth::caller_is_owner() {
                                        cap.tool_calls.clone()
                                    } else {
                                        Vec::new()
                                    },
                                    redaction_reason: None,
                                    provenance_hidden: false,
                                    steps: lanes::filter_steps_for_viewer(
                                        policy.as_deref(),
                                        &identity,
                                        &rev.branch,
                                        &cap.steps,
                                    ),
                                    session_id: Some(cap.session_id.clone()),
                                    sandbox: cap.sandbox.clone(),
                                    bytes_scrubbed: Some(cap.bytes_scrubbed),
                                    egress_calls: Some(cap.egress_calls),
                                    egress_blocked: Some(cap.egress_blocked),
                                    exit_code: cap.exit_code,
                                    created_at: Some(cap.created_at.clone()),
                                }
                            } else {
                                PromptProvenance {
                                    session_visible: false,
                                    agent_profile: cap.agent_profile.clone(),
                                    model: "redacted".to_owned(),
                                    prompt_summary: String::new(),
                                    tool_calls: vec![],
                                    redaction_reason: Some(
                                        "Only owners and the session's own principal see its transcript"
                                            .to_owned(),
                                    ),
                                    provenance_hidden: true,
                                    steps: lanes::filter_steps_for_viewer(
                                        policy.as_deref(),
                                        &identity,
                                        &rev.branch,
                                        &cap.steps,
                                    ),
                                    session_id: None,
                                    sandbox: None,
                                    bytes_scrubbed: None,
                                    egress_calls: None,
                                    egress_blocked: None,
                                    exit_code: None,
                                    created_at: None,
                                }
                            }
                        } else {
                            PromptProvenance {
                                session_visible: true,
                                agent_profile: rev
                                    .delegated_agent
                                    .clone()
                                    .unwrap_or_else(|| format!("human:{}", rev.author)),
                                model: format!("git:{short_oid}"),
                                prompt_summary: subj.to_owned(),
                                tool_calls: vec![format!("git show {short_oid} -- {path}")],
                                redaction_reason: None,
                                provenance_hidden: false,
                                steps: Vec::new(),
                                session_id: None,
                                sandbox: None,
                                bytes_scrubbed: None,
                                egress_calls: None,
                                egress_blocked: None,
                                exit_code: None,
                                created_at: None,
                            }
                        }
                    } else {
                        PromptProvenance {
                            session_visible: false,
                            agent_profile: rev
                                .delegated_agent
                                .clone()
                                .unwrap_or_else(|| "restricted".to_owned()),
                            model: "redacted".to_owned(),
                            prompt_summary: "[Session Provenance Redacted — Viewer lacks ACL]"
                                .to_owned(),
                            tool_calls: vec![],
                            redaction_reason: Some(if !allowed {
                                format!("Path '{path}' is outside caller's authorized zone")
                            } else {
                                "Unauthenticated viewers cannot inspect private session provenance"
                                    .to_owned()
                            }),
                            provenance_hidden: rev.provenance.is_some(),
                            steps: Vec::new(),
                            session_id: None,
                            sandbox: None,
                            bytes_scrubbed: None,
                            egress_calls: None,
                            egress_blocked: None,
                            exit_code: None,
                            created_at: None,
                        }
                    };

                    hunks.push(ReviewDiffHunk {
                        id: format!("r{}-h{}", rounds.len() + 1, hunks.len()),
                        path: path.clone(),
                        // A label only for a path the identity may read; never for a redacted one.
                        zone: if allowed {
                            policy
                                .as_ref()
                                .zip(rp.as_ref())
                                .and_then(|(pol, r)| pol.primary_zone(r))
                                .unwrap_or("")
                                .to_owned()
                        } else {
                            String::new()
                        },
                        header: header_line,
                        allowed,
                        lines,
                        provenance,
                    });
                }
            }

            // A round whose changes the identity can list none of is not theirs to know of, and
            // rounds are numbered among those shown.
            if hunks.is_empty() && !touched.is_empty() {
                continue;
            }
            let interdiff_summary = if let Some(prev_oid) = prev_shown_oid {
                // Counted after the loop (`pending_interdiff`), side by side with the rest.
                pending_interdiff.push((
                    records.len(),
                    rounds.len(),
                    prev_oid.to_owned(),
                    oid.clone(),
                    hunks.len(),
                    rev.branch.clone(),
                ));
                String::new()
            } else {
                format!(
                    "{} inspected on disk",
                    premier_git_bridge::plural(hunks.len(), "file")
                )
            };
            let addressed_comment_ids = round_meta
                .map(|m| {
                    m.addressed_comment_ids
                        .iter()
                        .filter(|id| visible_comment_ids.contains(*id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let round_conflicts = round_meta
                .map(|m| {
                    lanes::filter_conflicts_for_viewer(
                        policy.as_deref(),
                        &identity,
                        &rev.branch,
                        &m.conflicts,
                    )
                })
                .unwrap_or_default();

            rounds.push(ReviewRound {
                round: (rounds.len() + 1) as u32,
                commit_oid: short_oid,
                label: format!(
                    "Round {} — {}",
                    rounds.len() + 1,
                    subj.chars().take(48).collect::<String>()
                ),
                created_at: rel_time.to_owned(),
                rebased_cleanly: round_meta.is_none_or(|m| m.rebased_cleanly),
                interdiff_summary,
                hunks,
                session_id: round_meta.and_then(|m| m.session_id.clone()),
                // A steering prompt is session transcript text: same gate as the hunk provenance.
                steering_prompt: round_meta
                    .and_then(|m| m.steering_prompt.clone())
                    .filter(|_| {
                        can_see_prompt_session
                            && cap_opt.map_or_else(
                                || principal.to_string() == me && auth::caller_is_owner(),
                                sees_transcript,
                            )
                    }),
                addressed_comment_ids,
                conflicts: round_conflicts,
            });
            prev_shown_oid = Some(oid.as_str());
        }

        let matched_lane = stored_lanes.iter().find(|l| {
            let linked = rev.lane_id.as_deref() == Some(l.lane_id.as_str())
                || l.change_id.as_deref() == Some(rev.change_id.as_str());
            linked && lanes::lane_visible_to(&state, &identity, l)
        });
        let lane_id = matched_lane.map(|l| l.lane_id.clone()).or_else(|| {
            auth::caller_is_owner()
                .then(|| rev.lane_id.clone())
                .flatten()
        });
        let lane_status = matched_lane.map(|l| l.status.clone());
        let lane_conflicts = matched_lane
            .map(|l| {
                lanes::filter_conflicts_for_viewer(
                    policy.as_deref(),
                    &identity,
                    &rev.branch,
                    &l.conflicts,
                )
            })
            .unwrap_or_default();

        let session_id = any_allowed_hunk
            .then_some(rev.provenance.as_ref())
            .flatten()
            .filter(|c| can_see_prompt_session && sees_transcript(c))
            .map(|c| c.session_id.clone())
            .filter(|sid| sid != "manual");
        records.push(ChangeReviewRecord {
            change_id: rev.change_id,
            title: rev.title,
            branch: rev.branch,
            base_ref: rev.base_ref,
            author: rev.author,
            delegated_agent: rev.delegated_agent,
            visibility: rev.visibility,
            readiness: rev.readiness,
            quarantine_flagged,
            session_id,
            comments: visible_comments,
            verdicts: rev.verdicts,
            rounds,
            lane_id,
            lane_status,
            lane_conflicts,
        });
    }

    // How many files each round changed since the one shown before it (that the viewer may list).
    let counts = par_map(
        &pending_interdiff,
        |(_, _, prev_oid, oid, fallback, branch)| {
            premier_git_bridge::git_command(&state.workspace_root)
                .args([
                    "diff",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    "--end-of-options",
                    prev_oid,
                    oid,
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .split('\0')
                        .filter(|p| !p.is_empty())
                        .filter(|p| {
                            path_caps(policy.as_deref(), &identity, p, branch)
                                .contains(Capability::LIST)
                        })
                        .count()
                })
                .unwrap_or(*fallback)
        },
    );
    for ((record, round, ..), changed_visible) in pending_interdiff.iter().zip(counts) {
        records[*record].rounds[*round].interdiff_summary = format!(
            "{} changed since R{}",
            premier_git_bridge::plural(changed_visible, "file"),
            round
        );
    }

    Json(records)
}

/// Smart HTTP v2 `POST /git/repo.git/git-upload-pack` — dynamically projects the canonical
/// Git repository for the caller's principal & policy with strict anti-CFOR isolation.
async fn git_upload_pack_handler(
    State(state): State<ServerState>,
    Extension(auth::GitCaller(identity)): Extension<auth::GitCaller>,
    // The path the client used (`/git/<name>.git/â€¦`, `/r/<name>/â€¦`), not the dispatched one.
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    body: Bytes,
) -> Response {
    let Some(policy) = state.current_policy() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no .access.toml policy loaded on server",
        )
            .into_response();
    };

    let policy_fp_short = state.policy_fingerprint();
    let vis_map = state.branch_visibility_map();

    let workspace_root = state.workspace_root.clone();
    let policy_clone = Arc::clone(&policy);
    let identity_clone = identity.clone();
    let body_clone = body.clone();

    let result = tokio::task::spawn_blocking(move || {
        let canonical = CanonicalGitRepo::open(&workspace_root);
        let view = project_repository(
            &canonical,
            &policy_clone,
            &policy_fp_short,
            &identity_clone,
            &vis_map,
        )?;
        // HEAD is the default branch, under the name it is advertised by.
        let default_ref = canon::default_ref(&workspace_root)
            .as_deref()
            .and_then(ref_short)
            .map(|short| format!("refs/heads/{short}"));
        let resp_bytes = handle_upload_pack_v2(&view, default_ref.as_deref(), &body_clone)?;
        Ok::<_, premier_git_bridge::GitBridgeError>((resp_bytes, view.refs.len(), view.odb.len()))
    })
    .await;

    let result = match result {
        Ok(inner) => inner,
        Err(join_err) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, join_err.to_string()).into_response();
        }
    };

    match result {
        Ok((resp_bytes, ref_count, obj_count)) => {
            let mut ev = AuditEvent::now(
                &identity,
                "premier-git-bridge",
                "git_upload_pack_v2",
                AuditDecision::Allowed,
                format!(
                    "Projected Git v2 response for {} ({}, {obj_count} isolated objects)",
                    identity.principal,
                    premier_git_bridge::plural(ref_count, "authorized ref")
                ),
            );
            ev.target = Some(uri.path().to_owned());
            crate::auth::audit(&state.audit_sink, ev);

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                resp_bytes,
            )
                .into_response()
        }
        Err(premier_git_bridge::GitBridgeError::ObjectNotVisible) => {
            let mut ev = AuditEvent::now(
                &identity,
                "premier-git-bridge",
                "git_upload_pack_v2",
                AuditDecision::Denied,
                "Anti-CFOR rejected unauthorized OID want (zero oracle)",
            );
            ev.target = Some(uri.path().to_owned());
            crate::auth::audit(&state.audit_sink, ev);
            (
                StatusCode::NOT_FOUND,
                "object not found in authorized scope",
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub(crate) fn err_resp(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: msg.into(),
            ..ApiError::default()
        }),
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                let _ = sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Bind and run the HTTP control-plane server until Ctrl+C or `SIGTERM`. `state` is the default
/// repository; the others are loaded from `repos_dir` (default `<workspace>/.premier/repos`).
pub async fn serve(
    bind_addr: SocketAddr,
    state: ServerState,
    name: Option<String>,
    repos_dir: Option<PathBuf>,
) -> Result<(), ServerError> {
    serve_with_shutdown(bind_addr, state, name, repos_dir, shutdown_signal()).await
}

/// Bind and run the HTTP control-plane server (and optional Git-over-SSH server) until `shutdown`
/// resolves. Fails fast if `state.json` is corrupt or if the configured SSH socket/host key cannot
/// be initialized, and propagates shutdown to SSH and background tasks.
pub async fn serve_with_shutdown<F>(
    bind_addr: SocketAddr,
    mut state: ServerState,
    name: Option<String>,
    repos_dir: Option<PathBuf>,
    shutdown: F,
) -> Result<(), ServerError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Initialize and validate account and repository state before accepting traffic.
    let dir = store::state_dir(&state.workspace_root);
    db::StateDb::open(&dir)
        .and_then(|mut db| db.repo_state::<PersistedState>(&dir, None))
        .map_err(ServerError::Io)?;
    state.auth.txn(|_| ()).map_err(ServerError::Io)?;

    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| ServerError::Io(format!("failed to bind {bind_addr}: {e}")))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| ServerError::Io(format!("failed to read local addr: {e}")))?;
    tracing::info!(addr = %local_addr, "Premier control-plane server listening");

    // Probed once, here, so the answer is in the log before anyone asks for a session.
    let sandbox = runner::sandbox_mode(state.allow_unsandboxed_agents);
    tracing::info!(
        agent_sandbox = sandbox.as_str(),
        detail = %runner::sandbox_detail(state.allow_unsandboxed_agents),
        "agent session sandbox"
    );
    // Policy and schema are whatever the default branch has committed, not working-tree files.
    if state.workspace_root.join(".git").exists() {
        state.reload_repo_config().map_err(ServerError::Io)?;
    }
    state.oidc_issuer = Arc::new(lifecycle::load_oidc_issuer(state.account_root(), true));

    let host_key_path = store::account_dir(state.account_root()).join("ssh_host_ed25519.key");
    // Fail fast on SSH bind & host key before reporting `ssh_enabled: true`.
    let verified_ssh_addr = if let Some(ssh_addr) = state.ssh_bind {
        if let Some(parent) = host_key_path.parent() {
            premier_secrets::create_state_dir(parent)
                .map_err(|e| ServerError::Io(format!("create SSH host key dir failed: {e}")))?;
        }
        premier_ssh::load_or_generate_host_key(&host_key_path)
            .map_err(|e| ServerError::Io(format!("failed to load SSH host key: {e}")))?;
        let probe = TcpListener::bind(ssh_addr)
            .await
            .map_err(|e| ServerError::Io(format!("failed to bind SSH {ssh_addr}: {e}")))?;
        let bound_addr = probe
            .local_addr()
            .map_err(|e| ServerError::Io(format!("failed to read SSH local addr: {e}")))?;
        drop(probe);
        state.ssh_bind = Some(bound_addr);
        Some(bound_addr)
    } else {
        None
    };

    let shutdown_signal = state.shutdown.clone();
    let registry = repos::Registry::open(state, name, repos_dir);
    for repo in registry.states() {
        ops::spawn_background(&repo);
    }

    let (ssh_handle, ssh_fail_rx) = if let Some(ssh_addr) = verified_ssh_addr {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let ssh_backend = Arc::new(MeteredSsh {
            backend: ssh::ServerSshBackend::new(registry.clone()),
            metrics: registry.default_state().metrics,
        });
        tracing::info!(%ssh_addr, "Premier Git-over-SSH listening");
        let handle = tokio::spawn(async move {
            if let Err(err) = premier_ssh::serve_ssh(ssh_addr, host_key_path, ssh_backend).await {
                tracing::error!(%ssh_addr, error = %err, "Premier Git-over-SSH server failed");
                let _ = tx.send(format!(
                    "Premier Git-over-SSH server failed on {ssh_addr}: {err}"
                ));
            }
        });
        (Some(handle), Some(rx))
    } else {
        (None, None)
    };

    let ssh_error = Arc::new(Mutex::new(None::<String>));
    let ssh_error_writer = Arc::clone(&ssh_error);
    let wait_ssh_failure = async move {
        match ssh_fail_rx {
            Some(rx) => match rx.await {
                Ok(msg) => {
                    if let Ok(mut slot) = ssh_error_writer.lock() {
                        *slot = Some(msg);
                    }
                }
                Err(_) => std::future::pending::<()>().await,
            },
            None => std::future::pending::<()>().await,
        }
    };
    let combined_shutdown = async move {
        tokio::select! {
            () = shutdown => {}
            () = wait_ssh_failure => {}
        }
        shutdown_signal.send_replace(true);
    };

    let app = with_runtime_middleware(registry.router(), registry.default_state());
    let serve_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(combined_shutdown)
    .await
    .map_err(|e| ServerError::Io(format!("server error: {e}")));

    // Propagate shutdown to SSH and all repository background tasks/sessions.
    if let Some(handle) = ssh_handle {
        handle.abort();
        let _ = handle.await;
    }
    for repo in registry.states() {
        repo.stop_background_jobs();
        repo.session_manager.shutdown().await;
    }

    if let Some(msg) = ssh_error.lock().ok().and_then(|mut g| g.take()) {
        return Err(ServerError::Io(msg));
    }
    serve_result
}

struct MeteredSsh {
    backend: ssh::ServerSshBackend,
    metrics: Arc<RuntimeMetrics>,
}

#[premier_ssh::async_trait]
impl premier_ssh::SshGitBackend for MeteredSsh {
    async fn authenticate_pubkey(
        &self,
        username: &str,
        key_openssh: &str,
    ) -> Option<premier_ssh::SshAuthenticatedUser> {
        self.backend
            .authenticate_pubkey(username, key_openssh)
            .await
    }

    async fn advertise_refs(
        &self,
        user: &premier_ssh::SshAuthenticatedUser,
        repo: &str,
        service: premier_ssh::GitService,
        protocol_v2: bool,
    ) -> Result<Vec<u8>, String> {
        self.metrics.git_ssh.fetch_add(1, Ordering::Relaxed);
        self.backend
            .advertise_refs(user, repo, service, protocol_v2)
            .await
    }

    async fn handle_upload_pack(
        &self,
        user: &premier_ssh::SshAuthenticatedUser,
        repo: &str,
        protocol_v2: bool,
        stdin: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.backend
            .handle_upload_pack(user, repo, protocol_v2, stdin)
            .await
    }

    async fn reserve_push_slot(&self) -> Result<premier_ssh::PushSlot, String> {
        self.backend.reserve_push_slot().await
    }

    async fn handle_receive_pack(
        &self,
        user: &premier_ssh::SshAuthenticatedUser,
        repo: &str,
        stdin: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.backend.handle_receive_pack(user, repo, stdin).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use premier_policy::parse_policy_toml;
    pub(crate) use tower_like_call::oneshot;

    use super::*;

    mod tower_like_call {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, Response};
        use hyper_util::rt::TokioIo;
        use tokio::net::{TcpListener, TcpStream};

        pub async fn oneshot(
            router: Router,
            req: Request<Body>,
        ) -> Response<hyper::body::Incoming> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });

            let stream = TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await.unwrap()
        }
    }

    #[tokio::test]
    async fn probes_headers_and_metrics_are_public() {
        let tmp = tempfile::tempdir().unwrap();
        let router = build_router(auth_state(tmp.path()));
        let request = |uri| Request::get(uri).body(Body::empty()).unwrap();
        let live = oneshot(router.clone(), request("/livez")).await;
        assert_eq!(live.status(), StatusCode::OK);
        assert_eq!(live.headers()["x-content-type-options"], "nosniff");
        assert_eq!(live.headers()["x-frame-options"], "DENY");
        assert_eq!(live.headers()["referrer-policy"], "no-referrer");
        assert!(
            live.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("worker-src 'self' blob:")
        );
        let id = live.headers()["x-request-id"].to_str().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let ready = oneshot(
            router.clone(),
            Request::get("/readyz")
                .header("x-request-id", "test-probe-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(ready.status(), StatusCode::OK);
        assert_eq!(ready.headers()["x-request-id"], "test-probe-123");
        let denied = oneshot(router.clone(), request("/v1/repo/search")).await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(denied.headers()["x-frame-options"], "DENY");
        let metrics = oneshot(router, request("/metrics")).await;
        assert_eq!(
            metrics.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = metrics.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("premier_http_requests_total{status_class=\"2xx\"} 2\n"));
        assert!(body.contains("premier_http_requests_total{status_class=\"4xx\"} 1\n"));
    }

    #[tokio::test]
    async fn oidc_well_known_discovery_and_jwks_are_public() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let expected_kid = state.oidc_issuer.kid().to_owned();
        let router = build_router(state);

        let disc = oneshot(
            router.clone(),
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(disc.status(), StatusCode::OK);
        let disc_bytes = disc.into_body().collect().await.unwrap().to_bytes();
        let disc_json: serde_json::Value = serde_json::from_slice(&disc_bytes).unwrap();
        assert_eq!(
            disc_json["id_token_signing_alg_values_supported"],
            serde_json::json!(["EdDSA"])
        );
        assert!(
            disc_json["jwks_uri"]
                .as_str()
                .unwrap()
                .ends_with("/.well-known/jwks.json")
        );

        let jwks = oneshot(
            router,
            Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(jwks.status(), StatusCode::OK);
        assert_eq!(jwks.headers()[header::CACHE_CONTROL], "public, max-age=300");
        let jwks_bytes = jwks.into_body().collect().await.unwrap().to_bytes();
        let jwks_json: serde_json::Value = serde_json::from_slice(&jwks_bytes).unwrap();
        let key = &jwks_json["keys"][0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], expected_kid);
        assert!(!key["x"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn readiness_reports_database_failure_without_affecting_liveness() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let dir = store::state_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(db::DB_FILE), "bad database").unwrap();
        let router = build_router(state);
        let (status, _, ready) = call(&router, Method::GET, "/readyz", &[], None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(ready["checks"]["sqlite"], "unavailable");
        assert_eq!(ready["checks"]["ssh"], "disabled");
        let (status, _, live) = call(&router, Method::GET, "/livez", &[], None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(live, serde_json::json!({"status": "ok"}));
    }

    #[tokio::test]
    async fn readiness_reuses_probe_result_until_it_expires() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let cache = Arc::clone(&state.readiness_probe);
        let router = build_router(state);
        let check = || Request::get("/readyz").body(Body::empty()).unwrap();
        assert_eq!(
            oneshot(router.clone(), check()).await.status(),
            StatusCode::OK
        );
        std::fs::write(
            store::state_dir(tmp.path()).join(db::DB_FILE),
            "corrupt SQLite",
        )
        .unwrap();
        assert_eq!(
            oneshot(router.clone(), check()).await.status(),
            StatusCode::OK
        );
        if let Some((measured, _)) = cache.lock().await.as_mut() {
            *measured -= Duration::from_secs(3);
        }
        assert_eq!(
            oneshot(router, check()).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn rate_limit_is_per_ip_and_rejects_with_retry_after() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = auth_state(tmp.path());
        let mut metrics = RuntimeMetrics::new();
        metrics.limiter = RateLimiter::new(1, 1);
        state.metrics = Arc::new(metrics);
        let router = build_router(state).layer(axum::middleware::from_fn(
            |mut req: Request<Body>, next: axum::middleware::Next| async move {
                let peer: SocketAddr = req.headers()["x-test-peer"]
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                req.extensions_mut().insert(ConnectInfo(peer));
                next.run(req).await
            },
        ));
        let request = |uri, peer| {
            Request::get(uri)
                .header("x-test-peer", peer)
                .body(Body::empty())
                .unwrap()
        };
        let first_ip = "192.0.2.1:5000";
        let response = oneshot(router.clone(), request("/v1/repo/search", first_ip)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for path in [
            "/v1/backup",
            "/readyz",
            "/v1/traces/ingest",
            "/v1/access/scan",
        ] {
            let response = oneshot(router.clone(), request(path, first_ip)).await;
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        }
        let response = oneshot(router, request("/v1/repo/search", "192.0.2.2:5000")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rate_limiter_evicts_the_oldest_idle_ip_at_capacity() {
        let limiter = RateLimiter::new(1, 1);
        let oldest = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let now = Instant::now();
        {
            let mut table = limiter.table.lock().unwrap();
            for i in 0..8191 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1_u32));
                table.buckets.insert(
                    Some(ip),
                    Bucket {
                        tokens: 0.0,
                        updated: now,
                    },
                );
            }
            table.buckets.insert(
                Some(oldest),
                Bucket {
                    tokens: 0.0,
                    updated: now - Duration::from_secs(2),
                },
            );
        }
        assert_eq!(limiter.admit(None), Ok(()));
        let table = limiter.table.lock().unwrap();
        assert_eq!(table.buckets.len(), 8192);
        assert!(!table.buckets.contains_key(&Some(oldest)));
    }

    #[tokio::test]
    async fn sse_connection_closes_when_server_signals_shutdown() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let (cookie, _) = state.auth.seed("owner", PW);
        let shutdown = state.shutdown.clone();
        let response = oneshot(
            build_router(state),
            Request::get("/v1/events/stream")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body();
        assert!(stream.frame().await.is_some());
        shutdown.send_replace(true);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), stream.frame())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recent_credentials_are_readable_while_a_writer_holds_the_db_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let (cookie, token) = state.auth.seed("owner", PW);
        let cookie_headers = [(header::COOKIE, cookie.parse().unwrap())]
            .into_iter()
            .collect();
        let token_headers = [(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        )]
        .into_iter()
        .collect();
        // The first token use updates last_used_at; subsequent uses should be reads.
        assert!(
            auth::request_user(&state, &token_headers)
                .unwrap()
                .is_some()
        );
        let writer =
            rusqlite::Connection::open(store::account_dir(tmp.path()).join(db::DB_FILE)).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        for headers in [&cookie_headers, &token_headers] {
            assert_eq!(
                auth::request_user(&state, headers)
                    .unwrap()
                    .unwrap()
                    .username,
                "owner"
            );
        }
    }

    #[tokio::test]
    async fn branch_visibility_write_failure_keeps_previous_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let root = tmp.path();
        commit_all(root);
        store::bind_state_dir(root, external.path(), "test", true);
        let state = auth_state(root);
        let (owner, _) = state.auth.seed("owner", PW);
        let repo_dir = store::state_dir(root);
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join(db::DB_FILE), "corrupt SQLite").unwrap();
        let (status, _, _) = call(
            &build_router(state.clone()), Method::POST, "/v1/branches/visibility",
            &[("cookie", &owner)],
            Some(serde_json::json!({ "branch": "main", "visibility": Visibility::Org, "readiness": Readiness::Ready })),
        ).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.branch_visibility_map().is_empty());
    }

    #[tokio::test]
    async fn tree_reaches_visible_files_after_restricted_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("a-private")).unwrap();
        for n in 0..270 {
            std::fs::write(root.join(format!("a-private/{n:03}")), "private").unwrap();
        }
        std::fs::write(root.join("z-visible"), "visible").unwrap();
        commit_all(root);
        let mut state = auth_state(root);
        let policy = parse_policy_toml(
            r#"
version = 1
[defaults]
public = []
[[rules]]
id = "allow-visible"
effect = "allow"
principals = ["@member"]
paths = ["z-visible"]
capabilities = ["traverse", "list", "read"]
"#,
        )
        .unwrap();
        state.policy = Arc::new(RwLock::new(Some(Arc::new(
            CompiledPolicy::compile(None, &policy).unwrap(),
        ))));
        let (cookie, _) = state
            .auth
            .seed_as("member", "test-password", auth::Role::Member);
        let (status, _, body) = call(
            &build_router(state),
            Method::GET,
            "/v1/repo/tree?principal=@member",
            &[("cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{body}");
        assert_eq!(entries[0]["path"], "z-visible");
        assert_eq!(body["omitted_count"], 0);
    }

    #[tokio::test]
    async fn tree_reports_full_visible_count_with_250_returned_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for n in 0..260 {
            std::fs::write(root.join(format!("{n:03}")), "public").unwrap();
        }
        commit_all(root);
        let state = auth_state(root);
        let (cookie, _) = state
            .auth
            .seed_as("member", "test-password", auth::Role::Member);
        let (status, _, body) = call(
            &build_router(state),
            Method::GET,
            "/v1/repo/tree?principal=@member",
            &[("cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["visible_count"], 260);
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 250);
        assert_eq!(entries[249]["path"], "249");
    }

    #[tokio::test]
    async fn health_explain_xray_and_jit_approval_endpoints_work() {
        let policy_toml = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let policy_file = parse_policy_toml(policy_toml).unwrap();
        let policy = CompiledPolicy::compile(None, &policy_file).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("billing")).unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Demo\n").unwrap();
        std::fs::write(tmp.path().join("billing/secret.rs"), "pub fn s() {}\n").unwrap();
        std::fs::write(tmp.path().join("billing/master.key"), "KEY\n").unwrap();
        commit_all(tmp.path());

        let mut state =
            ServerState::minimal(Some(Arc::new(policy)), None, Arc::new(AuditSink::default()));
        state.workspace_root = tmp.path().to_path_buf();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.set_repo_policy_metadata(Some(policy_toml.to_owned()), Some(Arc::new(policy_file)));
        state.auth = Arc::new(auth::AuthStore::open(tmp.path()));
        let (cookie, _) = state.auth.seed("owner", "correct horse battery");

        let router = build_router(state);

        // 1. /health
        let health_req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .header("host", "localhost")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let health_resp = oneshot(router.clone(), health_req).await;
        assert_eq!(health_resp.status(), StatusCode::OK);

        // 2. /v1/access/explain
        let explain_body = serde_json::json!({
            "principal": "anonymous",
            "path": "billing/secret.rs",
            "ref_name": "main"
        })
        .to_string();
        let explain_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/access/explain")
            .header("host", "localhost")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(explain_body))
            .unwrap();
        let explain_resp = oneshot(router.clone(), explain_req).await;
        assert_eq!(explain_resp.status(), StatusCode::OK);
        let bytes = explain_resp.into_body().collect().await.unwrap().to_bytes();
        let dec: ExplainDecision = serde_json::from_slice(&bytes).unwrap();
        assert!(dec.effective.is_empty());

        // 3. Strict /v1/repo/tree omits billing paths for anonymous callers
        let tree_req = Request::builder()
            .method(Method::GET)
            .uri("/v1/repo/tree?principal=anonymous&xray=false")
            .header("host", "localhost")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let tree_resp = oneshot(router.clone(), tree_req).await;
        assert_eq!(tree_resp.status(), StatusCode::OK);
        let tree_bytes = tree_resp.into_body().collect().await.unwrap().to_bytes();
        let tree_json: serde_json::Value = serde_json::from_slice(&tree_bytes).unwrap();
        assert!(tree_json["omitted_count"].as_u64().unwrap() >= 2);
        assert!(
            !tree_json["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["path"].as_str().unwrap().starts_with("billing/"))
        );

        // 4. The scripted proxy simulation is gone: the route does not exist.
        let sim_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/proxy/simulate")
            .header("host", "localhost")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"scenario":"exfil_evil","principal":"@alice"}"#,
            ))
            .unwrap();
        let sim_resp = oneshot(router, sim_req).await;
        assert_eq!(sim_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn real_git_clone_over_smart_http_v2_enforces_zones_and_passes_fsck() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical_dir = tmp.path().join("canonical");
        std::fs::create_dir_all(canonical_dir.join("billing/ledger")).unwrap();
        std::fs::create_dir_all(canonical_dir.join("apps/web")).unwrap();

        let git = |dir: &Path, args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "Alice")
                .env("GIT_AUTHOR_EMAIL", "alice@acme.test")
                .env("GIT_COMMITTER_NAME", "Alice")
                .env("GIT_COMMITTER_EMAIL", "alice@acme.test")
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };

        git(&canonical_dir, &["init", "-b", "main"]);
        std::fs::write(canonical_dir.join("README.md"), "# Public Premier Repo\n").unwrap();
        std::fs::write(
            canonical_dir.join("apps/web/index.ts"),
            "export const ok = true;\n",
        )
        .unwrap();
        std::fs::write(
            canonical_dir.join("billing/ledger/tx.rs"),
            "pub fn secret() {}\n",
        )
        .unwrap();
        std::fs::write(
            canonical_dir.join("billing/ledger/master.key"),
            "SUPER_SECRET\n",
        )
        .unwrap();
        git(&canonical_dir, &["add", "."]);
        git(&canonical_dir, &["commit", "-m", "initial commit"]);

        let repo_policy_toml = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let server_policy_toml = r#"
version = 1
[[rules]]
id = "server-allow-billing"
effect = "allow"
principals = ["group:billing"]
paths = ["billing/ledger/**"]
capabilities = ["traverse", "list", "read", "write"]
[[rules]]
id = "server-deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["billing/ledger/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let compiled = CompiledPolicy::compile(
            Some(&parse_policy_toml(server_policy_toml).unwrap()),
            &parse_policy_toml(repo_policy_toml).unwrap(),
        )
        .unwrap();

        let mut state = ServerState::minimal(
            Some(Arc::new(compiled)),
            None,
            Arc::new(AuditSink::default()),
        );
        state.workspace_root = canonical_dir.clone();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.set_repo_policy_metadata(Some(repo_policy_toml.to_owned()), None);
        state.server_policy_toml = Some(server_policy_toml.to_owned());
        state.auth = Arc::new(auth::AuthStore::open(&canonical_dir));
        let (_, alice_token) = state.auth.seed("alice", "correct horse battery");
        std::fs::write(
            canonical_dir.join(".premier/directory.json"),
            r#"{"principals":{"@alice":{"groups":["billing"]}}}"#,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = build_router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // 1. Real `git clone` with no credentials: the anonymous public projection.
        let anon_clone = tmp.path().join("clone-anon");
        let clone_out = tokio::process::Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "credential.helper=",
                "-c",
                "protocol.version=2",
                "clone",
                &format!("http://{addr}/git/repo.git"),
                anon_clone.to_str().unwrap(),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            clone_out.status.success(),
            "anonymous git clone failed: {}",
            String::from_utf8_lossy(&clone_out.stderr)
        );

        // Must pass strict `git fsck` and contain ZERO billing files or filenames!
        git(&anon_clone, &["fsck", "--strict", "--full"]);
        assert!(anon_clone.join("README.md").exists());
        assert!(anon_clone.join("apps/web/index.ts").exists());
        assert!(!anon_clone.join("billing").exists());
        let anon_all_objs = git(&anon_clone, &["rev-list", "--all", "--objects"]);
        assert!(!anon_all_objs.contains("billing"));
        let anon_log = git(&anon_clone, &["log", "-1"]);
        // The projection writes nothing into a commit (its attestation is out-of-band).
        assert!(!anon_log.contains("Premier-Projection-Attestation"));

        // 2. Real `git clone` as @alice (group:billing): sees billing/ledger/tx.rs, STILL not master.key!
        let alice_clone = tmp.path().join("clone-alice");
        let alice_out = tokio::process::Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "credential.helper=",
                "-c",
                "protocol.version=2",
                "clone",
                &format!("http://alice:{alice_token}@{addr}/git/auth/repo.git"),
                alice_clone.to_str().unwrap(),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            alice_out.status.success(),
            "alice git clone failed: {}",
            String::from_utf8_lossy(&alice_out.stderr)
        );
        git(&alice_clone, &["fsck", "--strict", "--full"]);
        assert!(alice_clone.join("billing/ledger/tx.rs").exists());
        assert!(!alice_clone.join("billing/ledger/master.key").exists());
    }

    #[tokio::test]
    async fn reversible_git_push_vault_search_and_policy_hot_reload_work() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical_dir = tmp.path().join("canonical");
        std::fs::create_dir_all(canonical_dir.join("billing/ledger")).unwrap();
        std::fs::create_dir_all(canonical_dir.join("apps/web")).unwrap();

        let git = |dir: &Path, args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "Bob")
                .env("GIT_AUTHOR_EMAIL", "bob@acme.test")
                .env("GIT_COMMITTER_NAME", "Bob")
                .env("GIT_COMMITTER_EMAIL", "bob@acme.test")
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };

        git(&canonical_dir, &["init", "-b", "main"]);
        std::fs::write(canonical_dir.join("README.md"), "# Public v1\n").unwrap();
        std::fs::write(
            canonical_dir.join("billing/ledger/tx.rs"),
            "pub const SECRET_MARKER: &str = \"ledger-only\";\n",
        )
        .unwrap();
        std::fs::write(
            canonical_dir.join("billing/ledger/master.key"),
            "DO_NOT_DELETE\n",
        )
        .unwrap();
        git(&canonical_dir, &["add", "."]);
        git(&canonical_dir, &["commit", "-m", "initial commit"]);

        let repo_policy_toml = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read", "write"]
[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let server_policy_toml = r#"
version = 1
[[rules]]
id = "server-allow-billing"
effect = "allow"
principals = ["group:billing"]
paths = ["billing/ledger/**"]
capabilities = ["traverse", "list", "read", "write"]
[[rules]]
id = "server-deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["billing/ledger/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let repo_pf = parse_policy_toml(repo_policy_toml).unwrap();
        let compiled = CompiledPolicy::compile(
            Some(&parse_policy_toml(server_policy_toml).unwrap()),
            &repo_pf,
        )
        .unwrap();

        let policy_disk_path = canonical_dir.join(".access.toml");
        std::fs::write(&policy_disk_path, repo_policy_toml).unwrap();

        let mut state = ServerState::minimal(
            Some(Arc::new(compiled)),
            None,
            Arc::new(AuditSink::default()),
        );
        state.workspace_root = canonical_dir.clone();
        state.repo_policy_path = Some(policy_disk_path.clone());
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.set_repo_policy_metadata(Some(repo_policy_toml.to_owned()), Some(Arc::new(repo_pf)));
        state.server_policy_toml = Some(server_policy_toml.to_owned());
        state.auth = Arc::new(auth::AuthStore::open(&canonical_dir));
        let (cookie, bob_token) = state.auth.seed("bob", "correct horse battery");

        let router = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve_router = router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, serve_router).await;
        });

        // 1. Real `git clone` as @bob (no billing access) -> edit README.md -> real `git push`!
        let bob_clone = tmp.path().join("clone-bob");
        let clone_out = tokio::process::Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "credential.helper=",
                "-c",
                "protocol.version=2",
                "clone",
                &format!("http://bob:{bob_token}@{addr}/git/auth/repo.git"),
                bob_clone.to_str().unwrap(),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            clone_out.status.success(),
            "bob clone failed: {}",
            String::from_utf8_lossy(&clone_out.stderr)
        );
        assert!(!bob_clone.join("billing").exists());

        std::fs::write(bob_clone.join("README.md"), "# Public v2 from Bob\n").unwrap();
        git(&bob_clone, &["add", "README.md"]);
        git(
            &bob_clone,
            &["commit", "-m", "docs: update README from projected clone"],
        );

        let push_out = tokio::process::Command::new("git")
            .current_dir(&bob_clone)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "credential.helper=", "push", "origin", "main"])
            .output()
            .await
            .unwrap();
        assert!(
            push_out.status.success(),
            "bob reversible push failed: {}",
            String::from_utf8_lossy(&push_out.stderr)
        );

        // Verify canonical repo updated README.md AND preserved hidden billing subtree untouched!
        git(&canonical_dir, &["fsck", "--strict", "--full"]);
        let readme_canon = git(&canonical_dir, &["show", "main:README.md"]);
        assert_eq!(readme_canon, "# Public v2 from Bob");
        let tx_canon = git(&canonical_dir, &["show", "main:billing/ledger/tx.rs"]);
        assert!(tx_canon.contains("SECRET_MARKER"));
        let key_canon = git(&canonical_dir, &["show", "main:billing/ledger/master.key"]);
        assert_eq!(key_canon, "DO_NOT_DELETE");

        // The push round-trips: after a fetch bob's branch is in sync with what the server
        // projects for him, and one more commit pushes as a plain fast-forward (no rebase).
        let bob_git = |args: &'static [&'static str]| {
            let dir = bob_clone.clone();
            async move {
                let out = tokio::process::Command::new("git")
                    .current_dir(dir)
                    .env("GIT_TERMINAL_PROMPT", "0")
                    .args(["-c", "credential.helper="])
                    .args(args)
                    .output()
                    .await
                    .unwrap();
                assert!(
                    out.status.success(),
                    "git {args:?} failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                String::from_utf8_lossy(&out.stdout).trim().to_owned()
            }
        };
        let pushed = git(&bob_clone, &["rev-parse", "HEAD"]);
        bob_git(&["fetch", "origin"]).await;
        assert!(
            bob_git(&["ls-remote", "origin", "refs/heads/main"])
                .await
                .starts_with(&pushed)
        );
        assert_eq!(git(&bob_clone, &["rev-parse", "origin/main"]), pushed);
        assert_eq!(git(&bob_clone, &["status", "-sb"]), "## main...origin/main");
        std::fs::write(bob_clone.join("README.md"), "# Public v3 from Bob\n").unwrap();
        git(
            &bob_clone,
            &["commit", "-am", "docs: second push, no rebase"],
        );
        bob_git(&["push", "origin", "main"]).await;
        bob_git(&["fetch", "origin"]).await;
        assert_eq!(git(&bob_clone, &["status", "-sb"]), "## main...origin/main");
        assert_eq!(git(&canonical_dir, &["rev-list", "--count", "main"]), "3");

        // 2. Push attempting to write into denied `billing/` zone MUST be rejected!
        std::fs::create_dir_all(bob_clone.join("billing")).unwrap();
        std::fs::write(bob_clone.join("billing/evil.rs"), "// injected\n").unwrap();
        git(&bob_clone, &["add", "billing/evil.rs"]);
        git(&bob_clone, &["commit", "-m", "attempt restricted write"]);
        let bad_push = tokio::process::Command::new("git")
            .current_dir(&bob_clone)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "credential.helper=", "push", "origin", "main"])
            .output()
            .await
            .unwrap();
        assert!(
            !bad_push.status.success(),
            "push touching denied billing/ path should have been rejected"
        );

        // 3. ACL-scoped search: anonymous gets 0 hits for SECRET_MARKER, @alice gets hit!
        let anon_search = oneshot(
            router.clone(),
            Request::builder()
                .method(Method::GET)
                .uri("/v1/repo/search?q=SECRET_MARKER&principal=anonymous")
                .header("host", "localhost")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(anon_search.status(), StatusCode::OK);
        let anon_search_json: serde_json::Value =
            serde_json::from_slice(&anon_search.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(anon_search_json["hits"].as_array().unwrap().len(), 0);

        let alice_search = oneshot(
            router.clone(),
            Request::builder()
                .method(Method::GET)
                .uri("/v1/repo/search?q=SECRET_MARKER&principal=@alice&groups=billing")
                .header("host", "localhost")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(alice_search.status(), StatusCode::OK);
        let alice_search_json: serde_json::Value =
            serde_json::from_slice(&alice_search.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        // The client-supplied `groups=billing` is ignored: @alice is in no group yet.
        assert_eq!(alice_search_json["hits"].as_array().unwrap().len(), 0);

        let authed = [("cookie", cookie.as_str())];
        let (status, _, _) = call(
            &router,
            Method::PUT,
            "/v1/directory/principals/@alice",
            &authed,
            Some(serde_json::json!({ "display_name": "Alice", "groups": ["billing"] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, in_group) = call(
            &router,
            Method::GET,
            "/v1/repo/search?q=SECRET_MARKER&principal=@alice",
            &authed,
            None,
        )
        .await;
        assert_eq!(in_group["hits"].as_array().unwrap().len(), 1);

        // 4. Real age-encrypted secret vault: write never echoes raw secret, status shows configured.
        let set_resp = oneshot(
            router.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/secrets/set")
                .header("host", "localhost")
            .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"key":"STRIPE_SECRET_KEY","value":"sk_live_never_echo_999","principal":"@alice"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(set_resp.status(), StatusCode::OK);
        let set_body = String::from_utf8(
            set_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!set_body.contains("sk_live_never_echo_999"));
        assert!(canonical_dir.join(".premier/vault.toml").exists());

        // 5. Real live policy hot-reload (`PUT /v1/policy/repo`)!
        let updated_toml = repo_policy_toml.replace(
            "public = [\"traverse\", \"list\", \"read\"]",
            "public = [\"traverse\", \"list\"]",
        );
        let put_pol = oneshot(
            router.clone(),
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/policy/repo")
                .header("host", "localhost")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "toml": updated_toml,
                        "principal": "@alice"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(put_pol.status(), StatusCode::OK);

        // Verify hot-reloaded policy immediately denies anonymous READ on README.md!
        let explain_after = oneshot(
            router,
            Request::builder()
                .method(Method::POST)
                .uri("/v1/access/explain")
                .header("host", "localhost")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"principal":"anonymous","path":"README.md","ref_name":"main"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(explain_after.status(), StatusCode::OK);
        let dec: ExplainDecision = serde_json::from_slice(
            &explain_after
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert!(!dec.allows(Capability::READ));
    }

    // ---- account authentication ------------------------------------------------------------

    pub(crate) const PW: &str = "correct horse battery";

    /// Commit everything in `root` but server state, creating the repository if there is none:
    /// content is served from the committed tree only.
    pub(crate) fn commit_all(root: &Path) {
        let git = |args: &[&str]| {
            let out = premier_git_bridge::git_command(root)
                .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
                .args(["-c", "core.autocrlf=false"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        if !root.join(".git").exists() {
            git(&["init", "-q", "-b", "main"]);
        }
        git(&["add", "-A", "--", ".", ":!.premier", ":!.premier-local"]);
        git(&["commit", "-q", "--allow-empty", "-m", "fixture"]);
    }

    fn auth_state(root: &Path) -> ServerState {
        let policy_toml = "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\n";
        let policy = CompiledPolicy::compile(None, &parse_policy_toml(policy_toml).unwrap());
        let mut state = ServerState::minimal(
            Some(Arc::new(policy.unwrap())),
            None,
            Arc::new(AuditSink::default()),
        );
        state.workspace_root = root.to_path_buf();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.auth = Arc::new(auth::AuthStore::open(root));
        state
    }

    /// One request; returns status, the `premier_session=…` pair from Set-Cookie (if any), JSON body.
    pub(crate) async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        };
        let resp = oneshot(router.clone(), req.unwrap()).await;
        let status = resp.status();
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::to_owned);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, cookie, json)
    }

    #[tokio::test]
    async fn setup_login_gate_csrf_lockout_and_state_dir_isolation() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Demo\n").unwrap();
        commit_all(tmp.path());
        let router = build_router(auth_state(tmp.path()));
        let login =
            |password: &str| serde_json::json!({ "username": "owner", "password": password });

        // Nothing under /v1 answers without credentials, including the SSE stream.
        for uri in ["/v1/audit", "/v1/events/stream", "/v1/auth/sessions"] {
            let (status, _, _) = call(&router, Method::GET, uri, &[], None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        }
        let (status, _, _) = call(&router, Method::GET, "/health", &[], None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, st) = call(&router, Method::GET, "/v1/auth/status", &[], None).await;
        assert_eq!(st["setup_required"], true);
        assert_eq!(st["authenticated"], false);

        // Weak input is refused, then the first account becomes the owner.
        let weak = serde_json::json!({ "username": "owner", "password": "short" });
        let (status, _, _) = call(&router, Method::POST, "/v1/auth/setup", &[], Some(weak)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, cookie, st) = call(
            &router,
            Method::POST,
            "/v1/auth/setup",
            &[],
            Some(login(PW)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(st["user"]["principal"], "@owner");
        assert_eq!(st["user"]["totp_enabled"], false);
        let cookie = cookie.unwrap();
        let authed = [("cookie", cookie.as_str())];

        let (status, _, _) = call(&router, Method::GET, "/v1/audit", &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/auth/setup",
            &[],
            Some(login(PW)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // CSRF: a cookie write from another origin is refused, our own origin is fine.
        let revoke = "/v1/auth/sessions/revoke-others";
        let evil = [("cookie", cookie.as_str()), ("origin", "http://evil.test")];
        let (status, _, _) = call(&router, Method::POST, revoke, &evil, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let own = [("cookie", cookie.as_str()), ("origin", "http://localhost")];
        let (status, _, _) = call(&router, Method::POST, revoke, &own, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // The DB holds hashes, and no repository API will serve the file.
        let raw = std::fs::read(tmp.path().join(".premier/premier.db")).unwrap();
        let raw = String::from_utf8_lossy(&raw);
        assert!(raw.contains("$argon2id$") && !raw.contains(PW));
        assert!(!raw.contains(cookie.trim_start_matches("premier_session=")));
        let (status, _, ok) = call(
            &router,
            Method::GET,
            "/v1/repo/file?path=README.md&principal=@owner",
            &authed,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ok["allowed"], true);
        for path in [
            ".premier/premier.db",
            ".Premier/premier.db",
            ".premier./premier.db",
            ".git/config",
        ] {
            for api in ["file", "blame"] {
                let uri = format!("/v1/repo/{api}?path={path}&principal=@owner");
                let (status, _, body) = call(&router, Method::GET, &uri, &authed, None).await;
                // A spelling Windows would fold onto the directory is not a repository path.
                let expected = if path.contains("./") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                };
                assert_eq!(status, expected, "{uri}");
                assert!(!body.to_string().contains("argon2"), "{uri}");
            }
        }
        let write = serde_json::json!({
            "path": ".premier/premier.db", "content": "{}", "principal": "@owner"
        });
        let (status, _, _) =
            call(&router, Method::PUT, "/v1/repo/file", &authed, Some(write)).await;
        assert_ne!(status, StatusCode::OK);
        let (_, _, tree) = call(
            &router,
            Method::GET,
            "/v1/repo/tree?principal=@owner&xray=true",
            &authed,
            None,
        )
        .await;
        assert!(!tree.to_string().contains("premier.db"));
        let (_, _, hits) = call(
            &router,
            Method::GET,
            "/v1/repo/search?q=argon2id&principal=@owner",
            &authed,
            None,
        )
        .await;
        assert_eq!(hits["hits"].as_array().unwrap().len(), 0);

        // Wrong password and unknown user fail identically; five failures lock that client out.
        let wrong = || Some(login("wrong-password"));
        let (status, _, bad) = call(&router, Method::POST, "/v1/auth/login", &[], wrong()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let ghost = serde_json::json!({ "username": "ghost", "password": "wrong-password" });
        let (status, _, unknown) =
            call(&router, Method::POST, "/v1/auth/login", &[], Some(ghost)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(unknown, bad);
        let (status, fresh, _) = call(
            &router,
            Method::POST,
            "/v1/auth/login",
            &[],
            Some(login(PW)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fresh.is_some());
        for _ in 0..5 {
            let (status, _, _) = call(&router, Method::POST, "/v1/auth/login", &[], wrong()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _, locked) = call(
            &router,
            Method::POST,
            "/v1/auth/login",
            &[],
            Some(login(PW)),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // The wait is the real one: the window has only just started.
        assert_eq!(
            locked["error"],
            "Too many attempts. Try again in 15 minutes."
        );
        let (_, _, events) = call(&router, Method::GET, "/v1/auth/events", &authed, None).await;
        assert_eq!(events[0]["kind"], "login_failed");
    }

    #[tokio::test]
    async fn totp_tokens_git_credentials_and_cli_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let (cookie, seeded_token) = state.auth.seed("alice", PW);
        let router = build_router(state.clone());
        let authed = [("cookie", cookie.as_str())];
        let login = |password: &str, code: Option<String>| serde_json::json!({ "username": "alice", "password": password, "totp_code": code });

        // Bearer access token: works on the API, cannot administer the server or manage the
        // account, dies on revoke.
        let bearer = format!("Bearer {seeded_token}");
        let via_seeded = [("authorization", bearer.as_str())];
        let (status, _, _) = call(&router, Method::GET, "/v1/branches", &via_seeded, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(&router, Method::GET, "/v1/audit", &via_seeded, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(&router, Method::GET, "/v1/auth/tokens", &via_seeded, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let new = serde_json::json!({ "name": "ci", "expires_in_days": 30 });
        let (status, _, made) =
            call(&router, Method::POST, "/v1/auth/tokens", &authed, Some(new)).await;
        assert_eq!(status, StatusCode::OK);
        let made_token = made["token"].as_str().unwrap().to_owned();
        assert!(made_token.starts_with("prm_") && made["expires_at"].is_string());
        let (_, _, listed) = call(&router, Method::GET, "/v1/auth/tokens", &authed, None).await;
        assert_eq!(listed.as_array().unwrap().len(), 2);
        assert!(!listed.to_string().contains(&made_token));
        let made_bearer = format!("Bearer {made_token}");
        let via_made = [("authorization", made_bearer.as_str())];
        let (status, _, _) = call(&router, Method::GET, "/v1/branches", &via_made, None).await;
        assert_eq!(status, StatusCode::OK);
        let uri = format!("/v1/auth/tokens/{}", made["id"].as_str().unwrap());
        let (status, _, _) = call(&router, Method::DELETE, &uri, &authed, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = call(&router, Method::GET, "/v1/branches", &via_made, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Git smart-HTTP: push needs real credentials and X-Premier-Principal grants nothing.
        let push_refs = "/git/repo.git/info/refs?service=git-receive-pack";
        let basic = |user: &str, pass: &str| {
            use base64::Engine;
            let raw = format!("{user}:{pass}");
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            )
        };
        let resp = oneshot(
            router.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/git/repo.git/git-receive-pack")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
        let spoof = [("x-premier-principal", "@alice")];
        let (status, _, _) = call(&router, Method::GET, push_refs, &spoof, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = call(
            &router,
            Method::GET,
            "/git/auth/repo.git/info/refs",
            &spoof,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let bare_name = basic("alice", "x");
        let name_hdr = [("authorization", bare_name.as_str())];
        let (status, _, _) = call(&router, Method::GET, push_refs, &name_hdr, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let with_token = basic("git", &seeded_token);
        let token_hdr = [("authorization", with_token.as_str())];
        let (status, _, _) = call(&router, Method::GET, push_refs, &token_hdr, None).await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
        let with_password = basic("alice", PW);
        let pw_hdr = [("authorization", with_password.as_str())];
        let (status, _, _) = call(&router, Method::GET, push_refs, &pw_hdr, None).await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
        // No credentials at all still reaches the anonymous fetch advertisement.
        let (status, _, _) = call(&router, Method::GET, "/git/repo.git/info/refs", &[], None).await;
        assert_eq!(status, StatusCode::OK);

        // TOTP: enrol with a code computed from the secret, then login demands it.
        let (status, _, begin) =
            call(&router, Method::POST, "/v1/auth/totp/begin", &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        let secret = begin["secret"].as_str().unwrap().to_owned();
        assert!(begin["otpauth_url"].as_str().unwrap().contains(&secret));
        assert!(begin["qr_svg"].as_str().unwrap().contains("<svg"));
        let code_at = |offset: u64| auth::totp_code(&secret, auth::totp_step_now() + offset);
        let wrong = serde_json::json!({ "code": "000000x" });
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/auth/totp/enable",
            &authed,
            Some(wrong),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let enable = serde_json::json!({ "code": code_at(0) });
        let (status, _, enabled) = call(
            &router,
            Method::POST,
            "/v1/auth/totp/enable",
            &authed,
            Some(enable),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let recovery = |body: &serde_json::Value| -> Vec<String> {
            serde_json::from_value(body["recovery_codes"].clone()).unwrap()
        };
        let codes = recovery(&enabled);
        assert_eq!(codes.len(), 10);
        assert!(
            codes
                .iter()
                .all(|c| c.len() == 14 && c.split('-').all(|part| part.len() == 4))
        );

        let (status, _, body) = call(
            &router,
            Method::POST,
            "/v1/auth/login",
            &[],
            Some(login(PW, None)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["totp_required"], true);
        let bad_code = Some(login(PW, Some("000000x".to_owned())));
        let (status, _, body) = call(&router, Method::POST, "/v1/auth/login", &[], bad_code).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["totp_required"], true);
        // The enrolment step is spent, so use the next one; then prove it cannot be replayed.
        let code = code_at(1);
        let good = Some(login(PW, code.clone()));
        let (status, _, st) = call(&router, Method::POST, "/v1/auth/login", &[], good).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(st["user"]["totp_enabled"], true);
        let replay = Some(login(PW, code));
        let (status, _, _) = call(&router, Method::POST, "/v1/auth/login", &[], replay).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // A recovery code stands in for the authenticator, once; only its hash is stored.
        let spare = || Some(login(PW, Some(codes[0].clone())));
        let (status, _, st) = call(&router, Method::POST, "/v1/auth/login", &[], spare()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(st["user"]["recovery_codes_left"], 9);
        let (status, _, _) = call(&router, Method::POST, "/v1/auth/login", &[], spare()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let stored = std::fs::read(tmp.path().join(".premier/premier.db")).unwrap();
        let stored = String::from_utf8_lossy(&stored);
        assert!(!codes.iter().any(|c| stored.contains(c.as_str())));
        let (_, _, events) = call(&router, Method::GET, "/v1/auth/events", &authed, None).await;
        assert!(
            events.to_string().contains("recovery_code_used"),
            "{events}"
        );
        // Regenerating replaces the set: an old unused code stops working.
        let regen = "/v1/auth/totp/recovery-codes";
        let pw = Some(serde_json::json!({ "password": PW }));
        let (status, _, fresh) = call(&router, Method::POST, regen, &authed, pw).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(recovery(&fresh).len(), 10);
        assert!(!recovery(&fresh).contains(&codes[1]));
        let old = Some(login(PW, Some(codes[1].clone())));
        let (status, _, _) = call(&router, Method::POST, "/v1/auth/login", &[], old).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // With 2FA on, the bare password no longer works for Git; a token still does.
        let (status, _, _) = call(&router, Method::GET, push_refs, &pw_hdr, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = call(&router, Method::GET, push_refs, &token_hdr, None).await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);

        // CLI recovery acts on the same account DB as the running server.
        auth::disable_totp(tmp.path(), "alice").unwrap();
        assert!(auth::disable_totp(tmp.path(), "nobody").is_err());
        assert!(auth::reset_password(tmp.path(), "alice", "short").is_err());
        auth::reset_password(tmp.path(), "alice", "a brand new password").unwrap();
        let (status, _, _) = call(&router, Method::GET, "/v1/audit", &authed, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let relogin = Some(login("a brand new password", None));
        let (status, cookie, _) = call(&router, Method::POST, "/v1/auth/login", &[], relogin).await;
        assert_eq!(status, StatusCode::OK);

        // Mutations record the real account next to the "view as" principal.
        let cookie = cookie.unwrap();
        let secret_req = serde_json::json!({ "key": "K", "value": "v", "principal": "@mallory" });
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/secrets/set",
            &[("cookie", cookie.as_str())],
            Some(secret_req),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let last = state.audit_sink.snapshot().pop().unwrap();
        assert!(last.reason.ends_with("[actor: @alice]"), "{}", last.reason);
    }

    #[tokio::test]
    async fn directory_default_policy_owner_access_and_private_git_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(&root).unwrap();
        let git = |dir: &Path, args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "Owner")
                .env("GIT_AUTHOR_EMAIL", "owner@acme.test")
                .env("GIT_COMMITTER_NAME", "Owner")
                .env("GIT_COMMITTER_EMAIL", "owner@acme.test")
                .env("GIT_TERMINAL_PROMPT", "0")
                .args(["-c", "credential.helper=", "-c", "protocol.version=2"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        git(&root, &["init", "-b", "main"]);
        std::fs::write(root.join("README.md"), "# Private by default\n").unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-m", "confidential subject line"]);

        // A workspace with no .access.toml: the built-in default policy, in memory only.
        let default_file = parse_policy_toml(directory::DEFAULT_POLICY_TOML).unwrap();
        let compiled = CompiledPolicy::compile(None, &default_file).unwrap();
        let sink = Arc::new(AuditSink::default());
        let mut state = ServerState::minimal(Some(Arc::new(compiled)), None, Arc::clone(&sink));
        state.workspace_root = root.clone();
        state.repo_policy_path = Some(root.join(".access.toml"));
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.set_repo_policy_metadata(
            Some(directory::DEFAULT_POLICY_TOML.to_owned()),
            Some(Arc::new(default_file)),
        );
        state.auth = Arc::new(auth::AuthStore::open(&root));
        let (cookie, token) = state.auth.seed("owner", PW);
        let router = build_router(state.clone());
        let authed = [("cookie", cookie.as_str())];

        // The owner is always in the directory, with the implicit `owners` group.
        let (status, _, dir) = call(&router, Method::GET, "/v1/directory", &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            dir,
            serde_json::json!({
                "principals": [{
                    "principal": "@owner", "display_name": "owner",
                    "groups": ["owners"], "is_owner": true, "has_account": true
                }],
                "groups": ["owners"],
            })
        );

        // No principal in the request = the session user, who can read; nobody else can, and a
        // client-supplied `groups` value grants nothing.
        let read = |query: &'static str| {
            let uri = format!("/v1/repo/file?path=README.md{query}");
            let router = router.clone();
            let cookie = cookie.clone();
            async move {
                let (status, _, body) = call(
                    &router,
                    Method::GET,
                    &uri,
                    &[("cookie", cookie.as_str())],
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{uri}");
                body["allowed"].as_bool().unwrap()
            }
        };
        assert!(read("").await);
        assert!(read("&principal=@owner").await);
        assert!(!read("&principal=anonymous").await);
        assert!(!read("&principal=@bob").await);
        assert!(!read("&principal=@bob&groups=owners").await);
        let spoofed_write = serde_json::json!({
            "path": "x.txt", "content": "x", "principal": "@bob", "groups": ["owners"]
        });
        let (status, _, _) = call(
            &router,
            Method::PUT,
            "/v1/repo/file",
            &authed,
            Some(spoofed_write),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Upsert, validation, session-only mutation, delete.
        let bob = "/v1/directory/principals/@bob";
        let put = |uri: &'static str, body: serde_json::Value| {
            let router = router.clone();
            let cookie = cookie.clone();
            async move {
                call(
                    &router,
                    Method::PUT,
                    uri,
                    &[("cookie", cookie.as_str())],
                    Some(body),
                )
                .await
            }
        };
        let bob_body = serde_json::json!({ "display_name": "Bob", "groups": ["dev", "billing"] });
        let (status, _, dir) = put(bob, bob_body.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(dir["principals"][0]["principal"], "@owner");
        assert_eq!(
            dir["principals"][1],
            serde_json::json!({
                "principal": "@bob", "display_name": "Bob",
                "groups": ["billing", "dev"], "is_owner": false, "has_account": false
            })
        );
        assert_eq!(
            dir["groups"],
            serde_json::json!(["billing", "dev", "owners"])
        );
        assert!(root.join(".premier/directory.json").exists());
        for (uri, groups) in [
            (bob, serde_json::json!(["Bad Group"])),
            (bob, serde_json::json!(["owners"])),
            ("/v1/directory/principals/anonymous", serde_json::json!([])),
        ] {
            let (status, _, _) = put(uri, serde_json::json!({ "groups": groups })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
        // The owner's extra groups are stored; `owners` stays implicit.
        let (status, _, dir) = put(
            "/v1/directory/principals/@owner",
            serde_json::json!({ "display_name": "ignored", "groups": ["billing"] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            dir["principals"][0]["groups"],
            serde_json::json!(["owners", "billing"])
        );
        assert_eq!(dir["principals"][0]["display_name"], "owner");
        assert_eq!(dir["principals"].as_array().unwrap().len(), 2);

        let bearer = format!("Bearer {token}");
        let via_token = [("authorization", bearer.as_str())];
        let (status, _, _) = call(&router, Method::PUT, bob, &via_token, Some(bob_body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(&router, Method::GET, "/v1/directory", &via_token, None).await;
        assert_eq!(status, StatusCode::OK);

        let owner_uri = "/v1/directory/principals/@owner";
        let (status, _, _) = call(&router, Method::DELETE, owner_uri, &authed, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _, dir) = call(&router, Method::DELETE, bob, &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(dir["principals"].as_array().unwrap().len(), 1);
        let (status, _, _) = call(&router, Method::DELETE, bob, &authed, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let actions: Vec<String> = sink.snapshot().into_iter().map(|e| e.action).collect();
        assert!(actions.contains(&"directory_principal_upserted".to_owned()));
        assert!(actions.contains(&"directory_principal_removed".to_owned()));

        // A fresh workspace starts empty: no demo overlays, no seeded review, and the starter
        // policy's comment reads true once it is saved as the real file.
        let (_, _, overlays) = call(&router, Method::GET, "/v1/overlays", &authed, None).await;
        assert_eq!(overlays["entries"], serde_json::json!([]));
        let (_, _, reviews) = call(&router, Method::GET, "/v1/reviews", &authed, None).await;
        assert_eq!(reviews, serde_json::json!([]));
        assert!(!directory::DEFAULT_POLICY_TOML.contains("no .access.toml"));
        // Nobody but the owners can enter `main` under this policy, so it is not labelled public.
        let (_, _, branches) = call(&router, Method::GET, "/v1/branches", &authed, None).await;
        assert_eq!(branches[0]["name"], "main");
        assert_eq!(
            branches[0]["visibility"]["scope"], "restricted",
            "{branches}"
        );

        // Git: an anonymous caller is shown no ref and no object; the owner gets the repo.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve_router = router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, serve_router).await;
        });
        let anon_url = format!("http://{addr}/git/repo.git");
        let owner_url = format!("http://owner:{token}@{addr}/git/auth/repo.git");
        let (git_dir, anon_clone, owner_clone) = (
            tmp.path().to_path_buf(),
            tmp.path().join("clone-anon"),
            tmp.path().join("clone-owner"),
        );
        let (anon_refs, owner_refs) = tokio::task::spawn_blocking(move || {
            let anon_refs = git(&git_dir, &["ls-remote", &anon_url]);
            git(
                &git_dir,
                &["clone", &anon_url, anon_clone.to_str().unwrap()],
            );
            assert!(!anon_clone.join("README.md").exists());
            assert_eq!(
                git(&anon_clone, &["count-objects"]),
                "0 objects, 0 kilobytes"
            );
            let owner_refs = git(&git_dir, &["ls-remote", &owner_url]);
            git(
                &git_dir,
                &["clone", &owner_url, owner_clone.to_str().unwrap()],
            );
            assert!(owner_clone.join("README.md").exists());
            (anon_refs, owner_refs)
        })
        .await
        .unwrap();
        assert_eq!(anon_refs, "", "anonymous must see no refs");
        assert!(owner_refs.contains("refs/heads/main"), "{owner_refs}");

        // The Studio shows the default policy, and saving it commits a real .access.toml.
        let (_, _, summary) = call(&router, Method::GET, "/v1/policy/summary", &authed, None).await;
        assert_eq!(summary["policy_loaded"], true);
        assert_eq!(summary["repo_policy_toml"], directory::DEFAULT_POLICY_TOML);
        assert_eq!(summary["policy"]["rules"][0]["id"], "owners-full-access");
        assert!(!root.join(".access.toml").exists());
        let save = serde_json::json!({ "toml": directory::DEFAULT_POLICY_TOML });
        let (status, _, saved) =
            call(&router, Method::PUT, "/v1/policy/repo", &authed, Some(save)).await;
        assert_eq!(status, StatusCode::OK);
        let committed = premier_git_bridge::git_command(&root)
            .args([
                "cat-file",
                "blob",
                &format!("{}:.access.toml", saved["commit"].as_str().unwrap()),
            ])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&committed.stdout),
            directory::DEFAULT_POLICY_TOML
        );

        // Writes: allowed for the owner under the policy, refused outright with no policy loaded.
        let write = || Some(serde_json::json!({ "path": "notes.txt", "content": "hi" }));
        let (status, _, _) = call(&router, Method::PUT, "/v1/repo/file", &authed, write()).await;
        assert_eq!(status, StatusCode::OK);
        *state.policy.write().unwrap() = None;
        let (status, _, _) = call(&router, Method::PUT, "/v1/repo/file", &authed, write()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// Test-only stand-in for the TCP peer address, which `oneshot` connections do not carry.
    async fn test_peer_ip(
        mut req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> Response {
        let ip = req
            .headers()
            .get("x-test-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok());
        if let Some(ip) = ip {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 40000)));
        }
        next.run(req).await
    }

    #[tokio::test]
    async fn lockout_is_per_client_ip_and_https_proxy_headers_are_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = auth_state(tmp.path());
        state.trusted_proxies = Arc::new(vec!["10.0.0.1".parse().unwrap()]);
        let (cookie, _) = state.auth.seed("owner", PW);
        let router = build_router(state).layer(axum::middleware::from_fn(test_peer_ip));
        let login =
            |password: &str| Some(serde_json::json!({ "username": "owner", "password": password }));
        // Everyone below 10.0.0.1 arrives through the trusted proxy, which appends their address.
        let attacker = [
            ("x-test-ip", "10.0.0.1"),
            ("x-forwarded-for", "10.0.0.7, 10.0.0.66"),
        ];
        let owner_ip = [("x-test-ip", "10.0.0.1"), ("x-forwarded-for", "10.0.0.7")];

        // An attacker burning the owner's failures from one address locks only that address.
        for _ in 0..5 {
            let (status, _, _) = call(
                &router,
                Method::POST,
                "/v1/auth/login",
                &attacker,
                login("nope"),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/auth/login",
            &attacker,
            login(PW),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let (status, plain_cookie, _) = call(
            &router,
            Method::POST,
            "/v1/auth/login",
            &owner_ip,
            login(PW),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(plain_cookie.is_some());

        // From a peer that is not the proxy, X-Forwarded-For is noise: rotating it does not
        // dodge the lockout, and claiming a locked-out address does not inherit its lock.
        let direct = "10.0.0.50";
        for spoofed in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"] {
            let headers = [("x-test-ip", direct), ("x-forwarded-for", spoofed)];
            let (status, _, _) = call(
                &router,
                Method::POST,
                "/v1/auth/login",
                &headers,
                login("nope"),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let headers = [("x-test-ip", direct), ("x-forwarded-for", "6.6.6.6")];
        let (status, _, _) =
            call(&router, Method::POST, "/v1/auth/login", &headers, login(PW)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let headers = [("x-test-ip", "10.0.0.51"), ("x-forwarded-for", "10.0.0.66")];
        let (status, _, _) =
            call(&router, Method::POST, "/v1/auth/login", &headers, login(PW)).await;
        assert_eq!(status, StatusCode::OK);

        // `Secure` is set exactly when the trusted proxy reports HTTPS.
        let set_cookie = |peer: &'static str, https: bool| {
            let router = router.clone();
            let body = login(PW).unwrap().to_string();
            async move {
                let mut req = Request::builder()
                    .method(Method::POST)
                    .uri("/v1/auth/login")
                    .header("host", "localhost")
                    .header("x-test-ip", peer)
                    .header("x-forwarded-for", "10.0.0.7")
                    .header("content-type", "application/json");
                if https {
                    req = req.header("x-forwarded-proto", "http, https");
                }
                let resp = oneshot(router, req.body(Body::from(body)).unwrap()).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let expected_hsts = if https && peer == "10.0.0.1" {
                    Some("max-age=31536000; includeSubDomains")
                } else {
                    None
                };
                assert_eq!(
                    resp.headers()
                        .get(header::STRICT_TRANSPORT_SECURITY)
                        .and_then(|value| value.to_str().ok()),
                    expected_hsts
                );
                let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap();
                assert!(csp.contains("script-src 'self'; worker-src 'self' blob:"));
                let value = resp.headers().get(header::SET_COOKIE).unwrap();
                value.to_str().unwrap().to_owned()
            }
        };
        assert!(set_cookie("10.0.0.1", true).await.ends_with("; Secure"));
        assert!(!set_cookie("10.0.0.1", false).await.contains("Secure"));
        assert!(!set_cookie("10.0.0.9", true).await.contains("Secure"));

        // CSRF Origin check behind an HTTPS proxy: preserved Host, or X-Forwarded-Host.
        let revoke = "/v1/auth/sessions/revoke-others";
        for (headers, expected) in [
            (vec![("origin", "http://localhost")], StatusCode::NO_CONTENT),
            (vec![("origin", "https://localhost")], StatusCode::FORBIDDEN),
            (
                vec![
                    ("origin", "https://premier.example.com"),
                    (
                        "x-forwarded-host",
                        "spoofed.example.com, premier.example.com",
                    ),
                    ("x-forwarded-proto", "http, https"),
                    ("x-test-ip", "10.0.0.1"),
                ],
                StatusCode::NO_CONTENT,
            ),
            // The same header from anyone but the proxy is ignored.
            (
                vec![
                    ("origin", "https://premier.example.com"),
                    ("x-forwarded-host", "premier.example.com"),
                    ("x-test-ip", "10.0.0.9"),
                ],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![("origin", "https://premier.example.com")],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![
                    ("origin", "https://evil.test"),
                    ("x-forwarded-host", "premier.example.com"),
                    ("x-test-ip", "10.0.0.1"),
                ],
                StatusCode::FORBIDDEN,
            ),
        ] {
            let mut all = vec![("cookie", cookie.as_str())];
            all.extend(headers.iter().copied());
            let (status, _, _) = call(&router, Method::POST, revoke, &all, None).await;
            assert_eq!(status, expected, "{headers:?}");
        }
    }

    // ---- members ----------------------------------------------------------------------------

    /// Run the repository in `root` the way `premier serve --state-dir` does: its state in a
    /// directory of its own (kept for the test process), nothing of the server in the tree.
    /// Call before the state is built.
    pub(crate) fn state_outside(root: &Path) -> PathBuf {
        let dir = tempfile::tempdir().unwrap().keep();
        store::bind_state_dir(root, &dir, "repo", true);
        dir
    }

    /// `rev` as `@mia`'s clone has it: the commit id the API gives her and takes from her.
    pub(crate) fn hers(state: &ServerState, rev: &str) -> String {
        let root = &state.workspace_root;
        let canonical = repos::git_out(root, &["rev-parse", rev]).unwrap();
        let mia = DelegatedIdentity::human_only(Principal::User("mia".to_owned()), vec![]);
        let policy = state.current_policy().unwrap();
        let visibility = state.branch_visibility_map();
        let view = project_repository(
            &CanonicalGitRepo::open(root),
            &policy,
            "test",
            &mia,
            &visibility,
        );
        view.unwrap().canonical_to_projected[&canonical].clone()
    }

    /// Owners-only default policy over a one-file workspace, with an owner and a member seeded.
    /// Returns `(state, owner cookie, member cookie, member token)`.
    pub(crate) fn member_state(root: &Path) -> (ServerState, String, String, String) {
        std::fs::write(root.join("README.md"), "# Demo\n").unwrap();
        let file = parse_policy_toml(directory::DEFAULT_POLICY_TOML).unwrap();
        let mut state = auth_state(root);
        *state.policy.write().unwrap() =
            Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
        state.repo_policy_path = Some(root.join(".access.toml"));
        let (owner_cookie, _) = state.auth.seed("owner", PW);
        let (mia_cookie, mia_token) = state.auth.seed_as("mia", PW, auth::Role::Member);
        (state, owner_cookie, mia_cookie, mia_token)
    }

    #[tokio::test]
    async fn members_are_themselves_and_owner_only_routes_are_fenced() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, mia_cookie, mia_token) = member_state(tmp.path());
        commit_all(tmp.path());
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let mia = [("cookie", mia_cookie.as_str())];
        let bearer = format!("Bearer {mia_token}");
        let mia_api = [("authorization", bearer.as_str())];

        // The view-as lens is the owner's. A member naming @owner still gets their own view,
        // by session and by token, on reads and on writes.
        let file = "/v1/repo/file?path=README.md&principal=@owner&groups=owners";
        let (_, _, body) = call(&router, Method::GET, file, &owner, None).await;
        assert_eq!(body["allowed"], true);
        for who in [&mia, &mia_api] {
            let (status, _, body) = call(&router, Method::GET, file, who, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["allowed"], false);
            assert!(body["reason"].as_str().unwrap().contains("mia"), "{body}");
            let tree = "/v1/repo/tree?principal=@owner";
            let (_, _, body) = call(&router, Method::GET, tree, who, None).await;
            assert_eq!(body["principal"], "@mia");
            assert_eq!(body["visible_count"], 0);
            let write = serde_json::json!({
                "path": "x.txt", "content": "x", "principal": "@owner"
            });
            let (status, _, _) =
                call(&router, Method::PUT, "/v1/repo/file", who, Some(write)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (_, _, body) = call(
                &router,
                Method::GET,
                "/v1/repo/search?q=demo&principal=@owner",
                who,
                None,
            )
            .await;
            assert_eq!(body["total_hits"], 0);
        }
        assert!(!tmp.path().join("x.txt").exists());
        // An owner viewing as the member sees exactly that.
        let as_mia = "/v1/repo/file?path=README.md&principal=@mia";
        let (_, _, body) = call(&router, Method::GET, as_mia, &owner, None).await;
        assert_eq!(body["allowed"], false);

        // Workspace administration is the owner's: 403 for a member before any body is read.
        for (method, uri) in [
            (Method::PUT, "/v1/policy/repo"),
            (Method::GET, "/v1/users"),
            (Method::POST, "/v1/users"),
            (Method::PATCH, "/v1/users/owner"),
            (Method::DELETE, "/v1/users/owner"),
            (Method::GET, "/v1/backup"),
            (Method::POST, "/v1/secrets/set"),
            (Method::DELETE, "/v1/secrets/STRIPE_API_KEY"),
            (Method::GET, "/v1/audit"),
            (Method::GET, "/v1/audit/export"),
            (Method::PATCH, "/v1/settings"),
            (Method::PUT, "/v1/directory/principals/@mia"),
            (Method::DELETE, "/v1/directory/principals/@bob"),
            (Method::POST, "/v1/approvals/x/decide"),
            (Method::POST, "/v1/overlays/mount"),
            (Method::POST, "/v1/overlays/unmount"),
            (Method::POST, "/v1/agents/sessions"),
            (Method::POST, "/v1/branches/visibility"),
            (Method::POST, "/v1/branches/publish"),
            (Method::DELETE, "/v1/branches/main"),
        ] {
            let (status, _, body) = call(&router, method.clone(), uri, &mia, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
            assert_eq!(body["error"], "this action requires an owner account");
        }
        // What stays open to a member, and what they see of it.
        for uri in [
            "/v1/settings",
            "/v1/directory",
            "/v1/agents/sessions",
            "/v1/branches",
        ] {
            let (status, _, _) = call(&router, Method::GET, uri, &mia, None).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
        }
        let (_, _, status) = call(&router, Method::GET, "/v1/auth/status", &mia, None).await;
        assert_eq!(status["user"]["role"], "member");

        // Search, blame and commit diffs deny outright when no policy is loaded.
        let search = "/v1/repo/search?q=demo";
        let blame = "/v1/repo/blame?path=README.md";
        let (_, _, body) = call(&router, Method::GET, search, &owner, None).await;
        assert_eq!(body["total_hits"], 1);
        let (_, _, body) = call(&router, Method::GET, blame, &owner, None).await;
        assert_eq!(body["allowed"], true);
        *state.policy.write().unwrap() = None;
        let (status, _, body) = call(&router, Method::GET, search, &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total_hits"], 0);
        assert_eq!(body["files_scanned"], 0);
        let (status, _, body) = call(&router, Method::GET, blame, &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["allowed"], false);
    }

    #[tokio::test]
    async fn owner_manages_member_accounts() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, _, _) = member_state(tmp.path());
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let users = |method: Method, name: &'static str, body: Option<serde_json::Value>| {
            let router = router.clone();
            let cookie = owner_cookie.clone();
            async move {
                let uri = format!("/v1/users{name}");
                let (status, _, body) =
                    call(&router, method, &uri, &[("cookie", cookie.as_str())], body).await;
                (status, body)
            }
        };

        // Create: same rules as setup, member by default, 409 when taken.
        let new =
            |name: &str, pw: &str| Some(serde_json::json!({ "username": name, "password": pw }));
        let (status, row) = users(Method::POST, "", new("zed", PW)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(row["created_at"].as_str().map(str::is_empty), Some(false));
        let mut expected = serde_json::json!({
            "username": "zed", "display_name": "zed", "principal": "@zed", "role": "member",
            "totp_enabled": false, "recovery_codes_left": 0, "disabled": false,
            "last_login_at": null,
        });
        expected["created_at"] = row["created_at"].clone();
        assert_eq!(row, expected);
        for (name, pw, code) in [
            ("zed", PW, StatusCode::CONFLICT),
            ("Bad Name", PW, StatusCode::BAD_REQUEST),
            ("yan", "short", StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(
                users(Method::POST, "", new(name, pw)).await.0,
                code,
                "{name}"
            );
        }
        let (_, list) = users(Method::GET, "", None).await;
        let names: Vec<&str> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["owner", "mia", "zed"]);

        // Every account is a directory principal; it is removed as a user, not as a principal.
        let (_, _, dir) = call(&router, Method::GET, "/v1/directory", &owner, None).await;
        assert_eq!(
            dir["principals"][2],
            serde_json::json!({
                "principal": "@zed", "display_name": "zed", "groups": [],
                "is_owner": false, "has_account": true
            })
        );
        let zed_principal = "/v1/directory/principals/@zed";
        let groups = serde_json::json!({ "groups": ["dev"] });
        let (status, _, _) = call(&router, Method::PUT, zed_principal, &owner, Some(groups)).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(&router, Method::DELETE, zed_principal, &owner, None).await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Zed signs in, makes a token; both work, as zed, with the directory's groups over Git.
        let login = Some(serde_json::json!({ "username": "zed", "password": PW }));
        let (status, zed_cookie, body) =
            call(&router, Method::POST, "/v1/auth/login", &[], login.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["role"], "member");
        assert!(body["user"]["last_login_at"].is_string());
        let zed_cookie = zed_cookie.unwrap();
        let zed = [("cookie", zed_cookie.as_str())];
        let cookie = || ("cookie", zed_cookie.clone());
        let token_req = Some(serde_json::json!({ "name": "ci" }));
        let (_, _, tok) = call(&router, Method::POST, "/v1/auth/tokens", &zed, token_req).await;
        let bearer = format!("Bearer {}", tok["token"].as_str().unwrap());
        let api = || ("authorization", bearer.clone());
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("zed:{}", tok["token"].as_str().unwrap())
            )
        );
        let git = || ("authorization", basic.clone());
        let refs = "/git/auth/repo.git/info/refs?service=git-upload-pack";
        let works = |(name, value): (&'static str, String), uri: &'static str| {
            let router = router.clone();
            async move {
                call(&router, Method::GET, uri, &[(name, value.as_str())], None)
                    .await
                    .0
            }
        };
        let tree = "/v1/repo/tree";
        assert_eq!(works(cookie(), tree).await, StatusCode::OK);
        assert_eq!(works(api(), tree).await, StatusCode::OK);
        assert_ne!(works(git(), refs).await, StatusCode::UNAUTHORIZED);
        let zed_principal = Principal::parse("@zed").unwrap();
        assert_eq!(
            directory::groups_for(&state, &zed_principal).unwrap(),
            ["dev"]
        );
        // A member's own security page shows their events, not the workspace's.
        let (_, _, events) = call(&router, Method::GET, "/v1/auth/events", &zed, None).await;
        let kinds: Vec<&str> = events
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["token_created", "login_ok"]);

        // Disabled: the session is gone, the token and password are refused (API and Git).
        let patch = |body: serde_json::Value| users(Method::PATCH, "/zed", Some(body));
        let (status, row) = patch(serde_json::json!({ "disabled": true })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(row["disabled"], true);
        assert_eq!(works(cookie(), tree).await, StatusCode::UNAUTHORIZED);
        assert_eq!(works(api(), tree).await, StatusCode::UNAUTHORIZED);
        assert_eq!(works(git(), refs).await, StatusCode::UNAUTHORIZED);
        let (status, _, _) =
            call(&router, Method::POST, "/v1/auth/login", &[], login.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Re-enabled: the stored token works again, the revoked session does not.
        let (_, row) = patch(serde_json::json!({ "disabled": false, "display_name": "Zed" })).await;
        assert_eq!(row["disabled"], false);
        assert_eq!(row["display_name"], "Zed");
        assert_eq!(works(api(), tree).await, StatusCode::OK);
        assert_eq!(works(cookie(), tree).await, StatusCode::UNAUTHORIZED);

        // An owner-set password signs the user out everywhere and replaces the old one.
        let (_, second_cookie, _) =
            call(&router, Method::POST, "/v1/auth/login", &[], login.clone()).await;
        let (status, _) = patch(serde_json::json!({ "password": "short" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = patch(serde_json::json!({ "password": "a brand new password" })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            works(("cookie", second_cookie.unwrap()), tree).await,
            StatusCode::UNAUTHORIZED
        );
        let (status, _, _) = call(&router, Method::POST, "/v1/auth/login", &[], login).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The workspace always keeps an enabled owner, and nobody deletes themself.
        for body in [
            serde_json::json!({ "role": "member" }),
            serde_json::json!({ "disabled": true }),
        ] {
            let (status, _) = users(Method::PATCH, "/owner", Some(body)).await;
            assert_eq!(status, StatusCode::CONFLICT);
        }
        assert_eq!(
            users(Method::DELETE, "/owner", None).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            users(Method::DELETE, "/nobody", None).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            users(Method::PATCH, "/nobody", Some(serde_json::json!({})))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        // A second owner gets the implicit group; then the first may step down.
        let (_, row) = patch(serde_json::json!({ "role": "owner" })).await;
        assert_eq!(row["role"], "owner");
        let zed_principal = Principal::parse("@zed").unwrap();
        assert_eq!(
            directory::groups_for(&state, &zed_principal).unwrap(),
            ["owners", "dev"]
        );
        let (_, row) = patch(serde_json::json!({ "role": "member" })).await;
        assert_eq!(row["role"], "member");

        // Account management never takes an access token, even an owner's.
        let (_, _, tok) = call(
            &router,
            Method::POST,
            "/v1/auth/tokens",
            &owner,
            Some(serde_json::json!({ "name": "ci" })),
        )
        .await;
        let owner_bearer = format!("Bearer {}", tok["token"].as_str().unwrap());
        let via_token = [("authorization", owner_bearer.as_str())];
        let (status, _, _) = call(&router, Method::GET, "/v1/users", &via_token, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Delete: sessions, tokens and group assignments go with the account.
        assert_eq!(
            users(Method::DELETE, "/zed", None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(works(api(), tree).await, StatusCode::UNAUTHORIZED);
        let (_, _, dir) = call(&router, Method::GET, "/v1/directory", &owner, None).await;
        assert_eq!(dir["principals"].as_array().unwrap().len(), 2);
        let (_, _, events) = call(&router, Method::GET, "/v1/auth/events", &owner, None).await;
        let kinds: Vec<&str> = events
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        for kind in ["user_created", "user_updated", "user_deleted"] {
            assert!(kinds.contains(&kind), "{kind} missing from {kinds:?}");
        }
    }

    #[tokio::test]
    async fn single_owner_auth_json_from_before_roles_loads_as_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let state = auth_state(tmp.path());
        let source = tempfile::tempdir().unwrap();
        let source = auth::AuthStore::open(source.path());
        let (cookie, _) = source.seed("old", PW);
        // Write a pre-roles JSON fixture with a valid session.
        let path = tmp.path().join(".premier/auth.json");
        let mut json = source
            .txn(|data| serde_json::to_value(&*data))
            .unwrap()
            .unwrap();
        let user = json["users"][0].as_object_mut().unwrap();
        for field in ["role", "disabled", "last_login_at"] {
            assert!(user.remove(field).is_some(), "{field}");
        }
        json["events"] = serde_json::json!([{
            "at": "2026-01-01T00:00:00Z", "kind": "login_ok", "ip": "x", "user_agent": "x", "detail": ""
        }]);
        store::save_json(tmp.path(), "auth.json", &json).unwrap();
        assert!(path.is_file());

        let router = build_router(state.clone());
        let authed = [("cookie", cookie.as_str())];
        let (status, _, body) = call(&router, Method::GET, "/v1/auth/status", &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["role"], "owner");
        assert_eq!(body["user"]["disabled"], false);
        let (status, _, _) = call(&router, Method::GET, "/v1/users", &authed, None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, dir) = call(&router, Method::GET, "/v1/directory", &authed, None).await;
        assert_eq!(
            dir["principals"][0]["groups"],
            serde_json::json!(["owners"])
        );
        auth::reset_password(tmp.path(), "old", "a brand new password").unwrap();
    }

    // ---- what a member may see (one test per hardening item) ---------------------------------

    const OWNER_ONLY: &str = "this action requires an owner account";

    /// Owners have everything; any signed-in account reads the tree except `@mia` under
    /// `billing/`, and `@mia` may `use` (only) `STRIPE_API_KEY`.
    pub(crate) const MEMBER_POLICY: &str = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-no-billing"
effect = "deny"
principals = ["@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-stripe"
effect = "allow"
principals = ["@mia"]
paths = ["secrets/STRIPE_API_KEY"]
refs = ["*"]
capabilities = ["use"]
"#;

    pub(crate) fn use_member_policy(state: &ServerState) {
        let file = parse_policy_toml(MEMBER_POLICY).unwrap();
        *state.policy.write().unwrap() =
            Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
        state.set_repo_policy_metadata(Some(MEMBER_POLICY.to_owned()), Some(Arc::new(file)));
    }

    #[tokio::test]
    async fn member_gets_no_policy_text_and_only_usable_env_vars() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, owner_cookie, mia_cookie, _) = member_state(tmp.path());
        use_member_policy(&state);
        state.server_policy_toml = Some("version = 1\n".to_owned());
        let schema: EnvSchema = serde_json::from_value(serde_json::json!({
            "vars": { "STRIPE_API_KEY": {}, "DB_URL": { "required_in": ["prod"] } }
        }))
        .unwrap();
        state.env_schema = Arc::new(RwLock::new(Some(Arc::new(schema))));
        let router = build_router(state);
        let owner = [("cookie", owner_cookie.as_str())];
        let mia = [("cookie", mia_cookie.as_str())];

        let summary = "/v1/policy/summary";
        let (_, _, body) = call(&router, Method::GET, summary, &owner, None).await;
        assert_eq!(body["repo_policy_toml"], MEMBER_POLICY);
        assert_eq!(body["server_policy_toml"], "version = 1\n");
        assert_eq!(body["policy"]["rules"][1]["id"], "mia-no-billing");
        let (status, _, body) = call(&router, Method::GET, summary, &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "policy_loaded": true, "server_policy_loaded": true,
                "imported_policy_pending": false,
                "repo_policy_toml": "", "server_policy_toml": "", "policy": null
            })
        );

        let vars = |body: &serde_json::Value| -> Vec<String> {
            body["vars"].as_object().unwrap().keys().cloned().collect()
        };
        let (_, _, body) = call(&router, Method::GET, "/v1/env/schema", &owner, None).await;
        assert_eq!(vars(&body), ["DB_URL", "STRIPE_API_KEY"]);
        let (status, _, body) = call(&router, Method::GET, "/v1/env/schema", &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(vars(&body), ["STRIPE_API_KEY"]);
        let dash = "/v1/env/dashboard";
        let (_, _, body) = call(&router, Method::GET, dash, &owner, None).await;
        assert_eq!(body["reports"]["prod"]["issues"][0]["var_name"], "DB_URL");
        let (status, _, body) = call(&router, Method::GET, dash, &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(vars(&body["schema"]), ["STRIPE_API_KEY"]);
        assert!(!body.to_string().contains("DB_URL"), "{body}");
    }

    #[tokio::test]
    async fn member_sees_only_their_own_approvals_and_sessions_also_over_sse() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, owner_cookie, mia_cookie, _) = member_state(tmp.path());
        let session = |id: &str, principal: &str| runner::AgentSessionRecord {
            id: id.to_owned(),
            principal: principal.to_owned(),
            agent_profile: "ui-agent".to_owned(),
            env: "dev".to_owned(),
            command: "true".to_owned(),
            proxy_url: String::new(),
            placeholders: BTreeMap::new(),
            status: "completed".to_owned(),
            exit_code: Some(0),
            bytes_scrubbed: 0,
            started_at: String::new(),
            finished_at: None,
            output_lines: vec![format!("output of {principal}")],
            ..Default::default()
        };
        let sessions = vec![session("cage-0001", "@owner"), session("cage-0002", "@mia")];
        store::save_json(tmp.path(), "sessions.json", &sessions).unwrap();
        state.session_manager = Arc::new(SessionManager::open(tmp.path()));
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let mia = [("cookie", mia_cookie.as_str())];
        let approval = |principal: &str| premier_proxy::ApprovalRequest {
            principal: principal.to_owned(),
            agent_profile: None,
            var_name: "GITHUB_TOKEN".to_owned(),
            host: "api.github.com".to_owned(),
            method: "POST".to_owned(),
            path: "/".to_owned(),
            ttl_secs: 60,
            kind: None,
            mcp_server: None,
            mcp_tool: None,
            risk: None,
            args_summary: None,
            args_hash: None,
            ref_name: None,
            ..premier_proxy::ApprovalRequest::default()
        };

        // The live stream: the owner's approval is enqueued first and must never reach mia.
        let stream = Request::builder()
            .uri("/v1/events/stream")
            .header("host", "localhost")
            .header("cookie", &mia_cookie)
            .body(Body::empty())
            .unwrap();
        let mut stream = oneshot(router.clone(), stream).await.into_body();
        let _owner_pending = state.approval_hub.enqueue(approval("@owner"));
        let _mia_pending = state.approval_hub.enqueue(approval("@mia"));
        let mut seen = String::new();
        while !seen.contains("event: approval") {
            let frame = tokio::time::timeout(Duration::from_secs(10), stream.frame()).await;
            let data = frame.unwrap().unwrap().unwrap().into_data().unwrap();
            seen.push_str(&String::from_utf8_lossy(&data));
        }
        assert!(seen.contains("@mia") && !seen.contains("@owner"), "{seen}");

        let principals = |body: &serde_json::Value| -> Vec<String> {
            let rows = body.as_array().unwrap().iter();
            rows.map(|r| r["principal"].as_str().unwrap().to_owned())
                .collect()
        };
        for uri in ["/v1/approvals", "/v1/agents/sessions"] {
            let (_, _, body) = call(&router, Method::GET, uri, &owner, None).await;
            assert_eq!(principals(&body).len(), 2, "{uri}");
            let (status, _, body) = call(&router, Method::GET, uri, &mia, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(principals(&body), ["@mia"], "{uri}");
            assert!(!body.to_string().contains("@owner"), "{body}");
        }

        // No per-principal view of the vault or the overlays: the owner's.
        let check = || Some(serde_json::json!({ "paths": ["README.md"] }));
        for (method, uri, body) in [
            (Method::GET, "/v1/secrets/status", None),
            (Method::GET, "/v1/overlays", None),
            (Method::POST, "/v1/overlays/check", check()),
        ] {
            let (status, _, _) = call(&router, method.clone(), uri, &owner, body.clone()).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            let (status, _, body) = call(&router, method, uri, &mia, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(body["error"], OWNER_ONLY);
        }
    }

    #[tokio::test]
    async fn member_cannot_branch_diff_or_review_hidden_refs_or_unreadable_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (state, owner_cookie, mia_cookie, _) = member_state(root);
        use_member_policy(&state);
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(root)
                .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        std::fs::create_dir_all(root.join("billing")).unwrap();
        std::fs::write(root.join("billing/ledger.rs"), "// v1\n").unwrap();
        git(&["init", "-q", "-b", "main"]);
        git(&["add", "README.md", "billing"]);
        git(&["commit", "-q", "-m", "initial"]);
        git(&["checkout", "-q", "-b", "feature"]);
        std::fs::write(root.join("README.md"), "# Demo 2\n").unwrap();
        std::fs::write(root.join("billing/ledger.rs"), "// v2\n").unwrap();
        git(&["commit", "-q", "-am", "feature work"]);
        git(&["update-ref", "refs/premier-private/hush", "HEAD"]);
        git(&["checkout", "-q", "main"]);
        state.persisted.lock().unwrap().branch_metadata.insert(
            "hush".to_owned(),
            (
                Visibility::Restricted(vec!["@owner".to_owned()]),
                Readiness::Wip,
            ),
        );
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let mia = [("cookie", mia_cookie.as_str())];
        let post =
            |who: [(&'static str, String); 1], uri: &'static str, body: serde_json::Value| {
                let router = router.clone();
                async move {
                    let headers = [(who[0].0, who[0].1.as_str())];
                    let (status, _, body) =
                        call(&router, Method::POST, uri, &headers, Some(body)).await;
                    (status, body)
                }
            };
        let as_owner = || [("cookie", owner_cookie.clone())];
        let as_mia = || [("cookie", mia_cookie.clone())];

        // Branch create: a hidden base is a missing base, and a taken name is never moved.
        let create = |name: &str, from: &str| serde_json::json!({ "name": name, "from_ref": from });
        let hidden = post(as_mia(), "/v1/branches/create", create("a", "hush")).await;
        let missing = post(as_mia(), "/v1/branches/create", create("a", "nope")).await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND);
        assert_eq!(hidden, missing);
        // A name held by a branch she cannot see fails exactly like a ref git refuses to create;
        // only a branch she can see is reported as taken.
        let taken_hidden = post(as_mia(), "/v1/branches/create", create("hush", "main")).await;
        let generic = post(as_mia(), "/v1/branches/create", create("bad~name", "main")).await;
        assert_eq!(taken_hidden.0, StatusCode::BAD_REQUEST);
        assert_eq!(taken_hidden, generic);
        let (status, _) = post(as_mia(), "/v1/branches/create", create("feature", "main")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!matches!(
            state.branch_visibility_map()["refs/premier-private/hush"],
            Visibility::Public
        ));
        let (status, _) = post(as_mia(), "/v1/branches/create", create("mine", "main")).await;
        assert_eq!(status, StatusCode::OK);
        let private = "refs/premier-private/hush";
        let (status, _) = post(as_mia(), "/v1/branches/create", create("a", private)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = post(as_owner(), "/v1/branches/create", create("theirs", private)).await;
        assert_eq!(status, StatusCode::OK);

        // Squash preview: same, and a member is not told the names of paths they cannot read.
        let squash = "/v1/branches/squash-preview";
        let preview = |branch: &str| serde_json::json!({ "branch": branch });
        let hidden = post(as_mia(), squash, preview("hush")).await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND);
        assert_eq!(hidden, post(as_mia(), squash, preview("nope")).await);
        let (status, body) = post(as_owner(), squash, preview("hush")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["private_commits_collapsed"], 1);
        let both = serde_json::json!(["README.md", "billing/ledger.rs"]);
        let (_, body) = post(as_owner(), squash, preview("feature")).await;
        assert_eq!(body["scrubbed_paths"], both);
        let (status, body) = post(as_mia(), squash, preview("feature")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scrubbed_paths"], serde_json::json!(["README.md"]));
        assert!(!body.to_string().contains("billing"), "{body}");

        // Reviews: created, listed, commented and judged only on visible branches.
        let review = |branch: &str| serde_json::json!({ "title": "t", "branch": branch });
        let (status, hush_review) = post(as_owner(), "/v1/reviews", review("hush")).await;
        assert_eq!(status, StatusCode::OK);
        let (_, feature_review) = post(as_owner(), "/v1/reviews", review("feature")).await;
        let hidden = post(as_mia(), "/v1/reviews", review("hush")).await;
        let missing = post(as_mia(), "/v1/reviews", review("nope")).await;
        assert_eq!(hidden.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            hidden.1["error"].as_str().unwrap().replace("hush", "nope"),
            missing.1["error"]
        );

        let (_, _, list) = call(&router, Method::GET, "/v1/reviews", &owner, None).await;
        assert_eq!(list.as_array().unwrap().len(), 2);
        assert!(list.to_string().contains("billing/ledger.rs"));
        let (_, _, list) = call(&router, Method::GET, "/v1/reviews", &mia, None).await;
        let list = list.as_array().unwrap();
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(list[0]["change_id"], feature_review["change_id"]);
        let hunks = list[0]["rounds"][0]["hunks"].as_array().unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0]["path"], "README.md");
        assert!(!list[0].to_string().contains("billing"), "{list:?}");

        let uri = |id: &serde_json::Value, what: &str| -> &'static str {
            Box::leak(format!("/v1/reviews/{}/{what}", id.as_str().unwrap()).into_boxed_str())
        };
        let nope = serde_json::json!("Inope");
        let comment = || serde_json::json!({ "path": "README.md", "body": "hi" });
        let verdict = || serde_json::json!({ "round": 1, "verdict": "approve" });
        for (what, body) in [("comments", comment()), ("verdict", verdict())] {
            let hidden = post(as_mia(), uri(&hush_review["change_id"], what), body.clone()).await;
            assert_eq!(hidden.0, StatusCode::NOT_FOUND, "{what}");
            assert_eq!(hidden, post(as_mia(), uri(&nope, what), body.clone()).await);
            let (status, _) = post(
                as_owner(),
                uri(&hush_review["change_id"], what),
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{what}");
            let (status, _) = post(as_mia(), uri(&feature_review["change_id"], what), body).await;
            assert_eq!(status, StatusCode::OK, "{what}");
        }
        let unreadable = serde_json::json!({ "path": "billing/ledger.rs", "body": "hi" });
        let comments = uri(&feature_review["change_id"], "comments");
        let (status, _) = post(as_mia(), comments, unreadable).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Commit diffs: a file the viewer cannot list is left out, name included, and counted.
        // The root commit is diffed against the empty tree, and counts only visible files too.
        let rev = |name: &str| {
            let out = std::process::Command::new("git")
                .current_dir(root)
                .args(["rev-parse", name])
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let diff = format!("/v1/commits/{}", rev("feature"));
        // She names the commit as her clone has it.
        let her_diff = format!("/v1/commits/{}", hers(&state, "feature"));
        let (status, _, body) = call(&router, Method::GET, &her_diff, &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["hidden_files"], 1);
        assert_eq!(body["files"].as_array().unwrap().len(), 1);
        assert_eq!(body["files"][0]["path"], "README.md");
        assert_eq!(body["files"][0]["allowed"], true);
        assert!(!body.to_string().contains("billing"), "{body}");
        let (_, _, body) = call(&router, Method::GET, &diff, &owner, None).await;
        assert_eq!(body["hidden_files"], 0);
        assert_eq!(body["files"].as_array().unwrap().len(), 2);
        let (_, _, log) = call(&router, Method::GET, "/v1/commits", &owner, None).await;
        assert_eq!(log[0]["oid"], rev("main").as_str());
        assert_eq!(log[0]["files_changed"], 2);
        let (_, _, log) = call(&router, Method::GET, "/v1/commits", &mia, None).await;
        assert_eq!(log[0]["files_changed"], 1);

        // Without a policy, comments and hunks fail closed, for the owner too.
        *state.policy.write().unwrap() = None;
        let (status, _) = post(as_owner(), comments, comment()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, _, list) = call(&router, Method::GET, "/v1/reviews", &owner, None).await;
        for rev in list.as_array().unwrap() {
            assert_eq!(rev["rounds"][0]["hunks"], serde_json::json!([]));
            assert_eq!(rev["comments"], serde_json::json!([]));
        }
    }

    const STEER_POLICY: &str = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read"]
[zones.docs]
paths = ["README.md"]
[zones.ledger]
paths = ["billing/**"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-no-read-billing"
effect = "deny"
principals = ["@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["read", "write", "use"]
"#;

    #[tokio::test]
    async fn steering_comments_and_trust_receipts_respect_acls() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (state, owner_cookie, mia_cookie, _) = member_state(root);
        let file = parse_policy_toml(STEER_POLICY).unwrap();
        *state.policy.write().unwrap() =
            Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
        state.set_repo_policy_metadata(Some(STEER_POLICY.to_owned()), Some(Arc::new(file)));
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(root)
                .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        std::fs::create_dir_all(root.join("billing")).unwrap();
        std::fs::write(root.join("billing/ledger.rs"), "// v1\n").unwrap();
        git(&["init", "-q", "-b", "main"]);
        git(&["add", "README.md", "billing"]);
        git(&["commit", "-q", "-m", "initial"]);
        git(&["checkout", "-q", "-b", "feature"]);
        std::fs::write(root.join("README.md"), "# Demo 2\n").unwrap();
        std::fs::write(root.join("billing/ledger.rs"), "// v2\n").unwrap();
        git(&["commit", "-q", "-am", "feature work"]);
        git(&["checkout", "-q", "-b", "ledgeronly", "main"]);
        std::fs::write(root.join("billing/ledger.rs"), "// v3\n").unwrap();
        git(&["commit", "-q", "-am", "ledger only"]);
        git(&["update-ref", "refs/premier-private/hush", "HEAD"]);
        git(&["checkout", "-q", "main"]);
        state.persisted.lock().unwrap().branch_metadata.insert(
            "hush".to_owned(),
            (
                Visibility::Restricted(vec!["@owner".to_owned()]),
                Readiness::Wip,
            ),
        );
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let mia = [("cookie", mia_cookie.as_str())];

        let review = |b: &str| serde_json::json!({ "title": "t", "branch": b });
        let (_, _, feature) = call(
            &router,
            Method::POST,
            "/v1/reviews",
            &owner,
            Some(review("feature")),
        )
        .await;
        let (_, _, ledger) = call(
            &router,
            Method::POST,
            "/v1/reviews",
            &owner,
            Some(review("ledgeronly")),
        )
        .await;
        let (_, _, hush) = call(
            &router,
            Method::POST,
            "/v1/reviews",
            &owner,
            Some(review("hush")),
        )
        .await;
        // A captured caged session owned by `@owner` on every review.
        for r in state.persisted.lock().unwrap().reviews.iter_mut() {
            r.provenance = Some(crate::store::CapturedProvenance {
                session_id: "sess-1".to_owned(),
                principal: Some("@owner".to_owned()),
                agent_profile: "claude".to_owned(),
                command: "agent".to_owned(),
                prompt_summary: "do it".to_owned(),
                tool_calls: vec!["cat billing/ledger.rs".to_owned()],
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                steps: Vec::new(),
                sandbox: Some("bwrap".to_owned()),
                bytes_scrubbed: 7,
                exit_code: Some(0),
                egress_calls: 3,
                egress_blocked: 1,
            });
        }
        // Plus a captured session owned by `@mia` on `feature` to confirm she sees her own session.
        let (_, _, mia_own_rev) = call(
            &router,
            Method::POST,
            "/v1/reviews",
            &mia,
            Some(review("feature")),
        )
        .await;
        if let Ok(mut st) = state.persisted.lock()
            && let Some(r) = st
                .reviews
                .iter_mut()
                .find(|r| r.change_id == mia_own_rev["change_id"].as_str().unwrap())
        {
            r.provenance = Some(crate::store::CapturedProvenance {
                session_id: "sess-mia".to_owned(),
                principal: Some("@mia".to_owned()),
                agent_profile: "claude".to_owned(),
                command: "agent".to_owned(),
                prompt_summary: "mia session".to_owned(),
                tool_calls: vec!["cat README.md".to_owned()],
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                steps: Vec::new(),
                sandbox: Some("bwrap".to_owned()),
                bytes_scrubbed: 4,
                exit_code: Some(0),
                egress_calls: 2,
                egress_blocked: 0,
            });
        }

        let comments = |v: &serde_json::Value| {
            format!("/v1/reviews/{}/comments", v["change_id"].as_str().unwrap())
        };
        let steer = |path: &str, agent: serde_json::Value| {
            serde_json::json!({
                "path": path, "body": "use the helper", "kind": "steer",
                "target_agent": agent
            })
        };

        // Unknown/inaccessible steer_session_id is rejected (400).
        let uri = comments(&feature);
        let (status, _, _) = call(
            &router,
            Method::POST,
            &uri,
            &mia,
            Some(serde_json::json!({
                "path": "README.md", "body": "spoof", "kind": "steer",
                "target_agent": "claude", "steer_session_id": "sess-1"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A steering comment persists its kind and target.
        let (status, _, c) = call(
            &router,
            Method::POST,
            &uri,
            &mia,
            Some(steer("README.md", "claude".into())),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{c}");
        assert_eq!(c["kind"], "steer");
        assert_eq!(c["target_agent"], "claude");
        assert!(c.get("steer_session_id").is_none(), "{c}");
        let audited = state.audit_sink.snapshot();
        let ev = audited
            .iter()
            .find(|e| e.action == "review_steer_directive")
            .unwrap();
        assert_eq!(ev.target.as_deref(), Some("README.md"));
        assert!(ev.reason.contains(feature["change_id"].as_str().unwrap()));
        assert!(ev.reason.contains("claude"));
        // A plain comment stays a plain comment and omits the steering fields.
        let plain = serde_json::json!({ "path": "README.md", "body": "hi" });
        let (_, _, c) = call(&router, Method::POST, &uri, &mia, Some(plain)).await;
        assert_eq!(c["kind"], "comment");
        assert!(c.get("target_agent").is_none(), "{c}");

        // Bad labels are 400; an unreadable path is 403; a hidden branch's review is a 404.
        for bad in [
            serde_json::json!("   "),
            serde_json::json!("a".repeat(65)),
            serde_json::json!("bad\u{7}name"),
        ] {
            let (status, _, _) = call(
                &router,
                Method::POST,
                &uri,
                &mia,
                Some(steer("README.md", bad)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, _, _) = call(
            &router,
            Method::POST,
            &uri,
            &mia,
            Some(steer("billing/ledger.rs", "claude".into())),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(
            &router,
            Method::POST,
            &comments(&hush),
            &mia,
            Some(steer("README.md", "claude".into())),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Owner: full receipt, zones and the session on every hunk.
        let find = |list: &serde_json::Value, v: &serde_json::Value| {
            list.as_array()
                .unwrap()
                .iter()
                .find(|r| r["change_id"] == v["change_id"])
                .cloned()
        };
        let (_, _, list) = call(&router, Method::GET, "/v1/reviews", &owner, None).await;
        let rec = find(&list, &feature).unwrap();
        assert_eq!(rec["base_ref"], "main");
        assert_eq!(rec["session_id"], "sess-1");
        let hunks = rec["rounds"][0]["hunks"].as_array().unwrap();
        let zone_of = |p: &str| hunks.iter().find(|h| h["path"] == p).unwrap()["zone"].clone();
        assert_eq!(zone_of("README.md"), "docs");
        assert_eq!(zone_of("billing/ledger.rs"), "ledger");
        let prov = &hunks[0]["provenance"];
        assert_eq!(prov["sandbox"], "bwrap");
        assert_eq!(prov["bytes_scrubbed"], 7);
        assert_eq!(prov["egress_calls"], 3);
        assert_eq!(prov["egress_blocked"], 1);
        assert_eq!(prov["exit_code"], 0);
        assert_eq!(prov["session_id"], "sess-1");
        assert!(
            rec["comments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["kind"] == "steer")
        );

        // Mia: does NOT receive `@owner`'s session provenance/receipt even on readable README.md,
        // and the unreadable billing hunk is redacted outright.
        let (_, _, list) = call(&router, Method::GET, "/v1/reviews", &mia, None).await;
        assert!(find(&list, &hush).is_none(), "hidden branch review listed");
        let rec = find(&list, &feature).unwrap();
        assert!(rec.get("session_id").is_none(), "{rec}");
        assert!(!rec.to_string().contains("sess-1"), "{rec}");
        assert!(!rec.to_string().contains("cat billing/ledger.rs"), "{rec}");
        let hunks = rec["rounds"][0]["hunks"].as_array().unwrap();
        let readme = hunks.iter().find(|h| h["path"] == "README.md").unwrap();
        assert_eq!(readme["zone"], "docs");
        assert_eq!(readme["provenance"]["session_visible"], false);
        assert!(readme["provenance"].get("egress_calls").is_none());
        let billing = hunks
            .iter()
            .find(|h| h["path"] == "billing/ledger.rs")
            .unwrap();
        assert_eq!(billing["allowed"], false);
        assert_eq!(billing["zone"], "");
        for k in [
            "session_id",
            "sandbox",
            "bytes_scrubbed",
            "egress_calls",
            "egress_blocked",
            "exit_code",
            "created_at",
        ] {
            assert!(
                billing["provenance"].get(k).is_none(),
                "{k} leaked: {billing}"
            );
        }
        // Mia DOES receive her own session's receipt on readable README.md, still redacted on billing.
        let own_rec = find(&list, &mia_own_rev).unwrap();
        assert_eq!(own_rec["session_id"], "sess-mia");
        let own_hunks = own_rec["rounds"][0]["hunks"].as_array().unwrap();
        let own_readme = own_hunks.iter().find(|h| h["path"] == "README.md").unwrap();
        assert_eq!(own_readme["provenance"]["session_visible"], true);
        assert_eq!(own_readme["provenance"]["egress_calls"], 2);
        let own_billing = own_hunks
            .iter()
            .find(|h| h["path"] == "billing/ledger.rs")
            .unwrap();
        assert_eq!(own_billing["allowed"], false);
        assert!(own_billing["provenance"].get("egress_calls").is_none());

        // A review whose every hunk she cannot read does not name the session at all.
        let rec = find(&list, &ledger).unwrap();
        assert!(rec.get("session_id").is_none(), "{rec}");
        assert!(!rec.to_string().contains("sess-1"), "{rec}");
        assert!(!rec.to_string().contains("bwrap"), "{rec}");

        // Without a login, nothing of the receipt is served.
        let (status, _, body) = call(&router, Method::GET, "/v1/reviews", &[], None).await;
        assert_ne!(status, StatusCode::OK);
        assert!(!body.to_string().contains("sess-1"), "{body}");
    }

    #[tokio::test]
    async fn policy_simulators_are_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, mia_cookie, _) = member_state(tmp.path());
        let router = build_router(state);
        let policy = directory::DEFAULT_POLICY_TOML;
        for (uri, body) in [
            (
                "/v1/access/explain",
                serde_json::json!({ "principal": "@owner", "path": "README.md" }),
            ),
            (
                "/v1/access/diff",
                serde_json::json!({ "base_toml": policy, "head_toml": policy }),
            ),
        ] {
            let owner = [("cookie", owner_cookie.as_str())];
            let (status, _, _) = call(&router, Method::POST, uri, &owner, Some(body.clone())).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            let mia = [("cookie", mia_cookie.as_str())];
            let (status, _, body) = call(&router, Method::POST, uri, &mia, Some(body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(body, serde_json::json!({ "error": OWNER_ONLY }));
        }
    }

    #[tokio::test]
    async fn health_details_need_a_valid_session() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, mia_cookie, mia_token) = member_state(tmp.path());
        let router = build_router(state);
        let minimal = serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") });
        for headers in [vec![], vec![("cookie", "premier_session=forged")]] {
            let (status, _, body) = call(&router, Method::GET, "/health", &headers, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, minimal);
        }
        let bearer = format!("Bearer {mia_token}");
        let host = [
            "os",
            "workspace_root",
            "policy_loaded",
            "server_policy_loaded",
            "schema_loaded",
            "host_capabilities",
            "agent_sandbox_detail",
        ];
        // A member learns whether agents run sandboxed, not where or how the server lives.
        for headers in [
            [("cookie", mia_cookie.as_str())],
            [("authorization", bearer.as_str())],
        ] {
            let (_, _, body) = call(&router, Method::GET, "/health", &headers, None).await;
            assert_eq!(body["status"], "ok");
            assert!(!body["agent_sandbox"].is_null(), "{body}");
            for field in host {
                assert!(body[field].is_null(), "{field} shown to a member: {body}");
            }
        }
        let (_, _, body) = call(
            &router,
            Method::GET,
            "/health",
            &[("cookie", owner_cookie.as_str())],
            None,
        )
        .await;
        for field in host {
            assert!(!body[field].is_null(), "{field} missing from {body}");
        }
    }

    #[tokio::test]
    async fn a_claimed_identity_outside_a_gated_request_is_anonymous() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, ..) = member_state(tmp.path());
        // No gate scope here, exactly like a handler that built its identity in a spawned task
        // or on a route the gate does not authenticate: the claim must not stand.
        let claimed = directory::identity(&state, "@owner", None, "test").unwrap();
        assert_eq!(claimed.principal, Principal::Anonymous);
        assert!(claimed.groups.is_empty());
        assert_eq!(auth::effective_principal("@owner"), "anonymous");
        assert!(!auth::caller_is_owner());
        assert!(auth::owner_only().is_err());
    }

    #[tokio::test]
    async fn overlays_are_per_principal_encrypted_in_state_and_never_in_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("README.md"), "# Demo\n").unwrap();
        commit_all(root);
        let state = auth_state(root);
        let (alice, _) = state.auth.seed_as("alice", PW, auth::Role::Owner);
        let (bob, _) = state.auth.seed_as("bob", PW, auth::Role::Owner);
        let (carol, _) = state.auth.seed_as("carol", PW, auth::Role::Owner);
        let router = build_router(state.clone());
        let alice = [("cookie", alice.as_str())];
        let bob = [("cookie", bob.as_str())];
        let carol = [("cookie", carol.as_str())];
        let mount = |content: &str| {
            serde_json::json!({
                "path": "AGENTS.local.md", "scope": "personal", "encrypted": true,
                "create_file": true, "initial_content": content,
            })
        };

        let (status, _, body) = call(
            &router,
            Method::POST,
            "/v1/overlays/mount",
            &alice,
            Some(mount("alice-secret-notes")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["version"], 1);
        assert_eq!(body["entries"].as_array().unwrap().len(), 1, "{body}");
        let entry = &body["entries"][0];
        assert_eq!(entry["owner_principal"], "@alice");
        assert_eq!(entry["has_payload"], true);
        assert_eq!(entry["encrypted"], true);
        let (status, _, body) = call(
            &router,
            Method::POST,
            "/v1/overlays/mount",
            &bob,
            Some(mount("bob-secret-notes")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let glob = serde_json::json!({ "path": "bob/*.env", "scope": "personal" });
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/overlays/mount",
            &bob,
            Some(glob),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Nothing in the working tree; the state directory holds only ciphertext.
        assert!(!root.join("AGENTS.local.md").exists());
        let blobs = store::state_dir(root).join("overlays").join("blobs");
        let count = || std::fs::read_dir(&blobs).unwrap().count();
        assert_eq!(count(), 2);
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let text = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
                    assert!(!text.contains("secret-notes"), "{}", p.display());
                }
            }
        }

        // Each sees only their own personal overlays.
        let (_, _, list) = call(&router, Method::GET, "/v1/overlays", &alice, None).await;
        assert_eq!(list["entries"].as_array().unwrap().len(), 1, "{list}");
        assert_eq!(list["entries"][0]["owner_principal"], "@alice");
        let (_, _, list) = call(&router, Method::GET, "/v1/overlays", &bob, None).await;
        assert_eq!(list["entries"].as_array().unwrap().len(), 2, "{list}");
        let (_, _, list) = call(&router, Method::GET, "/v1/overlays", &carol, None).await;
        assert_eq!(list["entries"], serde_json::json!([]));

        // Push exclusion covers everyone's overlays, whoever checks.
        let check = serde_json::json!({ "paths": ["bob/prod.env", "src/main.rs"] });
        let (_, _, verdict) = call(
            &router,
            Method::POST,
            "/v1/overlays/check",
            &carol,
            Some(check),
        )
        .await;
        assert_eq!(verdict["allowed"], false);
        assert_eq!(
            verdict["blocked_paths"],
            serde_json::json!(["bob/prod.env"])
        );

        // Carol may not unmount someone else's personal overlay.
        let unmount = serde_json::json!({ "path": "AGENTS.local.md" });
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/overlays/unmount",
            &carol,
            Some(unmount.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(count(), 2);

        // Alice's unmount deletes her blob and leaves Bob's overlay (and its guard) intact.
        let (status, _, list) = call(
            &router,
            Method::POST,
            "/v1/overlays/unmount",
            &alice,
            Some(unmount),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list["entries"], serde_json::json!([]));
        assert_eq!(count(), 1);
        let store = overlay_store(root).unwrap();
        assert_eq!(
            store
                .read_payload_for_principal("AGENTS.local.md", "@bob", &[])
                .unwrap()
                .unwrap(),
            b"bob-secret-notes"
        );
        let recorded = state.persisted.lock().unwrap().overlays.clone();
        assert!(
            recorded.entries.iter().any(|e| e.path == "AGENTS.local.md"),
            "{recorded:?}"
        );
    }
}
