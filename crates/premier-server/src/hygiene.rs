//! Quiet ambient policy-hygiene insights (`GET /v1/hygiene/insights`, dismiss / restore).
//!
//! Four read-only detectors over the committed tree, the working tree, branch metadata and the
//! `.env.schema`: unzoned sensitive-looking folders, local files that should be overlays, stale
//! private branches, and missing vault secrets / broad egress allow-lists. Nothing here enforces
//! anything: an insight is a suggestion with a drafted action. Raw secret values are never read
//! into an insight; the vault is only asked whether a value exists.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use globset::{GlobBuilder, GlobMatcher};
use premier_core::{Capability, DelegatedIdentity, Principal, Readiness, RepoPath, Visibility};
use premier_overlay::{OverlayGuard, OverlayManifest};
use premier_policy::{AccessPolicyFile, CompiledPolicy};
use premier_secrets::{ApprovalMode, EnvSchema, SecretCoord, SecretLayer, Sensitivity, VarType};
use serde::{Deserialize, Serialize};

use crate::store::SecretMetaEntry;
use crate::{ApiError, PRIVATE_REF_PREFIX, ServerState, err_resp};

type ApiErr = (StatusCode, Json<ApiError>);

const STALE_BRANCH_DAYS: i64 = 14;
const MAX_DISMISSED: usize = 1000;
const MAX_ID_BYTES: usize = 512;
const MAX_OVERLAY_INSIGHTS: usize = 100;
const BROAD_SECRET_HOSTS: usize = 5;
const BROAD_AGENT_HOSTS: usize = 8;

/// What kind of hygiene problem an insight is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneCategory {
    UnzonedDirectory,
    OverlayLeak,
    StalePrivateBranch,
    MissingVaultSecret,
    BroadEgressHost,
}

impl HygieneCategory {
    fn rank(self) -> u8 {
        match self {
            Self::UnzonedDirectory => 0,
            Self::OverlayLeak => 1,
            Self::StalePrivateBranch => 2,
            Self::MissingVaultSecret => 3,
            Self::BroadEgressHost => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneSeverity {
    Attention,
    Notice,
}

impl HygieneSeverity {
    fn rank(self) -> u8 {
        match self {
            Self::Attention => 0,
            Self::Notice => 1,
        }
    }
}

/// The one-click follow-up an insight offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HygieneAction {
    DraftPolicyRule {
        zone_name: String,
        path_glob: String,
        toml_snippet: String,
    },
    AddOverlayGuard {
        path: String,
        suggested_scope: String,
    },
    ConfigureSecret {
        env: String,
        var_name: String,
    },
    InspectBranch {
        branch: String,
    },
    ReviewAgentEgress {
        profile: String,
        hosts: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneInsight {
    pub id: String,
    pub category: HygieneCategory,
    pub severity: HygieneSeverity,
    pub target: String,
    pub title: String,
    pub detail: String,
    pub dismissed: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dismissed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub action: Option<HygieneAction>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneInsightsQuery {
    #[serde(default)]
    pub ref_name: Option<String>,
    #[serde(default)]
    pub include_dismissed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneInsightsResponse {
    pub ref_name: String,
    pub generated_at: String,
    pub active_count: usize,
    pub dismissed_count: usize,
    pub insights: Vec<HygieneInsight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneDismissRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneDismissResponse {
    pub ok: bool,
    pub id: String,
    pub dismissed_at: String,
}

/// Everything the analyzer reads, so it can be run against fixtures with a fixed clock.
pub struct HygieneInput<'a> {
    pub workspace_root: &'a Path,
    pub ref_name: &'a str,
    /// Resolved Git ref (or `"HEAD"`) whose committed tree is analyzed; `None` for no commit yet.
    pub rev: Option<&'a str>,
    pub policy: Option<&'a CompiledPolicy>,
    pub repo_policy_file: Option<&'a AccessPolicyFile>,
    pub server_policy_file: Option<&'a AccessPolicyFile>,
    pub env_schema: Option<&'a EnvSchema>,
    pub overlay_manifest: &'a OverlayManifest,
    pub secret_meta: &'a BTreeMap<String, SecretMetaEntry>,
    /// Declared branch metadata keyed by full ref name.
    pub branch_metadata: &'a BTreeMap<String, (Visibility, Readiness)>,
    pub session_changed_paths: &'a [String],
    pub now_unix: i64,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

pub async fn insights_handler(
    State(state): State<ServerState>,
    Query(q): Query<HygieneInsightsQuery>,
) -> Result<Json<HygieneInsightsResponse>, (StatusCode, Json<ApiError>)> {
    crate::auth::owner_only()?;
    let ref_name = q
        .ref_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| crate::checked_out(&state.workspace_root).0);

    let (blocking_state, blocking_ref) = (state.clone(), ref_name.clone());
    let insights =
        tokio::task::spawn_blocking(move || evaluate_hygiene(&blocking_state, &blocking_ref))
            .await
            .map_err(|e| {
                err_resp(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("hygiene analysis failed: {e}"),
                )
            })?;

    let dismissed = state
        .persisted
        .lock()
        .map(|st| st.dismissed_hygiene_insights.clone())
        .unwrap_or_default();
    let (insights, active_count, dismissed_count) =
        apply_dismissals(insights, &dismissed, q.include_dismissed);

    Ok(Json(HygieneInsightsResponse {
        ref_name,
        generated_at: Utc::now().to_rfc3339(),
        active_count,
        dismissed_count,
        insights,
    }))
}

pub async fn dismiss_insight_handler(
    State(state): State<ServerState>,
    Json(req): Json<HygieneDismissRequest>,
) -> Result<Json<HygieneDismissResponse>, (StatusCode, Json<ApiError>)> {
    crate::auth::owner_only()?;
    let id = validate_insight_id(&req.id)?;
    let dismissed_at =
        dismiss_in_state(&state, id).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(HygieneDismissResponse {
        ok: true,
        id: id.to_owned(),
        dismissed_at,
    }))
}

pub async fn restore_insight_handler(
    State(state): State<ServerState>,
    Json(req): Json<HygieneDismissRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    crate::auth::owner_only()?;
    let id = validate_insight_id(&req.id)?;
    restore_in_state(&state, id).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "ok": true, "id": id })))
}

fn validate_insight_id(raw: &str) -> Result<&str, ApiErr> {
    let id = raw.trim();
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "insight id must be 1-512 bytes with no control characters",
        ));
    }
    Ok(id)
}

/// Record `id` as dismissed now and persist; returns the timestamp. Keeps at most
/// [`MAX_DISMISSED`] entries, dropping the oldest first.
fn dismiss_in_state(state: &ServerState, id: &str) -> Result<String, String> {
    let now = Utc::now().to_rfc3339();
    let mut st = state
        .persisted
        .lock()
        .map_err(|_| "state lock poisoned".to_owned())?;
    st.dismissed_hygiene_insights
        .insert(id.to_owned(), now.clone());
    while st.dismissed_hygiene_insights.len() > MAX_DISMISSED {
        let oldest = st
            .dismissed_hygiene_insights
            .iter()
            .min_by(|a, b| a.1.cmp(b.1))
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => st.dismissed_hygiene_insights.remove(&k),
            None => break,
        };
    }
    crate::store::save_state(&state.workspace_root, &st)?;
    Ok(now)
}

fn restore_in_state(state: &ServerState, id: &str) -> Result<(), String> {
    let mut st = state
        .persisted
        .lock()
        .map_err(|_| "state lock poisoned".to_owned())?;
    st.dismissed_hygiene_insights.remove(id);
    crate::store::save_state(&state.workspace_root, &st)
}

/// Stamp dismissals onto `insights`; returns (visible insights, active count, dismissed count).
fn apply_dismissals(
    mut insights: Vec<HygieneInsight>,
    dismissed: &BTreeMap<String, String>,
    include_dismissed: bool,
) -> (Vec<HygieneInsight>, usize, usize) {
    for i in &mut insights {
        if let Some(at) = dismissed.get(&i.id) {
            i.dismissed = true;
            i.dismissed_at = Some(at.clone());
        }
    }
    let dismissed_count = insights.iter().filter(|i| i.dismissed).count();
    let active_count = insights.len() - dismissed_count;
    if !include_dismissed {
        insights.retain(|i| !i.dismissed);
    }
    (insights, active_count, dismissed_count)
}

// ---------------------------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------------------------

/// Gather the live inputs from `state` and run [`analyze_hygiene`]. Blocking (runs `git`).
pub fn evaluate_hygiene(state: &ServerState, ref_name: &str) -> Vec<HygieneInsight> {
    let root = state.workspace_root.as_path();
    let policy = state.current_policy();
    let repo_policy_file = state.current_repo_policy_file();
    let server_policy_file = state
        .server_policy_toml
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| premier_policy::parse_policy_toml(s).ok());
    let env_schema = state.env_schema.read().ok().and_then(|g| g.clone());
    let (overlay_manifest, secret_meta) = state
        .persisted
        .lock()
        .map(|st| (st.overlays.clone(), st.secret_meta.clone()))
        .unwrap_or_else(|_| (OverlayManifest::default(), BTreeMap::new()));
    let branch_metadata = state.branch_metadata();
    let rev = crate::branch_full_ref(root, ref_name)
        .or_else(|| crate::canon::tip_of(root, "HEAD").map(|_| "HEAD".to_owned()));
    let session_changed_paths: Vec<String> = state
        .session_manager
        .list()
        .into_iter()
        .filter(|s| !s.discarded && s.commit.is_none())
        .flat_map(|s| s.changes.into_iter().map(|c| c.path))
        .collect();

    analyze_hygiene(&HygieneInput {
        workspace_root: root,
        ref_name,
        rev: rev.as_deref(),
        policy: policy.as_deref(),
        repo_policy_file: repo_policy_file.as_deref(),
        server_policy_file: server_policy_file.as_ref(),
        env_schema: env_schema.as_deref(),
        overlay_manifest: &overlay_manifest,
        secret_meta: &secret_meta,
        branch_metadata: &branch_metadata,
        session_changed_paths: &session_changed_paths,
        now_unix: Utc::now().timestamp(),
    })
}

/// Run every detector; the result is deduplicated by id and deterministically ordered.
pub fn analyze_hygiene(input: &HygieneInput<'_>) -> Vec<HygieneInsight> {
    // The independent `git` reads each detector needs, run side by side: a spawn costs tens of
    // milliseconds on Windows and these used to queue one after another.
    let root = input.workspace_root;
    let (committed, working, refs, default_branch) = std::thread::scope(|scope| {
        let working = scope.spawn(|| working_tree_paths(root));
        let refs = scope.spawn(|| stale_branch_listing(root));
        let default_branch = scope.spawn(|| crate::default_branch(root));
        let committed = input
            .rev
            .map(|rev| committed_files(root, rev))
            .unwrap_or_default();
        (
            committed,
            working.join().unwrap_or_default(),
            refs.join().unwrap_or_default(),
            default_branch.join().unwrap_or_default(),
        )
    });
    let mut out = Vec::new();
    detect_unzoned_dirs(input, &committed, &mut out);
    detect_overlay_leaks(input, &committed, working, &mut out);
    detect_stale_private_branches(input, refs.as_deref(), &default_branch, &mut out);
    detect_secrets_and_egress(input, &mut out);

    let mut seen = HashSet::new();
    out.retain(|i| seen.insert(i.id.clone()));
    out.sort_by(|a, b| {
        (a.severity.rank(), a.category.rank(), &a.target, &a.id).cmp(&(
            b.severity.rank(),
            b.category.rank(),
            &b.target,
            &b.id,
        ))
    });
    out
}

fn insight(
    id: String,
    category: HygieneCategory,
    severity: HygieneSeverity,
    target: String,
    title: String,
    detail: String,
    action: Option<HygieneAction>,
) -> HygieneInsight {
    HygieneInsight {
        id,
        category,
        severity,
        target,
        title,
        detail,
        dismissed: false,
        dismissed_at: None,
        action,
    }
}

/// `git` stdout, untrimmed (NUL-separated output and porcelain status lead with significant bytes).
fn git_raw(root: &Path, args: &[&str]) -> Option<String> {
    let out = premier_git_bridge::git_command(root)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn committed_files(root: &Path, rev: &str) -> Vec<String> {
    git_raw(root, &["ls-tree", "-r", "--name-only", "-z", rev])
        .map(|raw| {
            raw.split('\0')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// --- (A) unzoned directories -------------------------------------------------------------------

const SENSITIVE_TOKENS: &[&str] = &[
    "billing",
    "payroll",
    "internal",
    "infra",
    "infrastructure",
    "secrets",
    "secret",
    "private",
    "finance",
    "hr",
    "legal",
    "admin",
    "security",
    "auth",
    "credentials",
    "certs",
    "keys",
    "ops",
    "deploy",
    "terraform",
    "k8s",
    "helm",
    "vault",
    "payments",
    "pii",
    "compliance",
    "restricted",
    "confidential",
    "prod",
    "production",
];

const BENIGN_TOP_LEVEL: &[&str] = &[
    "docs",
    "doc",
    "src",
    "tests",
    "test",
    "examples",
    "example",
    "fixtures",
    "assets",
    "public",
    "static",
    "scripts",
    "crates",
    "apps",
    "web",
    "ui",
    "lib",
    "pkg",
    "cmd",
    "bin",
    "tools",
    "benches",
    "benchmarks",
    "config",
];

const SERVICE_SUFFIXES: &[&str] = &["service", "services", "api", "worker", "backend", "server"];

fn not_browsable(segment: &str) -> bool {
    matches!(
        segment,
        ".git"
            | "target"
            | "node_modules"
            | ".premier-local"
            | ".premier"
            | ".tmp"
            | ".cache"
            | "dist"
            | ".github"
            | ".vscode"
    )
}

fn is_catch_all(pattern: &str) -> bool {
    matches!(pattern, "" | "*" | "**" | "**/*")
}

fn compile_glob(pattern: &str) -> Option<GlobMatcher> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

/// Non-catch-all globs of `patterns`, compiled; catch-alls never count as explicit coverage.
fn specific_matchers(patterns: &[String]) -> Vec<GlobMatcher> {
    patterns
        .iter()
        .map(|p| p.trim().trim_start_matches('/'))
        .filter(|p| !is_catch_all(p))
        .filter_map(compile_glob)
        .collect()
}

fn matches_dir(matchers: &[GlobMatcher], dir: &str, probe: &str) -> bool {
    matchers
        .iter()
        .any(|m| m.is_match(dir) || m.is_match(probe))
}

/// Does a non-catch-all zone or rule of `file` explicitly cover `dir`?
fn explicitly_covered(file: &AccessPolicyFile, dir: &str, probe: &str, ref_name: &str) -> bool {
    for zone in file.zones.values() {
        let excluded = specific_matchers(&zone.exclude)
            .iter()
            .any(|m| m.is_match(probe));
        if !excluded && matches_dir(&specific_matchers(&zone.paths), dir, probe) {
            return true;
        }
    }
    file.rules.iter().any(|rule| {
        let ref_ok = rule.refs.is_empty()
            || rule.refs.iter().any(|r| {
                let r = r.trim();
                r == "*" || r == "**" || compile_glob(r).is_some_and(|m| m.is_match(ref_name))
            });
        ref_ok && matches_dir(&specific_matchers(&rule.paths), dir, probe)
    })
}

fn dir_tokens(dir: &str) -> Vec<String> {
    dir.to_lowercase()
        .split(['/', '-', '_'])
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Top-level directories that appeared in the last five commits.
fn recently_added_top_dirs(root: &Path, rev: &str) -> HashSet<String> {
    git_raw(
        root,
        &[
            "log",
            "-n",
            "5",
            "--diff-filter=A",
            "--name-only",
            "-z",
            "--format=",
            rev,
        ],
    )
    .map(|raw| {
        raw.split('\0')
            .map(|p| p.trim_matches('\n'))
            .filter_map(|p| p.split_once('/').map(|(top, _)| top.to_owned()))
            .collect()
    })
    .unwrap_or_default()
}

fn unique_zone_name(dir: &str, taken: &mut HashSet<String>) -> String {
    let base: String = dir
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-');
    let base = if base.is_empty() { "restricted" } else { base };
    let mut name = base.to_owned();
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base}-{n}");
        n += 1;
    }
    taken.insert(name.clone());
    name
}

fn zone_snippet(dir: &str, zone_name: &str, path_glob: &str) -> String {
    // `principals = ["anonymous"]`, never `"*"`: Deny overrides Allow, so `*` would lock out
    // the owners and members too.
    format!(
        "# Suggested zone guard for {dir}/\n\
[zones.{zone_name}]\n\
paths = [\"{path_glob}\"]\n\
description = \"Restricted {dir} directory\"\n\
\n\
[[rules]]\n\
id = \"restrict-{zone_name}-public\"\n\
effect = \"deny\"\n\
principals = [\"anonymous\"] # Add \"authenticated\" or specific groups to restrict members as well\n\
zones = [\"{zone_name}\"]\n\
capabilities = [\"traverse\", \"list\", \"read\", \"write\", \"use\"]\n\
reason = \"Ambient hygiene draft: protect {dir}/ from public inheritance\"\n"
    )
}

fn detect_unzoned_dirs(
    input: &HygieneInput<'_>,
    committed: &[String],
    out: &mut Vec<HygieneInsight>,
) {
    let (Some(policy), Some(rev)) = (input.policy, input.rev) else {
        return;
    };
    let root = input.workspace_root;

    // Directories at depth 1 and 2 that hold files; sorted so a parent precedes its children.
    let mut dirs = BTreeSet::new();
    for file in committed {
        let segments: Vec<&str> = file.split('/').collect();
        if segments.iter().any(|s| not_browsable(s)) {
            continue;
        }
        for depth in 1..=2 {
            if segments.len() > depth {
                dirs.insert(segments[..depth].join("/"));
            }
        }
    }

    let files = [input.repo_policy_file, input.server_policy_file];
    let mut taken_zones: HashSet<String> = files
        .iter()
        .flatten()
        .flat_map(|f| f.zones.keys().cloned())
        .collect();
    let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
    let mut recent: Option<HashSet<String>> = None;
    let mut flagged: HashSet<String> = HashSet::new();
    let mut flagged_attention: HashSet<String> = HashSet::new();

    for dir in dirs {
        // shortcut: directories with glob/TOML metacharacters get no drafted rule (it could not
        // be written safely); upgrade by escaping them if such folders turn out to matter.
        if dir
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '*' | '?' | '[' | ']' | '{' | '}'))
        {
            continue;
        }
        let tokens = dir_tokens(&dir);
        let sensitive = tokens
            .iter()
            .any(|t| SENSITIVE_TOKENS.contains(&t.as_str()));
        if let Some((parent, _)) = dir.split_once('/') {
            // A flagged parent already carries the alert. A mere notice on the parent does not
            // hide a child that is itself sensitive.
            if flagged_attention.contains(parent) || (flagged.contains(parent) && !sensitive) {
                continue;
            }
        }
        let Ok(probe_path) = RepoPath::new(format!("{dir}/__hygiene_probe__")) else {
            continue;
        };
        if !policy
            .explain(&anon, &probe_path, input.ref_name)
            .allows(Capability::READ)
        {
            continue;
        }
        let probe = probe_path.as_str();
        if files
            .iter()
            .flatten()
            .any(|f| explicitly_covered(f, &dir, probe, input.ref_name))
        {
            continue;
        }

        let depth_one = !dir.contains('/');
        let service_like = depth_one
            && !BENIGN_TOP_LEVEL.contains(&dir.to_lowercase().as_str())
            && (tokens
                .iter()
                .any(|t| SERVICE_SUFFIXES.iter().any(|s| t == s || t.ends_with(s)))
                || recent
                    .get_or_insert_with(|| recently_added_top_dirs(root, rev))
                    .contains(&dir));
        if !sensitive && !service_like {
            continue;
        }

        let (severity, title, detail) = if sensitive {
            (
                HygieneSeverity::Attention,
                format!("Sensitive-looking folder '{dir}/' is not in a zone"),
                format!("No zone or rule covers '{dir}/', so it inherits public read access."),
            )
        } else {
            (
                HygieneSeverity::Notice,
                format!("New or service-style folder '{dir}/' is not in a zone"),
                format!("No zone or rule covers '{dir}/'; confirm public read access is intended."),
            )
        };
        let zone_name = unique_zone_name(&dir, &mut taken_zones);
        let path_glob = format!("{dir}/**");
        let toml_snippet = zone_snippet(&dir, &zone_name, &path_glob);
        out.push(insight(
            format!("unzoned-dir:{dir}"),
            HygieneCategory::UnzonedDirectory,
            severity,
            dir.clone(),
            title,
            detail,
            Some(HygieneAction::DraftPolicyRule {
                zone_name,
                path_glob,
                toml_snippet,
            }),
        ));
        flagged.insert(dir.clone());
        if sensitive {
            flagged_attention.insert(dir);
        }
    }
}

// --- (B) overlay & local-leak watch ------------------------------------------------------------

const ENV_TEMPLATES: &[&str] = &[
    ".env.schema",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
];
const LOCAL_SUFFIXES: &[&str] = &[
    ".local.md",
    ".local.toml",
    ".local.json",
    ".local.yaml",
    ".local.yml",
];

fn is_env_file(basename: &str) -> bool {
    basename == ".env" || basename.starts_with(".env.")
}

fn leak_sensitive(path: &str) -> bool {
    let lower = path.to_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    (is_env_file(basename) && !ENV_TEMPLATES.contains(&basename))
        || LOCAL_SUFFIXES.iter().any(|s| lower.ends_with(s))
        || basename == "agents.local.md"
        || basename == "claude.local.md"
        || path.starts_with(".run/")
}

/// Paths `git status` reports (untracked files expanded), tolerant of malformed entries.
fn working_tree_paths(root: &Path) -> Vec<String> {
    let Some(raw) = git_raw(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    ) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    let mut tokens = raw.split('\0');
    while let Some(token) = tokens.next() {
        let bytes = token.as_bytes();
        // `XY path`; anything shorter or without the space is not an entry.
        if bytes.len() < 4 || bytes[2] != b' ' {
            continue;
        }
        if let Some(path) = token.get(3..) {
            paths.push(path.to_owned());
        }
        // A rename or copy is followed by its origin path as its own NUL token.
        if matches!(bytes[0], b'R' | b'C') || matches!(bytes[1], b'R' | b'C') {
            tokens.next();
        }
    }
    paths
}

fn detect_overlay_leaks(
    input: &HygieneInput<'_>,
    committed: &[String],
    working_tree: Vec<String>,
    out: &mut Vec<HygieneInsight>,
) {
    let guard = OverlayGuard::from_manifest(input.overlay_manifest).ok();
    // path -> present in the committed tree or a session diff (not only in the working tree)
    let mut candidates: BTreeMap<String, bool> = BTreeMap::new();
    for p in committed.iter().chain(input.session_changed_paths) {
        candidates.insert(p.clone(), true);
    }
    for p in working_tree {
        candidates.entry(p).or_insert(false);
    }

    let mut emitted = 0;
    for (path, in_tree_or_diff) in candidates {
        if emitted >= MAX_OVERLAY_INSIGHTS {
            break;
        }
        if path.split('/').any(|s| {
            matches!(
                s,
                ".git" | ".premier" | ".premier-local" | "node_modules" | "target"
            )
        }) || !leak_sensitive(&path)
        {
            continue;
        }
        let Ok(rp) = RepoPath::new(&path) else {
            continue;
        };
        let in_guard = guard.as_ref().is_some_and(|g| g.is_overlay_path(&rp));
        let found = if in_guard && !in_tree_or_diff {
            continue;
        } else if in_guard {
            let basename = path.rsplit('/').next().unwrap_or(&path);
            insight(
                format!("overlay-in-tree:{path}"),
                HygieneCategory::OverlayLeak,
                if is_env_file(&basename.to_lowercase()) {
                    HygieneSeverity::Attention
                } else {
                    HygieneSeverity::Notice
                },
                path.clone(),
                format!("Overlay file '{path}' appears in tree or diff"),
                "Tracked by OverlayGuard, but present in committed history or session changes."
                    .to_owned(),
                None,
            )
        } else {
            insight(
                format!("overlay-leak:{path}"),
                HygieneCategory::OverlayLeak,
                HygieneSeverity::Attention,
                path.clone(),
                format!("Unmapped local file '{path}'"),
                "Add to Overlay Guard so local secrets/notes are blocked from public pushes."
                    .to_owned(),
                Some(HygieneAction::AddOverlayGuard {
                    path: path.clone(),
                    suggested_scope: "personal".to_owned(),
                }),
            )
        };
        out.push(found);
        emitted += 1;
    }
}

// --- (C) stale private branches ----------------------------------------------------------------

/// Every branch with its tip's commit time, from one `git for-each-ref`.
fn stale_branch_listing(root: &Path) -> Option<String> {
    git_raw(
        root,
        &[
            "for-each-ref",
            "--format=%(refname)|%(committerdate:unix)",
            "refs/heads",
            "refs/premier-private",
        ],
    )
}

fn detect_stale_private_branches(
    input: &HygieneInput<'_>,
    listing: Option<&str>,
    default_branch: &str,
    out: &mut Vec<HygieneInsight>,
) {
    let Some(raw) = listing else {
        return;
    };
    for line in raw.lines() {
        let Some((full_ref, ts)) = line.trim().rsplit_once('|') else {
            continue;
        };
        let Ok(ts_unix) = ts.trim().parse::<i64>() else {
            continue;
        };
        let Some(short) = full_ref
            .strip_prefix("refs/heads/")
            .or_else(|| full_ref.strip_prefix(PRIVATE_REF_PREFIX))
            .map(str::to_owned)
        else {
            continue;
        };
        if short == default_branch {
            continue;
        }
        let vis = input
            .branch_metadata
            .get(full_ref)
            .map(|(v, _)| v.clone())
            .unwrap_or_else(|| crate::default_ref_visibility(full_ref));
        if vis != Visibility::Public && input.now_unix - ts_unix > STALE_BRANCH_DAYS * 86_400 {
            let age_days = (input.now_unix - ts_unix) / 86_400;
            out.push(insight(
                format!("stale-private-branch:{short}"),
                HygieneCategory::StalePrivateBranch,
                HygieneSeverity::Notice,
                short.clone(),
                format!("Private branch '{short}' untouched for {age_days}d"),
                "Review whether this embargoed/private branch can be published or deleted."
                    .to_owned(),
                Some(HygieneAction::InspectBranch { branch: short }),
            ));
        }
    }
}

// --- (D) missing vault secrets & broad egress --------------------------------------------------

const EXFIL_HOSTS: &[&str] = &[
    "ngrok",
    "webhook.site",
    "pastebin.com",
    "requestbin",
    "trycloudflare.com",
    "pipedream.net",
    "gist.github.com",
];

fn detect_secrets_and_egress(input: &HygieneInput<'_>, out: &mut Vec<HygieneInsight>) {
    let root = input.workspace_root;
    if let Some(schema) = input.env_schema {
        let repo_id = schema.repo_id.as_deref().unwrap_or("local/repo");
        // Opening the vault creates the age identity when missing; only open an existing vault
        // (sovereign age, envelope KMS, or configured external backend).
        let vault = crate::store::has_workspace_vault_or_external(root)
            .then(|| crate::store::resolve_vault_backend(root, repo_id).ok())
            .flatten();
        for (var_name, spec) in &schema.vars {
            let is_secret = matches!(
                spec.sensitivity,
                Sensitivity::Secret | Sensitivity::Restricted
            ) || spec.var_type == VarType::Secret;
            if is_secret {
                for env_name in ["prod", "staging"] {
                    let required = spec
                        .required_in
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(env_name) || e == "*");
                    if !required {
                        continue;
                    }
                    let meta_has = input
                        .secret_meta
                        .contains_key(&format!("{env_name}:{var_name}"))
                        || input
                            .secret_meta
                            .get(var_name)
                            .is_some_and(|m| m.env.eq_ignore_ascii_case(env_name));
                    // Only whether a value exists; it is dropped (and zeroized) at once.
                    let vault_has = vault.as_ref().is_some_and(|v| {
                        v.get(&SecretCoord {
                            repo_id: repo_id.to_owned(),
                            layer: SecretLayer::Env,
                            scope: env_name.to_owned(),
                            var_name: var_name.clone(),
                        })
                        .ok()
                        .flatten()
                        .is_some()
                    });
                    if !meta_has && !vault_has {
                        out.push(insight(
                            format!("missing-vault-secret:{env_name}:{var_name}"),
                            HygieneCategory::MissingVaultSecret,
                            HygieneSeverity::Attention,
                            format!("{env_name}:{var_name}"),
                            format!("Missing {env_name} vault secret '{var_name}'"),
                            format!(
                                "Required in {env_name} by .env.schema but not configured in the age vault."
                            ),
                            Some(HygieneAction::ConfigureSecret {
                                env: env_name.to_owned(),
                                var_name: var_name.clone(),
                            }),
                        ));
                    }
                }
            }
            let Some(egress) = &spec.egress else {
                continue;
            };
            let env = spec
                .required_in
                .first()
                .cloned()
                .unwrap_or_else(|| "prod".to_owned());
            let (severity, title, detail) = if egress.hosts.len() > BROAD_SECRET_HOSTS {
                (
                    HygieneSeverity::Attention,
                    format!("Broad egress allow-list on '{var_name}'"),
                    format!(
                        "{} hosts allowed ({}); narrow to exact required API hosts.",
                        egress.hosts.len(),
                        egress.hosts.join(", ")
                    ),
                )
            } else if spec.sensitivity == Sensitivity::Restricted
                && egress.approval == ApprovalMode::Auto
                && egress.path_prefixes.is_empty()
            {
                (
                    HygieneSeverity::Notice,
                    format!("Unrestricted path prefixes on '{var_name}'"),
                    "Restricted secret uses auto-approval with no path_prefixes restriction; consider scoping path_prefixes or JIT approval."
                        .to_owned(),
                )
            } else {
                continue;
            };
            out.push(insight(
                format!("broad-secret-egress:{var_name}"),
                HygieneCategory::BroadEgressHost,
                severity,
                var_name.clone(),
                title,
                detail,
                Some(HygieneAction::ConfigureSecret {
                    env,
                    var_name: var_name.clone(),
                }),
            ));
        }
    }

    for profile in input
        .repo_policy_file
        .iter()
        .chain(input.server_policy_file.iter())
        .flat_map(|f| f.agent_profiles.iter())
    {
        let broad = profile.allow_egress_hosts.len() > BROAD_AGENT_HOSTS
            || profile.allow_egress_hosts.iter().any(|h| {
                let h = h.to_lowercase();
                h.contains('*') || EXFIL_HOSTS.iter().any(|p| h.contains(p))
            });
        if !broad {
            continue;
        }
        out.push(insight(
            format!("broad-agent-egress:{}", profile.name),
            HygieneCategory::BroadEgressHost,
            HygieneSeverity::Attention,
            profile.name.clone(),
            format!("Broad agent egress hosts on '{}'", profile.name),
            format!(
                "Profile allows {} — verify host scope.",
                profile.allow_egress_hosts.join(", ")
            ),
            Some(HygieneAction::ReviewAgentEgress {
                profile: profile.name.clone(),
                hosts: profile.allow_egress_hosts.clone(),
            }),
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use premier_core::OverlayKind;
    use premier_overlay::OverlayEntry;
    use premier_policy::parse_policy_toml;
    use premier_proxy::AuditSink;

    use super::*;
    use crate::store::{PersistedState, load_state};

    const T0: i64 = 1_700_000_000;
    const DAY: i64 = 86_400;

    /// Public may read everything: what an unzoned folder inherits.
    const PUBLIC_READ: &str = "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\nauthenticated = [\"traverse\", \"list\", \"read\", \"write\"]\n";

    fn git(root: &Path, ts: Option<i64>, args: &[&str]) -> String {
        let mut cmd = std::process::Command::new("git");
        cmd.current_dir(root)
            .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
            .args(args);
        if let Some(ts) = ts {
            let date = format!("{ts} +0000");
            cmd.env("GIT_COMMITTER_DATE", &date)
                .env("GIT_AUTHOR_DATE", &date);
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn repo(files: &[&str]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        git(root, None, &["init", "-q", "-b", "main"]);
        git(root, None, &["config", "core.autocrlf", "false"]);
        for f in files {
            write(root, f, "x\n");
        }
        git(root, Some(T0), &["add", "-A"]);
        git(
            root,
            Some(T0),
            &["commit", "-q", "--allow-empty", "-m", "initial"],
        );
        tmp
    }

    struct Fixture {
        policy: Option<CompiledPolicy>,
        repo_file: Option<AccessPolicyFile>,
        server_file: Option<AccessPolicyFile>,
        schema: Option<EnvSchema>,
        manifest: OverlayManifest,
        secret_meta: BTreeMap<String, SecretMetaEntry>,
        branch_metadata: BTreeMap<String, (Visibility, Readiness)>,
        session_paths: Vec<String>,
        now: i64,
    }

    impl Fixture {
        fn new(policy_toml: &str) -> Self {
            let file = parse_policy_toml(policy_toml).unwrap();
            Self {
                policy: Some(CompiledPolicy::compile(None, &file).unwrap()),
                repo_file: Some(file),
                server_file: None,
                schema: None,
                manifest: OverlayManifest::default(),
                secret_meta: BTreeMap::new(),
                branch_metadata: BTreeMap::new(),
                session_paths: Vec::new(),
                now: T0 + DAY,
            }
        }

        fn run(&self, root: &Path) -> Vec<HygieneInsight> {
            analyze_hygiene(&HygieneInput {
                workspace_root: root,
                ref_name: "main",
                rev: Some("HEAD"),
                policy: self.policy.as_ref(),
                repo_policy_file: self.repo_file.as_ref(),
                server_policy_file: self.server_file.as_ref(),
                env_schema: self.schema.as_ref(),
                overlay_manifest: &self.manifest,
                secret_meta: &self.secret_meta,
                branch_metadata: &self.branch_metadata,
                session_changed_paths: &self.session_paths,
                now_unix: self.now,
            })
        }
    }

    fn ids(insights: &[HygieneInsight], cat: HygieneCategory) -> Vec<String> {
        insights
            .iter()
            .filter(|i| i.category == cat)
            .map(|i| i.id.clone())
            .collect()
    }

    fn find<'a>(insights: &'a [HygieneInsight], id: &str) -> &'a HygieneInsight {
        insights.iter().find(|i| i.id == id).unwrap_or_else(|| {
            panic!(
                "no insight {id}: {:?}",
                insights.iter().map(|i| &i.id).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn flags_unzoned_sensitive_dirs_and_drafts_a_working_rule() {
        let tmp = repo(&[
            "billing/ledger.rs",
            "payroll/run.rs",
            "infra/main.tf",
            "services/internal/x.rs",
            "src/main.rs",
            "docs/readme.md",
            "README.md",
        ]);
        let fx = Fixture::new(PUBLIC_READ);
        let found = fx.run(tmp.path());
        let unzoned = ids(&found, HygieneCategory::UnzonedDirectory);
        for want in [
            "unzoned-dir:billing",
            "unzoned-dir:payroll",
            "unzoned-dir:infra",
            "unzoned-dir:services/internal",
        ] {
            assert!(
                unzoned.iter().any(|i| i == want),
                "{want} missing in {unzoned:?}"
            );
        }
        assert!(!unzoned.iter().any(|i| i == "unzoned-dir:src"));
        assert!(!unzoned.iter().any(|i| i == "unzoned-dir:docs"));
        assert_eq!(
            find(&found, "unzoned-dir:billing").severity,
            HygieneSeverity::Attention
        );
        // The Notice on `services` does not hide its sensitive child.
        assert_eq!(
            find(&found, "unzoned-dir:services").severity,
            HygieneSeverity::Notice
        );

        // The drafted rule parses, compiles, denies anonymous and keeps members working.
        let Some(HygieneAction::DraftPolicyRule {
            zone_name,
            path_glob,
            toml_snippet,
        }) = find(&found, "unzoned-dir:billing").action.clone()
        else {
            panic!("expected DraftPolicyRule");
        };
        assert_eq!(zone_name, "billing");
        assert_eq!(path_glob, "billing/**");
        assert!(toml_snippet.contains("principals = [\"anonymous\"]"));
        let merged = format!("{PUBLIC_READ}\n{toml_snippet}");
        let file = parse_policy_toml(&merged).unwrap();
        let compiled = CompiledPolicy::compile(None, &file).unwrap();
        let path = RepoPath::new("billing/ledger.rs").unwrap();
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let owner = DelegatedIdentity::human_only(Principal::User("owner".to_owned()), vec![]);
        assert!(
            !compiled
                .explain(&anon, &path, "main")
                .allows(Capability::READ)
        );
        assert!(
            compiled
                .explain(&owner, &path, "main")
                .allows(Capability::READ)
        );
        assert!(
            compiled
                .explain(&owner, &path, "main")
                .allows(Capability::WRITE)
        );

        // Deterministic order: attention before notice.
        let first_notice = found
            .iter()
            .position(|i| i.severity == HygieneSeverity::Notice)
            .unwrap_or(found.len());
        assert!(
            found[first_notice..]
                .iter()
                .all(|i| i.severity == HygieneSeverity::Notice)
        );
    }

    #[test]
    fn zoned_dirs_and_closed_defaults_are_quiet() {
        let tmp = repo(&["billing/ledger.rs", "payroll/run.rs", "README.md"]);
        let zoned = format!("{PUBLIC_READ}\n[zones.billing]\npaths = [\"billing/**\"]\n");
        let mut fx = Fixture::new(PUBLIC_READ);
        fx.repo_file = Some(parse_policy_toml(&zoned).unwrap());
        let unzoned = ids(&fx.run(tmp.path()), HygieneCategory::UnzonedDirectory);
        assert_eq!(unzoned, vec!["unzoned-dir:payroll".to_owned()]);

        // A catch-all zone is not explicit coverage.
        let catch_all = format!("{PUBLIC_READ}\n[zones.everything]\npaths = [\"**\"]\n");
        fx.repo_file = Some(parse_policy_toml(&catch_all).unwrap());
        assert_eq!(
            ids(&fx.run(tmp.path()), HygieneCategory::UnzonedDirectory).len(),
            2
        );

        // Nothing public to inherit: nothing to flag.
        let closed = Fixture::new("version = 1\n[defaults]\npublic = []\n");
        assert!(ids(&closed.run(tmp.path()), HygieneCategory::UnzonedDirectory).is_empty());
    }

    #[test]
    fn newly_added_service_dirs_are_notices_but_old_plain_dirs_are_not() {
        let tmp = repo(&["legacy/a.rs"]);
        let root = tmp.path();
        for n in 0..6 {
            write(root, &format!("src/f{n}.rs"), "x\n");
            git(root, Some(T0), &["add", "-A"]);
            git(root, Some(T0), &["commit", "-q", "-m", &format!("c{n}")]);
        }
        write(root, "orders-service/main.rs", "x\n");
        write(root, "widgets/a.rs", "x\n");
        git(root, Some(T0), &["add", "-A"]);
        git(root, Some(T0), &["commit", "-q", "-m", "new dirs"]);
        let found = Fixture::new(PUBLIC_READ).run(root);
        let unzoned = ids(&found, HygieneCategory::UnzonedDirectory);
        assert!(unzoned.contains(&"unzoned-dir:orders-service".to_owned()));
        assert!(unzoned.contains(&"unzoned-dir:widgets".to_owned()));
        assert!(!unzoned.contains(&"unzoned-dir:legacy".to_owned()));
        assert_eq!(
            find(&found, "unzoned-dir:orders-service").severity,
            HygieneSeverity::Notice
        );
    }

    #[test]
    fn unmapped_local_files_are_flagged_and_templates_and_mounted_overlays_are_not() {
        let tmp = repo(&[
            "README.md",
            ".env.schema",
            ".env.example",
            "docs/notes.local.md",
        ]);
        let root = tmp.path();
        write(root, ".env.local", "A=1\n");
        write(root, "notes.local.md", "n\n");
        write(root, ".env.sample", "A=\n");
        write(root, "mounted/.env.secret", "A=1\n");
        let mut fx = Fixture::new("version = 1\n");
        fx.manifest = OverlayManifest {
            version: 1,
            entries: vec![OverlayEntry {
                kind: OverlayKind::Personal,
                path: "mounted/**".to_owned(),
                encrypted: false,
            }],
        };
        let found = fx.run(root);
        let leaks = ids(&found, HygieneCategory::OverlayLeak);
        assert!(
            leaks.contains(&"overlay-leak:.env.local".to_owned()),
            "{leaks:?}"
        );
        assert!(leaks.contains(&"overlay-leak:notes.local.md".to_owned()));
        assert!(leaks.contains(&"overlay-leak:docs/notes.local.md".to_owned()));
        for quiet in [
            ".env.schema",
            ".env.example",
            ".env.sample",
            "mounted/.env.secret",
        ] {
            assert!(
                !leaks.iter().any(|i| i.ends_with(&format!(":{quiet}"))),
                "{quiet} must not be flagged: {leaks:?}"
            );
        }
        let Some(HygieneAction::AddOverlayGuard {
            path,
            suggested_scope,
        }) = find(&found, "overlay-leak:.env.local").action.clone()
        else {
            panic!("expected AddOverlayGuard");
        };
        assert_eq!(
            (path.as_str(), suggested_scope.as_str()),
            (".env.local", "personal")
        );

        // A mounted overlay path that reached a session diff is still worth a notice.
        fx.session_paths = vec!["mounted/.env.secret".to_owned()];
        let found = fx.run(root);
        let i = find(&found, "overlay-in-tree:mounted/.env.secret");
        assert!(i.action.is_none());
        assert_eq!(i.severity, HygieneSeverity::Attention);
    }

    #[test]
    fn working_tree_parser_survives_renames_and_garbage() {
        let tmp = repo(&["old.local.md", "keep.txt"]);
        let root = tmp.path();
        git(root, None, &["mv", "old.local.md", "new.local.md"]);
        let paths = working_tree_paths(root);
        assert!(paths.contains(&"new.local.md".to_owned()), "{paths:?}");
        assert!(!paths.contains(&"old.local.md".to_owned()), "{paths:?}");
    }

    #[test]
    fn stale_private_branches_only() {
        let tmp = repo(&["README.md"]);
        let root = tmp.path();
        // Old commits on a private ref and on a public branch; a fresh one on another private ref.
        for (name, full, ts) in [
            ("stale", "refs/premier-private/stale", T0),
            ("fresh", "refs/premier-private/fresh", T0 + 29 * DAY),
            ("oldpub", "refs/heads/oldpub", T0),
        ] {
            git(
                root,
                None,
                &["checkout", "-q", "-b", &format!("tmp-{name}"), "main"],
            );
            write(root, &format!("{name}.txt"), "x\n");
            git(root, Some(ts), &["add", "-A"]);
            git(root, Some(ts), &["commit", "-q", "-m", name]);
            git(root, None, &["update-ref", full, "HEAD"]);
            git(root, None, &["checkout", "-q", "main"]);
            git(root, None, &["branch", "-q", "-D", &format!("tmp-{name}")]);
        }
        let mut fx = Fixture::new("version = 1\n");
        fx.now = T0 + 30 * DAY;
        let stale = ids(&fx.run(root), HygieneCategory::StalePrivateBranch);
        assert_eq!(stale, vec!["stale-private-branch:stale".to_owned()]);
        let found = fx.run(root);
        assert!(
            find(&found, "stale-private-branch:stale")
                .title
                .contains("30d")
        );

        // Declared non-public metadata makes the old `heads` branch count too.
        fx.branch_metadata.insert(
            "refs/heads/oldpub".to_owned(),
            (Visibility::Org, Readiness::Wip),
        );
        let stale = ids(&fx.run(root), HygieneCategory::StalePrivateBranch);
        assert!(stale.contains(&"stale-private-branch:oldpub".to_owned()));
        assert!(!stale.contains(&"stale-private-branch:fresh".to_owned()));
    }

    fn schema_with(vars: serde_json::Value) -> EnvSchema {
        serde_json::from_value(serde_json::json!({ "vars": vars })).unwrap()
    }

    #[test]
    fn missing_vault_secrets_clear_once_stored() {
        let tmp = repo(&["README.md"]);
        let root = tmp.path();
        let mut fx = Fixture::new("version = 1\n");
        fx.schema = Some(schema_with(serde_json::json!({
            "STRIPE_KEY": { "type": "secret", "required_in": ["prod", "staging"] },
            "LOG_LEVEL": { "sensitivity": "public", "required_in": ["prod"] },
            "DEV_ONLY": { "required_in": ["dev"] }
        })));
        let found = fx.run(root);
        let missing = ids(&found, HygieneCategory::MissingVaultSecret);
        assert_eq!(
            missing,
            vec![
                "missing-vault-secret:prod:STRIPE_KEY".to_owned(),
                "missing-vault-secret:staging:STRIPE_KEY".to_owned()
            ]
        );
        assert_eq!(
            find(&found, "missing-vault-secret:prod:STRIPE_KEY").action,
            Some(HygieneAction::ConfigureSecret {
                env: "prod".to_owned(),
                var_name: "STRIPE_KEY".to_owned()
            })
        );

        let mut persisted = PersistedState::default();
        crate::store::set_workspace_secret(
            root,
            "local/repo",
            "prod",
            "STRIPE_KEY",
            "sk_test_never_in_an_insight",
            &mut persisted,
        )
        .unwrap();

        // Cleared through the metadata ...
        fx.secret_meta = persisted.secret_meta.clone();
        let found = fx.run(root);
        assert_eq!(
            ids(&found, HygieneCategory::MissingVaultSecret),
            vec!["missing-vault-secret:staging:STRIPE_KEY".to_owned()]
        );
        // ... and through the vault alone.
        fx.secret_meta.clear();
        let found = fx.run(root);
        assert_eq!(
            ids(&found, HygieneCategory::MissingVaultSecret),
            vec!["missing-vault-secret:staging:STRIPE_KEY".to_owned()]
        );
        assert!(
            !serde_json::to_string(&found)
                .unwrap()
                .contains("sk_test_never_in_an_insight")
        );
    }

    #[test]
    fn broad_egress_is_flagged() {
        let tmp = repo(&["README.md"]);
        let root = tmp.path();
        let policy = r#"
version = 1
[[agent_profiles]]
name = "wild"
allow_egress_hosts = ["*.example.com"]
[[agent_profiles]]
name = "tunnel"
allow_egress_hosts = ["foo.ngrok.io"]
[[agent_profiles]]
name = "many"
allow_egress_hosts = ["a.io","b.io","c.io","d.io","e.io","f.io","g.io","h.io","i.io"]
[[agent_profiles]]
name = "tidy"
allow_egress_hosts = ["registry.npmjs.org"]
"#;
        let mut fx = Fixture::new(policy);
        fx.schema = Some(schema_with(serde_json::json!({
            "WIDE": { "egress": { "hosts": ["a.io","b.io","c.io","d.io","e.io","f.io"] } },
            "OPEN": { "sensitivity": "restricted", "egress": { "hosts": ["api.x.io"] } },
            "TIGHT": { "sensitivity": "restricted",
                       "egress": { "hosts": ["api.x.io"], "path_prefixes": ["/v1/"] } }
        })));
        let found = fx.run(root);
        let broad = ids(&found, HygieneCategory::BroadEgressHost);
        for want in [
            "broad-agent-egress:wild",
            "broad-agent-egress:tunnel",
            "broad-agent-egress:many",
            "broad-secret-egress:WIDE",
            "broad-secret-egress:OPEN",
        ] {
            assert!(
                broad.contains(&want.to_owned()),
                "{want} missing in {broad:?}"
            );
        }
        assert_eq!(broad.len(), 5, "{broad:?}");
        assert_eq!(
            find(&found, "broad-secret-egress:OPEN").severity,
            HygieneSeverity::Notice
        );
        assert_eq!(
            find(&found, "broad-secret-egress:WIDE").severity,
            HygieneSeverity::Attention
        );

        // The same profiles from the server policy count too.
        fx.repo_file = None;
        fx.server_file = Some(parse_policy_toml(policy).unwrap());
        assert!(
            ids(&fx.run(root), HygieneCategory::BroadEgressHost)
                .contains(&"broad-agent-egress:tunnel".to_owned())
        );
    }

    fn test_state(root: &Path) -> ServerState {
        let mut state = ServerState::minimal(None, None, Arc::new(AuditSink::default()));
        state.workspace_root = root.to_path_buf();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state
    }

    #[test]
    fn dismiss_and_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path());
        let make = |id: &str| HygieneInsight {
            id: id.to_owned(),
            category: HygieneCategory::OverlayLeak,
            severity: HygieneSeverity::Notice,
            target: id.to_owned(),
            title: String::new(),
            detail: String::new(),
            dismissed: false,
            dismissed_at: None,
            action: None,
        };
        let all = || vec![make("a"), make("b")];

        let at = dismiss_in_state(&state, "a").unwrap();
        let on_disk = load_state(tmp.path()).unwrap();
        assert_eq!(on_disk.dismissed_hygiene_insights.get("a"), Some(&at));

        let dismissed = state
            .persisted
            .lock()
            .unwrap()
            .dismissed_hygiene_insights
            .clone();
        let (shown, active, gone) = apply_dismissals(all(), &dismissed, false);
        assert_eq!((shown.len(), active, gone), (1, 1, 1));
        assert_eq!(shown[0].id, "b");
        let (shown, active, gone) = apply_dismissals(all(), &dismissed, true);
        assert_eq!((shown.len(), active, gone), (2, 1, 1));
        assert!(shown[0].dismissed && shown[0].dismissed_at.as_deref() == Some(at.as_str()));

        restore_in_state(&state, "a").unwrap();
        assert!(
            load_state(tmp.path())
                .unwrap()
                .dismissed_hygiene_insights
                .is_empty()
        );

        // Capped at 1000: the oldest goes first.
        {
            let mut st = state.persisted.lock().unwrap();
            for n in 0..MAX_DISMISSED {
                st.dismissed_hygiene_insights.insert(
                    format!("old-{n}"),
                    format!("2000-01-01T00:00:{:02}+00:00", n % 60),
                );
            }
            st.dismissed_hygiene_insights
                .insert("oldest".to_owned(), "1999-01-01T00:00:00+00:00".to_owned());
        }
        dismiss_in_state(&state, "new").unwrap();
        let st = state.persisted.lock().unwrap();
        assert_eq!(st.dismissed_hygiene_insights.len(), MAX_DISMISSED);
        assert!(st.dismissed_hygiene_insights.contains_key("new"));
        assert!(!st.dismissed_hygiene_insights.contains_key("oldest"));
    }

    #[test]
    fn insight_ids_are_validated() {
        assert!(validate_insight_id("  unzoned-dir:billing ").is_ok());
        assert_eq!(validate_insight_id("  x ").unwrap(), "x");
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_ID_BYTES + 1)] {
            assert_eq!(
                validate_insight_id(bad).unwrap_err().0,
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn wire_shape_matches_the_contract() {
        let i = insight(
            "x".to_owned(),
            HygieneCategory::StalePrivateBranch,
            HygieneSeverity::Notice,
            "b".to_owned(),
            "t".to_owned(),
            "d".to_owned(),
            Some(HygieneAction::InspectBranch {
                branch: "b".to_owned(),
            }),
        );
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["category"], "stale_private_branch");
        assert_eq!(v["severity"], "notice");
        assert_eq!(v["action"]["kind"], "inspect_branch");
        assert!(v.get("dismissed_at").is_none());
    }
}
