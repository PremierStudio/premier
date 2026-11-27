//! Living Policy Learning: tracks repeated read-only JIT approvals and proposes
//! narrow, explicit `[[vars.<VAR>.egress.auto_allow]]` rules for owner review and
//! browser-session-only graduation into `.env.schema`.
//!
//! Security invariants:
//! - Never auto-escalates: every graduation requires an explicit owner browser-session
//!   request (`POST /v1/approvals/suggestions/{id}/apply`) and commits to `.env.schema`.
//! - Only read-only (`GET`, `RiskLevel::ReadOnly`) patterns on non-`Restricted` secrets
//!   and non-sensitive path prefixes are eligible.
//! - Zero secret leakage: only structural coordinates (`var_name`, `agent_profile`,
//!   `host`, `GET`, `path_prefix`) are persisted or surfaced.

use std::collections::BTreeMap;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::Utc;
use premier_core::{AuditDecision, AuditEvent, DelegatedIdentity, Principal, RepoPath};
use premier_proxy::{ApprovalStatus, PendingApproval, RiskLevel};
use premier_secrets::{ApprovalMode, AutoAllowRule, EnvSchema, Sensitivity};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::canon::{self, CommitError};
use crate::store::save_state;
use crate::{ApiError, ServerState, err_resp};

/// Number of distinct human approvals required before proposing a living-policy rule.
pub const DEFAULT_GRADUATION_THRESHOLD: u32 = 3;

const SCHEMA_PATH: &str = ".env.schema";
const MAX_STORED_APPROVAL_IDS: usize = 64;

type ApiErr = (StatusCode, Json<ApiError>);

/// Persisted tally for one narrow `(var_name, agent_profile, host, GET, path_prefix)` pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPatternRecord {
    pub id: String,
    pub var_name: String,
    pub agent_profile: String,
    pub host: String,
    pub method: String,
    pub path_prefix: String,
    pub approved_count: u32,
    #[serde(default)]
    pub approval_ids: Vec<String>,
    pub last_approved_at: String,
    #[serde(default)]
    pub dismissed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graduated_commit: Option<String>,
}

/// Persisted map of learned approval patterns stored inside `.premier/state.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyLearningState {
    #[serde(default)]
    pub patterns: BTreeMap<String, ApprovalPatternRecord>,
}

/// Actionable suggestion surfaced in Studio once a safe read-only pattern hits threshold.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySuggestion {
    pub id: String,
    pub var_name: String,
    pub agent_profile: String,
    pub host: String,
    pub method: String,
    pub path_prefix: String,
    pub approved_count: u32,
    pub threshold: u32,
    pub summary: String,
    pub toml_snippet: String,
    pub last_approved_at: String,
}

/// Preview of the exact `.env.schema` patch and unified diff before committing.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySuggestionPreview {
    pub suggestion: PolicySuggestion,
    pub schema_path: String,
    pub before_toml: String,
    pub after_toml: String,
    pub unified_diff: String,
    pub already_covered: bool,
}

/// Response returned after committing a graduated rule to `.env.schema`.
#[derive(Debug, Clone, Serialize)]
pub struct ApplySuggestionResponse {
    pub ok: bool,
    pub suggestion_id: String,
    pub schema_path: String,
    pub commit: String,
}

/// Choose a narrow, valid path prefix for a suggested auto-allow rule.
///
/// Keeps a non-root schema prefix verbatim; when the schema allowed `"/"`, narrows to
/// the first valid path segment of `concrete_path` (`"/<seg>/"`) if available.
pub fn suggested_path_prefix(schema_prefix: &str, concrete_path: Option<&str>) -> String {
    if schema_prefix != "/" {
        return schema_prefix.to_owned();
    }
    if let Some(raw) = concrete_path {
        let path_only = raw.split(['?', '#']).next().unwrap_or(raw);
        if let Some(seg) = path_only.split('/').find(|s| !s.is_empty()) {
            let valid = seg != "."
                && seg != ".."
                && !seg
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\');
            if valid {
                return format!("/{seg}/");
            }
        }
    }
    "/".to_owned()
}

/// Deterministic, URL-safe identifier for one `(var_name, agent_profile, host, GET, prefix)` tuple.
pub fn pattern_id(var_name: &str, agent_profile: &str, host: &str, path_prefix: &str) -> String {
    let host_lower = host.trim().to_ascii_lowercase();
    let material = format!("{var_name}\0{agent_profile}\0{host_lower}\0GET\0{path_prefix}");
    let digest = premier_policy::sha256_hex(material.as_bytes());
    let short = digest.get(..12).unwrap_or(&digest);
    format!("sugg-{short}")
}

fn format_toml_key_segment(key: &str) -> String {
    let bare_ok = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare_ok {
        key.to_owned()
    } else {
        // A JSON string is a valid single-line TOML basic string (same escapes), unlike
        // `toml::Value`'s multi-line form, which is not allowed in key position.
        serde_json::Value::String(key.to_owned()).to_string()
    }
}

fn format_toml_snippet(
    var_name: &str,
    agent_profile: &str,
    host: &str,
    path_prefix: &str,
) -> String {
    let var_key = format_toml_key_segment(var_name);
    let profile_lit = toml::Value::String(agent_profile.to_owned()).to_string();
    let host_lit = toml::Value::String(host.to_owned()).to_string();
    let prefix_lit = toml::Value::String(path_prefix.to_owned()).to_string();
    format!(
        "[[vars.{var_key}.egress.auto_allow]]\nagent_profile = {profile_lit}\nhost = {host_lit}\nmethods = [\"GET\"]\npath_prefixes = [{prefix_lit}]"
    )
}

fn display_path_glob(path_prefix: &str) -> String {
    if path_prefix == "/" {
        "/*".to_owned()
    } else {
        format!("{path_prefix}*")
    }
}

fn is_eligible_for_schema(
    schema: &EnvSchema,
    var_name: &str,
    agent_profile: &str,
    host: &str,
    path_prefix: &str,
) -> bool {
    let Some(spec) = schema.vars.get(var_name) else {
        return false;
    };
    if spec.sensitivity == Sensitivity::Restricted {
        return false;
    }
    let Some(egress) = &spec.egress else {
        return false;
    };
    if egress.approval != ApprovalMode::Jit {
        return false;
    }
    if premier_proxy::is_sensitive_path(path_prefix) {
        return false;
    }
    if !(egress.matches_host(host)
        && egress.matches_method("GET")
        && egress.matches_path(path_prefix))
    {
        return false;
    }
    !egress.matches_auto_allow(Some(agent_profile), host, "GET", path_prefix)
}

/// Record a newly approved JIT knock if it qualifies for living-policy learning.
///
/// Returns `true` when the learning state changed and should be persisted.
pub fn record_approval(
    learning: &mut PolicyLearningState,
    item: &PendingApproval,
    schema: Option<&EnvSchema>,
) -> bool {
    if item.status != ApprovalStatus::Approved
        || !item.method.eq_ignore_ascii_case("GET")
        || item.risk_level != RiskLevel::ReadOnly
    {
        return false;
    }
    let Some(profile) = item
        .agent_profile
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "*")
    else {
        return false;
    };
    let Some(schema) = schema else {
        return false;
    };

    let prefix = suggested_path_prefix(&item.path, item.concrete_path.as_deref());
    let host_lower = item.host.trim().to_ascii_lowercase();
    if !is_eligible_for_schema(schema, &item.var_name, profile, &host_lower, &prefix) {
        return false;
    }

    let id = pattern_id(&item.var_name, profile, &host_lower, &prefix);
    let now = Utc::now().to_rfc3339();
    let rec = learning
        .patterns
        .entry(id.clone())
        .or_insert_with(|| ApprovalPatternRecord {
            id,
            var_name: item.var_name.clone(),
            agent_profile: profile.to_owned(),
            host: host_lower,
            method: "GET".to_owned(),
            path_prefix: prefix,
            approved_count: 0,
            approval_ids: Vec::new(),
            last_approved_at: now.clone(),
            dismissed: false,
            graduated_commit: None,
        });

    if rec.approval_ids.iter().any(|seen| seen == &item.id) {
        return false;
    }

    rec.approved_count = rec.approved_count.saturating_add(1);
    if rec.approval_ids.len() >= MAX_STORED_APPROVAL_IDS {
        rec.approval_ids.remove(0);
    }
    rec.approval_ids.push(item.id.clone());
    rec.last_approved_at = now;
    true
}

/// Compute active policy suggestions that meet `threshold` and remain valid against `schema`.
pub fn active_suggestions(
    learning: &PolicyLearningState,
    schema: Option<&EnvSchema>,
    threshold: u32,
) -> Vec<PolicySuggestion> {
    let Some(schema) = schema else {
        return Vec::new();
    };

    let mut out: Vec<PolicySuggestion> = learning
        .patterns
        .values()
        .filter(|rec| {
            !rec.dismissed
                && rec.graduated_commit.is_none()
                && rec.approved_count >= threshold
                && rec.method.eq_ignore_ascii_case("GET")
                && !rec.agent_profile.trim().is_empty()
                && rec.agent_profile != "*"
                && is_eligible_for_schema(
                    schema,
                    &rec.var_name,
                    &rec.agent_profile,
                    &rec.host,
                    &rec.path_prefix,
                )
        })
        .map(|rec| {
            let path_glob = display_path_glob(&rec.path_prefix);
            PolicySuggestion {
                id: rec.id.clone(),
                var_name: rec.var_name.clone(),
                agent_profile: rec.agent_profile.clone(),
                host: rec.host.clone(),
                method: "GET".to_owned(),
                path_prefix: rec.path_prefix.clone(),
                approved_count: rec.approved_count,
                threshold,
                summary: format!(
                    "You've approved GET {}{} for {} {} times. Promote to auto-allow in .env.schema?",
                    rec.host, path_glob, rec.agent_profile, rec.approved_count
                ),
                toml_snippet: format_toml_snippet(
                    &rec.var_name,
                    &rec.agent_profile,
                    &rec.host,
                    &rec.path_prefix,
                ),
                last_approved_at: rec.last_approved_at.clone(),
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.last_approved_at
            .cmp(&a.last_approved_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn read_head_schema_toml(state: &ServerState) -> Result<String, ApiErr> {
    let out = premier_git_bridge::git_command(&state.workspace_root)
        .args(["cat-file", "blob", "HEAD:.env.schema"])
        .output();
    if let Ok(output) = out
        && output.status.success()
    {
        return String::from_utf8(output.stdout).map_err(|_| {
            err_resp(
                StatusCode::BAD_REQUEST,
                ".env.schema on HEAD is not valid UTF-8",
            )
        });
    }
    let Some(schema) = state.current_env_schema() else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "repository has no .env.schema to patch",
        ));
    };
    toml::to_string_pretty(schema.as_ref())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn append_snippet(before: &str, snippet: &str) -> String {
    if before.is_empty() {
        format!("{snippet}\n")
    } else if before.ends_with("\n\n") {
        format!("{before}{snippet}\n")
    } else if before.ends_with('\n') {
        format!("{before}\n{snippet}\n")
    } else {
        format!("{before}\n\n{snippet}\n")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffOp {
    Context(usize, usize),
    Delete(usize),
    Insert(usize),
}

fn build_unified_diff(path: &str, before: &str, after: &str) -> String {
    let old_lines: Vec<&str> = before.lines().collect();
    let new_lines: Vec<&str> = after.lines().collect();
    if old_lines == new_lines {
        return String::new();
    }

    // Strip shared prefix and suffix so LCS only runs on the changed core.
    let mut prefix = 0;
    while prefix < old_lines.len()
        && prefix < new_lines.len()
        && old_lines[prefix] == new_lines[prefix]
    {
        prefix += 1;
    }
    let mut old_end = old_lines.len();
    let mut new_end = new_lines.len();
    while old_end > prefix && new_end > prefix && old_lines[old_end - 1] == new_lines[new_end - 1] {
        old_end -= 1;
        new_end -= 1;
    }

    let mut ops = Vec::with_capacity(old_lines.len() + new_lines.len());
    for i in 0..prefix {
        ops.push(DiffOp::Context(i, i));
    }

    let m = old_end - prefix;
    let n = new_end - prefix;
    if m == 0 {
        for j in prefix..new_end {
            ops.push(DiffOp::Insert(j));
        }
    } else if n == 0 {
        for i in prefix..old_end {
            ops.push(DiffOp::Delete(i));
        }
    } else if m.saturating_mul(n) <= 250_000 {
        let mut dp = vec![vec![0u32; n + 1]; m + 1];
        for i in (0..m).rev() {
            for j in (0..n).rev() {
                dp[i][j] = if old_lines[prefix + i] == new_lines[prefix + j] {
                    dp[i + 1][j + 1] + 1
                } else {
                    dp[i + 1][j].max(dp[i][j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < m && j < n {
            if old_lines[prefix + i] == new_lines[prefix + j] {
                ops.push(DiffOp::Context(prefix + i, prefix + j));
                i += 1;
                j += 1;
            } else if dp[i + 1][j] >= dp[i][j + 1] {
                ops.push(DiffOp::Delete(prefix + i));
                i += 1;
            } else {
                ops.push(DiffOp::Insert(prefix + j));
                j += 1;
            }
        }
        while i < m {
            ops.push(DiffOp::Delete(prefix + i));
            i += 1;
        }
        while j < n {
            ops.push(DiffOp::Insert(prefix + j));
            j += 1;
        }
    } else {
        for i in prefix..old_end {
            ops.push(DiffOp::Delete(i));
        }
        for j in prefix..new_end {
            ops.push(DiffOp::Insert(j));
        }
    }

    let suffix_len = old_lines.len() - old_end;
    for k in 0..suffix_len {
        ops.push(DiffOp::Context(old_end + k, new_end + k));
    }

    // Group non-context edits into unified hunks with 3 lines of context.
    const CTX: usize = 3;
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        if !matches!(op, DiffOp::Context(_, _)) {
            let start = idx.saturating_sub(CTX);
            let end = (idx + CTX + 1).min(ops.len());
            if let Some(last) = hunks.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                hunks.push((start, end));
            }
        }
    }

    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    for (start, end) in hunks {
        let slice = &ops[start..end];
        let old_count = slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Context(_, _) | DiffOp::Delete(_)))
            .count();
        let new_count = slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Context(_, _) | DiffOp::Insert(_)))
            .count();
        let old_start = slice
            .iter()
            .find_map(|op| match op {
                DiffOp::Context(i, _) | DiffOp::Delete(i) => Some(i + 1),
                DiffOp::Insert(_) => None,
            })
            .unwrap_or(0);
        let new_start = slice
            .iter()
            .find_map(|op| match op {
                DiffOp::Context(_, j) | DiffOp::Insert(j) => Some(j + 1),
                DiffOp::Delete(_) => None,
            })
            .unwrap_or(0);

        out.push_str(&format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        ));
        for op in slice {
            match *op {
                DiffOp::Context(i, _) => {
                    out.push(' ');
                    out.push_str(old_lines[i]);
                    out.push('\n');
                }
                DiffOp::Delete(i) => {
                    out.push('-');
                    out.push_str(old_lines[i]);
                    out.push('\n');
                }
                DiffOp::Insert(j) => {
                    out.push('+');
                    out.push_str(new_lines[j]);
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// Build and validate a `.env.schema` patch and unified diff for `suggestion`.
pub fn build_schema_patch(
    state: &ServerState,
    suggestion: &PolicySuggestion,
) -> Result<PolicySuggestionPreview, ApiErr> {
    let before_toml = read_head_schema_toml(state)?;
    let parsed_before = EnvSchema::parse_toml(&before_toml)
        .ok()
        .or_else(|| state.current_env_schema().map(|s| (*s).clone()));

    let already_covered = parsed_before
        .as_ref()
        .and_then(|s| s.vars.get(&suggestion.var_name))
        .and_then(|v| v.egress.as_ref())
        .is_some_and(|e| {
            e.matches_auto_allow(
                Some(&suggestion.agent_profile),
                &suggestion.host,
                &suggestion.method,
                &suggestion.path_prefix,
            )
        });

    let after_toml = if already_covered {
        before_toml.clone()
    } else {
        let appended = append_snippet(&before_toml, &suggestion.toml_snippet);
        if EnvSchema::parse_toml(&appended).is_ok() {
            appended
        } else {
            let mut cloned = parsed_before.ok_or_else(|| {
                err_resp(
                    StatusCode::BAD_REQUEST,
                    "cannot patch invalid or missing .env.schema",
                )
            })?;
            let spec = cloned.vars.get_mut(&suggestion.var_name).ok_or_else(|| {
                err_resp(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "variable '{}' not found in .env.schema",
                        suggestion.var_name
                    ),
                )
            })?;
            let egress = spec.egress.as_mut().ok_or_else(|| {
                err_resp(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "variable '{}' has no egress block in .env.schema",
                        suggestion.var_name
                    ),
                )
            })?;
            egress.auto_allow.push(AutoAllowRule {
                agent_profile: Some(suggestion.agent_profile.clone()),
                host: suggestion.host.clone(),
                methods: vec![suggestion.method.clone()],
                path_prefixes: vec![suggestion.path_prefix.clone()],
            });
            let serialized = toml::to_string_pretty(&cloned)
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
            EnvSchema::parse_toml(&serialized).map_err(|e| {
                err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("patched .env.schema failed validation: {e}"),
                )
            })?;
            serialized
        }
    };

    EnvSchema::parse_toml(&after_toml).map_err(|e| {
        err_resp(
            StatusCode::BAD_REQUEST,
            format!("patched .env.schema failed validation: {e}"),
        )
    })?;

    let unified_diff = build_unified_diff(SCHEMA_PATH, &before_toml, &after_toml);
    Ok(PolicySuggestionPreview {
        suggestion: suggestion.clone(),
        schema_path: SCHEMA_PATH.to_owned(),
        before_toml,
        after_toml,
        unified_diff,
        already_covered,
    })
}

fn find_active_suggestion(state: &ServerState, id: &str) -> Result<PolicySuggestion, ApiErr> {
    let learning = state
        .persisted
        .lock()
        .map(|g| g.policy_learning.clone())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let schema = state.current_env_schema();
    active_suggestions(&learning, schema.as_deref(), DEFAULT_GRADUATION_THRESHOLD)
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| {
            err_resp(
                StatusCode::NOT_FOUND,
                format!("suggestion '{id}' not found"),
            )
        })
}

/// `GET /v1/approvals/suggestions` (owner browser session only via router).
pub async fn list_suggestions_handler(
    State(state): State<ServerState>,
) -> Json<Vec<PolicySuggestion>> {
    let learning = state
        .persisted
        .lock()
        .map(|g| g.policy_learning.clone())
        .unwrap_or_default();
    let schema = state.current_env_schema();
    Json(active_suggestions(
        &learning,
        schema.as_deref(),
        DEFAULT_GRADUATION_THRESHOLD,
    ))
}

/// `POST /v1/approvals/suggestions/{id}/preview` (owner browser session only).
pub async fn preview_suggestion_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PolicySuggestionPreview>, ApiErr> {
    crate::auth::require_browser_session(&user)?;
    let suggestion = find_active_suggestion(&state, &id)?;
    let state_bg = state.clone();
    let preview = tokio::task::spawn_blocking(move || build_schema_patch(&state_bg, &suggestion))
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    Ok(Json(preview))
}

/// `POST /v1/approvals/suggestions/{id}/apply` (owner browser session only).
pub async fn apply_suggestion_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ApplySuggestionResponse>, ApiErr> {
    crate::auth::require_browser_session(&user)?;
    let suggestion = find_active_suggestion(&state, &id)?;

    let root = state.workspace_root.clone();
    let Some(full_ref) = canon::default_ref(&root) else {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "no branch is checked out to commit .env.schema on",
        ));
    };
    // The patch is built on this tip and committed only if the branch is still there, so a
    // concurrent `.env.schema` change (e.g. a narrowed egress) is never silently reverted.
    let base_tip = canon::tip_of(&root, &full_ref);

    let state_for_patch = state.clone();
    let suggestion_for_patch = suggestion.clone();
    let preview = tokio::task::spawn_blocking(move || {
        build_schema_patch(&state_for_patch, &suggestion_for_patch)
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;

    EnvSchema::parse_toml(&preview.after_toml).map_err(|e| {
        err_resp(
            StatusCode::BAD_REQUEST,
            format!("patched .env.schema failed validation: {e}"),
        )
    })?;

    let schema_path = RepoPath::new(SCHEMA_PATH)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let who = canon::committer(&state);
    let path_glob = display_path_glob(&suggestion.path_prefix);
    let commit_msg = format!(
        "Promote GET {}{} auto-allow for {}",
        suggestion.host, path_glob, suggestion.agent_profile
    );
    let after_toml = preview.after_toml;
    let state_bg = state.clone();

    let commit = tokio::task::spawn_blocking(move || {
        let before = canon::DefaultTip::capture(&root);
        let done = canon::commit_file(
            &root,
            &full_ref,
            base_tip.as_deref(),
            &schema_path,
            Some(after_toml.as_bytes()),
            &commit_msg,
            &who,
        )?;
        state_bg.default_branch_moved(before);
        state_bg
            .reload_repo_config()
            .map_err(CommitError::Internal)?;
        Ok(done)
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        CommitError::Moved => err_resp(
            StatusCode::CONFLICT,
            "the default branch moved while .env.schema was being committed: reload and try again",
        ),
        CommitError::Invalid(why) => err_resp(StatusCode::BAD_REQUEST, why),
        CommitError::Internal(why) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, why),
    })?;

    let principal =
        Principal::parse(&format!("@{}", user.username)).unwrap_or(Principal::Anonymous);
    let identity = DelegatedIdentity::human_only(principal, vec![]);
    let short_commit = &commit[..commit.len().min(12)];
    let mut ev = AuditEvent::now(
        &identity,
        "premier-policy",
        "policy_graduated",
        AuditDecision::Allowed,
        format!(
            "Graduated GET {}{} for {} on {} into .env.schema (commit {})",
            suggestion.host, path_glob, suggestion.agent_profile, suggestion.var_name, short_commit
        ),
    );
    ev.capability = Some(suggestion.var_name.clone());
    ev.target = Some(SCHEMA_PATH.to_owned());
    crate::auth::audit(&state.audit_sink, ev);

    if let Ok(mut guard) = state.persisted.lock()
        && let Some(rec) = guard.policy_learning.patterns.get_mut(&id)
    {
        rec.graduated_commit = Some(commit.clone());
        let _ = save_state(&state.workspace_root, &guard);
    }

    Ok(Json(ApplySuggestionResponse {
        ok: true,
        suggestion_id: id,
        schema_path: SCHEMA_PATH.to_owned(),
        commit,
    }))
}

/// `POST /v1/approvals/suggestions/{id}/dismiss` (owner browser session only).
pub async fn dismiss_suggestion_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    crate::auth::require_browser_session(&user)?;
    let mut guard = state
        .persisted
        .lock()
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(rec) = guard.policy_learning.patterns.get_mut(&id) else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            format!("suggestion '{id}' not found"),
        ));
    };
    rec.dismissed = true;
    save_state(&state.workspace_root, &guard)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use premier_proxy::{ApprovalRequest, AuditSink, GrantScope, RiskLevel};
    use premier_secrets::EnvSchema;
    use tower_service::Service;

    use super::*;
    use crate::build_router;

    const TEST_PW: &str = "correct horse battery staple";

    const SAMPLE_SCHEMA: &str = r#"version = 1

[vars.GITHUB_TOKEN]
type = "secret"
sensitivity = "secret"
required_in = ["dev"]

[vars.GITHUB_TOKEN.egress]
hosts = ["api.github.com"]
methods = ["GET", "POST"]
path_prefixes = ["/"]
approval = "jit"
jit_ttl_secs = 300

[vars.STRIPE_RESTRICTED]
type = "secret"
sensitivity = "restricted"
required_in = ["prod"]

[vars.STRIPE_RESTRICTED.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
approval = "jit"
jit_ttl_secs = 60
"#;

    const INLINE_EGRESS_SCHEMA: &str = r#"version = 1

[vars.GITHUB_TOKEN]
type = "secret"
sensitivity = "secret"
egress = { hosts = ["api.github.com"], methods = ["GET"], path_prefixes = ["/repos/"], approval = "jit" }
"#;

    fn git(root: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(root)
            .args(["-c", "user.name=Test", "-c", "user.email=t@example.test"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} failed: {out:?}");
    }

    fn init_repo_with_schema(
        root: &Path,
        schema_toml: &str,
    ) -> (ServerState, String, String, String) {
        git(root, &["init", "-q", "-b", "main"]);
        std::fs::write(root.join(".env.schema"), schema_toml).unwrap();
        std::fs::write(root.join("README.md"), "# test\n").unwrap();
        git(root, &["add", ".env.schema", "README.md"]);
        git(root, &["commit", "-q", "-m", "initial commit"]);

        let schema = Arc::new(EnvSchema::parse_toml(schema_toml).unwrap());
        let sink = Arc::new(AuditSink::new(None));
        let mut state = ServerState::minimal(None, Some(schema), sink);
        state.workspace_root = root.to_path_buf();
        state.auth = Arc::new(crate::auth::AuthStore::open(root));
        state.approval_hub = Arc::new(premier_proxy::ApprovalHub::new());
        state.persisted = Arc::new(std::sync::Mutex::new(
            crate::store::PersistedState::default(),
        ));

        let (owner_cookie, owner_token) = state.auth.seed("owner", TEST_PW);
        let (member_cookie, _) = state
            .auth
            .seed_as("mia", TEST_PW, crate::auth::Role::Member);
        (state, owner_cookie, member_cookie, owner_token)
    }

    async fn call_json(
        router: &axum::Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let resp = router.clone().call(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    struct Knock<'a> {
        var_name: &'a str,
        agent_profile: &'a str,
        host: &'a str,
        method: &'a str,
        path: &'a str,
        concrete_path: &'a str,
        risk_level: RiskLevel,
    }

    fn enqueue_knock(state: &ServerState, k: Knock<'_>) -> String {
        let (pending, _rx) = state.approval_hub.enqueue(ApprovalRequest {
            principal: "@owner".to_owned(),
            agent_profile: Some(k.agent_profile.to_owned()),
            var_name: k.var_name.to_owned(),
            host: k.host.to_owned(),
            method: k.method.to_owned(),
            path: k.path.to_owned(),
            ttl_secs: 300,
            concrete_path: Some(k.concrete_path.to_owned()),
            risk_level: k.risk_level,
            ..ApprovalRequest::default()
        });
        pending.id
    }

    #[tokio::test]
    async fn threshold_accumulation_deduplicates_and_excludes_mutations_and_restricted() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, _, _) = init_repo_with_schema(tmp.path(), SAMPLE_SCHEMA);
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];

        // 1. Two safe GET approvals are below threshold 3.
        let id1 = enqueue_knock(
            &state,
            Knock {
                var_name: "GITHUB_TOKEN",
                agent_profile: "triage-bot",
                host: "api.github.com",
                method: "GET",
                path: "/",
                concrete_path: "/repos/acme/app/issues",
                risk_level: RiskLevel::ReadOnly,
            },
        );
        let id2 = enqueue_knock(
            &state,
            Knock {
                var_name: "GITHUB_TOKEN",
                agent_profile: "triage-bot",
                host: "api.github.com",
                method: "GET",
                path: "/",
                concrete_path: "/repos/acme/app/pulls",
                risk_level: RiskLevel::ReadOnly,
            },
        );
        for id in [&id1, &id2] {
            let (st, _) = call_json(
                &router,
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &owner,
                Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }

        // Re-deciding id2 must NOT double-count toward threshold 3.
        let (st, _) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/{id2}/decide"),
            &owner,
            Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let (st, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(suggestions.as_array().unwrap().len(), 0);

        // 2. Three POST/DELETE mutations and three Restricted-secret GETs must never suggest.
        for _ in 0..3 {
            for method in ["POST", "DELETE"] {
                let mut_id = enqueue_knock(
                    &state,
                    Knock {
                        var_name: "GITHUB_TOKEN",
                        agent_profile: "triage-bot",
                        host: "api.github.com",
                        method,
                        path: "/",
                        concrete_path: "/repos/acme/app/issues",
                        risk_level: RiskLevel::StateMutation,
                    },
                );
                let (st, _) = call_json(
                    &router,
                    Method::POST,
                    &format!("/v1/approvals/{mut_id}/decide"),
                    &owner,
                    Some(serde_json::json!({ "approved": true, "ttl_secs": 60 })),
                )
                .await;
                assert_eq!(st, StatusCode::OK);
            }

            let restricted_id = enqueue_knock(
                &state,
                Knock {
                    var_name: "STRIPE_RESTRICTED",
                    agent_profile: "billing-bot",
                    host: "api.stripe.com",
                    method: "GET",
                    path: "/v1/",
                    concrete_path: "/v1/customers",
                    risk_level: RiskLevel::SensitiveScope,
                },
            );
            let (st, _) = call_json(
                &router,
                Method::POST,
                &format!("/v1/approvals/{restricted_id}/decide"),
                &owner,
                Some(serde_json::json!({ "approved": true, "ttl_secs": 60 })),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }

        let (_, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(suggestions.as_array().unwrap().len(), 0);

        // 3. Third distinct safe GET reaches threshold -> surfaces suggestion for /repos/.
        let id3 = enqueue_knock(
            &state,
            Knock {
                var_name: "GITHUB_TOKEN",
                agent_profile: "triage-bot",
                host: "api.github.com",
                method: "GET",
                path: "/",
                concrete_path: "/repos/acme/app/releases",
                risk_level: RiskLevel::ReadOnly,
            },
        );
        let (st, _) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/{id3}/decide"),
            &owner,
            Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let (st, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let rows = suggestions.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["var_name"], "GITHUB_TOKEN");
        assert_eq!(rows[0]["agent_profile"], "triage-bot");
        assert_eq!(rows[0]["host"], "api.github.com");
        assert_eq!(rows[0]["method"], "GET");
        assert_eq!(rows[0]["path_prefix"], "/repos/");
        assert_eq!(rows[0]["approved_count"], 3);
        assert_eq!(rows[0]["threshold"], 3);
        assert!(
            rows[0]["summary"]
                .as_str()
                .unwrap()
                .contains("api.github.com/repos/*")
        );
    }

    #[tokio::test]
    async fn decide_honors_grant_scope_rejects_read_only_prefix_on_post_and_records_denial_reason()
    {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, _, _) = init_repo_with_schema(tmp.path(), SAMPLE_SCHEMA);
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];

        // Reject read_only_prefix on POST with 400.
        let post_id = enqueue_knock(
            &state,
            Knock {
                var_name: "GITHUB_TOKEN",
                agent_profile: "triage-bot",
                host: "api.github.com",
                method: "POST",
                path: "/",
                concrete_path: "/repos/acme/app/issues",
                risk_level: RiskLevel::StateMutation,
            },
        );
        let (st, body) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/{post_id}/decide"),
            &owner,
            Some(serde_json::json!({
                "approved": true,
                "ttl_secs": 300,
                "grant_scope": "read_only_prefix"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");

        // Approve a GET with exact_path grant scope.
        let get_id = enqueue_knock(
            &state,
            Knock {
                var_name: "GITHUB_TOKEN",
                agent_profile: "triage-bot",
                host: "api.github.com",
                method: "GET",
                path: "/",
                concrete_path: "/repos/acme/app/issues/1",
                risk_level: RiskLevel::ReadOnly,
            },
        );
        let (st, body) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/{get_id}/decide"),
            &owner,
            Some(serde_json::json!({
                "approved": true,
                "ttl_secs": 120,
                "grant_scope": "exact_path"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["grant_scope"], "exact_path");
        assert_eq!(body["ttl_secs"], 120);

        // Deny POST with denial_reason -> recorded on PendingApproval and AuditEvent.
        let (st, denied) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/{post_id}/decide"),
            &owner,
            Some(serde_json::json!({
                "approved": false,
                "denial_reason": "no writes during release freeze"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{denied}");
        assert_eq!(denied["status"], "denied");
        assert_eq!(denied["denial_reason"], "no writes during release freeze");

        let events = state.audit_sink.snapshot();
        let deny_ev = events
            .iter()
            .find(|e| {
                e.action == "jit_approval_decision"
                    && e.decision == AuditDecision::Denied
                    && e.reason.contains("no writes during release freeze")
            })
            .expect("denial audit event with reason");
        assert_eq!(deny_ev.capability.as_deref(), Some("GITHUB_TOKEN"));

        let approve_ev = events
            .iter()
            .find(|e| {
                e.action == "jit_approval_decision"
                    && e.decision == AuditDecision::Allowed
                    && e.reason.contains("scope=exact_path")
            })
            .expect("approval audit event with grant_scope");
        assert_eq!(approve_ev.capability.as_deref(), Some("GITHUB_TOKEN"));
        let _ = GrantScope::ExactPath;
    }

    #[tokio::test]
    async fn preview_apply_auth_and_dismiss_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, member_cookie, owner_token) =
            init_repo_with_schema(tmp.path(), SAMPLE_SCHEMA);
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];
        let member = [("cookie", member_cookie.as_str())];
        let owner_bearer = format!("Bearer {owner_token}");
        let token_hdr = [("authorization", owner_bearer.as_str())];

        // Accumulate 3 approvals to create a suggestion.
        for n in 1..=3 {
            let concrete = format!("/repos/acme/app/issues/{n}");
            let id = enqueue_knock(
                &state,
                Knock {
                    var_name: "GITHUB_TOKEN",
                    agent_profile: "triage-bot",
                    host: "api.github.com",
                    method: "GET",
                    path: "/",
                    concrete_path: &concrete,
                    risk_level: RiskLevel::ReadOnly,
                },
            );
            let (st, _) = call_json(
                &router,
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &owner,
                Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }

        let (st, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let sugg_id = suggestions[0]["id"].as_str().unwrap().to_owned();

        // Preview returns valid TOML and unified diff.
        let (st, preview) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/suggestions/{sugg_id}/preview"),
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{preview}");
        assert_eq!(preview["schema_path"], ".env.schema");
        assert_eq!(preview["already_covered"], false);
        let after_toml = preview["after_toml"].as_str().unwrap();
        assert!(EnvSchema::parse_toml(after_toml).is_ok());
        let diff = preview["unified_diff"].as_str().unwrap();
        assert!(diff.contains("--- a/.env.schema"), "{diff}");
        assert!(diff.contains("+++ b/.env.schema"), "{diff}");
        assert!(
            diff.contains("+[[vars.GITHUB_TOKEN.egress.auto_allow]]"),
            "{diff}"
        );

        // Auth checks: member -> 403, owner prm_ access token -> 403.
        let apply_uri = format!("/v1/approvals/suggestions/{sugg_id}/apply");
        let (st, _) = call_json(&router, Method::POST, &apply_uri, &member, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, _) = call_json(&router, Method::POST, &apply_uri, &token_hdr, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // Apply with owner browser session commits .env.schema, reloads schema, and audits.
        let (st, applied) = call_json(&router, Method::POST, &apply_uri, &owner, None).await;
        assert_eq!(st, StatusCode::OK, "{applied}");
        assert_eq!(applied["ok"], true);
        assert_eq!(applied["suggestion_id"], sugg_id);
        assert_eq!(applied["schema_path"], ".env.schema");
        let commit = applied["commit"].as_str().unwrap();
        assert_eq!(commit.len(), 40);

        // Reloaded schema now auto-allows (triage-bot, api.github.com, GET, /repos/...)
        // and rejects POST or a different agent profile.
        let reloaded = state.current_env_schema().expect("reloaded schema");
        let egress = reloaded.vars["GITHUB_TOKEN"]
            .egress
            .as_ref()
            .expect("egress");
        assert!(egress.matches_auto_allow(
            Some("triage-bot"),
            "api.github.com",
            "GET",
            "/repos/acme/app/issues/99"
        ));
        assert!(!egress.matches_auto_allow(
            Some("triage-bot"),
            "api.github.com",
            "POST",
            "/repos/acme/app/issues/99"
        ));
        assert!(!egress.matches_auto_allow(
            Some("other-bot"),
            "api.github.com",
            "GET",
            "/repos/acme/app/issues/99"
        ));

        // Audit event "policy_graduated" was recorded.
        let graduated_ev = state
            .audit_sink
            .snapshot()
            .into_iter()
            .find(|e| e.action == "policy_graduated")
            .expect("policy_graduated audit event");
        assert_eq!(graduated_ev.decision, AuditDecision::Allowed);
        assert_eq!(graduated_ev.capability.as_deref(), Some("GITHUB_TOKEN"));
        assert_eq!(graduated_ev.target.as_deref(), Some(".env.schema"));

        // Suggestion is no longer active after graduation.
        let (_, remaining) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(remaining.as_array().unwrap().len(), 0);

        // Build a second suggestion on a different prefix and verify dismiss hides it.
        for n in 1..=3 {
            let concrete = format!("/orgs/acme/members/{n}");
            let id = enqueue_knock(
                &state,
                Knock {
                    var_name: "GITHUB_TOKEN",
                    agent_profile: "triage-bot",
                    host: "api.github.com",
                    method: "GET",
                    path: "/",
                    concrete_path: &concrete,
                    risk_level: RiskLevel::ReadOnly,
                },
            );
            let (st, _) = call_json(
                &router,
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &owner,
                Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }
        let (_, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(suggestions.as_array().unwrap().len(), 1);
        let dismiss_id = suggestions[0]["id"].as_str().unwrap().to_owned();

        let (st, body) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/suggestions/{dismiss_id}/dismiss"),
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);

        let (_, after_dismiss) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        assert_eq!(after_dismiss.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn preview_falls_back_cleanly_for_inline_egress_table() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, _, _) = init_repo_with_schema(tmp.path(), INLINE_EGRESS_SCHEMA);
        let router = build_router(state.clone());
        let owner = [("cookie", owner_cookie.as_str())];

        for n in 1..=3 {
            let concrete = format!("/repos/acme/{n}");
            let id = enqueue_knock(
                &state,
                Knock {
                    var_name: "GITHUB_TOKEN",
                    agent_profile: "triage-bot",
                    host: "api.github.com",
                    method: "GET",
                    path: "/repos/",
                    concrete_path: &concrete,
                    risk_level: RiskLevel::ReadOnly,
                },
            );
            let (st, _) = call_json(
                &router,
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &owner,
                Some(serde_json::json!({ "approved": true, "ttl_secs": 300 })),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }

        let (_, suggestions) = call_json(
            &router,
            Method::GET,
            "/v1/approvals/suggestions",
            &owner,
            None,
        )
        .await;
        let sugg_id = suggestions[0]["id"].as_str().unwrap();

        let (st, preview) = call_json(
            &router,
            Method::POST,
            &format!("/v1/approvals/suggestions/{sugg_id}/preview"),
            &owner,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{preview}");
        let parsed = EnvSchema::parse_toml(preview["after_toml"].as_str().unwrap()).unwrap();
        assert!(
            parsed.vars["GITHUB_TOKEN"]
                .egress
                .as_ref()
                .unwrap()
                .matches_auto_allow(Some("triage-bot"), "api.github.com", "GET", "/repos/acme/1")
        );
    }

    #[test]
    fn suggested_path_prefix_and_toml_escaping_prevent_injection() {
        assert_eq!(
            suggested_path_prefix("/", Some("/repos/acme/app")),
            "/repos/"
        );
        assert_eq!(suggested_path_prefix("/v1/", Some("/v1/items")), "/v1/");
        assert_eq!(suggested_path_prefix("/", Some("/../etc/passwd")), "/");
        assert_eq!(suggested_path_prefix("/", Some("/bad\"quote/x")), "/");
        assert_eq!(suggested_path_prefix("/", Some("/has space/x")), "/");

        let snippet = format_toml_snippet(
            "MY_TOKEN",
            "agent\"\n[vars.EVIL]",
            "api.github.com",
            "/repos/",
        );
        let doc = format!(
            "version = 1\n[vars.MY_TOKEN.egress]\nhosts = [\"api.github.com\"]\nmethods = [\"GET\"]\napproval = \"jit\"\n\n{snippet}\n"
        );
        let parsed = EnvSchema::parse_toml(&doc).unwrap();
        assert!(!parsed.vars.contains_key("EVIL"));
        assert_eq!(
            parsed.vars["MY_TOKEN"].egress.as_ref().unwrap().auto_allow[0]
                .agent_profile
                .as_deref(),
            Some("agent\"\n[vars.EVIL]")
        );
    }

    #[test]
    fn var_name_keys_and_encoded_sensitive_prefixes_cannot_escape_or_graduate() {
        let key = format_toml_key_segment("A.B\"]\n[x]");
        let doc: toml::Value = toml::from_str(&format!("[vars.{key}]\nv = 1\n")).unwrap();
        assert_eq!(doc["vars"].as_table().unwrap().len(), 1);
        assert!(doc.get("x").is_none());

        // `/k%65ys/` is `/keys/` upstream: never eligible, however often it is approved.
        let schema = EnvSchema::parse_toml(SAMPLE_SCHEMA).unwrap();
        let hub = premier_proxy::ApprovalHub::new();
        let mut learning = PolicyLearningState::default();
        for _ in 0..3 {
            let (p, _rx) = hub.enqueue(ApprovalRequest {
                principal: "@owner".to_owned(),
                agent_profile: Some("bot".to_owned()),
                var_name: "GITHUB_TOKEN".to_owned(),
                host: "api.github.com".to_owned(),
                method: "GET".to_owned(),
                path: "/".to_owned(),
                ttl_secs: 300,
                concrete_path: Some("/k%65ys/1".to_owned()),
                risk_level: RiskLevel::ReadOnly,
                ..ApprovalRequest::default()
            });
            let (item, _) = hub
                .decide_with_options(
                    &p.id,
                    premier_proxy::ApprovalDecision {
                        approved: true,
                        ..Default::default()
                    },
                )
                .unwrap()
                .unwrap();
            assert!(!record_approval(&mut learning, &item, Some(&schema)));
        }
        assert!(learning.patterns.is_empty());
    }
}
