//! Production v1 mutation, search, blame, secret-vault, overlay, review, live agent-cage,
//! and reversible `git-receive-pack` handlers for `premier-server`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufRead as _;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::Utc;
use premier_core::{
    AuditDecision, AuditEvent, Capability, OverlayKind, Readiness, RepoPath, Visibility,
};
use premier_git_bridge::{
    CanonicalGitRepo, handle_receive_pack_with_firewall, project_repository, render_info_refs_v2,
    render_receive_pack_refs,
};
use premier_overlay::{OverlayEntry, OverlayGuard};
use premier_policy::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::auth::{GitCaller, is_internal_path};
use crate::directory::identity as parse_identity;
use crate::runner::AgentSessionRecord;
use crate::store::{
    CapturedProvenance, ReviewComment, SecretMetaEntry, StoredReview, StoredRoundMeta,
    delete_workspace_secret, save_state, set_workspace_secret,
};
use crate::{ApiError, GitIds, PRIVATE_REF_PREFIX, ServerState, err_resp};

// ---------------------------------------------------------------------------
// 1. ACL-Scoped Repo Search, Git Blame, and ACL-Enforced File Write
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RepoSearchQuery {
    pub q: String,
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    /// Branch to search; left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub ref_name: Option<String>,
}

/// No principal/author in the request means the authenticated caller (see `auth::gate`). A
/// `groups` field in any request is ignored: membership comes from the principal directory.
fn default_caller() -> String {
    crate::auth::actor_principal()
}

#[derive(Debug, Serialize)]
pub struct SearchHit {
    pub path: String,
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct RepoSearchResponse {
    pub query: String,
    pub total_hits: usize,
    pub files_scanned: usize,
    pub hits: Vec<SearchHit>,
}

const MAX_SEARCH_HITS: usize = 150;

/// Code search over the committed tree of `ref_name` (like file and tree), strictly gated by `CompiledPolicy`
/// READ on every file. Never leaks filenames, hit counts, or snippets from unauthorized zones.
/// The query is a case-insensitive fixed string, never a regex.
pub async fn repo_search_handler(
    State(state): State<ServerState>,
    Query(q): Query<RepoSearchQuery>,
) -> Result<Json<RepoSearchResponse>, (StatusCode, Json<ApiError>)> {
    let needle = q.q.trim().to_owned();
    if needle.is_empty() {
        return Ok(Json(RepoSearchResponse {
            query: q.q,
            total_hits: 0,
            files_scanned: 0,
            hits: vec![],
        }));
    }
    // `git grep -e` reads a newline as "another pattern" (an empty one matches every line).
    if needle.contains(['\n', '\r', '\0']) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid query"));
    }

    let identity = parse_identity(&state, &q.principal, q.agent_profile, "studio-search")?;
    let policy = state.current_policy();
    let root = state.workspace_root.clone();
    // The decision and the data come from the same ref; a hidden one answers like a missing one.
    let ref_name = q.ref_name.unwrap_or_else(|| crate::default_branch(&root));
    let source = crate::content_source(&state, &identity, &ref_name)?;
    let query_orig = q.q.clone();

    let result = tokio::task::spawn_blocking(move || {
        // Fail closed: no compiled policy means nothing is searchable.
        let readable = |path: &str| {
            let rp = RepoPath::new(path).ok().filter(|rp| rp.as_str() == path);
            rp.is_some_and(|rp| {
                policy.as_ref().is_some_and(|pol| {
                    pol.explain(&identity, &rp, &ref_name)
                        .allows(Capability::READ)
                })
            })
        };
        let (hits, files_scanned) = match source {
            None => (Vec::new(), 0),
            Some(rev) => search_rev(&root, &rev, &needle, readable),
        };
        RepoSearchResponse {
            query: query_orig,
            total_hits: hits.len(),
            files_scanned,
            hits,
        }
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(result))
}

/// Hits in the readable files of the committed tree `rev` (a ref the caller was already found to
/// see), and how many files of it are readable.
fn search_rev(
    root: &Path,
    rev: &str,
    needle: &str,
    readable: impl Fn(&str) -> bool,
) -> (Vec<SearchHit>, usize) {
    let listed = premier_git_bridge::git_command(root)
        .args(["ls-tree", "-r", "-z", "--name-only", rev])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| o.stdout)
        .unwrap_or_default();
    let readable: HashSet<&[u8]> = listed
        .split(|b| *b == 0)
        .filter(|raw| {
            std::str::from_utf8(raw).is_ok_and(|path| {
                !path.is_empty() && !is_internal_path(root, path) && readable(path)
            })
        })
        .collect();
    let mut hits = Vec::new();
    // `-e` and the fixed positions keep the query from ever being read as an option, a revision
    // or a pathspec; `-F` keeps it from being a regex.
    let child = premier_git_bridge::git_command(root)
        .args([
            "grep",
            "-n",
            "-I",
            "-i",
            "-F",
            "-z",
            "--full-name",
            "--no-color",
        ])
        .args(["-e", needle, rev, "--"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        let prefix = format!("{rev}:");
        let stdout = child.stdout.take().map(std::io::BufReader::new);
        // One hit per line: `<rev>:<path>\0<line>\0<text>`.
        let records = stdout.into_iter().flat_map(|out| out.split(b'\n'));
        for record in records.map_while(Result::ok) {
            let mut parts = record.splitn(3, |b| *b == 0);
            let (Some(path), Some(line), Some(text)) = (
                parts.next().and_then(|p| p.strip_prefix(prefix.as_bytes())),
                parts
                    .next()
                    .and_then(|n| std::str::from_utf8(n).ok()?.parse().ok()),
                parts.next(),
            ) else {
                continue;
            };
            if !readable.contains(path) {
                continue;
            }
            hits.push(SearchHit {
                path: String::from_utf8_lossy(path).into_owned(),
                line,
                text: String::from_utf8_lossy(text).chars().take(200).collect(),
            });
            if hits.len() >= MAX_SEARCH_HITS {
                break;
            }
        }
        // Usually stopped at the cap: do not leave `git grep` writing into a closed pipe.
        let _ = child.kill();
        let _ = child.wait();
    }
    (hits, readable.len())
}

#[derive(Debug, Deserialize)]
pub struct RepoBlameQuery {
    pub path: String,
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    /// Branch to read; left out, the one that is checked out.
    #[serde(default)]
    pub ref_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BlameLine {
    pub line: usize,
    pub oid: String,
    pub author: String,
    pub date: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct RepoBlameResponse {
    pub path: String,
    pub allowed: bool,
    pub lines: Vec<BlameLine>,
}

/// Real `git blame --line-porcelain` strictly enforced by `CompiledPolicy` READ.
pub async fn repo_blame_handler(
    State(state): State<ServerState>,
    Query(q): Query<RepoBlameQuery>,
) -> Result<Json<RepoBlameResponse>, (StatusCode, Json<ApiError>)> {
    let rp =
        RepoPath::new(&q.path).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let identity = parse_identity(&state, &q.principal, q.agent_profile, "studio-blame")?;
    if is_internal_path(&state.workspace_root, rp.as_str()) {
        return Err(err_resp(StatusCode::NOT_FOUND, "path not found"));
    }
    // Blame is read from the commits of the ref the decision is made on (for the checked-out
    // branch: its tip), never from whatever the working tree happens to hold.
    let ref_name = q
        .ref_name
        .unwrap_or_else(|| crate::checked_out(&state.workspace_root).0);
    let rev =
        crate::content_source(&state, &identity, &ref_name)?.unwrap_or_else(|| "HEAD".to_owned());
    // Fail closed: no compiled policy means no blame.
    let readable = state.current_policy().is_some_and(|pol| {
        pol.explain(&identity, &rp, &ref_name)
            .allows(Capability::READ)
    });
    if !readable {
        return Ok(Json(RepoBlameResponse {
            path: q.path,
            allowed: false,
            lines: vec![],
        }));
    }

    let ids = GitIds::of(&state, &identity)?;
    let root = state.workspace_root.clone();
    let path_str = rp.as_str().to_owned();
    let mut lines = tokio::task::spawn_blocking(move || {
        // The path must be in that commit under exactly this name (a tree lookup does not fold
        // case the way a case-insensitive working tree does).
        let exact = premier_git_bridge::git_command(&root)
            .args(["cat-file", "-e", &format!("{rev}:{path_str}")])
            .output()
            .is_ok_and(|o| o.status.success());
        if !exact {
            return Vec::new();
        }
        let out = premier_git_bridge::git_command(&root)
            .args(["blame", "--line-porcelain", &rev, "--", &path_str])
            .output()
            .ok();
        let Some(o) = out.filter(|o| o.status.success()) else {
            return Vec::new();
        };
        parse_git_blame_porcelain(&String::from_utf8_lossy(&o.stdout))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Each line's commit as the viewer's clone has it.
    for line in &mut lines {
        line.oid = ids.shown(&line.oid).chars().take(7).collect();
    }

    Ok(Json(RepoBlameResponse {
        path: q.path,
        allowed: true,
        lines,
    }))
}

fn parse_git_blame_porcelain(raw: &str) -> Vec<BlameLine> {
    let mut out = Vec::new();
    let mut cur_oid = String::new();
    let mut cur_line = 0usize;
    let mut cur_author = String::new();
    let mut cur_summary = String::new();
    let mut cur_date = String::new();

    for line in raw.lines() {
        if line.starts_with('\t') {
            out.push(BlameLine {
                line: cur_line,
                oid: cur_oid.clone(),
                author: cur_author.clone(),
                date: cur_date.clone(),
                summary: cur_summary.clone(),
            });
            continue;
        }
        if let Some(a) = line.strip_prefix("author ") {
            cur_author = a.trim().to_owned();
        } else if let Some(s) = line.strip_prefix("summary ") {
            cur_summary = s.trim().to_owned();
        } else if let Some(ts) = line.strip_prefix("author-time ") {
            if let Ok(secs) = ts.trim().parse::<i64>()
                && let Some(dt) = chrono::DateTime::from_timestamp(secs, 0)
            {
                cur_date = dt.format("%Y-%m-%d").to_string();
            }
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3
                && parts[0].len() == 40
                && parts[0].chars().all(|c| c.is_ascii_hexdigit())
                && let Ok(ln) = parts[2].parse::<usize>()
            {
                cur_oid = parts[0].to_owned();
                cur_line = ln;
            }
        }
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct WriteRepoFileRequest {
    pub path: String,
    /// The file's new content; ignored by `DELETE`.
    #[serde(default)]
    pub content: String,
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    /// Branch to commit on; left out, the default (checked-out) one.
    #[serde(default)]
    pub ref_name: Option<String>,
    /// Commit message; left out, `Update <path>` / `Delete <path>`.
    #[serde(default)]
    pub message: Option<String>,
    /// The branch tip the edit was made on; given, a branch that has moved since answers 409
    /// instead of taking the change on top.
    #[serde(default)]
    pub expected_tip: Option<String>,
    /// An owner overriding the declassification firewall's blocking report: why, and the
    /// `report_digest` of the report they reviewed.
    #[serde(default)]
    pub override_reason: Option<String>,
    #[serde(default)]
    pub override_ack_digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WriteRepoFileResponse {
    pub path: String,
    pub bytes_written: usize,
    /// The branch tip after the change (unchanged when the content already matched).
    pub commit: String,
}

/// `PUT /v1/repo/file`: an ACL-enforced edit (`Capability::WRITE`, `human ∩ agent_task`) that is
/// one commit on the branch, authored by the authenticated account.
pub async fn write_repo_file_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<crate::auth::AuthUser>,
    Json(req): Json<WriteRepoFileRequest>,
) -> Result<Json<WriteRepoFileResponse>, (StatusCode, Json<ApiError>)> {
    commit_repo_file(state, &user, req, false).await
}

#[derive(Debug, Default, Deserialize)]
pub struct DeleteRepoFileQuery {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default)]
    pub ref_name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub expected_tip: Option<String>,
}

/// `DELETE /v1/repo/file`: the same, removing the file. Accepts either a JSON body or query
/// parameters (`?path=&ref_name=&message=&expected_tip=`) when the body is empty so strict reverse
/// proxies/WAFs that strip DELETE bodies still work.
pub async fn delete_repo_file_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<crate::auth::AuthUser>,
    Query(q): Query<DeleteRepoFileQuery>,
    body: axum::body::Bytes,
) -> Result<Json<WriteRepoFileResponse>, (StatusCode, Json<ApiError>)> {
    let req = if body.iter().all(u8::is_ascii_whitespace) {
        let Some(path) = q.path.filter(|p| !p.trim().is_empty()) else {
            return Err(err_resp(StatusCode::BAD_REQUEST, "missing path"));
        };
        WriteRepoFileRequest {
            path,
            content: String::new(),
            principal: q.principal.unwrap_or_else(default_caller),
            agent_profile: q.agent_profile,
            ref_name: q.ref_name,
            message: q.message,
            expected_tip: q.expected_tip,
            override_reason: None,
            override_ack_digest: None,
        }
    } else {
        serde_json::from_slice::<WriteRepoFileRequest>(&body)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?
    };
    commit_repo_file(state, &user, req, true).await
}

async fn commit_repo_file(
    state: ServerState,
    user: &crate::auth::AuthUser,
    req: WriteRepoFileRequest,
    delete: bool,
) -> Result<Json<WriteRepoFileResponse>, (StatusCode, Json<ApiError>)> {
    use crate::canon::{self, CommitError};

    let rp =
        RepoPath::new(&req.path).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    if rp.is_root() {
        return Err(err_resp(StatusCode::BAD_REQUEST, "path names no file"));
    }
    // Server state, `.git` and every alias of them: never repository content, whatever policy says.
    if rp
        .as_str()
        .split('/')
        .any(premier_git_bridge::is_reserved_path_component)
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "path names a reserved component",
        ));
    }
    // The files that configure the server are edited from a signed-in browser, as
    // `PUT /v1/policy/repo` is: never with an access token (a Git push is the one exception).
    if canon::CONFIG_FILES.contains(&rp.as_str()) {
        crate::auth::require_browser_session(user)?;
    }
    let verb = if delete { "Delete" } else { "Update" };
    // Only words the caller wrote are scanned; the default message names the edited path.
    let typed_message = req
        .message
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let message = match req
        .message
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        Some(m) if m.len() > 4096 || m.contains('\0') => {
            return Err(err_resp(StatusCode::BAD_REQUEST, "invalid commit message"));
        }
        Some(m) => m.to_owned(),
        None => format!("{verb} {rp}"),
    };
    let identity = parse_identity(&state, &req.principal, req.agent_profile, "studio-edit")?;
    let root = state.workspace_root.clone();
    let default_ref = canon::default_ref(&root);
    let ref_name = req.ref_name.unwrap_or_else(|| crate::checked_out(&root).0);
    // Any branch the caller can see (a hidden one answers like a missing one). The default
    // branch of a repository with no commit yet is there to take its first.
    let full_ref = match crate::content_source(&state, &identity, &ref_name)? {
        Some(full) if full.starts_with("refs/") => full,
        None if default_ref.is_some() => default_ref.clone().unwrap_or_default(),
        _ => {
            return Err(err_resp(
                StatusCode::CONFLICT,
                "no branch is checked out to commit on",
            ));
        }
    };

    // Where the server's filesystem folds names (`BILLING/x`, 8.3 short names) the working tree
    // would put the file on an existing path of another spelling: that path's rules apply too.
    let on_disk = crate::working_tree_path(&root, &rp);
    let folded = on_disk.as_ref().map_or(&rp, |(_, canonical)| canonical);
    // Fail closed: no compiled policy means no write, not an unchecked one.
    let allowed = state.current_policy().is_some_and(|pol| {
        [&rp, folded].into_iter().all(|p| {
            pol.explain(&identity, p, &ref_name)
                .allows(Capability::WRITE)
        })
    });
    // Detached `HEAD`: any branch may become the default one, so every branch is treated as it.
    let on_default = default_ref.as_deref().is_none_or(|d| d == full_ref);
    // On the default branch `.access.toml` and `.env.schema` configure the server: owners only,
    // and only content the server can load (same rule as a push).
    let config = if allowed && on_default && canon::CONFIG_FILES.contains(&rp.as_str()) {
        let is_owner =
            identity.matches_selector(&format!("group:{}", crate::directory::OWNERS_GROUP));
        let content = (!delete).then_some(req.content.as_bytes());
        state.check_config_change(is_owner, rp.as_str(), content)
    } else {
        Ok(())
    };
    if !allowed || config == Err(None) {
        let mut ev = AuditEvent::now(
            &identity,
            "premier-server",
            "repo_file_write",
            AuditDecision::Denied,
            format!("Denied WRITE on '{}' for {}", rp, identity.principal),
        );
        ev.target = Some(rp.as_str().to_owned());
        crate::auth::audit(&state.audit_sink, ev);
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            format!("policy denied WRITE on '{}'", rp),
        ));
    }
    if let Err(Some(why)) = config {
        return Err(err_resp(StatusCode::BAD_REQUEST, why));
    }
    if is_internal_path(&root, rp.as_str()) || is_internal_path(&root, folded.as_str()) {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "server state paths are not writable through the repo API",
        ));
    }
    if on_disk.is_none() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "path goes through a symbolic link or leaves the workspace",
        ));
    }
    if folded != &rp {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("'{rp}' is another spelling of the existing path '{folded}'"),
        ));
    }
    if !delete {
        let overlay_manifest = crate::overlay_manifest(&state)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let overlay_guard = OverlayGuard::from_manifest(&overlay_manifest)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Err(e) = overlay_guard.validate_public_paths(std::slice::from_ref(&rp)) {
            let mut ev = AuditEvent::now(
                &identity,
                "premier-server",
                "repo_file_write",
                AuditDecision::Denied,
                format!("OverlayGuard blocked write on '{rp}': {e}"),
            );
            ev.target = Some(rp.as_str().to_owned());
            crate::auth::audit(&state.audit_sink, ev);
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                format!("overlay guard blocked write: {e}"),
            ));
        }
    }

    // The declassification firewall and the instruction quarantine, before anything lands.
    let policy = state
        .current_policy()
        .ok_or_else(|| err_resp(StatusCode::SERVICE_UNAVAILABLE, "no compiled policy loaded"))?;
    let is_instruction = policy.is_instruction_file(&rp);
    if is_instruction && policy.quarantine_enforced() && user.role == crate::auth::Role::Owner {
        crate::auth::require_browser_session(user)?;
    }
    let actor_is_agent = identity.agent_task.is_some();
    let actor_is_owner = user.role == crate::auth::Role::Owner
        && identity.matches_selector(&format!("group:{}", crate::directory::OWNERS_GROUP));
    let scanned = [premier_policy::ScanTargetFile {
        path: rp.as_str().to_owned(),
        content: if delete {
            Vec::new()
        } else {
            req.content.as_bytes().to_vec()
        },
        deleted: delete,
    }];
    let report = crate::firewall::scan_change(
        &state,
        &policy,
        canon::tip_of(&root, &full_ref).as_deref(),
        &ref_name,
        &state.ref_visibility(&full_ref),
        &scanned,
        &typed_message,
        actor_is_owner,
        actor_is_agent,
    );
    if !report.passed {
        let as_owner = actor_is_owner && !actor_is_agent;
        let pure_quarantine = !report.has_sensitive_blocking();
        if !as_owner && !delete && pure_quarantine && policy.quarantine_hold_pending() {
            let base =
                crate::firewall::blob_at(&root, &full_ref, rp.as_str()).map(|b| sha256_hex(&b));
            let findings = report
                .findings
                .iter()
                .filter(|f| f.blocking)
                .cloned()
                .collect();
            let edit = crate::firewall::record_pending_quarantine_edit(
                &state,
                &identity,
                rp.as_str(),
                &full_ref,
                &req.content,
                base,
                &message,
                findings,
            )
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let body = ApiError {
                error: format!(
                    "'{rp}' is an instruction file: the edit is held for an owner's approval and nothing was committed"
                ),
                firewall: crate::FirewallRefusal::new(report.redact_for_non_owner(), Some(edit.id)),
                ..ApiError::default()
            };
            return Err((StatusCode::FORBIDDEN, Json(body)));
        }
        if req.override_reason.is_some() || req.override_ack_digest.is_some() {
            crate::firewall::verify_and_record_override(
                &state,
                user,
                &identity,
                &policy,
                "repo_file_write",
                &format!("{full_ref}:{rp}"),
                &report,
                req.override_reason.as_deref(),
                req.override_ack_digest.as_deref(),
            )?;
        } else {
            crate::firewall::record_firewall_audit(
                &state.audit_sink,
                &identity,
                "repo_file_write",
                rp.as_str(),
                &report,
            );
            let (status, body) = if as_owner {
                let error = format!(
                    "declassification firewall blocked this change ({}): nothing was committed",
                    premier_git_bridge::plural(report.blocking_count, "blocking finding")
                );
                (
                    StatusCode::CONFLICT,
                    ApiError {
                        error,
                        firewall: crate::FirewallRefusal::new(report, None),
                        ..ApiError::default()
                    },
                )
            } else {
                let status = if pure_quarantine {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::CONFLICT
                };
                let error = report
                    .push_rejection_message(false)
                    .unwrap_or_else(|| premier_policy::GENERIC_FIREWALL_REJECT.to_owned());
                (
                    status,
                    ApiError {
                        error,
                        firewall: crate::FirewallRefusal::new(report.redact_for_non_owner(), None),
                        ..ApiError::default()
                    },
                )
            };
            return Err((status, Json(body)));
        }
    }
    // An owner's own edit of an instruction file is what agents get from now on.
    let approve_as = (!delete && actor_is_owner && !actor_is_agent && is_instruction)
        .then(|| (rp.as_str().to_owned(), req.content.clone()));

    let who = canon::committer(&state);
    let bytes_written = if delete { 0 } else { req.content.len() };
    let content = (!delete).then(|| req.content.into_bytes());
    let (state_bg, full_bg, rp_bg) = (state.clone(), full_ref.clone(), rp.clone());
    // The tip the edit was made on is the one the caller's clone has.
    let ids = GitIds::of(&state, &identity)?;
    let expected = req
        .expected_tip
        .map(|tip| ids.canonical_tip(&ref_name, tip));
    let commit = tokio::task::spawn_blocking(move || {
        let before = on_default
            .then(|| canon::DefaultTip::capture(&root))
            .flatten();
        let done = canon::commit_file(
            &root,
            &full_bg,
            expected.as_deref(),
            &rp_bg,
            content.as_deref(),
            &message,
            &who,
        );
        state_bg.default_branch_moved(before);
        done
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        CommitError::Moved => err_resp(
            StatusCode::CONFLICT,
            format!("'{ref_name}' has moved since this change was made: reload and try again"),
        ),
        CommitError::Invalid(why) if delete => err_resp(StatusCode::NOT_FOUND, why),
        CommitError::Invalid(why) => err_resp(StatusCode::BAD_REQUEST, why),
        CommitError::Internal(why) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, why),
    })?;

    let short = &commit[..commit.len().min(12)];
    let mut ev = AuditEvent::now(
        &identity,
        "premier-server",
        "repo_file_write",
        AuditDecision::Allowed,
        format!("{verb}d '{rp}' on {full_ref} as commit {short} ({bytes_written} bytes)"),
    );
    ev.target = Some(rp.as_str().to_owned());
    crate::auth::audit(&state.audit_sink, ev);
    if let Some((path, content)) = approve_as
        && let Err(e) = crate::firewall::record_owner_instruction_approval(
            &state,
            &path,
            &content,
            &crate::auth::actor_principal(),
            "committed by an owner",
        )
    {
        tracing::warn!(error = %e, path, "failed to record instruction file approval");
    }

    Ok(Json(WriteRepoFileResponse {
        path: rp.as_str().to_owned(),
        bytes_written,
        // As the caller will fetch it: their view of the branch after this commit.
        commit: GitIds::of(&state, &identity)?
            .tip(&ref_name, &commit)
            .unwrap_or_default(),
    }))
}

// ---------------------------------------------------------------------------
// 2. Live Policy Hot-Reload (`PUT /v1/policy/repo`)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateRepoPolicyRequest {
    pub toml: String,
    #[serde(default = "default_caller")]
    pub principal: String,
    /// Optional SHA-256 of the base policy `.access.toml`; when set, mismatched commits fail with 409.
    #[serde(default)]
    pub expected_base_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateRepoPolicyResponse {
    pub ok: bool,
    /// Where the policy lives: `.access.toml` on the default branch.
    pub persisted_path: Option<String>,
    pub rule_count: usize,
    /// The default branch tip holding the applied policy.
    pub commit: String,
}

/// "Apply": validate and compile against the active Server Policy (`Server > Repo`), commit
/// `.access.toml` to the default branch, then make it live. Nothing is committed unless it
/// compiles and leaves the owners in.
pub async fn update_repo_policy_handler(
    State(state): State<ServerState>,
    Json(req): Json<UpdateRepoPolicyRequest>,
) -> Result<Json<UpdateRepoPolicyResponse>, (StatusCode, Json<ApiError>)> {
    use crate::canon::{self, CommitError};

    let (parsed_repo, _) = state
        .validate_repo_policy(&req.toml)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    let root = state.workspace_root.clone();
    let Some(full_ref) = canon::default_ref(&root) else {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "no branch is checked out to commit the policy on",
        ));
    };
    let path = RepoPath::new(canon::POLICY_FILE)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let who = canon::committer(&state);
    let (state_bg, toml, expected_base_sha256) =
        (state.clone(), req.toml, req.expected_base_sha256);
    let commit = tokio::task::spawn_blocking(move || {
        let before = canon::DefaultTip::capture(&root);
        if let Some(expected) = expected_base_sha256.as_deref() {
            let current = premier_git_bridge::git_command(&root)
                .args([
                    "cat-file",
                    "blob",
                    &format!("{full_ref}:{}", canon::POLICY_FILE),
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_else(|| {
                    let mem = state_bg.current_repo_policy_toml();
                    if mem.trim().is_empty() {
                        crate::directory::DEFAULT_POLICY_TOML.to_owned()
                    } else {
                        mem
                    }
                });
            if sha256_hex(current.as_bytes()) != expected.trim().to_ascii_lowercase() {
                return Err(CommitError::Moved);
            }
        }
        let done = canon::commit_file(
            &root,
            &full_ref,
            None,
            &path,
            Some(toml.as_bytes()),
            "Update access policy",
            &who,
        )?;
        // The owner has now chosen this policy: an imported one is no longer held back.
        let _ =
            std::fs::remove_file(crate::store::state_dir(&root).join(crate::repos::PENDING_POLICY));
        state_bg.default_branch_moved(before);
        // Also when the tip did not move (the imported text applied as it was).
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
            "the default branch moved while the policy was being committed: reload and try again",
        ),
        CommitError::Invalid(why) => err_resp(StatusCode::BAD_REQUEST, why),
        CommitError::Internal(why) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, why),
    })?;

    let rule_count = parsed_repo.rules.len();
    let id = parse_identity(&state, &req.principal, None, "policy-update")?;
    let mut ev = AuditEvent::now(
        &id,
        "premier-policy",
        "policy_hot_reloaded",
        AuditDecision::Allowed,
        format!(
            "Committed and applied .access.toml ({}, Server > Repo active)",
            premier_git_bridge::plural(rule_count, "repo rule")
        ),
    );
    ev.target = Some(canon::POLICY_FILE.to_owned());
    crate::auth::audit(&state.audit_sink, ev);

    Ok(Json(UpdateRepoPolicyResponse {
        ok: true,
        persisted_path: Some(canon::POLICY_FILE.to_owned()),
        rule_count,
        commit,
    }))
}

// ---------------------------------------------------------------------------
// 3. Real Git Branch Create / Delete / Publish (Squash-Declassify)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateBranchRequest {
    pub name: String,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub from_ref: Option<String>,
    /// Owners only. Left out, the branch is as visible as the one it is created from.
    #[serde(default)]
    pub visibility: Option<Visibility>,
    #[serde(default = "default_readiness_wip")]
    pub readiness: Readiness,
}

fn default_readiness_wip() -> Readiness {
    Readiness::Wip
}

/// Personal branches one member may hold (they cannot delete them: creating must not be free).
const MAX_MEMBER_BRANCHES: usize = 50;

#[derive(Debug, Serialize)]
pub struct CreateBranchResponse {
    pub name: String,
    pub full_ref: String,
    pub oid: String,
    pub visibility: Visibility,
    pub readiness: Readiness,
}

/// A branch name the API will create: a valid Git branch name, and nothing that could be read as
/// a full ref name (a branch literally called `refs/premier-private/x` or `refs/heads/main` would
/// collide with that ref's visibility entry), `HEAD`, or `@`.
pub(crate) fn valid_branch_name(root: &Path, name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name != "HEAD"
        && name != "@"
        && !name.starts_with("refs/")
        && !name.starts_with('-')
        && premier_git_bridge::git_command(root)
            .args(["check-ref-format", "--branch", name])
            .output()
            .is_ok_and(|o| o.status.success())
}

pub async fn create_branch_handler(
    State(state): State<ServerState>,
    Json(req): Json<CreateBranchRequest>,
) -> Result<Json<CreateBranchResponse>, (StatusCode, Json<ApiError>)> {
    let name = req.name.trim();
    let root = state.workspace_root.clone();
    // Owners in a browser session administer every branch. Members (and owner access tokens)
    // branch only from a ref they can see and have some access to (any other base answers exactly
    // like a missing one) and never onto a name already in use, which would move that branch and
    // rewrite its visibility.
    //
    // The chosen behaviour for a taken name: 409 only when the member can see the branch that has
    // it. A name held by a branch they cannot see gets `create_failed`, the same response as any
    // other failure to create the ref, so the answer never says "a hidden branch has this name".
    // (That a valid name fails at all is still a hint; only per-user namespaces would remove it.)
    let is_owner = crate::auth::owner_only().is_ok();
    let create_failed = || err_resp(StatusCode::BAD_REQUEST, "branch could not be created");
    if !valid_branch_name(&root, name) {
        // For a member, the same answer as a name a hidden branch holds (see above).
        return Err(if is_owner {
            err_resp(StatusCode::BAD_REQUEST, "invalid branch name")
        } else {
            create_failed()
        });
    }
    // Without an explicit choice, the visibility is the bridge's rule for a pushed branch
    // (`new_branch_visibility`), so the Studio and `git push` create the same thing.
    let me = parse_identity(&state, &default_caller(), None, "branch-create")?;
    let base = req
        .from_ref
        .clone()
        .unwrap_or_else(|| crate::default_branch(&root));
    // The branches the base is read through (a member's only): see the check below.
    let (from_ref, visibility, sources) = if is_owner {
        let metadata = state.branch_metadata();
        let taken = ["refs/heads/", PRIVATE_REF_PREFIX].iter().any(|ns| {
            let full = format!("{ns}{name}");
            metadata.contains_key(&full) || resolve_branch_oid(&root, &full).is_ok()
        });
        if taken {
            return Err(err_resp(StatusCode::CONFLICT, "branch already exists"));
        }
        // An owner's choice stands.
        let default = || {
            let source =
                crate::branch_full_ref(&root, &base).map(|full| state.ref_visibility(&full));
            premier_git_bridge::new_branch_visibility(true, &me.principal, source.as_slice())
        };
        // A private source is only reachable by its full name.
        let from = crate::branch_full_ref(&root, &base).unwrap_or_else(|| base.clone());
        (from, req.visibility.clone().unwrap_or_else(default), None)
    } else {
        // Visibility is the owners' to choose: a member's branch is always theirs alone.
        if req.visibility.is_some() {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "only an owner can choose a branch's visibility; leave it out for a personal branch",
            ));
        }
        let (from, sources) = crate::resolve_accessible_refs(&state, &me, &base)?;
        let metadata = state.branch_metadata();
        let taken = ["refs/heads/", PRIVATE_REF_PREFIX].iter().any(|ns| {
            let full = format!("{ns}{name}");
            metadata.contains_key(&full) || resolve_branch_oid(&root, &full).is_ok()
        });
        if taken {
            return Err(if crate::resolve_visible_rev(&state, &me, name).is_ok() {
                err_resp(StatusCode::CONFLICT, "branch name is not available")
            } else {
                create_failed()
            });
        }
        // Branching can never publish anything (that is the owner's `POST /v1/branches/publish`).
        let mine = premier_git_bridge::new_branch_visibility(false, &me.principal, &[]);
        if metadata.values().filter(|(v, _)| *v == mine).count() >= MAX_MEMBER_BRANCHES {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                format!(
                    "personal branch limit reached ({MAX_MEMBER_BRANCHES}): ask an owner to delete some"
                ),
            ));
        }
        (from, mine, Some(sources))
    };
    let is_private = !matches!(visibility, Visibility::Public);
    let full_ref = if is_private {
        format!("{PRIVATE_REF_PREFIX}{name}")
    } else {
        format!("refs/heads/{name}")
    };
    let full_ref_bg = full_ref.clone();
    let (policy, me_bg, name_bg) = (state.current_policy(), me.clone(), name.to_owned());

    let oid = tokio::task::spawn_blocking(move || {
        let bad = |msg: String| (StatusCode::BAD_REQUEST, msg);
        let out = premier_git_bridge::git_command(&root)
            .args(["rev-parse", "--verify", &from_ref])
            .output()
            .map_err(|e| bad(format!("git rev-parse failed: {e}")))?;
        if !out.status.success() {
            return Err(bad(format!(
                "base ref '{}' not found: {}",
                from_ref,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        // Path rules are ref-scoped: the new name must not unlock a file of this tree the
        // member cannot read where she branched from (`git push` makes the same check).
        if let Some(sources) = sources {
            let policy = policy.ok_or_else(|| bad("no compiled policy loaded".to_owned()))?;
            let tree = crate::repos::git_out(&root, &["ls-tree", "-r", "--name-only", "-z", &oid])
                .ok_or_else(|| bad("could not read the base tree".to_owned()))?;
            let hidden = tree.split('\0').filter(|p| {
                !p.is_empty()
                    && !sources
                        .iter()
                        .any(|b| premier_git_bridge::path_is_projected(&policy, &me_bg, b, p))
            });
            if premier_git_bridge::exposes_hidden_files(&policy, &me_bg, &name_bg, hidden) {
                return Err(bad(
                    "the new branch would expose files hidden on its base".to_owned()
                ));
            }
        }
        let _ref_lock = crate::canon::ref_lock(&root);
        let taken_now = ["refs/heads/", PRIVATE_REF_PREFIX].iter().any(|ns| {
            let full = format!("{ns}{name_bg}");
            resolve_branch_oid(&root, &full).is_ok()
        });
        if taken_now {
            return Err((StatusCode::CONFLICT, "branch already exists".to_owned()));
        }
        let canonical = CanonicalGitRepo::open(&root);
        canonical
            .update_ref_cas(
                &full_ref_bg,
                &oid,
                "0000000000000000000000000000000000000000",
            )
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
        Ok::<_, (StatusCode, String)>(oid)
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|(code, e)| {
        if is_owner {
            err_resp(code, e)
        } else {
            create_failed()
        }
    })?;

    if let Ok(mut st) = state.persisted.lock() {
        st.branch_metadata
            .insert(full_ref.clone(), (visibility.clone(), req.readiness));
        let _ = save_state(&state.workspace_root, &st);
    }

    Ok(Json(CreateBranchResponse {
        name: name.to_owned(),
        full_ref,
        // The new branch's tip as the creator's clone will have it.
        oid: GitIds::of(&state, &me)?.tip(name, &oid).unwrap_or_default(),
        visibility,
        readiness: req.readiness,
    }))
}

pub async fn delete_branch_handler(
    State(state): State<ServerState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let trimmed = name.trim().trim_start_matches('/');
    if !valid_branch_name(&state.workspace_root, trimmed) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid branch name"));
    }
    if trimmed == crate::default_branch(&state.workspace_root) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "refusing to delete protected default branch",
        ));
    }

    let root = state.workspace_root.clone();
    let target = trimmed.to_owned();
    tokio::task::spawn_blocking(move || {
        let _lock = crate::canon::ref_lock(&root);
        // Delete either refs/premier-private/<name> or refs/heads/<name>
        let priv_ref = format!("{PRIVATE_REF_PREFIX}{target}");
        let head_ref = format!("refs/heads/{target}");
        let del_priv = premier_git_bridge::git_command(&root)
            .args(["update-ref", "-d", "--", &priv_ref])
            .output()
            .ok()
            .is_some_and(|o| o.status.success());
        let del_head = premier_git_bridge::git_command(&root)
            .args(["branch", "-D", "--", &target])
            .output()
            .ok()
            .is_some_and(|o| o.status.success());
        if !del_priv && !del_head {
            let _ = premier_git_bridge::git_command(&root)
                .args(["update-ref", "-d", "--", &head_ref])
                .output();
        }
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Ok(mut st) = state.persisted.lock() {
        st.branch_metadata.remove(trimmed);
        for ns in ["refs/heads/", PRIVATE_REF_PREFIX] {
            st.branch_metadata.remove(&format!("{ns}{trimmed}"));
        }
        let _ = save_state(&state.workspace_root, &st);
    }

    Ok(Json(serde_json::json!({ "ok": true, "deleted": trimmed })))
}

#[derive(Debug, Deserialize)]
pub struct PublishBranchRequest {
    pub source_branch: String,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub target_branch: Option<String>,
    #[serde(default)]
    pub summary_message: Option<String>,
    /// Optional CAS guard on the source branch tip OID reviewed in preview (409 on mismatch).
    #[serde(default)]
    pub expected_source_oid: Option<String>,
    /// Optional CAS guard on the target branch tip OID reviewed in preview (409 on mismatch).
    #[serde(default)]
    pub expected_target_oid: Option<String>,
    /// An owner overriding the declassification firewall's blocking report: why, and the
    /// `report_digest` of the report they reviewed.
    #[serde(default)]
    pub override_reason: Option<String>,
    #[serde(default)]
    pub override_ack_digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublishBranchResponse {
    pub new_commit_oid: String,
    pub target_ref: String,
    /// Paths the commit added, changed or deleted on the target.
    pub published_paths: Vec<String>,
    /// Paths the branch changed that were left out (the target keeps its own version).
    pub scrubbed_paths: Vec<String>,
    /// Paths cleanly auto-merged by line-level 3-way merge during publish.
    #[serde(default)]
    pub merged_paths: Vec<String>,
    pub attestation_trailer: String,
    /// The new commit's full message, trailer included.
    pub commit_message: String,
    /// RFC 3339, when the server recorded the publish.
    pub published_at: String,
    /// The publishing account (canonical principal id).
    pub actor: String,
    /// The policy fingerprint the attestation names.
    pub policy_fingerprint: String,
}

/// The ref a publish lands on: `refs/heads/<target>`, or the default branch when none is named.
pub(crate) fn publish_target(
    root: &Path,
    target: Option<&str>,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    match target.map(str::trim).filter(|t| !t.is_empty()) {
        Some(full) if full.starts_with("refs/") => Ok(full.to_owned()),
        Some(name) => Ok(format!("refs/heads/{name}")),
        None => crate::canon::default_ref(root).ok_or_else(|| {
            err_resp(
                StatusCode::CONFLICT,
                "no branch is checked out to publish onto",
            )
        }),
    }
}

/// Publish (Squash-Declassify): land the changes of `source_branch` since it forked from the
/// target, minus the paths the public may not read, as ONE commit on top of the target. Nothing
/// else on the target changes; a path changed on both sides refuses the publish (409).
pub async fn publish_branch_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<crate::auth::AuthUser>,
    Json(req): Json<PublishBranchRequest>,
) -> Result<Json<PublishBranchResponse>, (StatusCode, Json<ApiError>)> {
    use premier_git_bridge::GitBridgeError;

    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let overlay_manifest = crate::overlay_manifest(&state)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let overlay_guard = OverlayGuard::from_manifest(&overlay_manifest)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let fp_short = state.policy_fingerprint();
    let policy_fingerprint = fp_short.clone();
    let root = state.workspace_root.clone();
    let source = req.source_branch.clone();
    let target_ref = publish_target(&root, req.target_branch.as_deref())?;
    let target = target_ref
        .strip_prefix("refs/heads/")
        .unwrap_or(&target_ref)
        .to_owned();
    // Left empty, `publish_commit_message` names the target only (what the preview proposed).
    let msg = req.summary_message.unwrap_or_default();
    // The authenticated account, as on every commit the server makes for a user.
    let (name, email) = crate::canon::committer(&state);
    let author_line = format!(
        "{} <{email}> {} +0000",
        name.replace(['<', '>', '\n', '\r'], ""),
        Utc::now().timestamp()
    );
    let is_owner = crate::auth::owner_only().is_ok();
    let me = parse_identity(&state, &default_caller(), None, "branch-publish")?;
    // An override is checked as far as it can be before the report exists; the bridge applies it
    // only to the report whose digest it names.
    let wants_override = req.override_reason.is_some() || req.override_ack_digest.is_some();
    let override_reason = if wants_override {
        Some(crate::firewall::check_override_preconditions(
            &user,
            &me,
            &policy,
            req.override_reason.as_deref(),
        )?)
    } else {
        None
    };
    let ack_digest = req.override_ack_digest.clone().filter(|_| wants_override);
    let vault = crate::firewall::build_vault_secret_index(&state);
    let approved = crate::firewall::approved_instruction_map(&state);

    // An empty OID means "not offered".
    let expected_source_oid = req.expected_source_oid.clone().filter(|e| !e.is_empty());
    let expected_target_oid = req.expected_target_oid.clone().filter(|e| !e.is_empty());
    let (state_bg, policy_bg, target_bg) = (state.clone(), policy.clone(), target_ref.clone());
    let (res, merged_paths) = tokio::task::spawn_blocking(move || {
        let (policy, target_ref) = (policy_bg, target_bg);
        let before = crate::canon::DefaultTip::capture(&root);
        let res = (|| {
            let canonical = CanonicalGitRepo::open(&root);
            let source_oid =
                resolve_branch_oid(&root, &source).map_err(GitBridgeError::Rejected)?;
            let target_parent_oid = crate::canon::tip_of(&root, &target_ref);
            if expected_source_oid
                .as_deref()
                .is_some_and(|exp| exp != source_oid)
            {
                return Err(GitBridgeError::RefMoved);
            }
            if expected_target_oid
                .as_deref()
                .is_some_and(|exp| target_parent_oid.as_deref() != Some(exp))
            {
                return Err(GitBridgeError::RefMoved);
            }
            let plan = premier_git_bridge::plan_squash_declassify(
                &canonical,
                &policy,
                &source_oid,
                &target_ref,
                target_parent_oid.as_deref(),
            )?;
            let merged_paths: Vec<String> = plan.merged_blobs.keys().cloned().collect();
            // Onto the default branch, the commit's policy and schema must be ones the server can
            // load (same rule as a Studio write or a push), checked before the ref moves.
            let on_default =
                crate::canon::default_ref(&root).as_deref() == Some(target_ref.as_str());
            let check = |new: &str| match on_default {
                true => state_bg.check_config_commit(is_owner, target_parent_oid.as_deref(), new),
                false => Ok(()),
            };
            let firewall = premier_git_bridge::SquashFirewallInput {
                vault: vault.as_ref(),
                approved_instructions: Some(&approved),
                actor_is_owner: is_owner,
                actor_is_agent: false,
                owner_override_digest: ack_digest.as_deref(),
            };
            // The report an override would be exercised on, when one is offered.
            let overridden = match &ack_digest {
                Some(digest) => {
                    let report = premier_git_bridge::scan_squash_declassify(
                        &canonical,
                        &policy,
                        &plan,
                        &source_oid,
                        &target_ref,
                        target_parent_oid.as_deref(),
                        &msg,
                        &firewall,
                    )?;
                    (!report.passed && report.report_digest == *digest).then_some(report)
                }
                None => None,
            };
            let published = premier_git_bridge::execute_squash_declassify_with_firewall(
                &canonical,
                &policy,
                &fp_short,
                Some(&overlay_guard),
                &source,
                &source_oid,
                &target_ref,
                target_parent_oid.as_deref(),
                &msg,
                &author_line,
                &firewall,
                Some(&check),
            )?;
            Ok(((published, overridden), merged_paths))
        })();
        state_bg.default_branch_moved(before);
        res
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        GitBridgeError::FirewallBlocked(report) => {
            crate::firewall::record_firewall_audit(
                &state.audit_sink,
                &me,
                "branch_publish",
                &target_ref,
                &report,
            );
            let error = format!(
                "publish refused by the declassification firewall ({}): nothing was published",
                premier_git_bridge::plural(report.blocking_count, "blocking finding")
            );
            let body = ApiError {
                error,
                firewall: crate::FirewallRefusal::new(*report, None),
                ..ApiError::default()
            };
            (StatusCode::CONFLICT, Json(body))
        }
        GitBridgeError::PublishConflict(paths) => {
            let total = paths.len();
            let conflicts: Vec<String> = paths
                .into_iter()
                .filter(|p| {
                    RepoPath::new(p)
                        .is_ok_and(|rp| policy.explain(&me, &rp, &target).allows(Capability::LIST))
                })
                .collect();
            let error = format!(
                "publish refused: {} changed on both '{}' and '{target}'; nothing was published",
                premier_git_bridge::plural(total, "path"),
                req.source_branch
            );
            let hidden_conflicts = Some(u32::try_from(total - conflicts.len()).unwrap_or(u32::MAX));
            let body = ApiError { error, conflicts, hidden_conflicts, ..ApiError::default() };
            (StatusCode::CONFLICT, Json(body))
        }
        GitBridgeError::PublishBlocked(paths) => {
            let total = paths.len();
            let blocked: Vec<String> = paths
                .into_iter()
                .filter(|p| {
                    RepoPath::new(p)
                        .is_ok_and(|rp| policy.explain(&me, &rp, &target).allows(Capability::LIST))
                })
                .collect();
            let error = format!(
                "publish refused: {} would carry the content of restricted files onto '{target}'; nothing was published",
                premier_git_bridge::plural(total, "path")
            );
            let hidden_blocked = Some(u32::try_from(total - blocked.len()).unwrap_or(u32::MAX));
            let body = ApiError { error, blocked, hidden_blocked, ..ApiError::default() };
            (StatusCode::CONFLICT, Json(body))
        }
        e @ GitBridgeError::RefMoved => err_resp(StatusCode::CONFLICT, e.to_string()),
        e => err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    })?;
    let (res, overridden) = res;
    if let (Some(report), Some(reason)) = (overridden, override_reason)
        && let Err(e) = crate::firewall::record_override(
            &state,
            &user,
            &me,
            "branch_publish",
            &target_ref,
            &report,
            &reason,
        )
    {
        tracing::warn!(error = %e, "failed to record a firewall override");
    }

    let now = Utc::now().to_rfc3339();
    let mut ev = AuditEvent::now(
        &me,
        "premier-git-bridge",
        "branch_publish",
        AuditDecision::Allowed,
        format!(
            "Declassified and published {} onto {} ({}, {} scrubbed)",
            res.new_commit_oid.chars().take(10).collect::<String>(),
            res.target_ref,
            premier_git_bridge::plural(res.published_paths.len(), "path"),
            res.scrubbed_paths.len()
        ),
    );
    ev.target = Some(res.target_ref.clone());
    crate::auth::audit(&state.audit_sink, ev);

    let trailer = res.attestation.to_git_trailer();
    Ok(Json(PublishBranchResponse {
        new_commit_oid: res.new_commit_oid,
        target_ref: res.target_ref,
        published_paths: res.published_paths,
        scrubbed_paths: res.scrubbed_paths,
        merged_paths,
        attestation_trailer: trailer,
        commit_message: res.commit_message,
        published_at: now,
        actor: me.principal.canonical_id(),
        policy_fingerprint,
    }))
}

pub(crate) fn resolve_branch_oid(root: &Path, name: &str) -> Result<String, String> {
    for candidate in [
        format!("{PRIVATE_REF_PREFIX}{name}"),
        format!("refs/heads/{name}"),
        name.to_owned(),
    ] {
        let out = premier_git_bridge::git_command(root)
            .args(["rev-parse", "--verify", "--end-of-options", &candidate])
            .output()
            .ok();
        if let Some(o) = out.filter(|o| o.status.success()) {
            return Ok(String::from_utf8_lossy(&o.stdout).trim().to_owned());
        }
    }
    Err(format!("branch or ref '{name}' not found in repository"))
}

// ---------------------------------------------------------------------------
// 4. Real Persisted Change-Id Reviews, Comments, and Verdicts (ZERO mocks!)
// ---------------------------------------------------------------------------

const MAX_REVIEW_TEXT_BYTES: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
pub struct CreateReviewRequest {
    pub title: String,
    pub branch: String,
    /// Left out, the repository's default (checked-out) branch.
    #[serde(default)]
    pub base_ref: Option<String>,
    #[serde(default = "default_caller")]
    pub author: String,
    #[serde(default)]
    pub delegated_agent: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub prompt_summary: Option<String>,
}

pub async fn create_review_handler(
    State(state): State<ServerState>,
    Json(req): Json<CreateReviewRequest>,
) -> Result<Json<StoredReview>, (StatusCode, Json<ApiError>)> {
    if req.title.trim().is_empty() || req.title.len() > MAX_REVIEW_TEXT_BYTES {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("review title must be 1-{MAX_REVIEW_TEXT_BYTES} bytes"),
        ));
    }
    if req
        .prompt_summary
        .as_deref()
        .is_some_and(|s| s.len() > MAX_REVIEW_TEXT_BYTES)
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("prompt_summary exceeds {MAX_REVIEW_TEXT_BYTES} bytes"),
        ));
    }
    let root = state.workspace_root.clone();
    // Only a branch (or commit) the author can see; a hidden one answers like a missing one.
    let not_found = || {
        let msg = format!("branch or ref '{}' not found in repository", req.branch);
        err_resp(StatusCode::BAD_REQUEST, msg)
    };
    let identity = parse_identity(&state, &req.author, None, "review-create")?;
    let branch =
        crate::resolve_accessible_rev(&state, &identity, &req.branch).map_err(|_| not_found())?;
    let base_ref = req
        .base_ref
        .unwrap_or_else(|| crate::default_branch(&state.workspace_root));
    let branch_bg = branch.clone();
    let base_ref_bg = base_ref.clone();
    let req_branch_bg = req.branch.clone();
    let (oid, round1_base) = tokio::task::spawn_blocking(move || {
        let oid = resolve_branch_oid(&root, &branch_bg)?;
        let merge_base = if base_ref_bg != req_branch_bg {
            crate::repos::git_out(&root, &["merge-base", &base_ref_bg, &oid])
                .filter(|mb| mb != &oid)
        } else {
            None
        };
        let base_commit = merge_base.or_else(|| {
            crate::repos::git_out(&root, &["rev-parse", "-q", "--verify", &format!("{oid}^")])
        });
        Ok::<_, String>((oid, base_commit))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|_| not_found())?;

    let cid_hash = sha256_hex(
        format!(
            "{}:{}:{}",
            req.branch,
            oid,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        )
        .as_bytes(),
    );
    let change_id = format!("I{}", &cid_hash[..10]);
    let effective_author = crate::auth::effective_principal(&req.author);
    let now = Utc::now().to_rfc3339();

    let linked_session = req.session_id.as_deref().and_then(|sid| {
        state
            .session_manager
            .list()
            .into_iter()
            .find(|s| s.id == sid && may_see_session(s))
    });
    let linked_session_id = linked_session.as_ref().map(|s| s.id.clone());
    let linked_lane_id = linked_session.as_ref().and_then(|s| s.lane_id.clone());
    let prompt_summary_orig = req.prompt_summary.clone();

    let provenance = if let Some(s) = linked_session {
        let (egress_calls, egress_blocked) = session_egress_counts(&state, &s);
        Some(CapturedProvenance {
            sandbox: (!s.sandbox.is_empty()).then(|| s.sandbox.clone()),
            bytes_scrubbed: s.bytes_scrubbed,
            exit_code: s.exit_code,
            egress_calls,
            egress_blocked,
            session_id: s.id.clone(),
            principal: Some(s.principal),
            agent_profile: s.agent_profile,
            command: s.command.clone(),
            prompt_summary: req.prompt_summary.clone().unwrap_or_else(|| {
                format!("Caged session {} (its command is shown to owners)", s.id)
            }),
            tool_calls: s.output_lines.into_iter().take(24).collect(),
            created_at: s.started_at,
            steps: s.provenance_steps,
        })
    } else {
        req.prompt_summary.map(|ps| CapturedProvenance {
            session_id: "manual".to_owned(),
            principal: Some(crate::auth::actor_principal()),
            agent_profile: req
                .delegated_agent
                .clone()
                .unwrap_or_else(|| "human".to_owned()),
            command: "git commit".to_owned(),
            prompt_summary: ps,
            tool_calls: vec![format!("git rev-parse {}", req.branch)],
            created_at: now.clone(),
            steps: Vec::new(),
            sandbox: None,
            bytes_scrubbed: 0,
            exit_code: None,
            egress_calls: 0,
            egress_blocked: 0,
        })
    };

    // As visible as its branch (a review of a bare commit: as the first branch of that name).
    let full_ref = if branch.starts_with("refs/") {
        Some(branch.clone())
    } else {
        crate::branch_full_ref(&state.workspace_root, &req.branch)
    };
    let (visibility, readiness) = full_ref
        .map(|full| {
            let declared = state.branch_metadata().remove(&full);
            declared.unwrap_or((crate::default_ref_visibility(&full), Readiness::Ready))
        })
        .unwrap_or((Visibility::Public, Readiness::Ready));

    let round1 = StoredRoundMeta {
        round: 1,
        commit_oid: oid.clone(),
        base_commit: round1_base,
        session_id: linked_session_id,
        steering_prompt: prompt_summary_orig,
        addressed_comment_ids: Vec::new(),
        rebased_cleanly: true,
        conflicts: Vec::new(),
        provenance: provenance.clone(),
        created_at: now.clone(),
    };

    let review = StoredReview {
        change_id,
        title: req.title,
        branch: req.branch,
        base_ref,
        author: effective_author,
        delegated_agent: req.delegated_agent,
        visibility,
        readiness,
        round_oids: vec![oid],
        comments: vec![],
        verdicts: BTreeMap::new(),
        provenance,
        created_at: now,
        lane_id: linked_lane_id.clone(),
        rounds_meta: vec![round1],
        github_pr_url: None,
        github_pr_number: None,
    };

    if let Ok(mut st) = state.persisted.lock() {
        st.reviews.insert(0, review.clone());
        if let Some(lid) = &linked_lane_id
            && let Some(lane) = st.lanes.iter_mut().find(|l| l.lane_id == *lid)
            && lane.change_id.is_none()
        {
            lane.change_id = Some(review.change_id.clone());
        }
        let _ = save_state(&state.workspace_root, &st);
    }

    let _ = state.review_tx.send(crate::ReviewEvent {
        change_id: review.change_id.clone(),
        visibility: review.visibility.clone(),
        kind: "review_created".to_owned(),
        latest_round: 1,
        lane_id: review.lane_id.clone(),
    });

    // Stored canonical; told to the author as their clone has it.
    let ids = GitIds::of(&state, &identity)?;
    let round_oids = review.round_oids.iter().map(|oid| ids.shown(oid)).collect();
    Ok(Json(StoredReview {
        round_oids,
        ..review
    }))
}

/// Egress `(calls, blocked)` for one already-visible session: its own output lines, and the
/// proxy audit events tagged with exactly this session's task id (never another session's).
fn session_egress_counts(state: &ServerState, s: &AgentSessionRecord) -> (usize, usize) {
    const MARKERS: [&str; 5] = [
        "[egress]",
        "proxy",
        "scrubbed",
        "exfiltration_blocked",
        "blocked",
    ];
    // The header line (`$ cmd # proxy=...`) is not a call.
    let lines: Vec<String> = s
        .output_lines
        .iter()
        .filter(|l| !l.starts_with("$ "))
        .map(|l| l.to_lowercase())
        .collect();
    let line_calls = lines
        .iter()
        .filter(|l| MARKERS.iter().any(|m| l.contains(m)))
        .count();
    let line_blocked = lines.iter().filter(|l| l.contains("blocked")).count();
    let (mut audit_calls, mut audit_blocked) = (0, 0);
    for ev in state.audit_sink.snapshot() {
        if ev.component == "premier-proxy" && ev.agent_task_id.as_deref() == Some(s.id.as_str()) {
            audit_calls += 1;
            if matches!(
                ev.decision,
                AuditDecision::ExfiltrationBlocked
                    | AuditDecision::Denied
                    | AuditDecision::RateLimited
            ) {
                audit_blocked += 1;
            }
        }
    }
    // Both sources can describe the same call, so take the larger rather than summing.
    (line_calls.max(audit_calls), line_blocked.max(audit_blocked))
}

#[derive(Debug, Deserialize)]
pub struct AddCommentRequest {
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub side: Option<String>,
    pub body: String,
    #[serde(default = "default_caller")]
    pub author: String,
    #[serde(default)]
    pub kind: crate::store::CommentKind,
    #[serde(default)]
    pub target_agent: Option<String>,
    #[serde(default)]
    pub steer_session_id: Option<String>,
}

/// Trim an optional label; empty, over 64 chars, or control characters are a 400.
fn clean_label(
    v: Option<String>,
    what: &str,
) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    let Some(raw) = v else { return Ok(None) };
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > 64 || t.chars().any(char::is_control) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("invalid {what}: 1-64 printable characters required"),
        ));
    }
    Ok(Some(t.to_owned()))
}

pub async fn add_review_comment_handler(
    State(state): State<ServerState>,
    AxumPath(change_id): AxumPath<String>,
    Json(req): Json<AddCommentRequest>,
) -> Result<Json<ReviewComment>, (StatusCode, Json<ApiError>)> {
    if req.body.trim().is_empty() {
        return Err(err_resp(StatusCode::BAD_REQUEST, "comment body is empty"));
    }
    if req.body.len() > MAX_REVIEW_TEXT_BYTES {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("comment body exceeds {MAX_REVIEW_TEXT_BYTES} bytes"),
        ));
    }
    if let Some(ref side) = req.side
        && side != "old"
        && side != "new"
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "comment side must be 'old' or 'new'",
        ));
    }
    let target_agent = clean_label(req.target_agent.clone(), "target_agent")?;
    let steer_session_id = clean_label(req.steer_session_id.clone(), "steer_session_id")?;
    if let Some(ref sid) = steer_session_id {
        let valid_session = state
            .session_manager
            .list()
            .into_iter()
            .any(|s| s.id == *sid && may_see_session(&s));
        if !valid_session {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                "unknown or inaccessible steer_session_id",
            ));
        }
    }
    let identity = parse_identity(&state, &req.author, None, "review-comment")?;
    // Fail closed before any review lookup when no policy is loaded (no oracle: same 403 for all).
    let Some(pol) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "cannot comment on restricted path outside caller zone",
        ));
    };
    let rev_branch = review_visible(&state, &identity, &change_id)?;
    // Fail closed: an unparseable path or missing READ on the review's own branch denies comment.
    let readable = RepoPath::new(&req.path).is_ok_and(|rp| {
        pol.explain(&identity, &rp, &rev_branch)
            .allows(Capability::READ)
    });
    if !readable {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "cannot comment on restricted path outside caller zone",
        ));
    }

    let mut comment = ReviewComment {
        id: format!("cmt-{}", Utc::now().timestamp_millis()),
        author: crate::auth::effective_principal(&req.author),
        path: req.path,
        line: req.line,
        side: req.side,
        body: req.body,
        created_at: Utc::now().to_rfc3339(),
        round: None,
        addressed_in_round: None,
        kind: req.kind,
        target_agent,
        steer_session_id,
    };

    let mut event = None;
    if let Ok(mut st) = state.persisted.lock()
        && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == change_id)
    {
        let latest = u32::try_from(rev.round_oids.len().max(1)).unwrap_or(u32::MAX);
        comment.round = Some(latest);
        // Two comments in one millisecond must not share an id (rounds address comments by id).
        while rev.comments.iter().any(|c| c.id == comment.id) {
            comment.id = format!("{}-{}", comment.id, rev.comments.len());
        }
        rev.comments.push(comment.clone());
        event = Some(crate::ReviewEvent {
            change_id: change_id.clone(),
            visibility: rev.visibility.clone(),
            kind: "comment_added".to_owned(),
            latest_round: latest,
            lane_id: rev.lane_id.clone(),
        });
        let _ = save_state(&state.workspace_root, &st);
    }
    let Some(event) = event else {
        return Err(err_resp(StatusCode::NOT_FOUND, "review not found"));
    };
    let _ = state.review_tx.send(event);

    if comment.kind == crate::store::CommentKind::Steer {
        let mut ev = AuditEvent::now(
            &identity,
            "premier-server",
            "review_steer_directive",
            AuditDecision::Allowed,
            format!(
                "Steering directive on review {change_id} for agent '{}'",
                comment.target_agent.as_deref().unwrap_or("unspecified")
            ),
        );
        ev.target = Some(comment.path.clone());
        crate::auth::audit(&state.audit_sink, ev);
    }

    Ok(Json(comment))
}

/// 404 unless review `change_id` exists on a branch `identity` can see: a review of a hidden
/// branch answers exactly like a missing one (AGENTS.md invariant 3). Returns the review's branch.
pub(crate) fn review_visible(
    state: &ServerState,
    identity: &premier_core::DelegatedIdentity,
    change_id: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let not_found = || err_resp(StatusCode::NOT_FOUND, "review not found");
    // The lock is released before `resolve_visible_rev` takes it again.
    let branch = state
        .persisted
        .lock()
        .ok()
        .and_then(|st| {
            let rev = st.reviews.iter().find(|r| r.change_id == change_id)?;
            Some(rev.branch.clone())
        })
        .ok_or_else(not_found)?;
    crate::resolve_accessible_rev(state, identity, &branch).map_err(|_| not_found())?;
    Ok(branch)
}

/// Owners see every caged session; a member only the ones run as them.
pub(crate) fn may_see_session(s: &AgentSessionRecord) -> bool {
    crate::auth::owner_only().is_ok() || s.principal == crate::auth::actor_principal()
}

#[derive(Debug, Deserialize)]
pub struct SetVerdictRequest {
    pub round: u32,
    pub verdict: String,
    #[serde(default = "default_caller")]
    pub principal: String,
}

pub async fn set_review_verdict_handler(
    State(state): State<ServerState>,
    AxumPath(change_id): AxumPath<String>,
    Json(req): Json<SetVerdictRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    if !matches!(
        req.verdict.as_str(),
        "approve" | "request_changes" | "comment" | "pending"
    ) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "verdict must be one of 'approve', 'request_changes', 'comment', or 'pending'",
        ));
    }
    let identity = parse_identity(&state, &req.principal, None, "review-verdict")?;
    review_visible(&state, &identity, &change_id)?;
    let principal = identity.principal.canonical_id();
    let key = format!("r{}:{}", req.round, principal);
    let mut found = false;
    if let Ok(mut st) = state.persisted.lock()
        && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == change_id)
    {
        rev.verdicts.insert(key.clone(), req.verdict.clone());
        found = true;
        let _ = save_state(&state.workspace_root, &st);
    }
    if !found {
        return Err(err_resp(StatusCode::NOT_FOUND, "review not found"));
    }
    Ok(Json(serde_json::json!({
        "ok": true,
        "change_id": change_id,
        "key": key,
        "verdict": req.verdict,
    })))
}

// ---------------------------------------------------------------------------
// 5. Real Encrypted Secret Vault CRUD (NEVER exposes plaintext!) + Overlays
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SecretStatusResponse {
    pub vault_path: String,
    pub entries: BTreeMap<String, SecretMetaEntry>,
}

pub async fn secrets_status_handler(
    State(state): State<ServerState>,
) -> Result<Json<SecretStatusResponse>, (StatusCode, Json<ApiError>)> {
    // Vault metadata has no per-principal view (and names the vault's path on disk).
    crate::auth::owner_only()?;
    let entries = state
        .persisted
        .lock()
        .map(|st| st.secret_meta.clone())
        .unwrap_or_default();
    let vault_path = crate::store::state_dir(&state.workspace_root)
        .join("vault.toml")
        .display()
        .to_string();
    Ok(Json(SecretStatusResponse {
        vault_path,
        entries,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SetSecretRequest {
    pub key: String,
    pub value: String,
    #[serde(default = "default_dev_env")]
    pub env: String,
    #[serde(default = "default_caller")]
    pub principal: String,
}

fn default_dev_env() -> String {
    "dev".to_owned()
}

pub async fn set_secret_handler(
    State(state): State<ServerState>,
    Json(req): Json<SetSecretRequest>,
) -> Result<Json<SecretMetaEntry>, (StatusCode, Json<ApiError>)> {
    if req.key.trim().is_empty() || req.value.is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "secret key and value must be non-empty",
        ));
    }
    let repo_id = state
        .current_env_schema()
        .and_then(|s| s.repo_id.clone())
        .unwrap_or_else(|| "local/repo".to_owned());

    let entry = {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        set_workspace_secret(
            &state.workspace_root,
            &repo_id,
            &req.env,
            req.key.trim(),
            &req.value,
            &mut st,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    let id = parse_identity(&state, &req.principal, None, "secret-set")?;
    let mut ev = AuditEvent::now(
        &id,
        "premier-secrets",
        "secret_rotated",
        AuditDecision::Allowed,
        format!(
            "Encrypted and stored '{}' in age AEAD vault (env={}, rotation #{})",
            req.key.trim(),
            req.env,
            entry.rotated_count
        ),
    );
    ev.capability = Some(req.key.trim().to_owned());
    crate::auth::audit(&state.audit_sink, ev);

    Ok(Json(entry))
}

#[derive(Debug, Deserialize)]
pub struct DeleteSecretQuery {
    #[serde(default = "default_dev_env")]
    pub env: String,
    #[serde(default = "default_caller")]
    pub principal: String,
}

pub async fn delete_secret_handler(
    State(state): State<ServerState>,
    AxumPath(key): AxumPath<String>,
    Query(q): Query<DeleteSecretQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let repo_id = state
        .current_env_schema()
        .and_then(|s| s.repo_id.clone())
        .unwrap_or_else(|| "local/repo".to_owned());

    {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        delete_workspace_secret(&state.workspace_root, &repo_id, &q.env, &key, &mut st)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    let id = parse_identity(&state, &q.principal, None, "secret-revoke")?;
    let mut ev = AuditEvent::now(
        &id,
        "premier-secrets",
        "secret_revoked",
        AuditDecision::Allowed,
        format!("Revoked and purged '{}' from local age AEAD vault", key),
    );
    ev.capability = Some(key.clone());
    crate::auth::audit(&state.audit_sink, ev);

    Ok(Json(serde_json::json!({ "ok": true, "revoked": key })))
}

#[derive(Debug, Deserialize)]
pub struct MountOverlayRequest {
    pub path: String,
    pub scope: String, // "personal" or "team:<name>"
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub create_file: bool,
    #[serde(default)]
    pub initial_content: Option<String>,
    /// Whose personal overlay: an owner's "view as" claim, else the caller.
    #[serde(default)]
    pub principal: Option<String>,
}

/// The principal an overlay request acts as: a claim only stands for an owner in a browser.
fn overlay_actor(claimed: Option<&str>) -> String {
    claimed
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map_or_else(
            crate::auth::actor_principal,
            crate::auth::effective_principal,
        )
}

/// Record the stored overlays in the persisted manifest too, so every push and write guard
/// (including those that read only `st.overlays`) excludes them at once.
fn sync_recorded_overlays(
    state: &ServerState,
    drop_path: Option<&str>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let stored = crate::overlay_store(&state.workspace_root)
        .and_then(|s| s.to_manifest())
        .map_err(crate::overlay_err)?;
    let mut st = state
        .persisted
        .lock()
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(path) = drop_path {
        st.overlays.entries.retain(|e| e.path != path);
    }
    // A stored overlay re-mounted with another `encrypted` flag replaces its old entry.
    st.overlays.entries.retain(|e| {
        !stored
            .entries
            .iter()
            .any(|s| s.kind == e.kind && s.path == e.path && s != e)
    });
    for entry in stored.entries {
        if !st.overlays.entries.contains(&entry) {
            st.overlays.entries.push(entry);
        }
    }
    save_state(&state.workspace_root, &st)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))
}

/// Mount a personal or team overlay. Its content (if any) goes to the encrypted overlay store
/// under the server's state directory, never into the working tree.
pub async fn mount_overlay_handler(
    State(state): State<ServerState>,
    Json(req): Json<MountOverlayRequest>,
) -> Result<Json<premier_overlay::OverlayListResponse>, (StatusCode, Json<ApiError>)> {
    let p = req.path.trim();
    let invalid = || err_resp(StatusCode::BAD_REQUEST, "invalid overlay path");
    // A repository-relative path or glob: never absolute, a drive, or a filesystem alias.
    let rp = RepoPath::new(p).map_err(|_| invalid())?;
    if rp.is_root() || is_internal_path(&state.workspace_root, p) {
        return Err(invalid());
    }
    let kind = if let Some(team) = req.scope.strip_prefix("team:") {
        OverlayKind::Team(team.trim().to_owned())
    } else {
        OverlayKind::Personal
    };
    // Validate the overlay glob BEFORE storing anything or mutating persisted state.
    OverlayGuard::from_manifest(&premier_overlay::OverlayManifest {
        version: 1,
        entries: vec![OverlayEntry {
            kind: kind.clone(),
            path: p.to_owned(),
            encrypted: req.encrypted,
        }],
    })
    .map_err(|e| {
        err_resp(
            StatusCode::BAD_REQUEST,
            format!("invalid overlay glob: {e}"),
        )
    })?;

    let is_glob = p.contains(['*', '?', '[', ']', '{', '}']);
    let wants_content = !is_glob && (req.create_file || req.initial_content.is_some());
    if wants_content {
        // The file that name would really open: inside the workspace, not through a symlink,
        // and not server state under another spelling. Nothing is written there.
        let (_, canonical) =
            crate::working_tree_path(&state.workspace_root, &rp).ok_or_else(invalid)?;
        if is_internal_path(&state.workspace_root, canonical.as_str()) {
            return Err(invalid());
        }
    }
    let payload = wants_content.then(|| {
        req.initial_content
            .unwrap_or_else(|| {
                format!("# Premier Overlay ({p})\n# Excluded from public pushes by OverlayGuard.\n")
            })
            .into_bytes()
    });

    let principal = overlay_actor(req.principal.as_deref());
    let team_group = match &kind {
        OverlayKind::Team(t) => Some(t.clone()),
        OverlayKind::Personal => None,
    };
    crate::overlay_store(&state.workspace_root)
        .and_then(|store| {
            store.mount(premier_overlay::MountOverlayInput {
                kind,
                path: p.to_owned(),
                owner_principal: Some(principal.clone()),
                team_group,
                encrypted: req.encrypted,
                payload,
            })
        })
        .map_err(crate::overlay_err)?;
    sync_recorded_overlays(&state, None)?;
    Ok(Json(crate::overlay_list_for(&state, Some(&principal))?))
}

#[derive(Debug, Deserialize)]
pub struct UnmountOverlayRequest {
    pub path: String,
    #[serde(default)]
    pub principal: Option<String>,
}

/// Unmount the caller's personal overlay at `path` (else the team overlays there) and delete its
/// stored content. Someone else's personal overlay is refused with 403.
pub async fn unmount_overlay_handler(
    State(state): State<ServerState>,
    Json(req): Json<UnmountOverlayRequest>,
) -> Result<Json<premier_overlay::OverlayListResponse>, (StatusCode, Json<ApiError>)> {
    let path = req.path.trim();
    let principal = overlay_actor(req.principal.as_deref());
    crate::overlay_store(&state.workspace_root)
        .and_then(|store| store.unmount(path, &principal))
        .map_err(crate::overlay_err)?;
    sync_recorded_overlays(&state, Some(path))?;
    Ok(Json(crate::overlay_list_for(&state, Some(&principal))?))
}

// ---------------------------------------------------------------------------
// 6. Live Agent Cage Session Runner Endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SpawnSessionRequest {
    pub command: String,
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default = "default_dev_env")]
    pub env: String,
    /// Seconds the session may run before it is killed: default 30 minutes, at most 4 hours.
    #[serde(default)]
    pub max_secs: Option<u64>,
    /// The branch whose files the session works on: default, the checked-out one.
    #[serde(default)]
    pub branch: Option<String>,
    /// Autonomy budget for this session; it can only tighten the agent profile's.
    #[serde(default)]
    pub budget: Option<premier_policy::AutonomyBudget>,
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub parent_lane_id: Option<String>,
    #[serde(default)]
    pub change_id: Option<String>,
}

pub async fn list_sessions_handler(
    State(state): State<ServerState>,
) -> Json<Vec<AgentSessionRecord>> {
    let mut sessions = state.session_manager.list();
    sessions.retain(may_see_session);
    if !crate::auth::caller_is_owner() {
        // A member's own sessions, with commits translated to her clone and conflicts/provenance
        // strictly ACL-filtered on each session's branch.
        let me = parse_identity(&state, &default_caller(), None, "sessions").ok();
        let ids = me.as_ref().and_then(|me| GitIds::of(&state, me).ok());
        let policy = state.current_policy();
        for session in &mut sessions {
            for oid in [&mut session.base_commit, &mut session.commit] {
                let shown = oid.take().zip(ids.as_ref()).map(|(c, ids)| ids.shown(&c));
                *oid = shown.filter(|c| !c.is_empty());
            }
            if let Some(ref viewer) = me {
                session.conflicts = crate::lanes::filter_conflicts_for_viewer(
                    policy.as_deref(),
                    viewer,
                    &session.branch,
                    &session.conflicts,
                );
                session.provenance_steps = crate::lanes::filter_steps_for_viewer(
                    policy.as_deref(),
                    viewer,
                    &session.branch,
                    &session.provenance_steps,
                );
            } else {
                session.conflicts.clear();
                session.provenance_steps.clear();
            }
            session.redact_for_member();
        }
    }
    Json(sessions)
}

pub async fn spawn_session_handler(
    State(state): State<ServerState>,
    Json(req): Json<SpawnSessionRequest>,
) -> Result<Json<AgentSessionRecord>, (StatusCode, Json<ApiError>)> {
    if req.command.trim().is_empty() {
        return Err(err_resp(StatusCode::BAD_REQUEST, "command cannot be empty"));
    }
    // A profile narrows the human identity and must be one the policy declares (an unknown one
    // would deny everything: an empty workspace and a command that fails for no visible
    // reason). Without one the session has the human identity alone.
    let prof = req.agent_profile.filter(|s| !s.trim().is_empty());
    if let Some(name) = &prof
        && !state
            .current_policy()
            .is_some_and(|p| p.has_agent_profile(name))
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("agent profile '{name}' is not defined in this repository's policy"),
        ));
    }
    let identity = parse_identity(&state, &req.principal, prof, "live-cage")?;
    if let premier_core::Principal::User(ref uname) = identity.principal
        && state.auth.is_user_disabled(uname)
    {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            format!("principal '@{uname}' is disabled and cannot start agent sessions"),
        ));
    }
    // A shell is only handed out inside a sandbox (or where the operator accepted none).
    let mode = crate::runner::sandbox_mode(state.allow_unsandboxed_agents);
    if mode == crate::runner::SandboxMode::None {
        return Err(err_resp(
            StatusCode::NOT_IMPLEMENTED,
            crate::runner::NO_SANDBOX,
        ));
    }
    let cage = crate::runner::Cage {
        mode,
        hidden: [
            Some(state.account_root().to_path_buf()),
            state.repos_dir.clone(),
            crate::store::state_root(&state.workspace_root),
        ]
        .into_iter()
        .flatten()
        .collect(),
    };
    let lane_id = req
        .lane_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let parent_lane_id = req
        .parent_lane_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let change_id = req
        .change_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    for candidate in lane_id.iter().chain(parent_lane_id.iter()) {
        if !crate::runner::valid_lane_id(candidate) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "invalid lane id"));
        }
    }

    let (base_commit_override, inherited_branch) = {
        let root = &state.workspace_root;
        let st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(lid) = &lane_id
            && let Some(lane) = st.lanes.iter().find(|l| l.lane_id == *lid)
        {
            let oid = lane
                .tip_oid
                .clone()
                .or_else(|| crate::canon::tip_of(root, &lane.lane_ref));
            (oid, Some(lane.base_branch.clone()))
        } else if let Some(pid) = &parent_lane_id {
            let parent = st
                .lanes
                .iter()
                .find(|l| l.lane_id == *pid)
                .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "parent lane not found"))?;
            let oid = parent
                .tip_oid
                .clone()
                .or_else(|| crate::canon::tip_of(root, &parent.lane_ref));
            (oid, Some(parent.base_branch.clone()))
        } else {
            (None, None)
        }
    };

    // The session works on a private copy of what its identity may read on this branch (a
    // branch it cannot see answers like a missing one), never in the repository itself.
    let branch = req
        .branch
        .filter(|b| !b.trim().is_empty())
        .or(inherited_branch)
        .unwrap_or_else(|| crate::checked_out(&state.workspace_root).0);
    let full_ref =
        crate::content_source(&state, &identity, &branch)?.filter(|full| full.starts_with("refs/"));
    // The workspace is the identity's projection of the branch (`runner::materialise`, the same
    // cached view): a branch that shows it no file is not in it, and there is nothing to run in.
    if let (Some(base_oid), Some(policy)) = (&base_commit_override, state.current_policy()) {
        let canonical = CanonicalGitRepo::open(&state.workspace_root);
        let projected = premier_git_bridge::project_commit_tree_for_workspace(
            &canonical, &policy, &identity, &branch, base_oid,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if projected.is_none() {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!(
                    "{} can read nothing on branch '{branch}': there is no workspace to run in",
                    identity.principal.canonical_id()
                ),
            ));
        }
    } else if let (Some(full), Some(policy)) = (&full_ref, state.current_policy()) {
        let canonical = CanonicalGitRepo::open(&state.workspace_root);
        let visibility = state.branch_visibility_map();
        let view = project_repository(&canonical, &policy, "agent-session", &identity, &visibility)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !view.ref_sources.values().any(|(source, _)| source == full) {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!(
                    "{} can read nothing on branch '{branch}': there is no workspace to run in",
                    identity.principal.canonical_id()
                ),
            ));
        }
    }

    let rec = state
        .session_manager
        .spawn_session(crate::runner::SessionRequest {
            workspace_root: state.workspace_root.clone(),
            identity,
            env_name: req.env,
            command: req.command,
            branch,
            full_ref,
            ref_visibility: state.branch_visibility_map(),
            policy: state.current_policy(),
            schema: state.current_env_schema(),
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage,
            limit: crate::runner::session_limit(req.max_secs),
            quarantine_approvals: crate::firewall::approved_instruction_entries(&state),
            budget: req.budget,
            base_commit_override,
            lane_id,
            change_id,
            steering_packet: None,
            on_complete: None,
        })
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(rec))
}

// ---------------------------------------------------------------------------
// 7. Reversible Smart HTTP `git-receive-pack` (`git push`) + Unified `info/refs`
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GitInfoRefsQuery {
    #[serde(default)]
    pub service: Option<String>,
}

pub async fn git_info_refs_v2_handler(
    State(state): State<ServerState>,
    Extension(GitCaller(identity)): Extension<GitCaller>,
    Query(q): Query<GitInfoRefsQuery>,
) -> Response {
    if q.service.as_deref() == Some("git-receive-pack") {
        let Some(policy) = state.current_policy() else {
            return (StatusCode::SERVICE_UNAVAILABLE, "no policy loaded").into_response();
        };
        let root = state.workspace_root.clone();
        let fp_short = state.policy_fingerprint();
        let vis_map = state.branch_visibility_map();
        let body = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root);
            let view = project_repository(&canonical, &policy, &fp_short, &identity, &vis_map)?;
            Ok::<_, premier_git_bridge::GitBridgeError>(render_receive_pack_refs(&view))
        })
        .await;

        return match body {
            Ok(Ok(bytes)) => (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "application/x-git-receive-pack-advertisement",
                )],
                bytes,
            )
                .into_response(),
            Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    let body = render_info_refs_v2();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-advertisement",
        )],
        body,
    )
        .into_response()
}

/// Push requests admitted at once, process-wide (every repository shares it). A push takes a slot
/// before its body is read, so one waiting its turn holds none of it.
pub(crate) static PUSH_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(premier_git_bridge::MAX_CONCURRENT_PUSHES);
const PUSH_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn git_receive_pack_handler(
    State(state): State<ServerState>,
    Extension(GitCaller(identity)): Extension<GitCaller>,
    // The path the client used (`/git/<name>.git/…`, `/r/<name>/…`), not the dispatched one.
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    body: axum::body::Body,
) -> Response {
    let Some(policy) = state.current_policy() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no policy loaded").into_response();
    };
    // The gate checked the credentials; the slot comes next, the body last.
    let Ok(Ok(_slot)) = tokio::time::timeout(PUSH_QUEUE_WAIT, PUSH_SLOTS.acquire()).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "server busy: retry the push in a moment",
        )
            .into_response();
    };
    // shortcut: the bridge parses the pack as one slice, so an admitted push still buffers its
    // body in memory (at most GIT_BODY_LIMIT x PUSH_SLOTS); feed the parser from a file if needed.
    let body = match axum::body::to_bytes(body, crate::ops::GIT_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "push body too large or interrupted",
            )
                .into_response();
        }
    };
    let root = state.workspace_root.clone();
    let fp_short = state.policy_fingerprint();
    let vis_map: HashMap<String, Visibility> = state.branch_visibility_map();
    let overlay_manifest = match crate::overlay_manifest(&state) {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let overlay_guard = match OverlayGuard::from_manifest(&overlay_manifest) {
        Ok(g) => g,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let identity_bg = identity.clone();
    let body_bg = body.clone();
    let state_bg = state.clone();
    // Decides the visibility of a branch this push creates, and who may push policy changes.
    let is_owner = identity.matches_selector(&format!("group:{}", crate::directory::OWNERS_GROUP));
    let vault = crate::firewall::build_vault_secret_index(&state);
    let approved = crate::firewall::approved_instruction_map(&state);
    let audit_bg = state.audit_sink.clone();

    let res = tokio::task::spawn_blocking(move || {
        let canonical = CanonicalGitRepo::open(&root);
        // No default branch (detached `HEAD`): the config-file protection below has no ref to
        // guard, so this push is judged under the built-in owner-only policy, which lets nobody
        // but an owner write anything, on any ref. Fails closed if that cannot be compiled.
        let policy = if crate::canon::default_ref(&root).is_some() {
            policy
        } else {
            state_bg
                .builtin_policy()
                .map_err(premier_git_bridge::GitBridgeError::Io)?
        };
        let view = project_repository(&canonical, &policy, &fp_short, &identity_bg, &vis_map)?;
        // A push that changes the default branch's policy or schema is the server's to judge.
        let before = crate::canon::DefaultTip::capture(&root);
        let default_ref = crate::canon::default_ref(&root).unwrap_or_default();
        let check = |name: &str, content: Option<&[u8]>| {
            state_bg.check_config_change(is_owner, name, content)
        };
        let protected = premier_git_bridge::ProtectedFiles {
            full_ref: &default_ref,
            names: &crate::canon::CONFIG_FILES,
            check: &check,
        };
        let on_blocked = |ref_name: &str, report: &premier_policy::DeclassificationReport| {
            crate::firewall::record_firewall_audit(
                &audit_bg,
                &identity_bg,
                "git_push",
                ref_name,
                report,
            );
        };
        let firewall = premier_git_bridge::ReceivePackFirewall {
            vault: vault.as_ref(),
            approved_instructions: &approved,
            on_blocked: Some(&on_blocked),
        };
        let res = handle_receive_pack_with_firewall(
            &canonical,
            &view,
            &policy,
            &overlay_guard,
            &identity_bg,
            is_owner,
            Some(&protected),
            Some(&firewall),
            &body_bg,
        );
        // Accepted or not: if the default branch moved, the working tree and the live policy follow.
        state_bg.default_branch_moved(before);
        res
    })
    .await;

    match res {
        Ok(Ok(pack_res)) => {
            // A branch the push created gets the visibility the bridge chose for it, and every
            // accepted update is attributed to the account that pushed it: the author and
            // committer inside the commits are only what the pusher claimed.
            if let Ok(mut st) = state.persisted.lock() {
                const ZERO_OID: &str = "0000000000000000000000000000000000000000";
                let mut changed = false;
                for update in &pack_res.accepted {
                    if update.canonical_new == ZERO_OID {
                        if st.branch_metadata.remove(&update.canonical_ref).is_some() {
                            changed = true;
                        }
                        if let Some(short) = crate::ref_short(&update.canonical_ref)
                            && st.branch_metadata.remove(short).is_some()
                        {
                            changed = true;
                        }
                    } else if let Some(visibility) = &update.created_visibility {
                        st.branch_metadata.insert(
                            update.canonical_ref.clone(),
                            (visibility.clone(), Readiness::Ready),
                        );
                        changed = true;
                    }
                }
                if changed {
                    let _ = save_state(&state.workspace_root, &st);
                }
            }
            for update in &pack_res.accepted {
                let mut ev = AuditEvent::now(
                    &identity,
                    "premier-git-bridge",
                    "git_ref_update",
                    AuditDecision::Allowed,
                    format!(
                        "pushed by {}: {} {}..{} ({})",
                        update.pusher,
                        update.canonical_ref,
                        update.canonical_old,
                        update.canonical_new,
                        premier_git_bridge::plural(update.commits, "commit")
                    ),
                );
                ev.target = Some(update.canonical_ref.clone());
                crate::auth::audit(&state.audit_sink, ev);
            }
            let decision = if pack_res.rejected_refs.is_empty() {
                AuditDecision::Allowed
            } else {
                AuditDecision::Denied
            };
            let mut ev = AuditEvent::now(
                &identity,
                "premier-git-bridge",
                "git_receive_pack",
                decision,
                format!(
                    "Reversible git push by {}: {} updated, {} rejected",
                    identity.principal,
                    pack_res.updated_refs.len(),
                    pack_res.rejected_refs.len()
                ),
            );
            ev.target = Some(uri.path().to_owned());
            crate::auth::audit(&state.audit_sink, ev);

            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "application/x-git-receive-pack-result",
                )],
                pack_res.response_bytes,
            )
                .into_response()
        }
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
