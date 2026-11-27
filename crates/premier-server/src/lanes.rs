//! Agent lanes, conflict resolution, round-to-round interdiffs, closed-loop executable review
//! steering, and ACL-sanitized provenance endpoints.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use premier_core::{
    AuditDecision, AuditEvent, Capability, DelegatedIdentity, RepoPath, Visibility,
};
use premier_git_bridge::{
    CanonicalGitRepo, GitBridgeError, LANE_REF_PREFIX, LaneConflict, LaneFileChange,
    compute_commit_interdiff, create_lane_snapshot_commit, diff_commits_to_changes,
    execute_three_way_rebase, git_command, is_reserved_path_component, plan_three_way_rebase,
    project_commit_tree_for_workspace,
};
use premier_policy::{CompiledPolicy, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::runner::{
    AgentSessionRecord, CommitReviewExtra, CommitSessionRequest, SessionCompleteHook,
    SteeringComment, SteeringPacket,
};
use crate::store::{AgentLane, CapturedProvenance, ProvenanceStep, StoredRoundMeta, save_state};
use crate::{ApiError, GitIds, ReviewEvent, ServerState, auth, canon, directory, err_resp};

type ApiErr = (StatusCode, Json<ApiError>);

fn default_caller() -> String {
    auth::actor_principal()
}

fn default_true() -> bool {
    true
}

fn non_empty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn author_line_now(state: &ServerState) -> String {
    let (name, email) = canon::committer(state);
    format!(
        "{} <{email}> {} +0000",
        name.replace(['<', '>', '\n', '\r'], ""),
        Utc::now().timestamp()
    )
}

fn short_oid(oid: &str) -> &str {
    &oid[..oid.len().min(12)]
}

/// Read the exact `(mode, bytes)` of `path` in `rev`'s tree, or `None` when absent or a directory.
fn read_tree_entry(
    canonical: &CanonicalGitRepo,
    rev: Option<&str>,
    path: &str,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let Some(rev) = rev else {
        return Ok(None);
    };
    let out = git_command(canonical.root())
        .args(["ls-tree", "-z", "--end-of-options", rev, "--", path])
        .output()
        .map_err(|e| format!("git ls-tree failed: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(record) = text.split('\0').find(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let Some((meta, _)) = record.split_once('\t') else {
        return Ok(None);
    };
    let mut parts = meta.split(' ');
    let (Some(mode), Some(kind), Some(oid)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(None);
    };
    if kind == "tree" {
        return Ok(None);
    }
    if mode == "160000" {
        return Ok(Some((mode.to_owned(), oid.as_bytes().to_vec())));
    }
    let obj = canonical
        .read_object(oid)
        .map_err(|e| format!("read blob {oid}: {e}"))?;
    Ok(Some((mode.to_owned(), obj.data.to_vec())))
}

fn tree_path_set(root: &Path, rev: Option<&str>) -> HashSet<String> {
    rev.and_then(|r| crate::repos::git_out(root, &["ls-tree", "-r", "--name-only", "-z", r]))
        .map(|out| {
            out.split('\0')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_onto_oid(root: &Path, onto: &str) -> Result<String, String> {
    let lane_candidate = format!("{LANE_REF_PREFIX}{onto}");
    if let Some(oid) = canon::tip_of(root, &lane_candidate) {
        return Ok(oid);
    }
    crate::handlers_v1::resolve_branch_oid(root, onto)
}

fn first_parent(root: &Path, oid: &str) -> Option<String> {
    crate::repos::git_out(root, &["rev-parse", "-q", "--verify", &format!("{oid}^")])
}

fn is_ancestor(root: &Path, ancestor: &str, descendant: &str) -> bool {
    git_command(root)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------
// 1. ACL & Viewer Sanitization Helpers
// ---------------------------------------------------------------------------

/// Filter `conflicts` strictly by the viewer's `LIST` / `READ` capabilities on `branch`.
/// Fails closed when no policy is loaded or a path cannot be parsed.
pub(crate) fn filter_conflicts_for_viewer(
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    branch: &str,
    conflicts: &[LaneConflict],
) -> Vec<LaneConflict> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in conflicts {
        let Ok(rp) = RepoPath::new(&c.path) else {
            continue;
        };
        let dec = policy.explain(identity, &rp, branch);
        if !dec.allows(Capability::LIST) {
            continue;
        }
        if !dec.allows(Capability::READ) {
            out.push(LaneConflict {
                path: c.path.clone(),
                kind: c.kind.clone(),
                summary: "Restricted conflict (caller lacks READ)".to_owned(),
                hunks: Vec::new(),
                allowed: false,
            });
        } else {
            let mut full = c.clone();
            full.allowed = true;
            out.push(full);
        }
    }
    out
}

/// Filter session provenance steps strictly by authentication and per-path ACLs on `branch`.
pub(crate) fn filter_steps_for_viewer(
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    branch: &str,
    steps: &[ProvenanceStep],
) -> Vec<ProvenanceStep> {
    if !identity.principal.is_authenticated() {
        return Vec::new();
    }
    let is_owner = auth::caller_is_owner();
    let mut out = Vec::new();
    for s in steps {
        let mut step = s.clone();
        if let Some(p) = &s.path {
            let Some(pol) = policy else {
                continue;
            };
            let Ok(rp) = RepoPath::new(p) else {
                continue;
            };
            let dec = pol.explain(identity, &rp, branch);
            if !dec.allows(Capability::LIST) {
                continue;
            }
            if !dec.allows(Capability::READ) {
                step.summary = "[redacted path]".to_owned();
            }
        }
        if !is_owner {
            if step.kind == "lane_conflict" {
                step.summary = "Conflict captured on lane".to_owned();
                step.target = None;
            }
            // Free text that may name (or print) files the viewer may not list.
            if step.kind == "command_exec" {
                step.summary = "Command run (shown to owners only)".to_owned();
            }
            // Merged paths are not filtered per viewer, and canonical commit ids are not hers.
            if let Some(at) = step.summary.find("; merged ") {
                step.summary.truncate(at);
            }
            step.summary = scrub_commit_ids(&step.summary);
            step.target = step.target.as_deref().map(scrub_commit_ids);
        }
        out.push(step);
    }
    out
}

/// `text` with every run of 7+ hex characters that holds a digit (a commit id) replaced by `…`.
fn scrub_commit_ids(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        let is_oid = word.len() >= 7
            && word.bytes().all(|b| b.is_ascii_hexdigit())
            && word.bytes().any(|b| b.is_ascii_digit());
        out.push_str(if is_oid { "…" } else { word.as_str() });
        word.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Whether `identity` is allowed to know that `lane` exists.
pub(crate) fn lane_visible_to(
    state: &ServerState,
    identity: &DelegatedIdentity,
    lane: &AgentLane,
) -> bool {
    if auth::caller_is_owner() {
        return true;
    }
    premier_git_bridge::can_see_ref(identity, &lane.visibility)
        && crate::resolve_accessible_rev(state, identity, &lane.base_branch).is_ok()
}

/// Sanitize a lane record for the current viewer (filtering conflicts and translating commit OIDs
/// for non-owners so raw canonical OIDs and unauthorized paths never leak).
pub(crate) fn sanitize_lane_for_viewer(
    state: &ServerState,
    identity: &DelegatedIdentity,
    ids: &GitIds,
    lane: &AgentLane,
) -> AgentLane {
    let mut out = lane.clone();
    if !auth::caller_is_owner() {
        out.conflicts = filter_conflicts_for_viewer(
            state.current_policy().as_deref(),
            identity,
            &lane.base_branch,
            &lane.conflicts,
        );
        out.base_commit = out
            .base_commit
            .map(|oid| ids.shown(&oid))
            .filter(|s| !s.is_empty());
        out.tip_oid = out
            .tip_oid
            .map(|oid| ids.shown(&oid))
            .filter(|s| !s.is_empty());
    }
    out
}

// ---------------------------------------------------------------------------
// 2. Lane CRUD, Rebase & Conflict Resolution Handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LanesQuery {
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
}

/// `GET /v1/lanes`: list all lanes visible to the viewer.
pub async fn list_lanes_handler(
    State(state): State<ServerState>,
    Query(q): Query<LanesQuery>,
) -> Result<Json<Vec<AgentLane>>, ApiErr> {
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "lanes-list")?;
    let ids = GitIds::of(&state, &identity)?;
    let lanes = state
        .persisted
        .lock()
        .map(|st| st.lanes.clone())
        .unwrap_or_default();
    let visible = lanes
        .iter()
        .filter(|lane| lane_visible_to(&state, &identity, lane))
        .map(|lane| sanitize_lane_for_viewer(&state, &identity, &ids, lane))
        .collect();
    Ok(Json(visible))
}

/// `GET /v1/lanes/{lane_id}`: fetch one lane visible to the viewer.
pub async fn get_lane_handler(
    State(state): State<ServerState>,
    AxumPath(lane_id): AxumPath<String>,
    Query(q): Query<LanesQuery>,
) -> Result<Json<AgentLane>, ApiErr> {
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "lane-get")?;
    let ids = GitIds::of(&state, &identity)?;
    let lane = state
        .persisted
        .lock()
        .ok()
        .and_then(|st| st.lanes.iter().find(|l| l.lane_id == lane_id).cloned())
        .filter(|l| lane_visible_to(&state, &identity, l))
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "lane not found"))?;
    Ok(Json(sanitize_lane_for_viewer(
        &state, &identity, &ids, &lane,
    )))
}

#[derive(Debug, Deserialize)]
pub struct CreateLaneRequest {
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub base_branch: Option<String>,
    #[serde(default)]
    pub parent_lane_id: Option<String>,
    #[serde(default)]
    pub change_id: Option<String>,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default)]
    pub visibility: Option<Visibility>,
}

/// `POST /v1/lanes`: create a new agent lane (owner-only).
pub async fn create_lane_handler(
    State(state): State<ServerState>,
    Json(req): Json<CreateLaneRequest>,
) -> Result<Json<AgentLane>, ApiErr> {
    let root = state.workspace_root.clone();
    let owner = auth::actor_principal();
    let lane_id = match req
        .lane_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(id) => id.to_owned(),
        None => {
            let seed = format!(
                "{}:{}:{}",
                owner,
                Utc::now().timestamp_nanos_opt().unwrap_or(0),
                req.base_branch.as_deref().unwrap_or("")
            );
            format!("lane-{}", &sha256_hex(seed.as_bytes())[..10])
        }
    };
    if !crate::runner::valid_lane_id(&lane_id) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid lane id"));
    }

    let agent_profile = req
        .agent_profile
        .as_deref()
        .and_then(non_empty)
        .unwrap_or_default();
    if !agent_profile.is_empty()
        && !state
            .current_policy()
            .is_some_and(|p| p.has_agent_profile(&agent_profile))
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("agent profile '{agent_profile}' is not defined in this repository's policy"),
        ));
    }

    let parent_lane_id = req.parent_lane_id.as_deref().and_then(non_empty);
    let change_id = req.change_id.as_deref().and_then(non_empty);
    if parent_lane_id.as_deref() == Some(lane_id.as_str()) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "lane cannot be its own parent",
        ));
    }

    let (base_branch, visibility, start_oid) = {
        let st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if st.lanes.iter().any(|l| l.lane_id == lane_id) {
            return Err(err_resp(StatusCode::CONFLICT, "lane already exists"));
        }
        if let Some(cid) = &change_id
            && !st.reviews.iter().any(|r| r.change_id == *cid)
        {
            return Err(err_resp(StatusCode::NOT_FOUND, "review not found"));
        }
        if let Some(pid) = &parent_lane_id {
            let parent = st
                .lanes
                .iter()
                .find(|l| l.lane_id == *pid)
                .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "parent lane not found"))?;
            if parent.status == "discarded" {
                return Err(err_resp(
                    StatusCode::CONFLICT,
                    "parent lane has been discarded",
                ));
            }
            // Guard against cycles in existing parent links.
            let mut visited = HashSet::from([lane_id.as_str()]);
            let mut cursor = Some(parent);
            while let Some(cur) = cursor {
                if !visited.insert(cur.lane_id.as_str()) {
                    return Err(err_resp(
                        StatusCode::BAD_REQUEST,
                        "parent lane chain contains a cycle",
                    ));
                }
                cursor = cur
                    .parent_lane_id
                    .as_deref()
                    .and_then(|next| st.lanes.iter().find(|l| l.lane_id == next));
            }
            let base_branch = req
                .base_branch
                .as_deref()
                .and_then(non_empty)
                .unwrap_or_else(|| parent.base_branch.clone());
            let visibility = req
                .visibility
                .clone()
                .unwrap_or_else(|| parent.visibility.clone());
            let start_oid = parent
                .tip_oid
                .clone()
                .or_else(|| canon::tip_of(&root, &parent.lane_ref))
                .or_else(|| parent.base_commit.clone());
            (base_branch, visibility, start_oid)
        } else {
            let base_branch = req
                .base_branch
                .as_deref()
                .and_then(non_empty)
                .unwrap_or_else(|| crate::default_branch(&root));
            let full_ref = crate::branch_full_ref(&root, &base_branch)
                .unwrap_or_else(|| format!("refs/heads/{base_branch}"));
            let start_oid = canon::tip_of(&root, &full_ref);
            drop(st);
            let visibility = req
                .visibility
                .clone()
                .unwrap_or_else(|| state.ref_visibility(&full_ref));
            (base_branch, visibility, start_oid)
        }
    };

    let lane_ref = format!("{LANE_REF_PREFIX}{lane_id}");
    if let Some(oid) = start_oid.clone() {
        let (root_bg, lane_ref_bg) = (root.clone(), lane_ref.clone());
        tokio::task::spawn_blocking(move || {
            CanonicalGitRepo::open(&root_bg).update_ref(&lane_ref_bg, &oid)
        })
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let now = Utc::now().to_rfc3339();
    let lane = AgentLane {
        lane_id: lane_id.clone(),
        lane_ref,
        base_branch,
        parent_lane_id,
        change_id: change_id.clone(),
        base_commit: start_oid.clone(),
        tip_oid: start_oid,
        owner,
        agent_profile,
        visibility,
        status: "active".to_owned(),
        conflicts: Vec::new(),
        last_session_id: None,
        created_at: now.clone(),
        updated_at: now,
    };

    {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if st.lanes.iter().any(|l| l.lane_id == lane.lane_id) {
            return Err(err_resp(StatusCode::CONFLICT, "lane already exists"));
        }
        st.lanes.push(lane.clone());
        if let Some(cid) = &change_id
            && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == *cid)
        {
            rev.lane_id = Some(lane.lane_id.clone());
        }
        let _ = save_state(&state.workspace_root, &st);
    }

    let _ = state.lane_tx.send(lane.clone());
    Ok(Json(lane))
}

#[derive(Debug, Default, Deserialize)]
pub struct RebaseLaneRequest {
    #[serde(default)]
    pub onto_ref: Option<String>,
    #[serde(default)]
    pub cascade: bool,
}

#[derive(Debug, Serialize)]
pub struct LaneRebaseResponse {
    pub lane: AgentLane,
    pub rebased: bool,
    pub merged_paths: Vec<String>,
    pub conflicts: Vec<LaneConflict>,
    pub cascaded_lanes: Vec<AgentLane>,
}

async fn rebase_one_lane(
    state: &ServerState,
    lane_id: &str,
    onto_ref: Option<&str>,
) -> Result<(AgentLane, bool, Vec<String>, Vec<LaneConflict>), ApiErr> {
    let root = state.workspace_root.clone();
    let (lane, parent_lane) = {
        let st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let lane = st
            .lanes
            .iter()
            .find(|l| l.lane_id == lane_id)
            .cloned()
            .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "lane not found"))?;
        let parent = lane
            .parent_lane_id
            .as_deref()
            .and_then(|pid| st.lanes.iter().find(|l| l.lane_id == pid).cloned());
        (lane, parent)
    };

    let target_oid = if let Some(onto) = onto_ref.and_then(non_empty) {
        let root_bg = root.clone();
        let oid = tokio::task::spawn_blocking(move || resolve_onto_oid(&root_bg, &onto))
            .await
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| err_resp(StatusCode::NOT_FOUND, e))?;
        Some(oid)
    } else if lane.parent_lane_id.is_some() {
        let parent =
            parent_lane.ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "parent lane not found"))?;
        parent
            .tip_oid
            .clone()
            .or_else(|| canon::tip_of(&root, &parent.lane_ref))
            .or_else(|| parent.base_commit.clone())
    } else {
        let full_ref = crate::branch_full_ref(&root, &lane.base_branch)
            .unwrap_or_else(|| format!("refs/heads/{}", lane.base_branch));
        canon::tip_of(&root, &full_ref)
    };

    let lane_identity = directory::identity(
        state,
        &lane.owner,
        non_empty(&lane.agent_profile),
        "lane-rebase",
    )?;
    let policy = state.current_policy();
    let author_line = author_line_now(state);

    enum RebaseOutcome {
        Clean {
            new_tip: Option<String>,
            merged_paths: Vec<String>,
            rebased: bool,
        },
        Conflicted {
            merged_paths: Vec<String>,
            conflicts: Vec<LaneConflict>,
        },
    }

    let lane_bg = lane.clone();
    let target_bg = target_oid.clone();
    let identity_bg = lane_identity.clone();
    let root_bg = root.clone();

    let outcome = tokio::task::spawn_blocking(move || -> Result<RebaseOutcome, ApiErr> {
        let canonical = CanonicalGitRepo::open(&root_bg);
        let tip_oid = lane_bg
            .tip_oid
            .clone()
            .or_else(|| canon::tip_of(&root_bg, &lane_bg.lane_ref));
        let changes = match (lane_bg.base_commit.as_deref(), tip_oid.as_deref()) {
            (Some(base), Some(tip)) if base != tip => diff_commits_to_changes(&canonical, base, tip)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            _ => Vec::new(),
        };

        let base_paths = tree_path_set(&root_bg, lane_bg.base_commit.as_deref());
        let target_paths = tree_path_set(&root_bg, target_bg.as_deref());
        for change in &changes {
            let rp = RepoPath::new(&change.path).map_err(|_| {
                err_resp(
                    StatusCode::FORBIDDEN,
                    format!("policy denied WRITE on '{}'", change.path),
                )
            })?;
            if rp
                .as_str()
                .split('/')
                .any(is_reserved_path_component)
                || auth::is_internal_path(&root_bg, rp.as_str())
            {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    format!("policy denied WRITE on reserved path '{}'", rp),
                ));
            }
            let Some(pol) = policy.as_deref() else {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "no compiled policy loaded: rebase denied",
                ));
            };
            let dec = pol.explain(&identity_bg, &rp, &lane_bg.base_branch);
            if !dec.allows(Capability::WRITE) {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    format!(
                        "policy denied WRITE on '{}' for lane '{}'",
                        rp, lane_bg.lane_id
                    ),
                ));
            }
            let newly_added = change.new_content.is_some() && !base_paths.contains(&change.path);
            if newly_added && target_paths.contains(&change.path) && !dec.allows(Capability::READ) {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    format!(
                        "policy denied READ+WRITE on newly added conflicting path '{}' for lane '{}'",
                        rp, lane_bg.lane_id
                    ),
                ));
            }
        }

        let plan = plan_three_way_rebase(
            &canonical,
            lane_bg.base_commit.as_deref(),
            target_bg.as_deref(),
            &changes,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !plan.conflicts.is_empty() {
            return Ok(RebaseOutcome::Conflicted {
                merged_paths: plan.merged_paths,
                conflicts: plan.conflicts,
            });
        }

        if !plan.rebased {
            return Ok(RebaseOutcome::Clean {
                new_tip: tip_oid,
                merged_paths: Vec::new(),
                rebased: false,
            });
        }

        let new_tip = if changes.is_empty() || plan.resolved_changes.is_empty() {
            if let Some(t) = target_bg.as_deref() {
                canonical
                    .update_ref(&lane_bg.lane_ref, t)
                    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            target_bg.clone()
        } else {
            let resolved: Vec<LaneFileChange> = plan
                .resolved_changes
                .into_iter()
                .map(|(path, new_content)| LaneFileChange { path, new_content })
                .collect();
            let target_label = target_bg
                .as_deref()
                .map(short_oid)
                .unwrap_or("root");
            let new_oid = create_lane_snapshot_commit(
                &canonical,
                &lane_bg.lane_ref,
                target_bg.as_deref(),
                &resolved,
                &format!("Rebase lane {} onto {target_label}", lane_bg.lane_id),
                &author_line,
            )
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Some(new_oid)
        };

        Ok(RebaseOutcome::Clean {
            new_tip,
            merged_paths: plan.merged_paths,
            rebased: true,
        })
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;

    let now = Utc::now().to_rfc3339();
    let (updated_lane, rebased, merged_paths, conflicts) = match outcome {
        RebaseOutcome::Clean {
            new_tip,
            merged_paths,
            rebased,
        } => {
            let mut updated = lane.clone();
            if let Ok(mut st) = state.persisted.lock() {
                if let Some(entry) = st.lanes.iter_mut().find(|l| l.lane_id == lane_id) {
                    entry.base_commit = target_oid;
                    entry.tip_oid = new_tip;
                    if rebased {
                        entry.status = "rebased".to_owned();
                    } else if entry.status == "conflicted" {
                        entry.status = "active".to_owned();
                    }
                    entry.conflicts.clear();
                    entry.updated_at = now;
                    updated = entry.clone();
                }
                let _ = save_state(&state.workspace_root, &st);
            }
            (updated, rebased, merged_paths, Vec::new())
        }
        RebaseOutcome::Conflicted {
            merged_paths,
            conflicts,
        } => {
            let mut updated = lane.clone();
            if let Ok(mut st) = state.persisted.lock() {
                if let Some(entry) = st.lanes.iter_mut().find(|l| l.lane_id == lane_id) {
                    entry.status = "conflicted".to_owned();
                    entry.conflicts = conflicts.clone();
                    entry.updated_at = now;
                    updated = entry.clone();
                }
                let _ = save_state(&state.workspace_root, &st);
            }
            (updated, false, merged_paths, conflicts)
        }
    };

    let _ = state.lane_tx.send(updated_lane.clone());
    Ok((updated_lane, rebased, merged_paths, conflicts))
}

/// `POST /v1/lanes/{lane_id}/rebase`: rebase one lane (and optionally cascade to child lanes).
pub async fn rebase_lane_handler(
    State(state): State<ServerState>,
    AxumPath(lane_id): AxumPath<String>,
    body: Option<Json<RebaseLaneRequest>>,
) -> Result<Json<LaneRebaseResponse>, ApiErr> {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let (lane, rebased, merged_paths, conflicts) =
        rebase_one_lane(&state, &lane_id, req.onto_ref.as_deref()).await?;

    let mut cascaded_lanes = Vec::new();
    if req.cascade && conflicts.is_empty() {
        let mut queue = VecDeque::from([lane_id.clone()]);
        let mut visited = HashSet::from([lane_id]);
        while let Some(cur_id) = queue.pop_front() {
            let children: Vec<String> = state
                .persisted
                .lock()
                .map(|st| {
                    st.lanes
                        .iter()
                        .filter(|l| l.parent_lane_id.as_deref() == Some(cur_id.as_str()))
                        .map(|l| l.lane_id.clone())
                        .collect()
                })
                .unwrap_or_default();
            for child_id in children {
                if !visited.insert(child_id.clone()) {
                    continue;
                }
                let (child_lane, _, _, child_conflicts) =
                    rebase_one_lane(&state, &child_id, None).await?;
                if child_conflicts.is_empty() {
                    queue.push_back(child_id);
                }
                cascaded_lanes.push(child_lane);
            }
        }
    }

    Ok(Json(LaneRebaseResponse {
        lane,
        rebased,
        merged_paths,
        conflicts,
        cascaded_lanes,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConflictResolutionInput {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub strategy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveLaneRequest {
    pub resolutions: Vec<ConflictResolutionInput>,
    #[serde(default = "default_true")]
    pub apply_to_branch: bool,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LaneResolveResponse {
    pub lane: AgentLane,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_round: Option<u32>,
}

/// `POST /v1/lanes/{lane_id}/resolve`: resolve conflicts on a lane and optionally land on branch.
pub async fn resolve_lane_handler(
    State(state): State<ServerState>,
    AxumPath(lane_id): AxumPath<String>,
    Json(req): Json<ResolveLaneRequest>,
) -> Result<Json<LaneResolveResponse>, ApiErr> {
    let lane = state
        .persisted
        .lock()
        .ok()
        .and_then(|st| st.lanes.iter().find(|l| l.lane_id == lane_id).cloned())
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "lane not found"))?;

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
        None => format!("Resolve conflicts on lane {lane_id}"),
    };

    let lane_identity = directory::identity(
        &state,
        &lane.owner,
        non_empty(&lane.agent_profile),
        "lane-resolve",
    )?;
    let root = state.workspace_root.clone();
    let target_full_ref = crate::branch_full_ref(&root, &lane.base_branch)
        .unwrap_or_else(|| format!("refs/heads/{}", lane.base_branch));
    let default_ref = canon::default_ref(&root);
    let on_default = default_ref.as_deref().is_none_or(|d| d == target_full_ref);
    let is_owner = lane_identity.matches_selector(&format!("group:{}", directory::OWNERS_GROUP));
    let policy = state.current_policy();

    // Validate EVERY resolution path before touching Git objects or refs.
    let mut provided_paths = HashSet::new();
    for item in &req.resolutions {
        let rp = RepoPath::new(&item.path)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
        if rp.is_root() {
            return Err(err_resp(StatusCode::BAD_REQUEST, "path names no file"));
        }
        if rp.as_str().split('/').any(is_reserved_path_component) {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("'{}' names a reserved component", rp),
            ));
        }
        if auth::is_internal_path(&root, rp.as_str()) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "server state paths are not writable",
            ));
        }
        let on_disk = crate::working_tree_path(&root, &rp);
        let Some((_, folded)) = on_disk else {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!(
                    "'{}' goes through a symbolic link or leaves the workspace",
                    rp
                ),
            ));
        };
        if folded != rp {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("'{}' is another spelling of existing path '{}'", rp, folded),
            ));
        }
        if auth::is_internal_path(&root, folded.as_str()) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "server state paths are not writable",
            ));
        }
        if let Some(strategy) = item.strategy.as_deref()
            && !matches!(strategy, "ours" | "theirs" | "delete" | "custom")
        {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("unsupported resolution strategy '{strategy}'"),
            ));
        }
        if let Some(mode) = item.mode.as_deref()
            && !matches!(mode, "100644" | "100755" | "120000")
        {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("unsupported git file mode '{mode}'"),
            ));
        }
        let allowed = policy.as_deref().is_some_and(|pol| {
            pol.explain(&lane_identity, &rp, &lane.base_branch)
                .allows(Capability::WRITE)
        });
        if !allowed {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                format!("policy denied WRITE on '{}'", rp),
            ));
        }
        if req.apply_to_branch
            && on_default
            && canon::CONFIG_FILES.contains(&rp.as_str())
            && matches!(item.strategy.as_deref(), None | Some("custom" | "delete"))
        {
            let content = if item.strategy.as_deref() == Some("delete") {
                None
            } else {
                item.content.as_deref().map(str::as_bytes)
            };
            match state.check_config_change(is_owner, rp.as_str(), content) {
                Ok(()) => {}
                Err(None) => {
                    return Err(err_resp(
                        StatusCode::FORBIDDEN,
                        format!("only an owner can change '{}' on the default branch", rp),
                    ));
                }
                Err(Some(why)) => return Err(err_resp(StatusCode::BAD_REQUEST, why)),
            }
        }
        provided_paths.insert(rp.as_str().to_owned());
    }

    for conflict in &lane.conflicts {
        if !provided_paths.contains(&conflict.path) {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("missing resolution for conflicted path '{}'", conflict.path),
            ));
        }
    }

    // A stacked lane kept on its lane is resolved onto its parent's tip, as its rebase is.
    let parent_tip = if req.apply_to_branch {
        None
    } else {
        lane.parent_lane_id.as_deref().and_then(|pid| {
            let parent = state
                .persisted
                .lock()
                .ok()?
                .lanes
                .iter()
                .find(|l| l.lane_id == pid)
                .cloned()?;
            parent
                .tip_oid
                .or_else(|| canon::tip_of(&root, &parent.lane_ref))
                .or(parent.base_commit)
        })
    };
    let author_line = author_line_now(&state);
    let apply_to_branch = req.apply_to_branch;
    let resolutions = req.resolutions;
    let state_bg = state.clone();
    let lane_bg = lane.clone();
    let identity_bg = lane_identity.clone();
    let target_full_bg = target_full_ref.clone();
    let msg_bg = message.clone();
    let root_bg = root.clone();

    let (commit_oid, target_tip) =
        tokio::task::spawn_blocking(move || -> Result<(String, Option<String>), ApiErr> {
            let canonical = CanonicalGitRepo::open(&root_bg);
            let before = (apply_to_branch && on_default)
                .then(|| canon::DefaultTip::capture(&root_bg))
                .flatten();
            let _lock = (apply_to_branch && before.is_none()).then(|| canon::ref_lock(&root_bg));

            let target_tip = parent_tip.or_else(|| canon::tip_of(&root_bg, &target_full_bg));
            let lane_tip = lane_bg
                .tip_oid
                .clone()
                .or_else(|| canon::tip_of(&root_bg, &lane_bg.lane_ref));
            let lane_changes = match (lane_bg.base_commit.as_deref(), lane_tip.as_deref()) {
                (Some(base), Some(tip)) if base != tip => {
                    diff_commits_to_changes(&canonical, base, tip)
                        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                }
                _ => Vec::new(),
            };
            let plan = plan_three_way_rebase(
                &canonical,
                lane_bg.base_commit.as_deref(),
                target_tip.as_deref(),
                &lane_changes,
            )
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let conflict_set: HashSet<&str> = plan
                .conflicts
                .iter()
                .map(|c| c.path.as_str())
                .chain(lane_bg.conflicts.iter().map(|c| c.path.as_str()))
                .collect();

            let mut final_map: BTreeMap<String, Option<(String, Vec<u8>)>> = BTreeMap::new();
            for (path, content) in plan.resolved_changes {
                if conflict_set.contains(path.as_str()) {
                    continue;
                }
                let rp = RepoPath::new(&path)
                    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
                if rp.as_str().split('/').any(is_reserved_path_component)
                    || auth::is_internal_path(&root_bg, rp.as_str())
                {
                    return Err(err_resp(
                        StatusCode::FORBIDDEN,
                        format!("policy denied WRITE on reserved path '{rp}'"),
                    ));
                }
                let allowed = policy.as_deref().is_some_and(|pol| {
                    pol.explain(&identity_bg, &rp, &lane_bg.base_branch)
                        .allows(Capability::WRITE)
                });
                if !allowed {
                    return Err(err_resp(
                        StatusCode::FORBIDDEN,
                        format!("policy denied WRITE on '{rp}'"),
                    ));
                }
                final_map.insert(path, content);
            }

            for item in resolutions {
                let rp = RepoPath::new(&item.path)
                    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
                let path = rp.as_str().to_owned();
                let entry = match item.strategy.as_deref() {
                    Some("delete") => None,
                    Some("ours") => read_tree_entry(&canonical, target_tip.as_deref(), &path)
                        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?,
                    Some("theirs") => read_tree_entry(&canonical, lane_tip.as_deref(), &path)
                        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?,
                    None | Some("custom") => item.content.map(|s| {
                        (
                            item.mode.unwrap_or_else(|| "100644".to_owned()),
                            s.into_bytes(),
                        )
                    }),
                    Some(other) => {
                        return Err(err_resp(
                            StatusCode::BAD_REQUEST,
                            format!("unsupported resolution strategy '{other}'"),
                        ));
                    }
                };
                if apply_to_branch && on_default && canon::CONFIG_FILES.contains(&path.as_str()) {
                    match state_bg.check_config_change(
                        is_owner,
                        &path,
                        entry.as_ref().map(|(_, b)| b.as_slice()),
                    ) {
                        Ok(()) => {}
                        Err(None) => {
                            return Err(err_resp(
                                StatusCode::FORBIDDEN,
                                format!("only an owner can change '{path}' on the default branch"),
                            ));
                        }
                        Err(Some(why)) => return Err(err_resp(StatusCode::BAD_REQUEST, why)),
                    }
                }
                final_map.insert(path, entry);
            }

            let final_changes: Vec<LaneFileChange> = final_map
                .into_iter()
                .map(|(path, new_content)| LaneFileChange { path, new_content })
                .collect();

            if apply_to_branch {
                let check = |new_oid: &str| -> Result<(), String> {
                    if on_default {
                        state_bg.check_config_commit(is_owner, target_tip.as_deref(), new_oid)
                    } else {
                        Ok(())
                    }
                };
                let applied = execute_three_way_rebase(
                    &canonical,
                    target_tip.as_deref(),
                    &target_full_bg,
                    target_tip.as_deref(),
                    &final_changes,
                    &msg_bg,
                    &author_line,
                    Some(&check),
                )
                .map_err(|e| match e {
                    GitBridgeError::RefMoved => err_resp(
                        StatusCode::CONFLICT,
                        "target branch moved while resolving conflicts: retry",
                    ),
                    GitBridgeError::Rejected(why) => err_resp(StatusCode::BAD_REQUEST, why),
                    other => err_resp(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?
                .map_err(|_| {
                    err_resp(
                        StatusCode::CONFLICT,
                        "conflicts remain after applying resolution",
                    )
                })?;
                if let Err(e) = canonical.update_ref(&lane_bg.lane_ref, &applied.commit_oid) {
                    tracing::warn!(error = %e, lane = %lane_bg.lane_ref, "could not move lane ref");
                }
                state_bg.default_branch_moved(before);
                Ok((applied.commit_oid, target_tip))
            } else {
                let snapshot_oid = create_lane_snapshot_commit(
                    &canonical,
                    &lane_bg.lane_ref,
                    target_tip.as_deref(),
                    &final_changes,
                    &msg_bg,
                    &author_line,
                )
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                Ok((snapshot_oid, target_tip))
            }
        })
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;

    let linked_session = lane
        .last_session_id
        .as_deref()
        .and_then(|sid| state.session_manager.get(sid));
    let now = Utc::now().to_rfc3339();
    let mut updated_lane = lane.clone();
    let mut review_round: Option<u32> = None;
    let mut review_event: Option<ReviewEvent> = None;

    {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(entry) = st.lanes.iter_mut().find(|l| l.lane_id == lane_id) {
            entry.status = if apply_to_branch {
                "active".to_owned()
            } else {
                "rebased".to_owned()
            };
            entry.base_commit = target_tip.clone();
            entry.tip_oid = Some(commit_oid.clone());
            entry.conflicts.clear();
            entry.updated_at = now.clone();
            updated_lane = entry.clone();
        }
        if apply_to_branch
            && let Some(cid) = &updated_lane.change_id
            && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == *cid)
        {
            rev.lane_id = Some(lane_id.clone());
            if rev.round_oids.last().map(String::as_str) != Some(commit_oid.as_str()) {
                rev.round_oids.push(commit_oid.clone());
                let n = u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX);
                let provenance = linked_session.as_ref().map(|s| CapturedProvenance {
                    session_id: s.id.clone(),
                    principal: Some(s.principal.clone()),
                    agent_profile: s.agent_profile.clone(),
                    command: s.command.clone(),
                    prompt_summary: message.clone(),
                    tool_calls: s.output_lines.iter().take(8).cloned().collect(),
                    created_at: s.started_at.clone(),
                    steps: s.provenance_steps.clone(),
                    sandbox: Some(s.sandbox.clone()),
                    bytes_scrubbed: s.bytes_scrubbed,
                    exit_code: s.exit_code,
                    egress_calls: 0,
                    egress_blocked: 0,
                });
                rev.rounds_meta.push(StoredRoundMeta {
                    round: n,
                    commit_oid: commit_oid.clone(),
                    base_commit: target_tip.clone(),
                    session_id: updated_lane.last_session_id.clone(),
                    steering_prompt: Some(message.clone()),
                    addressed_comment_ids: Vec::new(),
                    rebased_cleanly: true,
                    conflicts: Vec::new(),
                    provenance,
                    created_at: now.clone(),
                });
                review_round = Some(n);
                review_event = Some(ReviewEvent {
                    change_id: cid.clone(),
                    visibility: rev.visibility.clone(),
                    kind: "round_added".to_owned(),
                    latest_round: n,
                    lane_id: Some(lane_id.clone()),
                });
            }
        }
        let _ = save_state(&state.workspace_root, &st);
    }

    if apply_to_branch && let Some(sid) = &updated_lane.last_session_id {
        let updated_rec = state.session_manager.update(sid, |r| {
            r.commit = Some(commit_oid.clone());
            r.conflicts.clear();
            if review_round.is_some() {
                r.review_round = review_round;
            }
            if let (Some(n), Some(cid)) = (review_round, &updated_lane.change_id) {
                crate::runner::push_step(
                    r,
                    crate::runner::step(
                        "round_commit",
                        format!("Round {n} of review {cid}: {}", short_oid(&commit_oid)),
                    ),
                );
            }
        });
        if let (Some(cid), Some(n), Some(rec_after)) =
            (&updated_lane.change_id, review_round, updated_rec)
            && let Ok(mut st) = state.persisted.lock()
            && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == *cid)
            && let Some(meta) = rev.rounds_meta.iter_mut().find(|m| m.round == n)
        {
            if let Some(prov) = meta.provenance.as_mut() {
                prov.steps = rec_after.provenance_steps;
            }
            let _ = save_state(&state.workspace_root, &st);
        }
        crate::runner::cleanup_session_workspace(&state.workspace_root, sid);
    }

    let _ = state.lane_tx.send(updated_lane.clone());
    if let Some(ev) = review_event {
        let _ = state.review_tx.send(ev);
    }

    let mut audit_ev = AuditEvent::now(
        &lane_identity,
        "premier-server",
        "lane_resolved",
        AuditDecision::Allowed,
        format!(
            "Resolved lane '{lane_id}' as {} (apply_to_branch={apply_to_branch})",
            short_oid(&commit_oid)
        ),
    );
    audit_ev.target = Some(updated_lane.lane_ref.clone());
    auth::audit(&state.audit_sink, audit_ev);

    Ok(Json(LaneResolveResponse {
        lane: updated_lane,
        commit_oid: Some(commit_oid),
        review_round,
    }))
}

/// `DELETE /v1/lanes/{lane_id}`: remove a lane and delete its snapshot ref (owner-only).
pub async fn delete_lane_handler(
    State(state): State<ServerState>,
    AxumPath(lane_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let mut removed = {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let Some(pos) = st.lanes.iter().position(|l| l.lane_id == lane_id) else {
            return Err(err_resp(StatusCode::NOT_FOUND, "lane not found"));
        };
        let removed = st.lanes.remove(pos);
        for rev in &mut st.reviews {
            if rev.lane_id.as_deref() == Some(lane_id.as_str()) {
                rev.lane_id = None;
            }
        }
        let _ = save_state(&state.workspace_root, &st);
        removed
    };

    let (root, lane_ref) = (state.workspace_root.clone(), removed.lane_ref.clone());
    let _ = tokio::task::spawn_blocking(move || {
        let _ = git_command(&root)
            .args(["update-ref", "-d", &lane_ref])
            .output();
    })
    .await;

    removed.status = "discarded".to_owned();
    removed.updated_at = Utc::now().to_rfc3339();
    let _ = state.lane_tx.send(removed);

    Ok(Json(serde_json::json!({
        "ok": true,
        "deleted": lane_id,
    })))
}

// ---------------------------------------------------------------------------
// 3. Real Round-to-Round Interdiff Handler
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InterdiffQuery {
    #[serde(default)]
    pub from_round: Option<u32>,
    #[serde(default)]
    pub to_round: Option<u32>,
    #[serde(default = "default_caller")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InterdiffFile {
    pub path: String,
    pub status: String,
    pub allowed: bool,
    pub additions: usize,
    pub deletions: usize,
    pub binary: bool,
    pub patch: String,
}

#[derive(Debug, Serialize)]
pub struct ReviewInterdiffResponse {
    pub change_id: String,
    pub from_round: u32,
    pub to_round: u32,
    pub from_oid: String,
    pub to_oid: String,
    pub rebased_between_rounds: bool,
    pub upstream_files_skipped: usize,
    pub hidden_files: usize,
    pub files: Vec<InterdiffFile>,
}

/// `GET /v1/reviews/{change_id}/interdiff`: ACL-filtered round-to-round interdiff.
pub async fn review_interdiff_handler(
    State(state): State<ServerState>,
    AxumPath(change_id): AxumPath<String>,
    Query(q): Query<InterdiffQuery>,
) -> Result<Json<ReviewInterdiffResponse>, ApiErr> {
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "review-interdiff")?;
    crate::handlers_v1::review_visible(&state, &identity, &change_id)?;

    let rev = state
        .persisted
        .lock()
        .ok()
        .and_then(|st| {
            st.reviews
                .iter()
                .find(|r| r.change_id == change_id)
                .cloned()
        })
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "review not found"))?;

    let len = u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX);
    let to_round = q.to_round.unwrap_or(len);
    let from_round = q.from_round.unwrap_or_else(|| to_round.saturating_sub(1));
    if to_round == 0 || to_round > len || from_round >= to_round {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!(
                "invalid round range from_round={from_round} to_round={to_round} (available: 1..={len})"
            ),
        ));
    }

    let to_oid = rev.round_oids[(to_round - 1) as usize].clone();
    let root = state.workspace_root.clone();
    let rev_bg = rev.clone();
    let to_oid_bg = to_oid.clone();

    let interdiff = tokio::task::spawn_blocking(move || -> Result<_, ApiErr> {
        let canonical = CanonicalGitRepo::open(&root);
        let from_oid = if from_round > 0 {
            rev_bg.round_oids[(from_round - 1) as usize].clone()
        } else {
            rev_bg
                .rounds_meta
                .iter()
                .find(|m| m.round == 1)
                .and_then(|m| m.base_commit.clone())
                .or_else(|| {
                    crate::repos::git_out(
                        &root,
                        &["merge-base", &rev_bg.base_ref, &rev_bg.round_oids[0]],
                    )
                })
                .or_else(|| first_parent(&root, &rev_bg.round_oids[0]))
                .or_else(|| crate::handlers_v1::resolve_branch_oid(&root, &rev_bg.base_ref).ok())
                .ok_or_else(|| {
                    err_resp(
                        StatusCode::BAD_REQUEST,
                        "could not determine base commit for round 0",
                    )
                })?
        };

        let (from_base, to_base) = if from_round == 0 {
            (None, None)
        } else {
            let tb_opt = rev_bg
                .rounds_meta
                .iter()
                .find(|m| m.round == to_round)
                .and_then(|m| m.base_commit.clone())
                .or_else(|| first_parent(&root, &to_oid_bg));
            if tb_opt.as_deref() == Some(from_oid.as_str()) {
                (None, None)
            } else if let Some(tb) = tb_opt {
                let fb = if is_ancestor(&root, &from_oid, &tb) {
                    Some(from_oid.clone())
                } else {
                    rev_bg
                        .rounds_meta
                        .iter()
                        .find(|m| m.round == from_round)
                        .and_then(|m| m.base_commit.clone())
                        .or_else(|| first_parent(&root, &from_oid))
                };
                (fb, Some(tb))
            } else {
                (None, None)
            }
        };

        compute_commit_interdiff(
            &canonical,
            &from_oid,
            &to_oid_bg,
            from_base.as_deref(),
            to_base.as_deref(),
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;

    let policy = state.current_policy();
    let mut files = Vec::new();
    let mut hidden_files = 0usize;
    for entry in interdiff.files {
        let caps = match (policy.as_deref(), RepoPath::new(&entry.path).ok()) {
            (Some(pol), Some(rp)) => pol.explain(&identity, &rp, &rev.branch).effective,
            _ => Capability::empty(),
        };
        if !caps.contains(Capability::LIST) {
            hidden_files += 1;
            continue;
        }
        if !caps.contains(Capability::READ) {
            files.push(InterdiffFile {
                path: entry.path,
                status: entry.status,
                allowed: false,
                additions: 0,
                deletions: 0,
                binary: entry.binary,
                patch: String::new(),
            });
        } else {
            files.push(InterdiffFile {
                path: entry.path,
                status: entry.status,
                allowed: true,
                additions: entry.additions,
                deletions: entry.deletions,
                binary: entry.binary,
                patch: entry.patch,
            });
        }
    }

    let mut upstream_files_skipped = interdiff.upstream_files_skipped;
    let (from_oid_out, to_oid_out) = if auth::caller_is_owner() {
        (interdiff.from_oid, interdiff.to_oid)
    } else {
        // A member learns no count of what she cannot list (upstream noise included).
        hidden_files = 0;
        upstream_files_skipped = interdiff
            .upstream_skipped_paths
            .iter()
            .filter(|p| {
                crate::path_caps(policy.as_deref(), &identity, p, &rev.branch)
                    .contains(Capability::LIST)
            })
            .count();
        let ids = GitIds::of(&state, &identity)?;
        (ids.shown(&interdiff.from_oid), ids.shown(&interdiff.to_oid))
    };

    Ok(Json(ReviewInterdiffResponse {
        change_id,
        from_round,
        to_round,
        from_oid: from_oid_out,
        to_oid: to_oid_out,
        rebased_between_rounds: interdiff.rebased_between_rounds,
        upstream_files_skipped,
        hidden_files,
        files,
    }))
}

// ---------------------------------------------------------------------------
// 4. Closed-Loop Executable Steering Handler
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SteerReviewRequest {
    #[serde(default)]
    pub comment_ids: Vec<String>,
    #[serde(default)]
    pub instruction: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default = "default_true")]
    pub auto_commit: bool,
    #[serde(default)]
    pub mark_changes_requested: bool,
    #[serde(default)]
    pub max_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SteerReviewResponse {
    pub change_id: String,
    pub target_round: u32,
    pub lane_id: String,
    pub session: AgentSessionRecord,
    pub packaged_comments: usize,
    pub redacted_comments: usize,
    pub packaged_conflicts: usize,
}

/// `POST /v1/reviews/{change_id}/steer`: package ACL-filtered review comments & conflicts into a
/// `SteeringPacket`, launch a caged session under `human ∩ agent_profile`, and optionally
/// auto-commit its output as the next review round.
pub async fn steer_review_handler(
    State(state): State<ServerState>,
    AxumPath(change_id): AxumPath<String>,
    Json(req): Json<SteerReviewRequest>,
) -> Result<Json<SteerReviewResponse>, ApiErr> {
    let mode = crate::runner::sandbox_mode(state.allow_unsandboxed_agents);
    if mode == crate::runner::SandboxMode::None {
        return Err(err_resp(
            StatusCode::NOT_IMPLEMENTED,
            crate::runner::NO_SANDBOX,
        ));
    }

    let rev = state
        .persisted
        .lock()
        .ok()
        .and_then(|st| {
            st.reviews
                .iter()
                .find(|r| r.change_id == change_id)
                .cloned()
        })
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "review not found"))?;

    let policy = state.current_policy();
    let agent_profile = req
        .agent_profile
        .as_deref()
        .and_then(non_empty)
        .or_else(|| rev.delegated_agent.as_deref().and_then(non_empty));
    if let Some(name) = &agent_profile
        && !policy.as_deref().is_some_and(|p| p.has_agent_profile(name))
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("agent profile '{name}' is not defined in this repository's policy"),
        ));
    }

    let caller = auth::actor_principal();
    let agent_identity =
        directory::identity(&state, &caller, agent_profile.clone(), "review-steer")?;

    // Select comments: explicit comment_ids, or all unaddressed comments.
    let selected_comments: Vec<_> = if !req.comment_ids.is_empty() {
        rev.comments
            .iter()
            .filter(|c| req.comment_ids.contains(&c.id))
            .collect()
    } else {
        rev.comments
            .iter()
            .filter(|c| c.addressed_in_round.is_none())
            .collect()
    };

    // Strict ACL packaging (human ∩ agent_profile READ on &rev.branch).
    let mut packaged = Vec::new();
    let mut addressed_ids = Vec::new();
    let mut redacted_comments = 0usize;
    for c in selected_comments {
        let readable = policy.as_deref().is_some_and(|pol| {
            RepoPath::new(&c.path).is_ok_and(|rp| {
                pol.explain(&agent_identity, &rp, &rev.branch)
                    .allows(Capability::READ)
            })
        });
        if readable {
            packaged.push(SteeringComment {
                id: c.id.clone(),
                author: c.author.clone(),
                path: c.path.clone(),
                line: c.line,
                body: c.body.clone(),
                round: c.round,
            });
            addressed_ids.push(c.id.clone());
        } else {
            redacted_comments += 1;
        }
    }

    let instruction = req
        .instruction
        .as_deref()
        .and_then(non_empty)
        .unwrap_or_else(|| "Address the inline review comments cleanly".to_owned());

    let root = state.workspace_root.clone();
    let full_ref = crate::content_source(&state, &agent_identity, &rev.branch)?
        .filter(|full| full.starts_with("refs/"));
    let branch_tip = full_ref.as_deref().and_then(|r| canon::tip_of(&root, r));

    let lane_id = rev
        .lane_id
        .clone()
        .filter(|id| crate::runner::valid_lane_id(id))
        .unwrap_or_else(|| format!("lane-{}", rev.change_id.to_lowercase()));
    if !crate::runner::valid_lane_id(&lane_id) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "invalid lane id"));
    }
    let lane_ref = format!("{LANE_REF_PREFIX}{lane_id}");

    // Ensure lane exists, link to review, and mark changes requested if requested.
    let (lane_status, lane_tip_oid, raw_lane_conflicts, need_create_ref) = {
        let mut st = state
            .persisted
            .lock()
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let (status, tip, conflicts, created) =
            if let Some(existing) = st.lanes.iter_mut().find(|l| l.lane_id == lane_id) {
                if existing.change_id.is_none() {
                    existing.change_id = Some(rev.change_id.clone());
                }
                (
                    existing.status.clone(),
                    existing.tip_oid.clone(),
                    existing.conflicts.clone(),
                    false,
                )
            } else {
                let new_lane = AgentLane {
                    lane_id: lane_id.clone(),
                    lane_ref: lane_ref.clone(),
                    base_branch: rev.branch.clone(),
                    parent_lane_id: None,
                    change_id: Some(rev.change_id.clone()),
                    base_commit: branch_tip.clone(),
                    tip_oid: branch_tip.clone(),
                    owner: caller.clone(),
                    agent_profile: agent_profile.clone().unwrap_or_default(),
                    visibility: rev.visibility.clone(),
                    status: "active".to_owned(),
                    conflicts: Vec::new(),
                    last_session_id: None,
                    created_at: now.clone(),
                    updated_at: now,
                };
                st.lanes.push(new_lane);
                ("active".to_owned(), branch_tip.clone(), Vec::new(), true)
            };
        if let Some(stored_rev) = st.reviews.iter_mut().find(|r| r.change_id == change_id) {
            stored_rev.lane_id = Some(lane_id.clone());
            if req.mark_changes_requested {
                let latest = u32::try_from(stored_rev.round_oids.len().max(1)).unwrap_or(u32::MAX);
                stored_rev
                    .verdicts
                    .insert(format!("r{latest}:{caller}"), "changes".to_owned());
            }
        }
        let _ = save_state(&state.workspace_root, &st);
        (status, tip, conflicts, created)
    };

    if need_create_ref && let Some(tip) = branch_tip.clone() {
        let (root_bg, lane_ref_bg) = (root.clone(), lane_ref.clone());
        let _ = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root_bg);
            if canon::tip_of(&root_bg, &lane_ref_bg).is_none() {
                let _ = canonical.update_ref(&lane_ref_bg, &tip);
            }
        })
        .await;
    }

    // Strictly ACL-filter conflicts: ONLY READ-allowed (`allowed == true`) conflicts reach the agent!
    let packaged_conflicts: Vec<LaneConflict> = filter_conflicts_for_viewer(
        policy.as_deref(),
        &agent_identity,
        &rev.branch,
        &raw_lane_conflicts,
    )
    .into_iter()
    .filter(|c| c.allowed)
    .collect();

    // Verify workspace projection is non-empty for the delegated agent identity.
    let base_commit_override = if lane_status == "conflicted" {
        lane_tip_oid.clone()
    } else {
        None
    };
    let check_oid = base_commit_override.clone().or_else(|| branch_tip.clone());
    if let (Some(oid), Some(pol)) = (check_oid, policy.clone()) {
        let root_bg = root.clone();
        let id_bg = agent_identity.clone();
        let branch_bg = rev.branch.clone();
        let projected = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root_bg);
            project_commit_tree_for_workspace(&canonical, &pol, &id_bg, &branch_bg, &oid)
        })
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if projected.is_none() {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!(
                    "{} can read nothing on branch '{}': there is no workspace to run in",
                    agent_identity.principal.canonical_id(),
                    rev.branch
                ),
            ));
        }
    }

    let command = req
        .command
        .as_deref()
        .and_then(non_empty)
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "Get-Content $env:PREMIER_STEERING_MD".to_owned()
            } else {
                "cat \"$PREMIER_STEERING_MD\"".to_owned()
            }
        });

    let target_round = u32::try_from(rev.round_oids.len() + 1).unwrap_or(u32::MAX);
    let packaged_comments = packaged.len();
    let packaged_conflicts_len = packaged_conflicts.len();
    let packet = SteeringPacket {
        change_id: rev.change_id.clone(),
        target_round,
        lane_id: Some(lane_id.clone()),
        branch: rev.branch.clone(),
        instruction: instruction.clone(),
        comments: packaged,
        conflicts: packaged_conflicts,
        packaged_comments,
        redacted_comments,
    };

    let saved_actor = auth::capture_actor();
    let on_complete: Option<SessionCompleteHook> = req.auto_commit.then(|| {
        let state_bg = state.clone();
        let branch_bg = rev.branch.clone();
        let lane_bg = lane_id.clone();
        let cid_bg = rev.change_id.clone();
        let inst_bg = instruction.clone();
        let addressed_bg = addressed_ids.clone();
        let hook: SessionCompleteHook = Box::new(move |done| {
            Box::pin(auth::with_actor(saved_actor, async move {
                if done.status == "completed"
                    && done.exit_code == Some(0)
                    && !done.changes.is_empty()
                    && !done.changes_truncated
                {
                    let msg = format!(
                        "Review {} R{}: {}",
                        cid_bg,
                        target_round,
                        inst_bg.chars().take(72).collect::<String>()
                    );
                    let res = crate::runner::commit_session_changes(
                        &state_bg,
                        &done.id,
                        CommitSessionRequest {
                            branch: Some(branch_bg),
                            message: Some(msg),
                            auto_rebase: true,
                            lane_id: Some(lane_bg),
                            change_id: Some(cid_bg),
                            ..CommitSessionRequest::default()
                        },
                        CommitReviewExtra {
                            steering_prompt: Some(inst_bg),
                            addressed_comment_ids: addressed_bg,
                        },
                    )
                    .await;
                    if let Err((status, body)) = res
                        && status != StatusCode::CONFLICT
                    {
                        tracing::warn!(
                            session = %done.id,
                            status = %status,
                            error = %body.0.error,
                            "steered session auto-commit failed"
                        );
                    }
                }
            }))
        });
        hook
    });

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

    let quarantine_approvals = state
        .persisted
        .lock()
        .map(|s| s.approved_instructions.clone())
        .unwrap_or_default();

    let rec = state
        .session_manager
        .spawn_session(crate::runner::SessionRequest {
            workspace_root: state.workspace_root.clone(),
            identity: agent_identity.clone(),
            env_name: "dev".to_owned(),
            command,
            branch: rev.branch.clone(),
            full_ref,
            ref_visibility: state.branch_visibility_map(),
            policy,
            schema: state.current_env_schema(),
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage,
            limit: crate::runner::session_limit(req.max_secs),
            quarantine_approvals,
            budget: None,
            base_commit_override,
            lane_id: Some(lane_id.clone()),
            change_id: Some(rev.change_id.clone()),
            steering_packet: Some(packet),
            on_complete,
        })
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let updated_lane = if let Ok(mut st) = state.persisted.lock() {
        let lane_out = st.lanes.iter_mut().find(|l| l.lane_id == lane_id).map(|l| {
            l.last_session_id = Some(rec.id.clone());
            l.updated_at = Utc::now().to_rfc3339();
            l.clone()
        });
        let _ = save_state(&state.workspace_root, &st);
        lane_out
    } else {
        None
    };

    if let Some(lane_out) = updated_lane {
        let _ = state.lane_tx.send(lane_out);
    }
    let _ = state.review_tx.send(ReviewEvent {
        change_id: rev.change_id.clone(),
        visibility: rev.visibility.clone(),
        kind: "steered".to_owned(),
        latest_round: u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX),
        lane_id: Some(lane_id.clone()),
    });

    let mut ev = AuditEvent::now(
        &agent_identity,
        "premier-server",
        "review_steered",
        AuditDecision::Allowed,
        format!(
            "Steered review {} for round {} on lane '{}' (session {}, {} comments packaged, {} redacted, {} conflicts)",
            rev.change_id,
            target_round,
            lane_id,
            rec.id,
            packaged_comments,
            redacted_comments,
            packaged_conflicts_len
        ),
    );
    ev.target = Some(rev.change_id.clone());
    auth::audit(&state.audit_sink, ev);

    Ok(Json(SteerReviewResponse {
        change_id: rev.change_id,
        target_round,
        lane_id,
        session: rec,
        packaged_comments,
        redacted_comments,
        packaged_conflicts: packaged_conflicts_len,
    }))
}

// ---------------------------------------------------------------------------
// 5. Session Provenance Handler
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SessionProvenanceResponse {
    pub session_id: String,
    pub command: String,
    pub principal: String,
    pub agent_profile: String,
    pub steps: Vec<ProvenanceStep>,
}

/// `GET /v1/agents/sessions/{id}/provenance`: ACL-filtered chronological provenance timeline.
pub async fn session_provenance_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SessionProvenanceResponse>, ApiErr> {
    let rec = state
        .session_manager
        .get(&id)
        .filter(crate::handlers_v1::may_see_session)
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    let identity =
        directory::identity(&state, &auth::actor_principal(), None, "session-provenance")?;
    let steps = filter_steps_for_viewer(
        state.current_policy().as_deref(),
        &identity,
        &rec.branch,
        &rec.provenance_steps,
    );
    Ok(Json(SessionProvenanceResponse {
        session_id: rec.id,
        command: rec.command,
        principal: rec.principal,
        agent_profile: rec.agent_profile,
        steps,
    }))
}
