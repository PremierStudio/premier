//! Semantic Declassification Firewall and Active Instruction Quarantine for `premier-server`:
//! the server's inputs to the firewall (vault index, approved instruction files, restricted
//! corpus), owner overrides, held instruction-file edits, and the `/v1/access/scan` and
//! `/v1/quarantine*` endpoints.

use std::collections::BTreeMap;
use std::path::Path;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use premier_core::{AuditDecision, AuditEvent, DelegatedIdentity, RepoPath, Visibility};
use premier_git_bridge::{
    CanonicalGitRepo, SquashFirewallInput, plan_squash_declassify, scan_squash_declassify,
};
use premier_policy::{
    CompiledPolicy, DeclassificationReport, FirewallFinding, FirewallScanInput, PrivateBlobEntry,
    PrivateCorpus, ScanTargetFile, VaultSecretIndex, run_declassification_firewall,
    scan_instruction_file, sha256_hex,
};
use premier_proxy::AuditSink;
use serde::{Deserialize, Serialize};

use crate::store::{
    ApprovedInstructionFile, FirewallOverrideRecord, PendingQuarantineEdit, save_state,
};
use crate::{ApiError, ServerState, auth, canon, err_resp};

type ApiErr = (StatusCode, Json<ApiError>);

/// Largest prefix of one blob read into the restricted corpus (as the Git bridge reads it).
const MAX_CORPUS_BLOB_BYTES: usize = 4 * 1024 * 1024;
/// Records of each kind kept in the persisted state; the oldest go first.
const MAX_RECORDS: usize = 200;
/// Overrides `GET /v1/quarantine` lists, most recent first.
const RECENT_OVERRIDES: usize = 50;
const GITLINK_MODE: &str = "160000";

fn ise(e: impl std::fmt::Display) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn short(digest: &str) -> &str {
    &digest[..digest.len().min(12)]
}

fn random_id(prefix: &str) -> String {
    let hex: String = auth::random_bytes(8)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{prefix}-{hex}")
}

// ---------------------------------------------------------------------------------------------
// Inputs to the firewall.
// ---------------------------------------------------------------------------------------------

/// Keyed digests of every secret in the workspace vault; `None` when there are none. The raw
/// values are zeroized as soon as they are indexed.
pub fn build_vault_secret_index(state: &ServerState) -> Option<VaultSecretIndex> {
    let repo_id = state
        .current_env_schema()
        .and_then(|s| s.repo_id.clone())
        .unwrap_or_else(|| "local/repo".to_owned());
    let secrets = crate::store::load_vault_secrets_zeroizing(&state.workspace_root, &repo_id);
    let index =
        VaultSecretIndex::from_secrets(secrets.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    drop(secrets);
    (!index.is_empty()).then_some(index)
}

/// Owner-approved instruction files: path -> SHA-256 hex.
pub fn approved_instruction_map(state: &ServerState) -> BTreeMap<String, String> {
    state
        .persisted
        .lock()
        .map(|st| {
            st.approved_instructions
                .iter()
                .map(|(path, a)| (path.to_ascii_lowercase(), a.sha256.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Owner-approved instruction files, with their approved content.
pub fn approved_instruction_entries(
    state: &ServerState,
) -> BTreeMap<String, ApprovedInstructionFile> {
    state
        .persisted
        .lock()
        .map(|st| st.approved_instructions.clone())
        .unwrap_or_default()
}

/// `(path, mode, blob oid)` of every file in the tree of `rev` (empty when it has none).
pub fn tree_entries(root: &Path, rev: &str) -> Vec<(String, String, String)> {
    let Ok(out) = premier_git_bridge::git_command(root)
        .args(["ls-tree", "-r", "-z", "--end-of-options", rev])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter_map(|line| {
            let (meta, path) = line.split_once('\t')?;
            let mut parts = meta.split(' ');
            let (mode, kind, oid) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "blob").then(|| (path.to_owned(), mode.to_owned(), oid.to_owned()))
        })
        .collect()
}

/// The bytes of `path` in the tree of `rev`, if it is a file there.
pub fn blob_at(root: &Path, rev: &str, path: &str) -> Option<Vec<u8>> {
    let oid = crate::repos::git_out(
        root,
        &["rev-parse", "-q", "--verify", &format!("{rev}:{path}")],
    )?;
    CanonicalGitRepo::open(root)
        .read_object(&oid)
        .ok()
        .map(|o| o.data.to_vec())
}

/// The restricted side of the boundary at `rev`: every file anonymous may not read on
/// `ref_name`, against the files it may (`include_already_public`; left out, a scan of the tree
/// itself still reports what its public files already leak).
pub fn collect_private_corpus(
    root: &Path,
    policy: &CompiledPolicy,
    rev: &str,
    ref_name: &str,
    include_already_public: bool,
) -> PrivateCorpus {
    let canonical = CanonicalGitRepo::open(root);
    let (mut private, mut public) = (Vec::new(), Vec::new());
    for (path, mode, oid) in tree_entries(root, rev) {
        if mode == GITLINK_MODE {
            continue;
        }
        let is_public = RepoPath::new(&path).is_ok_and(|rp| policy.is_path_public(&rp, ref_name));
        if is_public && !include_already_public {
            continue;
        }
        let Ok(object) = canonical.read_object(&oid) else {
            continue;
        };
        let mut content = object.data.to_vec();
        content.truncate(MAX_CORPUS_BLOB_BYTES);
        let entry = PrivateBlobEntry { path, content };
        if is_public {
            public.push(entry);
        } else {
            private.push(entry);
        }
    }
    PrivateCorpus::build(
        &private,
        if include_already_public { &public } else { &[] },
        policy.firewall_min_snippet_bytes(),
        policy.firewall_min_shingle_matches(),
    )
}

/// Run the firewall over a change about to land on `ref_name` (whose readers `visibility`
/// says): the changed `files` and the commit `message`, against the restricted files of
/// `corpus_rev` when the branch is readable beyond its members, the vault and the approved
/// instruction files.
#[allow(clippy::too_many_arguments)]
pub fn scan_change(
    state: &ServerState,
    policy: &CompiledPolicy,
    corpus_rev: Option<&str>,
    ref_name: &str,
    visibility: &Visibility,
    files: &[ScanTargetFile],
    message: &str,
    actor_is_owner: bool,
    actor_is_agent: bool,
) -> DeclassificationReport {
    let check_cross_boundary = matches!(visibility, Visibility::Public | Visibility::Org);
    let corpus = corpus_rev
        .filter(|_| check_cross_boundary && policy.firewall_enabled())
        .map(|rev| collect_private_corpus(&state.workspace_root, policy, rev, ref_name, true));
    let vault = build_vault_secret_index(state);
    let approved = approved_instruction_map(state);
    let messages: Vec<String> = if message.trim().is_empty() {
        Vec::new()
    } else {
        vec![message.to_owned()]
    };
    run_declassification_firewall(&FirewallScanInput {
        policy,
        ref_name,
        commit_messages: &messages,
        files,
        corpus: corpus.as_ref(),
        vault: vault.as_ref(),
        check_cross_boundary,
        actor_is_owner,
        actor_is_agent,
        approved_instructions: &approved,
    })
}

/// Audit the tree at `rev` as it stands on `ref_name`: its public files and every instruction
/// file, against its restricted files (not discounting what the public files already hold, so
/// an existing leak is reported), the vault and the approved instruction files.
pub fn audit_tree(
    root: &Path,
    policy: &CompiledPolicy,
    rev: &str,
    ref_name: &str,
    messages: &[String],
    vault: Option<&VaultSecretIndex>,
    approved: &BTreeMap<String, String>,
) -> DeclassificationReport {
    let canonical = CanonicalGitRepo::open(root);
    let mut files = Vec::new();
    for (path, mode, oid) in tree_entries(root, rev) {
        let Ok(rp) = RepoPath::new(&path) else {
            continue;
        };
        let wanted = policy.is_path_public(&rp, ref_name) || policy.is_instruction_file(&rp);
        if mode == GITLINK_MODE || !wanted {
            continue;
        }
        if let Ok(object) = canonical.read_object(&oid) {
            files.push(ScanTargetFile {
                path,
                content: object.data.to_vec(),
                deleted: false,
            });
        }
    }
    let corpus = policy
        .firewall_enabled()
        .then(|| collect_private_corpus(root, policy, rev, ref_name, false));
    run_declassification_firewall(&FirewallScanInput {
        policy,
        ref_name,
        commit_messages: messages,
        files: &files,
        corpus: corpus.as_ref(),
        vault,
        check_cross_boundary: true,
        actor_is_owner: true,
        actor_is_agent: false,
        approved_instructions: approved,
    })
}

// ---------------------------------------------------------------------------------------------
// Audit, overrides, held edits, approvals.
// ---------------------------------------------------------------------------------------------

/// Audit a refusal by the firewall: rule ids, counts and a short digest, never content.
pub fn record_firewall_audit(
    audit_sink: &AuditSink,
    identity: &DelegatedIdentity,
    action: &str,
    target: &str,
    report: &DeclassificationReport,
) {
    let decision = if report.has_sensitive_blocking() {
        AuditDecision::ExfiltrationBlocked
    } else {
        AuditDecision::Denied
    };
    let mut rules: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.blocking)
        .map(|f| f.rule_id.as_str())
        .collect();
    rules.sort_unstable();
    rules.dedup();
    let mut ev = AuditEvent::now(
        identity,
        "premier-firewall",
        action,
        decision,
        format!(
            "declassification firewall refused {target}: {} ({}) [report {}]",
            premier_git_bridge::plural(report.blocking_count, "blocking finding"),
            rules.join(", "),
            short(&report.report_digest)
        ),
    );
    ev.target = Some(target.to_owned());
    auth::audit(audit_sink, ev);
}

/// Who may override a blocking report at all, before there is one to compare against: a human
/// owner from a signed-in browser, under a policy that allows overrides, with a reason.
pub fn check_override_preconditions(
    user: &auth::AuthUser,
    identity: &DelegatedIdentity,
    policy: &CompiledPolicy,
    reason: Option<&str>,
) -> Result<String, ApiErr> {
    if user.role != auth::Role::Owner {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "only an owner may override the declassification firewall",
        ));
    }
    auth::require_browser_session(user)?;
    if identity.agent_task.is_some() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "an agent may not override the declassification firewall",
        ));
    }
    if !policy.firewall_allow_owner_override() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "policy does not allow owner overrides of the declassification firewall",
        ));
    }
    let reason = reason.map(str::trim).unwrap_or_default();
    if reason.chars().count() < 8 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "an override needs a reason of at least 8 characters",
        ));
    }
    Ok(reason.to_owned())
}

/// Validate an owner's override of exactly `report` (`ack_digest` must be its digest: 409 with
/// the current report otherwise), then record and audit it.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_record_override(
    state: &ServerState,
    user: &auth::AuthUser,
    identity: &DelegatedIdentity,
    policy: &CompiledPolicy,
    action: &str,
    target: &str,
    report: &DeclassificationReport,
    reason: Option<&str>,
    ack_digest: Option<&str>,
) -> Result<FirewallOverrideRecord, ApiErr> {
    let reason = check_override_preconditions(user, identity, policy, reason)?;
    if ack_digest != Some(report.report_digest.as_str()) {
        let body = ApiError {
            error: "the override does not acknowledge this report: review the current findings and override again".to_owned(),
            firewall: crate::FirewallRefusal::new(report.clone(), None),
            ..ApiError::default()
        };
        return Err((StatusCode::CONFLICT, Json(body)));
    }
    record_override(state, user, identity, action, target, report, &reason).map_err(ise)
}

/// Record and audit an override already validated against `report`.
pub fn record_override(
    state: &ServerState,
    user: &auth::AuthUser,
    identity: &DelegatedIdentity,
    action: &str,
    target: &str,
    report: &DeclassificationReport,
    reason: &str,
) -> Result<FirewallOverrideRecord, String> {
    let record = FirewallOverrideRecord {
        id: random_id("fo"),
        action: action.to_owned(),
        target: target.to_owned(),
        owner: format!("@{}", user.username),
        reason: reason.to_owned(),
        report_digest: report.report_digest.clone(),
        finding_ids: report
            .findings
            .iter()
            .filter(|f| f.blocking)
            .map(|f| f.id.clone())
            .collect(),
        created_at: Utc::now().to_rfc3339(),
    };
    {
        let mut st = state.persisted.lock().map_err(|_| "state lock poisoned")?;
        st.firewall_overrides.push(record.clone());
        let excess = st.firewall_overrides.len().saturating_sub(MAX_RECORDS);
        st.firewall_overrides.drain(..excess);
        save_state(&state.workspace_root, &st)?;
    }
    let mut ev = AuditEvent::now(
        identity,
        "premier-firewall",
        "firewall_override",
        AuditDecision::Allowed,
        format!(
            "owner override of {} on {action} ({}) [report {}]: {reason}",
            premier_git_bridge::plural(record.finding_ids.len(), "blocking finding"),
            record.id,
            short(&report.report_digest)
        ),
    );
    ev.target = Some(target.to_owned());
    auth::audit(&state.audit_sink, ev);
    Ok(record)
}

/// Hold an instruction-file edit for an owner's decision instead of committing it.
#[allow(clippy::too_many_arguments)]
pub fn record_pending_quarantine_edit(
    state: &ServerState,
    identity: &DelegatedIdentity,
    path: &str,
    branch: &str,
    proposed_content: &str,
    base_sha256: Option<String>,
    commit_message: &str,
    findings: Vec<FirewallFinding>,
) -> Result<PendingQuarantineEdit, String> {
    let edit = PendingQuarantineEdit {
        id: random_id("qe"),
        path: path.to_owned(),
        branch: branch.to_owned(),
        proposed_by: identity.principal.canonical_id(),
        agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
        proposed_sha256: sha256_hex(proposed_content.as_bytes()),
        proposed_content: proposed_content.to_owned(),
        base_sha256,
        commit_message: commit_message.to_owned(),
        findings,
        created_at: Utc::now().to_rfc3339(),
        status: "pending".to_owned(),
        decided_by: None,
        decided_at: None,
        decision_reason: None,
    };
    {
        let mut st = state.persisted.lock().map_err(|_| "state lock poisoned")?;
        st.pending_quarantine_edits.push(edit.clone());
        let excess = st
            .pending_quarantine_edits
            .len()
            .saturating_sub(MAX_RECORDS);
        st.pending_quarantine_edits.drain(..excess);
        save_state(&state.workspace_root, &st)?;
    }
    let mut ev = AuditEvent::now(
        identity,
        "premier-quarantine",
        "quarantine_edit_held",
        AuditDecision::ApprovalRequired,
        format!(
            "instruction file edit on {branch} held for owner approval ({}, sha256 {})",
            edit.id,
            short(&edit.proposed_sha256)
        ),
    );
    ev.target = Some(path.to_owned());
    auth::audit(&state.audit_sink, ev);
    Ok(edit)
}

/// An owner approved exactly `content` at `path`: agents get it, and an owner's edit of it
/// passes the quarantine.
pub fn record_owner_instruction_approval(
    state: &ServerState,
    path: &str,
    content: &str,
    owner: &str,
    reason: &str,
) -> Result<ApprovedInstructionFile, String> {
    let approval = ApprovedInstructionFile {
        path: path.to_owned(),
        sha256: sha256_hex(content.as_bytes()),
        approved_by: owner.to_owned(),
        approved_at: Utc::now().to_rfc3339(),
        reason: reason.to_owned(),
        approved_content: Some(content.to_owned()),
    };
    let mut st = state.persisted.lock().map_err(|_| "state lock poisoned")?;
    st.approved_instructions
        .insert(path.to_owned(), approval.clone());
    save_state(&state.workspace_root, &st)?;
    Ok(approval)
}

// ---------------------------------------------------------------------------------------------
// `POST /v1/access/scan`
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub target_branch: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub files: Vec<ScanFileInput>,
}

#[derive(Debug, Deserialize)]
pub struct ScanFileInput {
    pub path: String,
    #[serde(default)]
    pub content: String,
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn short_ref(name: &str) -> &str {
    name.strip_prefix("refs/heads/")
        .or_else(|| name.strip_prefix(crate::PRIVATE_REF_PREFIX))
        .unwrap_or(name)
}

/// Owner dry run of the firewall: given `files`, over those files (and `message`) as if they
/// landed on `target_branch` (or `branch`, or the default branch); given a `branch` other than
/// the target, over what publishing it would land; otherwise an audit of the default branch tip
/// itself (its public files and every instruction file).
pub async fn scan_handler(
    State(state): State<ServerState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<DeclassificationReport>, ApiErr> {
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let root = state.workspace_root.clone();
    let message = req.message.clone().unwrap_or_default();
    let branch = nonempty(req.branch);
    let target = nonempty(req.target_branch);
    let default_branch = crate::checked_out(&root).0;

    if !req.files.is_empty() {
        let on = target.or(branch).unwrap_or(default_branch);
        let files: Vec<ScanTargetFile> = req
            .files
            .into_iter()
            .map(|f| ScanTargetFile {
                path: f.path,
                content: f.content.into_bytes(),
                deleted: false,
            })
            .collect();
        let report = tokio::task::spawn_blocking(move || {
            let rev = crate::handlers_v1::resolve_branch_oid(&state.workspace_root, &on).ok();
            scan_change(
                &state,
                &policy,
                rev.as_deref(),
                short_ref(&on),
                // Scanned as a change crossing the boundary, whatever the branch is now.
                &Visibility::Public,
                &files,
                &message,
                true,
                false,
            )
        })
        .await
        .map_err(ise)?;
        return Ok(Json(report));
    }

    let target_ref = crate::handlers_v1::publish_target(&root, target.as_deref())?;
    let target_short = short_ref(&target_ref).to_owned();
    if let Some(branch) = branch.filter(|b| short_ref(b) != target_short) {
        let source_oid = crate::handlers_v1::resolve_branch_oid(&root, &branch)
            .map_err(|_| err_resp(StatusCode::NOT_FOUND, "ref not found"))?;
        let vault = build_vault_secret_index(&state);
        let approved = approved_instruction_map(&state);
        let report = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root);
            let tip = canon::tip_of(&root, &target_ref);
            let plan = plan_squash_declassify(
                &canonical,
                &policy,
                &source_oid,
                &target_ref,
                tip.as_deref(),
            )?;
            scan_squash_declassify(
                &canonical,
                &policy,
                &plan,
                &source_oid,
                &target_ref,
                tip.as_deref(),
                &message,
                &SquashFirewallInput {
                    vault: vault.as_ref(),
                    approved_instructions: Some(&approved),
                    actor_is_owner: true,
                    ..SquashFirewallInput::default()
                },
            )
        })
        .await
        .map_err(ise)?
        .map_err(ise)?;
        return Ok(Json(report));
    }

    // The default branch tip, audited as it stands.
    let vault = build_vault_secret_index(&state);
    let approved = approved_instruction_map(&state);
    let report = tokio::task::spawn_blocking(move || {
        let Some(tip) = canon::default_ref(&root).and_then(|r| canon::tip_of(&root, &r)) else {
            return DeclassificationReport::from_findings(Vec::new());
        };
        let messages: Vec<String> = if message.trim().is_empty() {
            Vec::new()
        } else {
            vec![message]
        };
        audit_tree(
            &root,
            &policy,
            &tip,
            &default_branch,
            &messages,
            vault.as_ref(),
            &approved,
        )
    })
    .await
    .map_err(ise)?;
    Ok(Json(report))
}

// ---------------------------------------------------------------------------------------------
// `/v1/quarantine*`
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct QuarantineFileStatus {
    pub path: String,
    pub sha256: String,
    pub pinned_sha256: Option<String>,
    pub approved_sha256: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
    /// `pinned`, `approved`, `flagged` or `unverified`.
    pub status: &'static str,
    pub findings: Vec<FirewallFinding>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineOverviewResponse {
    pub enforced: bool,
    pub tracked_files: Vec<QuarantineFileStatus>,
    pub pending_edits: Vec<PendingQuarantineEdit>,
    pub recent_overrides: Vec<FirewallOverrideRecord>,
}

/// The default branch's instruction files and what the quarantine makes of each, the held
/// edits, and the latest owner overrides.
pub async fn list_quarantine_handler(
    State(state): State<ServerState>,
) -> Result<Json<QuarantineOverviewResponse>, ApiErr> {
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let approvals = approved_instruction_entries(&state);
    let root = state.workspace_root.clone();
    let policy_bg = policy.clone();
    let tracked_files = tokio::task::spawn_blocking(move || {
        let policy = policy_bg;
        let Some(tip) = canon::default_ref(&root).and_then(|r| canon::tip_of(&root, &r)) else {
            return Vec::new();
        };
        let canonical = CanonicalGitRepo::open(&root);
        let hosts = policy.all_allowed_egress_hosts();
        let mut out = Vec::new();
        for (path, mode, oid) in tree_entries(&root, &tip) {
            let Ok(rp) = RepoPath::new(&path) else {
                continue;
            };
            if mode == GITLINK_MODE || !policy.is_instruction_file(&rp) {
                continue;
            }
            let Ok(object) = canonical.read_object(&oid) else {
                continue;
            };
            let pinned = policy.pinned_instruction_hash(&rp);
            let scan = scan_instruction_file(&path, &object.data, &hosts, pinned);
            let approved = approvals.get(&path);
            let pin_ok = pinned.is_none_or(|p| p.eq_ignore_ascii_case(&scan.sha256));
            let approved_matches =
                approved.is_some_and(|a| a.sha256.eq_ignore_ascii_case(&scan.sha256));
            let blocking = scan.findings.iter().any(|f| f.blocking);
            let status = if blocking && !(approved_matches && pin_ok) {
                "flagged"
            } else if pinned.is_some() && pin_ok {
                "pinned"
            } else if approved_matches {
                "approved"
            } else {
                "unverified"
            };
            out.push(QuarantineFileStatus {
                sha256: scan.sha256,
                pinned_sha256: pinned.map(str::to_owned),
                approved_sha256: approved.map(|a| a.sha256.clone()),
                approved_by: approved.map(|a| a.approved_by.clone()),
                approved_at: approved.map(|a| a.approved_at.clone()),
                status,
                findings: scan.findings,
                path,
            });
        }
        out
    })
    .await
    .map_err(ise)?;
    let (pending_edits, recent_overrides) = state
        .persisted
        .lock()
        .map(|st| {
            let recent: Vec<FirewallOverrideRecord> = st
                .firewall_overrides
                .iter()
                .rev()
                .take(RECENT_OVERRIDES)
                .cloned()
                .collect();
            (st.pending_quarantine_edits.clone(), recent)
        })
        .map_err(|_| ise("state lock poisoned"))?;
    Ok(Json(QuarantineOverviewResponse {
        enforced: policy.quarantine_enforced(),
        tracked_files,
        pending_edits,
        recent_overrides,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ApproveQuarantineRequest {
    #[serde(default)]
    pub pending_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub acknowledge_diff: bool,
    #[serde(default)]
    pub apply_commit: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ApproveQuarantineResponse {
    pub ok: bool,
    pub path: String,
    pub sha256: String,
    pub commit: Option<String>,
}

fn owner_identity(state: &ServerState, tag: &str) -> Result<DelegatedIdentity, ApiErr> {
    crate::directory::identity(state, &auth::actor_principal(), None, tag)
}

fn quarantine_audit(
    state: &ServerState,
    identity: &DelegatedIdentity,
    action: &str,
    decision: AuditDecision,
    target: &str,
    reason: String,
) {
    let mut ev = AuditEvent::now(identity, "premier-quarantine", action, decision, reason);
    ev.target = Some(target.to_owned());
    auth::audit(&state.audit_sink, ev);
}

/// Approve a held edit (and, by default, commit it onto its branch), or the instruction file at
/// `path` as it stands on the default branch.
pub async fn approve_quarantine_handler(
    State(state): State<ServerState>,
    Json(req): Json<ApproveQuarantineRequest>,
) -> Result<Json<ApproveQuarantineResponse>, ApiErr> {
    if !req.acknowledge_diff {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "approving an instruction file requires acknowledging its diff",
        ));
    }
    let reason = req.reason.trim().to_owned();
    if reason.chars().count() < 4 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "an approval needs a reason of at least 4 characters",
        ));
    }
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let me = owner_identity(&state, "quarantine-approve")?;
    let owner = auth::actor_principal();
    let root = state.workspace_root.clone();

    if let Some(id) = nonempty(req.pending_id) {
        let edit = state
            .persisted
            .lock()
            .map_err(|_| ise("state lock poisoned"))?
            .pending_quarantine_edits
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such held edit"))?;
        if edit.status != "pending" {
            return Err(err_resp(
                StatusCode::CONFLICT,
                format!("this edit was already {}", edit.status),
            ));
        }
        let rp = RepoPath::new(&edit.path)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
        let mut commit = None;
        if req.apply_commit.unwrap_or(true) {
            let current = blob_at(&root, &edit.branch, &edit.path).map(|b| sha256_hex(&b));
            if current != edit.base_sha256 {
                return Err(err_resp(
                    StatusCode::CONFLICT,
                    "the file changed on its branch since this edit was proposed: it was not applied",
                ));
            }
            let who = canon::committer(&state);
            let (state_bg, edit_bg) = (state.clone(), edit.clone());
            let done = tokio::task::spawn_blocking(move || {
                let root = &state_bg.workspace_root;
                let on_default = canon::default_ref(root).is_none_or(|d| d == edit_bg.branch);
                let before = on_default
                    .then(|| canon::DefaultTip::capture(root))
                    .flatten();
                let done = canon::commit_file(
                    root,
                    &edit_bg.branch,
                    None,
                    &rp,
                    Some(edit_bg.proposed_content.as_bytes()),
                    &edit_bg.commit_message,
                    &who,
                );
                state_bg.default_branch_moved(before);
                done
            })
            .await
            .map_err(ise)?
            .map_err(|e| match e {
                canon::CommitError::Moved => {
                    err_resp(StatusCode::CONFLICT, "the branch moved: try again")
                }
                canon::CommitError::Invalid(why) => err_resp(StatusCode::BAD_REQUEST, why),
                canon::CommitError::Internal(why) => ise(why),
            })?;
            commit = Some(done);
        }
        record_owner_instruction_approval(
            &state,
            &edit.path,
            &edit.proposed_content,
            &owner,
            &reason,
        )
        .map_err(ise)?;
        {
            let mut st = state
                .persisted
                .lock()
                .map_err(|_| ise("state lock poisoned"))?;
            if let Some(e) = st.pending_quarantine_edits.iter_mut().find(|e| e.id == id) {
                e.status = "approved".to_owned();
                e.decided_by = Some(owner.clone());
                e.decided_at = Some(Utc::now().to_rfc3339());
                e.decision_reason = Some(reason.clone());
            }
            save_state(&state.workspace_root, &st).map_err(ise)?;
        }
        quarantine_audit(
            &state,
            &me,
            "quarantine_edit_approved",
            AuditDecision::Allowed,
            &edit.path,
            format!(
                "owner approved held edit {id} (sha256 {}){}: {reason}",
                short(&edit.proposed_sha256),
                commit
                    .as_deref()
                    .map(|c| format!(", committed as {}", short(c)))
                    .unwrap_or_default()
            ),
        );
        return Ok(Json(ApproveQuarantineResponse {
            ok: true,
            path: edit.path,
            sha256: edit.proposed_sha256,
            commit,
        }));
    }

    let Some(path) = nonempty(req.path) else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "name a held edit (pending_id) or an instruction file (path)",
        ));
    };
    let rp = RepoPath::new(&path).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    if !policy.is_instruction_file(&rp) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("'{rp}' is not an instruction file"),
        ));
    }
    let bytes = canon::default_ref(&root)
        .and_then(|r| canon::tip_of(&root, &r))
        .and_then(|tip| blob_at(&root, &tip, rp.as_str()))
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such file on the default branch"))?;
    let sha256 = sha256_hex(&bytes);
    if let Some(expected) = nonempty(req.sha256)
        && !expected.eq_ignore_ascii_case(&sha256)
    {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "the file changed since it was reviewed: review it again",
        ));
    }
    let approval = ApprovedInstructionFile {
        path: rp.as_str().to_owned(),
        sha256: sha256.clone(),
        approved_by: owner.clone(),
        approved_at: Utc::now().to_rfc3339(),
        reason: reason.clone(),
        approved_content: String::from_utf8(bytes).ok(),
    };
    {
        let mut st = state
            .persisted
            .lock()
            .map_err(|_| ise("state lock poisoned"))?;
        st.approved_instructions
            .insert(approval.path.clone(), approval);
        save_state(&state.workspace_root, &st).map_err(ise)?;
    }
    quarantine_audit(
        &state,
        &me,
        "quarantine_file_approved",
        AuditDecision::Allowed,
        rp.as_str(),
        format!(
            "owner approved instruction file (sha256 {}): {reason}",
            short(&sha256)
        ),
    );
    Ok(Json(ApproveQuarantineResponse {
        ok: true,
        path: rp.as_str().to_owned(),
        sha256,
        commit: None,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RejectQuarantineRequest {
    #[serde(default)]
    pub pending_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// Reject a held edit, or revoke the approval of the instruction file at `path`.
pub async fn reject_quarantine_handler(
    State(state): State<ServerState>,
    Json(req): Json<RejectQuarantineRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let reason = req.reason.trim().to_owned();
    if reason.chars().count() < 4 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "a rejection needs a reason of at least 4 characters",
        ));
    }
    let me = owner_identity(&state, "quarantine-reject")?;
    let owner = auth::actor_principal();
    if let Some(id) = nonempty(req.pending_id) {
        let path = {
            let mut st = state
                .persisted
                .lock()
                .map_err(|_| ise("state lock poisoned"))?;
            let edit = st
                .pending_quarantine_edits
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such held edit"))?;
            if edit.status != "pending" {
                return Err(err_resp(
                    StatusCode::CONFLICT,
                    format!("this edit was already {}", edit.status),
                ));
            }
            edit.status = "rejected".to_owned();
            edit.decided_by = Some(owner);
            edit.decided_at = Some(Utc::now().to_rfc3339());
            edit.decision_reason = Some(reason.clone());
            let path = edit.path.clone();
            save_state(&state.workspace_root, &st).map_err(ise)?;
            path
        };
        quarantine_audit(
            &state,
            &me,
            "quarantine_edit_rejected",
            AuditDecision::Denied,
            &path,
            format!("owner rejected held edit {id}: {reason}"),
        );
        return Ok(Json(serde_json::json!({ "ok": true })));
    }
    let Some(path) = nonempty(req.path) else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "name a held edit (pending_id) or an instruction file (path)",
        ));
    };
    let removed = {
        let mut st = state
            .persisted
            .lock()
            .map_err(|_| ise("state lock poisoned"))?;
        let removed = st.approved_instructions.remove(&path).is_some();
        if removed {
            save_state(&state.workspace_root, &st).map_err(ise)?;
        }
        removed
    };
    if !removed {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            "that instruction file has no approval to revoke",
        ));
    }
    quarantine_audit(
        &state,
        &me,
        "quarantine_approval_revoked",
        AuditDecision::Denied,
        &path,
        format!("owner revoked the instruction file approval: {reason}"),
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}
