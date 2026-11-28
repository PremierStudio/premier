//! Repository state, workspace state paths, and vaults for `premier-server`.
//!
//! Zero C dependencies; uses temp-file + atomic rename for crash-safe persistence across restarts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use premier_core::{Readiness, Visibility};
use premier_overlay::OverlayManifest;
use premier_secrets::{
    AgeKeyWrapper, AgeSovereignBackend, CompositeSecretBackend, EnvKekWrapper,
    EnvelopeVaultBackend, KeyTransparencyLog, KeyWrapper, OnePasswordConnectConfig,
    OnePasswordConnectConnector, SecretBackend, SecretCoord, SecretError, SecretLayer,
    VaultKvConfig, VaultKvConnector, VaultTransitConfig, VaultTransitWrapper,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::PRIVATE_REF_PREFIX;

/// Whether a review comment is a plain note or a steering directive for an agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentKind {
    #[default]
    Comment,
    Steer,
}

/// Inline line comment persisted on a real `Change-Id` review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewComment {
    pub id: String,
    pub author: String,
    pub path: String,
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    pub body: String,
    pub created_at: String,
    /// The review round the comment was written against.
    #[serde(default)]
    pub round: Option<u32>,
    /// The round whose agent session addressed it.
    #[serde(default)]
    pub addressed_in_round: Option<u32>,
    #[serde(default)]
    pub kind: CommentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steer_session_id: Option<String>,
}

/// One chronological step of an agent session (start, command, egress, file change, exit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceStep {
    pub seq: u64,
    pub kind: String,
    pub timestamp: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub bytes_scrubbed: usize,
}

/// An agent's lane: its change set held on `refs/premier-lanes/<lane_id>`, rebased onto
/// `base_branch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLane {
    pub lane_id: String,
    pub lane_ref: String,
    pub base_branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_lane_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_oid: Option<String>,
    pub owner: String,
    #[serde(default)]
    pub agent_profile: String,
    pub visibility: Visibility,
    /// `active`, `rebased` or `conflicted`.
    pub status: String,
    #[serde(default)]
    pub conflicts: Vec<premier_git_bridge::LaneConflict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_session_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn default_true() -> bool {
    true
}

/// What one review round is: its commit, the session that made it, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRoundMeta {
    pub round: u32,
    pub commit_oid: String,
    #[serde(default)]
    pub base_commit: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub steering_prompt: Option<String>,
    #[serde(default)]
    pub addressed_comment_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub rebased_cleanly: bool,
    #[serde(default)]
    pub conflicts: Vec<premier_git_bridge::LaneConflict>,
    #[serde(default)]
    pub provenance: Option<CapturedProvenance>,
    pub created_at: String,
}

/// Real captured prompt/session provenance attached to a Change-Id review.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapturedProvenance {
    pub session_id: String,
    /// Whose session (or prompt) this is, e.g. `@mia`. The transcript is shown only to them and
    /// to owners; a record from before this field is owner-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    pub agent_profile: String,
    pub command: String,
    pub prompt_summary: String,
    pub tool_calls: Vec<String>,
    pub created_at: String,
    #[serde(default)]
    pub steps: Vec<ProvenanceStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    #[serde(default)]
    pub bytes_scrubbed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub egress_calls: usize,
    #[serde(default)]
    pub egress_blocked: usize,
}

/// Persisted real `Change-Id` review linked to an actual Git branch & commit OID on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReview {
    pub change_id: String,
    pub title: String,
    pub branch: String,
    pub base_ref: String,
    pub author: String,
    pub delegated_agent: Option<String>,
    pub visibility: Visibility,
    pub readiness: Readiness,
    pub round_oids: Vec<String>,
    pub comments: Vec<ReviewComment>,
    pub verdicts: BTreeMap<String, String>,
    pub provenance: Option<CapturedProvenance>,
    pub created_at: String,
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub rounds_meta: Vec<StoredRoundMeta>,
    /// The GitHub pull request this change was published as ([`crate::github`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_pr_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_pr_number: Option<u64>,
}

/// Metadata for a configured secret (NEVER stores raw plaintext!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetaEntry {
    pub env: String,
    pub backend: String,
    pub updated_at: String,
    pub rotated_count: u32,
}

/// Persistent workspace control-plane state stored in `.premier/state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub version: u32,
    #[serde(default)]
    pub branch_metadata: BTreeMap<String, (Visibility, Readiness)>,
    #[serde(default = "no_overlays")]
    pub overlays: OverlayManifest,
    #[serde(default)]
    pub reviews: Vec<StoredReview>,
    #[serde(default)]
    pub secret_meta: BTreeMap<String, SecretMetaEntry>,
    #[serde(default)]
    pub settings: WorkspaceSettings,
    /// Instruction files an owner approved, by repository path (Active Instruction Quarantine).
    #[serde(default)]
    pub approved_instructions: BTreeMap<String, ApprovedInstructionFile>,
    /// Instruction-file edits by members or agents held for an owner's decision.
    #[serde(default)]
    pub pending_quarantine_edits: Vec<PendingQuarantineEdit>,
    /// Owner overrides of a blocking declassification report, most recent last.
    #[serde(default)]
    pub firewall_overrides: Vec<FirewallOverrideRecord>,
    /// Parallel agent lanes (closed-loop steering).
    #[serde(default)]
    pub lanes: Vec<AgentLane>,
    /// Knock-on-the-door living policy learning (graduation suggestions and decisions).
    #[serde(default)]
    pub policy_learning: crate::policy_learning::PolicyLearningState,
    /// Hygiene insights the owner dismissed (insight id → dismissal time).
    #[serde(default)]
    pub dismissed_hygiene_insights: BTreeMap<String, String>,
}

/// An instruction file whose exact bytes (`sha256`) an owner reviewed and approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedInstructionFile {
    pub path: String,
    pub sha256: String,
    pub approved_by: String,
    pub approved_at: String,
    pub reason: String,
    /// The approved text, substituted into an agent workspace when the branch holds other bytes.
    #[serde(default)]
    pub approved_content: Option<String>,
}

/// An instruction-file edit the quarantine held instead of committing (`status`: `pending`,
/// `approved` or `rejected`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingQuarantineEdit {
    pub id: String,
    pub path: String,
    pub branch: String,
    pub proposed_by: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    pub proposed_sha256: String,
    pub proposed_content: String,
    #[serde(default)]
    pub base_sha256: Option<String>,
    pub commit_message: String,
    pub findings: Vec<premier_policy::FirewallFinding>,
    pub created_at: String,
    pub status: String,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_at: Option<String>,
    #[serde(default)]
    pub decision_reason: Option<String>,
}

/// An owner overriding exactly one blocking report (`report_digest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallOverrideRecord {
    pub id: String,
    pub action: String,
    pub target: String,
    pub owner: String,
    pub reason: String,
    pub report_digest: String,
    pub finding_ids: Vec<String>,
    pub created_at: String,
}

/// Branch metadata keyed by full ref name (`refs/heads/x`, `refs/premier-private/x`), which is how it
/// is written now.
///
/// Entries written before that used the short branch name, which does not say which namespace it
/// meant. A short `x` resolves the fail-closed way: a non-public entry covers both
/// `refs/heads/x` and `refs/premier-private/x`, a public one only `refs/heads/x`. An entry under the
/// full name always wins.
pub fn full_ref_metadata(
    raw: &BTreeMap<String, (Visibility, Readiness)>,
) -> BTreeMap<String, (Visibility, Readiness)> {
    let (full, short): (Vec<_>, Vec<_>) = raw.iter().partition(|(k, _)| k.starts_with("refs/"));
    let mut out = BTreeMap::new();
    for (name, meta) in short {
        out.insert(format!("refs/heads/{name}"), meta.clone());
        if meta.0 != Visibility::Public {
            out.insert(format!("{PRIVATE_REF_PREFIX}{name}"), meta.clone());
        }
    }
    out.extend(full.into_iter().map(|(k, v)| (k.clone(), v.clone())));
    out
}

/// Owner-editable workspace settings (`GET`/`PATCH /v1/settings`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// Days of audit history kept on disk; `None` keeps it forever.
    #[serde(default)]
    pub audit_retention_days: Option<u32>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: 1,
            branch_metadata: BTreeMap::new(),
            overlays: no_overlays(),
            reviews: Vec::new(),
            secret_meta: BTreeMap::new(),
            settings: WorkspaceSettings::default(),
            approved_instructions: BTreeMap::new(),
            pending_quarantine_edits: Vec::new(),
            firewall_overrides: Vec::new(),
            lanes: Vec::new(),
            policy_learning: crate::policy_learning::PolicyLearningState::default(),
            dismissed_hygiene_insights: BTreeMap::new(),
        }
    }
}

fn no_overlays() -> OverlayManifest {
    OverlayManifest {
        version: 1,
        entries: Vec::new(),
    }
}

/// Where one repository's server state lives when the server runs with `--state-dir`.
#[derive(Clone)]
struct Binding {
    root: PathBuf,
    repo: PathBuf,
    /// Only the default repository has the account store.
    account: Option<PathBuf>,
}

/// Workspace root -> its state outside the working tree. Per workspace (not one global) so
/// every repository of a server, and every test in a process, resolves on its own.
static BINDINGS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<PathBuf, Binding>>,
> = std::sync::LazyLock::new(Default::default);

fn binding(workspace_root: &Path) -> Option<Binding> {
    BINDINGS.read().ok()?.get(workspace_root).cloned()
}

/// Files of the default repository's state that are the server's accounts, not the repository's.
pub(crate) const ACCOUNT_FILES: [&str; 7] = [
    "auth.json",
    crate::db::AUTH_KEY,
    "directory.json",
    "repos.json",
    "ssh_host_ed25519.key",
    "oidc.key",
    "oidc_revoked.json",
];
const LEGACY_STATE: &str = ".premier";
const LEGACY_AUDIT: &str = ".premier-local/audit.jsonl";
pub(crate) const LEGACY_AUDIT_HEAD: &str = ".premier-local/audit.jsonl.head";

/// The file in a repository's `.git` directory holding its stable id. State is keyed by it, not
/// by the name it is served under, which can change. Nothing in `.git` is ever served or projected.
const ID_FILE: &str = "premier-id";
/// `<state_root>/repo-index.json`: name -> id, for people reading the state directory. Never
/// consulted to find state.
const ID_INDEX: &str = "repo-index.json";

fn read_repo_id(git_dir: &Path) -> Option<String> {
    let id = std::fs::read_to_string(git_dir.join(ID_FILE)).ok()?;
    let id = id.trim();
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_owned())
}

/// Give the repository in `workspace_root` a new id, replacing any it had: a repository the
/// server just created or imported, so it never takes over state another one left behind.
pub(crate) fn new_repo_id(workspace_root: &Path) -> Result<String, String> {
    let id: String = crate::auth::random_bytes(16)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    premier_secrets::write_private(&workspace_root.join(".git").join(ID_FILE), id.as_bytes())
        .map_err(|e| format!("could not write the repository id: {e}"))?;
    Ok(id)
}

/// The directory name under `<state_root>/repos/` for this repository: its id, made on first use.
/// The first time, state an earlier server kept under its `name` is adopted (moved to the id).
// shortcut: without a `.git` directory yet (a restore binds before it clones; a linked worktree
// has a `.git` file) the state stays keyed by name until a later start gives it an id.
fn state_key(workspace_root: &Path, state_root: &Path, name: &str) -> String {
    let git_dir = workspace_root.join(".git");
    if !git_dir.is_dir() {
        return name.to_owned();
    }
    if let Some(id) = read_repo_id(&git_dir) {
        return id;
    }
    let by_name = state_root.join("repos").join(name);
    let Ok(id) = new_repo_id(workspace_root) else {
        return name.to_owned();
    };
    if by_name.is_dir() && move_state(&by_name, &state_root.join("repos").join(&id)).is_err() {
        // Keep using what is there rather than start an empty vault beside it.
        let _ = std::fs::remove_file(git_dir.join(ID_FILE));
        return name.to_owned();
    }
    id
}

/// Keep the server state of the repository in `workspace_root` under `state_root` from now on:
/// `<state_root>/repos/<id>/` ([`state_key`]), and for the default repository the accounts in
/// `<state_root>/account/`. Nothing server-owned is then written into the working tree.
pub fn bind_state_dir(workspace_root: &Path, state_root: &Path, name: &str, default: bool) {
    let key = state_key(workspace_root, state_root, name);
    if key != name {
        // shortcut: read-modify-write without a lock; two binds racing can drop an index entry,
        // which only a reader of the state directory would notice.
        let mut index: BTreeMap<String, String> = load_json_in(state_root, ID_INDEX);
        if index.get(name) != Some(&key) {
            index.insert(name.to_owned(), key.clone());
            let _ = save_json_in(state_root, ID_INDEX, &index);
        }
    }
    let binding = Binding {
        root: state_root.to_path_buf(),
        repo: state_root.join("repos").join(key),
        account: default.then(|| state_root.join("account")),
    };
    if let Ok(mut all) = BINDINGS.write() {
        all.insert(workspace_root.to_path_buf(), binding);
    }
}

/// Delete a repository's state directory and its index entry, and forget the binding.
pub(crate) fn remove_state_dir(workspace_root: &Path) {
    let Some(b) = binding(workspace_root) else {
        return;
    };
    let _ = std::fs::remove_dir_all(&b.repo);
    let mut index: BTreeMap<String, String> = load_json_in(&b.root, ID_INDEX);
    let before = index.len();
    index.retain(|_, id| Some(id.as_str()) != b.repo.file_name().and_then(|n| n.to_str()));
    if index.len() != before {
        let _ = save_json_in(&b.root, ID_INDEX, &index);
    }
    unbind_state_dir(workspace_root);
}

pub(crate) fn unbind_state_dir(workspace_root: &Path) {
    if let Ok(mut all) = BINDINGS.write() {
        all.remove(workspace_root);
    }
}

/// The configured state directory this workspace's state lives under; `None`: in the workspace.
pub fn state_root(workspace_root: &Path) -> Option<PathBuf> {
    binding(workspace_root).map(|b| b.root)
}

/// THE resolver of where a repository's server state is: state file, vault, age key, approvals,
/// sessions, markers. Without a state directory, `<workspace>/.premier` (a local checkout).
pub fn state_dir(workspace_root: &Path) -> PathBuf {
    binding(workspace_root).map_or_else(|| workspace_root.join(LEGACY_STATE), |b| b.repo)
}

/// Where the accounts, principal directory and repository list are ([`ACCOUNT_FILES`]).
pub fn account_dir(account_root: &Path) -> PathBuf {
    match binding(account_root) {
        Some(b) => b.account.unwrap_or(b.repo),
        None => account_root.join(LEGACY_STATE),
    }
}

/// The repository's audit log.
pub fn audit_path(workspace_root: &Path) -> PathBuf {
    binding(workspace_root).map_or_else(
        || workspace_root.join(LEGACY_AUDIT),
        |b| b.repo.join("audit.jsonl"),
    )
}

pub(crate) fn audit_head_path(audit_log: &Path) -> PathBuf {
    let mut path = audit_log.as_os_str().to_os_string();
    path.push(".head");
    path.into()
}

/// The repository's (or standalone server's) agent-trace JSONL store.
pub fn traces_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("traces.jsonl")
}

/// Where a backup entry (`.premier/<file>`, `.premier-local/audit.jsonl`) lives on this server;
/// `None` for anything else. Archive names never change, so old archives restore anywhere.
pub(crate) fn locate_backup_entry(workspace_root: &Path, rel: &Path) -> Option<PathBuf> {
    if rel == Path::new(LEGACY_AUDIT) {
        return Some(audit_path(workspace_root));
    }
    if rel == Path::new(LEGACY_AUDIT_HEAD) {
        return Some(audit_head_path(&audit_path(workspace_root)));
    }
    let inner = rel.strip_prefix(LEGACY_STATE).ok()?;
    let account = inner
        .to_str()
        .is_some_and(|name| ACCOUNT_FILES.contains(&name));
    let dir = if account {
        account_dir(workspace_root)
    } else {
        state_dir(workspace_root)
    };
    Some(dir.join(inner))
}

/// Move a state file or directory: a rename where possible, else (another filesystem, as from a
/// bind mount to a volume) copy then delete.
fn move_state(from: &Path, to: &Path) -> std::io::Result<()> {
    fn copy(from: &Path, to: &Path) -> std::io::Result<()> {
        let kind = std::fs::symlink_metadata(from)?.file_type();
        if kind.is_dir() {
            std::fs::create_dir_all(to)?;
            for entry in std::fs::read_dir(from)? {
                let entry = entry?;
                copy(&entry.path(), &to.join(entry.file_name()))?;
            }
            Ok(())
        } else if kind.is_file() {
            premier_secrets::write_private(to, &std::fs::read(from)?)
        } else {
            // State holds plain files only: a link there is not ours to read through.
            Err(std::io::Error::other(format!(
                "{} is not a regular file",
                from.display()
            )))
        }
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy(from, to)?;
    if from.is_dir() {
        std::fs::remove_dir_all(from)
    } else {
        std::fs::remove_file(from)
    }
}

/// One-time move of the state an earlier server left inside the working tree (`.premier/*`,
/// `.premier-local/audit.jsonl`) into this workspace's bound state directory. Only when that has
/// nothing yet: never a merge. Returns what moved. `.premier/repos` (the other repositories'
/// working trees) is not state and is left for the caller.
pub(crate) fn adopt_legacy_state(workspace_root: &Path) -> Result<Vec<String>, String> {
    let Some(b) = binding(workspace_root) else {
        return Ok(vec![]);
    };
    if b.repo.exists() || b.account.as_ref().is_some_and(|a| a.exists()) {
        return Ok(vec![]);
    }
    let legacy = workspace_root.join(LEGACY_STATE);
    let mut moved = Vec::new();
    let failed = |what: &Path, e: std::io::Error| {
        format!(
            "moving {} into the state directory failed: {e}",
            what.display()
        )
    };
    let legacy_db = legacy.join(crate::db::DB_FILE);
    if legacy_db.exists() {
        let temp = tempfile::tempdir().map_err(|e| failed(&legacy_db, e))?;
        let snapshot = temp.path().join(crate::db::DB_FILE);
        crate::db::StateDb::snapshot(&legacy_db, &snapshot)?;
        let mut repo = crate::db::StateDb::open(&b.repo)?;
        repo.import_scope(&snapshot, crate::db::Scope::Repo)?;
        if let Some(account) = &b.account {
            crate::db::StateDb::open(account)?.import_scope(&snapshot, crate::db::Scope::Auth)?;
        }
    }
    for entry in std::fs::read_dir(&legacy).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == crate::repos::REPOS_DIR
            || name == crate::db::DB_FILE
            || crate::db::SIDECARS.contains(&name.as_str())
        {
            continue;
        }
        if name == ".gitignore" {
            let _ = std::fs::remove_file(entry.path());
            continue;
        }
        let dir = match &b.account {
            Some(account) if ACCOUNT_FILES.contains(&name.as_str()) => account,
            _ => &b.repo,
        };
        move_state(&entry.path(), &dir.join(&name)).map_err(|e| failed(&entry.path(), e))?;
        moved.push(format!("{LEGACY_STATE}/{name}"));
    }
    let audit = workspace_root.join(LEGACY_AUDIT);
    for (name, dest) in [
        (LEGACY_AUDIT, "audit.jsonl"),
        (LEGACY_AUDIT_HEAD, "audit.jsonl.head"),
    ] {
        let src = workspace_root.join(name);
        if std::fs::symlink_metadata(&src).is_ok_and(|metadata| metadata.is_file()) {
            move_state(&src, &b.repo.join(dest)).map_err(|e| failed(&src, e))?;
            moved.push(name.to_owned());
        }
    }
    if legacy_db.exists() {
        std::fs::remove_file(&legacy_db).map_err(|e| failed(&legacy_db, e))?;
        for name in crate::db::SIDECARS {
            match std::fs::remove_file(legacy.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(failed(&legacy.join(name), e)),
            }
        }
        moved.push(format!("{LEGACY_STATE}/{}", crate::db::DB_FILE));
    }
    // Gone when nothing else is left in them.
    let _ = std::fs::remove_dir(&legacy);
    if let Some(local) = audit.parent() {
        let only_ignore = std::fs::read_dir(local)
            .is_ok_and(|mut d| d.all(|e| e.is_ok_and(|e| e.file_name() == ".gitignore")));
        if only_ignore {
            let _ = std::fs::remove_dir_all(local);
        }
    }
    Ok(moved)
}

pub fn state_file_path(workspace_root: &Path) -> PathBuf {
    let dir = state_dir(workspace_root);
    let db = dir.join(crate::db::DB_FILE);
    if db.exists() {
        db
    } else {
        dir.join("state.json")
    }
}

/// Whether the workspace has a SQLite control-plane store.
pub fn has_state_db(workspace_root: &Path) -> Result<bool, String> {
    let path = state_dir(workspace_root).join(crate::db::DB_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("read {} failed: {e}", path.display())),
    }
}

pub fn load_state(workspace_root: &Path) -> Result<PersistedState, String> {
    let dir = state_dir(workspace_root);
    for file in [crate::db::DB_FILE, "state.json"] {
        let path = dir.join(file);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return crate::db::StateDb::open(&dir)?.repo_state(&dir, None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("read {} failed: {e}", path.display())),
        }
    }
    Ok(PersistedState::default())
}

pub fn save_state(workspace_root: &Path, state: &PersistedState) -> Result<(), String> {
    let dir = state_dir(workspace_root);
    crate::db::StateDb::open(&dir)?.repo_state(&dir, Some(state))?;
    Ok(())
}

/// Read state file `<name>`; a missing or unreadable file is the type's default.
pub fn load_json<T: serde::de::DeserializeOwned + Default>(workspace_root: &Path, name: &str) -> T {
    load_json_in(&state_dir(workspace_root), name)
}

pub(crate) fn load_json_in<T: serde::de::DeserializeOwned + Default>(dir: &Path, name: &str) -> T {
    let path = dir.join(name);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return T::default();
    };
    match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "corrupt JSON state file; falling back to default"
            );
            T::default()
        }
    }
}

/// Write state file `<name>` crash-safely (temp file + atomic rename).
pub fn save_json<T: Serialize>(workspace_root: &Path, name: &str, value: &T) -> Result<(), String> {
    save_json_in(&state_dir(workspace_root), name, value)
}

pub(crate) fn save_json_in<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<(), String> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    premier_secrets::create_state_dir(dir).map_err(|e| format!("create state dir failed: {e}"))?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{name}.tmp.{}.{seq}", std::process::id()));
    let json =
        serde_json::to_string_pretty(value).map_err(|e| format!("serialize {name} failed: {e}"))?;
    premier_secrets::write_private(&tmp, json.as_bytes())
        .map_err(|e| format!("write {name} tmp failed: {e}"))?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| format!("atomic rename {name} failed: {e}"))
}

/// Path to the workspace-local `age` X25519 identity at `.premier/age.key`.
pub fn age_key_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("age.key")
}

fn parse_age_identity(raw: &str, key_path: &Path) -> Result<age::x25519::Identity, String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("AGE-SECRET-KEY-") {
            return trimmed
                .parse::<age::x25519::Identity>()
                .map_err(|e| format!("invalid age key: {e}"));
        }
    }
    Err(format!(
        "existing age key at {} is corrupt or missing an AGE-SECRET-KEY entry; refusing to overwrite",
        key_path.display()
    ))
}

/// Load or initialize the workspace-local `age` X25519 identity at `.premier/age.key`.
///
/// Fails closed if `age.key` exists but cannot be read or parsed (never overwrites an existing
/// key), and uses `OpenOptions::create_new(true)` with retry-read on `AlreadyExists` to prevent
/// concurrent creation races.
pub fn load_or_create_workspace_age_identity(
    workspace_root: &Path,
) -> Result<age::x25519::Identity, String> {
    let dir = state_dir(workspace_root);
    premier_secrets::create_state_dir(&dir)
        .map_err(|e| format!("create .premier dir failed: {e}"))?;
    let key_path = age_key_path(workspace_root);
    match std::fs::read_to_string(&key_path) {
        Ok(raw) => return parse_age_identity(&raw, &key_path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read age key failed: {e}")),
    }

    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let secret_str = id.to_string();
    let content = format!(
        "# Premier Local Sovereign Age Identity (never commit)\n# public: {}\n{}\n",
        id.to_public(),
        secret_str.expose_secret()
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&key_path) {
        Ok(mut file) => {
            use std::io::Write;
            if let Err(e) = file
                .write_all(content.as_bytes())
                .and_then(|()| file.sync_all())
            {
                let _ = std::fs::remove_file(&key_path);
                return Err(format!("write age key failed: {e}"));
            }
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut last_err = String::new();
            for attempt in 0..20 {
                match std::fs::read_to_string(&key_path) {
                    Ok(raw) => match parse_age_identity(&raw, &key_path) {
                        Ok(existing) => return Ok(existing),
                        Err(err) => last_err = err,
                    },
                    Err(err) => last_err = format!("read age key failed: {err}"),
                }
                if attempt + 1 < 20 {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            Err(last_err)
        }
        Err(e) => Err(format!("create age key failed: {e}")),
    }
}

/// Stable path-independent logical AAD path for workspace Sovereign `age` vaults.
const WORKSPACE_VAULT_LOGICAL_PATH: &str = ".premier/vault.toml";
/// Stable path-independent logical AAD path for dedicated GitHub Companion Sovereign `age` vaults.
const GITHUB_VAULT_LOGICAL_PATH: &str = ".premier/github.vault.toml";

/// The workspace's Key Transparency log, shared by its `age` and envelope vaults.
pub fn kt_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("key_transparency.jsonl")
}

/// The workspace's Envelope KMS vault file (present once the workspace uses envelope mode).
pub fn envelope_vault_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("vault.envelope.toml")
}

/// The workspace's Sovereign `age` vault file.
pub fn age_vault_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("vault.toml")
}

/// The workspace's dedicated GitHub Companion Sovereign `age` vault file.
pub fn github_age_vault_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("github.vault.toml")
}

/// The workspace's dedicated GitHub Companion Envelope KMS vault file.
pub fn github_envelope_vault_path(workspace_root: &Path) -> PathBuf {
    state_dir(workspace_root).join("github.vault.envelope.toml")
}

/// Open a Sovereign `age` vault using a path-independent logical AAD path so backups restore
/// cleanly to any host directory, with read-fallback for legacy absolute-path vaults.
fn open_age_vault_with_fallback(
    workspace_root: &Path,
    vault_path: &Path,
    repo_id: &str,
    stable_logical_path: &str,
) -> Result<AgeSovereignBackend, String> {
    let id = load_or_create_workspace_age_identity(workspace_root)?;
    let stable =
        AgeSovereignBackend::new(vault_path, repo_id, stable_logical_path, id.clone(), vec![]);
    if !vault_path.exists() {
        return Ok(stable);
    }
    if let Err(SecretError::Crypto(_)) = stable.list_entries() {
        let mut candidates = Vec::new();
        let current_abs = vault_path.to_string_lossy().into_owned();
        if current_abs != stable_logical_path {
            candidates.push(current_abs);
        }
        if let Ok(entries) = KeyTransparencyLog::open(kt_path(workspace_root)).entries() {
            for entry in entries.into_iter().rev() {
                if entry.repo_id == repo_id
                    && entry.vault_path != stable_logical_path
                    && !candidates.contains(&entry.vault_path)
                {
                    candidates.push(entry.vault_path);
                }
            }
        }
        for legacy_path in candidates {
            let candidate =
                AgeSovereignBackend::new(vault_path, repo_id, legacy_path, id.clone(), vec![]);
            if candidate.list_entries().is_ok() {
                return Ok(candidate);
            }
        }
    }
    Ok(stable)
}

/// Build the workspace's real encrypted `AgeSovereignBackend` (`.premier/vault.toml`), bound into
/// the workspace's Key Transparency log (a silent recipient swap fails closed).
pub fn open_workspace_vault(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<AgeSovereignBackend, String> {
    Ok(open_workspace_age_vault(workspace_root, repo_id)?
        .with_key_transparency(kt_path(workspace_root)))
}

/// [`open_workspace_vault`] without the Key Transparency check (only after one passed).
pub(crate) fn open_workspace_age_vault(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<AgeSovereignBackend, String> {
    let vault_path = age_vault_path(workspace_root);
    open_age_vault_with_fallback(
        workspace_root,
        &vault_path,
        repo_id,
        WORKSPACE_VAULT_LOGICAL_PATH,
    )
}

pub(crate) fn open_github_age_vault(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<AgeSovereignBackend, String> {
    let vault_path = github_age_vault_path(workspace_root);
    open_age_vault_with_fallback(
        workspace_root,
        &vault_path,
        repo_id,
        GITHUB_VAULT_LOGICAL_PATH,
    )
}

/// Composite key for `PersistedState::secret_meta` scoping metadata by environment and variable.
pub fn secret_meta_key(env: &str, var_name: &str) -> String {
    format!("{env}:{var_name}")
}

/// Look up secret metadata by `"{env}:{var_name}"`, falling back to legacy bare `var_name` key.
pub fn get_secret_meta<'a>(
    meta: &'a BTreeMap<String, SecretMetaEntry>,
    env: &str,
    var_name: &str,
) -> Option<&'a SecretMetaEntry> {
    meta.get(&secret_meta_key(env, var_name))
        .or_else(|| meta.get(var_name).filter(|m| m.env == env))
}

/// Every secret value in the workspace vault (sovereign `age` or envelope KMS), for keyed leak
/// detection. Empty when the workspace has no vault: never creates one (or its age key) as a side
/// effect.
pub fn load_vault_secrets_zeroizing(
    workspace_root: &Path,
    repo_id: &str,
) -> Vec<(String, zeroize::Zeroizing<String>)> {
    if !age_vault_path(workspace_root).exists() && !envelope_vault_path(workspace_root).exists() {
        return Vec::new();
    }
    open_workspace_vault_backend(workspace_root, repo_id)
        .ok()
        .and_then(|vault| vault.list_entries().ok())
        .map(|entries| {
            entries
                .into_iter()
                .map(|(key, value)| {
                    let var_name = key.rsplit(':').next().unwrap_or(&key).to_owned();
                    (var_name, value)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The workspace vault: an Envelope KMS vault, or the Sovereign `age` one.
pub enum WorkspaceVault {
    Envelope(EnvelopeVaultBackend),
    Age(AgeSovereignBackend),
}

impl WorkspaceVault {
    /// What `secret_meta` records as the entry's backend.
    pub fn backend_label(&self) -> &'static str {
        match self {
            Self::Envelope(_) => "envelope-kms",
            Self::Age(_) => "age-aead",
        }
    }

    fn inner(&self) -> &dyn SecretBackend {
        match self {
            Self::Envelope(b) => b,
            Self::Age(b) => b,
        }
    }

    /// Decrypt every entry (storage key -> value).
    pub fn list_entries(&self) -> Result<BTreeMap<String, Zeroizing<String>>, SecretError> {
        match self {
            Self::Envelope(b) => b.list_entries(),
            Self::Age(b) => b.list_entries(),
        }
    }
}

impl SecretBackend for WorkspaceVault {
    fn name(&self) -> &str {
        self.inner().name()
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        self.inner().get(coord)
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        self.inner().set(coord, value)
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        self.inner().delete(coord)
    }
}

fn env_set(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// PEM of extra trusted roots for self-hosted Vault / 1Password Connect (`PREMIER_VAULT_CACERT`).
fn extra_roots_pem() -> Result<Option<Vec<u8>>, String> {
    env_set("PREMIER_VAULT_CACERT")
        .map(|path| {
            std::fs::read(path).map_err(|e| format!("read PREMIER_VAULT_CACERT failed: {e}"))
        })
        .transpose()
}

/// True when an external KEK (Vault Transit, or `PREMIER_KMS_KEY` / `PREMIER_KMS_URI`) is set.
pub fn env_kms_configured() -> bool {
    (env_set("PREMIER_VAULT_TRANSIT_ADDR").is_some() && env_set("PREMIER_VAULT_TOKEN").is_some())
        || env_set(premier_secrets::PREMIER_KMS_KEY_ENV).is_some()
        || env_set(premier_secrets::PREMIER_KMS_URI_ENV).is_some()
}

/// True when an external read-through secret backend (HashiCorp Vault KV or 1Password Connect) is
/// configured in the process environment.
pub fn external_vault_configured() -> bool {
    (env_set("PREMIER_VAULT_KV_ADDR").is_some() && env_set("PREMIER_VAULT_TOKEN").is_some())
        || (env_set("PREMIER_OP_CONNECT_HOST").is_some()
            && env_set("PREMIER_OP_CONNECT_VAULT").is_some()
            && env_set("PREMIER_OP_CONNECT_TOKEN").is_some())
}

/// True when a local workspace vault (`vault.toml` or `vault.envelope.toml`) exists on disk or an
/// external read-through vault connector is configured.
pub fn has_workspace_vault_or_external(workspace_root: &Path) -> bool {
    age_vault_path(workspace_root).exists()
        || envelope_vault_path(workspace_root).exists()
        || external_vault_configured()
}

/// The KEK the workspace envelope vault is wrapped under, and whether it lives outside the state
/// directory: Vault Transit, else an env/file KEK, else the workspace `age` identity.
pub fn workspace_key_wrapper(workspace_root: &Path) -> Result<(Arc<dyn KeyWrapper>, bool), String> {
    if let (Some(address), Some(token)) = (
        env_set("PREMIER_VAULT_TRANSIT_ADDR"),
        env_set("PREMIER_VAULT_TOKEN"),
    ) {
        let mut config = VaultTransitConfig {
            address,
            mount: env_set("PREMIER_VAULT_TRANSIT_MOUNT").unwrap_or_else(|| "transit".to_owned()),
            key_name: env_set("PREMIER_VAULT_TRANSIT_KEY")
                .unwrap_or_else(|| "premier-kek".to_owned()),
            token: Zeroizing::new(token),
            namespace: env_set("PREMIER_VAULT_NAMESPACE"),
            allow_insecure_loopback: false,
            extra_root_certs: Vec::new(),
        };
        if let Some(pem) = extra_roots_pem()? {
            config.extra_root_certs =
                premier_secrets::parse_pem_certificates(&pem).map_err(|e| e.to_string())?;
        }
        let wrapper =
            VaultTransitWrapper::new(config).map_err(|e| format!("Vault Transit KEK: {e}"))?;
        return Ok((Arc::new(wrapper), true));
    }
    if env_set(premier_secrets::PREMIER_KMS_KEY_ENV).is_some()
        || env_set(premier_secrets::PREMIER_KMS_URI_ENV).is_some()
    {
        let wrapper = EnvKekWrapper::from_process_env(Some(&state_dir(workspace_root)))
            .map_err(|e| format!("KMS KEK: {e}"))?;
        return Ok((Arc::new(wrapper), true));
    }
    let identity = load_or_create_workspace_age_identity(workspace_root)?;
    Ok((Arc::new(AgeKeyWrapper::new(identity, vec![])), false))
}

/// The workspace vault this server reads and writes: envelope mode when an external KEK is
/// configured or the workspace was migrated, else the Sovereign `age` vault.
pub fn open_workspace_vault_backend(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<WorkspaceVault, String> {
    open_workspace_vault_backend_with_kms(workspace_root, repo_id, env_kms_configured())
}

pub(crate) fn open_workspace_vault_backend_with_kms(
    workspace_root: &Path,
    repo_id: &str,
    kms_configured: bool,
) -> Result<WorkspaceVault, String> {
    let envelope = envelope_vault_path(workspace_root);
    let age = age_vault_path(workspace_root);
    if !kms_configured && !envelope.exists() {
        return open_workspace_vault(workspace_root, repo_id).map(WorkspaceVault::Age);
    }
    if !envelope.exists() && age.exists() {
        return Err(
            "external KMS is configured while an un-migrated sovereign vault.toml exists; migrate first via POST /v1/secrets/kms/migrate or `premier env kms migrate`"
                .to_owned(),
        );
    }
    let (wrapper, separated) = workspace_key_wrapper(workspace_root)?;
    Ok(WorkspaceVault::Envelope(
        EnvelopeVaultBackend::new(envelope, repo_id, wrapper)
            .with_kek_separated(separated)
            .with_key_transparency(kt_path(workspace_root)),
    ))
}

/// The workspace vault with a read-through external fallback (HashiCorp Vault KV v2 or
/// 1Password Connect) when one is configured. Writes always stay in the workspace vault.
pub fn resolve_vault_backend(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<Arc<dyn SecretBackend>, String> {
    let primary: Arc<dyn SecretBackend> =
        Arc::new(open_workspace_vault_backend(workspace_root, repo_id)?);
    if let (Some(address), Some(token)) = (
        env_set("PREMIER_VAULT_KV_ADDR"),
        env_set("PREMIER_VAULT_TOKEN"),
    ) {
        let mut config = VaultKvConfig {
            address,
            mount: env_set("PREMIER_VAULT_KV_MOUNT").unwrap_or_else(|| "secret".to_owned()),
            prefix: env_set("PREMIER_VAULT_KV_PREFIX").unwrap_or_else(|| "premier".to_owned()),
            token: Zeroizing::new(token),
            namespace: env_set("PREMIER_VAULT_NAMESPACE"),
            allow_insecure_loopback: false,
            extra_root_certs: Vec::new(),
        };
        if let Some(pem) = extra_roots_pem()? {
            config.extra_root_certs =
                premier_secrets::parse_pem_certificates(&pem).map_err(|e| e.to_string())?;
        }
        let kv = VaultKvConnector::new(config).map_err(|e| format!("Vault KV connector: {e}"))?;
        return Ok(Arc::new(CompositeSecretBackend::new(primary, Arc::new(kv))));
    }
    if let (Some(host), Some(vault_id), Some(token)) = (
        env_set("PREMIER_OP_CONNECT_HOST"),
        env_set("PREMIER_OP_CONNECT_VAULT"),
        env_set("PREMIER_OP_CONNECT_TOKEN"),
    ) {
        let mut config = OnePasswordConnectConfig {
            host,
            vault_id,
            token: Zeroizing::new(token),
            allow_insecure_loopback: false,
            extra_root_certs: Vec::new(),
        };
        if let Some(pem) = extra_roots_pem()? {
            config.extra_root_certs =
                premier_secrets::parse_pem_certificates(&pem).map_err(|e| e.to_string())?;
        }
        let op = OnePasswordConnectConnector::new(config)
            .map_err(|e| format!("1Password Connect connector: {e}"))?;
        return Ok(Arc::new(CompositeSecretBackend::new(primary, Arc::new(op))));
    }
    Ok(primary)
}

/// Store or rotate a secret inside the encrypted `.premier/vault.toml` and update metadata.
pub fn set_workspace_secret(
    workspace_root: &Path,
    repo_id: &str,
    env: &str,
    var_name: &str,
    value: &str,
    state: &mut PersistedState,
) -> Result<SecretMetaEntry, String> {
    let vault = open_workspace_vault_backend(workspace_root, repo_id)?;
    let coord = SecretCoord {
        repo_id: repo_id.to_owned(),
        layer: SecretLayer::Env,
        scope: env.to_owned(),
        var_name: var_name.to_owned(),
    };
    vault
        .set(&coord, value)
        .map_err(|e| format!("vault encrypt/write failed: {e}"))?;

    let meta_key = secret_meta_key(env, var_name);
    let prev_rotations = get_secret_meta(&state.secret_meta, env, var_name)
        .map(|m| m.rotated_count)
        .unwrap_or(0);
    let entry = SecretMetaEntry {
        env: env.to_owned(),
        backend: vault.backend_label().to_owned(),
        updated_at: Utc::now().to_rfc3339(),
        rotated_count: prev_rotations + 1,
    };
    if state
        .secret_meta
        .get(var_name)
        .is_some_and(|m| m.env == env)
    {
        state.secret_meta.remove(var_name);
    }
    state.secret_meta.insert(meta_key, entry.clone());
    save_state(workspace_root, state)?;
    Ok(entry)
}

/// Delete / revoke a secret from `.premier/vault.toml` and remove its metadata.
pub fn delete_workspace_secret(
    workspace_root: &Path,
    repo_id: &str,
    env: &str,
    var_name: &str,
    state: &mut PersistedState,
) -> Result<(), String> {
    let vault = open_workspace_vault_backend(workspace_root, repo_id)?;
    let coord = SecretCoord {
        repo_id: repo_id.to_owned(),
        layer: SecretLayer::Env,
        scope: env.to_owned(),
        var_name: var_name.to_owned(),
    };
    vault
        .delete(&coord)
        .map_err(|e| format!("vault delete failed: {e}"))?;
    state.secret_meta.remove(&secret_meta_key(env, var_name));
    if state
        .secret_meta
        .get(var_name)
        .is_some_and(|m| m.env == env)
    {
        state.secret_meta.remove(var_name);
    }
    save_state(workspace_root, state)?;
    Ok(())
}

/// Vault repo id of the GitHub companion token: fixed, so editing `.env.schema` never orphans it.
pub const GITHUB_VAULT_REPO_ID: &str = "__premier_github__";
/// Vault scope of the GitHub companion token. It lives in its own dedicated vault file
/// (`github.vault.toml` or `github.vault.envelope.toml`), completely separate from workspace
/// secrets (`vault.toml` / `vault.envelope.toml`), eliminating `repo_id` collisions while
/// supporting Envelope KMS.
const GITHUB_TOKEN_SCOPE: &str = "__premier_github_companion__";
const GITHUB_TOKEN_VAR: &str = "GITHUB_COMPANION_TOKEN";

fn github_token_coord(repo_id: &str) -> SecretCoord {
    SecretCoord {
        repo_id: repo_id.to_owned(),
        layer: SecretLayer::Repo,
        scope: GITHUB_TOKEN_SCOPE.to_owned(),
        var_name: GITHUB_TOKEN_VAR.to_owned(),
    }
}

fn github_uses_envelope(workspace_root: &Path) -> bool {
    env_kms_configured()
        || github_envelope_vault_path(workspace_root).exists()
        || envelope_vault_path(workspace_root).exists()
}

/// Store (or replace) the GitHub companion token, encrypted in its dedicated vault
/// (`github.vault.envelope.toml` when Envelope KMS is active, else `github.vault.toml`).
pub fn store_github_token(workspace_root: &Path, repo_id: &str, token: &str) -> Result<(), String> {
    if github_uses_envelope(workspace_root) {
        let (wrapper, separated) = workspace_key_wrapper(workspace_root)?;
        let env_path = github_envelope_vault_path(workspace_root);
        let age_path = github_age_vault_path(workspace_root);
        if age_path.exists() && !env_path.exists() {
            // Verify the legacy GitHub age vault against KT before recording the KMS binding.
            let existing = open_github_age_vault(workspace_root, repo_id)?
                .with_key_transparency(kt_path(workspace_root));
            existing
                .list_entries()
                .map_err(|e| format!("github age vault verification failed: {e}"))?;
            let kt = KeyTransparencyLog::open(kt_path(workspace_root));
            let binding = vec![format!("{}:{}", wrapper.provider_name(), wrapper.key_id())];
            kt.append_binding(
                repo_id,
                GITHUB_VAULT_LOGICAL_PATH,
                &binding,
                "premier-server",
                "migrate_github_to_envelope",
            )
            .map_err(|e| format!("key transparency: {e}"))?;
        }
        let backend = EnvelopeVaultBackend::new(&env_path, repo_id, wrapper)
            .with_kek_separated(separated)
            .with_key_transparency(kt_path(workspace_root));
        backend
            .set(&github_token_coord(repo_id), token)
            .map_err(|e| format!("github vault encrypt/write failed: {e}"))?;
        if age_path.exists() {
            let _ = std::fs::remove_file(&age_path);
        }
        return Ok(());
    }
    let backend = open_github_age_vault(workspace_root, repo_id)?
        .with_key_transparency(kt_path(workspace_root));
    backend
        .set(&github_token_coord(repo_id), token)
        .map_err(|e| format!("github vault encrypt/write failed: {e}"))
}

/// The GitHub companion token, if one is stored.
pub fn load_github_token(
    workspace_root: &Path,
    repo_id: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    let env_path = github_envelope_vault_path(workspace_root);
    if env_path.exists() {
        let (wrapper, separated) = workspace_key_wrapper(workspace_root)?;
        let backend = EnvelopeVaultBackend::new(&env_path, repo_id, wrapper)
            .with_kek_separated(separated)
            .with_key_transparency(kt_path(workspace_root));
        return backend
            .get(&github_token_coord(repo_id))
            .map_err(|e| format!("github vault read failed: {e}"));
    }
    let age_path = github_age_vault_path(workspace_root);
    if age_path.exists() {
        let backend = open_github_age_vault(workspace_root, repo_id)?
            .with_key_transparency(kt_path(workspace_root));
        return backend
            .get(&github_token_coord(repo_id))
            .map_err(|e| format!("github vault read failed: {e}"));
    }
    // Read fallback for workspaces created before the dedicated GitHub vault file existed.
    if age_vault_path(workspace_root).exists()
        && let Ok(vault) = open_workspace_vault(workspace_root, repo_id)
        && let Ok(Some(token)) = vault.get(&github_token_coord(repo_id))
    {
        return Ok(Some(token));
    }
    Ok(None)
}

/// Remove the GitHub companion token from its dedicated vault (and any legacy entry).
pub fn delete_github_token(workspace_root: &Path, repo_id: &str) -> Result<(), String> {
    let env_path = github_envelope_vault_path(workspace_root);
    if env_path.exists() {
        let (wrapper, separated) = workspace_key_wrapper(workspace_root)?;
        let backend = EnvelopeVaultBackend::new(&env_path, repo_id, wrapper)
            .with_kek_separated(separated)
            .with_key_transparency(kt_path(workspace_root));
        backend
            .delete(&github_token_coord(repo_id))
            .map_err(|e| format!("github vault delete failed: {e}"))?;
    }
    let age_path = github_age_vault_path(workspace_root);
    if age_path.exists() {
        let backend = open_github_age_vault(workspace_root, repo_id)?
            .with_key_transparency(kt_path(workspace_root));
        backend
            .delete(&github_token_coord(repo_id))
            .map_err(|e| format!("github vault delete failed: {e}"))?;
    }
    if age_vault_path(workspace_root).exists()
        && let Ok(vault) = open_workspace_vault(workspace_root, repo_id)
    {
        let _ = vault.delete(&github_token_coord(repo_id));
    }
    Ok(())
}
