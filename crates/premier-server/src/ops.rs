//! Operating the single-owner deployment: workspace settings, audit query/export/retention,
//! backup + restore, and reloading approvals and agent sessions after a restart.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::Utc;
use premier_core::{AuditDecision, AuditEvent, DelegatedIdentity, Principal, RepoPath};
use premier_proxy::{ApprovalHub, ApprovalSnapshot};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::AuthUser;
use crate::db::{DB_FILE, SIDECARS, Scope, StateDb};
use crate::store::{WorkspaceSettings, account_dir, load_json, save_json, save_state, state_dir};
use crate::{ApiError, ServerState, err_resp};

type ApiErr = (StatusCode, Json<ApiError>);

/// Largest push body. It is buffered in memory once the push is admitted, so this is also the
/// RAM one push can pin (see `handlers_v1::PUSH_SLOTS`).
pub const GIT_BODY_LIMIT: usize = 512 * 1024 * 1024;
/// A fetch request (`git-upload-pack`) is a list of wants and haves, and may come from anyone.
pub const GIT_FETCH_BODY_LIMIT: usize = 1024 * 1024;
pub const JSON_BODY_LIMIT: usize = 4 * 1024 * 1024;

const APPROVALS_FILE: &str = "approvals.json";
const MAX_RETENTION_DAYS: u64 = 3650;
const MAX_AUDIT_LIMIT: usize = 2000;

/// Owner-only routes take a browser session, never an access token: same rule the auth gate
/// applies to `/v1/auth/*` account management.
pub(crate) fn require_session(user: &AuthUser, what: &str) -> Result<(), ApiErr> {
    if user.session_id.is_none() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            format!("{what} requires a browser session"),
        ));
    }
    Ok(())
}

fn ise(msg: impl Into<String>) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

fn attachment(content_type: &'static str, filename: &str, body: Body) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

fn today() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

// ---------------------------------------------------------------------------
// Workspace settings
// ---------------------------------------------------------------------------

/// `GET /v1/settings`: the stored settings plus read-only server facts clients display.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    #[serde(flatten)]
    settings: WorkspaceSettings,
    /// `--ssh-public-url`, for the "Clone over SSH" hint; `null` when not configured (clients
    /// then guess from their own origin).
    ssh_public_url: Option<String>,
}

pub async fn get_settings_handler(State(state): State<ServerState>) -> Json<SettingsView> {
    Json(SettingsView {
        settings: state
            .settings_state()
            .lock()
            .map(|g| g.settings.clone())
            .unwrap_or_default(),
        ssh_public_url: state.ssh_public_url.clone(),
    })
}

/// `PATCH /v1/settings`: every field optional; `"audit_retention_days": null` keeps forever.
pub async fn patch_settings_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(patch): Json<serde_json::Map<String, serde_json::Value>>,
) -> Result<Json<WorkspaceSettings>, ApiErr> {
    require_session(&user, "changing workspace settings")?;
    let mut guard = state
        .settings_state()
        .lock()
        .map_err(|_| ise("state lock poisoned"))?;
    let mut settings = guard.settings.clone();
    for (key, value) in &patch {
        match key.as_str() {
            "audit_retention_days" => {
                settings.audit_retention_days = match value {
                    serde_json::Value::Null => None,
                    v => Some(
                        v.as_u64()
                            .filter(|d| (1..=MAX_RETENTION_DAYS).contains(d))
                            .and_then(|d| u32::try_from(d).ok())
                            .ok_or_else(|| {
                                err_resp(
                                    StatusCode::BAD_REQUEST,
                                    "audit_retention_days must be null or an integer from 1 to 3650",
                                )
                            })?,
                    ),
                };
            }
            other => {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("unknown setting '{other}'"),
                ));
            }
        }
    }
    guard.settings = settings.clone();
    save_state(state.account_root(), &guard).map_err(ise)?;
    Ok(Json(settings))
}

// ---------------------------------------------------------------------------
// Audit query, export, retention
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
    pub q: Option<String>,
    pub principal: Option<String>,
    pub decision: Option<String>,
}

/// Filter `events` (already newest first) for `GET /v1/audit`.
pub fn filter_audit(events: Vec<AuditEvent>, query: &AuditQuery) -> Vec<AuditEvent> {
    let needle = query.q.as_deref().map(str::to_lowercase);
    // Accept the principal as stored (`user:alice`) or as typed in Studio (`@alice`).
    let principal = query.principal.as_deref().filter(|p| !p.is_empty());
    let canonical = principal.and_then(|p| Principal::parse(p).ok().map(|p| p.canonical_id()));
    let decision = query.decision.as_deref().filter(|d| !d.is_empty());
    let limit = query.limit.map_or(usize::MAX, |n| n.min(MAX_AUDIT_LIMIT));
    events
        .into_iter()
        .filter(|ev| {
            principal.is_none_or(|p| {
                ev.principal.eq_ignore_ascii_case(p)
                    || canonical.as_deref() == Some(ev.principal.as_str())
            })
        })
        .filter(|ev| {
            decision.is_none_or(|want| {
                serde_json::to_value(ev.decision)
                    .ok()
                    .and_then(|v| v.as_str().map(|have| have.eq_ignore_ascii_case(want)))
                    .unwrap_or(false)
            })
        })
        .filter(|ev| {
            needle.as_deref().is_none_or(|n| {
                serde_json::to_string(ev).is_ok_and(|json| json.to_lowercase().contains(n))
            })
        })
        .take(limit)
        .collect()
}

/// `GET /v1/audit/export`: the full on-disk log as NDJSON, streamed in chunks.
pub async fn audit_export_handler(State(state): State<ServerState>) -> Result<Response, ApiErr> {
    let body = match state.audit_sink.file_path() {
        Some(path) => match tokio::fs::File::open(path).await {
            Ok(mut file) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let chunk = match file.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => Ok(Bytes::copy_from_slice(&buf[..n])),
                            Err(e) => Err(e),
                        };
                        let failed = chunk.is_err();
                        if tx.send(chunk).await.is_err() || failed {
                            break;
                        }
                    }
                });
                Body::from_stream(ReceiverStream::new(rx))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Body::empty(),
            Err(e) => return Err(ise(format!("open audit log failed: {e}"))),
        },
        // No log file configured: export what the in-memory ring holds.
        None => Body::from(
            state
                .audit_sink
                .snapshot()
                .iter()
                .filter_map(|ev| serde_json::to_string(ev).ok())
                .map(|line| line + "\n")
                .collect::<String>(),
        ),
    };
    Ok(attachment(
        "application/x-ndjson",
        &format!("premier-audit-{}.jsonl", today()),
        body,
    ))
}

/// Drop on-disk audit events older than the configured retention (no-op when unset).
pub fn apply_audit_retention(state: &ServerState) {
    let days = state
        .settings_state()
        .lock()
        .ok()
        .and_then(|g| g.settings.audit_retention_days);
    let Some(days) = days else {
        return;
    };
    let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
    match state.audit_sink.prune_older_than(cutoff) {
        Ok(0) => {}
        Ok(dropped) => tracing::info!(dropped, days, "audit retention pruned old events"),
        Err(e) => tracing::warn!(error = %e, "audit retention failed"),
    }
}

// ---------------------------------------------------------------------------
// Restart persistence + background jobs
// ---------------------------------------------------------------------------

/// Rebuild the JIT approval hub from `.premier/approvals.json` (expired grants are dropped).
pub fn load_approvals(workspace_root: &Path) -> ApprovalHub {
    let hub = ApprovalHub::new();
    hub.restore(load_json::<ApprovalSnapshot>(
        workspace_root,
        APPROVALS_FILE,
    ));
    hub
}

/// Start approval persistence, audit metrics and audit retention jobs for this repository.
pub fn spawn_background(state: &ServerState) {
    // Subscribed before returning, so no approval made after this call is missed.
    let mut changes = state.approval_hub.subscribe();
    let hub = Arc::clone(&state.approval_hub);
    let root = state.workspace_root.clone();
    let mirror = tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        // A lagged receiver still means "something changed": the snapshot is always the full set.
        while !matches!(changes.recv().await, Err(RecvError::Closed)) {
            if let Err(e) = save_json(&root, APPROVALS_FILE, &hub.snapshot()) {
                tracing::warn!(error = %e, "failed to persist approvals");
            }
        }
    });

    let jobs = Arc::clone(&state.jobs);
    let mut audit = state.audit_sink.subscribe();
    let metrics = Arc::clone(&state.metrics);
    let meter = tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match audit.recv().await {
                Ok(event) => {
                    metrics.scrubbed.fetch_add(
                        event.bytes_scrubbed as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "audit metrics subscriber fell behind");
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
    let state = state.clone();
    let retention = tokio::spawn(async move {
        let mut daily = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        loop {
            daily.tick().await; // first tick fires immediately: the startup pass
            let st = state.clone();
            let _ = tokio::task::spawn_blocking(move || apply_audit_retention(&st)).await;
        }
    });
    if let Ok(mut jobs) = jobs.lock() {
        jobs.extend([
            mirror.abort_handle(),
            retention.abort_handle(),
            meter.abort_handle(),
        ]);
    }
}

// ---------------------------------------------------------------------------
// Backup + restore
// ---------------------------------------------------------------------------

const BUNDLE_ENTRY: &str = "repo.bundle";
const AUDIT_ENTRY: &str = ".premier-local/audit.jsonl";
const AUDIT_HEAD_ENTRY: &str = crate::store::LEGACY_AUDIT_HEAD;
const STATE_ENTRY: &str = ".premier";
/// Archive name for the account DB in an external state directory.
const ACCOUNT_DB_ENTRY: &str = "premier-account.db";
/// Archive directory of working-copy files, each at its workspace-relative path.
const FILES_ENTRY: &str = "workspace";
/// Where `restore_archive` parks the bundle (inside the target directory) while cloning from it.
const BUNDLE_TMP: &str = ".premier-restore.bundle";

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = premier_git_bridge::git_command(root)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Build the backup archive: the repository's state (and, for the default repository, the
/// account store) as `.premier/**`, the audit log as `.premier-local/audit.jsonl`, `repo.bundle`
/// (all refs),
/// and under `workspace/` the working-copy `.access.toml`, `.env.schema` and any of `policy_files`
/// (the configured repo and server policy paths) that live inside the workspace. The Studio saves
/// the policy uncommitted, so the bundle alone would restore an older one, or none.
///
/// The entry names are the same wherever the state lives on this server (in the workspace, or
/// in a `--state-dir`), so an archive restores onto either kind of server.
///
/// It holds the auth store, vault and age key, so whoever has the archive has the workspace.
// shortcut: built in memory (bundle + archive), fine for a home-server repo; spool to a temp
// file and stream it once repositories reach hundreds of MB.
pub fn build_backup(
    workspace_root: &Path,
    audit_log: Option<&Path>,
    policy_files: &[PathBuf],
) -> Result<Vec<u8>, String> {
    let io = |e: std::io::Error| format!("write backup archive failed: {e}");
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    // Nothing in a backup is read through a symbolic link.
    tar.follow_symlinks(false);
    let regular = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    let canonical_log = crate::store::audit_path(workspace_root);
    let audit_log = audit_log.unwrap_or(&canonical_log);
    let audit_head = crate::store::audit_head_path(audit_log);

    let dir = state_dir(workspace_root);
    let accounts = account_dir(workspace_root);
    let distinct_accounts = accounts != dir;
    let tmp = tempfile::tempdir().map_err(io)?;
    let db_snapshot = tmp.path().join(DB_FILE);
    let account_snapshot = tmp.path().join(ACCOUNT_DB_ENTRY);
    let repo_db = dir.join(DB_FILE);
    let account_db = accounts.join(DB_FILE);
    for (source, destination, archive_name) in [
        (repo_db, &db_snapshot, DB_FILE),
        (account_db, &account_snapshot, ACCOUNT_DB_ENTRY),
    ] {
        if archive_name == ACCOUNT_DB_ENTRY && !distinct_accounts {
            continue;
        }
        match std::fs::symlink_metadata(&source) {
            Ok(_) => {
                StateDb::snapshot(&source, destination)?;
                tar.append_path_with_name(destination, Path::new(STATE_ENTRY).join(archive_name))
                    .map_err(io)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
    }
    let has_scope = |snapshot: &Path, scope: Scope| {
        if snapshot.exists() {
            StateDb::snapshot_has_scope(snapshot, scope)
        } else {
            Ok(false)
        }
    };
    let migrated_repo = has_scope(&db_snapshot, Scope::Repo)?;
    let migrated_auth = has_scope(
        if distinct_accounts {
            &account_snapshot
        } else {
            &db_snapshot
        },
        Scope::Auth,
    )?;
    // Entry by entry, so the other repositories (`.premier/repos`, each backed up through its
    // own `/r/<name>/v1/backup`) and live agent workspaces are not swept into this one.
    let entries = [Some(dir), distinct_accounts.then_some(accounts)]
        .into_iter()
        .flatten()
        .flat_map(std::fs::read_dir)
        .flatten();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let path = entry.path();
        if name == crate::repos::REPOS_DIR
            || name == crate::runner::SESSION_WORKSPACES
            || name == "auth.json.lock"
            || name == DB_FILE
            || name == ACCOUNT_DB_ENTRY
            || name.to_str().is_some_and(|name| SIDECARS.contains(&name))
            || (migrated_repo && name == "state.json")
            || (migrated_auth && name == "auth.json")
            || path == audit_log
            || path == audit_head
        {
            continue;
        }
        append_regular_files(&mut tar, &path, &Path::new(STATE_ENTRY).join(&name)).map_err(io)?;
    }
    if regular(audit_log) || regular(&audit_head) {
        let log = tmp.path().join("audit.jsonl");
        let head = crate::store::audit_head_path(&log);
        // A writer may append or prune while we copy. Only archive a verified pair.
        let copy = || -> std::io::Result<()> {
            if regular(&audit_head) {
                std::fs::copy(&audit_head, &head)?;
            } else if head.exists() {
                std::fs::remove_file(&head)?;
            }
            if !regular(audit_log) {
                return Err(std::io::Error::other("audit log is not a regular file"));
            }
            std::fs::copy(audit_log, &log)?;
            premier_proxy::audit::verify_audit_chain(&log)?;
            Ok(())
        };
        copy().or_else(|_| copy()).map_err(io)?;
        tar.append_path_with_name(log, AUDIT_ENTRY).map_err(io)?;
        if head.is_file() {
            tar.append_path_with_name(head, AUDIT_HEAD_ENTRY)
                .map_err(io)?;
        }
    }
    // No working-copy file may come from the state directory (only through a link could one).
    let state_root = crate::store::state_root(workspace_root).and_then(|r| r.canonicalize().ok());
    let root_abs = std::path::absolute(workspace_root).map_err(io)?;
    let mut added: Vec<PathBuf> = Vec::new();
    let defaults = [".access.toml", ".env.schema"].map(|name| workspace_root.join(name));
    for file in defaults.iter().chain(policy_files) {
        let Ok(abs) = std::path::absolute(file) else {
            continue;
        };
        // Only plain files inside the workspace, by a path restore will accept.
        let Ok(rel) = abs.strip_prefix(&root_abs).map(Path::to_path_buf) else {
            continue;
        };
        let internal = crate::auth::is_internal_path(workspace_root, &rel.to_string_lossy());
        // `None` when a component (the file itself included) is a symbolic link.
        let real = repo_path(&rel)
            .and_then(|rp| crate::working_tree_path(workspace_root, &rp))
            .map(|(real, _)| real)
            .filter(|real| {
                regular(real) && !state_root.as_ref().is_some_and(|s| real.starts_with(s))
            });
        if let (Some(real), false, false) = (real, internal, added.contains(&rel)) {
            tar.append_path_with_name(&real, Path::new(FILES_ENTRY).join(&rel))
                .map_err(io)?;
            added.push(rel);
        }
    }
    // A workspace with no repository or no refs yet has nothing to bundle (git refuses an empty
    // bundle); any other bundle failure fails the backup rather than silently omitting history.
    let has_refs = git(workspace_root, &["for-each-ref", "--count=1"])
        .is_ok_and(|out| !out.iter().all(u8::is_ascii_whitespace));
    if has_refs {
        let bundle = git(workspace_root, &["bundle", "create", "-", "--all"])?;
        let mut head = tar::Header::new_gnu();
        head.set_size(bundle.len() as u64);
        head.set_mode(0o600);
        head.set_mtime(u64::try_from(Utc::now().timestamp()).unwrap_or(0));
        head.set_cksum();
        tar.append_data(&mut head, BUNDLE_ENTRY, bundle.as_slice())
            .map_err(io)?;
    }
    tar.into_inner().map_err(io)?.finish().map_err(io)
}

/// Write a private archive for a CLI caller, replacing an existing file only after it is complete.
pub fn write_backup(
    workspace_root: &Path,
    out: &Path,
    audit_log: Option<&Path>,
    policy_files: &[PathBuf],
) -> Result<(), String> {
    let archive = build_backup(workspace_root, audit_log, policy_files)?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let error = |err: std::io::Error| format!("write backup {} failed: {err}", out.display());
    let temp = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    premier_secrets::write_private(temp.path(), &archive).map_err(error)?;
    temp.persist(out).map_err(|err| error(err.error))?;
    Ok(())
}

/// `rel` (plain components only) as a repository path.
fn repo_path(rel: &Path) -> Option<RepoPath> {
    let parts = rel.components().map(|c| match c {
        Component::Normal(p) => p.to_str(),
        _ => None,
    });
    RepoPath::new(parts.collect::<Option<Vec<_>>>()?.join("/")).ok()
}

/// Append `src` as `dest`: the file, or every regular file below the directory. A symbolic link
/// (or a device, fifo...) is left out, never followed: state holds plain files only.
fn append_regular_files(
    tar: &mut tar::Builder<impl std::io::Write>,
    src: &Path,
    dest: &Path,
) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.is_dir() {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            append_regular_files(tar, &entry.path(), &dest.join(entry.file_name()))?;
        }
    } else if meta.is_file() {
        tar.append_path_with_name(src, dest)?;
    }
    Ok(())
}

/// Refuses `dest` unless it is under `base` by plain components and none of them that exists
/// (`dest` itself included) is a symbolic link: a restore never writes through one.
fn no_link_below(base: &Path, dest: &Path) -> Result<(), String> {
    let refuse = || {
        format!(
            "refusing to restore {}: it is not a plain path inside {}",
            dest.display(),
            base.display()
        )
    };
    let mut at = base.to_path_buf();
    for part in dest.strip_prefix(base).map_err(|_| refuse())?.components() {
        let Component::Normal(part) = part else {
            return Err(refuse());
        };
        at.push(part);
        if std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(refuse());
        }
    }
    Ok(())
}

/// `GET /v1/backup`: download the workspace backup. Browser session only.
pub async fn backup_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Response, ApiErr> {
    require_session(&user, "downloading a backup")?;
    let root = state.workspace_root.clone();
    let audit_log = state.audit_sink.file_path().map(Path::to_path_buf);
    let policy_files: Vec<PathBuf> = [&state.repo_policy_path, &state.server_policy_path]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    let bytes = tokio::task::spawn_blocking(move || {
        build_backup(&root, audit_log.as_deref(), &policy_files)
    })
    .await
    .map_err(|e| ise(e.to_string()))?
    .map_err(ise)?;

    let identity = DelegatedIdentity::human_only(
        Principal::parse(&format!("@{}", user.username)).unwrap_or(Principal::Anonymous),
        vec![],
    );
    let mut ev = AuditEvent::now(
        &identity,
        "premier-server",
        "backup_download",
        AuditDecision::Allowed,
        format!(
            "Downloaded workspace backup ({} bytes: auth store, vault, age key, audit log, repository bundle)",
            bytes.len()
        ),
    );
    ev.target = Some("/v1/backup".to_owned());
    crate::auth::audit(&state.audit_sink, ev);

    Ok(attachment(
        "application/gzip",
        &format!("premier-backup-{}.tar.gz", today()),
        Body::from(bytes),
    ))
}

/// What `restore_archive` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSummary {
    pub files_restored: usize,
    pub repo_cloned: bool,
}

/// Where an archive entry may land, relative to the workspace. Refuses absolute paths, `..`,
/// drive prefixes, links/devices, and anything outside the four things a backup contains.
fn restore_target(entry: &tar::Entry<'_, impl std::io::Read>) -> Result<Option<PathBuf>, String> {
    let raw = entry
        .path()
        .map_err(|e| format!("unreadable path in archive: {e}"))?;
    let mut rel = PathBuf::new();
    for part in raw.components() {
        match part {
            Component::Normal(p) => rel.push(p),
            Component::CurDir => {}
            _ => return Err(format!("unsafe path in archive: {}", raw.display())),
        }
    }
    let kind = entry.header().entry_type();
    if kind.is_dir() {
        return Ok(None);
    }
    let expected = rel.starts_with(STATE_ENTRY)
        || rel == Path::new(AUDIT_ENTRY)
        || rel == Path::new(AUDIT_HEAD_ENTRY)
        || rel == Path::new(BUNDLE_ENTRY)
        || rel.starts_with(FILES_ENTRY);
    if !kind.is_file() || !expected {
        return Err(format!("unexpected entry in archive: {}", raw.display()));
    }
    Ok(Some(rel))
}

/// Maximum decompressed bytes read from a backup archive during restore (2 GiB).
const MAX_RESTORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

struct LimitedReader<R> {
    inner: R,
    read: u64,
    limit: u64,
}

impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "backup archive exceeds maximum decompressed size (2 GiB)",
            ));
        }
        Ok(n)
    }
}

fn open_archive(archive: &Path) -> Result<tar::Archive<impl std::io::Read>, String> {
    let file = std::fs::File::open(archive)
        .map_err(|e| format!("cannot open {}: {e}", archive.display()))?;
    let limited = LimitedReader {
        inner: flate2::read::GzDecoder::new(file),
        read: 0,
        limit: MAX_RESTORE_BYTES,
    };
    Ok(tar::Archive::new(limited))
}

/// A `workspace/<path>` archive entry as `(path inside the workspace, contents)`; `None` for any
/// other entry. Never a path into `.git` or the server's own state.
fn workspace_file(
    into: &Path,
    rel: &Path,
    entry: &mut impl std::io::Read,
) -> Result<Option<(PathBuf, Vec<u8>)>, String> {
    let Ok(target) = rel.strip_prefix(FILES_ENTRY) else {
        return Ok(None);
    };
    if target.as_os_str().is_empty()
        || crate::auth::is_internal_path(into, &target.to_string_lossy())
    {
        return Err(format!("unexpected entry in archive: {}", rel.display()));
    }
    let mut bytes = Vec::new();
    entry
        .read_to_end(&mut bytes)
        .map_err(|e| format!("corrupt backup archive: {e}"))?;
    Ok(Some((target.to_path_buf(), bytes)))
}

/// Install a portable snapshot in either layout. For a forced partial restore, carry over
/// scopes the archive does not replace. This runs with the destination server offline.
fn restore_database(
    dir: &Path,
    snapshots: &[(Scope, &Path)],
    legacy_scopes: &[Scope],
    scopes: &[Scope],
) -> Result<(), String> {
    if snapshots.is_empty() && legacy_scopes.is_empty() {
        return Ok(());
    }
    let db = dir.join(DB_FILE);
    let exists = db.exists();
    if !exists && snapshots.is_empty() {
        return Ok(());
    }
    let io = |err: std::io::Error| format!("restore SQLite database failed: {err}");
    premier_secrets::create_state_dir(dir).map_err(io)?;
    let temp = tempfile::tempdir().map_err(io)?;
    let mut staged = StateDb::open(temp.path())?;
    for &scope in scopes {
        if let Some((_, source)) = snapshots.iter().find(|(part, _)| *part == scope) {
            staged.import_scope(source, scope)?;
        } else if exists && !legacy_scopes.contains(&scope) {
            staged.import_scope(&db, scope)?;
        }
    }
    drop(staged);
    let file = tempfile::NamedTempFile::new_in(dir).map_err(io)?;
    StateDb::snapshot(&temp.path().join(DB_FILE), file.path())?;
    for name in SIDECARS {
        match std::fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(io(err)),
        }
    }
    file.persist(db).map_err(|err| io(err.error))?;
    Ok(())
}

/// Unpack a `GET /v1/backup` archive into `into`. Workspace state is restored; the repository is
/// cloned from the bundle only when `into` has no `.git`; the working-copy policy files are put
/// back last, over whatever the clone checked out. Existing state, or an existing policy file
/// that differs from the backup's, is never overwritten unless `force`.
///
/// State goes where this workspace's state lives ([`crate::store::state_dir`]): the state
/// directory when `into` was bound to one first, else `<into>/.premier`.
pub fn restore_archive(archive: &Path, into: &Path, force: bool) -> Result<RestoreSummary, String> {
    let exists = |path: &Path| {
        format!(
            "{} already exists; pass --force to overwrite it",
            path.display()
        )
    };
    if state_dir(into).exists() && !force {
        return Err(exists(&state_dir(into)));
    }
    let bad = |e: std::io::Error| format!("corrupt backup archive: {e}");
    // Restored state lands under the configured state directory (else the workspace), only.
    let state_base = crate::store::state_root(into).unwrap_or_else(|| into.to_path_buf());
    let repo_dir = state_dir(into);
    let auth_dir = account_dir(into);
    let scratch = tempfile::tempdir().map_err(bad)?;
    let snapshot_entry = |rel: &Path| {
        [DB_FILE, ACCOUNT_DB_ENTRY]
            .into_iter()
            .find(|name| rel == Path::new(STATE_ENTRY).join(name))
    };
    let (mut legacy_repo, mut legacy_auth) = (false, false);

    // Pass 1: validate every entry before anything touches the disk.
    for entry in open_archive(archive)?.entries().map_err(bad)? {
        let mut entry = entry.map_err(bad)?;
        let Some(rel) = restore_target(&entry)? else {
            continue;
        };
        if rel.parent() == Some(Path::new(STATE_ENTRY)) {
            match rel.file_name().and_then(|n| n.to_str()) {
                Some(name) if SIDECARS.contains(&name) => continue,
                Some("state.json") => legacy_repo = true,
                Some("auth.json") => legacy_auth = true,
                _ => {}
            }
        }
        if let Some(name) = snapshot_entry(&rel) {
            let target = scratch.path().join(name);
            if target.exists() {
                return Err(format!("duplicate SQLite backup entry: {name}"));
            }
            entry.unpack(target).map_err(bad)?;
            continue;
        }
        if let Some((target, bytes)) = workspace_file(into, &rel, &mut entry)? {
            let existing = into.join(&target);
            if !force && std::fs::read(&existing).is_ok_and(|on_disk| on_disk != bytes) {
                return Err(format!(
                    "{} differs from the backup; pass --force to overwrite it",
                    existing.display()
                ));
            }
        } else if let Some(dest) = crate::store::locate_backup_entry(into, &rel) {
            no_link_below(&state_base, &dest)?;
            // In a state directory the accounts are not under this repository's state: an
            // archive that carries them (the default repository's) never replaces them unasked.
            if dest.starts_with(account_dir(into)) && dest.exists() && !force {
                return Err(exists(&dest));
            }
        }
    }

    let repo_snapshot = scratch.path().join(DB_FILE);
    let account_snapshot = scratch.path().join(ACCOUNT_DB_ENTRY);
    let snapshot_for = |scope| -> Result<Option<&Path>, String> {
        for source in [&account_snapshot, &repo_snapshot] {
            if source.exists() && StateDb::snapshot_has_scope(source, scope)? {
                return Ok(Some(source.as_path()));
            }
        }
        Ok(None)
    };
    let repo_source = snapshot_for(Scope::Repo)?;
    let auth_source = snapshot_for(Scope::Auth)?;
    for (dir, affected) in [
        (&repo_dir, repo_source.is_some() || legacy_repo),
        (&auth_dir, auth_source.is_some() || legacy_auth),
    ] {
        if affected {
            let db = dir.join(DB_FILE);
            no_link_below(&state_base, &db)?;
            if db.exists() && !force {
                return Err(exists(&db));
            }
            for name in SIDECARS {
                no_link_below(&state_base, &dir.join(name))?;
            }
        }
    }

    std::fs::create_dir_all(into).map_err(|e| format!("create {} failed: {e}", into.display()))?;
    let clone_repo = !into.join(".git").exists();
    let bundle_tmp = into.join(BUNDLE_TMP);
    let mut summary = RestoreSummary {
        files_restored: 0,
        repo_cloned: false,
    };
    let mut have_bundle = false;
    let mut workspace_files = Vec::new();

    for entry in open_archive(archive)?.entries().map_err(bad)? {
        let mut entry = entry.map_err(bad)?;
        let Some(rel) = restore_target(&entry)? else {
            continue;
        };
        if rel.parent() == Some(Path::new(STATE_ENTRY))
            && rel
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    SIDECARS.contains(&name)
                        || snapshot_entry(&rel).is_some()
                        || (name == "auth.json" && auth_source.is_some())
                        || (name == "state.json" && repo_source.is_some())
                })
        {
            continue;
        }
        // Written after the clone, whose checkout would otherwise replace them.
        if let Some(file) = workspace_file(into, &rel, &mut entry)? {
            workspace_files.push(file);
            continue;
        }
        let dest = if rel == Path::new(BUNDLE_ENTRY) {
            if !clone_repo {
                continue;
            }
            have_bundle = true;
            no_link_below(into, &bundle_tmp)?;
            bundle_tmp.clone()
        } else {
            summary.files_restored += 1;
            let dest = crate::store::locate_backup_entry(into, &rel)
                .ok_or_else(|| format!("unexpected entry in archive: {}", rel.display()))?;
            no_link_below(&state_base, &dest)?;
            dest
        };
        let write = |e: std::io::Error| format!("restore {} failed: {e}", rel.display());
        if let Some(parent) = dest.parent() {
            premier_secrets::create_state_dir(parent).map_err(write)?;
        }
        if rel != Path::new(BUNDLE_ENTRY) {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(write)?;
            premier_secrets::write_private(&dest, &bytes).map_err(write)?;
        } else {
            entry.unpack(&dest).map_err(write)?;
        }
    }

    let repo = repo_source.map(|src| (Scope::Repo, src));
    let auth = auth_source.map(|src| (Scope::Auth, src));
    let legacy_repo = legacy_repo.then_some(Scope::Repo);
    let legacy_auth = legacy_auth.then_some(Scope::Auth);
    if repo_dir == auth_dir {
        let snapshots: Vec<_> = repo.into_iter().chain(auth).collect();
        let legacy: Vec<_> = legacy_repo.into_iter().chain(legacy_auth).collect();
        restore_database(&repo_dir, &snapshots, &legacy, &[Scope::Repo, Scope::Auth])?;
        summary.files_restored += usize::from(!snapshots.is_empty());
    } else {
        restore_database(
            &repo_dir,
            repo.as_slice(),
            legacy_repo.as_slice(),
            &[Scope::Repo],
        )?;
        restore_database(
            &auth_dir,
            auth.as_slice(),
            legacy_auth.as_slice(),
            &[Scope::Auth],
        )?;
        summary.files_restored += usize::from(repo.is_some()) + usize::from(auth.is_some());
    }

    if have_bundle {
        let cloned = clone_from_bundle(into);
        let _ = std::fs::remove_file(&bundle_tmp);
        cloned?;
        summary.repo_cloned = true;
    }
    for (target, bytes) in workspace_files {
        // As the file API writes: never through a symbolic link (one the bundle just checked out
        // included), never out of the workspace.
        let dest = repo_path(&target)
            .and_then(|rp| crate::working_tree_path(into, &rp))
            .map(|(real, _)| real)
            .ok_or_else(|| {
                format!(
                    "refusing to restore {}: the path goes through a symbolic link",
                    target.display()
                )
            })?;
        let write = |e: std::io::Error| format!("restore {} failed: {e}", target.display());
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(write)?;
        }
        std::fs::write(&dest, bytes).map_err(write)?;
        summary.files_restored += 1;
    }
    Ok(summary)
}

/// Recreate the repository with every ref the bundle carries (including `refs/premier-private/*`),
/// then check out its HEAD. `into` already holds restored state, so a plain `git clone` into it
/// is not possible: mirror into `.git` and un-bare it. A HEAD the server would not check out
/// (a reserved path such as the state it would land on) is refused, and the repository removed.
fn clone_from_bundle(into: &Path) -> Result<(), String> {
    git(into, &["clone", "--quiet", "--mirror", BUNDLE_TMP, ".git"])?;
    git(into, &["config", "core.bare", "false"])?;
    git(into, &["config", "--remove-section", "remote.origin"])?;
    if let Some(why) = crate::canon::unsafe_to_check_out(into, "HEAD", &[]) {
        let _ = std::fs::remove_dir_all(into.join(".git"));
        return Err(format!(
            "the backup's repository was not checked out: {why}"
        ));
    }
    git(into, &["reset", "--quiet", "--hard"])?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Read;
    use std::sync::Mutex;

    #[test]
    fn restored_audit_chain_accepts_an_append() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let bound = tempfile::tempdir().unwrap();
        let actor = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let append = |path: &Path| {
            AuditSink::new(Some(path.to_path_buf())).record(AuditEvent::now(
                &actor,
                "test",
                "append",
                AuditDecision::Allowed,
                "audit backup test",
            ));
        };
        append(&crate::store::audit_path(src.path()));
        crate::store::bind_state_dir(src.path(), bound.path(), "backup-audit", true);
        let moved = crate::store::adopt_legacy_state(src.path()).unwrap();
        assert!(moved.iter().any(|entry| entry == AUDIT_HEAD_ENTRY));
        let source = crate::store::audit_path(src.path());
        let overlay_key = crate::store::state_dir(src.path()).join("overlays/.key");
        std::fs::create_dir_all(overlay_key.parent().unwrap()).unwrap();
        std::fs::write(&overlay_key, "fixture").unwrap();
        let archive = src.path().join("backup.tar.gz");
        let bytes = build_backup(src.path(), Some(&source), &[]).unwrap();
        std::fs::write(&archive, bytes).unwrap();
        restore_archive(&archive, dst.path(), false).unwrap();
        let restored = crate::store::audit_path(dst.path());
        let head = restored.with_extension("jsonl.head");
        assert!(head.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                &restored,
                &head,
                &state_dir(dst.path()).join("overlays/.key"),
            ] {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        append(&restored);
        assert_eq!(
            premier_proxy::audit::verify_audit_chain(&restored).unwrap(),
            2
        );
    }

    #[test]
    fn backup_restores_sqlite_state_to_bound_and_local_layouts() {
        let src = tempfile::tempdir().unwrap();
        let auth = crate::auth::AuthStore::open(src.path());
        let (_, token) = auth.seed("backup-owner", "correct horse battery");
        let mut state = crate::store::PersistedState::default();
        save_state(src.path(), &state).unwrap();
        let source_dir = state_dir(src.path());
        let reader = rusqlite::Connection::open(source_dir.join(DB_FILE)).unwrap();
        reader
            .execute_batch("BEGIN; SELECT data FROM repo_state;")
            .unwrap();
        state.settings.audit_retention_days = Some(19);
        save_state(src.path(), &state).unwrap();
        assert!(
            std::fs::metadata(source_dir.join(SIDECARS[0]))
                .unwrap()
                .len()
                > 0
        );
        let archive = src.path().join("backup.tar.gz");
        std::fs::write(&archive, build_backup(src.path(), None, &[]).unwrap()).unwrap();

        let dest = tempfile::tempdir().unwrap();
        let bound = tempfile::tempdir().unwrap();
        crate::store::bind_state_dir(dest.path(), bound.path(), "restored", true);
        restore_archive(&archive, dest.path(), false).unwrap();
        assert!(state_dir(dest.path()).join("premier.db").is_file());
        assert!(account_dir(dest.path()).join("premier.db").is_file());
        let restored = crate::auth::AuthStore::open(dest.path());
        assert!(restored.user_state("backup-owner").is_some());
        let mut state = state_at(dest.path());
        state.auth = Arc::new(restored);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(
            crate::auth::request_user(&state, &headers)
                .unwrap()
                .is_some()
        );

        std::fs::write(&archive, build_backup(dest.path(), None, &[]).unwrap()).unwrap();
        let local = tempfile::tempdir().unwrap();
        restore_archive(&archive, local.path(), false).unwrap();
        assert!(
            crate::auth::AuthStore::open(local.path())
                .user_state("backup-owner")
                .is_some()
        );
        assert_eq!(
            crate::store::load_state(local.path())
                .unwrap()
                .settings
                .audit_retention_days,
            Some(19)
        );
        // Restore replaces SQLite's files rather than replaying a previous database's sidecars.
        for sidecar in SIDECARS {
            std::fs::write(state_dir(local.path()).join(sidecar), "stale").unwrap();
        }
        restore_archive(&archive, local.path(), true).unwrap();
        for sidecar in SIDECARS {
            assert!(!state_dir(local.path()).join(sidecar).exists());
        }
    }

    #[test]
    fn legacy_backup_can_replace_sqlite_repo_state() {
        let legacy = tempfile::tempdir().unwrap();
        let mut old = crate::store::PersistedState::default();
        old.settings.audit_retention_days = Some(12);
        save_json(legacy.path(), "state.json", &old).unwrap();
        let archive = legacy.path().join("backup.tar.gz");
        std::fs::write(&archive, build_backup(legacy.path(), None, &[]).unwrap()).unwrap();

        let dest = tempfile::tempdir().unwrap();
        let auth = crate::auth::AuthStore::open(dest.path());
        auth.seed("existing-owner", "correct horse battery");
        old.settings.audit_retention_days = Some(30);
        save_state(dest.path(), &old).unwrap();
        restore_archive(&archive, dest.path(), true).unwrap();
        assert_eq!(
            crate::store::load_state(dest.path())
                .unwrap()
                .settings
                .audit_retention_days,
            Some(12)
        );
        assert!(auth.user_state("existing-owner").is_some());
    }

    use axum::Router;
    use axum::http::{HeaderMap, Method, Request};
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;
    use premier_policy::{CompiledPolicy, parse_policy_toml};
    use premier_proxy::{ApprovalRequest, ApprovalStatus, AuditSink};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::runner::SessionManager;
    use crate::store::load_state;
    use crate::{auth, build_router};

    const PW: &str = "correct horse battery";

    /// Server state rooted at `root`, loaded the way a fresh process would load it.
    fn state_at(root: &Path) -> ServerState {
        let policy_toml = "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\n";
        let policy = CompiledPolicy::compile(None, &parse_policy_toml(policy_toml).unwrap());
        let sink = AuditSink::new(Some(root.join(".premier-local/audit.jsonl")));
        let mut state = ServerState::minimal(Some(Arc::new(policy.unwrap())), None, Arc::new(sink));
        state.workspace_root = root.to_path_buf();
        state.persisted = Arc::new(Mutex::new(load_state(root).unwrap()));
        state.auth = Arc::new(auth::AuthStore::open(root));
        state.approval_hub = Arc::new(load_approvals(root));
        state.session_manager = Arc::new(SessionManager::open(root));
        state.static_ui_dir = None;
        // The test host may have no sandbox; what is tested here is the session bookkeeping.
        state.allow_unsandboxed_agents = true;
        state
    }

    async fn send(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Body,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender.send_request(req.body(body).unwrap()).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts.status, parts.headers, bytes)
    }

    fn json(bytes: &Bytes) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    fn json_body(v: serde_json::Value) -> Body {
        Body::from(v.to_string())
    }

    fn git_ok(root: &Path, args: &[&str]) -> String {
        String::from_utf8(git(root, args).unwrap()).unwrap()
    }

    /// A real repository with `main` (public) and a private branch nobody but `@alice` may see.
    fn init_repo(root: &Path) {
        git_ok(root, &["init", "-q", "-b", "main"]);
        git_ok(root, &["config", "user.email", "test@example.com"]);
        git_ok(root, &["config", "user.name", "Test"]);
        git_ok(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("README.md"), "# demo\n").unwrap();
        git_ok(root, &["add", "README.md"]);
        git_ok(root, &["commit", "-q", "-m", "public one"]);
        git_ok(root, &["checkout", "-q", "-b", "skunkworks"]);
        std::fs::write(root.join("plan.md"), "embargoed\n").unwrap();
        git_ok(root, &["add", "plan.md"]);
        git_ok(root, &["commit", "-q", "-m", "secret plan"]);
        git_ok(root, &["checkout", "-q", "main"]);
    }

    #[tokio::test]
    async fn settings_round_trip_and_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = state_at(tmp.path());
        state.ssh_public_url = Some("ssh://git@git.example.test:7429".to_owned());
        let (cookie, token) = state.auth.seed("owner", PW);
        let router = build_router(state);
        let authed = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/json"),
        ];

        let (status, _, body) =
            send(&router, Method::GET, "/v1/settings", &authed, Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json(&body),
            serde_json::json!({
                "audit_retention_days": null,
                "ssh_public_url": "ssh://git@git.example.test:7429"
            })
        );

        let patch = |v: serde_json::Value| {
            let router = router.clone();
            async move {
                send(
                    &router,
                    Method::PATCH,
                    "/v1/settings",
                    &authed,
                    json_body(v),
                )
                .await
            }
        };
        let (status, _, body) = patch(serde_json::json!({ "audit_retention_days": 30 })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["audit_retention_days"], 30);
        // An empty patch changes nothing; out-of-range and unknown fields are refused.
        let (status, _, body) = patch(serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["audit_retention_days"], 30);
        for bad in [
            serde_json::json!({ "audit_retention_days": 0 }),
            serde_json::json!({ "audit_retention_days": 3651 }),
            serde_json::json!({ "audit_retention_days": "30" }),
            serde_json::json!({ "nope": 1 }),
        ] {
            assert_eq!(patch(bad).await.0, StatusCode::BAD_REQUEST);
        }
        // Access tokens may read settings but not change them.
        let bearer = format!("Bearer {token}");
        let via_token = [
            ("authorization", bearer.as_str()),
            ("content-type", "application/json"),
        ];
        let (status, _, _) = send(
            &router,
            Method::PATCH,
            "/v1/settings",
            &via_token,
            json_body(serde_json::json!({ "audit_retention_days": null })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Persisted: a rebuilt server reads it back, and null clears it.
        let router = build_router(state_at(tmp.path()));
        let (_, _, body) = send(&router, Method::GET, "/v1/settings", &authed, Body::empty()).await;
        assert_eq!(json(&body)["audit_retention_days"], 30);
        let (status, _, body) = send(
            &router,
            Method::PATCH,
            "/v1/settings",
            &authed,
            json_body(serde_json::json!({ "audit_retention_days": null })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json(&body)["audit_retention_days"].is_null());
    }

    #[tokio::test]
    async fn audit_filters_export_and_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_at(tmp.path());
        let (cookie, _) = state.auth.seed("owner", PW);
        let id = |p: &str| DelegatedIdentity::human_only(Principal::parse(p).unwrap(), vec![]);
        let mut old = AuditEvent::now(
            &id("@alice"),
            "premier-proxy",
            "swap",
            AuditDecision::Allowed,
            "Ancient STRIPE use",
        );
        old.timestamp = Utc::now() - chrono::Duration::days(40);
        state.audit_sink.record(old);
        state.audit_sink.record(AuditEvent::now(
            &id("@alice"),
            "premier-proxy",
            "swap",
            AuditDecision::Allowed,
            "Used STRIPE key",
        ));
        state.audit_sink.record(AuditEvent::now(
            &id("@bob"),
            "premier-proxy",
            "exfil",
            AuditDecision::ExfiltrationBlocked,
            "Blocked evil.test",
        ));
        let router = build_router(state.clone());
        let authed = [("cookie", cookie.as_str())];
        let get = |uri: &'static str| {
            let router = router.clone();
            async move { send(&router, Method::GET, uri, &authed, Body::empty()).await }
        };
        let len = |b: &Bytes| json(b).as_array().unwrap().len();

        let (status, _, body) = get("/v1/audit").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(len(&body), 3);
        assert_eq!(json(&body)[0]["reason"], "Blocked evil.test"); // newest first, as before
        assert_eq!(len(&get("/v1/audit?limit=1").await.2), 1);
        assert_eq!(len(&get("/v1/audit?q=stripe").await.2), 2);
        assert_eq!(len(&get("/v1/audit?principal=@bob").await.2), 1);
        assert_eq!(len(&get("/v1/audit?principal=user:alice").await.2), 2);
        assert_eq!(
            len(&get("/v1/audit?decision=exfiltration_blocked").await.2),
            1
        );
        assert_eq!(len(&get("/v1/audit?decision=allowed&q=ancient").await.2), 1);
        assert_eq!(len(&get("/v1/audit?q=nomatch").await.2), 0);

        let (status, headers, body) = get("/v1/audit/export").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/x-ndjson");
        let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
        assert!(disposition.starts_with("attachment; filename=\"premier-audit-"));
        assert!(disposition.ends_with(".jsonl\""));
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(text.lines().count(), 3);
        for line in text.lines() {
            serde_json::from_str::<AuditEvent>(line).unwrap();
        }

        // Retention is off until configured, then drops only what is older than the window.
        apply_audit_retention(&state);
        assert_eq!(state.audit_sink.snapshot().len(), 3);
        state
            .persisted
            .lock()
            .unwrap()
            .settings
            .audit_retention_days = Some(30);
        apply_audit_retention(&state);
        let on_disk =
            std::fs::read_to_string(tmp.path().join(".premier-local/audit.jsonl")).unwrap();
        assert_eq!(on_disk.lines().count(), 2);
        assert!(!on_disk.contains("Ancient"));
    }

    #[tokio::test]
    async fn backup_is_session_only_and_restores_state_and_repository() {
        let tmp = tempfile::tempdir().unwrap();
        init_repo(tmp.path());
        // What the Studio leaves in the working copy without committing it.
        std::fs::create_dir(tmp.path().join("policy")).unwrap();
        for (file, text) in [
            (".access.toml", "version = 1\n"),
            (".env.schema", "# s\n"),
            ("policy/server.toml", "version = 1\n"),
        ] {
            std::fs::write(tmp.path().join(file), text).unwrap();
        }
        let mut state = state_at(tmp.path());
        state.server_policy_path = Some(tmp.path().join("policy/server.toml"));
        let (cookie, token) = state.auth.seed("owner", PW);
        let router = build_router(state);

        let (status, _, _) = send(&router, Method::GET, "/v1/backup", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let bearer = format!("Bearer {token}");
        let via_token = [("authorization", bearer.as_str())];
        let (status, _, _) = send(
            &router,
            Method::GET,
            "/v1/backup",
            &via_token,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let authed = [("cookie", cookie.as_str())];
        let (status, headers, body) =
            send(&router, Method::GET, "/v1/backup", &authed, Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/gzip");
        let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
        assert!(disposition.starts_with("attachment; filename=\"premier-backup-"));
        assert!(disposition.ends_with(".tar.gz\""));
        assert_eq!(&body[..2], &[0x1f, 0x8b]);

        let mut names = Vec::new();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&body[..]));
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            names.push(entry.path().unwrap().to_string_lossy().replace('\\', "/"));
        }
        assert!(
            names.contains(&".premier/premier.db".to_owned()),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|name| name.ends_with("-wal") || name.ends_with("-shm"))
        );
        assert!(names.contains(&"repo.bundle".to_owned()), "{names:?}");

        // The download itself is audited.
        let (_, _, audit) = send(
            &router,
            Method::GET,
            "/v1/audit?q=backup_download",
            &authed,
            Body::empty(),
        )
        .await;
        assert_eq!(json(&audit).as_array().unwrap().len(), 1);

        // `premier restore`: state unpacked, repository (private branch included) cloned from the bundle.
        let archive_path = tmp.path().join("backup.tar.gz");
        std::fs::write(&archive_path, &body).unwrap();
        let dest = tempfile::tempdir().unwrap();
        let summary = restore_archive(&archive_path, dest.path(), false).unwrap();
        assert!(summary.repo_cloned);
        assert!(dest.path().join(".premier/premier.db").is_file());
        assert!(
            crate::auth::AuthStore::open(dest.path())
                .user_state("owner")
                .is_some()
        );
        let readme = std::fs::read_to_string(dest.path().join("README.md")).unwrap();
        assert_eq!(readme.trim(), "# demo"); // trim: core.autocrlf may rewrite the line ending
        let branches = git_ok(dest.path(), &["for-each-ref", "--format=%(refname)"]);
        assert!(branches.contains("refs/heads/main") && branches.contains("refs/heads/skunkworks"));
        assert!(!dest.path().join(".premier-restore.bundle").exists());
        // The saved (uncommitted) policy files come back too.
        for file in [".access.toml", ".env.schema", "policy/server.toml"] {
            assert!(names.contains(&format!("workspace/{file}")), "{names:?}");
            assert!(dest.path().join(file).is_file(), "{file}");
        }
        // ...but never over a different file that is already there, unless forced.
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join(".access.toml"), "version = 1\n# mine\n").unwrap();
        let err = restore_archive(&archive_path, other.path(), false).unwrap_err();
        assert!(
            err.contains(".access.toml") && err.contains("--force"),
            "{err}"
        );
        assert!(!other.path().join(".premier").exists());
        restore_archive(&archive_path, other.path(), true).unwrap();
        let restored = std::fs::read_to_string(other.path().join(".access.toml")).unwrap();
        assert_eq!(restored, "version = 1\n");

        // A second restore refuses to clobber `.premier` without --force and never re-clones.
        let err = restore_archive(&archive_path, dest.path(), false).unwrap_err();
        assert!(err.contains("--force"), "{err}");
        let again = restore_archive(&archive_path, dest.path(), true).unwrap();
        assert!(!again.repo_cloned);
    }

    #[test]
    fn restore_rejects_path_traversal_and_foreign_entries() {
        let tmp = tempfile::tempdir().unwrap();
        // `tar::Builder` refuses to write `..` itself, so forge the header name bytes directly.
        let archive_with = |name: &str| {
            let mut head = tar::Header::new_gnu();
            head.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            head.set_size(4);
            head.set_mode(0o644);
            head.set_entry_type(tar::EntryType::Regular);
            head.set_cksum();
            let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut tar = tar::Builder::new(gz);
            tar.append(&head, &b"evil"[..]).unwrap();
            let path = tmp.path().join("evil.tar.gz");
            std::fs::write(&path, tar.into_inner().unwrap().finish().unwrap()).unwrap();
            path
        };
        let dest = tmp.path().join("dest");
        for name in [
            "../escape.txt",
            ".premier/../../escape.txt",
            "/abs.txt",
            "stray.txt",
        ] {
            let err = restore_archive(&archive_with(name), &dest, false).unwrap_err();
            assert!(err.contains("archive"), "{name}: {err}");
        }
        assert!(
            !dest.exists(),
            "nothing may be written when validation fails"
        );
        assert!(!tmp.path().join("escape.txt").exists());

        let ok = restore_archive(&archive_with(".premier/state.json"), &dest, false).unwrap();
        assert_eq!(ok.files_restored, 1);
        let mut restored = String::new();
        std::fs::File::open(dest.join(".premier/state.json"))
            .unwrap()
            .read_to_string(&mut restored)
            .unwrap();
        assert_eq!(restored, "evil");
    }

    fn symlink(target: &Path, at: &Path) -> bool {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, at).is_ok();
        #[cfg(windows)]
        return if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, at)
        } else {
            std::os::windows::fs::symlink_file(target, at)
        }
        .is_ok();
    }

    #[test]
    fn backup_never_follows_a_symbolic_link() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, state_root) = (tmp.path().join("repo"), tmp.path().join("state"));
        std::fs::create_dir(&root).unwrap();
        init_repo(&root);
        crate::store::bind_state_dir(&root, &state_root, "x", false);
        let account = state_root.join("account");
        std::fs::create_dir_all(&account).unwrap();
        std::fs::write(account.join("auth.json"), "ACCOUNT-SECRET").unwrap();
        let state = state_dir(&root);
        std::fs::create_dir_all(state.join("sub")).unwrap();
        std::fs::write(state.join("state.json"), "{}").unwrap();
        let outside = tmp.path().join("outside.txt");
        std::fs::write(&outside, "OUTSIDE-SECRET").unwrap();
        std::fs::write(root.join(".env.schema"), "# s\n").unwrap();
        // An imported tree's `.access.toml` naming the account store.
        if !symlink(&account.join("auth.json"), &root.join(".access.toml")) {
            eprintln!("skipped: this host cannot make symbolic links");
            return;
        }
        assert!(symlink(&outside, &state.join("evil.json")));
        assert!(symlink(&outside, &state.join("sub/deep.json")));
        // A configured policy file reached through a linked directory.
        assert!(symlink(&account, &root.join("cfg")));

        let bytes = build_backup(&root, None, &[root.join("cfg/auth.json")]).unwrap();
        let mut names = Vec::new();
        for entry in tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]))
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().replace('\\', "/");
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            let text = String::from_utf8_lossy(&content);
            assert!(
                !text.contains("ACCOUNT-SECRET") && !text.contains("OUTSIDE-SECRET"),
                "{name}"
            );
            assert!(entry.header().entry_type().is_file(), "{name}");
            names.push(name);
        }
        assert!(
            names.contains(&".premier/state.json".to_owned()),
            "{names:?}"
        );
        assert!(
            names.contains(&"workspace/.env.schema".to_owned()),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("evil") || n.contains("deep") || n.contains("access")),
            "{names:?}"
        );
    }

    /// A backup archive of `entries`, with every ref of `repo` as its bundle when given.
    fn crafted(path: &Path, repo: Option<&Path>, entries: &[(&str, &[u8])]) -> PathBuf {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        let bundle = repo.map(|r| git(r, &["bundle", "create", "-", "--all"]).unwrap());
        let all = entries
            .iter()
            .copied()
            .chain(bundle.as_deref().map(|b| (BUNDLE_ENTRY, b)));
        for (name, data) in all {
            let mut head = tar::Header::new_gnu();
            head.set_size(data.len() as u64);
            head.set_mode(0o644);
            head.set_cksum();
            tar.append_data(&mut head, name, data).unwrap();
        }
        std::fs::write(path, tar.into_inner().unwrap().finish().unwrap()).unwrap();
        path.to_path_buf()
    }

    #[test]
    fn restore_never_writes_through_a_symbolic_link() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let who = ("T".to_owned(), "t@example.test".to_owned());
        let repo_with = |name: &str, path: &str, content: &[u8], mode: &str| {
            let src = tmp.path().join(name);
            std::fs::create_dir(&src).unwrap();
            init_repo(&src);
            let path = RepoPath::new(path).unwrap();
            let change = [(&path, Some(content), Some(mode))];
            crate::canon::commit_changes(&src, "refs/heads/main", None, &change, "m", &who)
                .unwrap();
            src
        };

        // A bundle whose HEAD would check out over the state just restored: refused.
        let src = repo_with("src1", ".premier/auth.json", b"{\"accounts\":[]}", "100644");
        let archive = crafted(
            &tmp.path().join("a1.tgz"),
            Some(&src),
            &[(".premier/auth.json", b"restored")],
        );
        let dest = tmp.path().join("d1");
        let err = restore_archive(&archive, &dest, false).unwrap_err();
        assert!(
            err.contains("not checked out") && err.contains("reserved"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join(".premier/auth.json")).unwrap(),
            "restored"
        );
        assert!(!dest.join(".git").exists());

        // A bundle that checks out a link, and a working-copy file under it.
        let target = outside.to_str().unwrap().as_bytes();
        let src = repo_with("src2", "cfg", target, "120000");
        let archive = crafted(
            &tmp.path().join("a2.tgz"),
            Some(&src),
            &[("workspace/cfg/auth.json", b"pwned")],
        );
        assert!(restore_archive(&archive, &tmp.path().join("d2"), false).is_err());
        assert!(!outside.join("auth.json").exists());

        // A link already in the target directory: the same.
        let archive = crafted(
            &tmp.path().join("a3.tgz"),
            None,
            &[("workspace/cfg/auth.json", b"pwned")],
        );
        let dest = tmp.path().join("d3");
        std::fs::create_dir(&dest).unwrap();
        if !symlink(&outside, &dest.join("cfg")) {
            eprintln!("skipped the rest: this host cannot make symbolic links");
            return;
        }
        let err = restore_archive(&archive, &dest, false).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        assert!(!outside.join("auth.json").exists());

        // State only lands inside the state directory, never through a linked one.
        let archive = crafted(
            &tmp.path().join("a4.tgz"),
            None,
            &[(".premier/state.json", b"x")],
        );
        let dest = tmp.path().join("d4");
        std::fs::create_dir(&dest).unwrap();
        assert!(symlink(&outside, &dest.join(".premier")));
        let err = restore_archive(&archive, &dest, true).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(!outside.join("state.json").exists());
    }

    #[tokio::test]
    async fn approvals_and_sessions_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let request = |var: &str| ApprovalRequest {
            principal: "user:alice".to_owned(),
            agent_profile: Some("ui-agent".to_owned()),
            var_name: var.to_owned(),
            host: "api.example.com".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/charges".to_owned(),
            ttl_secs: 600,
            kind: None,
            mcp_server: None,
            mcp_tool: None,
            risk: None,
            args_summary: None,
            args_hash: None,
            ref_name: None,
            ..ApprovalRequest::default()
        };

        let state = state_at(root);
        let (cookie, _) = state.auth.seed("owner", PW);
        let authed = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/json"),
        ];
        spawn_background(&state);
        let (pending, _rx_pending) = state.approval_hub.enqueue(request("PENDING_KEY"));
        let (granted, _rx_granted) = state.approval_hub.enqueue(request("GRANTED_KEY"));
        let (lapsed, _rx_lapsed) = state.approval_hub.enqueue(request("LAPSED_KEY"));
        let router = build_router(state.clone());
        for (id, ttl) in [(&granted.id, 600), (&lapsed.id, 0)] {
            let (status, _, _) = send(
                &router,
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &authed,
                json_body(serde_json::json!({ "approved": true, "ttl_secs": ttl })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // One session that finishes before the "shutdown".
        let (status, _, body) = send(
            &router,
            Method::POST,
            "/v1/agents/sessions",
            &authed,
            json_body(serde_json::json!({ "command": "echo done", "principal": "@alice" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        let finished_id = json(&body)["id"].as_str().unwrap().to_owned();
        // Wait for the first session to finish and for the approval mirror to hit the disk.
        let approvals_file = root.join(".premier/approvals.json");
        let settled = || {
            let done = state
                .session_manager
                .list()
                .iter()
                .any(|s| s.id == finished_id && s.status != "running");
            let saved = std::fs::read_to_string(&approvals_file)
                .is_ok_and(|raw| raw.matches("\"approved\"").count() == 2);
            done && saved
        };
        for _ in 0..600 {
            if settled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            settled(),
            "session never finished or approvals never persisted"
        );

        // Started last, so it is certainly still running when the "old server" goes away.
        let sleep = if cfg!(windows) {
            "Start-Sleep -Seconds 3"
        } else {
            "sleep 3"
        };
        let (status, _, body) = send(
            &router,
            Method::POST,
            "/v1/agents/sessions",
            &authed,
            json_body(serde_json::json!({ "command": sleep, "principal": "@alice" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        let running_id = json(&body)["id"].as_str().unwrap().to_owned();

        // "Restart": a brand-new state over the same workspace.
        let restarted = state_at(root);
        let approvals = restarted.approval_hub.list();
        let status_of = |id: &str| approvals.iter().find(|a| a.id == id).unwrap().status;
        assert_eq!(status_of(&pending.id), ApprovalStatus::Pending);
        assert_eq!(status_of(&granted.id), ApprovalStatus::Approved);
        assert_eq!(status_of(&lapsed.id), ApprovalStatus::Expired);
        assert!(restarted.approval_hub.has_grant(&request("GRANTED_KEY")));
        assert!(!restarted.approval_hub.has_grant(&request("LAPSED_KEY")));
        assert!(!restarted.approval_hub.has_grant(&request("PENDING_KEY")));

        let router = build_router(restarted);
        let (_, _, body) = send(
            &router,
            Method::GET,
            "/v1/agents/sessions",
            &authed,
            Body::empty(),
        )
        .await;
        let sessions = json(&body);
        let session = |id: &str| {
            sessions
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(session(&running_id)["status"], "interrupted");
        assert!(session(&running_id)["finished_at"].is_string());
        assert_ne!(session(&finished_id)["status"], "running");
        assert_ne!(session(&finished_id)["status"], "interrupted");
        // The restored pending approval is still decidable over HTTP.
        let (status, _, body) = send(
            &router,
            Method::POST,
            &format!("/v1/approvals/{}/decide", pending.id),
            &authed,
            json_body(serde_json::json!({ "approved": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["status"], "denied");
    }

    #[tokio::test]
    async fn commits_ref_is_validated_and_scoped_to_visible_branches() {
        let tmp = tempfile::tempdir().unwrap();
        init_repo(tmp.path());
        let secret_oid = git_ok(tmp.path(), &["rev-parse", "skunkworks"])
            .trim()
            .to_owned();
        let public_oid = git_ok(tmp.path(), &["rev-parse", "main"]).trim().to_owned();
        let state = state_at(tmp.path());
        state.persisted.lock().unwrap().branch_metadata.insert(
            "skunkworks".to_owned(),
            (
                premier_core::Visibility::Restricted(vec!["@alice".to_owned()]),
                premier_core::Readiness::Ready,
            ),
        );
        let (cookie, _) = state.auth.seed("owner", PW);
        let router = build_router(state);
        let authed = [("cookie", cookie.as_str())];
        let get = |uri: String| {
            let router = router.clone();
            async move {
                let (status, _, body) =
                    send(&router, Method::GET, &uri, &authed, Body::empty()).await;
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                )
            }
        };
        let subjects = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|c| c["subject"].as_str().unwrap().to_owned())
                .collect()
        };

        // Bare call: HEAD, same array shape as before.
        let (status, body) = get("/v1/commits".to_owned()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(subjects(&body), ["public one"]);
        assert_eq!(body[0]["oid"], public_oid.as_str());

        // Anything git could read as an option is refused outright.
        for bad in ["-n1", "--all", "--output=/tmp/x"] {
            let (status, _) = get(format!("/v1/commits?ref={bad}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        // Rev expressions that could walk into hidden history are not refs.
        for sneaky in [
            "skunkworks~0",
            "main..skunkworks",
            ":/secret",
            "refs/heads/skunkworks",
            "nope",
        ] {
            let (status, _) = get(format!("/v1/commits?ref={sneaky}&principal=@bob")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{sneaky}");
        }

        // @bob cannot list the restricted branch by name or by an oid only it contains,
        // and gets the same answer as for a ref that does not exist.
        for hidden in ["skunkworks", secret_oid.as_str(), &secret_oid[..10]] {
            let (status, body) = get(format!("/v1/commits?ref={hidden}&principal=@bob")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{hidden}");
            assert_eq!(body["error"], "ref not found");
        }
        let (status, body) = get(format!("/v1/commits?ref={public_oid}&principal=@bob")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(subjects(&body), ["public one"]);

        // @alice is on the allow-list: branch name, oid, limit and skip all work.
        let (status, body) = get("/v1/commits?ref=skunkworks&principal=@alice".to_owned()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(subjects(&body), ["secret plan", "public one"]);
        let (_, body) = get(format!(
            "/v1/commits?ref={secret_oid}&principal=@alice&limit=1"
        ))
        .await;
        assert_eq!(subjects(&body), ["secret plan"]);
        let (_, body) =
            get("/v1/commits?ref=skunkworks&principal=@alice&limit=1&skip=1".to_owned()).await;
        assert_eq!(subjects(&body), ["public one"]);

        // The bare (HEAD) call is scoped the same way once HEAD is the restricted branch.
        git_ok(tmp.path(), &["checkout", "-q", "skunkworks"]);
        let (status, body) = get("/v1/commits?principal=@bob".to_owned()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(subjects(&body), Vec::<String>::new());
        let (_, body) = get("/v1/commits?principal=@alice".to_owned()).await;
        assert_eq!(subjects(&body), ["secret plan", "public one"]);
    }

    #[tokio::test]
    async fn large_git_push_body_is_not_rejected_but_json_is_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_at(tmp.path());
        let (cookie, token) = state.auth.seed("owner", PW);
        let router = build_router(state);

        // 3 MB: over axum's 2 MB default. It is not a valid pack, so the bridge rejects it, but
        // only after the whole body was accepted.
        let bearer = format!("Bearer {token}");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/git/repo.git/git-receive-pack",
            &[("authorization", bearer.as_str())],
            Body::from(vec![b'0'; 3 * 1024 * 1024]),
        )
        .await;
        assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_ne!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send(
            &router,
            Method::POST,
            "/v1/access/explain",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/json"),
            ],
            Body::from(vec![b' '; JSON_BODY_LIMIT + 1024]),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
