//! Several repositories behind one server and one account system.
//!
//! A [`ServerState`] is still exactly one repository workspace and [`build_router`] its router.
//! The [`Registry`] keeps one of each per repository and dispatches by path: `/r/{name}/<rest>`
//! and the Git aliases `/git/{name}.git/…`, `/git/auth/{name}.git/…` go to that repository's
//! router, everything else to the default repository's exactly as before. Accounts, the
//! principal directory, settings and the repository list live in the default workspace's
//! `.premier/`; policy, vault, audit log, approvals, sessions and reviews in each repository's own.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path as AxumPath, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, patch, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use premier_core::{Capability, DelegatedIdentity, Principal, RepoPath};
use premier_proxy::AuditSink;
use serde::{Deserialize, Serialize};
use tower_service::Service;

use crate::auth::{self, AuthUser, ClientIp};
use crate::runner::SessionManager;
use crate::store::{PersistedState, account_dir, load_json_in, load_state, save_json_in};
use crate::{ApiError, PRIVATE_REF_PREFIX, ServerState, build_router, directory, err_resp, ops};

/// Directory under the default workspace's `.premier/` holding the other repositories.
pub const REPOS_DIR: &str = "repos";
const META_FILE: &str = "repos.json";
/// `/git/repo.git` and `/git/auth/…` already mean the default repository.
const RESERVED: [&str; 2] = ["repo", "auth"];
const MAX_DESCRIPTION_CHARS: usize = 500;
/// Marker in a repository's `.premier/`: its `.access.toml` came with an import and is shown but
/// not enforced. Removed when the owner saves the policy.
pub(crate) const PENDING_POLICY: &str = "imported-policy-pending";
const GIT_TIMEOUT: Duration = Duration::from_secs(600);

type ApiErr = (StatusCode, Json<ApiError>);

/// What every non-default repository borrows from the default one.
pub struct Account {
    pub root: PathBuf,
    pub persisted: Arc<Mutex<PersistedState>>,
}

#[derive(Clone)]
struct Entry {
    state: ServerState,
    router: Router,
}

struct Inner {
    default_name: String,
    /// False for a standalone server started outside any git work tree: `default` then only
    /// hosts the control plane and is not listed as a repository.
    default_is_repo: bool,
    /// Serves every non-`/repos/<name>/` route (UI, health, auth, `/v1/*`).
    control_router: Router,
    default: ServerState,
    repos_dir: PathBuf,
    repos: RwLock<BTreeMap<String, Entry>>,
    /// Serialises read-modify-write of `repos.json`.
    meta_lock: Mutex<()>,
}

#[derive(Clone)]
pub struct Registry(Arc<Inner>);

/// Non-owning handle stored on `ServerState` so cross-repo operations avoid an `Arc` cycle.
#[derive(Clone)]
pub struct RegistryHandle(Weak<Inner>);

impl RegistryHandle {
    pub fn states(&self) -> Vec<ServerState> {
        self.0
            .upgrade()
            .map(|inner| Registry(inner).states())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Meta {
    #[serde(default)]
    description: String,
    #[serde(default)]
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct Repo {
    pub name: String,
    pub description: String,
    pub is_default: bool,
    pub default_branch: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub head_oid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRepo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub import_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatchRepo {
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRepo {
    #[serde(default)]
    pub confirm: String,
}

fn bad(msg: impl Into<String>) -> ApiErr {
    err_resp(StatusCode::BAD_REQUEST, msg)
}

fn ise(msg: impl Into<String>) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

fn not_found() -> ApiErr {
    err_resp(StatusCode::NOT_FOUND, "repository not found")
}

/// `[a-z0-9][a-z0-9._-]{0,62}`, and nothing that collides with a route or a path component.
pub fn valid_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = name.len() <= 63
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
    if !ok {
        return Err(
            "name must be 1-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
                .to_owned(),
        );
    }
    if name.ends_with(".git") {
        return Err("name must not end in .git".to_owned());
    }
    if RESERVED.contains(&name) {
        return Err(format!("'{name}' is a reserved name"));
    }
    Ok(())
}

/// The default repository's name from its directory name: whatever survives sanitising.
fn default_name(workspace_root: &Path) -> String {
    let raw = std::fs::canonicalize(workspace_root)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    let name: String = raw
        .trim_end_matches(".git")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take(63)
        .collect();
    if valid_name(&name).is_ok() {
        name
    } else {
        "default".to_owned()
    }
}

fn valid_description(raw: &str) -> Result<String, ApiErr> {
    let description = raw.trim();
    if description.chars().count() > MAX_DESCRIPTION_CHARS || description.contains(char::is_control)
    {
        return Err(bad(format!(
            "description must be at most {MAX_DESCRIPTION_CHARS} characters on one line"
        )));
    }
    Ok(description.to_owned())
}

/// Addresses an import never fetches from: this host and its link. Unless the server was started
/// with `--allow-private-imports`, also everything that is not the public internet: RFC 1918,
/// CGNAT (100.64/10, where tailnets live) and IPv6 unique-local addresses.
fn blocked_ip(ip: IpAddr, allow_private: bool) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let this_network = a == 0;
            let cgnat = a == 100 && (b & 0xc0) == 64;
            let reserved = a >= 240;
            let benchmark = a == 198 && (b == 18 || b == 19);
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || this_network
                || reserved
                || (!allow_private && (v4.is_private() || cgnat || benchmark))
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48.
            let nat64 = segs[0] == 0x0064
                && segs[1] == 0xff9b
                && ((segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0)
                    || segs[2] == 0x0001);
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xffc0) == 0xfec0
                || nat64
                || (!allow_private && (segs[0] & 0xfe00) == 0xfc00)
        }
    }
}

/// The only URLs an import may fetch: plain `https://host/...`. Everything git would treat as a
/// transport, a helper or an option (`ssh://`, `file://`, `git://`, `ext::`, `host:path`, `-o…`)
/// fails here, before any process is spawned.
pub fn validate_import_url(raw: &str, allow_private: bool) -> Result<url::Url, String> {
    if !raw.starts_with("https://") || raw.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err("import_url must be an https:// URL".to_owned());
    }
    let url = url::Url::parse(raw).map_err(|e| format!("import_url is not a valid URL: {e}"))?;
    let blocked = match url.host() {
        _ if url.scheme() != "https" => true,
        None => true,
        Some(url::Host::Ipv4(ip)) => blocked_ip(ip.into(), allow_private),
        Some(url::Host::Ipv6(ip)) => blocked_ip(ip.into(), allow_private),
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
    };
    if blocked {
        return Err("import_url must name a public https host".to_owned());
    }
    Ok(url)
}

/// [`validate_import_url`] plus a look at where the host name points. Also returns the
/// `http.curloptResolve` entry that pins git to the addresses vetted here, so a DNS-rebinding host
/// cannot hand git a different one a moment later.
async fn check_import_url(
    raw: &str,
    allow_private: bool,
) -> Result<(url::Url, Option<String>), String> {
    let url = validate_import_url(raw, allow_private)?;
    let Some(url::Host::Domain(host)) = url.host() else {
        return Ok((url, None));
    };
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("cannot resolve import host: {e}"))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() || addrs.iter().any(|ip| blocked_ip(*ip, allow_private)) {
        return Err("import_url must name a public https host".to_owned());
    }
    let pin = curlopt_resolve(host, port, &addrs);
    Ok((url, Some(pin)))
}

/// `HOST:PORT:ADDR[,ADDR]...`, the form `http.curloptResolve` takes.
fn curlopt_resolve(host: &str, port: u16, addrs: &[IpAddr]) -> String {
    let addrs: Vec<String> = addrs
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        })
        .collect();
    format!("{host}:{port}:{}", addrs.join(","))
}

/// Arguments of the import clone; with `pin`, git connects only to the vetted addresses.
/// Uses `--no-checkout` so quarantine & reserved-path validation run before any file touches disk.
fn clone_args(url: &str, pin: Option<&str>) -> Vec<String> {
    let pin = pin.map(|p| ["-c".to_owned(), format!("http.curloptResolve={p}")]);
    pin.into_iter()
        .flatten()
        .chain(
            [
                "clone",
                "--no-checkout",
                "--no-recurse-submodules",
                "--",
                url,
                ".",
            ]
            .map(str::to_owned),
        )
        .collect()
}

/// Run git in `dir`, non-interactively and https-only, killed after [`GIT_TIMEOUT`].
async fn run_git<S: AsRef<std::ffi::OsStr>>(dir: &Path, args: &[S]) -> Result<(), String> {
    let child = tokio::process::Command::from(premier_git_bridge::git_command(dir))
        // No stored credentials for a URL the caller chose, and no redirect to a host we did
        // not check.
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
        ])
        .args(args)
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GCM_INTERACTIVE", "never")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(GIT_TIMEOUT, child)
        .await
        .map_err(|_| "git timed out".to_owned())?
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tail: Vec<char> = stderr.trim().chars().rev().take(600).collect();
    Err(format!(
        "git failed: {}",
        tail.into_iter().rev().collect::<String>()
    ))
}

/// Trimmed stdout of a read-only git query in `dir`; `None` when git says no.
pub(crate) fn git_out(dir: &Path, args: &[&str]) -> Option<String> {
    let out = premier_git_bridge::git_command(dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn head_branch(dir: &Path) -> Option<String> {
    git_out(dir, &["symbolic-ref", "-q", "--short", "HEAD"])
}

/// Whether a member may know this repository exists: they can `traverse` its root on at least
/// one ref they can see. Same ref defaults as the Git projection (unlisted private-namespace
/// refs are visible to nobody).
fn visible_to(state: &ServerState, me: &DelegatedIdentity) -> bool {
    let (Some(policy), Ok(root)) = (state.current_policy(), RepoPath::new("")) else {
        return false;
    };
    let dir = &state.workspace_root;
    let listed = git_out(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads",
            PRIVATE_REF_PREFIX,
        ],
    )
    .unwrap_or_default();
    // A repository with no commit yet has no refs: judge it by the branch HEAD names.
    let unborn = head_branch(dir).map(|b| format!("refs/heads/{b}"));
    let overrides = state.branch_visibility_map();
    listed.lines().chain(unborn.as_deref()).any(|full| {
        let short = full
            .strip_prefix(PRIVATE_REF_PREFIX)
            .or_else(|| full.strip_prefix("refs/heads/"))
            .unwrap_or(full);
        let visibility = overrides
            .get(full)
            .cloned()
            .unwrap_or_else(|| crate::default_ref_visibility(full));
        premier_git_bridge::can_see_ref(me, &visibility)
            && policy
                .explain(me, &root, short)
                .effective
                .contains(Capability::TRAVERSE)
    })
}

/// Layer on every repository's router, just inside the auth gate: to a caller who can see nothing
/// in this repository it answers exactly as dispatch does for a name that is not a repository
/// (same status, same body), on every route, so neither Git nor `/r/<name>/…` is a name oracle.
/// Owners and the default repository (whose existence is no secret) pass.
// shortcut: two git subprocesses per member/anonymous request to a non-default repository; cache
// `visible_to` per (principal, policy, refs) if that shows up in profiles.
pub(crate) async fn hide_from_strangers(
    State(state): State<ServerState>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let ext = req.extensions();
    let owner = ext
        .get::<AuthUser>()
        .is_some_and(|u| u.role == auth::Role::Owner);
    let me = match (ext.get::<auth::GitCaller>(), ext.get::<AuthUser>()) {
        (Some(git), _) => Some(git.0.clone()),
        (None, user) => {
            let principal = user
                .and_then(|u| Principal::parse(&format!("@{}", u.username)).ok())
                .unwrap_or(Principal::Anonymous);
            directory::groups_for(&state, &principal)
                .ok()
                .map(|groups| DelegatedIdentity::human_only(principal, groups))
        }
    };
    if state.account.is_none() || owner || me.is_some_and(|me| visible_to(&state, &me)) {
        next.run(req).await
    } else {
        not_found().into_response()
    }
}

/// What an import leaves behind before the repository is opened. Server state is never taken
/// from the imported tree (pre-granted approvals, branch visibility, a planted vault), and an
/// imported `.access.toml` is not trusted either: the file stays as it is, but [`PENDING_POLICY`]
/// keeps the built-in owner-only policy in force until the owner saves a policy from the Studio.
/// Returns whether the import carried a policy. A config file that is not a regular file (a
/// symlink names a path, never content of its own) refuses the import.
fn quarantine_import(dir: &Path, state_root: Option<(&Path, &str)>) -> Result<bool, ApiErr> {
    // Bound before the marker below is written, so that never lands in the imported tree.
    if let Some((root, name)) = state_root {
        crate::store::bind_state_dir(dir, root, name, false);
    }
    for name in crate::canon::CONFIG_FILES {
        require_regular_config(dir, "HEAD", name).map_err(bad)?;
    }
    for internal in [".premier", ".premier-local"] {
        let _ = std::fs::remove_dir_all(dir.join(internal));
        let _ = std::fs::remove_file(dir.join(internal));
    }
    let imported_policy = git_out(dir, &["cat-file", "-e", "HEAD:.access.toml"]).is_some();
    if imported_policy {
        let state = crate::store::state_dir(dir);
        premier_secrets::create_state_dir(&state)
            .and_then(|()| premier_secrets::write_private(&state.join(PENDING_POLICY), b""))
            .map_err(|e| ise(format!("could not hold back the imported policy: {e}")))?;
    }
    Ok(imported_policy)
}

/// Refuse config file `name` ([`crate::canon::CONFIG_FILES`]) at `rev` when it is there but not a
/// regular file: a symlink's blob is a path (say, to the server's account store), not a policy.
pub(crate) fn require_regular_config(dir: &Path, rev: &str, name: &str) -> Result<(), String> {
    let entry = git_out(dir, &["ls-tree", "-z", rev, "--", name]).unwrap_or_default();
    match entry.split(' ').next() {
        None | Some("" | "100644" | "100755") => Ok(()),
        Some(_) => Err(format!(
            "{name} must be a regular file, not a symlink or a directory"
        )),
    }
}

/// Drop a deleted repository's state from the state directory (nothing to do without one: it
/// goes with the working tree).
fn forget_state(dir: &Path) {
    if crate::store::state_root(dir).is_some() {
        crate::store::remove_state_dir(dir);
    }
}

/// Remove a directory tree even when git packfiles or subdirectories are marked read-only
/// (as `git clone` does for `.git/objects/pack/*.pack` and `*.idx` on Windows).
fn remove_dir_all_force(path: &Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        let err = match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => e,
        };
        #[cfg(windows)]
        {
            return match std::fs::remove_dir(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(err),
            };
        }
        #[cfg(not(windows))]
        return Err(err);
    }
    if meta.is_dir() {
        let mut perms = meta.permissions();
        if perms.readonly() {
            clear_readonly_for_delete(&mut perms);
            match std::fs::set_permissions(path, perms) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            remove_dir_all_force(&entry.path())?;
        }
        match std::fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        let mut perms = meta.permissions();
        if perms.readonly() {
            clear_readonly_for_delete(&mut perms);
            match std::fs::set_permissions(path, perms) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Grants owner write permission (or clears Windows `FILE_ATTRIBUTE_READONLY`) immediately before
/// deleting a path; never widens Unix group/other bits.
fn clear_readonly_for_delete(perms: &mut std::fs::Permissions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(perms.mode() | 0o200);
    }
    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        perms.set_readonly(false);
    }
}

/// Where the other repositories' working trees live unless `--repos-dir` says: beside the state,
/// never under a hosted repository's tree, when there is a state directory.
fn default_repos_dir(workspace_root: &Path) -> PathBuf {
    match crate::store::state_root(workspace_root) {
        Some(root) => root.join("worktrees"),
        None => crate::store::state_dir(workspace_root).join(REPOS_DIR),
    }
}

/// The name the repository in `workspace_root` is served under: `name` when valid, else from
/// its directory.
pub fn repo_name(workspace_root: &Path, name: Option<&str>) -> String {
    match name.filter(|n| valid_name(n).is_ok()) {
        Some(name) => name.to_owned(),
        None => default_name(workspace_root),
    }
}

/// `premier serve --state-dir <dir>`: from now on ALL server state of the repository in
/// `workspace_root` (and of every repository opened next to it) lives under `state_root`. Call
/// before the [`ServerState`] is built. State an earlier server left in the working tree is moved
/// in once, when the state directory has none; `move_repos`: `--repos-dir` was not given, so the
/// old default `.premier/repos` moves too.
pub fn configure_state_dir(
    workspace_root: &Path,
    state_root: &Path,
    name: Option<&str>,
    move_repos: bool,
) -> Result<(), String> {
    let name = repo_name(workspace_root, name);
    std::fs::create_dir_all(state_root).map_err(|e| {
        format!(
            "create state directory {} failed: {e}",
            state_root.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("state directory {}: {e}", state_root.display()))?;
    }
    crate::store::bind_state_dir(workspace_root, state_root, &name, true);
    let mut moved = crate::store::adopt_legacy_state(workspace_root)?;
    let legacy_repos = workspace_root.join(".premier").join(REPOS_DIR);
    let repos = default_repos_dir(workspace_root);
    if move_repos && legacy_repos.is_dir() && !repos.exists() {
        // Whole git working trees: renamed, never copied file by file.
        std::fs::rename(&legacy_repos, &repos).map_err(|e| {
            format!(
                "could not move {} to {} ({e}): move it yourself, or start with --repos-dir {}",
                legacy_repos.display(),
                repos.display(),
                legacy_repos.display()
            )
        })?;
        let _ = std::fs::remove_dir(workspace_root.join(".premier"));
        moved.push(".premier/repos".to_owned());
    }
    if !moved.is_empty() {
        tracing::info!(repo = %workspace_root.display(), state_dir = %state_root.display(), moved = %moved.join(", "), "moved server state out of the working tree into the state directory");
    }
    Ok(())
}

/// Where a request path leads: `Some((repository, path inside its router))`, or `None` for the
/// default repository with the path untouched.
fn route(path: &str) -> Option<(&str, String)> {
    if let Some(rest) = path.strip_prefix("/r/") {
        let (name, rest) = rest.split_once('/').unwrap_or((rest, ""));
        return Some((name, format!("/{rest}")));
    }
    for (prefix, inner) in [
        ("/git/auth/", "/git/auth/repo.git/"),
        ("/git/", "/git/repo.git/"),
    ] {
        if let Some((name, rest)) = path
            .strip_prefix(prefix)
            .and_then(|p| p.split_once(".git/"))
        {
            return (name != "repo").then(|| (name, format!("{inner}{rest}")));
        }
    }
    None
}

/// Whether `path` belongs to the server/account control plane (or static UI fallback) and may be
/// served without a default repository configured.
fn is_control_plane_path(path: &str) -> bool {
    if path == "/v1" || path == "/git" || path.starts_with("/git/") {
        return false;
    }
    if !path.starts_with("/v1/") {
        return true;
    }
    matches!(
        path,
        "/v1/auth"
            | "/v1/users"
            | "/v1/directory"
            | "/v1/settings"
            | "/v1/security/offboard"
            | "/v1/oidc/discovery"
            | "/v1/oidc/verify"
            | "/v1/backup"
            | "/v1/traces"
            | "/v1/events/stream"
    ) || path.starts_with("/v1/auth/")
        || path.starts_with("/v1/users/")
        || path.starts_with("/v1/directory/")
        || path.starts_with("/v1/security/offboard/")
        || path.starts_with("/v1/traces/")
}

/// The per-repository router sees the request as if it were the only repository.
async fn dispatch(State(reg): State<Registry>, mut req: Request) -> Response {
    let mut router = None;
    if let Some((name, inner)) = route(req.uri().path()) {
        let inner = match req.uri().query() {
            Some(q) => format!("{inner}?{q}"),
            None => inner,
        };
        let mut parts = req.uri().clone().into_parts();
        parts.path_and_query = inner.parse().ok();
        let Ok(uri) = Uri::from_parts(parts) else {
            return not_found().into_response();
        };
        // An unknown name still passes the gate first, so a signed-out caller gets the same 401
        // whether or not the repository exists.
        router = Some(match reg.entry(name) {
            Some(entry) => entry.router,
            None => Router::new().fallback(|| async { not_found() }).layer(
                axum::middleware::from_fn_with_state(reg.0.default.clone(), auth::gate),
            ),
        });
        *req.uri_mut() = uri;
    }
    if router.is_none() && !reg.0.default_is_repo && !is_control_plane_path(req.uri().path()) {
        return err_resp(
            StatusCode::NOT_FOUND,
            "no default repository configured; address a repository under /r/<name>/",
        )
        .into_response();
    }
    let mut router = router.unwrap_or_else(|| reg.0.control_router.clone());
    match router.call(req).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    }
}

fn owner(methods: MethodRouter<Registry>) -> MethodRouter<Registry> {
    methods.route_layer(axum::middleware::from_fn(auth::require_owner))
}

impl Registry {
    /// `default` is the repository the server was started in; every git work tree directly
    /// under `repos_dir` (default `<default workspace>/.premier/repos`) is loaded next to it.
    pub fn open(
        mut default: ServerState,
        name: Option<String>,
        repos_dir: Option<PathBuf>,
    ) -> Self {
        let default_name = repo_name(&default.workspace_root, name.as_deref());
        let repos_dir = repos_dir.unwrap_or_else(|| default_repos_dir(&default.workspace_root));
        default.repos_dir = Some(repos_dir.clone());
        let default_is_repo = default.workspace_root.join(".git").exists();
        let control_router = build_router(default.clone());
        let mut repos = BTreeMap::new();
        if default_is_repo {
            repos.insert(
                default_name.clone(),
                Entry {
                    router: control_router.clone(),
                    state: default.clone(),
                },
            );
        }
        let reg = Self(Arc::new(Inner {
            default_name,
            default_is_repo,
            control_router,
            default,
            repos_dir,
            repos: RwLock::new(BTreeMap::new()),
            meta_lock: Mutex::new(()),
        }));
        if let Ok(mut slot) = reg.0.default.repo_registry.write() {
            *slot = Some(reg.downgrade());
        }
        for dir in std::fs::read_dir(&reg.0.repos_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = dir.file_name().to_string_lossy().into_owned();
            // Without its own `.git`, git run in there would answer for the enclosing repository.
            if valid_name(&name).is_err()
                || repos.contains_key(&name)
                || !dir.path().join(".git").exists()
            {
                continue;
            }
            match reg.open_repo(&dir.path()) {
                Ok(entry) => {
                    repos.insert(name, entry);
                }
                Err(e) => tracing::error!(repo = %name, error = %e, "repository not loaded"),
            }
        }
        if let Ok(mut guard) = reg.0.repos.write() {
            *guard = repos;
        }
        reg
    }

    /// The server's router: repository management, then per-repository dispatch.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/v1/repos",
                get(list_handler).merge(owner(post(create_handler))),
            )
            .route(
                "/v1/repos/{name}",
                owner(patch(patch_handler).delete(delete_handler)),
            )
            .layer(DefaultBodyLimit::max(ops::JSON_BODY_LIMIT))
            .layer(axum::middleware::from_fn_with_state(
                self.0.default.clone(),
                auth::gate,
            ))
            // Added after the layers: each repository's own router applies the gate and limits.
            .fallback(dispatch)
            .with_state(self.clone())
    }

    /// Every loaded repository's state (for the background jobs each one needs).
    pub fn states(&self) -> Vec<ServerState> {
        self.0
            .repos
            .read()
            .map(|g| g.values().map(|e| e.state.clone()).collect())
            .unwrap_or_default()
    }

    pub fn downgrade(&self) -> RegistryHandle {
        RegistryHandle(Arc::downgrade(&self.0))
    }

    /// The default repository's state (holds shared accounts and directory).
    pub fn default_state(&self) -> ServerState {
        self.0.default.clone()
    }

    /// Resolve a repository name (`"repo"`, the default repository's name, or any loaded named
    /// repository) to its [`ServerState`].
    pub(crate) fn state_for_repo(&self, name: &str) -> Option<ServerState> {
        let lookup = if self.0.default_is_repo && (name == "repo" || name == self.0.default_name) {
            self.0.default_name.as_str()
        } else {
            name
        };
        self.entry(lookup).map(|e| e.state)
    }

    /// Enforce the exact same repository visibility invariant as HTTP [`hide_from_strangers`]:
    /// owners and the default repository pass; non-owners must be able to traverse the root on
    /// at least one ref they can see.
    pub(crate) fn is_visible_to(
        &self,
        state: &ServerState,
        user: &premier_ssh::SshAuthenticatedUser,
        identity: &DelegatedIdentity,
    ) -> bool {
        state.account.is_none() || user.is_owner || visible_to(state, identity)
    }

    fn entry(&self, name: &str) -> Option<Entry> {
        self.0.repos.read().ok()?.get(name).cloned()
    }

    /// Build the state and router of the repository in `dir`: its own policy, schema, vault,
    /// audit log, approvals and sessions; the default repository's accounts.
    fn open_repo(&self, dir: &Path) -> Result<Entry, String> {
        let default = &self.0.default;
        let policy_path = dir.join(".access.toml");

        // The clone keeps what is shared: accounts, trusted proxies, server policy.
        let mut state = default.clone();
        state.account = Some(Arc::new(Account {
            root: default.account_root().to_path_buf(),
            persisted: Arc::clone(default.settings_state()),
        }));
        state.workspace_root = dir.to_path_buf();
        // With a state directory this repository's state is kept there too, never in its tree.
        if let (Some(root), Some(name)) = (
            crate::store::state_root(&default.workspace_root),
            dir.file_name(),
        ) {
            crate::store::bind_state_dir(dir, &root, &name.to_string_lossy(), false);
            let moved = crate::store::adopt_legacy_state(dir)?;
            if !moved.is_empty() {
                tracing::info!(repo = %dir.display(), moved = %moved.join(", "), "moved server state out of the working tree into the state directory");
            }
        }
        state.policy = Arc::default();
        state.repo_policy_path = Some(policy_path);
        state.repo_policy_file = Arc::default();
        state.jobs = Arc::default();
        state.readiness_probe = Arc::default();
        state.repo_policy_toml = Arc::default();
        state.env_schema = Arc::default();
        // Policy and schema as committed on its default branch (see `reload_repo_config`).
        state.reload_repo_config()?;
        state.audit_sink = Arc::new(AuditSink::new(Some(crate::store::audit_path(dir))));
        state.approval_hub = Arc::new(ops::load_approvals(dir));
        state.trace_store = Arc::new(premier_trace::TraceStore::new(
            Some(crate::store::traces_path(dir)),
            premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
        ));
        state.mcp_pins = Arc::new(crate::mcp_gateway::load_pins(dir));
        state.persisted = Arc::new(Mutex::new(load_state(dir)?));
        state.session_manager =
            Arc::new(SessionManager::open(dir).with_trace_store(Arc::clone(&state.trace_store)));
        // Its own event channels: a clone would share the default repository's.
        state.lane_tx = tokio::sync::broadcast::channel(128).0;
        state.review_tx = tokio::sync::broadcast::channel(128).0;
        state.static_ui_dir = None;
        Ok(Entry {
            router: build_router(state.clone()),
            state,
        })
    }

    fn describe(&self, name: &str, entry: &Entry, meta: &BTreeMap<String, Meta>) -> Repo {
        let dir = &entry.state.workspace_root;
        let meta = meta.get(name).cloned().unwrap_or_default();
        Repo {
            name: name.to_owned(),
            description: meta.description,
            is_default: self.0.default_is_repo && name == self.0.default_name,
            default_branch: head_branch(dir),
            created_at: meta.created_at,
            head_oid: git_out(dir, &["rev-parse", "-q", "--verify", "HEAD"]),
        }
    }

    fn load_meta(&self) -> BTreeMap<String, Meta> {
        load_json_in(&account_dir(self.0.default.account_root()), META_FILE)
    }

    fn edit_meta(&self, f: impl FnOnce(&mut BTreeMap<String, Meta>)) -> Result<(), ApiErr> {
        let _guard = self
            .0
            .meta_lock
            .lock()
            .map_err(|_| ise("repository list lock poisoned"))?;
        let mut meta = self.load_meta();
        f(&mut meta);
        save_json_in(
            &account_dir(self.0.default.account_root()),
            META_FILE,
            &meta,
        )
        .map_err(ise)
    }
}

/// `GET /v1/repos`: default first, then by name. Members only see repositories they can enter.
async fn list_handler(State(reg): State<Registry>) -> Json<Vec<Repo>> {
    let entries: Vec<(String, Entry)> = reg
        .0
        .repos
        .read()
        .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let owner = auth::caller_is_owner();
    let me = auth::actor_principal();
    let meta = reg.load_meta();
    let mut repos: Vec<Repo> = entries
        .iter()
        .filter(|(_, entry)| {
            owner
                || directory::identity(&entry.state, &me, None, "repos")
                    .is_ok_and(|id| visible_to(&entry.state, &id))
        })
        .map(|(name, entry)| {
            let mut repo = reg.describe(name, entry, &meta);
            if !owner {
                // The default branch's tip as the member's clone has it; neither it nor the
                // branch's name where her clone has no such branch.
                let ids = directory::identity(&entry.state, &me, None, "repos")
                    .and_then(|id| crate::GitIds::of(&entry.state, &id));
                repo.head_oid = ids
                    .ok()
                    .zip(repo.default_branch.as_deref())
                    .and_then(|(ids, b)| ids.tip(b, ""));
                if repo.head_oid.is_none() {
                    repo.default_branch = None;
                }
            }
            repo
        })
        .collect();
    repos.sort_by_key(|r| !r.is_default);
    Json(repos)
}

/// `POST /v1/repos`: `git init` (branch `main`), or an https-only clone of `import_url`.
async fn create_handler(
    State(reg): State<Registry>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(body): Json<CreateRepo>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    ops::require_session(&user, "creating a repository")?;
    let name = body.name;
    valid_name(&name).map_err(bad)?;
    let description = valid_description(body.description.as_deref().unwrap_or_default())?;
    let import = match body.import_url.as_deref().filter(|u| !u.is_empty()) {
        Some(raw) => Some(
            check_import_url(raw, reg.0.default.allow_private_imports)
                .await
                .map_err(bad)?,
        ),
        None => None,
    };
    let taken = || {
        err_resp(
            StatusCode::CONFLICT,
            format!("repository '{name}' already exists"),
        )
    };
    if reg.entry(&name).is_some() {
        return Err(taken());
    }
    // Creating the directory is the reservation: a concurrent create of the same name loses here.
    let dir = reg.0.repos_dir.join(&name);
    premier_secrets::create_state_dir(&account_dir(reg.0.default.account_root()))
        .and_then(|()| std::fs::create_dir_all(&reg.0.repos_dir))
        .map_err(|e| ise(format!("create repos dir failed: {e}")))?;
    std::fs::create_dir(&dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => taken(),
        _ => ise(format!("create repository dir failed: {e}")),
    })?;

    let made = match &import {
        Some((url, pin)) => run_git(&dir, &clone_args(url.as_str(), pin.as_deref()))
            .await
            .map_err(|e| err_resp(StatusCode::BAD_GATEWAY, e)),
        None => run_git(&dir, &["init", "-q", "-b", "main"])
            .await
            .map_err(ise),
    }
    // A new id before anything binds its state: never the state a repository of this name left.
    .and_then(|()| crate::store::new_repo_id(&dir).map_err(ise))
    .and_then(|_| match &import {
        Some(_) => {
            let root = crate::store::state_root(&reg.0.default.workspace_root);
            quarantine_import(&dir, root.as_deref().map(|r| (r, name.as_str())))
        }
        None => Ok(false),
    });
    let made = match made {
        Ok(imported) if import.is_some() => {
            if git_out(&dir, &["rev-parse", "-q", "--verify", "HEAD"]).is_some() {
                if let Some(why) = crate::canon::unsafe_to_check_out(&dir, "HEAD", &[]) {
                    Err(bad(format!(
                        "the imported repository cannot be checked out safely: {why}"
                    )))
                } else {
                    run_git(&dir, &["checkout", "-q", "HEAD"])
                        .await
                        .map(|()| imported)
                        .map_err(ise)
                }
            } else {
                Ok(imported)
            }
        }
        other => other,
    };
    let opened = made.and_then(|imported| Ok((imported, reg.open_repo(&dir).map_err(bad)?)));
    let (imported_policy, entry) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            forget_state(&dir);
            let _ = remove_dir_all_force(&dir);
            return Err(e);
        }
    };
    reg.0
        .repos
        .write()
        .map_err(|_| ise("repository registry lock poisoned"))?
        .insert(name.clone(), entry.clone());
    let meta = Meta {
        description,
        created_at: Some(Utc::now()),
    };
    reg.edit_meta(|m| {
        m.insert(name.clone(), meta);
    })?;
    ops::spawn_background(&entry.state);
    let detail = match &import {
        Some((url, _)) => format!(
            "{name} (imported from {})",
            url.host_str().unwrap_or_default()
        ),
        None => name.clone(),
    };
    auth::log_event(&reg.0.default.auth, &headers, &ip, "repo_created", detail);
    let mut repo = serde_json::to_value(reg.describe(&name, &entry, &reg.load_meta()))
        .map_err(|e| ise(e.to_string()))?;
    repo["imported_policy"] = imported_policy.into();
    Ok(Json(repo))
}

/// `PATCH /v1/repos/{name}`: change the description.
async fn patch_handler(
    State(reg): State<Registry>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<PatchRepo>,
) -> Result<Json<Repo>, ApiErr> {
    ops::require_session(&user, "changing a repository")?;
    let entry = reg.entry(&name).ok_or_else(not_found)?;
    let description = valid_description(&body.description)?;
    reg.edit_meta(|m| m.entry(name.clone()).or_default().description = description)?;
    auth::log_event(
        &reg.0.default.auth,
        &headers,
        &ip,
        "repo_updated",
        name.clone(),
    );
    Ok(Json(reg.describe(&name, &entry, &reg.load_meta())))
}

/// `DELETE /v1/repos/{name}` with `{ "confirm": "<name>" }`: unregister, stop its background jobs
/// and agent sessions, then delete from disk.
async fn delete_handler(
    State(reg): State<Registry>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<DeleteRepo>,
) -> Result<StatusCode, ApiErr> {
    ops::require_session(&user, "deleting a repository")?;
    if reg.entry(&name).is_none() {
        return Err(not_found());
    }
    if reg.0.default_is_repo && name == reg.0.default_name {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "the default repository cannot be deleted",
        ));
    }
    if body.confirm != name {
        return Err(bad("confirm must equal the repository name"));
    }
    let removed = reg
        .0
        .repos
        .write()
        .map_err(|_| ise("repository registry lock poisoned"))?
        .remove(&name)
        .ok_or_else(not_found)?;
    auth::log_event(
        &reg.0.default.auth,
        &headers,
        &ip,
        "repo_deleted",
        name.clone(),
    );
    reg.edit_meta(|m| {
        m.remove(&name);
    })?;
    removed.state.stop().await;
    let dir = removed.state.workspace_root.clone();
    drop(removed);
    tokio::task::spawn_blocking(move || {
        forget_state(&dir);
        remove_dir_all_force(&dir)
    })
    .await
    .map_err(|e| ise(e.to_string()))?
    .map_err(|e| {
        ise(format!(
            "repository unregistered, but deleting its directory failed: {e}"
        ))
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::body::Body;
    use axum::http::Method;
    use http_body_util::BodyExt;
    use premier_policy::{CompiledPolicy, parse_policy_toml};
    use serde_json::{Value, json};

    use super::*;

    const PW: &str = "correct horse battery";

    /// Default repository in `root` under the owners-only policy, with an owner and a member.
    /// Returns `(registry, owner cookie, owner token, member cookie)`.
    fn registry(root: &Path) -> (Registry, String, String, String) {
        std::fs::write(root.join("README.md"), "# default\n").unwrap();
        crate::tests::commit_all(root);
        let file = parse_policy_toml(directory::DEFAULT_POLICY_TOML).unwrap();
        let policy = CompiledPolicy::compile(None, &file).unwrap();
        let mut state =
            ServerState::minimal(Some(Arc::new(policy)), None, Arc::new(AuditSink::default()));
        state.workspace_root = root.to_path_buf();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.auth = Arc::new(auth::AuthStore::open(root));
        state.static_ui_dir = None;
        state.allow_unsandboxed_agents = true;
        let (owner, token) = state.auth.seed("owner", PW);
        let (mia, _) = state.auth.seed_as("mia", PW, auth::Role::Member);
        (
            Registry::open(state, Some("home".to_owned()), None),
            owner,
            token,
            mia,
        )
    }

    async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Vec<u8>) {
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
        let resp = router.clone().call(req.unwrap()).await.unwrap();
        let status = resp.status();
        (
            status,
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    fn js(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap_or(Value::Null)
    }

    fn names(body: &[u8]) -> Vec<String> {
        js(body)
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn names_and_import_urls_are_validated() {
        for ok in ["a", "docs", "my-repo.v2", "0day_x"] {
            assert!(valid_name(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(64);
        for bad in [
            "", ".", "..", ".hidden", "-x", "Caps", "a/b", "a b", "x.git", "repo", "auth", &long,
        ] {
            assert!(valid_name(bad).is_err(), "{bad}");
        }

        assert!(validate_import_url("https://example.com/org/repo.git", false).is_ok());
        assert!(validate_import_url("https://user:tok@example.com:8443/r.git", false).is_ok());
        for bad in [
            "file:///etc/passwd",
            "ssh://git@example.com/r.git",
            "git://example.com/r.git",
            "http://example.com/r.git",
            "http://127.0.0.1/x",
            "ext::sh -c 'touch /tmp/pwned'",
            "-oProxyCommand=calc",
            "--upload-pack=calc",
            "git@example.com:org/repo.git",
            "example.com/r.git",
            "HTTPS://example.com/r.git",
            " https://example.com/r.git",
            "https://example.com/r.git\n",
            "https://",
            "https://127.0.0.1/x",
            "https://127.1/x",
            "https://2130706433/x",
            "https://0x7f.0.0.1/x",
            "https://[::1]/x",
            "https://[::ffff:127.0.0.1]/x",
            "https://169.254.169.254/latest/meta-data",
            "https://[fe80::1]/x",
            "https://0.0.0.0/x",
            "https://localhost/x",
            "https://foo.localhost:8443/x",
        ] {
            assert!(validate_import_url(bad, false).is_err(), "{bad}");
        }
        // Private, CGNAT (tailnet) and unique-local hosts: only with `--allow-private-imports`,
        // which never opens loopback or link-local.
        for private in [
            "https://10.0.0.5/x",
            "https://172.16.0.1/x",
            "https://192.168.1.10/x",
            "https://100.64.0.1/x",
            "https://100.127.255.254/x",
            "https://[fd00::1]/x",
            "https://[::ffff:10.0.0.5]/x",
        ] {
            assert!(validate_import_url(private, false).is_err(), "{private}");
            assert!(validate_import_url(private, true).is_ok(), "{private}");
        }
        for never in [
            "https://127.0.0.1/x",
            "https://169.254.169.254/x",
            "https://[::1]/x",
        ] {
            assert!(validate_import_url(never, true).is_err(), "{never}");
        }
        assert!(validate_import_url("https://100.128.0.1/x", false).is_ok());
    }

    #[test]
    fn an_import_clone_is_pinned_to_the_vetted_addresses() {
        let addrs = [
            "93.184.216.34".parse().unwrap(),
            "2606:2800::1".parse().unwrap(),
        ];
        let pin = curlopt_resolve("example.com", 443, &addrs);
        assert_eq!(pin, "example.com:443:93.184.216.34,[2606:2800::1]");
        let url = "https://example.com/org/r.git";
        assert_eq!(
            clone_args(url, Some(&pin)),
            [
                "-c",
                "http.curloptResolve=example.com:443:93.184.216.34,[2606:2800::1]",
                "clone",
                "--no-checkout",
                "--no-recurse-submodules",
                "--",
                url,
                ".",
            ]
        );
        // An address literal needs no pin: there is nothing for DNS to change.
        assert_eq!(clone_args(url, None)[0], "clone");
    }

    #[test]
    fn paths_route_to_the_right_repository() {
        let to = |name: &'static str, path: &str| Some((name, path.to_owned()));
        assert_eq!(route("/r/docs/v1/repo/tree"), to("docs", "/v1/repo/tree"));
        assert_eq!(route("/r/docs"), to("docs", "/"));
        assert_eq!(
            route("/git/docs.git/info/refs"),
            to("docs", "/git/repo.git/info/refs")
        );
        assert_eq!(
            route("/git/auth/docs.git/git-upload-pack"),
            to("docs", "/git/auth/repo.git/git-upload-pack")
        );
        for default in [
            "/",
            "/health",
            "/v1/repo/tree",
            "/git/repo.git/info/refs",
            "/git/auth/repo.git/info/refs",
        ] {
            assert_eq!(route(default), None, "{default}");
        }
    }

    #[test]
    fn default_repository_is_named_after_its_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("My Project.git");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(default_name(&dir), "my-project");
        let reserved = tmp.path().join("repo");
        std::fs::create_dir(&reserved).unwrap();
        assert_eq!(default_name(&reserved), "default");
    }

    #[tokio::test]
    async fn imported_policy_is_shown_but_not_enforced_until_the_owner_saves() {
        const OPEN: &str = "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\n\
            [[rules]]\nid = \"owners\"\neffect = \"allow\"\nprincipals = [\"group:owners\"]\n\
            paths = [\"**\"]\nrefs = [\"*\"]\ncapabilities = [\"traverse\", \"list\", \"read\", \"write\"]\n";
        let tmp = tempfile::tempdir().unwrap();
        let (reg, owner, _, _) = registry(tmp.path());
        // What a clone of a hostile repository leaves: its own policy and planted server state.
        let dir = tmp.path().join(".premier/repos/imported");
        std::fs::create_dir_all(dir.join(".premier")).unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join(".access.toml"), OPEN).unwrap();
        std::fs::write(dir.join(".premier/state.json"), "{}").unwrap();
        crate::tests::commit_all(&dir);

        assert!(quarantine_import(&dir, None).unwrap());
        assert!(!dir.join(".premier/state.json").exists());
        let anonymous_enters = |entry: &Entry| {
            let anonymous = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
            let policy = entry.state.current_policy().unwrap();
            policy
                .explain(&anonymous, &RepoPath::root(), "main")
                .allows(Capability::TRAVERSE)
        };
        let entry = reg.open_repo(&dir).unwrap();
        assert!(!anonymous_enters(&entry));
        assert_eq!(entry.state.current_repo_policy_toml(), OPEN);

        // Saving from the Studio is the owner's decision to use it, and it survives a restart.
        let save = Some(json!({ "toml": OPEN }));
        let owner = [("cookie", owner.as_str())];
        let (status, _) = call(&entry.router, Method::PUT, "/v1/policy/repo", &owner, save).await;
        assert_eq!(status, StatusCode::OK);
        assert!(anonymous_enters(&entry));
        assert!(anonymous_enters(&reg.open_repo(&dir).unwrap()));

        // An import without a policy has nothing to hold back.
        std::fs::remove_file(dir.join(".access.toml")).unwrap();
        crate::tests::commit_all(&dir);
        assert!(!quarantine_import(&dir, None).unwrap());
    }

    #[tokio::test]
    async fn a_config_file_that_is_a_symlink_is_refused_on_import_and_never_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let (reg, _, _, _) = registry(tmp.path());
        let dir = tmp.path().join("imported");
        std::fs::create_dir(&dir).unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("README.md"), "# x\n").unwrap();
        std::fs::write(dir.join("target.txt"), "/var/lib/premier/account/auth.json").unwrap();
        crate::tests::commit_all(&dir);
        let link = git(&dir, &["hash-object", "-w", "target.txt"]);
        let commit = |dir: &Path| {
            git(
                dir,
                &[
                    "-c",
                    "user.name=T",
                    "-c",
                    "user.email=t@example.com",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "x",
                ],
            );
        };
        for name in crate::canon::CONFIG_FILES {
            // A symlink entry, made without touching the filesystem: what a hostile remote has.
            git(
                &dir,
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("120000,{link},{name}"),
                ],
            );
            commit(&dir);
            let (status, body) = quarantine_import(&dir, None).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(
                body.0.error.contains(name) && body.0.error.contains("symlink"),
                "{}",
                body.0.error
            );
            let refused = reg.open_repo(&dir).err().unwrap();
            assert!(refused.contains("must be a regular file"), "{refused}");
            git(&dir, &["rm", "-q", "--cached", name]);
            commit(&dir);
        }
        assert!(!quarantine_import(&dir, None).unwrap());
        assert!(reg.open_repo(&dir).is_ok());
    }

    #[test]
    fn repository_state_is_keyed_by_a_stable_id_not_its_name() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let repo = |name: &str| {
            let dir = tmp.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            git(&dir, &["init", "-q", "-b", "main"]);
            dir
        };

        // Renaming the default repository keeps its vault.
        let home = repo("home");
        configure_state_dir(&home, &state, Some("home"), true).unwrap();
        let vault = crate::store::state_dir(&home);
        assert!(
            vault.starts_with(state.join("repos")) && vault != state.join("repos/home"),
            "{vault:?}"
        );
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("vault.toml"), "kept").unwrap();
        crate::store::unbind_state_dir(&home);
        configure_state_dir(&home, &state, Some("renamed"), true).unwrap();
        assert_eq!(crate::store::state_dir(&home), vault);
        assert_eq!(
            std::fs::read_to_string(vault.join("vault.toml")).unwrap(),
            "kept"
        );
        crate::store::unbind_state_dir(&home);

        // State an earlier server kept by name is adopted once, by the repository of that name.
        let old = repo("old");
        std::fs::create_dir_all(state.join("repos/old")).unwrap();
        std::fs::write(state.join("repos/old/vault.toml"), "legacy").unwrap();
        configure_state_dir(&old, &state, Some("old"), true).unwrap();
        let adopted = crate::store::state_dir(&old);
        assert_ne!(adopted, state.join("repos/old"));
        assert_eq!(
            std::fs::read_to_string(adopted.join("vault.toml")).unwrap(),
            "legacy"
        );
        assert!(!state.join("repos/old").exists());
        crate::store::unbind_state_dir(&old);
    }

    #[tokio::test]
    async fn a_repository_created_under_an_old_name_starts_with_fresh_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("home");
        std::fs::create_dir(&root).unwrap();
        let state = tmp.path().join("state");
        crate::tests::commit_all(&root);
        configure_state_dir(&root, &state, Some("home"), true).unwrap();
        let (reg, owner, _, _) = registry(&root);
        let router = reg.router();
        let owner = [("cookie", owner.as_str())];
        let create = || {
            call(
                &router,
                Method::POST,
                "/v1/repos",
                &owner,
                Some(json!({ "name": "wiki" })),
            )
        };
        let wiki = state.join("worktrees/wiki");

        let (status, _) = create().await;
        assert_eq!(status, StatusCode::OK);
        let secret = json!({ "key": "K", "value": "v" });
        let (status, _) = call(
            &router,
            Method::POST,
            "/r/wiki/v1/secrets/set",
            &owner,
            Some(secret),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let first = crate::store::state_dir(&wiki);
        assert!(first.join("vault.toml").is_file());
        let confirm = json!({ "confirm": "wiki" });
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/wiki",
            &owner,
            Some(confirm),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!first.exists());

        // What an older server left under the name is not the new repository's either.
        std::fs::create_dir_all(state.join("repos/wiki")).unwrap();
        std::fs::write(state.join("repos/wiki/vault.toml"), "stale").unwrap();
        let (status, _) = create().await;
        assert_eq!(status, StatusCode::OK);
        let second = crate::store::state_dir(&wiki);
        assert_ne!(second, first);
        assert_ne!(second, state.join("repos/wiki"));
        assert!(!second.join("vault.toml").exists());
        let (_, body) = call(
            &router,
            Method::GET,
            "/r/wiki/v1/secrets/status",
            &owner,
            None,
        )
        .await;
        assert_eq!(
            js(&body)["entries"],
            json!({}),
            "{}",
            String::from_utf8_lossy(&body)
        );
        for bound in [&root, &wiki] {
            crate::store::unbind_state_dir(bound);
        }
    }

    #[tokio::test]
    async fn standalone_server_without_git_starts_with_zero_repos_and_can_create_first_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(!root.join(".git").exists());
        let file = parse_policy_toml(directory::DEFAULT_POLICY_TOML).unwrap();
        let policy = CompiledPolicy::compile(None, &file).unwrap();
        let mut state =
            ServerState::minimal(Some(Arc::new(policy)), None, Arc::new(AuditSink::default()));
        state.workspace_root = root.to_path_buf();
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.auth = Arc::new(auth::AuthStore::open(root));
        state.static_ui_dir = None;
        state.allow_unsandboxed_agents = true;
        let (owner, _) = state.auth.seed("owner", PW);
        let reg = Registry::open(state, Some("home".to_owned()), None);
        let router = reg.router();
        let owner = [("cookie", owner.as_str())];

        // Server/account control-plane routes answer although no repository is loaded.
        for path in [
            "/health",
            "/v1/auth/status",
            "/v1/users",
            "/v1/settings",
            "/v1/directory",
            "/v1/security/offboard/receipts",
            "/v1/repos",
        ] {
            let (status, body) = call(&router, Method::GET, path, &owner, None).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let (_, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(js(&body), json!([]));

        // Repo-scoped API and Git routes return 404 on the bare control plane and never write to
        // `workspace_root`.
        let snapshot = |dir: &Path| -> Vec<String> {
            let mut entries = std::fs::read_dir(dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        };
        let before = snapshot(root);
        for (method, path, payload) in [
            (
                Method::POST,
                "/v1/overlays/mount",
                Some(json!({ "path": "secret.txt", "content": "hi" })),
            ),
            (Method::GET, "/v1/agents/sessions", None),
            (Method::GET, "/v1/github/status", None),
            (Method::GET, "/v1/worktable", None),
            (
                Method::GET,
                "/git/repo.git/info/refs?service=git-upload-pack",
                None,
            ),
        ] {
            let (status, body) = call(&router, method, path, &owner, payload).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                js(&body)["error"],
                "no default repository configured; address a repository under /r/<name>/"
            );
        }
        assert_eq!(snapshot(root), before);
        assert!(!root.join("secret.txt").exists());
        assert!(reg.default_state().all_repo_states().is_empty());

        let new = json!({ "name": "my-app" });
        let (status, body) = call(&router, Method::POST, "/v1/repos", &owner, Some(new)).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(js(&body)["is_default"], false);
        let (_, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(names(&body), ["my-app"]);
        assert_eq!(reg.default_state().all_repo_states().len(), 1);

        // Read-only git packfiles (as `git clone` leaves on Windows) must not block deletion.
        let repo_dir = root.join(".premier/repos/my-app");
        let pack_dir = repo_dir.join(".git/objects/pack");
        std::fs::create_dir_all(&pack_dir).unwrap();
        let pack_file = pack_dir.join("test.pack");
        std::fs::write(&pack_file, b"PACK").unwrap();
        let mut perms = std::fs::metadata(&pack_file).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&pack_file, perms).unwrap();

        let confirm = json!({ "confirm": "my-app" });
        let (status, body) = call(
            &router,
            Method::DELETE,
            "/v1/repos/my-app",
            &owner,
            Some(confirm),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!repo_dir.exists());
        let (_, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(js(&body), json!([]));
    }

    #[tokio::test]
    async fn create_list_dispatch_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let (reg, owner, token, mia) = registry(tmp.path());
        let router = reg.router();
        let owner = [("cookie", owner.as_str())];
        let mia = [("cookie", mia.as_str())];
        let bearer = format!("Bearer {token}");
        let bearer = [("authorization", bearer.as_str())];

        // Members and access tokens cannot create; neither can a cross-origin page.
        let new = json!({ "name": "docs", "description": "Team docs" });
        let (status, _) = call(&router, Method::POST, "/v1/repos", &mia, Some(new.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &router,
            Method::POST,
            "/v1/repos",
            &bearer,
            Some(new.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let evil = [owner[0], ("origin", "https://evil.example")];
        let (status, _) = call(&router, Method::POST, "/v1/repos", &evil, Some(new.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(&router, Method::GET, "/v1/repos", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        for name in ["Docs", "x.git", "repo", "auth", "..", "a/b"] {
            let (status, _) = call(
                &router,
                Method::POST,
                "/v1/repos",
                &owner,
                Some(json!({ "name": name })),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        }
        // Rejected by the validator: no directory is reserved, so git never ran.
        for url in [
            "file:///etc/passwd",
            "ssh://git@example.com/r.git",
            "ext::sh -c 'touch pwned'",
            "-oProxyCommand=calc",
            "http://127.0.0.1/x",
            "https://127.0.0.1/x",
        ] {
            let body = json!({ "name": "imported", "import_url": url });
            let (status, body) = call(&router, Method::POST, "/v1/repos", &owner, Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{url}");
            assert!(js(&body)["error"].is_string());
            assert!(
                !tmp.path().join(".premier/repos/imported").exists(),
                "{url}"
            );
        }

        let (status, body) = call(
            &router,
            Method::POST,
            "/v1/repos",
            &owner,
            Some(new.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let repo = js(&body);
        assert_eq!(repo["name"], "docs");
        assert_eq!(repo["description"], "Team docs");
        assert_eq!(repo["is_default"], false);
        assert_eq!(repo["default_branch"], "main");
        assert!(repo["head_oid"].is_null());
        assert!(repo["created_at"].is_string());
        assert_eq!(repo["imported_policy"], false);
        let (status, _) = call(&router, Method::POST, "/v1/repos", &owner, Some(new)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        // Server state directories ignore themselves, so `git add -A` never stages them.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".premier/.gitignore")).unwrap(),
            "*\n"
        );

        let docs = tmp.path().join(".premier/repos/docs");
        std::fs::write(docs.join("GUIDE.md"), "# guide\n").unwrap();
        git(&docs, &["add", "GUIDE.md"]);
        git(
            &docs,
            &[
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "guide",
            ],
        );
        let head = git(&docs, &["rev-parse", "HEAD"]);

        let (status, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names(&body), ["home", "docs"]);
        assert_eq!(js(&body)[0]["is_default"], true);
        assert_eq!(js(&body)[1]["head_oid"], head.as_str());
        // The member has no rule in either repository: neither name reaches them.
        let (status, body) = call(&router, Method::GET, "/v1/repos", &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names(&body), Vec::<String>::new());

        // One cookie, every repository; each shows its own files.
        let paths = |body: &[u8]| -> Vec<String> {
            js(body)["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["path"].as_str().unwrap().to_owned())
                .collect()
        };
        let (status, body) = call(&router, Method::GET, "/r/docs/v1/repo/tree", &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(paths(&body), ["GUIDE.md"]);
        let (status, body) = call(&router, Method::GET, "/v1/repo/tree", &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(paths(&body), ["README.md"]);
        let (_, same) = call(&router, Method::GET, "/r/home/v1/repo/tree", &owner, None).await;
        assert_eq!(paths(&same), ["README.md"]);
        // A repository the caller can see nothing in answers exactly like a name that is not
        // one: to a member under `/r/…`, and to an anonymous Git client.
        let hidden = call(&router, Method::GET, "/r/docs/v1/repo/tree", &mia, None).await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND);
        assert_eq!(
            hidden,
            call(&router, Method::GET, "/r/nope/v1/repo/tree", &mia, None).await
        );
        let refs = |name: &str| format!("/git/{name}.git/info/refs?service=git-upload-pack");
        let hidden = call(&router, Method::GET, &refs("docs"), &[], None).await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND);
        assert_eq!(
            hidden,
            call(&router, Method::GET, &refs("nope"), &[], None).await
        );

        // The gate, CSRF check, owner fence and body limit hold under the prefix.
        let (status, _) = call(&router, Method::GET, "/r/docs/v1/repo/tree", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = call(&router, Method::GET, "/r/nope/v1/repo/tree", &owner, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(js(&body)["error"].is_string());
        let (status, _) = call(&router, Method::GET, "/r/nope/v1/repo/tree", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Settings are the server's, whichever repository is asked.
        let days = json!({ "audit_retention_days": 30 });
        let (status, _) = call(
            &router,
            Method::PATCH,
            "/r/docs/v1/settings",
            &owner,
            Some(days),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = call(&router, Method::GET, "/v1/settings", &owner, None).await;
        assert_eq!(js(&body)["audit_retention_days"], 30);
        assert!(!docs.join(".premier/state.json").exists());
        let policy = json!({ "toml": directory::DEFAULT_POLICY_TOML });
        let (status, _) = call(
            &router,
            Method::PUT,
            "/r/docs/v1/policy/repo",
            &mia,
            Some(policy.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND); // she cannot see `docs` at all
        let (status, _) = call(
            &router,
            Method::PUT,
            "/r/docs/v1/policy/repo",
            &evil,
            Some(policy),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let huge = json!({ "toml": "x".repeat(ops::JSON_BODY_LIMIT + 1) });
        let (status, _) = call(
            &router,
            Method::PUT,
            "/r/docs/v1/policy/repo",
            &owner,
            Some(huge),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, body) =
            call(&router, Method::GET, "/r/docs/v1/auth/status", &owner, None).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        // Git aliases reach the named repository.
        let (status, _) = call(&router, Method::GET, &refs("docs"), &bearer, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &router,
            Method::GET,
            "/git/auth/docs.git/info/refs?service=git-upload-pack",
            &[],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = call(
            &router,
            Method::GET,
            "/git/auth/docs.git/info/refs?service=git-receive-pack",
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&body).contains("refs/heads/main"));
        // Audited under the path the client used, not the one dispatch handed the repository.
        let mut ls_refs = premier_git_bridge::http_v2::encode_pkt_line(b"command=ls-refs\n");
        ls_refs.extend_from_slice(b"00010000");
        let req = Request::builder()
            .method(Method::POST)
            .uri("/git/auth/docs.git/git-upload-pack")
            .header("host", "localhost")
            .header(bearer[0].0, bearer[0].1)
            .header("git-protocol", "version=2")
            .body(Body::from(ls_refs))
            .unwrap();
        let resp = router.clone().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let audit = std::fs::read_to_string(crate::store::audit_path(&docs)).unwrap();
        assert!(
            audit.contains("\"/git/auth/docs.git/git-upload-pack\""),
            "{audit}"
        );
        assert!(!audit.contains("/git/repo.git/"), "{audit}");

        // A rule in that repository's own policy is what lets the member see it.
        let grant = format!(
            "{}\n[[rules]]\nid = \"mia-reads\"\neffect = \"allow\"\nprincipals = [\"@mia\"]\npaths = [\"**\"]\nrefs = [\"*\"]\ncapabilities = [\"traverse\", \"list\", \"read\"]\nreason = \"docs reader\"\n",
            directory::DEFAULT_POLICY_TOML
        );
        let file = parse_policy_toml(&grant).unwrap();
        let entry = reg.entry("docs").unwrap();
        entry.state.replace_repo_policy(
            Arc::new(CompiledPolicy::compile(None, &file).unwrap()),
            Arc::new(file),
            grant,
        );
        let (_, body) = call(&router, Method::GET, "/v1/repos", &mia, None).await;
        assert_eq!(names(&body), ["docs"]);
        let (status, body) = call(&router, Method::GET, "/r/docs/v1/repo/tree", &mia, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(paths(&body), ["GUIDE.md"]);
        // ...unless the only branch is hidden from them.
        entry
            .state
            .persisted
            .lock()
            .unwrap()
            .branch_metadata
            .insert(
                "main".to_owned(),
                (
                    premier_core::Visibility::Restricted(vec!["@owner".to_owned()]),
                    premier_core::Readiness::Ready,
                ),
            );
        let (_, body) = call(&router, Method::GET, "/v1/repos", &mia, None).await;
        assert!(names(&body).is_empty());

        // Per-repository state stays in the repository; accounts stay in the default workspace.
        assert!(!docs.join(".premier/premier.db").exists());
        assert!(tmp.path().join(".premier/premier.db").exists());
        assert!(tmp.path().join(".premier/repos.json").exists());

        // The default repository's backup does not sweep up the others.
        let backup = ops::build_backup(tmp.path(), None, &[]).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&backup[..]));
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(
            entries.contains(&".premier/premier.db".to_owned()),
            "{entries:?}"
        );
        assert!(
            !entries
                .iter()
                .any(|p| p.contains("repos/") || p.contains("GUIDE")),
            "{entries:?}"
        );

        // A restart finds the repository again.
        let again = Registry::open(reg.0.default.clone(), Some("home".to_owned()), None);
        assert!(again.entry("docs").is_some());

        let patch = json!({ "description": "Handbook" });
        let (status, _) = call(
            &router,
            Method::PATCH,
            "/v1/repos/docs",
            &mia,
            Some(patch.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &router,
            Method::PATCH,
            "/v1/repos/nope",
            &owner,
            Some(patch.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, body) = call(
            &router,
            Method::PATCH,
            "/v1/repos/docs",
            &owner,
            Some(patch),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(js(&body)["description"], "Handbook");
        assert!(js(&body)["created_at"].is_string());

        let confirm = |name: &str| Some(json!({ "confirm": name }));
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/docs",
            &mia,
            confirm("docs"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/docs",
            &owner,
            confirm("home"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/home",
            &owner,
            confirm("home"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/nope",
            &owner,
            confirm("nope"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Delete stops what runs for the repository: its background jobs and a live session.
        let doomed = reg.entry("docs").unwrap().state;
        let jobs: Vec<_> = doomed.jobs.lock().unwrap().clone();
        assert_eq!(jobs.len(), 3);
        let sleep = if cfg!(windows) {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };
        let spawn = Some(json!({ "command": sleep }));
        let (status, body) = call(
            &router,
            Method::POST,
            "/r/docs/v1/agents/sessions",
            &owner,
            spawn,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(doomed.session_manager.list()[0].status, "running");
        let (status, body) = call(
            &router,
            Method::DELETE,
            "/v1/repos/docs",
            &owner,
            confirm("docs"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!docs.exists());
        assert_eq!(doomed.session_manager.list()[0].status, "interrupted");
        tokio::task::yield_now().await;
        assert!(jobs.iter().all(tokio::task::AbortHandle::is_finished));
        assert!(doomed.jobs.lock().unwrap().is_empty());
        let (status, _) = call(&router, Method::GET, "/r/docs/v1/repo/tree", &owner, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(names(&body), ["home"]);

        // Every write left a security event.
        let (_, body) = call(&router, Method::GET, "/v1/auth/events", &owner, None).await;
        let events = String::from_utf8_lossy(&body).into_owned();
        for kind in ["repo_created", "repo_updated", "repo_deleted"] {
            assert!(events.contains(kind), "{kind}: {events}");
        }
    }

    #[tokio::test]
    async fn a_state_directory_takes_legacy_state_once_and_keeps_every_tree_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("home");
        std::fs::create_dir(&root).unwrap();
        let state_dir = tmp.path().join("state");

        // What an earlier server left in the working tree.
        {
            let (reg, owner, _, _) = registry(&root);
            let router = reg.router();
            let owner = [("cookie", owner.as_str())];
            let new = json!({ "name": "docs" });
            let (status, _) = call(&router, Method::POST, "/v1/repos", &owner, Some(new)).await;
            assert_eq!(status, StatusCode::OK);
            crate::store::save_state(&root, &PersistedState::default()).unwrap();
            std::fs::create_dir_all(root.join(".premier-local")).unwrap();
            std::fs::write(root.join(".premier-local/audit.jsonl"), "").unwrap();
        }
        assert!(root.join(".premier/premier.db").is_file());
        let accounts = crate::auth::AuthStore::open(&root).accounts().unwrap();
        assert!(root.join(".premier/repos/docs/.git").exists());

        // First start with a state directory: moved, all of it, and the tree is clean.
        configure_state_dir(&root, &state_dir, Some("home"), true).unwrap();
        assert!(state_dir.join("account/premier.db").is_file());
        assert_eq!(
            crate::auth::AuthStore::open(&root).accounts().unwrap(),
            accounts
        );
        assert!(state_dir.join("account/repos.json").is_file());
        // Keyed by the repository's id, not its name.
        let home = crate::store::state_dir(&root);
        assert!(
            home.starts_with(state_dir.join("repos")) && !state_dir.join("repos/home").exists()
        );
        assert!(home.join("premier.db").is_file());
        assert!(home.join("audit.jsonl").is_file());
        assert!(state_dir.join("worktrees/docs/.git").exists());
        assert!(!root.join(".premier").exists() && !root.join(".premier-local").exists());
        assert_eq!(crate::store::audit_path(&root), home.join("audit.jsonl"));

        // Never a merge: state that turns up in the tree later (a pushed `.premier/auth.json`
        // that got checked out) is not taken.
        std::fs::create_dir(root.join(".premier")).unwrap();
        std::fs::write(root.join(".premier/auth.json"), "{}").unwrap();
        configure_state_dir(&root, &state_dir, Some("home"), true).unwrap();
        assert_eq!(
            crate::auth::AuthStore::open(&root).accounts().unwrap(),
            accounts
        );
        std::fs::remove_dir_all(root.join(".premier")).unwrap();

        // The server on top of it: every repository's state is outside its tree.
        let (reg, owner, _, _) = registry(&root);
        let router = reg.router();
        let owner = [("cookie", owner.as_str())];
        let (_, body) = call(&router, Method::GET, "/v1/repos", &owner, None).await;
        assert_eq!(names(&body), ["home", "docs"]);
        let new = json!({ "name": "wiki" });
        let (status, _) = call(&router, Method::POST, "/v1/repos", &owner, Some(new)).await;
        assert_eq!(status, StatusCode::OK);
        let secret = json!({ "key": "K", "value": "v" });
        let (status, _) = call(
            &router,
            Method::POST,
            "/r/wiki/v1/secrets/set",
            &owner,
            Some(secret),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let wiki = state_dir.join("worktrees/wiki");
        let wiki_state = crate::store::state_dir(&wiki);
        assert!(wiki.join(".git").exists() && wiki_state.join("vault.toml").is_file());
        for tree in [&root, &wiki, &state_dir.join("worktrees/docs")] {
            assert!(
                !tree.join(".premier").exists() && !tree.join(".premier-local").exists(),
                "{tree:?}"
            );
        }

        // A backup keeps the entry names it always had, and restores into a state directory.
        let (status, body) = call(&router, Method::GET, "/v1/backup", &owner, None).await;
        assert_eq!(status, StatusCode::OK);
        let mut entries = Vec::new();
        for entry in tar::Archive::new(flate2::read::GzDecoder::new(&body[..]))
            .entries()
            .unwrap()
        {
            entries.push(
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
        for name in [".premier/premier.db", ".premier/repos.json", "repo.bundle"] {
            assert!(entries.contains(&name.to_owned()), "{name}: {entries:?}");
        }
        assert!(
            !entries.iter().any(|e| e.contains("session-workspaces")),
            "{entries:?}"
        );
        let archive = tmp.path().join("backup.tar.gz");
        std::fs::write(&archive, &body).unwrap();
        let (dest, dest_state) = (
            tmp.path().join("restored"),
            tmp.path().join("restored-state"),
        );
        std::fs::create_dir(&dest).unwrap();
        crate::store::bind_state_dir(&dest, &dest_state, "restored", true);
        let done = ops::restore_archive(&archive, &dest, false).unwrap();
        assert!(done.repo_cloned);
        assert!(dest_state.join("account/premier.db").is_file());
        assert!(dest_state.join("repos/restored/premier.db").is_file());
        assert!(dest.join("README.md").is_file() && !dest.join(".premier").exists());
        let again = ops::restore_archive(&archive, &dest, false).unwrap_err();
        assert!(again.contains("--force"), "{again}");

        // Deleting a repository takes its state with it.
        let confirm = json!({ "confirm": "wiki" });
        let (status, _) = call(
            &router,
            Method::DELETE,
            "/v1/repos/wiki",
            &owner,
            Some(confirm),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!wiki.exists() && !wiki_state.exists());
        for bound in [&root, &dest, &state_dir.join("worktrees/docs")] {
            crate::store::unbind_state_dir(bound);
        }
    }
}
