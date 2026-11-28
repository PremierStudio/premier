//! Live Agent Cage session runner wired directly into `premier-proxy`'s real `CapabilityProxy`,
//! `ApprovalHub`, `AuditSink`, and streaming `SecretRedactor`.
//!
//! A session never runs in the canonical repository. It gets a private workspace holding only
//! the files its identity (`human ∩ agent profile`) may read on its branch, a sandbox with no
//! network but a relay to its own egress proxy, and ONLY `premier_cap_v1_*` placeholders in
//! `process.env`. What it changed comes back as a change set the owner may commit.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use premier_core::{
    AuditDecision, AuditEvent, Capability, DelegatedIdentity, Environment, RepoPath, Visibility,
};
use premier_git_bridge::{
    CanonicalGitRepo, CommitObj, GitBridgeError, GitObjectKind, InMemoryOdb, LANE_REF_PREFIX,
    LaneConflict, LaneFileChange, git_command, hash_git_object, parse_tree, project_repository,
};
use premier_overlay::OverlayGuard;
use premier_policy::{AutonomyBudget, BudgetAction, CompiledPolicy};
use premier_proxy::cage::{CAGE_EXE, CAGE_PROXY_DIR, PROXY_SOCKET};
#[cfg(windows)]
use premier_proxy::sandbox::{WindowsJobGuard, WindowsJobLimits};
use premier_proxy::{
    ApprovalHub, AuditSink, BudgetAlert, BudgetResumeOutcome, BudgetSnapshot, BudgetTracker,
    CgroupGuard, HubGate, PauseOutcome, ProxyConfig, ResourceLimits, apply_rlimits,
    build_agent_env, cage_exec_argv_with_limits, configure_process_group, create_cgroup_v2,
    pause_session_tree, resume_session_tree, start_proxy,
};
use premier_secrets::{
    EnvSchema, PlaceholderRegistry, ResolveContext, SecretRedactor, SecretResolver, Sensitivity,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::io::AsyncReadExt as _;
use tokio::sync::broadcast;
use zeroize::Zeroizing;

use crate::store::{
    AgentLane, CapturedProvenance, PersistedState, ProvenanceStep, StoredRoundMeta, load_json,
    resolve_vault_backend, save_json,
};
use crate::telemetry::{SessionTelemetryTracker, TelemetryConfig, WorkspaceUsage};
use crate::{ApiError, ReviewEvent, ServerState, canon, err_resp};

pub use crate::telemetry::{
    InsightSeverity, SessionCheckpoint, SessionInsight, SessionInsightKind,
};

const SESSIONS_FILE: &str = "sessions.json";
/// Why a session is refused on a host without a working sandbox.
pub const NO_SANDBOX: &str = "agent sessions need a sandbox and this host has none that works (bubblewrap on Linux); start the server with --allow-unsandboxed-agents to run them as a plain process of the server user";
/// What a container needs for bubblewrap to work in it.
pub const DOCKER_HINT: &str = "run the container with --security-opt seccomp=unconfined --security-opt systempaths=unconfined";

/// How an agent session's process is confined on this host (AGENTS.md invariant 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Linux bubblewrap: see [`cage_args`].
    Bwrap,
    /// No working sandbox, and the operator accepted that (`--allow-unsandboxed-agents`): a
    /// plain process of the server user with a scrubbed environment, in a private workspace.
    UnsandboxedAllowed,
    /// No working sandbox: sessions are refused.
    None,
}

impl SandboxMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::UnsandboxedAllowed => "unsandboxed-allowed",
            Self::None => "none",
        }
    }
}

/// Who the agent is inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CageUser {
    /// Its own user namespace, uid/gid 1000.
    Unprivileged,
    /// The host forbids user namespaces: the server's user (root) with every capability dropped.
    RootNoCaps,
}

/// Fixed paths inside the sandbox, all under its private `/tmp`.
// shortcut: not `/workspace`: bwrap cannot create a mount point on the read-only root, so a new
// top-level directory would have to exist on the host. Move it when the image ships one.
pub const CAGE_WORKSPACE: &str = "/tmp/workspace";
const CAGE_HOME: &str = "/tmp/home";
/// Where the relay listens inside the sandbox's own network namespace.
const CAGE_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3128);

/// Everything that decides a session's bubblewrap arguments.
pub struct CagePlan<'a> {
    /// The session's private workspace on the host: the only writable host directory.
    pub workspace: &'a Path,
    /// The directory holding the session proxy's Unix socket.
    pub proxy_dir: &'a Path,
    /// The `premier` binary, run inside as the relay.
    pub exe: &'a Path,
    /// Host directories the agent must not see at all, from [`hidden_dirs`]. Only one that lies
    /// under a directory of [`CAGE_HOST_DIRS`] needs emptying: nothing else of the host is in
    /// the sandbox in the first place.
    pub hidden: &'a [PathBuf],
    pub user: CageUser,
}

/// The bubblewrap arguments of a session, up to and excluding `--` and the command. One function
/// for the startup probe and for real sessions, so the probe cannot pass where a session fails.
///
/// The root is an empty filesystem holding an ALLOW-list of the host, read-only
/// ([`CAGE_HOST_DIRS`]: programs, libraries, CA certificates), a generated `/etc/passwd` and
/// `/etc/group`, and nothing else: no `/etc/shadow`, no TLS keys, no server policy file, no
/// state directory, no volume, no `/etc/resolv.conf` (there is no DNS in there). `/tmp` is
/// private and holds the workspace (the only writable host directory), a fresh `$HOME`, the
/// proxy socket and the relay binary. Every namespace is private INCLUDING the network (the
/// agent has loopback and nothing else) and the process ids: `/proc` is the sandbox's own, so
/// `/proc/1` is bubblewrap, not the server.
///
/// Why an allow-list: inside the user namespace uid 1000 IS the server's uid, so every file the
/// server can read would be readable through a read-only bind of `/`, and could leave through
/// an allowed egress host.
pub fn cage_args(plan: &CagePlan<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["--unshare-all".into()];
    let mut push = |items: &[&std::ffi::OsStr]| args.extend(items.iter().map(|i| (*i).to_owned()));
    let s = std::ffi::OsStr::new;
    match plan.user {
        CageUser::Unprivileged => {
            push(&[
                s("--unshare-user"),
                s("--uid"),
                s("1000"),
                s("--gid"),
                s("1000"),
            ]);
        }
        CageUser::RootNoCaps => push(&[s("--cap-drop"), s("ALL")]),
    }
    push(&[s("--die-with-parent"), s("--new-session")]);
    for dir in CAGE_HOST_DIRS.map(Path::new) {
        match std::fs::symlink_metadata(dir) {
            // Merged-`/usr` hosts: `/bin -> usr/bin`. The link itself, not a second mount.
            Ok(meta) if meta.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(dir) {
                    push(&[s("--symlink"), target.as_os_str(), dir.as_os_str()]);
                }
            }
            Ok(_) => push(&[s("--ro-bind"), dir.as_os_str(), dir.as_os_str()]),
            Err(_) => {}
        }
    }
    // Minimal generated account files ([`cage_command`] writes them): names for uid 1000 and
    // for `nobody`, never the host's accounts.
    for name in CAGE_ETC {
        let host = plan.proxy_dir.join(name);
        push(&[s("--ro-bind"), host.as_os_str(), s(&format!("/etc/{name}"))]);
    }
    push(&[
        s("--dev"),
        s("/dev"),
        s("--proc"),
        s("/proc"),
        s("--tmpfs"),
        s("/tmp"),
    ]);
    for dir in plan.hidden {
        if CAGE_HOST_DIRS.iter().any(|bound| dir.starts_with(bound)) {
            push(&[s("--tmpfs"), dir.as_os_str()]);
        }
    }
    push(&[s("--dir"), s(CAGE_HOME)]);
    push(&[s("--bind"), plan.workspace.as_os_str(), s(CAGE_WORKSPACE)]);
    push(&[
        s("--ro-bind"),
        plan.proxy_dir.as_os_str(),
        s(CAGE_PROXY_DIR),
    ]);
    push(&[s("--ro-bind"), plan.exe.as_os_str(), s(CAGE_EXE)]);
    // The root itself (an empty tmpfs) is not a scratch disk either.
    push(&[s("--remount-ro"), s("/")]);
    push(&[s("--chdir"), s(CAGE_WORKSPACE)]);
    args
}

/// ALL of the host a caged agent sees (read-only; those that exist): programs and libraries, CA
/// certificates (never `/etc/ssl/private`), and the `alternatives` links programs in `/usr/bin`
/// resolve through.
const CAGE_HOST_DIRS: [&str; 9] = [
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc/ssl/certs",
    "/etc/ssl/openssl.cnf",
    "/etc/ca-certificates",
    "/etc/alternatives",
];

/// Generated files bound over `/etc/<name>`.
const CAGE_ETC: [&str; 2] = ["passwd", "group"];

/// What a sandbox empties on top of mounting next to nothing: `extra` and the server user's
/// home, for the case that one lies under a directory of [`CAGE_HOST_DIRS`]. Real directories
/// only (a link is not a mount point), outermost only (mounting below an emptied directory would
/// put its name back).
// shortcut: `$HOME`, not the passwd entry; read that too if the server may run with HOME unset.
pub(crate) fn hidden_dirs(extra: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = extra
        .into_iter()
        .chain(std::env::var_os("HOME").map(PathBuf::from))
        .filter_map(|p| p.canonicalize().ok())
        // Never `/` (the home of some service users): that would empty the whole sandbox.
        .filter(|p| p.is_dir() && p.parent().is_some())
        .collect();
    dirs.sort();
    let mut kept: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        if !kept.iter().any(|k| dir.starts_with(k)) {
            kept.push(dir);
        }
    }
    kept
}

/// `bwrap <cage_args> -- premier __cage-exec … -- <argv>`.
fn cage_command(plan: &CagePlan<'_>, argv: &[&str]) -> std::process::Command {
    cage_command_with_limits(plan, argv, &ResourceLimits::default())
}

/// [`cage_command`] whose relay caps the agent with `setrlimit` / cgroup v2 `limits`.
fn cage_command_with_limits(
    plan: &CagePlan<'_>,
    argv: &[&str],
    limits: &ResourceLimits,
) -> std::process::Command {
    // Written here, by the one builder the probe and every session share. A failure shows up as
    // bubblewrap refusing to start (the bind source is missing), never as a weaker sandbox.
    let _ = std::fs::write(
        plan.proxy_dir.join(CAGE_ETC[0]),
        "agent:x:1000:1000:agent:/tmp/home:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n",
    );
    let _ = std::fs::write(
        plan.proxy_dir.join(CAGE_ETC[1]),
        "agent:x:1000:\nnogroup:x:65534:\n",
    );
    let mut c = std::process::Command::new("bwrap");
    c.args(cage_args(plan))
        .arg("--")
        .args(cage_exec_argv_with_limits(CAGE_LISTEN, limits))
        .args(argv);
    c
}

static CAGE_EXE_HOST: OnceLock<PathBuf> = OnceLock::new();

/// Use `exe` as the `premier` binary bound into sandboxes (default: the running executable).
/// Only effective before the first session or probe; for hosts embedding the server.
pub fn set_cage_exe(exe: PathBuf) {
    let _ = CAGE_EXE_HOST.set(exe);
}

fn cage_exe() -> &'static Path {
    CAGE_EXE_HOST
        .get_or_init(|| std::env::current_exe().unwrap_or_else(|_| PathBuf::from("premier")))
}

/// What the startup probe found: who a caged agent runs as (`None`: no sandbox) and why.
struct Probe {
    user: Option<CageUser>,
    detail: String,
}

/// Turn bubblewrap's complaint into something an operator can act on.
fn explain_bwrap_failure(stderr: &str) -> String {
    let last = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("bwrap failed");
    let last: String = last.chars().take(300).collect();
    let lower = last.to_ascii_lowercase();
    let container = ["/proc", "namespace", "not permitted", "permission denied"];
    if container.iter().any(|n| lower.contains(n)) {
        format!("{last}: {DOCKER_HINT}")
    } else {
        last
    }
}

/// bubblewrap is probed once per process by running the relay and `true` under exactly the
/// arguments a session gets: installed is not enough (containers and hardened kernels often
/// forbid user namespaces or a fresh `/proc`).
fn probe() -> &'static Probe {
    static PROBE: OnceLock<Probe> = OnceLock::new();
    PROBE.get_or_init(|| {
        if !cfg!(target_os = "linux") {
            return Probe { user: None, detail: "the bubblewrap sandbox needs Linux".to_owned() };
        }
        let dir = std::env::temp_dir().join(format!("premier-probe-{}", std::process::id()));
        let (workspace, proxy_dir, hidden) = (dir.join("ws"), dir.join("proxy"), dir.join("hidden"));
        for d in [&workspace, &proxy_dir, &hidden] {
            let _ = std::fs::create_dir_all(d);
        }
        // The same mounts a session gets, the emptied home and host state included.
        let hidden = hidden_dirs([hidden]);
        let mut found = Probe { user: None, detail: String::new() };
        for user in [CageUser::Unprivileged, CageUser::RootNoCaps] {
            let plan = CagePlan {
                workspace: &workspace,
                proxy_dir: &proxy_dir,
                exe: cage_exe(),
                hidden: &hidden,
                user,
            };
            let run =
                cage_command(&plan, &["true"]).stdin(Stdio::null()).stdout(Stdio::null()).output();
            match run {
                Ok(out) if out.status.success() => {
                    found.user = Some(user);
                    found.detail = match user {
                        CageUser::Unprivileged => String::new(),
                        CageUser::RootNoCaps => format!(
                            "no user namespace here ({}): the agent runs as the server's user inside the sandbox, with all capabilities dropped",
                            found.detail
                        ),
                    };
                    break;
                }
                Ok(out) => {
                    found.detail = explain_bwrap_failure(&String::from_utf8_lossy(&out.stderr));
                }
                Err(e) => {
                    found.detail = format!("bwrap could not be run: {e}");
                    break;
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        found
    })
}

/// The uid this process runs as (unix).
#[cfg(unix)]
pub(crate) fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    static UID: OnceLock<Option<u32>> = OnceLock::new();
    *UID.get_or_init(|| {
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .ok()
            .or_else(|| {
                // No `/proc` (not Linux): the owner of a file we create is us.
                let probe =
                    std::env::temp_dir().join(format!("premier-uid-{}", std::process::id()));
                let uid = std::fs::File::create(&probe)
                    .and_then(|f| f.metadata())
                    .map(|m| m.uid())
                    .ok();
                let _ = std::fs::remove_file(&probe);
                uid
            })
    })
}

/// A sandbox that would run the agent as real root (no user namespace, and the server itself is
/// root): capabilities are dropped, but uid 0 still owns the host's files. Not offered.
fn root_fallback() -> bool {
    #[cfg(unix)]
    let root = own_uid() == Some(0);
    #[cfg(not(unix))]
    let root = false;
    root && probe().user == Some(CageUser::RootNoCaps)
}

/// The sandbox this host offers. A server running as root never falls back to a sandbox whose
/// agent is uid 0: that is a hard refusal unless the operator passed
/// `--allow-unsandboxed-agents`.
pub fn sandbox_mode(allow_unsandboxed: bool) -> SandboxMode {
    let usable = probe().user.is_some() && (allow_unsandboxed || !root_fallback());
    match (usable, allow_unsandboxed) {
        (true, _) => SandboxMode::Bwrap,
        (false, true) => SandboxMode::UnsandboxedAllowed,
        (false, false) => SandboxMode::None,
    }
}

/// Why [`sandbox_mode`] is not `bwrap`, or what is weaker than usual about it (empty: nothing).
pub fn sandbox_detail(allow_unsandboxed: bool) -> String {
    let detail = &probe().detail;
    if root_fallback() && !allow_unsandboxed {
        return format!(
            "{detail}; refused, because the server runs as root and the agent would too: run the server as a non-root user, or pass --allow-unsandboxed-agents"
        );
    }
    match sandbox_mode(allow_unsandboxed) {
        SandboxMode::UnsandboxedAllowed => {
            let job = if cfg!(windows) {
                "; a Windows Job Object bounds each session's processes, memory and lifetime                  (kill-on-close), but filesystem and network isolation needs Linux bwrap"
            } else {
                ""
            };
            format!("{detail}; sessions run unconfined (--allow-unsandboxed-agents){job}")
        }
        _ => detail.clone(),
    }
}

/// How to confine one session: the mode, and directories the agent must not see at all (the
/// account root and the other repositories; the canonical repository is always hidden).
pub struct Cage {
    pub mode: SandboxMode,
    pub hidden: Vec<PathBuf>,
}

/// Host variables an agent process keeps. Everything else the server was started with (cloud
/// credentials, tokens, `PREMIER_*` configuration) stays out of its environment.
const ENV_PASSTHROUGH: &[&str] = if cfg!(windows) {
    &[
        "PATH",
        "LANG",
        "TERM",
        "SystemRoot",
        "SystemDrive",
        "windir",
        "ComSpec",
        "PATHEXT",
    ]
} else {
    &["PATH", "LANG", "TERM"]
};

/// How long a session runs when the request does not say, and the most a request may ask for.
pub const DEFAULT_SESSION_SECS: u64 = 30 * 60;
pub const MAX_SESSION_SECS: u64 = 4 * 60 * 60;
/// An uncommitted workspace is kept this long after its session ended.
const WORKSPACE_TTL_SECS: i64 = 24 * 60 * 60;

/// The time limit of a session asked to run `max_secs` (at least one second).
pub fn session_limit(max_secs: Option<u64>) -> std::time::Duration {
    std::time::Duration::from_secs(
        max_secs
            .unwrap_or(DEFAULT_SESSION_SECS)
            .clamp(1, MAX_SESSION_SECS),
    )
}

// ---------------------------------------------------------------------------
// The private workspace: what goes in, and what comes back out
// ---------------------------------------------------------------------------

/// Keep session workspaces outside the working tree and at a stable path across restarts.
/// Use the repository's external state directory when configured, otherwise private user state.
pub(crate) fn sessions_root(workspace_root: &Path) -> PathBuf {
    if crate::store::state_root(workspace_root).is_some() {
        return crate::store::state_dir(workspace_root).join(SESSION_WORKSPACES);
    }
    let root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let key = hash_git_object(GitObjectKind::Blob, root.to_string_lossy().as_bytes());
    if let Some(base) = user_session_state() {
        return base.join(&key[..16]);
    }
    static PER_PROCESS: OnceLock<PathBuf> = OnceLock::new();
    let base = PER_PROCESS.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        // Randomly keyed by the standard library: 64 unpredictable bits without a new dependency.
        let nonce = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        std::env::temp_dir().join(format!(
            "premier-sessions-{}-{nonce:016x}",
            std::process::id()
        ))
    });
    base.join(&key[..16])
}

fn user_session_state() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    base.filter(|path| path.is_absolute())
        .map(|path| path.join("prem-sessions"))
}

/// Create `dir` for this user alone (0700 on unix), or accept an existing one only if it is a
/// real directory of ours that nobody else can enter: never a link or a directory someone else
/// put there first.
pub(crate) fn private_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir)?;
            #[cfg(unix)]
            let ours = {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                Some(meta.uid()) == own_uid() && meta.permissions().mode() & 0o077 == 0
            };
            #[cfg(not(unix))]
            let ours = true;
            if meta.is_dir() && ours {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "{} exists and is not a private directory of this user",
                    dir.display()
                )))
            }
        }
        Err(e) => Err(e),
    }
}

/// `<dir>/ws` is the workspace, `<dir>/proxy` holds the proxy socket, `<dir>/base.json` what the
/// workspace started as. `id` must be a known session id, never request text.
pub(crate) fn session_dir(workspace_root: &Path, id: &str) -> PathBuf {
    sessions_root(workspace_root).join(id)
}

/// Remove a session's private workspace directory once its changes have landed or been discarded.
pub(crate) fn cleanup_session_workspace(workspace_root: &Path, id: &str) {
    let _ = std::fs::remove_dir_all(session_dir(workspace_root, id));
}

const BASE_FILE: &str = "base.json";
/// A steered session's packet, in the session's proxy directory.
const STEERING_JSON: &str = "steering.json";
const STEERING_MD: &str = "steering.md";
/// Name of the session workspaces directory inside a repository's state directory.
pub(crate) const SESSION_WORKSPACES: &str = "session-workspaces";

fn git_quiet(dir: &Path, args: &[&str]) -> Result<(), String> {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let hooks_cfg = format!("core.hooksPath={null}");
    let out = git_command(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .args([
            "-c",
            "user.name=Premier",
            "-c",
            "user.email=premier@localhost",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "init.templateDir=",
            "-c",
            &hooks_cfg,
        ])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git {}: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// What a workspace started as: `path -> (git mode, blob oid)` of every file and symbolic link
/// written into it.
pub(crate) type Base = BTreeMap<String, (String, String)>;

const MODE_FILE: &str = "100644";
const MODE_EXEC: &str = "100755";
const MODE_LINK: &str = "120000";

/// Whether symbolic link `rel -> target` can only lead to a path inside the workspace: a
/// relative target that never climbs above the root and names no `.git`. `..` is accepted only
/// in front: after a name it would be resolved from wherever a link behind that name leads, and
/// two links that each look contained could then leave together.
fn link_stays_inside(rel: &str, target: &str) -> bool {
    let depth = rel.matches('/').count();
    let (mut ups, mut named) = (0usize, false);
    !target.is_empty()
        && target.split('/').all(|part| match part {
            // Absolute, or an empty segment.
            "" => false,
            "." => true,
            ".." => {
                ups += 1;
                !named && ups <= depth
            }
            name => {
                named = true;
                !name.eq_ignore_ascii_case(".git")
            }
        })
}

#[cfg(unix)]
fn make_link(target: &str, at: &Path) -> bool {
    std::os::unix::fs::symlink(target, at).is_ok()
}

// shortcut: no symbolic links on other hosts (Windows needs a privilege for them): they are
// reported as skipped and stay as they are on commit.
#[cfg(not(unix))]
fn make_link(_: &str, _: &Path) -> bool {
    false
}

/// What the instruction quarantine did to one instruction file of an agent's workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineWorkspaceAction {
    /// The branch's bytes were replaced by the owner-approved version.
    Substituted {
        path: String,
        from_sha: String,
        to_sha: String,
    },
    /// The file was left out of the workspace: no trusted version of it exists.
    Stripped { path: String, sha: String },
}

/// The instruction quarantine of an agent workspace ([`materialise_with_quarantine`]).
struct WorkspaceQuarantine<'a> {
    policy: &'a CompiledPolicy,
    approvals: &'a BTreeMap<String, crate::store::ApprovedInstructionFile>,
    hosts: Vec<String>,
    actions: Vec<QuarantineWorkspaceAction>,
}

enum Admit {
    Keep,
    Substitute(Vec<u8>),
    Strip,
}

impl WorkspaceQuarantine<'_> {
    /// An instruction file is handed to an agent as-is only when it matches its owner pin and
    /// scans clean, or is exactly an owner-approved version (and no pin contradicts that).
    /// Otherwise the approved version replaces it, or it is left out.
    fn admit(&mut self, rel: &str, data: &[u8]) -> Admit {
        let Ok(rp) = RepoPath::new(rel) else {
            return Admit::Keep;
        };
        if !self.policy.is_instruction_file(&rp) {
            return Admit::Keep;
        }
        let actual = premier_policy::sha256_hex(data);
        let pinned = self.policy.pinned_instruction_hash(&rp);
        let pin_ok = |sha: &str| pinned.is_none_or(|p| p.eq_ignore_ascii_case(sha));
        let approved = self.approvals.get(rel);
        let approved_matches = approved.is_some_and(|a| a.sha256.eq_ignore_ascii_case(&actual));
        let scan = premier_policy::scan_instruction_file(rel, data, &self.hosts, pinned);
        if (pinned.is_some() && pin_ok(&actual) && scan.passed)
            || (approved_matches && pin_ok(&actual))
        {
            return Admit::Keep;
        }
        let safe = approved.and_then(|a| {
            let text = a.approved_content.as_ref()?;
            let sha = premier_policy::sha256_hex(text.as_bytes());
            (sha.eq_ignore_ascii_case(&a.sha256) && pin_ok(&sha)).then(|| (text.clone(), sha))
        });
        match safe {
            Some((text, to_sha)) => {
                self.actions.push(QuarantineWorkspaceAction::Substituted {
                    path: rel.to_owned(),
                    from_sha: actual,
                    to_sha,
                });
                Admit::Substitute(text.into_bytes())
            }
            None => {
                self.actions.push(QuarantineWorkspaceAction::Stripped {
                    path: rel.to_owned(),
                    sha: actual,
                });
                Admit::Strip
            }
        }
    }
}

/// Write the files of projected tree `tree_oid` under `dir`, noting each in `base` and each
/// symbolic link (`path`, blob oid) in `links`: those are made by [`materialise`] once every
/// file is written, so no file is ever written through one.
// shortcut: submodules are not materialised (nor diffed back).
fn write_tree(
    odb: &InMemoryOdb,
    tree_oid: &str,
    dir: &Path,
    prefix: &str,
    base: &mut Base,
    links: &mut Vec<(String, String)>,
    mut quarantine: Option<&mut WorkspaceQuarantine<'_>>,
) -> Result<(), String> {
    let tree = odb.get(tree_oid).ok_or("projected tree is missing")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("workspace: {e}"))?;
    for entry in parse_tree(&tree.data).map_err(|e| e.to_string())? {
        let rel = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        // Nothing that is not a plain portable name leaves the directory, and no `.git`.
        if RepoPath::new(&rel).is_err() || entry.name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let target = dir.join(&entry.name);
        if entry.is_dir() {
            write_tree(
                odb,
                &entry.oid_hex,
                &target,
                &rel,
                base,
                links,
                quarantine.as_deref_mut(),
            )?;
        } else if entry.mode == MODE_LINK {
            links.push((rel, entry.oid_hex));
        } else if entry.mode.starts_with("100")
            && let Some(blob) = odb.get(&entry.oid_hex)
        {
            let admitted = quarantine
                .as_deref_mut()
                .map_or(Admit::Keep, |q| q.admit(&rel, &blob.data));
            let (data, oid) = match admitted {
                Admit::Keep => (blob.data.to_vec(), entry.oid_hex),
                Admit::Substitute(safe) => {
                    let oid = hash_git_object(GitObjectKind::Blob, &safe);
                    (safe, oid)
                }
                // Not written and not in `base`: a commit leaves the branch's file alone.
                Admit::Strip => continue,
            };
            std::fs::write(&target, &data).map_err(|e| format!("workspace file {rel}: {e}"))?;
            let mode = if entry.mode == MODE_EXEC {
                MODE_EXEC
            } else {
                MODE_FILE
            };
            #[cfg(unix)]
            if mode == MODE_EXEC {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
            }
            base.insert(rel, (mode.to_owned(), oid));
        }
    }
    Ok(())
}

/// Materialise in `workspace` what `identity` may READ at the tip of `full_ref`, as a small
/// standalone git repository with one commit (so `git status` and `git diff` work, without any
/// history). Nothing comes from the canonical `.git`: files are written from the identity's
/// projection, so a path it cannot read is not there in any form. `full_ref: None` (no commit
/// yet) and an identity that can read nothing both give an empty workspace.
///
/// Files keep their executable bit. A symbolic link is made only where the host can and its
/// target stays inside the workspace ([`link_stays_inside`]); the others are left out.
///
/// With `base_commit_override`, the workspace is that canonical commit instead (a lane or review
/// round), projected by the same rules for `branch`. The caller must already know `identity` may
/// see that commit: only its readable files are written, never its history.
///
/// Returns the canonical tip the workspace was taken from, what was written ([`Base`]) and the
/// paths of the symbolic links that were not.
// Kept for callers that need no quarantine (the unit tests).
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn materialise(
    canonical_root: &Path,
    full_ref: Option<&str>,
    branch: &str,
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
    workspace: &Path,
    base_commit_override: Option<&str>,
) -> Result<(Option<String>, Base, Vec<String>), String> {
    materialise_full(
        canonical_root,
        full_ref,
        branch,
        policy,
        identity,
        ref_visibility,
        workspace,
        base_commit_override,
        &BTreeMap::new(),
    )
    .map(|(tip, base, skipped, _)| (tip, base, skipped))
}

/// [`materialise`] with the Active Instruction Quarantine: for an agent identity under a
/// policy that enforces it, an instruction file that is neither pinned-and-clean nor
/// owner-approved is replaced by its approved version (`approvals`) or left out. Also returns
/// what it did to each such file.
#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(crate) fn materialise_with_quarantine(
    canonical_root: &Path,
    full_ref: Option<&str>,
    branch: &str,
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
    workspace: &Path,
    approvals: &BTreeMap<String, crate::store::ApprovedInstructionFile>,
) -> Result<
    (
        Option<String>,
        Base,
        Vec<String>,
        Vec<QuarantineWorkspaceAction>,
    ),
    String,
> {
    materialise_full(
        canonical_root,
        full_ref,
        branch,
        policy,
        identity,
        ref_visibility,
        workspace,
        None,
        approvals,
    )
}

/// [`materialise_with_quarantine`] that can start from `base_commit_override` (a lane or review
/// round) instead of the tip of `full_ref`; see [`materialise`].
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(crate) fn materialise_full(
    canonical_root: &Path,
    full_ref: Option<&str>,
    branch: &str,
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
    workspace: &Path,
    base_commit_override: Option<&str>,
    approvals: &BTreeMap<String, crate::store::ApprovedInstructionFile>,
) -> Result<
    (
        Option<String>,
        Base,
        Vec<String>,
        Vec<QuarantineWorkspaceAction>,
    ),
    String,
> {
    let mut quarantine = policy
        .filter(|p| identity.agent_task.is_some() && p.quarantine_enforced())
        .map(|policy| WorkspaceQuarantine {
            policy,
            approvals,
            hosts: policy.all_allowed_egress_hosts(),
            actions: Vec::new(),
        });
    std::fs::create_dir_all(workspace).map_err(|e| format!("workspace: {e}"))?;
    let mut base = Base::new();
    let mut skipped = Vec::new();
    let mut tip = None;
    if let Some(commit_oid) = base_commit_override {
        // Fail closed: without a policy nothing can be shown to be readable.
        let policy = policy.ok_or("no policy is loaded")?;
        if !matches!(commit_oid.len(), 40 | 64)
            || !commit_oid.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid base commit".to_owned());
        }
        let canonical = CanonicalGitRepo::open(canonical_root);
        let projected = premier_git_bridge::project_commit_tree_for_workspace(
            &canonical, policy, identity, branch, commit_oid,
        )
        .map_err(|e| format!("projection failed: {e}"))?;
        if let Some((tree, odb)) = projected {
            write_projected(
                &odb,
                &tree,
                workspace,
                &mut base,
                &mut skipped,
                quarantine.as_mut(),
            )?;
        }
        tip = Some(commit_oid.to_owned());
    } else if let Some(full_ref) = full_ref {
        // Fail closed: without a policy nothing can be shown to be readable.
        let policy = policy.ok_or("no policy is loaded")?;
        let canonical = CanonicalGitRepo::open(canonical_root);
        let view = project_repository(
            &canonical,
            policy,
            "agent-session",
            identity,
            ref_visibility,
        )
        .map_err(|e| format!("projection failed: {e}"))?;
        let advertised = view
            .ref_sources
            .iter()
            .find(|(_, (source, _))| source == full_ref);
        if let Some((advertised, (_, canonical_tip))) = advertised {
            tip = Some(canonical_tip.clone());
            let commit = view.refs.get(advertised).and_then(|oid| view.odb.get(oid));
            let commit = commit.ok_or("projected commit is missing")?;
            let tree = CommitObj::parse(&commit.data)
                .map_err(|e| e.to_string())?
                .tree;
            write_projected(
                &view.odb,
                &tree,
                workspace,
                &mut base,
                &mut skipped,
                quarantine.as_mut(),
            )?;
        } else {
            tip = canon::tip_of(canonical_root, full_ref);
        }
    }
    git_quiet(workspace, &["init", "-q", "-b", branch])
        .or_else(|_| git_quiet(workspace, &["init", "-q"]))?;
    git_quiet(workspace, &["add", "-A"])?;
    git_quiet(
        workspace,
        &["commit", "-q", "--allow-empty", "-m", "Session start"],
    )?;

    // Materialize authorized personal & team overlays into the projected agent workspace AFTER
    // the base Git commit so overlays never enter session history, and record their initial
    // hashes + `.git/info/exclude` entries so untouched overlays do not appear as pending edits.
    let overlay_store =
        crate::overlay_store(canonical_root).map_err(|e| format!("overlay store failed: {e}"))?;
    let materialized = overlay_store
        .materialize_into_dir(
            workspace,
            &identity.principal.canonical_id(),
            &identity.groups,
        )
        .map_err(|e| format!("overlay materialization failed: {e}"))?;
    if !materialized.is_empty() {
        use std::io::Write as _;
        let exclude_path = workspace.join(".git").join("info").join("exclude");
        if let Some(parent) = exclude_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut exclude_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exclude_path)
            .ok();
        for rel in materialized {
            let target = workspace.join(&rel);
            if let Ok(bytes) = std::fs::read(&target) {
                let oid = hash_git_object(GitObjectKind::Blob, &bytes);
                base.insert(rel.clone(), (MODE_FILE.to_owned(), oid));
            }
            if let Some(f) = exclude_file.as_mut() {
                let _ = writeln!(f, "/{rel}");
            }
        }
    }

    let actions = quarantine.map(|q| q.actions).unwrap_or_default();
    Ok((tip, base, skipped, actions))
}

/// Write projected tree `tree` into `workspace`, then the symbolic links that stay inside it
/// (the others go to `skipped`).
fn write_projected(
    odb: &InMemoryOdb,
    tree: &str,
    workspace: &Path,
    base: &mut Base,
    skipped: &mut Vec<String>,
    quarantine: Option<&mut WorkspaceQuarantine<'_>>,
) -> Result<(), String> {
    let mut links = Vec::new();
    write_tree(odb, tree, workspace, "", base, &mut links, quarantine)?;
    for (rel, oid) in links {
        let target = odb
            .get(&oid)
            .and_then(|b| std::str::from_utf8(&b.data).ok());
        let made = target
            .is_some_and(|t| link_stays_inside(&rel, t) && make_link(t, &workspace.join(&rel)));
        if made {
            base.insert(rel, (MODE_LINK.to_owned(), oid));
        } else {
            skipped.push(rel);
        }
    }
    Ok(())
}

/// One path a session changed in its workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChange {
    pub path: String,
    /// `added`, `modified` (content, or only the executable bit) or `deleted`.
    pub kind: String,
    /// Size in bytes now (0 when deleted).
    pub size: u64,
    /// Git mode now: `100644`, `100755` or `120000` (a symbolic link); empty when deleted.
    #[serde(default)]
    pub mode: String,
}

/// Most paths in one change set, largest single file, most bytes in all, most files looked at.
const MAX_CHANGES: usize = 2000;
const MAX_CHANGE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CHANGE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Most directory entries (files, directories, links, anything) one walk looks at.
const MAX_WALK_FILES: usize = 100_000;
/// Most not-carried link paths a session record lists; the rest are only counted.
const MAX_SKIPPED: usize = 200;
/// How often a running session's workspace is measured against [`MAX_WORKSPACE_BYTES`].
const SIZE_CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
/// The size budget of a session workspace: the most file bytes the server reads (hashes) to work
/// out one change set (a workspace over it at the end is shown, not committed), and what a
/// running session is killed for exceeding ([`workspace_usage`]).
// shortcut: a repository whose own readable tree is over 1 GiB cannot take session commits;
// keep each file's size in `Base` and skip unchanged-by-size files if such repositories appear.
const MAX_WORKSPACE_BYTES: u64 = 1024 * 1024 * 1024;

/// The git blob oid of a file, without holding it in memory.
fn blob_oid(path: &Path, size: u64) -> std::io::Result<String> {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {size}\0"));
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        hasher.update(&buf[..n]);
    }
    if read != size {
        return Err(std::io::Error::other("file changed while it was read"));
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// A change set: each change with the new content of an added or modified file, sorted by path.
type Changes = Vec<(SessionChange, Option<Vec<u8>>)>;

/// What differs between `workspace` and the `base` it started from. `true` when the set is
/// incomplete (too many or too large changes, names that are not repository paths): such a set
/// is shown, not committed.
///
/// The server walks the files itself and never runs git in a directory an agent wrote to (its
/// `.git/config` could name a program to run). `.git` directories and anything that is neither a
/// regular file nor a symbolic link are ignored. A link is never followed, so it cannot pull a
/// host file into a commit: it is carried as a link (its target text) when that target stays
/// inside the workspace, and otherwise ignored (what the branch has at that path stays).
///
/// The executable bit is the file's own where the host has one; elsewhere (Windows) a file keeps
/// the mode it started with and a new file is `100644`.
///
/// The agent chose what is in there, so the work is bounded BEFORE any byte is read: sizes come
/// from the entry's own metadata (`symlink_metadata`), a new file over the per-file cap is not
/// opened, and all hashing stops at [`MAX_WORKSPACE_BYTES`]. Special files and files with more
/// than one hard link (another name the walk cannot see) are skipped. Each of these marks the
/// set incomplete.
///
/// Third: the symbolic links that are not carried (`skipped`, at most [`MAX_SKIPPED`]), because
/// their target is absolute or leads out of the workspace; fourth: how many more there were.
pub(crate) fn diff_workspace_full(workspace: &Path, base: &Base) -> Left {
    let mut out: Changes = Vec::new();
    let mut truncated = false;
    let (mut skipped, mut more_skipped) = (Vec::new(), 0usize);
    let mut seen = BTreeSet::new();
    let (mut walked, mut bytes, mut hashed) = (0usize, 0u64, 0u64);
    let mut dirs = vec![(workspace.to_path_buf(), String::new())];
    'walk: while let Some((dir, prefix)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            truncated = true;
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            // Every entry counts, whatever it turns out to be: the agent chose how many there are.
            walked += 1;
            if walked > MAX_WALK_FILES {
                truncated = true;
                break 'walk;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                truncated = true;
                continue;
            };
            if name.eq_ignore_ascii_case(".git") {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            // Never followed: the entry's own metadata, read before anything else is.
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                truncated = true;
                continue;
            };
            let kind = meta.file_type();
            if kind.is_dir() {
                dirs.push((entry.path(), rel));
                continue;
            }
            let was = base.get(&rel);
            // A link's content is its target; `Some(None)`: a link that is not carried.
            let link = kind.is_symlink().then(|| {
                let target = std::fs::read_link(entry.path())
                    .ok()?
                    .into_os_string()
                    .into_string()
                    .ok()?;
                (cfg!(unix) && link_stays_inside(&rel, &target)).then(|| target.into_bytes())
            });
            if link == Some(None) {
                if skipped.len() < MAX_SKIPPED {
                    skipped.push(rel.clone());
                } else {
                    more_skipped += 1;
                }
                if was.is_some() {
                    seen.insert(rel);
                }
                continue;
            }
            #[cfg(unix)]
            let aliased = {
                use std::os::unix::fs::MetadataExt;
                kind.is_file() && meta.nlink() > 1
            };
            #[cfg(not(unix))]
            let aliased = false;
            // A device, fifo or socket; a file that is also something else's name; a file too
            // large to be a change and not one the workspace started with.
            let oversize = kind.is_file() && meta.len() > MAX_CHANGE_FILE_BYTES && was.is_none();
            if (!kind.is_file() && link.is_none()) || aliased || oversize {
                truncated = true;
                if was.is_some() {
                    seen.insert(rel);
                }
                continue;
            }
            if RepoPath::new(&rel).is_err() {
                truncated = true;
                continue;
            }
            seen.insert(rel.clone());
            let (size, oid, mode) = match &link {
                Some(Some(target)) => {
                    let oid = hash_git_object(GitObjectKind::Blob, target);
                    (target.len() as u64, Ok(oid), MODE_LINK)
                }
                _ => {
                    let size = meta.len();
                    hashed = hashed.saturating_add(size);
                    if hashed > MAX_WORKSPACE_BYTES {
                        truncated = true;
                        // Over budget: nothing more is read, and (below) nothing is "deleted".
                        walked = MAX_WALK_FILES + 1;
                        break 'walk;
                    }
                    #[cfg(unix)]
                    let exec = {
                        use std::os::unix::fs::PermissionsExt;
                        meta.permissions().mode() & 0o100 != 0
                    };
                    #[cfg(not(unix))]
                    let exec = was.is_some_and(|(mode, _)| mode == MODE_EXEC);
                    (
                        size,
                        blob_oid(&entry.path(), size),
                        if exec { MODE_EXEC } else { MODE_FILE },
                    )
                }
            };
            let Ok(oid) = oid else {
                truncated = true;
                continue;
            };
            if was.is_some_and(|(was_mode, was_oid)| was_mode == mode && *was_oid == oid) {
                continue;
            }
            if out.len() >= MAX_CHANGES {
                truncated = true;
                continue;
            }
            let fits = size <= MAX_CHANGE_FILE_BYTES && bytes + size <= MAX_CHANGE_TOTAL_BYTES;
            let content = match link {
                Some(target) => target,
                None => fits.then(|| std::fs::read(entry.path()).ok()).flatten(),
            };
            match &content {
                Some(data) => bytes += data.len() as u64,
                None => truncated = true,
            }
            let kind = if was.is_some() { "modified" } else { "added" };
            let change = SessionChange {
                path: rel,
                kind: kind.to_owned(),
                size,
                mode: mode.to_owned(),
            };
            out.push((change, content));
        }
    }
    // An unfinished walk cannot tell a deleted file from one it did not reach.
    if walked <= MAX_WALK_FILES {
        for path in base.keys().filter(|p| !seen.contains(*p)) {
            if out.len() >= MAX_CHANGES {
                truncated = true;
                break;
            }
            let change = SessionChange {
                path: path.clone(),
                kind: "deleted".to_owned(),
                size: 0,
                mode: String::new(),
            };
            out.push((change, None));
        }
    }
    out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    skipped.sort();
    (out, truncated, skipped, more_skipped)
}

/// What a session left: [`diff_workspace_full`].
type Left = (Changes, bool, Vec<String>, usize);

/// Whether the files of `workspace` hold more than `budget` bytes (by their own metadata, links
/// never followed), or it has more entries than a walk may look at: what a running session is
/// stopped for. Stops counting as soon as it knows.
#[cfg(test)]
fn workspace_over_budget(workspace: &Path, budget: u64) -> bool {
    workspace_usage(workspace, budget).over_budget
}

/// Measure `workspace` by each entry's own metadata (links never followed, no file opened):
/// file bytes, entries, and an order-independent fingerprint of `(path, size, mtime)` outside
/// `.git` that changes whenever the agent writes something. Stops once over `budget` bytes or
/// [`MAX_WALK_FILES`] entries (`over_budget`).
pub(crate) fn workspace_usage(workspace: &Path, budget: u64) -> WorkspaceUsage {
    use std::hash::{Hash, Hasher};
    let mut usage = WorkspaceUsage::default();
    let mut dirs = vec![(workspace.to_path_buf(), String::new(), false)];
    while let Some((dir, prefix, in_git)) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            usage.entries += 1;
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let name = entry.file_name();
            let in_git = in_git || name.eq_ignore_ascii_case(".git");
            let rel = format!("{prefix}/{}", name.to_string_lossy());
            if !in_git {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos());
                // `DefaultHasher::new()` has fixed keys: the same workspace, the same fingerprint.
                let mut h = std::collections::hash_map::DefaultHasher::new();
                (&rel, meta.len(), mtime).hash(&mut h);
                usage.fingerprint = usage.fingerprint.wrapping_add(h.finish());
            }
            if meta.is_dir() {
                dirs.push((entry.path(), rel, in_git));
            } else if meta.is_file() {
                usage.bytes = usage.bytes.saturating_add(meta.len());
            }
            if usage.bytes > budget || usage.entries > MAX_WALK_FILES {
                usage.over_budget = true;
                return usage;
            }
        }
    }
    usage
}

/// How often a session with a workspace budget (files, lines, bytes) is measured.
const BUDGET_CHECK_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

/// The base text of each modified or deleted path, read once per session (`None`: binary,
/// too large, or unreadable).
type BaseText = HashMap<String, Option<String>>;

/// How a running session ended.
enum End {
    Exited(std::io::Result<std::process::ExitStatus>),
    Stopped,
    /// Paused by its owner to step in: killed, its workspace kept.
    Paused,
    Timeout,
    SizeLimit,
    Budget(String),
}

fn breach_reason(tracker: &BudgetTracker) -> String {
    tracker
        .snapshot()
        .breach_reason
        .unwrap_or_else(|| "autonomy budget exceeded".to_owned())
}

/// Budget usage of session `id`'s workspace, which holds `bytes` (already measured, under the
/// hard ceiling [`MAX_WORKSPACE_BYTES`]): `(files changed, lines changed, bytes held)`.
/// Files and lines are only worked out when `need_diff` (a change set reads every file).
fn budget_usage(
    workspace_root: &Path,
    id: &str,
    base_commit: Option<&str>,
    need_diff: bool,
    base_text: &mut BaseText,
    bytes: u64,
) -> (u64, u64, u64) {
    if !need_diff {
        return (0, 0, bytes);
    }
    let Some((changes, _, _, _)) = session_changes(workspace_root, id) else {
        return (0, 0, bytes);
    };
    let text = |b: &[u8]| (!is_binary_bytes(b)).then(|| String::from_utf8_lossy(b).into_owned());
    let mut lines = 0u64;
    for (change, content) in &changes {
        let old = if change.kind == "added" {
            None
        } else {
            base_text
                .entry(change.path.clone())
                .or_insert_with(|| {
                    let base = base_commit?;
                    let out = git_command(workspace_root)
                        .args(["show", &format!("{base}:{}", change.path)])
                        .stdin(Stdio::null())
                        .output()
                        .ok()
                        .filter(|o| o.status.success())?;
                    (out.stdout.len() <= MAX_DIFF_FILE_BYTES)
                        .then(|| text(&out.stdout))
                        .flatten()
                })
                .clone()
        };
        let new = content.as_deref().and_then(text);
        let changed = match (old, new) {
            (Some(old), Some(new)) => {
                let (old, new): (Vec<&str>, Vec<&str>) =
                    (old.lines().collect(), new.lines().collect());
                myers_diff(&old, &new)
                    .iter()
                    .filter(|op| !matches!(op, DiffOp::Equal(..)))
                    .count()
            }
            (Some(only), None) | (None, Some(only)) => only.lines().count(),
            (None, None) => 0,
        };
        lines = lines.saturating_add(changed as u64);
    }
    (changes.len() as u64, lines, bytes)
}

/// The change set of session `id` (see [`diff_workspace_full`]), or `None` when its workspace
/// is gone.
fn session_changes(workspace_root: &Path, id: &str) -> Option<Left> {
    let dir = session_dir(workspace_root, id);
    let base = std::fs::read_to_string(dir.join(BASE_FILE)).ok()?;
    let base: Base = serde_json::from_str(&base).ok()?;
    let workspace = dir.join("ws");
    workspace
        .is_dir()
        .then(|| diff_workspace_full(&workspace, &base))
}

/// Record what a session left behind: its changes, and the links it made that are not carried
/// (at most [`MAX_SKIPPED`] listed, the rest counted).
fn note_changes(rec: &mut AgentSessionRecord, (changes, truncated, skipped, more): Left) {
    rec.changes = changes.into_iter().map(|(change, _)| change).collect();
    rec.changes_truncated = truncated;
    let all: BTreeSet<String> = rec.skipped.drain(..).chain(skipped).collect();
    rec.skipped_truncated += all.len().saturating_sub(MAX_SKIPPED) + more;
    rec.skipped = all.into_iter().take(MAX_SKIPPED).collect();
}

// ---------------------------------------------------------------------------
// Session records
// ---------------------------------------------------------------------------

/// Snapshot of a real live or completed caged agent session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentSessionRecord {
    pub id: String,
    pub principal: String,
    pub agent_profile: String,
    pub env: String,
    pub command: String,
    pub proxy_url: String,
    pub placeholders: BTreeMap<String, String>,
    /// `running`, `completed`, `failed`, `stopped`, `timed_out`, `paused` (stopped by its owner
    /// to step in: the workspace stays), or `interrupted` (server stopped mid-run).
    pub status: String,
    pub exit_code: Option<i32>,
    pub bytes_scrubbed: usize,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub output_lines: Vec<String>,
    /// `bwrap` (confined) or `none` (a plain process of the server user: not confined).
    #[serde(default)]
    pub sandbox: String,
    /// Why it ended: `exit code N`, `timeout`, `killed`, or why it never started.
    #[serde(default)]
    pub ended_reason: Option<String>,
    /// The branch the workspace was taken from, and its canonical tip then (`None`: no commit).
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub base_commit: Option<String>,
    /// What the session changed in its workspace, known once it has ended.
    #[serde(default)]
    pub changes: Vec<SessionChange>,
    /// The change set is incomplete (too many or too large changes): it cannot be committed.
    #[serde(default)]
    pub changes_truncated: bool,
    /// The commit the change set became.
    #[serde(default)]
    pub commit: Option<String>,
    /// The workspace was discarded (by its owner, or 24 h after the session ended).
    #[serde(default)]
    pub discarded: bool,
    /// Symbolic links that are not carried: links of the branch that are not in the workspace
    /// (their target leads outside it, or this host cannot make them), and links the session
    /// made whose target is absolute or leads outside. The branch keeps what it has at those
    /// paths when the session is committed.
    #[serde(default)]
    pub skipped: Vec<String>,
    /// How many more such links there were than `skipped` lists.
    #[serde(default)]
    pub skipped_truncated: usize,
    /// Live autonomy budget: limits, usage and breach state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetSnapshot>,
    /// The lane this session's work is kept on, and the review it is a round of.
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub change_id: Option<String>,
    /// The review round it was steered to produce, then the round its commit became.
    #[serde(default)]
    pub review_round: Option<u32>,
    /// Its commit was rebased three ways onto a branch that had moved.
    #[serde(default)]
    pub rebased: bool,
    /// Why its commit could not land (kept on its lane instead).
    #[serde(default)]
    pub conflicts: Vec<LaneConflict>,
    /// What it did, in order (at most [`MAX_STEPS`], oldest dropped first).
    #[serde(default)]
    pub provenance_steps: Vec<ProvenanceStep>,
    /// Ambient telemetry: at most one per kind, upserted by id while the session runs.
    #[serde(default)]
    pub insights: Vec<SessionInsight>,
    /// The time limit it ran under, in seconds (0 on records from before it was kept).
    #[serde(default)]
    pub limit_secs: u64,
    /// Human step-in checkpoints of its workspace (carried over when it is resumed).
    #[serde(default)]
    pub checkpoints: Vec<SessionCheckpoint>,
    /// The paused session this one resumed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_from: Option<String>,
}

impl AgentSessionRecord {
    /// Strip owner-only telemetry, step-in checkpoints, resume provenance, and step-in/pause
    /// log lines before sending a session record to a non-owner member.
    pub(crate) fn redact_for_member(&mut self) {
        self.insights.clear();
        self.checkpoints.clear();
        self.resumed_from = None;
        self.output_lines.retain(|l| {
            !l.starts_with("[step-in]")
                && !l.starts_with("[cage] paused by owner")
                && !l.starts_with("[cage] resumed from ")
        });
    }
}

/// A session still running (or paused): what its budget, kill switch and offboarding act on.
struct LiveSession {
    tracker: Arc<BudgetTracker>,
    pid: Option<u32>,
    cgroup: Option<Arc<CgroupGuard>>,
    principal: String,
}

/// A running or budget-paused session (not yet ended).
pub(crate) fn is_live(status: &str) -> bool {
    status == "running" || status == "paused"
}

/// Whether `rec` still has a process: `running`, or `paused` by its budget. A session paused by
/// its owner for step-in has the same status but has ended (`finished_at` is set).
pub(crate) fn is_live_rec(rec: &AgentSessionRecord) -> bool {
    is_live(&rec.status) && rec.finished_at.is_none()
}

/// Most provenance steps one session record keeps.
const MAX_STEPS: usize = 250;
/// Most `file_change` steps one session records.
const MAX_FILE_STEPS: usize = 50;

/// A step of `kind` now, numbered by [`push_step`].
pub(crate) fn step(kind: &str, summary: String) -> ProvenanceStep {
    ProvenanceStep {
        seq: 0,
        kind: kind.to_owned(),
        timestamp: Utc::now().to_rfc3339(),
        summary,
        path: None,
        target: None,
        decision: None,
        exit_code: None,
        bytes_scrubbed: 0,
    }
}

/// Append `step` to `rec` with the next sequence number, dropping the oldest over [`MAX_STEPS`].
pub(crate) fn push_step(rec: &mut AgentSessionRecord, mut step: ProvenanceStep) {
    step.seq = rec.provenance_steps.last().map_or(1, |s| s.seq + 1);
    rec.provenance_steps.push(step);
    let excess = rec.provenance_steps.len().saturating_sub(MAX_STEPS);
    rec.provenance_steps.drain(..excess);
}

/// One review comment handed to a steered session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SteeringComment {
    pub id: String,
    pub author: String,
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    pub body: String,
    #[serde(default)]
    pub round: Option<u32>,
}

/// What a session is asked to address: written to `steering.json` / `steering.md` next to its
/// proxy socket (never into the workspace, so never into a diff or commit).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SteeringPacket {
    pub change_id: String,
    pub target_round: u32,
    #[serde(default)]
    pub lane_id: Option<String>,
    pub branch: String,
    pub instruction: String,
    #[serde(default)]
    pub comments: Vec<SteeringComment>,
    #[serde(default)]
    pub conflicts: Vec<LaneConflict>,
    /// Comments the packet carries, and comments left out because the session may not read them.
    #[serde(default)]
    pub packaged_comments: usize,
    #[serde(default)]
    pub redacted_comments: usize,
}

impl SteeringPacket {
    /// The packet as Markdown, for an agent that reads prose.
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write as _;
        let mut md = format!(
            "# Steering for review {} (round {})\n\nBranch: `{}`\n",
            self.change_id, self.target_round, self.branch
        );
        if let Some(lane) = &self.lane_id {
            let _ = writeln!(md, "Lane: `{lane}`");
        }
        let _ = write!(md, "\n## Instruction\n\n{}\n", self.instruction);
        if !self.comments.is_empty() {
            md.push_str("\n## Review comments\n\n");
            for c in &self.comments {
                let at = c
                    .line
                    .map_or_else(|| c.path.clone(), |l| format!("{}:{l}", c.path));
                let _ = writeln!(md, "- [{}] `{at}` ({}): {}", c.id, c.author, c.body);
            }
        }
        if !self.conflicts.is_empty() {
            md.push_str("\n## Conflicts to resolve\n\n");
            for c in &self.conflicts {
                let _ = writeln!(md, "- `{}` ({}): {}", c.path, c.kind, c.summary);
            }
        }
        if self.redacted_comments > 0 {
            let _ = writeln!(
                md,
                "\n_{} not shown: outside what this session may read._",
                premier_git_bridge::plural(self.redacted_comments, "comment")
            );
        }
        md
    }
}

/// Run once a session has ended, with its final record.
pub type SessionCompleteHook = Box<
    dyn FnOnce(
            AgentSessionRecord,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send,
>;

/// What a session is started with.
pub struct SessionRequest {
    /// The canonical repository. The agent never sees it.
    pub workspace_root: PathBuf,
    /// Already `human ∩ agent task`.
    pub identity: DelegatedIdentity,
    pub env_name: String,
    pub command: String,
    /// Short branch name (what policy is evaluated on) and its canonical ref (`None`: no commit).
    pub branch: String,
    pub full_ref: Option<String>,
    pub ref_visibility: HashMap<String, Visibility>,
    pub policy: Option<Arc<CompiledPolicy>>,
    pub schema: Option<Arc<EnvSchema>>,
    pub audit_sink: Arc<AuditSink>,
    pub approval_hub: Arc<ApprovalHub>,
    pub cage: Cage,
    pub limit: std::time::Duration,
    /// Owner-approved instruction files ([`materialise_with_quarantine`]).
    pub quarantine_approvals: BTreeMap<String, crate::store::ApprovedInstructionFile>,
    /// Owner-requested autonomy budget; it can only tighten the agent profile's policy budget.
    pub budget: Option<AutonomyBudget>,
    /// Start from this canonical commit instead of the tip of `full_ref` (see [`materialise`]).
    pub base_commit_override: Option<String>,
    pub lane_id: Option<String>,
    pub change_id: Option<String>,
    pub steering_packet: Option<SteeringPacket>,
    pub on_complete: Option<SessionCompleteHook>,
}

/// The budget a session runs under: the profile's policy budget, tightened (never loosened) by
/// what the request asks for.
pub fn effective_budget(
    policy: Option<&CompiledPolicy>,
    agent_profile: Option<&str>,
    requested: Option<&AutonomyBudget>,
) -> AutonomyBudget {
    let from_policy = policy
        .zip(agent_profile)
        .and_then(|(p, a)| p.agent_budget(a));
    match (from_policy, requested) {
        (Some(p), Some(r)) => p.tighten(r),
        (Some(p), None) => p,
        (None, Some(r)) => r.clone(),
        (None, None) => AutonomyBudget::default(),
    }
}

/// Manages active and recent real caged agent sessions with SSE broadcast updates.
pub struct SessionManager {
    counter: AtomicU64,
    sessions: Mutex<Vec<AgentSessionRecord>>,
    tx: broadcast::Sender<AgentSessionRecord>,
    /// Workspace whose `.premier/sessions.json` mirrors `sessions`; `None` keeps them in memory.
    persist_root: Option<PathBuf>,
    /// The task driving each session's child process, so [`Self::stop_all`] can end them.
    running: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Per-session cancellation signal sent by `POST /v1/agents/sessions/{id}/stop` or `/pause`.
    cancel: Mutex<HashMap<String, tokio::sync::oneshot::Sender<CancelKind>>>,
    /// Sessions currently being committed: prevents concurrent double-commit races.
    committing: Mutex<HashSet<String>>,
    /// Budget alerts of every session, for the `budget_alert` SSE event.
    budget_tx: broadcast::Sender<BudgetAlert>,
    /// Sessions whose child process is still alive (running or paused).
    live: Mutex<HashMap<String, LiveSession>>,
    /// Every new or updated session insight (each is also kept on its session record).
    insight_tx: broadcast::Sender<SessionInsight>,
    /// Optional integrated flight-recorder store for automatic live span emission.
    trace_store: Option<Arc<premier_trace::TraceStore>>,
}

/// How the owner ends a running session: kill it, or pause it keeping its workspace to step in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelKind {
    Stop,
    Pause,
}

/// Aborts a helper task when the session task that owns it ends, however it ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Milliseconds since `start`: the telemetry clock.
fn ms_since(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

const PAUSED_LINE: &str = "[cage] paused by owner for human step-in (workspace preserved)";
const PAUSED_REASON: &str = "paused by owner for step-in";

/// Everything [`SessionManager::launch_in_workspace`] needs: a prepared session directory
/// (`ws/` and `base.json` in place) and who runs what in it.
struct Launch {
    session_id: String,
    dir: PathBuf,
    workspace_root: PathBuf,
    identity: DelegatedIdentity,
    env_name: String,
    command: String,
    branch: String,
    trace_branch: String,
    policy: Option<Arc<CompiledPolicy>>,
    schema: Option<Arc<EnvSchema>>,
    audit_sink: Arc<AuditSink>,
    approval_hub: Arc<ApprovalHub>,
    cage: Cage,
    cage_user: Option<CageUser>,
    limit: std::time::Duration,
    base_commit: Option<String>,
    skipped: Vec<String>,
    resumed_from: Option<String>,
    checkpoints: Vec<SessionCheckpoint>,
    /// Owner-requested autonomy budget; it can only tighten the agent profile's policy budget.
    requested_budget: Option<AutonomyBudget>,
    /// What the quarantine did to the workspace while it was materialised.
    quarantined: Vec<QuarantineWorkspaceAction>,
    lane_id: Option<String>,
    change_id: Option<String>,
    steering_packet: Option<SteeringPacket>,
    on_complete: Option<SessionCompleteHook>,
}

/// Who a session runs as under `mode`; `Err` when sessions cannot run on this host.
fn cage_user_for(mode: SandboxMode) -> Result<Option<CageUser>, String> {
    match mode {
        SandboxMode::None => Err(NO_SANDBOX.to_owned()),
        SandboxMode::Bwrap => Ok(Some(probe().user.ok_or(NO_SANDBOX)?)),
        SandboxMode::UnsandboxedAllowed => Ok(None),
    }
}

/// Tests run sessions in throwaway repositories: their workspaces go with the manager.
#[cfg(test)]
impl Drop for SessionManager {
    fn drop(&mut self) {
        if let Some(root) = &self.persist_root {
            let _ = std::fs::remove_dir_all(sessions_root(root));
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(128);
        let (budget_tx, _) = broadcast::channel(64);
        let (insight_tx, _) = broadcast::channel(128);
        Self {
            counter: AtomicU64::new(1),
            sessions: Mutex::new(Vec::new()),
            tx,
            persist_root: None,
            running: Mutex::new(Vec::new()),
            cancel: Mutex::new(HashMap::new()),
            committing: Mutex::new(HashSet::new()),
            budget_tx,
            live: Mutex::new(HashMap::new()),
            insight_tx,
            trace_store: None,
        }
    }

    /// Attach a [`premier_trace::TraceStore`] so caged agent sessions and their proxy egress
    /// events automatically emit live flight-recorder traces.
    pub fn with_trace_store(mut self, store: Arc<premier_trace::TraceStore>) -> Self {
        self.trace_store = Some(store);
        self
    }

    pub fn subscribe_budget_alerts(&self) -> broadcast::Receiver<BudgetAlert> {
        self.budget_tx.subscribe()
    }

    /// Human budget approval: install `new_limits` on a live session and, if `resume`, let a
    /// paused one continue. 404 for an unknown session, 409 for one that has ended or was
    /// terminated.
    pub fn raise_session_budget(
        &self,
        id: &str,
        new_limits: AutonomyBudget,
        resume: bool,
    ) -> Result<AgentSessionRecord, (StatusCode, String)> {
        let live = self.live.lock().ok().and_then(|m| {
            m.get(id)
                .map(|l| (Arc::clone(&l.tracker), l.pid, l.cgroup.clone()))
        });
        let Some((tracker, pid, cgroup)) = live else {
            return Err(match self.get(id) {
                None => (StatusCode::NOT_FOUND, "no such session".to_owned()),
                Some(_) => (
                    StatusCode::CONFLICT,
                    "the session is not running".to_owned(),
                ),
            });
        };
        if tracker.is_terminated() {
            return Err((
                StatusCode::CONFLICT,
                "the session was terminated; its budget cannot be raised".to_owned(),
            ));
        }
        let snap = tracker.raise_limits(new_limits, resume);
        if resume {
            resume_session_tree(pid, cgroup.as_deref());
        }
        self.update(id, |rec| {
            rec.budget = Some(snap);
            if resume && rec.status == "paused" {
                rec.status = "running".to_owned();
                rec.output_lines
                    .push("[cage] RESUMED: budget raised by owner".to_owned());
            }
        })
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no such session".to_owned()))
    }

    /// Kill switch: terminate every live session of `canonical_principal` (`@user`, any case)
    /// and wait briefly for each to end. Returns how many were terminated.
    pub async fn stop_for_principal(&self, canonical_principal: &str, reason: &str) -> usize {
        let targets: Vec<(String, Arc<BudgetTracker>)> = self
            .live
            .lock()
            .map(|m| {
                m.iter()
                    .filter(|(_, l)| l.principal.eq_ignore_ascii_case(canonical_principal))
                    .map(|(id, l)| (id.clone(), Arc::clone(&l.tracker)))
                    .collect()
            })
            .unwrap_or_default();
        for (id, tracker) in &targets {
            tracker.terminate(reason);
            let tx = self.cancel.lock().ok().and_then(|mut m| m.remove(id));
            if let Some(tx) = tx {
                let _ = tx.send(CancelKind::Stop);
            }
        }
        for (id, _) in &targets {
            for _ in 0..80 {
                if self.get(id).is_none_or(|r| !is_live_rec(&r)) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
        targets.len()
    }

    /// Every session insight as it is raised or updated.
    pub fn subscribe_insights(&self) -> broadcast::Receiver<SessionInsight> {
        self.insight_tx.subscribe()
    }

    /// Upsert `insight` (by id) on its session, persist, and broadcast both.
    pub(crate) fn record_insight(&self, insight: SessionInsight) {
        let updated = {
            let Ok(mut guard) = self.sessions.lock() else {
                return;
            };
            let Some(rec) = guard.iter_mut().find(|s| s.id == insight.session_id) else {
                return;
            };
            match rec.insights.iter_mut().find(|i| i.id == insight.id) {
                Some(slot) => *slot = insight.clone(),
                None => rec.insights.push(insight.clone()),
            }
            let rec = rec.clone();
            self.persist(&guard);
            rec
        };
        let _ = self.tx.send(updated);
        let _ = self.insight_tx.send(insight);
    }

    fn next_session_id(&self) -> String {
        let num = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("cage-{num:04}")
    }

    /// Kill every running session and remove its workspaces when deleting a repository.
    pub async fn stop_all(&self) {
        self.shutdown().await;
        if let Some(root) = &self.persist_root {
            let _ = std::fs::remove_dir_all(sessions_root(root));
        }
    }

    /// Stop live processes and proxies, preserving workspaces for recovery.
    pub async fn shutdown(&self) {
        if let Ok(mut cancel) = self.cancel.lock() {
            cancel.clear();
        }
        if let Ok(mut live) = self.live.lock() {
            live.clear();
        }
        let running = self
            .running
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        for task in &running {
            task.abort();
        }
        for task in running {
            let _ = task.await;
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            for rec in sessions.iter_mut().filter(|s| is_live_rec(s)) {
                rec.status = "interrupted".to_owned();
                rec.ended_reason = Some("killed".to_owned());
                rec.finished_at = Some(Utc::now().to_rfc3339());
                rec.output_lines.push(
                    "[cage] interrupted: the server stopped this repository's sessions".to_owned(),
                );
                if let Some(left) = self
                    .persist_root
                    .as_deref()
                    .and_then(|root| session_changes(root, &rec.id))
                {
                    note_changes(rec, left);
                }
            }
            self.persist(&sessions);
        }
    }

    /// Reload the session records persisted in `workspace_root` and keep persisting there.
    /// A session that was still running when the server stopped comes back `interrupted`: its
    /// process and capability proxy died with the old server. Workspaces nobody can commit any
    /// more are removed.
    pub fn open(workspace_root: &Path) -> Self {
        let mut sessions: Vec<AgentSessionRecord> = load_json(workspace_root, SESSIONS_FILE);
        let mut interrupted = false;
        for rec in &mut sessions {
            // A budget pause froze a process (it carries a budget snapshot) and the restart
            // killed it. A `paused` record without one is an owner step-in pause: no process,
            // workspace preserved, so it comes back as it was.
            if rec.status == "running" || (is_live_rec(rec) && rec.budget.is_some()) {
                interrupted = true;
                rec.status = "interrupted".to_owned();
                rec.ended_reason = Some("killed".to_owned());
                rec.finished_at = Some(Utc::now().to_rfc3339());
                rec.output_lines
                    .push("[cage] interrupted: the server restarted mid-session".to_owned());
                if let Some(left) = session_changes(workspace_root, &rec.id) {
                    note_changes(rec, left);
                }
            }
        }
        // Ids are `cage-NNNN`; continue after the highest restored one.
        let next = sessions
            .iter()
            .filter_map(|s| s.id.strip_prefix("cage-")?.parse::<u64>().ok())
            .max()
            .map_or(1, |n| n + 1);
        let mut mgr = Self::new();
        mgr.counter = AtomicU64::new(next);
        mgr.persist_root = Some(workspace_root.to_path_buf());
        if interrupted {
            mgr.persist(&sessions);
        }
        mgr.sessions = Mutex::new(sessions);
        mgr.collect_garbage(workspace_root);
        mgr
    }

    /// Remove every session directory of `workspace_root` that no record can still commit:
    /// committed, discarded, forgotten, or ended more than 24 h ago. Runs on startup and before
    /// each new session.
    fn collect_garbage(&self, workspace_root: &Path) {
        let now = Utc::now();
        let expired = |rec: &AgentSessionRecord| {
            rec.finished_at
                .as_deref()
                .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
                .is_some_and(|at| (now - at.with_timezone(&Utc)).num_seconds() > WORKSPACE_TTL_SECS)
        };
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let mut changed = false;
        for rec in sessions.iter_mut() {
            if !is_live_rec(rec) && rec.commit.is_none() && !rec.discarded && expired(rec) {
                rec.discarded = true;
                changed = true;
            }
        }
        let keep: HashSet<&str> = sessions
            .iter()
            .filter(|s| s.commit.is_none() && !s.discarded)
            .map(|s| s.id.as_str())
            .collect();
        let dirs = std::fs::read_dir(sessions_root(workspace_root));
        for entry in dirs.into_iter().flatten().flatten() {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| keep.contains(name))
            {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        if changed {
            self.persist(&sessions);
        }
    }

    /// Called with the lock held, on session start and finish (not per output line).
    fn persist(&self, sessions: &[AgentSessionRecord]) {
        if let Some(root) = &self.persist_root
            && let Err(e) = save_json(root, SESSIONS_FILE, &sessions)
        {
            tracing::warn!(error = %e, "failed to persist agent sessions");
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AgentSessionRecord> {
        self.tx.subscribe()
    }

    pub fn list(&self) -> Vec<AgentSessionRecord> {
        self.sessions.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn get(&self, id: &str) -> Option<AgentSessionRecord> {
        self.sessions
            .lock()
            .ok()?
            .iter()
            .find(|s| s.id == id)
            .cloned()
    }

    fn upsert(&self, rec: AgentSessionRecord) {
        if let Ok(mut guard) = self.sessions.lock() {
            if let Some(pos) = guard.iter().position(|s| s.id == rec.id) {
                guard[pos] = rec.clone();
            } else {
                guard.insert(0, rec.clone());
                if guard.len() > 30 {
                    guard.truncate(30);
                }
            }
            self.persist(&guard);
        }
        let _ = self.tx.send(rec);
    }

    /// A live budget alert of session `id`: tell the Studio, audit what the proxy did not
    /// (workspace breaches and terminations), and refresh the record's budget.
    fn on_budget_alert(
        &self,
        id: &str,
        identity: &DelegatedIdentity,
        audit_sink: &AuditSink,
        tracker: &BudgetTracker,
        alert: &BudgetAlert,
    ) {
        let _ = self.budget_tx.send(alert.clone());
        // The egress proxy audits the breaches it trips itself.
        let proxy_metric = matches!(
            alert.metric.as_str(),
            "egress_requests" | "egress_bytes" | "jit_requests" | "denied_attempts"
        );
        if !proxy_metric {
            let mut ev = AuditEvent::now(
                identity,
                "premier-cage",
                "budget_exceeded",
                AuditDecision::BudgetExceeded,
                format!("session {id}: {}", alert.message),
            );
            ev.target = Some(id.to_owned());
            ev.capability = Some(alert.metric.clone());
            crate::auth::audit(audit_sink, ev);
        }
        let snap = tracker.snapshot();
        self.update(id, |rec| rec.budget = Some(snap));
    }

    /// Refresh a running session's budget usage; broadcast only when the usage changed.
    fn set_budget_quiet(&self, id: &str, snap: BudgetSnapshot) {
        let same = |a: &BudgetSnapshot, b: &BudgetSnapshot| {
            BudgetSnapshot {
                elapsed_secs: 0,
                ..a.clone()
            } == BudgetSnapshot {
                elapsed_secs: 0,
                ..b.clone()
            }
        };
        let changed = self.sessions.lock().ok().and_then(|mut guard| {
            let rec = guard.iter_mut().find(|s| s.id == id)?;
            let changed = rec.budget.as_ref().is_none_or(|old| !same(old, &snap));
            rec.budget = Some(snap);
            changed.then(|| rec.clone())
        });
        if let Some(rec) = changed {
            let _ = self.tx.send(rec);
        }
    }

    fn append_line(&self, id: &str, line: String, scrubbed_delta: usize) {
        let snap = self
            .live
            .lock()
            .ok()
            .and_then(|m| m.get(id).map(|l| l.tracker.snapshot()));
        let updated = if let Ok(mut guard) = self.sessions.lock() {
            if let Some(rec) = guard.iter_mut().find(|s| s.id == id) {
                if snap.is_some() {
                    rec.budget = snap;
                }
                rec.bytes_scrubbed += scrubbed_delta;
                rec.output_lines.push(line);
                if rec.output_lines.len() > 250 {
                    let excess = rec.output_lines.len() - 250;
                    rec.output_lines.drain(0..excess);
                }
                Some(rec.clone())
            } else {
                None
            }
        } else {
            None
        };
        if let Some(rec) = updated {
            let _ = self.tx.send(rec);
        }
    }

    /// Change the record of `id`, persist and broadcast it.
    pub(crate) fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut AgentSessionRecord),
    ) -> Option<AgentSessionRecord> {
        let updated = {
            let mut guard = self.sessions.lock().ok()?;
            let rec = guard.iter_mut().find(|s| s.id == id)?;
            change(rec);
            let rec = rec.clone();
            self.persist(&guard);
            rec
        };
        let _ = self.tx.send(updated.clone());
        Some(updated)
    }

    /// Append a provenance step to `id` (numbered, capped at [`MAX_STEPS`]) and broadcast it;
    /// persisted at once only when the session is no longer running.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append_step(
        &self,
        id: &str,
        kind: &str,
        summary: String,
        path: Option<String>,
        target: Option<String>,
        decision: Option<String>,
        exit_code: Option<i32>,
        bytes_scrubbed: usize,
    ) -> Option<AgentSessionRecord> {
        let updated = {
            let mut guard = self.sessions.lock().ok()?;
            let rec = guard.iter_mut().find(|s| s.id == id)?;
            push_step(
                rec,
                ProvenanceStep {
                    path,
                    target,
                    decision,
                    exit_code,
                    bytes_scrubbed,
                    ..step(kind, summary)
                },
            );
            let rec = rec.clone();
            if rec.status != "running" {
                self.persist(&guard);
            }
            rec
        };
        let _ = self.tx.send(updated.clone());
        Some(updated)
    }

    fn finish(
        &self,
        id: &str,
        exit_code: Option<i32>,
        status: &str,
        reason: String,
        redactor: &SecretRedactor,
    ) {
        let trace_reason = reason.clone();
        self.update(id, |rec| {
            let scrubbed = rec.bytes_scrubbed;
            push_step(
                rec,
                ProvenanceStep {
                    exit_code,
                    bytes_scrubbed: scrubbed,
                    ..step("session_exit", reason.clone())
                },
            );
            rec.status = status.to_owned();
            rec.exit_code = exit_code;
            rec.ended_reason = Some(reason);
            rec.finished_at = Some(Utc::now().to_rfc3339());
        });
        if let Some(ref ts) = self.trace_store {
            let failed = exit_code.is_some_and(|c| c != 0) || status == "failed";
            let final_status = if failed {
                premier_trace::SessionStatus::Failed
            } else if status == "blocked" {
                premier_trace::SessionStatus::Blocked
            } else {
                premier_trace::SessionStatus::Completed
            };
            let now = Utc::now();
            let mut span = premier_trace::TraceSpan {
                span_id: premier_trace::deterministic_id("sp_finish", id),
                timestamp: now,
                kind: if failed {
                    premier_trace::SpanKind::ErrorDiagnostic
                } else {
                    premier_trace::SpanKind::DeliveryReport
                },
                summary: format!("Session {status}: {trace_reason}"),
                tool_name: Some("premier-runner".to_owned()),
                decision: Some(if failed {
                    AuditDecision::Denied
                } else {
                    AuditDecision::Allowed
                }),
                error_message: if failed { Some(trace_reason) } else { None },
                exit_code,
                correlation_id: Some(id.to_owned()),
                status: Some(status.to_owned()),
                source: Some("premier-runner".to_owned()),
                ..premier_trace::TraceSpan::default()
            };
            crate::traces::scrub_span(&mut span, redactor);
            let _ = ts.record_span(id, span);
            let _ = ts.link_commit_and_change(id, None, None, Some(final_status));
        }
    }

    /// Launch a real local process in a private projected workspace, wrapped in a live ephemeral
    /// `CapabilityProxy` with placeholder-only credentials and real streaming `SecretRedactor`
    /// scrubbing. Under bubblewrap that proxy is its only route to any network.
    pub async fn spawn_session(
        self: &Arc<Self>,
        req: SessionRequest,
    ) -> Result<AgentSessionRecord, String> {
        let SessionRequest {
            workspace_root,
            identity,
            env_name,
            command,
            branch,
            full_ref,
            ref_visibility,
            policy,
            schema,
            audit_sink,
            approval_hub,
            cage,
            limit,
            quarantine_approvals,
            budget: requested_budget,
            base_commit_override,
            lane_id,
            change_id,
            steering_packet,
            on_complete,
        } = req;
        let cage_user = cage_user_for(cage.mode)?;
        let trace_branch = full_ref.clone().unwrap_or_else(|| branch.clone());
        self.collect_garbage(&workspace_root);
        let session_id = self.next_session_id();

        // The private workspace: only what this identity may read on the branch.
        let dir = session_dir(&workspace_root, &session_id);
        let (workspace, proxy_dir, home) = (dir.join("ws"), dir.join("proxy"), dir.join("home"));
        let (base_commit, skipped, quarantined) = {
            let (root, session) = (workspace_root.clone(), dir.clone());
            let (workspace, proxy_dir, home) = (workspace.clone(), proxy_dir.clone(), home.clone());
            let (policy, identity, branch) = (policy.clone(), identity.clone(), branch.clone());
            let base_override = base_commit_override.clone();
            let steering = steering_packet.clone();
            let prepared = tokio::task::spawn_blocking(move || {
                let dir = session;
                if crate::store::state_root(&root).is_none()
                    && let Some(base) = user_session_state()
                {
                    private_dir(&base).map_err(|e| format!("session state directory: {e}"))?;
                }
                private_dir(&sessions_root(&root))
                    .map_err(|e| format!("session directory: {e}"))?;
                let _ = std::fs::remove_dir_all(&dir);
                for d in [&proxy_dir, &home] {
                    std::fs::create_dir_all(d).map_err(|e| format!("session directory: {e}"))?;
                }
                let (tip, base, skipped, quarantined) = materialise_full(
                    &root,
                    full_ref.as_deref(),
                    &branch,
                    policy.as_deref(),
                    &identity,
                    &ref_visibility,
                    &workspace,
                    base_override.as_deref(),
                    &quarantine_approvals,
                )?;
                let base = serde_json::to_string(&base).map_err(|e| e.to_string())?;
                std::fs::write(dir.join(BASE_FILE), base)
                    .map_err(|e| format!("session directory: {e}"))?;
                // Beside the proxy socket, never in the workspace: not part of any diff or commit.
                if let Some(packet) = &steering {
                    let json = serde_json::to_vec_pretty(packet).map_err(|e| e.to_string())?;
                    std::fs::write(proxy_dir.join(STEERING_JSON), json)
                        .and_then(|()| {
                            std::fs::write(proxy_dir.join(STEERING_MD), packet.to_markdown())
                        })
                        .map_err(|e| format!("steering packet: {e}"))?;
                }
                Ok::<_, String>((tip, skipped, quarantined))
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            match prepared {
                Ok(prepared) => prepared,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(format!("failed to prepare the session workspace: {e}"));
                }
            }
        };
        self.launch_in_workspace(Launch {
            session_id,
            dir,
            workspace_root,
            identity,
            env_name,
            command,
            branch,
            trace_branch,
            policy,
            schema,
            audit_sink,
            approval_hub,
            cage,
            cage_user,
            limit,
            base_commit,
            skipped,
            resumed_from: None,
            checkpoints: Vec::new(),
            requested_budget,
            quarantined,
            lane_id,
            change_id,
            steering_packet,
            on_complete,
        })
        .await
    }

    /// Run a session in its prepared directory (a new one, or one resumed from a paused
    /// session): capability proxy, scrubbed child process, live telemetry, and the task that
    /// records how it ends. Its `ws/` is kept when it ends; `proxy/` and `home/` are not.
    async fn launch_in_workspace(
        self: &Arc<Self>,
        launch: Launch,
    ) -> Result<AgentSessionRecord, String> {
        let Launch {
            session_id,
            dir,
            workspace_root,
            mut identity,
            env_name,
            command,
            branch,
            trace_branch,
            policy,
            schema,
            audit_sink,
            approval_hub,
            cage,
            cage_user,
            limit,
            base_commit,
            mut skipped,
            resumed_from,
            checkpoints,
            requested_budget,
            quarantined,
            lane_id,
            change_id,
            steering_packet,
            on_complete,
        } = launch;
        // The agent task is this session: its proxy's audit events carry the session id.
        if let Some(ref mut task) = identity.agent_task {
            task.task_id = session_id.clone();
        }
        let profile_name = identity.agent_task.as_ref().map(|t| t.profile.clone());
        let budget = effective_budget(
            policy.as_deref(),
            profile_name.as_deref(),
            requested_budget.as_ref(),
        );
        let resource_limits = ResourceLimits::from(&budget);
        let tracker = Arc::new(BudgetTracker::new(
            &session_id,
            identity.principal.canonical_id(),
            profile_name,
            budget,
            limit.as_secs(),
        ));
        let mut alert_rx = tracker.subscribe_alerts();
        let (workspace, proxy_dir, home) = (dir.join("ws"), dir.join("proxy"), dir.join("home"));
        let schema_val = schema.as_deref().cloned().unwrap_or_default();
        let repo_id = schema_val
            .repo_id
            .clone()
            .unwrap_or_else(|| "local/repo".to_owned());

        // Resolve real secrets from encrypted workspace vault or process env (USE capability only).
        let mut registry = PlaceholderRegistry::new();
        let mut public_vars = BTreeMap::new();
        let mut redactor_pairs: Vec<(String, Zeroizing<String>)> = Vec::new();
        let mut placeholders = BTreeMap::new();

        let vault_opt = resolve_vault_backend(&workspace_root, &repo_id).ok();
        // Every secret copy is `Zeroizing`, so the plaintext is wiped when the session is set up.
        let mut resolved_map: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();

        if let Some(ref vault) = vault_opt {
            let ctx = ResolveContext {
                repo_id: repo_id.clone(),
                org: "local".to_owned(),
                env: Environment::parse(&env_name),
                branch: branch.clone(),
                identity: identity.clone(),
            };
            let resolver = SecretResolver::new(&schema_val, policy.as_deref(), vault.as_ref());
            if let Ok(res) = resolver.resolve(&ctx, Capability::USE) {
                for (k, v) in res.values {
                    resolved_map.insert(k, Zeroizing::new(v.as_str().to_owned()));
                }
            }
        }

        for (var_name, spec) in &schema_val.vars {
            // Strictly resolve from workspace vault and `.env.schema` defaults; NEVER fall back
            // to host server `std::env::var`.
            let maybe_val = resolved_map
                .get(var_name)
                .cloned()
                .or_else(|| spec.default.clone().map(Zeroizing::new));

            if let Some(egress) = &spec.egress {
                // Fail closed: require a loaded compiled policy granting USE or READ.
                let allowed_use = policy.as_ref().is_some_and(|p| {
                    let dec = p.can_use_secret(&identity, var_name, spec.zone.as_deref(), &branch);
                    dec.allows(Capability::USE) || dec.allows(Capability::READ)
                });
                if allowed_use {
                    let secret_val = maybe_val.unwrap_or_else(|| {
                        Zeroizing::new(format!(
                            "premier_vault_unconfigured_{}",
                            var_name.to_lowercase()
                        ))
                    });
                    redactor_pairs.push((var_name.clone(), secret_val.clone()));
                    let ph = registry.register_with_sensitivity(
                        var_name.clone(),
                        secret_val,
                        egress.clone(),
                        spec.zone.clone(),
                        spec.sensitivity,
                    );
                    placeholders.insert(var_name.clone(), ph);
                }
            } else if matches!(
                spec.sensitivity,
                Sensitivity::Public | Sensitivity::Internal
            ) && let Some(v) = maybe_val
            {
                public_vars.insert(var_name.clone(), v.as_str().to_owned());
            }
        }

        // Start a real ephemeral CapabilityProxy bound to 127.0.0.1:0 wired to the shared ApprovalHub + AuditSink!
        let mut proxy_cfg = ProxyConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            identity.clone(),
            registry.clone(),
        );
        proxy_cfg.ref_name = branch.clone();
        proxy_cfg.session_id = Some(session_id.clone());
        proxy_cfg.policy = policy.as_deref().cloned();
        // A caged agent reaches the proxy through this socket only (bound into its sandbox).
        if cage_user.is_some() {
            proxy_cfg.unix_socket = Some(proxy_dir.join(PROXY_SOCKET));
        }
        // The non-secret hosts the agent profile may reach, as `premier agent run` allows them.
        if let (Some(policy), Some(task)) = (policy.as_deref(), &identity.agent_task) {
            proxy_cfg.allow_passthrough_hosts = policy
                .agent_allowed_egress_hosts(&task.profile)
                .into_iter()
                .collect();
        }
        proxy_cfg.audit_sink = Arc::clone(&audit_sink);
        // A still-live approval for this exact scope (possibly restored after a restart) is
        // honoured without asking again, for the TTL the approver chose.
        proxy_cfg.approval_gate = Box::new(HubGate(Arc::clone(&approval_hub)));
        proxy_cfg.budget = Some(Arc::clone(&tracker));
        // Every audit event of this proxy is tagged with the session, for its provenance steps.
        proxy_cfg.session_id = Some(session_id.clone());
        let audit_rx = audit_sink.subscribe();
        // Before the agent can make any request: its proxy's denials feed the telemetry.
        let telemetry_rx = audit_sink.subscribe();
        proxy_cfg.session_context = Some(premier_proxy::SessionContext {
            session_id: Some(session_id.clone()),
            branch: Some(branch.clone()),
            command: Some(command.clone()),
        });

        let proxy_handle = match start_proxy(proxy_cfg).await {
            Ok(handle) => handle,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("failed to start capability proxy: {e}"));
            }
        };
        let proxy_addr = proxy_handle.addr;
        let proxy_url = format!("http://{proxy_addr}");
        // Materialize the ephemeral HTTPS MITM proxy CA cert inside `proxy_dir` so agents trust
        // the proxy's TLS certificates without touching host trust stores.
        const PROXY_CA_PEM: &str = "proxy-ca.pem";
        if let Err(e) = std::fs::write(proxy_dir.join(PROXY_CA_PEM), &proxy_handle.ca_cert_pem) {
            proxy_handle.shutdown();
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("failed to write proxy CA cert: {e}"));
        }
        let agent_ca_cert_path = match cage_user {
            Some(_) => PathBuf::from(format!("{CAGE_PROXY_DIR}/{PROXY_CA_PEM}")),
            None => proxy_dir.join(PROXY_CA_PEM),
        };

        let agent_profile = identity
            .agent_task
            .as_ref()
            .map(|t| t.profile.clone())
            // No profile: the human identity alone.
            .unwrap_or_default();
        let sandbox = if cage_user.is_some() { "bwrap" } else { "none" };

        let mut output_lines = vec![format!(
            "$ {command}  # proxy={proxy_url} ({}, 0 raw secrets)",
            premier_git_bridge::plural(placeholders.len(), "capability placeholder")
        )];
        match cage_user {
            Some(CageUser::Unprivileged) => {}
            Some(CageUser::RootNoCaps) => output_lines.push(format!("[cage] {}", probe().detail)),
            None => output_lines.push(
                "[cage] NOT CONFINED: no sandbox on this host; this is a plain process of the server user"
                    .to_owned(),
            ),
        }
        if let Some(parent) = &resumed_from {
            output_lines.push(format!(
                "[cage] resumed from paused session {parent} (its workspace, human edits included)"
            ));
        }
        let skipped_truncated = skipped.len().saturating_sub(MAX_SKIPPED);
        skipped.truncate(MAX_SKIPPED);
        if !skipped.is_empty() {
            output_lines.push(format!(
                "[cage] {} not in this workspace: {}",
                premier_git_bridge::plural(skipped.len() + skipped_truncated, "symbolic link"),
                skipped.join(", ")
            ));
        }
        for action in &quarantined {
            let (line, path, decision) = match action {
                QuarantineWorkspaceAction::Substituted {
                    path,
                    from_sha,
                    to_sha,
                } => (
                    format!(
                        "[cage] quarantine: {path} replaced by its owner-approved version ({} -> {})",
                        &from_sha[..from_sha.len().min(12)],
                        &to_sha[..to_sha.len().min(12)]
                    ),
                    path,
                    AuditDecision::Redacted,
                ),
                QuarantineWorkspaceAction::Stripped { path, sha } => (
                    format!(
                        "[cage] quarantine: {path} left out of the workspace: unapproved instruction file ({})",
                        &sha[..sha.len().min(12)]
                    ),
                    path,
                    AuditDecision::Denied,
                ),
            };
            let mut ev = AuditEvent::now(
                &identity,
                "premier-quarantine",
                "quarantine_workspace_filter",
                decision,
                format!(
                    "session {session_id}: {}",
                    line.trim_start_matches("[cage] ")
                ),
            );
            ev.target = Some(path.clone());
            crate::auth::audit(&audit_sink, ev);
            output_lines.push(line);
        }
        let base_note = base_commit.as_deref().map_or_else(
            || "no commit".to_owned(),
            |c| c[..c.len().min(12)].to_owned(),
        );
        let lane_note = lane_id
            .as_deref()
            .map(|l| format!(", lane {l}"))
            .unwrap_or_default();
        let mut provenance_steps = Vec::new();
        for s in [
            step(
                "session_start",
                format!("Workspace of '{branch}' at {base_note}{lane_note} (sandbox: {sandbox})"),
            ),
            step("command_exec", format!("$ {command}")),
        ] {
            let seq = provenance_steps.len() as u64 + 1;
            provenance_steps.push(ProvenanceStep { seq, ..s });
        }
        let record = AgentSessionRecord {
            id: session_id.clone(),
            principal: identity.principal.canonical_id(),
            agent_profile: agent_profile.clone(),
            env: env_name.clone(),
            command: command.clone(),
            proxy_url: proxy_url.clone(),
            placeholders: placeholders.clone(),
            status: "running".to_owned(),
            exit_code: None,
            bytes_scrubbed: 0,
            started_at: Utc::now().to_rfc3339(),
            finished_at: None,
            output_lines,
            sandbox: sandbox.to_owned(),
            ended_reason: None,
            branch: branch.clone(),
            base_commit,
            changes: Vec::new(),
            changes_truncated: false,
            commit: None,
            discarded: false,
            skipped,
            skipped_truncated,
            budget: Some(tracker.snapshot()),
            review_round: steering_packet.as_ref().map(|p| p.target_round),
            lane_id,
            change_id,
            rebased: false,
            conflicts: Vec::new(),
            provenance_steps,
            insights: Vec::new(),
            limit_secs: limit.as_secs(),
            checkpoints,
            resumed_from,
        };
        self.upsert(record.clone());
        // Scrub against the unlocked repository vault as well as any defaults used by
        // the proxy. The inputs are zeroized when matcher construction finishes.
        redactor_pairs.extend(crate::store::load_vault_secrets_zeroizing(
            &workspace_root,
            &repo_id,
        ));
        let redactor = Arc::new(SecretRedactor::build(
            redactor_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        ));
        drop(redactor_pairs);
        if let Some(ref ts) = self.trace_store {
            let now = Utc::now();
            let cmd_str = record.command.clone();
            let profile_opt =
                (!record.agent_profile.is_empty()).then(|| record.agent_profile.clone());
            let mut trace_sess = premier_trace::TraceSession {
                session_id: record.id.clone(),
                started_at: now,
                updated_at: now,
                principal: record.principal.clone(),
                agent_profile: profile_opt.clone(),
                model: "premier-cage".to_owned(),
                tool_name: "premier-runner".to_owned(),
                branch: trace_branch,
                change_id: record.change_id.clone(),
                commit_oid: None,
                status: premier_trace::SessionStatus::Active,
                spans: vec![premier_trace::TraceSpan {
                    span_id: premier_trace::deterministic_id("sp_launch", &record.id),
                    timestamp: now,
                    kind: premier_trace::SpanKind::PromptTurn,
                    summary: format!("Launched caged agent session: {cmd_str}"),
                    command: Some(cmd_str),
                    tool_name: Some("premier-runner".to_owned()),
                    decision: Some(AuditDecision::Allowed),
                    actor_id: profile_opt.or_else(|| Some(record.principal.clone())),
                    actor_type: Some("agent".to_owned()),
                    correlation_id: Some(record.id.clone()),
                    status: Some("ok".to_owned()),
                    source: Some("premier-runner".to_owned()),
                    ..premier_trace::TraceSpan::default()
                }],
                delivery: premier_trace::DeliverySummary::default(),
            };
            for span in &mut trace_sess.spans {
                crate::traces::scrub_span(span, &redactor);
            }
            for label in [&mut trace_sess.branch, &mut trace_sess.principal]
                .into_iter()
                .chain(trace_sess.agent_profile.iter_mut())
                .chain(trace_sess.change_id.iter_mut())
            {
                crate::traces::scrub_text(label, &redactor);
            }
            let _ = ts.record_session(trace_sess);
        }
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<CancelKind>();
        if let Ok(mut cancel) = self.cancel.lock() {
            cancel.insert(session_id.clone(), cancel_tx);
        }
        if let Ok(mut live) = self.live.lock() {
            live.insert(
                session_id.clone(),
                LiveSession {
                    tracker: Arc::clone(&tracker),
                    pid: None,
                    cgroup: None,
                    principal: identity.principal.canonical_id(),
                },
            );
        }

        let mut ev = AuditEvent::now(
            &identity,
            "premier-cage",
            "session_started",
            AuditDecision::Allowed,
            format!("Started live caged session {session_id} (sandbox: {sandbox}): `{command}`"),
        );
        ev.target = Some(proxy_url.clone());
        crate::auth::audit(&audit_sink, ev);

        // The child starts from an empty environment: the allow-listed host variables, a
        // throwaway home, the proxy routes and placeholder tokens. Never the server's own.
        let prepare = || -> Result<(tokio::process::Command, SocketAddr), String> {
            Ok(match cage_user {
                Some(user) => {
                    let real = |p: &Path| {
                        p.canonicalize()
                            .map_err(|e| format!("{}: {e}", p.display()))
                    };
                    let hidden =
                        hidden_dirs(cage.hidden.iter().cloned().chain([workspace_root.clone()]));
                    let (workspace, proxy_dir) = (real(&workspace)?, real(&proxy_dir)?);
                    let plan = CagePlan {
                        workspace: &workspace,
                        proxy_dir: &proxy_dir,
                        exe: cage_exe(),
                        hidden: &hidden,
                        user,
                    };
                    let mut c = tokio::process::Command::from(cage_command_with_limits(
                        &plan,
                        &["sh", "-c", &command],
                        &resource_limits,
                    ));
                    c.env_clear().env("HOME", CAGE_HOME);
                    // Inside, the proxy is the relay on the sandbox's own loopback.
                    (c, CAGE_LISTEN)
                }
                None => {
                    let mut c = if cfg!(windows) {
                        let mut c = tokio::process::Command::new("powershell");
                        c.args(["-NoProfile", "-NonInteractive", "-Command", &command]);
                        c
                    } else {
                        let mut c = tokio::process::Command::new("sh");
                        c.args(["-c", &command]);
                        c
                    };
                    #[cfg(unix)]
                    {
                        // Own process group so killpg terminates any grandchildren on stop/timeout.
                        c.process_group(0);
                    }
                    c.current_dir(&workspace).env_clear();
                    for key in ["HOME", "USERPROFILE", "TEMP", "TMP"] {
                        c.env(key, &home);
                    }
                    apply_rlimits(&mut c, &resource_limits);
                    (c, proxy_addr)
                }
            })
        };
        let pre_cgroup = create_cgroup_v2(&session_id, &resource_limits).map(Arc::new);
        let spawned = if tracker.is_terminated() {
            Err("session terminated by offboarding before launch".to_owned())
        } else {
            prepare().and_then(|(mut cmd, agent_proxy)| {
                for key in ENV_PASSTHROUGH {
                    if let Some(value) = std::env::var_os(key) {
                        cmd.env(key, value);
                    }
                }
                let wiring = build_agent_env(
                    agent_proxy,
                    &proxy_handle.auth_token,
                    Some(&agent_ca_cert_path),
                    &registry,
                    &public_vars,
                );
                // The URL the agent uses carries the proxy's session token; the record's does not.
                cmd.env(
                    "PREMIER_PROXY_URL",
                    wiring.get("HTTP_PROXY").unwrap_or(&proxy_url),
                );
                cmd.envs(&wiring);
                cmd.env("PREMIER_SESSION_ID", &session_id);
                cmd.env("PREMIER_PRINCIPAL", identity.principal.canonical_id());
                cmd.env("PREMIER_AGENT_PROFILE", &agent_profile);
                if let Some(packet) = &steering_packet {
                    // Where the agent finds them: inside the sandbox, the proxy directory's mount.
                    let at = |name: &str| match cage_user {
                        Some(_) => OsString::from(format!("{CAGE_PROXY_DIR}/{name}")),
                        None => proxy_dir.join(name).into_os_string(),
                    };
                    cmd.env("PREMIER_STEERING_FILE", at(STEERING_JSON));
                    cmd.env("PREMIER_STEERING_MD", at(STEERING_MD));
                    cmd.env("PREMIER_TARGET_ROUND", packet.target_round.to_string());
                }
                if let Some(cid) = &record.change_id {
                    cmd.env("PREMIER_CHANGE_ID", cid);
                }
                if let Some(lane) = &record.lane_id {
                    cmd.env("PREMIER_LANE_ID", lane);
                }

                configure_process_group(&mut cmd);
                // So aborting the session task (`stop_all`) takes the process with it.
                cmd.kill_on_drop(true)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                cmd.spawn()
                    .map_err(|e| format!("failed to spawn caged command: {e}"))
            })
        };
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => {
                drop(pre_cgroup);
                if let Ok(mut cancel) = self.cancel.lock() {
                    cancel.remove(&session_id);
                }
                if let Ok(mut live) = self.live.lock() {
                    live.remove(&session_id);
                }
                // Nothing runs: close the session's proxy, its workspace and its record.
                proxy_handle.shutdown();
                let _ = std::fs::remove_dir_all(&dir);
                self.append_line(&session_id, format!("[error] {e}"), 0);
                self.update(&session_id, |rec| rec.discarded = true);
                let (status, reason) = if tracker.is_terminated() {
                    ("budget_exceeded", e.clone())
                } else {
                    ("failed", e.clone())
                };
                self.finish(&session_id, None, status, reason, &redactor);
                return Err(e);
            }
        };

        let pid = child.id();
        // Held until the child is gone; dropping it removes the cgroup.
        let cgroup = pre_cgroup.and_then(|cg| pid.is_some_and(|p| cg.attach_pid(p)).then_some(cg));
        let sandboxed = cage_user.is_some();
        // Windows has no `bwrap`: with `--allow-unsandboxed-agents` the process tree lives in a
        // Job Object (memory and process caps, killed with the guard). Held until the session ends.
        #[cfg(windows)]
        let job = if sandboxed {
            None
        } else {
            let attached = WindowsJobGuard::new(WindowsJobLimits::from(&resource_limits))
                .and_then(|job| job.attach_pid(pid.unwrap_or_default()).map(|()| job));
            match attached {
                Ok(job) => Some(job),
                Err(e) => {
                    self.append_line(
                        &session_id,
                        format!("[cage] warning: Windows Job Object not attached: {e}"),
                        0,
                    );
                    None
                }
            }
        };
        if let Ok(mut live) = self.live.lock()
            && let Some(entry) = live.get_mut(&session_id)
        {
            entry.pid = pid;
            entry.cgroup = cgroup.clone();
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let child_pid = child.id();
        let is_bwrap = cage_user.is_some();
        let mgr = Arc::clone(self);
        let sid_bg = session_id.clone();
        let identity_bg = identity.clone();
        let audit_bg = Arc::clone(&audit_sink);
        let base_commit_bg = record.base_commit.clone();

        // The session proxy's audit events become provenance steps while it runs.
        let (audit_stop, audit_stopped) = tokio::sync::oneshot::channel::<()>();
        let mut audit_listener = AbortOnDrop(tokio::spawn(record_proxy_steps(
            Arc::clone(self),
            session_id.clone(),
            audit_rx,
            audit_stopped,
            Arc::clone(&redactor),
        )));
        let tree_guard = ChildTreeGuard {
            pid: child_pid,
            is_bwrap,
            active: true,
        };

        let task = tokio::spawn(async move {
            let finish =
                |code, status, reason| mgr.finish(&sid_bg, code, status, reason, &redactor);
            let mut tree_guard = tree_guard;
            let started = std::time::Instant::now();
            let telemetry = Arc::new(Mutex::new(SessionTelemetryTracker::new(
                sid_bg.clone(),
                TelemetryConfig::default(),
            )));
            // This session's egress denials, for as long as the session task lives.
            let _audit_listener = {
                let (m, sid, tr) = (Arc::clone(&mgr), sid_bg.clone(), Arc::clone(&telemetry));
                let mut audit_rx = telemetry_rx;
                AbortOnDrop(tokio::spawn(async move {
                    loop {
                        match audit_rx.recv().await {
                            Ok(ev) if ev.agent_task_id.as_deref() == Some(sid.as_str()) => {
                                let insight = tr
                                    .lock()
                                    .ok()
                                    .and_then(|mut t| t.record_audit_event(&ev, ms_since(started)));
                                if let Some(insight) = insight {
                                    m.record_insight(insight);
                                }
                            }
                            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }))
            };
            let mut readers = Vec::new();
            if let Some(out) = stdout {
                readers.push(AbortOnDrop(tokio::spawn(read_stream_redacted(
                    out,
                    Arc::clone(&redactor),
                    Arc::clone(&mgr),
                    sid_bg.clone(),
                    "",
                    Arc::clone(&telemetry),
                    started,
                ))));
            }
            if let Some(err) = stderr {
                readers.push(AbortOnDrop(tokio::spawn(read_stream_redacted(
                    err,
                    Arc::clone(&redactor),
                    Arc::clone(&mgr),
                    sid_bg.clone(),
                    "[stderr] ",
                    Arc::clone(&telemetry),
                    started,
                ))));
            }

            // Until it exits, the owner stops it, its time is up, its workspace outgrows the hard
            // ceiling, or it breaches its autonomy budget (pause: wait for a human; terminate).
            let deadline = tokio::time::Instant::now() + limit;
            let mut cancel_active = true;
            let mut paused = false;
            let mut base_text: BaseText = HashMap::new();
            let mut last_sample = std::time::Instant::now();
            let end = loop {
                let limits = tracker.snapshot().limits;
                let workspace_budgeted = limits.max_files_modified.is_some()
                    || limits.max_lines_changed.is_some()
                    || limits.max_workspace_bytes.is_some();
                let scan_every = if workspace_budgeted {
                    BUDGET_CHECK_EVERY
                } else {
                    SIZE_CHECK_EVERY
                };
                tokio::select! {
                    done = child.wait() => break End::Exited(done),
                    res = &mut cancel_rx, if cancel_active => match res {
                        Ok(CancelKind::Stop) => {
                            break if tracker.is_terminated() {
                                End::Budget(breach_reason(&tracker))
                            } else {
                                End::Stopped
                            };
                        }
                        Ok(CancelKind::Pause) => break End::Paused,
                        Err(_) => cancel_active = false,
                    },
                    () = tokio::time::sleep_until(deadline) => break End::Timeout,
                    alert = alert_rx.recv() => {
                        let Ok(alert) = alert else { continue };
                        mgr.on_budget_alert(&sid_bg, &identity_bg, &audit_bg, &tracker, &alert);
                        if tracker.is_terminated() {
                            break End::Budget(alert.message);
                        }
                        if alert.action == BudgetAction::Pause && tracker.is_paused() && !paused {
                            match pause_session_tree(pid, cgroup.as_deref(), sandboxed) {
                                PauseOutcome::MustTerminate => {
                                    let msg = format!(
                                        "{} (sandboxed session tree cannot be frozen without cgroup v2; terminating)",
                                        alert.message
                                    );
                                    tracker.terminate(&msg);
                                    break End::Budget(msg);
                                }
                                PauseOutcome::Suspended | PauseOutcome::ProxyOnly => {
                                    paused = true;
                                    let snap = tracker.snapshot();
                                    mgr.update(&sid_bg, |rec| {
                                        rec.status = "paused".to_owned();
                                        rec.output_lines
                                            .push(format!("[cage] PAUSED: {}", alert.message));
                                        rec.budget = Some(snap);
                                    });
                                }
                            }
                        }
                    }
                    outcome = tracker.wait_resume_or_terminate(), if paused => {
                        paused = false;
                        if outcome == BudgetResumeOutcome::Terminated {
                            break End::Budget(breach_reason(&tracker));
                        }
                        resume_session_tree(pid, cgroup.as_deref());
                        let snap = tracker.snapshot();
                        mgr.update(&sid_bg, |rec| {
                            if rec.status == "paused" {
                                rec.status = "running".to_owned();
                                rec.output_lines
                                    .push("[cage] RESUMED: budget raised by owner".to_owned());
                            }
                            rec.budget = Some(snap);
                        });
                    }
                    () = tokio::time::sleep(scan_every) => {
                        let (root, sid, base) =
                            (workspace_root.clone(), sid_bg.clone(), base_commit_bg.clone());
                        let need_diff =
                            limits.max_files_modified.is_some() || limits.max_lines_changed.is_some();
                        let cache = std::mem::take(&mut base_text);
                        let ws = workspace.clone();
                        let scanned = tokio::task::spawn_blocking(move || {
                            let mut cache = cache;
                            let measured = workspace_usage(&ws, MAX_WORKSPACE_BYTES);
                            let usage = (!measured.over_budget).then(|| {
                                budget_usage(
                                    &root,
                                    &sid,
                                    base.as_deref(),
                                    need_diff,
                                    &mut cache,
                                    measured.bytes,
                                )
                            });
                            (measured, usage, cache)
                        })
                        .await;
                        let Ok((measured, usage, cache)) = scanned else { continue };
                        base_text = cache;
                        // Ambient telemetry samples the workspace every `SIZE_CHECK_EVERY`.
                        if last_sample.elapsed() >= SIZE_CHECK_EVERY {
                            last_sample = std::time::Instant::now();
                            let insights = telemetry
                                .lock()
                                .map(|mut t| {
                                    t.record_workspace_sample(
                                        measured,
                                        MAX_WORKSPACE_BYTES,
                                        MAX_WALK_FILES,
                                        started.elapsed().as_secs(),
                                        limit.as_secs(),
                                        ms_since(started),
                                    )
                                })
                                .unwrap_or_default();
                            for insight in insights {
                                mgr.record_insight(insight);
                            }
                        }
                        let Some((files, lines, bytes)) = usage else {
                            break End::SizeLimit;
                        };
                        // A breach arrives on `alert_rx` (next iteration).
                        let _ = tracker.update_workspace(files, lines, bytes);
                        let snap = tracker.snapshot();
                        mgr.set_budget_quiet(&sid_bg, snap);
                    }
                }
            };
            if let Ok(mut cancel) = mgr.cancel.lock() {
                cancel.remove(&sid_bg);
            }
            let clean_exit = matches!(end, End::Exited(Ok(_)));
            let drain_timeout = if clean_exit {
                tree_guard.active = false;
                std::time::Duration::from_millis(500)
            } else {
                // Thaw frozen cgroup tasks first so SIGKILL delivers promptly.
                if let Some(cg) = &cgroup {
                    cg.thaw();
                }
                kill_child_tree(child_pid, is_bwrap);
                #[cfg(windows)]
                if let Some(job) = &job {
                    let _ = job.terminate(1);
                }
                // A stopped (SIGSTOP) child still dies of SIGKILL.
                let _ = child.kill().await;
                tree_guard.active = false;
                std::time::Duration::from_millis(200)
            };
            let mut readers_timed_out = false;
            for mut reader in readers {
                if tokio::time::timeout(drain_timeout, &mut reader.0)
                    .await
                    .is_err()
                {
                    readers_timed_out = true;
                }
            }
            if readers_timed_out && clean_exit {
                // Backgrounded grandchildren held stdout/stderr open past drain timeout.
                kill_child_tree(child_pid, is_bwrap);
                #[cfg(windows)]
                if let Some(job) = &job {
                    let _ = job.terminate(1);
                }
            }
            if let Ok(mut live) = mgr.live.lock() {
                live.remove(&sid_bg);
            }
            drop(cgroup);
            // Closing the job kills anything of the session still alive on Windows.
            #[cfg(windows)]
            drop(job);
            proxy_handle.shutdown();
            // Whatever the proxy recorded up to now is taken, then the listener ends.
            let _ = audit_stop.send(());
            let _ = (&mut audit_listener.0).await;
            for scratch in [&proxy_dir, &home] {
                let _ = std::fs::remove_dir_all(scratch);
            }

            // What the session left behind, before anyone is told it has ended.
            let (root, sid) = (workspace_root.clone(), sid_bg.clone());
            let diff = tokio::task::spawn_blocking(move || session_changes(&root, &sid)).await;
            let snap = tracker.snapshot();
            mgr.update(&sid_bg, |rec| {
                if let Ok(Some(left)) = diff {
                    note_changes(rec, left);
                    let changed: Vec<ProvenanceStep> = rec
                        .changes
                        .iter()
                        .take(MAX_FILE_STEPS)
                        .map(|c| ProvenanceStep {
                            path: Some(c.path.clone()),
                            ..step(
                                "file_change",
                                format!("{} ({}, {} bytes)", c.path, c.kind, c.size),
                            )
                        })
                        .collect();
                    for s in changed {
                        push_step(rec, s);
                    }
                }
                rec.budget = Some(snap);
            });

            match end {
                End::Exited(Ok(status)) => {
                    let code = status.code();
                    let reason =
                        code.map_or_else(|| "killed".to_owned(), |c| format!("exit code {c}"));
                    let status = if status.success() {
                        "completed"
                    } else {
                        "failed"
                    };
                    finish(code, status, reason);
                }
                End::Exited(Err(e)) => {
                    mgr.append_line(&sid_bg, format!("[error] {e}"), 0);
                    finish(None, "failed", e.to_string());
                }
                End::Stopped => {
                    mgr.append_line(&sid_bg, "[cage] stopped by owner".to_owned(), 0);
                    finish(None, "stopped", "stopped by owner".to_owned());
                }
                End::Paused => {
                    mgr.append_line(&sid_bg, PAUSED_LINE.to_owned(), 0);
                    finish(None, "paused", PAUSED_REASON.to_owned());
                    let ev = AuditEvent::now(
                        &identity_bg,
                        "premier-cage",
                        "session_paused",
                        AuditDecision::Allowed,
                        format!("Paused session {sid_bg} for human step-in; workspace preserved"),
                    );
                    crate::auth::audit(&audit_bg, ev);
                }
                End::Timeout => {
                    mgr.append_line(
                        &sid_bg,
                        format!("[cage] killed: time limit of {}s reached", limit.as_secs()),
                        0,
                    );
                    finish(None, "timed_out", "timeout".to_owned());
                }
                End::SizeLimit => {
                    mgr.append_line(
                        &sid_bg,
                        format!("[cage] killed: workspace over {MAX_WORKSPACE_BYTES} bytes"),
                        0,
                    );
                    finish(None, "failed", "workspace size limit".to_owned());
                }
                End::Budget(reason) => {
                    mgr.append_line(&sid_bg, format!("[cage] TERMINATED: {reason}"), 0);
                    finish(None, "budget_exceeded", reason);
                }
            }
            if let (Some(hook), Some(done)) = (on_complete, mgr.get(&sid_bg)) {
                hook(done).await;
            }
        });
        if let Ok(mut running) = self.running.lock() {
            running.retain(|t| !t.is_finished());
            running.push(task);
        }

        Ok(record)
    }
}

/// Maximum bytes buffered per output line before flushing (prevents OOM from unbounded no-newline streams).
const MAX_OUTPUT_LINE_BYTES: usize = 64 * 1024;

/// Terminate a child process and any grandchildren it spawned.
fn kill_child_tree(pid: Option<u32>, is_bwrap: bool) {
    let Some(pid) = pid else {
        return;
    };
    #[cfg(unix)]
    if !is_bwrap {
        let _ = std::process::Command::new("kill")
            .args(["-9", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = is_bwrap;
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (pid, is_bwrap);
}

struct ChildTreeGuard {
    pid: Option<u32>,
    is_bwrap: bool,
    active: bool,
}

impl Drop for ChildTreeGuard {
    fn drop(&mut self) {
        if self.active {
            kill_child_tree(self.pid, self.is_bwrap);
        }
    }
}

/// Byte-bounded, lossy-UTF-8 streaming reader wired through `StreamingRedactor` so secrets split
/// across chunk boundaries are scrubbed and unbounded lines without `\n` cannot exhaust memory.
async fn read_stream_redacted<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    redactor: Arc<SecretRedactor>,
    mgr: Arc<SessionManager>,
    sid: String,
    prefix: &'static str,
    telemetry: Arc<Mutex<SessionTelemetryTracker>>,
    started: std::time::Instant,
) {
    let mut stream_red = redactor.streaming();
    let mut prev_scrubbed = 0usize;
    let mut line_buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8 * 1024];

    let emit_line = |buf: &mut Vec<u8>, scrubbed_delta: &mut usize| {
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        let text = String::from_utf8_lossy(buf);
        let formatted = if prefix.is_empty() {
            text.into_owned()
        } else {
            format!("{prefix}{text}")
        };
        let delta = std::mem::take(scrubbed_delta);
        let insight = telemetry
            .lock()
            .ok()
            .and_then(|mut t| t.record_output_line(&formatted, ms_since(started)));
        mgr.append_line(&sid, formatted, delta);
        if let Some(insight) = insight {
            mgr.record_insight(insight);
        }
        buf.clear();
    };

    let mut pending_scrubbed = 0usize;
    let mut feed = |bytes: &[u8], scrubbed_delta: usize| {
        pending_scrubbed += scrubbed_delta;
        for &b in bytes {
            if b == b'\n' {
                emit_line(&mut line_buf, &mut pending_scrubbed);
            } else {
                line_buf.push(b);
                if line_buf.len() >= MAX_OUTPUT_LINE_BYTES {
                    emit_line(&mut line_buf, &mut pending_scrubbed);
                }
            }
        }
    };

    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let safe = stream_red.push(&chunk[..n]);
                let now = stream_red.total_scrubbed();
                let delta = now.saturating_sub(prev_scrubbed);
                prev_scrubbed = now;
                feed(&safe, delta);
            }
        }
    }
    let tail = stream_red.finish();
    let now = stream_red.total_scrubbed();
    let delta = now.saturating_sub(prev_scrubbed);
    feed(&tail, delta);
    if !line_buf.is_empty() {
        emit_line(&mut line_buf, &mut pending_scrubbed);
    }
}

/// Per-session RAII guard serializing commits on the same session id.
struct CommitGuard {
    mgr: Arc<SessionManager>,
    id: String,
}

impl CommitGuard {
    fn acquire(mgr: &Arc<SessionManager>, id: &str) -> Result<Self, ApiErr> {
        let mut set = mgr
            .committing
            .lock()
            .map_err(|_| err_resp(StatusCode::INTERNAL_SERVER_ERROR, "session lock poisoned"))?;
        if !set.insert(id.to_owned()) {
            return Err(err_resp(
                StatusCode::CONFLICT,
                "a commit is already in progress for this session",
            ));
        }
        Ok(Self {
            mgr: Arc::clone(mgr),
            id: id.to_owned(),
        })
    }
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.mgr.committing.lock() {
            set.remove(&self.id);
        }
    }
}

/// Turn the audit events of session `sid`'s proxy into its provenance steps until `stop` fires
/// (or is dropped with the session task), then take what is still queued.
async fn record_proxy_steps(
    mgr: Arc<SessionManager>,
    sid: String,
    mut rx: broadcast::Receiver<AuditEvent>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    redactor: Arc<SecretRedactor>,
) {
    let note = |mut ev: AuditEvent| {
        if ev.component != "premier-proxy" || ev.agent_task_id.as_deref() != Some(sid.as_str()) {
            return;
        }
        let (kind, decision) = proxy_step_kind(ev.decision, ev.bytes_scrubbed);
        let scrubbed: usize = [&mut ev.reason, &mut ev.action, &mut ev.principal]
            .into_iter()
            .chain(ev.target.iter_mut())
            .chain(ev.capability.iter_mut())
            .chain(ev.agent_profile.iter_mut())
            .map(|field| crate::traces::scrub_text(field, &redactor))
            .sum();
        ev.bytes_scrubbed = ev.bytes_scrubbed.saturating_add(scrubbed);
        if let Some(ref ts) = mgr.trace_store {
            let _ = ts.record_proxy_audit_event(&sid, &ev);
        }
        mgr.append_step(
            &sid,
            kind,
            format!("{}: {}", ev.action, ev.reason),
            None,
            ev.target,
            Some(decision.to_owned()),
            None,
            ev.bytes_scrubbed,
        );
    };
    loop {
        tokio::select! {
            _ = &mut stop => break,
            got = rx.recv() => match got {
                Ok(ev) => note(ev),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
    while let Ok(ev) = rx.try_recv() {
        note(ev);
    }
}

/// The provenance step kind and decision name of a proxy audit event.
fn proxy_step_kind(decision: AuditDecision, scrubbed: usize) -> (&'static str, &'static str) {
    match decision {
        AuditDecision::Denied => ("egress_blocked", "denied"),
        AuditDecision::ExfiltrationBlocked => ("egress_blocked", "exfiltration_blocked"),
        AuditDecision::RateLimited => ("egress_blocked", "rate_limited"),
        AuditDecision::BudgetExceeded => ("egress_blocked", "budget_exceeded"),
        AuditDecision::ApprovalRequired => ("jit_approval", "approval_required"),
        AuditDecision::Redacted => ("egress_scrub", "redacted"),
        AuditDecision::Allowed if scrubbed > 0 => ("egress_scrub", "allowed"),
        AuditDecision::Allowed => ("egress_request", "allowed"),
    }
}

// ---------------------------------------------------------------------------
// Getting work out: diff, stop, commit, or discard a session's change set
// ---------------------------------------------------------------------------

type ApiErr = (StatusCode, Json<ApiError>);

/// Largest single file (256 KiB) for which `GET /v1/agents/sessions/{id}/diff` generates a patch.
const MAX_DIFF_FILE_BYTES: usize = 256 * 1024;
/// Total patch byte budget across all files in one `session_diff_handler` response (4 MiB).
const MAX_TOTAL_DIFF_BYTES: usize = 4 * 1024 * 1024;
/// Prefix scanned for NUL bytes to detect binary content (8 KiB).
const BINARY_SNIFF_BYTES: usize = 8 * 1024;
/// Context lines included around each unified-diff hunk.
const DIFF_CONTEXT_LINES: usize = 3;
/// Cap on Myers edit distance before falling back to a full replace hunk.
const MAX_MYERS_D: usize = 1024;

#[derive(Debug, Serialize)]
pub struct SessionDiffFile {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub binary: bool,
    pub truncated: bool,
    pub patch: String,
}

#[derive(Debug, Serialize)]
pub struct SessionDiffResponse {
    pub session_id: String,
    pub truncated: bool,
    pub files: Vec<SessionDiffFile>,
    /// Changed files left out because the viewer may not READ them on the session's branch.
    pub hidden_files: usize,
}

pub(crate) fn is_binary_bytes(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(BINARY_SNIFF_BYTES)].contains(&0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiffOp {
    Equal(usize, usize),
    Delete(usize),
    Insert(usize),
}

fn myers_diff(old: &[&str], new: &[&str]) -> Vec<DiffOp> {
    let mut prefix = 0;
    while prefix < old.len() && prefix < new.len() && old[prefix] == new[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < old.len() - prefix
        && suffix < new.len() - prefix
        && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let a = &old[prefix..old.len() - suffix];
    let b = &new[prefix..new.len() - suffix];
    let n = a.len();
    let m = b.len();

    let mut ops = Vec::with_capacity(old.len().max(new.len()));
    for i in 0..prefix {
        ops.push(DiffOp::Equal(i, i));
    }

    if n == 0 {
        for j in 0..m {
            ops.push(DiffOp::Insert(prefix + j));
        }
    } else if m == 0 {
        for i in 0..n {
            ops.push(DiffOp::Delete(prefix + i));
        }
    } else {
        let max_d = (n + m).min(MAX_MYERS_D);
        let offset = max_d as isize;
        let mut v = vec![0i32; 2 * max_d + 1];
        let mut trace: Vec<Vec<i32>> = Vec::new();
        let mut found_d: Option<usize> = None;

        'search: for d in 0..=max_d {
            let d_i = d as isize;
            let mut k = -d_i;
            while k <= d_i {
                let mut x = if d == 0 {
                    0
                } else if k == -d_i
                    || (k != d_i && v[(offset + k - 1) as usize] < v[(offset + k + 1) as usize])
                {
                    v[(offset + k + 1) as usize]
                } else {
                    v[(offset + k - 1) as usize] + 1
                };
                let mut y = x - k as i32;
                while x >= 0
                    && y >= 0
                    && (x as usize) < n
                    && (y as usize) < m
                    && a[x as usize] == b[y as usize]
                {
                    x += 1;
                    y += 1;
                }
                v[(offset + k) as usize] = x;
                if x == n as i32 && y == m as i32 {
                    found_d = Some(d);
                    break 'search;
                }
                k += 2;
            }
            trace.push(v[(max_d - d)..=(max_d + d)].to_vec());
        }

        if let Some(end_d) = found_d {
            let mut mid = Vec::new();
            let mut x = n as i32;
            let mut y = m as i32;
            for d in (1..=end_d).rev() {
                let prev = &trace[d - 1];
                let prev_off = (d - 1) as isize;
                let k = (x - y) as isize;
                let d_i = d as isize;
                let prev_k = if k == -d_i
                    || (k != d_i
                        && prev[(prev_off + k - 1) as usize] < prev[(prev_off + k + 1) as usize])
                {
                    k + 1
                } else {
                    k - 1
                };
                let prev_x = prev[(prev_off + prev_k) as usize];
                let prev_y = prev_x - prev_k as i32;
                while x > prev_x && y > prev_y {
                    x -= 1;
                    y -= 1;
                    mid.push(DiffOp::Equal(prefix + x as usize, prefix + y as usize));
                }
                if x == prev_x {
                    mid.push(DiffOp::Insert(prefix + prev_y as usize));
                } else {
                    mid.push(DiffOp::Delete(prefix + prev_x as usize));
                }
                x = prev_x;
                y = prev_y;
            }
            while x > 0 && y > 0 {
                x -= 1;
                y -= 1;
                mid.push(DiffOp::Equal(prefix + x as usize, prefix + y as usize));
            }
            mid.reverse();
            ops.extend(mid);
        } else {
            for i in 0..n {
                ops.push(DiffOp::Delete(prefix + i));
            }
            for j in 0..m {
                ops.push(DiffOp::Insert(prefix + j));
            }
        }
    }

    let old_tail = old.len() - suffix;
    let new_tail = new.len() - suffix;
    for s in 0..suffix {
        ops.push(DiffOp::Equal(old_tail + s, new_tail + s));
    }
    ops
}

pub(crate) fn unified_diff(path: &str, kind: &str, old_text: &str, new_text: &str) -> String {
    let (old_hdr, new_hdr) = match kind {
        "added" => ("--- /dev/null".to_owned(), format!("+++ b/{path}")),
        "deleted" => (format!("--- a/{path}"), "+++ /dev/null".to_owned()),
        _ => (format!("--- a/{path}"), format!("+++ b/{path}")),
    };
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    if kind == "added" || old_lines.is_empty() {
        let mut out = format!("{old_hdr}\n{new_hdr}\n");
        if !new_lines.is_empty() {
            out.push_str(&format!("@@ -0,0 +1,{} @@\n", new_lines.len()));
            for line in &new_lines {
                out.push('+');
                out.push_str(line);
                out.push('\n');
            }
        }
        return out;
    }
    if kind == "deleted" || new_lines.is_empty() {
        let mut out = format!("{old_hdr}\n{new_hdr}\n");
        if !old_lines.is_empty() {
            out.push_str(&format!("@@ -1,{} +0,0 @@\n", old_lines.len()));
            for line in &old_lines {
                out.push('-');
                out.push_str(line);
                out.push('\n');
            }
        }
        return out;
    }

    let ops = myers_diff(&old_lines, &new_lines);
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        if matches!(op, DiffOp::Equal(_, _)) {
            continue;
        }
        let start = idx.saturating_sub(DIFF_CONTEXT_LINES);
        let end = (idx + DIFF_CONTEXT_LINES + 1).min(ops.len());
        if let Some(last) = hunks.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            hunks.push((start, end));
        }
    }

    let mut out = format!("{old_hdr}\n{new_hdr}\n");
    for (start, end) in hunks {
        let slice = &ops[start..end];
        let old_count = slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_, _) | DiffOp::Delete(_)))
            .count();
        let new_count = slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_, _) | DiffOp::Insert(_)))
            .count();
        let old_start = slice
            .iter()
            .find_map(|op| match *op {
                DiffOp::Equal(o, _) | DiffOp::Delete(o) => Some(o + 1),
                DiffOp::Insert(_) => None,
            })
            .unwrap_or(0);
        let new_start = slice
            .iter()
            .find_map(|op| match *op {
                DiffOp::Equal(_, n) | DiffOp::Insert(n) => Some(n + 1),
                DiffOp::Delete(_) => None,
            })
            .unwrap_or(0);
        out.push_str(&format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        ));
        for op in slice {
            match *op {
                DiffOp::Equal(o, _) => {
                    out.push(' ');
                    out.push_str(old_lines[o]);
                    out.push('\n');
                }
                DiffOp::Delete(o) => {
                    out.push('-');
                    out.push_str(old_lines[o]);
                    out.push('\n');
                }
                DiffOp::Insert(n) => {
                    out.push('+');
                    out.push_str(new_lines[n]);
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// `GET /v1/agents/sessions/{id}/diff`: unified diffs for every file a finished session changed.
pub async fn session_diff_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SessionDiffResponse>, ApiErr> {
    let rec = ended_session(&state, &id)?;
    if rec.discarded {
        return Err(err_resp(
            StatusCode::GONE,
            "this session's workspace was discarded",
        ));
    }
    let Some(policy) = state.current_policy() else {
        return Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "no compiled policy loaded",
        ));
    };
    let session_identity = crate::directory::identity(
        &state,
        &rec.principal,
        Some(rec.agent_profile.clone()),
        "live-cage",
    )?;
    // Any owner may open any session, so each file is judged for the VIEWER (not only the
    // session's human) on the session's branch, as the file API does; unreadable ones are only
    // counted.
    let viewer = crate::caller_identity(&state, "session-diff")?;
    let branch = rec.branch.clone();
    let root = state.workspace_root.clone();
    let id_bg = id.clone();
    let base_commit = rec.base_commit.clone();

    enum DiffErr {
        Gone,
        Git(String),
    }

    let (files, truncated, hidden_files) = tokio::task::spawn_blocking(move || {
        let Some((changes, changes_truncated, _, _)) = session_changes(&root, &id_bg) else {
            return Err(DiffErr::Gone);
        };
        let mut out = Vec::with_capacity(changes.len());
        let mut total_patch_bytes = 0usize;
        let mut response_truncated = changes_truncated;
        let mut hidden_files = 0usize;
        for (change, new_bytes) in changes {
            // Re-verify READ policy on every changed path (session identity AND viewer) before
            // touching base or new bytes.
            let readable = [&session_identity, &viewer].into_iter().all(|identity| {
                crate::path_caps(Some(&*policy), identity, &change.path, &branch)
                    .contains(Capability::READ)
            });
            if !readable {
                hidden_files += 1;
                continue;
            }

            let mut base_oversized = false;
            let base_bytes = if change.kind == "added" {
                Vec::new()
            } else if let Some(base) = base_commit.as_deref() {
                let spec = format!("{base}:{}", change.path);
                let size_out = git_command(&root)
                    .args(["cat-file", "-s", &spec])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|e| DiffErr::Git(format!("failed to inspect base blob size: {e}")))?;
                if !size_out.status.success() {
                    return Err(DiffErr::Git(format!(
                        "git cat-file -s failed for '{}': {}",
                        change.path,
                        String::from_utf8_lossy(&size_out.stderr).trim()
                    )));
                }
                let base_size: usize = String::from_utf8_lossy(&size_out.stdout)
                    .trim()
                    .parse()
                    .map_err(|e| DiffErr::Git(format!("invalid base blob size: {e}")))?;
                if base_size > MAX_DIFF_FILE_BYTES {
                    base_oversized = true;
                    Vec::new()
                } else {
                    let blob_out = git_command(&root)
                        .args(["cat-file", "blob", &spec])
                        .stdin(Stdio::null())
                        .output()
                        .map_err(|e| DiffErr::Git(format!("failed to read base blob: {e}")))?;
                    if !blob_out.status.success() {
                        return Err(DiffErr::Git(format!(
                            "git cat-file blob failed for '{}': {}",
                            change.path,
                            String::from_utf8_lossy(&blob_out.stderr).trim()
                        )));
                    }
                    blob_out.stdout
                }
            } else {
                Vec::new()
            };

            let binary = !base_oversized
                && (is_binary_bytes(&base_bytes)
                    || new_bytes.as_deref().is_some_and(is_binary_bytes));
            let oversized = base_oversized
                || change.size > MAX_DIFF_FILE_BYTES as u64
                || base_bytes.len() > MAX_DIFF_FILE_BYTES
                || (change.kind != "deleted" && new_bytes.is_none())
                || new_bytes
                    .as_deref()
                    .is_some_and(|b| b.len() > MAX_DIFF_FILE_BYTES);

            let (file_binary, mut file_truncated, mut patch) = if binary {
                (true, false, String::new())
            } else if oversized {
                (false, true, String::new())
            } else {
                let old_text = String::from_utf8_lossy(&base_bytes);
                let new_text = new_bytes
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default();
                (
                    false,
                    false,
                    unified_diff(&change.path, &change.kind, &old_text, &new_text),
                )
            };

            if !patch.is_empty() {
                if total_patch_bytes.saturating_add(patch.len()) > MAX_TOTAL_DIFF_BYTES {
                    patch.clear();
                    file_truncated = true;
                    response_truncated = true;
                } else {
                    total_patch_bytes += patch.len();
                }
            }

            out.push(SessionDiffFile {
                path: change.path,
                kind: change.kind,
                size: change.size,
                binary: file_binary,
                truncated: file_truncated,
                patch,
            });
        }
        Ok((out, response_truncated, hidden_files))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        DiffErr::Gone => err_resp(StatusCode::GONE, "this session's workspace is gone"),
        DiffErr::Git(msg) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, msg),
    })?;

    Ok(Json(SessionDiffResponse {
        session_id: id,
        truncated,
        files,
        hidden_files,
    }))
}

/// `POST /v1/agents/sessions/{id}/stop`: kill a running session and wait briefly for it to end.
pub async fn stop_session_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<AgentSessionRecord>, ApiErr> {
    let rec = state
        .session_manager
        .get(&id)
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    if !is_live_rec(&rec) {
        return Err(err_resp(StatusCode::CONFLICT, "the session is not running"));
    }
    let tx = state
        .session_manager
        .cancel
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&id));
    if let Some(tx) = tx {
        let _ = tx.send(CancelKind::Stop);
    }
    for _ in 0..40 {
        if let Some(updated) = state.session_manager.get(&id)
            && !is_live_rec(&updated)
        {
            return Ok(Json(updated));
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let updated = state
        .session_manager
        .get(&id)
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    Ok(Json(updated))
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct CommitSessionRequest {
    /// Commit onto this branch instead of the one the session started from.
    #[serde(default)]
    pub branch: Option<String>,
    /// Create a new branch at the session's base commit and commit the session's changes there.
    #[serde(default)]
    pub new_branch: Option<String>,
    /// Visibility for `new_branch`; left out, inherited from the session's source branch.
    #[serde(default)]
    pub visibility: Option<Visibility>,
    /// Commit message; left out, `Agent session <id>`.
    #[serde(default)]
    pub message: Option<String>,
    /// An owner overriding the declassification firewall's blocking report: why, and the
    /// `report_digest` of the report they reviewed. Never lifts the instruction quarantine of an
    /// agent session.
    #[serde(default)]
    pub override_reason: Option<String>,
    #[serde(default)]
    pub override_ack_digest: Option<String>,
    /// When the branch moved since the session started, rebase three ways onto its tip (`true`,
    /// the default) or refuse (409).
    #[serde(default = "default_true")]
    pub auto_rebase: bool,
    /// The lane the work is kept on (`refs/premier-lanes/<lane_id>`); left out, the session's,
    /// else `lane-<session id>`.
    #[serde(default)]
    pub lane_id: Option<String>,
    /// The review this commit becomes the next round of; left out, the session's.
    #[serde(default)]
    pub change_id: Option<String>,
}

impl Default for CommitSessionRequest {
    fn default() -> Self {
        Self {
            branch: None,
            new_branch: None,
            visibility: None,
            message: None,
            override_reason: None,
            override_ack_digest: None,
            auto_rebase: true,
            lane_id: None,
            change_id: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CommitSessionResponse {
    pub commit: String,
    pub branch: String,
    pub rebased: bool,
    pub merged_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_round: Option<u32>,
}

/// What a review round made by a commit records besides the session: why it was run.
#[derive(Debug, Default)]
pub(crate) struct CommitReviewExtra {
    pub steering_prompt: Option<String>,
    pub addressed_comment_ids: Vec<String>,
}

/// Whether `id` may name a lane: one safe ref component (`refs/premier-lanes/<id>`).
pub(crate) fn valid_lane_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && !id.starts_with(['.', '-'])
        && !id.ends_with(".lock")
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A finished session of this repository the caller may act on.
fn ended_session(state: &ServerState, id: &str) -> Result<AgentSessionRecord, ApiErr> {
    let rec = state
        .session_manager
        .get(id)
        .filter(|s| crate::auth::caller_is_owner() || s.principal == crate::auth::actor_principal())
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    if is_live_rec(&rec) {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "the session is still running",
        ));
    }
    Ok(rec)
}

/// Insert or replace `lane` (keeping when it was created, its parent and its review).
fn save_lane(st: &mut PersistedState, mut lane: AgentLane) -> AgentLane {
    match st.lanes.iter_mut().find(|l| l.lane_id == lane.lane_id) {
        Some(old) => {
            lane.created_at = old.created_at.clone();
            lane.parent_lane_id = old.parent_lane_id.clone();
            if lane.change_id.is_none() {
                lane.change_id = old.change_id.clone();
            }
            *old = lane.clone();
        }
        None => st.lanes.push(lane.clone()),
    }
    lane
}

/// The provenance a review round records of the session that made it.
fn session_provenance(rec: &AgentSessionRecord, extra: &CommitReviewExtra) -> CapturedProvenance {
    CapturedProvenance {
        session_id: rec.id.clone(),
        principal: Some(rec.principal.clone()),
        agent_profile: rec.agent_profile.clone(),
        command: rec.command.clone(),
        prompt_summary: extra.steering_prompt.clone().unwrap_or_else(|| {
            format!("Caged session {} (its command is shown to owners)", rec.id)
        }),
        tool_calls: rec.output_lines.iter().take(8).cloned().collect(),
        created_at: rec.started_at.clone(),
        steps: rec.provenance_steps.clone(),
        sandbox: Some(rec.sandbox.clone()),
        bytes_scrubbed: rec.bytes_scrubbed,
        exit_code: rec.exit_code,
        egress_calls: 0,
        egress_blocked: 0,
    }
}

/// Make `commit` the next round of review `change_id` (linked to `lane_id`). `None` when there
/// is no such review; the round is `None` when `commit` already is its latest round.
fn append_round(
    st: &mut PersistedState,
    change_id: &str,
    commit: &str,
    base_commit: Option<String>,
    rec: &AgentSessionRecord,
    extra: &CommitReviewExtra,
    lane_id: Option<&str>,
) -> Option<(ReviewEvent, Option<u32>)> {
    let rev = st.reviews.iter_mut().find(|r| r.change_id == change_id)?;
    if let Some(lane) = lane_id {
        rev.lane_id = Some(lane.to_owned());
    }
    let mut round = None;
    if rev.round_oids.last().map(String::as_str) != Some(commit) {
        rev.round_oids.push(commit.to_owned());
        let n = u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX);
        rev.rounds_meta.push(StoredRoundMeta {
            round: n,
            commit_oid: commit.to_owned(),
            base_commit,
            session_id: Some(rec.id.clone()),
            steering_prompt: extra.steering_prompt.clone(),
            addressed_comment_ids: extra.addressed_comment_ids.clone(),
            rebased_cleanly: true,
            conflicts: Vec::new(),
            provenance: Some(session_provenance(rec, extra)),
            created_at: Utc::now().to_rfc3339(),
        });
        for c in rev
            .comments
            .iter_mut()
            .filter(|c| extra.addressed_comment_ids.contains(&c.id))
        {
            c.addressed_in_round = Some(n);
        }
        round = Some(n);
    }
    let event = ReviewEvent {
        change_id: change_id.to_owned(),
        visibility: rev.visibility.clone(),
        kind: if round.is_some() {
            "round_added"
        } else {
            "lane_linked"
        }
        .to_owned(),
        latest_round: u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX),
        lane_id: rev.lane_id.clone(),
    };
    Some((event, round))
}

/// Where a session's commit went.
enum Landed {
    /// On the branch (three-way rebased onto its tip when it had moved).
    Clean {
        commit: String,
        rebased: bool,
        merged_paths: Vec<String>,
        base_tip: Option<String>,
    },
    /// Not on the branch: kept as a snapshot on the lane, with what needs deciding.
    Conflicts {
        lane_ref: String,
        snapshot_oid: String,
        conflicts: Vec<LaneConflict>,
    },
}

/// `POST /v1/agents/sessions/{id}/commit`: see [`commit_session_changes`].
pub async fn commit_session_handler(
    State(state): State<ServerState>,
    axum::Extension(user): axum::Extension<crate::auth::AuthUser>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<CommitSessionRequest>>,
) -> Result<Json<CommitSessionResponse>, ApiErr> {
    let req = body.map(|Json(req)| req).unwrap_or_default();
    commit_session_changes_as(&state, &id, req, CommitReviewExtra::default(), Some(&user))
        .await
        .map(Json)
}

/// The session's change set as ONE commit on the branch it started from (or on a newly created
/// `new_branch`), authored by the human. Every path needs WRITE for the SESSION identity
/// (`human ∩ agent profile`): what the agent profile may not change stays unchanged even when the
/// human could change it.
///
/// When the branch moved since the session started, the change set is rebased three ways onto
/// its tip (only the paths it changed are touched); with `auto_rebase: false` that is refused
/// instead. Overlapping changes are not landed: the change set is kept as a snapshot on the
/// session's lane, its workspace stays, and the answer is 409 with the conflicts.
pub(crate) async fn commit_session_changes(
    state: &ServerState,
    id: &str,
    req: CommitSessionRequest,
    extra: CommitReviewExtra,
) -> Result<CommitSessionResponse, ApiErr> {
    commit_session_changes_as(state, id, req, extra, None).await
}

/// [`commit_session_changes`] for a request made by `user`, who alone may override the
/// declassification firewall's blocking report (a steered session's auto-commit has no user).
pub(crate) async fn commit_session_changes_as(
    state: &ServerState,
    id: &str,
    req: CommitSessionRequest,
    extra: CommitReviewExtra,
    user: Option<&crate::auth::AuthUser>,
) -> Result<CommitSessionResponse, ApiErr> {
    use canon::CommitError;

    // Serialize commits per session to eliminate concurrent double-commit races.
    let _commit_guard = CommitGuard::acquire(&state.session_manager, id)?;
    let rec = ended_session(state, id)?;
    if rec.commit.is_some() {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "this session is already committed",
        ));
    }
    if rec.discarded {
        return Err(err_resp(
            StatusCode::GONE,
            "this session's workspace was discarded",
        ));
    }
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
        None => format!("Agent session {id}"),
    };
    let identity = crate::directory::identity(
        state,
        &rec.principal,
        Some(rec.agent_profile.clone()),
        "live-cage",
    )?;
    let root = state.workspace_root.clone();
    let default_ref = canon::default_ref(&root);
    let new_branch = req
        .new_branch
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned);
    let nonempty = |s: Option<String>| s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let change_id = nonempty(req.change_id.clone()).or_else(|| rec.change_id.clone());
    // A commit onto an existing branch always has a lane: where it goes if it cannot land.
    let lane_id = nonempty(req.lane_id.clone())
        .or_else(|| rec.lane_id.clone())
        .or_else(|| new_branch.is_none().then(|| format!("lane-{id}")));
    if let Some(lane) = &lane_id {
        if !valid_lane_id(lane) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "invalid lane id"));
        }
        let owner = state.persisted.lock().ok().and_then(|st| {
            st.lanes
                .iter()
                .find(|l| l.lane_id == *lane)
                .map(|l| l.owner.clone())
        });
        if owner.is_some_and(|o| o != rec.principal) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                format!("lane '{lane}' belongs to someone else"),
            ));
        }
    }
    // The review must be one this session's identity can see.
    if let Some(cid) = &change_id {
        let branch_of = state.persisted.lock().ok().and_then(|st| {
            st.reviews
                .iter()
                .find(|r| r.change_id == *cid)
                .map(|r| r.branch.clone())
        });
        let visible =
            branch_of.is_some_and(|b| crate::resolve_accessible_rev(state, &identity, &b).is_ok());
        if !visible {
            return Err(err_resp(StatusCode::NOT_FOUND, "review not found"));
        }
    }

    // Paths already on the base commit, hidden ones included (fail closed on git ls-tree error).
    let base_tree_paths: Vec<String> = match rec.base_commit.as_deref() {
        Some(tip) => {
            let listed = crate::repos::git_out(&root, &["ls-tree", "-r", "--name-only", "-z", tip])
                .ok_or_else(|| {
                    err_resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to inspect base commit tree",
                    )
                })?;
            listed
                .split('\0')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        }
        None => Vec::new(),
    };
    let existing_lower: HashSet<String> =
        base_tree_paths.iter().map(|p| p.to_lowercase()).collect();
    let policy = state.current_policy();

    let (branch, full_ref, new_branch_vis) = if let Some(ref name) = new_branch {
        if !crate::handlers_v1::valid_branch_name(&root, name) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "invalid branch name"));
        }
        let metadata = state.branch_metadata();
        let taken = ["refs/heads/", crate::PRIVATE_REF_PREFIX].iter().any(|ns| {
            let full = format!("{ns}{name}");
            metadata.contains_key(&full)
                || crate::handlers_v1::resolve_branch_oid(&root, &full).is_ok()
        });
        if taken {
            return Err(err_resp(StatusCode::CONFLICT, "branch already exists"));
        }
        let source_vis =
            crate::branch_full_ref(&root, &rec.branch).map(|full| state.ref_visibility(&full));
        if req.visibility == Some(Visibility::Public)
            && source_vis
                .as_ref()
                .is_some_and(|v| *v != Visibility::Public)
        {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "cannot commit a non-public session directly onto a new public branch; use Squash-Declassify publish",
            ));
        }
        // Ref-scoped path rules: creating `new_branch` at `base_commit` must not unlock hidden files.
        if rec.base_commit.is_some() {
            let pol = policy.as_deref().ok_or_else(|| {
                err_resp(StatusCode::SERVICE_UNAVAILABLE, "no compiled policy loaded")
            })?;
            let hidden = base_tree_paths
                .iter()
                .map(String::as_str)
                .filter(|p| !premier_git_bridge::path_is_projected(pol, &identity, &rec.branch, p));
            if premier_git_bridge::exposes_hidden_files(pol, &identity, name, hidden) {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "the new branch would expose files hidden on the session's source branch",
                ));
            }
        }
        let vis = req.visibility.clone().unwrap_or_else(|| {
            premier_git_bridge::new_branch_visibility(
                true,
                &identity.principal,
                source_vis.as_slice(),
            )
        });
        let full = if matches!(vis, Visibility::Public) {
            format!("refs/heads/{name}")
        } else {
            format!("{}{name}", crate::PRIVATE_REF_PREFIX)
        };
        (name.clone(), full, Some(vis))
    } else {
        let branch = req
            .branch
            .clone()
            .filter(|b| !b.trim().is_empty())
            .unwrap_or_else(|| rec.branch.clone());
        let full_ref = match crate::content_source(state, &identity, &branch)? {
            Some(full) if full.starts_with("refs/") => full,
            None if default_ref.is_some() => default_ref.clone().unwrap_or_default(),
            _ => return Err(err_resp(StatusCode::CONFLICT, "no branch to commit on")),
        };
        (branch, full_ref, None)
    };
    // Detached `HEAD`: any branch may become the default one, so every branch is treated as it.
    let on_default = default_ref.as_deref().is_none_or(|d| d == full_ref);

    let (root_bg, id_bg) = (root.clone(), id.to_owned());
    let (changes, truncated, _, _) =
        tokio::task::spawn_blocking(move || session_changes(&root_bg, &id_bg))
            .await
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| err_resp(StatusCode::GONE, "this session's workspace is gone"))?;
    if truncated {
        return Err(err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            "this session's change set is too large or has unusable paths: it cannot be committed",
        ));
    }
    if changes.is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "this session changed nothing",
        ));
    }

    let denied = |path: &str| {
        let mut ev = AuditEvent::now(
            &identity,
            "premier-server",
            "session_commit",
            AuditDecision::Denied,
            format!(
                "Denied WRITE on '{path}' for session {id} of {}",
                identity.principal
            ),
        );
        ev.target = Some(path.to_owned());
        crate::auth::audit(&state.audit_sink, ev);
        err_resp(
            StatusCode::FORBIDDEN,
            format!("policy denied WRITE on '{path}' for this session: nothing was committed"),
        )
    };

    let overlay_manifest = crate::overlay_manifest(state)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let overlay_guard = OverlayGuard::from_manifest(&overlay_manifest)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let is_owner = identity.matches_selector(&format!("group:{}", crate::directory::OWNERS_GROUP));
    let mut paths = Vec::with_capacity(changes.len());
    let mut written_paths = Vec::new();
    for (change, content) in &changes {
        let rp = RepoPath::new(&change.path)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
        if change
            .path
            .split('/')
            .any(premier_git_bridge::is_reserved_path_component)
        {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!("'{rp}' names a reserved component: nothing was committed"),
            ));
        }
        let on_disk = crate::working_tree_path(&root, &rp);
        let folded = on_disk.as_ref().map_or(&rp, |(_, canonical)| canonical);
        // Fail closed: require WRITE on BOTH the session's source branch and the target branch.
        let allowed = policy.as_deref().is_some_and(|pol| {
            let branches: &[&str] = if branch == rec.branch {
                &[branch.as_str()]
            } else {
                &[rec.branch.as_str(), branch.as_str()]
            };
            branches.iter().all(|b| {
                [&rp, folded]
                    .into_iter()
                    .all(|p| pol.explain(&identity, p, b).allows(Capability::WRITE))
            })
        }) && !(change.kind == "added"
            && existing_lower.contains(&change.path.to_lowercase()))
            && !crate::auth::is_internal_path(&root, rp.as_str())
            && !crate::auth::is_internal_path(&root, folded.as_str());
        // On the default branch `.access.toml` and `.env.schema` configure the server: owners
        // only, and only content the server can load (same rule as a push or a Studio edit).
        let config = if allowed && on_default && canon::CONFIG_FILES.contains(&rp.as_str()) {
            state.check_config_change(is_owner, rp.as_str(), content.as_deref())
        } else {
            Ok(())
        };
        if !allowed || config == Err(None) {
            return Err(denied(rp.as_str()));
        }
        if let Err(Some(why)) = config {
            return Err(err_resp(StatusCode::BAD_REQUEST, why));
        }
        if on_disk.is_none() || folded != &rp {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                format!(
                    "'{rp}' goes through a symbolic link or is another spelling of an existing path"
                ),
            ));
        }
        if content.is_some() {
            written_paths.push(rp.clone());
        }
        paths.push(rp);
    }

    // Structural OverlayGuard check: overlays may never be committed into repository history.
    if let Err(e) = overlay_guard.validate_public_paths(&written_paths) {
        let mut ev = AuditEvent::now(
            &identity,
            "premier-server",
            "session_commit",
            AuditDecision::Denied,
            format!("OverlayGuard blocked session {id} commit: {e}"),
        );
        ev.target = Some(full_ref.clone());
        crate::auth::audit(&state.audit_sink, ev);
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            format!("overlay guard blocked session commit: {e}"),
        ));
    }

    // The declassification firewall and the instruction quarantine over what the commit lands.
    if let Some(pol) = policy.as_deref() {
        let is_agent = !rec.agent_profile.is_empty() || identity.agent_task.is_some();
        let files: Vec<premier_policy::ScanTargetFile> = changes
            .iter()
            .map(|(change, content)| premier_policy::ScanTargetFile {
                path: change.path.clone(),
                content: content.clone().unwrap_or_default(),
                deleted: content.is_none(),
            })
            .collect();
        let visibility = new_branch_vis
            .clone()
            .unwrap_or_else(|| state.ref_visibility(&full_ref));
        let corpus_rev = rec
            .base_commit
            .clone()
            .or_else(|| canon::tip_of(&root, &full_ref));
        let report = crate::firewall::scan_change(
            state,
            pol,
            corpus_rev.as_deref(),
            &branch,
            &visibility,
            &files,
            &message,
            is_owner,
            is_agent,
        );
        if !report.passed {
            let agent_edited_instructions = is_agent
                && report
                    .findings
                    .iter()
                    .any(|f| f.blocking && f.rule_id == "quarantine.unauthorized_edit");
            let wants_override = req.override_reason.is_some() || req.override_ack_digest.is_some();
            if agent_edited_instructions || !wants_override {
                crate::firewall::record_firewall_audit(
                    &state.audit_sink,
                    &identity,
                    "session_commit",
                    &full_ref,
                    &report,
                );
                let (status, error) = if agent_edited_instructions {
                    (
                        StatusCode::FORBIDDEN,
                        "this agent session changed an instruction file: an agent may not, and no override lifts that; nothing was committed".to_owned(),
                    )
                } else {
                    (
                        StatusCode::CONFLICT,
                        format!(
                            "declassification firewall blocked this session ({}): nothing was committed",
                            premier_git_bridge::plural(report.blocking_count, "blocking finding")
                        ),
                    )
                };
                let body = ApiError {
                    error,
                    firewall: crate::FirewallRefusal::new(report, None),
                    ..ApiError::default()
                };
                return Err((status, Json(body)));
            }
            // The overriding human is the owner committing, not the session's agent identity.
            let Some(user) = user else {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "a firewall override needs the owner's own request: nothing was committed",
                ));
            };
            let me = crate::directory::identity(
                state,
                &crate::auth::actor_principal(),
                None,
                "session-commit",
            )?;
            crate::firewall::verify_and_record_override(
                state,
                user,
                &me,
                pol,
                "session_commit",
                &full_ref,
                &report,
                req.override_reason.as_deref(),
                req.override_ack_digest.as_deref(),
            )?;
        }
    }

    enum SessionCommitErr {
        BranchExists,
        Commit(CommitError),
        /// An "added" path is a file the session may not read (or write) at the branch's tip.
        Hidden(String),
    }

    let who = canon::committer(state);
    let author_line = format!(
        "{} <{}> {} +0000",
        who.0.replace(['<', '>', '\n', '\r'], ""),
        who.1,
        Utc::now().timestamp()
    );
    let lane_ref = lane_id.as_ref().map(|l| format!("{LANE_REF_PREFIX}{l}"));
    let (state_bg, full_bg, base) = (state.clone(), full_ref.clone(), rec.base_commit.clone());
    let new_branch_bg = new_branch.clone();
    let (lane_ref_bg, branch_bg, identity_bg, id_bg) = (
        lane_ref.clone(),
        branch.clone(),
        identity.clone(),
        id.to_owned(),
    );
    let auto_rebase = req.auto_rebase;
    let landed = tokio::task::spawn_blocking(move || {
        let canonical = CanonicalGitRepo::open(&root);
        let keep_on_lane = |commit: &str| {
            if let Some(lane_ref) = &lane_ref_bg
                && let Err(e) = canonical.update_ref(lane_ref, commit)
            {
                tracing::warn!(error = %e, lane = %lane_ref, "could not move the lane ref");
            }
        };
        if let Some(ref name) = new_branch_bg {
            let before = on_default
                .then(|| canon::DefaultTip::capture(&root))
                .flatten();
            // `DefaultTip::capture` already holds `canon::ref_lock(&root)`; take it only if not held.
            let _lock = before.is_none().then(|| canon::ref_lock(&root));
            let taken_now = ["refs/heads/", crate::PRIVATE_REF_PREFIX].iter().any(|ns| {
                let full = format!("{ns}{name}");
                crate::handlers_v1::resolve_branch_oid(&root, &full).is_ok()
            });
            if taken_now {
                return Err(SessionCommitErr::BranchExists);
            }
            let mut created_ref_at_base = false;
            if let Some(base_oid) = base.as_deref() {
                canonical
                    .update_ref_cas(&full_bg, base_oid, &"0".repeat(40))
                    .map_err(|_| SessionCommitErr::BranchExists)?;
                created_ref_at_base = true;
            }
            let files: Vec<canon::FileChange<'_>> = paths
                .iter()
                .zip(&changes)
                .map(|(path, (change, content))| {
                    (path, content.as_deref(), Some(change.mode.as_str()))
                })
                .collect();
            let done =
                canon::commit_changes(&root, &full_bg, base.as_deref(), &files, &message, &who);
            if done.is_err()
                && created_ref_at_base
                && let Some(base_oid) = base.as_deref()
            {
                let _ = git_command(&root)
                    .args(["update-ref", "-d", &full_bg, base_oid])
                    .output();
            }
            if let Ok(commit) = &done {
                keep_on_lane(commit);
            }
            // Persist branch metadata under `canon::ref_lock`; roll back the new ref on failure.
            if let (Ok(new_oid), Some(vis)) = (&done, new_branch_vis) {
                let saved = state_bg
                    .persisted
                    .lock()
                    .map_err(|_| "persisted state lock poisoned".to_owned())
                    .and_then(|mut st| {
                        st.branch_metadata
                            .insert(full_bg.clone(), (vis, premier_core::Readiness::Wip));
                        let res = crate::store::save_state(&root, &st);
                        if res.is_err() {
                            st.branch_metadata.remove(&full_bg);
                        }
                        res
                    });
                if let Err(err) = saved {
                    let _ = git_command(&root)
                        .args(["update-ref", "-d", &full_bg, new_oid])
                        .output();
                    return Err(SessionCommitErr::Commit(CommitError::Internal(err)));
                }
            }
            state_bg.default_branch_moved(before);
            let commit = done.map_err(SessionCommitErr::Commit)?;
            return Ok(Landed::Clean {
                commit,
                rebased: false,
                merged_paths: Vec::new(),
                base_tip: base,
            });
        }

        let lane_changes: Vec<LaneFileChange> = changes
            .iter()
            .map(|(change, content)| LaneFileChange {
                path: change.path.clone(),
                new_content: content.clone().map(|bytes| (change.mode.clone(), bytes)),
            })
            .collect();
        for _attempt in 0..3 {
            let before = on_default
                .then(|| canon::DefaultTip::capture(&root))
                .flatten();
            let _lock = before.is_none().then(|| canon::ref_lock(&root));
            let target_tip = canon::tip_of(&root, &full_bg);
            // Strict compare-and-swap: also how a session from before the first commit is refused
            // once there is one.
            if target_tip != base && !auto_rebase {
                return Err(SessionCommitErr::Commit(CommitError::Moved));
            }
            // A file added on the branch while the session ran: the session may only collide
            // with it (and see it in a conflict) if it may read and write it.
            if target_tip != base
                && let Some(tip) = target_tip.as_deref()
            {
                let there: HashSet<String> =
                    crate::repos::git_out(&root, &["ls-tree", "-r", "--name-only", "-z", tip])
                        .ok_or_else(|| {
                            SessionCommitErr::Commit(CommitError::Internal(
                                "the branch's tree could not be listed".to_owned(),
                            ))
                        })?
                        .split('\0')
                        .map(str::to_owned)
                        .collect();
                for (change, _) in changes
                    .iter()
                    .filter(|(c, _)| c.kind == "added" && there.contains(&c.path))
                {
                    let may = RepoPath::new(&change.path).is_ok_and(|rp| {
                        policy.as_deref().is_some_and(|pol| {
                            let d = pol.explain(&identity_bg, &rp, &branch_bg);
                            d.allows(Capability::READ) && d.allows(Capability::WRITE)
                        })
                    });
                    if !may {
                        return Err(SessionCommitErr::Hidden(change.path.clone()));
                    }
                }
            }
            let check = |new_oid: &str| -> Result<(), String> {
                if on_default {
                    state_bg.check_config_commit(is_owner, target_tip.as_deref(), new_oid)
                } else {
                    Ok(())
                }
            };
            let res = premier_git_bridge::execute_three_way_rebase(
                &canonical,
                base.as_deref(),
                &full_bg,
                target_tip.as_deref(),
                &lane_changes,
                &message,
                &author_line,
                Some(&check),
            );
            match res {
                Ok(Ok(applied)) => {
                    keep_on_lane(&applied.commit_oid);
                    state_bg.default_branch_moved(before);
                    return Ok(Landed::Clean {
                        commit: applied.commit_oid,
                        rebased: applied.rebased,
                        merged_paths: applied.merged_paths,
                        base_tip: target_tip,
                    });
                }
                Ok(Err(conflicts)) => {
                    // The branch did not move; the work is kept on the lane.
                    drop(before);
                    let lane_ref = lane_ref_bg.clone().ok_or_else(|| {
                        SessionCommitErr::Commit(CommitError::Internal("no lane".to_owned()))
                    })?;
                    let snapshot_oid = premier_git_bridge::create_lane_snapshot_commit(
                        &canonical,
                        &lane_ref,
                        base.as_deref(),
                        &lane_changes,
                        &format!("Lane snapshot for {id_bg}: {message}"),
                        &author_line,
                    )
                    .map_err(|e| SessionCommitErr::Commit(CommitError::Internal(e.to_string())))?;
                    return Ok(Landed::Conflicts {
                        lane_ref,
                        snapshot_oid,
                        conflicts,
                    });
                }
                Err(GitBridgeError::RefMoved) => continue,
                Err(GitBridgeError::Rejected(why)) => {
                    return Err(SessionCommitErr::Commit(CommitError::Invalid(why)));
                }
                Err(e) => {
                    return Err(SessionCommitErr::Commit(CommitError::Internal(
                        e.to_string(),
                    )));
                }
            }
        }
        Err(SessionCommitErr::Commit(CommitError::Moved))
    })
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| match e {
        SessionCommitErr::BranchExists => err_resp(StatusCode::CONFLICT, "branch already exists"),
        SessionCommitErr::Hidden(path) => denied(&path),
        SessionCommitErr::Commit(CommitError::Moved) => err_resp(
            StatusCode::CONFLICT,
            format!(
                "'{branch}' has moved since this session started: its changes were not applied"
            ),
        ),
        SessionCommitErr::Commit(CommitError::Invalid(why)) => {
            err_resp(StatusCode::BAD_REQUEST, why)
        }
        SessionCommitErr::Commit(CommitError::Internal(why)) => {
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, why)
        }
    })?;

    let visibility = state.ref_visibility(&full_ref);
    let now = Utc::now().to_rfc3339();
    let lane_for = |status: &str, base_commit: Option<String>, tip: &str, conflicts| {
        lane_id.as_ref().map(|lane| AgentLane {
            lane_id: lane.clone(),
            lane_ref: format!("{LANE_REF_PREFIX}{lane}"),
            base_branch: branch.clone(),
            parent_lane_id: None,
            change_id: change_id.clone(),
            base_commit,
            tip_oid: Some(tip.to_owned()),
            owner: rec.principal.clone(),
            agent_profile: rec.agent_profile.clone(),
            visibility: visibility.clone(),
            status: status.to_owned(),
            conflicts,
            last_session_id: Some(id.to_owned()),
            created_at: now.clone(),
            updated_at: now.clone(),
        })
    };

    match landed {
        Landed::Clean {
            commit,
            rebased,
            merged_paths,
            base_tip,
        } => {
            let status = if rebased { "rebased" } else { "active" };
            let mut lane = lane_for(status, base_tip.clone(), &commit, Vec::new());
            let mut review = None;
            if let Ok(mut st) = state.persisted.lock() {
                lane = lane.map(|l| save_lane(&mut st, l));
                if let Some(cid) = &change_id {
                    review = append_round(
                        &mut st,
                        cid,
                        &commit,
                        base_tip.clone(),
                        &rec,
                        &extra,
                        lane_id.as_deref(),
                    );
                }
                let _ = crate::store::save_state(&state.workspace_root, &st);
            }
            let round = review.as_ref().and_then(|(_, round)| *round);
            if let Some(lane) = lane {
                let _ = state.lane_tx.send(lane);
            }
            if let Some((event, _)) = review {
                let _ = state.review_tx.send(event);
            }
            let short = |oid: &str| oid[..oid.len().min(12)].to_owned();
            let updated_rec = state.session_manager.update(id, |r| {
                r.commit = Some(commit.clone());
                r.branch = branch.clone();
                r.lane_id = lane_id.clone();
                r.change_id = change_id.clone();
                r.rebased = rebased;
                if round.is_some() {
                    r.review_round = round;
                }
                r.conflicts.clear();
                if rebased {
                    let onto = base_tip.as_deref().map(short).unwrap_or_default();
                    let merged = if merged_paths.is_empty() {
                        String::new()
                    } else {
                        format!("; merged {}", merged_paths.join(", "))
                    };
                    push_step(
                        r,
                        step(
                            "auto_rebase",
                            format!("Rebased onto '{branch}' at {onto}{merged}"),
                        ),
                    );
                }
                if let (Some(n), Some(cid)) = (round, &change_id) {
                    push_step(
                        r,
                        step(
                            "round_commit",
                            format!("Round {n} of review {cid}: {}", short(&commit)),
                        ),
                    );
                }
            });
            if let (Some(cid), Some(n), Some(rec_after)) = (&change_id, round, updated_rec)
                && let Ok(mut st) = state.persisted.lock()
                && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == *cid)
                && let Some(meta) = rev.rounds_meta.iter_mut().find(|m| m.round == n)
            {
                if let Some(prov) = meta.provenance.as_mut() {
                    prov.steps = rec_after.provenance_steps;
                }
                let _ = crate::store::save_state(&state.workspace_root, &st);
            }
            cleanup_session_workspace(&state.workspace_root, id);
            let mut ev = AuditEvent::now(
                &identity,
                "premier-server",
                "session_commit",
                AuditDecision::Allowed,
                format!(
                    "Committed session {id} on '{branch}' as {}{}",
                    short(&commit),
                    if rebased { " (rebased)" } else { "" }
                ),
            );
            ev.target = Some(full_ref);
            crate::auth::audit(&state.audit_sink, ev);
            Ok(CommitSessionResponse {
                commit,
                branch,
                rebased,
                merged_paths,
                lane_id,
                lane_ref,
                review_round: round,
            })
        }
        Landed::Conflicts {
            lane_ref,
            snapshot_oid,
            conflicts,
        } => {
            let lane_name = lane_id.clone().unwrap_or_default();
            let lane = lane_for(
                "conflicted",
                rec.base_commit.clone(),
                &snapshot_oid,
                conflicts.clone(),
            );
            let mut review = None;
            if let Ok(mut st) = state.persisted.lock() {
                let lane = lane.map(|l| save_lane(&mut st, l));
                if let Some(cid) = &change_id
                    && let Some(rev) = st.reviews.iter_mut().find(|r| r.change_id == *cid)
                {
                    rev.lane_id = Some(lane_name.clone());
                    review = Some(ReviewEvent {
                        change_id: cid.clone(),
                        visibility: rev.visibility.clone(),
                        kind: "lane_conflicted".to_owned(),
                        latest_round: u32::try_from(rev.round_oids.len()).unwrap_or(u32::MAX),
                        lane_id: Some(lane_name.clone()),
                    });
                }
                let _ = crate::store::save_state(&state.workspace_root, &st);
                if let Some(lane) = lane {
                    let _ = state.lane_tx.send(lane);
                }
            }
            if let Some(event) = review {
                let _ = state.review_tx.send(event);
            }
            let paths: Vec<String> = conflicts.iter().map(|c| c.path.clone()).collect();
            state.session_manager.update(id, |r| {
                r.lane_id = lane_id.clone();
                r.change_id = change_id.clone();
                r.conflicts = conflicts.clone();
                push_step(
                    r,
                    ProvenanceStep {
                        target: Some(lane_ref.clone()),
                        ..step(
                            "lane_conflict",
                            format!(
                                "Could not rebase onto '{branch}': {} kept on lane {lane_name}",
                                paths.join(", ")
                            ),
                        )
                    },
                );
            });
            let mut ev = AuditEvent::now(
                &identity,
                "premier-server",
                "session_lane_conflict",
                AuditDecision::Allowed,
                format!(
                    "Session {id} conflicts with '{branch}' on {}: kept on lane {lane_name}",
                    premier_git_bridge::plural(paths.len(), "path")
                ),
            );
            ev.target = Some(lane_ref.clone());
            crate::auth::audit(&state.audit_sink, ev);
            Err((
                StatusCode::CONFLICT,
                Json(ApiError {
                    error: format!(
                        "overlapping conflict while auto-rebasing onto '{branch}'; changes preserved on lane '{lane_name}'"
                    ),
                    conflicts: paths,
                    lane: Some(Box::new(crate::LaneErrorInfo {
                        lane_id: lane_name,
                        lane_ref,
                        lane_tip: snapshot_oid,
                        lane_conflicts: conflicts,
                    })),
                    ..ApiError::default()
                }),
            ))
        }
    }
}

/// `DELETE /v1/agents/sessions/{id}`: throw a finished session's workspace away.
pub async fn discard_session_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<AgentSessionRecord>, ApiErr> {
    let rec = ended_session(&state, &id)?;
    let _ = std::fs::remove_dir_all(session_dir(&state.workspace_root, &rec.id));
    let rec = state
        .session_manager
        .update(&id, |rec| rec.discarded = rec.commit.is_none())
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    Ok(Json(rec))
}

// ---------------------------------------------------------------------------
// Human step-in: pause, inspect and edit the workspace, checkpoint, resume
// ---------------------------------------------------------------------------
//
// The server never runs git in a workspace an agent wrote to (its `.git/config` could name a
// program to run): every listing, read, edit, checkpoint and copy here is plain file system
// work, links never followed, `.git` and reserved names skipped, and every path checked
// against the SESSION identity (`human ∩ agent profile`), as its commit will be.

/// Largest file a human reads or writes through step-in (512 KiB).
const MAX_STEP_IN_FILE_BYTES: usize = 512 * 1024;
/// Most files one workspace listing returns.
const MAX_STEP_IN_FILES: usize = 2000;
const DEFAULT_CHECKPOINT_LABEL: &str = "Human step-in checkpoint";

/// A regular file with more than one hard link: another name the walk cannot see.
fn aliased(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.is_file() && meta.nlink() > 1
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

/// `rp` inside session workspace `ws_root`: the absolute path to open and the repository path
/// it really is on disk (they differ where the file system folds names). `None` for the root,
/// a reserved component (`.git`, `.premier`, ...), a symbolic link anywhere on the way, or a
/// result outside the workspace.
pub(crate) fn safe_session_workspace_path(
    ws_root: &Path,
    rp: &RepoPath,
) -> Option<(PathBuf, RepoPath)> {
    if rp.is_root()
        || rp
            .segments()
            .into_iter()
            .any(premier_git_bridge::is_reserved_path_component)
    {
        return None;
    }
    crate::working_tree_path(ws_root, rp)
}

/// A session of this repository a human may step into: ended (not running), not committed,
/// workspace still there. Owners only.
fn require_step_in_session(state: &ServerState, id: &str) -> Result<AgentSessionRecord, ApiErr> {
    crate::auth::owner_only()?;
    let rec = state
        .session_manager
        .get(id)
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    if is_live_rec(&rec) {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "the session is still running: pause it first",
        ));
    }
    if rec.commit.is_some() {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "this session is already committed",
        ));
    }
    if rec.discarded || !session_dir(&state.workspace_root, id).join("ws").is_dir() {
        return Err(err_resp(
            StatusCode::GONE,
            "this session's workspace is gone",
        ));
    }
    Ok(rec)
}

/// The identity session `rec` ran as, exactly as its commit is checked.
fn session_identity(
    state: &ServerState,
    rec: &AgentSessionRecord,
) -> Result<DelegatedIdentity, ApiErr> {
    crate::directory::identity(
        state,
        &rec.principal,
        Some(rec.agent_profile.clone()),
        "live-cage",
    )
}

/// Fail closed: no compiled policy means no access.
fn session_may(
    policy: Option<&CompiledPolicy>,
    identity: &DelegatedIdentity,
    branch: &str,
    rp: &RepoPath,
    cap: Capability,
) -> bool {
    policy.is_some_and(|p| p.explain(identity, rp, branch).allows(cap))
}

fn step_in_audit(
    state: &ServerState,
    identity: &DelegatedIdentity,
    action: &str,
    decision: AuditDecision,
    reason: String,
    target: Option<String>,
) {
    let mut ev = AuditEvent::now(identity, "premier-server", action, decision, reason);
    ev.target = target;
    crate::auth::audit(&state.audit_sink, ev);
}

/// Request path `raw` in session `id`'s workspace: the file to open and its repository path.
/// 400 for anything that is not a plain file path of the workspace under its own spelling.
fn step_in_path(state: &ServerState, id: &str, raw: &str) -> Result<(PathBuf, RepoPath), ApiErr> {
    let rp = RepoPath::new(raw).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    if rp.is_root()
        || rp
            .segments()
            .into_iter()
            .any(premier_git_bridge::is_reserved_path_component)
        || crate::auth::is_internal_path(&state.workspace_root, rp.as_str())
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("'{raw}' is not a workspace file path"),
        ));
    }
    let ws = session_dir(&state.workspace_root, id).join("ws");
    match safe_session_workspace_path(&ws, &rp) {
        Some((abs, folded)) if folded == rp => Ok((abs, rp)),
        _ => Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!(
                "'{rp}' goes through a symbolic link, leaves the workspace, or is another spelling of an existing path"
            ),
        )),
    }
}

fn internal(e: impl std::fmt::Display) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Recompute the change set of session `id` (its workspace changed) onto its record.
async fn refresh_changes(state: &ServerState, id: &str) -> Option<AgentSessionRecord> {
    let (root, sid) = (state.workspace_root.clone(), id.to_owned());
    let left = tokio::task::spawn_blocking(move || session_changes(&root, &sid))
        .await
        .ok()
        .flatten();
    state.session_manager.update(id, |rec| {
        if let Some(left) = left {
            note_changes(rec, left);
        }
    })
}

/// `POST /v1/agents/sessions/{id}/pause`: stop a running session but keep its workspace so a
/// human can step in (inspect, edit, checkpoint, resume). An ended session whose workspace is
/// still there becomes paused too.
pub async fn pause_session_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<AgentSessionRecord>, ApiErr> {
    crate::auth::owner_only()?;
    let mgr = &state.session_manager;
    let not_found = || err_resp(StatusCode::NOT_FOUND, "no such session");
    let rec = mgr.get(&id).ok_or_else(not_found)?;
    if is_live_rec(&rec) {
        let tx = mgr.cancel.lock().ok().and_then(|mut map| map.remove(&id));
        if let Some(tx) = tx {
            let _ = tx.send(CancelKind::Pause);
        }
        for _ in 0..40 {
            if let Some(updated) = mgr.get(&id)
                && !is_live_rec(&updated)
            {
                return Ok(Json(updated));
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        return mgr.get(&id).map(Json).ok_or_else(not_found);
    }
    if rec.status == "paused" {
        return Ok(Json(rec));
    }
    if rec.commit.is_some() {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "this session is already committed",
        ));
    }
    if rec.discarded || !session_dir(&state.workspace_root, &id).join("ws").is_dir() {
        return Err(err_resp(
            StatusCode::GONE,
            "this session's workspace is gone",
        ));
    }
    mgr.update(&id, |rec| {
        rec.status = "paused".to_owned();
        rec.ended_reason = Some(PAUSED_REASON.to_owned());
        rec.output_lines.push(PAUSED_LINE.to_owned());
    })
    .ok_or_else(not_found)?;
    let updated = refresh_changes(&state, &id).await.ok_or_else(not_found)?;
    if let Ok(identity) = session_identity(&state, &updated) {
        step_in_audit(
            &state,
            &identity,
            "session_paused",
            AuditDecision::Allowed,
            format!("Paused ended session {id} for human step-in"),
            None,
        );
    }
    Ok(Json(updated))
}

#[derive(Debug, Serialize)]
pub struct SessionWorkspaceFile {
    pub path: String,
    pub size: u64,
    pub can_write: bool,
    /// `added` / `modified` when the session changed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_kind: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionWorkspaceFilesResponse {
    pub session_id: String,
    pub branch: String,
    pub truncated: bool,
    pub files: Vec<SessionWorkspaceFile>,
}

/// The regular files of workspace `ws` (path, size), sorted: no `.git` or reserved name, no
/// link, no special file, no file with other names. `true` when the walk was cut short.
fn workspace_files(ws: &Path) -> (Vec<(String, u64)>, bool) {
    let mut out = Vec::new();
    let (mut walked, mut truncated) = (0usize, false);
    let mut dirs = vec![(ws.to_path_buf(), String::new())];
    'walk: while let Some((dir, prefix)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            truncated = true;
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            walked += 1;
            if walked > MAX_WALK_FILES {
                truncated = true;
                break 'walk;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if premier_git_bridge::is_reserved_path_component(name) {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                dirs.push((entry.path(), rel));
            } else if meta.is_file() && !aliased(&meta) && RepoPath::new(&rel).is_ok() {
                out.push((rel, meta.len()));
            }
        }
    }
    out.sort();
    (out, truncated)
}

/// `GET /v1/agents/sessions/{id}/workspace/files`: the files of a paused session's workspace
/// its identity may read.
pub async fn session_workspace_files_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SessionWorkspaceFilesResponse>, ApiErr> {
    let rec = require_step_in_session(&state, &id)?;
    let identity = session_identity(&state, &rec)?;
    let policy = state.current_policy();
    let ws = session_dir(&state.workspace_root, &id).join("ws");
    let (found, mut truncated) = tokio::task::spawn_blocking(move || workspace_files(&ws))
        .await
        .map_err(internal)?;
    let kinds: HashMap<&str, &str> = rec
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind.as_str()))
        .collect();
    let mut files = Vec::new();
    for (path, size) in found {
        let Ok(rp) = RepoPath::new(&path) else {
            continue;
        };
        let may = |cap| session_may(policy.as_deref(), &identity, &rec.branch, &rp, cap);
        if crate::auth::is_internal_path(&state.workspace_root, rp.as_str())
            || !may(Capability::READ)
        {
            continue;
        }
        if files.len() >= MAX_STEP_IN_FILES {
            truncated = true;
            break;
        }
        let change_kind = kinds.get(path.as_str()).map(|k| (*k).to_owned());
        files.push(SessionWorkspaceFile {
            can_write: may(Capability::WRITE),
            change_kind,
            path,
            size,
        });
    }
    Ok(Json(SessionWorkspaceFilesResponse {
        session_id: id,
        branch: rec.branch.clone(),
        truncated,
        files,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SessionWorkspaceFileQuery {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct SessionWorkspaceFileContent {
    pub path: String,
    /// The text (empty for a binary file).
    pub content: String,
    pub size: u64,
    pub binary: bool,
    pub can_write: bool,
    pub sha256: String,
}

/// The bytes of regular file `abs`: never a link, a special file or a file with other names,
/// at most [`MAX_STEP_IN_FILE_BYTES`].
// shortcut: checked, then opened; the session is not running, so nothing swaps the file in
// between. Open with O_NOFOLLOW if step-in ever works on a live workspace.
fn read_step_in_file(abs: &Path) -> Result<Vec<u8>, ApiErr> {
    let meta = std::fs::symlink_metadata(abs)
        .map_err(|_| err_resp(StatusCode::NOT_FOUND, "no such file in this workspace"))?;
    if meta.file_type().is_symlink() || !meta.is_file() || aliased(&meta) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "not a regular file"));
    }
    let too_large = || {
        err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("files over {MAX_STEP_IN_FILE_BYTES} bytes cannot be opened here"),
        )
    };
    if meta.len() > MAX_STEP_IN_FILE_BYTES as u64 {
        return Err(too_large());
    }
    let bytes = std::fs::read(abs).map_err(internal)?;
    if bytes.len() > MAX_STEP_IN_FILE_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

/// `GET /v1/agents/sessions/{id}/workspace/file?path=`: one file of a paused session's
/// workspace, if its identity may read it.
pub async fn session_workspace_read_file_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<SessionWorkspaceFileQuery>,
) -> Result<Json<SessionWorkspaceFileContent>, ApiErr> {
    let rec = require_step_in_session(&state, &id)?;
    let (abs, rp) = step_in_path(&state, &id, &q.path)?;
    let identity = session_identity(&state, &rec)?;
    let policy = state.current_policy();
    let may = |cap| session_may(policy.as_deref(), &identity, &rec.branch, &rp, cap);
    if !may(Capability::READ) {
        step_in_audit(
            &state,
            &identity,
            "session_workspace_read",
            AuditDecision::Denied,
            format!("Denied READ on '{rp}' in session {id}"),
            Some(rp.as_str().to_owned()),
        );
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            format!("policy denied READ on '{rp}' for this session"),
        ));
    }
    let bytes = read_step_in_file(&abs)?;
    let utf8 = std::str::from_utf8(&bytes).ok();
    let binary = is_binary_bytes(&bytes) || utf8.is_none();
    Ok(Json(SessionWorkspaceFileContent {
        path: rp.as_str().to_owned(),
        content: if binary {
            String::new()
        } else {
            utf8.unwrap_or_default().to_owned()
        },
        size: bytes.len() as u64,
        binary,
        can_write: may(Capability::WRITE),
        sha256: premier_policy::sha256_hex(&bytes),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SessionWorkspaceWriteRequest {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct SessionWorkspaceWriteResponse {
    pub path: String,
    pub bytes_written: u64,
    pub session: AgentSessionRecord,
}

/// Write `bytes` at `abs` (`rp` in workspace `ws`) through a new temp file in the same, checked
/// directory, renamed over the target only while the path still resolves to the same place.
fn write_step_in_file(ws: &Path, rp: &RepoPath, abs: &Path, bytes: &[u8]) -> Result<(), ApiErr> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let moved = || {
        err_resp(
            StatusCode::BAD_REQUEST,
            "the path changed while it was written",
        )
    };
    let old = std::fs::symlink_metadata(abs).ok();
    if let Some(meta) = &old {
        if meta.file_type().is_symlink() || !meta.is_file() || aliased(meta) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "not a regular file"));
        }
        if meta.len() > MAX_STEP_IN_FILE_BYTES as u64 {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                "cannot overwrite a binary or oversized file with text",
            ));
        }
        let existing = std::fs::read(abs).map_err(internal)?;
        if is_binary_bytes(&existing) || std::str::from_utf8(&existing).is_err() {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                "cannot overwrite a binary or non-UTF-8 file with text",
            ));
        }
    }
    let parent = abs.parent().ok_or_else(moved)?;
    std::fs::create_dir_all(parent).map_err(internal)?;
    let same = || {
        safe_session_workspace_path(ws, rp).is_some_and(|(a, folded)| a == abs && &folded == rp)
            && std::fs::symlink_metadata(parent).is_ok_and(|m| m.is_dir())
    };
    if !same() {
        return Err(moved());
    }
    let tmp = parent.join(format!(
        ".premier-step-in-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        std::io::Write::write_all(&mut file, bytes)?;
        drop(file);
        if let Some(meta) = &old {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        if !same() {
            return Err(std::io::Error::other(
                "the path changed while it was written",
            ));
        }
        std::fs::rename(&tmp, abs)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(internal(format!("workspace write failed: {e}")));
    }
    Ok(())
}

/// `PUT /v1/agents/sessions/{id}/workspace/file`: a human edit in a paused session's
/// workspace. Needs WRITE for the session identity, exactly as committing it will.
pub async fn session_workspace_write_file_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<SessionWorkspaceWriteRequest>,
) -> Result<Json<SessionWorkspaceWriteResponse>, ApiErr> {
    let rec = require_step_in_session(&state, &id)?;
    if req.content.len() > MAX_STEP_IN_FILE_BYTES {
        return Err(err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("files over {MAX_STEP_IN_FILE_BYTES} bytes cannot be written here"),
        ));
    }
    let (abs, rp) = step_in_path(&state, &id, &req.path)?;
    let identity = session_identity(&state, &rec)?;
    let root = state.workspace_root.clone();
    let deny = |why: &str| {
        step_in_audit(
            &state,
            &identity,
            "session_workspace_edit",
            AuditDecision::Denied,
            format!("Denied WRITE on '{rp}' in session {id}: {why}"),
            Some(rp.as_str().to_owned()),
        );
        err_resp(
            StatusCode::FORBIDDEN,
            format!("policy denied WRITE on '{rp}' for this session: {why}"),
        )
    };
    let policy = state.current_policy();
    if !session_may(
        policy.as_deref(),
        &identity,
        &rec.branch,
        &rp,
        Capability::WRITE,
    ) {
        return Err(deny("not writable for the session identity"));
    }
    // A path the branch has that this session was never shown: writing it would replace a
    // file the session cannot see.
    let base: Base = std::fs::read_to_string(session_dir(&root, &id).join(BASE_FILE))
        .ok()
        .and_then(|b| serde_json::from_str(&b).ok())
        .unwrap_or_default();
    let hidden = !base.contains_key(rp.as_str())
        && rec
            .base_commit
            .as_deref()
            .and_then(|tip| {
                crate::repos::git_out(&root, &["ls-tree", "-r", "--name-only", "-z", tip])
            })
            .is_some_and(|out| out.split('\0').any(|p| p == rp.as_str()));
    if hidden {
        return Err(deny("a file the session cannot see is at that path"));
    }
    // On the default branch `.access.toml` and `.env.schema` configure the server: same rule as
    // a commit of the session.
    let default_ref = canon::default_ref(&root);
    let full_ref = crate::branch_full_ref(&root, &rec.branch);
    let on_default = default_ref
        .as_deref()
        .is_none_or(|d| full_ref.as_deref() == Some(d));
    if on_default && canon::CONFIG_FILES.contains(&rp.as_str()) {
        let is_owner =
            identity.matches_selector(&format!("group:{}", crate::directory::OWNERS_GROUP));
        match state.check_config_change(is_owner, rp.as_str(), Some(req.content.as_bytes())) {
            Ok(()) => {}
            Err(None) => return Err(deny("server configuration")),
            Err(Some(why)) => return Err(err_resp(StatusCode::BAD_REQUEST, why)),
        }
    }
    let ws = session_dir(&root, &id).join("ws");
    let bytes_written = req.content.len() as u64;
    let (rp_bg, abs_bg, content) = (rp.clone(), abs.clone(), req.content);
    tokio::task::spawn_blocking(move || {
        write_step_in_file(&ws, &rp_bg, &abs_bg, content.as_bytes())
    })
    .await
    .map_err(internal)??;
    let session = refresh_changes(&state, &id)
        .await
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    step_in_audit(
        &state,
        &identity,
        "session_workspace_edit",
        AuditDecision::Allowed,
        format!("Edited '{rp}' ({bytes_written} bytes) in paused session {id}"),
        Some(rp.as_str().to_owned()),
    );
    Ok(Json(SessionWorkspaceWriteResponse {
        path: rp.as_str().to_owned(),
        bytes_written,
        session,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct SessionCheckpointRequest {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionCheckpointResponse {
    pub checkpoint: SessionCheckpoint,
    pub session: AgentSessionRecord,
}

/// `POST /v1/agents/sessions/{id}/checkpoint`: record what a paused session's workspace holds
/// now (its change set) as a named checkpoint: a manifest beside the workspace, no git.
pub async fn checkpoint_session_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<SessionCheckpointRequest>>,
) -> Result<Json<SessionCheckpointResponse>, ApiErr> {
    let rec = require_step_in_session(&state, &id)?;
    let label = body
        .and_then(|Json(req)| req.label)
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| DEFAULT_CHECKPOINT_LABEL.to_owned());
    if label.chars().count() > 200 || label.chars().any(char::is_control) {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "invalid checkpoint label",
        ));
    }
    let identity = session_identity(&state, &rec)?;
    let (root, sid) = (state.workspace_root.clone(), id.clone());
    let left = tokio::task::spawn_blocking(move || session_changes(&root, &sid))
        .await
        .map_err(internal)?
        .ok_or_else(|| err_resp(StatusCode::GONE, "this session's workspace is gone"))?;
    let changes: Vec<&SessionChange> = left.0.iter().map(|(c, _)| c).collect();
    let dir = session_dir(&state.workspace_root, &id).join("checkpoints");
    std::fs::create_dir_all(&dir).map_err(internal)?;
    let mut next_num = rec
        .checkpoints
        .iter()
        .filter_map(|c| c.id.strip_prefix("cp-")?.parse::<usize>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    let created_at = Utc::now().to_rfc3339();
    let author = crate::auth::actor_principal();
    let edited_paths: Vec<String> = left.0.iter().map(|(c, _)| c.path.clone()).collect();
    let mut checkpoint = None;
    for _ in 0..10_000 {
        let cp_id = format!("cp-{next_num:03}");
        let path = dir.join(format!("{cp_id}.json"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let cp = SessionCheckpoint {
                    id: cp_id,
                    label: label.clone(),
                    created_at: created_at.clone(),
                    author: author.clone(),
                    edited_paths: edited_paths.clone(),
                };
                let manifest = serde_json::json!({
                    "session_id": id,
                    "checkpoint": &cp,
                    "changes": &changes,
                    "changes_truncated": left.1,
                });
                if let Err(e) =
                    std::io::Write::write_all(&mut file, manifest.to_string().as_bytes())
                {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(internal(e));
                }
                checkpoint = Some(cp);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                next_num += 1;
            }
            Err(e) => return Err(internal(e)),
        }
    }
    let checkpoint = checkpoint.ok_or_else(|| internal("too many checkpoints"))?;
    let line = format!(
        "[step-in] checkpoint {}: {} ({})",
        checkpoint.id,
        checkpoint.label,
        premier_git_bridge::plural(checkpoint.edited_paths.len(), "changed path")
    );
    let cp = checkpoint.clone();
    let session = state
        .session_manager
        .update(&id, move |rec| {
            note_changes(rec, left);
            rec.checkpoints.push(cp);
            rec.output_lines.push(line);
        })
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "no such session"))?;
    step_in_audit(
        &state,
        &identity,
        "session_checkpoint",
        AuditDecision::Allowed,
        format!(
            "Checkpoint {} of paused session {id}: {}",
            checkpoint.id, checkpoint.label
        ),
        None,
    );
    Ok(Json(SessionCheckpointResponse {
        checkpoint,
        session,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ResumeSessionRequest {
    pub command: String,
    /// Seconds the resumed session may run: default 30 minutes, at most 4 hours.
    #[serde(default)]
    pub max_secs: Option<u64>,
}

/// Copy paused workspace `from/ws` into `to/ws` with its `base.json`, as plain files: no
/// `.git` or reserved name, no special file or file with other names, a link only when its
/// target stays inside, every file READable by the session identity. The copy then gets a
/// fresh `.git` of the server's own (git runs only there, never in the agent-written tree).
fn copy_for_resume(
    from: &Path,
    to: &Path,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    branch: &str,
) -> Result<(), String> {
    let io = |e: std::io::Error| format!("session directory: {e}");
    let (src, dst) = (from.join("ws"), to.join("ws"));
    for d in [&dst, &to.join("proxy"), &to.join("home")] {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let readable = |rel: &str| {
        RepoPath::new(rel).is_ok_and(|rp| {
            policy
                .explain(identity, &rp, branch)
                .allows(Capability::READ)
        })
    };
    let (mut walked, mut bytes) = (0usize, 0u64);
    let mut dirs = vec![(src, dst.clone(), String::new())];
    while let Some((from_dir, to_dir, prefix)) = dirs.pop() {
        for entry in std::fs::read_dir(&from_dir).map_err(io)?.flatten() {
            walked += 1;
            if walked > MAX_WALK_FILES {
                return Err("the workspace has too many entries".to_owned());
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if premier_git_bridge::is_reserved_path_component(name) {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if RepoPath::new(&rel).is_err() {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let target = to_dir.join(name);
            let kind = meta.file_type();
            if kind.is_dir() {
                std::fs::create_dir(&target).map_err(io)?;
                dirs.push((entry.path(), target, rel));
            } else if kind.is_symlink() {
                let link = std::fs::read_link(entry.path())
                    .ok()
                    .and_then(|t| t.into_os_string().into_string().ok());
                if let Some(link) = link
                    && link_stays_inside(&rel, &link)
                    && readable(&rel)
                {
                    let _ = make_link(&link, &target);
                }
            } else if kind.is_file() && !aliased(&meta) && readable(&rel) {
                bytes = bytes.saturating_add(meta.len());
                if bytes > MAX_WORKSPACE_BYTES {
                    return Err("the workspace is over its size budget".to_owned());
                }
                std::fs::copy(entry.path(), &target).map_err(io)?;
            }
        }
    }
    std::fs::copy(from.join(BASE_FILE), to.join(BASE_FILE)).map_err(io)?;
    git_quiet(&dst, &["init", "-q", "-b", branch]).or_else(|_| git_quiet(&dst, &["init", "-q"]))?;
    git_quiet(&dst, &["add", "-A"])?;
    git_quiet(
        &dst,
        &["commit", "-q", "--allow-empty", "-m", "Session resumed"],
    )?;
    Ok(())
}

/// `POST /v1/agents/sessions/{id}/resume`: a NEW session that runs `command` on a copy of a
/// paused session's workspace (human edits included), as the same identity, from the same base:
/// committing it applies the agent's and the human's edits together.
pub async fn resume_session_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<ResumeSessionRequest>,
) -> Result<Json<AgentSessionRecord>, ApiErr> {
    let rec = require_step_in_session(&state, &id)?;
    let command = req.command.trim().to_owned();
    if command.is_empty() {
        return Err(err_resp(StatusCode::BAD_REQUEST, "a command is required"));
    }
    let mode = sandbox_mode(state.allow_unsandboxed_agents);
    let cage_user = cage_user_for(mode).map_err(|e| err_resp(StatusCode::NOT_IMPLEMENTED, e))?;
    let identity = session_identity(&state, &rec)?;
    let policy = state.current_policy().ok_or_else(|| {
        err_resp(
            StatusCode::FORBIDDEN,
            "no policy is loaded: nothing can be carried over",
        )
    })?;
    let cage = Cage {
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
    let mgr = Arc::clone(&state.session_manager);
    let session_id = mgr.next_session_id();
    let root = state.workspace_root.clone();
    let dir = session_dir(&root, &session_id);
    let copied = {
        let (from, to) = (session_dir(&root, &id), dir.clone());
        let (policy, identity, branch) =
            (Arc::clone(&policy), identity.clone(), rec.branch.clone());
        tokio::task::spawn_blocking(move || {
            copy_for_resume(&from, &to, &policy, &identity, &branch)
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r)
    };
    if let Err(e) = copied {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(internal(format!(
            "failed to prepare the resumed workspace: {e}"
        )));
    }
    let resumed = mgr
        .launch_in_workspace(Launch {
            session_id: session_id.clone(),
            dir,
            workspace_root: root,
            identity: identity.clone(),
            env_name: rec.env.clone(),
            command,
            branch: rec.branch.clone(),
            trace_branch: rec.branch.clone(),
            policy: Some(policy),
            schema: state.current_env_schema(),
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage,
            cage_user,
            limit: session_limit(
                req.max_secs
                    .filter(|&s| s > 0)
                    .or_else(|| (rec.limit_secs > 0).then_some(rec.limit_secs)),
            ),
            base_commit: rec.base_commit.clone(),
            skipped: rec.skipped.clone(),
            resumed_from: Some(id.clone()),
            checkpoints: rec.checkpoints.clone(),
            requested_budget: None,
            quarantined: Vec::new(),
            lane_id: rec.lane_id.clone(),
            change_id: rec.change_id.clone(),
            steering_packet: None,
            on_complete: None,
        })
        .await
        .map_err(internal)?;
    mgr.update(&id, |rec| {
        rec.output_lines
            .push(format!("[step-in] resumed as {session_id}"));
    });
    step_in_audit(
        &state,
        &identity,
        "session_resumed",
        AuditDecision::Allowed,
        format!("Resumed paused session {id} as {session_id}"),
        None,
    );
    Ok(Json(resumed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
