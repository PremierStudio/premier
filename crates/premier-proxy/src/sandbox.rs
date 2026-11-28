//! AI agent process launcher: allow-listed environment + proxy wiring everywhere, a Linux
//! `bwrap` sandbox (allow-listed read-only host dirs, private namespaces, key material masked)
//! where available, and a Windows Job Object (process-tree kill, memory and process caps; no
//! filesystem or network isolation) for opted-in unsandboxed agents.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use premier_secrets::{PlaceholderRegistry, SecretRedactor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::ProxyError;
use crate::proxy::{cap_base_url_for, proxy_url_for};

/// The only host environment variables an agent inherits. Everything else (cloud credentials,
/// tokens, `PREMIER_AGE_IDENTITY`, the raw values behind `--backend env`) is dropped: an
/// allow-list cannot miss a secret the way a deny-list of known prefixes does.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "TZ",
    "USER",
    "SHELL",
    "TMPDIR",
    // Windows processes do not start without these.
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "USERNAME",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "TEMP",
    "TMP",
];

/// Credential stores under `$HOME` hidden from a sandboxed agent.
const HOME_CREDENTIAL_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".config/premier",
    ".cargo/credentials.toml",
    ".pypirc",
    ".bash_history",
    ".zsh_history",
    ".netrc",
    ".npmrc",
    ".git-credentials",
];

/// ALL of the host a `bwrap` agent sees, read-only (those that exist). Mirrors the server cage's
/// allow-list: programs, libraries, loader config and CA certificates (never `/etc/ssl/private`),
/// and the `alternatives` links programs in `/usr/bin` resolve through. Nothing else of the host
/// is mounted, so a file the launching user can read is not readable by the agent.
const BWRAP_HOST_DIRS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/etc/ssl/certs",
    "/etc/ssl/openssl.cnf",
    "/etc/ca-certificates",
    "/etc/alternatives",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
];

/// Extra host files for the cooperative (`--share-net`) mode only: with a private network
/// namespace there is no DNS in the sandbox and they would just be host data.
const BWRAP_NET_FILES: &[&str] = &["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"];

/// Premier state directories in the workspace (vault, age identity, audit log, session CA).
const WORKSPACE_STATE_DIRS: &[&str] = &[".premier", ".premier-local"];

/// Everything `launch_sandboxed_agent` needs besides the command itself.
pub struct AgentLaunch<'a> {
    pub proxy_addr: SocketAddr,
    /// Session token from [`crate::ProxyHandle::auth_token`].
    pub proxy_token: &'a str,
    pub ca_cert_path: Option<&'a Path>,
    /// The proxy's Unix socket ([`crate::ProxyConfig::unix_socket`], alone in its directory).
    /// With it a sandboxed agent gets no network but a relay to that socket.
    pub proxy_socket: Option<&'a Path>,
    pub registry: &'a PlaceholderRegistry,
    pub public_vars: &'a BTreeMap<String, String>,
    /// The only directory the sandboxed agent may write to.
    pub workspace: &'a Path,
    /// Files or directories holding key material (age identity, vault, audit log) to hide.
    pub secret_paths: &'a [PathBuf],
    /// Use the kernel sandbox when the host has one.
    pub use_sandbox: bool,
    /// Explicit opt-in to run with environment sanitisation only.
    pub allow_unsandboxed: bool,
}

/// Summary of launched agent process execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRunResult {
    pub exit_code: i32,
    pub stdout_bytes_scrubbed: usize,
    pub stderr_bytes_scrubbed: usize,
    pub sandbox_mode: String,
}

/// Capabilities reported by `premier doctor` for the current host OS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostSandboxCapabilities {
    pub os: String,
    pub arch: String,
    pub posix_fifo_supported: bool,
    pub linux_bwrap_available: bool,
    pub linux_unshare_available: bool,
    pub linux_fuse3_available: bool,
    pub windows_projfs_available: bool,
}

impl HostSandboxCapabilities {
    pub fn detect() -> Self {
        let linux_bwrap_available = cfg!(target_os = "linux") && command_exists("bwrap");
        let linux_unshare_available = cfg!(target_os = "linux") && command_exists("unshare");
        let linux_fuse3_available = cfg!(target_os = "linux") && Path::new("/dev/fuse").exists();
        let windows_projfs_available = cfg!(target_os = "windows")
            && Path::new(r"C:\Windows\System32\ProjectedFSLib.dll").exists();

        Self {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            posix_fifo_supported: cfg!(unix),
            linux_bwrap_available,
            linux_unshare_available,
            linux_fuse3_available,
            windows_projfs_available,
        }
    }
}

fn command_exists(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

/// System CA certificate bundle locations probed when constructing the combined agent CA bundle.
const SYSTEM_CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

/// Default resource limits enforced on Windows Job Objects launched by [`launch_sandboxed_agent`].
#[cfg(windows)]
const DEFAULT_AGENT_RESOURCE_LIMITS: crate::cage::ResourceLimits = crate::cage::ResourceLimits {
    max_memory_mb: Some(4096),
    max_pids: Some(64),
    max_cpu_secs: None,
};

/// Sibling file path where the combined system + ephemeral proxy CA bundle is written.
pub fn combined_ca_bundle_path(ca_cert_path: &Path) -> PathBuf {
    let stem = ca_cert_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ca");
    let file_name = format!("{stem}-bundle.pem");
    match ca_cert_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file_name),
        _ => PathBuf::from(file_name),
    }
}

fn write_combined_ca_bundle_from(ca_cert_path: &Path, system_paths: &[&Path]) -> Option<PathBuf> {
    let ephemeral_pem = std::fs::read_to_string(ca_cert_path).ok()?;
    let mut combined = String::new();
    for sys_path in system_paths {
        if *sys_path != ca_cert_path
            && let Ok(sys_pem) = std::fs::read_to_string(sys_path)
            && !sys_pem.is_empty()
        {
            combined.push_str(&sys_pem);
            if !combined.ends_with('\n') {
                combined.push('\n');
            }
            break;
        }
    }
    combined.push_str(&ephemeral_pem);
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    let bundle_path = combined_ca_bundle_path(ca_cert_path);
    std::fs::write(&bundle_path, combined.as_bytes()).ok()?;
    Some(bundle_path)
}

fn write_combined_ca_bundle(ca_cert_path: &Path) -> Option<PathBuf> {
    let sys_paths: Vec<&Path> = SYSTEM_CA_BUNDLE_PATHS.iter().map(Path::new).collect();
    write_combined_ca_bundle_from(ca_cert_path, &sys_paths)
}

/// Build the environment map injected into the agent child process.
///
/// Guarantees:
/// - No raw secret values appear anywhere in the map.
/// - Every secret capability appears ONLY as its `premier_cap_v1_*` placeholder token.
/// - Proxy URLs and zero-MITM `PREMIER_CAP_<VAR>_BASE_URL` routes point strictly to the local
///   host proxy and carry the session token it requires.
pub fn build_agent_env(
    proxy_addr: SocketAddr,
    proxy_token: &str,
    ca_cert_path: Option<&Path>,
    registry: &PlaceholderRegistry,
    public_vars: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    // Schema-declared public values first: they can never displace the proxy wiring below.
    let mut env = public_vars.clone();
    let proxy_url = proxy_url_for(proxy_addr, proxy_token);

    env.insert("HTTP_PROXY".to_owned(), proxy_url.clone());
    env.insert("HTTPS_PROXY".to_owned(), proxy_url.clone());
    env.insert("http_proxy".to_owned(), proxy_url.clone());
    env.insert("https_proxy".to_owned(), proxy_url.clone());
    env.insert("ALL_PROXY".to_owned(), proxy_url.clone());
    env.insert("all_proxy".to_owned(), proxy_url);
    env.insert("NO_PROXY".to_owned(), "127.0.0.1,localhost".to_owned());

    if let Some(ca_path) = ca_cert_path {
        let ca_str = ca_path.to_string_lossy().into_owned();
        let bundle_path = write_combined_ca_bundle(ca_path);
        let bundle_str = bundle_path
            .as_deref()
            .unwrap_or(ca_path)
            .to_string_lossy()
            .into_owned();
        env.insert("SSL_CERT_FILE".to_owned(), bundle_str.clone());
        env.insert("NODE_EXTRA_CA_CERTS".to_owned(), ca_str);
        env.insert("REQUESTS_CA_BUNDLE".to_owned(), bundle_str.clone());
        env.insert("CURL_CA_BUNDLE".to_owned(), bundle_str.clone());
        env.insert("GIT_SSL_CAINFO".to_owned(), bundle_str.clone());
        env.insert("DENO_CERT".to_owned(), bundle_str);
    }

    for cap in registry.all() {
        env.insert(cap.var_name.clone(), cap.placeholder.clone());
        env.insert(
            format!("PREMIER_CAP_{}_BASE_URL", cap.var_name),
            cap_base_url_for(proxy_addr, proxy_token, &cap.var_name),
        );
    }

    env
}

/// The complete child environment: allow-listed host variables, then `injected` on top.
fn child_env(
    host_env: impl IntoIterator<Item = (String, String)>,
    injected: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = host_env
        .into_iter()
        .filter(|(k, _)| INHERITED_ENV.iter().any(|a| a.eq_ignore_ascii_case(k)))
        .collect();
    env.extend(injected.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// Paths hidden inside the sandbox: Premier state dirs, the caller's key/vault/audit paths
/// (relative ones resolve against `workspace`), and well-known credential stores.
fn masked_paths(workspace: &Path, home: Option<&Path>, secret_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = WORKSPACE_STATE_DIRS
        .iter()
        .map(|d| workspace.join(d))
        .collect();
    out.extend(secret_paths.iter().map(|p| workspace.join(p)));
    if let Some(home) = home {
        out.extend(HOME_CREDENTIAL_PATHS.iter().map(|p| home.join(p)));
    }
    // Session D-Bus / keyring / agent sockets: a path to the OS keychain and ssh-agent.
    out.push(PathBuf::from("/run/user"));
    out
}

/// `bwrap` args mounting one allow-listed host path read-only: a symlink (merged-`/usr` hosts:
/// `/bin -> usr/bin`) is recreated as a link, an existing path is bound, a missing one is skipped.
fn host_dir_args(dir: &Path) -> Vec<OsString> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::read_link(dir)
            .map(|target| {
                vec![
                    "--symlink".into(),
                    target.into_os_string(),
                    dir.as_os_str().to_owned(),
                ]
            })
            .unwrap_or_default(),
        Ok(_) => vec![
            "--ro-bind".into(),
            dir.as_os_str().to_owned(),
            dir.as_os_str().to_owned(),
        ],
        Err(_) => Vec::new(),
    }
}

/// `bwrap` argv for the agent. `masks` are existing paths with an `is_dir` flag. `egress` is
/// `(directory of the proxy socket, the premier binary, the proxy's TCP address)`. The host root
/// is never bound: only [`BWRAP_HOST_DIRS`] that exist.
fn bwrap_args(
    workspace: &Path,
    masks: &[(PathBuf, bool)],
    ca_cert_path: Option<&Path>,
    egress: Option<(&Path, &Path, SocketAddr)>,
    program: &str,
    args: &[String],
) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::new();
    let mut push = |items: &[&std::ffi::OsStr]| v.extend(items.iter().map(|i| (*i).to_owned()));
    let s = std::ffi::OsStr::new;

    // Fresh user/pid/ipc/uts/cgroup namespaces: the launcher (and its environment, which holds
    // raw values with `--backend env`) is not visible through /proc.
    // With `egress` the network namespace is private too: the only way out is the relay to the
    // proxy socket (`crate::cage`). Without it (no socket could be made) the host network is
    // shared and the proxy variables are cooperative.
    push(&[s("--unshare-all")]);
    if egress.is_none() {
        push(&[s("--share-net")]);
    }
    // `--new-session` stops TIOCSTI keystroke injection into the launching terminal.
    push(&[
        s("--die-with-parent"),
        s("--new-session"),
        s("--cap-drop"),
        s("ALL"),
    ]);
    // Allow-list, never `--ro-bind / /`: inside the user namespace the agent is the launching
    // uid, so a read-only bind of the root would expose every file that user can read.
    let net_files: &[&str] = if egress.is_none() {
        BWRAP_NET_FILES
    } else {
        &[]
    };
    for dir in BWRAP_HOST_DIRS.iter().chain(net_files) {
        for arg in host_dir_args(Path::new(dir)) {
            push(&[arg.as_os_str()]);
        }
    }
    push(&[
        s("--dev"),
        s("/dev"),
        s("--proc"),
        s("/proc"),
        s("--tmpfs"),
        s("/tmp"),
    ]);
    push(&[s("--bind"), workspace.as_os_str(), workspace.as_os_str()]);
    // Prevent a sandboxed agent from planting malicious Git hooks, redirecting a worktree
    // `.git` gitfile, or modifying `core.fsmonitor` in `.git/config`.
    let git_path = workspace.join(".git");
    if git_path.is_dir() {
        let git_hooks = workspace.join(".git/hooks");
        push(&[s("--tmpfs"), git_hooks.as_os_str()]);
    } else if git_path.is_file() {
        push(&[s("--ro-bind"), git_path.as_os_str(), git_path.as_os_str()]);
    }
    let git_config = workspace.join(".git/config");
    if git_config.is_file() {
        push(&[
            s("--ro-bind"),
            git_config.as_os_str(),
            git_config.as_os_str(),
        ]);
    }
    // Masks come after the workspace bind so they also cover state dirs inside it.
    for (path, is_dir) in masks {
        if *is_dir {
            push(&[s("--tmpfs"), path.as_os_str()]);
        } else {
            push(&[s("--ro-bind"), s("/dev/null"), path.as_os_str()]);
        }
    }
    // The session CA certificate (and combined bundle) are public; keep them readable under /tmp.
    if let Some(ca) = ca_cert_path {
        push(&[s("--ro-bind"), ca.as_os_str(), ca.as_os_str()]);
        let bundle = combined_ca_bundle_path(ca);
        if bundle.is_file() {
            push(&[s("--ro-bind"), bundle.as_os_str(), bundle.as_os_str()]);
        }
    }
    // The root (an empty tmpfs holding the allow-list) is not a scratch disk either.
    push(&[s("--remount-ro"), s("/")]);
    push(&[s("--chdir"), workspace.as_os_str()]);
    if let Some((socket_dir, exe, addr)) = egress {
        push(&[
            s("--ro-bind"),
            socket_dir.as_os_str(),
            s(crate::cage::CAGE_PROXY_DIR),
        ]);
        push(&[
            s("--ro-bind"),
            exe.as_os_str(),
            s(crate::cage::CAGE_EXE),
            s("--"),
        ]);
        // The relay listens where the proxy does on the host, so every injected URL still fits.
        v.extend(
            crate::cage::cage_exec_argv(addr)
                .into_iter()
                .map(OsString::from),
        );
        v.pop();
    }
    v.extend([s("--").to_owned(), s(program).to_owned()]);
    v.extend(args.iter().map(OsString::from));
    v
}

/// Whether to use the kernel sandbox, or an error when there is none and the caller did not
/// explicitly accept running without one.
fn sandbox_decision(
    available: bool,
    use_sandbox: bool,
    allow_unsandboxed: bool,
) -> Result<bool, ProxyError> {
    if use_sandbox && available {
        return Ok(true);
    }
    if allow_unsandboxed {
        return Ok(false);
    }
    Err(ProxyError::Io(
        "no kernel sandbox for the agent (needs Linux with `bwrap`); pass --allow-unsandboxed to \
         run with environment sanitisation only"
            .to_owned(),
    ))
}

/// Refuse to silently fall back to `--share-net` in sandboxed mode when no proxy Unix socket
/// is wired up, unless the caller explicitly opted into unsandboxed/cooperative egress.
fn validate_sandbox_egress(has_egress: bool, allow_unsandboxed: bool) -> Result<(), ProxyError> {
    if has_egress || allow_unsandboxed {
        return Ok(());
    }
    Err(ProxyError::Io(
        "sandboxed agent requires a proxy Unix socket for network isolation (refusing to fall \
         back to --share-net); pass --allow-unsandboxed to opt into cooperative egress"
            .to_owned(),
    ))
}

/// Make this process unreadable to other processes of the same user (`/proc/<pid>/environ`,
/// `/proc/<pid>/mem`, ptrace), so an unsandboxed agent cannot lift secrets from its parent.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn deny_same_user_inspection() {
    // SAFETY: PR_SET_DUMPABLE only changes a flag on the calling process.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn deny_same_user_inspection() {}

/// Caps for a [`WindowsJobGuard`]. `None` leaves that dimension unbounded.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsJobLimits {
    /// Committed memory of the whole job (`JOB_OBJECT_LIMIT_JOB_MEMORY`).
    pub max_memory_mb: Option<u64>,
    /// Simultaneously live processes in the job (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`).
    pub max_active_processes: Option<u32>,
}

#[cfg(windows)]
impl From<&crate::cage::ResourceLimits> for WindowsJobLimits {
    fn from(l: &crate::cage::ResourceLimits) -> Self {
        Self {
            max_memory_mb: l.max_memory_mb,
            max_active_processes: l.max_pids.map(|p| u32::try_from(p).unwrap_or(u32::MAX)),
        }
    }
}

/// A Windows Job Object holding an agent's whole process tree: kill-on-close, a memory cap and a
/// live-process cap. Windows has no `bwrap`, so this is process confinement only: the agent still
/// sees the filesystem and network as the launching user does. Dropping the guard closes the job
/// handle, which kills every process still in it.
///
/// shortcut: the process is assigned after `spawn`, so a grandchild forked in that window escapes;
/// upgrade to `CREATE_SUSPENDED` + resume if that matters.
#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsJobGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl WindowsJobGuard {
    /// Create an empty job with `limits` and kill-on-close set.
    pub fn new(limits: WindowsJobLimits) -> std::io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };

        // SAFETY: null attributes and name are documented as valid (default security, unnamed).
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // From here `Drop` closes the handle on every error path.
        let guard = Self { handle };

        // SAFETY: the struct is plain old data; all-zero means "no limit".
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(mb) = limits.max_memory_mb.filter(|mb| *mb > 0) {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit =
                usize::try_from(mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX);
        }
        if let Some(n) = limits.max_active_processes.filter(|n| *n > 0) {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = n;
        }
        info.BasicLimitInformation.LimitFlags = flags;

        // SAFETY: `handle` is the job just created; `info` is a live
        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION and the size passed is exactly its size.
        let ok = unsafe {
            SetInformationJobObject(
                guard.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(guard)
    }

    /// Put the running process `pid` (and, from now on, its descendants) into the job.
    pub fn attach_pid(&self, pid: u32) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        // SAFETY: plain value arguments; a null (0) handle is the failure signal, checked below.
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both handles are valid and owned here; the process handle is closed once.
        let (ok, err) = unsafe {
            let ok = AssignProcessToJobObject(self.handle, process);
            let err = std::io::Error::last_os_error();
            CloseHandle(process);
            (ok, err)
        };
        if ok == 0 { Err(err) } else { Ok(()) }
    }

    /// Kill every process in the job now.
    pub fn terminate(&self, exit_code: u32) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: `self.handle` is a valid job handle for the lifetime of `self`.
        if unsafe { TerminateJobObject(self.handle, exit_code) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Drop for WindowsJobGuard {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this guard and closed exactly once, here. Closing it
        // kills whatever is still in the job (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

/// Resume every suspended thread belonging to `pid` after it has been assigned to a Job Object.
#[cfg(windows)]
#[allow(unsafe_code)]
fn resume_process_threads(pid: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{BOOL, CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;

    #[repr(C)]
    struct ThreadEntry32 {
        dw_size: u32,
        cnt_usage: u32,
        th32_thread_id: u32,
        th32_owner_process_id: u32,
        tp_base_pri: i32,
        tp_delta_pri: i32,
        dw_flags: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> HANDLE;
        fn Thread32First(h_snapshot: HANDLE, lpte: *mut ThreadEntry32) -> BOOL;
        fn Thread32Next(h_snapshot: HANDLE, lpte: *mut ThreadEntry32) -> BOOL;
    }

    // SAFETY: TH32CS_SNAPTHREAD snapshots system threads; handle is checked and closed once.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE || snap == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut entry = ThreadEntry32 {
        dw_size: std::mem::size_of::<ThreadEntry32>() as u32,
        cnt_usage: 0,
        th32_thread_id: 0,
        th32_owner_process_id: 0,
        tp_base_pri: 0,
        tp_delta_pri: 0,
        dw_flags: 0,
    };
    let mut resumed = 0usize;
    let mut last_err: Option<std::io::Error> = None;

    // SAFETY: `snap` is valid and `entry.dw_size` is initialized to its exact byte size.
    let mut ok = unsafe { Thread32First(snap, std::ptr::addr_of_mut!(entry)) };
    while ok != 0 {
        if entry.th32_owner_process_id == pid {
            // SAFETY: `th32_thread_id` came from `snap`; handle is checked and closed once.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32_thread_id) };
            if thread == 0 {
                last_err = Some(std::io::Error::last_os_error());
            } else {
                // SAFETY: `thread` is a valid handle opened with `THREAD_SUSPEND_RESUME`.
                let prev = unsafe { ResumeThread(thread) };
                let err = std::io::Error::last_os_error();
                // SAFETY: `thread` is closed exactly once.
                unsafe { CloseHandle(thread) };
                if prev == u32::MAX {
                    last_err = Some(err);
                } else {
                    resumed += 1;
                }
            }
        }
        entry.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
        // SAFETY: `snap` is valid and `entry.dw_size` is set.
        ok = unsafe { Thread32Next(snap, std::ptr::addr_of_mut!(entry)) };
    }

    // SAFETY: `snap` is closed exactly once.
    unsafe { CloseHandle(snap) };

    if resumed == 0 {
        return Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no suspended thread found for pid {pid}"),
            )
        }));
    }
    Ok(())
}

/// Spawn an AI agent command wired to the host-side `premier-proxy`.
///
/// The child gets a cleared, allow-listed environment holding placeholders only. On Linux with
/// `bwrap` it also runs with a read-only root, a writable workspace, private namespaces, and
/// every path holding key material masked. Without a sandbox the launch is refused unless
/// `allow_unsandboxed` is set.
pub async fn launch_sandboxed_agent(
    program: &str,
    args: &[String],
    launch: &AgentLaunch<'_>,
) -> Result<AgentRunResult, ProxyError> {
    let registry = launch.registry;
    let sandboxed = sandbox_decision(
        cfg!(target_os = "linux") && command_exists("bwrap"),
        launch.use_sandbox,
        launch.allow_unsandboxed,
    )?;
    deny_same_user_inspection();

    let injected = build_agent_env(
        launch.proxy_addr,
        launch.proxy_token,
        launch.ca_cert_path,
        registry,
        launch.public_vars,
    );
    let redactor = SecretRedactor::build(
        registry
            .all()
            .map(|c| (c.var_name.as_str(), c.secret.as_str())),
    );

    let (mut cmd, sandbox_mode) = if sandboxed {
        let workspace = std::fs::canonicalize(launch.workspace)
            .map_err(|e| ProxyError::Io(format!("cannot resolve agent workspace: {e}")))?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        // Mask the real location, so a symlinked state dir is hidden through every route.
        let masks: Vec<(PathBuf, bool)> =
            masked_paths(&workspace, home.as_deref(), launch.secret_paths)
                .into_iter()
                .filter_map(|p| std::fs::canonicalize(p).ok())
                .filter_map(|p| std::fs::metadata(&p).ok().map(|m| (p, m.is_dir())))
                .collect();
        let exe = std::env::current_exe().ok();
        let egress = launch
            .proxy_socket
            .and_then(|socket| Some((socket.parent()?, exe.as_deref()?, launch.proxy_addr)));
        validate_sandbox_egress(egress.is_some(), launch.allow_unsandboxed)?;
        let mut c = Command::new("bwrap");
        c.args(bwrap_args(
            &workspace,
            &masks,
            launch.ca_cert_path,
            egress,
            program,
            args,
        ));
        let egress = if egress.is_some() {
            "enforced"
        } else {
            "cooperative"
        };
        (c, format!("linux-bwrap+proxy({egress}-egress)"))
    } else {
        eprintln!(
            "[premier agent] WARNING: no kernel sandbox; the agent can read every file this user can, including vault keys, and can bypass the proxy"
        );
        let mut c = Command::new(program);
        c.args(args);
        (
            c,
            format!("{}-env-only+proxy(UNSANDBOXED)", std::env::consts::OS),
        )
    };

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::inherit())
        .env_clear()
        .envs(child_env(std::env::vars(), &injected));

    // Unsandboxed on Windows: create the Job Object with resource limits and spawn the child
    // suspended (`CREATE_SUSPENDED`), attach it before any code runs, then resume it. Fail
    // closed (kill the child) if job assignment or resume fails.
    #[cfg(windows)]
    let job = if !sandboxed {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        let guard = WindowsJobGuard::new(WindowsJobLimits::from(&DEFAULT_AGENT_RESOURCE_LIMITS))
            .map_err(|e| ProxyError::Io(format!("failed to create Windows job object: {e}")))?;
        cmd.as_std_mut().creation_flags(CREATE_SUSPENDED);
        Some(guard)
    } else {
        None
    };

    let mut child = cmd
        .spawn()
        .map_err(|e| ProxyError::Io(format!("failed to spawn agent '{program}': {e}")))?;
    #[cfg(windows)]
    if let Some(ref guard) = job {
        let attach_res = match child.id() {
            Some(pid) => guard
                .attach_pid(pid)
                .and_then(|()| resume_process_threads(pid)),
            None => Err(std::io::Error::other(
                "spawned child exited before job assignment",
            )),
        };
        if let Err(e) = attach_res {
            let _ = child.kill().await;
            return Err(ProxyError::Io(format!(
                "failed to confine agent in Windows job object: {e}"
            )));
        }
    }

    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProxyError::Io("failed to capture agent stdout".to_owned()))?;
    let mut child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProxyError::Io("failed to capture agent stderr".to_owned()))?;

    let r_out = redactor.clone();
    let stdout_task = tokio::spawn(async move {
        let mut stream = r_out.streaming();
        let mut out = tokio::io::stdout();
        let mut buf = [0u8; 4096];
        while let Ok(n) = child_stdout.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let emit = stream.push(&buf[..n]);
            if !emit.is_empty() {
                let _ = out.write_all(&emit).await;
                let _ = out.flush().await;
            }
        }
        let tail = stream.finish();
        if !tail.is_empty() {
            let _ = out.write_all(&tail).await;
            let _ = out.flush().await;
        }
        stream.total_scrubbed()
    });

    let r_err = redactor;
    let stderr_task = tokio::spawn(async move {
        let mut stream = r_err.streaming();
        let mut err = tokio::io::stderr();
        let mut buf = [0u8; 4096];
        while let Ok(n) = child_stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let emit = stream.push(&buf[..n]);
            if !emit.is_empty() {
                let _ = err.write_all(&emit).await;
                let _ = err.flush().await;
            }
        }
        let tail = stream.finish();
        if !tail.is_empty() {
            let _ = err.write_all(&tail).await;
            let _ = err.flush().await;
        }
        stream.total_scrubbed()
    });

    let status = child
        .wait()
        .await
        .map_err(|e| ProxyError::Io(format!("agent wait failed: {e}")))?;
    #[cfg(windows)]
    drop(job);
    let stdout_bytes_scrubbed = stdout_task.await.unwrap_or(0);
    let stderr_bytes_scrubbed = stderr_task.await.unwrap_or(0);

    Ok(AgentRunResult {
        exit_code: status.code().unwrap_or(1),
        stdout_bytes_scrubbed,
        stderr_bytes_scrubbed,
        sandbox_mode,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use premier_secrets::{ApprovalMode, EgressSpec, InjectSpec};
    use zeroize::Zeroizing;

    use super::*;

    const RAW: &str = "sk_live_RAW_SECRET_VALUE_123";

    fn registry() -> (PlaceholderRegistry, String) {
        let mut reg = PlaceholderRegistry::new();
        let ph = reg.register(
            "STRIPE_API_KEY",
            Zeroizing::new(RAW.to_owned()),
            EgressSpec {
                hosts: vec!["api.stripe.com".to_owned()],
                methods: vec![],
                path_prefixes: vec![],
                upstream_base_url: None,
                inject: InjectSpec::PlaceholderReplace,
                rate_limit_per_min: None,
                approval: ApprovalMode::Auto,
                jit_ttl_secs: 60,
                auto_allow: vec![],
            },
            None,
        );
        (reg, ph)
    }

    #[test]
    fn agent_env_is_allow_listed_and_never_holds_raw_secrets() {
        let (reg, placeholder) = registry();
        let public = BTreeMap::from([
            ("APP_PORT".to_owned(), "8080".to_owned()),
            // A schema cannot re-point the agent's proxy.
            ("HTTPS_PROXY".to_owned(), "http://evil.example".to_owned()),
        ]);
        let addr: SocketAddr = "127.0.0.1:4455".parse().unwrap();
        let injected = build_agent_env(addr, "tok123", None, &reg, &public);
        let host = [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/dev"),
            ("LANG", "C.UTF-8"),
            ("TERM", "xterm"),
            ("PREMIER_AGE_IDENTITY", "AGE-SECRET-KEY-1XXXX"),
            ("STRIPE_API_KEY", RAW),
            ("AWS_SECRET_ACCESS_KEY", "aws-raw"),
            ("SOME_VENDOR_TOKEN", "not-on-any-deny-list"),
            ("SSH_AUTH_SOCK", "/run/user/1000/ssh"),
            ("LD_PRELOAD", "/tmp/x.so"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()));
        let env = child_env(host, &injected);

        for kept in ["PATH", "HOME", "LANG", "TERM", "APP_PORT"] {
            assert!(env.contains_key(kept), "{kept}");
        }
        for dropped in [
            "PREMIER_AGE_IDENTITY",
            "AWS_SECRET_ACCESS_KEY",
            "SOME_VENDOR_TOKEN",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
        ] {
            assert!(
                !env.contains_key(dropped),
                "{dropped} leaked into the agent"
            );
        }
        assert_eq!(env["STRIPE_API_KEY"], placeholder);
        assert!(
            env.values()
                .all(|v| !v.contains(RAW) && !v.contains("AGE-SECRET-KEY"))
        );
        assert_eq!(env["HTTPS_PROXY"], "http://premier:tok123@127.0.0.1:4455");
        assert_eq!(env["HTTP_PROXY"], env["HTTPS_PROXY"]);
        assert_eq!(env["ALL_PROXY"], env["HTTPS_PROXY"]);
        assert_eq!(env["all_proxy"], env["HTTPS_PROXY"]);
        assert_eq!(
            env["PREMIER_CAP_STRIPE_API_KEY_BASE_URL"],
            "http://127.0.0.1:4455/cap/tok123/STRIPE_API_KEY"
        );
    }

    #[test]
    fn bwrap_plan_isolates_namespaces_and_masks_key_material() {
        let ws = Path::new("/work/repo");
        let masked = masked_paths(
            ws,
            Some(Path::new("/home/dev")),
            &[
                PathBuf::from(".keys/age.key"),
                PathBuf::from("/etc/premier/vault.toml"),
            ],
        );
        for expected in [
            "/work/repo/.premier",
            "/work/repo/.premier-local",
            "/work/repo/.keys/age.key",
            "/etc/premier/vault.toml",
            "/home/dev/.ssh",
            "/home/dev/.aws",
            "/home/dev/.gnupg",
            "/home/dev/.config/premier",
            "/home/dev/.cargo/credentials.toml",
            "/home/dev/.pypirc",
            "/home/dev/.bash_history",
            "/home/dev/.zsh_history",
            "/run/user",
        ] {
            assert!(
                masked.contains(&PathBuf::from(expected)),
                "{expected} not masked"
            );
        }

        let masks = [
            (PathBuf::from("/work/repo/.premier-local"), true),
            (PathBuf::from("/work/repo/.keys/age.key"), false),
        ];
        let argv: Vec<String> = bwrap_args(
            ws,
            &masks,
            Some(Path::new("/tmp/ca.pem")),
            Some((
                Path::new("/run/s"),
                Path::new("/usr/bin/premier"),
                "127.0.0.1:4455".parse().unwrap(),
            )),
            "agent",
            &["--flag".to_owned()],
        )
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        let pos = |window: &[&str]| {
            argv.windows(window.len())
                .position(|w| w == window)
                .unwrap_or_else(|| panic!("{window:?} missing from {argv:?}"))
        };

        assert_eq!(argv[0], "--unshare-all");
        assert!(
            !argv.iter().any(|a| a == "--share-net"),
            "the agent must have no network"
        );
        pos(&["--ro-bind", "/run/s", "/tmp/premier-proxy"]);
        pos(&["--ro-bind", "/usr/bin/premier", "/tmp/premier"]);
        pos(&[
            "--",
            "/tmp/premier",
            "__cage-exec",
            "--proxy-socket",
            "/tmp/premier-proxy/proxy.sock",
        ]);
        pos(&["--listen", "127.0.0.1:4455", "--", "agent", "--flag"]);
        let shared = bwrap_args(ws, &[], None, None, "agent", &[]);
        assert!(shared.iter().any(|a| a == "--share-net"));
        assert!(
            !argv.iter().any(|a| a == "--dev-bind"),
            "host root must not be writable"
        );
        assert!(
            !argv.windows(3).any(|w| w == ["--ro-bind", "/", "/"]),
            "the whole host root must never be bound"
        );
        pos(&["--proc", "/proc"]);
        pos(&["--remount-ro", "/"]);
        let workspace_rw = pos(&["--bind", "/work/repo", "/work/repo"]);
        let dir_mask = pos(&["--tmpfs", "/work/repo/.premier-local"]);
        let file_mask = pos(&["--ro-bind", "/dev/null", "/work/repo/.keys/age.key"]);
        assert!(workspace_rw < dir_mask && workspace_rw < file_mask);
        assert!(pos(&["--tmpfs", "/tmp"]) < pos(&["--ro-bind", "/tmp/ca.pem", "/tmp/ca.pem"]));
        assert_eq!(&argv[argv.len() - 3..], ["--", "agent", "--flag"]);
    }

    #[tokio::test]
    async fn refuses_to_run_unsandboxed_without_opt_in() {
        assert!(sandbox_decision(true, true, false).unwrap());
        assert!(sandbox_decision(false, true, false).is_err());
        assert!(sandbox_decision(true, false, false).is_err());
        assert!(!sandbox_decision(false, true, true).unwrap());

        let (reg, _) = registry();
        let launch = AgentLaunch {
            proxy_addr: "127.0.0.1:1".parse().unwrap(),
            proxy_token: "t",
            ca_cert_path: None,
            proxy_socket: None,
            registry: &reg,
            public_vars: &BTreeMap::new(),
            workspace: Path::new("."),
            secret_paths: &[],
            use_sandbox: false,
            allow_unsandboxed: false,
        };
        let err = launch_sandboxed_agent("definitely-not-run", &[], &launch)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--allow-unsandboxed"));

        // Sandboxed mode must also refuse to fall back to `--share-net` when `proxy_socket` is None.
        assert!(validate_sandbox_egress(false, false).is_err());
        assert!(validate_sandbox_egress(true, false).is_ok());
        assert!(validate_sandbox_egress(false, true).is_ok());
    }

    #[test]
    fn bwrap_masks_git_hooks_and_mounts_git_config_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
        std::fs::write(
            ws.join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n",
        )
        .unwrap();

        let argv: Vec<String> = bwrap_args(
            ws,
            &[],
            None,
            Some((
                Path::new("/run/s"),
                Path::new("/usr/bin/premier"),
                "127.0.0.1:4455".parse().unwrap(),
            )),
            "agent",
            &[],
        )
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        let ws_s = ws.to_string_lossy().into_owned();
        let hooks_s = ws.join(".git/hooks").to_string_lossy().into_owned();
        let cfg_s = ws.join(".git/config").to_string_lossy().into_owned();
        let pos = |window: &[&str]| {
            argv.windows(window.len())
                .position(|w| w == window)
                .unwrap_or_else(|| panic!("{window:?} missing from {argv:?}"))
        };
        let ws_bind = pos(&["--bind", &ws_s, &ws_s]);
        let hooks_tmpfs = pos(&["--tmpfs", &hooks_s]);
        let cfg_ro = pos(&["--ro-bind", &cfg_s, &cfg_s]);
        assert!(ws_bind < hooks_tmpfs && ws_bind < cfg_ro);
    }

    #[test]
    fn bwrap_binds_only_the_host_allow_list_never_the_root() {
        let ws = Path::new("/work/repo");
        let argv: Vec<String> = bwrap_args(ws, &[], None, None, "agent", &[])
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !argv.windows(3).any(|w| w == ["--ro-bind", "/", "/"]),
            "{argv:?}"
        );
        // Every bind of a host path is one of the allow-listed ones.
        for w in argv.windows(3) {
            if w[0] == "--ro-bind" && w[1] == w[2] {
                assert!(
                    BWRAP_HOST_DIRS.contains(&w[1].as_str())
                        || BWRAP_NET_FILES.contains(&w[1].as_str()),
                    "unexpected host bind {}",
                    w[1]
                );
            }
        }
        // Whatever exists on this host is emitted, as a bind or (merged `/usr`) a symlink.
        for dir in BWRAP_HOST_DIRS.iter().chain(BWRAP_NET_FILES) {
            if std::fs::symlink_metadata(dir).is_ok() {
                assert!(
                    argv.windows(3)
                        .any(|w| w[0] == "--ro-bind" && w[1] == *dir && w[2] == *dir)
                        || argv.windows(3).any(|w| w[0] == "--symlink" && w[2] == *dir),
                    "{dir} missing from {argv:?}"
                );
            }
        }
        // Resolver files are only for the cooperative (shared-network) mode.
        let caged: Vec<String> = bwrap_args(
            ws,
            &[],
            None,
            Some((
                Path::new("/run/s"),
                Path::new("/usr/bin/premier"),
                "127.0.0.1:4455".parse().unwrap(),
            )),
            "agent",
            &[],
        )
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        assert!(!caged.iter().any(|a| a == "/etc/resolv.conf"));
    }

    #[test]
    fn host_dir_args_binds_existing_skips_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let present = tmp.path().join("lib");
        std::fs::create_dir(&present).unwrap();
        let p = present.to_string_lossy().into_owned();
        let got: Vec<String> = host_dir_args(&present)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, ["--ro-bind", p.as_str(), p.as_str()]);
        assert!(host_dir_args(&tmp.path().join("absent")).is_empty());

        #[cfg(unix)]
        {
            let link = tmp.path().join("bin");
            std::os::unix::fs::symlink("usr/bin", &link).unwrap();
            let got: Vec<String> = host_dir_args(&link)
                .into_iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert_eq!(got, ["--symlink", "usr/bin", &link.to_string_lossy()]);
        }
    }

    #[cfg(windows)]
    fn spawn_sleeper() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/C", "ping", "-n", "60", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn exited_within(child: &mut std::process::Child, ms: u64) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < end {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    #[cfg(windows)]
    #[test]
    fn job_guard_kills_the_child_on_drop() {
        let mut child = spawn_sleeper();
        let job = WindowsJobGuard::new(WindowsJobLimits {
            max_memory_mb: Some(1024),
            max_active_processes: Some(16),
        })
        .unwrap();
        job.attach_pid(child.id()).unwrap();
        assert!(child.try_wait().unwrap().is_none(), "still running");
        drop(job);
        let died = exited_within(&mut child, 10_000);
        if !died {
            let _ = child.kill();
        }
        assert!(died, "kill-on-close must end the attached child");
    }

    #[cfg(windows)]
    #[test]
    fn job_guard_terminate_kills_the_child_tree() {
        let mut child = spawn_sleeper();
        let job = WindowsJobGuard::new(WindowsJobLimits::default()).unwrap();
        job.attach_pid(child.id()).unwrap();
        job.terminate(1).unwrap();
        let died = exited_within(&mut child, 10_000);
        if !died {
            let _ = child.kill();
        }
        assert!(died, "terminate must end the attached child");
    }

    #[test]
    fn combined_ca_bundle_and_bwrap_hardening() {
        let tmp = tempfile::tempdir().unwrap();
        let sys_ca = tmp.path().join("sys-ca.crt");
        let ephem_ca = tmp.path().join("session-ca.pem");
        std::fs::write(
            &sys_ca,
            "-----BEGIN CERTIFICATE-----\nSYS\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &ephem_ca,
            "-----BEGIN CERTIFICATE-----\nEPHEM\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let bundle = write_combined_ca_bundle_from(&ephem_ca, &[sys_ca.as_path()]).unwrap();
        let contents = std::fs::read_to_string(&bundle).unwrap();
        assert!(contents.contains("SYS") && contents.contains("EPHEM"));

        let (reg, _) = registry();
        let addr: SocketAddr = "127.0.0.1:4455".parse().unwrap();
        let env = build_agent_env(addr, "tok", Some(&ephem_ca), &reg, &BTreeMap::new());
        let expected_bundle = combined_ca_bundle_path(&ephem_ca)
            .to_string_lossy()
            .into_owned();
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], ephem_ca.to_string_lossy());
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "DENO_CERT",
        ] {
            assert_eq!(env[var], expected_bundle, "{var}");
        }

        // `bwrap_args` drops all Linux capabilities and ro-binds a worktree `.git` gitfile.
        let ws = tmp.path().join("wt");
        std::fs::create_dir(&ws).unwrap();
        let gitfile = ws.join(".git");
        std::fs::write(&gitfile, "gitdir: /somewhere/else\n").unwrap();
        let argv: Vec<String> = bwrap_args(&ws, &[], Some(&ephem_ca), None, "sh", &[])
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(argv.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        let gf = gitfile.to_string_lossy().into_owned();
        assert!(
            argv.windows(3)
                .any(|w| w == ["--ro-bind", gf.as_str(), gf.as_str()]),
            "worktree .git gitfile must be ro-bound: {argv:?}"
        );
        assert!(
            argv.windows(3).any(|w| {
                w == [
                    "--ro-bind",
                    expected_bundle.as_str(),
                    expected_bundle.as_str(),
                ]
            }),
            "combined CA bundle must be ro-bound into bwrap"
        );
    }

    #[cfg(windows)]
    #[test]
    fn suspended_child_attaches_to_job_before_resume() {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "exit", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_SUSPENDED);
        let mut child = cmd.spawn().unwrap();
        let limits = WindowsJobLimits::from(&DEFAULT_AGENT_RESOURCE_LIMITS);
        assert!(limits.max_memory_mb.is_some() && limits.max_active_processes.is_some());
        let job = WindowsJobGuard::new(limits).unwrap();
        job.attach_pid(child.id()).unwrap();
        resume_process_threads(child.id()).unwrap();
        assert!(exited_within(&mut child, 10_000));
    }
}
