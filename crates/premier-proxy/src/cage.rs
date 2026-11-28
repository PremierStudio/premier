//! The in-sandbox half of enforced egress. A caged agent has no network namespace of its own
//! but loopback; the session's proxy listens on a Unix socket bound into the sandbox, and
//! `premier __cage-exec` (this module) relays a loopback TCP port to it before running the agent.
//! Any other address the agent dials has no route: the kernel refuses it, not a proxy variable.
//!
//! There is no resolver in the sandbox. That is intended: clients hand the proxy a host name
//! (`CONNECT host:443`, `GET http://host/`) and the proxy resolves it on the host side.

use std::net::SocketAddr;
use std::path::Path;

/// The hidden subcommand of the `premier` binary.
pub const CAGE_EXEC: &str = "__cage-exec";
/// Where the `premier` binary is bound inside a sandbox (under its private `/tmp`).
pub const CAGE_EXE: &str = "/tmp/premier";
/// Where the directory holding the proxy socket is bound inside a sandbox.
pub const CAGE_PROXY_DIR: &str = "/tmp/premier-proxy";
/// File name of the proxy socket in that directory.
pub const PROXY_SOCKET: &str = "proxy.sock";

/// `argv` prefix that runs what follows it behind the relay, inside a sandbox.
pub fn cage_exec_argv(listen: SocketAddr) -> Vec<String> {
    vec![
        CAGE_EXE.to_owned(),
        CAGE_EXEC.to_owned(),
        "--proxy-socket".to_owned(),
        format!("{CAGE_PROXY_DIR}/{PROXY_SOCKET}"),
        "--listen".to_owned(),
        listen.to_string(),
        "--".to_owned(),
    ]
}

/// Kernel-enforced resource caps for a caged agent (from the profile's `AutonomyBudget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceLimits {
    pub max_memory_mb: Option<u64>,
    pub max_pids: Option<u64>,
    pub max_cpu_secs: Option<u64>,
}

impl From<&premier_policy::AutonomyBudget> for ResourceLimits {
    fn from(b: &premier_policy::AutonomyBudget) -> Self {
        Self {
            max_memory_mb: b.max_memory_mb,
            max_pids: b.max_pids,
            max_cpu_secs: b.max_cpu_secs,
        }
    }
}

/// Like [`cage_exec_argv`], with `--max-memory-mb`/`--max-pids`/`--max-cpu-secs` for each set cap.
pub fn cage_exec_argv_with_limits(listen: SocketAddr, limits: &ResourceLimits) -> Vec<String> {
    let mut argv = cage_exec_argv(listen);
    argv.pop(); // the trailing `--`
    for (flag, value) in [
        ("--max-memory-mb", limits.max_memory_mb),
        ("--max-pids", limits.max_pids),
        ("--max-cpu-secs", limits.max_cpu_secs),
    ] {
        if let Some(v) = value {
            argv.extend([flag.to_owned(), v.to_string()]);
        }
    }
    argv.push("--".to_owned());
    argv
}

/// Cap the child's address space and CPU time with `setrlimit`, clamped to the hard limit so an
/// unprivileged caller can never fail on a raise. Process counts are enforced per-session via
/// cgroup v2 `pids.max` rather than UID-wide `RLIMIT_NPROC`. No-op off Linux.
pub fn apply_rlimits(cmd: &mut tokio::process::Command, limits: &ResourceLimits) {
    #[cfg(target_os = "linux")]
    {
        let mem = limits
            .max_memory_mb
            .map(|mb| mb.saturating_mul(1024 * 1024));
        let cpu = limits.max_cpu_secs;
        if mem.is_none() && cpu.is_none() {
            return;
        }
        #[allow(unsafe_code)]
        let cap = |resource, value: Option<u64>| -> std::io::Result<()> {
            let Some(v) = value else {
                return Ok(());
            };
            let mut cur = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `cur` is a properly initialized `libc::rlimit` struct on the stack.
            let got = unsafe { libc::getrlimit(resource, &mut cur) };
            if got != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let want = (v as libc::rlim_t).min(cur.rlim_max);
            let new = libc::rlimit {
                rlim_cur: want,
                rlim_max: cur.rlim_max,
            };
            // SAFETY: `new` is a properly initialized `libc::rlimit` struct on the stack.
            let set = unsafe { libc::setrlimit(resource, &new) };
            if set != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the closure runs in the forked child before exec and only calls
        // async-signal-safe libc functions (`getrlimit`/`setrlimit`) on stack values; it
        // allocates nothing and touches no locks.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                cap(libc::RLIMIT_AS, mem)?;
                cap(libc::RLIMIT_CPU, cpu)?;
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (cmd, limits);
}

/// Place the child into its own process group (`pgid == pid`) on Unix so group signals cover it
/// and any descendants that remain in the group. No-op off Unix.
pub fn configure_process_group(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    #[cfg(not(unix))]
    let _ = cmd;
}

/// Result of attempting to suspend a live agent process tree on budget pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseOutcome {
    /// Whole process tree suspended (cgroup v2 `cgroup.freeze` or Unix `-pgid` `SIGSTOP`).
    Suspended,
    /// Non-Unix host without kernel suspension: egress is blocked by the proxy (`429`).
    ProxyOnly,
    /// Sandboxed Unix session lacks cgroup v2 freezing (`bwrap --new-session` cannot be
    /// suspended safely via `kill`); caller must terminate instead of leaving it running.
    MustTerminate,
}

/// A cgroup v2 directory holding a caged process; thawed (best effort) and removed on drop.
#[derive(Debug)]
pub struct CgroupGuard {
    path: std::path::PathBuf,
}

impl CgroupGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Move `pid` into this cgroup (`cgroup.procs`). Returns `false` off Linux or on write error.
    pub fn attach_pid(&self, pid: u32) -> bool {
        #[cfg(target_os = "linux")]
        {
            std::fs::write(self.path.join("cgroup.procs"), pid.to_string()).is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            false
        }
    }

    /// Freeze the entire cgroup process tree via `cgroup.freeze`.
    pub fn freeze(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            std::fs::write(self.path.join("cgroup.freeze"), "1").is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Thaw a previously frozen cgroup process tree via `cgroup.freeze`.
    pub fn thaw(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            std::fs::write(self.path.join("cgroup.freeze"), "0").is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = std::fs::write(self.path.join("cgroup.freeze"), "0");
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Pre-create a cgroup v2 directory for `session_id` with `memory.max` / `pids.max` applied.
/// Returns `None` off Linux, without cgroup v2, without a write-delegated hierarchy, or if an
/// explicit limit failed to write.
pub fn create_cgroup_v2(session_id: &str, limits: &ResourceLimits) -> Option<CgroupGuard> {
    #[cfg(target_os = "linux")]
    {
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").is_file() {
            return None;
        }
        let name: String = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(48)
            .collect();
        let suffix = rand::random::<u64>();
        let path = root.join(format!("premier-{name}-{suffix:016x}"));
        std::fs::create_dir(&path).ok()?;
        let guard = CgroupGuard { path };
        if let Some(mb) = limits.max_memory_mb {
            let bytes = mb.saturating_mul(1024 * 1024);
            std::fs::write(guard.path.join("memory.max"), bytes.to_string()).ok()?;
        }
        if let Some(n) = limits.max_pids {
            std::fs::write(guard.path.join("pids.max"), n.to_string()).ok()?;
        }
        Some(guard)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (session_id, limits);
        None
    }
}

/// Best effort: create a cgroup v2 with `memory.max` / `pids.max` and attach `pid` to it.
pub fn try_attach_cgroup_v2(
    session_id: &str,
    pid: u32,
    limits: &ResourceLimits,
) -> Option<CgroupGuard> {
    let guard = create_cgroup_v2(session_id, limits)?;
    if !guard.attach_pid(pid) {
        return None;
    }
    Some(guard)
}

#[cfg(unix)]
fn signal_group_or_pid(pid: u32, sig: libc::c_int) -> bool {
    let Ok(raw) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    // SAFETY: `raw > 0`; `-raw` targets the child's dedicated process group when present,
    // falling back to `raw` only when no matching group exists (`ESRCH`).
    #[allow(unsafe_code)]
    unsafe {
        if libc::kill(-raw, sig) == 0 {
            return true;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return libc::kill(raw, sig) == 0;
        }
        false
    }
}

/// Suspend a running process group (falling back to single PID) with `SIGSTOP` on Unix.
pub fn pause_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_group_or_pid(pid, libc::SIGSTOP)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Resume a suspended process group (falling back to single PID) with `SIGCONT` on Unix.
pub fn resume_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_group_or_pid(pid, libc::SIGCONT)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Freeze the entire session process tree on budget breach (cgroup v2 primary, `-pgid` fallback for
/// unsandboxed Unix hosts; returns `MustTerminate` for sandboxed Unix hosts lacking cgroup v2).
pub fn pause_session_tree(
    pid: Option<u32>,
    cgroup: Option<&CgroupGuard>,
    sandboxed: bool,
) -> PauseOutcome {
    if let Some(cg) = cgroup
        && cg.freeze()
    {
        return PauseOutcome::Suspended;
    }
    #[cfg(unix)]
    {
        if !sandboxed
            && let Some(pid) = pid
            && pause_process(pid)
        {
            return PauseOutcome::Suspended;
        }
        PauseOutcome::MustTerminate
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, sandboxed);
        PauseOutcome::ProxyOnly
    }
}

/// Resume a paused session tree (cgroup thaw primary, `-pgid` `SIGCONT` fallback).
pub fn resume_session_tree(pid: Option<u32>, cgroup: Option<&CgroupGuard>) -> bool {
    if let Some(cg) = cgroup
        && cg.thaw()
    {
        return true;
    }
    pid.is_some_and(resume_process)
}

/// Relay every TCP connection accepted on `listener` to the Unix socket at `socket`.
#[cfg(unix)]
pub async fn relay(listener: tokio::net::TcpListener, socket: std::path::PathBuf) {
    loop {
        let Ok((mut tcp, _)) = listener.accept().await else {
            // Out of descriptors or similar: do not spin.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        };
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Ok(mut unix) = tokio::net::UnixStream::connect(&socket).await {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
            }
        });
    }
}

/// Start the relay on `listen`, run `command` as a child with this process's environment and
/// stdio, and return its exit code (`128 + signal` when a signal ended it).
#[cfg(unix)]
pub async fn cage_exec(
    proxy_socket: &Path,
    listen: SocketAddr,
    command: &[String],
) -> std::io::Result<i32> {
    cage_exec_with_limits(proxy_socket, listen, &ResourceLimits::default(), command).await
}

/// [`cage_exec`] with `setrlimit` caps on the child and, when permitted, a cgroup v2 cap.
#[cfg(unix)]
pub async fn cage_exec_with_limits(
    proxy_socket: &Path,
    listen: SocketAddr,
    limits: &ResourceLimits,
    command: &[String],
) -> std::io::Result<i32> {
    use std::os::unix::process::ExitStatusExt;

    let (program, args) = command
        .split_first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no command"))?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tokio::spawn(relay(listener, proxy_socket.to_path_buf()));
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    apply_rlimits(&mut cmd, limits);
    let mut child = cmd.spawn()?;
    let _cgroup = child
        .id()
        .and_then(|pid| try_attach_cgroup_v2(&format!("cage-{pid}"), pid, limits));
    let status = child.wait().await?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1))
}

#[cfg(not(unix))]
pub async fn cage_exec(_: &Path, _: SocketAddr, _: &[String]) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the cage relay needs Unix sockets",
    ))
}

#[cfg(not(unix))]
pub async fn cage_exec_with_limits(
    _: &Path,
    _: SocketAddr,
    _: &ResourceLimits,
    _: &[String],
) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the cage relay needs Unix sockets",
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn argv_runs_the_bound_binary_against_the_bound_socket() {
        let argv = cage_exec_argv("127.0.0.1:3128".parse().unwrap());
        assert_eq!(
            argv,
            [
                "/tmp/premier",
                "__cage-exec",
                "--proxy-socket",
                "/tmp/premier-proxy/proxy.sock",
                "--listen",
                "127.0.0.1:3128",
                "--"
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relay_round_trips_tcp_to_the_unix_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PROXY_SOCKET);
        let upstream = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf.map(|b| b.to_ascii_uppercase()))
                .await
                .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(relay(listener, socket));

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"PING");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cage_exec_returns_the_child_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let argv = ["sh".to_owned(), "-c".to_owned(), "exit 7".to_owned()];
        let code = cage_exec(
            &dir.path().join("none.sock"),
            "127.0.0.1:0".parse().unwrap(),
            &argv,
        )
        .await
        .unwrap();
        assert_eq!(code, 7);
    }
}
