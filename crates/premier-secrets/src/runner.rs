//! Local secret execution (`premier run`) with streaming stdout/stderr redaction,
//! plus Unix POSIX FIFO virtual `.env` mount (`premier env mount`).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::SecretError;
use crate::redactor::SecretRedactor;

/// Result of running a subprocess with in-memory secret injection and stream redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub exit_code: i32,
    pub stdout_bytes_scrubbed: usize,
    pub stderr_bytes_scrubbed: usize,
}

/// Spawn `program` with `args`, injecting `env_vars` strictly into child memory
/// (never writing `.env` to disk) and scrubbing all secret encodings from stdout & stderr.
pub async fn run_with_secrets(
    program: &str,
    args: &[String],
    env_vars: &BTreeMap<String, Zeroizing<String>>,
    redact_keys: &[String],
) -> Result<RunOutput, SecretError> {
    let redactor = SecretRedactor::build(
        redact_keys
            .iter()
            .filter_map(|k| env_vars.get(k).map(|v| (k.as_str(), v.as_str()))),
    );

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::inherit());

    for (k, v) in env_vars {
        cmd.env(k, v.as_str());
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| SecretError::Io(format!("failed to spawn '{program}': {e}")))?;

    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| SecretError::Io("failed to capture child stdout".to_owned()))?;
    let mut child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| SecretError::Io("failed to capture child stderr".to_owned()))?;

    let redactor_out = redactor.clone();
    let stdout_task = tokio::spawn(async move {
        let mut stream = redactor_out.streaming();
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

    let redactor_err = redactor;
    let stderr_task = tokio::spawn(async move {
        let mut stream = redactor_err.streaming();
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
        .map_err(|e| SecretError::Io(format!("wait failed: {e}")))?;
    let stdout_bytes_scrubbed = stdout_task.await.unwrap_or(0);
    let stderr_bytes_scrubbed = stderr_task.await.unwrap_or(0);

    Ok(RunOutput {
        exit_code: status.code().unwrap_or(1),
        stdout_bytes_scrubbed,
        stderr_bytes_scrubbed,
    })
}

/// Format resolved environment entries into dotenv lines inside a `Zeroizing<String>`.
pub fn render_dotenv(env_vars: &BTreeMap<String, Zeroizing<String>>) -> Zeroizing<String> {
    let mut out = String::new();
    for (k, v) in env_vars {
        let needs_quotes =
            v.is_empty() || v.contains([' ', '\t', '\n', '\r', '"', '\'', '#', '$', '`', '\\']);
        if needs_quotes {
            let escaped = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('$', "\\$")
                .replace('`', "\\`");
            out.push_str(&format!("{k}=\"{escaped}\"\n"));
        } else {
            out.push_str(&format!("{k}={}\n", v.as_str()));
        }
    }
    Zeroizing::new(out)
}

/// Check whether POSIX FIFO `.env` mounting is supported on the current platform.
/// Callers should invoke this before resolving secrets so unsupported platforms fail early.
pub fn check_fifo_mount_supported() -> Result<(), SecretError> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(SecretError::FifoUnsupportedOnPlatform)
    }
}

/// Serve a virtual uncommittable `.env` file via POSIX `mkfifo` named pipe (Linux & macOS).
///
/// Zero plaintext ever touches the filesystem; `git add` refuses `S_IFIFO` nodes.
#[cfg(unix)]
#[allow(unsafe_code)]
pub async fn mount_fifo(
    path: &Path,
    env_vars: &BTreeMap<String, Zeroizing<String>>,
) -> Result<(), SecretError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;

    check_fifo_mount_supported()?;

    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_fifo() {
                std::fs::remove_file(path).map_err(|e| {
                    SecretError::Io(format!("failed to replace existing FIFO: {e}"))
                })?;
            } else {
                return Err(SecretError::Io(format!(
                    "refusing to overwrite existing non-FIFO path '{}'",
                    path.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(SecretError::Io(format!(
                "failed to inspect mount path '{}': {e}",
                path.display()
            )));
        }
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SecretError::Io("FIFO path contains NUL byte".to_owned()))?;
    // SAFETY: `c_path` is a valid NUL-terminated C string; mode 0o600 restricts access to owner.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        return Err(SecretError::Io(format!(
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let payload = render_dotenv(env_vars);
    let path_owned = path.to_path_buf();

    tracing::info!(path = %path_owned.display(), "serving virtual FIFO .env (Ctrl+C to unmount)");
    loop {
        // OpenOptions must outlive the open future. A temporary in `select!` is dropped too soon.
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = std::fs::remove_file(&path_owned);
                return Ok(());
            }
            opened = opts.open(&path_owned) => {
                match opened {
                    Ok(mut file) => {
                        let _ = file.write_all(payload.as_bytes()).await;
                        let _ = file.flush().await;
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&path_owned);
                        return Err(SecretError::Io(format!("FIFO write failed: {e}")));
                    }
                }
            }
        }
    }
}

/// Windows does not support POSIX filesystem FIFOs (`mkfifo`).
/// Use `premier run -- <cmd>` (universal) or WSL2 / M3 ProjFS virtual `.env`.
#[cfg(not(unix))]
pub async fn mount_fifo(
    _path: &Path,
    _env_vars: &BTreeMap<String, Zeroizing<String>>,
) -> Result<(), SecretError> {
    check_fifo_mount_supported()
}
