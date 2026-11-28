//! `premier-ssh` — Pure-Rust Git-over-SSH transport for Premier.
//!
//! Enforces the same security invariants as Git Smart HTTP v2 at the SSH boundary:
//! - Public-key authentication only (`none`, `password`, and `keyboard-interactive` are refused).
//! - Strict `exec` command allow-list: only `git-upload-pack` and `git-receive-pack` (and their
//!   two-word `git upload-pack` / `git receive-pack` aliases) are permitted. Interactive shells,
//!   PTYs, subsystems, port forwarding, shell metacharacters, and path traversal are rejected
//!   fail-closed.
//! - Supports Git Smart Protocol v2 (`GIT_PROTOCOL=version=2`) with multi-request channel framing
//!   (`ls-refs` followed by `fetch` over one SSH channel) as well as protocol v0/v1 and
//!   `git-receive-pack`.
//! - Strips HTTP `# service=...\n0000` preambles automatically so backends can share advertisement
//!   code with Smart HTTP without leaking HTTP framing onto SSH stdout.

use std::any::Any;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
pub use async_trait::async_trait;
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, decode_secret_key};
use russh::server::{
    Auth, ChannelOpenHandle, Config, Handler, Msg, PublicKeyOffer, Session, VerifiedPublicKey,
};
use russh::{
    Channel, ChannelId, ChannelOpenFailure, Disconnect, MethodKind, MethodSet, Pty, SshId,
};

/// Default maximum request buffer accepted for `git-upload-pack` over SSH (4 MiB).
pub const DEFAULT_MAX_UPLOAD_PACK_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum push payload accepted for `git-receive-pack` over SSH (512 MiB).
pub const DEFAULT_MAX_RECEIVE_PACK_BYTES: usize = 512 * 1024 * 1024;
/// Maximum total buffered bytes across all open channels on one SSH connection (512 MiB).
pub const MAX_CONN_BUFFERED_BYTES: usize = DEFAULT_MAX_RECEIVE_PACK_BYTES;
/// Maximum simultaneous open session channels per SSH connection.
const MAX_CHANNELS_PER_CONN: usize = 8;
/// Chunk size for writing stdout/stderr frames over an SSH channel (fits under 32 KiB packet cap).
const SSH_WRITE_CHUNK_BYTES: usize = 32_000;
/// RFC 4254 extended data type for stderr.
const SSH_EXTENDED_DATA_STDERR: u32 = 1;
/// Maximum accepted length of a `GIT_PROTOCOL` environment variable value.
const MAX_GIT_PROTOCOL_LEN: usize = 128;
/// Zero SHA-1 OID used by Git to represent a ref creation or deletion.
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
/// Size of an empty Git packfile: `PACK` (4) + version (4) + object count 0 (4) + SHA-1 (20).
const EMPTY_PACK_BYTES: usize = 32;
/// Open TCP connections, process-wide, admitted before the SSH handshake.
const MAX_CONNECTIONS: usize = 64;
/// Open TCP connections from one source IP, admitted before the SSH handshake.
const MAX_CONNECTIONS_PER_IP: usize = 16;
/// Authenticated connections one account may hold at once.
const MAX_CONNECTIONS_PER_USER: usize = 4;

/// Guard for one of the backend's concurrent push slots; dropping it frees the slot.
pub type PushSlot = Box<dyn Any + Send + Sync>;

type LimiterState<K> = Arc<Mutex<(usize, HashMap<K, usize>)>>;

/// Counts open connections per key and in total; a [`ConnGuard`] gives its place back on drop.
struct ConnLimiter<K: Eq + Hash> {
    state: LimiterState<K>,
    per_key: usize,
    total: usize,
}

impl<K: Eq + Hash> Clone for ConnLimiter<K> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            per_key: self.per_key,
            total: self.total,
        }
    }
}

struct ConnGuard<K: Eq + Hash> {
    state: LimiterState<K>,
    key: K,
}

impl<K: Eq + Hash + Clone> ConnLimiter<K> {
    fn new(per_key: usize, total: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new((0, HashMap::new()))),
            per_key,
            total,
        }
    }

    fn try_acquire(&self, key: K) -> Option<ConnGuard<K>> {
        let mut guard = self.state.lock().ok()?;
        let (total, by_key) = &mut *guard;
        let n = by_key.get(&key).copied().unwrap_or(0);
        if *total >= self.total || n >= self.per_key {
            return None;
        }
        *total += 1;
        by_key.insert(key.clone(), n + 1);
        Some(ConnGuard {
            state: Arc::clone(&self.state),
            key,
        })
    }
}

impl<K: Eq + Hash> Drop for ConnGuard<K> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            let (total, by_key) = &mut *guard;
            *total = total.saturating_sub(1);
            if let Some(n) = by_key.get_mut(&self.key) {
                *n -= 1;
                if *n == 0 {
                    by_key.remove(&self.key);
                }
            }
        }
    }
}

/// Git smart-protocol service requested via SSH `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitService {
    UploadPack,
    ReceivePack,
}

impl GitService {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

/// Authenticated Premier account resolved from a verified SSH public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAuthenticatedUser {
    pub username: String,
    pub is_owner: bool,
}

/// Configurable per-channel request size caps for the SSH server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshLimits {
    pub max_upload_pack_bytes: usize,
    pub max_receive_pack_bytes: usize,
}

impl Default for SshLimits {
    fn default() -> Self {
        Self {
            max_upload_pack_bytes: DEFAULT_MAX_UPLOAD_PACK_BYTES,
            max_receive_pack_bytes: DEFAULT_MAX_RECEIVE_PACK_BYTES,
        }
    }
}

/// Parsed, sanitized Git SSH `exec` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGitCommand {
    pub service: GitService,
    pub repo: String,
}

/// Backend bridging authenticated SSH Git sessions onto Premier's projected repositories.
#[async_trait]
pub trait SshGitBackend: Send + Sync + 'static {
    /// Look up an enabled account matching `username` and the presented OpenSSH public key
    /// (`"<key-type> <base64>"`). Called during key offering and again after signature
    /// verification.
    async fn authenticate_pubkey(
        &self,
        username: &str,
        key_openssh: &str,
    ) -> Option<SshAuthenticatedUser>;

    /// Render the initial ref/capability advertisement for `repo` scoped to `user`'s projected
    /// view. May include or omit the Smart HTTP `# service=...\n0000` preamble; the SSH transport
    /// strips any HTTP service preamble automatically before writing to stdout.
    async fn advertise_refs(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        service: GitService,
        protocol_v2: bool,
    ) -> std::result::Result<Vec<u8>, String>;

    /// Execute one `git-upload-pack` request (either a single protocol v2 command such as
    /// `ls-refs` / `fetch`, or a full protocol v0/v1 negotiation payload) strictly inside `user`'s
    /// projected view.
    async fn handle_upload_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        protocol_v2: bool,
        stdin: &[u8],
    ) -> std::result::Result<Vec<u8>, String>;

    /// Reserve one of the server's concurrent push slots, before any push body is accepted.
    /// The transport holds the guard until the push is processed. `Err` refuses the push with
    /// that message (e.g. the server stayed busy).
    ///
    /// The default imposes no budget, so backends without a push cap (e.g. test doubles) need not
    /// implement it; production backends must override it.
    async fn reserve_push_slot(&self) -> std::result::Result<PushSlot, String> {
        Ok(Box::new(()))
    }

    /// Execute one `git-receive-pack` push payload (`ref updates + 0000 + PACK`) against `repo`,
    /// enforcing write policy, overlay guards, and reversible projection. The caller holds a
    /// slot from [`Self::reserve_push_slot`].
    async fn handle_receive_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        stdin: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, String>;
}

/// Load an existing SSH host key from `path`, or generate a new Ed25519 host key and persist it
/// with owner-only (`0600`) permissions on Unix.
pub fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH host key {}", path.display()))?;
        let key = decode_secret_key(&raw, None)
            .map_err(|e| anyhow!("failed to decode SSH host key {}: {e}", path.display()))?;
        return Ok(key);
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let created_parent = !parent.exists();
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create SSH host key directory {}",
                parent.display()
            )
        })?;
        #[cfg(unix)]
        if created_parent {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
                || {
                    format!(
                        "failed to set 0700 permissions on SSH host key directory {}",
                        parent.display()
                    )
                },
            )?;
        }
        #[cfg(not(unix))]
        let _ = created_parent;

        if parent.file_name().and_then(|n| n.to_str()) == Some(".premier") {
            let gitignore = parent.join(".gitignore");
            if !gitignore.exists() {
                std::fs::write(&gitignore, b"*\n").with_context(|| {
                    format!(
                        "failed to write .gitignore in SSH host key directory {}",
                        parent.display()
                    )
                })?;
            }
        }
    }

    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
        .map_err(|e| anyhow!("failed to generate Ed25519 SSH host key: {e}"))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode Ed25519 SSH host key: {e}"))?;
    write_private_file(path, pem.as_bytes())
        .with_context(|| format!("failed to write SSH host key {}", path.display()))?;
    tracing::info!(path = %path.display(), "generated new Ed25519 SSH host key");
    Ok(key)
}

/// Write a secret file with owner-only (`0600`) permissions on Unix. On Windows it inherits the
/// directory's ACL (the account's own data directory), which is accepted as-is.
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Parse and strictly validate a Git SSH `exec` command.
///
/// Accepts only:
/// - `git-upload-pack '<repo>'` / `git-upload-pack "<repo>"` / `git-upload-pack <repo>`
/// - `git-receive-pack '<repo>'` / `git-receive-pack "<repo>"` / `git-receive-pack <repo>`
/// - `git upload-pack ...` / `git receive-pack ...`
///
/// Rejects arbitrary commands, extra arguments, flags, shell metacharacters, control characters,
/// and path traversal attempts (fail-closed).
pub fn parse_git_ssh_command(raw: &str) -> std::result::Result<ParsedGitCommand, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty SSH command".to_owned());
    }
    if contains_forbidden_shell_chars(trimmed) {
        return Err("forbidden character in SSH command".to_owned());
    }

    let (service, rest) = if let Some(r) = trimmed.strip_prefix("git-upload-pack ") {
        (GitService::UploadPack, r)
    } else if let Some(r) = trimmed.strip_prefix("git-receive-pack ") {
        (GitService::ReceivePack, r)
    } else if let Some(r) = trimmed.strip_prefix("git upload-pack ") {
        (GitService::UploadPack, r)
    } else if let Some(r) = trimmed.strip_prefix("git receive-pack ") {
        (GitService::ReceivePack, r)
    } else {
        return Err("only git-upload-pack and git-receive-pack are permitted".to_owned());
    };

    let arg = rest.trim();
    let unquoted = strip_single_quote_pair(arg)?;
    let repo = sanitize_repo_path(unquoted)?;
    Ok(ParsedGitCommand { service, repo })
}

fn contains_forbidden_shell_chars(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                ';' | '|'
                    | '&'
                    | '$'
                    | '`'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | '\\'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '!'
                    | '#'
                    | '~'
            )
    })
}

fn strip_single_quote_pair(arg: &str) -> std::result::Result<&str, String> {
    if arg.is_empty() {
        return Err("missing repository path".to_owned());
    }
    let inner = if let Some(s) = arg.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        s
    } else if let Some(s) = arg.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        s
    } else {
        arg
    };

    if inner.contains('\'') || inner.contains('"') {
        return Err("unexpected quote inside repository path".to_owned());
    }
    if inner.chars().any(char::is_whitespace) {
        return Err("unexpected whitespace or extra arguments in SSH command".to_owned());
    }
    Ok(inner)
}

/// Sanitize a Git SSH repository path, rejecting traversal, hidden/reserved segments, and
/// non-portable characters.
///
/// Normalizes single-segment repo names and `/<name>.git`, `/git/<name>.git`, and
/// `/git/auth/<name>.git` (with or without leading `/` or trailing `.git`) to `<name>`, matching
/// `premier-server`'s `Registry::state_for_repo`.
pub fn sanitize_repo_path(raw: &str) -> std::result::Result<String, String> {
    if raw.is_empty() || raw.len() > 255 {
        return Err("invalid repository path length".to_owned());
    }
    if contains_forbidden_shell_chars(raw) || raw.chars().any(char::is_whitespace) {
        return Err("forbidden character in repository path".to_owned());
    }
    if raw.starts_with("//") || raw.ends_with('/') {
        return Err("malformed repository path".to_owned());
    }

    let without_leading = raw.strip_prefix('/').unwrap_or(raw);
    let without_git = without_leading
        .strip_suffix(".git")
        .unwrap_or(without_leading);

    if without_git.is_empty() {
        return Err("empty repository path".to_owned());
    }

    let segments: Vec<&str> = without_git.split('/').collect();
    if segments.len() > 3 {
        return Err("repository path too deep".to_owned());
    }

    for seg in &segments {
        if seg.is_empty()
            || *seg == "."
            || *seg == ".."
            || seg.contains("..")
            || seg.starts_with('.')
            || seg.starts_with('-')
            || seg.ends_with('.')
        {
            return Err("invalid path segment in repository path".to_owned());
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("unsupported character in repository path".to_owned());
        }
    }

    let repo_name = match segments.as_slice() {
        [name] => *name,
        ["git", name] if *name != "auth" => *name,
        ["git", "auth", name] => *name,
        _ => return Err("unsupported repository path structure".to_owned()),
    };

    Ok(repo_name.to_owned())
}

/// Strictly parse a 4-byte Git pkt-line hexadecimal length header, rejecting leading `+`/`-` signs
/// and any non-hexadecimal byte.
fn parse_pkt_len(len_bytes: &[u8]) -> std::result::Result<usize, String> {
    if len_bytes.len() != 4 || !len_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "invalid pkt-line length '{}'",
            String::from_utf8_lossy(len_bytes)
        ));
    }
    let len_str =
        std::str::from_utf8(len_bytes).map_err(|_| "non-ASCII pkt-line length".to_owned())?;
    usize::from_str_radix(len_str, 16).map_err(|_| format!("invalid pkt-line length '{len_str}'"))
}

/// Format a Git-style `fatal: ...` stderr line without ever double-prefixing `"fatal: "`.
fn format_fatal_stderr(msg: &str) -> String {
    let mut body = msg;
    while let Some(rest) = body.strip_prefix("fatal: ") {
        body = rest;
    }
    if body.ends_with('\n') {
        format!("fatal: {body}")
    } else {
        format!("fatal: {body}\n")
    }
}

/// Strip the Smart HTTP `# service=...\n0000` preamble from a ref advertisement when present.
///
/// Smart HTTP prepends a pkt-line `# service=git-upload-pack\n` (or `git-receive-pack`) followed
/// by a `0000` flush packet, whereas Git over SSH begins directly with the protocol v2 capability
/// lines or the v0/v1 ref lines. Calling this makes SSH advertisement framing clean whether the
/// backend reuses Smart HTTP helpers or emits raw SSH pkt-lines.
pub fn strip_http_service_preamble(bytes: &[u8]) -> &[u8] {
    if bytes.len() < 4 {
        return bytes;
    }
    let Ok(len) = parse_pkt_len(&bytes[..4]) else {
        return bytes;
    };
    if len < 4 || len > bytes.len() {
        return bytes;
    }
    if !bytes[4..len].starts_with(b"# service=") {
        return bytes;
    }
    let rest = &bytes[len..];
    rest.strip_prefix(b"0000").unwrap_or(rest)
}

/// Result of inspecting the protocol v2 stdin buffer for the next framed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Frame {
    /// A complete protocol v2 command terminated by a `0000` flush-pkt.
    Command(Vec<u8>),
    /// A standalone `0000` flush-pkt signaling that the client is terminating the session.
    Terminate,
    /// Not enough bytes have arrived yet to complete the next pkt-line or command.
    Incomplete,
    /// Malformed pkt-line framing.
    Invalid(String),
}

/// Inspect `buf` for the next complete Git protocol v2 command terminated by a `0000` flush-pkt,
/// or a standalone `0000` flush-pkt indicating client termination.
pub fn extract_next_v2_command(buf: &mut Vec<u8>) -> V2Frame {
    if buf.len() < 4 {
        return V2Frame::Incomplete;
    }

    let first_len = match parse_pkt_len(&buf[..4]) {
        Ok(len) => len,
        Err(reason) => return V2Frame::Invalid(reason),
    };
    if first_len == 0 {
        buf.drain(..4);
        return V2Frame::Terminate;
    }

    let mut offset = 0usize;
    while offset + 4 <= buf.len() {
        let len = match parse_pkt_len(&buf[offset..offset + 4]) {
            Ok(len) => len,
            Err(reason) => return V2Frame::Invalid(reason),
        };

        match len {
            0 => {
                let end = offset + 4;
                let cmd: Vec<u8> = buf.drain(..end).collect();
                return V2Frame::Command(cmd);
            }
            1 | 2 => {
                offset += 4;
            }
            3 => {
                return V2Frame::Invalid("invalid pkt-line length 0003".to_owned());
            }
            _ => {
                if offset + len > buf.len() {
                    return V2Frame::Incomplete;
                }
                offset += len;
            }
        }
    }
    V2Frame::Incomplete
}

/// Readiness status of an incremental `git-receive-pack` stdin buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivePackReady {
    /// Need more bytes (incomplete ref-update header, or non-empty packfile still streaming).
    NeedMore,
    /// Client sent only `0000` (nothing to push); close cleanly with exit 0.
    EmptyFlush,
    /// Payload is complete and ready to dispatch immediately without waiting for `channel_eof`
    /// (all-deletion push with no packfile, or an empty 32-byte packfile with `object_count == 0`).
    ReadyToDispatch,
    /// Malformed pkt-line framing.
    Invalid(String),
}

/// Inspect an incoming `git-receive-pack` stdin buffer to detect packless deletion pushes,
/// 0-object empty packs, and empty `0000` flushes so the server never deadlocks waiting for
/// `channel_eof` while `git send-pack` waits for `report-status`.
pub fn inspect_receive_pack_buffer(buf: &[u8]) -> ReceivePackReady {
    let mut offset = 0usize;
    let mut commands = 0usize;
    let mut all_deletions = true;

    while offset + 4 <= buf.len() {
        let len = match parse_pkt_len(&buf[offset..offset + 4]) {
            Ok(len) => len,
            Err(reason) => return ReceivePackReady::Invalid(reason),
        };

        match len {
            0 => {
                let pack_offset = offset + 4;
                if commands == 0 {
                    return ReceivePackReady::EmptyFlush;
                }
                if all_deletions {
                    return ReceivePackReady::ReadyToDispatch;
                }
                let trailing = &buf[pack_offset..];
                if trailing.len() >= 12 && trailing.starts_with(b"PACK") {
                    let obj_count =
                        u32::from_be_bytes([trailing[8], trailing[9], trailing[10], trailing[11]]);
                    if obj_count == 0 && trailing.len() >= EMPTY_PACK_BYTES {
                        return ReceivePackReady::ReadyToDispatch;
                    }
                }
                return ReceivePackReady::NeedMore;
            }
            1 | 2 => {
                offset += 4;
            }
            3 => {
                return ReceivePackReady::Invalid("invalid pkt-line length 0003".to_owned());
            }
            _ => {
                if offset + len > buf.len() {
                    return ReceivePackReady::NeedMore;
                }
                let payload = &buf[offset + 4..offset + len];
                let before_nul = payload.split(|&b| b == 0).next().unwrap_or(payload);
                let Ok(line) = std::str::from_utf8(before_nul) else {
                    return ReceivePackReady::Invalid("non-UTF-8 receive-pack command".to_owned());
                };
                let line = line.trim_end_matches(['\r', '\n']);
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(_old_oid), Some(new_oid), Some(_ref_name)) => {
                        commands += 1;
                        if new_oid != ZERO_OID {
                            all_deletions = false;
                        }
                    }
                    _ => {
                        commands += 1;
                        all_deletions = false;
                    }
                }
                offset += len;
            }
        }
    }

    ReceivePackReady::NeedMore
}

/// Incremental negotiation state for Git wire protocol v0/v1 `git-upload-pack`.
#[derive(Debug, Default)]
pub struct V0UploadState {
    wants_complete: bool,
    wants_section: Vec<u8>,
    accumulated_haves: Vec<u8>,
}

/// Next action derived from inspecting a protocol v0/v1 `git-upload-pack` stdin buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V0UploadAction {
    /// Need more bytes before the next negotiation boundary arrives.
    NeedMore,
    /// Client sent `0000` with zero `want` lines (already up to date / empty repo).
    EmptyFlush,
    /// Initial `want ... 0000` section was parsed; continue inspecting remaining buffer bytes.
    WantsAccepted,
    /// Client sent a `have ... 0000` negotiation batch without `done`; dispatch or reply
    /// `0008NAK\n` while keeping the channel open.
    HaveBatch(Vec<u8>),
    /// Client sent `0009done\n`; dispatch the full `wants + accumulated_haves + done` payload and
    /// close the channel.
    Done(Vec<u8>),
    /// Malformed pkt-line framing.
    Invalid(String),
}

impl V0UploadState {
    fn buffered_bytes(&self) -> usize {
        self.wants_section.len() + self.accumulated_haves.len()
    }

    fn clear(&mut self) {
        self.wants_complete = false;
        self.wants_section.clear();
        self.accumulated_haves.clear();
    }

    /// Consume the next protocol v0/v1 framing unit from `buf`.
    pub fn advance(&mut self, buf: &mut Vec<u8>) -> V0UploadAction {
        if !self.wants_complete {
            let mut offset = 0usize;
            let mut saw_want = false;
            while offset + 4 <= buf.len() {
                let len = match parse_pkt_len(&buf[offset..offset + 4]) {
                    Ok(len) => len,
                    Err(reason) => return V0UploadAction::Invalid(reason),
                };
                match len {
                    0 => {
                        let end = offset + 4;
                        let section: Vec<u8> = buf.drain(..end).collect();
                        if !saw_want {
                            return V0UploadAction::EmptyFlush;
                        }
                        self.wants_section = section;
                        self.wants_complete = true;
                        return V0UploadAction::WantsAccepted;
                    }
                    1 | 2 => {
                        offset += 4;
                    }
                    3 => {
                        return V0UploadAction::Invalid("invalid pkt-line length 0003".to_owned());
                    }
                    _ => {
                        if offset + len > buf.len() {
                            return V0UploadAction::NeedMore;
                        }
                        let payload = &buf[offset + 4..offset + len];
                        if payload.starts_with(b"want ") {
                            saw_want = true;
                        }
                        offset += len;
                    }
                }
            }
            return V0UploadAction::NeedMore;
        }

        let mut offset = 0usize;
        while offset + 4 <= buf.len() {
            let len = match parse_pkt_len(&buf[offset..offset + 4]) {
                Ok(len) => len,
                Err(reason) => return V0UploadAction::Invalid(reason),
            };
            match len {
                0 => {
                    self.accumulated_haves.extend_from_slice(&buf[..offset]);
                    let batch: Vec<u8> = buf.drain(..offset + 4).collect();
                    return V0UploadAction::HaveBatch(batch);
                }
                1 | 2 => {
                    offset += 4;
                }
                3 => {
                    return V0UploadAction::Invalid("invalid pkt-line length 0003".to_owned());
                }
                _ => {
                    if offset + len > buf.len() {
                        return V0UploadAction::NeedMore;
                    }
                    let payload = &buf[offset + 4..offset + len];
                    if payload == b"done\n" || payload == b"done" || payload == b"done\r\n" {
                        self.accumulated_haves.extend_from_slice(&buf[..offset]);
                        let done_pkt = buf[offset..offset + len].to_vec();
                        buf.drain(..offset + len);
                        let mut full = Vec::with_capacity(
                            self.wants_section.len()
                                + self.accumulated_haves.len()
                                + done_pkt.len(),
                        );
                        full.extend_from_slice(&self.wants_section);
                        full.extend_from_slice(&self.accumulated_haves);
                        full.extend_from_slice(&done_pkt);
                        self.clear();
                        return V0UploadAction::Done(full);
                    }
                    offset += len;
                }
            }
        }
        V0UploadAction::NeedMore
    }

    /// Assemble any buffered v0/v1 state together with remaining `stdin_buf` on `channel_eof`.
    fn take_eof_payload(&mut self, stdin_buf: &mut Vec<u8>) -> Vec<u8> {
        let mut full = Vec::with_capacity(
            self.wants_section.len() + self.accumulated_haves.len() + stdin_buf.len(),
        );
        full.extend_from_slice(&self.wants_section);
        full.extend_from_slice(&self.accumulated_haves);
        full.extend_from_slice(stdin_buf);
        self.clear();
        stdin_buf.clear();
        full
    }
}

/// Whether `buf` is a whole `git-receive-pack` command list (ending in its flush, nothing after)
/// whose every command deletes a ref. Git sends no pack for such a push, and over SSH it does
/// not close stdin either: it waits for the report, so the server must answer without an EOF.
pub fn is_complete_delete_only_push(buf: &[u8]) -> bool {
    let mut offset = 0usize;
    let mut commands = 0usize;
    while offset + 4 <= buf.len() {
        let Some(len) = std::str::from_utf8(&buf[offset..offset + 4])
            .ok()
            .and_then(|s| usize::from_str_radix(s, 16).ok())
        else {
            return false;
        };
        if len == 0 {
            return commands > 0 && offset + 4 == buf.len();
        }
        if len <= 4 || offset + len > buf.len() {
            return false;
        }
        let line = &buf[offset + 4..offset + len];
        let line = line.split(|&b| b == 0).next().unwrap_or(line);
        let mut parts = line.split(|&b| b == b' ');
        let (Some(_old), Some(new), Some(_name)) = (parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        if new.is_empty() || !new.iter().all(|&b| b == b'0') {
            return false;
        }
        commands += 1;
        offset += len;
    }
    false
}

/// Check whether a `GIT_PROTOCOL` value safely enables Git wire protocol v2.
fn parse_git_protocol_v2(value: &str) -> std::result::Result<bool, String> {
    if value.len() > MAX_GIT_PROTOCOL_LEN {
        return Err("GIT_PROTOCOL value too long".to_owned());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b':' | b'_' | b'-' | b'.'))
    {
        return Err("invalid character in GIT_PROTOCOL".to_owned());
    }
    Ok(value.split(':').any(|token| token == "version=2"))
}

/// Start the pure-Rust Git-over-SSH server bound to `bind` with default request size caps
/// (4 MiB for `git-upload-pack`, 512 MiB for `git-receive-pack`).
pub async fn serve_ssh(
    bind: SocketAddr,
    host_key_path: PathBuf,
    backend: Arc<dyn SshGitBackend>,
) -> Result<()> {
    serve_ssh_with_limits(bind, host_key_path, backend, SshLimits::default()).await
}

/// Start the pure-Rust Git-over-SSH server with explicit request size limits.
pub async fn serve_ssh_with_limits(
    bind: SocketAddr,
    host_key_path: PathBuf,
    backend: Arc<dyn SshGitBackend>,
    limits: SshLimits,
) -> Result<()> {
    let host_key = load_or_generate_host_key(&host_key_path)?;
    let config = Config {
        server_id: SshId::Standard("SSH-2.0-Premier_0.1".into()),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        max_auth_attempts: 6,
        ..Config::default()
    };

    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("SSH server failed to bind {bind}"))?;
    // Admission happens here, before the handshake: russh's own accept loop takes everyone.
    let ip_limiter = ConnLimiter::<IpAddr>::new(MAX_CONNECTIONS_PER_IP, MAX_CONNECTIONS);
    let user_limiter = ConnLimiter::<String>::new(MAX_CONNECTIONS_PER_USER, usize::MAX);
    tracing::info!(%bind, "Premier Git-over-SSH server listening");
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // e.g. out of file descriptors: back off instead of spinning.
                tracing::warn!(error = %e, "SSH accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(ip_guard) = ip_limiter.try_acquire(peer.ip()) else {
            tracing::warn!(%peer, "SSH connection refused: connection limit reached");
            continue;
        };
        tracing::debug!(%peer, "accepted SSH connection");
        let mut handler = GitSshSession::new(Arc::clone(&backend), limits, user_limiter.clone());
        handler.peer_addr = Some(peer);
        handler._ip_guard = Some(ip_guard);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let result = match russh::server::run_stream(config, socket, handler).await {
                Ok(session) => session.await,
                Err(e) => Err(e),
            };
            if let Err(error) = result {
                tracing::debug!(%peer, error = %error, "SSH session ended with error");
            }
        });
    }
}

struct ChannelState {
    protocol_v2: bool,
    command: Option<ParsedGitCommand>,
    stdin_buf: Vec<u8>,
    v0_upload: V0UploadState,
    dispatched: bool,
    finished: bool,
    /// Held from `exec git-receive-pack` until the push is processed.
    push_slot: Option<PushSlot>,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            protocol_v2: false,
            command: None,
            stdin_buf: Vec::new(),
            v0_upload: V0UploadState::default(),
            dispatched: false,
            finished: false,
            push_slot: None,
        }
    }

    fn buffered_bytes(&self) -> usize {
        self.stdin_buf.len() + self.v0_upload.buffered_bytes()
    }

    fn clear_buffers(&mut self) -> usize {
        let freed = self.buffered_bytes();
        self.stdin_buf = Vec::new();
        self.v0_upload.clear();
        freed
    }

    /// Mark the channel done, drop its buffers and push slot; returns the freed buffered bytes
    /// so the caller can release them from the per-connection budget.
    fn finish(&mut self) -> usize {
        let freed = self.clear_buffers();
        self.dispatched = true;
        self.finished = true;
        self.push_slot = None;
        freed
    }
}

/// Append incoming `data` onto `state` while enforcing both the per-channel `max_channel_bytes`
/// cap and the per-connection `max_conn_bytes` budget across all channels on the SSH session.
fn buffer_channel_data(
    state: &mut ChannelState,
    conn_buffered_bytes: &mut usize,
    data: &[u8],
    max_channel_bytes: usize,
    max_conn_bytes: usize,
    service: GitService,
) -> std::result::Result<(), String> {
    if state.buffered_bytes().saturating_add(data.len()) > max_channel_bytes {
        return Err(format!(
            "{} request exceeded maximum allowed size of {} bytes",
            service.as_str(),
            max_channel_bytes
        ));
    }
    if conn_buffered_bytes.saturating_add(data.len()) > max_conn_bytes {
        return Err(format!(
            "SSH connection buffer exceeded maximum allowed size of {} bytes",
            max_conn_bytes
        ));
    }
    state.stdin_buf.extend_from_slice(data);
    *conn_buffered_bytes = conn_buffered_bytes.saturating_add(data.len());
    Ok(())
}

struct GitSshSession {
    peer_addr: Option<SocketAddr>,
    backend: Arc<dyn SshGitBackend>,
    limits: SshLimits,
    authenticated_user: Option<SshAuthenticatedUser>,
    /// `(ssh user, OpenSSH key)` that authenticated, re-checked for every new command.
    auth_key: Option<(String, String)>,
    channels: HashMap<ChannelId, ChannelState>,
    conn_buffered_bytes: usize,
    user_limiter: ConnLimiter<String>,
    user_guard: Option<ConnGuard<String>>,
    _ip_guard: Option<ConnGuard<IpAddr>>,
}

impl GitSshSession {
    fn new(
        backend: Arc<dyn SshGitBackend>,
        limits: SshLimits,
        user_limiter: ConnLimiter<String>,
    ) -> Self {
        Self {
            peer_addr: None,
            backend,
            limits,
            authenticated_user: None,
            auth_key: None,
            channels: HashMap::new(),
            conn_buffered_bytes: 0,
            user_limiter,
            user_guard: None,
            _ip_guard: None,
        }
    }

    /// Re-run the full key check (account enabled, key still on it, current role) so a revoked
    /// key or a disabled/demoted account takes effect on the next command of a live connection.
    /// Also takes this connection's place under the per-account limit.
    async fn reauthorize(&mut self) -> std::result::Result<SshAuthenticatedUser, String> {
        let denied = || "SSH key or account is no longer authorized".to_owned();
        let (ssh_user, key) = self.auth_key.clone().ok_or_else(denied)?;
        let cached = self.authenticated_user.as_ref().ok_or_else(denied)?;
        let fresh = self
            .backend
            .authenticate_pubkey(&ssh_user, &key)
            .await
            .filter(|fresh| fresh.username == cached.username)
            .ok_or_else(denied)?;
        if self.user_guard.is_none() {
            let guard = self.user_limiter.try_acquire(fresh.username.clone());
            self.user_guard = Some(guard.ok_or_else(|| {
                format!(
                    "too many concurrent SSH connections for this account \
                     (limit {MAX_CONNECTIONS_PER_USER}); retry shortly"
                )
            })?);
        }
        self.authenticated_user = Some(fresh.clone());
        Ok(fresh)
    }

    /// Run the request buffered on `channel` (at EOF, or once a delete-only push is complete).
    async fn run_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        let Some(user) = self.authenticated_user.clone() else {
            return Ok(());
        };

        // `_push_slot` lives until this push has been processed.
        let (service, repo, protocol_v2, payload, _push_slot) = {
            let Some(state) = self.channels.get_mut(&channel) else {
                return Ok(());
            };
            if state.finished || state.dispatched {
                return Ok(());
            }
            let Some(cmd) = state.command.as_ref() else {
                let freed = state.finish();
                self.conn_buffered_bytes = self.conn_buffered_bytes.saturating_sub(freed);
                return Self::finish_channel(session, channel, 0);
            };
            let service = cmd.service;
            let repo = cmd.repo.clone();
            let protocol_v2 = state.protocol_v2;
            let freed = state.buffered_bytes();
            let payload = if service == GitService::UploadPack && !protocol_v2 {
                state.v0_upload.take_eof_payload(&mut state.stdin_buf)
            } else {
                state.v0_upload.clear();
                std::mem::take(&mut state.stdin_buf)
            };
            let push_slot = state.push_slot.take();
            state.finished = true;
            state.dispatched = true;
            self.conn_buffered_bytes = self.conn_buffered_bytes.saturating_sub(freed);
            (service, repo, protocol_v2, payload, push_slot)
        };

        if payload.is_empty() || payload == b"0000" {
            return Self::finish_channel(session, channel, 0);
        }

        let response = match service {
            GitService::UploadPack => {
                self.backend
                    .handle_upload_pack(&user, &repo, protocol_v2, &payload)
                    .await
            }
            GitService::ReceivePack => {
                self.backend
                    .handle_receive_pack(&user, &repo, payload)
                    .await
            }
        };

        match response {
            Ok(bytes) => {
                Self::write_stdout(session, channel, &bytes)?;
                Self::finish_channel(session, channel, 0)
            }
            Err(reason) => self.fail_channel(session, channel, &reason),
        }
    }

    /// Admit one push on this connection: at most one at a time, and only with a server push
    /// slot, taken before any of its body is accepted.
    async fn admit_push(&self) -> std::result::Result<PushSlot, String> {
        if self.channels.values().any(|st| st.push_slot.is_some()) {
            return Err("only one push at a time per SSH connection".to_owned());
        }
        self.backend.reserve_push_slot().await
    }

    fn reject_publickey() -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
            partial_success: false,
        }
    }

    fn write_stdout(session: &mut Session, channel: ChannelId, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(SSH_WRITE_CHUNK_BYTES) {
            session.data(channel, chunk.to_vec())?;
        }
        Ok(())
    }

    fn write_stderr(session: &mut Session, channel: ChannelId, msg: &str) -> Result<()> {
        for chunk in msg.as_bytes().chunks(SSH_WRITE_CHUNK_BYTES) {
            session.extended_data(channel, SSH_EXTENDED_DATA_STDERR, chunk.to_vec())?;
        }
        Ok(())
    }

    fn finish_channel(session: &mut Session, channel: ChannelId, exit_code: u32) -> Result<()> {
        session.exit_status_request(channel, exit_code)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    fn mark_channel_finished_and_clear(&mut self, channel: ChannelId) {
        if let Some(state) = self.channels.get_mut(&channel) {
            let freed = state.finish();
            self.conn_buffered_bytes = self.conn_buffered_bytes.saturating_sub(freed);
        }
    }

    /// Reject an unsupported channel request per RFC 4254 without sending channel data before
    /// `SSH_MSG_CHANNEL_FAILURE`.
    fn reject_channel_request(&mut self, session: &mut Session, channel: ChannelId) -> Result<()> {
        self.mark_channel_finished_and_clear(channel);
        session.channel_failure(channel)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    /// Accept a disallowed `exec` request per RFC 4254 so the `fatal: ...` diagnostic reaches
    /// OpenSSH/Git on stderr, then exit with status 1 and close the channel.
    fn fail_exec_request(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        msg: &str,
    ) -> Result<()> {
        session.channel_success(channel)?;
        self.fail_channel(session, channel, msg)
    }

    fn fail_channel(&mut self, session: &mut Session, channel: ChannelId, msg: &str) -> Result<()> {
        self.mark_channel_finished_and_clear(channel);
        let line = format_fatal_stderr(msg);
        Self::write_stderr(session, channel, &line)?;
        Self::finish_channel(session, channel, 1)
    }

    fn max_bytes_for(&self, service: GitService) -> usize {
        match service {
            GitService::UploadPack => self.limits.max_upload_pack_bytes,
            GitService::ReceivePack => self.limits.max_receive_pack_bytes,
        }
    }
}

impl Handler for GitSshSession {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Self::reject_publickey())
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Self::reject_publickey())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        let Ok(openssh) = offer.public_key.to_openssh() else {
            return Ok(Self::reject_publickey());
        };
        if self
            .backend
            .authenticate_pubkey(user, &openssh)
            .await
            .is_some()
        {
            Ok(Auth::Accept)
        } else {
            Ok(Self::reject_publickey())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        verified: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let Ok(openssh) = verified.public_key.to_openssh() else {
            return Ok(Self::reject_publickey());
        };
        match self.backend.authenticate_pubkey(user, &openssh).await {
            Some(auth_user) => {
                tracing::info!(
                    peer = ?self.peer_addr,
                    username = %auth_user.username,
                    "SSH publickey authentication succeeded"
                );
                // Over the per-account limit: no place yet; `reauthorize` retries, then refuses.
                self.user_guard = self.user_limiter.try_acquire(auth_user.username.clone());
                self.auth_key = Some((user.to_owned(), openssh));
                self.authenticated_user = Some(auth_user);
                Ok(Auth::Accept)
            }
            None => {
                tracing::warn!(
                    peer = ?self.peer_addr,
                    ssh_user = %user,
                    "SSH publickey authentication rejected"
                );
                Ok(Self::reject_publickey())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.authenticated_user.is_none() || self.channels.len() >= MAX_CHANNELS_PER_CONN {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.channels.insert(channel.id(), ChannelState::new());
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject_channel_request(session, channel)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL"
            && let Ok(is_v2) = parse_git_protocol_v2(variable_value)
            && let Some(state) = self.channels.get_mut(&channel)
            && state.command.is_none()
        {
            state.protocol_v2 = is_v2;
            session.channel_success(channel)?;
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.authenticated_user.is_none() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let user = match self.reauthorize().await {
            Ok(user) => user,
            Err(reason) => {
                tracing::warn!(peer = ?self.peer_addr, reason = %reason, "SSH command refused");
                self.fail_exec_request(session, channel, &reason)?;
                session.disconnect(Disconnect::ByApplication, &reason, "")?;
                return Ok(());
            }
        };

        let Some(protocol_v2) = self
            .channels
            .get(&channel)
            .filter(|st| st.command.is_none() && !st.finished)
            .map(|st| st.protocol_v2)
        else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Ok(raw_cmd) = std::str::from_utf8(data) else {
            return self.fail_exec_request(session, channel, "non-UTF-8 SSH command");
        };

        let parsed = match parse_git_ssh_command(raw_cmd) {
            Ok(cmd) => cmd,
            Err(reason) => {
                tracing::warn!(
                    peer = ?self.peer_addr,
                    username = %user.username,
                    reason = %reason,
                    "rejected disallowed SSH exec command"
                );
                return self.fail_exec_request(session, channel, &reason);
            }
        };

        let effective_v2 = protocol_v2 && parsed.service == GitService::UploadPack;
        let push_slot = if parsed.service == GitService::ReceivePack {
            match self.admit_push().await {
                Ok(slot) => Some(slot),
                Err(reason) => return self.fail_exec_request(session, channel, &reason),
            }
        } else {
            None
        };
        session.channel_success(channel)?;

        match self
            .backend
            .advertise_refs(&user, &parsed.repo, parsed.service, effective_v2)
            .await
        {
            Ok(raw_adv) => {
                let adv = strip_http_service_preamble(&raw_adv);
                Self::write_stdout(session, channel, adv)?;
                if let Some(state) = self.channels.get_mut(&channel) {
                    state.protocol_v2 = effective_v2;
                    state.command = Some(parsed);
                    state.push_slot = push_slot;
                }
                Ok(())
            }
            Err(reason) => self.fail_channel(session, channel, &reason),
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(user) = self.authenticated_user.clone() else {
            return Ok(());
        };

        let (service, repo, protocol_v2, max_bytes) = {
            let Some(state) = self.channels.get(&channel) else {
                return Ok(());
            };
            if state.finished || state.dispatched {
                return Ok(());
            }
            let Some(cmd) = state.command.as_ref() else {
                return Ok(());
            };
            (
                cmd.service,
                cmd.repo.clone(),
                state.protocol_v2,
                self.max_bytes_for(cmd.service),
            )
        };

        let buffer_res = {
            let Some(state) = self.channels.get_mut(&channel) else {
                return Ok(());
            };
            buffer_channel_data(
                state,
                &mut self.conn_buffered_bytes,
                data,
                max_bytes,
                MAX_CONN_BUFFERED_BYTES,
                service,
            )
        };
        if let Err(reason) = buffer_res {
            return self.fail_channel(session, channel, &reason);
        }

        // A delete-only push sends no pack and keeps stdin open until it reads the report.
        if service == GitService::ReceivePack
            && self
                .channels
                .get(&channel)
                .is_some_and(|st| is_complete_delete_only_push(&st.stdin_buf))
        {
            return self.run_request(channel, session).await;
        }

        match (service, protocol_v2) {
            // In Git protocol v2 over SSH, the client sends one command terminated by `0000`
            // (e.g. `ls-refs`) and waits for the server's response before sending `fetch` (or a
            // standalone `0000` disconnect) on the same SSH channel.
            (GitService::UploadPack, true) => loop {
                let frame = {
                    let Some(state) = self.channels.get_mut(&channel) else {
                        return Ok(());
                    };
                    let before = state.buffered_bytes();
                    let frame = extract_next_v2_command(&mut state.stdin_buf);
                    let freed = before.saturating_sub(state.buffered_bytes());
                    self.conn_buffered_bytes = self.conn_buffered_bytes.saturating_sub(freed);
                    frame
                };

                match frame {
                    V2Frame::Command(next_cmd) => {
                        match self
                            .backend
                            .handle_upload_pack(&user, &repo, true, &next_cmd)
                            .await
                        {
                            Ok(response) => Self::write_stdout(session, channel, &response)?,
                            Err(reason) => return self.fail_channel(session, channel, &reason),
                        }
                    }
                    V2Frame::Terminate => {
                        self.mark_channel_finished_and_clear(channel);
                        return Self::finish_channel(session, channel, 0);
                    }
                    V2Frame::Incomplete => break,
                    V2Frame::Invalid(reason) => {
                        return self.fail_channel(session, channel, &reason);
                    }
                }
            },
            // In Git protocol v0/v1 over SSH, the client does NOT send EOF while waiting for
            // `0008NAK\n` during `have` negotiation or for the packfile after `0009done\n`.
            (GitService::UploadPack, false) => loop {
                let action = {
                    let Some(state) = self.channels.get_mut(&channel) else {
                        return Ok(());
                    };
                    let before = state.buffered_bytes();
                    let action = state.v0_upload.advance(&mut state.stdin_buf);
                    let freed = before.saturating_sub(state.buffered_bytes());
                    self.conn_buffered_bytes = self.conn_buffered_bytes.saturating_sub(freed);
                    action
                };

                match action {
                    V0UploadAction::NeedMore => break,
                    V0UploadAction::WantsAccepted => continue,
                    V0UploadAction::EmptyFlush => {
                        self.mark_channel_finished_and_clear(channel);
                        return Self::finish_channel(session, channel, 0);
                    }
                    V0UploadAction::HaveBatch(batch) => {
                        match self
                            .backend
                            .handle_upload_pack(&user, &repo, false, &batch)
                            .await
                        {
                            Ok(response) if response.is_empty() => {
                                Self::write_stdout(session, channel, b"0008NAK\n")?;
                            }
                            Ok(response) => {
                                Self::write_stdout(session, channel, &response)?;
                            }
                            Err(reason) => return self.fail_channel(session, channel, &reason),
                        }
                    }
                    V0UploadAction::Done(full_payload) => {
                        self.mark_channel_finished_and_clear(channel);
                        match self
                            .backend
                            .handle_upload_pack(&user, &repo, false, &full_payload)
                            .await
                        {
                            Ok(response) => {
                                Self::write_stdout(session, channel, &response)?;
                                return Self::finish_channel(session, channel, 0);
                            }
                            Err(reason) => return self.fail_channel(session, channel, &reason),
                        }
                    }
                    V0UploadAction::Invalid(reason) => {
                        return self.fail_channel(session, channel, &reason);
                    }
                }
            },
            // For `git-receive-pack`, packless pushes (all deletions, 0-object empty pack, or
            // empty `0000` flush) leave stdin open while `git send-pack` waits for `report-status`.
            // Dispatch those immediately so they never deadlock waiting for `channel_eof`.
            (GitService::ReceivePack, _) => {
                let readiness = {
                    let Some(state) = self.channels.get(&channel) else {
                        return Ok(());
                    };
                    inspect_receive_pack_buffer(&state.stdin_buf)
                };

                match readiness {
                    ReceivePackReady::NeedMore => {}
                    ReceivePackReady::EmptyFlush => {
                        self.mark_channel_finished_and_clear(channel);
                        return Self::finish_channel(session, channel, 0);
                    }
                    ReceivePackReady::ReadyToDispatch => {
                        return self.run_request(channel, session).await;
                    }
                    ReceivePackReady::Invalid(reason) => {
                        return self.fail_channel(session, channel, &reason);
                    }
                }
            }
        }

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.run_request(channel, session).await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&channel) {
            self.conn_buffered_bytes = self
                .conn_buffered_bytes
                .saturating_sub(state.buffered_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pkt_line(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() + 4;
        let mut out = format!("{len:04x}").into_bytes();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_standard_git_ssh_commands() {
        assert_eq!(
            parse_git_ssh_command("git-upload-pack '/repo.git'").unwrap(),
            ParsedGitCommand {
                service: GitService::UploadPack,
                repo: "repo".to_owned(),
            }
        );
        assert_eq!(
            parse_git_ssh_command("git-receive-pack '/notes.git'").unwrap(),
            ParsedGitCommand {
                service: GitService::ReceivePack,
                repo: "notes".to_owned(),
            }
        );
        assert_eq!(
            parse_git_ssh_command("git upload-pack \"/git/myrepo.git\"").unwrap(),
            ParsedGitCommand {
                service: GitService::UploadPack,
                repo: "myrepo".to_owned(),
            }
        );
        assert_eq!(
            parse_git_ssh_command("git upload-pack '/git/auth/myrepo.git'").unwrap(),
            ParsedGitCommand {
                service: GitService::UploadPack,
                repo: "myrepo".to_owned(),
            }
        );
        assert_eq!(
            parse_git_ssh_command("git receive-pack /my_repo-1").unwrap(),
            ParsedGitCommand {
                service: GitService::ReceivePack,
                repo: "my_repo-1".to_owned(),
            }
        );
    }

    #[test]
    fn normalizes_repo_paths_and_rejects_unrecognized_multi_segment_paths() {
        assert_eq!(sanitize_repo_path("myrepo").unwrap(), "myrepo");
        assert_eq!(sanitize_repo_path("myrepo.git").unwrap(), "myrepo");
        assert_eq!(sanitize_repo_path("/myrepo.git").unwrap(), "myrepo");
        assert_eq!(sanitize_repo_path("/git/myrepo.git").unwrap(), "myrepo");
        assert_eq!(sanitize_repo_path("git/myrepo.git").unwrap(), "myrepo");
        assert_eq!(
            sanitize_repo_path("/git/auth/myrepo.git").unwrap(),
            "myrepo"
        );
        assert_eq!(sanitize_repo_path("git/auth/myrepo").unwrap(), "myrepo");

        // Unrecognized multi-segment paths and `/git/auth` without a repo name are rejected.
        assert!(sanitize_repo_path("/acme/platform.git").is_err());
        assert!(sanitize_repo_path("/git/auth").is_err());
        assert!(sanitize_repo_path("/git/auth.git").is_err());
        assert!(sanitize_repo_path("/git/foo/bar.git").is_err());
        assert!(sanitize_repo_path("/git/auth/foo/bar.git").is_err());
    }

    #[test]
    fn rejects_shell_injection_and_arbitrary_commands() {
        let disallowed = [
            "",
            "sh",
            "/bin/sh -c id",
            "git status",
            "git-upload-archive '/repo.git'",
            "git-upload-pack '/repo.git'; id",
            "git-upload-pack '/repo.git' | cat /etc/passwd",
            "git-upload-pack '/repo.git' && whoami",
            "git-upload-pack '`id`'",
            "git-upload-pack '$(id)'",
            "git-upload-pack '/repo.git'\nid",
            "git-upload-pack '--upload-pack=evil /repo.git'",
            "git-upload-pack '-repo.git'",
            "git-upload-pack '/repo.git' extra",
            "git-upload-pack \"/repo'bad.git\"",
            "git-receive-pack '/repo>out'",
        ];

        for cmd in disallowed {
            assert!(
                parse_git_ssh_command(cmd).is_err(),
                "expected command to be rejected: {cmd:?}"
            );
        }
    }

    #[test]
    fn rejects_path_traversal_and_hidden_segments() {
        let bad_paths = [
            "",
            "/",
            "//repo.git",
            "/repo/",
            "../secret.git",
            "/../etc/passwd",
            "/org/../secret.git",
            "/git/../secret.git",
            "/git/auth/../secret.git",
            "/repo/..",
            "/.",
            "/.git",
            "/git/.git",
            "/git/auth/.git",
            "/.premier/auth.json",
            "/repo/.hidden",
            "/git/.hidden.git",
            "/repo..name",
            "/a/b/c/d/e",
            "/-flag",
            "/repo\\win",
            "/repo\0null",
        ];

        for path in bad_paths {
            assert!(
                sanitize_repo_path(path).is_err(),
                "expected repo path to be rejected: {path:?}"
            );
        }
    }

    #[test]
    fn strips_http_service_preamble_for_ssh_advertisements() {
        let http_v2 =
            b"001e# service=git-upload-pack\n0000000eversion 2\n0016agent=premier/0.1\n0000";
        assert_eq!(
            strip_http_service_preamble(http_v2),
            b"000eversion 2\n0016agent=premier/0.1\n0000"
        );

        let http_receive = b"001f# service=git-receive-pack\n0000003f0000000000000000000000000000000000000000 capabilities^{}\0atomic\n0000";
        assert_eq!(
            strip_http_service_preamble(http_receive),
            b"003f0000000000000000000000000000000000000000 capabilities^{}\0atomic\n0000"
        );

        // Already SSH-framed (no `# service=` header): returned untouched.
        let raw_ssh = b"000eversion 2\n0000";
        assert_eq!(strip_http_service_preamble(raw_ssh), raw_ssh);
    }

    #[test]
    fn extracts_sequential_protocol_v2_commands_and_terminate_flush() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"0014command=ls-refs\n0001000csymrefs\n0000");
        buf.extend_from_slice(b"0012command=fetch\n00010009done\n00000000");

        assert_eq!(
            extract_next_v2_command(&mut buf),
            V2Frame::Command(b"0014command=ls-refs\n0001000csymrefs\n0000".to_vec())
        );

        assert_eq!(
            extract_next_v2_command(&mut buf),
            V2Frame::Command(b"0012command=fetch\n00010009done\n0000".to_vec())
        );

        // Trailing standalone `0000` flush signals clean session termination.
        assert_eq!(extract_next_v2_command(&mut buf), V2Frame::Terminate);
        assert!(buf.is_empty());
        assert_eq!(extract_next_v2_command(&mut buf), V2Frame::Incomplete);
    }

    #[test]
    fn protocol_v2_waits_for_incomplete_pkt_line() {
        let mut buf = b"0014command=ls-re".to_vec();
        assert_eq!(extract_next_v2_command(&mut buf), V2Frame::Incomplete);
        buf.extend_from_slice(b"fs\n0000");
        assert_eq!(
            extract_next_v2_command(&mut buf),
            V2Frame::Command(b"0014command=ls-refs\n0000".to_vec())
        );
    }

    #[test]
    fn rejects_non_hex_and_plus_prefixed_pkt_line_lengths() {
        assert!(parse_pkt_len(b"+004").is_err());
        assert!(parse_pkt_len(b"-004").is_err());
        assert!(parse_pkt_len(b"000g").is_err());
        assert!(parse_pkt_len(b" 004").is_err());
        assert_eq!(parse_pkt_len(b"001a").unwrap(), 0x1a);

        let mut v2_buf = b"+004".to_vec();
        assert!(matches!(
            extract_next_v2_command(&mut v2_buf),
            V2Frame::Invalid(_)
        ));

        assert!(matches!(
            inspect_receive_pack_buffer(b"+004"),
            ReceivePackReady::Invalid(_)
        ));

        let mut v0 = V0UploadState::default();
        let mut v0_buf = b"+004".to_vec();
        assert!(matches!(
            v0.advance(&mut v0_buf),
            V0UploadAction::Invalid(_)
        ));
    }

    #[test]
    fn receive_pack_detects_packless_deletions_empty_pack_and_empty_flush() {
        let old = "1111111111111111111111111111111111111111";
        let new = "2222222222222222222222222222222222222222";

        // 1. Standalone `0000` (nothing to push).
        assert_eq!(
            inspect_receive_pack_buffer(b"0000"),
            ReceivePackReady::EmptyFlush
        );

        // 2. All-deletion push (no packfile follows `0000`).
        let mut del_buf = pkt_line(
            format!("{old} {ZERO_OID} refs/heads/stale\0report-status side-band-64k\n").as_bytes(),
        );
        del_buf.extend_from_slice(&pkt_line(
            format!("{old} {ZERO_OID} refs/heads/other\n").as_bytes(),
        ));
        assert_eq!(
            inspect_receive_pack_buffer(&del_buf),
            ReceivePackReady::NeedMore
        );
        del_buf.extend_from_slice(b"0000");
        assert_eq!(
            inspect_receive_pack_buffer(&del_buf),
            ReceivePackReady::ReadyToDispatch
        );

        // 3. Non-deletion ref update followed by an empty 32-byte packfile (`object_count == 0`).
        let mut empty_pack_buf =
            pkt_line(format!("{old} {new} refs/heads/main\0report-status\n").as_bytes());
        empty_pack_buf.extend_from_slice(b"0000");
        assert_eq!(
            inspect_receive_pack_buffer(&empty_pack_buf),
            ReceivePackReady::NeedMore
        );
        // Header only (12 bytes): still waiting for the 20-byte SHA-1 trailer.
        empty_pack_buf.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x00");
        assert_eq!(
            inspect_receive_pack_buffer(&empty_pack_buf),
            ReceivePackReady::NeedMore
        );
        // Add 20-byte SHA-1 trailer -> 32-byte empty pack complete.
        empty_pack_buf.extend_from_slice(&[0xAB; 20]);
        assert_eq!(
            inspect_receive_pack_buffer(&empty_pack_buf),
            ReceivePackReady::ReadyToDispatch
        );

        // 4. Normal push with `object_count > 0` waits for `channel_eof`.
        let mut normal_buf = pkt_line(format!("{old} {new} refs/heads/main\n").as_bytes());
        normal_buf.extend_from_slice(b"0000");
        normal_buf.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x01");
        normal_buf.extend_from_slice(&[0xCD; 40]);
        assert_eq!(
            inspect_receive_pack_buffer(&normal_buf),
            ReceivePackReady::NeedMore
        );
    }

    #[test]
    fn protocol_v0_upload_pack_handles_empty_done_and_have_rounds() {
        let oid_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let oid_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let oid_c = "cccccccccccccccccccccccccccccccccccccccc";

        // 1. Standalone `0000` with zero wants -> EmptyFlush.
        let mut st_empty = V0UploadState::default();
        let mut buf_empty = b"0000".to_vec();
        assert_eq!(st_empty.advance(&mut buf_empty), V0UploadAction::EmptyFlush);
        assert!(buf_empty.is_empty());

        // 2. Clone (`want ... 0000` + `0009done\n`) in one or multiple chunks.
        let mut st_clone = V0UploadState::default();
        let want_line = pkt_line(format!("want {oid_a} side-band-64k\n").as_bytes());
        let mut buf_clone = want_line.clone();
        buf_clone.extend_from_slice(b"00000009done\n");

        assert_eq!(
            st_clone.advance(&mut buf_clone),
            V0UploadAction::WantsAccepted
        );
        let expected_clone = [want_line.as_slice(), b"0000", b"0009done\n"].concat();
        assert_eq!(
            st_clone.advance(&mut buf_clone),
            V0UploadAction::Done(expected_clone)
        );
        assert!(buf_clone.is_empty());

        // 3. Multi-round fetch: `want ... 0000`, then `have b 0000`, then `have c` + `0009done\n`.
        let mut st_fetch = V0UploadState::default();
        let mut buf_fetch = want_line.clone();
        buf_fetch.extend_from_slice(b"0000");
        assert_eq!(
            st_fetch.advance(&mut buf_fetch),
            V0UploadAction::WantsAccepted
        );
        assert_eq!(st_fetch.advance(&mut buf_fetch), V0UploadAction::NeedMore);

        let have_b = pkt_line(format!("have {oid_b}\n").as_bytes());
        buf_fetch.extend_from_slice(&have_b);
        buf_fetch.extend_from_slice(b"0000");
        let expected_batch = [have_b.as_slice(), b"0000"].concat();
        assert_eq!(
            st_fetch.advance(&mut buf_fetch),
            V0UploadAction::HaveBatch(expected_batch)
        );
        assert!(buf_fetch.is_empty());

        let have_c = pkt_line(format!("have {oid_c}\n").as_bytes());
        buf_fetch.extend_from_slice(&have_c);
        buf_fetch.extend_from_slice(b"0009done\n");
        let expected_full = [
            want_line.as_slice(),
            b"0000",
            have_b.as_slice(),
            have_c.as_slice(),
            b"0009done\n",
        ]
        .concat();
        assert_eq!(
            st_fetch.advance(&mut buf_fetch),
            V0UploadAction::Done(expected_full)
        );
        assert!(buf_fetch.is_empty());
        assert_eq!(st_fetch.buffered_bytes(), 0);
    }

    #[test]
    fn format_fatal_stderr_never_double_prefixes() {
        assert_eq!(
            format_fatal_stderr("repository not found"),
            "fatal: repository not found\n"
        );
        assert_eq!(
            format_fatal_stderr("fatal: repository not found"),
            "fatal: repository not found\n"
        );
        assert_eq!(
            format_fatal_stderr("fatal: repository not found\n"),
            "fatal: repository not found\n"
        );
        assert_eq!(
            format_fatal_stderr("fatal: fatal: double\n"),
            "fatal: double\n"
        );
    }

    #[test]
    fn enforces_connection_wide_buffer_budget_across_channels() {
        let mut conn_bytes = 0usize;
        let max_channel = 100usize;
        let max_conn = 150usize;

        let mut ch1 = ChannelState::new();
        let mut ch2 = ChannelState::new();
        let data_80 = vec![b'a'; 80];

        buffer_channel_data(
            &mut ch1,
            &mut conn_bytes,
            &data_80,
            max_channel,
            max_conn,
            GitService::ReceivePack,
        )
        .unwrap();
        assert_eq!(conn_bytes, 80);

        // Second channel fits under `max_channel` (80 <= 100) but exceeds `max_conn` (160 > 150).
        let err = buffer_channel_data(
            &mut ch2,
            &mut conn_bytes,
            &data_80,
            max_channel,
            max_conn,
            GitService::ReceivePack,
        )
        .unwrap_err();
        assert!(err.contains("connection buffer"));
        assert_eq!(conn_bytes, 80);

        // Per-channel limit still triggers when a single channel exceeds `max_channel`.
        let err_ch = buffer_channel_data(
            &mut ch1,
            &mut conn_bytes,
            &[b'b'; 21],
            max_channel,
            max_conn,
            GitService::ReceivePack,
        )
        .unwrap_err();
        assert!(err_ch.contains("git-receive-pack"));

        // Clearing ch1 releases the connection budget so ch2 can now buffer.
        let freed = ch1.clear_buffers();
        conn_bytes = conn_bytes.saturating_sub(freed);
        assert_eq!(conn_bytes, 0);
        buffer_channel_data(
            &mut ch2,
            &mut conn_bytes,
            &data_80,
            max_channel,
            max_conn,
            GitService::ReceivePack,
        )
        .unwrap();
        assert_eq!(conn_bytes, 80);
        assert_eq!(MAX_CONN_BUFFERED_BYTES, DEFAULT_MAX_RECEIVE_PACK_BYTES);
    }

    #[test]
    fn a_delete_only_push_is_complete_at_its_flush() {
        let pkt = |s: &str| format!("{:04x}{s}", s.len() + 4);
        let zero = "0".repeat(40);
        let old = "a".repeat(40);
        let del = pkt(&format!(
            "{old} {zero} refs/heads/gone\0report-status atomic
"
        ));
        let del2 = pkt(&format!(
            "{old} {zero} refs/heads/also-gone
"
        ));
        let upd = pkt(&format!(
            "{old} {} refs/heads/main
",
            "b".repeat(40)
        ));

        assert!(is_complete_delete_only_push(
            format!("{del}0000").as_bytes()
        ));
        assert!(is_complete_delete_only_push(
            format!("{del}{del2}0000").as_bytes()
        ));
        // Not yet complete: waits for more data (or EOF).
        assert!(!is_complete_delete_only_push(del.as_bytes()));
        assert!(!is_complete_delete_only_push(
            &format!("{del}0000").as_bytes()[..10]
        ));
        // A delete combined with an update carries a pack: it ends at EOF as before.
        assert!(!is_complete_delete_only_push(
            format!("{del}{upd}0000").as_bytes()
        ));
        assert!(!is_complete_delete_only_push(
            format!("{del}0000PACK").as_bytes()
        ));
        // An empty push (`0000` alone) is no delete.
        assert!(!is_complete_delete_only_push(b"0000"));
    }

    #[test]
    fn parses_git_protocol_env_strictly() {
        assert!(parse_git_protocol_v2("version=2").unwrap());
        assert!(parse_git_protocol_v2("version=2:foo=bar").unwrap());
        assert!(!parse_git_protocol_v2("version=1").unwrap());
        assert!(parse_git_protocol_v2("version=2;rm -rf /").is_err());
        assert!(parse_git_protocol_v2("version=2\n").is_err());
    }

    /// Accounts by key (`key -> (username, is_owner)`) and a push-slot semaphore.
    struct FakeBackend {
        keys: Mutex<HashMap<String, (String, bool)>>,
        slots: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait]
    impl SshGitBackend for FakeBackend {
        async fn authenticate_pubkey(&self, _: &str, key: &str) -> Option<SshAuthenticatedUser> {
            let keys = self.keys.lock().unwrap();
            keys.get(key)
                .map(|(username, is_owner)| SshAuthenticatedUser {
                    username: username.clone(),
                    is_owner: *is_owner,
                })
        }
        async fn advertise_refs(
            &self,
            _: &SshAuthenticatedUser,
            _: &str,
            _: GitService,
            _: bool,
        ) -> std::result::Result<Vec<u8>, String> {
            Err("unused".to_owned())
        }
        async fn handle_upload_pack(
            &self,
            _: &SshAuthenticatedUser,
            _: &str,
            _: bool,
            _: &[u8],
        ) -> std::result::Result<Vec<u8>, String> {
            Err("unused".to_owned())
        }
        async fn reserve_push_slot(&self) -> std::result::Result<PushSlot, String> {
            match Arc::clone(&self.slots).try_acquire_owned() {
                Ok(permit) => Ok(Box::new(permit)),
                Err(_) => Err("server busy: retry the push in a moment".to_owned()),
            }
        }
        async fn handle_receive_pack(
            &self,
            _: &SshAuthenticatedUser,
            _: &str,
            _: Vec<u8>,
        ) -> std::result::Result<Vec<u8>, String> {
            Err("unused".to_owned())
        }
    }

    fn fake_backend(slots: usize) -> Arc<FakeBackend> {
        let keys = HashMap::from([("key-a".to_owned(), ("alice".to_owned(), true))]);
        Arc::new(FakeBackend {
            keys: Mutex::new(keys),
            slots: Arc::new(tokio::sync::Semaphore::new(slots)),
        })
    }

    /// A session as `auth_publickey` leaves it after `alice` authenticated with `key-a`.
    fn authed_session(backend: &Arc<FakeBackend>, users: &ConnLimiter<String>) -> GitSshSession {
        let mut session = GitSshSession::new(backend.clone(), SshLimits::default(), users.clone());
        session.user_guard = users.try_acquire("alice".to_owned());
        session.auth_key = Some(("git".to_owned(), "key-a".to_owned()));
        session.authenticated_user = Some(SshAuthenticatedUser {
            username: "alice".to_owned(),
            is_owner: true,
        });
        session
    }

    fn channel_id() -> ChannelId {
        use russh::keys::ssh_encoding::Decode;
        ChannelId::decode(&mut &[0u8, 0, 0, 0][..]).unwrap()
    }

    #[test]
    fn conn_limiter_caps_per_key_and_in_total_and_frees_on_drop() {
        let limiter = ConnLimiter::<&str>::new(2, 3);
        let a1 = limiter.try_acquire("a").unwrap();
        let _a2 = limiter.try_acquire("a").unwrap();
        assert!(limiter.try_acquire("a").is_none(), "per-key cap");
        let _b1 = limiter.try_acquire("b").unwrap();
        assert!(limiter.try_acquire("c").is_none(), "total cap");
        drop(a1);
        assert!(
            limiter.try_acquire("a").is_some(),
            "a dropped guard frees its place"
        );
        assert!(limiter.try_acquire("c").is_some());
    }

    #[tokio::test]
    async fn every_command_rechecks_the_key_the_role_and_the_account_limit() {
        let backend = fake_backend(1);
        let users = ConnLimiter::new(MAX_CONNECTIONS_PER_USER, usize::MAX);
        let mut session = authed_session(&backend, &users);
        assert!(session.reauthorize().await.unwrap().is_owner);

        // Demoted: the next command runs with the current role.
        backend.keys.lock().unwrap().get_mut("key-a").unwrap().1 = false;
        assert!(!session.reauthorize().await.unwrap().is_owner);
        assert!(!session.authenticated_user.as_ref().unwrap().is_owner);

        // Revoked key (or disabled account): refused on the live connection.
        backend.keys.lock().unwrap().clear();
        assert_eq!(
            session.reauthorize().await.unwrap_err(),
            "SSH key or account is no longer authorized"
        );

        // The key moved to another account: still refused, never re-bound.
        backend
            .keys
            .lock()
            .unwrap()
            .insert("key-a".to_owned(), ("mallory".to_owned(), true));
        assert!(session.reauthorize().await.is_err());

        // A connection over the per-account limit gets no place and no command.
        backend
            .keys
            .lock()
            .unwrap()
            .insert("key-a".to_owned(), ("alice".to_owned(), true));
        let _others: Vec<_> = (1..MAX_CONNECTIONS_PER_USER)
            .map(|_| authed_session(&backend, &users))
            .collect();
        let mut over = authed_session(&backend, &users);
        assert!(over.user_guard.is_none());
        let err = over.reauthorize().await.unwrap_err();
        assert!(err.contains("too many concurrent SSH connections"), "{err}");
        drop(session);
        assert!(
            over.reauthorize().await.is_ok(),
            "a closed connection frees a place"
        );
    }

    #[tokio::test]
    async fn a_push_needs_a_server_slot_and_one_per_connection() {
        let backend = fake_backend(1);
        let users = ConnLimiter::new(MAX_CONNECTIONS_PER_USER, usize::MAX);
        let mut first = authed_session(&backend, &users);
        let second = authed_session(&backend, &users);

        let slot = first.admit_push().await.unwrap();
        let mut channel = ChannelState::new();
        channel.push_slot = Some(slot);
        first.channels.insert(channel_id(), channel);

        // Same connection: refused while its push is in flight.
        assert_eq!(
            first.admit_push().await.unwrap_err(),
            "only one push at a time per SSH connection"
        );
        // Other connection: the server's only slot is taken.
        assert!(
            second
                .admit_push()
                .await
                .unwrap_err()
                .contains("server busy")
        );

        // The push finishes: its slot goes back.
        first.channels.get_mut(&channel_id()).unwrap().finish();
        assert!(second.admit_push().await.is_ok());
    }

    #[test]
    fn generates_and_reloads_ed25519_host_key_and_secures_premier_dir() {
        let dir = tempfile::tempdir().unwrap();
        let premier_dir = dir.path().join(".premier");
        let key_path = premier_dir.join("ssh_host_ed25519.key");

        let generated = load_or_generate_host_key(&key_path).unwrap();
        let reloaded = load_or_generate_host_key(&key_path).unwrap();
        assert_eq!(
            generated.public_key().to_openssh().unwrap(),
            reloaded.public_key().to_openssh().unwrap()
        );

        let gitignore = std::fs::read_to_string(premier_dir.join(".gitignore")).unwrap();
        assert_eq!(gitignore, "*\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&premier_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
