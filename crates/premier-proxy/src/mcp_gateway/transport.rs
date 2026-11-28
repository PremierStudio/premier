//! Upstream MCP transports: newline-delimited JSON-RPC over a child's stdio, and the
//! Streamable HTTP / SSE transport over hyper + rustls with SSRF guards.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use premier_secrets::SecretRedactor;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio_rustls::TlsConnector;
use url::Url;
use zeroize::Zeroizing;

/// Boxed `Send` future used by the object-safe [`McpUpstream`] trait.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Largest JSON-RPC frame (stdio line or HTTP body) accepted from an upstream.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_LIST_PAGES: usize = 32;
const PROTOCOL_VERSION: &str = "2024-11-05";
/// Host environment a spawned MCP server may inherit; everything else is cleared.
#[cfg(windows)]
const BASELINE_ENV: &[&str] = &[
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "PATHEXT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "APPDATA",
];
#[cfg(not(windows))]
const BASELINE_ENV: &[&str] = &["PATH", "TEMP", "TMP", "TMPDIR"];
const MAX_STDERR_LINE: usize = 4096;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("secret error: {0}")]
    Secret(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// A connection to one upstream MCP server.
pub trait McpUpstream: Send + Sync {
    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Value>, GatewayError>>;
    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> BoxFuture<'_, Result<Value, GatewayError>>;
}

fn initialize_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": { "name": "premier-mcp-gateway", "version": env!("CARGO_PKG_VERSION") },
    })
}

/// Pull `result` out of a JSON-RPC response, turning `error` into [`GatewayError::Upstream`].
fn take_result(mut resp: Value, redactor: &SecretRedactor) -> Result<Value, GatewayError> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        return Err(GatewayError::Upstream(format!(
            "{} (code {code})",
            redactor.redact_str(msg).0
        )));
    }
    resp.get_mut("result")
        .map(Value::take)
        .ok_or_else(|| GatewayError::Protocol("response has neither result nor error".to_owned()))
}

/// Accumulate paginated `tools/list` results using `request(cursor)`.
async fn list_all_tools<F, Fut>(mut request: F) -> Result<Vec<Value>, GatewayError>
where
    F: FnMut(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, GatewayError>>,
{
    let mut tools = Vec::new();
    let mut params = json!({});
    for _ in 0..MAX_LIST_PAGES {
        let result = request(params).await?;
        if let Some(items) = result.get("tools").and_then(Value::as_array) {
            tools.extend(items.iter().cloned());
        }
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(cursor) if !cursor.is_empty() => params = json!({ "cursor": cursor }),
            _ => return Ok(tools),
        }
    }
    Err(GatewayError::Protocol(
        "tools/list pagination exceeded page limit".to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------

type DynReader = BufReader<Box<dyn AsyncRead + Unpin + Send>>;
type DynWriter = Box<dyn AsyncWrite + Unpin + Send>;

struct StdioConn {
    reader: DynReader,
    writer: DynWriter,
    // Held so `kill_on_drop` reaps the server when the connection is dropped.
    _child: Option<Child>,
    initialized: bool,
}

struct SpawnSpec {
    command: String,
    args: Vec<String>,
    static_env: BTreeMap<String, String>,
    injected_secrets: Vec<(String, Zeroizing<String>)>,
}

struct StdioState {
    conn: Option<StdioConn>,
    next_id: u64,
}

/// MCP server reached over newline-delimited JSON-RPC on stdin/stdout.
pub struct StdioUpstream {
    spawn: Option<SpawnSpec>,
    state: tokio::sync::Mutex<StdioState>,
    timeout: Duration,
    redactor: Arc<SecretRedactor>,
}

/// Build the child command: no shell, cleared environment, only baseline OS variables plus the
/// server's own static env and bound credentials.
pub(crate) fn build_command(
    command: &str,
    args: &[String],
    static_env: &BTreeMap<String, String>,
    injected_secrets: &[(String, Zeroizing<String>)],
) -> Command {
    let mut cmd = Command::new(command);
    cmd.args(args).env_clear();
    for name in BASELINE_ENV {
        if let Some(v) = std::env::var_os(name) {
            cmd.env(name, v);
        }
    }
    cmd.envs(static_env);
    for (name, value) in injected_secrets {
        cmd.env(name, value.as_str());
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

impl StdioUpstream {
    /// Spawned lazily on first use.
    pub fn new(
        command: &str,
        args: &[String],
        static_env: BTreeMap<String, String>,
        injected_secrets: Vec<(String, Zeroizing<String>)>,
        timeout: Duration,
        redactor: Arc<SecretRedactor>,
    ) -> Self {
        Self {
            spawn: Some(SpawnSpec {
                command: command.to_owned(),
                args: args.to_vec(),
                static_env,
                injected_secrets,
            }),
            state: tokio::sync::Mutex::new(StdioState {
                conn: None,
                next_id: 1,
            }),
            timeout,
            redactor,
        }
    }

    /// Speak MCP over arbitrary streams (no process). Not reconnectable once it fails.
    pub fn from_io<R, W>(
        reader: R,
        writer: W,
        timeout: Duration,
        redactor: Arc<SecretRedactor>,
    ) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            spawn: None,
            state: tokio::sync::Mutex::new(StdioState {
                conn: Some(StdioConn {
                    reader: BufReader::new(Box::new(reader)),
                    writer: Box::new(writer),
                    _child: None,
                    initialized: false,
                }),
                next_id: 1,
            }),
            timeout,
            redactor,
        }
    }

    fn scrub(&self, text: impl AsRef<str>) -> String {
        self.redactor.redact_str(text.as_ref()).0
    }

    fn spawn_conn(&self) -> Result<StdioConn, GatewayError> {
        let spec = self
            .spawn
            .as_ref()
            .ok_or_else(|| GatewayError::Transport("stdio transport is closed".to_owned()))?;
        let mut child = build_command(
            &spec.command,
            &spec.args,
            &spec.static_env,
            &spec.injected_secrets,
        )
        .spawn()
        .map_err(|e| {
            GatewayError::Transport(self.scrub(format!("spawn '{}' failed: {e}", spec.command)))
        })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
            return Err(GatewayError::Transport(
                "child stdio unavailable".to_owned(),
            ));
        };
        if let Some(mut stderr) = child.stderr.take() {
            let redactor = Arc::clone(&self.redactor);
            let label = spec.command.clone();
            tokio::spawn(async move {
                let mut raw = [0u8; MAX_STDERR_LINE];
                let mut line = Vec::with_capacity(MAX_STDERR_LINE);
                let mut truncated = false;
                let flush = |line: &mut Vec<u8>, truncated: &mut bool| {
                    if !line.is_empty() {
                        let text = String::from_utf8_lossy(line);
                        let (clean, _) = redactor.redact_str(text.trim_end_matches('\r'));
                        let suffix = if *truncated { "… [truncated]" } else { "" };
                        tracing::warn!(server_command = %label, "mcp stderr: {clean}{suffix}");
                        line.clear();
                    }
                    *truncated = false;
                };
                while let Ok(n) = stderr.read(&mut raw).await {
                    if n == 0 {
                        flush(&mut line, &mut truncated);
                        break;
                    }
                    for &b in &raw[..n] {
                        if b == b'\n' {
                            flush(&mut line, &mut truncated);
                        } else if line.len() < MAX_STDERR_LINE {
                            line.push(b);
                        } else {
                            truncated = true;
                        }
                    }
                }
            });
        }
        Ok(StdioConn {
            reader: BufReader::new(Box::new(stdout)),
            writer: Box::new(stdin),
            _child: Some(child),
            initialized: false,
        })
    }

    async fn send(writer: &mut DynWriter, msg: &Value) -> Result<(), GatewayError> {
        let mut line = serde_json::to_vec(msg)
            .map_err(|e| GatewayError::Protocol(format!("encode request failed: {e}")))?;
        line.push(b'\n');
        writer
            .write_all(&line)
            .await
            .map_err(|e| GatewayError::Transport(format!("write to server failed: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| GatewayError::Transport(format!("flush to server failed: {e}")))
    }

    /// Send one request and read lines until the response with the same `id` arrives.
    async fn round_trip(
        conn: &mut StdioConn,
        id: u64,
        method: &str,
        params: Value,
    ) -> Result<Value, GatewayError> {
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        Self::send(&mut conn.writer, &req).await?;
        loop {
            let mut buf = Vec::new();
            let n = (&mut conn.reader)
                .take(MAX_FRAME_BYTES as u64 + 1)
                .read_until(b'\n', &mut buf)
                .await
                .map_err(|e| GatewayError::Transport(format!("read from server failed: {e}")))?;
            if n == 0 {
                return Err(GatewayError::Transport("server closed stdout".to_owned()));
            }
            if buf.len() > MAX_FRAME_BYTES {
                return Err(GatewayError::Protocol("frame exceeds 16 MiB".to_owned()));
            }
            let text = String::from_utf8_lossy(&buf);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<Value>(text) else {
                return Err(GatewayError::Protocol(
                    "server sent invalid JSON".to_owned(),
                ));
            };
            if msg.get("method").is_some() {
                // Server-initiated request: refuse it so the server does not wait on us.
                if let Some(req_id) = msg.get("id") {
                    let refusal = json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": { "code": -32601, "message": "not supported by premier gateway" },
                    });
                    Self::send(&mut conn.writer, &refusal).await?;
                }
                continue;
            }
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(msg);
            }
        }
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, GatewayError> {
        let mut st = self.state.lock().await;
        let work = async {
            if st.conn.is_none() {
                st.conn = Some(self.spawn_conn()?);
            }
            let mut next_id = st.next_id;
            let conn = st
                .conn
                .as_mut()
                .ok_or_else(|| GatewayError::Transport("stdio transport is closed".to_owned()))?;
            if !conn.initialized {
                let init =
                    Self::round_trip(conn, next_id, "initialize", initialize_params()).await?;
                next_id += 1;
                take_result(init, &self.redactor)?;
                let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
                Self::send(&mut conn.writer, &note).await?;
                conn.initialized = true;
            }
            let resp = Self::round_trip(conn, next_id, method, params).await;
            Ok::<_, GatewayError>((resp, next_id + 1))
        };
        let outcome = tokio::time::timeout(self.timeout, work).await;
        match outcome {
            Ok(Ok((Ok(resp), next))) => {
                st.next_id = next;
                take_result(resp, &self.redactor)
            }
            Ok(Ok((Err(e), _))) | Ok(Err(e)) => {
                // The stream may be mid-frame; drop it (and kill the child) so it restarts clean.
                st.conn = None;
                Err(scrub_err(e, &self.redactor))
            }
            Err(_) => {
                st.conn = None;
                Err(GatewayError::Timeout(format!(
                    "'{method}' exceeded {}s",
                    self.timeout.as_secs_f32()
                )))
            }
        }
    }
}

fn scrub_err(e: GatewayError, r: &SecretRedactor) -> GatewayError {
    let s = |m: String| r.redact_str(&m).0;
    match e {
        GatewayError::Transport(m) => GatewayError::Transport(s(m)),
        GatewayError::Upstream(m) => GatewayError::Upstream(s(m)),
        GatewayError::Policy(m) => GatewayError::Policy(s(m)),
        GatewayError::Secret(m) => GatewayError::Secret(s(m)),
        GatewayError::Timeout(m) => GatewayError::Timeout(s(m)),
        GatewayError::Protocol(m) => GatewayError::Protocol(s(m)),
    }
}

impl McpUpstream for StdioUpstream {
    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Value>, GatewayError>> {
        Box::pin(list_all_tools(move |params| {
            self.request("tools/list", params)
        }))
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> BoxFuture<'_, Result<Value, GatewayError>> {
        let params = json!({ "name": tool_name, "arguments": arguments });
        Box::pin(self.request("tools/call", params))
    }
}

// ---------------------------------------------------------------------------
// Streamable HTTP / SSE
// ---------------------------------------------------------------------------

/// Network policy for [`HttpSseUpstream`].
#[derive(Debug, Clone, Default)]
pub struct HttpUpstreamOptions {
    /// Allow plain `http` (and loopback addresses) for `127.0.0.1`, `::1` and `localhost`.
    pub allow_loopback_http: bool,
    /// Allow RFC 1918, CGNAT and IPv6 ULA destinations.
    pub allow_private_upstreams: bool,
    pub extra_upstream_roots: Vec<CertificateDer<'static>>,
}

struct HttpState {
    initialized: bool,
    session_id: Option<String>,
    next_id: u64,
}

/// MCP server reached over Streamable HTTP (JSON or `text/event-stream` responses).
pub struct HttpSseUpstream {
    url: Url,
    host: String,
    port: u16,
    use_tls: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
    tls: TlsConnector,
    opts: HttpUpstreamOptions,
    timeout: Duration,
    redactor: Arc<SecretRedactor>,
    state: tokio::sync::Mutex<HttpState>,
}

fn is_loopback_name(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let segs = v6.segments();
    // IPv4-compatible `::a.b.c.d` (excluding `::` and `::1`).
    if segs[..6] == [0, 0, 0, 0, 0, 0] && !(segs[6] == 0 && segs[7] <= 1) {
        let b = v6.octets();
        return Some(std::net::Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    }
    // NAT64 well-known `64:ff9b::/96` and local-use `64:ff9b:1::/48`.
    if (segs[0] == 0x0064 && segs[1] == 0xFF9B && segs[2..6] == [0, 0, 0, 0])
        || (segs[0] == 0x0064 && segs[1] == 0xFF9B && segs[2] == 0x0001)
    {
        let b = v6.octets();
        return Some(std::net::Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    }
    // 6to4 `2002::/16`: upper 32 bits of the IID carry the IPv4 endpoint.
    if segs[0] == 0x2002 {
        let b = v6.octets();
        return Some(std::net::Ipv4Addr::new(b[2], b[3], b[4], b[5]));
    }
    None
}

/// Why `ip` may not be dialled under `opts`, if it may not.
pub(crate) fn blocked_ip_reason(ip: IpAddr, opts: &HttpUpstreamOptions) -> Option<&'static str> {
    let ip = match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let (always_blocked, loopback, private) = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let special_v4 = o[0] == 0
                || (o[0], o[1], o[2]) == (192, 0, 0)
                || (o[0], o[1], o[2]) == (192, 0, 2)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || (o[0], o[1], o[2]) == (198, 51, 100)
                || (o[0], o[1], o[2]) == (203, 0, 113)
                || o[0] >= 240;
            (
                v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || special_v4,
                v4.is_loopback(),
                v4.is_private() || (o[0] == 100 && (o[1] & 0xC0) == 64),
            )
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let seg0 = segs[0];
            let site_local = (seg0 & 0xFFC0) == 0xFEC0;
            let discard = segs[..4] == [0x0100, 0, 0, 0];
            (
                v6.is_unspecified()
                    || v6.is_multicast()
                    || (seg0 & 0xFFC0) == 0xFE80
                    || site_local
                    || discard,
                v6.is_loopback(),
                (seg0 & 0xFE00) == 0xFC00,
            )
        }
    };
    if always_blocked {
        Some("link-local, unspecified, broadcast or multicast address")
    } else if loopback && !opts.allow_loopback_http {
        Some("loopback address")
    } else if private && !opts.allow_private_upstreams {
        Some("private network address")
    } else {
        None
    }
}

impl HttpSseUpstream {
    pub fn new(
        url: &str,
        static_headers: &BTreeMap<String, String>,
        injected_headers: Vec<(String, Zeroizing<String>)>,
        timeout: Duration,
        redactor: Arc<SecretRedactor>,
        opts: HttpUpstreamOptions,
    ) -> Result<Self, GatewayError> {
        let parsed = Url::parse(url)
            .map_err(|e| GatewayError::Policy(format!("invalid MCP server url: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| GatewayError::Policy("MCP server url has no host".to_owned()))?
            .to_owned();
        let use_tls = match parsed.scheme() {
            "https" => true,
            "http" if opts.allow_loopback_http && is_loopback_name(&host) => false,
            "http" => {
                return Err(GatewayError::Policy(
                    "plain http is only allowed for loopback upstreams".to_owned(),
                ));
            }
            other => {
                return Err(GatewayError::Policy(format!(
                    "unsupported MCP url scheme '{other}'"
                )));
            }
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(GatewayError::Policy(
                "credentials in the MCP url are not allowed; bind them as credentials".to_owned(),
            ));
        }
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| GatewayError::Policy("MCP server url has no port".to_owned()))?;

        let mut headers = Vec::new();
        let mut add = |name: &str, value: &str, sensitive: bool| -> Result<(), GatewayError> {
            let n = HeaderName::try_from(name)
                .map_err(|_| GatewayError::Policy(format!("invalid header name '{name}'")))?;
            let mut v = HeaderValue::try_from(value)
                .map_err(|_| GatewayError::Secret(format!("invalid value for header '{name}'")))?;
            v.set_sensitive(sensitive);
            headers.push((n, v));
            Ok(())
        };
        for (k, v) in static_headers {
            add(k, v, false)?;
        }
        for (k, v) in &injected_headers {
            add(k, v.as_str(), true)?;
        }

        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for extra in &opts.extra_upstream_roots {
            roots
                .add(extra.clone())
                .map_err(|e| GatewayError::Transport(format!("add upstream root failed: {e}")))?;
        }
        let tls_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| GatewayError::Transport(format!("rustls config failed: {e}")))?
                .with_root_certificates(roots)
                .with_no_client_auth();

        Ok(Self {
            url: parsed,
            host,
            port,
            use_tls,
            headers,
            tls: TlsConnector::from(Arc::new(tls_cfg)),
            opts,
            timeout,
            redactor,
            state: tokio::sync::Mutex::new(HttpState {
                initialized: false,
                session_id: None,
                next_id: 1,
            }),
        })
    }

    fn scrub(&self, text: impl AsRef<str>) -> String {
        self.redactor.redact_str(text.as_ref()).0
    }

    /// Resolve the host and return one address, refusing if ANY answer is a blocked range
    /// (so a rebinding resolver cannot mix in an internal address).
    async fn resolve(&self) -> Result<SocketAddr, GatewayError> {
        let bare = self.host.trim_matches(['[', ']']);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, self.port))
            .await
            .map_err(|e| GatewayError::Transport(format!("resolve '{}' failed: {e}", self.host)))?
            .collect();
        if addrs.is_empty() {
            return Err(GatewayError::Transport(format!(
                "'{}' resolved to no addresses",
                self.host
            )));
        }
        for a in &addrs {
            if let Some(why) = blocked_ip_reason(a.ip(), &self.opts) {
                return Err(GatewayError::Policy(format!(
                    "upstream '{}' resolves to a blocked {why}",
                    self.host
                )));
            }
        }
        Ok(addrs[0])
    }

    /// POST one JSON-RPC message; returns the matching response (or `None` for a notification).
    async fn post(
        &self,
        msg: &Value,
        id: Option<u64>,
        session_id: Option<&str>,
    ) -> Result<(Option<Value>, Option<String>), GatewayError> {
        let addr = self.resolve().await?;
        // Dial the vetted address itself so DNS cannot change between check and connect.
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| GatewayError::Transport(format!("connect failed: {e}")))?;

        let mut path = self.url.path().to_owned();
        if let Some(q) = self.url.query() {
            path.push('?');
            path.push_str(q);
        }
        let host_header = match self.url.port() {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        };
        let body = serde_json::to_vec(msg)
            .map_err(|e| GatewayError::Protocol(format!("encode request failed: {e}")))?;
        let mut builder = Request::post(path)
            .header(http::header::HOST, host_header)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(sid) = session_id {
            builder = builder.header("mcp-session-id", sid);
        }
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let req = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| GatewayError::Protocol("build request failed".to_owned()))?;

        let resp = if self.use_tls {
            let name = ServerName::try_from(self.host.trim_matches(['[', ']']).to_owned())
                .map_err(|_| GatewayError::Transport("invalid TLS server name".to_owned()))?;
            let tls = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| GatewayError::Transport(format!("TLS handshake failed: {e}")))?;
            send_http1(TokioIo::new(tls), req).await?
        } else {
            send_http1(TokioIo::new(tcp), req).await?
        };

        let status = resp.status();
        let new_session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let encoding = resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("identity")
            .trim()
            .to_ascii_lowercase();
        if encoding != "identity" && !encoding.is_empty() {
            return Err(GatewayError::Protocol(format!(
                "compressed upstream response ('{encoding}') refused"
            )));
        }
        let content_type = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let bytes = Limited::new(resp.into_body(), MAX_FRAME_BYTES)
            .collect()
            .await
            .map_err(|e| GatewayError::Transport(format!("read response failed: {e}")))?
            .to_bytes();

        if !status.is_success() {
            let snippet: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
            return Err(GatewayError::Upstream(format!("HTTP {status}: {snippet}")));
        }
        let Some(id) = id else {
            return Ok((None, new_session));
        };
        if status == StatusCode::ACCEPTED || bytes.is_empty() {
            return Err(GatewayError::Protocol(
                "empty response to request".to_owned(),
            ));
        }
        let found = if content_type.starts_with("text/event-stream") {
            find_in_sse(&bytes, id)
        } else {
            serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| match_response(v, id))
        };
        found
            .map(|v| (Some(v), new_session))
            .ok_or_else(|| GatewayError::Protocol(format!("no JSON-RPC response with id {id}")))
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, GatewayError> {
        let work = async {
            let mut st = self.state.lock().await;
            if !st.initialized {
                let id = st.next_id;
                st.next_id += 1;
                let init = json!({
                    "jsonrpc": "2.0", "id": id, "method": "initialize", "params": initialize_params(),
                });
                let (resp, sid) = self.post(&init, Some(id), None).await?;
                take_result(resp.unwrap_or(Value::Null), &self.redactor)?;
                st.session_id = sid;
                let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
                self.post(&note, None, st.session_id.as_deref()).await?;
                st.initialized = true;
            }
            let id = st.next_id;
            st.next_id += 1;
            let session = st.session_id.clone();
            drop(st);
            let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
            let (resp, _) = self.post(&req, Some(id), session.as_deref()).await?;
            take_result(resp.unwrap_or(Value::Null), &self.redactor)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(r) => r.map_err(|e| scrub_err(e, &self.redactor)),
            Err(_) => Err(GatewayError::Timeout(self.scrub(format!(
                "'{method}' exceeded {}s",
                self.timeout.as_secs_f32()
            )))),
        }
    }
}

async fn send_http1<IO>(
    io: TokioIo<IO>,
    req: Request<Full<Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>, GatewayError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // shortcut: one connection per request; pool connections if call volume ever matters.
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| GatewayError::Transport(format!("http1 handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| GatewayError::Transport(format!("send failed: {e}")))
}

/// The response for `id` in a single message or a batch array.
fn match_response(v: Value, id: u64) -> Option<Value> {
    match v {
        Value::Array(items) => items.into_iter().find_map(|i| match_response(i, id)),
        v if v.get("method").is_none() && v.get("id").and_then(Value::as_u64) == Some(id) => {
            Some(v)
        }
        _ => None,
    }
}

/// Scan SSE events (blank-line separated, `data:` lines joined by `\n`) for the response to `id`.
fn find_in_sse(bytes: &[u8], id: u64) -> Option<Value> {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    for event in text.split("\n\n") {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|d| d.strip_prefix(' ').unwrap_or(d))
            .collect();
        if data.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&data.join("\n"))
            && let Some(found) = match_response(v, id)
        {
            return Some(found);
        }
    }
    None
}

impl McpUpstream for HttpSseUpstream {
    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Value>, GatewayError>> {
        Box::pin(list_all_tools(move |params| {
            self.request("tools/list", params)
        }))
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> BoxFuture<'_, Result<Value, GatewayError>> {
        let params = json!({ "name": tool_name, "arguments": arguments });
        Box::pin(self.request("tools/call", params))
    }
}
