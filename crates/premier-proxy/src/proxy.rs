//! Host-side AI Agent Egress Capability Proxy (`tokio` + `hyper` v1 + `rustls`/`ring`).
//!
//! Supports:
//! 1. **Zero-MITM Reverse Proxy (`/cap/<VAR_NAME>/<path>`)** — zero CA friction across all OSes.
//! 2. **Explicit HTTP Proxy (`GET http://host/path`)** — allow-listed non-secret hosts only.
//! 3. **HTTPS `CONNECT` MITM (`rcgen` ephemeral CA)** — intercepts only schema-declared secret hosts,
//!    passes through explicit non-secret registries, and default-denies all other egress.
//!
//! Every request must carry the per-session token, the listener is loopback-only, and a real
//! secret only ever leaves over TLS to a declared host on its declared port.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use premier_core::{AuditDecision, AuditEvent, Capability, DelegatedIdentity};
use premier_policy::CompiledPolicy;
use premier_secrets::{
    ApprovalMode, BoundCapability, InjectSpec, PlaceholderRegistry, SecretRedactor,
    percent_encode_component,
};
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ProxyError;
use crate::approval::{
    ApprovalGate, ApprovalManager, ApprovalRequest, DenyJitGate, RiskLevel, SanitizedHeader,
    SessionContext, WirePreview, classify_risk, synthesize_intent_summary,
};
use crate::audit::AuditSink;
use crate::budget::{BudgetAlert, BudgetGateDecision, BudgetTracker};
use crate::ca::EphemeralCa;

/// Runtime configuration for `EgressProxyServer`.
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    /// Also listen on this Unix socket (Unix hosts): the one route out of a sandbox that has no
    /// network of its own. Same token, same rules as the TCP listener.
    pub unix_socket: Option<std::path::PathBuf>,
    pub identity: DelegatedIdentity,
    pub ref_name: String,
    pub policy: Option<CompiledPolicy>,
    pub registry: PlaceholderRegistry,
    /// Non-secret hosts allowed to tunnel via `CONNECT` without secret injection (e.g. `crates.io`).
    pub allow_passthrough_hosts: HashSet<String>,
    pub audit_sink: Arc<AuditSink>,
    pub approval_gate: Box<dyn ApprovalGate>,
    /// Optional additional root cert DER for upstream TLS verification (e.g. local integration tests).
    pub extra_upstream_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Pin a logical host (lowercase) to a socket address, like `curl --resolve`. TLS is still
    /// verified against the logical host. Set by the embedding host only, never from a schema.
    pub upstream_resolve: HashMap<String, SocketAddr>,
    /// Deadline for upstream DNS resolution and, separately, TCP connection establishment.
    pub upstream_connect_timeout: Duration,
    /// Deadline for each upstream TLS handshake.
    pub upstream_tls_timeout: Duration,
    /// Total deadline for the upstream HTTP exchange, including the response body.
    pub upstream_request_timeout: Duration,
    /// Largest request body buffered for placeholder substitution.
    pub max_request_body: usize,
    /// Largest upstream response body buffered for scrubbing; larger responses are withheld.
    pub max_response_body: usize,
    /// Per-session autonomy budget; `None` leaves egress unmetered.
    pub budget: Option<Arc<BudgetTracker>>,
    /// Cage session (`cage-NNNN`) every audit event of this proxy is tagged with (stamped as
    /// `agent_task_id`, so a session's egress denials can be told apart).
    pub session_id: Option<String>,
    /// Where this proxy session runs (branch, session, command), shown on JIT knocks.
    pub session_context: Option<SessionContext>,
}

impl ProxyConfig {
    pub fn new(
        bind_addr: SocketAddr,
        identity: DelegatedIdentity,
        registry: PlaceholderRegistry,
    ) -> Self {
        Self {
            bind_addr,
            unix_socket: None,
            identity,
            ref_name: "main".to_owned(),
            policy: None,
            registry,
            allow_passthrough_hosts: HashSet::new(),
            audit_sink: Arc::new(AuditSink::default()),
            approval_gate: Box::new(DenyJitGate),
            extra_upstream_roots: Vec::new(),
            upstream_resolve: HashMap::new(),
            upstream_connect_timeout: Duration::from_secs(10),
            upstream_tls_timeout: Duration::from_secs(10),
            upstream_request_timeout: Duration::from_secs(60),
            max_request_body: 32 * 1024 * 1024,
            max_response_body: 64 * 1024 * 1024,
            budget: None,
            session_id: None,
            session_context: None,
        }
    }
}

/// Handle to a running `EgressProxyServer`.
pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub ca_cert_pem: String,
    pub audit_sink: Arc<AuditSink>,
    /// Per-session token every proxy request must present.
    pub auth_token: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

/// Proxy URL carrying the session token as userinfo, so standard HTTP clients send it as
/// `Proxy-Authorization` on every request including `CONNECT`.
pub fn proxy_url_for(addr: SocketAddr, token: &str) -> String {
    format!("http://premier:{token}@{addr}")
}

/// Zero-MITM base URL for one capability. The token rides in the path because clients do not
/// send `Proxy-Authorization` to an origin server.
pub fn cap_base_url_for(addr: SocketAddr, token: &str, var_name: &str) -> String {
    format!("http://{addr}/cap/{token}/{var_name}")
}

impl ProxyHandle {
    pub fn proxy_url(&self) -> String {
        proxy_url_for(self.addr, &self.auth_token)
    }

    pub fn cap_base_url(&self, var_name: &str) -> String {
        cap_base_url_for(self.addr, &self.auth_token, var_name)
    }

    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct RateLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn check_and_increment(&self, var_name: &str, limit_per_min: u32) -> bool {
        let Ok(mut guard) = self.windows.lock() else {
            return false;
        };
        let now = Instant::now();
        let entry = guard.entry(var_name.to_owned()).or_insert_with(|| (now, 0));
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= limit_per_min {
            return false;
        }
        entry.1 += 1;
        true
    }
}

struct ProxyState {
    identity: DelegatedIdentity,
    session_id: Option<String>,
    ref_name: String,
    policy: Option<CompiledPolicy>,
    registry: PlaceholderRegistry,
    redactor: SecretRedactor,
    allow_passthrough_hosts: HashSet<String>,
    audit: Arc<AuditSink>,
    approvals: ApprovalManager,
    rate_limiter: RateLimiter,
    ca: EphemeralCa,
    upstream_tls: TlsConnector,
    auth_token: String,
    upstream_resolve: HashMap<String, SocketAddr>,
    upstream_connect_timeout: Duration,
    upstream_tls_timeout: Duration,
    upstream_request_timeout: Duration,
    max_request_body: usize,
    max_response_body: usize,
    budget: Option<Arc<BudgetTracker>>,
    session_context: Option<SessionContext>,
}

/// Reject non-public / host-local IP addresses to prevent host-side SSRF and DNS rebinding.
///
/// Blocks IPv4 loopback, `0.0.0.0/8`, link-local/IMDS (`169.254.0.0/16`), RFC 1918 private,
/// CGNAT (`100.64.0.0/10`), multicast, broadcast, reserved (`240.0.0.0/4`), and IPv6
/// loopback, unspecified, link-local (`fe80::/10`), ULA (`fc00::/7`), multicast,
/// IPv4-mapped/compatible, and NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`).
pub fn is_blocked_egress_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || o[0] == 0 // 0.0.0.0/8 ("this host on this network")
                || v4.is_link_local() // 169.254.0.0/16 (incl. cloud IMDS 169.254.169.254)
                || v4.is_private() // RFC 1918: 10/8, 172.16/12, 192.168/16
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
                || v4.is_multicast() // 224.0.0.0/4
                || v4.is_broadcast() // 255.255.255.255
                || o[0] >= 240 // reserved 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_egress_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] == 0x0064
                    && s[1] == 0xff9b
                    && s[2] == 0
                    && s[3] == 0
                    && s[4] == 0
                    && s[5] == 0) // NAT64 64:ff9b::/96
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // Local NAT64 64:ff9b:1::/48
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0) // ::/96
        }
    }
}

enum EgressResolveError {
    Timeout,
    Blocked(String),
    LookupFailed(String),
}

/// Resolve an outbound destination to vetted `SocketAddr`s without re-resolving at `connect`.
///
/// Operator-pinned hosts (`upstream_resolve`) connect directly to their explicit `SocketAddr`.
/// All other hosts are resolved once via DNS and rejected if empty or if ANY resolved IP
/// matches [`is_blocked_egress_ip`].
async fn resolve_vetted_upstream(
    state: &ProxyState,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, EgressResolveError> {
    if let Some(pinned) = state.upstream_resolve.get(&host.to_ascii_lowercase()) {
        return Ok(vec![*pinned]);
    }
    let unbracketed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        if is_blocked_egress_ip(ip) {
            return Err(EgressResolveError::Blocked(format!(
                "SSRF blocked: egress to non-public IP '{ip}' is forbidden"
            )));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        state.upstream_connect_timeout,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| EgressResolveError::Timeout)?
    .map_err(|e| {
        EgressResolveError::LookupFailed(format!("DNS lookup for {host}:{port} failed: {e}"))
    })?
    .collect();
    if addrs.is_empty() {
        return Err(EgressResolveError::Blocked(format!(
            "DNS lookup for '{host}' returned no addresses"
        )));
    }
    for addr in &addrs {
        if is_blocked_egress_ip(addr.ip()) {
            return Err(EgressResolveError::Blocked(format!(
                "SSRF blocked: '{host}' resolved to non-public IP '{}'",
                addr.ip()
            )));
        }
    }
    Ok(addrs)
}

/// Headers that describe one connection and must never be relayed (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

impl ProxyState {
    fn token_ok(&self, candidate: &[u8]) -> bool {
        candidate.ct_eq(self.auth_token.as_bytes()).into()
    }

    /// `Proxy-Authorization: Bearer <token>` or `Basic base64(<any user>:<token>)`.
    fn header_authorized(&self, headers: &HeaderMap) -> bool {
        headers
            .get_all(http::header::PROXY_AUTHORIZATION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.trim().split_once(' '))
            .any(|(scheme, cred)| {
                if scheme.eq_ignore_ascii_case("bearer") {
                    self.token_ok(cred.trim().as_bytes())
                } else if scheme.eq_ignore_ascii_case("basic") {
                    base64::engine::general_purpose::STANDARD
                        .decode(cred.trim())
                        .ok()
                        .and_then(|d| {
                            let pw = d.splitn(2, |b| *b == b':').nth(1)?;
                            Some(self.token_ok(pw))
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            })
    }

    fn auth_required(&self) -> Response<Full<Bytes>> {
        let mut resp = self.error(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy session token required",
        );
        resp.headers_mut().insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"premier-proxy\""),
        );
        resp
    }

    /// Proxy-generated response. The message is scrubbed like any upstream body, so no code
    /// path can hand a real secret back to the agent through an error.
    fn error(&self, status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
        let (msg, _) = self.redactor.redact_str(msg);
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({ "error": msg }).to_string(),
            )))
            .unwrap_or_else(|_| {
                Response::new(Full::new(Bytes::from_static(b"{\"error\":\"proxy\"}")))
            })
    }

    /// Text bound for an approver or an audit trail: secrets (in every encoding the redactor
    /// knows) and the proxy session token are replaced.
    fn sanitize_text(&self, text: &str) -> String {
        self.redactor
            .redact_str(text)
            .0
            .replace(&self.auth_token, "[REDACTED:PROXY_TOKEN]")
    }

    fn is_secret_host_port(&self, host: &str, port: u16) -> bool {
        self.registry
            .all()
            .any(|cap| cap.egress.matches_host(host) && cap.egress.tls_port() == port)
    }

    fn is_passthrough_host_port(&self, host: &str, port: u16) -> bool {
        let lower = host.trim().to_ascii_lowercase();
        self.allow_passthrough_hosts.iter().any(|entry| {
            let (allowed_host, allowed_port) = split_host_port(entry.trim(), 443);
            allowed_host.eq_ignore_ascii_case(&lower) && allowed_port == port
        })
    }

    /// `Some(response)` when the session budget already blocks all egress.
    fn budget_gate(&self) -> Option<Response<Full<Bytes>>> {
        match self.budget.as_ref()?.gate_state() {
            BudgetGateDecision::Allowed => None,
            BudgetGateDecision::Paused => Some(self.error(
                StatusCode::TOO_MANY_REQUESTS,
                "session paused: autonomy budget exceeded; awaiting human budget approval",
            )),
            BudgetGateDecision::Terminated => Some(self.error(
                StatusCode::FORBIDDEN,
                "session terminated: autonomy budget exceeded",
            )),
        }
    }

    /// Audit a budget breach and build its `429` (paused) / `403` (terminated) response.
    fn budget_exceeded(&self, target: &str, alert: &BudgetAlert) -> Response<Full<Bytes>> {
        self.record_audit(
            "budget",
            Some(target.to_owned()),
            None,
            AuditDecision::BudgetExceeded,
            alert.message.clone(),
            0,
        );
        self.budget_gate().unwrap_or_else(|| {
            self.error(StatusCode::TOO_MANY_REQUESTS, "autonomy budget exceeded")
        })
    }

    /// Audit a breach that tripped on bookkeeping (the in-flight response is still delivered).
    fn note_budget(&self, target: &str, alert: Option<BudgetAlert>) {
        if let Some(alert) = alert {
            self.record_audit(
                "budget",
                Some(target.to_owned()),
                None,
                AuditDecision::BudgetExceeded,
                alert.message,
                0,
            );
        }
    }

    /// Count a denied / exfiltration-blocked attempt toward the anomaly cap.
    fn note_denied(&self, target: &str, reason: &str) {
        if let Some(budget) = &self.budget {
            self.note_budget(target, budget.record_denied_attempt(reason));
        }
    }

    fn record_audit(
        &self,
        action: &str,
        target: Option<String>,
        capability: Option<String>,
        decision: AuditDecision,
        reason: impl Into<String>,
        bytes_scrubbed: usize,
    ) {
        let (reason, _) = self.redactor.redact_str(&reason.into());
        let mut ev = AuditEvent::now(&self.identity, "premier-proxy", action, decision, reason);
        ev.target = target.map(|t| self.redactor.redact_str(&t).0);
        ev.capability = capability.map(|c| self.redactor.redact_str(&c).0);
        ev.bytes_scrubbed = bytes_scrubbed;
        if let Some(sid) = &self.session_id {
            ev.agent_task_id = Some(sid.clone());
        }
        self.audit.record(ev);
    }
}

#[cfg(unix)]
type SocketListener = tokio::net::UnixListener;
#[cfg(not(unix))]
type SocketListener = std::convert::Infallible;

#[cfg(unix)]
async fn accept_socket(
    listener: Option<&SocketListener>,
) -> std::io::Result<tokio::net::UnixStream> {
    match listener {
        Some(l) => l.accept().await.map(|(stream, _)| stream),
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn accept_socket(_: Option<&SocketListener>) -> std::io::Result<TcpStream> {
    std::future::pending().await
}

fn bind_socket(path: Option<&std::path::Path>) -> Result<Option<SocketListener>, ProxyError> {
    let Some(path) = path else { return Ok(None) };
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(path);
        SocketListener::bind(path)
            .map(Some)
            .map_err(|e| ProxyError::Io(format!("bind {} failed: {e}", path.display())))
    }
    #[cfg(not(unix))]
    Err(ProxyError::Io(format!(
        "a Unix socket listener ({}) needs a Unix host",
        path.display()
    )))
}

fn serve_connection<S>(state: Arc<ProxyState>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let svc = service_fn(move |req: Request<Incoming>| {
            let state = Arc::clone(&state);
            async move { handle_outer_request(state, req).await }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(io, svc)
            .with_upgrades()
            .await;
    });
}

/// Start the host-side egress capability proxy on `config.bind_addr`.
pub async fn start_proxy(config: ProxyConfig) -> Result<ProxyHandle, ProxyError> {
    if !config.bind_addr.ip().is_loopback() {
        return Err(ProxyError::Io(format!(
            "refusing to bind the capability proxy to non-loopback address {}",
            config.bind_addr
        )));
    }
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let auth_token = hex::encode(token_bytes);

    let ca = EphemeralCa::generate()?;
    let ca_cert_pem = ca.ca_cert_pem().to_owned();

    let mut root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for extra in config.extra_upstream_roots {
        root_store
            .add(extra)
            .map_err(|e| ProxyError::Tls(format!("add extra upstream root failed: {e}")))?;
    }

    let client_cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Tls(format!("rustls client protocol versions failed: {e}")))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let redactor = SecretRedactor::build(
        config
            .registry
            .all()
            .map(|c| (c.var_name.as_str(), c.secret.as_str())),
    );

    let state = Arc::new(ProxyState {
        identity: config.identity,
        session_id: config.session_id.clone(),
        ref_name: config.ref_name,
        policy: config.policy,
        registry: config.registry,
        redactor,
        allow_passthrough_hosts: config.allow_passthrough_hosts,
        audit: Arc::clone(&config.audit_sink),
        approvals: ApprovalManager::new(config.approval_gate),
        rate_limiter: RateLimiter::new(),
        ca,
        upstream_tls: TlsConnector::from(Arc::new(client_cfg)),
        auth_token: auth_token.clone(),
        upstream_resolve: config.upstream_resolve,
        upstream_connect_timeout: config.upstream_connect_timeout,
        upstream_tls_timeout: config.upstream_tls_timeout,
        upstream_request_timeout: config.upstream_request_timeout,
        max_request_body: config.max_request_body,
        max_response_body: config.max_response_body,
        budget: config.budget,
        session_context: config.session_context,
    });

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|e| ProxyError::Io(format!("bind {} failed: {e}", config.bind_addr)))?;
    let addr = listener
        .local_addr()
        .map_err(|e| ProxyError::Io(format!("local_addr failed: {e}")))?;
    let socket = bind_socket(config.unix_socket.as_deref())?;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept_res = listener.accept() => {
                    if let Ok((stream, _peer)) = accept_res {
                        serve_connection(Arc::clone(&state), stream);
                    }
                }
                accept_res = accept_socket(socket.as_ref()) => {
                    if let Ok(stream) = accept_res {
                        serve_connection(Arc::clone(&state), stream);
                    }
                }
            }
        }
    });

    Ok(ProxyHandle {
        addr,
        ca_cert_pem,
        audit_sink: config.audit_sink,
        auth_token,
        shutdown_tx: Some(shutdown_tx),
    })
}

async fn handle_outer_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Mode A: Zero-MITM Reverse Proxy (`/cap/[<token>/]<VAR_NAME>/<rest>`); authenticates itself.
    if req.method() != Method::CONNECT
        && req.uri().scheme().is_none()
        && req.uri().path().starts_with("/cap/")
    {
        return Ok(handle_reverse_cap_request(state, req).await);
    }

    if !state.header_authorized(req.headers()) {
        return Ok(state.auth_required());
    }

    if req.method() == Method::CONNECT {
        return Ok(handle_connect(state, req).await);
    }

    // Mode B (plain HTTP proxy): `GET http://host[:port]/path HTTP/1.1`
    if let Some(scheme) = req.uri().scheme_str() {
        let use_tls = scheme.eq_ignore_ascii_case("https");
        if !use_tls && !scheme.eq_ignore_ascii_case("http") {
            return Ok(state.error(StatusCode::BAD_REQUEST, "unsupported URL scheme"));
        }
        let host = req.uri().host().unwrap_or_default().to_owned();
        let port = req
            .uri()
            .port_u16()
            .unwrap_or(if use_tls { 443 } else { 80 });
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        return Ok(
            enforce_and_forward(state, req, host, port, use_tls, path_and_query, None).await,
        );
    }

    Ok(state.error(
        StatusCode::BAD_REQUEST,
        "unsupported proxy request; use /cap/<VAR>/..., HTTP_PROXY, or HTTPS CONNECT",
    ))
}

async fn handle_connect(state: Arc<ProxyState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_owned())
        .unwrap_or_default();
    let (host, port) = split_host_port(&authority, 443);

    if host.is_empty() {
        return state.error(StatusCode::BAD_REQUEST, "missing CONNECT host");
    }
    if let Some(resp) = state.budget_gate() {
        return resp;
    }

    // A secret host is reachable only on the TLS port its capability declares (443 by default),
    // an allow-listed passthrough host only on 443 (or its explicitly declared port).
    let is_secret = state.is_secret_host_port(&host, port);
    let is_passthrough = !is_secret && state.is_passthrough_host_port(&host, port);

    // Default-deny egress!
    if !is_secret && !is_passthrough {
        state.record_audit(
            "connect",
            Some(format!("{host}:{port}")),
            None,
            AuditDecision::Denied,
            format!(
                "'{host}:{port}' is not a declared .env.schema egress host/port or an allow-listed passthrough host on an allowed port"
            ),
            0,
        );
        state.note_denied(&format!("{host}:{port}"), "connect default-deny");
        return state.error(
            StatusCode::FORBIDDEN,
            &format!("egress denied by default-deny policy for '{host}:{port}'"),
        );
    }

    if is_secret {
        // Intercept TLS with ephemeral CA leaf cert for schema-declared secret host.
        let server_cfg = match state.ca.server_config_for_host(&host) {
            Ok(cfg) => cfg,
            Err(e) => {
                return state.error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("ephemeral cert generation failed: {e}"),
                );
            }
        };
        let state_clone = Arc::clone(&state);
        let host_clone = host.clone();

        tokio::spawn(async move {
            const MITM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
            const MITM_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                return;
            };
            let acceptor = TlsAcceptor::from(server_cfg);
            let Ok(Ok(tls_stream)) = tokio::time::timeout(
                MITM_HANDSHAKE_TIMEOUT,
                acceptor.accept(TokioIo::new(upgraded)),
            )
            .await
            else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |inner_req: Request<Incoming>| {
                let state = Arc::clone(&state_clone);
                let host = host_clone.clone();
                async move {
                    let pq = inner_req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str().to_owned())
                        .unwrap_or_else(|| "/".to_owned());
                    Ok::<_, hyper::Error>(
                        enforce_and_forward(state, inner_req, host, port, true, pq, None).await,
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .timer(TokioTimer::new())
                .header_read_timeout(MITM_HEADER_READ_TIMEOUT)
                .serve_connection(io, svc)
                .await;
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    } else {
        // Explicit non-secret passthrough host (e.g. package registry).
        if let Some(budget) = &state.budget
            && let Err(alert) = budget.check_and_record_egress_request(0)
        {
            return state.budget_exceeded(&format!("{host}:{port}"), &alert);
        }
        // Resolve & vet destination IPs BEFORE establishing the tunnel to prevent host-side SSRF
        // and DNS rebinding.
        let vetted_addrs = match resolve_vetted_upstream(&state, &host, port).await {
            Ok(addrs) => addrs,
            Err(EgressResolveError::Timeout) => {
                return state.error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream DNS resolution timed out",
                );
            }
            Err(EgressResolveError::Blocked(reason)) => {
                state.record_audit(
                    "connect_passthrough",
                    Some(format!("{host}:{port}")),
                    None,
                    AuditDecision::ExfiltrationBlocked,
                    reason.clone(),
                    0,
                );
                return state.error(StatusCode::FORBIDDEN, &reason);
            }
            Err(EgressResolveError::LookupFailed(reason)) => {
                state.record_audit(
                    "connect_passthrough",
                    Some(format!("{host}:{port}")),
                    None,
                    AuditDecision::Denied,
                    reason.clone(),
                    0,
                );
                return state.error(StatusCode::BAD_GATEWAY, &reason);
            }
        };
        let mut upstream =
            match connect_upstream(&vetted_addrs, state.upstream_connect_timeout).await {
                Ok(stream) => stream,
                Err(error) => return state.error(error.status(), &error.to_string()),
            };
        state.record_audit(
            "connect_passthrough",
            Some(format!("{host}:{port}")),
            None,
            AuditDecision::Allowed,
            "allow-listed non-secret passthrough host",
            0,
        );
        let target_addr = format!("{host}:{port}");
        let tunnel_state = Arc::clone(&state);
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                return;
            };
            let mut client = TokioIo::new(upgraded);
            pump_metered_tunnel(&mut client, &mut upstream, &tunnel_state, &target_addr).await;
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    }
}

async fn handle_reverse_cap_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let raw_pq = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_default();
    let mut rest = raw_pq.strip_prefix("/cap/").unwrap_or("");

    // The session token arrives as the first path segment or as `Proxy-Authorization`.
    let mut authorized = state.header_authorized(req.headers());
    if let Some((first, tail)) = rest.split_once('/')
        && state.token_ok(first.as_bytes())
    {
        authorized = true;
        rest = tail;
    }
    if !authorized {
        return state.auth_required();
    }

    let (var_name, forwarded_pq) = match rest.split_once('/') {
        Some((v, tail)) => (v.to_owned(), format!("/{tail}")),
        None => (rest.to_owned(), "/".to_owned()),
    };

    let Some(cap) = state.registry.get_by_var(&var_name) else {
        state.record_audit(
            "reverse_cap",
            Some(format!("/cap/{var_name}")),
            Some(var_name.clone()),
            AuditDecision::Denied,
            "unknown capability in /cap/<VAR> route",
            0,
        );
        return state.error(
            StatusCode::FORBIDDEN,
            &format!("unknown or unauthorized capability '{var_name}'"),
        );
    };

    let Some(logical_host) = cap.egress.hosts.first().cloned() else {
        return state.error(StatusCode::FORBIDDEN, "capability declares no egress host");
    };
    let port = cap.egress.tls_port();

    enforce_and_forward(
        state,
        req,
        logical_host,
        port,
        true,
        forwarded_pq,
        Some(var_name),
    )
    .await
}

async fn enforce_and_forward(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
    logical_host: String,
    upstream_port: u16,
    upstream_tls: bool,
    mut path_and_query: String,
    explicit_cap_var: Option<String>,
) -> Response<Full<Bytes>> {
    if let Some(resp) = state.budget_gate() {
        return resp;
    }
    let method = req.method().clone();
    let method_str = method.as_str().to_owned();
    let mut headers = req.headers().clone();

    // Framing cannot desync here: hyper drops `Content-Length` when `Transfer-Encoding` is
    // present, and the body is buffered whole and re-framed with a fresh `Content-Length`.
    let body_bytes = match Limited::new(req.into_body(), state.max_request_body)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            return state.error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the proxy limit or could not be read",
            );
        }
    };

    if let Some(budget) = &state.budget
        && let Err(alert) = budget.check_and_record_egress_request(body_bytes.len() as u64)
    {
        return state.budget_exceeded(
            &format!("{method_str} {logical_host}{path_and_query}"),
            &alert,
        );
    }

    // 1. Scan ALL headers, URI, and request body for ANY registered placeholder token!
    let mut matched_caps: Vec<&BoundCapability> = Vec::new();
    let mut seen_vars: HashSet<String> = HashSet::new();

    if let Some(ref explicit_var) = explicit_cap_var
        && let Some(cap) = state.registry.get_by_var(explicit_var)
    {
        seen_vars.insert(cap.var_name.clone());
        matched_caps.push(cap);
    }

    for (_, val) in &headers {
        for cap in state.registry.find_in_bytes(val.as_bytes()) {
            if seen_vars.insert(cap.var_name.clone()) {
                matched_caps.push(cap);
            }
        }
    }
    for cap in state.registry.find_in_bytes(path_and_query.as_bytes()) {
        if seen_vars.insert(cap.var_name.clone()) {
            matched_caps.push(cap);
        }
    }
    for cap in state.registry.find_in_bytes(&body_bytes) {
        if seen_vars.insert(cap.var_name.clone()) {
            matched_caps.push(cap);
        }
    }

    // 2. EXFILTRATION CHECK: Every placeholder present MUST be bound to `logical_host`!
    for cap in &matched_caps {
        if !cap.egress.matches_host(&logical_host) {
            state.record_audit(
                "exfiltration_attempt",
                Some(format!("{method_str} {logical_host}{path_and_query}")),
                Some(cap.var_name.clone()),
                AuditDecision::ExfiltrationBlocked,
                format!(
                    "BLOCKED: placeholder for '{}' sent to unauthorized host '{}' (allowed: {:?})",
                    cap.var_name, logical_host, cap.egress.hosts
                ),
                0,
            );
            state.note_denied(&format!("{logical_host}{path_and_query}"), "exfiltration");
            return state.error(
                StatusCode::FORBIDDEN,
                &format!(
                    "exfiltration blocked: capability '{}' is not authorized for host '{}'",
                    cap.var_name, logical_host
                ),
            );
        }
    }

    // 2b. A real secret only ever leaves over TLS, on the port its capability declares.
    for cap in &matched_caps {
        if !upstream_tls || upstream_port != cap.egress.tls_port() {
            state.record_audit(
                "capability_use",
                Some(format!("{method_str} {logical_host}:{upstream_port}")),
                Some(cap.var_name.clone()),
                AuditDecision::Denied,
                format!(
                    "'{}' is only delivered over TLS on port {}",
                    cap.var_name,
                    cap.egress.tls_port()
                ),
                0,
            );
            state.note_denied(&format!("{logical_host}:{upstream_port}"), "tls-only");
            return state.error(
                StatusCode::FORBIDDEN,
                &format!(
                    "capability '{}' is only delivered over TLS on port {}",
                    cap.var_name,
                    cap.egress.tls_port()
                ),
            );
        }
    }

    // 3. Default-deny host, port, and plaintext check for requests without a matched capability.
    if matched_caps.is_empty() {
        let allowed_secret = state.is_secret_host_port(&logical_host, upstream_port);
        let allowed_passthrough = state.is_passthrough_host_port(&logical_host, upstream_port);
        if !allowed_secret && !allowed_passthrough {
            state.record_audit(
                "egress",
                Some(format!(
                    "{method_str} {logical_host}:{upstream_port}{path_and_query}"
                )),
                None,
                AuditDecision::Denied,
                format!(
                    "'{logical_host}:{upstream_port}' not in egress allow-list (only declared TLS/passthrough ports permitted)"
                ),
                0,
            );
            state.note_denied(
                &format!("{logical_host}:{upstream_port}"),
                "host default-deny",
            );
            return state.error(
                StatusCode::FORBIDDEN,
                &format!(
                    "egress denied by default-deny policy for '{logical_host}:{upstream_port}'"
                ),
            );
        }
        let has_pin = state
            .upstream_resolve
            .contains_key(&logical_host.to_ascii_lowercase());
        if !upstream_tls && !has_pin {
            state.record_audit(
                "egress",
                Some(format!(
                    "{method_str} {logical_host}:{upstream_port}{path_and_query}"
                )),
                None,
                AuditDecision::Denied,
                format!("plaintext HTTP egress denied for external host '{logical_host}'"),
                0,
            );
            return state.error(
                StatusCode::FORBIDDEN,
                &format!(
                    "plaintext HTTP egress denied for external host '{logical_host}'; use HTTPS"
                ),
            );
        }
    }

    let path_only = path_and_query
        .split('?')
        .next()
        .unwrap_or(&path_and_query)
        .to_owned();

    // 4. Policy (`human ∩ agent`), method, path prefix, rate-limit, and JIT approval checks.
    for cap in &matched_caps {
        if let Some(policy) = &state.policy {
            let decision = policy.can_use_secret(
                &state.identity,
                &cap.var_name,
                cap.zone.as_deref(),
                &state.ref_name,
            );
            if !decision.allows(Capability::USE) && !decision.allows(Capability::READ) {
                state.record_audit(
                    "capability_use",
                    Some(format!("{method_str} {logical_host}{path_only}")),
                    Some(cap.var_name.clone()),
                    AuditDecision::Denied,
                    "policy denied USE capability for delegated identity",
                    0,
                );
                state.note_denied(&logical_host, "policy denied");
                return state.error(
                    StatusCode::FORBIDDEN,
                    &format!("policy denied USE of '{}'", cap.var_name),
                );
            }
        }

        if !cap.egress.matches_method(&method_str) {
            state.record_audit(
                "capability_use",
                Some(format!("{method_str} {logical_host}{path_only}")),
                Some(cap.var_name.clone()),
                AuditDecision::Denied,
                format!(
                    "HTTP method '{method_str}' not allowed for '{}'",
                    cap.var_name
                ),
                0,
            );
            state.note_denied(&logical_host, "method denied");
            return state.error(
                StatusCode::FORBIDDEN,
                &format!("method '{method_str}' not permitted for '{}'", cap.var_name),
            );
        }

        let Some(approved_prefix) = cap.egress.matched_path_prefix(&path_only) else {
            state.record_audit(
                "capability_use",
                Some(format!("{method_str} {logical_host}{path_only}")),
                Some(cap.var_name.clone()),
                AuditDecision::Denied,
                format!(
                    "path '{path_only}' outside allowed prefixes for '{}'",
                    cap.var_name
                ),
                0,
            );
            state.note_denied(&logical_host, "path denied");
            return state.error(
                StatusCode::FORBIDDEN,
                &format!("path '{path_only}' not permitted for '{}'", cap.var_name),
            );
        };

        if let Some(limit) = cap.egress.rate_limit_per_min
            && !state.rate_limiter.check_and_increment(&cap.var_name, limit)
        {
            state.record_audit(
                "capability_use",
                Some(format!("{method_str} {logical_host}{path_only}")),
                Some(cap.var_name.clone()),
                AuditDecision::RateLimited,
                format!("rate limit ({limit}/min) exceeded for '{}'", cap.var_name),
                0,
            );
            return state.error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("rate limit exceeded for '{}'", cap.var_name),
            );
        }

        let agent_profile = state
            .identity
            .agent_task
            .as_ref()
            .map(|t| t.profile.as_str());
        let risk_level = classify_risk(&method_str, &path_only, cap.sensitivity);
        // A learned or hand-written auto_allow never skips the knock for a restricted secret or
        // a sensitive scope: those are always shown to a human.
        if cap.egress.approval == ApprovalMode::Jit
            && (risk_level == RiskLevel::SensitiveScope
                || !cap.egress.matches_auto_allow(
                    agent_profile,
                    &logical_host,
                    &method_str,
                    &path_only,
                ))
        {
            if let Some(budget) = &state.budget
                && let Err(alert) = budget.record_jit_request()
            {
                return state
                    .budget_exceeded(&format!("{method_str} {logical_host}{path_only}"), &alert);
            }
            let concrete_path = state.sanitize_text(&path_only);
            let scrub = |v: &Option<String>| v.as_deref().map(|s| state.sanitize_text(s));
            let req = ApprovalRequest {
                principal: state.identity.principal.canonical_id(),
                agent_profile: agent_profile.map(str::to_owned),
                var_name: cap.var_name.clone(),
                host: logical_host.clone(),
                method: method_str.clone(),
                // The grant covers exactly the prefix the approver is shown.
                path: approved_prefix.to_owned(),
                ttl_secs: cap.egress.jit_ttl_secs,
                intent_summary: Some(synthesize_intent_summary(
                    &method_str,
                    &logical_host,
                    &concrete_path,
                    risk_level,
                )),
                wire_preview: Some(build_wire_preview(
                    &state,
                    cap,
                    &method_str,
                    &logical_host,
                    &path_and_query,
                    &path_only,
                    &headers,
                    &body_bytes,
                )),
                session_context: state.session_context.as_ref().map(|c| SessionContext {
                    session_id: scrub(&c.session_id),
                    branch: scrub(&c.branch),
                    command: scrub(&c.command),
                }),
                sensitivity: serde_json::to_value(cap.sensitivity)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned)),
                concrete_path: Some(concrete_path),
                risk_level,
                expires_at: None,
                ..Default::default()
            };
            if let Err(reason) = state.approvals.authorize_request(req) {
                let reason = reason.map(|r| state.sanitize_text(&r));
                let suffix = reason
                    .as_deref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default();
                state.record_audit(
                    "jit_approval",
                    Some(format!("{method_str} {logical_host}{path_only}")),
                    Some(cap.var_name.clone()),
                    AuditDecision::ApprovalRequired,
                    format!("JIT capability approval denied or timed out{suffix}"),
                    0,
                );
                let msg = match reason {
                    Some(r) => format!("JIT approval denied for '{}': {r}", cap.var_name),
                    None => format!("JIT approval required and denied for '{}'", cap.var_name),
                };
                return state.error(StatusCode::FORBIDDEN, &msg);
            }
        }
    }

    // 4b. Resolve & vet destination IPs BEFORE secret substitution and TCP connect (anti-SSRF &
    //     anti-DNS-rebinding).
    let vetted_addrs = match resolve_vetted_upstream(&state, &logical_host, upstream_port).await {
        Ok(addrs) => addrs,
        Err(EgressResolveError::Timeout) => {
            return state.error(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream DNS resolution timed out",
            );
        }
        Err(EgressResolveError::Blocked(reason)) => {
            state.record_audit(
                "egress_ssrf",
                Some(format!(
                    "{method_str} {logical_host}:{upstream_port}{path_only}"
                )),
                if matched_caps.is_empty() {
                    None
                } else {
                    Some(
                        matched_caps
                            .iter()
                            .map(|c| c.var_name.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                },
                AuditDecision::ExfiltrationBlocked,
                reason.clone(),
                0,
            );
            return state.error(StatusCode::FORBIDDEN, &reason);
        }
        Err(EgressResolveError::LookupFailed(reason)) => {
            state.record_audit(
                "egress",
                Some(format!(
                    "{method_str} {logical_host}:{upstream_port}{path_only}"
                )),
                None,
                AuditDecision::Denied,
                reason.clone(),
                0,
            );
            return state.error(StatusCode::BAD_GATEWAY, &reason);
        }
    };

    // Drop hop-by-hop headers, and everything that would let the upstream answer with bytes the
    // scrubber cannot read: compression, and ranges that could slice a reflected secret.
    strip_hop_by_hop(&mut headers);
    for name in [
        "host",
        "content-length",
        "accept-encoding",
        "range",
        "if-range",
    ] {
        headers.remove(name);
    }
    headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let host_header = if upstream_port == if upstream_tls { 443 } else { 80 } {
        logical_host.clone()
    } else {
        format!("{logical_host}:{upstream_port}")
    };
    if let Ok(hv) = HeaderValue::from_str(&host_header) {
        headers.insert(http::header::HOST, hv);
    }

    // 5. Wire substitution: swap placeholder -> real secret (Zeroizing) & apply InjectSpec.
    //    From here on nothing derived from `headers`, `path_and_query` or `outbound_body` may be
    //    formatted into an error, a log line or an audit record.
    let mut outbound_body = body_bytes;

    for cap in &matched_caps {
        // Replace placeholder anywhere in headers, query, or body.
        replace_in_headers(&mut headers, &cap.placeholder, cap.secret.as_str());
        if path_and_query.contains(&cap.placeholder) {
            path_and_query = path_and_query.replace(
                &cap.placeholder,
                &percent_encode_component(cap.secret.as_str()),
            );
        }
        outbound_body = replace_bytes(
            &outbound_body,
            cap.placeholder.as_bytes(),
            cap.secret.as_bytes(),
        );

        // Apply declarative injection mode when caller did not already include placeholder in header.
        match &cap.egress.inject {
            InjectSpec::PlaceholderReplace => {}
            InjectSpec::BearerHeader { header } => {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(header.as_bytes()),
                    HeaderValue::from_str(&format!("Bearer {}", cap.secret.as_str())),
                ) {
                    headers.insert(name, val);
                }
            }
            InjectSpec::Header { header, prefix } => {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(header.as_bytes()),
                    HeaderValue::from_str(&format!("{prefix}{}", cap.secret.as_str())),
                ) {
                    headers.insert(name, val);
                }
            }
            InjectSpec::QueryParam { param } => {
                let sep = if path_and_query.contains('?') {
                    '&'
                } else {
                    '?'
                };
                path_and_query.push_str(&format!(
                    "{sep}{param}={}",
                    percent_encode_component(cap.secret.as_str())
                ));
            }
        }
    }

    // 6. Forward request to upstream over TCP or TLS (`rustls`/`ring`). The TLS peer is always
    //    verified as `logical_host`; a schema can never point the connection anywhere else.
    let target = format!("{method_str} {logical_host}{path_only}");
    let cap_summary = if matched_caps.is_empty() {
        None
    } else {
        Some(
            matched_caps
                .iter()
                .map(|c| c.var_name.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
    };

    let response = tokio::time::timeout(
        state.upstream_request_timeout,
        forward_upstream(
            &state,
            &logical_host,
            &vetted_addrs,
            upstream_tls,
            method,
            &path_and_query,
            headers,
            outbound_body,
        ),
    )
    .await
    .unwrap_or(Err(UpstreamError::Timeout("HTTP exchange")));
    let (parts, raw_resp_body) = match response {
        Ok(response) => response,
        Err(error) => {
            state.record_audit(
                "capability_use",
                Some(target),
                cap_summary,
                AuditDecision::Denied,
                format!("response withheld: {error}"),
                0,
            );
            return state.error(error.status(), &format!("response withheld: {error}"));
        }
    };

    // 7. Scrub raw secrets (and their encodings) from response headers AND body.
    let (scrubbed_body, mut total_scrubbed) = state.redactor.redact_bytes(&raw_resp_body);
    let mut out_headers = parts.headers;
    strip_hop_by_hop(&mut out_headers);
    out_headers.remove(http::header::CONTENT_LENGTH);
    let mut out_builder = Response::builder().status(parts.status);
    for (name, value) in &out_headers {
        let (scrubbed_val, n) = state.redactor.redact_bytes(value.as_bytes());
        total_scrubbed += n;
        if let Ok(hv) = HeaderValue::from_bytes(&scrubbed_val) {
            out_builder = out_builder.header(name, hv);
        }
    }

    if let Some(budget) = &state.budget {
        let alert = budget.record_egress_bytes(raw_resp_body.len() as u64);
        budget.record_scrubbed(total_scrubbed as u64);
        state.note_budget(&target, alert);
    }

    state.record_audit(
        "capability_use",
        Some(target),
        cap_summary,
        if total_scrubbed > 0 {
            AuditDecision::Redacted
        } else {
            AuditDecision::Allowed
        },
        if total_scrubbed > 0 {
            format!("forwarded with {total_scrubbed} secret bytes scrubbed from upstream response")
        } else {
            "forwarded cleanly".to_owned()
        },
        total_scrubbed,
    );

    out_builder
        .body(Full::new(Bytes::from(scrubbed_body)))
        .unwrap_or_else(|_| state.error(StatusCode::INTERNAL_SERVER_ERROR, "response build error"))
}

/// Most query keys a preview lists.
const PREVIEW_MAX_QUERY_KEYS: usize = 32;
/// Most body characters a preview shows.
const PREVIEW_MAX_BODY_CHARS: usize = 1024;

/// What the approver sees of a request: built strictly BEFORE wire substitution, so it holds
/// placeholders, never secrets; everything is scrubbed again and the session token removed.
#[allow(clippy::too_many_arguments)]
fn build_wire_preview(
    state: &ProxyState,
    cap: &BoundCapability,
    method_str: &str,
    logical_host: &str,
    path_and_query: &str,
    path_only: &str,
    headers: &HeaderMap,
    body_bytes: &[u8],
) -> WirePreview {
    let mut wire_headers = headers.clone();
    strip_hop_by_hop(&mut wire_headers);
    let mut preview_headers: Vec<SanitizedHeader> = wire_headers
        .iter()
        .map(|(name, value)| SanitizedHeader {
            name: name.as_str().to_owned(),
            value: state.sanitize_text(&String::from_utf8_lossy(value.as_bytes())),
            contains_placeholder: !state.registry.find_in_bytes(value.as_bytes()).is_empty(),
        })
        .collect();

    // Keys only: query values may carry anything.
    let mut query_keys: Vec<String> = Vec::new();
    let query = path_and_query.split_once('?').map_or("", |(_, q)| q);
    for pair in query.split('&') {
        let key = state.sanitize_text(pair.split('=').next().unwrap_or(""));
        if !key.is_empty() && !query_keys.contains(&key) {
            query_keys.push(key);
        }
    }

    // Mirror step 5's declarative injection, with the placeholder standing in for the secret.
    let injected = match &cap.egress.inject {
        InjectSpec::PlaceholderReplace => None,
        InjectSpec::BearerHeader { header } => {
            Some((header, format!("Bearer {}", cap.placeholder)))
        }
        InjectSpec::Header { header, prefix } => {
            Some((header, format!("{prefix}{}", cap.placeholder)))
        }
        InjectSpec::QueryParam { param } => {
            if !query_keys.contains(param) {
                query_keys.push(param.clone());
            }
            None
        }
    };
    if let Some((header, value)) = injected {
        // Step 5 overwrites the header, so the preview shows only the injected value.
        preview_headers.retain(|h| !h.name.eq_ignore_ascii_case(header));
        preview_headers.push(SanitizedHeader {
            name: header.to_ascii_lowercase(),
            value: state.sanitize_text(&value),
            contains_placeholder: true,
        });
    }
    query_keys.truncate(PREVIEW_MAX_QUERY_KEYS);

    // Scrub the WHOLE body before cutting it, so no secret can straddle the truncation point.
    let (scrubbed, _) = state.redactor.redact_bytes(body_bytes);
    let scrubbed = replace_bytes(
        &scrubbed,
        state.auth_token.as_bytes(),
        b"[REDACTED:PROXY_TOKEN]",
    );
    let text = std::str::from_utf8(&scrubbed)
        .ok()
        .filter(|t| !t.contains('\0'));
    let body_is_binary = text.is_none();
    let body_truncated = text.is_some_and(|t| t.chars().count() > PREVIEW_MAX_BODY_CHARS);
    let body_preview = text
        .filter(|t| !t.is_empty())
        .map(|t| t.chars().take(PREVIEW_MAX_BODY_CHARS).collect());

    WirePreview {
        method: method_str.to_ascii_uppercase(),
        host: logical_host.to_ascii_lowercase(),
        concrete_path: state.sanitize_text(path_only),
        query_keys,
        headers: preview_headers,
        body_preview,
        body_size_bytes: body_bytes.len(),
        body_truncated,
        body_is_binary,
    }
}

#[derive(Debug, thiserror::Error)]
enum UpstreamError {
    #[error("upstream {0} timed out")]
    Timeout(&'static str),
    #[error(transparent)]
    Failed(#[from] ProxyError),
}

impl UpstreamError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::Failed(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

async fn connect_upstream(
    addrs: &[SocketAddr],
    deadline: Duration,
) -> Result<TcpStream, UpstreamError> {
    Ok(tokio::time::timeout(deadline, TcpStream::connect(addrs))
        .await
        .map_err(|_| UpstreamError::Timeout("TCP connect"))?
        .map_err(|e| ProxyError::Io(format!("upstream connect failed: {e}")))?)
}

#[allow(clippy::too_many_arguments)]
async fn forward_upstream(
    state: &ProxyState,
    connect_host: &str,
    vetted_addrs: &[SocketAddr],
    use_tls: bool,
    method: Method,
    path_and_query: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(http::response::Parts, Bytes), UpstreamError> {
    let tcp = connect_upstream(vetted_addrs, state.upstream_connect_timeout).await?;

    // Post-substitution data: never echo the path or the parse error.
    let uri: Uri = path_and_query
        .parse()
        .map_err(|_| ProxyError::Http("outbound request target is not a valid URI".to_owned()))?;

    let mut req_builder = Request::builder().method(method).uri(uri);
    for (k, v) in &headers {
        req_builder = req_builder.header(k, v);
    }
    let outbound_req = req_builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| ProxyError::Http(format!("build outbound request failed: {e}")))?;

    if use_tls {
        let server_name = ServerName::try_from(connect_host.to_owned()).map_err(|e| {
            ProxyError::Tls(format!("invalid TLS server name '{connect_host}': {e}"))
        })?;
        let tls_stream = tokio::time::timeout(
            state.upstream_tls_timeout,
            state.upstream_tls.connect(server_name, tcp),
        )
        .await
        .map_err(|_| UpstreamError::Timeout("TLS handshake"))?
        .map_err(|e| ProxyError::Tls(format!("upstream TLS handshake failed: {e}")))?;
        exchange_http(tls_stream, outbound_req, state.max_response_body).await
    } else {
        exchange_http(tcp, outbound_req, state.max_response_body).await
    }
}

async fn exchange_http<I>(
    stream: I,
    request: Request<Full<Bytes>>,
    max_response_body: usize,
) -> Result<(http::response::Parts, Bytes), UpstreamError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| ProxyError::Http(format!("upstream HTTP handshake failed: {e}")))?;
    let response = async move {
        let (parts, body) = sender
            .send_request(request)
            .await
            .map_err(|e| ProxyError::Http(format!("upstream send failed: {e}")))?
            .into_parts();
        // Fail closed on formats the scrubber cannot inspect as plain bytes.
        if parts
            .headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(UpstreamError::from(ProxyError::Http(
                "upstream ignored Accept-Encoding: identity".to_owned(),
            )));
        }
        let body = Limited::new(body, max_response_body)
            .collect()
            .await
            .map_err(|_| {
                ProxyError::Http(
                    "upstream response exceeds the scrubbing limit or could not be read".to_owned(),
                )
            })?
            .to_bytes();
        Ok((parts, body))
    };
    tokio::pin!(response);
    // Driving both futures here makes deadline cancellation close the connection and free buffers.
    tokio::select! {
        biased;
        result = &mut response => result,
        result = connection => {
            result.map_err(|e| ProxyError::Http(format!("upstream connection failed: {e}")))?;
            response.await
        }
    }
}

fn replace_in_headers(headers: &mut HeaderMap, placeholder: &str, secret: &str) {
    let keys: Vec<HeaderName> = headers.keys().cloned().collect();
    for key in keys {
        let updated: Vec<HeaderValue> = headers
            .get_all(&key)
            .iter()
            .map(|val| {
                if let Ok(s) = val.to_str()
                    && s.contains(placeholder)
                {
                    let replaced = s.replace(placeholder, secret);
                    return HeaderValue::from_str(&replaced).unwrap_or_else(|_| val.clone());
                }
                val.clone()
            })
            .collect();
        headers.remove(&key);
        for v in updated {
            headers.append(&key, v);
        }
    }
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

async fn relay_one_half<R, W>(reader: &mut R, writer: &mut W, state: &ProxyState, target_addr: &str)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            break;
        }
        if let Some(budget) = &state.budget {
            let alert = budget.record_egress_bytes(n as u64);
            let blocked = alert.is_some() || budget.gate_state() != BudgetGateDecision::Allowed;
            state.note_budget(target_addr, alert);
            if blocked {
                return;
            }
        }
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Relay bytes in both directions across an upgraded `CONNECT` tunnel while accounting every chunk
/// to `state.budget` (including error/abort paths) and severing the connection immediately on breach.
async fn pump_metered_tunnel<C, U>(
    client: &mut C,
    upstream: &mut U,
    state: &ProxyState,
    target_addr: &str,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    {
        let (mut cr, mut cw) = tokio::io::split(&mut *client);
        let (mut ur, mut uw) = tokio::io::split(&mut *upstream);
        let c2u = relay_one_half(&mut cr, &mut uw, state, target_addr);
        let u2c = relay_one_half(&mut ur, &mut cw, state, target_addr);
        if let Some(budget) = &state.budget {
            tokio::select! {
                _ = async { tokio::join!(c2u, u2c) } => {}
                _ = budget.wait_blocked() => {}
            }
        } else {
            tokio::join!(c2u, u2c);
        }
    }
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = authority.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.trim_matches(['[', ']']).to_owned(), port);
    }
    (authority.trim_matches(['[', ']']).to_owned(), default_port)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use premier_core::Principal;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn proxy_times_out_on_stalled_upstream_response_body() {
        assert_stall_times_out(false).await;
    }

    #[tokio::test]
    async fn proxy_times_out_on_stalled_upstream_tls_handshake() {
        assert_stall_times_out(true).await;
    }

    async fn assert_stall_times_out(use_tls: bool) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            DelegatedIdentity::human_only(Principal::Anonymous, vec![]),
            PlaceholderRegistry::new(),
        );
        let host = "stall.example";
        let (scheme, port) = if use_tls {
            ("https", 443)
        } else {
            ("http", 80)
        };
        let authority = format!("{host}:{port}");
        config.allow_passthrough_hosts.insert(authority.clone());
        config
            .upstream_resolve
            .insert(host.to_owned(), upstream.local_addr().unwrap());
        if use_tls {
            config.upstream_tls_timeout = Duration::from_millis(100);
        } else {
            config.upstream_request_timeout = Duration::from_millis(100);
        }
        let proxy = start_proxy(config).await.unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            if !use_tls {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
                    .await
                    .unwrap();
            }
            // A timed-out exchange drops the upstream socket, so the peer sees EOF.
            assert_eq!(socket.read(&mut request).await.unwrap(), 0);
        });
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("premier:{}", proxy.auth_token));
        client.write_all(format!("GET {scheme}://{authority}/ HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(std::time::Duration::from_millis(800), async {
            client.read_to_string(&mut response).await.unwrap();
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 504 "), "{response}");
        assert!(response.contains(if use_tls {
            "TLS handshake"
        } else {
            "HTTP exchange"
        }));
        assert!(!response.contains("partial"));
    }
}
