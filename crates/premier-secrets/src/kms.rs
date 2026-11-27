//! Server-mediated Envelope KMS: per-vault DEKs wrapped by a separated KEK (env/file KEK,
//! HashiCorp Vault Transit, or `age`), plus the strict-TLS HTTP helper shared by every
//! outbound connector in this crate.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::SecretError;
use crate::backend::{
    AgeSovereignBackend, SecretBackend, SecretCoord, age_unwrap, age_wrap, create_state_dir,
    write_private,
};
use crate::key_transparency::{KeyTransparencyLog, acquire_path_lock, recipients_fingerprint};

/// Process env var holding a 32-byte KEK as 64 hex chars or base64.
pub const PREMIER_KMS_KEY_ENV: &str = "PREMIER_KMS_KEY";
/// Process env var holding `env://VAR_NAME` or `file:///path/to/kek.key`.
pub const PREMIER_KMS_URI_ENV: &str = "PREMIER_KMS_URI";
/// On-disk format version of [`EnvelopeVaultFile`].
pub const ENVELOPE_VAULT_VERSION: u32 = 2;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 1 << 20;

// ---------------------------------------------------------------------------------------------
// Strict-TLS HTTP JSON helper
// ---------------------------------------------------------------------------------------------

/// One outbound JSON request. Header values and bodies are zeroized after use.
pub(crate) struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    pub body: Option<Zeroizing<Vec<u8>>>,
    pub allow_insecure_loopback: bool,
    pub block_private_ips: bool,
    pub extra_root_certs: Vec<CertificateDer<'static>>,
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

impl HttpResponse {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parse the body. The serde error is dropped on purpose: it can quote response values.
    pub(crate) fn json<T: DeserializeOwned>(&self, what: &str) -> Result<T, SecretError> {
        serde_json::from_slice(&self.body)
            .map_err(|_| SecretError::Backend(format!("{what} returned an unexpected JSON body")))
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// `https` anywhere; cleartext `http` only to loopback and only when explicitly allowed.
/// Returns whether TLS is required.
pub(crate) fn validate_endpoint(
    url: &Url,
    allow_insecure_loopback: bool,
) -> Result<bool, SecretError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SecretError::Backend(
            "endpoint URL must not embed credentials".to_owned(),
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(SecretError::Backend(
            "endpoint URL must name a host".to_owned(),
        ));
    }
    match url.scheme() {
        "https" => Ok(true),
        "http" if allow_insecure_loopback && is_loopback(url) => Ok(false),
        "http" => Err(SecretError::Backend(
            "cleartext http is refused: use https (http is only allowed to loopback with allow_insecure_loopback)".to_owned(),
        )),
        other => Err(SecretError::Backend(format!(
            "unsupported endpoint scheme '{other}'"
        ))),
    }
}

/// Parse and validate a connector base address (`https://host[:port][/base]`).
pub(crate) fn validate_base_url(
    raw: &str,
    allow_insecure_loopback: bool,
) -> Result<Url, SecretError> {
    let url = Url::parse(raw.trim())
        .map_err(|e| SecretError::Backend(format!("invalid endpoint address: {e}")))?;
    validate_endpoint(&url, allow_insecure_loopback)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(SecretError::Backend(
            "endpoint address must not carry a query or fragment".to_owned(),
        ));
    }
    Ok(url)
}

/// `base` + an already-encoded absolute `path`.
pub(crate) fn join_url(base: &Url, path: &str) -> String {
    format!("{}{path}", base.as_str().trim_end_matches('/'))
}

/// `a/b/c` of `[A-Za-z0-9._-]` segments: no empty, `.` or `..` segments, no `?`/`#`/`%`.
pub(crate) fn validate_path_segments(
    what: &str,
    value: &str,
    allow_nested: bool,
) -> Result<(), SecretError> {
    let ok = !value.is_empty()
        && (allow_nested || !value.contains('/'))
        && value.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        });
    if ok {
        Ok(())
    } else {
        Err(SecretError::Backend(format!(
            "{what} must be safe path segments of [A-Za-z0-9._-] (no '..', '?', '#')"
        )))
    }
}

/// Parse PEM certificates (e.g. a private CA for an on-prem Vault) into extra trust roots.
pub fn parse_pem_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, SecretError> {
    let mut reader = pem;
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SecretError::Backend(format!("invalid PEM certificate: {e}")))?;
    if certs.is_empty() {
        return Err(SecretError::Backend("no PEM certificates found".to_owned()));
    }
    Ok(certs)
}

fn tls_client_config(extra: &[CertificateDer<'static>]) -> Result<ClientConfig, SecretError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots
            .add(cert.clone())
            .map_err(|e| SecretError::Backend(format!("add extra root certificate failed: {e}")))?;
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| SecretError::Backend(format!("TLS protocol setup failed: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn send_http1<S>(io: S, request: Request<Full<Bytes>>) -> Result<HttpResponse, SecretError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| SecretError::Backend(format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| SecretError::Backend(format!("HTTP request failed: {e}")))?;
    let status = resp.status().as_u16();
    let collected = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| {
            SecretError::Backend("reading HTTP response failed or exceeded 1 MiB".to_owned())
        })?;
    Ok(HttpResponse {
        status,
        body: Zeroizing::new(collected.to_bytes().to_vec()),
    })
}

fn is_forbidden_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (b & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
                || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 protocol assignments
                || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmark
                || a >= 240 // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_webhook_ip(IpAddr::V4(mapped));
            }
            let segs = v6.segments();
            if segs[..6] == [0; 6] {
                if let Some(compat) = v6.to_ipv4() {
                    return is_forbidden_webhook_ip(IpAddr::V4(compat));
                }
                return true;
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (segs[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (segs[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
                || (segs[0] == 0x2001 && segs[1] == 0x0db8) // documentation 2001:db8::/32
                || (segs[0] == 0x0064
                    && segs[1] == 0xff9b
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0) // NAT64 well-known prefix 64:ff9b::/96
                || (segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001) // NAT64 local-use 64:ff9b:1::/48
                || segs[0] == 0x2002 // 6to4 2002::/16
                || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0) // discard-only 100::/64
        }
    }
}

/// Send one JSON request over verified TLS (webpki roots + `extra_root_certs`).
pub(crate) async fn http_json_request_async(req: HttpRequest) -> Result<HttpResponse, SecretError> {
    let url = Url::parse(&req.url)
        .map_err(|e| SecretError::Backend(format!("invalid endpoint URL: {e}")))?;
    let use_tls = validate_endpoint(&url, req.allow_insecure_loopback)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| SecretError::Backend("endpoint URL has no port".to_owned()))?;
    let (host, addrs): (String, Vec<SocketAddr>) = match url.host() {
        Some(Host::Ipv4(ip)) => (ip.to_string(), vec![SocketAddr::new(IpAddr::V4(ip), port)]),
        Some(Host::Ipv6(ip)) => (ip.to_string(), vec![SocketAddr::new(IpAddr::V6(ip), port)]),
        Some(Host::Domain(d)) => {
            let host = d.to_owned();
            let resolved = tokio::net::lookup_host((d, port))
                .await
                .map_err(|e| SecretError::Backend(format!("resolve {host}:{port} failed: {e}")))?
                .collect();
            (host, resolved)
        }
        None => {
            return Err(SecretError::Backend(
                "endpoint URL must name a host".to_owned(),
            ));
        }
    };
    if addrs.is_empty() {
        return Err(SecretError::Backend(format!(
            "no addresses resolved for {host}:{port}"
        )));
    }
    if req.block_private_ips
        && let Some(bad) = addrs.iter().find(|a| is_forbidden_webhook_ip(a.ip()))
    {
        return Err(SecretError::Backend(format!(
            "refusing private, loopback, or link-local webhook address {} for '{host}'",
            bad.ip()
        )));
    }
    let host_str = url.host_str().unwrap_or_default();
    let host_header = match url.port() {
        Some(p) => format!("{host_str}:{p}"),
        None => host_str.to_owned(),
    };
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };

    let mut builder = Request::builder()
        .method(req.method)
        .uri(target)
        .header(header::HOST, host_header)
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "premier-secrets");
    for (name, value) in &req.headers {
        let mut v = HeaderValue::from_str(value)
            .map_err(|_| SecretError::Backend(format!("header {name} has an invalid value")))?;
        v.set_sensitive(true);
        builder = builder.header(*name, v);
    }
    let body = match &req.body {
        Some(b) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Bytes::copy_from_slice(b)
        }
        None => Bytes::new(),
    };
    let request = builder
        .body(Full::new(body))
        .map_err(|e| SecretError::Backend(format!("build HTTP request failed: {e}")))?;

    let exchange = async {
        // Connect to the pinned pre-validated SocketAddrs so DNS rebinding cannot pivot targets.
        let tcp = TcpStream::connect(&addrs[..])
            .await
            .map_err(|e| SecretError::Backend(format!("connect to {host}:{port} failed: {e}")))?;
        if use_tls {
            let connector = TlsConnector::from(Arc::new(tls_client_config(&req.extra_root_certs)?));
            let name = ServerName::try_from(host.clone())
                .map_err(|_| SecretError::Backend(format!("invalid TLS server name '{host}'")))?;
            let tls = connector.connect(name, tcp).await.map_err(|e| {
                SecretError::Backend(format!("TLS handshake with {host} failed: {e}"))
            })?;
            send_http1(tls, request).await
        } else {
            send_http1(tcp, request).await
        }
    };
    tokio::time::timeout(HTTP_TIMEOUT, exchange)
        .await
        .map_err(|_| SecretError::Backend(format!("request to {host} timed out")))?
}

/// Run `fut` to completion on a dedicated thread with its own current-thread runtime, so
/// synchronous `SecretBackend`/`KeyWrapper` calls work from inside an async runtime too.
pub(crate) fn run_async<F, T>(fut: F) -> Result<T, SecretError>
where
    F: Future<Output = Result<T, SecretError>> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SecretError::Backend(format!("start async runtime failed: {e}")))?
            .block_on(fut)
    })
    .join()
    .map_err(|_| SecretError::Backend("async worker thread panicked".to_owned()))?
}

/// Blocking form of [`http_json_request_async`].
pub(crate) fn http_json_request(req: HttpRequest) -> Result<HttpResponse, SecretError> {
    run_async(http_json_request_async(req))
}

// ---------------------------------------------------------------------------------------------
// AEAD helpers
// ---------------------------------------------------------------------------------------------

fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<String, SecretError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SecretError::Crypto(format!("aes-gcm init failed: {e}")))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| SecretError::Crypto(format!("aes-gcm encrypt failed: {e}")))?;
    Ok(format!("{}:{}", B64.encode(nonce), B64.encode(ct)))
}

/// `None` on any malformed input or authentication failure (callers name the context).
fn aead_open(key: &[u8; 32], aad: &[u8], encoded: &str) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce_b64, ct_b64) = encoded.split_once(':')?;
    let nonce = B64.decode(nonce_b64).ok().filter(|n| n.len() == 12)?;
    let ct = B64.decode(ct_b64).ok()?;
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct.as_slice(),
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn dek_from_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    if bytes.len() != 32 {
        return Err(SecretError::Crypto(
            "unwrapped DEK has wrong length".to_owned(),
        ));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(bytes);
    Ok(dek)
}

fn random_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *dek);
    dek
}

fn wrap_aad(key_id: &str, aad_context: &str) -> String {
    format!("premier-kms-dek-v1:{key_id}:{aad_context}")
}

// ---------------------------------------------------------------------------------------------
// Key wrappers
// ---------------------------------------------------------------------------------------------

/// Wraps/unwraps 32-byte data-encryption keys under a key-encryption key held elsewhere.
pub trait KeyWrapper: Send + Sync {
    fn provider_name(&self) -> &str;
    fn key_id(&self) -> &str;
    fn wrap_dek(&self, dek: &[u8; 32], aad_context: &str) -> Result<String, SecretError>;
    fn unwrap_dek(
        &self,
        wrapped: &str,
        aad_context: &str,
    ) -> Result<Zeroizing<[u8; 32]>, SecretError>;
}

/// Local 32-byte KEK from the environment or a file kept outside the vault directory.
pub struct EnvKekWrapper {
    key_id: String,
    kek: Zeroizing<[u8; 32]>,
    source_path: Option<PathBuf>,
}

impl std::fmt::Debug for EnvKekWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvKekWrapper")
            .field("key_id", &self.key_id)
            .field("kek", &"[redacted]")
            .field("source_path", &self.source_path)
            .finish()
    }
}

fn decode_kek(raw: &str) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    let raw = raw.trim();
    let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(raw).map_err(|_| SecretError::Crypto("KEK hex is invalid".to_owned()))?
    } else {
        B64.decode(raw).map_err(|_| {
            SecretError::Crypto("KEK must be 64 hex chars or base64 of 32 bytes".to_owned())
        })?
    };
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 32 {
        return Err(SecretError::Crypto(
            "KEK must be exactly 32 bytes".to_owned(),
        ));
    }
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&bytes);
    Ok(kek)
}

/// Stable, non-reversible id for a KEK (bound into every wrap's AAD).
fn kek_key_id(kek: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"premier-kek-id-v1");
    h.update(kek);
    let digest = hex::encode(h.finalize());
    format!("kek-{}", &digest[..16])
}

/// Absolute path with symlinks resolved for the deepest existing ancestor.
fn canonicalize_lenient(path: &Path) -> Result<PathBuf, SecretError> {
    let abs = std::path::absolute(path)
        .map_err(|e| SecretError::Io(format!("resolve path failed: {e}")))?;
    if abs.components().any(|c| c == Component::ParentDir) {
        return Err(SecretError::Backend(
            "KEK and vault paths must not contain '..'".to_owned(),
        ));
    }
    let mut existing = abs.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(canon) = existing.canonicalize() {
            let mut out = canon;
            out.extend(rest.iter().rev());
            return Ok(out);
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                existing = parent;
            }
            _ => return Err(SecretError::Io("cannot resolve path".to_owned())),
        }
    }
}

impl EnvKekWrapper {
    pub fn from_key_bytes(key_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            kek: Zeroizing::new(key),
            source_path: None,
        }
    }

    /// Read a hex/base64 KEK from the environment variable `var_name`.
    pub fn from_env(var_name: &str) -> Result<Self, SecretError> {
        let raw = Zeroizing::new(std::env::var(var_name).map_err(|_| {
            SecretError::Backend(format!("KEK environment variable {var_name} is not set"))
        })?);
        let kek = decode_kek(&raw)?;
        Ok(Self {
            key_id: kek_key_id(&kek),
            kek,
            source_path: None,
        })
    }

    /// `env://VAR_NAME` or `file:///path/to/kek.key`. A file KEK inside `vault_dir_to_exclude`
    /// is refused before it is read.
    pub fn from_uri(uri: &str, vault_dir_to_exclude: Option<&Path>) -> Result<Self, SecretError> {
        let uri = uri.trim();
        if let Some(var) = uri.strip_prefix("env://") {
            if var.is_empty() {
                return Err(SecretError::Backend(
                    "env:// KEK URI must name a variable".to_owned(),
                ));
            }
            return Self::from_env(var);
        }
        if uri.starts_with("file://") {
            let path = Url::parse(uri)
                .ok()
                .and_then(|u| u.to_file_path().ok())
                .ok_or_else(|| {
                    SecretError::Backend(
                        "file:// KEK URI must be an absolute local path".to_owned(),
                    )
                })?;
            if let Some(dir) = vault_dir_to_exclude {
                ensure_outside(&path, dir)?;
            }
            let raw = Zeroizing::new(
                std::fs::read_to_string(&path)
                    .map_err(|e| SecretError::Io(format!("read KEK file failed: {e}")))?,
            );
            let kek = decode_kek(&raw)?;
            return Ok(Self {
                key_id: kek_key_id(&kek),
                kek,
                source_path: Some(path),
            });
        }
        Err(SecretError::Backend(
            "KMS URI must be env://VAR_NAME or file:///path/to/kek.key".to_owned(),
        ))
    }

    /// `PREMIER_KMS_KEY` if set, else `PREMIER_KMS_URI`.
    pub fn from_process_env(vault_dir_to_exclude: Option<&Path>) -> Result<Self, SecretError> {
        if std::env::var_os(PREMIER_KMS_KEY_ENV).is_some() {
            return Self::from_env(PREMIER_KMS_KEY_ENV);
        }
        let uri = std::env::var(PREMIER_KMS_URI_ENV).map_err(|_| {
            SecretError::Backend(format!(
                "neither {PREMIER_KMS_KEY_ENV} nor {PREMIER_KMS_URI_ENV} is set"
            ))
        })?;
        Self::from_uri(&uri, vault_dir_to_exclude)
    }

    /// Where the KEK was read from, for `file://` KEKs.
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Refuse a file KEK stored inside `vault_dir` (KEK/state separation).
    pub fn reject_if_in_dir(&self, vault_dir: &Path) -> Result<(), SecretError> {
        match &self.source_path {
            Some(path) => ensure_outside(path, vault_dir),
            None => Ok(()),
        }
    }
}

fn ensure_outside(kek_path: &Path, vault_dir: &Path) -> Result<(), SecretError> {
    if canonicalize_lenient(kek_path)?.starts_with(canonicalize_lenient(vault_dir)?) {
        return Err(SecretError::Crypto(
            "KEK file must not live inside the vault state directory (KEK/state separation)"
                .to_owned(),
        ));
    }
    Ok(())
}

impl KeyWrapper for EnvKekWrapper {
    fn provider_name(&self) -> &str {
        "env-kek"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_dek(&self, dek: &[u8; 32], aad_context: &str) -> Result<String, SecretError> {
        let aad = wrap_aad(&self.key_id, aad_context);
        Ok(format!(
            "env-kek-v1:{}",
            aead_seal(&self.kek, aad.as_bytes(), dek)?
        ))
    }

    fn unwrap_dek(
        &self,
        wrapped: &str,
        aad_context: &str,
    ) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let body = wrapped
            .strip_prefix("env-kek-v1:")
            .ok_or_else(|| SecretError::Crypto("DEK is not env-kek-v1 wrapped".to_owned()))?;
        let aad = wrap_aad(&self.key_id, aad_context);
        let pt = aead_open(&self.kek, aad.as_bytes(), body).ok_or_else(|| {
            SecretError::Crypto("DEK unwrap failed (wrong KEK or tampered vault)".to_owned())
        })?;
        dek_from_bytes(&pt)
    }
}

/// HashiCorp Vault Transit settings. `token` is never logged or serialized.
#[derive(Clone)]
pub struct VaultTransitConfig {
    pub address: String,
    pub mount: String,
    pub key_name: String,
    pub token: Zeroizing<String>,
    pub namespace: Option<String>,
    pub allow_insecure_loopback: bool,
    pub extra_root_certs: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for VaultTransitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTransitConfig")
            .field("address", &self.address)
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("token", &"[redacted]")
            .field("namespace", &self.namespace)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

/// Wraps DEKs with Vault Transit `encrypt`/`decrypt` (the KEK never leaves Vault).
#[derive(Debug)]
pub struct VaultTransitWrapper {
    base: Url,
    config: VaultTransitConfig,
    key_id: String,
}

#[derive(Deserialize)]
struct TransitEncryptResponse {
    data: TransitCiphertext,
}

#[derive(Deserialize)]
struct TransitCiphertext {
    ciphertext: String,
}

#[derive(Deserialize)]
struct TransitDecryptResponse {
    data: TransitPlaintext,
}

#[derive(Deserialize)]
struct TransitPlaintext {
    plaintext: String,
}

impl VaultTransitWrapper {
    pub fn new(config: VaultTransitConfig) -> Result<Self, SecretError> {
        validate_path_segments("vault transit mount", &config.mount, true)?;
        validate_path_segments("vault transit key_name", &config.key_name, false)?;
        if let Some(ns) = &config.namespace {
            validate_path_segments("vault namespace", ns, true)?;
        }
        if config.token.trim().is_empty() {
            return Err(SecretError::Backend(
                "vault transit token must not be empty".to_owned(),
            ));
        }
        let base = validate_base_url(&config.address, config.allow_insecure_loopback)?;
        let key_id = format!("vault-transit:{}/{}", config.mount, config.key_name);
        Ok(Self {
            base,
            config,
            key_id,
        })
    }

    fn call(&self, op: &str, body: Zeroizing<Vec<u8>>) -> Result<HttpResponse, SecretError> {
        let url = join_url(
            &self.base,
            &format!("/v1/{}/{op}/{}", self.config.mount, self.config.key_name),
        );
        let mut headers = vec![("X-Vault-Token", self.config.token.clone())];
        if let Some(ns) = &self.config.namespace {
            headers.push(("X-Vault-Namespace", Zeroizing::new(ns.clone())));
        }
        let resp = http_json_request(HttpRequest {
            method: Method::POST,
            url,
            headers,
            body: Some(body),
            allow_insecure_loopback: self.config.allow_insecure_loopback,
            block_private_ips: false,
            extra_root_certs: self.config.extra_root_certs.clone(),
        })?;
        if !resp.is_success() {
            return Err(SecretError::Backend(format!(
                "Vault Transit {op} failed with HTTP {}",
                resp.status
            )));
        }
        Ok(resp)
    }
}

impl KeyWrapper for VaultTransitWrapper {
    fn provider_name(&self) -> &str {
        "vault-transit"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_dek(&self, dek: &[u8; 32], aad_context: &str) -> Result<String, SecretError> {
        let plaintext_b64 = Zeroizing::new(B64.encode(dek));
        let aad_b64 = B64.encode(wrap_aad(&self.key_id, aad_context));
        // Base64 needs no JSON escaping; building the body by hand keeps it in zeroized memory.
        let body = Zeroizing::new(
            format!(
                r#"{{"plaintext":"{}","associated_data":"{aad_b64}"}}"#,
                plaintext_b64.as_str()
            )
            .into_bytes(),
        );
        let resp: TransitEncryptResponse = self.call("encrypt", body)?.json("Vault Transit")?;
        if !resp.data.ciphertext.starts_with("vault:v") {
            return Err(SecretError::Crypto(
                "Vault Transit returned a malformed ciphertext".to_owned(),
            ));
        }
        Ok(format!("vault-transit-v1:{}", resp.data.ciphertext))
    }

    fn unwrap_dek(
        &self,
        wrapped: &str,
        aad_context: &str,
    ) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let ciphertext = wrapped
            .strip_prefix("vault-transit-v1:")
            .ok_or_else(|| SecretError::Crypto("DEK is not vault-transit-v1 wrapped".to_owned()))?;
        let body = serde_json::to_vec(&serde_json::json!({
            "ciphertext": ciphertext,
            "associated_data": B64.encode(wrap_aad(&self.key_id, aad_context)),
        }))
        .map_err(|e| SecretError::Backend(format!("encode transit request failed: {e}")))?;
        let resp: TransitDecryptResponse = self
            .call("decrypt", Zeroizing::new(body))?
            .json("Vault Transit")?;
        let plaintext_b64 = Zeroizing::new(resp.data.plaintext);
        let dek = Zeroizing::new(B64.decode(plaintext_b64.as_str()).map_err(|_| {
            SecretError::Crypto("Vault Transit returned a malformed plaintext".to_owned())
        })?);
        dek_from_bytes(&dek)
    }
}

/// Wraps DEKs to `age` X25519 recipients; AAD is bound by a trailing SHA-256 of the context.
pub struct AgeKeyWrapper {
    identity: age::x25519::Identity,
    recipients: Vec<age::x25519::Recipient>,
    key_id: String,
}

impl AgeKeyWrapper {
    pub fn new(
        identity: age::x25519::Identity,
        extra_recipients: Vec<age::x25519::Recipient>,
    ) -> Self {
        let mut recipients = vec![identity.to_public()];
        recipients.extend(extra_recipients);
        let keys: Vec<String> = recipients.iter().map(ToString::to_string).collect();
        let key_id = format!("age-{}", &recipients_fingerprint(&keys)[..16]);
        Self {
            identity,
            recipients,
            key_id,
        }
    }

    fn aad_digest(&self, aad_context: &str) -> [u8; 32] {
        Sha256::digest(wrap_aad(&self.key_id, aad_context).as_bytes()).into()
    }
}

impl KeyWrapper for AgeKeyWrapper {
    fn provider_name(&self) -> &str {
        "age"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_dek(&self, dek: &[u8; 32], aad_context: &str) -> Result<String, SecretError> {
        let mut payload = Zeroizing::new(Vec::with_capacity(64));
        payload.extend_from_slice(dek);
        payload.extend_from_slice(&self.aad_digest(aad_context));
        Ok(format!(
            "age-v1:{}",
            B64.encode(age_wrap(&self.recipients, &payload)?)
        ))
    }

    fn unwrap_dek(
        &self,
        wrapped: &str,
        aad_context: &str,
    ) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let body = wrapped
            .strip_prefix("age-v1:")
            .ok_or_else(|| SecretError::Crypto("DEK is not age-v1 wrapped".to_owned()))?;
        let raw = B64
            .decode(body)
            .map_err(|_| SecretError::Crypto("age-wrapped DEK is not base64".to_owned()))?;
        let payload = age_unwrap(&self.identity, &raw)?;
        if payload.len() != 64
            || payload[32..]
                .ct_eq(&self.aad_digest(aad_context))
                .unwrap_u8()
                != 1
        {
            return Err(SecretError::Crypto(
                "age-wrapped DEK context mismatch (possible transplant)".to_owned(),
            ));
        }
        dek_from_bytes(&payload[..32])
    }
}

// ---------------------------------------------------------------------------------------------
// Envelope vault
// ---------------------------------------------------------------------------------------------

/// Envelope vault (v2): one KMS-wrapped DEK, AES-256-GCM entries with repo/DEK-version AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeVaultFile {
    pub version: u32,
    pub repo_id: String,
    pub provider: String,
    pub key_id: String,
    pub dek_version: u32,
    pub wrapped_dek: String,
    #[serde(default)]
    pub kt_bound: bool,
    #[serde(default)]
    pub entries: BTreeMap<String, String>,
}

/// Non-secret KMS / Key Transparency health summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsStatus {
    pub mode: String,
    pub provider: String,
    pub key_id: String,
    pub envelope_version: u32,
    pub dek_version: u32,
    pub kek_separated: bool,
    pub vault_path: String,
    pub entry_count: usize,
    pub kt_enabled: bool,
    pub kt_entries: usize,
    pub kt_valid: bool,
    pub kt_error: Option<String>,
}

/// [`SecretBackend`] over an [`EnvelopeVaultFile`] whose DEK is wrapped by a [`KeyWrapper`].
pub struct EnvelopeVaultBackend {
    vault_path: PathBuf,
    repo_id: String,
    wrapper: Arc<dyn KeyWrapper>,
    kek_separated: bool,
    kt_log_path: Option<PathBuf>,
}

type OpenVault = (EnvelopeVaultFile, Zeroizing<[u8; 32]>);

impl EnvelopeVaultBackend {
    pub fn new(
        vault_path: impl Into<PathBuf>,
        repo_id: impl Into<String>,
        wrapper: Arc<dyn KeyWrapper>,
    ) -> Self {
        Self {
            vault_path: vault_path.into(),
            repo_id: repo_id.into(),
            wrapper,
            kek_separated: false,
            kt_log_path: None,
        }
    }

    /// Record that the KEK is held outside the vault's state directory (reported by `status`).
    pub fn with_kek_separated(mut self, separated: bool) -> Self {
        self.kek_separated = separated;
        self
    }

    /// Bind the vault's KMS key into a Key Transparency log and fail closed on drift.
    pub fn with_key_transparency(mut self, kt_log_path: impl Into<PathBuf>) -> Self {
        self.kt_log_path = Some(kt_log_path.into());
        self
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    fn wrap_context(
        &self,
        dek_version: u32,
        provider: &str,
        key_id: &str,
        kt_bound: bool,
    ) -> String {
        format!(
            "{}:dek-v{dek_version}:provider={provider}:key={key_id}:kt={kt_bound}",
            self.repo_id
        )
    }

    fn entry_aad(&self, dek_version: u32, map_key: &str) -> String {
        format!(
            "premier-envelope-v2:{}:{dek_version}:{map_key}",
            self.repo_id
        )
    }

    fn kt_binding(provider: &str, key_id: &str) -> Vec<String> {
        vec![format!("{provider}:{key_id}")]
    }

    fn kt(&self) -> Option<KeyTransparencyLog> {
        self.kt_log_path.as_ref().map(KeyTransparencyLog::open)
    }

    fn read_file(&self) -> Result<Option<EnvelopeVaultFile>, SecretError> {
        if !self.vault_path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&self.vault_path)
            .map_err(|e| SecretError::Backend(format!("read envelope vault failed: {e}")))?;
        let vault: EnvelopeVaultFile = toml::from_str(&text)
            .map_err(|e| SecretError::Backend(format!("parse envelope vault failed: {e}")))?;
        if vault.version != ENVELOPE_VAULT_VERSION {
            return Err(SecretError::Backend(format!(
                "unsupported envelope vault version {}",
                vault.version
            )));
        }
        if vault.repo_id != self.repo_id {
            return Err(SecretError::Crypto(
                "envelope vault belongs to a different repo".to_owned(),
            ));
        }
        Ok(Some(vault))
    }

    fn open_unlocked(&self) -> Result<Option<OpenVault>, SecretError> {
        let Some(mut vault) = self.read_file()? else {
            return Ok(None);
        };
        if vault.key_id != self.wrapper.key_id() {
            return Err(SecretError::Crypto(format!(
                "envelope vault DEK is wrapped under '{}', not the configured key '{}'",
                vault.key_id,
                self.wrapper.key_id()
            )));
        }
        let needs_kt_bootstrap = if let Some(kt) = self.kt() {
            let binding = Self::kt_binding(&vault.provider, &vault.key_id);
            if kt
                .verify_vault_recipients(&self.repo_id, &binding)?
                .latest_hash
                .is_none()
            {
                if vault.kt_bound {
                    return Err(SecretError::Crypto(
                        "key transparency binding missing for bound envelope vault; possible KT log deletion or replay"
                            .to_owned(),
                    ));
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        let ctx = self.wrap_context(
            vault.dek_version,
            &vault.provider,
            &vault.key_id,
            vault.kt_bound,
        );
        let dek = self.wrapper.unwrap_dek(&vault.wrapped_dek, &ctx)?;
        if needs_kt_bootstrap && let Some(kt) = self.kt() {
            // Genuine pre-KT vault: re-wrap the DEK with `kt_bound = true` in AAD, then persist
            // the KT bootstrap entry so later log deletion fails closed.
            let binding = Self::kt_binding(&vault.provider, &vault.key_id);
            let new_ctx =
                self.wrap_context(vault.dek_version, &vault.provider, &vault.key_id, true);
            vault.wrapped_dek = self.wrapper.wrap_dek(&dek, &new_ctx)?;
            vault.kt_bound = true;
            self.kt_append(&kt, &binding, "bootstrap")?;
            self.save_unlocked(&vault, None)?;
        }
        Ok(Some((vault, dek)))
    }

    fn create_unlocked(&self) -> Result<OpenVault, SecretError> {
        let provider = self.wrapper.provider_name().to_owned();
        let key_id = self.wrapper.key_id().to_owned();
        if let Some(kt) = self.kt() {
            // A recreated vault must still match the repo's last binding.
            kt.verify_vault_recipients(&self.repo_id, &Self::kt_binding(&provider, &key_id))?;
        }
        let kt_bound = self.kt_log_path.is_some();
        let dek = random_dek();
        let wrapped_dek = self
            .wrapper
            .wrap_dek(&dek, &self.wrap_context(1, &provider, &key_id, kt_bound))?;
        let vault = EnvelopeVaultFile {
            version: ENVELOPE_VAULT_VERSION,
            repo_id: self.repo_id.clone(),
            provider,
            key_id,
            dek_version: 1,
            wrapped_dek,
            kt_bound,
            entries: BTreeMap::new(),
        };
        Ok((vault, dek))
    }

    fn kt_append(
        &self,
        kt: &KeyTransparencyLog,
        binding: &[String],
        event: &str,
    ) -> Result<(), SecretError> {
        kt.append_binding(
            &self.repo_id,
            &self.vault_path.display().to_string(),
            binding,
            "premier-secrets",
            event,
        )
        .map(|_| ())
    }

    /// Persist; `kt_event` appends a fresh binding of the vault's (possibly new) key.
    fn save_unlocked(
        &self,
        vault: &EnvelopeVaultFile,
        kt_event: Option<&str>,
    ) -> Result<(), SecretError> {
        if let Some(parent) = self
            .vault_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            create_state_dir(parent)
                .map_err(|e| SecretError::Backend(format!("create vault dir failed: {e}")))?;
        }
        let mut to_write = vault.clone();
        if self.kt_log_path.is_some() {
            to_write.kt_bound = true;
        }
        let text = toml::to_string_pretty(&to_write)
            .map_err(|e| SecretError::Backend(format!("serialize envelope vault failed: {e}")))?;
        write_private(&self.vault_path, text.as_bytes())
            .map_err(|e| SecretError::Backend(format!("write envelope vault failed: {e}")))?;
        if let (Some(kt), Some(event)) = (self.kt(), kt_event)
            && let Err(e) = self.kt_append(
                &kt,
                &Self::kt_binding(&to_write.provider, &to_write.key_id),
                event,
            )
        {
            if event == "genesis" {
                let _ = std::fs::remove_file(&self.vault_path);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Open (or create) the vault, apply `f`, save (caller holds `acquire_path_lock`).
    fn mutate_unlocked<R>(
        &self,
        f: impl FnOnce(&mut EnvelopeVaultFile, &[u8; 32]) -> Result<R, SecretError>,
    ) -> Result<R, SecretError> {
        let (mut vault, dek, created) = match self.open_unlocked()? {
            Some((v, d)) => (v, d, false),
            None => {
                let (v, d) = self.create_unlocked()?;
                (v, d, true)
            }
        };
        let out = f(&mut vault, &dek)?;
        self.save_unlocked(&vault, created.then_some("genesis"))?;
        Ok(out)
    }

    fn seal_entry(
        &self,
        dek: &[u8; 32],
        dek_version: u32,
        map_key: &str,
        value: &str,
    ) -> Result<String, SecretError> {
        aead_seal(
            dek,
            self.entry_aad(dek_version, map_key).as_bytes(),
            value.as_bytes(),
        )
    }

    fn open_entry(
        &self,
        dek: &[u8; 32],
        dek_version: u32,
        map_key: &str,
        encoded: &str,
    ) -> Result<Zeroizing<String>, SecretError> {
        let mut pt = aead_open(
            dek,
            self.entry_aad(dek_version, map_key).as_bytes(),
            encoded,
        )
        .ok_or_else(|| {
            SecretError::Crypto(format!(
                "AEAD authentication failed for key '{map_key}' (possible tampering or key-swap)"
            ))
        })?;
        String::from_utf8(std::mem::take(&mut *pt))
            .map(Zeroizing::new)
            .map_err(|_| SecretError::Crypto("decrypted secret is not UTF-8".to_owned()))
    }

    /// Re-encrypt every entry under a fresh DEK; returns the new DEK version.
    pub fn rotate_dek(&self) -> Result<u32, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut vault, old_dek) = self.open_unlocked()?.ok_or_else(|| {
            SecretError::Backend("envelope vault does not exist yet; nothing to rotate".to_owned())
        })?;
        let new_version = vault
            .dek_version
            .checked_add(1)
            .ok_or_else(|| SecretError::Backend("DEK version overflow".to_owned()))?;
        let new_dek = random_dek();
        let mut entries = BTreeMap::new();
        for (key, enc) in &vault.entries {
            let value = self.open_entry(&old_dek, vault.dek_version, key, enc)?;
            entries.insert(
                key.clone(),
                self.seal_entry(&new_dek, new_version, key, &value)?,
            );
        }
        let kt_bound = vault.kt_bound || self.kt_log_path.is_some();
        vault.kt_bound = kt_bound;
        vault.wrapped_dek = self.wrapper.wrap_dek(
            &new_dek,
            &self.wrap_context(new_version, &vault.provider, &vault.key_id, kt_bound),
        )?;
        vault.dek_version = new_version;
        vault.entries = entries;
        self.save_unlocked(&vault, None)?;
        Ok(new_version)
    }

    /// Re-wrap the current DEK under `new_wrapper` (KEK rotation / provider migration). Open
    /// the vault with a backend built on `new_wrapper` afterwards.
    pub fn rewrap_dek(&self, new_wrapper: &dyn KeyWrapper) -> Result<(), SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut vault, dek) = self.open_unlocked()?.ok_or_else(|| {
            SecretError::Backend("envelope vault does not exist yet; nothing to rewrap".to_owned())
        })?;
        let kt_bound = vault.kt_bound || self.kt_log_path.is_some();
        vault.wrapped_dek = new_wrapper.wrap_dek(
            &dek,
            &self.wrap_context(
                vault.dek_version,
                new_wrapper.provider_name(),
                new_wrapper.key_id(),
                kt_bound,
            ),
        )?;
        new_wrapper.provider_name().clone_into(&mut vault.provider);
        new_wrapper.key_id().clone_into(&mut vault.key_id);
        vault.kt_bound = kt_bound;
        self.save_unlocked(&vault, Some("rewrap"))
    }

    pub fn status(&self) -> Result<KmsStatus, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let vault = self.read_file()?;
        let (kt_enabled, kt_entries, kt_valid, kt_error) = match self.kt() {
            None => (false, 0, false, None),
            Some(kt) => {
                let check = match &vault {
                    Some(v) => {
                        let report = kt.verify_vault_recipients(
                            &self.repo_id,
                            &Self::kt_binding(&v.provider, &v.key_id),
                        );
                        match report {
                            Ok(r) if v.kt_bound && r.latest_hash.is_none() => {
                                Err(SecretError::Crypto(
                                    "key transparency binding missing for bound envelope vault"
                                        .to_owned(),
                                ))
                            }
                            other => other,
                        }
                    }
                    None => kt.verify_chain(),
                };
                match check {
                    Ok(r) => (true, r.entry_count, true, None),
                    Err(e) => (
                        true,
                        kt.entries().map_or(0, |e| e.len()),
                        false,
                        Some(e.to_string()),
                    ),
                }
            }
        };
        Ok(KmsStatus {
            mode: "envelope".to_owned(),
            provider: vault.as_ref().map_or_else(
                || self.wrapper.provider_name().to_owned(),
                |v| v.provider.clone(),
            ),
            key_id: vault
                .as_ref()
                .map_or_else(|| self.wrapper.key_id().to_owned(), |v| v.key_id.clone()),
            envelope_version: ENVELOPE_VAULT_VERSION,
            dek_version: vault.as_ref().map_or(0, |v| v.dek_version),
            kek_separated: self.kek_separated,
            vault_path: self.vault_path.display().to_string(),
            entry_count: vault.as_ref().map_or(0, |v| v.entries.len()),
            kt_enabled,
            kt_entries,
            kt_valid,
            kt_error,
        })
    }

    /// Decrypt every entry (storage key -> value).
    pub fn list_entries(&self) -> Result<BTreeMap<String, Zeroizing<String>>, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((vault, dek)) = self.open_unlocked()? else {
            return Ok(BTreeMap::new());
        };
        vault
            .entries
            .iter()
            .map(|(k, enc)| Ok((k.clone(), self.open_entry(&dek, vault.dek_version, k, enc)?)))
            .collect()
    }

    fn import_entries(
        &self,
        entries: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<usize, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.mutate_unlocked(|vault, dek| {
            for (key, value) in entries {
                let enc = self.seal_entry(dek, vault.dek_version, key, value)?;
                vault.entries.insert(key.clone(), enc);
            }
            Ok(entries.len())
        })
    }
}

impl SecretBackend for EnvelopeVaultBackend {
    fn name(&self) -> &str {
        "envelope-kms"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((vault, dek)) = self.open_unlocked()? else {
            return Ok(None);
        };
        let map_key = coord.storage_key();
        vault
            .entries
            .get(&map_key)
            .map(|enc| self.open_entry(&dek, vault.dek_version, &map_key, enc))
            .transpose()
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let map_key = coord.storage_key();
        self.mutate_unlocked(|vault, dek| {
            let enc = self.seal_entry(dek, vault.dek_version, &map_key, value)?;
            vault.entries.insert(map_key.clone(), enc);
            Ok(())
        })
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((mut vault, _)) = self.open_unlocked()? else {
            return Ok(());
        };
        if vault.entries.remove(&coord.storage_key()).is_some() {
            self.save_unlocked(&vault, None)?;
        }
        Ok(())
    }
}

/// Copy every entry of a Sovereign `age` vault into an Envelope KMS vault; returns the count.
pub fn migrate_from_age_vault(
    age: &AgeSovereignBackend,
    envelope: &EnvelopeVaultBackend,
) -> Result<usize, SecretError> {
    envelope.import_entries(&age.list_entries()?)
}
