//! GitHub companion control plane: connect a repository to one GitHub repository, publish a
//! branch to it as a Squash-Declassified pull request, and keep a zone of the default branch in
//! sync with GitHub both ways.
//!
//! What may leave and come back is decided by `premier_git_bridge::companion`, on a throwaway
//! local *staging* bare repository. This module owns everything that talks to GitHub:
//!
//! - the token lives only in the encrypted workspace vault ([`crate::store::store_github_token`]),
//!   reaches git only through the environment (never argv, a `-c` value or a URL) and is scrubbed
//!   from every error;
//! - GitHub hosts are validated (github.com, or an enterprise host the server was started with),
//!   resolved once, refused when any address is not public, and git and the REST client are
//!   pinned to the vetted addresses; redirects are refused;
//! - every route is an owner's, from a browser session, and every call is audited.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex as StdMutex, PoisonError};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;
use premier_core::{AuditDecision, AuditEvent};
use premier_git_bridge::{
    CanonicalGitRepo, GitBridgeError, GithubPrSquashPlan, ProjectedFileDiff,
    ScrubbedMetadataSummary, ZoneSyncInResult, ZoneSyncMappingState, ZoneSyncOutResult,
    apply_zone_sync_in, materialize_github_pr_in_staging, plan_github_pr_squash,
    project_zone_sync_out,
};
use premier_overlay::OverlayGuard;
use premier_policy::{CompiledPolicy, sha256_hex};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::auth::AuthUser;
use crate::{ApiError, ServerState, canon, store};

/// The companion's state file in the repository's state directory. Never holds the token.
const STATE_FILE: &str = "github-companion.json";
/// Vault repo id of the token: fixed, so editing `.env.schema` never orphans it.
const VAULT_REPO_ID: &str = store::GITHUB_VAULT_REPO_ID;
const MAX_RECEIPTS: usize = 100;
/// Most of a GitHub API response read.
const API_RESPONSE_CAP: usize = 4 * 1024 * 1024;
const NET_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_TIMEOUT: Duration = Duration::from_secs(300);
const CLIENT_UA: &str = "premier-vcs/0.1";
const GITHUB_HOST: &str = "github.com";
const GITHUB_API_HOST: &str = "api.github.com";

// ---------------------------------------------------------------------------------------------
// Persisted state and wire types (mirrored by `apps/web/src/api.ts`)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    #[default]
    Bidirectional,
    Outbound,
    Inbound,
}

/// The connected GitHub repository. Nothing in it is secret: it is shown as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubCompanionConfigStored {
    pub owner: String,
    pub repo: String,
    pub full_name: String,
    pub host: String,
    pub api_host: String,
    pub default_branch: String,
    pub zone: Option<String>,
    pub sync_direction: SyncDirection,
    pub token_configured: bool,
    pub token_updated_at: Option<String>,
    pub connected_at: String,
    pub connected_by: String,
}

pub type GithubCompanionConfigPublic = GithubCompanionConfigStored;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GithubSyncStateSummary {
    pub last_canonical_oid: Option<String>,
    pub last_upstream_oid: Option<String>,
    pub mapped_commits: usize,
    pub last_policy_fingerprint: Option<String>,
    pub last_sync_out_at: Option<String>,
    pub last_sync_in_at: Option<String>,
    pub last_sync_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubPrReceipt {
    pub id: String,
    pub source_branch: String,
    pub base_branch: String,
    pub pr_branch: String,
    pub pr_number: u64,
    pub pr_url: String,
    pub pr_title: String,
    pub public_commit_oid: String,
    pub published_paths: Vec<String>,
    pub scrubbed_paths_count: usize,
    pub attestation_trailer: String,
    pub change_id: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GithubCompanionFile {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub config: Option<GithubCompanionConfigStored>,
    #[serde(default)]
    pub mapping: ZoneSyncMappingState,
    #[serde(default)]
    pub pair_mappings: BTreeMap<String, ZoneSyncMappingState>,
    #[serde(default)]
    pub last_sync_out_at: Option<String>,
    #[serde(default)]
    pub last_sync_in_at: Option<String>,
    #[serde(default)]
    pub last_sync_summary: Option<String>,
    /// Newest first, at most [`MAX_RECEIPTS`].
    #[serde(default)]
    pub receipts: Vec<GithubPrReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubCompanionStatus {
    pub connected: bool,
    pub config: Option<GithubCompanionConfigPublic>,
    pub sync_state: Option<GithubSyncStateSummary>,
    pub receipts: Vec<GithubPrReceipt>,
    pub available_zones: Vec<String>,
    pub enterprise_hosts_allowed: Vec<String>,
}

/// `PUT /v1/github/config`. No `Debug`: it carries the token.
#[derive(Clone, Deserialize)]
pub struct GithubConfigPayload {
    pub repo: String,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub sync_direction: Option<SyncDirection>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub api_host: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

/// Preview (`draft` and `change_id` ignored) and publish of a pull request.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubPrRequest {
    pub source_branch: String,
    #[serde(default)]
    pub base_branch: Option<String>,
    #[serde(default)]
    pub pr_branch: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubPrPreviewResponse {
    pub repo: String,
    pub source_branch: String,
    pub base_branch: String,
    pub pr_branch: String,
    pub zone: Option<String>,
    pub gate_passed: bool,
    pub reason: Option<String>,
    pub published_paths: Vec<String>,
    pub scrubbed_paths: Vec<String>,
    pub held_back_reasons: std::collections::BTreeMap<String, String>,
    pub conflicts: Vec<String>,
    pub blocked: Vec<String>,
    pub diffs: Vec<ProjectedFileDiff>,
    pub diff_truncated: bool,
    pub scrubbed_metadata: ScrubbedMetadataSummary,
    pub clean_commit_message: String,
    pub pr_title: String,
    pub pr_body: String,
    pub attestation_trailer: String,
}

impl GithubPrPreviewResponse {
    fn new(repo: String, plan: GithubPrSquashPlan) -> Self {
        Self {
            repo,
            source_branch: plan.source_branch,
            base_branch: plan.base_branch,
            pr_branch: plan.pr_branch,
            zone: plan.zone,
            gate_passed: plan.gate_passed,
            reason: plan.reason,
            published_paths: plan.published_paths,
            scrubbed_paths: plan.scrubbed_paths,
            held_back_reasons: plan.held_back_reasons,
            conflicts: plan.conflicts,
            blocked: plan.blocked,
            diffs: plan.diffs,
            diff_truncated: plan.diff_truncated,
            scrubbed_metadata: plan.scrubbed_metadata,
            clean_commit_message: plan.clean_commit_message,
            pr_title: plan.pr_title,
            pr_body: plan.pr_body,
            attestation_trailer: plan.attestation_trailer,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishGithubPrResult {
    pub receipt: GithubPrReceipt,
    pub published_paths: Vec<String>,
    pub scrubbed_paths: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncOutRequest {
    #[serde(default)]
    pub source_branch: Option<String>,
    #[serde(default)]
    pub target_branch: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default = "default_true")]
    pub squash: bool,
    #[serde(default)]
    pub summary_message: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for SyncOutRequest {
    fn default() -> Self {
        Self {
            source_branch: None,
            target_branch: None,
            zone: None,
            squash: true,
            summary_message: None,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SyncInRequest {
    #[serde(default)]
    pub upstream_ref: Option<String>,
    #[serde(default)]
    pub pr_number: Option<u64>,
    #[serde(default)]
    pub target_branch: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

/// Tests only: a local bare repository stands in for GitHub's git endpoint and a plain-HTTP
/// server for its REST API. Set on [`ServerState`] by test code, never from a request.
#[derive(Debug, Clone)]
pub struct GithubTestOverride {
    pub bare_remote_path: PathBuf,
    pub mock_api_base_url: String,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A refused or failed companion call: an HTTP status and the JSON error body.
#[derive(Debug)]
pub struct GithubError {
    pub status: StatusCode,
    pub body: ApiError,
}

impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.body.error)
    }
}

impl std::error::Error for GithubError {}

impl From<GithubError> for (StatusCode, Json<ApiError>) {
    fn from(e: GithubError) -> Self {
        (e.status, Json(e.body))
    }
}

fn gh_err(status: StatusCode, msg: impl Into<String>) -> GithubError {
    GithubError {
        status,
        body: ApiError {
            error: msg.into(),
            ..ApiError::default()
        },
    }
}

fn bad(msg: impl Into<String>) -> GithubError {
    gh_err(StatusCode::BAD_REQUEST, msg)
}

fn internal(msg: impl Into<String>) -> GithubError {
    gh_err(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// A bridge refusal. `rejected` is the status of a plain [`GitBridgeError::Rejected`].
fn bridge_err(e: GitBridgeError, rejected: StatusCode) -> GithubError {
    match e {
        GitBridgeError::PublishBlocked(blocked) => GithubError {
            status: StatusCode::CONFLICT,
            body: ApiError {
                error: format!(
                    "refused: {} would carry the content of restricted files to GitHub; nothing left this server",
                    premier_git_bridge::plural(blocked.len(), "path")
                ),
                blocked,
                ..ApiError::default()
            },
        },
        GitBridgeError::PublishConflict(conflicts) => GithubError {
            status: StatusCode::CONFLICT,
            body: ApiError {
                error: format!(
                    "refused: {} changed on GitHub too and cannot be merged",
                    premier_git_bridge::plural(conflicts.len(), "path")
                ),
                conflicts,
                ..ApiError::default()
            },
        },
        e @ GitBridgeError::RefMoved => gh_err(StatusCode::CONFLICT, e.to_string()),
        GitBridgeError::Rejected(msg) => gh_err(rejected, msg),
        e => internal(e.to_string()),
    }
}

// ---------------------------------------------------------------------------------------------
// Validation and SSRF pinning
// ---------------------------------------------------------------------------------------------

/// `owner/repo`, nothing else: no URL, userinfo, whitespace, `.git` suffix or extra segment.
pub fn validate_owner_repo(raw: &str) -> Result<(String, String), String> {
    let refused = || format!("'{raw}' is not a GitHub repository (expected owner/repo)");
    let mut parts = raw.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(refused());
    };
    let ok = |part: &str| {
        (1..=100).contains(&part.len())
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            && !part.starts_with('.')
            && !part.ends_with('.')
    };
    if !ok(owner) || !ok(repo) || repo.to_ascii_lowercase().ends_with(".git") {
        return Err(refused());
    }
    Ok((owner.to_owned(), repo.to_owned()))
}

/// A lowercased DNS host name: letters, digits, `-` and `.`, a dot somewhere, a top-level label
/// starting with a letter (so no IP literal in any notation), and not a loopback or mDNS name.
fn normalize_host(raw: &str, what: &str) -> Result<String, String> {
    let host = raw.trim().to_ascii_lowercase();
    let refused = || {
        Err(format!(
            "{what} '{}' is not an allowed host name",
            raw.trim()
        ))
    };
    let labels_ok = host.split('.').all(|l| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    let tld_ok = host
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.starts_with(|c: char| c.is_ascii_alphabetic()));
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || !labels_ok
        || !tld_ok
        || host.parse::<IpAddr>().is_ok()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
    {
        return refused();
    }
    Ok(host)
}

/// The web and API hosts to use: github.com with api.github.com, or an enterprise host the
/// server allows (`allowed_enterprise`) with itself, `api.<host>` or another allowed host.
pub fn validate_github_hosts(
    host: Option<&str>,
    api_host: Option<&str>,
    allowed_enterprise: &[String],
) -> Result<(String, String), String> {
    let host = normalize_host(host.unwrap_or(GITHUB_HOST), "host")?;
    let default_api = if host == GITHUB_HOST {
        GITHUB_API_HOST.to_owned()
    } else {
        host.clone()
    };
    let api_host = match api_host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(api) => normalize_host(api, "api_host")?,
        None => default_api,
    };
    let allowed = |h: &str| {
        allowed_enterprise
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case(h))
    };
    if host == GITHUB_HOST {
        if api_host != GITHUB_API_HOST {
            return Err("github.com is only reached through api.github.com".to_owned());
        }
    } else {
        if !allowed(&host) {
            return Err(format!(
                "host '{host}' is not an allowed GitHub Enterprise host on this server"
            ));
        }
        if api_host != host && api_host != format!("api.{host}") && !allowed(&api_host) {
            return Err(format!(
                "api_host '{api_host}' is neither '{host}', 'api.{host}' nor an allowed host"
            ));
        }
    }
    Ok((host, api_host))
}

/// Addresses the companion never connects to: anything but the public internet.
pub(crate) fn blocked_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            let this_net = o[0] == 0;
            let ietf_prot = o[0] == 192 && o[1] == 0 && o[2] == 0;
            let bench = o[0] == 198 && (o[1] & 0xfe) == 18;
            let reserved = o[0] >= 240;
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_private()
                || v4.is_documentation()
                || cgnat
                || this_net
                || ietf_prot
                || bench
                || reserved
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let nat64 = s[0] == 0x0064 && s[1] == 0xff9b;
            let six_to_four = s[0] == 0x2002;
            let discard = s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0;
            let site_local = (s[0] & 0xffc0) == 0xfec0;
            let v4_compat = s[..6] == [0; 6];
            let doc = s[0] == 0x2001 && s[1] == 0x0db8;
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || nat64
                || six_to_four
                || discard
                || site_local
                || v4_compat
                || doc
        }
    }
}

/// Resolve `host:443` once and refuse it unless every address is public. Returns the addresses
/// and the `http.curloptResolve` entry that pins git to them (no DNS rebinding in between).
pub async fn resolve_and_vet_host(host: &str) -> Result<(Vec<SocketAddr>, String), String> {
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(NET_TIMEOUT, tokio::net::lookup_host((host, 443)))
            .await
            .map_err(|_| format!("resolving '{host}' timed out"))?
            .map_err(|e| format!("cannot resolve '{host}': {e}"))?
            .collect();
    if addrs.is_empty() || addrs.iter().any(|a| blocked_ip(a.ip())) {
        return Err(format!(
            "'{host}' does not resolve to public addresses only"
        ));
    }
    let list: Vec<String> = addrs
        .iter()
        .map(|a| match a.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        })
        .collect();
    let pin = format!("{host}:443:{}", list.join(","));
    Ok((addrs, pin))
}

/// A branch name GitHub and git both take, safe as a single argument.
fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'))
        && !name.starts_with(['-', '/', '.'])
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("/.")
        && !name.ends_with(".lock")
}

fn require_branch(name: &str, what: &str) -> Result<(), GithubError> {
    if valid_branch(name) {
        Ok(())
    } else {
        Err(bad(format!("{what} '{name}' is not a valid branch name")))
    }
}

/// A canonical branch named by the caller: looked up, never parsed as an option.
fn require_canonical_name(name: &str, what: &str) -> Result<(), GithubError> {
    if name.is_empty()
        || name.starts_with('-')
        || name.contains(|c: char| c.is_control() || c.is_whitespace())
    {
        return Err(bad(format!("{what} '{name}' is not a valid branch name")));
    }
    Ok(())
}

/// Printable ASCII without spaces: it becomes an HTTP header value.
fn validate_token(token: &str) -> Result<(), GithubError> {
    if token.is_empty() || token.len() > 1024 || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(bad("token must be a non-empty GitHub token without spaces"));
    }
    Ok(())
}

fn bare_zone(zone: &str) -> &str {
    let zone = zone.trim();
    zone.strip_prefix("zone:").unwrap_or(zone)
}

// ---------------------------------------------------------------------------------------------
// GitHub REST client (pinned HTTPS; plain HTTP only to a test mock)
// ---------------------------------------------------------------------------------------------

fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for secret in secrets.iter().filter(|s| s.len() >= 4) {
        out = out.replace(secret, "[redacted]");
    }
    out
}

/// What the pull request should be.
pub struct PullRequestSpec<'a> {
    pub head: &'a str,
    pub base: &'a str,
    pub title: &'a str,
    pub body: &'a str,
    pub draft: bool,
}

fn pulls_path(cfg: &GithubCompanionConfigStored) -> String {
    let prefix = if cfg.api_host == GITHUB_API_HOST || cfg.api_host.starts_with("api.") {
        ""
    } else {
        "/api/v3"
    };
    format!("{prefix}/repos/{}/{}/pulls", cfg.owner, cfg.repo)
}

async fn send_over<S>(
    io: S,
    req: hyper::Request<Full<Bytes>>,
) -> Result<(StatusCode, Bytes), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("GitHub API handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = resp.status();
    let body = Limited::new(resp.into_body(), API_RESPONSE_CAP)
        .collect()
        .await
        .map_err(|e| format!("GitHub API response unreadable: {e}"))?
        .to_bytes();
    Ok((status, body))
}

fn pr_request(
    host_header: &str,
    path: &str,
    token: &str,
    payload: Vec<u8>,
) -> Result<hyper::Request<Full<Bytes>>, String> {
    let mut auth = hyper::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "the stored token is not a valid header value".to_owned())?;
    auth.set_sensitive(true);
    hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(path)
        .header(HOST, host_header)
        .header(AUTHORIZATION, auth)
        .header(ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(USER_AGENT, CLIENT_UA)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, payload.len())
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| format!("could not build the GitHub request: {e}"))
}

fn parse_pr_response(
    status: StatusCode,
    body: &[u8],
    token: &str,
) -> Result<(u64, String), String> {
    if status.is_redirection() {
        return Err(format!(
            "GitHub API answered with a redirect ({}); refused",
            status.as_u16()
        ));
    }
    if !status.is_success() {
        let json: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let mut msg = json["message"].as_str().unwrap_or_default().to_owned();
        if let Some(detail) = json["errors"][0]["message"].as_str() {
            msg = format!("{msg}: {detail}");
        }
        let msg: String = scrub(&msg, &[token]).chars().take(300).collect();
        return Err(format!(
            "GitHub refused the pull request ({}): {msg}",
            status.as_u16()
        ));
    }
    #[derive(Deserialize)]
    struct Created {
        number: u64,
        html_url: String,
    }
    let created: Created = serde_json::from_slice(body)
        .map_err(|_| "GitHub answered with an unexpected body".to_owned())?;
    if !created.html_url.starts_with("https://") {
        return Err("GitHub answered with a pull request URL that is not https".to_owned());
    }
    Ok((created.number, created.html_url))
}

/// Open the pull request through GitHub's REST API; returns its number and URL.
pub async fn create_github_pull_request(
    cfg: &GithubCompanionConfigStored,
    token: &str,
    test_override: Option<&GithubTestOverride>,
    pr: &PullRequestSpec<'_>,
) -> Result<(u64, String), String> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "title": pr.title,
        "body": pr.body,
        "head": pr.head,
        "base": pr.base,
        "draft": pr.draft,
    }))
    .map_err(|e| e.to_string())?;
    let path = pulls_path(cfg);
    let exchange = async {
        match test_override {
            Some(ov) => {
                let url = url::Url::parse(&ov.mock_api_base_url).map_err(|e| e.to_string())?;
                let host = url.host_str().ok_or("mock API URL has no host")?.to_owned();
                let port = url
                    .port_or_known_default()
                    .ok_or("mock API URL has no port")?;
                let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(|e| format!("cannot reach the GitHub API: {e}"))?;
                send_over(
                    tcp,
                    pr_request(&format!("{host}:{port}"), &path, token, payload)?,
                )
                .await
            }
            None => {
                let (addrs, _) = resolve_and_vet_host(&cfg.api_host).await?;
                let tcp = tokio::net::TcpStream::connect(&addrs[..])
                    .await
                    .map_err(|e| format!("cannot reach the GitHub API: {e}"))?;
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("TLS setup failed: {e}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
                let name = rustls::pki_types::ServerName::try_from(cfg.api_host.clone())
                    .map_err(|e| format!("invalid API host name: {e}"))?;
                let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg))
                    .connect(name, tcp)
                    .await
                    .map_err(|e| format!("TLS handshake with the GitHub API failed: {e}"))?;
                send_over(tls, pr_request(&cfg.api_host, &path, token, payload)?).await
            }
        }
    };
    let (status, body) = tokio::time::timeout(NET_TIMEOUT, exchange)
        .await
        .map_err(|_| "the GitHub API timed out".to_owned())??;
    parse_pr_response(status, &body, token)
}

// ---------------------------------------------------------------------------------------------
// Git transport through a throwaway staging repository
// ---------------------------------------------------------------------------------------------

/// How git reaches GitHub: the URL, pinning options, and the token, in the environment only.
pub struct GitRemote {
    url: String,
    config_args: Vec<String>,
    envs: Vec<(&'static str, Zeroizing<String>)>,
    secrets: Vec<Zeroizing<String>>,
}

impl GitRemote {
    /// For `cfg` with `token`: pinned https to the vetted addresses, or (tests) the local bare
    /// repository of the override.
    pub async fn new(
        cfg: &GithubCompanionConfigStored,
        token: &str,
        test_override: Option<&GithubTestOverride>,
    ) -> Result<Self, String> {
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        let header = Zeroizing::new(format!("Authorization: Basic {basic}"));
        let mut envs: Vec<(&'static str, Zeroizing<String>)> = vec![
            ("GCM_INTERACTIVE", Zeroizing::new("never".to_owned())),
            ("GIT_TERMINAL_PROMPT", Zeroizing::new("0".to_owned())),
            ("GIT_CONFIG_COUNT", Zeroizing::new("1".to_owned())),
            (
                "GIT_CONFIG_KEY_0",
                Zeroizing::new(format!("http.https://{}/.extraHeader", cfg.host)),
            ),
            ("GIT_CONFIG_VALUE_0", header.clone()),
        ];
        let mut config_args = vec!["-c".to_owned(), "credential.helper=".to_owned()];
        let url = match test_override {
            Some(ov) => {
                envs.push(("GIT_ALLOW_PROTOCOL", Zeroizing::new("file".to_owned())));
                ov.bare_remote_path.to_string_lossy().into_owned()
            }
            None => {
                let (_, pin) = resolve_and_vet_host(&cfg.host).await?;
                config_args.extend([
                    "-c".to_owned(),
                    "http.followRedirects=false".to_owned(),
                    "-c".to_owned(),
                    format!("http.curloptResolve={pin}"),
                ]);
                envs.push(("GIT_ALLOW_PROTOCOL", Zeroizing::new("https".to_owned())));
                format!("https://{}/{}/{}.git", cfg.host, cfg.owner, cfg.repo)
            }
        };
        Ok(Self {
            url,
            config_args,
            envs,
            secrets: vec![
                header,
                Zeroizing::new(basic),
                Zeroizing::new(token.to_owned()),
            ],
        })
    }

    fn scrub(&self, text: &str) -> String {
        let secrets: Vec<&str> = self.secrets.iter().map(|s| s.as_str()).collect();
        scrub(text, &secrets)
    }
}

/// Run git in `dir` (through `remote` when given), killed after [`GIT_TIMEOUT`]. Errors carry
/// the tail of stderr, scrubbed of the token.
async fn git_in(dir: &Path, remote: Option<&GitRemote>, args: &[&str]) -> Result<String, String> {
    let mut cmd = tokio::process::Command::from(premier_git_bridge::git_command(dir));
    if let Some(remote) = remote {
        cmd.args(&remote.config_args);
        for (key, value) in &remote.envs {
            cmd.env(key, value.as_str());
        }
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let out = tokio::time::timeout(GIT_TIMEOUT, cmd.output())
        .await
        .map_err(|_| "git timed out".to_owned())?
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr = remote.map_or_else(|| stderr.to_string(), |r| r.scrub(&stderr));
    let tail: Vec<char> = stderr.trim().chars().rev().take(600).collect();
    Err(format!(
        "git failed: {}",
        tail.into_iter().rev().collect::<String>()
    ))
}

/// A throwaway bare repository, deleted when dropped.
pub struct Staging(PathBuf);

impl Staging {
    pub async fn new() -> Result<Self, String> {
        let id: String = crate::auth::random_bytes(12)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = std::env::temp_dir().join(format!("premier-github-{id}"));
        std::fs::create_dir_all(&dir).map_err(|e| format!("staging directory: {e}"))?;
        let staging = Self(dir);
        git_in(&staging.0, None, &["init", "-q", "--bare"]).await?;
        git_in(&staging.0, None, &["config", "core.autocrlf", "false"]).await?;
        Ok(staging)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The OID `full_ref` has on the remote; `None` when the remote has no such ref. A transport or
/// auth failure is an `Err`, never `None`.
pub async fn remote_ref_oid(
    staging: &Path,
    remote: &GitRemote,
    full_ref: &str,
) -> Result<Option<String>, String> {
    let out = git_in(staging, Some(remote), &["ls-remote", &remote.url, full_ref]).await?;
    Ok(out.lines().find_map(|line| {
        let (oid, name) = line.split_once('\t')?;
        (name == full_ref
            && (oid.len() == 40 || oid.len() == 64)
            && oid.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| oid.to_owned())
    }))
}

/// Fetch the remote's `remote_ref` into `local_ref` of the staging repository; `None` when the
/// remote has no such ref.
pub async fn fetch_ref_into_staging(
    staging: &Path,
    remote: &GitRemote,
    remote_ref: &str,
    local_ref: &str,
) -> Result<Option<String>, String> {
    if remote_ref_oid(staging, remote, remote_ref).await?.is_none() {
        return Ok(None);
    }
    let refspec = format!("+{remote_ref}:{local_ref}");
    git_in(
        staging,
        Some(remote),
        &[
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "fetch.fsckObjects=true",
            "fetch",
            "-q",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            &remote.url,
            &refspec,
        ],
    )
    .await?;
    git_in(staging, None, &["rev-parse", "--verify", local_ref])
        .await
        .map(Some)
}

/// Push staging's `local_ref` to the remote branch, only if the remote branch is still at
/// `expected_remote_oid` (`None`: it must not exist yet).
pub async fn push_ref_from_staging(
    staging: &Path,
    remote: &GitRemote,
    local_ref: &str,
    remote_branch: &str,
    expected_remote_oid: Option<&str>,
) -> Result<(), String> {
    let lease = format!(
        "--force-with-lease=refs/heads/{remote_branch}:{}",
        expected_remote_oid.unwrap_or_default()
    );
    let refspec = format!("{local_ref}:refs/heads/{remote_branch}");
    git_in(
        staging,
        Some(remote),
        &["push", "-q", "--no-verify", &lease, &remote.url, &refspec],
    )
    .await
    .map(drop)
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// Serializes the companion's operations per repository inside this process.
fn companion_lock(root: &Path) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: LazyLock<StdMutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> =
        LazyLock::new(Default::default);
    LOCKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(root.to_path_buf())
        .or_default()
        .clone()
}

/// Guard holding both the in-process async mutex and the cross-process OS advisory lock on
/// `github-companion.lock` so concurrent server and CLI commands cannot clobber state.
struct CompanionGuard {
    _file: std::fs::File,
    _in_proc: tokio::sync::OwnedMutexGuard<()>,
}

async fn acquire_companion_lock(root: &Path) -> Result<CompanionGuard, GithubError> {
    let in_proc = companion_lock(root).lock_owned().await;
    let lock_root = root.to_path_buf();
    let file = blocking(move || {
        let dir = store::state_dir(&lock_root);
        premier_secrets::create_state_dir(&dir)
            .map_err(|e| internal(format!("create state dir failed: {e}")))?;
        let path = dir.join("github-companion.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| internal(format!("open companion lock failed: {e}")))?;
        file.lock()
            .map_err(|e| internal(format!("lock companion lock failed: {e}")))?;
        Ok(file)
    })
    .await?;
    Ok(CompanionGuard {
        _file: file,
        _in_proc: in_proc,
    })
}

fn sync_pair_key(canonical: &str, upstream: &str, zone: Option<&str>) -> String {
    format!("{canonical}\t{upstream}\t{}", zone.unwrap_or(""))
}

fn is_default_pair(
    root: &Path,
    cfg: &GithubCompanionConfigStored,
    canonical: &str,
    upstream: &str,
    zone: Option<&str>,
) -> bool {
    canonical_default_branch(root).ok().as_deref() == Some(canonical)
        && upstream == cfg.default_branch
        && zone == cfg.zone.as_deref().map(bare_zone)
}

fn load_file(root: &Path) -> GithubCompanionFile {
    store::load_json(root, STATE_FILE)
}

fn save_file(root: &Path, file: &mut GithubCompanionFile) -> Result<(), GithubError> {
    file.version = 1;
    store::save_json(root, STATE_FILE, file).map_err(internal)
}

fn audited<T>(
    state: &ServerState,
    actor: &str,
    action: &str,
    target: Option<String>,
    result: Result<T, GithubError>,
) -> Result<T, GithubError> {
    let (decision, reason) = match &result {
        Ok(_) => (AuditDecision::Allowed, "ok".to_owned()),
        Err(e) => (
            AuditDecision::Denied,
            format!("{} {}", e.status.as_u16(), e.body.error),
        ),
    };
    crate::auth::audit(
        &state.audit_sink,
        AuditEvent {
            timestamp: Utc::now(),
            principal: actor.to_owned(),
            agent_profile: None,
            agent_task_id: None,
            component: "premier-github".to_owned(),
            action: action.to_owned(),
            target,
            capability: None,
            decision,
            reason,
            bytes_scrubbed: 0,
        },
    );
    result
}

/// Policy, its fingerprint and the overlay guard every export is checked with.
struct ExportCtx {
    root: PathBuf,
    policy: Arc<CompiledPolicy>,
    fingerprint: String,
    overlay_guard: OverlayGuard,
}

fn export_ctx(state: &ServerState) -> Result<ExportCtx, GithubError> {
    let policy = state
        .current_policy()
        .ok_or_else(|| gh_err(StatusCode::SERVICE_UNAVAILABLE, "no compiled policy loaded"))?;
    let manifest = state
        .persisted
        .lock()
        .map(|g| g.overlays.clone())
        .unwrap_or_default();
    let overlay_guard =
        OverlayGuard::from_manifest(&manifest).map_err(|e| internal(e.to_string()))?;
    let fingerprint = sha256_hex(state.current_repo_policy_toml().as_bytes())[..16].to_owned();
    Ok(ExportCtx {
        root: state.workspace_root.clone(),
        policy,
        fingerprint,
        overlay_guard,
    })
}

fn require_config(file: &GithubCompanionFile) -> Result<GithubCompanionConfigStored, GithubError> {
    file.config
        .clone()
        .ok_or_else(|| bad("no GitHub repository is connected"))
}

fn require_token(state: &ServerState) -> Result<Zeroizing<String>, GithubError> {
    store::load_github_token(&state.workspace_root, VAULT_REPO_ID)
        .map_err(internal)?
        .ok_or_else(|| {
            gh_err(
                StatusCode::CONFLICT,
                "no GitHub token is configured: add one in the GitHub settings",
            )
        })
}

fn require_direction(cfg: &GithubCompanionConfigStored, outbound: bool) -> Result<(), GithubError> {
    let refused = match cfg.sync_direction {
        SyncDirection::Bidirectional => false,
        SyncDirection::Outbound => !outbound,
        SyncDirection::Inbound => outbound,
    };
    if refused {
        let way = if outbound { "to" } else { "from" };
        return Err(gh_err(
            StatusCode::CONFLICT,
            format!("this companion is not configured to sync {way} GitHub"),
        ));
    }
    Ok(())
}

/// The zone exports are bound to: `requested` or the configured one, which policy must declare.
fn bound_zone(
    policy: &CompiledPolicy,
    requested: Option<&str>,
    cfg: &GithubCompanionConfigStored,
) -> Result<Option<String>, GithubError> {
    let zone = requested
        .map(bare_zone)
        .filter(|z| !z.is_empty())
        .map(str::to_owned)
        .or_else(|| cfg.zone.clone());
    if let Some(zone) = &zone
        && !policy.has_zone(zone)
    {
        return Err(bad(format!("unknown zone '{zone}'")));
    }
    Ok(zone)
}

/// The canonical default branch's short name.
fn canonical_default_branch(root: &Path) -> Result<String, GithubError> {
    canon::default_ref(root)
        .and_then(|r| r.strip_prefix("refs/heads/").map(str::to_owned))
        .ok_or_else(|| {
            gh_err(
                StatusCode::CONFLICT,
                "the repository has no default branch checked out",
            )
        })
}

/// `Name <user@users.noreply.premier> <now> +0000` for `actor` (`@username`).
fn author_line(state: &ServerState, actor: &str) -> String {
    let username: String = actor
        .trim_start_matches('@')
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .collect();
    let display = state
        .auth
        .accounts()
        .ok()
        .and_then(|all| all.into_iter().find(|(id, _, _)| id == actor))
        .map(|(_, display, _)| display)
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| username.clone());
    format!(
        "{} <{username}@{}> {} +0000",
        display.replace(['<', '>', '\n', '\r'], ""),
        canon::COMMIT_EMAIL_DOMAIN,
        Utc::now().timestamp()
    )
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, GithubError> + Send + 'static,
) -> Result<T, GithubError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(e.to_string()))?
}

fn net_err(msg: String) -> GithubError {
    gh_err(StatusCode::BAD_GATEWAY, msg)
}

/// What the companion is connected to, how far the sync got, and its pull requests.
pub async fn service_status(
    state: &ServerState,
    actor: &str,
) -> Result<GithubCompanionStatus, GithubError> {
    audited(state, actor, "github-status", None, Ok(status_of(state)))
}

fn status_of(state: &ServerState) -> GithubCompanionStatus {
    let file = load_file(&state.workspace_root);
    let sync_state = file.config.as_ref().map(|_| GithubSyncStateSummary {
        last_canonical_oid: file.mapping.last_canonical_oid.clone(),
        last_upstream_oid: file.mapping.last_upstream_oid.clone(),
        mapped_commits: file.mapping.canonical_to_upstream.len(),
        last_policy_fingerprint: file.mapping.last_policy_fingerprint.clone(),
        last_sync_out_at: file.last_sync_out_at.clone(),
        last_sync_in_at: file.last_sync_in_at.clone(),
        last_sync_summary: file.last_sync_summary.clone(),
    });
    GithubCompanionStatus {
        connected: file.config.is_some(),
        config: file.config,
        sync_state,
        receipts: file.receipts,
        available_zones: state
            .current_policy()
            .map(|p| p.zone_names())
            .unwrap_or_default(),
        enterprise_hosts_allowed: state.github_enterprise_hosts.to_vec(),
    }
}

/// Connect (or reconnect) the GitHub repository. A token given is stored encrypted; a token for
/// another host is dropped rather than ever sent to the new one.
pub async fn service_configure(
    state: &ServerState,
    actor: &str,
    payload: GithubConfigPayload,
) -> Result<GithubCompanionStatus, GithubError> {
    let target = Some(payload.repo.clone());
    let result = configure(state, actor, payload).await;
    audited(state, actor, "github-configure", target, result)?;
    Ok(status_of(state))
}

async fn configure(
    state: &ServerState,
    actor: &str,
    payload: GithubConfigPayload,
) -> Result<(), GithubError> {
    let (owner, repo) = validate_owner_repo(&payload.repo).map_err(bad)?;
    let (host, api_host) = validate_github_hosts(
        payload.host.as_deref(),
        payload.api_host.as_deref(),
        &state.github_enterprise_hosts,
    )
    .map_err(bad)?;
    let default_branch = payload
        .default_branch
        .map(|b| b.trim().to_owned())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "main".to_owned());
    require_branch(&default_branch, "default_branch")?;
    let zone = payload
        .zone
        .as_deref()
        .map(bare_zone)
        .filter(|z| !z.is_empty())
        .map(str::to_owned);
    if let Some(zone) = &zone
        && !state.current_policy().is_some_and(|p| p.has_zone(zone))
    {
        return Err(bad(format!("unknown zone '{zone}'")));
    }
    let token = payload.token.map(Zeroizing::new);
    if let Some(token) = &token {
        validate_token(token.trim())?;
    }

    let root = &state.workspace_root;
    let _guard = acquire_companion_lock(root).await?;
    let mut file = load_file(root);
    let prev = file.config.take();
    let full_name = format!("{owner}/{repo}");
    let same_host = prev.as_ref().is_some_and(|p| p.host == host);
    let same_remote = same_host
        && prev
            .as_ref()
            .is_some_and(|p| p.full_name.eq_ignore_ascii_case(&full_name));
    let now = Utc::now().to_rfc3339();
    let (token_configured, token_updated_at) = match &token {
        Some(token) => {
            store::store_github_token(root, VAULT_REPO_ID, token.trim()).map_err(internal)?;
            (true, Some(now.clone()))
        }
        None if same_host => prev
            .as_ref()
            .map(|p| (p.token_configured, p.token_updated_at.clone()))
            .unwrap_or_default(),
        None => {
            store::delete_github_token(root, VAULT_REPO_ID).map_err(internal)?;
            (false, None)
        }
    };
    if !same_remote {
        file.mapping = ZoneSyncMappingState::default();
        file.pair_mappings.clear();
        file.last_sync_in_at = None;
        file.last_sync_out_at = None;
        file.last_sync_summary = None;
    }
    file.config = Some(GithubCompanionConfigStored {
        owner,
        repo,
        full_name,
        host,
        api_host,
        default_branch,
        zone,
        sync_direction: payload.sync_direction.unwrap_or_default(),
        token_configured,
        token_updated_at,
        connected_at: prev.filter(|_| same_remote).map_or(now, |p| p.connected_at),
        connected_by: actor.to_owned(),
    });
    save_file(root, &mut file)
}

/// Disconnect: the token is purged from the vault and the sync state forgotten. Receipts stay.
pub async fn service_disconnect(state: &ServerState, actor: &str) -> Result<(), GithubError> {
    let root = &state.workspace_root;
    let result = async {
        let _guard = acquire_companion_lock(root).await?;
        store::delete_github_token(root, VAULT_REPO_ID).map_err(internal)?;
        let mut file = load_file(root);
        file.config = None;
        file.mapping = ZoneSyncMappingState::default();
        file.pair_mappings.clear();
        file.last_sync_in_at = None;
        file.last_sync_out_at = None;
        file.last_sync_summary = None;
        save_file(root, &mut file)
    }
    .await;
    audited(state, actor, "github-disconnect", None, result)
}

/// The canonical pieces of a pull request plan, resolved from the request.
struct PrInputs {
    source_branch: String,
    source_oid: String,
    base_branch: String,
    base_oid: String,
    pr_branch: Option<String>,
}

fn resolve_companion_source_branch(root: &Path, name: &str) -> Result<String, GithubError> {
    for candidate in [
        format!("{}{name}", premier_git_bridge::PRIVATE_REF_PREFIX),
        format!("refs/heads/{name}"),
    ] {
        if let Some(oid) = canon::tip_of(root, &candidate) {
            return Ok(oid);
        }
    }
    Err(gh_err(
        StatusCode::NOT_FOUND,
        format!("branch '{name}' not found in repository"),
    ))
}

fn pr_inputs(
    root: &Path,
    cfg: &GithubCompanionConfigStored,
    req: &GithubPrRequest,
) -> Result<PrInputs, GithubError> {
    let source_branch = req.source_branch.trim().to_owned();
    require_branch(&source_branch, "source_branch")?;
    let base_branch = req
        .base_branch
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .unwrap_or(&cfg.default_branch)
        .to_owned();
    require_branch(&base_branch, "base_branch")?;
    let pr_branch = req
        .pr_branch
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned);
    if let Some(pr) = &pr_branch {
        require_branch(pr, "pr_branch")?;
        if *pr == base_branch {
            return Err(bad("pr_branch must differ from base_branch"));
        }
    }
    let source_oid = resolve_companion_source_branch(root, &source_branch)?;
    // shortcut: GitHub's base branch is taken to have the same name canonically; map names
    // explicitly if a repository ever mirrors `main` as something else.
    let base_oid = canon::tip_of(root, &format!("refs/heads/{base_branch}")).ok_or_else(|| {
        gh_err(
            StatusCode::NOT_FOUND,
            format!("canonical base branch '{base_branch}' not found"),
        )
    })?;
    Ok(PrInputs {
        source_branch,
        source_oid,
        base_branch,
        base_oid,
        pr_branch,
    })
}

fn plan_pr(
    ctx: &ExportCtx,
    zone: Option<&str>,
    inputs: &PrInputs,
    req: &GithubPrRequest,
) -> Result<GithubPrSquashPlan, GithubError> {
    plan_github_pr_squash(
        &CanonicalGitRepo::open(&ctx.root),
        &ctx.policy,
        &ctx.fingerprint,
        Some(&ctx.overlay_guard),
        zone,
        &inputs.source_branch,
        &inputs.source_oid,
        &inputs.base_branch,
        &inputs.base_oid,
        inputs.pr_branch.as_deref(),
        req.title.as_deref(),
        req.body.as_deref(),
    )
    .map_err(|e| bridge_err(e, StatusCode::BAD_REQUEST))
}

/// Dry run of a pull request: what GitHub would get, read from the canonical repository only.
/// No network.
pub fn service_preview_pr(
    state: &ServerState,
    actor: &str,
    req: &GithubPrRequest,
) -> Result<GithubPrPreviewResponse, GithubError> {
    let result = (|| {
        let cfg = require_config(&load_file(&state.workspace_root))?;
        let ctx = export_ctx(state)?;
        let zone = bound_zone(&ctx.policy, None, &cfg)?;
        let inputs = pr_inputs(&ctx.root, &cfg, req)?;
        let plan = plan_pr(&ctx, zone.as_deref(), &inputs, req)?;
        Ok(GithubPrPreviewResponse::new(cfg.full_name, plan))
    })();
    audited(
        state,
        actor,
        "github-pr-preview",
        Some(req.source_branch.clone()),
        result,
    )
}

/// Publish `source_branch` to GitHub as one Squash-Declassified pull request commit, open the
/// pull request, keep a receipt, and link the review it belongs to. A blocked or conflicting
/// plan is refused before anything reaches GitHub.
pub async fn service_publish_pr(
    state: &ServerState,
    actor: &str,
    req: GithubPrRequest,
) -> Result<PublishGithubPrResult, GithubError> {
    let target = Some(req.source_branch.clone());
    let result = publish_pr(state, actor, req).await;
    audited(state, actor, "github-pr-publish", target, result)
}

async fn publish_pr(
    state: &ServerState,
    actor: &str,
    req: GithubPrRequest,
) -> Result<PublishGithubPrResult, GithubError> {
    let root = state.workspace_root.clone();
    let _guard = acquire_companion_lock(&root).await?;
    let cfg = require_config(&load_file(&root))?;
    require_direction(&cfg, true)?;
    let token = require_token(state)?;
    if let Some(cid) = &req.change_id {
        let known = state
            .persisted
            .lock()
            .map(|st| st.reviews.iter().any(|r| r.change_id == *cid))
            .unwrap_or(false);
        if !known {
            return Err(gh_err(
                StatusCode::NOT_FOUND,
                format!("review '{cid}' not found"),
            ));
        }
    }
    let ctx = Arc::new(export_ctx(state)?);
    let zone = bound_zone(&ctx.policy, None, &cfg)?;
    let inputs = Arc::new(pr_inputs(&root, &cfg, &req)?);

    // Refuse locally first: a blocked or conflicting plan never touches GitHub.
    let plan = {
        let (ctx, inputs, req, zone) = (ctx.clone(), inputs.clone(), req.clone(), zone.clone());
        blocking(move || plan_pr(&ctx, zone.as_deref(), &inputs, &req)).await?
    };
    if !plan.blocked.is_empty() {
        return Err(bridge_err(
            GitBridgeError::PublishBlocked(plan.blocked),
            StatusCode::BAD_REQUEST,
        ));
    }
    if !plan.conflicts.is_empty() {
        return Err(bridge_err(
            GitBridgeError::PublishConflict(plan.conflicts),
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Some(reason) = plan.reason {
        return Err(bad(reason));
    }
    let pr_branch = plan.pr_branch.clone();

    let test = state.github_test_override.as_deref();
    let remote = GitRemote::new(&cfg, &token, test).await.map_err(bad)?;
    let staging = Staging::new().await.map_err(internal)?;
    let base_ref = format!("refs/heads/{}", inputs.base_branch);
    let upstream_base = fetch_ref_into_staging(
        staging.path(),
        &remote,
        &base_ref,
        "refs/remotes/github/base",
    )
    .await
    .map_err(net_err)?;
    let existing_head = remote_ref_oid(staging.path(), &remote, &format!("refs/heads/{pr_branch}"))
        .await
        .map_err(net_err)?;

    let file = load_file(&root);
    if existing_head.is_some()
        && !pr_branch.starts_with("premier/declassify-")
        && !pr_branch.starts_with("premier/pr-")
        && !file
            .receipts
            .iter()
            .any(|r| r.pr_branch == pr_branch && r.source_branch == inputs.source_branch)
    {
        return Err(gh_err(
            StatusCode::CONFLICT,
            format!(
                "target pr_branch '{pr_branch}' already exists on GitHub and is not managed by Premier"
            ),
        ));
    }

    let author = author_line(state, actor);
    let materialized = {
        let (ctx, inputs, req, zone) = (ctx.clone(), inputs.clone(), req.clone(), zone.clone());
        let (staging_dir, pr_branch) = (staging.path().to_path_buf(), pr_branch.clone());
        blocking(move || {
            materialize_github_pr_in_staging(
                &CanonicalGitRepo::open(&ctx.root),
                &staging_dir,
                &ctx.policy,
                &ctx.fingerprint,
                Some(&ctx.overlay_guard),
                zone.as_deref(),
                &inputs.source_branch,
                &inputs.source_oid,
                &inputs.base_branch,
                &inputs.base_oid,
                upstream_base.as_deref(),
                &pr_branch,
                req.title.as_deref(),
                req.body.as_deref(),
                &author,
            )
            .map_err(|e| bridge_err(e, StatusCode::BAD_REQUEST))
        })
        .await?
    };

    push_ref_from_staging(
        staging.path(),
        &remote,
        &format!("refs/heads/{pr_branch}"),
        &pr_branch,
        existing_head.as_deref(),
    )
    .await
    .map_err(|e| gh_err(StatusCode::CONFLICT, format!("push to GitHub refused: {e}")))?;

    let (pr_number, pr_url) = create_github_pull_request(
        &cfg,
        &token,
        test,
        &PullRequestSpec {
            head: &pr_branch,
            base: &inputs.base_branch,
            title: &materialized.pr_title,
            body: &materialized.pr_body,
            draft: req.draft,
        },
    )
    .await
    .map_err(|e| net_err(remote.scrub(&e)))?;

    let receipt = GithubPrReceipt {
        id: format!(
            "ghpr_{}",
            crate::auth::random_bytes(8)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        source_branch: inputs.source_branch.clone(),
        base_branch: inputs.base_branch.clone(),
        pr_branch: pr_branch.clone(),
        pr_number,
        pr_url: pr_url.clone(),
        pr_title: materialized.pr_title.clone(),
        public_commit_oid: materialized.public_commit_oid.clone(),
        published_paths: materialized.published_paths.clone(),
        scrubbed_paths_count: materialized.scrubbed_paths.len(),
        attestation_trailer: materialized.attestation.to_git_trailer(),
        change_id: req.change_id.clone(),
        created_by: actor.to_owned(),
        created_at: Utc::now().to_rfc3339(),
    };
    let mut file = load_file(&root);
    file.receipts.insert(0, receipt.clone());
    file.receipts.truncate(MAX_RECEIPTS);
    save_file(&root, &mut file)?;

    if let Ok(mut st) = state.persisted.lock() {
        let mut updated_review = false;
        let review = match &req.change_id {
            Some(cid) => st.reviews.iter_mut().find(|r| r.change_id == *cid),
            None => st
                .reviews
                .iter_mut()
                .find(|r| r.branch == inputs.source_branch),
        };
        if let Some(review) = review {
            review.github_pr_url = Some(pr_url.clone());
            review.github_pr_number = Some(pr_number);
            updated_review = true;
        }
        if updated_review {
            let state_path = store::state_file_path(&root);
            if state_path.exists() {
                let mut on_disk = store::load_state(&root).map_err(internal)?;
                let disk_review = match &req.change_id {
                    Some(cid) => on_disk.reviews.iter_mut().find(|r| r.change_id == *cid),
                    None => on_disk
                        .reviews
                        .iter_mut()
                        .find(|r| r.branch == inputs.source_branch),
                };
                if let Some(disk_review) = disk_review {
                    disk_review.github_pr_url = Some(pr_url);
                    disk_review.github_pr_number = Some(pr_number);
                    store::save_state(&root, &on_disk).map_err(internal)?;
                } else {
                    store::save_state(&root, &st).map_err(internal)?;
                }
            } else {
                store::save_state(&root, &st).map_err(internal)?;
            }
        }
    }

    Ok(PublishGithubPrResult {
        receipt,
        published_paths: materialized.published_paths,
        scrubbed_paths: materialized.scrubbed_paths,
    })
}

/// Project the canonical branch's zone onto GitHub's branch and push it there.
pub async fn service_sync_out(
    state: &ServerState,
    actor: &str,
    req: SyncOutRequest,
) -> Result<ZoneSyncOutResult, GithubError> {
    let target = req.target_branch.clone();
    let result = sync_out(state, actor, req).await;
    audited(state, actor, "github-sync-out", target, result)
}

async fn sync_out(
    state: &ServerState,
    actor: &str,
    req: SyncOutRequest,
) -> Result<ZoneSyncOutResult, GithubError> {
    let root = state.workspace_root.clone();
    let _guard = acquire_companion_lock(&root).await?;
    let mut file = load_file(&root);
    let cfg = require_config(&file)?;
    require_direction(&cfg, true)?;
    let token = require_token(state)?;
    let ctx = Arc::new(export_ctx(state)?);
    let zone = bound_zone(&ctx.policy, req.zone.as_deref(), &cfg)?;
    let source = match req
        .source_branch
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_owned(),
        None => canonical_default_branch(&root)?,
    };
    require_canonical_name(&source, "source_branch")?;
    let full_ref = format!("refs/heads/{source}");
    let canonical_tip = canon::tip_of(&root, &full_ref).ok_or_else(|| {
        gh_err(
            StatusCode::NOT_FOUND,
            format!("branch '{source}' not found"),
        )
    })?;
    if state.ref_visibility(&full_ref) != premier_core::Visibility::Public {
        return Err(gh_err(
            StatusCode::FORBIDDEN,
            format!(
                "branch '{source}' is not public; use squash-declassify PR publish instead of sync-out"
            ),
        ));
    }
    let target = req
        .target_branch
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or(&cfg.default_branch)
        .to_owned();
    require_branch(&target, "target_branch")?;

    let use_default_slot = is_default_pair(&root, &cfg, &source, &target, zone.as_deref());
    let pair_key = sync_pair_key(&source, &target, zone.as_deref());
    let prev_mapping = if use_default_slot {
        file.mapping.clone()
    } else {
        file.pair_mappings
            .get(&pair_key)
            .cloned()
            .unwrap_or_default()
    };

    let test = state.github_test_override.as_deref();
    let remote = GitRemote::new(&cfg, &token, test).await.map_err(bad)?;
    let staging = Staging::new().await.map_err(internal)?;
    let target_ref = format!("refs/heads/{target}");
    let upstream_tip = fetch_ref_into_staging(staging.path(), &remote, &target_ref, &target_ref)
        .await
        .map_err(net_err)?;

    let author = author_line(state, actor);
    let result = {
        let (staging_dir, mapping, zone) =
            (staging.path().to_path_buf(), prev_mapping, zone.clone());
        let (source, target, upstream_tip) = (source.clone(), target.clone(), upstream_tip.clone());
        let summary = req.summary_message.clone();
        let (squash, dry_run) = (req.squash, req.dry_run);
        blocking(move || {
            project_zone_sync_out(
                &CanonicalGitRepo::open(&ctx.root),
                &staging_dir,
                &ctx.policy,
                &ctx.fingerprint,
                Some(&ctx.overlay_guard),
                zone.as_deref(),
                &source,
                &canonical_tip,
                &target,
                upstream_tip.as_deref(),
                &mapping,
                squash,
                summary.as_deref(),
                &author,
                dry_run,
            )
            .map_err(|e| bridge_err(e, StatusCode::CONFLICT))
        })
        .await?
    };
    if req.dry_run {
        return Ok(result);
    }
    if let Some(new_tip) = &result.upstream_tip
        && result.upstream_tip != upstream_tip
    {
        push_ref_from_staging(
            staging.path(),
            &remote,
            new_tip,
            &target,
            upstream_tip.as_deref(),
        )
        .await
        .map_err(|e| {
            gh_err(
                StatusCode::CONFLICT,
                format!("push to GitHub refused (run sync-in first?): {e}"),
            )
        })?;
    }
    if use_default_slot {
        file.mapping = result.updated_mapping.clone();
    } else {
        file.pair_mappings
            .insert(pair_key, result.updated_mapping.clone());
    }
    file.last_sync_out_at = Some(Utc::now().to_rfc3339());
    file.last_sync_summary = Some(format!(
        "sync-out {source} -> {target}: {} projected, {} collapsed",
        result.commits_projected, result.commits_collapsed
    ));
    save_file(&root, &mut file)?;
    Ok(result)
}

/// The upstream ref a sync-in reads: a PR head, a full branch ref, or a branch name.
fn upstream_ref(
    req: &SyncInRequest,
    cfg: &GithubCompanionConfigStored,
) -> Result<String, GithubError> {
    if let Some(n) = req.pr_number {
        return Ok(format!("refs/pull/{n}/head"));
    }
    let raw = req
        .upstream_ref
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .unwrap_or(&cfg.default_branch);
    if let Some(rest) = raw.strip_prefix("refs/pull/") {
        let n = rest.strip_suffix("/head").unwrap_or("");
        if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(raw.to_owned());
        }
        return Err(bad(format!(
            "upstream_ref '{raw}' is not a pull request head"
        )));
    }
    let branch = raw.strip_prefix("refs/heads/").unwrap_or(raw);
    require_branch(branch, "upstream_ref")?;
    Ok(format!("refs/heads/{branch}"))
}

/// Import GitHub's new public commits onto the canonical branch, leaving every file GitHub does
/// not see untouched. Any change policy does not let in refuses the whole import (403).
pub async fn service_sync_in(
    state: &ServerState,
    actor: &str,
    req: SyncInRequest,
) -> Result<ZoneSyncInResult, GithubError> {
    let target = req
        .upstream_ref
        .clone()
        .or_else(|| req.pr_number.map(|n| format!("refs/pull/{n}/head")));
    let result = sync_in(state, actor, req).await;
    audited(state, actor, "github-sync-in", target, result)
}

async fn sync_in(
    state: &ServerState,
    _actor: &str,
    req: SyncInRequest,
) -> Result<ZoneSyncInResult, GithubError> {
    let root = state.workspace_root.clone();
    let _guard = acquire_companion_lock(&root).await?;
    let mut file = load_file(&root);
    let cfg = require_config(&file)?;
    require_direction(&cfg, false)?;
    let token = require_token(state)?;
    let ctx = Arc::new(export_ctx(state)?);
    let zone = bound_zone(&ctx.policy, None, &cfg)?;
    let upstream_ref = upstream_ref(&req, &cfg)?;
    let target = match req
        .target_branch
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(t) => t.to_owned(),
        None => canonical_default_branch(&root)?,
    };
    require_branch(&target, "target_branch")?;

    let pr_ref = upstream_ref.starts_with("refs/pull/");
    let pair_upstream = if pr_ref {
        cfg.default_branch.as_str()
    } else {
        upstream_ref
            .strip_prefix("refs/heads/")
            .unwrap_or(&cfg.default_branch)
    };
    let use_default_slot = is_default_pair(&root, &cfg, &target, pair_upstream, zone.as_deref());
    let pair_key = sync_pair_key(&target, pair_upstream, zone.as_deref());
    let prev_mapping = if use_default_slot {
        file.mapping.clone()
    } else {
        file.pair_mappings
            .get(&pair_key)
            .cloned()
            .unwrap_or_default()
    };

    let test = state.github_test_override.as_deref();
    let remote = GitRemote::new(&cfg, &token, test).await.map_err(bad)?;
    let staging = Staging::new().await.map_err(internal)?;
    let upstream_tip = fetch_ref_into_staging(
        staging.path(),
        &remote,
        &upstream_ref,
        "refs/remotes/github/in",
    )
    .await
    .map_err(net_err)?
    .ok_or_else(|| {
        gh_err(
            StatusCode::NOT_FOUND,
            format!("'{upstream_ref}' not found on GitHub"),
        )
    })?;

    let result = {
        let (staging_dir, mapping, zone) = (
            staging.path().to_path_buf(),
            prev_mapping.clone(),
            zone.clone(),
        );
        let (upstream_ref, target, dry_run) = (upstream_ref.clone(), target.clone(), req.dry_run);
        let state = state.clone();
        blocking(move || {
            let root = &ctx.root;
            // The canonical ref moves under the repository's ref lock, and the working tree
            // follows the default branch as after any other server-made commit.
            let before = (!dry_run)
                .then(|| canon::DefaultTip::capture(root))
                .flatten();
            let _lock = (!dry_run && before.is_none()).then(|| canon::ref_lock(root));
            let canonical_tip = canon::tip_of(root, &format!("refs/heads/{target}"));
            let result = apply_zone_sync_in(
                &CanonicalGitRepo::open(root),
                &staging_dir,
                &ctx.policy,
                &ctx.fingerprint,
                Some(&ctx.overlay_guard),
                zone.as_deref(),
                &upstream_ref,
                &upstream_tip,
                &target,
                canonical_tip.as_deref(),
                &mapping,
                dry_run,
            );
            state.default_branch_moved(before);
            result.map_err(|e| bridge_err(e, StatusCode::CONFLICT))
        })
        .await?
    };
    if !result.policy_violations.is_empty() {
        return Err(GithubError {
            status: StatusCode::FORBIDDEN,
            body: ApiError {
                error: format!(
                    "sync-in refused: {} on GitHub may not come in; nothing was imported",
                    premier_git_bridge::plural(result.policy_violations.len(), "change")
                ),
                policy_violations: Some(Box::new(result.policy_violations)),
                ..ApiError::default()
            },
        });
    }
    if !result.conflicts.is_empty() {
        return Err(bridge_err(
            GitBridgeError::PublishConflict(result.conflicts),
            StatusCode::CONFLICT,
        ));
    }
    if req.dry_run {
        return Ok(result);
    }
    let cursor_changed = result.updated_mapping != prev_mapping;
    let should_save = result.new_canonical_tip.is_some() || (!pr_ref && cursor_changed);
    if !should_save {
        return Ok(result);
    }
    let slot = if use_default_slot {
        &mut file.mapping
    } else {
        file.pair_mappings.entry(pair_key).or_default()
    };
    if !pr_ref {
        *slot = result.updated_mapping.clone();
    } else if result.new_canonical_tip.is_some() {
        // PR heads extend the OID map without moving the default branch's `last` pair.
        slot.upstream_to_canonical
            .extend(result.updated_mapping.upstream_to_canonical.clone());
        slot.canonical_to_upstream
            .extend(result.updated_mapping.canonical_to_upstream.clone());
    }
    file.last_sync_in_at = Some(Utc::now().to_rfc3339());
    file.last_sync_summary = Some(if result.commits_imported == 0 {
        format!("sync-in {upstream_ref} -> {target}: re-anchored cursor (up to date)")
    } else {
        format!(
            "sync-in {upstream_ref} -> {target}: {} imported",
            premier_git_bridge::plural(result.commits_imported, "commit")
        )
    });
    save_file(&root, &mut file)?;
    Ok(result)
}

// ---------------------------------------------------------------------------------------------
// Handlers (all mounted behind `owner(..)`; each also insists on a browser session)
// ---------------------------------------------------------------------------------------------

type ApiErr = (StatusCode, Json<ApiError>);
const WHAT: &str = "the GitHub companion";

pub async fn status_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<GithubCompanionStatus>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    Ok(Json(service_status(&state, &actor).await?))
}

pub async fn configure_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<GithubConfigPayload>,
) -> Result<Json<GithubCompanionStatus>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    Ok(Json(service_configure(&state, &actor, payload).await?))
}

pub async fn disconnect_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    service_disconnect(&state, &actor).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn preview_pr_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<GithubPrRequest>,
) -> Result<Json<GithubPrPreviewResponse>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    let preview = tokio::task::spawn_blocking(move || service_preview_pr(&state, &actor, &req))
        .await
        .map_err(|e| crate::err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    Ok(Json(preview))
}

pub async fn publish_pr_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<GithubPrRequest>,
) -> Result<Json<PublishGithubPrResult>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    Ok(Json(service_publish_pr(&state, &actor, req).await?))
}

pub async fn sync_out_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<SyncOutRequest>,
) -> Result<Json<ZoneSyncOutResult>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    Ok(Json(service_sync_out(&state, &actor, req).await?))
}

pub async fn sync_in_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<SyncInRequest>,
) -> Result<Json<ZoneSyncInResult>, ApiErr> {
    crate::ops::require_session(&user, WHAT)?;
    let actor = crate::auth::actor_principal();
    Ok(Json(service_sync_in(&state, &actor, req).await?))
}
