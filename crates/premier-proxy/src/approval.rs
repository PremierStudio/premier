//! Per-capability JIT approval gate with scoped TTL caching and async Control-Plane UI hub.
//!
//! Approving one capability for a short TTL never unlocks any other secret. A knock carries a
//! sanitized wire preview (never the raw secret) so the approver sees exactly what will be sent.

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use premier_core::DelegatedIdentity;
use premier_secrets::{Sensitivity, path_matches_prefix};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot};

/// Longest a single JIT grant may live. Larger values (from a schema, an approver or a restored
/// snapshot) are clamped, so TTL arithmetic can never overflow. `0` means "this request only".
pub const MAX_JIT_TTL_SECS: u64 = 24 * 60 * 60;

/// How long a knock waits for a human before it is expired and the request denied.
pub const PENDING_APPROVAL_TIMEOUT_SECS: u64 = 180;

/// Default maximum time [`HubGate`] waits for a human decision before timing out and denying.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(PENDING_APPROVAL_TIMEOUT_SECS);

const TIMED_OUT: &str = "approval request timed out";

/// Deterministic risk tier shown on a knock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    ReadOnly,
    #[default]
    StateMutation,
    SensitiveScope,
}

/// What an approval covers beyond the request that knocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// This request only; never cached.
    Once,
    /// Same method and exact concrete path.
    ExactPath,
    /// `GET` only, any concrete path under the approved schema prefix.
    ReadOnlyPrefix,
    /// Same method, same schema prefix (the legacy grant shape).
    ExactScope,
}

/// One outbound header as the approver sees it: scrubbed, placeholders visible, never secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedHeader {
    pub name: String,
    pub value: String,
    pub contains_placeholder: bool,
}

/// Sanitized preview of the request as it will go on the wire (before secret substitution).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WirePreview {
    pub method: String,
    pub host: String,
    pub concrete_path: String,
    pub query_keys: Vec<String>,
    pub headers: Vec<SanitizedHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
    pub body_size_bytes: usize,
    pub body_truncated: bool,
    pub body_is_binary: bool,
}

/// Where the knock came from (session, branch, command), when the host knows.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// An approver's answer to a knock.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approved: bool,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub grant_scope: Option<GrantScope>,
    #[serde(default)]
    pub denial_reason: Option<String>,
}

/// What a gate hands back to the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Approved {
        ttl_secs: u64,
        grant_scope: GrantScope,
    },
    Denied {
        reason: Option<String>,
    },
}

pub fn is_read_only_method(method: &str) -> bool {
    ["GET", "HEAD", "OPTIONS"]
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method.trim()))
}

const SENSITIVE_SEGMENTS: &[&str] = &[
    "admin",
    "billing",
    "charges",
    "payouts",
    "refunds",
    "transfers",
    "tokens",
    "keys",
    "secrets",
    "credentials",
    "auth",
    "oauth",
    "iam",
    "roles",
    "permissions",
    "webhooks",
    "deployments",
    "prod",
];

/// Sensitive even to read.
const SECRET_BEARING_SEGMENTS: &[&str] = &["admin", "secrets", "credentials", "tokens", "keys"];

/// `%XX` decoded, so `/k%65ys` is classified as the `/keys` the upstream will serve.
fn percent_decode(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b, hex) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A path segment is `word`, or `word` followed by a separator (`prod-eu`, `admin_v2`).
fn has_segment(path: &str, words: &[&str]) -> bool {
    percent_decode(path)
        .to_ascii_lowercase()
        .split('/')
        .any(|seg| {
            words.iter().any(|w| {
                seg.strip_prefix(w)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(['-', '_', '.']))
            })
        })
}

pub fn is_sensitive_path(path: &str) -> bool {
    has_segment(path, SENSITIVE_SEGMENTS)
}

pub fn classify_risk(method: &str, concrete_path: &str, sensitivity: Sensitivity) -> RiskLevel {
    if sensitivity == Sensitivity::Restricted
        || (is_sensitive_path(concrete_path)
            && (!is_read_only_method(method)
                || has_segment(concrete_path, SECRET_BEARING_SEGMENTS)))
    {
        RiskLevel::SensitiveScope
    } else if is_read_only_method(method) {
        RiskLevel::ReadOnly
    } else {
        RiskLevel::StateMutation
    }
}

pub fn synthesize_intent_summary(
    method: &str,
    host: &str,
    concrete_path: &str,
    risk: RiskLevel,
) -> String {
    let m = method.trim().to_ascii_uppercase();
    match risk {
        RiskLevel::SensitiveScope if is_read_only_method(&m) => {
            format!("Sensitive read ({m}) on restricted scope {host}{concrete_path}")
        }
        RiskLevel::SensitiveScope => format!("Sensitive mutation ({m}) on {host}{concrete_path}"),
        RiskLevel::ReadOnly => format!("Read-only check against {host}{concrete_path}"),
        _ if m == "DELETE" => format!("Destructive delete (DELETE) on {host}{concrete_path}"),
        _ => format!("Write mutation ({m}) to {host}{concrete_path}"),
    }
}

/// Trim, drop control characters, cap at 240 chars; blank means no reason.
fn sanitize_denial_reason(reason: Option<String>) -> Option<String> {
    let clean: String = reason?
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect();
    let clean = clean.trim().to_owned();
    (!clean.is_empty()).then_some(clean)
}

/// Request details presented when a capability has `approval = "jit"`.
///
/// `path` is the schema path prefix that authorised the request; `concrete_path` is the URL path
/// actually requested. What a grant covers beyond this request is set by its [`GrantScope`].
/// An action `kind` / MCP server / MCP tool / args hash / ref (when present) is part of the
/// grant scope, so an egress approval never unlocks an MCP tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub principal: String,
    pub agent_profile: Option<String>,
    pub var_name: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub ttl_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concrete_path: Option<String>,
    #[serde(default)]
    pub risk_level: RiskLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_preview: Option<WirePreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
}

impl ApprovalRequest {
    pub fn effective_concrete_path(&self) -> &str {
        self.concrete_path.as_deref().unwrap_or(&self.path)
    }

    /// True if the approved grant recorded in `item` covers this request. Never widens: the
    /// principal, agent profile, variable and host must match exactly, then the grant scope.
    pub fn covered_by(&self, item: &PendingApproval) -> bool {
        if item.status != ApprovalStatus::Approved
            || item.principal != self.principal
            || item.agent_profile != self.agent_profile
            || item.var_name != self.var_name
            || !item.host.eq_ignore_ascii_case(&self.host)
            || item.kind != self.kind
            || item.mcp_server != self.mcp_server
            || item.mcp_tool != self.mcp_tool
            || item.args_hash != self.args_hash
            || item.ref_name != self.ref_name
        {
            return false;
        }
        let same_method = item.method.eq_ignore_ascii_case(&self.method);
        let concrete = self.effective_concrete_path();
        match item.effective_grant_scope() {
            GrantScope::Once => false,
            GrantScope::ExactPath => {
                same_method && item.concrete_path.as_deref().unwrap_or(&item.path) == concrete
            }
            GrantScope::ReadOnlyPrefix => {
                self.method.eq_ignore_ascii_case("GET")
                    && item.method.eq_ignore_ascii_case("GET")
                    && path_matches_prefix(concrete, &item.path)
            }
            GrantScope::ExactScope => {
                same_method && item.path == self.path && path_matches_prefix(concrete, &item.path)
            }
        }
    }
}

/// Lifecycle state of an interactive JIT capability approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Outcome of waiting asynchronously on an [`ApprovalHub`] for a JIT capability decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalWaitOutcome {
    Approved { ttl_secs: u64, reused_grant: bool },
    Denied,
    TimedOut,
}

/// Serializable pending or decided JIT approval visible in Premier Studio.
///
/// `expires_at` is the knock timeout while pending, and the grant expiry once approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub var_name: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub ttl_secs: u64,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concrete_path: Option<String>,
    #[serde(default)]
    pub risk_level: RiskLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_preview: Option<WirePreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_scope: Option<GrantScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

impl PendingApproval {
    fn from_request(id: String, req: ApprovalRequest, now: DateTime<Utc>) -> Self {
        Self {
            id,
            principal: req.principal,
            agent_profile: req.agent_profile,
            var_name: req.var_name,
            host: req.host,
            method: req.method,
            path: req.path,
            ttl_secs: req.ttl_secs.min(MAX_JIT_TTL_SECS),
            status: ApprovalStatus::Pending,
            created_at: now,
            decided_at: None,
            kind: req.kind,
            mcp_server: req.mcp_server,
            mcp_tool: req.mcp_tool,
            risk: req.risk,
            args_summary: req.args_summary,
            args_hash: req.args_hash,
            ref_name: req.ref_name,
            expires_at: req.expires_at,
            concrete_path: req.concrete_path,
            risk_level: req.risk_level,
            intent_summary: req.intent_summary,
            wire_preview: req.wire_preview,
            session_context: req.session_context,
            sensitivity: req.sensitivity,
            grant_scope: None,
            denial_reason: None,
        }
    }

    /// Grants decided before scopes existed: TTL 0 was "once", anything else the full scope.
    fn effective_grant_scope(&self) -> GrantScope {
        self.grant_scope.unwrap_or(if self.ttl_secs == 0 {
            GrantScope::Once
        } else {
            GrantScope::ExactScope
        })
    }
}

/// Async hub enabling 1-click browser/UI JIT capability approval over SSE + REST.
pub struct ApprovalHub {
    seq: AtomicU64,
    items: Mutex<Vec<PendingApproval>>,
    waiters: Mutex<HashMap<String, oneshot::Sender<GateOutcome>>>,
    tx: broadcast::Sender<PendingApproval>,
    wait_timeout: Duration,
}

impl Default for ApprovalHub {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(128);
        Self {
            seq: AtomicU64::new(1),
            items: Mutex::new(Vec::new()),
            waiters: Mutex::new(HashMap::new()),
            tx,
            wait_timeout: DEFAULT_APPROVAL_TIMEOUT,
        }
    }

    /// Override the maximum time [`HubGate`] waits for an interactive approval decision.
    pub fn with_wait_timeout(mut self, timeout: Duration) -> Self {
        self.wait_timeout = timeout;
        self
    }

    /// Enqueue a new JIT approval request and return `(approval_record, decision_receiver)`.
    /// The knock expires [`PENDING_APPROVAL_TIMEOUT_SECS`] after it is created.
    pub fn enqueue(
        &self,
        req: ApprovalRequest,
    ) -> (PendingApproval, oneshot::Receiver<GateOutcome>) {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("jit-{n:04}");
        let now = Utc::now();
        let mut record = PendingApproval::from_request(id.clone(), req, now);
        record.expires_at = Some(now + timeout_delta(self.wait_timeout));
        let (tx_one, rx_one) = oneshot::channel();
        let evicted_id = if let Ok(mut items) = self.items.lock() {
            let evicted = if items.len() >= 128 {
                Some(items.remove(0).id)
            } else {
                None
            };
            items.push(record.clone());
            evicted
        } else {
            None
        };
        if let Ok(mut waiters) = self.waiters.lock() {
            if let Some(evicted) = evicted_id {
                // Dropping the evicted sender unblocks any waiting thread immediately with `false`.
                waiters.remove(&evicted);
            }
            waiters.insert(id, tx_one);
        }
        let _ = self.tx.send(record.clone());
        (record, rx_one)
    }

    /// Resolve a pending JIT approval by `id`. Returns the updated record if found.
    pub fn decide(
        &self,
        id: &str,
        approved: bool,
        ttl_override: Option<u64>,
    ) -> Option<PendingApproval> {
        self.decide_with_options(
            id,
            ApprovalDecision {
                approved,
                ttl_secs: ttl_override,
                ..ApprovalDecision::default()
            },
        )
        .ok()
        .flatten()
        .map(|(item, _)| item)
    }

    /// Resolve a pending knock. `Ok(None)`: unknown id. `Ok(Some((record, false)))`: it was
    /// already decided or expired, nothing changed. `Err`: the decision itself is invalid.
    pub fn decide_with_options(
        &self,
        id: &str,
        decision: ApprovalDecision,
    ) -> Result<Option<(PendingApproval, bool)>, String> {
        let (updated, outcome) = {
            let Ok(mut items) = self.items.lock() else {
                return Ok(None);
            };
            let Some(item) = items.iter_mut().find(|i| i.id == id) else {
                return Ok(None);
            };
            if decision.approved
                && decision.grant_scope == Some(GrantScope::ReadOnlyPrefix)
                && !item.method.eq_ignore_ascii_case("GET")
            {
                return Err(
                    "read_only_prefix grant scope is only valid for GET requests".to_owned(),
                );
            }
            if item.status != ApprovalStatus::Pending {
                return Ok(Some((item.clone(), false)));
            }
            let now = Utc::now();
            let outcome = if decision.approved {
                let mut ttl = decision
                    .ttl_secs
                    .unwrap_or(item.ttl_secs)
                    .min(MAX_JIT_TTL_SECS);
                let scope = decision.grant_scope.unwrap_or(if ttl == 0 {
                    GrantScope::Once
                } else {
                    GrantScope::ExactScope
                });
                if scope == GrantScope::Once {
                    ttl = 0;
                }
                item.status = ApprovalStatus::Approved;
                item.ttl_secs = ttl;
                item.grant_scope = Some(scope);
                item.denial_reason = None;
                GateOutcome::Approved {
                    ttl_secs: ttl,
                    grant_scope: scope,
                }
            } else {
                item.status = ApprovalStatus::Denied;
                item.ttl_secs = 0;
                item.grant_scope = None;
                item.denial_reason = sanitize_denial_reason(decision.denial_reason);
                GateOutcome::Denied {
                    reason: item.denial_reason.clone(),
                }
            };
            item.decided_at = Some(now);
            item.expires_at = (item.status == ApprovalStatus::Approved && item.ttl_secs > 0)
                .then(|| i64::try_from(item.ttl_secs).ok())
                .flatten()
                .map(|ttl| now + chrono::Duration::seconds(ttl));
            (item.clone(), outcome)
        };
        let _ = self.tx.send(updated.clone());
        self.deliver(id, outcome);
        Ok(Some((updated, true)))
    }

    /// Expire a knock nobody answered in time. Returns the current record if found; it is
    /// `Expired` only when it was still pending.
    pub fn expire_pending(&self, id: &str) -> Option<PendingApproval> {
        let updated = {
            let mut items = self.items.lock().ok()?;
            let Some(item) = items.iter_mut().find(|i| i.id == id) else {
                // Evicted from the ring while pending: still drop its waiter so it cannot leak.
                drop(items);
                self.deliver(id, GateOutcome::Denied { reason: None });
                return None;
            };
            if item.status != ApprovalStatus::Pending {
                return Some(item.clone());
            }
            item.status = ApprovalStatus::Expired;
            item.expires_at = None;
            item.decided_at = Some(Utc::now());
            item.clone()
        };
        self.deliver(
            id,
            GateOutcome::Denied {
                reason: Some(TIMED_OUT.to_owned()),
            },
        );
        let _ = self.tx.send(updated.clone());
        Some(updated)
    }

    fn deliver(&self, id: &str, outcome: GateOutcome) {
        if let Ok(mut waiters) = self.waiters.lock()
            && let Some(sender) = waiters.remove(id)
        {
            let _ = sender.send(outcome);
        }
    }

    /// Mark a still-pending JIT approval as [`ApprovalStatus::Expired`] by `id`.
    /// Returns the updated (or already-decided) record if found.
    pub fn expire(&self, id: &str) -> Option<PendingApproval> {
        self.expire_pending(id)
    }

    /// Wait up to `timeout` for a JIT approval decision, optionally reusing a live grant for the
    /// same scope. Marks the pending request [`ApprovalStatus::Expired`] if `timeout` elapses.
    pub async fn request_and_wait(
        &self,
        req: ApprovalRequest,
        timeout: Duration,
        allow_reuse: bool,
    ) -> ApprovalWaitOutcome {
        if allow_reuse && let Some(left) = self.grant_secs_left(&req) {
            return ApprovalWaitOutcome::Approved {
                ttl_secs: left,
                reused_grant: true,
            };
        }

        let (pending, rx) = self.enqueue(req);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(GateOutcome::Approved { ttl_secs, .. })) => ApprovalWaitOutcome::Approved {
                ttl_secs,
                reused_grant: false,
            },
            Ok(Ok(GateOutcome::Denied { .. })) | Ok(Err(_)) => ApprovalWaitOutcome::Denied,
            Err(_elapsed) => {
                self.expire_pending(&pending.id);
                ApprovalWaitOutcome::TimedOut
            }
        }
    }

    /// Revoke everything held by a principal or agent profile: pending requests are denied (their
    /// waiters get `false`) and live approved grants expire. Returns how many records changed.
    pub fn revoke_principal(&self, target: &str) -> usize {
        let now = Utc::now();
        let mut changed = Vec::new();
        if let Ok(mut items) = self.items.lock() {
            for item in items
                .iter_mut()
                .filter(|i| i.principal == target || i.agent_profile.as_deref() == Some(target))
            {
                match item.status {
                    ApprovalStatus::Pending => {
                        item.status = ApprovalStatus::Denied;
                        item.decided_at = Some(now);
                    }
                    ApprovalStatus::Approved if grant_live(item, now) => {
                        item.status = ApprovalStatus::Expired;
                    }
                    _ => continue,
                }
                changed.push(item.clone());
            }
        }
        for item in &changed {
            if item.status == ApprovalStatus::Denied
                && let Ok(mut waiters) = self.waiters.lock()
                && let Some(sender) = waiters.remove(&item.id)
            {
                let _ = sender.send(GateOutcome::Denied { reason: None });
            }
            let _ = self.tx.send(item.clone());
        }
        changed.len()
    }

    /// Snapshot all tracked approval requests (newest first).
    pub fn list(&self) -> Vec<PendingApproval> {
        self.items
            .lock()
            .map(|g| {
                let mut v = g.clone();
                v.reverse();
                v
            })
            .unwrap_or_default()
    }

    /// Subscribe to real-time approval requests and decisions.
    pub fn subscribe(&self) -> broadcast::Receiver<PendingApproval> {
        self.tx.subscribe()
    }

    /// True while an approved grant covering `req` (see [`ApprovalRequest::covered_by`]) is
    /// inside its TTL. It never unlocks anything else.
    pub fn has_grant(&self, req: &ApprovalRequest) -> bool {
        self.grant_for(req).is_some()
    }

    /// Seconds a live grant covering `req` still has, if there is one.
    pub fn grant_secs_left(&self, req: &ApprovalRequest) -> Option<u64> {
        self.grant_for(req).map(|(secs, _)| secs)
    }

    /// The longest-lived grant covering `req`: `(seconds left, its scope)`.
    pub fn grant_for(&self, req: &ApprovalRequest) -> Option<(u64, GrantScope)> {
        let now = Utc::now();
        self.items
            .lock()
            .ok()?
            .iter()
            .filter(|i| req.covered_by(i))
            .filter_map(|i| secs_left(i, now).map(|s| (s, i.effective_grant_scope())))
            .max_by_key(|(s, _)| *s)
    }

    /// Everything a restart would lose. The caller owns persistence (this crate does no file I/O).
    pub fn snapshot(&self) -> ApprovalSnapshot {
        ApprovalSnapshot {
            next_seq: self.seq.load(Ordering::Relaxed),
            items: self.items.lock().map(|g| g.clone()).unwrap_or_default(),
        }
    }

    /// Replace the hub's records with a persisted snapshot. Approved records whose TTL has lapsed
    /// come back `Expired`, so a stale grant can never be honoured after a restart.
    pub fn restore(&self, mut snap: ApprovalSnapshot) {
        let now = Utc::now();
        for item in &mut snap.items {
            if item.status == ApprovalStatus::Approved && !grant_live(item, now) {
                item.status = ApprovalStatus::Expired;
            }
        }
        self.seq.fetch_max(snap.next_seq, Ordering::Relaxed);
        if let Ok(mut items) = self.items.lock() {
            *items = snap.items;
        }
    }
}

fn timeout_delta(wait: Duration) -> chrono::Duration {
    chrono::Duration::from_std(wait)
        .unwrap_or_else(|_| chrono::Duration::seconds(PENDING_APPROVAL_TIMEOUT_SECS as i64))
}

fn grant_live(item: &PendingApproval, now: DateTime<Utc>) -> bool {
    secs_left(item, now).is_some()
}

fn secs_left(item: &PendingApproval, now: DateTime<Utc>) -> Option<u64> {
    if item.status != ApprovalStatus::Approved {
        return None;
    }
    let ttl = i64::try_from(item.ttl_secs.min(MAX_JIT_TTL_SECS)).ok()?;
    let expiry = item
        .decided_at?
        .checked_add_signed(chrono::Duration::seconds(ttl))?;
    u64::try_from((expiry - now).num_milliseconds())
        .ok()
        .filter(|ms| *ms > 0)
        .map(|ms| ms.div_ceil(1000))
}

/// Serializable copy of an [`ApprovalHub`]'s records, for persistence across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    pub next_seq: u64,
    pub items: Vec<PendingApproval>,
}

/// Pluggable approval gate (TTY prompt, callback/UI, auto-approve, or deny-all).
pub trait ApprovalGate: Send + Sync {
    fn prompt(&self, req: &ApprovalRequest) -> bool;

    /// Like [`prompt`](Self::prompt), returning the TTL (seconds) the approver granted, or
    /// `None` when denied. Gates with no notion of an approver TTL grant the requested one.
    fn prompt_ttl(&self, req: &ApprovalRequest) -> Option<u64> {
        self.prompt(req).then_some(req.ttl_secs)
    }

    /// Full decision: TTL, grant scope, or a denial reason. Defaults to [`prompt_ttl`]
    /// (TTL 0 approves this request only; anything else grants the legacy exact scope).
    ///
    /// [`prompt_ttl`]: Self::prompt_ttl
    fn prompt_decision(&self, req: &ApprovalRequest) -> GateOutcome {
        match self.prompt_ttl(req) {
            Some(ttl_secs) => GateOutcome::Approved {
                ttl_secs,
                grant_scope: if ttl_secs == 0 {
                    GrantScope::Once
                } else {
                    GrantScope::ExactScope
                },
            },
            None => GateOutcome::Denied { reason: None },
        }
    }
}

/// Gate backed by an [`ApprovalHub`]: reuses a live grant covering the request, otherwise
/// queues a knock for a human and blocks until it is decided or times out. Honours the
/// approver's TTL and scope. Must be called from a multi-threaded tokio runtime.
pub struct HubGate(pub Arc<ApprovalHub>);

impl HubGate {
    /// [`prompt_decision`](ApprovalGate::prompt_decision) with an explicit knock timeout.
    pub fn prompt_decision_with_timeout(
        &self,
        req: &ApprovalRequest,
        timeout: Duration,
    ) -> GateOutcome {
        if let Some((ttl_secs, grant_scope)) = self.0.grant_for(req) {
            return GateOutcome::Approved {
                ttl_secs,
                grant_scope,
            };
        }
        let (pending, mut rx) = self.0.enqueue(req.clone());
        let waited = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(tokio::time::timeout(timeout, &mut rx))
            }),
            Err(_) => {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                else {
                    self.0.expire_pending(&pending.id);
                    return GateOutcome::Denied { reason: None };
                };
                rt.block_on(tokio::time::timeout(timeout, &mut rx))
            }
        };
        match waited {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => GateOutcome::Denied { reason: None },
            Err(_) => {
                // A decision can land between the timeout firing and the expiry; honour it.
                let expired = self
                    .0
                    .expire_pending(&pending.id)
                    .is_none_or(|i| i.status == ApprovalStatus::Expired);
                match rx.try_recv() {
                    Ok(outcome) if !expired => outcome,
                    _ => GateOutcome::Denied {
                        reason: Some(TIMED_OUT.to_owned()),
                    },
                }
            }
        }
    }
}

impl ApprovalGate for HubGate {
    fn prompt(&self, req: &ApprovalRequest) -> bool {
        matches!(self.prompt_decision(req), GateOutcome::Approved { .. })
    }

    fn prompt_ttl(&self, req: &ApprovalRequest) -> Option<u64> {
        match self.prompt_decision(req) {
            GateOutcome::Approved { ttl_secs, .. } => Some(ttl_secs),
            GateOutcome::Denied { .. } => None,
        }
    }

    fn prompt_decision(&self, req: &ApprovalRequest) -> GateOutcome {
        self.prompt_decision_with_timeout(req, self.0.wait_timeout)
    }
}

/// Always approves JIT prompts (for non-interactive tests).
#[derive(Debug, Default)]
pub struct AutoApproveGate;

impl ApprovalGate for AutoApproveGate {
    fn prompt(&self, _req: &ApprovalRequest) -> bool {
        true
    }
}

/// Always denies JIT prompts (default for headless CI unless explicitly granted).
#[derive(Debug, Default)]
pub struct DenyJitGate;

impl ApprovalGate for DenyJitGate {
    fn prompt(&self, _req: &ApprovalRequest) -> bool {
        false
    }
}

/// Terminal interactive y/N prompt scoped to one capability and TTL.
#[derive(Debug, Default)]
pub struct InteractiveTtyGate;

impl ApprovalGate for InteractiveTtyGate {
    fn prompt(&self, req: &ApprovalRequest) -> bool {
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "\n[Premier JIT Approval] principal={} agent={} requests USE of {} -> {} {} {} (TTL {}s). Approve? [y/N]: ",
            req.principal,
            req.agent_profile.as_deref().unwrap_or("none"),
            req.var_name,
            req.method,
            req.host,
            req.effective_concrete_path(),
            req.ttl_secs
        );
        let _ = stderr.flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_ok() {
            matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        } else {
            false
        }
    }
}

/// Closure-backed gate for tests or UI integration.
pub struct CallbackGate<F>(pub F)
where
    F: Fn(&ApprovalRequest) -> bool + Send + Sync;

impl<F> ApprovalGate for CallbackGate<F>
where
    F: Fn(&ApprovalRequest) -> bool + Send + Sync,
{
    fn prompt(&self, req: &ApprovalRequest) -> bool {
        (self.0)(req)
    }
}

/// An approved, cacheable grant: the decided record plus its monotonic expiry.
struct CachedGrant {
    record: PendingApproval,
    expires: Instant,
}

/// Scoped TTL cache wrapping an `ApprovalGate`. Applies the same [`GrantScope`] rules as
/// [`ApprovalHub`]; `Once` and zero-TTL approvals are never cached.
pub struct ApprovalManager {
    gate: Box<dyn ApprovalGate>,
    grants: Mutex<Vec<CachedGrant>>,
}

impl ApprovalManager {
    pub fn new(gate: Box<dyn ApprovalGate>) -> Self {
        Self {
            gate,
            grants: Mutex::new(Vec::new()),
        }
    }

    /// Drop every cached grant held by a principal or agent profile. Returns how many were dropped.
    pub fn revoke_principal(&self, target: &str) -> usize {
        let Ok(mut guard) = self.grants.lock() else {
            return 0;
        };
        let before = guard.len();
        guard.retain(|g| {
            g.record.principal != target && g.record.agent_profile.as_deref() != Some(target)
        });
        before - guard.len()
    }

    /// Reuse a live grant for exactly this scope, or invoke the `ApprovalGate`. `path_prefix` is
    /// the schema prefix that authorised the request; the approver sees it and the grant covers
    /// it, nothing wider.
    pub fn authorize(
        &self,
        identity: &DelegatedIdentity,
        var_name: &str,
        host: &str,
        method: &str,
        path_prefix: &str,
        ttl_secs: u64,
    ) -> bool {
        self.authorize_request(ApprovalRequest {
            principal: identity.principal.canonical_id(),
            agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
            var_name: var_name.to_owned(),
            host: host.to_owned(),
            method: method.to_owned(),
            path: path_prefix.to_owned(),
            ttl_secs,
            ..ApprovalRequest::default()
        })
        .is_ok()
    }

    /// Reuse a live cached grant covering `req`, or ask the gate. `Err` carries the approver's
    /// (sanitized) denial reason, if any.
    pub fn authorize_request(&self, mut req: ApprovalRequest) -> Result<(), Option<String>> {
        req.host = req.host.to_ascii_lowercase();
        req.method = req.method.to_ascii_uppercase();
        req.ttl_secs = req.ttl_secs.min(MAX_JIT_TTL_SECS);

        if let Ok(mut guard) = self.grants.lock() {
            let now = Instant::now();
            guard.retain(|g| g.expires > now);
            if guard.iter().any(|g| req.covered_by(&g.record)) {
                return Ok(());
            }
        }

        match self.gate.prompt_decision(&req) {
            GateOutcome::Denied { reason } => Err(sanitize_denial_reason(reason)),
            GateOutcome::Approved {
                ttl_secs,
                grant_scope,
            } => {
                // The approver's TTL wins over the schema default; zero approves this request only.
                let ttl = ttl_secs.min(MAX_JIT_TTL_SECS);
                if ttl > 0
                    && grant_scope != GrantScope::Once
                    && let Ok(mut guard) = self.grants.lock()
                {
                    let mut record = PendingApproval::from_request(String::new(), req, Utc::now());
                    record.status = ApprovalStatus::Approved;
                    record.ttl_secs = ttl;
                    record.grant_scope = Some(grant_scope);
                    guard.push(CachedGrant {
                        record,
                        expires: Instant::now() + Duration::from_secs(ttl),
                    });
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn req(var: &str) -> ApprovalRequest {
        ApprovalRequest {
            principal: "user:alice".to_owned(),
            agent_profile: Some("ui-agent".to_owned()),
            var_name: var.to_owned(),
            host: "api.example.com".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            ttl_secs: 300,
            ..ApprovalRequest::default()
        }
    }

    /// A request for `method` on `concrete`, authorised by schema prefix `/v1/`.
    fn at(method: &str, concrete: &str) -> ApprovalRequest {
        ApprovalRequest {
            method: method.to_owned(),
            path: "/v1/".to_owned(),
            concrete_path: Some(concrete.to_owned()),
            ..req("KEY")
        }
    }

    fn mcp_req(server: &str, tool: &str) -> ApprovalRequest {
        ApprovalRequest {
            principal: "user:alice".to_owned(),
            agent_profile: Some("ui-agent".to_owned()),
            var_name: "GITHUB_TOKEN".to_owned(),
            host: "api.github.com".to_owned(),
            method: "POST".to_owned(),
            path: "/mcp".to_owned(),
            ttl_secs: 300,
            kind: Some("mcp_tool".to_owned()),
            mcp_server: Some(server.to_owned()),
            mcp_tool: Some(tool.to_owned()),
            risk: Some("write".to_owned()),
            args_summary: Some("repo=acme/app".to_owned()),
            args_hash: Some("hash-1".to_owned()),
            ref_name: Some("main".to_owned()),
            ..ApprovalRequest::default()
        }
    }

    fn alice_agent() -> DelegatedIdentity {
        DelegatedIdentity::delegated(
            premier_core::Principal::User("alice".to_owned()),
            vec![],
            "ui-agent",
            "task-1",
        )
    }

    #[test]
    fn jit_grant_is_scoped_to_what_was_approved() {
        let prompts = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&prompts);
        let mgr = ApprovalManager::new(Box::new(CallbackGate(move |_req: &ApprovalRequest| {
            seen.fetch_add(1, Ordering::Relaxed);
            true
        })));
        let id = alice_agent();
        let ask = |id: &DelegatedIdentity, var: &str, host: &str, method: &str, prefix: &str| {
            assert!(mgr.authorize(id, var, host, method, prefix, 300));
            prompts.load(Ordering::Relaxed)
        };

        assert_eq!(ask(&id, "KEY", "api.example.com", "GET", "/v1/"), 1);
        // Same scope: served from the grant, no new prompt.
        assert_eq!(ask(&id, "KEY", "API.example.com", "get", "/v1/"), 1);
        // Anything the approver was not shown needs its own approval.
        assert_eq!(ask(&id, "KEY", "api.example.com", "DELETE", "/v1/"), 2);
        assert_eq!(ask(&id, "KEY", "api.example.com", "GET", "/admin/"), 3);
        assert_eq!(ask(&id, "KEY", "other.example.com", "GET", "/v1/"), 4);
        assert_eq!(ask(&id, "OTHER", "api.example.com", "GET", "/v1/"), 5);
        let other_profile = DelegatedIdentity::delegated(
            premier_core::Principal::User("alice".to_owned()),
            vec![],
            "deploy-agent",
            "task-1",
        );
        assert_eq!(
            ask(&other_profile, "KEY", "api.example.com", "GET", "/v1/"),
            6
        );

        // The hub applies the same scope.
        let hub = ApprovalHub::new();
        let (item, _rx) = hub.enqueue(req("KEY"));
        hub.decide(&item.id, true, None);
        assert!(hub.has_grant(&req("KEY")));
        for widened in [
            ApprovalRequest {
                method: "DELETE".to_owned(),
                ..req("KEY")
            },
            ApprovalRequest {
                path: "/admin/".to_owned(),
                ..req("KEY")
            },
            ApprovalRequest {
                host: "evil.example".to_owned(),
                ..req("KEY")
            },
        ] {
            assert!(!hub.has_grant(&widened));
        }
    }

    /// Approve `knock` on a fresh hub with `scope`, then report which probes it covers.
    fn covered(knock: ApprovalRequest, scope: GrantScope, probes: &[ApprovalRequest]) -> Vec<bool> {
        let hub = ApprovalHub::new();
        let (item, _rx) = hub.enqueue(knock);
        let (decided, changed) = hub
            .decide_with_options(
                &item.id,
                ApprovalDecision {
                    approved: true,
                    ttl_secs: Some(600),
                    grant_scope: Some(scope),
                    denial_reason: None,
                },
            )
            .unwrap()
            .unwrap();
        assert!(changed);
        assert_eq!(decided.grant_scope, Some(scope));
        probes.iter().map(|p| hub.has_grant(p)).collect()
    }

    #[test]
    fn grant_scopes_cover_exactly_what_they_name() {
        let probes = [
            at("GET", "/v1/charges/ch_1"),   // the knock itself
            at("GET", "/v1/charges/ch_2"),   // sibling under the prefix
            at("POST", "/v1/charges/ch_1"),  // other method, same path
            at("GET", "/v1/charges/ch_1/x"), // deeper path
            ApprovalRequest {
                path: "/v2/".to_owned(),
                ..at("GET", "/v2/charges/ch_1")
            }, // other prefix
            at("GET", "/v1/../v2/admin"),    // traversal
            ApprovalRequest {
                var_name: "OTHER".to_owned(),
                ..at("GET", "/v1/charges/ch_1")
            },
        ];
        let knock = at("GET", "/v1/charges/ch_1");

        // Once: approves the knock only, never reusable even with a TTL.
        assert_eq!(
            covered(knock.clone(), GrantScope::Once, &probes),
            [false; 7]
        );
        // ExactPath: same method, exact concrete path.
        assert_eq!(
            covered(knock.clone(), GrantScope::ExactPath, &probes),
            [true, false, false, false, false, false, false]
        );
        // ReadOnlyPrefix: any GET under the prefix, never another method or prefix.
        assert_eq!(
            covered(knock.clone(), GrantScope::ReadOnlyPrefix, &probes),
            [true, true, false, true, false, false, false]
        );
        // ExactScope: same method and schema prefix.
        assert_eq!(
            covered(knock.clone(), GrantScope::ExactScope, &probes),
            [true, true, false, true, false, false, false]
        );
        // ExactScope on a POST knock keeps the method exact; it never covers GETs.
        let post = at("POST", "/v1/charges");
        assert_eq!(
            covered(
                post.clone(),
                GrantScope::ExactScope,
                &[post.clone(), at("GET", "/v1/charges")]
            ),
            [true, false]
        );
    }

    #[test]
    fn read_only_prefix_is_rejected_for_mutations_and_denials_record_a_clean_reason() {
        let hub = ApprovalHub::new();
        let (post, _rx) = hub.enqueue(at("POST", "/v1/charges"));
        let err = hub
            .decide_with_options(
                &post.id,
                ApprovalDecision {
                    approved: true,
                    grant_scope: Some(GrantScope::ReadOnlyPrefix),
                    ..ApprovalDecision::default()
                },
            )
            .unwrap_err();
        assert!(err.contains("only valid for GET"));
        // Still pending: the invalid decision changed nothing.
        assert_eq!(hub.list()[0].status, ApprovalStatus::Pending);

        let (decided, changed) = hub
            .decide_with_options(
                &post.id,
                ApprovalDecision {
                    approved: false,
                    ttl_secs: Some(600),
                    grant_scope: Some(GrantScope::ExactScope),
                    denial_reason: Some(format!("  use the test key\u{7}\n{}", "x".repeat(400))),
                },
            )
            .unwrap()
            .unwrap();
        assert!(changed);
        assert_eq!(decided.status, ApprovalStatus::Denied);
        assert_eq!(decided.grant_scope, None);
        assert_eq!(decided.ttl_secs, 0);
        assert_eq!(decided.expires_at, None);
        let reason = decided.denial_reason.unwrap();
        assert!(reason.starts_with("use the test key"));
        assert!(!reason.chars().any(char::is_control));
        assert_eq!(reason.chars().count(), 240);
        // Deciding again is a no-op.
        let (_, changed) = hub
            .decide_with_options(&post.id, ApprovalDecision::default())
            .unwrap()
            .unwrap();
        assert!(!changed);
        assert!(
            hub.decide_with_options("nope", ApprovalDecision::default())
                .unwrap()
                .is_none()
        );

        // A blank reason is no reason.
        let (get, _rx) = hub.enqueue(at("GET", "/v1/charges"));
        let (decided, _) = hub
            .decide_with_options(
                &get.id,
                ApprovalDecision {
                    denial_reason: Some(" \t ".to_owned()),
                    ..ApprovalDecision::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(decided.denial_reason, None);
    }

    #[test]
    fn once_forces_zero_ttl_and_grants_expire() {
        let hub = ApprovalHub::new();
        let (item, _rx) = hub.enqueue(at("GET", "/v1/a"));
        assert!(item.expires_at.unwrap() > item.created_at);
        let (once, _) = hub
            .decide_with_options(
                &item.id,
                ApprovalDecision {
                    approved: true,
                    ttl_secs: Some(600),
                    grant_scope: Some(GrantScope::Once),
                    denial_reason: None,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(once.ttl_secs, 0);
        assert_eq!(once.expires_at, None);

        let (item, _rx) = hub.enqueue(at("GET", "/v1/b"));
        let decided = hub.decide(&item.id, true, Some(60)).unwrap();
        assert_eq!(decided.grant_scope, Some(GrantScope::ExactScope));
        let expiry = decided.expires_at.unwrap() - decided.decided_at.unwrap();
        assert_eq!(expiry.num_seconds(), 60);
        assert!(hub.has_grant(&at("GET", "/v1/b")));

        // Wind the decision back past its TTL: the grant is gone.
        let mut snap = hub.snapshot();
        for i in &mut snap.items {
            i.decided_at = i.decided_at.map(|d| d - chrono::Duration::seconds(61));
        }
        hub.restore(snap);
        assert!(!hub.has_grant(&at("GET", "/v1/b")));
    }

    struct ScopedGate(GateOutcome, Arc<AtomicU64>);
    impl ApprovalGate for ScopedGate {
        fn prompt(&self, _req: &ApprovalRequest) -> bool {
            unreachable!()
        }
        fn prompt_decision(&self, _req: &ApprovalRequest) -> GateOutcome {
            self.1.fetch_add(1, Ordering::Relaxed);
            self.0.clone()
        }
    }

    #[test]
    fn manager_caches_grants_with_the_same_scope_rules_as_the_hub() {
        let run = |outcome: GateOutcome, knock: ApprovalRequest, probe: ApprovalRequest| {
            let prompts = Arc::new(AtomicU64::new(0));
            let mgr = ApprovalManager::new(Box::new(ScopedGate(outcome, Arc::clone(&prompts))));
            let first = mgr.authorize_request(knock);
            let second = mgr.authorize_request(probe);
            (first, second, prompts.load(Ordering::Relaxed))
        };
        let approve = |scope| GateOutcome::Approved {
            ttl_secs: 600,
            grant_scope: scope,
        };
        // Covered probes are served from the cache (1 prompt), others ask again (2 prompts).
        let knock = at("GET", "/v1/charges/ch_1");
        for (scope, probe, prompts) in [
            (GrantScope::Once, knock.clone(), 2),
            (GrantScope::ExactPath, knock.clone(), 1),
            (GrantScope::ExactPath, at("GET", "/v1/charges/ch_2"), 2),
            (GrantScope::ReadOnlyPrefix, at("GET", "/v1/customers"), 1),
            (
                GrantScope::ReadOnlyPrefix,
                at("POST", "/v1/charges/ch_1"),
                2,
            ),
            (GrantScope::ExactScope, at("GET", "/v1/customers"), 1),
            (GrantScope::ExactScope, at("DELETE", "/v1/customers"), 2),
        ] {
            assert_eq!(
                run(approve(scope), knock.clone(), probe.clone()).2,
                prompts,
                "{scope:?} {probe:?}"
            );
        }
        // Zero TTL is never cached either.
        let zero = GateOutcome::Approved {
            ttl_secs: 0,
            grant_scope: GrantScope::ExactScope,
        };
        assert_eq!(run(zero, knock.clone(), knock.clone()).2, 2);
        // Denials carry the approver's reason through.
        let deny = GateOutcome::Denied {
            reason: Some("not on prod\u{1b}[31m".to_owned()),
        };
        let (first, _, _) = run(deny, knock.clone(), knock);
        assert_eq!(first, Err(Some("not on prod[31m".to_owned())));
    }

    #[test]
    fn risk_and_intent_are_deterministic() {
        use Sensitivity::{Restricted, Secret};
        assert!(is_read_only_method("get") && is_read_only_method("HEAD"));
        assert!(!is_read_only_method("POST"));
        assert!(is_sensitive_path("/v1/Charges/ch_1"));
        assert!(is_sensitive_path("/env/prod-eu/deploy"));
        assert!(!is_sensitive_path("/v1/products"));
        assert!(!is_sensitive_path("/v1/customers"));

        assert_eq!(
            classify_risk("GET", "/v1/customers", Restricted),
            RiskLevel::SensitiveScope
        );
        assert_eq!(
            classify_risk("GET", "/v1/customers", Secret),
            RiskLevel::ReadOnly
        );
        assert_eq!(
            classify_risk("GET", "/v1/charges", Secret),
            RiskLevel::ReadOnly
        );
        assert_eq!(
            classify_risk("GET", "/v1/api_keys/keys", Secret),
            RiskLevel::SensitiveScope
        );
        assert_eq!(
            classify_risk("POST", "/v1/charges", Secret),
            RiskLevel::SensitiveScope
        );
        assert_eq!(
            classify_risk("POST", "/v1/customers", Secret),
            RiskLevel::StateMutation
        );

        let s = |m, p, r| synthesize_intent_summary(m, "api.stripe.com", p, r);
        assert_eq!(
            s("get", "/v1/keys", RiskLevel::SensitiveScope),
            "Sensitive read (GET) on restricted scope api.stripe.com/v1/keys"
        );
        assert_eq!(
            s("POST", "/v1/charges", RiskLevel::SensitiveScope),
            "Sensitive mutation (POST) on api.stripe.com/v1/charges"
        );
        assert_eq!(
            s("GET", "/v1/customers", RiskLevel::ReadOnly),
            "Read-only check against api.stripe.com/v1/customers"
        );
        assert_eq!(
            s("delete", "/v1/customers/c", RiskLevel::StateMutation),
            "Destructive delete (DELETE) on api.stripe.com/v1/customers/c"
        );
        assert_eq!(
            s("PATCH", "/v1/customers/c", RiskLevel::StateMutation),
            "Write mutation (PATCH) to api.stripe.com/v1/customers/c"
        );
    }

    #[test]
    fn legacy_snapshots_still_deserialize() {
        let legacy = r#"{"next_seq":3,"items":[{"id":"jit-0001","principal":"user:alice",
            "var_name":"KEY","host":"api.example.com","method":"GET","path":"/","ttl_secs":300,
            "status":"approved","created_at":"2026-01-01T00:00:00Z",
            "decided_at":"2026-01-01T00:00:01Z"}]}"#;
        let snap: ApprovalSnapshot = serde_json::from_str(legacy).unwrap();
        let item = &snap.items[0];
        assert_eq!(item.risk_level, RiskLevel::StateMutation);
        assert_eq!(item.grant_scope, None);
        assert_eq!(item.effective_grant_scope(), GrantScope::ExactScope);
        // New optional fields stay out of the JSON when unset.
        let json = serde_json::to_string(item).unwrap();
        assert!(!json.contains("wire_preview") && !json.contains("denial_reason"));
    }

    struct TtlGate(u64);
    impl ApprovalGate for TtlGate {
        fn prompt(&self, _req: &ApprovalRequest) -> bool {
            true
        }
        fn prompt_ttl(&self, _req: &ApprovalRequest) -> Option<u64> {
            Some(self.0)
        }
    }

    #[test]
    fn approver_ttl_is_honoured_and_huge_ttls_are_clamped() {
        let id = alice_agent();
        let cached =
            |mgr: &ApprovalManager| mgr.grants.lock().map(|g| g.len()).unwrap_or(usize::MAX);

        // The approver granted this one request only: nothing is cached despite a 300 s default.
        let once = ApprovalManager::new(Box::new(TtlGate(0)));
        assert!(once.authorize(&id, "KEY", "h", "GET", "/", 300));
        assert_eq!(cached(&once), 0);

        // A huge TTL (schema or approver) neither panics nor poisons the lock.
        let huge = ApprovalManager::new(Box::new(TtlGate(u64::MAX)));
        assert!(huge.authorize(&id, "KEY", "h", "GET", "/", u64::MAX));
        assert!(huge.authorize(&id, "KEY", "h", "GET", "/", u64::MAX));
        assert_eq!(cached(&huge), 1);

        let hub = Arc::new(ApprovalHub::new());
        let (item, _rx) = hub.enqueue(ApprovalRequest {
            ttl_secs: u64::MAX,
            ..req("KEY")
        });
        assert_eq!(item.ttl_secs, MAX_JIT_TTL_SECS);
        let decided = hub.decide(&item.id, true, Some(u64::MAX)).unwrap();
        assert_eq!(decided.ttl_secs, MAX_JIT_TTL_SECS);
        assert!(hub.has_grant(&req("KEY")));
        // A snapshot written before the clamp existed is clamped on read, too.
        let mut snap = hub.snapshot();
        snap.items[0].ttl_secs = u64::MAX;
        hub.restore(snap);
        assert!(hub.grant_secs_left(&req("KEY")).unwrap() <= MAX_JIT_TTL_SECS);

        // A live hub grant is reused by `HubGate` for the time it has left, without a prompt.
        let left = HubGate(Arc::clone(&hub)).prompt_ttl(&req("KEY")).unwrap();
        assert!(left > 0 && left <= MAX_JIT_TTL_SECS);
        assert_eq!(hub.list().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hub_gate_returns_the_ttl_the_approver_chose() {
        let hub = Arc::new(ApprovalHub::new());
        let mut events = hub.subscribe();
        let decider = Arc::clone(&hub);
        tokio::spawn(async move {
            let pending = events.recv().await.unwrap();
            decider.decide(&pending.id, true, Some(7));
        });
        let mgr = ApprovalManager::new(Box::new(HubGate(Arc::clone(&hub))));
        let id = alice_agent();
        assert!(mgr.authorize(&id, "KEY", "api.example.com", "GET", "/", 300));
        let expiry = mgr.grants.lock().unwrap().first().unwrap().expires;
        assert!(expiry <= Instant::now() + Duration::from_secs(7));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hub_gate_expires_unanswered_knocks_and_relays_scope_and_reason() {
        let hub = Arc::new(ApprovalHub::new());
        let gate = HubGate(Arc::clone(&hub));

        // Nobody answers: the knock expires and the request is denied.
        let outcome =
            gate.prompt_decision_with_timeout(&at("GET", "/v1/a"), Duration::from_millis(50));
        assert_eq!(
            outcome,
            GateOutcome::Denied {
                reason: Some("approval request timed out".to_owned())
            }
        );
        let expired = &hub.list()[0];
        assert_eq!(expired.status, ApprovalStatus::Expired);
        assert_eq!(expired.expires_at, None);
        // Expiring twice (or deciding after) changes nothing.
        assert_eq!(
            hub.expire_pending(&expired.id).unwrap().status,
            ApprovalStatus::Expired
        );
        assert!(
            !hub.decide_with_options(&expired.id, ApprovalDecision::default())
                .unwrap()
                .unwrap()
                .1
        );

        // The approver's scope and denial reason reach the gate.
        let mut events = hub.subscribe();
        let decider = Arc::clone(&hub);
        tokio::spawn(async move {
            let first = events.recv().await.unwrap();
            decider
                .decide_with_options(
                    &first.id,
                    ApprovalDecision {
                        approved: true,
                        ttl_secs: Some(30),
                        grant_scope: Some(GrantScope::ExactPath),
                        denial_reason: None,
                    },
                )
                .unwrap();
            let _decided = events.recv().await.unwrap();
            let second = events.recv().await.unwrap();
            decider
                .decide_with_options(
                    &second.id,
                    ApprovalDecision {
                        denial_reason: Some("wrong env".to_owned()),
                        ..ApprovalDecision::default()
                    },
                )
                .unwrap();
        });
        assert_eq!(
            gate.prompt_decision_with_timeout(&at("GET", "/v1/b"), Duration::from_secs(10)),
            GateOutcome::Approved {
                ttl_secs: 30,
                grant_scope: GrantScope::ExactPath
            }
        );
        // ExactPath: the same path is now served from the grant, a sibling knocks again.
        assert!(matches!(
            gate.prompt_decision_with_timeout(&at("GET", "/v1/b"), Duration::from_millis(10)),
            GateOutcome::Approved {
                grant_scope: GrantScope::ExactPath,
                ..
            }
        ));
        assert_eq!(
            gate.prompt_decision_with_timeout(&at("GET", "/v1/c"), Duration::from_secs(10)),
            GateOutcome::Denied {
                reason: Some("wrong env".to_owned())
            }
        );
    }

    #[test]
    fn snapshot_restore_keeps_pending_and_live_grants_and_expires_stale_ones() {
        let hub = ApprovalHub::new();
        let (live, _rx1) = hub.enqueue(req("LIVE"));
        let (stale, _rx2) = hub.enqueue(req("STALE"));
        let (pending, _rx3) = hub.enqueue(req("PENDING"));
        hub.decide(&live.id, true, None);
        hub.decide(&stale.id, true, Some(0));
        assert!(hub.has_grant(&req("LIVE")));
        assert!(!hub.has_grant(&req("PENDING")));

        let json = serde_json::to_string(&hub.snapshot()).unwrap();
        let restored = ApprovalHub::new();
        restored.restore(serde_json::from_str(&json).unwrap());

        assert!(restored.has_grant(&req("LIVE")));
        assert!(!restored.has_grant(&req("STALE")));
        assert!(!restored.has_grant(&req("OTHER")));
        let by_id = |id: &str| {
            restored
                .list()
                .into_iter()
                .find(|i| i.id == id)
                .unwrap()
                .status
        };
        assert_eq!(by_id(&stale.id), ApprovalStatus::Expired);
        assert_eq!(by_id(&pending.id), ApprovalStatus::Pending);
        // Restored pending requests stay decidable, and new ids never collide with old ones.
        assert!(restored.decide(&pending.id, true, None).is_some());
        let (next, _rx) = restored.enqueue(req("NEXT"));
        assert!(![live.id, stale.id, pending.id].contains(&next.id));
    }

    #[test]
    fn eviction_unblocks_evicted_waiter_immediately() {
        let hub = ApprovalHub::new();
        let (_first, mut first_rx) = hub.enqueue(req("KEY_0"));
        let mut receivers = Vec::new();
        for i in 1..=128 {
            let (_rec, rx) = hub.enqueue(req(&format!("KEY_{i}")));
            receivers.push(rx);
        }
        // Item 0 was evicted when the 129th entry arrived; its sender must have been dropped so
        // any waiting thread unblocks immediately with `false` instead of leaking forever.
        assert_eq!(
            first_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
        // Most recent waiter is still live.
        assert_eq!(
            receivers.last_mut().unwrap().try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hub_gate_times_out_and_cleans_up_waiter() {
        let hub = Arc::new(ApprovalHub::new().with_wait_timeout(Duration::from_millis(50)));
        let gate = HubGate(Arc::clone(&hub));
        let start = Instant::now();
        let granted = gate.prompt_ttl(&req("TIMED_OUT"));
        assert!(granted.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
        let items = hub.list();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, ApprovalStatus::Expired);
        assert!(hub.waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn mcp_approval_scope_isolation() {
        let base_mcp = mcp_req("github", "create_pr");
        let matching_egress_none = ApprovalRequest {
            kind: None,
            mcp_server: None,
            mcp_tool: None,
            risk: None,
            args_summary: None,
            args_hash: None,
            ref_name: None,
            ..base_mcp.clone()
        };
        let matching_egress_explicit = ApprovalRequest {
            kind: Some("egress".to_owned()),
            mcp_server: None,
            mcp_tool: None,
            risk: None,
            args_summary: None,
            args_hash: None,
            ref_name: None,
            ..base_mcp.clone()
        };

        // 1. Egress approvals (implicit `None` or explicit `"egress"`) NEVER unlock an MCP tool.
        let egress_hub = ApprovalHub::new();
        for eg in [&matching_egress_none, &matching_egress_explicit] {
            let (item, _rx) = egress_hub.enqueue(eg.clone());
            egress_hub.decide(&item.id, true, None);
        }
        assert!(egress_hub.has_grant(&matching_egress_none));
        assert!(egress_hub.has_grant(&matching_egress_explicit));
        assert!(!egress_hub.has_grant(&base_mcp));

        // 2. An MCP tool approval unlocks ONLY that exact server + tool, never egress or other tools.
        let mcp_hub = ApprovalHub::new();
        let (approved_mcp, _rx) = mcp_hub.enqueue(base_mcp.clone());
        mcp_hub.decide(&approved_mcp.id, true, None);

        assert!(mcp_hub.has_grant(&base_mcp));
        assert!(mcp_hub.has_grant(&ApprovalRequest {
            args_summary: Some("repo=acme/other".to_owned()),
            risk: Some("read".to_owned()),
            ..base_mcp.clone()
        }));

        for forbidden in [
            matching_egress_none,
            matching_egress_explicit,
            mcp_req("github", "delete_repo"),
            mcp_req("gitlab", "create_pr"),
            ApprovalRequest {
                mcp_tool: None,
                ..base_mcp.clone()
            },
            ApprovalRequest {
                mcp_server: None,
                ..base_mcp.clone()
            },
            ApprovalRequest {
                args_hash: Some("hash-2".to_owned()),
                ..base_mcp.clone()
            },
            ApprovalRequest {
                ref_name: Some("release".to_owned()),
                ..base_mcp
            },
        ] {
            assert!(!mcp_hub.has_grant(&forbidden), "{forbidden:?}");
        }
    }

    #[tokio::test]
    async fn request_and_wait_approves_reuses_and_respects_allow_reuse_false() {
        let hub = Arc::new(ApprovalHub::new());
        let mut events = hub.subscribe();
        let decider = Arc::clone(&hub);
        tokio::spawn(async move {
            let mut count = 0u32;
            while let Ok(ev) = events.recv().await {
                if ev.status != ApprovalStatus::Pending {
                    continue;
                }
                count += 1;
                let ttl = if count == 1 { 120 } else { 45 };
                decider.decide(&ev.id, true, Some(ttl));
                if count == 2 {
                    break;
                }
            }
        });

        let target = mcp_req("github", "create_pr");

        // Initial approval grants custom TTL (120s), not a reused grant.
        let first = hub
            .request_and_wait(target.clone(), Duration::from_secs(5), true)
            .await;
        assert_eq!(
            first,
            ApprovalWaitOutcome::Approved {
                ttl_secs: 120,
                reused_grant: false,
            }
        );
        assert_eq!(hub.list().len(), 1);

        // Subsequent request with `allow_reuse = true` reuses the live grant without enqueuing.
        let second = hub
            .request_and_wait(target.clone(), Duration::from_secs(5), true)
            .await;
        match second {
            ApprovalWaitOutcome::Approved {
                ttl_secs,
                reused_grant,
            } => {
                assert!(reused_grant);
                assert!(ttl_secs > 0 && ttl_secs <= 120);
            }
            other => panic!("expected reused approval, got {other:?}"),
        }
        assert_eq!(hub.list().len(), 1);

        // With `allow_reuse = false` (e.g. destructive tool), a fresh pending request is enqueued.
        let third = hub
            .request_and_wait(target, Duration::from_secs(5), false)
            .await;
        assert_eq!(
            third,
            ApprovalWaitOutcome::Approved {
                ttl_secs: 45,
                reused_grant: false,
            }
        );
        assert_eq!(hub.list().len(), 2);
    }

    #[tokio::test]
    async fn request_and_wait_deny_and_timeout_expiry_broadcast() {
        // 1. Explicit denial returns `Denied` and leaves no live grant.
        let deny_hub = Arc::new(ApprovalHub::new());
        let mut deny_events = deny_hub.subscribe();
        let decider = Arc::clone(&deny_hub);
        tokio::spawn(async move {
            let pending = deny_events.recv().await.unwrap();
            assert_eq!(pending.status, ApprovalStatus::Pending);
            decider.decide(&pending.id, false, None);
        });

        let denied_req = mcp_req("github", "delete_repo");
        let outcome = deny_hub
            .request_and_wait(denied_req.clone(), Duration::from_secs(5), true)
            .await;
        assert_eq!(outcome, ApprovalWaitOutcome::Denied);
        assert!(!deny_hub.has_grant(&denied_req));
        let denied_item = &deny_hub.list()[0];
        assert_eq!(denied_item.status, ApprovalStatus::Denied);
        // `expire` on an already-decided item preserves its decision; unknown id returns `None`.
        assert_eq!(
            deny_hub.expire(&denied_item.id).unwrap().status,
            ApprovalStatus::Denied
        );
        assert!(deny_hub.expire("jit-9999").is_none());

        // 2. Timeout calls `expire`, returns `TimedOut`, marks `Expired`, and broadcasts on SSE.
        let timeout_hub = ApprovalHub::new();
        let mut sse = timeout_hub.subscribe();
        let timed_out = timeout_hub
            .request_and_wait(
                mcp_req("github", "delete_repo"),
                Duration::from_millis(25),
                true,
            )
            .await;
        assert_eq!(timed_out, ApprovalWaitOutcome::TimedOut);

        let items = timeout_hub.list();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, ApprovalStatus::Expired);
        assert!(items[0].decided_at.is_some());

        let first_event = sse.recv().await.unwrap();
        assert_eq!(first_event.id, items[0].id);
        assert_eq!(first_event.status, ApprovalStatus::Pending);

        let expired_event = sse.recv().await.unwrap();
        assert_eq!(expired_event.id, items[0].id);
        assert_eq!(expired_event.status, ApprovalStatus::Expired);
        assert!(expired_event.decided_at.is_some());
        assert_eq!(expired_event.mcp_tool.as_deref(), Some("delete_repo"));
    }

    #[test]
    fn legacy_snapshot_deserializes_and_mcp_fields_round_trip() {
        let now_rfc3339 = Utc::now().to_rfc3339();
        let legacy_json = format!(
            r#"{{
                "next_seq": 5,
                "items": [{{
                    "id": "jit-0001",
                    "principal": "user:alice",
                    "var_name": "STRIPE_KEY",
                    "host": "api.stripe.com",
                    "method": "POST",
                    "path": "/v1/charges",
                    "ttl_secs": 300,
                    "status": "approved",
                    "created_at": "{now_rfc3339}",
                    "decided_at": "{now_rfc3339}"
                }}]
            }}"#
        );

        let legacy_snap: ApprovalSnapshot = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(legacy_snap.next_seq, 5);
        assert_eq!(legacy_snap.items.len(), 1);
        let item = &legacy_snap.items[0];
        assert_eq!(item.kind, None);
        assert_eq!(item.mcp_server, None);
        assert_eq!(item.mcp_tool, None);
        assert_eq!(item.risk, None);
        assert_eq!(item.args_summary, None);
        assert_eq!(item.args_hash, None);
        assert_eq!(item.ref_name, None);

        // Re-serializing legacy egress records omits `None` MCP fields cleanly.
        let reserialized = serde_json::to_string(&legacy_snap).unwrap();
        for omitted in [
            "\"kind\"",
            "\"mcp_server\"",
            "\"mcp_tool\"",
            "\"risk\"",
            "\"args_summary\"",
            "\"args_hash\"",
            "\"ref_name\"",
        ] {
            assert!(!reserialized.contains(omitted), "{reserialized}");
        }

        // Round-trip when MCP metadata fields are populated.
        let hub = ApprovalHub::new();
        hub.restore(legacy_snap);
        let mcp = mcp_req("github", "create_pr");
        let (pending, _rx) = hub.enqueue(mcp.clone());
        hub.decide(&pending.id, true, Some(600));

        let snap_json = serde_json::to_string(&hub.snapshot()).unwrap();
        let round_tripped: ApprovalSnapshot = serde_json::from_str(&snap_json).unwrap();
        let restored = ApprovalHub::new();
        restored.restore(round_tripped);

        assert!(restored.has_grant(&mcp));
        let saved_mcp = restored
            .list()
            .into_iter()
            .find(|i| i.id == pending.id)
            .unwrap();
        assert_eq!(saved_mcp.kind.as_deref(), Some("mcp_tool"));
        assert_eq!(saved_mcp.mcp_server.as_deref(), Some("github"));
        assert_eq!(saved_mcp.mcp_tool.as_deref(), Some("create_pr"));
        assert_eq!(saved_mcp.risk.as_deref(), Some("write"));
        assert_eq!(saved_mcp.args_summary.as_deref(), Some("repo=acme/app"));
        assert_eq!(saved_mcp.args_hash.as_deref(), Some("hash-1"));
        assert_eq!(saved_mcp.ref_name.as_deref(), Some("main"));
    }

    #[test]
    fn percent_encoded_segments_are_classified_as_the_upstream_sees_them() {
        for path in ["/v1/k%65ys", "/v1/%73ecrets/s_1", "/v1/ADMIN%5fv2"] {
            assert!(is_sensitive_path(path), "{path}");
            assert_eq!(
                classify_risk("GET", path, Sensitivity::Secret),
                RiskLevel::SensitiveScope,
                "{path}"
            );
        }
        assert!(is_sensitive_path("/v1/ch%61rges"));
        // Malformed escapes are kept literally, never panic.
        assert!(!is_sensitive_path("/v1/%zz%4"));
        assert_eq!(
            classify_risk("GET", "/v1/customers%", Sensitivity::Secret),
            RiskLevel::ReadOnly
        );
    }

    #[test]
    fn evicted_pending_knocks_do_not_leak_their_waiter() {
        let hub = ApprovalHub::new();
        let (first, mut rx) = hub.enqueue(req("FIRST"));
        for _ in 0..128 {
            let _ = hub.enqueue(req("FILL"));
        }
        assert!(hub.list().iter().all(|i| i.id != first.id));
        assert!(hub.expire_pending(&first.id).is_none());
        assert!(!hub.waiters.lock().unwrap().contains_key(&first.id));
        // Eviction drops the waiter, so a blocked gate unblocks (as denied) at once.
        assert_eq!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    }
}
