//! Account authentication for the control plane (owners and members): argon2id passwords, hashed
//! session cookies and `prm_` access tokens, RFC 6238 TOTP, login lockout, and the one request
//! gate that enforces all of it for `/v1/*` and Git smart-HTTP.
//!
//! State lives in SQLite and is re-read on every transaction, so the `premier auth`
//! recovery commands take effect on a running server without a restart.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, password_hash::rand_core::RngCore};
use axum::extract::{ConnectInfo, Path as AxumPath, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use premier_core::{AuditEvent, DelegatedIdentity, Principal};
use premier_policy::sha256_hex;
use premier_proxy::AuditSink;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::{ApiError, ServerState, err_resp};

const COOKIE: &str = "premier_session";
const SESSION_IDLE_SECS: i64 = 30 * 24 * 3600;
const TOUCH_SECS: i64 = 60;
const LOCK_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failures allowed per `(username, ip)` pair, and per ip across all usernames.
const LOCK_MAX_FAILURES: usize = 5;
const LOCK_MAX_IP_FAILURES: usize = 20;
const MAX_EVENTS: usize = 200;
const MIN_PASSWORD_CHARS: usize = 10;
/// Longest password hashed, at login as at account creation: argon2 input is attacker-chosen.
const MAX_PASSWORD_BYTES: usize = 1024;
/// Keys the in-memory lockout table holds; beyond it the stalest window is dropped.
const LOCK_MAX_KEYS: usize = 10_000;
/// argon2id runs at once (each takes ~19 MiB and a core); further requests queue.
static ARGON2_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
const TOKEN_PREFIX: &str = "prm_";
const RECOVERY_CODES: usize = 10;
const MAX_SSH_KEYS_PER_USER: usize = 50;
const MAX_SSH_KEY_BYTES: usize = 16 * 1024;
const ALLOWED_SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Authenticated caller of the request being handled.
#[derive(Clone)]
struct Actor {
    username: String,
    owner: bool,
    /// Signed in with a browser session, not an access token.
    session: bool,
    /// Agent profile bound to the access token, if any (narrows effective permissions).
    agent_profile: Option<String>,
}

tokio::task_local! {
    static ACTOR: Actor;
}

/// Owners administer the workspace and may evaluate policy as anyone ("view as"); members are
/// only ever themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    /// Accounts written before roles existed are the single owner.
    fn legacy() -> Self {
        Self::Owner
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub display_name: String,
    #[serde(default = "Role::legacy")]
    pub role: Role,
    /// A disabled account cannot sign in and its access tokens are refused (but kept).
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    last_login_at: Option<DateTime<Utc>>,
    password_hash: String,
    /// Base32 TOTP secret once enabled.
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    totp_pending: Option<String>,
    /// Last accepted time step, so a code cannot be replayed.
    #[serde(default)]
    totp_last_step: u64,
    /// SHA-256 of each unused two-factor recovery code; one is removed when it signs in.
    #[serde(default)]
    recovery_codes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRec {
    id: String,
    token_hash: String,
    username: String,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    user_agent: String,
    ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRec {
    id: String,
    token_hash: String,
    username: String,
    name: String,
    prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_profile: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthEvent {
    at: DateTime<Utc>,
    kind: String,
    /// Account the event belongs to; empty on events written before members existed.
    #[serde(default)]
    username: String,
    ip: String,
    user_agent: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyRecord {
    pub id: String,
    pub name: String,
    pub username: String,
    pub key_type: String,
    /// Normalized `"<key-type> <base64>"` without trailing comment.
    pub key_openssh: String,
    /// `"SHA256:<base64-no-pad>"` fingerprint of the decoded public key bytes.
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

/// Public SSH key metadata returned by `/v1/auth/ssh-keys` and `AuthStore` methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

impl From<&SshKeyRecord> for SshKeyInfo {
    fn from(rec: &SshKeyRecord) -> Self {
        Self {
            id: rec.id.clone(),
            name: rec.name.clone(),
            key_type: rec.key_type.clone(),
            fingerprint: rec.fingerprint.clone(),
            created_at: rec.created_at,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthData {
    #[serde(default)]
    users: Vec<Account>,
    #[serde(default)]
    sessions: Vec<SessionRec>,
    #[serde(default)]
    tokens: Vec<TokenRec>,
    #[serde(default)]
    ssh_keys: Vec<SshKeyRecord>,
    #[serde(default)]
    events: Vec<AuthEvent>,
    #[serde(skip)]
    dirty: bool,
}

/// Who is calling: where from and with which client.
#[derive(Debug, Clone)]
struct Client {
    ip: String,
    user_agent: String,
    /// Account acting (or, at login, being signed in to).
    user: String,
}

impl AuthData {
    fn user(&self, username: &str) -> Option<&Account> {
        self.users.iter().find(|a| a.username == username)
    }

    fn user_mut(&mut self, username: &str) -> Option<&mut Account> {
        self.dirty = true;
        self.users.iter_mut().find(|a| a.username == username)
    }

    fn log(&mut self, kind: &str, client: &Client, detail: impl Into<String>) {
        self.events.push(AuthEvent {
            at: Utc::now(),
            kind: kind.to_owned(),
            username: client.user.clone(),
            ip: client.ip.clone(),
            user_agent: client.user_agent.clone(),
            detail: detail.into(),
        });
        let extra = self.events.len().saturating_sub(MAX_EVENTS);
        self.events.drain(..extra);
        self.dirty = true;
    }

    /// Returns the raw cookie value; only its SHA-256 is stored.
    fn new_session(&mut self, username: &str, client: &Client) -> String {
        let token = random_b64(32);
        let now = Utc::now();
        self.sessions.push(SessionRec {
            id: random_b64(9),
            token_hash: sha256_hex(token.as_bytes()),
            username: username.to_owned(),
            created_at: now,
            last_seen_at: now,
            user_agent: client.user_agent.clone(),
            ip: client.ip.clone(),
        });
        self.dirty = true;
        token
    }

    /// Returns `(public metadata, raw token)`; only the token's SHA-256 is stored.
    pub(crate) fn new_token(
        &mut self,
        username: &str,
        name: &str,
        expires_at: Option<DateTime<Utc>>,
        agent_profile: Option<String>,
    ) -> (Value, String) {
        let token = format!("{TOKEN_PREFIX}{}", random_b64(32));
        let rec = TokenRec {
            id: random_b64(9),
            token_hash: sha256_hex(token.as_bytes()),
            username: username.to_owned(),
            name: name.to_owned(),
            prefix: token.chars().take(10).collect(),
            agent_profile,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at,
        };
        let meta = token_json(&rec);
        self.tokens.push(rec);
        self.dirty = true;
        (meta, token)
    }

    /// The enabled account `username` as the gate attaches it to a request.
    fn auth_user(
        &self,
        username: &str,
        session_id: Option<String>,
        agent_profile: Option<String>,
    ) -> Option<AuthUser> {
        let a = self.user(username).filter(|a| !a.disabled)?;
        Some(AuthUser {
            username: a.username.clone(),
            role: a.role,
            session_id,
            agent_profile,
        })
    }

    fn session_user(&mut self, cookie: &str) -> Option<AuthUser> {
        let now = Utc::now();
        let before = self.sessions.len();
        self.sessions
            .retain(|s| (now - s.last_seen_at).num_seconds() < SESSION_IDLE_SECS);
        self.dirty |= self.sessions.len() != before;
        let hash = sha256_hex(cookie.as_bytes());
        let s = self
            .sessions
            .iter_mut()
            .find(|s| ct_eq(&s.token_hash, &hash))?;
        if (now - s.last_seen_at).num_seconds() >= TOUCH_SECS {
            s.last_seen_at = now;
            self.dirty = true;
        }
        let (username, id) = (s.username.clone(), s.id.clone());
        self.auth_user(&username, Some(id), None)
    }

    fn token_user(&mut self, token: &str) -> Option<AuthUser> {
        let now = Utc::now();
        let hash = sha256_hex(token.as_bytes());
        let t = self
            .tokens
            .iter_mut()
            .find(|t| ct_eq(&t.token_hash, &hash))?;
        if t.expires_at.is_some_and(|e| e <= now) {
            return None;
        }
        if t.last_used_at
            .is_none_or(|l| (now - l).num_seconds() >= TOUCH_SECS)
        {
            t.last_used_at = Some(now);
            self.dirty = true;
        }
        let username = t.username.clone();
        let agent_profile = t.agent_profile.clone();
        self.auth_user(&username, None, agent_profile)
    }
}

/// SQLite account state plus the in-memory login-failure windows.
pub struct AuthStore {
    workspace_root: PathBuf,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl AuthStore {
    pub fn open(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// SQLite serializes read-modify-write across CLI and server processes. A corrupt DB
    /// or failed legacy import is an error so it cannot reopen first-run setup.
    pub fn txn<R>(&self, f: impl FnOnce(&mut AuthData) -> R) -> Result<R, String> {
        let dir = crate::store::account_dir(&self.workspace_root);
        crate::db::StateDb::open(&dir)?.auth_transaction(&dir, |data: &mut AuthData| {
            let result = f(data);
            (result, data.dirty)
        })
    }

    /// Test fixture: create an owner directly, returning `(Cookie header value, access token)`.
    #[cfg(test)]
    pub(crate) fn seed(&self, username: &str, password: &str) -> (String, String) {
        self.seed_as(username, password, Role::Owner)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn seed_as(&self, username: &str, password: &str, role: Role) -> (String, String) {
        let password_hash = hash_password(password).unwrap();
        let local = Client {
            ip: "test".to_owned(),
            user_agent: "test".to_owned(),
            user: username.to_owned(),
        };
        self.txn(|d| {
            d.users.push(Account {
                role,
                ..Account::new(username, username, password_hash)
            });
            let cookie = format!("{COOKIE}={}", d.new_session(username, &local));
            (cookie, d.new_token(username, "test", None, None).1)
        })
        .unwrap()
    }

    fn with_failures<R>(&self, f: impl FnOnce(&mut HashMap<String, Vec<Instant>>) -> R) -> R {
        let mut map = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        map.retain(|_, v| {
            v.retain(|t| t.elapsed() < LOCK_WINDOW);
            !v.is_empty()
        });
        f(&mut map)
    }

    /// Count an attempt against every one of `keys` before its password is hashed, so a
    /// parallel burst cannot run more hashes than the limits allow. `Err` is how long until
    /// another attempt is allowed, when any key is locked out (nothing is counted then).
    fn reserve(&self, keys: &[(String, usize)]) -> Result<(), Duration> {
        self.with_failures(|m| {
            let wait = keys
                .iter()
                .filter_map(|(k, max)| {
                    let failures = m.get(k)?;
                    // Unlocked again once the failure that completed the limit leaves the window.
                    let completing = failures.get(failures.len().checked_sub(*max)?)?;
                    Some(LOCK_WINDOW.saturating_sub(completing.elapsed()))
                })
                .max();
            match wait {
                Some(wait) => Err(wait),
                None => {
                    record_failure(m, keys);
                    Ok(())
                }
            }
        })
    }

    /// The attempt [`Self::reserve`] counted turned out fine: it is not a failure.
    fn release(&self, keys: &[(String, usize)]) {
        self.with_failures(|m| {
            for (k, _) in keys {
                if let Some(failures) = m.get_mut(k) {
                    failures.pop();
                }
            }
        });
    }

    fn fail(&self, keys: &[(String, usize)]) {
        self.with_failures(|m| record_failure(m, keys));
    }

    /// Every account as `(principal id, display_name, is_owner)`, oldest first.
    pub fn accounts(&self) -> Result<Vec<(String, String, bool)>, String> {
        self.txn(|d| {
            d.users
                .iter()
                .map(|a| {
                    let id = format!("@{}", a.username);
                    (id, a.display_name.clone(), a.role == Role::Owner)
                })
                .collect()
        })
    }

    /// List all SSH public keys registered to `username`.
    pub fn list_ssh_keys(&self, username: &str) -> Vec<SshKeyInfo> {
        self.txn(|d| {
            d.ssh_keys
                .iter()
                .filter(|k| k.username == username)
                .map(SshKeyInfo::from)
                .collect()
        })
        .unwrap_or_default()
    }

    /// Register a new SSH public key for `username`. Rejects globally duplicate keys with 409
    /// Conflict so `git@host` lookup is unambiguous, caps keys per user at
    /// [`MAX_SSH_KEYS_PER_USER`], and records a security event.
    pub fn add_ssh_key(
        &self,
        username: &str,
        name: &str,
        raw_key: &str,
    ) -> Result<SshKeyInfo, (StatusCode, String)> {
        let client = Client {
            ip: "local".to_owned(),
            user_agent: "premier".to_owned(),
            user: username.to_owned(),
        };
        self.add_ssh_key_with_client(username, name, raw_key, &client)
    }

    fn add_ssh_key_with_client(
        &self,
        username: &str,
        name: &str,
        raw_key: &str,
        client: &Client,
    ) -> Result<SshKeyInfo, (StatusCode, String)> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err((
                StatusCode::BAD_REQUEST,
                "SSH key name must be 1-64 characters".to_owned(),
            ));
        }
        let (key_type, key_openssh, fingerprint) =
            normalize_ssh_public_key(raw_key).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

        self.txn(|d| {
            if d.user(username).is_none() {
                return Err((StatusCode::NOT_FOUND, "user not found".to_owned()));
            }
            if d.ssh_keys
                .iter()
                .any(|k| k.fingerprint == fingerprint || k.key_openssh == key_openssh)
            {
                return Err((
                    StatusCode::CONFLICT,
                    "SSH key is already registered".to_owned(),
                ));
            }
            let user_count = d.ssh_keys.iter().filter(|k| k.username == username).count();
            if user_count >= MAX_SSH_KEYS_PER_USER {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("SSH key limit reached ({MAX_SSH_KEYS_PER_USER})"),
                ));
            }
            let rec = SshKeyRecord {
                id: random_b64(9),
                name: name.to_owned(),
                username: username.to_owned(),
                key_type,
                key_openssh,
                fingerprint,
                created_at: Utc::now(),
            };
            let info = SshKeyInfo::from(&rec);
            d.log(
                "ssh_key_added",
                client,
                format!("key '{}' ({})", rec.name, rec.fingerprint),
            );
            d.ssh_keys.push(rec);
            Ok(info)
        })
        .map_err(|msg| (StatusCode::INTERNAL_SERVER_ERROR, msg))?
    }

    /// Revoke an SSH public key owned by `username` and record a security event.
    pub fn revoke_ssh_key(&self, username: &str, id: &str) -> Result<(), (StatusCode, String)> {
        let client = Client {
            ip: "local".to_owned(),
            user_agent: "premier".to_owned(),
            user: username.to_owned(),
        };
        self.revoke_ssh_key_with_client(username, id, &client)
    }

    fn revoke_ssh_key_with_client(
        &self,
        username: &str,
        id: &str,
        client: &Client,
    ) -> Result<(), (StatusCode, String)> {
        self.txn(|d| {
            let Some(pos) = d
                .ssh_keys
                .iter()
                .position(|k| k.id == id && k.username == username)
            else {
                return Err((StatusCode::NOT_FOUND, "SSH key not found".to_owned()));
            };
            let rec = d.ssh_keys.remove(pos);
            d.log(
                "ssh_key_revoked",
                client,
                format!("key '{}' ({})", rec.name, rec.fingerprint),
            );
            Ok(())
        })
        .map_err(|msg| (StatusCode::INTERNAL_SERVER_ERROR, msg))?
    }

    /// Re-verify that `username` still exists and is enabled, returning its live role.
    pub fn user_state(&self, username: &str) -> Option<AuthUser> {
        self.txn(|d| d.auth_user(username, None, None))
            .ok()
            .flatten()
    }

    /// Authenticate a presented SSH public key (`"<key-type> <base64>"`). When `username == "git"`,
    /// matches the key's owning user; otherwise requires `rec.username == username`. Verifies the
    /// account exists and is enabled.
    pub fn authenticate_ssh_key(&self, username: &str, key_openssh: &str) -> Option<AuthUser> {
        let (_, normalized, fingerprint) = normalize_ssh_public_key(key_openssh).ok()?;
        self.txn(|d| {
            let rec = d.ssh_keys.iter().find(|k| {
                ct_eq(&k.fingerprint, &fingerprint) && ct_eq(&k.key_openssh, &normalized)
            })?;
            if username != "git" && rec.username != username {
                return None;
            }
            d.auth_user(&rec.username, None, None)
        })
        .ok()
        .flatten()
    }

    /// Lockout check, then a constant-shape password verification (unknown users burn the same
    /// argon2 work against a dummy hash). Failures are counted and logged here.
    async fn check_password(
        &self,
        username: &str,
        password: &str,
        client: &Client,
    ) -> Result<Account, PwError> {
        // Never a real password, so not worth an argon2 run (or a lockout slot).
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(PwError::Bad);
        }
        let keys = lock_keys(username, &client.ip);
        self.reserve(&keys).map_err(PwError::Locked)?;
        let acct = self
            .txn(|d| d.user(username).cloned())
            .map_err(PwError::Store)?;
        let hash = acct.as_ref().map(|a| a.password_hash.clone());
        let pw = password.to_owned();
        let ok = argon2_blocking(move || {
            verify_password(&pw, hash.as_deref().unwrap_or_else(|| dummy_hash()))
        })
        .await
        .unwrap_or(false);
        match acct {
            Some(a) if ok && !a.disabled => {
                self.release(&keys);
                Ok(a)
            }
            _ => {
                // Already counted by `reserve`.
                let who: String = username.chars().take(32).collect();
                let _ = self.txn(|d| d.log("login_failed", client, format!("user {who}")));
                Err(PwError::Bad)
            }
        }
    }
}

enum PwError {
    /// Locked out for this much longer.
    Locked(Duration),
    Bad,
    Store(String),
}

impl PwError {
    /// `bad` is the status for a wrong password: 401 at login, 403 when re-confirming inside a
    /// live session (a 401 there would read as "session expired").
    fn response(self, bad: StatusCode, bad_msg: &str) -> ApiErr {
        match self {
            Self::Locked(wait) => {
                let minutes = wait.as_secs().div_ceil(60).max(1);
                let s = if minutes == 1 { "" } else { "s" };
                e(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Too many attempts. Try again in {minutes} minute{s}."),
                )
            }
            Self::Bad => e(bad, bad_msg),
            Self::Store(msg) => e(StatusCode::INTERNAL_SERVER_ERROR, msg),
        }
    }
}

fn record_failure(m: &mut HashMap<String, Vec<Instant>>, keys: &[(String, usize)]) {
    for (k, max) in keys {
        // Bounded: expired windows are pruned on every access (`with_failures`), and when the
        // table is still full the key that failed longest ago makes room.
        if m.len() >= LOCK_MAX_KEYS
            && !m.contains_key(k)
            && let Some(stalest) = m
                .iter()
                .min_by_key(|(_, v)| v.last().copied())
                .map(|(k, _)| k.clone())
        {
            m.remove(&stalest);
        }
        let failures = m.entry(k.clone()).or_default();
        failures.push(Instant::now());
        // Only the newest `max` decide a lockout.
        let extra = failures.len().saturating_sub(*max);
        failures.drain(..extra);
    }
}

/// Record `attempts` failures from as many addresses, plus as many again on one key; returns
/// `(keys held, key limit, longest window)`.
#[cfg(test)]
pub(crate) fn test_lockout_flood(attempts: usize) -> (usize, usize, usize) {
    let mut m = HashMap::new();
    for i in 0..attempts {
        record_failure(
            &mut m,
            &lock_keys("owner", &format!("10.0.{}.{}", i / 256, i % 256)),
        );
        record_failure(&mut m, &lock_keys("owner", "10.9.9.9"));
    }
    let longest = m.values().map(Vec::len).max().unwrap_or(0);
    (m.len(), LOCK_MAX_KEYS, longest)
}

/// `(key, failure limit)` windows a login attempt counts against. The first is always the
/// `(username, ip)` pair. There is deliberately no username-only key: that would let anyone who
/// can reach the server lock the owner out from everywhere.
fn lock_keys(username: &str, ip: &str) -> Vec<(String, usize)> {
    let user: String = username.chars().take(64).collect();
    let mut keys = vec![(format!("u:{user}|ip:{ip}"), LOCK_MAX_FAILURES)];
    if ip != "unknown" {
        keys.push((format!("ip:{ip}"), LOCK_MAX_IP_FAILURES));
    }
    keys
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn random_b64(n: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(n))
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let hex = sha256_hex(data);
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        if let (Some(hi), Some(lo)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            *slot = (hi << 4) | lo;
        }
    }
    out
}

fn read_ssh_string<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if buf.len() < 4 {
        return Err("truncated SSH public key wire payload".to_owned());
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err("truncated SSH public key wire payload".to_owned());
    }
    let (field, rest) = buf.split_at(len);
    *buf = rest;
    Ok(field)
}

fn parse_positive_mpint<'a>(raw: &'a [u8], label: &str) -> Result<&'a [u8], String> {
    if raw.is_empty() {
        return Err(format!("RSA {label} mpint cannot be empty"));
    }
    if (raw[0] & 0x80) != 0 {
        return Err(format!("RSA {label} mpint must be positive"));
    }
    let trimmed = if raw[0] == 0 { &raw[1..] } else { raw };
    if trimmed.is_empty() || trimmed.iter().all(|&b| b == 0) {
        return Err(format!("RSA {label} mpint must be non-zero"));
    }
    if trimmed[0] == 0 {
        return Err(format!("RSA {label} mpint is not canonically encoded"));
    }
    Ok(trimmed)
}

fn validate_ssh_wire_format(key_type: &str, decoded: &[u8]) -> Result<(), String> {
    let mut cursor = decoded;
    let wire_alg = read_ssh_string(&mut cursor)?;
    if wire_alg != key_type.as_bytes() {
        return Err(format!(
            "SSH public key wire algorithm does not match declared type '{key_type}'"
        ));
    }
    match key_type {
        "ssh-ed25519" => {
            let pk = read_ssh_string(&mut cursor)?;
            if pk.len() != 32 {
                return Err(format!(
                    "invalid ssh-ed25519 public key length ({} bytes, expected 32)",
                    pk.len()
                ));
            }
        }
        "ssh-rsa" => {
            let e = parse_positive_mpint(read_ssh_string(&mut cursor)?, "exponent")?;
            let n = parse_positive_mpint(read_ssh_string(&mut cursor)?, "modulus")?;
            let e_is_odd = e.last().is_some_and(|b| (b & 1) == 1);
            let e_ge_3 = e.len() > 1 || e[0] >= 3;
            if !e_is_odd || !e_ge_3 {
                return Err("RSA public exponent must be an odd integer >= 3".to_owned());
            }
            if n.len() < 256 {
                return Err("RSA public key modulus must be at least 2048 bits".to_owned());
            }
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let expected_curve = match key_type {
                "ecdsa-sha2-nistp256" => b"nistp256".as_slice(),
                "ecdsa-sha2-nistp384" => b"nistp384".as_slice(),
                _ => b"nistp521".as_slice(),
            };
            let curve = read_ssh_string(&mut cursor)?;
            if curve != expected_curve {
                return Err(format!("ECDSA curve mismatch for '{key_type}'"));
            }
            let point = read_ssh_string(&mut cursor)?;
            if point.is_empty() {
                return Err("ECDSA public key point cannot be empty".to_owned());
            }
        }
        "sk-ssh-ed25519@openssh.com" => {
            let pk = read_ssh_string(&mut cursor)?;
            if pk.len() != 32 {
                return Err(format!(
                    "invalid sk-ssh-ed25519 public key length ({} bytes, expected 32)",
                    pk.len()
                ));
            }
            let app = read_ssh_string(&mut cursor)?;
            if app.is_empty() {
                return Err("sk-ssh-ed25519 application name cannot be empty".to_owned());
            }
        }
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let curve = read_ssh_string(&mut cursor)?;
            if curve != b"nistp256" {
                return Err(
                    "ECDSA curve mismatch for 'sk-ecdsa-sha2-nistp256@openssh.com'".to_owned(),
                );
            }
            let point = read_ssh_string(&mut cursor)?;
            if point.is_empty() {
                return Err("sk-ecdsa public key point cannot be empty".to_owned());
            }
            let app = read_ssh_string(&mut cursor)?;
            if app.is_empty() {
                return Err("sk-ecdsa application name cannot be empty".to_owned());
            }
        }
        _ => return Err(format!("unsupported SSH key type '{key_type}'")),
    }
    if !cursor.is_empty() {
        return Err("SSH public key contains unexpected trailing bytes".to_owned());
    }
    Ok(())
}

/// Validate and normalize an OpenSSH public key line (`"<key-type> <base64> [comment...]"`).
///
/// Returns `(key_type, normalized_openssh, sha256_fingerprint)` where `normalized_openssh` is
/// `"<key-type> <canonical-base64>"` (trailing comment stripped) and `sha256_fingerprint` is
/// `"SHA256:<base64-no-pad>"`.
pub fn normalize_ssh_public_key(raw: &str) -> Result<(String, String, String), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("SSH public key cannot be empty".to_owned());
    }
    if trimmed.contains(['\r', '\n', '\0']) {
        return Err("SSH public key must be a single line".to_owned());
    }
    let mut parts = trimmed.split_whitespace();
    let key_type = parts
        .next()
        .ok_or_else(|| "missing SSH key type".to_owned())?;
    let key_b64 = parts
        .next()
        .ok_or_else(|| "missing SSH key data".to_owned())?;
    if !ALLOWED_SSH_KEY_TYPES.contains(&key_type) {
        return Err(format!("unsupported SSH key type '{key_type}'"));
    }
    if key_b64.len() > (MAX_SSH_KEY_BYTES * 4) / 3 + 8 {
        return Err("SSH public key exceeds maximum size (16 KiB)".to_owned());
    }
    let decoded = STANDARD
        .decode(key_b64)
        .map_err(|_| "invalid base64 in SSH public key".to_owned())?;
    if decoded.is_empty() {
        return Err("SSH public key data cannot be empty".to_owned());
    }
    if decoded.len() > MAX_SSH_KEY_BYTES {
        return Err("SSH public key exceeds maximum size (16 KiB)".to_owned());
    }
    validate_ssh_wire_format(key_type, &decoded)?;
    let normalized = format!("{key_type} {}", STANDARD.encode(&decoded));
    let digest = sha256_bytes(&decoded);
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(digest));
    Ok((key_type.to_owned(), normalized, fingerprint))
}

fn hash_password(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| format!("password hash failed: {e}"))
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&random_b64(16)).unwrap_or_default())
}

/// Run one argon2 computation off the async threads, at most a few at a time server-wide.
async fn argon2_blocking<R: Send + 'static>(
    f: impl FnOnce() -> R + Send + 'static,
) -> Result<R, String> {
    let _slot = ARGON2_SLOTS.acquire().await.map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())
}

async fn hash_password_blocking(password: String) -> Result<String, ApiErr> {
    argon2_blocking(move || hash_password(&password))
        .await
        .and_then(|r| r)
        .map_err(ise)
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(data: &[u8]) -> String {
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = B32.iter().position(|x| *x == c.to_ascii_uppercase())?;
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// RFC 6238 code (HMAC-SHA1, 6 digits, 30 s step) for a base32 secret at a given time step.
pub fn totp_code(secret_b32: &str, step: u64) -> Option<String> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&b32_decode(secret_b32)?).ok()?;
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
    Some(format!("{:06}", bin % 1_000_000))
}

pub fn totp_step_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0) / 30
}

/// Accept the current step ±1, never a step at or before the last accepted one.
fn totp_verify(secret_b32: &str, code: &str, last_step: u64) -> Option<u64> {
    let code = code.trim();
    let now = totp_step_now();
    (now.saturating_sub(1)..=now + 1)
        .filter(|step| *step > last_step)
        .find(|step| totp_code(secret_b32, *step).is_some_and(|c| ct_eq(&c, code)))
}

// ---------------------------------------------------------------------------
// Request gate (the single enforcement point)
// ---------------------------------------------------------------------------

/// Authenticated account attached to request extensions. `session_id` is `None` for access tokens.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
    pub session_id: Option<String>,
    pub agent_profile: Option<String>,
}

/// Client address of the request: the TCP peer, or what a trusted proxy reported (`client_ip`).
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

const FORWARDED: [&str; 3] = ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"];

/// Client address for lockout and logs. `X-Forwarded-*` means something only when the TCP peer
/// is a configured trusted proxy. From anyone else the headers are removed right here, so nothing
/// downstream (cookie `Secure`, the Origin check) can be steered by them.
pub(crate) fn client_ip(
    trusted: &[IpAddr],
    peer: Option<IpAddr>,
    headers: &mut HeaderMap,
) -> String {
    let peer = peer.map(|ip| ip.to_canonical());
    if !peer.is_some_and(|ip| trusted.iter().any(|t| t.to_canonical() == ip)) {
        for name in FORWARDED {
            headers.remove(name);
        }
        return peer.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    }
    // Right-most entry: the one our proxy appended. Everything left of it is client-supplied.
    headers
        .get_all(FORWARDED[0])
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .or(peer)
        .map_or_else(|| "unknown".to_owned(), |ip| ip.to_canonical().to_string())
}

/// Identity the Git smart-HTTP handlers must project for, resolved from verified credentials.
#[derive(Debug, Clone)]
pub struct GitCaller(pub DelegatedIdentity);

type ApiErr = (StatusCode, Json<ApiError>);

fn e(status: StatusCode, msg: impl Into<String>) -> ApiErr {
    err_resp(status, msg)
}

fn ise(msg: String) -> ApiErr {
    e(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

fn client(headers: &HeaderMap, ip: &str) -> Client {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    Client {
        ip: ip.to_owned(),
        user_agent: ua.chars().take(200).collect(),
        user: ACTOR.try_with(|a| a.username.clone()).unwrap_or_default(),
    }
}

/// Record a security event (shown under `/v1/auth/events`) for the caller of this request.
pub(crate) fn log_event(
    store: &AuthStore,
    headers: &HeaderMap,
    ip: &str,
    kind: &str,
    detail: String,
) {
    let who = client(headers, ip);
    if let Err(e) = store.txn(|d| d.log(kind, &who, detail)) {
        tracing::warn!(error = %e, kind, "failed to record security event");
    }
}

fn forwarded_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(name)
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
}

pub(crate) fn forwarded_https(headers: &HeaderMap) -> bool {
    forwarded_header(headers, "x-forwarded-proto").is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

/// `Origin`, when a browser sends one, must be this server: same host:port as `Host`, or as
/// `X-Forwarded-Host` behind a trusted reverse proxy that rewrites `Host` (the gate has already
/// dropped that header from any other peer). When `Origin` is absent, checks `Sec-Fetch-Site`
/// (must be `same-origin` or `none`) and `Referer` (host must match `Host`) if present.
fn same_origin(headers: &HeaderMap) -> bool {
    let host = forwarded_header(headers, "x-forwarded-host").or_else(|| {
        headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    });
    // The HTTP listener is plain HTTP. A trusted TLS terminator reports the external scheme.
    let scheme = match forwarded_header(headers, "x-forwarded-proto") {
        Some(proto) if proto.eq_ignore_ascii_case("https") => "https",
        Some(proto) if proto.eq_ignore_ascii_case("http") => "http",
        None if !headers.contains_key("x-forwarded-proto") => "http",
        _ => return false,
    };
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().ok().and_then(|o| o.split_once("://"));
        return matches!((origin, host), (Some((s, o)), Some(h))
            if s.eq_ignore_ascii_case(scheme) && o.eq_ignore_ascii_case(h));
    }
    if let Some(sfs) = headers.get("sec-fetch-site") {
        let ok = sfs.to_str().ok().is_some_and(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("same-origin") || v.eq_ignore_ascii_case("none")
        });
        if !ok {
            return false;
        }
    }
    if let Some(referer) = headers.get(header::REFERER) {
        let Some(h) = host else {
            return false;
        };
        let Ok(parsed) = referer
            .to_str()
            .ok()
            .and_then(|r| url::Url::parse(r).ok())
            .ok_or(())
        else {
            return false;
        };
        let Some(ref_host) = parsed.host_str() else {
            return false;
        };
        let explicit = match parsed.port() {
            Some(p) => format!("{ref_host}:{p}"),
            None => ref_host.to_owned(),
        };
        let with_default_port = parsed
            .port_or_known_default()
            .map(|p| format!("{ref_host}:{p}"));
        let matches = explicit.eq_ignore_ascii_case(h)
            || with_default_port.is_some_and(|wp| wp.eq_ignore_ascii_case(h));
        if !matches || parsed.scheme() != scheme {
            return false;
        }
    }
    true
}

/// The enabled account whose Bearer access token or session cookie `headers` carry, if any.
pub(crate) fn request_user(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<Option<AuthUser>, String> {
    let (token, cookie) = (bearer(headers), session_cookie(headers));
    if token.is_none() && cookie.is_none() {
        return Ok(None);
    }
    // A presented Bearer token is authoritative; it never falls back to the cookie.
    let lookup = |d: &mut AuthData| match (token, cookie) {
        (Some(t), _) => d.token_user(t),
        (None, Some(c)) => d.session_user(c),
        (None, None) => None,
    };
    let dir = crate::store::account_dir(&state.auth.workspace_root);
    if let Some(mut data) =
        crate::db::StateDb::read_auth_credentials::<AuthData>(&dir, token.is_some())?
    {
        let user = lookup(&mut data);
        if !data.dirty {
            return Ok(user);
        }
    }
    // Re-check the latest credentials under the write lock if we need to touch or purge them.
    state.auth.txn(lookup)
}

/// Router-wide middleware: authenticates `/v1/*` (session cookie or Bearer access token), applies
/// the CSRF Origin check, and resolves Git smart-HTTP credentials. Everything else passes through.
pub async fn gate(State(state): State<ServerState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = client_ip(&state.trusted_proxies, peer, req.headers_mut());
    req.extensions_mut().insert(ClientIp(ip.clone()));
    let path = req.uri().path().to_owned();

    if path.starts_with("/git/") {
        let identity = match git_identity(&state, req.headers(), &ip).await {
            Ok(identity) => identity,
            Err(resp) => return *resp,
        };
        let needs_account = path.starts_with("/git/auth/")
            || path.ends_with("/git-receive-pack")
            || req.uri().query().is_some_and(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .any(|(k, v)| k == "service" && v == "git-receive-pack")
            });
        if needs_account && matches!(identity.principal, Principal::Anonymous) {
            return git_challenge("authentication required");
        }
        req.extensions_mut().insert(GitCaller(identity));
        return next.run(req).await;
    }
    if !path.starts_with("/v1/") {
        return next.run(req).await;
    }

    let headers = req.headers();
    let token = bearer(headers);
    let user = match request_user(&state, headers) {
        Ok(user) => user,
        Err(msg) => return ise(msg).into_response(),
    };

    let public = matches!(
        path.as_str(),
        "/v1/auth/status" | "/v1/auth/setup" | "/v1/auth/login"
    );
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    // Browsers attach the cookie on their own, so cookie (and pre-login) writes must come from
    // our own origin. Bearer callers opted in explicitly and are exempt.
    if !safe && token.is_none() && !same_origin(headers) {
        return e(StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    let Some(user) = user else {
        if public {
            return next.run(req).await;
        }
        return e(StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    // An access token is for the API and Git, not for taking over the account that issued it.
    // What an owner does to the server itself (a shell, the policy, the vault, approvals,
    // publishing) is refused to a token by `require_owner`, on every owner-only route.
    let account_mgmt = path.starts_with("/v1/auth/") || path.starts_with("/v1/users");
    if account_mgmt && !public && user.session_id.is_none() {
        return e(
            StatusCode::FORBIDDEN,
            "account management requires a browser session",
        )
        .into_response();
    }
    let actor = Actor {
        username: user.username.clone(),
        owner: user.role == Role::Owner,
        session: user.session_id.is_some(),
        agent_profile: user.agent_profile.clone(),
    };
    req.extensions_mut().insert(user);
    ACTOR.scope(actor, next.run(req)).await
}

/// Route layer for workspace administration: 403 for members, and 403 for an owner's access
/// token. Runs inside [`gate`]. This is the ONE declaration of "owner-only": a route wrapped in
/// it cannot be owner-only without also being browser-session-only, so the two cannot drift.
///
/// The exception is Git: a push that changes `.access.toml` is accepted from an owner's token
/// (Git has no browser session). It is validated like a Studio edit and audited per ref update.
pub async fn require_owner(
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> Response {
    if user.role != Role::Owner {
        return owner_required().into_response();
    }
    if let Err(refused) = require_browser_session(&user) {
        return refused.into_response();
    }
    next.run(req).await
}

/// Administering the server takes a signed-in browser, never an access token: a token leaked
/// from a script or a CI job must not be able to change policy, approve its own egress, read
/// the audit log or open a shell.
pub(crate) fn require_browser_session(user: &AuthUser) -> Result<(), ApiErr> {
    if user.session_id.is_none() {
        return Err(e(
            StatusCode::FORBIDDEN,
            "this action requires a browser session",
        ));
    }
    Ok(())
}

fn owner_required() -> ApiErr {
    e(
        StatusCode::FORBIDDEN,
        "this action requires an owner account",
    )
}

/// [`require_owner`] for a handler whose response depends on the caller: same 403 for members,
/// and the same 403 for an owner's access token, so an in-handler check can never be weaker.
pub(crate) fn owner_only() -> Result<(), ApiErr> {
    match ACTOR.try_with(|a| (a.owner, a.session)) {
        Ok((true, true)) => Ok(()),
        Ok((true, false)) => Err(e(
            StatusCode::FORBIDDEN,
            "this action requires a browser session",
        )),
        _ => Err(owner_required()),
    }
}

/// The principal a request may be evaluated as. Owners in a browser session keep the "view as"
/// lens, so their claim stands; members and access tokens are always themselves, whatever the
/// request says.
// Reads the gate's task-local. Outside it (a spawned task, a route the gate does not
// authenticate) nobody vouched for the claim, so it fails closed to `anonymous`.
pub(crate) fn effective_principal(claimed: &str) -> String {
    match ACTOR.try_with(|a| (!(a.owner && a.session)).then(|| format!("@{}", a.username))) {
        Ok(Some(me)) => me,
        Ok(None) => claimed.to_owned(),
        Err(_) => "anonymous".to_owned(),
    }
}

/// True only for an authenticated owner, on the request task.
pub(crate) fn caller_is_owner() -> bool {
    ACTOR.try_with(|a| a.owner).unwrap_or(false)
}

/// The `agent_profile` bound to the authenticated caller's access token, if any.
pub(crate) fn bound_agent_profile() -> Option<String> {
    ACTOR
        .try_with(|a| a.agent_profile.clone())
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
}

/// Record an audit event, stamping the real authenticated account next to whatever principal the
/// handler evaluated policy for (the Studio "view as" lens).
pub(crate) fn audit(sink: &AuditSink, mut ev: AuditEvent) {
    if let Ok(actor) = ACTOR.try_with(|a| a.username.clone()) {
        ev.reason.push_str(&format!(" [actor: @{actor}]"));
    }
    sink.record(ev);
}

/// Snapshot of the current request's authenticated actor, used to propagate task-local auth
/// context into background tasks spawned on behalf of that request.
#[derive(Clone)]
pub(crate) struct SavedActor(Actor);

/// Capture the current task-local actor, if running inside [`gate`].
pub(crate) fn capture_actor() -> Option<SavedActor> {
    ACTOR.try_with(|a| SavedActor(a.clone())).ok()
}

/// Run `fut` with `saved` installed as the `ACTOR` task-local (or unchanged when `None`).
pub(crate) async fn with_actor<F: std::future::Future>(
    saved: Option<SavedActor>,
    fut: F,
) -> F::Output {
    match saved {
        Some(s) => ACTOR.scope(s.0, fut).await,
        None => fut.await,
    }
}

/// `@username` of the authenticated caller of the request being handled, `anonymous` outside one.
pub(crate) fn actor_principal() -> String {
    ACTOR
        .try_with(|actor| format!("@{}", actor.username))
        .unwrap_or_else(|_| "anonymous".to_owned())
}

fn git_challenge(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, r#"Basic realm="Premier""#)],
        msg,
    )
        .into_response()
}

/// No credentials: the anonymous public projection. Otherwise the Basic password or Bearer value
/// must be an access token (or the account password, when TOTP is off) of an existing account.
async fn git_identity(
    state: &ServerState,
    headers: &HeaderMap,
    ip: &str,
) -> Result<DelegatedIdentity, Box<Response>> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(DelegatedIdentity::human_only(Principal::Anonymous, vec![]));
    };
    let bad = || Box::new(git_challenge("invalid credentials"));
    let raw = raw.to_str().map_err(|_| bad())?;
    let (basic_user, secret) = if let Some(t) = raw.strip_prefix("Bearer ") {
        (None, t.trim().to_owned())
    } else {
        let decoded = raw
            .strip_prefix("Basic ")
            .and_then(|b| STANDARD.decode(b.trim()).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(bad)?;
        let (user, pass) = decoded.split_once(':').ok_or_else(bad)?;
        (Some(user.to_owned()), pass.to_owned())
    };

    let (username, agent_profile) = if secret.starts_with(TOKEN_PREFIX) {
        let token_user = state
            .auth
            .txn(|d| d.token_user(&secret))
            .map_err(|msg| Box::new(ise(msg).into_response()))?
            .ok_or_else(bad)?;
        (token_user.username, token_user.agent_profile)
    } else {
        let user = basic_user.ok_or_else(bad)?;
        let acct = state
            .auth
            .check_password(&user, &secret, &client(headers, ip))
            .await
            .map_err(|err| match err {
                PwError::Bad => bad(),
                other => Box::new(other.response(StatusCode::UNAUTHORIZED, "").into_response()),
            })?;
        // The password alone must not sidestep the second factor; such accounts use a token.
        if acct.totp_secret.is_some() {
            return Err(Box::new(git_challenge(
                "two-factor is enabled: use an access token as the password",
            )));
        }
        (acct.username, None)
    };

    let principal = Principal::parse(&format!("@{username}")).map_err(|_| bad())?;
    let groups = crate::directory::groups_for(state, &principal)
        .map_err(|msg| Box::new(ise(msg).into_response()))?;
    Ok(match agent_profile.filter(|s| !s.trim().is_empty()) {
        Some(profile) => DelegatedIdentity::delegated(principal, groups, profile, "git-http"),
        None => DelegatedIdentity::human_only(principal, groups),
    })
}

// ---------------------------------------------------------------------------
// `/v1/auth/*` handlers
// ---------------------------------------------------------------------------

type Res = Result<Response, ApiErr>;

/// The auth `user` object and the `/v1/users` row: one shape.
fn user_json(a: &Account) -> Value {
    json!({
        "username": a.username,
        "display_name": a.display_name,
        "principal": format!("@{}", a.username),
        "role": a.role,
        "totp_enabled": a.totp_secret.is_some(),
        "recovery_codes_left": a.totp_secret.as_ref().map_or(0, |_| a.recovery_codes.len()),
        "disabled": a.disabled,
        "created_at": a.created_at,
        "last_login_at": a.last_login_at,
    })
}

/// Give `a` a fresh set of one-time recovery codes (`xxxx-xxxx-xxxx`), invalidating the old ones.
/// The plain codes are returned to show once; only their SHA-256 is kept.
fn new_recovery_codes(a: &mut Account) -> Vec<String> {
    let codes: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| {
            let raw = b32_encode(&random_bytes(10)).to_ascii_lowercase();
            format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..12])
        })
        .collect();
    a.recovery_codes = codes.iter().map(|c| sha256_hex(c.as_bytes())).collect();
    codes
}

fn token_json(t: &TokenRec) -> Value {
    json!({
        "id": t.id,
        "name": t.name,
        "prefix": t.prefix,
        "agent_profile": t.agent_profile,
        "created_at": t.created_at,
        "last_used_at": t.last_used_at,
        "expires_at": t.expires_at,
    })
}

fn status_json(d: &AuthData, username: Option<&str>) -> Value {
    let user = username.and_then(|u| d.user(u));
    json!({
        "setup_required": d.users.is_empty(),
        "authenticated": user.is_some(),
        "user": user.map(user_json),
    })
}

/// `Secure` only when a TLS-terminating proxy says the browser spoke HTTPS; on plain LAN HTTP the
/// browser would drop a `Secure` cookie. Max-Age is the browser ceiling; the 30-day idle expiry is
/// enforced server-side on `last_seen_at`.
fn set_cookie(token: &str, headers: &HeaderMap) -> String {
    let secure = if forwarded_https(headers) {
        "; Secure"
    } else {
        ""
    };
    format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=34560000{secure}")
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn valid_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_BYTES} bytes"
        ));
    }
    Ok(())
}

pub(crate) fn valid_display_name(raw: &str) -> Result<String, ApiErr> {
    let name = raw.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(e(
            StatusCode::BAD_REQUEST,
            "display name must be 1-64 characters",
        ));
    }
    Ok(name.to_owned())
}

impl Account {
    fn new(username: &str, display_name: &str, password_hash: String) -> Self {
        Self {
            username: username.to_owned(),
            display_name: display_name.to_owned(),
            role: Role::Owner,
            disabled: false,
            last_login_at: None,
            password_hash,
            totp_secret: None,
            totp_pending: None,
            totp_last_step: 0,
            recovery_codes: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

/// Validate and hash a new account (an owner until the caller says otherwise): the one set of
/// username/password rules for first-run setup and `POST /v1/users`.
async fn new_account(
    username: &str,
    password: String,
    display_name: Option<&str>,
) -> Result<Account, ApiErr> {
    let name_ok = (2..=32).contains(&username.len())
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !name_ok {
        return Err(e(
            StatusCode::BAD_REQUEST,
            "username must be 2-32 characters of a-z, 0-9, '_' or '-'",
        ));
    }
    valid_password(&password).map_err(|m| e(StatusCode::BAD_REQUEST, m))?;
    let display_name = match display_name.map(str::trim) {
        Some(n) if !n.is_empty() => valid_display_name(n)?,
        _ => username.to_owned(),
    };
    let password_hash = hash_password_blocking(password).await?;
    Ok(Account::new(username, &display_name, password_hash))
}

pub async fn status_handler(
    State(state): State<ServerState>,
    user: Option<Extension<AuthUser>>,
) -> Res {
    let username = user.map(|Extension(u)| u.username);
    let body = state
        .auth
        .txn(|d| status_json(d, username.as_deref()))
        .map_err(ise)?;
    Ok(Json(body).into_response())
}

#[derive(Deserialize)]
pub struct SetupRequest {
    username: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
}

pub async fn setup_handler(
    State(state): State<ServerState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<SetupRequest>,
) -> Res {
    let exists = || e(StatusCode::CONFLICT, "an account already exists");
    if !state.auth.txn(|d| d.users.is_empty()).map_err(ise)? {
        return Err(exists());
    }
    let mut acct = new_account(&req.username, req.password, req.display_name.as_deref()).await?;
    acct.last_login_at = Some(acct.created_at);
    let mut client = client(&headers, &ip);
    client.user.clone_from(&req.username);

    let created = state
        .auth
        .txn(|d| {
            // Re-checked under the lock: two racing setups cannot both become owner.
            if !d.users.is_empty() {
                return None;
            }
            d.users.push(acct);
            d.log("login_ok", &client, "owner account created");
            let cookie = d.new_session(&req.username, &client);
            Some((cookie, status_json(d, Some(&req.username))))
        })
        .map_err(ise)?;
    let (cookie, body) = created.ok_or_else(exists)?;
    Ok((
        [(header::SET_COOKIE, set_cookie(&cookie, &headers))],
        Json(body),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

pub async fn login_handler(
    State(state): State<ServerState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Res {
    let mut client = client(&headers, &ip);
    client.user = req.username.chars().take(32).collect();
    let acct = state
        .auth
        .check_password(&req.username, &req.password, &client)
        .await
        .map_err(|err| {
            let counter = match err {
                PwError::Locked(_) => Some(&state.metrics.auth_locked),
                PwError::Bad => Some(&state.metrics.auth_failed),
                PwError::Store(_) => None,
            };
            if let Some(counter) = counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            err.response(StatusCode::UNAUTHORIZED, "invalid username or password")
        })?;

    let code = req.totp_code.as_deref().filter(|c| !c.trim().is_empty());
    let outcome = state
        .auth
        .txn(|d| {
            let a = d.user_mut(&acct.username)?;
            let mut recovery_left = None;
            if let Some(secret) = a.totp_secret.clone() {
                let step = code.and_then(|c| totp_verify(&secret, c, a.totp_last_step));
                // The same field takes a recovery code: each works once.
                let spare = code.and_then(|c| {
                    let hash = sha256_hex(c.trim().to_ascii_lowercase().as_bytes());
                    a.recovery_codes.iter().position(|h| ct_eq(h, &hash))
                });
                match (step, spare) {
                    (Some(step), _) => a.totp_last_step = step,
                    (None, Some(used)) => {
                        a.recovery_codes.remove(used);
                        recovery_left = Some(a.recovery_codes.len());
                    }
                    (None, None) => {
                        if code.is_some() {
                            d.log("login_failed", &client, "wrong two-factor code");
                        }
                        return Some(Err(()));
                    }
                }
            }
            a.last_login_at = Some(Utc::now());
            if let Some(left) = recovery_left {
                d.log("recovery_code_used", &client, format!("{left} left"));
            }
            d.log("login_ok", &client, "");
            let cookie = d.new_session(&acct.username, &client);
            Some(Ok((cookie, status_json(d, Some(&acct.username)))))
        })
        .map_err(ise)?
        .ok_or_else(|| e(StatusCode::UNAUTHORIZED, "invalid username or password"))?;

    let keys = lock_keys(&acct.username, &ip);
    let Ok((cookie, body)) = outcome else {
        let error = if code.is_some() {
            // A guessed code is a failed login like any other, or the 6 digits are brute-forceable.
            state.auth.fail(&keys);
            state.metrics.auth_failed.fetch_add(1, Ordering::Relaxed);
            "invalid two-factor code"
        } else {
            "two-factor code required"
        };
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": error, "totp_required": true })),
        )
            .into_response());
    };
    state.auth.with_failures(|m| {
        m.remove(&keys[0].0);
    });
    state.metrics.auth_ok.fetch_add(1, Ordering::Relaxed);
    Ok((
        [(header::SET_COOKIE, set_cookie(&cookie, &headers))],
        Json(body),
    )
        .into_response())
}

pub async fn logout_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Res {
    state
        .auth
        .txn(|d| {
            d.sessions
                .retain(|s| Some(&s.id) != user.session_id.as_ref());
            d.log("logout", &client(&headers, &ip), "");
        })
        .map_err(ise)?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie())],
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    current_password: String,
    new_password: String,
}

pub async fn password_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<PasswordRequest>,
) -> Res {
    valid_password(&req.new_password).map_err(|m| e(StatusCode::BAD_REQUEST, m))?;
    let client = client(&headers, &ip);
    state
        .auth
        .check_password(&user.username, &req.current_password, &client)
        .await
        .map_err(|err| err.response(StatusCode::FORBIDDEN, "current password is incorrect"))?;
    let hash = hash_password_blocking(req.new_password).await?;
    state
        .auth
        .txn(|d| {
            if let Some(a) = d.user_mut(&user.username) {
                a.password_hash = hash;
            }
            d.sessions
                .retain(|s| s.username != user.username || Some(&s.id) == user.session_id.as_ref());
            d.log("password_changed", &client, "other sessions revoked");
        })
        .map_err(ise)?;
    Ok(no_content())
}

#[derive(Deserialize)]
pub struct ProfileRequest {
    display_name: String,
}

pub async fn profile_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<ProfileRequest>,
) -> Res {
    let name = valid_display_name(&req.display_name)?;
    state
        .auth
        .txn(|d| {
            let a = d.user_mut(&user.username)?;
            a.display_name = name;
            Some(user_json(a))
        })
        .map_err(ise)?
        .map(|body| Json(body).into_response())
        .ok_or_else(|| e(StatusCode::UNAUTHORIZED, "authentication required"))
}

pub async fn list_sessions_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Res {
    let rows = state
        .auth
        .txn(|d| {
            d.sessions
                .iter()
                .filter(|s| s.username == user.username)
                .map(|s| {
                    json!({
                        "id": s.id,
                        "created_at": s.created_at,
                        "last_seen_at": s.last_seen_at,
                        "user_agent": s.user_agent,
                        "ip": s.ip,
                        "current": Some(&s.id) == user.session_id.as_ref(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .map_err(ise)?;
    Ok(Json(rows).into_response())
}

pub async fn revoke_session_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Res {
    let removed = state
        .auth
        .txn(|d| {
            let before = d.sessions.len();
            d.sessions
                .retain(|s| !(s.id == id && s.username == user.username));
            let removed = d.sessions.len() != before;
            if removed {
                d.log(
                    "session_revoked",
                    &client(&headers, &ip),
                    format!("session {id}"),
                );
            }
            removed
        })
        .map_err(ise)?;
    if removed {
        Ok(no_content())
    } else {
        Err(e(StatusCode::NOT_FOUND, "session not found"))
    }
}

pub async fn revoke_other_sessions_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Res {
    state
        .auth
        .txn(|d| {
            d.sessions
                .retain(|s| s.username != user.username || Some(&s.id) == user.session_id.as_ref());
            d.log(
                "session_revoked",
                &client(&headers, &ip),
                "all other sessions",
            );
        })
        .map_err(ise)?;
    Ok(no_content())
}

pub async fn list_tokens_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Res {
    let rows = state
        .auth
        .txn(|d| {
            d.tokens
                .iter()
                .filter(|t| t.username == user.username)
                .map(token_json)
                .collect::<Vec<_>>()
        })
        .map_err(ise)?;
    Ok(Json(rows).into_response())
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    name: String,
    #[serde(default)]
    expires_in_days: Option<u32>,
    #[serde(default)]
    agent_profile: Option<String>,
}

pub async fn create_token_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Res {
    if user.agent_profile.is_some() {
        return Err(e(
            StatusCode::FORBIDDEN,
            "agent-scoped tokens cannot create access tokens",
        ));
    }
    let name = req.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(e(
            StatusCode::BAD_REQUEST,
            "token name must be 1-64 characters",
        ));
    }
    let agent_profile = match req.agent_profile {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim().to_owned();
            if trimmed.is_empty()
                || trimmed.len() > 64
                || !trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                return Err(e(
                    StatusCode::BAD_REQUEST,
                    "agent_profile must be 1-64 ASCII characters matching [A-Za-z0-9._-]",
                ));
            }
            Some(trimmed)
        }
    };
    let expires_at = match req.expires_in_days {
        None => None,
        Some(days @ 1..=3650) => Some(Utc::now() + chrono::Duration::days(i64::from(days))),
        Some(_) => {
            return Err(e(
                StatusCode::BAD_REQUEST,
                "expires_in_days must be between 1 and 3650",
            ));
        }
    };
    let mut body = state
        .auth
        .txn(|d| {
            let (mut meta, token) = d.new_token(&user.username, &name, expires_at, agent_profile);
            meta["token"] = Value::String(token);
            d.log(
                "token_created",
                &client(&headers, &ip),
                format!("token '{name}'"),
            );
            meta
        })
        .map_err(ise)?;
    Ok(Json(body.take()).into_response())
}

pub async fn revoke_token_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Res {
    let removed = state
        .auth
        .txn(|d| {
            let pos = d
                .tokens
                .iter()
                .position(|t| t.id == id && t.username == user.username)?;
            let t = d.tokens.remove(pos);
            d.log(
                "token_revoked",
                &client(&headers, &ip),
                format!("token '{}'", t.name),
            );
            Some(())
        })
        .map_err(ise)?;
    removed
        .map(|()| no_content())
        .ok_or_else(|| e(StatusCode::NOT_FOUND, "token not found"))
}

pub async fn list_ssh_keys_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Res {
    let rows = state
        .auth
        .txn(|d| {
            d.ssh_keys
                .iter()
                .filter(|k| k.username == user.username)
                .map(SshKeyInfo::from)
                .collect::<Vec<_>>()
        })
        .map_err(ise)?;
    Ok(Json(rows).into_response())
}

#[derive(Deserialize)]
pub struct AddSshKeyRequest {
    name: String,
    #[serde(alias = "public_key")]
    key: String,
}

pub async fn add_ssh_key_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<AddSshKeyRequest>,
) -> Res {
    let info = state
        .auth
        .add_ssh_key_with_client(&user.username, &req.name, &req.key, &client(&headers, &ip))
        .map_err(|(status, msg)| e(status, msg))?;
    Ok(Json(info).into_response())
}

pub async fn revoke_ssh_key_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Res {
    state
        .auth
        .revoke_ssh_key_with_client(&user.username, &id, &client(&headers, &ip))
        .map_err(|(status, msg)| e(status, msg))?;
    Ok(no_content())
}

pub async fn totp_begin_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Res {
    let secret = b32_encode(&random_bytes(20));
    let otpauth_url = format!(
        "otpauth://totp/Premier:{}?secret={secret}&issuer=Premier&algorithm=SHA1&digits=6&period=30",
        user.username
    );
    let qr_svg = qrcode::QrCode::new(otpauth_url.as_bytes())
        .map_err(|err| ise(err.to_string()))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();
    let started = state
        .auth
        .txn(|d| {
            let a = d.user_mut(&user.username)?;
            if a.totp_secret.is_some() {
                return None;
            }
            a.totp_pending = Some(secret.clone());
            Some(())
        })
        .map_err(ise)?;
    if started.is_none() {
        return Err(e(
            StatusCode::CONFLICT,
            "two-factor is already enabled; disable it first",
        ));
    }
    Ok(
        Json(json!({ "secret": secret, "otpauth_url": otpauth_url, "qr_svg": qr_svg }))
            .into_response(),
    )
}

#[derive(Deserialize)]
pub struct TotpEnableRequest {
    code: String,
}

pub async fn totp_enable_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<TotpEnableRequest>,
) -> Res {
    let enabled = state
        .auth
        .txn(|d| {
            let a = d.user_mut(&user.username)?;
            let secret = a.totp_pending.clone()?;
            let step = totp_verify(&secret, &req.code, 0)?;
            a.totp_secret = Some(secret);
            a.totp_pending = None;
            a.totp_last_step = step;
            let codes = new_recovery_codes(a);
            d.log("totp_enabled", &client(&headers, &ip), "");
            Some(codes)
        })
        .map_err(ise)?;
    let codes = enabled.ok_or_else(|| {
        e(
            StatusCode::BAD_REQUEST,
            "invalid code, or no two-factor setup in progress",
        )
    })?;
    Ok(Json(json!({ "recovery_codes": codes })).into_response())
}

/// `POST /v1/auth/totp/recovery-codes` `{ password }`: replace the recovery codes with new ones.
pub async fn totp_recovery_codes_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<TotpDisableRequest>,
) -> Res {
    let client = client(&headers, &ip);
    state
        .auth
        .check_password(&user.username, &req.password, &client)
        .await
        .map_err(|err| err.response(StatusCode::FORBIDDEN, "password is incorrect"))?;
    let codes = state
        .auth
        .txn(|d| {
            let a = d
                .user_mut(&user.username)
                .filter(|a| a.totp_secret.is_some())?;
            let codes = new_recovery_codes(a);
            d.log("recovery_codes_regenerated", &client, "");
            Some(codes)
        })
        .map_err(ise)?
        .ok_or_else(|| e(StatusCode::CONFLICT, "two-factor is not enabled"))?;
    Ok(Json(json!({ "recovery_codes": codes })).into_response())
}

/// Body of the two-factor routes that re-confirm the password (disable, new recovery codes).
#[derive(Deserialize)]
pub struct TotpDisableRequest {
    password: String,
}

pub async fn totp_disable_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<TotpDisableRequest>,
) -> Res {
    let client = client(&headers, &ip);
    state
        .auth
        .check_password(&user.username, &req.password, &client)
        .await
        .map_err(|err| err.response(StatusCode::FORBIDDEN, "password is incorrect"))?;
    state
        .auth
        .txn(|d| {
            if let Some(a) = d.user_mut(&user.username) {
                a.totp_secret = None;
                a.totp_pending = None;
                a.recovery_codes.clear();
            }
            d.log("totp_disabled", &client, "");
        })
        .map_err(ise)?;
    Ok(no_content())
}

/// Security events: owners see the workspace's, members only their own.
pub async fn events_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
) -> Res {
    let rows = state
        .auth
        .txn(|d| {
            d.events
                .iter()
                .rev()
                .filter(|ev| user.role == Role::Owner || ev.username == user.username)
                .take(50)
                .cloned()
                .collect::<Vec<_>>()
        })
        .map_err(ise)?;
    Ok(Json(rows).into_response())
}

// ---------------------------------------------------------------------------
// `/v1/users` (owners only via `require_owner`, browser session only via the gate)
// ---------------------------------------------------------------------------

fn enabled_owners<'a>(users: impl Iterator<Item = &'a Account>) -> usize {
    users
        .filter(|a| a.role == Role::Owner && !a.disabled)
        .count()
}

fn last_owner() -> ApiErr {
    e(
        StatusCode::CONFLICT,
        "the workspace must keep at least one enabled owner",
    )
}

fn no_user() -> ApiErr {
    e(StatusCode::NOT_FOUND, "user not found")
}

pub async fn list_users_handler(State(state): State<ServerState>) -> Res {
    let rows = state
        .auth
        .txn(|d| d.users.iter().map(user_json).collect::<Vec<_>>())
        .map_err(ise)?;
    Ok(Json(rows).into_response())
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<Role>,
}

pub async fn create_user_handler(
    State(state): State<ServerState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Res {
    let mut acct = new_account(&req.username, req.password, req.display_name.as_deref()).await?;
    acct.role = req.role.unwrap_or(Role::Member);
    let client = client(&headers, &ip);
    state
        .auth
        .txn(|d| {
            if d.user(&acct.username).is_some() {
                return None;
            }
            let row = user_json(&acct);
            let detail = format!("user {} ({})", acct.username, acct.role.as_str());
            d.log("user_created", &client, detail);
            d.users.push(acct);
            Some(row)
        })
        .map_err(ise)?
        .map(|row| Json(row).into_response())
        .ok_or_else(|| e(StatusCode::CONFLICT, "username is already taken"))
}

#[derive(Deserialize)]
pub struct PatchUserRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    password: Option<String>,
}

pub async fn patch_user_handler(
    State(state): State<ServerState>,
    Extension(me): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
    Json(req): Json<PatchUserRequest>,
) -> Res {
    let display_name = req
        .display_name
        .as_deref()
        .map(valid_display_name)
        .transpose()?;
    let password_hash = match req.password {
        Some(pw) => {
            valid_password(&pw).map_err(|m| e(StatusCode::BAD_REQUEST, m))?;
            Some(hash_password_blocking(pw).await?)
        }
        None => None,
    };
    let client = client(&headers, &ip);
    let row = state
        .auth
        .txn(|d| {
            let mut next = d.user(&username).cloned().ok_or_else(no_user)?;
            let mut changed = Vec::new();
            if let Some(name) = display_name {
                next.display_name = name;
                changed.push("display name");
            }
            if let Some(role) = req.role {
                next.role = role;
                changed.push(role.as_str());
            }
            if let Some(disabled) = req.disabled {
                next.disabled = disabled;
                changed.push(if disabled { "disabled" } else { "enabled" });
            }
            // A new password or a disable ends that user's sessions (not the one making the call).
            let revoke = password_hash.is_some() || req.disabled == Some(true);
            if let Some(hash) = password_hash {
                next.password_hash = hash;
                changed.push("password");
            }
            let others = d.users.iter().filter(|a| a.username != username);
            if enabled_owners(others.chain([&next])) == 0 {
                return Err(last_owner());
            }
            if revoke {
                d.sessions
                    .retain(|s| s.username != username || Some(&s.id) == me.session_id.as_ref());
            }
            let row = user_json(&next);
            let detail = format!("user {username}: {}", changed.join(", "));
            d.log("user_updated", &client, detail);
            if let Some(a) = d.user_mut(&username) {
                *a = next;
            }
            Ok(row)
        })
        .map_err(ise)??;
    Ok(Json(row).into_response())
}

pub async fn delete_user_handler(
    State(state): State<ServerState>,
    Extension(me): Extension<AuthUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
) -> Res {
    if username == me.username {
        return Err(e(
            StatusCode::CONFLICT,
            "you cannot delete your own account",
        ));
    }
    let client = client(&headers, &ip);
    state
        .auth
        .txn(|d| {
            let pos = d
                .users
                .iter()
                .position(|a| a.username == username)
                .ok_or_else(no_user)?;
            if enabled_owners(d.users.iter().filter(|a| a.username != username)) == 0 {
                return Err(last_owner());
            }
            d.users.remove(pos);
            d.sessions.retain(|s| s.username != username);
            d.tokens.retain(|t| t.username != username);
            d.ssh_keys.retain(|k| k.username != username);
            d.log("user_deleted", &client, format!("user {username}"));
            Ok(())
        })
        .map_err(ise)??;
    // Group assignments go with the account, so a later namesake does not inherit them.
    crate::directory::forget(&state, &format!("@{username}")).map_err(ise)?;
    Ok(no_content())
}

/// What [`AuthStore::revoke_user_access`] took away from an account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRevokeSummary {
    /// The principal has a login account (a policy-only principal has none).
    pub found: bool,
    pub account_disabled: bool,
    pub account_deleted: bool,
    pub sessions_revoked: usize,
    pub tokens_revoked: usize,
    pub ssh_keys_revoked: usize,
}

impl AuthStore {
    /// True if `username` exists in the store (case-insensitive) and is currently disabled.
    pub fn is_user_disabled(&self, username: &str) -> bool {
        let target = username.trim().trim_start_matches('@');
        self.txn(|d| {
            d.users
                .iter()
                .find(|a| a.username.eq_ignore_ascii_case(target))
                .is_some_and(|a| a.disabled)
        })
        .unwrap_or(false)
    }

    /// Offboarding: disable (or delete) `username` and revoke every browser session, access
    /// token and SSH key it holds. Refuses to take away the last enabled owner. A principal
    /// without a login account is not an error (`found: false`): the caller still revokes its
    /// approvals, agent sessions and workload tokens.
    pub fn revoke_user_access(
        &self,
        username: &str,
        actor: &str,
        reason: &str,
        delete_account: bool,
    ) -> Result<AuthRevokeSummary, (StatusCode, String)> {
        let target_username = username.trim().trim_start_matches('@').to_ascii_lowercase();
        let who = Client {
            ip: "local".to_owned(),
            user_agent: "premier-offboard".to_owned(),
            user: target_username.clone(),
        };
        self.txn(|d| {
            let Some(pos) = d
                .users
                .iter()
                .position(|a| a.username.eq_ignore_ascii_case(&target_username))
            else {
                return Ok(AuthRevokeSummary::default());
            };
            let actual = d.users[pos].username.clone();
            let counts_as_owner = d.users[pos].role == Role::Owner && !d.users[pos].disabled;
            if counts_as_owner
                && enabled_owners(
                    d.users
                        .iter()
                        .filter(|a| !a.username.eq_ignore_ascii_case(&target_username)),
                ) == 0
            {
                return Err((
                    StatusCode::CONFLICT,
                    "the workspace must keep at least one enabled owner".to_owned(),
                ));
            }
            if delete_account {
                d.users.remove(pos);
            } else if let Some(a) = d.user_mut(&actual) {
                a.disabled = true;
            }
            let count = |before: usize, after: usize| before.saturating_sub(after);
            let (s, t, k) = (d.sessions.len(), d.tokens.len(), d.ssh_keys.len());
            d.sessions
                .retain(|x| !x.username.eq_ignore_ascii_case(&target_username));
            d.tokens
                .retain(|x| !x.username.eq_ignore_ascii_case(&target_username));
            d.ssh_keys
                .retain(|x| !x.username.eq_ignore_ascii_case(&target_username));
            let summary = AuthRevokeSummary {
                found: true,
                account_disabled: !delete_account,
                account_deleted: delete_account,
                sessions_revoked: count(s, d.sessions.len()),
                tokens_revoked: count(t, d.tokens.len()),
                ssh_keys_revoked: count(k, d.ssh_keys.len()),
            };
            d.log(
                "user_offboarded",
                &who,
                format!("offboarded by {actor}: {reason}"),
            );
            Ok(summary)
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    }
}

// ---------------------------------------------------------------------------
// Offline recovery (`premier auth …`)
// ---------------------------------------------------------------------------

fn recover(
    workspace_root: &Path,
    username: &str,
    kind: &str,
    f: impl FnOnce(&mut AuthData, &mut Account),
) -> Result<(), String> {
    let local = Client {
        ip: "local".to_owned(),
        user_agent: "premier-cli".to_owned(),
        user: username.to_owned(),
    };
    AuthStore::open(workspace_root)
        .txn(|d| {
            let pos = d.users.iter().position(|a| a.username == username)?;
            let mut acct = d.users.remove(pos);
            f(d, &mut acct);
            d.users.insert(pos, acct);
            d.log(kind, &local, "recovered with the premier CLI");
            Some(())
        })?
        .ok_or_else(|| format!("no account named '{username}' in this workspace"))
}

/// Set a new password for `username` and revoke every session.
pub fn reset_password(workspace_root: &Path, username: &str, password: &str) -> Result<(), String> {
    valid_password(password)?;
    let hash = hash_password(password)?;
    recover(workspace_root, username, "password_changed", |d, a| {
        a.password_hash = hash;
        d.sessions.retain(|s| s.username != username);
    })
}

/// Turn off two-factor for `username` (lost authenticator).
pub fn disable_totp(workspace_root: &Path, username: &str) -> Result<(), String> {
    recover(workspace_root, username, "totp_disabled", |_, a| {
        a.totp_secret = None;
        a.totp_pending = None;
        a.recovery_codes.clear();
    })
}

/// True when a workspace-relative path points into server-internal state (`.premier`, `.premier-local`,
/// `.git`): password hashes, vault keys and audit logs are never repo content, whatever policy says.
pub(crate) fn is_internal_path(workspace_root: &Path, rel: &str) -> bool {
    const INTERNAL: [&str; 3] = [".premier", ".premier-local", ".git"];
    // Windows opens "x.", "x " and "x::$DATA" as "x", case-insensitively.
    let named = rel.split(['/', '\\']).any(|seg| {
        let seg = seg.split(':').next().unwrap_or(seg);
        let seg = seg.trim_end_matches(['.', ' ']).to_ascii_lowercase();
        INTERNAL.contains(&seg.as_str())
    });
    if named {
        return true;
    }
    // Symlinks and 8.3 short names: resolve the nearest existing ancestor and compare for real.
    let mut probe = workspace_root.join(rel);
    let resolved = loop {
        if let Ok(c) = probe.canonicalize() {
            break c;
        }
        if !probe.pop() {
            return false;
        }
    };
    INTERNAL.iter().any(|dir| {
        workspace_root
            .join(dir)
            .canonicalize()
            .is_ok_and(|c| resolved.starts_with(c))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sqlite_tests {
    use super::*;

    #[test]
    fn legacy_migration_preserves_both_scopes_and_encrypts_totp() {
        const TOTP: &str = "JBSWY3DPEHPK3PXP";
        const PENDING: &str = "JBSWY3DPEHPK3PXQ";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = crate::store::state_dir(root);
        let mut legacy_auth = AuthData::default();
        let mut account = Account::new(
            "old",
            "Old account",
            hash_password("test-password").unwrap(),
        );
        account.totp_secret = Some(TOTP.to_owned());
        account.totp_pending = Some(PENDING.to_owned());
        account.recovery_codes = vec![sha256_hex(b"old-recovery-code")];
        account.totp_last_step = 21;
        legacy_auth.users.push(account);
        let client = Client {
            ip: "test".to_owned(),
            user_agent: "test".to_owned(),
            user: "old".to_owned(),
        };
        legacy_auth.new_session("old", &client);
        legacy_auth.new_token("old", "ci", None, None);
        legacy_auth.ssh_keys.push(SshKeyRecord {
            id: "ssh".to_owned(),
            name: "work".to_owned(),
            username: "old".to_owned(),
            key_type: "ssh-ed25519".to_owned(),
            key_openssh: "test fixture".to_owned(),
            fingerprint: "test fingerprint".to_owned(),
            created_at: Utc::now(),
        });
        legacy_auth.log("login_ok", &client, "");
        crate::store::save_json(root, "auth.json", &legacy_auth).unwrap();
        let mut repo = crate::store::PersistedState::default();
        repo.settings.audit_retention_days = Some(7);
        repo.branch_metadata.insert(
            "private".to_owned(),
            (
                premier_core::Visibility::Restricted(vec!["@old".to_owned()]),
                premier_core::Readiness::Wip,
            ),
        );
        crate::store::save_json(root, "state.json", &repo).unwrap();

        let expected = serde_json::to_value(&legacy_auth).unwrap();
        let reopen = || AuthStore::open(root);
        let migrated = reopen()
            .txn(|data| serde_json::to_value(data).unwrap())
            .unwrap();
        assert_eq!(migrated, expected);
        assert!(!dir.join("auth.json").exists());
        let db_path = dir.join(crate::db::DB_FILE);
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
        let sql: String = conn
            .query_row("SELECT data FROM users", [], |row| row.get(0))
            .unwrap();
        assert!(!sql.contains(TOTP));
        assert!(!sql.contains(PENDING));
        let file = std::fs::read(&db_path).unwrap();
        assert!(
            !file
                .windows(TOTP.len())
                .any(|bytes| bytes == TOTP.as_bytes())
        );
        let code = totp_code(TOTP, totp_step_now()).unwrap();
        reopen()
            .txn(|data| {
                let account = data.user("old").unwrap();
                assert!(verify_password("test-password", &account.password_hash));
                assert!(
                    totp_verify(
                        account.totp_secret.as_deref().unwrap(),
                        &code,
                        account.totp_last_step
                    )
                    .is_some()
                );
                assert_eq!(serde_json::to_value(data).unwrap(), expected);
            })
            .unwrap();

        let mut migrated_repo = crate::store::load_state(root).unwrap();
        assert_eq!(migrated_repo.branch_metadata, repo.branch_metadata);
        migrated_repo.settings.audit_retention_days = Some(42);
        crate::store::save_state(root, &migrated_repo).unwrap();
        assert_eq!(
            crate::store::load_state(root)
                .unwrap()
                .settings
                .audit_retention_days,
            Some(42)
        );
        crate::store::save_json(root, "auth.json", &AuthData::default()).unwrap();
        assert!(reopen().user_state("old").is_some());
    }
}
