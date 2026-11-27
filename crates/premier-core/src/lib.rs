//! `premier-core` — Zero-IO domain primitives for Premier.
//!
//! Models the four orthogonal access primitives (Zones/Path ACLs, Ref/Branch
//! Confidentiality, Typed Overlays, and Secret Capabilities) plus delegated
//! human∩agent identities and structured audit events.

use std::fmt;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Core domain validation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid repository path '{path}': {reason}")]
    InvalidRepoPath { path: String, reason: &'static str },

    #[error("unknown capability '{0}'")]
    UnknownCapability(String),

    #[error("invalid principal '{0}'")]
    InvalidPrincipal(String),
}

bitflags! {
    /// Five orthogonal capabilities compiled into prefix-trie bitmasks.
    ///
    /// Separating `TRAVERSE` from `LIST` and `READ` ensures structural ancestor
    /// traversal never leaks restricted sibling filenames or blob hashes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Capability: u8 {
        /// Walk through an ancestor directory to reach an authorized descendant,
        /// without seeing sibling entries.
        const TRAVERSE = 0b0000_0001;
        /// Enumerate immediate child names of a directory.
        const LIST     = 0b0000_0010;
        /// Read blob contents or secret plaintext values.
        const READ     = 0b0000_0100;
        /// Modify or create blobs/paths.
        const WRITE    = 0b0000_1000;
        /// Invoke a secret capability via the egress proxy without reading its raw value.
        const USE      = 0b0001_0000;
    }
}

impl Capability {
    /// Parse a single capability name (case-insensitive).
    pub fn parse_name(name: &str) -> Result<Self, CoreError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::empty()),
            "traverse" => Ok(Self::TRAVERSE),
            "list" => Ok(Self::LIST),
            "read" => Ok(Self::READ),
            "write" => Ok(Self::WRITE),
            "use" => Ok(Self::USE),
            "all" | "*" => Ok(Self::all()),
            other => Err(CoreError::UnknownCapability(other.to_owned())),
        }
    }

    /// Parse a slice of capability names into a combined bitmask.
    pub fn from_names<'a, I>(names: I) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut mask = Self::empty();
        for name in names {
            mask |= Self::parse_name(name)?;
        }
        Ok(mask)
    }

    /// Return the canonical lowercase names of every bit set in this mask.
    pub fn to_names(self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(5);
        if self.contains(Self::TRAVERSE) {
            out.push("traverse");
        }
        if self.contains(Self::LIST) {
            out.push("list");
        }
        if self.contains(Self::READ) {
            out.push("read");
        }
        if self.contains(Self::WRITE) {
            out.push("write");
        }
        if self.contains(Self::USE) {
            out.push("use");
        }
        out
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.to_names();
        if names.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", names.join(","))
        }
    }
}

/// Normalized, traversal-safe POSIX repository path.
///
/// Root is represented by the empty string `""`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoPath(String);

impl RepoPath {
    /// Validate a repository-relative path. The empty string is the root.
    ///
    /// Strict on every platform, because the same path must mean the same file wherever the
    /// repository is checked out: Windows and macOS open `BILLING/x`, `billing./x`, `billing /x`
    /// and `billing/x::$DATA` as `billing/x`, and `C:/x` or `/x` joined onto a root replaces it.
    /// So no absolute paths, drive letters or `:`, no backslashes or control characters, and no
    /// segment that is empty, `.`, `..`, or ends in `.` or a space.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, CoreError> {
        let raw_str = raw.as_ref();
        let bad = |reason| {
            Err(CoreError::InvalidRepoPath {
                path: raw_str.to_owned(),
                reason,
            })
        };
        if raw_str.is_empty() {
            return Ok(Self(String::new()));
        }
        if raw_str.contains(char::is_control) {
            return bad("control characters are not permitted");
        }
        if raw_str.contains('\\') {
            return bad("backslashes are not permitted; use POSIX '/' separators");
        }
        if raw_str.starts_with('/') {
            return bad("absolute paths are not permitted");
        }
        for segment in raw_str.split('/') {
            if segment == ".." {
                return bad("parent traversal ('..') is forbidden");
            }
            if segment.is_empty() || segment == "." {
                return bad("empty and '.' segments are not permitted");
            }
            if segment.contains(':') {
                return bad("':' is not permitted (drive letters, NTFS streams)");
            }
            if segment.ends_with(['.', ' ']) {
                return bad("a segment may not end in '.' or a space");
            }
        }
        Ok(Self(raw_str.to_owned()))
    }

    /// Root repository path (`""`).
    pub fn root() -> Self {
        Self(String::new())
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path segments from root to leaf. Empty for root.
    pub fn segments(&self) -> Vec<&str> {
        if self.0.is_empty() {
            Vec::new()
        } else {
            self.0.split('/').collect()
        }
    }

    /// Returns all strict ancestor paths from root down to parent.
    pub fn ancestors(&self) -> Vec<Self> {
        if self.0.is_empty() {
            return Vec::new();
        }
        let segs = self.segments();
        let mut out = Vec::with_capacity(segs.len());
        out.push(Self::root());
        for i in 1..segs.len() {
            out.push(Self(segs[..i].join("/")));
        }
        out
    }

    /// True if `self` is a strict ancestor of `other`.
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        if self.0.is_empty() {
            return !other.0.is_empty();
        }
        other
            .0
            .strip_prefix(&self.0)
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl TryFrom<String> for RepoPath {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RepoPath> for String {
    fn from(value: RepoPath) -> Self {
        value.0
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, ".")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// A named security principal (user, group, service workload, or anonymous).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Principal {
    /// Unauthenticated/public caller (`anonymous` or `*`).
    Anonymous,
    /// Human user (`@alice` or `user:alice`).
    User(String),
    /// Team or org group (`group:billing` or `team:billing`).
    Group(String),
    /// Non-human CI/CD or service workload (`service:ci-deploy` or `spiffe://...`).
    Service(String),
    /// Bot principal (`bot:dependabot`).
    Bot(String),
}

impl Principal {
    /// Parse a CLI or policy principal string (`@alice`, `user:alice`, `group:billing`,
    /// `team:core`, `service:ci`, `bot:premier`, `anonymous`).
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(CoreError::InvalidPrincipal(raw.to_owned()));
        }
        if s.eq_ignore_ascii_case("anonymous") || s.eq_ignore_ascii_case("public") {
            return Ok(Self::Anonymous);
        }
        if let Some(user) = s.strip_prefix('@') {
            if user.is_empty() {
                return Err(CoreError::InvalidPrincipal(raw.to_owned()));
            }
            return Ok(Self::User(user.to_owned()));
        }
        if let Some((prefix, id)) = s.split_once(':') {
            if id.is_empty() {
                return Err(CoreError::InvalidPrincipal(raw.to_owned()));
            }
            return match prefix.to_ascii_lowercase().as_str() {
                "user" => Ok(Self::User(id.to_owned())),
                "group" | "team" => Ok(Self::Group(id.to_owned())),
                "service" | "spiffe" => Ok(Self::Service(s.to_owned())),
                "bot" => Ok(Self::Bot(id.to_owned())),
                _ => Err(CoreError::InvalidPrincipal(raw.to_owned())),
            };
        }
        Ok(Self::User(s.to_owned()))
    }

    pub fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// Canonical token used when matching against `.access.toml` rule principal patterns.
    pub fn canonical_id(&self) -> String {
        match self {
            Self::Anonymous => "anonymous".to_owned(),
            Self::User(u) => format!("@{u}"),
            Self::Group(g) => format!("group:{g}"),
            Self::Service(s) => s.clone(),
            Self::Bot(b) => format!("bot:{b}"),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical_id())
    }
}

/// An AI coding agent task identity acting on behalf of a human (`act` claim).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentTaskIdentity {
    /// Profile name declared in `.access.toml` (e.g. `ui-agent`, `ci-triage`).
    pub profile: String,
    /// Ephemeral task/session identifier (e.g. SPIFFE SVID or run UUID).
    pub task_id: String,
}

/// Delegated caller identity enforcing `permissions(human) ∩ permissions(agent_task)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedIdentity {
    pub principal: Principal,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub agent_task: Option<AgentTaskIdentity>,
}

impl DelegatedIdentity {
    pub fn human_only(principal: Principal, groups: Vec<String>) -> Self {
        Self {
            principal,
            groups,
            agent_task: None,
        }
    }

    pub fn delegated(
        principal: Principal,
        groups: Vec<String>,
        profile: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        Self {
            principal,
            groups,
            agent_task: Some(AgentTaskIdentity {
                profile: profile.into(),
                task_id: task_id.into(),
            }),
        }
    }

    /// Check whether this caller's human/principal identity matches a policy selector.
    ///
    /// Supported selectors: `*`, `authenticated`, `anonymous`, `@alice`, `user:alice`,
    /// `group:<name>`, `team:<name>`, `service:<name>`, `bot:<name>`, `agent:*`, `agent:<profile>`.
    pub fn matches_selector(&self, selector: &str) -> bool {
        let sel = selector.trim();
        if sel == "*" {
            return true;
        }
        if sel.eq_ignore_ascii_case("authenticated") {
            return self.principal.is_authenticated();
        }
        if sel.eq_ignore_ascii_case("anonymous") || sel.eq_ignore_ascii_case("public") {
            return matches!(self.principal, Principal::Anonymous);
        }
        if let Some(agent_pat) = sel.strip_prefix("agent:") {
            return match &self.agent_task {
                Some(task) => agent_pat == "*" || task.profile == agent_pat,
                None => false,
            };
        }
        if let Some(group) = sel
            .strip_prefix("group:")
            .or_else(|| sel.strip_prefix("team:"))
        {
            if matches!(&self.principal, Principal::Group(g) if g == group) {
                return true;
            }
            return self.groups.iter().any(|g| g == group);
        }
        if let Some(user) = sel.strip_prefix('@').or_else(|| sel.strip_prefix("user:")) {
            return matches!(&self.principal, Principal::User(u) if u == user);
        }
        if let Some(bot) = sel.strip_prefix("bot:") {
            return matches!(&self.principal, Principal::Bot(b) if b == bot);
        }
        if sel.starts_with("service:") || sel.starts_with("spiffe:") {
            return matches!(&self.principal, Principal::Service(s) if s == sel);
        }
        false
    }
}

/// Named Zone identifier (`zone:public`, `zone:billing`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub String);

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zone:{}", self.0)
    }
}

/// Orthogonal Ref/Branch Visibility (never conflated with `Readiness`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "allow", rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Org,
    Restricted(Vec<String>),
    /// `allow` is a one-element list on the wire, like `restricted`'s; a bare string (what
    /// earlier versions wrote) is still read.
    #[serde(
        serialize_with = "personal_to_list",
        deserialize_with = "personal_from_list"
    )]
    Personal(String),
}

fn personal_to_list<S: serde::Serializer>(owner: &str, s: S) -> Result<S::Ok, S::Error> {
    [owner].serialize(s)
}

fn personal_from_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrList {
        One(String),
        List(Vec<String>),
    }
    match OneOrList::deserialize(d)? {
        OneOrList::One(owner) => Ok(owner),
        OneOrList::List(mut list) if list.len() == 1 => Ok(list.remove(0)),
        OneOrList::List(_) => Err(serde::de::Error::custom(
            "a personal branch has exactly one owner",
        )),
    }
}

/// Orthogonal Change Readiness (Gerrit model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Wip,
    Ready,
}

/// Typed Overlay classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum OverlayKind {
    Team(String),
    Personal,
}

/// Target deployment/runtime environment for `.env.schema` resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Dev,
    Preview,
    Staging,
    Prod,
    Custom(String),
}

impl Environment {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dev" | "development" => Self::Dev,
            "preview" => Self::Preview,
            "staging" => Self::Staging,
            "prod" | "production" => Self::Prod,
            other => Self::Custom(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Dev => "dev",
            Self::Preview => "preview",
            Self::Staging => "staging",
            Self::Prod => "prod",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Structured audit decision emitted by policy, secret, and egress proxy layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Denied,
    ExfiltrationBlocked,
    Redacted,
    ApprovalRequired,
    RateLimited,
    BudgetExceeded,
}

/// Canonical audit log entry (never contains raw secret values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_task_id: Option<String>,
    pub component: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    pub decision: AuditDecision,
    pub reason: String,
    #[serde(default)]
    pub bytes_scrubbed: usize,
}

impl AuditEvent {
    pub fn now(
        identity: &DelegatedIdentity,
        component: impl Into<String>,
        action: impl Into<String>,
        decision: AuditDecision,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            principal: identity.principal.canonical_id(),
            agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
            agent_task_id: identity.agent_task.as_ref().map(|a| a.task_id.clone()),
            component: component.into(),
            action: action.into(),
            target: None,
            capability: None,
            decision,
            reason: reason.into(),
            bytes_scrubbed: 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_path_rejects_traversal_and_backslashes() {
        assert!(RepoPath::new("../secret").is_err());
        assert!(RepoPath::new("a/../b").is_err());
        assert!(RepoPath::new("a\\b").is_err());
        assert!(RepoPath::new("a\0b").is_err());

        let p = RepoPath::new("apps/web/src/index.ts").unwrap();
        assert_eq!(p.as_str(), "apps/web/src/index.ts");
        assert_eq!(p.segments(), vec!["apps", "web", "src", "index.ts"]);
        let anc: Vec<String> = p.ancestors().into_iter().map(String::from).collect();
        assert_eq!(anc, vec!["", "apps", "apps/web", "apps/web/src"]);
        assert!(RepoPath::new("apps/web").unwrap().is_ancestor_of(&p));
    }

    #[test]
    fn repo_path_rejects_host_paths_and_filesystem_aliases() {
        for alias in [
            "/etc/passwd",
            "C:/Windows/win.ini",
            "c:secret",
            "billing/ledger.rs::$DATA",
            "billing./ledger.rs",
            "billing /ledger.rs",
            "billing/ledger.rs.",
            "billing/ledger.rs ",
            "billing//ledger.rs",
            "billing/./ledger.rs",
            "billing/",
            "a\tb",
            " ",
        ] {
            assert!(RepoPath::new(alias).is_err(), "{alias:?} must be rejected");
        }
        assert!(RepoPath::new("").unwrap().is_root());
        for fine in [".access.toml", "a b/c.d", "src/..hidden", ".run/x"] {
            assert_eq!(RepoPath::new(fine).unwrap().as_str(), fine);
        }
    }

    #[test]
    fn delegated_identity_selector_matching() {
        let id = DelegatedIdentity::delegated(
            Principal::parse("@alice").unwrap(),
            vec!["billing".to_owned()],
            "ui-agent",
            "task-123",
        );
        assert!(id.matches_selector("@alice"));
        assert!(id.matches_selector("user:alice"));
        assert!(id.matches_selector("group:billing"));
        assert!(id.matches_selector("team:billing"));
        assert!(id.matches_selector("authenticated"));
        assert!(id.matches_selector("agent:*"));
        assert!(id.matches_selector("agent:ui-agent"));
        assert!(!id.matches_selector("agent:deploy-agent"));
        assert!(!id.matches_selector("anonymous"));
    }
}
