//! `.access.toml` schema types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Precedence origin of a policy rule.
///
/// Server/org policies always override in-repo `.access.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    Server,
    Repo,
}

/// Rule effect. Within a layer, `Deny` always overrides `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// Top-level `.access.toml` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicyFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub zones: BTreeMap<String, ZoneConfig>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub agent_profiles: Vec<AgentProfile>,
    #[serde(default)]
    pub quarantine: QuarantineConfig,
    /// MCP server registry (`[mcp_servers.<name>]`). Server-layer entries override Repo-layer ones.
    #[serde(default)]
    pub mcp_servers: BTreeMap<String, McpServerConfig>,
    /// MCP tool rules (`[[mcp_rules]]`). Default-deny: a tool is callable only if a rule allows it.
    #[serde(default)]
    pub mcp_rules: Vec<McpToolRule>,
    #[serde(default)]
    pub firewall: FirewallConfig,
}

fn default_version() -> u32 {
    1
}

impl Default for AccessPolicyFile {
    fn default() -> Self {
        Self {
            version: 1,
            defaults: DefaultsConfig::default(),
            zones: BTreeMap::new(),
            rules: Vec::new(),
            agent_profiles: Vec::new(),
            quarantine: QuarantineConfig::default(),
            mcp_servers: BTreeMap::new(),
            mcp_rules: Vec::new(),
            firewall: FirewallConfig::default(),
        }
    }
}

/// Default base capabilities applied before explicit allow/deny rules.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DefaultsConfig {
    /// Capabilities granted to anonymous/public principals by default.
    #[serde(default)]
    pub public: Vec<String>,
    /// Capabilities granted to authenticated principals by default.
    #[serde(default)]
    pub authenticated: Vec<String>,
    /// True when `public` was explicitly present in the parsed document (even if `[]`),
    /// distinguishing explicit default-deny from an omitted field.
    #[serde(skip)]
    public_explicit: bool,
    /// True when `authenticated` was explicitly present in the parsed document (even if `[]`).
    #[serde(skip)]
    authenticated_explicit: bool,
}

impl DefaultsConfig {
    /// True if `public` was explicitly set (including an explicit empty list `public = []`)
    /// or populated programmatically.
    pub fn has_explicit_public(&self) -> bool {
        self.public_explicit || !self.public.is_empty()
    }

    /// True if `authenticated` was explicitly set (including an explicit empty list
    /// `authenticated = []`) or populated programmatically.
    pub fn has_explicit_authenticated(&self) -> bool {
        self.authenticated_explicit || !self.authenticated.is_empty()
    }

    /// Builder that marks `public` as explicitly configured (even when empty).
    pub fn with_public(mut self, caps: Vec<String>) -> Self {
        self.public = caps;
        self.public_explicit = true;
        self
    }

    /// Builder that marks `authenticated` as explicitly configured (even when empty).
    pub fn with_authenticated(mut self, caps: Vec<String>) -> Self {
        self.authenticated = caps;
        self.authenticated_explicit = true;
        self
    }
}

#[derive(Deserialize)]
struct DefaultsConfigWire {
    #[serde(default)]
    public: Option<Vec<String>>,
    #[serde(default)]
    authenticated: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for DefaultsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DefaultsConfigWire::deserialize(deserializer)?;
        Ok(Self {
            public_explicit: wire.public.is_some(),
            public: wire.public.unwrap_or_default(),
            authenticated_explicit: wire.authenticated.is_some(),
            authenticated: wire.authenticated.unwrap_or_default(),
        })
    }
}

/// Named bidirectional Zone definition.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ZoneConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub owners: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Single allow or deny rule over principals, paths/zones, refs, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub effect: RuleEffect,
    #[serde(default)]
    pub principals: Vec<String>,
    /// Selectors carved out of `principals`: the rule never applies to an identity matching one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except_principals: Vec<String>,
    /// Direct path globs (POSIX).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Optional zone names whose path patterns this rule targets.
    #[serde(default)]
    pub zones: Vec<String>,
    /// Optional Git ref patterns (defaults to `["*"]` when omitted).
    #[serde(default)]
    pub refs: Vec<String>,
    /// Capabilities affected (`traverse`, `list`, `read`, `write`, `use`, `*`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Action taken when an AI agent session exceeds an autonomy budget or anomaly cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetAction {
    #[default]
    Pause,
    Terminate,
}

/// Blast-radius and resource autonomy budgets declared on `[[agent_profiles]]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AutonomyBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files_modified: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lines_changed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_workspace_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_jit_requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_denied_attempts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pids: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_secs: Option<u64>,
    #[serde(default)]
    pub on_budget_exceeded: BudgetAction,
}

impl AutonomyBudget {
    /// True if no numeric cap is configured on this budget.
    pub fn is_empty(&self) -> bool {
        self.max_files_modified.is_none()
            && self.max_lines_changed.is_none()
            && self.max_workspace_bytes.is_none()
            && self.max_egress_requests.is_none()
            && self.max_egress_bytes.is_none()
            && self.max_jit_requests.is_none()
            && self.max_denied_attempts.is_none()
            && self.max_memory_mb.is_none()
            && self.max_pids.is_none()
            && self.max_cpu_secs.is_none()
    }

    /// Intersect two budgets by taking the stricter (smaller) bound on each field
    /// and `Terminate` if either specifies termination.
    pub fn tighten(&self, other: &Self) -> Self {
        fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
            match (a, b) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (Some(x), None) | (None, Some(x)) => Some(x),
                (None, None) => None,
            }
        }
        let on_budget_exceeded = match (self.on_budget_exceeded, other.on_budget_exceeded) {
            (BudgetAction::Terminate, _) | (_, BudgetAction::Terminate) => BudgetAction::Terminate,
            (BudgetAction::Pause, BudgetAction::Pause) => BudgetAction::Pause,
        };
        Self {
            max_files_modified: min_opt(self.max_files_modified, other.max_files_modified),
            max_lines_changed: min_opt(self.max_lines_changed, other.max_lines_changed),
            max_workspace_bytes: min_opt(self.max_workspace_bytes, other.max_workspace_bytes),
            max_egress_requests: min_opt(self.max_egress_requests, other.max_egress_requests),
            max_egress_bytes: min_opt(self.max_egress_bytes, other.max_egress_bytes),
            max_jit_requests: min_opt(self.max_jit_requests, other.max_jit_requests),
            max_denied_attempts: min_opt(self.max_denied_attempts, other.max_denied_attempts),
            max_memory_mb: min_opt(self.max_memory_mb, other.max_memory_mb),
            max_pids: min_opt(self.max_pids, other.max_pids),
            max_cpu_secs: min_opt(self.max_cpu_secs, other.max_cpu_secs),
            on_budget_exceeded,
        }
    }
}

/// Bounded authority profile for an AI coding agent task (`permissions(human) ∩ permissions(agent_task)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfile {
    pub name: String,
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
    /// Path capabilities permitted for this agent profile (never includes raw secret READ unless explicitly opted in).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Secret variable names this agent may `USE` through the egress proxy (never `READ`).
    #[serde(default)]
    pub allow_secret_use: Vec<String>,
    /// Explicit non-secret hosts allowed during agent execution (e.g. package registries).
    #[serde(default)]
    pub allow_egress_hosts: Vec<String>,
    /// MCP tool patterns (`<server_glob>:<tool_glob>` or `*`) this agent profile may call.
    #[serde(default)]
    pub allow_mcp_tools: Vec<String>,
    /// MCP tool patterns this agent profile can never call (overrides `allow_mcp_tools`).
    #[serde(default)]
    pub deny_mcp_tools: Vec<String>,
    /// Graduated blast-radius and resource autonomy budgets.
    #[serde(flatten, default)]
    pub budget: AutonomyBudget,
}

/// Untrusted repo instruction-file quarantine settings (`CLAUDE.md`, `AGENTS.md`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineConfig {
    #[serde(default = "default_instruction_files")]
    pub instruction_files: Vec<String>,
    /// Repo-owner pinned SHA-256 hashes (hex) for instruction files.
    #[serde(default)]
    pub pinned_hashes: BTreeMap<String, String>,
    /// Block pushes that touch instruction files (effective default `true`;
    /// Server `Some(true)` overrides Repo `Some(false)`).
    #[serde(default)]
    pub enforce: Option<bool>,
    /// Hold non-owner instruction-file changes pending owner approval (effective default `true`).
    #[serde(default)]
    pub hold_pending_for_non_owners: Option<bool>,
    /// Extra egress hosts instruction files may reference without a quarantine finding.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// True when `allowed_hosts` was explicitly present in the parsed document (even if `[]`).
    #[serde(skip)]
    allowed_hosts_explicit: bool,
}

impl QuarantineConfig {
    /// True if `allowed_hosts` was explicitly configured (including `allowed_hosts = []`)
    /// or populated programmatically.
    pub fn has_explicit_allowed_hosts(&self) -> bool {
        self.allowed_hosts_explicit || !self.allowed_hosts.is_empty()
    }

    /// Builder that marks `allowed_hosts` as explicitly configured (even when empty).
    pub fn with_allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = hosts;
        self.allowed_hosts_explicit = true;
        self
    }
}

#[derive(Deserialize)]
struct QuarantineConfigWire {
    #[serde(default = "default_instruction_files")]
    instruction_files: Vec<String>,
    #[serde(default)]
    pinned_hashes: BTreeMap<String, String>,
    #[serde(default)]
    enforce: Option<bool>,
    #[serde(default)]
    hold_pending_for_non_owners: Option<bool>,
    #[serde(default)]
    allowed_hosts: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for QuarantineConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = QuarantineConfigWire::deserialize(deserializer)?;
        Ok(Self {
            instruction_files: wire.instruction_files,
            pinned_hashes: wire.pinned_hashes,
            enforce: wire.enforce,
            hold_pending_for_non_owners: wire.hold_pending_for_non_owners,
            allowed_hosts_explicit: wire.allowed_hosts.is_some(),
            allowed_hosts: wire.allowed_hosts.unwrap_or_default(),
        })
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            instruction_files: default_instruction_files(),
            pinned_hashes: BTreeMap::new(),
            enforce: None,
            hold_pending_for_non_owners: None,
            allowed_hosts: Vec::new(),
            allowed_hosts_explicit: false,
        }
    }
}

/// Declassification firewall settings (cross-boundary leak + secret push protection).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct FirewallConfig {
    /// Effective default `true`; Server `Some(true)` overrides Repo `Some(false)`.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Code names / identifiers that must never appear in public content.
    #[serde(default)]
    pub sensitive_identifiers: Vec<String>,
    /// Minimum normalized contiguous snippet length (effective default 48, clamped >= 24).
    #[serde(default)]
    pub min_snippet_bytes: Option<usize>,
    /// Verified contiguous matches needed to flag a file (effective default 1).
    #[serde(default)]
    pub min_shingle_matches: Option<usize>,
    /// Effective default `true`; Server `Some(false)` overrides Repo.
    #[serde(default)]
    pub allow_owner_override: Option<bool>,
    /// Public path globs excluded from metadata/snippet leak checks.
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    /// True when `ignore_paths` was explicitly present in the parsed document (even if `[]`).
    #[serde(skip)]
    ignore_paths_explicit: bool,
}

impl FirewallConfig {
    /// True if `ignore_paths` was explicitly configured (including `ignore_paths = []`)
    /// or populated programmatically.
    pub fn has_explicit_ignore_paths(&self) -> bool {
        self.ignore_paths_explicit || !self.ignore_paths.is_empty()
    }

    /// Builder that marks `ignore_paths` as explicitly configured (even when empty).
    pub fn with_ignore_paths(mut self, paths: Vec<String>) -> Self {
        self.ignore_paths = paths;
        self.ignore_paths_explicit = true;
        self
    }
}

#[derive(Deserialize)]
struct FirewallConfigWire {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    sensitive_identifiers: Vec<String>,
    #[serde(default)]
    min_snippet_bytes: Option<usize>,
    #[serde(default)]
    min_shingle_matches: Option<usize>,
    #[serde(default)]
    allow_owner_override: Option<bool>,
    #[serde(default)]
    ignore_paths: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for FirewallConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = FirewallConfigWire::deserialize(deserializer)?;
        Ok(Self {
            enabled: wire.enabled,
            sensitive_identifiers: wire.sensitive_identifiers,
            min_snippet_bytes: wire.min_snippet_bytes,
            min_shingle_matches: wire.min_shingle_matches,
            allow_owner_override: wire.allow_owner_override,
            ignore_paths_explicit: wire.ignore_paths.is_some(),
            ignore_paths: wire.ignore_paths.unwrap_or_default(),
        })
    }
}

fn default_instruction_files() -> Vec<String> {
    vec![
        "AGENTS.md",
        "CLAUDE.md",
        "**/AGENTS.md",
        "**/CLAUDE.md",
        ".cursorrules",
        "**/.cursorrules",
        ".cursor/rules/**",
        ".github/copilot-instructions.md",
        "**/.github/copilot-instructions.md",
        ".mcp.json",
        "**/.mcp.json",
        ".claude/**",
        ".github/workflows/**",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

// ---------------------------------------------------------------------------
// MCP tool gateway schema
// ---------------------------------------------------------------------------

/// How the gateway reaches an MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    #[default]
    Stdio,
    HttpSse,
}

/// Blast radius of a tool call. `Read < Write < Destructive`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum McpRiskLevel {
    #[default]
    Read,
    Write,
    Destructive,
}

/// Approval required before a call runs. `Auto < Jit < Deny` (higher is stricter).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum McpApprovalMode {
    Auto,
    #[default]
    Jit,
    Deny,
}

/// Binds a secret to an MCP server by name; the gateway injects it host-side (`use != read`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "inject", rename_all = "snake_case")]
pub enum McpCredentialBinding {
    /// Set an environment variable on the spawned server (defaults to the secret's own name).
    Env {
        secret: String,
        #[serde(default)]
        env_var: Option<String>,
    },
    /// `Authorization: Bearer <secret>` (or a custom header name).
    BearerHeader {
        secret: String,
        #[serde(default = "default_auth_header")]
        header: String,
    },
    /// `<header>: <prefix><secret>`.
    Header {
        secret: String,
        header: String,
        #[serde(default)]
        prefix: String,
    },
}

fn default_auth_header() -> String {
    "Authorization".to_owned()
}

impl McpCredentialBinding {
    /// Name of the secret variable this binding injects.
    pub fn secret_name(&self) -> &str {
        match self {
            Self::Env { secret, .. }
            | Self::BearerHeader { secret, .. }
            | Self::Header { secret, .. } => secret,
        }
    }

    /// Stable tag for the injection mechanism (audit/UI).
    pub fn inject_kind(&self) -> &'static str {
        match self {
            Self::Env { .. } => "env",
            Self::BearerHeader { .. } => "bearer_header",
            Self::Header { .. } => "header",
        }
    }
}

/// One `[mcp_servers.<name>]` registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerConfig {
    #[serde(default)]
    pub transport: McpTransportKind,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub credentials: Vec<McpCredentialBinding>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Tool name -> pinned SHA-256 (hex) of its definition (rug-pull / tool-poisoning defence).
    #[serde(default)]
    pub pinned_tool_hashes: BTreeMap<String, String>,
    #[serde(default)]
    pub default_approval: Option<McpApprovalMode>,
    #[serde(default = "default_jit_ttl_secs")]
    pub jit_ttl_secs: u64,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_true")]
    pub pin_on_first_use: bool,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            transport: McpTransportKind::default(),
            command: None,
            args: Vec::new(),
            url: None,
            env: BTreeMap::new(),
            headers: BTreeMap::new(),
            credentials: Vec::new(),
            zone: None,
            description: None,
            pinned_tool_hashes: BTreeMap::new(),
            default_approval: None,
            jit_ttl_secs: default_jit_ttl_secs(),
            timeout_secs: default_timeout_secs(),
            pin_on_first_use: true,
        }
    }
}

fn default_jit_ttl_secs() -> u64 {
    300
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

/// Argument constraint enforced on a tool call before it reaches the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpArgConstraint {
    /// The argument is a repo path (or list of paths) the caller must hold `capability` on.
    PathZone {
        arg: String,
        #[serde(default = "default_path_cap")]
        capability: String,
        #[serde(default)]
        allow_globs: Vec<String>,
        #[serde(default)]
        deny_globs: Vec<String>,
    },
    /// Glob match on the (whitespace-normalised) string value; `*` crosses `/` and spaces.
    Pattern {
        arg: String,
        #[serde(default)]
        allow_patterns: Vec<String>,
        #[serde(default)]
        deny_patterns: Vec<String>,
        #[serde(default)]
        case_insensitive: bool,
    },
    /// The argument must be exactly one of `values`.
    AllowedValues { arg: String, values: Vec<String> },
    /// The argument must not be supplied at all.
    ForbidArg { arg: String },
}

fn default_path_cap() -> String {
    "read".to_owned()
}

impl McpArgConstraint {
    /// Dotted argument path this constraint inspects.
    pub fn arg(&self) -> &str {
        match self {
            Self::PathZone { arg, .. }
            | Self::Pattern { arg, .. }
            | Self::AllowedValues { arg, .. }
            | Self::ForbidArg { arg } => arg,
        }
    }

    /// Concise one-line description for UI/audit display.
    pub fn summary(&self) -> String {
        match self {
            Self::PathZone {
                arg,
                capability,
                allow_globs,
                deny_globs,
            } => format!(
                "{arg}: path needs '{capability}' (allow {}, deny {})",
                allow_globs.len(),
                deny_globs.len()
            ),
            Self::Pattern {
                arg,
                allow_patterns,
                deny_patterns,
                ..
            } => format!(
                "{arg}: pattern (allow {}, deny {})",
                allow_patterns.len(),
                deny_patterns.len()
            ),
            Self::AllowedValues { arg, values } => {
                format!("{arg}: one of [{}]", values.join(", "))
            }
            Self::ForbidArg { arg } => format!("{arg}: forbidden"),
        }
    }
}

/// `[[mcp_rules]]` allow/deny rule over principals, `<server>:<tool>` patterns and refs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolRule {
    pub id: String,
    pub effect: RuleEffect,
    #[serde(default)]
    pub principals: Vec<String>,
    /// `<server_glob>:<tool_glob>` patterns, or `*` for every tool on every server.
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub risk: Option<McpRiskLevel>,
    #[serde(default)]
    pub approval: Option<McpApprovalMode>,
    #[serde(default)]
    pub jit_ttl_secs: Option<u64>,
    #[serde(default)]
    pub arg_constraints: Vec<McpArgConstraint>,
    #[serde(default)]
    pub required_secrets: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}
