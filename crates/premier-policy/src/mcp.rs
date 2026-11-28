//! Policy-unified MCP tool gateway: `<server>:<tool>` rule compiler, default-deny decision
//! engine (`human ∩ agent_profile`), and argument-constraint validation.
//!
//! MCP tools are **default-deny**: a call is allowed only when an `[[mcp_rules]]` allow rule
//! matches, no deny rule overrides it, and (for agents) the agent profile also allows it.
//! Precedence mirrors path policy: within a layer Deny beats Allow; Server beats Repo.

use std::collections::{BTreeMap, BTreeSet};

use globset::{GlobBuilder, GlobMatcher};
use premier_core::{Capability, DelegatedIdentity, RepoPath};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::PolicyError;
use crate::schema::{
    AccessPolicyFile, McpApprovalMode, McpArgConstraint, McpRiskLevel, McpServerConfig,
    McpToolRule, PolicyLayer, RuleEffect,
};
use crate::trie::{
    CompiledGlob, CompiledPolicy, MAX_PATTERN_LEN, MAX_PATTERNS_PER_RULE, MAX_RULES, check_limit,
    check_pattern_limits, ref_globs_match,
};

/// Upper bound on distinct MCP servers in one compiled policy.
pub const MAX_MCP_SERVERS: usize = 128;
const MAX_MCP_SAMPLES: usize = 2048;
/// Path components no MCP tool argument may ever address (VCS / Premier control directories).
const RESERVED_PATH_COMPONENTS: &[&str] = &[".git", ".premier", ".premier-local"];

fn is_ignorable_path_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
    )
}

fn is_reserved_path_component(seg: &str) -> bool {
    let stripped: String = seg
        .chars()
        .filter(|c| !is_ignorable_path_char(*c))
        .collect();
    // NTFS Alternate Data Streams (`name:stream`) resolve to `name`, and NTFS ignores trailing
    // dots and spaces.
    let base = stripped
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches(['.', ' ']);
    if RESERVED_PATH_COMPONENTS
        .iter()
        .any(|r| base.eq_ignore_ascii_case(r))
    {
        return true;
    }
    // Windows 8.3 short-name aliases for `.git`, `.premier`, `.premier-local` (standard `GIT~1`,
    // `PREMIE~1.LOC`, and NTFS hash-based short names such as `GI7EBA~1` / `PRxxxx~1`).
    if let Some((prefix, suffix)) = base.split_once('~') {
        let digits = suffix.split('.').next().unwrap_or("");
        let lower_prefix = prefix.to_ascii_lowercase();
        let is_short_alias = matches!(lower_prefix.as_str(), "git" | "premie")
            || (lower_prefix.len() == 6
                && (lower_prefix.starts_with("gi") || lower_prefix.starts_with("pr"))
                && lower_prefix.as_bytes()[2..]
                    .iter()
                    .all(|b| b.is_ascii_hexdigit()));
        if is_short_alias && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    false
}

fn invalid(msg: impl Into<String>) -> PolicyError {
    PolicyError::InvalidMcpPolicy(msg.into())
}

/// Re-label glob syntax errors as MCP policy errors; keep complexity errors as they are.
fn glob_err(ctx: &str, err: PolicyError) -> PolicyError {
    match err {
        PolicyError::InvalidGlob { pattern, source } => {
            invalid(format!("{ctx}: invalid glob '{pattern}': {source}"))
        }
        other => other,
    }
}

fn build_glob(
    raw: &str,
    literal_separator: bool,
    case_insensitive: bool,
) -> Result<GlobMatcher, globset::Error> {
    Ok(GlobBuilder::new(raw)
        .literal_separator(literal_separator)
        .backslash_escape(true)
        .case_insensitive(case_insensitive)
        .build()?
        .compile_matcher())
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// ---------------------------------------------------------------------------
// Tool patterns
// ---------------------------------------------------------------------------

/// One half (server or tool) of a `<server_glob>:<tool_glob>` pattern.
#[derive(Debug, Clone)]
struct NameGlob {
    raw: String,
    /// `None` matches every name (`*` / `**`).
    matcher: Option<GlobMatcher>,
}

impl NameGlob {
    fn compile(raw: &str, whole: &str, part: &str) -> Result<Self, PolicyError> {
        if raw.is_empty() {
            return Err(invalid(format!(
                "tool pattern '{whole}' has an empty {part} part (expected '<server>:<tool>' or '*')"
            )));
        }
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid(format!(
                "tool pattern '{whole}': {part} part must not contain whitespace or control characters"
            )));
        }
        check_pattern_limits(raw)?;
        // `*` and `?` never cross `/`; a bare `*` / `**` is "any name".
        let matcher = if raw == "*" || raw == "**" {
            None
        } else {
            Some(build_glob(raw, true, false).map_err(|e| {
                invalid(format!(
                    "tool pattern '{whole}': invalid {part} glob '{raw}': {e}"
                ))
            })?)
        };
        Ok(Self {
            raw: raw.to_owned(),
            matcher,
        })
    }

    fn matches(&self, name: &str) -> bool {
        self.matcher.as_ref().is_none_or(|m| m.is_match(name))
    }

    fn is_literal(&self) -> bool {
        !self.raw.contains(['*', '?', '[', ']', '{', '}', '\\'])
    }

    /// A representative concrete name for a wildcard glob (`delete_*` -> `delete_<filler>`).
    fn synthesize(&self, filler: &str) -> Option<String> {
        if self.is_literal() {
            return Some(self.raw.clone());
        }
        if self.raw.contains(['[', '{', '\\']) {
            return None;
        }
        let mut out = String::new();
        let mut prev_star = false;
        for c in self.raw.chars() {
            match c {
                '*' => {
                    if !prev_star {
                        out.push_str(filler);
                    }
                    prev_star = true;
                }
                '?' => {
                    out.push('x');
                    prev_star = false;
                }
                other => {
                    out.push(other);
                    prev_star = false;
                }
            }
        }
        self.matches(&out).then_some(out)
    }
}

/// Compiled `<server_glob>:<tool_glob>` pattern. The two halves compile independently so a
/// wildcard in one can never swallow the `:` separator.
#[derive(Debug, Clone)]
pub(crate) struct McpToolPattern {
    server: NameGlob,
    tool: NameGlob,
}

impl McpToolPattern {
    pub(crate) fn compile(pattern: &str) -> Result<Self, PolicyError> {
        let whole = pattern.trim();
        if whole == "*" {
            return Ok(Self {
                server: NameGlob::compile("*", whole, "server")?,
                tool: NameGlob::compile("*", whole, "tool")?,
            });
        }
        let Some((server, tool)) = whole.split_once(':') else {
            return Err(invalid(format!(
                "tool pattern '{pattern}' must be '<server>:<tool>' or '*'"
            )));
        };
        Ok(Self {
            server: NameGlob::compile(server, whole, "server")?,
            tool: NameGlob::compile(tool, whole, "tool")?,
        })
    }

    pub(crate) fn matches(&self, server: &str, tool: &str) -> bool {
        self.server.matches(server) && self.tool.matches(tool)
    }
}

// ---------------------------------------------------------------------------
// Compiled policy pieces
// ---------------------------------------------------------------------------

/// Effective registry entry after Server-over-Repo merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMcpServer {
    /// Layer whose definition won (Server overrides Repo).
    pub layer: PolicyLayer,
    pub name: String,
    /// Winning config; `pinned_tool_hashes` is the merge of both layers (Server pins win).
    pub config: McpServerConfig,
    /// Tool names whose pin hash was set by the trusted Server layer.
    pub server_pinned_tools: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct CompiledMcpRule {
    id: String,
    layer: PolicyLayer,
    effect: RuleEffect,
    principals: Vec<String>,
    has_agent_selector: bool,
    tools: Vec<McpToolPattern>,
    ref_globs: Vec<CompiledGlob>,
    risk: Option<McpRiskLevel>,
    approval: Option<McpApprovalMode>,
    jit_ttl_secs: Option<u64>,
    arg_constraints: Vec<McpArgConstraint>,
    required_secrets: Vec<String>,
    reason: Option<String>,
}

impl CompiledMcpRule {
    fn compile(layer: PolicyLayer, rule: &McpToolRule) -> Result<Self, PolicyError> {
        if rule.id.trim().is_empty() {
            return Err(invalid("mcp rule id must not be empty"));
        }
        if rule.tools.is_empty() {
            return Err(invalid(format!(
                "mcp rule '{}' must list at least one tool pattern",
                rule.id
            )));
        }
        check_limit(
            "patterns in one mcp rule",
            rule.tools.len() + rule.refs.len() + rule.arg_constraints.len(),
            MAX_PATTERNS_PER_RULE,
        )?;
        let ctx = format!("mcp rule '{}'", rule.id);
        let tools = rule
            .tools
            .iter()
            .map(|t| McpToolPattern::compile(t).map_err(|e| prefix_err(&ctx, e)))
            .collect::<Result<Vec<_>, _>>()?;
        let ref_globs = rule
            .refs
            .iter()
            .map(|r| CompiledGlob::new(r).map_err(|e| glob_err(&ctx, e)))
            .collect::<Result<Vec<_>, _>>()?;
        for c in &rule.arg_constraints {
            validate_constraint(&rule.id, c)?;
        }
        Ok(Self {
            id: rule.id.clone(),
            layer,
            effect: rule.effect,
            has_agent_selector: rule
                .principals
                .iter()
                .any(|p| p.trim().starts_with("agent:")),
            principals: rule.principals.clone(),
            tools,
            ref_globs,
            risk: rule.risk,
            approval: rule.approval,
            jit_ttl_secs: rule.jit_ttl_secs,
            arg_constraints: rule.arg_constraints.clone(),
            required_secrets: rule.required_secrets.clone(),
            reason: rule.reason.clone(),
        })
    }

    fn matches_principal(&self, identity: &DelegatedIdentity) -> bool {
        self.principals
            .iter()
            .any(|sel| identity.matches_selector(sel))
    }

    fn matches_ref(&self, ref_name: &str) -> bool {
        ref_globs_match(&self.ref_globs, ref_name)
    }

    fn matches_tool(&self, server: &str, tool: &str) -> bool {
        self.tools.iter().any(|t| t.matches(server, tool))
    }
}

fn prefix_err(ctx: &str, err: PolicyError) -> PolicyError {
    match err {
        PolicyError::InvalidMcpPolicy(m) => invalid(format!("{ctx}: {m}")),
        other => other,
    }
}

fn validate_constraint(rule_id: &str, c: &McpArgConstraint) -> Result<(), PolicyError> {
    let arg = c.arg();
    let ctx = format!("mcp rule '{rule_id}' constraint on '{arg}'");
    if arg.is_empty() || arg.split('.').any(str::is_empty) {
        return Err(invalid(format!(
            "{ctx}: argument path must be non-empty dotted segments"
        )));
    }
    check_limit(
        "constraint argument path length",
        arg.len(),
        MAX_PATTERN_LEN,
    )?;
    match c {
        McpArgConstraint::PathZone {
            capability,
            allow_globs,
            deny_globs,
            ..
        } => {
            Capability::parse_name(capability)
                .map_err(|e| invalid(format!("{ctx}: invalid capability: {e}")))?;
            check_limit(
                "globs in one path constraint",
                allow_globs.len() + deny_globs.len(),
                MAX_PATTERNS_PER_RULE,
            )?;
            for g in allow_globs.iter().chain(deny_globs) {
                CompiledGlob::new(g).map_err(|e| glob_err(&ctx, e))?;
            }
        }
        McpArgConstraint::Pattern {
            allow_patterns,
            deny_patterns,
            case_insensitive,
            ..
        } => {
            check_limit(
                "patterns in one value constraint",
                allow_patterns.len() + deny_patterns.len(),
                MAX_PATTERNS_PER_RULE,
            )?;
            for p in allow_patterns.iter().chain(deny_patterns) {
                check_limit("value pattern length", p.len(), MAX_PATTERN_LEN)?;
                check_limit(
                    "value pattern brace alternates",
                    p.matches('{').count(),
                    crate::trie::MAX_BRACE_ALTERNATES,
                )?;
                build_glob(p, false, *case_insensitive)
                    .map_err(|e| invalid(format!("{ctx}: invalid pattern '{p}': {e}")))?;
            }
        }
        McpArgConstraint::AllowedValues { values, .. } => {
            check_limit("allowed values", values.len(), MAX_RULES)?;
        }
        McpArgConstraint::ForbidArg { .. } => {}
    }
    Ok(())
}

/// MCP half of a [`CompiledPolicy`]: merged server registry plus compiled tool rules.
#[derive(Debug, Clone, Default)]
pub(crate) struct McpPolicy {
    servers: BTreeMap<String, CompiledMcpServer>,
    rules: Vec<CompiledMcpRule>,
}

impl McpPolicy {
    pub(crate) fn compile(
        server_policy: Option<&AccessPolicyFile>,
        repo_policy: &AccessPolicyFile,
    ) -> Result<Self, PolicyError> {
        let mut servers: BTreeMap<String, CompiledMcpServer> = BTreeMap::new();
        for (name, config) in &repo_policy.mcp_servers {
            check_server_name(name)?;
            servers.insert(
                name.clone(),
                CompiledMcpServer {
                    layer: PolicyLayer::Repo,
                    name: name.clone(),
                    config: config.clone(),
                    server_pinned_tools: BTreeSet::new(),
                },
            );
        }
        check_limit("mcp server count", servers.len(), MAX_MCP_SERVERS)?;
        if let Some(srv) = server_policy {
            for (name, config) in &srv.mcp_servers {
                check_server_name(name)?;
                let mut config = config.clone();
                let server_pinned_tools: BTreeSet<String> =
                    config.pinned_tool_hashes.keys().cloned().collect();
                if let Some(prev) = servers.get(name) {
                    // Server pins always win; Repo pins the Server layer is silent on survive.
                    let mut pins = prev.config.pinned_tool_hashes.clone();
                    pins.extend(std::mem::take(&mut config.pinned_tool_hashes));
                    config.pinned_tool_hashes = pins;
                }
                servers.insert(
                    name.clone(),
                    CompiledMcpServer {
                        layer: PolicyLayer::Server,
                        name: name.clone(),
                        config,
                        server_pinned_tools,
                    },
                );
            }
            check_limit("mcp server count", servers.len(), MAX_MCP_SERVERS)?;
        }

        check_limit(
            "mcp rule count",
            repo_policy.mcp_rules.len() + server_policy.map_or(0, |s| s.mcp_rules.len()),
            MAX_RULES,
        )?;
        let mut rules = Vec::new();
        for rule in &repo_policy.mcp_rules {
            rules.push(CompiledMcpRule::compile(PolicyLayer::Repo, rule)?);
        }
        if let Some(srv) = server_policy {
            for rule in &srv.mcp_rules {
                rules.push(CompiledMcpRule::compile(PolicyLayer::Server, rule)?);
            }
        }
        Ok(Self { servers, rules })
    }
}

fn check_server_name(name: &str) -> Result<(), PolicyError> {
    if valid_server_name(name) {
        Ok(())
    } else {
        Err(invalid(format!(
            "mcp server name '{name}' must be non-empty and match [a-zA-Z0-9._-]+"
        )))
    }
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// Trace entry for a rule that matched an MCP tool evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpMatchedRuleTrace {
    pub id: String,
    pub layer: PolicyLayer,
    pub effect: RuleEffect,
    /// True when the rule only applied through an `agent:*` / `agent:<profile>` selector.
    #[serde(default)]
    pub agent_scoped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Deterministic decision and audit trace for one `<server>:<tool>` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolDecision {
    pub server: String,
    pub tool: String,
    /// `"<server>:<tool>"`.
    pub full_name: String,
    pub principal: String,
    pub agent_profile: Option<String>,
    /// Final verdict: `human_allowed ∩ agent_allowed ∩ approval != deny`.
    pub allowed: bool,
    pub human_allowed: bool,
    pub agent_allowed: Option<bool>,
    pub risk: McpRiskLevel,
    pub approval: McpApprovalMode,
    /// Lifetime of a JIT grant; `0` means single-use.
    pub jit_ttl_secs: u64,
    pub required_secrets: Vec<String>,
    pub arg_constraints: Vec<McpArgConstraint>,
    pub matched_rules: Vec<McpMatchedRuleTrace>,
    pub reason: String,
}

#[derive(Default)]
struct LayerAgg {
    allow: bool,
    deny: bool,
    approval: Option<McpApprovalMode>,
    ttl: Option<u64>,
}

fn tighten_approval(slot: &mut Option<McpApprovalMode>, a: Option<McpApprovalMode>) {
    if let Some(a) = a {
        *slot = Some(slot.map_or(a, |cur| cur.max(a)));
    }
}

fn tighten_ttl(slot: &mut Option<u64>, t: Option<u64>) {
    if let Some(t) = t {
        *slot = Some(slot.map_or(t, |cur| cur.min(t)));
    }
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

fn rule_ids(traces: &[McpMatchedRuleTrace], f: impl Fn(&McpMatchedRuleTrace) -> bool) -> String {
    traces
        .iter()
        .filter(|t| f(t))
        .map(|t| t.id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl CompiledPolicy {
    /// All merged MCP servers, keyed by name.
    pub fn mcp_servers(&self) -> &BTreeMap<String, CompiledMcpServer> {
        &self.mcp.servers
    }

    pub fn mcp_server(&self, name: &str) -> Option<&CompiledMcpServer> {
        self.mcp.servers.get(name)
    }

    /// Pinned definition hash for `tool` on `server` (Server pins override Repo pins).
    pub fn pinned_mcp_tool_hash(&self, server: &str, tool: &str) -> Option<&str> {
        self.mcp
            .servers
            .get(server)?
            .config
            .pinned_tool_hashes
            .get(tool)
            .map(String::as_str)
    }

    /// Pinned definition hash for `tool` on `server` together with `true` if the pin came
    /// from the trusted Server layer (`false` if only set in Repo `.access.toml`).
    pub fn pinned_mcp_tool_hash_with_layer(
        &self,
        server: &str,
        tool: &str,
    ) -> Option<(&str, bool)> {
        let srv = self.mcp.servers.get(server)?;
        let hash = srv.config.pinned_tool_hashes.get(tool)?.as_str();
        Some((hash, srv.server_pinned_tools.contains(tool)))
    }

    /// Concrete tool names declared for `server` via pins or literal `mcp_rules` patterns.
    pub fn mcp_literal_tools(&self, server: &str) -> Vec<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        if let Some(srv) = self.mcp.servers.get(server) {
            out.extend(srv.config.pinned_tool_hashes.keys().cloned());
        }
        for rule in &self.mcp.rules {
            for pat in &rule.tools {
                if pat.server.matches(server) && pat.tool.is_literal() {
                    out.insert(pat.tool.raw.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// Conservative pre-flight check before spawning or connecting to `server`: returns `false`
    /// only when it is impossible for `identity` (on `ref_name`, if given) to call any tool on
    /// `server` under the compiled rules and agent profile.
    pub fn can_potentially_access_mcp_server(
        &self,
        identity: &DelegatedIdentity,
        server: &str,
        ref_name: Option<&str>,
    ) -> bool {
        if !valid_server_name(server) {
            return false;
        }
        let human_id =
            DelegatedIdentity::human_only(identity.principal.clone(), identity.groups.clone());
        let matches_ref = |rule: &CompiledMcpRule, exact: bool| -> bool {
            match ref_name {
                Some(r) => rule.matches_ref(r),
                None => !exact || rule.ref_globs.is_empty(),
            }
        };

        // Any unconditional Server blanket deny (`*` or `<server>:*`) rules out the whole server.
        let srv_blanket_deny = self.mcp.rules.iter().any(|r| {
            r.layer == PolicyLayer::Server
                && r.effect == RuleEffect::Deny
                && matches_ref(r, true)
                && r.matches_principal(&human_id)
                && r.tools
                    .iter()
                    .any(|p| p.server.matches(server) && p.tool.matcher.is_none())
        });
        if srv_blanket_deny {
            return false;
        }

        let repo_blanket_deny = self.mcp.rules.iter().any(|r| {
            r.layer == PolicyLayer::Repo
                && r.effect == RuleEffect::Deny
                && matches_ref(r, true)
                && r.matches_principal(&human_id)
                && r.tools
                    .iter()
                    .any(|p| p.server.matches(server) && p.tool.matcher.is_none())
        });

        let mut surviving_wildcard = false;
        let mut surviving_literals: BTreeSet<String> = BTreeSet::new();
        for rule in &self.mcp.rules {
            if rule.effect != RuleEffect::Allow
                || rule.approval == Some(McpApprovalMode::Deny)
                || !matches_ref(rule, false)
                || !rule.matches_principal(&human_id)
            {
                continue;
            }
            if rule.layer == PolicyLayer::Repo && repo_blanket_deny {
                continue;
            }
            for pat in &rule.tools {
                if pat.server.matches(server) {
                    if pat.tool.is_literal() {
                        surviving_literals.insert(pat.tool.raw.clone());
                    } else {
                        surviving_wildcard = true;
                    }
                }
            }
        }
        if !surviving_wildcard && surviving_literals.is_empty() {
            return false;
        }

        if let Some(task) = identity.agent_task.as_ref() {
            let Some((allow_mcp_tools, deny_mcp_tools)) =
                self.agent_profile_mcp_patterns(&task.profile)
            else {
                return false;
            };
            let agent_blanket_deny = deny_mcp_tools
                .iter()
                .any(|p| p.server.matches(server) && p.tool.matcher.is_none())
                || self.mcp.rules.iter().any(|r| {
                    r.effect == RuleEffect::Deny
                        && r.has_agent_selector
                        && matches_ref(r, true)
                        && r.matches_principal(identity)
                        && r.tools
                            .iter()
                            .any(|p| p.server.matches(server) && p.tool.matcher.is_none())
                });
            if agent_blanket_deny {
                return false;
            }
            let profile_allows_server = allow_mcp_tools.iter().any(|p| p.server.matches(server));
            if !profile_allows_server {
                return false;
            }
            if !surviving_wildcard {
                let any_profile_literal_hit = surviving_literals.iter().any(|t| {
                    self.agent_profile_allows_mcp(&task.profile, server, t) == Some(true)
                        && ref_name
                            .is_none_or(|r| self.evaluate_mcp_tool(identity, server, t, r).allowed)
                });
                return any_profile_literal_hit;
            }
        } else if !surviving_wildcard && let Some(r) = ref_name {
            return surviving_literals
                .iter()
                .any(|t| self.evaluate_mcp_tool(identity, server, t, r).allowed);
        }

        true
    }

    /// Concrete `(server, tool)` pairs derived from `mcp_rules`, used to diff MCP access between
    /// two policies. Literal patterns yield themselves; wildcards expand against configured
    /// servers and their pinned tool names, plus one synthesized representative.
    pub fn mcp_rule_tool_samples(&self) -> Vec<(String, String)> {
        let mut out: BTreeSet<(String, String)> = BTreeSet::new();
        for rule in &self.mcp.rules {
            for pat in &rule.tools {
                let mut servers: Vec<String> = Vec::new();
                if pat.server.is_literal() {
                    servers.push(pat.server.raw.clone());
                } else {
                    servers.extend(
                        self.mcp
                            .servers
                            .keys()
                            .filter(|n| pat.server.matches(n))
                            .cloned(),
                    );
                    if servers.is_empty() {
                        servers.extend(pat.server.synthesize("server"));
                    }
                }
                for server in servers {
                    let mut tools: Vec<String> = Vec::new();
                    if pat.tool.is_literal() {
                        tools.push(pat.tool.raw.clone());
                    } else {
                        if let Some(cfg) = self.mcp.servers.get(&server) {
                            tools.extend(
                                cfg.config
                                    .pinned_tool_hashes
                                    .keys()
                                    .filter(|t| pat.tool.matches(t))
                                    .cloned(),
                            );
                        }
                        tools.extend(pat.tool.synthesize("tool"));
                    }
                    for tool in tools {
                        if out.len() >= MAX_MCP_SAMPLES {
                            return out.into_iter().collect();
                        }
                        out.insert((server.clone(), tool));
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    /// Decide whether `identity` may call `server:tool` on `ref_name`.
    ///
    /// Default-deny. `human_allowed = ((repo allow ∧ ¬repo deny) ∨ server allow) ∧ ¬server deny`;
    /// an agent additionally needs its profile's `allow_mcp_tools` (minus `deny_mcp_tools`) and
    /// no matching `agent:` deny rule, and can only ever tighten approval, risk and TTL.
    pub fn evaluate_mcp_tool(
        &self,
        identity: &DelegatedIdentity,
        server: &str,
        tool: &str,
        ref_name: &str,
    ) -> McpToolDecision {
        let agent_task = identity.agent_task.as_ref();
        let mut decision = McpToolDecision {
            server: server.to_owned(),
            tool: tool.to_owned(),
            full_name: format!("{server}:{tool}"),
            principal: identity.principal.canonical_id(),
            agent_profile: agent_task.map(|a| a.profile.clone()),
            allowed: false,
            human_allowed: false,
            agent_allowed: agent_task.map(|_| false),
            risk: McpRiskLevel::Read,
            approval: McpApprovalMode::Deny,
            jit_ttl_secs: 0,
            required_secrets: Vec::new(),
            arg_constraints: Vec::new(),
            matched_rules: Vec::new(),
            reason: String::new(),
        };
        // Path separators in a tool name could slip past `*` (which never crosses `/`), so
        // such names are refused outright rather than risk a deny glob failing open.
        if !valid_server_name(server)
            || tool.is_empty()
            || tool.contains(['/', '\\'])
            || tool.chars().any(char::is_control)
        {
            decision.reason = "invalid MCP server or tool name".to_owned();
            return decision;
        }

        let human_id =
            DelegatedIdentity::human_only(identity.principal.clone(), identity.groups.clone());
        let server_entry = self.mcp.servers.get(server);
        let server_cfg = server_entry.map(|s| &s.config);

        let mut repo = LayerAgg::default();
        let mut srv = LayerAgg::default();
        let mut agent_denied = false;
        let mut agent_approval: Option<McpApprovalMode> = None;
        let mut agent_ttl: Option<u64> = None;
        let mut risk: Option<McpRiskLevel> = None;
        let mut rule_secrets: Vec<String> = Vec::new();
        let mut constraints: Vec<McpArgConstraint> = Vec::new();
        let mut traces: Vec<McpMatchedRuleTrace> = Vec::new();

        for rule in &self.mcp.rules {
            if !rule.matches_ref(ref_name) || !rule.matches_tool(server, tool) {
                continue;
            }
            let human_hit = rule.matches_principal(&human_id);
            let agent_hit =
                agent_task.is_some() && rule.has_agent_selector && rule.matches_principal(identity);
            if !human_hit && !agent_hit {
                continue;
            }
            traces.push(McpMatchedRuleTrace {
                id: rule.id.clone(),
                layer: rule.layer,
                effect: rule.effect,
                agent_scoped: !human_hit,
                reason: rule.reason.clone(),
            });
            if let Some(r) = rule.risk {
                risk = Some(risk.map_or(r, |cur| cur.max(r)));
            }
            if rule.effect == RuleEffect::Allow {
                for s in &rule.required_secrets {
                    push_unique(&mut rule_secrets, s.clone());
                }
                for c in &rule.arg_constraints {
                    push_unique(&mut constraints, c.clone());
                }
            }
            if human_hit {
                let agg = match rule.layer {
                    PolicyLayer::Repo => &mut repo,
                    PolicyLayer::Server => &mut srv,
                };
                match rule.effect {
                    RuleEffect::Allow => {
                        agg.allow = true;
                        tighten_approval(&mut agg.approval, rule.approval);
                        tighten_ttl(&mut agg.ttl, rule.jit_ttl_secs);
                    }
                    RuleEffect::Deny => agg.deny = true,
                }
            }
            if agent_hit {
                match rule.effect {
                    RuleEffect::Deny => agent_denied = true,
                    RuleEffect::Allow => {
                        tighten_approval(&mut agent_approval, rule.approval);
                        tighten_ttl(&mut agent_ttl, rule.jit_ttl_secs);
                    }
                }
            }
        }

        let repo_allowed = repo.allow && !repo.deny;
        let human_allowed = (repo_allowed || srv.allow) && !srv.deny;
        let profile_verdict =
            agent_task.map(|t| self.agent_profile_allows_mcp(&t.profile, server, tool));
        let agent_allowed = profile_verdict.map(|v| v.unwrap_or(false) && !agent_denied);
        let mut allowed = human_allowed && agent_allowed.unwrap_or(true);

        let risk = risk.unwrap_or_default();
        let risk_default_approval = match risk {
            McpRiskLevel::Read => McpApprovalMode::Auto,
            McpRiskLevel::Write | McpRiskLevel::Destructive => McpApprovalMode::Jit,
        };
        // If Repo denied this tool and Server overrode it, ignore any Repo Allow approval/TTL.
        let repo_approval = repo_allowed.then_some(repo.approval).flatten();
        let repo_ttl = repo_allowed.then_some(repo.ttl).flatten();
        let srv_cfg_is_server = server_entry.is_some_and(|s| s.layer == PolicyLayer::Server);
        let srv_floor_approval = srv
            .approval
            .or_else(|| {
                if srv_cfg_is_server {
                    server_cfg.and_then(|c| c.default_approval)
                } else {
                    None
                }
            })
            .or_else(|| srv.allow.then_some(risk_default_approval));
        let repo_default_approval = (!srv_cfg_is_server)
            .then(|| server_cfg.and_then(|c| c.default_approval))
            .flatten();
        let repo_effective_approval = repo_approval.or(repo_default_approval);

        let mut approval = if allowed {
            let combined = match (srv_floor_approval, repo_effective_approval) {
                (Some(sf), Some(rf)) => sf.max(rf),
                (Some(sf), None) => sf,
                (None, Some(rf)) => rf,
                (None, None) => risk_default_approval,
            };
            // Destructive operations require at least JIT unless the Server layer opted out.
            if risk == McpRiskLevel::Destructive && srv_floor_approval.is_none() {
                combined.max(McpApprovalMode::Jit)
            } else {
                combined
            }
        } else {
            McpApprovalMode::Deny
        };
        if allowed {
            // An agent never gets looser approval than the human.
            if let Some(a) = agent_approval {
                approval = approval.max(a);
            }
            if approval == McpApprovalMode::Deny {
                allowed = false;
            }
        }

        let srv_floor_ttl = if risk == McpRiskLevel::Destructive {
            Some(srv.ttl.unwrap_or(0))
        } else {
            srv.ttl.or_else(|| {
                (srv_cfg_is_server || srv.allow).then(|| server_cfg.map_or(300, |c| c.jit_ttl_secs))
            })
        };
        let mut ttl = match (srv_floor_ttl, repo_ttl) {
            (Some(sf), Some(rf)) => sf.min(rf),
            (Some(sf), None) => sf,
            (None, Some(rf)) => rf,
            (None, None) => server_cfg.map_or(300, |c| c.jit_ttl_secs),
        };
        if let Some(a) = agent_ttl {
            ttl = ttl.min(a);
        }

        let mut required_secrets: Vec<String> = Vec::new();
        if let Some(cfg) = server_cfg {
            for cred in &cfg.credentials {
                push_unique(&mut required_secrets, cred.secret_name().to_owned());
            }
        }
        for s in rule_secrets {
            push_unique(&mut required_secrets, s);
        }

        let reason = if allowed {
            format!(
                "allowed ({risk:?} risk, {approval:?} approval) by rule(s) {}",
                rule_ids(&traces, |t| t.effect == RuleEffect::Allow)
            )
        } else if !human_allowed {
            if srv.deny {
                format!(
                    "denied by server rule(s) {}",
                    rule_ids(&traces, |t| {
                        t.layer == PolicyLayer::Server && t.effect == RuleEffect::Deny
                    })
                )
            } else if repo.deny && !srv.allow {
                format!(
                    "denied by repo rule(s) {}",
                    rule_ids(&traces, |t| {
                        t.layer == PolicyLayer::Repo && t.effect == RuleEffect::Deny
                    })
                )
            } else {
                format!(
                    "no mcp_rules allow '{}' for this principal; MCP tools are default-deny",
                    decision.full_name
                )
            }
        } else if agent_allowed == Some(false) {
            let profile = agent_task.map_or("", |t| t.profile.as_str());
            if agent_denied {
                format!(
                    "agent '{profile}' denied by rule(s) {}",
                    rule_ids(&traces, |t| t.agent_scoped && t.effect == RuleEffect::Deny)
                )
            } else if profile_verdict == Some(None) {
                format!("agent profile '{profile}' is not defined; default-deny")
            } else {
                format!(
                    "agent profile '{profile}' does not allow '{}'",
                    decision.full_name
                )
            }
        } else {
            "approval policy is 'deny' for this tool".to_owned()
        };

        decision.allowed = allowed;
        decision.human_allowed = human_allowed;
        decision.agent_allowed = agent_allowed;
        decision.risk = risk;
        decision.approval = approval;
        decision.jit_ttl_secs = ttl;
        decision.required_secrets = required_secrets;
        decision.arg_constraints = constraints;
        decision.matched_rules = traces;
        decision.reason = reason;
        decision
    }

    /// Check a tool call's JSON arguments against `decision.arg_constraints`.
    ///
    /// Fails closed: a denied decision, a missing required argument, an unparseable path or an
    /// invalid glob all reject. Every violation is reported, none of the argument values that
    /// failed a `Pattern` check are echoed back.
    pub fn validate_mcp_args(
        &self,
        identity: &DelegatedIdentity,
        decision: &McpToolDecision,
        args: &Map<String, Value>,
        ref_name: &str,
    ) -> Result<(), Vec<String>> {
        if !decision.allowed {
            return Err(vec![format!(
                "tool '{}' is not allowed: {}",
                decision.full_name, decision.reason
            )]);
        }
        let mut errors = Vec::new();
        for c in &decision.arg_constraints {
            let found = resolve_arg(args, c.arg());
            match c {
                McpArgConstraint::PathZone { .. } => {
                    errors.extend(self.path_zone_errors(identity, ref_name, c, &found));
                }
                McpArgConstraint::Pattern {
                    arg,
                    allow_patterns,
                    deny_patterns,
                    case_insensitive,
                } => errors.extend(pattern_errors(
                    arg,
                    allow_patterns,
                    deny_patterns,
                    *case_insensitive,
                    &found,
                )),
                McpArgConstraint::AllowedValues { arg, values } => {
                    if found.is_empty() {
                        errors.push(format!("'{arg}': required argument is missing"));
                    }
                    for v in &found {
                        match scalar_string(v) {
                            Some(s) if values.contains(&s) => {}
                            Some(_) => errors
                                .push(format!("'{arg}': value is not one of the allowed values")),
                            None => errors.push(format!("'{arg}': must be a scalar value")),
                        }
                    }
                }
                McpArgConstraint::ForbidArg { arg } => {
                    if !found.is_empty() {
                        errors.push(format!("'{arg}': argument is forbidden"));
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn path_zone_errors(
        &self,
        identity: &DelegatedIdentity,
        ref_name: &str,
        constraint: &McpArgConstraint,
        found: &[&Value],
    ) -> Vec<String> {
        let McpArgConstraint::PathZone {
            arg,
            capability,
            allow_globs,
            deny_globs,
        } = constraint
        else {
            return Vec::new();
        };
        let mut errors = Vec::new();
        let req_cap = match Capability::parse_name(capability) {
            Ok(c) => c,
            Err(e) => return vec![format!("'{arg}': invalid capability: {e}")],
        };
        let compile = |globs: &[String]| -> Result<Vec<CompiledGlob>, String> {
            globs
                .iter()
                .map(|g| CompiledGlob::new(g).map_err(|e| format!("'{arg}': {e}")))
                .collect()
        };
        let (allow, deny) = match (compile(allow_globs), compile(deny_globs)) {
            (Ok(a), Ok(d)) => (a, d),
            (Err(e), _) | (_, Err(e)) => return vec![e],
        };
        if found.is_empty() {
            return vec![format!("'{arg}': required path argument is missing")];
        }

        let mut raws: Vec<&str> = Vec::new();
        for v in found {
            match v {
                Value::String(s) => raws.push(s),
                Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_string) => {
                    raws.extend(items.iter().filter_map(Value::as_str));
                }
                _ => errors.push(format!(
                    "'{arg}': must be a string or a non-empty array of strings"
                )),
            }
        }
        for raw in raws {
            if raw.is_empty() {
                errors.push(format!("'{arg}': path must not be empty"));
                continue;
            }
            let path = match RepoPath::new(raw) {
                Ok(p) => p,
                Err(e) => {
                    errors.push(format!("'{arg}': path rejected: {e}"));
                    continue;
                }
            };
            if let Some(seg) = path
                .segments()
                .into_iter()
                .find(|seg| is_reserved_path_component(seg))
            {
                errors.push(format!(
                    "'{arg}': path '{raw}' addresses reserved component '{seg}'"
                ));
                continue;
            }
            if !self.explain(identity, &path, ref_name).allows(req_cap) {
                errors.push(format!(
                    "'{arg}': '{raw}' is not permitted ({capability} required)"
                ));
                continue;
            }
            if deny.iter().any(|g| g.is_match_case_insensitive(&path)) {
                errors.push(format!("'{arg}': '{raw}' matches a denied path glob"));
            } else if !allow.is_empty() && !allow.iter().any(|g| g.is_match(&path)) {
                errors.push(format!(
                    "'{arg}': '{raw}' is outside the allowed path globs"
                ));
            }
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Non-null values addressed by `arg`. A dotted name is looked up both as a literal key and as
/// a nested object path, and every hit is checked so the two readings cannot disagree.
fn resolve_arg<'a>(args: &'a Map<String, Value>, arg: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    if let Some(v) = args.get(arg).filter(|v| !v.is_null()) {
        out.push(v);
    }
    if arg.contains('.') {
        let mut segs = arg.split('.');
        let mut cur = segs.next().and_then(|first| args.get(first));
        for seg in segs {
            cur = cur.and_then(Value::as_object).and_then(|o| o.get(seg));
        }
        if let Some(v) = cur.filter(|v| !v.is_null()) {
            out.push(v);
        }
    }
    out
}

fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Collapse every run of ASCII whitespace to one space so `DROP\n\tTABLE` reads `DROP TABLE`.
fn normalize_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out.trim().to_owned()
}

fn pattern_errors(
    arg: &str,
    allow_patterns: &[String],
    deny_patterns: &[String],
    case_insensitive: bool,
    found: &[&Value],
) -> Vec<String> {
    let mut errors = Vec::new();
    let constrained = !allow_patterns.is_empty() || !deny_patterns.is_empty();
    if found.is_empty() {
        if !allow_patterns.is_empty() {
            errors.push(format!("'{arg}': required argument is missing"));
        }
        return errors;
    }
    // No `literal_separator`: `*` must span spaces and `/` inside queries and expressions.
    let compile = |pats: &[String]| -> Result<Vec<GlobMatcher>, String> {
        pats.iter()
            .map(|p| {
                build_glob(p, false, case_insensitive)
                    .map_err(|e| format!("'{arg}': invalid pattern '{p}': {e}"))
            })
            .collect()
    };
    let (allow, deny) = match (compile(allow_patterns), compile(deny_patterns)) {
        (Ok(a), Ok(d)) => (a, d),
        (Err(e), _) | (_, Err(e)) => return vec![e],
    };
    for v in found {
        let Some(raw) = scalar_string(v) else {
            if constrained {
                errors.push(format!("'{arg}': must be a scalar value"));
            }
            continue;
        };
        let value = normalize_ws(&raw);
        if deny.iter().any(|m| m.is_match(&value)) {
            errors.push(format!("'{arg}': value matches a denied pattern"));
        } else if !allow.is_empty() && !allow.iter().any(|m| m.is_match(&value)) {
            errors.push(format!("'{arg}': value matches no allowed pattern"));
        }
    }
    errors
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use premier_core::Principal;
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;
    use crate::diff::compute_access_diff;
    use crate::parse_policy_toml;

    const REPO: &str = r#"
version = 1

[defaults]
authenticated = ["traverse", "list", "read"]

[[rules]]
id = "deny-secrets-dir"
effect = "deny"
principals = ["*"]
paths = ["secrets/**"]
capabilities = ["read"]

[mcp_servers.github]
transport = "http_sse"
url = "https://mcp.example/github"
description = "GitHub"
credentials = [{ inject = "bearer_header", secret = "GH_TOKEN" }]
[mcp_servers.github.pinned_tool_hashes]
create_issue = "aaaa"
list_issues = "bbbb"

[mcp_servers.fs]
command = "mcp-fs"
args = ["--root", "."]
[mcp_servers.fs.env]
LOG = "1"

[[mcp_rules]]
id = "read-tools"
effect = "allow"
principals = ["authenticated"]
tools = ["github:list_*", "fs:read_file"]
risk = "read"

[[mcp_rules]]
id = "write-issue"
effect = "allow"
principals = ["group:eng"]
tools = ["github:create_issue"]
risk = "write"
required_secrets = ["GH_TOKEN", "OTHER"]

[[mcp_rules]]
id = "no-delete"
effect = "deny"
principals = ["*"]
tools = ["*:delete_*"]

[[agent_profiles]]
name = "triage"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read"]
allow_mcp_tools = ["github:list_*", "github:create_issue", "fs:*"]
deny_mcp_tools = ["github:create_issue"]

[[agent_profiles]]
name = "empty"
"#;

    const SERVER: &str = r#"
version = 1

[mcp_servers.github]
transport = "http_sse"
url = "https://corp.example/github"
[mcp_servers.github.pinned_tool_hashes]
create_issue = "cccc"

[[mcp_rules]]
id = "srv-allow-delete-branch"
effect = "allow"
principals = ["group:eng"]
tools = ["github:delete_branch"]
risk = "destructive"
"#;

    fn policy(repo: &str, server: Option<&str>) -> CompiledPolicy {
        let repo = parse_policy_toml(repo).unwrap();
        let server = server.map(|s| parse_policy_toml(s).unwrap());
        CompiledPolicy::compile(server.as_ref(), &repo).unwrap()
    }

    fn alice() -> DelegatedIdentity {
        DelegatedIdentity::human_only(Principal::parse("@alice").unwrap(), vec!["eng".to_owned()])
    }

    fn alice_agent(profile: &str) -> DelegatedIdentity {
        DelegatedIdentity::delegated(
            Principal::parse("@alice").unwrap(),
            vec!["eng".to_owned()],
            profile,
            "task-1",
        )
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn compile_err(repo: &str) -> PolicyError {
        let parsed = parse_policy_toml(repo).unwrap();
        CompiledPolicy::compile(None, &parsed).unwrap_err()
    }

    #[test]
    fn enum_ordering_is_strictness() {
        assert!(McpRiskLevel::Read < McpRiskLevel::Write);
        assert!(McpRiskLevel::Write < McpRiskLevel::Destructive);
        assert!(McpApprovalMode::Auto < McpApprovalMode::Jit);
        assert!(McpApprovalMode::Jit < McpApprovalMode::Deny);
        assert_eq!(McpApprovalMode::default(), McpApprovalMode::Jit);
        assert_eq!(McpRiskLevel::default(), McpRiskLevel::Read);
    }

    #[test]
    fn existing_policies_parse_unchanged_and_have_no_mcp_surface() {
        let legacy = r#"
version = 1
[[rules]]
id = "r"
effect = "allow"
principals = ["*"]
paths = ["src/**"]
capabilities = ["read"]
[[agent_profiles]]
name = "bot"
allow_paths = ["src/**"]
"#;
        let parsed = parse_policy_toml(legacy).unwrap();
        assert!(parsed.mcp_servers.is_empty() && parsed.mcp_rules.is_empty());
        assert!(parsed.agent_profiles[0].allow_mcp_tools.is_empty());
        let compiled = CompiledPolicy::compile(None, &parsed).unwrap();
        assert!(compiled.mcp_servers().is_empty());
        assert!(
            !compiled
                .evaluate_mcp_tool(&alice(), "github", "list_issues", "main")
                .allowed
        );
    }

    #[test]
    fn parses_server_config_defaults_and_credential_bindings() {
        let parsed = parse_policy_toml(REPO).unwrap();
        let fs = &parsed.mcp_servers["fs"];
        assert_eq!(fs.transport, crate::schema::McpTransportKind::Stdio);
        assert_eq!(fs.command.as_deref(), Some("mcp-fs"));
        assert_eq!(fs.jit_ttl_secs, 300);
        assert_eq!(fs.timeout_secs, 30);
        assert!(fs.pin_on_first_use);
        assert_eq!(fs.env["LOG"], "1");

        let gh = &parsed.mcp_servers["github"];
        let cred = &gh.credentials[0];
        assert_eq!(cred.secret_name(), "GH_TOKEN");
        assert_eq!(cred.inject_kind(), "bearer_header");
        assert!(matches!(
            cred,
            crate::schema::McpCredentialBinding::BearerHeader { header, .. }
                if header == "Authorization"
        ));

        let t = r#"
version = 1
[mcp_servers.x]
credentials = [
  { inject = "env", secret = "A" },
  { inject = "header", secret = "B", header = "X-Key", prefix = "Key " },
]
[[mcp_rules]]
id = "r"
effect = "allow"
tools = ["x:*"]
arg_constraints = [
  { kind = "path_zone", arg = "path" },
  { kind = "pattern", arg = "q", deny_patterns = ["*DROP*"] },
  { kind = "allowed_values", arg = "mode", values = ["a"] },
  { kind = "forbid_arg", arg = "force" },
]
"#;
        let p = parse_policy_toml(t).unwrap();
        let creds = &p.mcp_servers["x"].credentials;
        assert_eq!(creds[0].inject_kind(), "env");
        assert_eq!(creds[1].inject_kind(), "header");
        assert!(matches!(
            &p.mcp_rules[0].arg_constraints[0],
            McpArgConstraint::PathZone { capability, .. } if capability == "read"
        ));
        for c in &p.mcp_rules[0].arg_constraints {
            assert!(!c.summary().is_empty());
        }
        CompiledPolicy::compile(None, &p).unwrap();
    }

    #[test]
    fn mcp_is_default_deny() {
        let p = policy(REPO, None);
        let d = p.evaluate_mcp_tool(&alice(), "github", "merge_pr", "main");
        assert!(!d.allowed && !d.human_allowed);
        assert_eq!(d.approval, McpApprovalMode::Deny);
        assert!(d.reason.contains("default-deny"));
        // Unknown server too.
        assert!(!p.evaluate_mcp_tool(&alice(), "nope", "x", "main").allowed);
        // Anonymous matches no `authenticated` rule.
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        assert!(
            !p.evaluate_mcp_tool(&anon, "github", "list_issues", "main")
                .allowed
        );
    }

    #[test]
    fn allow_rules_drive_risk_approval_and_secrets() {
        let p = policy(REPO, None);
        let read = p.evaluate_mcp_tool(&alice(), "github", "list_issues", "main");
        assert!(read.allowed);
        assert_eq!(read.risk, McpRiskLevel::Read);
        assert_eq!(read.approval, McpApprovalMode::Auto);
        assert_eq!(read.required_secrets, ["GH_TOKEN"]);
        assert_eq!(read.jit_ttl_secs, 300);
        assert_eq!(read.full_name, "github:list_issues");

        let write = p.evaluate_mcp_tool(&alice(), "github", "create_issue", "main");
        assert!(write.allowed);
        assert_eq!(write.risk, McpRiskLevel::Write);
        assert_eq!(write.approval, McpApprovalMode::Jit);
        // credentials first, then rule secrets, de-duplicated.
        assert_eq!(write.required_secrets, ["GH_TOKEN", "OTHER"]);

        // Non-members of `eng` don't get the write rule.
        let bob = DelegatedIdentity::human_only(Principal::parse("@bob").unwrap(), vec![]);
        assert!(
            !p.evaluate_mcp_tool(&bob, "github", "create_issue", "main")
                .allowed
        );
    }

    #[test]
    fn deny_overrides_allow_and_server_overrides_repo() {
        let p = policy(REPO, Some(SERVER));
        // Repo deny `*:delete_*` is overridden by the Server allow.
        let del = p.evaluate_mcp_tool(&alice(), "github", "delete_branch", "main");
        assert!(del.allowed, "{}", del.reason);
        assert_eq!(del.risk, McpRiskLevel::Destructive);
        assert_eq!(del.approval, McpApprovalMode::Jit);
        assert_eq!(del.jit_ttl_secs, 0, "destructive defaults to single-use");

        // Without the Server layer the same call is denied by the repo rule.
        let repo_only = policy(REPO, None);
        let denied = repo_only.evaluate_mcp_tool(&alice(), "github", "delete_branch", "main");
        assert!(!denied.allowed);
        assert!(denied.reason.contains("no-delete") || denied.reason.contains("default-deny"));

        // Server deny beats everything, including its own layer's allow and repo allow.
        let mut srv = parse_policy_toml(SERVER).unwrap();
        srv.mcp_rules.push(McpToolRule {
            id: "srv-deny-all-github".to_owned(),
            effect: RuleEffect::Deny,
            principals: vec!["*".to_owned()],
            tools: vec!["github:*".to_owned()],
            refs: vec![],
            risk: None,
            approval: None,
            jit_ttl_secs: None,
            arg_constraints: vec![],
            required_secrets: vec![],
            reason: Some("freeze".to_owned()),
        });
        let repo = parse_policy_toml(REPO).unwrap();
        let frozen = CompiledPolicy::compile(Some(&srv), &repo).unwrap();
        for tool in ["list_issues", "create_issue", "delete_branch"] {
            let d = frozen.evaluate_mcp_tool(&alice(), "github", tool, "main");
            assert!(!d.allowed, "{tool}");
            assert!(d.reason.contains("srv-deny-all-github"));
        }
        assert!(
            frozen
                .evaluate_mcp_tool(&alice(), "fs", "read_file", "main")
                .allowed
        );
    }

    #[test]
    fn approval_precedence_server_then_repo_then_server_default_then_risk() {
        let repo = r#"
version = 1
[mcp_servers.s]
default_approval = "auto"
jit_ttl_secs = 60
[[mcp_rules]]
id = "repo-jit"
effect = "allow"
principals = ["*"]
tools = ["s:a"]
approval = "jit"
jit_ttl_secs = 120
[[mcp_rules]]
id = "plain"
effect = "allow"
principals = ["*"]
tools = ["s:b"]
risk = "write"
[[mcp_rules]]
id = "repo-auto"
effect = "allow"
principals = ["*"]
tools = ["s:c"]
approval = "auto"
"#;
        let server = r#"
version = 1
[[mcp_rules]]
id = "srv-auto"
effect = "allow"
principals = ["*"]
tools = ["s:c"]
approval = "deny"
jit_ttl_secs = 5
"#;
        let p = policy(repo, Some(server));
        let a = p.evaluate_mcp_tool(&alice(), "s", "a", "main");
        assert_eq!((a.approval, a.jit_ttl_secs), (McpApprovalMode::Jit, 120));
        // Server default_approval beats the risk default (write would be jit).
        let b = p.evaluate_mcp_tool(&alice(), "s", "b", "main");
        assert_eq!((b.approval, b.jit_ttl_secs), (McpApprovalMode::Auto, 60));
        // Server rule approval = deny beats repo approval = auto and denies the call.
        let c = p.evaluate_mcp_tool(&alice(), "s", "c", "main");
        assert!(!c.allowed);
        assert_eq!(c.approval, McpApprovalMode::Deny);
        assert_eq!(c.jit_ttl_secs, 5);
    }

    #[test]
    fn refs_scope_rules() {
        let t = r#"
version = 1
[[mcp_rules]]
id = "main-only"
effect = "allow"
principals = ["*"]
tools = ["s:t"]
refs = ["main"]
"#;
        let p = policy(t, None);
        assert!(p.evaluate_mcp_tool(&alice(), "s", "t", "main").allowed);
        assert!(!p.evaluate_mcp_tool(&alice(), "s", "t", "feature/x").allowed);
    }

    #[test]
    fn agent_is_human_intersect_profile() {
        let p = policy(REPO, None);
        let ev = |id: &DelegatedIdentity, s: &str, t: &str| p.evaluate_mcp_tool(id, s, t, "main");

        let triage = alice_agent("triage");
        // Allowed by human rule + profile glob.
        let ok = ev(&triage, "github", "list_issues");
        assert!(ok.allowed);
        assert_eq!(ok.agent_allowed, Some(true));
        assert_eq!(ok.agent_profile.as_deref(), Some("triage"));
        // Human may create_issue, but the profile denies it (deny_mcp_tools beats allow).
        let human = ev(&alice(), "github", "create_issue");
        let agent = ev(&triage, "github", "create_issue");
        assert!(human.allowed && !agent.allowed);
        assert_eq!(agent.agent_allowed, Some(false));
        assert!(agent.reason.contains("does not allow"));
        // Profile allows `fs:*`, but the human has no rule for fs:write_file.
        let nope = ev(&triage, "fs", "write_file");
        assert!(!nope.allowed && !nope.human_allowed);
        assert_eq!(nope.agent_allowed, Some(true));
        // Profile with no allow_mcp_tools and an unknown profile are default-denied.
        let empty = ev(&alice_agent("empty"), "github", "list_issues");
        assert!(!empty.allowed && empty.human_allowed);
        let ghost = ev(&alice_agent("ghost"), "github", "list_issues");
        assert!(!ghost.allowed);
        assert_eq!(ghost.agent_allowed, Some(false));
        assert!(ghost.reason.contains("not defined"));
    }

    #[test]
    fn agent_rules_deny_and_only_tighten() {
        let t = format!(
            r#"{REPO}
[[mcp_rules]]
id = "agents-never-fs"
effect = "deny"
principals = ["agent:*"]
tools = ["fs:read_file"]

[[mcp_rules]]
id = "agents-jit-reads"
effect = "allow"
principals = ["agent:triage"]
tools = ["github:list_issues"]
approval = "jit"
jit_ttl_secs = 30
risk = "write"
arg_constraints = [{{ kind = "forbid_arg", arg = "admin" }}]

[[mcp_rules]]
id = "agents-loosen-attempt"
effect = "allow"
principals = ["agent:triage"]
tools = ["github:create_issue"]
approval = "auto"
"#
        );
        let p = policy(&t, None);
        let human = p.evaluate_mcp_tool(&alice(), "fs", "read_file", "main");
        let agent = p.evaluate_mcp_tool(&alice_agent("triage"), "fs", "read_file", "main");
        assert!(human.allowed);
        assert!(!agent.allowed);
        assert!(agent.reason.contains("agents-never-fs"));
        assert!(agent.matched_rules.iter().any(|m| m.agent_scoped));
        // The human never sees agent-scoped rules.
        assert!(human.matched_rules.iter().all(|m| !m.agent_scoped));

        let h = p.evaluate_mcp_tool(&alice(), "github", "list_issues", "main");
        let a = p.evaluate_mcp_tool(&alice_agent("triage"), "github", "list_issues", "main");
        assert_eq!((h.approval, h.jit_ttl_secs), (McpApprovalMode::Auto, 300));
        assert!(a.allowed);
        assert_eq!((a.approval, a.jit_ttl_secs), (McpApprovalMode::Jit, 30));
        assert_eq!(a.risk, McpRiskLevel::Write);
        assert_eq!(a.arg_constraints.len(), 1);
        assert!(h.arg_constraints.is_empty());
    }

    #[test]
    fn server_pins_override_repo_pins_and_server_config_wins() {
        let p = policy(REPO, Some(SERVER));
        // Server wins for the overlapping pin, Repo-only pin survives.
        assert_eq!(
            p.pinned_mcp_tool_hash("github", "create_issue"),
            Some("cccc")
        );
        assert_eq!(
            p.pinned_mcp_tool_hash("github", "list_issues"),
            Some("bbbb")
        );
        assert_eq!(p.pinned_mcp_tool_hash("github", "nope"), None);
        assert_eq!(p.pinned_mcp_tool_hash("nope", "create_issue"), None);

        let gh = p.mcp_server("github").unwrap();
        assert_eq!(gh.layer, PolicyLayer::Server);
        assert_eq!(gh.name, "github");
        assert_eq!(
            gh.config.url.as_deref(),
            Some("https://corp.example/github")
        );
        // Server config replaces the repo one wholesale (no repo credentials leak through).
        assert!(gh.config.credentials.is_empty());
        assert_eq!(p.mcp_server("fs").unwrap().layer, PolicyLayer::Repo);
        assert_eq!(p.mcp_servers().len(), 2);
    }

    #[test]
    fn invalid_mcp_policies_are_rejected() {
        let is_mcp = |e: PolicyError| matches!(e, PolicyError::InvalidMcpPolicy(_));
        for name in ["", "has space", "a:b", "a/b", "ünï"] {
            let t = format!("version = 1\n[mcp_servers.\"{name}\"]\n");
            assert!(is_mcp(compile_err(&t)), "server name '{name}'");
        }
        let rule = |tools: &str, extra: &str| {
            format!(
                "version = 1\n[[mcp_rules]]\nid = \"r\"\neffect = \"allow\"\nprincipals = [\"*\"]\n\
                 tools = {tools}\n{extra}"
            )
        };
        for tools in [
            r#"["noseparator"]"#,
            r#"[":tool"]"#,
            r#"["server:"]"#,
            r#"["s:[unclosed"]"#,
            r#"["{a:b"]"#,
            r#"["s: tool"]"#,
            "[]",
        ] {
            assert!(is_mcp(compile_err(&rule(tools, ""))), "tools {tools}");
        }
        for constraint in [
            r#"arg_constraints = [{ kind = "path_zone", arg = "p", capability = "execute" }]"#,
            r#"arg_constraints = [{ kind = "path_zone", arg = "p", allow_globs = ["[bad"] }]"#,
            r#"arg_constraints = [{ kind = "pattern", arg = "q", deny_patterns = ["[bad"] }]"#,
            r#"arg_constraints = [{ kind = "forbid_arg", arg = "a..b" }]"#,
            r#"arg_constraints = [{ kind = "forbid_arg", arg = "" }]"#,
        ] {
            assert!(
                is_mcp(compile_err(&rule(r#"["s:t"]"#, constraint))),
                "{constraint}"
            );
        }
        // Invalid agent profile patterns.
        let prof = "version = 1\n[[agent_profiles]]\nname = \"p\"\nallow_mcp_tools = [\"bad\"]\n";
        assert!(is_mcp(compile_err(prof)));
        // Too many servers.
        let mut many = AccessPolicyFile::default();
        for i in 0..=MAX_MCP_SERVERS {
            many.mcp_servers
                .insert(format!("s{i}"), McpServerConfig::default());
        }
        assert!(matches!(
            CompiledPolicy::compile(None, &many),
            Err(PolicyError::TooComplex(_))
        ));
    }

    #[test]
    fn star_pattern_expands_and_never_crosses_colon() {
        let any = McpToolPattern::compile("*").unwrap();
        assert!(any.matches("a", "b") && any.matches("a-b", "x_y"));
        let p = McpToolPattern::compile("git*:list_*").unwrap();
        assert!(p.matches("github", "list_issues"));
        assert!(!p.matches("github", "create"));
        // The two halves compile independently: the first `:` is the separator, so a tool
        // name may itself contain one.
        assert!(
            McpToolPattern::compile("s:a:*")
                .unwrap()
                .matches("s", "a:b")
        );
        let tool_colon = McpToolPattern::compile("s:*").unwrap();
        assert!(tool_colon.matches("s", "anything"));
        assert!(!tool_colon.matches("other", "anything"));
    }

    #[test]
    fn tool_names_with_path_separators_are_refused() {
        let t = r#"
version = 1
[[mcp_rules]]
id = "allow-all"
effect = "allow"
principals = ["*"]
tools = ["*"]
"#;
        let p = policy(t, None);
        assert!(
            p.evaluate_mcp_tool(&alice(), "s", "ok_tool", "main")
                .allowed
        );
        for tool in ["a/b", "a\\b", "", "a\nb"] {
            assert!(!p.evaluate_mcp_tool(&alice(), "s", tool, "main").allowed);
        }
        assert!(
            !p.evaluate_mcp_tool(&alice(), "bad name", "t", "main")
                .allowed
        );
        assert!(
            !p.evaluate_mcp_tool(&alice(), "git:hub", "t", "main")
                .allowed
        );
        assert!(!p.evaluate_mcp_tool(&alice(), "", "t", "main").allowed);
    }

    fn constrained_decision(constraints: &str) -> (CompiledPolicy, McpToolDecision) {
        let t = format!(
            r#"{REPO_PATHS}
[[mcp_rules]]
id = "c"
effect = "allow"
principals = ["*"]
tools = ["fs:op"]
arg_constraints = {constraints}
"#
        );
        let p = policy(&t, None);
        let d = p.evaluate_mcp_tool(&alice(), "fs", "op", "main");
        assert!(d.allowed, "{}", d.reason);
        (p, d)
    }

    const REPO_PATHS: &str = r#"
version = 1
[defaults]
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "deny-secrets"
effect = "deny"
principals = ["*"]
paths = ["secrets/**"]
capabilities = ["read"]
"#;

    #[test]
    fn path_zone_blocks_traversal_reserved_dirs_and_unreadable_paths() {
        let (p, d) = constrained_decision(r#"[{ kind = "path_zone", arg = "options.file" }]"#);
        let check = |v: Value| p.validate_mcp_args(&alice(), &d, &args(v), "main");
        assert!(check(json!({"options": {"file": "src/lib.rs"}})).is_ok());
        assert!(check(json!({"options": {"file": ["src/a.rs", "docs/b.md"]}})).is_ok());
        for bad in [
            "../etc/passwd",
            "src/../../x",
            "/etc/passwd",
            "C:\\Windows\\system32",
            "C:/x",
            "src\\lib.rs",
            "src/lib.rs.",
            "src/lib.rs ",
            "a\u{0}b",
            "",
            ".git/config",
            "sub/.git/hooks/pre-commit",
            ".GIT/config",
            ".Git./config",
            ".premier/state",
            ".premier-local/keys",
            "GIT~1/config",
            "secrets/api.key",
        ] {
            let r = check(json!({"options": {"file": bad}}));
            assert!(r.is_err(), "path {bad:?} must be rejected");
        }
        // Missing / wrong-typed arguments fail closed.
        assert!(check(json!({})).is_err());
        assert!(check(json!({"options": {"file": []}})).is_err());
        assert!(check(json!({"options": {"file": 7}})).is_err());
        assert!(check(json!({"options": {"file": ["ok.rs", 7]}})).is_err());
        assert!(check(json!({"options": {"file": null}})).is_err());
        // Literal dotted key is checked too, so the two readings cannot disagree.
        assert!(
            check(json!({"options": {"file": "ok.rs"}, "options.file": ".git/config"})).is_err()
        );
        // Anonymous callers hold no READ (no defaults), so the path is refused.
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        assert!(
            p.validate_mcp_args(
                &anon,
                &d,
                &args(json!({"options": {"file": "src/lib.rs"}})),
                "main"
            )
            .is_err()
        );
    }

    #[test]
    fn path_zone_capability_and_globs() {
        let (p, d) = constrained_decision(
            r#"[{ kind = "path_zone", arg = "p", capability = "write", allow_globs = ["src/**"], deny_globs = ["src/gen/**"] }]"#,
        );
        // authenticated defaults grant no WRITE.
        assert!(
            p.validate_mcp_args(&alice(), &d, &args(json!({"p": "src/a.rs"})), "main")
                .is_err()
        );

        let t = format!(
            r#"{REPO_PATHS}
[[rules]]
id = "alice-write"
effect = "allow"
principals = ["@alice"]
paths = ["**"]
capabilities = ["write"]
[[mcp_rules]]
id = "c"
effect = "allow"
principals = ["*"]
tools = ["fs:op"]
arg_constraints = [{{ kind = "path_zone", arg = "p", capability = "write", allow_globs = ["src/**"], deny_globs = ["src/gen/**"] }}]
"#
        );
        let p = policy(&t, None);
        let d = p.evaluate_mcp_tool(&alice(), "fs", "op", "main");
        let check = |v: Value| p.validate_mcp_args(&alice(), &d, &args(v), "main");
        assert!(check(json!({"p": "src/a.rs"})).is_ok());
        assert!(check(json!({"p": "src/gen/a.rs"})).is_err());
        assert!(check(json!({"p": "src/GEN/a.rs"})).is_err());
        assert!(check(json!({"p": "SRC/Gen/A.RS"})).is_err());
        assert!(check(json!({"p": "docs/a.md"})).is_err());
        assert!(check(json!({"p": ["src/a.rs", "docs/a.md"]})).is_err());
        // NTFS ADS streams and Windows 8.3 dotgit hash short names are rejected.
        for bad in [
            ".git::$DATA/config",
            ".git:stream/HEAD",
            ".premier::$INDEX_ALLOCATION/vault.toml",
            "GI7EBA~1/config",
            "gi7eba~2/HEAD",
            "src/GI7EBA~1/hooks",
        ] {
            assert!(check(json!({"p": bad})).is_err(), "expected {bad} rejected");
        }
    }

    #[test]
    fn pattern_constraint_defeats_multiline_and_case_evasion() {
        let (p, d) = constrained_decision(
            r#"[{ kind = "pattern", arg = "sql", allow_patterns = ["SELECT *"], deny_patterns = ["*DROP TABLE*", "*DELETE FROM*"], case_insensitive = true }]"#,
        );
        let check = |v: Value| p.validate_mcp_args(&alice(), &d, &args(v), "main");
        assert!(check(json!({"sql": "SELECT a, b FROM t WHERE x = '/a/b'"})).is_ok());
        assert!(check(json!({"sql": "  select\n\t1  "})).is_ok());
        for bad in [
            "SELECT 1; DROP TABLE users",
            "SELECT 1; DROP\nTABLE users",
            "SELECT 1; drop \r\n\t\t table users",
            "SELECT 1;\x0cDROP\x0bTABLE users",
            "SELECT 1; delete  from users",
            "UPDATE t SET a = 1",
            "",
        ] {
            assert!(check(json!({"sql": bad})).is_err(), "{bad:?}");
        }
        // Allow patterns make the argument mandatory and scalar.
        assert!(check(json!({})).is_err());
        assert!(check(json!({"sql": ["SELECT 1"]})).is_err());
        assert!(check(json!({"sql": {"x": "SELECT 1"}})).is_err());
        // Scalars are stringified.
        let (p2, d2) =
            constrained_decision(r#"[{ kind = "pattern", arg = "n", allow_patterns = ["4?"] }]"#);
        assert!(
            p2.validate_mcp_args(&alice(), &d2, &args(json!({"n": 42})), "main")
                .is_ok()
        );
        assert!(
            p2.validate_mcp_args(&alice(), &d2, &args(json!({"n": 7})), "main")
                .is_err()
        );
        // Case sensitivity is honoured when not requested.
        let (p3, d3) = constrained_decision(
            r#"[{ kind = "pattern", arg = "q", deny_patterns = ["*DROP*"] }]"#,
        );
        assert!(
            p3.validate_mcp_args(&alice(), &d3, &args(json!({"q": "drop"})), "main")
                .is_ok()
        );
        assert!(
            p3.validate_mcp_args(&alice(), &d3, &args(json!({"q": "DROP"})), "main")
                .is_err()
        );
        // Deny-only constraints still refuse a non-scalar that could hide a payload.
        assert!(
            p3.validate_mcp_args(&alice(), &d3, &args(json!({"q": ["DROP"]})), "main")
                .is_err()
        );
        assert!(
            p3.validate_mcp_args(&alice(), &d3, &args(json!({})), "main")
                .is_ok()
        );
    }

    #[test]
    fn allowed_values_and_forbid_arg() {
        let (p, d) = constrained_decision(
            r#"[
  { kind = "allowed_values", arg = "mode", values = ["dry-run", "7"] },
  { kind = "forbid_arg", arg = "opts.force" },
]"#,
        );
        let check = |v: Value| p.validate_mcp_args(&alice(), &d, &args(v), "main");
        assert!(check(json!({"mode": "dry-run"})).is_ok());
        assert!(check(json!({"mode": 7})).is_ok());
        assert!(check(json!({"mode": "dry-run", "opts": {"other": 1}})).is_ok());
        assert!(check(json!({"mode": "dry-run", "opts": {"force": null}})).is_ok());
        assert!(check(json!({"mode": "apply"})).is_err());
        assert!(check(json!({})).is_err());
        assert!(check(json!({"mode": ["dry-run"]})).is_err());
        assert!(check(json!({"mode": "dry-run", "opts": {"force": false}})).is_err());
        assert!(check(json!({"mode": "dry-run", "opts.force": true})).is_err());
        // Every violation is reported.
        let errs = check(json!({"mode": "apply", "opts": {"force": true}})).unwrap_err();
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn validate_args_fails_closed_on_denied_decision() {
        let p = policy(REPO, None);
        let d = p.evaluate_mcp_tool(&alice(), "github", "merge_pr", "main");
        let errs = p
            .validate_mcp_args(&alice(), &d, &Map::new(), "main")
            .unwrap_err();
        assert!(errs[0].contains("not allowed"));
    }

    #[test]
    fn rule_samples_expand_wildcards_against_pins() {
        let p = policy(REPO, Some(SERVER));
        let samples = p.mcp_rule_tool_samples();
        let has = |s: &str, t: &str| samples.contains(&(s.to_owned(), t.to_owned()));
        assert!(has("github", "list_issues"), "pinned tool matching list_*");
        assert!(has("github", "create_issue"));
        assert!(has("fs", "read_file"));
        assert!(has("github", "delete_branch"));
        assert!(
            has("github", "delete_tool") && has("fs", "delete_tool"),
            "{samples:?}"
        );
        let mut sorted = samples.clone();
        sorted.sort();
        assert_eq!(sorted, samples, "samples are deterministic");
    }

    #[test]
    fn access_diff_reports_mcp_deltas_and_escalations() {
        let base = policy(REPO, None);
        let identities = [alice(), alice_agent("triage")];
        let run =
            |head: &CompiledPolicy| compute_access_diff(&base, head, &identities, &[], &[], "main");

        // Identical policies: no deltas, no escalation.
        let same = run(&base);
        assert!(same.mcp_deltas.is_empty() && !same.has_escalations());

        // Server layer newly allows a destructive tool => escalation for the human, and the
        // agent (profile doesn't list it) is unchanged.
        let head = policy(REPO, Some(SERVER));
        let diff = run(&head);
        let d = diff
            .mcp_deltas
            .iter()
            .find(|d| d.tool == "github:delete_branch" && d.agent_profile.is_none())
            .unwrap();
        assert!(!d.before_allowed && d.after_allowed && d.escalated);
        assert_eq!(d.before_approval, McpApprovalMode::Deny);
        assert_eq!(d.after_approval, McpApprovalMode::Jit);
        assert!(diff.has_escalations());
        assert!(
            diff.mcp_deltas
                .iter()
                .all(|d| d.agent_profile.is_none() || d.tool != "github:delete_branch")
        );

        // Loosened approval (jit -> auto) on an already-allowed tool is an escalation.
        let mut loosened = parse_policy_toml(REPO).unwrap();
        loosened
            .mcp_rules
            .iter_mut()
            .find(|r| r.id == "write-issue")
            .unwrap()
            .approval = Some(McpApprovalMode::Auto);
        let head = CompiledPolicy::compile(None, &loosened).unwrap();
        let diff = run(&head);
        let d = diff
            .mcp_deltas
            .iter()
            .find(|d| d.tool == "github:create_issue" && d.agent_profile.is_none())
            .unwrap();
        assert!(d.before_allowed && d.after_allowed && d.escalated);
        assert!(d.after_approval < d.before_approval);

        // Removing an allow is a (non-escalating) change.
        let mut removed = parse_policy_toml(REPO).unwrap();
        removed.mcp_rules.retain(|r| r.id != "read-tools");
        let head = CompiledPolicy::compile(None, &removed).unwrap();
        let diff = run(&head);
        assert!(!diff.mcp_deltas.is_empty());
        assert!(diff.mcp_deltas.iter().all(|d| !d.escalated));
        assert!(!diff.has_escalations());
    }

    #[test]
    fn server_floor_blocks_repo_loosening_and_overridden_repo_allow() {
        let repo = r#"
version = 1
[mcp_servers.repo_srv]
default_approval = "auto"

[[mcp_rules]]
id = "repo-try-loosen-srv"
effect = "allow"
principals = ["*"]
tools = ["srv:pinned"]
approval = "auto"
jit_ttl_secs = 3600

[[mcp_rules]]
id = "repo-tighten"
effect = "allow"
principals = ["*"]
tools = ["srv:tighten"]
approval = "jit"
jit_ttl_secs = 45

[[mcp_rules]]
id = "repo-deny-leak"
effect = "deny"
principals = ["*"]
tools = ["srv:overridden"]

[[mcp_rules]]
id = "repo-allow-leak"
effect = "allow"
principals = ["*"]
tools = ["srv:overridden"]
approval = "jit"
jit_ttl_secs = 15

[[mcp_rules]]
id = "repo-destructive-loosen"
effect = "allow"
principals = ["*"]
tools = ["repo_srv:nuke"]
risk = "destructive"
approval = "auto"
jit_ttl_secs = 999

[[mcp_rules]]
id = "repo-loosen-srv-cfg"
effect = "allow"
principals = ["*"]
tools = ["srv_cfg_only:op"]
approval = "auto"
jit_ttl_secs = 600

[[mcp_rules]]
id = "repo-loosen-srv-write"
effect = "allow"
principals = ["*"]
tools = ["srv:write_implicit"]
approval = "auto"
jit_ttl_secs = 3600
"#;
        let server = r#"
version = 1
[mcp_servers.srv_cfg_only]
default_approval = "jit"
jit_ttl_secs = 60

[[mcp_rules]]
id = "srv-pinned"
effect = "allow"
principals = ["*"]
tools = ["srv:pinned"]
approval = "jit"
jit_ttl_secs = 60

[[mcp_rules]]
id = "srv-write-implicit"
effect = "allow"
principals = ["*"]
tools = ["srv:write_implicit"]
risk = "write"

[[mcp_rules]]
id = "srv-loose"
effect = "allow"
principals = ["*"]
tools = ["srv:tighten"]
approval = "auto"
jit_ttl_secs = 300

[[mcp_rules]]
id = "srv-override-deny"
effect = "allow"
principals = ["*"]
tools = ["srv:overridden"]
approval = "auto"
jit_ttl_secs = 120
"#;
        let p = policy(repo, Some(server));
        let pinned = p.evaluate_mcp_tool(&alice(), "srv", "pinned", "main");
        assert_eq!(
            (pinned.approval, pinned.jit_ttl_secs),
            (McpApprovalMode::Jit, 60)
        );

        // Repo can still tighten a Server Auto/300 rule to Jit/45.
        let tightened = p.evaluate_mcp_tool(&alice(), "srv", "tighten", "main");
        assert_eq!(
            (tightened.approval, tightened.jit_ttl_secs),
            (McpApprovalMode::Jit, 45)
        );

        // Server [mcp_servers.*] config acts as floor against Repo loosening.
        let cfg_floor = p.evaluate_mcp_tool(&alice(), "srv_cfg_only", "op", "main");
        assert_eq!(
            (cfg_floor.approval, cfg_floor.jit_ttl_secs),
            (McpApprovalMode::Jit, 60)
        );

        // Overridden Repo Allow rule must not leak approval=jit / ttl=15 onto Server Allow.
        let overridden = p.evaluate_mcp_tool(&alice(), "srv", "overridden", "main");
        assert_eq!(
            (overridden.approval, overridden.jit_ttl_secs),
            (McpApprovalMode::Auto, 120)
        );

        // Destructive keeps Jit approval and 0 TTL unless Server explicitly relaxes it.
        let nuke = p.evaluate_mcp_tool(&alice(), "repo_srv", "nuke", "main");
        assert_eq!(
            (nuke.approval, nuke.jit_ttl_secs),
            (McpApprovalMode::Jit, 0)
        );

        // Server Write rule omitting explicit approval/TTL sets a floor (Jit, 300s) Repo cannot loosen.
        let write_floor = p.evaluate_mcp_tool(&alice(), "srv", "write_implicit", "main");
        assert_eq!(
            (write_floor.approval, write_floor.jit_ttl_secs),
            (McpApprovalMode::Jit, 300)
        );
    }

    #[test]
    fn pin_layer_and_preflight_access_and_literal_tools() {
        let repo = r#"
version = 1
[mcp_servers.github.pinned_tool_hashes]
list_issues = "repo-list"
create_issue = "repo-create"
list_tools = "repo-tools"

[[mcp_rules]]
id = "allow-gh"
effect = "allow"
principals = ["group:eng"]
tools = ["github:list_tools", "github:create_issue"]

[[agent_profiles]]
name = "locked"
allow_mcp_tools = ["github:create_issue"]
deny_mcp_tools = ["github:create_issue"]
"#;
        let server = r#"
version = 1
[mcp_servers.github.pinned_tool_hashes]
create_issue = "srv-create"
"#;
        let p = policy(repo, Some(server));
        assert_eq!(
            p.pinned_mcp_tool_hash_with_layer("github", "list_issues"),
            Some(("repo-list", false))
        );
        assert_eq!(
            p.pinned_mcp_tool_hash_with_layer("github", "create_issue"),
            Some(("srv-create", true))
        );

        assert!(p.can_potentially_access_mcp_server(&alice(), "github", Some("main")));
        let bob = DelegatedIdentity::human_only(Principal::parse("@bob").unwrap(), vec![]);
        assert!(!p.can_potentially_access_mcp_server(&bob, "github", Some("main")));
        assert!(!p.can_potentially_access_mcp_server(
            &alice_agent("locked"),
            "github",
            Some("main")
        ));

        let literals = p.mcp_literal_tools("github");
        assert!(literals.contains(&"list_tools".to_owned()));
        assert!(literals.contains(&"create_issue".to_owned()));
        assert!(!literals.contains(&"tool".to_owned()));
    }

    #[test]
    fn reserved_path_segments_and_unicode_whitespace_guardrails() {
        let repo = r#"
version = 1
[[mcp_rules]]
id = "ops"
effect = "allow"
principals = ["*"]
tools = ["fs:read", "db:query"]
[[mcp_rules.arg_constraints]]
kind = "path_zone"
arg = "path"
capability = "read"
allow_globs = ["**"]
[[mcp_rules.arg_constraints]]
kind = "pattern"
arg = "sql"
deny_patterns = ["*DROP TABLE*"]
"#;
        let p = policy(repo, None);
        let read_d = p.evaluate_mcp_tool(&alice(), "fs", "read", "main");
        for bad in [
            ".git/config",
            ".Git./config",
            ".git\u{200b}/config",
            "GIT~2/HEAD",
            "premie~1/secrets",
            ".premier-local/state.json",
        ] {
            assert!(
                p.validate_mcp_args(&alice(), &read_d, &args(json!({ "path": bad })), "main")
                    .is_err(),
                "expected reserved rejection for {bad:?}"
            );
        }

        let sql_d = p.evaluate_mcp_tool(&alice(), "db", "query", "main");
        assert!(
            p.validate_mcp_args(
                &alice(),
                &sql_d,
                &args(json!({ "sql": "DROP\u{00A0}TABLE users" })),
                "main"
            )
            .is_err()
        );
    }

    #[test]
    fn access_diff_detects_ttl_constraint_and_server_changes() {
        let base_toml = r#"
version = 1
[mcp_servers.github]
transport = "http_sse"
url = "https://mcp.example/github"
[[mcp_rules]]
id = "write-issue"
effect = "allow"
principals = ["*"]
tools = ["github:create_issue"]
risk = "write"
approval = "jit"
jit_ttl_secs = 60
[[mcp_rules.arg_constraints]]
kind = "forbid_arg"
arg = "force"
"#;
        let base = policy(base_toml, None);

        // Longer TTL + removed constraint => escalated.
        let mut head_parsed = parse_policy_toml(base_toml).unwrap();
        head_parsed.mcp_rules[0].jit_ttl_secs = Some(600);
        head_parsed.mcp_rules[0].arg_constraints.clear();
        let head = CompiledPolicy::compile(None, &head_parsed).unwrap();
        let diff = compute_access_diff(&base, &head, &[alice()], &[], &[], "main");
        assert!(diff.has_escalations());
        assert!(diff.mcp_deltas.iter().any(|d| d.escalated));

        // Adding a repo stdio server emits critical .access.toml QuarantineAlert and sets has_escalations().
        let mut added_srv = parse_policy_toml(base_toml).unwrap();
        added_srv.mcp_servers.insert(
            "evil".to_owned(),
            McpServerConfig {
                transport: crate::schema::McpTransportKind::Stdio,
                command: Some("sh".to_owned()),
                args: vec!["-c".to_owned(), "env".to_owned()],
                ..McpServerConfig::default()
            },
        );
        let head_srv = CompiledPolicy::compile(None, &added_srv).unwrap();
        let srv_diff = compute_access_diff(&base, &head_srv, &[alice()], &[], &[], "main");
        assert!(srv_diff.has_escalations());
        assert!(
            srv_diff
                .quarantine_alerts
                .iter()
                .any(|a| a.path == ".access.toml" && a.severity == "critical")
        );
    }

    fn opt_mode(n: u8) -> Option<McpApprovalMode> {
        match n {
            0 => Some(McpApprovalMode::Auto),
            1 => Some(McpApprovalMode::Jit),
            2 => Some(McpApprovalMode::Deny),
            _ => None,
        }
    }

    fn mcp_rule(
        id: &str,
        effect: RuleEffect,
        principal: &str,
        approval: Option<McpApprovalMode>,
    ) -> McpToolRule {
        McpToolRule {
            id: id.to_owned(),
            effect,
            principals: vec![principal.to_owned()],
            tools: vec!["srv:tool".to_owned()],
            refs: vec![],
            risk: None,
            approval,
            jit_ttl_secs: None,
            arg_constraints: vec![],
            required_secrets: vec![],
            reason: None,
        }
    }

    proptest! {
        /// Invariants for ANY mix of layer rules and profile settings:
        /// Server Deny and Repo Deny (absent a Server Allow) always deny the human, and an
        /// agent is always a subset of the human: never allowed when the human isn't, never
        /// looser approval, never longer TTL.
        #[test]
        fn prop_mcp_invariants(
            repo_allow in any::<bool>(),
            repo_deny in any::<bool>(),
            srv_allow in any::<bool>(),
            srv_deny in any::<bool>(),
            profile_allow in any::<bool>(),
            profile_deny in any::<bool>(),
            agent_deny in any::<bool>(),
            repo_appr in 0u8..4,
            srv_appr in 0u8..4,
            agent_appr in 0u8..4,
            unknown_profile in any::<bool>(),
        ) {
            let mut repo = AccessPolicyFile::default();
            let mut server = AccessPolicyFile::default();
            if repo_allow {
                repo.mcp_rules.push(mcp_rule("r-allow", RuleEffect::Allow, "@alice", opt_mode(repo_appr)));
            }
            if repo_deny {
                repo.mcp_rules.push(mcp_rule("r-deny", RuleEffect::Deny, "@alice", None));
            }
            if srv_allow {
                server.mcp_rules.push(mcp_rule("s-allow", RuleEffect::Allow, "@alice", opt_mode(srv_appr)));
            }
            if srv_deny {
                server.mcp_rules.push(mcp_rule("s-deny", RuleEffect::Deny, "*", None));
            }
            if agent_deny {
                repo.mcp_rules.push(mcp_rule("a-deny", RuleEffect::Deny, "agent:bot", None));
            }
            if let Some(a) = opt_mode(agent_appr) {
                let mut r = mcp_rule("a-appr", RuleEffect::Allow, "agent:*", Some(a));
                r.jit_ttl_secs = Some(10);
                repo.mcp_rules.push(r);
            }
            repo.agent_profiles.push(crate::schema::AgentProfile {
                name: "bot".to_owned(),
                allow_paths: vec![],
                deny_paths: vec![],
                capabilities: vec![],
                allow_secret_use: vec![],
                allow_egress_hosts: vec![],
                allow_mcp_tools: if profile_allow { vec!["srv:tool".to_owned()] } else { vec![] },
                deny_mcp_tools: if profile_deny { vec!["srv:*".to_owned()] } else { vec![] },
                budget: crate::schema::AutonomyBudget::default(),
            });

            let compiled = CompiledPolicy::compile(Some(&server), &repo).unwrap();
            let user = Principal::User("alice".to_owned());
            let human = DelegatedIdentity::human_only(user.clone(), vec![]);
            let profile = if unknown_profile { "ghost" } else { "bot" };
            let agent = DelegatedIdentity::delegated(user, vec![], profile, "t");

            let h = compiled.evaluate_mcp_tool(&human, "srv", "tool", "main");
            let a = compiled.evaluate_mcp_tool(&agent, "srv", "tool", "main");

            let expect_human = ((repo_allow && !repo_deny) || srv_allow) && !srv_deny;
            if srv_deny {
                prop_assert!(!h.allowed && !a.allowed);
            }
            if repo_deny && !srv_allow {
                prop_assert!(!h.allowed && !a.allowed);
            }
            prop_assert_eq!(h.human_allowed, expect_human);
            // Default-deny: no allow rule at all means no access for anyone.
            if !repo_allow && !srv_allow {
                prop_assert!(!h.allowed && !a.allowed);
            }
            // agent <= human.
            if a.allowed {
                prop_assert!(h.allowed);
                prop_assert!(a.approval >= h.approval);
                prop_assert!(a.jit_ttl_secs <= h.jit_ttl_secs);
                prop_assert!(!unknown_profile && profile_allow && !profile_deny && !agent_deny);
            }
            let expect_agent = h.allowed
                && !unknown_profile
                && profile_allow
                && !profile_deny
                && !agent_deny
                && a.approval != McpApprovalMode::Deny;
            prop_assert_eq!(a.allowed, expect_agent);
            prop_assert_eq!(h.allowed, h.approval != McpApprovalMode::Deny && expect_human);
        }
    }
}
