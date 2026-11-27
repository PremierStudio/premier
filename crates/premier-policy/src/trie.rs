//! Prefix-trie bitmask compiler and deterministic `explain` evaluator.

use std::collections::{BTreeMap, HashMap};

use globset::{GlobBuilder, GlobMatcher};
use premier_core::{Capability, DelegatedIdentity, Principal, RepoPath};
use serde::{Deserialize, Serialize};

use crate::PolicyError;
use crate::mcp::{McpPolicy, McpToolPattern};
use crate::schema::{
    AccessPolicyFile, AgentProfile, AutonomyBudget, PolicyLayer, PolicyRule, RuleEffect, ZoneConfig,
};

/// Always-fenced paths that AI agents cannot modify unless explicitly allowed by Server policy.
pub(crate) const AGENT_PROTECTED_WRITE_PATHS: &[&str] = &[
    ".access.toml",
    "**/.access.toml",
    ".env.schema",
    "**/.env.schema",
    ".github/workflows/**",
    "AGENTS.md",
    "**/AGENTS.md",
    "CLAUDE.md",
    "**/CLAUDE.md",
    ".cursorrules",
    "**/.cursorrules",
    ".cursor/rules/**",
    ".github/copilot-instructions.md",
    "**/.github/copilot-instructions.md",
    ".mcp.json",
    "**/.mcp.json",
    ".claude/**",
    ".gitmodules",
    "**/.gitmodules",
];

// Compile-time guards against pathological policies.
pub(crate) const MAX_RULES: usize = 4096;
const MAX_AGENT_PROFILES: usize = 256;
pub(crate) const MAX_PATTERNS_PER_RULE: usize = 256;
pub(crate) const MAX_PATTERN_LEN: usize = 512;
pub(crate) const MAX_BRACE_ALTERNATES: usize = 64;
const MAX_INSTRUCTION_FILES: usize = 64;

pub(crate) fn check_limit(what: &str, n: usize, max: usize) -> Result<(), PolicyError> {
    if n > max {
        return Err(PolicyError::TooComplex(format!(
            "{what}: {n} exceeds the limit of {max}"
        )));
    }
    Ok(())
}

/// Shared length / brace-alternate guard for every glob compiled from policy text.
pub(crate) fn check_pattern_limits(pattern: &str) -> Result<(), PolicyError> {
    check_limit("glob pattern length", pattern.len(), MAX_PATTERN_LEN)?;
    check_limit(
        "glob brace alternates",
        pattern.matches(['{', ',']).count(),
        MAX_BRACE_ALTERNATES,
    )
}

/// True if `ref_name` satisfies `ref_globs` (an empty list means every ref).
pub(crate) fn ref_globs_match(ref_globs: &[CompiledGlob], ref_name: &str) -> bool {
    if ref_globs.is_empty() {
        return true;
    }
    let fake_path = RepoPath::new(ref_name.trim_start_matches('/')).ok();
    ref_globs.iter().any(|g| {
        if g.pattern == "*" || g.pattern == "**" {
            return true;
        }
        if let Some(ref p) = fake_path {
            g.is_match(p)
        } else {
            g.pattern == ref_name
        }
    })
}

/// Leading path segments free of glob metacharacters. A segment holding any of `* ? [ {` or a
/// backslash ends the prefix, so the rule is indexed high enough in the trie to stay a
/// candidate for every path it can match.
pub(crate) fn literal_prefix(pattern: &str) -> Vec<&str> {
    pattern
        .split('/')
        .take_while(|s| !s.contains(['*', '?', '[', '{', '\\']))
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledGlob {
    pattern: String,
    matcher: GlobMatcher,
    /// Case-insensitive matcher used for deny/fencing rules to block macOS/Windows
    /// case-folding ACL bypasses (e.g. `BILLING/secret.rs` vs `billing/**`).
    ci_matcher: GlobMatcher,
    /// Precompiled base matcher for `<base>/**` patterns to detect unconditional subtree coverage.
    subtree_base_matcher: Option<GlobMatcher>,
    /// Case-insensitive counterpart to `subtree_base_matcher`.
    ci_subtree_base_matcher: Option<GlobMatcher>,
}

impl CompiledGlob {
    pub(crate) fn new(pattern: &str) -> Result<Self, PolicyError> {
        let normalized = pattern.trim().trim_start_matches('/');
        check_pattern_limits(normalized)?;
        // `*` and `?` stop at `/` (only `**` crosses directories), and a backslash escapes on
        // every platform so a policy evaluates identically everywhere.
        let matcher = GlobBuilder::new(normalized)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
            .map_err(|e| PolicyError::InvalidGlob {
                pattern: pattern.to_owned(),
                source: e,
            })?
            .compile_matcher();
        let ci_matcher = GlobBuilder::new(normalized)
            .literal_separator(true)
            .backslash_escape(true)
            .case_insensitive(true)
            .build()
            .map_err(|e| PolicyError::InvalidGlob {
                pattern: pattern.to_owned(),
                source: e,
            })?
            .compile_matcher();
        let subtree_base = normalized
            .strip_suffix("/**")
            .filter(|base| !base.is_empty());
        let subtree_base_matcher = subtree_base.and_then(|base| {
            GlobBuilder::new(base)
                .literal_separator(true)
                .backslash_escape(true)
                .build()
                .ok()
                .map(|g| g.compile_matcher())
        });
        let ci_subtree_base_matcher = subtree_base.and_then(|base| {
            GlobBuilder::new(base)
                .literal_separator(true)
                .backslash_escape(true)
                .case_insensitive(true)
                .build()
                .ok()
                .map(|g| g.compile_matcher())
        });
        Ok(Self {
            pattern: normalized.to_owned(),
            matcher,
            ci_matcher,
            subtree_base_matcher,
            ci_subtree_base_matcher,
        })
    }

    pub(crate) fn is_match(&self, path: &RepoPath) -> bool {
        if self.pattern == "**" || self.pattern == "*" && !path.as_str().contains('/') {
            return true;
        }
        if path.is_root() {
            return self.pattern.is_empty() || self.pattern == "**";
        }
        self.matcher.is_match(path.as_str())
    }

    pub(crate) fn is_match_case_insensitive(&self, path: &RepoPath) -> bool {
        if self.pattern == "**" || self.pattern == "*" && !path.as_str().contains('/') {
            return true;
        }
        if path.is_root() {
            return self.pattern.is_empty() || self.pattern == "**";
        }
        self.ci_matcher.is_match(path.as_str())
    }

    /// True if this glob matches EVERY descendant path strictly beneath `dir`
    /// (e.g. `**` or `<base>/**` where `<base>` matches `dir` or a strict ancestor of `dir`).
    #[allow(dead_code)]
    fn covers_subtree_of(&self, dir: &RepoPath) -> bool {
        if self.pattern == "**" {
            return true;
        }
        if dir.is_root() {
            return false;
        }
        if let Some(ref base) = self.subtree_base_matcher {
            if base.is_match(dir.as_str()) {
                return true;
            }
            return dir
                .ancestors()
                .iter()
                .any(|anc| !anc.is_root() && base.is_match(anc.as_str()));
        }
        false
    }

    /// Case-insensitive counterpart to `covers_subtree_of` for deny/fencing rules.
    fn covers_subtree_of_case_insensitive(&self, dir: &RepoPath) -> bool {
        if self.pattern == "**" {
            return true;
        }
        if dir.is_root() {
            return false;
        }
        if let Some(ref base) = self.ci_subtree_base_matcher {
            if base.is_match(dir.as_str()) {
                return true;
            }
            return dir
                .ancestors()
                .iter()
                .any(|anc| !anc.is_root() && base.is_match(anc.as_str()));
        }
        false
    }

    /// True if `dir` is an ancestor of at least one path that this glob can match, enabling
    /// structural `TRAVERSE` synthesis without leaking sibling names.
    fn has_potential_descendant_under(&self, dir: &RepoPath) -> bool {
        if self.pattern == "**" {
            return true;
        }
        if dir.is_root() {
            return !self.pattern.is_empty();
        }
        let dir_str = dir.as_str();
        let dir_segs = dir.segments();
        let pat_segs: Vec<&str> = self.pattern.split('/').collect();

        // Extract literal segment prefix before the first wildcard.
        let literal_segs = literal_prefix(&self.pattern);
        if literal_segs.is_empty() {
            // Pattern starts with wildcard (e.g. `**/foo.rs`) — could match inside `dir`.
            if self.pattern.starts_with("**/") {
                return true;
            }
            if let Some(star_pos) = pat_segs.iter().position(|&s| s == "**") {
                let prefix_len = star_pos.min(dir_segs.len());
                if prefix_len == 0 {
                    return true;
                }
                let prefix_pat = pat_segs[..prefix_len].join("/");
                let dir_head = dir_segs[..prefix_len].join("/");
                return GlobBuilder::new(&prefix_pat)
                    .literal_separator(true)
                    .backslash_escape(true)
                    .build()
                    .is_ok_and(|g| g.compile_matcher().is_match(&dir_head));
            }
            if pat_segs.len() > dir_segs.len() {
                let prefix_pat = pat_segs[..dir_segs.len()].join("/");
                return GlobBuilder::new(&prefix_pat)
                    .literal_separator(true)
                    .backslash_escape(true)
                    .build()
                    .is_ok_and(|g| g.compile_matcher().is_match(dir_str));
            }
            return false;
        }
        let literal_prefix = literal_segs.join("/");
        // `literal_prefix` is strictly beneath `dir` (e.g. dir="billing", literal="billing/invoices/2026")
        if literal_prefix
            .strip_prefix(dir_str)
            .is_some_and(|rest| rest.starts_with('/'))
        {
            return true;
        }
        // Or `dir` is equal to `literal_prefix` AND pattern has additional segments.
        if literal_prefix == dir_str && self.pattern.len() > literal_prefix.len() {
            return true;
        }
        if dir_str
            .strip_prefix(&literal_prefix)
            .is_some_and(|rest| rest.starts_with('/'))
        {
            if self.pattern.contains("**") {
                return true;
            }
            if pat_segs.len() > dir_segs.len() {
                let prefix_pat = pat_segs[..dir_segs.len()].join("/");
                return GlobBuilder::new(&prefix_pat)
                    .literal_separator(true)
                    .backslash_escape(true)
                    .build()
                    .is_ok_and(|g| g.compile_matcher().is_match(dir_str));
            }
        }
        false
    }
}

/// Independent `(include, exclude)` target group so each zone's `exclude` list stays scoped
/// to that zone rather than leaking across other zones or direct `paths` on the same rule.
#[derive(Debug, Clone)]
struct CompiledTargetGroup {
    include_globs: Vec<CompiledGlob>,
    exclude_globs: Vec<CompiledGlob>,
}

impl CompiledTargetGroup {
    fn matches_path(&self, path: &RepoPath) -> bool {
        self.include_globs.iter().any(|g| g.is_match(path))
            && !self.exclude_globs.iter().any(|g| g.is_match(path))
    }

    /// Case-insensitive include match for `Deny` rules so macOS/Windows case-folding cannot
    /// bypass denials. Exclusions remain case-sensitive so wrong casing can never carve out a deny.
    fn matches_path_case_insensitive_deny(&self, path: &RepoPath) -> bool {
        self.include_globs
            .iter()
            .any(|g| g.is_match_case_insensitive(path))
            && !self.exclude_globs.iter().any(|g| g.is_match(path))
    }

    fn has_descendant_under(&self, dir: &RepoPath) -> bool {
        if self.exclude_globs.iter().any(|g| g.covers_subtree_of(dir)) {
            return false;
        }
        self.include_globs
            .iter()
            .any(|g| g.has_potential_descendant_under(dir))
    }

    fn covers_subtree_of_case_insensitive(&self, dir: &RepoPath) -> bool {
        if !self.exclude_globs.is_empty() {
            return false;
        }
        self.include_globs
            .iter()
            .any(|g| g.covers_subtree_of_case_insensitive(dir))
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: String,
    layer: PolicyLayer,
    effect: RuleEffect,
    principals: Vec<String>,
    except_principals: Vec<String>,
    target_groups: Vec<CompiledTargetGroup>,
    ref_globs: Vec<CompiledGlob>,
    capabilities: Capability,
    reason: Option<String>,
    /// Zone names the rule targets (`rule.zones`).
    zone_names: Vec<String>,
}

impl CompiledRule {
    fn matches_principal(&self, identity: &DelegatedIdentity) -> bool {
        self.principals
            .iter()
            .any(|sel| identity.matches_selector(sel))
            && !self
                .except_principals
                .iter()
                .any(|sel| identity.matches_selector(sel))
    }

    fn matches_ref(&self, ref_name: &str) -> bool {
        ref_globs_match(&self.ref_globs, ref_name)
    }

    fn matches_path(&self, path: &RepoPath) -> bool {
        self.target_groups.iter().any(|g| g.matches_path(path))
    }

    fn matches_path_case_insensitive_deny(&self, path: &RepoPath) -> bool {
        self.target_groups
            .iter()
            .any(|g| g.matches_path_case_insensitive_deny(path))
    }

    fn has_descendant_under(&self, dir: &RepoPath) -> bool {
        self.target_groups
            .iter()
            .any(|g| g.has_descendant_under(dir))
    }

    fn covers_subtree_of_case_insensitive(&self, dir: &RepoPath) -> bool {
        self.target_groups
            .iter()
            .any(|g| g.covers_subtree_of_case_insensitive(dir))
    }
}

/// A named zone's compiled path patterns: a path is in the zone when an include matches and no
/// exclude does.
#[derive(Debug, Clone)]
struct CompiledZone {
    include_globs: Vec<CompiledGlob>,
    exclude_globs: Vec<CompiledGlob>,
    // Carried for zone-owner approvals and audit output; nothing reads them yet.
    #[allow(dead_code)]
    owners: Vec<String>,
    #[allow(dead_code)]
    description: Option<String>,
}

impl CompiledZone {
    fn compile(zone: &ZoneConfig) -> Result<Self, PolicyError> {
        check_limit(
            "patterns in one zone",
            zone.paths.len() + zone.exclude.len(),
            MAX_PATTERNS_PER_RULE,
        )?;
        let globs = |patterns: &[String]| {
            patterns
                .iter()
                .map(|p| CompiledGlob::new(p))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            include_globs: globs(&zone.paths)?,
            exclude_globs: globs(&zone.exclude)?,
            owners: zone.owners.clone(),
            description: zone.description.clone(),
        })
    }

    fn contains(&self, path: &RepoPath) -> bool {
        self.include_globs.iter().any(|g| g.is_match(path))
            && !self.exclude_globs.iter().any(|g| g.is_match(path))
    }
}

/// A zone name as policies spell it, without the optional `zone:` prefix.
fn bare_zone_name(zone_name: &str) -> &str {
    let name = zone_name.trim();
    name.strip_prefix("zone:").unwrap_or(name)
}

/// Segment prefix-trie node holding indices of rules rooted at this literal prefix.
#[derive(Debug, Default, Clone)]
struct TrieNode {
    /// Rules whose literal path prefix terminates at this exact node.
    rule_indices: Vec<usize>,
    /// Child literal segments.
    children: BTreeMap<String, TrieNode>,
}

impl TrieNode {
    fn insert(&mut self, prefix_segments: &[&str], rule_idx: usize) {
        let mut node = self;
        for seg in prefix_segments {
            node = node.children.entry(seg.to_lowercase()).or_default();
        }
        node.rule_indices.push(rule_idx);
    }

    /// Collect all candidate rules along the path from root to `segments`.
    /// Keys are lowercased so case-insensitive `Deny` rules are always surfaced as candidates;
    /// `Allow` rules still verify exact casing during rule matching.
    fn collect_candidates(&self, segments: &[&str], out: &mut Vec<usize>) {
        out.extend_from_slice(&self.rule_indices);
        let mut node = self;
        for seg in segments {
            let key = seg.to_lowercase();
            match node.children.get(&key) {
                Some(child) => {
                    out.extend_from_slice(&child.rule_indices);
                    node = child;
                }
                None => break,
            }
        }
    }

    /// Collect all candidate rules that may match descendants beneath `segments`,
    /// including wildcard rules anchored at root or intermediate ancestors (e.g. `**/public.md`).
    fn collect_descendant_rules(&self, segments: &[&str], out: &mut Vec<usize>) {
        let mut node = self;
        out.extend_from_slice(&node.rule_indices);
        for seg in segments {
            let key = seg.to_lowercase();
            match node.children.get(&key) {
                Some(child) => {
                    node = child;
                    out.extend_from_slice(&node.rule_indices);
                }
                None => return,
            }
        }
        for child in node.children.values() {
            child.collect_all(out);
        }
    }

    fn collect_all(&self, out: &mut Vec<usize>) {
        out.extend_from_slice(&self.rule_indices);
        for child in self.children.values() {
            child.collect_all(out);
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledAgentProfile {
    layer: PolicyLayer,
    name: String,
    allow_paths: Vec<CompiledGlob>,
    deny_paths: Vec<CompiledGlob>,
    protected_write_paths: Vec<CompiledGlob>,
    capabilities: Capability,
    allow_secret_use: Vec<String>,
    allow_egress_hosts: Vec<String>,
    allow_mcp_tools: Vec<McpToolPattern>,
    deny_mcp_tools: Vec<McpToolPattern>,
    budget: AutonomyBudget,
}

impl CompiledAgentProfile {
    fn compile(layer: PolicyLayer, profile: &AgentProfile) -> Result<Self, PolicyError> {
        check_limit(
            "patterns in one agent profile",
            profile.allow_paths.len()
                + profile.deny_paths.len()
                + profile.allow_mcp_tools.len()
                + profile.deny_mcp_tools.len(),
            MAX_PATTERNS_PER_RULE,
        )?;
        let allow_mcp_tools = profile
            .allow_mcp_tools
            .iter()
            .map(|p| McpToolPattern::compile(p))
            .collect::<Result<Vec<_>, _>>()?;
        let deny_mcp_tools = profile
            .deny_mcp_tools
            .iter()
            .map(|p| McpToolPattern::compile(p))
            .collect::<Result<Vec<_>, _>>()?;
        let allow_paths = profile
            .allow_paths
            .iter()
            .map(|p| CompiledGlob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let deny_paths = profile
            .deny_paths
            .iter()
            .map(|p| CompiledGlob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let protected_write_paths = AGENT_PROTECTED_WRITE_PATHS
            .iter()
            .map(|p| CompiledGlob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let capabilities = Capability::from_names(profile.capabilities.iter().map(String::as_str))?;

        Ok(Self {
            layer,
            name: profile.name.clone(),
            allow_paths,
            deny_paths,
            protected_write_paths,
            capabilities,
            allow_secret_use: profile.allow_secret_use.clone(),
            allow_egress_hosts: profile.allow_egress_hosts.clone(),
            allow_mcp_tools,
            deny_mcp_tools,
            budget: profile.budget.clone(),
        })
    }

    fn evaluate_path(&self, path: &RepoPath) -> (Capability, bool) {
        if self
            .deny_paths
            .iter()
            .any(|g| g.is_match_case_insensitive(path))
        {
            return (Capability::empty(), false);
        }
        let allowed = self.allow_paths.iter().any(|g| g.is_match(path));
        if !allowed {
            // Check structural traverse for ancestor directories of allowed paths,
            // refusing to synthesize when the entire subtree is explicitly denied.
            let subtree_denied = self
                .deny_paths
                .iter()
                .any(|g| g.covers_subtree_of_case_insensitive(path));
            let can_traverse = !subtree_denied
                && self
                    .allow_paths
                    .iter()
                    .any(|g| g.has_potential_descendant_under(path));
            if can_traverse {
                return (Capability::TRAVERSE, true);
            }
            return (Capability::empty(), false);
        }

        let mut mask = self.capabilities;
        // Agent branch/file fencing: never allow WRITE to `.access.toml`, workflows, or
        // instruction files unless defined in a Server-layer profile.
        if self.layer == PolicyLayer::Repo
            && self
                .protected_write_paths
                .iter()
                .any(|g| g.is_match_case_insensitive(path))
        {
            mask.remove(Capability::WRITE);
        }
        (mask, false)
    }
}

/// Trace entry for a matched rule during `explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRuleTrace {
    pub id: String,
    pub layer: PolicyLayer,
    pub effect: RuleEffect,
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Deterministic decision and full audit trace from `CompiledPolicy::explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainDecision {
    pub path: String,
    pub ref_name: String,
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub effective: Capability,
    pub human_effective: Capability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_effective: Option<Capability>,
    pub synthesized_traverse: bool,
    pub matched_rules: Vec<MatchedRuleTrace>,
}

impl ExplainDecision {
    pub fn allows(&self, cap: Capability) -> bool {
        self.effective.contains(cap)
    }
}

/// Effective (Server > Repo merged) declassification firewall settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveFirewallConfig {
    pub enabled: bool,
    pub sensitive_identifiers: Vec<String>,
    pub min_snippet_bytes: usize,
    pub min_shingle_matches: usize,
    pub allow_owner_override: bool,
}

/// Compiled, immutable prefix-trie policy evaluator combining optional Server
/// overrides and in-repo `.access.toml`.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    public_defaults: Capability,
    authenticated_defaults: Capability,
    rules: Vec<CompiledRule>,
    trie: TrieNode,
    agent_profiles: HashMap<String, CompiledAgentProfile>,
    instruction_globs: Vec<CompiledGlob>,
    pinned_instruction_hashes: BTreeMap<String, String>,
    pinned_instruction_hashes_lower: BTreeMap<String, String>,
    pub(crate) mcp: McpPolicy,
    firewall: EffectiveFirewallConfig,
    firewall_ignore_globs: Vec<CompiledGlob>,
    quarantine_enforced: bool,
    quarantine_hold_pending: bool,
    quarantine_allowed_hosts: Vec<String>,
    /// Named zones; a server zone replaces the repository zone of the same name.
    zones: BTreeMap<String, CompiledZone>,
    /// Every zone definition from both layers, overridden ones included: a rule in each layer
    /// resolves its own layer's zone, so holding back "zone X" must cover either definition.
    layered_zones: Vec<(String, CompiledZone)>,
}

/// Identities an inbound (GitHub -> Premier) sync writes as: the public it came from, and the
/// sync service itself.
const INBOUND_SYNC_SERVICE: &str = "service:github-sync";

impl CompiledPolicy {
    /// Compile optional server/org policy + in-repo `.access.toml`.
    pub fn compile(
        server_policy: Option<&AccessPolicyFile>,
        repo_policy: &AccessPolicyFile,
    ) -> Result<Self, PolicyError> {
        let mut public_defaults =
            Capability::from_names(repo_policy.defaults.public.iter().map(String::as_str))?;
        let mut authenticated_defaults = Capability::from_names(
            repo_policy
                .defaults
                .authenticated
                .iter()
                .map(String::as_str),
        )?;
        // Server defaults override/narrow repo defaults when explicitly configured
        // (including explicit empty lists `public = []` / `authenticated = []` for default-deny).
        if let Some(srv) = server_policy {
            if srv.defaults.has_explicit_public() {
                public_defaults =
                    Capability::from_names(srv.defaults.public.iter().map(String::as_str))?;
            }
            if srv.defaults.has_explicit_authenticated() {
                authenticated_defaults =
                    Capability::from_names(srv.defaults.authenticated.iter().map(String::as_str))?;
            }
        }

        let mut rules = Vec::new();
        let mut trie = TrieNode::default();

        Self::compile_layer_rules(PolicyLayer::Repo, repo_policy, &mut rules, &mut trie)?;
        if let Some(srv) = server_policy {
            Self::compile_layer_rules(PolicyLayer::Server, srv, &mut rules, &mut trie)?;
        }

        check_limit(
            "agent profile count",
            repo_policy.agent_profiles.len() + server_policy.map_or(0, |s| s.agent_profiles.len()),
            MAX_AGENT_PROFILES,
        )?;
        // Server agent profiles override repo agent profiles with the same name.
        let mut agent_profiles = HashMap::new();
        for profile in &repo_policy.agent_profiles {
            let compiled = CompiledAgentProfile::compile(PolicyLayer::Repo, profile)?;
            agent_profiles.insert(compiled.name.clone(), compiled);
        }
        if let Some(srv) = server_policy {
            for profile in &srv.agent_profiles {
                let compiled = CompiledAgentProfile::compile(PolicyLayer::Server, profile)?;
                agent_profiles.insert(compiled.name.clone(), compiled);
            }
        }

        // Cap quarantine instruction globs before compiling them.
        check_limit(
            "quarantine instruction_files count",
            repo_policy.quarantine.instruction_files.len()
                + server_policy.map_or(0, |s| s.quarantine.instruction_files.len()),
            MAX_INSTRUCTION_FILES,
        )?;
        // Merge quarantine instruction globs & pinned hashes (server overrides repo pins).
        let mut instruction_globs = Vec::new();
        for pat in &repo_policy.quarantine.instruction_files {
            instruction_globs.push(CompiledGlob::new(pat)?);
        }
        let mut pinned_instruction_hashes = repo_policy.quarantine.pinned_hashes.clone();
        let mut pinned_instruction_hashes_lower: BTreeMap<String, String> = repo_policy
            .quarantine
            .pinned_hashes
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        if let Some(srv) = server_policy {
            for pat in &srv.quarantine.instruction_files {
                instruction_globs.push(CompiledGlob::new(pat)?);
            }
            for (k, v) in &srv.quarantine.pinned_hashes {
                pinned_instruction_hashes.insert(k.clone(), v.clone());
                pinned_instruction_hashes_lower.insert(k.to_ascii_lowercase(), v.clone());
            }
        }

        let mcp = McpPolicy::compile(server_policy, repo_policy)?;
        // Firewall + quarantine enforcement: Server `Some(..)` always wins over Repo.
        let default_file = AccessPolicyFile::default();
        let srv = server_policy.unwrap_or(&default_file);
        let (sfw, rfw) = (&srv.firewall, &repo_policy.firewall);
        let mut sensitive_identifiers: Vec<String> = rfw
            .sensitive_identifiers
            .iter()
            .chain(&sfw.sensitive_identifiers)
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        sensitive_identifiers.sort();
        sensitive_identifiers.dedup();
        let firewall = EffectiveFirewallConfig {
            enabled: sfw.enabled.or(rfw.enabled).unwrap_or(true),
            sensitive_identifiers,
            min_snippet_bytes: sfw
                .min_snippet_bytes
                .or(rfw.min_snippet_bytes)
                .unwrap_or(48)
                .max(24),
            min_shingle_matches: sfw
                .min_shingle_matches
                .or(rfw.min_shingle_matches)
                .unwrap_or(1)
                .max(1),
            allow_owner_override: sfw
                .allow_owner_override
                .or(rfw.allow_owner_override)
                .unwrap_or(true),
        };
        check_limit(
            "firewall ignore_paths",
            rfw.ignore_paths.len() + sfw.ignore_paths.len(),
            MAX_PATTERNS_PER_RULE,
        )?;
        // In-repo `firewall.ignore_paths` must NEVER weaken or silence a server-enforced or
        // server-configured declassification firewall: only server `ignore_paths` apply then.
        let server_controls_firewall_ignores = server_policy.is_some_and(|s| {
            let fw = &s.firewall;
            fw.enabled == Some(true)
                || fw.has_explicit_ignore_paths()
                || !fw.sensitive_identifiers.is_empty()
                || fw.min_snippet_bytes.is_some()
                || fw.min_shingle_matches.is_some()
                || fw.allow_owner_override.is_some()
        });
        let active_ignore_paths = if server_controls_firewall_ignores {
            &sfw.ignore_paths
        } else {
            &rfw.ignore_paths
        };
        let firewall_ignore_globs = active_ignore_paths
            .iter()
            .map(|p| CompiledGlob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let (sq, rq) = (&srv.quarantine, &repo_policy.quarantine);
        // In-repo `quarantine.allowed_hosts` must NEVER expand a server-enforced or
        // server-configured quarantine allow-list.
        let server_controls_quarantine_hosts = server_policy.is_some_and(|s| {
            let q = &s.quarantine;
            q.enforce == Some(true)
                || q.has_explicit_allowed_hosts()
                || q.hold_pending_for_non_owners == Some(true)
                || !q.pinned_hashes.is_empty()
        });
        let mut quarantine_allowed_hosts: Vec<String> = if server_controls_quarantine_hosts {
            sq.allowed_hosts.clone()
        } else {
            rq.allowed_hosts.clone()
        };
        quarantine_allowed_hosts.sort();
        quarantine_allowed_hosts.dedup();
        check_limit(
            "zone count",
            repo_policy.zones.len() + server_policy.map_or(0, |s| s.zones.len()),
            MAX_RULES,
        )?;
        let mut zones = BTreeMap::new();
        let mut layered_zones = Vec::new();
        for layer in std::iter::once(repo_policy).chain(server_policy) {
            for (name, zone) in &layer.zones {
                let (name, zone) = (
                    bare_zone_name(name).to_owned(),
                    CompiledZone::compile(zone)?,
                );
                layered_zones.push((name.clone(), zone.clone()));
                zones.insert(name, zone);
            }
        }

        Ok(Self {
            public_defaults,
            authenticated_defaults,
            rules,
            trie,
            agent_profiles,
            instruction_globs,
            pinned_instruction_hashes,
            pinned_instruction_hashes_lower,
            mcp,
            firewall,
            firewall_ignore_globs,
            quarantine_enforced: sq.enforce.or(rq.enforce).unwrap_or(true),
            quarantine_hold_pending: sq
                .hold_pending_for_non_owners
                .or(rq.hold_pending_for_non_owners)
                .unwrap_or(true),
            quarantine_allowed_hosts,
            zones,
            layered_zones,
        })
    }

    fn compile_layer_rules(
        layer: PolicyLayer,
        file: &AccessPolicyFile,
        rules: &mut Vec<CompiledRule>,
        trie: &mut TrieNode,
    ) -> Result<(), PolicyError> {
        check_limit("rule count", rules.len() + file.rules.len(), MAX_RULES)?;
        for rule in &file.rules {
            let compiled = Self::compile_rule(layer, file, rule)?;
            let idx = rules.len();
            // Index this rule in the prefix trie under every literal prefix it targets.
            for group in &compiled.target_groups {
                for glob in &group.include_globs {
                    trie.insert(&literal_prefix(&glob.pattern), idx);
                }
            }
            rules.push(compiled);
        }
        Ok(())
    }

    fn compile_rule(
        layer: PolicyLayer,
        file: &AccessPolicyFile,
        rule: &PolicyRule,
    ) -> Result<CompiledRule, PolicyError> {
        let capabilities = Capability::from_names(rule.capabilities.iter().map(String::as_str))?;
        check_limit(
            "principals in one rule",
            rule.principals.len() + rule.except_principals.len(),
            MAX_PATTERNS_PER_RULE,
        )?;

        // Check total pattern budget BEFORE compiling any glob to prevent compile-time CPU DoS.
        let mut total_patterns = rule.paths.len().saturating_add(rule.refs.len());
        let mut resolved_zones = Vec::with_capacity(rule.zones.len());
        for zone_name in &rule.zones {
            let zone = file
                .zones
                .get(zone_name)
                .ok_or_else(|| PolicyError::UnknownZone {
                    rule_id: rule.id.clone(),
                    zone: zone_name.clone(),
                })?;
            total_patterns = total_patterns
                .saturating_add(zone.paths.len())
                .saturating_add(zone.exclude.len());
            resolved_zones.push(zone);
        }
        check_limit(
            "patterns in one rule",
            total_patterns,
            MAX_PATTERNS_PER_RULE,
        )?;

        let mut target_groups = Vec::new();

        if !rule.paths.is_empty() {
            let include_globs = rule
                .paths
                .iter()
                .map(|p| CompiledGlob::new(p))
                .collect::<Result<Vec<_>, _>>()?;
            target_groups.push(CompiledTargetGroup {
                include_globs,
                exclude_globs: Vec::new(),
            });
        }

        // Keep each zone's `(paths, exclude)` scoped independently so one zone's exclusions
        // never suppress paths matched by another zone or direct `paths` on the same rule.
        for zone in resolved_zones {
            let include_globs = zone
                .paths
                .iter()
                .map(|p| CompiledGlob::new(p))
                .collect::<Result<Vec<_>, _>>()?;
            let exclude_globs = zone
                .exclude
                .iter()
                .map(|ex| CompiledGlob::new(ex))
                .collect::<Result<Vec<_>, _>>()?;
            if !include_globs.is_empty() {
                target_groups.push(CompiledTargetGroup {
                    include_globs,
                    exclude_globs,
                });
            }
        }

        if target_groups.is_empty() {
            return Err(PolicyError::EmptyRuleTargets {
                rule_id: rule.id.clone(),
            });
        }

        let ref_globs = rule
            .refs
            .iter()
            .map(|r| CompiledGlob::new(r))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CompiledRule {
            id: rule.id.clone(),
            layer,
            effect: rule.effect,
            principals: rule.principals.clone(),
            except_principals: rule.except_principals.clone(),
            target_groups,
            ref_globs,
            capabilities,
            reason: rule.reason.clone(),
            zone_names: rule.zones.clone(),
        })
    }

    /// Evaluate effective capabilities and return a complete deterministic explanation.
    pub fn explain(
        &self,
        identity: &DelegatedIdentity,
        path: &RepoPath,
        ref_name: &str,
    ) -> ExplainDecision {
        // Compute human/base identity without agent_task first so we can strictly intersect.
        let human_id =
            DelegatedIdentity::human_only(identity.principal.clone(), identity.groups.clone());

        let defaults = if human_id.principal.is_authenticated() {
            self.public_defaults | self.authenticated_defaults
        } else {
            self.public_defaults
        };

        let segments = path.segments();
        let mut candidate_indices = Vec::new();
        self.trie
            .collect_candidates(&segments, &mut candidate_indices);
        candidate_indices.sort_unstable();
        candidate_indices.dedup();

        let mut repo_allow = Capability::empty();
        let mut repo_deny = Capability::empty();
        let mut server_allow = Capability::empty();
        let mut server_deny = Capability::empty();
        let mut repo_subtree_deny = Capability::empty();
        let mut server_subtree_deny = Capability::empty();
        let mut matched_rules = Vec::new();

        for idx in candidate_indices {
            let rule = &self.rules[idx];
            if !rule.matches_principal(&human_id) || !rule.matches_ref(ref_name) {
                continue;
            }
            if rule.effect == RuleEffect::Deny && rule.covers_subtree_of_case_insensitive(path) {
                match rule.layer {
                    PolicyLayer::Repo => repo_subtree_deny |= rule.capabilities,
                    PolicyLayer::Server => server_subtree_deny |= rule.capabilities,
                }
            }
            let path_matches = match rule.effect {
                RuleEffect::Allow => rule.matches_path(path),
                RuleEffect::Deny => rule.matches_path_case_insensitive_deny(path),
            };
            if !path_matches {
                continue;
            }
            match (rule.layer, rule.effect) {
                (PolicyLayer::Repo, RuleEffect::Allow) => repo_allow |= rule.capabilities,
                (PolicyLayer::Repo, RuleEffect::Deny) => repo_deny |= rule.capabilities,
                (PolicyLayer::Server, RuleEffect::Allow) => server_allow |= rule.capabilities,
                (PolicyLayer::Server, RuleEffect::Deny) => server_deny |= rule.capabilities,
            }
            matched_rules.push(MatchedRuleTrace {
                id: rule.id.clone(),
                layer: rule.layer,
                effect: rule.effect,
                capabilities: rule
                    .capabilities
                    .to_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                reason: rule.reason.clone(),
            });
        }

        // Core precedence algebra:
        // 1. Within Repo: Deny overrides Allow.
        // 2. Server overrides Repo (Server Allow overrides Repo Deny; Server Deny overrides ALL).
        let repo_net = (defaults | repo_allow) & !repo_deny;
        let mut human_effective = (repo_net | server_allow) & !server_deny;

        // Structural ancestor TRAVERSE synthesis:
        // - Server Deny on TRAVERSE (on `path` or its entire subtree) always blocks synthesis.
        // - Repo Deny on TRAVERSE (or subtree deny cancelling every capability of a Repo allow)
        //   blocks Repo descendant Allows, while a Server descendant Allow still synthesizes
        //   TRAVERSE (Server overrides Repo) without granting LIST or READ.
        let mut synthesized_traverse = false;
        let server_denied_traverse = server_deny.contains(Capability::TRAVERSE)
            || server_subtree_deny.contains(Capability::TRAVERSE);
        let repo_denied_traverse = (repo_deny.contains(Capability::TRAVERSE)
            || repo_subtree_deny.contains(Capability::TRAVERSE))
            && !server_allow.contains(Capability::TRAVERSE);

        if !human_effective.contains(Capability::TRAVERSE) && !server_denied_traverse {
            let mut desc_indices = Vec::new();
            self.trie
                .collect_descendant_rules(&segments, &mut desc_indices);
            desc_indices.sort_unstable();
            desc_indices.dedup();

            let has_authorized_descendant = desc_indices.iter().any(|&idx| {
                let rule = &self.rules[idx];
                if rule.effect != RuleEffect::Allow
                    || !rule.matches_principal(&human_id)
                    || !rule.matches_ref(ref_name)
                    || !rule.has_descendant_under(path)
                {
                    return false;
                }
                let surviving = match rule.layer {
                    PolicyLayer::Server => rule.capabilities & !server_subtree_deny,
                    PolicyLayer::Repo => {
                        if repo_denied_traverse {
                            return false;
                        }
                        rule.capabilities & !(repo_subtree_deny | server_subtree_deny)
                    }
                };
                surviving.intersects(
                    Capability::LIST | Capability::READ | Capability::WRITE | Capability::USE,
                )
            });

            if has_authorized_descendant {
                human_effective |= Capability::TRAVERSE;
                synthesized_traverse = true;
            }
        }

        // Enforce Delegated Agent Authority: effective = permissions(human) ∩ permissions(agent_task)
        let (effective, agent_effective) = match &identity.agent_task {
            None => (human_effective, None),
            Some(agent_task) => {
                let (agent_rule_deny, traces) = self.agent_rule_deny(identity, path, ref_name);
                matched_rules.extend(traces);

                let profile_mask = match self.agent_profiles.get(&agent_task.profile) {
                    Some(profile) => {
                        let (mask, synth) = profile.evaluate_path(path);
                        if synth {
                            synthesized_traverse = true;
                        }
                        mask
                    }
                    // Unknown agent profile => default-deny.
                    None => Capability::empty(),
                };
                let agent_mask = profile_mask & !agent_rule_deny;
                (human_effective & agent_mask, Some(agent_mask))
            }
        };

        ExplainDecision {
            path: path.to_string(),
            ref_name: ref_name.to_owned(),
            principal: identity.principal.canonical_id(),
            agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
            effective,
            human_effective,
            agent_effective,
            synthesized_traverse,
            matched_rules,
        }
    }

    /// Capabilities removed by explicit `agent:*` / `agent:<profile>` deny rules matching `path`.
    fn agent_rule_deny(
        &self,
        identity: &DelegatedIdentity,
        path: &RepoPath,
        ref_name: &str,
    ) -> (Capability, Vec<MatchedRuleTrace>) {
        let mut denied = Capability::empty();
        let mut traces = Vec::new();
        let mut cands = Vec::new();
        self.trie.collect_candidates(&path.segments(), &mut cands);
        cands.sort_unstable();
        cands.dedup();
        for idx in cands {
            let rule = &self.rules[idx];
            if rule.effect == RuleEffect::Deny
                && rule
                    .principals
                    .iter()
                    .any(|p| p.trim().starts_with("agent:"))
                && rule.matches_principal(identity)
                && rule.matches_ref(ref_name)
                && rule.matches_path_case_insensitive_deny(path)
            {
                denied |= rule.capabilities;
                traces.push(MatchedRuleTrace {
                    id: rule.id.clone(),
                    layer: rule.layer,
                    effect: rule.effect,
                    capabilities: rule
                        .capabilities
                        .to_names()
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    reason: rule.reason.clone(),
                });
            }
        }
        (denied, traces)
    }

    /// Evaluate whether `identity` may `USE` a secret capability via the egress proxy
    /// (enforcing `human ∩ agent_task` and binding to the variable's zone if set).
    pub fn can_use_secret(
        &self,
        identity: &DelegatedIdentity,
        var_name: &str,
        zone: Option<&str>,
        ref_name: &str,
    ) -> ExplainDecision {
        let synthetic_path = match zone {
            Some(z) => format!("secrets/{z}/{var_name}"),
            None => format!("secrets/{var_name}"),
        };
        // Fail closed on invalid/traversal variable or zone names: never fall back to root.
        let Ok(path) = RepoPath::new(&synthetic_path) else {
            return ExplainDecision {
                path: synthetic_path,
                ref_name: ref_name.to_owned(),
                principal: identity.principal.canonical_id(),
                agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
                effective: Capability::empty(),
                human_effective: Capability::empty(),
                agent_effective: identity.agent_task.as_ref().map(|_| Capability::empty()),
                synthesized_traverse: false,
                matched_rules: Vec::new(),
            };
        };

        // Evaluate base human permissions on the secret's logical path.
        let human_id =
            DelegatedIdentity::human_only(identity.principal.clone(), identity.groups.clone());
        let mut decision = self.explain(&human_id, &path, ref_name);

        if let Some(agent_task) = &identity.agent_task {
            // The profile must list the variable and must not fence off its logical path.
            let agent_allows_use = self
                .agent_profiles
                .get(&agent_task.profile)
                .is_some_and(|p| {
                    p.allow_secret_use
                        .iter()
                        .any(|allowed| allowed == var_name || allowed == "*")
                        && !p
                            .deny_paths
                            .iter()
                            .any(|g| g.is_match_case_insensitive(&path))
                });
            let (agent_rule_deny, traces) = self.agent_rule_deny(identity, &path, ref_name);
            decision.matched_rules.extend(traces);
            // Agents NEVER receive raw READ on secrets; only USE if both human and agent allow it.
            let agent_mask = if agent_allows_use {
                Capability::USE & !agent_rule_deny
            } else {
                Capability::empty()
            };
            decision.agent_profile = Some(agent_task.profile.clone());
            decision.agent_effective = Some(agent_mask);
            decision.effective = decision.human_effective & agent_mask;
        }
        decision
    }

    /// Names of Zones (sorted by name) whose include globs match `path` and no exclude glob does.
    /// Labelling only: callers must apply ACL checks before exposing the result.
    pub fn zones_for_path(&self, path: &RepoPath) -> Vec<&str> {
        self.zones
            .iter()
            .filter(|(_, z)| z.contains(path))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// First matching Zone name for `path`, if any.
    pub fn primary_zone(&self, path: &RepoPath) -> Option<&str> {
        self.zones
            .iter()
            .find(|(_, z)| z.contains(path))
            .map(|(name, _)| name.as_str())
    }

    /// Whether the policy (repository or server) declares an agent profile of this name.
    pub fn has_agent_profile(&self, profile_name: &str) -> bool {
        self.agent_profiles.contains_key(profile_name)
    }

    /// Whether agent profile `profile` may call `server:tool` (`allow_mcp_tools` minus
    /// `deny_mcp_tools`). `None` means the profile is unknown (callers default-deny).
    pub(crate) fn agent_profile_allows_mcp(
        &self,
        profile: &str,
        server: &str,
        tool: &str,
    ) -> Option<bool> {
        let p = self.agent_profiles.get(profile)?;
        let hit = |pats: &[McpToolPattern]| pats.iter().any(|t| t.matches(server, tool));
        Some(hit(&p.allow_mcp_tools) && !hit(&p.deny_mcp_tools))
    }

    pub(crate) fn agent_profile_mcp_patterns(
        &self,
        profile: &str,
    ) -> Option<(&[McpToolPattern], &[McpToolPattern])> {
        self.agent_profiles
            .get(profile)
            .map(|p| (p.allow_mcp_tools.as_slice(), p.deny_mcp_tools.as_slice()))
    }

    /// Return the non-secret egress hosts explicitly allowed for an agent profile.
    pub fn agent_allowed_egress_hosts(&self, profile_name: &str) -> Vec<String> {
        self.agent_profiles
            .get(profile_name)
            .map(|p| p.allow_egress_hosts.clone())
            .unwrap_or_default()
    }

    /// Return the autonomy budget declared on an agent profile (Server overrides Repo).
    pub fn agent_budget(&self, profile_name: &str) -> Option<AutonomyBudget> {
        self.agent_profiles
            .get(profile_name)
            .map(|p| p.budget.clone())
    }

    /// Names of the zones that contain `path`, sorted and unique. A zone defined in both layers
    /// matches under either definition (unlike `zones_for_path`, where the server's replaces).
    pub fn matching_zones(&self, path: &RepoPath) -> Vec<String> {
        let names: std::collections::BTreeSet<&String> = self
            .layered_zones
            .iter()
            .filter(|(_, z)| z.contains(path))
            .map(|(name, _)| name)
            .collect();
        names.into_iter().cloned().collect()
    }

    /// Zones named by a deny rule that removes anonymous read, list or traverse on `ref_name`,
    /// sorted and unique: what a publish onto that ref holds back by zone.
    pub fn anonymous_denied_zones(&self, ref_name: &str) -> Vec<String> {
        let public = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let visibility_caps = Capability::READ | Capability::LIST | Capability::TRAVERSE;
        let names: std::collections::BTreeSet<&str> = self
            .rules
            .iter()
            .filter(|r| {
                r.effect == RuleEffect::Deny
                    && r.capabilities.intersects(visibility_caps)
                    && r.matches_principal(&public)
                    && r.matches_ref(ref_name)
            })
            .flat_map(|r| r.zone_names.iter().map(String::as_str))
            .collect();
        names.into_iter().map(str::to_owned).collect()
    }

    /// True if `path` is an untrusted repo instruction file subject to quarantine.
    pub fn is_instruction_file(&self, path: &RepoPath) -> bool {
        self.instruction_globs
            .iter()
            .any(|g| g.is_match_case_insensitive(path))
    }

    /// Pinned SHA-256 hash (if any) for an instruction file (case-insensitive path lookup).
    pub fn pinned_instruction_hash(&self, path: &RepoPath) -> Option<&str> {
        self.pinned_instruction_hashes_lower
            .get(&path.as_str().to_ascii_lowercase())
            .map(String::as_str)
    }

    /// All pinned instruction file hashes `(path -> sha256_hex)`.
    pub fn pinned_instruction_hashes(&self) -> &BTreeMap<String, String> {
        &self.pinned_instruction_hashes
    }

    pub fn firewall_enabled(&self) -> bool {
        self.firewall.enabled
    }

    pub fn firewall_sensitive_identifiers(&self) -> &[String] {
        &self.firewall.sensitive_identifiers
    }

    pub fn firewall_min_snippet_bytes(&self) -> usize {
        self.firewall.min_snippet_bytes
    }

    pub fn firewall_min_shingle_matches(&self) -> usize {
        self.firewall.min_shingle_matches
    }

    pub fn firewall_allow_owner_override(&self) -> bool {
        self.firewall.allow_owner_override
    }

    /// True if `path` is excluded from firewall metadata/snippet leak checks.
    pub fn is_firewall_ignored_path(&self, path: &RepoPath) -> bool {
        self.firewall_ignore_globs.iter().any(|g| g.is_match(path))
    }

    pub fn quarantine_enforced(&self) -> bool {
        self.quarantine_enforced
    }

    pub fn quarantine_hold_pending(&self) -> bool {
        self.quarantine_hold_pending
    }

    pub fn quarantine_allowed_hosts(&self) -> &[String] {
        &self.quarantine_allowed_hosts
    }

    /// Every egress host any agent profile or the quarantine config allows (sorted, deduped).
    pub fn all_allowed_egress_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .agent_profiles
            .values()
            .flat_map(|p| p.allow_egress_hosts.iter())
            .chain(&self.quarantine_allowed_hosts)
            .cloned()
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// True if an anonymous principal may read `path` and enter every ancestor directory
    /// (mirrors the projected public view in `premier-git-bridge`).
    pub fn is_path_public(&self, path: &RepoPath, ref_name: &str) -> bool {
        let public = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let may = |p: &str, any_of: Capability| {
            RepoPath::new(p).is_ok_and(|rp| {
                self.explain(&public, &rp, ref_name)
                    .effective
                    .intersects(any_of)
            })
        };
        let enter = Capability::TRAVERSE | Capability::LIST | Capability::READ;
        let p = path.as_str();
        !path.is_root()
            && may(p, Capability::READ)
            && p.match_indices('/').all(|(end, _)| may(&p[..end], enter))
    }

    /// Whether the policy (repository or server) declares the zone (`name` or `zone:name`).
    pub fn has_zone(&self, zone_name: &str) -> bool {
        self.zones.contains_key(bare_zone_name(zone_name))
    }

    /// Every declared zone name, sorted, without the `zone:` prefix.
    pub fn zone_names(&self) -> Vec<String> {
        self.zones.keys().cloned().collect()
    }

    /// Whether `path` is in the zone: one of its paths matches and none of its excludes does.
    /// An unknown zone contains nothing.
    pub fn path_in_zone(&self, zone_name: &str, path: &RepoPath) -> bool {
        self.zones
            .get(bare_zone_name(zone_name))
            .is_some_and(|zone| zone.contains(path))
    }

    /// Whether an inbound sync may write `path` on `ref_name`, judged by explicit `write` rules
    /// for both the anonymous public and `service:github-sync`: refused when a Server rule denies
    /// either, or a Repo rule denies either without a Server rule allowing that one. The public
    /// defaults are not consulted: anonymous pushes are normally off, while an owner-run sync
    /// writes public files unless `write` is denied.
    pub fn allows_inbound_write(&self, path: &RepoPath, ref_name: &str) -> bool {
        let mut candidates = Vec::new();
        self.trie
            .collect_candidates(&path.segments(), &mut candidates);
        candidates.sort_unstable();
        candidates.dedup();
        let identities = [
            DelegatedIdentity::human_only(premier_core::Principal::Anonymous, vec![]),
            DelegatedIdentity::human_only(
                premier_core::Principal::Service(INBOUND_SYNC_SERVICE.to_owned()),
                vec![],
            ),
        ];
        identities.iter().all(|identity| {
            let (mut repo_deny, mut server_allow, mut server_deny) = (false, false, false);
            let matching = candidates
                .iter()
                .map(|&idx| &self.rules[idx])
                .filter(|rule| {
                    rule.capabilities.contains(Capability::WRITE)
                        && rule.matches_principal(identity)
                        && rule.matches_ref(ref_name)
                        && match rule.effect {
                            RuleEffect::Allow => rule.matches_path(path),
                            RuleEffect::Deny => rule.matches_path_case_insensitive_deny(path),
                        }
                });
            for rule in matching {
                match (rule.layer, rule.effect) {
                    (PolicyLayer::Repo, RuleEffect::Deny) => repo_deny = true,
                    (PolicyLayer::Server, RuleEffect::Allow) => server_allow = true,
                    (PolicyLayer::Server, RuleEffect::Deny) => server_deny = true,
                    (PolicyLayer::Repo, RuleEffect::Allow) => {}
                }
            }
            !server_deny && (!repo_deny || server_allow)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod zone_tests {
    use super::*;
    use crate::parse_policy_toml;

    fn compile(server: Option<&str>, repo: &str) -> CompiledPolicy {
        let srv = server.map(|s| parse_policy_toml(s).unwrap());
        CompiledPolicy::compile(srv.as_ref(), &parse_policy_toml(repo).unwrap()).unwrap()
    }

    fn p(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    #[test]
    fn zone_matching_and_exclusions() {
        let pol = compile(
            None,
            r#"
version = 1
[zones.billing]
paths = ["billing/**"]
exclude = ["billing/public/**"]
[zones.docs]
paths = ["docs/**", "billing/README.md"]
"#,
        );
        assert_eq!(pol.zones_for_path(&p("billing/a.rs")), vec!["billing"]);
        assert_eq!(pol.primary_zone(&p("billing/a.rs")), Some("billing"));
        // Excluded from billing; matches no other zone.
        assert!(pol.zones_for_path(&p("billing/public/x.md")).is_empty());
        assert_eq!(pol.primary_zone(&p("billing/public/x.md")), None);
        // Overlapping zones are all reported, in deterministic (name) order.
        assert_eq!(
            pol.zones_for_path(&p("billing/README.md")),
            vec!["billing", "docs"]
        );
        assert_eq!(pol.primary_zone(&p("src/main.rs")), None);
    }

    #[test]
    fn server_zone_overrides_repo_zone_of_same_name() {
        let pol = compile(
            Some("version = 1\n[zones.core]\npaths = [\"server/**\"]\n"),
            "version = 1\n[zones.core]\npaths = [\"repo/**\"]\n[zones.extra]\npaths = [\"repo/**\"]\n",
        );
        assert_eq!(pol.primary_zone(&p("server/a")), Some("core"));
        // Repo's definition of `core` is replaced, so only `extra` claims repo/**.
        assert_eq!(pol.zones_for_path(&p("repo/a")), vec!["extra"]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod airlock_zone_tests {
    use super::*;
    use crate::parse_policy_toml;

    #[test]
    fn zones_match_paths_and_anonymous_denies_name_zones() {
        let repo = parse_policy_toml(
            r#"
[zones.billing]
paths = ["billing/**"]
exclude = ["billing/public/**"]
[zones.docs]
paths = ["docs/**"]
[zones.unused]
paths = ["billing/**"]
[[rules]]
id = "hide-billing"
effect = "deny"
principals = ["anonymous"]
zones = ["billing"]
refs = ["main"]
capabilities = ["read"]
[[rules]]
id = "docs-for-all"
effect = "allow"
principals = ["*"]
zones = ["docs"]
capabilities = ["read"]
[[rules]]
id = "docs-no-write"
effect = "deny"
principals = ["anonymous"]
zones = ["docs"]
refs = ["main"]
capabilities = ["write"]
"#,
        )
        .unwrap();
        let server = parse_policy_toml(
            r#"
[zones.billing]
paths = ["ledger/**"]
[zones.vault]
paths = ["vault/**"]
[[rules]]
id = "srv-vault"
effect = "deny"
principals = ["group:contractors"]
zones = ["vault"]
capabilities = ["read"]
"#,
        )
        .unwrap();
        let policy = CompiledPolicy::compile(Some(&server), &repo).unwrap();
        let zones = |p: &str| policy.matching_zones(&RepoPath::new(p).unwrap());
        assert_eq!(zones("billing/x.txt"), ["billing", "unused"]);
        assert_eq!(zones("billing/public/x.txt"), ["unused"]);
        // Same name in both layers: either definition puts a path in the zone.
        assert_eq!(zones("ledger/a"), ["billing"]);
        assert_eq!(zones("docs/a.md"), ["docs"]);
        assert!(zones("src/main.rs").is_empty());

        assert_eq!(policy.anonymous_denied_zones("main"), ["billing"]);
        // Wrong ref, or a deny that is not anonymous's: nothing.
        assert!(policy.anonymous_denied_zones("dev").is_empty());
    }

    #[test]
    fn pinned_instruction_hash_is_case_insensitive_and_gitmodules_is_agent_protected() {
        let repo = parse_policy_toml(
            r#"
[[rules]]
id = "allow-all"
effect = "allow"
principals = ["*"]
paths = ["**"]
capabilities = ["read", "list", "traverse", "write"]

[[agent_profiles]]
name = "coder"
allow_paths = ["**"]
capabilities = ["read", "list", "traverse", "write"]

[quarantine.pinned_hashes]
"CLAUDE.md" = "aaaa1111"
"docs/Agents.md" = "bbbb2222"
"#,
        )
        .unwrap();
        let server = parse_policy_toml(
            r#"
[quarantine.pinned_hashes]
"claude.md" = "cccc3333"
"#,
        )
        .unwrap();
        let policy = CompiledPolicy::compile(Some(&server), &repo).unwrap();
        // Server pin overrides repo pin regardless of path casing, and lookups are case-insensitive.
        assert_eq!(
            policy.pinned_instruction_hash(&RepoPath::new("CLAUDE.md").unwrap()),
            Some("cccc3333")
        );
        assert_eq!(
            policy.pinned_instruction_hash(&RepoPath::new("claude.md").unwrap()),
            Some("cccc3333")
        );
        assert_eq!(
            policy.pinned_instruction_hash(&RepoPath::new("DOCS/AGENTS.MD").unwrap()),
            Some("bbbb2222")
        );
        // `.gitmodules` and case variants are always write-fenced for agents.
        let agent = DelegatedIdentity::delegated(
            Principal::User("alice".to_owned()),
            vec![],
            "coder",
            "task-1",
        );
        for p in [".gitmodules", ".GITMODULES", "sub/.gitmodules"] {
            let d = policy.explain(&agent, &RepoPath::new(p).unwrap(), "main");
            assert!(
                !d.allows(Capability::WRITE),
                "agent must not be allowed to write {p}"
            );
        }
    }
}
