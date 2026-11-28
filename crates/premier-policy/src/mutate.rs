//! Comment-preserving `.access.toml` mutator: turns one direct-manipulation intent from Studio
//! into proposed policy text. It only proposes; the server validates it and an owner applies it.
//!
//! Every edit keeps the security algebra intact: intents only add Repo-layer rules or narrow agent
//! profiles, owners are never carved out of a restriction, and agents only ever gain secret `use`
//! (never `read`).

use premier_core::RepoPath;
use serde::{Deserialize, Serialize};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use crate::schema::{AccessPolicyFile, PolicyRule, RuleEffect};
use crate::trie::{AGENT_PROTECTED_WRITE_PATHS, CompiledGlob, CompiledPolicy, literal_prefix};
use crate::{PolicyError, parse_policy_toml, sha256_hex};

const ALL_CAPS: &[&str] = &["traverse", "list", "read", "write", "use"];
const READ_CAPS: &[&str] = &["traverse", "list", "read"];
const RW_CAPS: &[&str] = &["traverse", "list", "read", "write"];
const OWNERS: &str = "group:owners";
/// Stand-in child name used to probe whether a glob reaches inside a directory.
const PROBE_CHILD: &str = "__premier_probe__";
const MAX_REASON_LEN: usize = 512;

/// What an intent acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyTarget {
    File { path: String },
    Dir { path: String },
    Zone { zone: String },
}

/// One direct-manipulation policy edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyIntent {
    ShieldFromAnonymous {
        target: PolicyTarget,
        #[serde(default)]
        reason: Option<String>,
    },
    ShieldFromAllAgents {
        target: PolicyTarget,
        #[serde(default)]
        reason: Option<String>,
    },
    ShieldFromAgent {
        target: PolicyTarget,
        agent_profile: String,
        #[serde(default)]
        reason: Option<String>,
    },
    AllowAgentAccess {
        target: PolicyTarget,
        agent_profile: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        reason: Option<String>,
    },
    RestrictToPrincipals {
        target: PolicyTarget,
        principals: Vec<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        reason: Option<String>,
    },
    AllowAgentSecretUse {
        var_name: String,
        #[serde(default)]
        zone: Option<String>,
        agent_profile: String,
        #[serde(default)]
        human_principals: Vec<String>,
        #[serde(default)]
        reason: Option<String>,
    },
    RevokeAgentSecretUse {
        var_name: String,
        #[serde(default)]
        zone: Option<String>,
        agent_profile: String,
        #[serde(default)]
        reason: Option<String>,
    },
}

/// A secret whose `use` an intent touched, for the caller to diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretProbe {
    pub var_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMutationResult {
    pub proposed_toml: String,
    pub rule_id: String,
    pub summary: String,
    pub warnings: Vec<String>,
    pub target_paths: Vec<String>,
    pub secret_probes: Vec<SecretProbe>,
}

fn invalid(msg: impl Into<String>) -> PolicyError {
    PolicyError::InvalidIntent(msg.into())
}

/// A resolved [`PolicyTarget`].
struct Target {
    /// `<slug>-<hash6>`, the deterministic suffix of every rule id for this target.
    slug: String,
    label: String,
    /// Rule `paths` / `zones` fields.
    paths: Vec<String>,
    zones: Vec<String>,
    /// Every glob the target expands to (zone paths included).
    globs: Vec<String>,
    /// Concrete representative paths, for overlap warnings.
    probes: Vec<RepoPath>,
    target_paths: Vec<String>,
}

/// Escape glob metacharacters so a literal file or directory name matches only itself.
fn escape_glob(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `slug` (lowercase `[a-z0-9-]`, ≤36 chars) plus 6 hex chars of `sha256(key)`, so targets whose
/// slugs collide (`a/b` vs `a-b`) still get distinct ids.
fn rule_slug(text: &str, key: &str) -> String {
    let mut slug = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.truncate(36);
    let slug = slug.trim_end_matches('-');
    let slug = if slug.is_empty() { "root" } else { slug };
    let hash = sha256_hex(key.as_bytes());
    format!("{slug}-{}", &hash[..6])
}

fn child(dir: &RepoPath) -> Option<RepoPath> {
    if dir.is_root() {
        RepoPath::new(PROBE_CHILD).ok()
    } else {
        RepoPath::new(format!("{dir}/{PROBE_CHILD}")).ok()
    }
}

/// Representative paths a glob covers: its literal prefix, and a child of it if it goes deeper.
fn glob_probes(pattern: &str) -> Vec<RepoPath> {
    let pattern = pattern.trim().trim_start_matches('/');
    let prefix = literal_prefix(pattern).join("/");
    let mut out = Vec::new();
    if let Ok(rp) = RepoPath::new(&prefix) {
        if prefix.len() < pattern.len() {
            out.extend(child(&rp));
        }
        out.push(rp);
    }
    out
}

fn resolve_target(file: &AccessPolicyFile, target: &PolicyTarget) -> Result<Target, PolicyError> {
    match target {
        PolicyTarget::File { path } => {
            let rp = RepoPath::new(path)?;
            if rp.is_root() {
                return Err(invalid("a file target needs a non-empty path"));
            }
            let glob = escape_glob(path);
            Ok(Target {
                slug: rule_slug(path, &format!("file:{path}")),
                label: format!("file `{path}`"),
                paths: vec![glob.clone()],
                zones: vec![],
                globs: vec![glob],
                probes: vec![rp],
                target_paths: vec![path.clone()],
            })
        }
        PolicyTarget::Dir { path } => {
            let path = path.trim_end_matches('/');
            let rp = RepoPath::new(path)?;
            let globs = if rp.is_root() {
                vec!["**".to_owned()]
            } else {
                let e = escape_glob(path);
                vec![e.clone(), format!("{e}/**")]
            };
            let label = if rp.is_root() {
                "the whole repository".to_owned()
            } else {
                format!("directory `{path}/`")
            };
            Ok(Target {
                slug: rule_slug(path, &format!("dir:{path}")),
                label,
                paths: globs.clone(),
                zones: vec![],
                globs,
                probes: child(&rp).into_iter().chain([rp.clone()]).collect(),
                target_paths: if rp.is_root() {
                    vec![]
                } else {
                    vec![path.to_owned()]
                },
            })
        }
        PolicyTarget::Zone { zone } => {
            let config = file
                .zones
                .get(zone)
                .ok_or_else(|| invalid(format!("unknown zone '{zone}'")))?;
            if config.paths.is_empty() {
                return Err(invalid(format!("zone '{zone}' has no paths")));
            }
            Ok(Target {
                slug: rule_slug(zone, &format!("zone:{zone}")),
                label: format!("zone `{zone}`"),
                paths: vec![],
                zones: vec![zone.clone()],
                globs: config.paths.clone(),
                probes: config.paths.iter().flat_map(|p| glob_probes(p)).collect(),
                target_paths: config.paths.clone(),
            })
        }
    }
}

fn validate_name(what: &str, s: &str, max: usize) -> Result<(), PolicyError> {
    if s.is_empty()
        || s.len() > max
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(invalid(format!(
            "{what} must be 1-{max} characters of [A-Za-z0-9_-], got '{s}'"
        )));
    }
    Ok(())
}

fn validate_var(var: &str) -> Result<(), PolicyError> {
    let mut chars = var.chars();
    let head_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !head_ok || var.len() > 128 || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(invalid(format!(
            "secret variable name must match [A-Za-z_][A-Za-z0-9_]* (≤128 chars), got '{var}'"
        )));
    }
    Ok(())
}

/// Principal selectors that may be granted access by name: no wildcard or anonymous selectors,
/// and no agent selectors (agents are scoped through their profile).
fn validate_grantees(what: &str, selectors: &[String]) -> Result<Vec<String>, PolicyError> {
    let mut out: Vec<String> = Vec::new();
    for sel in selectors {
        if sel.is_empty() || sel.len() > 64 || !sel.chars().all(|c| c.is_ascii_graphic()) {
            return Err(invalid(format!(
                "{what}: selector must be 1-64 printable ASCII characters without spaces, got '{sel}'"
            )));
        }
        if sel == "*"
            || sel.eq_ignore_ascii_case("anonymous")
            || sel.eq_ignore_ascii_case("public")
            || sel.eq_ignore_ascii_case("authenticated")
        {
            return Err(invalid(format!(
                "{what}: '{sel}' would grant everyone; name users or groups"
            )));
        }
        if sel.starts_with("agent:") {
            return Err(invalid(format!(
                "{what}: '{sel}' is an agent; agents are granted through their profile"
            )));
        }
        if !out.contains(sel) {
            out.push(sel.clone());
        }
    }
    Ok(out)
}

fn reason_or(reason: &Option<String>, default: String) -> Result<String, PolicyError> {
    match reason.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => {
            if r.len() > MAX_REASON_LEN || r.contains(char::is_control) {
                return Err(invalid(format!(
                    "reason must be one line of at most {MAX_REASON_LEN} bytes"
                )));
            }
            Ok(r.to_owned())
        }
        _ => Ok(default),
    }
}

// ---- toml_edit helpers -----------------------------------------------------------------------

/// The `[[key]]` array of tables, created if absent (an inline `key = [...]` is converted).
fn aot<'a>(doc: &'a mut DocumentMut, key: &str) -> Result<&'a mut ArrayOfTables, PolicyError> {
    let item = doc
        .as_table_mut()
        .entry(key)
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
    if !item.is_array_of_tables() {
        let taken = std::mem::take(item);
        *item = Item::ArrayOfTables(
            taken
                .into_array_of_tables()
                .map_err(|_| invalid(format!("`{key}` must be an array of tables")))?,
        );
    }
    item.as_array_of_tables_mut()
        .ok_or_else(|| invalid(format!("`{key}` must be an array of tables")))
}

fn str_array<S: AsRef<str>>(items: &[S]) -> Array {
    items.iter().map(AsRef::as_ref).collect()
}

fn list<'a>(table: &'a mut Table, key: &str) -> Result<&'a mut Array, PolicyError> {
    table
        .entry(key)
        .or_insert(value(Array::new()))
        .as_array_mut()
        .ok_or_else(|| invalid(format!("`{key}` must be an array of strings")))
}

fn strings(table: &Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(Item::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique(arr: &mut Array, s: &str) {
    if !arr.iter().any(|v| v.as_str() == Some(s)) {
        arr.push(s);
    }
}

fn remove_all(arr: &mut Array, s: &str) -> bool {
    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(s));
    let removed = arr.len() != before;
    if removed {
        arr.fmt();
    }
    removed
}

struct NewRule<'a> {
    id: String,
    effect: RuleEffect,
    principals: Vec<String>,
    except_principals: Vec<String>,
    paths: &'a [String],
    zones: &'a [String],
    capabilities: &'static [&'static str],
    reason: String,
}

fn non_empty<S: AsRef<str>>(items: &[S]) -> Option<Item> {
    (!items.is_empty()).then(|| value(str_array(items)))
}

/// Insert the rule, or update the managed keys of the rule with the same id in place.
fn upsert_rule(doc: &mut DocumentMut, rule: &NewRule) -> Result<(), PolicyError> {
    let effect = match rule.effect {
        RuleEffect::Allow => "allow",
        RuleEffect::Deny => "deny",
    };
    let fields = [
        ("id", Some(value(rule.id.as_str()))),
        ("effect", Some(value(effect))),
        ("principals", Some(value(str_array(&rule.principals)))),
        ("except_principals", non_empty(&rule.except_principals)),
        ("paths", non_empty(rule.paths)),
        ("zones", non_empty(rule.zones)),
        ("refs", Some(value(str_array(&["*"])))),
        ("capabilities", Some(value(str_array(rule.capabilities)))),
        ("reason", Some(value(rule.reason.as_str()))),
    ];
    let rules = aot(doc, "rules")?;
    let idx = rules
        .iter()
        .position(|t| t.get("id").and_then(Item::as_str) == Some(rule.id.as_str()));
    match idx.and_then(|i| rules.get_mut(i)) {
        Some(table) => {
            for (key, item) in fields {
                match item {
                    Some(item) => {
                        table.insert(key, item);
                    }
                    None => {
                        table.remove(key);
                    }
                }
            }
        }
        None => {
            let mut table = Table::new();
            for (key, item) in fields {
                if let Some(item) = item {
                    table.insert(key, item);
                }
            }
            rules.push(table);
        }
    }
    Ok(())
}

fn remove_rules(doc: &mut DocumentMut, mut drop: impl FnMut(&str) -> bool) {
    if let Some(rules) = doc.get_mut("rules").and_then(Item::as_array_of_tables_mut) {
        rules.retain(|t| !t.get("id").and_then(Item::as_str).is_some_and(&mut drop));
    }
}

/// The `[[agent_profiles]]` table named `name`, created if absent.
fn profile<'a>(doc: &'a mut DocumentMut, name: &str) -> Result<&'a mut Table, PolicyError> {
    let profiles = aot(doc, "agent_profiles")?;
    let found = profiles
        .iter()
        .position(|t| t.get("name").and_then(Item::as_str) == Some(name));
    let idx = match found {
        Some(idx) => idx,
        None => {
            let mut table = Table::new();
            table.insert("name", value(name));
            profiles.push(table);
            profiles.len() - 1
        }
    };
    profiles
        .get_mut(idx)
        .ok_or_else(|| invalid("agent profile vanished"))
}

// ---- overlap checks (warnings only) ----------------------------------------------------------

fn globs_hit<'a>(globs: impl IntoIterator<Item = &'a str>, probes: &[RepoPath]) -> bool {
    globs
        .into_iter()
        .filter_map(|g| CompiledGlob::new(g).ok())
        .any(|g| probes.iter().any(|p| g.is_match(p)))
}

/// Whether `rule` targets any probe. shortcut: zone `exclude` is ignored, so this may over-warn;
/// fine for warnings, never used to decide access.
fn rule_hits(file: &AccessPolicyFile, rule: &PolicyRule, probes: &[RepoPath]) -> bool {
    let zone_paths = rule
        .zones
        .iter()
        .filter_map(|z| file.zones.get(z))
        .flat_map(|z| z.paths.iter());
    globs_hit(
        rule.paths.iter().chain(zone_paths).map(String::as_str),
        probes,
    )
}

fn covers_cap(rule: &PolicyRule, caps: &[&str]) -> bool {
    rule.capabilities
        .iter()
        .any(|c| c == "*" || caps.contains(&c.as_str()))
}

/// Pre-existing Repo deny rules on agents (`agent:*` or `agent:<profile>`) that hit the probes.
fn agent_denies<'a>(
    file: &'a AccessPolicyFile,
    profile: &str,
    probes: &'a [RepoPath],
    caps: &'a [&'a str],
    managed: impl Fn(&str) -> bool + 'a,
) -> impl Iterator<Item = &'a str> + 'a {
    let own = format!("agent:{profile}");
    file.rules
        .iter()
        .filter(move |r| {
            r.effect == RuleEffect::Deny
                && !managed(&r.id)
                && r.principals.iter().any(|p| p == "agent:*" || *p == own)
                && covers_cap(r, caps)
                && rule_hits(file, r, probes)
        })
        .map(|r| r.id.as_str())
}

fn has_cap(arr: &Array, cap: &str) -> bool {
    arr.iter()
        .any(|v| v.as_str() == Some(cap) || v.as_str() == Some("*"))
}

/// Apply `intent` to `base_toml`, preserving its comments and formatting, and return the proposed
/// policy text. The result always parses and compiles on its own.
pub fn apply_policy_intent(
    base_toml: &str,
    intent: &PolicyIntent,
) -> Result<PolicyMutationResult, PolicyError> {
    let empty = base_toml.trim().is_empty();
    let base = if empty {
        AccessPolicyFile::default()
    } else {
        parse_policy_toml(base_toml)?
    };
    let mut doc: DocumentMut = if empty {
        let mut doc = DocumentMut::new();
        doc["version"] = value(1_i64);
        doc
    } else {
        base_toml
            .parse()
            .map_err(|e: toml_edit::TomlError| invalid(e.to_string()))?
    };
    let mut warnings = Vec::new();
    let mut secret_probes = Vec::new();

    let (rule_id, summary, target_paths) = match intent {
        PolicyIntent::ShieldFromAnonymous { target, reason } => {
            let t = resolve_target(&base, target)?;
            let id = format!("shield-anon-{}", t.slug);
            shield(&mut doc, &t, &id, "anonymous", reason, "anonymous visitors")?;
            (
                id,
                format!("Hide {} from anonymous visitors", t.label),
                t.target_paths,
            )
        }
        PolicyIntent::ShieldFromAllAgents { target, reason } => {
            let t = resolve_target(&base, target)?;
            let id = format!("shield-agents-{}", t.slug);
            shield(&mut doc, &t, &id, "agent:*", reason, "every AI agent")?;
            (
                id,
                format!("Hide {} from every AI agent", t.label),
                t.target_paths,
            )
        }
        PolicyIntent::ShieldFromAgent {
            target,
            agent_profile,
            reason,
        } => {
            validate_name("agent_profile", agent_profile, 64)?;
            let t = resolve_target(&base, target)?;
            let id = format!("shield-agent-{agent_profile}-{}", t.slug);
            let who = format!("agent profile `{agent_profile}`");
            shield(
                &mut doc,
                &t,
                &id,
                &format!("agent:{agent_profile}"),
                reason,
                &who,
            )?;
            (id, format!("Hide {} from {who}", t.label), t.target_paths)
        }
        PolicyIntent::AllowAgentAccess {
            target,
            agent_profile,
            write,
            reason,
        } => {
            validate_name("agent_profile", agent_profile, 64)?;
            let t = resolve_target(&base, target)?;
            allow_agent_access(
                &mut doc,
                &base,
                &t,
                agent_profile,
                *write,
                reason,
                &mut warnings,
            )?
        }
        PolicyIntent::RestrictToPrincipals {
            target,
            principals,
            write,
            reason,
        } => {
            let principals = validate_grantees("principals", principals)?;
            if principals.is_empty() {
                return Err(invalid("restrict needs at least one principal"));
            }
            let t = resolve_target(&base, target)?;
            let deny_id = format!("restrict-deny-{}", t.slug);
            let allow_id = format!("restrict-allow-{}", t.slug);
            let ro_id = format!("restrict-readonly-{}", t.slug);
            let who = principals.join(", ");
            let reason = reason_or(
                reason,
                format!("Only owners and {who} may access {}", t.label),
            )?;
            let mut except = vec![OWNERS.to_owned()];
            except.extend(principals.iter().filter(|p| *p != OWNERS).cloned());
            upsert_rule(
                &mut doc,
                &NewRule {
                    id: deny_id.clone(),
                    effect: RuleEffect::Deny,
                    principals: vec!["*".to_owned()],
                    except_principals: except,
                    paths: &t.paths,
                    zones: &t.zones,
                    capabilities: ALL_CAPS,
                    reason: reason.clone(),
                },
            )?;
            upsert_rule(
                &mut doc,
                &NewRule {
                    id: allow_id,
                    effect: RuleEffect::Allow,
                    principals: principals.clone(),
                    except_principals: vec![],
                    paths: &t.paths,
                    zones: &t.zones,
                    capabilities: if *write { RW_CAPS } else { READ_CAPS },
                    reason,
                },
            )?;
            if *write {
                remove_rules(&mut doc, |id| id == ro_id);
            } else {
                upsert_rule(
                    &mut doc,
                    &NewRule {
                        id: ro_id,
                        effect: RuleEffect::Deny,
                        principals: principals.clone(),
                        except_principals: vec![OWNERS.to_owned()],
                        paths: &t.paths,
                        zones: &t.zones,
                        capabilities: &["write"],
                        reason: format!("Read-only restriction on {} for {who}", t.label),
                    },
                )?;
            }
            for r in &base.rules {
                if r.id != deny_id
                    && r.effect == RuleEffect::Deny
                    && r.principals.iter().any(|p| p == "*")
                    && r.except_principals.is_empty()
                    && rule_hits(&base, r, &t.probes)
                {
                    warnings.push(format!(
                        "rule '{}' still denies everyone on {}; {who} stay locked out until it is removed or narrowed",
                        r.id, t.label
                    ));
                }
            }
            let access = if *write { "read and write" } else { "read" };
            (
                deny_id,
                format!("Restrict {} to owners and {who} ({access})", t.label),
                t.target_paths,
            )
        }
        PolicyIntent::AllowAgentSecretUse {
            var_name,
            zone,
            agent_profile,
            human_principals,
            reason,
        } => {
            let (logical, slug) = secret_target(var_name, zone.as_deref())?;
            validate_name("agent_profile", agent_profile, 64)?;
            let humans = validate_grantees("human_principals", human_principals)?;
            let probes = [RepoPath::new(&logical)?];
            let shield_id = format!("shield-secret-{agent_profile}-{slug}");

            let prof = profile(&mut doc, agent_profile)?;
            push_unique(list(prof, "allow_secret_use")?, var_name);
            if globs_hit(
                strings(prof, "deny_paths").iter().map(String::as_str),
                &probes,
            ) {
                warnings.push(format!(
                    "agent profile `{agent_profile}` deny_paths cover {logical}; the agent still cannot use {var_name}"
                ));
            }
            remove_rules(&mut doc, |id| id == shield_id);
            for id in agent_denies(&base, agent_profile, &probes, &["use"], |id| {
                id == shield_id
            }) {
                warnings.push(format!(
                    "rule '{id}' denies agents `use` on {logical}; the agent still cannot use {var_name} until it is removed"
                ));
            }

            let rule_id = if humans.is_empty() {
                warnings.push(format!(
                    "the agent acts as permissions(human) ∩ permissions(agent): the delegating human also needs `use` on {logical}"
                ));
                format!("agent-profile:{agent_profile}")
            } else {
                let id = format!("allow-secret-use-{slug}");
                upsert_rule(
                    &mut doc,
                    &NewRule {
                        id: id.clone(),
                        effect: RuleEffect::Allow,
                        principals: humans,
                        except_principals: vec![],
                        paths: std::slice::from_ref(&logical),
                        zones: &[],
                        capabilities: &["use"],
                        reason: reason_or(
                            reason,
                            format!("May use {var_name} through the egress proxy (never read it)"),
                        )?,
                    },
                )?;
                id
            };
            secret_probes.push(SecretProbe {
                var_name: var_name.clone(),
                zone: zone.clone(),
            });
            (
                rule_id,
                format!("Let agent `{agent_profile}` use {var_name} without reading it"),
                vec![logical],
            )
        }
        PolicyIntent::RevokeAgentSecretUse {
            var_name,
            zone,
            agent_profile,
            reason,
        } => {
            let (logical, slug) = secret_target(var_name, zone.as_deref())?;
            validate_name("agent_profile", agent_profile, 64)?;
            if !base.agent_profiles.iter().any(|p| p.name == *agent_profile) {
                return Err(invalid(format!("unknown agent profile '{agent_profile}'")));
            }
            let prof = profile(&mut doc, agent_profile)?;
            let (removed, wildcard) = match prof
                .get_mut("allow_secret_use")
                .and_then(Item::as_array_mut)
            {
                Some(arr) => (remove_all(arr, var_name), has_cap(arr, "*")),
                None => (false, false),
            };
            let rule_id = if wildcard {
                let id = format!("shield-secret-{agent_profile}-{slug}");
                upsert_rule(
                    &mut doc,
                    &NewRule {
                        id: id.clone(),
                        effect: RuleEffect::Deny,
                        principals: vec![format!("agent:{agent_profile}")],
                        except_principals: vec![],
                        paths: std::slice::from_ref(&logical),
                        zones: &[],
                        capabilities: &["use"],
                        reason: reason_or(
                            reason,
                            format!("Agent `{agent_profile}` may not use {var_name}"),
                        )?,
                    },
                )?;
                warnings.push(format!(
                    "agent profile `{agent_profile}` allows every secret (\"*\"); added deny rule '{id}' for {var_name}"
                ));
                id
            } else {
                if !removed {
                    warnings.push(format!(
                        "agent profile `{agent_profile}` was not allowed to use {var_name}; nothing to revoke"
                    ));
                }
                format!("agent-profile:{agent_profile}")
            };
            secret_probes.push(SecretProbe {
                var_name: var_name.clone(),
                zone: zone.clone(),
            });
            (
                rule_id,
                format!("Stop agent `{agent_profile}` from using {var_name}"),
                vec![logical],
            )
        }
    };

    let proposed_toml = doc.to_string();
    let parsed = parse_policy_toml(&proposed_toml)?;
    CompiledPolicy::compile(None, &parsed)?;
    Ok(PolicyMutationResult {
        proposed_toml,
        rule_id,
        summary,
        warnings,
        target_paths,
        secret_probes,
    })
}

/// Logical secret path (`secrets/<zone>/<VAR>` or `secrets/<VAR>`) and its rule slug.
fn secret_target(var_name: &str, zone: Option<&str>) -> Result<(String, String), PolicyError> {
    validate_var(var_name)?;
    let logical = match zone {
        Some(z) => {
            validate_name("zone", z, 64)?;
            format!("secrets/{z}/{var_name}")
        }
        None => format!("secrets/{var_name}"),
    };
    let text = logical.trim_start_matches("secrets/");
    let slug = rule_slug(text, &format!("secret:{logical}"));
    Ok((logical, slug))
}

fn shield(
    doc: &mut DocumentMut,
    t: &Target,
    id: &str,
    selector: &str,
    reason: &Option<String>,
    who: &str,
) -> Result<(), PolicyError> {
    upsert_rule(
        doc,
        &NewRule {
            id: id.to_owned(),
            effect: RuleEffect::Deny,
            principals: vec![selector.to_owned()],
            except_principals: vec![],
            paths: &t.paths,
            zones: &t.zones,
            capabilities: ALL_CAPS,
            reason: reason_or(reason, format!("{} is hidden from {who}", t.label))?,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn allow_agent_access(
    doc: &mut DocumentMut,
    base: &AccessPolicyFile,
    t: &Target,
    agent: &str,
    write: bool,
    reason: &Option<String>,
    warnings: &mut Vec<String>,
) -> Result<(String, String, Vec<String>), PolicyError> {
    let ro_prefix = format!("agent-readonly-{agent}-");
    let ro_id = format!("{ro_prefix}{}", t.slug);
    let shield_id = format!("shield-agent-{agent}-{}", t.slug);
    let selector = format!("agent:{agent}");

    let prof = profile(doc, agent)?;
    let previous_allow = strings(prof, "allow_paths");
    let allow = list(prof, "allow_paths")?;
    for g in &t.globs {
        push_unique(allow, g);
    }
    if let Some(deny) = prof.get_mut("deny_paths").and_then(Item::as_array_mut) {
        for g in &t.globs {
            remove_all(deny, g);
        }
    }
    if globs_hit(
        strings(prof, "deny_paths").iter().map(String::as_str),
        &t.probes,
    ) {
        warnings.push(format!(
            "agent profile `{agent}` still has deny_paths covering {}; those paths stay hidden from it",
            t.label
        ));
    }
    let caps = list(prof, "capabilities")?;
    let had_write = has_cap(caps, "write");
    if !has_cap(caps, "*") {
        for c in READ_CAPS {
            push_unique(caps, c);
        }
        if write {
            push_unique(caps, "write");
        }
    }
    remove_rules(doc, |id| id == shield_id);

    let rule_id = if write {
        // Profile capabilities apply to every allow_path: keep paths it could only read read-only.
        let preserved: Vec<String> = previous_allow
            .into_iter()
            .filter(|g| !t.globs.contains(g))
            .collect();
        if !had_write && !preserved.is_empty() {
            let id = format!(
                "{ro_prefix}{}",
                rule_slug("preserved", &format!("preserve:{agent}"))
            );
            upsert_rule(
                doc,
                &NewRule {
                    id: id.clone(),
                    effect: RuleEffect::Deny,
                    principals: vec![selector.clone()],
                    except_principals: vec![],
                    paths: &preserved,
                    zones: &[],
                    capabilities: &["write"],
                    reason: format!("Agent `{agent}` keeps read-only access here"),
                },
            )?;
            warnings.push(format!(
                "agent profile `{agent}` was read-only; added '{id}' so its other paths stay read-only"
            ));
        }
        remove_rules(doc, |id| id == ro_id);
        // Strip this target from other read-only rules of the profile; drop rules left empty.
        if let Some(rules) = doc.get_mut("rules").and_then(Item::as_array_of_tables_mut) {
            for rule in rules.iter_mut().filter(|r| {
                r.get("id")
                    .and_then(Item::as_str)
                    .is_some_and(|id| id.starts_with(&ro_prefix))
            }) {
                if let Some(paths) = rule.get_mut("paths").and_then(Item::as_array_mut) {
                    for g in &t.globs {
                        remove_all(paths, g);
                    }
                }
            }
            rules.retain(|r| {
                let managed = r
                    .get("id")
                    .and_then(Item::as_str)
                    .is_some_and(|id| id.starts_with(&ro_prefix));
                !managed || !strings(r, "paths").is_empty() || !strings(r, "zones").is_empty()
            });
        }
        let protected_hit = AGENT_PROTECTED_WRITE_PATHS.iter().any(|p| {
            globs_hit(t.globs.iter().map(String::as_str), &glob_probes(p))
                || globs_hit([*p], &t.probes)
        });
        if protected_hit {
            warnings.push(format!(
                "{} overlaps protected files ({}); Repo-layer agent profiles can never write those",
                t.label,
                AGENT_PROTECTED_WRITE_PATHS.join(", ")
            ));
        }
        format!("agent-profile:{agent}")
    } else {
        upsert_rule(
            doc,
            &NewRule {
                id: ro_id.clone(),
                effect: RuleEffect::Deny,
                principals: vec![selector],
                except_principals: vec![],
                paths: &t.paths,
                zones: &t.zones,
                capabilities: &["write"],
                reason: reason_or(
                    reason,
                    format!("Agent `{agent}` may read but not write {}", t.label),
                )?,
            },
        )?;
        ro_id
    };

    if write {
        let proposed = parse_policy_toml(&doc.to_string())?;
        for r in &proposed.rules {
            if r.id.starts_with(&ro_prefix) && rule_hits(&proposed, r, &t.probes) {
                warnings.push(format!(
                    "rule '{}' still keeps {} read-only for agent `{agent}`",
                    r.id, t.label
                ));
            }
        }
    }
    for id in agent_denies(base, agent, &t.probes, ALL_CAPS, |id| {
        id == shield_id || id.starts_with(&ro_prefix)
    }) {
        warnings.push(format!(
            "rule '{id}' denies agents on {}; agent `{agent}` stays blocked there until it is removed",
            t.label
        ));
    }
    if !t.zones.is_empty() {
        warnings.push(format!(
            "agent allow_paths take the zone's paths; its `exclude` list is not carried into the profile for {}",
            t.label
        ));
    }
    let access = if write { "read and write" } else { "read" };
    Ok((
        rule_id,
        format!("Let agent `{agent}` {access} {}", t.label),
        t.target_paths.clone(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use premier_core::{Capability, DelegatedIdentity, Principal};

    use super::*;
    use crate::compute_secret_use_deltas;

    const BASE: &str = r#"# Team policy — keep this comment!
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.billing]
paths = ["billing/**"]  # money lives here

# Owners always win.
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/web/**"]
capabilities = ["traverse", "list", "read"]
"#;

    fn apply(base: &str, intent: PolicyIntent) -> PolicyMutationResult {
        apply_policy_intent(base, &intent).unwrap()
    }

    fn compiled(text: &str) -> CompiledPolicy {
        CompiledPolicy::compile(None, &parse_policy_toml(text).unwrap()).unwrap()
    }

    fn caps(p: &CompiledPolicy, id: &DelegatedIdentity, path: &str) -> Capability {
        p.explain(id, &RepoPath::new(path).unwrap(), "main")
            .effective
    }

    fn human(name: &str, groups: &[&str]) -> DelegatedIdentity {
        DelegatedIdentity::human_only(
            Principal::parse(name).unwrap(),
            groups.iter().map(|g| (*g).to_owned()).collect(),
        )
    }

    fn agent(name: &str, groups: &[&str], profile: &str) -> DelegatedIdentity {
        DelegatedIdentity::delegated(
            Principal::parse(name).unwrap(),
            groups.iter().map(|g| (*g).to_owned()).collect(),
            profile,
            "t",
        )
    }

    fn dir(path: &str) -> PolicyTarget {
        PolicyTarget::Dir {
            path: path.to_owned(),
        }
    }

    #[test]
    fn intents_deserialize_from_the_wire_contract() {
        let intent: PolicyIntent = serde_json::from_value(serde_json::json!({
            "kind": "restrict_to_principals",
            "target": { "kind": "zone", "zone": "billing" },
            "principals": ["@alice"]
        }))
        .unwrap();
        assert_eq!(
            intent,
            PolicyIntent::RestrictToPrincipals {
                target: PolicyTarget::Zone {
                    zone: "billing".to_owned()
                },
                principals: vec!["@alice".to_owned()],
                write: false,
                reason: None,
            }
        );
    }

    #[test]
    fn shield_from_anonymous_preserves_comments_and_is_idempotent() {
        let out = apply(
            BASE,
            PolicyIntent::ShieldFromAnonymous {
                target: dir("docs/private"),
                reason: None,
            },
        );
        assert!(out.rule_id.starts_with("shield-anon-docs-private-"));
        for kept in [
            "# Team policy — keep this comment!",
            "# money lives here",
            "# Owners always win.",
        ] {
            assert!(out.proposed_toml.contains(kept), "{}", out.proposed_toml);
        }
        for line in BASE.lines() {
            assert!(out.proposed_toml.contains(line), "lost {line:?}");
        }
        assert_eq!(out.target_paths, vec!["docs/private"]);

        let p = compiled(&out.proposed_toml);
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        assert!(caps(&p, &anon, "docs/private").is_empty());
        assert!(caps(&p, &anon, "docs/private/a.md").is_empty());
        assert!(caps(&p, &anon, "docs/public.md").contains(Capability::READ));
        assert!(caps(&p, &human("@bob", &[]), "docs/private/a.md").contains(Capability::READ));

        let again = apply(
            &out.proposed_toml,
            PolicyIntent::ShieldFromAnonymous {
                target: dir("docs/private"),
                reason: None,
            },
        );
        assert_eq!(again.proposed_toml, out.proposed_toml);
    }

    #[test]
    fn empty_base_starts_a_clean_policy() {
        let out = apply(
            "  \n",
            PolicyIntent::ShieldFromAllAgents {
                target: dir(""),
                reason: None,
            },
        );
        assert!(out.proposed_toml.starts_with("version = 1\n"));
        assert!(out.rule_id.starts_with("shield-agents-root-"));
        assert!(out.target_paths.is_empty());
        let p = compiled(&out.proposed_toml);
        assert!(caps(&p, &agent("@a", &[], "x"), "src/a.rs").is_empty());
    }

    #[test]
    fn rule_ids_do_not_collide_and_globs_are_escaped() {
        let id = |path: &str| {
            apply(
                BASE,
                PolicyIntent::ShieldFromAnonymous {
                    target: PolicyTarget::File {
                        path: path.to_owned(),
                    },
                    reason: None,
                },
            )
            .rule_id
        };
        assert_ne!(id("a/b"), id("a-b"));

        let out = apply(
            BASE,
            PolicyIntent::ShieldFromAnonymous {
                target: PolicyTarget::File {
                    path: "docs/[draft]*.md".to_owned(),
                },
                reason: None,
            },
        );
        let p = compiled(&out.proposed_toml);
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        assert!(caps(&p, &anon, "docs/[draft]*.md").is_empty());
        assert!(caps(&p, &anon, "docs/dx.md").contains(Capability::READ));
    }

    #[test]
    fn hostile_inputs_are_rejected_or_escaped() {
        let bad = [
            PolicyIntent::ShieldFromAgent {
                target: dir("docs"),
                agent_profile: "x\"]\n[[rules]]".to_owned(),
                reason: None,
            },
            PolicyIntent::ShieldFromAnonymous {
                target: dir("../etc"),
                reason: None,
            },
            PolicyIntent::ShieldFromAnonymous {
                target: PolicyTarget::File {
                    path: String::new(),
                },
                reason: None,
            },
            PolicyIntent::ShieldFromAnonymous {
                target: PolicyTarget::Zone {
                    zone: "nope".to_owned(),
                },
                reason: None,
            },
            PolicyIntent::ShieldFromAnonymous {
                target: dir("docs"),
                reason: Some("line\n[[rules]]".to_owned()),
            },
            PolicyIntent::AllowAgentSecretUse {
                var_name: "1BAD".to_owned(),
                zone: None,
                agent_profile: "ui-agent".to_owned(),
                human_principals: vec![],
                reason: None,
            },
            PolicyIntent::AllowAgentSecretUse {
                var_name: "K".to_owned(),
                zone: Some("../x".to_owned()),
                agent_profile: "ui-agent".to_owned(),
                human_principals: vec![],
                reason: None,
            },
            PolicyIntent::AllowAgentSecretUse {
                var_name: "K".to_owned(),
                zone: None,
                agent_profile: "ui-agent".to_owned(),
                human_principals: vec!["*".to_owned()],
                reason: None,
            },
            PolicyIntent::RevokeAgentSecretUse {
                var_name: "K".to_owned(),
                zone: None,
                agent_profile: "ghost".to_owned(),
                reason: None,
            },
        ];
        for intent in bad {
            assert!(
                matches!(
                    apply_policy_intent(BASE, &intent),
                    Err(PolicyError::InvalidIntent(_) | PolicyError::Core(_))
                ),
                "{intent:?}"
            );
        }
        for principals in [
            vec![],
            vec!["*"],
            vec!["Anonymous"],
            vec!["public"],
            vec!["a b"],
        ] {
            let intent = PolicyIntent::RestrictToPrincipals {
                target: dir("docs"),
                principals: principals.iter().map(|s| (*s).to_owned()).collect(),
                write: false,
                reason: None,
            };
            assert!(
                apply_policy_intent(BASE, &intent).is_err(),
                "{principals:?}"
            );
        }

        // Quotes and TOML syntax in a reason stay inside one string.
        let out = apply(
            BASE,
            PolicyIntent::ShieldFromAnonymous {
                target: dir("docs"),
                reason: Some(r#"x" ] [[rules]] id = "pwn"#.to_owned()),
            },
        );
        let parsed = parse_policy_toml(&out.proposed_toml).unwrap();
        assert_eq!(parsed.rules.len(), 2);
        assert!(!parsed.rules.iter().any(|r| r.id == "pwn"));
    }

    #[test]
    fn restrict_keeps_owners_and_beats_permissive_defaults() {
        let out = apply(
            BASE,
            PolicyIntent::RestrictToPrincipals {
                target: PolicyTarget::Zone {
                    zone: "billing".to_owned(),
                },
                principals: vec!["@alice".to_owned(), "group:finance".to_owned()],
                write: false,
                reason: None,
            },
        );
        assert!(out.rule_id.starts_with("restrict-deny-billing-"));
        assert_eq!(out.target_paths, vec!["billing/**"]);
        let p = compiled(&out.proposed_toml);
        let path = "billing/ledger.rs";
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        assert!(caps(&p, &anon, path).is_empty());
        assert!(caps(&p, &human("@bob", &[]), path).is_empty());
        let alice = caps(&p, &human("@alice", &[]), path);
        assert!(alice.contains(Capability::READ) && !alice.contains(Capability::WRITE));
        assert!(caps(&p, &human("@fay", &["finance"]), path).contains(Capability::READ));
        assert!(
            caps(&p, &human("@olga", &["owners"]), path)
                .contains(Capability::READ | Capability::WRITE)
        );
        // Outside the zone nothing changed.
        assert!(caps(&p, &human("@bob", &[]), "src/a.rs").contains(Capability::READ));

        // Permissive defaults with `write` are stripped when `write: false`, while owners keep write.
        let writer_defaults = BASE.replace(
            "authenticated = [\"traverse\", \"list\", \"read\"]",
            "authenticated = [\"traverse\", \"list\", \"read\", \"write\"]",
        );
        let ro_from_writer = apply(
            &writer_defaults,
            PolicyIntent::RestrictToPrincipals {
                target: PolicyTarget::Zone {
                    zone: "billing".to_owned(),
                },
                principals: vec!["@alice".to_owned()],
                write: false,
                reason: None,
            },
        );
        let p_ro = compiled(&ro_from_writer.proposed_toml);
        let alice_ro = caps(&p_ro, &human("@alice", &[]), path);
        assert!(alice_ro.contains(Capability::READ) && !alice_ro.contains(Capability::WRITE));
        assert!(caps(&p_ro, &human("@olga", &["owners"]), path).contains(Capability::WRITE));

        let rw = apply(
            &out.proposed_toml,
            PolicyIntent::RestrictToPrincipals {
                target: PolicyTarget::Zone {
                    zone: "billing".to_owned(),
                },
                principals: vec!["@alice".to_owned()],
                write: true,
                reason: None,
            },
        );
        let p = compiled(&rw.proposed_toml);
        assert!(caps(&p, &human("@alice", &[]), path).contains(Capability::WRITE));
        // Re-application updated the rules in place: @finance is no longer excepted.
        assert!(caps(&p, &human("@fay", &["finance"]), path).is_empty());
        assert_eq!(parse_policy_toml(&rw.proposed_toml).unwrap().rules.len(), 3);
    }

    #[test]
    fn wildcard_and_authenticated_grantees_are_rejected() {
        for sel in [
            "*",
            "anonymous",
            "public",
            "authenticated",
            "Authenticated",
            "agent:*",
        ] {
            assert!(
                apply_policy_intent(
                    BASE,
                    &PolicyIntent::RestrictToPrincipals {
                        target: dir("docs"),
                        principals: vec![sel.to_owned()],
                        write: false,
                        reason: None,
                    },
                )
                .is_err(),
                "restrict should reject {sel}"
            );
            assert!(
                apply_policy_intent(
                    BASE,
                    &PolicyIntent::AllowAgentSecretUse {
                        var_name: "STRIPE_API_KEY".to_owned(),
                        zone: None,
                        agent_profile: "ui-agent".to_owned(),
                        human_principals: vec![sel.to_owned()],
                        reason: None,
                    },
                )
                .is_err(),
                "secret use should reject {sel}"
            );
        }
    }

    #[test]
    fn restrict_warns_about_a_blanket_deny_it_cannot_lift() {
        let base = format!(
            "{BASE}\n[[rules]]\nid = \"nobody-billing\"\neffect = \"deny\"\nprincipals = [\"*\"]\n\
             zones = [\"billing\"]\ncapabilities = [\"*\"]\n"
        );
        let out = apply(
            &base,
            PolicyIntent::RestrictToPrincipals {
                target: dir("billing"),
                principals: vec!["@alice".to_owned()],
                write: false,
                reason: None,
            },
        );
        assert!(
            out.warnings.iter().any(|w| w.contains("nobody-billing")),
            "{:?}",
            out.warnings
        );
        assert!(out.proposed_toml.contains("id = \"nobody-billing\""));
    }

    #[test]
    fn agent_access_read_only_and_read_write_keep_sibling_paths() {
        let ro = apply(
            BASE,
            PolicyIntent::AllowAgentAccess {
                target: dir("docs"),
                agent_profile: "ui-agent".to_owned(),
                write: false,
                reason: None,
            },
        );
        assert!(ro.rule_id.starts_with("agent-readonly-ui-agent-docs-"));
        let p = compiled(&ro.proposed_toml);
        let a = agent("@olga", &["owners"], "ui-agent");
        let docs = caps(&p, &a, "docs/a.md");
        assert!(docs.contains(Capability::READ) && !docs.contains(Capability::WRITE));
        assert!(caps(&p, &a, "docs").contains(Capability::READ));

        // Grant write on docs: apps/web stays read-only (it never had write), docs becomes writable.
        let rw = apply(
            &ro.proposed_toml,
            PolicyIntent::AllowAgentAccess {
                target: dir("docs"),
                agent_profile: "ui-agent".to_owned(),
                write: true,
                reason: None,
            },
        );
        let p = compiled(&rw.proposed_toml);
        assert!(caps(&p, &a, "docs/a.md").contains(Capability::WRITE));
        let web = caps(&p, &a, "apps/web/x.ts");
        assert!(web.contains(Capability::READ) && !web.contains(Capability::WRITE));
        assert!(!rw.proposed_toml.contains(&ro.rule_id));
        // The agent still never exceeds its human.
        let bob_agent = agent("@bob", &[], "ui-agent");
        assert!(!caps(&p, &bob_agent, "docs/a.md").contains(Capability::WRITE));

        // Write on a protected file warns, and is still fenced.
        let prot = apply(
            BASE,
            PolicyIntent::AllowAgentAccess {
                target: PolicyTarget::File {
                    path: "AGENTS.md".to_owned(),
                },
                agent_profile: "ui-agent".to_owned(),
                write: true,
                reason: None,
            },
        );
        assert!(
            prot.warnings.iter().any(|w| w.contains("protected")),
            "{:?}",
            prot.warnings
        );
        let p = compiled(&prot.proposed_toml);
        assert!(!caps(&p, &a, "AGENTS.md").contains(Capability::WRITE));
    }

    #[test]
    fn agent_access_lifts_a_profile_shield_and_warns_on_blanket_agent_denies() {
        let shielded = apply(
            BASE,
            PolicyIntent::ShieldFromAgent {
                target: dir("apps/web"),
                agent_profile: "ui-agent".to_owned(),
                reason: None,
            },
        );
        let a = agent("@olga", &["owners"], "ui-agent");
        assert!(caps(&compiled(&shielded.proposed_toml), &a, "apps/web/x.ts").is_empty());
        let all = apply(
            &shielded.proposed_toml,
            PolicyIntent::ShieldFromAllAgents {
                target: dir("apps/web"),
                reason: None,
            },
        );
        let out = apply(
            &all.proposed_toml,
            PolicyIntent::AllowAgentAccess {
                target: dir("apps/web"),
                agent_profile: "ui-agent".to_owned(),
                write: false,
                reason: None,
            },
        );
        assert!(!out.proposed_toml.contains(&shielded.rule_id));
        assert!(
            out.warnings.iter().any(|w| w.contains(&all.rule_id)),
            "{:?}",
            out.warnings
        );
        // The all-agents shield still holds.
        assert!(caps(&compiled(&out.proposed_toml), &a, "apps/web/x.ts").is_empty());
    }

    #[test]
    fn agent_secret_use_grants_use_never_read_and_revokes() {
        let out = apply(
            BASE,
            PolicyIntent::AllowAgentSecretUse {
                var_name: "STRIPE_API_KEY".to_owned(),
                zone: Some("billing".to_owned()),
                agent_profile: "ui-agent".to_owned(),
                human_principals: vec!["group:billing".to_owned()],
                reason: None,
            },
        );
        assert!(
            out.rule_id
                .starts_with("allow-secret-use-billing-stripe-api-key-")
        );
        assert_eq!(out.target_paths, vec!["secrets/billing/STRIPE_API_KEY"]);
        assert_eq!(
            out.secret_probes,
            vec![SecretProbe {
                var_name: "STRIPE_API_KEY".to_owned(),
                zone: Some("billing".to_owned()),
            }]
        );
        let parsed = parse_policy_toml(&out.proposed_toml).unwrap();
        let rule = parsed.rules.iter().find(|r| r.id == out.rule_id).unwrap();
        assert_eq!(rule.capabilities, vec!["use"]);
        let prof = &parsed.agent_profiles[0];
        assert_eq!(prof.allow_secret_use, vec!["STRIPE_API_KEY"]);
        assert!(!prof.allow_paths.iter().any(|p| p.starts_with("secrets")));
        assert!(!prof.capabilities.contains(&"use".to_owned()));

        let base = compiled(BASE);
        let head = compiled(&out.proposed_toml);
        let a = agent("@bill", &["billing"], "ui-agent");
        let d = head.can_use_secret(&a, "STRIPE_API_KEY", Some("billing"), "main");
        assert!(d.allows(Capability::USE) && !d.allows(Capability::READ));
        // A human outside billing (or their agent) gets nothing.
        let other = agent("@bob", &[], "ui-agent");
        assert!(
            !head
                .can_use_secret(&other, "STRIPE_API_KEY", Some("billing"), "main")
                .allows(Capability::USE)
        );

        let ids = [a.clone(), other];
        let secrets = [("STRIPE_API_KEY".to_owned(), Some("billing".to_owned()))];
        let deltas = compute_secret_use_deltas(&base, &head, &ids, &secrets, "main");
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].path, "secret:STRIPE_API_KEY (@billing)");
        assert_eq!(deltas[0].granted, vec!["use"]);
        assert_eq!(deltas[0].agent_profile.as_deref(), Some("ui-agent"));

        let revoked = apply(
            &out.proposed_toml,
            PolicyIntent::RevokeAgentSecretUse {
                var_name: "STRIPE_API_KEY".to_owned(),
                zone: Some("billing".to_owned()),
                agent_profile: "ui-agent".to_owned(),
                reason: None,
            },
        );
        let after = compiled(&revoked.proposed_toml);
        assert!(
            !after
                .can_use_secret(&a, "STRIPE_API_KEY", Some("billing"), "main")
                .allows(Capability::USE)
        );
        let back = compute_secret_use_deltas(&head, &after, &ids, &secrets, "main");
        assert_eq!(back[0].revoked, vec!["use"]);
    }

    #[test]
    fn revoking_from_a_wildcard_profile_adds_an_explicit_deny() {
        let base = BASE.replace(
            "capabilities = [\"traverse\", \"list\", \"read\"]\n",
            "capabilities = [\"traverse\", \"list\", \"read\"]\nallow_secret_use = [\"*\"]\n",
        );
        let out = apply(
            &base,
            PolicyIntent::RevokeAgentSecretUse {
                var_name: "DB_URL".to_owned(),
                zone: None,
                agent_profile: "ui-agent".to_owned(),
                reason: None,
            },
        );
        assert!(out.rule_id.starts_with("shield-secret-ui-agent-db-url-"));
        assert!(!out.warnings.is_empty());
        let p = compiled(&out.proposed_toml);
        let a = agent("@olga", &["owners"], "ui-agent");
        assert!(
            !p.can_use_secret(&a, "DB_URL", None, "main")
                .allows(Capability::USE)
        );
        assert!(
            p.can_use_secret(&a, "OTHER", None, "main")
                .allows(Capability::USE)
        );
    }
}
