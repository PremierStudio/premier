//! TOML `.env.schema` contract parser and validator.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use premier_core::Environment;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::SecretError;

/// Top-level `.env.schema` TOML document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSchema {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub vars: BTreeMap<String, VarSpec>,
}

fn default_version() -> u32 {
    1
}

impl Default for EnvSchema {
    fn default() -> Self {
        Self {
            version: 1,
            repo_id: None,
            vars: BTreeMap::new(),
        }
    }
}

/// Typed value constraint for a schema variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VarType {
    #[default]
    String,
    Url,
    Int,
    Bool,
    Secret,
}

/// Sensitivity tier determining whether values can be exposed raw vs proxied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    #[default]
    Secret,
    Restricted,
}

/// Approval policy for AI-agent `USE` via the egress capability proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    Auto,
    /// Require per-capability interactive JIT approval with TTL.
    Jit,
}

/// How the egress proxy injects the real secret onto an authorized outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InjectSpec {
    /// Replace any occurrence of the placeholder token in headers/query/body.
    #[default]
    PlaceholderReplace,
    /// Set `Authorization: Bearer <secret>` (or custom header name).
    BearerHeader {
        #[serde(default = "default_auth_header")]
        header: String,
    },
    /// Set a specific HTTP header to `<prefix><secret>`.
    Header {
        header: String,
        #[serde(default)]
        prefix: String,
    },
    /// Append or replace a query parameter.
    QueryParam { param: String },
}

fn default_auth_header() -> String {
    "Authorization".to_owned()
}

/// Strict domain-bound egress capability policy declared inside `.env.schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSpec {
    /// Exact allowed destination hosts (e.g. `["api.stripe.com"]`). Wildcards forbidden for restricted secrets.
    pub hosts: Vec<String>,
    /// Allowed HTTP methods (empty = `GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Allowed URL path prefixes (e.g. `["/v1/"]`; empty = `"/"`).
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// Optional explicit upstream scheme/port override (defaults to `https` port 443; useful for local test mocks).
    #[serde(default)]
    pub upstream_base_url: Option<String>,
    #[serde(default)]
    pub inject: InjectSpec,
    #[serde(default)]
    pub rate_limit_per_min: Option<u32>,
    #[serde(default)]
    pub approval: ApprovalMode,
    /// Default TTL in seconds when `approval = "jit"`.
    #[serde(default = "default_jit_ttl_secs")]
    pub jit_ttl_secs: u64,
    /// Learned JIT bypass rules: narrow `(agent_profile, host, methods, path_prefixes)` tuples
    /// that skip the interactive knock. Each must sit strictly inside the egress envelope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auto_allow: Vec<AutoAllowRule>,
}

/// A "living policy" JIT auto-allow rule learned from repeated human approvals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoAllowRule {
    /// Exact agent profile this rule applies to; `None` only matches requests with no agent task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub host: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

fn default_jit_ttl_secs() -> u64 {
    300
}

impl EgressSpec {
    pub fn matches_host(&self, host: &str) -> bool {
        let target = host.trim().to_ascii_lowercase();
        self.hosts.iter().any(|h| h.eq_ignore_ascii_case(&target))
    }

    pub fn matches_method(&self, method: &str) -> bool {
        if self.methods.is_empty() {
            return true;
        }
        self.methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method.trim()))
    }

    pub fn matches_path(&self, path: &str) -> bool {
        self.matched_path_prefix(path).is_some()
    }

    /// The declared prefix that authorises `path` (`"/"` when none is declared), or `None`.
    ///
    /// Paths an upstream could resolve to a different resource than the one compared here are
    /// refused outright: dot-segments, encoded dots/slashes/backslashes, double-encoding.
    pub fn matched_path_prefix(&self, path: &str) -> Option<&str> {
        if !is_unambiguous_path(path) {
            return None;
        }
        if self.path_prefixes.is_empty() {
            return Some("/");
        }
        self.path_prefixes
            .iter()
            .map(String::as_str)
            .find(|prefix| path_matches_prefix(path, prefix))
    }

    /// Whether a learned `auto_allow` rule covers this exact request, letting it skip JIT.
    /// The request must still sit inside the egress envelope; rules can never widen it.
    pub fn matches_auto_allow(
        &self,
        agent_profile: Option<&str>,
        host: &str,
        method: &str,
        path: &str,
    ) -> bool {
        if !is_unambiguous_path(path)
            || !(self.matches_host(host) && self.matches_method(method) && self.matches_path(path))
        {
            return false;
        }
        let (host, method) = (host.trim(), method.trim());
        self.auto_allow.iter().any(|rule| {
            let profile_ok = match (rule.agent_profile.as_deref(), agent_profile) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            };
            profile_ok
                && rule.host.eq_ignore_ascii_case(host)
                && !rule.methods.is_empty()
                && rule.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
                && !rule.path_prefixes.is_empty()
                && rule
                    .path_prefixes
                    .iter()
                    .any(|p| path_matches_prefix(path, p))
        })
    }

    /// TLS port the secret may be delivered on: 443 unless `upstream_base_url` declares another.
    pub fn tls_port(&self) -> u16 {
        self.checked_upstream()
            .ok()
            .flatten()
            .and_then(|u| u.port())
            .unwrap_or(443)
    }

    /// `upstream_base_url` may only pin a port on a declared host over https. Anything else
    /// would let a schema edit redirect the real secret to a host nobody approved.
    fn checked_upstream(&self) -> Result<Option<Url>, String> {
        let Some(raw) = &self.upstream_base_url else {
            return Ok(None);
        };
        let url = Url::parse(raw).map_err(|e| format!("upstream_base_url is not a URL: {e}"))?;
        if url.scheme() != "https" {
            return Err("upstream_base_url must use https".to_owned());
        }
        if !url.host_str().is_some_and(|h| self.matches_host(h)) {
            return Err("upstream_base_url host must be one of egress.hosts".to_owned());
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("upstream_base_url may only be https://<declared host>[:port]".to_owned());
        }
        Ok(Some(url))
    }
}

/// `path` falls under `prefix` on a segment boundary (`/v1` covers `/v1/x`, never `/v1evil`),
/// and is free of dot-segments / encoded separators an upstream could resolve differently.
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    is_unambiguous_path(path)
        && (prefix == "/"
            || path.strip_prefix(prefix).is_some_and(|rest| {
                prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/')
            }))
}

fn is_unambiguous_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.contains("//")
        || path.bytes().any(|b| b == b'\\' || b.is_ascii_control())
    {
        return false;
    }
    if path
        .split('/')
        .any(|seg| seg == "." || seg == ".." || seg.contains(';'))
    {
        return false;
    }
    let bytes = path.as_bytes();
    for (i, _) in path.match_indices('%') {
        let Some(hex) = bytes.get(i + 1..i + 3) else {
            return false;
        };
        if !hex.iter().all(u8::is_ascii_hexdigit)
            || matches!(
                hex.to_ascii_lowercase().as_slice(),
                b"2e" | b"2f" | b"5c" | b"25" | b"3b"
            )
        {
            return false;
        }
    }
    true
}

fn validate_identifier_segment(value: &str, kind: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{kind} must not be empty"));
    }
    if value == "." || value.contains("..") {
        return Err(format!(
            "{kind} '{value}' must not contain path traversal ('..')"
        ));
    }
    if value.contains('/') || value.contains('\\') || value.contains(':') {
        return Err(format!(
            "{kind} '{value}' must not contain '/', '\\\\', or ':'"
        ));
    }
    if value.bytes().any(|b| b == 0) || value.chars().any(char::is_control) {
        return Err(format!(
            "{kind} '{value}' must not contain NUL or control characters"
        ));
    }
    if value.ends_with('.') || value.ends_with(' ') {
        return Err(format!("{kind} '{value}' must not end with '.' or a space"));
    }
    Ok(())
}

/// An auto-allow rule may only narrow the egress envelope: exact profile, exact declared host,
/// explicit methods and path prefixes that the envelope itself already allows.
fn validate_auto_allow(egress: &EgressSpec, rule: &AutoAllowRule) -> Result<(), String> {
    if let Some(profile) = &rule.agent_profile {
        let p = profile.trim();
        if p.is_empty() || p == "*" {
            return Err("auto_allow.agent_profile must be an exact profile name".to_owned());
        }
    }
    let host = rule.host.trim();
    if host.is_empty() || host.contains('*') || host.contains("://") || host.contains('/') {
        return Err(format!(
            "auto_allow host '{}' must be an exact hostname (no wildcards, schemes, or paths)",
            rule.host
        ));
    }
    if !egress.matches_host(&rule.host) {
        return Err(format!(
            "auto_allow host '{}' must be one of egress.hosts",
            rule.host
        ));
    }
    if rule.methods.is_empty() {
        return Err("auto_allow.methods must list at least one explicit method".to_owned());
    }
    for m in &rule.methods {
        if m.trim().is_empty() || m.contains('*') || !egress.matches_method(m) {
            return Err(format!(
                "auto_allow method '{m}' must be an explicit method allowed by egress.methods"
            ));
        }
    }
    if rule.path_prefixes.is_empty() {
        return Err("auto_allow.path_prefixes must list at least one explicit prefix".to_owned());
    }
    for p in &rule.path_prefixes {
        if !is_unambiguous_path(p) || !egress.matches_path(p) {
            return Err(format!(
                "auto_allow path prefix '{p}' must be an unambiguous path inside egress.path_prefixes"
            ));
        }
    }
    Ok(())
}

/// Optional auto-rotation webhook hook metadata (Iron Law of Revocation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatorSpec {
    pub provider: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Signed dual-phase rotation webhook (`prepare` -> `commit`, `rollback` on failure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationSpec {
    #[serde(default)]
    pub provider: Option<String>,
    pub webhook_url: String,
    /// Reference (never the value) of the HMAC key that signs webhook payloads.
    pub signing_secret_ref: String,
    #[serde(default)]
    pub max_age_days: Option<u32>,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default = "default_true")]
    pub revoke_on_offboard: bool,
}

impl RotationSpec {
    fn validate(&self) -> Result<(), String> {
        let url = Url::parse(&self.webhook_url)
            .map_err(|e| format!("rotation.webhook_url is not a URL: {e}"))?;
        if url.scheme() != "https" {
            return Err("rotation.webhook_url must use https".to_owned());
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err("rotation.webhook_url must name a host".to_owned());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("rotation.webhook_url must not embed credentials".to_owned());
        }
        if self.signing_secret_ref.trim().is_empty() {
            return Err("rotation.signing_secret_ref must not be empty".to_owned());
        }
        Ok(())
    }
}

/// Specification for one environment variable / secret in `.env.schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarSpec {
    #[serde(rename = "type", default)]
    pub var_type: VarType,
    #[serde(default)]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub required_in: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub allowed_values: Vec<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub egress: Option<EgressSpec>,
    #[serde(default)]
    pub rotator: Option<RotatorSpec>,
    #[serde(default)]
    pub rotation: Option<RotationSpec>,
    /// MCP server names this secret may be injected into (empty = any server the caller holds
    /// `USE` for). Exact names only; never globs.
    #[serde(default)]
    pub mcp_servers: Vec<String>,
}

impl VarSpec {
    /// Whether this secret may be bound to the MCP server `server_name`, optionally reaching
    /// `upstream_host`. Requires explicit `mcp_servers` opt-in, and rejects `egress`-bound
    /// secrets on stdio servers (`upstream_host` is `None`). Caller `USE` capability is enforced
    /// separately by `CompiledPolicy`.
    pub fn allows_mcp_server(&self, server_name: &str, upstream_host: Option<&str>) -> bool {
        if !self
            .mcp_servers
            .iter()
            .any(|s| s.eq_ignore_ascii_case(server_name))
        {
            return false;
        }
        if let Some(egress) = &self.egress {
            let Some(host) = upstream_host else {
                return false;
            };
            return egress.matches_host(host);
        }
        true
    }
}

/// Single validation failure (never contains secret values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub var_name: String,
    pub message: String,
}

/// Schema validation report for a target environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub environment: String,
    pub checked_vars: usize,
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }
}

impl EnvSchema {
    /// Parse and structurally validate a TOML `.env.schema`.
    pub fn parse_toml(input: &str) -> Result<Self, SecretError> {
        let schema: Self = toml::from_str(input)?;
        schema.validate_schema()?;
        Ok(schema)
    }

    /// Verify schema-level security invariants (e.g., no wildcard egress hosts).
    pub fn validate_schema(&self) -> Result<(), SecretError> {
        for (name, spec) in &self.vars {
            validate_identifier_segment(name, "variable name").map_err(|reason| {
                SecretError::InvalidSchema {
                    var_name: name.clone(),
                    reason,
                }
            })?;
            if let Some(zone) = &spec.zone {
                validate_identifier_segment(zone, "zone").map_err(|reason| {
                    SecretError::InvalidSchema {
                        var_name: name.clone(),
                        reason,
                    }
                })?;
            }
            if let Some(egress) = &spec.egress {
                if egress.hosts.is_empty() {
                    return Err(SecretError::InvalidSchema {
                        var_name: name.clone(),
                        reason: "egress.hosts must declare at least one explicit host".to_owned(),
                    });
                }
                egress
                    .checked_upstream()
                    .map_err(|reason| SecretError::InvalidSchema {
                        var_name: name.clone(),
                        reason,
                    })?;
                for host in &egress.hosts {
                    let trimmed = host.trim();
                    if trimmed.is_empty()
                        || trimmed.contains('*')
                        || trimmed.contains('/')
                        || trimmed.contains("://")
                        || trimmed.chars().any(char::is_whitespace)
                    {
                        return Err(SecretError::InvalidSchema {
                            var_name: name.clone(),
                            reason: format!(
                                "egress host '{host}' must be an exact hostname (no wildcards, schemes, or paths)"
                            ),
                        });
                    }
                    let unbracketed = trimmed.trim_start_matches('[').trim_end_matches(']');
                    if IpAddr::from_str(unbracketed).is_ok() || trimmed.contains(':') {
                        return Err(SecretError::InvalidSchema {
                            var_name: name.clone(),
                            reason: format!(
                                "egress host '{host}' must be a DNS hostname, not an IP literal or host:port"
                            ),
                        });
                    }
                    let lower = trimmed.trim_end_matches('.').to_ascii_lowercase();
                    if lower == "localhost" || lower.ends_with(".localhost") {
                        return Err(SecretError::InvalidSchema {
                            var_name: name.clone(),
                            reason: format!("egress host '{host}' must not target localhost"),
                        });
                    }
                }
                for rule in &egress.auto_allow {
                    validate_auto_allow(egress, rule).map_err(|reason| {
                        SecretError::InvalidSchema {
                            var_name: name.clone(),
                            reason,
                        }
                    })?;
                }
            }
            for server in &spec.mcp_servers {
                if server.is_empty()
                    || server.contains(['*', '/', ':'])
                    || server.contains(char::is_whitespace)
                {
                    return Err(SecretError::InvalidSchema {
                        var_name: name.clone(),
                        reason: format!(
                            "mcp_servers entry '{server}' must be a non-empty exact server name (no wildcards, '/', ':' or whitespace)"
                        ),
                    });
                }
            }
            if let Some(rotation) = &spec.rotation {
                rotation
                    .validate()
                    .map_err(|reason| SecretError::InvalidSchema {
                        var_name: name.clone(),
                        reason,
                    })?;
            }
            if matches!(
                spec.sensitivity,
                Sensitivity::Secret | Sensitivity::Restricted
            ) && spec.default.is_some()
            {
                return Err(SecretError::InvalidSchema {
                    var_name: name.clone(),
                    reason: "secret/restricted variables must never hardcode a default value in .env.schema"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Validate resolved key/value pairs against this schema for `env`.
    pub fn validate_values(
        &self,
        env: &Environment,
        values: &BTreeMap<String, String>,
    ) -> ValidationReport {
        let env_str = env.as_str();
        let mut issues = Vec::new();

        for (name, spec) in &self.vars {
            let required = spec
                .required_in
                .iter()
                .any(|e| e.eq_ignore_ascii_case(env_str) || e == "*");
            let resolved = values
                .get(name)
                .map(String::as_str)
                .or(spec.default.as_deref());

            let Some(val) = resolved else {
                if required {
                    issues.push(ValidationIssue {
                        var_name: name.clone(),
                        message: format!("required in environment '{env_str}' but missing"),
                    });
                }
                continue;
            };

            if val.is_empty() && required {
                issues.push(ValidationIssue {
                    var_name: name.clone(),
                    message: format!("required in environment '{env_str}' but empty"),
                });
                continue;
            }

            match spec.var_type {
                VarType::Int => {
                    if val.parse::<i64>().is_err() {
                        issues.push(ValidationIssue {
                            var_name: name.clone(),
                            message: "expected integer value".to_owned(),
                        });
                    }
                }
                VarType::Bool => {
                    if !matches!(
                        val.to_ascii_lowercase().as_str(),
                        "true" | "false" | "1" | "0"
                    ) {
                        issues.push(ValidationIssue {
                            var_name: name.clone(),
                            message: "expected boolean value (true/false/1/0)".to_owned(),
                        });
                    }
                }
                VarType::Url => {
                    if Url::parse(val).is_err() {
                        issues.push(ValidationIssue {
                            var_name: name.clone(),
                            message: "expected valid URL".to_owned(),
                        });
                    }
                }
                VarType::String | VarType::Secret => {}
            }

            if !spec.allowed_values.is_empty() && !spec.allowed_values.iter().any(|a| a == val) {
                issues.push(ValidationIssue {
                    var_name: name.clone(),
                    message: format!("value not in allowed set {:?}", spec.allowed_values),
                });
            }
        }

        ValidationReport {
            environment: env_str.to_owned(),
            checked_vars: self.vars.len(),
            issues,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(vars: &str) -> Result<EnvSchema, SecretError> {
        EnvSchema::parse_toml(&format!("version = 1\n{vars}"))
    }

    #[test]
    fn mcp_servers_parse_and_default_empty() {
        let schema = parse(
            r#"
[vars.GH_TOKEN]
type = "secret"
mcp_servers = ["github", "GitLab"]

[vars.PLAIN]
type = "secret"
"#,
        )
        .unwrap();
        assert_eq!(schema.vars["GH_TOKEN"].mcp_servers, ["github", "GitLab"]);
        assert!(schema.vars["PLAIN"].mcp_servers.is_empty());
    }

    #[test]
    fn mcp_servers_reject_wildcards_separators_and_whitespace() {
        for bad in ["", "*", "git*", "a/b", "a:b", "a b", " github", "git\thub"] {
            let err = parse(&format!(
                "[vars.X]\ntype = \"secret\"\nmcp_servers = [\"{}\"]\n",
                bad
            ))
            .unwrap_err();
            assert!(
                matches!(err, SecretError::InvalidSchema { ref var_name, .. } if var_name == "X"),
                "'{bad}' must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn allows_mcp_server_checks_name_and_host() {
        let schema = parse(
            r#"
[vars.BOUND]
type = "secret"
mcp_servers = ["github"]
[vars.BOUND.egress]
hosts = ["api.github.com"]

[vars.STDIO_BOUND]
type = "secret"
mcp_servers = ["local-tool"]

[vars.OPEN]
type = "secret"
"#,
        )
        .unwrap();
        let bound = &schema.vars["BOUND"];
        assert!(!bound.allows_mcp_server("github", None));
        assert!(bound.allows_mcp_server("GitHub", Some("API.github.com")));
        assert!(!bound.allows_mcp_server("gitlab", None));
        assert!(!bound.allows_mcp_server("gitlab", Some("api.github.com")));
        assert!(!bound.allows_mcp_server("github", Some("evil.example.com")));

        let stdio = &schema.vars["STDIO_BOUND"];
        assert!(stdio.allows_mcp_server("local-tool", None));
        assert!(stdio.allows_mcp_server("LOCAL-TOOL", Some("any.host")));
        assert!(!stdio.allows_mcp_server("github", None));

        let open = &schema.vars["OPEN"];
        assert!(!open.allows_mcp_server("anything", None));
        assert!(!open.allows_mcp_server("anything", Some("any.host")));
    }
}
