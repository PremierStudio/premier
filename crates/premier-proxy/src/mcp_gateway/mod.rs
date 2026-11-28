//! Policy-unified MCP tool gateway.
//!
//! Agents talk to one MCP endpoint. The gateway fans out to the upstream servers declared in
//! `.access.toml` (`[mcp_servers.*]`), exposing only tools that are (a) not quarantined by the
//! pin registry and (b) allowed for `human ∩ agent_profile` by `[[mcp_rules]]`. Calls pass
//! argument guardrails, placeholder-exfiltration checks and JIT approval before the upstream
//! sees them; credentials are injected host-side and every reflected secret is scrubbed.

mod pinning;
mod transport;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use premier_core::{AuditDecision, AuditEvent, Capability, DelegatedIdentity};
use premier_policy::{
    CompiledMcpServer, CompiledPolicy, McpApprovalMode, McpCredentialBinding, McpRiskLevel,
    McpToolDecision, McpTransportKind, PolicyLayer, sha256_hex,
};
use premier_secrets::{EnvSchema, PLACEHOLDER_PREFIX, SecretRedactor};
use rustls::pki_types::CertificateDer;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

pub use pinning::{
    ObservedToolRecord, PinRegistrySnapshot, QuarantineEntry, TofuPin, ToolDriftAlert,
    ToolPinRegistry, ToolPinStatus, ToolVerificationResult, canonical_json_bytes,
    hash_tool_definition, scan_tool_poisoning,
};
pub use transport::{
    BoxFuture, GatewayError, HttpSseUpstream, HttpUpstreamOptions, MAX_FRAME_BYTES, McpUpstream,
    StdioUpstream,
};

use crate::approval::{ApprovalHub, ApprovalRequest, ApprovalWaitOutcome};
use crate::audit::AuditSink;

const COMPONENT: &str = "premier-mcp-gateway";
const PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_ARGS_SUMMARY: usize = 256;
const MAX_JSONRPC_BATCH: usize = 32;
/// Argument keys a caller could use to claim another identity.
const IDENTITY_OVERRIDE_KEYS: &[&str] = &[
    "principal",
    "groups",
    "agent_profile",
    "as_agent",
    "_premier_principal",
    "principal_override",
    "agent_profile_override",
];

/// Premier's own in-process MCP tools/resources, served alongside upstream servers.
pub trait BuiltinMcpHandler: Send + Sync {
    fn list_tools(&self) -> Vec<Value>;
    /// MCP `tools/call` result (`{ content, isError }`), or `None` if `name` is not a builtin.
    fn call_tool(&self, name: &str, arguments: &Map<String, Value>) -> Option<Value>;
    fn list_resources(&self) -> Vec<Value> {
        Vec::new()
    }
    /// MCP `resources/read` result (`{ contents }`), or `None` if unknown.
    fn read_resource(&self, _uri: &str) -> Option<Value> {
        None
    }
}

/// How JIT tool approvals are decided.
#[derive(Clone)]
pub enum McpApprovalHandler {
    Hub {
        hub: Arc<ApprovalHub>,
        timeout: Duration,
    },
    AutoApprove,
    DenyAll,
    Callback(Arc<dyn Fn(&ApprovalRequest) -> bool + Send + Sync>),
}

impl McpApprovalHandler {
    async fn decide(&self, req: ApprovalRequest, allow_reuse: bool) -> ApprovalWaitOutcome {
        match self {
            Self::Hub { hub, timeout } => hub.request_and_wait(req, *timeout, allow_reuse).await,
            Self::AutoApprove => ApprovalWaitOutcome::Approved {
                ttl_secs: req.ttl_secs,
                reused_grant: false,
            },
            Self::DenyAll => ApprovalWaitOutcome::Denied,
            Self::Callback(f) => {
                if f(&req) {
                    ApprovalWaitOutcome::Approved {
                        ttl_secs: req.ttl_secs,
                        reused_grant: false,
                    }
                } else {
                    ApprovalWaitOutcome::Denied
                }
            }
        }
    }
}

pub struct McpGatewayConfig {
    pub identity: DelegatedIdentity,
    pub ref_name: String,
    pub policy: Arc<CompiledPolicy>,
    pub env_schema: Arc<EnvSchema>,
    pub resolved_secrets: BTreeMap<String, Zeroizing<String>>,
    pub audit_sink: Arc<AuditSink>,
    pub pin_registry: Arc<ToolPinRegistry>,
    pub approval_handler: McpApprovalHandler,
    pub allow_loopback_http: bool,
    pub allow_private_upstreams: bool,
    /// Allow `stdio` servers declared only in repo `.access.toml` (not Server layer).
    pub allow_repo_stdio_servers: bool,
    pub extra_upstream_roots: Vec<CertificateDer<'static>>,
    /// Pre-built upstreams by server name (tests, embedders). Credential checks still apply.
    pub custom_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
    pub builtins: Option<Arc<dyn BuiltinMcpHandler>>,
}

enum ServerSlot {
    Ready(Arc<dyn McpUpstream>),
    /// Credential binding or transport config failed; never connected, reason is for audit.
    Unavailable(String),
}

/// Policy-enforcing MCP gateway bound to one caller identity.
pub struct McpGateway {
    identity: DelegatedIdentity,
    ref_name: String,
    policy: Arc<CompiledPolicy>,
    env_schema: Arc<EnvSchema>,
    resolved_secrets: BTreeMap<String, Zeroizing<String>>,
    audit: Arc<AuditSink>,
    pins: Arc<ToolPinRegistry>,
    approval: McpApprovalHandler,
    redactor: Arc<SecretRedactor>,
    servers: BTreeMap<String, ServerSlot>,
    builtins: Option<Arc<dyn BuiltinMcpHandler>>,
}

fn upstream_host(server: &CompiledMcpServer) -> Option<String> {
    if server.config.transport != McpTransportKind::HttpSse {
        return None;
    }
    let url = url::Url::parse(server.config.url.as_deref()?).ok()?;
    url.host_str().map(str::to_owned)
}

/// Whether `identity` may bind `secret` into `server` (schema binding, `USE`, and a value).
fn check_secret(
    cfg: (
        &CompiledPolicy,
        &EnvSchema,
        &BTreeMap<String, Zeroizing<String>>,
    ),
    identity: &DelegatedIdentity,
    ref_name: &str,
    server: &CompiledMcpServer,
    secret: &str,
) -> Result<(), String> {
    let (policy, schema, resolved) = cfg;
    let spec = schema
        .vars
        .get(secret)
        .ok_or_else(|| format!("secret '{secret}' is not declared in .env.schema"))?;
    if !spec.allows_mcp_server(&server.name, upstream_host(server).as_deref()) {
        return Err(format!(
            "secret '{secret}' is not bound to MCP server '{}'",
            server.name
        ));
    }
    let zone = spec.zone.as_deref().or(server.config.zone.as_deref());
    if !policy
        .can_use_secret(identity, secret, zone, ref_name)
        .allows(Capability::USE)
    {
        return Err(format!("caller lacks 'use' on secret '{secret}'"));
    }
    if !resolved.contains_key(secret) {
        return Err(format!("secret '{secret}' has no resolved value"));
    }
    Ok(())
}

fn risk_str(risk: McpRiskLevel) -> &'static str {
    match risk {
        McpRiskLevel::Read => "read",
        McpRiskLevel::Write => "write",
        McpRiskLevel::Destructive => "destructive",
    }
}

fn tool_error(message: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": message.into() }], "isError": true })
}

fn contains_placeholder(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(PLACEHOLDER_PREFIX),
        Value::Array(items) => items.iter().any(contains_placeholder),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.contains(PLACEHOLDER_PREFIX) || contains_placeholder(v)),
        _ => false,
    }
}

/// Scrub every string (and key) in `v` in place; returns bytes scrubbed.
fn scrub_value(v: &mut Value, redactor: &SecretRedactor) -> usize {
    match v {
        Value::String(s) => {
            let (clean, n) = redactor.redact_str(s);
            if n > 0 {
                *s = clean;
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(|i| scrub_value(i, redactor)).sum(),
        Value::Object(map) => {
            let mut total = 0;
            let entries = std::mem::take(map);
            for (k, mut val) in entries {
                let (key, n) = redactor.redact_str(&k);
                total += n + scrub_value(&mut val, redactor);
                map.insert(key, val);
            }
            total
        }
        _ => 0,
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

impl McpGateway {
    pub fn new(config: McpGatewayConfig) -> Result<Self, GatewayError> {
        let redactor = Arc::new(SecretRedactor::build(
            config
                .resolved_secrets
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        ));
        let opts = transport::HttpUpstreamOptions {
            allow_loopback_http: config.allow_loopback_http,
            allow_private_upstreams: config.allow_private_upstreams,
            extra_upstream_roots: config.extra_upstream_roots.clone(),
        };

        let mut servers = BTreeMap::new();
        for (name, server) in config.policy.mcp_servers() {
            if !config.policy.can_potentially_access_mcp_server(
                &config.identity,
                name,
                Some(&config.ref_name),
            ) {
                servers.insert(
                    name.clone(),
                    ServerSlot::Unavailable(
                        "caller has no access to any tool on this server".to_owned(),
                    ),
                );
                continue;
            }
            if server.config.transport == McpTransportKind::Stdio
                && server.layer == PolicyLayer::Repo
                && !config.allow_repo_stdio_servers
                && !config.custom_upstreams.contains_key(name)
            {
                servers.insert(
                    name.clone(),
                    ServerSlot::Unavailable(
                        "repo-defined stdio MCP server is disabled by server policy".to_owned(),
                    ),
                );
                continue;
            }
            let checks = (
                config.policy.as_ref(),
                config.env_schema.as_ref(),
                &config.resolved_secrets,
            );
            let failed = server.config.credentials.iter().find_map(|cred| {
                check_secret(
                    checks,
                    &config.identity,
                    &config.ref_name,
                    server,
                    cred.secret_name(),
                )
                .err()
            });
            let slot = match failed {
                Some(reason) => ServerSlot::Unavailable(reason),
                None => match config.custom_upstreams.get(name) {
                    Some(up) => ServerSlot::Ready(Arc::clone(up)),
                    None => {
                        match build_upstream(server, &config.resolved_secrets, &redactor, &opts) {
                            Ok(up) => ServerSlot::Ready(up),
                            Err(e) => {
                                ServerSlot::Unavailable(redactor.redact_str(&e.to_string()).0)
                            }
                        }
                    }
                },
            };
            if let ServerSlot::Unavailable(reason) = &slot {
                tracing::warn!(server = %name, "MCP server unavailable: {reason}");
            }
            servers.insert(name.clone(), slot);
        }

        Ok(Self {
            identity: config.identity,
            ref_name: config.ref_name,
            policy: config.policy,
            env_schema: config.env_schema,
            resolved_secrets: config.resolved_secrets,
            audit: config.audit_sink,
            pins: config.pin_registry,
            approval: config.approval_handler,
            redactor,
            servers,
            builtins: config.builtins,
        })
    }

    pub fn pin_registry(&self) -> &Arc<ToolPinRegistry> {
        &self.pins
    }

    fn audit(
        &self,
        action: &str,
        target: Option<String>,
        capability: Option<&str>,
        decision: AuditDecision,
        reason: impl Into<String>,
        bytes_scrubbed: usize,
    ) {
        let mut ev = AuditEvent::now(&self.identity, COMPONENT, action, decision, reason);
        ev.target = target;
        ev.capability = capability.map(str::to_owned);
        ev.bytes_scrubbed = bytes_scrubbed;
        self.audit.record(ev);
    }

    /// Handle one newline-delimited JSON-RPC message; `None` for notifications.
    pub async fn handle_jsonrpc_line(&self, line: &str) -> Option<String> {
        let resp = match serde_json::from_str::<Value>(line) {
            Ok(msg) => self.handle_jsonrpc_value(msg).await?,
            Err(_) => rpc_error(Value::Null, -32700, "Parse error"),
        };
        serde_json::to_string(&resp).ok()
    }

    pub async fn handle_jsonrpc_value(&self, msg: Value) -> Option<Value> {
        if let Value::Array(batch) = msg {
            if batch.is_empty() {
                return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
            }
            if batch.len() > MAX_JSONRPC_BATCH {
                return Some(rpc_error(
                    Value::Null,
                    -32600,
                    &format!("Invalid Request: batch exceeds maximum of {MAX_JSONRPC_BATCH} items"),
                ));
            }
            if batch.iter().any(Value::is_array) {
                return Some(rpc_error(
                    Value::Null,
                    -32600,
                    "Invalid Request: nested batch arrays are not allowed",
                ));
            }
            let mut out = Vec::new();
            for item in batch {
                if let Some(r) = Box::pin(self.handle_jsonrpc_value(item)).await {
                    out.push(r);
                }
            }
            return (!out.is_empty()).then_some(Value::Array(out));
        }
        let id = msg.get("id").cloned();
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            return id.map(|id| rpc_error(id, -32600, "Invalid Request"));
        };
        // Notifications get no reply.
        let id = id?;
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        Some(match self.dispatch(method, params).await {
            Ok(result) => rpc_result(id, result),
            Err((code, message)) => rpc_error(id, code, &message),
        })
    }

    async fn dispatch(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {}, "resources": {} },
                "serverInfo": { "name": COMPONENT, "version": env!("CARGO_PKG_VERSION") },
            })),
            "notifications/initialized" | "ping" => Ok(json!({})),
            "resources/list" => Ok(json!({
                "resources": self.builtins.as_ref().map(|b| b.list_resources()).unwrap_or_default(),
            })),
            "resources/read" => {
                let uri = params
                    .get("uri")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let mut result = self
                    .builtins
                    .as_ref()
                    .and_then(|b| b.read_resource(uri))
                    .ok_or((-32002, "Resource not found".to_owned()))?;
                let scrubbed = scrub_value(&mut result, &self.redactor);
                if scrubbed > 0 {
                    self.audit(
                        "mcp_resource_read",
                        Some(uri.to_owned()),
                        None,
                        AuditDecision::Redacted,
                        "resource read completed; reflected secrets scrubbed",
                        scrubbed,
                    );
                }
                Ok(result)
            }
            "tools/list" => Ok(json!({ "tools": self.list_tools().await })),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or((-32602, "tools/call requires a string 'name'".to_owned()))?;
                let args = match params.get("arguments") {
                    None | Some(Value::Null) => Map::new(),
                    Some(Value::Object(m)) => m.clone(),
                    Some(_) => return Err((-32602, "'arguments' must be an object".to_owned())),
                };
                Ok(self.call_tool(name, args).await)
            }
            _ => Err((-32601, format!("Method not found: {method}"))),
        }
    }

    /// Fetch `server`'s raw tool definitions without modifying the pin registry.
    async fn fetch_raw_tools(
        &self,
        upstream: &Arc<dyn McpUpstream>,
    ) -> Result<Vec<(String, Value)>, String> {
        let tools = upstream
            .list_tools()
            .await
            .map_err(|e| self.redactor.redact_str(&e.to_string()).0)?;
        let mut out = Vec::new();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            out.push((name, tool));
        }
        Ok(out)
    }

    fn verify_tool(
        &self,
        server: &CompiledMcpServer,
        tool_name: &str,
        tool: &Value,
    ) -> pinning::ToolVerificationResult {
        self.pins.verify_or_pin(
            &server.name,
            tool,
            self.policy
                .pinned_mcp_tool_hash_with_layer(&server.name, tool_name),
            server.config.pin_on_first_use,
            Some(&self.redactor),
        )
    }

    async fn list_tools(&self) -> Vec<Value> {
        let mut exposed = self
            .builtins
            .as_ref()
            .map(|b| b.list_tools())
            .unwrap_or_default();
        for (name, server) in self.policy.mcp_servers() {
            let Some(ServerSlot::Ready(upstream)) = self.servers.get(name) else {
                // Unavailable servers stay invisible to the caller.
                continue;
            };
            let tools = match self.fetch_raw_tools(upstream).await {
                Ok(t) => t,
                Err(reason) => {
                    tracing::warn!(server = %name, "MCP tools/list failed: {reason}");
                    self.audit(
                        "mcp_tools_list",
                        Some(name.clone()),
                        None,
                        AuditDecision::Denied,
                        format!("upstream tools/list failed: {reason}"),
                        0,
                    );
                    continue;
                }
            };
            for (tool_name, tool) in tools {
                // Authorize before inspecting/pinning so disallowed tools never create TOFU state.
                let decision =
                    self.policy
                        .evaluate_mcp_tool(&self.identity, name, &tool_name, &self.ref_name);
                if !decision.allowed {
                    continue;
                }
                let full_name = format!("{name}:{tool_name}");
                let verdict = self.verify_tool(server, &tool_name, &tool);
                if verdict.status == ToolPinStatus::Quarantined {
                    self.audit(
                        "mcp_tool_quarantined",
                        Some(full_name),
                        None,
                        AuditDecision::Denied,
                        "tool hidden: quarantined by schema drift or poisoning alert",
                        0,
                    );
                    continue;
                }
                let mut entry = Map::new();
                entry.insert("name".to_owned(), Value::String(full_name));
                for key in ["description", "inputSchema", "annotations"] {
                    if let Some(v) = tool.get(key).filter(|v| !v.is_null()) {
                        entry.insert(key.to_owned(), v.clone());
                    }
                }
                entry
                    .entry("inputSchema")
                    .or_insert_with(|| json!({ "type": "object" }));
                let mut entry = Value::Object(entry);
                scrub_value(&mut entry, &self.redactor);
                exposed.push(entry);
            }
        }
        exposed
    }

    /// Resolve `name` to a declared `(server, tool)`.
    fn parse_tool_name<'a>(&self, name: &'a str) -> Option<(String, &'a str)> {
        let servers = self.policy.mcp_servers();
        if let Some((server, tool)) = name.split_once(':') {
            return servers
                .contains_key(server)
                .then(|| (server.to_owned(), tool));
        }
        servers
            .keys()
            .filter_map(|s| {
                let tool = name.strip_prefix(s.as_str())?.strip_prefix("__")?;
                Some((s.clone(), tool))
            })
            .max_by_key(|(s, _)| s.len())
    }

    fn deny(
        &self,
        target: &str,
        risk: Option<&str>,
        decision: AuditDecision,
        reason: &str,
    ) -> Value {
        self.deny_with_client_msg(target, risk, decision, reason, reason)
    }

    fn deny_with_client_msg(
        &self,
        target: &str,
        risk: Option<&str>,
        decision: AuditDecision,
        audit_reason: &str,
        client_msg: &str,
    ) -> Value {
        self.audit(
            "mcp_tool_call",
            Some(target.to_owned()),
            risk,
            decision,
            audit_reason,
            0,
        );
        tool_error(client_msg)
    }

    async fn call_tool(&self, name: &str, args: Map<String, Value>) -> Value {
        if let Some(key) = args.keys().find(|k| {
            IDENTITY_OVERRIDE_KEYS
                .iter()
                .any(|o| k.eq_ignore_ascii_case(o))
        }) {
            return self.deny(
                name,
                None,
                AuditDecision::Denied,
                &format!("identity override argument '{key}' is not allowed"),
            );
        }

        let Some((server_name, tool)) = self.parse_tool_name(name) else {
            if let Some(mut result) = self
                .builtins
                .as_ref()
                .and_then(|b| b.call_tool(name, &args))
            {
                let scrubbed = scrub_value(&mut result, &self.redactor);
                self.audit(
                    "mcp_builtin_call",
                    Some(name.to_owned()),
                    None,
                    if scrubbed > 0 {
                        AuditDecision::Redacted
                    } else {
                        AuditDecision::Allowed
                    },
                    if scrubbed > 0 {
                        "builtin tool; reflected secrets scrubbed"
                    } else {
                        "builtin tool"
                    },
                    scrubbed,
                );
                return result;
            }
            return tool_error(format!("unknown tool '{name}'"));
        };
        let full_name = format!("{server_name}:{tool}");
        let (Some(server), Some(slot)) = (
            self.policy.mcp_server(&server_name),
            self.servers.get(&server_name),
        ) else {
            return tool_error(format!("unknown tool '{name}'"));
        };

        // Policy first: an unauthorized caller never causes an upstream connection.
        let decision =
            self.policy
                .evaluate_mcp_tool(&self.identity, &server_name, tool, &self.ref_name);
        let risk = risk_str(decision.risk);
        if !decision.allowed {
            return self.deny_with_client_msg(
                &full_name,
                Some(risk),
                AuditDecision::Denied,
                &format!("tool not allowed: {}", decision.reason),
                &format!("tool '{full_name}' is not allowed"),
            );
        }

        let upstream = match slot {
            ServerSlot::Ready(up) => up,
            ServerSlot::Unavailable(reason) => {
                self.audit(
                    "mcp_tool_call",
                    Some(full_name.clone()),
                    Some(risk),
                    AuditDecision::Denied,
                    format!("server unavailable: {reason}"),
                    0,
                );
                return tool_error(format!(
                    "MCP server '{server_name}' is unavailable for this session"
                ));
            }
        };
        let checks = (
            self.policy.as_ref(),
            self.env_schema.as_ref(),
            &self.resolved_secrets,
        );
        if let Some(reason) = decision
            .required_secrets
            .iter()
            .find_map(|s| check_secret(checks, &self.identity, &self.ref_name, server, s).err())
        {
            return self.deny_with_client_msg(
                &full_name,
                Some(risk),
                AuditDecision::Denied,
                &reason,
                &format!(
                    "tool '{full_name}' is unavailable: required credentials are not authorized or configured"
                ),
            );
        }

        // No direct-call bypass: an un-listed allowed tool, or one whose recorded hash does not
        // match the active policy pin, is fetched and verified before execution.
        let policy_pin = self.policy.pinned_mcp_tool_hash(&server_name, tool);
        let needs_verify = if !self.pins.has_observed_tool(&server_name, tool) {
            true
        } else if let Some(expected) = policy_pin {
            let (_, observed) = self.pins.status_of(&server_name, tool, Some(expected));
            !observed
                .as_deref()
                .is_some_and(|obs| obs.eq_ignore_ascii_case(expected))
        } else {
            false
        };
        if needs_verify {
            match self.fetch_raw_tools(upstream).await {
                Ok(tools) => {
                    if let Some((_, def)) = tools.into_iter().find(|(n, _)| n == tool) {
                        let verdict = self.verify_tool(server, tool, &def);
                        if verdict.status == ToolPinStatus::Quarantined {
                            return self.deny(
                                &full_name,
                                Some(risk),
                                AuditDecision::Denied,
                                "tool quarantined due to schema drift or poisoning alert",
                            );
                        }
                    } else {
                        return self.deny(
                            &full_name,
                            Some(risk),
                            AuditDecision::Denied,
                            "tool is not offered by the upstream server",
                        );
                    }
                }
                Err(reason) => {
                    return self.deny(
                        &full_name,
                        Some(risk),
                        AuditDecision::Denied,
                        &format!("could not verify tool definition: {reason}"),
                    );
                }
            }
        }
        if let Some(expected) = policy_pin {
            let (_, observed) = self.pins.status_of(&server_name, tool, Some(expected));
            if !observed
                .as_deref()
                .is_some_and(|obs| obs.eq_ignore_ascii_case(expected))
            {
                return self.deny(
                    &full_name,
                    Some(risk),
                    AuditDecision::Denied,
                    "tool definition does not match its policy-pinned hash",
                );
            }
        }
        if self.pins.is_quarantined(&server_name, tool) {
            return self.deny(
                &full_name,
                Some(risk),
                AuditDecision::Denied,
                "tool quarantined due to schema drift or poisoning alert",
            );
        }

        if let Err(errs) =
            self.policy
                .validate_mcp_args(&self.identity, &decision, &args, &self.ref_name)
        {
            return self.deny(
                &full_name,
                Some(risk),
                AuditDecision::Denied,
                &format!("argument guardrail violated: {}", errs.join("; ")),
            );
        }
        let arguments = Value::Object(args);
        if contains_placeholder(&arguments) {
            return self.deny(
                &full_name,
                Some(risk),
                AuditDecision::ExfiltrationBlocked,
                "placeholder token cannot be passed to external MCP tool",
            );
        }

        if let Some(blocked) = self
            .approve(&decision, &server_name, tool, &arguments)
            .await
        {
            return blocked;
        }

        let mut result = match upstream.call_tool(tool, arguments).await {
            Ok(r) => r,
            Err(e) => {
                let msg = self.redactor.redact_str(&e.to_string()).0;
                return self.deny(
                    &full_name,
                    Some(risk),
                    AuditDecision::Denied,
                    &format!("upstream call failed: {msg}"),
                );
            }
        };
        let scrubbed = scrub_value(&mut result, &self.redactor);
        self.audit(
            "mcp_tool_call",
            Some(full_name),
            Some(risk),
            if scrubbed > 0 {
                AuditDecision::Redacted
            } else {
                AuditDecision::Allowed
            },
            if scrubbed > 0 {
                "tool call completed; reflected secrets scrubbed"
            } else {
                "tool call completed"
            },
            scrubbed,
        );
        result
    }

    /// Enforce the decision's approval mode. `Some(error_result)` blocks the call.
    async fn approve(
        &self,
        decision: &McpToolDecision,
        server: &str,
        tool: &str,
        arguments: &Value,
    ) -> Option<Value> {
        let full_name = format!("{server}:{tool}");
        let risk = risk_str(decision.risk);
        match decision.approval {
            McpApprovalMode::Auto => None,
            McpApprovalMode::Deny => Some(self.deny(
                &full_name,
                Some(risk),
                AuditDecision::Denied,
                "tool approval mode is deny",
            )),
            McpApprovalMode::Jit => {
                let mut summary = arguments.clone();
                scrub_value(&mut summary, &self.redactor);
                let mut summary = summary.to_string();
                if let Some((idx, _)) = summary.char_indices().nth(MAX_ARGS_SUMMARY - 1) {
                    summary.truncate(idx);
                    summary.push('…');
                }
                let args_hash = Some(sha256_hex(&pinning::canonical_json_bytes(arguments)));
                let req = ApprovalRequest {
                    principal: self.identity.principal.canonical_id(),
                    agent_profile: self.identity.agent_task.as_ref().map(|a| a.profile.clone()),
                    var_name: format!("mcp:{server}:{tool}"),
                    host: server.to_owned(),
                    method: "MCP_CALL".to_owned(),
                    path: format!("/{server}/{tool}"),
                    ttl_secs: decision.jit_ttl_secs,
                    kind: Some("mcp_tool".to_owned()),
                    mcp_server: Some(server.to_owned()),
                    mcp_tool: Some(tool.to_owned()),
                    risk: Some(risk.to_owned()),
                    args_summary: Some(summary),
                    args_hash,
                    ref_name: Some(self.ref_name.clone()),
                    ..ApprovalRequest::default()
                };
                self.audit(
                    "mcp_tool_call",
                    Some(full_name.clone()),
                    Some(risk),
                    AuditDecision::ApprovalRequired,
                    "JIT approval requested",
                    0,
                );
                let allow_reuse =
                    decision.risk != McpRiskLevel::Destructive && decision.jit_ttl_secs > 0;
                match self.approval.decide(req, allow_reuse).await {
                    ApprovalWaitOutcome::Approved { .. } => None,
                    ApprovalWaitOutcome::Denied => Some(self.deny(
                        &full_name,
                        Some(risk),
                        AuditDecision::Denied,
                        "JIT approval denied",
                    )),
                    ApprovalWaitOutcome::TimedOut => Some(self.deny(
                        &full_name,
                        Some(risk),
                        AuditDecision::Denied,
                        "JIT approval timed out",
                    )),
                }
            }
        }
    }
}

/// Build the transport for a server whose credentials all passed [`check_secret`].
fn build_upstream(
    server: &CompiledMcpServer,
    resolved: &BTreeMap<String, Zeroizing<String>>,
    redactor: &Arc<SecretRedactor>,
    opts: &transport::HttpUpstreamOptions,
) -> Result<Arc<dyn McpUpstream>, GatewayError> {
    let cfg = &server.config;
    let timeout = Duration::from_secs(cfg.timeout_secs.max(1));
    let mut env = Vec::new();
    let mut headers = Vec::new();
    for cred in &cfg.credentials {
        let value = resolved
            .get(cred.secret_name())
            .ok_or_else(|| GatewayError::Secret("unresolved credential".to_owned()))?;
        match cred {
            McpCredentialBinding::Env { secret, env_var } => env.push((
                env_var.clone().unwrap_or_else(|| secret.clone()),
                value.clone(),
            )),
            McpCredentialBinding::BearerHeader { header, .. } => headers.push((
                header.clone(),
                Zeroizing::new(format!("Bearer {}", value.as_str())),
            )),
            McpCredentialBinding::Header { header, prefix, .. } => headers.push((
                header.clone(),
                Zeroizing::new(format!("{prefix}{}", value.as_str())),
            )),
        }
    }
    match cfg.transport {
        McpTransportKind::Stdio => {
            if !headers.is_empty() {
                return Err(GatewayError::Policy(
                    "header credentials need an http_sse transport".to_owned(),
                ));
            }
            let command = cfg
                .command
                .as_deref()
                .ok_or_else(|| GatewayError::Policy("stdio server has no command".to_owned()))?;
            Ok(Arc::new(StdioUpstream::new(
                command,
                &cfg.args,
                cfg.env.clone(),
                env,
                timeout,
                Arc::clone(redactor),
            )))
        }
        McpTransportKind::HttpSse => {
            if !env.is_empty() {
                return Err(GatewayError::Policy(
                    "env credentials need a stdio transport".to_owned(),
                ));
            }
            let url = cfg
                .url
                .as_deref()
                .ok_or_else(|| GatewayError::Policy("http_sse server has no url".to_owned()))?;
            Ok(Arc::new(HttpSseUpstream::new(
                url,
                &cfg.headers,
                headers,
                timeout,
                Arc::clone(redactor),
                opts.clone(),
            )?))
        }
    }
}
