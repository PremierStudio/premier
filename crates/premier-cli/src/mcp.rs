//! `premier mcp` — Model Context Protocol (MCP) JSON-RPC 2.0 stdio server & client config generator.
//!
//! Exposes read-only policy inspection, environment schema metadata (`use != read`),
//! overlay leak checks, and policy impact diff simulations to AI coding assistants
//! (Claude Code, Codex, Cursor) without ever revealing raw secret values or vault paths.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use premier_core::{Capability, DelegatedIdentity, OverlayKind, Principal, RepoPath};
use premier_overlay::{OverlayEntry, OverlayError, OverlayGuard, OverlayManifest};
use premier_policy::{
    AccessPolicyFile, CompiledPolicy, compute_access_diff, parse_policy_toml, sha256_hex,
};
use premier_proxy::{BuiltinMcpHandler, McpGateway, PinRegistrySnapshot, ToolPinRegistry};
use premier_secrets::{EnvSchema, PLACEHOLDER_PREFIX, Sensitivity};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// Supported MCP protocol versions for `initialize` negotiation (newest first).
pub const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Default MCP protocol version advertised when a client omits or sends an unsupported version.
pub const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

/// Maximum accepted JSON-RPC line length over stdio (2 MiB).
pub const MAX_JSONRPC_LINE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum `head_toml` payload size for `premier_policy_diff` (256 KiB).
pub const MAX_HEAD_TOML_BYTES: usize = 256 * 1024;

/// Maximum number of paths accepted by `premier_overlays_check` and `premier_policy_diff`.
pub const MAX_MCP_PATHS: usize = 500;

/// Maximum number of changed files accepted by `premier_policy_diff`.
pub const MAX_MCP_CHANGED_FILES: usize = 200;

/// Forbidden identity-override argument names rejected across MCP tools.
const FORBIDDEN_IDENTITY_KEYS: &[&str] = &[
    "principal",
    "principals",
    "groups",
    "agent_profile",
    "as_agent",
];

/// Supported MCP client config targets for `premier mcp config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum McpClient {
    /// Anthropic Claude Code (`.mcp.json`)
    ClaudeCode,
    /// OpenAI Codex CLI (`~/.codex/config.toml`)
    Codex,
    /// Cursor IDE (`.cursor/mcp.json`)
    Cursor,
}

/// Options for rendering MCP client configs and `premier agent run` wrapper commands.
#[derive(Debug, Clone, Default)]
pub struct McpConfigOptions<'a> {
    pub agent_profile: Option<&'a str>,
    pub principal: Option<&'a str>,
    pub groups: &'a [String],
    pub policy: Option<&'a Path>,
    pub server_policy: Option<&'a Path>,
}

/// Immutable runtime context for the Premier MCP stdio server.
///
/// Holds only compiled policy metadata, `.env.schema` declarations, overlay guards,
/// and the fixed caller identity (`permissions(human) ∩ permissions(agent_profile)`).
/// Never holds a secret backend, vault file path, or raw secret material.
#[derive(Debug, Clone)]
pub struct McpContext {
    pub repo_policy_file: AccessPolicyFile,
    pub server_policy_file: Option<AccessPolicyFile>,
    pub compiled_policy: CompiledPolicy,
    pub policy_fingerprint: String,
    pub env_schema: EnvSchema,
    pub overlay_guard: OverlayGuard,
    pub identity: DelegatedIdentity,
    pub default_branch: String,
}

impl McpContext {
    /// Construct an `McpContext` from in-memory policy, schema, and overlay objects.
    pub fn new(
        repo_policy_toml: &str,
        server_policy_toml: Option<&str>,
        env_schema: EnvSchema,
        overlay_manifest: &OverlayManifest,
        identity: DelegatedIdentity,
        default_branch: String,
    ) -> Result<Self> {
        let repo_policy_file = parse_policy_toml(repo_policy_toml)
            .context("failed to parse repository .access.toml")?;
        let server_policy_file = server_policy_toml
            .map(parse_policy_toml)
            .transpose()
            .context("failed to parse server policy .access.toml")?;
        let compiled_policy =
            CompiledPolicy::compile(server_policy_file.as_ref(), &repo_policy_file)
                .context("failed to compile access policy")?;

        let fingerprint_input = match server_policy_toml {
            Some(srv) => format!("{repo_policy_toml}\n---server-policy---\n{srv}"),
            None => repo_policy_toml.to_owned(),
        };
        let policy_fingerprint = sha256_hex(fingerprint_input.as_bytes());
        let overlay_guard = OverlayGuard::from_manifest(overlay_manifest)
            .context("failed to compile overlay guard")?;

        Ok(Self {
            repo_policy_file,
            server_policy_file,
            compiled_policy,
            policy_fingerprint,
            env_schema,
            overlay_guard,
            identity,
            default_branch,
        })
    }

    /// Load an `McpContext` from workspace paths on disk.
    ///
    /// Missing `.access.toml` falls back to default-deny (`AccessPolicyFile::default()`).
    /// Missing `.env.schema` or `.premier/overlays.toml` fall back to empty defaults.
    /// An explicitly supplied `--server-policy` path must exist and parse cleanly.
    #[allow(clippy::too_many_arguments)]
    pub fn from_paths(
        policy_path: &Path,
        server_policy_path: Option<&Path>,
        schema_path: &Path,
        overlays_path: &Path,
        principal: &str,
        groups: Vec<String>,
        agent_profile: Option<String>,
        default_branch: String,
    ) -> Result<Self> {
        let repo_policy_toml = if policy_path.exists() {
            let text = std::fs::read_to_string(policy_path)
                .with_context(|| format!("failed to read policy file {}", policy_path.display()))?;
            warn_if_policy_differs_from_head(policy_path, &text);
            text
        } else {
            tracing::warn!(
                path = %policy_path.display(),
                "policy file not found; falling back to default-deny policy"
            );
            "version = 1\n".to_owned()
        };

        let server_policy_toml = match server_policy_path {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read server policy {}", p.display()))?,
            ),
            None => None,
        };

        let env_schema = if schema_path.exists() {
            let text = std::fs::read_to_string(schema_path)
                .with_context(|| format!("failed to read schema {}", schema_path.display()))?;
            EnvSchema::parse_toml(&text)
                .with_context(|| format!("failed to parse schema {}", schema_path.display()))?
        } else {
            tracing::warn!(
                path = %schema_path.display(),
                "env schema file not found; exposing empty schema"
            );
            EnvSchema::default()
        };

        let workspace_root = policy_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let overlay_manifest = load_workspace_overlays(overlays_path, workspace_root)?;

        let parsed_principal = Principal::parse(principal)
            .with_context(|| format!("invalid principal '{principal}'"))?;
        let identity = match agent_profile {
            Some(profile) => DelegatedIdentity::delegated(
                parsed_principal,
                groups,
                profile,
                format!("mcp-pid-{}", std::process::id()),
            ),
            None => DelegatedIdentity::human_only(parsed_principal, groups),
        };

        Self::new(
            &repo_policy_toml,
            server_policy_toml.as_deref(),
            env_schema,
            &overlay_manifest,
            identity,
            default_branch,
        )
    }
}

/// Emit a warning to `stderr` if the working-tree `.access.toml` differs from `HEAD:.access.toml`.
fn warn_if_policy_differs_from_head(policy_path: &Path, working_tree_toml: &str) {
    let dir = policy_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Ok(out) = std::process::Command::new("git")
        .current_dir(dir)
        .args(["show", "HEAD:.access.toml"])
        .output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    if let Ok(head_toml) = std::str::from_utf8(&out.stdout) {
        let norm_wt = working_tree_toml.replace("\r\n", "\n");
        let norm_head = head_toml.replace("\r\n", "\n");
        if norm_wt != norm_head {
            eprintln!(
                "[premier mcp] warning: working-tree {} differs from git HEAD:.access.toml; \
                 premier serve enforces the committed default-branch policy",
                policy_path.display()
            );
            tracing::warn!(
                path = %policy_path.display(),
                "working-tree .access.toml differs from git HEAD:.access.toml"
            );
        }
    }
}

/// Load workspace overlays from `overlays_path` (TOML or JSON) and merge any overlays
/// persisted in the repository's SQLite state, including migrated legacy state.
pub fn load_workspace_overlays(
    overlays_path: &Path,
    workspace_root: &Path,
) -> Result<OverlayManifest> {
    let mut manifest = if overlays_path.exists() {
        let text = std::fs::read_to_string(overlays_path)
            .with_context(|| format!("failed to read overlays file {}", overlays_path.display()))?;
        parse_overlay_manifest(&text)
            .with_context(|| format!("failed to parse overlays file {}", overlays_path.display()))?
    } else {
        OverlayManifest::default()
    };

    let persisted =
        premier_server::store::load_state(workspace_root).map_err(anyhow::Error::msg)?;
    let mut merge = |overlays: OverlayManifest| {
        for entry in overlays.entries {
            if !manifest.entries.contains(&entry) {
                manifest.entries.push(entry);
            }
        }
    };
    merge(persisted.overlays);

    // Also accept legacy manifests stored alongside an explicitly selected overlays file.
    let primary = premier_server::store::state_file_path(workspace_root);
    let mut state_candidates = Vec::new();
    let local_state = workspace_root.join(".premier").join("state.json");
    if primary != local_state {
        state_candidates.push(local_state);
    }
    if let Some(sibling_state) = overlays_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join("state.json"))
        && sibling_state != primary
        && !state_candidates.contains(&sibling_state)
    {
        state_candidates.push(sibling_state);
    }

    for candidate in state_candidates {
        if !candidate.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        let Ok(state) = serde_json::from_str::<premier_server::store::PersistedState>(&raw) else {
            continue;
        };
        merge(state.overlays);
    }

    Ok(manifest)
}

enum BoundedLine {
    Eof,
    Line(String),
    TooLong,
    InvalidUtf8,
}

/// Read a single newline-delimited line capped at `max_bytes` (excluding line terminator).
///
/// Oversized lines are drained in constant memory until the next `\n` or EOF so an
/// attacker cannot trigger unbounded memory growth.
fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> std::io::Result<BoundedLine> {
    let mut buf = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    let n = reader.take(limit).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(BoundedLine::Eof);
    }

    let ended_with_newline = buf.ends_with(b"\n");
    if ended_with_newline {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }

    if buf.len() > max_bytes || (!ended_with_newline && n > max_bytes) {
        if !ended_with_newline {
            loop {
                let avail = reader.fill_buf()?;
                if avail.is_empty() {
                    break;
                }
                if let Some(pos) = avail.iter().position(|&b| b == b'\n') {
                    reader.consume(pos + 1);
                    break;
                }
                let len = avail.len();
                reader.consume(len);
            }
        }
        return Ok(BoundedLine::TooLong);
    }

    match String::from_utf8(buf) {
        Ok(s) => Ok(BoundedLine::Line(s)),
        Err(_) => Ok(BoundedLine::InvalidUtf8),
    }
}

/// Run the newline-delimited JSON-RPC 2.0 MCP server loop over stdin/stdout.
///
/// All diagnostic logging goes exclusively to `stderr` so `stdout` carries only
/// valid newline-delimited JSON-RPC 2.0 frames.
pub fn run_stdio_server(ctx: &McpContext) -> Result<()> {
    tracing::info!(
        principal = %ctx.identity.principal,
        agent_profile = ?ctx.identity.agent_task.as_ref().map(|a| a.profile.as_str()),
        branch = %ctx.default_branch,
        "starting premier-mcp JSON-RPC 2.0 stdio server"
    );

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());
    let writer = BufWriter::new(stdout.lock());

    run_stdio_loop(ctx, reader, writer, MAX_JSONRPC_LINE_BYTES)?;

    tracing::info!("stdin closed; shutting down premier-mcp server");
    Ok(())
}

/// Core bounded stdio loop, factored for deterministic testing.
pub fn run_stdio_loop<R: BufRead, W: Write>(
    ctx: &McpContext,
    mut reader: R,
    mut writer: W,
    max_line_bytes: usize,
) -> Result<()> {
    loop {
        let response = match read_bounded_line(&mut reader, max_line_bytes)
            .context("failed to read line from stdin")?
        {
            BoundedLine::Eof => break,
            BoundedLine::TooLong => Some(jsonrpc_error(
                Value::Null,
                -32600,
                &format!("Invalid Request: line exceeds maximum size of {max_line_bytes} bytes"),
            )),
            BoundedLine::InvalidUtf8 => Some(jsonrpc_error(
                Value::Null,
                -32700,
                "Parse error: request line is not valid UTF-8",
            )),
            BoundedLine::Line(line) => handle_jsonrpc_line(ctx, &line),
        };

        if let Some(resp) = response {
            writer
                .write_all(resp.as_bytes())
                .context("failed to write JSON-RPC response to stdout")?;
            writer
                .write_all(b"\n")
                .context("failed to write newline delimiter to stdout")?;
            writer.flush().context("failed to flush stdout")?;
        }
    }
    Ok(())
}

/// Pure, single-line JSON-RPC 2.0 MCP request handler.
///
/// Returns `None` for blank lines and JSON-RPC notifications (messages without an `id`).
/// Returns `Some(json_line)` containing a single-line JSON-RPC 2.0 response for every
/// request carrying an `id` (or malformed JSON / invalid request).
pub fn handle_jsonrpc_line(ctx: &McpContext, line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(err) => {
            return Some(jsonrpc_error(
                Value::Null,
                -32700,
                &format!("Parse error: {err}"),
            ));
        }
    };

    let Some(obj) = parsed.as_object() else {
        return Some(jsonrpc_error(
            Value::Null,
            -32600,
            "Invalid Request: expected JSON object",
        ));
    };

    // Strict JSON-RPC / MCP `id` validation: accept ONLY string or number when present.
    let id = match obj.get("id") {
        None => None,
        Some(v @ (Value::String(_) | Value::Number(_))) => Some(v.clone()),
        Some(_) => {
            return Some(jsonrpc_error(
                Value::Null,
                -32600,
                "Invalid Request: \"id\" must be a string or number",
            ));
        }
    };

    let jsonrpc_ok = obj
        .get("jsonrpc")
        .and_then(Value::as_str)
        .is_some_and(|v| v == "2.0");
    let method = obj.get("method").and_then(Value::as_str);

    if !jsonrpc_ok {
        return Some(jsonrpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request: jsonrpc must be \"2.0\"",
        ));
    }

    let Some(method) = method else {
        return Some(jsonrpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request: missing string \"method\"",
        ));
    };

    // Notifications carry no `id` and must never emit a response.
    let id = id?;

    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let response = match method {
        "initialize" => {
            let negotiated = params
                .as_object()
                .and_then(|o| o.get("protocolVersion"))
                .and_then(Value::as_str)
                .filter(|v| SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(MCP_PROTOCOL_VERSION);
            jsonrpc_ok_response(
                id,
                json!({
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {},
                        "resources": {}
                    },
                    "serverInfo": {
                        "name": "premier-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )
        }
        "notifications/initialized" => jsonrpc_ok_response(id, json!({})),
        "ping" => jsonrpc_ok_response(id, json!({})),
        "tools/list" => jsonrpc_ok_response(id, json!({ "tools": tool_definitions() })),
        "tools/call" => handle_tools_call(ctx, id, &params),
        "resources/list" => jsonrpc_ok_response(id, json!({ "resources": resource_definitions() })),
        "resources/read" => handle_resources_read(ctx, id, &params),
        other => jsonrpc_error(id, -32601, &format!("Method not found: {other}")),
    };

    Some(response)
}

/// Adapter exposing Premier's 5 built-in policy/schema/overlay tools and 2 resources
/// inside the unified [`McpGateway`].
#[derive(Debug, Clone)]
pub struct PremierBuiltinMcpHandler {
    ctx: McpContext,
}

impl PremierBuiltinMcpHandler {
    pub fn new(ctx: McpContext) -> Self {
        Self { ctx }
    }
}

impl BuiltinMcpHandler for PremierBuiltinMcpHandler {
    fn list_tools(&self) -> Vec<Value> {
        builtin_tool_list()
    }

    fn call_tool(&self, name: &str, arguments: &Map<String, Value>) -> Option<Value> {
        let result = match name {
            "premier_access_explain" => tool_access_explain(&self.ctx, arguments),
            "premier_policy_summary" => Ok(build_policy_summary(&self.ctx)),
            "premier_env_schema" => Ok(build_env_schema_metadata(&self.ctx)),
            "premier_overlays_check" => tool_overlays_check(&self.ctx, arguments),
            "premier_policy_diff" => tool_policy_diff(&self.ctx, arguments),
            _ => return None,
        };
        Some(match result {
            Ok(payload) => tool_ok_result(&payload),
            Err(ToolCallError::InvalidParams(msg) | ToolCallError::Execution(msg)) => {
                tool_error_result(&msg)
            }
        })
    }

    fn list_resources(&self) -> Vec<Value> {
        builtin_resource_list()
    }

    fn read_resource(&self, uri: &str) -> Option<Value> {
        let payload = match uri {
            "premier://policy/summary" => build_policy_summary(&self.ctx),
            "premier://env/schema" => build_env_schema_metadata(&self.ctx),
            _ => return None,
        };
        let text = serialize_json(&payload);
        Some(json!({
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text
                }
            ]
        }))
    }
}

/// Load a persisted [`PinRegistrySnapshot`] from `pins_path` if present, or start empty.
pub fn load_pin_registry(pins_path: Option<&Path>) -> Result<Arc<ToolPinRegistry>> {
    let registry = ToolPinRegistry::new();
    if let Some(path) = pins_path
        && path.exists()
    {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read MCP pin registry {}", path.display()))?;
        if !raw.trim().is_empty() {
            let snap: PinRegistrySnapshot = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse MCP pin registry {}", path.display()))?;
            registry.restore(snap);
        }
    }
    Ok(Arc::new(registry))
}

/// Atomically persist `pins.snapshot()` to `pins_path` with private file permissions.
pub fn save_pin_registry(pins: &ToolPinRegistry, pins_path: &Path) -> Result<()> {
    if let Some(parent) = pins_path.parent()
        && !parent.as_os_str().is_empty()
    {
        premier_secrets::create_state_dir(parent)
            .with_context(|| format!("failed to create MCP pin directory {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(&pins.snapshot())
        .context("failed to serialize MCP pin registry snapshot")?;
    bytes.push(b'\n');

    let file_name = pins_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("mcp-pins.json");
    let tmp_path = pins_path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    premier_secrets::write_private(&tmp_path, &bytes).with_context(|| {
        format!(
            "failed to write temporary MCP pin registry {}",
            tmp_path.display()
        )
    })?;
    if let Err(rename_err) = std::fs::rename(&tmp_path, pins_path) {
        let _ = std::fs::remove_file(&tmp_path);
        premier_secrets::write_private(pins_path, &bytes).with_context(|| {
            format!(
                "failed to persist MCP pin registry {} (rename error: {rename_err})",
                pins_path.display()
            )
        })?;
    }
    Ok(())
}

fn request_may_update_pins(raw_line: &str) -> bool {
    let Ok(val) = serde_json::from_str::<Value>(raw_line) else {
        return false;
    };
    value_mentions_tools(&val)
}

fn value_mentions_tools(val: &Value) -> bool {
    match val {
        Value::Object(obj) => matches!(
            obj.get("method").and_then(Value::as_str),
            Some("tools/list" | "tools/call")
        ),
        Value::Array(items) => items.iter().any(value_mentions_tools),
        _ => false,
    }
}

/// Run the async newline-delimited JSON-RPC 2.0 unified MCP gateway over stdin/stdout.
///
/// Writes ONLY single-line JSON-RPC 2.0 responses followed by `\n` to `stdout`, flushing
/// after every response. All diagnostic logging goes strictly to `tracing` (`stderr`).
pub async fn run_stdio_gateway(
    gateway: &McpGateway,
    pins: &ToolPinRegistry,
    pins_path: Option<&Path>,
) -> Result<()> {
    tracing::info!(
        pins_path = ?pins_path.map(|p| p.display().to_string()),
        "starting premier-mcp-gateway JSON-RPC 2.0 stdio server"
    );

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut writer = tokio::io::BufWriter::new(tokio::io::stdout());

    while let Some(line) = lines
        .next_line()
        .await
        .context("failed to read line from stdin")?
    {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let may_touch_pins = request_may_update_pins(trimmed);
        if let Some(response) = gateway.handle_jsonrpc_line(trimmed).await {
            writer
                .write_all(response.as_bytes())
                .await
                .context("failed to write JSON-RPC response to stdout")?;
            writer
                .write_all(b"\n")
                .await
                .context("failed to write newline delimiter to stdout")?;
            writer.flush().await.context("failed to flush stdout")?;
        }
        if may_touch_pins
            && let Some(path) = pins_path
            && let Err(err) = save_pin_registry(pins, path)
        {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed to persist MCP pin registry snapshot"
            );
        }
    }

    tracing::info!("stdin closed; shutting down premier-mcp-gateway");
    Ok(())
}

fn tool_definitions() -> Value {
    Value::Array(builtin_tool_list())
}

fn builtin_tool_list() -> Vec<Value> {
    vec![
        json!({
            "name": "premier_access_explain",
            "description": "Explain effective Premier capabilities (traverse, list, read, write, use) for a repository path under the configured principal and agent profile (strictly enforcing permissions(human) ∩ permissions(agent_profile)).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repository-relative POSIX path (e.g. \"apps/web/src/main.ts\")."
                    },
                    "ref_name": {
                        "type": "string",
                        "description": "Optional branch/ref name (defaults to the configured branch)."
                    }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "premier_policy_summary",
            "description": "Return the compiled .access.toml policy fingerprint, zone and rule counts, declared agent profile names, and default permissions (no raw secrets).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "premier_env_schema",
            "description": "List declared .env.schema variables, sensitivity levels, required environments, allowed egress hosts/methods/paths, and the opaque placeholder prefix (premier_cap_v1_). Never exposes raw secret values or vault paths.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "premier_overlays_check",
            "description": "Check a list of repository paths against OverlayGuard to verify none would leak team or personal overlay files into public commits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "maxItems": MAX_MCP_PATHS,
                        "items": { "type": "string" },
                        "description": "Candidate repository-relative POSIX paths to validate."
                    }
                },
                "required": ["paths"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "premier_policy_diff",
            "description": "Read-only simulation computing an AccessImpactDiff between the active .access.toml and a proposed head_toml over the given paths strictly for the configured session identity (human ∩ agent_profile), preserving active server policy overrides.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "head_toml": {
                        "type": "string",
                        "maxLength": MAX_HEAD_TOML_BYTES,
                        "description": "Proposed .access.toml document text."
                    },
                    "paths": {
                        "type": "array",
                        "maxItems": MAX_MCP_PATHS,
                        "items": { "type": "string" },
                        "description": "Repository-relative POSIX paths to evaluate."
                    },
                    "changed_files": {
                        "type": "array",
                        "maxItems": MAX_MCP_CHANGED_FILES,
                        "items": { "type": "string" },
                        "description": "Optional changed file paths to evaluate against untrusted instruction-file quarantine rules."
                    },
                    "ref_name": {
                        "type": "string",
                        "description": "Optional branch/ref name (defaults to the configured branch)."
                    }
                },
                "required": ["head_toml", "paths"],
                "additionalProperties": false
            }
        }),
    ]
}

fn resource_definitions() -> Value {
    Value::Array(builtin_resource_list())
}

fn builtin_resource_list() -> Vec<Value> {
    vec![
        json!({
            "uri": "premier://policy/summary",
            "name": "Premier Policy Summary",
            "description": "Compiled policy fingerprint, zone/rule counts, agent profile names, and default permissions (no raw secrets).",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "premier://env/schema",
            "name": "Premier Environment Schema",
            "description": "Declared .env.schema variables, sensitivity levels, egress constraints, and placeholder prefix (no raw secrets or vault paths).",
            "mimeType": "application/json"
        }),
    ]
}

enum ToolCallError {
    InvalidParams(String),
    Execution(String),
}

fn validate_allowed_keys(
    args: &Map<String, Value>,
    allowed: &[&str],
) -> std::result::Result<(), ToolCallError> {
    for key in args.keys() {
        if !allowed.contains(&key.as_str()) {
            if FORBIDDEN_IDENTITY_KEYS.contains(&key.as_str()) {
                return Err(ToolCallError::InvalidParams(format!(
                    "Invalid params: identity override '{key}' is forbidden (additionalProperties: false): capabilities are strictly bound to configured human ∩ agent_profile"
                )));
            }
            return Err(ToolCallError::InvalidParams(format!(
                "Invalid params: unexpected argument '{key}' (additionalProperties: false)"
            )));
        }
    }
    Ok(())
}

fn handle_tools_call(ctx: &McpContext, id: Value, params: &Value) -> String {
    let Some(obj) = params.as_object() else {
        return jsonrpc_error(id, -32602, "Invalid params: expected object");
    };
    let Some(name) = obj.get("name").and_then(Value::as_str) else {
        return jsonrpc_error(id, -32602, "Invalid params: missing tool \"name\"");
    };
    let args = match obj.get("arguments") {
        None => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => {
            return jsonrpc_error(
                id,
                -32602,
                "Invalid params: \"arguments\" must be a JSON object",
            );
        }
    };

    let result = match name {
        "premier_access_explain" => tool_access_explain(ctx, &args),
        "premier_policy_summary" => {
            validate_allowed_keys(&args, &[]).map(|()| build_policy_summary(ctx))
        }
        "premier_env_schema" => {
            validate_allowed_keys(&args, &[]).map(|()| build_env_schema_metadata(ctx))
        }
        "premier_overlays_check" => tool_overlays_check(ctx, &args),
        "premier_policy_diff" => tool_policy_diff(ctx, &args),
        unknown => {
            return jsonrpc_error(
                id,
                -32602,
                &format!("Invalid params: unknown tool '{unknown}'"),
            );
        }
    };

    match result {
        Ok(payload) => jsonrpc_ok_response(id, tool_ok_result(&payload)),
        Err(ToolCallError::InvalidParams(msg)) => jsonrpc_error(id, -32602, &msg),
        Err(ToolCallError::Execution(msg)) => jsonrpc_ok_response(id, tool_error_result(&msg)),
    }
}

fn handle_resources_read(ctx: &McpContext, id: Value, params: &Value) -> String {
    let Some(uri) = params
        .as_object()
        .and_then(|o| o.get("uri"))
        .and_then(Value::as_str)
    else {
        return jsonrpc_error(id, -32602, "Invalid params: missing resource \"uri\"");
    };

    let payload = match uri {
        "premier://policy/summary" => build_policy_summary(ctx),
        "premier://env/schema" => build_env_schema_metadata(ctx),
        other => {
            return jsonrpc_error(id, -32002, &format!("Resource not found: {other}"));
        }
    };

    let text = serialize_json(&payload);
    jsonrpc_ok_response(
        id,
        json!({
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text
                }
            ]
        }),
    )
}

fn tool_access_explain(
    ctx: &McpContext,
    args: &Map<String, Value>,
) -> std::result::Result<Value, ToolCallError> {
    validate_allowed_keys(args, &["path", "ref_name"])?;

    let raw_path = args.get("path").and_then(Value::as_str).ok_or_else(|| {
        ToolCallError::InvalidParams("missing required string argument 'path'".to_owned())
    })?;
    let repo_path = RepoPath::new(raw_path)
        .map_err(|e| ToolCallError::Execution(format!("invalid path: {e}")))?;

    let ref_name = match args.get("ref_name") {
        None | Some(Value::Null) => ctx.default_branch.as_str(),
        Some(v) => v.as_str().ok_or_else(|| {
            ToolCallError::InvalidParams("argument 'ref_name' must be a string".to_owned())
        })?,
    };

    // Always evaluate strictly with the server-configured DelegatedIdentity.
    let decision = ctx
        .compiled_policy
        .explain(&ctx.identity, &repo_path, ref_name);

    Ok(json!({
        "path": decision.path,
        "ref_name": decision.ref_name,
        "principal": decision.principal,
        "agent_profile": decision.agent_profile,
        "effective": decision.effective.to_names(),
        "human_effective": decision.human_effective.to_names(),
        "agent_effective": decision.agent_effective.map(Capability::to_names),
        "synthesized_traverse": decision.synthesized_traverse,
        "matched_rules": decision.matched_rules
    }))
}

fn build_policy_summary(ctx: &McpContext) -> Value {
    let mut zone_names: BTreeSet<&str> = ctx
        .repo_policy_file
        .zones
        .keys()
        .map(String::as_str)
        .collect();
    if let Some(srv) = &ctx.server_policy_file {
        for z in srv.zones.keys() {
            zone_names.insert(z.as_str());
        }
    }

    let mut agent_profiles: BTreeSet<&str> = ctx
        .repo_policy_file
        .agent_profiles
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    if let Some(srv) = &ctx.server_policy_file {
        for p in &srv.agent_profiles {
            agent_profiles.insert(p.name.as_str());
        }
    }

    let repo_rule_count = ctx.repo_policy_file.rules.len();
    let server_rule_count = ctx.server_policy_file.as_ref().map_or(0, |s| s.rules.len());

    json!({
        "version": ctx.repo_policy_file.version,
        "fingerprint": ctx.policy_fingerprint,
        "has_server_policy": ctx.server_policy_file.is_some(),
        "zone_count": zone_names.len(),
        "zones": zone_names.into_iter().collect::<Vec<_>>(),
        "rule_count": repo_rule_count + server_rule_count,
        "repo_rule_count": repo_rule_count,
        "server_rule_count": server_rule_count,
        "agent_profiles": agent_profiles.into_iter().collect::<Vec<_>>(),
        "defaults": {
            "public": ctx.repo_policy_file.defaults.public,
            "authenticated": ctx.repo_policy_file.defaults.authenticated
        },
        "session": {
            "principal": ctx.identity.principal.canonical_id(),
            "groups": ctx.identity.groups,
            "agent_profile": ctx.identity.agent_task.as_ref().map(|a| a.profile.as_str()),
            "default_branch": ctx.default_branch
        }
    })
}

fn build_env_schema_metadata(ctx: &McpContext) -> Value {
    // CRITICAL (AGENTS.md Invariant 6): expose ONLY schema metadata — never raw secret
    // values, never process environment values, and never vault/key file paths.
    let variables: Vec<Value> = ctx
        .env_schema
        .vars
        .iter()
        .map(|(name, spec)| {
            let egress = spec.egress.as_ref().map(|e| {
                json!({
                    "hosts": e.hosts,
                    "methods": e.methods,
                    "path_prefixes": e.path_prefixes,
                    "approval": e.approval,
                    "rate_limit_per_min": e.rate_limit_per_min,
                    "jit_ttl_secs": e.jit_ttl_secs
                })
            });

            let can_use = ctx
                .compiled_policy
                .can_use_secret(
                    &ctx.identity,
                    name,
                    spec.zone.as_deref(),
                    &ctx.default_branch,
                )
                .allows(Capability::USE);

            let is_sensitive = matches!(
                spec.sensitivity,
                Sensitivity::Secret | Sensitivity::Restricted
            );

            json!({
                "name": name,
                "type": spec.var_type,
                "sensitivity": spec.sensitivity,
                "required_in": spec.required_in,
                "zone": spec.zone,
                "description": spec.description,
                "egress": egress,
                "proxy_capable": spec.egress.is_some(),
                "session_can_use": can_use,
                "raw_value_exposed": false,
                "has_public_default": !is_sensitive && spec.default.is_some()
            })
        })
        .collect();

    json!({
        "version": ctx.env_schema.version,
        "repo_id": ctx.env_schema.repo_id,
        "placeholder_prefix": PLACEHOLDER_PREFIX,
        "variable_count": variables.len(),
        "variables": variables
    })
}

fn tool_overlays_check(
    ctx: &McpContext,
    args: &Map<String, Value>,
) -> std::result::Result<Value, ToolCallError> {
    validate_allowed_keys(args, &["paths"])?;

    let raw_paths = args.get("paths").and_then(Value::as_array).ok_or_else(|| {
        ToolCallError::InvalidParams("missing required array argument 'paths'".to_owned())
    })?;

    if raw_paths.len() > MAX_MCP_PATHS {
        return Err(ToolCallError::InvalidParams(format!(
            "Invalid params: 'paths' exceeds maximum of {MAX_MCP_PATHS} entries"
        )));
    }

    let mut repo_paths = Vec::with_capacity(raw_paths.len());
    for (idx, item) in raw_paths.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            ToolCallError::InvalidParams(format!("paths[{idx}] must be a string"))
        })?;
        let rp = RepoPath::new(s)
            .map_err(|e| ToolCallError::Execution(format!("paths[{idx}] invalid: {e}")))?;
        repo_paths.push(rp);
    }

    match ctx.overlay_guard.validate_public_paths(&repo_paths) {
        Ok(()) => Ok(json!({
            "ok": true,
            "checked_count": repo_paths.len(),
            "blocked_paths": Vec::<String>::new(),
            "safe_paths": repo_paths.iter().map(ToString::to_string).collect::<Vec<_>>()
        })),
        Err(OverlayError::LeakBlocked { paths: blocked }) => {
            let blocked_set: BTreeSet<&str> = blocked.iter().map(String::as_str).collect();
            let safe: Vec<String> = repo_paths
                .iter()
                .map(ToString::to_string)
                .filter(|p| !blocked_set.contains(p.as_str()))
                .collect();
            Ok(json!({
                "ok": false,
                "checked_count": repo_paths.len(),
                "blocked_paths": blocked,
                "safe_paths": safe,
                "reason": "overlay files must never be committed or pushed to public Git history"
            }))
        }
        Err(other) => Err(ToolCallError::Execution(other.to_string())),
    }
}

fn tool_policy_diff(
    ctx: &McpContext,
    args: &Map<String, Value>,
) -> std::result::Result<Value, ToolCallError> {
    // Reject `principals` and any other identity overrides to prevent active-policy oracles.
    validate_allowed_keys(args, &["head_toml", "paths", "changed_files", "ref_name"])?;

    let head_toml = args
        .get("head_toml")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolCallError::InvalidParams("missing required string argument 'head_toml'".to_owned())
        })?;
    if head_toml.len() > MAX_HEAD_TOML_BYTES {
        return Err(ToolCallError::InvalidParams(format!(
            "Invalid params: 'head_toml' exceeds maximum size of {MAX_HEAD_TOML_BYTES} bytes"
        )));
    }

    let raw_paths = args.get("paths").and_then(Value::as_array).ok_or_else(|| {
        ToolCallError::InvalidParams("missing required array argument 'paths'".to_owned())
    })?;
    if raw_paths.len() > MAX_MCP_PATHS {
        return Err(ToolCallError::InvalidParams(format!(
            "Invalid params: 'paths' exceeds maximum of {MAX_MCP_PATHS} entries"
        )));
    }
    let mut repo_paths = Vec::with_capacity(raw_paths.len());
    for (idx, item) in raw_paths.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            ToolCallError::InvalidParams(format!("paths[{idx}] must be a string"))
        })?;
        let rp = RepoPath::new(s)
            .map_err(|e| ToolCallError::Execution(format!("paths[{idx}] invalid: {e}")))?;
        repo_paths.push(rp);
    }

    let ref_name = match args.get("ref_name") {
        None | Some(Value::Null) => ctx.default_branch.as_str(),
        Some(v) => v.as_str().ok_or_else(|| {
            ToolCallError::InvalidParams("argument 'ref_name' must be a string".to_owned())
        })?,
    };

    // Never read host files during simulation: quarantine checks receive `None` for bytes.
    let changed_files = match args.get("changed_files") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_MCP_CHANGED_FILES {
                return Err(ToolCallError::InvalidParams(format!(
                    "Invalid params: 'changed_files' exceeds maximum of {MAX_MCP_CHANGED_FILES} entries"
                )));
            }
            let mut out = Vec::with_capacity(arr.len());
            for (idx, item) in arr.iter().enumerate() {
                let s = item.as_str().ok_or_else(|| {
                    ToolCallError::InvalidParams(format!("changed_files[{idx}] must be a string"))
                })?;
                let rp = RepoPath::new(s).map_err(|e| {
                    ToolCallError::Execution(format!("changed_files[{idx}] invalid: {e}"))
                })?;
                out.push((rp, None));
            }
            out
        }
        Some(_) => {
            return Err(ToolCallError::InvalidParams(
                "argument 'changed_files' must be an array of strings".to_owned(),
            ));
        }
    };

    let head_file = parse_policy_toml(head_toml)
        .map_err(|e| ToolCallError::Execution(format!("failed to parse head_toml: {e}")))?;
    // Server policy overrides ALWAYS remain enforced during simulation.
    let head_compiled = CompiledPolicy::compile(ctx.server_policy_file.as_ref(), &head_file)
        .map_err(|e| ToolCallError::Execution(format!("failed to compile head_toml: {e}")))?;

    // Strictly evaluate ONLY the configured caller identity (`permissions(human) ∩ permissions(agent_profile)`).
    let identities = [ctx.identity.clone()];
    let diff = compute_access_diff(
        &ctx.compiled_policy,
        &head_compiled,
        &identities,
        &repo_paths,
        &changed_files,
        ref_name,
    );

    Ok(json!({
        "ref_name": diff.ref_name,
        "has_escalations": diff.has_escalations(),
        "deltas": diff.deltas,
        "quarantine_alerts": diff.quarantine_alerts
    }))
}

fn build_serve_args(opts: &McpConfigOptions<'_>) -> Vec<String> {
    let mut serve_args = vec!["mcp".to_owned(), "serve".to_owned()];
    if let Some(policy) = opts.policy {
        serve_args.push("--policy".to_owned());
        serve_args.push(policy.to_string_lossy().into_owned());
    }
    if let Some(server_policy) = opts.server_policy {
        serve_args.push("--server-policy".to_owned());
        serve_args.push(server_policy.to_string_lossy().into_owned());
    }
    if let Some(p) = opts.principal {
        serve_args.push("--principal".to_owned());
        serve_args.push(p.to_owned());
    }
    for group in opts.groups {
        serve_args.push("--group".to_owned());
        serve_args.push(group.clone());
    }
    if let Some(profile) = opts.agent_profile {
        serve_args.push("--agent-profile".to_owned());
        serve_args.push(profile.to_owned());
    }
    serve_args
}

/// POSIX single-quote shell escaping for safe copy-paste wrapper commands.
fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
                )
        })
    {
        return arg.to_owned();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Generate a strictly valid, directly parseable MCP client configuration (JSON for
/// Claude Code and Cursor, TOML for Codex). Never mixes shell comments or wrapper commands.
pub fn render_client_config(client: McpClient, opts: &McpConfigOptions<'_>) -> String {
    let serve_args = build_serve_args(opts);

    match client {
        McpClient::ClaudeCode => {
            let config = json!({
                "mcpServers": {
                    "premier": {
                        "type": "stdio",
                        "command": "premier",
                        "args": serve_args
                    }
                }
            });
            let pretty = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_owned());
            format!("{pretty}\n")
        }
        McpClient::Codex => {
            let mut premier_tbl = toml::Table::new();
            premier_tbl.insert(
                "command".to_owned(),
                toml::Value::String("premier".to_owned()),
            );
            premier_tbl.insert(
                "args".to_owned(),
                toml::Value::Array(serve_args.into_iter().map(toml::Value::String).collect()),
            );
            let mut mcp_servers = toml::Table::new();
            mcp_servers.insert("premier".to_owned(), toml::Value::Table(premier_tbl));
            let mut root = toml::Table::new();
            root.insert("mcp_servers".to_owned(), toml::Value::Table(mcp_servers));
            toml::to_string_pretty(&root).unwrap_or_default()
        }
        McpClient::Cursor => {
            let config = json!({
                "mcpServers": {
                    "premier": {
                        "command": "premier",
                        "args": serve_args
                    }
                }
            });
            let pretty = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_owned());
            format!("{pretty}\n")
        }
    }
}

/// Generate the shell-quoted `premier agent run` capability-proxied wrapper command
/// matching the configured MCP client options (always passing `--policy`).
pub fn render_agent_wrapper(client: McpClient, opts: &McpConfigOptions<'_>) -> String {
    let policy_arg = opts
        .policy
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".access.toml".to_owned());
    let wrapper_profile = opts.agent_profile.unwrap_or("default-agent");

    let mut parts = vec![
        "premier".to_owned(),
        "agent".to_owned(),
        "run".to_owned(),
        "--policy".to_owned(),
        policy_arg,
    ];
    if let Some(sp) = opts.server_policy {
        parts.push("--server-policy".to_owned());
        parts.push(sp.to_string_lossy().into_owned());
    }
    if let Some(p) = opts.principal {
        parts.push("--principal".to_owned());
        parts.push(p.to_owned());
    }
    for group in opts.groups {
        parts.push("--group".to_owned());
        parts.push(group.clone());
    }
    parts.push("--profile".to_owned());
    parts.push(wrapper_profile.to_owned());
    parts.push("--".to_owned());
    parts.push(
        match client {
            McpClient::ClaudeCode => "claude",
            McpClient::Codex => "codex",
            McpClient::Cursor => "cursor-agent",
        }
        .to_owned(),
    );

    parts
        .iter()
        .map(|p| shell_quote(p))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate a ready-to-paste unified MCP gateway client configuration (JSON or TOML) and
/// the corresponding `premier agent run` capability-proxied wrapper command.
pub fn render_gateway_client_config(
    client: McpClient,
    agent_profile: Option<&str>,
    principal: Option<&str>,
    env: Option<&str>,
    backend: Option<&str>,
    server_policy: Option<&str>,
) -> String {
    let mut gateway_args = vec!["mcp".to_owned(), "gateway".to_owned()];
    if let Some(p) = principal {
        gateway_args.push("--principal".to_owned());
        gateway_args.push(p.to_owned());
    }
    if let Some(profile) = agent_profile {
        gateway_args.push("--agent-profile".to_owned());
        gateway_args.push(profile.to_owned());
    }
    if let Some(e) = env {
        gateway_args.push("--env".to_owned());
        gateway_args.push(e.to_owned());
    }
    let effective_backend = backend.unwrap_or("age");
    gateway_args.push("--backend".to_owned());
    gateway_args.push(effective_backend.to_owned());
    if let Some(sp) = server_policy {
        gateway_args.push("--server-policy".to_owned());
        gateway_args.push(sp.to_owned());
    }

    let wrapper_profile = agent_profile.unwrap_or("default-agent");
    let mut wrapper_parts = vec!["premier".to_owned(), "agent".to_owned(), "run".to_owned()];
    if let Some(p) = principal {
        wrapper_parts.push("--principal".to_owned());
        wrapper_parts.push(p.to_owned());
    }
    wrapper_parts.push("--profile".to_owned());
    wrapper_parts.push(wrapper_profile.to_owned());
    if let Some(e) = env {
        wrapper_parts.push("--env".to_owned());
        wrapper_parts.push(e.to_owned());
    }
    wrapper_parts.push("--backend".to_owned());
    wrapper_parts.push(effective_backend.to_owned());
    if let Some(sp) = server_policy {
        wrapper_parts.push("--server-policy".to_owned());
        wrapper_parts.push(sp.to_owned());
    }
    wrapper_parts.push("--".to_owned());

    match client {
        McpClient::ClaudeCode => {
            wrapper_parts.push("claude".to_owned());
            let config = json!({
                "mcpServers": {
                    "premier-gateway": {
                        "command": "premier",
                        "args": gateway_args
                    }
                }
            });
            let pretty = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_owned());
            format!(
                "# Claude Code unified MCP gateway config (.mcp.json or ~/.claude.json)\n{pretty}\n\n# Launch Claude Code inside Premier's capability-proxied cage (use != read):\n{}\n",
                wrapper_parts.join(" ")
            )
        }
        McpClient::Codex => {
            wrapper_parts.push("codex".to_owned());
            let quoted_args: Vec<String> = gateway_args
                .iter()
                .map(|a| serde_json::to_string(a).unwrap_or_else(|_| format!("\"{a}\"")))
                .collect();
            format!(
                "# Codex CLI unified MCP gateway config (~/.codex/config.toml)\n[mcp_servers.premier_gateway]\ncommand = \"premier\"\nargs = [{}]\n\n# Launch Codex inside Premier's capability-proxied cage (use != read):\n{}\n",
                quoted_args.join(", "),
                wrapper_parts.join(" ")
            )
        }
        McpClient::Cursor => {
            wrapper_parts.push("cursor-agent".to_owned());
            let config = json!({
                "mcpServers": {
                    "premier-gateway": {
                        "command": "premier",
                        "args": gateway_args
                    }
                }
            });
            let pretty = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_owned());
            format!(
                "# Cursor unified MCP gateway config (.cursor/mcp.json)\n{pretty}\n\n# Launch Cursor agent inside Premier's capability-proxied cage (use != read):\n{}\n",
                wrapper_parts.join(" ")
            )
        }
    }
}

/// Parse `.premier/overlays.toml` (or JSON manifest) into an `OverlayManifest`.
///
/// Uses `toml::from_str` for full TOML spec compliance, supporting `[[entries]]` and
/// `[[overlays]]` tables with `path = "..."`, `paths = [...]`, `kind = "personal" | "team:<name>"`,
/// and `encrypted = true|false`, as well as JSON manifests.
pub fn parse_overlay_manifest(input: &str) -> Result<OverlayManifest> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(OverlayManifest::default());
    }
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed).context("invalid JSON overlay manifest");
    }

    let table: toml::Table = toml::from_str(trimmed).context("invalid TOML overlay manifest")?;

    let mut manifest = OverlayManifest {
        version: 1,
        entries: Vec::new(),
    };

    if let Some(v) = table.get("version") {
        let ver = v
            .as_integer()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| anyhow::anyhow!("invalid 'version' in overlay manifest"))?;
        manifest.version = ver;
    }

    if let Some(p) = table.get("path") {
        let s = p
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("top-level 'path' must be a string"))?;
        manifest.entries.push(OverlayEntry {
            kind: OverlayKind::Personal,
            path: s.to_owned(),
            encrypted: false,
        });
    }

    if let Some(ps) = table.get("paths") {
        for s in parse_toml_value_string_array(ps, "paths")? {
            manifest.entries.push(OverlayEntry {
                kind: OverlayKind::Personal,
                path: s,
                encrypted: false,
            });
        }
    }

    for array_key in ["entries", "overlays"] {
        let Some(val) = table.get(array_key) else {
            continue;
        };
        let items = val
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("'{array_key}' must be an array of tables"))?;
        for (idx, item) in items.iter().enumerate() {
            let entry_tbl = item
                .as_table()
                .ok_or_else(|| anyhow::anyhow!("{array_key}[{idx}] must be a table"))?;
            let kind = match entry_tbl.get("kind") {
                None => OverlayKind::Personal,
                Some(kval) => parse_overlay_kind_toml(kval, &format!("{array_key}[{idx}].kind"))?,
            };
            let encrypted = match entry_tbl.get("encrypted") {
                None => false,
                Some(b) => b.as_bool().ok_or_else(|| {
                    anyhow::anyhow!("{array_key}[{idx}].encrypted must be a boolean")
                })?,
            };

            let mut entry_paths = Vec::new();
            if let Some(p) = entry_tbl.get("path") {
                let s = p
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{array_key}[{idx}].path must be a string"))?;
                entry_paths.push(s.to_owned());
            }
            if let Some(ps) = entry_tbl.get("paths") {
                entry_paths.extend(parse_toml_value_string_array(
                    ps,
                    &format!("{array_key}[{idx}].paths"),
                )?);
            }
            for p in entry_paths {
                manifest.entries.push(OverlayEntry {
                    kind: kind.clone(),
                    path: p,
                    encrypted,
                });
            }
        }
    }

    Ok(manifest)
}

fn parse_toml_value_string_array(val: &toml::Value, field: &str) -> Result<Vec<String>> {
    let arr = val
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'{field}' must be an array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{field}[{idx}] must be a string"))?;
        out.push(s.to_owned());
    }
    Ok(out)
}

fn parse_overlay_kind_toml(val: &toml::Value, field: &str) -> Result<OverlayKind> {
    if let Some(s) = val.as_str() {
        if let Some(team) = s.strip_prefix("team:") {
            return Ok(OverlayKind::Team(team.to_owned()));
        }
        if s.eq_ignore_ascii_case("personal") {
            return Ok(OverlayKind::Personal);
        }
        return Ok(OverlayKind::Team(s.to_owned()));
    }
    if let Some(tbl) = val.as_table() {
        let tag = tbl
            .get("kind")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{field}.kind must be a string"))?;
        return match tag {
            "personal" => Ok(OverlayKind::Personal),
            "team" => {
                let name = tbl
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("{field}.name must be a string"))?;
                Ok(OverlayKind::Team(name.to_owned()))
            }
            other => bail!("{field}: unknown overlay kind '{other}'"),
        };
    }
    bail!("{field} must be a string or table")
}

fn tool_ok_result(payload: &Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serialize_json(payload)
            }
        ],
        "isError": false
    })
}

fn tool_error_result(message: &str) -> Value {
    let payload = json!({ "error": message });
    json!({
        "content": [
            {
                "type": "text",
                "text": serialize_json(&payload)
            }
        ],
        "isError": true
    })
}

fn jsonrpc_ok_response(id: Value, result: Value) -> String {
    serialize_json(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> String {
    serialize_json(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    }))
}

fn serialize_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const TEST_POLICY_TOML: &str = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.billing]
paths = ["billing/**"]
owners = ["@alice"]

[zones.web]
paths = ["apps/web/**"]

[[rules]]
id = "deny-billing-everyone"
effect = "deny"
principals = ["*"]
zones = ["billing"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Billing is restricted"

[[rules]]
id = "allow-web-write"
effect = "allow"
principals = ["@alice"]
zones = ["web"]
capabilities = ["traverse", "list", "read", "write"]

[[rules]]
id = "allow-stripe-use"
effect = "allow"
principals = ["@alice"]
paths = ["secrets/billing/STRIPE_API_KEY"]
capabilities = ["use"]

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/web/**", "README.md", ".access.toml"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_API_KEY"]
allow_egress_hosts = ["registry.npmjs.org"]
"#;

    const TEST_SERVER_POLICY_TOML: &str = r#"
version = 1

[[rules]]
id = "server-hard-deny-keys"
effect = "deny"
principals = ["*"]
paths = ["apps/web/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Server hard deny"
"#;

    const TEST_SCHEMA_TOML: &str = r#"
version = 1
repo_id = "acme/web"

[vars.PUBLIC_API_URL]
type = "url"
sensitivity = "public"
required_in = ["dev", "prod"]
default = "https://api.acme.test"
description = "Public frontend API base URL"

[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "restricted"
required_in = ["staging", "prod"]
zone = "billing"
description = "Stripe secret API key (use via proxy only)"

[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
approval = "jit"
rate_limit_per_min = 30
"#;

    const TEST_OVERLAYS_TOML: &str = r#"
version = 1

[[entries]]
kind = "team:frontend"
path = ".run/**"
encrypted = false

[[entries]]
kind = "personal"
paths = [
  ".vscode/launch.json",
  "notes,local.md",
  "notes.local.md",
]
"#;

    fn make_test_ctx(agent_profile: Option<&str>) -> McpContext {
        let schema = EnvSchema::parse_toml(TEST_SCHEMA_TOML).unwrap();
        let manifest = parse_overlay_manifest(TEST_OVERLAYS_TOML).unwrap();
        let principal = Principal::parse("@alice").unwrap();
        let identity = match agent_profile {
            Some(prof) => DelegatedIdentity::delegated(principal, vec![], prof, "test-task"),
            None => DelegatedIdentity::human_only(principal, vec![]),
        };
        McpContext::new(
            TEST_POLICY_TOML,
            Some(TEST_SERVER_POLICY_TOML),
            schema,
            &manifest,
            identity,
            "main".to_owned(),
        )
        .unwrap()
    }

    fn call_rpc(ctx: &McpContext, req: Value) -> Value {
        let line = serde_json::to_string(&req).unwrap();
        let out = handle_jsonrpc_line(ctx, &line).unwrap();
        serde_json::from_str(&out).unwrap()
    }

    fn parse_tool_text(resp: &Value) -> (Value, bool) {
        let result = &resp["result"];
        let is_error = result["isError"].as_bool().unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        (serde_json::from_str(text).unwrap(), is_error)
    }

    #[test]
    fn initialize_negotiates_protocol_version_and_handles_notifications() {
        let ctx = make_test_ctx(Some("ui-agent"));

        // Supported versions are echoed back verbatim.
        for version in SUPPORTED_MCP_PROTOCOL_VERSIONS {
            let init = call_rpc(
                &ctx,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": { "protocolVersion": version }
                }),
            );
            assert_eq!(init["jsonrpc"], "2.0");
            assert_eq!(init["id"], 1);
            assert_eq!(init["result"]["protocolVersion"], *version);
            assert_eq!(init["result"]["serverInfo"]["name"], "premier-mcp");
            assert!(init["result"]["capabilities"]["tools"].is_object());
            assert!(init["result"]["capabilities"]["resources"].is_object());
        }

        // Unsupported or omitted protocolVersion falls back to MCP_PROTOCOL_VERSION.
        let fallback = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": { "protocolVersion": "1999-01-01" }
            }),
        );
        assert_eq!(fallback["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        let omitted = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {}
            }),
        );
        assert_eq!(omitted["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        // Notifications with no id produce no output.
        let notif = handle_jsonrpc_line(
            &ctx,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        assert!(notif.is_none());

        // Blank lines are ignored.
        assert!(handle_jsonrpc_line(&ctx, "   ").is_none());

        // Ping returns empty object.
        let ping = call_rpc(
            &ctx,
            json!({ "jsonrpc": "2.0", "id": "p-1", "method": "ping" }),
        );
        assert_eq!(ping["id"], "p-1");
        assert_eq!(ping["result"], json!({}));
    }

    #[test]
    fn strict_jsonrpc_id_validation_rejects_non_string_or_number() {
        let ctx = make_test_ctx(None);

        for bad_id in [json!(null), json!(true), json!([1, 2]), json!({"a": 1})] {
            let resp = call_rpc(
                &ctx,
                json!({
                    "jsonrpc": "2.0",
                    "id": bad_id,
                    "method": "ping"
                }),
            );
            assert_eq!(resp["error"]["code"], -32600);
            assert_eq!(resp["id"], Value::Null);
        }
    }

    #[test]
    fn invalid_tool_name_non_object_args_and_extra_keys_return_32602() {
        let ctx = make_test_ctx(Some("ui-agent"));

        // Unknown tool name -> -32602 Invalid params.
        let unknown = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": { "name": "premier_does_not_exist", "arguments": {} }
            }),
        );
        assert_eq!(unknown["error"]["code"], -32602);
        assert!(unknown.get("result").is_none());

        // Non-object arguments -> -32602 Invalid params.
        for bad_args in [
            json!(null),
            json!(["a"]),
            json!("str"),
            json!(42),
            json!(true),
        ] {
            let resp = call_rpc(
                &ctx,
                json!({
                    "jsonrpc": "2.0",
                    "id": 101,
                    "method": "tools/call",
                    "params": { "name": "premier_policy_summary", "arguments": bad_args }
                }),
            );
            assert_eq!(resp["error"]["code"], -32602);
        }

        // Unexpected key violating additionalProperties: false -> -32602 Invalid params.
        let extra_key = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {
                    "name": "premier_policy_summary",
                    "arguments": { "bogus": 1 }
                }
            }),
        );
        assert_eq!(extra_key["error"]["code"], -32602);
    }

    #[test]
    fn tools_list_advertises_all_five_tools() {
        let ctx = make_test_ctx(Some("ui-agent"));
        let resp = call_rpc(
            &ctx,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        );
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "premier_access_explain",
                "premier_policy_summary",
                "premier_env_schema",
                "premier_overlays_check",
                "premier_policy_diff",
            ]
        );
        // Ensure `principals` is not advertised in premier_policy_diff schema.
        let diff_tool = tools
            .iter()
            .find(|t| t["name"] == "premier_policy_diff")
            .unwrap();
        assert!(
            diff_tool["inputSchema"]["properties"]
                .get("principals")
                .is_none()
        );
    }

    #[test]
    fn access_explain_enforces_human_intersect_agent_and_blocks_escalation() {
        let ctx = make_test_ctx(Some("ui-agent"));

        // Allowed path for both @alice and ui-agent.
        let resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "premier_access_explain",
                    "arguments": { "path": "apps/web/index.ts" }
                }
            }),
        );
        let (body, is_err) = parse_tool_text(&resp);
        assert!(!is_err);
        assert_eq!(body["principal"], "@alice");
        assert_eq!(body["agent_profile"], "ui-agent");
        assert_eq!(
            body["effective"],
            json!(["traverse", "list", "read", "write"])
        );

        // Protected file: `.access.toml` WRITE is stripped for repo-layer agent profiles.
        let resp_protected = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "premier_access_explain",
                    "arguments": { "path": ".access.toml" }
                }
            }),
        );
        let (body_p, is_err_p) = parse_tool_text(&resp_protected);
        assert!(!is_err_p);
        let eff_p: Vec<&str> = body_p["effective"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(eff_p.contains(&"read"));
        assert!(!eff_p.contains(&"write"));

        // Server hard deny overrides everything on `apps/web/master.key`.
        let resp_key = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "premier_access_explain",
                    "arguments": { "path": "apps/web/master.key" }
                }
            }),
        );
        let (body_k, is_err_k) = parse_tool_text(&resp_key);
        assert!(!is_err_k);
        assert_eq!(body_k["effective"], json!([]));

        // Attempting to override principal or agent_profile is rejected with -32602.
        let resp_esc = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "premier_access_explain",
                    "arguments": { "path": "billing/ledger.rs", "principal": "@owner" }
                }
            }),
        );
        assert_eq!(resp_esc["error"]["code"], -32602);
        assert!(
            resp_esc["error"]["message"]
                .as_str()
                .unwrap()
                .contains("forbidden")
        );
    }

    #[test]
    fn policy_summary_returns_fingerprint_counts_profiles_and_defaults() {
        let ctx = make_test_ctx(Some("ui-agent"));
        let resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": { "name": "premier_policy_summary", "arguments": {} }
            }),
        );
        let (body, is_err) = parse_tool_text(&resp);
        assert!(!is_err);
        assert_eq!(body["fingerprint"].as_str().unwrap().len(), 64);
        assert_eq!(body["has_server_policy"], true);
        assert_eq!(body["zone_count"], 2);
        assert_eq!(body["rule_count"], 4);
        assert_eq!(body["repo_rule_count"], 3);
        assert_eq!(body["server_rule_count"], 1);
        assert_eq!(body["agent_profiles"], json!(["ui-agent"]));
        assert_eq!(
            body["defaults"]["public"],
            json!(["traverse", "list", "read"])
        );
    }

    #[test]
    fn env_schema_exposes_metadata_and_zero_raw_secrets_or_vault_paths() {
        // Put a canary secret in the process environment; MCP must NEVER read or return it.
        let canary = "sk_live_SUPER_SECRET_CANARY_99999";
        let ctx = make_test_ctx(Some("ui-agent"));
        let resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": { "name": "premier_env_schema", "arguments": {} }
            }),
        );
        let raw_response = serde_json::to_string(&resp).unwrap();
        assert!(!raw_response.contains(canary));
        assert!(!raw_response.contains("vault.toml"));
        assert!(!raw_response.contains("age.key"));

        let (body, is_err) = parse_tool_text(&resp);
        assert!(!is_err);
        assert_eq!(body["placeholder_prefix"], "premier_cap_v1_");
        assert_eq!(body["variable_count"], 2);

        let vars = body["variables"].as_array().unwrap();
        let stripe = vars.iter().find(|v| v["name"] == "STRIPE_API_KEY").unwrap();
        assert_eq!(stripe["sensitivity"], "restricted");
        assert_eq!(stripe["required_in"], json!(["staging", "prod"]));
        assert_eq!(stripe["egress"]["hosts"], json!(["api.stripe.com"]));
        assert_eq!(stripe["egress"]["methods"], json!(["GET", "POST"]));
        assert_eq!(stripe["egress"]["path_prefixes"], json!(["/v1/"]));
        assert_eq!(stripe["raw_value_exposed"], false);
        assert_eq!(stripe["session_can_use"], true);
        assert!(stripe.get("value").is_none());
        assert!(stripe.get("secret").is_none());
        assert!(stripe.get("vault").is_none());
    }

    #[test]
    fn overlays_check_blocks_default_and_manifest_overlay_files() {
        let ctx = make_test_ctx(Some("ui-agent"));

        // Safe paths pass.
        let ok_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 40,
                "method": "tools/call",
                "params": {
                    "name": "premier_overlays_check",
                    "arguments": { "paths": ["apps/web/src/app.tsx", "README.md"] }
                }
            }),
        );
        let (ok_body, ok_err) = parse_tool_text(&ok_resp);
        assert!(!ok_err);
        assert_eq!(ok_body["ok"], true);
        assert_eq!(ok_body["blocked_paths"], json!([]));

        // Default overlay (`AGENTS.local.md`) and manifest overlays (including commas in multiline TOML) are blocked.
        let leak_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "premier_overlays_check",
                    "arguments": {
                        "paths": [
                            "apps/web/src/app.tsx",
                            "AGENTS.local.md",
                            ".run/debug.xml",
                            "notes,local.md",
                            "notes.local.md"
                        ]
                    }
                }
            }),
        );
        let (leak_body, leak_err) = parse_tool_text(&leak_resp);
        assert!(!leak_err);
        assert_eq!(leak_body["ok"], false);
        assert_eq!(
            leak_body["blocked_paths"],
            json!([
                "AGENTS.local.md",
                ".run/debug.xml",
                "notes,local.md",
                "notes.local.md"
            ])
        );
        assert_eq!(leak_body["safe_paths"], json!(["apps/web/src/app.tsx"]));

        // Traversal path fails with isError: true.
        let bad_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "premier_overlays_check",
                    "arguments": { "paths": ["../etc/passwd"] }
                }
            }),
        );
        let (_bad_body, bad_err) = parse_tool_text(&bad_resp);
        assert!(bad_err);

        // Exceeding MAX_MCP_PATHS returns -32602.
        let too_many: Vec<String> = (0..=MAX_MCP_PATHS)
            .map(|i| format!("file_{i}.rs"))
            .collect();
        let cap_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 43,
                "method": "tools/call",
                "params": {
                    "name": "premier_overlays_check",
                    "arguments": { "paths": too_many }
                }
            }),
        );
        assert_eq!(cap_resp["error"]["code"], -32602);
    }

    #[test]
    fn policy_diff_blocks_identity_oracle_and_preserves_server_overrides() {
        let ctx = make_test_ctx(None);

        // Proposed policy drops deny-billing-everyone and tries to grant master.key.
        let proposed_toml = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[[rules]]
id = "try-allow-master-key"
effect = "allow"
principals = ["@alice"]
paths = ["apps/web/master.key"]
capabilities = ["read", "write"]
"#;

        // Caller-supplied `principals` is forbidden (closes active-policy identity oracle).
        let oracle_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 49,
                "method": "tools/call",
                "params": {
                    "name": "premier_policy_diff",
                    "arguments": {
                        "head_toml": proposed_toml,
                        "paths": ["billing/invoices.csv"],
                        "principals": ["@bob", "anonymous"]
                    }
                }
            }),
        );
        assert_eq!(oracle_resp["error"]["code"], -32602);
        assert!(
            oracle_resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("forbidden")
        );

        // Valid diff evaluates strictly for configured caller identity (`@alice`).
        let resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 50,
                "method": "tools/call",
                "params": {
                    "name": "premier_policy_diff",
                    "arguments": {
                        "head_toml": proposed_toml,
                        "paths": ["billing/invoices.csv", "apps/web/master.key"],
                        "changed_files": ["AGENTS.md"]
                    }
                }
            }),
        );
        let (body, is_err) = parse_tool_text(&resp);
        assert!(!is_err);
        assert_eq!(body["has_escalations"], true);

        // Billing access escalated for @alice, while server hard-deny kept apps/web/master.key unchanged.
        let deltas = body["deltas"].as_array().unwrap();
        assert!(
            deltas.iter().all(|d| d["principal"] == "@alice"),
            "all diff deltas must evaluate strictly under the configured session identity"
        );
        assert!(
            deltas
                .iter()
                .any(|d| d["path"] == "billing/invoices.csv" && d["principal"] == "@alice")
        );
        assert!(
            !deltas.iter().any(|d| d["path"] == "apps/web/master.key"),
            "server policy hard deny must remain enforced during diff simulation"
        );
        // Unpinned AGENTS.md triggers quarantine alert.
        assert_eq!(body["quarantine_alerts"].as_array().unwrap().len(), 1);

        // Oversized head_toml (> 256 KiB) is rejected with -32602.
        let huge_toml = "a".repeat(MAX_HEAD_TOML_BYTES + 1);
        let huge_resp = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 51,
                "method": "tools/call",
                "params": {
                    "name": "premier_policy_diff",
                    "arguments": {
                        "head_toml": huge_toml,
                        "paths": ["README.md"]
                    }
                }
            }),
        );
        assert_eq!(huge_resp["error"]["code"], -32602);
    }

    #[test]
    fn resources_list_and_read_expose_policy_and_schema_without_secrets() {
        let ctx = make_test_ctx(Some("ui-agent"));

        let list = call_rpc(
            &ctx,
            json!({ "jsonrpc": "2.0", "id": 60, "method": "resources/list" }),
        );
        let resources = list["result"]["resources"].as_array().unwrap();
        let uris: Vec<&str> = resources
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert_eq!(
            uris,
            vec!["premier://policy/summary", "premier://env/schema"]
        );

        let policy_res = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 61,
                "method": "resources/read",
                "params": { "uri": "premier://policy/summary" }
            }),
        );
        let policy_text = policy_res["result"]["contents"][0]["text"]
            .as_str()
            .unwrap();
        let policy_json: Value = serde_json::from_str(policy_text).unwrap();
        assert_eq!(policy_json["zone_count"], 2);

        let schema_res = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 62,
                "method": "resources/read",
                "params": { "uri": "premier://env/schema" }
            }),
        );
        let schema_text = schema_res["result"]["contents"][0]["text"]
            .as_str()
            .unwrap();
        let schema_json: Value = serde_json::from_str(schema_text).unwrap();
        assert_eq!(schema_json["placeholder_prefix"], "premier_cap_v1_");
        assert!(!schema_text.contains("vault.toml"));

        // Unknown URI returns -32002 Resource not found.
        let missing = call_rpc(
            &ctx,
            json!({
                "jsonrpc": "2.0",
                "id": 63,
                "method": "resources/read",
                "params": { "uri": "premier://secrets/raw" }
            }),
        );
        assert_eq!(missing["error"]["code"], -32002);
    }

    #[test]
    fn invalid_method_and_malformed_json_return_jsonrpc_errors() {
        let ctx = make_test_ctx(None);

        let bad_method = call_rpc(
            &ctx,
            json!({ "jsonrpc": "2.0", "id": 70, "method": "nonexistent/method" }),
        );
        assert_eq!(bad_method["error"]["code"], -32601);

        let bad_json = handle_jsonrpc_line(&ctx, "{not valid json").unwrap();
        let parsed: Value = serde_json::from_str(&bad_json).unwrap();
        assert_eq!(parsed["error"]["code"], -32700);
    }

    #[test]
    fn stdio_loop_caps_oversized_lines_and_recovers() {
        let ctx = make_test_ctx(None);
        let oversized = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{}\"}}\n",
            "x".repeat(512)
        );
        let valid = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let input = format!("{oversized}{valid}");

        let mut out = Vec::new();
        run_stdio_loop(&ctx, Cursor::new(input.as_bytes()), &mut out, 128).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["error"]["code"], -32600);

        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["id"], 2);
        assert_eq!(second["result"], json!({}));
    }

    #[test]
    fn load_workspace_overlays_merges_state_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let premier_dir = root.join(".premier");
        std::fs::create_dir_all(&premier_dir).unwrap();

        let state = premier_server::store::PersistedState {
            overlays: OverlayManifest {
                version: 1,
                entries: vec![OverlayEntry {
                    kind: OverlayKind::Personal,
                    path: "scratch/private.txt".to_owned(),
                    encrypted: false,
                }],
            },
            ..Default::default()
        };
        std::fs::write(
            premier_dir.join("state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .unwrap();

        let manifest = load_workspace_overlays(&premier_dir.join("overlays.toml"), root).unwrap();
        let guard = OverlayGuard::from_manifest(&manifest).unwrap();
        assert!(guard.is_overlay_path(&RepoPath::new("scratch/private.txt").unwrap()));
    }

    #[test]
    fn render_client_configs_are_strictly_parseable_json_and_toml() {
        let groups = vec!["billing".to_owned(), "web team".to_owned()];
        let opts = McpConfigOptions {
            agent_profile: Some("ui-agent"),
            principal: Some("@alice"),
            groups: &groups,
            policy: Some(Path::new("custom policy/.access.toml")),
            server_policy: Some(Path::new("/etc/premier/server.toml")),
        };

        // Claude Code outputs strictly valid JSON with "type": "stdio".
        let claude = render_client_config(McpClient::ClaudeCode, &opts);
        let claude_json: Value = serde_json::from_str(&claude).unwrap();
        assert_eq!(claude_json["mcpServers"]["premier"]["type"], "stdio");
        assert_eq!(claude_json["mcpServers"]["premier"]["command"], "premier");
        let claude_args = claude_json["mcpServers"]["premier"]["args"]
            .as_array()
            .unwrap();
        assert!(claude_args.contains(&json!("--group")));
        assert!(claude_args.contains(&json!("billing")));
        assert!(claude_args.contains(&json!("--policy")));
        assert!(claude_args.contains(&json!("custom policy/.access.toml")));
        assert!(claude_args.contains(&json!("--server-policy")));
        assert!(claude_args.contains(&json!("/etc/premier/server.toml")));

        // Codex outputs strictly valid TOML parseable by `toml::from_str`.
        let codex = render_client_config(McpClient::Codex, &opts);
        let codex_toml: toml::Value = toml::from_str(&codex).unwrap();
        assert_eq!(
            codex_toml["mcp_servers"]["premier"]["command"].as_str(),
            Some("premier")
        );
        assert!(codex_toml["mcp_servers"]["premier"]["args"].is_array());

        // Cursor outputs strictly valid JSON.
        let cursor = render_client_config(McpClient::Cursor, &McpConfigOptions::default());
        let cursor_json: Value = serde_json::from_str(&cursor).unwrap();
        assert_eq!(cursor_json["mcpServers"]["premier"]["command"], "premier");

        // Wrapper command includes `--policy` and shell-quotes arguments with spaces.
        let wrapper = render_agent_wrapper(McpClient::ClaudeCode, &opts);
        assert!(wrapper.contains("--policy 'custom policy/.access.toml'"));
        assert!(wrapper.contains("--server-policy /etc/premier/server.toml"));
        assert!(wrapper.contains("--group billing"));
        assert!(wrapper.contains("--group 'web team'"));
        assert!(wrapper.contains("--profile ui-agent -- claude"));

        let default_wrapper = render_agent_wrapper(McpClient::Cursor, &McpConfigOptions::default());
        assert_eq!(
            default_wrapper,
            "premier agent run --policy .access.toml --profile default-agent -- cursor-agent"
        );
    }

    #[test]
    fn render_gateway_client_configs_for_all_three_clients() {
        let claude = render_gateway_client_config(
            McpClient::ClaudeCode,
            Some("ui-agent"),
            Some("@alice"),
            Some("staging"),
            Some("age"),
            Some("org.access.toml"),
        );
        assert!(claude.contains("\"mcpServers\""));
        assert!(claude.contains("\"premier-gateway\""));
        assert!(claude.contains("\"mcp\""));
        assert!(claude.contains("\"gateway\""));
        assert!(claude.contains("\"--agent-profile\""));
        assert!(claude.contains("\"ui-agent\""));
        assert!(claude.contains("\"--env\""));
        assert!(claude.contains("\"staging\""));
        assert!(claude.contains("\"--backend\""));
        assert!(claude.contains("\"age\""));
        assert!(claude.contains("\"--server-policy\""));
        assert!(claude.contains("\"org.access.toml\""));
        assert!(claude.contains(
            "premier agent run --principal @alice --profile ui-agent --env staging --backend age --server-policy org.access.toml -- claude"
        ));

        let codex = render_gateway_client_config(
            McpClient::Codex,
            Some("ci-triage"),
            Some("@bob"),
            Some("dev"),
            Some("keychain"),
            None,
        );
        assert!(codex.contains("[mcp_servers.premier_gateway]"));
        assert!(codex.contains("command = \"premier\""));
        assert!(codex.contains("\"mcp\", \"gateway\""));
        assert!(codex.contains(
            "premier agent run --principal @bob --profile ci-triage --env dev --backend keychain -- codex"
        ));

        let cursor = render_gateway_client_config(McpClient::Cursor, None, None, None, None, None);
        assert!(cursor.contains("\"mcpServers\""));
        assert!(cursor.contains("\"premier-gateway\""));
        assert!(cursor.contains("\"gateway\""));
        assert!(cursor.contains("\"--backend\""));
        assert!(cursor.contains("\"age\""));
        assert!(
            cursor.contains(
                "premier agent run --profile default-agent --backend age -- cursor-agent"
            )
        );
    }

    #[test]
    fn pin_registry_load_and_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let pins_path = dir.path().join(".premier-local").join("mcp-pins.json");

        let empty = load_pin_registry(Some(&pins_path)).unwrap();
        assert!(empty.list_alerts().is_empty());
        assert!(!empty.has_observed_tool("gh", "list_issues"));

        let tool_v1 = json!({
            "name": "list_issues",
            "description": "List GitHub issues",
            "inputSchema": { "type": "object" }
        });
        let verdict = empty.verify_or_pin("gh", &tool_v1, None, true, None);
        assert_eq!(verdict.status, premier_proxy::ToolPinStatus::Tofu);

        save_pin_registry(&empty, &pins_path).unwrap();
        assert!(pins_path.exists());
        assert!(dir.path().join(".premier-local/.gitignore").exists());

        let restored = load_pin_registry(Some(&pins_path)).unwrap();
        assert!(restored.has_observed_tool("gh", "list_issues"));

        let tool_v2 = json!({
            "name": "list_issues",
            "description": "Modified description (rug pull)",
            "inputSchema": { "type": "object" }
        });
        let drift = restored.verify_or_pin("gh", &tool_v2, None, true, None);
        assert_eq!(drift.status, premier_proxy::ToolPinStatus::Quarantined);
        assert_eq!(drift.alert.unwrap().kind, "rug_pull_detected");
    }

    struct StubUpstream {
        tools: Vec<Value>,
        reply_prefix: String,
    }

    impl premier_proxy::McpUpstream for StubUpstream {
        fn list_tools(
            &self,
        ) -> premier_proxy::mcp_gateway::BoxFuture<
            '_,
            std::result::Result<Vec<Value>, premier_proxy::GatewayError>,
        > {
            let tools = self.tools.clone();
            Box::pin(async move { Ok(tools) })
        }

        fn call_tool(
            &self,
            tool_name: &str,
            arguments: Value,
        ) -> premier_proxy::mcp_gateway::BoxFuture<
            '_,
            std::result::Result<Value, premier_proxy::GatewayError>,
        > {
            let text = format!("{} tool={tool_name} args={arguments}", self.reply_prefix);
            Box::pin(async move {
                Ok(json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false
                }))
            })
        }
    }

    #[tokio::test]
    async fn unified_gateway_exposes_builtins_and_authorized_upstreams_with_zero_raw_secrets() {
        use premier_proxy::{AuditSink, McpApprovalHandler, McpGatewayConfig, McpUpstream};
        use std::collections::{BTreeMap, HashMap};
        use zeroize::Zeroizing;

        let gh_secret = "ghp_SUPER_SECRET_UPSTREAM_TOKEN_123456";
        let stripe_secret = "sk_live_SUPER_SECRET_STRIPE_999999";

        let gateway_policy_toml = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.billing]
paths = ["billing/**"]

[zones.web]
paths = ["apps/web/**"]

[[rules]]
id = "allow-alice-secrets"
effect = "allow"
principals = ["@alice"]
paths = ["secrets/**"]
capabilities = ["use"]

[mcp_servers.gh]
transport = "http_sse"
url = "https://mcp.github.example/mcp"
credentials = [{ inject = "bearer_header", secret = "GH_TOKEN" }]

[mcp_servers.db]
command = "mcp-db"

[[mcp_rules]]
id = "allow-gh-read"
effect = "allow"
principals = ["@alice"]
tools = ["gh:list_*", "gh:create_pr"]
approval = "auto"

[[mcp_rules]]
id = "deny-gh-delete"
effect = "deny"
principals = ["*"]
tools = ["gh:delete_*"]

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/web/**", "README.md"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["GH_TOKEN", "STRIPE_API_KEY"]
allow_mcp_tools = ["gh:list_*", "gh:create_pr"]
deny_mcp_tools = ["gh:create_pr"]
"#;

        let gateway_schema_toml = r#"
version = 1
repo_id = "acme/web"

[vars.GH_TOKEN]
type = "secret"
sensitivity = "restricted"
mcp_servers = ["gh"]

[vars.GH_TOKEN.egress]
hosts = ["mcp.github.example"]

[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "restricted"
zone = "billing"
required_in = ["prod"]

[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
"#;

        let schema = EnvSchema::parse_toml(gateway_schema_toml).unwrap();
        let manifest = parse_overlay_manifest(TEST_OVERLAYS_TOML).unwrap();
        let identity = DelegatedIdentity::delegated(
            Principal::parse("@alice").unwrap(),
            vec![],
            "ui-agent",
            "gateway-test",
        );
        let ctx = McpContext::new(
            gateway_policy_toml,
            Some(TEST_SERVER_POLICY_TOML),
            schema,
            &manifest,
            identity.clone(),
            "main".to_owned(),
        )
        .unwrap();

        let gh_upstream: Arc<dyn McpUpstream> = Arc::new(StubUpstream {
            tools: vec![
                json!({
                    "name": "list_issues",
                    "description": "List open issues",
                    "inputSchema": { "type": "object", "properties": { "repo": { "type": "string" } } }
                }),
                json!({
                    "name": "create_pr",
                    "description": "Create PR (denied by agent profile)",
                    "inputSchema": { "type": "object" }
                }),
                json!({
                    "name": "delete_repo",
                    "description": "Delete repository (denied by mcp_rules)",
                    "inputSchema": { "type": "object" }
                }),
            ],
            // Deliberately echo the secret back from upstream to prove gateway scrubs it!
            reply_prefix: format!("upstream_echo={gh_secret}"),
        });
        let db_upstream: Arc<dyn McpUpstream> = Arc::new(StubUpstream {
            tools: vec![json!({
                "name": "drop_all",
                "description": "Unallowed default-deny DB tool",
                "inputSchema": { "type": "object" }
            })],
            reply_prefix: "db".to_owned(),
        });

        let mut custom_upstreams = HashMap::new();
        custom_upstreams.insert("gh".to_owned(), gh_upstream);
        custom_upstreams.insert("db".to_owned(), db_upstream);

        let mut resolved_secrets = BTreeMap::new();
        resolved_secrets.insert("GH_TOKEN".to_owned(), Zeroizing::new(gh_secret.to_owned()));
        resolved_secrets.insert(
            "STRIPE_API_KEY".to_owned(),
            Zeroizing::new(stripe_secret.to_owned()),
        );

        let pins = Arc::new(ToolPinRegistry::new());
        let builtins: Arc<dyn BuiltinMcpHandler> =
            Arc::new(PremierBuiltinMcpHandler::new(ctx.clone()));
        let gateway = McpGateway::new(McpGatewayConfig {
            identity,
            ref_name: "main".to_owned(),
            policy: Arc::new(ctx.compiled_policy.clone()),
            env_schema: Arc::new(ctx.env_schema.clone()),
            resolved_secrets,
            audit_sink: Arc::new(AuditSink::new(None)),
            pin_registry: Arc::clone(&pins),
            approval_handler: McpApprovalHandler::AutoApprove,
            allow_loopback_http: false,
            allow_private_upstreams: false,
            allow_repo_stdio_servers: true,
            extra_upstream_roots: Vec::new(),
            custom_upstreams,
            builtins: Some(builtins),
        })
        .unwrap();

        // 1. tools/list returns all 5 built-in tools + authorized upstream `gh:list_issues`,
        //    while hiding `gh:create_pr`, `gh:delete_repo`, and `db:drop_all`.
        let list_line = gateway
            .handle_jsonrpc_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
            .await
            .unwrap();
        let list_resp: Value = serde_json::from_str(&list_line).unwrap();
        let names: Vec<&str> = list_resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "premier_access_explain",
                "premier_policy_summary",
                "premier_env_schema",
                "premier_overlays_check",
                "premier_policy_diff",
                "gh:list_issues",
            ]
        );

        // 2. tools/call works for built-in `premier_policy_summary`.
        let summary_line = gateway
            .handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"premier_policy_summary","arguments":{}}}"#,
            )
            .await
            .unwrap();
        let summary_resp: Value = serde_json::from_str(&summary_line).unwrap();
        let (summary_body, summary_err) = parse_tool_text(&summary_resp);
        assert!(!summary_err);
        assert_eq!(summary_body["zone_count"], 2);
        assert_eq!(summary_body["agent_profiles"], json!(["ui-agent"]));

        // 3. tools/call works for authorized upstream `gh:list_issues` AND scrubs reflected secrets.
        let upstream_line = gateway
            .handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gh:list_issues","arguments":{"repo":"acme/web"}}}"#,
            )
            .await
            .unwrap();
        assert!(!upstream_line.contains(gh_secret));
        assert!(upstream_line.contains("[REDACTED:GH_TOKEN]"));
        let upstream_resp: Value = serde_json::from_str(&upstream_line).unwrap();
        assert_eq!(upstream_resp["result"]["isError"], false);

        // Unauthorized upstream call fails closed.
        let denied_line = gateway
            .handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gh:create_pr","arguments":{}}}"#,
            )
            .await
            .unwrap();
        let denied_resp: Value = serde_json::from_str(&denied_line).unwrap();
        assert_eq!(denied_resp["result"]["isError"], true);

        // 4. resources/read works for `premier://env/schema` with ZERO raw secrets exposed.
        let res_line = gateway
            .handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"premier://env/schema"}}"#,
            )
            .await
            .unwrap();
        assert!(!res_line.contains(gh_secret));
        assert!(!res_line.contains(stripe_secret));
        assert!(!res_line.contains("vault.toml"));
        let res_json: Value = serde_json::from_str(&res_line).unwrap();
        let schema_text = res_json["result"]["contents"][0]["text"].as_str().unwrap();
        let schema_body: Value = serde_json::from_str(schema_text).unwrap();
        assert_eq!(schema_body["placeholder_prefix"], "premier_cap_v1_");
        assert_eq!(schema_body["variable_count"], 2);
        for v in schema_body["variables"].as_array().unwrap() {
            assert_eq!(v["raw_value_exposed"], false);
            assert!(v.get("value").is_none());
        }
    }
}
