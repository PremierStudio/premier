//! Agent hook ingestion normalizing real JSON hook payloads from Claude Code
//! (`PreToolUse` / `PostToolUse` / `Stop`), Cursor, Codex, and `ai-tools` into
//! canonical [`TraceSpan`] records.

use chrono::{DateTime, Utc};
use premier_core::AuditDecision;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::TraceError;
use crate::model::{SpanKind, TraceSpan, deterministic_id};

/// Normalized hook ingestion result ready to be recorded into [`crate::TraceStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestedHookSpan {
    pub session_id: String,
    pub tool_source: String,
    pub hook_event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    pub span: TraceSpan,
}

/// Parse a raw JSON hook payload emitted by Claude Code, Cursor, Codex, or `ai-tools`
/// into a normalized [`IngestedHookSpan`].
pub fn ingest_agent_hook_json(raw_json: &str) -> Result<IngestedHookSpan, TraceError> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Err(TraceError::InvalidHookPayload(
            "hook payload is empty".to_owned(),
        ));
    }

    let root: Value = serde_json::from_str(trimmed)?;
    let obj = root.as_object().ok_or_else(|| {
        TraceError::InvalidHookPayload("hook payload must be a JSON object".to_owned())
    })?;

    // Native OpenTelemetry OTLP/HTTP JSON (`resourceSpans` → `scopeSpans` → `spans`).
    if obj.contains_key("resourceSpans") {
        return ingest_otlp_object(obj);
    }

    let tool_source = detect_tool_source(obj);
    let hook_event = detect_hook_event(obj).ok_or_else(|| {
        TraceError::InvalidHookPayload(
            "missing hook event field (expected 'hook_event_name', 'event', 'type', or 'kind')"
                .to_owned(),
        )
    })?;

    let session_id = first_str(
        obj,
        &[
            "session_id",
            "sessionId",
            "conversation_id",
            "conversationId",
            "thread-id",
            "thread_id",
            "generation_id",
        ],
    )
    .map(str::to_owned)
    .unwrap_or_else(|| deterministic_id("sess", &format!("{tool_source}:{hook_event}")));

    let timestamp = parse_timestamp(obj).unwrap_or_else(Utc::now);

    let principal = first_str(obj, &["principal", "user", "author"]).map(str::to_owned);
    let model = first_str(obj, &["model", "model_name"]).map(str::to_owned);
    let branch = first_str(obj, &["branch", "git_branch"]).map(str::to_owned);
    let change_id = first_str(obj, &["change_id", "changeId"]).map(str::to_owned);

    let tool_input = obj.get("tool_input").and_then(Value::as_object);
    let tool_response = obj.get("tool_response").and_then(Value::as_object);

    let tool_name = first_str(obj, &["tool_name", "toolName", "tool"])
        .map(str::to_owned)
        .or_else(|| Some(tool_source.clone()));

    let raw_path = first_str(obj, &["file_path", "filePath", "path", "target_file"])
        .or_else(|| {
            tool_input.and_then(|ti| {
                first_str(
                    ti,
                    &[
                        "file_path",
                        "filePath",
                        "path",
                        "target_file",
                        "notebook_path",
                    ],
                )
            })
        })
        .map(normalize_hook_path);

    let command = first_str(obj, &["command", "cmd"])
        .map(str::to_owned)
        .or_else(|| {
            tool_input
                .and_then(|ti| first_str(ti, &["command", "cmd"]))
                .map(str::to_owned)
        })
        .or_else(|| {
            obj.get("command")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|s| !s.is_empty())
        });

    let error_message = extract_error_message(obj, tool_response);
    let duration_ms = first_u64(obj, &["duration_ms", "durationMs", "elapsed_ms"]);
    let decision = extract_decision(obj, error_message.is_some());

    let kind = classify_span_kind(
        &hook_event,
        tool_name.as_deref(),
        raw_path.is_some(),
        error_message.is_some(),
    );

    let summary = build_summary(
        obj,
        &tool_source,
        &hook_event,
        tool_name.as_deref(),
        raw_path.as_deref(),
        command.as_deref(),
        error_message.as_deref(),
    );

    let span_id = first_str(
        obj,
        &["span_id", "tool_use_id", "call_id", "turn-id", "turn_id"],
    )
    .map(str::to_owned)
    .unwrap_or_else(|| {
        let seed = format!(
            "{session_id}:{hook_event}:{}:{}:{summary}",
            timestamp.timestamp_nanos_opt().unwrap_or_default(),
            raw_path.as_deref().unwrap_or(""),
        );
        deterministic_id("sp", &seed)
    });

    let parent_span_id = first_str(
        obj,
        &[
            "parent_span_id",
            "parentSpanId",
            "parent_tool_use_id",
            "parent_event_id",
        ],
    )
    .map(str::to_owned);
    let correlation_id = first_str(
        obj,
        &["correlation_id", "correlationId", "trace_id", "run_id"],
    )
    .map(str::to_owned);
    let actor_id = first_str(obj, &["actor_id", "actorId", "agent_id", "agentId"])
        .map(str::to_owned)
        .or_else(|| Some(tool_source.clone()));
    let actor_type = first_str(obj, &["actor_type", "actorType"])
        .map(str::to_owned)
        .or_else(|| {
            Some(match kind {
                SpanKind::ProxyEgress => "proxy".to_owned(),
                SpanKind::PromptTurn => "human".to_owned(),
                SpanKind::DeliveryReport => "system".to_owned(),
                _ => "agent".to_owned(),
            })
        });
    let links: Vec<String> = obj
        .get("links")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let exit_code = obj
        .get("exit_code")
        .or_else(|| tool_response.and_then(|tr| tr.get("exit_code")))
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok());

    let usage = obj.get("usage").and_then(Value::as_object);
    let tokens_in = first_u64(obj, &["tokens_in", "input_tokens"]).or_else(|| {
        usage.and_then(|u| first_u64(u, &["input_tokens", "prompt_tokens", "tokens_in"]))
    });
    let tokens_out = first_u64(obj, &["tokens_out", "output_tokens"]).or_else(|| {
        usage.and_then(|u| first_u64(u, &["output_tokens", "completion_tokens", "tokens_out"]))
    });
    let cost_usd_micros = first_u64(obj, &["cost_usd_micros"]);

    let input = obj
        .get("input")
        .or_else(|| obj.get("tool_input"))
        .or_else(|| obj.get("arguments"))
        .cloned();
    let output = obj
        .get("output")
        .or_else(|| obj.get("tool_response"))
        .or_else(|| obj.get("result"))
        .cloned();
    let authority = obj.get("authority").or_else(|| obj.get("policy")).cloned();

    let diff = first_str(obj, &["diff", "patch", "unified_diff"])
        .map(str::to_owned)
        .or_else(|| {
            tool_input.and_then(|ti| {
                let old = first_str(ti, &["old_string", "old_str"])?;
                let new = first_str(ti, &["new_string", "new_str"])?;
                let target = raw_path.as_deref().unwrap_or("file");
                Some(synthesize_unified_diff(target, old, new))
            })
        });

    let code_snippet = first_str(obj, &["code_snippet", "snippet", "code"])
        .map(str::to_owned)
        .or_else(|| {
            tool_input
                .and_then(|ti| first_str(ti, &["content", "new_source"]))
                .map(|s| s.chars().take(4000).collect())
        });
    let language = first_str(obj, &["language", "lang"]).map(str::to_owned);
    let status = first_str(obj, &["status"]).map(str::to_owned).or_else(|| {
        Some(if error_message.is_some() {
            "error".to_owned()
        } else if matches!(
            decision,
            Some(AuditDecision::Denied | AuditDecision::ExfiltrationBlocked)
        ) {
            "blocked".to_owned()
        } else {
            "ok".to_owned()
        })
    });

    let span = TraceSpan {
        span_id,
        timestamp,
        kind,
        summary,
        path: raw_path,
        zone: first_str(obj, &["zone"]).map(str::to_owned),
        tool_name,
        command,
        decision,
        error_message,
        bytes_scrubbed: 0,
        duration_ms,
        redacted_for_viewer: false,
        actor_id,
        actor_type,
        parent_span_id,
        correlation_id,
        links,
        status,
        exit_code,
        tokens_in,
        tokens_out,
        cost_usd_micros,
        input,
        output,
        diff,
        code_snippet,
        language,
        authority,
        source: Some(tool_source.clone()),
        ..TraceSpan::default()
    };

    Ok(IngestedHookSpan {
        session_id,
        tool_source,
        hook_event,
        principal,
        model,
        branch,
        change_id,
        span,
    })
}

fn detect_tool_source(obj: &serde_json::Map<String, Value>) -> String {
    if let Some(src) = first_str(obj, &["source", "tool_source", "agent", "client"]) {
        return src.to_ascii_lowercase();
    }

    if let Some(ev) = first_str(obj, &["hook_event_name"]) {
        if matches!(
            ev,
            "PreToolUse"
                | "PostToolUse"
                | "PostToolUseFailure"
                | "UserPromptSubmit"
                | "Stop"
                | "SubagentStop"
                | "Notification"
        ) {
            return "claude-code".to_owned();
        }
        if matches!(
            ev,
            "beforeShellExecution"
                | "afterShellExecution"
                | "afterFileEdit"
                | "beforeSubmitPrompt"
                | "beforeReadFile"
                | "stop"
        ) {
            return "cursor".to_owned();
        }
    }

    if obj.contains_key("conversation_id") || obj.contains_key("generation_id") {
        return "cursor".to_owned();
    }

    if obj.contains_key("thread-id")
        || obj.contains_key("turn-id")
        || obj.contains_key("last-assistant-message")
        || obj.contains_key("input-messages")
    {
        return "codex".to_owned();
    }

    if obj.contains_key("transcript_path") || obj.contains_key("tool_input") {
        return "claude-code".to_owned();
    }

    if obj.contains_key("gemini_session_id")
        || first_str(obj, &["model", "model_name"])
            .is_some_and(|m| m.to_ascii_lowercase().contains("gemini"))
    {
        return "gemini-cli".to_owned();
    }

    "ai-tools".to_owned()
}

fn detect_hook_event(obj: &serde_json::Map<String, Value>) -> Option<String> {
    first_str(obj, &["hook_event_name", "event", "type", "hook", "kind"]).map(str::to_owned)
}

fn classify_span_kind(
    hook_event: &str,
    tool_name: Option<&str>,
    has_path: bool,
    has_error: bool,
) -> SpanKind {
    let ev = hook_event.to_ascii_lowercase();
    if has_error || ev.contains("failure") || ev.contains("error") {
        return SpanKind::ErrorDiagnostic;
    }
    if ev.contains("prompt") {
        return SpanKind::PromptTurn;
    }
    if ev == "stop"
        || ev == "subagentstop"
        || ev == "agent-turn-complete"
        || ev.contains("delivery")
        || ev.contains("complete")
    {
        return SpanKind::DeliveryReport;
    }
    if ev.contains("proxy") || ev.contains("egress") {
        return SpanKind::ProxyEgress;
    }
    if ev.contains("file") || ev.contains("patch") {
        return SpanKind::FileAccess;
    }
    if has_path
        && tool_name.is_some_and(|t| {
            matches!(
                t.to_ascii_lowercase().as_str(),
                "read" | "write" | "edit" | "multiedit" | "read_file" | "write_file" | "edit_file"
            )
        })
    {
        return SpanKind::FileAccess;
    }
    SpanKind::ToolCall
}

fn extract_error_message(
    obj: &serde_json::Map<String, Value>,
    tool_response: Option<&serde_json::Map<String, Value>>,
) -> Option<String> {
    if let Some(err) = first_str(obj, &["error", "error_message", "stderr"])
        && !err.trim().is_empty()
    {
        return Some(err.to_owned());
    }

    if let Some(resp) = tool_response {
        if let Some(err) = first_str(resp, &["error", "stderr", "error_message"])
            && !err.trim().is_empty()
        {
            return Some(err.to_owned());
        }
        if resp
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && let Some(msg) = first_str(resp, &["message", "output", "content"])
        {
            return Some(msg.to_owned());
        }
    }

    if let Some(code) = obj.get("exit_code").and_then(Value::as_i64)
        && code != 0
    {
        return Some(format!("command exited with non-zero status {code}"));
    }

    None
}

fn extract_decision(
    obj: &serde_json::Map<String, Value>,
    has_error: bool,
) -> Option<AuditDecision> {
    if let Some(raw) = first_str(obj, &["decision", "permission", "status"]) {
        match raw.to_ascii_lowercase().as_str() {
            "allow" | "allowed" | "completed" | "success" | "ok" => {
                return Some(AuditDecision::Allowed);
            }
            "deny" | "denied" | "block" | "blocked" => return Some(AuditDecision::Denied),
            "exfiltration_blocked" => return Some(AuditDecision::ExfiltrationBlocked),
            "redacted" => return Some(AuditDecision::Redacted),
            "ask" | "approval_required" => return Some(AuditDecision::ApprovalRequired),
            "rate_limited" => return Some(AuditDecision::RateLimited),
            _ => {}
        }
    }
    if has_error {
        Some(AuditDecision::Denied)
    } else {
        Some(AuditDecision::Allowed)
    }
}

fn build_summary(
    obj: &serde_json::Map<String, Value>,
    tool_source: &str,
    hook_event: &str,
    tool_name: Option<&str>,
    path: Option<&str>,
    command: Option<&str>,
    error_message: Option<&str>,
) -> String {
    if let Some(explicit) = first_str(
        obj,
        &[
            "summary",
            "prompt",
            "message",
            "last-assistant-message",
            "last_assistant_message",
        ],
    ) && !explicit.trim().is_empty()
    {
        return explicit.to_owned();
    }

    if let Some(arr) = obj.get("input-messages").and_then(Value::as_array)
        && let Some(first) = arr.iter().filter_map(Value::as_str).next()
        && !first.trim().is_empty()
    {
        return first.to_owned();
    }

    let tool_label = tool_name.unwrap_or(tool_source);
    if let Some(err) = error_message {
        return format!("{tool_source} {hook_event} ({tool_label}) failed: {err}");
    }
    if let Some(p) = path {
        return format!("{tool_source} {hook_event} ({tool_label}) on {p}");
    }
    if let Some(cmd) = command {
        return format!("{tool_source} {hook_event} ({tool_label}): {cmd}");
    }
    format!("{tool_source} {hook_event} ({tool_label})")
}

fn normalize_hook_path(raw: &str) -> String {
    let trimmed = raw.trim();
    // Preserve parent-traversal payloads intact so RepoPath validation fails closed.
    if trimmed.contains("..") {
        return trimmed.to_owned();
    }
    let posix = trimmed.replace('\\', "/");
    posix
        .strip_prefix("./")
        .unwrap_or(&posix)
        .trim_start_matches('/')
        .to_owned()
}

fn first_str<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(s) = obj.get(*key).and_then(Value::as_str)
            && !s.is_empty()
        {
            return Some(s);
        }
    }
    None
}

fn first_u64(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(v) = obj.get(*key).and_then(Value::as_u64) {
            return Some(v);
        }
    }
    None
}

fn synthesize_unified_diff(path: &str, old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n",
        old_lines.len().max(1),
        new_lines.len().max(1)
    );
    for l in old_lines {
        out.push('-');
        out.push_str(l);
        out.push('\n');
    }
    for l in new_lines {
        out.push('+');
        out.push_str(l);
        out.push('\n');
    }
    out.trim_end_matches('\n').to_owned()
}

fn parse_timestamp(obj: &serde_json::Map<String, Value>) -> Option<DateTime<Utc>> {
    for key in ["timestamp", "created_at", "ts", "startTimeUnixNano"] {
        if let Some(val) = obj.get(key) {
            if let Some(s) = val.as_str() {
                if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                    return Some(dt.with_timezone(&Utc));
                }
                if let Ok(n) = s.parse::<i64>() {
                    return epoch_to_utc(n);
                }
            } else if let Some(n) = val.as_i64() {
                return epoch_to_utc(n);
            }
        }
    }
    None
}

fn epoch_to_utc(n: i64) -> Option<DateTime<Utc>> {
    if n > 1_000_000_000_000_000_000 {
        // Nanoseconds
        DateTime::from_timestamp(n / 1_000_000_000, (n % 1_000_000_000).unsigned_abs() as u32)
    } else if n > 1_000_000_000_000 {
        // Milliseconds
        DateTime::from_timestamp_millis(n)
    } else if n > 1_000_000_000 {
        // Seconds
        DateTime::from_timestamp(n, 0)
    } else {
        None
    }
}

/// Normalize an OpenTelemetry OTLP/HTTP JSON payload (`resourceSpans` → `scopeSpans` → `spans`)
/// into a canonical [`IngestedHookSpan`].
fn ingest_otlp_object(
    obj: &serde_json::Map<String, Value>,
) -> Result<IngestedHookSpan, TraceError> {
    let rs = obj
        .get("resourceSpans")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            TraceError::InvalidHookPayload("OTLP payload missing resourceSpans[0]".to_owned())
        })?;

    let resource_attrs = rs
        .get("resource")
        .and_then(|r| r.get("attributes"))
        .and_then(Value::as_array);
    let service_name = otlp_attr_str(resource_attrs, "service.name")
        .unwrap_or("otlp-agent")
        .to_owned();
    let model = otlp_attr_str(resource_attrs, "gen_ai.request.model")
        .or_else(|| otlp_attr_str(resource_attrs, "llm.model_name"))
        .map(str::to_owned);
    let principal = otlp_attr_str(resource_attrs, "enduser.id")
        .or_else(|| otlp_attr_str(resource_attrs, "premier.principal"))
        .map(str::to_owned);

    let otlp_span = rs
        .get("scopeSpans")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("spans"))
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            TraceError::InvalidHookPayload("OTLP payload missing scopeSpans[0].spans[0]".to_owned())
        })?;

    let attrs = otlp_span.get("attributes").and_then(Value::as_array);
    let name = first_str(otlp_span, &["name"]).unwrap_or("otlp.span");
    let trace_id = first_str(otlp_span, &["traceId"]).unwrap_or("otlp");
    let span_id = first_str(otlp_span, &["spanId"])
        .map(|s| format!("sp_{s}"))
        .unwrap_or_else(|| deterministic_id("sp", &format!("{trace_id}:{name}")));
    let parent_span_id = first_str(otlp_span, &["parentSpanId"]).map(|s| format!("sp_{s}"));

    let start_ns = otlp_span.get("startTimeUnixNano").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| v.as_i64())
    });
    let end_ns = otlp_span.get("endTimeUnixNano").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| v.as_i64())
    });
    let timestamp = start_ns.and_then(epoch_to_utc).unwrap_or_else(Utc::now);
    let duration_ms = match (start_ns, end_ns) {
        (Some(s), Some(e)) if e >= s => Some(((e - s) / 1_000_000) as u64),
        _ => None,
    };

    let path = otlp_attr_str(attrs, "file.path")
        .or_else(|| otlp_attr_str(attrs, "code.filepath"))
        .map(normalize_hook_path);
    let zone = otlp_attr_str(attrs, "premier.zone").map(str::to_owned);
    let tool_name = otlp_attr_str(attrs, "gen_ai.tool.name")
        .or_else(|| otlp_attr_str(attrs, "tool.name"))
        .map(str::to_owned)
        .or_else(|| Some(name.to_owned()));
    let tokens_in = otlp_attr_u64(attrs, "gen_ai.usage.input_tokens");
    let tokens_out = otlp_attr_u64(attrs, "gen_ai.usage.output_tokens");
    let span_model = otlp_attr_str(attrs, "gen_ai.request.model")
        .map(str::to_owned)
        .or(model);
    let session_id = otlp_attr_str(attrs, "gen_ai.conversation.id")
        .or_else(|| otlp_attr_str(attrs, "session.id"))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("tr_otlp_{}", &trace_id[..trace_id.len().min(12)]));

    let status_code = otlp_span
        .get("status")
        .and_then(|s| s.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let error_message = if status_code == 2 {
        otlp_span
            .get("status")
            .and_then(|s| s.get("message"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some(format!("OTLP span '{name}' failed")))
    } else {
        None
    };

    let kind = if error_message.is_some() {
        SpanKind::ErrorDiagnostic
    } else if path.is_some() {
        SpanKind::FileAccess
    } else if name.to_ascii_lowercase().contains("prompt")
        || name.to_ascii_lowercase().contains("chat")
    {
        SpanKind::PromptTurn
    } else if otlp_attr_str(attrs, "http.url").is_some()
        || otlp_attr_str(attrs, "url.full").is_some()
    {
        SpanKind::ProxyEgress
    } else {
        SpanKind::ToolCall
    };

    let mut attr_map = serde_json::Map::new();
    if let Some(list) = attrs {
        for item in list {
            if let Some(k) = item.get("key").and_then(Value::as_str)
                && let Some(val_obj) = item.get("value").and_then(Value::as_object)
            {
                if let Some(s) = val_obj.get("stringValue").and_then(Value::as_str) {
                    attr_map.insert(k.to_owned(), Value::String(s.to_owned()));
                } else if let Some(v) = val_obj.get("intValue") {
                    attr_map.insert(k.to_owned(), v.clone());
                } else if let Some(b) = val_obj.get("boolValue") {
                    attr_map.insert(k.to_owned(), b.clone());
                }
            }
        }
    }

    let span = TraceSpan {
        span_id,
        timestamp,
        kind,
        summary: otlp_attr_str(attrs, "premier.summary")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{service_name}: {name}")),
        path,
        zone,
        tool_name,
        command: otlp_attr_str(attrs, "process.command_line")
            .or_else(|| otlp_attr_str(attrs, "url.full"))
            .map(str::to_owned),
        decision: Some(if error_message.is_some() {
            AuditDecision::Denied
        } else {
            AuditDecision::Allowed
        }),
        error_message,
        duration_ms,
        actor_id: Some(service_name.clone()),
        actor_type: Some("agent".to_owned()),
        parent_span_id,
        correlation_id: Some(trace_id.to_owned()),
        status: Some(if status_code == 2 {
            "error".to_owned()
        } else {
            "ok".to_owned()
        }),
        tokens_in,
        tokens_out,
        input: if attr_map.is_empty() {
            None
        } else {
            Some(Value::Object(attr_map))
        },
        source: Some("otlp".to_owned()),
        ..TraceSpan::default()
    };

    Ok(IngestedHookSpan {
        session_id,
        tool_source: service_name,
        hook_event: format!("otlp:{name}"),
        principal,
        model: span_model,
        branch: otlp_attr_str(attrs, "vcs.ref.head.name").map(str::to_owned),
        change_id: otlp_attr_str(attrs, "premier.change_id").map(str::to_owned),
        span,
    })
}

fn otlp_attr_str<'a>(attrs: Option<&'a Vec<Value>>, key: &str) -> Option<&'a str> {
    attrs?.iter().find_map(|item| {
        if item.get("key").and_then(Value::as_str) == Some(key) {
            item.get("value")
                .and_then(|v| v.get("stringValue"))
                .and_then(Value::as_str)
        } else {
            None
        }
    })
}

fn otlp_attr_u64(attrs: Option<&Vec<Value>>, key: &str) -> Option<u64> {
    attrs?.iter().find_map(|item| {
        if item.get("key").and_then(Value::as_str) == Some(key) {
            let v = item.get("value")?.get("intValue")?;
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        } else {
            None
        }
    })
}
