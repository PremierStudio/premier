use premier_trace::EventInput;
use serde_json::{Value, json};
use std::path::Path;

pub const ADAPTER_SCHEMA_VERSION: u32 = 1;
const MAX_NATIVE_LINE_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterChoice {
    Auto,
    None,
    Codex,
    Claude,
    Gemini,
    Grok,
    Opencode,
    Kimi,
    Droid,
}

impl std::str::FromStr for AdapterChoice {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            "gemini" => Ok(Self::Gemini),
            "grok" => Ok(Self::Grok),
            "opencode" => Ok(Self::Opencode),
            "kimi" => Ok(Self::Kimi),
            "droid" => Ok(Self::Droid),
            _ => Err(
                "adapter must be auto, none, codex, claude, gemini, grok, opencode, kimi, or droid"
                    .into(),
            ),
        }
    }
}

impl AdapterChoice {
    pub fn is_explicit(self) -> bool {
        !matches!(self, Self::Auto | Self::None)
    }

    pub fn resolve(self, executable: &str, args: &[String], pty: bool) -> Option<Provider> {
        if pty || self == Self::None {
            return None;
        }
        let explicit = match self {
            Self::Codex => Some(Provider::Codex),
            Self::Claude => Some(Provider::Claude),
            Self::Gemini => Some(Provider::Gemini),
            Self::Grok => Some(Provider::Grok),
            Self::Opencode => Some(Provider::Opencode),
            Self::Kimi => Some(Provider::Kimi),
            Self::Droid => Some(Provider::Droid),
            Self::Auto | Self::None => None,
        };
        if explicit.is_some() {
            return explicit;
        }
        let name = Path::new(executable)
            .file_stem()
            .and_then(|value| value.to_str())?
            .trim_end_matches(".exe")
            .to_ascii_lowercase();
        let provider = Provider::from_name(&name)?;
        provider.has_structured_output(args).then_some(provider)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Codex,
    Claude,
    Gemini,
    Grok,
    Opencode,
    Kimi,
    Droid,
}

impl Provider {
    pub fn id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Grok => "grok",
            Self::Opencode => "opencode",
            Self::Kimi => "kimi",
            Self::Droid => "droid",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            "gemini" => Some(Self::Gemini),
            "grok" => Some(Self::Grok),
            "opencode" => Some(Self::Opencode),
            "kimi" => Some(Self::Kimi),
            "droid" => Some(Self::Droid),
            _ => None,
        }
    }

    fn has_structured_output(self, args: &[String]) -> bool {
        let has_pair = |flag: &str, value: &str| {
            args.windows(2)
                .any(|pair| pair[0] == flag && pair[1] == value)
                || args.iter().any(|arg| arg == &format!("{flag}={value}"))
        };
        match self {
            Self::Codex => args.iter().any(|arg| arg == "--json"),
            Self::Claude => has_pair("--output-format", "stream-json"),
            Self::Gemini => has_pair("--output-format", "stream-json"),
            Self::Grok => has_pair("--output-format", "streaming-json"),
            Self::Opencode => has_pair("--format", "json"),
            Self::Kimi => has_pair("--output-format", "stream-json"),
            Self::Droid => has_pair("--output-format", "json") || has_pair("-o", "json"),
        }
    }
}

pub struct NativeAdapter {
    provider: Provider,
    pending: Vec<u8>,
    discarding_oversize: bool,
    line_number: u64,
}

impl NativeAdapter {
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            pending: Vec::new(),
            discarding_oversize: false,
            line_number: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<EventInput> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.discarding_oversize {
                if byte == b'\n' {
                    self.discarding_oversize = false;
                }
                continue;
            }
            if byte == b'\n' {
                self.line_number += 1;
                let line = std::mem::take(&mut self.pending);
                if let Some(event) = self.parse_line(&line) {
                    events.extend(event);
                }
            } else if self.pending.len() == MAX_NATIVE_LINE_BYTES {
                self.pending.clear();
                self.discarding_oversize = true;
                self.line_number += 1;
                events
                    .push(self.diagnostic("native JSONL line exceeded 256 KiB and was discarded"));
            } else {
                self.pending.push(byte);
            }
        }
        events
    }

    pub fn finish(&mut self) -> Vec<EventInput> {
        if self.discarding_oversize {
            self.discarding_oversize = false;
            return Vec::new();
        }
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.line_number += 1;
        let line = std::mem::take(&mut self.pending);
        self.parse_line(&line).unwrap_or_default()
    }

    fn parse_line(&self, line: &[u8]) -> Option<Vec<EventInput>> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let line = strip_terminal_prefix(line);
        let native: Value = match serde_json::from_slice(line) {
            Ok(Value::Object(object)) => Value::Object(object),
            Ok(_) => {
                return Some(vec![
                    self.diagnostic("native JSONL event was not an object"),
                ]);
            }
            Err(error) => {
                return Some(vec![
                    self.diagnostic(&format!("malformed native JSONL: {error}")),
                ]);
            }
        };
        Some(vec![normalize(self.provider, native)])
    }

    fn diagnostic(&self, message: &str) -> EventInput {
        EventInput {
            kind: "adapter.diagnostic".into(),
            source: format!("adapter.{}.v{ADAPTER_SCHEMA_VERSION}", self.provider.id()),
            actor_id: self.provider.id().into(),
            actor_type: "agent".into(),
            status: "warning".into(),
            payload: json!({
                "provider": self.provider.id(),
                "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
                "line": self.line_number,
                "message": message,
            }),
            ..EventInput::default()
        }
    }
}

fn strip_terminal_prefix(mut line: &[u8]) -> &[u8] {
    loop {
        line = line.trim_ascii_start();
        if !line.starts_with(b"\x1b") {
            return line;
        }
        if line.starts_with(b"\x1b[") {
            let Some(end) = line[2..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
            else {
                return line;
            };
            line = &line[end + 3..];
            continue;
        }
        if line.starts_with(b"\x1b]")
            && let Some(end) = line[2..].iter().position(|byte| *byte == 0x07)
        {
            line = &line[end + 3..];
            continue;
        }
        return line;
    }
}

fn string_at<'a>(value: &'a Value, paths: &[&[&str]]) -> Option<&'a str> {
    paths.iter().find_map(|path| {
        let mut current = value;
        for key in *path {
            current = current.get(*key)?;
        }
        current.as_str()
    })
}

fn collect_discriminators(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "type" | "subtype" | "kind" | "event" | "hook_name" | "role"
                ) && let Some(value) = value.as_str()
                {
                    output.push(value.to_ascii_lowercase());
                }
                collect_discriminators(value, output);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_discriminators(item, output);
            }
        }
        _ => {}
    }
}

fn normalize(provider: Provider, native: Value) -> EventInput {
    let native_type = string_at(
        &native,
        &[
            &["type"],
            &["event"],
            &["kind"],
            &["method"],
            &["item", "type"],
            &["part", "type"],
        ],
    )
    .unwrap_or("unknown")
    .to_ascii_lowercase();
    let combined = combined_discriminators(&native);
    let completed = is_completed(&native, &combined);
    let failed = is_failed(&native, &combined);
    let kind = classify_kind(provider, &native, &combined, completed);
    let correlation_id = string_at(
        &native,
        &[
            &["call_id"],
            &["tool_use_id"],
            &["tool_call_id"],
            &["item", "id"],
            &["message", "id"],
            &["request_id"],
            &["uuid"],
            &["id"],
            &["session_id"],
            &["thread_id"],
        ],
    )
    .unwrap_or("")
    .to_owned();
    EventInput {
        kind: kind.into(),
        source: format!("adapter.{}.v{ADAPTER_SCHEMA_VERSION}", provider.id()),
        actor_id: provider.id().into(),
        actor_type: "agent".into(),
        span_id: correlation_id.clone(),
        correlation_id,
        status: if failed {
            "error"
        } else if completed || kind.ends_with("response") || kind.ends_with("result") {
            "ok"
        } else {
            "running"
        }
        .into(),
        duration_ms: native
            .get("duration_ms")
            .or_else(|| native.get("item")?.get("duration_ms"))
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        payload: json!({
            "provider": provider.id(),
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "native_type": native_type,
            "native": native,
        }),
        ..EventInput::default()
    }
}

fn combined_discriminators(native: &Value) -> String {
    let mut discriminators = Vec::new();
    collect_discriminators(native, &mut discriminators);
    discriminators.join(" ")
}

fn is_completed(native: &Value, combined: &str) -> bool {
    ["completed", "result", "finish", "end"]
        .iter()
        .any(|marker| combined.contains(marker))
        || native.get("exit_code").is_some()
        || native
            .get("item")
            .and_then(|item| item.get("exit_code"))
            .is_some()
}

fn is_failed(native: &Value, combined: &str) -> bool {
    combined.contains("error")
        || combined.contains("fail")
        || has_failed_status(native)
        || has_nonzero_exit(native)
}

fn has_failed_status(native: &Value) -> bool {
    string_at(native, &[&["status"], &["item", "status"]]).is_some_and(|status| {
        matches!(
            status.to_ascii_lowercase().as_str(),
            "error" | "failed" | "denied"
        )
    })
}

fn has_nonzero_exit(native: &Value) -> bool {
    native
        .get("exit_code")
        .or_else(|| native.get("item")?.get("exit_code"))
        .and_then(Value::as_i64)
        .is_some_and(|code| code != 0)
}

fn classify_kind(
    provider: Provider,
    native: &Value,
    combined: &str,
    completed: bool,
) -> &'static str {
    if provider == Provider::Droid && native.get("type").and_then(Value::as_str) == Some("result") {
        return "model.response";
    }
    if provider == Provider::Kimi && native.get("role").and_then(Value::as_str) == Some("tool") {
        return "tool.result";
    }
    if contains_any(combined, &["approval", "permission"]) {
        return lifecycle_kind(completed, "approval.decision", "approval.request");
    }
    if contains_any(
        combined,
        &["tool", "command_execution", "function_call", "mcp_"],
    ) {
        return lifecycle_kind(completed, "tool.result", "tool.invocation");
    }
    if contains_any(combined, &["assistant", "message", "model", "turn"]) {
        let response = completed || contains_any(combined, &["assistant", "message"]);
        return lifecycle_kind(response, "model.response", "model.request");
    }
    if contains_any(combined, &["session", "thread", "agent", "step"]) {
        return lifecycle_kind(completed, "agent.result", "agent.turn");
    }
    "provider.event"
}

fn contains_any(value: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| value.contains(marker))
}

fn lifecycle_kind(
    completed: bool,
    completed_kind: &'static str,
    running_kind: &'static str,
) -> &'static str {
    if completed {
        completed_kind
    } else {
        running_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn auto_only_activates_for_native_structured_output() {
        assert_eq!(
            AdapterChoice::Auto.resolve("codex", &["exec".into(), "--json".into()], false),
            Some(Provider::Codex)
        );
        assert_eq!(
            AdapterChoice::Auto.resolve("codex", &["exec".into()], false),
            None
        );
        assert_eq!(
            AdapterChoice::Auto.resolve("claude", &["--output-format=stream-json".into()], false),
            Some(Provider::Claude)
        );
        assert_eq!(AdapterChoice::Codex.resolve("anything", &[], true), None);
    }

    #[test]
    fn provider_fixtures_normalize_to_typed_events() {
        let cases = [
            (
                Provider::Codex,
                include_bytes!("../tests/fixtures/adapters/codex.jsonl").as_slice(),
                "tool.result",
            ),
            (
                Provider::Claude,
                include_bytes!("../tests/fixtures/adapters/claude.jsonl").as_slice(),
                "tool.invocation",
            ),
            (
                Provider::Gemini,
                include_bytes!("../tests/fixtures/adapters/gemini.jsonl").as_slice(),
                "tool.result",
            ),
            (
                Provider::Grok,
                include_bytes!("../tests/fixtures/adapters/grok.jsonl").as_slice(),
                "model.response",
            ),
            (
                Provider::Opencode,
                include_bytes!("../tests/fixtures/adapters/opencode.jsonl").as_slice(),
                "tool.invocation",
            ),
            (
                Provider::Kimi,
                include_bytes!("../tests/fixtures/adapters/kimi.jsonl").as_slice(),
                "tool.result",
            ),
            (
                Provider::Droid,
                include_bytes!("../tests/fixtures/adapters/droid.jsonl").as_slice(),
                "model.response",
            ),
        ];
        for (provider, fixture, expected) in cases {
            let mut adapter = NativeAdapter::new(provider);
            let events = adapter.push(fixture);
            assert!(
                events.iter().any(|event| event.kind == expected),
                "{} lacked {expected}: {events:?}",
                provider.id()
            );
            assert!(
                events
                    .iter()
                    .all(|event| event.source == format!("adapter.{}.v1", provider.id()))
            );
        }
    }

    #[test]
    fn fragmented_and_malformed_lines_are_bounded_and_diagnostic() {
        let mut adapter = NativeAdapter::new(Provider::Codex);
        assert!(adapter.push(b"{\"type\":\"item.").is_empty());
        let events = adapter.push(
            b"completed\",\"item\":{\"type\":\"command_execution\",\"id\":\"x\"}}\nnot-json\n",
        );
        assert_eq!(events[0].kind, "tool.result");
        assert_eq!(events[1].kind, "adapter.diagnostic");
        let oversized = vec![b'x'; MAX_NATIVE_LINE_BYTES + 10];
        let events = adapter.push(&oversized);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "adapter.diagnostic");
        assert!(adapter.pending.len() <= MAX_NATIVE_LINE_BYTES);
    }

    #[test]
    fn nested_tool_content_and_nonzero_exit_are_normalized_truthfully() {
        let event = normalize(
            Provider::Claude,
            json!({
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "call-1"}]},
                "item": {"id": "call-1", "exit_code": 7, "duration_ms": 42}
            }),
        );
        assert_eq!(event.kind, "tool.result");
        assert_eq!(event.status, "error");
        assert_eq!(event.duration_ms, 42);
        assert_eq!(event.correlation_id, "call-1");
    }

    #[test]
    fn strips_bounded_terminal_control_prefixes_before_json() {
        let mut adapter = NativeAdapter::new(Provider::Droid);
        let events = adapter.push(
            b"\x1b[?u\x1b[c{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "model.response");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_chunking_never_panics_or_exceeds_the_line_bound(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..8192), 0..80)
        ) {
            let mut adapter = NativeAdapter::new(Provider::Codex);
            for chunk in chunks {
                let events = adapter.push(&chunk);
                prop_assert!(adapter.pending.len() <= MAX_NATIVE_LINE_BYTES);
                prop_assert!(events.len() <= chunk.iter().filter(|byte| **byte == b'\n').count() + 1);
            }
            let _ = adapter.finish();
            prop_assert!(adapter.pending.is_empty());
        }
    }
}
