//! `premier-trace` — Premier's integrated `agent-trace` engine.
//!
//! Provides local-first AI coding agent tracing, structured error diagnostics,
//! delivery reporting, live SSE streaming, and ACL-scoped Prompt/Session Provenance
//! ("blame the prompt") with mandatory pre-write secret scrubbing and read-time
//! Zone ACL redaction.

pub mod hook;
pub mod model;
pub mod store;

use thiserror::Error;

pub use hook::{IngestedHookSpan, ingest_agent_hook_json};
pub use model::{
    DeliverySummary, IntegrityReport, IntegrityStatus, REDACTED_ZONE_PATH, SessionStatus, SpanKind,
    TraceEvent, TraceSession, TraceSpan, deterministic_id,
};
pub use store::{
    REDACTED_COMMAND, REDACTED_PROMPT_SUMMARY, REDACTED_ZONE_SUMMARY, TraceStore,
    filter_session_for_viewer, scrub_raw_secret_patterns, scrub_session, scrub_span,
};

/// Errors emitted by `premier-trace` persistence and hook ingestion.
#[derive(Debug, Error)]
pub enum TraceError {
    #[error("trace I/O error: {0}")]
    Io(String),

    #[error("trace JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid agent hook payload: {0}")]
    InvalidHookPayload(String),

    #[error("trace session '{0}' not found")]
    SessionNotFound(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Utc;
    use premier_core::{AuditDecision, AuditEvent, DelegatedIdentity, Principal};
    use premier_policy::{CompiledPolicy, parse_policy_toml};
    use premier_secrets::SecretRedactor;

    use super::*;

    const TEST_POLICY: &str = r#"
version = 1

[defaults]
public = []
authenticated = []

[zones.billing]
paths = ["billing/**"]
owners = ["@alice"]

[[rules]]
id = "allow-public-apps"
effect = "allow"
principals = ["*"]
paths = ["apps/**", "README.md", "AGENTS.md"]
capabilities = ["traverse", "list", "read"]

[[rules]]
id = "allow-billing-team"
effect = "allow"
principals = ["group:billing"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]

[[rules]]
id = "deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["billing/ledger/master.key"]
capabilities = ["read", "write"]
"#;

    fn compiled_test_policy() -> CompiledPolicy {
        let parsed = parse_policy_toml(TEST_POLICY).unwrap();
        CompiledPolicy::compile(None, &parsed).unwrap()
    }

    #[test]
    fn pre_write_secret_scrubbing_never_persists_plaintext_to_disk_or_memory() {
        let dir = tempfile::tempdir().unwrap();
        let trace_file = dir.path().join(".premier").join("traces.jsonl");

        let raw_secret_buf = ["sk", "live", "TraceScrubKey_0123456789"].join("_");
        let raw_secret = raw_secret_buf.as_str();
        let redactor = SecretRedactor::build([("STRIPE_API_KEY", raw_secret)]);
        let store = TraceStore::new(Some(trace_file.clone()), redactor);

        let now = Utc::now();
        let session = TraceSession {
            session_id: "sess_scrub_1".to_owned(),
            started_at: now,
            updated_at: now,
            principal: "@alice".to_owned(),
            agent_profile: Some("ui-agent".to_owned()),
            model: "gemini-4-neon".to_owned(),
            tool_name: "claude-code".to_owned(),
            branch: "main".to_owned(),
            change_id: Some("Iabc1234".to_owned()),
            commit_oid: Some("1122334".to_owned()),
            status: SessionStatus::Active,
            spans: vec![TraceSpan {
                span_id: "sp_1".to_owned(),
                timestamp: now,
                kind: SpanKind::ToolCall,
                summary: format!("curl returned token={raw_secret}"),
                path: Some("apps/web/index.tsx".to_owned()),
                zone: Some("public".to_owned()),
                tool_name: Some("Bash".to_owned()),
                command: Some(format!(
                    "curl -H 'Authorization: Bearer {raw_secret}' https://api.stripe.com/v1/charges"
                )),
                decision: Some(AuditDecision::Redacted),
                error_message: Some(format!("upstream echoed {raw_secret}")),
                bytes_scrubbed: 0,
                duration_ms: Some(50),
                redacted_for_viewer: false,
                input: Some(serde_json::json!({ "header": format!("Bearer {raw_secret}") })),
                diff: Some(format!("+const key = \"{raw_secret}\";")),
                ..TraceSpan::default()
            }],
            delivery: DeliverySummary::default(),
        };

        let stored = store.record_session(session).unwrap();
        assert!(stored.delivery.bytes_scrubbed >= raw_secret.len() * 5);
        assert!(!stored.spans[0].summary.contains(raw_secret));
        assert!(
            stored.spans[0]
                .summary
                .contains("[REDACTED:STRIPE_API_KEY]")
        );
        assert!(
            !stored.spans[0]
                .command
                .as_deref()
                .unwrap()
                .contains(raw_secret)
        );
        assert!(
            !stored.spans[0]
                .error_message
                .as_deref()
                .unwrap()
                .contains(raw_secret)
        );
        assert!(
            !stored.spans[0]
                .diff
                .as_deref()
                .unwrap()
                .contains(raw_secret)
        );
        assert!(
            !stored.spans[0]
                .input
                .as_ref()
                .unwrap()
                .to_string()
                .contains(raw_secret)
        );

        // Also test incremental `record_span` pre-write scrubbing.
        let extra_span = TraceSpan {
            span_id: "sp_2".to_owned(),
            timestamp: Utc::now(),
            kind: SpanKind::ErrorDiagnostic,
            summary: format!("stderr leaked {raw_secret}"),
            path: None,
            zone: None,
            tool_name: Some("Bash".to_owned()),
            command: None,
            decision: Some(AuditDecision::Denied),
            error_message: Some(format!("fatal: {raw_secret}")),
            bytes_scrubbed: 0,
            duration_ms: Some(15),
            redacted_for_viewer: false,
            ..TraceSpan::default()
        };
        let recorded_span = store.record_span("sess_scrub_1", extra_span).unwrap();
        assert!(recorded_span.bytes_scrubbed >= raw_secret.len() * 2);
        assert!(!recorded_span.summary.contains(raw_secret));

        // Verify raw `.premier/traces.jsonl` bytes on disk contain ZERO plaintext secrets.
        let disk_contents = std::fs::read_to_string(&trace_file).unwrap();
        assert!(!disk_contents.contains(raw_secret));
        assert!(disk_contents.contains("[REDACTED:STRIPE_API_KEY]"));
    }

    #[test]
    fn read_time_zone_acl_filtering_enforces_viewer_boundaries_and_fail_closed() {
        let policy = compiled_test_policy();
        let now = Utc::now();

        let mut session = TraceSession {
            session_id: "sess_acl_1".to_owned(),
            started_at: now,
            updated_at: now,
            principal: "@alice".to_owned(),
            agent_profile: Some("ui-agent".to_owned()),
            model: "gemini-4-neon".to_owned(),
            tool_name: "claude-code".to_owned(),
            branch: "launch-v3-embargo".to_owned(),
            change_id: Some("I7a3f92c8e1".to_owned()),
            commit_oid: Some("9f4c2a1".to_owned()),
            status: SessionStatus::Completed,
            spans: vec![
                TraceSpan {
                    span_id: "sp_prompt".to_owned(),
                    timestamp: now,
                    kind: SpanKind::PromptTurn,
                    summary: "Internal org prompt: refactor ledger rounding".to_owned(),
                    path: None,
                    zone: None,
                    tool_name: Some("claude-code".to_owned()),
                    command: None,
                    decision: Some(AuditDecision::Allowed),
                    error_message: None,
                    bytes_scrubbed: 0,
                    duration_ms: Some(100),
                    redacted_for_viewer: false,
                    ..TraceSpan::default()
                },
                TraceSpan {
                    span_id: "sp_public".to_owned(),
                    timestamp: now,
                    kind: SpanKind::FileAccess,
                    summary: "Edited public UI component".to_owned(),
                    path: Some("apps/web/index.tsx".to_owned()),
                    zone: Some("public".to_owned()),
                    tool_name: Some("Edit".to_owned()),
                    command: Some("pnpm typecheck".to_owned()),
                    decision: Some(AuditDecision::Allowed),
                    error_message: None,
                    bytes_scrubbed: 0,
                    duration_ms: Some(200),
                    redacted_for_viewer: false,
                    ..TraceSpan::default()
                },
                TraceSpan {
                    span_id: "sp_billing".to_owned(),
                    timestamp: now,
                    kind: SpanKind::ErrorDiagnostic,
                    summary: "Failed invariant in billing/ledger/tx.rs".to_owned(),
                    path: Some("billing/ledger/tx.rs".to_owned()),
                    zone: Some("billing".to_owned()),
                    tool_name: Some("Edit".to_owned()),
                    command: Some("cargo test -p billing".to_owned()),
                    decision: Some(AuditDecision::Denied),
                    error_message: Some("negative balance in secret ledger".to_owned()),
                    bytes_scrubbed: 0,
                    duration_ms: Some(300),
                    redacted_for_viewer: false,
                    diff: Some("--- a/billing/ledger/tx.rs\n+++ b/billing/ledger/tx.rs\n@@ -1 +1 @@\n-old\n+secret_formula".to_owned()),
                    code_snippet: Some("fn secret_formula() -> i64 { 42 }".to_owned()),
                    input: Some(serde_json::json!({ "file": "billing/ledger/tx.rs" })),
                    ..TraceSpan::default()
                },
                TraceSpan {
                    span_id: "sp_traversal".to_owned(),
                    timestamp: now,
                    kind: SpanKind::FileAccess,
                    summary: "Suspicious parent traversal".to_owned(),
                    path: Some("../etc/passwd".to_owned()),
                    zone: None,
                    tool_name: Some("Read".to_owned()),
                    command: None,
                    decision: Some(AuditDecision::Denied),
                    error_message: None,
                    bytes_scrubbed: 0,
                    duration_ms: Some(10),
                    redacted_for_viewer: false,
                    ..TraceSpan::default()
                },
            ],
            delivery: DeliverySummary::default(),
        };
        session.recompute_delivery();

        // 1. Anonymous viewer: prompt + command redacted, billing & traversal paths server-redacted.
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let anon_view = filter_session_for_viewer(&session, &anon, Some(&policy), "main");
        assert_eq!(anon_view.spans[0].summary, REDACTED_PROMPT_SUMMARY);
        assert!(anon_view.spans[0].redacted_for_viewer);
        assert_eq!(
            anon_view.spans[1].path.as_deref(),
            Some("apps/web/index.tsx")
        );
        assert_eq!(
            anon_view.spans[1].command.as_deref(),
            Some(REDACTED_COMMAND)
        );
        assert!(anon_view.spans[1].redacted_for_viewer);
        assert_eq!(anon_view.spans[2].path.as_deref(), Some(REDACTED_ZONE_PATH));
        assert_eq!(anon_view.spans[2].summary, REDACTED_ZONE_SUMMARY);
        assert_eq!(
            anon_view.spans[2].error_message.as_deref(),
            Some(REDACTED_ZONE_SUMMARY)
        );
        assert!(anon_view.spans[2].zone.is_none());
        assert!(anon_view.spans[2].redacted_for_viewer);
        // Invalid RepoPath fails closed even if defaults allow public read.
        assert_eq!(anon_view.spans[3].path.as_deref(), Some(REDACTED_ZONE_PATH));
        assert!(anon_view.spans[3].redacted_for_viewer);
        // Restricted filename never leaks via delivery.files_touched.
        assert_eq!(anon_view.delivery.files_touched, vec!["apps/web/index.tsx"]);

        // 2. Fail closed for anonymous viewer when policy is None!
        let anon_no_policy = filter_session_for_viewer(&session, &anon, None, "main");
        assert_eq!(anon_no_policy.spans[0].summary, REDACTED_PROMPT_SUMMARY);
        assert_eq!(
            anon_no_policy.spans[1].path.as_deref(),
            Some(REDACTED_ZONE_PATH)
        );
        assert!(anon_no_policy.delivery.files_touched.is_empty());

        // 3. Authenticated user outside group:billing sees prompts + public files, NOT billing.
        let bob = DelegatedIdentity::human_only(Principal::User("bob".to_owned()), vec![]);
        let bob_view = filter_session_for_viewer(&session, &bob, Some(&policy), "main");
        assert!(!bob_view.spans[0].redacted_for_viewer);
        assert!(!bob_view.spans[1].redacted_for_viewer);
        assert_eq!(bob_view.spans[2].path.as_deref(), Some(REDACTED_ZONE_PATH));
        assert_eq!(bob_view.spans[2].summary, REDACTED_ZONE_SUMMARY);
        assert!(bob_view.spans[2].redacted_for_viewer);
        assert!(bob_view.spans[2].diff.is_none());
        assert!(bob_view.spans[2].code_snippet.is_none());
        assert!(bob_view.spans[2].input.is_none());

        // 4. Authenticated user in group:billing sees both public and billing/ledger/**,
        //    while invalid traversal path STILL fails closed.
        let alice = DelegatedIdentity::human_only(
            Principal::User("alice".to_owned()),
            vec!["billing".to_owned()],
        );
        let alice_view = filter_session_for_viewer(&session, &alice, Some(&policy), "main");
        assert!(!alice_view.spans[2].redacted_for_viewer);
        assert_eq!(
            alice_view.spans[2].path.as_deref(),
            Some("billing/ledger/tx.rs")
        );
        assert_eq!(
            alice_view.spans[3].path.as_deref(),
            Some(REDACTED_ZONE_PATH)
        );
    }

    #[test]
    fn jsonl_reload_roundtrip_and_proxy_audit_bridge_work() {
        let dir = tempfile::tempdir().unwrap();
        let trace_file = dir.path().join(".premier").join("traces.jsonl");

        let alice = DelegatedIdentity::delegated(
            Principal::User("alice".to_owned()),
            vec!["billing".to_owned()],
            "ui-agent",
            "task-99",
        );

        {
            let store = TraceStore::new(
                Some(trace_file.clone()),
                SecretRedactor::build([("API_KEY", "secret_val_9999")]),
            );
            let mut rx = store.subscribe();

            let mut audit = AuditEvent::now(
                &alice,
                "premier-proxy",
                "egress_inject",
                AuditDecision::ExfiltrationBlocked,
                "blocked exfil carrying secret_val_9999 to evil.example",
            );
            audit.target = Some("https://evil.example/leak".to_owned());
            audit.capability = Some("use:STRIPE_API_KEY".to_owned());
            audit.bytes_scrubbed = 12;

            let span = store
                .record_proxy_audit_event("sess_proxy_bridge", &audit)
                .unwrap();
            assert_eq!(span.kind, SpanKind::ProxyEgress);
            assert_eq!(span.decision, Some(AuditDecision::ExfiltrationBlocked));
            assert!(!span.summary.contains("secret_val_9999"));
            assert!(span.bytes_scrubbed >= 12 + "secret_val_9999".len());

            // Verify both SessionRecorded and SpanRecorded broadcast events were emitted.
            let ev1 = rx.try_recv().unwrap();
            let ev2 = rx.try_recv().unwrap();
            assert!(matches!(ev1, TraceEvent::SessionRecorded { .. }));
            assert!(matches!(ev2, TraceEvent::SpanRecorded { .. }));
        }

        // Reopen from disk and confirm lossless reload roundtrip.
        let reloaded = TraceStore::new(
            Some(trace_file),
            SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
        );
        let sessions = reloaded.list_sessions_for_viewer(&alice, None, "main");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "sess_proxy_bridge");
        assert_eq!(sessions[0].status, SessionStatus::Blocked);
        assert_eq!(sessions[0].spans.len(), 1);
        assert_eq!(sessions[0].delivery.blocked_count, 1);
        assert_eq!(sessions[0].delivery.error_count, 1);
    }

    #[test]
    fn demo_seeding_and_blame_by_change_or_commit_respect_acls() {
        let policy = compiled_test_policy();
        let store = TraceStore::default();
        store.seed_demo_sessions();
        // Calling twice must be idempotent.
        store.seed_demo_sessions();
        assert_eq!(store.session_count(), 2);

        let alice = DelegatedIdentity::human_only(
            Principal::User("alice".to_owned()),
            vec!["billing".to_owned()],
        );
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);

        let by_change =
            store.blame_by_change_or_commit("I7a3f92c8e1", &alice, Some(&policy), "main");
        assert_eq!(by_change.len(), 1);
        assert_eq!(by_change[0].commit_oid.as_deref(), Some("9f4c2a1"));
        assert!(
            by_change[0]
                .delivery
                .files_touched
                .contains(&"billing/ledger/tx.rs".to_owned())
        );

        let by_commit_anon =
            store.blame_by_change_or_commit("9f4c2a1", &anon, Some(&policy), "main");
        assert_eq!(by_commit_anon.len(), 1);
        assert!(
            !by_commit_anon[0]
                .delivery
                .files_touched
                .contains(&"billing/ledger/tx.rs".to_owned())
        );
        assert_eq!(by_commit_anon[0].spans[0].summary, REDACTED_PROMPT_SUMMARY);

        let by_change_2 =
            store.blame_by_change_or_commit("I2e81b4a09f", &alice, Some(&policy), "main");
        assert_eq!(by_change_2.len(), 1);
        assert_eq!(by_change_2[0].status, SessionStatus::Blocked);
    }

    #[test]
    fn ingest_agent_hook_json_supports_claude_code_cursor_codex_and_ai_tools() {
        // 1. Claude Code PreToolUse (Bash)
        let claude_pre = r#"{
            "session_id": "cc-sess-01",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "toolu_123",
            "tool_input": { "command": "cargo test --workspace" }
        }"#;
        let parsed = ingest_agent_hook_json(claude_pre).unwrap();
        assert_eq!(parsed.tool_source, "claude-code");
        assert_eq!(parsed.session_id, "cc-sess-01");
        assert_eq!(parsed.span.span_id, "toolu_123");
        assert_eq!(parsed.span.kind, SpanKind::ToolCall);
        assert_eq!(
            parsed.span.command.as_deref(),
            Some("cargo test --workspace")
        );

        // 2. Claude Code PostToolUse (Edit file)
        let claude_post = r#"{
            "session_id": "cc-sess-01",
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": { "file_path": "apps/web/src/App.tsx" },
            "duration_ms": 180
        }"#;
        let parsed_post = ingest_agent_hook_json(claude_post).unwrap();
        assert_eq!(parsed_post.span.kind, SpanKind::FileAccess);
        assert_eq!(
            parsed_post.span.path.as_deref(),
            Some("apps/web/src/App.tsx")
        );
        assert_eq!(parsed_post.span.duration_ms, Some(180));

        // 3. Claude Code Stop -> DeliveryReport
        let claude_stop = r#"{
            "session_id": "cc-sess-01",
            "hook_event_name": "Stop",
            "summary": "Completed checkout badge update"
        }"#;
        let parsed_stop = ingest_agent_hook_json(claude_stop).unwrap();
        assert_eq!(parsed_stop.span.kind, SpanKind::DeliveryReport);

        // 4. Cursor afterFileEdit
        let cursor_edit = r#"{
            "conversation_id": "cur-conv-77",
            "hook_event_name": "afterFileEdit",
            "file_path": "billing/ledger/tx.rs",
            "model": "claude-sonnet-4"
        }"#;
        let parsed_cursor = ingest_agent_hook_json(cursor_edit).unwrap();
        assert_eq!(parsed_cursor.tool_source, "cursor");
        assert_eq!(parsed_cursor.session_id, "cur-conv-77");
        assert_eq!(parsed_cursor.span.kind, SpanKind::FileAccess);
        assert_eq!(
            parsed_cursor.span.path.as_deref(),
            Some("billing/ledger/tx.rs")
        );

        // 5. Codex CLI agent-turn-complete
        let codex_turn = r#"{
            "type": "agent-turn-complete",
            "thread-id": "codex-th-42",
            "turn-id": "turn-9",
            "last-assistant-message": "All unit tests pass after refactoring."
        }"#;
        let parsed_codex = ingest_agent_hook_json(codex_turn).unwrap();
        assert_eq!(parsed_codex.tool_source, "codex");
        assert_eq!(parsed_codex.session_id, "codex-th-42");
        assert_eq!(parsed_codex.span.span_id, "turn-9");
        assert_eq!(parsed_codex.span.kind, SpanKind::DeliveryReport);

        // 6. ai-tools normalized failure payload
        let ai_tools_err = r#"{
            "source": "ai-tools",
            "event": "tool_error",
            "session_id": "ait-01",
            "tool": "cargo",
            "command": "cargo clippy -- -D warnings",
            "exit_code": 101,
            "error": "clippy lint violation"
        }"#;
        let parsed_ai = ingest_agent_hook_json(ai_tools_err).unwrap();
        assert_eq!(parsed_ai.tool_source, "ai-tools");
        assert_eq!(parsed_ai.span.kind, SpanKind::ErrorDiagnostic);
        assert_eq!(parsed_ai.span.decision, Some(AuditDecision::Denied));
        assert_eq!(
            parsed_ai.span.error_message.as_deref(),
            Some("clippy lint violation")
        );

        // 7. Invalid payload errors cleanly
        assert!(ingest_agent_hook_json("not-json").is_err());
        assert!(ingest_agent_hook_json("{}").is_err());
    }

    #[test]
    fn hash_chain_integrity_detects_tampering_and_zone_only_acl_redacts() {
        let store =
            TraceStore::in_memory(SecretRedactor::build(std::iter::empty::<(&str, &str)>()));
        store.seed_demo_sessions();

        let owner = DelegatedIdentity::human_only(Principal::User("alice".to_owned()), vec![]);
        let sessions = store.list_sessions_for_viewer(&owner, None, "main");
        let s1 = sessions
            .iter()
            .find(|s| s.session_id == "tr_i7a3f92c8e1_r2")
            .unwrap();
        assert_eq!(s1.delivery.integrity.status, IntegrityStatus::Verified);
        assert_eq!(s1.delivery.integrity.verified_spans, s1.spans.len());
        assert!(s1.spans.iter().enumerate().all(|(i, sp)| {
            sp.sequence == (i as u64) + 1 && sp.event_hash.is_some() && sp.prev_hash.is_some()
        }));

        // Tamper with a span payload and verify integrity catches it immediately.
        let mut tampered = s1.clone();
        tampered.spans[1].summary = "forged summary".to_owned();
        let report = tampered.verify_integrity();
        assert_eq!(report.status, IntegrityStatus::Tampered);
        assert!(
            report
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("hash mismatch"))
        );

        // Zone-only span (`path: None, zone: Some("billing")`) must be redacted for unauthorized viewers.
        let policy = compiled_test_policy();
        let bob = DelegatedIdentity::human_only(Principal::User("bob".to_owned()), vec![]);
        let filtered = filter_session_for_viewer(s1, &bob, Some(&policy), "main");
        let billing_egress = filtered
            .spans
            .iter()
            .find(|sp| sp.span_id == "sp_103_proxy_stripe")
            .unwrap();
        assert!(billing_egress.redacted_for_viewer);
        assert_eq!(billing_egress.summary, REDACTED_ZONE_SUMMARY);
        assert!(billing_egress.authority.is_none());
        // Read-time ACL redaction preserves the verified underlying integrity status.
        assert_eq!(
            filtered.delivery.integrity.status,
            IntegrityStatus::Verified
        );
    }

    #[test]
    fn expanded_secret_scrubber_and_otlp_ingestion_work() {
        let mut span = TraceSpan {
            span_id: "sp_sec_wide".to_owned(),
            timestamp: Utc::now(),
            kind: SpanKind::ToolCall,
            summary: format!(
                "google={} aws={} url=postgres://{}:{}@db.internal:5432/prod auth=Bearer {}.{}",
                ["AIza", "SyD1234567890abcdefghijklmno"].concat(),
                ["ASIA", "IOSFODNN7EXAMPLE"].concat(),
                "admin",
                "supersecret",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ",
                "abc123def456",
            ),
            code_snippet: Some(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"
                    .to_owned(),
            ),
            ..TraceSpan::default()
        };
        let scrubbed = scrub_raw_secret_patterns(&mut span);
        assert!(scrubbed > 50);
        assert!(!span.summary.contains("AIzaSy"));
        assert!(!span.summary.contains("ASIAIOSFODNN7EXAMPLE"));
        assert!(!span.summary.contains("supersecret"));
        assert!(!span.summary.contains("eyJhbGci"));
        assert!(span.summary.contains("[REDACTED:GOOGLE_API_KEY]"));
        assert!(span.summary.contains("[REDACTED:AWS_ACCESS_KEY]"));
        assert!(span.summary.contains("[REDACTED:URL_CREDENTIALS]"));
        assert!(span.summary.contains("[REDACTED:JWT]"));
        assert_eq!(span.code_snippet.as_deref(), Some("[REDACTED:PRIVATE_KEY]"));

        // OTLP resourceSpans ingestion
        let otlp = r#"{
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        { "key": "service.name", "value": { "stringValue": "langgraph-worker" } },
                        { "key": "gen_ai.request.model", "value": { "stringValue": "claude-sonnet-4-6" } }
                    ]
                },
                "scopeSpans": [{
                    "spans": [{
                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                        "spanId": "00f067aa0ba902b7",
                        "name": "edit_file",
                        "startTimeUnixNano": "1763900000000000000",
                        "endTimeUnixNano": "1763900000450000000",
                        "attributes": [
                            { "key": "file.path", "value": { "stringValue": "apps/web/src/checkout.ts" } },
                            { "key": "gen_ai.usage.input_tokens", "value": { "intValue": "920" } },
                            { "key": "gen_ai.usage.output_tokens", "value": { "intValue": "180" } }
                        ]
                    }]
                }]
            }]
        }"#;
        let parsed = ingest_agent_hook_json(otlp).unwrap();
        assert_eq!(parsed.tool_source, "langgraph-worker");
        assert_eq!(parsed.model.as_deref(), Some("claude-sonnet-4-6"));
        assert_eq!(parsed.span.kind, SpanKind::FileAccess);
        assert_eq!(parsed.span.duration_ms, Some(450));
        assert_eq!(parsed.span.tokens_in, Some(920));
        assert_eq!(parsed.span.tokens_out, Some(180));
        assert_eq!(parsed.span.source.as_deref(), Some("otlp"));
    }
}
