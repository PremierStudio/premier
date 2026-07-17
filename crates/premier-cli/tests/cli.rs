use premier_trace::read_events;
#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

fn evidence_trace(path: &std::path::Path, variant: &str) {
    let mut writer = premier_trace::TraceWriter::create_named(
        path,
        vec!["agent".into(), "run".into()],
        Some(format!("{variant} evidence")),
    )
    .unwrap();
    writer
        .append_input(premier_trace::EventInput {
            kind: "agent.turn".into(),
            actor_id: "coordinator".into(),
            actor_type: "agent".into(),
            status: "running".into(),
            payload: serde_json::json!({"task": "inspect billing", "api_key": "top-secret"}),
            timestamp: Some("2026-07-15T12:00:00Z".into()),
            ..Default::default()
        })
        .unwrap();
    writer
        .append_input(premier_trace::EventInput {
            kind: "tool.execution".into(),
            actor_id: "researcher".into(),
            actor_type: "subagent".into(),
            status: if variant == "current" {
                "warning".into()
            } else {
                "ok".into()
            },
            duration_ms: if variant == "current" { 240 } else { 100 },
            payload: serde_json::json!({
                "tool": "search",
                "query": if variant == "current" { "invoices" } else { "billing" },
                "headers": {"Authorization": "Bearer hidden"},
                "nested": [{"client_secret": "also-hidden"}]
            }),
            timestamp: Some("2026-07-15T12:00:00.100Z".into()),
            ..Default::default()
        })
        .unwrap();
    if variant == "current" {
        writer
            .append_input(premier_trace::EventInput {
                kind: "agent.result".into(),
                actor_id: "coordinator".into(),
                actor_type: "agent".into(),
                status: "ok".into(),
                payload: serde_json::json!({"result": "done"}),
                timestamp: Some("2026-07-15T12:00:00.200Z".into()),
                ..Default::default()
            })
            .unwrap();
    }
    writer.finish(0).unwrap();
}

#[test]
fn query_filters_local_events_and_bounds_json_results() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("query.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("query")
        .arg(&trace)
        .args([
            "--actor",
            "researcher",
            "--kind",
            "tool.execution",
            "--status",
            "ok",
            "--search",
            "billing",
            "--limit",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["matched"], 1);
    assert_eq!(result["returned"], 1);
    assert_eq!(result["events"][0]["kind"], "tool.execution");
    assert_eq!(result["events"][0]["actor_id"], "researcher");
}

#[test]
fn query_rejects_an_unbounded_limit() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("query-limit.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("query")
        .arg(&trace)
        .args(["--limit", "1001", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1000"));
}

#[test]
fn export_writes_portable_json_with_recursive_secret_redaction() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("export.atrace");
    let exported = temp.path().join("evidence.json");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("export")
        .arg(&trace)
        .args(["--output"])
        .arg(&exported)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(exported).unwrap();
    assert!(!text.contains("top-secret"));
    assert!(!text.contains("Bearer hidden"));
    assert!(!text.contains("also-hidden"));
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["format"], "premier.portable-evidence.v1");
    assert_eq!(document["events"][0]["payload"]["api_key"], "[REDACTED]");
    assert_eq!(
        document["events"][1]["payload"]["headers"]["Authorization"],
        "[REDACTED]"
    );
    assert_eq!(
        document["events"][1]["payload"]["nested"][0]["client_secret"],
        "[REDACTED]"
    );
}

#[test]
fn diff_uses_semantic_structure_and_ignores_generated_trace_identity() {
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join("baseline.atrace");
    let current = temp.path().join("current.atrace");
    evidence_trace(&baseline, "baseline");
    evidence_trace(&current, "current");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("diff")
        .arg(&baseline)
        .arg(&current)
        .args(["--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["counts"]["unchanged"], 1);
    assert_eq!(result["counts"]["changed"], 1);
    assert_eq!(result["counts"]["added"], 1);
    assert_eq!(result["counts"]["removed"], 0);
    let changed = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["status"] == "changed")
        .unwrap();
    assert!(
        changed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "duration_ms")
    );
    assert!(
        changed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "payload.query")
    );
}

#[test]
fn replay_is_explicitly_non_execution_and_can_skip_timing_delays() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("replay.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("replay")
        .arg(&trace)
        .arg("--no-sleep")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("NON-EXECUTION evidence replay"));
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap()["sequence"],
        1
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap()["sequence"],
        2
    );
}

#[test]
fn records_and_verifies_a_real_command() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("cli.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--name", "CLI smoke test", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "printf premier-e2e"])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), "premier-e2e");
    assert_eq!(
        premier_trace::read_manifest(&trace)
            .unwrap()
            .name
            .as_deref(),
        Some("CLI smoke test")
    );

    let verified = Command::new(premier)
        .arg("verify")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("verified"));
}

#[test]
fn child_process_can_emit_subagent_events_through_the_local_collector() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("agent.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let script = r#"curl -sS -X POST -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" --data '{"kind":"agent.spawn","actor_id":"researcher","actor_type":"subagent","span_id":"research","parent_span_id":"root","status":"running","payload":{"task":"investigate"}}' "$PREMIER_COLLECTOR_URL" >/dev/null"#;
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let spawned = events
        .iter()
        .find(|event| event.kind == "agent.spawn")
        .unwrap();
    assert_eq!(spawned.actor_id, "researcher");
    assert_eq!(spawned.parent_span_id, "root");
}

#[test]
fn native_adapter_preserves_stdout_and_adds_normalized_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("native-adapter.atrace");
    let fixture = include_str!("fixtures/adapters/codex.jsonl");
    let fixture_path = temp.path().join("codex.jsonl");
    std::fs::write(&fixture_path, fixture).unwrap();
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--adapter", "codex", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "cat \"$1\"", "sh"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), fixture);
    let events = read_events(&trace).unwrap();
    let raw: String = events
        .iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(raw, fixture);
    assert!(
        events
            .iter()
            .any(|event| { event.kind == "tool.result" && event.source == "adapter.codex.v1" })
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(manifest.capabilities.contains(&"adapter.codex.v1".into()));
    assert_eq!(manifest.adapter.unwrap().provider, "codex");
}

#[test]
fn malformed_native_output_is_diagnostic_and_does_not_fail_recording() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("malformed-adapter.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--adapter", "gemini", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "printf 'not-json\\n'"])
        .output()
        .unwrap();
    assert!(recorded.status.success());
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), "not-json\n");
    let diagnostic = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "adapter.diagnostic")
        .unwrap();
    assert_eq!(diagnostic.status, "warning");
    assert_eq!(diagnostic.source, "adapter.gemini.v1");
}

#[cfg(unix)]
#[test]
fn auto_adapter_detects_a_structured_provider_command() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("auto-adapter.atrace");
    let executable = temp.path().join("codex");
    let fixture = include_str!("fixtures/adapters/codex.jsonl");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            fixture.replace('\u{27}', "'\\''")
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&executable, permissions).unwrap();
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--output"])
        .arg(&trace)
        .arg(&executable)
        .args(["exec", "--json"])
        .output()
        .unwrap();
    assert!(recorded.status.success());
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.adapter.unwrap().provider, "codex");
    assert!(
        read_events(&trace)
            .unwrap()
            .iter()
            .any(|event| event.source == "adapter.codex.v1")
    );
}

#[test]
fn record_redacts_collector_payloads_and_documents_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("redacted-agent.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let script = r#"curl -sS -X POST -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" --data '{"kind":"tool.execution","payload":{"authorization":"Bearer collector-secret","nested":[{"password":"nested-secret","account_pin":"4815"}]}}' "$PREMIER_COLLECTOR_URL" >/dev/null"#;
    let recorded = Command::new(premier)
        .args(["record", "--redact-field", "account_pin", "--output"])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    let journal = std::fs::read(trace.join("events/000001.events.pb.zst")).unwrap();
    assert!(!String::from_utf8_lossy(&journal).contains("collector-secret"));
    let event = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "tool.execution")
        .unwrap();
    assert_eq!(event.payload()["authorization"], "[REDACTED]");
    assert_eq!(event.payload()["nested"][0]["password"], "[REDACTED]");
    assert_eq!(event.payload()["nested"][0]["account_pin"], "[REDACTED]");
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.redaction.unwrap().custom_fields,
        vec!["account_pin"]
    );
}

#[test]
fn record_only_redacts_terminal_text_with_explicit_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("redacted-terminal.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args([
            "record",
            "--redact-literal",
            "literal-secret",
            "--redact-regex",
            "token=[A-Za-z0-9-]+",
            "--output",
        ])
        .arg(&trace)
        .args(["sh", "-c", "printf 'literal-secret token=regex-secret'"])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "literal-secret token=regex-secret"
    );
    let stored: String = read_events(&trace)
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(stored, "[REDACTED] [REDACTED]");
    let provenance = premier_trace::read_manifest(&trace)
        .unwrap()
        .redaction
        .unwrap();
    assert_eq!(provenance.terminal_literal_count, 1);
    assert_eq!(provenance.terminal_regex_count, 1);
}

#[test]
fn child_process_can_emit_via_premier_emit_cli() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("emit-cli.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    // Use the same binary via PATH so the child can invoke `premier emit`.
    let bin_dir = std::path::Path::new(premier)
        .parent()
        .expect("cargo bin dir");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "premier emit --kind agent.spawn --actor researcher --actor-type subagent --span research --parent-span root --status running --payload '{\"task\":\"investigate\"}'",
        ])
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let spawned = events
        .iter()
        .find(|event| event.kind == "agent.spawn")
        .expect("agent.spawn event");
    assert_eq!(spawned.actor_id, "researcher");
    assert_eq!(spawned.actor_type, "subagent");
    assert_eq!(spawned.parent_span_id, "root");
}

#[test]
fn demo_creates_a_verifiable_multi_agent_trace() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("demo.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let generated = Command::new(premier)
        .args(["demo", "--output"])
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let events = read_events(&trace).unwrap();
    assert!(events.iter().any(|event| event.kind == "agent.delegation"));
    assert!(events.iter().any(|event| event.kind == "approval.decision"));
    assert!(events.iter().any(|event| event.actor_type == "subagent"));
}

#[test]
fn demo_refuses_to_delete_an_arbitrary_existing_directory() {
    let temp = tempfile::tempdir().unwrap();
    let precious = temp.path().join("user-project");
    std::fs::create_dir_all(&precious).unwrap();
    std::fs::write(precious.join("important.txt"), "keep me").unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");
    let generated = Command::new(premier)
        .args(["demo", "--output"])
        .arg(&precious)
        .output()
        .unwrap();
    assert!(
        !generated.status.success(),
        "demo must not succeed against a non-trace directory"
    );
    let stderr = String::from_utf8_lossy(&generated.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "stderr should explain refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(precious.join("important.txt")).unwrap(),
        "keep me"
    );
}

#[test]
fn demo_may_replace_an_existing_trace_directory() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("demo.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    for _ in 0..2 {
        let generated = Command::new(premier)
            .args(["demo", "--output"])
            .arg(&trace)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
    }
    assert!(read_events(&trace).unwrap().len() > 5);
}

#[test]
fn record_preserves_multibyte_utf8_check_marks() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("utf8.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    // 400 check marks exercise multi-byte sequences across 8 KiB pump chunks.
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "python3",
            "-c",
            "import sys; sys.stdout.buffer.write(('✓'*400).encode())",
        ])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let stdout: String = events
        .iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(stdout.chars().filter(|&c| c == '✓').count(), 400);
    assert!(
        !stdout.contains('\u{FFFD}'),
        "must not inject replacement characters into valid UTF-8"
    );
}

#[cfg(unix)]
#[test]
fn pty_record_exposes_a_terminal_and_records_merged_ordered_output() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("pty.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&trace)
        .args([
            "python3",
            "-c",
            "import os,sys; print(f'TTY={os.isatty(0)},{os.isatty(1)},{os.isatty(2)}'); sys.stdout.write('OUT-'); sys.stdout.flush(); sys.stderr.write('ERR-'); sys.stderr.flush(); sys.stdout.write('DONE' + '✓'*400); sys.stdout.flush()",
        ])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|item| item == "terminal.pty")
    );
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|item| item == "terminal.merged-output")
    );
    let events = read_events(&trace).unwrap();
    let start = events
        .iter()
        .find(|event| event.kind == "session.start")
        .expect("session.start");
    assert_eq!(start.payload()["terminal"]["mode"], "pty");
    assert!(start.payload()["terminal"]["rows"].as_u64().unwrap() > 0);
    assert!(start.payload()["terminal"]["cols"].as_u64().unwrap() > 0);
    let terminal: String = events
        .iter()
        .filter(|event| event.kind == "process.terminal")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert!(terminal.contains("TTY=True,True,True"), "{terminal:?}");
    assert!(terminal.contains("OUT-ERR-DONE"), "{terminal:?}");
    assert_eq!(
        terminal
            .chars()
            .filter(|character| *character == '✓')
            .count(),
        400
    );
    assert!(!terminal.contains('\u{FFFD}'));
}

#[cfg(unix)]
#[test]
fn pty_record_finalizes_exact_exit_and_signal_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");

    let exit_trace = temp.path().join("pty-exit.atrace");
    let exited = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&exit_trace)
        .args(["sh", "-c", "exit 37"])
        .output()
        .unwrap();
    assert_eq!(exited.status.code(), Some(37));
    premier_trace::verify(&exit_trace).unwrap();
    let exit_manifest = premier_trace::read_manifest(&exit_trace).unwrap();
    assert_eq!(exit_manifest.exit_code, Some(37));
    assert_eq!(
        exit_manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Exit
    );

    let signal_trace = temp.path().join("pty-signal.atrace");
    let signaled = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&signal_trace)
        .args(["sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(signaled.status.code(), Some(143));
    premier_trace::verify(&signal_trace).unwrap();
    let signal_manifest = premier_trace::read_manifest(&signal_trace).unwrap();
    assert_eq!(signal_manifest.exit_code, Some(143));
    let termination = signal_manifest.termination.unwrap();
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(15));
    assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
}

#[cfg(unix)]
#[test]
fn record_preserves_exact_child_signal_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("signal.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();

    assert!(!recorded.status.success());
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(143));
    let termination = manifest.termination.expect("termination metadata");
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(15));
    assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
    let exit = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "process.exit")
        .expect("process.exit event");
    assert_eq!(exit.payload()["exit_code"], 143);
    assert_eq!(exit.payload()["signal"], 15);
    assert_eq!(exit.payload()["signal_name"], "SIGTERM");
    assert_eq!(exit.payload()["termination"], "signal");
}

#[test]
fn record_returns_the_child_exit_code_after_finalization() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("exit-37.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "exit 37"])
        .output()
        .unwrap();

    assert_eq!(recorded.status.code(), Some(37));
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(37));
    assert_eq!(
        manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Exit
    );
}

#[test]
fn recover_command_requires_force_for_a_fresh_trace_then_finalizes_it() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("abandoned.atrace");
    let mut writer = premier_trace::TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "test", serde_json::json!({"live": true}))
        .unwrap();
    drop(writer);
    let premier = env!("CARGO_BIN_EXE_premier");

    let guarded = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(!guarded.status.success());
    assert!(
        String::from_utf8_lossy(&guarded.stderr).contains("appears active"),
        "{}",
        String::from_utf8_lossy(&guarded.stderr)
    );

    let recovered = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(String::from_utf8_lossy(&recovered.stdout).contains("recovered"));
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Interrupted
    );
}

#[cfg(unix)]
#[test]
fn recorder_sigterm_is_forwarded_and_finalized_without_timing_races() {
    assert_recorder_signal_is_forwarded("-TERM", 15, 143, false);
}

#[cfg(unix)]
#[test]
fn recorder_sigint_is_forwarded_and_finalized_without_timing_races() {
    assert_recorder_signal_is_forwarded("-INT", 2, 130, false);
}

#[cfg(unix)]
#[test]
fn pty_recorder_sigterm_is_forwarded_to_the_process_group_and_finalized() {
    assert_recorder_signal_is_forwarded("-TERM", 15, 143, true);
}

#[cfg(unix)]
fn assert_recorder_signal_is_forwarded(
    kill_argument: &str,
    expected_signal: i32,
    expected_exit_code: i32,
    pty: bool,
) {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("forwarded-signal.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let mut command = Command::new(premier);
    command.arg("record");
    if pty {
        command.arg("--pty");
    }
    let mut recorder = command
        .arg("--output")
        .arg(&trace)
        .args(["sh", "-c", "printf 'READY %s\\n' \"$$\"; exec sleep 300"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Reading the child's output through Premier proves the child is running
    // and Premier's signal forwarder has already been installed.
    let mut stdout = BufReader::new(recorder.stdout.take().unwrap());
    let mut ready = String::new();
    while !ready.contains("READY ") {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "readiness EOF");
        ready.push_str(&line);
    }
    let ready_marker = ready.find("READY ").expect("child readiness marker");
    let child_pid = ready[ready_marker..]
        .trim()
        .strip_prefix("READY ")
        .unwrap()
        .parse::<u32>()
        .expect("child pid");

    let signal = Command::new("kill")
        .args([kill_argument, &recorder.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let status = recorder.wait().unwrap();

    assert_eq!(status.code(), Some(expected_exit_code));
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(expected_exit_code));
    let termination = manifest.termination.expect("termination metadata");
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(expected_signal));
    let events = read_events(&trace).unwrap();
    let exit = events
        .iter()
        .find(|event| event.kind == "process.exit")
        .expect("process.exit event");
    assert_eq!(exit.payload()["termination"], "signal");
    assert_eq!(exit.payload()["signal"], expected_signal);
    assert_eq!(exit.payload()["forwarded_by_recorder"], true);
    premier_trace::verify(&trace).unwrap();
    assert!(!trace.join(premier_trace::RECORDER_LEASE).exists());
    let child_still_exists = Command::new("kill")
        .args(["-0", &child_pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !child_still_exists.success(),
        "recorded child was not reaped"
    );
}

#[test]
fn claim_command_migrates_local_tenant_ownership_once() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("claim.atrace");
    premier_trace::TraceWriter::create(&trace, vec!["agent".into()])
        .unwrap()
        .finish(0)
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["claim", trace.to_str().unwrap(), "--tenant", "acme"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        premier_trace::read_manifest(&trace).unwrap().tenant_id,
        "acme"
    );
}

#[test]
fn encrypt_command_migrates_and_verifies_a_finalized_trace() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("encrypt.atrace");
    let mut writer = premier_trace::TraceWriter::create_named(
        &trace,
        vec!["agent".into(), "private-command".into()],
        None,
    )
    .unwrap();
    writer
        .append(
            "agent.result",
            "test",
            serde_json::json!({"private":"evidence"}),
        )
        .unwrap();
    writer.finish(0).unwrap();
    let key_file = temp.path().join("key");
    std::fs::write(&key_file, "71".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args([
            "encrypt",
            trace.to_str().unwrap(),
            "--new-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let key = premier_trace::EncryptionKey::from_file(&key_file).unwrap();
    assert!(premier_trace::trace_is_encrypted(&trace).unwrap());
    assert_eq!(
        premier_trace::read_events_with_key(&trace, &key)
            .unwrap()
            .len(),
        1
    );
    let stored = std::fs::read_to_string(trace.join("manifest.json")).unwrap();
    assert!(!stored.contains("private-command"));
}
