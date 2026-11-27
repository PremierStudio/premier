#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use premier_core::{OverlayKind, Readiness, Visibility};
use premier_overlay::{OverlayEntry, OverlayManifest};
use premier_server::store::PersistedState;
use serde_json::{Value, json};

const CANARY_STRIPE: &str = "sk_live_canary_99999";
const CANARY_OPENAI: &str = "sk-canary-never-leak-88888";

const E2E_POLICY_TOML: &str = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.public]
paths = ["**"]
exclude = ["billing/**", "secrets/**"]
owners = ["@alice"]

[zones.billing]
paths = ["billing/**"]
owners = ["@alice"]
description = "Billing ledger and payment provider integrations"

[[rules]]
id = "deny-billing-everyone"
effect = "deny"
principals = ["*"]
zones = ["billing"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Billing internals restricted by default"

[[rules]]
id = "allow-billing-secret-use"
effect = "allow"
principals = ["group:billing"]
paths = ["secrets/billing/**"]
capabilities = ["use"]
reason = "Billing engineers and delegated agents may USE billing secrets via egress proxy"

[[rules]]
id = "allow-billing-ledger-write"
effect = "allow"
principals = ["group:billing"]
paths = ["billing/ledger/**"]
capabilities = ["traverse", "list", "read", "write"]

[[agent_profiles]]
name = "claude-code"
allow_paths = ["apps/web/**", "README.md", "docs/**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"]
allow_egress_hosts = ["registry.npmjs.org", "crates.io"]

[quarantine]
instruction_files = ["AGENTS.md", "CLAUDE.md", ".cursorrules"]
"#;

const E2E_SERVER_POLICY_TOML: &str = r#"
version = 1

[[rules]]
id = "org-hard-deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["apps/web/master.key", "billing/ledger/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Server policy forbids direct key access regardless of in-repo rules"
"#;

const E2E_ENV_SCHEMA_TOML: &str = r#"
version = 1
repo_id = "acme/platform"

[vars.APP_ENV]
type = "string"
sensitivity = "public"
default = "development"
allowed_values = ["development", "preview", "staging", "production"]
required_in = ["dev", "preview", "staging", "prod"]

[vars.STRIPE_SECRET_KEY]
type = "secret"
sensitivity = "restricted"
required_in = ["staging", "prod"]
zone = "billing"
description = "Stripe secret key — agents may USE only via egress proxy"

[vars.STRIPE_SECRET_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
inject = { kind = "bearer_header", header = "Authorization" }
rate_limit_per_min = 60
approval = "auto"

[vars.OPENAI_API_KEY]
type = "secret"
sensitivity = "restricted"
required_in = ["prod"]
description = "OpenAI API key — JIT capability proxy only"

[vars.OPENAI_API_KEY.egress]
hosts = ["api.openai.com"]
methods = ["POST"]
path_prefixes = ["/v1/"]
inject = { kind = "bearer_header", header = "Authorization" }
rate_limit_per_min = 30
approval = "jit"
jit_ttl_secs = 300
"#;

fn premier_bin() -> &'static str {
    env!("CARGO_BIN_EXE_premier")
}

#[test]
fn init_creates_starter_files_and_preserves_existing_configuration() {
    let tmp = tempfile::tempdir().unwrap();
    let run = |subcommand| {
        let result = Command::new(premier_bin())
            .current_dir(tmp.path())
            .arg(subcommand)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    run("init");
    let branch = Command::new("git")
        .current_dir(tmp.path())
        .args(["symbolic-ref", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&branch.stdout).trim(),
        "refs/heads/main"
    );
    let policy = tmp.path().join(".access.toml");
    premier_policy::parse_policy_toml(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    let schema = tmp.path().join(".env.schema");
    premier_secrets::EnvSchema::parse_toml(&std::fs::read_to_string(&schema).unwrap()).unwrap();
    std::fs::write(&policy, "# User configuration\n").unwrap();
    run("init");
    assert_eq!(
        std::fs::read_to_string(policy).unwrap(),
        "# User configuration\n"
    );
    let doctor = run("doctor");
    for label in [
        "Git",
        "Repository",
        ".access.toml",
        ".env.schema",
        "State directory",
        "Studio UI",
    ] {
        assert!(doctor.contains(label), "{doctor}");
    }
}

fn run_git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "user.name=Test Bot",
            "-c",
            "user.email=test@premier.local",
        ])
        .args(args)
        .output()
        .expect("failed to execute git");
    assert!(
        out.status.success(),
        "git {:?} failed (status {:?}):\nstdout: {}\nstderr: {}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn init_mcp_test_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    run_git(root, &["init", "-q", "-b", "main"]);

    std::fs::write(root.join(".access.toml"), E2E_POLICY_TOML).expect("write .access.toml");
    std::fs::write(root.join(".env.schema"), E2E_ENV_SCHEMA_TOML).expect("write .env.schema");
    std::fs::write(root.join("server-policy.toml"), E2E_SERVER_POLICY_TOML)
        .expect("write server-policy.toml");
    std::fs::write(root.join("README.md"), "# Premier E2E Repo\n").expect("write README.md");
    std::fs::create_dir_all(root.join("billing")).expect("create billing dir");
    std::fs::write(
        root.join("billing/ledger.rs"),
        "pub fn settle_invoice() {}\n",
    )
    .expect("write billing/ledger.rs");

    run_git(
        root,
        &[
            "add",
            ".access.toml",
            ".env.schema",
            "README.md",
            "billing/ledger.rs",
        ],
    );
    run_git(root, &["commit", "-q", "-m", "initial commit"]);

    // Seed `.premier/state.json` with a personal overlay, a team overlay, and a private branch.
    let premier_dir = root.join(".premier");
    std::fs::create_dir_all(&premier_dir).expect("create .premier dir");
    let mut state = PersistedState {
        overlays: OverlayManifest {
            version: 1,
            entries: vec![
                OverlayEntry {
                    kind: OverlayKind::Personal,
                    path: "scratch/mia-notes.md".to_owned(),
                    encrypted: false,
                },
                OverlayEntry {
                    kind: OverlayKind::Team("platform".to_owned()),
                    path: ".run/**".to_owned(),
                    encrypted: false,
                },
            ],
        },
        ..Default::default()
    };
    state.branch_metadata.insert(
        "refs/premier-private/embargo-q4".to_owned(),
        (
            Visibility::Restricted(vec!["@alice".to_owned()]),
            Readiness::Ready,
        ),
    );
    std::fs::write(
        premier_dir.join("state.json"),
        serde_json::to_string_pretty(&state).expect("serialize state.json"),
    )
    .expect("write .premier/state.json");

    tmp
}

fn send_line(stdin: &mut impl Write, line: &str) {
    writeln!(stdin, "{line}").expect("write line to child stdin");
    stdin.flush().expect("flush child stdin");
}

fn send_json(stdin: &mut impl Write, payload: &Value) {
    let encoded = serde_json::to_string(payload).expect("serialize JSON-RPC request");
    send_line(stdin, &encoded);
}

fn recv_json(rx: &mpsc::Receiver<String>, label: &str) -> Value {
    let raw = rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("timed out waiting for JSON-RPC response ({label}): {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("stdout line for {label} was not valid JSON ({e}): {raw:?}"))
}

fn parse_tool_payload(resp: &Value) -> (Value, bool) {
    assert_eq!(resp["jsonrpc"], "2.0");
    assert!(
        resp.get("error").is_none(),
        "expected tool result, got JSON-RPC error: {resp}"
    );
    let result = &resp["result"];
    let is_error = result["isError"]
        .as_bool()
        .expect("result.isError must be boolean");
    let text = result["content"][0]["text"]
        .as_str()
        .expect("result.content[0].text must be string");
    let parsed: Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("tool content text was not valid JSON ({e}): {text:?}"));
    (parsed, is_error)
}

#[test]
fn mcp_config_outputs_strict_formats_and_wrapper_hints_for_all_clients() {
    // 1. Claude Code: strict JSON on stdout with "type": "stdio", policy & group args; wrapper hint on stderr.
    let claude = Command::new(premier_bin())
        .args([
            "mcp",
            "config",
            "--client",
            "claude-code",
            "--policy",
            ".access.toml",
            "--group",
            "engineers",
        ])
        .output()
        .expect("run premier mcp config claude-code");
    assert!(
        claude.status.success(),
        "claude-code config failed: {}",
        String::from_utf8_lossy(&claude.stderr)
    );
    let claude_json: Value = serde_json::from_slice(&claude.stdout).unwrap_or_else(|e| {
        panic!(
            "claude-code stdout must parse strictly as JSON ({e}):\n{}",
            String::from_utf8_lossy(&claude.stdout)
        )
    });
    assert_eq!(claude_json["mcpServers"]["premier"]["type"], "stdio");
    assert_eq!(claude_json["mcpServers"]["premier"]["command"], "premier");
    let claude_args = claude_json["mcpServers"]["premier"]["args"]
        .as_array()
        .expect("claude-code args array");
    assert!(claude_args.contains(&json!("mcp")));
    assert!(claude_args.contains(&json!("serve")));
    assert!(claude_args.contains(&json!("--policy")));
    assert!(claude_args.contains(&json!(".access.toml")));
    assert!(claude_args.contains(&json!("--group")));
    assert!(claude_args.contains(&json!("engineers")));

    let claude_stderr = String::from_utf8_lossy(&claude.stderr);
    assert!(
        claude_stderr.contains("premier agent run")
            && claude_stderr.contains("--policy .access.toml")
            && claude_stderr.contains("--group engineers"),
        "expected wrapper hint on stderr, got: {claude_stderr:?}"
    );

    // 2. Cursor: strict JSON on stdout; wrapper hint on stderr.
    let cursor = Command::new(premier_bin())
        .args([
            "mcp",
            "config",
            "--client",
            "cursor",
            "--policy",
            ".access.toml",
        ])
        .output()
        .expect("run premier mcp config cursor");
    assert!(
        cursor.status.success(),
        "cursor config failed: {}",
        String::from_utf8_lossy(&cursor.stderr)
    );
    let cursor_json: Value = serde_json::from_slice(&cursor.stdout).unwrap_or_else(|e| {
        panic!(
            "cursor stdout must parse strictly as JSON ({e}):\n{}",
            String::from_utf8_lossy(&cursor.stdout)
        )
    });
    assert_eq!(cursor_json["mcpServers"]["premier"]["command"], "premier");
    let cursor_args = cursor_json["mcpServers"]["premier"]["args"]
        .as_array()
        .expect("cursor args array");
    assert!(cursor_args.contains(&json!("--policy")));
    assert!(cursor_args.contains(&json!(".access.toml")));
    let cursor_stderr = String::from_utf8_lossy(&cursor.stderr);
    assert!(
        cursor_stderr.contains("premier agent run") && cursor_stderr.contains("cursor-agent"),
        "expected cursor wrapper hint on stderr, got: {cursor_stderr:?}"
    );

    // 3. Codex: strict TOML on stdout; wrapper hint on stderr.
    let codex = Command::new(premier_bin())
        .args([
            "mcp",
            "config",
            "--client",
            "codex",
            "--policy",
            ".access.toml",
        ])
        .output()
        .expect("run premier mcp config codex");
    assert!(
        codex.status.success(),
        "codex config failed: {}",
        String::from_utf8_lossy(&codex.stderr)
    );
    let codex_stdout = String::from_utf8(codex.stdout).expect("codex stdout valid UTF-8");
    let codex_toml: toml::Value = toml::from_str(&codex_stdout).unwrap_or_else(|e| {
        panic!("codex stdout must parse strictly as TOML ({e}):\n{codex_stdout}")
    });
    assert_eq!(
        codex_toml["mcp_servers"]["premier"]["command"].as_str(),
        Some("premier")
    );
    let codex_args = codex_toml["mcp_servers"]["premier"]["args"]
        .as_array()
        .expect("codex args array");
    assert!(codex_args.contains(&toml::Value::String("--policy".to_owned())));
    assert!(codex_args.contains(&toml::Value::String(".access.toml".to_owned())));
    let codex_stderr = String::from_utf8_lossy(&codex.stderr);
    assert!(
        codex_stderr.contains("premier agent run") && codex_stderr.contains("codex"),
        "expected codex wrapper hint on stderr, got: {codex_stderr:?}"
    );

    // 4. `--wrapper`: prints the `premier agent run` command with `--policy` directly to stdout.
    let wrapper = Command::new(premier_bin())
        .args([
            "mcp",
            "config",
            "--client",
            "claude-code",
            "--policy",
            ".access.toml",
            "--wrapper",
        ])
        .output()
        .expect("run premier mcp config --wrapper");
    assert!(
        wrapper.status.success(),
        "wrapper config failed: {}",
        String::from_utf8_lossy(&wrapper.stderr)
    );
    let wrapper_stdout = String::from_utf8_lossy(&wrapper.stdout);
    assert!(
        wrapper_stdout.contains("premier agent run")
            && wrapper_stdout.contains("--policy .access.toml")
            && wrapper_stdout.contains("-- claude"),
        "unexpected wrapper stdout: {wrapper_stdout:?}"
    );
    assert!(
        wrapper.stderr.is_empty(),
        "expected empty stderr for --wrapper, got: {}",
        String::from_utf8_lossy(&wrapper.stderr)
    );
}

#[test]
fn mcp_serve_stdio_e2e_protocol_tools_purity_and_secret_canaries() {
    let repo = init_mcp_test_repo();
    let root = repo.path();
    // Simulate Studio having already migrated its overlay manifest into SQLite.
    let state = premier_server::store::load_state(root).unwrap();
    assert_eq!(state.overlays.entries.len(), 2);
    assert!(root.join(".premier/premier.db").is_file());
    std::fs::remove_file(root.join(".premier/state.json")).unwrap();
    assert!(!root.join(".premier/state.json").exists());
    let policy_path = root.join(".access.toml");
    let server_policy_path = root.join("server-policy.toml");
    let schema_path = root.join(".env.schema");

    let mut child = Command::new(premier_bin())
        .current_dir(root)
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path UTF-8"),
            "--server-policy",
            server_policy_path
                .to_str()
                .expect("server policy path UTF-8"),
            "--schema",
            schema_path.to_str().expect("schema path UTF-8"),
            "--principal",
            "@mia",
            "--agent-profile",
            "claude-code",
        ])
        .env("RUST_LOG", "debug")
        .env("STRIPE_SECRET_KEY", CANARY_STRIPE)
        .env("OPENAI_API_KEY", CANARY_OPENAI)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn premier mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");

    // Dedicated stdout reader thread prevents deadlocks and captures every raw line for purity checks.
    let (stdout_tx, stdout_rx) = mpsc::channel::<String>();
    let stdout_handle = std::thread::spawn(move || {
        let mut all_lines = Vec::new();
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line.expect("read stdout line");
            all_lines.push(line.clone());
            let _ = stdout_tx.send(line);
        }
        all_lines
    });

    // Dedicated stderr reader drains debug tracing continuously so pipes never stall.
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut reader = BufReader::new(stderr);
        std::io::Read::read_to_string(&mut reader, &mut buf).expect("read stderr");
        buf
    });

    let mut expected_responses = 0usize;

    // (a) initialize with protocolVersion "2025-06-18".
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "e2e-harness", "version": "1.0.0" }
            }
        }),
    );
    expected_responses += 1;
    let init = recv_json(&stdout_rx, "initialize");
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "premier-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(init["result"]["capabilities"]["resources"].is_object());

    // (b) notifications/initialized MUST emit NO response; verify via an immediate ping.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping"
        }),
    );
    expected_responses += 1;
    let ping = recv_json(&stdout_rx, "ping after notifications/initialized");
    assert_eq!(
        ping["id"], 2,
        "notifications/initialized must not emit a stdout frame before ping"
    );
    assert_eq!(ping["result"], json!({}));

    // (c) tools/list returns all 5 tools with exact names and hardened schemas.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list"
        }),
    );
    expected_responses += 1;
    let list_resp = recv_json(&stdout_rx, "tools/list");
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools/list tools array");
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name string"))
        .collect();
    assert_eq!(
        tool_names,
        vec![
            "premier_access_explain",
            "premier_policy_summary",
            "premier_env_schema",
            "premier_overlays_check",
            "premier_policy_diff",
        ]
    );
    let diff_schema = tools
        .iter()
        .find(|t| t["name"] == "premier_policy_diff")
        .expect("premier_policy_diff in tools/list");
    assert!(
        diff_schema["inputSchema"]["properties"]
            .get("principals")
            .is_none(),
        "premier_policy_diff schema must not advertise principals"
    );

    // (d) premier_access_explain on README.md (allowed) and billing/ledger.rs (denied).
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "premier_access_explain",
                "arguments": { "path": "README.md" }
            }
        }),
    );
    expected_responses += 1;
    let (readme_body, readme_err) = parse_tool_payload(&recv_json(&stdout_rx, "explain README.md"));
    assert!(!readme_err);
    assert_eq!(readme_body["principal"], "@mia");
    assert_eq!(readme_body["agent_profile"], "claude-code");
    let readme_eff: Vec<&str> = readme_body["effective"]
        .as_array()
        .expect("effective array")
        .iter()
        .map(|v| v.as_str().expect("cap name"))
        .collect();
    assert!(readme_eff.contains(&"read"));
    assert!(readme_eff.contains(&"traverse"));
    assert!(readme_eff.contains(&"list"));

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "premier_access_explain",
                "arguments": { "path": "billing/ledger.rs" }
            }
        }),
    );
    expected_responses += 1;
    let (billing_body, billing_err) =
        parse_tool_payload(&recv_json(&stdout_rx, "explain billing/ledger.rs"));
    assert!(!billing_err);
    assert_eq!(billing_body["principal"], "@mia");
    assert_eq!(billing_body["agent_profile"], "claude-code");
    assert_eq!(billing_body["effective"], json!([]));

    // (e) premier_policy_summary returns compiled metadata bound to caller session.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "premier_policy_summary",
                "arguments": {}
            }
        }),
    );
    expected_responses += 1;
    let (summary_body, summary_err) =
        parse_tool_payload(&recv_json(&stdout_rx, "premier_policy_summary"));
    assert!(!summary_err);
    assert_eq!(
        summary_body["fingerprint"]
            .as_str()
            .expect("fingerprint")
            .len(),
        64
    );
    assert_eq!(summary_body["has_server_policy"], true);
    assert_eq!(summary_body["session"]["principal"], "@mia");
    assert_eq!(summary_body["session"]["agent_profile"], "claude-code");
    assert_eq!(summary_body["session"]["default_branch"], "main");
    assert_eq!(summary_body["agent_profiles"], json!(["claude-code"]));

    // (f) premier_policy_diff: reject "principals" override with -32602, and evaluate strictly
    // for caller identity while preserving server policy hard-denies.
    let proposed_toml = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[[rules]]
id = "grant-mia-readme-write"
effect = "allow"
principals = ["@mia"]
paths = ["README.md"]
capabilities = ["traverse", "list", "read", "write"]

[[rules]]
id = "try-allow-master-key"
effect = "allow"
principals = ["@mia"]
paths = ["apps/web/master.key"]
capabilities = ["traverse", "list", "read", "write"]

[[agent_profiles]]
name = "claude-code"
allow_paths = ["apps/web/**", "README.md", "docs/**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"]

[quarantine]
instruction_files = ["AGENTS.md", "CLAUDE.md", ".cursorrules"]
"#;

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "premier_policy_diff",
                "arguments": {
                    "head_toml": proposed_toml,
                    "paths": ["README.md"],
                    "principals": ["@alice", "anonymous"]
                }
            }
        }),
    );
    expected_responses += 1;
    let diff_oracle = recv_json(&stdout_rx, "premier_policy_diff with forbidden principals");
    assert_eq!(diff_oracle["id"], 7);
    assert_eq!(diff_oracle["error"]["code"], -32602);
    assert!(
        diff_oracle["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("forbidden")
    );

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "premier_policy_diff",
                "arguments": {
                    "head_toml": proposed_toml,
                    "paths": ["README.md", "apps/web/master.key"],
                    "changed_files": ["AGENTS.md"]
                }
            }
        }),
    );
    expected_responses += 1;
    let (diff_body, diff_err) = parse_tool_payload(&recv_json(&stdout_rx, "premier_policy_diff"));
    assert!(!diff_err);
    assert_eq!(diff_body["has_escalations"], true);
    let deltas = diff_body["deltas"].as_array().expect("deltas array");
    assert!(!deltas.is_empty());
    assert!(
        deltas.iter().all(|d| d["principal"] == "@mia"),
        "policy diff must evaluate strictly for configured caller @mia: {deltas:?}"
    );
    assert!(
        deltas.iter().any(|d| d["path"] == "README.md"),
        "expected escalation delta on README.md: {deltas:?}"
    );
    assert!(
        !deltas.iter().any(|d| d["path"] == "apps/web/master.key"),
        "server policy hard deny must remain enforced on apps/web/master.key: {deltas:?}"
    );
    assert_eq!(
        diff_body["quarantine_alerts"]
            .as_array()
            .expect("quarantine_alerts array")
            .len(),
        1
    );

    // (g) premier_env_schema returns metadata with ZERO canary secret values.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "premier_env_schema",
                "arguments": {}
            }
        }),
    );
    expected_responses += 1;
    let schema_resp = recv_json(&stdout_rx, "premier_env_schema");
    let schema_raw = serde_json::to_string(&schema_resp).expect("serialize schema response");
    assert!(!schema_raw.contains(CANARY_STRIPE));
    assert!(!schema_raw.contains(CANARY_OPENAI));
    let (schema_body, schema_err) = parse_tool_payload(&schema_resp);
    assert!(!schema_err);
    assert_eq!(schema_body["placeholder_prefix"], "premier_cap_v1_");
    assert_eq!(schema_body["variable_count"], 3);
    let vars = schema_body["variables"]
        .as_array()
        .expect("variables array");
    for secret_name in ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"] {
        let entry = vars
            .iter()
            .find(|v| v["name"] == secret_name)
            .unwrap_or_else(|| panic!("expected {secret_name} in env schema metadata"));
        assert_eq!(entry["sensitivity"], "restricted");
        assert_eq!(entry["raw_value_exposed"], false);
        assert!(entry.get("value").is_none());
        assert!(entry.get("secret").is_none());
    }

    // (h) premier_overlays_check catches overlays merged from SQLite state + defaults.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "premier_overlays_check",
                "arguments": {
                    "paths": [
                        "README.md",
                        "scratch/mia-notes.md",
                        ".run/debug.xml",
                        "AGENTS.local.md"
                    ]
                }
            }
        }),
    );
    expected_responses += 1;
    let (ov_leak_body, ov_leak_err) =
        parse_tool_payload(&recv_json(&stdout_rx, "premier_overlays_check leak"));
    assert!(!ov_leak_err);
    assert_eq!(ov_leak_body["ok"], false);
    assert_eq!(ov_leak_body["safe_paths"], json!(["README.md"]));
    let blocked: Vec<&str> = ov_leak_body["blocked_paths"]
        .as_array()
        .expect("blocked_paths array")
        .iter()
        .map(|v| v.as_str().expect("blocked path str"))
        .collect();
    assert!(blocked.contains(&"scratch/mia-notes.md"));
    assert!(blocked.contains(&".run/debug.xml"));
    assert!(blocked.contains(&"AGENTS.local.md"));

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "premier_overlays_check",
                "arguments": { "paths": ["README.md"] }
            }
        }),
    );
    expected_responses += 1;
    let (ov_ok_body, ov_ok_err) =
        parse_tool_payload(&recv_json(&stdout_rx, "premier_overlays_check safe"));
    assert!(!ov_ok_err);
    assert_eq!(ov_ok_body["ok"], true);
    assert_eq!(ov_ok_body["blocked_paths"], json!([]));

    // (i) resources/list and resources/read work over stdio with zero secret leakage.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "resources/list"
        }),
    );
    expected_responses += 1;
    let res_list = recv_json(&stdout_rx, "resources/list");
    let uris: Vec<&str> = res_list["result"]["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .map(|r| r["uri"].as_str().expect("uri str"))
        .collect();
    assert_eq!(
        uris,
        vec!["premier://policy/summary", "premier://env/schema"]
    );

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "resources/read",
            "params": { "uri": "premier://env/schema" }
        }),
    );
    expected_responses += 1;
    let res_env = recv_json(&stdout_rx, "resources/read premier://env/schema");
    let res_env_text = res_env["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource text");
    assert!(!res_env_text.contains(CANARY_STRIPE));
    assert!(!res_env_text.contains(CANARY_OPENAI));

    // (j) Negative protocol tests:
    //     1. Unknown tool name -> JSON-RPC error -32602.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": { "name": "premier_nonexistent_tool", "arguments": {} }
        }),
    );
    expected_responses += 1;
    let unknown_tool = recv_json(&stdout_rx, "unknown tool");
    assert_eq!(unknown_tool["id"], 14);
    assert_eq!(unknown_tool["error"]["code"], -32602);

    //     2. Unexpected extra argument violating additionalProperties: false -> -32602.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "premier_policy_summary",
                "arguments": { "unexpected_extra_arg": "nope" }
            }
        }),
    );
    expected_responses += 1;
    let extra_arg = recv_json(&stdout_rx, "unexpected extra argument");
    assert_eq!(extra_arg["id"], 15);
    assert_eq!(extra_arg["error"]["code"], -32602);

    //     3. Request with `"id": null` -> JSON-RPC error -32600.
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "ping"
        }),
    );
    expected_responses += 1;
    let null_id = recv_json(&stdout_rx, "null id");
    assert_eq!(null_id["id"], Value::Null);
    assert_eq!(null_id["error"]["code"], -32600);

    //     4. Malformed JSON -> JSON-RPC error -32700.
    send_line(&mut stdin, "{not valid json");
    expected_responses += 1;
    let malformed = recv_json(&stdout_rx, "malformed json");
    assert_eq!(malformed["id"], Value::Null);
    assert_eq!(malformed["error"]["code"], -32700);

    // Close stdin and verify clean exit 0.
    drop(stdin);
    let all_stdout_lines = stdout_handle.join().expect("join stdout reader thread");
    let all_stderr = stderr_handle.join().expect("join stderr reader thread");
    let status = child.wait().expect("wait for premier mcp serve exit");

    assert!(
        status.success(),
        "premier mcp serve exited with {:?}; stderr:\n{}",
        status.code(),
        all_stderr
    );

    // Stdout purity: exact response count, every single line is valid JSON-RPC 2.0, zero tracing pollution.
    assert_eq!(
        all_stdout_lines.len(),
        expected_responses,
        "unexpected stdout line count (extra/missing frames): {all_stdout_lines:?}"
    );
    for (idx, line) in all_stdout_lines.iter().enumerate() {
        let parsed: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("stdout line {idx} is not valid JSON ({e}): {line:?}"));
        assert_eq!(
            parsed["jsonrpc"], "2.0",
            "stdout line {idx} missing jsonrpc 2.0: {line:?}"
        );
        assert!(
            !line.contains(CANARY_STRIPE) && !line.contains(CANARY_OPENAI),
            "SECRET CANARY LEAKED IN STDOUT LINE {idx}: {line:?}"
        );
    }

    // Stderr verification: RUST_LOG=debug tracing went strictly to stderr, and ZERO secret canaries leaked.
    assert!(
        all_stderr.contains("starting premier-mcp JSON-RPC 2.0 stdio server"),
        "expected tracing output on stderr with RUST_LOG=debug, got: {all_stderr:?}"
    );
    assert!(
        !all_stderr.contains(CANARY_STRIPE) && !all_stderr.contains(CANARY_OPENAI),
        "SECRET CANARY LEAKED IN STDERR:\n{all_stderr}"
    );
}

#[test]
fn premier_ssh_bind_empty_env_does_not_fail_clap_while_invalid_addr_does() {
    // 1. `premier serve --help` documents `--ssh-bind` and `PREMIER_SSH_BIND`.
    let help = Command::new(premier_bin())
        .args(["serve", "--help"])
        .output()
        .expect("run premier serve --help");
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("--ssh-bind"));
    assert!(help_stdout.contains("PREMIER_SSH_BIND"));

    let tmp = tempfile::tempdir().expect("create tempdir");
    let missing_server_policy: PathBuf = tmp.path().join("definitely-missing-server-policy.toml");
    let missing_arg = missing_server_policy
        .to_str()
        .expect("missing policy path UTF-8");

    // 2. Empty and whitespace-only PREMIER_SSH_BIND pass clap parsing cleanly (failing only
    //    inside `Commands::Serve` when reading the nonexistent `--server-policy`, NOT in clap).
    for empty_val in ["", "   "] {
        let out = Command::new(premier_bin())
            .current_dir(tmp.path())
            .env("PREMIER_SSH_BIND", empty_val)
            .args([
                "serve",
                "--bind",
                "127.0.0.1:0",
                "--server-policy",
                missing_arg,
            ])
            .output()
            .expect("run premier serve with empty PREMIER_SSH_BIND");
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("failed to read server policy"),
            "PREMIER_SSH_BIND={empty_val:?} should pass clap and reach Commands::Serve; stderr:\n{stderr}"
        );
        assert!(
            !stderr.contains("invalid SSH bind address"),
            "PREMIER_SSH_BIND={empty_val:?} must not fail SSH bind parsing; stderr:\n{stderr}"
        );
    }

    // 3. Explicit `--ssh-bind ""` also passes clap parsing cleanly.
    let empty_flag = Command::new(premier_bin())
        .current_dir(tmp.path())
        .env_remove("PREMIER_SSH_BIND")
        .args([
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--ssh-bind",
            "",
            "--server-policy",
            missing_arg,
        ])
        .output()
        .expect("run premier serve with --ssh-bind ''");
    assert!(!empty_flag.status.success());
    let empty_flag_stderr = String::from_utf8_lossy(&empty_flag.stderr);
    assert!(
        empty_flag_stderr.contains("failed to read server policy"),
        "--ssh-bind '' should pass clap and reach Commands::Serve; stderr:\n{empty_flag_stderr}"
    );

    // 4. Invalid PREMIER_SSH_BIND="not-an-addr" MUST fail clap argument parsing immediately.
    let invalid = Command::new(premier_bin())
        .current_dir(tmp.path())
        .env("PREMIER_SSH_BIND", "not-an-addr")
        .args([
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--server-policy",
            missing_arg,
        ])
        .output()
        .expect("run premier serve with invalid PREMIER_SSH_BIND");
    assert_eq!(
        invalid.status.code(),
        Some(2),
        "invalid PREMIER_SSH_BIND must fail clap with exit code 2; stderr:\n{}",
        String::from_utf8_lossy(&invalid.stderr)
    );
    let invalid_stderr = String::from_utf8_lossy(&invalid.stderr);
    assert!(
        invalid_stderr.contains("invalid SSH bind address"),
        "expected clap invalid SSH bind address error; stderr:\n{invalid_stderr}"
    );
    assert!(
        !invalid_stderr.contains("failed to read server policy"),
        "invalid PREMIER_SSH_BIND must fail in clap before reaching Commands::Serve; stderr:\n{invalid_stderr}"
    );
}
